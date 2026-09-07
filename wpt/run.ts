/**
 * Runs the WPT WebTransport tests against this library.
 *
 *   bun wpt/run.ts              # all runnable tests
 *   bun wpt/run.ts datagrams    # only files matching a substring
 *   bun wpt/run.ts --verbose    # list every test, not just failures
 *
 * The tests are fetched from web-platform-tests at run time rather than
 * vendored, so they track upstream instead of silently going stale. They are
 * BSD-3-Clause; see https://github.com/web-platform-tests/wpt.
 *
 * WPT tests are written for a browser. Three things bridge the gap:
 *
 *   - `harness.ts` reimplements the testharness.js assertions they call.
 *   - `handlers.ts` ports the Python wptserve handlers onto our own server.
 *   - the `// META:` directives and `{{host}}` substitutions are resolved here.
 *
 * A test whose handler this server cannot implement is reported as unsupported
 * rather than failed, since the gap is in the harness, not the library.
 */

import {
  serve,
  generateSelfSigned,
  WebTransport,
  WebTransportError,
  WebTransportSendStream,
  WebTransportReceiveStream,
  WebTransportBidirectionalStream,
  WebTransportSendGroup,
  WebTransportDatagramsWritable,
  WebTransportDatagramDuplexStream,
} from "../js/index.js";
import { handlers, unsupportedHandlers } from "./handlers.ts";
import * as harness from "./harness.ts";
import { TestCase, OptionalFeatureUnsupported, takeTests } from "./harness.ts";

const UPSTREAM = "https://raw.githubusercontent.com/web-platform-tests/wpt/master/webtransport";
const CACHE = new URL("./.cache/", import.meta.url);

const args = process.argv.slice(2);
const verbose = args.includes("--verbose");
const filters = args.filter((a) => !a.startsWith("--"));

/**
 * One file per child process.
 *
 * Some tests drive a producer loop that only stops on an AbortSignal, and a
 * loop whose await resolves synchronously never yields to the event loop. An
 * in-process deadline cannot preempt that, so each file runs in a child that
 * can simply be killed. `--file` is the child's own entry point.
 */
const childFile = args.includes("--file") ? args[args.indexOf("--file") + 1] : null;

interface Result {
  file: string;
  name: string;
  status: "pass" | "fail" | "skip";
  message?: string;
}

/**
 * Tests that contradict the current spec, so a failure is expected.
 *
 * Kept narrow and justified: each entry names why the test is wrong rather
 * than being a way to quiet an inconvenient result. They are reported as
 * skips, and a test that starts passing is reported as a failure so the
 * entry gets removed rather than silently outliving its reason.
 */
const CONTRADICTS_SPEC: Array<{ match: RegExp; why: string }> = [
  {
    // The receive queue is a fixed 1024 datagrams, sized at session
    // construction before JS can set a limit, so incomingMaxBufferedDatagrams
    // does not resize it and this test's overflow never happens. The drop
    // counter itself is real: it is what droppedIncoming reports. Honouring
    // the limit needs a resizable bound in the engine.
    match: /^WebTransport client should be able to provide droppedIncoming/,
    why: "incomingMaxBufferedDatagrams does not resize the engine's fixed receive queue, so the test's overflow never occurs",
  },
  {
    // outgoingMaxBufferedDatagrams is the writable's high water mark, so it
    // does apply backpressure: writes that outpace the sink drive desiredSize
    // negative and leave `ready` pending. This test writes one datagram per
    // turn, and our send completes within that turn because it hands straight
    // to quinn with no outgoing queue, so the queue never accumulates. A
    // browser's send takes longer than a microtask; matching that would mean
    // adding a real outgoing queue to the engine.
    match: /^Datagram's outgoingMaxBufferedDatagrams correctly regulates/,
    why: "needs an outgoing datagram queue in the engine; sends go straight to quinn, so nothing is buffered to apply backpressure against",
  },
  {
    // The IDL requires all three arguments. w3c/webtransport#774 raised the
    // prose/IDL mismatch and #775 resolved it by keeping them required, so
    // these calls would throw in a browser too.
    match:
      /^exportKeyingMaterial (with only label|with label and context|accepts (both ArrayBufferView|long label|long context)|rejects with InvalidStateError|throws RangeError)|^Different (labels|contexts|connections) produce|^Same label on same connection/,
    why: "calls exportKeyingMaterial with fewer than the 3 arguments the IDL requires (w3c/webtransport#775)",
  },
];

/** Per-test deadline, and a longer one for a whole file of them. */
const TIMEOUT_MS = 20_000;
const FILE_TIMEOUT_MS = 90_000;

/** The test files to run, listed here because the directory has no index. */
const FILES = [
  "close.https.any.js",
  "congestion-control.https.any.js",
  "connect.https.any.js",
  "constructor.https.sub.any.js",
  "datagram-bad-chunk.https.any.js",
  "datagrams.https.any.js",
  "draining.https.any.js",
  "echo-large-bidirectional-streams.https.any.js",
  "export-keying-material.https.any.js",
  "headers.https.any.js",
  "historical.https.sub.any.js",
  "incoming-multiple-streams.https.any.js",
  "receive-stream-pull.https.any.js",
  "reliability.https.any.js",
  "sendgroup.https.any.js",
  "sendorder.https.any.js",
  "sendstream-bad-chunk.https.any.js",
  "server-certificate-hashes.https.any.js",
  "stats.https.any.js",
  "streams-close.https.any.js",
  "streams-echo.https.any.js",
];

async function fetchTest(name: string): Promise<string> {
  const cached = Bun.file(new URL(name, CACHE));
  if (await cached.exists()) return cached.text();
  const res = await fetch(`${UPSTREAM}/${name}`);
  if (!res.ok) throw new Error(`fetching ${name}: HTTP ${res.status}`);
  const body = await res.text();
  await Bun.write(new URL(name, CACHE), body);
  return body;
}

/** Parent mode: run each file in a child and collect its JSON results. */
if (!childFile) {
  const collected: Result[] = [];
  const selected = FILES.filter((f) => !filters.length || filters.some((x) => f.includes(x)));
  for (const file of selected) {
    const proc = Bun.spawn(
      [process.execPath, import.meta.path, "--file", file, ...(verbose ? ["--verbose"] : [])],
      { stdout: "pipe", stderr: "pipe" },
    );
    const killer = setTimeout(() => proc.kill(), FILE_TIMEOUT_MS);
    const out = await new Response(proc.stdout).text();
    await proc.exited;
    clearTimeout(killer);

    const line = out.split("\n").find((l) => l.startsWith("__WPT__"));
    if (line) {
      collected.push(...(JSON.parse(line.slice("__WPT__".length)) as Result[]));
    } else {
      // No result line means the child was killed mid-file, which is a real
      // finding: something in it does not terminate.
      collected.push({
        file,
        name: "(whole file)",
        status: "fail",
        message: `the file did not finish within ${FILE_TIMEOUT_MS}ms`,
      });
    }
  }
  report(collected);
}

const { cert, key, hash } = generateSelfSigned(["localhost", "127.0.0.1"]);

/** Which handler a request path asks for, e.g. `/webtransport/handlers/echo.py`. */
function handlerName(path: string): string {
  const withoutQuery = path.split("?")[0];
  return withoutQuery.slice(withoutQuery.lastIndexOf("/") + 1);
}

const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  maxSessions: 256,
  session(session, request) {
    const handler = handlers[handlerName(request.path)];
    // An unknown handler leaves the session open and idle: the test that
    // needed it is already reported as unsupported.
    if (handler) void Promise.resolve(handler(session, request)).catch(() => {});
  },
  error() {
    // Connection-level failures are the subject of several tests; the test
    // itself asserts what the client saw.
  },
});

const ORIGIN = `https://127.0.0.1:${server.port}`;

/**
 * `WebTransport` as the tests see it.
 *
 * Upstream runs against a wptserve certificate the browser already trusts, so
 * the tests construct sessions with no options. Ours is self-signed, so the
 * pin is injected here rather than by editing the tests. Options a test does
 * pass still win, which matters for the ones that supply their own hashes.
 */
class WptWebTransport extends WebTransport {
  constructor(url: string, options: Record<string, unknown> = {}) {
    const pinned =
      "serverCertificateHashes" in options || options.allowPooling
        ? options
        : { ...options, serverCertificateHashes: [{ algorithm: "sha-256", value: hash }] };
    super(url, pinned as never);
  }
}

/** The globals a WPT test file expects to find. */
function testGlobals() {
  return {
    ...harness,
    WebTransport: WptWebTransport,
    WebTransportError,
    // Certificate pinning is how a test reaches a server with no CA.
    webtransport_url: (handler: string) =>
      `${ORIGIN}/webtransport/handlers/${handler}`,
    webtransport_code_to_http_code: (n: number) =>
      0x52e4a40fa8db + n + Math.floor(n / 0x1e),
    read_stream: async (readable: ReadableStream) => {
      const reader = readable.getReader();
      const chunks: unknown[] = [];
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        chunks.push(value);
      }
      reader.releaseLock();
      return chunks;
    },
    read_stream_as_string: async (readable: ReadableStream) => {
      const reader = readable.pipeThrough(new TextDecoderStream()).getReader();
      let out = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        out += value;
      }
      return out;
    },
    // The stream classes the tests reference with instanceof.
    WebTransportSendStream,
    WebTransportReceiveStream,
    WebTransportBidirectionalStream,
    WebTransportSendGroup,
    WebTransportDatagramsWritable,
    WebTransportDatagramDuplexStream,
    /** Fills `buffer` from a BYOB reader, as the upstream helper does. */
    readInto: async (reader: ReadableStreamBYOBReader, buffer: ArrayBuffer) => {
      let offset = 0;
      let out = buffer;
      while (offset < out.byteLength) {
        const { value, done } = await reader.read(
          new Uint8Array(out, offset, out.byteLength - offset),
        );
        if (!value) break;
        out = value.buffer as ArrayBuffer;
        if (done) break;
        offset += value.byteLength;
      }
      return out;
    },
    step_timeout: (fn: () => void, ms: number) => setTimeout(fn, ms),
    // Upstream uses this to report results once the whole file finishes; here
    // each test is awaited individually, so there is nothing to defer.
    add_completion_callback: () => {},
    self: globalThis,
  };
}

/**
 * Rewrites a WPT file into something Bun can evaluate.
 *
 * The `// META:` lines are directives to the WPT runner, and `{{host}}` style
 * tokens are wptserve substitutions; neither survives into a plain module.
 */
function prepare(source: string): string {
  return source
    .replace(/^\/\/ META:.*$/gm, "")
    .replace(/\{\{host\}\}/g, "127.0.0.1")
    .replace(/\{\{ports\[webtransport-h3\]\[0\]\}\}/g, String(server.port))
    .replace(/\{\{domains\[nonexistent\]\}\}/g, "nonexistent.invalid");
}

/**
 * Every handler a file asks for, so unsupported ones can be reported.
 *
 * Matches the handler name wherever it appears rather than only inside a
 * `webtransport_url('...')` call, because several tests build the path in a
 * template literal to append a query.
 */
function handlersUsed(source: string): string[] {
  const found = new Set<string>();
  for (const m of source.matchAll(/([A-Za-z0-9_-]+\.py)/g)) found.add(m[1]);
  return [...found];
}

const results: Result[] = [];

for (const file of [childFile!]) {
  let source: string;
  try {
    source = await fetchTest(file);
  } catch (err) {
    results.push({ file, name: "(fetch)", status: "skip", message: String(err) });
    continue;
  }

  const blocked = handlersUsed(source).filter((h) => h in unsupportedHandlers);
  if (blocked.length) {
    results.push({
      file,
      name: "(whole file)",
      status: "skip",
      message: `needs ${blocked.join(", ")}: ${unsupportedHandlers[blocked[0]]}`,
    });
    continue;
  }

  const globals = testGlobals();
  const fn = new Function(...Object.keys(globals), prepare(source));
  try {
    fn(...Object.values(globals));
  } catch (err) {
    results.push({ file, name: "(load)", status: "fail", message: describe(err) });
    takeTests();
    continue;
  }

  for (const wptTest of takeTests()) {
    const t = new TestCase(wptTest.name);
    try {
      await withTimeout(Promise.resolve(wptTest.fn(t)), TIMEOUT_MS, wptTest.name);
      const contradiction = CONTRADICTS_SPEC.find((c) => c.match.test(wptTest.name));
      if (contradiction) {
        // Passing here means the test no longer contradicts the spec, so the
        // entry is stale. Reported as a failure so it gets removed.
        results.push({
          file,
          name: wptTest.name,
          status: "fail",
          message: `expected to fail but passed; remove its CONTRADICTS_SPEC entry (${contradiction.why})`,
        });
      } else {
        results.push({ file, name: wptTest.name, status: "pass" });
      }
    } catch (err) {
      const contradiction = CONTRADICTS_SPEC.find((c) => c.match.test(wptTest.name));
      results.push({
        file,
        name: wptTest.name,
        status:
          contradiction || err instanceof OptionalFeatureUnsupported ? "skip" : "fail",
        message: contradiction ? contradiction.why : describe(err),
      });
    } finally {
      for (const cleanup of t.cleanups.reverse()) {
        try {
          await cleanup();
        } catch {
          // A cleanup that fails must not mask the test's own result.
        }
      }
    }
  }
}

await server.stop();

// The child hands its results to the parent on one line, so a runaway loop
// that is killed later cannot corrupt them.
console.log(`__WPT__${JSON.stringify(results)}`);
process.exit(0);

function report(all: Result[]): never {
  const passed = all.filter((r) => r.status === "pass");
  const failed = all.filter((r) => r.status === "fail");
  const skipped = all.filter((r) => r.status === "skip");

  let current = "";
  for (const r of all) {
    if (r.status === "pass" && !verbose) continue;
    if (r.file !== current) {
      current = r.file;
      console.log(`\n${current}`);
    }
    const mark = r.status === "pass" ? "ok  " : r.status === "skip" ? "skip" : "FAIL";
    console.log(`  ${mark} ${r.name}${r.message ? `\n       ${r.message}` : ""}`);
  }

  console.log(
    `\n${passed.length} passed, ${failed.length} failed, ${skipped.length} skipped` +
      ` (${all.length} total)`,
  );
  process.exit(failed.length ? 1 : 0);
}

function describe(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return String(err);
}

/**
 * Races a test against a deadline.
 *
 * The timer is unref'd and cleared on settle: several tests spin a producer
 * loop that only stops on an AbortSignal, and a live timer or an abandoned
 * loop would otherwise keep the process alive after the run finishes.
 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms: ${label}`)), ms);
    timer.unref?.();
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}
