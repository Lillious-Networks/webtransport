/**
 * Chromium interop check.
 *
 * Serves a WebTransport endpoint plus a plain HTTP page that drives a real
 * browser's WebTransport client against it, and reports what it saw.
 *
 *   bun examples/04-chrome-interop.ts
 *
 * Then open http://127.0.0.1:8099/ in whichever browser you are checking.
 * The page reports back to this process, so the result appears in this
 * terminal as well as on the page, labelled with the browser that sent it.
 * Several browsers can report in one run, and each keeps its own verdict.
 *
 * This exists because our own client cannot catch browser-facing bugs: both
 * ends share our assumptions. A browser exercises QPACK Huffman coding, the
 * full static table, and the SETTINGS ordering rules that our client never
 * stresses.
 */
import { generateSelfSigned, serve } from "../js/index.ts";

// Surface the engine's own tracing, which is where a handshake that fails
// before our CONNECT handler reports why.
process.env.RUST_LOG ||= "wt_core=debug";

const { cert, key, hash } = generateSelfSigned(["localhost", "127.0.0.1"]);
const WT_PORT = 4433;
const PAGE_PORT = 8099;

/// What each browser reported, keyed by the name derived from its user agent.
///
/// Per browser rather than one flag: a later PASS used to overwrite an earlier
/// FAIL, so the summary reflected whichever browser reported last and a real
/// failure could read as green.
const results = new Map<string, "pass" | "fail">();

const wtServer = await serve({
  port: WT_PORT,
  hostname: "127.0.0.1",
  cert,
  key,
  maxSessions: 16,
  async session(session, request) {
    console.log(`server: session accepted on ${request.path}`);
    console.log(`server: headers ${[...request.headers].map(([k, v]) => `${k}=${v}`).join(" ")}`);

    // Echo a datagram and a stream, so the browser confirms data actually
    // flows rather than only that the handshake completed.
    try {
      const reader = session.datagrams.readable.getReader();
      const writer = session.datagrams.createWritable().getWriter();
      const { value } = await reader.read();
      console.log(`server: datagram ${JSON.stringify(new TextDecoder().decode(value))}`);
      await writer.write(new TextEncoder().encode("pong"));

      const streams = session.incomingUnidirectionalStreams.getReader();
      const { value: incoming } = await streams.read();
      console.log(`server: stream ${JSON.stringify(await new Response(incoming).text())}`);
    } catch (err: any) {
      console.log(`server: session ended: ${err?.message ?? err}`);
    }
  },
  error(err: any) {
    console.log(`server error: ${err?.message ?? err}`);
  },
});

const hashBytes = [...hash].join(",");

const page = `<!doctype html>
<meta charset="utf-8">
<title>WebTransport interop</title>
<style>body{font:14px/1.5 system-ui;padding:2rem}pre{background:#f4f4f5;padding:1rem;border-radius:6px}</style>
<h1>WebTransport interop</h1>
<pre id="out">running...</pre>
<script>
const out = document.getElementById("out");
const lines = [];
const log = (m) => {
  lines.push(m);
  out.textContent = lines.join("\\n");
  fetch("/report", { method: "POST", body: m }).catch(() => {});
};

(async () => {
  try {
    const wt = new WebTransport("https://127.0.0.1:${WT_PORT}/interop", {
      serverCertificateHashes: [{
        algorithm: "sha-256",
        value: new Uint8Array([${hashBytes}]),
      }],
    });
    await wt.ready;
    log("ready: handshake succeeded");
    log("reliability: " + wt.reliability);

    // The CR replaced \`datagrams.writable\` with \`createWritable()\`, and
    // browsers are at different points in that move, so take whichever the
    // one under test offers.
    const datagramsWritable =
      typeof wt.datagrams.createWritable === "function"
        ? wt.datagrams.createWritable()
        : wt.datagrams.writable;
    const dw = datagramsWritable.getWriter();
    await dw.write(new TextEncoder().encode("ping"));
    log("sent datagram");

    const dr = wt.datagrams.readable.getReader();
    const { value } = await dr.read();
    log("got datagram: " + JSON.stringify(new TextDecoder().decode(value)));

    const s = await wt.createUnidirectionalStream();
    const w = s.getWriter();
    await w.write(new TextEncoder().encode("hello from the browser"));
    await w.close();
    log("sent stream");

    log("PASS");
  } catch (err) {
    log("FAIL: " + err);
  }
})();
</script>
`;

/// Names the browser from its user agent, for labelling its output.
///
/// Order matters: Edge and Chrome both claim "Chrome", and every WebKit
/// browser carries "Safari", so the more specific tokens are tested first.
function browserName(userAgent: string): string {
  if (userAgent.includes("Firefox/")) return "firefox";
  if (userAgent.includes("Edg/")) return "edge";
  if (userAgent.includes("Chrome/")) return "chrome";
  if (userAgent.includes("Safari/")) return "safari";
  return "browser";
}

Bun.serve({
  port: PAGE_PORT,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/report") {
      const message = await req.text();
      const name = browserName(req.headers.get("user-agent") ?? "");
      console.log(`${name}: ${message}`);

      if (message === "PASS") results.set(name, "pass");
      if (message.startsWith("FAIL")) results.set(name, "fail");

      // Summarised only when a browser reaches a verdict, and never
      // downgraded: a browser that failed stays failed however many others
      // pass afterwards.
      if (message === "PASS" || message.startsWith("FAIL")) {
        const summary = [...results]
          .map(([browser, outcome]) => `${browser} ${outcome.toUpperCase()}`)
          .join(", ");
        const failed = [...results.values()].includes("fail");
        console.log(`
interop ${failed ? "FAILED" : "PASSED"}: ${summary}
`);
      }
      return new Response("ok");
    }
    return new Response(page, { headers: { "content-type": "text/html" } });
  },
});

console.log(`WebTransport server on https://127.0.0.1:${WT_PORT}`);
console.log(`\nOpen this in a browser:  http://127.0.0.1:${PAGE_PORT}/\n`);
console.log("No flags needed: the page pins the certificate by hash.");
console.log("Press Ctrl+C when done.\n");
