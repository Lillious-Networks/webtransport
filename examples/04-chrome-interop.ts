/**
 * Chromium interop check.
 *
 * Serves a WebTransport endpoint plus a plain HTTP page that drives a real
 * Chrome WebTransport client against it, and reports what the browser saw.
 *
 *   bun examples/04-chrome-interop.ts
 *
 * Then open http://127.0.0.1:8099/ in Chrome. The page reports back to this
 * process, so the result appears in this terminal as well as on the page.
 *
 * This exists because our own client cannot catch browser-facing bugs: both
 * ends share our assumptions. A browser exercises QPACK Huffman coding, the
 * full static table, and the SETTINGS ordering rules that our client never
 * stresses.
 */
import { generateSelfSigned, serve } from "../js/index.js";

// Surface the engine's own tracing, which is where a handshake that fails
// before our CONNECT handler reports why.
process.env.RUST_LOG ||= "wt_core=debug";

const { cert, key, hash } = generateSelfSigned(["localhost", "127.0.0.1"]);
const WT_PORT = 4433;
const PAGE_PORT = 8099;

let passed = false;

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

    const dw = wt.datagrams.writable.getWriter();
    await dw.write(new TextEncoder().encode("ping"));
    log("sent datagram");

    const dr = wt.datagrams.readable.getReader();
    const { value } = await dr.read();
    log("got datagram: " + JSON.stringify(new TextDecoder().decode(value)));

    const s = await wt.createUnidirectionalStream();
    const w = s.getWriter();
    await w.write(new TextEncoder().encode("hello from chrome"));
    await w.close();
    log("sent stream");

    log("PASS");
  } catch (err) {
    log("FAIL: " + err);
  }
})();
</script>
`;

Bun.serve({
  port: PAGE_PORT,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/report") {
      const message = await req.text();
      console.log(`chrome: ${message}`);
      if (message === "PASS") passed = true;
      if (message.startsWith("FAIL")) {
        console.log("\ninterop FAILED");
      }
      if (passed) console.log("\ninterop PASSED");
      return new Response("ok");
    }
    return new Response(page, { headers: { "content-type": "text/html" } });
  },
});

console.log(`WebTransport server on https://127.0.0.1:${WT_PORT}`);
console.log(`\nOpen this in Chrome:  http://127.0.0.1:${PAGE_PORT}/\n`);
console.log("Chrome needs no flags: the page pins the certificate by hash.");
console.log("Press Ctrl+C when done.\n");
