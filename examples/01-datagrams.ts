/**
 * Milestone 1: a session and datagrams, end to end.
 *
 *   bun examples/01-datagrams.ts
 */

import { WebTransport, generateSelfSigned, serve } from "../js/index.js";

// WebTransport requires TLS even locally. The client trusts this certificate by
// its hash, which is what serverCertificateHashes is for.
const { cert, key, hash } = generateSelfSigned(["localhost"]);

const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  async session(session, request) {
    console.log(`server: session opened on ${request.path}`);

    const reader = session.datagrams.readable.getReader();
    const writer = session.datagrams.createWritable().getWriter();

    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      const text = new TextDecoder().decode(value);
      console.log(`server: received ${JSON.stringify(text)}`);
      await writer.write(new TextEncoder().encode(text.toUpperCase()));
    }
  },
});

console.log(`server: listening on port ${server.port}`);

const wt = new WebTransport(`https://localhost:${server.port}/echo`, {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
});

await wt.ready;
console.log(`client: connected, reliability=${wt.reliability}`);
console.log(`client: maxDatagramSize=${wt.datagrams.maxDatagramSize}`);

const writer = wt.datagrams.createWritable().getWriter();
const reader = wt.datagrams.readable.getReader();

for (const message of ["hello", "from", "webtransport"]) {
  await writer.write(new TextEncoder().encode(message));
  const { value } = await reader.read();
  console.log(`client: echoed back ${JSON.stringify(new TextDecoder().decode(value))}`);
}

wt.close({ closeCode: 0, reason: "done" });
const info = await wt.closed;
console.log(`client: closed (code ${info.closeCode}, reason ${JSON.stringify(info.reason)})`);

await server.stop();
process.exit(0);
