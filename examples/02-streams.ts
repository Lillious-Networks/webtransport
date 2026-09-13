/**
 * Milestone 2: streams, both directions, with backpressure.
 *
 *   bun examples/02-streams.ts
 */

import { WebTransport, generateSelfSigned, serve } from "../js/index.ts";

const { cert, key, hash } = generateSelfSigned(["localhost"]);

const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  async session(session, request) {
    console.log(`server: session on ${request.path}`);

    // Echo every bidirectional stream back, uppercased.
    const reader = session.incomingBidirectionalStreams.getReader();
    for (;;) {
      const { value: stream, done } = await reader.read();
      if (done) break;

      const text = await new Response(stream.readable).text();
      console.log(`server: received ${JSON.stringify(text)}`);

      const writer = stream.writable.getWriter();
      await writer.write(new TextEncoder().encode(text.toUpperCase()));
      await writer.close();
    }
  },
});

console.log(`server: listening on port ${server.port}`);

const wt = new WebTransport(`https://localhost:${server.port}/echo`, {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
});
await wt.ready;
console.log("client: connected");

for (const message of ["hello", "streams"]) {
  const stream = await wt.createBidirectionalStream();
  const writer = stream.writable.getWriter();
  await writer.write(new TextEncoder().encode(message));
  await writer.close();

  const echoed = await new Response(stream.readable).text();
  console.log(`client: echoed back ${JSON.stringify(echoed)}`);
}

// A unidirectional stream, sending only.
const uni = await wt.createUnidirectionalStream();
const uniWriter = uni.getWriter();
await uniWriter.write(new TextEncoder().encode("one way"));
await uniWriter.close();
console.log("client: sent a unidirectional stream");

// Stream stats.
const stats = await uni.getStats();
console.log(`client: wrote ${stats.bytesWritten} bytes on that stream`);

wt.close({ closeCode: 0, reason: "done" });
const info = await wt.closed;
console.log(`client: closed (code ${info.closeCode})`);

await server.stop();
process.exit(0);
