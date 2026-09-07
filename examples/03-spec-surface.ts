/**
 * Milestone 3: send groups and ordering, keying material, stats.
 *
 *   bun examples/03-spec-surface.ts
 */

import { WebTransport, generateSelfSigned, serve } from "../js/index.js";

const { cert, key, hash } = generateSelfSigned(["localhost"]);

const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  async session(session) {
    const reader = session.incomingUnidirectionalStreams.getReader();
    for (;;) {
      const { value: stream, done } = await reader.read();
      if (done) break;
      const text = await new Response(stream).text();
      console.log(`server: received ${JSON.stringify(text)}`);
    }
  },
});

const wt = new WebTransport(`https://localhost:${server.port}/spec`, {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
  congestionControl: "low-latency",
});
await wt.ready;
console.log(`client: connected (congestionControl=${wt.congestionControl})`);

// Send groups are equal claimants on bandwidth, each with its own sendOrder
// numberspace.
const urgent = wt.createSendGroup();
const bulk = wt.createSendGroup();

// sendOrder is 64-bit: values beyond Number.MAX_SAFE_INTEGER stay exact.
const high = await wt.createUnidirectionalStream({
  sendGroup: urgent,
  sendOrder: 9007199254740993n,
});
const low = await wt.createUnidirectionalStream({
  sendGroup: bulk,
  sendOrder: 1n,
});
console.log(`client: high stream sendOrder=${high.sendOrder}`);
console.log(`client: low  stream sendOrder=${low.sendOrder}`);

const hw = high.getWriter();
const lw = low.getWriter();
await hw.write(new TextEncoder().encode("urgent"));
await lw.write(new TextEncoder().encode("bulk"));
await hw.close();
await lw.close();

// Group statistics total their streams.
console.log(`client: urgent group wrote ${(await urgent.getStats()).bytesWritten} bytes`);

// Keying material is bound to this session, not just the TLS connection.
const material = await wt.exportKeyingMaterial(
  new TextEncoder().encode("my-label"),
  new TextEncoder().encode("my-context"),
  32,
);
console.log(`client: derived ${material.byteLength} bytes of keying material`);

// Stats report what the transport can actually source; members it cannot are
// absent rather than reported as zero.
const stats = await wt.getStats();
console.log(
  `client: sent ${stats.bytesSent} bytes in ${stats.packetsSent} packets, ` +
    `rtt ${stats.smoothedRtt.toFixed(2)}ms`,
);
console.log(`client: rttVariation present? ${"rttVariation" in stats}`);

await Bun.sleep(200);
wt.close({ closeCode: 0, reason: "done" });
await wt.closed;
console.log("client: closed");

await server.stop();
process.exit(0);
