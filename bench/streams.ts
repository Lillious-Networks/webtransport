/**
 * Stream setup rate and bulk transfer baseline.
 *
 *   bun bench/streams.ts
 */

import { WebTransport, generateSelfSigned, serve } from "../js/index.js";

const { cert, key, hash } = generateSelfSigned(["localhost"]);

/** Drains every incoming stream as fast as it can. */
async function startSink() {
  return await serve({
    port: 0,
    hostname: "127.0.0.1",
    cert,
    key,
    async session(session) {
      const reader = session.incomingUnidirectionalStreams.getReader();
      for (;;) {
        const { value: stream, done } = await reader.read();
        if (done) break;
        // Drain each stream on its own task so setup is not serialised
        // behind transfer.
        (async () => {
          const r = stream.getReader();
          try {
            for (;;) {
              const { done } = await r.read();
              if (done) break;
            }
          } catch {
            // The session ended.
          }
        })();
      }
    },
  });
}

async function connect(port: number) {
  const wt = new WebTransport(`https://localhost:${port}/bench`, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
  });
  await wt.ready;
  return wt;
}

async function measureSetupRate(port: number) {
  const wt = await connect(port);
  const count = 500;
  const start = performance.now();
  for (let i = 0; i < count; i++) {
    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new Uint8Array(8));
    await writer.close();
  }
  const elapsed = (performance.now() - start) / 1000;
  wt.close();
  return { perSecond: Math.round(count / elapsed) };
}

async function measureBulk(port: number, bytes: number) {
  const wt = await connect(port);
  const stream = await wt.createUnidirectionalStream();
  const writer = stream.getWriter();

  const chunk = new Uint8Array(64 * 1024);
  const chunks = Math.ceil(bytes / chunk.byteLength);

  const start = performance.now();
  for (let i = 0; i < chunks; i++) await writer.write(chunk);
  await writer.close();
  const elapsed = (performance.now() - start) / 1000;
  wt.close();

  const total = chunks * chunk.byteLength;
  return { mbps: (total * 8) / elapsed / 1e6, seconds: elapsed };
}

const server = await startSink();
console.log(`sink server on port ${server.port}\n`);

const setup = await measureSetupRate(server.port);
console.log(`stream setup:  ${setup.perSecond} streams/s`);

for (const size of [16, 64, 256]) {
  const r = await measureBulk(server.port, size * 1024 * 1024);
  console.log(
    `bulk ${String(size).padStart(4)}MB:  ${r.mbps.toFixed(0).padStart(6)} Mbit/s  (${r.seconds.toFixed(2)}s)`,
  );
}

server.stop();
process.exit(0);
