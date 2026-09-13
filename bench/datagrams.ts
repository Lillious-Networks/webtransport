/**
 * Datagram throughput and latency baseline.
 *
 * Establishes the numbers milestone 4 tunes against, so a regression is visible
 * as it happens rather than at the end.
 *
 *   bun bench/datagrams.ts
 */

import { WebTransport, generateSelfSigned, serve } from "../js/index.ts";

const PAYLOAD_SIZES = [64, 512, 1024];
const THROUGHPUT_DURATION_MS = 3000;
const LATENCY_SAMPLES = 1000;

const { cert, key, hash } = generateSelfSigned(["localhost"]);

/** Echoes every datagram back, for round-trip timing. */
async function startEchoServer() {
  return await serve({
    port: 0,
    hostname: "127.0.0.1",
    cert,
    key,
    async session(session) {
      const reader = session.datagrams.readable.getReader();
      const writer = session.datagrams.createWritable().getWriter();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          await writer.write(value);
        }
      } catch {
        // The session ended; nothing to clean up.
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

function percentile(sorted: number[], p: number) {
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[index];
}

async function measureThroughput(port: number, size: number) {
  const wt = await connect(port);
  const writer = wt.datagrams.createWritable().getWriter();
  const payload = new Uint8Array(size).fill(0x61);

  let sent = 0;
  const start = performance.now();
  while (performance.now() - start < THROUGHPUT_DURATION_MS) {
    // Send in batches so the loop's own overhead does not dominate.
    for (let i = 0; i < 100; i++) {
      await writer.write(payload);
      sent++;
    }
  }
  const elapsed = (performance.now() - start) / 1000;
  wt.close();

  const mbps = (sent * size * 8) / elapsed / 1e6;
  return { size, sent, perSecond: Math.round(sent / elapsed), mbps };
}

async function measureLatency(port: number) {
  const wt = await connect(port);
  const writer = wt.datagrams.createWritable().getWriter();
  const reader = wt.datagrams.readable.getReader();
  const payload = new Uint8Array(64);

  const samples: number[] = [];
  // Warm up so the first samples do not include path discovery.
  for (let i = 0; i < 50; i++) {
    await writer.write(payload);
    await reader.read();
  }

  for (let i = 0; i < LATENCY_SAMPLES; i++) {
    const start = performance.now();
    await writer.write(payload);
    await reader.read();
    samples.push(performance.now() - start);
  }
  wt.close();

  samples.sort((a, b) => a - b);
  return {
    p50: percentile(samples, 50),
    p95: percentile(samples, 95),
    p99: percentile(samples, 99),
  };
}

const server = await startEchoServer();
console.log(`echo server on port ${server.port}\n`);

console.log("throughput (client -> server)");
for (const size of PAYLOAD_SIZES) {
  const r = await measureThroughput(server.port, size);
  console.log(
    `  ${String(size).padStart(5)}B  ${String(r.perSecond).padStart(8)} dg/s  ${r.mbps.toFixed(1).padStart(7)} Mbit/s`,
  );
}

console.log("\nround-trip latency (64B, echoed)");
const l = await measureLatency(server.port);
console.log(`  p50 ${l.p50.toFixed(3)} ms`);
console.log(`  p95 ${l.p95.toFixed(3)} ms`);
console.log(`  p99 ${l.p99.toFixed(3)} ms`);

server.stop();
process.exit(0);
