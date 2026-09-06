/**
 * Memory and concurrency baseline.
 *
 * Measures what many concurrent sessions and streams actually cost, which is
 * the number milestone 4's tuning has to move.
 *
 *   bun bench/memory.ts
 */

import { WebTransport, generateSelfSigned, serve } from "../js/index.js";

const { cert, key, hash } = generateSelfSigned(["localhost"]);

/** Resident set size in MB, after giving the GC a chance to run. */
function rss(): number {
  Bun.gc(true);
  return process.memoryUsage().rss / 1024 / 1024;
}

async function startServer() {
  const sessions: any[] = [];
  const server = await serve({
    port: 0,
    hostname: "127.0.0.1",
    cert,
    key,
    maxSessions: 4096,
    async session(session) {
      sessions.push(session);
      // Drain anything sent, so writers are never blocked by an idle reader.
      const reader = session.incomingUnidirectionalStreams.getReader();
      try {
        for (;;) {
          const { value: stream, done } = await reader.read();
          if (done) break;
          void (async () => {
            const r = stream.getReader();
            try {
              for (;;) {
                const { done } = await r.read();
                if (done) break;
              }
            } catch {
              // Session ended.
            }
          })();
        }
      } catch {
        // Session ended.
      }
    },
  });
  return { server, sessions };
}

async function connect(port: number) {
  const wt = new WebTransport(`https://localhost:${port}/bench`, {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
  });
  await wt.ready;
  return wt;
}

async function measureSessions(port: number, count: number) {
  const before = rss();
  const start = performance.now();

  const clients: any[] = [];
  for (let i = 0; i < count; i++) clients.push(await connect(port));

  const elapsed = (performance.now() - start) / 1000;
  const after = rss();

  return {
    perSecond: Math.round(count / elapsed),
    kbEach: ((after - before) * 1024) / count,
    clients,
  };
}

async function measureStreams(wt: any, count: number) {
  const before = rss();
  const start = performance.now();

  const streams: any[] = [];
  for (let i = 0; i < count; i++) {
    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new Uint8Array(64));
    streams.push({ stream, writer });
  }

  const elapsed = (performance.now() - start) / 1000;
  const after = rss();

  // Close them all so the next measurement starts clean.
  for (const { writer } of streams) await writer.close();

  return {
    perSecond: Math.round(count / elapsed),
    kbEach: ((after - before) * 1024) / count,
  };
}

/** Datagram round-trip under many concurrent sessions. */
async function measureConcurrentDatagrams(clients: any[], perClient: number) {
  const payload = new Uint8Array(256);
  const start = performance.now();

  await Promise.all(
    clients.map(async (wt) => {
      const writer = wt.datagrams.createWritable().getWriter();
      for (let i = 0; i < perClient; i++) await writer.write(payload);
    }),
  );

  const elapsed = (performance.now() - start) / 1000;
  const total = clients.length * perClient;
  return {
    perSecond: Math.round(total / elapsed),
    mbps: (total * payload.byteLength * 8) / elapsed / 1e6,
  };
}

const { server } = await startServer();
console.log(`server on port ${server.port}`);
console.log(`cores available: ${navigator.hardwareConcurrency}\n`);

console.log("concurrent sessions");
for (const count of [50, 200]) {
  const r = await measureSessions(server.port, count);
  console.log(
    `  ${String(count).padStart(4)} sessions:  ${String(r.perSecond).padStart(5)} /s  ${r.kbEach.toFixed(0).padStart(5)} KB each`,
  );
  if (count === 200) {
    const d = await measureConcurrentDatagrams(r.clients, 100);
    console.log(
      `\ndatagrams across ${count} sessions: ${d.perSecond} /s, ${d.mbps.toFixed(1)} Mbit/s`,
    );
  }
  for (const wt of r.clients) wt.close();
  await Bun.sleep(100);
}

console.log("\nconcurrent streams on one session");
const wt = await connect(server.port);
for (const count of [200, 1000]) {
  const r = await measureStreams(wt, count);
  console.log(
    `  ${String(count).padStart(4)} streams:   ${String(r.perSecond).padStart(5)} /s  ${r.kbEach.toFixed(1).padStart(5)} KB each`,
  );
}
wt.close();

console.log(`\nfinal RSS: ${rss().toFixed(0)} MB`);
server.stop();
process.exit(0);
