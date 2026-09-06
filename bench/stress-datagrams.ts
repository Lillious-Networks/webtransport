/**
 * Sustained datagram echo load test with per-hop counters and latency.
 *
 *   bun bench/stress-datagrams.ts            # app-style sends (writer.write)
 *   bun bench/stress-datagrams.ts --batch    # fast path (sendSyncBatch), finds the server ceiling
 */
import { WebTransport, generateSelfSigned, serve } from "../js/index.js";

const DURATION_MS = 10000;
const { cert, key, hash } = generateSelfSigned(["localhost"]);
const FAST = process.argv.includes("--batch");

const counts = { serverRecv: 0, serverEcho: 0 };

const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  async session(session) {
    const reader = session.datagrams.readable.getReader();
    const writer = session.datagrams.createWritable().getWriter();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      counts.serverRecv++;
      await writer.write(value);
      counts.serverEcho++;
    }
  },
});

const wt = new WebTransport(`https://localhost:${server.port}/stress`, {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
});
await wt.ready;

const reader = wt.datagrams.readable.getReader();
const payload = new Uint8Array(24);
const view = new DataView(payload.buffer);
const sentTimes = new Map();
const latencies: number[] = [];
let nextId = 0;
let totalSent = 0;
let totalEchoed = 0;
let late = 0;

let stop = false;
const writer = wt.datagrams.createWritable().getWriter();
const sender = (async () => {
  const stamp = () => {
    view.setFloat64(0, nextId, true);
    view.setFloat64(8, performance.now(), true);
    sentTimes.set(nextId, performance.now());
    if (sentTimes.size > 200000) sentTimes.delete(nextId - 200000);
    nextId++;
    totalSent++;
  };
  while (!stop) {
    if (FAST) {
      const batch = [];
      for (let i = 0; i < 1000; i++) {
        stamp();
        batch.push(payload.slice());
      }
      wt.datagrams.sendSyncBatch(batch);
      await Bun.sleep(0);
    } else {
      for (let i = 0; i < 200; i++) {
        stamp();
        await writer.write(payload);
      }
      await Bun.sleep(0);
    }
  }
})();

const receiver = (async () => {
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    totalEchoed++;
    const id = view.getFloat64(0, true);
    const sent = sentTimes.get(id);
    if (sent === undefined) { late++; continue; }
    sentTimes.delete(id);
    latencies.push((performance.now() - sent) / 2);
  }
})();

await Bun.sleep(DURATION_MS);
stop = true;
await sender;
await Bun.sleep(1500);
wt.close();
await Promise.race([receiver, Bun.sleep(2000)]);

const rate = (n: number) => (n / (DURATION_MS / 1000)).toFixed(0);
latencies.sort((a, b) => a - b);
const pct = (p: number) => latencies[Math.min(latencies.length - 1, Math.floor((p / 100) * latencies.length))];
console.log(`mode: ${FAST ? "batch" : "writer.write"}`);
console.log(`client sent:   ${totalSent} (${rate(totalSent)}/s)`);
console.log(`server recv:   ${counts.serverRecv} (${rate(counts.serverRecv)}/s)  ${((1 - counts.serverRecv / totalSent) * 100).toFixed(1)}% lost inbound`);
console.log(`server echoed: ${counts.serverEcho} (${rate(counts.serverEcho)}/s)`);
console.log(`client echoed: ${totalEchoed}  ${((1 - totalEchoed / totalSent) * 100).toFixed(1)}% total loss  (${late} outside tracking window)`);
if (latencies.length) {
  console.log(`one-way ms: min ${latencies[0].toFixed(2)}  avg ${(latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(2)}  p95 ${pct(95).toFixed(2)}  p99 ${pct(99).toFixed(2)}  max ${latencies[latencies.length - 1].toFixed(2)}`);
}

process.exit(0);
