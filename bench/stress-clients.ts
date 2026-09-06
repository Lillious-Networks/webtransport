/**
 * Stress clients: N movement clients against a stress server.
 *
 *   bun bench/stress-clients.ts <port> <hashHex> <clients> <rate-per-second> [seconds] [payload-bytes]
 *
 * The server prints `<port> <hashHex>` on its first line; pass both so the
 * clients pin the server's actual certificate. Each client sends a paced
 * movement datagram and times the echo. The payload size defaults to 24
 * bytes; sizes above 63 exercise the LEB128 batch framing that short test
 * vectors cannot.
 */
import { WebTransport } from "../js/index.js";

const port = Number(process.argv[2] ?? 0);
const hashHex = process.argv[3] ?? "";
const N = Number(process.argv[4] ?? 1000);
const RATE = Number(process.argv[5] ?? 11.5);
const DURATION_S = Number(process.argv[6] ?? 30);
const PAYLOAD_SIZE = Math.max(16, Number(process.argv[7] ?? 24));
const RELAY = process.argv[8] === "relay";
// Game-style arrival: B back-to-back sends, then a pause B× the pacing gap.
// The average rate is unchanged; only the burstiness differs.
const BURST = Math.max(1, Number(process.argv[9] ?? 1));
// Simulated per-datagram application work (µs of CPU burn per received echo).
const RECV_WORK_US = Number(process.argv[10] ?? 0);

/** Burns roughly `us` microseconds of CPU. */
function burn(us: number) {
  if (us <= 0) return;
  const end = performance.now() + us / 1000;
  while (performance.now() < end) {}
}

if (!port || !hashHex) throw new Error("usage: stress-clients.ts <port> <hashHex> <clients> <rate> [seconds] [payload-bytes]");

const hash = Uint8Array.from(Buffer.from(hashHex, "hex"));

let sent = 0;
let echoed = 0;
let failedClients = 0;
let corrupted = 0;
let connected = 0;
let peerCloses = 0;
const latencies: number[] = [];
const intervalMs = 1000 / RATE;

async function runClient(id: number) {
  try {
    const wt = new WebTransport(`https://localhost:${port}/stress`, {
      serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
    });
    await wt.ready;
    connected++;

    // A close the client did not ask for is the interesting case: log who did
    // it and with what code. A clean local close carries code 0.
    wt.closed.then((info) => {
      if (info.closeCode !== 0 || info.reason !== "") {
        peerCloses++;
        console.log(`client ${id}: closed by peer code=${info.closeCode} reason=${JSON.stringify(info.reason)}`);
      }
    });

    const payload = new Uint8Array(PAYLOAD_SIZE);
    const view = new DataView(payload.buffer);
    payload.fill(0x61, 16);
    payload[16] = id & 0xff;
    payload[17] = (id >> 8) & 0xff;
    const reader = wt.datagrams.readable.getReader();
    const writer = wt.datagrams.createWritable().getWriter();

    const receiver = (async () => {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        echoed++;
        burn(RECV_WORK_US);
        if (!RELAY && (value.length !== PAYLOAD_SIZE || value[16] !== payload[16] || value[17] !== payload[17])) {
          corrupted++;
        }
        latencies.push(performance.now() - view.getFloat64(8, true));
      }
    })();

    let seq = 0;
    const deadline = Date.now() + DURATION_S * 1000;
    while (Date.now() < deadline) {
      for (let b = 0; b < BURST; b++) {
        view.setFloat64(0, seq++, true);
        view.setFloat64(8, performance.now(), true);
        await writer.write(payload);
        sent++;
      }
      await Bun.sleep(intervalMs * BURST);
    }
    wt.close();
    await Promise.race([receiver, Bun.sleep(1000)]);
  } catch (err) {
    failedClients++;
    console.log(`client ${id} failed: ${(err as Error)?.message ?? err}`);
  }
}

const started = Date.now();
await Promise.all(Array.from({ length: N }, (_, i) => runClient(i)));
await Bun.sleep(2000);

latencies.sort((a, b) => a - b);
const pct = (p: number) => latencies[Math.min(latencies.length - 1, Math.floor((p / 100) * latencies.length))];
const avg = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
console.log(`duration: ${((Date.now() - started) / 1000).toFixed(1)}s`);
console.log(`connected: ${connected}/${N}  failed: ${failedClients}  peerClosed: ${peerCloses}`);
console.log(`sent: ${sent}  echoed: ${echoed}  loss: ${(((sent - echoed) / sent) * 100).toFixed(2)}%  (${sent - echoed})  corrupted: ${corrupted}  payload: ${PAYLOAD_SIZE}B`);
if (latencies.length) {
  console.log(`one-way ms: min ${latencies[0]?.toFixed(1)}  avg ${avg.toFixed(1)}  p95 ${pct(95).toFixed(1)}  p99 ${pct(99).toFixed(1)}  max ${latencies[latencies.length - 1]?.toFixed(1)}  samples ${latencies.length}`);
} else {
  console.log("no latency samples");
}
process.exit(0);
