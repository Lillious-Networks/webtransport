/**
 * Stress server: echo or room-relay endpoint with per-second counters.
 *
 *   bun bench/stress-server.ts [seconds] [--relay <room-size>]
 *
 * With --relay K, sessions are grouped into rooms of K and every datagram is
 * relayed to all K members (including the sender), which multiplies the
 * server's send load by K, the shape of a multiplayer movement server.
 */
import { generateSelfSigned, serve } from "../js/index.ts";

const DURATION_S = Number(process.argv[2] ?? 30);
const relayArg = process.argv.indexOf("--relay");
const ROOM = relayArg >= 0 ? Number(process.argv[relayArg + 1] ?? 0) : 0;
const workArg = process.argv.indexOf("--work-us");
const WORK_US = workArg >= 0 ? Number(process.argv[workArg + 1] ?? 0) : 0;
const { cert, key, hash } = generateSelfSigned(["localhost"]);

/** Burns roughly `us` microseconds of CPU, simulating per-datagram app work. */
function burn(us: number) {
  if (us <= 0) return;
  const end = performance.now() + us / 1000;
  while (performance.now() < end) {}
}

let recv = 0;
let sent = 0;
let sessions = 0;
let closed = 0;
const dropBySession = new Map();
const udpBySession = new Map();
type DatagramWriter = WritableStreamDefaultWriter<ArrayBuffer | ArrayBufferView>;
const rooms: DatagramWriter[][] = [];
let current: DatagramWriter[] | null = null;

const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  maxSessions: 4096,
  async session(session) {
    sessions++;
    const reader = session.datagrams.readable.getReader();
    const writer = session.datagrams.createWritable().getWriter();
    // Observe how this session ends: who closed it, and with what code. A
    // disconnect the application never asked for is the interesting case.
    session.closed.then((info) => {
      closed++;
      if (info.closeCode !== 0 || info.reason !== "") {
        console.log(`session closed: code=${info.closeCode} reason=${JSON.stringify(info.reason)} (${closed} so far)`);
      }
    });
    const room = ROOM
      ? (() => {
          if (!current || current.length >= ROOM) {
            current = [];
            rooms.push(current);
          }
          current.push(writer);
          return current;
        })()
      : null;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      recv++;
      burn(WORK_US);
      if (room) {
        for (const w of room) await w.write(value);
        sent += room.length;
      } else {
        await writer.write(value);
        sent++;
      }
      dropBySession.set(session, session.datagramsDropped);
      udpBySession.set(session, session.udpPacketsReceived);
    }
  },
});

const totalDropped = () => [...dropBySession.values()].reduce((a, b) => a + b, 0n);
const totalUdp = () => [...udpBySession.values()].reduce((a, b) => a + b, 0n);

console.log(`PORT ${server.port} HASH ${Buffer.from(hash).toString("hex")} MODE ${ROOM ? `relay-${ROOM}` : "echo"} WORK ${WORK_US}us`);
const started = Date.now();
const tick = setInterval(() => {
  const elapsed = (Date.now() - started) / 1000;
  console.log(`t=${elapsed.toFixed(1)}s sessions=${sessions} recv=${recv} sent=${sent} dropped=${totalDropped()} udp=${totalUdp()} rate=${(recv / elapsed).toFixed(0)}/s send=${(sent / elapsed).toFixed(0)}/s`);
}, 5000);

await Bun.sleep(DURATION_S * 1000);
clearInterval(tick);
const elapsed = (Date.now() - started) / 1000;
console.log(`FINAL sessions=${sessions} recv=${recv} sent=${sent} dropped=${totalDropped()} rate=${(recv / elapsed).toFixed(0)}/s`);
process.exit(0);
