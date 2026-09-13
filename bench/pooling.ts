/**
 * What pooling saves.
 *
 * A dedicated session carries a whole QUIC connection: TLS session state, a
 * congestion controller, packet buffers. Pooled sessions share one, so the
 * marginal cost is just the session's own routing state.
 *
 *   bun bench/pooling.ts
 */

import { generateSelfSigned, serve } from "../js/index.ts";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
// The napi layer applies pooling without the spec's JS-level ban on combining
// it with certificate pinning, so both paths can be measured against the same
// self-signed server. Applications go through the JS API, where that rule holds.
const native = require("../wt.node");

const { cert, key, hash } = generateSelfSigned(["localhost"]);
const server = await serve({
  port: 0,
  hostname: "127.0.0.1",
  cert,
  key,
  maxSessions: 8192,
  session() {},
});

function mb(): number {
  Bun.gc(true);
  return process.memoryUsage().rss / 1048576;
}

const url = `https://localhost:${server.port}/bench`;

async function measure(label: string, allowPooling: boolean, count: number) {
  const before = mb();
  const start = performance.now();

  const held: any[] = [];
  for (let i = 0; i < count; i++) {
    held.push(
      await native.connect(url, {
        serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
        allowPooling,
      }),
    );
  }

  const elapsed = (performance.now() - start) / 1000;
  const kbEach = ((mb() - before) * 1024) / count;
  console.log(
    `${label.padEnd(11)} ${String(Math.round(count / elapsed)).padStart(5)} sessions/s   ` +
      `${kbEach.toFixed(0).padStart(5)} KB each`,
  );
  return { kbEach, held };
}

console.log(`server on port ${server.port}\n`);

const COUNT = 300;
const dedicated = await measure("dedicated", false, COUNT);
const pooled = await measure("pooled", true, COUNT);

const ratio = dedicated.kbEach / Math.max(pooled.kbEach, 0.001);
console.log(`\npooling uses ${ratio.toFixed(0)}x less memory per session`);

server.stop();
process.exit(0);
