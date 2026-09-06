/**
 * Server-side loss locator: drop this into your own session handler to get
 * per-hop attribution when datagrams go missing.
 *
 *   import { datagramLossProbe } from "../bench/datagram-probe.js";
 *   async session(session) {
 *     const probe = datagramLossProbe(session, "room-7");
 *     // ... your handler ...
 *   }
 *
 * Every 5s it prints one line per session with movement, unless everything is
 * clean, in which case it prints a single summary line on session close.
 */

/** @param {object} session the server-side session object */
export function datagramLossProbe(session, label) {
  let read = 0n;
  let written = 0n;
  const startDropped = session.datagramsDropped;
  const startUdp = session.udpPacketsReceived;
  let warned = false;

  const timer = setInterval(() => {
    const dropped = session.datagramsDropped - startDropped;
    const udp = session.udpPacketsReceived - startUdp;
    if (dropped > 0n || read - written > 4096n) {
      warned = true;
      console.log(
        `[probe ${label}] read=${read} written=${written} queueDropped=${dropped} udpRecv=${udp} backlog=${read - written}`,
      );
    }
  }, 5000);

  return {
    /** Call once per datagram your handler reads. */
    onRead() {
      read++;
    },
    /** Call once per datagram your handler sends (echo/relay). */
    onWrite() {
      written++;
    },
    close() {
      clearInterval(timer);
      const dropped = session.datagramsDropped - startDropped;
      console.log(
        `[probe ${label}] done: read=${read} written=${written} queueDropped=${dropped}`,
      );
    },
  };
}
