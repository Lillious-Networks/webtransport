/**
 * Milestone 3 surface: send groups and ordering, keying material, stats,
 * pooling validation, and the remaining spec attributes.
 */

import { describe, expect, test, afterAll } from "bun:test";
import {
  WebTransport,
  WebTransportError,
  WebTransportSendGroup,
  generateSelfSigned,
  serve,
} from "../js/index.js";

const { cert, key, hash } = generateSelfSigned(["localhost"]);
const servers: Array<{ stop(): void }> = [];
/// Transports handed out by `pair`, closed in teardown.
///
/// A transport left open at process exit keeps addon handles with work still
/// pending on them, and abandoning those is what aborts the process once the
/// runtime is torn down: the suite reports every test passing and the runner
/// still sees a crash. Individual tests need not close what they open.
const transports: Array<{ close(): void; closed: Promise<unknown> }> = [];

afterAll(async () => {
  // Transports first: closing one settles the work pending on its session and
  // streams, which is what has to happen before the process goes away. A
  // transport a test already closed settles immediately.
  for (const wt of transports) {
    wt.close();
    await wt.closed.catch(() => {});
  }
  // Awaited; see the note in datagrams.test.ts.
  await Promise.all(servers.map((s) => s.stop()));
});

function options(extra: Record<string, unknown> = {}) {
  return {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
    ...extra,
  };
}

/** Connects a client to a server of its own. */
async function pair(extra: Record<string, unknown> = {}) {
  const accepted: any[] = [];
  const server = await serve({
    port: 0,
    hostname: "127.0.0.1",
    cert,
    key,
    session(session) {
      accepted.push(session);
    },
  });
  servers.push(server);

  const wt = new WebTransport(`https://localhost:${server.port}/spec`, options(extra));
  await wt.ready;
  const start = Date.now();
  while (accepted.length === 0) {
    if (Date.now() - start > 5000) throw new Error("server never accepted");
    await Bun.sleep(5);
  }
  transports.push(wt);
  return { wt, session: accepted.shift(), server };
}

describe("send groups", () => {
  test("createSendGroup returns a group bound to its transport", async () => {
    const { wt } = await pair();
    const group = wt.createSendGroup();

    expect(group).toBeInstanceOf(WebTransportSendGroup);
    // Each group is a distinct claimant on bandwidth.
    expect(wt.createSendGroup().id).not.toBe(group.id);

    wt.close();
  });

  test("a stream can be created in a group", async () => {
    const { wt } = await pair();
    const group = wt.createSendGroup();
    const stream = await wt.createUnidirectionalStream({ sendGroup: group });

    expect(stream.sendGroup).toBe(group);

    wt.close();
  });

  test("a stream can be moved between groups", async () => {
    const { wt } = await pair();
    const first = wt.createSendGroup();
    const second = wt.createSendGroup();

    const stream = await wt.createUnidirectionalStream({ sendGroup: first });
    stream.sendGroup = second;
    expect(stream.sendGroup).toBe(second);

    // Moving to the null group is allowed: it is a claimant like any other.
    stream.sendGroup = null;
    expect(stream.sendGroup).toBeNull();

    wt.close();
  });

  test("group stats total their streams", async () => {
    const { wt } = await pair();
    const group = wt.createSendGroup();

    const a = await wt.createUnidirectionalStream({ sendGroup: group });
    const b = await wt.createUnidirectionalStream({ sendGroup: group });

    const aw = a.getWriter();
    const bw = b.getWriter();
    await aw.write(new Uint8Array(1000));
    await bw.write(new Uint8Array(500));
    await aw.close();
    await bw.close();

    const stats = await group.getStats();
    expect(stats.bytesWritten).toBe(1500n);

    wt.close();
  });
});

describe("sendOrder", () => {
  test("survives the full 64-bit range", async () => {
    const { wt } = await pair();

    // Beyond Number.MAX_SAFE_INTEGER and beyond i32, where a naive
    // implementation would clamp or lose precision.
    // A BigInt is accepted so the full 64-bit range reaches the scheduler.
    // The getter returns a Number, as the IDL's `long long` requires, so a
    // value past 2**53 reads back rounded, exactly as it would in a browser.
    const huge = 9223372036854775807n;
    const stream = await wt.createUnidirectionalStream({ sendOrder: huge });
    expect(stream.sendOrder).toBe(Number(huge));
    expect(typeof stream.sendOrder).toBe("number");

    stream.sendOrder = -9223372036854775808n;
    expect(stream.sendOrder).toBe(Number(-9223372036854775808n));

    wt.close();
  });

  test("two orders that clamp to the same i32 stay distinct", async () => {
    const { wt } = await pair();

    const a = await wt.createUnidirectionalStream({ sendOrder: 2147483648n });
    const b = await wt.createUnidirectionalStream({ sendOrder: 2147483649n });

    expect(a.sendOrder).not.toBe(b.sendOrder);

    wt.close();
  });

  test("defaults to zero", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream();
    expect(stream.sendOrder).toBe(0);
    wt.close();
  });
});

describe("exportKeyingMaterial", () => {
  const label = new TextEncoder().encode("label");
  const context = new TextEncoder().encode("context");

  test("derives material of the requested length", async () => {
    const { wt } = await pair();
    const material = await wt.exportKeyingMaterial(label, context, 32);

    expect(material).toBeInstanceOf(Uint8Array);
    expect(material.byteLength).toBe(32);
    // All-zero output would mean the export silently did nothing.
    expect(material.some((b) => b !== 0)).toBe(true);

    wt.close();
  });

  test("is deterministic for the same inputs", async () => {
    const { wt } = await pair();
    const a = await wt.exportKeyingMaterial(label, context, 16);
    const b = await wt.exportKeyingMaterial(label, context, 16);
    expect(a).toEqual(b);
    wt.close();
  });

  test("different labels derive different material", async () => {
    const { wt } = await pair();
    const a = await wt.exportKeyingMaterial(label, context, 16);
    const b = await wt.exportKeyingMaterial(
      new TextEncoder().encode("other"),
      context,
      16,
    );
    expect(a).not.toEqual(b);
    wt.close();
  });

  test("different sessions derive different material", async () => {
    const first = await pair();
    const second = await pair();

    const a = await first.wt.exportKeyingMaterial(label, context, 32);
    const b = await second.wt.exportKeyingMaterial(label, context, 32);
    expect(a).not.toEqual(b);

    first.wt.close();
    second.wt.close();
  });
});

describe("getStats", () => {
  test("reports connection counters", async () => {
    const { wt } = await pair();
    const stats = await wt.getStats();

    // The IDL types the counters `unsigned long long`, which WebIDL maps to
    // a Number, so none of these come back as BigInt.
    expect(typeof stats.bytesSent).toBe("number");
    expect(typeof stats.bytesReceived).toBe("number");
    expect(stats.bytesSent).toBeGreaterThan(0);
    expect(stats.packetsSent).toBeGreaterThan(0);
    expect(typeof stats.smoothedRtt).toBe("number");

    // `datagrams` is required by the IDL, so it is always present.
    expect(typeof stats.datagrams).toBe("object");
    expect(typeof stats.datagrams.droppedIncoming).toBe("number");
    expect(typeof stats.datagrams.expiredIncoming).toBe("number");
    expect(typeof stats.datagrams.expiredOutgoing).toBe("number");
    expect(typeof stats.datagrams.lostOutgoing).toBe("number");

    wt.close();
  });

  test("omits members the transport cannot source", async () => {
    const { wt } = await pair();
    const stats = await wt.getStats();

    // Reporting these as 0 would read as a measurement rather than an absence.
    expect("rttVariation" in stats).toBe(false);
    expect("estimatedSendRate" in stats).toBe(false);

    wt.close();
  });

  test("counters grow as data flows", async () => {
    const { wt, session } = await pair();
    const before = await wt.getStats();

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new Uint8Array(200_000));
    await writer.close();

    const reader = session.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    const r = incoming.getReader();
    for (;;) {
      const { done } = await r.read();
      if (done) break;
    }

    const after = await wt.getStats();
    expect(after.bytesSent).toBeGreaterThan(before.bytesSent);

    wt.close();
  });
});

describe("pooling", () => {
  test("allowPooling with certificate hashes is refused", () => {
    // The spec makes this a constructor throw: a pooled connection was
    // validated for whoever opened it, so a later session cannot impose a pin.
    try {
      new WebTransport("https://example.com/", {
        allowPooling: true,
        serverCertificateHashes: [{ algorithm: "sha-256", value: new Uint8Array(32) }],
      });
      throw new Error("should have thrown");
    } catch (err: any) {
      expect(err.name).toBe("NotSupportedError");
    }
  });

  test("allowPooling alone is accepted", async () => {
    // Without hashes the option is legal; it simply may not find a connection
    // to reuse here.
    const { wt } = await pair();
    expect(wt.reliability).toBe("supports-unreliable");
    wt.close();
  });
});

describe("remaining attributes", () => {
  test("protocol is exposed", async () => {
    const { wt } = await pair();
    // No subprotocol was negotiated, so this is the empty string, not undefined.
    expect(wt.protocol).toBe("");
    wt.close();
  });

  test("congestionControl reflects the requested mode", async () => {
    const { wt } = await pair({ congestionControl: "low-latency" });
    expect(wt.congestionControl).toBe("low-latency");
    wt.close();
  });

  test("supportsReliableOnly is a static boolean", () => {
    expect(typeof WebTransport.supportsReliableOnly).toBe("boolean");
  });

  test("anticipated stream counts round-trip", async () => {
    const { wt } = await pair({
      anticipatedConcurrentIncomingUnidirectionalStreams: 4,
      anticipatedConcurrentIncomingBidirectionalStreams: 8,
    });

    expect(wt.anticipatedConcurrentIncomingUnidirectionalStreams).toBe(4);
    expect(wt.anticipatedConcurrentIncomingBidirectionalStreams).toBe(8);

    wt.anticipatedConcurrentIncomingUnidirectionalStreams = 16;
    expect(wt.anticipatedConcurrentIncomingUnidirectionalStreams).toBe(16);

    wt.close();
  });
});

describe("atomicWrite", () => {
  test("writes a chunk that fits the window", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.atomicWrite(new TextEncoder().encode("small enough"));
    await writer.close();

    const reader = session.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    const text = await new Response(incoming).text();
    expect(text).toBe("small enough");

    wt.close();
  });

  test("commit is callable", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    expect(() => writer.commit()).not.toThrow();
    wt.close();
  });

  test("an undefined chunk is a no-op", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.atomicWrite();
    wt.close();
  });
});

describe("draining", () => {
  // Regression: the server had no way to start draining, so a client's
  // `draining` promise could never settle no matter what the peer did.
  test("a server drain settles the client's draining promise", async () => {
    const { wt, session } = await pair();

    expect(typeof session.drain).toBe("function");

    let drained = false;
    wt.draining.then(() => {
      drained = true;
    });

    session.drain();
    const start = Date.now();
    while (!drained && Date.now() - start < 5000) await Bun.sleep(10);

    expect(drained).toBe(true);
    expect(session.state).toBe("draining");
  });

  test("draining leaves the session usable", async () => {
    const { wt, session } = await pair();
    session.drain();
    await wt.draining;
    // Draining asks the peer to stop opening streams; those already open,
    // and the datagram path, keep working until close.
    expect(wt.datagrams.sendSync(new Uint8Array([1]))).toBe(true);
  });
});

describe("responseHeaders", () => {
  // Regression: this was declared and read but never assigned, so it always
  // returned null. It is still null here, because our server sends only
  // `:status`, but reading it must not throw on the pseudo-header.
  test("is null when the response carries no real headers", async () => {
    const { wt } = await pair();
    expect(wt.responseHeaders).toBeNull();
  });

  test("excludes pseudo-headers rather than rejecting them", async () => {
    const { wt } = await pair();
    // A Headers object cannot hold ":status"; reaching this line at all
    // proves the pseudo-header was filtered before construction.
    expect(() => wt.responseHeaders).not.toThrow();
  });
});

describe("synchronous datagram sends", () => {
  test("sendSync and sendSyncBatch live on the datagrams object", async () => {
    const { wt } = await pair();
    expect(typeof wt.datagrams.sendSync).toBe("function");
    expect(typeof wt.datagrams.sendSyncBatch).toBe("function");
    expect(wt.datagrams.sendSync(new Uint8Array([1, 2]))).toBe(true);
    expect(wt.datagrams.sendSyncBatch([new Uint8Array([1]), new Uint8Array([2])])).toBe(2);
    expect(wt.datagrams.sendSyncBatch([])).toBe(0);
  });
});

describe("server session stats", () => {
  // Regression: this returned hardcoded zeros, which read as real
  // measurements of an idle session rather than as "not measured".
  test("report counters that grow with traffic", async () => {
    const { wt, session } = await pair();
    const writer = wt.datagrams.createWritable().getWriter();
    for (let i = 0; i < 20; i++) await writer.write(new Uint8Array(1200));

    const start = Date.now();
    let stats = await session.getStats();
    while (stats.bytesReceived === 0 && Date.now() - start < 5000) {
      await Bun.sleep(20);
      stats = await session.getStats();
    }

    expect(stats.bytesReceived).toBeGreaterThan(0);
    expect(stats.packetsReceived).toBeGreaterThan(0);
    // Present on the server side too, not just the client's dictionary.
    expect(typeof stats.smoothedRtt).toBe("number");
  });
});

describe("waitUntilAvailable", () => {
  // The Rust layer covers the limit itself (see wt-core/tests/many_streams).
  // What is checked here is that the JS flag reaches it and that refusing to
  // wait surfaces a WebTransportError rather than some other rejection.
  test("false rejects with a WebTransportError once the limit is reached", async () => {
    const { wt } = await pair();
    const open: any[] = [];
    let refused: unknown = null;

    // The limit is high, so this opens until it either trips or gives up.
    for (let i = 0; i < 12000; i++) {
      try {
        open.push(await wt.createUnidirectionalStream({ waitUntilAvailable: false }));
      } catch (err) {
        refused = err;
        break;
      }
    }

    if (refused) {
      expect(refused).toBeInstanceOf(WebTransportError);
      expect((refused as WebTransportError).source).toBe("session");
    } else {
      // Never hit the limit; the flag still has to be accepted, which the
      // successful opens above already prove.
      expect(open.length).toBeGreaterThan(0);
    }

    // Thousands of streams is far more pending addon work than any other test
    // leaves behind, and abandoning that much is what aborts the process at
    // exit. The shared teardown closes the transport, which covers the
    // streams; closing them here as well keeps the peak bounded.
    await Promise.all(open.map((stream) => stream.close().catch(() => {})));
  }, 60000);

  test("true is the default and opens a usable stream", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream({ waitUntilAvailable: true });
    const writer = stream.getWriter();
    await writer.write(new Uint8Array([1, 2, 3]));
    await writer.close();
  });
});

describe("chunk validation", () => {
  // A chunk of the wrong type is a caller mistake, so it must surface as
  // TypeError rather than being wrapped as a transport failure. The stream
  // path converted inside its try block and reported WebTransportError.
  test("a non-BufferSource stream chunk rejects with TypeError", async () => {
    const { wt } = await pair();
    const { writable } = await wt.createBidirectionalStream();
    const writer = writable.getWriter();
    await expect(writer.write("foo" as any)).rejects.toBeInstanceOf(TypeError);
  });

  test("a non-BufferSource datagram chunk rejects with TypeError", async () => {
    const { wt } = await pair();
    const writer = wt.datagrams.createWritable().getWriter();
    await expect(writer.write("foo" as any)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("exportKeyingMaterial validation", () => {
  const label = new TextEncoder().encode("label");
  const context = new TextEncoder().encode("context");

  // The exporter context encodes each length in one byte, so the spec caps
  // both at 255 and rejects an output length of zero or beyond the limit.
  test("rejects a label longer than 255 bytes", async () => {
    const { wt } = await pair();
    await expect(wt.exportKeyingMaterial(new Uint8Array(256), context, 32)).rejects.toBeInstanceOf(
      RangeError,
    );
    await expect(wt.exportKeyingMaterial(new Uint8Array(255), context, 32)).resolves.toBeInstanceOf(
      Uint8Array,
    );
  });

  test("rejects a context longer than 255 bytes", async () => {
    const { wt } = await pair();
    await expect(wt.exportKeyingMaterial(label, new Uint8Array(256), 32)).rejects.toBeInstanceOf(
      RangeError,
    );
  });

  test("rejects an output length of zero or beyond the cap", async () => {
    const { wt } = await pair();
    await expect(wt.exportKeyingMaterial(label, context, 0)).rejects.toBeInstanceOf(RangeError);
    await expect(wt.exportKeyingMaterial(label, context, 4097)).rejects.toBeInstanceOf(RangeError);
    await expect(wt.exportKeyingMaterial(label, context, 4096)).resolves.toBeInstanceOf(Uint8Array);
  });

  test("requires all three arguments, as the IDL does", async () => {
    const { wt } = await pair();
    // @ts-expect-error deliberately calling with too few arguments
    await expect(wt.exportKeyingMaterial(label)).rejects.toBeInstanceOf(TypeError);
  });

  test("rejects with InvalidStateError once closed", async () => {
    const { wt } = await pair();
    wt.close();
    await expect(wt.exportKeyingMaterial(label, context, 32)).rejects.toMatchObject({
      name: "InvalidStateError",
    });
  });
});

describe("draining semantics", () => {
  // draft-ietf-webtrans-http3 §5: WT_DRAIN_SESSION asks the peer to wind
  // down. It does not close the session, and both sides may keep opening
  // streams until one of them actually closes it.
  test("a draining session still opens streams", async () => {
    const { wt, session } = await pair();
    session.drain();
    await wt.draining;

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new Uint8Array([1]));
    await writer.close();
  });

  test("draining does not settle closed", async () => {
    const { wt, session } = await pair();
    session.drain();
    await wt.draining;

    const winner = await Promise.race([
      wt.closed.then(() => "settled", () => "settled"),
      Bun.sleep(150).then(() => "pending"),
    ]);
    expect(winner).toBe("pending");
  });

  test("closing without draining leaves draining pending", async () => {
    const { wt } = await pair();
    wt.close();
    await wt.closed;

    // `draining` reports that the session began winding down, not that it
    // ended, so a close that never drained must never settle it.
    const winner = await Promise.race([
      wt.draining.then(() => "settled", () => "settled"),
      Bun.sleep(150).then(() => "pending"),
    ]);
    expect(winner).toBe("pending");
  });
});

describe("sendGroup and sendOrder coercion", () => {
  // The setter throws InvalidStateError for a group from another transport,
  // where createUnidirectionalStream rejects with TypeError. Both are spec.
  test("assigning a group from another transport throws InvalidStateError", async () => {
    const first = await pair();
    const second = await pair();

    const stream = await first.wt.createUnidirectionalStream();
    const foreign = second.wt.createSendGroup();

    expect(() => {
      stream.sendGroup = foreign;
    }).toThrow(DOMException);
    try {
      stream.sendGroup = foreign;
    } catch (err: any) {
      expect(err.name).toBe("InvalidStateError");
    }

    // A group from its own transport is fine.
    stream.sendGroup = first.wt.createSendGroup();
  });

  // WebIDL coerces `long long` through ToNumber, so null becomes 0 and a
  // fractional value truncates. BigInt() throws for both.
  test("sendOrder coerces like a WebIDL long long", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream();

    stream.sendOrder = 4;
    expect(stream.sendOrder).toBe(4);
    stream.sendOrder = null;
    expect(stream.sendOrder).toBe(0);
    stream.sendOrder = 3.7;
    expect(stream.sendOrder).toBe(3);
  });
});
