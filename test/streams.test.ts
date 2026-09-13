/**
 * Stream tests through the public JS API.
 *
 * These check the WHATWG stream contract as much as the transport: real
 * backpressure, BYOB reads, and spec-shaped errors.
 */

import { describe, expect, test, afterAll } from "bun:test";
import {
  WebTransport,
  WebTransportBidirectionalStream,
  WebTransportError,
  WebTransportReceiveStream,
  WebTransportSendStream,
  generateSelfSigned,
  serve,
} from "../js/index.ts";

const { cert, key, hash } = generateSelfSigned(["localhost"]);

/** Servers started by tests, stopped together at the end. */
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

/**
 * Connects a client to a server of its own and returns both ends.
 *
 * Each test gets a fresh server: several tests deliberately leave streams
 * unread or sessions open, and a shared accept queue would let one test pick up
 * another's session.
 */
async function pair() {
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

  const wt = new WebTransport(`https://localhost:${server.port}/streams`, options());
  await wt.ready;
  const start = Date.now();
  while (accepted.length === 0) {
    if (Date.now() - start > 5000) throw new Error("server never accepted");
    await Bun.sleep(5);
  }
  transports.push(wt);
  return { wt, session: accepted.shift(), server };
}

/** Reads a ReadableStream of bytes to completion. */
async function readAll(stream: ReadableStream): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.byteLength;
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

describe("unidirectional streams", () => {
  test("carry data from client to server", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new TextEncoder().encode("hello stream"));
    await writer.close();

    const reader = session.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    expect(incoming).toBeInstanceOf(WebTransportReceiveStream);
    expect(new TextDecoder().decode(await readAll(incoming))).toBe("hello stream");

    wt.close();
  });

  test("carry data from server to client", async () => {
    const { wt, session } = await pair();

    const stream = await session.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new TextEncoder().encode("server says hi"));
    await writer.close();

    const reader = wt.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    expect(new TextDecoder().decode(await readAll(incoming))).toBe("server says hi");

    wt.close();
  });

  test("are real WritableStreams", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream();

    expect(stream).toBeInstanceOf(WritableStream);
    const writer = stream.getWriter();
    expect(stream.locked).toBe(true);
    writer.releaseLock();
    expect(stream.locked).toBe(false);

    wt.close();
  });
});

describe("bidirectional streams", () => {
  test("carry data both ways", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createBidirectionalStream();
    expect(stream).toBeInstanceOf(WebTransportBidirectionalStream);
    expect(stream.readable).toBeInstanceOf(ReadableStream);
    expect(stream.writable).toBeInstanceOf(WritableStream);

    const writer = stream.writable.getWriter();
    await writer.write(new TextEncoder().encode("ping"));
    await writer.close();

    const reader = session.incomingBidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    expect(new TextDecoder().decode(await readAll(incoming.readable))).toBe("ping");

    const back = incoming.writable.getWriter();
    await back.write(new TextEncoder().encode("pong"));
    await back.close();
    expect(new TextDecoder().decode(await readAll(stream.readable))).toBe("pong");

    wt.close();
  });
});

describe("stream data integrity", () => {
  test("a large payload arrives byte for byte", async () => {
    const { wt, session } = await pair();

    // A pattern, so truncation or reordering shows up.
    const payload = new Uint8Array(512 * 1024);
    for (let i = 0; i < payload.length; i++) payload[i] = i % 251;

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    const writing = (async () => {
      await writer.write(payload);
      await writer.close();
    })();

    const reader = session.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    const received = await readAll(incoming);
    await writing;

    expect(received.length).toBe(payload.length);
    expect(received).toEqual(payload);

    wt.close();
  });

  test("many streams stay distinct", async () => {
    const { wt, session } = await pair();

    const count = 10;
    for (let i = 0; i < count; i++) {
      const stream = await wt.createUnidirectionalStream();
      const writer = stream.getWriter();
      await writer.write(new TextEncoder().encode(`stream-${i}`));
      await writer.close();
    }

    const reader = session.incomingUnidirectionalStreams.getReader();
    const seen = new Set<string>();
    for (let i = 0; i < count; i++) {
      const { value: incoming } = await reader.read();
      seen.add(new TextDecoder().decode(await readAll(incoming)));
    }

    expect(seen.size).toBe(count);
    for (let i = 0; i < count; i++) expect(seen.has(`stream-${i}`)).toBe(true);

    wt.close();
  });
});

describe("BYOB reads", () => {
  test("a receive stream supports a BYOB reader", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new TextEncoder().encode("byob data"));
    await writer.close();

    const reader = session.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();

    // Requesting a BYOB reader is only possible on a real byte stream.
    const byob = incoming.getReader({ mode: "byob" });
    const { value } = await byob.read(new Uint8Array(64));
    expect(new TextDecoder().decode(value)).toBe("byob data");

    wt.close();
  });
});

describe("stream errors", () => {
  test("a reset surfaces as a WebTransportError with the peer's code", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createBidirectionalStream();
    const writer = stream.writable.getWriter();
    await writer.write(new TextEncoder().encode("partial"));

    const reader = session.incomingBidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    const incomingReader = incoming.readable.getReader();
    await incomingReader.read();

    await writer.abort(new WebTransportError("done", { streamErrorCode: 4242 }));

    let error: unknown;
    try {
      for (;;) {
        const { done } = await incomingReader.read();
        if (done) break;
      }
    } catch (err) {
      error = err;
    }

    expect(error).toBeInstanceOf(WebTransportError);
    expect((error as WebTransportError).source).toBe("stream");
    expect((error as WebTransportError).streamErrorCode).toBe(4242);

    wt.close();
  });

  test("createUnidirectionalStream rejects once the session is closed", async () => {
    const { wt } = await pair();
    wt.close();

    let error: unknown;
    try {
      await wt.createUnidirectionalStream();
    } catch (err) {
      error = err;
    }
    expect((error as DOMException).name).toBe("InvalidStateError");
  });
});

describe("sendOrder and sendGroup", () => {
  test("sendOrder is a settable 64-bit value", async () => {
    const { wt } = await pair();
    const stream = await wt.createUnidirectionalStream({ sendOrder: 5 });

    expect(stream.sendOrder).toBe(5);
    // A BigInt past 2**53 is accepted and reaches the scheduler intact; the
    // getter returns a Number per the IDL, so it reads back rounded.
    stream.sendOrder = 9007199254740993n;
    expect(stream.sendOrder).toBe(Number(9007199254740993n));

    wt.close();
  });

  test("a send group from another transport is refused", async () => {
    const { wt } = await pair();
    const { wt: other } = await pair();

    const foreign = other.createSendGroup();
    let error: unknown;
    try {
      await wt.createUnidirectionalStream({ sendGroup: foreign });
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(TypeError);

    wt.close();
    other.close();
  });
});

describe("stream stats", () => {
  test("report what crossed the stream", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();
    await writer.write(new Uint8Array(1000));
    await writer.close();

    const sendStats = await stream.getStats();
    expect(sendStats.bytesWritten).toBe(1000n);

    const reader = session.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await reader.read();
    await readAll(incoming);
    const recvStats = await incoming.getStats();
    expect(recvStats.bytesRead).toBe(1000n);

    wt.close();
  });
});

describe("backpressure", () => {
  test("a writer that is not read stops resolving", async () => {
    const { wt, session } = await pair();

    const stream = await wt.createUnidirectionalStream();
    const writer = stream.getWriter();

    // Accept the stream but never read it, so the flow-control window fills.
    const reader = session.incomingUnidirectionalStreams.getReader();
    await reader.read();

    const chunk = new Uint8Array(256 * 1024);
    let completed = 0;
    let blocked = false;

    // Write until one write stays pending: that pending write *is* the
    // backpressure. Waiting on the condition rather than on a fixed delay
    // keeps the test from depending on how busy the machine is.
    const pump = (async () => {
      for (let i = 0; i < 200; i++) {
        const write = writer.write(chunk);
        let settled = false;
        write.then(
          () => {
            settled = true;
          },
          () => {
            settled = true;
          },
        );
        // Give the write a turn to complete if the window has room.
        await Bun.sleep(20);
        if (!settled) {
          blocked = true;
          // Leave it pending: resolving it would need the peer to read.
          return;
        }
        await write;
        completed++;
      }
    })();
    pump.catch(() => {});

    await pump;

    expect(blocked).toBe(true);
    expect(completed).toBeGreaterThan(0);
    expect(completed).toBeLessThan(200);

    await writer.abort().catch(() => {});
    wt.close();
  });
});

describe("BYOB reads", () => {
  // Regression: the pull answered a pending BYOB request with zero bytes and
  // then closed the controller. Responding with zero is only legal once the
  // stream is closed, so the final read threw instead of reporting done.
  test("a one-byte-at-a-time read drains the stream and then ends", async () => {
    const { wt, session } = await pair();

    const outgoing = await session.createUnidirectionalStream();
    const writer = outgoing.getWriter();
    await writer.write(new Uint8Array([1, 2, 3, 4]));
    await writer.close();

    const streams = wt.incomingUnidirectionalStreams.getReader();
    const { value: incoming } = await streams.read();
    const reader = incoming.getReader({ mode: "byob" });

    for (let i = 1; i <= 4; i++) {
      const { value, done } = await reader.read(new Uint8Array(1));
      expect(done).toBe(false);
      expect(Array.from(value)).toEqual([i]);
    }

    const last = await reader.read(new Uint8Array(1));
    expect(last.done).toBe(true);
    expect(last.value.byteLength).toBe(0);
    await reader.closed;
  });
});
