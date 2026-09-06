/**
 * End-to-end tests through the public JS API.
 *
 * A real client against a real server over loopback QUIC, exercising the shapes
 * an application actually uses.
 */

import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import {
  WebTransport,
  WebTransportError,
  generateSelfSigned,
  serve,
} from "../js/index.js";

const { cert, key, hash } = generateSelfSigned(["localhost"]);

/** Sessions the server has accepted, so tests can drive the far end. */
const accepted: any[] = [];
let server: { port: number; stop(): void };

beforeAll(async () => {
  server = await serve({
    port: 0,
    hostname: "127.0.0.1",
    cert,
    key,
    session(session) {
      accepted.push(session);
    },
  });
});

afterAll(() => {
  server.stop();
});

function url(path = "/") {
  return `https://localhost:${server.port}${path}`;
}

function options(extra: Record<string, unknown> = {}) {
  return {
    serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
    ...extra,
  };
}

/** Waits for the server to accept the next session. */
async function nextSession(): Promise<any> {
  const start = Date.now();
  while (accepted.length === 0) {
    if (Date.now() - start > 5000) throw new Error("server never accepted a session");
    await Bun.sleep(5);
  }
  return accepted.shift();
}

describe("datagram stream teardown", () => {
  test("a cancelled reader does not throw when the session then closes", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    // Cancelling closes the readable from this side. The pump still has its
    // terminating batch to deliver, and closing an already-closed stream
    // throws from inside a threadsafe callback, where nothing can catch it:
    // it surfaced as an unhandled error rather than a test failure.
    await wt.datagrams.readable.cancel();

    wt.close({ closeCode: 0, reason: "" });
    await wt.closed;

    // Give the pump's terminating batch time to arrive after the close.
    await Bun.sleep(50);
    expect(true).toBe(true);
  });

  test("closing twice over does not throw", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    wt.close({ closeCode: 0, reason: "" });
    await wt.closed;
    await Bun.sleep(30);
    // A second close is a no-op per spec, and must not disturb the pump.
    wt.close({ closeCode: 0, reason: "" });
    await Bun.sleep(30);
    expect(true).toBe(true);
  });
});

describe("WebTransport constructor", () => {
  test("rejects a non-https scheme synchronously", () => {
    expect(() => new WebTransport("http://example.com/")).toThrow(DOMException);
    try {
      new WebTransport("http://example.com/");
    } catch (err: any) {
      expect(err.name).toBe("SyntaxError");
    }
  });

  test("rejects a URL with a fragment", () => {
    try {
      new WebTransport("https://example.com/path#section");
      throw new Error("should have thrown");
    } catch (err: any) {
      expect(err.name).toBe("SyntaxError");
    }
  });

  test("rejects certificate hashes combined with pooling", () => {
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

  test("rejects an unknown congestionControl value", () => {
    expect(
      () => new WebTransport("https://example.com/", { congestionControl: "fastest" as any }),
    ).toThrow(TypeError);
  });
});

describe("session lifecycle", () => {
  test("ready resolves once connected", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    expect(wt.reliability).toBe("supports-unreliable");
    await nextSession();
    wt.close();
  });

  test("ready rejects with a WebTransportError when the pin does not match", async () => {
    const wt = new WebTransport(
      url(),
      options({ serverCertificateHashes: [{ algorithm: "sha-256", value: new Uint8Array(32) }] }),
    );
    let error: unknown;
    try {
      await wt.ready;
    } catch (err) {
      error = err;
    }
    expect(error).toBeInstanceOf(WebTransportError);
    expect((error as WebTransportError).source).toBe("session");
  });

  test("close resolves closed with the supplied info", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    wt.close({ closeCode: 42, reason: "all done" });
    const info = await wt.closed;
    expect(info.closeCode).toBe(42);
    expect(info.reason).toBe("all done");
  });

  test("an unobserved ready rejection does not become unhandled", async () => {
    // Constructing and ignoring a failing session must not crash the process.
    new WebTransport(
      url(),
      options({ serverCertificateHashes: [{ algorithm: "sha-256", value: new Uint8Array(32) }] }),
    );
    await Bun.sleep(300);
    expect(true).toBe(true);
  });
});

describe("datagrams", () => {
  test("travel from client to server", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    const session = await nextSession();

    const writer = wt.datagrams.createWritable().getWriter();
    await writer.write(new TextEncoder().encode("hello server"));

    const reader = session.datagrams.readable.getReader();
    const { value } = await reader.read();
    expect(new TextDecoder().decode(value)).toBe("hello server");

    wt.close();
  });

  test("travel from server to client", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    const session = await nextSession();

    const writer = session.datagrams.createWritable().getWriter();
    await writer.write(new TextEncoder().encode("hello client"));

    const reader = wt.datagrams.readable.getReader();
    const { value } = await reader.read();
    expect(new TextDecoder().decode(value)).toBe("hello client");

    wt.close();
  });

  test("readable is a real ReadableStream", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    expect(wt.datagrams.readable).toBeInstanceOf(ReadableStream);
    // Real streams support the full protocol, including locking.
    const reader = wt.datagrams.readable.getReader();
    expect(wt.datagrams.readable.locked).toBe(true);
    reader.releaseLock();
    expect(wt.datagrams.readable.locked).toBe(false);

    wt.close();
  });

  test("createWritable returns a real WritableStream", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    const writable = wt.datagrams.createWritable();
    expect(writable).toBeInstanceOf(WritableStream);
    expect(writable.sendOrder).toBe(0);

    writable.sendOrder = 5;
    expect(writable.sendOrder).toBe(5);

    wt.close();
  });

  test("maxDatagramSize reports a usable limit", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    expect(wt.datagrams.maxDatagramSize).toBeGreaterThan(0);
    expect(wt.datagrams.maxDatagramSize).toBeLessThan(1500);

    wt.close();
  });

  test("a burst arrives in order", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    const session = await nextSession();

    const writer = wt.datagrams.createWritable().getWriter();
    for (let i = 0; i < 10; i++) {
      await writer.write(new TextEncoder().encode(`packet-${i}`));
    }

    const reader = session.datagrams.readable.getReader();
    for (let i = 0; i < 10; i++) {
      const { value } = await reader.read();
      expect(new TextDecoder().decode(value)).toBe(`packet-${i}`);
    }

    wt.close();
  });

  test("age and high-water-mark knobs validate their input", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    const d = wt.datagrams;
    d.incomingMaxAge = 1000;
    expect(d.incomingMaxAge).toBe(1000);
    d.incomingMaxAge = null;
    expect(d.incomingMaxAge).toBeNull();

    // Only a negative or NaN age throws; zero means "no limit" and reads
    // back as null.
    expect(() => (d.outgoingMaxAge = -1)).toThrow(RangeError);
    expect(() => (d.incomingMaxAge = NaN)).toThrow(RangeError);
    d.incomingMaxAge = 0;
    expect(d.incomingMaxAge).toBeNull();

    // The buffer limits are `unsigned long`, so they coerce rather than
    // throw, and are floored at 1.
    d.incomingMaxBufferedDatagrams = 0;
    expect(d.incomingMaxBufferedDatagrams).toBe(1);
    d.outgoingMaxBufferedDatagrams = 0.5;
    expect(d.outgoingMaxBufferedDatagrams).toBe(1);
    d.incomingMaxBufferedDatagrams = -1;
    expect(d.incomingMaxBufferedDatagrams).toBe(4294967295);

    // The spec renamed these from incoming/outgoingHighWaterMark. WPT's
    // historical test asserts the old names are gone, so they must not linger.
    expect("incomingHighWaterMark" in d).toBe(false);
    expect("outgoingHighWaterMark" in d).toBe(false);
    // Likewise `writable`, replaced by createWritable().
    expect("writable" in d).toBe(false);

    wt.close();
  });
});

describe("WebTransportError", () => {
  test("is a DOMException with the spec's name and code", () => {
    const err = new WebTransportError("boom", { source: "stream", streamErrorCode: 7 });
    expect(err).toBeInstanceOf(DOMException);
    expect(err.name).toBe("WebTransportError");
    expect(err.code).toBe(0);
    expect(err.source).toBe("stream");
    expect(err.streamErrorCode).toBe(7);
  });

  test("defaults source to stream and streamErrorCode to null", () => {
    const err = new WebTransportError("boom");
    expect(err.source).toBe("stream");
    expect(err.streamErrorCode).toBeNull();
  });

  test("clamps an out-of-range streamErrorCode rather than throwing", () => {
    expect(new WebTransportError("x", { streamErrorCode: -5 }).streamErrorCode).toBe(0);
    expect(
      new WebTransportError("x", { streamErrorCode: 0x1_0000_0000 }).streamErrorCode,
    ).toBe(0xffffffff);
  });
});

describe("server", () => {
  test("reports the ephemeral port it bound", () => {
    expect(server.port).toBeGreaterThan(0);
  });

  test("the request path and headers reach the handler", async () => {
    const seen: any[] = [];
    const other = await serve({
      port: 0,
      hostname: "127.0.0.1",
      cert,
      key,
      session(session, request) {
        seen.push({ path: request.path, token: request.headers.get("x-token") });
      },
    });

    const wt = new WebTransport(
      `https://localhost:${other.port}/room/9`,
      options({ headers: { "x-token": "secret" } }),
    );
    await wt.ready;

    const start = Date.now();
    while (seen.length === 0 && Date.now() - start < 5000) await Bun.sleep(5);

    expect(seen[0].path).toBe("/room/9");
    expect(seen[0].token).toBe("secret");

    wt.close();
    other.stop();
  });
});

describe("datagramsReadableType", () => {
  test("defaults to a non-byte stream, so BYOB is refused", async () => {
    const wt = new WebTransport(url(), options());
    await wt.ready;
    await nextSession();

    expect(() => (wt.datagrams.readable as any).getReader({ mode: "byob" })).toThrow();

    wt.close();
  });

  test('"bytes" gives a readable byte stream', async () => {
    const wt = new WebTransport(url(), options({ datagramsReadableType: "bytes" }));
    await wt.ready;
    const session = await nextSession();

    const writer = session.datagrams.createWritable().getWriter();
    await writer.write(new Uint8Array([1, 2, 3]));

    const reader = (wt.datagrams.readable as any).getReader({ mode: "byob" });
    const { value } = await reader.read(new Uint8Array(16));
    expect(Array.from(value)).toEqual([1, 2, 3]);

    wt.close();
  });

  // A datagram is one message, so a view too small to hold it cannot be
  // filled without splitting it: the spec errors the stream instead.
  test("a BYOB view smaller than the datagram errors the stream", async () => {
    const wt = new WebTransport(url(), options({ datagramsReadableType: "bytes" }));
    await wt.ready;
    const session = await nextSession();

    const writer = session.datagrams.createWritable().getWriter();
    await writer.write(new Uint8Array(10));

    const reader = (wt.datagrams.readable as any).getReader({ mode: "byob" });
    await expect(reader.read(new Uint8Array(1))).rejects.toBeInstanceOf(RangeError);

    wt.close();
  });

  test("rejects an unknown value", () => {
    expect(
      () => new WebTransport("https://example.com/", { datagramsReadableType: "nope" as any }),
    ).toThrow(TypeError);
  });
});
