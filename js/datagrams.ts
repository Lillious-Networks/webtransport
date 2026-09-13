/**
 * WebTransportDatagramDuplexStream and WebTransportDatagramsWritable.
 *
 * Note this follows the current CR: datagrams are written through
 * `createWritable()`, not a `writable` attribute.
 */

import { toWebTransportError } from "./errors.ts";
import { toSendOrderValue } from "./streams.ts";
import type { BufferChunk } from "./streams.ts";
import type { NativeSession } from "./native.ts";
import type { WebTransportSendGroup } from "./index.ts";

export interface DatagramsWritableOptions {
  sendGroup?: WebTransportSendGroup | null;
  sendOrder?: number | bigint;
  /** The outgoing buffer limit, in datagrams. */
  highWaterMark?: number;
}

/**
 * A WritableStream of datagrams, carrying its own send priority.
 *
 * Datagrams are unreliable: a write resolves once the datagram has been handed
 * to the transport, which is not a delivery guarantee.
 */
export class WebTransportDatagramsWritable extends WritableStream<BufferChunk> {
  #sendGroup: WebTransportSendGroup | null;
  #sendOrder: bigint;

  /**
   * @param session resolves with the addon session handle, or null once it has
   *   been released
   *
   * Takes a promise so a writable can be created before the handshake
   * completes: a write simply waits for the session, as the spec's queueing
   * behaviour requires.
   */
  constructor(session: Promise<NativeSession | null>, options: DatagramsWritableOptions = {}) {
    // How many synchronous sends may pass before the write path yields to the
    // macrotask queue. Small enough that a reader is never starved for long,
    // large enough that the timer is amortised away.
    const YIELD_EVERY = 64;
    let writesSinceYield = 0;

    super(
      {
        write: async (chunk) => {
          const bytes = toBytes(chunk);
          try {
            const native = await session;
            // Null once the session has ended and its handle was released. A
            // datagram then is dropped, exactly as one sent into a dead path is.
            if (!native) return;
            native.sendDatagram(bytes);
            // Sending is synchronous, so a producer awaiting each write would
            // only ever run microtasks, and the datagram pump delivers on a
            // macrotask: a send loop would starve its own reader forever.
            // Yielding every write costs most of the throughput (a timer per
            // datagram), so this yields periodically instead, which bounds how
            // long the loop can hold the thread without paying on every send.
            if (++writesSinceYield >= YIELD_EVERY) {
              writesSinceYield = 0;
              await new Promise((resolve) => setTimeout(resolve, 0));
            }
          } catch (err) {
            // An oversized datagram is the application's error to see, but it
            // must not tear down the stream: the spec has datagram writes that
            // cannot be sent be dropped rather than error the stream. The same
            // applies to a peer that has just gone away: a datagram into a
            // closed session is dropped exactly like one lost in flight, and a
            // peer leaving is ordinary operation, not an error to report.
            const wtErr = toWebTransportError(err, "session");
            if (
              !/exceeds the .*-byte limit/.test(wtErr.message) &&
              wtErr.message !== "the session is closed"
            ) {
              throw wtErr;
            }
          }
        },
      },
      // The outgoing datagram buffer is what applies backpressure: a writer's
      // `ready` stays unresolved once this many datagrams are queued, which is
      // what stops a producer loop from spinning without bound.
      new CountQueuingStrategy({ highWaterMark: options.highWaterMark ?? 1 }),
    );
    this.#sendGroup = options.sendGroup ?? null;
    this.#sendOrder = toSendOrderValue(options.sendOrder ?? 0);
  }

  get sendGroup(): WebTransportSendGroup | null {
    return this.#sendGroup;
  }

  set sendGroup(value: WebTransportSendGroup | null) {
    this.#sendGroup = value ?? null;
  }

  /** A Number, as the IDL's `long long` maps to; see the send stream's. */
  get sendOrder(): number {
    return Number(this.#sendOrder);
  }

  set sendOrder(value: number | bigint) {
    this.#sendOrder = toSendOrderValue(value);
  }
}

/**
 * The `datagrams` attribute of a WebTransport.
 */
export class WebTransportDatagramDuplexStream {
  #native: NativeSession | null = null;
  #session: Promise<NativeSession | null> | null;
  #readable: ReadableStream<Uint8Array>;
  #incomingMaxAge: number | null = null;
  #outgoingMaxAge: number | null = null;
  #incomingMaxBufferedDatagrams = 1;
  #outgoingMaxBufferedDatagrams = 1;

  /**
   * @param session the addon session handle, or a promise for it
   *
   * A promise rather than the handle itself: the spec's `datagrams` getter
   * returns a stored object and never throws, so this has to exist from the
   * constructor, before the handshake that produces the handle has finished.
   * Everything that needs the handle awaits it.
   */
  constructor(
    session: NativeSession | Promise<NativeSession | null>,
    { readableType = "default" }: { readableType?: "default" | "bytes" } = {},
  ) {
    const sessionPromise = Promise.resolve(session);
    this.#session = sessionPromise;
    // Kept for the synchronous paths, which are usable only once connected.
    sessionPromise.then(
      (native) => {
        this.#native = native;
      },
      () => {
        // A failed handshake leaves #native null; the session's own `ready`
        // and `closed` promises are what report that.
      },
    );

    // A ReadableStream of Uint8Array, fed by a Rust push pump.
    //
    // Datagrams arrive through a threadsafe callback, not a pull: even batched
    // pulls pay the promise machinery once per batch per session, which for
    // many low-rate sessions is once per datagram, which saturates the JS
    // thread long before the transport does. The pump crosses into JS without
    // a promise; each batch is one buffer of varint-length-prefixed datagrams,
    // split here into views, so the per-datagram cost is a stream enqueue with
    // no copy. Backpressure lives in Rust: the pump's queue is bounded and
    // blocks, which fills the session's own bounded queue, which drops the
    // oldest datagram.
    this.#readable = new ReadableStream<Uint8Array>({
      // `datagramsReadableType: "bytes"` asks for a readable byte stream, so
      // BYOB reads work. The spec notes the mismatch: datagrams are discrete
      // messages, and a BYOB read that does not fit one truncates it.
      ...(readableType === "bytes" ? { type: "bytes" as const } : {}),
      // Async so the stream exists immediately while the pump starts once the
      // handshake completes. A reader that arrives first simply waits.
      start: async (controller) => {
        let native: NativeSession | null;
        try {
          // Captured locally rather than through `this`, so the pump callback
          // below closes over neither this stream nor the session promise.
          // Rust holds that callback for the pump's lifetime, and anything it
          // reaches is held with it: closing over `this` kept the session
          // handle alive and stopped the addon ever running its finalizer.
          native = await sessionPromise;
        } catch {
          native = null;
        }
        if (!native) {
          // The session never connected. Its own promises report why, so the
          // datagram stream just ends. Guarded because the consumer may have
          // cancelled it while the handshake was still running, which closes
          // the stream and makes a second close throw.
          try {
            controller.close();
          } catch {
            // Already closed, which is where this was heading regardless.
          }
          return;
        }
        // The pump can deliver its terminating empty batch after the stream
        // has already ended: a cancelled reader, or a session that closes
        // while a batch is in flight, both close the stream from this side
        // first. Closing twice throws, and this runs in a threadsafe callback
        // with no caller to catch it, so it has to be idempotent here.
        let ended = false;
        native.startDatagramPump((packed) => {
          if (ended) return;
          if (packed.byteLength === 0) {
            ended = true;
            // Still guarded: the consumer may have cancelled the stream,
            // which closes it without going through this callback.
            try {
              controller.close();
            } catch {
              // Already closed, which is the outcome this wanted anyway.
            }
            return;
          }
          const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
          let offset = 0;
          while (offset < packed.byteLength) {
            let length = 0;
            let shift = 0;
            let byte;
            do {
              byte = view.getUint8(offset++);
              length += (byte & 0x7f) * 2 ** shift;
              shift += 7;
            } while (byte & 0x80);
            try {
              enqueueDatagram(controller, packed.subarray(offset, offset + length));
            } catch {
              // The consumer cancelled while this batch was in flight. The
              // rest of the batch has nowhere to go, so drop it: datagrams
              // are unreliable, and losing them on a cancelled stream is
              // exactly what that means.
              ended = true;
              return;
            }
            offset += length;
          }
        });
      },
    });
  }

  get readable(): ReadableStream<Uint8Array> {
    return this.#readable;
  }

  /**
   * @internal Drops the references to the addon session once it has ended.
   *
   * The session promise resolves with the addon handle, so holding it keeps
   * the handle reachable and the addon cannot run its finalizer. The readable
   * has already been closed by the pump at this point, and the synchronous
   * paths check for a null handle.
   */
  releaseSession(): void {
    this.#native = null;
    this.#session = null;
  }

  /** Creates a writable side for these datagrams. */
  createWritable(options: DatagramsWritableOptions = {}): WebTransportDatagramsWritable {
    // After the session ends the handle is released, so a writable made now
    // has nothing to send on. Its writes are dropped, which is what an
    // unreliable send into a dead session does anyway.
    return new WebTransportDatagramsWritable(this.#session ?? Promise.resolve(null), {
      // The buffer limit is a property of the duplex stream, so a writable
      // takes the value current when it is created.
      highWaterMark: this.#outgoingMaxBufferedDatagrams,
      ...options,
    });
  }

  /**
   * Largest datagram that can currently be sent. Changes with the path MTU.
   *
   * Zero before the handshake completes, since the path is not known yet.
   */
  get maxDatagramSize(): number {
    return this.#native?.maxDatagramSize ?? 0;
  }

  /**
   * Sends one datagram immediately, outside the stream machinery.
   *
   * Not in the spec, which routes datagrams through `createWritable()`. That
   * path allocates a writer and a promise per datagram, which is real overhead
   * for an application pushing tens of thousands a second, and since datagrams
   * are unreliable and the enqueue never blocks, there is nothing to await.
   *
   * @returns whether the datagram was accepted for sending
   */
  sendSync(payload: BufferChunk): boolean {
    try {
      // Before the handshake finishes there is nowhere to send: a datagram
      // now is dropped exactly as one sent into a lossy path would be.
      if (!this.#native) return false;
      this.#native.sendDatagram(toBytes(payload));
      return true;
    } catch {
      // Unreliable by definition: a datagram that cannot be sent is dropped,
      // exactly as one lost in flight would be.
      return false;
    }
  }

  /**
   * Sends several datagrams in one crossing into the transport.
   *
   * @returns how many were accepted
   */
  sendSyncBatch(payloads: BufferChunk[]): number {
    if (!payloads?.length || !this.#native) return 0;
    return this.#native.sendDatagrams(payloads.map(toBytes));
  }

  get incomingMaxAge(): number | null {
    return this.#incomingMaxAge;
  }

  set incomingMaxAge(value: number | null) {
    this.#incomingMaxAge = toMaxAge(value, "incomingMaxAge");
  }

  get outgoingMaxAge(): number | null {
    return this.#outgoingMaxAge;
  }

  set outgoingMaxAge(value: number | null) {
    this.#outgoingMaxAge = toMaxAge(value, "outgoingMaxAge");
  }

  get incomingMaxBufferedDatagrams(): number {
    return this.#incomingMaxBufferedDatagrams;
  }

  set incomingMaxBufferedDatagrams(value: number) {
    // Coerced as an unsigned long, then floored at 1: a zero-length buffer
    // would drop every datagram before it could be read.
    this.#incomingMaxBufferedDatagrams = Math.max(1, toMaxBuffered(value));
  }

  get outgoingMaxBufferedDatagrams(): number {
    return this.#outgoingMaxBufferedDatagrams;
  }

  set outgoingMaxBufferedDatagrams(value: number) {
    this.#outgoingMaxBufferedDatagrams = Math.max(1, toMaxBuffered(value));
  }
}

/**
 * Delivers one datagram to a readable's controller.
 *
 * On a byte stream a waiting BYOB read has to be answered through its own
 * request rather than by enqueuing, or the read never settles. A datagram
 * larger than the view errors the stream rather than being split.
 */
function enqueueDatagram(controller: ReadableStreamController<Uint8Array>, datagram: Uint8Array): void {
  // A default controller has no byobRequest at all, which reads as undefined.
  const request = (controller as ReadableByteStreamController).byobRequest ?? null;
  const view = request?.view ?? null;
  if (!request || !view) {
    controller.enqueue(datagram as Uint8Array<ArrayBuffer>);
    return;
  }
  // A datagram is one message, so a view too small to hold it cannot be
  // filled without splitting it. The spec errors the stream instead, since
  // silently truncating would hand the reader a corrupt datagram.
  if (view.byteLength < datagram.byteLength) {
    controller.error(
      new RangeError(
        `a ${datagram.byteLength}-byte datagram does not fit the ${view.byteLength}-byte buffer supplied`,
      ),
    );
    return;
  }
  new Uint8Array(view.buffer, view.byteOffset, view.byteLength).set(datagram);
  request.respond(datagram.byteLength);
}

/**
 * Normalises an age setter's value.
 *
 * The spec throws only for a negative or NaN value; zero means "no limit" and
 * is stored as null, which is also what the getter reports.
 *
 * @param name for the error message
 */
function toMaxAge(value: unknown, name: string): number | null {
  if (value === null || value === undefined) return null;
  const asNumber = Number(value);
  if (Number.isNaN(asNumber) || asNumber < 0) {
    throw new RangeError(`${name} must not be negative or NaN`);
  }
  return asNumber === 0 ? null : asNumber;
}

/**
 * Normalises a datagram buffer limit.
 *
 * WebIDL types these `unsigned long`, so a negative or fractional value is
 * coerced rather than rejected.
 */
function toMaxBuffered(value: unknown): number {
  const asNumber = Number(value);
  if (!Number.isFinite(asNumber)) return 0;
  // ToUint32, as WebIDL applies for an unsigned long.
  return Math.trunc(asNumber) >>> 0;
}

/** Normalises a chunk to the bytes to send. */
function toBytes(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  if (ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
  throw new TypeError("datagram chunks must be BufferSource");
}
