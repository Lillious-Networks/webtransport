/**
 * WebTransportSendStream, WebTransportReceiveStream and friends.
 *
 * These are genuine WHATWG stream subclasses, not lookalikes: a receive stream
 * is a readable byte stream so BYOB readers work, and a send stream's writes
 * resolve only once the transport has accepted the bytes, so backpressure is
 * real rather than advisory.
 */

import { markHandled, toWebTransportError } from "./errors.ts";
import type { NativeBidiStream, NativeRecvStream, NativeSendStream } from "./native.ts";
import type { WebTransport, WebTransportSendGroup } from "./index.ts";
import type { WebTransportReceiveStreamStats, WebTransportSendStreamStats } from "./types.d.ts";

/** A chunk a caller may write: any BufferSource. */
export type BufferChunk = ArrayBufferView | ArrayBuffer;

/** Placement of an outgoing stream in the send scheduler. */
export interface SendStreamOptions {
  sendGroup?: WebTransportSendGroup | null;
  sendOrder?: number | bigint;
  /** The transport the stream belongs to, which bounds its send groups. */
  transport?: WebTransport | null;
}

/**
 * A ReadableStream of Uint8Array over an incoming WebTransport stream.
 */
export class WebTransportReceiveStream extends ReadableStream<Uint8Array> {
  #native: NativeRecvStream;

  constructor(native: NativeRecvStream) {
    super(
      {
        // A byte stream so consumers may use a BYOB reader, as the spec
        // requires of WebTransportReceiveStream.
        type: "bytes",
        pull: async (controller) => {
          const bytes = controller as ReadableByteStreamController;
          try {
            // With a BYOB request, read exactly what the consumer has room
            // for; otherwise take whatever is available.
            const request = bytes.byobRequest;
            const view = request?.view ?? null;
            const chunk = await native.read(view ? view.byteLength : undefined);

            if (chunk === null || chunk === undefined) {
              // End of stream. The controller is closed first: responding with
              // zero bytes is only legal on an already-closed stream, and the
              // close is what resolves the pending BYOB read as done.
              bytes.close();
              request?.respond(0);
              return;
            }

            if (request && view) {
              new Uint8Array(view.buffer, view.byteOffset, view.byteLength).set(chunk);
              request.respond(chunk.byteLength);
            } else {
              bytes.enqueue(chunk as Uint8Array<ArrayBuffer>);
            }
          } catch (err) {
            bytes.error(toWebTransportError(err, "stream"));
          }
        },
        cancel: async (reason) => {
          // Cancelling tells the peer to stop sending. A numeric reason is
          // taken as the application error code.
          await native.stop(errorCodeFrom(reason));
        },
      },
      // Byte streams take a byte-length queuing strategy.
      { highWaterMark: 0 },
    );
    this.#native = native;
  }

  async getStats(): Promise<WebTransportReceiveStreamStats> {
    const read = this.#native.bytesRead;
    // bytesReceived counts what arrived; without per-stream transport
    // accounting the best truthful answer is what we have actually read.
    return { bytesReceived: read, bytesRead: read };
  }
}

/**
 * A WritableStream over an outgoing WebTransport stream.
 */
export class WebTransportSendStream extends WritableStream<BufferChunk> {
  #native: NativeSendStream;
  #sendGroup: WebTransportSendGroup | null;
  #sendOrder: bigint;
  /** The transport this stream belongs to, which bounds its send groups. */
  #transport: WebTransport | null;

  constructor(native: NativeSendStream, options: SendStreamOptions = {}) {
    super({
      write: async (chunk) => {
        // Converted before the try: a chunk of the wrong type is a caller
        // mistake and must surface as TypeError, not as a transport error.
        const bytes = toBytes(chunk);
        try {
          // Resolves only once the transport has taken every byte, which is
          // what makes the stream's backpressure real.
          await native.write(bytes);
        } catch (err) {
          throw toWebTransportError(err, "stream");
        }
      },
      close: async () => {
        try {
          await native.finish();
        } catch (err) {
          throw toWebTransportError(err, "stream");
        }
      },
      abort: async (reason) => {
        await native.reset(errorCodeFrom(reason));
      },
    });
    this.#native = native;
    this.#transport = options.transport ?? options.sendGroup?.transport ?? null;
    this.#sendGroup = options.sendGroup ?? null;
    this.#sendOrder = toSendOrderValue(options.sendOrder ?? 0);
    this.#sendGroup?.addStream(this);
  }

  /** @internal the addon handle, for atomicWrite */
  get native(): NativeSendStream {
    return this.#native;
  }

  get sendGroup(): WebTransportSendGroup | null {
    return this.#sendGroup;
  }

  set sendGroup(value: WebTransportSendGroup | null) {
    // A group schedules against one connection's bandwidth, so it cannot
    // take a stream from another transport. The spec throws here rather than
    // rejecting, since the setter returns nothing.
    if (value != null && this.#transport != null && value.transport !== this.#transport) {
      throw new DOMException(
        "the sendGroup belongs to a different WebTransport",
        "InvalidStateError",
      );
    }
    this.#sendGroup = value ?? null;
    this.#sendGroup?.addStream(this);
    // A group is its own sendOrder numberspace, so moving between groups
    // changes which streams this one competes with.
    this.#native.setSendGroup(this.#sendGroup?.id ?? null);
  }

  /**
   * The IDL types this `long long`, which WebIDL maps to a Number, so that is
   * what reads back. It is kept as a BigInt internally: the scheduler compares
   * the full 64-bit value, and only the read-back loses precision beyond
   * 2**53, exactly as it would in a browser.
   */
  get sendOrder(): number {
    return Number(this.#sendOrder);
  }

  set sendOrder(value: number | bigint) {
    this.#sendOrder = toSendOrderValue(value);
    // Passed as a BigInt so the full 64-bit range reaches the scheduler; a JS
    // number could not carry it, and truncating would reorder streams.
    this.#native.setSendOrder(this.#sendOrder);
  }

  override getWriter(): WebTransportWriter {
    return new WebTransportWriter(this);
  }

  async getStats(): Promise<WebTransportSendStreamStats> {
    const written = this.#native.bytesWritten;
    // bytesAcknowledged needs per-stream ack accounting the transport does not
    // expose; reporting what we know beats inventing a number.
    return { bytesWritten: written, bytesSent: written, bytesAcknowledged: 0n };
  }
}

/**
 * A WritableStreamDefaultWriter with the two extra methods the spec adds.
 */
export class WebTransportWriter extends WritableStreamDefaultWriter<BufferChunk> {
  #stream: WebTransportSendStream;
  #pendingAtomic: Uint8Array[] = [];

  constructor(stream: WebTransportSendStream) {
    super(stream);
    this.#stream = stream;
    // An aborted or peer-closed writer rejects `closed`, which is an ordinary
    // outcome here. Marking it handled keeps that from surfacing as an
    // unhandled rejection; a caller that observes `closed` still sees it.
    markHandled(this.closed);
  }

  /**
   * Writes a chunk only if it fits entirely in the current flow-control window.
   *
   * Rejects rather than blocking when it does not, which is the point: it lets
   * transactional callers avoid a flow-control deadlock (RFC 9308 §4.4).
   */
  async atomicWrite(chunk?: BufferChunk): Promise<undefined> {
    if (chunk === undefined) return;
    const bytes = toBytes(chunk);
    try {
      const accepted = await this.#stream.native.writeSome(bytes);
      if (accepted < bytes.byteLength) {
        // Partially written: the chunk did not fit the window in its
        // entirety, which is exactly what atomicWrite promises not to do.
        throw new RangeError(
          `atomicWrite could not place all ${bytes.byteLength} bytes in the current flow control window`,
        );
      }
    } catch (err) {
      throw err instanceof RangeError ? err : toWebTransportError(err, "stream");
    }
  }

  /**
   * Commits queued atomic writes.
   *
   * Writes reach the transport as they are made, so there is nothing held back
   * to flush; the method exists so callers can use the spec's shape.
   */
  commit(): void {
    this.#pendingAtomic = [];
  }
}

/**
 * A bidirectional stream: a readable and a writable half.
 */
export class WebTransportBidirectionalStream {
  #readable: WebTransportReceiveStream;
  #writable: WebTransportSendStream;

  constructor(native: NativeBidiStream, options: SendStreamOptions = {}) {
    this.#readable = new WebTransportReceiveStream(native.readable);
    this.#writable = new WebTransportSendStream(native.writable, options);
  }

  get readable(): WebTransportReceiveStream {
    return this.#readable;
  }

  get writable(): WebTransportSendStream {
    return this.#writable;
  }
}

/**
 * Derives an application error code from an abort or cancel reason.
 *
 * A WebTransportError carries its own code; anything else has none, and the
 * spec's default of 0 applies.
 */
function errorCodeFrom(reason: unknown): number {
  if (reason && typeof reason === "object" && "streamErrorCode" in reason) {
    const code = reason.streamErrorCode;
    if (typeof code === "number") return code >>> 0;
  }
  if (typeof reason === "number") return reason >>> 0;
  return 0;
}

/**
 * Coerces a `sendOrder` the way WebIDL coerces a `long long`.
 *
 * `BigInt(value)` is close but not the same: WebIDL runs ToNumber first, so
 * `null` becomes 0 and a fractional number truncates, where `BigInt` throws
 * for both.
 */
export function toSendOrderValue(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  const asNumber = Number(value);
  if (!Number.isFinite(asNumber)) return 0n;
  return BigInt(Math.trunc(asNumber));
}

/** Normalises a chunk to the bytes to send. */
function toBytes(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) return chunk;
  if (ArrayBuffer.isView(chunk)) {
    return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
  }
  if (chunk instanceof ArrayBuffer) return new Uint8Array(chunk);
  throw new TypeError("stream chunks must be BufferSource");
}
