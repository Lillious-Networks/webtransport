/**
 * W3C WebTransport for Bun.
 *
 * Implements the WebTransport Candidate Recommendation of 30 July 2026 over a
 * Rust QUIC/HTTP-3 stack. Milestone 1 covers sessions and datagrams; streams
 * arrive in milestone 2.
 */

import { native } from "./native.js";
import { WebTransportError, toWebTransportError, markHandled } from "./errors.js";
import {
  WebTransportDatagramDuplexStream,
  WebTransportDatagramsWritable,
} from "./datagrams.js";
import {
  WebTransportBidirectionalStream,
  WebTransportReceiveStream,
  WebTransportSendStream,
  WebTransportWriter,
} from "./streams.js";
import { makeIncomingStreams } from "./incoming.js";

/**
 * Largest keying material `exportKeyingMaterial` will derive.
 *
 * The spec leaves the cap implementation-defined but requires at least 4096,
 * which is what this allows: beyond it the export is far more likely to be a
 * mistake than a need.
 */
const MAX_KEYING_MATERIAL = 4096;

/**
 * Groups streams for bandwidth allocation. Each group is an equal claimant on
 * bandwidth and its own `sendOrder` numberspace.
 */
export class WebTransportSendGroup {
  #transport;
  #id;
  #streams = new Set();

  /**
   * @param {WebTransport} transport
   * @param {bigint} id identifies the group to the scheduler
   */
  constructor(transport, id) {
    this.#transport = transport;
    this.#id = id;
  }

  /** @internal */
  get transport() {
    return this.#transport;
  }

  /** @internal the scheduler's identifier for this group */
  get id() {
    return this.#id;
  }

  /** @internal tracks a stream so the group can total its statistics */
  addStream(stream) {
    this.#streams.add(stream);
  }

  /** @returns {Promise<{bytesWritten: bigint, bytesSent: bigint, bytesAcknowledged: bigint}>} */
  async getStats() {
    // A group's statistics are the sum of its streams'.
    let bytesWritten = 0n;
    let bytesSent = 0n;
    for (const stream of this.#streams) {
      const stats = await stream.getStats();
      bytesWritten += stats.bytesWritten;
      bytesSent += stats.bytesSent;
    }
    // bytesAcknowledged needs per-stream ack accounting the transport does not
    // expose, so it is omitted rather than reported as a figure we cannot back.
    return { bytesWritten, bytesSent };
  }
}

export class WebTransport {
  #native = null;
  #datagrams = null;
  /** Settles with the addon session, so objects that need it can exist first. */
  #sessionReady;
  #resolveSession;
  #rejectSession;
  #state = "connecting";
  #ready;
  #closed;
  #draining;
  #resolveReady;
  #rejectReady;
  #resolveClosed;
  #rejectClosed;
  #resolveDraining;
  #rejectDraining;
  #reliability = "pending";
  #congestionControl;
  #protocol = "";
  #responseHeaders = null;
  #anticipatedIncomingUni = null;
  #anticipatedIncomingBidi = null;
  #incomingBidi = null;
  #incomingUni = null;
  #nextSendGroupId = 1n;

  /**
   * @param {string} url
   * @param {object} [options]
   */
  constructor(url, options = {}) {
    // These checks are synchronous throws in the spec, so they run before any
    // I/O is started.
    const parsed = parseUrl(url);
    const allowPooling = options.allowPooling ?? false;
    const hashes = options.serverCertificateHashes ?? [];

    if (allowPooling && hashes.length > 0) {
      throw new DOMException(
        "serverCertificateHashes cannot be used with allowPooling",
        "NotSupportedError",
      );
    }

    const congestionControl = options.congestionControl ?? "default";
    if (!["default", "throughput", "low-latency"].includes(congestionControl)) {
      throw new TypeError(
        `congestionControl must be "default", "throughput" or "low-latency"`,
      );
    }
    this.#congestionControl = congestionControl;

    const datagramsReadableType = options.datagramsReadableType ?? "default";
    if (!["default", "bytes"].includes(datagramsReadableType)) {
      throw new TypeError(`datagramsReadableType must be "default" or "bytes"`);
    }

    this.#anticipatedIncomingUni =
      options.anticipatedConcurrentIncomingUnidirectionalStreams ?? null;
    this.#anticipatedIncomingBidi =
      options.anticipatedConcurrentIncomingBidirectionalStreams ?? null;

    this.#ready = markHandled(
      new Promise((resolve, reject) => {
        this.#resolveReady = resolve;
        this.#rejectReady = reject;
      }),
    );
    this.#closed = markHandled(
      new Promise((resolve, reject) => {
        this.#resolveClosed = resolve;
        this.#rejectClosed = reject;
      }),
    );
    this.#draining = markHandled(
      new Promise((resolve, reject) => {
        this.#resolveDraining = resolve;
        this.#rejectDraining = reject;
      }),
    );

    // The spec's `datagrams`, `incomingBidirectionalStreams` and
    // `incomingUnidirectionalStreams` getters return stored objects and never
    // throw, so they exist from here. Each is backed by a promise for the
    // session, which the handshake settles.
    this.#sessionReady = markHandled(
      new Promise((resolve, reject) => {
        this.#resolveSession = resolve;
        this.#rejectSession = reject;
      }),
    );
    this.#datagrams = new WebTransportDatagramDuplexStream(this.#sessionReady, {
      readableType: datagramsReadableType,
    });
    this.#incomingBidi = makeIncomingStreams(
      async () => (await this.#sessionReady)?.acceptBidirectionalStream() ?? null,
      (native) => new WebTransportBidirectionalStream(native, { transport: this }),
    );
    this.#incomingUni = makeIncomingStreams(
      async () => (await this.#sessionReady)?.acceptUnidirectionalStream() ?? null,
      (native) => new WebTransportReceiveStream(native),
    );

    this.#connect(parsed.href, options, hashes);
  }

  async #connect(url, options, hashes) {
    try {
      const session = await native.connect(url, {
        serverCertificateHashes: hashes.map((h) => ({
          algorithm: h.algorithm,
          value: toBytes(h.value),
        })),
        headers: normaliseHeaders(options.headers),
        protocols: options.protocols ?? [],
        requireUnreliable: options.requireUnreliable ?? false,
        congestionControl: this.#congestionControl,
        allowPooling: options.allowPooling ?? false,
      });

      this.#native = session;
      this.#state = "connected";
      this.#reliability = session.reliability;
      this.#protocol = session.protocol ?? "";
      // The spec exposes the CONNECT response headers as a Headers object,
      // and leaves it null when the handshake produced none. Pseudo-headers
      // are dropped: they are not headers, and Headers rejects the name.
      const pairs = (session.responseHeaders ?? []).filter(([name]) => !name.startsWith(":"));
      this.#responseHeaders = pairs.length ? new Headers(pairs) : null;
      // Releases the datagram and incoming-stream objects built in the
      // constructor, which have been waiting on this.
      this.#resolveSession(session);
      this.#resolveReady();

      this.#watchLifecycle(session);
    } catch (err) {
      this.#state = "failed";
      const error = toWebTransportError(err, "session");
      // Anything waiting on the session (datagrams, incoming streams) fails
      // with the same error rather than waiting forever.
      this.#rejectSession(error);
      this.#rejectReady(error);
      this.#rejectClosed(error);
      this.#rejectDraining(error);
    }
  }

  async #watchLifecycle(session) {
    // Resolves true once the session drains, false if it ends without ever
    // draining. `draining` stays pending in that second case, as the spec
    // requires: it reports that the session began winding down, not that it
    // ended. The addon answers rather than staying pending so that nothing
    // holds this transport alive once the session is gone.
    session.draining().then(
      (drained) => {
        if (!drained) return;
        if (this.#state === "connected") this.#state = "draining";
        this.#resolveDraining();
      },
      () => {},
    );

    const info = await session.closed();
    // A close initiated by us or cleanly by the peer resolves `closed`; a
    // transport failure rejects it.
    if (this.#state === "failed") return;
    this.#state = "closed";
    // `draining` is deliberately left alone: it settles only when the session
    // actually starts draining, so closing without a drain signal leaves it
    // pending for good.
    this.#resolveClosed({ closeCode: info.closeCode, reason: info.reason });
    this.#releaseSession();
  }

  /**
   * Drops this transport's references to the addon session.
   *
   * The addon frees a session's transport state in its finalizer, which only
   * runs once nothing holds the handle. `#sessionReady` resolves *with* that
   * handle, so the promise keeps it reachable, and the datagram stream and
   * both incoming stream readers hold the promise: a closed session stayed
   * alive for the life of the process. Everything that needed the handle has
   * had it by the time the session is over, so releasing here is safe and is
   * what lets the addon reclaim the connection.
   */
  #releaseSession() {
    this.#native = null;
    this.#sessionReady = null;
    this.#datagrams?.releaseSession();
  }

  /** @returns {Promise<undefined>} */
  get ready() {
    return this.#ready;
  }

  /** @returns {Promise<{closeCode: number, reason: string}>} */
  get closed() {
    return this.#closed;
  }

  /** @returns {Promise<undefined>} */
  get draining() {
    return this.#draining;
  }

  /** @returns {"pending" | "reliable-only" | "supports-unreliable"} */
  get reliability() {
    return this.#reliability;
  }

  get congestionControl() {
    return this.#congestionControl;
  }

  /**
   * @returns {WebTransportDatagramDuplexStream}
   *
   * Always present: the spec's getter returns the stored object, so it exists
   * from the constructor and never throws for a session still connecting.
   */
  get datagrams() {
    return this.#datagrams;
  }

  /**
   * Opens a bidirectional stream.
   * @param {{sendGroup?: object|null, sendOrder?: number|bigint, waitUntilAvailable?: boolean}} [options]
   * @returns {Promise<WebTransportBidirectionalStream>}
   */
  async createBidirectionalStream(options = {}) {
    this.#assertUsable();
    validateSendGroup(options.sendGroup, this);
    try {
      // Awaited rather than read from #native: a call before `ready` waits
      // for the handshake instead of failing.
      const session = await this.#sessionReady;
      const native = await session.createBidirectionalStream(
        options.sendGroup?.id ?? null,
        toSendOrder(options.sendOrder),
        options.waitUntilAvailable ?? true,
      );
      return new WebTransportBidirectionalStream(native, { ...options, transport: this });
    } catch (err) {
      throw toWebTransportError(err, "session");
    }
  }

  /**
   * Opens a unidirectional stream.
   * @param {{sendGroup?: object|null, sendOrder?: number|bigint, waitUntilAvailable?: boolean}} [options]
   * @returns {Promise<WebTransportSendStream>}
   */
  async createUnidirectionalStream(options = {}) {
    this.#assertUsable();
    validateSendGroup(options.sendGroup, this);
    try {
      const session = await this.#sessionReady;
      const native = await session.createUnidirectionalStream(
        options.sendGroup?.id ?? null,
        toSendOrder(options.sendOrder),
        options.waitUntilAvailable ?? true,
      );
      return new WebTransportSendStream(native, { ...options, transport: this });
    } catch (err) {
      throw toWebTransportError(err, "session");
    }
  }

  /**
   * @returns {ReadableStream} of WebTransportBidirectionalStream
   *
   * Stored from the constructor, as the spec's getter requires, so reading it
   * before the handshake completes returns a stream that simply has nothing
   * in it yet.
   */
  get incomingBidirectionalStreams() {
    return this.#incomingBidi;
  }

  /** @returns {ReadableStream} of WebTransportReceiveStream */
  get incomingUnidirectionalStreams() {
    return this.#incomingUni;
  }

  /**
   * Throws unless the session can still be used.
   *
   * A session still connecting is usable: the spec rejects stream creation
   * only in the "closed" and "failed" states, so a call made before `ready`
   * waits for the handshake rather than failing.
   */
  #assertUsable() {
    if (this.#state === "closed" || this.#state === "failed") {
      throw new DOMException("the session is closed", "InvalidStateError");
    }
  }

  get protocol() {
    return this.#protocol;
  }

  get responseHeaders() {
    return this.#responseHeaders;
  }

  get anticipatedConcurrentIncomingUnidirectionalStreams() {
    return this.#anticipatedIncomingUni;
  }

  set anticipatedConcurrentIncomingUnidirectionalStreams(value) {
    this.#anticipatedIncomingUni = value;
  }

  get anticipatedConcurrentIncomingBidirectionalStreams() {
    return this.#anticipatedIncomingBidi;
  }

  set anticipatedConcurrentIncomingBidirectionalStreams(value) {
    this.#anticipatedIncomingBidi = value;
  }

  /**
   * Terminates the session.
   * @param {{closeCode?: number, reason?: string}} [closeInfo]
   */
  close(closeInfo = {}) {
    if (this.#state === "closed" || this.#state === "failed") return;
    const closeCode = closeInfo.closeCode ?? 0;
    const reason = closeInfo.reason ?? "";
    this.#native?.close({ closeCode, reason });
    this.#state = "closed";
    // See #watchLifecycle: closing is not draining, so `draining` stays put.
    this.#resolveClosed({ closeCode, reason });
  }


  /**
   * Bytes queued for sending but not yet taken by the transport.
   *
   * Not in the spec. An application that broadcasts to many peers needs to know
   * when one has stopped keeping up, so it can shed load for that peer rather
   * than buffer without bound. Cheap to sample: callers poll it per frame.
   *
   * @returns {bigint}
   */
  get queuedBytes() {
    return this.#native?.queuedBytes ?? 0n;
  }

  /**
   * Inbound datagrams dropped because the receive queue was full.
   *
   * Not in the spec; the overload counterpart of {@link queuedBytes}.
   *
   * @returns {bigint}
   */
  get datagramsDropped() {
    return this.#native?.datagramsDropped ?? 0n;
  }

  /** @returns {WebTransportSendGroup} */
  createSendGroup() {
    // A group only means anything as a claimant on a live connection's
    // bandwidth, so a closed or failed session has none to hand out.
    if (this.#state === "closed" || this.#state === "failed") {
      throw new DOMException("the session is closed", "InvalidStateError");
    }
    return new WebTransportSendGroup(this, this.#nextSendGroupId++);
  }

  /**
   * Derives keying material bound to this session.
   *
   * Not a raw RFC 5705 export: the session id is folded into the exporter
   * context, so two sessions sharing a connection derive different bytes from
   * the same label and context.
   *
   * @param {BufferSource} label
   * @param {BufferSource} context
   * @param {number} outputLength
   * @returns {Promise<Uint8Array>}
   */
  async exportKeyingMaterial(label, context, outputLength) {
    // All three are required by the IDL, so a missing one is a TypeError
    // rather than whatever the addon makes of an undefined argument.
    if (arguments.length < 3) {
      throw new TypeError(
        `exportKeyingMaterial requires 3 arguments, but only ${arguments.length} were passed`,
      );
    }
    // The exporter context encodes each length in a single byte, so the spec
    // caps both at 255 and rejects a zero or oversized output length.
    const labelBytes = toBytes(label);
    const contextBytes = toBytes(context);
    if (labelBytes.byteLength > 255) {
      throw new RangeError(`label must be at most 255 bytes, got ${labelBytes.byteLength}`);
    }
    if (contextBytes.byteLength > 255) {
      throw new RangeError(`context must be at most 255 bytes, got ${contextBytes.byteLength}`);
    }
    if (!(outputLength > 0) || outputLength > MAX_KEYING_MATERIAL) {
      throw new RangeError(
        `outputLength must be between 1 and ${MAX_KEYING_MATERIAL}, got ${outputLength}`,
      );
    }

    if (this.#state === "closed" || this.#state === "failed") {
      throw new DOMException("the session is closed", "InvalidStateError");
    }
    if (!this.#native) {
      throw new DOMException("the session is not connected yet", "InvalidStateError");
    }
    try {
      return this.#native.exportKeyingMaterial(labelBytes, contextBytes, outputLength);
    } catch (err) {
      throw toWebTransportError(err, "session");
    }
  }

  /**
   * Connection statistics.
   *
   * Members this transport cannot source are absent rather than zero:
   * `rttVariation` (quinn tracks no RTT variance) and `estimatedSendRate`
   * (quinn exposes no estimate). Reporting a zero would read as a measurement.
   *
   * @returns {Promise<object>}
   */
  async getStats() {
    // Called before the handshake finishes, this waits for it rather than
    // reporting an empty dictionary: there are no statistics until there is a
    // connection. A handshake that fails rejects the wait, which surfaces as
    // the InvalidStateError the spec asks for.
    if (this.#state === "connecting") {
      try {
        await this.#sessionReady;
        // Released once the session ended; the state check below reports it.
      } catch {
        throw new DOMException("the session failed", "InvalidStateError");
      }
    }
    if (this.#state === "failed") {
      throw new DOMException("the session failed", "InvalidStateError");
    }
    const stats = this.#native?.getStats();
    if (!stats) {
      return {};
    }
    // The counters are `unsigned long long` in the IDL, which WebIDL maps to
    // a Number. The addon hands them over as BigInt so the full u64 survives
    // the boundary; the conversion happens here, at the spec's surface, and
    // only loses exactness past 2**53, as it would in a browser.
    return {
      bytesSent: Number(stats.bytesSent),
      bytesReceived: Number(stats.bytesReceived),
      packetsSent: Number(stats.packetsSent),
      packetsReceived: Number(stats.packetsReceived),
      packetsLost: Number(stats.packetsLost),
      bytesLost: Number(stats.bytesLost),
      smoothedRtt: stats.smoothedRtt,
      minRtt: stats.minRtt,
      congestionWindow: Number(stats.congestionWindow),
      atSendCapacity: false,
      // Required by the IDL, so it is always present. Only droppedIncoming
      // has a real source: the session's bounded receive queue counts what it
      // discarded. The rest need per-datagram expiry and loss accounting the
      // transport does not expose, and are reported as 0 rather than omitted
      // because the dictionary's members are not themselves optional.
      datagrams: {
        droppedIncoming: Number(this.#native?.datagramsDropped ?? 0n),
        expiredIncoming: 0,
        expiredOutgoing: 0,
        lostOutgoing: 0,
      },
    };
  }

  static get supportsReliableOnly() {
    return true;
  }
}

/**
 * Validates a WebTransport URL, throwing what the constructor steps require.
 * @param {string} url
 */
function parseUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new DOMException(`${url} is not a valid URL`, "SyntaxError");
  }
  if (parsed.protocol !== "https:") {
    throw new DOMException("the URL scheme must be https", "SyntaxError");
  }
  if (parsed.hash !== "") {
    throw new DOMException("the URL must not have a fragment", "SyntaxError");
  }
  return parsed;
}

/** @param {unknown} headers */
function normaliseHeaders(headers) {
  if (!headers) return [];
  if (headers instanceof Headers) {
    return [...headers].map(([name, value]) => ({ name, value }));
  }
  if (Array.isArray(headers)) {
    return headers.map(([name, value]) => ({ name: String(name), value: String(value) }));
  }
  return Object.entries(headers).map(([name, value]) => ({
    name,
    value: String(value),
  }));
}

/** @param {unknown} source */
function toBytes(source) {
  if (source instanceof Uint8Array) return source;
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  throw new TypeError("certificate hash values must be BufferSource");
}

/** A send group must belong to the transport it is used with. */
function validateSendGroup(sendGroup, transport) {
  if (sendGroup != null && sendGroup.transport !== transport) {
    throw new TypeError("the sendGroup belongs to a different WebTransport");
  }
}

/**
 * Normalises `sendOrder` for the scheduler.
 *
 * `null` means the stream did not opt into strict ordering. A value is passed
 * as a BigInt so the spec's full 64-bit range survives: a JS number cannot
 * represent it, and truncating would silently reorder streams.
 */
function toSendOrder(sendOrder) {
  if (sendOrder === undefined || sendOrder === null) return null;
  return BigInt(sendOrder);
}

export {
  WebTransportError,
  WebTransportDatagramDuplexStream,
  WebTransportDatagramsWritable,
  WebTransportBidirectionalStream,
  WebTransportReceiveStream,
  WebTransportSendStream,
  WebTransportWriter,
};
export { serve } from "./server.js";
export { generateSelfSigned, generateCaSigned, signWithCa } from "./cert.js";
