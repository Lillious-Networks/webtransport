/**
 * W3C WebTransport for Bun.
 *
 * Mirrors the WebTransport Candidate Recommendation of 30 July 2026, plus a
 * server API (not in the W3C spec, which covers only the client) and a few
 * non-spec additions, each marked where it appears.
 */

export interface WebTransportHash {
  algorithm: string;
  /**
   * The digest bytes.
   *
   * Typed as ArrayBufferView rather than BufferSource so a plain
   * `Uint8Array`, including what `generateSelfSigned` returns, is accepted
   * under configurations that distinguish ArrayBuffer from ArrayBufferLike.
   */
  value: ArrayBufferView | ArrayBuffer;
}

export type WebTransportCongestionControl = "default" | "throughput" | "low-latency";
export type WebTransportReliabilityMode = "pending" | "reliable-only" | "supports-unreliable";
export type WebTransportErrorSource = "stream" | "session";

export interface WebTransportOptions {
  /** Share a QUIC connection with other sessions to the same origin. */
  allowPooling?: boolean;
  requireUnreliable?: boolean;
  headers?: HeadersInit;
  /** Cannot be combined with `allowPooling`; doing so throws NotSupportedError. */
  serverCertificateHashes?: WebTransportHash[];
  congestionControl?: WebTransportCongestionControl;
  anticipatedConcurrentIncomingUnidirectionalStreams?: number | null;
  anticipatedConcurrentIncomingBidirectionalStreams?: number | null;
  protocols?: string[];
  /**
   * `"bytes"` makes `datagrams.readable` a readable byte stream, so BYOB
   * reads work. Note the mismatch the spec calls out: datagrams are discrete
   * messages, so a BYOB view too small for one errors the stream with a
   * RangeError rather than splitting it.
   */
  datagramsReadableType?: "default" | "bytes";
}

export interface WebTransportCloseInfo {
  closeCode?: number;
  reason?: string;
}

export interface WebTransportSendOptions {
  sendGroup?: WebTransportSendGroup | null;
  /** 64-bit; pass a bigint to use the full range. */
  sendOrder?: number | bigint;
}

export interface WebTransportSendStreamOptions extends WebTransportSendOptions {
  /** When false, fails rather than waiting if the peer's stream limit is reached. */
  waitUntilAvailable?: boolean;
}

export interface WebTransportSendStreamStats {
  bytesWritten: bigint;
  bytesSent: bigint;
  /** Absent: the transport exposes no per-stream acknowledgement accounting. */
  bytesAcknowledged?: bigint;
}

export interface WebTransportReceiveStreamStats {
  bytesReceived: bigint;
  bytesRead: bigint;
}

/**
 * Connection statistics.
 *
 * Members the transport cannot source are absent rather than zero, so callers
 * can tell "not measured" from "measured as none": `rttVariation` and
 * `estimatedSendRate` are never present.
 */
/**
 * Datagram counters. Only `droppedIncoming` has a real source: the session's
 * bounded receive queue counts what it discarded. The others need per-datagram
 * expiry and loss accounting the transport does not expose, and report 0.
 */
export interface WebTransportDatagramStats {
  droppedIncoming: number;
  expiredIncoming: number;
  expiredOutgoing: number;
  lostOutgoing: number;
}

export interface WebTransportConnectionStats {
  bytesSent: number;
  bytesReceived: number;
  packetsSent: number;
  packetsReceived: number;
  packetsLost: number;
  bytesLost: number;
  /** Milliseconds. */
  smoothedRtt: number;
  /** Milliseconds. */
  minRtt: number;
  congestionWindow: number;
  atSendCapacity: boolean;
  datagrams: WebTransportDatagramStats;
}

export interface WebTransportErrorOptions {
  source?: WebTransportErrorSource;
  streamErrorCode?: number | null;
}

export class WebTransportError extends DOMException {
  constructor(message?: string, options?: WebTransportErrorOptions);
  readonly source: WebTransportErrorSource;
  readonly streamErrorCode: number | null;
}

export class WebTransportSendGroup {
  getStats(): Promise<WebTransportSendStreamStats>;
}

export class WebTransportSendStream extends WritableStream<ArrayBufferView | ArrayBuffer> {
  sendGroup: WebTransportSendGroup | null;
  sendOrder: bigint;
  getStats(): Promise<WebTransportSendStreamStats>;
  getWriter(): WebTransportWriter;
}

export class WebTransportReceiveStream extends ReadableStream<Uint8Array> {
  getStats(): Promise<WebTransportReceiveStreamStats>;
}

export class WebTransportWriter extends WritableStreamDefaultWriter<ArrayBufferView | ArrayBuffer> {
  /** Rejects unless the chunk fits entirely in the current flow-control window. */
  atomicWrite(chunk?: ArrayBufferView | ArrayBuffer): Promise<void>;
  commit(): void;
}

export class WebTransportBidirectionalStream {
  readonly readable: WebTransportReceiveStream;
  readonly writable: WebTransportSendStream;
}

export class WebTransportDatagramsWritable extends WritableStream<ArrayBufferView | ArrayBuffer> {
  sendGroup: WebTransportSendGroup | null;
  sendOrder: bigint;
}

export class WebTransportDatagramDuplexStream {
  readonly readable: ReadableStream<Uint8Array>;
  createWritable(options?: WebTransportSendOptions): WebTransportDatagramsWritable;
  readonly maxDatagramSize: number;
  incomingMaxAge: number | null;
  outgoingMaxAge: number | null;
  incomingMaxBufferedDatagrams: number;
  outgoingMaxBufferedDatagrams: number;

  /**
   * Sends one datagram without the writer machinery. Not in the spec.
   *
   * Datagrams are unreliable and the enqueue never blocks, so an application
   * sending tens of thousands a second can skip the per-datagram promise.
   * Returns whether it was accepted for sending.
   */
  sendSync(payload: ArrayBufferView | ArrayBuffer): boolean;

  /**
   * Sends several datagrams in one crossing into the transport. Not in the
   * spec. Returns how many were accepted.
   */
  sendSyncBatch(payloads: Array<ArrayBufferView | ArrayBuffer>): number;
}

export class WebTransport {
  constructor(url: string, options?: WebTransportOptions);

  readonly ready: Promise<undefined>;
  readonly closed: Promise<WebTransportCloseInfo>;
  readonly draining: Promise<undefined>;
  readonly reliability: WebTransportReliabilityMode;
  readonly congestionControl: WebTransportCongestionControl;
  readonly datagrams: WebTransportDatagramDuplexStream;
  readonly protocol: string;
  readonly responseHeaders: Headers | null;

  anticipatedConcurrentIncomingUnidirectionalStreams: number | null;
  anticipatedConcurrentIncomingBidirectionalStreams: number | null;

  createBidirectionalStream(
    options?: WebTransportSendStreamOptions,
  ): Promise<WebTransportBidirectionalStream>;
  createUnidirectionalStream(
    options?: WebTransportSendStreamOptions,
  ): Promise<WebTransportSendStream>;

  readonly incomingBidirectionalStreams: ReadableStream<WebTransportBidirectionalStream>;
  readonly incomingUnidirectionalStreams: ReadableStream<WebTransportReceiveStream>;

  createSendGroup(): WebTransportSendGroup;
  getStats(): Promise<WebTransportConnectionStats>;
  exportKeyingMaterial(
    label: ArrayBufferView | ArrayBuffer,
    context: ArrayBufferView | ArrayBuffer,
    outputLength: number,
  ): Promise<Uint8Array>;
  close(closeInfo?: WebTransportCloseInfo): void;

  /**
   * Bytes queued for sending but not yet taken by the transport. Not in the
   * spec: an application broadcasting to many peers uses this to shed load for
   * one that has stopped keeping up.
   */
  readonly queuedBytes: bigint;

  static readonly supportsReliableOnly: boolean;
}

/** A session as seen by the server. Same shape as a client `WebTransport`. */
export class WebTransportServerSession {
  /** The CONNECT stream id identifying this session on its connection. */
  readonly id: bigint;
  readonly datagrams: WebTransportDatagramDuplexStream;
  readonly closed: Promise<WebTransportCloseInfo>;
  readonly reliability: WebTransportReliabilityMode;
  readonly state: string;
  readonly incomingBidirectionalStreams: ReadableStream<WebTransportBidirectionalStream>;
  readonly incomingUnidirectionalStreams: ReadableStream<WebTransportReceiveStream>;
  /** Bytes queued for sending but not yet taken by the transport. */
  readonly queuedBytes: bigint;
  /**
   * Datagrams dropped because the receive queue was full.
   *
   * Not in the spec. Exposed because a server shedding load needs to know it
   * is happening.
   */
  readonly datagramsDropped: bigint;
  /**
   * UDP packets received on this session's connection.
   *
   * Not in the spec; the transport-level counterpart of {@link datagramsDropped},
   * which distinguishes datagrams lost in the network from ones dropped here.
   */
  readonly udpPacketsReceived: bigint;

  /**
   * Begins draining: the peer is asked to stop opening new streams while the
   * ones already open finish. Lets a server shed sessions before shutdown
   * without cutting work short.
   */
  drain(): void;

  createBidirectionalStream(
    options?: WebTransportSendStreamOptions,
  ): Promise<WebTransportBidirectionalStream>;
  createUnidirectionalStream(
    options?: WebTransportSendStreamOptions,
  ): Promise<WebTransportSendStream>;
  close(closeInfo?: WebTransportCloseInfo): void;
  getStats(): Promise<Partial<WebTransportConnectionStats>>;
}

/** The extended CONNECT request that opened a session. */
export class WebTransportSessionRequest {
  readonly path: string;
  readonly authority: string;
  readonly headers: Headers;
  /** Subprotocols the client offered, in preference order. */
  readonly protocols: string[];
}

export interface ServeOptions {
  port: number;
  hostname?: string;
  /** PEM certificate chain. */
  cert: string;
  /** PEM private key. */
  key: string;
  maxSessions?: number;
  /**
   * Concurrent QUIC streams per direction, per connection. Defaults to 2000.
   *
   * The transport reserves bookkeeping proportional to this, roughly 0.36 KiB
   * per permitted stream, so raising it buys headroom at the cost of memory on
   * every connection the server holds.
   */
  maxConcurrentStreams?: number;
  /** Returning accepts the session; throwing rejects it. */
  session: (
    session: WebTransportServerSession,
    request: WebTransportSessionRequest,
  ) => unknown;
  error?: (err: unknown) => unknown;
}

export interface WebTransportServer {
  readonly port: number;
  stop(): void;
}

/** Starts a WebTransport server. */
export function serve(options: ServeOptions): Promise<WebTransportServer>;

/**
 * Generates a self-signed certificate for local development, with the SHA-256
 * hash a client passes as `serverCertificateHashes`.
 */
export function generateSelfSigned(hostnames?: string[]): {
  cert: string;
  key: string;
  hash: Uint8Array;
};
