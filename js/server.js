/**
 * WebTransport server.
 *
 * Not part of the W3C spec, which covers only the client. Wire behaviour
 * follows draft-ietf-webtrans-http3; the JS shapes mirror the client's, so a
 * session object behaves the same on both sides.
 */

import { native } from "./native.js";
import { toWebTransportError } from "./errors.js";
import { WebTransportDatagramDuplexStream } from "./datagrams.js";
import {
  WebTransportBidirectionalStream,
  WebTransportReceiveStream,
  WebTransportSendStream,
} from "./streams.js";
import { makeIncomingStreams } from "./incoming.js";

/**
 * A session as seen by the server. Same shape as a client `WebTransport`.
 */
export class WebTransportServerSession {
  #native;
  #datagrams;
  #closed;
  #resolveClosed;
  #state = "connected";
  #incomingBidi;
  #incomingUni;

  /** @param {object} nativeSession */
  constructor(nativeSession) {
    this.#native = nativeSession;
    this.#datagrams = new WebTransportDatagramDuplexStream(nativeSession);
    this.#incomingBidi = makeIncomingStreams(
      () => nativeSession.acceptBidirectionalStream(),
      (native) => new WebTransportBidirectionalStream(native),
    );
    this.#incomingUni = makeIncomingStreams(
      () => nativeSession.acceptUnidirectionalStream(),
      (native) => new WebTransportReceiveStream(native),
    );
    this.#closed = new Promise((resolve) => {
      this.#resolveClosed = resolve;
    });
    this.#closed.catch(() => {});

    nativeSession.closed().then(
      (info) => {
        this.#state = "closed";
        this.#resolveClosed({ closeCode: info.closeCode, reason: info.reason });
      },
      () => {
        this.#state = "closed";
        this.#resolveClosed({ closeCode: 0, reason: "" });
      },
    );
  }

  get datagrams() {
    return this.#datagrams;
  }

  get closed() {
    return this.#closed;
  }

  get reliability() {
    return this.#native.reliability;
  }

  /** The CONNECT stream id identifying this session on its connection. */
  get id() {
    return this.#native.id;
  }

  /**
   * Bytes queued for sending but not yet taken by the transport.
   *
   * Not in the spec; a server broadcasting to many clients uses it to shed
   * load for one that has stopped reading. See the client-side note.
   *
   * @returns {bigint}
   */
  get queuedBytes() {
    return this.#native.queuedBytes;
  }

  /**
   * Inbound datagrams dropped because the receive queue was full.
   *
   * Not in the spec; together with {@link queuedBytes} this is the overload
   * signal an operator watches. @returns {bigint}
   */
  get datagramsDropped() {
    return this.#native.datagramsDropped;
  }

  /**
   * UDP datagrams the transport has received on this session's connection.
   *
   * Not in the spec; the transport-level counterpart of {@link datagramsDropped}.
   * @returns {bigint}
   */
  get udpPacketsReceived() {
    return this.#native.udpPacketsReceived;
  }

  /** @returns {ReadableStream} of WebTransportBidirectionalStream */
  get incomingBidirectionalStreams() {
    return this.#incomingBidi;
  }

  /** @returns {ReadableStream} of WebTransportReceiveStream */
  get incomingUnidirectionalStreams() {
    return this.#incomingUni;
  }

  /**
   * Opens a bidirectional stream to the client.
   * @returns {Promise<WebTransportBidirectionalStream>}
   */
  async createBidirectionalStream(options = {}) {
    const native = await this.#native.createBidirectionalStream(
      options.sendGroup?.id ?? null,
      options.sendOrder === undefined || options.sendOrder === null
        ? null
        : BigInt(options.sendOrder),
      options.waitUntilAvailable ?? true,
    );
    return new WebTransportBidirectionalStream(native, options);
  }

  /**
   * Opens a unidirectional stream to the client.
   * @returns {Promise<WebTransportSendStream>}
   */
  async createUnidirectionalStream(options = {}) {
    const native = await this.#native.createUnidirectionalStream(
      options.sendGroup?.id ?? null,
      options.sendOrder === undefined || options.sendOrder === null
        ? null
        : BigInt(options.sendOrder),
      options.waitUntilAvailable ?? true,
    );
    return new WebTransportSendStream(native, options);
  }

  get state() {
    return this.#state;
  }

  close(closeInfo = {}) {
    if (this.#state === "closed") return;
    const closeCode = closeInfo.closeCode ?? 0;
    const reason = closeInfo.reason ?? "";
    this.#native.close({ closeCode, reason });
    this.#state = "closed";
    this.#resolveClosed({ closeCode, reason });
  }

  /**
   * Begins draining. The peer is asked to stop opening new streams while the
   * ones already open finish, which is how a server sheds sessions before
   * shutting down without cutting work short.
   */
  drain() {
    if (this.#state !== "connected") return;
    this.#native.drain();
    this.#state = "draining";
  }

  /**
   * Connection statistics for this session.
   *
   * Members the transport cannot source are omitted rather than reported as
   * zero, so a caller can tell "nothing sent" apart from "not measured".
   */
  async getStats() {
    const stats = this.#native.getStats();
    if (!stats) return {};
    return {
      // Numbers, as the IDL's `unsigned long long` maps to; see the client's.
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
      datagrams: {
        droppedIncoming: Number(this.#native.datagramsDropped ?? 0n),
        expiredIncoming: 0,
        expiredOutgoing: 0,
        lostOutgoing: 0,
      },
    };
  }
}

/**
 * The request that opened a session, for routing and authorization.
 */
export class WebTransportSessionRequest {
  #incoming;
  #headers;

  /** @param {object} incoming */
  constructor(incoming) {
    this.#incoming = incoming;
    this.#headers = new Headers(
      incoming.headers.map(({ name, value }) => [name, value]),
    );
  }

  get path() {
    return this.#incoming.path;
  }

  get authority() {
    return this.#incoming.authority;
  }

  /** @returns {Headers} */
  get headers() {
    return this.#headers;
  }

  /** Subprotocols the client offered, in preference order. */
  get protocols() {
    return this.#incoming.protocols;
  }
}

/**
 * Starts a WebTransport server.
 *
 * ```js
 * const server = serve({
 *   port: 4433,
 *   cert, key,
 *   session(session, request) { ... },
 * });
 * ```
 *
 * Returning normally from `session` accepts; throwing rejects the session.
 *
 * @param {{
 *   port: number,
 *   hostname?: string,
 *   cert: string,
 *   key: string,
 *   maxSessions?: number,
 *   session: (session: WebTransportServerSession, request: WebTransportSessionRequest) => unknown,
 *   error?: (err: unknown) => unknown,
 * }} options
 */
export async function serve(options) {
  if (typeof options?.session !== "function") {
    throw new TypeError("serve() requires a session handler");
  }
  if (!options.cert || !options.key) {
    throw new TypeError("serve() requires cert and key");
  }

  const server = await native.WebTransportServer.bind({
    port: options.port ?? 0,
    host: options.hostname,
    cert: options.cert,
    key: options.key,
    maxSessions: options.maxSessions,
    maxConcurrentStreams: options.maxConcurrentStreams,
  });

  let stopped = false;
  const onError =
    options.error ??
    ((err) => {
      // Without a handler a failing session would be silent, which is worse
      // than a message on stderr.
      console.error("webtransport: unhandled session error:", err);
    });

  // Connection-level failures never reach a session, so they are drained
  // separately and reported through the same handler.
  (async () => {
    while (!stopped) {
      const message = await server.nextError();
      if (message === null || message === undefined) return;
      if (!stopped) onError(toWebTransportError(message, "session"));
    }
  })();

  (async () => {
    while (!stopped) {
      let incoming;
      try {
        incoming = await server.accept();
      } catch (err) {
        if (!stopped) onError(toWebTransportError(err, "session"));
        return;
      }
      if (!incoming) return;

      const request = new WebTransportSessionRequest(incoming);
      // Each session is handled independently: one throwing must not stop the
      // server from accepting others.
      (async () => {
        try {
          const nativeSession = incoming.accept();
          const session = new WebTransportServerSession(nativeSession);
          await options.session(session, request);
        } catch (err) {
          onError(toWebTransportError(err, "session"));
        }
      })();
    }
  })();

  return {
    get port() {
      return server.port;
    },
    stop() {
      stopped = true;
      // Not just a flag: both loops are parked on `accept()` and
      // `nextError()`, which resolve only once the addon ends those queues.
      // Leaving them pending keeps the event loop alive so the process never
      // exits, and leaves napi calls outstanding at teardown, which aborts it.
      return server.stop();
    },
  };
}
