/**
 * WebTransportError and the mapping from engine errors to it.
 *
 * Per the spec this is a DOMException subclass whose `name` is
 * "WebTransportError" and whose `code` is therefore 0 (the name has no legacy
 * code mapping).
 */

export class WebTransportError extends DOMException {
  #source;
  #streamErrorCode;

  /**
   * @param {string} [message]
   * @param {{ source?: "stream" | "session", streamErrorCode?: number | null }} [options]
   */
  constructor(message = "", options = {}) {
    super(message, "WebTransportError");
    const source = options.source ?? "stream";
    if (source !== "stream" && source !== "session") {
      throw new TypeError(
        `source must be "stream" or "session", got ${JSON.stringify(source)}`,
      );
    }
    this.#source = source;

    const code = options.streamErrorCode ?? null;
    if (code !== null) {
      // The IDL clamps rather than throwing, so out-of-range values saturate.
      const clamped = Math.min(Math.max(Math.round(Number(code)), 0), 0xffffffff);
      this.#streamErrorCode = Number.isNaN(clamped) ? 0 : clamped;
    } else {
      this.#streamErrorCode = null;
    }
  }

  /** @returns {"stream" | "session"} */
  get source() {
    return this.#source;
  }

  /** @returns {number | null} */
  get streamErrorCode() {
    return this.#streamErrorCode;
  }
}

/**
 * Patterns the engine uses to report peer-signalled failures. The Rust layer
 * formats these; parsing them here keeps the addon boundary free of a bespoke
 * error-object protocol.
 */
const RESET_PATTERN = /peer reset the stream \(code (\d+)\)/;
const STOPPED_PATTERN = /peer stopped reading the stream \(code (\d+)\)/;
const CLOSED_BY_PEER_PATTERN = /peer closed the session \(code (\d+)\)/;

/**
 * Converts an error thrown by the native addon into a WebTransportError.
 *
 * @param {unknown} err
 * @param {"stream" | "session"} [defaultSource]
 * @returns {WebTransportError}
 */
export function toWebTransportError(err, defaultSource = "session") {
  if (err instanceof WebTransportError) return err;

  const message = err instanceof Error ? err.message : String(err);

  const reset = RESET_PATTERN.exec(message);
  if (reset) {
    return new WebTransportError(message, {
      source: "stream",
      streamErrorCode: Number(reset[1]),
    });
  }

  const stopped = STOPPED_PATTERN.exec(message);
  if (stopped) {
    return new WebTransportError(message, {
      source: "stream",
      streamErrorCode: Number(stopped[1]),
    });
  }

  const closed = CLOSED_BY_PEER_PATTERN.exec(message);
  if (closed) {
    return new WebTransportError(message, { source: "session" });
  }

  return new WebTransportError(message, { source: defaultSource });
}

/**
 * Marks a promise as handled so an expected rejection never surfaces as an
 * unhandled rejection.
 *
 * The spec has `ready`, `closed` and `draining` reject in the normal course of
 * events, and an application is not obliged to observe all three.
 *
 * @template T
 * @param {Promise<T>} promise
 * @returns {Promise<T>}
 */
export function markHandled(promise) {
  promise.catch(() => {});
  return promise;
}
