/**
 * Turns the addon's "accept the next stream" call into a ReadableStream.
 *
 * `incomingBidirectionalStreams` and `incomingUnidirectionalStreams` are
 * ReadableStreams of stream objects, so the pull loop hands each accepted
 * stream to the consumer and closes when the session ends.
 */

import { toWebTransportError } from "./errors.ts";

/**
 * @param accept the addon's accept call, resolving null once the session ends
 * @param wrap builds the JS stream object around an accepted native handle
 */
export function makeIncomingStreams<N, T>(
  accept: () => Promise<N | null | undefined>,
  wrap: (native: N) => T,
): ReadableStream<T> {
  return new ReadableStream<T>({
    async pull(controller) {
      try {
        const native = await accept();
        if (native === null || native === undefined) {
          // The session ended, so no further streams can arrive.
          controller.close();
          return;
        }
        controller.enqueue(wrap(native));
      } catch (err) {
        controller.error(toWebTransportError(err, "session"));
      }
    },
  });
}
