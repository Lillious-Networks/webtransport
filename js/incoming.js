/**
 * Turns the addon's "accept the next stream" call into a ReadableStream.
 *
 * `incomingBidirectionalStreams` and `incomingUnidirectionalStreams` are
 * ReadableStreams of stream objects, so the pull loop hands each accepted
 * stream to the consumer and closes when the session ends.
 */

import { toWebTransportError } from "./errors.js";

/**
 * @param {() => Promise<object | null>} accept the addon's accept call
 * @param {(native: object) => object} wrap builds the JS stream object
 * @returns {ReadableStream}
 */
export function makeIncomingStreams(accept, wrap) {
  return new ReadableStream({
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
