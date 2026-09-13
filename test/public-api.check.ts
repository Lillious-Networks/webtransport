/**
 * Compile-time conformance between the implementation and the published
 * declarations.
 *
 * Consumers type-check against `js/types.d.ts` while Bun runs `js/index.ts`,
 * and nothing else ties the two together. This file fails `bun run typecheck`
 * when an export the declarations promise is missing from the implementation,
 * or its type no longer matches. It is type-checked only, never executed.
 */

import type * as Public from "../js/types.d.ts";
import * as Impl from "../js/index.ts";

/** Resolves only when `Actual` is assignable to `Expected`. */
export type Conforms<Actual extends Expected, Expected> = Actual;

// Constructible classes and exported functions are compared as whole values:
// constructor signature, static members and call signature included.
Impl.WebTransport satisfies typeof Public.WebTransport;
Impl.WebTransportError satisfies typeof Public.WebTransportError;
Impl.serve satisfies typeof Public.serve;
Impl.generateSelfSigned satisfies typeof Public.generateSelfSigned;
Impl.generateCaSigned satisfies typeof Public.generateCaSigned;
Impl.signWithCa satisfies typeof Public.signWithCa;

// The declarations give these a private constructor: the implementation's
// constructors take native handles and are not public API. Only their
// instances are compared.
export type Instances = [
  Conforms<Impl.WebTransportSendGroup, Public.WebTransportSendGroup>,
  Conforms<Impl.WebTransportSendStream, Public.WebTransportSendStream>,
  Conforms<Impl.WebTransportReceiveStream, Public.WebTransportReceiveStream>,
  Conforms<Impl.WebTransportWriter, Public.WebTransportWriter>,
  Conforms<Impl.WebTransportBidirectionalStream, Public.WebTransportBidirectionalStream>,
  Conforms<Impl.WebTransportDatagramsWritable, Public.WebTransportDatagramsWritable>,
  Conforms<Impl.WebTransportDatagramDuplexStream, Public.WebTransportDatagramDuplexStream>,
  Conforms<Impl.WebTransportServerSession, Public.WebTransportServerSession>,
  Conforms<Impl.WebTransportSessionRequest, Public.WebTransportSessionRequest>,
  Conforms<Impl.WebTransportServer, Public.WebTransportServer>,
];
