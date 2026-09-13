/**
 * The WPT WebTransport server handlers, ported from `webtransport/handlers/*.py`.
 *
 * Upstream runs these under wptserve, whose handler API is a set of callbacks
 * (`session_established`, `stream_data_received`, `datagram_received`). This
 * maps the same behaviour onto our own server, keyed by the request path so one
 * server can serve every handler the tests ask for.
 */

import type { WebTransportServerSession, WebTransportSessionRequest } from "../js/types.d.ts";

export type Handler = (
  session: WebTransportServerSession,
  request: WebTransportSessionRequest,
) => unknown;

/** Pipes every incoming stream back to the peer, and echoes datagrams. */
const echo: Handler = async (session) => {
  void pumpDatagrams(session, (data) => data);

  // echo.py opens a bidirectional stream from session_established, which the
  // tests read from incomingBidirectionalStreams and expect to echo.
  void (async () => {
    try {
      const opened = await session.createBidirectionalStream();
      await opened.readable.pipeTo(opened.writable);
    } catch {
      // The peer never used it, or the session ended first.
    }
  })();

  // Bidirectional streams echo on the same stream; unidirectional ones echo
  // onto a fresh unidirectional stream, matching echo.py.
  void (async () => {
    const reader = session.incomingBidirectionalStreams.getReader();
    for (;;) {
      const { value, done } = await reader.read().catch(() => ({ value: undefined, done: true }));
      if (done || !value) break;
      void value.readable.pipeTo(value.writable).catch(() => {});
    }
  })();

  void (async () => {
    const reader = session.incomingUnidirectionalStreams.getReader();
    for (;;) {
      const { value, done } = await reader.read().catch(() => ({ value: undefined, done: true }));
      if (done || !value) break;
      void (async () => {
        try {
          const out = await session.createUnidirectionalStream();
          await value.pipeTo(out);
        } catch {
          // The peer went away mid-echo, which the tests treat as ordinary.
        }
      })();
    }
  })();
};

/** Replies to each datagram with the JSON length of what arrived. */
const echoDatagramLength: Handler = async (session) => {
  const encoder = new TextEncoder();
  void pumpDatagrams(session, (data) => encoder.encode(JSON.stringify({ length: data.byteLength })));
};

/** Closes the session, optionally with the code and reason from the query. */
const serverClose: Handler = async (session, request) => {
  const query = queryOf(request.path);
  const code = query.get("code");
  if (code === null) {
    session.close();
  } else {
    session.close({ closeCode: Number(code), reason: query.get("reason") ?? "" });
  }
};

/** Begins draining when the query says to. */
const serverDrain: Handler = async (session, request) => {
  if (queryOf(request.path).has("drain")) session.drain();
};

/** Reads a stream to completion, then closes the session. */
const serverReadThenClose: Handler = async (session) => {
  const reader = session.incomingUnidirectionalStreams.getReader();
  const { value } = await reader.read().catch(() => ({ value: undefined }));
  if (value) await new Response(value as any).arrayBuffer().catch(() => {});
  session.close();
};

/**
 * Opens `count` streams of the requested type, writing "stream<i>" on each.
 *
 * The payload is what the test matches on, so each stream is closed after
 * its write rather than left open.
 */
const serverCreateMultipleStreams: Handler = async (session, request) => {
  const query = queryOf(request.path);
  const count = Number(query.get("count") ?? "3");
  const unidirectional = query.get("type") === "unidi";
  const encoder = new TextEncoder();

  for (let i = 0; i < count; i++) {
    const writable = unidirectional
      ? await session.createUnidirectionalStream()
      : (await session.createBidirectionalStream()).writable;
    const writer = writable.getWriter();
    await writer.write(encoder.encode(`stream${i}`));
    await writer.close().catch(() => {});
  }
};

export const handlers: Record<string, Handler> = {
  "echo.py": echo,
  "echo_datagram_length.py": echoDatagramLength,
  "server-close.py": serverClose,
  "server-drain.py": serverDrain,
  "server-read-then-close.py": serverReadThenClose,
  "server-create-multiple-streams.py": serverCreateMultipleStreams,
};

/**
 * Handlers upstream implements that this server cannot serve, with why.
 *
 * Recorded rather than dropped so a test that needs one is reported as
 * unsupported instead of silently failing on a connection that never
 * behaves as the test expects.
 */
export const unsupportedHandlers: Record<string, string> = {
  "custom-response.py":
    "needs the CONNECT response headers and status to be set by the application; serve() exposes neither",
  "echo-request-headers.py":
    "needs application-supplied CONNECT response headers to echo the request's back",
  "abort-stream-from-server.py": "needs a server-side stream abort with a chosen error code",
  "client-close.py": "needs the close code and reason the client sent to be readable by the handler",
  "server-connection-close.py": "needs the QUIC connection closed underneath the session",
  "sendorder.py": "needs per-stream send order applied to server-created streams from the handler",
  "query.py": "a wptserve helper with no session behaviour of its own",
  "token-count.py": "needs cross-session state keyed by a token in the query",
};

/** Reads datagrams until the session ends, replying with `respond(data)`. */
async function pumpDatagrams(
  session: WebTransportServerSession,
  respond: (data: Uint8Array) => Uint8Array,
): Promise<void> {
  try {
    const reader = session.datagrams.readable.getReader();
    const writer = session.datagrams.createWritable().getWriter();
    for (;;) {
      const { value, done } = await reader.read();
      if (done || !value) break;
      await writer.write(respond(value));
    }
  } catch {
    // The session ended; nothing here outlives it.
  }
}

function queryOf(path: string): URLSearchParams {
  const q = path.indexOf("?");
  return new URLSearchParams(q === -1 ? "" : path.slice(q + 1));
}
