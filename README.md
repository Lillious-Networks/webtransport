# @lillious-networks/webtransport-bun

W3C [WebTransport](https://www.w3.org/TR/webtransport/) for [Bun](https://bun.sh),
backed by a Rust QUIC/HTTP-3 stack (quinn + rustls) through a napi-rs addon.

Client and server, datagrams and streams, over HTTP/3. Verified against Chrome, Firefox, and Safari (desktop and iOS).

- Implements the W3C Candidate Recommendation surface, including `sendGroup` /
  `sendOrder` scheduling, `WebTransportWriter`, `exportKeyingMaterial`, and
  connection pooling.
- Streams are real WHATWG `ReadableStream` / `WritableStream` with working
  backpressure, not lookalikes.
- Protocol work happens in Rust on a Tokio runtime. Nothing blocks the JS thread.

Requires **Bun >= 1.4**. There is no Node or Deno support by design.

## Install

```bash
bun add @lillious-networks/webtransport-bun
```

Prebuilt binaries ship for linux x64/arm64 (gnu and musl), macOS x64/arm64, and
Windows x64. Other platforms build from source and need a Rust toolchain.

## Client

```ts
import { WebTransport } from "@lillious-networks/webtransport-bun";

const wt = new WebTransport("https://example.com:4433/chat");
await wt.ready;

// Datagrams: unreliable, unordered, no head-of-line blocking.
const writer = wt.datagrams.createWritable().getWriter();
await writer.write(new TextEncoder().encode("hello"));

const reader = wt.datagrams.readable.getReader();
const { value } = await reader.read();

// Streams: reliable and ordered.
const stream = await wt.createBidirectionalStream();
await stream.writable.getWriter().write(new Uint8Array([1, 2, 3]));

await wt.close({ closeCode: 0, reason: "done" });
```

## Server

```ts
import { serve, generateSelfSigned } from "@lillious-networks/webtransport-bun";

const { cert, key, hash } = generateSelfSigned(["localhost", "127.0.0.1"]);

const server = await serve({
  port: 4433,
  hostname: "0.0.0.0",
  cert,
  key,
  maxSessions: 1024,
  async session(session, request) {
    console.log(`session on ${request.path}`);

    const reader = session.datagrams.readable.getReader();
    const writer = session.datagrams.createWritable().getWriter();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      await writer.write(value);
    }
  },
  error(err) {
    console.error(err);
  },
});
```

A session object has the same shape on both sides, so one mental model covers
client and server.

## Connecting without a CA

WebTransport requires TLS even on localhost. `generateSelfSigned` returns a
certificate a browser will accept by hash, which avoids running a CA for local
development:

```ts
const { cert, key, hash } = generateSelfSigned(["localhost", "127.0.0.1"]);

const wt = new WebTransport("https://127.0.0.1:4433/", {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
});
```

Certificates used this way must be ECDSA P-256 and valid for at most two weeks,
which is a spec requirement rather than a choice here. `generateSelfSigned`
issues a 13-day certificate to stay inside it. Note that `serverCertificateHashes`
and `allowPooling` are mutually exclusive, per spec.

## Scheduling

Send groups are equal claimants on bandwidth. Within a group, streams drain by
`sendOrder`, highest first:

```ts
const group = wt.createSendGroup();
const critical = await wt.createUnidirectionalStream({ sendGroup: group, sendOrder: 100n });
const bulk = await wt.createUnidirectionalStream({ sendGroup: group, sendOrder: 0n });
```

Each group is its own numberspace, so orders never compare across groups.

## API

Exports: `WebTransport`, `WebTransportError`, `WebTransportSendGroup`,
`WebTransportDatagramDuplexStream`, `WebTransportDatagramsWritable`,
`WebTransportBidirectionalStream`, `WebTransportReceiveStream`,
`WebTransportSendStream`, `WebTransportWriter`, `serve`, `generateSelfSigned`.

Full type declarations are in [`js/index.d.ts`](js/index.d.ts). Runnable
examples are in [`examples/`](examples/).

## Development

```bash
bun install
bun run build          # build the native addon
bun test               # JS suite (needs the addon built)
cargo test --workspace # Rust suite
bun run typecheck
```

Check Chrome interop with `bun examples/04-chrome-interop.ts`, then open
`http://127.0.0.1:8099/`. Keep that server running for the whole check: each
restart mints a new certificate, and the page pins the old hash.

## Known limits

- Each QUIC connection reserves stream bookkeeping proportional to
  `maxConcurrentStreams`, roughly 0.36 KiB per permitted stream. The default of
  2000 costs about 0.7 MiB per connection, which a server holding thousands of
  them will feel; raise it only if an application genuinely needs more
  concurrent streams than that, and expect the memory to scale with it.
- `getStats` omits members quinn cannot source rather than reporting invented
  values, so a returned dictionary may be missing fields the IDL lists.
- `congestionControl` is a hint, as the spec permits. It selects a quinn
  controller and pacing behaviour.
- `outgoingMaxBufferedDatagrams` is the outgoing writable's high water mark, so
  it does apply backpressure, but a send hands straight to quinn with no
  outgoing queue. A producer that writes one datagram per turn therefore never
  builds a backlog, where a browser's slower send would.
- `incomingMaxBufferedDatagrams` does not resize the receive queue, which is a
  fixed 1024 datagrams chosen when the session is created. Datagrams dropped by
  that queue are counted and reported as `getStats().datagrams.droppedIncoming`.
- Datagram stats other than `droppedIncoming` report 0: per-datagram expiry and
  loss accounting is not available from the transport. They are present rather
  than omitted because the IDL does not make them optional.

## Web Platform Tests

`bun run wpt` runs the upstream WPT WebTransport suite against this library.
The tests are fetched from web-platform-tests at run time rather than vendored,
so they track upstream rather than going stale.

They are written for a browser, so three pieces bridge the gap: `wpt/harness.ts`
reimplements the testharness.js assertions they call, `wpt/handlers.ts` ports the
Python `wptserve` handlers onto this server, and `wpt/run.ts` resolves the
`// META:` directives and substitutions.

Not everything can run. A handler needing CONNECT response headers, which
`serve()` does not expose, is reported as unsupported rather than failed, and a
handful of tests contradict the current spec (calling `exportKeyingMaterial`
with fewer than the three arguments the IDL requires, for instance) and are
recorded as such with the reason. A test recorded that way which starts passing
is reported as a failure, so the entry gets removed rather than outliving it.

Chromium interop is checked separately with `examples/04-chrome-interop.ts`.

## License

MIT
