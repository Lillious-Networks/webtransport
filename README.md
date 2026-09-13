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
certificate a client will accept by hash, which avoids running a CA for local
development:

```ts
const { cert, key, hash } = generateSelfSigned(["localhost", "127.0.0.1"]);

const wt = new WebTransport("https://127.0.0.1:4433/", {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
});
```

### Certificate constraints

A certificate accepted through `serverCertificateHashes` must satisfy the W3C
WebTransport requirements:

| Property | Requirement |
|---|---|
| Key | ECDSA P-256 |
| Validity period | At most 14 days |
| Subject Alternative Name | Must cover the host in the connection URL |

`serverCertificateHashes` and `allowPooling` are mutually exclusive; supplying
both throws `NotSupportedError` from the constructor. Safari does not implement
`serverCertificateHashes`. For Safari, use a certificate that chains to a
trusted CA (see `generateCaSigned`).

### `generateSelfSigned(hostnames?)`

Returns `{ cert: string, key: string, hash: Uint8Array }`.

| Field | Format |
|---|---|
| `cert` | PEM-encoded certificate, ECDSA P-256, valid for 13 days |
| `key` | PEM-encoded PKCS#8 private key |
| `hash` | 32-byte SHA-256 digest of the DER-encoded certificate |

`hostnames` defaults to `["localhost"]` and populates the SAN. Each call
generates a new key pair and certificate. Two calls, including calls made in
separate processes, return different certificates with different hashes.

### Hash value

`serverCertificateHashes[].value` is typed `BufferSource`. The library accepts a
`Uint8Array`, any other `ArrayBufferView`, or an `ArrayBuffer`. Strings are
rejected with `TypeError` at construction. A `sha-256` value must be exactly 32
bytes.

The hash is the SHA-256 digest of the certificate's DER encoding, so it can be
recomputed from the PEM at any time:

```ts
import { createHash, X509Certificate } from "node:crypto";

const hash = new Uint8Array(createHash("sha256").update(new X509Certificate(cert).raw).digest());
```

### Persisting a certificate across processes

When the server and client run as separate processes, both must use the same
certificate. The following module persists the PEM files, derives the hash on
load, and regenerates the certificate within 24 hours of expiry:

```ts
// devcert.ts, imported by both server and client
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateSelfSigned } from "@lillious-networks/webtransport-bun";

const DIR = ".certs";
const CERT = join(DIR, "cert.pem");
const KEY = join(DIR, "key.pem");
const RENEW_MS = 24 * 60 * 60 * 1000;

function load() {
  if (!existsSync(CERT) || !existsSync(KEY)) return null;
  const cert = readFileSync(CERT, "utf8");
  const expires = Date.parse(new X509Certificate(cert).validTo);
  if (expires - Date.now() < RENEW_MS) return null;
  return { cert, key: readFileSync(KEY, "utf8") };
}

export function devCertificate() {
  let pair = load();
  if (!pair) {
    const { cert, key } = generateSelfSigned(["localhost", "127.0.0.1"]);
    mkdirSync(DIR, { recursive: true });
    writeFileSync(CERT, cert);
    writeFileSync(KEY, key, { mode: 0o600 });
    pair = { cert, key };
  }
  const hash = new Uint8Array(
    createHash("sha256").update(new X509Certificate(pair.cert).raw).digest(),
  );
  return { ...pair, hash };
}
```

```ts
// server.ts
const { cert, key } = devCertificate();
await serve({ port: 4433, cert, key, session(session) {} });

// client.ts
const { hash } = devCertificate();
const wt = new WebTransport("https://127.0.0.1:4433/", {
  serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
});
```

`.certs/key.pem` is a private key and should be excluded from version control.
A renewed certificate has a new hash; clients holding the previous hash must
reload it.

### Transmitting the hash as text

To deliver the hash to a client that cannot share the module above, such as a
browser page, encode it as base64 and decode it back to bytes before passing it
to `WebTransport`:

```ts
const text = Buffer.from(hash).toString("base64"); // server
const value = Uint8Array.from(atob(text), (c) => c.charCodeAt(0)); // browser
```

### Errors

| Error | Cause |
|---|---|
| `server certificate does not match any serverCertificateHashes entry` | The server presented a certificate whose digest is not in `serverCertificateHashes`. The two sides are using different certificates. |
| `TypeError: certificate hash values must be BufferSource, got a string` | `value` is a string. Decode it to bytes. |
| `a Sha256 hash must be 32 bytes, got N` | `value` has the wrong length, typically from decoding with the wrong encoding. |
| Handshake failure after the certificate's `validTo` | The certificate has expired. Regenerate it. |

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
`WebTransportSendStream`, `WebTransportWriter`, `serve`, `generateSelfSigned`,
`generateCaSigned`, `signWithCa`.

Full type declarations are in [`js/types.d.ts`](js/types.d.ts). Runnable
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
