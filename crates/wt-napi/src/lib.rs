//! napi-rs bindings exposing the WebTransport engine to Bun.
//!
//! The addon owns a multi-threaded Tokio runtime independent of Bun's event
//! loop. Nothing here blocks the JS thread: every operation that can wait is an
//! async function returning a promise, and inbound events reach JS through
//! threadsafe callbacks.
//!
//! This layer is deliberately thin. It exposes handles and primitives; the W3C
//! semantics (stream types, promise states, error shapes) live in the JS layer,
//! which is where the spec's stream machinery belongs.

#![deny(clippy::all)]

use napi::bindgen_prelude::*;
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
// The builder's callback type still uses this name; see `start_datagram_pump`.
#[allow(deprecated)]
use napi::threadsafe_function::ThreadSafeCallContext;
use napi_derive::napi;
use std::sync::Arc;
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::{client, server, CloseInfo, Session, State};

/// A batch of datagram payloads, packed for the JS crossing: each entry is a
/// varint length followed by that many payload bytes. One buffer per batch
/// keeps the threadsafe call count down to one per batch rather than one per
/// datagram, and lets JS split it into views without copying.
type DatagramBatch = Vec<u8>;

/// The pump's threadsafe function: delivers `DatagramBatch` to JS, holds up to
/// 16 batches, and does not keep the event loop alive on its own.
type DatagramTsfn =
    ThreadsafeFunction<DatagramBatch, Unknown<'static>, Uint8Array, Status, false, true, 16>;

/// Options accepted by `connect`, mirroring `WebTransportOptions`.
#[napi(object)]
#[derive(Default)]
pub struct JsClientOptions {
    /// Certificate hashes as `{ algorithm, value }`, where value is a byte array.
    pub server_certificate_hashes: Option<Vec<JsCertHash>>,
    pub headers: Option<Vec<JsHeader>>,
    pub protocols: Option<Vec<String>>,
    pub require_unreliable: Option<bool>,
    /// "default" | "throughput" | "low-latency".
    pub congestion_control: Option<String>,
    /// Share a QUIC connection with other sessions to the same origin. The JS
    /// layer rejects this alongside certificate hashes before it reaches here.
    pub allow_pooling: Option<bool>,
}

#[napi(object)]
pub struct JsCertHash {
    pub algorithm: String,
    pub value: Uint8Array,
}

#[napi(object)]
pub struct JsHeader {
    pub name: String,
    pub value: String,
}

/// Connection statistics that the transport can actually report.
#[napi(object)]
pub struct JsConnectionStats {
    pub bytes_sent: BigInt,
    pub bytes_received: BigInt,
    pub packets_sent: BigInt,
    pub packets_received: BigInt,
    pub packets_lost: BigInt,
    pub bytes_lost: BigInt,
    /// Milliseconds.
    pub smoothed_rtt: f64,
    /// Milliseconds.
    pub min_rtt: f64,
    pub congestion_window: BigInt,
}

/// Converts an optional BigInt group id.
fn to_group(value: Option<BigInt>) -> Option<u64> {
    value.map(|b| b.get_u64().1)
}

/// Converts an optional BigInt send order, preserving the full 64-bit range.
fn to_order(value: Option<BigInt>) -> Option<i64> {
    value.map(|b| b.get_i64().0)
}

/// How a session ended.
#[napi(object)]
pub struct JsCloseInfo {
    pub close_code: u32,
    pub reason: String,
}

fn to_napi_err(e: wt_core::Error) -> Error {
    // The JS layer turns these into WebTransportError with the right source and
    // streamErrorCode; the reason travels as the message.
    Error::new(Status::GenericFailure, e.to_string())
}

/// A connected WebTransport session, as seen from JS.
#[napi]
pub struct WebTransportSession {
    inner: Arc<SessionHolder>,
}

/// Keeps the session alive together with whatever handles its transport needs.
struct SessionHolder {
    session: Session,
    /// The negotiated subprotocol, empty when none was chosen.
    protocol: String,
    /// The client-side handles (endpoint, CONNECT stream, h3 sender) whose drop
    /// would close the session. Absent for server-side sessions, which are kept
    /// alive by the server's connection task instead.
    _client: Option<client::ClientSession>,
}

#[napi]
impl WebTransportSession {
    /// The CONNECT stream id identifying this session.
    #[napi(getter)]
    pub fn id(&self) -> BigInt {
        BigInt::from(self.inner.session.id())
    }

    /// "pending" | "reliable-only" | "supports-unreliable".
    #[napi(getter)]
    pub fn reliability(&self) -> String {
        if self.inner.session.supports_datagrams() {
            "supports-unreliable".to_owned()
        } else {
            "reliable-only".to_owned()
        }
    }

    /// Largest datagram payload that can be sent right now, or null when
    /// datagrams are unavailable. Varies with the path MTU.
    #[napi(getter)]
    pub fn max_datagram_size(&self) -> Option<u32> {
        self.inner.session.max_datagram_size().map(|v| v as u32)
    }

    /// The subprotocol the server selected, or an empty string.
    #[napi(getter)]
    pub fn protocol(&self) -> String {
        self.inner.protocol.clone()
    }

    /// Headers from the server's CONNECT response, as name/value pairs.
    ///
    /// Empty for a server-side session, which never receives one.
    #[napi(getter)]
    pub fn response_headers(&self) -> Vec<Vec<String>> {
        self.inner
            ._client
            .as_ref()
            .map(|c| {
                c.response_headers
                    .iter()
                    .map(|(name, value)| vec![name.clone(), value.clone()])
                    .collect()
            })
            .unwrap_or_default()
    }

    #[napi(getter)]
    pub fn state(&self) -> String {
        match self.inner.session.state() {
            State::Connecting => "connecting",
            State::Connected => "connected",
            State::Draining => "draining",
            State::Closed(_) => "closed",
            State::Failed(_) => "failed",
        }
        .to_owned()
    }

    /// Sends one datagram.
    ///
    /// Synchronous because it either fits the current window or fails at once;
    /// there is nothing to await.
    #[napi]
    pub fn send_datagram(&self, payload: Uint8Array) -> Result<()> {
        self.inner
            .session
            .send_datagram(payload.as_ref())
            .map_err(to_napi_err)
    }

    /// Sends several datagrams in one call.
    ///
    /// A game server pushing tens of thousands of movement datagrams a second
    /// pays the JS-to-native crossing per datagram; batching amortises it.
    /// Oversized entries are skipped rather than failing the batch, matching
    /// the unreliable semantics of a single send.
    #[napi]
    pub fn send_datagrams(&self, payloads: Vec<Uint8Array>) -> u32 {
        let mut sent = 0u32;
        for payload in &payloads {
            if self.inner.session.send_datagram(payload.as_ref()).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    /// Bytes currently queued for sending on this session.
    ///
    /// Applications use this for their own backpressure decisions (shedding
    /// load for a client that has stopped keeping up), so it is a cheap
    /// synchronous read rather than part of `getStats`.
    #[napi(getter)]
    pub fn queued_bytes(&self) -> BigInt {
        BigInt::from(self.inner.session.queued_bytes())
    }

    /// Inbound datagrams dropped because the receive queue was full.
    ///
    /// Non-zero under overload; the pattern of loss (steady vs bursty) tells an
    /// application whether it is behind by a constant margin or just failing
    /// to absorb spikes.
    #[napi(getter)]
    pub fn datagrams_dropped(&self) -> BigInt {
        BigInt::from(self.inner.session.datagrams_dropped())
    }

    /// UDP datagrams the transport has received on this session's connection.
    ///
    /// Not in the spec; the transport-level counterpart of `datagramsDropped`.
    /// Comparing the two locates loss: a gap means the network or socket
    /// dropped packets; parity means an application-level queue did.
    #[napi(getter)]
    pub fn udp_packets_received(&self) -> BigInt {
        let received = self
            .inner
            .session
            .stats()
            .map(|s| s.packets_received)
            .unwrap_or(0);
        BigInt::from(received)
    }

    /// Resolves with the next inbound datagram, or null once the session ends.
    ///
    /// Returns owned bytes: the payload outlives the Rust buffer it arrived in.
    #[napi]
    pub async fn recv_datagram(&self) -> Option<Uint8Array> {
        self.inner
            .session
            .recv_datagram()
            .await
            .map(|b| Uint8Array::new(b.to_vec()))
    }

    /// Resolves with up to `max` inbound datagrams, or null once the session
    /// ends.
    ///
    /// The async boundary costs a promise per call, so pulling datagrams one at
    /// a time caps throughput far below what the transport delivers (the Rust
    /// path sustains millions a second; per-datagram promises sustain
    /// thousands). One call per batch amortises that crossing.
    #[napi]
    pub async fn recv_datagrams(&self, max: u32) -> Option<Vec<Uint8Array>> {
        let batch = self
            .inner
            .session
            .recv_datagrams(max.clamp(1, 4096) as usize)
            .await?;
        Some(
            batch
                .into_iter()
                .map(|b| Uint8Array::new(b.to_vec()))
                .collect(),
        )
    }

    /// Switches inbound datagram delivery to a push pump.
    ///
    /// `callback` is invoked on the JS thread with batches of `Uint8Array`,
    /// and once with an empty batch when the session ends. Push delivery
    /// exists because even batched pulls still pay the promise machinery once
    /// per batch per session: under many low-rate sessions that is once per
    /// datagram, which saturates the JS thread long before the transport
    /// does. A threadsafe function crosses into JS without a promise, so the
    /// per-datagram cost becomes an ordinary stream enqueue.
    ///
    /// The pump applies backpressure in Rust: its queue holds 16 batches and
    /// blocks when full, which fills the session's own bounded queue, which
    /// drops the oldest datagram, so loss stays accounted for and bounded.
    #[napi]
    #[allow(deprecated)]
    pub fn start_datagram_pump(&self, callback: Function<'_, (), Unknown<'static>>) -> Result<()> {
        let tsfn: DatagramTsfn = callback
            .build_threadsafe_function::<DatagramBatch>()
            .max_queue_size::<16>()
            .weak::<true>()
            .callee_handled::<false>()
            .build_callback(|ctx: ThreadSafeCallContext<DatagramBatch>| {
                Ok(Uint8Array::new(ctx.value))
            })?;

        // Deliberately not stored on the holder. The callback reaches back
        // into JS (it holds the datagram stream's controller, which holds this
        // session handle), so keeping it here makes a reference cycle across
        // the boundary that neither collector can see: the session's finalizer
        // would never run and its transport state never be freed. The spawned
        // task below owns the callback, and drops it when the pump ends.
        let session = self.inner.session.clone();
        // `spawn` from the prelude, not tokio's: this method is a sync napi
        // call on the JS thread, where no runtime context exists. The prelude
        // helper targets the addon's own runtime regardless of the caller.
        napi::bindgen_prelude::spawn(async move {
            loop {
                match session.recv_datagrams(256).await {
                    Some(batch) => {
                        // The LEB128-framed batch format lives in wt-core so it
                        // is unit-tested against the JS decoder; encoding it
                        // here would drift (a mismatch corrupts every payload
                        // above 63 bytes while short test vectors still pass).
                        let packed = wt_core::Session::pack_datagram_batch(&batch);
                        if tsfn.call(packed, ThreadsafeFunctionCallMode::Blocking) != Status::Ok {
                            break;
                        }
                    }
                    None => {
                        // Session ended: an empty batch tells JS to close the
                        // stream rather than hang its reader.
                        let _ = tsfn.call(Vec::new(), ThreadsafeFunctionCallMode::Blocking);
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    /// Resolves when the session reaches a terminal state, reporting how it
    /// ended. Backs the `closed` promise.
    #[napi]
    pub async fn closed(&self) -> JsCloseInfo {
        let mut watch = self.inner.session.watch();
        loop {
            let state = watch.borrow().clone();
            match state {
                State::Closed(info) => {
                    return JsCloseInfo {
                        close_code: info.code,
                        reason: info.reason,
                    }
                }
                State::Failed(reason) => {
                    return JsCloseInfo {
                        close_code: 0,
                        reason,
                    }
                }
                _ => {}
            }
            if watch.changed().await.is_err() {
                // The session was dropped without a recorded close.
                return JsCloseInfo {
                    close_code: 0,
                    reason: String::new(),
                };
            }
        }
    }

    /// Resolves once the session begins draining. Backs the `draining` promise.
    ///
    /// Only `Draining` settles this. A session that closes without ever
    /// draining leaves the promise pending for good, which is what the spec
    /// asks for: `draining` reports that the session started winding down,
    /// not that it ended.
    /// Resolves `true` once the session drains, or `false` if it ends without
    /// ever draining.
    ///
    /// It reports the outcome rather than staying pending on the second case:
    /// a napi future that never settles holds its JS callback, and through it
    /// the whole `WebTransport`, for the life of the process. The JS layer
    /// leaves its own `draining` promise pending when this answers `false`,
    /// which is what the spec asks for.
    #[napi]
    pub async fn draining(&self) -> bool {
        let mut watch = self.inner.session.watch();
        loop {
            let state = watch.borrow().clone();
            if matches!(state, State::Draining) {
                return true;
            }
            if state.is_terminal() || watch.changed().await.is_err() {
                return false;
            }
        }
    }

    /// Opens a unidirectional stream to the peer.
    ///
    /// `send_group` and `send_order` place the stream in the scheduler; the
    /// order is a string so the full 64-bit range survives the JS boundary,
    /// which cannot represent it as a number.
    #[napi]
    pub async fn create_unidirectional_stream(
        &self,
        send_group: Option<BigInt>,
        send_order: Option<BigInt>,
        wait_until_available: Option<bool>,
    ) -> Result<WtSendStream> {
        let send = self
            .inner
            .session
            .open_uni_with(
                to_group(send_group),
                to_order(send_order),
                wait_until_available.unwrap_or(true),
            )
            .await
            .map_err(to_napi_err)?;
        Ok(WtSendStream { inner: send })
    }

    /// Opens a bidirectional stream to the peer.
    #[napi]
    pub async fn create_bidirectional_stream(
        &self,
        send_group: Option<BigInt>,
        send_order: Option<BigInt>,
        wait_until_available: Option<bool>,
    ) -> Result<WtBidiStream> {
        let stream = self
            .inner
            .session
            .open_bi_with(
                to_group(send_group),
                to_order(send_order),
                wait_until_available.unwrap_or(true),
            )
            .await
            .map_err(to_napi_err)?;
        Ok(WtBidiStream {
            send: stream.send,
            recv: stream.recv,
        })
    }

    /// Derives keying material bound to this session.
    #[napi]
    pub fn export_keying_material(
        &self,
        label: Uint8Array,
        context: Uint8Array,
        length: u32,
    ) -> Result<Uint8Array> {
        self.inner
            .session
            .export_keying_material(label.as_ref(), context.as_ref(), length as usize)
            .map(Uint8Array::new)
            .map_err(to_napi_err)
    }

    /// Connection statistics. Members the transport cannot source are absent
    /// rather than zero.
    #[napi]
    pub fn get_stats(&self) -> Option<JsConnectionStats> {
        self.inner.session.stats().map(|s| JsConnectionStats {
            bytes_sent: BigInt::from(s.bytes_sent),
            bytes_received: BigInt::from(s.bytes_received),
            packets_sent: BigInt::from(s.packets_sent),
            packets_received: BigInt::from(s.packets_received),
            packets_lost: BigInt::from(s.packets_lost),
            bytes_lost: BigInt::from(s.bytes_lost),
            smoothed_rtt: s.smoothed_rtt.as_secs_f64() * 1000.0,
            min_rtt: s.min_rtt.as_secs_f64() * 1000.0,
            congestion_window: BigInt::from(s.congestion_window),
        })
    }

    /// Resolves with the next incoming unidirectional stream, or null once the
    /// session ends.
    #[napi]
    pub async fn accept_unidirectional_stream(&self) -> Option<WtRecvStream> {
        self.inner
            .session
            .accept_uni()
            .await
            .map(|recv| WtRecvStream { inner: recv })
    }

    /// Resolves with the next incoming bidirectional stream, or null once the
    /// session ends.
    #[napi]
    pub async fn accept_bidirectional_stream(&self) -> Option<WtBidiStream> {
        self.inner.session.accept_bi().await.map(|s| WtBidiStream {
            send: s.send,
            recv: s.recv,
        })
    }

    #[napi]
    pub fn close(&self, info: Option<JsCloseInfo>) {
        let info = info
            .map(|i| CloseInfo {
                code: i.close_code,
                reason: i.reason,
            })
            .unwrap_or_default();
        self.inner.session.close(info);
    }

    /// Begins draining: the peer is told to stop opening new streams while
    /// existing ones finish. Sends WT_DRAIN_SESSION on the CONNECT stream.
    #[napi]
    pub fn drain(&self) {
        self.inner.session.drain();
    }
}

/// The send half of a WebTransport stream.
#[napi]
pub struct WtSendStream {
    inner: Arc<wt_core::SendStream>,
}

#[napi]
impl WtSendStream {
    /// Writes a chunk, resolving once the transport has accepted all of it.
    ///
    /// The pending promise is what gives the JS WritableStream real
    /// backpressure: it stays unresolved while the flow-control window is full.
    #[napi]
    pub async fn write(&self, chunk: Uint8Array) -> Result<()> {
        self.inner
            .write_all(chunk.as_ref())
            .await
            .map_err(to_napi_err)
    }

    /// Writes only what fits the current flow-control window, returning how
    /// many bytes were accepted. Backs `atomicWrite`.
    #[napi]
    pub async fn write_some(&self, chunk: Uint8Array) -> Result<u32> {
        self.inner
            .write_some(chunk.as_ref())
            .await
            .map(|n| n as u32)
            .map_err(to_napi_err)
    }

    #[napi]
    pub async fn finish(&self) -> Result<()> {
        self.inner.finish().await.map_err(to_napi_err)
    }

    #[napi]
    pub async fn reset(&self, code: u32) -> Result<()> {
        self.inner.reset(code).await.map_err(to_napi_err)
    }

    /// Resolves with the peer's error code once it stops reading, or null if
    /// the stream ended without one.
    #[napi]
    pub async fn stopped(&self) -> Result<Option<u32>> {
        self.inner.stopped().await.map_err(to_napi_err)
    }

    #[napi(getter)]
    pub fn bytes_written(&self) -> BigInt {
        BigInt::from(self.inner.bytes_written())
    }

    #[napi]
    pub async fn set_priority(&self, priority: i32) {
        self.inner.set_priority(priority).await;
    }

    /// The scheduler id, so send group and order can be changed later.
    #[napi(getter)]
    pub fn scheduler_id(&self) -> Option<BigInt> {
        self.inner.scheduler_id().map(BigInt::from)
    }

    /// Moves this stream into a different send group, or the null group.
    #[napi]
    pub fn set_send_group(&self, group: Option<BigInt>) {
        self.inner.set_send_group(to_group(group));
    }

    /// Changes this stream's send order. `null` withdraws it from strict
    /// ordering, leaving it to share its group's turn.
    #[napi]
    pub fn set_send_order(&self, send_order: Option<BigInt>) {
        self.inner.set_send_order(to_order(send_order));
    }
}

/// The receive half of a WebTransport stream.
#[napi]
pub struct WtRecvStream {
    inner: Arc<wt_core::RecvStream>,
}

#[napi]
impl WtRecvStream {
    /// Reads the next chunk, or null at end of stream.
    ///
    /// `max` bounds the read so a BYOB reader asks for only what it can hold.
    #[napi]
    pub async fn read(&self, max: Option<u32>) -> Result<Option<Uint8Array>> {
        self.inner
            .read_chunk(max.map(|m| m as usize))
            .await
            .map(|opt| opt.map(|b| Uint8Array::new(b.to_vec())))
            .map_err(to_napi_err)
    }

    #[napi]
    pub async fn stop(&self, code: u32) -> Result<()> {
        self.inner.stop(code).await.map_err(to_napi_err)
    }

    #[napi(getter)]
    pub fn bytes_read(&self) -> BigInt {
        BigInt::from(self.inner.bytes_read())
    }
}

/// A bidirectional stream's two halves.
#[napi]
pub struct WtBidiStream {
    send: Arc<wt_core::SendStream>,
    recv: Arc<wt_core::RecvStream>,
}

#[napi]
impl WtBidiStream {
    #[napi(getter)]
    pub fn writable(&self) -> WtSendStream {
        WtSendStream {
            inner: self.send.clone(),
        }
    }

    #[napi(getter)]
    pub fn readable(&self) -> WtRecvStream {
        WtRecvStream {
            inner: self.recv.clone(),
        }
    }
}

/// Opens a WebTransport session. Resolves once the session is established.
#[napi]
pub async fn connect(url: String, options: Option<JsClientOptions>) -> Result<WebTransportSession> {
    let options = options.unwrap_or_default();

    let mut hashes = Vec::new();
    for h in options.server_certificate_hashes.unwrap_or_default() {
        // The spec says to ignore hashes whose algorithm we do not know, rather
        // than reject the whole connection.
        if let Some(algorithm) = HashAlgorithm::parse(&h.algorithm) {
            hashes.push(CertHash {
                algorithm,
                value: h.value.to_vec(),
            });
        }
    }

    let allow_pooling = options.allow_pooling.unwrap_or(false);
    let core_options = client::ClientOptions {
        allow_pooling,
        server_certificate_hashes: hashes,
        headers: options
            .headers
            .unwrap_or_default()
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect(),
        protocols: options.protocols.unwrap_or_default(),
        require_unreliable: options.require_unreliable.unwrap_or(false),
        congestion_control: match options.congestion_control.as_deref() {
            Some("throughput") => client::CongestionControl::Throughput,
            Some("low-latency") => client::CongestionControl::LowLatency,
            _ => client::CongestionControl::Default,
        },
    };

    let connected = client::connect(&url, core_options)
        .await
        .map_err(to_napi_err)?;
    let session = connected.session.clone();
    let protocol = connected.protocol.clone().unwrap_or_default();
    Ok(WebTransportSession {
        inner: Arc::new(SessionHolder {
            session,
            protocol,
            _client: Some(connected),
        }),
    })
}

/// A listening WebTransport server.
#[napi]
pub struct WebTransportServer {
    server: Arc<server::Server>,
    incoming: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<server::IncomingSession>>>,
    /// Connection-level failures, which happen before any session exists.
    errors: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<String>>>,
}

/// An incoming session, before the application accepts it.
#[napi]
pub struct IncomingSession {
    path: String,
    authority: String,
    headers: Vec<JsHeader>,
    protocols: Vec<String>,
    inner: Option<server::IncomingSession>,
}

#[napi]
impl IncomingSession {
    #[napi(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }

    #[napi(getter)]
    pub fn authority(&self) -> String {
        self.authority.clone()
    }

    #[napi(getter)]
    pub fn headers(&self) -> Vec<JsHeader> {
        self.headers
            .iter()
            .map(|h| JsHeader {
                name: h.name.clone(),
                value: h.value.clone(),
            })
            .collect()
    }

    /// Subprotocols the client offered, in preference order.
    #[napi(getter)]
    pub fn protocols(&self) -> Vec<String> {
        self.protocols.clone()
    }

    /// Accepts the session. Can only be called once.
    #[napi]
    pub fn accept(&mut self) -> Result<WebTransportSession> {
        let incoming = self
            .inner
            .take()
            .ok_or_else(|| Error::new(Status::InvalidArg, "session already accepted"))?;
        let session = incoming.accept();
        Ok(WebTransportSession {
            inner: Arc::new(SessionHolder {
                session,
                protocol: String::new(),
                _client: None,
            }),
        })
    }
}

#[napi(object)]
pub struct JsServerOptions {
    pub port: u16,
    pub host: Option<String>,
    /// PEM certificate chain.
    pub cert: String,
    /// PEM private key.
    pub key: String,
    pub max_sessions: Option<u32>,
    /// Concurrent QUIC streams per direction, per connection. Reserved
    /// bookkeeping scales with this, so it trades headroom against memory.
    pub max_concurrent_streams: Option<u32>,
}

#[napi]
impl WebTransportServer {
    /// Binds a server. Throws if the address is unavailable or the TLS material
    /// cannot be parsed.
    ///
    /// Async because binding spawns the accept task, which needs the addon's
    /// Tokio runtime to be entered; a sync napi call has no runtime context.
    #[napi(factory)]
    pub async fn bind(options: JsServerOptions) -> Result<Self> {
        let host = options.host.unwrap_or_else(|| "::".to_owned());
        let addr: std::net::SocketAddr = format!("{host}:{}", options.port)
            .parse()
            .map_err(|e| Error::new(Status::InvalidArg, format!("invalid address: {e}")))?;

        let chain = parse_certificates(&options.cert)?;
        let key = parse_private_key(&options.key)?;

        let server = server::Server::bind(server::ServerConfig {
            addr,
            certificate_chain: chain,
            private_key: key,
            max_sessions: options.max_sessions.unwrap_or(16) as u64,
            max_concurrent_streams: options.max_concurrent_streams,
        })
        .map_err(to_napi_err)?;

        let (errors_tx, errors_rx) = tokio::sync::mpsc::channel(32);
        let incoming = server.accept_sessions_with_errors(64, Some(errors_tx));
        Ok(Self {
            server: Arc::new(server),
            incoming: Arc::new(tokio::sync::Mutex::new(incoming)),
            errors: Arc::new(tokio::sync::Mutex::new(errors_rx)),
        })
    }

    /// The port actually bound, resolving 0 to the ephemeral port chosen.
    #[napi(getter)]
    pub fn port(&self) -> Result<u16> {
        Ok(self.server.local_addr().map_err(to_napi_err)?.port())
    }

    /// Resolves with the next connection-level failure, or null once the
    /// server stops. These happen before a session exists, so they cannot be
    /// reported on one.
    #[napi]
    pub async fn next_error(&self) -> Option<String> {
        let mut rx = self.errors.lock().await;
        rx.recv().await
    }

    /// Resolves with the next incoming session, or null once the server stops.
    #[napi]
    pub async fn accept(&self) -> Option<IncomingSession> {
        let mut rx = self.incoming.lock().await;
        rx.recv().await.map(|incoming| IncomingSession {
            path: incoming.path.clone(),
            authority: incoming.authority.clone(),
            headers: incoming
                .headers
                .iter()
                .map(|(n, v)| JsHeader {
                    name: n.clone(),
                    value: v.clone(),
                })
                .collect(),
            protocols: incoming.protocols.clone(),
            inner: Some(incoming),
        })
    }
}

fn parse_certificates(pem: &str) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let certs: std::result::Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut pem.as_bytes()).collect();
    let certs =
        certs.map_err(|e| Error::new(Status::InvalidArg, format!("invalid certificate: {e}")))?;
    if certs.is_empty() {
        return Err(Error::new(
            Status::InvalidArg,
            "no certificates found in the supplied PEM",
        ));
    }
    Ok(certs)
}

fn parse_private_key(pem: &str) -> Result<rustls_pki_types::PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .map_err(|e| Error::new(Status::InvalidArg, format!("invalid private key: {e}")))?
        .ok_or_else(|| {
            Error::new(
                Status::InvalidArg,
                "no private key found in the supplied PEM",
            )
        })
}

/// Generates a self-signed certificate for local development, returning the PEM
/// pair and the SHA-256 hash a client passes as `serverCertificateHashes`.
#[napi(object)]
pub struct SelfSignedCert {
    pub cert: String,
    pub key: String,
    pub hash: Uint8Array,
}

#[napi]
pub fn generate_self_signed(hostnames: Vec<String>) -> Result<SelfSignedCert> {
    let names = if hostnames.is_empty() {
        vec!["localhost".to_owned()]
    } else {
        hostnames
    };
    // The spec constrains any certificate used with serverCertificateHashes:
    // ECDSA P-256 (never RSA), and a validity period of at most two weeks.
    // rcgen defaults to a validity of several centuries, which browsers reject
    // outright: the handshake fails with "certificate unknown" long before
    // HTTP/3, and our own client never notices because it only compares the
    // hash.
    let mut params = rcgen::CertificateParams::new(names)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(13 * 24 * 60 * 60)).into();

    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;
    let der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let hash = wt_core::tls::certificate_hash(&der);
    Ok(SelfSignedCert {
        cert: cert.pem(),
        key: key.serialize_pem(),
        hash: Uint8Array::new(hash),
    })
}
