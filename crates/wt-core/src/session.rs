//! A live WebTransport session.
//!
//! One session is one extended CONNECT stream on an HTTP/3 connection. Because
//! several sessions can share a connection (`allowPooling`), a session never
//! owns the QUIC connection: it holds a handle to it plus the routing state that
//! tells its own streams and datagrams apart from its neighbours'.

use crate::error::{Error, Result};
use crate::stream::{BidiStream, RecvStream};
use bytes::Bytes;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use wt_proto::datagram;

/// Connection statistics, mirroring `WebTransportConnectionStats`.
///
/// Members the transport cannot source are omitted from the JS dictionary
/// rather than reported as zero, per the plan's stance on stats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub bytes_lost: u64,
    pub smoothed_rtt: std::time::Duration,
    pub min_rtt: std::time::Duration,
    pub congestion_window: u64,
}

// Members the spec defines that this transport genuinely cannot source, and
// which the JS layer therefore omits rather than reporting as zero:
//
//   rttVariation      - quinn tracks no RTT variance
//   estimatedSendRate - quinn exposes no send-rate estimate
//   bytesAcknowledged - quinn has no per-stream acknowledgement accounting

/// How a session ended, mirroring `WebTransportCloseInfo`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CloseInfo {
    pub code: u32,
    pub reason: String,
}

/// Session lifecycle, mirroring the spec's `[[State]]` slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Connecting,
    Connected,
    /// The peer sent WT_DRAIN_SESSION, or we did: a request to wind the
    /// session down. Both sides may keep using it and keep opening streams
    /// until one of them actually closes it.
    Draining,
    Closed(CloseInfo),
    Failed(String),
}

impl State {
    pub fn is_terminal(&self) -> bool {
        matches!(self, State::Closed(_) | State::Failed(_))
    }
}

/// Depth of the per-session incoming stream queues.
///
/// Unlike datagrams, streams are reliable: a full queue applies backpressure
/// rather than dropping, since discarding a stream would lose data the peer
/// believes was delivered.
pub const DEFAULT_STREAM_QUEUE: usize = 128;

/// Depth of the per-session inbound datagram queue.
///
/// Datagrams are unreliable by definition, so a full queue drops the oldest
/// rather than applying backpressure: stalling the connection's datagram reader
/// would penalise every other session sharing it. Sized to absorb the bursts a
/// thousand synchronised clients produce while staying a strict bound: a
/// saturated consumer stays at most this many datagrams behind before loss
/// starts, and every eviction is counted.
pub const DEFAULT_DATAGRAM_QUEUE: usize = 1024;

/// The connection-level operations a session needs.
///
/// A trait so session logic can be exercised without a real QUIC connection:
/// the engine supplies a quinn-backed implementation.
pub trait ConnectionHandle: Send + Sync + 'static {
    /// Sends one QUIC datagram, already framed with its quarter stream ID.
    fn send_datagram(&self, payload: Bytes) -> Result<()>;
    /// Largest datagram the path currently allows, or `None` if unsupported.
    fn max_datagram_size(&self) -> Option<usize>;
    /// Closes the whole QUIC connection.
    fn close(&self, code: u64, reason: &[u8]);
    /// The QUIC connection, for opening streams. `None` for test doubles that
    /// stub the handle without a real connection.
    fn quinn(&self) -> Option<quinn::Connection> {
        None
    }
}

/// A bounded queue of inbound datagrams with push-time eviction.
///
/// The demux pushes; the application (or the JS pump) pops. Unlike an mpsc
/// channel, pushing can never fail: when full, the oldest datagram is evicted
/// and counted. That property matters because the push path runs on the
/// connection's demux task, which must never block or drop silently, so an mpsc
/// whose receiver lock is held drops the *new* datagram uncounted, which makes
/// loss invisible to `datagrams_dropped` exactly when it is highest.
struct DatagramQueue {
    inner: std::sync::Mutex<std::collections::VecDeque<Bytes>>,
    /// Signals a non-empty queue to waiting poppers.
    notify: tokio::sync::Notify,
    capacity: usize,
    closed: std::sync::atomic::AtomicBool,
    dropped: std::sync::atomic::AtomicU64,
}

impl DatagramQueue {
    fn new(capacity: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(
                capacity.min(64),
            )),
            notify: tokio::sync::Notify::new(),
            capacity: capacity.max(1),
            closed: std::sync::atomic::AtomicBool::new(false),
            dropped: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Pushes a datagram, evicting the oldest if the queue is full.
    ///
    /// Never blocks, never fails: for unreliable delivery the freshest
    /// datagram is the useful one, so evicting beats dropping the newcomer.
    /// After close a push is discarded outright: nobody will ever pop it.
    fn push(&self, payload: Bytes) {
        if self.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        if inner.len() == self.capacity {
            inner.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        inner.push_back(payload);
        drop(inner);
        self.notify.notify_one();
    }

    /// Pops the oldest datagram without waiting, if one is queued.
    fn try_pop(&self) -> Option<Bytes> {
        self.inner.lock().unwrap().pop_front()
    }

    /// Waits for a datagram, or `None` once the queue is closed.
    async fn pop(&self) -> Option<Bytes> {
        loop {
            // Register the waiter before checking: a push between the check and
            // the await leaves a permit that this notified future consumes.
            let notified = self.notify.notified();
            {
                let mut inner = self.inner.lock().unwrap();
                if let Some(payload) = inner.pop_front() {
                    return Some(payload);
                }
                if self.closed.load(Ordering::SeqCst) {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Ends the queue: pending pops resolve to `None`; pushes are refused.
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

/// Shared session state. Cloneable; all clones refer to one session.
#[derive(Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

struct Inner {
    id: u64,
    conn: Arc<dyn ConnectionHandle>,
    state: watch::Sender<State>,
    /// Inbound datagrams, already stripped of their quarter stream ID.
    datagrams: DatagramQueue,
    /// Streams the peer opened, awaiting the application.
    incoming_bi_rx: tokio::sync::Mutex<mpsc::Receiver<BidiStream>>,
    incoming_bi_tx: mpsc::Sender<BidiStream>,
    incoming_uni_rx: tokio::sync::Mutex<mpsc::Receiver<Arc<RecvStream>>>,
    incoming_uni_tx: mpsc::Sender<Arc<RecvStream>>,
    /// Set once a close has been initiated, so the close path runs once.
    closing: AtomicBool,
    supports_datagrams: bool,
    /// Governs which of this session's send streams writes next.
    scheduler: Arc<crate::SendScheduler>,
    /// The runtime this session's background work runs on. Captured at
    /// construction because `close` may be called from a thread without one.
    runtime: Option<tokio::runtime::Handle>,
    /// The send half of the CONNECT stream, for close and drain capsules.
    ///
    /// draft §5: terminating a session means sending WT_CLOSE_SESSION here.
    /// Without it a close is purely local and the peer never learns of it.
    connect_send: tokio::sync::Mutex<Option<quinn::SendStream>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.inner.id)
            .field("state", &*self.inner.state.borrow())
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn new(
        id: u64,
        conn: Arc<dyn ConnectionHandle>,
        supports_datagrams: bool,
        queue_depth: usize,
    ) -> Self {
        let (incoming_bi_tx, incoming_bi_rx) = mpsc::channel(DEFAULT_STREAM_QUEUE);
        let (incoming_uni_tx, incoming_uni_rx) = mpsc::channel(DEFAULT_STREAM_QUEUE);
        let (state, _) = watch::channel(State::Connecting);
        Self {
            inner: Arc::new(Inner {
                id,
                conn,
                state,
                datagrams: DatagramQueue::new(queue_depth),
                incoming_bi_rx: tokio::sync::Mutex::new(incoming_bi_rx),
                incoming_bi_tx,
                incoming_uni_rx: tokio::sync::Mutex::new(incoming_uni_rx),
                incoming_uni_tx,
                closing: AtomicBool::new(false),
                supports_datagrams,
                scheduler: Arc::new(crate::SendScheduler::new()),
                runtime: tokio::runtime::Handle::try_current().ok(),
                connect_send: tokio::sync::Mutex::new(None),
            }),
        }
    }

    /// The CONNECT stream ID identifying this session.
    pub fn id(&self) -> u64 {
        self.inner.id
    }

    pub fn state(&self) -> State {
        self.inner.state.borrow().clone()
    }

    /// Watches state transitions, for waking `ready` / `closed` / `draining`.
    pub fn watch(&self) -> watch::Receiver<State> {
        self.inner.state.subscribe()
    }

    /// Datagrams are only usable when the peer enabled them (draft §4.4); this
    /// also decides the reported `reliability` mode.
    pub fn supports_datagrams(&self) -> bool {
        self.inner.supports_datagrams
    }

    /// Number of inbound datagrams dropped because the queue was full.
    pub fn datagrams_dropped(&self) -> u64 {
        self.inner.datagrams.dropped.load(Ordering::Relaxed)
    }

    pub(crate) fn set_state(&self, state: State) {
        // Terminal states are final: a later transition would resolve promises
        // that the spec says are already settled.
        if self.inner.state.borrow().is_terminal() {
            return;
        }
        // `send_replace`, not `send`: the value must be stored even when nobody
        // is currently watching, since state is read directly as well.
        self.inner.state.send_replace(state);
    }

    /// Largest payload `send_datagram` will accept right now.
    ///
    /// This is the path limit minus the quarter-stream-ID header, so it is what
    /// the application may actually write. It changes with the path MTU.
    pub fn max_datagram_size(&self) -> Option<usize> {
        let path_max = self.inner.conn.max_datagram_size()?;
        let header = datagram::header_len(self.inner.id).ok()?;
        path_max.checked_sub(header)
    }

    /// Sends one datagram.
    ///
    /// Oversized payloads are refused rather than truncated: silently dropping
    /// the tail would corrupt the message.
    pub fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        if self.state().is_terminal() {
            return Err(Error::SessionClosed);
        }
        if !self.inner.supports_datagrams {
            return Err(Error::DatagramUnsupported);
        }
        let max = self.max_datagram_size().ok_or(Error::DatagramUnsupported)?;
        if payload.len() > max {
            return Err(Error::DatagramTooLarge {
                size: payload.len(),
                max,
            });
        }
        let header_len =
            datagram::header_len(self.inner.id).map_err(|e| Error::Protocol(e.to_string()))?;
        let mut framed = Vec::with_capacity(header_len + payload.len());
        datagram::encode(&mut framed, self.inner.id, payload)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        self.inner.conn.send_datagram(Bytes::from(framed))
    }

    /// Queues an inbound datagram, evicting the oldest if the queue is full.
    ///
    /// Called by the connection's demux task with the payload already stripped.
    /// Never drops the newcomer silently: every eviction is counted, so
    /// `datagrams_dropped` always equals the actual loss.
    pub(crate) fn deliver_datagram(&self, payload: Bytes) {
        self.inner.datagrams.push(payload);
    }

    /// Waits for the next inbound datagram, or `None` once the session ends.
    pub async fn recv_datagram(&self) -> Option<Bytes> {
        self.inner.datagrams.pop().await
    }

    /// Waits for inbound datagrams, returning up to `max` in one batch.
    ///
    /// The first datagram is awaited; the rest are taken opportunistically so
    /// the caller does not pay a wakeup per datagram. The JS layer uses this to
    /// amortise the async boundary: a promise per datagram caps throughput at
    /// a few thousand a second, which pure-Rust delivery exceeds by hundreds.
    pub async fn recv_datagrams(&self, max: usize) -> Option<Vec<Bytes>> {
        let first = self.inner.datagrams.pop().await?;
        let mut batch = Vec::with_capacity(max.min(256));
        batch.push(first);
        while batch.len() < max {
            match self.inner.datagrams.try_pop() {
                Some(next) => batch.push(next),
                None => break,
            }
        }
        Some(batch)
    }

    /// Packs a batch into one buffer for the JS boundary.
    ///
    /// The format is a private Rust-to-JS framing, deliberately **not** the
    /// wire format: each entry is its LEB128 length followed by that many
    /// payload bytes. LEB128 is chosen because it is what the JS side decodes,
    /// and it must match there exactly: a length encoding mismatch corrupts
    /// every payload above 63 bytes while looking perfect for short test
    /// vectors, which is exactly how this bug first shipped.
    pub fn pack_datagram_batch(batch: &[Bytes]) -> Vec<u8> {
        let mut packed = Vec::with_capacity(batch.iter().map(|d| d.len() + 4).sum());
        for datagram in batch {
            let mut len = datagram.len() as u64;
            while len >= 0x80 {
                packed.push((len as u8) | 0x80);
                len >>= 7;
            }
            packed.push(len as u8);
            packed.extend_from_slice(datagram);
        }
        packed
    }

    /// Derives keying material bound to this session (draft §4.7).
    ///
    /// Not a raw RFC 5705 export: the TLS label is fixed and the caller's label
    /// and context are nested inside a struct carrying the session id, so two
    /// sessions on one connection derive different material from the same
    /// arguments.
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        if self.state().is_terminal() {
            return Err(Error::SessionClosed);
        }
        let conn = self
            .inner
            .conn
            .quinn()
            .ok_or_else(|| Error::Protocol("this session has no TLS connection".into()))?;
        let exporter_context = wt_proto::exporter::context(self.inner.id, label, context)
            .map_err(|e| Error::Protocol(e.to_string()))?;

        let mut out = vec![0u8; length];
        conn.export_keying_material(&mut out, wt_proto::exporter::TLS_LABEL, &exporter_context)
            .map_err(|_| Error::Tls("the connection cannot export keying material".into()))?;
        Ok(out)
    }

    /// Connection statistics, as far as the transport can report them.
    pub fn stats(&self) -> Option<ConnectionStats> {
        let conn = self.inner.conn.quinn()?;
        let stats = conn.stats();
        Some(ConnectionStats {
            bytes_sent: stats.udp_tx.bytes,
            bytes_received: stats.udp_rx.bytes,
            packets_sent: stats.udp_tx.datagrams,
            packets_received: stats.udp_rx.datagrams,
            packets_lost: stats.path.lost_packets,
            bytes_lost: stats.path.lost_bytes,
            smoothed_rtt: stats.path.rtt,
            min_rtt: conn.rtt(),
            congestion_window: stats.path.cwnd,
        })
    }

    /// Bytes queued for sending but not yet handed to the transport.
    ///
    /// This is the scheduler's own backlog: what the application has written
    /// and the connection has not yet taken. Applications use it to shed load
    /// for a peer that has stopped reading, so it must be cheap to sample:
    /// callers poll it per frame at high rates.
    pub fn queued_bytes(&self) -> u64 {
        self.inner.scheduler.queued_bytes()
    }

    /// Hands the session the send half of its CONNECT stream.
    ///
    /// Held so `close` and `drain` can put their capsules on it, which is what
    /// tells the peer the session ended rather than just changing local state.
    pub async fn attach_connect_stream(&self, stream: quinn::SendStream) {
        *self.inner.connect_send.lock().await = Some(stream);
    }

    /// Spawns capsule delivery onto the runtime that owns this session.
    ///
    /// `close` and `drain` are synchronous and reachable from a thread with no
    /// runtime of its own (the JS thread), so the handle captured at session
    /// creation is what the work runs on.
    fn spawn_capsule(&self, capsule: wt_proto::Capsule, take_stream: bool) {
        let Some(runtime) = self.inner.runtime.clone() else {
            return;
        };
        let session = self.clone();
        runtime.spawn(async move {
            session.send_capsule(&capsule).await;
            if take_stream {
                // Dropping the CONNECT stream ends the session for the peer
                // even if the capsule could not be written.
                session.inner.connect_send.lock().await.take();
            }
        });
    }

    /// Sends a capsule on the CONNECT stream, if it is still available.
    async fn send_capsule(&self, capsule: &wt_proto::Capsule) {
        use tokio::io::AsyncWriteExt;
        let Ok(encoded) = crate::capsules::encode(capsule) else {
            return;
        };
        let mut guard = self.inner.connect_send.lock().await;
        let Some(stream) = guard.as_mut() else { return };
        // A failure here means the stream is already gone, which is the same
        // outcome the capsule was announcing.
        let _ = stream.write_all(&encoded).await;
        let _ = stream.flush().await;
    }

    /// The scheduler arbitrating this session's send streams.
    pub fn scheduler(&self) -> Arc<crate::SendScheduler> {
        self.inner.scheduler.clone()
    }

    /// Opens a unidirectional stream to the peer.
    ///
    /// A draining session still opens streams: the draft lets either endpoint
    /// keep using one after the signal.
    pub async fn open_uni(
        &self,
        group: Option<u64>,
        send_order: Option<i64>,
    ) -> Result<Arc<crate::stream::SendStream>> {
        self.open_uni_with(group, send_order, true).await
    }

    /// Opens a unidirectional stream, optionally waiting for capacity.
    ///
    /// `wait_until_available` mirrors `WebTransportSendStreamOptions`: with it
    /// false the call fails rather than waiting when the peer's stream limit is
    /// reached, so an application can decide what to do instead of stalling.
    pub async fn open_uni_with(
        &self,
        group: Option<u64>,
        send_order: Option<i64>,
        wait_until_available: bool,
    ) -> Result<Arc<crate::stream::SendStream>> {
        let conn = self.stream_capable_connection()?;
        let opening = crate::stream::open_uni_raw(&conn, self.inner.id);
        let mut stream = self.await_opening(opening, wait_until_available).await?;
        let id = self.inner.scheduler.register(group, send_order);
        stream.attach_scheduler(self.inner.scheduler.clone(), id);
        Ok(Arc::new(stream))
    }

    /// Opens a bidirectional stream to the peer.
    pub async fn open_bi(&self, group: Option<u64>, send_order: Option<i64>) -> Result<BidiStream> {
        self.open_bi_with(group, send_order, true).await
    }

    /// Opens a bidirectional stream, optionally waiting for capacity.
    pub async fn open_bi_with(
        &self,
        group: Option<u64>,
        send_order: Option<i64>,
        wait_until_available: bool,
    ) -> Result<BidiStream> {
        let conn = self.stream_capable_connection()?;
        let opening = crate::stream::open_bi_raw(&conn, self.inner.id);
        let (mut send, recv) = self.await_opening(opening, wait_until_available).await?;
        let id = self.inner.scheduler.register(group, send_order);
        send.attach_scheduler(self.inner.scheduler.clone(), id);
        Ok(BidiStream {
            send: Arc::new(send),
            recv: Arc::new(recv),
        })
    }

    /// Awaits a stream opening, bounding the wait when the caller asked not to
    /// block on the peer's stream limit.
    ///
    /// Without a bound, exhausting the limit stalls until the whole connection
    /// times out, which surfaces as a dead session rather than a refused
    /// stream, a far worse outcome than a prompt error.
    async fn await_opening<T>(
        &self,
        opening: impl std::future::Future<Output = Result<T>>,
        wait_until_available: bool,
    ) -> Result<T> {
        if wait_until_available {
            return opening.await;
        }
        // A short grace period: opening normally completes at once, and only a
        // exhausted stream limit makes it wait.
        match tokio::time::timeout(std::time::Duration::from_millis(50), opening).await {
            Ok(result) => result,
            Err(_) => Err(Error::StreamLimitReached),
        }
    }

    /// The connection to open streams on, if the session still permits it.
    fn stream_capable_connection(&self) -> Result<quinn::Connection> {
        match self.state() {
            State::Closed(_) | State::Failed(_) => return Err(Error::SessionClosed),
            // A draining session still opens streams. draft-ietf-webtrans-http3
            // §5: after sending or receiving WT_DRAIN_SESSION an endpoint MAY
            // continue using the session and MAY open new streams. The signal
            // asks the peer to wind down, it does not close anything.
            _ => {}
        }
        self.inner
            .conn
            .quinn()
            .ok_or_else(|| Error::Protocol("this session cannot open streams".into()))
    }

    /// Waits for the peer to open a bidirectional stream.
    ///
    /// Races the session state so a close resolves this even when the queue
    /// stays open: `close_queues` can only close a receiver it can lock, and
    /// this future is holding that lock precisely while it waits. Without the
    /// race an accept outstanding at close time never finishes, and it holds a
    /// `Session` clone, so the whole session leaks.
    pub async fn accept_bi(&self) -> Option<BidiStream> {
        let mut rx = self.inner.incoming_bi_rx.lock().await;
        tokio::select! {
            stream = rx.recv() => stream,
            _ = self.ended() => None,
        }
    }

    /// Waits for the peer to open a unidirectional stream.
    ///
    /// Races the session state for the reason given on `accept_bi`.
    pub async fn accept_uni(&self) -> Option<Arc<RecvStream>> {
        let mut rx = self.inner.incoming_uni_rx.lock().await;
        tokio::select! {
            stream = rx.recv() => stream,
            _ = self.ended() => None,
        }
    }

    /// Resolves once the session reaches a terminal state.
    async fn ended(&self) {
        let mut watch = self.watch();
        loop {
            if matches!(*watch.borrow(), State::Closed(_) | State::Failed(_)) {
                return;
            }
            if watch.changed().await.is_err() {
                return;
            }
        }
    }

    /// Queues a bidirectional stream the peer opened.
    ///
    /// Awaits rather than dropping when the queue is full: streams are
    /// reliable, so the backpressure has to reach the peer.
    pub(crate) async fn deliver_bi(&self, stream: BidiStream) {
        let _ = self.inner.incoming_bi_tx.send(stream).await;
    }

    /// Queues a unidirectional stream the peer opened.
    pub(crate) async fn deliver_uni(&self, stream: Arc<RecvStream>) {
        let _ = self.inner.incoming_uni_tx.send(stream).await;
    }

    /// Marks the session as draining, asking the peer to wind it down.
    ///
    /// Both sides may keep using it and keep opening streams; this is a
    /// request to stop starting new work, not a close.
    pub fn drain(&self) {
        if self.state().is_terminal() {
            return;
        }
        self.set_state(State::Draining);
        // Tell the peer to stop opening new streams (draft §5).
        self.spawn_capsule(wt_proto::Capsule::DrainSession, false);
    }

    /// Closes the session, recording why.
    ///
    /// Idempotent: only the first call decides the close info, so a local close
    /// racing a peer close does not overwrite the outcome.
    pub fn close(&self, info: CloseInfo) {
        if self.inner.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        // Announce the close to the peer before settling locally. draft §5
        // ties session termination to a WT_CLOSE_SESSION capsule on the CONNECT
        // stream; without it the peer sees a live session until the whole
        // connection eventually times out.
        self.spawn_capsule(
            wt_proto::Capsule::CloseSession {
                code: info.code,
                reason: info.reason.clone(),
            },
            true,
        );

        self.set_state(State::Closed(info));
        // Close the receive halves so anything awaiting them resolves to None
        // instead of hanging on a session that will never deliver again.
        self.close_queues();
    }

    /// Ends every inbound queue, so pending receives resolve rather than hang.
    ///
    /// The stream receivers are behind a lock an in-flight accept is holding,
    /// so `try_lock` fails exactly when there is a waiter to wake. That case is
    /// covered by `accept_bi` and `accept_uni` racing the session state; the
    /// close here is what stops a *later* accept from waiting on a dead
    /// session.
    fn close_queues(&self) {
        self.inner.datagrams.close();
        if let Ok(mut rx) = self.inner.incoming_bi_rx.try_lock() {
            rx.close();
        }
        if let Ok(mut rx) = self.inner.incoming_uni_rx.try_lock() {
            rx.close();
        }
    }

    /// Fails the session: the transport broke rather than closing cleanly.
    pub fn fail(&self, reason: impl Into<String>) {
        if self.inner.closing.swap(true, Ordering::SeqCst) {
            return;
        }
        self.set_state(State::Failed(reason.into()));
        self.close_queues();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A connection handle that records what was sent instead of using a socket.
    #[derive(Default)]
    struct FakeConn {
        sent: Mutex<Vec<Bytes>>,
        max_datagram: Option<usize>,
        closed: Mutex<Option<(u64, Vec<u8>)>>,
    }

    impl FakeConn {
        fn with_mtu(max: usize) -> Arc<Self> {
            Arc::new(Self {
                max_datagram: Some(max),
                ..Default::default()
            })
        }
    }

    impl ConnectionHandle for FakeConn {
        fn send_datagram(&self, payload: Bytes) -> Result<()> {
            self.sent.lock().unwrap().push(payload);
            Ok(())
        }
        fn max_datagram_size(&self) -> Option<usize> {
            self.max_datagram
        }
        fn close(&self, code: u64, reason: &[u8]) {
            *self.closed.lock().unwrap() = Some((code, reason.to_vec()));
        }
    }

    /// An accept outstanding when the session closes must resolve, not hang.
    ///
    /// It holds the receiver lock, so `close_queues` cannot close the queue
    /// underneath it. Before the state race in `accept_bi`, such an accept
    /// waited for good and kept a `Session` clone alive with it, which held the
    /// whole session: closed sessions were never freed and a process churning
    /// them grew without bound.
    #[tokio::test]
    async fn accept_resolves_when_the_session_closes_under_it() {
        let session = session(Arc::new(FakeConn::default()));
        let accepting = {
            let session = session.clone();
            tokio::spawn(async move { session.accept_bi().await })
        };
        // Let the accept take the lock before closing.
        tokio::task::yield_now().await;
        session.close(CloseInfo::default());

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), accepting)
            .await
            .expect("accept should resolve once the session closes")
            .expect("accept task should not panic");
        assert!(result.is_none(), "a closed session yields no stream");
    }

    fn session(conn: Arc<FakeConn>) -> Session {
        Session::new(0, conn, true, DEFAULT_DATAGRAM_QUEUE)
    }

    #[test]
    fn a_new_session_is_connecting() {
        assert_eq!(session(FakeConn::with_mtu(1200)).state(), State::Connecting);
    }

    /// The size offered to the application excludes the framing we add, so a
    /// payload of exactly that size still fits in one QUIC datagram.
    #[test]
    fn max_datagram_size_excludes_the_session_header() {
        let s = session(FakeConn::with_mtu(1200));
        // Session 0 quarters to 0, a one-byte varint.
        assert_eq!(s.max_datagram_size(), Some(1199));
    }

    #[test]
    fn header_overhead_grows_with_the_session_id() {
        let conn = FakeConn::with_mtu(1200);
        let s = Session::new(4 * 0x4000, conn, true, 8);
        // Quarter id 0x4000 needs a four-byte varint.
        assert_eq!(s.max_datagram_size(), Some(1196));
    }

    #[test]
    fn sent_datagrams_are_framed_with_the_quarter_stream_id() {
        let conn = FakeConn::with_mtu(1200);
        let s = Session::new(4, conn.clone(), true, 8);
        s.set_state(State::Connected);
        s.send_datagram(b"hello").unwrap();
        let sent = conn.sent.lock().unwrap();
        assert_eq!(&sent[0][..], &[0x01, b'h', b'e', b'l', b'l', b'o'][..]);
    }

    #[test]
    fn oversized_datagrams_are_refused_not_truncated() {
        let s = session(FakeConn::with_mtu(64));
        s.set_state(State::Connected);
        let err = s.send_datagram(&[0u8; 64]).unwrap_err();
        assert!(
            matches!(err, Error::DatagramTooLarge { size: 64, max: 63 }),
            "got {err:?}"
        );
        // One byte smaller fits exactly.
        assert!(s.send_datagram(&[0u8; 63]).is_ok());
    }

    #[test]
    fn sending_on_a_closed_session_fails() {
        let s = session(FakeConn::with_mtu(1200));
        s.close(CloseInfo::default());
        assert!(matches!(s.send_datagram(b"x"), Err(Error::SessionClosed)));
    }

    #[test]
    fn datagrams_are_refused_when_the_peer_disabled_them() {
        let s = Session::new(0, FakeConn::with_mtu(1200), false, 8);
        s.set_state(State::Connected);
        assert!(matches!(
            s.send_datagram(b"x"),
            Err(Error::DatagramUnsupported)
        ));
    }

    #[tokio::test]
    async fn inbound_datagrams_arrive_in_order() {
        let s = session(FakeConn::with_mtu(1200));
        s.deliver_datagram(Bytes::from_static(b"one"));
        s.deliver_datagram(Bytes::from_static(b"two"));
        assert_eq!(s.recv_datagram().await.unwrap(), Bytes::from_static(b"one"));
        assert_eq!(s.recv_datagram().await.unwrap(), Bytes::from_static(b"two"));
    }

    /// Unreliable transport: a slow reader must not stall the shared connection,
    /// so the oldest queued datagram is dropped to make room for the newest.
    #[tokio::test]
    async fn a_full_queue_drops_the_oldest_datagram() {
        let s = Session::new(0, FakeConn::with_mtu(1200), true, 2);
        s.deliver_datagram(Bytes::from_static(b"1"));
        s.deliver_datagram(Bytes::from_static(b"2"));
        s.deliver_datagram(Bytes::from_static(b"3"));
        assert_eq!(s.datagrams_dropped(), 1);
        assert_eq!(s.recv_datagram().await.unwrap(), Bytes::from_static(b"2"));
        assert_eq!(s.recv_datagram().await.unwrap(), Bytes::from_static(b"3"));
    }

    /// The LEB128 framing in `pack_datagram_batch` is what the JS pump decodes.
    /// These vectors pin that contract: the decoder walks length-prefixed
    /// entries, so every length boundary must match its LEB128 encoding.
    #[test]
    fn packed_batches_use_leb128_lengths() {
        // LEB128 is single-byte through 127; the QUIC wire varint goes to two
        // bytes at 64, which is exactly the divergence that corrupted payloads
        // when the two were confused. 127/128 are the first real LEB128
        // boundary, and 16383/16384 the next.
        let pack = |n: usize| Session::pack_datagram_batch(&[Bytes::from(vec![0xab; n])]);
        assert_eq!(pack(0), vec![0x00]);
        assert_eq!(pack(1), [&[0x01][..], &[0xab][..]].concat());
        assert_eq!(pack(63), [&[0x3f][..], &vec![0xab; 63][..]].concat());
        assert_eq!(pack(64), [&[0x40][..], &vec![0xab; 64][..]].concat());
        assert_eq!(pack(127), [&[0x7f][..], &vec![0xab; 127][..]].concat());
        assert_eq!(
            pack(128),
            [&[0x80, 0x01][..], &vec![0xab; 128][..]].concat()
        );
        assert_eq!(
            pack(16383),
            [&[0xff, 0x7f][..], &vec![0xab; 16383][..]].concat()
        );
        assert_eq!(
            pack(16384),
            [&[0x80, 0x80, 0x01][..], &vec![0xab; 16384][..]].concat()
        );
    }

    /// A batch unpacks back to its datagrams when read with the JS side's
    /// decoder rules, including payloads large enough to trip any length
    /// encoding mismatch.
    #[test]
    fn packed_batches_round_trip_with_a_leb128_decoder() {
        let batch: Vec<Bytes> = vec![
            Bytes::from(vec![0x01; 7]),
            Bytes::from(vec![0x02; 63]),
            Bytes::from(vec![0x03; 64]),
            Bytes::from(vec![0x04; 300]),
            Bytes::from(vec![0x05; 1400]),
        ];
        let packed = Session::pack_datagram_batch(&batch);
        let mut offset = 0usize;
        for expected in &batch {
            let mut length = 0u64;
            let mut shift = 0u32;
            loop {
                let byte = packed[offset];
                offset += 1;
                length += u64::from(byte & 0x7f) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            assert_eq!(length, expected.len() as u64);
            assert_eq!(&packed[offset..offset + expected.len()], &expected[..]);
            offset += expected.len();
        }
        assert_eq!(offset, packed.len());
    }

    #[tokio::test]
    async fn closing_ends_the_inbound_datagram_stream() {
        let s = session(FakeConn::with_mtu(1200));
        s.deliver_datagram(Bytes::from_static(b"queued"));
        s.close(CloseInfo {
            code: 3,
            reason: "done".into(),
        });
        // Already-queued datagrams still drain, then the stream ends.
        assert_eq!(
            s.recv_datagram().await.unwrap(),
            Bytes::from_static(b"queued")
        );
        assert_eq!(s.recv_datagram().await, None);
    }

    /// The first close wins, so a local close racing a peer close does not
    /// rewrite the reason the application observes.
    #[test]
    fn close_is_idempotent() {
        let s = session(FakeConn::with_mtu(1200));
        s.close(CloseInfo {
            code: 1,
            reason: "first".into(),
        });
        s.close(CloseInfo {
            code: 2,
            reason: "second".into(),
        });
        assert_eq!(
            s.state(),
            State::Closed(CloseInfo {
                code: 1,
                reason: "first".into()
            })
        );
    }

    #[test]
    fn failure_after_close_does_not_overwrite_the_outcome() {
        let s = session(FakeConn::with_mtu(1200));
        s.close(CloseInfo {
            code: 7,
            reason: "clean".into(),
        });
        s.fail("connection lost");
        assert!(matches!(s.state(), State::Closed(info) if info.code == 7));
    }

    #[test]
    fn draining_is_not_terminal_and_still_permits_sending() {
        let s = session(FakeConn::with_mtu(1200));
        s.set_state(State::Connected);
        s.drain();
        assert_eq!(s.state(), State::Draining);
        assert!(!s.state().is_terminal());
        assert!(s.send_datagram(b"still allowed").is_ok());
    }

    #[test]
    fn draining_a_closed_session_does_nothing() {
        let s = session(FakeConn::with_mtu(1200));
        s.close(CloseInfo::default());
        s.drain();
        assert!(matches!(s.state(), State::Closed(_)));
    }

    #[tokio::test]
    async fn state_changes_are_observable() {
        let s = session(FakeConn::with_mtu(1200));
        let mut watch = s.watch();
        s.set_state(State::Connected);
        watch.changed().await.unwrap();
        assert_eq!(*watch.borrow(), State::Connected);
    }
}
