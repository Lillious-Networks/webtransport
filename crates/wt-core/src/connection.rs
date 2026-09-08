//! QUIC connection ownership and per-connection session routing.
//!
//! One QUIC connection carries one HTTP/3 connection, which carries one or more
//! WebTransport sessions. This module owns that connection, demultiplexes
//! inbound datagrams to the right session, and is the unit `allowPooling` shares.

use crate::error::{Error, Result};
use crate::session::{ConnectionHandle, Session};
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use wt_proto::datagram;
use wt_proto::frame::{frame_type, stream_type};

/// A quinn connection exposed through the session-facing handle.
#[derive(Debug)]
pub struct QuinnHandle {
    conn: quinn::Connection,
}

impl QuinnHandle {
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }
}

impl ConnectionHandle for QuinnHandle {
    fn send_datagram(&self, payload: Bytes) -> Result<()> {
        self.conn.send_datagram(payload).map_err(|e| match e {
            quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => {
                Error::DatagramUnsupported
            }
            quinn::SendDatagramError::TooLarge => Error::DatagramTooLarge {
                size: 0,
                max: self.conn.max_datagram_size().unwrap_or(0),
            },
            quinn::SendDatagramError::ConnectionLost(e) => Error::Io(e.to_string()),
        })
    }

    fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    fn close(&self, code: u64, reason: &[u8]) {
        // A code above the varint range would panic in quinn; clamp instead,
        // since a malformed close is worse than an imprecise one.
        let code = quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX);
        self.conn.close(code, reason);
    }

    fn quinn(&self) -> Option<quinn::Connection> {
        Some(self.conn.clone())
    }
}

/// The sessions sharing one QUIC connection, keyed by CONNECT stream ID.
///
/// Registration is separate from the connection handle so the demux task can
/// route datagrams without holding the connection lock.
#[derive(Debug, Default)]
pub struct SessionRegistry {
    sessions: RwLock<HashMap<u64, Session>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, session: Session) {
        self.sessions.write().unwrap().insert(session.id(), session);
    }

    pub fn get(&self, id: u64) -> Option<Session> {
        self.sessions.read().unwrap().get(&id).cloned()
    }

    pub fn remove(&self, id: u64) -> Option<Session> {
        self.sessions.write().unwrap().remove(&id)
    }

    pub fn len(&self) -> usize {
        self.sessions.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every live session, for connection-wide events such as loss.
    pub fn all(&self) -> Vec<Session> {
        self.sessions.read().unwrap().values().cloned().collect()
    }

    /// Routes one received QUIC datagram to its session.
    ///
    /// A datagram for an unknown session is dropped: per draft §4.4 it may
    /// simply have arrived after that session ended, which is not an error.
    /// Returns whether it was delivered, which the tests assert on.
    pub fn route_datagram(&self, raw: Bytes) -> bool {
        let Ok((session_id, payload)) = datagram::decode(raw) else {
            // A datagram we cannot parse is not attributable to any session, so
            // there is nobody to report it to.
            return false;
        };
        match self.get(session_id) {
            Some(session) => {
                session.deliver_datagram(payload);
                true
            }
            None => false,
        }
    }
}

/// An HTTP/3 request stream the demux could not attribute to a session.
///
/// `first_type` is the frame type already read from the stream, and `buffered`
/// the bytes read past it, so the consumer can carry on parsing.
pub struct HttpRequestStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
    pub first_type: u64,
    pub buffered: Bytes,
}

impl std::fmt::Debug for HttpRequestStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequestStream")
            .field("first_type", &self.first_type)
            .finish_non_exhaustive()
    }
}

/// A QUIC connection plus the sessions running on it.
#[derive(Clone)]
pub struct Connection {
    handle: Arc<QuinnHandle>,
    registry: Arc<SessionRegistry>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("sessions", &self.registry.len())
            .finish_non_exhaustive()
    }
}

impl Connection {
    pub fn new(conn: quinn::Connection) -> Self {
        Self {
            handle: Arc::new(QuinnHandle::new(conn)),
            registry: Arc::new(SessionRegistry::new()),
        }
    }

    pub fn handle(&self) -> Arc<QuinnHandle> {
        self.handle.clone()
    }

    pub fn registry(&self) -> Arc<SessionRegistry> {
        self.registry.clone()
    }

    pub fn quinn(&self) -> &quinn::Connection {
        self.handle.connection()
    }

    /// Accepts every incoming stream and routes it by type.
    ///
    /// This is the connection's only stream acceptor. A bidirectional stream is
    /// either a WebTransport stream (frame type 0x41 plus a session id) or an
    /// HTTP/3 request; a unidirectional stream is either a WebTransport stream
    /// (type 0x54) or HTTP/3 plumbing. Splitting that decision across two
    /// acceptors would race, so it happens in one place.
    ///
    /// `requests` receives HTTP/3 request streams, which only a server uses.
    pub async fn run_stream_demux(self, requests: Option<mpsc::Sender<HttpRequestStream>>) {
        self.run_stream_demux_with_settings(requests, None).await
    }

    /// As [`run_stream_demux`], additionally reporting the peer's SETTINGS.
    ///
    /// A server must not process WebTransport requests until it has seen them
    /// (draft §3.1), and the control stream is one of the streams this loop
    /// accepts, so it is the only place they can be read.
    pub async fn run_stream_demux_with_settings(
        self,
        requests: Option<mpsc::Sender<HttpRequestStream>>,
        settings: Option<tokio::sync::oneshot::Sender<wt_proto::settings::Settings>>,
    ) {
        let settings = Arc::new(std::sync::Mutex::new(settings));
        let bi = {
            let this = self.clone();
            let requests = requests.clone();
            async move {
                loop {
                    let (send, mut recv) = match this.quinn().accept_bi().await {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let registry = this.registry.clone();
                    let requests = requests.clone();
                    // Per-stream task: a peer that opens a stream then stalls
                    // before writing its header must not block other streams.
                    tokio::spawn(async move {
                        let (ty, rest) = match crate::h3::read_stream_type(&mut recv).await {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        tracing::trace!(frame_type = ty, "incoming bidi stream");
                        if ty == frame_type::WEBTRANSPORT_BIDI {
                            let (session_id, _) =
                                match crate::h3::read_varint(&mut recv, rest).await {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                            if let Some(session) = registry.get(session_id) {
                                session
                                    .deliver_bi(crate::stream::BidiStream {
                                        send: Arc::new(crate::stream::SendStream::from_quinn(send)),
                                        recv: Arc::new(crate::stream::RecvStream::from_quinn(recv)),
                                    })
                                    .await;
                            }
                        } else if let Some(tx) = requests {
                            // An HTTP/3 request. The frame type just read is
                            // the start of its first frame, so hand both on.
                            let _ = tx
                                .send(HttpRequestStream {
                                    send,
                                    recv,
                                    first_type: ty,
                                    buffered: rest,
                                })
                                .await;
                        }
                    });
                }
            }
        };

        let uni = {
            let this = self.clone();
            let settings = settings.clone();
            async move {
                loop {
                    let mut recv = match this.quinn().accept_uni().await {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let registry = this.registry.clone();
                    let settings = settings.clone();
                    tokio::spawn(async move {
                        let (ty, rest) = match crate::h3::read_stream_type(&mut recv).await {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        tracing::trace!(stream_type = ty, "incoming uni stream");
                        if ty == stream_type::WEBTRANSPORT {
                            let (session_id, _) =
                                match crate::h3::read_varint(&mut recv, rest).await {
                                    Ok(v) => v,
                                    Err(_) => return,
                                };
                            if let Some(session) = registry.get(session_id) {
                                session
                                    .deliver_uni(Arc::new(crate::stream::RecvStream::from_quinn(
                                        recv,
                                    )))
                                    .await;
                            }
                        } else if ty == stream_type::CONTROL {
                            // The control stream carries the peer's SETTINGS,
                            // which gate WebTransport processing.
                            if let Ok((peer, control)) = crate::h3::read_settings(recv).await {
                                // Logged because a peer that refuses the
                                // session before CONNECT leaves no other
                                // trace of why: the codepoints it did and
                                // did not send are the whole diagnosis, and
                                // `unknown` is where a draft revision we do
                                // not advertise shows up.
                                tracing::debug!(
                                    extended_connect = peer.enable_connect_protocol,
                                    h3_datagram = peer.h3_datagram,
                                    wt_enabled = peer.wt_enabled,
                                    wt_max_sessions = peer.wt_max_sessions,
                                    unknown = ?peer.unknown,
                                    raw = ?peer
                                        .raw
                                        .iter()
                                        .map(|(id, v)| format!("{id:#x}={v}"))
                                        .collect::<Vec<_>>(),
                                    "peer SETTINGS",
                                );
                                if let Some(tx) = settings.lock().unwrap().take() {
                                    let _ = tx.send(peer);
                                }
                                // The control stream stays open for the
                                // connection's lifetime (RFC 9114 §6.2.1).
                                crate::client::drain(control).await;
                            }
                        } else {
                            // QPACK streams: keep them open and discard their
                            // contents, since our encoder fills no dynamic
                            // table and so the peer sends no instructions.
                            crate::client::drain(recv).await;
                        }
                    });
                }
            }
        };

        tokio::join!(bi, uni);
    }

    /// Reads datagrams until the connection ends, routing each to its session.
    ///
    /// Runs as its own task: one reader per connection, not per session, so
    /// sessions sharing a connection cannot starve each other.
    pub async fn run_datagram_demux(self) {
        loop {
            match self.quinn().read_datagram().await {
                Ok(raw) => {
                    self.registry.route_datagram(raw);
                }
                Err(e) => {
                    // The connection is gone; every session on it has failed.
                    let reason = e.to_string();
                    for session in self.registry.all() {
                        session.fail(reason.clone());
                    }
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::DEFAULT_DATAGRAM_QUEUE;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeConn {
        sent: Mutex<Vec<Bytes>>,
    }

    impl ConnectionHandle for FakeConn {
        fn send_datagram(&self, payload: Bytes) -> Result<()> {
            self.sent.lock().unwrap().push(payload);
            Ok(())
        }
        fn max_datagram_size(&self) -> Option<usize> {
            Some(1200)
        }
        fn close(&self, _code: u64, _reason: &[u8]) {}
    }

    fn registry_with(ids: &[u64]) -> (Arc<SessionRegistry>, Vec<Session>) {
        let registry = Arc::new(SessionRegistry::new());
        let conn = Arc::new(FakeConn::default());
        let sessions: Vec<_> = ids
            .iter()
            .map(|&id| Session::new(id, conn.clone(), true, DEFAULT_DATAGRAM_QUEUE))
            .collect();
        for s in &sessions {
            registry.insert(s.clone());
        }
        (registry, sessions)
    }

    fn framed(session_id: u64, payload: &[u8]) -> Bytes {
        let mut buf = Vec::new();
        datagram::encode(&mut buf, session_id, payload).unwrap();
        Bytes::from(buf)
    }

    /// The point of the demux: two sessions on one connection each receive only
    /// their own datagrams.
    #[tokio::test]
    async fn datagrams_are_routed_to_the_owning_session() {
        let (registry, sessions) = registry_with(&[0, 4]);
        assert!(registry.route_datagram(framed(0, b"for-zero")));
        assert!(registry.route_datagram(framed(4, b"for-four")));

        assert_eq!(
            sessions[0].recv_datagram().await.unwrap(),
            Bytes::from_static(b"for-zero")
        );
        assert_eq!(
            sessions[1].recv_datagram().await.unwrap(),
            Bytes::from_static(b"for-four")
        );
    }

    /// A datagram may outlive its session; dropping it is correct, not an error.
    #[test]
    fn datagrams_for_unknown_sessions_are_dropped() {
        let (registry, _sessions) = registry_with(&[0]);
        assert!(!registry.route_datagram(framed(8, b"nobody")));
    }

    #[test]
    fn undecodable_datagrams_are_dropped() {
        let (registry, _sessions) = registry_with(&[0]);
        assert!(
            !registry.route_datagram(Bytes::new()),
            "empty datagram has no session id"
        );
    }

    #[test]
    fn sessions_can_be_registered_and_removed() {
        let (registry, _sessions) = registry_with(&[0, 4, 8]);
        assert_eq!(registry.len(), 3);
        assert!(registry.get(4).is_some());
        assert_eq!(registry.remove(4).map(|s| s.id()), Some(4));
        assert!(registry.get(4).is_none());
        assert_eq!(registry.len(), 2);
    }

    /// Once a session is removed its datagrams stop being delivered, so a
    /// closed session cannot keep receiving.
    #[test]
    fn removed_sessions_stop_receiving() {
        let (registry, _sessions) = registry_with(&[0]);
        assert!(registry.route_datagram(framed(0, b"first")));
        registry.remove(0);
        assert!(!registry.route_datagram(framed(0, b"second")));
    }

    #[test]
    fn an_empty_registry_reports_itself_empty() {
        let registry = SessionRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.all().is_empty());
    }
}
