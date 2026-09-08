//! WebTransport server: accepting connections and extended CONNECT sessions.

use crate::client::CongestionControl;
use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::h3;
use crate::session::{Session, State, DEFAULT_DATAGRAM_QUEUE};
use crate::tls;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use wt_proto::settings::Settings;

/// Server configuration.
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
    /// Concurrent WebTransport sessions advertised per connection.
    pub max_sessions: u64,
    /// Concurrent QUIC streams permitted per direction, per connection.
    ///
    /// quinn reserves bookkeeping proportional to this, so it trades headroom
    /// against memory: a server holding many connections pays it on each one.
    /// `None` uses [`crate::client::DEFAULT_MAX_CONCURRENT_STREAMS`].
    pub max_concurrent_streams: Option<u32>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("addr", &self.addr)
            .field("certificate_chain", &self.certificate_chain.len())
            .field("max_sessions", &self.max_sessions)
            .finish_non_exhaustive()
    }
}

/// An incoming session the application may accept or reject.
///
/// The CONNECT request is available before accepting, so authorization can be
/// decided from its path and headers.
pub struct IncomingSession {
    pub authority: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Subprotocols the client offered, in preference order.
    pub protocols: Vec<String>,
    session: Session,
    connection: Connection,
}

impl std::fmt::Debug for IncomingSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingSession")
            .field("path", &self.path)
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl IncomingSession {
    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Accepts the session, marking it connected.
    ///
    /// The 2xx response has already been sent by the time the application sees
    /// this, so accepting is a local state change.
    pub fn accept(self) -> Session {
        self.session.set_state(State::Connected);
        self.session
    }
}

/// A listening WebTransport server.
pub struct Server {
    endpoint: quinn::Endpoint,
    max_sessions: u64,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("local_addr", &self.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Binds a server to its configured address.
    pub fn bind(config: ServerConfig) -> Result<Self> {
        let crypto = tls::server_config(config.certificate_chain, config.private_key)
            .map_err(|e| Error::Tls(e.to_string()))?;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
            .map_err(|e| Error::Tls(e.to_string()))?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(Arc::new(crate::client::transport_config_with(
            CongestionControl::Default,
            config
                .max_concurrent_streams
                .unwrap_or(crate::client::DEFAULT_MAX_CONCURRENT_STREAMS),
        )));

        // A socket with a burst-sized receive buffer: the OS default overflows
        // when many clients connect at once, turning a flood of Initial packets
        // into handshake timeouts (see `bind_udp_socket`).
        let socket = crate::client::bind_udp_socket(config.addr)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            quinn::default_runtime().expect("no default quinn runtime"),
        )
        .map_err(|e| Error::Io(e.to_string()))?;
        Ok(Self {
            endpoint,
            max_sessions: config.max_sessions,
        })
    }

    /// Stops accepting and closes every live connection.
    ///
    /// Peers get a connection close rather than silence, and the endpoint's
    /// driver retires, which is what lets the host runtime shut down cleanly.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"server stopped");
    }

    /// The address actually bound, which resolves port 0 to the real port.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::Io(e.to_string()))
    }

    /// Accepts connections, emitting each WebTransport session they carry.
    ///
    /// One connection may yield several sessions when a client pools them, so
    /// this returns a stream of sessions rather than of connections.
    pub fn accept_sessions(&self, buffer: usize) -> mpsc::Receiver<IncomingSession> {
        self.accept_sessions_with_errors(buffer, None)
    }

    /// As [`accept_sessions`], also reporting connection-level failures.
    ///
    /// A handshake that fails before a session exists cannot be reported on a
    /// session, so without this it would be silent.
    pub fn accept_sessions_with_errors(
        &self,
        buffer: usize,
        errors: Option<mpsc::Sender<String>>,
    ) -> mpsc::Receiver<IncomingSession> {
        let (tx, rx) = mpsc::channel(buffer.max(1));
        let endpoint = self.endpoint.clone();
        let max_sessions = self.max_sessions;
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let tx = tx.clone();
                // Each connection is served independently: one failing
                // handshake must not stop the listener.
                let errors = errors.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_connection(incoming, tx, max_sessions).await {
                        // Surfaced rather than swallowed: a handshake that
                        // fails before any session exists has no other way to
                        // reach the application.
                        if let Some(errors) = errors {
                            let _ = errors.send(e.to_string()).await;
                        }
                    }
                });
            }
        });
        rx
    }
}

impl Drop for Server {
    /// Closes the endpoint when the server goes away.
    ///
    /// An application is not required to call `close`, and a server that is
    /// simply dropped must not leave its endpoint driver running: a live
    /// driver at process exit aborts the process on Linux, after everything
    /// else has succeeded. Closing here makes that impossible to get wrong
    /// from the outside, rather than relying on a teardown hook that may run
    /// too late or not at all.
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"server dropped");
    }
}

/// Drives one QUIC connection, emitting the WebTransport sessions on it.
async fn serve_connection(
    incoming: quinn::Incoming,
    tx: mpsc::Sender<IncomingSession>,
    max_sessions: u64,
) -> Result<()> {
    let quic = match incoming.await {
        Ok(c) => c,
        Err(e) => return Err(Error::Connect(e.to_string())),
    };
    let supports_datagrams = quic.max_datagram_size().is_some();

    // Announce WebTransport support before anything else: a client must see
    // our SETTINGS before it may open a session (draft §4.5).
    let advertised = Settings::advertised(max_sessions);
    tracing::debug!(
        ?advertised,
        supports_datagrams,
        max_datagram_size = ?quic.max_datagram_size(),
        "advertising SETTINGS",
    );
    let control = h3::open_control_stream(&quic, advertised).await?;
    let qpack = h3::open_qpack_streams(&quic).await?;

    // A peer that refuses our SETTINGS closes the connection instead of
    // sending CONNECT, and its error code is the only thing that says why.
    // Without this the refusal is indistinguishable from the client simply
    // going away.
    {
        let quic = quic.clone();
        tokio::spawn(async move {
            let reason = quic.closed().await;
            tracing::debug!(%reason, "connection closed");
        });
    }

    let connection = Connection::new(quic.clone());

    // The demux is the connection's only stream acceptor: it routes
    // WebTransport streams to their session and hands HTTP/3 requests here.
    let (requests_tx, mut requests) = mpsc::channel(16);
    let (settings_tx, settings_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(connection.clone().run_datagram_demux());
    tokio::spawn(
        connection
            .clone()
            .run_stream_demux_with_settings(Some(requests_tx), Some(settings_tx)),
    );

    // Hold our HTTP/3 streams open for the connection's lifetime.
    let _keepalive = (control, qpack);

    // draft §3.1: a server MUST NOT process WebTransport requests until the
    // client's SETTINGS have arrived, because the client may be speaking a
    // different draft. A CONNECT can legitimately arrive first (§4.5), so this
    // waits rather than rejecting.
    let client_settings =
        match tokio::time::timeout(std::time::Duration::from_secs(10), settings_rx).await {
            Ok(Ok(settings)) => settings,
            // No SETTINGS means no usable HTTP/3 connection.
            _ => return Err(Error::Protocol("the client never sent its SETTINGS".into())),
        };
    // Only H3_DATAGRAM is checked, matching quic-go's server: SETTINGS_ENABLE_
    // CONNECT_PROTOCOL is a server-to-client signal (RFC 9220), so a
    // conforming client does not send it and requiring it here would reject
    // every browser. The WebTransport support indicators are not checked
    // either, since final-spec clients may send none of them, and the draft
    // only has us wait for the client's SETTINGS to arrive (§3.1).
    if !client_settings.h3_datagram {
        tracing::debug!("closing: client SETTINGS lack H3_DATAGRAM");
        quic.close(0u32.into(), b"client does not support http datagrams");
        return Err(Error::Protocol(format!(
            "client SETTINGS lack datagram support: {client_settings:?}"
        )));
    }

    while let Some(request) = requests.recv().await {
        let crate::connection::HttpRequestStream {
            mut send,
            mut recv,
            first_type,
            buffered,
        } = request;

        let fields = match h3::read_headers_resuming(&mut recv, first_type, buffered).await {
            Ok(f) => f,
            // Dropping the stream here answers nothing, so the peer waits for
            // a response that never comes and reports only a generic session
            // failure. A QPACK sequence we cannot decode looks exactly like
            // that from the outside, so say so.
            Err(e) => {
                tracing::debug!(error = %e, "could not read CONNECT headers");
                continue;
            }
        };
        tracing::debug!(?fields, "CONNECT request");

        let is_webtransport = h3::field(&fields, ":method") == Some("CONNECT")
            && h3::field(&fields, ":protocol") == Some("webtransport");
        if !is_webtransport {
            tracing::debug!(
                method = ?h3::field(&fields, ":method"),
                protocol = ?h3::field(&fields, ":protocol"),
                "not a WebTransport CONNECT, answering 501",
            );
            let response = vec![(":status".to_owned(), "501".to_owned())];
            let _ = h3::write_headers(&mut send, &response).await;
            continue;
        }

        // The session id is the CONNECT stream's id (draft §4.1).
        let session_id = send.id().index() * 4;
        let session = Session::new(
            session_id,
            connection.handle(),
            supports_datagrams,
            DEFAULT_DATAGRAM_QUEUE,
        );
        connection.registry().insert(session.clone());

        let incoming = IncomingSession {
            authority: h3::field(&fields, ":authority")
                .unwrap_or_default()
                .to_owned(),
            path: h3::field(&fields, ":path").unwrap_or("/").to_owned(),
            protocols: h3::field(&fields, "wt-available-protocols")
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            headers: fields
                .iter()
                .filter(|(n, _)| !n.starts_with(':'))
                .cloned()
                .collect(),
            session: session.clone(),
            connection: connection.clone(),
        };

        // The 2xx response is what establishes the session on the wire.
        let mut response = vec![(":status".to_owned(), "200".to_owned())];
        // draft-02 negotiates in the CONNECT exchange as well as in SETTINGS:
        // a client offering it sends `Sec-Webtransport-Http3-Draft02: 1` and
        // the server confirms with `Sec-Webtransport-Http3-Draft: draft02`.
        // Echoed only when asked for, so a peer on a later draft sees nothing
        // extra. Chromium negotiates draft-02 and tolerates the confirmation
        // being absent; nothing says every client does.
        if h3::field(&fields, "sec-webtransport-http3-draft02").is_some() {
            response.push((
                "sec-webtransport-http3-draft".to_owned(),
                "draft02".to_owned(),
            ));
        }
        if let Err(e) = h3::write_headers(&mut send, &response).await {
            tracing::debug!(error = %e, session_id, "could not write the CONNECT response");
            connection.registry().remove(session_id);
            continue;
        }
        tracing::debug!(session_id, "session established");

        // The session owns its CONNECT stream: its lifetime is the session's,
        // and close and drain put their capsules on it.
        session.attach_connect_stream(send).await;
        tokio::spawn(crate::capsules::watch_connect_stream(
            recv,
            session.clone(),
            Some(connection.clone()),
        ));

        if tx.send(incoming).await.is_err() {
            // Nobody is accepting sessions any more.
            return Ok(());
        }
    }
    Ok(())
}

/// Generates a self-signed certificate for local development.
///
/// The digest is what a client passes as `serverCertificateHashes`, which is how
/// a browser or our client trusts a server with no CA.
#[cfg(feature = "self-signed")]
pub fn self_signed(
    subject_alt_names: &[String],
) -> Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<u8>,
)> {
    // Bounded validity and an ECDSA P-256 key, as serverCertificateHashes
    // requires: a browser rejects anything else during the TLS handshake.
    let mut params = rcgen::CertificateParams::new(subject_alt_names.to_vec())
        .map_err(|e| Error::Tls(e.to_string()))?;
    let now = std::time::SystemTime::now();
    params.not_before = now.into();
    params.not_after = (now + std::time::Duration::from_secs(13 * 24 * 60 * 60)).into();

    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Tls(e.to_string()))?;
    let cert = params
        .self_signed(&keypair)
        .map_err(|e| Error::Tls(e.to_string()))?;

    let der = CertificateDer::from(cert.der().to_vec());
    let hash = tls::certificate_hash(&der);
    let key =
        PrivateKeyDer::try_from(keypair.serialize_der()).map_err(|e| Error::Tls(e.to_string()))?;
    Ok((vec![der], key, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "self-signed")]
    fn local_config(port: u16) -> ServerConfig {
        let (chain, key, _) = self_signed(&["localhost".into()]).unwrap();
        ServerConfig {
            addr: (std::net::Ipv4Addr::LOCALHOST, port).into(),
            certificate_chain: chain,
            private_key: key,
            max_sessions: 1,
            max_concurrent_streams: None,
        }
    }

    #[cfg(feature = "self-signed")]
    #[test]
    fn a_self_signed_certificate_carries_its_own_hash() {
        let (chain, _key, hash) = self_signed(&["localhost".into()]).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(hash.len(), 32, "sha-256 digest");
        assert_eq!(hash, tls::certificate_hash(&chain[0]));
    }

    /// Binding to port 0 must report the port the OS actually chose, which is
    /// what tests and examples connect to.
    #[cfg(feature = "self-signed")]
    #[tokio::test]
    async fn binding_to_port_zero_reports_the_real_port() {
        let server = Server::bind(local_config(0)).unwrap();
        let addr = server.local_addr().unwrap();
        assert_ne!(addr.port(), 0, "an ephemeral port must be resolved");
        assert!(addr.ip().is_loopback());
    }

    #[cfg(feature = "self-signed")]
    #[tokio::test]
    async fn two_servers_can_bind_independently() {
        let a = Server::bind(local_config(0)).unwrap();
        let b = Server::bind(local_config(0)).unwrap();
        assert_ne!(a.local_addr().unwrap(), b.local_addr().unwrap());
    }
}
