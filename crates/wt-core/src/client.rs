//! WebTransport client: QUIC connection setup and session establishment.

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::h3;
use crate::session::{Session, State, DEFAULT_DATAGRAM_QUEUE};
use crate::tls::{self, CertHash};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use wt_proto::settings::Settings;

/// Options for opening a session, mirroring `WebTransportOptions`.
#[derive(Debug, Clone, Default)]
pub struct ClientOptions {
    /// Pin trust to these certificate hashes instead of the platform store.
    pub server_certificate_hashes: Vec<CertHash>,
    /// Application-level headers on the CONNECT request.
    pub headers: Vec<(String, String)>,
    /// Subprotocols to offer via the `WT-Available-Protocols` header.
    pub protocols: Vec<String>,
    /// Refuse the session if datagrams are unavailable.
    pub require_unreliable: bool,
    pub congestion_control: CongestionControl,
    /// Share a QUIC connection with other sessions to the same origin.
    ///
    /// The spec forbids combining this with `server_certificate_hashes`: a
    /// pooled connection was validated for whoever opened it.
    pub allow_pooling: bool,
}

/// `WebTransportCongestionControl`. A hint: the spec lets the user agent do
/// what it can, so this selects a controller rather than promising behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CongestionControl {
    #[default]
    Default,
    Throughput,
    LowLatency,
}

/// A validated WebTransport URL.
///
/// The spec requires an https scheme, a host, and no fragment; those are
/// synchronous constructor throws, so validation happens before any I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTransportUrl {
    pub authority: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl WebTransportUrl {
    pub fn parse(url: &str) -> Result<Self> {
        // A fragment is never valid, and a permissive parser would keep it.
        if url.contains('#') {
            return Err(Error::InvalidUrl(
                "a WebTransport URL cannot have a fragment".into(),
            ));
        }
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| Error::InvalidUrl("the scheme must be https".into()))?;

        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(Error::InvalidUrl("missing host".into()));
        }

        // An IPv6 literal is bracketed, so scan for the port after the bracket.
        let (host, port) = if let Some(end) = authority.rfind(']') {
            let host = &authority[..=end];
            let port = authority[end + 1..]
                .strip_prefix(':')
                .map(str::parse::<u16>)
                .transpose()
                .map_err(|_| Error::InvalidUrl("invalid port".into()))?;
            (host.to_owned(), port.unwrap_or(443))
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_owned(),
                    p.parse()
                        .map_err(|_| Error::InvalidUrl("invalid port".into()))?,
                ),
                None => (authority.to_owned(), 443),
            }
        };
        if host.is_empty() {
            return Err(Error::InvalidUrl("missing host".into()));
        }

        Ok(Self {
            authority: authority.to_owned(),
            host,
            port,
            path: path.to_owned(),
        })
    }
}

/// Creates a client-side QUIC endpoint bound to an ephemeral local port.
///
/// Prefer [`shared_endpoint`]: a QUIC endpoint owns a UDP socket, a driver task
/// and its crypto state, and one endpoint can carry any number of connections.
pub fn client_endpoint(
    remote: SocketAddr,
    hashes: &[CertHash],
    congestion: CongestionControl,
) -> Result<quinn::Endpoint> {
    let crypto = tls::client_config(hashes).map_err(|e| Error::Tls(e.to_string()))?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config(congestion)));

    let bind: SocketAddr = if remote.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = bind_udp_socket(bind)?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        quinn::default_runtime().expect("no default quinn runtime"),
    )
    .map_err(|e| Error::Io(e.to_string()))?;
    endpoint.set_default_client_config(config);
    // Closed at module teardown, before napi drops the runtime its driver runs
    // on; see `crate::shutdown`.
    crate::shutdown::register(&endpoint);
    Ok(endpoint)
}

/// Endpoints shared between sessions, keyed by address family.
///
/// Giving every session its own endpoint costs a socket and a driver task each,
/// while one endpoint can carry any number of connections. Only the address
/// family has to differ, since the per-session TLS configuration travels with
/// `connect_with` rather than the endpoint.
///
/// An endpoint's driver runs on the Tokio runtime that created it, so the cache
/// is per-runtime: reusing one across runtimes hands out an endpoint whose
/// driver has already shut down, which surfaces much later as "endpoint driver
/// future was dropped".
static SHARED_ENDPOINTS: std::sync::OnceLock<Mutex<HashMap<(usize, bool), quinn::Endpoint>>> =
    std::sync::OnceLock::new();

/// Returns the shared endpoint for `remote`'s address family, creating it once
/// per Tokio runtime.
pub fn shared_endpoint(remote: SocketAddr) -> Result<quinn::Endpoint> {
    let key = (runtime_key(), remote.is_ipv6());
    let endpoints = SHARED_ENDPOINTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut endpoints = endpoints.lock().unwrap();

    if let Some(endpoint) = endpoints.get(&key) {
        // `local_addr` fails once the endpoint's driver has shut down. Checking
        // beats handing back an endpoint whose connections would fail on first
        // use, with an error that points nowhere near the cause.
        if endpoint.local_addr().is_ok() {
            return Ok(endpoint.clone());
        }
        endpoints.remove(&key);
    }

    let bind: SocketAddr = if remote.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = bind_udp_socket(bind)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket,
        quinn::default_runtime().expect("no default quinn runtime"),
    )
    .map_err(|e| Error::Io(e.to_string()))?;
    // Closed at module teardown, before napi drops the runtime its driver runs
    // on; see `crate::shutdown`.
    crate::shutdown::register(&endpoint);
    endpoints.insert(key, endpoint.clone());
    Ok(endpoint)
}

/// Binds a UDP socket for an endpoint, with a receive buffer sized for bursts.
///
/// The OS default (64 KiB on Windows) overflows when many connections begin at
/// once: a thousand handshakes are a burst of Initial packets far larger than
/// that, and the resulting retransmits push slow handshakes past quinn's
/// timeout. Datagrams under load hit the same wall. A large buffer is the fix
/// on every OS, and memory-cheap since the buffer pages are touched on demand.
pub(crate) fn bind_udp_socket(addr: SocketAddr) -> Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| Error::Io(e.to_string()))?;
    // Best-effort: Windows caps SO_RCVBUF without admin privileges, but even
    // its cap is far above the default.
    let _ = socket.set_recv_buffer_size(8 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(8 * 1024 * 1024);
    socket
        .set_nonblocking(false)
        .map_err(|e| Error::Io(e.to_string()))?;
    socket
        .bind(&addr.into())
        .map_err(|e| Error::Io(e.to_string()))?;
    Ok(socket.into())
}

/// A stable identifier for the current Tokio runtime.
fn runtime_key() -> usize {
    use std::hash::{Hash, Hasher};
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            handle.id().hash(&mut hasher);
            hasher.finish() as usize
        }
        // Outside a runtime there is nothing to share with.
        Err(_) => 0,
    }
}

/// The client configuration for one session's trust and congestion settings.
pub fn client_config_for(
    hashes: &[CertHash],
    congestion: CongestionControl,
) -> Result<quinn::ClientConfig> {
    let crypto = tls::client_config(hashes).map_err(|e| Error::Tls(e.to_string()))?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config(congestion)));
    Ok(config)
}

/// Default concurrent streams permitted per direction.
///
/// quinn reserves per-connection bookkeeping proportional to this, about
/// 0.36 KiB per permitted stream, so the limit is a memory decision as much as
/// a protocol one: at 10,000 a connection costs roughly 2.5 MiB before it
/// carries any data, which a server holding thousands of them feels. 2,000 is
/// far above quinn's default of 100 and above what ordinary use reaches, while
/// keeping a connection near 0.7 MiB. Applications that genuinely want more
/// can raise it per endpoint.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 2000;

/// Transport settings shared by both ends, with the default stream limit.
pub(crate) fn transport_config(congestion: CongestionControl) -> quinn::TransportConfig {
    transport_config_with(congestion, DEFAULT_MAX_CONCURRENT_STREAMS)
}

/// Transport settings with an explicit concurrent-stream limit.
pub(crate) fn transport_config_with(
    congestion: CongestionControl,
    max_concurrent_streams: u32,
) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    // WebTransport needs datagrams; a zero-size receive buffer disables them.
    // Sized for bursts, not throughput: the per-connection queue absorbs a
    // synchronised spike from many peers while the session queues drain it,
    // and quinn drops from it before the application ever sees pressure.
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(256 * 1024);

    // quinn defaults to 100 concurrent streams per direction. WebTransport
    // applications routinely want far more (a stream per request or per
    // object is an intended use), and exhausting the limit stalls the opener
    // rather than failing it, so the default reads as a hang. These bounds
    // still cap what a peer can force us to track.
    let streams = max_concurrent_streams.max(1);
    transport.max_concurrent_uni_streams(streams.into());
    transport.max_concurrent_bidi_streams(streams.into());

    // Per-stream and connection-wide receive windows. The defaults are tuned
    // for a handful of HTTP requests; with thousands of streams the connection
    // window is the binding constraint on throughput.
    transport.stream_receive_window((1024u32 * 1024).into());
    transport.receive_window((16u32 * 1024 * 1024).into());
    transport.send_window(16777216);
    match congestion {
        CongestionControl::LowLatency => {
            // BBR holds queues shorter than loss-based control, which is what
            // "low-latency" asks for.
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
        CongestionControl::Throughput | CongestionControl::Default => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        }
    }
    transport
}

/// A connected WebTransport client session plus the connection carrying it.
pub struct ClientSession {
    pub session: Session,
    pub connection: Connection,
    /// Response headers from the server's CONNECT response.
    pub response_headers: Vec<(String, String)>,
    /// The negotiated subprotocol, if the server chose one.
    pub protocol: Option<String>,
    /// The QUIC endpoint this session runs on.
    ///
    /// Held for its lifetime on purpose: dropping a `quinn::Endpoint` shuts down
    /// its driver task and silently kills every connection on it.
    _endpoint: quinn::Endpoint,
    /// The connection's HTTP/3 streams, shared with any pooled siblings.
    _keepalive: Arc<crate::pool::H3Streams>,
}

impl std::fmt::Debug for ClientSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientSession")
            .field("session", &self.session)
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

/// Opens a WebTransport session.
pub async fn connect(url: &str, options: ClientOptions) -> Result<ClientSession> {
    connect_with_pool(url, options, crate::pool::global()).await
}

/// As [`connect`], but against a caller-supplied pool.
///
/// The spec forbids combining pooling with `serverCertificateHashes`, which
/// makes the pooled path impossible to reach against a self-signed server
/// through the public API. Tests use this to exercise real connection sharing
/// without weakening that rule for callers.
pub async fn connect_with_pool(
    url: &str,
    options: ClientOptions,
    pool: &crate::pool::ConnectionPool,
) -> Result<ClientSession> {
    let url = WebTransportUrl::parse(url)?;

    let pool_key = crate::pool::PoolKey::new(&url.host, url.port, options.congestion_control);
    let pooled = if options.allow_pooling {
        pool.get(&pool_key)
    } else {
        None
    };

    let (connection, endpoint, keepalive, datagrams_ok) = match pooled {
        // Join an existing connection: its HTTP/3 setup is already done.
        Some(existing) => {
            let datagrams_ok = existing.connection.quinn().max_datagram_size().is_some();
            (
                existing.connection,
                existing.endpoint,
                existing.keepalive,
                datagrams_ok,
            )
        }
        None => {
            let (connection, endpoint, keepalive, datagrams_ok) = establish(&url, &options).await?;
            if options.allow_pooling {
                pool.insert(
                    pool_key,
                    crate::pool::PooledConnection {
                        connection: connection.clone(),
                        endpoint: endpoint.clone(),
                        keepalive: keepalive.clone(),
                    },
                );
            }
            (connection, endpoint, keepalive, datagrams_ok)
        }
    };

    if options.require_unreliable && !datagrams_ok {
        return Err(Error::DatagramUnsupported);
    }

    open_session(url, options, connection, endpoint, keepalive, datagrams_ok).await
}

/// Establishes a fresh QUIC connection with its HTTP/3 layer set up.
async fn establish(
    url: &WebTransportUrl,
    options: &ClientOptions,
) -> Result<(
    Connection,
    quinn::Endpoint,
    Arc<crate::pool::H3Streams>,
    bool,
)> {
    let addr = resolve(url).await?;
    // One endpoint serves every session: its socket and driver are shared, and
    // the per-session trust and congestion settings travel with the connection
    // rather than the endpoint.
    let endpoint = shared_endpoint(addr)?;
    let config = client_config_for(
        &options.server_certificate_hashes,
        options.congestion_control,
    )?;

    let quic = endpoint
        .connect_with(config, addr, hostname_for_tls(&url.host))
        .map_err(|e| Error::Connect(e.to_string()))?
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;

    let supports_datagrams = quic.max_datagram_size().is_some();

    // HTTP/3 setup: our control stream with SETTINGS, then the QPACK streams.
    let control = h3::open_control_stream(&quic, Settings::advertised(16)).await?;
    let (qpack_encoder, qpack_decoder) = h3::open_qpack_streams(&quic).await?;

    // The peer's SETTINGS decide whether WebTransport is available at all
    // (draft §3.1, §4.5), so wait for them before opening a session.
    let peer_settings = read_peer_settings(&quic).await?;
    if !peer_settings.accepts_webtransport() {
        quic.close(0u32.into(), b"no webtransport support");
        return Err(Error::WebTransportUnsupported);
    }

    let connection = Connection::new(quic);
    tokio::spawn(connection.clone().run_datagram_demux());
    tokio::spawn(connection.clone().run_stream_demux(None));

    Ok((
        connection,
        endpoint,
        Arc::new(crate::pool::H3Streams {
            _control: control,
            _qpack_encoder: qpack_encoder,
            _qpack_decoder: qpack_decoder,
        }),
        supports_datagrams && peer_settings.supports_datagrams(),
    ))
}

/// Opens one session on an established connection.
async fn open_session(
    url: WebTransportUrl,
    options: ClientOptions,
    connection: Connection,
    endpoint: quinn::Endpoint,
    keepalive: Arc<crate::pool::H3Streams>,
    datagrams_ok: bool,
) -> Result<ClientSession> {
    // The CONNECT request stream: its id becomes the session id.
    let (mut connect_send, mut connect_recv) = connection
        .quinn()
        .open_bi()
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
    let session_id = connect_send.id().index() * 4;

    let fields = h3::connect_request_fields(
        &url.authority,
        &url.path,
        &options.headers,
        &options.protocols,
    );
    h3::write_headers(&mut connect_send, &fields).await?;

    let response = h3::read_headers(&mut connect_recv).await?;
    let status = h3::status_of(&response).unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(Error::SessionRejected(status));
    }

    let protocol = h3::field(&response, "wt-protocol").map(str::to_owned);

    let session = Session::new(
        session_id,
        connection.handle(),
        datagrams_ok,
        DEFAULT_DATAGRAM_QUEUE,
    );
    session.set_state(State::Connected);
    session.attach_connect_stream(connect_send).await;
    connection.registry().insert(session.clone());

    // The CONNECT stream ending means the session ended (draft §6).
    tokio::spawn(crate::capsules::watch_connect_stream(
        connect_recv,
        session.clone(),
        Some(connection.clone()),
    ));

    Ok(ClientSession {
        session,
        connection,
        response_headers: response,
        protocol,
        _endpoint: endpoint,
        _keepalive: keepalive,
    })
}

/// Accepts unidirectional streams until the peer's control stream arrives,
/// then reads its SETTINGS.
async fn read_peer_settings(quic: &quinn::Connection) -> Result<Settings> {
    use wt_proto::frame::stream_type;
    loop {
        let mut stream = quic
            .accept_uni()
            .await
            .map_err(|e| Error::Connect(format!("waiting for SETTINGS: {e}")))?;
        let (ty, _rest) = h3::read_stream_type(&mut stream).await?;
        if ty == stream_type::CONTROL {
            let (settings, control) = h3::read_settings(stream).await?;
            // The control stream must stay open for the connection's lifetime,
            // so park it rather than dropping it here.
            tokio::spawn(drain(control));
            return Ok(settings);
        }
        // QPACK and other streams are accepted and drained; we never need their
        // contents because our encoder emits no dynamic table instructions.
        tokio::spawn(drain(stream));
    }
}

/// Reads and discards a stream until it ends, keeping it open meanwhile.
pub(crate) async fn drain(mut stream: quinn::RecvStream) {
    let mut sink = [0u8; 1024];
    while matches!(stream.read(&mut sink).await, Ok(Some(_))) {}
}

/// The name to validate the certificate against.
///
/// An IPv6 literal keeps its brackets in the URL but must be presented to TLS
/// without them.
fn hostname_for_tls(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Resolves the URL's host to a socket address.
async fn resolve(url: &WebTransportUrl) -> Result<SocketAddr> {
    let host = hostname_for_tls(&url.host).to_owned();
    let port = url.port;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.clone(), port))
        .await
        .map_err(|_| Error::Dns(host.clone()))?
        .collect();
    if addrs.is_empty() {
        return Err(Error::Dns(host));
    }
    // Prefer IPv4. A name like "localhost" commonly resolves to ::1 first, and
    // blindly taking that address silently fails against an IPv4-bound server:
    // the handshake goes nowhere and only surfaces as a timeout.
    addrs.sort_by_key(|a| u8::from(a.is_ipv6()));
    Ok(addrs[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_valid_https_url() {
        let url = WebTransportUrl::parse("https://example.com:4433/counter").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 4433);
        assert_eq!(url.path, "/counter");
        assert_eq!(url.authority, "example.com:4433");
    }

    #[test]
    fn defaults_to_port_443_and_root_path() {
        let url = WebTransportUrl::parse("https://example.com").unwrap();
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/");
    }

    /// The spec throws SyntaxError for a non-https scheme, so it must never
    /// reach the network.
    #[test]
    fn rejects_non_https_schemes() {
        for url in [
            "http://example.com/",
            "wss://example.com/",
            "ftp://example.com/",
        ] {
            assert!(
                matches!(WebTransportUrl::parse(url), Err(Error::InvalidUrl(_))),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_urls_with_a_fragment() {
        for url in ["https://example.com/path#frag", "https://example.com/path#"] {
            assert!(
                matches!(WebTransportUrl::parse(url), Err(Error::InvalidUrl(_))),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_urls_without_a_host() {
        assert!(matches!(
            WebTransportUrl::parse("https:///path"),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn parses_ipv6_literals() {
        let url = WebTransportUrl::parse("https://[::1]:4433/x").unwrap();
        assert_eq!(url.host, "[::1]");
        assert_eq!(url.port, 4433);
        assert_eq!(
            hostname_for_tls(&url.host),
            "::1",
            "TLS sees the address without brackets"
        );
    }

    #[tokio::test]
    async fn ip_literals_resolve_without_dns() {
        let v4 = WebTransportUrl::parse("https://127.0.0.1:4433/").unwrap();
        assert_eq!(
            resolve(&v4).await.unwrap(),
            "127.0.0.1:4433".parse().unwrap()
        );
        let v6 = WebTransportUrl::parse("https://[::1]:4433/").unwrap();
        assert_eq!(resolve(&v6).await.unwrap(), "[::1]:4433".parse().unwrap());
    }
}
