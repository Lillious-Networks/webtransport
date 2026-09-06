//! End-to-end tests: a real client against a real server over loopback QUIC.
//!
//! These exercise the whole milestone-1 stack (QUIC handshake, HTTP/3, extended
//! CONNECT, session establishment and datagram delivery) over a self-signed
//! certificate the client trusts via `serverCertificateHashes`.

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::{CloseInfo, Session, State};

/// Anything needing the network gets a bound, so a hang fails instead of
/// blocking the suite forever.
const TIMEOUT: Duration = Duration::from_secs(10);

async fn with_timeout<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out waiting for {what}"),
    }
}

/// Starts a server on an ephemeral port, returning its URL and cert hash.
///
/// The `Server` is returned so the caller keeps it alive: dropping it drops the
/// QUIC endpoint, which stops the driver and kills every connection on it.
fn start_server() -> (
    Server,
    String,
    CertHash,
    tokio::sync::mpsc::Receiver<server::IncomingSession>,
) {
    let (chain, key, hash) = server::self_signed(&["localhost".into()]).expect("self-signed cert");
    let server = Server::bind(ServerConfig {
        addr: (Ipv4Addr::LOCALHOST, 0).into(),
        certificate_chain: chain,
        private_key: key,
        max_sessions: 4,
        max_concurrent_streams: None,
    })
    .expect("bind");
    let addr = server.local_addr().expect("local addr");
    let incoming = server.accept_sessions(8);
    (
        server,
        format!("https://localhost:{}/", addr.port()),
        CertHash {
            algorithm: HashAlgorithm::Sha256,
            value: hash,
        },
        incoming,
    )
}

fn pinned(hash: CertHash) -> ClientOptions {
    ClientOptions {
        server_certificate_hashes: vec![hash],
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn client_connects_and_server_observes_the_session() {
    let (_server, url, hash, mut incoming) = start_server();

    let connected = with_timeout("client connect", client::connect(&url, pinned(hash)))
        .await
        .expect("session should be established");

    assert_eq!(connected.session.state(), State::Connected);

    let server_session = with_timeout("server accept", incoming.recv())
        .await
        .expect("server should see the session");
    assert_eq!(server_session.path, "/");

    // Both ends agree on the session id: it is the CONNECT stream's id.
    assert_eq!(server_session.session().id(), connected.session.id());
}

#[tokio::test(flavor = "multi_thread")]
async fn datagrams_travel_from_client_to_server() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    connected
        .session
        .send_datagram(b"hello server")
        .expect("send");

    let received = with_timeout("datagram", server_session.recv_datagram())
        .await
        .expect("a datagram should arrive");
    assert_eq!(&received[..], b"hello server");
}

#[tokio::test(flavor = "multi_thread")]
async fn datagrams_travel_from_server_to_client() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    server_session.send_datagram(b"hello client").expect("send");

    let received = with_timeout("datagram", connected.session.recv_datagram())
        .await
        .expect("a datagram should arrive");
    assert_eq!(&received[..], b"hello client");
}

/// Datagrams are unreliable but not reordered arbitrarily on a quiet loopback,
/// so a small burst should arrive intact and in order.
#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_datagrams_round_trips() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    const COUNT: usize = 16;
    for i in 0..COUNT {
        connected
            .session
            .send_datagram(format!("packet-{i}").as_bytes())
            .expect("send");
    }

    for i in 0..COUNT {
        let received = with_timeout("datagram", server_session.recv_datagram())
            .await
            .expect("datagram");
        assert_eq!(&received[..], format!("packet-{i}").as_bytes());
    }
}

/// A datagram is delivered whole or not at all, so a payload at exactly the
/// reported limit must survive intact.
#[tokio::test(flavor = "multi_thread")]
async fn a_maximum_sized_datagram_arrives_intact() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let max = connected
        .session
        .max_datagram_size()
        .expect("datagrams supported");
    let payload = vec![0xab_u8; max];
    connected.session.send_datagram(&payload).expect("send");

    let received = with_timeout("datagram", server_session.recv_datagram())
        .await
        .expect("datagram");
    assert_eq!(received.len(), max, "the whole payload must arrive");
    assert!(received.iter().all(|&b| b == 0xab));
}

/// The client must refuse a server whose certificate does not match the pin.
#[tokio::test(flavor = "multi_thread")]
async fn a_mismatched_certificate_hash_is_rejected() {
    let (_server, url, _hash, _incoming) = start_server();

    // A syntactically valid hash of the right length, but the wrong certificate.
    let wrong = CertHash {
        algorithm: HashAlgorithm::Sha256,
        value: vec![0u8; 32],
    };
    let result = with_timeout("connect", client::connect(&url, pinned(wrong))).await;

    assert!(result.is_err(), "a mismatched pin must not connect");
}

/// Two sessions to the same server are independent: each receives only its own
/// datagrams. This is the routing the demux exists to provide.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_sessions_do_not_cross_talk() {
    let (_server, url, hash, mut incoming) = start_server();

    let first = with_timeout("connect a", client::connect(&url, pinned(hash.clone())))
        .await
        .expect("first session");
    let server_first = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout("connect b", client::connect(&url, pinned(hash)))
        .await
        .expect("second session");
    let server_second = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    first.session.send_datagram(b"to-first").expect("send");
    second.session.send_datagram(b"to-second").expect("send");

    let a = with_timeout("first datagram", server_first.recv_datagram())
        .await
        .expect("datagram");
    let b = with_timeout("second datagram", server_second.recv_datagram())
        .await
        .expect("datagram");

    assert_eq!(&a[..], b"to-first");
    assert_eq!(&b[..], b"to-second");
}

/// Closing is observable on the closing side and leaves the session unusable.
#[tokio::test(flavor = "multi_thread")]
async fn closing_a_session_makes_it_unusable() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let _server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    connected.session.close(CloseInfo {
        code: 7,
        reason: "done".into(),
    });

    assert!(matches!(
        connected.session.state(),
        State::Closed(info) if info.code == 7 && info.reason == "done"
    ));
    assert!(
        connected.session.send_datagram(b"too late").is_err(),
        "a closed session must refuse to send"
    );
}

/// The CONNECT path reaches the server, so an application can route on it.
#[tokio::test(flavor = "multi_thread")]
async fn the_connect_path_and_headers_reach_the_server() {
    let (_server, base, hash, mut incoming) = start_server();
    let url = format!("{}chat/room-9", base.trim_end_matches('/').to_owned() + "/");

    let options = ClientOptions {
        server_certificate_hashes: vec![hash],
        headers: vec![("x-token".into(), "secret".into())],
        protocols: vec!["chat.v1".into()],
        ..Default::default()
    };
    let _connected = with_timeout("connect", client::connect(&url, options))
        .await
        .expect("connect");

    let session: server::IncomingSession = with_timeout("accept", incoming.recv())
        .await
        .expect("accept");
    assert_eq!(session.path, "/chat/room-9");
    assert!(
        session
            .headers
            .iter()
            .any(|(n, v)| n == "x-token" && v == "secret"),
        "application headers should reach the server: {:?}",
        session.headers
    );
    assert_eq!(session.protocols, vec!["chat.v1".to_string()]);
}

/// `Session` is the shape the napi layer will hold, so it must be shareable
/// across tasks without extra wrapping.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_can_be_used_from_another_task() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session: Session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let sender = connected.session.clone();
    let task = tokio::spawn(async move { sender.send_datagram(b"from another task") });
    task.await.expect("task").expect("send");

    let received = with_timeout("datagram", server_session.recv_datagram())
        .await
        .expect("datagram");
    assert_eq!(&received[..], b"from another task");
}

/// Closing must reach the peer, not just settle locally.
///
/// draft §5 ties session termination to a WT_CLOSE_SESSION capsule on the
/// CONNECT stream. Without it the peer sees a live session until the whole
/// connection times out, which is minutes of a session that is already gone.
#[tokio::test(flavor = "multi_thread")]
async fn closing_reaches_the_peer_with_its_code_and_reason() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    connected.session.close(CloseInfo {
        code: 7,
        reason: "bye".into(),
    });

    // The server's session should settle on its own, well inside any timeout.
    let mut watch = server_session.watch();
    let observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let State::Closed(info) = &*watch.borrow_and_update() {
                return info.clone();
            }
            if watch.changed().await.is_err() {
                panic!("the session ended without a close");
            }
        }
    })
    .await
    .expect("the peer should observe the close");

    assert_eq!(observed.code, 7);
    assert_eq!(observed.reason, "bye");
}

/// Draining asks the peer to wind the session down.
///
/// It does not close anything: draft-ietf-webtrans-http3 §5 lets either
/// endpoint keep using a draining session and keep opening streams.
#[tokio::test(flavor = "multi_thread")]
async fn draining_reaches_the_peer() {
    let (_server, url, hash, mut incoming) = start_server();
    let connected = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    connected.session.drain();

    let mut watch = server_session.watch();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if matches!(*watch.borrow_and_update(), State::Draining) {
                return;
            }
            if watch.changed().await.is_err() {
                panic!("the session ended without draining");
            }
        }
    })
    .await
    .expect("the peer should observe the drain");
}
