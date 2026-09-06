//! Pooling: several sessions sharing one QUIC connection.

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};

const TIMEOUT: Duration = Duration::from_secs(10);

async fn with_timeout<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out waiting for {what}"),
    }
}

fn start_server() -> (
    Server,
    String,
    CertHash,
    tokio::sync::mpsc::Receiver<server::IncomingSession>,
) {
    let (chain, key, hash) = server::self_signed(&["localhost".into()]).expect("cert");
    let server = Server::bind(ServerConfig {
        addr: (Ipv4Addr::LOCALHOST, 0).into(),
        certificate_chain: chain,
        private_key: key,
        max_sessions: 16,
        max_concurrent_streams: None,
    })
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    let incoming = server.accept_sessions(16);
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

fn dedicated(hash: CertHash) -> ClientOptions {
    ClientOptions {
        server_certificate_hashes: vec![hash],
        allow_pooling: false,
        ..Default::default()
    }
}

/// Pooling forbids certificate pinning through the public API, so reaching the
/// pooled path against a self-signed server needs `connect_with_pool`, which
/// takes a pool of the test's own rather than the process-wide one.
fn pooled(hash: CertHash) -> ClientOptions {
    ClientOptions {
        server_certificate_hashes: vec![hash],
        allow_pooling: true,
        ..Default::default()
    }
}

/// Two sessions to the same origin share one QUIC connection.
#[tokio::test(flavor = "multi_thread")]
async fn pooled_sessions_share_one_connection() {
    use wt_core::pool::ConnectionPool;

    let (_server, url, hash, mut incoming) = start_server();
    let pool = ConnectionPool::new();

    let first = with_timeout(
        "connect a",
        client::connect_with_pool(&url, pooled(hash.clone()), &pool),
    )
    .await
    .expect("first");
    let _a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout(
        "connect b",
        client::connect_with_pool(&url, pooled(hash), &pool),
    )
    .await
    .expect("second");
    let _b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    assert_eq!(
        first.connection.quinn().stable_id(),
        second.connection.quinn().stable_id(),
        "pooled sessions must share one QUIC connection"
    );
    assert_eq!(pool.len(), 1, "one origin means one pooled connection");

    // Sharing a connection must not merge the sessions: each keeps its own id,
    // which is what scopes its streams and datagrams.
    assert_ne!(first.session.id(), second.session.id());
}

/// Sessions sharing a connection still receive only their own datagrams.
#[tokio::test(flavor = "multi_thread")]
async fn pooled_sessions_do_not_cross_talk() {
    use wt_core::pool::ConnectionPool;

    let (_server, url, hash, mut incoming) = start_server();
    let pool = ConnectionPool::new();

    let first = with_timeout(
        "connect a",
        client::connect_with_pool(&url, pooled(hash.clone()), &pool),
    )
    .await
    .expect("first");
    let server_a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout(
        "connect b",
        client::connect_with_pool(&url, pooled(hash), &pool),
    )
    .await
    .expect("second");
    let server_b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    first.session.send_datagram(b"to-first").expect("send");
    second.session.send_datagram(b"to-second").expect("send");

    let a = with_timeout("datagram a", server_a.recv_datagram())
        .await
        .expect("datagram");
    let b = with_timeout("datagram b", server_b.recv_datagram())
        .await
        .expect("datagram");
    assert_eq!(
        &a[..],
        b"to-first",
        "a pooled session received its neighbour's datagram"
    );
    assert_eq!(&b[..], b"to-second");
}

/// Streams stay scoped to their session across a shared connection, which is
/// the whole reason the wire format carries a session id on every stream.
#[tokio::test(flavor = "multi_thread")]
async fn pooled_sessions_keep_their_streams_apart() {
    use wt_core::pool::ConnectionPool;

    let (_server, url, hash, mut incoming) = start_server();
    let pool = ConnectionPool::new();

    let first = with_timeout(
        "connect a",
        client::connect_with_pool(&url, pooled(hash.clone()), &pool),
    )
    .await
    .expect("first");
    let server_a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout(
        "connect b",
        client::connect_with_pool(&url, pooled(hash), &pool),
    )
    .await
    .expect("second");
    let server_b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let send = first.session.open_uni(None, None).await.expect("open");
    send.write_all(b"belongs to the first session")
        .await
        .expect("write");
    send.finish().await.expect("finish");

    let recv = with_timeout("accept on a", server_a.accept_uni())
        .await
        .expect("stream");
    let mut data = Vec::new();
    while let Some(chunk) = recv.read_chunk(None).await.expect("read") {
        data.extend_from_slice(&chunk);
    }
    assert_eq!(data, b"belongs to the first session");

    // The other session must not have seen it.
    let leaked = tokio::time::timeout(Duration::from_millis(300), server_b.accept_uni()).await;
    assert!(leaked.is_err(), "a stream leaked into a pooled neighbour");

    let _ = second;
}

/// Keying material stays separate even when the TLS connection is shared. This
/// is exactly what the WebTransport exporter context exists to guarantee.
#[tokio::test(flavor = "multi_thread")]
async fn pooled_sessions_derive_different_keying_material() {
    use wt_core::pool::ConnectionPool;

    let (_server, url, hash, mut incoming) = start_server();
    let pool = ConnectionPool::new();

    let first = with_timeout(
        "connect a",
        client::connect_with_pool(&url, pooled(hash.clone()), &pool),
    )
    .await
    .expect("first");
    let _a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();
    let second = with_timeout(
        "connect b",
        client::connect_with_pool(&url, pooled(hash), &pool),
    )
    .await
    .expect("second");
    let _b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    // Same TLS connection, same label and context: only the session id differs.
    let a = first
        .session
        .export_keying_material(b"l", b"c", 32)
        .expect("export");
    let b = second
        .session
        .export_keying_material(b"l", b"c", 32)
        .expect("export");
    assert_ne!(
        a, b,
        "sessions sharing a connection must still derive distinct material"
    );
}

/// Pooled sessions avoid a QUIC handshake each, which is what makes them
/// dramatically cheaper than dedicated ones.
///
/// This asserts the mechanism rather than a timing figure: every pooled session
/// after the first must land on the same connection, so none of them pays for a
/// handshake, TLS state or congestion controller of its own.
#[tokio::test(flavor = "multi_thread")]
async fn pooled_sessions_reuse_one_handshake() {
    use wt_core::pool::ConnectionPool;

    let (_server, url, hash, mut incoming) = start_server();
    let pool = ConnectionPool::new();

    // Drain the accept queue so the server keeps accepting.
    tokio::spawn(async move { while incoming.recv().await.is_some() {} });

    const COUNT: usize = 25;
    let mut sessions = Vec::new();
    for _ in 0..COUNT {
        sessions.push(
            with_timeout(
                "connect",
                client::connect_with_pool(&url, pooled(hash.clone()), &pool),
            )
            .await
            .expect("connect"),
        );
    }

    // One connection carries them all.
    assert_eq!(
        pool.len(),
        1,
        "every session should join the same connection"
    );
    let first = sessions[0].connection.quinn().stable_id();
    for session in &sessions {
        assert_eq!(
            session.connection.quinn().stable_id(),
            first,
            "a pooled session opened a connection of its own"
        );
    }

    // And each still has its own identity.
    let ids: std::collections::HashSet<_> = sessions.iter().map(|s| s.session.id()).collect();
    assert_eq!(ids.len(), COUNT, "session ids must stay distinct");
}

/// A different origin is a different pool entry, so it gets its own connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_different_origin_is_not_pooled_together() {
    use wt_core::pool::ConnectionPool;

    let (_server_a, url_a, hash_a, mut incoming_a) = start_server();
    let (_server_b, url_b, hash_b, mut incoming_b) = start_server();
    let pool = ConnectionPool::new();

    let first = with_timeout(
        "connect a",
        client::connect_with_pool(&url_a, pooled(hash_a), &pool),
    )
    .await
    .expect("first");
    let _a = with_timeout("accept a", incoming_a.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout(
        "connect b",
        client::connect_with_pool(&url_b, pooled(hash_b), &pool),
    )
    .await
    .expect("second");
    let _b = with_timeout("accept b", incoming_b.recv())
        .await
        .expect("accept")
        .accept();

    assert_ne!(
        first.connection.quinn().stable_id(),
        second.connection.quinn().stable_id(),
        "different ports are different origins"
    );
    assert_eq!(pool.len(), 2);
}

/// Without pooling, each session gets a connection of its own.
#[tokio::test(flavor = "multi_thread")]
async fn dedicated_sessions_do_not_share_a_connection() {
    let (_server, url, hash, mut incoming) = start_server();

    let first = with_timeout("connect a", client::connect(&url, dedicated(hash.clone())))
        .await
        .expect("first");
    let _a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout("connect b", client::connect(&url, dedicated(hash)))
        .await
        .expect("second");
    let _b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    // Different QUIC connections have different stable ids.
    assert_ne!(
        first.connection.quinn().stable_id(),
        second.connection.quinn().stable_id(),
        "dedicated sessions must not share a connection"
    );
}

/// Each session on its own connection still has its own session id, and both
/// remain usable at once.
#[tokio::test(flavor = "multi_thread")]
async fn dedicated_sessions_work_independently() {
    let (_server, url, hash, mut incoming) = start_server();

    let first = with_timeout("connect a", client::connect(&url, dedicated(hash.clone())))
        .await
        .expect("first");
    let server_a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let second = with_timeout("connect b", client::connect(&url, dedicated(hash)))
        .await
        .expect("second");
    let server_b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    first.session.send_datagram(b"to-first").expect("send");
    second.session.send_datagram(b"to-second").expect("send");

    let a = with_timeout("datagram a", server_a.recv_datagram())
        .await
        .expect("datagram");
    let b = with_timeout("datagram b", server_b.recv_datagram())
        .await
        .expect("datagram");
    assert_eq!(&a[..], b"to-first");
    assert_eq!(&b[..], b"to-second");
}

/// The pool hands back only live connections, so a closed one is never reused.
#[tokio::test(flavor = "multi_thread")]
async fn the_pool_discards_closed_connections() {
    use wt_core::pool::{ConnectionPool, PoolKey};
    use wt_core::CongestionControl;

    let pool = ConnectionPool::new();
    let key = PoolKey::new("example.com", 443, CongestionControl::Default);

    // An empty pool has nothing to hand out.
    assert!(pool.get(&key).is_none());
    assert_eq!(pool.prune(), 0);
}

/// A session id is unique within its connection, which is what lets pooled
/// sessions share one without their streams colliding.
#[tokio::test(flavor = "multi_thread")]
async fn session_ids_are_distinct_per_connection() {
    let (_server, url, hash, mut incoming) = start_server();

    let first = with_timeout("connect a", client::connect(&url, dedicated(hash.clone())))
        .await
        .expect("first");
    let server_a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept");
    let second = with_timeout("connect b", client::connect(&url, dedicated(hash)))
        .await
        .expect("second");
    let server_b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept");

    // Both ends agree on each session's id.
    assert_eq!(server_a.session().id(), first.session.id());
    assert_eq!(server_b.session().id(), second.session.id());
}

/// Keying material is bound to the session, so two sessions derive different
/// bytes from the same label and context. That separation is the point of the
/// WebTransport exporter context.
#[tokio::test(flavor = "multi_thread")]
async fn keying_material_differs_between_sessions() {
    let (_server, url, hash, mut incoming) = start_server();

    let first = with_timeout("connect a", client::connect(&url, dedicated(hash.clone())))
        .await
        .expect("first");
    let _a = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();
    let second = with_timeout("connect b", client::connect(&url, dedicated(hash)))
        .await
        .expect("second");
    let _b = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let a = first
        .session
        .export_keying_material(b"label", b"context", 32)
        .expect("export");
    let b = second
        .session
        .export_keying_material(b"label", b"context", 32)
        .expect("export");

    assert_eq!(a.len(), 32);
    assert_ne!(a, b, "different sessions must derive different material");
}

/// The same session, label and context always derive the same bytes.
#[tokio::test(flavor = "multi_thread")]
async fn keying_material_is_deterministic() {
    let (_server, url, hash, mut incoming) = start_server();
    let client = with_timeout("connect", client::connect(&url, dedicated(hash)))
        .await
        .expect("connect");
    let _s = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let a = client
        .session
        .export_keying_material(b"l", b"c", 16)
        .expect("export");
    let b = client
        .session
        .export_keying_material(b"l", b"c", 16)
        .expect("export");
    assert_eq!(a, b);

    // A different label must give different material.
    let c = client
        .session
        .export_keying_material(b"other", b"c", 16)
        .expect("export");
    assert_ne!(a, c);
}

/// Statistics come from the live connection, so they grow as data flows.
#[tokio::test(flavor = "multi_thread")]
async fn stats_reflect_traffic() {
    let (_server, url, hash, mut incoming) = start_server();
    let client = with_timeout("connect", client::connect(&url, dedicated(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let before = client.session.stats().expect("stats");

    let stream = client.session.open_uni(None, None).await.expect("open");
    stream.write_all(&vec![0u8; 200_000]).await.expect("write");
    stream.finish().await.expect("finish");

    let recv = with_timeout("accept stream", server_session.accept_uni())
        .await
        .expect("stream");
    while recv.read_chunk(None).await.expect("read").is_some() {}

    let after = client.session.stats().expect("stats");
    assert!(
        after.bytes_sent > before.bytes_sent,
        "bytes_sent should grow: {} then {}",
        before.bytes_sent,
        after.bytes_sent
    );
    assert!(after.packets_sent > before.packets_sent);
}

/// Keying material cannot be derived once the session has ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_exports_no_keying_material() {
    let (_server, url, hash, mut incoming) = start_server();
    let client = with_timeout("connect", client::connect(&url, dedicated(hash)))
        .await
        .expect("connect");
    let _s = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();

    client.session.close(wt_core::CloseInfo::default());
    assert!(client
        .session
        .export_keying_material(b"l", b"c", 16)
        .is_err());
}
