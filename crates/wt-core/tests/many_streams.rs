//! Opening many streams on one session.
//!
//! WebTransport is meant to carry many concurrent streams; a session that
//! stalls after a few hundred would be unusable for its main use case.

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::Session;

const TIMEOUT: Duration = Duration::from_secs(30);

async fn with_timeout<T>(what: &str, fut: impl std::future::Future<Output = T>) -> T {
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(v) => v,
        Err(_) => panic!("timed out waiting for {what}"),
    }
}

async fn pair() -> (Server, client::ClientSession, Session) {
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
    let mut incoming = server.accept_sessions(16);
    let url = format!("https://localhost:{}/", addr.port());

    let options = ClientOptions {
        server_certificate_hashes: vec![CertHash {
            algorithm: HashAlgorithm::Sha256,
            value: hash,
        }],
        ..Default::default()
    };
    let client = with_timeout("connect", client::connect(&url, options))
        .await
        .expect("connect");
    let session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();
    tokio::spawn(async move {
        let mut incoming = incoming;
        while incoming.recv().await.is_some() {}
    });
    (server, client, session)
}

/// A session must sustain many concurrent streams without stalling.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_carries_a_thousand_streams() {
    let (_server, client, server_session) = pair().await;

    const COUNT: usize = 1000;

    // Drain on the server as streams arrive, so the client is never blocked by
    // an idle reader.
    let drainer = tokio::spawn(async move {
        let mut seen = 0usize;
        while seen < COUNT {
            let Some(recv) = server_session.accept_uni().await else {
                break;
            };
            seen += 1;
            tokio::spawn(
                async move { while recv.read_chunk(None).await.ok().flatten().is_some() {} },
            );
        }
        seen
    });

    for i in 0..COUNT {
        let stream = with_timeout("open", client.session.open_uni(None, None))
            .await
            .unwrap_or_else(|e| panic!("failed to open stream {i}: {e}"));
        stream.write_all(&[0u8; 64]).await.expect("write");
        stream.finish().await.expect("finish");
    }

    let seen = with_timeout("drain", drainer).await.expect("drainer");
    assert_eq!(seen, COUNT, "every stream should reach the server");
}

/// Streams held open concurrently must not exhaust the peer's limit.
///
/// quinn defaults to 100 concurrent streams per direction, and exceeding it
/// stalls the opener until the whole connection times out, so a session would
/// die at around a hundred held-open streams, which is well within ordinary
/// WebTransport use.
#[tokio::test(flavor = "multi_thread")]
async fn many_streams_can_be_held_open_at_once() {
    let (_server, client, server_session) = pair().await;

    const COUNT: usize = 500;

    // Accept on the server but never finish, so every stream stays open.
    let accepted = tokio::spawn(async move {
        let mut held = Vec::new();
        while held.len() < COUNT {
            let Some(recv) = server_session.accept_uni().await else {
                break;
            };
            held.push(recv);
        }
        held.len()
    });

    let mut held = Vec::new();
    for i in 0..COUNT {
        let stream = with_timeout("open", client.session.open_uni(None, None))
            .await
            .unwrap_or_else(|e| panic!("could not open stream {i} of {COUNT}: {e}"));
        stream.write_all(&[0u8; 16]).await.expect("write");
        // Deliberately not finished: the stream stays open and counts against
        // the concurrency limit.
        held.push(stream);
    }

    assert_eq!(held.len(), COUNT);
    let seen = with_timeout("accept", accepted).await.expect("accept task");
    assert_eq!(
        seen, COUNT,
        "every held-open stream should reach the server"
    );
}

/// With `wait_until_available` false, exhausting the limit fails promptly
/// rather than stalling until the connection times out.
#[tokio::test(flavor = "multi_thread")]
async fn opening_without_waiting_fails_rather_than_hanging() {
    let (_server, client, _server_session) = pair().await;

    // Far beyond the configured limit, never accepted on the far side, so the
    // limit is certain to be reached.
    let mut held = Vec::new();
    let mut refused = false;
    for _ in 0..(wt_core::client::DEFAULT_MAX_CONCURRENT_STREAMS as usize + 50) {
        match client.session.open_uni_with(None, None, false).await {
            Ok(stream) => held.push(stream),
            Err(wt_core::Error::StreamLimitReached) => {
                refused = true;
                break;
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert!(
        refused,
        "the stream limit should eventually refuse an opening"
    );
    // The session must survive: a refused stream is not a failed session.
    assert!(!client.session.state().is_terminal());
}

/// Streams opened concurrently must not deadlock against each other.
#[tokio::test(flavor = "multi_thread")]
async fn many_streams_can_be_opened_concurrently() {
    let (_server, client, server_session) = pair().await;

    const COUNT: usize = 200;

    let drainer = tokio::spawn(async move {
        let mut seen = 0usize;
        while seen < COUNT {
            let Some(recv) = server_session.accept_uni().await else {
                break;
            };
            seen += 1;
            tokio::spawn(
                async move { while recv.read_chunk(None).await.ok().flatten().is_some() {} },
            );
        }
        seen
    });

    let mut openers = Vec::new();
    for _ in 0..COUNT {
        let session = client.session.clone();
        openers.push(tokio::spawn(async move {
            let stream = session.open_uni(None, None).await.expect("open");
            stream.write_all(&[1u8; 64]).await.expect("write");
            stream.finish().await.expect("finish");
        }));
    }
    for opener in openers {
        with_timeout("opener", opener).await.expect("opener task");
    }

    let seen = with_timeout("drain", drainer).await.expect("drainer");
    assert_eq!(seen, COUNT);
}
