//! End-to-end stream tests over real loopback QUIC.

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::{Error, Session};

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
        max_sessions: 4,
        max_concurrent_streams: None,
    })
    .expect("bind");
    let addr = server.local_addr().expect("addr");
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

/// Connects a client and returns both ends of the session.
async fn pair() -> (Server, client::ClientSession, Session) {
    let (server, url, hash, mut incoming) = start_server();
    let client = with_timeout("connect", client::connect(&url, pinned(hash)))
        .await
        .expect("connect");
    let server_session = with_timeout("accept", incoming.recv())
        .await
        .expect("accept")
        .accept();
    // The receiver must stay alive or the server stops accepting; leak it into
    // a task that simply holds it.
    tokio::spawn(async move {
        let mut incoming = incoming;
        while incoming.recv().await.is_some() {}
    });
    (server, client, server_session)
}

/// Reads a stream to end of data.
async fn read_to_end(recv: &wt_core::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = recv.read_chunk(None).await.expect("read") {
        out.extend_from_slice(&chunk);
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_unidirectional_stream_carries_data_to_the_peer() {
    let (_server, client, server_session) = pair().await;

    let send = with_timeout("open uni", client.session.open_uni(None, None))
        .await
        .expect("open");
    send.write_all(b"hello over a stream").await.expect("write");
    send.finish().await.expect("finish");

    let recv = with_timeout("accept uni", server_session.accept_uni())
        .await
        .expect("a stream should arrive");
    assert_eq!(read_to_end(&recv).await, b"hello over a stream");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bidirectional_stream_carries_data_both_ways() {
    let (_server, client, server_session) = pair().await;

    let stream = with_timeout("open bi", client.session.open_bi(None, None))
        .await
        .expect("open");
    stream.send.write_all(b"ping").await.expect("write");
    stream.send.finish().await.expect("finish");

    let server_stream = with_timeout("accept bi", server_session.accept_bi())
        .await
        .expect("a stream should arrive");
    assert_eq!(read_to_end(&server_stream.recv).await, b"ping");

    server_stream.send.write_all(b"pong").await.expect("write");
    server_stream.send.finish().await.expect("finish");
    assert_eq!(read_to_end(&stream.recv).await, b"pong");
}

/// Streams opened by the server must reach the client, not only the reverse.
#[tokio::test(flavor = "multi_thread")]
async fn the_server_can_open_streams_to_the_client() {
    let (_server, client, server_session) = pair().await;

    let send = with_timeout("open uni", server_session.open_uni(None, None))
        .await
        .expect("open");
    send.write_all(b"server initiated").await.expect("write");
    send.finish().await.expect("finish");

    let recv = with_timeout("accept uni", client.session.accept_uni())
        .await
        .expect("a stream should arrive");
    assert_eq!(read_to_end(&recv).await, b"server initiated");
}

/// Data larger than a single packet must arrive whole and in order.
#[tokio::test(flavor = "multi_thread")]
async fn a_large_payload_arrives_intact() {
    let (_server, client, server_session) = pair().await;

    // A pattern rather than zeroes, so truncation or reordering is visible.
    let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();

    let send = with_timeout("open uni", client.session.open_uni(None, None))
        .await
        .expect("open");
    let to_send = payload.clone();
    let writer = tokio::spawn(async move {
        send.write_all(&to_send).await.expect("write");
        send.finish().await.expect("finish");
    });

    let recv = with_timeout("accept uni", server_session.accept_uni())
        .await
        .expect("stream");
    let received = with_timeout("read", read_to_end(&recv)).await;
    writer.await.expect("writer task");

    assert_eq!(received.len(), payload.len());
    assert_eq!(received, payload, "the payload must arrive byte for byte");
}

#[tokio::test(flavor = "multi_thread")]
async fn many_concurrent_streams_stay_distinct() {
    let (_server, client, server_session) = pair().await;

    const COUNT: usize = 20;
    for i in 0..COUNT {
        let send = client.session.open_uni(None, None).await.expect("open");
        send.write_all(format!("stream-{i}").as_bytes())
            .await
            .expect("write");
        send.finish().await.expect("finish");
    }

    let mut seen = std::collections::HashSet::new();
    for _ in 0..COUNT {
        let recv = with_timeout("accept", server_session.accept_uni())
            .await
            .expect("stream");
        seen.insert(String::from_utf8(read_to_end(&recv).await).expect("utf8"));
    }

    assert_eq!(seen.len(), COUNT, "every stream must arrive exactly once");
    for i in 0..COUNT {
        assert!(seen.contains(&format!("stream-{i}")), "missing stream-{i}");
    }
}

/// A reset must reach the reader as the peer's application error code, which
/// exercises the WebTransport<->HTTP/3 code remapping over the wire.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_reaches_the_reader_with_its_application_code() {
    let (_server, client, server_session) = pair().await;

    let stream = with_timeout("open bi", client.session.open_bi(None, None))
        .await
        .expect("open");
    stream.send.write_all(b"partial").await.expect("write");

    let server_stream = with_timeout("accept bi", server_session.accept_bi())
        .await
        .expect("stream");
    // Read the first chunk so the stream is established before the reset.
    let _ = with_timeout("first read", server_stream.recv.read_chunk(None)).await;

    stream.send.reset(4242).await.expect("reset");

    // Read until the reset surfaces; buffered data may be delivered first.
    let err = loop {
        match with_timeout("read", server_stream.recv.read_chunk(None)).await {
            Ok(Some(_)) => continue,
            Ok(None) => panic!("expected a reset, saw a clean end of stream"),
            Err(e) => break e,
        }
    };

    assert!(matches!(err, Error::StreamReset(4242)), "got {err:?}");
    assert_eq!(err.stream_error_code(), Some(4242));
}

/// Codes on either side of a reserved HTTP/3 codepoint must survive the round
/// trip, since those are exactly the values the mapping has to step over.
#[tokio::test(flavor = "multi_thread")]
async fn reset_codes_around_reserved_codepoints_round_trip() {
    for code in [0u32, 1, 0x1d, 0x1e, 0x1f, 0x3c, u32::MAX] {
        let (_server, client, server_session) = pair().await;
        let stream = with_timeout("open bi", client.session.open_bi(None, None))
            .await
            .expect("open");
        stream.send.write_all(b"x").await.expect("write");
        let server_stream = with_timeout("accept bi", server_session.accept_bi())
            .await
            .expect("stream");
        let _ = with_timeout("first read", server_stream.recv.read_chunk(None)).await;

        stream.send.reset(code).await.expect("reset");

        let err = loop {
            match with_timeout("read", server_stream.recv.read_chunk(None)).await {
                Ok(Some(_)) => continue,
                Ok(None) => panic!("expected a reset for code {code}"),
                Err(e) => break e,
            }
        };
        assert_eq!(
            err.stream_error_code(),
            Some(code),
            "code {code} did not survive the mapping"
        );
    }
}

/// Stopping a read tells the writer, with the code the reader chose.
#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_read_reaches_the_writer() {
    let (_server, client, server_session) = pair().await;

    let stream = with_timeout("open bi", client.session.open_bi(None, None))
        .await
        .expect("open");
    stream.send.write_all(b"data").await.expect("write");

    let server_stream = with_timeout("accept bi", server_session.accept_bi())
        .await
        .expect("stream");
    let _ = with_timeout("first read", server_stream.recv.read_chunk(None)).await;
    server_stream.recv.stop(99).await.expect("stop");

    // Writing until the stop is observed: the signal is asynchronous.
    let err = loop {
        match stream.send.write_all(&[0u8; 4096]).await {
            Ok(()) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(e) => break e,
        }
    };
    assert!(matches!(err, Error::StreamStopped(99)), "got {err:?}");
}

/// A clean finish is end-of-stream, not an error.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_stream_ends_cleanly() {
    let (_server, client, server_session) = pair().await;

    let send = with_timeout("open uni", client.session.open_uni(None, None))
        .await
        .expect("open");
    send.write_all(b"complete").await.expect("write");
    send.finish().await.expect("finish");

    let recv = with_timeout("accept uni", server_session.accept_uni())
        .await
        .expect("stream");
    let mut data = Vec::new();
    while let Some(chunk) = with_timeout("read", recv.read_chunk(None))
        .await
        .expect("no error")
    {
        data.extend_from_slice(&chunk);
    }
    assert_eq!(data, b"complete");
}

#[tokio::test(flavor = "multi_thread")]
async fn byte_counters_track_what_crossed_the_stream() {
    let (_server, client, server_session) = pair().await;

    let send = with_timeout("open uni", client.session.open_uni(None, None))
        .await
        .expect("open");
    send.write_all(&[0u8; 5000]).await.expect("write");
    send.finish().await.expect("finish");
    // The header is written before the application's bytes and must not be
    // counted against them.
    assert_eq!(send.bytes_written(), 5000);

    let recv = with_timeout("accept uni", server_session.accept_uni())
        .await
        .expect("stream");
    let received = read_to_end(&recv).await;
    assert_eq!(received.len(), 5000);
    assert_eq!(recv.bytes_read(), 5000);
}

/// Once a session is closed it cannot open new streams.
#[tokio::test(flavor = "multi_thread")]
async fn a_closed_session_cannot_open_streams() {
    let (_server, client, _server_session) = pair().await;

    client.session.close(wt_core::CloseInfo {
        code: 0,
        reason: String::new(),
    });
    let err = client.session.open_uni(None, None).await.unwrap_err();
    assert!(matches!(err, Error::SessionClosed), "got {err:?}");
}

/// A draining session still opens streams.
///
/// draft-ietf-webtrans-http3 §5: after sending or receiving WT_DRAIN_SESSION
/// an endpoint MAY continue using the session and MAY open new streams. The
/// capsule asks the peer to wind down; it does not close anything.
#[tokio::test(flavor = "multi_thread")]
async fn a_draining_session_can_still_open_streams() {
    let (_server, client, _server_session) = pair().await;

    client.session.drain();
    client
        .session
        .open_bi(None, None)
        .await
        .expect("draining must not stop a stream from opening");
}

/// Streams belong to a session: two sessions on one connection must not see
/// each other's streams.
#[tokio::test(flavor = "multi_thread")]
async fn streams_do_not_leak_between_sessions() {
    let (_server, url, hash, mut incoming) = start_server();

    let first = with_timeout("connect a", client::connect(&url, pinned(hash.clone())))
        .await
        .expect("first");
    let server_first = with_timeout("accept a", incoming.recv())
        .await
        .expect("accept")
        .accept();

    // Held alive: dropping the client session would close the connection and
    // make the no-leak assertion below trivially true.
    let _second = with_timeout("connect b", client::connect(&url, pinned(hash)))
        .await
        .expect("second");
    let server_second = with_timeout("accept b", incoming.recv())
        .await
        .expect("accept")
        .accept();

    let send = first.session.open_uni(None, None).await.expect("open");
    send.write_all(b"for the first session")
        .await
        .expect("write");
    send.finish().await.expect("finish");

    let recv = with_timeout("accept on first", server_first.accept_uni())
        .await
        .expect("stream");
    assert_eq!(read_to_end(&recv).await, b"for the first session");

    // The second session must not have received anything.
    let leaked = tokio::time::timeout(Duration::from_millis(300), server_second.accept_uni()).await;
    assert!(leaked.is_err(), "a stream leaked into the wrong session");
}
