//! Perf probe: how fast do datagrams flow in pure Rust (no JS/napi)?
//!
//! A regression canary for the transport itself, run explicitly:
//!
//!   cargo test --release -p wt-core --test dg_throughput -- --ignored --nocapture

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};

const DURATION: Duration = Duration::from_secs(5);

#[tokio::test(flavor = "multi_thread")]
#[ignore = "throughput probe; run explicitly"]
async fn datagram_throughput_pure_rust() {
    let (chain, key, hash) = server::self_signed(&["localhost".into()]).expect("cert");
    let server = Server::bind(ServerConfig {
        addr: (Ipv4Addr::LOCALHOST, 0).into(),
        certificate_chain: chain,
        private_key: key,
        max_sessions: 4,
        max_concurrent_streams: None,
    })
    .expect("bind");
    let mut incoming = server.accept_sessions(8);
    let addr = server.local_addr().expect("addr");
    let url = format!("https://localhost:{}/", addr.port());

    let connected = client::connect(
        &url,
        ClientOptions {
            server_certificate_hashes: vec![CertHash {
                algorithm: HashAlgorithm::Sha256,
                value: hash,
            }],
            ..Default::default()
        },
    )
    .await
    .expect("connect");
    let server_session = incoming.recv().await.expect("accept").accept();

    let payload = vec![0x61u8; 24];
    let sender_session = connected.session.clone();
    let sender = tokio::spawn(async move {
        let mut sent: u64 = 0;
        let start = std::time::Instant::now();
        while start.elapsed() < DURATION {
            if sender_session.send_datagram(&payload).is_ok() {
                sent += 1;
            }
            // Yield so the connection's driver task also gets the lock: a
            // busy send loop would otherwise starve the actual IO.
            if sent % 256 == 0 {
                tokio::task::yield_now().await;
            }
        }
        sent
    });

    let mut received: u64 = 0;
    let start = std::time::Instant::now();
    while start.elapsed() < DURATION {
        if server_session.recv_datagram().await.is_some() {
            received += 1;
        }
    }

    let sent = sender.await.expect("sender");
    println!(
        "pure rust: sent {} in {:.1}s ({:.0}/s enqueued), server received {} ({:.0}/s, {:.1}% loss)",
        sent,
        DURATION.as_secs_f64(),
        sent as f64 / DURATION.as_secs_f64(),
        received,
        received as f64 / DURATION.as_secs_f64(),
        (1.0 - received as f64 / sent as f64) * 100.0,
    );
}
