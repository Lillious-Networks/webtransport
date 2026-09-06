//! Does connection churn retain memory in the engine, with no JS involved?
//!
//! This isolates a leak seen from Bun: if the working set grows here too, the
//! retention is in the Rust engine; if it stays flat, it is at the napi
//! boundary or in JS. Ignored by default because it measures process memory,
//! which is noisy under a parallel test run.

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::CloseInfo;

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

/// The process working set, in bytes.
fn working_set() -> u64 {
    std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-Process -Id {}).WorkingSet64", std::process::id()),
        ])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measures process memory; run with --ignored"]
async fn connection_churn_does_not_retain_memory() {
    let (_server, url, hash, mut incoming) = start_server();
    tokio::spawn(async move { while incoming.recv().await.is_some() {} });

    let base = working_set();
    for round in 1..=4 {
        for _ in 0..20 {
            let s = client::connect(&url, pinned(hash.clone()))
                .await
                .expect("connect");
            s.session.close(CloseInfo::default());
            drop(s);
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
        let grown = working_set().saturating_sub(base) as f64 / 1e6;
        println!(
            "round {round} ({} connections): {grown:.1}MB above baseline",
            round * 20
        );
        // A ceiling rather than an exact figure: the point is to catch a
        // return to the old behaviour, where the per-connection cost was so
        // large that 80 connections grew the working set past 200MB. The
        // headroom keeps allocator noise from failing the run.
        assert!(
            grown < 120.0,
            "80 connections should not retain {grown:.1}MB; per-connection state has regressed"
        );
    }
}
