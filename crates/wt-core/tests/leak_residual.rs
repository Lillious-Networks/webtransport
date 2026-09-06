//! Isolates what a connection retains once the stream limit is small.
//!
//! `leak_probe` showed per-connection cost scaling with the stream limit.
//! This holds that limit at its floor so anything still growing is a
//! different cause, and reports the slope rather than a total.

use std::net::Ipv4Addr;
use std::time::Duration;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::CloseInfo;

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
async fn residual_retention_per_connection() {
    let (chain, key, hash) = server::self_signed(&["localhost".into()]).expect("cert");
    let server = Server::bind(ServerConfig {
        addr: (Ipv4Addr::LOCALHOST, 0).into(),
        certificate_chain: chain,
        private_key: key,
        max_sessions: 4,
        // The floor: whatever still grows is not stream bookkeeping.
        max_concurrent_streams: Some(16),
    })
    .expect("bind");
    let addr = server.local_addr().expect("addr");
    let mut incoming = server.accept_sessions(64);
    tokio::spawn(async move { while incoming.recv().await.is_some() {} });
    let url = format!("https://localhost:{}/", addr.port());
    let pin = CertHash {
        algorithm: HashAlgorithm::Sha256,
        value: hash,
    };

    // Warm up so one-time allocations are not counted as growth.
    for _ in 0..20 {
        let s = client::connect(
            &url,
            ClientOptions {
                server_certificate_hashes: vec![pin.clone()],
                ..Default::default()
            },
        )
        .await
        .expect("connect");
        s.session.close(CloseInfo::default());
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    let base = working_set();
    for round in 1..=4 {
        for _ in 0..20 {
            let s = client::connect(
                &url,
                ClientOptions {
                    server_certificate_hashes: vec![pin.clone()],
                    ..Default::default()
                },
            )
            .await
            .expect("connect");
            s.session.close(CloseInfo::default());
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        let grown = working_set().saturating_sub(base) as f64 / 1e6;
        println!(
            "round {round} ({} connections past warmup): {grown:.1}MB, {:.0}KB per connection",
            round * 20,
            grown * 1000.0 / (round * 20) as f64
        );
    }
}
