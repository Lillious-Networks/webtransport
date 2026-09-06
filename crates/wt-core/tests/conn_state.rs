//! Does closing a session close the QUIC connection under it?

use std::net::Ipv4Addr;
use wt_core::client::{self, ClientOptions};
use wt_core::server::{self, Server, ServerConfig};
use wt_core::tls::{CertHash, HashAlgorithm};
use wt_core::CloseInfo;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "diagnostic"]
async fn closing_a_session_closes_its_connection() {
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
    let mut incoming = server.accept_sessions(8);
    tokio::spawn(async move { while incoming.recv().await.is_some() {} });

    let s = client::connect(
        &format!("https://localhost:{}/", addr.port()),
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

    let quinn_conn = s.connection.quinn().clone();
    println!(
        "before close: close_reason = {:?}",
        quinn_conn.close_reason()
    );
    s.session.close(CloseInfo::default());
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!(
        "after session.close(): close_reason = {:?}",
        quinn_conn.close_reason()
    );
    drop(s);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!(
        "after dropping ClientSession: close_reason = {:?}",
        quinn_conn.close_reason()
    );
}
