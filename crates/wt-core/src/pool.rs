//! Connection pooling for `allowPooling`.
//!
//! With `allowPooling: false` (the spec's default, "yes-and-dedicated") every
//! session gets its own QUIC connection. With `allowPooling: true` a session may
//! share an existing connection to the same origin, which is why the wire format
//! scopes streams and datagrams by session id in the first place.
//!
//! Pooling and `serverCertificateHashes` are mutually exclusive: a pooled
//! connection's certificate was validated for whoever opened it, so a later
//! session cannot impose its own pin. The spec makes that a constructor throw,
//! enforced in the JS layer before anything reaches here.

use crate::connection::Connection;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What makes two sessions poolable: the same origin, reached the same way.
///
/// Congestion control is part of the key because it is chosen per connection,
/// so a session asking for different behaviour cannot reuse one configured
/// otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
    pub congestion_control: &'static str,
}

impl PoolKey {
    pub fn new(host: &str, port: u16, congestion_control: crate::CongestionControl) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
            congestion_control: match congestion_control {
                crate::CongestionControl::Default => "default",
                crate::CongestionControl::Throughput => "throughput",
                crate::CongestionControl::LowLatency => "low-latency",
            },
        }
    }
}

/// A connection available for pooling, plus the endpoint keeping it alive.
#[derive(Clone)]
pub struct PooledConnection {
    pub connection: Connection,
    pub endpoint: quinn::Endpoint,
    /// Streams the HTTP/3 layer must keep open for the connection's lifetime.
    pub keepalive: Arc<H3Streams>,
}

impl std::fmt::Debug for PooledConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledConnection")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

/// The HTTP/3 streams a connection must hold open (RFC 9114 §6.2.1).
pub struct H3Streams {
    pub _control: quinn::SendStream,
    pub _qpack_encoder: quinn::SendStream,
    pub _qpack_decoder: quinn::SendStream,
}

impl std::fmt::Debug for H3Streams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3Streams")
    }
}

/// Connections available for reuse, keyed by origin.
#[derive(Debug, Default)]
pub struct ConnectionPool {
    connections: Mutex<HashMap<PoolKey, PooledConnection>>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a usable pooled connection, if one exists.
    ///
    /// A connection that has since closed is dropped rather than handed out: a
    /// session opened on it would fail immediately.
    pub fn get(&self, key: &PoolKey) -> Option<PooledConnection> {
        let mut connections = self.connections.lock().unwrap();
        let pooled = connections.get(key)?;
        if pooled.connection.quinn().close_reason().is_some() {
            connections.remove(key);
            return None;
        }
        Some(pooled.clone())
    }

    /// Offers a connection for reuse by later sessions.
    pub fn insert(&self, key: PoolKey, pooled: PooledConnection) {
        self.connections.lock().unwrap().insert(key, pooled);
    }

    /// Forgets a connection, so no further session joins it.
    pub fn remove(&self, key: &PoolKey) {
        self.connections.lock().unwrap().remove(key);
    }

    /// Drops every closed connection, and reports how many remain.
    pub fn prune(&self) -> usize {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|_, pooled| pooled.connection.quinn().close_reason().is_none());
        connections.len()
    }

    pub fn len(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The process-wide pool. Pooling is only meaningful across separate
/// `connect` calls, so the pool has to outlive any one of them.
pub fn global() -> &'static ConnectionPool {
    static POOL: std::sync::OnceLock<ConnectionPool> = std::sync::OnceLock::new();
    POOL.get_or_init(ConnectionPool::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CongestionControl;

    #[test]
    fn the_same_origin_produces_the_same_key() {
        let a = PoolKey::new("example.com", 443, CongestionControl::Default);
        let b = PoolKey::new("example.com", 443, CongestionControl::Default);
        assert_eq!(a, b);
    }

    /// Host comparison is case-insensitive, so "Example.com" and "example.com"
    /// pool together as one origin.
    #[test]
    fn host_matching_ignores_case() {
        assert_eq!(
            PoolKey::new("Example.COM", 443, CongestionControl::Default),
            PoolKey::new("example.com", 443, CongestionControl::Default)
        );
    }

    #[test]
    fn a_different_port_is_a_different_origin() {
        assert_ne!(
            PoolKey::new("example.com", 443, CongestionControl::Default),
            PoolKey::new("example.com", 4433, CongestionControl::Default)
        );
    }

    /// Congestion control is chosen per connection, so a session wanting
    /// different behaviour must not reuse one configured otherwise.
    #[test]
    fn congestion_control_separates_pools() {
        assert_ne!(
            PoolKey::new("example.com", 443, CongestionControl::Default),
            PoolKey::new("example.com", 443, CongestionControl::LowLatency)
        );
        assert_ne!(
            PoolKey::new("example.com", 443, CongestionControl::Throughput),
            PoolKey::new("example.com", 443, CongestionControl::LowLatency)
        );
    }

    #[test]
    fn an_empty_pool_yields_nothing() {
        let pool = ConnectionPool::new();
        assert!(pool.is_empty());
        assert!(pool
            .get(&PoolKey::new(
                "example.com",
                443,
                CongestionControl::Default
            ))
            .is_none());
    }

    #[test]
    fn removing_a_key_empties_the_pool() {
        let pool = ConnectionPool::new();
        let key = PoolKey::new("example.com", 443, CongestionControl::Default);
        // Nothing to insert without a live connection, but removing an absent
        // key must be harmless.
        pool.remove(&key);
        assert!(pool.is_empty());
    }
}
