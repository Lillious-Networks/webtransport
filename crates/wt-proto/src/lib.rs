//! Pure WebTransport-over-HTTP/3 protocol logic.
//!
//! Built from [draft-ietf-webtrans-http3-13], RFC 9297 (HTTP Datagrams and the
//! Capsule Protocol) and RFC 9114 (HTTP/3). This crate performs no I/O and holds
//! no connection state: it encodes and decodes wire formats and answers
//! questions about them, so the parts most easily got wrong are testable without
//! a network.
//!
//! [draft-ietf-webtrans-http3-13]: https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/13/

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod capsule;
pub mod datagram;
pub mod error_code;
pub mod exporter;
pub mod frame;
pub mod huffman;
pub mod qpack;
pub mod scheduler;
pub mod settings;
pub mod stream_header;
pub mod varint;

pub use capsule::{Capsule, CapsuleError, Dir};

/// HTTP/3 error codes this implementation sends (RFC 9114 §8.1, draft §9.2).
pub mod h3_error {
    /// Peer violated the WebTransport protocol.
    pub const WEBTRANSPORT_BUFFERED_STREAM_REJECTED: u64 = 0x3994_bd84;
    /// The session a stream or datagram referred to is gone.
    pub const WEBTRANSPORT_SESSION_GONE: u64 = 0x170d_7b68;
}
