//! WebTransport-over-HTTP/3 session engine, built directly on quinn.
//!
//! The HTTP/3 layer is ours ([`h3`]), not the `h3` crate. h3 0.0.8 cannot host
//! WebTransport: it swallows incoming unidirectional streams into a private
//! buffer, and its client rejects incoming bidirectional streams outright.
//! Since carrying those streams is the entire point, HTTP/3 had to be
//! implemented here: only the parts session establishment needs.

#![forbid(unsafe_code)]

pub mod capsules;
pub mod client;
pub mod connection;
pub mod error;
pub mod h3;
pub mod pool;
pub mod send_scheduler;
pub mod server;
pub mod session;
pub mod shutdown;
pub mod stream;
pub mod tls;

pub use client::{ClientOptions, ClientSession, CongestionControl};
pub use connection::Connection;
pub use error::{Error, ErrorSource, Result};
pub use send_scheduler::SendScheduler;
pub use server::{IncomingSession, Server, ServerConfig};
pub use session::{CloseInfo, Session, State};
pub use stream::{BidiStream, RecvStream, SendStream};
