//! Errors crossing the session engine boundary.
//!
//! These map onto the spec's `WebTransportError`: `source` distinguishes a
//! stream failure from a session failure, and `streamErrorCode` carries the
//! peer's application code when there is one.

use wt_proto::capsule::CapsuleError;

/// Which layer a failure came from, matching `WebTransportErrorSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSource {
    Stream,
    Session,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the URL is not a valid https origin: {0}")]
    InvalidUrl(String),

    #[error("could not resolve {0}")]
    Dns(String),

    #[error("connection failed: {0}")]
    Connect(String),

    /// The server completed an HTTP/3 handshake but did not offer
    /// WebTransport, so no session can be opened on it.
    #[error("the server does not support WebTransport")]
    WebTransportUnsupported,

    /// The server answered the extended CONNECT request with a non-2xx status.
    #[error("the server rejected the session with HTTP status {0}")]
    SessionRejected(u16),

    #[error("the session is closed")]
    SessionClosed,

    /// The peer closed the session with a WT_CLOSE_SESSION capsule.
    #[error("the peer closed the session (code {code})")]
    ClosedByPeer { code: u32, reason: String },

    /// The peer reset a stream with an application error code.
    #[error("the peer reset the stream (code {0})")]
    StreamReset(u32),

    /// The peer stopped reading a stream we were writing.
    #[error("the peer stopped reading the stream (code {0})")]
    StreamStopped(u32),

    #[error("the stream is closed")]
    StreamClosed,

    /// The peer's concurrent-stream limit is exhausted and the caller asked not
    /// to wait for capacity.
    #[error("the peer's stream limit is reached")]
    StreamLimitReached,

    #[error("datagrams are not supported on this connection")]
    DatagramUnsupported,

    /// A datagram exceeded the path MTU and cannot be sent.
    #[error("datagram of {size} bytes exceeds the {max}-byte limit")]
    DatagramTooLarge { size: usize, max: usize },

    #[error("protocol violation: {0}")]
    Protocol(String),

    #[error(transparent)]
    Capsule(#[from] CapsuleError),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("{0}")]
    Io(String),
}

impl Error {
    /// Which `WebTransportError.source` this maps to.
    pub fn source_kind(&self) -> ErrorSource {
        match self {
            Error::StreamReset(_) | Error::StreamStopped(_) | Error::StreamClosed => {
                ErrorSource::Stream
            }
            _ => ErrorSource::Session,
        }
    }

    /// The peer's application error code, where the failure carries one.
    ///
    /// `None` for failures that are not a peer-signalled stream error, which
    /// the spec surfaces as a null `streamErrorCode`.
    pub fn stream_error_code(&self) -> Option<u32> {
        match self {
            Error::StreamReset(code) | Error::StreamStopped(code) => Some(*code),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Only peer-signalled stream failures are stream-sourced; everything else
    /// is a session failure, since the spec has no third category.
    #[test]
    fn stream_failures_are_stream_sourced() {
        for err in [
            Error::StreamReset(1),
            Error::StreamStopped(2),
            Error::StreamClosed,
        ] {
            assert_eq!(err.source_kind(), ErrorSource::Stream, "for {err:?}");
        }
    }

    #[test]
    fn connection_failures_are_session_sourced() {
        for err in [
            Error::SessionClosed,
            Error::WebTransportUnsupported,
            Error::SessionRejected(404),
            Error::ClosedByPeer {
                code: 0,
                reason: String::new(),
            },
            Error::DatagramUnsupported,
        ] {
            assert_eq!(err.source_kind(), ErrorSource::Session, "for {err:?}");
        }
    }

    #[test]
    fn only_peer_signalled_resets_carry_an_error_code() {
        assert_eq!(Error::StreamReset(7).stream_error_code(), Some(7));
        assert_eq!(Error::StreamStopped(9).stream_error_code(), Some(9));
        assert_eq!(Error::StreamClosed.stream_error_code(), None);
        assert_eq!(Error::SessionClosed.stream_error_code(), None);
    }

    /// A close code of 0 is a real code, not an absent one.
    #[test]
    fn zero_is_a_valid_stream_error_code() {
        assert_eq!(Error::StreamReset(0).stream_error_code(), Some(0));
    }
}
