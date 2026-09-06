//! WebTransport stream headers (draft §4.2, §4.3).
//!
//! A WebTransport stream is an HTTP/3 stream whose first bytes identify it as
//! belonging to a session. Unidirectional streams carry a stream type followed
//! by the session ID; bidirectional streams carry a frame type followed by the
//! session ID. In both cases the session ID is the CONNECT stream ID, and here it
//! is written whole, not quartered as in datagrams.

use crate::varint::{self, VarIntError};
use bytes::{BufMut, Bytes};

/// Stream type prefixing a WebTransport unidirectional stream.
pub const UNI_STREAM_TYPE: u64 = 0x54;
/// Frame type prefixing a WebTransport bidirectional stream.
pub const BIDI_FRAME_TYPE: u64 = 0x41;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Uni,
    Bidi,
}

impl StreamKind {
    const fn tag(self) -> u64 {
        match self {
            StreamKind::Uni => UNI_STREAM_TYPE,
            StreamKind::Bidi => BIDI_FRAME_TYPE,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StreamHeaderError {
    #[error("malformed varint: {0}")]
    VarInt(#[from] VarIntError),
    #[error("stream tag {0:#x} does not introduce a WebTransport stream")]
    NotWebTransport(u64),
}

/// Writes the header introducing a WebTransport stream for `session_id`.
pub fn encode<B: BufMut>(
    buf: &mut B,
    kind: StreamKind,
    session_id: u64,
) -> Result<(), StreamHeaderError> {
    varint::encode(buf, kind.tag())?;
    varint::encode(buf, session_id)?;
    Ok(())
}

/// Number of bytes [`encode`] writes.
pub fn encoded_len(kind: StreamKind, session_id: u64) -> usize {
    varint::encoded_len(kind.tag()) + varint::encoded_len(session_id)
}

/// Reads a stream header, returning the session it belongs to.
///
/// Returns `Ok(None)` if `buf` does not yet hold the whole header, leaving `buf`
/// unchanged so the caller can retry as bytes arrive.
pub fn decode(buf: &mut Bytes, kind: StreamKind) -> Result<Option<u64>, StreamHeaderError> {
    let mut probe = buf.clone();
    let tag = match varint::decode(&mut probe) {
        Ok(v) => v,
        Err(VarIntError::UnexpectedEnd) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if tag != kind.tag() {
        return Err(StreamHeaderError::NotWebTransport(tag));
    }
    let session_id = match varint::decode(&mut probe) {
        Ok(v) => v,
        Err(VarIntError::UnexpectedEnd) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    *buf = probe;
    Ok(Some(session_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn round_trips_both_kinds() {
        for kind in [StreamKind::Uni, StreamKind::Bidi] {
            for session in [0u64, 4, 400, 0x4000] {
                let mut buf = BytesMut::new();
                encode(&mut buf, kind, session).unwrap();
                assert_eq!(encoded_len(kind, session), buf.len());
                let mut bytes = buf.freeze();
                assert_eq!(decode(&mut bytes, kind).unwrap(), Some(session));
                assert!(
                    bytes.is_empty(),
                    "header decode must consume exactly the header"
                );
            }
        }
    }

    /// The session ID is written whole here, unlike the quartered form used in
    /// datagram framing. Guards against copying the datagram logic by mistake.
    #[test]
    fn session_id_is_not_quartered() {
        let mut buf = BytesMut::new();
        encode(&mut buf, StreamKind::Uni, 400).unwrap();
        // 0x54 as a two-byte varint, then 400 as a two-byte varint.
        assert_eq!(&buf[..], &[0x40, 0x54, 0x41, 0x90][..]);
    }

    #[test]
    fn uni_and_bidi_tags_differ() {
        let (mut u, mut b) = (BytesMut::new(), BytesMut::new());
        encode(&mut u, StreamKind::Uni, 4).unwrap();
        encode(&mut b, StreamKind::Bidi, 4).unwrap();
        assert_ne!(u, b);
    }

    #[test]
    fn payload_after_the_header_is_left_alone() {
        let mut buf = BytesMut::new();
        encode(&mut buf, StreamKind::Bidi, 4).unwrap();
        buf.put_slice(b"body");
        let mut bytes = buf.freeze();
        assert_eq!(decode(&mut bytes, StreamKind::Bidi).unwrap(), Some(4));
        assert_eq!(&bytes[..], b"body");
    }

    #[test]
    fn partial_header_is_not_consumed() {
        let mut full = BytesMut::new();
        encode(&mut full, StreamKind::Uni, 0x4000).unwrap();
        let full = full.freeze();
        for cut in 1..full.len() {
            let mut partial = full.slice(..cut);
            assert_eq!(
                decode(&mut partial, StreamKind::Uni).unwrap(),
                None,
                "cut at {cut}"
            );
            assert_eq!(partial.len(), cut, "failed decode consumed input at {cut}");
        }
    }

    #[test]
    fn rejects_a_stream_that_is_not_webtransport() {
        let mut bytes = Bytes::from_static(&[0x00, 0x04]);
        assert_eq!(
            decode(&mut bytes, StreamKind::Uni),
            Err(StreamHeaderError::NotWebTransport(0))
        );
    }

    /// A bidi frame tag on a uni stream is a protocol error, not a session.
    #[test]
    fn rejects_mismatched_kind() {
        let mut buf = BytesMut::new();
        encode(&mut buf, StreamKind::Bidi, 4).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(
            decode(&mut bytes, StreamKind::Uni),
            Err(StreamHeaderError::NotWebTransport(BIDI_FRAME_TYPE))
        );
    }
}
