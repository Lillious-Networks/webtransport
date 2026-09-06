//! WebTransport datagram framing (draft §4.4, RFC 9297 §2.1).
//!
//! A QUIC DATAGRAM frame carrying WebTransport data starts with the Quarter
//! Stream ID (the CONNECT stream ID divided by four) which identifies the
//! session. The payload follows unmodified.
//!
//! Dividing by four is lossless here: CONNECT streams are client-initiated
//! bidirectional streams, whose IDs are always a multiple of four.

use crate::varint::{self, VarIntError};
use bytes::{BufMut, Bytes};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DatagramError {
    #[error("malformed quarter stream id: {0}")]
    VarInt(#[from] VarIntError),
    #[error("session id {0} is not a client-initiated bidirectional stream id")]
    NotAConnectStream(u64),
    #[error("quarter stream id {0} is too large to name a stream")]
    QuarterIdTooLarge(u64),
}

/// Converts a CONNECT stream ID to the quarter stream ID used on the wire.
pub fn quarter_id(session_id: u64) -> Result<u64, DatagramError> {
    // Client-initiated bidirectional stream IDs have their low two bits clear.
    if session_id % 4 != 0 {
        return Err(DatagramError::NotAConnectStream(session_id));
    }
    Ok(session_id / 4)
}

/// Converts a wire quarter stream ID back to a CONNECT stream ID.
pub fn session_id(quarter: u64) -> Result<u64, DatagramError> {
    quarter
        .checked_mul(4)
        .filter(|id| *id <= varint::MAX)
        .ok_or(DatagramError::QuarterIdTooLarge(quarter))
}

/// Number of bytes [`encode`] prepends for `session_id`.
pub fn header_len(session_id: u64) -> Result<usize, DatagramError> {
    Ok(varint::encoded_len(quarter_id(session_id)?))
}

/// Writes the quarter stream ID followed by `payload`.
pub fn encode<B: BufMut>(
    buf: &mut B,
    session_id: u64,
    payload: &[u8],
) -> Result<(), DatagramError> {
    varint::encode(buf, quarter_id(session_id)?)?;
    buf.put_slice(payload);
    Ok(())
}

/// Splits a received QUIC datagram into its session ID and payload.
///
/// The payload is a zero-copy slice of `datagram`.
pub fn decode(mut datagram: Bytes) -> Result<(u64, Bytes), DatagramError> {
    let quarter = varint::decode(&mut datagram)?;
    Ok((session_id(quarter)?, datagram))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn round_trips_through_the_wire_format() {
        for id in [0u64, 4, 8, 400, 4 * 0x3fff, 4 * 0x4000] {
            let mut buf = BytesMut::new();
            encode(&mut buf, id, b"payload").unwrap();
            let (got_id, payload) = decode(buf.freeze()).unwrap();
            assert_eq!(got_id, id);
            assert_eq!(&payload[..], b"payload");
        }
    }

    /// Session 0 is the common case and must cost exactly one header byte.
    #[test]
    fn session_zero_costs_one_byte() {
        let mut buf = BytesMut::new();
        encode(&mut buf, 0, b"hi").unwrap();
        assert_eq!(&buf[..], &[0x00, b'h', b'i'][..]);
        assert_eq!(header_len(0).unwrap(), 1);
    }

    #[test]
    fn quarter_id_divides_by_four() {
        assert_eq!(quarter_id(0).unwrap(), 0);
        assert_eq!(quarter_id(4).unwrap(), 1);
        assert_eq!(quarter_id(400).unwrap(), 100);
        assert_eq!(session_id(100).unwrap(), 400);
    }

    /// Only client-initiated bidirectional streams (id % 4 == 0) can carry a
    /// session, so anything else is a programming error rather than wire data.
    #[test]
    fn rejects_non_connect_stream_ids() {
        for id in [1u64, 2, 3, 5, 6, 7] {
            assert_eq!(quarter_id(id), Err(DatagramError::NotAConnectStream(id)));
        }
    }

    #[test]
    fn empty_payload_is_valid() {
        let mut buf = BytesMut::new();
        encode(&mut buf, 4, b"").unwrap();
        let (id, payload) = decode(buf.freeze()).unwrap();
        assert_eq!(id, 4);
        assert!(payload.is_empty());
    }

    #[test]
    fn payload_is_returned_unmodified() {
        // A payload whose leading bytes look like a varint must not be reparsed.
        let raw = &[0xc0u8, 0x01, 0x02, 0xff];
        let mut buf = BytesMut::new();
        encode(&mut buf, 4, raw).unwrap();
        let (_, payload) = decode(buf.freeze()).unwrap();
        assert_eq!(&payload[..], raw);
    }

    #[test]
    fn rejects_empty_datagram() {
        assert!(matches!(
            decode(Bytes::new()),
            Err(DatagramError::VarInt(_))
        ));
    }

    #[test]
    fn rejects_quarter_id_that_cannot_name_a_stream() {
        let huge = varint::MAX;
        assert_eq!(
            session_id(huge),
            Err(DatagramError::QuarterIdTooLarge(huge))
        );
    }

    #[test]
    fn header_len_matches_encoded_output() {
        for id in [0u64, 4, 4 * 64, 4 * 16384, 4 * 0x4000_0000] {
            let mut buf = BytesMut::new();
            encode(&mut buf, id, b"").unwrap();
            assert_eq!(header_len(id).unwrap(), buf.len(), "for session {id}");
        }
    }
}
