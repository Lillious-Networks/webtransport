//! WebTransport capsules (draft-ietf-webtrans-http3-13 §5, §6) in the Capsule
//! Protocol framing of RFC 9297 §3.2: `Type (i), Length (i), Value (..)`.

use crate::varint::{self, VarIntError};
use bytes::{Buf, BufMut, Bytes};

pub mod ty {
    pub const CLOSE_SESSION: u64 = 0x2843;
    pub const DRAIN_SESSION: u64 = 0x78ae;
    pub const MAX_STREAMS_BIDI: u64 = 0x190b_4d3f;
    pub const MAX_STREAMS_UNI: u64 = 0x190b_4d40;
    pub const MAX_DATA: u64 = 0x190b_4d3d;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x190b_4d43;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x190b_4d44;
    pub const DATA_BLOCKED: u64 = 0x190b_4d41;
}

/// Longest close reason a peer may send (draft §6: 1024 bytes of UTF-8).
pub const MAX_CLOSE_REASON_LEN: usize = 1024;

/// Cap on a single buffered capsule, guarding against a hostile length.
const MAX_CAPSULE_LEN: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    CloseSession {
        code: u32,
        reason: String,
    },
    DrainSession,
    MaxStreams {
        dir: Dir,
        max: u64,
    },
    MaxData {
        max: u64,
    },
    StreamsBlocked {
        dir: Dir,
        limit: u64,
    },
    DataBlocked {
        limit: u64,
    },
    /// A capsule type we do not implement. Per RFC 9297 unknown capsules are
    /// skipped, so it is carried rather than treated as an error.
    Unknown {
        ty: u64,
        payload: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Bi,
    Uni,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CapsuleError {
    #[error("malformed varint: {0}")]
    VarInt(#[from] VarIntError),
    #[error("capsule payload is truncated")]
    Truncated,
    #[error("capsule length {0} exceeds what this endpoint will buffer")]
    TooLong(u64),
    #[error("close reason is not valid UTF-8")]
    InvalidReason,
    #[error("close reason of {0} bytes exceeds the 1024-byte limit")]
    ReasonTooLong(usize),
    #[error("{0} capsule has a malformed payload")]
    MalformedPayload(&'static str),
}

impl Capsule {
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), CapsuleError> {
        let mut payload = Vec::new();
        let ty = match self {
            Capsule::CloseSession { code, reason } => {
                if reason.len() > MAX_CLOSE_REASON_LEN {
                    return Err(CapsuleError::ReasonTooLong(reason.len()));
                }
                payload.put_u32(*code);
                payload.put_slice(reason.as_bytes());
                ty::CLOSE_SESSION
            }
            Capsule::DrainSession => ty::DRAIN_SESSION,
            Capsule::MaxStreams { dir, max } => {
                varint::encode(&mut payload, *max)?;
                match dir {
                    Dir::Bi => ty::MAX_STREAMS_BIDI,
                    Dir::Uni => ty::MAX_STREAMS_UNI,
                }
            }
            Capsule::MaxData { max } => {
                varint::encode(&mut payload, *max)?;
                ty::MAX_DATA
            }
            Capsule::StreamsBlocked { dir, limit } => {
                varint::encode(&mut payload, *limit)?;
                match dir {
                    Dir::Bi => ty::STREAMS_BLOCKED_BIDI,
                    Dir::Uni => ty::STREAMS_BLOCKED_UNI,
                }
            }
            Capsule::DataBlocked { limit } => {
                varint::encode(&mut payload, *limit)?;
                ty::DATA_BLOCKED
            }
            Capsule::Unknown { ty, payload: p } => {
                payload.extend_from_slice(p);
                *ty
            }
        };
        varint::encode(buf, ty)?;
        varint::encode(buf, payload.len() as u64)?;
        buf.put_slice(&payload);
        Ok(())
    }

    /// Decodes one capsule, consuming it from `buf`.
    ///
    /// Returns `Ok(None)` when `buf` holds only part of a capsule; `buf` is left
    /// untouched so the caller can retry once more bytes arrive.
    pub fn decode(buf: &mut Bytes) -> Result<Option<Self>, CapsuleError> {
        let mut probe = buf.clone();
        let ty = match varint::decode(&mut probe) {
            Ok(v) => v,
            Err(VarIntError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let len = match varint::decode(&mut probe) {
            Ok(v) => v,
            Err(VarIntError::UnexpectedEnd) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if len > MAX_CAPSULE_LEN {
            return Err(CapsuleError::TooLong(len));
        }
        let len = len as usize;
        if probe.remaining() < len {
            return Ok(None);
        }
        let payload = probe.split_to(len);
        *buf = probe;
        Self::from_parts(ty, payload).map(Some)
    }

    fn from_parts(ty: u64, mut payload: Bytes) -> Result<Self, CapsuleError> {
        // Reads the single varint that most flow-control capsules carry, and
        // rejects trailing junk rather than ignoring it.
        let sole_varint = |p: &mut Bytes, what: &'static str| -> Result<u64, CapsuleError> {
            let v = varint::decode(p).map_err(|_| CapsuleError::MalformedPayload(what))?;
            if p.has_remaining() {
                return Err(CapsuleError::MalformedPayload(what));
            }
            Ok(v)
        };

        Ok(match ty {
            ty::CLOSE_SESSION => {
                // An empty payload is the "code 0, no reason" close.
                if payload.is_empty() {
                    return Ok(Capsule::CloseSession {
                        code: 0,
                        reason: String::new(),
                    });
                }
                if payload.remaining() < 4 {
                    return Err(CapsuleError::Truncated);
                }
                let code = payload.get_u32();
                if payload.remaining() > MAX_CLOSE_REASON_LEN {
                    return Err(CapsuleError::ReasonTooLong(payload.remaining()));
                }
                let reason =
                    String::from_utf8(payload.to_vec()).map_err(|_| CapsuleError::InvalidReason)?;
                Capsule::CloseSession { code, reason }
            }
            ty::DRAIN_SESSION => Capsule::DrainSession,
            ty::MAX_STREAMS_BIDI => Capsule::MaxStreams {
                dir: Dir::Bi,
                max: sole_varint(&mut payload, "WT_MAX_STREAMS")?,
            },
            ty::MAX_STREAMS_UNI => Capsule::MaxStreams {
                dir: Dir::Uni,
                max: sole_varint(&mut payload, "WT_MAX_STREAMS")?,
            },
            ty::MAX_DATA => Capsule::MaxData {
                max: sole_varint(&mut payload, "WT_MAX_DATA")?,
            },
            ty::STREAMS_BLOCKED_BIDI => Capsule::StreamsBlocked {
                dir: Dir::Bi,
                limit: sole_varint(&mut payload, "WT_STREAMS_BLOCKED")?,
            },
            ty::STREAMS_BLOCKED_UNI => Capsule::StreamsBlocked {
                dir: Dir::Uni,
                limit: sole_varint(&mut payload, "WT_STREAMS_BLOCKED")?,
            },
            ty::DATA_BLOCKED => Capsule::DataBlocked {
                limit: sole_varint(&mut payload, "WT_DATA_BLOCKED")?,
            },
            other => Capsule::Unknown { ty: other, payload },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn round_trip(c: &Capsule) -> Capsule {
        let mut buf = BytesMut::new();
        c.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let out = Capsule::decode(&mut bytes)
            .unwrap()
            .expect("a whole capsule");
        assert!(bytes.is_empty(), "decode must consume exactly one capsule");
        out
    }

    #[test]
    fn every_capsule_round_trips() {
        for c in [
            Capsule::CloseSession {
                code: 0,
                reason: String::new(),
            },
            Capsule::CloseSession {
                code: 42,
                reason: "bye".into(),
            },
            Capsule::CloseSession {
                code: u32::MAX,
                reason: "non-ascii \u{2202}".into(),
            },
            Capsule::DrainSession,
            Capsule::MaxStreams {
                dir: Dir::Bi,
                max: 100,
            },
            Capsule::MaxStreams {
                dir: Dir::Uni,
                max: 0,
            },
            Capsule::MaxData { max: 1 << 40 },
            Capsule::StreamsBlocked {
                dir: Dir::Bi,
                limit: 7,
            },
            Capsule::StreamsBlocked {
                dir: Dir::Uni,
                limit: 7,
            },
            Capsule::DataBlocked { limit: 99 },
        ] {
            assert_eq!(round_trip(&c), c, "round-trip failed for {c:?}");
        }
    }

    /// Wire layout is fixed by the draft: type, length, then a 32-bit code
    /// followed by the reason with no length prefix of its own.
    #[test]
    fn close_session_wire_layout() {
        let mut buf = BytesMut::new();
        Capsule::CloseSession {
            code: 1,
            reason: "hi".into(),
        }
        .encode(&mut buf)
        .unwrap();
        assert_eq!(&buf[..], &[0x68, 0x43, 0x06, 0, 0, 0, 1, b'h', b'i'][..]);
    }

    #[test]
    fn drain_session_carries_no_payload() {
        let mut buf = BytesMut::new();
        Capsule::DrainSession.encode(&mut buf).unwrap();
        assert_eq!(&buf[..], &[0x80, 0x00, 0x78, 0xae, 0x00][..]);
    }

    #[test]
    fn bidi_and_uni_max_streams_are_distinct_types() {
        let (mut b, mut u) = (BytesMut::new(), BytesMut::new());
        Capsule::MaxStreams {
            dir: Dir::Bi,
            max: 1,
        }
        .encode(&mut b)
        .unwrap();
        Capsule::MaxStreams {
            dir: Dir::Uni,
            max: 1,
        }
        .encode(&mut u)
        .unwrap();
        assert_ne!(b, u);
    }

    /// Partial input must not consume the buffer, so a streaming caller can
    /// simply retry after more bytes arrive.
    #[test]
    fn partial_capsule_is_not_consumed() {
        let mut full = BytesMut::new();
        Capsule::CloseSession {
            code: 7,
            reason: "reason".into(),
        }
        .encode(&mut full)
        .unwrap();
        let full = full.freeze();
        for cut in 1..full.len() {
            let mut partial = full.slice(..cut);
            assert_eq!(Capsule::decode(&mut partial).unwrap(), None, "cut at {cut}");
            assert_eq!(partial.len(), cut, "failed decode consumed input at {cut}");
        }
        let mut whole = full.clone();
        assert!(Capsule::decode(&mut whole).unwrap().is_some());
    }

    #[test]
    fn decodes_a_stream_of_capsules_in_order() {
        let mut buf = BytesMut::new();
        Capsule::DrainSession.encode(&mut buf).unwrap();
        Capsule::MaxData { max: 5 }.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(
            Capsule::decode(&mut bytes).unwrap(),
            Some(Capsule::DrainSession)
        );
        assert_eq!(
            Capsule::decode(&mut bytes).unwrap(),
            Some(Capsule::MaxData { max: 5 })
        );
        assert_eq!(Capsule::decode(&mut bytes).unwrap(), None);
    }

    /// RFC 9297: unknown capsule types are skipped, not fatal.
    #[test]
    fn unknown_capsule_is_preserved_and_skipped() {
        let mut buf = BytesMut::new();
        Capsule::Unknown {
            ty: 0x3fff,
            payload: Bytes::from_static(b"xy"),
        }
        .encode(&mut buf)
        .unwrap();
        Capsule::DrainSession.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        assert_eq!(
            Capsule::decode(&mut bytes).unwrap(),
            Some(Capsule::Unknown {
                ty: 0x3fff,
                payload: Bytes::from_static(b"xy")
            })
        );
        assert_eq!(
            Capsule::decode(&mut bytes).unwrap(),
            Some(Capsule::DrainSession)
        );
    }

    #[test]
    fn rejects_invalid_utf8_reason() {
        // CLOSE_SESSION, length 5, code 0, then a lone continuation byte.
        let mut bytes = Bytes::from_static(&[0x68, 0x43, 0x05, 0, 0, 0, 0, 0xff]);
        assert_eq!(
            Capsule::decode(&mut bytes),
            Err(CapsuleError::InvalidReason)
        );
    }

    #[test]
    fn rejects_close_session_with_partial_error_code() {
        let mut bytes = Bytes::from_static(&[0x68, 0x43, 0x02, 0x00, 0x00]);
        assert_eq!(Capsule::decode(&mut bytes), Err(CapsuleError::Truncated));
    }

    #[test]
    fn rejects_oversized_close_reason() {
        let reason = "a".repeat(MAX_CLOSE_REASON_LEN + 1);
        let mut buf = BytesMut::new();
        let err = Capsule::CloseSession { code: 0, reason }
            .encode(&mut buf)
            .unwrap_err();
        assert_eq!(err, CapsuleError::ReasonTooLong(MAX_CLOSE_REASON_LEN + 1));
    }

    #[test]
    fn rejects_absurd_capsule_length() {
        // A valid type, then a length far beyond what we will buffer.
        let mut bytes = Bytes::from_static(&[
            0x80, 0x00, 0x78, 0xae, // DRAIN_SESSION
            0xc0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, // 8-byte varint length
        ]);
        assert!(matches!(
            Capsule::decode(&mut bytes),
            Err(CapsuleError::TooLong(_))
        ));
    }

    #[test]
    fn rejects_flow_control_capsule_with_trailing_bytes() {
        // MAX_DATA with a varint followed by an unexpected extra byte.
        let mut bytes = Bytes::from_static(&[0x99, 0x0b, 0x4d, 0x3d, 0x02, 0x05, 0x00]);
        assert!(matches!(
            Capsule::decode(&mut bytes),
            Err(CapsuleError::MalformedPayload(_))
        ));
    }
}
