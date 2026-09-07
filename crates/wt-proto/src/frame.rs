//! HTTP/3 frames and stream types (RFC 9114 §7), limited to what WebTransport
//! session establishment needs: SETTINGS on the control stream, and HEADERS on
//! the CONNECT stream.

use crate::settings::{self, Settings};
use crate::varint::{self, VarIntError};
use bytes::{Buf, BufMut, Bytes};

/// Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).
pub mod stream_type {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
    /// draft §4.2: a WebTransport unidirectional stream.
    pub const WEBTRANSPORT: u64 = 0x54;
}

/// Frame types (RFC 9114 §7.2).
pub mod frame_type {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0d;
    /// draft §4.3: introduces a WebTransport bidirectional stream.
    pub const WEBTRANSPORT_BIDI: u64 = 0x41;
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("malformed varint: {0}")]
    VarInt(#[from] VarIntError),
    #[error("frame length {0} exceeds what this endpoint will buffer")]
    TooLong(u64),
    #[error("SETTINGS payload is malformed")]
    MalformedSettings,
}

/// Cap on a single buffered frame, bounding what a peer can make us allocate.
const MAX_FRAME_LEN: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Settings(Settings),
    Headers(Bytes),
    Data(Bytes),
    /// A frame type we do not act on. RFC 9114 requires unknown frames to be
    /// ignored, so it is carried rather than treated as an error.
    Unknown {
        ty: u64,
        payload: Bytes,
    },
}

impl Frame {
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), FrameError> {
        match self {
            Frame::Settings(s) => {
                let mut payload = Vec::new();
                let mut put = |id: u64, value: u64| -> Result<(), FrameError> {
                    varint::encode(&mut payload, id)?;
                    varint::encode(&mut payload, value)?;
                    Ok(())
                };
                if s.enable_connect_protocol {
                    put(settings::ENABLE_CONNECT_PROTOCOL, 1)?;
                }
                // Sent even though the value is zero: the default is also
                // zero, but stating it tells the peer we will not resolve a
                // dynamic reference rather than leaving it to infer that.
                put(
                    settings::QPACK_MAX_TABLE_CAPACITY,
                    s.qpack_max_table_capacity,
                )?;
                put(settings::QPACK_BLOCKED_STREAMS, s.qpack_blocked_streams)?;
                if s.h3_datagram {
                    put(settings::H3_DATAGRAM, 1)?;
                }
                if s.wt_max_sessions > 0 {
                    // The draft-07 codepoint carries the real session limit
                    // and is the one spelling every shipped browser knows:
                    // Chromium's draft-07 client still sends it today, and
                    // Safari 26.x refuses the session before CONNECT when a
                    // server does not advertise it non-zero.
                    put(settings::WT_MAX_SESSIONS_DRAFT07, s.wt_max_sessions)?;
                    // quiche peers (Chromium and derivatives) negotiate
                    // WebTransport by version intersection, and the draft-02
                    // spelling of this setting is a boolean enable flag there:
                    // only 0 and 1 are accepted, and 1 is what enables draft-02
                    // on a client. Firefox (Neqo) knows no other codepoint.
                    // Omitting it leaves such a peer with an empty version
                    // intersection and the session fails with
                    // ERR_METHOD_NOT_SUPPORTED.
                    put(settings::WT_MAX_SESSIONS_DRAFT02, 1)?;
                    // The draft-13 spelling (0x14e9cd29) is deliberately not
                    // advertised: no shipped browser implements it, and Safari
                    // 26.x fails the handshake when it appears next to the
                    // draft-07 codepoint.
                }
                if s.wt_initial_max_data > 0 {
                    put(settings::WT_INITIAL_MAX_DATA, s.wt_initial_max_data)?;
                }
                if s.wt_initial_max_streams_uni > 0 {
                    put(
                        settings::WT_INITIAL_MAX_STREAMS_UNI,
                        s.wt_initial_max_streams_uni,
                    )?;
                }
                if s.wt_initial_max_streams_bidi > 0 {
                    put(
                        settings::WT_INITIAL_MAX_STREAMS_BIDI,
                        s.wt_initial_max_streams_bidi,
                    )?;
                }
                varint::encode(buf, frame_type::SETTINGS)?;
                varint::encode(buf, payload.len() as u64)?;
                buf.put_slice(&payload);
            }
            Frame::Headers(payload) => {
                varint::encode(buf, frame_type::HEADERS)?;
                varint::encode(buf, payload.len() as u64)?;
                buf.put_slice(payload);
            }
            Frame::Data(payload) => {
                varint::encode(buf, frame_type::DATA)?;
                varint::encode(buf, payload.len() as u64)?;
                buf.put_slice(payload);
            }
            Frame::Unknown { ty, payload } => {
                varint::encode(buf, *ty)?;
                varint::encode(buf, payload.len() as u64)?;
                buf.put_slice(payload);
            }
        }
        Ok(())
    }

    /// Decodes one frame, consuming it from `buf`.
    ///
    /// Returns `Ok(None)` when `buf` holds only part of a frame, leaving `buf`
    /// untouched so a streaming caller can retry.
    pub fn decode(buf: &mut Bytes) -> Result<Option<Self>, FrameError> {
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
        if len > MAX_FRAME_LEN {
            return Err(FrameError::TooLong(len));
        }
        if probe.remaining() < len as usize {
            return Ok(None);
        }
        let payload = probe.split_to(len as usize);
        *buf = probe;

        Ok(Some(match ty {
            frame_type::SETTINGS => {
                let mut settings = Settings::default();
                let mut p = payload;
                while p.has_remaining() {
                    let id = varint::decode(&mut p).map_err(|_| FrameError::MalformedSettings)?;
                    let value =
                        varint::decode(&mut p).map_err(|_| FrameError::MalformedSettings)?;
                    settings.apply(id, value);
                }
                Frame::Settings(settings)
            }
            frame_type::HEADERS => Frame::Headers(payload),
            frame_type::DATA => Frame::Data(payload),
            other => Frame::Unknown { ty: other, payload },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn round_trip(frame: &Frame) -> Frame {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        let out = Frame::decode(&mut bytes).unwrap().expect("a whole frame");
        assert!(bytes.is_empty(), "decode must consume exactly one frame");
        out
    }

    /// The SETTINGS a WebTransport endpoint advertises must survive the trip,
    /// since they are what tell the peer WebTransport is available at all.
    #[test]
    fn advertised_settings_round_trip() {
        let settings = Settings::advertised(16);
        let Frame::Settings(decoded) = round_trip(&Frame::Settings(settings)) else {
            panic!("expected SETTINGS");
        };
        assert!(decoded.accepts_webtransport());
        assert!(decoded.supports_datagrams());
        assert_eq!(decoded.wt_max_sessions, 16);
    }

    #[test]
    fn flow_control_settings_round_trip() {
        let mut settings = Settings::advertised(4);
        settings.wt_initial_max_data = 1 << 20;
        settings.wt_initial_max_streams_uni = 8;
        settings.wt_initial_max_streams_bidi = 16;
        let Frame::Settings(decoded) = round_trip(&Frame::Settings(settings)) else {
            panic!("expected SETTINGS");
        };
        assert_eq!(decoded.wt_initial_max_data, 1 << 20);
        assert_eq!(decoded.wt_initial_max_streams_uni, 8);
        assert_eq!(decoded.wt_initial_max_streams_bidi, 16);
    }

    #[test]
    fn headers_and_data_round_trip() {
        assert_eq!(
            round_trip(&Frame::Headers(Bytes::from_static(b"encoded"))),
            Frame::Headers(Bytes::from_static(b"encoded"))
        );
        assert_eq!(
            round_trip(&Frame::Data(Bytes::from_static(b"body"))),
            Frame::Data(Bytes::from_static(b"body"))
        );
    }

    #[test]
    fn empty_settings_are_valid() {
        let Frame::Settings(decoded) = round_trip(&Frame::Settings(Settings::default())) else {
            panic!("expected SETTINGS");
        };
        assert!(!decoded.accepts_webtransport());
    }

    /// RFC 9114: unknown frame types are ignored, not fatal.
    #[test]
    fn unknown_frames_are_preserved() {
        let frame = Frame::Unknown {
            ty: 0x21,
            payload: Bytes::from_static(b"xx"),
        };
        assert_eq!(round_trip(&frame), frame);
    }

    #[test]
    fn a_stream_of_frames_decodes_in_order() {
        let mut buf = BytesMut::new();
        Frame::Settings(Settings::advertised(1))
            .encode(&mut buf)
            .unwrap();
        Frame::Headers(Bytes::from_static(b"h"))
            .encode(&mut buf)
            .unwrap();
        let mut bytes = buf.freeze();
        assert!(matches!(
            Frame::decode(&mut bytes).unwrap(),
            Some(Frame::Settings(_))
        ));
        assert!(matches!(
            Frame::decode(&mut bytes).unwrap(),
            Some(Frame::Headers(_))
        ));
        assert_eq!(Frame::decode(&mut bytes).unwrap(), None);
    }

    #[test]
    fn partial_frames_are_not_consumed() {
        let mut full = BytesMut::new();
        Frame::Headers(Bytes::from_static(b"some headers"))
            .encode(&mut full)
            .unwrap();
        let full = full.freeze();
        for cut in 1..full.len() {
            let mut partial = full.slice(..cut);
            assert_eq!(Frame::decode(&mut partial).unwrap(), None, "cut at {cut}");
            assert_eq!(
                partial.len(),
                cut,
                "a failed decode consumed input at {cut}"
            );
        }
    }

    #[test]
    fn rejects_an_absurd_frame_length() {
        // HEADERS with an 8-byte length far beyond what we buffer.
        let mut bytes = Bytes::from_static(&[0x01, 0xc0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(
            Frame::decode(&mut bytes),
            Err(FrameError::TooLong(_))
        ));
    }

    #[test]
    fn rejects_malformed_settings() {
        // SETTINGS whose payload ends mid-pair.
        let mut bytes = Bytes::from_static(&[0x04, 0x01, 0x08]);
        assert_eq!(
            Frame::decode(&mut bytes),
            Err(FrameError::MalformedSettings)
        );
    }
}
