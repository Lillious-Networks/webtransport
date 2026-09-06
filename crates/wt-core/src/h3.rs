//! The HTTP/3 layer WebTransport needs, over quinn.
//!
//! This replaces the `h3` crate. h3 0.0.8 cannot host WebTransport streams: it
//! consumes incoming unidirectional streams into a private buffer we cannot
//! reach, and its client rejects incoming bidirectional streams outright with
//! H3_STREAM_CREATION_ERROR. Since WebTransport's whole point is carrying those
//! streams, the HTTP/3 layer has to leave them to us.
//!
//! Only what session establishment requires is implemented: the control stream
//! with SETTINGS, the QPACK streams (kept at zero capacity so neither side uses
//! a dynamic table), and extended CONNECT on a request stream. Everything else
//! an HTTP/3 endpoint might do is out of scope, because WebTransport never needs
//! it.

use crate::error::{Error, Result};
use bytes::{Bytes, BytesMut};
use wt_proto::frame::{stream_type, Frame};
use wt_proto::settings::Settings;
use wt_proto::{qpack, varint};

/// Opens the control stream and sends our SETTINGS.
///
/// RFC 9114 §6.2.1: the control stream is unidirectional, starts with its stream
/// type, and carries SETTINGS as its first frame.
pub async fn open_control_stream(
    conn: &quinn::Connection,
    settings: Settings,
) -> Result<quinn::SendStream> {
    let mut stream = conn
        .open_uni()
        .await
        .map_err(|e| Error::Connect(format!("could not open the control stream: {e}")))?;

    let mut buf = Vec::new();
    varint::encode(&mut buf, stream_type::CONTROL).map_err(|e| Error::Protocol(e.to_string()))?;
    Frame::Settings(settings)
        .encode(&mut buf)
        .map_err(|e| Error::Protocol(e.to_string()))?;

    use tokio::io::AsyncWriteExt;
    stream
        .write_all(&buf)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    stream.flush().await.map_err(|e| Error::Io(e.to_string()))?;
    Ok(stream)
}

/// Opens the QPACK encoder and decoder streams.
///
/// Both stay empty. Announcing them is mandatory (RFC 9204 §4.2) even when the
/// dynamic table is never used, and a peer that sees no insertions will not
/// reference one.
pub async fn open_qpack_streams(
    conn: &quinn::Connection,
) -> Result<(quinn::SendStream, quinn::SendStream)> {
    use tokio::io::AsyncWriteExt;
    let mut streams = Vec::new();
    for ty in [stream_type::QPACK_ENCODER, stream_type::QPACK_DECODER] {
        let mut stream = conn
            .open_uni()
            .await
            .map_err(|e| Error::Connect(format!("could not open a QPACK stream: {e}")))?;
        let mut buf = Vec::new();
        varint::encode(&mut buf, ty).map_err(|e| Error::Protocol(e.to_string()))?;
        stream
            .write_all(&buf)
            .await
            .map_err(|e| Error::Io(e.to_string()))?;
        stream.flush().await.map_err(|e| Error::Io(e.to_string()))?;
        streams.push(stream);
    }
    let decoder = streams.pop().expect("two streams were opened");
    let encoder = streams.pop().expect("two streams were opened");
    Ok((encoder, decoder))
}

/// Reads the peer's SETTINGS from its control stream.
///
/// Returns the settings and the stream, which is kept open: closing the control
/// stream is a connection error (RFC 9114 §6.2.1).
pub async fn read_settings(mut stream: quinn::RecvStream) -> Result<(Settings, quinn::RecvStream)> {
    let mut buf = BytesMut::new();
    let mut chunk = [0u8; 1024];
    loop {
        let mut probe = buf.clone().freeze();
        match Frame::decode(&mut probe) {
            Ok(Some(Frame::Settings(settings))) => return Ok((settings, stream)),
            // RFC 9114: unknown frames before SETTINGS are ignored, but a peer
            // must send SETTINGS first, so keep reading rather than accepting.
            Ok(Some(_)) => {
                buf = BytesMut::from(&probe[..]);
                continue;
            }
            Ok(None) => {}
            Err(e) => return Err(Error::Protocol(e.to_string())),
        }
        match stream.read(&mut chunk).await {
            Ok(Some(0)) => continue,
            Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(None) => {
                return Err(Error::Protocol(
                    "the control stream ended before SETTINGS".into(),
                ))
            }
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
}

/// A request or response's header fields.
pub type Fields = Vec<(String, String)>;

/// Builds the extended CONNECT request fields (RFC 9220, draft §3.3).
pub fn connect_request_fields(
    authority: &str,
    path: &str,
    extra: &[(String, String)],
    protocols: &[String],
) -> Fields {
    let mut fields = vec![
        (":method".to_owned(), "CONNECT".to_owned()),
        (":protocol".to_owned(), "webtransport".to_owned()),
        (":scheme".to_owned(), "https".to_owned()),
        (":authority".to_owned(), authority.to_owned()),
        (":path".to_owned(), path.to_owned()),
    ];
    if !protocols.is_empty() {
        fields.push(("wt-available-protocols".to_owned(), protocols.join(", ")));
    }
    fields.extend(extra.iter().cloned());
    fields
}

/// Writes a HEADERS frame carrying `fields`.
pub async fn write_headers(stream: &mut quinn::SendStream, fields: &Fields) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let encoded = qpack::encode_field_section(fields);
    let mut buf = Vec::new();
    Frame::Headers(Bytes::from(encoded))
        .encode(&mut buf)
        .map_err(|e| Error::Protocol(e.to_string()))?;
    stream
        .write_all(&buf)
        .await
        .map_err(|e| Error::Io(e.to_string()))?;
    stream.flush().await.map_err(|e| Error::Io(e.to_string()))?;
    Ok(())
}

/// Reads a HEADERS frame given bytes already taken from the stream.
///
/// The demux consumes a stream's leading varint to classify it, so the frame
/// parser has to resume from what it left rather than from the stream's start.
pub async fn read_headers_resuming(
    stream: &mut quinn::RecvStream,
    first_type: u64,
    buffered: Bytes,
) -> Result<Fields> {
    let mut prefix = Vec::new();
    varint::encode(&mut prefix, first_type).map_err(|e| Error::Protocol(e.to_string()))?;
    prefix.extend_from_slice(&buffered);
    read_headers_from(stream, BytesMut::from(&prefix[..])).await
}

/// Reads the next HEADERS frame from a stream.
///
/// Reads a byte at a time once a frame header is in hand, so nothing beyond the
/// frame is consumed: on a CONNECT stream the bytes that follow belong to the
/// session's capsules.
pub async fn read_headers(stream: &mut quinn::RecvStream) -> Result<Fields> {
    read_headers_from(stream, BytesMut::new()).await
}

/// Reads a HEADERS frame, starting from bytes already buffered.
async fn read_headers_from(stream: &mut quinn::RecvStream, mut buf: BytesMut) -> Result<Fields> {
    let mut byte = [0u8; 1];
    loop {
        let mut probe = buf.clone().freeze();
        match Frame::decode(&mut probe) {
            Ok(Some(Frame::Headers(payload))) => {
                return qpack::decode_field_section(payload)
                    .map_err(|e| Error::Protocol(e.to_string()));
            }
            // Skip frames that are not HEADERS, as RFC 9114 requires.
            Ok(Some(_)) => {
                buf = BytesMut::from(&probe[..]);
                continue;
            }
            Ok(None) => {}
            Err(e) => return Err(Error::Protocol(e.to_string())),
        }
        match stream.read(&mut byte).await {
            Ok(Some(0)) => continue,
            Ok(Some(_)) => buf.extend_from_slice(&byte),
            Ok(None) => {
                return Err(Error::Protocol(
                    "the stream ended before a HEADERS frame".into(),
                ))
            }
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
}

/// Extracts the `:status` from a response's fields.
pub fn status_of(fields: &Fields) -> Option<u16> {
    fields
        .iter()
        .find(|(n, _)| n == ":status")
        .and_then(|(_, v)| v.parse().ok())
}

/// Finds a field by name, ignoring case.
pub fn field<'a>(fields: &'a Fields, name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Classifies an incoming unidirectional stream by its leading stream type.
///
/// Returns the type and the bytes already read past it, which matters for
/// WebTransport streams: the session id follows immediately and must not be
/// lost.
pub async fn read_stream_type(stream: &mut quinn::RecvStream) -> Result<(u64, Bytes)> {
    let mut buf = BytesMut::new();
    let mut byte = [0u8; 1];
    loop {
        let mut probe = buf.clone().freeze();
        match varint::decode(&mut probe) {
            Ok(ty) => return Ok((ty, probe)),
            Err(varint::VarIntError::UnexpectedEnd) => {}
            Err(e) => return Err(Error::Protocol(e.to_string())),
        }
        match stream.read(&mut byte).await {
            Ok(Some(0)) => continue,
            Ok(Some(_)) => buf.extend_from_slice(&byte),
            Ok(None) => return Err(Error::Protocol("the stream ended before its type".into())),
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
}

/// Reads the frame type introducing a bidirectional stream.
///
/// A WebTransport bidirectional stream starts with the WEBTRANSPORT_BIDI frame
/// type followed by the session id (draft §4.3), so the caller distinguishes a
/// session stream from an ordinary HTTP/3 request by this value.
pub async fn peek_bidi_frame_type(stream: &mut quinn::RecvStream) -> Result<(u64, Bytes)> {
    read_stream_type(stream).await
}

/// Reads a varint from a buffer that may need topping up from the stream.
pub async fn read_varint(stream: &mut quinn::RecvStream, prefix: Bytes) -> Result<(u64, Bytes)> {
    let mut buf = BytesMut::from(&prefix[..]);
    let mut byte = [0u8; 1];
    loop {
        let mut probe = buf.clone().freeze();
        match varint::decode(&mut probe) {
            Ok(value) => return Ok((value, probe)),
            Err(varint::VarIntError::UnexpectedEnd) => {}
            Err(e) => return Err(Error::Protocol(e.to_string())),
        }
        match stream.read(&mut byte).await {
            Ok(Some(0)) => continue,
            Ok(Some(_)) => buf.extend_from_slice(&byte),
            Ok(None) => return Err(Error::Protocol("stream ended mid-varint".into())),
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_carries_the_extended_connect_pseudo_headers() {
        let fields = connect_request_fields("example.com:4433", "/chat", &[], &[]);
        assert_eq!(field(&fields, ":method"), Some("CONNECT"));
        assert_eq!(
            field(&fields, ":protocol"),
            Some("webtransport"),
            "extended CONNECT is selected by :protocol"
        );
        assert_eq!(field(&fields, ":scheme"), Some("https"));
        assert_eq!(field(&fields, ":authority"), Some("example.com:4433"));
        assert_eq!(field(&fields, ":path"), Some("/chat"));
    }

    #[test]
    fn application_headers_and_protocols_are_included() {
        let extra = vec![("x-token".to_owned(), "abc".to_owned())];
        let protocols = vec!["chat".to_owned(), "echo".to_owned()];
        let fields = connect_request_fields("h", "/", &extra, &protocols);
        assert_eq!(field(&fields, "x-token"), Some("abc"));
        assert_eq!(field(&fields, "wt-available-protocols"), Some("chat, echo"));
    }

    #[test]
    fn no_protocol_header_when_none_are_offered() {
        let fields = connect_request_fields("h", "/", &[], &[]);
        assert_eq!(field(&fields, "wt-available-protocols"), None);
    }

    /// The request must survive a QPACK round trip, since that is how it
    /// actually reaches the peer.
    #[test]
    fn the_request_survives_qpack() {
        let fields = connect_request_fields("example.com", "/x", &[], &[]);
        let encoded = qpack::encode_field_section(&fields);
        let decoded = qpack::decode_field_section(Bytes::from(encoded)).expect("decodes");
        assert_eq!(decoded, fields);
    }

    #[test]
    fn status_is_read_from_the_response() {
        assert_eq!(
            status_of(&vec![(":status".to_owned(), "200".to_owned())]),
            Some(200)
        );
        assert_eq!(status_of(&vec![]), None);
        assert_eq!(
            status_of(&vec![(":status".to_owned(), "nonsense".to_owned())]),
            None
        );
    }

    #[test]
    fn field_lookup_ignores_case() {
        let fields = vec![("X-Token".to_owned(), "v".to_owned())];
        assert_eq!(field(&fields, "x-token"), Some("v"));
        assert_eq!(field(&fields, "X-TOKEN"), Some("v"));
        assert_eq!(field(&fields, "other"), None);
    }
}
