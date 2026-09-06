//! Keying-material exporter context for WebTransport (draft §4.7).
//!
//! `exportKeyingMaterial` is not a raw RFC 5705 export. Because one QUIC
//! connection may carry several WebTransport sessions, the TLS label is fixed to
//! `EXPORTER-WebTransport` and the caller's label and context are nested inside a
//! struct that also carries the session ID. That keeps material derived for one
//! session separate from every other session on the same connection.
//!
//! ```text
//! WebTransport Exporter Context {
//!   WebTransport Session ID (64),
//!   Application-Supplied Exporter Label Length (8),
//!   Application-Supplied Exporter Label (8..),
//!   Application-Supplied Exporter Context Length (8),
//!   Application-Supplied Exporter Context (..)
//! }
//! ```

use bytes::BufMut;

/// The fixed TLS exporter label. The application's own label goes in the
/// context, never here.
pub const TLS_LABEL: &[u8] = b"EXPORTER-WebTransport";

/// Both nested fields carry an 8-bit length, so neither can exceed 255 bytes.
pub const MAX_FIELD_LEN: usize = u8::MAX as usize;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExporterError {
    #[error("exporter label is {0} bytes, which exceeds the 255-byte limit")]
    LabelTooLong(usize),
    #[error("exporter context is {0} bytes, which exceeds the 255-byte limit")]
    ContextTooLong(usize),
}

/// Builds the exporter context to pass to the TLS exporter alongside
/// [`TLS_LABEL`].
pub fn context(
    session_id: u64,
    label: &[u8],
    app_context: &[u8],
) -> Result<Vec<u8>, ExporterError> {
    if label.len() > MAX_FIELD_LEN {
        return Err(ExporterError::LabelTooLong(label.len()));
    }
    if app_context.len() > MAX_FIELD_LEN {
        return Err(ExporterError::ContextTooLong(app_context.len()));
    }
    let mut out = Vec::with_capacity(8 + 1 + label.len() + 1 + app_context.len());
    out.put_u64(session_id);
    out.put_u8(label.len() as u8);
    out.put_slice(label);
    out.put_u8(app_context.len() as u8);
    out.put_slice(app_context);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_session_id_then_length_prefixed_fields() {
        let out = context(1, b"ab", b"xyz").unwrap();
        assert_eq!(
            out,
            vec![0, 0, 0, 0, 0, 0, 0, 1, 2, b'a', b'b', 3, b'x', b'y', b'z']
        );
    }

    #[test]
    fn session_id_is_big_endian_64_bit() {
        let out = context(u64::MAX, b"", b"").unwrap();
        assert_eq!(&out[..8], &[0xff; 8]);
        assert_eq!(&out[8..], &[0, 0], "two empty length prefixes");
    }

    /// Different sessions must derive different material from the same
    /// application label and context. That separation is the whole point.
    #[test]
    fn distinct_sessions_produce_distinct_contexts() {
        assert_ne!(
            context(1, b"l", b"c").unwrap(),
            context(2, b"l", b"c").unwrap()
        );
    }

    /// Length prefixes must prevent a label/context split from being ambiguous:
    /// ("ab", "c") and ("a", "bc") are different contexts.
    #[test]
    fn field_boundaries_are_unambiguous() {
        assert_ne!(
            context(1, b"ab", b"c").unwrap(),
            context(1, b"a", b"bc").unwrap()
        );
    }

    #[test]
    fn accepts_maximum_length_fields() {
        let max = vec![b'x'; MAX_FIELD_LEN];
        let out = context(0, &max, &max).unwrap();
        assert_eq!(out.len(), 8 + 1 + MAX_FIELD_LEN + 1 + MAX_FIELD_LEN);
    }

    #[test]
    fn rejects_fields_that_cannot_be_length_prefixed() {
        let over = vec![b'x'; MAX_FIELD_LEN + 1];
        assert_eq!(
            context(0, &over, b""),
            Err(ExporterError::LabelTooLong(MAX_FIELD_LEN + 1))
        );
        assert_eq!(
            context(0, b"", &over),
            Err(ExporterError::ContextTooLong(MAX_FIELD_LEN + 1))
        );
    }
}
