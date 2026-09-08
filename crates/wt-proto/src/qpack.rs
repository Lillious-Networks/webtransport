//! Minimal QPACK (RFC 9204) for WebTransport's extended CONNECT exchange.
//!
//! WebTransport needs exactly one header exchange per session, so the dynamic
//! table earns nothing: we encode every field as a literal with a zero required
//! insert count, and decode static-table references plus literals. A peer that
//! sees our zero-capacity encoder stream will not send dynamic references, and
//! one that does anyway is reported rather than mis-decoded.
//!
//! Huffman-coded values are decoded in full (see [`crate::huffman`]): browsers
//! Huffman-code essentially every header, so a decoder without it cannot read a
//! real client at all. We do not Huffman-code what we send, which is legal and
//! costs only a few bytes per session.

use crate::varint::VarIntError;
use bytes::{Buf, BufMut, Bytes};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QpackError {
    #[error("field section is truncated")]
    Truncated,
    #[error("malformed integer: {0}")]
    VarInt(#[from] VarIntError),
    #[error("static table index {0} does not exist")]
    UnknownStaticIndex(u64),
    #[error("dynamic table references are not supported")]
    DynamicTableUnsupported,
    #[error("malformed Huffman coding: {0}")]
    Huffman(#[from] crate::huffman::HuffmanError),
    #[error("header value is not valid UTF-8")]
    InvalidUtf8,
    #[error("field section is larger than this endpoint accepts")]
    TooLarge,
}

/// Cap on a decoded field section, bounding what a peer can make us allocate.
const MAX_FIELD_SECTION: usize = 64 * 1024;

/// The QPACK static table (RFC 9204 Appendix A), all 99 entries.
///
/// A peer may index any of these, so a partial table would misdecode a
/// request rather than merely miss a compression opportunity.
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains",
    ),
    (
        "strict-transport-security",
        "max-age=31536000; includesubdomains; preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Looks up a static-table entry.
pub fn static_entry(index: u64) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE.get(index as usize).copied()
}

/// Finds a static index whose name and value both match.
fn find_static_pair(name: &str, value: &str) -> Option<usize> {
    STATIC_TABLE
        .iter()
        .position(|(n, v)| *n == name && *v == value)
}

/// Finds a static index matching just the name.
fn find_static_name(name: &str) -> Option<usize> {
    STATIC_TABLE.iter().position(|(n, _)| *n == name)
}

/// Writes a QPACK prefixed integer (RFC 9204 §4.1.1).
///
/// `prefix_bits` is how many low bits of the first byte carry the value;
/// `flags` supplies the high bits.
fn encode_prefixed_int<B: BufMut>(buf: &mut B, value: u64, prefix_bits: u8, flags: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        buf.put_u8(flags | value as u8);
        return;
    }
    buf.put_u8(flags | max as u8);
    let mut remainder = value - max;
    while remainder >= 128 {
        buf.put_u8((remainder % 128) as u8 + 128);
        remainder /= 128;
    }
    buf.put_u8(remainder as u8);
}

/// Reads a QPACK prefixed integer, given the already-consumed first byte.
fn decode_prefixed_int<B: Buf>(buf: &mut B, first: u8, prefix_bits: u8) -> Result<u64, QpackError> {
    let max = (1u64 << prefix_bits) - 1;
    let value = u64::from(first) & max;
    if value < max {
        return Ok(value);
    }
    let mut result = max;
    let mut shift = 0u32;
    loop {
        if !buf.has_remaining() {
            return Err(QpackError::Truncated);
        }
        let byte = buf.get_u8();
        result = result
            .checked_add(u64::from(byte & 0x7f) << shift)
            .ok_or(QpackError::TooLarge)?;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 62 {
            return Err(QpackError::TooLarge);
        }
    }
}

/// Writes a string literal, uncompressed.
fn encode_string<B: BufMut>(buf: &mut B, value: &str, prefix_bits: u8, flags: u8) {
    // The Huffman bit stays clear: we always emit raw bytes.
    encode_prefixed_int(buf, value.len() as u64, prefix_bits, flags);
    buf.put_slice(value.as_bytes());
}

/// Reads a string literal.
fn decode_string<B: Buf>(buf: &mut B, first: u8, prefix_bits: u8) -> Result<String, QpackError> {
    let huffman = first & (1 << prefix_bits) != 0;
    let len = decode_prefixed_int(buf, first, prefix_bits)? as usize;
    if len > MAX_FIELD_SECTION {
        return Err(QpackError::TooLarge);
    }
    if buf.remaining() < len {
        return Err(QpackError::Truncated);
    }
    let mut bytes = vec![0u8; len];
    buf.copy_to_slice(&mut bytes);
    if huffman {
        bytes = crate::huffman::decode(&bytes, MAX_FIELD_SECTION).map_err(QpackError::Huffman)?;
    }
    String::from_utf8(bytes).map_err(|_| QpackError::InvalidUtf8)
}

/// Encodes a field section (RFC 9204 §4.5) with no dynamic table use.
pub fn encode_field_section(fields: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    // Required Insert Count 0 and Delta Base 0: this section references no
    // dynamic entries, so it never blocks on the encoder stream.
    out.put_u8(0);
    out.put_u8(0);

    for (name, value) in fields {
        let lower = name.to_ascii_lowercase();
        if let Some(index) = find_static_pair(&lower, value) {
            // 1_1_index(6): indexed field line, static table.
            encode_prefixed_int(&mut out, index as u64, 6, 0xc0);
        } else if let Some(index) = find_static_name(&lower) {
            // 01_N_T_index(4): literal with static name reference.
            encode_prefixed_int(&mut out, index as u64, 4, 0x50);
            encode_string(&mut out, value, 7, 0);
        } else {
            // 001_N_H_len(3): literal with a literal name.
            encode_string(&mut out, &lower, 3, 0x20);
            encode_string(&mut out, value, 7, 0);
        }
    }
    out
}

/// Decodes a field section into name/value pairs, preserving order.
pub fn decode_field_section(mut buf: Bytes) -> Result<Vec<(String, String)>, QpackError> {
    if buf.remaining() < 2 {
        return Err(QpackError::Truncated);
    }
    // Required Insert Count and Delta Base. A non-zero insert count would mean
    // the peer referenced its dynamic table, which we never permit it to fill.
    let first = buf.get_u8();
    let required_insert_count = decode_prefixed_int(&mut buf, first, 8)?;
    if required_insert_count != 0 {
        return Err(QpackError::DynamicTableUnsupported);
    }
    if !buf.has_remaining() {
        return Err(QpackError::Truncated);
    }
    let base = buf.get_u8();
    let _ = decode_prefixed_int(&mut buf, base, 7)?;

    let mut fields = Vec::new();
    while buf.has_remaining() {
        let first = buf.get_u8();
        if first & 0x80 != 0 {
            // 1_T_index(6): indexed field line.
            let is_static = first & 0x40 != 0;
            let index = decode_prefixed_int(&mut buf, first, 6)?;
            if !is_static {
                return Err(QpackError::DynamicTableUnsupported);
            }
            let (name, value) = static_entry(index).ok_or(QpackError::UnknownStaticIndex(index))?;
            fields.push((name.to_owned(), value.to_owned()));
        } else if first & 0x40 != 0 {
            // 01_N_T_index(4): literal with a name reference.
            let is_static = first & 0x10 != 0;
            let index = decode_prefixed_int(&mut buf, first, 4)?;
            if !is_static {
                return Err(QpackError::DynamicTableUnsupported);
            }
            let (name, _) = static_entry(index).ok_or(QpackError::UnknownStaticIndex(index))?;
            if !buf.has_remaining() {
                return Err(QpackError::Truncated);
            }
            let vfirst = buf.get_u8();
            let value = decode_string(&mut buf, vfirst, 7)?;
            fields.push((name.to_owned(), value));
        } else if first & 0x20 != 0 {
            // 001_N_H_len(3): literal with a literal name.
            let name = decode_string(&mut buf, first, 3)?;
            if !buf.has_remaining() {
                return Err(QpackError::Truncated);
            }
            let vfirst = buf.get_u8();
            let value = decode_string(&mut buf, vfirst, 7)?;
            fields.push((name, value));
        } else {
            // Post-base indexing, which requires a dynamic table.
            return Err(QpackError::DynamicTableUnsupported);
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(fields: &[(&str, &str)]) -> Vec<(String, String)> {
        let owned: Vec<(String, String)> = fields
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect();
        let encoded = encode_field_section(&owned);
        decode_field_section(Bytes::from(encoded)).expect("decodes")
    }

    /// The exact field set an extended CONNECT request carries.
    #[test]
    fn extended_connect_headers_round_trip() {
        let fields = round_trip(&[
            (":method", "CONNECT"),
            (":protocol", "webtransport"),
            (":scheme", "https"),
            (":authority", "example.com:4433"),
            (":path", "/chat"),
            ("origin", "https://example.com"),
        ]);
        assert_eq!(fields[0], (":method".into(), "CONNECT".into()));
        assert_eq!(fields[1], (":protocol".into(), "webtransport".into()));
        assert_eq!(fields[3], (":authority".into(), "example.com:4433".into()));
        assert_eq!(fields[4], (":path".into(), "/chat".into()));
    }

    #[test]
    fn a_response_status_round_trips() {
        assert_eq!(
            round_trip(&[(":status", "200")]),
            vec![(":status".to_string(), "200".to_string())]
        );
        // A status with no static entry must still work, via a literal.
        assert_eq!(
            round_trip(&[(":status", "418")]),
            vec![(":status".to_string(), "418".to_string())]
        );
    }

    /// A fully indexed field must encode to fewer bytes than a literal, which
    /// is the only reason to consult the static table at all.
    #[test]
    fn static_entries_encode_compactly() {
        let indexed = encode_field_section(&[(":method".into(), "CONNECT".into())]);
        let literal = encode_field_section(&[("x-method".into(), "CONNECT".into())]);
        assert!(
            indexed.len() < literal.len(),
            "{} vs {}",
            indexed.len(),
            literal.len()
        );
        // Two prefix bytes plus a single indexed field line.
        assert_eq!(indexed.len(), 3);
    }

    #[test]
    fn header_names_are_lowercased() {
        let fields = round_trip(&[("X-Custom-Header", "Value")]);
        assert_eq!(
            fields[0].0, "x-custom-header",
            "HTTP/3 field names are lowercase"
        );
        assert_eq!(fields[0].1, "Value", "values keep their case");
    }

    #[test]
    fn empty_and_long_values_round_trip() {
        let long = "a".repeat(5000);
        let fields = round_trip(&[("x-empty", ""), ("x-long", &long)]);
        assert_eq!(fields[0].1, "");
        assert_eq!(fields[1].1, long);
    }

    #[test]
    fn field_order_is_preserved() {
        let fields = round_trip(&[("a", "1"), ("b", "2"), ("c", "3")]);
        assert_eq!(
            fields.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn prefixed_integers_round_trip_across_the_boundary() {
        for value in [0u64, 1, 62, 63, 64, 127, 128, 1000, 100_000] {
            for bits in [3u8, 4, 6, 7] {
                let max = (1u64 << bits) - 1;
                let mut buf = Vec::new();
                encode_prefixed_int(&mut buf, value, bits, 0);
                let mut slice = &buf[..];
                let first = slice.get_u8();
                assert_eq!(
                    decode_prefixed_int(&mut slice, first, bits).unwrap(),
                    value,
                    "value {value} with {bits}-bit prefix (max {max})"
                );
            }
        }
    }

    #[test]
    fn rejects_a_dynamic_table_reference() {
        // A non-zero required insert count means the peer used its dynamic table.
        let encoded = Bytes::from_static(&[0x05, 0x00]);
        assert_eq!(
            decode_field_section(encoded),
            Err(QpackError::DynamicTableUnsupported)
        );
    }

    #[test]
    fn rejects_an_unknown_static_index() {
        // Indexed field line, static, with an index past the 99-entry table.
        let mut encoded = vec![0x00, 0x00];
        encode_prefixed_int(&mut encoded, 500, 6, 0xc0);
        assert!(matches!(
            decode_field_section(Bytes::from(encoded)),
            Err(QpackError::UnknownStaticIndex(500))
        ));
    }

    #[test]
    fn rejects_a_truncated_section() {
        assert_eq!(
            decode_field_section(Bytes::from_static(&[0x00])),
            Err(QpackError::Truncated)
        );
        // A literal claiming more bytes than are present.
        assert_eq!(
            decode_field_section(Bytes::from_static(&[0x00, 0x00, 0x27, 0xff])),
            Err(QpackError::Truncated)
        );
    }

    /// Browsers Huffman-code essentially every header, so a Huffman-coded
    /// field section must decode rather than be rejected. This is the case
    /// that made Chrome fail with ERR_METHOD_NOT_SUPPORTED.
    #[test]
    fn decodes_huffman_coded_fields() {
        // Build a section by hand with Huffman-coded name and value, which is
        // what a real client sends.
        let name = crate::huffman::encode(b"x-custom");
        let value = crate::huffman::encode(b"webtransport");
        let mut encoded = vec![0x00, 0x00];
        // 001_N_H_len(3) with the Huffman bit set.
        encode_prefixed_int(&mut encoded, name.len() as u64, 3, 0x20 | 0x08);
        encoded.extend_from_slice(&name);
        // Value: H_len(7) with the Huffman bit set.
        encode_prefixed_int(&mut encoded, value.len() as u64, 7, 0x80);
        encoded.extend_from_slice(&value);

        let fields = decode_field_section(Bytes::from(encoded)).expect("decodes");
        assert_eq!(
            fields,
            vec![("x-custom".to_string(), "webtransport".to_string())]
        );
    }

    /// A malformed Huffman value is reported rather than silently mangled.
    #[test]
    fn rejects_malformed_huffman() {
        let mut encoded = vec![0x00, 0x00];
        encode_prefixed_int(&mut encoded, 2, 3, 0x20 | 0x08);
        // Zero bits never form a valid code.
        encoded.extend_from_slice(&[0x00, 0x00]);
        assert!(matches!(
            decode_field_section(Bytes::from(encoded)),
            Err(QpackError::Huffman(_))
        ));
    }

    /// RFC 9204 Appendix A defines exactly 99 entries, and a peer may index
    /// any of them. The table was previously short by three, which did not
    /// merely lose compression: every entry after the gap shifted, so a
    /// browser's index decoded to the wrong header, and indices past the end
    /// failed the whole field section. Both spellings of that bug are silent
    /// at the call site, so pin the size and the anchors that move first.
    #[test]
    fn the_static_table_matches_rfc9204() {
        assert_eq!(STATIC_TABLE.len(), 99);
        assert_eq!(static_entry(0), Some((":authority", "")));
        assert_eq!(
            static_entry(52),
            Some(("content-type", "text/html; charset=utf-8"))
        );
        assert_eq!(
            static_entry(56),
            Some(("strict-transport-security", "max-age=31536000"))
        );
        assert_eq!(
            static_entry(57),
            Some((
                "strict-transport-security",
                "max-age=31536000; includesubdomains"
            ))
        );
        assert_eq!(
            static_entry(58),
            Some((
                "strict-transport-security",
                "max-age=31536000; includesubdomains; preload"
            ))
        );
        assert_eq!(static_entry(95), Some(("user-agent", "")));
        assert_eq!(static_entry(96), Some(("x-forwarded-for", "")));
        assert_eq!(static_entry(98), Some(("x-frame-options", "sameorigin")));
        assert_eq!(static_entry(99), None);
    }

    /// A browser encodes common request headers by static index. Decoding one
    /// to the wrong name is what made a real Safari CONNECT unreadable, so
    /// walk the whole table rather than trusting a spot check.
    #[test]
    fn every_static_index_decodes_to_itself() {
        for (i, (name, value)) in STATIC_TABLE.iter().enumerate() {
            assert_eq!(
                static_entry(i as u64),
                Some((*name, *value)),
                "index {i} decoded to the wrong entry"
            );
        }
    }
}
