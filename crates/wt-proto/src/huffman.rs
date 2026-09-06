//! HPACK Huffman coding (RFC 7541 Appendix B), as used by QPACK.
//!
//! Field values on the wire are Huffman-coded whenever that is shorter, and
//! real clients do it routinely: Chrome Huffman-codes essentially every header
//! it sends. A decoder that cannot handle it cannot read a browser's extended
//! CONNECT request at all, which is why this replaces the earlier
//! "peers only use it when it helps" assumption.
//!
//! Decoding walks the code bit by bit against the canonical table. That is
//! slower than a multi-bit lookup tree, but a header section is a few hundred
//! bytes once per session, so a table anyone can check by eye wins.

/// `(code, bit length)` for each symbol, indexed by byte value.
///
/// Index 256 is the EOS symbol, which may never appear in a decoded value.
const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// The EOS symbol. Its presence in a value is a decoding error (RFC 7541 §5.2).
const EOS: usize = 256;

/// Longest code in the table, which bounds how far a decode can wander before
/// concluding the input is malformed.
const MAX_CODE_BITS: u8 = 30;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HuffmanError {
    #[error("Huffman-coded value contains an invalid code")]
    InvalidCode,
    #[error("Huffman-coded value contains the EOS symbol")]
    UnexpectedEos,
    #[error("Huffman-coded value has invalid trailing padding")]
    InvalidPadding,
    #[error("decoded value exceeds the size this endpoint accepts")]
    TooLong,
}

/// Decodes a Huffman-coded string.
///
/// `limit` caps the decoded length: a short input can expand considerably, so
/// the caller's bound is enforced as we go rather than after the fact.
pub fn decode(input: &[u8], limit: usize) -> Result<Vec<u8>, HuffmanError> {
    let mut out = Vec::new();
    // The current partial code and how many bits it holds.
    let mut code: u32 = 0;
    let mut bits: u8 = 0;

    for byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            bits += 1;

            if let Some(symbol) = lookup(code, bits) {
                if symbol == EOS {
                    return Err(HuffmanError::UnexpectedEos);
                }
                if out.len() >= limit {
                    return Err(HuffmanError::TooLong);
                }
                out.push(symbol as u8);
                code = 0;
                bits = 0;
            } else if bits > MAX_CODE_BITS {
                return Err(HuffmanError::InvalidCode);
            }
        }
    }

    // Whatever is left must be padding: fewer than 8 bits, all ones, and not a
    // complete code (RFC 7541 §5.2). Anything else is malformed.
    if bits >= 8 {
        return Err(HuffmanError::InvalidPadding);
    }
    if bits > 0 {
        let expected = (1u32 << bits) - 1;
        if code != expected {
            return Err(HuffmanError::InvalidPadding);
        }
    }
    Ok(out)
}

/// Finds the symbol whose code is exactly `code` in `bits` bits.
fn lookup(code: u32, bits: u8) -> Option<usize> {
    CODES
        .iter()
        .position(|(candidate, length)| *length == bits && *candidate == code)
}

/// Encodes a string with Huffman coding.
pub fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut buffer: u64 = 0;
    let mut bits: u8 = 0;

    for byte in input {
        let (code, length) = CODES[*byte as usize];
        buffer = (buffer << length) | u64::from(code);
        bits += length;
        while bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }

    // Pad the final byte with ones, which is what the padding check expects.
    if bits > 0 {
        let pad = 8 - bits;
        buffer = (buffer << pad) | ((1u64 << pad) - 1);
        out.push(buffer as u8);
    }
    out
}

/// Length `input` would occupy Huffman-coded, for deciding whether it helps.
pub fn encoded_len(input: &[u8]) -> usize {
    let bits: usize = input
        .iter()
        .map(|b| usize::from(CODES[*b as usize].1))
        .sum();
    bits.div_ceil(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked examples from RFC 7541 Appendix C.4.
    #[test]
    fn rfc7541_appendix_c4_vectors() {
        for (plain, coded) in [
            (
                "www.example.com",
                &[
                    0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
                ][..],
            ),
            ("no-cache", &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
            (
                "custom-key",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
            ),
            (
                "custom-value",
                &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
            ),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded, "encoding {plain}");
            assert_eq!(
                decode(coded, 1024).unwrap(),
                plain.as_bytes(),
                "decoding {plain}"
            );
        }
    }

    /// The fields a browser actually sends on an extended CONNECT, which is
    /// what this decoder exists to read.
    #[test]
    fn connect_request_values_round_trip() {
        for value in [
            "webtransport",
            "CONNECT",
            "https",
            "example.com:4433",
            "/chat/room-9",
            "https://example.com",
        ] {
            let coded = encode(value.as_bytes());
            assert_eq!(decode(&coded, 1024).unwrap(), value.as_bytes(), "{value}");
        }
    }

    #[test]
    fn every_byte_round_trips() {
        let all: Vec<u8> = (0..=255u8).collect();
        assert_eq!(decode(&encode(&all), 4096).unwrap(), all);
    }

    #[test]
    fn empty_input_decodes_to_empty() {
        assert_eq!(encode(b""), Vec::<u8>::new());
        assert_eq!(decode(b"", 16).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn encoded_len_matches_encoding() {
        for value in ["", "a", "webtransport", "example.com:4433"] {
            assert_eq!(
                encoded_len(value.as_bytes()),
                encode(value.as_bytes()).len(),
                "{value}"
            );
        }
    }

    /// EOS must never appear in a value: a peer sending it is signalling a
    /// truncated or hostile encoding rather than data.
    #[test]
    fn rejects_the_eos_symbol() {
        // EOS is 30 ones, so five 0xff bytes contain it followed by padding.
        let err = decode(&[0xff, 0xff, 0xff, 0xff, 0xff], 64).unwrap_err();
        assert_eq!(err, HuffmanError::UnexpectedEos);
    }

    /// Padding must be all ones and shorter than a byte (RFC 7541 §5.2).
    #[test]
    fn rejects_bad_padding() {
        // "a" is 5 bits (0b00011), so one byte holds it plus 3 padding bits.
        // Zero padding rather than ones is malformed.
        assert_eq!(
            decode(&[0b0001_1000], 16),
            Err(HuffmanError::InvalidPadding)
        );
    }

    #[test]
    fn enforces_the_length_limit() {
        let coded = encode(&[b'a'; 100]);
        assert_eq!(decode(&coded, 10), Err(HuffmanError::TooLong));
        assert!(decode(&coded, 100).is_ok());
    }

    /// A decoder must not loop forever on input that never completes a code.
    #[test]
    fn rejects_an_incomplete_code() {
        // 0x00 repeated never forms a valid code: the shortest codes are ones.
        let err = decode(&[0x00; 8], 64).unwrap_err();
        assert!(
            matches!(
                err,
                HuffmanError::InvalidCode | HuffmanError::InvalidPadding
            ),
            "got {err:?}"
        );
    }
}
