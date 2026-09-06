//! QUIC variable-length integers (RFC 9000 §16).

use bytes::{Buf, BufMut};

/// Largest value representable as a QUIC varint: 2^62 - 1.
pub const MAX: u64 = (1 << 62) - 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VarIntError {
    #[error("value {0} exceeds the maximum varint value")]
    TooLarge(u64),
    #[error("buffer ended mid-varint")]
    UnexpectedEnd,
}

/// Number of bytes `value` occupies on the wire.
pub const fn encoded_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    }
}

pub fn encode<B: BufMut>(buf: &mut B, value: u64) -> Result<(), VarIntError> {
    if value > MAX {
        return Err(VarIntError::TooLarge(value));
    }
    match encoded_len(value) {
        1 => buf.put_u8(value as u8),
        2 => buf.put_u16(0x4000 | value as u16),
        4 => buf.put_u32(0x8000_0000 | value as u32),
        _ => buf.put_u64(0xc000_0000_0000_0000 | value),
    }
    Ok(())
}

/// Decodes a varint, advancing `buf` only on success.
pub fn decode<B: Buf>(buf: &mut B) -> Result<u64, VarIntError> {
    if !buf.has_remaining() {
        return Err(VarIntError::UnexpectedEnd);
    }
    // Peek the tag before consuming, so a short buffer leaves `buf` untouched.
    let first = buf.chunk()[0];
    let len = 1usize << (first >> 6);
    if buf.remaining() < len {
        return Err(VarIntError::UnexpectedEnd);
    }
    let mut value = u64::from(first & 0x3f);
    buf.advance(1);
    for _ in 1..len {
        value = (value << 8) | u64::from(buf.get_u8());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four worked examples from RFC 9000 §A.1.
    #[test]
    fn rfc9000_appendix_a1_vectors() {
        for (value, bytes) in [
            (
                151_288_809_941_952_652u64,
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c][..],
            ),
            (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
            (15_293, &[0x7b, 0xbd]),
            (37, &[0x25]),
        ] {
            let mut out = Vec::new();
            encode(&mut out, value).unwrap();
            assert_eq!(out, bytes, "encoding {value}");
            assert_eq!(decode(&mut &bytes[..]).unwrap(), value, "decoding {value}");
        }
    }

    /// The two-byte encoding of 37 must decode too: length comes from the tag,
    /// not from the value, so decoders cannot assume minimal encoding.
    #[test]
    fn non_minimal_encoding_decodes() {
        assert_eq!(decode(&mut &[0x40, 0x25][..]).unwrap(), 37);
    }

    #[test]
    fn boundaries_round_trip() {
        for value in [0, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000, MAX] {
            let mut out = Vec::new();
            encode(&mut out, value).unwrap();
            assert_eq!(out.len(), encoded_len(value));
            assert_eq!(decode(&mut &out[..]).unwrap(), value);
        }
    }

    #[test]
    fn rejects_oversized_value() {
        assert_eq!(
            encode(&mut Vec::new(), MAX + 1),
            Err(VarIntError::TooLarge(MAX + 1))
        );
    }

    #[test]
    fn truncated_input_leaves_buffer_unconsumed() {
        let mut buf = &[0xc2, 0x19][..];
        assert_eq!(decode(&mut buf), Err(VarIntError::UnexpectedEnd));
        assert_eq!(buf.len(), 2, "a failed decode must not consume input");
        assert_eq!(decode(&mut &[][..]), Err(VarIntError::UnexpectedEnd));
    }
}
