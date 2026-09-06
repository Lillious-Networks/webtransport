//! Mapping between WebTransport application error codes and HTTP/3 error codes.
//!
//! draft-ietf-webtrans-http3-13 §4.6. WebTransport stream errors are 32-bit, but
//! travel as HTTP/3 error codes in a reserved 2^32-wide range. The range is not
//! contiguous: HTTP/3 (RFC 9114 §8.1) reserves every codepoint of the form
//! `0x1f * N + 0x21` for greasing, and those must be skipped when mapping.

/// First HTTP/3 codepoint in the WT_APPLICATION_ERROR range.
pub const FIRST: u64 = 0x52e4_a40f_a8db;
/// Last HTTP/3 codepoint in the WT_APPLICATION_ERROR range.
pub const LAST: u64 = 0x52e5_ac98_3162;

/// Is `h` a codepoint HTTP/3 reserves for greasing?
const fn is_reserved(h: u64) -> bool {
    // Equivalent to `h == 0x1f * n + 0x21` for some non-negative n.
    h >= 0x21 && (h - 0x21) % 0x1f == 0
}

/// WebTransport application error code -> HTTP/3 error code.
///
/// Every 0x1e-th code skips one slot, stepping over the reserved codepoint that
/// would otherwise fall inside the range.
pub fn to_http(n: u32) -> u64 {
    let n = u64::from(n);
    FIRST + n + (n / 0x1e)
}

/// HTTP/3 error code -> WebTransport application error code.
///
/// Returns `None` for codes outside the WebTransport range or landing on a
/// reserved codepoint, neither of which can name an application error.
pub fn from_http(h: u64) -> Option<u32> {
    if !(FIRST..=LAST).contains(&h) || is_reserved(h) {
        return None;
    }
    let shifted = h - FIRST;
    u32::try_from(shifted - (shifted / 0x1f)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_endpoints_match_the_draft() {
        assert_eq!(to_http(0), FIRST);
        assert_eq!(to_http(u32::MAX), LAST);
        assert_eq!(from_http(FIRST), Some(0));
        assert_eq!(from_http(LAST), Some(u32::MAX));
    }

    /// The property that matters: every application code round-trips, and none
    /// of them ever lands on a greased codepoint.
    #[test]
    fn round_trips_and_never_hits_reserved() {
        let sample = (0..2000u32)
            .chain([0x1d, 0x1e, 0x1f, 0x20, 0x3b, 0x3c, 0xffff, 0x10_0000])
            .chain((u32::MAX - 2000)..=u32::MAX);
        for n in sample {
            let h = to_http(n);
            assert!(
                !is_reserved(h),
                "code {n} mapped onto reserved codepoint {h:#x}"
            );
            assert!((FIRST..=LAST).contains(&h), "code {n} mapped outside range");
            assert_eq!(from_http(h), Some(n), "round-trip failed for {n}");
        }
    }

    /// to_http must be strictly increasing, so ordering is preserved and no two
    /// application codes collide on one HTTP/3 codepoint.
    #[test]
    fn mapping_is_strictly_increasing() {
        let mut prev = to_http(0);
        for n in 1..5000u32 {
            let h = to_http(n);
            assert!(h > prev, "not increasing at {n}");
            prev = h;
        }
    }

    #[test]
    fn rejects_codes_outside_the_range() {
        assert_eq!(from_http(FIRST - 1), None);
        assert_eq!(from_http(LAST + 1), None);
        assert_eq!(from_http(0), None);
        assert_eq!(from_http(0x21), None, "0x21 is reserved");
    }

    /// Reserved codepoints inside the range decode to nothing, and the codes
    /// adjacent to a skipped slot stay adjacent as application codes.
    #[test]
    fn reserved_codepoints_are_skipped_not_mapped() {
        let reserved: Vec<u64> = (FIRST..=LAST).filter(|&h| is_reserved(h)).take(4).collect();
        assert!(
            !reserved.is_empty(),
            "range should contain reserved codepoints"
        );
        for h in reserved {
            assert_eq!(from_http(h), None, "{h:#x} is reserved and must not decode");
            let (before, after) = (from_http(h - 1), from_http(h + 1));
            if let (Some(b), Some(a)) = (before, after) {
                assert_eq!(a, b + 1, "codes either side of {h:#x} must be adjacent");
            }
        }
    }
}
