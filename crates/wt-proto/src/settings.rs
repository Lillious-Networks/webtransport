//! HTTP/3 SETTINGS relevant to WebTransport (draft §3.1, §5.5).
//!
//! Both peers advertise support by sending `SETTINGS_WT_MAX_SESSIONS` with a
//! non-zero value; a server must additionally send
//! `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` (RFC 9220). A client must not open a
//! session before it has seen the server's SETTINGS, since only then does it
//! know WebTransport is available.
//!
//! The setting's codepoint changed across drafts, and each codepoint doubles
//! as version negotiation. We advertise the set that quic-go ships and that
//! Safari's iOS path accepts: draft-02 (Chromium, Firefox), the final
//! `SETTINGS_WT_ENABLED`, and the draft-13 `SETTINGS_WT_MAX_SESSIONS`
//! accompanied by all three `WT_INITIAL_MAX_*` limits — Safari switches
//! session-level flow control on when the session limit exceeds 1, and with
//! those three absent it reads zero credit and refuses the session before
//! CONNECT. The draft-07 spelling is still recognised when parsing so older
//! clients (Chromium, Safari 26.x on macOS) are accepted.

/// RFC 9204: the dynamic table capacity we permit a peer to use.
///
/// We advertise 0, which forbids the dynamic table outright. A peer that sees
/// this will not emit dynamic references, so the decoder never has to resolve
/// one, and saying so explicitly beats relying on the default.
pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
/// RFC 9204: how many streams may be blocked on dynamic table state. Zero,
/// for the same reason.
pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
/// RFC 9220: enables extended CONNECT.
pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
/// RFC 9297: enables HTTP/3 datagrams.
pub const H3_DATAGRAM: u64 = 0x33;
/// draft-07 spelling of `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
///
/// Recognised when parsing so older peers (Chromium's draft-07 client and
/// Safari 26.x on macOS, which refuses servers that do not send it non-zero)
/// are accepted, but no longer advertised: the quic-go set below is what
/// Safari's iOS path reads.
pub const WT_MAX_SESSIONS_DRAFT07: u64 = 0xc671_706a;
/// Final spelling of the support indicator, `SETTINGS_WT_ENABLED`.
///
/// Draft-13 and later use this codepoint instead of a session limit; a value
/// of 1 is the only valid one. quic-go clients require a server to send it.
pub const WT_ENABLED: u64 = 0x2c7c_f000;
/// The draft-02 spelling of the same setting.
///
/// Accepted when parsing a peer's SETTINGS so we can talk to endpoints on an
/// old draft, and advertised with the value 1: quiche treats this codepoint as
/// a boolean enable flag ("SETTINGS_ENABLE_WEBTRANSPORT"), rejecting any value
/// above 1 with H3_SETTINGS_ERROR, and matches peers by version intersection.
/// Omitting it makes draft-02-only Chromium — and Firefox, whose Neqo knows no
/// other codepoint — conclude WebTransport is unsupported.
pub const WT_MAX_SESSIONS_DRAFT02: u64 = 0x2b60_3742;
/// draft-13 spelling of `SETTINGS_WT_MAX_SESSIONS`.
///
/// The codepoint Safari's iOS path requires at a value of at least 1; when it
/// exceeds 1 Safari also enables session-level flow control, so the three
/// `WT_INITIAL_MAX_*` settings must be advertised alongside it or the session
/// is refused before CONNECT.
pub const WT_MAX_SESSIONS_DRAFT13: u64 = 0x14e9_cd29;
/// draft §9.2: initial session-level flow-control limit.
pub const WT_INITIAL_MAX_DATA: u64 = 0x2b61;
/// draft §9.2: initial limit on incoming unidirectional streams.
pub const WT_INITIAL_MAX_STREAMS_UNI: u64 = 0x2b64;
/// draft §9.2: initial limit on incoming bidirectional streams.
pub const WT_INITIAL_MAX_STREAMS_BIDI: u64 = 0x2b65;

/// The WebTransport-relevant subset of a peer's SETTINGS frame.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Settings {
    pub enable_connect_protocol: bool,
    pub h3_datagram: bool,
    /// The final `SETTINGS_WT_ENABLED` flag: draft-13+ peers send this rather
    /// than a session limit.
    pub wt_enabled: bool,
    pub wt_max_sessions: u64,
    pub wt_initial_max_data: u64,
    pub wt_initial_max_streams_uni: u64,
    pub wt_initial_max_streams_bidi: u64,
    /// The peer's QPACK dynamic table capacity. We advertise 0.
    pub qpack_max_table_capacity: u64,
    /// The peer's QPACK blocked-stream allowance. We advertise 0.
    pub qpack_blocked_streams: u64,
    /// Settings we do not recognise, kept for diagnostics.
    pub unknown: Vec<(u64, u64)>,
}

impl Settings {
    /// Settings a WebTransport endpoint advertises.
    pub fn advertised(max_sessions: u64) -> Self {
        Self {
            enable_connect_protocol: true,
            h3_datagram: true,
            wt_enabled: true,
            wt_max_sessions: max_sessions,
            // Safari enables session-level flow control whenever the session
            // limit exceeds 1 and reads these as the opening credit; leaving
            // them zero makes it refuse the session before CONNECT. The
            // values mirror quic-go's, which is what Safari's iOS path was
            // tested against.
            wt_initial_max_data: 1 << 60,
            wt_initial_max_streams_uni: 1 << 60,
            wt_initial_max_streams_bidi: 1 << 60,
            // Explicitly zero: the decoder resolves no dynamic references, so
            // a peer must not make any.
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            ..Self::default()
        }
    }

    /// Records one setting, ignoring those WebTransport does not care about.
    pub fn apply(&mut self, id: u64, value: u64) {
        match id {
            ENABLE_CONNECT_PROTOCOL => self.enable_connect_protocol = value == 1,
            H3_DATAGRAM => self.h3_datagram = value == 1,
            WT_ENABLED => self.wt_enabled = value == 1,
            WT_MAX_SESSIONS_DRAFT02 | WT_MAX_SESSIONS_DRAFT07 | WT_MAX_SESSIONS_DRAFT13 => {
                // Either spelling means the same thing; take the larger so a
                // peer sending several is not read as offering fewer sessions.
                self.wt_max_sessions = self.wt_max_sessions.max(value);
            }
            WT_INITIAL_MAX_DATA => self.wt_initial_max_data = value,
            WT_INITIAL_MAX_STREAMS_UNI => self.wt_initial_max_streams_uni = value,
            WT_INITIAL_MAX_STREAMS_BIDI => self.wt_initial_max_streams_bidi = value,
            QPACK_MAX_TABLE_CAPACITY => self.qpack_max_table_capacity = value,
            QPACK_BLOCKED_STREAMS => self.qpack_blocked_streams = value,
            // Record anything unrecognised so a codepoint mismatch is
            // diagnosable rather than silently reading as "no support".
            other => self.unknown.push((other, value)),
        }
    }

    /// May a client open a WebTransport session against a server that sent
    /// these settings?
    ///
    /// Extended CONNECT alone is not enough: without a non-zero session limit
    /// — or, for draft-13+ peers, the `WT_ENABLED` flag — the server is
    /// telling us it will accept none.
    pub fn accepts_webtransport(&self) -> bool {
        self.enable_connect_protocol && (self.wt_max_sessions > 0 || self.wt_enabled)
    }

    /// Are datagrams usable on this connection? Drives `reliability`:
    /// `supports-unreliable` when true, `reliable-only` when false.
    pub fn supports_datagrams(&self) -> bool {
        self.h3_datagram
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_settings() -> Settings {
        let mut s = Settings::default();
        s.apply(ENABLE_CONNECT_PROTOCOL, 1);
        s.apply(H3_DATAGRAM, 1);
        s.apply(WT_MAX_SESSIONS_DRAFT07, 1);
        s
    }

    #[test]
    fn a_conforming_server_is_accepted() {
        let s = server_settings();
        assert!(s.accepts_webtransport());
        assert!(s.supports_datagrams());
    }

    /// The default of WT_MAX_SESSIONS is 0, meaning "no sessions", so an absent
    /// setting must not be read as support.
    #[test]
    fn absent_settings_mean_no_webtransport() {
        assert!(!Settings::default().accepts_webtransport());
    }

    #[test]
    fn extended_connect_alone_is_not_enough() {
        let mut s = Settings::default();
        s.apply(ENABLE_CONNECT_PROTOCOL, 1);
        assert!(
            !s.accepts_webtransport(),
            "zero max sessions must be refused"
        );
    }

    #[test]
    fn max_sessions_alone_is_not_enough() {
        let mut s = Settings::default();
        s.apply(WT_MAX_SESSIONS_DRAFT07, 4);
        assert!(!s.accepts_webtransport(), "extended CONNECT is required");
    }

    /// Every draft spelling of the session limit is recognised, and the
    /// largest value wins when a peer sends more than one.
    #[test]
    fn every_max_sessions_spelling_is_recognised() {
        let mut s = Settings::default();
        s.apply(WT_MAX_SESSIONS_DRAFT02, 1);
        s.apply(WT_MAX_SESSIONS_DRAFT07, 4);
        s.apply(WT_MAX_SESSIONS_DRAFT13, 2);
        assert_eq!(s.wt_max_sessions, 4);
    }

    /// Draft-13+ peers signal support with SETTINGS_WT_ENABLED instead of a
    /// session limit; a session limit of zero must not read as "no support".
    #[test]
    fn wt_enabled_flag_alone_is_support() {
        let mut s = Settings::default();
        s.apply(ENABLE_CONNECT_PROTOCOL, 1);
        s.apply(WT_ENABLED, 1);
        assert_eq!(s.wt_max_sessions, 0);
        assert!(s.accepts_webtransport());
    }

    /// Datagram support is independent of session support and decides the
    /// reliability mode reported to JS.
    #[test]
    fn datagram_support_is_tracked_separately() {
        let mut s = server_settings();
        s.apply(H3_DATAGRAM, 0);
        assert!(s.accepts_webtransport());
        assert!(!s.supports_datagrams(), "reliable-only session");
    }

    #[test]
    fn boolean_settings_only_accept_one() {
        let mut s = Settings::default();
        s.apply(ENABLE_CONNECT_PROTOCOL, 2);
        assert!(
            !s.enable_connect_protocol,
            "only the value 1 enables the setting"
        );
    }

    #[test]
    fn unknown_settings_are_ignored() {
        let mut s = server_settings();
        let before = s.clone();
        s.apply(0xdead_beef, 99);
        assert_eq!(s.wt_max_sessions, before.wt_max_sessions);
        assert_eq!(s.unknown, vec![(0xdead_beef, 99)]);
    }

    #[test]
    fn flow_control_limits_are_recorded() {
        let mut s = Settings::default();
        s.apply(WT_INITIAL_MAX_DATA, 1 << 20);
        s.apply(WT_INITIAL_MAX_STREAMS_UNI, 3);
        s.apply(WT_INITIAL_MAX_STREAMS_BIDI, 5);
        assert_eq!(s.wt_initial_max_data, 1 << 20);
        assert_eq!(s.wt_initial_max_streams_uni, 3);
        assert_eq!(s.wt_initial_max_streams_bidi, 5);
    }

    #[test]
    fn advertised_settings_enable_webtransport() {
        let s = Settings::advertised(16);
        assert!(s.accepts_webtransport());
        assert!(s.supports_datagrams());
        assert!(s.wt_enabled);
        assert_eq!(s.wt_max_sessions, 16);
        // Safari refuses sessions when the session limit exceeds 1 but these
        // initial flow-control credits are absent, so the advertised set must
        // always carry them.
        assert!(s.wt_initial_max_data > 0);
        assert!(s.wt_initial_max_streams_uni > 0);
        assert!(s.wt_initial_max_streams_bidi > 0);
    }
}
