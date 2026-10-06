//! The transport superset: every way `PattNG` can connect, in one matrix.
//!
//! Ferrox-core is a superset of Xray-core, sing-box, xray-rust and `PattNG`'s
//! Xray fork — not a re-implementation of one of them. That means the matrix
//! below lists transports this core does *not* implement yet, with the reason
//! each cell is empty, rather than omitting them. An omitted cell reads as
//! "not measured"; an empty-with-reason cell reads as "measured, unsupported".
//!
//! One method is implemented at a time. The order is the table order: the
//! first row is the only [`Support::Implemented`] one, and a row moves up only
//! with its differential proof and its benchmark gate.
//!
//! | # | transport | status | notes |
//! | - | --------- | ------ | ----- |
//! | 1 | VLESS TCP REALITY Vision | **implemented** | the brief's link; `vless.rs` parses, header encode benchmarked |
//! | 2 | VLESS TCP TLS (Vision optional) | planned | parses; dials after rung 1 lands |
//! | 3 | VLESS TCP none (private) | **implemented** | [`crate::vless::VlessLink::is_none_private_method`]; header encode is `vless.rs`'s, relay is the raw path, and the `UDP` command rides it framed (`u16` length plus payload) |
//! | 4 | VLESS TCP none to public (`PattNG` ext.) | unsafe opt-in | parses; [`Security::NoneToPublic`], needs explicit opt-in |
//! | 5 | `TROJAN` TCP TLS / to-public-plaintext (`PattNG` ext.) | **implemented** | `ferrox-app` carries it over raw `TCP`; to-public-plaintext keeps the `PattNG` opt-in |
//! | 6 | `VMess` TCP | **implemented** | `ferrox-app`'s `vmess.rs`, both roles over raw `TCP` |
//! | 7 | Shadowsocks TCP/UDP | **implemented** | [`crate::shadowsocks`]: three `AEAD` ciphers, both roles, `UDP` over raw `TCP` framed (`u16` length plus payload); no `2022` |
//! | 8 | VLESS WS / `XHTTP` / gRPC / `HTTPUpgrade` / HTTP masquerade | **implemented** | `ferrox-app`'s `ws.rs`, `xhttp.rs`, `grpc.rs`, `httpupgrade.rs`, `httpheader.rs`; both `ws`/`websocket` and `xhttp`/`splithttp` spellings parse |
//! | 9 | `QUIC` | **implemented (dial, `VLESS` only)** | `ferrox-app`'s `quic.rs`: `quiche`, `ALPN h3`, stream 0, explicit trust anchors from `tlsSettings.caCertFile`; no serve side |
//! | 9a | `KCP` / `Hysteria` / `MASQUE` H2+H3 / `XDRive` | **refused** | each name parses to its own `Carrier` cell and every serve/dial arm refuses — never a raw `TCP` downgrade |
//! | 10 | `cipherSuites` + `unsafe-*` fingerprints (`PattNG` ext.) | unsafe opt-in | parsed and carried; enabling needs [`crate::policy`] sign-off |
//! | 11 | multiplex over every row above | **implemented** | [`crate::mux`]; the one row that is not a transport — serve demuxes raw-`TCP`, dial carries one session per uplink |
//! | 12 | `?ed=N` early data on `ws` / `httpupgrade` | **implemented** | [`EarlyData`]; both roles, one parse |
//!
//! [`crate::vless::VlessLink::support`] is the code form of this table: it
//! never panics and never errors on an unknown transport — unknown is
//! `Planned`, because the matrix is a superset by construction.
//!
//! # Why row 12 is one row and not two
//!
//! Early data is one mechanism wearing two carriers, and all four
//! implementations spell the mechanism rather than the carrier:
//! `Xray-core` writes the same eleven lines in `WebSocketConfig.Build` and
//! again in `HttpUpgradeConfig.Build`, `xray-rust` writes it in
//! `parse_websocket_settings` and again in `parse_httpupgrade_settings`, and
//! `sing-box` sidesteps it by making the budget a config field
//! (`max_early_data`) that no share link has to spell inside a path. It is
//! [`EarlyData::split`] here, called from both carriers and once.
//!
//! # Why row 11 is not a transport
//!
//! Rows 1-10 are one way to reach a server. Multiplexing is a way to put many
//! conversations inside one of them, so it composes with every row instead of
//! competing with it: landing it turns ten rows into ten families. It is also the
//! row that was most conspicuously missing — Xray-core, sing-box and `PattNG` all
//! carry it and this workspace carried none of it, while xray-rust, the fourth
//! implementation, refuses it outright at config-parse time.
//!
//! It is therefore not a [`TransportKind`] and does not appear in one: there is
//! no `type=mux` to parse, because a link asks for multiplexing by having its
//! protocol and security layers compose, not by naming a transport.

use std::fmt;

/// The wire transport under the security layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// `type=tcp` (or absent, which Xray reads as TCP).
    Tcp,
    /// `type=ws`.
    Ws,
    /// `type=xhttp`.
    Xhttp,
    /// `type=grpc`.
    Grpc,
    /// `type=quic`.
    Quic,
    /// `type=httpupgrade`.
    HttpUpgrade,
    /// `type=kcp` (or `mkcp`).
    Kcp,
    /// `type=hysteria`.
    Hysteria,
    /// `type=masque`.
    Masque,
    /// `type=xdrive`.
    Xdrive,
    /// Anything else (preserved, never rejected at parse).
    Other,
}

impl TransportKind {
    /// Every kind, so a test can walk the whole space rather than a list of it.
    ///
    /// Eleven, and a new variant that forgets to extend this fails the test that
    /// walks it: an unlisted kind is a kind no exhaustive check can reach.
    pub const ALL: [Self; 11] = [
        Self::Tcp,
        Self::Ws,
        Self::Xhttp,
        Self::Grpc,
        Self::Quic,
        Self::HttpUpgrade,
        Self::Kcp,
        Self::Hysteria,
        Self::Masque,
        Self::Xdrive,
        Self::Other,
    ];
}

impl TransportKind {
    /// From a `type=` query value. Empty means TCP, as Xray does.
    #[must_use]
    pub fn from_link(t: &str) -> Self {
        match t {
            "" | "tcp" => Self::Tcp,
            "ws" | "websocket" => Self::Ws,
            "xhttp" | "splithttp" => Self::Xhttp,
            "grpc" => Self::Grpc,
            "quic" => Self::Quic,
            "httpupgrade" => Self::HttpUpgrade,
            "kcp" | "mkcp" => Self::Kcp,
            "hysteria" => Self::Hysteria,
            "masque" => Self::Masque,
            "xdrive" => Self::Xdrive,
            _ => Self::Other,
        }
    }

    /// Whether `ferrox-app` dials this carrier today.
    ///
    /// One `const` list rather than a hand-written row in each of three tables,
    /// because the three disagreed: this module's own matrix said row 8 was
    /// implemented, [`crate::vless::VlessLink::support`] said `planned:
    /// scheduled after tcp-tls`, and `ferrox-bench`'s `methods.rs` said a
    /// third thing. The code was right — `proxy.rs` carries `match` arms for
    /// every carrier in this list — and the two registries were stale copies of
    /// an earlier plan. [`crate::vless::VlessLink::support`] now reads this, so
    /// the registry and the dial path cannot drift again.
    ///
    /// The `const` is what makes it a gate rather than a comment: a carrier
    /// added here without a `match` arm fails the test that dials each of them
    /// through a loopback listener.
    #[must_use]
    pub const fn is_dialled(self) -> bool {
        matches!(
            self,
            Self::Tcp | Self::Ws | Self::Xhttp | Self::Grpc | Self::Quic | Self::HttpUpgrade
        )
    }
}

/// The security layer over the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// `security=tls`.
    Tls,
    /// `security=reality`.
    Reality,
    /// `security=none` to a private/loopback address (or no address check).
    None,
    /// `security=none` to a *public* address: the `PattNG` extension upstream
    /// Xray-core refuses. Parses fine; dials only with explicit opt-in.
    NoneToPublic,
    /// Anything else (preserved).
    Other,
}

impl Security {
    /// From a `security=` value plus the destination host, so `none` splits
    /// into [`Self::None`] vs [`Self::NoneToPublic`] at parse time rather
    /// than at dial time — where a silent plaintext fallback would hide.
    #[must_use]
    pub fn from_link(s: &str, host: &str) -> Self {
        match s {
            "tls" => Self::Tls,
            "reality" => Self::Reality,
            "none" | "" => {
                if is_public_host(host) {
                    Self::NoneToPublic
                } else {
                    Self::None
                }
            }
            _ => Self::Other,
        }
    }
}

/// `?ed=N` taken off a `ws` or `httpupgrade` path: the path to serve, and the budget.
///
/// # What the budget is
///
/// A `WebSocket` client that sends it puts its **first write** in the handshake,
/// as unpadded base64url in `Sec-WebSocket-Protocol`, and sends no frame for
/// those bytes. `N` is the whole budget and the boundary is inclusive: a first
/// write longer than `N` does not travel truncated, it travels in a frame and
/// early data is off for the rest of the connection. `0` is not a budget of zero
/// bytes, it is no early data at all — the setting off.
///
/// # Why the path loses `ed`
///
/// The `ws` and `httpupgrade` servers match a request's `URL.Path`, which has no
/// query in it, against a configured path that does. So the key has to come out
/// or the row can never be served, and it is the only key that ever is there.
/// Upstream re-encodes the surviving pairs through `url.Values.Encode`, which
/// also sorts them; this keeps them in the order they were written, which is the
/// same answer for every sorted query and for every query in the matrix, and the
/// one input where the two differ — surviving pairs written out of order — is a
/// path no peer serves either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyData {
    /// The path with a non-empty `ed=` removed; surviving pairs keep their order.
    pub path: String,
    /// Bytes the first write may ride in the handshake; `0` for none.
    pub budget: u32,
}

impl EarlyData {
    /// Split `?ed=N` off `path`, as `Xray-core` does for its two carriers.
    ///
    /// The path comes back byte for byte with a budget of `0` in every case
    /// upstream's `if u.Query().Get("ed") != ""` guard skips the rewrite: no
    /// query, no `ed` key, `ed` with no `=`, or `ed=` with an empty value. That
    /// guard is load-bearing rather than defensive — it is why `ed=abc` still
    /// costs a budget of `0` **and** still leaves the path, which reads as a
    /// pointless rewrite and is what every peer then requires.
    #[must_use]
    pub fn split(path: &str) -> Self {
        // `url.Parse` takes the fragment first, so a `?` inside it is not a
        // query at all, and the fragment survives the rewrite behind whatever
        // query is left.
        let (head, fragment) = path
            .split_once('#')
            .map_or((path, None), |(h, f)| (h, Some(f)));
        let untouched = || Self {
            path: path.to_owned(),
            budget: 0,
        };
        let Some((base, query)) = head.split_once('?') else {
            return untouched();
        };
        let is_ed = |pair: &str| pair.split_once('=').is_some_and(|(key, _)| key == "ed");
        // `Values.Get` is the first value for the key, and an empty one reads as
        // absent, so `ed=&ed=4` is as absent as `ed=` is.
        let first = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(key, _)| *key == "ed")
            .map_or("", |(_, value)| value);
        if first.is_empty() {
            return untouched();
        }
        let kept = query
            .split('&')
            .filter(|pair| !pair.is_empty() && !is_ed(pair))
            .collect::<Vec<_>>();
        let mut out = base.to_owned();
        if !kept.is_empty() {
            out.push('?');
            out.push_str(&kept.join("&"));
        }
        if let Some(fragment) = fragment {
            out.push('#');
            out.push_str(fragment);
        }
        Self {
            path: out,
            budget: atoi(first) as u32,
        }
    }
}

/// `strconv.Atoi`'s number: `0` on anything unparsable, the saturated bound on overflow.
///
/// Go ignores the error `Atoi` returns and casts the value straight to `uint32`,
/// so `ed=-1` is a 4294967295-byte budget rather than no budget, and `ed=abc` is
/// `0`. Both are reproduced, because both are what a peer's path was built from.
fn atoi(text: &str) -> i64 {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        let Some(next) = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i64::from(byte - b'0')))
        else {
            return if negative { i64::MIN } else { i64::MAX };
        };
        value = next;
    }
    if negative {
        -value
    } else {
        value
    }
}

/// Base64url alphabet, unpadded: the only alphabet early data travels in, and
/// the only place it differs from the RFC 6455 one is the last two digits.
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// One base64 digit in either alphabet, so early data decodes from a peer that
/// wrote the standard one.
fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Base64url, no padding, appended to whatever is already in `out`.
///
/// Appends rather than returns, because the one caller is building a handshake in
/// a buffer it already owns: four digits per three bytes land in that buffer with
/// no second string between, and every implementation upstream builds one and pays
/// a copy for it. `reserve` is once for the whole run, so the pushes below never
/// reallocate — which is the only thing this does that a plain `String::push` loop
/// does not.
pub fn early_encode_into(out: &mut String, data: &[u8]) {
    out.reserve(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        out.push(URL_ALPHABET[(word >> 18 & 0x3F) as usize] as char);
        out.push(URL_ALPHABET[(word >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(URL_ALPHABET[(word >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(URL_ALPHABET[(word & 0x3F) as usize] as char);
        }
    }
}

/// Base64url decode, no padding, either alphabet; `None` on a length or digit
/// a base64 string cannot have.
///
/// `Some(empty)` for an empty string, because that is a header that carried no
/// early data rather than a malformed one — the caller serves nothing for it.
pub fn early_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().trim_end_matches('=');
    if text.is_empty() {
        return Some(Vec::new());
    }
    if text.len() % 4 == 1 {
        return None;
    }
    let bytes = text.as_bytes();
    let (full, rest) = bytes.split_at(bytes.len() / 4 * 4);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 3);
    for group in full.as_chunks::<4>().0 {
        let mut word = 0u32;
        for &byte in group {
            word = (word << 6) | u32::from(digit(byte)?);
        }
        out.extend_from_slice(&word.to_be_bytes()[1..]);
    }
    if !rest.is_empty() {
        let mut word = 0u32;
        for &byte in rest {
            word = (word << 6) | u32::from(digit(byte)?);
        }
        word <<= 6 * (4 - rest.len());
        let tail = word.to_be_bytes();
        out.extend_from_slice(&tail[1..rest.len()]);
    }
    Some(out)
}

/// True for a host that is neither loopback, private, nor a test name.
/// Used only to split `None` from `NoneToPublic`; the dial path re-checks.
///
/// `h` is already lowercased by the caller, so the suffix comparisons below
/// are case-insensitive by construction rather than by a second pass.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_public_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return false;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_multicast());
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return !(v6.is_loopback() || v6.is_multicast());
    }
    // A bare domain name is treated as public: resolving it to decide would
    // put DNS in the parser, and the dial path checks again anyway.
    // `example.*` / `test.*` / `.invalid` / `.localhost` are the documented
    // non-public exceptions (RFC 2606 / 6761).
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h == "example.com" || h == "example.org" || h == "example.net" {
        return false;
    }
    !(h.ends_with(".test")
        || h.ends_with(".example")
        || h.ends_with(".invalid")
        || h.ends_with(".localhost")
        || h == "test")
}

/// Whether a link's transport can be dialled by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Diallable now. `method` names the rung (e.g. `vless-tcp-reality-vision`).
    Implemented {
        /// Rung name, for reports.
        method: &'static str,
    },
    /// Parses but not diallable yet. The reason is the cell content in the
    /// comparison table — never an omission.
    Planned {
        /// Why the cell is empty.
        reason: &'static str,
    },
    /// Parses but dials only with an explicit, audited opt-in
    /// (see [`crate::policy`]). Plaintext-to-public and `unsafe-*`
    /// fingerprints live here.
    UnsafeRequiresOptIn {
        /// Why opt-in is required.
        reason: &'static str,
    },
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented { method } => write!(f, "implemented ({method})"),
            Self::Planned { reason } => write!(f, "planned: {reason}"),
            Self::UnsafeRequiresOptIn { reason } => write!(f, "unsafe opt-in required: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_none_is_not_public() {
        assert_eq!(Security::from_link("none", "127.0.0.1"), Security::None);
        assert_eq!(Security::from_link("", "localhost"), Security::None);
        assert_eq!(
            Security::from_link("none", "192.0.2.1"),
            Security::NoneToPublic
        );
    }

    /// The `?ed=N` rewrite, spelled out from Go's own arithmetic rather than
    /// from a run of it: `q.Get("ed") != ""` gates the rewrite, `Atoi` supplies
    /// the number with its error ignored, and `uint32(...)` truncates it.
    #[test]
    fn early_data_split_matches_go_arithmetic() {
        // (path, budget, path out) — the rewrite only fires on a non-empty `ed`.
        for (path, budget, want) in [
            ("/interop-ws", 0u32, "/interop-ws"),
            ("/interop-ws?a=1", 0, "/interop-ws?a=1"),
            ("/interop-ws?ed", 0, "/interop-ws?ed"),
            ("/interop-ws?ed=", 0, "/interop-ws?ed="),
            ("/interop-ws?ed=&ed=4", 0, "/interop-ws?ed=&ed=4"),
            ("/interop-ws?ed=2048", 2048, "/interop-ws"),
            ("/interop-ws?ed=2048&ed=9", 2048, "/interop-ws"),
            ("/interop-ws?ed=abc", 0, "/interop-ws"),
            ("/interop-ws?ed=2048x", 0, "/interop-ws"),
            ("/interop-ws?ed=+2048", 2048, "/interop-ws"),
            ("/interop-ws?ed=002048", 2048, "/interop-ws"),
            // A negative budget is not refused: `uint32(-1)` is 4294967295.
            ("/p?ed=-1", 4_294_967_295, "/p"),
            ("/p?ed=4294967295", 4_294_967_295, "/p"),
            ("/p?ed=4294967296", 0, "/p"),
            ("/p?ed=99999999999999999999", u32::MAX, "/p"),
            // The saturated negative bound truncates to zero, and so does Go's:
            // a `uint32` conversion keeps the low 32 bits either way.
            ("/p?ed=-99999999999999999999", 0, "/p"),
            ("/p?ed=-9223372036854775808", 0, "/p"),
            // Survivors keep their order, which is `Values.Encode`'s own answer
            // for a query that is already sorted — and the only shape of query a
            // `ws` server can serve, since it matches on a query-free path.
            ("/p?a=1&ed=4&b=2", 4, "/p?a=1&b=2"),
            ("/?ed=1", 1, "/"),
            // An empty pair carries no key and no value, so it goes too — which is
            // `ZeroNet`'s answer and not `Xray-core`'s, whose `Values.Encode` writes
            // that pair back as a bare `=`. No request can carry either one.
            ("/p?ed=4&", 4, "/p"),
            // The fragment is taken before the query, so a `?` inside it is not
            // a query and a rewrite keeps what is behind one.
            ("/p#tag?ed=4", 0, "/p#tag?ed=4"),
            ("/p?ed=4#tag", 4, "/p#tag"),
        ] {
            assert_eq!(
                EarlyData::split(path),
                EarlyData {
                    path: want.to_owned(),
                    budget,
                },
                "{path}"
            );
        }
    }

    /// `Atoi`'s three answers, since the rewrite above depends on all three.
    #[test]
    fn atoi_reproduces_the_three_answers() {
        for (text, want) in [
            ("0", 0i64),
            ("2048", 2048),
            ("+2048", 2048),
            ("-0", 0),
            ("2048abc", 0),
            ("abc", 0),
            ("", 0),
            ("-", 0),
            ("+", 0),
            ("9223372036854775807", i64::MAX),
            ("9223372036854775808", i64::MAX),
            ("-9223372036854775808", i64::MIN),
            ("-9223372036854775809", i64::MIN),
        ] {
            assert_eq!(atoi(text), want, "{text}");
        }
    }

    /// The `RFC 4648` vectors for the url-safe alphabet, arithmetic shown: each
    /// group is three bytes read big-endian into 24 bits, split into four
    /// six-bit digits, and the last group's unused low bits are dropped.
    #[test]
    fn early_data_base64url_matches_rfc_4648() {
        for (bytes, want) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg"),
            (&b"fooba"[..], "Zm9vYmE"),
            (&b"foobar"[..], "Zm9vYmFy"),
            // The two digits the url alphabet exists for, and both positions a
            // partial group can put them in: `0xff 0xff 0x00` is six ones three
            // times over, and `0xff 0x00` leaves a two-bit group that still
            // carries one.
            (&[0xff, 0xff, 0x00][..], "__8A"),
            (&[0xff, 0x00][..], "_wA"),
            (&[0xfb, 0xef, 0xbe][..], "----"),
            // Every digit's low six bits, so a shifted alphabet shows up.
            (&[0x00, 0x10, 0x83][..], "ABCD"),
        ] {
            let mut out = String::from("prefix:");
            early_encode_into(&mut out, bytes);
            assert_eq!(out, format!("prefix:{want}"), "{bytes:?}");
            assert_eq!(early_decode(want).as_deref(), Some(bytes), "{want}");
        }
    }

    /// The codec round-trips at every length, and decodes what a peer may write
    /// that is not what we write: the standard alphabet, and a padded tail.
    #[test]
    fn early_data_base64url_round_trips_every_length() {
        for len in 0..=192usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
            let mut out = String::new();
            early_encode_into(&mut out, &bytes);
            assert!(!out.contains('='), "{len}: no padding");
            assert!(
                !out.contains('+') && !out.contains('/'),
                "{len}: url alphabet"
            );
            // Four digits per three bytes and then none for the bytes that are
            // not there: `⌈4n/3⌉`, which is 2 for one byte and 3 for two.
            assert_eq!(
                out.len(),
                (len * 4).div_ceil(3),
                "{len}: four per three, less padding"
            );
            assert_eq!(early_decode(&out).as_deref(), Some(&bytes[..]), "{len}");
        }
        assert_eq!(
            early_decode("Zm9vYg==").as_deref(),
            Some(&b"foob"[..]),
            "a padded peer is still a peer"
        );
        assert_eq!(early_decode("--8").as_deref(), Some(&[0xfb, 0xef][..]));
        assert_eq!(early_decode("abcde"), None, "five is not a base64 length");
        assert_eq!(early_decode("ab*d"), None, "a digit base64 does not have");
        assert_eq!(early_decode(""), Some(Vec::new()));
    }
}
