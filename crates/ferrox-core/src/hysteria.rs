//! Hysteria version 2 framing: the bytes around the QUIC streams, not the streams.
//!
//! Every TCP flow is one bidirectional QUIC stream starting with the `0x401`
//! type as a QUIC variable-length integer, and the connection opens with an
//! HTTP/3 `POST` to `/auth` carrying the password, answered by status `233`.
//! UDP datagrams are `BE32` session ids ahead of the payload for the layer that
//! relays them; this layer parses them and carries no UDP flows itself.

use crate::foxy::{frames, hpack};

pub const TCP_FRAME: u64 = 0x401;

pub const AUTH_STATUS: u16 = 233;

pub const AUTH_PATH: &str = "/auth";

pub const AUTH_HEADER: &str = "hysteria-auth";

pub const CC_RX_HEADER: &str = "hysteria-cc-rx";

pub const UDP_HEADER: &str = "hysteria-udp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    Reno,
    Bbr,
    Brutal,
}

impl Congestion {
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text {
            "reno" => Self::Reno,
            "brutal" | "force-brutal" => Self::Brutal,
            _ => Self::Bbr,
        }
    }

    #[must_use]
    pub fn quiche_name(self) -> &'static str {
        match self {
            Self::Reno => "reno",
            Self::Bbr | Self::Brutal => "bbr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub auth: String,
    pub cc: Congestion,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: String::new(),
            cc: Congestion::Bbr,
        }
    }
}

pub fn tcp_prefix(out: &mut Vec<u8>) {
    frames::quic_varint(out, TCP_FRAME);
}

#[must_use]
pub fn read_tcp_prefix(packet: &[u8]) -> Option<usize> {
    let mut at = 0usize;
    (frames::quic_read(packet, &mut at) == Some(TCP_FRAME)).then_some(at)
}

pub fn wrap_dgram(session: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(payload);
}

#[must_use]
pub fn open_dgram(packet: &[u8]) -> Option<(u32, &[u8])> {
    let (id, body) = packet.split_at_checked(4)?;
    Some((u32::from_be_bytes([id[0], id[1], id[2], id[3]]), body))
}

pub fn build_auth_request(host: &str, auth: &str, out: &mut Vec<u8>) {
    hpack::qpack_literal_many(
        &[
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", host),
            (":path", AUTH_PATH),
            (AUTH_HEADER, auth),
            (CC_RX_HEADER, "0"),
        ],
        out,
    );
}

pub fn build_auth_response(out: &mut Vec<u8>) {
    hpack::qpack_literal_many(
        &[
            (":status", "233"),
            (UDP_HEADER, "false"),
            (CC_RX_HEADER, "0"),
        ],
        out,
    );
}

fn find<'a>(fields: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(key, _)| key == name.as_bytes())
        .map(|(_, value)| value.as_slice())
}

#[must_use]
pub fn verify_auth_request(block: &[u8], expected_auth: &str) -> bool {
    if expected_auth.is_empty() {
        return false;
    }
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    find(&fields, ":method") == Some(b"POST".as_slice())
        && find(&fields, ":path") == Some(AUTH_PATH.as_bytes())
        && find(&fields, AUTH_HEADER) == Some(expected_auth.as_bytes())
}

#[must_use]
pub fn verify_auth_response(block: &[u8]) -> bool {
    let Some(fields) = hpack::qpack_fields(block) else {
        return false;
    };
    find(&fields, ":status") == Some(b"233".as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tcp_frame_type_is_two_bytes_on_the_wire() {
        let mut out = Vec::new();
        tcp_prefix(&mut out);
        assert_eq!(out, vec![0x44, 0x01]);
        assert_eq!(read_tcp_prefix(&out), Some(2));
        assert_eq!(read_tcp_prefix(&[0x44]), None);
        assert_eq!(read_tcp_prefix(&[0x40, 0x01]), None);
        assert_eq!(read_tcp_prefix(&[0x44, 0x01, 0x00]), Some(2));
    }

    #[test]
    fn a_datagram_is_a_session_id_ahead_of_its_payload() {
        let mut out = Vec::new();
        wrap_dgram(1, b"ping", &mut out);
        assert_eq!(out, vec![0, 0, 0, 1, b'p', b'i', b'n', b'g']);
        assert_eq!(open_dgram(&out), Some((1, b"ping".as_slice())));
        let mut empty = Vec::new();
        wrap_dgram(u32::MAX, b"", &mut empty);
        assert_eq!(open_dgram(&empty), Some((u32::MAX, &[][..])));
        assert_eq!(open_dgram(&[0, 0, 0]), None);
        assert_eq!(open_dgram(&[]), None);
    }

    #[test]
    fn an_auth_request_carries_post_auth_and_no_brutal_cap() {
        let mut block = Vec::new();
        build_auth_request("edge.example:443", "s3cret", &mut block);
        assert!(verify_auth_request(&block, "s3cret"));
        assert!(!verify_auth_request(&block, "wrong"));
        assert!(!verify_auth_request(&block, ""));
        let fields = hpack::qpack_fields(&block).expect("reads");
        assert_eq!(fields.len(), 6);
        assert!(fields.contains(&(b":method".to_vec(), b"POST".to_vec())));
        assert!(fields.contains(&(b":path".to_vec(), b"/auth".to_vec())));
        assert!(fields.contains(&(b"hysteria-cc-rx".to_vec(), b"0".to_vec())));
    }

    #[test]
    fn an_auth_request_with_the_wrong_shape_is_refused() {
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "GET"),
                (":path", "/auth"),
                (AUTH_HEADER, "s3cret"),
            ],
            &mut block,
        );
        assert!(!verify_auth_request(&block, "s3cret"));
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[
                (":method", "POST"),
                (":path", "/other"),
                (AUTH_HEADER, "s3cret"),
            ],
            &mut block,
        );
        assert!(!verify_auth_request(&block, "s3cret"));
        assert!(!verify_auth_request(&[0x01, 0x00], "s3cret"));
    }

    #[test]
    fn an_auth_response_is_status_233_and_nothing_else_counts() {
        let mut block = Vec::new();
        build_auth_response(&mut block);
        assert!(verify_auth_response(&block));
        let mut block = Vec::new();
        hpack::qpack_literal_many(&[(":status", "200")], &mut block);
        assert!(!verify_auth_response(&block));
        assert!(!verify_auth_response(&[0x00]));
    }

    #[test]
    fn congestion_spellings_map_to_the_paced_default() {
        assert_eq!(Congestion::parse("reno"), Congestion::Reno);
        assert_eq!(Congestion::parse("bbr"), Congestion::Bbr);
        assert_eq!(Congestion::parse("brutal"), Congestion::Brutal);
        assert_eq!(Congestion::parse("force-brutal"), Congestion::Brutal);
        assert_eq!(Congestion::parse(""), Congestion::Bbr);
        assert_eq!(Congestion::parse("cubic"), Congestion::Bbr);
        assert_eq!(Congestion::Reno.quiche_name(), "reno");
        assert_eq!(Congestion::Bbr.quiche_name(), "bbr");
        assert_eq!(Congestion::Brutal.quiche_name(), "bbr");
    }
}
