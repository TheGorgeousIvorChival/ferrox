//! Hysteria version 2 framing: the bytes around the QUIC streams, not the streams.
//!
//! Every TCP flow is one bidirectional QUIC stream starting with the `0x401`
//! type as a QUIC variable-length integer, then a request carrying the target
//! as `host:port` text and answered by a status response. The connection opens
//! with an HTTP/3 `POST` to `/auth` carrying the password, answered by status
//! `233`. UDP flows are QUIC datagrams carrying their own destination, with
//! fragmentation for payloads past the path's datagram cap.
//!
//! This layer parses all of it and dials none of it: padding bytes are
//! caller-supplied (the app randomises them) and address text is returned as
//! borrowed text (resolution is the app's job, and this crate resolves
//! nothing).

use crate::foxy::{frames, hpack};

pub const TCP_FRAME: u64 = 0x401;

pub const AUTH_STATUS: u16 = 233;

pub const AUTH_PATH: &str = "/auth";

pub const AUTH_HEADER: &str = "hysteria-auth";

pub const CC_RX_HEADER: &str = "hysteria-cc-rx";

pub const UDP_HEADER: &str = "hysteria-udp";

// Bounds mirrored from the pinned implementation: an address past 2048 bytes
// or padding past 4096 is a refused request, not a longer read.
pub const TCP_ADDR_MAX: usize = 2048;
pub const TCP_MSG_MAX: usize = 2048;
pub const TCP_PAD_MAX: usize = 4096;

// Padding lengths the app randomises per request and response.
pub const REQ_PAD_MIN: usize = 64;
pub const REQ_PAD_MAX: usize = 512;
pub const RESP_PAD_MIN: usize = 128;
pub const RESP_PAD_MAX: usize = 1024;

// UDP header ahead of the address: session, packet, fragment id and count.
pub const UDP_HEAD_LEN: usize = 8;

// A reassembled datagram never exceeds one UDP payload.
pub const UDP_REASSEMBLED_MAX: usize = 65535;

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

// A TCP request is the address length, the `host:port` text, then the padding
// length and the padding. Lengths outside the bounds are refused, never
// written: a request that cannot be read back is not a request.
#[must_use]
pub fn encode_tcp_request(addr: &str, padding: &[u8], out: &mut Vec<u8>) -> bool {
    if addr.is_empty() || addr.len() > TCP_ADDR_MAX || padding.len() > TCP_PAD_MAX {
        return false;
    }
    frames::quic_varint(out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    frames::quic_varint(out, padding.len() as u64);
    out.extend_from_slice(padding);
    true
}

// Returns the target text and the bytes the request occupies; trailing bytes
// are the flow's payload, not a second request.
#[must_use]
pub fn decode_tcp_request(packet: &[u8]) -> Option<(&str, usize)> {
    let mut at = 0usize;
    let addr_len = frames::quic_read(packet, &mut at)? as usize;
    if addr_len == 0 || addr_len > TCP_ADDR_MAX {
        return None;
    }
    let addr = packet.get(at..at + addr_len)?;
    at += addr_len;
    let pad_len = frames::quic_read(packet, &mut at)? as usize;
    if pad_len > TCP_PAD_MAX {
        return None;
    }
    packet.get(at..at + pad_len)?;
    at += pad_len;
    Some((core::str::from_utf8(addr).ok()?, at))
}

// A TCP response is one status byte, the message, then the padding. The
// message is empty on the flows this tree opens.
#[must_use]
pub fn encode_tcp_response(ok: bool, msg: &str, padding: &[u8], out: &mut Vec<u8>) -> bool {
    if msg.len() > TCP_MSG_MAX || padding.len() > TCP_PAD_MAX {
        return false;
    }
    out.push(u8::from(!ok));
    frames::quic_varint(out, msg.len() as u64);
    out.extend_from_slice(msg.as_bytes());
    frames::quic_varint(out, padding.len() as u64);
    out.extend_from_slice(padding);
    true
}

#[must_use]
pub fn decode_tcp_response(packet: &[u8]) -> Option<(bool, &str, usize)> {
    let (status, rest) = packet.split_first()?;
    let mut at = 0usize;
    let msg_len = frames::quic_read(rest, &mut at)? as usize;
    if msg_len > TCP_MSG_MAX {
        return None;
    }
    let msg = rest.get(at..at + msg_len)?;
    at += msg_len;
    let pad_len = frames::quic_read(rest, &mut at)? as usize;
    if pad_len > TCP_PAD_MAX {
        return None;
    }
    rest.get(at..at + pad_len)?;
    at += pad_len;
    Some((*status == 0, core::str::from_utf8(msg).ok()?, 1 + at))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    pub session: u32,
    pub packet: u16,
    pub frag: u8,
    pub count: u8,
    pub addr: &'a str,
    pub data: &'a [u8],
}

// A UDP datagram carries its own destination: session, packet and fragment
// ids, then the address length, the `host:port` text, then the payload.
#[must_use]
pub fn encode_udp_message(msg: &UdpMessage<'_>, out: &mut Vec<u8>) -> bool {
    if msg.count == 0
        || msg.frag >= msg.count
        || msg.addr.is_empty()
        || msg.addr.len() > TCP_ADDR_MAX
    {
        return false;
    }
    out.extend_from_slice(&msg.session.to_be_bytes());
    out.extend_from_slice(&msg.packet.to_be_bytes());
    out.push(msg.frag);
    out.push(msg.count);
    frames::quic_varint(out, msg.addr.len() as u64);
    out.extend_from_slice(msg.addr.as_bytes());
    out.extend_from_slice(msg.data);
    true
}

#[must_use]
pub fn decode_udp_message(packet: &[u8]) -> Option<UdpMessage<'_>> {
    let head = packet.get(..UDP_HEAD_LEN)?;
    let session = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
    let number = u16::from_be_bytes([head[4], head[5]]);
    let (frag, count) = (head[6], head[7]);
    if count == 0 || frag >= count {
        return None;
    }
    let mut at = UDP_HEAD_LEN;
    let addr_len = frames::quic_read(packet, &mut at)? as usize;
    if addr_len == 0 || addr_len > TCP_ADDR_MAX {
        return None;
    }
    let addr = packet.get(at..at + addr_len)?;
    at += addr_len;
    let data = packet.get(at..)?;
    if data.is_empty() {
        return None;
    }
    Some(UdpMessage {
        session,
        packet: number,
        frag,
        count,
        addr: core::str::from_utf8(addr).ok()?,
        data,
    })
}

// Reassembles one fragmented packet at a time; a fragment for another packet
// discards what came before. Single datagrams never touch the state.
#[derive(Debug, Default)]
pub struct Reassembler {
    packet: u16,
    count: u8,
    got: u8,
    parts: Vec<(u8, Vec<u8>)>,
    size: usize,
}

impl Reassembler {
    #[must_use]
    pub fn feed(&mut self, msg: &UdpMessage<'_>) -> Option<Vec<u8>> {
        if msg.count <= 1 {
            return Some(msg.data.to_vec());
        }
        if msg.packet != self.packet || msg.count != self.count {
            self.packet = msg.packet;
            self.count = msg.count;
            self.got = 0;
            self.parts.clear();
            self.size = 0;
        }
        if self.parts.iter().any(|(frag, _)| *frag == msg.frag) {
            return None;
        }
        if self.size + msg.data.len() > UDP_REASSEMBLED_MAX {
            self.count = 0;
            self.parts.clear();
            self.size = 0;
            return None;
        }
        self.parts.push((msg.frag, msg.data.to_vec()));
        self.size += msg.data.len();
        self.got += 1;
        if self.got != self.count {
            return None;
        }
        let mut out = Vec::with_capacity(self.size);
        for frag in 0..self.count {
            let (_, data) = self.parts.iter().find(|(id, _)| *id == frag)?;
            out.extend_from_slice(data);
        }
        self.count = 0;
        self.parts.clear();
        self.size = 0;
        Some(out)
    }
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
    fn a_tcp_request_is_an_address_then_padding() {
        let mut out = Vec::new();
        assert!(encode_tcp_request("198.51.100.7:53", &[9u8; 64], &mut out));
        let (addr, used) = decode_tcp_request(&out).expect("reads");
        assert_eq!(addr, "198.51.100.7:53");
        assert_eq!(used, out.len());
        assert!(!encode_tcp_request("", &[0u8; 64], &mut Vec::new()));
        assert!(!encode_tcp_request("a:1", &[0u8; TCP_PAD_MAX + 1], &mut Vec::new()));
        assert_eq!(decode_tcp_request(&[0]), None);
    }

    #[test]
    fn a_tcp_request_with_payload_after_it_reads_to_the_padding_end() {
        let mut out = Vec::new();
        assert!(encode_tcp_request("example.com:443", &[], &mut out));
        out.extend_from_slice(b"payload");
        let (addr, used) = decode_tcp_request(&out).expect("reads");
        assert_eq!(addr, "example.com:443");
        assert_eq!(&out[used..], b"payload");
    }

    #[test]
    fn a_tcp_response_is_a_status_then_a_message() {
        let mut out = Vec::new();
        assert!(encode_tcp_response(true, "", &[7u8; 128], &mut out));
        let (ok, msg, used) = decode_tcp_response(&out).expect("reads");
        assert!(ok);
        assert_eq!(msg, "");
        assert_eq!(used, out.len());
        let mut out = Vec::new();
        assert!(encode_tcp_response(false, "refused", &[], &mut out));
        let (ok, msg, _) = decode_tcp_response(&out).expect("reads");
        assert!(!ok);
        assert_eq!(msg, "refused");
        assert_eq!(decode_tcp_response(&[]), None);
    }

    #[test]
    fn a_udp_datagram_carries_its_own_destination() {
        let mut out = Vec::new();
        let msg = UdpMessage {
            session: 7,
            packet: 3,
            frag: 0,
            count: 1,
            addr: "198.51.100.7:53",
            data: b"ping",
        };
        assert!(encode_udp_message(&msg, &mut out));
        let back = decode_udp_message(&out).expect("reads");
        assert_eq!(back, msg);
        assert_eq!(decode_udp_message(&out[..7]), None);
        assert_eq!(decode_udp_message(&[0, 0, 0, 1, 0, 0, 0, 0]), None);
    }

    #[test]
    fn fragments_reassemble_in_arrival_order() {
        let mut keep = Reassembler::default();
        let first = UdpMessage {
            session: 1,
            packet: 9,
            frag: 1,
            count: 2,
            addr: "a:1",
            data: b"second",
        };
        let mut wire = Vec::new();
        assert!(encode_udp_message(&first, &mut wire));
        let got = decode_udp_message(&wire).expect("reads");
        assert_eq!(keep.feed(&got), None);
        let second = UdpMessage {
            session: 1,
            packet: 9,
            frag: 0,
            count: 2,
            addr: "a:1",
            data: b"first-",
        };
        wire.clear();
        assert!(encode_udp_message(&second, &mut wire));
        let got = decode_udp_message(&wire).expect("reads");
        assert_eq!(keep.feed(&got), Some(b"first-second".to_vec()));
        let single = UdpMessage {
            session: 1,
            packet: 10,
            frag: 0,
            count: 1,
            addr: "a:1",
            data: b"whole",
        };
        wire.clear();
        assert!(encode_udp_message(&single, &mut wire));
        let got = decode_udp_message(&wire).expect("reads");
        assert_eq!(keep.feed(&got), Some(b"whole".to_vec()));
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
            &[(":method", "GET"), (":path", "/auth"), (AUTH_HEADER, "s3cret")],
            &mut block,
        );
        assert!(!verify_auth_request(&block, "s3cret"));
        let mut block = Vec::new();
        hpack::qpack_literal_many(
            &[(":method", "POST"), (":path", "/other"), (AUTH_HEADER, "s3cret")],
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
