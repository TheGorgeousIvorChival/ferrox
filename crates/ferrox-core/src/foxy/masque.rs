//! MASQUE CONNECT-UDP over the HTTP/2 edge: one UDP target per stream.
//!
//! The request shape is RFC 9298 §3.4 (extended CONNECT with
//! `:protocol = connect-udp` and the default URI template) and the datagrams
//! are RFC 9297 §3.5 DATAGRAM capsules carrying RFC 9298 §5 payloads
//! (context 0 plus the UDP bytes). Arithmetic only, like the rest of this
//! module: nothing here opens a socket.

use super::frames::{quic_read, quic_varint};
use super::hpack::integer;

/// The default URI template's path for one target, RFC 9298 §2: only a colon
/// is encoded, because a target host is a DNS name, an IPv4 literal, or an
/// IPv6 literal, and of those only IPv6 uses one.
pub fn udp_path(target_host: &str, target_port: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(b"/.well-known/masque/udp/");
    for byte in target_host.bytes() {
        if byte == b':' {
            out.extend_from_slice(b"%3A");
        } else {
            out.push(byte);
        }
    }
    out.push(b'/');
    let mut port = target_port;
    let mut digits = [0u8; 5];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (port % 10) as u8;
        port /= 10;
        if port == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
    out.push(b'/');
}

fn literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x00);
    integer(out, 7, 0x00, name.len());
    out.extend_from_slice(name);
    integer(out, 7, 0x00, value.len());
    out.extend_from_slice(value);
}

/// One CONNECT-UDP request: the extended-CONNECT fields in the RFC's own
/// order, the edge as the authority, the default template as the path, and
/// the account's pass as a `Bearer` token, which is the shape the edge
/// answers on the TCP lane already.
pub fn connect_udp(
    edge_authority: &str,
    target_host: &str,
    target_port: u16,
    bearer: &str,
    out: &mut Vec<u8>,
) {
    literal(out, b":method", b"CONNECT");
    literal(out, b":protocol", b"connect-udp");
    literal(out, b":scheme", b"https");
    literal(out, b":authority", edge_authority.as_bytes());
    let mut path = Vec::with_capacity(32 + target_host.len());
    udp_path(target_host, target_port, &mut path);
    literal(out, b":path", &path);
    let mut auth = Vec::with_capacity(7 + bearer.len());
    auth.extend_from_slice(b"Bearer ");
    auth.extend_from_slice(bearer.as_bytes());
    literal(out, b"proxy-authorization", &auth);
    literal(out, b"capsule-protocol", b"?1");
}

/// One UDP payload as one DATAGRAM capsule: type zero, the context byte zero,
/// then the bytes unchanged.
pub fn datagram_encode(payload: &[u8], out: &mut Vec<u8>) {
    out.push(0x00);
    quic_varint(out, 1 + payload.len() as u64);
    out.push(0x00);
    out.extend_from_slice(payload);
}

/// The first complete DATAGRAM capsule in a stream buffer: bytes consumed and
/// the UDP payload, or `None` when the capsule is not whole yet. Capsules of
/// an unknown type and datagrams of a nonzero context are skipped rather than
/// refused, because neither carries bytes this lane reads.
#[must_use]
pub fn datagram_split(buf: &[u8]) -> Option<(usize, &[u8])> {
    let mut at = 0usize;
    while at < buf.len() {
        let capsule = quic_read(buf, &mut at)?;
        let length = quic_read(buf, &mut at)? as usize;
        let end = at.checked_add(length)?;
        let value = buf.get(at..end)?;
        if capsule == 0 {
            let mut context_at = 0usize;
            if quic_read(value, &mut context_at) == Some(0) {
                return Some((end, &value[context_at..]));
            }
        }
        if end == at {
            return None;
        }
        at = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_template_path_names_its_target_and_encodes_only_colons() {
        let mut out = Vec::new();
        udp_path("example.com", 443, &mut out);
        assert_eq!(out, b"/.well-known/masque/udp/example.com/443/");
        out.clear();
        udp_path("192.0.2.6", 53, &mut out);
        assert_eq!(out, b"/.well-known/masque/udp/192.0.2.6/53/");
        out.clear();
        udp_path("2001:db8::42", 443, &mut out);
        assert_eq!(out, b"/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/");
    }

    #[test]
    fn a_connect_udp_block_carries_protocol_path_and_bearer() {
        let mut block = Vec::new();
        connect_udp(
            "edge.example:2499",
            "example.com",
            443,
            "the-pass",
            &mut block,
        );
        let text = String::from_utf8_lossy(&block);
        for field in [
            "CONNECT",
            "connect-udp",
            "https",
            "edge.example:2499",
            "/.well-known/masque/udp/example.com/443/",
            "Bearer the-pass",
            "capsule-protocol",
            "?1",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        assert_eq!(super::super::hpack::hpack_status(&block), None);
    }

    #[test]
    fn a_datagram_round_trips_split_anywhere() {
        let payload: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let mut coded = Vec::new();
        datagram_encode(&payload, &mut coded);
        for cut in [1, 2, 3, 5, 10, 100] {
            let cut = cut.min(coded.len() - 1);
            assert_eq!(datagram_split(&coded[..cut]), None, "cut at {cut}");
        }
        let (used, back) = datagram_split(&coded).expect("whole");
        assert_eq!((used, back), (coded.len(), payload.as_slice()));
    }

    #[test]
    fn capsules_this_lane_does_not_read_are_skipped_not_refused() {
        let mut buf = Vec::new();
        buf.push(0x17);
        quic_varint(&mut buf, 3);
        buf.extend_from_slice(b"abc");
        buf.push(0x00);
        quic_varint(&mut buf, 3);
        buf.push(0x02);
        buf.extend_from_slice(b"xy");
        let mut good = Vec::new();
        datagram_encode(b"ok", &mut good);
        buf.extend_from_slice(&good);
        let (used, back) = datagram_split(&buf).expect("skips to the datagram");
        assert_eq!((used, back.len()), (buf.len(), 2));
        assert_eq!(back, b"ok");
    }
}
