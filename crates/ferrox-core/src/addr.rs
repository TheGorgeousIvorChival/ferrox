//! The address codec, once: `VLESS` and [`crate::mux`] both write the same
//! bytes, and upstream keeps three copies of them in one file.
//!
//! The field is a family byte and then four octets, one length byte and that
//! many domain bytes, or sixteen octets. Both callers put the two-byte port
//! immediately *before* the family byte; the only thing they disagree about is
//! the one network byte mux writes in front of the port, and that belongs to the
//! caller rather than here.
//!
//! # What is not duplicated here
//!
//! Xray-core's mux writes the target, source and local addresses out inline
//! three times and reads all three back inline three times — six copies of one
//! codec in a single file, each with its own error message — and pays a pooled
//! 8 KiB buffer per address to move at most eighteen bytes through it. A codec
//! written once, that answers its own length and reads over a borrowed slice, is
//! smaller than any one of the six and is the only thing either caller needs.
//!
//! # Licence
//!
//! Parsed, not copied. An address field is a wire format, not an implementation,
//! so re-deriving it here is licence-clean; see the same note in
//! [`crate::vless`].

/// Family byte of a four-octet address.
pub const IPV4: u8 = 0x01;
/// Family byte of a length-prefixed domain.
pub const DOMAIN: u8 = 0x02;
/// Family byte of a sixteen-octet address.
pub const IPV6: u8 = 0x03;

/// The longest domain the one-byte length field can name.
pub const MAX_DOMAIN: usize = 255;

/// Why [`Addr::take`] refused a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyError {
    /// A family byte the format does not name, kept so the caller can report it.
    Unknown(u8),
    /// The buffer ends inside the field.
    Short,
}

/// A host classified once, as the family byte and the bytes that follow it.
///
/// `of` decides; `wire_len`, `encode_into` and `take` answer from what it
/// decided and from nothing else. A caller can size a buffer from `wire_len` and
/// fill it from `encode_into` without ever looking at the host string again,
/// which is the whole reason the classification is a value rather than a
/// question asked twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addr<'a> {
    /// Four octets, family [`IPV4`].
    V4([u8; 4]),
    /// Sixteen octets, family [`IPV6`].
    V6([u8; 16]),
    /// Domain bytes already cut to [`MAX_DOMAIN`], family [`DOMAIN`].
    Name(&'a [u8]),
}

impl<'a> Addr<'a> {
    /// Classify `host` the way the wire format does, parsing at most once.
    ///
    /// An `IPv4` literal never contains `:` and an `IPv6` literal always does, so
    /// only one parse is ever attempted: a name pays one failed parse, each
    /// literal one successful one, and a mistaken `host:port` falls through to a
    /// name rather than to a half-parsed address.
    #[must_use]
    pub fn of(host: &'a str) -> Self {
        if host.contains(':') {
            if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
                return Self::V6(ip.octets());
            }
        } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Self::V4(ip.octets());
        }
        // Cut here rather than at the encode: the one byte that names a domain's
        // length then cannot overflow, so no frame downstream has to check for it.
        let bytes = host.as_bytes();
        Self::Name(&bytes[..bytes.len().min(MAX_DOMAIN)])
    }

    /// Field bytes on the wire, *including* the family byte.
    ///
    /// A domain is one longer than it looks, because its length byte is inside
    /// the count, and a name never costs the four an `Ipv4Addr` would.
    #[must_use]
    pub const fn wire_len(&self) -> usize {
        match self {
            Self::V4(_) => 1 + 4,
            Self::V6(_) => 1 + 16,
            Self::Name(bytes) => 1 + 1 + bytes.len(),
        }
    }

    /// The address bytes without the family byte: four octets, sixteen, or the
    /// domain exactly as written.
    ///
    /// What [`Self::wire_len`] counts minus the family byte, handed back as a
    /// slice so a caller that has just classified a host can hand its bytes to
    /// something that wants an address rather than a host.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        match self {
            Self::V4(octets) => octets,
            Self::V6(octets) => octets,
            Self::Name(bytes) => bytes,
        }
    }

    /// Write the family byte and the address into `out`, returning bytes written.
    ///
    /// # Panics
    ///
    /// If `out` is shorter than [`Self::wire_len`].
    pub fn encode_into(&self, out: &mut [u8]) -> usize {
        assert!(out.len() >= self.wire_len(), "address buffer too short");
        match self {
            Self::V4(octets) => {
                out[0] = IPV4;
                out[1..5].copy_from_slice(octets);
                5
            }
            Self::V6(octets) => {
                out[0] = IPV6;
                out[1..17].copy_from_slice(octets);
                17
            }
            Self::Name(bytes) => {
                out[0] = DOMAIN;
                out[1] = bytes.len() as u8;
                out[2..2 + bytes.len()].copy_from_slice(bytes);
                2 + bytes.len()
            }
        }
    }

    /// Read one address off the front of `buf`, with the bytes it used.
    ///
    /// `buf` is `&'a` and not elided because what comes back borrows it: a
    /// `Name` hands the caller a slice of the caller's own buffer rather than a
    /// copy of it, which is the whole reason this direction allocates nothing.
    ///
    /// `#[inline]` because this is a match and a slice read, and it is called
    /// three times for a bridge's frame — from the other crate, where without the
    /// hint each of those is a real call.
    #[inline]
    pub fn take(buf: &'a [u8]) -> Result<(Self, usize), FamilyError> {
        let Some((&family, rest)) = buf.split_first() else {
            return Err(FamilyError::Short);
        };
        let (addr, body) = match family {
            IPV4 => (Self::V4(fixed::<4>(rest).ok_or(FamilyError::Short)?), 4),
            IPV6 => (Self::V6(fixed::<16>(rest).ok_or(FamilyError::Short)?), 16),
            DOMAIN => {
                let (&n, tail) = rest.split_first().ok_or(FamilyError::Short)?;
                let n = usize::from(n);
                (Self::Name(tail.get(..n).ok_or(FamilyError::Short)?), 1 + n)
            }
            other => return Err(FamilyError::Unknown(other)),
        };
        Ok((addr, 1 + body))
    }
}

/// The first `N` bytes of `b` as an array, or `None` when it is shorter.
fn fixed<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    let head = b.get(..N)?;
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_families_encode_to_the_bytes_the_field_defines() {
        let mut buf = [0u8; 17];

        let v4 = Addr::of("192.0.2.53");
        assert_eq!(v4.wire_len(), 5);
        assert_eq!(v4.encode_into(&mut buf), 5);
        assert_eq!(&buf[..5], &[IPV4, 192, 0, 2, 53]);

        let v6 = Addr::of("2001:db8::1");
        assert_eq!(v6.wire_len(), 17);
        assert_eq!(v6.encode_into(&mut buf), 17);
        assert_eq!(
            &buf[..17],
            &[IPV6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        let name = Addr::of("example.com");
        // Family, the domain's own length, then eleven bytes: thirteen, which is
        // one more than the name looks and the thing a caller sizing a buffer has
        // to be told.
        assert_eq!(name.wire_len(), 13);
        assert_eq!(name.encode_into(&mut buf), 13);
        assert_eq!(&buf[..13], b"\x02\x0bexample.com");
    }

    #[test]
    fn every_host_round_trips_through_its_own_bytes() {
        for host in ["192.0.2.53", "2001:db8::1", "example.com", "a", "x.test"] {
            let addr = Addr::of(host);
            let mut buf = [0u8; 17];
            let n = addr.encode_into(&mut buf);
            assert_eq!(Addr::take(&buf[..n]), Ok((addr, n)), "{host}");
        }
    }

    #[test]
    fn a_domain_longer_than_the_length_byte_is_cut_not_wrapped() {
        // Upstream admits 256 and writes a zero length byte, which turns the
        // domain into "whatever follows". The cut happens at classification, so
        // that frame cannot be built.
        let long = "d".repeat(MAX_DOMAIN + 1);
        let addr = Addr::of(&long);
        assert!(matches!(addr, Addr::Name(b) if b.len() == MAX_DOMAIN));
        let mut buf = [0u8; MAX_DOMAIN + 2];
        let n = addr.encode_into(&mut buf);
        assert_eq!(buf[1], u8::try_from(MAX_DOMAIN).expect("255 fits a byte"));
        assert_eq!(Addr::take(&buf[..n]), Ok((addr, n)));
    }

    #[test]
    fn take_tells_a_bad_family_byte_from_a_short_field() {
        assert_eq!(Addr::take(&[]), Err(FamilyError::Short));
        assert_eq!(Addr::take(&[IPV4, 1, 2, 3]), Err(FamilyError::Short));
        assert_eq!(Addr::take(&[IPV6, 0, 0, 0, 0]), Err(FamilyError::Short));
        assert_eq!(Addr::take(&[DOMAIN]), Err(FamilyError::Short));
        assert_eq!(
            Addr::take(&[DOMAIN, 4, b'a', b'b']),
            Err(FamilyError::Short)
        );
        assert_eq!(
            Addr::take(&[0xff, 1, 2, 3, 4]),
            Err(FamilyError::Unknown(0xff))
        );
    }
}
