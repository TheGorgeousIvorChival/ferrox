//! The two header block codecs a CONNECT lane needs: HPACK for HTTP/2 and
//! QPACK for HTTP/3. A CONNECT reply carries one field this lane reads — the
//! status — so both decoders answer exactly one question and refuse everything
//! they cannot answer it from, which is every representation needing a table
//! the lane never fills. Both encoders write the literal form only: one request
//! per stream, no table state on either end, no Huffman to compute.
//!
//! Both codecs number their integers the same way, in one prefix length: a value
//! below `2^n - 1` is the low `n` bits of one byte, and anything longer is that
//! maximum followed by the remainder in base-128, high bit per byte.

use std::sync::OnceLock;

/// The HPACK Huffman code is canonical: the codes of a length are consecutive
/// and each length's codes start where the previous length's ended, shifted left.
/// So one byte per symbol — its code length — rebuilds every code, and a code
/// maps back to a symbol by its offset within its length.
const HUFFMAN_BITS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, //
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, //
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, //
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, //
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, //
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, //
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, //
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, //
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, //
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, //
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, //
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, //
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, //
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, //
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, //
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, //
    30,
];

const SHORTEST: usize = 5;
const MAX_BITS: usize = 30;

struct Huffman {
    /// The first code of each length, and how many codes share that length.
    first: [u32; MAX_BITS + 1],
    count: [u16; MAX_BITS + 1],
    /// Where each length's symbols begin in `symbols`, which is ordered by length
    /// and then by symbol, so a code is `first[length] + offset`.
    base: [u16; MAX_BITS + 1],
    symbols: [u16; 257],
}

fn huffman() -> &'static Huffman {
    static TABLE: OnceLock<Huffman> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = Huffman {
            first: [0; MAX_BITS + 1],
            count: [0; MAX_BITS + 1],
            base: [0; MAX_BITS + 1],
            symbols: [0; 257],
        };
        let mut next = 0u32;
        let mut placed = 0usize;
        let mut previous = 0usize;
        for bits in SHORTEST..=MAX_BITS {
            if !HUFFMAN_BITS.contains(&(bits as u8)) {
                continue;
            }
            next <<= bits - previous;
            previous = bits;
            table.first[bits] = next;
            table.base[bits] = placed as u16;
            for (symbol, length) in HUFFMAN_BITS.iter().enumerate() {
                if usize::from(*length) != bits {
                    continue;
                }
                table.symbols[placed] = symbol as u16;
                table.count[bits] += 1;
                placed += 1;
                next += 1;
            }
        }
        table
    })
}

/// The code of one symbol, read back out of the same table the decoder uses, so
/// the encoder the tests prove against the RFC cannot be a second source of
/// truth. Only the tests call it: a CONNECT request is written as literals.
#[cfg(test)]
fn huffman_code(symbol: usize) -> Option<(u32, usize)> {
    let bits = usize::from(HUFFMAN_BITS[symbol]);
    let table = huffman();
    let base = table.base[bits] as usize;
    let slot = table.symbols[base..base + table.count[bits] as usize]
        .iter()
        .position(|other| usize::from(*other) == symbol)?;
    Some((table.first[bits] + slot as u32, bits))
}

/// Decodes one Huffman-coded string. The 257th entry is the EOS code, which is
/// padding rather than a symbol: a block that decodes one is malformed, and the
/// all-ones prefix shorter than eight bits that a string may end on is the only
/// thing allowed after its last symbol.
fn huffman_decode(code: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let table = huffman();
    let mut acc = 0u32;
    let mut bits = 0usize;
    for byte in code {
        for shift in (0..8).rev() {
            acc = (acc << 1) | u32::from(byte >> shift & 1);
            bits += 1;
            if bits > MAX_BITS {
                return None;
            }
            let offset = acc.wrapping_sub(table.first[bits]);
            if table.count[bits] == 0 || offset >= u32::from(table.count[bits]) {
                continue;
            }
            let symbol = table.symbols[table.base[bits] as usize + offset as usize];
            if symbol == 256 {
                return None;
            }
            out.push(symbol as u8);
            acc = 0;
            bits = 0;
        }
    }
    if bits != 0 && (bits >= 8 || acc != (1 << bits) - 1) {
        return None;
    }
    Some(())
}

#[cfg(test)]
fn huffman_encode(bytes: &[u8], out: &mut Vec<u8>) {
    let mut acc = 0u64;
    let mut bits = 0u32;
    for byte in bytes {
        let Some((code, length)) = huffman_code(usize::from(*byte)) else {
            continue;
        };
        let length = length as u32;
        acc = (acc << length) | u64::from(code);
        bits += length;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits != 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
}

/// An integer in one byte carrying `prefix` low bits, continued in base-128.
fn integer(out: &mut Vec<u8>, prefix: u8, mask: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(mask | value as u8);
        return;
    }
    out.push(mask | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// The same integer as `integer`, continued into the byte the pattern already
/// occupies rather than a new one — the one form QPACK uses for a field name,
/// where the low bits of the pattern byte are the length prefix.
fn integer_into(out: &mut Vec<u8>, prefix: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    let slot = out.len() - 1;
    if value < max {
        out[slot] |= value as u8;
        return;
    }
    out[slot] |= max as u8;
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn read_integer(block: &[u8], at: &mut usize, prefix: u8) -> Option<usize> {
    let first = *block.get(*at)?;
    *at += 1;
    let max = (1usize << prefix) - 1;
    let mut value = usize::from(first & max as u8);
    if value < max {
        return Some(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *block.get(*at)?;
        *at += 1;
        if shift > 56 {
            return None;
        }
        value = value.checked_add(usize::from(byte & 0x7f).checked_shl(shift)?)?;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
}

/// One string literal, borrowed from the block when it is stored as-is and
/// owned when it arrives Huffman coded. The Huffman path allocates because a
/// status is three digits and a name this lane reads is one short literal.
enum Literal<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl Literal<'_> {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    fn is_status(&self) -> bool {
        self.as_bytes() == b":status"
    }
}

fn string_literal<'a>(block: &'a [u8], at: &mut usize) -> Option<Literal<'a>> {
    let coded = *block.get(*at)? & 0x80 != 0;
    let len = read_integer(block, at, 7)?;
    let raw = block.get(*at..at.checked_add(len)?)?;
    *at += len;
    if !coded {
        return Some(Literal::Borrowed(raw));
    }
    let mut out = Vec::with_capacity(len);
    huffman_decode(raw, &mut out)?;
    Some(Literal::Owned(out))
}

/// The `:status` entries of a static table, HPACK's from index 8 and QPACK's from
/// index 23. Every other index is a field this lane never reads, so an index
/// outside these two tables is refused rather than skipped: a block carrying one
/// is a block whose dynamic table this lane does not have.
fn static_status(index: usize, h2: bool) -> Option<u16> {
    const H2: [u16; 7] = [200, 204, 206, 304, 400, 404, 500];
    const QPACK: [u16; 6] = [103, 200, 304, 404, 503, 500];
    let (table, base) = if h2 { (&H2[..], 8) } else { (&QPACK[..], 23) };
    table.get(index.checked_sub(base)?).copied()
}

/// A three-digit decimal status, read in place rather than copied out.
fn status_of(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        u16::from(bytes[0] - b'0') * 100
            + u16::from(bytes[1] - b'0') * 10
            + u16::from(bytes[2] - b'0'),
    )
}

/// Reads the `:status` of an HPACK header block. The top three bits of a
/// representation say which of the four forms it is, and this lane implements
/// the two that carry a literal: everything else either needs a table it never
/// fills — a dynamic size update, an incremental index — or is a field it does
/// not read, which is skipped.
pub fn hpack_status(block: &[u8]) -> Option<u16> {
    let mut at = 0usize;
    let mut status = None;
    while at < block.len() {
        let first = block[at];
        let name_is_status = match first & 0xE0 {
            0x80 => {
                let index = read_integer(block, &mut at, 7)?;
                status = Some(static_status(index, true)?);
                continue;
            }
            0x40 => {
                let index = read_integer(block, &mut at, 6)?;
                if index != 8 {
                    return None;
                }
                true
            }
            0x00 => {
                at += 1;
                string_literal(block, &mut at)?.is_status()
            }
            _ => return None,
        };
        let value = string_literal(block, &mut at)?;
        if name_is_status {
            status = Some(status_of(value.as_bytes())?);
        }
    }
    status
}

/// Reads the `:status` of a QPACK header block. QPACK prefixes the block with a
/// required insert count and a delta base; a response whose block is not two
/// zero bytes names the dynamic table, which this lane does not have.
pub fn qpack_status(block: &[u8]) -> Option<u16> {
    if *block.first()? != 0 || *block.get(1)? != 0 {
        return None;
    }
    let mut at = 2usize;
    let mut status = None;
    while at < block.len() {
        let first = block[at];
        let name_is_status = if first & 0x80 != 0 {
            let index = read_integer(block, &mut at, 6)?;
            status = Some(static_status(index, false)?);
            continue;
        } else if first & 0xE0 == 0x20 {
            qpack_name(block, &mut at)?.is_status()
        } else {
            return None;
        };
        let value = string_literal(block, &mut at)?;
        if name_is_status {
            status = Some(status_of(value.as_bytes())?);
        }
    }
    status
}

/// QPACK's literal field line packs the `001` pattern, the never-indexed bit,
/// the name's Huffman bit and a three-bit name length into one byte, so the
/// name is a prefixed integer read from the byte the pattern already occupies.
fn qpack_name<'a>(block: &'a [u8], at: &mut usize) -> Option<Literal<'a>> {
    let coded = *block.get(*at)? & 0x08 != 0;
    let len = read_integer(block, at, 3)?;
    let raw = block.get(*at..at.checked_add(len)?)?;
    *at += len;
    if !coded {
        return Some(Literal::Borrowed(raw));
    }
    let mut out = Vec::with_capacity(len);
    huffman_decode(raw, &mut out)?;
    Some(Literal::Owned(out))
}

/// One CONNECT request, three fields, literal names and literal values: the
/// smallest header block a CONNECT can be written in.
pub fn hpack_connect(target: &str, bearer: &str, out: &mut Vec<u8>) {
    for (name, value) in [
        (":method", "CONNECT"),
        (":authority", target),
        ("proxy-authorization", bearer),
    ] {
        out.push(0x00);
        integer(out, 7, 0x00, name.len());
        out.extend_from_slice(name.as_bytes());
        integer(out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
}

/// The same three fields under QPACK, whose block starts with a required insert
/// count of zero and names its fields with the `001` literal pattern.
pub fn qpack_connect(target: &str, bearer: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x00, 0x00]);
    for (name, value) in [
        (":method", "CONNECT"),
        (":authority", target),
        ("proxy-authorization", bearer),
    ] {
        out.push(0x20);
        integer_into(out, 3, name.len());
        out.extend_from_slice(name.as_bytes());
        integer(out, 7, 0x00, value.len());
        out.extend_from_slice(value.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One QPACK literal field line, written the way a peer would write it.
    fn qpack_literal_coded(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        if block.is_empty() {
            block.extend_from_slice(&[0x00, 0x00]);
        }
        block.push(0x20);
        integer_into(block, 3, name.len());
        block.extend_from_slice(name.as_bytes());
        block.push(0x80 | value.len() as u8);
        block.extend_from_slice(value);
    }

    fn qpack_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        if block.is_empty() {
            block.extend_from_slice(&[0x00, 0x00]);
        }
        block.push(0x20);
        integer_into(block, 3, name.len());
        block.extend_from_slice(name.as_bytes());
        integer(block, 7, 0x00, value.len());
        block.extend_from_slice(value);
    }

    /// One HPACK literal field line with a literal name, the form this lane writes.
    fn hpack_literal(block: &mut Vec<u8>, name: &str, value: &[u8]) {
        block.push(0x00);
        integer(block, 7, 0x00, name.len());
        block.extend_from_slice(name.as_bytes());
        integer(block, 7, 0x00, value.len());
        block.extend_from_slice(value);
    }

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|byte| (byte as char).to_digit(16).expect("hex") as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    #[test]
    fn the_rfc7541_huffman_examples_decode_to_their_plain_text() {
        for (encoded, plain) in [
            ("f1e3c2e5f23a6ba0ab90f4ff", "www.example.com"),
            ("a8eb10649cbf", "no-cache"),
            ("25a849e95ba97d7f", "custom-key"),
            ("25a849e95bb8e8b4bf", "custom-value"),
            ("90692f", "date"),
        ] {
            let raw = hex(encoded);
            let mut out = Vec::new();
            huffman_decode(&raw, &mut out).expect("decodes");
            assert_eq!(out, plain.as_bytes(), "{encoded}");
        }
    }

    #[test]
    fn encoding_huffman_reproduces_the_rfc7541_appendix_c_bit_strings() {
        for (plain, encoded) in [
            ("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff"),
            ("no-cache", "a8eb10649cbf"),
            ("custom-key", "25a849e95ba97d7f"),
            ("custom-value", "25a849e95bb8e8b4bf"),
            ("date", "90692f"),
            ("", ""),
        ] {
            let mut out = Vec::new();
            huffman_encode(plain.as_bytes(), &mut out);
            assert_eq!(out, hex(encoded), "{plain}");
        }
    }

    #[test]
    fn every_symbol_round_trips_through_the_canonical_table() {
        let all: Vec<u8> = (0..=255u8).collect();
        let mut coded = Vec::new();
        huffman_encode(&all, &mut coded);
        let mut back = Vec::new();
        huffman_decode(&coded, &mut back).expect("decodes");
        assert_eq!(back, all);
        assert_eq!(huffman_decode(&[], &mut Vec::new()), Some(()));
    }

    #[test]
    fn every_symbol_decodes_to_itself_one_at_a_time() {
        for symbol in 0..=255usize {
            let mut coded = Vec::new();
            let byte = symbol as u8;
            huffman_encode(&[byte], &mut coded);
            let mut out = Vec::new();
            huffman_decode(&coded, &mut out).expect("decodes");
            assert_eq!(out, vec![byte], "symbol {symbol}");
        }
    }

    #[test]
    fn the_rebuilt_table_is_the_rfc_table_code_for_code() {
        for (symbol, expected) in [
            (0usize, (8184, 13)),
            (32, (20, 6)),
            (37, (21, 6)),
            (46, (23, 6)),
            (48, (0, 5)),
            (49, (1, 5)),
            (50, (2, 5)),
            (58, (92, 7)),
            (63, (1020, 10)),
            (97, (3, 5)),
            (98, (35, 6)),
            (124, (2044, 11)),
            (255, (67_108_846, 26)),
            (256, (1_073_741_823, 30)),
        ] {
            assert_eq!(huffman_code(symbol), Some(expected), "symbol {symbol}");
        }
    }

    #[test]
    fn an_eos_code_inside_a_string_is_refused_and_padding_is_not() {
        let mut coded = Vec::new();
        huffman_encode(b"200", &mut coded);
        assert!(huffman_decode(&coded, &mut Vec::new()).is_some());
        assert!(
            huffman_decode(&[0xff], &mut Vec::new()).is_none(),
            "eight bits of padding"
        );
        let eos = [0xff, 0xff, 0xff, 0xff];
        assert!(
            huffman_decode(&eos, &mut Vec::new()).is_none(),
            "an EOS symbol"
        );
        assert!(
            huffman_decode(&[0x90], &mut Vec::new()).is_none(),
            "half a symbol"
        );
        let padded = [0x90, 0x69];
        let mut out = Vec::new();
        assert!(
            huffman_decode(&padded, &mut out).is_some(),
            "padding is allowed"
        );
        assert_eq!(out, b"dat");
    }

    #[test]
    fn the_integer_prefix_spans_its_own_boundary() {
        for prefix in [4u8, 5, 6, 7] {
            for value in [
                0usize, 1, 14, 15, 16, 30, 31, 32, 126, 127, 128, 129, 1_000, 70_000,
            ] {
                let mut out = Vec::new();
                integer(&mut out, prefix, 0x00, value);
                let mut at = 0;
                assert_eq!(
                    read_integer(&out, &mut at, prefix),
                    Some(value),
                    "{prefix}/{value}"
                );
                assert_eq!(at, out.len());
            }
        }
    }

    #[test]
    fn a_truncated_or_oversized_integer_is_refused() {
        assert_eq!(read_integer(&[0x7e], &mut 0, 7), Some(126));
        assert_eq!(read_integer(&[0x7f, 0x00], &mut 0, 7), Some(127));
        assert_eq!(read_integer(&[0xff], &mut 0, 7), None);
        assert_eq!(read_integer(&[0xff, 0x80], &mut 0, 7), None);
        assert_eq!(read_integer(&[0xff; 12], &mut 0, 7), None);
        assert_eq!(read_integer(&[0x7f, 0xff], &mut 0, 7), None);
    }

    #[test]
    fn a_literal_status_of_three_digits_is_read_in_both_codecs() {
        let mut h2 = Vec::new();
        hpack_literal(&mut h2, ":status", b"200");
        assert_eq!(hpack_status(&h2), Some(200));
        let mut q3 = Vec::new();
        qpack_literal(&mut q3, ":status", b"200");
        assert_eq!(qpack_status(&q3), Some(200));
    }

    #[test]
    fn an_indexed_status_is_read_from_both_static_tables() {
        for (index, want) in [
            (8usize, 200u16),
            (9, 204),
            (10, 206),
            (11, 304),
            (12, 400),
            (13, 404),
            (14, 500),
        ] {
            let mut h2 = Vec::new();
            integer(&mut h2, 7, 0x80, index);
            assert_eq!(hpack_status(&h2), Some(want), "hpack {index}");
            if index == 8 {
                let mut literal = vec![0x40];
                integer_into(&mut literal, 6, index);
                integer(&mut literal, 7, 0x00, 3);
                literal.extend_from_slice(b"200");
                assert_eq!(hpack_status(&literal), Some(200), "a literal status");
            }
        }
        for (index, want) in [
            (23usize, 103u16),
            (24, 200),
            (25, 304),
            (26, 404),
            (27, 503),
            (28, 500),
        ] {
            let mut q3 = vec![0x00, 0x00];
            integer(&mut q3, 6, 0xC0, index);
            assert_eq!(qpack_status(&q3), Some(want), "qpack {index}");
        }
    }

    #[test]
    fn a_huffman_coded_status_is_read() {
        let mut value = Vec::new();
        huffman_encode(b"200", &mut value);
        let mut block = vec![0x40];
        integer_into(&mut block, 6, 8);
        block.push(0x80 | value.len() as u8);
        block.extend_from_slice(&value);
        assert_eq!(hpack_status(&block), Some(200));
        let mut q3_coded = Vec::new();
        qpack_literal_coded(&mut q3_coded, ":status", &value);
        assert_eq!(qpack_status(&q3_coded), Some(200), "a huffman status");
        let mut q3_raw = Vec::new();
        qpack_literal(&mut q3_raw, ":status", b"200");
        assert_eq!(qpack_status(&q3_raw), Some(200), "a literal status");
    }

    #[test]
    fn a_status_that_is_not_three_digits_is_refused() {
        for text in ["", "2", "20", "2000", "abc", "2 0", "++"] {
            let mut block = Vec::new();
            hpack_literal(&mut block, ":status", text.as_bytes());
            assert_eq!(hpack_status(&block), None, "{text:?}");
        }
    }

    #[test]
    fn a_response_naming_a_table_this_lane_never_fills_is_refused() {
        assert_eq!(hpack_status(&[0x3f, 0xe1, 0x1f]), None, "a size update");
        assert_eq!(
            hpack_status(&[0x0f, 0x61, 0x62, 0x63]),
            None,
            "an unindexed name"
        );
        assert_eq!(
            hpack_status(&[0xff, 0x02, 0x00, 0x40]),
            None,
            "a table index"
        );
        assert_eq!(
            hpack_status(&[0x3f, 0xe1, 0x1f, 0x82]),
            None,
            "a size update first"
        );
        assert_eq!(
            qpack_status(&[0x01, 0x00, 0xC0, 0x01]),
            None,
            "a dynamic insert count"
        );
        assert_eq!(qpack_status(&[0x00]), None, "a truncated prefix");
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x40, 0x01]),
            None,
            "a name reference"
        );
        assert_eq!(
            qpack_status(&[0x00, 0x00, 0x30, 0x00]),
            None,
            "a post-base index"
        );
    }

    #[test]
    fn a_field_this_lane_does_not_read_is_skipped_not_refused() {
        let mut block = Vec::new();
        for (name, value) in [("date", "x"), (":status", "200"), ("server", "edge")] {
            hpack_literal(&mut block, name, value.as_bytes());
        }
        assert_eq!(hpack_status(&block), Some(200));
        let mut q3 = Vec::new();
        for (name, value) in [("date", "x"), (":status", "404"), ("server", "edge")] {
            qpack_literal(&mut q3, name, value.as_bytes());
        }
        assert_eq!(qpack_status(&q3), Some(404));
    }

    #[test]
    fn a_connect_block_is_the_smallest_literal_form_and_holds_the_bearer() {
        let mut h2 = Vec::new();
        hpack_connect("example.com:443", "p", &mut h2);
        let mut q3 = Vec::new();
        qpack_connect("example.com:443", "p", &mut q3);
        assert_eq!(h2, hex("00073a6d 6574686f 6407434f 4e4e4543 54000a3a 61757468 6f726974 790f6578 616d706c 652e636f 6d3a3434 33001370 726f7879 2d617574 686f7269 7a617469 6f6e0170"));
        assert_eq!(q3, hex("00002700 3a6d6574 686f6407 434f4e4e 45435427 033a6175 74686f72 6974790f 6578616d 706c652e 636f6d3a 34343327 0c70726f 78792d61 7574686f 72697a61 74696f6e 0170"));
        assert_eq!((h2.len(), q3.len()), (68, 70));
    }

    #[test]
    fn a_long_name_length_spans_the_three_bit_qpack_prefix() {
        let name = "x".repeat(40);
        let mut q3 = Vec::new();
        qpack_literal(&mut q3, &name, b"");
        assert_eq!(qpack_status(&q3), None, "not a status field");
        let mut h2 = Vec::new();
        hpack_literal(&mut h2, &name, b"");
        assert_eq!(hpack_status(&h2), None, "not a status field");
    }
}
