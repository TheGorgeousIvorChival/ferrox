//! `gRPC` carrier over blocking `TCP`: minimal `HTTP/2` plus the `Hunk` envelope.
//!
//! One stream per connection; `VLESS` bytes ride inside length-delimited messages.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

/// Client connection preface, magic plus the first `SETTINGS` frame's prefix.
const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// `DATA` frame type.
const T_DATA: u8 = 0x00;
/// `HEADERS` frame type.
const T_HEADERS: u8 = 0x01;
/// `RST_STREAM` frame type.
const T_RST: u8 = 0x03;
/// `SETTINGS` frame type.
const T_SETTINGS: u8 = 0x04;
/// `PING` frame type.
const T_PING: u8 = 0x06;
/// `GOAWAY` frame type.
const T_GOAWAY: u8 = 0x07;
/// `WINDOW_UPDATE` frame type.
const T_WINDOW: u8 = 0x08;
/// `CONTINUATION` frame type.
const T_CONT: u8 = 0x09;
/// `END_STREAM` flag.
const F_END: u8 = 0x01;
/// `ACK` flag on `SETTINGS` and `PING`.
const F_ACK: u8 = 0x01;
/// `END_HEADERS` flag.
const F_END_HEADERS: u8 = 0x04;
/// `PADDED` flag.
const F_PADDED: u8 = 0x08;
/// `PRIORITY` flag on `HEADERS`.
const F_PRIORITY: u8 = 0x20;
/// `INITIAL_WINDOW_SIZE` setting id.
const S_WINDOW: u16 = 0x04;
/// `MAX_FRAME_SIZE` setting id.
const S_MAX_FRAME: u16 = 0x05;
/// `REFUSED_STREAM` error code.
const E_REFUSED: u32 = 0x07;
/// Stream window this side advertises, in bytes.
const WINDOW: u32 = 4 * 1024 * 1024;
/// Largest `HTTP/2` frame payload accepted.
const FRAME_CAP: usize = 17 * 1024 * 1024;
/// Largest header block accepted.
const HEAD_CAP: usize = 64 * 1024;
/// Largest `gRPC` message accepted.
const MSG_CAP: usize = 16 * 1024 * 1024;
/// Application bytes per `Hunk` message.
const HUNK: usize = 16 * 1024;
/// Largest flow-control window, per `RFC 7540` section 6.9.2.
const WINDOW_MAX: u64 = (1 << 31) - 1;

/// Huffman codes from `RFC 7541` Appendix B, as `(code, bits)` per byte.
const HUFFMAN: [(u32, u8); 256] = [
    (0x1ff8, 13),
    (0x007f_ffd8, 23),
    (0x0fff_ffe2, 28),
    (0x0fff_ffe3, 28),
    (0x0fff_ffe4, 28),
    (0x0fff_ffe5, 28),
    (0x0fff_ffe6, 28),
    (0x0fff_ffe7, 28),
    (0x0fff_ffe8, 28),
    (0x00ff_ffea, 24),
    (0x3fff_fffc, 30),
    (0x0fff_ffe9, 28),
    (0x0fff_ffea, 28),
    (0x3fff_fffd, 30),
    (0x0fff_ffeb, 28),
    (0x0fff_ffec, 28),
    (0x0fff_ffed, 28),
    (0x0fff_ffee, 28),
    (0x0fff_ffef, 28),
    (0x0fff_fff0, 28),
    (0x0fff_fff1, 28),
    (0x0fff_fff2, 28),
    (0x3fff_fffe, 30),
    (0x0fff_fff3, 28),
    (0x0fff_fff4, 28),
    (0x0fff_fff5, 28),
    (0x0fff_fff6, 28),
    (0x0fff_fff7, 28),
    (0x0fff_fff8, 28),
    (0x0fff_fff9, 28),
    (0x0fff_fffa, 28),
    (0x0fff_fffb, 28),
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
    (0x0007_fff0, 19),
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
    (0x0fff_fffc, 28),
    (0x000f_ffe6, 20),
    (0x003f_ffd2, 22),
    (0x000f_ffe7, 20),
    (0x000f_ffe8, 20),
    (0x003f_ffd3, 22),
    (0x003f_ffd4, 22),
    (0x003f_ffd5, 22),
    (0x007f_ffd9, 23),
    (0x003f_ffd6, 22),
    (0x007f_ffda, 23),
    (0x007f_ffdb, 23),
    (0x007f_ffdc, 23),
    (0x007f_ffdd, 23),
    (0x007f_ffde, 23),
    (0x00ff_ffeb, 24),
    (0x007f_ffdf, 23),
    (0x00ff_ffec, 24),
    (0x00ff_ffed, 24),
    (0x003f_ffd7, 22),
    (0x007f_ffe0, 23),
    (0x00ff_ffee, 24),
    (0x007f_ffe1, 23),
    (0x007f_ffe2, 23),
    (0x007f_ffe3, 23),
    (0x007f_ffe4, 23),
    (0x001f_ffdc, 21),
    (0x003f_ffd8, 22),
    (0x007f_ffe5, 23),
    (0x003f_ffd9, 22),
    (0x007f_ffe6, 23),
    (0x007f_ffe7, 23),
    (0x00ff_ffef, 24),
    (0x003f_ffda, 22),
    (0x001f_ffdd, 21),
    (0x000f_ffe9, 20),
    (0x003f_ffdb, 22),
    (0x003f_ffdc, 22),
    (0x007f_ffe8, 23),
    (0x007f_ffe9, 23),
    (0x001f_ffde, 21),
    (0x007f_ffea, 23),
    (0x003f_ffdd, 22),
    (0x003f_ffde, 22),
    (0x00ff_fff0, 24),
    (0x001f_ffdf, 21),
    (0x003f_ffdf, 22),
    (0x007f_ffeb, 23),
    (0x007f_ffec, 23),
    (0x001f_ffe0, 21),
    (0x001f_ffe1, 21),
    (0x003f_ffe0, 22),
    (0x001f_ffe2, 21),
    (0x007f_ffed, 23),
    (0x003f_ffe1, 22),
    (0x007f_ffee, 23),
    (0x007f_ffef, 23),
    (0x000f_ffea, 20),
    (0x003f_ffe2, 22),
    (0x003f_ffe3, 22),
    (0x003f_ffe4, 22),
    (0x007f_fff0, 23),
    (0x003f_ffe5, 22),
    (0x003f_ffe6, 22),
    (0x007f_fff1, 23),
    (0x03ff_ffe0, 26),
    (0x03ff_ffe1, 26),
    (0x000f_ffeb, 20),
    (0x0007_fff1, 19),
    (0x003f_ffe7, 22),
    (0x007f_fff2, 23),
    (0x003f_ffe8, 22),
    (0x01ff_ffec, 25),
    (0x03ff_ffe2, 26),
    (0x03ff_ffe3, 26),
    (0x03ff_ffe4, 26),
    (0x07ff_ffde, 27),
    (0x07ff_ffdf, 27),
    (0x03ff_ffe5, 26),
    (0x00ff_fff1, 24),
    (0x01ff_ffed, 25),
    (0x0007_fff2, 19),
    (0x001f_ffe3, 21),
    (0x03ff_ffe6, 26),
    (0x07ff_ffe0, 27),
    (0x07ff_ffe1, 27),
    (0x03ff_ffe7, 26),
    (0x07ff_ffe2, 27),
    (0x00ff_fff2, 24),
    (0x001f_ffe4, 21),
    (0x001f_ffe5, 21),
    (0x03ff_ffe8, 26),
    (0x03ff_ffe9, 26),
    (0x0fff_fffd, 28),
    (0x07ff_ffe3, 27),
    (0x07ff_ffe4, 27),
    (0x07ff_ffe5, 27),
    (0x000f_ffec, 20),
    (0x00ff_fff3, 24),
    (0x000f_ffed, 20),
    (0x001f_ffe6, 21),
    (0x003f_ffe9, 22),
    (0x001f_ffe7, 21),
    (0x001f_ffe8, 21),
    (0x007f_fff3, 23),
    (0x003f_ffea, 22),
    (0x003f_ffeb, 22),
    (0x01ff_ffee, 25),
    (0x01ff_ffef, 25),
    (0x00ff_fff4, 24),
    (0x00ff_fff5, 24),
    (0x03ff_ffea, 26),
    (0x007f_fff4, 23),
    (0x03ff_ffeb, 26),
    (0x07ff_ffe6, 27),
    (0x03ff_ffec, 26),
    (0x03ff_ffed, 26),
    (0x07ff_ffe7, 27),
    (0x07ff_ffe8, 27),
    (0x07ff_ffe9, 27),
    (0x07ff_ffea, 27),
    (0x07ff_ffeb, 27),
    (0x0fff_fffe, 28),
    (0x07ff_ffec, 27),
    (0x07ff_ffed, 27),
    (0x07ff_ffee, 27),
    (0x07ff_ffef, 27),
    (0x07ff_fff0, 27),
    (0x03ff_ffee, 26),
];

/// `RFC 7541` static header table, indexed from one.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// Append an integer with a `prefix`-bit first field carrying `first`.
fn push_int(out: &mut Vec<u8>, prefix: u8, first: u8, value: usize) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push(rest as u8 & 0x7F | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Append a raw string with its length, never Huffman-coded on the way out.
fn push_str(out: &mut Vec<u8>, text: &str) {
    push_int(out, 7, 0x00, text.len());
    out.extend_from_slice(text.as_bytes());
}

/// Encode headers as literals without indexing; every peer must accept them.
fn block_encode(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.push(0x00);
        push_str(&mut out, name);
        push_str(&mut out, value);
    }
    out
}

/// Decode one prefixed integer, returning its value and the remaining bytes.
fn prefixed(block: &[u8], prefix: u8) -> Option<(usize, &[u8])> {
    let max = (1usize << prefix) - 1;
    let first = *block.first()? as usize & max;
    if first < max {
        return Some((first, &block[1..]));
    }
    let mut value = max;
    let mut shift = 0u32;
    let mut rest = &block[1..];
    loop {
        let byte = *rest.first()?;
        rest = &rest[1..];
        value += usize::from(byte & 0x7F) << shift;
        shift += 7;
        if shift > 28 || value > HEAD_CAP {
            return None;
        }
        if byte & 0x80 == 0 {
            return Some((value, rest));
        }
    }
}

/// Decode one Huffman-coded string, checking its padding is all ones.
fn huffman_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u8;
    let mut at = 0usize;
    while at < data.len() * 8 {
        let bit = u32::from(data[at / 8] >> (7 - at % 8)) & 1;
        acc = (acc << 1) | bit;
        bits += 1;
        at += 1;
        let hit = HUFFMAN
            .iter()
            .position(|&(code, len)| len == bits && code == acc);
        match hit {
            Some(256) => return None,
            Some(sym) => {
                out.push(sym as u8);
                acc = 0;
                bits = 0;
            }
            None => {
                if bits > 30 {
                    return None;
                }
            }
        }
    }
    if bits >= 8 || acc != (1u32 << bits) - 1 {
        return None;
    }
    Some(out)
}

/// Decode one string, Huffman-coded or raw depending on its first bit.
fn string_decode(block: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let huffman = block.first()? & 0x80 != 0;
    let (len, mut rest) = prefixed(block, 7)?;
    if rest.len() < len {
        return None;
    }
    let (raw, tail) = rest.split_at(len);
    rest = tail;
    if huffman {
        Some((huffman_decode(raw)?, rest))
    } else {
        Some((raw.to_vec(), rest))
    }
}

/// `HPACK` decoder with a 4 KiB dynamic table, enough for handshake blocks.
#[derive(Debug, Default)]
struct Decoder {
    /// Newest-first entries; static entries are never stored here.
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Current table size counting 32 bytes per entry plus both lengths.
    size: usize,
}

impl Decoder {
    /// Look up a 1-based index across the static table and the dynamic one.
    fn entry(&self, index: usize) -> Option<(Vec<u8>, Vec<u8>)> {
        if index == 0 {
            return None;
        }
        if index <= STATIC.len() {
            let (name, value) = STATIC[index - 1];
            return Some((name.as_bytes().to_vec(), value.as_bytes().to_vec()));
        }
        self.table.get(index - STATIC.len() - 1).cloned()
    }

    /// Name for an index, or a literal name when the index is zero.
    fn named<'a>(&self, block: &'a [u8], index: usize) -> Option<(Vec<u8>, &'a [u8])> {
        if index == 0 {
            let (name, rest) = string_decode(block)?;
            if name.is_empty() {
                return None;
            }
            return Some((name, rest));
        }
        Some((self.entry(index)?.0, block))
    }

    /// Insert an entry, evicting oldest-first past the 4 KiB budget.
    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.size += 32 + name.len() + value.len();
        self.table.push_front((name, value));
        while self.size > 4096 {
            let Some((name, value)) = self.table.pop_back() else {
                break;
            };
            self.size -= 32 + name.len() + value.len();
        }
    }

    /// Decode one header block into name/value pairs.
    fn decode(&mut self, mut block: &[u8], out: &mut Vec<(Vec<u8>, Vec<u8>)>) -> Option<()> {
        while !block.is_empty() {
            let first = block[0];
            if first & 0x80 != 0 {
                let (index, rest) = prefixed(block, 7)?;
                out.push(self.entry(index)?);
                block = rest;
            } else if first & 0x40 != 0 {
                let (index, rest) = prefixed(block, 6)?;
                let (name, rest) = self.named(rest, index)?;
                let (value, rest) = string_decode(rest)?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
                block = rest;
            } else if first & 0x20 != 0 {
                let (max, rest) = prefixed(block, 5)?;
                if max > 4096 {
                    return None;
                }
                while self.size > max {
                    let Some((name, value)) = self.table.pop_back() else {
                        break;
                    };
                    self.size -= 32 + name.len() + value.len();
                }
                block = rest;
            } else {
                let (index, rest) = prefixed(block, 4)?;
                let (name, rest) = self.named(rest, index)?;
                let (value, rest) = string_decode(rest)?;
                out.push((name, value));
                block = rest;
            }
        }
        Some(())
    }
}

/// One `HTTP/2` frame header off the wire: `(length, kind, flags, stream)`.
fn read_head(stream: &mut TcpStream) -> Option<(usize, u8, u8, u32)> {
    let mut head = [0u8; 9];
    crate::proxy::read_exact(stream, &mut head).ok()?;
    let len = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    if len > FRAME_CAP {
        return None;
    }
    let id = u32::from_be_bytes(head[5..9].try_into().unwrap()) & 0x7FFF_FFFF;
    Some((len, head[3], head[4], id))
}

/// Write one frame; lengths past the peer's maximum are never constructed.
///
/// The nine header bytes and the body go out in one syscall where the platform
/// allows it (see [`crate::proxy::write_all_two`]): same bytes in the same
/// order as two writes, so the peer's `read_exact` pair cannot tell.
fn write_frame(stream: &mut TcpStream, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
    let mut head = [0u8; 9];
    head[0..3].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&id.to_be_bytes());
    crate::proxy::write_all_two(stream, &head, body)
}

/// Remaining peer send windows in bytes.
#[derive(Debug, Default)]
struct SendWindow {
    /// Connection-level window, starting at 64 KiB like every peer.
    conn: u64,
    /// Stream-level window, replaced by the peer's `SETTINGS` when it arrives.
    stream: u64,
}

/// Socket half plus send windows shared by the relay thread and the replies.
#[derive(Debug)]
struct Shared {
    /// Socket half every frame is written through, one writer at a time.
    stream: Mutex<TcpStream>,
    /// Remaining send windows, waited on when exhausted.
    send: Mutex<SendWindow>,
    /// Signalled on every window or settings update and on death.
    wake: Condvar,
    /// Largest frame the peer accepts.
    max_frame: Mutex<usize>,
    /// Last advertised stream window, for adjusting open streams.
    init: Mutex<u64>,
    /// Whether our upload ended, so the close frame goes out once.
    ended: AtomicBool,
    /// Whether the connection is dead, failing every waiter.
    dead: AtomicBool,
}

/// Reserve `need` send-window bytes, waiting for updates unless dead.
fn take_window(shared: &Shared, need: u64) -> bool {
    let mut send = shared.send.lock().unwrap_or_else(PoisonError::into_inner);
    while send.conn < need || send.stream < need {
        if shared.dead.load(Ordering::SeqCst) {
            return false;
        }
        send = shared
            .wake
            .wait(send)
            .unwrap_or_else(PoisonError::into_inner);
    }
    send.conn -= need;
    send.stream -= need;
    true
}

/// Byte stream over one `gRPC` tunnel; `Read` yields message payload bytes.
#[derive(Debug)]
pub(crate) struct GrpcReader {
    /// Socket half frames are read from.
    read: TcpStream,
    /// Shared writer for acknowledgements and window updates.
    shared: Arc<Shared>,
    /// Header decoder with its dynamic table.
    decoder: Decoder,
    /// Our stream id, odd for clients and even for accepted ones.
    stream: u32,
    /// Whether this end opened the stream, deciding header validation.
    server: bool,
    /// Expected request path, checked once on accept.
    path: String,
    /// Whether the opening headers were answered, starting the byte flow.
    answered: bool,
    /// Header block accumulating across `CONTINUATION` frames.
    head: Vec<u8>,
    /// Stream the accumulating block belongs to.
    head_id: u32,
    /// Current message bytes, envelope first.
    msg: Vec<u8>,
    /// Remaining message bytes once its length is known.
    need: usize,
    /// Decoded application bytes not yet consumed.
    backlog: Vec<u8>,
    /// Current frame payload, reused across `pump` calls.
    frame: Vec<u8>,
    /// Whether the peer ended the stream, after which reads report `EOF`.
    eof: bool,
}

/// Message writer; cheap to clone for the relay thread.
#[derive(Debug, Clone)]
pub(crate) struct GrpcWriter {
    /// Shared socket half and send windows.
    shared: Arc<Shared>,
    /// Our stream id.
    stream: u32,
}

impl GrpcReader {
    /// Send one frame through the shared writer.
    fn emit(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut stream, kind, flags, id, body)
    }

    /// Answer `SETTINGS`, adjusting our stream window to the newly advertised one.
    fn settings(&self, flags: u8, body: &[u8]) {
        if flags & F_ACK != 0 {
            return;
        }
        let mut at = 0;
        while at + 6 <= body.len() {
            let id = u16::from_be_bytes([body[at], body[at + 1]]);
            let value =
                u32::from_be_bytes([body[at + 2], body[at + 3], body[at + 4], body[at + 5]]);
            if id == S_WINDOW {
                let mut init = self
                    .shared
                    .init
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let mut send = self
                    .shared
                    .send
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                send.stream = send
                    .stream
                    .saturating_add(u64::from(value))
                    .saturating_sub(*init);
                send.stream = send.stream.min(WINDOW_MAX);
                *init = u64::from(value);
                self.shared.wake.notify_all();
            } else if id == S_MAX_FRAME {
                let mut max = self
                    .shared
                    .max_frame
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                *max = usize::try_from(value).unwrap_or(FRAME_CAP).min(FRAME_CAP);
            }
            at += 6;
        }
        self.emit(T_SETTINGS, F_ACK, 0, &[]);
    }

    /// Answer a `PING` with the same payload and the `ACK` flag.
    fn ping(&self, flags: u8, body: &[u8]) {
        if flags & F_ACK == 0 && body.len() == 8 {
            self.emit(T_PING, F_ACK, 0, body);
        }
    }

    /// Credit connection and stream windows for consumed bytes.
    fn replenish(&self, id: u32, len: usize) {
        if len == 0 {
            return;
        }
        let inc = (len.min(1 << 30) as u32).to_be_bytes();
        self.emit(T_WINDOW, 0, 0, &inc);
        if id != 0 {
            self.emit(T_WINDOW, 0, id, &inc);
        }
    }

    /// Refuse a stream this server will not serve.
    fn refuse(&self, id: u32) {
        self.emit(T_RST, 0, id, &E_REFUSED.to_be_bytes());
    }

    /// Header value by lowercase name.
    fn find<'a>(headers: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
        headers.iter().find_map(|(key, value)| {
            key.eq_ignore_ascii_case(name.as_bytes())
                .then_some(value.as_slice())
        })
    }

    /// Route one complete header block by role.
    fn headers(&mut self, id: u32, flags: u8, block: &[u8]) -> Option<()> {
        let mut headers = Vec::new();
        self.decoder.decode(block, &mut headers)?;
        if self.server {
            return self.serve_headers(id, flags, &headers);
        }
        if id != self.stream {
            return Some(());
        }
        if !self.answered {
            let status = Self::find(&headers, ":status")?;
            if status != b"200" {
                return None;
            }
            self.answered = true;
        }
        if flags & F_END != 0 {
            self.eof = true;
        }
        Some(())
    }

    /// Validate one request and answer `200`, or refuse it and fail.
    fn serve_headers(&mut self, id: u32, flags: u8, headers: &[(Vec<u8>, Vec<u8>)]) -> Option<()> {
        if self.answered {
            if flags & F_END != 0 {
                self.eof = true;
            }
            return Some(());
        }
        let ok = Self::find(headers, ":method") == Some(b"POST".as_slice())
            && Self::find(headers, ":path") == Some(self.path.as_bytes())
            && Self::find(headers, "content-type")
                .is_some_and(|v| v.starts_with(b"application/grpc"));
        if !ok {
            self.refuse(id);
            return None;
        }
        let block = block_encode(&[
            (":status", "200"),
            ("content-type", "application/grpc"),
            ("grpc-encoding", "identity"),
        ]);
        if !self.emit(T_HEADERS, F_END_HEADERS, id, &block) {
            return None;
        }
        self.stream = id;
        self.answered = true;
        if flags & F_END != 0 {
            self.eof = true;
        }
        Some(())
    }

    /// Feed one `DATA` payload into the message parser.
    fn data(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        if id != self.stream || !self.answered {
            return Some(());
        }
        let body = if flags & F_PADDED != 0 {
            let pad = usize::from(*body.first()?);
            if pad + 1 > body.len() {
                return None;
            }
            &body[1..body.len() - pad]
        } else {
            body
        };
        self.replenish(id, body.len());
        self.msg.extend_from_slice(body);
        let end = flags & F_END != 0;
        loop {
            if self.need == 0 {
                if self.msg.len() < 5 {
                    break;
                }
                if self.msg[0] != 0 {
                    return None;
                }
                let len = u32::from_be_bytes(self.msg[1..5].try_into().unwrap()) as usize;
                if len > MSG_CAP {
                    return None;
                }
                self.need = len;
                self.msg.drain(..5);
            }
            if self.msg.len() < self.need {
                break;
            }
            let payload = hunk_decode(&self.msg[..self.need])?;
            self.backlog.extend_from_slice(payload);
            self.msg.drain(..self.need);
            self.need = 0;
        }
        if end {
            if self.need != 0 || !self.msg.is_empty() {
                return None;
            }
            self.eof = true;
        }
        Some(())
    }

    /// Process one frame; a dead socket or fatal error ends the stream.
    fn pump(&mut self) -> Option<()> {
        let head = read_head(&mut self.read);
        let (len, kind, flags, id) = head?;
        // Taken, not borrowed: the handlers below need `&mut self` and the
        // body at once, which one object cannot lend itself. Restored at every
        // exit, so the next frame reuses the same allocation.
        let mut frame = std::mem::take(&mut self.frame);
        frame.resize(len, 0);
        if len > 0 && crate::proxy::read_exact(&mut self.read, &mut frame).is_err() {
            self.frame = frame;
            return None;
        }
        let out = match kind {
            T_DATA => self.data(id, flags, &frame),
            T_HEADERS => self.head_block(id, flags, &frame),
            T_CONT => self.continue_block(id, flags, &frame),
            T_RST => {
                if id == self.stream {
                    self.eof = true;
                }
                Some(())
            }
            T_SETTINGS => {
                if id == 0 {
                    self.settings(flags, &frame);
                }
                Some(())
            }
            T_PING => {
                if id == 0 {
                    self.ping(flags, &frame);
                }
                Some(())
            }
            T_WINDOW => {
                self.window(id, &frame);
                Some(())
            }
            T_GOAWAY => {
                self.eof = true;
                Some(())
            }
            _ => Some(()),
        };
        self.frame = frame;
        out
    }

    /// Start a header block, decoding it at once when complete.
    fn head_block(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        let mut body = body;
        if flags & F_PADDED != 0 {
            let pad = usize::from(*body.first()?);
            if pad + 1 > body.len() {
                return None;
            }
            body = &body[1..body.len() - pad];
        }
        if flags & F_PRIORITY != 0 {
            if body.len() < 5 {
                return None;
            }
            body = &body[5..];
        }
        if flags & F_END_HEADERS != 0 {
            return self.headers(id, flags, body);
        }
        if self.head.len() + body.len() > HEAD_CAP {
            return None;
        }
        self.head.extend_from_slice(body);
        self.head_id = id;
        Some(())
    }

    /// Extend the open header block, decoding it once complete.
    fn continue_block(&mut self, id: u32, flags: u8, body: &[u8]) -> Option<()> {
        if id != self.head_id || self.head.len() + body.len() > HEAD_CAP {
            return None;
        }
        if flags & F_END_HEADERS != 0 {
            let mut block = std::mem::take(&mut self.head);
            block.extend_from_slice(body);
            return self.headers(id, flags, &block);
        }
        self.head.extend_from_slice(body);
        Some(())
    }

    /// Credit our send windows from a peer update.
    fn window(&self, id: u32, body: &[u8]) {
        if body.len() != 4 {
            return;
        }
        let inc = u64::from(u32::from_be_bytes(body[..4].try_into().unwrap()) & 0x7FFF_FFFF);
        if inc == 0 {
            return;
        }
        let mut send = self
            .shared
            .send
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if id == 0 {
            send.conn = send.conn.saturating_add(inc).min(WINDOW_MAX);
        } else if id == self.stream {
            send.stream = send.stream.saturating_add(inc).min(WINDOW_MAX);
        } else {
            return;
        }
        self.shared.wake.notify_all();
    }
}

impl Read for GrpcReader {
    /// Fill `buf` with message payload bytes; empty means clean `EOF`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if !self.backlog.is_empty() {
                let n = self.backlog.len().min(buf.len());
                buf[..n].copy_from_slice(&self.backlog[..n]);
                self.backlog.drain(..n);
                return Ok(n);
            }
            if self.eof {
                return Ok(0);
            }
            if self.pump().is_none() {
                self.eof = true;
            }
        }
    }
}

impl GrpcWriter {
    /// Send application bytes as `Hunk` messages, split to the peer's frames.
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        for piece in data.chunks(HUNK) {
            if !self.message(piece, false) {
                return false;
            }
        }
        true
    }

    /// End the upload with an empty final frame, exactly once.
    pub(crate) fn close(&self) {
        if self.shared.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        self.message(&[], true);
    }

    /// Send one message, splitting across frames the peer accepts.
    fn message(&self, data: &[u8], end: bool) -> bool {
        let frame = hunk_frame(data);
        let max = *self
            .shared
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let max = max.max(1);
        let mut at = 0;
        while at < frame.len() {
            let n = (frame.len() - at).min(max);
            let last = at + n == frame.len();
            if !take_window(&self.shared, n as u64) {
                return false;
            }
            let flags = if last && end { F_END } else { 0 };
            let Ok(mut stream) = self.shared.stream.lock() else {
                return false;
            };
            if !write_frame(&mut stream, T_DATA, flags, self.stream, &frame[at..at + n]) {
                return false;
            }
            drop(stream);
            at += n;
        }
        true
    }
}

/// [`Write`] over the tunnel: bytes in, `Hunk` messages out.
impl std::io::Write for GrpcWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.send(data) {
            Ok(data.len())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Wrap application bytes as one `Hunk` message with its `gRPC` envelope.
fn hunk_frame(data: &[u8]) -> Vec<u8> {
    // One buffer, not two: the old form built the hunk in its own `Vec` and
    // copied it behind a five-zero prefix, so every message paid an allocation
    // and a full copy for five length bytes.
    let mut out = vec![0u8; 5];
    out.push(0x0A);
    push_varint(&mut out, data.len() as u64);
    out.extend_from_slice(data);
    let hunk_len = (out.len() - 5) as u32;
    out[1..5].copy_from_slice(&hunk_len.to_be_bytes());
    out
}

/// Append a protobuf varint.
fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 & 0x7F | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Read a protobuf varint, bounded against overflow.
fn read_varint(msg: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *msg.get(*at)?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// Decode a `Hunk`, keeping the last value of a repeated field like decoders do.
/// Field 1 of one hunk message, borrowed: the old owned return copied the
/// whole message just for the caller to copy it into the backlog again.
fn hunk_decode(msg: &[u8]) -> Option<&[u8]> {
    let mut at = 0;
    let mut data: &[u8] = &[];
    while at < msg.len() {
        let key = read_varint(msg, &mut at)?;
        let field = (key >> 3) as u32;
        let wire = (key & 0x07) as u8;
        if field == 0 {
            return None;
        }
        if field == 1 {
            if wire != 2 {
                return None;
            }
            let len = usize::try_from(read_varint(msg, &mut at)?).ok()?;
            let end = at.checked_add(len)?;
            data = msg.get(at..end)?;
            at = end;
        } else {
            skip_field(msg, &mut at, wire)?;
        }
    }
    Some(data)
}

/// Skip one unknown protobuf field without recursing into groups.
fn skip_field(msg: &[u8], at: &mut usize, wire: u8) -> Option<()> {
    let fixed = match wire {
        0 => {
            read_varint(msg, at)?;
            return Some(());
        }
        1 => 8,
        2 => usize::try_from(read_varint(msg, at)?).ok()?,
        5 => 4,
        _ => return None,
    };
    *at = at.checked_add(fixed)?;
    if *at > msg.len() {
        return None;
    }
    Some(())
}

/// Open the first tunnel on a fresh connection as a server.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(GrpcReader, GrpcWriter)> {
    let mut read = stream;
    let mut magic = [0u8; 24];
    crate::proxy::read_exact(&mut read, &mut magic).ok()?;
    if magic != *MAGIC {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let shared = Arc::new(Shared {
        stream: Mutex::new(write),
        send: Mutex::new(SendWindow {
            conn: 65_535,
            stream: 65_535,
        }),
        wake: Condvar::new(),
        max_frame: Mutex::new(16_384),
        init: Mutex::new(65_535),
        ended: AtomicBool::new(false),
        dead: AtomicBool::new(false),
    });
    {
        let mut initial = Vec::with_capacity(12);
        initial.extend_from_slice(&S_WINDOW.to_be_bytes());
        initial.extend_from_slice(&WINDOW.to_be_bytes());
        let Ok(mut socket) = shared.stream.lock() else {
            return None;
        };
        if !write_frame(&mut socket, T_SETTINGS, 0, 0, &initial) {
            return None;
        }
    }
    let mut reader = GrpcReader {
        read,
        shared: Arc::clone(&shared),
        decoder: Decoder::default(),
        stream: 0,
        server: true,
        path: path.to_owned(),
        answered: false,
        head: Vec::new(),
        head_id: 0,
        msg: Vec::new(),
        need: 0,
        backlog: Vec::new(),
        frame: Vec::new(),
        eof: false,
    };
    while !reader.answered && !reader.eof {
        if reader.pump().is_none() {
            reader.eof = true;
        }
    }
    if !reader.answered {
        return None;
    }
    let writer = GrpcWriter {
        shared,
        stream: reader.stream,
    };
    Some((reader, writer))
}

/// Open one tunnel on a fresh connection as a client.
pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
) -> Option<(GrpcReader, GrpcWriter)> {
    let mut read = stream;
    read.write_all(MAGIC).ok()?;
    let mut initial = Vec::with_capacity(12);
    initial.extend_from_slice(&S_WINDOW.to_be_bytes());
    initial.extend_from_slice(&WINDOW.to_be_bytes());
    if !write_frame(&mut read, T_SETTINGS, 0, 0, &initial) {
        return None;
    }
    let block = block_encode(&[
        (":method", "POST"),
        (":scheme", "http"),
        (":path", path),
        (":authority", host),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("grpc-encoding", "identity"),
        ("grpc-accept-encoding", "gzip,identity"),
    ]);
    if !write_frame(&mut read, T_HEADERS, F_END_HEADERS, 1, &block) {
        return None;
    }
    let shared = Arc::new(Shared {
        stream: Mutex::new(read.try_clone().ok()?),
        send: Mutex::new(SendWindow {
            conn: 65_535,
            stream: 65_535,
        }),
        wake: Condvar::new(),
        max_frame: Mutex::new(16_384),
        init: Mutex::new(65_535),
        ended: AtomicBool::new(false),
        dead: AtomicBool::new(false),
    });
    let reader = GrpcReader {
        read,
        shared: Arc::clone(&shared),
        decoder: Decoder::default(),
        stream: 1,
        server: false,
        path: path.to_owned(),
        answered: false,
        head: Vec::new(),
        head_id: 0,
        msg: Vec::new(),
        need: 0,
        backlog: Vec::new(),
        frame: Vec::new(),
        eof: false,
    };
    Some((reader, GrpcWriter { shared, stream: 1 }))
}

/// This carrier's write half, as a [`crate::proxy::CarrierSink`].
///
/// The inner loop's call resolves to `GrpcWriter::send` at compile time; see the
/// `ws` impl above for why that is the same code the old `relay` emitted.
impl crate::proxy::CarrierSink for GrpcWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn close(&self) {
        self.close();
    }
}

/// The two lines the old `grpc::relay` did at the end of the downlink loop:
/// mark the shared state dead and wake anyone waiting on a send window.
///
/// Once per connection, exactly as before — it is what `relay_sink`'s
/// `on_reader_done` is for, and it is a closure rather than a flag in the shared
/// signature so that `ws`, which has nothing to do here, pays for nothing.
pub(crate) fn mark_reader_dead(reader: &mut GrpcReader) {
    reader.shared.dead.store(true, Ordering::SeqCst);
    reader.shared.wake.notify_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn huffman_matches_the_rfc_example() {
        let coded = [
            0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF,
        ];
        assert_eq!(huffman_decode(&coded).expect("decodes"), b"www.example.com");
        assert!(huffman_decode(b"\xff").is_none());
    }

    #[test]
    fn headers_decode_the_rfc_request_example() {
        let first = [
            0x82, 0x86, 0x84, 0x41, 0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB,
            0x90, 0xF4, 0xFF,
        ];
        let mut decoder = Decoder::default();
        let mut headers = Vec::new();
        decoder.decode(&first, &mut headers).expect("decodes");
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| key == name.as_bytes())
                .map(|(_, value)| value.clone())
        };
        assert_eq!(get(":method").expect("method"), b"GET");
        assert_eq!(get(":scheme").expect("scheme"), b"http");
        assert_eq!(get(":path").expect("path"), b"/");
        assert_eq!(get(":authority").expect("authority"), b"www.example.com");
    }

    #[test]
    fn headers_round_trip_without_indexing() {
        let block = block_encode(&[(":method", "POST"), (":path", "/TunnelService/Tun")]);
        let mut decoder = Decoder::default();
        let mut headers = Vec::new();
        decoder.decode(&block, &mut headers).expect("decodes");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[1].1, b"/TunnelService/Tun");
    }

    #[test]
    fn hunks_carry_the_xray_schema_bytes() {
        assert_eq!(hunk_frame(b"ping"), b"\0\0\0\0\x06\x0a\x04ping");
        assert_eq!(
            hunk_decode(&[0x0A, 0x04, b'p', b'i', b'n', b'g']).expect("decodes"),
            b"ping"
        );
        assert!(hunk_decode(b"raw payload").is_none());
        assert!(hunk_decode(&[0x0A, 0x80]).is_none());
    }

    #[test]
    fn tunnel_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/TunnelService/Tun").expect("serves");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
            drain(&mut reader);
            writer.close();
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            connect(stream, "127.0.0.1", "/TunnelService/Tun").expect("dials");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        writer.close();
        drain(&mut reader);
        server.join().expect("joins");
    }

    /// Read until clean `EOF`, consuming handshake acks so both ends close clean.
    fn drain(reader: &mut GrpcReader) {
        let mut buf = [0u8; 1024];
        while reader.read(&mut buf).unwrap_or(0) != 0 {}
    }

    #[test]
    fn tunnel_rejects_a_wrong_path() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/TunnelService/Tun").is_none());
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (_, writer) = connect(stream, "127.0.0.1", "/other/Tun").expect("dials");
        drop(writer);
        server.join().expect("joins");
    }
}
