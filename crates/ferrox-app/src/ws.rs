//! `WebSocket` carrier over blocking `TCP`, both roles.
//!
//! Upgrade handshake plus binary framing; the `VLESS` bytes ride unchanged.
//!
//! # Early data
//!
//! A `?ed=N` budget on the path — [`ferrox_core::transport::EarlyData`] —
//! spends the layer above's first write inside the handshake: it travels as
//! unpadded base64url in `Sec-WebSocket-Protocol` and no frame is sent for it.
//! The whole write or nothing, and the boundary is inclusive, so a write longer
//! than `N` is not truncated but sent as a frame with early data off for the
//! connection. Nothing is copied: the decision reads the caller's own slice and
//! the digits are encoded from it into the request this module was building
//! anyway, so a handshake with a budget allocates what one without it does.
//! `Xray-core`, `xray-rust` and `sing-box` each build a second string for those
//! digits, and two of the three copy the payload into it before encoding.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ferrox_core::transport::early_decode;

/// `RFC 6455` upgrade fingerprint, shared by every implementation on the wire.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest handshake block read before the upgrade is refused, not buffered.
const HEAD_LIMIT: usize = 16 * 1024;
/// Largest single frame payload accepted; anything bigger closes fast.
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
/// Binary data frame opcode.
const OP_DATA: u8 = 0x02;
/// Subsequent fragment opcode.
const OP_CONT: u8 = 0x00;
/// Close opcode.
const OP_CLOSE: u8 = 0x08;
/// Ping opcode, answered with a pong carrying the same payload.
const OP_PING: u8 = 0x09;
/// Pong opcode, never answered.
const OP_PONG: u8 = 0x0A;
/// Normal-closure body sent with each close frame.
const CLOSE_BODY: [u8; 2] = [0x03, 0xE8];

/// Standard base64 alphabet, the encoding both handshake keys arrive in.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 encode with padding, for handshake keys only.
///
/// The RFC 6455 half, and the reason this alphabet is spelled out here even
/// though the early-data one lives in [`ferrox_core::transport`]: a
/// `Sec-WebSocket-Key` is standard base64 *with* padding while the bytes beside
/// it in the same handshake are url-safe without, which is a difference worth
/// having in two places rather than one switch.
fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        out.push(ALPHABET[(word >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(word >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(word >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(word & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Expected `Sec-WebSocket-Accept` for a client key, per `RFC 6455` section 1.3.
fn accept_key(key: &str) -> String {
    use sha1::Digest as _;
    let mut hash = sha1::Sha1::new();
    hash.update(key.trim().as_bytes());
    hash.update(GUID.as_bytes());
    b64_encode(&hash.finalize())
}

/// Sixteen fresh random bytes as standard base64, the client handshake key.
fn fresh_key() -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    Some(b64_encode(&raw))
}

/// XOR `buf` with the 4-byte mask repeated; the mask period divides 16, so
/// whole 16-byte chunks take one vector XOR each and only the tail stays
/// scalar.
///
/// One spelling per baseline vector ISA, chosen at compile time: `SSE2` is
/// part of `x86_64` and `NEON` part of `aarch64`, so neither needs a runtime
/// probe. Lane-wise XOR is lane-wise XOR on each, so the bytes are identical
/// however the machine vectorizes. This crate's `Miri` job covers only
/// `ferrox-core`, so these intrinsics are discharged the same way the
/// `ChaCha20` backends are: by the differential test below, at every chunk
/// edge, rather than by interpretation.
fn apply_mask(buf: &mut [u8], mask: [u8; 4]) {
    let wide = [
        mask[0], mask[1], mask[2], mask[3], mask[0], mask[1], mask[2], mask[3], mask[0], mask[1],
        mask[2], mask[3], mask[0], mask[1], mask[2], mask[3],
    ];
    let (chunks, tail) = buf.as_chunks_mut::<16>();
    for chunk in chunks {
        xor_block(chunk, &wide);
    }
    for (i, byte) in tail.iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
}

/// XOR one 16-byte block with the repeated mask, in a single vector op.
///
/// `inline(always)`: the `x86_64` build must not outline this away from whatever
/// calls it into a context without the baseline features the body assumes —
/// outlining would spill the block to the stack on every call. Same reason as
/// the lane primitives in the `ChaCha20` core.
#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the vector op inlined at every call site"
)]
#[inline(always)]
fn xor_block(chunk: &mut [u8; 16], wide: &[u8; 16]) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
        // SAFETY: unaligned loads and stores need no alignment; both sides are
        // exactly 16 bytes, read and written once, and the instructions retain
        // nothing after they return.
        unsafe {
            let data = _mm_loadu_si128(chunk.as_ptr().cast());
            let key = _mm_loadu_si128(wide.as_ptr().cast());
            _mm_storeu_si128(chunk.as_mut_ptr().cast(), _mm_xor_si128(data, key));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::{veorq_u8, vld1q_u8, vst1q_u8};
        // SAFETY: `NEON` is baseline on `aarch64`, so no feature gate is
        // needed; the loads and store each touch exactly 16 live bytes.
        unsafe {
            let data = vld1q_u8(chunk.as_ptr());
            let key = vld1q_u8(wide.as_ptr());
            vst1q_u8(chunk.as_mut_ptr(), veorq_u8(data, key));
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        for (byte, key) in chunk.iter_mut().zip(wide.iter()) {
            *byte ^= *key;
        }
    }
}

/// Four fresh random bytes, the mask of one client frame.
///
/// Batched: one `getrandom` per 512 frames, not one per frame. The bytes are
/// still fresh `getrandom` bytes per frame, from the same source; they are just
/// drawn 2048 at a time from a thread-local batch. A mask is sent on the wire
/// and the peer unmasks with whatever it receives, so batching changes no byte
/// the peer checks — it only removes the syscall. Returns `None` when the
/// platform has no entropy, exactly as before.
fn fresh_mask() -> Option<[u8; 4]> {
    thread_local! {
        static BATCH: RefCell<([u8; 2048], usize)> = const { RefCell::new(([0u8; 2048], 2048)) };
    }
    BATCH
        .try_with(|cell| {
            let (buf, at) = &mut *cell.borrow_mut();
            if *at + 4 > buf.len() {
                getrandom::getrandom(&mut buf[..]).ok()?;
                *at = 0;
            }
            let mask: [u8; 4] = buf[*at..*at + 4].try_into().ok()?;
            *at += 4;
            Some(mask)
        })
        .ok()?
}

/// Read until `\r\n\r\n`; `None` past the limit.
///
/// [`crate::proxy::read_http_head`] is the one implementation of this, and it is
/// peeked rather than read a byte at a time: the old loop did a one-byte `read_exact`
/// per byte — a syscall per byte, ~500 syscalls for a 500-byte header. A header
/// arrives in one packet, so one peek sees it all and the scan for `\r\n\r\n` is
/// over bytes already in memory. `peek` does not consume, so the exact header length
/// is then read with no over-read — pipelined bytes after the header stay in the
/// kernel for the next reader, exactly as the byte loop left them. Same bytes, same
/// limit, ~250x fewer syscalls per handshake, and the same answer for the two other
/// carriers that were still doing it a byte at a time.
fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT)
}

/// Write handle shared by the relay thread and the control replies.
#[derive(Debug)]
struct Shared {
    /// Socket half every frame is written through, one writer at a time.
    stream: Mutex<TcpStream>,
    /// Whether a close frame already went out, so it goes out once.
    closed: AtomicBool,
}

/// Byte stream over `WebSocket` messages; `Read` yields message payload bytes.
#[derive(Debug)]
pub(crate) struct WsReader {
    /// Socket half frames are read from.
    read: TcpStream,
    /// Shared writer for pong and close replies.
    shared: Arc<Shared>,
    /// Decoded payload bytes not yet consumed.
    backlog: Vec<u8>,
    /// Consumed prefix of `backlog`; takes are counted, never shifted.
    bat: usize,
    /// Early-data bytes served before the first message.
    early: Vec<u8>,
    /// Consumed prefix of `early`; takes are counted, never shifted.
    eat: usize,
    /// Whether the peer closed cleanly, after which reads report `EOF`.
    eof: bool,
}

/// Frame writer; cheap to clone for the relay thread.
#[derive(Debug, Clone)]
pub(crate) struct WsWriter {
    /// Shared socket half every frame is written through.
    shared: Arc<Shared>,
    /// Whether frames are masked, which only clients do.
    masked: bool,
}

impl WsReader {
    /// Decode one frame head from the socket: `(fin, opcode, length, mask)`.
    ///
    /// Two reads however long the head is: the two base bytes, then the
    /// extension and mask bytes in one second read. The old spelling read
    /// each in turn — three syscalls for every masked 16-bit frame, which is
    /// every relay message one way.
    fn frame_head(&mut self) -> Option<(bool, u8, usize, Option<[u8; 4]>)> {
        let mut head = [0u8; 2];
        crate::proxy::read_exact(&mut self.read, &mut head).ok()?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0F;
        let masked = head[1] & 0x80 != 0;
        let marker = usize::from(head[1] & 0x7F);
        let ext_len = if marker == 126 {
            2
        } else if marker == 127 {
            8
        } else {
            0
        };
        let mut rest = [0u8; 12];
        let rest_len = ext_len + if masked { 4 } else { 0 };
        crate::proxy::read_exact(&mut self.read, &mut rest[..rest_len]).ok()?;
        let mut len = marker;
        if marker == 126 {
            len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        } else if marker == 127 {
            len = usize::try_from(u64::from_be_bytes(rest[..8].try_into().ok()?)).ok()?;
        }
        if len > FRAME_LIMIT {
            return None;
        }
        if opcode & 0x08 != 0 && (len > 125 || !fin) {
            return None;
        }
        let mask = if masked {
            let mut mask = [0u8; 4];
            mask.copy_from_slice(&rest[ext_len..ext_len + 4]);
            Some(mask)
        } else {
            None
        };
        Some((fin, opcode, len, mask))
    }

    /// Append one data frame's payload to the backlog, unmasked in place.
    fn data_into(&mut self, len: usize, mask: Option<[u8; 4]>) -> Option<()> {
        if len == 0 {
            return Some(());
        }
        self.backlog.reserve(len);
        let base = self.backlog.len();
        // SAFETY: `reserve` made room and the read below writes every new byte
        // before anything reads it; on a short read the tail is truncated back
        // and `None` returned, so uninitialized bytes are never observed.
        unsafe {
            self.backlog.set_len(base + len);
        }
        if crate::proxy::read_exact(&mut self.read, &mut self.backlog[base..]).is_err() {
            self.backlog.truncate(base);
            return None;
        }
        if let Some(mask) = mask {
            apply_mask(&mut self.backlog[base..], mask);
        }
        Some(())
    }

    /// Decode one data message into the backlog, answering ping and close inline.
    fn message(&mut self) -> Option<usize> {
        let base = self.backlog.len();
        let mut open = false;
        loop {
            let (fin, opcode, len, mask) = self.frame_head()?;
            match opcode {
                OP_CLOSE => {
                    let mut body = [0u8; 125];
                    if len > 0 {
                        crate::proxy::read_exact(&mut self.read, &mut body[..len]).ok()?;
                    }
                    self.reply(OP_CLOSE, &body[..len]);
                    self.eof = true;
                    self.backlog.truncate(base);
                    return None;
                }
                OP_PING => {
                    let mut body = [0u8; 125];
                    if len > 0 {
                        crate::proxy::read_exact(&mut self.read, &mut body[..len]).ok()?;
                    }
                    self.reply(OP_PONG, &body[..len]);
                }
                OP_PONG => {
                    let mut body = [0u8; 125];
                    if len > 0 {
                        crate::proxy::read_exact(&mut self.read, &mut body[..len]).ok()?;
                    }
                }
                OP_DATA | OP_CONT => {
                    let continues = opcode == OP_CONT;
                    if continues && !open || !continues && open {
                        return None;
                    }
                    open = true;
                    self.data_into(len, mask)?;
                    if fin {
                        return Some(self.backlog.len() - base);
                    }
                }
                _ => {
                    self.backlog.truncate(base);
                    return None;
                }
            }
        }
    }

    /// Answer a control frame through the shared writer, at most one close.
    fn reply(&self, opcode: u8, payload: &[u8]) {
        if opcode == OP_CLOSE && self.shared.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = write_frame(&mut stream, false, opcode, payload);
    }
}

impl Read for WsReader {
    /// Fill `buf` with message payload bytes; empty means clean `EOF`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.eat < self.early.len() {
                let n = (self.early.len() - self.eat).min(buf.len());
                buf[..n].copy_from_slice(&self.early[self.eat..self.eat + n]);
                self.eat += n;
                return Ok(n);
            }
            if self.bat < self.backlog.len() {
                let n = (self.backlog.len() - self.bat).min(buf.len());
                buf[..n].copy_from_slice(&self.backlog[self.bat..self.bat + n]);
                self.bat += n;
                return Ok(n);
            }
            self.early.clear();
            self.eat = 0;
            self.backlog.clear();
            self.bat = 0;
            if self.eof {
                return Ok(0);
            }
            if self.message().is_none() {
                return Ok(0);
            }
        }
    }
}

impl WsWriter {
    /// Send one binary message, returning `false` when the socket is gone.
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut stream, self.masked, OP_DATA, data)
    }

    /// Send the close frame once, however the relay is ending.
    ///
    /// `pub(crate)` because a carried protocol ends its carrier itself: a relay
    /// over this carrier has to close the carrier when it stops, and it is not
    /// this module's relay.
    pub(crate) fn close(&self) {
        if self.shared.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = write_frame(&mut stream, self.masked, OP_CLOSE, &CLOSE_BODY);
    }
}

/// [`Write`] over one message per call: bytes in, one binary message out.
///
/// The peer reads a byte stream over messages and never looks at the boundary,
/// so one message per `write` is a byte-identical stream however the caller
/// sizes its writes. This stages nothing: a caller that writes three slices
/// sends three messages carrying the same bytes in the same order, and `flush`
/// is a no-op because there is nothing staged to flush.
impl Write for WsWriter {
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

// The buffer a masked frame is staged in, one per thread that sends one.
//
// Masking has to happen somewhere that is not the caller's buffer, so the frame is
// assembled in a scratch buffer and written from there — but the scratch does not have
// to be fresh. This form allocated and freed the whole frame, head, mask and payload,
// for every message: on a 16 KiB frame that is a 16 KiB `malloc`/`free` pair on the
// hot path, for a buffer whose shape is the same every time. Reused, it is one
// allocation per thread, and a thread that relays one connection holds it for exactly
// that connection's life.
//
// Per thread rather than per writer, because the frame is built while the shared
// writer lock is held and a lock is what a shared buffer would have to sit behind.
thread_local! {
    static MASKED_FRAME: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Encode one frame onto the stream; clients mask, servers never do.
///
/// The header rides on the stack and goes out with the body in one syscall
/// where the platform allows it (see [`crate::proxy::write_all_two`]), so an
/// unmasked frame allocates nothing: the old form staged header plus body in
/// one `Vec`, a full copy of every message. Masked frames still stage once —
/// the mask has to be applied somewhere that is not the caller's buffer — and
/// now stage into [`MASKED_FRAME`] rather than a fresh allocation per message.
/// Same bytes either way.
fn write_frame(stream: &mut TcpStream, masked: bool, opcode: u8, data: &[u8]) -> bool {
    let flag: u8 = if masked { 0x80 } else { 0 };
    let mut head = [0u8; 10];
    head[0] = 0x80 | (opcode & 0x0F);
    let hlen = if data.len() < 126 {
        head[1] = flag | data.len() as u8;
        2
    } else if u16::try_from(data.len()).is_ok() {
        head[1] = flag | 0x7E;
        head[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
        4
    } else {
        head[1] = flag | 0x7F;
        head[2..10].copy_from_slice(&(data.len() as u64).to_be_bytes());
        10
    };
    if !masked {
        return crate::proxy::write_all_two(stream, &head[..hlen], data);
    }
    let Some(mask) = fresh_mask() else {
        return false;
    };
    MASKED_FRAME.with(|cell| {
        let mut frame = cell.borrow_mut();
        frame.clear();
        frame.reserve(hlen + 4 + data.len());
        frame.extend_from_slice(&head[..hlen]);
        frame.extend_from_slice(&mask);
        let base = frame.len();
        frame.extend_from_slice(data);
        apply_mask(&mut frame[base..], mask);
        stream.write_all(&frame).is_ok()
    })
}

/// Accept the upgrade as a server, checking the configured path exactly.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(WsReader, WsWriter)> {
    use std::fmt::Write as _;
    let mut read = stream;
    let head = read_head(&mut read)?;
    if crate::proxy::request_path(&head)? != path {
        return None;
    }
    let key = crate::proxy::header_value(&head, "sec-websocket-key")?;
    if key.is_empty() {
        return None;
    }
    let offered = crate::proxy::header_value(&head, "sec-websocket-protocol").unwrap_or_default();
    let early = early_decode(&offered)
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or_default();
    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        accept_key(&key)
    );
    if !early.is_empty() {
        let _ = write!(response, "Sec-WebSocket-Protocol: {offered}\r\n");
    }
    response.push_str("\r\n");
    read.write_all(response.as_bytes()).ok()?;
    split(read, early, false)
}

/// Perform the upgrade as a client, verifying the accept key before use.
///
/// `first` is the layer above's first write, which is what a `?ed=` budget
/// measures and what it carries: inside the handshake when the whole of it fits
/// in `ed`, and in one frame after the `101` when it does not. It is spent
/// either way, so the caller writes it here and not again, and `ed` of `0`
/// leaves the bytes on the wire exactly where they were before the setting
/// existed. Upstream calls this from inside the first `write` with the socket
/// still held back; passing the bytes in costs one argument and no state.
pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
) -> Option<(WsReader, WsWriter)> {
    let key = fresh_key()?;
    let mut read = stream;
    let (handshake, early) = request(host, path, &key, budget, first);
    read.write_all(handshake.as_bytes()).ok()?;
    let head = read_head(&mut read)?;
    let text = std::str::from_utf8(&head).ok()?;
    if text.split("\r\n").next()?.split(' ').nth(1)? != "101" {
        return None;
    }
    if crate::proxy::header_value(&head, "sec-websocket-accept")? != accept_key(&key) {
        return None;
    }
    let at = head.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let mut behind = Vec::new();
    behind.extend_from_slice(&head[at..]);
    let (reader, writer) = split(read, behind, true)?;
    // An empty `first` is a caller with nothing to spend, and sends no frame:
    // the shape every carrier test that writes after connecting is in.
    if !early && !first.is_empty() && !writer.send(first) {
        return None;
    }
    Some((reader, writer))
}

/// The upgrade request, and whether `first` went into it.
///
/// One buffer, built once, written once. The early-data line is appended in
/// place with the request's own terminator trimmed off, so the encoded digits
/// land in the allocation the handshake was going to make anyway rather than in
/// a second string the four of them upstream would each have built. The returned
/// flag is what the caller spends `first` on: in here, or in a frame.
fn request(host: &str, path: &str, key: &str, budget: u32, first: &[u8]) -> (String, bool) {
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    // Inclusive boundary, and no truncation: past the budget the bytes travel in
    // a frame and early data is off for the rest of the connection.
    let early = !first.is_empty() && first.len() as u64 <= u64::from(budget);
    if early {
        // Two bytes, not four: the last two are the blank line's own CRLF and the
        // header above it keeps its. Taking four joins the new line onto
        // `Sec-WebSocket-Version`, and a server reading that finds no
        // `Sec-WebSocket-Protocol` at all — the request parses and the payload
        // silently vanishes, which is what run 37248505865 measured.
        request.truncate(request.len() - 2);
        request.push_str("Sec-WebSocket-Protocol: ");
        ferrox_core::transport::early_encode_into(&mut request, first);
        request.push_str("\r\n\r\n");
    }
    (request, early)
}

/// Split one socket into its reader and writer halves around early bytes.
fn split(read: TcpStream, early: Vec<u8>, masked: bool) -> Option<(WsReader, WsWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let shared = Arc::new(Shared {
        stream: Mutex::new(write),
        closed: AtomicBool::new(false),
    });
    let reader = WsReader {
        read,
        shared: Arc::clone(&shared),
        backlog: Vec::new(),
        bat: 0,
        early,
        eat: 0,
        eof: false,
    };
    Some((reader, WsWriter { shared, masked }))
}

/// This carrier's write half, as a [`crate::proxy::CarrierSink`].
///
/// Two forwarding methods and nothing else: `relay_sink` is generic over the
/// writer, so the call in the inner loop resolves to `WsWriter::send` here at
/// compile time — the same direct call `relay` made when it was its own function.
impl crate::proxy::CarrierSink for WsWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn close(&self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrox_core::transport::EarlyData;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn accept_matches_the_rfc_example() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn mask_chunks_match_the_byte_loop() {
        // The naive loop stays as the checker: any chunking mistake shows up as
        // a byte difference, and unmasking twice must restore the plaintext.
        for len in [
            0, 1, 3, 4, 5, 15, 16, 17, 31, 32, 33, 63, 64, 255, 1024, 8192,
        ] {
            for mask in [[0u8, 0, 0, 0], [1, 2, 3, 4], [0xFF, 0x00, 0xA5, 0x5A]] {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut want = plain.clone();
                for (i, byte) in want.iter_mut().enumerate() {
                    *byte ^= mask[i & 3];
                }
                let mut got = plain.clone();
                apply_mask(&mut got, mask);
                assert_eq!(got, want, "len {len} mask {mask:?}");
                apply_mask(&mut got, mask);
                assert_eq!(got, plain, "len {len} unmasks");
            }
        }
    }

    #[test]
    fn frames_round_trip_masked_and_plain() {
        for len in [0, 1, 125, 126, 200, 65_535, 65_536] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for masked in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let expected = payload.clone();
                let writer = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().expect("accepts");
                    assert!(write_frame(&mut stream, masked, OP_DATA, &expected));
                });
                let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let shared = Arc::new(Shared {
                    stream: Mutex::new(stream.try_clone().expect("clones")),
                    closed: AtomicBool::new(false),
                });
                let mut reader = WsReader {
                    read: stream,
                    shared,
                    backlog: Vec::new(),
                    bat: 0,
                    early: Vec::new(),
                    eat: 0,
                    eof: false,
                };
                let n = reader.message().expect("reads");
                assert_eq!(&reader.backlog[..n], &payload[..]);
                writer.join().expect("joins");
            }
        }
    }

    #[test]
    fn handshake_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let plain = EarlyData::split("/tunnel");
        let (mut reader, _writer) =
            connect(stream, "127.0.0.1", &plain.path, plain.budget, b"ping").expect("upgrades");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The upgrade request a budget produces, byte for byte.
    ///
    /// The claim is that `?ed=` adds one line and changes nothing else: the
    /// request without it is the request with it minus that line and its
    /// terminator, and the line is the payload's own base64url. Nothing is
    /// truncated at the budget — a payload that does not fit produces no line at
    /// all rather than a shorter one, which is the whole of the boundary rule.
    #[test]
    fn early_data_adds_one_line_and_truncates_nothing() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let prefix = format!(
            "GET /tunnel HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        let plain = format!("{prefix}\r\n");
        assert_eq!(request("example.com", "/tunnel", key, 0, b"hello").0, plain);
        for (payload, budget, rides) in [
            (&b"hello"[..], 5u32, true),
            (&b"hello"[..], 4, false),
            (&b""[..], 2048, false),
            (&b"hi"[..], 2048, true),
            (&b"hi"[..], 2, true),
            (&b"hi"[..], 1, false),
        ] {
            let (got, early) = request("example.com", "/tunnel", key, budget, payload);
            assert_eq!(early, rides, "{payload:?} at {budget}");
            if !rides {
                assert_eq!(got, plain, "{payload:?} at {budget}: no line at all");
                continue;
            }
            let mut line = String::from("Sec-WebSocket-Protocol: ");
            ferrox_core::transport::early_encode_into(&mut line, payload);
            line.push_str("\r\n");
            assert_eq!(
                got,
                format!("{prefix}{line}\r\n"),
                "{payload:?} at {budget}"
            );
        }
    }

    /// Early data over loopback, both sides of the budget's boundary.
    ///
    /// The payload arrives at the server either way, and with a budget that fits
    /// it arrives with no frame on the wire to carry it — the property the
    /// setting buys. Two peers here are this file's own two roles, so what is
    /// proved is the bytes and the arithmetic; the peer that decides the row is
    /// pinned Xray-core, through `conformance.yml`.
    #[test]
    fn early_data_reaches_the_server_with_and_without_a_budget_that_fits() {
        for budget in [2048u32, 4, 3] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accepts");
                let configured = EarlyData::split(&format!("/tunnel?ed={budget}"));
                assert_eq!(configured.budget, budget);
                let (mut reader, _writer) = accept(stream, &configured.path).expect("upgrades");
                let mut buf = [0u8; 4];
                reader.read_exact(&mut buf).expect("reads");
                assert_eq!(&buf, b"ping");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let configured = EarlyData::split(&format!("/tunnel?ed={budget}"));
            connect(
                stream,
                "127.0.0.1",
                &configured.path,
                configured.budget,
                b"ping",
            )
            .expect("upgrades");
            server.join().expect("joins");
        }
    }

    /// A configured budget serves the bare path, because a request's path has no
    /// query in it and the configured one has lost `ed`. This is the shape the
    /// two upstream early-data oracle rows use, in both carriers.
    #[test]
    fn a_configured_budget_serves_the_bare_path() {
        for path in ["/interop-ws?ed=2048", "/interop-ws"] {
            assert_eq!(EarlyData::split(path).path, "/interop-ws", "{path}");
        }
        // `ed=` with nothing after it is not a budget at all, and Xray's guard
        // skips the rewrite for it, so the query stays and nothing can match it.
        assert_eq!(EarlyData::split("/interop-ws?ed=").path, "/interop-ws?ed=");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let configured = EarlyData::split("/interop-ws?ed=2048");
            assert!(accept(stream, &configured.path).is_some());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /interop-ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Key: aGVsbG8gd29ybGQxMjM0NQ==\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }

    #[test]
    fn handshake_rejects_a_wrong_path_and_key() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nSec-WebSocket-Key: k\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
