use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ferrox_core::transport::{early_decode, Mimic};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const HEAD_LIMIT: usize = 16 * 1024;
const FRAME_LIMIT: usize = 16 * 1024 * 1024;
const OP_DATA: u8 = 0x02;
const OP_CONT: u8 = 0x00;
const OP_CLOSE: u8 = 0x08;
const OP_PING: u8 = 0x09;
const OP_PONG: u8 = 0x0A;
const CLOSE_BODY: [u8; 2] = [0x03, 0xE8];

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

fn accept_key(key: &str) -> String {
    use sha1::Digest as _;
    let mut hash = sha1::Sha1::new();
    hash.update(key.trim().as_bytes());
    hash.update(GUID.as_bytes());
    b64_encode(&hash.finalize())
}

fn fresh_key() -> Option<String> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).ok()?;
    Some(b64_encode(&raw))
}

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

#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the vector op inlined at every call site"
)]
#[inline(always)]
fn xor_block(chunk: &mut [u8; 16], wide: &[u8; 16]) {
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::{_mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128};
        unsafe {
            let data = _mm_loadu_si128(chunk.as_ptr().cast());
            let key = _mm_loadu_si128(wide.as_ptr().cast());
            _mm_storeu_si128(chunk.as_mut_ptr().cast(), _mm_xor_si128(data, key));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use core::arch::aarch64::{veorq_u8, vld1q_u8, vst1q_u8};
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

fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT)
}

#[derive(Debug)]
struct Shared {
    stream: Mutex<TcpStream>,
    closed: AtomicBool,
}

#[derive(Debug)]
pub(crate) struct WsReader {
    read: TcpStream,
    shared: Arc<Shared>,
    backlog: Vec<u8>,
    bat: usize,
    early: Vec<u8>,
    eat: usize,
    eof: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WsWriter {
    shared: Arc<Shared>,
    masked: bool,
}

impl WsReader {
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

    fn data_into(&mut self, len: usize, mask: Option<[u8; 4]>) -> Option<()> {
        if len == 0 {
            return Some(());
        }
        self.backlog.reserve(len);
        let base = self.backlog.len();
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
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut stream, self.masked, OP_DATA, data)
    }

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

thread_local! {
    static MASKED_FRAME: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

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

pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
    budget: u32,
    first: &[u8],
    mimic: Mimic,
) -> Option<(WsReader, WsWriter)> {
    let key = fresh_key()?;
    let mut read = stream;
    let (handshake, unsent) = request_mimic(host, path, &key, budget, first, mimic);
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
    if !unsent.is_empty() && !writer.send(unsent) {
        return None;
    }
    Some((reader, writer))
}

fn base_request(host: &str, path: &str, key: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
}

fn push_early_line(request: &mut String, early: &[u8]) {
    request.truncate(request.len() - 2);
    request.push_str("Sec-WebSocket-Protocol: ");
    ferrox_core::transport::early_encode_into(request, early);
    request.push_str("\r\n\r\n");
}

fn request(host: &str, path: &str, key: &str, budget: u32, first: &[u8]) -> (String, bool) {
    let mut request = base_request(host, path, key);
    let early = !first.is_empty() && first.len() as u64 <= u64::from(budget);
    if early {
        push_early_line(&mut request, first);
    }
    (request, early)
}

fn request_mimic<'a>(
    host: &str,
    path: &str,
    key: &str,
    budget: u32,
    first: &'a [u8],
    mimic: Mimic,
) -> (String, &'a [u8]) {
    match mimic {
        Mimic::SingBox => {
            let mut request = base_request(host, path, key);
            let at = (budget as usize).min(first.len());
            if at > 0 {
                push_early_line(&mut request, &first[..at]);
            }
            (request, &first[at..])
        }
        Mimic::Xray | Mimic::Zray => {
            let (request, early) = request(host, path, key, budget, first);
            (request, if early { &[][..] } else { first })
        }
    }
}

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
        let (mut reader, _writer) = connect(
            stream,
            "127.0.0.1",
            &plain.path,
            plain.budget,
            b"ping",
            Mimic::Xray,
        )
        .expect("upgrades");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

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
        for (payload, budget, early_len) in [
            (&b"hello"[..], 5u32, 5usize),
            (&b"hello"[..], 4, 4),
            (&b"hello"[..], 0, 0),
            (&b""[..], 2048, 0),
        ] {
            let (got, unsent) = request_mimic(
                "example.com",
                "/tunnel",
                key,
                budget,
                payload,
                Mimic::SingBox,
            );
            assert_eq!(unsent, &payload[early_len..], "{payload:?} at {budget}");
            let mut line = String::from("Sec-WebSocket-Protocol: ");
            ferrox_core::transport::early_encode_into(&mut line, &payload[..early_len]);
            if early_len == 0 {
                assert_eq!(got, plain, "{payload:?} at {budget}: no line at all");
            } else {
                line.push_str("\r\n");
                assert_eq!(
                    got,
                    format!("{prefix}{line}\r\n"),
                    "{payload:?} at {budget}"
                );
            }
        }
    }

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
                Mimic::Xray,
            )
            .expect("upgrades");
            server.join().expect("joins");
        }
    }

    #[test]
    fn singbox_sends_what_does_not_fit_after_the_101() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, _writer) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        connect(stream, "127.0.0.1", "/tunnel", 3, b"ping", Mimic::SingBox).expect("upgrades");
        server.join().expect("joins");
    }

    #[test]
    fn a_configured_budget_serves_the_bare_path() {
        for path in ["/interop-ws?ed=2048", "/interop-ws"] {
            assert_eq!(EarlyData::split(path).path, "/interop-ws", "{path}");
        }
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
