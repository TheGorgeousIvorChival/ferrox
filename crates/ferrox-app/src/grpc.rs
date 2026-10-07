use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};

const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const T_DATA: u8 = 0x00;
const T_HEADERS: u8 = 0x01;
const T_RST: u8 = 0x03;
const T_SETTINGS: u8 = 0x04;
const T_PING: u8 = 0x06;
const T_GOAWAY: u8 = 0x07;
const T_WINDOW: u8 = 0x08;
const T_CONT: u8 = 0x09;
const F_END: u8 = 0x01;
const F_ACK: u8 = 0x01;
const F_END_HEADERS: u8 = 0x04;
const F_PADDED: u8 = 0x08;
const F_PRIORITY: u8 = 0x20;
const S_WINDOW: u16 = 0x04;
const S_MAX_FRAME: u16 = 0x05;
const E_REFUSED: u32 = 0x07;
const WINDOW: u32 = 4 * 1024 * 1024;
const FRAME_CAP: usize = 17 * 1024 * 1024;
const HEAD_CAP: usize = 64 * 1024;
const MSG_CAP: usize = 16 * 1024 * 1024;
const HUNK: usize = 16 * 1024;
const WINDOW_MAX: u64 = (1 << 31) - 1;

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

fn push_str(out: &mut Vec<u8>, text: &str) {
    push_int(out, 7, 0x00, text.len());
    out.extend_from_slice(text.as_bytes());
}

fn block_encode(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.push(0x00);
        push_str(&mut out, name);
        push_str(&mut out, value);
    }
    out
}

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

fn string_decode(block: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let huffman = block.first()? & 0x80 != 0;
    let (len, mut rest) = prefixed(block, 7)?;
    if rest.len() < len {
        return None;
    }
    let (raw, tail) = rest.split_at(len);
    rest = tail;
    if huffman {
        let mut out = Vec::new();
        ferrox_core::foxy::hpack::huffman_decode(raw, &mut out)?;
        Some((out, rest))
    } else {
        Some((raw.to_vec(), rest))
    }
}

#[derive(Debug, Default)]
struct Decoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
}

impl Decoder {
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

fn write_frame_parts(
    stream: &mut TcpStream,
    kind: u8,
    flags: u8,
    id: u32,
    first: &[u8],
    second: &[u8],
) -> bool {
    let mut head = [0u8; 9];
    let len = first.len() + second.len();
    head[0..3].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&id.to_be_bytes());
    crate::proxy::write_all_three(stream, &head, first, second)
}

fn write_frame(stream: &mut TcpStream, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
    let mut head = [0u8; 9];
    head[0..3].copy_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    head[3] = kind;
    head[4] = flags;
    head[5..9].copy_from_slice(&id.to_be_bytes());
    crate::proxy::write_all_two(stream, &head, body)
}

#[derive(Debug, Default)]
struct SendWindow {
    conn: u64,
    stream: u64,
}

#[derive(Debug)]
struct Shared {
    stream: Mutex<TcpStream>,
    send: Mutex<SendWindow>,
    wake: Condvar,
    max_frame: Mutex<usize>,
    init: Mutex<u64>,
    ended: AtomicBool,
    dead: AtomicBool,
}

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

#[derive(Debug)]
pub(crate) struct GrpcReader {
    read: TcpStream,
    shared: Arc<Shared>,
    decoder: Decoder,
    stream: u32,
    server: bool,
    path: String,
    answered: bool,
    head: Vec<u8>,
    head_id: u32,
    msg: Vec<u8>,
    msg_at: usize,
    need: usize,
    backlog: Vec<u8>,
    backlog_at: usize,
    frame: Vec<u8>,
    eof: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct GrpcWriter {
    shared: Arc<Shared>,
    stream: u32,
}

impl GrpcReader {
    fn emit(&self, kind: u8, flags: u8, id: u32, body: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        write_frame(&mut stream, kind, flags, id, body)
    }

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

    fn ping(&self, flags: u8, body: &[u8]) {
        if flags & F_ACK == 0 && body.len() == 8 {
            self.emit(T_PING, F_ACK, 0, body);
        }
    }

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

    fn refuse(&self, id: u32) {
        self.emit(T_RST, 0, id, &E_REFUSED.to_be_bytes());
    }

    fn find<'a>(headers: &'a [(Vec<u8>, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
        headers.iter().find_map(|(key, value)| {
            key.eq_ignore_ascii_case(name.as_bytes())
                .then_some(value.as_slice())
        })
    }

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
                let msg = &self.msg[self.msg_at..];
                if msg.len() < 5 {
                    break;
                }
                if msg[0] != 0 {
                    return None;
                }
                let len = u32::from_be_bytes(msg[1..5].try_into().unwrap()) as usize;
                if len > MSG_CAP {
                    return None;
                }
                self.need = len;
                self.msg_at += 5;
            } else {
                let msg = &self.msg[self.msg_at..];
                if msg.len() < self.need {
                    break;
                }
                let payload = hunk_decode(&msg[..self.need])?;
                self.backlog.extend_from_slice(payload);
                self.msg_at += self.need;
                self.need = 0;
            }
        }
        if self.msg_at * 2 >= self.msg.len() {
            let at = self.msg_at;
            self.msg.copy_within(at.., 0);
            self.msg.truncate(self.msg.len() - at);
            self.msg_at = 0;
        }
        if end {
            if self.need != 0 || self.msg_at != self.msg.len() {
                return None;
            }
            self.eof = true;
        }
        Some(())
    }

    fn pump(&mut self) -> Option<()> {
        let head = read_head(&mut self.read);
        let (len, kind, flags, id) = head?;
        let mut frame = std::mem::take(&mut self.frame);
        crate::proxy::resize_scratch(&mut frame, len);
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
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.backlog_at < self.backlog.len() {
                let n = (self.backlog.len() - self.backlog_at).min(buf.len());
                buf[..n].copy_from_slice(&self.backlog[self.backlog_at..self.backlog_at + n]);
                self.backlog_at += n;
                if self.backlog_at * 2 >= self.backlog.len() {
                    let at = self.backlog_at;
                    self.backlog.copy_within(at.., 0);
                    self.backlog.truncate(self.backlog.len() - at);
                    self.backlog_at = 0;
                }
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
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        for piece in data.chunks(HUNK) {
            if !self.message(piece, false) {
                return false;
            }
        }
        true
    }

    pub(crate) fn close(&self) {
        if self.shared.ended.swap(true, Ordering::SeqCst) {
            return;
        }
        self.message(&[], true);
    }

    fn message(&self, data: &[u8], end: bool) -> bool {
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(data.len(), &mut prefix);
        let total = plen + data.len();
        let max = *self
            .shared
            .max_frame
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let max = max.max(1);
        let mut at = 0;
        while at < total {
            let n = (total - at).min(max);
            let last = at + n == total;
            if !take_window(&self.shared, n as u64) {
                return false;
            }
            let flags = if last && end { F_END } else { 0 };
            let Ok(mut stream) = self.shared.stream.lock() else {
                return false;
            };
            let wrote = if at + n <= plen {
                write_frame(&mut stream, T_DATA, flags, self.stream, &prefix[at..at + n])
            } else if at >= plen {
                let from = at - plen;
                write_frame(
                    &mut stream,
                    T_DATA,
                    flags,
                    self.stream,
                    &data[from..from + n],
                )
            } else {
                write_frame_parts(
                    &mut stream,
                    T_DATA,
                    flags,
                    self.stream,
                    &prefix[at..plen],
                    &data[..n - (plen - at)],
                )
            };
            if !wrote {
                return false;
            }
            drop(stream);
            at += n;
        }
        true
    }
}

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

fn frame_prefix(data_len: usize, out: &mut [u8; 16]) -> usize {
    let mut value = data_len as u64;
    let mut at = 6;
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out[at] = byte;
            at += 1;
            break;
        }
        out[at] = byte | 0x80;
        at += 1;
    }
    let inner = (at - 5 + data_len) as u32;
    out[0] = 0;
    out[1..5].copy_from_slice(&inner.to_be_bytes());
    out[5] = 0x0A;
    at
}

#[cfg(test)]
fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 & 0x7F | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

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
        msg_at: 0,
        need: 0,
        backlog: Vec::new(),
        backlog_at: 0,
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
        msg_at: 0,
        need: 0,
        backlog: Vec::new(),
        backlog_at: 0,
        frame: Vec::new(),
        eof: false,
    };
    Some((reader, GrpcWriter { shared, stream: 1 }))
}

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
        let mut plain = Vec::new();
        ferrox_core::foxy::hpack::huffman_decode(&coded, &mut plain).expect("decodes");
        assert_eq!(plain, b"www.example.com");
        assert!(ferrox_core::foxy::hpack::huffman_decode(b"\xff", &mut Vec::new()).is_none());
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
        let mut prefix = [0u8; 16];
        let plen = frame_prefix(4, &mut prefix);
        let mut frame = prefix[..plen].to_vec();
        frame.extend_from_slice(b"ping");
        assert_eq!(frame, b"\0\0\0\0\x06\x0a\x04ping");
        assert_eq!(
            hunk_decode(&[0x0A, 0x04, b'p', b'i', b'n', b'g']).expect("decodes"),
            b"ping"
        );
        assert!(hunk_decode(b"raw payload").is_none());
        assert!(hunk_decode(&[0x0A, 0x80]).is_none());
    }

    #[test]
    fn messages_frame_identically_at_every_chunk_size() {
        for max in [1usize, 2, 5, 6, 7, 8, 11, 16, 100, 16_384] {
            for len in [0usize, 1, 4, 127, 300] {
                let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut want = vec![0u8; 5];
                want.push(0x0A);
                push_varint(&mut want, len as u64);
                want.extend_from_slice(&data);
                let hunk_len = (want.len() - 5) as u32;
                want[1..5].copy_from_slice(&hunk_len.to_be_bytes());

                let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
                let port = listener.local_addr().expect("addr").port();
                let handle = thread::spawn(move || {
                    let (stream, _) = listener.accept().expect("accepts");
                    let shared = Arc::new(Shared {
                        stream: Mutex::new(stream),
                        send: Mutex::new(SendWindow {
                            conn: u64::MAX,
                            stream: u64::MAX,
                        }),
                        wake: Condvar::new(),
                        max_frame: Mutex::new(max),
                        init: Mutex::new(u64::from(WINDOW)),
                        ended: AtomicBool::new(false),
                        dead: AtomicBool::new(false),
                    });
                    let writer = GrpcWriter { shared, stream: 1 };
                    assert!(writer.message(&data, true), "max {max} len {len}");
                });
                let mut read = TcpStream::connect(("127.0.0.1", port)).expect("connects");
                let mut wire = Vec::new();
                read.read_to_end(&mut wire).expect("reads");
                handle.join().expect("joins");
                let mut body = Vec::new();
                let mut at = 0;
                while at < wire.len() {
                    let head = &wire[at..at + 9];
                    let len = usize::from(head[0]) << 16
                        | usize::from(head[1]) << 8
                        | usize::from(head[2]);
                    assert_eq!(head[3], T_DATA, "max {max} len {len}");
                    assert_eq!(u32::from_be_bytes(head[5..9].try_into().unwrap()), 1);
                    at += 9;
                    body.extend_from_slice(&wire[at..at + len]);
                    at += len;
                }
                assert_eq!(body, want, "max {max} len {len}");
            }
        }
    }

    #[test]
    fn frame_prefix_matches_the_vec_form_at_varint_edges() {
        for len in [0usize, 1, 127, 128, 300, 16383, 16384, 1 << 21, 1 << 28] {
            let mut varint = Vec::new();
            push_varint(&mut varint, len as u64);
            let inner = (1 + varint.len() + len) as u32;
            let mut want = vec![0u8];
            want.extend_from_slice(&inner.to_be_bytes());
            want.push(0x0A);
            want.extend_from_slice(&varint);
            let mut prefix = [0u8; 16];
            let plen = frame_prefix(len, &mut prefix);
            assert_eq!(&prefix[..plen], &want[..], "len {len}");
        }
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
