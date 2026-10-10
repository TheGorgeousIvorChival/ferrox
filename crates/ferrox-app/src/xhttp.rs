use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex};

const HEAD_LIMIT: usize = 64 * 1024;
const CHUNK: usize = 16 * 1024;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

fn path_covers(configured: &str, requested: &str) -> bool {
    if configured == "/" {
        return requested.starts_with('/');
    }
    requested == configured
        || requested
            .strip_prefix(configured)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn bare_path(target: &str) -> &str {
    target.split_once('?').map_or(target, |(base, _)| base)
}

fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT).map(|head| (head, Vec::new()))
}

fn size_line(n: usize, out: &mut [u8; 6]) -> usize {
    debug_assert!((1..=CHUNK).contains(&n));
    let width = (usize::BITS - n.leading_zeros()).div_ceil(4) as usize;
    for i in 0..width {
        out[width - 1 - i] = HEX[n >> (4 * i) & 0xf];
    }
    out[width] = b'\r';
    out[width + 1] = b'\n';
    width + 2
}

fn read_line_into(reader: &mut Reader<impl Read>, out: &mut [u8; 130]) -> Option<usize> {
    loop {
        if let Some(end) = reader.prefix[reader.at..]
            .windows(2)
            .position(|w| w == b"\r\n")
        {
            if end > 127 {
                return None;
            }
            out[..end].copy_from_slice(&reader.prefix[reader.at..reader.at + end]);
            reader.at += end + 2;
            return Some(end);
        }
        if reader.prefix.len() - reader.at >= 129 {
            return None;
        }
        if reader.at >= reader.prefix.len() {
            reader.prefix.clear();
            reader.at = 0;
        } else if reader.at > 0 {
            reader.prefix.drain(..reader.at);
            reader.at = 0;
        }
        let mut tmp = [0u8; 128];
        match reader.take(&mut tmp) {
            Ok(n) if n > 0 => reader.prefix.extend_from_slice(&tmp[..n]),
            _ => return None,
        }
    }
}

fn chunk_size(line: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(line).ok()?;
    let size = text.split(';').next().unwrap_or_default().trim();
    if size.is_empty() || size.len() > 16 {
        return None;
    }
    usize::from_str_radix(size, 16).ok()
}

/// Generic over the underlying `Read` so a test can drive it from an in-memory
/// stream and count the reads, the way `WsReader` counts its own. `reads` is
/// that counter: the read-syscall row is measured from it.
#[derive(Debug)]
pub(crate) struct Reader<R> {
    read: R,
    prefix: Vec<u8>,
    at: usize,
    left: usize,
    ended: bool,
    reads: usize,
}

pub(crate) type XhttpReader = Reader<TcpStream>;

impl<R: Read> Reader<R> {
    /// Every read that reaches the stream, counted where it happens; quiet sockets retry.
    fn take(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.reads += 1;
            match self.read.read(buf) {
                Err(error) if crate::proxy::is_timeout(&error) => {}
                outcome => return outcome,
            }
        }
    }

    /// The syscall counter, read by `a_chunk_costs_two_reads_not_three` and
    /// `a_real_socket_drains_the_same_bytes`.
    #[cfg_attr(not(test), expect(dead_code, reason = "only the gate reads it"))]
    #[must_use]
    pub(crate) fn reads(&self) -> usize {
        self.reads
    }
}

impl<R: Read> Reader<R> {
    fn body(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            return Some(n);
        }
        match self.take(buf) {
            Ok(n) if n > 0 => Some(n),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct XhttpWriter {
    shared: Arc<Shared>,
}

struct Shared {
    stream: Mutex<Box<dyn crate::proxy::FrameWrite + Send>>,
    finished: AtomicBool,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.ended {
                return Ok(0);
            }
            if self.left > 0 {
                let n = self.left.min(buf.len());
                let got = self
                    .body(&mut buf[..n])
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
                self.left -= got;
                if self.left == 0 {
                    let mut crlf = [0u8; 2];
                    if self.at < self.prefix.len() {
                        if self.prefix.len() - self.at < 2 {
                            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                        }
                        crlf.copy_from_slice(&self.prefix[self.at..self.at + 2]);
                        self.at += 2;
                    } else {
                        // One window instead of a two-byte read: the bytes past
                        // the CRLF are the next size line, which `read_line_into`
                        // then finds without asking the socket again.
                        // Loop until two bytes are buffered: a peer that
                        // segments the CRLF across reads still gets through,
                        // which a single read would have refused.
                        self.prefix.clear();
                        let mut got = 0usize;
                        while got < 2 {
                            let mut tmp = [0u8; 128];
                            let n = self.take(&mut tmp).map_err(|_| {
                                std::io::Error::from(std::io::ErrorKind::InvalidData)
                            })?;
                            if n == 0 {
                                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                            }
                            self.prefix.extend_from_slice(&tmp[..n]);
                            got += n;
                        }
                        crlf.copy_from_slice(&self.prefix[..2]);
                        self.at = 2;
                    }
                    if crlf != *b"\r\n" {
                        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                    }
                }
                return Ok(got);
            }
            let mut line = [0u8; 130];
            let len = read_line_into(self, &mut line)
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            let size = chunk_size(&line[..len])
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
            if size == 0 {
                loop {
                    let mut trailer = [0u8; 130];
                    let len = read_line_into(self, &mut trailer)
                        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
                    if len == 0 {
                        break;
                    }
                }
                self.ended = true;
                return Ok(0);
            }
            if size > 64 * 1024 * 1024 {
                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
            }
            self.left = size;
        }
    }
}

impl XhttpWriter {
    #[allow(dead_code)]
    pub(crate) fn new<W: crate::proxy::FrameWrite + Send + 'static>(w: W) -> Self {
        Self {
            shared: Arc::new(Shared {
                stream: Mutex::new(Box::new(w) as Box<dyn crate::proxy::FrameWrite + Send>),
                finished: AtomicBool::new(false),
            }),
        }
    }
    pub(crate) fn send(&self, data: &[u8]) -> bool {
        let Ok(mut stream) = self.shared.stream.lock() else {
            return false;
        };
        for piece in data.chunks(CHUNK) {
            if piece.is_empty() {
                continue;
            }
            let mut line = [0u8; 6];
            let len = size_line(piece.len(), &mut line);
            if !stream.write_slices(&[&line[..len], piece, b"\r\n"]) {
                return false;
            }
        }
        true
    }
    pub(crate) fn finish(&self) {
        if self.shared.finished.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = self.shared.stream.lock() else {
            return;
        };
        let _ = stream.write_all(b"0\r\n\r\n");
    }
}

impl Write for XhttpWriter {
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

fn split(read: TcpStream, prefix: Vec<u8>) -> Option<(XhttpReader, XhttpWriter)> {
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some(split_halves(read, write, prefix))
}

// The same split over halves that cannot clone: the handshake leaves pipelined bytes as the prefix.
fn split_halves<R: Read, W: crate::proxy::FrameWrite + 'static>(
    read: R,
    write: W,
    prefix: Vec<u8>,
) -> (Reader<R>, XhttpWriter) {
    let reader = Reader {
        read,
        prefix,
        at: 0,
        left: 0,
        ended: false,
        reads: 0,
    };
    let writer = XhttpWriter {
        shared: Arc::new(Shared {
            stream: Mutex::new(Box::new(write) as Box<dyn crate::proxy::FrameWrite + Send>),
            finished: AtomicBool::new(false),
        }),
    };
    (reader, writer)
}

fn has_chunked(value: &str) -> bool {
    value
        .as_bytes()
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"chunked"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum XhttpMode {
    StreamOne,
    StreamUp,
    PacketUp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Placement {
    Path,
    Query,
    Header,
    Cookie,
    Body,
    Auto,
    QueryInHeader,
}

#[allow(dead_code)]
impl Placement {
    fn parse(s: &str) -> Option<Placement> {
        Some(match s {
            "path" => Placement::Path,
            "query" => Placement::Query,
            "header" => Placement::Header,
            "cookie" => Placement::Cookie,
            "body" => Placement::Body,
            "auto" => Placement::Auto,
            "queryInHeader" => Placement::QueryInHeader,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PadMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct XhttpSettings {
    pub path: String,
    pub mode: XhttpMode,
    pub session_placement: Placement,
    pub session_key: String,
    pub seq_placement: Placement,
    pub seq_key: String,
    pub uplink_data_placement: Placement,
    pub uplink_data_key: String,
    pub uplink_method: String,
    pub x_padding_bytes: (u32, u32),
    pub x_padding_obfs: bool,
    pub x_padding_placement: Placement,
    pub x_padding_key: String,
    pub x_padding_header: String,
    pub x_padding_method: PadMethod,
    pub sc_max_each_post: usize,
    pub sc_max_buffered: usize,
    pub sc_min_posts_interval_ms: u64,
    pub no_sse: bool,
    pub no_grpc_header: bool,
}

#[allow(dead_code)]
impl XhttpSettings {
    pub(crate) fn stream_one() -> Self {
        Self {
            path: "/".to_owned(),
            mode: XhttpMode::StreamOne,
            session_placement: Placement::Path,
            session_key: String::new(),
            seq_placement: Placement::Path,
            seq_key: String::new(),
            uplink_data_placement: Placement::Body,
            uplink_data_key: String::new(),
            uplink_method: "POST".to_owned(),
            x_padding_bytes: (100, 1000),
            x_padding_obfs: false,
            x_padding_placement: Placement::Header,
            x_padding_key: "x_padding".to_owned(),
            x_padding_header: "X-Padding".to_owned(),
            x_padding_method: PadMethod::RepeatX,
            sc_max_each_post: 1_000_000,
            sc_max_buffered: 30,
            sc_min_posts_interval_ms: 30,
            no_sse: false,
            no_grpc_header: false,
        }
    }
}

#[allow(dead_code)]
const HUFFMAN_CODE_LEN: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[allow(dead_code)]
fn huffman_len(s: &[u8]) -> usize {
    s.iter()
        .map(|&b| HUFFMAN_CODE_LEN[b as usize] as usize)
        .sum::<usize>()
        .div_ceil(8)
}

#[allow(dead_code)]
fn generate_tokenish(target_huffman_bytes: usize) -> String {
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let n = (target_huffman_bytes * 10).div_ceil(8);
    let mut raw = vec![0u8; n.max(1)];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    let mut s: String = raw
        .iter()
        .map(|&b| BASE62[(b as usize) % 62] as char)
        .collect();
    for iter in 0..150 {
        let cur = huffman_len(s.as_bytes());
        if cur.abs_diff(target_huffman_bytes) <= 2 {
            return s;
        }
        if cur < target_huffman_bytes {
            s.push(if iter % 2 == 0 { 'X' } else { 'Z' });
        } else if s.len() > 1 {
            s.pop();
        } else {
            return s;
        }
    }
    s
}

#[allow(dead_code)]
fn pad_value(method: PadMethod, len: usize) -> String {
    match method {
        PadMethod::RepeatX => "X".repeat(len),
        PadMethod::Tokenish => generate_tokenish(len),
    }
}

#[allow(dead_code)]
fn pad_target_len(settings: &XhttpSettings) -> usize {
    let (from, to) = settings.x_padding_bytes;
    if to <= from {
        return from as usize;
    }
    let mut raw = [0u8; 4];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    from as usize + (u32::from_le_bytes(raw) as usize % (to as usize - from as usize + 1))
}

#[allow(dead_code)]
fn padding_valid(value: &str, from: u32, to: u32, method: PadMethod) -> bool {
    if value.is_empty() {
        return false;
    }
    match method {
        PadMethod::RepeatX => {
            let n = value.len() as u32;
            n >= from && n <= to
        }
        PadMethod::Tokenish => {
            let n = huffman_len(value.as_bytes()) as u32;
            n >= from.saturating_sub(2) && n <= to + 2
        }
    }
}

#[allow(dead_code)]
fn query_param<'a>(target: &'a str, key: &str) -> Option<&'a str> {
    let q = target.split_once('?')?.1;
    for part in q.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            if k == key {
                return Some(v);
            }
        }
    }
    None
}

#[allow(dead_code)]
fn header_cookie<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    for line in text.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.eq_ignore_ascii_case("cookie") {
            for part in v.trim().split(';') {
                let Some((n, val)) = part.trim().split_once('=') else {
                    continue;
                };
                if n == name {
                    return Some(val);
                }
            }
        }
    }
    None
}

#[allow(dead_code)]
fn extract_padding<'a>(
    head: &'a [u8],
    target: &'a str,
    settings: &XhttpSettings,
) -> Option<&'a str> {
    if !settings.x_padding_obfs {
        if let Some(remark) = crate::proxy::header_value(head, "referer") {
            if let Some(v) = query_param(remark, "x_padding") {
                return Some(v);
            }
        }
        return query_param(target, "x_padding");
    }
    if let Some(cookie) = header_cookie(head, &settings.x_padding_key) {
        return Some(cookie);
    }
    if let Some(value) =
        crate::proxy::header_value(head, &settings.x_padding_header.to_ascii_lowercase())
    {
        if settings.x_padding_placement == Placement::Header {
            return Some(value);
        }
        if let Some(v) = query_param(value, &settings.x_padding_key) {
            return Some(v);
        }
    }
    query_param(target, &settings.x_padding_key)
}

#[allow(dead_code)]
fn extract_meta<'a>(
    head: &'a [u8],
    target: &'a str,
    settings: &XhttpSettings,
) -> (Option<&'a str>, Option<&'a str>) {
    let segments: Vec<&str> = {
        let rest = target.strip_prefix(settings.path.as_str()).unwrap_or("");
        let rest_path = rest.split_once('?').map_or(rest, |(r, _)| r);
        rest_path.split('/').filter(|s| !s.is_empty()).collect()
    };
    let mut sid = None;
    let mut seq = None;
    let mut idx = 0;
    if settings.session_placement == Placement::Path {
        sid = segments.get(idx).copied();
        idx += 1;
    }
    if settings.seq_placement == Placement::Path {
        seq = segments.get(idx).copied();
    }
    if settings.session_placement == Placement::Query {
        sid = query_param(target, &settings.session_key);
    }
    if settings.session_placement == Placement::Header {
        sid = crate::proxy::header_value(head, &settings.session_key.to_ascii_lowercase());
    }
    if settings.session_placement == Placement::Cookie {
        sid = header_cookie(head, &settings.session_key);
    }
    if settings.seq_placement == Placement::Query {
        seq = query_param(target, &settings.seq_key);
    }
    if settings.seq_placement == Placement::Header {
        seq = crate::proxy::header_value(head, &settings.seq_key.to_ascii_lowercase());
    }
    if settings.seq_placement == Placement::Cookie {
        seq = header_cookie(head, &settings.seq_key);
    }
    (sid, seq)
}

#[allow(dead_code)]
struct Session {
    state: Mutex<SessionState>,
    cv: Condvar,
}

#[allow(dead_code)]
struct SessionState {
    upload: Option<Box<dyn Read + Send>>,
    packets: BTreeMap<u64, Vec<u8>>,
    next_seq: u64,
    ended: bool,
}

#[allow(dead_code)]
type Sessions = Mutex<HashMap<String, Arc<Session>>>;

#[allow(dead_code)]
fn sessions() -> &'static Sessions {
    static CELL: LazyLock<Sessions> = LazyLock::new(|| Mutex::new(HashMap::new()));
    &CELL
}

#[allow(dead_code)]
fn get_or_create_session(id: &str) -> Arc<Session> {
    let mut map = sessions().lock().expect("sessions lock");
    map.entry(id.to_owned())
        .or_insert_with(|| {
            Arc::new(Session {
                state: Mutex::new(SessionState {
                    upload: None,
                    packets: BTreeMap::new(),
                    next_seq: 0,
                    ended: false,
                }),
                cv: Condvar::new(),
            })
        })
        .clone()
}

#[allow(dead_code)]
fn close_session(s: &Arc<Session>) {
    let mut st = s.state.lock().expect("session lock");
    st.ended = true;
    s.cv.notify_all();
}

#[allow(dead_code)]
impl Session {
    fn set_upload(&self, reader: Box<dyn Read + Send>) {
        let mut st = self.state.lock().expect("session lock");
        st.upload = Some(reader);
        self.cv.notify_all();
    }
    fn push_packet(&self, seq: u64, payload: Vec<u8>) {
        let mut st = self.state.lock().expect("session lock");
        st.packets.insert(seq, payload);
        self.cv.notify_all();
    }
    fn wait_ended(&self) {
        let mut st = self.state.lock().expect("session lock");
        while !st.ended {
            st = self.cv.wait(st).expect("session lock");
        }
    }
}

#[allow(dead_code)]
struct SessionReader {
    session: Arc<Session>,
    id: String,
    cur: Vec<u8>,
    cur_at: usize,
}

#[allow(dead_code)]
impl SessionReader {
    fn new(session: Arc<Session>, id: String) -> Self {
        Self {
            session,
            id,
            cur: Vec::new(),
            cur_at: 0,
        }
    }
}

#[allow(dead_code)]
impl Read for SessionReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let upload = {
                let mut st = self.session.state.lock().expect("session lock");
                st.upload.take()
            };
            if let Some(mut upload) = upload {
                let got = upload.read(buf);
                let mut st = self.session.state.lock().expect("session lock");
                st.upload = Some(upload);
                return match got {
                    Ok(0) => {
                        st.ended = true;
                        self.session.cv.notify_all();
                        Ok(0)
                    }
                    Ok(n) => {
                        drop(st);
                        Ok(n)
                    }
                    Err(e) => {
                        st.ended = true;
                        self.session.cv.notify_all();
                        Err(e)
                    }
                };
            }
            let mut st = self.session.state.lock().expect("session lock");
            if self.cur_at < self.cur.len() {
                let avail = &self.cur[self.cur_at..];
                let n = avail.len().min(buf.len());
                buf[..n].copy_from_slice(&avail[..n]);
                self.cur_at += n;
                if self.cur_at == self.cur.len() {
                    self.cur.clear();
                    self.cur_at = 0;
                }
                return Ok(n);
            }
            if let Some(pkt) = {
                let seq = st.next_seq;
                st.packets.remove(&seq)
            } {
                st.next_seq += 1;
                if pkt.len() <= buf.len() {
                    buf[..pkt.len()].copy_from_slice(&pkt);
                    return Ok(pkt.len());
                }
                self.cur = pkt;
                self.cur_at = buf.len();
                buf.copy_from_slice(&self.cur[..buf.len()]);
                return Ok(buf.len());
            }
            if st.ended {
                return Ok(0);
            }
            st = self.session.cv.wait(st).expect("session lock");
        }
    }
}

#[allow(dead_code)]
impl Drop for SessionReader {
    fn drop(&mut self) {
        if !self.id.is_empty() {
            let mut map = sessions().lock().expect("sessions lock");
            map.remove(&self.id);
        }
        close_session(&self.session);
    }
}

#[allow(dead_code)]
fn downlink_headers(settings: &XhttpSettings) -> String {
    if settings.no_sse {
        String::new()
    } else {
        "Content-Type: text/event-stream\r\n".to_owned()
    }
}

#[allow(dead_code)]
fn padded_response(stream: &mut impl Write, settings: &XhttpSettings, padded: &str, framing: &str) {
    let mut head = String::from("HTTP/1.1 200 OK\r\n");
    if settings.x_padding_obfs {
        match settings.x_padding_placement {
            Placement::Header => {
                head.push_str(&settings.x_padding_header);
                head.push_str(": ");
                head.push_str(padded);
                head.push_str("\r\n");
            }
            Placement::Cookie => {
                head.push_str("Set-Cookie: ");
                head.push_str(&settings.x_padding_key);
                head.push('=');
                head.push_str(padded);
                head.push_str("; Path=/\r\n");
            }
            _ => {
                head.push_str("X-Padding: ");
                head.push_str(padded);
                head.push_str("\r\n");
            }
        }
    } else {
        head.push_str("X-Padding: ");
        head.push_str(padded);
        head.push_str("\r\n");
    }
    head.push_str("X-Accel-Buffering: no\r\n");
    head.push_str("Cache-Control: no-store\r\n");
    head.push_str(&downlink_headers(settings));
    head.push_str(framing);
    let _ = stream.write_all(head.as_bytes());
}

#[allow(dead_code)]
fn sse_ok(stream: &mut impl Write, settings: &XhttpSettings, padded: &str) {
    padded_response(
        stream,
        settings,
        padded,
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
    );
}

#[allow(dead_code)]
fn plain_ok(stream: &mut impl Write, settings: &XhttpSettings, padded: &str) {
    padded_response(
        stream,
        settings,
        padded,
        "Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    );
}

fn ok_status(head: &[u8]) -> bool {
    std::str::from_utf8(head)
        .ok()
        .and_then(|t| t.lines().next().map(|l| l.starts_with("HTTP/1.1 200 OK")))
        .unwrap_or(false)
}

fn check_response(head: &[u8]) -> Option<()> {
    if !ok_status(head) {
        return None;
    }
    if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
}

#[allow(dead_code)]
fn emit_404(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
#[allow(dead_code)]
fn emit_400(stream: &mut impl Write) {
    let _ = stream
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}
#[allow(dead_code)]
fn emit_405(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}
#[allow(dead_code)]
fn emit_413(stream: &mut impl Write) {
    let _ = stream.write_all(
        b"HTTP/1.1 413 Request Entity Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

#[allow(dead_code)]
fn content_length(head: &[u8]) -> Option<usize> {
    crate::proxy::header_value(head, "content-length").and_then(|v| v.trim().parse().ok())
}

#[allow(dead_code)]
fn b64_url_decode(s: &str) -> Option<Vec<u8>> {
    let mut bits: Vec<u8> = Vec::new();
    for &b in s.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits.push(v);
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= bits.len() {
        out.push((bits[i] << 2) | (bits[i + 1] >> 4));
        out.push(((bits[i + 1] & 0x0f) << 4) | (bits[i + 2] >> 2));
        out.push(((bits[i + 2] & 0x03) << 6) | bits[i + 3]);
        i += 4;
    }
    match bits.len() - i {
        2 => out.push((bits[i] << 2) | (bits[i + 1] >> 4)),
        3 => {
            out.push((bits[i] << 2) | (bits[i + 1] >> 4));
            out.push(((bits[i + 1] & 0x0f) << 4) | (bits[i + 2] >> 2));
        }
        _ => {}
    }
    Some(out)
}

#[allow(dead_code)]
fn b64_url_encode(data: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i + 3 <= data.len() {
        out.push(TBL[(data[i] >> 2) as usize] as char);
        out.push(TBL[(((data[i] & 0x03) << 4) | (data[i + 1] >> 4)) as usize] as char);
        out.push(TBL[(((data[i + 1] & 0x0f) << 2) | (data[i + 2] >> 6)) as usize] as char);
        out.push(TBL[(data[i + 2] & 0x3f) as usize] as char);
        i += 3;
    }
    match data.len() - i {
        1 => {
            out.push(TBL[(data[i] >> 2) as usize] as char);
            out.push(TBL[((data[i] & 0x03) << 4) as usize] as char);
        }
        2 => {
            out.push(TBL[(data[i] >> 2) as usize] as char);
            out.push(TBL[(((data[i] & 0x03) << 4) | (data[i + 1] >> 4)) as usize] as char);
            out.push(TBL[((data[i + 1] & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }
    out
}

#[allow(dead_code)]
fn target_with_meta(
    settings: &XhttpSettings,
    base_path: &str,
    sid: Option<&str>,
    seq: Option<&str>,
) -> String {
    let (path, base_query) = base_path.split_once('?').unwrap_or((base_path, ""));
    let mut t = path.trim_end_matches('/').to_owned();
    if settings.session_placement == Placement::Path {
        if let Some(s) = sid {
            t.push('/');
            t.push_str(s);
        }
    }
    if settings.seq_placement == Placement::Path {
        if let Some(q) = seq {
            t.push('/');
            t.push_str(q);
        }
    }
    let mut query: Vec<String> = Vec::new();
    if !base_query.is_empty() {
        query.push(base_query.to_owned());
    }
    if settings.session_placement == Placement::Query {
        if let Some(s) = sid {
            query.push(format!("{}={}", settings.session_key, s));
        }
    }
    if settings.seq_placement == Placement::Query {
        if let Some(q) = seq {
            query.push(format!("{}={}", settings.seq_key, q));
        }
    }
    if !query.is_empty() {
        t.push('?');
        t.push_str(&query.join("&"));
    }
    t
}

#[allow(dead_code)]
fn generate_session_id() -> String {
    let mut raw = [0u8; 8];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    let mut s = String::with_capacity(16);
    for b in raw {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[allow(dead_code)]
fn headers_with_padding(head: &mut String, settings: &XhttpSettings, target: &str) {
    let padded = pad_value(settings.x_padding_method, pad_target_len(settings));
    if !settings.x_padding_obfs {
        let sep = if target.contains('?') { '&' } else { '?' };
        let _ = write!(head, "Referer: {target}{sep}x_padding={padded}\r\n");
        return;
    }
    match settings.x_padding_placement {
        Placement::Header => {
            let _ = write!(head, "{}: {}\r\n", settings.x_padding_header, padded);
        }
        Placement::Cookie => {
            let _ = write!(head, "Cookie: {}={}\r\n", settings.x_padding_key, padded);
        }
        Placement::Query | Placement::QueryInHeader => {
            let sep = if target.contains('?') { '&' } else { '?' };
            let _ = write!(
                head,
                "Referer: {target}{sep}{}={padded}\r\n",
                settings.x_padding_key
            );
        }
        _ => {}
    }
}

pub(crate) struct PacketWriter {
    shared: Arc<PacketWriterShared>,
}

struct PacketWriterShared {
    #[allow(clippy::type_complexity)]
    open: Mutex<Option<Box<dyn FnMut() -> Option<TcpStream> + Send>>>,
    host: String,
    path: String,
    sid: String,
    next: AtomicU64,
    done: AtomicBool,
    settings: XhttpSettings,
}

#[allow(dead_code)]
impl Clone for PacketWriter {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

#[allow(dead_code)]
impl PacketWriter {
    fn new(
        open: Box<dyn FnMut() -> Option<TcpStream> + Send>,
        host: String,
        path: String,
        sid: String,
        settings: XhttpSettings,
    ) -> Self {
        Self {
            shared: Arc::new(PacketWriterShared {
                open: Mutex::new(Some(open)),
                host,
                path,
                sid,
                next: AtomicU64::new(0),
                done: AtomicBool::new(false),
                settings,
            }),
        }
    }

    fn post(&self, data: &[u8]) -> bool {
        for chunk in data.chunks(self.shared.settings.sc_max_each_post) {
            if chunk.is_empty() {
                continue;
            }
            let seq = self.shared.next.fetch_add(1, Ordering::SeqCst);
            if seq > 0 && self.shared.settings.sc_min_posts_interval_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(
                    self.shared.settings.sc_min_posts_interval_ms,
                ));
            }
            let pair = {
                let mut open = self.shared.open.lock().expect("open lock");
                match open.as_mut() {
                    Some(o) => o(),
                    None => return false,
                }
            };
            let Some(stream) = pair else {
                return false;
            };
            let Ok(mut head_reader) = stream.try_clone() else {
                return false;
            };
            let mut head_writer = stream;
            let seq_str = seq.to_string();
            let target = target_with_meta(
                &self.shared.settings,
                &self.shared.path,
                Some(&self.shared.sid),
                Some(&seq_str),
            );
            let mut head = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\n",
                self.shared.settings.uplink_method, target, self.shared.host
            );
            match self.shared.settings.uplink_data_placement {
                Placement::Header => {
                    let key = if self.shared.settings.uplink_data_key.is_empty() {
                        "X-Data".to_owned()
                    } else {
                        self.shared.settings.uplink_data_key.clone()
                    };
                    let _ = write!(head, "{key}-0: {}\r\n", b64_url_encode(chunk));
                    head.push_str("Content-Length: 0\r\n");
                }
                Placement::Cookie => {
                    let key = if self.shared.settings.uplink_data_key.is_empty() {
                        "x_data".to_owned()
                    } else {
                        self.shared.settings.uplink_data_key.clone()
                    };
                    let _ = write!(head, "Cookie: {key}_0={}\r\n", b64_url_encode(chunk));
                    head.push_str("Content-Length: 0\r\n");
                }
                _ => {
                    let _ = write!(head, "Content-Length: {}\r\n", chunk.len());
                }
            }
            headers_with_padding(&mut head, &self.shared.settings, &target);
            head.push_str("Connection: keep-alive\r\n\r\n");
            if head_writer
                .write_all(head.as_bytes())
                .and_then(|()| head_writer.write_all(chunk))
                .is_err()
            {
                return false;
            }
            let mut head = Vec::with_capacity(256);
            let mut chunk = [0u8; 256];
            loop {
                match head_reader.read(&mut chunk) {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => {
                        head.extend_from_slice(&chunk[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                        if head.len() > 64 * 1024 {
                            return false;
                        }
                    }
                }
            }
            if !ok_status(&head) {
                return false;
            }
        }
        true
    }
}

#[allow(dead_code)]
impl Write for PacketWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.post(data) {
            Ok(data.len())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[allow(dead_code)]
impl crate::proxy::CarrierSink for PacketWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.post(bytes)
    }
    #[inline]
    fn close(&self) {
        self.shared.done.store(true, Ordering::SeqCst);
    }
}

#[allow(dead_code)]
pub(crate) enum ModeWriter {
    Stream(XhttpWriter),
    Packets(PacketWriter),
}

#[allow(dead_code)]
impl Clone for ModeWriter {
    fn clone(&self) -> Self {
        match self {
            Self::Stream(w) => Self::Stream(w.clone()),
            Self::Packets(w) => Self::Packets(w.clone()),
        }
    }
}

#[allow(dead_code)]
impl ModeWriter {
    pub(crate) fn finish(&self) {
        match self {
            Self::Stream(w) => w.finish(),
            Self::Packets(w) => crate::proxy::CarrierSink::close(w),
        }
    }
}

#[allow(dead_code)]
impl Write for ModeWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Stream(w) => w.write(data),
            Self::Packets(w) => w.write(data),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Stream(w) => w.flush(),
            Self::Packets(w) => w.flush(),
        }
    }
}

#[allow(dead_code)]
impl crate::proxy::CarrierSink for ModeWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Stream(w) => w.send(bytes),
            Self::Packets(w) => w.send(bytes),
        }
    }
    #[inline]
    fn close(&self) {
        self.finish();
    }
}

// --- Server ------------------------------------------------------------------

// The stream-one handshake the tree has always served: POST with chunked
// framing on one connection. Mode handshakes live in
// `accept_with_settings`; this stays so every existing rung keeps dialling.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    check_request(&head, path)?;
    read.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n").ok()?;
    split(read, prefix)
}

fn check_request(head: &[u8], path: &str) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    let mut parts = text.split("\r\n").next()?.split_ascii_whitespace();
    if parts.next()? != "POST" {
        return None;
    }
    let target = parts.next()?;
    if !path_covers(path, bare_path(target)) {
        return None;
    }
    if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
}

// The same accept over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn accept_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    path: &str,
) -> Option<(Reader<R>, XhttpWriter)> {
    let (head, prefix) = crate::proxy::read_exact_head(&mut read, HEAD_LIMIT)?;
    check_request(&head, path)?;
    write.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n").ok()?;
    Some(split_halves(read, write, prefix))
}

#[allow(dead_code)]
#[allow(clippy::too_many_lines)]
pub(crate) fn accept_with_settings(
    mut stream: TcpStream,
    settings: &XhttpSettings,
) -> Option<(Box<dyn Read + Send>, XhttpWriter)> {
    let (head, prefix) = read_head(&mut stream)?;
    let text = std::str::from_utf8(&head).ok()?;
    let first = text.lines().next()?;
    let mut parts = first.split_ascii_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;

    if !path_covers(settings.path.as_str(), bare_path(target)) {
        emit_404(&mut stream);
        return None;
    }

    let padded = pad_value(settings.x_padding_method, pad_target_len(settings));

    if method == "OPTIONS" {
        let mut head = String::from("HTTP/1.1 200 OK\r\n");
        if !settings.x_padding_obfs {
            let _ = write!(head, "X-Padding: {padded}\r\n");
        }
        head.push_str("Access-Control-Allow-Methods: *\r\nAccess-Control-Allow-Headers: *\r\nAccess-Control-Allow-Origin: *\r\n");
        head.push_str("Content-Length: 0\r\nConnection: keep-alive\r\n\r\n");
        let _ = stream.write_all(head.as_bytes());
        return None;
    }

    let pad_ok = match extract_padding(&head, target, settings) {
        Some(v) => padding_valid(
            v,
            settings.x_padding_bytes.0,
            settings.x_padding_bytes.1,
            settings.x_padding_method,
        ),
        None => false,
    };
    if !pad_ok {
        emit_400(&mut stream);
        return None;
    }

    let (sid, seq) = extract_meta(&head, target, settings);

    match (sid, seq) {
        (None, None) => {
            if settings.mode == XhttpMode::PacketUp {
                emit_400(&mut stream);
                return None;
            }
            if method == "GET" {
                sse_ok(&mut stream, settings, &padded);
                let write = stream.try_clone().ok()?;
                let writer = XhttpWriter::new(write);
                let session = get_or_create_session("__none__");
                session.state.lock().expect("session lock").ended = true;
                return Some((Box::new(SessionReader::new(session, String::new())), writer));
            }
            if method == "POST" {
                if !crate::proxy::header_value(&head, "transfer-encoding").is_some_and(has_chunked)
                {
                    emit_400(&mut stream);
                    return None;
                }
                sse_ok(&mut stream, settings, &padded);
                let reader = Reader {
                    read: stream.try_clone().ok()?,
                    prefix,
                    at: 0,
                    left: 0,
                    ended: false,
                    reads: 0,
                };
                let writer = XhttpWriter::new(stream);
                return Some((Box::new(reader), writer));
            }
            emit_405(&mut stream);
            None
        }
        (Some(sid), None) => {
            if method == "GET" {
                let session = get_or_create_session(sid);
                sse_ok(&mut stream, settings, &padded);
                let write = stream.try_clone().ok()?;
                let writer = XhttpWriter::new(write);
                return Some((
                    Box::new(SessionReader::new(session, sid.to_owned())),
                    writer,
                ));
            }
            if settings.mode == XhttpMode::PacketUp {
                emit_400(&mut stream);
                return None;
            }
            if !crate::proxy::header_value(&head, "transfer-encoding").is_some_and(has_chunked) {
                emit_400(&mut stream);
                return None;
            }
            let session = get_or_create_session(sid);
            session.set_upload(Box::new(Reader {
                read: stream.try_clone().ok()?,
                prefix,
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
            }));
            plain_ok(&mut stream, settings, &padded);
            session.wait_ended();
            None
        }
        (Some(sid), Some(seq)) => {
            if settings.mode == XhttpMode::StreamUp {
                emit_400(&mut stream);
                return None;
            }
            let Ok(seq_num) = seq.parse::<u64>() else {
                emit_400(&mut stream);
                return None;
            };
            let session = get_or_create_session(sid);
            let payload = match settings.uplink_data_placement {
                Placement::Header => {
                    let key = if settings.uplink_data_key.is_empty() {
                        "X-Data".to_owned()
                    } else {
                        settings.uplink_data_key.clone()
                    };
                    let mut joined = String::new();
                    for i in 0.. {
                        match crate::proxy::header_value(
                            &head,
                            &format!("{key}-{i}").to_ascii_lowercase(),
                        ) {
                            Some(v) => joined.push_str(v),
                            None => break,
                        }
                    }
                    b64_url_decode(&joined)
                }
                Placement::Cookie => {
                    let key = if settings.uplink_data_key.is_empty() {
                        "x_data".to_owned()
                    } else {
                        settings.uplink_data_key.clone()
                    };
                    let mut joined = String::new();
                    for i in 0.. {
                        match header_cookie(&head, &format!("{key}_{i}")) {
                            Some(v) => joined.push_str(v),
                            None => break,
                        }
                    }
                    b64_url_decode(&joined)
                }
                _ => {
                    if let Some(n) = content_length(&head) {
                        if n > settings.sc_max_each_post {
                            emit_413(&mut stream);
                            return None;
                        }
                        let mut buf = vec![0u8; n];
                        let pre = prefix.len().min(n);
                        buf[..pre].copy_from_slice(&prefix[..pre]);
                        let mut at = pre;
                        while at < n {
                            match stream.read(&mut buf[at..]) {
                                Ok(0) => break,
                                Ok(r) => at += r,
                                Err(_) => return None,
                            }
                        }
                        if at < n {
                            None
                        } else {
                            Some(buf)
                        }
                    } else if crate::proxy::header_value(&head, "transfer-encoding")
                        .is_some_and(has_chunked)
                    {
                        let mut reader = Reader {
                            read: stream.try_clone().ok()?,
                            prefix,
                            at: 0,
                            left: 0,
                            ended: false,
                            reads: 0,
                        };
                        let mut payload = Vec::new();
                        let mut tmp = [0u8; 8192];
                        loop {
                            match reader.read(&mut tmp) {
                                Ok(0) => break,
                                Ok(n) => {
                                    payload.extend_from_slice(&tmp[..n]);
                                    if payload.len() > settings.sc_max_each_post {
                                        emit_413(&mut stream);
                                        return None;
                                    }
                                }
                                Err(_) => return None,
                            }
                        }
                        Some(payload)
                    } else {
                        Some(Vec::new())
                    }
                }
            };
            let Some(payload) = payload else {
                emit_400(&mut stream);
                return None;
            };
            if payload.len() > settings.sc_max_each_post {
                emit_413(&mut stream);
                return None;
            }
            session.push_packet(seq_num, payload);
            plain_ok(&mut stream, settings, &padded);
            None
        }
        (None, Some(_)) => {
            emit_405(&mut stream);
            None
        }
    }
}

// The stream-one dial the tree has always made: one POST, chunked framing
// both ways. Mode dials live in `connect_with_settings`.
pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
) -> Option<(XhttpReader, XhttpWriter)> {
    let mut read = stream;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
    );
    read.write_all(request.as_bytes()).ok()?;
    let (head, prefix) = read_head(&mut read)?;
    check_response(&head)?;
    split(read, prefix)
}

#[allow(dead_code)]
pub(crate) fn connect_with_settings(
    stream: TcpStream,
    host: &str,
    settings: &XhttpSettings,
    mut open: impl FnMut() -> Option<TcpStream> + Send + 'static,
) -> Option<(Reader<TcpStream>, ModeWriter)> {
    let sid = generate_session_id();
    match settings.mode {
        XhttpMode::StreamOne => {
            let target = &settings.path;
            let mut request = format!(
                "POST {target} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n",
            );
            headers_with_padding(&mut request, settings, target);
            request.push_str("\r\n");
            let mut read = stream;
            read.write_all(request.as_bytes()).ok()?;
            let (head, prefix) = read_head(&mut read)?;
            check_response(&head)?;
            let write = read.try_clone().ok()?;
            let reader = Reader {
                read,
                prefix,
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
            };
            Some((reader, ModeWriter::Stream(XhttpWriter::new(write))))
        }
        XhttpMode::StreamUp => {
            let target = target_with_meta(settings, &settings.path, Some(&sid), None);
            let mut head =
                format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n");
            headers_with_padding(&mut head, settings, &target);
            head.push_str("\r\n");
            let mut down = stream;
            down.write_all(head.as_bytes()).ok()?;
            let (head_resp, prefix) = read_head(&mut down)?;
            check_response(&head_resp)?;
            let reader = Reader {
                read: down,
                prefix,
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
            };
            let up = open()?;
            let up_target = target_with_meta(settings, &settings.path, Some(&sid), None);
            let mut up_head = format!(
                "{} {up_target} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/grpc\r\nConnection: keep-alive\r\n",
                settings.uplink_method
            );
            headers_with_padding(&mut up_head, settings, &up_target);
            up_head.push_str("\r\n");
            let mut up = up;
            up.write_all(up_head.as_bytes()).ok()?;
            let (resp, _) = read_head(&mut up)?;
            if !ok_status(&resp) {
                return None;
            }
            let write = up.try_clone().ok()?;
            Some((reader, ModeWriter::Stream(XhttpWriter::new(write))))
        }
        XhttpMode::PacketUp => {
            let target = target_with_meta(settings, &settings.path, Some(&sid), None);
            let mut head =
                format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n");
            headers_with_padding(&mut head, settings, &target);
            head.push_str("\r\n");
            let mut down = stream;
            down.write_all(head.as_bytes()).ok()?;
            let (head_resp, prefix) = read_head(&mut down)?;
            check_response(&head_resp)?;
            let reader = Reader {
                read: down,
                prefix,
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
            };
            // Packet writer over open() per packet: TcpStream transport.
            let writer = PacketWriter::new(
                Box::new(open),
                host.to_owned(),
                settings.path.clone(),
                sid.clone(),
                settings.clone(),
            );
            Some((reader, ModeWriter::Packets(writer)))
        }
    }
}

// The same connect over halves that cannot peek: pipelined bytes arrive as a prefix.
pub(crate) fn connect_split<R: Read, W: crate::proxy::FrameWrite + 'static>(
    mut read: R,
    mut write: W,
    host: &str,
    path: &str,
) -> Option<(Reader<R>, XhttpWriter)> {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
    );
    write.write_all(request.as_bytes()).ok()?;
    let (head, prefix) = crate::proxy::read_exact_head(&mut read, HEAD_LIMIT)?;
    check_response(&head)?;
    Some(split_halves(read, write, prefix))
}

impl crate::proxy::CarrierSink for XhttpWriter {
    #[inline]
    fn send(&self, bytes: &[u8]) -> bool {
        self.send(bytes)
    }
    #[inline]
    fn close(&self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// The same drain over a real socket. This asserts the *bytes* and nothing
    /// else: a real socket may segment, so its read count moves with the
    /// scheduler and cannot gate a number. The count claim belongs to
    /// `a_chunk_costs_two_reads_not_three`, which drives an in-memory stream
    /// that always answers the whole buffer. Measured here off a loopback
    /// socket, idle: 33 reads for 16 chunks against 49 for the old shape.
    #[test]
    fn a_real_socket_drains_the_same_bytes() {
        let count = 16usize;
        let mut wire = Vec::new();
        for _ in 0..count {
            wire.extend_from_slice(format!("{CHUNK:X}\r\n").as_bytes());
            wire.extend(std::iter::repeat_n(0x5Au8, CHUNK));
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"0\r\n\r\n");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let h = thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accepts");
            let mut head = [0u8; 4096];
            let n = sock.read(&mut head).expect("reads the request");
            assert!(n > 0);
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .expect("replies");
            sock.write_all(&wire).expect("sends");
            sock.shutdown(std::net::Shutdown::Write).ok();
        });
        let sock = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, _w) = connect(sock, "h", "/share").expect("dials");
        let mut buf = vec![0u8; CHUNK];
        let mut got = 0usize;
        loop {
            let n = reader.read(&mut buf).expect("reads");
            if n == 0 {
                break;
            }
            got += n;
        }
        h.join().expect("joins");
        assert_eq!(got, CHUNK * count, "the payload must be byte-identical");
        assert!(reader.reads() <= count * 3 + 1, "a bound, not the claim");
    }

    #[test]
    fn size_lines_match_format_without_allocating() {
        for n in [1usize, 9, 10, 15, 16, 255, 256, 4096, 16384] {
            let mut line = [0u8; 6];
            let len = size_line(n, &mut line);
            assert_eq!(&line[..len], format!("{n:X}\r\n").as_bytes());
        }
    }

    #[test]
    fn paths_cover_prefixes_without_crossing_names() {
        assert!(path_covers("/service", "/service"));
        assert!(path_covers("/service", "/service/session"));
        assert!(path_covers("/", "/anything"));
        assert!(!path_covers("/service", "/service-evil"));
    }

    #[test]
    fn chunked_matches_case_insensitive_contains() {
        for (value, want) in [
            ("chunked", true),
            ("Chunked", true),
            ("CHUNKED", true),
            ("gzip, chunked", true),
            ("chunked, gzip", true),
            ("mychunked", true),
            ("chunkedx", true),
            ("chu", false),
            ("", false),
            ("gzip", false),
            ("identity", false),
        ] {
            assert_eq!(has_chunked(value), want, "{value}");
        }
    }

    #[test]
    fn exchange_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/share").expect("serves");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            assert!(writer.send(b"pong"));
            writer.finish();
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) = connect(stream, "oracle.example", "/share").expect("dials");
        assert!(writer.send(b"ping"));
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// Reads are driven with a fixed CHUNK buffer, the way `relay_ordered`
    /// drives them, so the count is the reader's and not `read_to_end`'s buffer
    /// growth. `reads` is the counter that says so, exactly as `WsReader::pull`
    /// has one.
    #[test]
    fn a_chunk_costs_two_reads_not_three() {
        fn framed(chunks: &[usize]) -> Vec<u8> {
            let mut wire = Vec::new();
            for &n in chunks {
                wire.extend_from_slice(format!("{n:X}\r\n").as_bytes());
                wire.extend(std::iter::repeat_n(0x5Au8, n));
                wire.extend_from_slice(b"\r\n");
            }
            wire.extend_from_slice(b"0\r\n\r\n");
            wire
        }

        for count in [1usize, 2, 4, 8, 16] {
            let chunks: Vec<usize> = std::iter::repeat_n(CHUNK, count).collect();
            let payload: Vec<u8> = vec![0x5Au8; CHUNK * count];
            let mut reader = Reader {
                read: std::io::Cursor::new(framed(&chunks)),
                prefix: Vec::new(),
                at: 0,
                left: 0,
                ended: false,
                reads: 0,
            };
            let mut got = Vec::new();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = reader.read(&mut buf).expect("reads");
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            assert_eq!(got, payload, "{count} chunks: the bytes must be unchanged");
            // Two reads per chunk amortised -- one framing window, one body --
            // plus the terminating size line. The old shape read the size line
            // and the two-byte CRLF separately, so it cost three per chunk.
            assert_eq!(
                reader.reads(),
                count * 2 + 1,
                "{count} chunks: framing reads must amortise to one per chunk"
            );
        }
    }

    /// The counter must see the *short* reads too: a stream that hands over one
    /// byte at a time is the worst case, and it is what makes a bounded window
    /// better than an unbounded one.
    #[test]
    fn a_trickling_stream_still_drains_whole() {
        struct Trickle {
            inner: std::io::Cursor<Vec<u8>>,
        }
        impl Read for Trickle {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let take = buf.len().min(1);
                self.inner.read(&mut buf[..take])
            }
        }

        let mut wire = Vec::new();
        wire.extend_from_slice(b"40\r\n");
        wire.extend(std::iter::repeat_n(0x11u8, 64));
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut reader = Reader {
            read: Trickle {
                inner: std::io::Cursor::new(wire),
            },
            prefix: Vec::new(),
            at: 0,
            left: 0,
            ended: false,
            reads: 0,
        };
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("drains");
        assert_eq!(got, vec![0x11u8; 64]);
        assert!(
            reader.reads() > 64,
            "one byte per read cannot be fewer reads than bytes, got {}",
            reader.reads()
        );
    }

    #[test]
    fn chunks_drain_in_order_before_the_close_is_answered() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, writer) = accept(stream, "/share").expect("serves");
            let mut first = [0u8; 26];
            reader.read_exact(&mut first).expect("reads header");
            assert!(writer.send(&[0, 0]));
            let mut ping = [0u8; 4];
            reader.read_exact(&mut ping).expect("reads ping");
            assert_eq!(&ping, b"ping");
            assert!(writer.send(b"ping"));
            let mut drained = Vec::new();
            reader.read_to_end(&mut drained).expect("drains the close");
            assert_eq!(drained, [] as [u8; 0]);
            writer.finish();
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .expect("timeout");
        let (mut reader, writer) = connect(stream, "h", "/share").expect("dials");
        assert!(writer.send(&[1u8; 26]));
        let mut reply = [0u8; 2];
        reader.read_exact(&mut reply).expect("replies");
        assert_eq!(reply, [0, 0]);
        assert!(writer.send(b"ping"));
        writer.finish();
        let mut back = Vec::new();
        reader.read_to_end(&mut back).expect("echoes");
        assert_eq!(back, b"ping");
        server.join().expect("joins");
    }

    #[test]
    fn exchange_rejects_a_wrong_path() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/share").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"POST /other HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
