use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

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
#[cfg(test)]
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

fn check_response(head: &[u8]) -> Option<()> {
    let text = std::str::from_utf8(head).ok()?;
    if text.split("\r\n").next()? != "HTTP/1.1 200 OK" {
        return None;
    }
    if !crate::proxy::header_value(head, "transfer-encoding").is_some_and(has_chunked) {
        return None;
    }
    Some(())
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
