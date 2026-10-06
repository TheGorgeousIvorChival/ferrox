//! `TCP` `HTTP` camouflage header over blocking `TCP`, both roles.
//!
//! One `GET` before the first protocol bytes and one `200` before the first
//! reply bytes, then raw bytes both ways: no framing follows the blank line.

use std::io::{Read, Write};
use std::net::TcpStream;

/// Largest handshake block read before the header is refused, not buffered.
const HEAD_LIMIT: usize = 8192;

/// Byte stream past the header; `Read` serves pipelined bytes first.
#[derive(Debug)]
pub(crate) struct HeadReader {
    read: TcpStream,
    prefix: Vec<u8>,
    /// Consumed prefix of `prefix`; takes are counted, never shifted.
    at: usize,
}

impl Read for HeadReader {
    /// Fill `buf`; empty means the peer closed a clean `TCP` `EOF`.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.at < self.prefix.len() {
            let n = (self.prefix.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[self.at..self.at + n]);
            self.at += n;
            if self.at >= self.prefix.len() {
                self.prefix.clear();
                self.at = 0;
            }
            return Ok(n);
        }
        self.read.read(buf)
    }
}

/// Read until `\r\n\r\n`, keeping pipelined bytes; `None` past the limit.
///
/// Now [`crate::proxy::read_http_head`], which the other carriers use and which is
/// the better of the two by construction: it **peeks** for the terminator and then
/// consumes exactly `at + 4`, so the bytes after the head stay in the kernel. This
/// module's own version read into a growing `Vec` and then copied everything past
/// the terminator into a **second** allocation with `head[end..].to_vec()`, which
/// is one extra allocation and one extra copy of the first payload bytes per
/// connection for a prefix that the kernel already had.
///
/// The consequence the two do not share is that this module's reader is the only
/// one that needed a `prefix` at all; [`HeadReader::prefix`] stays, because a
/// peer's payload can still arrive in the same segment as the blank line and the
/// shared reader is allowed to leave it there, but it is now empty in the case
/// where it used to be a fresh `Vec`.
fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT).map(|head| (head, Vec::new()))
}

/// The request's target path, without its query, or `None` on a malformed line.
///
/// A borrow, where this used to return a `String`. The only caller compared it
/// against the link's path and dropped it, so every connection allocated a
/// `String` to hold bytes that were already in the head buffer, and a comparison
/// against `&str` does the same work.
fn request_target(head: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(head).ok()?;
    let mut parts = text.split("\r\n").next()?.split_ascii_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(target.split('?').next().unwrap_or(target))
}

/// Accept the camouflage as a server, checking the configured path exactly.
pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(HeadReader, TcpStream)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    if request_target(&head)? != path {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
        .ok()?;
    Some((
        HeadReader {
            read,
            prefix,
            at: 0,
        },
        write,
    ))
}

/// Perform the camouflage as a client, checking the `200` before use.
pub(crate) fn connect(
    stream: TcpStream,
    host: &str,
    path: &str,
) -> Option<(HeadReader, TcpStream)> {
    let mut read = stream;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n");
    read.write_all(request.as_bytes()).ok()?;
    let (head, prefix) = read_head(&mut read)?;
    let text = std::str::from_utf8(&head).ok()?;
    let mut parts = text.split("\r\n").next()?.split_ascii_whitespace();
    if parts.next()? != "HTTP/1.1" || parts.next()? != "200" {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some((
        HeadReader {
            read,
            prefix,
            at: 0,
        },
        write,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn header_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, mut write) = accept(stream, "/camouflage").expect("headers");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            write.write_all(b"pong").expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/camouflage").expect("headers");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    /// The path compare is a borrow and a `&str` equality, so the two shapes of
    /// request this module has to answer both come back without allocating: the
    /// plain target, and the same target with a query appended by a peer that
    /// treats this as a cache-buster.
    #[test]
    fn the_request_target_is_a_borrow_and_ignores_the_query() {
        assert_eq!(
            request_target(b"GET /camouflage HTTP/1.1\r\nHost: h\r\n\r\n"),
            Some("/camouflage")
        );
        assert_eq!(
            request_target(b"GET /camouflage?t=17 HTTP/1.1\r\n\r\n"),
            Some("/camouflage")
        );
        assert_eq!(request_target(b"POST /camouflage HTTP/1.1\r\n\r\n"), None);
        assert_eq!(request_target(b"GET\r\n\r\n"), None);
        assert_eq!(request_target(&[0xff, 0xfe, 0xfd]), None);
        assert_eq!(
            request_target(b"GET /camouflage HTTP/1.1\r\n\r\n"),
            Some("/camouflage"),
            "and the bytes it points at are the head's, not a copy"
        );
    }

    #[test]
    fn header_rejects_a_wrong_path() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/camouflage").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
