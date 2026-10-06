use std::io::{Read, Write};
use std::net::TcpStream;

const HEAD_LIMIT: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) struct UpReader {
    read: TcpStream,
    prefix: Vec<u8>,
}

impl Read for UpReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.len());
            buf[..n].copy_from_slice(&self.prefix[..n]);
            self.prefix.drain(..n);
            return Ok(n);
        }
        self.read.read(buf)
    }
}

fn read_head(stream: &mut TcpStream) -> Option<(Vec<u8>, Vec<u8>)> {
    crate::proxy::read_http_head(stream, HEAD_LIMIT).map(|head| (head, Vec::new()))
}

pub(crate) fn accept(stream: TcpStream, path: &str) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    let (head, prefix) = read_head(&mut read)?;
    if crate::proxy::request_path(&head)? != path {
        return None;
    }
    let upgrade = crate::proxy::header_value(&head, "upgrade").unwrap_or_default();
    let connection = crate::proxy::header_value(&head, "connection").unwrap_or_default();
    if !upgrade.eq_ignore_ascii_case("websocket") || !connection.eq_ignore_ascii_case("upgrade") {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    let mut write = write;
    write
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .ok()?;
    Some((UpReader { read, prefix }, write))
}

fn upgrade_request(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    )
}

pub(crate) fn connect(stream: TcpStream, host: &str, path: &str) -> Option<(UpReader, TcpStream)> {
    let mut read = stream;
    read.write_all(upgrade_request(host, path).as_bytes())
        .ok()?;
    let (head, prefix) = read_head(&mut read)?;
    let text = std::str::from_utf8(&head).ok()?;
    if text.split("\r\n").next()? != "HTTP/1.1 101 Switching Protocols" {
        return None;
    }
    if !crate::proxy::header_value(&head, "connection")?.eq_ignore_ascii_case("upgrade") {
        return None;
    }
    if !crate::proxy::header_value(&head, "upgrade")?.eq_ignore_ascii_case("websocket") {
        return None;
    }
    let Ok(write) = read.try_clone() else {
        return None;
    };
    Some((UpReader { read, prefix }, write))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn upgrade_carries_an_echo_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (mut reader, write) = accept(stream, "/tunnel").expect("upgrades");
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
            let mut write = write;
            write.write_all(b"pong").expect("writes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut write) =
            connect(stream, "oracle.example", "/tunnel").expect("upgrades");
        write.write_all(b"ping").expect("writes");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("reads");
        assert_eq!(&buf, b"pong");
        server.join().expect("joins");
    }

    #[test]
    fn an_early_data_budget_leaves_the_request_unchanged() {
        for budget in [0u32, 1, 2048, 4_294_967_295] {
            let configured =
                ferrox_core::transport::EarlyData::split(&format!("/interop-upgrade?ed={budget}"));
            assert_eq!(configured.budget, budget);
            assert_eq!(
                upgrade_request("oracle.example", &configured.path),
                "GET /interop-upgrade HTTP/1.1\r\nHost: oracle.example\r\n\
                 Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                "{budget}"
            );
        }
    }

    #[test]
    fn a_configured_budget_serves_the_bare_path() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let configured = ferrox_core::transport::EarlyData::split("/interop-upgrade?ed=2048");
            let (_reader, write) = accept(stream, &configured.path).expect("upgrades");
            drop(write);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let configured = ferrox_core::transport::EarlyData::split("/interop-upgrade?ed=2048");
        let (_reader, _write) =
            connect(stream, "oracle.example", &configured.path).expect("upgrades");
        server.join().expect("joins");
    }

    #[test]
    fn upgrade_rejects_a_wrong_path_and_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            assert!(accept(stream, "/tunnel").is_none());
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /other HTTP/1.1\r\nHost: h\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
            .expect("writes");
        server.join().expect("joins");
        drop(stream);
    }
}
