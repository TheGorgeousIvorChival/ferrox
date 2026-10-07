//! The Foxy lane in the app: a CONNECT tunnel to an account's CDN edge, carried
//! over whichever of HTTP/1.1, HTTP/2 or HTTP/3 the edge answers.
//!
//! One shape for all three carriers — open a stream to the edge, send three
//! header fields, read one status, relay — and the parts that decide rather than
//! move bytes live in `ferrox_core::foxy`. The relay itself is shared: a lane
//! hands the caller a `Read + Write` and the caller does not know which carrier
//! produced it.

use ferrox_core::foxy::{self, frames, hpack, Failure, Pass};
use ferrox_core::tls::TlsProvider;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const DEFAULT_WINDOW: u32 = 65_535;
const OUR_WINDOW: u32 = 1_048_576;
const MAX_FRAME: usize = 65_536;
const MAX_HEAD: usize = 8_192;
const SEND_WAIT: Duration = Duration::from_secs(10);
/// A QUIC connection's flow-control ceiling as the relay sees it: the lane
/// advertises far more than a tunnel needs, so the window is never the limit.
const MAX_WINDOW: i64 = i64::MAX / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carrier {
    H1,
    H2,
    H3,
}

impl Carrier {
    #[must_use]
    pub(crate) const fn alpn(self) -> &'static [u8] {
        match self {
            Self::H1 => b"http/1.1",
            Self::H2 => b"h2",
            Self::H3 => b"h3",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FoxyDial {
    /// The edge name: the TLS server name, the ALPN subject, and the country the
    /// hostname itself pins.
    pub(crate) host: String,
    pub(crate) port: u16,
    /// The address to connect to, when it is not the name's own resolution.
    pub(crate) address: Option<SocketAddr>,
    pub(crate) carrier: Carrier,
    pub(crate) roots: Vec<Vec<u8>>,
    pub(crate) pins: foxy::pin::Pins,
    pub(crate) pass: Pass,
}

fn tls_config(dial: &FoxyDial) -> ferrox_core::tls::TlsConfig {
    ferrox_core::tls::TlsConfig {
        server_name: dial.host.clone(),
        alpn: vec![dial.carrier.alpn().to_vec()],
        roots: dial.roots.clone(),
        pins: dial.pins.clone(),
    }
}

fn peer(dial: &FoxyDial) -> Result<SocketAddr, Failure> {
    if let Some(address) = dial.address {
        return Ok(address);
    }
    format!("{}:{}", dial.host, dial.port)
        .to_socket_addrs()
        .map_err(|_| Failure::Io)?
        .next()
        .ok_or(Failure::Io)
}

fn tcp(dial: &FoxyDial) -> Result<TcpStream, Failure> {
    let stream =
        TcpStream::connect_timeout(&peer(dial)?, CONNECT_TIMEOUT).map_err(|_| Failure::Io)?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// A handshake that answered a different ALPN is a refusal, not a downgrade: the
/// lane asked for exactly one protocol and the edge chose another.
fn negotiated<S: TlsProvider>(tls: &S, dial: &FoxyDial) -> Result<(), Failure> {
    match tls.alpn() {
        Some(got) if got == dial.carrier.alpn() => Ok(()),
        _ => Err(Failure::Frame),
    }
}

fn opened(status: u16) -> Result<(), Failure> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(Failure::Rejected(status))
    }
}

fn read_exact<S: Read>(io: &mut S, buf: &mut [u8]) -> Result<(), ()> {
    let mut at = 0usize;
    while at < buf.len() {
        match io.read(&mut buf[at..]) {
            Ok(0) | Err(_) => return Err(()),
            Ok(read) => at += read,
        }
    }
    Ok(())
}

/// HTTP/1.1 CONNECT: the request, the status line, then the target's own bytes.
pub(crate) fn open_h1(dial: &FoxyDial, target: &str) -> Result<Tls1, Failure> {
    let stream = tcp(dial)?;
    let mut tls = ferrox_core::tls::RustlsProvider::connect(&tls_config(dial), stream)
        .map_err(|_| Failure::Io)?;
    tls.handshake().map_err(|_| Failure::Io)?;
    negotiated(&tls, dial)?;
    tls.write_all(&foxy::connect_request(target, &dial.pass.token))
        .map_err(|_| Failure::Io)?;
    opened(foxy::connect_status(&head(&mut tls)?)?)?;
    Ok(Tls1(tls))
}

fn head<S: Read>(io: &mut S) -> Result<Vec<u8>, Failure> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(Failure::Frame);
        }
        read_exact(io, &mut byte).map_err(|()| Failure::Stream)?;
        head.push(byte[0]);
    }
    Ok(head)
}

/// HTTP/2 CONNECT: the preface, the settings, stream 1, and the status that
/// stream's first header block carries. Stream 1 is this lane's and the only one
/// it opens, so the codec needs no stream-id bookkeeping.
pub(crate) fn open_h2(dial: &FoxyDial, target: &str) -> Result<Tls2, Failure> {
    let stream = tcp(dial)?;
    let mut tls = ferrox_core::tls::RustlsProvider::connect(&tls_config(dial), stream)
        .map_err(|_| Failure::Io)?;
    tls.handshake().map_err(|_| Failure::Io)?;
    negotiated(&tls, dial)?;

    let empty = frames::H2Frame {
        kind: frames::SETTINGS,
        flags: 0,
        stream: 0,
        length: 0,
    };
    let mut block = Vec::with_capacity(96 + dial.pass.token.len());
    hpack::hpack_connect(target, &dial.pass.token, &mut block);
    let headers = frames::H2Frame {
        kind: frames::HEADERS,
        flags: 0x4,
        stream: 1,
        length: block.len() as u32,
    };
    tls.write_all(frames::PREFACE)
        .and_then(|()| tls.write_all(&empty.header()))
        .and_then(|()| tls.write_all(&headers.header()))
        .and_then(|()| tls.write_all(&block))
        .and_then(|()| tls.flush())
        .map_err(|_| Failure::Io)?;

    let mut lane = Tls2 {
        tls,
        window: foxy::flow::Window::new(i64::from(DEFAULT_WINDOW), i64::from(DEFAULT_WINDOW)),
        max_frame: MAX_FRAME,
        send_window: OUR_WINDOW,
        carry: Vec::new(),
        fin: false,
    };
    let status = lane.await_status()?;
    opened(status)?;
    Ok(lane)
}

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8], out: &mut Vec<u8>) {
    let frame = frames::H2Frame {
        kind,
        flags,
        stream,
        length: payload.len() as u32,
    };
    out.extend_from_slice(&frame.header());
    out.extend_from_slice(payload);
}

/// A relay over a TLS stream that speaks HTTP/2: the frames go on and come off,
/// and a caller writing bytes sees a DATA frame and a caller reading bytes sees
/// the payload of one.
pub(crate) struct Tls2 {
    tls: ferrox_core::tls::RustlsProvider<TcpStream>,
    window: foxy::flow::Window,
    max_frame: usize,
    send_window: u32,
    carry: Vec<u8>,
    fin: bool,
}

impl Tls2 {
    fn read_frame(&mut self) -> Result<(frames::H2Frame, Vec<u8>), Failure> {
        let mut header = [0u8; frames::H2_HEADER];
        read_exact(&mut self.tls, &mut header).map_err(|()| Failure::Stream)?;
        let frame = frames::H2Frame::parse(&header).ok_or(Failure::Frame)?;
        let len = (frame.length as usize).min(self.max_frame);
        let mut payload = vec![0u8; len];
        read_exact(&mut self.tls, &mut payload).map_err(|()| Failure::Stream)?;
        Ok((frame, payload))
    }

    fn await_status(&mut self) -> Result<u16, Failure> {
        let deadline = Instant::now() + HEADER_TIMEOUT;
        let mut block = Vec::with_capacity(64);
        loop {
            if Instant::now() >= deadline {
                return Err(Failure::Stream);
            }
            let (frame, payload) = self.read_frame()?;
            match frames::h2_event(frame, &payload, 1) {
                frames::H2Event::Headers { block: more, .. } => {
                    block.extend_from_slice(more);
                    return hpack::hpack_status(&block).ok_or(Failure::Frame);
                }
                frames::H2Event::Settings {
                    ack: false,
                    payload,
                } => {
                    let mut out = Vec::with_capacity(32);
                    let mut at = 0usize;
                    while let Some((id, value)) = frames::setting(payload, at) {
                        match id {
                            4 => self.window.reset_stream(value),
                            5 => self.max_frame = (value as usize).clamp(16_384, MAX_FRAME),
                            _ => {}
                        }
                        at += 6;
                    }
                    h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                    h2_frame(
                        frames::WINDOW_UPDATE,
                        0,
                        0,
                        &(self.send_window - DEFAULT_WINDOW).to_be_bytes(),
                        &mut out,
                    );
                    self.tls.write_all(&out).map_err(|_| Failure::Io)?;
                }
                frames::H2Event::Ping {
                    ack: false,
                    payload,
                } => {
                    let mut out = Vec::with_capacity(17);
                    h2_frame(frames::PING, 0x1, 0, payload, &mut out);
                    self.tls.write_all(&out).map_err(|_| Failure::Io)?;
                }
                frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                    return Err(Failure::Stream);
                }
                frames::H2Event::Push => {
                    let mut out = Vec::with_capacity(13);
                    h2_frame(frames::RST_STREAM, 0, 1, &8u32.to_be_bytes(), &mut out);
                    self.tls.write_all(&out).map_err(|_| Failure::Io)?;
                }
                _ => {}
            }
        }
    }
}

impl Write for Tls2 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = foxy::flow::frame_size(buf.len(), self.max_frame).min(self.window.stream());
        if frame == 0 {
            return Ok(0);
        }
        self.window.take(frame);
        let frame = frame as usize;
        let mut out = Vec::with_capacity(frames::H2_HEADER + frame);
        h2_frame(frames::DATA, 0, 1, &buf[..frame], &mut out);
        self.tls.write_all(&out)?;
        Ok(frame)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tls.flush()
    }
}

impl Read for Tls2 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.carry.is_empty() {
                let take = buf.len().min(self.carry.len());
                buf[..take].copy_from_slice(&self.carry[..take]);
                self.carry.drain(..take);
                return Ok(take);
            }
            if self.fin {
                return Ok(0);
            }
            let (frame, payload) = self.read_frame().map_err(io)?;
            match frames::h2_event(frame, &payload, 1) {
                frames::H2Event::Data { payload, end } => {
                    self.window.add_stream(payload.len() as u32);
                    self.window.add_connection(payload.len() as u32);
                    if !payload.is_empty() {
                        let mut out = Vec::with_capacity(13 + payload.len());
                        h2_frame(
                            frames::WINDOW_UPDATE,
                            0,
                            1,
                            &(payload.len() as u32).to_be_bytes(),
                            &mut out,
                        );
                        h2_frame(
                            frames::WINDOW_UPDATE,
                            0,
                            0,
                            &(payload.len() as u32).to_be_bytes(),
                            &mut out,
                        );
                        self.tls.write_all(&out)?;
                        self.carry.extend_from_slice(payload);
                    }
                    self.fin = end;
                }
                frames::H2Event::Ping {
                    ack: false,
                    payload,
                } => {
                    let mut out = Vec::with_capacity(17);
                    h2_frame(frames::PING, 0x1, 0, payload, &mut out);
                    self.tls.write_all(&out)?;
                }
                frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                    self.fin = true;
                }
                _ => {}
            }
        }
    }
}

/// The HTTP/1.1 relay: bytes in, bytes out, once the status has been read.
pub(crate) struct Tls1(pub(crate) ferrox_core::tls::RustlsProvider<TcpStream>);

impl Write for Tls1 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl Read for Tls1 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

/// HTTP/3 CONNECT over one QUIC connection: a unidirectional control stream, a
/// request stream, one HEADERS frame each way, and then DATA frames in both
/// directions. The lane shares the connection across flows, which is what makes
/// the QUIC carrier worth having at all.
/// The pooled QUIC connection one flow of the HTTP/3 carrier rides: the shared
/// connection, its socket, the local address its packets come from, and the
/// bidirectional stream id this flow opened.
pub(crate) type Quic = (
    std::sync::Arc<std::sync::Mutex<quiche::Connection>>,
    std::sync::Arc<UdpSocket>,
    SocketAddr,
    u64,
);

pub(crate) struct H3 {
    shared: std::sync::Arc<std::sync::Mutex<quiche::Connection>>,
    sock: std::sync::Arc<UdpSocket>,
    local: SocketAddr,
    stream: u64,
    window: foxy::flow::Window,
    carry: Vec<u8>,
    fin: bool,
    deadline: Instant,
}

impl H3 {
    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Quic) -> Result<Self, Failure> {
        let (shared, sock, local, stream) = quic;
        let mut lane = Self {
            shared,
            sock,
            local,
            stream,
            window: foxy::flow::Window::new(MAX_WINDOW, MAX_WINDOW),
            carry: Vec::new(),
            fin: false,
            deadline: Instant::now(),
        };
        lane.control()?;
        let status = lane.request(target, &dial.pass.token)?;
        opened(status)?;
        Ok(lane)
    }

    fn with_conn<T>(&mut self, body: impl FnOnce(&mut quiche::Connection) -> T) -> Option<T> {
        let mut guard = self.shared.lock().ok()?;
        let out = body(&mut guard);
        crate::quic::flush_egress(&mut guard, &self.sock);
        Some(out)
    }

    /// The control stream is unidirectional stream 2, which is the first id QUIC
    /// hands a client after its own 0; a SETTINGS frame on it is what the peer
    /// waits for before it will answer anything.
    fn control(&mut self) -> Result<(), Failure> {
        let mut settings = Vec::new();
        frames::quic_varint(&mut settings, 0x04);
        frames::quic_varint(&mut settings, 0);
        self.send(2, &settings, false)?;
        self.fin(2)?;
        Ok(())
    }

    fn request(&mut self, target: &str, bearer: &str) -> Result<u16, Failure> {
        let mut block = Vec::with_capacity(96 + bearer.len());
        hpack::qpack_connect(target, bearer, &mut block);
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        self.send(0, &frame, false)?;
        self.read_head()
    }

    fn send(&mut self, stream: u64, buf: &[u8], fin: bool) -> Result<(), Failure> {
        let deadline = Instant::now() + SEND_WAIT;
        let mut rest = buf;
        while !rest.is_empty() {
            let written = self
                .with_conn(|conn| conn.stream_send(stream, rest, false))
                .ok_or(Failure::Io)?
                .map_err(|_| Failure::Io)?;
            rest = &rest[written..];
            if written == 0 {
                if Instant::now() >= deadline {
                    return Err(Failure::Io);
                }
                self.pump(Duration::from_millis(5));
            }
        }
        if fin {
            self.fin(stream)?;
        }
        Ok(())
    }

    fn fin(&mut self, stream: u64) -> Result<(), Failure> {
        let sent = self
            .with_conn(|conn| conn.stream_send(stream, &[], true))
            .ok_or(Failure::Io)?;
        sent.map(|_| ()).map_err(|_| Failure::Io)
    }

    fn pump(&mut self, wait: Duration) {
        let local = self.local;
        if let Ok(mut guard) = self.shared.lock() {
            crate::quic::pump_once(&mut guard, &self.sock, local, wait);
        }
    }

    fn read_head(&mut self) -> Result<u16, Failure> {
        self.deadline = Instant::now() + HEADER_TIMEOUT;
        let mut head = Vec::with_capacity(64);
        while Instant::now() < self.deadline {
            let mut chunk = [0u8; 4096];
            let id = self.stream;
            let read = self.with_conn(move |conn| conn.stream_recv(id, &mut chunk));
            let Some(read) = read else {
                return Err(Failure::Io);
            };
            match read {
                Ok((n, fin)) => {
                    head.extend_from_slice(&chunk[..n]);
                    if fin {
                        break;
                    }
                }
                Err(quiche::Error::Done) => {
                    if Instant::now() >= self.deadline {
                        return Err(Failure::Stream);
                    }
                    self.pump(Duration::from_millis(5));
                }
                Err(_) => return Err(Failure::Stream),
            }
            let Some((frame, body)) = frames::h3_frame(&head, &mut 0)
                .filter(|frame| frame.length as usize <= head.len())
                .map(|frame| (frame, &head[..]))
            else {
                continue;
            };
            if let frames::H3Event::Headers { block, .. } = frames::h3_event(frame, body) {
                return hpack::qpack_status(block).ok_or(Failure::Frame);
            }
        }
        Err(Failure::Frame)
    }
}

impl Write for H3 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = foxy::flow::frame_size(buf.len(), 16_384).min(self.window.stream());
        if frame == 0 {
            return Ok(0);
        }
        self.window.take(frame);
        let frame = frame as usize;
        let mut out = Vec::with_capacity(8 + frame);
        frames::quic_varint(&mut out, frames::H3_DATA);
        frames::quic_varint(&mut out, frame as u64);
        out.extend_from_slice(&buf[..frame]);
        self.send(self.stream, &out, false).map_err(io)?;
        Ok(frame)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.with_conn(|_| ()).ok_or_else(|| io(Failure::Io))
    }
}

impl Read for H3 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.carry.is_empty() {
                let take = buf.len().min(self.carry.len());
                buf[..take].copy_from_slice(&self.carry[..take]);
                self.carry.drain(..take);
                return Ok(take);
            }
            if self.fin {
                return Ok(0);
            }
            let mut chunk = [0u8; 8192];
            let id = self.stream;
            let read = self
                .with_conn(move |conn| conn.stream_recv(id, &mut chunk))
                .ok_or_else(|| io(Failure::Io))?;
            let (n, fin) = read.map_err(|_| io(Failure::Stream))?;
            self.window.add_stream(n as u32);
            self.window.add_connection(n as u32);
            self.carry.extend_from_slice(&chunk[..n]);
            if fin {
                self.fin = true;
            }
        }
    }
}

/// Reads the two-letter country out of whatever the probe answered: a
/// `loc=XX` line, a `"countryCode":"XX"` field, or nothing. A probe that cannot
/// be read is not evidence.
#[must_use]
pub(crate) fn exit_country(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    if let Some(after) = text.split_once("loc=") {
        let code: String = after
            .1
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
            return Some(code);
        }
    }
    let key = "\"countryCode\":\"";
    let at = text.find(key)? + key.len();
    text.get(at..at + 2)
        .filter(|code| code.chars().all(|c| c.is_ascii_uppercase()))
        .map(str::to_owned)
}

fn io(failure: Failure) -> std::io::Error {
    std::io::Error::other(failure.to_string())
}

/// Opens the tunnel on whichever carrier the dial names and hands the caller
/// something it can read and write. The `H3` arm needs its connection already
/// established, which the pool is what provides.
pub(crate) enum Tunnel {
    H1(Tls1),
    H2(Tls2),
    H3(Box<H3>),
}

impl Tunnel {
    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Option<Quic>) -> Result<Self, Failure> {
        match (dial.carrier, quic) {
            (Carrier::H1, _) => open_h1(dial, target).map(Self::H1),
            (Carrier::H2, _) => open_h2(dial, target).map(Self::H2),
            (Carrier::H3, Some(quic)) => {
                H3::open(dial, target, quic).map(|lane| Self::H3(Box::new(lane)))
            }
            (Carrier::H3, None) => Err(Failure::Stream),
        }
    }
}

impl Write for Tunnel {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.write(buf),
            Self::H2(lane) => lane.write(buf),
            Self::H3(lane) => lane.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.flush(),
            Self::H2(lane) => lane.flush(),
            Self::H3(lane) => lane.flush(),
        }
    }
}

impl Read for Tunnel {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::H1(lane) => lane.read(buf),
            Self::H2(lane) => lane.read(buf),
            Self::H3(lane) => lane.read(buf),
        }
    }
}

/// The SOCKS reply a refusal becomes: an edge that declined the target says so
/// locally instead of paying a round trip to hear the same status again.
pub(crate) fn refusal_reply(failure: Failure) -> u8 {
    match failure {
        Failure::Rejected(status) if foxy::target_is_unreachable(status) => 0x04,
        Failure::Stream => 0x06,
        Failure::Rejected(_) | Failure::Frame | Failure::Io => 0x01,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dial(host: &str, carrier: Carrier) -> FoxyDial {
        FoxyDial {
            host: host.to_owned(),
            port: 443,
            address: Some(SocketAddr::from(([127, 0, 0, 1], 1))),
            carrier,
            roots: Vec::new(),
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        }
    }

    #[test]
    fn every_carrier_asks_for_exactly_its_own_alpn() {
        for (carrier, want) in [
            (Carrier::H1, &b"http/1.1"[..]),
            (Carrier::H2, &b"h2"[..]),
            (Carrier::H3, &b"h3"[..]),
        ] {
            assert_eq!(
                tls_config(&dial("edge.example", carrier)).alpn,
                vec![want.to_vec()]
            );
        }
    }

    #[test]
    fn the_tls_config_names_the_edge_and_carries_its_pins() {
        let mut d = dial("edge.example", Carrier::H2);
        d.roots = vec![vec![1, 2, 3]];
        d.pins = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let config = tls_config(&d);
        assert_eq!(config.server_name, "edge.example");
        assert_eq!(config.roots, vec![vec![1, 2, 3]]);
        assert_eq!(config.pins.len(), 1);
    }

    #[test]
    fn only_a_two_hundred_opens_the_tunnel() {
        for status in [200u16, 204, 299] {
            assert!(opened(status).is_ok(), "{status}");
        }
        for status in [199u16, 300, 401, 403, 502] {
            assert_eq!(opened(status), Err(Failure::Rejected(status)));
        }
    }

    #[test]
    fn a_refusal_becomes_the_socks_reply_that_says_so() {
        assert_eq!(refusal_reply(Failure::Rejected(502)), 0x04);
        assert_eq!(refusal_reply(Failure::Rejected(403)), 0x01);
        assert_eq!(refusal_reply(Failure::Stream), 0x06);
        assert_eq!(refusal_reply(Failure::Io), 0x01);
        assert_eq!(refusal_reply(Failure::Frame), 0x01);
    }

    #[test]
    fn the_dial_order_is_the_pinned_country_only() {
        let edges = vec![
            foxy::Candidate {
                host: "de1".into(),
                port: 443,
                country: "DE".into(),
                city: "berlin".into(),
            },
            foxy::Candidate {
                host: "us1".into(),
                port: 443,
                country: "US".into(),
                city: "nyc".into(),
            },
            foxy::Candidate {
                host: "de2".into(),
                port: 443,
                country: "DE".into(),
                city: "frankfurt".into(),
            },
        ];
        let order = foxy::dial_order(&edges, "DE", None, 3);
        assert_eq!(order.len(), 2);
        assert!(order.iter().all(|edge| edge.country == "DE"));
    }

    #[test]
    fn a_quic_lane_without_a_connection_is_a_refusal_not_a_panic() {
        assert_eq!(
            Tunnel::open(&dial("edge.example", Carrier::H3), "e:443", None).err(),
            Some(Failure::Stream)
        );
    }

    #[test]
    fn an_exit_probe_is_read_in_either_shape_it_can_answer_in() {
        assert_eq!(exit_country(b"fl=1\nloc=DE\n"), Some("DE".to_owned()));
        assert_eq!(
            exit_country(b"{\"status\":\"success\",\"countryCode\":\"US\"}"),
            Some("US".to_owned())
        );
        assert_eq!(
            exit_country(b"loc=de"),
            None,
            "a lowercase answer is not a country code"
        );
        assert_eq!(exit_country(b"nothing here"), None);
        assert_eq!(exit_country(b"loc=DEU"), None);
    }
}

#[cfg(test)]
mod loopback {
    use super::*;
    use std::net::TcpListener;

    const PAYLOAD: &[u8] = b"the tunnel carries the bytes unchanged";

    fn minted(alpn: &[u8]) -> (Vec<Vec<u8>>, ferrox_core::tls::TlsServerConfig) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let server = ferrox_core::tls::TlsServerConfig {
            cert_chain: vec![minted.cert.der().to_vec()],
            key_der: minted.key_pair.serialize_der(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
            alpn: vec![alpn.to_vec()],
        };
        (roots, server)
    }

    fn dial_for(
        roots: Vec<Vec<u8>>,
        port: u16,
        carrier: Carrier,
        pins: foxy::pin::Pins,
    ) -> FoxyDial {
        FoxyDial {
            host: "localhost".to_owned(),
            port,
            address: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            carrier,
            roots,
            pins,
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        }
    }

    fn round_trip(tunnel: &mut Tunnel) {
        tunnel.write_all(PAYLOAD).expect("writes");
        tunnel.flush().expect("flushes");
        let mut back = vec![0u8; PAYLOAD.len()];
        tunnel.read_exact(&mut back).expect("reads");
        assert_eq!(back, PAYLOAD);
    }

    #[test]
    fn the_http11_carrier_sends_three_fields_and_carries_the_bytes() {
        let (roots, server) = minted(b"http/1.1");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                read_exact(&mut tls, &mut byte).expect("reads the request");
                head.push(byte[0]);
            }
            let request = String::from_utf8(head).expect("ascii");
            assert_eq!(
                request,
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Bearer the-pass\r\n\r\n"
            );
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = tls.read(&mut buf).expect("reads");
            assert_eq!(&buf[..read], PAYLOAD);
            tls.write_all(&buf[..read]).expect("echoes");
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }

    #[test]
    fn a_rejected_http11_request_is_a_status_not_a_tunnel() {
        let (roots, server) = minted(b"http/1.1");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
            tls.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .expect("answers");
            std::thread::sleep(Duration::from_millis(50));
        });
        let dial = dial_for(roots, port, Carrier::H1, foxy::pin::Pins::default());
        assert_eq!(
            Tunnel::open(&dial, "example.com:443", None).err(),
            Some(Failure::Rejected(407))
        );
        assert_eq!(refusal_reply(Failure::Rejected(407)), 0x01);
        edge.join().expect("joins");
    }

    /// The edge side of the HTTP/2 carrier: preface, settings, one stream, one
    /// status, then DATA both ways.
    fn h2_edge(
        listener: TcpListener,
        server: ferrox_core::tls::TlsServerConfig,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; 24 + frames::H2_HEADER];
            read_exact(&mut tls, &mut head).expect("reads the preface");
            assert_eq!(&head[..24], frames::PREFACE);
            let mut settings = Vec::new();
            frames::H2Frame {
                kind: frames::SETTINGS,
                flags: 0,
                stream: 0,
                length: 0,
            }
            .header()
            .to_vec();
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0, 0, &[], &mut ack);
            tls.write_all(&ack).expect("acks");
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                read_exact(&mut tls, &mut header).expect("reads a frame");
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                read_exact(&mut tls, &mut payload).expect("reads a payload");
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Headers { block, .. } => {
                        seen.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
                        settings.push(frame.stream);
                    }
                    frames::H2Event::Data { payload, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::DATA, 0, 1, payload, &mut out);
                        tls.write_all(&out).expect("echoes");
                    }
                    _ => {}
                }
            }
        })
    }

    #[test]
    fn the_http2_carrier_writes_one_literal_header_block_and_relays() {
        let (roots, server) = minted(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let mut want = Vec::new();
        hpack::hpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the same block the lane wrote");
        round_trip(&mut tunnel);
    }

    #[test]
    fn the_http2_carrier_reads_a_huffman_coded_status() {
        let (roots, server) = minted(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 4096];
            let _ = tls.read(&mut sink);
            // an indexed `:status` of 200, which is one byte
            let mut out = Vec::new();
            h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
            tls.write_all(&out).expect("answers");
            std::thread::sleep(Duration::from_millis(100));
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    #[test]
    fn a_pinned_edge_that_is_not_the_pin_is_refused() {
        let (roots, server) = minted(b"http/1.1");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            let _ = tls.handshake();
            std::thread::sleep(Duration::from_millis(200));
        });
        let wrong = foxy::pin::Pins::parse([
            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned()
        ]);
        let dial = dial_for(roots, port, Carrier::H1, wrong);
        assert!(Tunnel::open(&dial, "example.com:443", None).is_err());
        edge.join().expect("joins");
    }

    #[test]
    fn a_pinned_edge_that_is_the_pin_opens_the_tunnel() {
        let (roots, server) = minted(b"http/1.1");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let right =
            foxy::pin::Pins::parse([foxy::pin::spki_pin(&server.cert_chain[0]).expect("pins")]);
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut sink = vec![0u8; 1024];
            let _ = tls.read(&mut sink);
            tls.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            std::thread::sleep(Duration::from_millis(100));
        });
        let dial = dial_for(roots, port, Carrier::H1, right);
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }
}
