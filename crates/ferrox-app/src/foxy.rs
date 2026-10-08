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
const MAX_FRAME: usize = frames::MAX_FRAME as usize;
const MAX_HEAD: usize = 8_192;
const SEND_WAIT: Duration = Duration::from_secs(10);
/// The client's first unidirectional stream, which is where the SETTINGS that
/// make this connection HTTP/3 go.
const CONTROL_STREAM: u64 = 2;
/// How much of the request stream is buffered before the lane starts dropping
/// what it has already read, and the frame size one DATA frame may carry.
const H3_WINDOW: usize = 256 * 1024;
const H3_FRAME: usize = 16 * 1024;

/// The carriers the lane can carry, in the order `auto` prefers them: QUIC
/// first because one handshake carries every flow, HTTP/2 because the edge
/// speaks it, HTTP/1.1 because every edge does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carrier {
    H1,
    H2,
    H3,
    /// Try each carrier in turn, so an edge that will not answer QUIC is a
    /// slower tunnel rather than a refused one.
    Auto,
}

impl Carrier {
    #[must_use]
    pub(crate) const fn alpn(self) -> &'static [u8] {
        match self {
            Self::H1 => b"http/1.1",
            Self::H2 => b"h2",
            Self::H3 => b"h3",
            // An unexpanded `auto` offers nothing, so a dial that reaches here
            // with one fails the handshake instead of quietly dialling HTTP/2.
            Self::Auto => b"",
        }
    }

    /// The carriers to try, most preferred first, one entry when not `auto`.
    #[must_use]
    pub(crate) const fn order(self) -> [Self; 3] {
        match self {
            Self::Auto => [Self::H3, Self::H2, Self::H1],
            Self::H3 => [Self::H3, Self::H3, Self::H3],
            Self::H2 => [Self::H2, Self::H2, Self::H2],
            Self::H1 => [Self::H1, Self::H1, Self::H1],
        }
    }
}

/// Reads a carrier from a config or a link: `auto` is a carrier, and anything
/// the lane does not know is `auto` rather than a silent HTTP/2.
pub(crate) fn carrier(name: &str) -> Carrier {
    match name {
        "h1" | "http/1.1" => Carrier::H1,
        "h2" | "http/2" => Carrier::H2,
        "h3" | "quic" => Carrier::H3,
        _ => Carrier::Auto,
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

fn read_exact<S: Read>(io: &mut S, buf: &mut [u8]) -> std::io::Result<()> {
    let mut at = 0usize;
    while at < buf.len() {
        match io.read(&mut buf[at..]) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Err(error) => return Err(error),
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
        read_exact(io, &mut byte).map_err(|_| Failure::Stream)?;
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

    let mut block = Vec::with_capacity(96 + dial.pass.token.len());
    hpack::hpack_connect(target, &dial.pass.token, &mut block);
    // The stream window arrives in the settings; the connection window only
    // moves by a frame, so without this one the tunnel is paced by a round trip
    // for its first 64 KiB however large the stream window is.
    let mut opening = Vec::with_capacity(48 + block.len());
    opening.extend_from_slice(frames::PREFACE);
    h2_frame(
        frames::SETTINGS,
        0,
        0,
        &frames::client_settings(),
        &mut opening,
    );
    h2_frame(
        frames::WINDOW_UPDATE,
        0,
        0,
        &(frames::WINDOW - frames::DEFAULT_WINDOW).to_be_bytes(),
        &mut opening,
    );
    h2_frame(frames::HEADERS, 0x4, 1, &block, &mut opening);
    tls.write_all(&opening).map_err(|_| Failure::Io)?;

    let mut lane = Tls2 {
        tls,
        window: foxy::flow::Window::new(i64::from(frames::WINDOW), i64::from(frames::WINDOW)),
        max_frame: MAX_FRAME,
        carry: Vec::new(),
        at: 0,
        out: Vec::new(),
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
    /// Bytes read from a DATA frame that the caller has not taken yet, and how
    /// far into them it has got: a cursor rather than a drain, because draining
    /// moves what is left on every call.
    carry: Vec<u8>,
    at: usize,
    /// The frame this lane writes, reused so a relay allocates nothing per frame.
    out: Vec<u8>,
    fin: bool,
}

/// One frame off the wire: the header, and the payload in the buffer the caller
/// owns, because a field cannot be borrowed and written in the same match.
/// A socket timeout keeps its kind so a relay can tell an idle quantum from a
/// dead peer; anything else is a corrupt frame either way.
fn read_frame(
    tls: &mut ferrox_core::tls::RustlsProvider<TcpStream>,
    out: &mut Vec<u8>,
    max_frame: usize,
) -> std::io::Result<frames::H2Frame> {
    let mut header = [0u8; frames::H2_HEADER];
    read_exact(tls, &mut header)?;
    let frame = frames::H2Frame::parse(&header)
        .ok_or_else(|| std::io::Error::other("foxy: a header that is not a frame"))?;
    crate::proxy::resize_scratch(out, (frame.length as usize).min(max_frame));
    read_exact(tls, out)?;
    Ok(frame)
}

impl Tls2 {
    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        self.tls.get_ref().set_read_timeout(Some(quantum))
    }

    /// Reads one frame, hands it to `body` with the payload borrowed, and puts
    /// the buffer back: the frame is handled while the lane owns it.
    fn with_frame<R>(
        &mut self,
        body: impl FnOnce(&mut Self, frames::H2Frame, &[u8]) -> R,
    ) -> std::io::Result<R> {
        let mut payload = std::mem::take(&mut self.out);
        let frame = read_frame(&mut self.tls, &mut payload, self.max_frame);
        let out = match frame {
            Ok(frame) => body(self, frame, &payload),
            Err(error) => {
                self.out = payload;
                return Err(error);
            }
        };
        self.out = payload;
        Ok(out)
    }

    /// The window this lane grants back as it reads, one update per frame: the
    /// peer may not send faster than the tunnel is drained, and the connection
    /// update is the one that would otherwise stop a relay in its tracks.
    fn credit(&mut self, len: usize) -> Result<(), Failure> {
        let increment = (len as u32).to_be_bytes();
        let mut out = [0u8; 26];
        for (slot, stream) in [(9usize, 1u32), (22, 0)] {
            let frame = frames::H2Frame {
                kind: frames::WINDOW_UPDATE,
                flags: 0,
                stream,
                length: 4,
            };
            out[slot - 9..slot].copy_from_slice(&frame.header());
            out[slot..slot + 4].copy_from_slice(&increment);
        }
        self.tls.write_all(&out).map_err(|_| Failure::Io)
    }

    fn ack(&mut self, kind: u8, payload: &[u8]) -> Result<(), Failure> {
        self.out.clear();
        h2_frame(kind, 0x1, 0, payload, &mut self.out);
        self.tls.write_all(&self.out).map_err(|_| Failure::Io)
    }

    /// A push promise is refused by name, which is the only stream the lane
    /// answers that is not the one stream it opened.
    fn refuse_push(&mut self) -> Result<(), Failure> {
        self.out.clear();
        h2_frame(frames::RST_STREAM, 0, 1, &8u32.to_be_bytes(), &mut self.out);
        self.tls.write_all(&self.out).map_err(|_| Failure::Io)
    }

    fn await_status(&mut self) -> Result<u16, Failure> {
        let deadline = Instant::now() + HEADER_TIMEOUT;
        let mut block = Vec::with_capacity(64);
        while Instant::now() < deadline {
            let status = self
                .with_frame(
                    |lane, frame, payload| match frames::h2_event(frame, payload, 1) {
                        frames::H2Event::Headers { block: more, .. } => {
                            block.extend_from_slice(more);
                            hpack::hpack_status(&block).map(Some).ok_or(Failure::Frame)
                        }
                        frames::H2Event::Settings { ack: false, .. } => {
                            let mut at = 0usize;
                            while let Some((id, value)) = frames::setting(payload, at) {
                                match id {
                                    4 => lane.window.reset_stream(value),
                                    5 => lane.max_frame = (value as usize).clamp(16_384, MAX_FRAME),
                                    _ => {}
                                }
                                at += 6;
                            }
                            lane.ack(frames::SETTINGS, &[]).map(|()| None)
                        }
                        frames::H2Event::Ping { ack: false, .. } => {
                            lane.ack(frames::PING, payload).map(|()| None)
                        }
                        frames::H2Event::Push => lane.refuse_push().map(|()| None),
                        frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                            Err(Failure::Stream)
                        }
                        _ => Ok(None),
                    },
                )
                .map_err(|_| Failure::Stream)??;
            if let Some(status) = status {
                return Ok(status);
            }
        }
        Err(Failure::Stream)
    }

    /// Hands the caller what it asked for out of `carry` and moves the cursor:
    /// a copy of the bytes only, never a move of what is left.
    fn take(&mut self, buf: &mut [u8]) -> usize {
        let take = buf.len().min(self.carry.len() - self.at);
        buf[..take].copy_from_slice(&self.carry[self.at..self.at + take]);
        self.at += take;
        if self.at == self.carry.len() {
            self.carry.clear();
            self.at = 0;
        }
        take
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
        self.out.clear();
        h2_frame(frames::DATA, 0, 1, &buf[..frame], &mut self.out);
        self.tls.write_all(&self.out)?;
        Ok(frame)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tls.flush()
    }
}

impl Read for Tls2 {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.at < self.carry.len() {
                return Ok(self.take(buf));
            }
            if self.fin {
                return Ok(0);
            }
            let read = self.with_frame(|lane, frame, payload| -> std::io::Result<()> {
                match frames::h2_event(frame, payload, 1) {
                    frames::H2Event::Data { payload, end } => {
                        let len = payload.len();
                        lane.carry.clear();
                        lane.carry.extend_from_slice(payload);
                        lane.at = 0;
                        lane.window.add_stream(len as u32);
                        lane.window.add_connection(len as u32);
                        lane.fin = end;
                        if len > 0 {
                            lane.credit(len).map_err(io)?;
                        }
                        Ok(())
                    }
                    frames::H2Event::Ping { ack: false, .. } => {
                        lane.ack(frames::PING, payload).map_err(io)?;
                        Ok(())
                    }
                    frames::H2Event::Reset { .. } | frames::H2Event::GoAway { .. } => {
                        lane.fin = true;
                        Ok(())
                    }
                    _ => Ok(()),
                }
            });
            read??;
        }
    }
}

/// The HTTP/1.1 relay: bytes in, bytes out, once the status has been read.
pub(crate) struct Tls1(pub(crate) ferrox_core::tls::RustlsProvider<TcpStream>);

/// Bounds one blocking read so a relay holding one lock for both directions
/// can interleave: the backward read returns `WouldBlock` within the quantum
/// instead of holding the lock while no bytes arrive.
impl Tls1 {
    pub(crate) fn set_read_quantum(&self, quantum: Duration) -> std::io::Result<()> {
        self.0.get_ref().set_read_timeout(Some(quantum))
    }
}

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
    /// The request's HEADERS frame and whatever followed it on the same stream,
    /// plus the frame this lane writes: three buffers, none of them per frame.
    head: Vec<u8>,
    carried: usize,
    carry: Vec<u8>,
    at: usize,
    out: Vec<u8>,
    inbox: Vec<u8>,
    fin: bool,
    deadline: Instant,
    /// Bounds one blocking `Read::read` the way the socket timeout bounds the
    /// TCP carriers: unset reads until a DATA payload arrives, set returns
    /// `WouldBlock` after the quantum with no payload so a relay holding one
    /// lock for both directions can interleave.
    quantum: Option<Duration>,
}

impl H3 {
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) {
        self.quantum = Some(quantum);
    }

    pub(crate) fn open(dial: &FoxyDial, target: &str, quic: Quic) -> Result<Self, Failure> {
        let (shared, sock, local, stream) = quic;
        let mut lane = Self {
            shared,
            sock,
            local,
            stream,
            head: Vec::with_capacity(256),
            carried: 0,
            carry: Vec::new(),
            at: 0,
            out: Vec::new(),
            inbox: Vec::new(),
            fin: false,
            deadline: Instant::now(),
            quantum: None,
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

    /// The control stream is the client's first unidirectional stream, id 2, and
    /// its SETTINGS are what the peer waits for before it answers anything.
    ///
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` is sent as zero on purpose: it says
    /// this lane sends a classic CONNECT with no `:protocol`, which is the shape
    /// the edge answers over HTTP/2, and a peer that believes otherwise reads
    /// the request as one it may refuse.
    fn control(&mut self) -> Result<(), Failure> {
        self.out.clear();
        frames::quic_varint(&mut self.out, frames::H3_DATA);
        frames::quic_varint(&mut self.out, 4);
        frames::quic_varint(&mut self.out, 0x04);
        frames::quic_varint(&mut self.out, 0);
        let settings = std::mem::take(&mut self.out);
        let sent = self.send(CONTROL_STREAM, &settings, false);
        self.out = settings;
        sent?;
        self.fin(CONTROL_STREAM)?;
        Ok(())
    }

    fn request(&mut self, target: &str, bearer: &str) -> Result<u16, Failure> {
        let mut block = Vec::with_capacity(96 + bearer.len());
        hpack::qpack_connect(target, bearer, &mut block);
        let mut frame = Vec::with_capacity(16 + block.len());
        frames::quic_varint(&mut frame, frames::H3_HEADERS);
        frames::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        self.send(self.stream, &frame, false)?;
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

    /// Pulls the request stream until a whole HEADERS frame has arrived, then
    /// reads the status out of it. Bytes read past that frame stay buffered,
    /// because the first DATA frame the edge sends is the tunnel and not a
    /// header the caller wants.
    fn read_head(&mut self) -> Result<u16, Failure> {
        self.deadline = Instant::now() + HEADER_TIMEOUT;
        while Instant::now() < self.deadline {
            let at = self.carried;
            if let Some(status) = Self::header_in(&self.head[at..])? {
                return Ok(status);
            }
            self.fill()?;
        }
        Err(Failure::Stream)
    }

    /// The status of the first complete HEADERS frame in `bytes`, and how much
    /// of it that frame was.
    fn header_in(bytes: &[u8]) -> Result<Option<u16>, Failure> {
        let mut at = 0usize;
        let Some(frame) = frames::h3_frame(bytes, &mut at) else {
            return Ok(None);
        };
        let Some(end) = at.checked_add(frame.length as usize) else {
            return Err(Failure::Frame);
        };
        let Some(body) = bytes.get(at..end) else {
            return Ok(None);
        };
        match frames::h3_event(frame, body) {
            frames::H3Event::Headers { block, .. } => {
                hpack::qpack_status(block).map(Some).ok_or(Failure::Frame)
            }
            frames::H3Event::Reset { .. } | frames::H3Event::GoAway { .. } => Err(Failure::Stream),
            _ => Ok(None),
        }
    }

    /// One read from the request stream into the head buffer, or a pump when
    /// nothing has arrived: the same two answers a QUIC stream can give.
    fn fill(&mut self) -> Result<(), Failure> {
        let id = self.stream;
        let room = H3_WINDOW - self.head.len();
        let mut chunk = std::mem::take(&mut self.inbox);
        crate::proxy::resize_scratch(&mut chunk, room.max(1));
        let read = self.with_conn(|conn| conn.stream_recv(id, &mut chunk).map(|r| (r, ())));
        self.inbox = chunk;
        let Some(Ok(((n, fin), ()))) = read else {
            return match read {
                Some(Err(quiche::Error::Done)) => {
                    if Instant::now() >= self.deadline {
                        return Err(Failure::Stream);
                    }
                    self.pump(Duration::from_millis(5));
                    Ok(())
                }
                _ => Err(Failure::Io),
            };
        };
        self.head.extend_from_slice(&self.inbox[..n]);
        if n == 0 && fin {
            return Err(Failure::Stream);
        }
        Ok(())
    }
}

impl Write for H3 {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = foxy::flow::frame_size(buf.len(), H3_FRAME);
        if frame == 0 {
            return Ok(0);
        }
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        frames::quic_varint(&mut out, frames::H3_DATA);
        frames::quic_varint(&mut out, u64::from(frame));
        out.extend_from_slice(&buf[..frame as usize]);
        let sent = self.send(self.stream, &out, false);
        self.out = out;
        sent.map_err(io)?;
        Ok(frame as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.with_conn(|_| ()).ok_or_else(|| io(Failure::Io))
    }
}

impl Read for H3 {
    /// The tunnel, not the stream: what the caller gets is the payload of DATA
    /// frames, because a frame header read as payload is a tunnel that carries
    /// its own framing into every byte after it.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let started = Instant::now();
        loop {
            if self.at < self.carry.len() {
                let take = buf.len().min(self.carry.len() - self.at);
                buf[..take].copy_from_slice(&self.carry[self.at..self.at + take]);
                self.at += take;
                if self.at == self.carry.len() {
                    self.carry.clear();
                    self.at = 0;
                }
                return Ok(take);
            }
            if self.fin {
                return Ok(0);
            }
            if self
                .quantum
                .is_some_and(|quantum| started.elapsed() >= quantum)
            {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            self.deadline = Instant::now() + HEADER_TIMEOUT;
            let room = H3_WINDOW - self.head.len();
            if room < 16 {
                self.head.drain(..self.carried);
                self.carried = 0;
            }
            self.fill().map_err(io)?;
            self.take_frames().map_err(io)?;
        }
    }
}

impl H3 {
    /// Walks the buffered frames, keeping a DATA payload for the caller and
    /// leaving anything that is not tunnel bytes where the next read starts.
    fn take_frames(&mut self) -> Result<(), Failure> {
        loop {
            let at = self.carried;
            let mut head = 0usize;
            let Some(frame) = frames::h3_frame(&self.head[at..], &mut head) else {
                return Ok(());
            };
            let end = match at
                .checked_add(head)
                .and_then(|body| body.checked_add(frame.length as usize))
            {
                Some(end) if end <= self.head.len() => end,
                _ => return Ok(()),
            };
            let body = at + head;
            match frames::h3_event(frame, &self.head[body..end]) {
                frames::H3Event::Data { payload, .. } => {
                    self.carry.clear();
                    self.carry.extend_from_slice(payload);
                    self.at = 0;
                    self.carried = end;
                    return Ok(());
                }
                frames::H3Event::Reset { .. } | frames::H3Event::GoAway { .. } => {
                    self.fin = true;
                    self.carried = self.head.len();
                    return Ok(());
                }
                _ => self.carried = end,
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
            // `auto` is expanded by the caller into the carriers it prefers; an
            // unexpanded one here is a bug, and the answer is not a downgrade.
            (Carrier::Auto, _) => Err(Failure::Frame),
        }
    }

    /// Bounds one blocking read on every carrier, so a relay sharing one lane
    /// between its two directions stops holding its lock while idle: reads past
    /// the quantum answer `WouldBlock` and the relay retries instead of wedging.
    pub(crate) fn set_read_quantum(&mut self, quantum: Duration) -> std::io::Result<()> {
        match self {
            Self::H1(lane) => lane.set_read_quantum(quantum),
            Self::H2(lane) => lane.set_read_quantum(quantum),
            Self::H3(lane) => {
                lane.set_read_quantum(quantum);
                Ok(())
            }
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
            let mut head = vec![0u8; frames::PREFACE.len()];
            read_exact(&mut tls, &mut head).expect("reads the preface");
            assert_eq!(head, frames::PREFACE);
            let mut ack = Vec::new();
            h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut ack);
            tls.write_all(&ack).expect("acks");
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                read_exact(&mut tls, &mut header).expect("reads a frame");
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                read_exact(&mut tls, &mut payload).expect("reads a payload");
                match frames::h2_event(frame, &payload, 1) {
                    frames::H2Event::Settings { ack: false, .. } => {
                        let mut out = Vec::new();
                        h2_frame(frames::SETTINGS, 0x1, 0, &[], &mut out);
                        tls.write_all(&out).expect("acks the settings");
                    }
                    frames::H2Event::Headers { block, .. } => {
                        seen.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
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
    fn the_shared_lane_carries_both_directions_at_once() {
        const BIG: usize = 256 * 1024;
        let (roots, server) = minted(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(50))
            .expect("bounds one read");
        let lane = std::sync::Arc::new(std::sync::Mutex::new(tunnel));
        let sent: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let forward = std::sync::Arc::clone(&lane);
        let chunk = sent.clone();
        std::thread::spawn(move || {
            let mut at = 0usize;
            while at < chunk.len() {
                match forward.lock().expect("locks").write(&chunk[at..]) {
                    Ok(0) => std::thread::sleep(Duration::from_millis(5)),
                    Ok(wrote) => at += wrote,
                    Err(error) => panic!("the write failed: {error}"),
                }
            }
            done_tx.send(()).expect("reports");
        });
        let mut back = vec![0u8; BIG];
        let mut at = 0usize;
        while at < BIG {
            match lane.lock().expect("locks").read(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("both directions flow at once");
        assert_eq!(back, sent);
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

    /// The edge half of the QUIC carrier: a control stream, one HEADERS frame
    /// with a QPACK status, and DATA frames echoed both ways.
    ///
    /// This is the proof the QUIC lane did not have: the request on the wire is
    /// compared byte for byte with the block the lane wrote, the status is read
    /// through the QPACK decoder, and the bytes that follow the head travel
    /// through the tunnel. A codec test cannot answer any of those three.
    fn h3_edge(
        sock: UdpSocket,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let tag = format!("ferrox-foxy-h3-{}-{stamp}", std::process::id());
            let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
            let key_path = std::env::temp_dir().join(format!("{tag}.key"));
            std::fs::write(&cert_path, &cert_pem).expect("stages cert");
            std::fs::write(&key_path, &key_pem).expect("stages key");
            let mut config = crate::quic::server_config(crate::quic::ALPN);
            config
                .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
                .expect("loads chain");
            config
                .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
                .expect("loads key");
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let mut conn = crate::quic::server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            // A server's own control stream is its first unidirectional stream,
            // id 3, and the client's SETTINGS are answered on it.
            let mut control = Vec::new();
            frames::quic_varint(&mut control, frames::H3_DATA);
            frames::quic_varint(&mut control, 0);
            conn.stream_send(3, &control, true).expect("opens control");
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut request = None;
            while request.is_none() {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                let ids: Vec<u64> = conn.readable().collect();
                conn.recv(&mut buf[..n], info).expect("drives");
                for id in ids {
                    // The control stream is unidirectional and the request is
                    // not, so the stream id itself tells them apart.
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        request = Some((id, piece));
                        break;
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let (stream, raw) = request.expect("read");
            let mut at = 0usize;
            let frame = frames::h3_frame(&raw, &mut at).expect("a frame");
            let block = raw[at..at + frame.length as usize].to_vec();
            let _ = seen.send(block);

            let mut reply = Vec::new();
            frames::quic_varint(&mut reply, frames::H3_HEADERS);
            frames::quic_varint(&mut reply, 3);
            // `0xd9` is QPACK static index 25, which is `:status 200`: the
            // indexed field line with a six-bit prefix, then the block's two
            // required zero bytes.
            reply.extend_from_slice(&[0x00, 0x00, 0xd9]);
            conn.stream_send(stream, &reply, false).expect("answers");
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }

            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            let mut received: Vec<u8> = Vec::new();
            let mut sent = 0usize;
            while sent < PAYLOAD.len() {
                assert!(std::time::Instant::now() < deadline, "the tunnel echoes");
                if let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) {
                    let info = quiche::RecvInfo { from, to: local };
                    conn.recv(&mut buf[..n], info).expect("drives");
                    let piece = drain(&mut conn, stream);
                    let mut at = 0usize;
                    while let Some(frame) = frames::h3_frame(&piece, &mut at) {
                        let end = (at + frame.length as usize).min(piece.len());
                        if let frames::H3Event::Data { payload, .. } =
                            frames::h3_event(frame, &piece[at..end])
                        {
                            received.extend_from_slice(payload);
                        }
                        at = end;
                    }
                }
                if received.len() > sent {
                    let n = (received.len() - sent).min(16_384);
                    let mut frame = Vec::new();
                    frames::quic_varint(&mut frame, frames::H3_DATA);
                    frames::quic_varint(&mut frame, n as u64);
                    frame.extend_from_slice(&received[sent..sent + n]);
                    conn.stream_send(stream, &frame, false).expect("echoes");
                    sent += n;
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
        })
    }

    /// Every byte a stream holds, read into a buffer that exists: a `Vec` handed
    /// to `stream_recv` is a zero-length slice and never receives anything.
    fn drain(conn: &mut quiche::Connection, id: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
        out
    }

    #[test]
    fn the_quic_carrier_sends_the_block_reads_the_status_and_carries_the_bytes() {
        let (roots, server) = minted(b"h3");
        let sock = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let port = sock.local_addr().expect("addr").port();
        let key_pem = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(
            sock,
            crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE"),
            key_pem,
            seen_tx,
        );

        let dial = dial_for(roots, port, Carrier::H3, foxy::pin::Pins::default());
        let quic = crate::quic::direct_stream("localhost", "127.0.0.1", port, &dial.roots)
            .expect("a connection");
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("block");
        let mut want = Vec::new();
        hpack::qpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge reads the same block the lane wrote");
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }
}
