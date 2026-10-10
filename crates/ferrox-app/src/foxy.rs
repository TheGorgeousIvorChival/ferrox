//! The Foxy lane in the app: a CONNECT tunnel to an account's CDN edge, carried
//! over whichever of HTTP/1.1, HTTP/2 or HTTP/3 the edge answers.
//!
//! One shape for all three carriers — open a stream to the edge, send three
//! header fields, read one status, relay — and the parts that decide rather than
//! move bytes live in `ferrox_core::foxy`. The relay itself is shared: a lane
//! hands the caller a `Read + Write` and the caller does not know which carrier
//! produced it.

use ferrox_core::foxy::{self, authority, frames, hpack, masque, Failure, Pass};
use ferrox_core::tls::TlsProvider;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs as _};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_FRAME: usize = frames::MAX_FRAME as usize;
const MAX_HEAD: usize = 8_192;
/// How much of a capsule stream waits unparsed before the lane fails the
/// association rather than buffering a peer that never completes a capsule.
const DATAGRAM_BUF_MAX: usize = 256 * 1024;
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
    /// The upstream hop the dial chains through, so a network that only permits
    /// proxy egress can still start the lane: TCP over CONNECT or a SOCKS5
    /// stream, and the QUIC carrier over a SOCKS5 UDP association.
    pub(crate) upstream: Option<UpstreamProxy>,
    pub(crate) roots: Vec<Vec<u8>>,
    pub(crate) pins: foxy::pin::Pins,
    pub(crate) pass: Pass,
}

/// One hop before the edge: plain HTTP CONNECT or a no-auth SOCKS5 handshake.
/// Anything else, including credentials the lane has nowhere to put, refuses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct UpstreamProxy {
    http: bool,
    host: String,
    port: u16,
}

impl UpstreamProxy {
    /// Whether the hop speaks HTTP CONNECT, which is a TCP-only hop: a QUIC
    /// carrier has nothing to ride it with and must be refused instead.
    pub(crate) fn http(&self) -> bool {
        self.http
    }
}

pub(crate) fn upstream_proxy(text: &str) -> Option<UpstreamProxy> {
    let text = text.trim();
    let (http, rest) = text
        .strip_prefix("http://")
        .map(|rest| (true, rest))
        .or_else(|| text.strip_prefix("socks5://").map(|rest| (false, rest)))
        .or_else(|| text.strip_prefix("socks5h://").map(|rest| (false, rest)))?;
    let (host, port) = rest.rsplit_once(':')?;
    if host.is_empty() || host.contains('/') || host.contains('@') {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    Some(UpstreamProxy {
        http,
        host: host.to_owned(),
        port,
    })
}

fn tls_config(dial: &FoxyDial) -> ferrox_core::tls::TlsConfig {
    ferrox_core::tls::TlsConfig {
        server_name: dial.host.clone(),
        alpn: vec![dial.carrier.alpn().to_vec()],
        roots: dial.roots.clone(),
        pins: dial.pins.clone(),
    }
}

fn tcp(dial: &FoxyDial) -> Result<TcpStream, Failure> {
    if let Some(proxy) = dial.upstream.as_ref() {
        return tcp_via(proxy, dial);
    }
    // A name answers with more than one address and the first is not a
    // promise: an edge that listens on one family and not the other is dialed
    // on the family that answers, so every address is tried rather than the
    // one the resolver happened to list first. An address the config names is
    // the dial it named, and nothing else.
    let peers = match dial.address {
        Some(address) => vec![address],
        None => format!("{}:{}", dial.host, dial.port)
            .to_socket_addrs()
            .map_err(|_| Failure::Io)?
            .collect(),
    };
    let mut tried = 0usize;
    for peer in peers {
        tried += 1;
        if let Ok(stream) = TcpStream::connect_timeout(&peer, CONNECT_TIMEOUT) {
            let _ = stream.set_nodelay(true);
            return Ok(stream);
        }
    }
    debug_stage("the edge accepted TCP on none of its addresses");
    if tried > 1 {
        eprintln!("foxy: the edge answered on none of its {tried} addresses");
    }
    Err(Failure::Io)
}

/// TCP to the edge through one upstream hop: the TLS name stays the edge's,
/// so the hop carries bytes it can neither read nor address.
fn tcp_via(proxy: &UpstreamProxy, dial: &FoxyDial) -> Result<TcpStream, Failure> {
    let mut stream = tcp_to_proxy(proxy).ok_or(Failure::Io)?;
    let edge = authority(&dial.host, dial.port);
    if proxy.http {
        let request = format!("CONNECT {edge} HTTP/1.1\r\nHost: {edge}\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|_| Failure::Io)?;
        // The whole head, not just the status line: the blank line's bytes
        // belong to the proxy, and anything left in the stream becomes the
        // first bytes of the TLS handshake that follows.
        let mut head = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            read_exact(&mut stream, &mut byte).map_err(|_| Failure::Io)?;
            head.push(byte[0]);
            if head.len() > 4096 {
                return Err(Failure::Io);
            }
        }
        let code = head
            .split(|b| *b == b'\n')
            .next()
            .and_then(|line| line.split(|b| *b == b' ').nth(1))
            .and_then(|code| std::str::from_utf8(code).ok())
            .and_then(|code| code.trim().parse::<u16>().ok())
            .ok_or(Failure::Io)?;
        opened(code)?;
    } else {
        socks_greeting(&mut stream)?;
        let host_len = u8::try_from(dial.host.len()).map_err(|_| Failure::Io)?;
        let mut request = vec![5, 1, 0, 3, host_len];
        request.extend_from_slice(dial.host.as_bytes());
        request.extend_from_slice(&dial.port.to_be_bytes());
        stream.write_all(&request).map_err(|_| Failure::Io)?;
        // The address the hop bound is not the edge's, so it is read past and
        // dropped: the connection itself is the answer.
        if socks_reply(&mut stream)?.is_none() {
            return Err(Failure::Io);
        }
    }
    Ok(stream)
}

/// One UDP association with a SOCKS5 hop: the greeting this tree already speaks,
/// a request that names no destination yet, and the relay address the hop
/// answers with. The control connection is the caller's to hold — dropping it
/// is how the association ends — and a hop that refuses answers the way it
/// refuses a CONNECT, with a status that is not zero.
pub(crate) fn associate_udp(proxy: &UpstreamProxy) -> Option<(Arc<TcpStream>, SocketAddr)> {
    let mut control = tcp_to_proxy(proxy)?;
    if socks_greeting(&mut control).is_err() {
        return None;
    }
    if control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return None;
    }
    let Ok(Some(relay)) = socks_reply(&mut control) else {
        return None;
    };
    Some((Arc::new(control), relay))
}

/// The one hop this tree speaks to, dialed and kept alive: a proxy that does
/// not answer at all is a failed dial, not a lane running direct.
fn tcp_to_proxy(proxy: &UpstreamProxy) -> Option<TcpStream> {
    // Same reason the edge dial tries each one: a hop that answers on the
    // family the resolver listed second is still the hop this lane uses.
    for addr in format!("{}:{}", proxy.host, proxy.port)
        .to_socket_addrs()
        .ok()?
    {
        if let Ok(stream) = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            let _ = stream.set_nodelay(true);
            return Some(stream);
        }
    }
    None
}

/// No authentication offered, no authentication accepted: a hop that selects
/// anything else is one this lane cannot use.
fn socks_greeting(stream: &mut TcpStream) -> Result<(), Failure> {
    stream.write_all(&[5, 1, 0]).map_err(|_| Failure::Io)?;
    let mut method = [0u8; 2];
    read_exact(stream, &mut method).map_err(|_| Failure::Io)?;
    if method != [5, 0] {
        return Err(Failure::Io);
    }
    Ok(())
}

/// Whether the hop granted the request, and the address it bound the far side
/// to: a refusal answers the same reply with a non-zero status, and a hop that
/// answers in a name is one this tree cannot address back.
fn socks_reply(stream: &mut TcpStream) -> Result<Option<SocketAddr>, Failure> {
    let mut head = [0u8; 4];
    read_exact(stream, &mut head).map_err(|_| Failure::Io)?;
    if head[1] != 0 {
        return Ok(None);
    }
    let mut read = |into: &mut [u8]| read_exact(stream, into).map_err(|_| Failure::Io);
    let ip = match head[3] {
        1 => {
            let mut octets = [0u8; 4];
            read(&mut octets)?;
            std::net::Ipv4Addr::from(octets).into()
        }
        4 => {
            let mut octets = [0u8; 16];
            read(&mut octets)?;
            std::net::Ipv6Addr::from(octets).into()
        }
        _ => return Err(Failure::Io),
    };
    let mut port = [0u8; 2];
    read(&mut port)?;
    Ok(Some(SocketAddr::new(ip, u16::from_be_bytes(port))))
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
        .inspect_err(|_| debug_stage("the TLS handshake with the edge failed"))
        .map_err(|_| Failure::Io)?;
    tls.handshake()
        .inspect_err(|_| debug_stage("the TLS handshake with the edge failed"))
        .map_err(|_| Failure::Io)?;
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
    let mut block = Vec::with_capacity(96 + dial.pass.token.len());
    hpack::hpack_connect(target, &dial.pass.token, &mut block);
    open_h2_with(dial, &block)
}

/// One UDP target as its own H2 connection carrying CONNECT-UDP: a lane stays
/// one stream on one connection, so a second target is a second connection
/// rather than stream bookkeeping this codec does not have.
pub(crate) fn open_udp(
    dial: &FoxyDial,
    target_host: &str,
    target_port: u16,
) -> Result<Tls2, Failure> {
    let edge = if dial.port == 443 {
        dial.host.clone()
    } else {
        format!("{}:{}", dial.host, dial.port)
    };
    let mut block = Vec::with_capacity(160 + dial.pass.token.len() + target_host.len());
    masque::connect_udp(
        &edge,
        target_host,
        target_port,
        &dial.pass.token,
        &mut block,
    );
    open_h2_with(dial, &block)
}

fn open_h2_with(dial: &FoxyDial, block: &[u8]) -> Result<Tls2, Failure> {
    let stream = tcp(dial)?;
    let mut tls = ferrox_core::tls::RustlsProvider::connect(&tls_config(dial), stream)
        .inspect_err(|_| debug_stage("the TLS handshake with the edge failed"))
        .map_err(|_| Failure::Io)?;
    tls.handshake()
        .inspect_err(|_| debug_stage("the TLS handshake with the edge failed"))
        .map_err(|_| Failure::Io)?;
    negotiated(&tls, dial)?;

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
    h2_frame(frames::HEADERS, 0x4, 1, block, &mut opening);
    tls.write_all(&opening).map_err(|_| Failure::Io)?;

    let mut lane = Tls2 {
        tls,
        window: foxy::flow::Window::new(i64::from(frames::WINDOW), i64::from(frames::WINDOW)),
        max_frame: MAX_FRAME,
        carry: Vec::new(),
        at: 0,
        out: Vec::new(),
        capsule_buf: Vec::new(),
        fin: false,
    };
    let status = lane.await_status()?;
    opened(status)?;
    Ok(lane)
}

/// The stage the lane's edge dial lost, behind `FOXY_DEBUG`: the lane already
/// says that it failed, and a red leg is only actionable when it says where.
fn debug_stage(stage: &str) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: {stage}");
    }
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
    /// Bytes of the capsule stream a datagram read has not parsed yet: one
    /// capsule may span DATA frames, so frames accumulate here.
    capsule_buf: Vec<u8>,
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
                            header_status(&mut block, more, frame.flags & frames::END_HEADERS != 0)
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
                        // A status larger than one frame arrives in pieces: each
                        // fragment is appended and the block is read once the
                        // peer's `END_HEADERS` says it is whole.
                        frames::H2Event::Other { kind } if kind == frames::CONTINUATION => {
                            header_status(
                                &mut block,
                                payload,
                                frame.flags & frames::END_HEADERS != 0,
                            )
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

    /// One UDP payload as one DATAGRAM capsule, split over DATA frames when it
    /// does not fit: the capsule stream is byte-oriented, so a frame boundary
    /// inside it is legal and the reader reassembles.
    pub(crate) fn write_datagram(&mut self, payload: &[u8]) -> std::io::Result<()> {
        if self.fin {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        self.out.clear();
        masque::datagram_encode(payload, &mut self.out);
        let mut at = 0usize;
        while at < self.out.len() {
            let frame = foxy::flow::frame_size(self.out.len() - at, self.max_frame)
                .min(self.window.stream());
            if frame == 0 {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            self.window.take(frame);
            let frame = frame as usize;
            let header = frames::H2Frame {
                kind: frames::DATA,
                flags: 0,
                stream: 1,
                length: frame as u32,
            }
            .header();
            self.tls.write_all(&header)?;
            self.tls.write_all(&self.out[at..at + frame])?;
            at += frame;
        }
        Ok(())
    }

    /// One UDP payload out of the capsule stream: frames accumulate until a
    /// whole DATAGRAM capsule parses, so a capsule split over frames still
    /// arrives as one datagram. Empty datagrams carry nothing and are skipped,
    /// which keeps `Ok(0)` for the end of the stream.
    pub(crate) fn read_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if let Some((used, payload)) = masque::datagram_split(&self.capsule_buf) {
                let take = buf.len().min(payload.len());
                buf[..take].copy_from_slice(&payload[..take]);
                let len = payload.len();
                self.capsule_buf.drain(..used);
                if len == 0 {
                    continue;
                }
                return Ok(len);
            }
            if self.fin {
                return Ok(0);
            }
            if self.capsule_buf.len() > DATAGRAM_BUF_MAX {
                self.capsule_buf.clear();
                return Err(std::io::Error::other(
                    "foxy: a capsule stream that never parses",
                ));
            }
            let read = self.with_frame(|lane, frame, payload| -> std::io::Result<()> {
                match frames::h2_event(frame, payload, 1) {
                    frames::H2Event::Data { payload, end } => {
                        lane.capsule_buf.extend_from_slice(payload);
                        lane.fin = end;
                        lane.window.add_stream(payload.len() as u32);
                        lane.window.add_connection(payload.len() as u32);
                        if !payload.is_empty() {
                            lane.credit(payload.len()).map_err(io)?;
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

/// One HTTP/2 session to the edge with the opening already written and no
/// stream on it yet, for the check that asks the edge what it does with a
/// second CONNECT: the answer is what says whether the lane may pool the
/// session, and no loopback edge can stand in for the real one.
#[cfg(test)]
pub(crate) fn raw_h2_session(
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<TcpStream>, Failure> {
    open_h2_with_raw(dial)
}

/// The dial half of `open_h2_with`, before any stream: the session an H2 lane
/// rides, written the way the lane writes its first one.
#[cfg(test)]
fn open_h2_with_raw(
    dial: &FoxyDial,
) -> Result<ferrox_core::tls::RustlsProvider<TcpStream>, Failure> {
    let stream = tcp(dial)?;
    let mut tls = ferrox_core::tls::RustlsProvider::connect(&tls_config(dial), stream)
        .inspect_err(|_| debug_stage("the TLS handshake with the edge failed"))
        .map_err(|_| Failure::Io)?;
    tls.handshake()
        .inspect_err(|_| debug_stage("the TLS handshake with the edge failed"))
        .map_err(|_| Failure::Io)?;
    negotiated(&tls, dial)?;
    let mut opening = Vec::with_capacity(48);
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
    tls.write_all(&opening).map_err(|_| Failure::Io)?;
    tls.flush().map_err(|_| Failure::Io)?;
    Ok(tls)
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

/// Temporary undecodable-block dump behind `FOXY_DEBUG`: the hex of a header
/// block no codec in this tree reads, so a red live run names the encoding.
fn debug_block(block: &[u8]) {
    if std::env::var("FOXY_DEBUG").is_ok() {
        eprintln!("foxy-debug: undecodable header block {block:02x?}");
    }
}

/// Appends one header-block fragment and reads the status once the peer's
/// `END_HEADERS` says the block is whole; a partial block is never parsed.
fn header_status(
    block: &mut Vec<u8>,
    piece: &[u8],
    end_headers: bool,
) -> Result<Option<u16>, Failure> {
    block.extend_from_slice(piece);
    if !end_headers {
        return Ok(None);
    }
    hpack::hpack_status(block).map(Some).ok_or_else(|| {
        debug_block(block);
        Failure::Frame
    })
}

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
    std::sync::Arc<crate::quic::Datagram>,
    SocketAddr,
    u64,
);

pub(crate) struct H3 {
    shared: std::sync::Arc<std::sync::Mutex<quiche::Connection>>,
    sock: std::sync::Arc<crate::quic::Datagram>,
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

    /// The HTTP/3 opening one fresh connection carries exactly once: control
    /// with a complete SETTINGS frame plus the QPACK encoder and decoder
    /// hellos. No dynamic table (the QPACK below is literal-only), no blocked
    /// streams, classic CONNECT. A truncated SETTINGS is a peer that waits
    /// forever; a second control stream is a connection error. Neither the
    /// opening nor any of the three streams is ever finished.
    pub(crate) fn h3_opening() -> [(u64, Vec<u8>); 3] {
        let mut control = Vec::with_capacity(16);
        frames::quic_varint(&mut control, 0x00);
        let settings = [0x01u8, 0x00, 0x07, 0x00, 0x08, 0x00];
        frames::quic_varint(&mut control, 0x04);
        frames::quic_varint(&mut control, settings.len() as u64);
        control.extend_from_slice(&settings);
        let mut encoder = Vec::with_capacity(2);
        frames::quic_varint(&mut encoder, 0x02);
        let mut decoder = Vec::with_capacity(2);
        frames::quic_varint(&mut decoder, 0x03);
        [(CONTROL_STREAM, control), (6, encoder), (10, decoder)]
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
            upstream: None,
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
    fn an_upstream_proxy_names_its_scheme_host_and_port() {
        let http = upstream_proxy("http://proxy.local:8080").expect("parses");
        assert!(http.http);
        assert_eq!((http.host, http.port), ("proxy.local".to_owned(), 8080));
        let socks = upstream_proxy("socks5://proxy.local:1080").expect("parses");
        assert!(!socks.http);
        assert_eq!((socks.host, socks.port), ("proxy.local".to_owned(), 1080));
        let h = upstream_proxy("socks5h://proxy.local:1080").expect("parses");
        assert!(!h.http);
        for bad in [
            "",
            "proxy.local:8080",
            "gopher://proxy.local:70",
            "http://proxy.local",
            "http://proxy.local:99999",
            "http://proxy.local:80/extra",
            "http://user:pass@proxy.local:8080",
        ] {
            assert!(upstream_proxy(bad).is_none(), "{bad:?} refuses");
        }
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
            upstream: None,
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

    /// A name answers with more than one address, and the first the resolver
    /// lists is not a promise: the edge is dialed on the family that answers,
    /// which is what a runner behind a resolver that prefers v6 needs when the
    /// edge listens on v4 only. `localhost` answers v6 first on both runners,
    /// so a v4 listener is exactly the case the first address cannot serve.
    #[test]
    fn the_edge_is_dialed_on_the_address_that_answers_not_the_first_one() {
        let (roots, _server) = minted(b"tls");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds on v4");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            drop(stream);
            seen_tx.send(()).expect("reports");
        });
        // No address named: the name is what dials, and the family it answers
        // on is what is connected to.
        let dial = FoxyDial {
            host: "localhost".to_owned(),
            port,
            address: None,
            carrier: Carrier::H1,
            upstream: None,
            roots,
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        };
        let stream = tcp(&dial).expect("dials an address the name answers on");
        assert_eq!(
            stream.peer_addr().ok(),
            Some(SocketAddr::from(([127, 0, 0, 1], port))),
            "the dial reached the address that answers, not the first one listed"
        );
        seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("the edge accepted");
    }

    /// An address the config names is the dial it named: a name that answers
    /// does not get it, because that address is the poison-proof dial and the
    /// TLS name is verified against it.
    #[test]
    fn an_address_the_config_names_is_the_dial_it_named() {
        let (roots, _server) = minted(b"tls");
        let dial = FoxyDial {
            host: "localhost".to_owned(),
            port: 443,
            address: Some(SocketAddr::from(([127, 0, 0, 1], 1))),
            carrier: Carrier::H1,
            upstream: None,
            roots,
            pins: foxy::pin::Pins::default(),
            pass: Pass {
                token: "the-pass".to_owned(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
        };
        assert!(
            tcp(&dial).is_err(),
            "the named address is the only one dialed"
        );
    }

    fn round_trip(tunnel: &mut Tunnel) {
        tunnel.write_all(PAYLOAD).expect("writes");
        tunnel.flush().expect("flushes");
        let mut back = vec![0u8; PAYLOAD.len()];
        tunnel.read_exact(&mut back).expect("reads");
        assert_eq!(back, PAYLOAD);
    }

    /// A dial whose hop is the only way to the edge: the name the CONNECT
    /// carries is not the name anything resolves, so a dial that reaches the
    /// edge has gone through the hop.
    fn upstream_dial(proxy: UpstreamProxy, edge: Option<SocketAddr>) -> FoxyDial {
        FoxyDial {
            host: "edge.test".to_owned(),
            port: 2499,
            address: edge,
            carrier: Carrier::H1,
            upstream: Some(proxy),
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

    fn read_head(stream: &mut dyn std::io::Read) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("reads a head");
            head.push(byte[0]);
        }
        String::from_utf8(head).expect("ascii")
    }

    #[test]
    fn tcp_through_an_http_upstream_sends_connect_and_carries_bytes() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).expect("reads");
            stream.write_all(&buf[..read]).expect("echoes");
            head
        });
        let proxy = upstream_proxy(&format!("http://127.0.0.1:{port}")).expect("parses");
        let mut stream = tcp(&upstream_dial(proxy, None)).expect("chains");
        stream.write_all(PAYLOAD).expect("writes");
        let mut back = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut back).expect("echoes");
        assert_eq!(back, PAYLOAD);
        assert_eq!(
            seen.join().expect("joins"),
            "CONNECT edge.test:2499 HTTP/1.1\r\nHost: edge.test:2499\r\n\r\n"
        );
    }

    #[test]
    fn tcp_through_a_socks5_upstream_shakes_hands_and_carries_bytes() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let seen = std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            stream.write_all(&[5, 0]).expect("selects");
            let mut request = vec![0u8; 16];
            read_exact(&mut stream, &mut request).expect("connects");
            let mut want = vec![5, 1, 0, 3, 9];
            want.extend_from_slice(b"edge.test");
            want.extend_from_slice(&2499u16.to_be_bytes());
            assert_eq!(request, want);
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("grants");
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).expect("reads");
            stream.write_all(&buf[..read]).expect("echoes");
            greet.to_vec()
        });
        let proxy = upstream_proxy(&format!("socks5://127.0.0.1:{port}")).expect("parses");
        let mut stream = tcp(&upstream_dial(proxy, None)).expect("chains");
        stream.write_all(PAYLOAD).expect("writes");
        let mut back = vec![0u8; PAYLOAD.len()];
        stream.read_exact(&mut back).expect("echoes");
        assert_eq!(back, PAYLOAD);
        assert_eq!(seen.join().expect("joins"), vec![5, 1, 0]);
    }

    /// A hop that refuses is a failed dial and not a fallback: the edge is
    /// never dialed around a proxy the config named, because a lane that
    /// bypasses its configured hop is a leak.
    #[test]
    fn a_refused_upstream_is_a_failed_dial_and_not_a_direct_one() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = proxy.local_addr().expect("addr").port();
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let edge_port = listener.local_addr().expect("addr").port();
        let (dialed_tx, dialed_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                drop(stream);
                let _ = dialed_tx.send(());
            }
        });
        std::thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            stream.write_all(&[5, 0]).expect("selects");
            let mut request = vec![0u8; 15];
            read_exact(&mut stream, &mut request).expect("connects");
            // A general failure, which is how a hop says it will not connect.
            stream
                .write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0])
                .expect("refuses");
        });
        let proxy = upstream_proxy(&format!("socks5://127.0.0.1:{port}")).expect("parses");
        let edge = Some(SocketAddr::from(([127, 0, 0, 1], edge_port)));
        assert!(
            tcp(&upstream_dial(proxy, edge)).is_err(),
            "a refused hop is a failed dial"
        );
        assert!(
            dialed_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "the edge on port {edge_port} was dialed around the hop"
        );
    }

    #[test]
    fn h1_through_an_http_upstream_reaches_its_edge() {
        let (roots, server) = minted(b"http/1.1");
        let edge = TcpListener::bind("127.0.0.1:0").expect("binds");
        let edge_port = edge.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (stream, _) = edge.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let request = read_head(&mut tls);
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
        let proxy = TcpListener::bind("127.0.0.1:0").expect("binds");
        let proxy_port = proxy.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut downstream, _) = proxy.accept().expect("accepts");
            downstream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let head = read_head(&mut downstream);
            assert_eq!(
                head,
                format!(
                    "CONNECT localhost:{edge_port} HTTP/1.1\r\nHost: localhost:{edge_port}\r\n\r\n"
                )
            );
            downstream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("answers");
            let edge = TcpStream::connect(("127.0.0.1", edge_port)).expect("dials");
            let (mut up_read, mut up_write) = (edge.try_clone().expect("clones"), edge);
            let mut down = downstream.try_clone().expect("clones");
            let pipe = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(read) = down.read(&mut buf) {
                    if read == 0 || up_write.write_all(&buf[..read]).is_err() {
                        break;
                    }
                }
            });
            let mut buf = [0u8; 8192];
            while let Ok(read) = up_read.read(&mut buf) {
                if read == 0 || downstream.write_all(&buf[..read]).is_err() {
                    break;
                }
            }
            pipe.join().expect("joins");
        });
        let mut dial = dial_for(roots, edge_port, Carrier::H1, foxy::pin::Pins::default());
        dial.upstream = upstream_proxy(&format!("http://127.0.0.1:{proxy_port}"));
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        round_trip(&mut tunnel);
    }

    /// A SOCKS5 hop for the QUIC carrier: a TCP side that answers `UDP
    /// ASSOCIATE` with the address of its own relay socket, and a relay socket
    /// that carries datagrams between the lane and the edge with the header the
    /// association frames them in. Both halves write that header themselves, so
    /// the framing is witnessed by something other than the code it checks.
    fn socks_relay(edge_port: u16) -> UpstreamProxy {
        let control = TcpListener::bind("127.0.0.1:0").expect("binds");
        let proxy_port = control.local_addr().expect("addr").port();
        let relay = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let relay_addr = relay.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut stream, _) = control.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("times out");
            let mut greet = [0u8; 3];
            read_exact(&mut stream, &mut greet).expect("greets");
            assert_eq!(greet, [5, 1, 0], "no authentication offered");
            stream.write_all(&[5, 0]).expect("selects");
            let mut ask = [0u8; 10];
            read_exact(&mut stream, &mut ask).expect("associates");
            assert_eq!(&ask[..4], [5, 3, 0, 1], "a UDP association, naming nothing");
            let octets = match relay_addr.ip() {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            };
            let mut grant = vec![5, 0, 0, 1];
            grant.extend_from_slice(&octets);
            grant.extend_from_slice(&relay_addr.port().to_be_bytes());
            stream.write_all(&grant).expect("grants");
            // The association lives as long as the control connection does, so
            // this thread holds it until the lane is done with the hop.
            let mut sink = [0u8; 64];
            let _ = stream.read(&mut sink);
        });
        std::thread::spawn(move || {
            relay
                .set_read_timeout(Some(Duration::from_secs(60)))
                .expect("times out");
            let mut lane: Option<SocketAddr> = None;
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = relay.recv_from(&mut buf) {
                match lane {
                    // The lane's first datagram is the one that says so: the
                    // association names no destination, so nothing arrives from
                    // the edge until the lane has spoken.
                    None => lane = Some(from),
                    Some(lane) if lane == from => {
                        if n < 10 || buf[2] != 0 || buf[3] != 1 {
                            continue;
                        }
                        let ip = [buf[4], buf[5], buf[6], buf[7]];
                        let port = u16::from_be_bytes([buf[8], buf[9]]);
                        let _ = relay.send_to(&buf[10..n], SocketAddr::from((ip, port)));
                    }
                    Some(lane) => {
                        // The edge's answer, framed for the lane the way the
                        // lane's own header framed the request.
                        let mut framed = vec![0, 0, 0, 1, 127, 0, 0, 1];
                        framed.extend_from_slice(&edge_port.to_be_bytes());
                        framed.extend_from_slice(&buf[..n]);
                        let _ = relay.send_to(&framed, lane);
                    }
                }
            }
        });
        upstream_proxy(&format!("socks5://127.0.0.1:{proxy_port}")).expect("parses")
    }

    #[test]
    fn the_quic_carrier_rides_a_socks5_upstream_and_carries_the_bytes() {
        let (roots, server) = minted(b"h3");
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let edge_port = sock.local_addr().expect("addr").port();
        let cert = crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE");
        let key = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, uni_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(sock, cert, key, seen_tx, uni_tx);
        let proxy = socks_relay(edge_port);
        let (client, peer, local) = crate::quic::udp_to_server("127.0.0.1", edge_port)
            .expect("a socket the edge can be addressed from");
        let (relay_control, relay) = associate_udp(&proxy).expect("associates");
        let quic = crate::quic::direct_stream_on(
            crate::quic::Datagram::relayed(client, relay, relay_control),
            peer,
            local,
            "localhost",
            &roots,
        )
        .expect("a connection through the hop");
        let mut dial = dial_for(roots, edge_port, Carrier::H3, foxy::pin::Pins::default());
        dial.upstream = Some(proxy);
        let mut tunnel = Tunnel::open(&dial, "example.com:443", Some(quic)).expect("opens");
        let block = seen_rx
            // The edge's own budget is a minute, so a lane that needs longer
            // than that is a hang and not a slow machine.
            .recv_timeout(Duration::from_secs(60))
            .expect("block");
        let mut want = Vec::new();
        hpack::qpack_connect("example.com:443", "the-pass", &mut want);
        assert_eq!(block, want, "the edge read the block the lane wrote");
        // The opening arrived as well as the request: a relay that dropped the
        // control stream would still carry the request stream, because both
        // travel the same datagrams.
        let uni = uni_rx.recv_timeout(Duration::from_secs(60)).expect("uni");
        let stream = |id| {
            uni.iter()
                .find(|(known, _, _)| *known == id)
                .unwrap_or_else(|| panic!("stream {id} opened"))
        };
        let (_, control, control_fin) = stream(2);
        let mut at = 0usize;
        assert_eq!(control.first(), Some(&0x00), "a control stream type");
        at += 1;
        assert_eq!(control.get(at), Some(&0x04), "one SETTINGS frame");
        at += 1;
        let len = frames::quic_read(control, &mut at).expect("a length") as usize;
        assert_eq!(
            control.len(),
            at + len,
            "a complete SETTINGS, no truncation"
        );
        assert!(!control_fin, "control stays open");
        for (id, first) in [(6u64, 0x02u8), (10, 0x03)] {
            let (_, bytes, fin) = stream(id);
            assert_eq!(bytes.as_slice(), &[first], "qpack stream {id}");
            assert!(!fin, "qpack stream {id} stays open");
        }
        round_trip(&mut tunnel);
        edge.join().expect("joins");
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
        const BIG: usize = 16 * 1024;
        const STEP: usize = 1024;
        let (roots, server) = minted(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, _seen_rx) = std::sync::mpsc::channel();
        let _edge = h2_edge(listener, server, seen_tx);
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut tunnel = Tunnel::open(&dial, "example.com:443", None).expect("opens");
        tunnel
            .set_read_quantum(Duration::from_millis(5))
            .expect("bounds one read");
        let lane = std::sync::Arc::new(std::sync::Mutex::new(tunnel));
        let sent: Vec<u8> = (0..BIG).map(|i| (i % 251) as u8).collect();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let forward = std::sync::Arc::clone(&lane);
        let chunk = sent.clone();
        std::thread::spawn(move || {
            let mut at = 0usize;
            while at < chunk.len() {
                let end = (at + STEP).min(chunk.len());
                match forward.lock().expect("locks").write(&chunk[at..end]) {
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
                    ) =>
                {
                    // The lane is shared with the writer, so an idle poll
                    // sleeps instead of re-locking: a tight poll loop starves
                    // the writer behind the same mutex under load.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("both directions flow at once");
        assert_eq!(back, sent);
    }

    #[test]
    fn the_http2_carrier_assembles_a_status_split_over_continuation() {
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
            let mut head = vec![0u8; frames::PREFACE.len()];
            read_exact(&mut tls, &mut head).expect("reads the preface");
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
                    frames::H2Event::Headers { .. } => {
                        // The status in two fragments: an indexed field the
                        // lane skips, then the indexed 200 on a CONTINUATION.
                        let mut first = Vec::new();
                        h2_frame(frames::HEADERS, 0x0, 1, &[0x80 | 0x21], &mut first);
                        tls.write_all(&first).expect("sends the fragment");
                        let mut rest = Vec::new();
                        h2_frame(frames::CONTINUATION, 0x4, 1, &[0x88], &mut rest);
                        tls.write_all(&rest).expect("sends the tail");
                        return;
                    }
                    _ => {}
                }
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        assert!(Tunnel::open(&dial, "example.com:443", None).is_ok());
        edge.join().expect("joins");
    }

    #[test]
    fn the_masque_carrier_opens_connect_udp_and_echoes_a_datagram() {
        let (roots, server) = minted(b"h2");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let edge = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(20)))
                .expect("times out");
            let mut tls =
                ferrox_core::tls::RustlsServerProvider::accept(&server, stream).expect("accepts");
            tls.handshake().expect("handshakes");
            let mut head = vec![0u8; frames::PREFACE.len()];
            read_exact(&mut tls, &mut head).expect("reads the preface");
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
                        seen_tx.send(block.to_vec()).expect("reports the block");
                        let mut out = Vec::new();
                        h2_frame(frames::HEADERS, 0x5, 1, &[0x88], &mut out);
                        tls.write_all(&out).expect("answers");
                        break;
                    }
                    _ => {}
                }
            }
            let mut stream = Vec::new();
            loop {
                let mut header = [0u8; frames::H2_HEADER];
                read_exact(&mut tls, &mut header).expect("reads a datagram frame");
                let frame = frames::H2Frame::parse(&header).expect("parses");
                let mut payload = vec![0u8; frame.length as usize];
                read_exact(&mut tls, &mut payload).expect("reads a datagram");
                if frame.kind != frames::DATA {
                    continue;
                }
                stream.extend_from_slice(&payload);
                if let Some((_, datagram)) = masque::datagram_split(&stream) {
                    let mut echo = Vec::new();
                    masque::datagram_encode(datagram, &mut echo);
                    let mut out = Vec::new();
                    h2_frame(frames::DATA, 0, 1, &echo, &mut out);
                    tls.write_all(&out).expect("echoes");
                    return;
                }
            }
        });
        let dial = dial_for(roots, port, Carrier::H2, foxy::pin::Pins::default());
        let mut lane = open_udp(&dial, "example.com", 443).expect("opens");
        let block = seen_rx
            .recv_timeout(Duration::from_secs(20))
            .expect("block");
        let text = String::from_utf8_lossy(&block);
        for field in [
            "connect-udp",
            "/.well-known/masque/udp/example.com/443/",
            "Bearer the-pass",
        ] {
            assert!(text.contains(field), "missing {field}");
        }
        lane.write_datagram(b"hello udp").expect("writes");
        lane.flush().expect("flushes");
        let mut back = [0u8; 64];
        let mut at = 0usize;
        while at < b"hello udp".len() {
            match lane.read_datagram(&mut back[at..]) {
                Ok(0) => panic!("the echo ended early"),
                Ok(read) => at += read,
                Err(error) => panic!("the echo failed: {error}"),
            }
        }
        assert_eq!(&back[..at], b"hello udp");
        edge.join().expect("joins");
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
        sock: crate::quic::Datagram,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        seen: std::sync::mpsc::Sender<Vec<u8>>,
        uni: std::sync::mpsc::Sender<Vec<(u64, Vec<u8>, bool)>>,
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
            // The client's unidirectional streams, id plus bytes plus whether
            // the lane closed one: control must arrive whole and stay open.
            let mut uni_streams: Vec<(u64, Vec<u8>, bool)> = Vec::new();
            let uni_ready = |streams: &[(u64, Vec<u8>, bool)]| {
                [2u64, 6, 10].iter().all(|want| {
                    streams
                        .iter()
                        .any(|(id, bytes, _)| id == want && !bytes.is_empty())
                })
            };
            while request.is_none() || !uni_ready(&uni_streams) {
                assert!(std::time::Instant::now() < deadline, "the request arrives");
                let Some((n, from)) = crate::quic::server_poll(&sock, &mut buf) else {
                    crate::quic::server_idle(&mut conn, &sock, &mut out);
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                let ids: Vec<u64> = conn.readable().collect();
                conn.recv(&mut buf[..n], info).expect("drives");
                for id in ids {
                    if id % 4 == 2 {
                        drain_uni(&mut conn, id, &mut uni_streams);
                        continue;
                    }
                    // The control stream is unidirectional and the request is
                    // not, so the stream id itself tells them apart.
                    if id % 4 != 0 {
                        continue;
                    }
                    let piece = drain(&mut conn, id);
                    if !piece.is_empty() {
                        request = Some((id, piece));
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    let _ = sock.send_to(&out[..written], info.to);
                }
            }
            let _ = uni.send(uni_streams);
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
            echo_stream(&sock, local, &mut conn, &mut buf, &mut out, stream);
        })
    }

    /// Echoes one request stream's DATA payloads until the lane's whole
    /// payload has come back: the tunnel half of the loopback proof.
    fn echo_stream(
        sock: &crate::quic::Datagram,
        local: SocketAddr,
        conn: &mut quiche::Connection,
        buf: &mut [u8; 1350],
        out: &mut [u8; 1350],
        stream: u64,
    ) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut received: Vec<u8> = Vec::new();
        let mut sent = 0usize;
        while sent < PAYLOAD.len() {
            assert!(std::time::Instant::now() < deadline, "the tunnel echoes");
            if let Some((n, from)) = crate::quic::server_poll(sock, &mut buf[..]) {
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let piece = drain(&mut *conn, stream);
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
            while let Ok((written, info)) = conn.send(&mut out[..]) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        }
    }

    /// One unidirectional stream's bytes plus whether it has closed, merged
    /// into the snapshot the test asserts the lane's opening against.
    fn drain_uni(conn: &mut quiche::Connection, id: u64, streams: &mut Vec<(u64, Vec<u8>, bool)>) {
        let mut chunk = [0u8; 8192];
        loop {
            match conn.stream_recv(id, &mut chunk) {
                Ok((0, _)) | Err(_) => break,
                Ok((n, fin)) => match streams.iter_mut().find(|(known, _, _)| *known == id) {
                    Some((_, bytes, closed)) => {
                        bytes.extend_from_slice(&chunk[..n]);
                        *closed = *closed || fin;
                    }
                    None => streams.push((id, chunk[..n].to_vec(), fin)),
                },
            }
        }
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
        let sock =
            crate::quic::Datagram::plain(crate::quic::bind_datagram("127.0.0.1:0").expect("binds"));
        let port = sock.local_addr().expect("addr").port();
        let key_pem = crate::quic::der_to_pem(&server.key_der, "PRIVATE KEY");
        let (seen_tx, seen_rx) = std::sync::mpsc::channel();
        let (uni_tx, uni_rx) = std::sync::mpsc::channel();
        let edge = h3_edge(
            sock,
            crate::quic::der_to_pem(&server.cert_chain[0], "CERTIFICATE"),
            key_pem,
            seen_tx,
            uni_tx,
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
        let uni = uni_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("uni streams");
        let stream = |id| {
            uni.iter()
                .find(|(known, _, _)| *known == id)
                .unwrap_or_else(|| panic!("stream {id} opened"))
        };
        let (_, control, control_fin) = stream(2);
        let mut at = 0usize;
        assert_eq!(control.first(), Some(&0x00), "a control stream type");
        at += 1;
        assert_eq!(control.get(at), Some(&0x04), "one SETTINGS frame");
        at += 1;
        let len = frames::quic_read(control, &mut at).expect("a length") as usize;
        assert_eq!(
            control.len(),
            at + len,
            "a complete SETTINGS, no truncation"
        );
        assert!(!control_fin, "control stays open");
        for (id, first) in [(6u64, 0x02u8), (10, 0x03)] {
            let (_, bytes, fin) = stream(id);
            assert_eq!(bytes.as_slice(), &[first], "qpack stream {id}");
            assert!(!fin, "qpack stream {id} stays open");
        }
        round_trip(&mut tunnel);
        edge.join().expect("joins");
    }
}
