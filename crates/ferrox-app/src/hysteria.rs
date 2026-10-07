use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use ferrox_core::foxy::frames;
use ferrox_core::hysteria;

const AUTH_STREAM: u64 = 0;

const FIRST_FLOW_STREAM: u64 = 4;

const HEAD_CAP: usize = 16 * 1024;

const ROUTE_POLL: Duration = Duration::from_millis(100);

const STREAM_POLL: Duration = Duration::from_millis(5);

const SCID_LEN: usize = 16;

// Datagram queue depth per QUIC connection, each way.
const DGRAM_QUEUE: usize = 128;

// Largest QUIC datagram this tree sends, mirroring the reference's
// `MaxDatagramFrameSize`; larger UDP payloads fragment, never silently drop.
const DGRAM_MAX: usize = 1200;

// Idle UDP sessions are reaped after this, mirroring the reference default.
const UDP_IDLE: Duration = Duration::from_secs(60);

// Datagrams queued per session id; fuller sessions drop, never grow.
const UDP_CHAN: usize = 64;

pub(crate) struct Dial {
    pub(crate) host: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) config: hysteria::Config,
    pub(crate) roots: Option<Vec<Vec<u8>>>,
}

#[derive(Clone)]
pub(crate) struct Session {
    shared: Arc<Mutex<quiche::Connection>>,
    sock: Arc<UdpSocket>,
    local: SocketAddr,
}

fn send_all(session: &Session, stream: u64, mut buf: &[u8], fin: bool) -> bool {
    let deadline = Instant::now() + crate::quic::SEND_WAIT;
    loop {
        let last = buf.is_empty();
        if last && !fin {
            return true;
        }
        let Ok(mut conn) = session.shared.lock() else {
            return false;
        };
        match conn.stream_send(stream, buf, fin && last) {
            Ok(written) => {
                buf = &buf[written..];
                crate::quic::flush_egress(&mut conn, &session.sock);
                if buf.is_empty() && (!fin || last) {
                    return true;
                }
                if written == 0 && Instant::now() >= deadline {
                    return false;
                }
            }
            Err(quiche::Error::Done) => {
                if Instant::now() >= deadline {
                    return false;
                }
            }
            Err(_) => return false,
        }
        drop(conn);
        std::thread::sleep(STREAM_POLL);
    }
}

fn read_headers_block(session: &Session, stream: u64, deadline: Instant) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(128);
    let mut chunk = [0u8; 4096];
    loop {
        if head.len() >= HEAD_CAP || Instant::now() >= deadline {
            return None;
        }
        let mut at = 0usize;
        if let Some(frame) = frames::h3_frame(&head, &mut at) {
            if frame.kind != frames::H3_HEADERS {
                return None;
            }
            if let Some(body) = head.get(at..at + frame.length as usize) {
                return Some(body.to_vec());
            }
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, &mut chunk) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&chunk[..n]);
        } else {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            crate::quic::pump_once(&mut conn, &session.sock, session.local, STREAM_POLL);
        }
    }
}

fn control_settings(session: &Session) -> bool {
    let mut settings = Vec::new();
    frames::quic_varint(&mut settings, 0x04);
    frames::quic_varint(&mut settings, 0);
    send_all(session, 2, &settings, true)
}

fn post_auth(session: &Session, host: &str, auth: &str) -> bool {
    let mut block = Vec::with_capacity(64 + host.len() + auth.len());
    hysteria::build_auth_request(host, auth, &mut block);
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    if !send_all(session, AUTH_STREAM, &frame, true) {
        return false;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let Some(body) = read_headers_block(session, AUTH_STREAM, deadline) else {
        return false;
    };
    hysteria::verify_auth_response(&body)
}

pub(crate) fn connect(dial: &Dial) -> Option<Session> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, peer, local) = crate::quic::udp_to_server(&dial.address, dial.port)?;
    let mut scid = [0u8; SCID_LEN];
    getrandom::getrandom(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = crate::quic::quiche_config(roots, Some(dial.config.cc.quiche_name()))?;
    config.enable_dgram(true, DGRAM_QUEUE, DGRAM_QUEUE);
    let Ok(mut conn) = quiche::connect(Some(&dial.host), &cid, local, peer, &mut config) else {
        return None;
    };
    crate::quic::drive_handshake(&mut conn, &sock, local)?;
    let session = Session {
        shared: Arc::new(Mutex::new(conn)),
        sock: Arc::new(sock),
        local,
    };
    if !control_settings(&session) {
        return None;
    }
    if !post_auth(&session, &dial.host, &dial.config.auth) {
        return None;
    }
    Some(session)
}

// The target as the request carries it: `host:port` text, never a header.
pub(crate) fn addr_text(target: &SocketAddr) -> String {
    target.to_string()
}

// Parses request address text back to a diallable target; domains resolve
// here, on the app side, because the framing layer resolves nothing.
pub(crate) fn parse_addr_text(text: &str) -> Option<SocketAddr> {
    let (host, port) = text.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse() {
        return Some(SocketAddr::new(ip, port));
    }
    (host, port).to_socket_addrs().ok()?.next()
}

fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let span = max - min + 1;
    let mut one = [0u8; 1];
    getrandom::getrandom(&mut one).ok();
    let len = min + usize::from(one[0]) % span;
    let mut padding = vec![0u8; len];
    getrandom::getrandom(&mut padding).ok();
    padding
}

fn recv_response(session: &Session, stream: u64, deadline: Instant) -> Option<bool> {
    let mut head = Vec::with_capacity(256);
    let mut chunk = [0u8; 1024];
    loop {
        if head.len() >= hysteria::TCP_MSG_MAX + hysteria::TCP_PAD_MAX + 16
            || Instant::now() >= deadline
        {
            return None;
        }
        if let Some((ok, _, _)) = hysteria::decode_tcp_response(&head) {
            return Some(ok);
        }
        let read = {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            match conn.stream_recv(stream, &mut chunk) {
                Ok((n, _)) => Some(n),
                Err(quiche::Error::Done) => None,
                Err(_) => return None,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&chunk[..n]);
        } else {
            let Ok(mut conn) = session.shared.lock() else {
                return None;
            };
            crate::quic::pump_once(&mut conn, &session.sock, session.local, STREAM_POLL);
        }
    }
}

pub(crate) fn open_flow(session: &Session, target: &SocketAddr) -> Option<Flow> {
    let text = addr_text(target);
    let padding = random_padding(hysteria::REQ_PAD_MIN, hysteria::REQ_PAD_MAX);
    let mut request = Vec::with_capacity(2 + text.len() + padding.len() + 16);
    hysteria::tcp_prefix(&mut request);
    if !hysteria::encode_tcp_request(&text, &padding, &mut request) {
        return None;
    }
    if !send_all(session, FIRST_FLOW_STREAM, &request, false) {
        return None;
    }
    let deadline = Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    if recv_response(session, FIRST_FLOW_STREAM, deadline) != Some(true) {
        return None;
    }
    Some(Flow {
        session: session.clone(),
        stream: FIRST_FLOW_STREAM,
        backlog: Vec::new(),
        at: 0,
    })
}

// Dials the target itself: the request carries the address, so no inner
// protocol header exists and the identity the config names is not sent.
pub(crate) fn dial_direct(client: &TcpStream, dial: &Dial, target: &SocketAddr) {
    let Some(session) = connect(dial) else {
        return;
    };
    let Some(flow) = open_flow(&session, target) else {
        return;
    };
    relay(client, &flow);
}

// One UDP association: session ids demultiplex targets on one connection,
// packet ids group fragments. Replies are matched by session id only.
pub(crate) struct UdpLink {
    session: Session,
    next: u32,
    packet: u16,
    re: hysteria::Reassembler,
    re_session: u32,
}

pub(crate) fn connect_udp(dial: &Dial) -> Option<UdpLink> {
    connect(dial).map(|session| UdpLink {
        session,
        next: 1,
        packet: 1,
        re: hysteria::Reassembler::default(),
        re_session: 0,
    })
}

impl UdpLink {
    pub(crate) fn next_session(&mut self) -> u32 {
        let id = self.next;
        self.next = self.next.wrapping_add(1).max(1);
        id
    }

    // Sends one addressed payload, fragmenting past the datagram cap the way
    // the reference fragments on `DatagramTooLarge` instead of dropping.
    pub(crate) fn send(&mut self, session: u32, addr: &str, data: &[u8]) -> bool {
        if addr.is_empty() || addr.len() > hysteria::TCP_ADDR_MAX {
            return false;
        }
        let locked = self.session.shared.lock();
        let Ok(mut conn) = locked else {
            return false;
        };
        let cap = conn
            .dgram_max_writable_len()
            .unwrap_or(DGRAM_MAX)
            .min(DGRAM_MAX);
        let headroom = hysteria::UDP_HEAD_LEN + addr.len() + 8;
        if headroom >= cap {
            return false;
        }
        let per = cap - headroom;
        let count = data.len().div_ceil(per).clamp(1, 255);
        let number = if count == 1 {
            0
        } else {
            let id = self.packet;
            self.packet = self.packet.wrapping_add(1).max(1);
            id
        };
        for (frag, chunk) in data.chunks(per).enumerate() {
            let msg = hysteria::UdpMessage {
                session,
                packet: number,
                frag: frag as u8,
                count: count as u8,
                addr,
                data: chunk,
            };
            let mut wire = Vec::with_capacity(cap);
            if !hysteria::encode_udp_message(&msg, &mut wire) || wire.len() > cap {
                return false;
            }
            if conn.dgram_send(&wire).is_err() {
                return false;
            }
        }
        crate::quic::flush_egress(&mut conn, &self.session.sock);
        true
    }

    // Receives one reassembled payload with its session id, waiting to the
    // deadline; fragments for other sessions reset the reassembler.
    pub(crate) fn recv(&mut self, deadline: Instant) -> Option<(u32, Vec<u8>)> {
        let mut buf = [0u8; 1350];
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            let got = {
                let Ok(mut conn) = self.session.shared.lock() else {
                    return None;
                };
                conn.dgram_recv(&mut buf).ok()
            };
            if let Some(n) = got {
                if let Some(msg) = hysteria::decode_udp_message(&buf[..n]) {
                    if msg.session != self.re_session {
                        self.re = hysteria::Reassembler::default();
                        self.re_session = msg.session;
                    }
                    if let Some(data) = self.re.feed(&msg) {
                        return Some((msg.session, data));
                    }
                }
                continue;
            }
            let Ok(mut conn) = self.session.shared.lock() else {
                return None;
            };
            crate::quic::pump_once(
                &mut conn,
                &self.session.sock,
                self.session.local,
                STREAM_POLL,
            );
        }
    }
}

#[derive(Clone)]
pub(crate) struct Flow {
    session: Session,
    stream: u64,
    backlog: Vec<u8>,
    at: usize,
}

impl Flow {
    pub(crate) fn from_parts(
        shared: Arc<Mutex<quiche::Connection>>,
        sock: Arc<UdpSocket>,
        local: SocketAddr,
        stream: u64,
        backlog: Vec<u8>,
    ) -> Self {
        Self {
            session: Session {
                shared,
                sock,
                local,
            },
            stream,
            backlog,
            at: 0,
        }
    }

    fn close(&self) {
        if let Ok(mut conn) = self.session.shared.lock() {
            let _ = conn.stream_send(self.stream, &[], true);
            crate::quic::flush_egress(&mut conn, &self.session.sock);
        }
    }
}

fn broken() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::BrokenPipe)
}

impl Read for Flow {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.at < self.backlog.len() {
            let n = (self.backlog.len() - self.at).min(buf.len());
            buf[..n].copy_from_slice(&self.backlog[self.at..self.at + n]);
            self.at += n;
            return Ok(n);
        }
        loop {
            let read = {
                let Ok(mut conn) = self.session.shared.lock() else {
                    return Err(broken());
                };
                if conn.is_closed() {
                    return Ok(0);
                }
                match conn.stream_recv(self.stream, buf) {
                    Ok((n, _)) => Some(n),
                    Err(quiche::Error::Done) => None,
                    Err(_) => return Err(broken()),
                }
            };
            if let Some(n) = read {
                return Ok(n);
            }
            let Ok(mut conn) = self.session.shared.lock() else {
                return Err(broken());
            };
            crate::quic::pump_once(
                &mut conn,
                &self.session.sock,
                self.session.local,
                STREAM_POLL,
            );
        }
    }
}

impl Write for Flow {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if send_all(&self.session, self.stream, buf, false) {
            Ok(buf.len())
        } else {
            Err(broken())
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn relay(tcp: &TcpStream, flow: &Flow) {
    let Ok(tcp_read) = tcp.try_clone() else {
        return;
    };
    let Ok(mut tcp_write) = tcp.try_clone() else {
        return;
    };
    let up = flow.clone();
    let done = std::thread::spawn(move || {
        let mut tcp_read = tcp_read;
        let mut up = up;
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        up.close();
    });
    let mut back = flow.clone();
    let mut buf = vec![0u8; 16384];
    loop {
        match back.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tcp_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = tcp_write.shutdown(Shutdown::Write);
    let _ = done.join();
    flow.close();
}

pub(crate) fn server_config(
    cert_path: &str,
    key_path: &str,
    cc: hysteria::Congestion,
) -> Option<quiche::Config> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
    config.set_application_protos(&[crate::quic::ALPN]).ok()?;
    config.set_cc_algorithm_name(cc.quiche_name()).ok()?;
    config.enable_dgram(true, DGRAM_QUEUE, DGRAM_QUEUE);
    config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
    config.set_initial_max_data(crate::quic::MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
    config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
    config.load_cert_chain_from_pem_file(cert_path).ok()?;
    config.load_priv_key_from_pem_file(key_path).ok()?;
    Some(config)
}

pub(crate) type Serve = Arc<dyn Fn(Flow, SocketAddr) + Send + Sync>;

// What a UDP session hands the proxy: its destination text, a channel
// carrying the first reassembled payload ahead of the rest, and a flow for
// the replies.
pub(crate) struct UdpCtx {
    pub(crate) addr: String,
    pub(crate) rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) flow: UdpFlow,
}

pub(crate) type ServeUdp = Arc<dyn Fn(UdpCtx) + Send + Sync>;

#[derive(Clone)]
pub(crate) struct UdpFlow {
    session: Session,
    id: u32,
}

impl UdpFlow {
    // Replies with the session id this flow was opened under, fragmenting past
    // the datagram cap; unfragmented replies carry packet zero like the
    // reference server's.
    pub(crate) fn send(&self, addr: &str, data: &[u8]) -> bool {
        if addr.is_empty() || addr.len() > hysteria::TCP_ADDR_MAX {
            return false;
        }
        let Ok(mut conn) = self.session.shared.lock() else {
            return false;
        };
        let cap = conn
            .dgram_max_writable_len()
            .unwrap_or(DGRAM_MAX)
            .min(DGRAM_MAX);
        let headroom = hysteria::UDP_HEAD_LEN + addr.len() + 8;
        if headroom >= cap {
            return false;
        }
        let per = cap - headroom;
        let count = data.len().div_ceil(per).clamp(1, 255);
        let number = if count == 1 {
            0
        } else {
            let mut id = [0u8; 2];
            getrandom::getrandom(&mut id).ok();
            u16::from_be_bytes(id).max(1)
        };
        for (frag, chunk) in data.chunks(per).enumerate() {
            let msg = hysteria::UdpMessage {
                session: self.id,
                packet: number,
                frag: frag as u8,
                count: count as u8,
                addr,
                data: chunk,
            };
            let mut wire = Vec::with_capacity(cap);
            if !hysteria::encode_udp_message(&msg, &mut wire) || wire.len() > cap {
                return false;
            }
            if conn.dgram_send(&wire).is_err() {
                return false;
            }
        }
        crate::quic::flush_egress(&mut conn, &self.session.sock);
        true
    }
}

struct UdpEntry {
    tx: Option<mpsc::SyncSender<Vec<u8>>>,
    re: hysteria::Reassembler,
    re_session: u32,
    last: Instant,
}

struct Inbound {
    conn: Arc<Mutex<quiche::Connection>>,
    client_cid: Vec<u8>,
    authed: bool,
    auth_buf: Vec<u8>,
    served: HashSet<u64>,
    udp: HashMap<u32, UdpEntry>,
}

fn answer_auth(conn: &mut quiche::Connection, ok: bool) -> bool {
    let mut block = Vec::with_capacity(32);
    if ok {
        hysteria::build_auth_response(&mut block);
    } else {
        ferrox_core::foxy::hpack::qpack_literal_many(&[(":status", "404")], &mut block);
    }
    let mut frame = Vec::with_capacity(16 + block.len());
    frames::quic_varint(&mut frame, frames::H3_HEADERS);
    frames::quic_varint(&mut frame, block.len() as u64);
    frame.extend_from_slice(&block);
    conn.stream_send(AUTH_STREAM, &frame, true).is_ok()
}

fn drain_settings(conn: &mut quiche::Connection) {
    let mut junk = [0u8; 128];
    while let Ok((n, _)) = conn.stream_recv(2, &mut junk) {
        if n == 0 {
            break;
        }
    }
}

fn answer_request(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<UdpSocket>,
    stream: u64,
    ok: bool,
) {
    let padding = random_padding(hysteria::RESP_PAD_MIN, hysteria::RESP_PAD_MAX);
    let mut out = Vec::with_capacity(256 + padding.len());
    if !hysteria::encode_tcp_response(ok, "", &padding, &mut out) {
        return;
    }
    if let Ok(mut conn) = shared.lock() {
        let _ = conn.stream_send(stream, &out, false);
        crate::quic::flush_egress(&mut conn, sock);
    }
}

fn serve_stream(
    shared: &Arc<Mutex<quiche::Connection>>,
    sock: &Arc<UdpSocket>,
    local: SocketAddr,
    stream: u64,
    serve: &Serve,
) {
    let mut head = Vec::with_capacity(8);
    let mut chunk = [0u8; 64];
    let prefix = loop {
        if head.len() >= 8 {
            return;
        }
        let read = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            match conn.stream_recv(stream, &mut chunk) {
                Ok((0, _)) | Err(quiche::Error::Done) => None,
                Ok((n, _)) => Some(n),
                Err(_) => return,
            }
        };
        if let Some(n) = read {
            head.extend_from_slice(&chunk[..n]);
        } else {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.is_closed() {
                return;
            }
            crate::quic::pump_once(&mut conn, sock, local, STREAM_POLL);
            continue;
        }
        if head.is_empty() {
            continue;
        }
        let want = 1usize << usize::from(head[0] >> 6);
        if head.len() >= want {
            let Some(consumed) = hysteria::read_tcp_prefix(&head) else {
                return;
            };
            break consumed;
        }
    };
    let mut request = head[prefix..].to_vec();
    let mut piece = [0u8; 1024];
    let (addr, used) = loop {
        if request.len() > hysteria::TCP_ADDR_MAX + hysteria::TCP_PAD_MAX + 16 {
            return;
        }
        if let Some((addr, used)) = hysteria::decode_tcp_request(&request) {
            break (addr.to_owned(), used);
        }
        let read = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            match conn.stream_recv(stream, &mut piece) {
                Ok((0, _)) | Err(quiche::Error::Done) => None,
                Ok((n, _)) => Some(n),
                Err(_) => return,
            }
        };
        if let Some(n) = read {
            request.extend_from_slice(&piece[..n]);
        } else {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.is_closed() {
                return;
            }
            crate::quic::pump_once(&mut conn, sock, local, STREAM_POLL);
        }
    };
    let Some(target) = parse_addr_text(&addr) else {
        answer_request(shared, sock, stream, false);
        return;
    };
    answer_request(shared, sock, stream, true);
    let backlog = request[used..].to_vec();
    serve(
        Flow::from_parts(Arc::clone(shared), Arc::clone(sock), local, stream, backlog),
        target,
    );
}

struct Router<'a> {
    sock: Arc<UdpSocket>,
    local: SocketAddr,
    out: [u8; 1350],
    config: &'a hysteria::Config,
    serve: &'a Serve,
    serve_udp: &'a ServeUdp,
    routes: HashMap<Vec<u8>, Inbound>,
}

fn flush(sock: &UdpSocket, conn: &mut quiche::Connection, out: &mut [u8; 1350]) {
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

fn auth_exchange(
    sock: &UdpSocket,
    out: &mut [u8; 1350],
    conn: &mut quiche::Connection,
    config: &hysteria::Config,
    inbound: &mut Inbound,
) -> Option<bool> {
    let mut chunk = [0u8; 4096];
    loop {
        match conn.stream_recv(AUTH_STREAM, &mut chunk) {
            Ok((0, _)) | Err(_) => break,
            Ok((n, _)) => inbound.auth_buf.extend_from_slice(&chunk[..n]),
        }
    }
    if inbound.auth_buf.len() >= HEAD_CAP {
        return Some(false);
    }
    let mut at = 0usize;
    let ready = frames::h3_frame(&inbound.auth_buf, &mut at)
        .filter(|frame| frame.kind == frames::H3_HEADERS)
        .and_then(|frame| inbound.auth_buf.get(at..at + frame.length as usize))
        .map(<[u8]>::to_vec);
    let body = ready?;
    let ok = hysteria::verify_auth_request(&body, &config.auth);
    if !answer_auth(conn, ok) {
        return None;
    }
    flush(sock, conn, out);
    inbound.auth_buf.clear();
    inbound.authed = true;
    Some(ok)
}

impl Router<'_> {
    fn accept(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        template: &mut quiche::Config,
        client_cid: &[u8],
    ) {
        let mut scid = [0u8; SCID_LEN];
        if getrandom::getrandom(&mut scid).is_err() {
            return;
        }
        let cid = quiche::ConnectionId::from_ref(&scid);
        let Ok(mut conn) = quiche::accept(&cid, None, self.local, from, template) else {
            return;
        };
        let info = quiche::RecvInfo {
            from,
            to: self.local,
        };
        if conn.recv(packet, info).is_err() {
            return;
        }
        flush(&self.sock, &mut conn, &mut self.out);
        self.routes.insert(
            scid.to_vec(),
            Inbound {
                conn: Arc::new(Mutex::new(conn)),
                client_cid: client_cid.to_vec(),
                authed: false,
                auth_buf: Vec::new(),
                served: HashSet::new(),
                udp: HashMap::new(),
            },
        );
    }

    fn drive(&mut self, dcid: &[u8], packet: &mut [u8], from: SocketAddr) {
        let Self {
            routes,
            sock,
            out,
            config,
            serve,
            local,
            ..
        } = self;
        let Some(shared) = routes.get(dcid).map(|i| Arc::clone(&i.conn)) else {
            return;
        };
        let info = quiche::RecvInfo { from, to: *local };
        let spawn: Vec<u64> = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.recv(packet, info).is_err() {
                return;
            }
            flush(sock, &mut conn, out);
            if !conn.is_established() || conn.is_closed() {
                return;
            }
            drain_settings(&mut conn);
            let authed = routes.get(dcid).is_some_and(|i| i.authed);
            if !authed {
                let Some(inbound) = routes.get_mut(dcid) else {
                    return;
                };
                let Some(ok) = auth_exchange(sock, out, &mut conn, config, inbound) else {
                    return;
                };
                if !ok {
                    let _ = conn.close(false, 0, b"refused");
                    flush(sock, &mut conn, out);
                    return;
                }
                let mut settings = Vec::new();
                frames::quic_varint(&mut settings, 0x04);
                frames::quic_varint(&mut settings, 0);
                let _ = conn.stream_send(3, &settings, true);
                flush(sock, &mut conn, out);
            }
            conn.readable().collect()
        };
        let Some(inbound) = routes.get_mut(dcid) else {
            return;
        };
        for id in spawn {
            if id < FIRST_FLOW_STREAM || id % 4 != 0 || inbound.served.contains(&id) {
                continue;
            }
            inbound.served.insert(id);
            let thread_shared = Arc::clone(&shared);
            let thread_sock = Arc::clone(sock);
            let thread_serve = Arc::clone(serve);
            let local = *local;
            std::thread::spawn(move || {
                serve_stream(&thread_shared, &thread_sock, local, id, &thread_serve);
            });
        }
        self.ingest(dcid);
    }

    fn ingest(&mut self, dcid: &[u8]) {
        let Some(shared) = self.routes.get(dcid).map(|i| Arc::clone(&i.conn)) else {
            return;
        };
        let arrivals = {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            let mut wire = [0u8; 1350];
            let mut found = Vec::new();
            while let Ok(n) = conn.dgram_recv(&mut wire) {
                found.push(wire[..n].to_vec());
            }
            flush(&self.sock, &mut conn, &mut self.out);
            found
        };
        let now = Instant::now();
        for wire in &arrivals {
            let Some(msg) = hysteria::decode_udp_message(wire) else {
                continue;
            };
            let Some(inbound) = self.routes.get_mut(dcid) else {
                return;
            };
            let entry = inbound.udp.entry(msg.session).or_insert_with(|| UdpEntry {
                tx: None,
                re: hysteria::Reassembler::default(),
                re_session: msg.session,
                last: now,
            });
            if msg.session != entry.re_session {
                entry.re = hysteria::Reassembler::default();
                entry.re_session = msg.session;
            }
            entry.last = now;
            let Some(data) = entry.re.feed(&msg) else {
                continue;
            };
            if let Some(tx) = &entry.tx {
                let _ = tx.try_send(data);
                continue;
            }
            let (tx, rx) = mpsc::sync_channel(UDP_CHAN);
            let _ = tx.try_send(data);
            entry.tx = Some(tx);
            let flow = UdpFlow {
                session: Session {
                    shared: Arc::clone(&shared),
                    sock: Arc::clone(&self.sock),
                    local: self.local,
                },
                id: msg.session,
            };
            let udp = Arc::clone(self.serve_udp);
            let addr = msg.addr.to_owned();
            std::thread::spawn(move || {
                udp(UdpCtx { addr, rx, flow });
            });
        }
    }

    fn idle(&mut self) {
        let Self {
            routes, sock, out, ..
        } = self;
        let now = Instant::now();
        let dead: Vec<Vec<u8>> = routes
            .iter()
            .filter(|(_, inbound)| inbound.conn.lock().is_ok_and(|conn| conn.is_closed()))
            .map(|(id, _)| id.clone())
            .collect();
        for id in dead {
            routes.remove(&id);
        }
        for inbound in routes.values_mut() {
            inbound.udp.retain(|_, entry| now - entry.last < UDP_IDLE);
            let Ok(mut conn) = inbound.conn.lock() else {
                continue;
            };
            conn.on_timeout();
            flush(sock, &mut conn, out);
        }
    }
}

pub(crate) fn serve_loop(
    address: &str,
    config: &hysteria::Config,
    cert_path: &str,
    key_path: &str,
    serve: &Serve,
    serve_udp: &ServeUdp,
) {
    let Some(bound) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        return;
    };
    let Ok(sock) = UdpSocket::bind(bound) else {
        return;
    };
    let local = sock.local_addr().unwrap_or(bound);
    let Some(mut template) = server_config(cert_path, key_path, config.cc) else {
        return;
    };
    let mut router = Router {
        sock: Arc::new(sock),
        local,
        out: [0u8; 1350],
        config,
        serve,
        serve_udp,
        routes: HashMap::new(),
    };
    let mut buf = [0u8; 1350];
    loop {
        if router.sock.set_read_timeout(Some(ROUTE_POLL)).is_err() {
            return;
        }
        match router.sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let Ok(header) = quiche::Header::from_slice(&mut buf[..n], SCID_LEN) else {
                    continue;
                };
                if header.ty != quiche::Type::Short && header.version != quiche::PROTOCOL_VERSION {
                    continue;
                }
                let dcid = header.dcid.as_ref().to_vec();
                let peer_cid = header.scid.as_ref().to_vec();
                let initial = header.ty == quiche::Type::Initial;
                if initial {
                    if let Some(key) = router.routes.iter().find_map(|(key, inbound)| {
                        (inbound.client_cid == peer_cid).then(|| key.clone())
                    }) {
                        router.drive(&key, &mut buf[..n], from);
                    } else if !router.routes.contains_key(&dcid) {
                        router.accept(&mut buf[..n], from, &mut template, &peer_cid);
                    } else {
                        router.drive(&dcid, &mut buf[..n], from);
                    }
                } else {
                    router.drive(&dcid, &mut buf[..n], from);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                router.idle();
            }
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_refuses_without_a_chain_it_can_read() {
        let cc = hysteria::Congestion::Bbr;
        assert!(server_config("/nonexistent.crt", "/nonexistent.key", cc).is_none());
    }

    #[test]
    fn request_addresses_round_trip_through_text() {
        let target: SocketAddr = "198.51.100.7:53".parse().expect("parses");
        assert_eq!(parse_addr_text(&addr_text(&target)), Some(target));
        assert_eq!(addr_text(&target), "198.51.100.7:53");
        assert_eq!(parse_addr_text(""), None);
        assert_eq!(parse_addr_text("no-port"), None);
        assert_eq!(parse_addr_text("198.51.100.7:not-a-port"), None);
    }
}
