use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub(crate) struct QuicDial {
    pub(crate) id: [u8; 16],
    pub(crate) host: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) roots: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QuicServer {
    address: String,
    port: u16,
    host: String,
    roots: Option<Vec<Vec<u8>>>,
}

struct PooledState {
    sessions: HashMap<u64, TcpStream>,
    opening: HashSet<u64>,
    next_id: u64,
}

/// The shared connection one flow rides, its socket, the local address its
/// packets come from, and the bidirectional stream id this flow opened.
pub(crate) type PooledStream = (
    Arc<Mutex<quiche::Connection>>,
    Arc<UdpSocket>,
    SocketAddr,
    u64,
);

#[derive(Clone)]
struct PooledConn {
    conn: Arc<Mutex<quiche::Connection>>,
    table: Arc<Mutex<PooledState>>,
    sock: Arc<UdpSocket>,
    key: Arc<QuicServer>,
}

struct QuicPool {
    inner: Mutex<HashMap<QuicServer, PooledConn>>,
}

impl QuicPool {
    /// The connection already open to this edge, if there is one.
    fn stream(&self, dial: &QuicDial) -> Option<PooledConn> {
        let key = QuicServer {
            address: dial.address.clone(),
            port: dial.port,
            host: dial.host.clone(),
            roots: dial.roots.clone(),
        };
        self.inner.lock().ok()?.get(&key).cloned()
    }
}

static QUIC_POOL: OnceLock<QuicPool> = OnceLock::new();

fn pool() -> &'static QuicPool {
    QUIC_POOL.get_or_init(|| QuicPool {
        inner: Mutex::new(HashMap::new()),
    })
}

pub(crate) const ALPN: &[u8] = b"h3";

const SCID_LEN: usize = 16;

const MAX_DATAGRAM: usize = 1350;

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) const IDLE_TIMEOUT_MS: u64 = 300_000;

pub(crate) const MAX_DATA: u64 = 10_000_000;
pub(crate) const MAX_STREAM_DATA: u64 = 1_000_000;
pub(crate) const MAX_STREAMS: u64 = 100;

const PUMP_POLL: Duration = Duration::from_millis(500);

const SEND_WAIT: Duration = Duration::from_secs(10);

static TRUST_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) static QSTAGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(crate) fn qstage(ev: String) {
    if let Ok(mut log) = QSTAGES.lock() {
        log.push(ev);
    }
}

/// How long a loopback edge waits for the next packet before it lets quiche run
/// its timers, which is what keeps an idle connection alive in a test.
#[cfg(test)]
pub(crate) const SERVER_POLL: Duration = Duration::from_millis(100);

#[cfg(test)]
pub(crate) fn qms() -> u128 {
    static QT0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    QT0.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn b64_table() -> [u8; 256] {
    let mut table = [255u8; 256];
    let mut i = 0usize;
    while i < 64 {
        table[B64[i] as usize] = i as u8;
        i += 1;
    }
    table
}

const B64_TABLE: [u8; 256] = b64_table();

fn base64_encode_block(out: &mut [u8; 64], bytes: &[u8]) -> usize {
    assert!(bytes.len() <= 48, "base64 lines are 48 input bytes");
    let mut written = 0;
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for byte in chunk {
            word = (word << 8) | u32::from(*byte);
        }
        word <<= 8 * (3 - chunk.len());
        let pad = 3 - chunk.len();
        for slot in 0..4 {
            if slot < 4 - pad {
                out[written] = B64[((word >> (18 - 6 * slot)) & 63) as usize];
            } else {
                out[written] = b'=';
            }
            written += 1;
        }
    }
    written
}

fn base64_value(byte: u8) -> Option<u8> {
    let v = B64_TABLE[byte as usize];
    if v == 255 {
        None
    } else {
        Some(v)
    }
}

fn base64_decode(text: &[u8], out: &mut Vec<u8>) -> bool {
    let mut word = 0u32;
    let mut slots = 0;
    let mut pads = 0;
    for byte in text {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if *byte == b'=' {
            pads += 1;
            word <<= 6;
        } else {
            if pads > 0 {
                return false;
            }
            let Some(digit) = base64_value(*byte) else {
                return false;
            };
            word = (word << 6) | u32::from(digit);
        }
        slots += 1;
        if slots == 4 {
            if pads > 2 {
                return false;
            }
            out.push((word >> 16) as u8);
            if pads < 2 {
                out.push((word >> 8) as u8);
            }
            if pads == 0 {
                out.push(word as u8);
            }
            word = 0;
            slots = 0;
            pads = 0;
        }
    }
    slots == 0
}

pub(crate) fn der_to_pem(der: &[u8], label: &str) -> Vec<u8> {
    let mut pem = Vec::new();
    pem.extend_from_slice(b"-----BEGIN ");
    pem.extend_from_slice(label.as_bytes());
    pem.extend_from_slice(b"-----\n");
    let mut block = [0u8; 64];
    for line in der.chunks(48) {
        let n = base64_encode_block(&mut block, line);
        pem.extend_from_slice(&block[..n]);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END ");
    pem.extend_from_slice(label.as_bytes());
    pem.extend_from_slice(b"-----\n");
    pem
}

pub(crate) fn parse_ca_pem(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.windows(BEGIN.len()).position(|w| w == BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let Some(end) = after.windows(END.len()).position(|w| w == END) else {
            return Vec::new();
        };
        let mut der = Vec::new();
        if !base64_decode(&after[..end], &mut der) {
            return Vec::new();
        }
        certs.push(der);
        rest = &after[end + END.len()..];
    }
    certs
}

// create_new is O_EXCL, so a name already sitting in a shared tmp is a failure
// rather than a file to truncate; following one would hand BoringSSL a trust
// bundle this process did not write.
fn stage_trust_file(bundle: &[u8]) -> Option<(std::path::PathBuf, String)> {
    let name = format!(
        "ferrox-quic-roots-{}-{}.pem",
        std::process::id(),
        TRUST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    stage_at(&std::env::temp_dir().join(name), bundle)
}

fn stage_at(path: &std::path::Path, bundle: &[u8]) -> Option<(std::path::PathBuf, String)> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    std::io::Write::write_all(&mut file, bundle).ok()?;
    let text = path.to_str()?.to_owned();
    Some((path.to_path_buf(), text))
}

pub(crate) fn quiche_config(roots: &[Vec<u8>]) -> Option<quiche::Config> {
    if roots.is_empty() {
        return None;
    }
    let mut bundle = Vec::new();
    for root in roots {
        bundle.extend_from_slice(&der_to_pem(root, "CERTIFICATE"));
    }
    let (path, path_text) = stage_trust_file(&bundle)?;
    let config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .ok()
        .and_then(|mut config| {
            config.verify_peer(true);
            config.set_application_protos(&[ALPN]).ok()?;
            config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
            config.set_initial_max_data(MAX_DATA);
            config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
            config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
            config.set_initial_max_stream_data_uni(MAX_STREAM_DATA);
            config.set_initial_max_streams_bidi(MAX_STREAMS);
            config.set_initial_max_streams_uni(MAX_STREAMS);
            config.load_verify_locations_from_file(&path_text).ok()?;
            Some(config)
        });
    let _ = std::fs::remove_file(&path);
    config
}

pub(crate) fn flush_egress(conn: &mut quiche::Connection, sock: &UdpSocket) {
    let mut out = [0u8; MAX_DATAGRAM];
    while let Ok((written, info)) = conn.send(&mut out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

pub(crate) fn pump_once(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
    wait: Duration,
) -> bool {
    let timer = conn.timeout().map_or(wait, |left| left.min(wait));
    if sock
        .set_read_timeout(Some(timer.max(Duration::from_millis(1))))
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; MAX_DATAGRAM];
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => {
            let info = quiche::RecvInfo { from, to: local };
            let _ = conn.recv(&mut buf[..n], info);
            flush_egress(conn, sock);
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            conn.on_timeout();
            flush_egress(conn, sock);
        }
        Err(_) => return false,
    }
    true
}

pub(crate) fn drive_handshake(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
) -> Option<()> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    while !conn.is_established() {
        if conn.is_closed() || Instant::now() >= deadline {
            return None;
        }
        flush_egress(conn, sock);
        let left = deadline.saturating_duration_since(Instant::now());
        if !pump_once(conn, sock, local, left) {
            return None;
        }
    }
    Some(())
}

pub(crate) fn stream_send_all(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    stream: u64,
    mut buf: &[u8],
    fin: bool,
    deadline: Instant,
) -> bool {
    while !buf.is_empty() || fin {
        match conn.stream_send(stream, buf, fin && buf.is_empty()) {
            Ok(written) => {
                buf = &buf[written..];
                if buf.is_empty() {
                    flush_egress(conn, sock);
                    return true;
                }
                if written == 0 {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    flush_egress(conn, sock);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Err(quiche::Error::Done) => {
                if Instant::now() >= deadline {
                    return false;
                }
                flush_egress(conn, sock);
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
    flush_egress(conn, sock);
    true
}

pub(crate) fn stream_recv_exact(
    conn: &mut quiche::Connection,
    sock: &UdpSocket,
    local: SocketAddr,
    stream: u64,
    want: usize,
    deadline: Instant,
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(want);
    let mut chunk = [0u8; 8192];
    while out.len() < want {
        match conn.stream_recv(stream, &mut chunk) {
            Ok((0, _)) | Err(quiche::Error::Done) => {
                if conn.is_closed() || Instant::now() >= deadline {
                    return None;
                }
                let left = deadline.saturating_duration_since(Instant::now());
                if !pump_once(conn, sock, local, left) {
                    return None;
                }
            }
            Ok((n, fin)) => {
                out.extend_from_slice(&chunk[..n]);
                if fin {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    (out.len() == want).then_some(out)
}

/// Binds a datagram socket that QUIC will read one packet at a time.
///
/// Linux coalesces loopback datagrams into a single skb, so one `recv_from`
/// can hand back several QUIC packets at once: read into a packet-sized buffer
/// and the tail of that skb is discarded, so the packets in it are lost with no
/// error anywhere. One `setsockopt` per socket is cheaper than splitting every
/// packet, and a kernel that has never heard of UDP GRO declines it harmlessly.
pub(crate) fn bind_datagram(address: &str) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(address)?;
    #[cfg(target_os = "linux")]
    if let Ok(raw) = std::os::fd::AsRawFd::as_raw_fd(&sock) {
        let off: libc::c_int = 0;
        // SAFETY: `off` outlives the call, and the size is its own.
        unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_UDP,
                libc::UDP_GRO,
                std::ptr::addr_of!(off).cast(),
                libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
                    .unwrap_or(libc::socklen_t::MAX),
            );
        }
    }
    Ok(sock)
}

pub(crate) fn udp_to_server(
    address: &str,
    port: u16,
) -> Option<(UdpSocket, SocketAddr, SocketAddr)> {
    let peer = format!("{address}:{port}").to_socket_addrs().ok()?.next()?;
    let sock = if peer.is_ipv6() {
        bind_datagram("[::]:0").ok()?
    } else {
        bind_datagram("0.0.0.0:0").ok()?
    };
    let local = sock.local_addr().ok()?;
    Some((sock, peer, local))
}

pub(crate) fn handshake(
    sock: &UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    server_name: &str,
    roots: &[Vec<u8>],
) -> Option<quiche::Connection> {
    let mut scid = [0u8; SCID_LEN];
    getrandom::getrandom(&mut scid).ok()?;
    let cid = quiche::ConnectionId::from_ref(&scid);
    let mut config = quiche_config(roots)?;
    let mut conn = quiche::connect(Some(server_name), &cid, local, peer, &mut config).ok()?;
    drive_handshake(&mut conn, sock, local)?;
    Some(conn)
}

fn pump(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    sock: &UdpSocket,
    local: SocketAddr,
) {
    let mut ready: Vec<(u64, TcpStream)> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        ready.clear();
        {
            let Ok(mut conn) = shared.lock() else {
                return;
            };
            if conn.is_closed() {
                return;
            }
            if !pump_once(&mut conn, sock, local, PUMP_POLL) {
                return;
            }
            for id in conn.readable() {
                let half = {
                    let Ok(table) = table.lock() else {
                        break;
                    };
                    if table.opening.contains(&id) {
                        continue;
                    }
                    table
                        .sessions
                        .get(&id)
                        .and_then(|half| half.try_clone().ok())
                };
                if half.is_none() {
                    while let Ok((n, _)) = conn.stream_recv(id, &mut chunk) {
                        if n == 0 {
                            break;
                        }
                    }
                    continue;
                }
                ready.push((id, half.expect("cloned")));
            }
            if conn.is_closed() {
                return;
            }
        }
        for (id, mut up) in ready.drain(..) {
            loop {
                let (n, fin) = {
                    let Ok(mut conn) = shared.lock() else {
                        return;
                    };
                    match conn.stream_recv(id, &mut chunk) {
                        Ok((0, _)) | Err(_) => break,
                        Ok(found) => found,
                    }
                };
                if up.write_all(&chunk[..n]).is_err() {
                    break;
                }
                if fin {
                    let _ = up.shutdown(Shutdown::Write);
                    break;
                }
            }
        }
    }
}

fn leave_session(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    flush_sock: &UdpSocket,
    pool: &'static QuicPool,
    key: &QuicServer,
    id: u64,
) {
    let last = match table.lock() {
        Ok(mut table) => {
            table.sessions.remove(&id);
            table.opening.remove(&id);
            table.sessions.is_empty() && table.opening.is_empty()
        }
        Err(_) => false,
    };
    if !last {
        return;
    }
    if let Ok(mut conn) = shared.lock() {
        let _ = conn.close(false, 0, b"done");
        flush_egress(&mut conn, flush_sock);
    }
    if let Ok(mut pool) = pool.inner.lock() {
        pool.remove(key);
    }
}

fn open_session(pooled: &PooledConn, key: &QuicServer, client: &TcpStream) -> Option<u64> {
    let Ok(conn) = pooled.conn.lock() else {
        return None;
    };
    if conn.is_closed() {
        drop(conn);
        if let Ok(mut pool) = pool().inner.lock() {
            pool.remove(key);
        }
        return None;
    }
    let Ok(mut table) = pooled.table.lock() else {
        return None;
    };
    if table.sessions.len() >= MAX_STREAMS as usize {
        return None;
    }
    let id = table.next_id;
    table.next_id += 4;
    let Ok(up) = client.try_clone() else {
        return None;
    };
    table.sessions.insert(id, up);
    table.opening.insert(id);
    Some(id)
}

fn uplink_stream(pooled: &PooledConn, key: &QuicServer, id: u64, client: &TcpStream) {
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), key, id);
        return;
    };
    let Ok(mut plain) = client.try_clone() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), key, id);
        return;
    };
    let mut chunk = [0u8; 8192];
    loop {
        match plain.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut rest = &chunk[..n];
                let deadline = Instant::now() + SEND_WAIT;
                let sent = loop {
                    let Ok(mut conn) = pooled.conn.lock() else {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-lock-none {id}", key.port, qms()));
                        break false;
                    };
                    if conn.is_closed() {
                        #[cfg(test)]
                        qstage(format!("{} t={} up-closed {id}", key.port, qms()));
                        break false;
                    }
                    match conn.stream_send(id, rest, false) {
                        Ok(written) => {
                            rest = &rest[written..];
                            flush_egress(&mut conn, &flush_sock);
                            if rest.is_empty() {
                                break true;
                            }
                            if written == 0 {
                                if Instant::now() >= deadline {
                                    #[cfg(test)]
                                    qstage(format!("{} t={} up-stall {id}", key.port, qms()));
                                    break false;
                                }
                                drop(conn);
                                std::thread::sleep(Duration::from_millis(5));
                            }
                        }
                        Err(quiche::Error::Done) => {
                            if Instant::now() >= deadline {
                                #[cfg(test)]
                                qstage(format!("{} t={} up-done-timeout {id}", key.port, qms()));
                                break false;
                            }
                            drop(conn);
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => {
                            #[cfg(test)]
                            qstage(format!("{} t={} up-err {id}", key.port, qms()));
                            break false;
                        }
                    }
                };
                if !sent {
                    #[cfg(test)]
                    qstage(format!("{} t={} up-unsent {id}", key.port, qms()));
                    break;
                }
                #[cfg(test)]
                qstage(format!("{} t={} up {id} {n}", key.port, qms()));
            }
        }
    }
    if let Ok(mut conn) = pooled.conn.lock() {
        let _ = conn.stream_send(id, &[], true);
    }
    #[cfg(test)]
    qstage(format!("{} t={} uplink-end {id}", key.port, qms()));
    leave_session(&pooled.conn, &pooled.table, &flush_sock, pool(), key, id);
}

pub(crate) fn dial_pooled(client: &TcpStream, dial: &QuicDial, target: &SocketAddr) {
    let key = QuicServer {
        address: dial.address.clone(),
        port: dial.port,
        host: dial.host.clone(),
        roots: dial.roots.clone(),
    };
    let pooled = if let Ok(pool) = pool().inner.lock() {
        pool.get(&key).cloned()
    } else {
        None
    };
    #[cfg(test)]
    qstage(format!(
        "{} t={} lookup hit={}",
        dial.port,
        qms(),
        pooled.is_some()
    ));
    let Some(pooled) = pooled.or_else(|| {
        let fresh = build_pooled(dial)?;
        #[cfg(test)]
        qstage(format!("{} t={} built", dial.port, qms()));
        let Ok(mut pool) = pool().inner.lock() else {
            return Some(fresh);
        };
        if let Some(live) = pool.get(&key) {
            if let Ok(mut conn) = fresh.conn.lock() {
                let _ = conn.close(false, 0, b"superseded");
            }
            Some(live.clone())
        } else {
            pool.insert(key.clone(), fresh.clone());
            Some(fresh)
        }
    }) else {
        #[cfg(test)]
        qstage(format!("{} t={} build-none", dial.port, qms()));
        return;
    };
    let Some(id) = open_session(&pooled, &key, client) else {
        #[cfg(test)]
        qstage(format!("{} t={} open-none", dial.port, qms()));
        return;
    };
    #[cfg(test)]
    qstage(format!("{} t={} opened {id}", dial.port, qms()));
    let Ok(flush_sock) = pooled.sock.try_clone() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
        return;
    };
    let Ok(local) = pooled.sock.local_addr() else {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
        return;
    };
    let header = crate::proxy::vless_header(&dial.id, 1, target);
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let opened = {
        let Ok(mut conn) = pooled.conn.lock() else {
            leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
            return;
        };
        stream_send_all(&mut conn, &flush_sock, id, &header, false, deadline)
            && stream_recv_exact(&mut conn, &flush_sock, local, id, 2, deadline).as_deref()
                == Some(&[0, 0])
    };
    #[cfg(test)]
    qstage(format!("{} t={} header {id} {opened}", dial.port, qms()));
    if !opened {
        leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
        return;
    }
    if let Ok(mut table) = pooled.table.lock() {
        table.opening.remove(&id);
    }
    #[cfg(test)]
    qstage(format!("{} t={} graduated {id}", dial.port, qms()));
    uplink_stream(&pooled, &key, id, client);
}

/// The pooled connection for an edge, built on first use and shared after that,
/// plus a fresh bidirectional stream id on it. The Foxy lane asks for one of
/// these instead of building a connection per flow, because that is the whole
/// point of the QUIC carrier: one handshake carries many tunnels.
pub(crate) fn pooled_stream(dial: &QuicDial) -> Option<PooledStream> {
    let pooled = pool().stream(dial).or_else(|| {
        let fresh = build_pooled(dial)?;
        let Ok(mut pool) = pool().inner.lock() else {
            return Some(fresh);
        };
        if let Some(live) = pool.get(fresh.key.as_ref()) {
            return Some(live.clone());
        }
        pool.insert(fresh.key.as_ref().clone(), fresh.clone());
        Some(fresh)
    })?;
    let id = {
        let Ok(mut table) = pooled.table.lock() else {
            return None;
        };
        if table.opening.len() >= MAX_STREAMS as usize {
            return None;
        }
        let id = table.next_id;
        table.next_id += 4;
        table.opening.insert(id);
        id
    };
    let local = pooled.sock.local_addr().ok()?;
    Some((
        Arc::clone(&pooled.conn),
        Arc::clone(&pooled.sock),
        local,
        id,
    ))
}

/// Hands a stream back to the pool once its tunnel is over, and closes the
/// connection when it was the last stream on it.
pub(crate) fn release_stream(dial: &QuicDial, id: u64) {
    let key = QuicServer {
        address: dial.address.clone(),
        port: dial.port,
        host: dial.host.clone(),
        roots: dial.roots.clone(),
    };
    let pooled = pool().stream(dial);
    let Some(pooled) = pooled else { return };
    leave_session(&pooled.conn, &pooled.table, &pooled.sock, pool(), &key, id);
}

fn build_pooled(dial: &QuicDial) -> Option<PooledConn> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, peer, local) = udp_to_server(&dial.address, dial.port)?;
    let mut conn = handshake(&sock, peer, local, &dial.host, roots)?;
    flush_egress(&mut conn, &sock);
    let shared = Arc::new(Mutex::new(conn));
    let table = Arc::new(Mutex::new(PooledState {
        sessions: HashMap::new(),
        opening: HashSet::new(),
        next_id: 0,
    }));
    let task_shared = Arc::clone(&shared);
    let task_table = Arc::clone(&table);
    let Ok(pump_sock) = sock.try_clone() else {
        return None;
    };
    std::thread::spawn(move || pump(&task_shared, &task_table, &pump_sock, local));
    Some(PooledConn {
        conn: shared,
        table,
        sock: Arc::new(sock),
        key: Arc::new(QuicServer {
            address: dial.address.clone(),
            port: dial.port,
            host: dial.host.clone(),
            roots: dial.roots.clone(),
        }),
    })
}

/// One connection and one stream on it, with nothing else reading the socket.
///
/// The pool's own thread owns the connection while it drives its sessions, so a
/// loopback that proves the lane proves the lane and not the pool: which reader
/// owns a shared connection is `P38`'s question, and a proof that depends on the
/// answer is a proof of the answer.
#[cfg(test)]
pub(crate) fn direct_stream(
    host: &str,
    address: &str,
    port: u16,
    roots: &[Vec<u8>],
) -> Option<PooledStream> {
    let (sock, peer, local) = udp_to_server(address, port)?;
    let mut conn = handshake(&sock, peer, local, host, roots)?;
    flush_egress(&mut conn, &sock);
    Some((
        std::sync::Arc::new(std::sync::Mutex::new(conn)),
        std::sync::Arc::new(sock),
        local,
        4,
    ))
}

/// One datagram off a loopback edge's socket, or nothing when none arrived.
#[cfg(test)]
pub(crate) fn server_poll(sock: &UdpSocket, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
    sock.set_read_timeout(Some(SERVER_POLL)).ok()?;
    match sock.recv_from(buf) {
        Ok(found) => Some(found),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            None
        }
        Err(e) => panic!("loopback edge socket died: {e:?}"),
    }
}

/// Lets a waiting connection run its own timers and answer whatever it queued,
/// which is the only thing an edge can do between packets.
#[cfg(test)]
pub(crate) fn server_idle(conn: &mut quiche::Connection, sock: &UdpSocket, out: &mut [u8]) {
    conn.on_timeout();
    while let Ok((written, info)) = conn.send(out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

/// A loopback edge's half of a QUIC connection: the first Initial it sees is fed
/// to quiche and the handshake is driven to completion.
#[cfg(test)]
pub(crate) fn server_accept(
    sock: &UdpSocket,
    local: SocketAddr,
    config: &mut quiche::Config,
) -> quiche::Connection {
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut out = [0u8; MAX_DATAGRAM];
    let mut conn = loop {
        let Some((n, from)) = server_poll(sock, &mut buf) else {
            continue;
        };
        let Ok(header) = quiche::Header::from_slice(&mut buf[..n], 20) else {
            continue;
        };
        if header.ty != quiche::Type::Initial || header.version != quiche::PROTOCOL_VERSION {
            continue;
        }
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut fresh = quiche::accept(&cid, None, local, from, config).expect("accepts");
        let info = quiche::RecvInfo { from, to: local };
        fresh.recv(&mut buf[..n], info).expect("handshakes");
        while let Ok((written, info)) = fresh.send(&mut out) {
            let _ = sock.send_to(&out[..written], info.to);
        }
        break fresh;
    };
    while !conn.is_established() {
        if let Some((n, from)) = server_poll(sock, &mut buf) {
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            while let Ok((written, info)) = conn.send(&mut out) {
                let _ = sock.send_to(&out[..written], info.to);
            }
        } else {
            server_idle(&mut conn, sock, &mut out);
        }
    }
    conn
}

/// A loopback edge's ALPN, flow-control and certificate settings, which are the
/// ones the lane itself configures, so an edge is not a weaker peer than a real
/// one for want of a window.
#[cfg(test)]
pub(crate) fn server_config(alpn: &[u8]) -> quiche::Config {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
    config.set_application_protos(&[alpn]).expect("negotiates");
    config.set_max_idle_timeout(IDLE_TIMEOUT_MS);
    config.set_initial_max_data(MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_uni(MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(MAX_STREAMS);
    config.set_initial_max_streams_uni(MAX_STREAMS);
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The option this socket is read under is the whole reason the edge stops
    /// losing packets, so it is read back rather than assumed.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_quic_socket_is_bound_with_datagram_coalescing_off() {
        use std::os::fd::AsRawFd as _;
        let sock = bind_datagram("127.0.0.1:0").expect("binds");
        let mut on: libc::c_int = -1;
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
            .expect("size fits a socklen");
        // SAFETY: `on` and `len` describe the buffer the kernel writes into.
        let got = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                libc::SOL_UDP,
                libc::UDP_GRO,
                std::ptr::addr_of_mut!(on).cast(),
                &mut len,
            )
        };
        assert_eq!(got, 0, "the kernel knows UDP_GRO");
        assert_eq!(on, 0, "one recv_from carries one packet");
        assert!(udp_to_server("127.0.0.1", 443).is_some(), "still dials");
    }

    #[test]
    fn base64_matches_the_rfc_vectors() {
        let mut block = [0u8; 64];
        for (raw, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            let n = base64_encode_block(&mut block, raw.as_bytes());
            assert_eq!(&block[..n], text.as_bytes());
            let mut back = Vec::new();
            assert!(base64_decode(&block[..n], &mut back));
            assert_eq!(back, raw.as_bytes());
        }
        let mut garbage = Vec::new();
        assert!(!base64_decode(b"!!!", &mut garbage));
        assert!(!base64_decode(b"Zg=", &mut garbage));
        let long = vec![0xabu8; 50];
        let mut wrapped = Vec::new();
        for chunk in long.chunks(48) {
            let n = base64_encode_block(&mut block, chunk);
            wrapped.extend_from_slice(&block[..n]);
        }
        wrapped.insert(64, b'\n');
        let mut unwrapped = Vec::new();
        assert!(base64_decode(&wrapped, &mut unwrapped));
        assert_eq!(unwrapped, long);
    }

    #[test]
    fn pem_wraps_at_sixty_four_columns() {
        let pem = der_to_pem(&[0xabu8; 48], "CERTIFICATE");
        let text = std::str::from_utf8(&pem).expect("ascii");
        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        for line in text.lines().skip(1) {
            if line.starts_with("-----END") {
                break;
            }
            assert_eq!(line.len(), 64);
        }
        assert_eq!(parse_ca_pem(&pem), vec![vec![0xabu8; 48]]);
    }

    #[test]
    fn corrupt_bundle_parses_to_nothing() {
        assert_eq!(parse_ca_pem(b"no blocks here"), Vec::<Vec<u8>>::new());
        let mut pem = der_to_pem(&[1u8; 32], "CERTIFICATE");
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n");
        assert_eq!(parse_ca_pem(&pem), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn the_base64_table_agrees_with_the_alphabet() {
        for byte in 0..=u8::MAX {
            let scanned = B64
                .iter()
                .position(|digit| *digit == byte)
                .map_or(u8::MAX, |slot| slot as u8);
            assert_eq!(B64_TABLE[usize::from(byte)], scanned, "byte {byte:#04x}");
        }
        for (slot, digit) in B64.iter().enumerate() {
            assert_eq!(base64_value(*digit), Some(slot as u8));
        }
        for byte in [b'=', b' ', b'\n', b'!', 0, 0xff] {
            assert_eq!(base64_value(byte), None);
        }
    }

    fn owned_staging_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("ferrox-quic-test-{}-{tag}.pem", std::process::id()))
    }

    #[test]
    fn staging_refuses_a_name_something_else_already_holds() {
        let path = owned_staging_path("taken");
        std::fs::write(&path, b"planted").expect("plants");
        assert!(stage_at(&path, b"mine").is_none());
        assert_eq!(std::fs::read(&path).expect("reads"), b"planted");
        std::fs::remove_file(&path).expect("removes");
        let (back, text) = stage_at(&path, b"mine").expect("stages");
        assert_eq!(back, path);
        assert_eq!(text, path.to_string_lossy());
        assert_eq!(std::fs::read(&path).expect("reads"), b"mine");
        std::fs::remove_file(&path).expect("removes");
    }

    #[test]
    fn staging_returns_the_name_it_wrote_so_the_caller_can_remove_it() {
        let path = owned_staging_path("removable");
        let (back, text) = stage_at(&path, b"bundle").expect("stages");
        assert_eq!(back, path);
        assert_eq!(text, path.to_string_lossy());
        assert_eq!(std::fs::read(&path).expect("reads"), b"bundle");
        std::fs::remove_file(&path).expect("removes");
        assert!(!path.exists());
    }

    #[test]
    fn config_refuses_without_trust() {
        assert!(quiche_config(&[]).is_none());
        assert!(quiche_config(&[vec![0u8; 16]]).is_none());
    }

    #[test]
    fn config_loads_a_minted_anchor() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()]).expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        assert!(quiche_config(&roots).is_some());
    }
}
