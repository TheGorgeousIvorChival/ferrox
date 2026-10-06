//! `QUIC` dial for `VLESS`: pooled connections, one stream per session,
//! through `quiche`.
//!
//! Why `quiche`: it is the `QUIC` stack the conformance notes name as the one
//! the rungs dial through, pinned at the same version this builds against, and
//! `sing-box`'s `with_quic` transport shows the shape to copy — a `UDP` socket,
//! a `TLS` handshake inside `QUIC`, application bytes on stream zero — without
//! copying any of its lines. `Xray-core` dropped the transport and `xray-rust`
//! never had it, so there is no second wire to match: the `ALPN` below is `h3`,
//! the default `sing-box` offers when none is configured, which is what makes
//! this end compatible with the one peer that still speaks it.
//!
//! Trust is explicit or nothing: the caller hands over `DER` trust anchors the
//! way [`ferrox_core::tls::TlsConfig`] does, they are wrapped to `PEM` and
//! loaded into `BoringSSL` from a staged file that is deleted before dialling,
//! and an empty anchor set refuses rather than connecting unverified. There is
//! no system store, no `allowInsecure`, no fallback.
//!
//! One thread pumps packets and the downlink, the calling thread carries the
//! uplink; the pump wakes on packets and timers, and the uplink flushes its own
//! egress straight after queueing so no wake-up channel stands between a chunk
//! and the wire. Joining is bounded by a poll cap, never by a peer.
//!
//! Connections are pooled by server: concurrent dials share one handshake and
//! one socket, each on its own stream, the way `sing-box` pools its `QUIC`
//! transports — except here a stream is a whole `VLESS` session with no mux
//! framing at all, because `QUIC` streams already are that. The last stream
//! out closes the connection; there is no idle linger (an idle pool needs a
//! reaper, which is its own slice).

use std::collections::{HashMap, HashSet};
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs as _, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// What a `QUIC` dial needs: the server as written, and explicit trust.
#[derive(Debug, Clone)]
pub(crate) struct QuicDial {
    /// User id bytes for the `VLESS` header on stream zero.
    pub(crate) id: [u8; 16],
    /// Server name for `SNI` and certificate verification.
    pub(crate) host: String,
    /// Server host as written.
    pub(crate) address: String,
    /// Server port.
    pub(crate) port: u16,
    /// `DER` trust anchors; `None` (or empty) refuses the dial outright.
    pub(crate) roots: Option<Vec<Vec<u8>>>,
}

/// One pooled server: the dial parameters a connection is safe to share.
///
/// The anchors ride along because two dials to one address with different
/// trust must never share verification: equality is byte equality, not
/// name equality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct QuicServer {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// Server name for `SNI` and certificate verification.
    host: String,
    /// `DER` trust anchors the connection verified against.
    roots: Option<Vec<Vec<u8>>>,
}

/// Sessions on one pooled connection: stream id to its `TCP` write half,
/// plus the next client-initiated bidirectional id (`0`, `4`, `8`, …).
struct PooledState {
    /// Stream id to the `TCP` half its downlink writes through.
    sessions: HashMap<u64, TcpStream>,
    /// Ids whose header exchange still belongs to their dial thread: the
    /// pump leaves their bytes buffered for that thread's read, because a
    /// `[0, 0]` drained here would reach the client as echo bytes and
    /// starve the handshake that is waiting for it.
    opening: HashSet<u64>,
    /// Next id to hand out; client-initiated bidirectional ids step by four.
    next_id: u64,
}

/// One pooled connection: the shared stack, its session table, and the
/// socket the pump thread reads. Dial threads flush through clones, which
/// share the same local port.
#[derive(Clone)]
struct PooledConn {
    /// The shared `quiche` state; locked before the table, never after.
    conn: Arc<Mutex<quiche::Connection>>,
    /// Session table; locked only while holding the connection lock or alone.
    table: Arc<Mutex<PooledState>>,
    /// The bound socket; clones share its port.
    sock: Arc<UdpSocket>,
}

/// All pooled `QUIC` connections, by server. One per process: a relay that
/// never runs should not pay for any, and a second pool would only split
/// sharing along an invisible line.
struct QuicPool {
    /// Server to its live connection; entries leave only through eviction
    /// below, so a lookup that finds one shares it.
    inner: Mutex<HashMap<QuicServer, PooledConn>>,
}

/// One per process, built on first use rather than at start-up.
static QUIC_POOL: OnceLock<QuicPool> = OnceLock::new();

/// The process pool: acquire here, never beside it.
fn pool() -> &'static QuicPool {
    QUIC_POOL.get_or_init(|| QuicPool {
        inner: Mutex::new(HashMap::new()),
    })
}

/// The `ALPN` offered: `h3`, the default the one remaining peer negotiates.
const ALPN_H3: &[u8] = b"h3";

/// Source connection id bytes: unpredictable per connection, per `RFC 9000`.
const SCID_LEN: usize = 16;

/// Largest `UDP` payload taken per read, above any path `MTU` this dials over.
const MAX_DATAGRAM: usize = 1350;

/// A handshake slower than this is a path that will not carry the stream
/// either — but shared runners stall threads for seconds, and a slow peer is
/// not a dead one, so this is thirty seconds, not eight: the `TCP` dial
/// budget it once mirrored measures one round trip, while a `QUIC`
/// handshake is four flights plus crypto on both ends.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Idle `QUIC` connections close themselves after this long.
///
/// Five minutes, not two: a relayed stream outlives silence the way its `TCP`
/// half does (which has no killer at all), and shared runners demonstrably
/// stall threads past two minutes while the pump keeps ticking wall-clock
/// timeouts — an idle killer at or below the test bounds reaps a connection
/// whose dial already succeeded, and the relay drops `TCP` the test still
/// holds. Dead peers still reap — just within five minutes instead of two —
/// and every test bound below stays well under this one, so nothing here can
/// die before the protocol gives up.
pub(crate) const IDLE_TIMEOUT_MS: u64 = 300_000;

/// Flow-control windows, the orders of magnitude `quiche`'s own apps default
/// to: one stream carries whole sessions here, so an exhausted window is a
/// dead peer rather than a tuning knob. Without these the stack advertises
/// zero streams and every send fails with `StreamLimit`.
pub(crate) const MAX_DATA: u64 = 10_000_000;
/// Per-stream flow-control window; see [`MAX_DATA`].
pub(crate) const MAX_STREAM_DATA: u64 = 1_000_000;
/// Concurrent stream budget; see [`MAX_DATA`].
pub(crate) const MAX_STREAMS: u64 = 100;

/// How long the pump sleeps past a missing timer: it bounds joining after a
/// local close, never the wire, which wakes on packets and real timers.
const PUMP_POLL: Duration = Duration::from_millis(500);

/// How long queued stream bytes wait for flow-control window before the dial
/// gives up: windows this small mean a peer that will not read.
const SEND_WAIT: Duration = Duration::from_secs(10);

/// Staged trust files are unique per process and per dial.
static TRUST_SEQ: AtomicU64 = AtomicU64::new(0);

/// Temporary diagnosis log for the pooled-`QUIC` sharing test: every dial and
/// uplink stage with test-relative milliseconds, tagged by server port,
/// dumped into the panic message on failure so it survives `cargo test`
/// output capture. Removed once the `Linux` slowness is attributed.
#[cfg(test)]
pub(crate) static QSTAGES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Record one diagnosis stage; test builds only, see [`QSTAGES`].
#[cfg(test)]
pub(crate) fn qstage(ev: String) {
    if let Ok(mut log) = QSTAGES.lock() {
        log.push(ev);
    }
}

/// Milliseconds since the first diagnosis stage: per-phase durations without
/// trusting interleaved log timestamps. Test builds only.
#[cfg(test)]
pub(crate) fn qms() -> u128 {
    static QT0: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    QT0.get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis()
}

/// Standard-base64 alphabet, the one `PEM` wraps `DER` in.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// One base64 line: up to 48 input bytes into the 64 output bytes a `PEM`
/// line holds, padding included; returns the bytes written.
///
/// A full line is exactly 64 characters with no padding, so encoding line by
/// line is the same bytes as encoding whole and wrapping after — which is
/// what lets [`der_to_pem`] skip the intermediate buffer entirely.
///
/// # Panics
///
/// If `bytes` is longer than 48: longer input would overrun `out`, and every
/// caller here works in 48-byte lines or shorter.
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

/// One base64 digit value, `None` for padding and garbage alike.
fn base64_value(byte: u8) -> Option<u8> {
    B64.iter()
        .position(|digit| *digit == byte)
        .map(|slot| slot as u8)
}

/// Standard-base64 decode, whitespace skipped; `false` on any garbage.
///
/// Padding is terminal: data after `=` or more than two pads is garbage, and
/// a short final quantum emits only the bytes it names — `"Zg=="` is one
/// byte, not three.
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

/// Wrap `DER` in `PEM` under `label`, body at 64 columns.
///
/// One pass with no intermediate buffer: 48 input bytes encode to exactly one
/// 64-character line, so each line is encoded straight into the output.
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

/// Every `CERTIFICATE` block in `pem` as `DER`.
///
/// Strict: one undecodable block voids the whole bundle, because trust anchors
/// are not the place where "most of it parsed" is a passing grade.
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

/// Stage a trust bundle where `BoringSSL` can load it: a unique file in the
/// temporary directory, deleted by the caller right after loading.
fn stage_trust_file(bundle: &[u8]) -> Option<std::path::PathBuf> {
    let name = format!(
        "ferrox-quic-roots-{}-{}.pem",
        std::process::id(),
        TRUST_SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = std::env::temp_dir().join(name);
    std::fs::write(&path, bundle).ok()?;
    Some(path)
}

/// A client `quiche` config over explicit anchors, `None` without any.
///
/// Verification stays on: an empty anchor set is a refusal, not an unverified
/// connection. The staged file is deleted before returning either way.
pub(crate) fn quiche_config(roots: &[Vec<u8>]) -> Option<quiche::Config> {
    if roots.is_empty() {
        return None;
    }
    let mut bundle = Vec::new();
    for root in roots {
        bundle.extend_from_slice(&der_to_pem(root, "CERTIFICATE"));
    }
    let path = stage_trust_file(&bundle)?;
    let path_text = path.to_str()?.to_owned();
    let config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .ok()
        .and_then(|mut config| {
            config.verify_peer(true);
            config.set_application_protos(&[ALPN_H3]).ok()?;
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

/// Send every queued datagram at the address `quiche` names, ignoring
/// per-packet loss.
///
/// Loss is `QUIC`'s own job to notice and repair; a datagram the kernel
/// refuses surfaces as a handshake or stream timeout at the operation that is
/// actually waiting, which is where the error belongs.
fn flush_egress(conn: &mut quiche::Connection, sock: &UdpSocket) {
    let mut out = [0u8; MAX_DATAGRAM];
    while let Ok((written, info)) = conn.send(&mut out) {
        let _ = sock.send_to(&out[..written], info.to);
    }
}

/// One inbound datagram through the connection plus one flush out.
///
/// `false` only when the socket itself is gone; undecodable packets are
/// dropped on the floor, because anything brighter (closing on garbage) hands
/// every off-path spoofer a kill switch for the connection.
fn pump_once(
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

/// Drive a fresh connection to established, or `None` on timeout or refusal.
fn drive_handshake(
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

/// Queue the whole buffer on a stream, waiting out flow control within reason.
fn stream_send_all(
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
                // No progress without an error is a wait like `Done`, not a
                // state to spin in: bound it by the same deadline, or a peer
                // that never opens window hangs the dial aimlessly.
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

/// Read exactly `want` stream bytes, pumping packets meanwhile.
fn stream_recv_exact(
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

/// A `UDP` socket bound for `address:port`, family-matched like the `TCP` dial.
fn udp_to_server(address: &str, port: u16) -> Option<(UdpSocket, SocketAddr, SocketAddr)> {
    let peer = format!("{address}:{port}").to_socket_addrs().ok()?.next()?;
    let sock = if peer.is_ipv6() {
        UdpSocket::bind("[::]:0").ok()?
    } else {
        UdpSocket::bind("0.0.0.0:0").ok()?
    };
    let local = sock.local_addr().ok()?;
    Some((sock, peer, local))
}

/// Handshake one `QUIC` connection at `peer`, over explicit anchors.
fn handshake(
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

/// Packets in and every open stream out to its `TCP` half, until the
/// connection ends.
///
/// Unknown ids drain into the void rather than stalling the connection:
/// a removed session's bytes are nobody's, but its window still belongs to
/// the flow control both ends agreed on. The staging list is reused across
/// wakeups; only the session table behind it is shared.
fn pump(
    shared: &Arc<Mutex<quiche::Connection>>,
    table: &Arc<Mutex<PooledState>>,
    sock: &UdpSocket,
    local: SocketAddr,
) {
    // One scratch list, reused: it names the streams with data this wakeup,
    // never the data itself, which is written straight through below.
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
                    // Gone mid-flight: still drain, or its window never opens.
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

/// Drop one session and, when it was the last, the connection with it.
///
/// Every exit path lands here or nowhere: an entry left behind is a stream
/// id never handed out again on a connection nobody closes. Each step
/// tolerates already being done, because two sessions can end together and
/// only one of them finds anything left to close.
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

/// Open one session on a pooled connection: refuse a dead stack (evicting
/// it so the next dial rebuilds), refuse past the advertised stream budget,
/// and register the downlink half marked still-opening — or `None` on any
/// of those, having added nothing. The dial graduates it past the header
/// exchange; until then the pump will not touch its bytes.
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

/// Carry one stream's uplink on the calling thread, then leave: `fin` the
/// stream and drop the session, closing (and evicting) when it was the last.
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
                // Locked per attempt, never across the sleep: holding the
                // lock while waiting for window starves the pump behind us,
                // and no window ever opens.
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

/// Dial one `VLESS` stream over a pooled `QUIC` connection: share the
/// server's connection when one lives, build (and publish for the next dial)
/// when none does, then header, `[0, 0]` and relay on a fresh stream.
pub(crate) fn dial_pooled(client: &TcpStream, dial: &QuicDial, target: &SocketAddr) {
    let key = QuicServer {
        address: dial.address.clone(),
        port: dial.port,
        host: dial.host.clone(),
        roots: dial.roots.clone(),
    };
    // Look first, build outside the lock: holding the pool across a handshake
    // would serialize every dial behind one slow server.
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
            // Nowhere to publish it, but nothing stops this dial from using
            // it privately: eviction below is a no-op on an absent key.
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
    // Graduated: the acceptance is read, so the downlink is the pump's now.
    if let Ok(mut table) = pooled.table.lock() {
        table.opening.remove(&id);
    }
    #[cfg(test)]
    qstage(format!("{} t={} graduated {id}", dial.port, qms()));
    uplink_stream(&pooled, &key, id, client);
}

/// Build one pooled connection outside the pool lock: socket, handshake,
/// pump thread, table — or `None` when any of it refuses.
fn build_pooled(dial: &QuicDial) -> Option<PooledConn> {
    let roots = dial.roots.as_deref().unwrap_or(&[]);
    let (sock, peer, local) = udp_to_server(&dial.address, dial.port)?;
    let mut conn = handshake(&sock, peer, local, &dial.host, roots)?;
    // Drain anything the handshake left queued before sharing the stack.
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `RFC 4648` vectors, the whole contract in four lines.
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
        // A wrapped body with padding decodes back exactly.
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

    /// `PEM` wraps at 64 columns under the label given.
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

    /// One corrupt block voids the bundle: trust is all-or-nothing.
    #[test]
    fn corrupt_bundle_parses_to_nothing() {
        assert_eq!(parse_ca_pem(b"no blocks here"), Vec::<Vec<u8>>::new());
        let mut pem = der_to_pem(&[1u8; 32], "CERTIFICATE");
        pem.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n");
        assert_eq!(parse_ca_pem(&pem), Vec::<Vec<u8>>::new());
    }

    /// No anchors, no config; garbage anchors, no config either.
    #[test]
    fn config_refuses_without_trust() {
        assert!(quiche_config(&[]).is_none());
        assert!(quiche_config(&[vec![0u8; 16]]).is_none());
    }

    /// A real anchor builds a real config: `rcgen` mints, `quiche` loads.
    #[test]
    fn config_loads_a_minted_anchor() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["quic.test".to_owned()]).expect("mints");
        let roots = parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        assert!(quiche_config(&roots).is_some());
    }
}
