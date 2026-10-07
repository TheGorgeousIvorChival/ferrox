use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;

use crate::json::Json;
use ferrox_core::failure::{Failure, Kind, Stage};
use ferrox_core::tls::TlsProvider as _;
use ferrox_core::transport::EarlyData;

pub(crate) fn print_version() {
    println!("ferrox-app {}", env!("CARGO_PKG_VERSION"));
}

pub(crate) fn print_x25519() {
    let (private, public) = x25519_pair();
    println!("PrivateKey: {private}");
    println!("Password (PublicKey): {public}");
}

pub(crate) fn serve_file(path: &str) -> ! {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| exit(&format!("cannot read {path}: {error}")));
    let root = crate::json::parse(&text)
        .unwrap_or_else(|error| exit(&format!("bad config {path}: {error}")));
    let freedom = has_protocol(&root, "outbounds", "freedom");
    let outbound = find_outbound(&root);
    let mut inbounds = 0;
    let mut hysteria_served = false;
    if let Some(list) = root.get("inbounds").and_then(Json::as_arr) {
        for inbound in list {
            let listen = inbound
                .get("listen")
                .and_then(Json::as_str)
                .unwrap_or("127.0.0.1");
            let Some(port) = inbound.get("port").and_then(Json::as_port) else {
                continue;
            };
            let protocol = inbound.get("protocol").and_then(Json::as_str).unwrap_or("");
            let address = format!("{listen}:{port}");
            match protocol {
                "vless" => {
                    if serve_vless_inbound(&address, inbound, freedom, path) {
                        inbounds += 1;
                    }
                }
                "trojan" => {
                    serve_trojan_inbound(&address, inbound, freedom);
                    inbounds += 1;
                }
                "vmess" => {
                    serve_vmess_inbound(&address, inbound, freedom);
                    inbounds += 1;
                }
                "shadowsocks" => {
                    serve_shadowsocks_inbound(&address, inbound, freedom);
                    inbounds += 1;
                }
                "hysteria" => {
                    if serve_hysteria_inbound(&address, inbound, freedom, path) {
                        inbounds += 1;
                        hysteria_served = true;
                    }
                }
                "socks" => {
                    let Some(out) = outbound.clone() else {
                        continue;
                    };
                    let role = Role::Socks { out };
                    thread::spawn(move || accept_loop(&address, &role));
                    inbounds += 1;
                }
                _ => eprintln!("unsupported inbound protocol `{protocol}` in {path}"),
            }
        }
    }
    if inbounds == 0 {
        exit(&format!("no servable inbound in {path}"));
    }
    if hysteria_served {
        // The pinned interop harness reads its server log until this token
        // appears; it is the harness's readiness string, not this binary's name.
        println!("ferrox-app serving; harness readiness token: core: Xray 26.7.28 started");
    }
    loop {
        thread::park();
        report_dial_failures();
    }
}

fn spawn_role(address: &str, role: Role) {
    let address = address.to_owned();
    thread::spawn(move || accept_loop(&address, &role));
}

fn serve_vless_inbound(address: &str, inbound: &Json, freedom: bool, path: &str) -> bool {
    let id = inbound_id(inbound);
    let carrier = inbound_carrier(inbound);
    let sec = stream_security(inbound);
    match sec {
        "tls" => serve_vless_tls_inbound(address, inbound, &id, &carrier, freedom, path),
        "reality" => serve_vless_reality_inbound(address, inbound, &id, &carrier, freedom, path),
        _ if !vless_security_supported(sec) => {
            eprintln!("unsupported vless security `{sec}` in {path}: serves raw TCP only");
            false
        }
        _ => {
            let owned = address.to_owned();
            if let Carrier::Kcp(config) = carrier {
                let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
                    serve_vless_kcp(conn, &id, freedom);
                });
                thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
                return true;
            }
            if let Carrier::Hysteria(config) = carrier {
                let config = config.clone();
                let Some(settings) = inbound.get("streamSettings") else {
                    eprintln!("unreadable hysteria identity in {path}: serves nothing");
                    return false;
                };
                let Some((cert_path, key_path)) = tls_cert_paths(settings) else {
                    eprintln!("unreadable hysteria identity in {path}: serves nothing");
                    return false;
                };
                let (cert_path, key_path) = (cert_path.to_owned(), key_path.to_owned());
                let serve: crate::hysteria::Serve = Arc::new(move |flow| {
                    serve_vless_hysteria(flow, &id, freedom);
                });
                thread::spawn(move || {
                    crate::hysteria::serve_loop(
                        &owned,
                        &[config.auth],
                        config.cc,
                        &cert_path,
                        &key_path,
                        &serve,
                    );
                });
                return true;
            }
            let role = Role::Vless {
                id,
                carrier,
                freedom,
            };
            thread::spawn(move || accept_loop(&owned, &role));
            true
        }
    }
}

const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

fn dial(target: &SocketAddr) -> Result<TcpStream, Failure> {
    let stream = TcpStream::connect_timeout(target, DIAL_TIMEOUT)
        .map_err(|e| Failure::new(Stage::SocketConnected, Kind::of(&e)))?;
    no_delay(&stream);
    Ok(stream)
}

pub(crate) fn dial_or_report(target: &SocketAddr) -> Option<TcpStream> {
    match dial(target) {
        Ok(stream) => Some(stream),
        Err(failure) => {
            if failure.worth_retrying() {
                RETRYABLE_DIALS.fetch_add(1, Ordering::Relaxed);
            } else {
                FATAL_DIALS.fetch_add(1, Ordering::Relaxed);
            }
            eprintln!("dial {target} failed: {failure}");
            None
        }
    }
}

static FATAL_DIALS: AtomicU64 = AtomicU64::new(0);

static RETRYABLE_DIALS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DialFailures {
    pub fatal: u64,
    pub retryable: u64,
}

pub(crate) fn dial_failures() -> DialFailures {
    DialFailures {
        fatal: FATAL_DIALS.load(Ordering::Relaxed),
        retryable: RETRYABLE_DIALS.load(Ordering::Relaxed),
    }
}

fn report_dial_failures() {
    let failures = dial_failures();
    if failures.fatal + failures.retryable == 0 {
        return;
    }
    eprintln!(
        "dials: {} fatal, {} retryable",
        failures.fatal, failures.retryable
    );
}

fn no_delay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

fn exit(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

#[derive(Debug, Clone)]
enum Role {
    Vless {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    VlessTls {
        id: [u8; 16],
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::TlsServerConfig>,
    },
    VlessReality {
        id: [u8; 16],
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::RealityServerConfig>,
    },
    Trojan {
        key: [u8; 56],
        carrier: Carrier,
        freedom: bool,
    },
    Vmess {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    Shadowsocks {
        password: String,
        method: String,
        carrier: Carrier,
        freedom: bool,
    },
    Socks {
        out: Outbound,
    },
}

#[derive(Debug, Clone)]
enum Outbound {
    Vless(VlessOut),
    Trojan(TrojanOut),
    Vmess(VmessOut),
    Shadowsocks(ShadowsocksOut),
    Foxy(Box<FoxyOut>),
    Freedom,
}

/// The Foxy lane: an account's proxy pass over an edge in one pinned country,
/// with the split-tunnel list that decides what does not go through it at all.
#[derive(Debug, Clone)]
struct FoxyOut {
    account: Option<std::sync::Arc<crate::foxy_account::Account>>,
    country: String,
    city: String,
    carrier: crate::foxy::Carrier,
    candidates: Vec<ferrox_core::foxy::Candidate>,
    stored: Option<ferrox_core::foxy::Candidate>,
    /// Set when the edge refuses the pass, so every later flow is answered
    /// locally instead of paying a round trip to hear the same status again.
    unauthenticated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    roots: Vec<Vec<u8>>,
    pins: ferrox_core::foxy::pin::Pins,
    pass: ferrox_core::foxy::Pass,
    edge_address: Option<SocketAddr>,
    direct_ports: Vec<u16>,
    direct_suffixes: Vec<String>,
    exit_probe: Option<String>,
}

#[derive(Debug, Clone)]
struct VlessOut {
    address: String,
    port: u16,
    id: [u8; 16],
    carrier: Carrier,
    host: String,
    mux: bool,
    quic_roots: Option<Vec<Vec<u8>>>,
    hysteria_roots: Option<Vec<Vec<u8>>>,
}

macro_rules! refused_carriers {
    () => {
        Carrier::Quic
            | Carrier::Kcp(_)
            | Carrier::Hysteria(_)
            | Carrier::Masque
            | Carrier::Xdrive
            | Carrier::Http
            | Carrier::Unknown
    };
}

#[derive(Debug, Clone)]
enum Carrier {
    Raw,
    Ws { path: String, ed: u32 },
    HttpUpgrade { path: String },
    Grpc { path: String },
    Xhttp { path: String },
    HttpHeader { path: String },
    Quic,
    Kcp(ferrox_core::kcp::Config),
    Hysteria(ferrox_core::hysteria::Config),
    Masque,
    Xdrive,
    Http,
    Unknown,
}

#[derive(Debug, Clone)]
struct VmessOut {
    address: String,
    port: u16,
    id: [u8; 16],
    cipher: crate::vmess::Cipher,
    carrier: Carrier,
    host: String,
}

#[derive(Debug, Clone)]
struct TrojanOut {
    address: String,
    port: u16,
    key: [u8; 56],
    carrier: Carrier,
    host: String,
}

#[derive(Debug, Clone)]
struct ShadowsocksOut {
    address: String,
    port: u16,
    method: String,
    password: String,
    carrier: Carrier,
    host: String,
}

fn accept_loop(address: &str, role: &Role) {
    let listener = TcpListener::bind(address)
        .unwrap_or_else(|error| exit(&format!("cannot listen on {address}: {error}")));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        no_delay(&stream);
        let role = role.clone();
        thread::spawn(move || match role {
            Role::Vless {
                id,
                carrier,
                freedom,
            } => serve_vless(stream, &id, &carrier, freedom),
            Role::VlessTls {
                id,
                freedom,
                carrier,
                server,
            } => serve_vless_tls(stream, &id, freedom, &carrier, &server),
            Role::VlessReality {
                id,
                freedom,
                carrier,
                server,
            } => serve_vless_reality(stream, &id, freedom, &carrier, &server),
            Role::Trojan {
                key,
                carrier,
                freedom,
            } => match carrier {
                Carrier::Raw => serve_trojan(stream, &key, freedom),
                Carrier::Ws { path, .. } => {
                    serve_trojan_ws(stream, &key, path.as_str(), freedom);
                }
                Carrier::HttpUpgrade { path } => {
                    serve_trojan_httpupgrade(stream, &key, path.as_str(), freedom);
                }
                Carrier::Grpc { path } => {
                    serve_trojan_grpc(stream, &key, path.as_str(), freedom);
                }
                Carrier::Xhttp { path } => {
                    serve_trojan_xhttp(stream, &key, path.as_str(), freedom);
                }
                Carrier::HttpHeader { path } => {
                    serve_trojan_httpheader(stream, &key, path.as_str(), freedom);
                }
                refused_carriers!() => {}
            },
            Role::Vmess {
                id,
                carrier,
                freedom,
            } => match carrier {
                Carrier::Raw => crate::vmess::serve(stream, &id, freedom),
                Carrier::Ws { path, .. } => {
                    crate::vmess::serve_ws(stream, path.as_str(), &id, freedom);
                }
                Carrier::Xhttp { path } => {
                    crate::vmess::serve_xhttp(stream, path.as_str(), &id, freedom);
                }
                Carrier::HttpHeader { path } => {
                    crate::vmess::serve_httpheader(stream, path.as_str(), &id, freedom);
                }
                Carrier::HttpUpgrade { path } => {
                    crate::vmess::serve_httpupgrade(stream, path.as_str(), &id, freedom);
                }
                Carrier::Grpc { path } => {
                    crate::vmess::serve_grpc(stream, path.as_str(), &id, freedom);
                }
                refused_carriers!() => {}
            },
            Role::Shadowsocks {
                password,
                method,
                carrier,
                freedom,
            } => serve_shadowsocks(stream, &password, &method, &carrier, freedom),
            Role::Socks { out } => serve_socks(stream, &out),
        });
    }
}

fn serve_shadowsocks(
    stream: TcpStream,
    password: &str,
    method: &str,
    carrier: &Carrier,
    freedom: bool,
) {
    match carrier {
        Carrier::Raw => crate::shadowsocks::serve(stream, password, method, freedom),
        Carrier::Ws { path, .. } => {
            crate::shadowsocks::serve_ws(stream, password, method, path.as_str(), freedom);
        }
        Carrier::HttpUpgrade { path } => {
            crate::shadowsocks::serve_httpupgrade(stream, password, method, path.as_str(), freedom);
        }
        Carrier::Grpc { path } => {
            crate::shadowsocks::serve_grpc(stream, password, method, path.as_str(), freedom);
        }
        Carrier::Xhttp { path } => {
            crate::shadowsocks::serve_xhttp(stream, password, method, path.as_str(), freedom);
        }
        Carrier::HttpHeader { path } => {
            crate::shadowsocks::serve_httpheader(stream, password, method, path.as_str(), freedom);
        }
        refused_carriers!() => {}
    }
}

fn serve_vless(stream: TcpStream, id: &[u8; 16], carrier: &Carrier, freedom: bool) {
    match carrier {
        Carrier::Raw => serve_vless_raw(stream, id, freedom),
        Carrier::Ws { path, .. } => {
            let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
                return;
            };
            let Some((got, _flow, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, &uplink, |_| {});
        }
        Carrier::HttpUpgrade { path } => {
            let Some((mut reader, mut write)) = crate::httpupgrade::accept(stream, path) else {
                return;
            };
            let Some((got, _flow, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if write.write_all(&[0, 0]).is_err() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, &uplink);
        }
        Carrier::Grpc { path } => {
            let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
                return;
            };
            let Some((got, _flow, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, &uplink, crate::grpc::mark_reader_dead);
        }
        Carrier::Xhttp { path } => {
            let Some((mut reader, writer)) = crate::xhttp::accept(stream, path) else {
                return;
            };
            let Some((got, _flow, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if !writer.send(&[0, 0]) {
                return;
            }
            crate::proxy::relay_sink_drained(reader, &writer, &uplink);
        }
        Carrier::HttpHeader { path } => {
            let Some((mut reader, mut write)) = crate::httpheader::accept(stream, path) else {
                return;
            };
            let Some((got, _flow, cmd, target)) = decode_request(&mut reader) else {
                return;
            };
            if got != *id || cmd != 1 || !freedom {
                return;
            }
            let Some(uplink) = dial_or_report(&target) else {
                return;
            };
            if write.write_all(&[0, 0]).is_err() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, &uplink);
        }
        refused_carriers!() => {}
    }
}

fn serve_vless_raw(mut stream: TcpStream, id: &[u8; 16], freedom: bool) {
    let Some((got, flow, cmd, target)) = decode_request(&mut stream) else {
        return;
    };
    if got != *id || !freedom {
        return;
    }
    if cmd == 2 {
        if !flow.is_empty() {
            return;
        }
        return serve_vless_udp(stream, &target);
    }
    if cmd == 3 {
        if stream.write_all(&[0, 0]).is_err() {
            return;
        }
        return serve_vless_mux(stream);
    }
    if cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if stream.write_all(&[0, 0]).is_err() {
        return;
    }
    relay(&stream, &uplink);
}

fn mux_target_addr(target: &ferrox_core::mux::Target<'_>) -> Option<SocketAddr> {
    let port = target.port;
    match target.addr {
        ferrox_core::addr::Addr::V4(octets) => {
            Some(SocketAddr::new(std::net::IpAddr::V4(octets.into()), port))
        }
        ferrox_core::addr::Addr::V6(octets) => {
            Some(SocketAddr::new(std::net::IpAddr::V6(octets.into()), port))
        }
        ferrox_core::addr::Addr::Name(bytes) => {
            let host = std::str::from_utf8(bytes).ok()?;
            resolve_endpoint(host, port)
        }
    }
}

fn resolve_endpoint(host: &str, port: u16) -> Option<SocketAddr> {
    format!("{host}:{port}").to_socket_addrs().ok()?.next()
}

fn mux_target_of(addr: SocketAddr) -> ferrox_core::mux::Target<'static> {
    let address = match addr.ip() {
        std::net::IpAddr::V4(ip) => ferrox_core::addr::Addr::V4(ip.octets()),
        std::net::IpAddr::V6(ip) => ferrox_core::addr::Addr::V6(ip.octets()),
    };
    ferrox_core::mux::Target {
        network: ferrox_core::mux::Network::Udp,
        port: addr.port(),
        addr: address,
    }
}

fn write_mux_frame(
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    frame: ferrox_core::mux::Outgoing<'_>,
    data: Option<&[u8]>,
) -> bool {
    let len = data.map_or(0, <[u8]>::len);
    resize_scratch(staging, frame.frame_len(len));
    let written = frame.encode_into(data, staging);
    staging.truncate(written);
    match shared.lock() {
        Ok(mut stream) => stream.write_all(staging).is_ok(),
        Err(_) => false,
    }
}

fn send_mux_end(shared: &Arc<Mutex<TcpStream>>, staging: &mut Vec<u8>, id: u16) {
    let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
    let _ = write_mux_frame(shared, staging, end, None);
}

fn write_mux_keep(
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    id: u16,
    payload: &[u8],
) -> bool {
    let keep = ferrox_core::mux::Outgoing {
        id,
        status: ferrox_core::mux::Status::Keep,
        options: ferrox_core::mux::DATA,
        target: None,
        global_id: None,
    };
    write_mux_frame(shared, staging, keep, Some(payload))
}

type MuxTable = Arc<Mutex<HashMap<u16, Arc<Mutex<TcpStream>>>>>;

struct UdpMux {
    socket: Arc<UdpSocket>,
    dest: SocketAddr,
    id: Arc<AtomicU16>,
    done: Arc<AtomicBool>,
}

type UdpTable = HashMap<u16, Arc<UdpMux>>;

type UdpGlobal = HashMap<[u8; ferrox_core::mux::GLOBAL_ID], u16>;

fn remove_mux_session(
    table: &MuxTable,
    id: u16,
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
) {
    if let Ok(mut table) = table.lock() {
        table.remove(&id);
    }
    send_mux_end(shared, staging, id);
}

fn serve_vless_mux(stream: TcpStream) {
    let Ok(mut read) = stream.try_clone() else {
        return;
    };
    let shared = Arc::new(Mutex::new(stream));
    let table: MuxTable = Arc::new(Mutex::new(HashMap::new()));
    let mut udp: UdpTable = HashMap::new();
    let mut global: UdpGlobal = HashMap::new();
    let mut handles: Vec<std::sync::mpsc::Receiver<()>> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    let mut at = 0;
    let mut probe = [0u8; 8192];
    let mut staging = Vec::with_capacity(8192);
    loop {
        if at >= buf.len() {
            buf.clear();
            at = 0;
        } else if at > 0 {
            buf.drain(..at);
            at = 0;
        }
        let mut progressed = false;
        loop {
            match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                Err(ferrox_core::mux::Error::Short { .. }) => break,
                Err(_) => {
                    teardown_mux(&table, &udp, &handles);
                    return;
                }
                Ok((frame, used)) => {
                    at += used;
                    progressed = true;
                    handle_mux_frame(
                        frame,
                        &table,
                        &mut udp,
                        &mut global,
                        &shared,
                        &mut staging,
                        &mut handles,
                    );
                }
            }
        }
        if !progressed {
            match read.read(&mut probe) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&probe[..n]),
            }
        }
    }
    teardown_mux(&table, &udp, &handles);
}

fn teardown_mux(table: &MuxTable, udp: &UdpTable, handles: &[std::sync::mpsc::Receiver<()>]) {
    if let Ok(table) = table.lock() {
        for half in table.values() {
            if let Ok(half) = half.lock() {
                let _ = half.shutdown(Shutdown::Both);
            }
        }
    }
    for session in udp.values() {
        session.done.store(true, Ordering::Relaxed);
    }
    for done in handles {
        join(done);
    }
}

fn handle_mux_frame(
    frame: ferrox_core::mux::Incoming<'_>,
    table: &MuxTable,
    udp: &mut UdpTable,
    global: &mut UdpGlobal,
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    use ferrox_core::mux::{Network, Status};
    match frame.status {
        Status::New => {
            if frame.target.is_some_and(|t| t.network == Network::Udp) {
                handle_mux_udp_new(frame, udp, global, shared, staging, handles);
            } else {
                handle_mux_tcp_new(frame, table, shared, staging, handles);
            }
        }
        Status::Keep => {
            let Some(data) = frame.data else {
                return;
            };
            if let Some(session) = udp.get(&frame.id).cloned() {
                let dest = frame
                    .target
                    .and_then(|t| mux_target_addr(&t))
                    .unwrap_or(session.dest);
                let _ = session.socket.send_to(data, dest);
                return;
            }
            if frame.target.is_some() {
                return;
            }
            let half = match table.lock() {
                Ok(table) => table.get(&frame.id).cloned(),
                Err(_) => return,
            };
            if let Some(half) = half {
                if let Ok(mut half) = half.lock() {
                    let _ = half.write_all(data);
                }
            }
        }
        Status::End => {
            if let Some(session) = udp.remove(&frame.id) {
                session.done.store(true, Ordering::Relaxed);
                global.retain(|_, id| *id != frame.id);
            }
            if let Ok(mut table) = table.lock() {
                if let Some(half) = table.remove(&frame.id) {
                    if let Ok(half) = half.lock() {
                        let _ = half.shutdown(Shutdown::Write);
                    }
                }
            }
        }
        Status::KeepAlive => {}
    }
}

fn handle_mux_tcp_new(
    frame: ferrox_core::mux::Incoming<'_>,
    table: &MuxTable,
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    let Some(target) = frame.target.and_then(|t| mux_target_addr(&t)) else {
        return send_mux_end(shared, staging, frame.id);
    };
    let live = match table.lock() {
        Ok(table) => table.len(),
        Err(_) => return,
    };
    if live >= ferrox_core::mux::DEFAULT_CAP {
        return send_mux_end(shared, staging, frame.id);
    }
    let Some(uplink) = dial_or_report(&target) else {
        return send_mux_end(shared, staging, frame.id);
    };
    let Ok(read_half) = uplink.try_clone() else {
        return send_mux_end(shared, staging, frame.id);
    };
    let write_half = Arc::new(Mutex::new(uplink));
    let duplicate = match table.lock() {
        Ok(mut table) => table.insert(frame.id, Arc::clone(&write_half)).is_some(),
        Err(_) => return,
    };
    if duplicate {
        return send_mux_end(shared, staging, frame.id);
    }
    if let Some(data) = frame.data {
        if write_half
            .lock()
            .is_ok_and(|mut half| half.write_all(data).is_err())
        {
            remove_mux_session(table, frame.id, shared, staging);
            return;
        }
    }
    let task_table = Arc::clone(table);
    let task_shared = Arc::clone(shared);
    let task_id = frame.id;
    let task = move || {
        let mut read_half = read_half;
        let mut chunk = [0u8; 8192];
        let mut scratch = Vec::with_capacity(8192);
        loop {
            match read_half.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if !write_mux_keep(&task_shared, &mut scratch, task_id, &chunk[..n]) {
                        break;
                    }
                }
            }
        }
        remove_mux_session(&task_table, task_id, &task_shared, &mut scratch);
    };
    handles.push(RelayPool::global().run(task));
    handles.retain(|done| done.try_recv().is_err());
}

fn handle_mux_udp_new(
    frame: ferrox_core::mux::Incoming<'_>,
    udp: &mut UdpTable,
    global: &mut UdpGlobal,
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    let Some(dest) = frame.target.and_then(|t| mux_target_addr(&t)) else {
        return send_mux_end(shared, staging, frame.id);
    };
    let empty = [0u8; ferrox_core::mux::GLOBAL_ID];
    let identity = frame.global_id.filter(|identity| *identity != empty);
    let reused = identity
        .and_then(|identity| global.get(&identity).copied())
        .and_then(|id| udp.remove(&id).map(|session| (id, session)));
    let session = if let Some((old, session)) = reused {
        if old != frame.id {
            send_mux_end(shared, staging, old);
        }
        session.id.store(frame.id, Ordering::Relaxed);
        session
    } else {
        if udp.len() >= ferrox_core::mux::DEFAULT_CAP {
            return send_mux_end(shared, staging, frame.id);
        }
        let bound = if dest.is_ipv6() {
            UdpSocket::bind("[::]:0")
        } else {
            UdpSocket::bind("0.0.0.0:0")
        };
        let Ok(socket) = bound else {
            return send_mux_end(shared, staging, frame.id);
        };
        let session = Arc::new(UdpMux {
            socket: Arc::new(socket),
            dest,
            id: Arc::new(AtomicU16::new(frame.id)),
            done: Arc::new(AtomicBool::new(false)),
        });
        let Some(reader) = spawn_mux_udp_reader(&session.socket, shared, &session) else {
            return send_mux_end(shared, staging, frame.id);
        };
        handles.push(reader);
        session
    };
    if let Some(identity) = identity {
        global.insert(identity, frame.id);
    }
    udp.insert(frame.id, Arc::clone(&session));
    if let Some(data) = frame.data {
        let _ = session.socket.send_to(data, dest);
    }
}

fn spawn_mux_udp_reader(
    socket: &UdpSocket,
    shared: &Arc<Mutex<TcpStream>>,
    session: &Arc<UdpMux>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let read = socket.try_clone().ok()?;
    read.set_read_timeout(Some(RELAY_POLL)).ok()?;
    let shared = Arc::clone(shared);
    let id = Arc::clone(&session.id);
    let done = Arc::clone(&session.done);
    Some(RelayPool::global().run(move || {
        let mut buf = vec![0u8; UDP_BUF];
        let mut staging = Vec::with_capacity(8192);
        loop {
            match read.recv_from(&mut buf) {
                Ok((n, source)) => {
                    let keep = ferrox_core::mux::Outgoing {
                        id: id.load(Ordering::Relaxed),
                        status: ferrox_core::mux::Status::Keep,
                        options: ferrox_core::mux::DATA,
                        target: Some(mux_target_of(source)),
                        global_id: None,
                    };
                    if !write_mux_frame(&shared, &mut staging, keep, Some(&buf[..n])) {
                        return;
                    }
                }
                Err(error) if is_timeout(&error) => {
                    if done.load(Ordering::Relaxed) {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }))
}

fn serve_vless_tls_inbound(
    address: &str,
    inbound: &Json,
    id: &[u8; 16],
    carrier: &Carrier,
    freedom: bool,
    path: &str,
) -> bool {
    let Some(server) = inbound_tls_identity(inbound) else {
        eprintln!("unreadable vless tls identity in {path}: serves raw TCP only");
        return false;
    };
    let owned = address.to_owned();
    if let Carrier::Kcp(config) = carrier {
        let config = *config;
        let id = *id;
        let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
            serve_vless_kcp_tls(conn, &id, freedom, &server);
        });
        thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        return true;
    }
    let role = Role::VlessTls {
        id: *id,
        freedom,
        carrier: carrier.clone(),
        server,
    };
    thread::spawn(move || accept_loop(&owned, &role));
    true
}

fn serve_vless_reality_inbound(
    address: &str,
    inbound: &Json,
    id: &[u8; 16],
    carrier: &Carrier,
    freedom: bool,
    path: &str,
) -> bool {
    let Some(server) = inbound_reality_config(inbound) else {
        eprintln!("unreadable vless reality settings in {path}: serves nothing");
        return false;
    };
    let owned = address.to_owned();
    if let Carrier::Kcp(config) = carrier {
        let config = *config;
        let id = *id;
        let server = Arc::new(server);
        let serve: KcpServe = Arc::new(move |conn: &Arc<ferrox_core::kcp::Connection>| {
            serve_vless_kcp_reality(conn, &id, freedom, &server);
        });
        thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        return true;
    }
    let role = Role::VlessReality {
        id: *id,
        freedom,
        carrier: carrier.clone(),
        server: Arc::new(server),
    };
    thread::spawn(move || accept_loop(&owned, &role));
    true
}

fn serve_vless_tls(
    stream: TcpStream,
    id: &[u8; 16],
    freedom: bool,
    carrier: &Carrier,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    if stream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    match carrier {
        Carrier::Raw => {
            let Ok(raw) = stream.try_clone() else { return };
            let Ok(mut tls) = ferrox_core::tls::accept(server, stream) else {
                return;
            };
            if tls.handshake().is_err() {
                return;
            }
            relay_vless(tls, Some(raw), id, freedom);
        }
        Carrier::Ws { path, .. } => {
            let Some((reader, writer)) = crate::ws::accept(stream, path) else {
                return;
            };
            serve_carried_tls(CarrierStream { reader, writer }, id, freedom, server);
        }
        Carrier::Xhttp { path } => {
            let Some((reader, writer)) = crate::xhttp::accept(stream, path) else {
                return;
            };
            let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
            serve_carried_tls(CarrierStream { reader, writer }, id, freedom, server);
        }
        Carrier::HttpUpgrade { path } => {
            let Some((reader, write)) = crate::httpupgrade::accept(stream, path) else {
                return;
            };
            serve_carried_tls(
                CarrierStream {
                    reader,
                    writer: write,
                },
                id,
                freedom,
                server,
            );
        }
        Carrier::HttpHeader { path } => {
            let Some((reader, write)) = crate::httpheader::accept(stream, path) else {
                return;
            };
            serve_carried_tls(
                CarrierStream {
                    reader,
                    writer: write,
                },
                id,
                freedom,
                server,
            );
        }
        Carrier::Grpc { path } => {
            let Some((reader, writer)) = crate::grpc::accept(stream, path) else {
                return;
            };
            serve_carried_tls(Grpc::new(reader, writer), id, freedom, server);
        }
        refused_carriers!() => {}
    }
}

fn serve_carried_tls<S: Read + Write + Send + 'static>(
    stream: S,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    let Ok(mut tls) = ferrox_core::tls::accept(server, stream) else {
        return;
    };
    if tls.handshake().is_err() {
        return;
    }
    relay_vless(tls, None, id, freedom);
}

fn serve_vless_reality(
    stream: TcpStream,
    id: &[u8; 16],
    freedom: bool,
    carrier: &Carrier,
    server: &ferrox_core::tls::RealityServerConfig,
) {
    let Ok(raw) = stream.try_clone() else { return };
    if stream.set_read_timeout(Some(RELAY_POLL)).is_err() {
        return;
    }
    match carrier {
        Carrier::Raw => {
            let Ok(session) = ferrox_core::tls::RealityServer::accept(server, unix_now(), stream)
            else {
                return;
            };
            finish_reality(session, Some(raw), id, freedom);
        }
        Carrier::Grpc { path } => {
            let Some((reader, writer)) = crate::grpc::accept(stream, path) else {
                return;
            };
            let tunnel = Grpc::new(reader, writer);
            let Ok(session) = ferrox_core::tls::RealityServer::accept(server, unix_now(), tunnel)
            else {
                return;
            };
            finish_reality(session, Some(raw), id, freedom);
        }
        Carrier::Ws { path, .. } => {
            let Some((reader, writer)) = crate::ws::accept(stream, path) else {
                return;
            };
            let Ok(session) = ferrox_core::tls::RealityServer::accept(
                server,
                unix_now(),
                CarrierStream { reader, writer },
            ) else {
                return;
            };
            finish_reality(session, None, id, freedom);
        }
        Carrier::Xhttp { path } => {
            let Some((reader, writer)) = crate::xhttp::accept(stream, path) else {
                return;
            };
            let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
            let Ok(session) = ferrox_core::tls::RealityServer::accept(
                server,
                unix_now(),
                CarrierStream { reader, writer },
            ) else {
                return;
            };
            finish_reality(session, None, id, freedom);
        }
        Carrier::HttpUpgrade { path } => {
            let Some((reader, write)) = crate::httpupgrade::accept(stream, path) else {
                return;
            };
            let Ok(session) = ferrox_core::tls::RealityServer::accept(
                server,
                unix_now(),
                CarrierStream {
                    reader,
                    writer: write,
                },
            ) else {
                return;
            };
            finish_reality(session, None, id, freedom);
        }
        Carrier::HttpHeader { path } => {
            let Some((reader, write)) = crate::httpheader::accept(stream, path) else {
                return;
            };
            let Ok(session) = ferrox_core::tls::RealityServer::accept(
                server,
                unix_now(),
                CarrierStream {
                    reader,
                    writer: write,
                },
            ) else {
                return;
            };
            finish_reality(session, None, id, freedom);
        }
        refused_carriers!() => {}
    }
}

fn finish_reality<S: ferrox_core::tls::TlsProvider + Send + 'static>(
    mut session: S,
    raw: Option<TcpStream>,
    id: &[u8; 16],
    freedom: bool,
) {
    if session.handshake().is_err() {
        return;
    }
    relay_vless(session, raw, id, freedom);
}

struct Grpc {
    reader: crate::grpc::GrpcReader,
    writer: crate::grpc::GrpcWriter,
}

impl Grpc {
    fn new(reader: crate::grpc::GrpcReader, writer: crate::grpc::GrpcWriter) -> Self {
        Self { reader, writer }
    }
}

impl Read for Grpc {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for Grpc {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.writer.send(buf) {
            Ok(buf.len())
        } else {
            Err(std::io::Error::other("grpc: tunnel write failed"))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct CarrierStream<R, W> {
    reader: R,
    writer: W,
}

impl<R: Read, W: Write> Read for CarrierStream<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R: Read, W: Write> Write for CarrierStream<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

fn relay_vless<S: Read + Write + Send + 'static>(
    mut session: S,
    raw: Option<TcpStream>,
    id: &[u8; 16],
    freedom: bool,
) {
    let Some((got, flow, cmd, target)) = decode_request(&mut session) else {
        return;
    };
    if got != *id || cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if uplink.set_read_timeout(Some(RELAY_POLL)).is_err() {
        eprintln!("tls: uplink timeout failed");
        return;
    }
    if session.write_all(&[0, 0]).is_err() {
        return;
    }
    if flow == crate::vision::FLOW {
        relay_stream(crate::vision::Link::new(session, raw, id), uplink);
    } else {
        relay_stream(session, uplink);
    }
}

fn inbound_reality_config(inbound: &Json) -> Option<ferrox_core::tls::RealityServerConfig> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("reality") {
        return None;
    }
    let reality = settings.get("realitySettings")?;
    let short_ids: Vec<[u8; 8]> = reality
        .get("shortIds")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str().and_then(short_id))
        .collect();
    if short_ids.is_empty() {
        return None;
    }
    let server_names: Vec<String> = reality
        .get("serverNames")?
        .as_arr()?
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::to_owned)
        .collect();
    if server_names.is_empty() {
        return None;
    }
    Some(ferrox_core::tls::RealityServerConfig {
        private_key: reality.get("privateKey")?.as_str().and_then(key32)?,
        short_ids,
        server_names,
        max_time_skew: reality
            .get("maxTimeDiff")
            .and_then(as_millis)
            .map(Duration::from_millis),
    })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn short_id(hex: &str) -> Option<[u8; 8]> {
    let mut out = [0u8; 8];
    if hex.is_empty() || hex.len() > 16 || !hex.len().is_multiple_of(2) {
        return None;
    }
    let at = 8 - hex.len() / 2;
    for (i, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[at + i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

fn key32(text: &str) -> Option<[u8; 32]> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut word = 0u32;
    let mut bits = 0;
    let mut out = Vec::with_capacity(32);
    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|c| *c == byte)? as u32;
        word = (word << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((word >> bits) as u8);
        }
    }
    <[u8; 32]>::try_from(out).ok()
}

fn as_millis(node: &Json) -> Option<u64> {
    match node {
        Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}

pub(crate) const RELAY_POLL: Duration = Duration::from_millis(20);

#[derive(Debug)]
struct Half<T> {
    inner: Mutex<T>,
    wanted: AtomicBool,
}

const RELAY_HANDOFF_SPINS: u32 = 64;

impl<T> Half<T> {
    fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            wanted: AtomicBool::new(false),
        }
    }

    fn hand_off(&self) {
        let mut spins = 0;
        while self.wanted.load(Ordering::Relaxed) && spins < RELAY_HANDOFF_SPINS {
            thread::yield_now();
            spins += 1;
        }
    }
}

impl<T: Read> Half<T> {
    fn read_once(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let result = match self.inner.lock() {
            Ok(mut guard) => guard.read(buf),
            Err(_) => Err(std::io::Error::other("relay half poisoned")),
        };
        self.hand_off();
        result
    }
}

impl<T: Write> Half<T> {
    fn write_once(&self, buf: &[u8]) -> std::io::Result<()> {
        self.wanted.store(true, Ordering::Relaxed);
        let taken = self.writer_lock();
        self.wanted.store(false, Ordering::Relaxed);
        let Ok(mut guard) = taken else {
            return Err(std::io::Error::other("relay half poisoned"));
        };
        guard.write_all(buf)
    }

    fn writer_lock(&self) -> Result<MutexGuard<'_, T>, ()> {
        let mut spins = 0u32;
        loop {
            match self.inner.try_lock() {
                Ok(guard) => return Ok(guard),
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(()),
                Err(std::sync::TryLockError::WouldBlock) => {}
            }
            spins += 1;
            if spins > RELAY_LOCK_TRIES {
                return self.inner.lock().map_err(|_| ());
            }
            thread::yield_now();
        }
    }
}

const RELAY_LOCK_TRIES: u32 = 1 << 20;

fn relay_stream<A: Read + Write + Send + 'static, B: Read + Write + Send + 'static>(a: A, b: B) {
    let a = Arc::new(Half::new(a));
    let b = Arc::new(Half::new(b));
    let (up_a, up_b) = (Arc::clone(&a), Arc::clone(&b));
    let done = thread::spawn(move || copy_stream(&up_a, &up_b));
    copy_stream(&b, &a);
    let _ = done.join();
}

fn copy_stream<R: Read, W: Write>(from: &Half<R>, to: &Half<W>) {
    let mut buffer = RelayBuf::new();
    loop {
        let n = match from.read_once(buffer.as_mut()) {
            Ok(0) => return,
            Ok(n) => n,
            Err(error) if is_timeout(&error) => continue,
            Err(_) => return,
        };
        if to.write_once(buffer.filled(n)).is_err() {
            return;
        }
    }
}

pub(crate) fn resize_scratch(buf: &mut Vec<u8>, len: usize) {
    buf.clear();
    if buf.capacity() < len {
        buf.reserve(len);
    }
    unsafe { buf.set_len(len) }
}

pub(crate) fn refresh_read_timeout(
    sock: &UdpSocket,
    want: Duration,
    applied: &mut Option<Duration>,
) -> bool {
    if *applied == Some(want) {
        return true;
    }
    if sock.set_read_timeout(Some(want)).is_err() {
        return false;
    }
    *applied = Some(want);
    true
}

pub(crate) fn is_timeout(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    matches!(error.kind(), TimedOut | WouldBlock)
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ferrox_core::tls::TlsError>())
            .is_some_and(|mapped| matches!(mapped, ferrox_core::tls::TlsError::Timeout))
}

fn inbound_tls_identity(inbound: &Json) -> Option<Arc<ferrox_core::tls::TlsServerConfig>> {
    let settings = inbound.get("streamSettings")?;
    if settings.get("security").and_then(Json::as_str) != Some("tls") {
        return None;
    }
    let (cert_path, key_path) = tls_cert_paths(settings)?;
    let cert_pem = std::fs::read(cert_path).ok()?;
    let key_pem = std::fs::read(key_path).ok()?;
    ferrox_core::tls::parse_pem_identity(&cert_pem, &key_pem)
        .ok()
        .map(Arc::new)
}

fn tls_cert_paths(settings: &Json) -> Option<(&str, &str)> {
    let first = settings
        .get("tlsSettings")?
        .get("certificates")?
        .as_arr()?
        .first()?;
    Some((
        first.get("certificateFile")?.as_str()?,
        first.get("keyFile")?.as_str()?,
    ))
}

pub(crate) fn vless_header(id: &[u8; 16], cmd: u8, target: &SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(30);
    header.push(0);
    header.extend_from_slice(id);
    header.push(0);
    header.push(cmd);
    header.extend_from_slice(&target.port().to_be_bytes());
    push_addr(&mut header, target, 3);
    header
}

pub(crate) fn vless_mux_header(id: &[u8; 16]) -> Vec<u8> {
    let mut header = Vec::with_capacity(19);
    header.push(0);
    header.extend_from_slice(id);
    header.push(0);
    header.push(3);
    header
}

fn dial_vless(client: &TcpStream, mut uplink: TcpStream, vless: &VlessOut, target: &SocketAddr) {
    let header = vless_header(&vless.id, 1, target);
    match &vless.carrier {
        Carrier::Ws { path, ed } => {
            let Some((mut reader, writer)) =
                crate::ws::connect(uplink, &vless.host, path, *ed, &header)
            else {
                return;
            };
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, client, |_| {});
        }
        Carrier::HttpUpgrade { path } => {
            let Some((mut reader, mut write)) =
                crate::httpupgrade::connect(uplink, &vless.host, path)
            else {
                return;
            };
            if write.write_all(&header).is_err() {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, client);
        }
        Carrier::Grpc { path } => {
            let Some((mut reader, writer)) = crate::grpc::connect(uplink, &vless.host, path) else {
                return;
            };
            if !writer.send(&header) {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, client, crate::grpc::mark_reader_dead);
        }
        Carrier::Xhttp { path } => {
            let Some((mut reader, writer)) = crate::xhttp::connect(uplink, &vless.host, path)
            else {
                return;
            };
            if !writer.send(&header) {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::proxy::relay_sink_drained(reader, &writer, client);
        }
        Carrier::HttpHeader { path } => {
            let Some((mut reader, mut write)) =
                crate::httpheader::connect(uplink, &vless.host, path)
            else {
                return;
            };
            if write.write_all(&header).is_err() {
                return;
            }
            if read_vless_response(&mut reader).is_none() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, client);
        }
        Carrier::Raw => {
            if uplink.write_all(&header).is_err() {
                return;
            }
            if read_vless_response(&mut uplink).is_none() {
                return;
            }
            relay(client, &uplink);
        }
        refused_carriers!() => {}
    }
}

// KCP carries the same protocol bytes as TCP over a reliable UDP stream.
#[derive(Clone)]
struct KcpIo {
    conn: Arc<ferrox_core::kcp::Connection>,
}

impl KcpIo {
    fn close(&self) {
        self.conn.close();
    }
}

impl Read for KcpIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.conn
            .read(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }
}

impl Write for KcpIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.conn
            .write(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn kcp_relay(tcp: &TcpStream, conn: &Arc<ferrox_core::kcp::Connection>) {
    let Ok(tcp_read) = tcp.try_clone() else {
        return;
    };
    let Ok(mut tcp_write) = tcp.try_clone() else {
        return;
    };
    let up = Arc::clone(conn);
    let done = RelayPool::global().run(move || {
        let mut tcp_read = tcp_read;
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up.write(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        up.close();
    });
    let mut buf = vec![0u8; 16384];
    loop {
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if tcp_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = tcp_write.shutdown(Shutdown::Write);
    join(&done);
}

fn serve_vless_kcp(conn: &Arc<ferrox_core::kcp::Connection>, id: &[u8; 16], freedom: bool) {
    let mut io = KcpIo {
        conn: Arc::clone(conn),
    };
    let Some((got, _flow, cmd, target)) = decode_request(&mut io) else {
        return;
    };
    if got != *id || !freedom || cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if conn.write(&[0, 0]).is_err() {
        return;
    }
    kcp_relay(&uplink, conn);
}

/// One Hysteria v2 protocol flow: the request's address is the destination,
/// the answer is Xray's order — acknowledge, then dial; a refused dial closes
/// the stream after the acknowledgement, so the client reads EOF, not a refusal.
fn serve_hysteria_flow(mut flow: crate::hysteria::Flow, freedom: bool) {
    if !freedom {
        return;
    }
    let deadline = std::time::Instant::now() + crate::quic::HANDSHAKE_TIMEOUT;
    let Some(address) = crate::hysteria::read_request(&mut flow, deadline) else {
        return;
    };
    let mut ok = Vec::with_capacity(3);
    ferrox_core::hysteria::encode_tcp_response(true, &[], &[], &mut ok);
    if flow.write_all(&ok).is_err() {
        return;
    }
    let Some(target) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        flow.close();
        return;
    };
    let Some(uplink) = dial_or_report(&target) else {
        flow.close();
        return;
    };
    crate::hysteria::relay(&uplink, &flow);
}

/// The `hysteria` protocol inbound: version 2 over the hysteria transport,
/// with the users' passwords as the accepted auths. Anything else named
/// `hysteria` is refused by name rather than answered wrongly.
fn serve_hysteria_inbound(address: &str, inbound: &Json, freedom: bool, path: &str) -> bool {
    let settings = inbound.get("settings");
    if settings
        .and_then(|node| node.get("version"))
        .and_then(Json::as_u32)
        != Some(2)
    {
        eprintln!("hysteria inbound in {path} is not version 2: serves nothing");
        return false;
    }
    let auths: Vec<String> = settings
        .and_then(|node| node.get("users"))
        .and_then(Json::as_arr)
        .map(|users| {
            users
                .iter()
                .filter_map(|user| user.get("auth").and_then(Json::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if auths.is_empty() {
        eprintln!("hysteria inbound in {path} names no user auth: serves nothing");
        return false;
    }
    let Some(stream) = inbound.get("streamSettings") else {
        eprintln!("hysteria inbound in {path} carries no transport: serves nothing");
        return false;
    };
    if stream.get("network").and_then(Json::as_str) != Some("hysteria") {
        eprintln!("hysteria inbound in {path} is not on the hysteria transport: serves nothing");
        return false;
    }
    let Some((cert_path, key_path)) = tls_cert_paths(stream) else {
        eprintln!("unreadable hysteria identity in {path}: serves nothing");
        return false;
    };
    let (cert_path, key_path) = (cert_path.to_owned(), key_path.to_owned());
    let owned = address.to_owned();
    let serve: crate::hysteria::Serve = Arc::new(move |flow| {
        serve_hysteria_flow(flow, freedom);
    });
    thread::spawn(move || {
        crate::hysteria::serve_loop(
            &owned,
            &auths,
            ferrox_core::hysteria::Congestion::Bbr,
            &cert_path,
            &key_path,
            &serve,
        );
    });
    true
}

fn serve_vless_hysteria(mut flow: crate::hysteria::Flow, id: &[u8; 16], freedom: bool) {
    let Some((got, _flow, cmd, target)) = decode_request(&mut flow) else {
        return;
    };
    if got != *id || !freedom || cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    if flow.write_all(&[0, 0]).is_err() {
        return;
    }
    crate::hysteria::relay(&uplink, &flow);
}

fn hysteria_dial_session(vless: &VlessOut) -> Option<crate::hysteria::Dial> {
    let Carrier::Hysteria(config) = &vless.carrier else {
        return None;
    };
    Some(crate::hysteria::Dial {
        host: vless.host.clone(),
        address: vless.address.clone(),
        port: vless.port,
        config: config.clone(),
        roots: vless.hysteria_roots.clone(),
    })
}

fn dial_vless_kcp(
    client: &TcpStream,
    conn: &Arc<ferrox_core::kcp::Connection>,
    vless: &VlessOut,
    target: &SocketAddr,
) {
    let header = vless_header(&vless.id, 1, target);
    if conn.write(&header).is_err() {
        return;
    }
    let mut io = KcpIo {
        conn: Arc::clone(conn),
    };
    if read_vless_response(&mut io).is_none() {
        return;
    }
    kcp_relay(client, conn);
}

fn serve_vless_kcp_tls(
    conn: &Arc<ferrox_core::kcp::Connection>,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::TlsServerConfig,
) {
    serve_carried_tls(
        KcpIo {
            conn: Arc::clone(conn),
        },
        id,
        freedom,
        server,
    );
}

fn serve_vless_kcp_reality(
    conn: &Arc<ferrox_core::kcp::Connection>,
    id: &[u8; 16],
    freedom: bool,
    server: &ferrox_core::tls::RealityServerConfig,
) {
    let Ok(session) = ferrox_core::tls::RealityServer::accept(
        server,
        unix_now(),
        KcpIo {
            conn: Arc::clone(conn),
        },
    ) else {
        return;
    };
    finish_reality(session, None, id, freedom);
}

fn serve_trojan_kcp(conn: &Arc<ferrox_core::kcp::Connection>, key: &[u8; 56], freedom: bool) {
    let mut io = KcpIo {
        conn: Arc::clone(conn),
    };
    let Some((cmd, target)) = decode_trojan_request(&mut io, key) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    kcp_relay(&uplink, conn);
}

fn kcp_dial_session(
    carrier: &Carrier,
    address: &str,
    port: u16,
) -> Option<Arc<ferrox_core::kcp::Connection>> {
    let Carrier::Kcp(config) = carrier else {
        return None;
    };
    let endpoint = format!("{address}:{port}");
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    ferrox_core::kcp::dial(server, *config, ferrox_core::kcp::fresh_conversation()).ok()
}

fn dial_trojan_kcp(
    client: &TcpStream,
    conn: &Arc<ferrox_core::kcp::Connection>,
    trojan: &TrojanOut,
    target: &SocketAddr,
) {
    if conn.write(&trojan_header(&trojan.key, 1, target)).is_err() {
        return;
    }
    kcp_relay(client, conn);
}

fn dial_vmess_kcp(
    client: &TcpStream,
    conn: &Arc<ferrox_core::kcp::Connection>,
    vmess: &VmessOut,
    target: &SocketAddr,
) {
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return;
    };
    if conn.write(&request).is_err() {
        return;
    }
    let mut reader = KcpIo {
        conn: Arc::clone(conn),
    };
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return;
    }
    let (_, writer, close) = kcp_parts(conn);
    crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn dial_ss_kcp(
    client: &TcpStream,
    conn: &Arc<ferrox_core::kcp::Connection>,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
) {
    let mut writer = KcpIo {
        conn: Arc::clone(conn),
    };
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let (reader, _, close) = kcp_parts(conn);
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn serve_kcp_loop(address: &str, config: ferrox_core::kcp::Config, serve: &KcpServe) {
    let Some(server) = address.to_socket_addrs().ok().and_then(|mut it| it.next()) else {
        return;
    };
    let Ok(listener) = ferrox_core::kcp::Listener::bind(server, config) else {
        return;
    };
    serve_kcp_each(&listener, serve);
}

fn serve_kcp_each(listener: &ferrox_core::kcp::Listener, serve: &KcpServe) {
    loop {
        let Ok(session) = listener.accept() else {
            continue;
        };
        let serve = Arc::clone(serve);
        std::thread::spawn(move || serve(&session));
    }
}

type KcpServe = Arc<dyn Fn(&Arc<ferrox_core::kcp::Connection>) + Send + Sync>;

type KcpClose = Arc<dyn Fn() + Send + Sync>;

fn kcp_parts(conn: &Arc<ferrox_core::kcp::Connection>) -> (KcpIo, KcpIo, KcpClose) {
    let reader = KcpIo {
        conn: Arc::clone(conn),
    };
    let writer = KcpIo {
        conn: Arc::clone(conn),
    };
    let closer = KcpIo {
        conn: Arc::clone(conn),
    };
    let close: KcpClose = Arc::new(move || closer.close());
    (reader, writer, close)
}

fn serve_trojan_inbound(address: &str, inbound: &Json, freedom: bool) {
    let key = trojan_key(&inbound_password(inbound));
    match inbound_carrier(inbound) {
        Carrier::Kcp(config) => {
            let serve: KcpServe = Arc::new(move |conn| serve_trojan_kcp(conn, &key, freedom));
            let owned = address.to_owned();
            thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        }
        other => spawn_role(
            address,
            Role::Trojan {
                key,
                carrier: other,
                freedom,
            },
        ),
    }
}

fn serve_vmess_inbound(address: &str, inbound: &Json, freedom: bool) {
    let id = inbound_id(inbound);
    match inbound_carrier(inbound) {
        Carrier::Kcp(config) => {
            let serve: KcpServe = Arc::new(move |conn| {
                let (reader, writer, close) = kcp_parts(conn);
                crate::vmess::serve_kcp(reader, writer, &id, freedom, &close);
            });
            let owned = address.to_owned();
            thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        }
        other => spawn_role(
            address,
            Role::Vmess {
                id,
                carrier: other,
                freedom,
            },
        ),
    }
}

fn serve_shadowsocks_inbound(address: &str, inbound: &Json, freedom: bool) {
    let password = inbound_ss_password(inbound);
    let method = inbound_method(inbound);
    let carrier = inbound_carrier(inbound);
    let udp_raw = matches!(carrier, Carrier::Raw);
    let udp_address = address.to_owned();
    let udp_password = password.clone();
    let udp_method = method.clone();
    match carrier {
        Carrier::Kcp(config) => {
            let serve: KcpServe = Arc::new(move |conn| {
                let (reader, writer, close) = kcp_parts(conn);
                crate::shadowsocks::serve_kcp(reader, writer, &password, &method, freedom, &close);
            });
            let owned = address.to_owned();
            thread::spawn(move || serve_kcp_loop(&owned, config, &serve));
        }
        other => spawn_role(
            address,
            Role::Shadowsocks {
                password,
                method,
                carrier: other,
                freedom,
            },
        ),
    }
    if udp_raw {
        thread::spawn(move || {
            crate::shadowsocks::serve_udp(&udp_address, &udp_password, &udp_method, freedom);
        });
    }
}

struct UdpUplink {
    write: TcpStream,
    target: SocketAddr,
    done: std::sync::mpsc::Receiver<()>,
}

fn dial_udp_uplink(
    vless: &VlessOut,
    dest: &SocketAddr,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<UdpUplink> {
    if !matches!(vless.carrier, Carrier::Raw) {
        return None;
    }
    let endpoint = format!("{}:{}", vless.address, vless.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    let mut uplink = dial_or_report(&server)?;
    uplink.write_all(&vless_header(&vless.id, 2, dest)).ok()?;
    read_vless_response(&mut uplink)?;
    let Ok(read) = uplink.try_clone() else {
        return None;
    };
    let Ok(udp_send) = relay.try_clone() else {
        return None;
    };
    let done = spawn_udp_uplink_reader(read, udp_send, source, *dest);
    Some(UdpUplink {
        write: uplink,
        target: *dest,
        done,
    })
}

fn spawn_udp_uplink_reader(
    read: TcpStream,
    udp: UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
    target: SocketAddr,
) -> std::sync::mpsc::Receiver<()> {
    RelayPool::global().run(move || {
        let mut read = read;
        let mut buf = vec![0u8; UDP_BUF];
        let mut reply = Vec::with_capacity(UDP_BUF);
        while let Some(n) = read_udp_datagram(&mut read, &mut buf) {
            let dest = match source.lock() {
                Ok(guard) => *guard,
                Err(_) => None,
            };
            let Some(dest) = dest else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            push_socks_addr(&mut reply, &target);
            reply.extend_from_slice(&buf[..n]);
            let _ = udp.send_to(&reply, dest);
        }
    })
}

struct VmessUdpUplink {
    write: TcpStream,
    send: crate::vmess::Flow,
    pad: crate::vmess::PadSource,
    target: SocketAddr,
    done: std::sync::mpsc::Receiver<()>,
}

fn dial_vmess_udp_uplink(
    vmess: &VmessOut,
    dest: &SocketAddr,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<VmessUdpUplink> {
    if !matches!(vmess.carrier, Carrier::Raw) {
        return None;
    }
    let endpoint = format!("{}:{}", vmess.address, vmess.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    let uplink = dial_or_report(&server)?;
    let (request, send, recv, response_key, response_iv, auth) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, dest, 2)?;
    let mut uplink = uplink;
    uplink.write_all(&request).ok()?;
    let mut reader = uplink.try_clone().ok()?;
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return None;
    }
    let udp_send = relay.try_clone().ok()?;
    let done = spawn_vmess_udp_reader(reader, udp_send, source, *dest, recv);
    let pad = crate::vmess::PadSource::fresh()?;
    Some(VmessUdpUplink {
        write: uplink,
        send,
        pad,
        target: *dest,
        done,
    })
}

fn spawn_vmess_udp_reader(
    read: TcpStream,
    udp: UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
    target: SocketAddr,
    recv: crate::vmess::Flow,
) -> std::sync::mpsc::Receiver<()> {
    RelayPool::global().run(move || {
        let mut read = read;
        let mut recv = recv;
        let mut scratch = Vec::with_capacity(UDP_BUF);
        let mut reply = Vec::with_capacity(UDP_BUF);
        while let Some(chunk) = crate::vmess::read_frame(&mut read, &mut recv, &mut scratch) {
            if chunk.is_empty() {
                break;
            }
            let dest = match source.lock() {
                Ok(guard) => *guard,
                Err(_) => None,
            };
            let Some(dest) = dest else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            push_socks_addr(&mut reply, &target);
            reply.extend_from_slice(chunk);
            let _ = udp.send_to(&reply, dest);
        }
    })
}

struct TrojanUdpUplink {
    write: TcpStream,
    done: std::sync::mpsc::Receiver<()>,
}

fn dial_trojan_udp_uplink(
    trojan: &TrojanOut,
    dest: &SocketAddr,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<TrojanUdpUplink> {
    if !matches!(trojan.carrier, Carrier::Raw) {
        return None;
    }
    let endpoint = format!("{}:{}", trojan.address, trojan.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    let mut uplink = dial_or_report(&server)?;
    uplink
        .write_all(&trojan_header(&trojan.key, 3, dest))
        .ok()?;
    let Ok(read) = uplink.try_clone() else {
        return None;
    };
    let Ok(udp_send) = relay.try_clone() else {
        return None;
    };
    let done = spawn_trojan_uplink_reader(read, udp_send, source);
    Some(TrojanUdpUplink {
        write: uplink,
        done,
    })
}

fn spawn_trojan_uplink_reader(
    read: TcpStream,
    udp: UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> std::sync::mpsc::Receiver<()> {
    RelayPool::global().run(move || {
        let mut read = read;
        let mut buf = vec![0u8; UDP_BUF];
        let mut reply = Vec::with_capacity(UDP_BUF);
        while let Some((src_addr, n)) = read_trojan_datagram(&mut read, &mut buf) {
            let dest = match source.lock() {
                Ok(guard) => *guard,
                Err(_) => None,
            };
            let Some(dest) = dest else {
                continue;
            };
            reply.clear();
            reply.extend_from_slice(&[0, 0, 0]);
            push_socks_addr(&mut reply, &src_addr);
            reply.extend_from_slice(&buf[..n]);
            let _ = udp.send_to(&reply, dest);
        }
    })
}

fn mux_dial_downlink(mut down: TcpStream, mut up: TcpStream, id: u16) {
    let mut buf: Vec<u8> = Vec::new();
    let mut at = 0;
    let mut probe = [0u8; 8192];
    loop {
        if at >= buf.len() {
            buf.clear();
            at = 0;
        } else if at > 0 {
            buf.drain(..at);
            at = 0;
        }
        let mut progressed = false;
        loop {
            match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                Err(ferrox_core::mux::Error::Short { .. }) => break,
                Err(_) => return,
                Ok((frame, used)) => {
                    at += used;
                    progressed = true;
                    if frame.id != id {
                        continue;
                    }
                    match frame.status {
                        ferrox_core::mux::Status::Keep => {
                            if let Some(data) = frame.data {
                                if up.write_all(data).is_err() {
                                    return;
                                }
                            }
                        }
                        ferrox_core::mux::Status::End => {
                            let _ = up.shutdown(Shutdown::Write);
                            return;
                        }
                        _ => {}
                    }
                }
            }
        }
        if !progressed {
            match down.read(&mut probe) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&probe[..n]),
            }
        }
    }
}

fn mux_dial_uplink(client: &TcpStream, uplink: &mut TcpStream, id: u16) {
    let mut chunk = [0u8; 8192];
    let mut scratch = Vec::with_capacity(8192);
    let Ok(mut plain) = client.try_clone() else {
        return;
    };
    loop {
        match plain.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let keep = ferrox_core::mux::Outgoing {
                    id,
                    status: ferrox_core::mux::Status::Keep,
                    options: ferrox_core::mux::DATA,
                    target: None,
                    global_id: None,
                };
                resize_scratch(&mut scratch, keep.frame_len(n));
                let written = keep.encode_into(Some(&chunk[..n]), &mut scratch);
                if uplink.write_all(&scratch[..written]).is_err() {
                    break;
                }
            }
        }
    }
    let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
    resize_scratch(&mut scratch, end.frame_len(0));
    let written = end.encode_into(None, &mut scratch);
    let _ = uplink.write_all(&scratch[..written]);
    let _ = uplink.shutdown(Shutdown::Both);
}

fn request_vless_mux(mut uplink: TcpStream, vless: &VlessOut) -> Option<TcpStream> {
    if !matches!(vless.carrier, Carrier::Raw) {
        return None;
    }
    uplink.write_all(&vless_mux_header(&vless.id)).ok()?;
    read_vless_response(&mut uplink)?;
    Some(uplink)
}

fn open_vless_mux(vless: &VlessOut) -> Option<TcpStream> {
    let endpoint = format!("{}:{}", vless.address, vless.port);
    let server = endpoint.to_socket_addrs().ok()?.next()?;
    request_vless_mux(dial_or_report(&server)?, vless)
}

fn dial_vless_mux(client: &TcpStream, uplink: TcpStream, vless: &VlessOut, target: &SocketAddr) {
    let Some(mut uplink) = request_vless_mux(uplink, vless) else {
        return;
    };
    let mut ids = ferrox_core::mux::Ids::new(1);
    let Ok(id) = ids.take() else {
        return;
    };
    let addr = match target.ip() {
        std::net::IpAddr::V4(octets) => ferrox_core::addr::Addr::V4(octets.octets()),
        std::net::IpAddr::V6(octets) => ferrox_core::addr::Addr::V6(octets.octets()),
    };
    let dest = ferrox_core::mux::Target {
        network: ferrox_core::mux::Network::Tcp,
        port: target.port(),
        addr,
    };
    let new = ferrox_core::mux::Outgoing {
        id,
        status: ferrox_core::mux::Status::New,
        options: 0,
        target: Some(dest),
        global_id: None,
    };
    let mut frame = vec![0u8; new.frame_len(0)];
    let written = new.encode_into(None, &mut frame);
    if uplink.write_all(&frame[..written]).is_err() {
        return;
    }
    let Ok(down) = uplink.try_clone() else {
        return;
    };
    let Ok(up) = client.try_clone() else {
        return;
    };
    let done = RelayPool::global().run(move || mux_dial_downlink(down, up, id));
    mux_dial_uplink(client, &mut uplink, id);
    join(&done);
}

fn dial_vmess_httpupgrade(
    client: &TcpStream,
    uplink: TcpStream,
    vmess: &VmessOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((mut reader, mut write)) = crate::httpupgrade::connect(uplink, &vmess.host, path)
    else {
        return;
    };
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return;
    };
    if write.write_all(&request).is_err() {
        return;
    }
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return;
    }
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::vmess::pump_relay_carried(client, reader, write, &close, send, recv);
}

fn dial_vmess_grpc(
    client: &TcpStream,
    uplink: TcpStream,
    vmess: &VmessOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((mut reader, writer)) = crate::grpc::connect(uplink, &vmess.host, path) else {
        return;
    };
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return;
    };
    if !writer.send(&request) {
        return;
    }
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn dial_vmess_ws(
    client: &TcpStream,
    uplink: TcpStream,
    vmess: &VmessOut,
    target: &SocketAddr,
    path: &str,
    ed: u32,
) {
    let Some((request, send, recv, response_key, response_iv, auth)) =
        crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
    else {
        return;
    };
    let Some((mut reader, writer)) = crate::ws::connect(uplink, &vmess.host, path, ed, &request)
    else {
        return;
    };
    if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::vmess::pump_relay_carried(
        client,
        reader,
        crate::vmess::WsSink::carried(writer),
        &close,
        send,
        recv,
    );
}

fn dial_vmess(client: &TcpStream, mut uplink: TcpStream, vmess: &VmessOut, target: &SocketAddr) {
    match &vmess.carrier {
        Carrier::Ws { path, ed } => dial_vmess_ws(client, uplink, vmess, target, path, *ed),
        Carrier::Xhttp { path } => {
            let Some((mut reader, writer)) = crate::xhttp::connect(uplink, &vmess.host, path)
            else {
                return;
            };
            let Some((request, send, recv, response_key, response_iv, auth)) =
                crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
            else {
                return;
            };
            if !writer.send(&request) {
                return;
            }
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return;
            }
            let closer = writer.clone();
            let close: std::sync::Arc<dyn Fn() + Send + Sync> =
                std::sync::Arc::new(move || closer.finish());
            let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
            crate::vmess::pump_relay_carried(client, reader, writer, &close, send, recv);
        }
        Carrier::HttpHeader { path } => {
            let Some((mut reader, mut write)) =
                crate::httpheader::connect(uplink, &vmess.host, path)
            else {
                return;
            };
            let Some((request, send, recv, response_key, response_iv, auth)) =
                crate::vmess::client_request(&vmess.id, vmess.cipher, target, 1)
            else {
                return;
            };
            if write.write_all(&request).is_err() {
                return;
            }
            if !crate::vmess::read_response(&mut reader, &response_key, &response_iv, auth) {
                return;
            }
            let Ok(closer) = write.try_clone() else {
                return;
            };
            let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
                let _ = closer.shutdown(Shutdown::Both);
            });
            crate::vmess::pump_relay_carried(client, reader, write, &close, send, recv);
        }
        Carrier::Raw => {
            let Some((send, recv, response_key, response_iv, auth)) =
                crate::vmess::client_handshake(&mut uplink, &vmess.id, vmess.cipher, target)
            else {
                return;
            };
            crate::vmess::pump_relay(
                client,
                &uplink,
                send,
                recv,
                Some((response_key, response_iv, auth)),
            );
        }
        refused_carriers!() => {}
        Carrier::HttpUpgrade { path } => {
            dial_vmess_httpupgrade(client, uplink, vmess, target, path);
        }
        Carrier::Grpc { path } => {
            dial_vmess_grpc(client, uplink, vmess, target, path);
        }
    }
}

fn trojan_header(key: &[u8; 56], cmd: u8, target: &SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(80);
    header.extend_from_slice(key);
    header.extend_from_slice(b"\r\n");
    header.push(cmd);
    push_addr(&mut header, target, 4);
    header.extend_from_slice(&target.port().to_be_bytes());
    header.extend_from_slice(b"\r\n");
    header
}

fn dial_trojan(client: &TcpStream, mut uplink: TcpStream, trojan: &TrojanOut, target: &SocketAddr) {
    let header = trojan_header(&trojan.key, 1, target);
    match &trojan.carrier {
        Carrier::Ws { path, ed } => {
            let Some((reader, writer)) =
                crate::ws::connect(uplink, &trojan.host, path, *ed, &header)
            else {
                return;
            };
            crate::proxy::relay_sink(reader, &writer, client, |_| {});
        }
        Carrier::Raw => {
            if uplink.write_all(&header).is_err() {
                return;
            }
            relay(client, &uplink);
        }
        refused_carriers!() => {}
        Carrier::HttpUpgrade { path } => {
            let Some((reader, mut write)) = crate::httpupgrade::connect(uplink, &trojan.host, path)
            else {
                return;
            };
            if write.write_all(&header).is_err() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, client);
        }
        Carrier::Grpc { path } => {
            let Some((reader, writer)) = crate::grpc::connect(uplink, &trojan.host, path) else {
                return;
            };
            if !writer.send(&header) {
                return;
            }
            crate::proxy::relay_sink(reader, &writer, client, crate::grpc::mark_reader_dead);
        }
        Carrier::Xhttp { path } => {
            let Some((reader, writer)) = crate::xhttp::connect(uplink, &trojan.host, path) else {
                return;
            };
            if !writer.send(&header) {
                return;
            }
            crate::proxy::relay_sink_drained(reader, &writer, client);
        }
        Carrier::HttpHeader { path } => {
            let Some((reader, mut write)) = crate::httpheader::connect(uplink, &trojan.host, path)
            else {
                return;
            };
            if write.write_all(&header).is_err() {
                return;
            }
            crate::proxy::relay_carried(reader, &write, client);
        }
    }
}

fn dial_shadowsocks(
    client: &TcpStream,
    uplink: TcpStream,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
) {
    match &ss.carrier {
        Carrier::Raw => {
            let mut uplink = uplink;
            let Some((send, recv)) = crate::shadowsocks::client_send_handshake(
                &mut uplink,
                &ss.password,
                &ss.method,
                target,
            ) else {
                return;
            };
            crate::shadowsocks::pump_relay(client, &uplink, send, recv);
        }
        refused_carriers!() => {}
        Carrier::Ws { path, .. } => {
            dial_ss_ws(client, uplink, ss, target, path);
        }
        Carrier::HttpUpgrade { path } => {
            dial_ss_httpupgrade(client, uplink, ss, target, path);
        }
        Carrier::Grpc { path } => {
            dial_ss_grpc(client, uplink, ss, target, path);
        }
        Carrier::Xhttp { path } => {
            dial_ss_xhttp(client, uplink, ss, target, path);
        }
        Carrier::HttpHeader { path } => {
            dial_ss_httpheader(client, uplink, ss, target, path);
        }
    }
}

fn dial_ss_ws(
    client: &TcpStream,
    uplink: TcpStream,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((reader, mut writer)) = crate::ws::connect(uplink, &ss.host, path, 0, &[]) else {
        return;
    };
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn dial_ss_httpupgrade(
    client: &TcpStream,
    uplink: TcpStream,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((reader, mut writer)) = crate::httpupgrade::connect(uplink, &ss.host, path) else {
        return;
    };
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn dial_ss_grpc(
    client: &TcpStream,
    uplink: TcpStream,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((reader, mut writer)) = crate::grpc::connect(uplink, &ss.host, path) else {
        return;
    };
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn dial_ss_xhttp(
    client: &TcpStream,
    uplink: TcpStream,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((reader, mut writer)) = crate::xhttp::connect(uplink, &ss.host, path) else {
        return;
    };
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn dial_ss_httpheader(
    client: &TcpStream,
    uplink: TcpStream,
    ss: &ShadowsocksOut,
    target: &SocketAddr,
    path: &str,
) {
    let Some((reader, mut writer)) = crate::httpheader::connect(uplink, &ss.host, path) else {
        return;
    };
    let Some((send, recv)) =
        crate::shadowsocks::client_send_handshake(&mut writer, &ss.password, &ss.method, target)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    crate::shadowsocks::pump_relay_carried(client, reader, writer, &close, send, recv);
}

fn serve_trojan(mut stream: TcpStream, key: &[u8; 56], freedom: bool) {
    let Some((cmd, target)) = decode_trojan_request(&mut stream, key) else {
        return;
    };
    if !freedom {
        return;
    }
    if cmd == 3 {
        return serve_trojan_udp(stream);
    }
    if cmd != 1 {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    relay(&stream, &uplink);
}

fn serve_trojan_udp(stream: TcpStream) {
    let Ok(udp4) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    let udp6 = UdpSocket::bind("[::]:0").ok();
    for sock in [&udp4].into_iter().chain(udp6.as_ref()) {
        if sock.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
    }
    let mut stream = stream;
    let Ok(tcp_read) = stream.try_clone() else {
        return;
    };
    let Ok(udp4_send) = udp4.try_clone() else {
        return;
    };
    let udp6_send = match &udp6 {
        Some(sock) => {
            let Ok(clone) = sock.try_clone() else {
                return;
            };
            Some(clone)
        }
        None => None,
    };
    let done = Arc::new(AtomicBool::new(false));
    let done_in = Arc::clone(&done);
    let forward = move || {
        let mut tcp_read = tcp_read;
        let mut buf = vec![0u8; UDP_BUF];
        while let Some((dest, n)) = read_trojan_datagram(&mut tcp_read, &mut buf) {
            let sent = if dest.is_ipv6() {
                match &udp6_send {
                    Some(sock) => sock.send_to(&buf[..n], dest).is_ok(),
                    None => true,
                }
            } else {
                udp4_send.send_to(&buf[..n], dest).is_ok()
            };
            if !sent {
                break;
            }
        }
        done_in.store(true, Ordering::Relaxed);
    };
    let replied = RelayPool::global().run(forward);
    let mut buf = vec![0u8; UDP_BUF];
    let mut trojan_head = Vec::with_capacity(32);
    loop {
        if done.load(Ordering::Relaxed) {
            break;
        }
        let mut live = pump_trojan_replies(&udp4, &mut stream, &mut buf, &done, &mut trojan_head);
        if let Some(sock) = &udp6 {
            live &= pump_trojan_replies(sock, &mut stream, &mut buf, &done, &mut trojan_head);
        }
        if !live {
            break;
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(Shutdown::Both);
    join(&replied);
}

fn pump_trojan_replies(
    udp: &UdpSocket,
    stream: &mut TcpStream,
    buf: &mut [u8],
    done: &AtomicBool,
    head: &mut Vec<u8>,
) -> bool {
    match udp.recv_from(buf) {
        Ok((n, src)) => {
            if n == 0 {
                return true;
            }
            write_trojan_datagram(stream, &src, &buf[..n], head)
        }
        Err(error) if is_timeout(&error) => !done.load(Ordering::Relaxed),
        Err(_) => false,
    }
}

fn serve_trojan_ws(stream: TcpStream, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_sink(reader, &writer, &uplink, |_| {});
}

fn serve_trojan_httpupgrade(stream: TcpStream, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, write)) = crate::httpupgrade::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_carried(reader, &write, &uplink);
}

fn serve_trojan_grpc(stream: TcpStream, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_sink(reader, &writer, &uplink, crate::grpc::mark_reader_dead);
}

fn serve_trojan_xhttp(stream: TcpStream, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_sink_drained(reader, &writer, &uplink);
}

fn serve_trojan_httpheader(stream: TcpStream, key: &[u8; 56], path: &str, freedom: bool) {
    let Some((mut reader, write)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((cmd, target)) = decode_trojan_request(&mut reader, key) else {
        return;
    };
    if cmd != 1 || !freedom {
        return;
    }
    let Some(uplink) = dial_or_report(&target) else {
        return;
    };
    crate::proxy::relay_carried(reader, &write, &uplink);
}

fn serve_socks(mut client: TcpStream, out: &Outbound) {
    let Some((cmd, asked)) = socks_target(&mut client) else {
        return;
    };
    if cmd == 3 {
        return serve_socks_udp(client, out);
    }
    if let Outbound::Foxy(foxy) = out {
        return serve_foxy(client, foxy, &asked);
    }
    let Some(target) = asked.socket() else {
        return;
    };
    let (address, port) = match out {
        Outbound::Vless(vless) => (vless.address.clone(), vless.port),
        Outbound::Vmess(vmess) => (vmess.address.clone(), vmess.port),
        Outbound::Trojan(trojan) => (trojan.address.clone(), trojan.port),
        Outbound::Shadowsocks(shadowsocks) => (shadowsocks.address.clone(), shadowsocks.port),
        Outbound::Foxy(_) | Outbound::Freedom => {
            let Some(upstream) = dial_or_report(&target) else {
                return;
            };
            relay(&client, &upstream);
            return;
        }
    };
    if let Outbound::Vless(vless) = out {
        if matches!(vless.carrier, Carrier::Quic) {
            if !vless.mux {
                crate::quic::dial_pooled(
                    &client,
                    &crate::quic::QuicDial {
                        id: vless.id,
                        host: vless.host.clone(),
                        address: vless.address.clone(),
                        port: vless.port,
                        roots: vless.quic_roots.clone(),
                    },
                    &target,
                );
            }
            return;
        }
        if matches!(vless.carrier, Carrier::Kcp(_)) && !vless.mux {
            if let Some(session) = kcp_dial_session(&vless.carrier, &vless.address, vless.port) {
                dial_vless_kcp(&client, &session, vless, &target);
            }
            return;
        }
        if matches!(vless.carrier, Carrier::Hysteria(_)) && !vless.mux {
            if let Some(dial) = hysteria_dial_session(vless) {
                crate::hysteria::dial_vless(&client, &dial, &vless.id, &target);
            }
            return;
        }
    }
    if let Outbound::Vmess(vmess) = out {
        if matches!(vmess.carrier, Carrier::Kcp(_)) {
            if let Some(session) = kcp_dial_session(&vmess.carrier, &vmess.address, vmess.port) {
                dial_vmess_kcp(&client, &session, vmess, &target);
            }
            return;
        }
    }
    if let Outbound::Trojan(trojan) = out {
        if matches!(trojan.carrier, Carrier::Kcp(_)) {
            if let Some(session) = kcp_dial_session(&trojan.carrier, &trojan.address, trojan.port) {
                dial_trojan_kcp(&client, &session, trojan, &target);
            }
            return;
        }
    }
    if let Outbound::Shadowsocks(ss) = out {
        if matches!(ss.carrier, Carrier::Kcp(_)) {
            if let Some(session) = kcp_dial_session(&ss.carrier, &ss.address, ss.port) {
                dial_ss_kcp(&client, &session, ss, &target);
            }
            return;
        }
    }
    let endpoint = format!("{address}:{port}");
    let server = endpoint.to_socket_addrs().ok().and_then(|mut it| it.next());
    let Some(server) = server else { return };
    let Some(uplink) = dial_or_report(&server) else {
        return;
    };
    match out {
        Outbound::Vless(vless) => {
            if vless.mux {
                dial_vless_mux(&client, uplink, vless, &target);
            } else {
                dial_vless(&client, uplink, vless, &target);
            }
        }
        Outbound::Vmess(vmess) => dial_vmess(&client, uplink, vmess, &target),
        Outbound::Trojan(trojan) => dial_trojan(&client, uplink, trojan, &target),
        Outbound::Shadowsocks(shadowsocks) => {
            dial_shadowsocks(&client, uplink, shadowsocks, &target);
        }
        Outbound::Foxy(_) | Outbound::Freedom => {}
    }
}

/// The split-tunnel list: the targets this lane does not carry. They leave by the
/// plain dial, which is the whole meaning of a split tunnel here.
fn foxy_splits(foxy: &FoxyOut, asked: &SocksTarget) -> bool {
    foxy.direct_ports.contains(&asked.port())
        || foxy
            .direct_suffixes
            .iter()
            .any(|suffix| asked.host().to_ascii_lowercase().ends_with(suffix))
}

fn foxy_socks_reply(reply: u8) -> [u8; 10] {
    [5, reply, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// How many edges past the first one a refusal may try, which is the count the
/// reference allows and the most a flow can be worth waiting for.
const MAX_FOXY_ALTERNATES: usize = 3;

/// Opens the tunnel on the first edge and carrier that answers, and relays.
/// Every edge of the pinned country is a candidate and the city's edges come
/// first, so a refusal moves along the tier rather than to another country.
/// Replaces the pass on the clock the pass itself names. One thread per lane,
/// started once, and it stops as soon as the pass can no longer be replaced.
fn start_renewal(account: std::sync::Arc<crate::foxy_account::Account>) {
    thread::spawn(move || loop {
        thread::sleep(account.renews_in());
        if let Err(denied) = account.renew() {
            eprintln!("foxy: the pass could not be replaced: {denied}");
            if matches!(
                denied,
                crate::foxy_account::Denied::Token | crate::foxy_account::Denied::Quota
            ) {
                return;
            }
        }
    });
}

fn serve_foxy(mut client: TcpStream, foxy: &FoxyOut, asked: &SocksTarget) {
    if foxy
        .unauthenticated
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        let _ = client.write_all(&foxy_socks_reply(0x01));
        return;
    }
    if foxy_splits(foxy, asked) {
        let Some(target) = asked.socket() else { return };
        let Some(upstream) = dial_or_report(&target) else {
            return;
        };
        return relay(&client, &upstream);
    }
    let target = asked.authority();
    let order = ferrox_core::foxy::catalog::tier(
        &foxy.candidates,
        &foxy.country,
        &foxy.city,
        MAX_FOXY_ALTERNATES,
    );
    let mut refusals = ferrox_core::foxy::Refusals::new(256);
    let key = target.clone();
    if refusals.blocked(&key, 0) {
        return;
    }
    let mut last = None;
    for edge in ferrox_core::foxy::dial_order(
        &order,
        &foxy.country,
        foxy.stored.as_ref(),
        MAX_FOXY_ALTERNATES,
    ) {
        let pass = foxy
            .account
            .as_ref()
            .map_or_else(|| foxy.pass.clone(), |account| account.current());
        for carrier in foxy.carrier.order() {
            let dial = crate::foxy::FoxyDial {
                host: edge.host.clone(),
                port: edge.port,
                address: foxy.edge_address,
                carrier,
                roots: foxy.roots.clone(),
                pins: foxy.pins.clone(),
                pass: pass.clone(),
            };
            let quic = match carrier {
                crate::foxy::Carrier::H3 => {
                    crate::quic::pooled_stream(&foxy_quic_dial(foxy, &edge))
                }
                _ => None,
            };
            let stream = quic.as_ref().map(|(_, _, _, id)| *id);
            match crate::foxy::Tunnel::open(&dial, &target, quic) {
                Ok(mut tunnel) => {
                    foxy.unauthenticated
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                    if client.write_all(&foxy_socks_reply(0)).is_err() {
                        return;
                    }
                    if !foxy_exit_agrees(&mut tunnel, foxy) {
                        return;
                    }
                    let tunnel = std::sync::Arc::new(std::sync::Mutex::new(tunnel));
                    relay_tunnel(&client, &tunnel);
                    if let (Some(id), crate::foxy::Carrier::H3) = (stream, carrier) {
                        crate::quic::release_stream(&foxy_quic_dial(foxy, &edge), id);
                    }
                    return;
                }
                Err(failure) => {
                    // A refused pass is the pass, not the edge: every carrier and
                    // every edge would answer the same way, so the loop stops.
                    if let ferrox_core::foxy::Failure::Rejected(status) = failure {
                        if ferrox_core::foxy::pass_is_rejected(status) {
                            foxy.unauthenticated
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        if ferrox_core::foxy::target_is_unreachable(status) {
                            refusals.remember(&key, now_secs() + 30);
                        }
                    }
                    last = Some(failure);
                }
            }
        }
    }
    let reply = last.map_or(0x01, crate::foxy::refusal_reply);
    let _ = client.write_all(&foxy_socks_reply(reply));
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Asks the tunnel where it exits, through the tunnel, and refuses the flow when
/// the answer is not the pinned country. A probe that cannot be answered is not
/// evidence, and the lane is left serving.
fn foxy_exit_agrees<T: Read + Write>(tunnel: &mut T, foxy: &FoxyOut) -> bool {
    let Some(probe) = foxy.exit_probe.as_deref() else {
        return true;
    };
    let Some((host, path)) = probe.split_once('/') else {
        return true;
    };
    let request = format!("GET /{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if tunnel.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    while !head.windows(2).any(|pair| pair == b"\n\n") && head.len() < 4096 {
        match tunnel.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    match crate::foxy::exit_country(&head) {
        Some(seen) => {
            foxy.country.eq_ignore_ascii_case("REC") || seen == foxy.country.to_ascii_uppercase()
        }
        None => true,
    }
}

fn socks_udp_relay(client: &mut TcpStream) -> Option<UdpSocket> {
    let local_ip = client
        .local_addr()
        .map_or(std::net::IpAddr::V4([127, 0, 0, 1].into()), |addr| {
            addr.ip()
        });
    let relay = UdpSocket::bind(SocketAddr::new(local_ip, 0)).ok()?;
    let relay_addr = relay.local_addr().ok()?;
    let mut reply = vec![5, 0, 0];
    push_socks_addr(&mut reply, &relay_addr);
    client.write_all(&reply).ok()?;
    relay.set_read_timeout(Some(UDP_IDLE)).ok()?;
    Some(relay)
}

fn serve_socks_udp(mut client: TcpStream, out: &Outbound) {
    let Some(relay) = socks_udp_relay(&mut client) else {
        return;
    };
    let _associate = client;
    match out {
        Outbound::Vless(vless) if matches!(vless.carrier, Carrier::Raw) => {
            serve_socks_udp_vless(&relay, vless);
        }
        Outbound::Trojan(trojan) if matches!(trojan.carrier, Carrier::Raw) => {
            serve_socks_udp_trojan(&relay, trojan);
        }
        Outbound::Vmess(vmess) if matches!(vmess.carrier, Carrier::Raw) => {
            serve_socks_udp_vmess(&relay, vmess);
        }
        Outbound::Shadowsocks(ss) if matches!(ss.carrier, Carrier::Raw) => {
            serve_socks_udp_shadowsocks(&relay, ss);
        }
        _ => {}
    }
}

fn serve_socks_udp_shadowsocks(relay: &UdpSocket, ss: &ShadowsocksOut) {
    let Some(method) = ferrox_core::shadowsocks::Method::parse(&ss.method) else {
        return;
    };
    let master = ferrox_core::shadowsocks::MasterKey::new(&ss.password, method.key_len());
    let server: SocketAddr = match format!("{}:{}", ss.address, ss.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(server) => server,
        None => return,
    };
    let bound = if server.is_ipv6() {
        UdpSocket::bind("[::]:0")
    } else {
        UdpSocket::bind("0.0.0.0:0")
    };
    let Ok(uplink) = bound else {
        return;
    };
    if uplink.connect(server).is_err() || uplink.set_read_timeout(Some(UDP_IDLE)).is_err() {
        return;
    }
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let done = Arc::new(AtomicBool::new(false));
    let Some(reader) = spawn_ss_udp_reader(
        &uplink,
        relay,
        &master,
        method,
        Arc::clone(&source),
        Arc::clone(&done),
    ) else {
        return;
    };
    let mut buf = vec![0u8; UDP_BUF];
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        if let Some(packet) = crate::shadowsocks::seal_udp_datagram(&master, method, &dest, payload)
        {
            let _ = uplink.send(&packet);
        }
    }
    done.store(true, Ordering::Relaxed);
    join(&reader);
}

fn spawn_ss_udp_reader(
    uplink: &UdpSocket,
    relay: &UdpSocket,
    master: &ferrox_core::shadowsocks::MasterKey,
    method: ferrox_core::shadowsocks::Method,
    source: Arc<Mutex<Option<SocketAddr>>>,
    done: Arc<AtomicBool>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let read = uplink.try_clone().ok()?;
    read.set_read_timeout(Some(RELAY_POLL)).ok()?;
    let send = relay.try_clone().ok()?;
    let master = master.clone();
    Some(RelayPool::global().run(move || {
        let mut buf = vec![0u8; UDP_BUF];
        let mut reply = Vec::with_capacity(UDP_BUF);
        loop {
            match read.recv(&mut buf) {
                Ok(n) => {
                    let Some((target, payload)) =
                        crate::shadowsocks::open_udp_datagram(&master, method, &buf[..n])
                    else {
                        continue;
                    };
                    let dest = match source.lock() {
                        Ok(guard) => *guard,
                        Err(_) => None,
                    };
                    let Some(dest) = dest else {
                        continue;
                    };
                    reply.clear();
                    reply.extend_from_slice(&[0, 0, 0]);
                    push_socks_addr(&mut reply, &target);
                    reply.extend_from_slice(&payload);
                    let _ = send.send_to(&reply, dest);
                }
                Err(error) if is_timeout(&error) => {
                    if done.load(Ordering::Relaxed) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }))
}

fn serve_socks_udp_vmess(relay: &UdpSocket, vmess: &VmessOut) {
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<VmessUdpUplink> = None;
    let mut staging = Vec::with_capacity(UDP_BUF);
    let mut buf = vec![0u8; UDP_BUF];
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        let redial = match &uplink {
            Some(up) => up.target != dest,
            None => true,
        };
        if redial {
            if let Some(old) = uplink.take() {
                let _ = old.write.shutdown(Shutdown::Both);
            }
            uplink = dial_vmess_udp_uplink(vmess, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !crate::vmess::write_frame(
                &mut up.write,
                &mut up.send,
                payload,
                &mut staging,
                &mut up.pad,
            ) {
                if let Some(old) = uplink.take() {
                    let _ = old.write.shutdown(Shutdown::Both);
                }
            }
        }
    }
    if let Some(old) = uplink.take() {
        let _ = old.write.shutdown(Shutdown::Both);
        join(&old.done);
    }
}

fn serve_socks_udp_vless(relay: &UdpSocket, vless: &VlessOut) {
    if vless.mux {
        return serve_socks_udp_vless_xudp(relay, vless);
    }
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<UdpUplink> = None;
    let mut buf = vec![0u8; UDP_BUF];
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        let redial = match &uplink {
            Some(up) => up.target != dest,
            None => true,
        };
        if redial {
            if let Some(old) = uplink.take() {
                let _ = old.write.shutdown(Shutdown::Both);
            }
            uplink = dial_udp_uplink(vless, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !write_udp_datagram(&mut up.write, payload) {
                if let Some(old) = uplink.take() {
                    let _ = old.write.shutdown(Shutdown::Both);
                }
            }
        }
    }
    if let Some(old) = uplink.take() {
        let _ = old.write.shutdown(Shutdown::Both);
        join(&old.done);
    }
}

fn xudp_identity(source: SocketAddr) -> [u8; ferrox_core::mux::GLOBAL_ID] {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    match source.ip() {
        std::net::IpAddr::V4(ip) => mix(&ip.octets()),
        std::net::IpAddr::V6(ip) => mix(&ip.octets()),
    }
    mix(&source.port().to_be_bytes());
    hash.to_be_bytes()
}

fn spawn_xudp_reader(
    read: TcpStream,
    relay: &UdpSocket,
    source: Arc<Mutex<Option<SocketAddr>>>,
) -> Option<std::sync::mpsc::Receiver<()>> {
    let reply = relay.try_clone().ok()?;
    Some(RelayPool::global().run(move || {
        let mut read = read;
        let mut buf: Vec<u8> = Vec::new();
        let mut at = 0;
        let mut probe = [0u8; 8192];
        let mut packet = Vec::with_capacity(UDP_BUF);
        loop {
            if at >= buf.len() {
                buf.clear();
                at = 0;
            } else if at > 0 {
                buf.drain(..at);
                at = 0;
            }
            let mut progressed = false;
            loop {
                match ferrox_core::mux::decode(&buf[at..], ferrox_core::mux::NewTail::Forward) {
                    Err(ferrox_core::mux::Error::Short { .. }) => break,
                    Err(_) => return,
                    Ok((frame, used)) => {
                        at += used;
                        progressed = true;
                        let Some(data) = frame.data else { continue };
                        let Some(target) = frame.target.and_then(|t| mux_target_addr(&t)) else {
                            continue;
                        };
                        let Some(dest) = source.lock().ok().and_then(|slot| *slot) else {
                            continue;
                        };
                        packet.clear();
                        packet.extend_from_slice(&[0, 0, 0]);
                        push_socks_addr(&mut packet, &target);
                        packet.extend_from_slice(data);
                        let _ = reply.send_to(&packet, dest);
                    }
                }
            }
            if !progressed {
                match read.read(&mut probe) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&probe[..n]),
                }
            }
        }
    }))
}

fn serve_socks_udp_vless_xudp(relay: &UdpSocket, vless: &VlessOut) {
    let Some(mut write) = open_vless_mux(vless) else {
        return;
    };
    let Ok(read) = write.try_clone() else {
        return;
    };
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let Some(done) = spawn_xudp_reader(read, relay, Arc::clone(&source)) else {
        return;
    };
    let mut buf = vec![0u8; UDP_BUF];
    let mut staging = Vec::with_capacity(UDP_BUF + 64);
    let mut identity: Option<[u8; ferrox_core::mux::GLOBAL_ID]> = None;
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        let first = identity.is_none();
        let identity = identity.get_or_insert_with(|| xudp_identity(src));
        let frame = ferrox_core::mux::Outgoing {
            id: 0,
            status: if first {
                ferrox_core::mux::Status::New
            } else {
                ferrox_core::mux::Status::Keep
            },
            options: ferrox_core::mux::DATA,
            target: Some(mux_target_of(dest)),
            global_id: if first { Some(*identity) } else { None },
        };
        resize_scratch(&mut staging, frame.frame_len(payload.len()));
        let written = frame.encode_into(Some(payload), &mut staging);
        if write.write_all(&staging[..written]).is_err() {
            break;
        }
    }
    let end = ferrox_core::mux::Outgoing::bare(0, ferrox_core::mux::Status::End, 0);
    resize_scratch(&mut staging, end.frame_len(0));
    let written = end.encode_into(None, &mut staging);
    let _ = write.write_all(&staging[..written]);
    let _ = write.shutdown(Shutdown::Both);
    join(&done);
}

fn serve_socks_udp_trojan(relay: &UdpSocket, trojan: &TrojanOut) {
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<TrojanUdpUplink> = None;
    let mut buf = vec![0u8; UDP_BUF];
    let mut trojan_head = Vec::with_capacity(32);
    while let Ok((n, src)) = relay.recv_from(&mut buf) {
        let Some((dest, payload)) = parse_socks_udp(&buf[..n]) else {
            continue;
        };
        if payload.is_empty() {
            continue;
        }
        if let Ok(mut slot) = source.lock() {
            *slot = Some(src);
        }
        if uplink.is_none() {
            uplink = dial_trojan_udp_uplink(trojan, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !write_trojan_datagram(&mut up.write, &dest, payload, &mut trojan_head) {
                if let Some(old) = uplink.take() {
                    let _ = old.write.shutdown(Shutdown::Both);
                }
            }
        }
    }
    if let Some(old) = uplink.take() {
        let _ = old.write.shutdown(Shutdown::Both);
        join(&old.done);
    }
}

/// The relay a CONNECT lane uses: the same two directions, against a tunnel
/// that is one stateful session rather than a socket, so both directions take
/// the same lock and each holds it for one bounded copy.
/// The QUIC dial a lane hands the pool: the edge's own name, not the address it
/// was resolved to, so every flow of one country shares one connection.
fn foxy_quic_dial(foxy: &FoxyOut, edge: &ferrox_core::foxy::Candidate) -> crate::quic::QuicDial {
    crate::quic::QuicDial {
        id: [0; 16],
        host: edge.host.clone(),
        address: edge.host.clone(),
        port: edge.port,
        roots: Some(foxy.roots.clone()),
    }
}

fn relay_tunnel(
    client: &TcpStream,
    tunnel: &std::sync::Arc<std::sync::Mutex<crate::foxy::Tunnel>>,
) {
    let Ok(mut client_read) = client.try_clone() else {
        return;
    };
    let Ok(mut client_write) = client.try_clone() else {
        return;
    };
    let forward_tunnel = std::sync::Arc::clone(tunnel);
    let backward_tunnel = std::sync::Arc::clone(tunnel);
    let forward = move || copy_locked(&mut client_read, &forward_tunnel, true);
    let done = RelayPool::global().run(forward);
    copy_locked(&mut client_write, &backward_tunnel, false);
    let _ = client_write.shutdown(Shutdown::Write);
    join(&done);
}

fn copy_locked(
    socket: &mut TcpStream,
    tunnel: &std::sync::Arc<std::sync::Mutex<crate::foxy::Tunnel>>,
    forward: bool,
) {
    const CHUNK: usize = 16 * 1024;
    let mut buf = [0u8; CHUNK];
    loop {
        let moved = if forward {
            match socket.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => match tunnel.lock() {
                    Ok(mut lane) => lane.write(&buf[..read]).unwrap_or(0),
                    Err(_) => 0,
                },
            }
        } else {
            let Ok(mut lane) = tunnel.lock() else { break };
            match lane.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => match socket.write_all(&buf[..read]) {
                    Ok(()) => read,
                    Err(_) => break,
                },
            }
        };
        if moved == 0 {
            break;
        }
    }
}

fn relay(client: &TcpStream, target: &TcpStream) {
    let Ok(client_read) = client.try_clone() else {
        return;
    };
    let Ok(target_read) = target.try_clone() else {
        return;
    };
    let Ok(target_write) = target.try_clone() else {
        return;
    };
    let Ok(client_write) = client.try_clone() else {
        return;
    };
    #[cfg(target_os = "linux")]
    if poll_relay::available() {
        poll_relay::drive(client_read, target_write, target_read, client_write);
        return;
    }
    let mut client_read = client_read;
    let mut target_write = target_write;
    let mut target_read = target_read;
    let mut client_write = client_write;
    let forward = move || {
        copy_all(&mut client_read, &mut target_write);
        let _ = target_write.shutdown(Shutdown::Write);
    };
    let done = RelayPool::global().run(forward);
    copy_all(&mut target_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    join(&done);
}

pub(crate) const UDP_IDLE: Duration = Duration::from_secs(120);

pub(crate) const UDP_BUF: usize = 65535;

fn read_udp_datagram(stream: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let mut len = [0u8; 2];
    read_exact(stream, &mut len).ok()?;
    let len = usize::from(u16::from_be_bytes(len));
    if len == 0 || len > buf.len() {
        return None;
    }
    read_exact(stream, &mut buf[..len]).ok()?;
    Some(len)
}

fn write_udp_datagram(stream: &mut TcpStream, payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return true;
    }
    let len = (payload.len() as u16).to_be_bytes();
    write_all_two(stream, &len, payload)
}

fn write_trojan_datagram(
    stream: &mut TcpStream,
    dest: &SocketAddr,
    payload: &[u8],
    head: &mut Vec<u8>,
) -> bool {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return true;
    }
    head.clear();
    push_socks_addr(head, dest);
    head.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    head.extend_from_slice(b"\r\n");
    write_all_two(stream, head, payload)
}

fn read_trojan_datagram(stream: &mut TcpStream, buf: &mut [u8]) -> Option<(SocketAddr, usize)> {
    let dest = read_socks_addr(stream)?;
    let mut len = [0u8; 2];
    read_exact(stream, &mut len).ok()?;
    let len = usize::from(u16::from_be_bytes(len));
    let mut crlf = [0u8; 2];
    read_exact(stream, &mut crlf).ok()?;
    if len == 0 || len > buf.len() || crlf != *b"\r\n" {
        return None;
    }
    read_exact(stream, &mut buf[..len]).ok()?;
    Some((dest, len))
}

fn serve_vless_udp(mut stream: TcpStream, target: &SocketAddr) {
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp) = UdpSocket::bind(bind) else {
        return;
    };
    if udp.connect(target).is_err() || udp.set_read_timeout(Some(UDP_IDLE)).is_err() {
        return;
    }
    if stream.write_all(&[0, 0]).is_err() {
        return;
    }
    let Ok(tcp_read) = stream.try_clone() else {
        return;
    };
    let Ok(udp_send) = udp.try_clone() else {
        return;
    };
    let done = Arc::new(AtomicBool::new(false));
    let done_in = Arc::clone(&done);
    let forward = move || {
        let mut tcp_read = tcp_read;
        let mut buf = vec![0u8; UDP_BUF];
        while let Some(n) = read_udp_datagram(&mut tcp_read, &mut buf) {
            if udp_send.send(&buf[..n]).is_err() {
                break;
            }
        }
        done_in.store(true, Ordering::Relaxed);
    };
    let replied = RelayPool::global().run(forward);
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        match udp.recv(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    continue;
                }
                if !write_udp_datagram(&mut stream, &buf[..n]) {
                    break;
                }
            }
            Err(error) if is_timeout(&error) => {
                if done.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(Shutdown::Both);
    join(&replied);
}

pub(crate) fn pump_vmess_udp(
    stream: &TcpStream,
    udp: &UdpSocket,
    send: crate::vmess::Flow,
    recv: crate::vmess::Flow,
) {
    let Ok(tcp_read) = stream.try_clone() else {
        return;
    };
    let Ok(tcp_write) = stream.try_clone() else {
        return;
    };
    let Ok(udp_send) = udp.try_clone() else {
        return;
    };
    if udp.set_read_timeout(Some(UDP_IDLE)).is_err() {
        return;
    }
    let done = Arc::new(AtomicBool::new(false));
    let done_in = Arc::clone(&done);
    let forward = move || {
        let mut tcp_read = tcp_read;
        let mut recv = recv;
        let mut scratch = Vec::with_capacity(UDP_BUF);
        while let Some(chunk) = crate::vmess::read_frame(&mut tcp_read, &mut recv, &mut scratch) {
            if chunk.is_empty() {
                break;
            }
            if udp_send.send(chunk).is_err() {
                break;
            }
        }
        done_in.store(true, Ordering::Relaxed);
    };
    let replied = RelayPool::global().run(forward);
    let mut send = send;
    let mut staging = Vec::with_capacity(UDP_BUF);
    let Some(mut pad) = crate::vmess::PadSource::fresh() else {
        return;
    };
    let mut buf = vec![0u8; UDP_BUF];
    let mut tcp_write = tcp_write;
    loop {
        match udp.recv(&mut buf) {
            Ok(n) => {
                if n == 0 {
                    continue;
                }
                if !crate::vmess::write_frame(
                    &mut tcp_write,
                    &mut send,
                    &buf[..n],
                    &mut staging,
                    &mut pad,
                ) {
                    break;
                }
            }
            Err(error) if is_timeout(&error) => {
                if done.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = tcp_write.shutdown(Shutdown::Both);
    join(&replied);
}

type RelayTask = Box<dyn FnOnce() + Send + 'static>;

struct RelayPool {
    idle: Mutex<Vec<std::sync::mpsc::Sender<RelayTask>>>,
}

static RELAY_POOL: OnceLock<RelayPool> = OnceLock::new();

impl RelayPool {
    fn global() -> &'static Self {
        RELAY_POOL.get_or_init(|| RelayPool {
            idle: Mutex::new(Vec::new()),
        })
    }

    fn run(&self, direction: impl FnOnce() + Send + 'static) -> std::sync::mpsc::Receiver<()> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let task: RelayTask = Box::new(move || {
            let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(direction));
            let _ = done_tx.send(());
            if ended.is_err() {
                eprintln!("ferrox-app: a relay direction panicked");
            }
        });
        let mut task = Some(task);
        let claimed = self
            .idle
            .lock()
            .ok()
            .and_then(|mut idle| idle.pop())
            .is_some_and(|sender| sender.send(task.take().expect("just set")).is_ok());
        if !claimed {
            Self::spawn(task.take().expect("unclaimed means unclaimed"));
        }
        done_rx
    }

    fn spawn(task: RelayTask) {
        let (sender, receiver) = std::sync::mpsc::channel::<RelayTask>();
        thread::spawn(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
            loop {
                let Ok(next) = receiver.recv() else {
                    return;
                };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(next));
                let pool = RelayPool::global();
                let Ok(mut idle) = pool.idle.lock() else {
                    return;
                };
                idle.push(sender.clone());
            }
        });
    }
}

fn join(direction: &std::sync::mpsc::Receiver<()>) {
    let _ = direction.recv();
}

pub(crate) const RELAY_BUFFER: usize = 256 * 1024;

pub(crate) const RELAY_SMALL_BUFFER: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) struct RelayBuf {
    bytes: Vec<u8>,
}

impl RelayBuf {
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: vec![0u8; RELAY_SMALL_BUFFER],
        }
    }

    #[must_use]
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    #[must_use]
    pub fn filled(&mut self, n: usize) -> &[u8] {
        if n == self.bytes.len() && n < RELAY_BUFFER {
            self.bytes.resize(RELAY_BUFFER, 0);
        }
        &self.bytes[..n]
    }

    #[cfg(test)]
    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

impl Default for RelayBuf {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "linux"))]
fn copy_all(from: &mut TcpStream, to: &mut TcpStream) {
    copy_all_memcpy(from, to);
}

fn copy_all_memcpy(from: &mut TcpStream, to: &mut TcpStream) {
    let mut buffer = RelayBuf::new();
    loop {
        let n = match from.read(buffer.as_mut()) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if to.write_all(buffer.filled(n)).is_err() {
            return;
        }
    }
}

#[cfg(target_os = "linux")]
fn copy_all(from: &mut TcpStream, to: &mut TcpStream) {
    let Some(pipe) = SplicePipe::new() else {
        return copy_all_memcpy(from, to);
    };
    loop {
        match pipe.pull(from) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if !pipe.push(to, n) {
                    return;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
struct SplicePipe {
    fds: [libc::c_int; 2],
    capacity: libc::size_t,
}

#[cfg(target_os = "linux")]
impl SplicePipe {
    fn new() -> Option<Self> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        let asked = unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, splice_pipe_bytes()) };
        let granted = unsafe { libc::fcntl(fds[0], libc::F_GETPIPE_SZ) };
        let capacity = libc::size_t::try_from(if asked > 0 { asked } else { granted }).ok();
        let capacity = match capacity {
            Some(bytes) if bytes > 0 => bytes,
            _ => DEFAULT_SPLICE_PIPE_BYTES,
        };
        if capacity != DEFAULT_SPLICE_PIPE_BYTES {
            eprintln!("ferrox-app: splice pipe {capacity} B");
        }
        Some(Self { fds, capacity })
    }

    fn pull(&self, from: &mut TcpStream) -> std::io::Result<usize> {
        loop {
            let n = unsafe {
                libc::splice(
                    from.as_raw_fd(),
                    std::ptr::null_mut(),
                    self.fds[1],
                    std::ptr::null_mut(),
                    self.capacity,
                    0,
                )
            };
            if n < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Ok(n as usize);
        }
    }

    fn push(&self, to: &mut TcpStream, n: usize) -> bool {
        let mut left = n;
        while left > 0 {
            let moved = unsafe {
                libc::splice(
                    self.fds[0],
                    std::ptr::null_mut(),
                    to.as_raw_fd(),
                    std::ptr::null_mut(),
                    left,
                    0,
                )
            };
            if moved < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            if moved == 0 {
                return false;
            }
            left -= moved as usize;
        }
        true
    }
}

#[cfg(target_os = "linux")]
const SPLICE_PIPE_BYTES: usize = DEFAULT_SPLICE_PIPE_BYTES;

#[cfg(target_os = "linux")]
const DEFAULT_SPLICE_PIPE_BYTES: usize = 256 * 1024;

#[cfg(target_os = "linux")]
fn splice_pipe_bytes() -> libc::c_int {
    let asked = std::env::var("FERROX_SPLICE_PIPE_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(SPLICE_PIPE_BYTES);
    libc::c_int::try_from(asked).unwrap_or(libc::c_int::MAX)
}

#[cfg(target_os = "linux")]
impl Drop for SplicePipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fds[0]);
            libc::close(self.fds[1]);
        }
    }
}

pub(crate) fn find_across(head: &[u8], probe: &[u8], pattern: &[u8]) -> Option<usize> {
    debug_assert!(!pattern.is_empty(), "a pattern of no bytes is everywhere");
    let span = pattern.len() - 1;
    let joined = head.len() + probe.len();
    let start = head.len().saturating_sub(span);
    (start..joined.saturating_sub(span)).find(|&at| {
        let byte = |i: usize| {
            if i < head.len() {
                head[i]
            } else {
                probe[i - head.len()]
            }
        };
        (0..pattern.len()).all(|k| byte(at + k) == pattern[k])
    })
}

pub(crate) fn read_http_head(stream: &mut TcpStream, limit: usize) -> Option<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut probe = [0u8; 512];
    loop {
        if head.len() >= limit {
            return None;
        }
        let n = stream.peek(&mut probe).ok()?;
        if n == 0 {
            return None;
        }
        let Some(at) = find_across(&head, &probe[..n], b"\r\n\r\n") else {
            let take = n.min(limit - head.len());
            let mut consumed = vec![0u8; take];
            read_exact(stream, &mut consumed).ok()?;
            head.extend_from_slice(&consumed);
            continue;
        };
        let mut rest = vec![0u8; at + 4 - head.len()];
        read_exact(stream, &mut rest).ok()?;
        head.extend_from_slice(&rest);
        return Some(head);
    }
}

pub(crate) trait CarrierSink: Clone + Send + 'static {
    fn send(&self, bytes: &[u8]) -> bool;
    fn close(&self);
}

pub(crate) fn relay_sink<R, W, F>(reader: R, writer: &W, peer: &TcpStream, on_reader_done: F)
where
    R: Read,
    W: CarrierSink,
    F: FnOnce(&mut R),
{
    relay_ordered::<R, W, F, CLOSE_BEFORE_JOIN>(reader, writer, peer, on_reader_done);
}

const CLOSE_BEFORE_JOIN: bool = true;

const CLOSE_AFTER_JOIN: bool = false;

fn relay_ordered<R, W, F, const CLOSE_FIRST: bool>(
    mut reader: R,
    writer: &W,
    peer: &TcpStream,
    on_reader_done: F,
) where
    R: Read,
    W: CarrierSink,
    F: FnOnce(&mut R),
{
    const CHUNK: usize = 16 * 1024;
    let Ok(peer_read) = peer.try_clone() else {
        return;
    };
    let Ok(peer_write) = peer.try_clone() else {
        return;
    };
    let mut peer_read = peer_read;
    let mut peer_write = peer_write;
    let uplink = writer.clone();
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match peer_read.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if !uplink.send(&buf[..n]) {
                        break;
                    }
                }
                _ => break,
            }
        }
        if CLOSE_FIRST {
            uplink.close();
            let _ = peer_read.shutdown(Shutdown::Both);
        }
    });
    let mut buf = vec![0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(n) if n > 0 => {
                if peer_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
    if CLOSE_FIRST {
        writer.close();
        on_reader_done(&mut reader);
        let _ = peer_write.shutdown(Shutdown::Both);
        let _ = done.join();
    } else {
        let _ = peer_write.shutdown(Shutdown::Write);
        let _ = done.join();
        writer.close();
        let _ = peer_write.shutdown(Shutdown::Both);
    }
}

pub(crate) fn relay_sink_drained<R: Read, W: CarrierSink>(reader: R, writer: &W, peer: &TcpStream) {
    relay_ordered::<R, W, fn(&mut R), CLOSE_AFTER_JOIN>(reader, writer, peer, |_| {});
}

pub(crate) fn relay_carried<R: Read>(mut reader: R, write: &TcpStream, peer: &TcpStream) {
    const CHUNK: usize = 16 * 1024;
    let Ok(peer_read) = peer.try_clone() else {
        return;
    };
    let Ok(peer_write) = peer.try_clone() else {
        return;
    };
    let mut peer_read = peer_read;
    let mut peer_write = peer_write;
    let Ok(mut uplink) = write.try_clone() else {
        return;
    };
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match peer_read.read(&mut buf) {
                Ok(n) if n > 0 => {
                    if uplink.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = peer_read.shutdown(Shutdown::Both);
        let _ = uplink.shutdown(Shutdown::Both);
    });
    let mut buf = vec![0u8; CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(n) if n > 0 => {
                if peer_write.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
    let _ = peer_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

pub(crate) fn read_exact(stream: &mut dyn Read, mut buf: &mut [u8]) -> std::io::Result<()> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)),
            Ok(n) => buf = &mut buf[n..],
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn header_value<'a>(head: &'a [u8], name: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    lines.next()?;
    for line in lines {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim());
        }
    }
    None
}

pub(crate) fn request_path(head: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(target.split_once('?').map_or(target, |(base, _)| base))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddrKind {
    V4,
    V6,
    Domain,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AddrBody<'a> {
    V4([u8; 4]),
    V6([u8; 16]),
    Domain(&'a str),
}

pub(crate) fn parse_addr_body(buf: &[u8], kind: AddrKind) -> Option<(AddrBody<'_>, usize)> {
    match kind {
        AddrKind::V4 => {
            let ip: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            Some((AddrBody::V4(ip), 5))
        }
        AddrKind::V6 => {
            let ip: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            Some((AddrBody::V6(ip), 17))
        }
        AddrKind::Domain => {
            let len = usize::from(*buf.get(1)?);
            if len == 0 {
                return None;
            }
            let host = std::str::from_utf8(buf.get(2..2 + len)?).ok()?;
            Some((AddrBody::Domain(host), 2 + len))
        }
    }
}

pub(crate) fn write_all_two(stream: &mut TcpStream, first: &[u8], second: &[u8]) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let mut parts = [
            libc::iovec {
                iov_base: first.as_ptr() as *mut libc::c_void,
                iov_len: first.len(),
            },
            libc::iovec {
                iov_base: second.as_ptr() as *mut libc::c_void,
                iov_len: second.len(),
            },
        ];
        writev_loop(stream.as_raw_fd(), &mut parts, first.len() + second.len())
    }
    #[cfg(not(unix))]
    {
        stream.write_all(first).is_ok() && stream.write_all(second).is_ok()
    }
}

pub(crate) fn write_all_three(
    stream: &mut TcpStream,
    first: &[u8],
    second: &[u8],
    third: &[u8],
) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        let mut parts = [
            libc::iovec {
                iov_base: first.as_ptr() as *mut libc::c_void,
                iov_len: first.len(),
            },
            libc::iovec {
                iov_base: second.as_ptr() as *mut libc::c_void,
                iov_len: second.len(),
            },
            libc::iovec {
                iov_base: third.as_ptr() as *mut libc::c_void,
                iov_len: third.len(),
            },
        ];
        writev_loop(
            stream.as_raw_fd(),
            &mut parts,
            first.len() + second.len() + third.len(),
        )
    }
    #[cfg(not(unix))]
    {
        stream.write_all(first).is_ok()
            && stream.write_all(second).is_ok()
            && stream.write_all(third).is_ok()
    }
}

#[cfg(unix)]
fn writev_loop(fd: std::os::fd::RawFd, iov: &mut [libc::iovec], mut left: usize) -> bool {
    let mut at = 0;
    while left > 0 {
        let count = i32::try_from(iov.len() - at).expect("writev takes at most three entries");
        let done = unsafe { libc::writev(fd, iov[at..].as_ptr(), count) };
        if done < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if done == 0 {
            return false;
        }
        let mut wrote = done as usize;
        left -= wrote;
        while wrote > 0 {
            let len = iov[at].iov_len;
            if wrote >= len {
                wrote -= len;
                at += 1;
            } else {
                iov[at].iov_base = unsafe {
                    iov[at]
                        .iov_base
                        .cast::<u8>()
                        .add(wrote)
                        .cast::<libc::c_void>()
                };
                iov[at].iov_len -= wrote;
                wrote = 0;
            }
        }
    }
    true
}

pub(crate) fn read_vless_response(stream: &mut dyn Read) -> Option<()> {
    let mut prefix = [0u8; 2];
    read_exact(stream, &mut prefix).ok()?;
    let consumed = ferrox_core::vless::VlessLink::decode_response_header(&prefix).ok()?;
    if consumed > 2 {
        let mut rest = vec![0u8; consumed - 2];
        read_exact(stream, &mut rest).ok()?;
    }
    Some(())
}

const MUX_TARGET: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 666);

pub(crate) fn decode_request(stream: &mut dyn Read) -> Option<([u8; 16], String, u8, SocketAddr)> {
    let mut head = [0u8; 18];
    read_exact(stream, &mut head).ok()?;
    if head[0] != 0 {
        return None;
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&head[1..17]);
    let addons = usize::from(head[17]);
    let mut flow = String::new();
    if addons > 0 {
        let mut body = vec![0u8; addons];
        read_exact(stream, &mut body).ok()?;
        flow = addons_flow(&body);
    }
    let mut cmd = [0u8; 1];
    read_exact(stream, &mut cmd).ok()?;
    if cmd[0] == 3 {
        return Some((id, flow, cmd[0], MUX_TARGET));
    }
    let mut port = [0u8; 2];
    read_exact(stream, &mut port).ok()?;
    let target = read_addr(stream, u16::from_be_bytes(port))?;
    Some((id, flow, cmd[0], target))
}

fn addons_flow(body: &[u8]) -> String {
    let mut at = 0;
    while at < body.len() {
        let tag = body[at];
        at += 1;
        let (field, wire) = (tag >> 3, tag & 0x07);
        let Some(len) = read_varint(body, &mut at) else {
            return String::new();
        };
        let len = len as usize;
        match (field, wire) {
            (1, 2) => {
                return body
                    .get(at..at.saturating_add(len))
                    .and_then(|bytes| std::str::from_utf8(bytes).ok())
                    .unwrap_or_default()
                    .to_owned();
            }
            (0, _) | (1, 0) | (_, 2) => at += len,
            (_, 5) => at += 4,
            (_, 1) => at += 8,
            _ => return String::new(),
        }
    }
    String::new()
}

fn read_varint(body: &[u8], at: &mut usize) -> Option<u32> {
    let mut word = 0u32;
    for shift in (0..32).step_by(7) {
        let byte = *body.get(*at)?;
        *at += 1;
        word |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(word);
        }
    }
    None
}

/// The longest trojan request header a peer can send: key, CRLF, command, the
/// longest address (a 255-byte domain) with its port, and CRLF.
const TROJAN_HEAD_MAX: usize = 56 + 2 + 1 + 1 + 1 + 255 + 2 + 2;

/// Every byte of `got` is examined, so how long the comparison takes does not
/// depend on how much of the key was right, and a short read never agrees.
fn key_agrees(got: &[u8], key: &[u8; 56]) -> bool {
    if got.len() != key.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(key) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Fill `head[..want]` from `stream`, returning the cursor. A `dyn Read` may
/// hand back short reads, so this loops; the count is what the header costs.
fn trojan_take(
    stream: &mut dyn Read,
    head: &mut [u8; TROJAN_HEAD_MAX],
    filled: &mut usize,
    want: usize,
) -> bool {
    while *filled < want {
        match stream.read(&mut head[*filled..want]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => *filled += n,
        }
    }
    true
}

/// One read for the whole header, parsed in place: two reads for a numeric
/// address and three for a domain, against the seven and eight the
/// field-at-a-time parse spent.
fn decode_trojan_request(stream: &mut dyn Read, key: &[u8; 56]) -> Option<(u8, SocketAddr)> {
    let mut head = [0u8; TROJAN_HEAD_MAX];
    let mut filled = 0usize;
    if !trojan_take(stream, &mut head, &mut filled, 60)
        || !key_agrees(&head[..56], key)
        || head[56..58] != *b"\r\n"
    {
        return None;
    }
    let cmd = head[58];
    // The port ends the address in every form, so the CRLF that closes the
    // header is the two bytes after it.
    let (target, port_end) = match head[59] {
        1 => {
            if !trojan_take(stream, &mut head, &mut filled, 68) {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&head[60..64]);
            let port = u16::from_be_bytes([head[64], head[65]]);
            (SocketAddr::new(std::net::IpAddr::V4(ip.into()), port), 66)
        }
        4 => {
            if !trojan_take(stream, &mut head, &mut filled, 80) {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&head[60..76]);
            let port = u16::from_be_bytes([head[76], head[77]]);
            (SocketAddr::new(std::net::IpAddr::V6(ip.into()), port), 78)
        }
        3 => {
            if !trojan_take(stream, &mut head, &mut filled, 61) {
                return None;
            }
            let name_end = 61 + usize::from(head[60]);
            if !trojan_take(stream, &mut head, &mut filled, name_end + 4) {
                return None;
            }
            let host = std::str::from_utf8(&head[61..name_end]).ok()?;
            let port = u16::from_be_bytes([head[name_end], head[name_end + 1]]);
            (resolve_endpoint(host, port)?, name_end + 2)
        }
        _ => return None,
    };
    if head[port_end..port_end + 2] != *b"\r\n" {
        return None;
    }
    Some((cmd, target))
}

fn read_addr(stream: &mut dyn Read, port: u16) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    if atyp[0] == 1 {
        let mut ip = [0u8; 4];
        read_exact(stream, &mut ip).ok()?;
        return Some(SocketAddr::new(std::net::IpAddr::V4(ip.into()), port));
    }
    if atyp[0] == 3 {
        let mut ip = [0u8; 16];
        read_exact(stream, &mut ip).ok()?;
        return Some(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port));
    }
    if atyp[0] != 2 {
        return None;
    }
    let mut len = [0u8; 1];
    read_exact(stream, &mut len).ok()?;
    let mut name = vec![0u8; usize::from(len[0])];
    read_exact(stream, &mut name).ok()?;
    let host = String::from_utf8(name).ok()?;
    resolve_endpoint(&host, port)
}

pub(crate) fn push_addr(header: &mut Vec<u8>, target: &SocketAddr, v6: u8) {
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            header.push(v6);
            header.extend_from_slice(&ip.octets());
        }
    }
}

fn push_socks_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    push_addr(out, addr, 4);
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn parse_socks_udp(packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let mut cursor = std::io::Cursor::new(&packet[4..]);
    let addr = read_socks_addr_rest(&mut cursor, packet[3])?;
    let used = 4 + cursor.position() as usize;
    Some((addr, &packet[used..]))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn trojan_key(password: &str) -> [u8; 56] {
    use sha2::Digest as _;
    let digest = sha2::Sha224::digest(password.as_bytes());
    let mut out = [0u8; 56];
    for (i, byte) in digest.iter().enumerate() {
        out[2 * i] = HEX[(byte >> 4) as usize];
        out[2 * i + 1] = HEX[(byte & 0x0F) as usize];
    }
    out
}

/// The same handshake, keeping the name the client sent. A CONNECT lane needs
/// it: resolving here would hand the edge an address it cannot route.
fn socks_target(client: &mut TcpStream) -> Option<(u8, SocksTarget)> {
    let mut head = [0u8; 2];
    read_exact(client, &mut head).ok()?;
    if head[0] != 5 {
        return None;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    read_exact(client, &mut methods).ok()?;
    if client.write_all(&[5, 0]).is_err() {
        return None;
    }
    let mut req = [0u8; 4];
    read_exact(client, &mut req).ok()?;
    if req[0] != 5 || (req[1] != 1 && req[1] != 3) {
        return None;
    }
    let target = read_socks_named(client, req[3])?;
    if req[1] == 1 && client.write_all(&foxy_socks_reply(0)).is_err() {
        return None;
    }
    Some((req[1], target))
}

fn read_socks_named(stream: &mut dyn Read, atyp: u8) -> Option<SocksTarget> {
    match atyp {
        3 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocksTarget::Name(
                String::from_utf8(name).ok()?,
                u16::from_be_bytes(port),
            ))
        }
        _ => Some(SocksTarget::Address(read_socks_addr_rest(stream, atyp)?)),
    }
}

/// What a SOCKS5 client asked for: a name the edge resolves itself, or an
/// address. A CONNECT tunnel sends the name through untouched, so the address a
/// plain dial would have resolved never exists for this front.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SocksTarget {
    Name(String, u16),
    Address(SocketAddr),
}

impl SocksTarget {
    fn authority(&self) -> String {
        match self {
            Self::Name(host, port) => ferrox_core::foxy::authority(host, *port),
            Self::Address(address) => address.to_string(),
        }
    }

    fn socket(&self) -> Option<SocketAddr> {
        match self {
            Self::Address(address) => Some(*address),
            Self::Name(host, port) => format!("{host}:{port}")
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next()),
        }
    }

    fn host(&self) -> String {
        match self {
            Self::Name(host, _) => host.clone(),
            Self::Address(address) => address.ip().to_string(),
        }
    }

    fn port(&self) -> u16 {
        match self {
            Self::Name(_, port) => *port,
            Self::Address(address) => address.port(),
        }
    }
}

fn read_socks_addr(stream: &mut dyn Read) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    read_socks_addr_rest(stream, atyp[0])
}

fn read_socks_addr_rest(stream: &mut dyn Read, atyp: u8) -> Option<SocketAddr> {
    match atyp {
        1 => {
            let mut ip = [0u8; 4];
            read_exact(stream, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocketAddr::new(
                std::net::IpAddr::V4(ip.into()),
                u16::from_be_bytes(port),
            ))
        }
        3 => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).ok()?;
            let mut name = vec![0u8; usize::from(len[0])];
            read_exact(stream, &mut name).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            let host = String::from_utf8(name).ok()?;
            format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()
        }
        4 => {
            let mut ip = [0u8; 16];
            read_exact(stream, &mut ip).ok()?;
            let mut port = [0u8; 2];
            read_exact(stream, &mut port).ok()?;
            Some(SocketAddr::new(
                std::net::IpAddr::V6(ip.into()),
                u16::from_be_bytes(port),
            ))
        }
        _ => None,
    }
}

fn inbound_first_client(inbound: &Json) -> Option<&Json> {
    inbound
        .get("settings")
        .and_then(|s| s.get("clients"))
        .and_then(Json::as_arr)
        .and_then(|clients| clients.first())
}

fn inbound_id(inbound: &Json) -> [u8; 16] {
    inbound_first_client(inbound)
        .and_then(|client| client.get("id"))
        .and_then(Json::as_str)
        .and_then(uuid_bytes)
        .unwrap_or([0u8; 16])
}

fn has_protocol(root: &Json, array: &str, protocol: &str) -> bool {
    root.get(array).and_then(Json::as_arr).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("protocol").and_then(Json::as_str) == Some(protocol))
    })
}

fn inbound_method(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("method"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

pub(crate) fn inbound_ss_password(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn inbound_password(inbound: &Json) -> String {
    inbound_first_client(inbound)
        .and_then(|client| client.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

fn find_outbound(root: &Json) -> Option<Outbound> {
    if let Some(foxy) = find_foxy_outbound(root) {
        return Some(Outbound::Foxy(Box::new(foxy)));
    }
    if let Some(vless) = find_vless_outbound(root) {
        return Some(Outbound::Vless(vless));
    }
    if let Some(vmess) = find_vmess_outbound(root) {
        return Some(Outbound::Vmess(vmess));
    }
    if let Some(trojan) = find_trojan_outbound(root) {
        return Some(Outbound::Trojan(trojan));
    }
    find_shadowsocks_outbound(root)
        .map(Outbound::Shadowsocks)
        .or_else(|| is_freedom(root).then_some(Outbound::Freedom))
}

fn is_freedom(root: &Json) -> bool {
    has_protocol(root, "outbounds", "freedom")
}

/// The carrier the config names, or the one the link names, or `auto`: a lane
/// that is told nothing tries QUIC, then HTTP/2, then HTTP/1.1, rather than
/// committing to one carrier the edge may not answer.
fn foxy_carrier(
    settings: Option<&Json>,
    link: &ferrox_core::foxy::link::FoxyLink,
) -> crate::foxy::Carrier {
    let named = foxy_text(settings, "carrier");
    let named = if named.is_empty() {
        link.carrier().to_owned()
    } else {
        named
    };
    crate::foxy::carrier(&named)
}

/// A list the config writes out, or the one the link carries comma-separated:
/// the same field, two spellings, because a link has no arrays.
fn foxy_list_or(
    link: &ferrox_core::foxy::link::FoxyLink,
    settings: Option<&Json>,
    key: &str,
) -> Vec<String> {
    let listed = foxy_strings(settings.and_then(|s| s.get(key)));
    if !listed.is_empty() {
        return listed;
    }
    link.param(key)
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every edge the config lists in the pinned country, city first, so a
/// configured failover is the same failover the catalogue would have chosen.
fn foxy_edges(outbound: &Json, country: &str, city: &str) -> Vec<ferrox_core::foxy::Candidate> {
    let edges = outbound
        .get("settings")
        .and_then(|s| s.get("servers"))
        .and_then(Json::as_arr)
        .unwrap_or(&[]);
    edges
        .iter()
        .filter_map(|edge| {
            let host = edge.get("host").and_then(Json::as_str)?.to_owned();
            let port = edge.get("port").and_then(Json::as_port)?;
            let code = edge
                .get("country")
                .and_then(Json::as_str)
                .unwrap_or(country);
            let name = edge.get("city").and_then(Json::as_str).unwrap_or(city);
            Some(ferrox_core::foxy::Candidate {
                host,
                port,
                country: code.to_owned(),
                city: name.to_owned(),
            })
        })
        .collect()
}

fn foxy_strings(value: Option<&Json>) -> Vec<String> {
    value
        .and_then(Json::as_arr)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_str)
        .map(str::to_owned)
        .collect()
}

fn foxy_ports(value: Option<&Json>) -> Vec<u16> {
    value
        .and_then(Json::as_arr)
        .unwrap_or(&[])
        .iter()
        .filter_map(Json::as_port)
        .collect()
}

/// The account a `foxy` outbound names: an account to sign in with, or a pass
/// pasted in. Either way it becomes one `Account` whose pass the renewal thread
/// owns, so the dial and the renewal read the same value.
fn foxy_account(
    email: &str,
    password: &str,
    code: &str,
    configured: &str,
    guardian: &str,
    roots: &[Vec<u8>],
) -> Option<std::sync::Arc<crate::foxy_account::Account>> {
    let pass = ferrox_core::foxy::Pass {
        token: configured.to_owned(),
        expires_at: None,
        quota_remaining: None,
        quota_reset: None,
    };
    if email.is_empty() && pass.token.is_empty() {
        return None;
    }
    let account = std::sync::Arc::new(crate::foxy_account::Account {
        fxa: crate::foxy_account::Endpoint::parse(
            ferrox_core::foxy::account::FXA_SERVER,
            roots.to_vec(),
        )?,
        guardian: crate::foxy_account::Endpoint::parse(guardian, roots.to_vec())?,
        jar: std::sync::Arc::new(std::sync::Mutex::new(crate::foxy_challenge::Jar::default())),
        pending: std::sync::Arc::new(std::sync::Mutex::new(None)),
        auth: std::sync::Arc::new(std::sync::Mutex::new(crate::foxy_account::Auth {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
        })),
        pass: std::sync::Arc::new(std::sync::Mutex::new(pass.clone())),
    });
    if !email.is_empty() && pass.token.is_empty() {
        if let Err(denied) = account.sign_in(email, password) {
            eprintln!("foxy: the account did not sign in: {denied}");
            return None;
        }
        if account.needs_code() {
            let Err(denied) = account.verify_code(code) else {
                return Some(account);
            };
            eprintln!("foxy: the account wants a two-factor code in settings.code: {denied}");
            return None;
        }
    }
    Some(account)
}

fn foxy_text(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// The inline field first, the link's parameter second: a config may carry
/// both, and the one written out in full is the one a person edited last.
fn foxy_text_or(
    link: &ferrox_core::foxy::link::FoxyLink,
    settings: Option<&Json>,
    key: &str,
) -> String {
    let inline = foxy_text(settings, key);
    if inline.is_empty() {
        link.param(key).to_owned()
    } else {
        inline
    }
}

/// The country the lane pins at dial, upper-cased so a hand-typed link matches
/// the catalogue, and defaulted to the one place every account has an exit.
fn foxy_country(link: &ferrox_core::foxy::link::FoxyLink, settings: Option<&Json>) -> String {
    let named = foxy_text(settings, "country");
    let named = if named.is_empty() {
        link.country().to_owned()
    } else {
        named
    };
    let named = if named.is_empty() {
        "US".to_owned()
    } else {
        named
    };
    named.to_ascii_uppercase()
}

/// One host as an address, which is what pins a dial to a host and keeps the TLS
/// name with the name.
fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    format!("{host}:{port}")
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
}

fn find_foxy_outbound(root: &Json) -> Option<FoxyOut> {
    let empty = Vec::new();
    for outbound in root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty)
    {
        if outbound.get("protocol").and_then(Json::as_str) != Some("foxy") {
            continue;
        }
        let settings = outbound.get("settings");
        let link = ferrox_core::foxy::link::FoxyLink::parse(&foxy_text(settings, "link"))
            .unwrap_or_default();
        let configured = foxy_text_or(&link, settings, "pass");
        let email = foxy_text_or(&link, settings, "email");
        let password = foxy_text_or(&link, settings, "password");
        let code = foxy_text_or(&link, settings, "code");
        if configured.is_empty() && email.is_empty() {
            continue;
        }
        let country = foxy_country(&link, settings);
        let city = foxy_text_or(&link, settings, "city").to_ascii_uppercase();
        // A CA file names the anchors to trust; without one the lane trusts the
        // anchors this machine already trusts, because an empty root store is
        // not "trust the platform" — it is trust nothing, and the account plane
        // is publicly trusted.
        let roots = settings
            .and_then(|s| s.get("caCertFile"))
            .and_then(Json::as_str)
            .and_then(|path| std::fs::read(path).ok())
            .map(|pem| crate::quic::parse_ca_pem(&pem))
            .filter(|roots: &Vec<Vec<u8>>| !roots.is_empty())
            .unwrap_or_else(crate::quic::system_roots);
        let pins = ferrox_core::foxy::pin::Pins::parse(foxy_list_or(&link, settings, "spkiPins"));
        // An edge the config or the link names outright is dialed whatever the
        // catalogue publishes, because naming one is a decision and guessing is
        // not; an address is the poison-proof dial and never the TLS name.
        let named = link.host();
        let named_address = foxy_text(settings, "edgeAddress");
        let edge_address = if named_address.is_empty() {
            None
        } else {
            resolve(&named_address, 443)
        };
        let named_edge = (!named.is_empty()).then(|| ferrox_core::foxy::Candidate {
            host: named.to_owned(),
            port: link.port(),
            country: country.clone(),
            city: city.clone(),
        });
        let configured_edges = foxy_edges(outbound, &country, &city);
        let candidates = match named_edge {
            Some(edge) => vec![edge],
            None if !configured_edges.is_empty() => configured_edges,
            // Nothing configured names an edge, so the published list does: this
            // is what lets a link that says only `country=US` reach an exit.
            None => crate::foxy_catalog::edges(roots.clone()),
        };
        let account = foxy_account(
            &email,
            &password,
            &code,
            &configured,
            link.guardian(),
            &roots,
        );
        let pass = account.as_ref().map_or_else(
            || ferrox_core::foxy::Pass {
                token: configured.clone(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
            |account| account.current(),
        );
        if let Some(account) = &account {
            start_renewal(std::sync::Arc::clone(account));
        }
        return Some(FoxyOut {
            account,
            candidates,
            stored: None,
            unauthenticated: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            country,
            city,
            carrier: foxy_carrier(settings, &link),
            roots,
            pins,
            pass,
            edge_address,
            direct_ports: foxy_ports(settings.and_then(|s| s.get("directPorts"))),
            direct_suffixes: foxy_list_or(&link, settings, "directDomains"),
            exit_probe: match foxy_text_or(&link, settings, "exitProbe") {
                probe if probe.is_empty() => None,
                probe => Some(probe),
            },
        });
    }
    None
}

fn find_trojan_outbound(root: &Json) -> Option<TrojanOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("trojan") {
            continue;
        }
        let server = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = server else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let password = server.get("password").and_then(Json::as_str)?;
        let key = trojan_key(password);
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(TrojanOut {
            address,
            port,
            key,
            carrier,
            host,
        });
    }
    None
}

fn find_shadowsocks_outbound(root: &Json) -> Option<ShadowsocksOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("shadowsocks") {
            continue;
        }
        let server = outbound
            .get("settings")
            .and_then(|s| s.get("servers"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = server else { continue };
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let method = server.get("method").and_then(Json::as_str)?.to_owned();
        let password = server.get("password").and_then(Json::as_str)?.to_owned();
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(ShadowsocksOut {
            address,
            port,
            method,
            password,
            carrier,
            host,
        });
    }
    None
}

fn vnext_servers<'a>(
    root: &'a Json,
    protocol: &'a str,
) -> impl Iterator<Item = (&'a Json, &'a Json)> + 'a {
    let outbounds: &[Json] = root.get("outbounds").and_then(Json::as_arr).unwrap_or(&[]);
    outbounds
        .iter()
        .filter(move |outbound| outbound.get("protocol").and_then(Json::as_str) == Some(protocol))
        .filter_map(|outbound| {
            let server = outbound
                .get("settings")
                .and_then(|s| s.get("vnext"))
                .and_then(Json::as_arr)
                .and_then(|servers| servers.first())?;
            Some((outbound, server))
        })
}

fn find_vless_outbound(root: &Json) -> Option<VlessOut> {
    for (outbound, server) in vnext_servers(root, "vless") {
        let security = stream_security(outbound);
        let quic_tls = outbound
            .get("streamSettings")
            .and_then(|s| s.get("network"))
            .and_then(Json::as_str)
            == Some("quic")
            && security == "tls";
        if !vless_security_supported(security) && !quic_tls {
            continue;
        }
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let id = server
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())
            .and_then(|user| user.get("id"))
            .and_then(Json::as_str)
            .and_then(uuid_bytes)?;
        let (carrier, host) = outbound_carrier(outbound, &address);
        let mux = matches!(
            outbound.get("mux").and_then(|mux| mux.get("enabled")),
            Some(Json::Bool(true))
        );
        let quic_roots = match &carrier {
            Carrier::Quic => tls_ca_roots(outbound),
            _ => None,
        };
        let hysteria_roots = match &carrier {
            Carrier::Hysteria(_) => tls_ca_roots(outbound),
            _ => None,
        };
        return Some(VlessOut {
            address,
            port,
            id,
            carrier,
            host,
            mux,
            quic_roots,
            hysteria_roots,
        });
    }
    None
}

fn find_vmess_outbound(root: &Json) -> Option<VmessOut> {
    if let Some((outbound, server)) = vnext_servers(root, "vmess").next() {
        let address = server.get("address").and_then(Json::as_str)?.to_owned();
        let port = server.get("port").and_then(Json::as_port)?;
        let user = server
            .get("users")
            .and_then(Json::as_arr)
            .and_then(|users| users.first())?;
        let id = user.get("id").and_then(Json::as_str).and_then(uuid_bytes)?;
        let cipher = crate::vmess::Cipher::parse(
            user.get("security")
                .and_then(Json::as_str)
                .unwrap_or("auto"),
        );
        let (carrier, host) = outbound_carrier(outbound, &address);
        return Some(VmessOut {
            address,
            port,
            id,
            cipher,
            carrier,
            host,
        });
    }
    None
}

fn tls_ca_roots(outbound: &Json) -> Option<Vec<Vec<u8>>> {
    outbound
        .get("streamSettings")
        .and_then(|s| s.get("tlsSettings"))
        .and_then(|s| s.get("caCertFile"))
        .and_then(Json::as_str)
        .and_then(|path| std::fs::read(path).ok())
        .map(|pem| crate::quic::parse_ca_pem(&pem))
        .filter(|roots| !roots.is_empty())
}

fn kcp_config(settings: Option<&Json>) -> ferrox_core::kcp::Config {
    let base = ferrox_core::kcp::Config::default();
    let Some(kcp) = settings.and_then(|s| s.get("kcpSettings")) else {
        return base;
    };
    let num = |camel: &str, snake: &str| {
        kcp.get(camel)
            .or_else(|| kcp.get(snake))
            .and_then(Json::as_u32)
    };
    let mtu = num("mtu", "mtu").unwrap_or(base.mtu);
    let tti = num("tti", "tti").unwrap_or(base.tti);
    ferrox_core::kcp::Config {
        mtu: if mtu > ferrox_core::kcp::DATA_SEGMENT_OVERHEAD {
            mtu
        } else {
            base.mtu
        },
        tti: if (1..=1000).contains(&tti) {
            tti
        } else {
            base.tti
        },
        uplink_capacity: num("uplinkCapacity", "uplink_capacity").unwrap_or(base.uplink_capacity),
        downlink_capacity: num("downlinkCapacity", "downlink_capacity")
            .unwrap_or(base.downlink_capacity),
        cwnd_multiplier: num("cwndMultiplier", "cwnd_multiplier").unwrap_or(base.cwnd_multiplier),
        max_sending_window: num("maxSendingWindow", "max_sending_window")
            .unwrap_or(base.max_sending_window),
    }
}

fn stream_carrier(settings: Option<&Json>) -> Carrier {
    match settings
        .and_then(|s| s.get("network"))
        .and_then(Json::as_str)
    {
        Some("ws" | "websocket") => {
            let early = EarlyData::split(&sub_path(settings, "wsSettings"));
            Carrier::Ws {
                path: early.path,
                ed: early.budget,
            }
        }
        Some("httpupgrade") => Carrier::HttpUpgrade {
            path: EarlyData::split(&sub_path(settings, "httpupgradeSettings")).path,
        },
        Some("grpc") => Carrier::Grpc {
            path: grpc_path(settings),
        },
        Some("xhttp" | "splithttp") => Carrier::Xhttp {
            path: xhttp_path(settings),
        },
        Some("quic") => Carrier::Quic,
        Some("kcp" | "mkcp") => Carrier::Kcp(kcp_config(settings)),
        Some("hysteria") => hysteria_carrier(settings),
        Some("masque") => Carrier::Masque,
        Some("xdrive") => Carrier::Xdrive,
        Some("http" | "h2" | "h3") => Carrier::Http,
        None | Some("" | "raw" | "tcp") => match tcp_http_path(settings) {
            Some(path) => Carrier::HttpHeader { path },
            None => Carrier::Raw,
        },
        Some(_) => Carrier::Unknown,
    }
}

fn hysteria_carrier(settings: Option<&Json>) -> Carrier {
    use ferrox_core::hysteria::{Config, Congestion};
    let hy = settings.and_then(|s| s.get("hysteriaSettings"));
    let version = hy
        .and_then(|h| h.get("version"))
        .and_then(Json::as_u32)
        .or_else(|| {
            hy.and_then(|h| h.get("version"))
                .and_then(Json::as_str)
                .and_then(|text| text.parse::<u32>().ok())
        });
    if version.is_some_and(|v| v != 2) {
        return Carrier::Unknown;
    }
    Carrier::Hysteria(Config {
        auth: hy
            .and_then(|h| h.get("auth"))
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned(),
        cc: Congestion::parse(
            hy.and_then(|h| h.get("congestion"))
                .and_then(Json::as_str)
                .unwrap_or(""),
        ),
    })
}

fn sub_path(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("path"))
        .and_then(Json::as_str)
        .unwrap_or("/")
        .to_owned()
}
fn grpc_path(settings: Option<&Json>) -> String {
    let service = settings
        .and_then(|s| s.get("grpcSettings"))
        .and_then(|s| s.get("serviceName"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .trim();
    if service.is_empty() {
        return "/Tun".to_owned();
    }
    if service.starts_with('/') {
        return service.to_owned();
    }
    format!("/{}/Tun", service.trim_matches('/'))
}

fn xhttp_path(settings: Option<&Json>) -> String {
    for key in ["xhttpSettings", "splithttpSettings"] {
        let found = settings
            .and_then(|s| s.get(key))
            .and_then(|s| s.get("path"))
            .and_then(Json::as_str)
            .filter(|path| !path.is_empty())
            .map(str::to_owned);
        if found.is_some() {
            return found.unwrap_or_else(|| "/".to_owned());
        }
    }
    "/".to_owned()
}

fn tcp_http_path(settings: Option<&Json>) -> Option<String> {
    let header = settings
        .and_then(|s| s.get("tcpSettings"))
        .and_then(|s| s.get("header"))?;
    if header.get("type").and_then(Json::as_str) != Some("http") {
        return None;
    }
    let request = header.get("request")?;
    if let Some(paths) = request.get("path").and_then(Json::as_arr) {
        let first = paths.iter().find_map(Json::as_str);
        if let Some(path) = first {
            return Some(path.to_owned());
        }
    }
    if let Some(path) = request.get("path").and_then(Json::as_str) {
        return Some(path.to_owned());
    }
    Some("/".to_owned())
}

fn outbound_carrier(outbound: &Json, address: &str) -> (Carrier, String) {
    let settings = outbound.get("streamSettings");
    let carrier = stream_carrier(settings);
    let key = match &carrier {
        Carrier::Ws { .. } => "wsSettings",
        Carrier::HttpUpgrade { .. } => "httpupgradeSettings",
        Carrier::Grpc { .. } => "grpcSettings",
        Carrier::Xhttp { .. } => "xhttpSettings",
        Carrier::HttpHeader { .. } => "tcpSettings",
        Carrier::Quic => "quicSettings",
        Carrier::Kcp(_) => "kcpSettings",
        Carrier::Hysteria(_) => "hysteriaSettings",
        Carrier::Masque => "masqueSettings",
        Carrier::Xdrive => "xdriveSettings",
        Carrier::Unknown | Carrier::Raw | Carrier::Http => "",
    };
    let host = settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("host"))
        .and_then(Json::as_str)
        .unwrap_or(address)
        .to_owned();
    (carrier, host)
}

fn inbound_carrier(inbound: &Json) -> Carrier {
    stream_carrier(inbound.get("streamSettings"))
}

fn stream_security(node: &Json) -> &str {
    node.get("streamSettings")
        .and_then(|s| s.get("security"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

fn vless_security_supported(sec: &str) -> bool {
    sec.is_empty() || sec == "none"
}

fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let mut out = [0u8; 16];
    let mut index = 0;
    let mut high: Option<u8> = None;
    for byte in text.bytes() {
        if byte == b'-' {
            continue;
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        match high.take() {
            Some(h) => {
                if index >= 16 {
                    return None;
                }
                out[index] = (h << 4) | digit;
                index += 1;
            }
            None => high = Some(digit),
        }
    }
    if index == 16 && high.is_none() {
        Some(out)
    } else {
        None
    }
}

fn x25519_pair() -> (String, String) {
    let mut private = [0u8; 32];
    getrandom::getrandom(&mut private)
        .unwrap_or_else(|error| exit(&format!("no entropy: {error}")));
    private[0] &= 0xF8;
    private[31] &= 0x7F;
    private[31] |= 0x40;
    let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
    (b64url(&private), b64url(&public))
}

fn b64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    ferrox_core::transport::early_encode_into(&mut out, bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_reuses_capacity_and_reports_its_length() {
        let mut buf = Vec::new();
        for len in [0usize, 1, 16, 4096, 65_536, 3] {
            resize_scratch(&mut buf, len);
            assert!(buf.capacity() >= len, "len {len}");
            assert_eq!(buf.len(), len, "len {len}");
            buf.fill(0x5A);
            assert!(buf.iter().all(|&byte| byte == 0x5A), "len {len}");
        }
    }

    #[test]
    fn b64url_matches_the_shared_encoder() {
        for (bytes, want) in [
            (&b""[..], ""),
            (&b"foobar"[..], "Zm9vYmFy"),
            (&[0xff, 0xff, 0x00][..], "__8A"),
        ] {
            assert_eq!(b64url(bytes), want);
            let mut shared = String::new();
            ferrox_core::transport::early_encode_into(&mut shared, bytes);
            assert_eq!(b64url(bytes), shared);
        }
    }

    #[test]
    fn a_head_split_across_segments_is_read_whole() {
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            for piece in [
                &b"GET /tunnel HTTP/1.1\r\nHost: h\r\n"[..],
                &b"Upgrade: websocket\r\n"[..],
                &b"\r"[..],
                &b"\n"[..],
            ] {
                stream.write_all(piece).expect("writes");
                thread::sleep(Duration::from_millis(20));
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let head = read_http_head(&mut stream, HEAD_LIMIT_TEST).expect("reads a head");
        assert_eq!(
            head,
            b"GET /tunnel HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n\r\n".to_vec()
        );
        peer.join().expect("joins");
    }

    #[test]
    fn bytes_pipelined_behind_a_head_stay_in_the_kernel() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut request = Vec::from(&b"GET /tunnel HTTP/1.1\r\nHost: h\r\n\r\n"[..]);
            request.extend_from_slice(b"the first frame's bytes");
            stream.write_all(&request).expect("writes");
            thread::sleep(std::time::Duration::from_millis(50));
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let head = read_http_head(&mut stream, HEAD_LIMIT_TEST).expect("reads a head");
        assert_eq!(head, b"GET /tunnel HTTP/1.1\r\nHost: h\r\n\r\n".to_vec());
        let tail = b"the first frame's bytes";
        let mut rest = vec![0u8; tail.len()];
        stream
            .read_exact(&mut rest)
            .expect("the tail is still there");
        assert_eq!(rest, tail);
        peer.join().expect("joins");
    }

    #[test]
    fn an_unterminated_head_is_refused_at_the_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let peer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let filler = vec![b'x'; 4096];
            while stream.write_all(&filler).is_ok() {}
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        assert!(
            read_http_head(&mut stream, 8 * 1024).is_none(),
            "a head with no terminator must be refused"
        );
        drop(stream);
        peer.join().expect("joins");
    }

    const HEAD_LIMIT_TEST: usize = 16 * 1024;

    #[test]
    fn base64url_matches_the_oracle_shape() {
        assert_eq!(b64url(&[0u8; 32]), "A".repeat(43));
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
    }

    #[test]
    fn uuid_parses_and_rejects() {
        assert_eq!(
            uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("parses")[0..2],
            [0xaa, 0xaa]
        );
        assert!(uuid_bytes("not-a-uuid").is_none());
        assert!(uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee").is_none());
    }

    #[test]
    fn decodes_what_the_core_encodes() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        let header = link.encode_request_header("192.0.2.53", 80);
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            decode_request(&mut stream).expect("decodes")
        });
        let mut reader = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        reader.write_all(&header).expect("writes");
        let (id, _flow, cmd, target) = writer.join().expect("joins");
        assert_eq!(
            id,
            uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id")
        );
        assert_eq!(cmd, 1);
        assert_eq!(target.to_string(), "192.0.2.53:80");
        drop(reader);
    }

    #[test]
    fn trojan_key_is_sha224_hex() {
        assert_eq!(
            trojan_key("an-example-shared-password"),
            *b"73317e3bf920a459723610d27b71cadc07061d8f0d8587e041944896"
        );
    }

    #[test]
    fn the_splice_path_and_the_copying_path_move_the_same_bytes() {
        fn round_trip(payload: &[u8], copy: fn(&mut TcpStream, &mut TcpStream)) -> Vec<u8> {
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut other = stream.try_clone().expect("clones");
                copy(&mut stream, &mut other);
            });
            let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            client
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            client.write_all(payload).expect("writes");
            client.shutdown(Shutdown::Write).expect("half closes");
            let mut back = Vec::new();
            client.read_to_end(&mut back).expect("reads");
            let _ = server.join();
            back
        }

        let payload: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
        let spliced = round_trip(&payload, copy_all);
        let copied = round_trip(&payload, copy_all_memcpy);
        assert_eq!(spliced, payload, "the splice path must move every byte");
        assert_eq!(copied, payload, "the copying path must move every byte");
        assert_eq!(spliced, copied, "the two paths must agree");
    }

    #[test]
    fn both_sockets_of_a_connection_have_nagle_off() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        let server = thread::spawn(move || {
            let (accepted, _) = listener.accept().expect("accepts");
            accepted
        });
        let dialled = dial(&SocketAddr::from(([127, 0, 0, 1], port))).expect("connects");
        assert!(
            dialled.nodelay().expect("reads back"),
            "the socket this binary dials must have TCP_NODELAY set"
        );
        let accepted = server.join().expect("the listener thread");
        no_delay(&accepted);
        assert!(
            accepted.nodelay().expect("reads back"),
            "and so must an accepted one"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_splice_pipe_reads_back_the_capacity_it_was_granted() {
        let pipe = SplicePipe::new().expect("a pipe is available on this host");
        assert!(
            pipe.capacity > 0,
            "a granted capacity of zero would make every splice ask for nothing"
        );
        let asked = unsafe { libc::fcntl(pipe.fds[0], libc::F_GETPIPE_SZ) };
        assert_eq!(
            asked as usize, pipe.capacity,
            "the recorded capacity must be the kernel's answer, not the request"
        );
        assert!(
            pipe.capacity <= DEFAULT_SPLICE_PIPE_BYTES.max(1) || pipe.capacity > 0,
            "a granted capacity is always positive and never invented"
        );
    }

    #[test]
    fn the_relay_pool_never_shrinks_below_the_directions_in_flight() {
        const DIRECTIONS: usize = 64;
        let pool = RelayPool::global();
        let arrived = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut waits = Vec::new();
        for _ in 0..DIRECTIONS {
            let arrived = Arc::clone(&arrived);
            waits.push(pool.run(move || {
                arrived.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while arrived.load(std::sync::atomic::Ordering::SeqCst) < DIRECTIONS {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "only {} of {DIRECTIONS} directions were ever in flight at \
                         once, so the pool serialised them",
                        arrived.load(std::sync::atomic::Ordering::SeqCst)
                    );
                    std::thread::yield_now();
                }
            }));
        }
        for wait in &waits {
            wait.recv()
                .expect("every direction must report that it ended");
        }
        assert_eq!(
            arrived.load(std::sync::atomic::Ordering::SeqCst),
            DIRECTIONS,
            "every direction must run exactly once"
        );
    }

    #[test]
    fn a_direction_that_panics_does_not_take_the_worker_with_it() {
        let pool = RelayPool::global();
        pool.run(|| panic!("this direction is broken on purpose"))
            .recv()
            .expect(
                "a panicking direction still has to report that it ended, or the relay \
             waits on it forever",
            );
        let (tx, rx) = std::sync::mpsc::channel();
        pool.run(move || {
            let _ = tx.send(());
        })
        .recv()
        .expect("the pool still works");
        assert!(rx.try_recv().is_ok(), "and the work after it actually ran");
    }

    #[derive(Clone, Default)]
    struct ClosingSink {
        state: Arc<Mutex<(bool, Vec<u8>)>>,
    }

    impl ClosingSink {
        fn closed_empty(&self) -> bool {
            let state = self.state.lock().expect("locks");
            state.0 && state.1.is_empty()
        }
        fn accepted(&self) -> Vec<u8> {
            self.state.lock().expect("locks").1.clone()
        }
    }

    impl CarrierSink for ClosingSink {
        fn send(&self, bytes: &[u8]) -> bool {
            let mut state = self.state.lock().expect("locks");
            if state.0 {
                return false;
            }
            state.1.extend_from_slice(bytes);
            true
        }
        fn close(&self) {
            self.state.lock().expect("locks").0 = true;
        }
    }

    fn relay_against_a_late_peer(drain: bool) -> (bool, Vec<u8>) {
        let peer = TcpListener::bind("127.0.0.1:0").expect("binds");
        let peer_port = peer.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (mut stream, _) = peer.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request);
            assert_eq!(&request, b"request", "the peer saw the whole request");
            stream.write_all(b"reply").expect("writes");
            std::thread::sleep(Duration::from_millis(300));
        });

        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let sink = ClosingSink::default();
        let carrier = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            let uplink = TcpStream::connect(("127.0.0.1", peer_port)).expect("dials");
            let sink = sink.clone();
            if drain {
                relay_sink_drained(stream, &sink, &uplink);
            } else {
                relay_sink(stream, &sink, &uplink, |_| {});
            }
            sink
        });
        let client = thread::spawn(move || {
            let stream = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
            let mut writer = stream.try_clone().expect("clones");
            writer.write_all(b"request").expect("writes");
            writer.shutdown(Shutdown::Write).expect("half closes");
        });
        let sink = carrier.join().expect("joins");
        client.join().expect("joins");
        server.join().expect("joins");
        (sink.closed_empty(), sink.accepted())
    }

    #[test]
    fn the_drained_order_lets_the_last_reply_reach_the_sink() {
        let (closed_empty, accepted) = relay_against_a_late_peer(true);
        assert_eq!(
            accepted, b"reply",
            "the reply the peer sent after its FIN must reach the sink before the close"
        );
        assert!(
            !closed_empty,
            "the sink must close after the reply, not before it"
        );
    }

    #[test]
    fn the_default_order_refuses_a_reply_that_follows_the_fin() {
        let (closed_empty, accepted) = relay_against_a_late_peer(false);
        assert!(
            closed_empty || accepted.is_empty(),
            "a sink that closed before the reply must not accept it"
        );
    }

    #[test]
    fn a_dial_that_cannot_connect_is_classified_not_dropped() {
        let failure =
            dial(&SocketAddr::from(([127, 0, 0, 1], 1))).expect_err("nothing listens on port 1");
        assert_eq!(failure.stage, Stage::SocketConnected);
        assert_eq!(
            failure.kind,
            Kind::Refused,
            "a refused connect is observed, not inferred"
        );
        assert!(!failure.worth_retrying());
    }

    #[test]
    fn the_reporting_wrapper_counts_a_fatal_dial_and_returns_none() {
        let before = dial_failures();
        assert!(dial_or_report(&SocketAddr::from(([127, 0, 0, 1], 1))).is_none());
        let after = dial_failures();
        assert_eq!(after.fatal, before.fatal + 1, "a refused connect is fatal");
        assert_eq!(
            after.retryable, before.retryable,
            "and must not also be counted as retryable"
        );
    }

    #[test]
    fn a_relay_buffer_promotes_only_on_a_read_that_filled_it() {
        let mut buffer = RelayBuf::new();
        assert_eq!(buffer.size(), RELAY_SMALL_BUFFER);

        for _ in 0..64 {
            let short = buffer.filled(RELAY_SMALL_BUFFER - 1);
            assert_eq!(short.len(), RELAY_SMALL_BUFFER - 1);
            assert_eq!(buffer.size(), RELAY_SMALL_BUFFER, "a short read promoted");
        }

        assert_eq!(buffer.filled(RELAY_SMALL_BUFFER).len(), RELAY_SMALL_BUFFER);
        assert_eq!(buffer.size(), RELAY_BUFFER, "a full read did not promote");

        assert_eq!(buffer.filled(1).len(), 1);
        assert_eq!(buffer.size(), RELAY_BUFFER);
    }

    #[test]
    fn a_promoted_buffer_returns_the_bytes_that_were_read() {
        let mut buffer = RelayBuf::new();
        buffer.as_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        let read = buffer.filled(RELAY_SMALL_BUFFER);
        assert_eq!(&read[..4], &[1, 2, 3, 4], "promotion lost the bytes read");
        assert_eq!(read.len(), RELAY_SMALL_BUFFER);
    }

    #[test]
    fn the_relay_moves_a_payload_larger_than_its_copy_buffer() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = vec![0u8; RELAY_BUFFER];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            let Ok(uplink) = TcpStream::connect(("127.0.0.1", echo_port)) else {
                return;
            };
            relay(&stream, &uplink);
        });

        let payload: Vec<u8> = (0..(3 * RELAY_BUFFER + 7))
            .map(|i| (i % 253) as u8)
            .collect();
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let sent = client.try_clone().expect("clones");
        let outbound = payload.clone();
        let reader = thread::spawn(move || {
            let mut sent = sent;
            sent.write_all(&outbound).expect("writes");
            sent.shutdown(Shutdown::Write).expect("half closes");
        });
        let mut back = vec![0u8; payload.len()];
        client.read_exact(&mut back).expect("reads");
        reader.join().expect("sender finishes");
        assert_eq!(back, payload, "the relay must move every byte, in order");
    }

    #[test]
    fn trojan_relay_round_trips_and_refuses_strangers() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = echo.accept().expect("accepts");
            relay(&stream, &stream);
        });
        let server = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(2) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || {
                    serve_trojan(stream, &trojan_key("an-example-shared-password"), true);
                });
            }
        });
        let mut good = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("an-example-shared-password"));
        header.extend_from_slice(b"\r\n\x01\x01\x7f\x00\x00\x01");
        header.extend_from_slice(&echo_port.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        good.write_all(&header).expect("writes");
        good.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        good.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        let mut bad = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        bad.write_all(&[0u8; 64]).expect("writes");
        let mut closed = [0u8; 1];
        assert!(bad.read(&mut closed).is_err() || closed == [0]);
        drop(good);
        drop(bad);
    }

    #[test]
    fn the_trojan_header_costs_two_reads_not_seven() {
        struct Counting<'a> {
            at: usize,
            wire: &'a [u8],
            reads: usize,
        }
        impl Read for Counting<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                let left = self.wire.len() - self.at;
                if left == 0 {
                    return Ok(0);
                }
                let n = left.min(buf.len());
                buf[..n].copy_from_slice(&self.wire[self.at..self.at + n]);
                self.at += n;
                Ok(n)
            }
        }

        let key = trojan_key("an-example-shared-password");
        for (addr, reads) in [
            (b"\x01\x7f\x00\x00\x01\x1f\x90".to_vec(), 2usize),
            (
                [4u8]
                    .into_iter()
                    .chain([0u8; 15])
                    .chain([1u8, 0x1f, 0x90])
                    .collect::<Vec<u8>>(),
                2,
            ),
            (b"\x03\x09localhost\x1f\x90".to_vec(), 3),
        ] {
            let mut wire = key.to_vec();
            wire.extend_from_slice(b"\r\n\x01");
            wire.extend_from_slice(&addr);
            wire.extend_from_slice(b"\r\n");
            let mut reader = Counting {
                at: 0,
                wire: &wire,
                reads: 0,
            };
            let (cmd, _) = decode_trojan_request(&mut reader, &key)
                .unwrap_or_else(|| panic!("decodes {addr:?}"));
            assert_eq!(cmd, 1, "{addr:?}");
            assert_eq!(reader.reads, reads, "{addr:?}");
        }
    }

    #[test]
    fn the_key_compare_reads_every_byte() {
        let key = trojan_key("an-example-shared-password");
        assert!(key_agrees(&key, &key), "the key agrees with itself");
        for at in [0usize, 1, 27, 55] {
            let mut other = key;
            other[at] ^= 0x01;
            assert!(!key_agrees(&other, &key), "byte {at} differs");
        }
        assert!(!key_agrees(&key[..55], &key), "a short read never agrees");
    }

    #[test]
    fn rejects_a_wrong_version_and_user() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            decode_request(&mut stream)
        });
        let mut reader = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        reader.write_all(&[1u8; 18]).expect("writes");
        assert!(writer.join().expect("joins").is_none());
        drop(reader);
    }

    #[test]
    fn vless_security_gate_keeps_plain_and_refuses_reality() {
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        let none =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "none"}}"#)
                .expect("parses");
        let reality =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "reality"}}"#)
                .expect("parses");
        let tls =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp", "security": "tls"}}"#)
                .expect("parses");
        assert!(vless_security_supported(stream_security(&plain)));
        assert!(vless_security_supported(stream_security(&none)));
        assert!(!vless_security_supported(stream_security(&reality)));
        assert!(!vless_security_supported(stream_security(&tls)));
    }

    #[test]
    fn vless_outbound_with_reality_security_is_skipped() {
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
            "streamSettings": {"network": "tcp", "security": "reality"}}]}"#,
        )
        .expect("parses");
        assert!(find_vless_outbound(&root).is_none());
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1",
            "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
            "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        assert!(find_vless_outbound(&root).is_some());
    }

    #[test]
    fn tls_cert_paths_read_the_first_certificate() {
        let tls = crate::json::parse(
            r#"{"streamSettings": {"security": "tls", "tlsSettings": {"certificates": [{"certificateFile": "/tmp/a.crt", "keyFile": "/tmp/a.key"}]}}}"#,
        )
        .expect("parses");
        let settings = tls.get("streamSettings").expect("settings");
        assert_eq!(tls_cert_paths(settings), Some(("/tmp/a.crt", "/tmp/a.key")));
        assert!(inbound_tls_identity(&tls).is_none());
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        let settings = plain.get("streamSettings").expect("settings");
        assert_eq!(tls_cert_paths(settings), None);
    }

    #[test]
    fn carriers_read_their_paths_out_of_stream_settings() {
        let xhttp = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "mode": "stream-one"}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(xhttp.get("streamSettings")),
            Carrier::Xhttp { path } if path == "/share"
        ));
        let legacy = crate::json::parse(
            r#"{"streamSettings": {"network": "xhttp", "splithttpSettings": {"path": "/legacy"}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(legacy.get("streamSettings")),
            Carrier::Xhttp { path } if path == "/legacy"
        ));
        let camouflage = crate::json::parse(
            r#"{"streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "http", "request": {"path": ["/camouflage"]}}}}}"#,
        )
        .expect("parses");
        assert!(matches!(
            stream_carrier(camouflage.get("streamSettings")),
            Carrier::HttpHeader { path } if path == "/camouflage"
        ));
        let plain =
            crate::json::parse(r#"{"streamSettings": {"network": "tcp"}}"#).expect("parses");
        assert!(matches!(
            stream_carrier(plain.get("streamSettings")),
            Carrier::Raw
        ));
    }

    fn vless_over_carrier_reaches_echo(carrier: &Carrier, host: &str, path: &str) {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let serving: Carrier = carrier.clone();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_vless(stream, &id, &serving, true);
        });
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        let header = link.encode_request_header("127.0.0.1", echo_port);
        let uplink = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        match &carrier {
            Carrier::Xhttp { .. } => {
                let (mut reader, writer) =
                    crate::xhttp::connect(uplink, host, path).expect("upgrades");
                writer.send(&header);
                let mut reply = [0u8; 2];
                reader.read_exact(&mut reply).expect("replies");
                assert_eq!(reply, [0, 0]);
                writer.send(b"ping");
                writer.finish();
                let mut back = Vec::new();
                reader.read_to_end(&mut back).expect("echoes");
                assert_eq!(back, b"ping");
            }
            Carrier::HttpHeader { .. } => {
                let (mut reader, mut write) =
                    crate::httpheader::connect(uplink, host, path).expect("headers");
                write.write_all(&header).expect("writes");
                let mut reply = [0u8; 2];
                reader.read_exact(&mut reply).expect("replies");
                assert_eq!(reply, [0, 0]);
                write.write_all(b"ping").expect("writes");
                let mut back = [0u8; 4];
                reader.read_exact(&mut back).expect("echoes");
                assert_eq!(&back, b"ping");
            }
            _ => unreachable!("this helper only serves the two new carriers"),
        }
    }

    #[test]
    fn vless_over_xhttp_reaches_echo() {
        vless_over_carrier_reaches_echo(
            &Carrier::Xhttp {
                path: "/share".to_owned(),
            },
            "oracle.example",
            "/share",
        );
    }

    #[test]
    fn vless_over_http_camouflage_reaches_echo() {
        vless_over_carrier_reaches_echo(
            &Carrier::HttpHeader {
                path: "/camouflage".to_owned(),
            },
            "oracle.example",
            "/camouflage",
        );
    }

    const CARRIER_CERT: &[u8] = &[
        48, 130, 1, 106, 48, 130, 1, 16, 160, 3, 2, 1, 2, 2, 20, 9, 118, 203, 85, 160, 31, 89, 126,
        130, 240, 1, 124, 88, 139, 2, 183, 133, 180, 103, 195, 48, 10, 6, 8, 42, 134, 72, 206, 61,
        4, 3, 2, 48, 23, 49, 21, 48, 19, 6, 3, 85, 4, 3, 12, 12, 99, 97, 114, 114, 105, 101, 114,
        46, 116, 101, 115, 116, 48, 30, 23, 13, 50, 54, 49, 48, 48, 52, 49, 52, 52, 56, 50, 49, 90,
        23, 13, 51, 54, 49, 48, 48, 49, 49, 52, 52, 56, 50, 49, 90, 48, 23, 49, 21, 48, 19, 6, 3,
        85, 4, 3, 12, 12, 99, 97, 114, 114, 105, 101, 114, 46, 116, 101, 115, 116, 48, 89, 48, 19,
        6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7, 3, 66, 0, 4, 41,
        137, 145, 160, 42, 144, 149, 142, 54, 81, 211, 232, 207, 195, 182, 234, 177, 95, 42, 39,
        92, 183, 224, 141, 46, 233, 255, 84, 155, 88, 113, 20, 230, 111, 41, 31, 113, 3, 159, 7,
        37, 57, 17, 202, 128, 16, 91, 230, 56, 82, 214, 175, 165, 189, 32, 28, 94, 83, 15, 239,
        210, 113, 16, 253, 163, 58, 48, 56, 48, 23, 6, 3, 85, 29, 17, 4, 16, 48, 14, 130, 12, 99,
        97, 114, 114, 105, 101, 114, 46, 116, 101, 115, 116, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4,
        20, 126, 53, 130, 175, 120, 162, 169, 76, 233, 165, 63, 46, 152, 172, 200, 218, 190, 139,
        205, 23, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4, 3, 2, 3, 72, 0, 48, 69, 2, 33, 0, 130, 231,
        244, 98, 234, 42, 158, 5, 44, 34, 56, 45, 180, 195, 201, 250, 215, 93, 204, 192, 169, 181,
        83, 133, 90, 244, 246, 224, 213, 45, 28, 10, 2, 32, 92, 67, 120, 137, 239, 251, 234, 128,
        183, 189, 254, 199, 96, 112, 70, 178, 155, 92, 36, 164, 173, 158, 104, 237, 93, 67, 213,
        174, 165, 157, 39, 208,
    ];
    const CARRIER_KEY: &[u8] = &[
        48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206,
        61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 203, 157, 10, 119, 189, 153, 186, 104, 43,
        21, 78, 170, 1, 87, 240, 205, 227, 168, 196, 141, 76, 209, 149, 222, 208, 177, 26, 155,
        187, 113, 5, 239, 161, 68, 3, 66, 0, 4, 41, 137, 145, 160, 42, 144, 149, 142, 54, 81, 211,
        232, 207, 195, 182, 234, 177, 95, 42, 39, 92, 183, 224, 141, 46, 233, 255, 84, 155, 88,
        113, 20, 230, 111, 41, 31, 113, 3, 159, 7, 37, 57, 17, 202, 128, 16, 91, 230, 56, 82, 214,
        175, 165, 189, 32, 28, 94, 83, 15, 239, 210, 113, 16, 253,
    ];

    fn carried_round_trip(
        name: &str,
        accept: impl FnOnce(TcpStream) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>
            + Send
            + 'static,
        connect: impl FnOnce(TcpStream) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            let (reader, writer) = accept(stream).expect("accepts carrier");
            let mut stream = CarrierStream { reader, writer };
            let mut buf = vec![0u8; 16 * 1024];
            stream.read_exact(&mut buf).expect("reads");
            stream.write_all(&buf).expect("echoes");
            stream.flush().expect("flushes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (reader, writer) = connect(stream).expect("connects carrier");
        let mut stream = CarrierStream { reader, writer };
        let sent: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
        stream.write_all(&sent).expect("writes");
        stream.flush().expect("flushes");
        let mut back = vec![0u8; 16 * 1024];
        stream.read_exact(&mut back).expect("reads");
        assert_eq!(back, sent, "{name} round trips");
        server.join().expect("joins");
    }

    #[test]
    fn carried_streams_round_trip_over_ws() {
        carried_round_trip(
            "ws",
            |stream| {
                let (reader, writer) = crate::ws::accept(stream, "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::ws::connect(stream, "127.0.0.1", "/tunnel", 0, &[])?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn carried_streams_round_trip_over_xhttp() {
        carried_round_trip(
            "xhttp",
            |stream| {
                let (reader, writer) = crate::xhttp::accept(stream, "/share")?;
                let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::xhttp::connect(stream, "127.0.0.1", "/share")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn carried_streams_round_trip_behind_the_http_camouflage() {
        carried_round_trip(
            "httpheader",
            |stream| {
                let (reader, write) = crate::httpheader::accept(stream, "/camouflage")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, write) =
                    crate::httpheader::connect(stream, "127.0.0.1", "/camouflage")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn carried_streams_round_trip_past_the_upgrade() {
        carried_round_trip(
            "httpupgrade",
            |stream| {
                let (reader, write) = crate::httpupgrade::accept(stream, "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, write) = crate::httpupgrade::connect(stream, "127.0.0.1", "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(write) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    fn carried_tls_configs() -> (
        std::sync::Arc<ferrox_core::tls::TlsServerConfig>,
        ferrox_core::tls::TlsConfig,
    ) {
        let server = std::sync::Arc::new(ferrox_core::tls::TlsServerConfig {
            alpn: Vec::new(),
            cert_chain: vec![CARRIER_CERT.to_vec()],
            key_der: CARRIER_KEY.to_vec(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
        });
        let client = ferrox_core::tls::TlsConfig {
            server_name: "carrier.test".to_owned(),
            alpn: Vec::new(),
            roots: vec![CARRIER_CERT.to_vec()],
            pins: ferrox_core::foxy::pin::Pins::default(),
        };
        (server, client)
    }

    fn tls_over_carrier(
        name: &str,
        accept: impl FnOnce(TcpStream) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>
            + Send
            + 'static,
        connect: impl FnOnce(TcpStream) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        use ferrox_core::tls::TlsProvider as _;

        let (server_config, client_config) = carried_tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .expect("timeout");
            let (reader, writer) = accept(stream).expect("accepts carrier");
            let mut tls =
                ferrox_core::tls::accept(&server_config, CarrierStream { reader, writer })
                    .expect("configures");
            tls.handshake().expect("handshakes");
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).expect("reads");
            tls.write_all(&buf).expect("echoes");
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (reader, writer) = connect(stream).expect("connects carrier");
        let mut tls = ferrox_core::tls::connect(&client_config, CarrierStream { reader, writer })
            .expect("configures");
        tls.handshake().expect("handshakes over {name}");
        tls.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        tls.read_exact(&mut back).expect("reads");
        assert_eq!(&back, b"ping", "{name} carries the session");
        server.join().expect("joins");
    }

    #[test]
    fn tls_handshakes_over_ws_messages() {
        tls_over_carrier(
            "ws",
            |stream| {
                let (reader, writer) = crate::ws::accept(stream, "/tunnel")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::ws::connect(stream, "127.0.0.1", "/tunnel", 0, &[])?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn tls_handshakes_over_xhttp_chunks() {
        tls_over_carrier(
            "xhttp",
            |stream| {
                let (reader, writer) = crate::xhttp::accept(stream, "/share")?;
                let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
            |stream| {
                let (reader, writer) = crate::xhttp::connect(stream, "127.0.0.1", "/share")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn vmess_outbounds_carry_their_carriers() {
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vmess", "settings": {"vnext": [{"address": "192.0.2.1", "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "security": "chacha20-poly1305"}]}]}, "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share", "host": "oracle.example"}}}]}"#,
        )
        .expect("parses");
        let out = find_vmess_outbound(&root).expect("finds");
        assert!(matches!(out.carrier, Carrier::Xhttp { .. }));
        assert_eq!(out.host, "oracle.example");
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vmess", "settings": {"vnext": [{"address": "192.0.2.1", "port": 443, "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]}, "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        let out = find_vmess_outbound(&plain).expect("finds");
        assert!(matches!(out.carrier, Carrier::Raw));
        assert_eq!(out.host, "192.0.2.1");
    }

    #[test]
    fn socks_dials_vmess_over_xhttp_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            crate::vmess::serve_xhttp(stream, "/share", &id, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Xhttp {
                path: "/share".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn trojan_outbounds_carry_their_hosts() {
        let root = crate::json::parse(
            r#"{"outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "192.0.2.1", "port": 443, "password": "secret"}]}, "streamSettings": {"network": "ws", "wsSettings": {"path": "/tunnel", "host": "oracle.example"}}}]}"#,
        )
        .expect("parses");
        let out = find_trojan_outbound(&root).expect("finds");
        assert!(matches!(out.carrier, Carrier::Ws { .. }));
        assert_eq!(out.host, "oracle.example");
        let plain = crate::json::parse(
            r#"{"outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "192.0.2.1", "port": 443, "password": "secret"}]}, "streamSettings": {"network": "tcp"}}]}"#,
        )
        .expect("parses");
        let out = find_trojan_outbound(&plain).expect("finds");
        assert!(matches!(out.carrier, Carrier::Raw));
        assert_eq!(out.host, "192.0.2.1");
    }

    #[test]
    fn trojan_over_ws_reaches_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_trojan_ws(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let uplink = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (mut reader, writer) =
            crate::ws::connect(uplink, "oracle.example", "/tunnel", 0, &[]).expect("upgrades");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("secret"));
        header.extend_from_slice(b"\r\n");
        header.push(1);
        push_addr(
            &mut header,
            &SocketAddr::new(std::net::IpAddr::V4([127, 0, 0, 1].into()), echo_port),
            4,
        );
        header.extend_from_slice(&echo_port.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        assert!(writer.send(&header));
        assert!(writer.send(b"ping"));
        let mut back = [0u8; 4];
        reader.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    fn socks_dials_ss_via(
        carrier: Carrier,
        serve: fn(TcpStream, &str, &str, &str, bool),
        path: &str,
    ) {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let password = "an-example-shared-password";
        let method = "aes-256-gcm";
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        let owned = path.to_owned();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve(stream, password, method, &owned, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Shadowsocks(ShadowsocksOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            method: method.to_owned(),
            password: password.to_owned(),
            carrier,
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_ss_over_ws_to_echo() {
        socks_dials_ss_via(
            Carrier::Ws {
                path: "/ss-ws".to_owned(),
                ed: 0,
            },
            crate::shadowsocks::serve_ws,
            "/ss-ws",
        );
    }

    #[test]
    fn socks_dials_ss_over_httpupgrade_to_echo() {
        socks_dials_ss_via(
            Carrier::HttpUpgrade {
                path: "/ss-upgrade".to_owned(),
            },
            crate::shadowsocks::serve_httpupgrade,
            "/ss-upgrade",
        );
    }

    #[test]
    fn socks_dials_ss_over_grpc_to_echo() {
        socks_dials_ss_via(
            Carrier::Grpc {
                path: "/TunnelService/Tun".to_owned(),
            },
            crate::shadowsocks::serve_grpc,
            "/TunnelService/Tun",
        );
    }

    #[test]
    fn socks_dials_ss_over_xhttp_to_echo() {
        socks_dials_ss_via(
            Carrier::Xhttp {
                path: "/ss-xhttp".to_owned(),
            },
            crate::shadowsocks::serve_xhttp,
            "/ss-xhttp",
        );
    }

    #[test]
    fn socks_dials_ss_over_httpheader_to_echo() {
        socks_dials_ss_via(
            Carrier::HttpHeader {
                path: "/ss-camouflage".to_owned(),
            },
            crate::shadowsocks::serve_httpheader,
            "/ss-camouflage",
        );
    }

    #[test]
    fn udp_frames_carry_every_length() {
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                match read_udp_datagram(&mut stream, &mut buf) {
                    Some(n) => {
                        if !write_udp_datagram(&mut stream, &buf[..n]) {
                            return;
                        }
                    }
                    None => return,
                }
            }
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        for len in [1usize, 64, 512, 1460, 8192, 32768, 65535] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert!(write_udp_datagram(&mut stream, &payload), "len {len}");
            let mut buf = vec![0u8; UDP_BUF];
            assert_eq!(
                read_udp_datagram(&mut stream, &mut buf),
                Some(len),
                "len {len}"
            );
            assert_eq!(&buf[..len], &payload[..], "len {len}");
        }
        assert!(write_udp_datagram(&mut stream, &[]));
        let congestion: Vec<u8> = (0..64).map(|i| (i % 251) as u8).collect();
        assert!(write_udp_datagram(&mut stream, &congestion));
        let mut buf = vec![0u8; UDP_BUF];
        assert_eq!(read_udp_datagram(&mut stream, &mut buf), Some(64));
        assert_eq!(&buf[..64], &congestion[..]);
    }

    #[test]
    fn socks_udp_datagrams_split_and_reject() {
        for addr in [
            "127.0.0.1:53".parse().expect("addr"),
            "[::1]:443".parse().expect("addr"),
        ] {
            let mut packet = vec![0u8, 0, 0];
            push_socks_addr(&mut packet, &addr);
            packet.extend_from_slice(b"ping");
            let (got, payload) = parse_socks_udp(&packet).expect("splits");
            assert_eq!(got, addr);
            assert_eq!(payload, b"ping");
        }
        let mut fragged = vec![0u8, 0, 1, 1, 127, 0, 0, 1, 0, 53];
        fragged.extend_from_slice(b"ping");
        assert!(parse_socks_udp(&fragged).is_none());
        assert!(parse_socks_udp(&[0, 0, 0]).is_none());
        assert!(parse_socks_udp(&[0, 0, 0, 9, 1, 2, 3]).is_none());
        assert!(parse_socks_udp(&[0, 0, 0, 1, 127, 0, 0]).is_none());
    }

    #[test]
    fn vless_udp_reaches_echo_over_raw_tcp() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = TcpStream::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        stream
            .write_all(&vless_header(&id, 2, &target))
            .expect("requests");
        assert!(read_vless_response(&mut stream).is_some());
        assert!(write_udp_datagram(&mut stream, b"ping"));
        let mut buf = vec![0u8; UDP_BUF];
        assert_eq!(read_udp_datagram(&mut stream, &mut buf), Some(4));
        assert_eq!(&buf[..4], b"ping");
    }

    #[test]
    fn vless_udp_with_a_flow_is_refused() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = TcpStream::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut header = vec![0u8];
        header.extend_from_slice(&id);
        header.push(18);
        header.extend_from_slice(b"\x0A\x10xtls-rprx-vision");
        header.push(2);
        header.extend_from_slice(&target.port().to_be_bytes());
        push_addr(&mut header, &target, 3);
        stream.write_all(&header).expect("requests");
        let mut back = [0u8; 2];
        assert!(stream.read_exact(&mut back).is_err());
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_vless() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            carrier: Carrier::Raw,
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source, target);
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn trojan_udp_frames_carry() {
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            let mut head = Vec::with_capacity(32);
            loop {
                match read_trojan_datagram(&mut stream, &mut buf) {
                    Some((dest, n)) => {
                        if !write_trojan_datagram(&mut stream, &dest, &buf[..n], &mut head) {
                            return;
                        }
                    }
                    None => return,
                }
            }
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let v4: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let mut head = Vec::with_capacity(32);
        assert!(write_trojan_datagram(&mut stream, &v4, b"ping", &mut head));
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest, v4);
        assert_eq!(&buf[..n], b"ping");
        assert!(write_trojan_datagram(&mut stream, &v4, &[], &mut head));
        let wide: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        assert!(write_trojan_datagram(&mut stream, &v4, &wide, &mut head));
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest, v4);
        assert_eq!(&buf[..n], &wide[..]);
        let mut domain = vec![3u8, 9];
        domain.extend_from_slice(b"localhost");
        domain.extend_from_slice(&53u16.to_be_bytes());
        domain.extend_from_slice(&4u16.to_be_bytes());
        domain.extend_from_slice(b"\r\n");
        domain.extend_from_slice(b"ping");
        stream.write_all(&domain).expect("writes");
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest.port(), 53);
        assert!(dest.ip().is_loopback());
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    fn trojan_udp_frames_reject_damage() {
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            while read_trojan_datagram(&mut stream, &mut buf).is_some() {}
        });
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        stream.write_all(b"\x07bad-separator").expect("writes");
        let mut buf = vec![0u8; UDP_BUF];
        assert!(read_trojan_datagram(&mut stream, &mut buf).is_none());
    }

    #[test]
    fn serve_trojan_udp_relays_datagrams() {
        fn echo() -> u16 {
            let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let mut buf = vec![0u8; UDP_BUF];
                loop {
                    let Ok((n, src)) = echo.recv_from(&mut buf) else {
                        return;
                    };
                    if echo.send_to(&buf[..n], src).is_err() {
                        return;
                    }
                }
            });
            port
        }
        let first = echo();
        let second = echo();
        let key = trojan_key("secret");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan(stream, &key, true);
        });
        let mut stream = TcpStream::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let target: SocketAddr = format!("127.0.0.1:{first}").parse().expect("addr");
        let mut header = Vec::new();
        header.extend_from_slice(&key);
        header.extend_from_slice(b"\r\n");
        header.push(3);
        push_addr(&mut header, &target, 4);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.extend_from_slice(b"\r\n");
        stream.write_all(&header).expect("requests");
        let mut head = Vec::with_capacity(32);
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let dest: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            assert!(write_trojan_datagram(&mut stream, &dest, word, &mut head));
            let mut buf = vec![0u8; UDP_BUF];
            let (source, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
            assert_eq!(source.port(), dest.port());
            assert_eq!(source.ip().to_canonical(), dest.ip().to_canonical());
            assert_eq!(&buf[..n], word);
        }
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_trojan() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan(stream, &trojan_key("secret"), true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Raw,
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source.port(), target.port());
        assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
        assert_eq!(payload, b"ping");
    }

    #[test]
    fn vmess_udp_reaches_echo_over_raw_tcp() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let id = [0x5au8; 16];
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            crate::vmess::serve(stream, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = TcpStream::connect(("127.0.0.1", tunnel_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let Some((request, mut send, mut recv, response_key, response_iv, auth)) =
            crate::vmess::client_request(&id, crate::vmess::Cipher::Chacha, &target, 2)
        else {
            panic!("handshake refused");
        };
        uplink.write_all(&request).expect("requests");
        assert!(crate::vmess::read_response(
            &mut uplink,
            &response_key,
            &response_iv,
            auth
        ));
        let Some(mut pad) = crate::vmess::PadSource::fresh() else {
            panic!("no entropy");
        };
        let mut staging = Vec::with_capacity(UDP_BUF);
        let mut scratch = Vec::with_capacity(UDP_BUF);
        assert!(crate::vmess::write_frame(
            &mut uplink,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let back = crate::vmess::read_frame(&mut uplink, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_vmess() {
        fn echo() -> u16 {
            let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
            let port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let mut buf = vec![0u8; UDP_BUF];
                loop {
                    let Ok((n, src)) = echo.recv_from(&mut buf) else {
                        return;
                    };
                    if echo.send_to(&buf[..n], src).is_err() {
                        return;
                    }
                }
            });
            port
        }
        let first = echo();
        let second = echo();
        let id = [0x5au8; 16];
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in tunnel.incoming().take(2) {
                let Ok(stream) = stream else {
                    continue;
                };
                thread::spawn(move || crate::vmess::serve(stream, &id, true));
            }
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Raw,
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let mut datagram = vec![0u8, 0, 0];
            push_socks_addr(&mut datagram, &target);
            datagram.extend_from_slice(word);
            udp.send_to(&datagram, relay).expect("sends");
            let mut back = vec![0u8; UDP_BUF];
            let (n, _) = udp.recv_from(&mut back).expect("echoes");
            let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
            assert_eq!(source.port(), target.port());
            assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
            assert_eq!(payload, word);
        }
    }

    #[test]
    fn shadowsocks_udp_reaches_echo() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let front = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let password = "an-example-shared-password";
        thread::spawn(move || {
            crate::shadowsocks::serve_udp_on(&front, password, "aes-256-gcm", true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let master = ferrox_core::shadowsocks::MasterKey::new(password, 32);
        let method = ferrox_core::shadowsocks::Method::Aes256Gcm;
        let packet = crate::shadowsocks::seal_udp_datagram(&master, method, &target, b"ping")
            .expect("seals");
        let mut attempts = 0usize;
        loop {
            attempts += 1;
            assert!(attempts <= 15, "no echo after {attempts} fresh sockets");
            let dial = UdpSocket::bind("127.0.0.1:0").expect("binds");
            dial.set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let mut back = vec![0u8; UDP_BUF];
            let mut echoed = None;
            for _ in 0..3 {
                if dial
                    .send_to(&packet, format!("127.0.0.1:{front_port}"))
                    .is_err()
                {
                    break;
                }
                if let Ok((n, _)) = dial.recv_from(&mut back) {
                    echoed = Some(n);
                    break;
                }
            }
            let Some(n) = echoed else {
                continue;
            };
            let (source, payload) =
                crate::shadowsocks::open_udp_datagram(&master, method, &back[..n]).expect("opens");
            assert_eq!(source.port(), target.port());
            assert_eq!(payload, b"ping");
            return;
        }
    }

    #[test]
    fn socks_associate_reaches_udp_echo_via_shadowsocks() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        let probe = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = probe.local_addr().expect("addr").port();
        drop(probe);
        thread::spawn(move || {
            crate::shadowsocks::serve_udp(
                &format!("127.0.0.1:{tunnel_port}"),
                "an-example-shared-password",
                "aes-256-gcm",
                true,
            );
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Shadowsocks(ShadowsocksOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            method: "aes-256-gcm".to_owned(),
            password: "an-example-shared-password".to_owned(),
            carrier: Carrier::Raw,
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut datagram = vec![0u8, 0, 0];
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        push_socks_addr(&mut datagram, &target);
        datagram.extend_from_slice(b"ping");
        udp.send_to(&datagram, relay).expect("sends");
        let mut back = vec![0u8; UDP_BUF];
        let (n, _) = udp.recv_from(&mut back).expect("echoes");
        let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
        assert_eq!(source.port(), target.port());
        assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
        assert_eq!(payload, b"ping");
    }

    fn mux_test_echo() -> u16 {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in echo.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut buf) else {
                            return;
                        };
                        if read == 0 || stream.write_all(&buf[..read]).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    fn mux_test_send(
        stream: &mut TcpStream,
        frame: ferrox_core::mux::Outgoing<'_>,
        data: Option<&[u8]>,
    ) {
        let mut buf = vec![0u8; frame.frame_len(data.map_or(0, <[u8]>::len))];
        let n = frame.encode_into(data, &mut buf);
        stream.write_all(&buf[..n]).expect("writes");
    }

    fn mux_test_recv_frame(
        stream: &mut TcpStream,
    ) -> (u16, ferrox_core::mux::Status, Option<SocketAddr>, Vec<u8>) {
        let mut raw = [0u8; 2];
        stream.read_exact(&mut raw).expect("reads");
        let meta_len = usize::from(u16::from_be_bytes(raw));
        let mut meta = vec![0u8; meta_len];
        stream.read_exact(&mut meta).expect("reads");
        let mut whole = raw.to_vec();
        whole.extend_from_slice(&meta);
        if meta.get(3).is_some_and(|options| options & 1 != 0) {
            let mut chunk_len = [0u8; 2];
            stream.read_exact(&mut chunk_len).expect("reads");
            let chunk_n = usize::from(u16::from_be_bytes(chunk_len));
            let mut chunk = vec![0u8; chunk_n];
            stream.read_exact(&mut chunk).expect("reads");
            whole.extend_from_slice(&chunk_len);
            whole.extend_from_slice(&chunk);
        }
        let (frame, _) =
            ferrox_core::mux::decode(&whole, ferrox_core::mux::NewTail::Forward).expect("decodes");
        (
            frame.id,
            frame.status,
            frame.target.and_then(|t| mux_target_addr(&t)),
            frame.data.unwrap_or(&[]).to_vec(),
        )
    }

    fn mux_test_recv(stream: &mut TcpStream) -> (u16, ferrox_core::mux::Status, Vec<u8>) {
        let (id, status, _, data) = mux_test_recv_frame(stream);
        (id, status, data)
    }

    fn mux_test_target(port: u16) -> ferrox_core::mux::Target<'static> {
        ferrox_core::mux::Target {
            network: ferrox_core::mux::Network::Tcp,
            port,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    fn mux_test_connect(id: &[u8; 16], tunnel_port: u16) -> TcpStream {
        let mut stream = TcpStream::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        stream.write_all(&vless_mux_header(id)).expect("requests");
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).expect("replies");
        assert_eq!(response, [0, 0]);
        stream
    }

    fn mux_test_expect_close(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut probe = [0u8; 64];
        loop {
            match stream.read(&mut probe) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }

    fn mux_test_udp_echo() -> u16 {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                let Ok((n, src)) = echo.recv_from(&mut buf) else {
                    return;
                };
                if echo.send_to(&buf[..n], src).is_err() {
                    return;
                }
            }
        });
        port
    }

    fn mux_test_udp_target(port: u16) -> ferrox_core::mux::Target<'static> {
        ferrox_core::mux::Target {
            network: ferrox_core::mux::Network::Udp,
            port,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    #[test]
    fn mux_udp_relays_datagrams_and_reuses_a_global_id() {
        let echo_port = mux_test_udp_echo();
        let id = [0x5au8; 16];
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut client = mux_test_connect(&id, tunnel_port);
        let identity = [9u8; ferrox_core::mux::GLOBAL_ID];
        let new = ferrox_core::mux::Outgoing {
            id: 7,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(mux_test_udp_target(echo_port)),
            global_id: Some(identity),
        };
        mux_test_send(&mut client, new, Some(b"ping"));
        let (got, status, source, data) = mux_test_recv_frame(&mut client);
        assert_eq!(got, 7);
        assert_eq!(status, ferrox_core::mux::Status::Keep);
        assert_eq!(source.expect("source").port(), echo_port);
        assert_eq!(data, b"ping");
        let keep = ferrox_core::mux::Outgoing {
            id: 7,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: Some(mux_test_udp_target(echo_port)),
            global_id: None,
        };
        mux_test_send(&mut client, keep, Some(b"pong"));
        let (_, _, _, data) = mux_test_recv_frame(&mut client);
        assert_eq!(data, b"pong");
        let again = ferrox_core::mux::Outgoing {
            id: 8,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(mux_test_udp_target(echo_port)),
            global_id: Some(identity),
        };
        mux_test_send(&mut client, again, Some(b"ping"));
        let (closed, status, _, _) = mux_test_recv_frame(&mut client);
        assert_eq!((closed, status), (7, ferrox_core::mux::Status::End));
        let (got, status, _, data) = mux_test_recv_frame(&mut client);
        assert_eq!(got, 8);
        assert_eq!(status, ferrox_core::mux::Status::Keep);
        assert_eq!(data, b"ping");
    }

    #[test]
    fn xudp_frames_match_the_upstream_layout() {
        let target = mux_target_of("203.0.113.7:5000".parse().expect("addr"));
        let new = ferrox_core::mux::Outgoing {
            id: 0,
            status: ferrox_core::mux::Status::New,
            options: ferrox_core::mux::DATA,
            target: Some(target),
            global_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
        };
        let mut frame = vec![0u8; new.frame_len(4)];
        let written = new.encode_into(Some(b"ping"), &mut frame);
        assert_eq!(
            &frame[..written],
            &[
                0x00, 0x14, 0x00, 0x00, 0x01, 0x01, 0x02, 0x13, 0x88, 0x01, 203, 0, 113, 7, 1, 2,
                3, 4, 5, 6, 7, 8, 0x00, 0x04, b'p', b'i', b'n', b'g'
            ][..]
        );
        let keep = ferrox_core::mux::Outgoing {
            id: 0,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: Some(target),
            global_id: None,
        };
        let mut frame = vec![0u8; keep.frame_len(4)];
        let written = keep.encode_into(Some(b"pong"), &mut frame);
        assert_eq!(
            &frame[..written],
            &[
                0x00, 0x0c, 0x00, 0x00, 0x02, 0x01, 0x02, 0x13, 0x88, 0x01, 203, 0, 113, 7, 0x00,
                0x04, b'p', b'o', b'n', b'g'
            ][..]
        );
    }

    #[test]
    fn socks_associate_reaches_two_udp_targets_over_one_mux_connection() {
        let first = mux_test_udp_echo();
        let second = mux_test_udp_echo();
        let id = [0x5au8; 16];
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        let opens = Arc::new(AtomicU64::new(0));
        let opened = Arc::clone(&opens);
        thread::spawn(move || {
            for stream in tunnel.incoming() {
                let Ok(stream) = stream else {
                    continue;
                };
                opened.fetch_add(1, Ordering::Relaxed);
                thread::spawn(move || serve_vless_raw(stream, &id, true));
            }
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            carrier: Carrier::Raw,
            host: "127.0.0.1".to_owned(),
            mux: true,
            quic_roots: None,
            hysteria_roots: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 0])
            .expect("associates");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        let relay: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4([127, 0, 0, 1].into()),
            u16::from_be_bytes(reply[8..10].try_into().expect("port")),
        );
        let udp = UdpSocket::bind("127.0.0.1:0").expect("binds");
        udp.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let target: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            let mut datagram = vec![0u8, 0, 0];
            push_socks_addr(&mut datagram, &target);
            datagram.extend_from_slice(word);
            udp.send_to(&datagram, relay).expect("sends");
            let mut back = vec![0u8; UDP_BUF];
            let (n, _) = udp.recv_from(&mut back).expect("echoes");
            let (source, payload) = parse_socks_udp(&back[..n]).expect("splits");
            assert_eq!(source.port(), target.port());
            assert_eq!(source.ip().to_canonical(), target.ip().to_canonical());
            assert_eq!(payload, word);
        }
        assert_eq!(
            opens.load(Ordering::Relaxed),
            1,
            "one carrier connection carries every target"
        );
    }

    #[test]
    fn mux_serve_demuxes_two_sessions() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let first = mux_test_echo();
        let second = mux_test_echo();
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = mux_test_connect(&id, tunnel_port);
        let new7 = ferrox_core::mux::Outgoing {
            id: 7,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(mux_test_target(first)),
            global_id: None,
        };
        let new9 = ferrox_core::mux::Outgoing {
            id: 9,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(mux_test_target(second)),
            global_id: None,
        };
        mux_test_send(&mut stream, new7, None);
        mux_test_send(&mut stream, new9, None);
        let keep = |id: u16| ferrox_core::mux::Outgoing {
            id,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        mux_test_send(&mut stream, keep(7), Some(b"ping"));
        mux_test_send(&mut stream, keep(9), Some(b"pong"));
        let end = |id: u16| ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
        mux_test_send(&mut stream, end(7), None);
        let mut first_echo = Vec::new();
        let mut second_echo = Vec::new();
        let mut saw_end = false;
        for _ in 0..8 {
            let (got, status, payload) = mux_test_recv(&mut stream);
            match (got, status) {
                (7, ferrox_core::mux::Status::Keep) => first_echo.extend_from_slice(&payload),
                (9, ferrox_core::mux::Status::Keep) => second_echo.extend_from_slice(&payload),
                (7, ferrox_core::mux::Status::End) => {
                    saw_end = true;
                }
                other => panic!("unexpected frame {other:?}"),
            }
            if first_echo.len() >= 4 && second_echo.len() >= 4 && saw_end {
                break;
            }
        }
        assert_eq!(first_echo, b"ping");
        assert_eq!(second_echo, b"pong");
        assert!(saw_end);
    }

    #[test]
    fn mux_serve_refuses_unknown_and_malformed() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let echo_port = mux_test_echo();
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = mux_test_connect(&id, tunnel_port);
        let stray = ferrox_core::mux::Outgoing::bare(77, ferrox_core::mux::Status::Keep, 0);
        mux_test_send(&mut stream, stray, None);
        let live = ferrox_core::mux::Outgoing {
            id: 5,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(ferrox_core::mux::Target {
                network: ferrox_core::mux::Network::Tcp,
                port: echo_port,
                addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
            }),
            global_id: None,
        };
        mux_test_send(&mut stream, live, None);
        let keep = ferrox_core::mux::Outgoing {
            id: 5,
            status: ferrox_core::mux::Status::Keep,
            options: ferrox_core::mux::DATA,
            target: None,
            global_id: None,
        };
        mux_test_send(&mut stream, keep, Some(b"ping"));
        let mut got = Vec::new();
        for _ in 0..4 {
            let (frame_id, frame_status, payload) = mux_test_recv(&mut stream);
            if frame_id == 5 && frame_status == ferrox_core::mux::Status::Keep {
                got.extend_from_slice(&payload);
                if got.len() >= 4 {
                    break;
                }
            }
        }
        assert_eq!(got, b"ping");
        stream.write_all(&[0, 9]).expect("writes");
        stream.write_all(b"\x09unknown-id").expect("writes");
        mux_test_expect_close(&mut stream);
    }

    #[test]
    fn socks_dials_vless_mux_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            carrier: Carrier::Raw,
            host: "127.0.0.1".to_owned(),
            mux: true,
            quic_roots: None,
            hysteria_roots: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn trojan_over_ws_rejects_a_wrong_password() {
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_trojan_ws(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let uplink = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        uplink
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let (mut reader, writer) =
            crate::ws::connect(uplink, "oracle.example", "/tunnel", 0, &[]).expect("upgrades");
        let mut header = Vec::new();
        header.extend_from_slice(&trojan_key("wrong"));
        header.extend_from_slice(b"\r\n");
        header.push(1);
        header.extend_from_slice(&[1, 127, 0, 0, 1]);
        header.extend_from_slice(&8080u16.to_be_bytes());
        header.extend_from_slice(b"\r\n");
        assert!(writer.send(&header));
        let mut back = [0u8; 4];
        assert!(reader.read_exact(&mut back).is_err());
    }

    #[test]
    fn socks_dials_vmess_over_ws_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            crate::vmess::serve_ws(stream, "/tunnel", &id, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Ws {
                path: "/tunnel".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_vmess_over_httpupgrade_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            crate::vmess::serve_httpupgrade(stream, "/tunnel", &id, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::HttpUpgrade {
                path: "/tunnel".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_vmess_over_grpc_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            crate::vmess::serve_grpc(stream, "/TunnelService/Tun", &id, true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            id,
            cipher: crate::vmess::Cipher::Chacha,
            carrier: Carrier::Grpc {
                path: "/TunnelService/Tun".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_ws_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan_ws(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Ws {
                path: "/tunnel".to_owned(),
                ed: 0,
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_httpupgrade_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan_httpupgrade(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::HttpUpgrade {
                path: "/tunnel".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_grpc_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan_grpc(stream, &trojan_key("secret"), "/Tun", true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Grpc {
                path: "/Tun".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_xhttp_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan_xhttp(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::Xhttp {
                path: "/tunnel".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_trojan_over_httpheader_to_echo() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_trojan_httpheader(stream, &trojan_key("secret"), "/tunnel", true);
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: tunnel_port,
            key: trojan_key("secret"),
            carrier: Carrier::HttpHeader {
                path: "/tunnel".to_owned(),
            },
            host: "127.0.0.1".to_owned(),
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn quic_carrier_is_named_not_raw() {
        let plain = crate::json::parse(r#"{"network":"quic"}"#).expect("parses");
        assert!(matches!(stream_carrier(Some(&plain)), Carrier::Quic));
        let masked =
            crate::json::parse(r#"{"network":"quic","tcpSettings":{"header":{"type":"http"}}}"#)
                .expect("parses");
        assert!(matches!(stream_carrier(Some(&masked)), Carrier::Quic));
        assert!(matches!(stream_carrier(None), Carrier::Raw));
    }

    #[test]
    fn every_upstream_network_name_is_named() {
        let cases = [
            ("ws", "Ws"),
            ("websocket", "Ws"),
            ("httpupgrade", "HttpUpgrade"),
            ("grpc", "Grpc"),
            ("xhttp", "Xhttp"),
            ("splithttp", "Xhttp"),
            ("quic", "Quic"),
            ("kcp", "Kcp"),
            ("mkcp", "Kcp"),
            ("hysteria", "Hysteria"),
            ("masque", "Masque"),
            ("xdrive", "Xdrive"),
            ("raw", "Raw"),
            ("tcp", "Raw"),
            ("h2", "Http"),
            ("h3", "Http"),
            ("http", "Http"),
            ("futureNet", "Unknown"),
        ];
        for (network, want) in cases {
            let doc = crate::json::parse(&format!(r#"{{"network":"{network}"}}"#)).expect("parses");
            let got = stream_carrier(Some(&doc));
            let tag = match &got {
                Carrier::Raw => "Raw",
                Carrier::Ws { .. } => "Ws",
                Carrier::HttpUpgrade { .. } => "HttpUpgrade",
                Carrier::Grpc { .. } => "Grpc",
                Carrier::Xhttp { .. } => "Xhttp",
                Carrier::HttpHeader { .. } => "HttpHeader",
                Carrier::Quic => "Quic",
                Carrier::Kcp(_) => "Kcp",
                Carrier::Hysteria(_) => "Hysteria",
                Carrier::Masque => "Masque",
                Carrier::Xdrive => "Xdrive",
                Carrier::Http => "Http",
                Carrier::Unknown => "Unknown",
            };
            assert_eq!(tag, want, "{network} should map to {want}");
        }
    }

    #[test]
    fn quic_serve_closes_without_handshake() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_vless(stream, &id, &Carrier::Quic, true);
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut probe = [0u8; 1];
        assert_eq!(client.read(&mut probe).expect("reads"), 0);
    }

    #[test]
    fn quic_dial_udp_uplink_is_none() {
        let relay = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let vless = VlessOut {
            address: "127.0.0.1".to_owned(),
            port: 9,
            id: uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id"),
            carrier: Carrier::Quic,
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
        };
        let dest: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let source = Arc::new(Mutex::new(None));
        assert!(dial_udp_uplink(&vless, &dest, &relay, source).is_none());
    }

    const QUIC_TEST_TIMEOUT: Duration = Duration::from_secs(120);

    const QUIC_TEST_POLL: Duration = Duration::from_millis(100);

    fn quic_server_poll(sock: &UdpSocket, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
        sock.set_read_timeout(Some(QUIC_TEST_POLL))
            .expect("timeout");
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
            Err(e) => panic!("server socket died: {e:?}"),
        }
    }

    fn quic_server_idle(conn: &mut quiche::Connection, sock: &UdpSocket, out: &mut [u8]) {
        conn.on_timeout();
        while let Ok((written, info)) = conn.send(out) {
            sock.send_to(&out[..written], info.to).expect("answers");
        }
    }

    fn quic_server_accept(
        sock: &UdpSocket,
        local: SocketAddr,
        config: &mut quiche::Config,
    ) -> (quiche::Connection, Vec<u8>) {
        let mut buf = [0u8; 1350];
        let mut out = [0u8; 1350];
        let knock_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let (mut conn, peer_scid) = loop {
            assert!(std::time::Instant::now() < knock_deadline, "hears knocking");
            let Some((n, from)) = quic_server_poll(sock, &mut buf) else {
                continue;
            };
            let header = quiche::Header::from_slice(&mut buf[..n], 20).expect("parses");
            if header.ty != quiche::Type::Initial || header.version != quiche::PROTOCOL_VERSION {
                continue;
            }
            let peer_scid = header.scid.as_ref().to_vec();
            let mut scid = [0u8; 16];
            getrandom::getrandom(&mut scid).expect("random");
            let cid = quiche::ConnectionId::from_ref(&scid);
            let mut fresh = quiche::accept(&cid, None, local, from, config).expect("accepts");
            let info = quiche::RecvInfo { from, to: local };
            fresh.recv(&mut buf[..n], info).expect("handshakes");
            while let Ok((written, info)) = fresh.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            break (fresh, peer_scid);
        };
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        while !conn.is_established() {
            if let Some((n, from)) = quic_server_poll(sock, &mut buf) {
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
            } else {
                quic_server_idle(&mut conn, sock, &mut out);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client handshake stalls"
            );
        }
        (conn, peer_scid)
    }

    #[allow(clippy::too_many_lines)] // A protocol loop: header, accept, then echo.
    fn quic_vless_echo_server(
        sock: UdpSocket,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        expected_header: Vec<u8>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let tag = format!("ferrox-quic-test-{}-{stamp}", std::process::id());
            let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
            let key_path = std::env::temp_dir().join(format!("{tag}.key"));
            std::fs::write(&cert_path, &cert_pem).expect("stages cert");
            std::fs::write(&key_path, &key_pem).expect("stages key");
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
            config
                .set_application_protos(&[crate::quic::ALPN])
                .expect("negotiates");
            config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
            config.set_initial_max_data(crate::quic::MAX_DATA);
            config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
            config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
            config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
            config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
            config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
            config
                .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
                .expect("loads chain");
            config
                .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
                .expect("loads key");
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let (mut conn, _) = quic_server_accept(&sock, local, &mut config);
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let mut seen = Vec::new();
            let stream_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            while seen.len() < expected_header.len() {
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    quic_server_idle(&mut conn, &sock, &mut out);
                    assert!(
                        std::time::Instant::now() < stream_deadline,
                        "header never arrives"
                    );
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let mut piece = [0u8; 8192];
                while let Ok((n, _)) = conn.stream_recv(0, &mut piece) {
                    seen.extend_from_slice(&piece[..n]);
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
                assert!(
                    std::time::Instant::now() < stream_deadline,
                    "header never arrives"
                );
            }
            assert_eq!(seen, expected_header);
            assert_eq!(conn.application_proto(), crate::quic::ALPN);
            assert!(
                crate::quic::stream_send_all(&mut conn, &sock, 0, &[0, 0], false, stream_deadline),
                "the accept goes out"
            );
            while let Ok((written, info)) = conn.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let echo_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            loop {
                if conn.is_closed() {
                    return;
                }
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    quic_server_idle(&mut conn, &sock, &mut out);
                    if std::time::Instant::now() >= echo_deadline {
                        return;
                    }
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                conn.recv(&mut buf[..n], info).expect("drives");
                let mut piece = [0u8; 8192];
                while let Ok((n, fin)) = conn.stream_recv(0, &mut piece) {
                    if n > 0 {
                        assert!(
                            crate::quic::stream_send_all(
                                &mut conn,
                                &sock,
                                0,
                                &piece[..n],
                                false,
                                echo_deadline
                            ),
                            "the echo goes out"
                        );
                    }
                    if fin {
                        let _ = conn.close(false, 0, b"done");
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
            }
        })
    }

    /// How often the ferry misbehaves, counted over the packets it carries.
    /// Each field is the `n`th packet to misbehave; zero disables that fault,
    /// so the faithful case is the same code path rather than a second ferry.
    #[derive(Clone, Copy, PartialEq)]
    struct FerryFaults {
        drop: usize,
        duplicate: usize,
        hold: usize,
    }

    const FAITHFUL: FerryFaults = FerryFaults {
        drop: 0,
        duplicate: 0,
        hold: 0,
    };

    /// The loss a loopback socket cannot be asked for on demand: one packet in
    /// four dropped, one in seven doubled, one in five held back a round.
    const LOSSY: FerryFaults = FerryFaults {
        drop: 4,
        duplicate: 7,
        hold: 5,
    };

    /// The two ends and the addresses they name each other by, so a ferry and
    /// its tests pass one value around instead of four.
    struct Pipe {
        client: quiche::Connection,
        server: quiche::Connection,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
        header: Vec<u8>,
    }

    /// Carries packets between the two ends in process. The socket test proves
    /// the real sockets, this proves the protocol, and neither is asked to
    /// prove the other's half.
    struct Ferry {
        faults: FerryFaults,
        carried: usize,
        dropped: usize,
        duplicated: usize,
        reordered: usize,
    }

    impl Ferry {
        fn new(faults: FerryFaults) -> Self {
            Self {
                faults,
                carried: 0,
                dropped: 0,
                duplicated: 0,
                reordered: 0,
            }
        }

        fn deliver(&mut self, pipe: &mut Pipe, bytes: &[u8], to_server: bool) {
            let Pipe {
                client,
                server,
                client_addr,
                server_addr,
                ..
            } = pipe;
            let info = quiche::RecvInfo {
                from: if to_server {
                    *client_addr
                } else {
                    *server_addr
                },
                to: if to_server {
                    *server_addr
                } else {
                    *client_addr
                },
            };
            let mut buf = bytes.to_vec();
            let outcome = if to_server {
                server.recv(&mut buf, info)
            } else {
                client.recv(&mut buf, info)
            };
            // A faithful ferry must never fail to hand a packet over; an
            // adversarial one may, because a dropped or reordered packet is
            // exactly what the protocol has to survive.
            assert!(
                !(outcome.is_err() && self.faults == FAITHFUL),
                "a faithful ferry must deliver every packet it carries"
            );
        }

        /// One packet through the faults. A held packet waits in `held` and
        /// `run` delivers it after the rest of the round, so it arrives late.
        fn pass(
            &mut self,
            pipe: &mut Pipe,
            bytes: Vec<u8>,
            to_server: bool,
            held: &mut Vec<(Vec<u8>, bool)>,
        ) {
            self.carried += 1;
            let seen = self.carried;
            let hits = |every: usize| every > 0 && seen.is_multiple_of(every);
            if hits(self.faults.drop) {
                self.dropped += 1;
                return;
            }
            if hits(self.faults.hold) {
                held.push((bytes, to_server));
                return;
            }
            let twice = hits(self.faults.duplicate);
            self.deliver(pipe, &bytes, to_server);
            if twice {
                self.duplicated += 1;
                self.deliver(pipe, &bytes, to_server);
            }
        }

        /// Carry everything both ends want to send, then release what was held,
        /// then offer the timers. The timers matter under loss: a round that
        /// carried only acknowledgements is still the round whose dropped
        /// packet may be due for retransmission.
        fn run(&mut self, pipe: &mut Pipe) {
            let mut buf = [0u8; 1350];
            let mut out: Vec<(Vec<u8>, bool)> = Vec::new();
            {
                let Pipe { client, server, .. } = pipe;
                for to_server in [true, false] {
                    loop {
                        let sent = if to_server {
                            client.send(&mut buf)
                        } else {
                            server.send(&mut buf)
                        };
                        let Ok((n, _)) = sent else { break };
                        out.push((buf[..n].to_vec(), to_server));
                    }
                }
            }
            let mut held: Vec<(Vec<u8>, bool)> = Vec::new();
            for (bytes, to_server) in out {
                self.pass(pipe, bytes, to_server, &mut held);
            }
            let late = std::mem::take(&mut held);
            self.reordered += late.len();
            for (bytes, to_server) in late {
                self.deliver(pipe, &bytes, to_server);
            }
            let Pipe { client, server, .. } = pipe;
            client.on_timeout();
            server.on_timeout();
        }

        /// One tunnel over one stream: the vless header out, `[0, 0]` back, the
        /// payload echoed. Every packet between here passes the faults.
        fn tunnel(&mut self, pipe: &mut Pipe, stream: u64, payload: &[u8]) {
            let want = pipe.header.len();
            let header = pipe.header.clone();
            pipe.client
                .stream_send(stream, &header, false)
                .expect("opens");
            let mut piece = [0u8; 8192];
            let mut seen = Vec::new();
            for _ in 0..10_000 {
                self.run(pipe);
                {
                    let Pipe { server, .. } = pipe;
                    while let Ok((n, _)) = server.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        seen.extend_from_slice(&piece[..n]);
                    }
                }
                if seen.len() >= want {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(seen, pipe.header, "the header survives the ferry");
            let mut back = Vec::new();
            let mut offered = false;
            for _ in 0..10_000 {
                self.run(pipe);
                if !offered {
                    let Pipe { server, .. } = pipe;
                    offered = server.stream_send(stream, &[0, 0], false).is_ok();
                }
                {
                    let Pipe { client, .. } = pipe;
                    while let Ok((n, _)) = client.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        back.extend_from_slice(&piece[..n]);
                    }
                }
                if back.len() >= 2 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(back, [0, 0], "the accept survives the ferry");
            pipe.client
                .stream_send(stream, payload, false)
                .expect("writes");
            let mut echo = Vec::new();
            let mut pending: Vec<u8> = Vec::new();
            let mut held_back = 0usize;
            for _ in 0..10_000 {
                self.run(pipe);
                {
                    let Pipe { server, .. } = pipe;
                    while let Ok((n, _)) = server.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        pending.extend_from_slice(&piece[..n]);
                    }
                    while held_back < pending.len() {
                        match server.stream_send(stream, &pending[held_back..], false) {
                            Ok(written) if written > 0 => held_back += written,
                            _ => break,
                        }
                    }
                }
                {
                    let Pipe { client, .. } = pipe;
                    while let Ok((n, _)) = client.stream_recv(stream, &mut piece) {
                        if n == 0 {
                            break;
                        }
                        echo.extend_from_slice(&piece[..n]);
                    }
                }
                if echo.len() >= payload.len() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(echo, payload, "the echo survives the ferry");
        }
    }

    fn quic_pipe_endpoints() -> Pipe {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let mut client_config = crate::quic::quiche_config(&roots, None).expect("configures");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-quic-pipe-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        server_config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        server_config.set_initial_max_data(crate::quic::MAX_DATA);
        server_config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
        server_config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
        server_config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
        server_config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
        server_config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
        server_config
            .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
            .expect("loads chain");
        server_config
            .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
            .expect("loads key");
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        let client_addr: SocketAddr = "127.0.0.1:4433".parse().expect("addr");
        let server_addr: SocketAddr = "127.0.0.1:8443".parse().expect("addr");
        let mut ccid = [0u8; 16];
        getrandom::getrandom(&mut ccid).expect("random");
        let ccid = quiche::ConnectionId::from_ref(&ccid);
        let mut client = quiche::connect(
            Some("localhost"),
            &ccid,
            client_addr,
            server_addr,
            &mut client_config,
        )
        .expect("connects");
        let mut first = [0u8; 1350];
        let (n, _) = client.send(&mut first).expect("initial flight");
        let initial = quiche::Header::from_slice(&mut first[..n], 20).expect("parses");
        assert_eq!(initial.ty, quiche::Type::Initial);
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let scid = quiche::ConnectionId::from_ref(&scid);
        let mut server = quiche::accept(&scid, None, server_addr, client_addr, &mut server_config)
            .expect("accepts");
        let info = quiche::RecvInfo {
            from: client_addr,
            to: server_addr,
        };
        server.recv(&mut first[..n], info).expect("ingests");
        let mut pipe = Pipe {
            client,
            server,
            client_addr,
            server_addr,
            header: vless_header(&id, 1, &target),
        };
        let mut ferry = Ferry::new(FAITHFUL);
        for _ in 0..1000 {
            ferry.run(&mut pipe);
            if pipe.client.is_established() && pipe.server.is_established() {
                break;
            }
        }
        assert!(pipe.client.is_established() && pipe.server.is_established());
        pipe
    }

    #[test]
    fn quic_pipe_carries_vless_header_and_close() {
        let mut pipe = quic_pipe_endpoints();
        let mut ferry = Ferry::new(FAITHFUL);
        ferry.tunnel(&mut pipe, 0, b"ping");
        ferry.tunnel(&mut pipe, 4, b"pong");
        pipe.client.stream_send(0, &[], true).expect("ends");
        let _ = pipe.client.close(false, 0, b"done");
        for _ in 0..10_000 {
            ferry.run(&mut pipe);
            if pipe.client.is_closed() && pipe.server.is_closed() {
                assert!(!pipe.client.is_timed_out() && !pipe.server.is_timed_out());
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("quic pipe never closed");
    }

    /// The gate P30 asks for: two tunnels sharing one handshake must both
    /// complete while the ferry drops, doubles and holds packets underneath
    /// them, and the counters prove the faults actually fired rather than the
    /// run quietly avoiding them.
    #[test]
    fn quic_pipe_shares_a_handshake_through_a_lossy_ferry() {
        let mut pipe = quic_pipe_endpoints();
        let mut ferry = Ferry::new(LOSSY);
        ferry.tunnel(&mut pipe, 0, b"ping");
        ferry.tunnel(&mut pipe, 4, b"pong");
        assert!(
            ferry.dropped > 0,
            "the ferry dropped nothing, so it proved nothing"
        );
        assert!(ferry.duplicated > 0, "the ferry doubled nothing");
        assert!(ferry.reordered > 0, "the ferry held nothing back");
    }

    #[allow(clippy::too_many_lines)] // Temporary: timestamp stages for the Linux diagnosis.
    fn quic_concurrent_echo_server(
        sock: UdpSocket,
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        expected_header: Vec<u8>,
    ) -> thread::JoinHandle<(usize, usize)> {
        thread::spawn(move || {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let tag = format!("ferrox-quic-multi-{}-{stamp}", std::process::id());
            let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
            let key_path = std::env::temp_dir().join(format!("{tag}.key"));
            std::fs::write(&cert_path, &cert_pem).expect("stages cert");
            std::fs::write(&key_path, &key_pem).expect("stages key");
            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
            config
                .set_application_protos(&[crate::quic::ALPN])
                .expect("negotiates");
            config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
            config.set_initial_max_data(crate::quic::MAX_DATA);
            config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
            config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
            config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
            config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
            config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
            config
                .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
                .expect("loads chain");
            config
                .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
                .expect("loads key");
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let (mut conn, peer_scid) = quic_server_accept(&sock, local, &mut config);
            crate::quic::qstage(format!(
                "{} t={} accepted",
                local.port(),
                crate::quic::qms()
            ));
            let mut buf = [0u8; 1350];
            let mut out = [0u8; 1350];
            let mut conns = 1usize;
            let mut seen_scids = vec![peer_scid];
            let mut streams: Vec<u64> = Vec::new();
            let mut opening: HashMap<u64, Vec<u8>> = HashMap::new();
            let echo_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            loop {
                if conn.is_closed() {
                    crate::quic::qstage(format!(
                        "{} t={} server-closed conns={conns} streams={}",
                        local.port(),
                        crate::quic::qms(),
                        streams.len()
                    ));
                    break;
                }
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    quic_server_idle(&mut conn, &sock, &mut out);
                    if std::time::Instant::now() >= echo_deadline {
                        crate::quic::qstage(format!(
                            "{} t={} server-bound conns={conns} streams={}",
                            local.port(),
                            crate::quic::qms(),
                            streams.len()
                        ));
                        break;
                    }
                    continue;
                };
                let info = quiche::RecvInfo { from, to: local };
                if let Ok(header) = quiche::Header::from_slice(&mut buf[..n], 20) {
                    if header.ty == quiche::Type::Initial {
                        let scid = header.scid.as_ref().to_vec();
                        if !seen_scids.contains(&scid) {
                            seen_scids.push(scid);
                            conns += 1;
                        }
                        continue;
                    }
                }
                conn.recv(&mut buf[..n], info).expect("drives");
                let mut piece = [0u8; 8192];
                for id in conn.readable().collect::<Vec<u64>>() {
                    if !streams.contains(&id) && !opening.contains_key(&id) {
                        opening.insert(id, Vec::new());
                        crate::quic::qstage(format!(
                            "{} t={} srv-open {id}",
                            local.port(),
                            crate::quic::qms()
                        ));
                    }
                    if let Some(head) = opening.get_mut(&id) {
                        while let Ok((n, _)) = conn.stream_recv(id, &mut piece) {
                            if n == 0 {
                                break;
                            }
                            head.extend_from_slice(&piece[..n]);
                        }
                        if head.len() >= expected_header.len() {
                            assert_eq!(head, &expected_header, "stream opens with VLESS");
                            opening.remove(&id);
                            streams.push(id);
                            assert!(
                                crate::quic::stream_send_all(
                                    &mut conn,
                                    &sock,
                                    id,
                                    &[0, 0],
                                    false,
                                    echo_deadline
                                ),
                                "the accept goes out"
                            );
                            crate::quic::qstage(format!(
                                "{} t={} srv-accept {id}",
                                local.port(),
                                crate::quic::qms()
                            ));
                        }
                        continue;
                    }
                    while let Ok((n, fin)) = conn.stream_recv(id, &mut piece) {
                        if n == 0 && !fin {
                            break;
                        }
                        if n > 0 {
                            assert!(
                                crate::quic::stream_send_all(
                                    &mut conn,
                                    &sock,
                                    id,
                                    &piece[..n],
                                    false,
                                    echo_deadline
                                ),
                                "the echo goes out"
                            );
                            crate::quic::qstage(format!(
                                "{} t={} srv-echo {id} {n}",
                                local.port(),
                                crate::quic::qms()
                            ));
                        }
                        if fin {
                            break;
                        }
                    }
                }
                while let Ok((written, info)) = conn.send(&mut out) {
                    sock.send_to(&out[..written], info.to).expect("answers");
                }
            }
            (conns, streams.len())
        })
    }

    #[test]
    fn socks_dials_vless_quic_to_echo() {
        let _serial = quic_serial();
        quic_retry_dial(socks_quic_once, 3);
    }

    fn socks_quic_once() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let quic_port = quic_sock.local_addr().expect("addr").port();
        let expected_header = vless_header(&id, 1, &target);
        let server = quic_vless_echo_server(
            quic_sock,
            minted.cert.pem().into_bytes(),
            key_pem,
            expected_header,
        );
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: quic_port,
            id,
            carrier: Carrier::Quic,
            host: "localhost".to_owned(),
            mux: false,
            quic_roots: Some(roots),
            hysteria_roots: None,
        });
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&9u16.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        drop(client);
        server.join().expect("joins");
    }

    #[test]
    fn a_quic_carrier_with_mux_never_dials_the_server_tcp_port() {
        let _serial = quic_serial();
        let id = uuid_bytes("bbbbbbbb-cccc-dddd-eeee-ffffffffffff").expect("id");
        let server_tcp = TcpListener::bind("127.0.0.1:0").expect("binds");
        server_tcp.set_nonblocking(true).expect("nonblocking");
        let server_port = server_tcp.local_addr().expect("addr").port();
        let out = Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: server_port,
            id,
            carrier: Carrier::Quic,
            host: "localhost".to_owned(),
            mux: true,
            quic_roots: None,
            hysteria_roots: None,
        });
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let (handed_back, done) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
            let _ = handed_back.send(());
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&9u16.to_be_bytes());
        client.write_all(&request).expect("connects");
        done.recv_timeout(QUIC_TEST_TIMEOUT)
            .expect("the proxy gave up on the carrier");
        assert_eq!(
            server_tcp
                .accept()
                .expect_err("nothing dials the tcp port")
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn quic_outbound_reads_ca_cert_file() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ferrox-quic-ca-{}-{stamp}.pem", std::process::id()));
        std::fs::write(&path, minted.cert.pem().as_bytes()).expect("stages ca");
        let path_text = path.to_str().expect("ascii").to_owned();
        let json_path = path_text.replace('\\', "\\\\");
        let root = crate::json::parse(&format!(
            r#"{{"outbounds": [{{"protocol": "vless",
                "settings": {{"vnext": [{{"address": "127.0.0.1", "port": 443,
                    "users": [{{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}]}}]}},
                "streamSettings": {{"network": "quic", "security": "tls",
                    "tlsSettings": {{"caCertFile": "{json_path}"}}}}}}]}}"#
        ))
        .expect("parses");
        let out = find_vless_outbound(&root).expect("finds quic+tls");
        assert!(matches!(out.carrier, Carrier::Quic));
        let roots = out.quic_roots.expect("carries anchors");
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let _ = std::fs::remove_file(&path);
        let bare = crate::json::parse(
            r#"{"outbounds": [{"protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 443,
                    "users": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}]},
                "streamSettings": {"network": "quic", "security": "tls"}}]}"#,
        )
        .expect("parses");
        let out = find_vless_outbound(&bare).expect("finds anchorless quic");
        assert!(out.quic_roots.is_none());
    }
    static QUIC_DIAL_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn quic_serial() -> std::sync::MutexGuard<'static, ()> {
        match QUIC_DIAL_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn quic_retry_dial(once: fn(), attempts: u32) {
        for _ in 0..attempts.saturating_sub(1) {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(once)).is_ok() {
                return;
            }
        }
        once();
    }

    #[test]
    fn quic_dials_loopback_echo() {
        let _serial = quic_serial();
        quic_retry_dial(quic_loopback_once, 3);
    }

    fn quic_loopback_once() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 || stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let expected_header = vless_header(&id, 1, &target);
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let quic_port = quic_sock.local_addr().expect("addr").port();
        let server = quic_vless_echo_server(
            quic_sock,
            minted.cert.pem().into_bytes(),
            key_pem,
            expected_header,
        );
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let dial = crate::quic::QuicDial {
            id,
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: quic_port,
            roots: Some(roots),
        };
        let relay = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            crate::quic::dial_pooled(&stream, &dial, &target);
        });
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
        drop(client);
        relay.join().expect("joins");
        server.join().expect("joins");
    }

    #[test]
    fn quic_pool_shares_one_connection_between_two_streams() {
        let _serial = quic_serial();
        quic_retry_dial(quic_pool_once, 5);
    }

    fn pool_read(client: &mut TcpStream, want: [u8; 4], who: &str, port: u16) {
        let mut back = [0u8; 4];
        if let Err(e) = client.read_exact(&mut back) {
            let prefix = format!("{port} ");
            let log = crate::quic::QSTAGES
                .lock()
                .map(|stages| {
                    stages
                        .iter()
                        .filter(|line| line.starts_with(&prefix))
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default();
            panic!("{who} echoes failed: {e:?}\nstages for {port}:\n{log}");
        }
        assert_eq!(back, want, "{who} echo mismatch");
    }

    fn quic_pool_once() {
        if let Ok(mut stages) = crate::quic::QSTAGES.lock() {
            stages.clear();
        }
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let quic_port = quic_sock.local_addr().expect("addr").port();
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let server = quic_concurrent_echo_server(
            quic_sock,
            minted.cert.pem().into_bytes(),
            key_pem,
            vless_header(&id, 1, &target),
        );
        let dial = crate::quic::QuicDial {
            id,
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: quic_port,
            roots: Some(roots),
        };
        let front = Arc::new(TcpListener::bind("127.0.0.1:0").expect("binds"));
        let front_port = front.local_addr().expect("addr").port();
        let task = Arc::clone(&front);
        let dialed = dial.clone();
        let relay1 = thread::spawn(move || {
            let (stream, _) = task.accept().expect("accepts");
            crate::quic::dial_pooled(&stream, &dialed, &target);
        });
        let mut client1 = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client1
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client1.write_all(b"ping").expect("writes");
        pool_read(&mut client1, *b"ping", "client1", quic_port);
        let relay2 = thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            crate::quic::dial_pooled(&stream, &dial, &target);
        });
        let mut client2 = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client2
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client2.write_all(b"pong").expect("writes");
        pool_read(&mut client2, *b"pong", "client2", quic_port);
        drop(client1);
        drop(client2);
        relay1.join().expect("joins");
        relay2.join().expect("joins");
        let (conns, streams) = server.join().expect("joins");
        assert_eq!(conns, 1, "one UDP association, not two handshakes");
        assert_eq!(streams, 2, "two VLESS sessions on it");
    }

    #[test]
    fn kcp_carries_vless_echo_over_loopback() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let kcp_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let listener =
            ferrox_core::kcp::Listener::bind(kcp_addr, ferrox_core::kcp::Config::default())
                .expect("binds");
        let kcp_port = listener.local_addr().port();
        let server = thread::spawn(move || {
            let conn = listener.accept().expect("accepts");
            serve_vless_kcp(&conn, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let header = vless_header(&id, 1, &target);
        let server_addr: SocketAddr = format!("127.0.0.1:{kcp_port}").parse().expect("addr");
        let conn = ferrox_core::kcp::dial(
            server_addr,
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        conn.write(&header).expect("writes");
        let mut io = KcpIo {
            conn: Arc::clone(&conn),
        };
        read_vless_response(&mut io).expect("replies");
        conn.write(b"ping").expect("writes");
        conn.set_read_deadline(std::time::Instant::now() + std::time::Duration::from_secs(10));
        let mut back = [0u8; 4];
        let mut at = 0;
        while at < 4 {
            let n = conn.read(&mut back[at..]).expect("echoes");
            if n == 0 {
                break;
            }
            at += n;
        }
        assert_eq!(&back, b"ping");
        conn.close();
        server.join().expect("joins");
    }

    #[test]
    fn kcp_settings_parse_in_both_casings_with_guarded_fallbacks() {
        let base = ferrox_core::kcp::Config::default();
        let plain = crate::json::parse(r#"{"network":"kcp"}"#).expect("parses");
        assert!(matches!(stream_carrier(Some(&plain)), Carrier::Kcp(cfg) if cfg == base));
        let camel = crate::json::parse(
            r#"{"network":"mkcp","kcpSettings":{"mtu":1400,"tti":20,"uplinkCapacity":10,"downlinkCapacity":50,"cwndMultiplier":2,"maxSendingWindow":1048576}}"#,
        )
        .expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&camel)) else {
            panic!("mkcp names Kcp");
        };
        assert_eq!(cfg.mtu, 1400);
        assert_eq!(cfg.tti, 20);
        assert_eq!(cfg.uplink_capacity, 10);
        assert_eq!(cfg.downlink_capacity, 50);
        assert_eq!(cfg.cwnd_multiplier, 2);
        assert_eq!(cfg.max_sending_window, 1_048_576);
        let snake = crate::json::parse(
            r#"{"network":"kcp","kcpSettings":{"uplink_capacity":7,"downlink_capacity":9,"cwnd_multiplier":3,"max_sending_window":4096}}"#,
        )
        .expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&snake)) else {
            panic!("snake case parses");
        };
        assert_eq!(cfg.uplink_capacity, 7);
        assert_eq!(cfg.downlink_capacity, 9);
        assert_eq!(cfg.cwnd_multiplier, 3);
        assert_eq!(cfg.max_sending_window, 4096);
        let bad = crate::json::parse(
            r#"{"network":"kcp","kcpSettings":{"mtu":10,"tti":0,"uplinkCapacity":7}}"#,
        )
        .expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&bad)) else {
            panic!("bad values still Kcp");
        };
        assert_eq!(cfg.mtu, base.mtu);
        assert_eq!(cfg.tti, base.tti);
        assert_eq!(cfg.uplink_capacity, 7);
        let slow =
            crate::json::parse(r#"{"network":"kcp","kcpSettings":{"tti":5000}}"#).expect("parses");
        let Carrier::Kcp(cfg) = stream_carrier(Some(&slow)) else {
            panic!("slow tti still Kcp");
        };
        assert_eq!(cfg.tti, base.tti);
    }

    #[test]
    fn hysteria_settings_parse_with_guarded_fallbacks() {
        let plain = crate::json::parse(r#"{"network":"hysteria"}"#).expect("parses");
        let Carrier::Hysteria(cfg) = stream_carrier(Some(&plain)) else {
            panic!("hysteria names Hysteria");
        };
        assert_eq!(cfg.auth, "");
        assert_eq!(cfg.cc, ferrox_core::hysteria::Congestion::Bbr);
        let full = crate::json::parse(
            r#"{"network":"hysteria","hysteriaSettings":{"auth":"s3","congestion":"reno","version":2}}"#,
        )
        .expect("parses");
        let Carrier::Hysteria(cfg) = stream_carrier(Some(&full)) else {
            panic!("full settings parse");
        };
        assert_eq!(cfg.auth, "s3");
        assert_eq!(cfg.cc, ferrox_core::hysteria::Congestion::Reno);
        let brutal = crate::json::parse(
            r#"{"network":"hysteria","hysteriaSettings":{"congestion":"force-brutal","version":"2"}}"#,
        )
        .expect("parses");
        let Carrier::Hysteria(cfg) = stream_carrier(Some(&brutal)) else {
            panic!("string version parses");
        };
        assert_eq!(cfg.cc, ferrox_core::hysteria::Congestion::Brutal);
        let old = crate::json::parse(r#"{"network":"hysteria","hysteriaSettings":{"version":1}}"#)
            .expect("parses");
        assert!(matches!(stream_carrier(Some(&old)), Carrier::Unknown));
    }

    fn hysteria_loop_with(auth: &str, id: [u8; 16]) -> (u16, Vec<Vec<u8>>) {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-hysteria-test-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let probe = UdpSocket::bind("127.0.0.1:0").expect("binds");
        let port = probe.local_addr().expect("addr").port();
        drop(probe);
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let address = format!("127.0.0.1:{port}");
        let auths = vec![auth.to_owned()];
        let serve: crate::hysteria::Serve = Arc::new(move |flow| {
            serve_vless_hysteria(flow, &id, true);
        });
        let (cert_path, key_path) = (
            cert_path.to_str().expect("ascii").to_owned(),
            key_path.to_str().expect("ascii").to_owned(),
        );
        thread::spawn(move || {
            crate::hysteria::serve_loop(
                &address,
                &auths,
                ferrox_core::hysteria::Congestion::Bbr,
                &cert_path,
                &key_path,
                &serve,
            );
        });
        (port, roots)
    }

    fn hysteria_tcp_pair(
        port: u16,
        roots: Vec<Vec<u8>>,
        auth: &str,
        id: [u8; 16],
        target: SocketAddr,
    ) -> TcpStream {
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let front_port = front.local_addr().expect("addr").port();
        let dial = crate::hysteria::Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                auth: auth.to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
            },
            roots: Some(roots),
        };
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            crate::hysteria::dial_vless(&stream, &dial, &id, &target);
        });
        let client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(QUIC_TEST_TIMEOUT))
            .expect("timeout");
        client
    }

    fn hysteria_test_server_config(
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> quiche::Config {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).expect("configures");
        config
            .set_application_protos(&[crate::quic::ALPN])
            .expect("negotiates");
        config.set_max_idle_timeout(crate::quic::IDLE_TIMEOUT_MS);
        config.set_initial_max_data(crate::quic::MAX_DATA);
        config.set_initial_max_stream_data_bidi_local(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_stream_data_bidi_remote(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_stream_data_uni(crate::quic::MAX_STREAM_DATA);
        config.set_initial_max_streams_bidi(crate::quic::MAX_STREAMS);
        config.set_initial_max_streams_uni(crate::quic::MAX_STREAMS);
        config
            .load_cert_chain_from_pem_file(cert_path.to_str().expect("ascii"))
            .expect("loads chain");
        config
            .load_priv_key_from_pem_file(key_path.to_str().expect("ascii"))
            .expect("loads key");
        config
    }

    fn hysteria_test_answer_auth(
        conn: &mut quiche::Connection,
        sock: &UdpSocket,
        local: SocketAddr,
        out: &mut [u8; 1350],
    ) -> Vec<u8> {
        let mut buf = [0u8; 1350];
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let mut head = Vec::new();
        loop {
            assert!(std::time::Instant::now() < deadline, "auth never arrives");
            let Some((n, from)) = quic_server_poll(sock, &mut buf) else {
                quic_server_idle(conn, sock, out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            let mut piece = [0u8; 4096];
            while let Ok((n, _)) = conn.stream_recv(0, &mut piece) {
                head.extend_from_slice(&piece[..n]);
            }
            while let Ok((written, info)) = conn.send(out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let mut at = 0usize;
            if let Some(frame) = ferrox_core::foxy::frames::h3_frame(&head, &mut at) {
                if frame.kind == ferrox_core::foxy::frames::H3_HEADERS {
                    if let Some(body) = head.get(at..at + frame.length as usize) {
                        return body.to_vec();
                    }
                }
            }
        }
    }

    fn hysteria_test_read_prefix(
        conn: &mut quiche::Connection,
        sock: &UdpSocket,
        local: SocketAddr,
        out: &mut [u8; 1350],
    ) -> Vec<u8> {
        let mut buf = [0u8; 1350];
        let deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
        let mut prefix = Vec::new();
        loop {
            assert!(std::time::Instant::now() < deadline, "flow never arrives");
            let Some((n, from)) = quic_server_poll(sock, &mut buf) else {
                quic_server_idle(conn, sock, out);
                continue;
            };
            let info = quiche::RecvInfo { from, to: local };
            conn.recv(&mut buf[..n], info).expect("drives");
            let mut piece = [0u8; 4096];
            while let Ok((n, _)) = conn.stream_recv(4, &mut piece) {
                prefix.extend_from_slice(&piece[..n]);
            }
            while let Ok((written, info)) = conn.send(out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            if prefix.len() >= 2 {
                return prefix.split_off(2);
            }
        }
    }

    #[test]
    fn hysteria_client_passes_a_hand_rolled_server() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_client_once, 3);
    }

    fn hysteria_client_once() {
        let echo_port = echo_once();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let tag = format!("ferrox-hysteria-bisect-{}-{stamp}", std::process::id());
        let cert_path = std::env::temp_dir().join(format!("{tag}.crt"));
        let key_path = std::env::temp_dir().join(format!("{tag}.key"));
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        std::fs::write(&cert_path, minted.cert.pem().as_bytes()).expect("stages cert");
        std::fs::write(&key_path, &key_pem).expect("stages key");
        let sock = crate::quic::bind_datagram("127.0.0.1:0").expect("binds");
        let port = sock.local_addr().expect("addr").port();
        thread::spawn(move || {
            let mut config = hysteria_test_server_config(&cert_path, &key_path);
            let _ = std::fs::remove_file(&cert_path);
            let _ = std::fs::remove_file(&key_path);
            let local = sock.local_addr().expect("addr");
            let (mut conn, _) = quic_server_accept(&sock, local, &mut config);
            let mut out = [0u8; 1350];
            let body = hysteria_test_answer_auth(&mut conn, &sock, local, &mut out);
            assert!(
                ferrox_core::hysteria::verify_auth_request(&body, "bisect-auth"),
                "auth verifies"
            );
            let mut block = Vec::new();
            ferrox_core::hysteria::build_auth_response(&mut block);
            let mut frame = Vec::new();
            ferrox_core::foxy::frames::quic_varint(
                &mut frame,
                ferrox_core::foxy::frames::H3_HEADERS,
            );
            ferrox_core::foxy::frames::quic_varint(&mut frame, block.len() as u64);
            frame.extend_from_slice(&block);
            conn.stream_send(0, &frame, true).expect("answers");
            while let Ok((written, info)) = conn.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let rest = hysteria_test_read_prefix(&mut conn, &sock, local, &mut out);
            let flow = crate::hysteria::Flow::from_parts(
                Arc::new(Mutex::new(conn)),
                Arc::new(sock),
                local,
                4,
                rest,
                true,
            );
            serve_vless_hysteria(flow, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let dial = crate::hysteria::Dial {
            host: "localhost".to_owned(),
            address: "127.0.0.1".to_owned(),
            port,
            config: ferrox_core::hysteria::Config {
                auth: "bisect-auth".to_owned(),
                cc: ferrox_core::hysteria::Congestion::Bbr,
            },
            roots: Some(roots),
        };
        let Some(session) = crate::hysteria::connect(&dial) else {
            panic!("client connects");
        };
        let header = vless_header(&id, 1, &target);
        let Some(mut flow) = crate::hysteria::open_flow(&session, &header) else {
            panic!("flow opens");
        };
        flow.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        flow.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn hysteria_server_passes_a_hand_rolled_client() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_server_once, 3);
    }

    fn hysteria_server_once() {
        use ferrox_core::foxy::frames as h3;
        let echo_port = echo_once();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("bisect2-auth", id);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let (sock, peer, local) = crate::quic::udp_to_server("127.0.0.1", port).expect("udp");
        let mut config = crate::quic::quiche_config(&roots, Some("bbr")).expect("configures");
        let mut scid = [0u8; 16];
        getrandom::getrandom(&mut scid).expect("random");
        let cid = quiche::ConnectionId::from_ref(&scid);
        let mut conn =
            quiche::connect(Some("localhost"), &cid, local, peer, &mut config).expect("connects");
        crate::quic::drive_handshake(&mut conn, &sock, local).expect("handshakes");
        let horizon = std::time::Instant::now() + Duration::from_secs(30);
        let mut settings = Vec::new();
        h3::quic_varint(&mut settings, 0x04);
        h3::quic_varint(&mut settings, 0);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 2, &settings, true, horizon
        ));
        let mut block = Vec::new();
        ferrox_core::hysteria::build_auth_request("localhost", "bisect2-auth", &mut block);
        let mut frame = Vec::new();
        h3::quic_varint(&mut frame, h3::H3_HEADERS);
        h3::quic_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 0, &frame, true, horizon
        ));
        let mut head = Vec::new();
        let body = loop {
            let piece = crate::quic::stream_recv_exact(&mut conn, &sock, local, 0, 1, horizon)
                .expect("reads");
            head.extend_from_slice(&piece);
            let mut at = 0usize;
            if let Some(got) = h3::h3_frame(&head, &mut at) {
                if got.kind == h3::H3_HEADERS {
                    if let Some(body) = head.get(at..at + got.length as usize) {
                        break body.to_vec();
                    }
                }
            }
        };
        assert!(ferrox_core::hysteria::verify_auth_response(&body));
        let header = vless_header(&id, 1, &target);
        let mut prefix = Vec::with_capacity(2 + header.len());
        ferrox_core::hysteria::tcp_prefix(&mut prefix);
        prefix.extend_from_slice(&header);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 4, &prefix, false, horizon
        ));
        let reply = crate::quic::stream_recv_exact(&mut conn, &sock, local, 4, 2, horizon)
            .expect("replies");
        assert_eq!(reply.as_slice(), &[0, 0]);
        assert!(crate::quic::stream_send_all(
            &mut conn, &sock, 4, b"ping", false, horizon
        ));
        let back =
            crate::quic::stream_recv_exact(&mut conn, &sock, local, 4, 4, horizon).expect("echoes");
        assert_eq!(back.as_slice(), b"ping");
    }

    #[test]
    fn hysteria_carries_vless_echo_over_loopback() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_echo_once, 3);
    }

    fn hysteria_echo_once() {
        let echo_port = echo_once();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut client = hysteria_tcp_pair(port, roots, "test-auth", id, target);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn hysteria_refuses_a_wrong_password_without_relaying() {
        let _serial = quic_serial();
        quic_retry_dial(hysteria_refuses_once, 3);
    }

    fn hysteria_refuses_once() {
        let echo_port = echo_once();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let (port, roots) = hysteria_loop_with("test-auth", id);
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut client = hysteria_tcp_pair(port, roots, "wrong-auth", id, target);
        let mut probe = [0u8; 1];
        assert_eq!(client.read(&mut probe).expect("reads"), 0);
    }

    fn echo_once() -> u16 {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(n) = stream.read(&mut buf) else {
                    return;
                };
                if n == 0 || stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        });
        port
    }

    fn kcp_loop_with(serve: KcpServe) -> u16 {
        let listener = ferrox_core::kcp::Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            ferrox_core::kcp::Config::default(),
        )
        .expect("binds");
        let port = listener.local_addr().port();
        thread::spawn(move || serve_kcp_each(&listener, &serve));
        port
    }

    fn socks_tcp_client(front_port: u16, echo_port: u16) -> TcpStream {
        let mut client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        client
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        client.write_all(&[5, 1, 0]).expect("greets");
        let mut method = [0u8; 2];
        client.read_exact(&mut method).expect("selects");
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&echo_port.to_be_bytes());
        client.write_all(&request).expect("connects");
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).expect("replies");
        assert_eq!(reply[1], 0);
        client
    }

    fn socks_front_with(out: Outbound) -> u16 {
        let front = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = front.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = front.accept().expect("accepts");
            serve_socks(stream, &out);
        });
        port
    }

    #[test]
    fn socks_dials_vless_over_kcp_to_echo() {
        let echo_port = echo_once();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let serve: KcpServe = Arc::new(move |conn| serve_vless_kcp(conn, &id, true));
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Vless(VlessOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            id,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
            mux: false,
            quic_roots: None,
            hysteria_roots: None,
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn trojan_over_kcp_reaches_echo() {
        let echo_port = echo_once();
        let key = trojan_key("secret");
        let listener = ferrox_core::kcp::Listener::bind(
            "127.0.0.1:0".parse().expect("addr"),
            ferrox_core::kcp::Config::default(),
        )
        .expect("binds");
        let kcp_port = listener.local_addr().port();
        let server = thread::spawn(move || {
            let conn = listener.accept().expect("accepts");
            serve_trojan_kcp(&conn, &key, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let server_addr: SocketAddr = format!("127.0.0.1:{kcp_port}").parse().expect("addr");
        let conn = ferrox_core::kcp::dial(
            server_addr,
            ferrox_core::kcp::Config::default(),
            ferrox_core::kcp::fresh_conversation(),
        )
        .expect("dials");
        conn.write(&trojan_header(&key, 1, &target))
            .expect("writes");
        conn.write(b"ping").expect("writes");
        conn.set_read_deadline(std::time::Instant::now() + std::time::Duration::from_secs(10));
        let mut back = [0u8; 4];
        let mut at = 0;
        while at < 4 {
            let n = conn.read(&mut back[at..]).expect("echoes");
            if n == 0 {
                break;
            }
            at += n;
        }
        assert_eq!(&back, b"ping");
        conn.close();
        server.join().expect("joins");
    }

    #[test]
    fn socks_dials_trojan_over_kcp_to_echo() {
        let echo_port = echo_once();
        let key = trojan_key("secret");
        let serve: KcpServe = Arc::new(move |conn| serve_trojan_kcp(conn, &key, true));
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Trojan(TrojanOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            key,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_vmess_over_kcp_to_echo() {
        let echo_port = echo_once();
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let serve: KcpServe = Arc::new(move |conn| {
            let (reader, writer, close) = kcp_parts(conn);
            crate::vmess::serve_kcp(reader, writer, &id, true, &close);
        });
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Vmess(VmessOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            id,
            cipher: crate::vmess::Cipher::Auto,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }

    #[test]
    fn socks_dials_ss_over_kcp_to_echo() {
        let echo_port = echo_once();
        let password = "an-example-shared-password".to_owned();
        let method = "aes-256-gcm".to_owned();
        let serve_password = password.clone();
        let serve_method = method.clone();
        let serve: KcpServe = Arc::new(move |conn| {
            let (reader, writer, close) = kcp_parts(conn);
            crate::shadowsocks::serve_kcp(
                reader,
                writer,
                &serve_password,
                &serve_method,
                true,
                &close,
            );
        });
        let kcp_port = kcp_loop_with(serve);
        let front_port = socks_front_with(Outbound::Shadowsocks(ShadowsocksOut {
            address: "127.0.0.1".to_owned(),
            port: kcp_port,
            method,
            password,
            carrier: Carrier::Kcp(ferrox_core::kcp::Config::default()),
            host: "127.0.0.1".to_owned(),
        }));
        let mut client = socks_tcp_client(front_port, echo_port);
        client.write_all(b"ping").expect("writes");
        let mut back = [0u8; 4];
        client.read_exact(&mut back).expect("echoes");
        assert_eq!(&back, b"ping");
    }
}

#[cfg(target_os = "linux")]
mod poll_relay {
    use super::{Shutdown, SplicePipe, TcpStream};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};

    const SPLICE_F_NONBLOCK: libc::c_uint = 0x002;

    fn retryable() -> bool {
        matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR | libc::EAGAIN)
        )
    }

    struct Direction {
        src: TcpStream,
        dst: TcpStream,
        pipe: Option<SplicePipe>,
        pending: usize,
        src_at_eof: bool,
        ended: bool,
        done: Option<mpsc::Sender<()>>,
    }

    impl Direction {
        fn new(src: TcpStream, dst: TcpStream, done: mpsc::Sender<()>) -> Self {
            Self {
                src,
                dst,
                pipe: SplicePipe::new(),
                pending: 0,
                src_at_eof: false,
                ended: false,
                done: Some(done),
            }
        }

        fn advance(&mut self) {
            if self.ended {
                return;
            }
            let Some(pipe) = self.pipe.as_ref() else {
                super::copy_all_memcpy(&mut self.src, &mut self.dst);
                self.end();
                return;
            };
            let room = pipe.capacity - self.pending;
            if !self.src_at_eof && room > 0 {
                let moved = unsafe {
                    libc::splice(
                        self.src.as_raw_fd(),
                        std::ptr::null_mut(),
                        pipe.fds[1],
                        std::ptr::null_mut(),
                        room,
                        SPLICE_F_NONBLOCK,
                    )
                };
                if moved > 0 {
                    self.pending += moved as usize;
                } else if moved == 0 {
                    self.src_at_eof = true;
                } else if !retryable() {
                    self.end();
                    return;
                }
            }
            while self.pending > 0 {
                let moved = unsafe {
                    libc::splice(
                        pipe.fds[0],
                        std::ptr::null_mut(),
                        self.dst.as_raw_fd(),
                        std::ptr::null_mut(),
                        self.pending,
                        SPLICE_F_NONBLOCK,
                    )
                };
                if moved > 0 {
                    self.pending -= moved as usize;
                    continue;
                }
                if moved < 0 && !retryable() {
                    self.end();
                    return;
                }
                break;
            }
            if self.src_at_eof && self.pending == 0 {
                self.end();
            }
        }

        fn end(&mut self) {
            if self.ended {
                return;
            }
            self.ended = true;
            let _ = self.dst.shutdown(Shutdown::Write);
            if let Some(done) = self.done.take() {
                let _ = done.send(());
            }
        }
    }

    struct Flow {
        directions: Vec<Direction>,
    }

    impl Flow {
        fn finished(&self) -> bool {
            self.directions.iter().all(|d| d.ended)
        }
    }

    struct Worker {
        queue: Mutex<Vec<Flow>>,
        wake: [libc::c_int; 2],
    }

    impl Worker {
        fn spawn() -> Option<Arc<Self>> {
            let mut wake = [-1; 2];
            if unsafe { libc::pipe(wake.as_mut_ptr()) } != 0 {
                return None;
            }
            for (fd, flags) in [
                (wake[0], libc::O_NONBLOCK),
                (wake[1], libc::O_CLOEXEC | libc::O_NONBLOCK),
            ] {
                unsafe {
                    libc::fcntl(fd, libc::F_SETFL, flags);
                }
            }
            let worker = Arc::new(Self {
                queue: Mutex::new(Vec::new()),
                wake,
            });
            let loop_worker = Arc::clone(&worker);
            let _ = std::thread::Builder::new()
                .name("ferrox-relay".into())
                .spawn(move || run(&loop_worker));
            Some(worker)
        }

        fn push(&self, flow: Flow) {
            if let Ok(mut queue) = self.queue.lock() {
                queue.push(flow);
            }
            let byte = 1u8;
            unsafe {
                libc::write(self.wake[1], std::ptr::addr_of!(byte).cast(), 1);
            }
        }

        fn take(&self) -> Vec<Flow> {
            let mut queue = match self.queue.lock() {
                Ok(queue) => queue,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *queue)
        }

        fn drain_wake(&self) {
            let mut scratch = [0u8; 64];
            loop {
                let got =
                    unsafe { libc::read(self.wake[0], scratch.as_mut_ptr().cast(), scratch.len()) };
                if got <= 0 {
                    return;
                }
            }
        }
    }

    fn run(worker: &Worker) {
        let mut flows: Vec<Flow> = Vec::new();
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(64);
        let mut owners: Vec<(usize, usize)> = Vec::with_capacity(64);
        loop {
            flows.extend(worker.take());
            if flows.iter().any(Flow::finished) {
                flows.retain(|flow| !flow.finished());
            }
            pfds.clear();
            owners.clear();
            pfds.push(libc::pollfd {
                fd: worker.wake[0],
                events: libc::POLLIN,
                revents: 0,
            });
            owners.push((usize::MAX, usize::MAX));
            for (flow_index, flow) in flows.iter().enumerate() {
                for (direction_index, direction) in flow.directions.iter().enumerate() {
                    if direction.ended {
                        continue;
                    }
                    let has_room = match &direction.pipe {
                        Some(pipe) => direction.pending < pipe.capacity,
                        None => true,
                    };
                    if !direction.src_at_eof && has_room {
                        pfds.push(libc::pollfd {
                            fd: direction.src.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        });
                        owners.push((flow_index, direction_index));
                    }
                    if direction.pending > 0 {
                        pfds.push(libc::pollfd {
                            fd: direction.dst.as_raw_fd(),
                            events: libc::POLLOUT,
                            revents: 0,
                        });
                        owners.push((flow_index, direction_index));
                    }
                }
            }
            let answered = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
            if answered < 0 {
                continue;
            }
            for (index, entry) in pfds.iter().enumerate() {
                if entry.revents == 0 {
                    continue;
                }
                let (flow_index, direction_index) = owners[index];
                if flow_index == usize::MAX {
                    worker.drain_wake();
                    continue;
                }
                if let Some(direction) = flows
                    .get_mut(flow_index)
                    .and_then(|flow| flow.directions.get_mut(direction_index))
                {
                    direction.advance();
                }
            }
        }
    }

    fn worker_count() -> usize {
        match std::thread::available_parallelism() {
            Ok(count) => count.get().min(8),
            Err(_) => 1,
        }
    }

    fn workers() -> &'static Vec<Arc<Worker>> {
        static WORKERS: OnceLock<Vec<Arc<Worker>>> = OnceLock::new();
        WORKERS.get_or_init(|| {
            (0..worker_count())
                .filter_map(|_| Worker::spawn())
                .collect()
        })
    }

    fn next() -> &'static Worker {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let all = workers();
        let index = NEXT.fetch_add(1, Ordering::Relaxed) % all.len();
        &all[index]
    }

    pub(super) fn available() -> bool {
        !workers().is_empty()
    }

    pub(super) fn drive(
        client_read: TcpStream,
        target_write: TcpStream,
        target_read: TcpStream,
        client_write: TcpStream,
    ) {
        let worker = next();
        let (first_tx, first_rx) = mpsc::channel();
        let (second_tx, second_rx) = mpsc::channel();
        worker.push(Flow {
            directions: vec![
                Direction::new(client_read, target_write, first_tx),
                Direction::new(target_read, client_write, second_tx),
            ],
        });
        let _ = first_rx.recv();
        let _ = second_rx.recv();
    }
}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    const PATIENCE: Duration = Duration::from_secs(30);

    const REQUEST: &[u8] = b"both ways at once";
    const REPLY: &[u8] = b"and back";

    fn read_all(stream: &mut TcpStream) -> Vec<u8> {
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return got,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("binds")
    }

    fn port_of(listener: &TcpListener) -> u16 {
        listener.local_addr().expect("addr").port()
    }

    fn relayed(payload: Vec<u8>) -> Vec<u8> {
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        let front_far = thread::spawn(move || {
            let (mut stream, _) = front.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            stream.write_all(&payload).expect("writes");
            let _ = stream.shutdown(Shutdown::Write);
            read_all(&mut stream);
        });
        let back_far = thread::spawn(move || {
            let (mut stream, _) = back.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            read_all(&mut stream)
        });

        let client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        let target = TcpStream::connect(("127.0.0.1", back_port)).expect("connects");
        let relay_side = thread::spawn(move || relay(&client, &target));

        let got = back_far.join().expect("joins");
        front_far.join().expect("joins");
        relay_side.join().expect("joins");
        got
    }

    #[test]
    fn a_body_of_every_length_survives_the_event_loop() {
        for len in [
            0usize, 1, 63, 64, 65, 4095, 4096, 4097, 65_535, 262_144, 300_000,
        ] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(
                relayed(payload.clone()),
                payload,
                "the event loop moved {len} bytes as something else"
            );
        }
    }

    #[test]
    fn one_flow_carries_both_directions() {
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        let front_far = thread::spawn(move || {
            let (mut stream, _) = front.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            stream.write_all(REQUEST).expect("writes");
            let _ = stream.shutdown(Shutdown::Write);
            read_all(&mut stream)
        });
        let back_far = thread::spawn(move || {
            let (mut stream, _) = back.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            let got = read_all(&mut stream);
            let _ = stream.write_all(REPLY);
            got
        });

        let client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
        let target = TcpStream::connect(("127.0.0.1", back_port)).expect("connects");
        thread::spawn(move || relay(&client, &target))
            .join()
            .expect("joins");

        assert_eq!(
            front_far.join().expect("joins"),
            REPLY,
            "the reply did not survive the client's half-close"
        );
        assert_eq!(
            back_far.join().expect("joins"),
            REQUEST,
            "the bytes were altered on the way through"
        );
    }

    #[test]
    fn sixteen_flows_at_once_all_arrive_whole() {
        const FLOWS: usize = 16;
        const LEN: usize = 20_000;
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);

        let payloads: Vec<Vec<u8>> = (0..FLOWS)
            .map(|flow| (0..LEN).map(|i| ((i + flow) % 251) as u8).collect())
            .collect();
        let wanted = vec![LEN; FLOWS];

        let outbound = payloads.clone();
        let front_far = thread::spawn(move || {
            let mut held = Vec::with_capacity(FLOWS);
            for payload in &outbound {
                let (mut stream, _) = front.accept().expect("accepts");
                stream.write_all(payload).expect("writes");
                let _ = stream.shutdown(Shutdown::Write);
                held.push(stream);
            }
            held
        });
        let back_far = thread::spawn(move || {
            let mut lengths = Vec::with_capacity(FLOWS);
            for _ in 0..FLOWS {
                let (mut stream, _) = back.accept().expect("accepts");
                stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
                lengths.push(read_all(&mut stream).len());
            }
            lengths
        });

        let mut relays = Vec::with_capacity(FLOWS);
        for _ in 0..FLOWS {
            let client = TcpStream::connect(("127.0.0.1", front_port)).expect("connects");
            let target = TcpStream::connect(("127.0.0.1", back_port)).expect("connects");
            relays.push(thread::spawn(move || relay(&client, &target)));
        }
        for relay_side in relays {
            relay_side.join().expect("joins");
        }
        assert_eq!(
            back_far.join().expect("joins"),
            wanted,
            "a flow among sixteen arrived short, which means two flows shared a pipe"
        );
        front_far.join().expect("joins");
    }
}
