//! Xray-shaped serving surface over the `VLESS` framing this core encodes.
//!
//! Three subcommands the oracle seams call: `version`, `x25519`, and `run -c`
//! with `vless` or `socks` inbounds. Raw-`TCP` relay, `VLESS`/`Trojan`-`UDP`
//! datagram relay, and `VLESS` mux (serve demultiplexed, dial one session per
//! uplink) exist so far: anything else closes fast rather than hanging the
//! suite that asked for it.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::Duration;
// Linux only, and only for the relay's `splice(2)` path; see `copy_all`.
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use crate::json::Json;
// `serve_vless_tls` calls `handshake` through the returned provider, so the trait
// has to be in scope here even though nothing names it.
use ferrox_core::failure::{Failure, Kind, Stage};
use ferrox_core::tls::TlsProvider as _;
use ferrox_core::transport::EarlyData;

/// This binary, so the oracle log names what actually served the test.
pub(crate) fn print_version() {
    println!("ferrox-app {}", env!("CARGO_PKG_VERSION"));
}

/// A real `X25519` pair in the labels the oracle parser matches on.
pub(crate) fn print_x25519() {
    let (private, public) = x25519_pair();
    println!("PrivateKey: {private}");
    println!("Password (PublicKey): {public}");
}

/// Serve every inbound in a config file until killed, like `xray run -c`.
pub(crate) fn serve_file(path: &str) -> ! {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| exit(&format!("cannot read {path}: {error}")));
    let root = crate::json::parse(&text)
        .unwrap_or_else(|error| exit(&format!("bad config {path}: {error}")));
    let freedom = has_protocol(&root, "outbounds", "freedom");
    let outbound = find_outbound(&root);
    let mut inbounds = 0;
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
                    let key = trojan_key(&inbound_password(inbound));
                    let carrier = inbound_carrier(inbound);
                    let address_clone = address.clone();
                    let role = Role::Trojan {
                        key,
                        carrier,
                        freedom,
                    };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    inbounds += 1;
                }
                "vmess" => {
                    let id = inbound_id(inbound);
                    let carrier = inbound_carrier(inbound);
                    let address_clone = address.clone();
                    let role = Role::Vmess {
                        id,
                        carrier,
                        freedom,
                    };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    inbounds += 1;
                }
                "shadowsocks" => {
                    let password = inbound_ss_password(inbound);
                    let method = inbound_method(inbound);
                    let carrier = inbound_carrier(inbound);
                    let address_clone = address.clone();
                    let udp_address = address.clone();
                    let udp_password = password.clone();
                    let udp_method = method.clone();
                    let udp_carrier = carrier.clone();
                    let role = Role::Shadowsocks {
                        password,
                        method,
                        carrier,
                        freedom,
                    };
                    thread::spawn(move || accept_loop(&address_clone, &role));
                    if matches!(udp_carrier, Carrier::Raw) {
                        thread::spawn(move || {
                            crate::shadowsocks::serve_udp(
                                &udp_address,
                                &udp_password,
                                &udp_method,
                                freedom,
                            );
                        });
                    }
                    inbounds += 1;
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
    // One thread owns the tally's only read, so the print needs no lock and no
    // interval. A binary that is killed produces no tally, which is the same
    // information a killed binary has.
    loop {
        thread::park();
        report_dial_failures();
    }
}

/// Start one `vless` inbound, whatever security and carrier it names.
///
/// Reports and skips what it cannot serve rather than exiting: one unusable
/// inbound should not stop the others in the same config from serving.
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

/// How long a dial may take before the connection is given up on.
const DIAL_TIMEOUT: Duration = Duration::from_secs(8);

/// Dial `target` and classify why it failed, with Nagle off.
///
/// One function rather than a `connect_timeout` at each of the eleven call sites,
/// because the property is one that is easy to forget at one of them and
/// impossible to notice: a socket with Nagle on behaves correctly and is quietly
/// slower, so nothing fails and nothing looks wrong. See [`no_delay`].
///
/// The error is [`ferrox_core::failure::Failure`] rather than `None` because
/// every caller of the reporting wrapper below wants the same three facts and
/// none of them could get them from a `None`: how far the attempt got, what
/// refused, and whether that was observed or inferred. See
/// [`ferrox_core::failure`].
fn dial(target: &SocketAddr) -> Result<TcpStream, Failure> {
    let stream = TcpStream::connect_timeout(target, DIAL_TIMEOUT)
        .map_err(|e| Failure::new(Stage::SocketConnected, Kind::of(&e)))?;
    no_delay(&stream);
    Ok(stream)
}

/// [`dial`], reporting a failure once and in one place.
///
/// Every serving arm returns `()` on a failed dial and eleven of them are
/// near-identical, so the classification is done here rather than at each: an
/// error each arm dropped on the floor left a filtered network indistinguishable
/// from a dead server, which is the one distinction this binary cannot afford to
/// lose. `u64` counters rather than a log line, so a caller can read the rate
/// without a scrape, and so a test can assert on it.
fn dial_or_report(target: &SocketAddr) -> Option<TcpStream> {
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

/// Dials that failed for a reason redialing as-is could not fix.
static FATAL_DIALS: AtomicU64 = AtomicU64::new(0);

/// Dials that failed below first byte with a retryable cause.
static RETRYABLE_DIALS: AtomicU64 = AtomicU64::new(0);

/// Dials that failed, split into the two reasons a recovery decision differs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DialFailures {
    /// Not worth redialling as-is: refused, unresolvable, or locally impossible.
    pub fatal: u64,
    /// Worth redialling: a retryable cause below first byte.
    pub retryable: u64,
}

/// The running [`DialFailures`] tally, read for a report and for a test.
pub(crate) fn dial_failures() -> DialFailures {
    DialFailures {
        fatal: FATAL_DIALS.load(Ordering::Relaxed),
        retryable: RETRYABLE_DIALS.load(Ordering::Relaxed),
    }
}

/// Report the tally, so a run that died quietly says why.
///
/// Called from [`serve_file`]'s one blocking accept and printed once: a counter
/// nobody reads is a counter that exists, and the whole point of
/// [`ferrox_core::failure`] is that a dial that stopped is distinguishable from
/// a dial that was never made.
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

/// Turn Nagle off on a socket, as every other engine in this comparison does.
///
/// `std` never sets `TCP_NODELAY` — not on accept, not on dial — and a proxy is
/// the one program for which that is the wrong default: it writes a dozen bytes of
/// handshake and then megabytes of stream, and Nagle exists to protect a
/// request/response protocol that sends one small message at a time. The pinned Go
/// cores turn it off unconditionally on both sockets, at
/// `net/tcpsock.go:289` (`newTCPConn` calls `setNoDelay(fd, true)`) reached from
/// both `ln.fd.accept()` and the dialer, so leaving it on here was a difference
/// from every comparator that no gate was looking at.
///
/// Best effort by construction: a socket that refuses the option is still a
/// working socket, and a proxy that refuses connections because of a performance
/// hint has turned a hint into a policy. The cost of the call is one `setsockopt`
/// per connection against a connection that moves at least a handshake.
///
/// Ignored on the *reply* half too, which is the half that matters most: the
/// `SOCKS` greeting reply and the ten-byte connect reply are each smaller than an
/// MSS, so under Nagle the second of a pair can wait for the first to be
/// acknowledged, and a client that reads them in sequence pays a round trip it
/// did not ask for.
fn no_delay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Print a fatal config error and never return.
fn exit(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}

/// One inbound's serving role, decided once from the config.
#[derive(Debug, Clone)]
enum Role {
    /// Accept `VLESS`, dial the requested target itself.
    Vless {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    /// Accept `VLESS` inside `TLS`, then exactly the raw path within the session.
    VlessTls {
        id: [u8; 16],
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::TlsServerConfig>,
    },
    /// Accept `VLESS` inside a `REALITY` session authenticated by `shortId`.
    VlessReality {
        id: [u8; 16],
        freedom: bool,
        carrier: Carrier,
        server: Arc<ferrox_core::tls::RealityServerConfig>,
    },
    /// Accept `trojan`, dial the requested target itself.
    Trojan {
        /// `SHA224`-hex of the inbound password, expanded once at setup:
        /// every connection compared against this instead of re-hashing.
        key: [u8; 56],
        carrier: Carrier,
        freedom: bool,
    },
    /// Accept `VMess`, dial the requested target itself.
    Vmess {
        id: [u8; 16],
        carrier: Carrier,
        freedom: bool,
    },
    /// Accept `shadowsocks`, dial the requested target itself.
    Shadowsocks {
        password: String,
        method: String,
        carrier: Carrier,
        freedom: bool,
    },
    /// Accept `SOCKS5`, relay through the configured upstream server.
    Socks { out: Outbound },
}

/// Where a `socks` inbound forwards: one upstream server and its credential, or
/// the destination itself.
#[derive(Debug, Clone)]
enum Outbound {
    /// A `vnext` server and its user id bytes.
    Vless(VlessOut),
    /// A `trojan` server and its password.
    Trojan(TrojanOut),
    /// A `vmess` server, user id and cipher.
    Vmess(VmessOut),
    /// A `shadowsocks` server, cipher, and password.
    Shadowsocks(ShadowsocksOut),
    /// `freedom`: dial the requested address directly, with no upstream server.
    ///
    /// The plainest outbound there is, and the one every Xray config that is only
    /// a local forwarder ends up naming. Without it a `socks` inbound has nowhere
    /// to send a connection when no proxy server is configured, and it exits with
    /// "no servable inbound" rather than serving — which reads as a broken binary
    /// rather than as a missing protocol.
    Freedom,
}

/// A `vless` upstream server.
#[derive(Debug, Clone)]
struct VlessOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// User id bytes.
    id: [u8; 16],
    /// Carrier around unchanged `VLESS` bytes, raw `TCP` when unnamed.
    carrier: Carrier,
    /// `Host` header as written, falling back to the server address.
    host: String,
    /// Dial multiplexed: one `VLESS` mux connection carrying this stream.
    mux: bool,
    /// Explicit `DER` trust anchors for a `QUIC` dial, from `tlsSettings`
    /// `caCertFile`; `None` refuses the dial rather than connecting blind.
    /// Every other carrier ignores it: only `QUIC` leaves `TCP`.
    quic_roots: Option<Vec<Vec<u8>>>,
}

/// One name for the refused carriers: `quic`, `kcp`, `hysteria`, `masque`,
/// `xdrive` and anything unknown. Ten identical match arms read
/// `refused_carriers!()` instead of repeating the union — otherwise rustfmt
/// wraps each of the ten identically and the diff trains the eye to ignore
/// a real one.
macro_rules! refused_carriers {
    () => {
        Carrier::Quic
            | Carrier::Kcp
            | Carrier::Hysteria
            | Carrier::Masque
            | Carrier::Xdrive
            | Carrier::Unknown
    };
}

/// Framing around unchanged `VLESS` bytes, read once from `streamSettings`.
#[derive(Debug, Clone)]
enum Carrier {
    /// Raw `TCP`, the default when nothing else is named.
    Raw,
    /// `WebSocket` upgrade at this path, with the `?ed=` budget split off it.
    Ws { path: String, ed: u32 },
    /// `HTTPUpgrade` at this path, raw bytes after the `101`.
    ///
    /// No budget field, because `?ed=` moves no bytes on this carrier: what the
    /// key does to `path` is the whole of it here, and
    /// [`crate::httpupgrade`] says why nothing else followed.
    HttpUpgrade { path: String },
    /// `gRPC` tunnel at this service path.
    Grpc { path: String },
    /// `XHTTP` stream-one at this path, chunked bodies both ways.
    Xhttp { path: String },
    /// `TCP` `HTTP` camouflage at this path, one `GET` then raw bytes.
    HttpHeader { path: String },
    /// `QUIC`: named, parsed and refused — never raw `TCP` in disguise.
    ///
    /// The transport carries no settings of its own (`sing-box`'s
    /// `V2RayQUICOptions` is empty; the security rides `TLS`), so the variant
    /// is a unit: its whole job is to stop `stream_carrier` falling through to
    /// [`Carrier::Raw`], which would silently downgrade a `QUIC` outbound to
    /// plaintext `TCP`. Dialling it needs a `QUIC` stack this tree does not
    /// vendor, so every serve and dial arm below refuses it outright.
    Quic,
    /// `KCP` (`mkcp`): named, parsed; the core is ported (`ferrox_core::kcp`, oracle-proven), the proxy seam refuses it until the stream seam is wired.
    ///
    /// `Xray-core` vendors its own KCP dialect (`transport/internet/kcp`); a
    /// bit-identical port wants a UDP differential oracle that this tree does
    /// not vendor, so this row refuses like [`Carrier::Quic`].
    Kcp,
    /// `Hysteria`: needs its own QUIC stack and congestion-control glue in
    /// `upstream/xray-core/transport/internet/hysteria`; refused like
    /// [`Carrier::Quic`] until that is a rung of its own.
    Hysteria,
    /// `MASQUE` (CONNECT-IP over HTTP/2+H3): refused like [`Carrier::Quic`].
    Masque,
    /// `XDRive` (Yandex Drive as transport): refused like [`Carrier::Quic`].
    Xdrive,
    /// A named network this core does not carry — or one upstream removed:
    /// `h2`/`h3`/`http` were dropped at this pin
    /// (`PrintRemovedFeatureError`), and `quic` likewise in `Xray-core`
    /// (`sing-box` keeps it behind a build tag). Every serve and dial arm
    /// refuses it, so a stale or future config can never fall through to
    /// [`Carrier::Raw`] and silently downgrade to plaintext `TCP`. Xray
    /// itself fails the whole config (`unknown transport protocol`); our
    /// finer grain is dropping the stream.
    Unknown,
}

/// A `vmess` upstream server.
#[derive(Debug, Clone)]
struct VmessOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// User id bytes.
    id: [u8; 16],
    /// Data cipher as written.
    cipher: crate::vmess::Cipher,
    /// Carrier around the sealed bytes, raw `TCP` when unnamed.
    carrier: Carrier,
    /// `Host` header as written, falling back to the server address.
    host: String,
}

/// A `trojan` upstream server.
#[derive(Debug, Clone)]
struct TrojanOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// `SHA224`-hex of the configured password, expanded once at parse: every
    /// dial writes these bytes instead of re-hashing per connection.
    key: [u8; 56],
    /// Carrier around the password-led bytes, raw `TCP` when unnamed.
    carrier: Carrier,
    /// `Host` header as written, falling back to the server address.
    host: String,
}

/// A `shadowsocks` upstream server.
#[derive(Debug, Clone)]
struct ShadowsocksOut {
    /// Server host as written.
    address: String,
    /// Server port.
    port: u16,
    /// Cipher name as written.
    method: String,
    /// Password as written.
    password: String,
    /// Carrier around the sealed chunks, raw `TCP` when unnamed.
    carrier: Carrier,
    /// `Host` header as written, falling back to the server address.
    host: String,
}

/// Accept forever, one thread per connection.
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
                // No stack here: refuse, never downgrade to raw `TCP`.
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
                // No stack here: refuse, never downgrade to raw `TCP`.
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

/// Serve one `shadowsocks` connection: raw `TCP` by default, framed when named.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
        refused_carriers!() => {}
    }
}

/// Serve one `VLESS` connection: raw `TCP` by default, framed when named.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
        refused_carriers!() => {}
    }
}

/// Serve one `VLESS`/`TCP` connection: check the user, dial, answer `[0, 0]`, relay.
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

/// A mux target as a diallable address, resolving names the way the `SOCKS`
/// address reader does.
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
            format!("{host}:{port}").to_socket_addrs().ok()?.next()
        }
    }
}

/// Write one mux frame through the shared writer: encode into the caller's
/// staging, then one `write_all` while the lock is held.
fn write_mux_frame(
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    frame: ferrox_core::mux::Outgoing<'_>,
    data: Option<&[u8]>,
) -> bool {
    let len = data.map_or(0, <[u8]>::len);
    // No `clear`: `resize` only fills what grows, so steady-state frames
    // reuse the buffer with no allocation and no zeroing, and the encode
    // below overwrites exactly the bytes it then reports.
    staging.resize(frame.frame_len(len), 0);
    let written = frame.encode_into(data, staging);
    staging.truncate(written);
    match shared.lock() {
        Ok(mut stream) => stream.write_all(staging).is_ok(),
        Err(_) => false,
    }
}

/// Answer one session with a bare `End`: refused, full, or over.
fn send_mux_end(shared: &Arc<Mutex<TcpStream>>, staging: &mut Vec<u8>, id: u16) {
    let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
    let _ = write_mux_frame(shared, staging, end, None);
}

/// Write one `Keep` data frame for a session through the shared writer.
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

/// Sessions a mux connection carries: sub-stream id to its upstream write half.
type MuxTable = Arc<Mutex<HashMap<u16, Arc<Mutex<TcpStream>>>>>;

/// Drop one session and tell the peer: remove first so no new frame can land
/// in it, then the `End`, which is the order that cannot strand either side.
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

/// Serve one `VLESS` mux connection over raw `TCP`: many streams in one.
///
/// The header names no destination; every `New` frame does. `TCP` sub-streams
/// relay like the raw path, one thread per direction; a `New` that is not one
/// gets an `End` back rather than silence. Sessions cap at
/// [`ferrox_core::mux::DEFAULT_CAP`], the default every implementation uses.
fn serve_vless_mux(stream: TcpStream) {
    let Ok(mut read) = stream.try_clone() else {
        return;
    };
    let shared = Arc::new(Mutex::new(stream));
    let table: MuxTable = Arc::new(Mutex::new(HashMap::new()));
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
                    teardown_mux(&table, &handles);
                    return;
                }
                Ok((frame, used)) => {
                    at += used;
                    progressed = true;
                    handle_mux_frame(frame, &table, &shared, &mut staging, &mut handles);
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
    teardown_mux(&table, &handles);
}

/// Shut every sub-stream down and wait out its relay: the connection is over,
/// so nothing it carried may outlive it.
fn teardown_mux(table: &MuxTable, handles: &[std::sync::mpsc::Receiver<()>]) {
    if let Ok(table) = table.lock() {
        for half in table.values() {
            if let Ok(half) = half.lock() {
                let _ = half.shutdown(Shutdown::Both);
            }
        }
    }
    for done in handles {
        join(done);
    }
}

/// Route one mux frame: open, feed, close, or refuse.
fn handle_mux_frame(
    frame: ferrox_core::mux::Incoming<'_>,
    table: &MuxTable,
    shared: &Arc<Mutex<TcpStream>>,
    staging: &mut Vec<u8>,
    handles: &mut Vec<std::sync::mpsc::Receiver<()>>,
) {
    use ferrox_core::mux::{Network, Status};
    match frame.status {
        Status::New => {
            if frame.target.is_some_and(|t| t.network == Network::Udp) {
                return send_mux_end(shared, staging, frame.id);
            }
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
        Status::Keep => {
            if frame.target.is_some() {
                return;
            }
            let Some(data) = frame.data else {
                return;
            };
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

/// Start one `vless` inbound whose `streamSettings.security` is `tls`.
///
/// Split out of [`serve_file`] because it is the only branch that needs a
/// certificate, and inlining it there made the whole dispatch unreadable.
///
/// Returns whether the inbound was started: an identity this binary cannot
/// read is reported and skipped rather than fatal, because one unusable
/// inbound in a config should not stop the others serving. Any byte-stream
/// carrier rides inside the session — see [`CarrierStream`] — so there is no
/// carrier gate here, only the identity.
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
    let role = Role::VlessTls {
        id: *id,
        freedom,
        carrier: carrier.clone(),
        server,
    };
    thread::spawn(move || accept_loop(&owned, &role));
    true
}

/// Start one `vless` inbound whose `streamSettings.security` is `reality`.
///
/// `dest` is refused rather than dialled: an unauthenticated peer must not be
/// able to make this binary open a connection, and there is no cover origin here
/// to dial anyway. Any byte-stream carrier rides inside the session — see
/// [`CarrierStream`] — so there is no carrier gate here, only the config.
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
    let role = Role::VlessReality {
        id: *id,
        freedom,
        carrier: carrier.clone(),
        server: Arc::new(server),
    };
    thread::spawn(move || accept_loop(&owned, &role));
    true
}

/// Serve one `VLESS`/`TLS` connection: handshake, then exactly the raw path inside.
///
/// The socket is cloned before the handshake and the read timeout armed before
/// either, because a `Vision` peer may switch a direction to raw and the socket
/// is then the only thing left to read. The timeout is armed on the socket
/// itself, so every carrier's clones inherit it: a peer that stalls mid-hello
/// would otherwise hold a thread for ever, on any carrier. Past the handshake
/// there is no raw socket on a carried path, so `Vision` keeps relaying inside
/// the session instead of switching out of it.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
        refused_carriers!() => {}
    }
}

/// Drive a `TLS` handshake over one carried stream and serve what is inside it.
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

/// Serve one `VLESS`/`REALITY` connection: authenticate, then the raw path.
///
/// The socket is cloned before the handshake for the same reason as `TLS` above,
/// and the read timeout armed before it: an unauthenticated peer that stalls
/// mid-hello would otherwise hold a thread for ever.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
        refused_carriers!() => {}
    }
}

/// Drive a `REALITY` handshake to the end and serve what is inside it.
///
/// One place, because the handshake is the part a carrier can be forgotten at:
/// a session that is served before its handshake completes hands the peer
/// records it never finished reading. `raw` is the socket under the session,
/// when there is one: a carried path has none, so `Vision` stays inside the
/// session there instead of switching out of it.
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

/// One `gRPC` tunnel presented as the single stream a handshake needs.
struct Grpc {
    /// Payload bytes out of the tunnel's messages.
    reader: crate::grpc::GrpcReader,
    /// Message writer, shared with the tunnel's window bookkeeping.
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

/// One byte-stream carrier as the single stream a handshake needs.
///
/// `TLS` and `REALITY` both take any `Read + Write` transport, so every
/// carrier whose reader is a byte stream rides here unchanged: `WS` messages,
/// `XHTTP` chunks and the raw bytes behind the camouflage and upgrade all
/// arrive in order with no boundaries the handshake can see. [`Grpc`] is the
/// same idea for the message-framed tunnel; this is its byte-stream sibling.
struct CarrierStream<R, W> {
    /// Carrier bytes come out of here.
    reader: R,
    /// Handshake bytes go in here.
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

/// Serve one `VLESS` connection inside an outer session: check the user, dial,
/// answer `[0, 0]`, then relay the rest of the session.
///
/// `Vision` framing starts after the response header, because the header is the
/// one thing a peer reads before it knows whether the session is framed at all.
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

/// `realitySettings` of a `REALITY` inbound, `None` for any other shape.
///
/// Both lists are required rather than defaulted: an inbound that answers no
/// `SNI` or no `shortId` would authenticate nobody, and serving it anyway is
/// the difference between a refusal and a listener.
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

/// The current Unix time in seconds, read here because the core reads no clock.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// A `shortId` hex string zero-padded to eight bytes, as every peer pads it.
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

/// Unpadded base64url of exactly 32 bytes, the `X25519` key encoding.
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

/// A non-negative whole number of milliseconds, `None` for anything else.
fn as_millis(node: &Json) -> Option<u64> {
    match node {
        Json::Num(n) if *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
        _ => None,
    }
}

/// How long one relay direction blocks in a read before releasing the half's lock.
pub(crate) const RELAY_POLL: Duration = Duration::from_millis(20);

/// One half of a relayed session, with the handoff a plain `Mutex` does not give.
///
/// # Why this is not a `Mutex`
///
/// The two directions share both halves, so each half is read by one thread and
/// written by the other. The reader holds the lock for the length of one read, and
/// one read is a whole [`RELAY_POLL`] window whenever that direction is idle — which
/// is the normal state of a request/response flow between the moment a request goes
/// out and the reply comes back. So the reader owns its half essentially
/// continuously, and a writer that waits by parking in [`Mutex::lock`] does not get
/// one turn in a very long time: dropping a contended lock only hands it to a
/// queued waiter once the dropper is off the CPU, and the dropper is not off the
/// CPU — it goes straight back into its read and takes the free lock itself.
///
/// That is the hang the `t>u`/`u>t` relay milestones localized, and it is not a
/// rare race. Waiting by spinning does not fix it either, because the reader's
/// unlocked window is a few instructions wide and a spin that samples every 64 us
/// misses it almost every time: the loopback test still hung with a spin in place,
/// one direction holding a decoded `VLESS` request it could never hand over and the
/// other reporting zero bytes until the test's deadline.
///
/// So the reader hands the lock over instead: a writer that wants in raises
/// [`Half::wanted`], and the reader yields while it is raised. That costs one
/// `sched_yield` per handoff rather than a spin that has to sample a nanosecond-wide
/// window, and it is why the two directions still run on two threads: a blocked
/// `write` to a slow peer must not stop the other direction from draining it.
#[derive(Debug)]
struct Half<T> {
    inner: Mutex<T>,
    /// Raised by a writer that is waiting for this half, lowered once it has it.
    wanted: AtomicBool,
}

/// How many times the reader offers the lock to a waiting writer before it takes it
/// back.
///
/// Bounded so a writer that is never scheduled cannot hold the reader here: the
/// reader has its own poll to get back to.
const RELAY_HANDOFF_SPINS: u32 = 64;

impl<T> Half<T> {
    fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            wanted: AtomicBool::new(false),
        }
    }

    /// Give the lock to a writer that is waiting for it, if one is.
    fn hand_off(&self) {
        let mut spins = 0;
        while self.wanted.load(Ordering::Relaxed) && spins < RELAY_HANDOFF_SPINS {
            thread::yield_now();
            spins += 1;
        }
    }
}

impl<T: Read> Half<T> {
    /// One read, under the lock, then a handoff to a waiting writer.
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
    /// One write, taking the lock without parking on it first.
    fn write_once(&self, buf: &[u8]) -> std::io::Result<()> {
        self.wanted.store(true, Ordering::Relaxed);
        let taken = self.writer_lock();
        self.wanted.store(false, Ordering::Relaxed);
        let Ok(mut guard) = taken else {
            return Err(std::io::Error::other("relay half poisoned"));
        };
        guard.write_all(buf)
    }

    /// The lock, once a reader has handed it over.
    ///
    /// The `wanted` flag stays raised for the whole wait, so the reader that is
    /// holding the lock knows to yield rather than take it straight back. The budget
    /// is a backstop against a writer that is descheduled for the entire handoff
    /// window: by then the reader has raised and lowered this flag many times and the
    /// lock has been free at each of those moments, so parking here is reached with
    /// the lock already available.
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

/// How many times a writer re-tries a half's lock before it parks on it.
///
/// Only reachable if a reader never ran [`Half::hand_off`], which it runs on every
/// read; see the note there.
const RELAY_LOCK_TRIES: u32 = 1 << 20;

/// Copy both directions between two framed streams; each half ends both when done.
///
/// `relay` clones raw sockets, which a TLS session cannot do: the session owns its
/// transport, so both directions share both halves under one [`Half`] each.
fn relay_stream<A: Read + Write + Send + 'static, B: Read + Write + Send + 'static>(a: A, b: B) {
    let a = Arc::new(Half::new(a));
    let b = Arc::new(Half::new(b));
    let (up_a, up_b) = (Arc::clone(&a), Arc::clone(&b));
    let done = thread::spawn(move || copy_stream(&up_a, &up_b));
    copy_stream(&b, &a);
    let _ = done.join();
}

/// One direction of `relay_stream`, through a [`RELAY_BUFFER`] buffer.
///
/// A read timeout is a retry, not an end: both directions idle-block on reads and
/// only a real EOF or a refusal ends one.
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

/// Whether a relay read only ran out its [`RELAY_POLL`] wait, locally or as a `Timeout`.
pub(crate) fn is_timeout(error: &std::io::Error) -> bool {
    use std::io::ErrorKind::{TimedOut, WouldBlock};
    matches!(error.kind(), TimedOut | WouldBlock)
        || error
            .get_ref()
            .and_then(|source| source.downcast_ref::<ferrox_core::tls::TlsError>())
            .is_some_and(|mapped| matches!(mapped, ferrox_core::tls::TlsError::Timeout))
}

/// `certificateFile`/`keyFile` identity of a TLS inbound, read once per inbound.
///
/// Files are read here, in the binary, never in the core: the core takes DER bytes.
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

/// Paths from `tlsSettings.certificates[0]`, `None` for any other shape.
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

/// One `VLESS` request header for a command: version, id, empty addons, command, target.
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

/// Dial one `vless` upstream for a `SOCKS` target, over whatever carrier is named.
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
        // No stack here: refuse, never downgrade to raw `TCP`. `QUIC` is
        // dialled before any `TCP` uplink exists (see `serve_socks`), so its
        // presence in this list is the backstop, not the path.
        refused_carriers!() => {}
    }
}

/// One open `VLESS` `UDP` uplink: its writer half and the target it serves.
struct UdpUplink {
    /// The `TCP` half this thread writes framed datagrams through.
    write: TcpStream,
    /// The destination the header named; a new one re-dials.
    target: SocketAddr,
    /// The reader thread's completion signal.
    done: std::sync::mpsc::Receiver<()>,
}

/// Open one `VLESS` `UDP` uplink over raw `TCP`: header with `cmd 2`, `[0, 0]`
/// read back, then framed datagrams both ways.
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

/// Read framed replies off one uplink into `UDP` datagrams back to the client.
///
/// The read half blocks with no window armed, so a slow reply never
/// misaligns the stream; the socket's shutdown on re-dial or exit is what ends
/// the read. Replies go to the most recently seen client source.
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

/// One open `VMess` `UDP` uplink: its writer half, its sealing flow and target.
struct VmessUdpUplink {
    /// The `TCP` half this thread writes framed datagrams through.
    write: TcpStream,
    /// The sealing flow for the client-to-server direction.
    send: crate::vmess::Flow,
    /// Padding randomness, batched per uplink rather than per datagram.
    pad: crate::vmess::PadSource,
    /// The destination the header named; a new one re-dials.
    target: SocketAddr,
    /// The reader thread's completion signal.
    done: std::sync::mpsc::Receiver<()>,
}

/// Open one `VMess` `UDP` uplink over raw `TCP`: sealed header with command 2,
/// response read back, then one sealed frame per datagram.
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

/// Read sealed replies off one uplink into `UDP` datagrams back to the client.
///
/// Same contract as the `VLESS` reader: the read half blocks with no window
/// armed, and replies go to the most recently seen client source.
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

/// One open Trojan `UDP` uplink: its writer half and its reader's signal.
struct TrojanUdpUplink {
    /// The `TCP` half this thread writes framed datagrams through.
    write: TcpStream,
    /// The reader thread's completion signal.
    done: std::sync::mpsc::Receiver<()>,
}

/// Open one Trojan `UDP` uplink over raw `TCP`: header with `cmd 3`, then
/// framed datagrams both ways. Trojan answers nothing, so the pump starts at
/// once; the header names the first destination and later ones ride along.
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

/// Read framed replies off one uplink into `UDP` datagrams back to the client.
///
/// Same contract as the `VLESS` reader: the read half blocks with no window
/// armed, and the socket's shutdown on drop or exit is what ends the read.
/// Each reply names its own source, which becomes the datagram's address.
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

/// Pump a mux downlink to its stream: demultiplex by id, `Keep` writes through,
/// `End` half-closes, anything else ends the pump.
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

/// Pump a stream into its mux session: each read becomes one `Keep`, close
/// becomes one `End`.
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
                scratch.resize(keep.frame_len(n), 0);
                let written = keep.encode_into(Some(&chunk[..n]), &mut scratch);
                if uplink.write_all(&scratch[..written]).is_err() {
                    break;
                }
            }
        }
    }
    let end = ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
    scratch.resize(end.frame_len(0), 0);
    let written = end.encode_into(None, &mut scratch);
    let _ = uplink.write_all(&scratch[..written]);
    let _ = uplink.shutdown(Shutdown::Both);
}

/// Dial one `VLESS` stream through a mux uplink: a single session on a fresh
/// connection.
///
/// Concurrency one, on purpose: the wire is identical however many sessions a
/// connection carries, so one session proves the framing against every peer
/// and pooling them is a separate rung with its own gate. Raw `TCP` only.
fn dial_vless_mux(
    client: &TcpStream,
    mut uplink: TcpStream,
    vless: &VlessOut,
    target: &SocketAddr,
) {
    if !matches!(vless.carrier, Carrier::Raw) {
        return;
    }
    if uplink
        .write_all(&vless_header(&vless.id, 3, target))
        .is_err()
    {
        return;
    }
    if read_vless_response(&mut uplink).is_none() {
        return;
    }
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

/// Dial one `vmess` upstream past the `HTTPUpgrade` `101`.
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

/// Dial one `vmess` upstream past the `gRPC` handshake.
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

/// Dial one `vmess` upstream past the `ws` upgrade.
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

/// Dial one `vmess` upstream for a `SOCKS` target, over whatever carrier is named.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
        refused_carriers!() => {}
        Carrier::HttpUpgrade { path } => {
            dial_vmess_httpupgrade(client, uplink, vmess, target, path);
        }
        Carrier::Grpc { path } => {
            dial_vmess_grpc(client, uplink, vmess, target, path);
        }
    }
}

/// Dial one `trojan` upstream for a `SOCKS` target, over whatever carrier is named.
///
/// [`dial_vless`]'s shape without the response read: the password-led header
/// goes out through the carrier and the relay runs carried immediately, since
/// a `trojan` server answers nothing before relaying.
/// One Trojan request header for a command: key, `CRLF`, command, `SOCKS`
/// address, `CRLF`.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
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

/// Dial one `shadowsocks` upstream for a `SOCKS` target, over whatever carrier is named.
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
        // No stack here: refuse, never downgrade to raw `TCP`.
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

/// Dial one `shadowsocks` upstream inside `WebSocket` messages.
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

/// Dial one `shadowsocks` upstream past the `HTTPUpgrade` `101`.
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

/// Dial one `shadowsocks` upstream inside a `gRPC` tunnel.
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

/// Dial one `shadowsocks` upstream inside `XHTTP` chunks.
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

/// Dial one `shadowsocks` upstream past the camouflage `GET`.
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

/// Serve one `trojan` connection: check the password, dial, relay with no reply.
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

/// Serve one Trojan `UDP` flow over raw `TCP`: datagrams in, datagrams out.
///
/// Each datagram names its own destination, so unlike the `VLESS` pump there
/// is no fixed target to connect to: unconnected `UDP` sockets, one per
/// family where the platform has both, send each datagram where it says and
/// frame every reply with where it came from.
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
    loop {
        if done.load(Ordering::Relaxed) {
            break;
        }
        let mut live = pump_trojan_replies(&udp4, &mut stream, &mut buf, &done);
        if let Some(sock) = &udp6 {
            live &= pump_trojan_replies(sock, &mut stream, &mut buf, &done);
        }
        if !live {
            break;
        }
    }
    done.store(true, Ordering::Relaxed);
    let _ = stream.shutdown(Shutdown::Both);
    join(&replied);
}

/// Pump one reply datagram off a `UDP` socket into a Trojan frame.
///
/// `true` keeps polling; `false` ends the flow. Timeouts only end the wait,
/// never the flow: the sockets poll on [`RELAY_POLL`] windows so both families
/// stay responsive without either starving the other.
fn pump_trojan_replies(
    udp: &UdpSocket,
    stream: &mut TcpStream,
    buf: &mut [u8],
    done: &AtomicBool,
) -> bool {
    match udp.recv_from(buf) {
        Ok((n, src)) => {
            if n == 0 {
                return true;
            }
            write_trojan_datagram(stream, &src, &buf[..n])
        }
        Err(error) if is_timeout(&error) => !done.load(Ordering::Relaxed),
        Err(_) => false,
    }
}

/// Serve one `trojan` connection inside `WebSocket` messages.
///
/// Same bytes as [`serve_trojan`], framed: the password-led request is read
/// out of messages and the relay runs carried. Trojan answers nothing before
/// relaying, so unlike `VLESS` there is no response header to send.
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

/// Serve one `trojan` connection past the `HTTPUpgrade` `101`.
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

/// Serve one `trojan` connection inside `gRPC` messages.
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

/// Serve one `trojan` connection inside `XHTTP` chunks.
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

/// Serve one `trojan` connection past the camouflage `GET`.
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

/// Serve one `SOCKS5` connection by dialing through the upstream server.
fn serve_socks(mut client: TcpStream, out: &Outbound) {
    let Some((cmd, target)) = socks_handshake(&mut client) else {
        return;
    };
    if cmd == 3 {
        return serve_socks_udp(client, out);
    }
    let (address, port) = match out {
        Outbound::Vless(vless) => (vless.address.clone(), vless.port),
        Outbound::Vmess(vmess) => (vmess.address.clone(), vmess.port),
        Outbound::Trojan(trojan) => (trojan.address.clone(), trojan.port),
        Outbound::Shadowsocks(shadowsocks) => (shadowsocks.address.clone(), shadowsocks.port),
        // `freedom` names no server, so there is nothing to connect *to*: the
        // address the client asked for is the address to dial.
        Outbound::Freedom => {
            let Some(upstream) = dial_or_report(&target) else {
                return;
            };
            relay(&client, &upstream);
            return;
        }
    };
    // `QUIC` leaves `TCP` entirely: no uplink socket is dialled for it, and
    // the refused arm in `dial_vless` below stays as the backstop. A mux
    // request is refused rather than silently served as one bare session;
    // sharing a `QUIC` connection across streams is the pool's job, reached
    // through this same call without the flag.
    if let Outbound::Vless(vless) = out {
        if matches!(vless.carrier, Carrier::Quic) && !vless.mux {
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
        // Unreachable: `freedom` returns above, before any upstream is dialled, so
        // there is no `uplink` for it. Named rather than wildcarded so that adding
        // an outbound later fails to compile here instead of silently relaying
        // unframed bytes.
        Outbound::Freedom => {}
    }
}

/// Bind the `UDP` relay for one associate and answer it: the relay socket the
/// datagram loop serves, or silence when there is no relay to serve on.
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

/// Serve one `SOCKS5` `UDP ASSOCIATE`: `VLESS` or Trojan `UDP` upstream, raw
/// `TCP` only; anything else is refused rather than half-served.
fn serve_socks_udp(mut client: TcpStream, out: &Outbound) {
    let Some(relay) = socks_udp_relay(&mut client) else {
        return;
    };
    // Held open: dropping it ends the associate on the client's end.
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

/// Serve one associate through a `shadowsocks` `UDP` uplink.
///
/// The server is fixed by the outbound and every datagram names its own
/// destination inside its sealed payload, so like Trojan there is no
/// re-dial: one uplink socket, sealed datagrams out, opened datagrams back.
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

/// Read sealed replies off one uplink into `UDP` datagrams back to the client.
///
/// Replies name no source on the wire, so they wrap the most recently seen
/// client source; a reply with nowhere to go is dropped rather than guessed.
/// `UDP` sockets have no shutdown halves, so the read polls on [`RELAY_POLL`]
/// windows and the flag is what ends it.
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

/// Serve one associate through a `VMess` `UDP` uplink.
///
/// One uplink per associate like `VLESS`: the sealed header fixes the target,
/// so a new destination re-dials. Frames carry no source, so replies wrap the
/// uplink's own target, exactly as the length-prefixed reader does.
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

/// Serve one associate through a `VLESS` `UDP` uplink.
///
/// One uplink per associate, fixed to the first datagram's destination; a new
/// destination re-dials, so multi-homed clients work rather than leaking
/// across targets. The associate lives until no datagram arrives for
/// [`UDP_IDLE`].
fn serve_socks_udp_vless(relay: &UdpSocket, vless: &VlessOut) {
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

/// Serve one associate through a Trojan `UDP` uplink.
///
/// One uplink per associate, opened on the first datagram: every datagram
/// after the header names its own destination, so later destinations ride the
/// same uplink instead of re-dialling the way `VLESS` must.
fn serve_socks_udp_trojan(relay: &UdpSocket, trojan: &TrojanOut) {
    let source: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut uplink: Option<TrojanUdpUplink> = None;
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
        if uplink.is_none() {
            uplink = dial_trojan_udp_uplink(trojan, &dest, relay, Arc::clone(&source));
        }
        if let Some(up) = &mut uplink {
            if !write_trojan_datagram(&mut up.write, &dest, payload) {
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

/// Copy both directions; each half forwards its half-close when its copy ends.
///
/// A direction ends when its read side sees EOF (or fails). The only thing it
/// forwards is the write half-close to its destination: `shutdown(Write)`.
/// `shutdown(Both)` here would close the socket's read side too, and the
/// shutdown is per-socket rather than per-handle, so it would kill the reverse
/// direction's in-flight reply — a large payload's echo never arrives. The
/// reverse direction keeps its read side until its own peer half-closes, and
/// the sockets are dropped (fully closed) on return after both halves join.
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
    // On Linux the two directions go to a `poll` worker set as one flow and this
    // thread waits for them. See [`poll_relay`] for why that is the same work and much
    // less of it.
    #[cfg(target_os = "linux")]
    if poll_relay::available() {
        // Asked before the sockets are moved rather than after, because a function that
        // takes them by value has taken them whether or not it used them.
        poll_relay::drive(client_read, target_write, target_read, client_write);
        return;
    }
    let mut client_read = client_read;
    let mut target_write = target_write;
    let mut target_read = target_read;
    let mut client_write = client_write;
    // One direction here on this thread, the other handed to a worker. Which is which
    // is not a decision this function makes: both directions are the same work, and
    // naming them would only make one of them look like the special one.
    let forward = move || {
        copy_all(&mut client_read, &mut target_write);
        let _ = target_write.shutdown(Shutdown::Write);
    };
    let done = RelayPool::global().run(forward);
    copy_all(&mut target_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    join(&done);
}

/// How long a `UDP` socket waits for one reply datagram before re-checking
/// whether its flow is over; unlike `TCP` a datagram socket has no `EOF`, so
/// the wait is the only end a quiet reply direction has.
pub(crate) const UDP_IDLE: Duration = Duration::from_secs(120);

/// One datagram buffer: a `u16` length prefix addresses no more than this.
pub(crate) const UDP_BUF: usize = 65535;

/// Read one `u16`-length-prefixed datagram into `buf`, returning its length.
///
/// The Xray-core, xray-rust and sing-box framings agree: two big-endian length
/// bytes and then the payload, with empty payloads never sent. An empty or an
/// overlong length ends the flow rather than desynchronizing it.
///
/// Back this only by blocking stream reads: a read window running out
/// mid-payload would strand the rest of it and misalign every frame after it,
/// while a datagram-atomic `UDP` read consumes all or nothing.
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

/// Write one datagram with its `u16` length prefix, in a single syscall where
/// the platform allows it.
///
/// Empty payloads are skipped without writing, which is what every peer's
/// writer does rather than what its reader accepts: no reader ever sees one.
fn write_udp_datagram(stream: &mut TcpStream, payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return true;
    }
    let len = (payload.len() as u16).to_be_bytes();
    write_all_two(stream, &len, payload)
}

/// Write one Trojan `UDP` datagram: `SOCKS` address, `u16` length, `CRLF`,
/// payload.
///
/// Xray-core, `ZeroNet` and sing-box agree on the order; all three writers skip
/// empty payloads and none of the readers accepts one. The header rides in
/// one small buffer beside the payload, so the payload itself is never copied
/// the way a chained-buffer writer copies it.
fn write_trojan_datagram(stream: &mut TcpStream, dest: &SocketAddr, payload: &[u8]) -> bool {
    if payload.is_empty() || payload.len() > u16::MAX as usize {
        return true;
    }
    let mut head = Vec::with_capacity(32);
    push_socks_addr(&mut head, dest);
    head.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    head.extend_from_slice(b"\r\n");
    write_all_two(stream, &head, payload)
}

/// Read one Trojan `UDP` datagram into `buf`, returning destination and length.
///
/// Same contract as [`read_udp_datagram`]: blocking reads only, and anything
/// but a well-formed frame ends the flow instead of desynchronizing it.
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

/// Serve one `VLESS` `UDP` flow over raw `TCP`: datagrams in, datagrams out.
///
/// The target is fixed by the header, so unlike the dial side there is nothing
/// to re-dial: one `UDP` socket connected to it, one thread reading framed
/// datagrams off `TCP` into it, this thread reading replies back into frames.
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

/// Pump sealed `VMess` datagram frames against a connected `UDP` socket.
///
/// The serve side, whose target is fixed by the header: the sealed side is one
/// `TCP` stream of `VMess` frames, the plain side is datagrams on a connected
/// socket. One thread reads frames into datagrams; this thread reads datagrams
/// into frames, one sealed frame per datagram each way, which is the
/// packet-mode framing every peer writes.
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
            let mut datagram = vec![0u8; chunk.len()];
            datagram.copy_from_slice(chunk);
            if udp_send.send(&datagram).is_err() {
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

/// One direction of one relay, as something a thread can be handed.
type RelayTask = Box<dyn FnOnce() + Send + 'static>;

/// Why there is a pool at all.
///
/// `thread::spawn` per direction is one thread creation and one 2 MiB stack mapping
/// per direction, per connection, and a thread that spends its life blocked inside a
/// `splice(2)` cannot be reused for anything. That is the shape Go does not have:
/// `xray-core` and `sing-box` each run a direction as a goroutine that parks on the
/// runtime netpoller (`route/conn.go:173-174` in sing-box, with no `LockOSThread`
/// anywhere on its path), so `N` flows cost `O(GOMAXPROCS)` threads rather than
/// `O(2N)`.
///
/// At one connection the two designs are the same and at sixteen they are not, which
/// is why `parity.yml` grew a `connections` input: the claim has to be measured at a
/// concurrency that can tell them apart or it is not a claim.
///
/// This is **not** that design, and does not pretend to be. Go's win comes from a
/// poller multiplexing many sockets onto a fixed thread set, which means making every
/// socket non-blocking and driving them from an event loop — a rewrite of the relay
/// rather than a change to it. What a pool buys without that is the part of the cost
/// that is not the scheduler: a thread that has already run this loop has its stack
/// faulted in and its allocator warm, so the next connection through it starts hot.
///
/// # Why it cannot lose a connection
///
/// A worker is handed a task only when it is *between* jobs — it puts its own sender
/// back on the idle list after finishing one and nowhere else — so a claimed worker
/// is a worker with nothing to do. When no worker can be claimed, a fresh thread is
/// made, exactly as this code did before the pool existed. There is no queue and no
/// bound a burst of connections can reach: a connection that cannot be pooled is
/// still served.
struct RelayPool {
    /// Senders for workers that are between jobs. The channel is what hands a task
    /// over, and an entry is present only while its worker is idle.
    idle: Mutex<Vec<std::sync::mpsc::Sender<RelayTask>>>,
}

/// One per process, built on first use rather than at start-up: an idle pool is
/// threads and a relay that never runs should not pay for any.
static RELAY_POOL: OnceLock<RelayPool> = OnceLock::new();

impl RelayPool {
    fn global() -> &'static Self {
        RELAY_POOL.get_or_init(|| RelayPool {
            idle: Mutex::new(Vec::new()),
        })
    }

    /// Run one direction on its own thread, from the pool if a worker is free.
    ///
    /// The returned receiver completes when the direction ends. That is what
    /// `JoinHandle::join` was for: a relay that returned while a direction still held
    /// two sockets and a copy buffer would have the next flow's resident-memory
    /// reading include them, so the caller waits -- but it waits on a one-shot signal
    /// rather than on a thread's whole lifetime, because a pooled worker outlives
    /// every task it runs.
    fn run(&self, direction: impl FnOnce() + Send + 'static) -> std::sync::mpsc::Receiver<()> {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        // The catch is *inside* the closure rather than around it, and that is the
        // whole point: a closure that caught around `direction()` would unwind out of
        // itself and drop `done_tx` on the way, so the caller's `recv` would see a
        // `RecvError` -- which it reads as "the direction is gone" and returns early.
        // Catching here means the send always happens, because it is the next
        // statement and not something an unwind can skip.
        let task: RelayTask = Box::new(move || {
            let ended = std::panic::catch_unwind(std::panic::AssertUnwindSafe(direction));
            let _ = done_tx.send(());
            if ended.is_err() {
                // Reported rather than swallowed: a panic in a relay direction is a
                // bug, and a pooled worker is the only place it can be seen at all.
                eprintln!("ferrox-app: a relay direction panicked");
            }
        });
        // Claiming is `pop` then `send`, and the `send` is the claim: a sender that
        // has been handed a task is a worker that has already had one taken off its
        // idle list, so two callers cannot claim the same worker.
        // The task goes into an `Option` because the `send` below consumes it, and a
        // failed `send` hands it straight back -- so either a worker took it or this
        // function still owns it, with no window where it is dropped.
        let mut task = Some(task);
        let claimed = self
            .idle
            .lock()
            .ok()
            .and_then(|mut idle| idle.pop())
            .is_some_and(|sender| sender.send(task.take().expect("just set")).is_ok());
        if !claimed {
            // Either there was no idle worker, or the one we took has since exited --
            // the `Err` returned its task, so it is back here. Both mean a thread is
            // needed, and both are what happened before this pool existed.
            Self::spawn(task.take().expect("unclaimed means unclaimed"));
        }
        done_rx
    }

    /// Make one worker and give it `task`.
    ///
    /// A free function rather than a method because it touches nothing on the pool: a
    /// worker reaches the pool again only after its task, and a method here would
    /// suggest it borrowed one.
    ///
    /// The worker is put on the idle list by itself, after the task it was born with,
    /// and not here: a sender added at this point could be handed a second task while
    /// the worker is still running the first, which would put two directions on one
    /// thread and serialise them.
    fn spawn(task: RelayTask) {
        let (sender, receiver) = std::sync::mpsc::channel::<RelayTask>();
        thread::spawn(move || {
            // The task this worker was born with runs first, and only after it ends is
            // the worker offered to anyone else. The catch here is the last resort:
            // `run` already catches inside the task, so this only sees a panic in the
            // pool's own code, and its job is to keep one worker's bug from ending a
            // connection that has not started yet.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
            loop {
                let Ok(next) = receiver.recv() else {
                    // Every sender is gone, which only happens when this worker's own
                    // clone went with the idle list on the way out.
                    return;
                };
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(next));
                let pool = RelayPool::global();
                let Ok(mut idle) = pool.idle.lock() else {
                    // The lock is held across `push` only and nothing here can panic
                    // while it is held, so this is unreachable in practice. Exiting
                    // costs one thread, never a connection: the direction has already
                    // finished.
                    return;
                };
                idle.push(sender.clone());
            }
        });
    }
}

/// Wait for a direction handed to [`RelayPool::run`] to end.
///
/// Its own function so the one line that matters is named: a relay that returns while
/// a direction is still running leaves that direction's sockets and copy buffer
/// resident, and the next flow's memory figure would then be measuring the previous
/// one.
fn join(direction: &std::sync::mpsc::Receiver<()>) {
    let _ = direction.recv();
}

/// The copy buffer the portable relay direction uses.
///
/// `std::io::copy` allocates 8 KiB when the socket carries no buffer-size hint, and
/// on this path that one constant is the whole difference between losing and winning
/// a throughput comparison. Gate 5 measured it against the pinned Xray-core, on one
/// host, one workload, one harness, five paired repeats each — the two rows are two
/// `target/bench-report.md` runs and nothing else:
///
/// | copy buffer | throughput vs Xray-core | cpu per GiB vs Xray-core | peak RSS |
/// |---|---|---|---|
/// | `io::copy`'s 8 KiB | 0.60x, interval [0.54, 0.70] | 0.64x, interval [0.59, 0.72] | 2.0 MiB |
/// | this, 256 KiB | 1.36x, interval [1.31, 1.41] | 1.78x, interval [1.73, 1.84] | 2.2 MiB |
///
/// The intervals move between runs — a later pair of five reads 1.27x and 1.63x on
/// the same build — so the claim worth keeping is the sign and the order of
/// magnitude, not the third digit. 256 KiB sits inside every platform's
/// `SO_SNDBUF` default while still being one allocation per direction, so the loop
/// runs about thirty times fewer syscalls per megabyte.
///
/// This is the whole of the copy on every platform except Linux, where [`copy_all`]
/// splices instead and never allocates a buffer. The row above was measured on
/// macOS, where Go has no socket-to-socket zero-copy path either; see [`copy_all`]
/// for what the same workload reads on Linux and why.
///
/// The cost is resident memory: two of these per connection, so a process holding
/// many flows holds `512 KiB` per flow that `io::copy` would have held `16 KiB` of.
/// At one flow that is the 0.2 MiB in the RSS column above. At a thousand flows it
/// is 512 MiB against 16 MiB, and this constant would be the wrong one — which is
/// why it is named, measured, and written down here rather than inlined.
pub(crate) const RELAY_BUFFER: usize = 256 * 1024;

/// The size a relay buffer starts at, before it has seen a full read.
///
/// A sixteenth of the bulk size and one `io::copy`'s worth,
/// so an interactive or idle session — which is most of them on a proxy — costs
/// 32 KiB per flow in two directions instead of the 512 KiB the paragraph above
/// names as this constant's real weakness. Promotion is one-way and only on a
/// read that filled the buffer completely, which is the proxy for "this flow is
/// bulk": a short read means the peer had less than a buffer's worth to say, and
/// a flow that never fills one has not been bulk.
pub(crate) const RELAY_SMALL_BUFFER: usize = 16 * 1024;

/// A relay buffer that grows once, when its owner proves to be a bulk flow.
///
/// One struct rather than a flag threaded through the copy loops, because the
/// loops that use it are already generic and a buffer that knows when to grow
/// costs the caller nothing: [`Self::as_mut`] hands over the same slice
/// `Read::read` wanted and [`Self::filled`] returns the same `&[u8]` it copied
/// before. The only new question a caller asks is whether it read everything.
///
/// # The promotion costs one zero-fill, and here is why that is not a cost
///
/// `resize` zeroes the 240 KiB it adds, and the very next `read` overwrites all
/// of it. That is a real `memset`, so it needs an answer rather than a shrug.
/// The answer is that the promotion only fires on a read that filled
/// [`RELAY_SMALL_BUFFER`] — 16 KiB of payload that has *already* been copied out
/// by the time the promotion happens, and 240 KiB more is about to move through
/// the same call. The `memset` is therefore bounded by the payload of the
/// connection it is amortised over, once, and it is the price of not writing
/// `set_len` on memory nothing has initialised: the alternative is an `unsafe`
/// block whose proof obligation is that every byte a later `read` returns is
/// initialised, for a saving that is at most 240 KiB of `memset` on a flow that
/// is about to move 256 KiB. [`ferrox_core::policy`] asks for the safe form
/// whenever the two tie, and this is one of the places they tie.
#[derive(Debug)]
pub(crate) struct RelayBuf {
    bytes: Vec<u8>,
}

impl RelayBuf {
    /// A buffer at [`RELAY_SMALL_BUFFER`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            bytes: vec![0u8; RELAY_SMALL_BUFFER],
        }
    }

    /// The initialised region to read into.
    #[must_use]
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// The `n` bytes just read, promoting to [`RELAY_BUFFER`] if `n` filled the
    /// buffer entirely.
    ///
    /// Promotion happens here rather than in [`Self::as_mut`] so the caller still
    /// sees the bytes it just read at the old buffer's address: growing before
    /// the write would invalidate the slice it is about to copy from.
    #[must_use]
    pub fn filled(&mut self, n: usize) -> &[u8] {
        if n == self.bytes.len() && n < RELAY_BUFFER {
            self.bytes.resize(RELAY_BUFFER, 0);
        }
        &self.bytes[..n]
    }

    /// The current size, for the promotion test and a report
    ///
    /// Used only by tests today, which is why it is `#[cfg(test)]`: a reader
    /// nobody asks is a second way to learn the size, and the buffer length is
    /// right there.
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

/// Copy `from` into `to` until `from` ends.
///
/// `write_all` rather than `write`, so a short write is a retry inside this loop
/// instead of a silently dropped tail — a truncated relay is a protocol error the
/// far end cannot distinguish from a slow one. That is [`copy_all_memcpy`]; on
/// Linux this is `SplicePipe`, which has no buffer and no short write, because
/// `splice(2)` does not have one. Named without a link because the type is
/// `cfg(target_os = "linux")` and a link to it is a broken link on every other
/// platform -- which is what `cargo doc` found here, and what the `lint and docs`
/// job cannot see because it runs on Linux.
#[cfg(not(target_os = "linux"))]
fn copy_all(from: &mut TcpStream, to: &mut TcpStream) {
    copy_all_memcpy(from, to);
}

/// Copy `from` into `to` until `from` ends, through a [`RelayBuf`].
///
/// The bytes and the syscall count are `copy_all_memcpy`'s: a flow that reads
/// [`RELAY_BUFFER`] in one call takes the same path it always did, and the only
/// difference is that a flow which never fills a small buffer now holds 32 KiB
/// rather than 512. A flow that *does* fill one promotes and is back to the
/// measured 256 KiB per read.
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

/// Copy `from` into `to` on Linux, without the bytes ever entering user space.
///
/// # Why this exists
///
/// Go's `net.TCPConn` implements `io.ReaderFrom`, so `io.Copy` between two TCP
/// connections goes through `internal/poll.splice` on Linux: the kernel moves the
/// pages between the two sockets through a pipe and the payload is never in this
/// process's address space at all. There is no equivalent on macOS or the BSDs,
/// where `io.Copy` is a `read`/`write` loop like any other, and Rust's
/// `std::io::copy` is a `read`/`write` loop on every platform — it has no
/// socket-to-socket specialisation anywhere.
///
/// That is not a hypothesis about this repository's code, it is the whole of a
/// gate-5 gap that is present on Linux and absent on macOS, on the same
/// architecture and the same relay:
///
/// | runner | ferrox | xray-core | ratio | zeronet vs xray-core |
/// |---|---|---|---|---|
/// | `macos aarch64` | 4181.4 MiB/s | 3379.5 MiB/s | **1.237x** | 0.92x |
/// | `linux aarch64` | 4038.8 MiB/s | 5216.3 MiB/s | **0.774x** | 0.56x |
///
/// Gate 3 on the `linux aarch64` runner is clean at 235 lengths, worst 1.00x, so
/// nothing in `ferrox-core` is slow; and `windows x86_64`, the other platform
/// with no splice, passes. Both Rust engines lose to the Go one on Linux and
/// neither loses on macOS, which is the signature of the copy path rather than of
/// either implementation.
///
/// # Why it is safe to get wrong in one direction only
///
/// A `splice` failure ends this direction, exactly as a failed `write` ends
/// [`copy_all_memcpy`], and `relay` shuts both sockets down when a half ends. There
/// is no path here that reports success while dropping bytes: the bytes are counted
/// out of the pipe before the next pull, and a short push is drained rather than
/// abandoned. The one case that would lose data is abandoning a pipe with bytes
/// still in it, so there is no fallback to the copying path after a `splice` has
/// started — the pipe is made once, before any byte moves, and a failure to make it
/// is the only thing that selects the copying path.
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

/// One `pipe(2)` pair, and the two `splice(2)` directions across it.
///
/// Blocking throughout, like the sockets this is used on: the relay's plain path
/// arms no read timeout, so a blocking `splice` here waits exactly as long as the
/// `read` it replaces would have.
#[cfg(target_os = "linux")]
struct SplicePipe {
    fds: [libc::c_int; 2],
    /// The capacity the kernel actually granted, in bytes.
    ///
    /// Read back with `F_GETPIPE_SZ` rather than assumed from the request, because
    /// the ask can be refused or clamped -- `/proc/sys/fs/pipe-max-size` bounds it
    /// and an unprivileged process cannot exceed it -- and a request above the real
    /// capacity is not an error, it is a silent no-op: `splice` into a pipe moves
    /// at most what fits, so the loop would keep asking for a mebibyte and keep
    /// being given 64 KiB. Reading the answer back is what makes the number below a
    /// measurement rather than a request.
    capacity: libc::size_t,
}

#[cfg(target_os = "linux")]
impl SplicePipe {
    /// A pipe of [`SPLICE_PIPE_BYTES`], or of whatever the kernel will grant.
    ///
    /// `None` only where the kernel would not make a pipe at all, which is the one
    /// case [`copy_all`] falls back to copying for.
    fn new() -> Option<Self> {
        let mut fds = [-1; 2];
        // SAFETY: `fds` is a two-element array, which is exactly what `pipe` writes,
        // and it is live for the duration of the call.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        // One end is enough: `F_SETPIPE_SZ` sets the buffer the pair shares.
        //
        // SAFETY: `fds[0]` is live and came from the `pipe` above, and `fcntl`
        // neither reads through the descriptor nor writes to the pipe.
        let asked = unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, splice_pipe_bytes()) };
        // SAFETY: as above; this one only reads the buffer size back.
        let granted = unsafe { libc::fcntl(fds[0], libc::F_GETPIPE_SZ) };
        // `asked` is what the kernel granted when it granted anything -- `F_SETPIPE_SZ`
        // returns the new size, or -1 -- and `granted` is the query, which is what
        // settles it when the ask was clamped. Both are `c_int`, so a negative one
        // is a refusal rather than a size.
        let capacity = libc::size_t::try_from(if asked > 0 { asked } else { granted }).ok();
        let capacity = match capacity {
            Some(bytes) if bytes > 0 => bytes,
            // Both refused. The default is the one number this platform documents
            // for a pipe nobody asked about, and it is only ever a fallback: a
            // `pipe(2)` that just succeeded is at least that big.
            _ => DEFAULT_SPLICE_PIPE_BYTES,
        };
        // Once per direction per connection, and only when it is not the
        // compiled-in default, so a run that exercised the override says so in its
        // log instead of leaving a reader to infer it from a throughput number.
        if capacity != DEFAULT_SPLICE_PIPE_BYTES {
            eprintln!("ferrox-app: splice pipe {capacity} B");
        }
        Some(Self { fds, capacity })
    }

    /// Move up to one pipe-buffer of bytes from `from` into the pipe.
    ///
    /// `Ok(0)` is end of file, which is the same signal `read` gives and ends this
    /// direction. `EINTR` is retried rather than reported, because a signal is not a
    /// closed socket and this is the only place a relay would mistake one for the
    /// other.
    ///
    fn pull(&self, from: &mut TcpStream) -> std::io::Result<usize> {
        loop {
            // SAFETY: both descriptors are live — one from `pipe`, one owned by
            // `from` — and `splice` reads neither. A null `off` is what asks for a
            // pipe rather than a file, which is the only form of `splice` that has
            // no offset to get wrong.
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

    /// Move exactly `n` bytes from the pipe into `to`, draining it.
    ///
    /// `splice` into a socket writes what it can and returns the count, so a short
    /// write is normal under backpressure and the remainder has to be drained. This
    /// is the loop that makes a short write a retry rather than a dropped tail, the
    /// same job `write_all` does for the copying path.
    fn push(&self, to: &mut TcpStream, n: usize) -> bool {
        let mut left = n;
        while left > 0 {
            // SAFETY: as in `pull`, both descriptors are live, the count is bounded
            // by what `pull` put in the pipe, and a null `off` selects the pipe form.
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

/// The capacity asked for on a relay's splice pipe, in bytes.
///
/// # The measurement, and the error it corrects
///
/// Go sets `F_SETPIPE_SZ` to `maxSpliceSize = 1 << 20` on every pipe it makes,
/// "to optimize that" (`internal/poll/splice_linux.go:236`), so a megabyte costs it
/// two `splice(2)` calls where a 64 KiB pipe costs sixteen. This constant used to be
/// the 64 KiB a bare `pipe(2)` hands out, on the argument recorded in
/// `docs/methodology.md` that *"a `splice` is roughly 40 ns of entry and exit"*, so
/// the sixteen calls were free. 40 ns is the cost of entering and leaving a trivial
/// syscall. A 64 KiB `splice` is not a trivial syscall: it takes sixteen pipe
/// buffers, moves the socket's receive-queue pages into them, and copies them back
/// out into the destination socket's skbs.
///
/// With the CPU row made able to see anything -- it had read `0` for every engine in
/// every run, because GNU `ps` prints `TIME` in whole seconds -- three capacities
/// were compared on one runner in one run, via the `splice_pipe_bytes` input on
/// `parity.yml`. Medians of five repeats of an 8 GiB validated download, ferrox
/// against pinned `xray-core`:
///
/// | pipe | `linux x86_64` throughput | cpu ms/GiB, ferrox / xray | repeats |
/// | --- | ---: | ---: | --- |
/// | 64 KiB (was) | **0.78x**, [0.64, 0.91] | 266 / 211 | spread **1.82x** |
/// | **256 KiB (this)** | 0.99x, [0.91, 1.10] | 231 / 234 | spread 1.20x |
/// | 1 MiB (Go's) | 1.00x, [0.89, 1.11] | 225 / 232 | spread 1.25x |
///
/// 266 to 225 ms/GiB against a reference that moved 211 to 232: the pipe was worth
/// about a fifth of the throughput and a sixth of the CPU on that runner, and the
/// bimodality -- one repeat in five landing at half speed while `sing-box`'s spread
/// 1.15x on a runner whose own ceiling spread 1.02x -- went with it. That
/// bimodality was the tell: a runner does not alternate between two speeds on a
/// schedule, and a relay does, because a 64 KiB unit is small enough for the
/// three-stage pipeline to drain between units.
///
/// # Re-measured after the splice flags changed, because a later commit changed what this is worth
///
/// The sweep above decided this constant and it is not withdrawn. What has changed is
/// how much of that finding is still this constant's to claim, because the splice
/// flags and the worker pool landed afterwards and took the rest of it. Same two capacities,
/// one commit, one runner each, five repeats of an 8 GiB download, `linux x86_64`,
/// `parity.yml` runs 37260088926 (64 KiB) and 37260096483 (256 KiB):
///
/// | pipe | throughput vs xray-core | cpu ms/GiB, ferrox / xray | ferrox's repeats |
/// | --- | ---: | ---: | --- |
/// | 64 KiB | **0.80x**, [0.76, 0.84] | 306 / 243 | spread **1.14x** |
/// | **256 KiB (this)** | 0.97x, [0.93, 1.00] | 276 / 304 | spread 1.09x |
///
/// The spread column is the fastest of that engine's five repeats over its slowest, so
/// it is reproducible from the report's per-repeat table rather than taken on trust.
///
/// Three things to read off it, and the first is the one that moves a sentence above.
///
/// **The bimodality is gone at 64 KiB.** Five repeats, 3132 to 3582 MiB/s, no half-speed
/// repeat, where the sweep above had one in five at 1.82x spread. So the paragraph above
/// credits this constant with removing a bimodality that the splice flags removed. The
/// tell was sound and the thing it pointed at got fixed twice.
///
/// **The absolute cost of a 64 KiB pipe roughly halved.** Median 3277 MiB/s at 64 KiB
/// now, against 1783 MiB/s when this constant was chosen -- and against 3191 at 256 KiB
/// in the same run. The throughput argument for raising the pipe is now a fifth of what
/// it was, and what is left of it is a ratio (0.80x to 0.97x) rather than a cliff.
///
/// **The CPU row now moves more than the effect.** The reference read 243 ms/GiB in one
/// leg and 304 in the other, a fifth, while this constant is worth 306 to 276. A row
/// whose noise is larger than the difference it is deciding cannot decide it, which is
/// why the ratio above is the claim and the CPU column is context.
///
/// So 256 KiB still ships, for the CPU and for a gate that resolves at 64 KiB and fails
/// (`Gate: FAIL`, 0.799x [0.760, 0.844]) where 256 KiB passes. What is withdrawn is the
/// claim that the pipe is worth a fifth of the throughput, and the claim that raising it
/// is what removed the bimodality.
///
/// # Why the two directions want different sizes, and what that costs
///
/// The pipe only sets how much can be moved *per round*, so it only matters when the
/// source has more than that waiting. And how much is waiting is set by whoever is
/// writing into it, which on this benchmark is the harness and is not the same on both
/// directions:
///
/// | direction | who writes | chunk | what a 256 KiB pipe can absorb |
/// | --- | --- | ---: | --- |
/// | download | the sink (`parity::emit`) | 64 KiB | 64 KiB — the pipe is never the limit |
/// | upload | the driver (`parity::stream_up`) | 1 MiB | 256 KiB — the pipe *is* the limit |
///
/// So a pipe that is generous enough for the download direction is four times too
/// small for the upload one, and a single constant has to choose. That is not a
/// reason to leave it at 64 KiB, which is too small for both.
///
/// # Why 256 KiB and not 1 MiB, when they measure the same
///
/// Both are at parity with the reference inside the interval, so the tie is broken on
/// what the number costs rather than on a digit neither can resolve. 256 KiB is a
/// quarter of the pipe memory -- `512 KiB` per connection against `2 MiB`, on a row
/// whose whole claim is an order of magnitude of resident memory -- it is a 64-page
/// kernel allocation rather than a 256-page one, and it needs only `pipe-max-size` to
/// be at least 256 KiB, so it survives a host that caps pipes below the 1 MiB
/// default. Where the kernel grants less than this, `F_GETPIPE_SZ` reads the grant
/// back, the loop uses the granted capacity, and the relay is slower rather than
/// wrong.
#[cfg(target_os = "linux")]
const SPLICE_PIPE_BYTES: usize = DEFAULT_SPLICE_PIPE_BYTES;

/// The capacity asked for, which is also the fallback when the kernel answers
/// neither `F_SETPIPE_SZ` nor `F_GETPIPE_SZ`. Named so the request and the fallback
/// are the same fact rather than two literals that can disagree.
#[cfg(target_os = "linux")]
const DEFAULT_SPLICE_PIPE_BYTES: usize = 256 * 1024;

/// The capacity to request, overridable so the choice can be re-measured.
///
/// `c_int` because that is `fcntl`'s third argument, and the conversion is
/// checked rather than cast: a value above `c_int::MAX` is not a capacity any
/// kernel will grant (`pipe-max-size` is bounded well below it), and passing a
/// truncated one would ask for a size nobody intended.
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
        // SAFETY: both descriptors came from one `pipe` call, are closed exactly
        // once here, and are not used again — `copy_all` holds the only reference.
        unsafe {
            libc::close(self.fds[0]);
            libc::close(self.fds[1]);
        }
    }
}

/// Where `pattern` starts in `head ++ probe`, or `None`.
///
/// The pattern may straddle the join, which is the whole reason this is a function
/// rather than a `windows` over either half: `head` is what has already been read and
/// `probe` is what is on view but not consumed, and a terminator split across them —
/// `head` ending `\r\n` and `probe` beginning `\r\n` — is one the join would hide. One
/// fewer byte than the pattern's length is the most overlap that can matter, so that
/// is where the scan starts; the range ends one byte short of the last place a
/// pattern of that length fits.
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

/// Read one HTTP head — through its `\r\n\r\n` — or `None` past `limit`.
///
/// # Why this is peeked and not read a byte at a time
///
/// A head is a few hundred bytes that arrive in one segment, and the byte-at-a-time
/// loop this replaces spent one `read(2)` per byte of it: a couple of hundred
/// syscalls, and a couple of hundred times the chance of a context switch in the
/// middle of a handshake, to learn something one peek sees whole. `peek` consumes
/// nothing, so the scan for the terminator runs over bytes already in memory and the
/// head itself is then read with a single `read_exact`.
///
/// # What that does to the bytes after the terminator
///
/// Nothing, which is the property that lets one function serve every carrier here.
/// `peek` leaves the socket's queue untouched, so a request that pipelines its first
/// frame behind the head still has those bytes waiting for the reader that comes
/// next — no `prefix` to carry, and no window in which they can be lost. That is why
/// [`crate::ws`], [`crate::httpupgrade`] and [`crate::httpheader`] all call this
/// rather than each keeping a loop of their own.
///
/// The limit is enforced on what has been *read*, so a peer that never terminates a
/// head is refused at `limit` bytes rather than growing the buffer.
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
            // No terminator in view: keep these bytes and look again.
            let take = n.min(limit - head.len());
            let mut consumed = vec![0u8; take];
            read_exact(stream, &mut consumed).ok()?;
            head.extend_from_slice(&consumed);
            continue;
        };
        // Consume exactly the head — `at + 4` in total, of which `head.len()` are
        // already read — and leave everything after it in the kernel.
        let mut rest = vec![0u8; at + 4 - head.len()];
        read_exact(stream, &mut rest).ok()?;
        head.extend_from_slice(&rest);
        return Some(head);
    }
}

/// A carrier's write half, for the one loop every carrier's relay is.
///
/// # Why this is a generic trait and not a `dyn`
///
/// The per-byte path is `read` into a chunk and then `sink.send(&buf[..n])`. If
/// this were `dyn CarrierSink` that second call is a **virtual call every 16 KiB**,
/// on the hottest loop in the application, and "one trait" would be paid for with
/// throughput — which is the one thing this change is not allowed to do.
///
/// As a generic bound the call is resolved at compile time, so
/// `relay_sink::<WsReader, WsWriter, _>` emits a **direct call to `WsWriter::send`
/// and nothing else** — the same static call the inherent method got before this
/// trait existed. Nothing about the emitted per-chunk code changes, which is the
/// whole argument; the trait removes the duplicated *loop*, not the call.
pub(crate) trait CarrierSink: Clone + Send + 'static {
    /// Hand `bytes` to the peer. `false` ends the relay.
    fn send(&self, bytes: &[u8]) -> bool;
    /// The carrier's end-of-stream, run once per connection.
    fn close(&self);
}

/// The relay `ws.rs` and `grpc.rs` each had, once.
///
/// # The two were the same function
///
/// Same two `try_clone`s, same `vec![0u8; CHUNK]` per direction, same
/// `read`/`send`/`write_all` loop, same teardown: `uplink.close()` and
/// `peer_read.shutdown(Both)` at the end of the spawned thread, `writer.close()`
/// and `peer_write.shutdown(Both)` on this one, then the join. `grpc.rs` added two
/// lines that set a `dead` flag and notify a condition variable, and those two
/// lines are what `on_reader_done` is for.
///
/// # Why it cannot be slower
///
/// Two claims, and they are different in kind:
///
/// - **The per-chunk path is unchanged code.** `W` is a generic, so `uplink.send`
///   is a direct call, inlined if it was inlined before, and `CHUNK` is still a
///   `const` in the monomorphised body. There is no `dyn`, no vtable, no
///   per-chunk indirection, and one `vec![0u8; CHUNK]` per direction per
///   connection exactly as there was.
/// - **The only new indirection is per connection, not per byte.**
///   `on_reader_done` is an `FnOnce`, called once after the downlink loop ends.
///   `grpc.rs`'s `dead` store and `notify_all` were already once-per-connection
///   work, and `ws.rs`'s is an empty closure that the optimiser drops. Nothing in
///   the inner loops goes through a pointer that did not go through one before.
///
pub(crate) fn relay_sink<R, W, F>(reader: R, writer: &W, peer: &TcpStream, on_reader_done: F)
where
    R: Read,
    W: CarrierSink,
    F: FnOnce(&mut R),
{
    relay_ordered::<R, W, F, CLOSE_BEFORE_JOIN>(reader, writer, peer, on_reader_done);
}

/// Close the sink and shut the peer down on both sides, then join.
///
/// `ws` and `grpc`: a carrier close frame is the last thing the peer sees and
/// nothing can still be queued behind it, so the sink closes as soon as either
/// loop ends.
const CLOSE_BEFORE_JOIN: bool = true;

/// Half-close the peer's write side, join, then close the sink.
///
/// `xhttp`: the sink's close is the **zero chunk**, and a zero chunk that wins
/// the race against the uplink thread ends the peer's reader before the last
/// reply arrives — a clean but empty stream rather than an error. So the peer's
/// write side is half-closed first, which lets it answer the `FIN` by draining,
/// the uplink thread is joined, and only then does the close go out.
///
/// The order is a protocol decision, not a style one, which is why this is a
/// `const` parameter and not a runtime flag: the two orders are different
/// programs and the compiler is told which one it is emitting.
const CLOSE_AFTER_JOIN: bool = false;

/// The one relay loop, in the two teardown orders the carriers need.
///
/// # Why this is a `const` and not a flag
///
/// `CLOSE_FIRST` is folded at MIR level, so each instantiation emits one order
/// and not a branch. That is a claim about codegen, so it was checked rather
/// than asserted: on `macos aarch64` with this profile, the `grpc` and `xhttp`
/// monomorphised bodies came out **instruction-for-instruction identical** to
/// `relay_sink` and `xhttp::relay` as they were before this parameter existed,
/// and `ws`'s differed only in a 32-byte-smaller stack frame and one merged
/// load pair.
///
/// Neither per-chunk loop contains a comparison on it, which is the part that
/// matters: the hot path has nothing to fold, so the parameter costs nothing per
/// chunk and the two orders are both whole programs.
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

/// The `xhttp` ordering: the sink closes after the join, never before.
///
/// `xhttp`'s close is the zero chunk and its teardown is the one order-sensitive
/// one, which is [`CLOSE_AFTER_JOIN`]. Everything else in the relay is the
/// shared loop, so there is one loop and not two.
pub(crate) fn relay_sink_drained<R: Read, W: CarrierSink>(reader: R, writer: &W, peer: &TcpStream) {
    relay_ordered::<R, W, fn(&mut R), CLOSE_AFTER_JOIN>(reader, writer, peer, |_| {});
}

/// Relay `reader` to `peer` and `peer` back, both directions, until either ends.
///
/// # Why this is here rather than one per carrier
///
/// `httpupgrade` and `httpheader` each had this function, and the two bodies were
/// **byte-identical** apart from the reader type in the signature and the local
/// `CHUNK`, which was the same `16 * 1024` in both. Two copies of a copy loop is
/// two places for the chunk size, the shutdown sequence and the half-close to
/// drift apart, and it is also two copies of the same machine code.
///
/// # Why it cannot be slower
///
/// The argument here is structural rather than statistical, because the two
/// bodies were the same code to begin with. A generic over `R: Read` is
/// **monomorphised**, so `relay::<UpReader>` and `relay::<HeadReader>` emit exactly
/// the two functions the compiler was emitting before — one `vec![0u8; CHUNK]`
/// per direction per connection, one `read` syscall per iteration, one
/// `write_all`, and no indirection through a trait object. The only thing that
/// changes is that the loop now lives in one place.
///
/// # What is deliberately *not* here
///
/// The other three carriers write through a carrier writer rather than a
/// `TcpStream`, so they use [`relay_sink`] and its two teardown orders instead:
/// they need a `send(&[u8]) -> bool` and a `close()` that are the carrier's own
/// framing, and `grpc.rs` additionally has a `dead` flag and a condition
/// variable to notify. That is a different body, not a parameter of this one.
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

/// Read exactly `buf.len()` bytes, one partial read at a time.
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

/// Header value for `name`, case-insensitive, trimmed, `None` when absent.
///
/// One walk of the head per header looked for, which is what every carrier did
/// before it had its own copy: three of them spelled this identically and the
/// request-path walk beside it twice.
pub(crate) fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    lines.next()?;
    for line in lines {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Request path without its query string, `None` on a malformed request line.
///
/// Query-free because that is what a configured path is compared against, and
/// because `?ed=` is the one query key that has to be gone before anything can
/// match — see [`ferrox_core::transport::EarlyData`].
pub(crate) fn request_path(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.split("\r\n").next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    Some(
        target
            .split_once('?')
            .map_or(target, |(base, _)| base)
            .to_owned(),
    )
}

/// Write two slices with one syscall where the platform allows it.
///
/// The bytes are the concatenation, exactly what two `write_all` calls would
/// put on the wire in order, so a byte-stream reader cannot tell. On `unix`
/// this is one `writev(2)`; elsewhere it is two `write_all` calls. Partial
/// writes advance across both slices the way `write_all` would, and an empty
/// slice is skipped without a syscall of its own.
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

/// Write three slices with one syscall where the platform allows it.
///
/// Same contract as [`write_all_two`]: the concatenation in order, one
/// `writev(2)` on `unix`, three `write_all` calls elsewhere.
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

/// Drain `iov` through `writev(2)` until `left` bytes are out, `false` on error.
///
/// `unix`-only: the only caller is [`write_all_two`] and [`write_all_three`],
/// so this is compiled out everywhere else.
///
/// A short write advances across whole entries and into at most one partial
/// entry, exactly like `write_all`'s loop over one buffer. `EINTR` retries;
/// any other error ends the stream, the same outcome a failed `write_all`
/// reports. `left` of zero writes nothing and reports success.
#[cfg(unix)]
fn writev_loop(fd: std::os::fd::RawFd, iov: &mut [libc::iovec], mut left: usize) -> bool {
    let mut at = 0;
    while left > 0 {
        // The count fits `c_int`: the callers pass at most three entries and
        // `at` only advances, so this conversion cannot fail.
        let count = i32::try_from(iov.len() - at).expect("writev takes at most three entries");
        // SAFETY: entries `at..` point into the caller's slices, which outlive
        // this call and are not mutated while the kernel reads them; `writev`
        // retains nothing after it returns.
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
                // SAFETY: `wrote < len`, so the advanced base stays inside the
                // same live slice and the shortened length still describes it.
                // The entry is only read again by the next `writev` below.
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

/// Read one `VLESS` response header off the stream, `None` on any mismatch.
fn read_vless_response(stream: &mut dyn Read) -> Option<()> {
    let mut prefix = [0u8; 2];
    read_exact(stream, &mut prefix).ok()?;
    let consumed = ferrox_core::vless::VlessLink::decode_response_header(&prefix).ok()?;
    if consumed > 2 {
        let mut rest = vec![0u8; consumed - 2];
        read_exact(stream, &mut rest).ok()?;
    }
    Some(())
}

/// Decode a client request header from the stream.
///
/// The second field is `Addons.Flow`, which selects the framing of everything
/// that follows: empty for raw bytes, `xtls-rprx-vision` for padded frames.
fn decode_request(stream: &mut dyn Read) -> Option<([u8; 16], String, u8, SocketAddr)> {
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
    let mut port = [0u8; 2];
    read_exact(stream, &mut port).ok()?;
    let target = read_addr(stream, u16::from_be_bytes(port))?;
    Some((id, flow, cmd[0], target))
}

/// `Addons.Flow` out of a length-delimited `Addons` message: field 1, a string.
///
/// Protobuf rather than a fixed layout, so this walks tags and stops at the
/// first field 1; anything it cannot read is an empty flow, which is the
/// unframed path rather than a guess at a framed one.
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

/// One `protobuf` varint from `at`, advancing it past the bytes read.
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

/// Decode a `trojan` request: key, `CRLF`, command, `SOCKS`-order address, `CRLF`.
fn decode_trojan_request(stream: &mut dyn Read, key: &[u8; 56]) -> Option<(u8, SocketAddr)> {
    let mut got = [0u8; 56];
    read_exact(stream, &mut got).ok()?;
    if got != *key {
        return None;
    }
    let mut crlf = [0u8; 2];
    read_exact(stream, &mut crlf).ok()?;
    if crlf != *b"\r\n" {
        return None;
    }
    let mut cmd = [0u8; 1];
    read_exact(stream, &mut cmd).ok()?;
    let target = read_socks_addr(stream)?;
    read_exact(stream, &mut crlf).ok()?;
    if crlf != *b"\r\n" {
        return None;
    }
    Some((cmd[0], target))
}

/// Read one `VLESS` address (`1`/`2`/`3`) for a known port.
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
    format!("{host}:{port}").to_socket_addrs().ok()?.next()
}

/// Append `atyp` plus address bytes for a socket address; `v6` tags `IPv6`.
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

/// Append a `SOCKS`-order address (`atyp`, address, port) for replies and datagrams.
fn push_socks_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    push_addr(out, addr, 4);
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Split one `SOCKS`-`UDP` datagram into destination and payload.
///
/// The header is `rsv(2)`, `frag(1)`, then a `SOCKS`-order address; fragments
/// are refused rather than reassembled, like every peer reassembles them.
fn parse_socks_udp(packet: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let mut cursor = std::io::Cursor::new(&packet[4..]);
    let addr = read_socks_addr_rest(&mut cursor, packet[3])?;
    let used = 4 + cursor.position() as usize;
    Some((addr, &packet[used..]))
}

/// Hex digits for password hashing.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex `SHA224` of a password: the 56-byte `trojan` key.
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

/// Accept a `SOCKS5` `CONNECT` or `UDP ASSOCIATE`, returning the command and target.
fn socks_handshake(client: &mut TcpStream) -> Option<(u8, SocketAddr)> {
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
    let target = read_socks_addr_rest(client, req[3])?;
    if req[1] == 1 && client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).is_err() {
        return None;
    }
    Some((req[1], target))
}

/// Read a `SOCKS`-order address (`atyp`, address, port) from the stream.
fn read_socks_addr(stream: &mut dyn Read) -> Option<SocketAddr> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).ok()?;
    read_socks_addr_rest(stream, atyp[0])
}

/// Read the address and port after a `SOCKS`-order `atyp` byte.
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

/// First inbound `vless` client's id bytes, zeros when unparseable.
fn inbound_id(inbound: &Json) -> [u8; 16] {
    inbound
        .get("settings")
        .and_then(|s| s.get("clients"))
        .and_then(Json::as_arr)
        .and_then(|clients| clients.first())
        .and_then(|client| client.get("id"))
        .and_then(Json::as_str)
        .and_then(uuid_bytes)
        .unwrap_or([0u8; 16])
}

/// Whether any entry in `array` names `protocol`.
fn has_protocol(root: &Json, array: &str, protocol: &str) -> bool {
    root.get(array).and_then(Json::as_arr).is_some_and(|items| {
        items
            .iter()
            .any(|item| item.get("protocol").and_then(Json::as_str) == Some(protocol))
    })
}

/// First inbound cipher name, empty when unparseable.
fn inbound_method(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("method"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Inbound `shadowsocks` password, sitting beside `method`, empty when absent.
pub(crate) fn inbound_ss_password(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// First inbound `trojan` client's password, empty when unparseable.
fn inbound_password(inbound: &Json) -> String {
    inbound
        .get("settings")
        .and_then(|s| s.get("clients"))
        .and_then(Json::as_arr)
        .and_then(|clients| clients.first())
        .and_then(|client| client.get("password"))
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_owned()
}

/// First non-`freedom` outbound in `vless`, `vmess`, `trojan`, `shadowsocks` order.
fn find_outbound(root: &Json) -> Option<Outbound> {
    if let Some(vless) = find_vless_outbound(root) {
        return Some(Outbound::Vless(vless));
    }
    if let Some(vmess) = find_vmess_outbound(root) {
        return Some(Outbound::Vmess(vmess));
    }
    if let Some(trojan) = find_trojan_outbound(root) {
        return Some(Outbound::Trojan(trojan));
    }
    // `freedom` last: a config that names a proxy server and a `freedom` fallback
    // is the common shape, and the server is the one a `socks` inbound should use.
    find_shadowsocks_outbound(root)
        .map(Outbound::Shadowsocks)
        .or_else(|| is_freedom(root).then_some(Outbound::Freedom))
}

/// A `freedom` outbound, named by its protocol alone.
fn is_freedom(root: &Json) -> bool {
    has_protocol(root, "outbounds", "freedom")
}

/// First `trojan` outbound's server and password, `None` when the shape differs.
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

/// First `shadowsocks` outbound's server, cipher and password, `None` otherwise.
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

/// First `vless` outbound's server and user, `None` when the shape differs.
fn find_vless_outbound(root: &Json) -> Option<VlessOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("vless") {
            continue;
        }
        // `QUIC` is always `TLS` on the wire and `quiche` performs that
        // handshake itself (verified, against explicit anchors), so a
        // `quic`+`tls` outbound is dialable even though raw-`TCP` dials no
        // `TLS` at all. Anything else past this gate stays as it was.
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
        let vnext = outbound
            .get("settings")
            .and_then(|s| s.get("vnext"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = vnext else { continue };
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
        let quic_roots = if matches!(carrier, Carrier::Quic) {
            outbound
                .get("streamSettings")
                .and_then(|s| s.get("tlsSettings"))
                .and_then(|s| s.get("caCertFile"))
                .and_then(Json::as_str)
                .and_then(|path| std::fs::read(path).ok())
                .map(|pem| crate::quic::parse_ca_pem(&pem))
                .filter(|roots| !roots.is_empty())
        } else {
            None
        };
        return Some(VlessOut {
            address,
            port,
            id,
            carrier,
            host,
            mux,
            quic_roots,
        });
    }
    None
}

/// First `vmess` outbound's server, user and cipher, `None` otherwise.
fn find_vmess_outbound(root: &Json) -> Option<VmessOut> {
    let empty = Vec::new();
    let outbounds = root
        .get("outbounds")
        .and_then(Json::as_arr)
        .unwrap_or(&empty);
    for outbound in outbounds {
        if outbound.get("protocol").and_then(Json::as_str) != Some("vmess") {
            continue;
        }
        let vnext = outbound
            .get("settings")
            .and_then(|s| s.get("vnext"))
            .and_then(Json::as_arr)
            .and_then(|servers| servers.first());
        let Some(server) = vnext else { continue };
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

/// Carrier from a `streamSettings` block, raw `TCP` when nothing is named.
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
        Some("kcp" | "mkcp") => Carrier::Kcp,
        Some("hysteria") => Carrier::Hysteria,
        Some("masque") => Carrier::Masque,
        Some("xdrive") => Carrier::Xdrive,
        // Absent, empty, explicit raw or tcp: the only rows that may ride raw
        // TCP, and the only place the `HTTP` camouflage header wins.
        None | Some("" | "raw" | "tcp") => match tcp_http_path(settings) {
            Some(path) => Carrier::HttpHeader { path },
            None => Carrier::Raw,
        },
        // Every other spelling — including the `h2`/`h3`/`http` networks
        // upstream removed at this pin — refuses rather than downgrading.
        Some(_) => Carrier::Unknown,
    }
}

/// Upgrade path from a settings block, `/` when unnamed.
fn sub_path(settings: Option<&Json>, key: &str) -> String {
    settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("path"))
        .and_then(Json::as_str)
        .unwrap_or("/")
        .to_owned()
}
/// `gRPC` service path from `serviceName`, `/<service>/Tun` like every peer.
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

/// `XHTTP` path from `xhttpSettings` or its legacy `splithttpSettings` alias.
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

/// Camouflage path when `tcpSettings.header.type` is `http`, `None` otherwise.
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

/// Carrier plus `Host` from an outbound's `streamSettings`, raw by default.
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
        Carrier::Kcp => "kcpSettings",
        Carrier::Hysteria => "hysteriaSettings",
        Carrier::Masque => "masqueSettings",
        Carrier::Xdrive => "xdriveSettings",
        Carrier::Unknown | Carrier::Raw => "",
    };
    let host = settings
        .and_then(|s| s.get(key))
        .and_then(|s| s.get("host"))
        .and_then(Json::as_str)
        .unwrap_or(address)
        .to_owned();
    (carrier, host)
}

/// Carrier from an inbound's `streamSettings`, raw `TCP` when unnamed.
fn inbound_carrier(inbound: &Json) -> Carrier {
    stream_carrier(inbound.get("streamSettings"))
}

/// Outer security of an inbound or outbound, `""` when unnamed.
fn stream_security(node: &Json) -> &str {
    node.get("streamSettings")
        .and_then(|s| s.get("security"))
        .and_then(Json::as_str)
        .unwrap_or("")
}

/// Whether this build serves or dials that security over raw `TCP`.
fn vless_security_supported(sec: &str) -> bool {
    sec.is_empty() || sec == "none"
}

/// Lowercase-hex `8-4-4-4-12` UUID to bytes, `None` on any other shape.
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

/// Fresh clamped private key with its public key, both unpadded base64url.
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

/// Unpadded base64url, the encoding the oracle keys arrive in.
fn b64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        let mut shift = 18;
        for _ in 0..=chunk.len() {
            out.push(ALPHABET[((word >> shift) & 0x3F) as usize] as char);
            shift -= 6;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A head is read whole even when the terminator arrives in pieces.
    ///
    /// The head is peeked rather than read a byte at a time, and `peek` sees what has
    /// arrived — so a `\\r\\n\\r\\n` split across segments is the case that would break a
    /// reader that trusted one view. It is joined across the two, and the bytes are
    /// the ones a byte-at-a-time loop would have read.
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

    /// The bytes behind a head are left in the kernel for whoever reads next.
    ///
    /// This is the contract that lets one peeked head serve every carrier: a peer that
    /// pipelines its first frame behind the request must not lose it, and `peek`
    /// consumes nothing, so the socket's queue is untouched by reading the head. If
    /// this ever fails, every carrier that calls [`read_http_head`] is dropping the
    /// first bytes of its payload.
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

    /// A head that never terminates is refused at the limit, not buffered past it.
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

    /// The limit the tests above read at, so each test names no number of its own.
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

    /// The two copy paths must move the same bytes.
    ///
    /// On Linux `copy_all` is `splice(2)` through a pipe and `copy_all_memcpy` is the
    /// `read`/`write` loop, so this is the only place the pair is compared, and it is
    /// the whole correctness argument for the splice path: same bytes, no buffer. The
    /// payload is far larger than one 64 KiB pipe buffer, so `SplicePipe::push` drains
    /// the pipe several times per direction rather than once, which is the loop a
    /// short write would break.
    ///
    /// Everywhere else `copy_all` *is* `copy_all_memcpy`, so the comparison collapses
    /// to a tautology there. That is stated rather than hidden: the assertion that
    /// carries weight is `spliced == payload`, which holds on every platform.
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

        // Deterministic and not all-zero: a run of equal bytes would pass through a
        // loop that dropped every other one.
        let payload: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
        let spliced = round_trip(&payload, copy_all);
        let copied = round_trip(&payload, copy_all_memcpy);
        assert_eq!(spliced, payload, "the splice path must move every byte");
        assert_eq!(copied, payload, "the copying path must move every byte");
        assert_eq!(spliced, copied, "the two paths must agree");
    }

    /// A payload larger than the copy buffer, through the real relay, byte for byte.
    ///
    /// Nagle is off on both ends of a connection this binary opens.
    ///
    /// The property, not the call site: `no_delay` is the whole of it and
    /// `dial` is the only way this file dials, so testing the two covers every
    /// accept and every dial. A socket that is connected and *not* Nagle-free is
    /// the exact regression this is here to catch -- `std` never sets the option,
    /// so nothing else in the tree does, and a socket with Nagle on is not broken,
    /// it is quietly slower.
    #[test]
    fn both_sockets_of_a_connection_have_nagle_off() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        let server = thread::spawn(move || {
            let (accepted, _) = listener.accept().expect("accepts");
            accepted
        });
        let dialled = dial(&SocketAddr::from(([127, 0, 0, 1], port))).expect("connects");
        // A connect that succeeded has reached `SocketConnected` and no further,
        // which is what the failure taxonomy calls evidence of nothing.
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

    /// The splice pipe's capacity is read back, so a clamped or refused
    /// `F_SETPIPE_SZ` cannot leave the loop asking for a size the pipe does not have.
    ///
    /// This is the difference between a measurement and a guess. `splice` into a
    /// pipe moves at most what fits, so a request above the real capacity is not an
    /// error -- it is a request that is silently reduced, every round, forever.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_splice_pipe_reads_back_the_capacity_it_was_granted() {
        let pipe = SplicePipe::new().expect("a pipe is available on this host");
        assert!(
            pipe.capacity > 0,
            "a granted capacity of zero would make every splice ask for nothing"
        );
        // SAFETY: the descriptor is live and came from `pipe`, and `fcntl` reads
        // the buffer size rather than the descriptor's contents.
        let asked = unsafe { libc::fcntl(pipe.fds[0], libc::F_GETPIPE_SZ) };
        assert_eq!(
            asked as usize, pipe.capacity,
            "the recorded capacity must be the kernel's answer, not the request"
        );
        // And it is the capacity, not the request: a request the kernel refused
        // must not survive into the loop.
        assert!(
            pipe.capacity <= DEFAULT_SPLICE_PIPE_BYTES.max(1) || pipe.capacity > 0,
            "a granted capacity is always positive and never invented"
        );
    }

    /// The pool must never serialise two directions, and must never lose one.
    ///
    /// Both properties are about the same mistake — handing a task to a worker that is
    /// not idle — and it is the mistake a worker that puts itself on the idle list
    /// *before* running its first task would make. So the test runs more concurrent
    /// tasks than there are workers and requires every one of them to be inside its
    /// body at the same time. If two shared a thread the barrier would never fill and
    /// the test would time out rather than pass.
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
                // Spin until every other direction has also arrived. A pooled thread
                // shared by two of them would deadlock here, which is the failure this
                // is looking for -- and it fails the test rather than hanging it,
                // because the wait is bounded.
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

    /// A direction that panics must not take its worker with it: the connection it
    /// belonged to is already gone, and the pool has to survive it.
    #[test]
    fn a_direction_that_panics_does_not_take_the_worker_with_it() {
        let pool = RelayPool::global();
        pool.run(|| panic!("this direction is broken on purpose"))
            .recv()
            .expect(
                "a panicking direction still has to report that it ended, or the relay \
             waits on it forever",
            );
        // The pool must still hand work out afterwards.
        let (tx, rx) = std::sync::mpsc::channel();
        pool.run(move || {
            let _ = tx.send(());
        })
        .recv()
        .expect("the pool still works");
        assert!(rx.try_recv().is_ok(), "and the work after it actually ran");
    }

    /// A sink that behaves like `xhttp`'s: once closed, it refuses further bytes.
    ///
    /// This models the property the ordering exists for. `xhttp`'s sink close is the
    /// zero chunk, and a peer that has read the zero chunk stops reading, so a reply
    /// that arrives after the close is **dropped** — a clean but empty stream rather
    /// than an error. Modelling that here is what makes the two orders observably
    /// different instead of two spellings of the same sequence.
    #[derive(Clone, Default)]
    struct ClosingSink {
        state: Arc<Mutex<(bool, Vec<u8>)>>,
    }

    impl ClosingSink {
        /// Whether the sink closed before anything was sent to it.
        fn closed_empty(&self) -> bool {
            let state = self.state.lock().expect("locks");
            state.0 && state.1.is_empty()
        }
        /// The bytes the sink accepted before it closed.
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

    /// Drives one relay against a peer that answers only after the client half closes.
    ///
    /// The peer replies to the *end* of the request, so its answer is necessarily in
    /// flight while the relay tears down. That is the race the two orders resolve
    /// differently, and it is why this cannot be faked with an in-memory pair.
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
            // Answering the *end* of the request is what puts the reply in
            // flight while the relay is tearing down.
            stream.write_all(b"reply").expect("writes");
            // Held open, so the reply is still unread when the uplink thread
            // goes looking for it.
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
            // The half-close is what the relay forwards to the peer as its FIN.
            writer.shutdown(Shutdown::Write).expect("half closes");
        });
        let sink = carrier.join().expect("joins");
        client.join().expect("joins");
        server.join().expect("joins");
        (sink.closed_empty(), sink.accepted())
    }

    /// `xhttp`'s ordering: the sink closes **after** the join, so the last reply
    /// still gets in.
    ///
    /// The peer's write side is half-closed first, which lets the peer answer the
    /// `FIN` by draining and replying; the uplink thread carries that reply to the
    /// sink; only then does the zero chunk go out. Closing first would end the
    /// peer's reader before the reply arrived, which reads as a clean but empty
    /// stream rather than an error — invisible, which is why it is asserted here.
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

    /// `ws` and `grpc` keep the other order, and this is what it costs them.
    ///
    /// Closing before the join means a peer that only answers its `FIN` has its
    /// reply refused by the sink. That is correct for a carrier whose close frame
    /// ends the exchange and is wrong for `xhttp`'s, which is the whole reason there
    /// are two orders rather than one — and it is asserted so that folding them
    /// together would fail here rather than in a protocol trace.
    #[test]
    fn the_default_order_refuses_a_reply_that_follows_the_fin() {
        let (closed_empty, accepted) = relay_against_a_late_peer(false);
        assert!(
            closed_empty || accepted.is_empty(),
            "a sink that closed before the reply must not accept it"
        );
    }

    /// A refused dial is `None`, not a panic and not a socket.
    #[test]
    fn a_dial_that_cannot_connect_is_classified_not_dropped() {
        // Port 1 on loopback: nothing listens there, and the connection is
        // refused rather than hanging, so this does not wait out `DIAL_TIMEOUT`.
        let failure =
            dial(&SocketAddr::from(([127, 0, 0, 1], 1))).expect_err("nothing listens on port 1");
        assert_eq!(failure.stage, Stage::SocketConnected);
        assert_eq!(
            failure.kind,
            Kind::Refused,
            "a refused connect is observed, not inferred"
        );
        // The whole reason this is a type: a refused connect is not worth
        // redialling, and an `Err` that had been an `io::Error` could not say so.
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

    /// A flow that never fills a small buffer stays small, and one that does is
    /// back to the measured bulk size. The 512 KiB-per-flow weakness the
    /// [`RELAY_BUFFER`] comment names is exactly the case that never promotes, so
    /// this is the test that says the constant is no longer paid unconditionally.
    #[test]
    fn a_relay_buffer_promotes_only_on_a_read_that_filled_it() {
        let mut buffer = RelayBuf::new();
        assert_eq!(buffer.size(), RELAY_SMALL_BUFFER);

        // A short read: a peer with less to say than a buffer holds. This is the
        // interactive case and it must not promote, however many times it happens.
        for _ in 0..64 {
            let short = buffer.filled(RELAY_SMALL_BUFFER - 1);
            assert_eq!(short.len(), RELAY_SMALL_BUFFER - 1);
            assert_eq!(buffer.size(), RELAY_SMALL_BUFFER, "a short read promoted");
        }

        // A read that filled it: the bulk case, promoted once.
        assert_eq!(buffer.filled(RELAY_SMALL_BUFFER).len(), RELAY_SMALL_BUFFER);
        assert_eq!(buffer.size(), RELAY_BUFFER, "a full read did not promote");

        // And promotion is one-way: a short read afterwards does not shrink it,
        // because the flow has already proven what it is.
        assert_eq!(buffer.filled(1).len(), 1);
        assert_eq!(buffer.size(), RELAY_BUFFER);
    }

    #[test]
    fn a_promoted_buffer_returns_the_bytes_that_were_read() {
        // Promotion resizes, which moves nothing but must not corrupt the prefix a
        // caller is about to write out. A `Vec` that reallocates mid-read would
        // hand back a slice over freed memory here.
        let mut buffer = RelayBuf::new();
        buffer.as_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);
        let read = buffer.filled(RELAY_SMALL_BUFFER);
        assert_eq!(&read[..4], &[1, 2, 3, 4], "promotion lost the bytes read");
        assert_eq!(read.len(), RELAY_SMALL_BUFFER);
    }

    /// [`the_splice_path_and_the_copying_path_move_the_same_bytes`] proves the two
    /// paths against each other; this proves the wiring, because `relay` clones four
    /// sockets, spawns one direction and shuts both down when a half ends, and that
    /// is where a splice pipe's lifetime has to line up with the socket's.
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

    /// One `VLESS` connection through each new carrier, against a loopback echo.
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

    /// Throwaway P-256 leaf for `carrier.test`, generated once with openssl
    /// and embedded as DER: a PEM private-key block would fail
    /// `scripts/check-fixture-safety.sh`, and DER byte arrays are what
    /// `ferrox-core`'s own `tls.test` anchor does. It signs nothing real
    /// and trusts nothing real — both ends of the carried-`TLS` tests.
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

    /// One 16 KiB round trip through [`CarrierStream`], on one byte-stream
    /// carrier. This is the property the handshakes need: `TLS` and `REALITY`
    /// both take any `Read + Write`, so a carrier that carries a round trip
    /// carries a handshake.
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

    /// Server identity plus client trust for the carried-`TLS` tests, from the
    /// fixture below.
    fn carried_tls_configs() -> (
        std::sync::Arc<ferrox_core::tls::TlsServerConfig>,
        ferrox_core::tls::TlsConfig,
    ) {
        let server = std::sync::Arc::new(ferrox_core::tls::TlsServerConfig {
            cert_chain: vec![CARRIER_CERT.to_vec()],
            key_der: CARRIER_KEY.to_vec(),
            key_kind: ferrox_core::tls::ServerKeyKind::Pkcs8,
        });
        let client = ferrox_core::tls::TlsConfig {
            server_name: "carrier.test".to_owned(),
            alpn: Vec::new(),
            roots: vec![CARRIER_CERT.to_vec()],
        };
        (server, client)
    }

    /// A real `TLS` handshake through [`CarrierStream`], then a 4-byte echo
    /// inside the session. The handshake writes flights as several small
    /// writes and reads records split across frames and chunks, so this is
    /// what proves the message and chunk boundaries are invisible to it.
    ///
    /// Neither side flushes: this provider pushes records on every write, so a
    /// flush after the last write only performs a trailing read for peer input
    /// the protocol never sends — a hang on a transport whose peer stays silent
    /// with its socket open, which is exactly what both ends do here while one
    /// joins the other.
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
            // Mirror the client's timeout: a stalled handshake must fail this
            // test at the stage that stalled (see the `expect` below), not hang
            // the whole test binary on a thread nobody joins.
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

    /// `SOCKS` dialing `VMess` over `XHTTP`, against a loopback echo.
    ///
    /// This is the carried-dial path end to end: the `socks` handshake, the
    /// sealed request and response through chunks, then plaintext against
    /// sealed frames both ways.
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

    /// `trojan` outbounds read their carrier and `Host` like every other
    /// password-led outbound: `ws` plus `host` here, raw `TCP` plus the
    /// address fallback when nothing is named.
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

    /// One `trojan` connection over `WebSocket`, against a loopback echo.
    ///
    /// The password-led header goes out as the first message and the ping
    /// comes back as messages: no reply header exists, so the first bytes
    /// back are already the relay.
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

    /// `SOCKS` dialing `shadowsocks` over one carrier, against a loopback echo.
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

    /// The `UDP` framing's own round trip: `u16` length plus payload, at every
    /// size that matters, with an empty write sending nothing at all.
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

    /// `SOCKS`-order addresses split and reject: every family round-trips, and
    /// fragments, unknown families and truncated tails refuse.
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

    /// `VLESS` `UDP` over raw `TCP` against a loopback echo, both directions.
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

    /// A `UDP` command with a flow is refused: `Vision` framing has no datagram
    /// form, so a peer asking for both gets silence rather than plain relay.
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

    /// `SOCKS` `UDP ASSOCIATE` through `VLESS` `UDP` to a loopback echo.
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

    /// The Trojan `UDP` framing's own round trip: address, length, `CRLF`,
    /// payload, with empties skipped and separators checked.
    #[test]
    fn trojan_udp_frames_carry() {
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = tunnel.accept().expect("accepts");
            let mut buf = vec![0u8; UDP_BUF];
            loop {
                match read_trojan_datagram(&mut stream, &mut buf) {
                    Some((dest, n)) => {
                        if !write_trojan_datagram(&mut stream, &dest, &buf[..n]) {
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
        assert!(write_trojan_datagram(&mut stream, &v4, b"ping"));
        let mut buf = vec![0u8; UDP_BUF];
        let (dest, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
        assert_eq!(dest, v4);
        assert_eq!(&buf[..n], b"ping");
        assert!(write_trojan_datagram(&mut stream, &v4, &[]));
        let wide: Vec<u8> = (0..512).map(|i| (i % 251) as u8).collect();
        assert!(write_trojan_datagram(&mut stream, &v4, &wide));
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

    /// A bad separator on the Trojan `UDP` path ends the flow.
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

    /// Trojan `UDP` over raw `TCP` against loopback echoes, with two
    /// destinations on one flow to prove datagrams route by their own address.
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
        for (port, word) in [(first, b"ping".as_slice()), (second, b"pong".as_slice())] {
            let dest: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
            assert!(write_trojan_datagram(&mut stream, &dest, word));
            let mut buf = vec![0u8; UDP_BUF];
            let (source, n) = read_trojan_datagram(&mut stream, &mut buf).expect("reads");
            assert_eq!(source.port(), dest.port());
            assert_eq!(source.ip().to_canonical(), dest.ip().to_canonical());
            assert_eq!(&buf[..n], word);
        }
    }

    /// `SOCKS` `UDP ASSOCIATE` through Trojan `UDP` to a loopback echo.
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

    /// `VMess` `UDP` over raw `TCP` against a loopback echo, both directions.
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

    /// `SOCKS` `UDP ASSOCIATE` through `VMess` `UDP` to a loopback echo, with a
    /// second destination proving the re-dial.
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

    /// `shadowsocks` datagrams against a loopback echo, both directions.
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
        // The serving socket is bound here and handed over, so there is no race
        // for the port: the old shape picked a port with a probe socket, dropped
        // it, and asked `serve_udp` to bind it on another thread, which meant a
        // first datagram could go out to a port nothing had bound yet. On
        // `windows x86_64` that is not a slow start, it is a wrong answer --
        // `ICMP port unreachable` marks the sending socket `WSAECONNRESET`, so
        // every later read on it fails at once instead of waiting out its
        // timeout, and fifteen retries finish in milliseconds. Binding first also
        // means the port this test reads is the port the server has.
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
        // Each attempt sends from a **fresh** socket. The serving port is bound
        // by `serve_udp` on another thread and the first datagram goes out
        // without waiting for it, which is a race the retry loop has to absorb,
        // and on `windows x86_64` one socket cannot absorb it: an `ICMP port
        // unreachable` from a send to the not-yet-bound port marks the socket
        // `WSAECONNRESET`, and every later `recv_from` on that socket fails at
        // once instead of waiting out its timeout. Fifteen retries on one socket
        // then finish in milliseconds and the failure reads `echoes` — a server
        // that was never slow. So the retry is a retry of the whole exchange,
        // socket and all.
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

    /// `SOCKS` `UDP ASSOCIATE` through `shadowsocks` to a loopback echo.
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

    /// A loopback echo for mux tests: every connection is echoed back.
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

    /// One mux frame out.
    fn mux_test_send(
        stream: &mut TcpStream,
        frame: ferrox_core::mux::Outgoing<'_>,
        data: Option<&[u8]>,
    ) {
        let mut buf = vec![0u8; frame.frame_len(data.map_or(0, <[u8]>::len))];
        let n = frame.encode_into(data, &mut buf);
        stream.write_all(&buf[..n]).expect("writes");
    }

    /// One mux frame in, chunk included when `DATA` says one follows.
    fn mux_test_recv(stream: &mut TcpStream) -> (u16, ferrox_core::mux::Status, Vec<u8>) {
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
        let (frame, _) = ferrox_core::mux::decode(&whole, ferrox_core::mux::NewTail::Forward)
            .expect("decodes");
        (frame.id, frame.status, frame.data.unwrap_or(&[]).to_vec())
    }

    /// A loopback `TCP` mux target.
    fn mux_test_target(port: u16) -> ferrox_core::mux::Target<'static> {
        ferrox_core::mux::Target {
            network: ferrox_core::mux::Network::Tcp,
            port,
            addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
        }
    }

    /// Open a raw-`TCP` `VLESS` mux tunnel: handshake in, `[0, 0]` out.
    fn mux_test_connect(id: &[u8; 16], tunnel_port: u16) -> TcpStream {
        let mut stream = TcpStream::connect(("127.0.0.1", tunnel_port)).expect("connects");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut header = vec![0u8];
        header.extend_from_slice(id);
        header.push(0);
        header.push(3);
        header.extend_from_slice(&0u16.to_be_bytes());
        header.push(1);
        header.extend_from_slice(&[127, 0, 0, 1]);
        stream.write_all(&header).expect("requests");
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).expect("replies");
        assert_eq!(response, [0, 0]);
        stream
    }

    /// The peer closed: drain any coalesced bytes, then the end of stream.
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

    /// `VLESS` mux serve demultiplexes two interleaved sessions: each `New`
    /// opens its own echo relay, `Keep` payloads route by id, and each `End`
    /// comes back once its direction closes.
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
        let end =
            |id: u16| ferrox_core::mux::Outgoing::bare(id, ferrox_core::mux::Status::End, 0);
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

    /// `VLESS` mux serve refuses what it will not carry: a `UDP` open gets an
    /// `End` back, an unknown id is dropped without disturbing the living, and
    /// a malformed frame ends the connection instead of desynchronizing it.
    #[test]
    fn mux_serve_refuses_udp_unknown_and_malformed() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let echo_port = mux_test_echo();
        let tunnel = TcpListener::bind("127.0.0.1:0").expect("binds");
        let tunnel_port = tunnel.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = tunnel.accept().expect("accepts");
            serve_vless_raw(stream, &id, true);
        });
        let mut stream = mux_test_connect(&id, tunnel_port);
        let udp = ferrox_core::mux::Outgoing {
            id: 3,
            status: ferrox_core::mux::Status::New,
            options: 0,
            target: Some(ferrox_core::mux::Target {
                network: ferrox_core::mux::Network::Udp,
                port: 53,
                addr: ferrox_core::addr::Addr::V4([127, 0, 0, 1]),
            }),
            global_id: None,
        };
        mux_test_send(&mut stream, udp, None);
        let (got_id, got_status, _) = mux_test_recv(&mut stream);
        assert_eq!(got_id, 3);
        assert_eq!(got_status, ferrox_core::mux::Status::End);
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

    /// `SOCKS` through a `VLESS` mux uplink to a loopback echo, both roles over
    /// one multiplexed connection.
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

    /// A wrong password ends the `trojan` handshake with no relay: the server
    /// returns, the socket closes, and the client's next read fails.
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

    /// `SOCKS` dialing `VMess` over `WebSocket`, against a loopback echo.
    ///
    /// The true dial path end to end (`dial_vmess` through `serve_socks`),
    /// unlike the hand-rolled client in the carrier unit test: the sealed
    /// request goes out as messages, the response header is read back through
    /// them, then sealed frames both ways.
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

    /// `SOCKS` dialing `VMess` over `HTTPUpgrade`, against a loopback echo.
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

    /// `SOCKS` dialing `VMess` over `gRPC`, against a loopback echo.
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

    /// `SOCKS` dialing `trojan` over `WebSocket`, against a loopback echo.
    ///
    /// This is the dial path end to end: the `socks` handshake, the
    /// password-led header through one message, then raw relay both ways.
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

    /// `SOCKS` dialing `trojan` over `HTTPUpgrade`, against a loopback echo.
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

    /// `SOCKS` dialing `trojan` over `gRPC`, against a loopback echo.
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

    /// `SOCKS` dialing `trojan` over `XHTTP`, against a loopback echo.
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

    /// `SOCKS` dialing `trojan` over camouflage `GET`, against a loopback echo.
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

    /// `network=quic` names [`Carrier::Quic`], never raw `TCP` — including
    /// beside a `tcpSettings` `HTTP` masquerade, which the fallthrough below
    /// must not steal.
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

    /// Every network name the two upstreams spell is named here: the carried
    /// ones map to their carrier, the carried-aliases (`websocket`,
    /// `splithttp`) to theirs, and everything named-but-unbuilt refuses as its
    /// own variant — never raw `TCP` in disguise.
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
            ("h2", "Unknown"),
            ("h3", "Unknown"),
            ("http", "Unknown"),
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
                Carrier::Kcp => "Kcp",
                Carrier::Hysteria => "Hysteria",
                Carrier::Masque => "Masque",
                Carrier::Xdrive => "Xdrive",
                Carrier::Unknown => "Unknown",
            };
            assert_eq!(tag, want, "{network} should map to {want}");
        }
    }

    /// A `QUIC` serve closes without reading: refusal, not a handshake.
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

    /// No `QUIC` `UDP` uplink: the gate is the carrier, before any socket.
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
        };
        let dest: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let source = Arc::new(Mutex::new(None));
        assert!(dial_udp_uplink(&vless, &dest, &relay, source).is_none());
    }

    /// Wall-clock bound for every `QUIC` test wait: socket timeouts, the
    /// handshake, the header arrival, the echo loops. One bound on purpose —
    /// a descheduled server thread wakes to a `WouldBlock` its socket
    /// timeout raised, and a bound below the connection idle timeout would
    /// fail the test for a stall the protocol survives. A genuinely stuck
    /// peer still fails loudly at the bound instead of hanging the suite.
    const QUIC_TEST_TIMEOUT: Duration = Duration::from_secs(120);

    /// Poll quantum for every `QUIC` test-server wait: `quiche` loss
    /// detection, retransmit and idle timers only fire in `on_timeout`, so a
    /// server parked a whole `QUIC_TEST_TIMEOUT` in one `recv_from` never
    /// retransmits a lost flight — one dropped datagram then costs the full
    /// bound instead of one probe round, blowing past the dial's own budget.
    /// Short polls drive the timers; the overall bound stays
    /// `QUIC_TEST_TIMEOUT` at each loop's own deadline.
    const QUIC_TEST_POLL: Duration = Duration::from_millis(100);

    /// One server-side datagram wait: `Some` on arrival, `None` on a quiet
    /// poll. Quiet is routine, never an error — the caller drives
    /// `on_timeout`, flushes, and re-checks its own deadline. A dead socket
    /// fails loudly at once; silence fails loudly at the deadline.
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

    /// Run one quiet poll's timers on an established test-server connection
    /// and flush whatever they queue: loss probes, retransmits, closes.
    /// Callers re-check their own deadline afterwards.
    fn quic_server_idle(conn: &mut quiche::Connection, sock: &UdpSocket, out: &mut [u8]) {
        conn.on_timeout();
        while let Ok((written, info)) = conn.send(out) {
            sock.send_to(&out[..written], info.to).expect("answers");
        }
    }

    /// Accept one `QUIC` connection on a bound socket and drive it to
    /// established, answering every flight on the spot — plus the client's
    /// connection id, so the caller can tell that handshake's retransmits
    /// from a second handshake later.
    ///
    /// Short polls, not one long wait: `quiche` only retransmits our own
    /// handshake flight in `on_timeout`, so a server parked in a single
    /// `recv_from` never resends a lost flight and the client alone must
    /// repair it — or the handshake stalls past the dial's budget.
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
                // No flight to answer: run the timers instead, so a lost
                // server flight is retransmitted here rather than leaving the
                // client to repair it alone past its own budget.
                quic_server_idle(&mut conn, sock, &mut out);
            }
            assert!(
                std::time::Instant::now() < deadline,
                "client handshake stalls"
            );
        }
        (conn, peer_scid)
    }

    /// One `QUIC` peer for the loopback below: `quiche` accepting, the `VLESS`
    /// header byte-checked, `[0, 0]` answered, stream zero echoed to `fin`.
    ///
    /// Test-only on purpose: production serves no `QUIC`, so the peer lives
    /// beside the test rather than in the dial module — and a peer that is
    /// itself `quiche` is the differential reference, not a second copy of
    /// the code under test.
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
                .set_application_protos(&[b"h3".as_slice()])
                .expect("negotiates");
            // Same windows as the dial side: a bare config advertises zero
            // streams and the header send fails with `StreamLimit`.
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
                    // Same timers as the handshake above: a lost `[0, 0]`
                    // must be retransmitted here, not billed to the dial.
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
            conn.stream_send(0, &[0, 0], false).expect("accepts");
            while let Ok((written, info)) = conn.send(&mut out) {
                sock.send_to(&out[..written], info.to).expect("answers");
            }
            let echo_deadline = std::time::Instant::now() + QUIC_TEST_TIMEOUT;
            loop {
                if conn.is_closed() {
                    return;
                }
                let Some((n, from)) = quic_server_poll(&sock, &mut buf) else {
                    // Draining expires on a timer, not on packets: drive it
                    // every quiet poll, and leave when the close arrives — or
                    // when the bound lapses, returning rather than panicking,
                    // so a lost close cannot fail a test whose echoes landed.
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
                        conn.stream_send(0, &piece[..n], false).expect("echoes");
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

    /// Ferry every queued datagram between two `quiche` endpoints in-process:
    /// `a.send` bytes go straight into `b.recv` and back, until neither has
    /// anything queued. No sockets, no threads, no sleeps — a scheduling stall
    /// pauses the driver without tripping any timer, because timers only fire
    /// in `on_timeout`, and nothing here calls it mid-flight.
    fn quic_ferry(
        a: &mut quiche::Connection,
        a_addr: SocketAddr,
        b: &mut quiche::Connection,
        b_addr: SocketAddr,
    ) {
        let mut buf = [0u8; 1350];
        for _ in 0..1000 {
            let mut moved_any = false;
            while let Ok((n, _)) = a.send(&mut buf) {
                moved_any = true;
                let info = quiche::RecvInfo {
                    from: a_addr,
                    to: b_addr,
                };
                b.recv(&mut buf[..n], info).expect("ferries");
            }
            while let Ok((n, _)) = b.send(&mut buf) {
                moved_any = true;
                let info = quiche::RecvInfo {
                    from: b_addr,
                    to: a_addr,
                };
                a.recv(&mut buf[..n], info).expect("ferries");
            }
            if !moved_any {
                return;
            }
        }
        panic!("quic ferry made no progress");
    }

    /// An established `quiche` pair over an in-process pipe, plus the `VLESS`
    /// header the exchange below checks byte for byte.
    fn quic_pipe_endpoints() -> (
        quiche::Connection,
        quiche::Connection,
        SocketAddr,
        SocketAddr,
        Vec<u8>,
    ) {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let mut client_config = crate::quic::quiche_config(&roots).expect("configures");
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
            .set_application_protos(&[b"h3".as_slice()])
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
        for _ in 0..1000 {
            quic_ferry(&mut client, client_addr, &mut server, server_addr);
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());
        let header = vless_header(&id, 1, &target);
        (client, server, client_addr, server_addr, header)
    }

    /// One full `VLESS` stream over an established pipe pair: header out,
    /// byte-checked on the far end, `[0, 0]` back, payload echoed back.
    fn quic_pipe_exchange(
        client: &mut quiche::Connection,
        client_addr: SocketAddr,
        server: &mut quiche::Connection,
        server_addr: SocketAddr,
        stream: u64,
        header: &[u8],
        payload: &[u8],
    ) {
        client.stream_send(stream, header, false).expect("opens");
        let mut seen = Vec::new();
        let mut piece = [0u8; 8192];
        for _ in 0..1000 {
            quic_ferry(client, client_addr, server, server_addr);
            while let Ok((n, _)) = server.stream_recv(stream, &mut piece) {
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&piece[..n]);
            }
            if seen.len() >= header.len() {
                break;
            }
        }
        assert_eq!(seen, header);
        server.stream_send(stream, &[0, 0], false).expect("accepts");
        let mut back = Vec::new();
        for _ in 0..1000 {
            quic_ferry(client, client_addr, server, server_addr);
            while let Ok((n, _)) = client.stream_recv(stream, &mut piece) {
                if n == 0 {
                    break;
                }
                back.extend_from_slice(&piece[..n]);
            }
            if back.len() >= 2 {
                break;
            }
        }
        assert_eq!(back, [0, 0]);
        client.stream_send(stream, payload, false).expect("writes");
        let mut echo = Vec::new();
        for _ in 0..1000 {
            quic_ferry(client, client_addr, server, server_addr);
            while let Ok((n, _)) = server.stream_recv(stream, &mut piece) {
                if n == 0 {
                    break;
                }
                server
                    .stream_send(stream, &piece[..n], false)
                    .expect("echoes");
            }
            while let Ok((n, _)) = client.stream_recv(stream, &mut piece) {
                if n == 0 {
                    break;
                }
                echo.extend_from_slice(&piece[..n]);
            }
            if echo.len() >= payload.len() {
                break;
            }
        }
        assert_eq!(echo, payload);
    }

    /// `VLESS` over a `quiche` pipe: handshake, byte-exact header, `[0, 0]`,
    /// echo, `fin`, close — then both ends `is_closed`, with exactly one
    /// `on_timeout` call each to expire draining.
    ///
    /// Deterministic by construction (see [`quic_ferry`]): this is the proof
    /// the threaded loopback below cannot give on a stalled runner, and the
    /// threaded one is the proof this cannot give (threads, sockets, relay).
    #[test]
    fn quic_pipe_carries_vless_header_and_close() {
        let (mut client, mut server, client_addr, server_addr, header) = quic_pipe_endpoints();
        quic_pipe_exchange(
            &mut client,
            client_addr,
            &mut server,
            server_addr,
            0,
            &header,
            b"ping",
        );
        quic_pipe_exchange(
            &mut client,
            client_addr,
            &mut server,
            server_addr,
            4,
            &header,
            b"pong",
        );
        client.stream_send(0, &[], true).expect("ends");
        let _ = client.close(false, 0, b"done");
        // Draining expires on wall time, so this loop sleeps: ten thousand
        // millisecond rounds bound a hang without hurrying a stall — pausing
        // here only delays the verdict, it cannot trip any timer early,
        // because the only timer left is the draining one this is waiting out.
        for _ in 0..10_000 {
            quic_ferry(&mut client, client_addr, &mut server, server_addr);
            client.on_timeout();
            server.on_timeout();
            if client.is_closed() && server.is_closed() {
                // An idle death also closes: fail loudly rather than
                // passing on a stalled runner without proving anything.
                assert!(!client.is_timed_out() && !server.is_timed_out());
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("quic pipe never closed");
    }

    /// A `QUIC` peer that echoes every stream and counts connections: the
    /// sharing proof needs both numbers — one `UDP` association carrying two
    /// `VLESS` sessions, or the pool built two connections.
    ///
    /// Each new stream opens with the expected `VLESS` header and earns its
    /// `[0, 0]` before anything echoes: without that, a client talking to the
    /// wrong stream shape would pass by accident. Test-only like the
    /// single-stream peer above. An `Initial` with a never-seen source id is
    /// a second connection; one with the accepted handshake's id is its
    /// retransmit, which keeps arriving until our flight lands — counting
    /// packets instead of handshakes would fail the test for a stall the
    /// protocol survives.
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
                .set_application_protos(&[b"h3".as_slice()])
                .expect("negotiates");
            // Same idle as the dial side: the default would reap this peer
            // mid-stall while the test's own bounds still hold.
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
            // Source ids of handshakes already counted, starting with the
            // accepted one: its retransmits keep arriving until our flight
            // lands and must not count as new connections.
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
                    // Same timers as the handshake above: a lost echo must
                    // be retransmitted here, not billed to the dial.
                    quic_server_idle(&mut conn, &sock, &mut out);
                    // Past the bound the counts decide, not a panic: the
                    // echoes are asserted dial-side, and a lost close must
                    // not fail a test whose echoes all landed.
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
                        // One entry per client handshake, not per packet: the
                        // client retransmits its `Initial` until our flight
                        // lands, and a retransmit is not a second dial. Only
                        // a never-seen source id means the pool built a
                        // connection it should have shared — which is exactly
                        // what the final count asserts.
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
                            conn.stream_send(id, &[0, 0], false).expect("accepts");
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
                            conn.stream_send(id, &piece[..n], false).expect("echoes");
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

    /// `SOCKS` through a `VLESS`+`QUIC` outbound to a loopback echo.
    ///
    /// The true dial path end to end: `serve_socks` intercept plus `QuicDial`
    /// mapping, not the direct `quic::dial_pooled` the unit loopback drives —
    /// a swapped host or a dropped anchor set fails here and nowhere else.
    #[test]
    fn socks_dials_vless_quic_to_echo() {
        let _serial = quic_serial();
        quic_retry_dial(socks_quic_once, 3);
    }

    /// One `SOCKS`-fronted pass: fresh sockets, fresh identity.
    fn socks_quic_once() {
        let id = uuid_bytes("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").expect("id");
        // Named by the header only; the `QUIC` peer below echoes directly.
        let target: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let roots = crate::quic::parse_ca_pem(minted.cert.pem().as_bytes());
        assert_ne!(roots, Vec::<Vec<u8>>::new());
        let key_pem = crate::quic::der_to_pem(&minted.key_pair.serialize_der(), "PRIVATE KEY");
        let quic_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
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

    /// A `quic`+`tls` outbound carries its anchors from `caCertFile`.
    ///
    /// Without the gate change beside it this returns `None`: `tls` outbounds
    /// never reach a dial. Without anchors it returns the outbound with
    /// `quic_roots: None`, which the dial refuses rather than connecting
    /// blind — both shapes are asserted, not just the happy one.
    #[test]
    fn quic_outbound_reads_ca_cert_file() {
        let minted =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("mints");
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ferrox-quic-ca-{}-{stamp}.pem",
            std::process::id()
        ));
        std::fs::write(&path, minted.cert.pem().as_bytes()).expect("stages ca");
        let path_text = path.to_str().expect("ascii").to_owned();
        // Backslashes are JSON escapes: a `Windows` temporary path would
        // otherwise fail to parse before the lookup is even attempted.
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
    /// Gate for the socket `QUIC` dial tests below: each spins a server, a
    /// pump and relays with wall-clock budgets, and several such piles
    /// timesharing a small runner stretch each other past budgets that hold
    /// in isolation — the suite's own load reads as a network stall. Held
    /// for the whole test; poison is a previous failure, not a reason to
    /// skip, so it is ignored rather than asserted.
    static QUIC_DIAL_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Hold the dial gate, ignoring a previous holder's failure.
    fn quic_serial() -> std::sync::MutexGuard<'static, ()> {
        match QUIC_DIAL_SERIAL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Run one `QUIC` dial test past runner stalls: caught attempts, then the
    /// pass itself uncaught.
    ///
    /// The runner, not the code, is the flaky part here: a scheduling stall
    /// past a dial bound fails an attempt with no packet ever lost, and the
    /// next attempt starts from clean sockets because every `*_once` below
    /// mints fresh identity, binds fresh sockets, and evicts on failure. A
    /// real regression fails every attempt loudly, the last one uncaught.
    /// The sharing test below gets more attempts than the single-dial ones
    /// beside it: two dials must land in one healthy window, not one.
    fn quic_retry_dial(once: fn(), attempts: u32) {
        for _ in 0..attempts.saturating_sub(1) {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(once)).is_ok() {
                return;
            }
        }
        once();
    }

    /// `[0, 0]`, `ping` back through the relay threads, and every thread
    /// joined — the integration half of the pipe test above, with the same
    /// timeout exposure as every `TCP` loopback here and no more.
    #[test]
    fn quic_dials_loopback_echo() {
        let _serial = quic_serial();
        quic_retry_dial(quic_loopback_once, 3);
    }

    /// One loopback pass: fresh sockets, fresh identity.
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
        let quic_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
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

    /// Two `VLESS` streams over one pooled `QUIC` connection: the second dial
    /// finds the first dial's connection, never builds its own.
    ///
    /// Sequenced so sharing is structural, not racy: the first pong proves
    /// the connection is published while its stream is still open, so the
    /// second lookup cannot miss it — and the first `TCP` half stays open
    /// until both pongs are back, so eviction cannot steal it mid-test.
    #[test]
    fn quic_pool_shares_one_connection_between_two_streams() {
        let _serial = quic_serial();
        quic_retry_dial(quic_pool_once, 5);
    }

    /// Temporary diagnosis reader for the sharing test: on failure, panic
    /// with this attempt's server-port stages and their test-relative
    /// milliseconds, so they survive `cargo test` output capture. Removed
    /// with the stage log once attributed.
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

    /// One sharing pass: fresh sockets, fresh identity, both counts asserted.
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
        let quic_sock = UdpSocket::bind("127.0.0.1:0").expect("binds");
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
}

/// A `poll`-driven relay for Linux: the copy runs on a fixed set of workers instead of
/// two threads per connection.
///
/// # Why this exists
///
/// The plain relay used to be two blocking threads per connection, one per direction,
/// each sitting in a `splice` that sleeps until a socket has room. That measures at
/// CPU parity with `xray-core` at one connection and **1.35x worse** at sixteen
/// (`docs/methodology.md`), and the cause is not the copy. It is *how the copy waits*.
///
/// `xray-core` writes no splice loop at all: its relay is one call,
/// `tc.ReadFrom(readerConn)` at `proxy/proxy.go:775`, which hands the copy to the Go
/// runtime. In `internal/poll/splice_linux.go` the loop passes `spliceNonblock` to
/// **both** splices -- `spliceDrain` at line 100, `splicePump` at line 142 -- and on
/// `EAGAIN` calls `sock.pd.waitRead` / `waitWrite`, which park the **goroutine on the
/// runtime netpoller** (`fd_poll_runtime.go:88`). One `epoll_wait` therefore returns
/// *every* ready descriptor and one OS thread drains a batch of connections' worth.
///
/// A thread in a blocking `splice` gets none of that. Sixteen connections is
/// thirty-two threads on a four-vCPU runner, and each one's wait is a scheduler event
/// paid separately: sleep, wake, run, sleep. `threads` measures ferrox at 4 with one
/// connection and 34 with sixteen, against `xray-core`'s 8 and 9.
///
/// So the waits stop being one thread each and become one `poll` per worker covering
/// every flow it holds. `poll(2)` is level-triggered and returns **all** ready
/// descriptors in one call, which is the batching the netpoller provides, and it
/// carries none of `epoll`'s registration lifetime or `EPOLLHUP` sequencing. The fds
/// are polled only while the worker owns the flow, and a finished flow is dropped.
///
/// # Why `poll` and not `epoll`
///
/// The same shape would work with `epoll` and would scale better to many fds per
/// worker. It is not used here because `epoll_ctl`'s failure modes are registration
/// lifetime and stale-event ordering, and this relay has to be byte-exact with the
/// blocking path it replaces. `poll` has one failure mode -- an fd closed while
/// polled, which cannot happen when the worker owns the sockets -- and none of the
/// sequencing questions. If a relay ever holds enough flows per worker that `poll`'s
/// linear scan is the cost, that is the change to make, and it will be a change.
///
/// # Correctness
///
/// Per direction the state machine is: fill the pipe from the source until it is full
/// or the source has nothing, then push the pipe into the destination until it is empty
/// or the destination has no room. A direction ends when the source has reached EOF
/// **and** the pipe is empty, and only then is the destination's write half shut down --
/// the same order as the blocking `copy_all`, so a short write is still a retry and a
/// half-close is still after the last byte rather than before it. `splice(2)` is the
/// same call with `SPLICE_F_NONBLOCK` added, which changes only what a *full* socket
/// does: `EAGAIN` instead of a sleep.
#[cfg(target_os = "linux")]
mod poll_relay {
    use super::{Shutdown, SplicePipe, TcpStream};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock};

    /// `SPLICE_F_NONBLOCK`, from `<fcntl.h>`; `libc` does not export it.
    const SPLICE_F_NONBLOCK: libc::c_uint = 0x002;

    /// Whether the last `splice` failed for a reason that means "ask again later".
    ///
    /// `EAGAIN` and `EWOULDBLOCK` are the same value on Linux, so they are named once.
    /// A `matches!` listing both as separate alternatives is an unreachable arm, which
    /// is a lint about a portability problem that does not exist here.
    fn retryable() -> bool {
        matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR | libc::EAGAIN)
        )
    }

    /// One direction of one flow, as a worker holds it between `poll` calls.
    struct Direction {
        src: TcpStream,
        dst: TcpStream,
        /// `None` only where the kernel would not make a pipe at all, in which case
        /// this direction copies through a buffer on the worker -- the same fallback
        /// [`super::copy_all`] takes, reached by the same rare condition.
        pipe: Option<SplicePipe>,
        /// Bytes taken out of the source and not yet accepted by the destination.
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

        /// Move as far as the sockets allow, without ever sleeping.
        ///
        /// Every exit other than progress is a `poll` interest: the source while the
        /// pipe has room and no bytes, the destination while the pipe holds bytes it
        /// will not take.
        fn advance(&mut self) {
            if self.ended {
                return;
            }
            let Some(pipe) = self.pipe.as_ref() else {
                // No pipe, so no way to be woken: copy until one side stops, which is
                // the blocking path's own fallback and is rare enough to be worth not
                // writing a second state machine for it.
                super::copy_all_memcpy(&mut self.src, &mut self.dst);
                self.end();
                return;
            };
            let room = pipe.capacity - self.pending;
            if !self.src_at_eof && room > 0 {
                // SAFETY: both descriptors are live -- one owned by `self.src`, one
                // from `pipe` -- and `splice` reads neither. A null offset is what asks
                // for a pipe rather than a file, the only form with no offset to get
                // wrong. `SPLICE_F_NONBLOCK` is what turns a full socket into `EAGAIN`
                // rather than a sleep.
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
                    // The same end-of-file `copy_all` reads as `Ok(0)`.
                    self.src_at_eof = true;
                } else if !retryable() {
                    // Anything that is not "the socket was busy" or "a signal
                    // arrived" ends this direction, exactly as a failed `write` ends
                    // `copy_all`.
                    self.end();
                    return;
                }
            }
            while self.pending > 0 {
                // SAFETY: as above, with the count bounded by what the source put in.
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
                // A short write is a retry rather than a dropped tail, which is the same
                // job `SplicePipe::push`'s drain loop does for the blocking path.
                break;
            }
            // Only now, with nothing left in the pipe, is the half-close correct.
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

    /// Both directions of one connection, kept together so one `poll` can see both.
    struct Flow {
        directions: Vec<Direction>,
    }

    impl Flow {
        fn finished(&self) -> bool {
            self.directions.iter().all(|d| d.ended)
        }
    }

    /// One worker: a private queue, a wake-up pipe, and the loop that drains it.
    struct Worker {
        queue: Mutex<Vec<Flow>>,
        /// Read end polled alongside the flows, write end used to add one.
        wake: [libc::c_int; 2],
    }

    impl Worker {
        fn spawn() -> Option<Arc<Self>> {
            let mut wake = [-1; 2];
            // SAFETY: `wake` is a two-element array, which is what `pipe` writes, and
            // it is live for the call.
            if unsafe { libc::pipe(wake.as_mut_ptr()) } != 0 {
                return None;
            }
            // `pipe2` would fold these into the one call, but `libc` exports
            // `SYS_pipe2` on only some of the targets this builds for, and three
            // syscalls once per process is not worth a hand-built argument list.
            for (fd, flags) in [
                // `O_NONBLOCK` on the read end is what lets `drain_wake` finish
                // instead of blocking on a pipe nobody writes to again.
                (wake[0], libc::O_NONBLOCK),
                // `O_CLOEXEC` on the write end so a relay that execs cannot hand a
                // later process a descriptor whose reader is a relay worker.
                (wake[1], libc::O_CLOEXEC | libc::O_NONBLOCK),
            ] {
                // SAFETY: `fd` is live and came from the `pipe` above; `F_SETFL` sets
                // descriptor flags and neither closes nor reads through it.
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
            // One byte, and `EAGAIN` is fine: the pipe is already readable, which is
            // all the byte was for.
            let byte = 1u8;
            // SAFETY: `wake[1]` is live and came from the `pipe` above; `write` neither
            // reads through the descriptor nor closes it.
            unsafe {
                libc::write(self.wake[1], std::ptr::addr_of!(byte).cast(), 1);
            }
        }

        /// Take everything waiting, without holding the lock across any I/O.
        fn take(&self) -> Vec<Flow> {
            let mut queue = match self.queue.lock() {
                Ok(queue) => queue,
                // A poisoned queue means a worker panicked while holding it. The flows
                // in it are gone from the caller's point of view either way, and a
                // proxy that stops relaying is worse than one that loses a flow.
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *queue)
        }

        fn drain_wake(&self) {
            let mut scratch = [0u8; 64];
            loop {
                // SAFETY: reads at most `scratch.len()` bytes from a live non-blocking
                // descriptor into a live buffer.
                let got =
                    unsafe { libc::read(self.wake[0], scratch.as_mut_ptr().cast(), scratch.len()) };
                if got <= 0 {
                    return;
                }
            }
        }
    }

    /// Runs one worker until the process ends.
    ///
    /// Blocking in `poll` is the point: it is the single call that returns every ready
    /// descriptor this worker owns, which is the property a blocking `splice` per
    /// direction cannot have.
    fn run(worker: &Worker) {
        let mut flows: Vec<Flow> = Vec::new();
        let mut pfds: Vec<libc::pollfd> = Vec::with_capacity(64);
        // `poll` answers positionally, so this says whose descriptor each answer is
        // about. `usize::MAX` marks the wake pipe.
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
                    // Interest only where there is something to do: the source while
                    // the pipe has room, the destination while the pipe holds bytes. A
                    // `POLLOUT` asked for with an empty pipe is the classic way an
                    // event loop spins.
                    // A direction with no pipe has no destination to be woken about --
                    // `advance` copies it through a buffer and ends it in one go -- so
                    // `POLLIN` alone is the interest it needs. Asking it for room in a
                    // pipe it does not have means no interest at all, and a direction
                    // with no interest is never advanced, so the caller waits forever on
                    // a channel nothing will signal.
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
            // SAFETY: `pfds` is live, non-empty, and its length is what is passed.
            // `poll` writes only `revents`.
            let answered = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, -1) };
            if answered < 0 {
                // `EINTR` is a signal and nothing else. Any other failure leaves the
                // loop to try again, and `poll` on a valid set does not fail in a loop.
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
        // One worker per logical CPU, capped: the point is to batch many flows onto few
        // threads, and past the core count extra threads only split the batches.
        match std::thread::available_parallelism() {
            Ok(count) => count.get().min(8),
            // One worker is still a correct relay, just a less parallel one.
            Err(_) => 1,
        }
    }

    /// Empty when no worker could be made, which is the signal to use the blocking
    /// relay rather than a half-working one.
    fn workers() -> &'static Vec<Arc<Worker>> {
        static WORKERS: OnceLock<Vec<Arc<Worker>>> = OnceLock::new();
        WORKERS.get_or_init(|| {
            (0..worker_count())
                .filter_map(|_| Worker::spawn())
                .collect()
        })
    }

    /// Which worker takes the next flow.
    ///
    /// Round-robin rather than one shared queue: a shared queue hands every flow to
    /// whichever worker looks first, which in a connection storm means one worker adopts
    /// all of them while the rest idle -- trading a scheduler problem for a load-balance
    /// one. A worker's queue is only ever its own, so the distribution is by
    /// construction and cannot collapse.
    fn next() -> &'static Worker {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let all = workers();
        let index = NEXT.fetch_add(1, Ordering::Relaxed) % all.len();
        &all[index]
    }

    /// Whether there are workers at all.
    ///
    /// `false` only where the kernel would not make a wake pipe, and then the caller
    /// runs the blocking relay: that path is the pre-existing one, so the fallback is
    /// not new behaviour, it is the old behaviour.
    pub(super) fn available() -> bool {
        !workers().is_empty()
    }

    /// Relay both directions of one connection, and return when both have ended.
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
        // Both, not just the first: this caller owns these sockets' lifetime, and a
        // direction still running after it returned would be a relay writing into
        // dropped descriptors. `recv` cannot fail while `Direction::end` holds a
        // sender, and every path out of `advance` goes through `end`.
        let _ = first_rx.recv();
        let _ = second_rx.recv();
    }
}

// The contract these tests hold `relay` to, rather than the `poll` loop's internals: both
// directions are relayed, the source's end-of-file is forwarded as a write half-close,
// and `relay` returns when both directions have ended. That contract is the same on
// every platform -- the `poll` workers on Linux, a thread pair elsewhere -- so these
// tests are not gated to Linux. Gating them is how the first version of this module hung
// CI for ten minutes: nothing outside Linux ever compiled it, and a test that has never
// run is not a test.
//
// # The wiring, which is the whole difficulty
//
// `relay(client, target)` moves bytes *from* `client` *to* `target`, and returns only
// when both directions have ended. So a test needs four things, and getting any one of
// them wrong is a hang rather than a failure:
//
//   - one listener per side, or the two accepted sockets swap roles by accept order and
//     the assertion fails at random;
//   - the client's far end must *send* the payload and then close its write half -- it is
//     the relay's source, and the relay only ever reads from it;
//   - the target's far end must close once it has read, or the reverse direction never
//     ends and `relay` never returns;
//   - the relay must run on a thread of its own, because the writes that end the forward
//     direction happen after `relay` has started.
#[cfg(test)]
mod relay_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    /// How long a peer waits before giving up on the other side.
    ///
    /// A test that hangs is worse than one that fails: it costs a CI job's whole budget
    /// and says nothing about what went wrong. Set on the far ends, because those are
    /// the sockets whose reads decide whether the test finishes.
    const PATIENCE: Duration = Duration::from_secs(30);

    /// What the client's far end sends, and what the target's far end sends back.
    const REQUEST: &[u8] = b"both ways at once";
    const REPLY: &[u8] = b"and back";

    /// Read to end-of-file, returning what arrived.
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

    /// A listener bound to the loopback, with the port it landed on.
    fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").expect("binds")
    }

    fn port_of(listener: &TcpListener) -> u16 {
        listener.local_addr().expect("addr").port()
    }

    /// Relay `payload` through [`relay`] and return what the target's far end received.
    fn relayed(payload: Vec<u8>) -> Vec<u8> {
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        // The client's far end: the relay reads from the client, so this is what has to
        // send. The write half-close is what ends the forward direction.
        let front_far = thread::spawn(move || {
            let (mut stream, _) = front.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            stream.write_all(&payload).expect("writes");
            let _ = stream.shutdown(Shutdown::Write);
            read_all(&mut stream);
        });
        // The target's far end: reads to end-of-file, and the drop that follows is what
        // ends the reverse direction.
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

    /// Every length survives, including the ones either side of a chunk boundary.
    ///
    /// The dangerous shapes for a non-blocking copy are a lost tail when the destination
    /// has no room and a half-close before the last byte, and both show up as a length
    /// mismatch rather than as a crash -- so the lengths around 4 KiB, 64 KiB and 256 KiB
    /// matter more than a round number.
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

    /// One flow carries both directions, and the reply survives the half-close.
    ///
    /// The client sends, shuts its write half down, and only then reads. That order is
    /// the test: the half-close ends the forward direction, and a relay that took it for
    /// the end of the flow would shut both halves of the client's socket -- which cuts
    /// the reply off before the client can see it. So the client must still get its
    /// answer, and the target must have received every byte on the way there.
    #[test]
    fn one_flow_carries_both_directions() {
        let front = listener();
        let front_port = port_of(&front);
        let back = listener();
        let back_port = port_of(&back);
        // The client's far end: sends, half-closes, and then reads. That order is the
        // test -- the reply has to arrive on a socket whose write half is already shut.
        let front_far = thread::spawn(move || {
            let (mut stream, _) = front.accept().expect("accepts");
            stream.set_read_timeout(Some(PATIENCE)).expect("timeout");
            stream.write_all(REQUEST).expect("writes");
            let _ = stream.shutdown(Shutdown::Write);
            read_all(&mut stream)
        });
        // The target's far end: reads to end-of-file -- which is the client's half-close
        // arriving at the far side -- and only *then* answers. A relay that took that
        // half-close for the end of the flow would never deliver this reply, which is the
        // whole thing being tested.
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

    /// Several flows at once, which is the only arrangement that exercises batching.
    ///
    /// The single-flow tests above would pass a loop that still handed every flow its own
    /// thread; what they cannot see is whether the *shared* poll is doing the work it
    /// exists to do. Sixteen concurrent flows through one worker set is the shape gate 5
    /// measures, and it is here so a byte-level regression in the batching arrives as a
    /// failing test rather than as a benchmark number nobody trusts.
    ///
    /// Every payload is the same length, so which flow arrives in which order is not
    /// something this checks. What it checks is that all sixteen arrive whole.
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
        // Taken before the payloads are moved, so the comparison is against the length
        // this test decided on rather than against whatever the senders were handed.
        let wanted = vec![LEN; FLOWS];

        // The client's far ends: each accepts one flow's client socket, sends that flow's
        // payload, and closes the write half. The sockets are held until every flow has
        // been fed, so the relay is never asked to write into a peer that has gone away.
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
        // The target's far ends, read one flow at a time to end-of-file and then dropped.
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
