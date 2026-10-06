//! `shadowsocks` chunk transport over `TCP` and datagrams over `UDP`, both roles.
//!
//! Salt first, then length-prefixed sealed chunks; the target address rides in
//! the first chunk. Over `UDP` each datagram is its own salt plus one sealed
//! address-and-payload chunk. The cipher table, the key derivation and the
//! per-chunk `AEAD` are [`ferrox_core::shadowsocks`]'s, which is where the
//! bit-identity proofs are; what is left here is the socket half, the address
//! header and the relay.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::thread;
use std::time::Duration;

use ferrox_core::shadowsocks::{Cipher, MasterKey, Method, LENGTH_LEN, MAX_CHUNK, TAG_LEN};

use crate::proxy::{push_addr, read_exact, RELAY_POLL, UDP_BUF};

/// Largest salt on the wire; each method sends its key length (16 for
/// `aes-128-gcm`, 32 for the other two), which is what Xray-core's per-method
/// `IVBytes` says and what the oracle's `aes-256-gcm` row checks.
const SALT_LEN: usize = 32;
/// Largest plaintext read per relay turn.
const READ_CHUNK: usize = 0x4000;

/// Serve one `shadowsocks` connection: salt, address chunk, dial, relay sealed.
pub(crate) fn serve(mut stream: TcpStream, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let master = MasterKey::new(password, method.key_len());
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    if read_exact(&mut stream, &mut salt[..salt_len]).is_err() {
        return;
    }
    let Some(mut recv) = Cipher::from_master_key(method, &master, &salt[..salt_len]) else {
        return;
    };
    let mut first = Vec::with_capacity(MAX_CHUNK + TAG_LEN);
    let Some(first) = open_chunk(&mut stream, &mut recv, &mut first) else {
        return;
    };
    let Some((target, used)) = parse_addr_header(first) else {
        return;
    };
    let Ok(mut uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if uplink.write_all(&first[used..]).is_err() {
        return;
    }
    let mut salt = [0u8; SALT_LEN];
    if getrandom::getrandom(&mut salt[..salt_len]).is_err() {
        return;
    }
    let Some(send) = Cipher::from_master_key(method, &master, &salt[..salt_len]) else {
        return;
    };
    if stream.write_all(&salt[..salt_len]).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, send, Recv::Ready(recv));
}

/// Serve one `shadowsocks` connection inside `WebSocket` messages.
pub(crate) fn serve_ws(stream: TcpStream, password: &str, method: &str, path: &str, freedom: bool) {
    let Some((mut reader, mut writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Serve one `shadowsocks` connection past the `HTTPUpgrade` `101`.
pub(crate) fn serve_httpupgrade(
    stream: TcpStream,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::httpupgrade::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Serve one `shadowsocks` connection inside a `gRPC` tunnel.
pub(crate) fn serve_grpc(
    stream: TcpStream,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::grpc::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Serve one `shadowsocks` connection inside `XHTTP` chunks.
pub(crate) fn serve_xhttp(
    stream: TcpStream,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Serve one `shadowsocks` connection past the camouflage `GET`.
pub(crate) fn serve_httpheader(
    stream: TcpStream,
    password: &str,
    method: &str,
    path: &str,
    freedom: bool,
) {
    let Some((mut reader, mut writer)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((uplink, send, recv)) = accept_on(&mut reader, &mut writer, password, method, freedom)
    else {
        return;
    };
    let Ok(closer) = writer.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Read one handshake off any byte stream: salt, sealed address, dial, answer salt.
fn accept_on(
    reader: &mut dyn Read,
    writer: &mut dyn Write,
    password: &str,
    method: &str,
    freedom: bool,
) -> Option<(TcpStream, Cipher, Recv)> {
    let method = Method::parse(method)?;
    if !freedom {
        return None;
    }
    let master = MasterKey::new(password, method.key_len());
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    read_exact(reader, &mut salt[..salt_len]).ok()?;
    let mut recv = Cipher::from_master_key(method, &master, &salt[..salt_len])?;
    let mut first = Vec::with_capacity(MAX_CHUNK + TAG_LEN);
    let first = open_chunk(reader, &mut recv, &mut first)?;
    let (target, used) = parse_addr_header(first)?;
    let mut uplink = TcpStream::connect_timeout(&target, Duration::from_secs(8)).ok()?;
    uplink.write_all(&first[used..]).ok()?;
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt[..salt_len]).ok()?;
    let send = Cipher::from_master_key(method, &master, &salt[..salt_len])?;
    writer.write_all(&salt[..salt_len]).ok()?;
    Some((uplink, send, Recv::Ready(recv)))
}

/// Dial a `shadowsocks` server for a target: salt and sealed address, no waiting.
pub(crate) fn client_send_handshake(
    uplink: &mut dyn Write,
    password: &str,
    method: &str,
    target: &SocketAddr,
) -> Option<(Cipher, Recv)> {
    let method = Method::parse(method)?;
    let master = MasterKey::new(password, method.key_len());
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt[..salt_len]).ok()?;
    uplink.write_all(&salt[..salt_len]).ok()?;
    let mut send = Cipher::from_master_key(method, &master, &salt[..salt_len])?;
    let mut addr = Vec::with_capacity(20);
    push_addr(&mut addr, target, 4);
    addr.extend_from_slice(&target.port().to_be_bytes());
    let mut staging = Vec::with_capacity(addr.len());
    seal_all(&mut send, &addr, &mut staging, uplink).ok()?;
    Some((send, Recv::Waiting(method, master)))
}

/// Receive cipher: ready, or still waiting on the peer's salt.
pub(crate) enum Recv {
    /// Salt read, cipher derived; unboxed, since the schedules inside are already.
    Ready(Cipher),
    /// Salt unread; the method and the master key to derive it from on arrival.
    Waiting(Method, MasterKey),
}

/// Relay plaintext one side against sealed chunks the other, both ways to close.
pub(crate) fn pump_relay(plain: &TcpStream, sealed: &TcpStream, send: Cipher, recv: Recv) {
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(closer) = sealed.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(plain, sealed_read, sealed_write, &close, send, recv);
}

/// Relay plaintext against sealed chunks where the sealed side is a carrier.
pub(crate) fn pump_relay_carried<R, W>(
    plain: &TcpStream,
    mut reader: R,
    mut writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Cipher,
    recv: Recv,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut plain_write = plain_write;
    let mut send = send;
    let thread_close = std::sync::Arc::clone(close);
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; READ_CHUNK];
        let mut staging = Vec::with_capacity(MAX_CHUNK);
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                break;
            }
            if seal_all(&mut send, &buf[..read], &mut staging, &mut writer).is_err() {
                break;
            }
        }
        thread_close();
        let _ = plain_read.shutdown(Shutdown::Both);
    });
    let mut recv = match recv {
        Recv::Ready(cipher) => cipher,
        Recv::Waiting(method, master) => {
            let salt_len = method.key_len();
            let mut peer = [0u8; SALT_LEN];
            if read_exact(&mut reader, &mut peer[..salt_len]).is_err() {
                return;
            }
            let Some(cipher) = Cipher::from_master_key(method, &master, &peer[..salt_len]) else {
                return;
            };
            cipher
        }
    };
    let mut chunk = Vec::with_capacity(MAX_CHUNK + TAG_LEN);
    while let Some(payload) = open_chunk(&mut reader, &mut recv, &mut chunk) {
        if plain_write.write_all(payload).is_err() {
            break;
        }
    }
    close();
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// Serve `shadowsocks` datagrams on an address: open each packet, forward its
/// payload where it says, seal every reply back to its client.
///
/// Two sockets like the direction split in [`pump_relay`]: one bound here
/// talks to clients only, one ephemeral talks to targets only, so replies and
/// requests never need demultiplexing. Replies map to clients by target, last
/// writer wins; the table is bounded because a legitimate client re-establishes
/// its entry on its next datagram. Both sockets poll on [`RELAY_POLL`]
/// windows, which costs idle wakeups per inbound rather than per flow.
pub(crate) fn serve_udp(address: &str, password: &str, method: &str, freedom: bool) {
    let Ok(clients) = UdpSocket::bind(address) else {
        return;
    };
    serve_udp_on(&clients, password, method, freedom);
}

/// [`serve_udp`] on a socket the caller has already bound.
///
/// The bind belongs to the caller so that a caller who needs to know the port can
/// read it off the socket instead of guessing one: a server that binds `:0` in
/// here has no way to tell anyone, and a caller that picks a port and asks for it
/// to be bound later is in a race with every other socket in the process. It also
/// makes the one failure that matters visible instead of silent. Every early
/// return in this body is a `return` with nothing said, so a `serve_udp` whose
/// bind failed was indistinguishable from a client that never answered -- which is
/// exactly what `shadowsocks_udp_reaches_echo` reported on `windows x86_64` after
/// the `QUIC` dial landed: fifteen retries, each failing in milliseconds because
/// the port nothing was listening on answered with `ICMP port unreachable`, and
/// on Windows that error poisons the sending socket for every later read.
pub(crate) fn serve_udp_on(clients: &UdpSocket, password: &str, method: &str, freedom: bool) {
    let Some(method) = Method::parse(method) else {
        return;
    };
    if !freedom {
        return;
    }
    let master = MasterKey::new(password, method.key_len());
    let Ok(upstream) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    let upstream6 = UdpSocket::bind("[::]:0").ok();
    for sock in [clients, &upstream].into_iter().chain(upstream6.as_ref()) {
        if sock.set_read_timeout(Some(RELAY_POLL)).is_err() {
            return;
        }
    }
    let mut table: HashMap<SocketAddr, SocketAddr> = HashMap::new();
    let mut buf = vec![0u8; UDP_BUF];
    let mut reply = vec![0u8; UDP_BUF];
    loop {
        match clients.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some((dest, payload)) = open_udp_datagram(&master, method, &buf[..n]) {
                    if table.len() >= 4096 {
                        table.clear();
                    }
                    table.insert(dest, src);
                    if dest.is_ipv6() {
                        if let Some(sock) = &upstream6 {
                            let _ = sock.send_to(&payload, dest);
                        }
                    } else {
                        let _ = upstream.send_to(&payload, dest);
                    }
                }
            }
            Err(error) if crate::proxy::is_timeout(&error) => {}
            Err(_) => break,
        }
        for sock in [&upstream].into_iter().chain(upstream6.as_ref()) {
            while let Ok((n, src)) = sock.recv_from(&mut reply) {
                if let Some(client) = table.get(&src) {
                    if let Some(packet) = seal_udp_datagram(&master, method, &src, &reply[..n]) {
                        let _ = clients.send_to(&packet, client);
                    }
                }
            }
        }
    }
}

/// Seal every `MAX_CHUNK` slice of plaintext into length-plus-payload chunks.
fn seal_all(
    send: &mut Cipher,
    plain: &[u8],
    staging: &mut Vec<u8>,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    for chunk in plain.chunks(MAX_CHUNK) {
        let length = (chunk.len() as u16).to_be_bytes();
        seal_into(send, &length, staging, out)?;
        seal_into(send, chunk, staging, out)?;
    }
    Ok(())
}

/// Seal one plaintext slice plus its tag onto the stream, staging through the
/// caller's buffer: the old per-chunk `to_vec` allocated and copied every
/// chunk on the way out, and `staging` is already warm after the first one.
///
/// The sixteen tag bytes ride behind the ciphertext in the same write — one
/// `write_all` where there were two, same bytes in the same order, so a peer
/// reading length-plus-tag and body-plus-tag off the byte stream cannot tell.
fn seal_into(
    send: &mut Cipher,
    plain: &[u8],
    staging: &mut Vec<u8>,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    staging.clear();
    if send.seal_into(plain, staging).is_none() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    out.write_all(staging)?;
    Ok(())
}

/// Open one length-plus-payload chunk pair into the caller's buffer.
///
/// Returns the plaintext borrowed from `chunk`: a function handing back `&'a [u8]`
/// tied to `&'a mut Vec<u8>` cannot also have copied it somewhere, because there
/// is nowhere to return it from. The length prefix rides on the stack; `chunk`
/// is resized, never reallocated, so only growth past its high-water mark memsets.
fn open_chunk<'a>(
    stream: &mut dyn Read,
    recv: &mut Cipher,
    chunk: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    use crate::proxy::read_exact;
    let mut length = [0u8; LENGTH_LEN + TAG_LEN];
    read_exact(stream, &mut length).ok()?;
    if open_into(recv, &mut length)? != LENGTH_LEN {
        return None;
    }
    let size = usize::from(u16::from_be_bytes([length[0], length[1]]));
    if size > MAX_CHUNK {
        return None;
    }
    chunk.resize(size + TAG_LEN, 0);
    read_exact(stream, chunk).ok()?;
    let plain = open_into(recv, chunk)?;
    Some(&chunk[..plain])
}

/// Decrypt one sealed buffer in place, returning the plaintext length.
///
/// The plaintext is the buffer's own prefix; returning its length instead of a
/// fresh `Vec` removes one allocation and one copy per chunk.
fn open_into(recv: &mut Cipher, chunk: &mut [u8]) -> Option<usize> {
    recv.open_in_place(chunk)
}

/// Seal one `UDP` datagram: fresh salt plus the address and payload sealed
/// under it as a single chunk.
///
/// A fresh salt per datagram means the nonce starts at zero every time, which
/// is what makes the zero nonce safe: no key-nonce pair ever repeats. Same
/// bytes as Xray-core's `EncodeUDPPacket`, down to the salt lengths.
pub(crate) fn seal_udp_datagram(
    master: &MasterKey,
    method: Method,
    dest: &SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let salt_len = method.key_len();
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt[..salt_len]).ok()?;
    let mut cipher = Cipher::from_master_key(method, master, &salt[..salt_len])?;
    let mut addr = Vec::with_capacity(20);
    push_addr(&mut addr, dest, 4);
    addr.extend_from_slice(&dest.port().to_be_bytes());
    let mut plain = Vec::with_capacity(addr.len() + payload.len());
    plain.extend_from_slice(&addr);
    plain.extend_from_slice(payload);
    let mut out = Vec::with_capacity(salt_len + plain.len() + TAG_LEN);
    out.extend_from_slice(&salt[..salt_len]);
    cipher.seal_into(&plain, &mut out)?;
    Some(out)
}

/// Open one `UDP` datagram into destination and payload.
///
/// Salt length follows the method like everywhere else here; anything shorter
/// than salt plus tag, or with a tag that does not match, is dropped rather
/// than answered, so a scanner learns nothing per probe.
pub(crate) fn open_udp_datagram(
    master: &MasterKey,
    method: Method,
    packet: &[u8],
) -> Option<(SocketAddr, Vec<u8>)> {
    let salt_len = method.key_len();
    if packet.len() < salt_len + TAG_LEN + 1 {
        return None;
    }
    let mut cipher = Cipher::from_master_key(method, master, &packet[..salt_len])?;
    let mut sealed = packet[salt_len..].to_vec();
    let len = cipher.open_in_place(&mut sealed)?;
    let (target, used) = parse_addr_header(&sealed[..len])?;
    Some((target, sealed[used..len].to_vec()))
}

/// Parse a `SOCKS`-order address header, returning the target and bytes used.
fn parse_addr_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    let &atyp = buf.first()?;
    match atyp {
        1 => {
            if buf.len() < 7 {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&buf[1..5]);
            let mut port = [0u8; 2];
            port.copy_from_slice(&buf[5..7]);
            Some((
                SocketAddr::new(std::net::IpAddr::V4(ip.into()), u16::from_be_bytes(port)),
                7,
            ))
        }
        4 => {
            if buf.len() < 19 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[1..17]);
            let mut port = [0u8; 2];
            port.copy_from_slice(&buf[17..19]);
            Some((
                SocketAddr::new(std::net::IpAddr::V6(ip.into()), u16::from_be_bytes(port)),
                19,
            ))
        }
        3 => {
            let len = usize::from(*buf.get(1)?);
            if len == 0 || buf.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&buf[2..2 + len]).ok()?;
            let mut port = [0u8; 2];
            port.copy_from_slice(&buf[2 + len..4 + len]);
            let target = format!("{host}:{}", u16::from_be_bytes(port))
                .to_socket_addrs()
                .ok()?
                .next()?;
            Some((target, 4 + len))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every method this rung names, with the spellings a real `ss://` link uses.
    fn methods() -> [(&'static str, Method); 8] {
        [
            ("aes-128-gcm", Method::Aes128Gcm),
            ("aead_aes_128_gcm", Method::Aes128Gcm),
            ("aes-256-gcm", Method::Aes256Gcm),
            ("aead_aes_256_gcm", Method::Aes256Gcm),
            ("chacha20-ietf-poly1305", Method::Chacha20Poly1305),
            ("aead_chacha20_poly1305", Method::Chacha20Poly1305),
            ("chacha20-poly1305", Method::Chacha20Poly1305),
            ("AES-256-GCM", Method::Aes256Gcm),
        ]
    }

    /// The application's own framing — length sealed as a chunk of its own, then
    /// the payload — for every method and every spelling, over a real socket.
    ///
    /// This is the row the cipher table exists for: a `serve` that used to compare
    /// the `method=` string against `"aes-256-gcm"` and close the connection on
    /// anything else now carries a `ping` for all three. The bytes themselves are
    /// `ferrox_core::shadowsocks`'s business and are proved there.
    #[test]
    fn every_named_method_and_spelling_relays_an_echo() {
        for (name, method) in methods() {
            let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
            let echo_port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                let (mut stream, _) = echo.accept().expect("accepts");
                let mut buf = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buf) {
                    if read == 0 || stream.write_all(&buf[..read]).is_err() {
                        return;
                    }
                }
            });
            let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            let announced = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let announced = announced.clone();
                    thread::spawn(move || {
                        serve(stream, "an-example-shared-password", &announced, true);
                    });
                }
            });
            let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .expect("timeout");
            let Some((mut send, recv)) =
                client_send_handshake(&mut uplink, "an-example-shared-password", name, &target)
            else {
                panic!("{name}: handshake refused");
            };
            assert_eq!(send.method(), method, "{name}: and it is the named one");
            seal_all(&mut send, b"ping", &mut Vec::new(), &mut uplink).expect("seals");
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(_, master) => {
                    let salt_len = method.key_len();
                    let mut peer = [0u8; SALT_LEN];
                    read_exact(&mut uplink, &mut peer[..salt_len]).expect("salt");
                    Cipher::from_master_key(method, &master, &peer[..salt_len]).expect("derives")
                }
            };
            let mut buf = Vec::with_capacity(MAX_CHUNK + TAG_LEN);
            let back = open_chunk(&mut uplink, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..], "{name}");
        }
    }

    /// A method this rung does not name is still refused, and refused by closing
    /// rather than by relaying: the neighbours are in the matrix and this rung's
    /// boundary is a decision, not an accident.
    #[test]
    fn a_method_outside_the_rung_is_refused() {
        for name in [
            "aes-192-gcm",
            "xchacha20-ietf-poly1305",
            "2022-blake3-aes-256-gcm",
            "rc4-md5",
            "none",
            "",
        ] {
            let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = server.local_addr().expect("addr").port();
            let refused = name.to_owned();
            thread::spawn(move || {
                for stream in server.incoming().take(1) {
                    let Ok(stream) = stream else { continue };
                    let refused = refused.clone();
                    thread::spawn(move || {
                        serve(stream, "an-example-shared-password", &refused, true);
                    });
                }
            });
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            uplink
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .expect("timeout");
            let target: SocketAddr = "127.0.0.1:1".parse().expect("addr");
            assert!(
                client_send_handshake(&mut uplink, "an-example-shared-password", name, &target)
                    .is_none(),
                "{name}: refused"
            );
        }
    }

    /// Every carrier this rung names relays an echo both ways over loopback.
    ///
    /// The framing is [`ferrox_core::shadowsocks`]'s business and is proved
    /// there; what this proves is the plumbing: the salt and the sealed chunks
    /// are the same bytes through `ws` messages, the `httpupgrade` `101`,
    /// `gRPC` `Hunk` envelopes and `xhttp` chunks as through raw `TCP`.
    #[test]
    fn carried_transports_relay_an_echo() {
        fn echo() -> u16 {
            let echo = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = echo.local_addr().expect("addr").port();
            thread::spawn(move || {
                for stream in echo.incoming() {
                    let Ok(mut stream) = stream else {
                        continue;
                    };
                    thread::spawn(move || {
                        let mut buf = [0u8; 1024];
                        while let Ok(read) = stream.read(&mut buf) {
                            if read == 0 || stream.write_all(&buf[..read]).is_err() {
                                return;
                            }
                        }
                    });
                }
            });
            port
        }
        fn round_trip(reader: &mut dyn Read, writer: &mut dyn Write, target: &SocketAddr) {
            let Some((mut send, recv)) =
                client_send_handshake(writer, "an-example-shared-password", "aes-256-gcm", target)
            else {
                panic!("handshake refused");
            };
            let mut recv = match recv {
                Recv::Ready(cipher) => cipher,
                Recv::Waiting(_, master) => {
                    let mut peer = [0u8; SALT_LEN];
                    read_exact(reader, &mut peer).expect("salt");
                    Cipher::from_master_key(Method::Aes256Gcm, &master, &peer).expect("derives")
                }
            };
            seal_all(&mut send, b"ping", &mut Vec::new(), writer).expect("seals");
            let mut buf = Vec::with_capacity(MAX_CHUNK + TAG_LEN);
            let back = open_chunk(reader, &mut recv, &mut buf).expect("opens");
            assert_eq!(back, &b"ping"[..]);
        }
        let password = "an-example-shared-password";
        let method = "aes-256-gcm";
        let echo_port = echo();
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_ws(stream, password, method, "/ss-ws", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::ws::connect(stream, "127.0.0.1", "/ss-ws", 0, &[]).expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_httpupgrade(stream, password, method, "/ss-upgrade", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::httpupgrade::connect(stream, "127.0.0.1", "/ss-upgrade").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_grpc(stream, password, method, "/TunnelService/Tun", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::grpc::connect(stream, "127.0.0.1", "/TunnelService/Tun").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_xhttp(stream, password, method, "/ss-xhttp", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::xhttp::connect(stream, "127.0.0.1", "/ss-xhttp").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            serve_httpheader(stream, password, method, "/ss-camouflage", true);
        });
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::httpheader::connect(stream, "127.0.0.1", "/ss-camouflage").expect("carries");
        round_trip(&mut reader, &mut writer, &target);
    }

    /// The framing's own round trip: the length is sealed as a chunk of its own,
    /// then the payload, and a damaged chunk never reaches the caller.
    #[test]
    fn chunks_open_that_seal_sealed_and_reject_damage() {
        let salt = [7u8; SALT_LEN];
        let method = Method::Aes256Gcm;
        let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut wire = Vec::new();
        let mut staging = Vec::with_capacity(64);
        seal_all(&mut send, b"length-is-framing", &mut staging, &mut wire).expect("seals");
        let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        let mut cursor = std::io::Cursor::new(&wire);
        let mut buf = Vec::with_capacity(MAX_CHUNK + TAG_LEN);
        let back = open_chunk(&mut cursor, &mut recv, &mut buf).expect("opens");
        assert_eq!(back, &b"length-is-framing"[..]);

        let mut tampered = wire.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut damaged = std::io::Cursor::new(&tampered);
        let mut fresh = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
        assert!(open_chunk(&mut damaged, &mut fresh, &mut Vec::new()).is_none());
    }

    /// Salt sizes follow the method: 16 for `aes-128-gcm`, 32 below, on sends
    /// and receives alike, which is what the oracle checks for `aes-256-gcm`
    /// and what Xray-core's per-method `IVBytes` says for the rest.
    #[test]
    fn udp_salts_follow_the_method() {
        for (name, salt_len) in [
            ("aes-128-gcm", 16),
            ("aes-256-gcm", 32),
            ("chacha20-ietf-poly1305", 32),
        ] {
            let method = Method::parse(name).expect("names");
            assert_eq!(method.key_len(), salt_len, "{name}");
            let master = MasterKey::new("an-example-shared-password", salt_len);
            let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
            let packet = seal_udp_datagram(&master, method, &target, b"ping").expect("seals");
            assert_eq!(packet.len(), salt_len + 7 + 4 + TAG_LEN, "{name}");
            let (got, payload) = open_udp_datagram(&master, method, &packet).expect("opens");
            assert_eq!(got, target, "{name}");
            assert_eq!(payload, b"ping", "{name}");
        }
    }

    /// Sealed datagrams open only with the right password and intact bytes.
    #[test]
    fn udp_datagrams_reject_damage() {
        let method = Method::Aes256Gcm;
        let master = MasterKey::new("an-example-shared-password", 32);
        let target: SocketAddr = "127.0.0.1:53".parse().expect("addr");
        let packet = seal_udp_datagram(&master, method, &target, b"ping").expect("seals");
        let wrong = MasterKey::new("a-different-password", 32);
        assert!(open_udp_datagram(&wrong, method, &packet).is_none());
        let mut cut = packet.clone();
        cut.pop();
        assert!(open_udp_datagram(&master, method, &cut).is_none());
        let mut flipped = packet.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(open_udp_datagram(&master, method, &flipped).is_none());
        assert!(open_udp_datagram(&master, method, &packet[..10]).is_none());
        assert!(open_udp_datagram(&master, method, &[]).is_none());
    }
}
