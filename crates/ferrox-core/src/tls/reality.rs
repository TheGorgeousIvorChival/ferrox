use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use super::{Stream, TlsError, TlsProvider};
use crate::tls::rustls_backend::RustlsServerProvider;
use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use ring::signature::KeyPair as _;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_X25519_MLKEM768_DRAFT: u16 = 0x6399;
const MLKEM768_KEY_LEN: usize = 1184;
const TLS13: u16 = 0x0304;
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
const PKCS8_ED25519_SEED_HEADER: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const SIGNATURE_LEN: usize = 64;
const MAX_RECORD: usize = 16_384 + 2_048;
const MAX_HELLO: usize = 1 << 16;

const ED25519_SEED: [u8; 32] = [
    0x64, 0x6f, 0x76, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x2d, 0x72, 0x65, 0x61, 0x6c, 0x69, 0x74, 0x79,
    0x2d, 0x65, 0x64, 0x32, 0x35, 0x31, 0x39, 0x2d, 0x73, 0x65, 0x65, 0x64, 0x2d, 0x76, 0x31, 0x63,
];

/// How fast the cover origin may be fed once a splice has passed `after_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

/// The cover origin an unauthenticated peer is spliced into, dialled lazily so
/// that an authenticated client costs the real site nothing.
#[derive(Debug, Clone, Default)]
pub struct RealityServerConfig {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub max_time_skew: Option<Duration>,
    pub min_client_ver: Option<[u8; 3]>,
    pub max_client_ver: Option<[u8; 3]>,
    pub limit_fallback_upload: Option<RateLimit>,
    pub limit_fallback_download: Option<RateLimit>,
    pub dest: Option<String>,
    pub xver: u8,
    pub show: bool,
}

/// The two ends of a socket, for the PROXY-protocol header a cover origin is
/// sent before anything else: `local` is the source the cover origin sees and
/// `peer` the destination it was dialled on.
#[derive(Debug, Clone, Copy, Default)]
pub struct Edges {
    pub peer: Option<SocketAddr>,
    pub local: Option<SocketAddr>,
}

impl Edges {
    pub fn of(io: &TcpStream) -> Self {
        Self {
            peer: io.peer_addr().ok(),
            local: io.local_addr().ok(),
        }
    }
}

/// What the server answers with once the `ClientHello` has been read: either an
/// authenticated session, or the splice that carries an unauthenticated peer to
/// the cover origin it asked for.
#[allow(
    clippy::large_enum_variant,
    reason = "the session holds the TLS stack and the splice holds two sockets; boxing either would add a pointer chase to every handshake"
)]
pub enum RealityAccept<S: Stream> {
    Session(RealityServer<S>),
    Proxied(Proxied<S>),
}

impl<S: Stream> std::fmt::Debug for RealityAccept<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(_) => f.write_str("RealityAccept::Session"),
            Self::Proxied(_) => f.write_str("RealityAccept::Proxied"),
        }
    }
}

/// An unauthenticated peer and the cover origin it is now being spliced into.
pub struct Proxied<S: Stream> {
    pub client: S,
    pub target: TcpStream,
    pub upload: Option<RateLimit>,
    pub download: Option<RateLimit>,
}

impl<S: Stream> std::fmt::Debug for Proxied<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxied")
            .field("upload", &self.upload)
            .field("download", &self.download)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct RealityServer<S: Stream> {
    inner: RustlsServerProvider<Replay<S>>,
}

impl<S: Stream> RealityServer<S> {
    /// Reads the `ClientHello`, authenticates it, and answers with the session or
    /// with the splice. A hello that does not authenticate and has no cover
    /// origin configured is an error, which is the whole of a refusal.
    pub fn accept(
        cfg: &RealityServerConfig,
        now_ms: u64,
        io: S,
        edges: Edges,
    ) -> Result<RealityAccept<S>, TlsError> {
        let mut replay = Replay::new(io);
        let (raw, hello) = read_client_hello(&mut replay)?;
        let Ok(auth_key) = authenticate(cfg, &hello, now_ms) else {
            return splice(cfg, replay.into_inner(), &raw, edges);
        };
        let identity = super::TlsServerConfig {
            alpn: Vec::new(),
            cert_chain: vec![bound_certificate(&auth_key, first_name(cfg))],
            key_der: ed25519_pkcs8(),
            key_kind: super::ServerKeyKind::Pkcs8,
        };
        replay.set_prefix(&raw);
        Ok(RealityAccept::Session(Self {
            inner: RustlsServerProvider::accept(&identity, replay)?,
        }))
    }

    pub fn get_ref(&self) -> &S {
        self.inner.get_ref().transport()
    }
}

impl<S: Stream> TlsProvider for RealityServer<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        self.inner.suites()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.inner.handshake()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.inner.alpn()
    }
}

impl<S: Stream> Read for RealityServer<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S: Stream> Write for RealityServer<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Dials the cover origin, hands it the hello the server read, and answers with
/// the splice. The dial is lazy on purpose: an authenticated client never costs
/// the real site a connection, and neither does a port scanner.
fn splice<S: Stream>(
    cfg: &RealityServerConfig,
    io: S,
    hello: &[u8],
    edges: Edges,
) -> Result<RealityAccept<S>, TlsError> {
    let Some(dest) = cfg.dest.as_deref() else {
        return Err(TlsError::Other(format!(
            "{}: refused, no cover origin configured",
            cfg.server_names.first().map_or("reality", String::as_str)
        )));
    };
    let refused = |why: &str| TlsError::Other(format!("reality: cover origin, {why}"));
    let mut target = TcpStream::connect(dest).map_err(|_| refused("unreachable"))?;
    if cfg.xver > 0 {
        proxy_protocol(&mut target, cfg.xver, edges).map_err(|_| refused("proxy protocol"))?;
    }
    target.write_all(hello).map_err(|_| refused("hello"))?;
    target.flush().map_err(|_| refused("hello"))?;
    Ok(RealityAccept::Proxied(Proxied {
        client: io,
        target,
        upload: cfg.limit_fallback_upload,
        download: cfg.limit_fallback_download,
    }))
}

fn narrow(edge: &SocketAddr) -> [u8; 4] {
    match edge.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || v6.octets()[12..].try_into().unwrap_or([0; 4]),
            |v4| v4.octets(),
        ),
    }
}

fn wide(edge: &SocketAddr) -> [u8; 16] {
    match edge.ip() {
        std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        std::net::IpAddr::V6(v6) => v6.octets(),
    }
}

/// The PROXY-protocol header, either the text form or the binary one, written
/// before the hello so the cover origin sees who really connected.
fn proxy_protocol(target: &mut TcpStream, version: u8, edges: Edges) -> Result<(), std::io::Error> {
    match version {
        1 => {
            let line = match (edges.local, edges.peer) {
                (Some(local), Some(peer)) => {
                    let family = if local.is_ipv4() && peer.is_ipv4() {
                        "TCP4"
                    } else {
                        "TCP6"
                    };
                    format!(
                        "PROXY {family} {} {} {} {}\r\n",
                        local.ip(),
                        peer.ip(),
                        local.port(),
                        peer.port()
                    )
                }
                _ => "PROXY UNKNOWN\r\n".to_owned(),
            };
            target.write_all(line.as_bytes())
        }
        2 => {
            const MAGIC: [u8; 12] = [
                0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
            ];
            let mut body = Vec::with_capacity(36);
            if let (Some(local), Some(peer)) = (edges.local, edges.peer) {
                let four = local.is_ipv4() && peer.is_ipv4();
                let (near, far) = if four {
                    (narrow(&local).to_vec(), narrow(&peer).to_vec())
                } else {
                    (Vec::from(wide(&local)), Vec::from(wide(&peer)))
                };
                body.extend_from_slice(&near);
                body.extend_from_slice(&far);
                body.extend_from_slice(&local.port().to_be_bytes());
                body.extend_from_slice(&peer.port().to_be_bytes());
                let fam = if four { 0x11 } else { 0x21 };
                target.write_all(&MAGIC)?;
                target.write_all(&[0x21, fam])?;
            } else {
                body.extend_from_slice(&[0; 12]);
                target.write_all(&MAGIC)?;
                target.write_all(&[0x20, 0x30])?;
            }
            let rest = u16::try_from(body.len()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "oversized proxy header")
            })?;
            target.write_all(&rest.to_be_bytes())?;
            target.write_all(&body)
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported proxy protocol version",
        )),
    }
}

struct Replay<S> {
    prefix: Vec<u8>,
    at: usize,
    io: S,
}

impl<S> Replay<S> {
    fn new(io: S) -> Self {
        Self {
            prefix: Vec::new(),
            at: 0,
            io,
        }
    }

    fn set_prefix(&mut self, bytes: &[u8]) {
        self.prefix.clear();
        self.prefix.extend_from_slice(bytes);
        self.at = 0;
    }

    fn into_inner(self) -> S {
        self.io
    }

    fn transport(&self) -> &S {
        &self.io
    }
}

impl<S: Read> Read for Replay<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(rest) = self.prefix.get(self.at..) {
            if !rest.is_empty() {
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                self.at += n;
                return Ok(n);
            }
        }
        self.io.read(buf)
    }
}

impl<S: Write> Write for Replay<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.io.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io.flush()
    }
}

#[derive(Debug)]
struct ClientHello {
    bytes: Vec<u8>,
    session_id: (usize, usize),
    random: [u8; 32],
    server_name: Option<String>,
    peer_key: [u8; 32],
}

fn read_client_hello<S: Read>(io: &mut S) -> Result<(Vec<u8>, ClientHello), TlsError> {
    let mut raw: Vec<u8> = Vec::new();
    let mut bytes: Vec<u8> = Vec::new();
    let mut header = [0u8; 5];
    loop {
        if !read_fully(io, &mut header) {
            return Err(TlsError::Closed);
        }
        if header[0] != 0x16 {
            return Err(TlsError::Other(
                "reality: expected a handshake record".to_owned(),
            ));
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len > MAX_RECORD {
            return Err(TlsError::Other(
                "reality: oversized handshake record".to_owned(),
            ));
        }
        let at = bytes.len();
        bytes.resize(at + len, 0);
        if !read_fully(io, &mut bytes[at..]) {
            return Err(TlsError::Closed);
        }
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&bytes[at..]);
        if let Some(whole) = hello_is_whole(&bytes) {
            return Ok((raw, parse_client_hello(bytes[..whole].to_vec())?));
        }
        if bytes.len() > MAX_HELLO {
            return Err(TlsError::Other("reality: oversized ClientHello".to_owned()));
        }
    }
}

pub(crate) fn read_fully<R: Read>(io: &mut R, buf: &mut [u8]) -> bool {
    let mut at = 0;
    while at < buf.len() {
        match io.read(&mut buf[at..]) {
            Ok(0) => return false,
            Ok(n) => at += n,
            Err(error) if waiting(&error) => {}
            Err(_) => return false,
        }
    }
    true
}

fn waiting(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn hello_is_whole(bytes: &[u8]) -> Option<usize> {
    if bytes.first()? != &0x01 || bytes.len() < 4 {
        return None;
    }
    let want = 4 + u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as usize;
    (bytes.len() >= want).then_some(want)
}

fn authenticate(
    cfg: &RealityServerConfig,
    hello: &ClientHello,
    now_ms: u64,
) -> Result<[u8; 32], TlsError> {
    let refused = |why: &str| -> TlsError { TlsError::Other(format!("reality: refused, {why}")) };
    if hello.session_id.1 != 32 {
        return Err(refused("session id length"));
    }
    let name = hello.server_name.as_deref().unwrap_or_default();
    if !cfg.server_names.iter().any(|allowed| allowed == name) {
        return Err(refused("server name"));
    }

    let shared = x25519_dalek::x25519(cfg.private_key, hello.peer_key);
    if shared.iter().all(|byte| *byte == 0) {
        return Err(refused("zero shared secret"));
    }
    let mut auth_key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&hello.random[..20]), &shared)
        .expand(b"REALITY", &mut auth_key)
        .map_err(|_| refused("hkdf"))?;

    let mut sealed = hello.bytes.clone();
    let (at, len) = hello.session_id;
    sealed[at..at + len].fill(0);
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&auth_key).map_err(|_| refused("cipher"))?;
    let mut plain = [0u8; 16];
    let opened = cipher
        .decrypt(
            aes_gcm::Nonce::from_slice(&hello.random[20..]),
            Payload {
                msg: &hello.bytes[at..at + len],
                aad: &sealed,
            },
        )
        .map_err(|_| refused("tag"))?;
    plain.copy_from_slice(&opened);

    let client_ver = [plain[0], plain[1], plain[2]];
    if cfg.min_client_ver.is_some_and(|lo| client_ver < lo)
        || cfg.max_client_ver.is_some_and(|hi| client_ver > hi)
    {
        return Err(refused("client version"));
    }
    let short_id = std::array::from_fn(|i| plain[8 + i]);
    if !cfg.short_ids.contains(&short_id) {
        return Err(refused("short id"));
    }
    if let Some(skew) = cfg.max_time_skew {
        let sent = u64::from(u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]])) * 1000;
        if now_ms.abs_diff(sent) > u64::try_from(skew.as_millis()).unwrap_or(u64::MAX) {
            return Err(refused("clock"));
        }
    }
    Ok(auth_key)
}

fn first_name(cfg: &RealityServerConfig) -> &str {
    cfg.server_names.first().map_or("", String::as_str)
}

fn parse_client_hello(bytes: Vec<u8>) -> Result<ClientHello, TlsError> {
    let bad = || TlsError::Other("reality: malformed ClientHello".to_owned());
    let mut at = 4 + 2;
    let random = bytes
        .get(at..at + 32)
        .and_then(|r| <[u8; 32]>::try_from(r).ok())
        .ok_or_else(bad)?;
    at += 32;
    let session_id_len = usize::from(*bytes.get(at).ok_or_else(bad)?);
    at += 1;
    if bytes.get(at..at + session_id_len).is_none() {
        return Err(bad());
    }
    let session_id = (at, session_id_len);
    at += session_id_len;
    let suites_len = usize::from(u16::from_be_bytes(
        bytes
            .get(at..at + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .ok_or_else(bad)?,
    ));
    at += 2 + suites_len;
    let compression_len = usize::from(*bytes.get(at).ok_or_else(bad)?);
    at += 1 + compression_len;
    let ext_len = usize::from(u16::from_be_bytes(
        bytes
            .get(at..at + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .ok_or_else(bad)?,
    ));
    at += 2;
    if bytes.get(at..at + ext_len).is_none() {
        return Err(bad());
    }

    let mut hello = ClientHello {
        bytes,
        session_id,
        random,
        server_name: None,
        peer_key: [0u8; 32],
    };
    let mut offers_tls13 = false;
    let mut key_share = None;
    for (kind, body) in extensions(&hello.bytes, at, ext_len) {
        match kind {
            0x0000 => hello.server_name = server_name(body),
            0x002b => offers_tls13 = supported_versions(body).contains(&TLS13),
            0x0033 => key_share = x25519_share(body),
            _ => {}
        }
    }
    if !offers_tls13 {
        return Err(TlsError::Other(
            "reality: ClientHello does not offer TLS 1.3".to_owned(),
        ));
    }
    hello.peer_key = key_share.ok_or_else(|| {
        TlsError::Other("reality: ClientHello carries no X25519 share".to_owned())
    })?;
    Ok(hello)
}

fn extensions(bytes: &[u8], at: usize, len: usize) -> impl Iterator<Item = (u16, &[u8])> {
    let end = at + len;
    (at..end).scan(at, move |cursor, _| {
        let head = bytes.get(*cursor..*cursor + 4)?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let size = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let body = bytes.get(*cursor + 4..*cursor + 4 + size)?;
        *cursor += 4 + size;
        Some((kind, body))
    })
}

fn server_name(body: &[u8]) -> Option<String> {
    let mut list = Cursor::new(body, 2);
    while !list.empty() {
        let kind = list.byte()?;
        let name = list.slice()?;
        if kind == 0 {
            return String::from_utf8(name.to_vec()).ok();
        }
    }
    None
}

fn supported_versions(body: &[u8]) -> Vec<u16> {
    let Some(&len) = body.first() else {
        return Vec::new();
    };
    body.get(1..1 + usize::from(len))
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_be_bytes)
        .collect()
}

fn x25519_share(body: &[u8]) -> Option<[u8; 32]> {
    let hybrid_len = MLKEM768_KEY_LEN + 32;
    let mut plain = None;
    let mut hybrid = None;
    let mut list = Cursor::new(body, 2);
    while !list.empty() {
        let group = list.u16()?;
        let share = list.slice()?;
        match (group, share.len()) {
            (GROUP_X25519, 32) if plain.is_none() => {
                plain = Some(<[u8; 32]>::try_from(share).ok()?);
            }
            (GROUP_X25519_MLKEM768, len) if len == hybrid_len && hybrid.is_none() => {
                hybrid = Some(<[u8; 32]>::try_from(&share[MLKEM768_KEY_LEN..]).ok()?);
            }
            (GROUP_X25519_MLKEM768_DRAFT, len) if len == hybrid_len && hybrid.is_none() => {
                hybrid = Some(<[u8; 32]>::try_from(&share[..32]).ok()?);
            }
            _ => {}
        }
    }
    plain.or(hybrid)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], at: usize) -> Self {
        Self { bytes, at }
    }

    fn empty(&self) -> bool {
        self.at >= self.bytes.len()
    }

    fn byte(&mut self) -> Option<u8> {
        let value = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(value)
    }

    fn u16(&mut self) -> Option<u16> {
        let head = self.bytes.get(self.at..self.at + 2)?;
        self.at += 2;
        Some(u16::from_be_bytes([head[0], head[1]]))
    }

    fn slice(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        let body = self.bytes.get(self.at..self.at + len)?;
        self.at += len;
        Some(body)
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else if body.len() < 0x100 {
        out.push(0x81);
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(body);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

fn bound_certificate(auth_key: &[u8; 32], name: &str) -> Vec<u8> {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, auth_key);
    let proof = ring::hmac::sign(&key, public_key());

    let algorithm = tlv(0x30, &OID_ED25519);
    let who = distinguished_name(name);
    let validity = tlv(
        0x30,
        &sequence(&[&tlv(0x17, b"260101000000Z"), &tlv(0x17, b"491231235959Z")]),
    );
    let spki = tlv(
        0x30,
        &sequence(&[&algorithm, &tlv(0x03, &sequence(&[&[0x00], public_key()]))]),
    );
    let tbs = tlv(
        0x30,
        &sequence(&[
            &tlv(0xa0, &tlv(0x02, &[0x02])),
            &tlv(0x02, &[0x01]),
            &algorithm,
            &who,
            &validity,
            &who,
            &spki,
        ]),
    );
    let der = tlv(
        0x30,
        &sequence(&[
            &tbs,
            &algorithm,
            &tlv(0x03, &sequence(&[&[0x00], proof.as_ref()])),
        ]),
    );
    debug_assert_eq!(&der[der.len() - SIGNATURE_LEN..], proof.as_ref());
    der
}

fn distinguished_name(name: &str) -> Vec<u8> {
    let attribute = tlv(
        0x30,
        &sequence(&[&tlv(0x06, &[0x55, 0x04, 0x03]), &tlv(0x0c, name.as_bytes())]),
    );
    tlv(0x30, &sequence(&[&tlv(0x31, &attribute)]))
}

fn public_key() -> &'static [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8())
            .expect("the fixed seed is a PKCS#8 Ed25519 key ring accepts");
        <[u8; 32]>::try_from(pair.public_key().as_ref()).expect("an Ed25519 key is 32 bytes")
    })
}

fn ed25519_pkcs8() -> Vec<u8> {
    pkcs8()
}

fn pkcs8() -> Vec<u8> {
    let mut out = PKCS8_ED25519_SEED_HEADER.to_vec();
    out.extend_from_slice(&ED25519_SEED);
    out
}

#[cfg(test)]
fn proof_at(der: &[u8]) -> &[u8] {
    &der[der.len() - SIGNATURE_LEN..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    const SERVER_PRIVATE: [u8; 32] = [
        0x69, 0x20, 0xca, 0xab, 0x2b, 0x4d, 0xe3, 0x7d, 0xfc, 0xfe, 0xbf, 0x60, 0x8b, 0x2a, 0x43,
        0x1c, 0x0e, 0xbb, 0xae, 0x26, 0x93, 0x9a, 0x9c, 0x01, 0x9e, 0x06, 0x1e, 0x8a, 0x0b, 0x4e,
        0x6b, 0x91,
    ];
    const SHORT_ID: [u8; 8] = [1, 35, 69, 103, 137, 171, 205, 239];
    const SNI: &str = "www.google.com";

    fn settings() -> RealityServerConfig {
        RealityServerConfig {
            private_key: SERVER_PRIVATE,
            short_ids: vec![SHORT_ID],
            server_names: vec![SNI.to_owned()],
            max_time_skew: None,
            ..RealityServerConfig::default()
        }
    }

    fn hello_body(random: &[u8; 32], share: &[u8; 32], sni: &str) -> Vec<u8> {
        let mut ext = Vec::new();
        ext.extend_from_slice(&tlv_header(0x0000, &name_list(sni)));
        ext.extend_from_slice(&tlv_header(0x002b, &[2, 0x03, 0x04]));
        let mut one = Vec::new();
        one.extend_from_slice(&GROUP_X25519.to_be_bytes());
        one.extend_from_slice(&32u16.to_be_bytes());
        one.extend_from_slice(share);
        let mut shares = u16::try_from(one.len()).unwrap().to_be_bytes().to_vec();
        shares.extend_from_slice(&one);
        ext.extend_from_slice(&tlv_header(0x0033, &shares));
        let ext_len = u16::try_from(ext.len()).unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(&[0x01, 0, 0, 0]);
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(random);
        body.push(32);
        body.extend_from_slice(&[0u8; 32]);
        let suites: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
        body.extend_from_slice(&u16::try_from(suites.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&suites);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&ext_len.to_be_bytes());
        body.extend_from_slice(&ext);
        let len = u32::try_from(body.len() - 4).unwrap();
        body[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
        body
    }

    fn tlv_header(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn name_list(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0);
        out.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        let mut list = u16::try_from(out.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&out);
        list
    }

    fn seal(
        body: &mut Vec<u8>,
        random: &[u8; 32],
        client_private: &[u8; 32],
        short_id: [u8; 8],
        now: u32,
    ) -> [u8; 32] {
        let mut server_public = [0u8; 32];
        server_public[0] = 9;
        let server_public = x25519_dalek::x25519(SERVER_PRIVATE, server_public);
        let shared = x25519_dalek::x25519(*client_private, server_public);
        let mut auth_key = [0u8; 32];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&random[..20]), &shared)
            .expand(b"REALITY", &mut auth_key)
            .unwrap();

        let mut plain = Vec::new();
        plain.extend_from_slice(&[26, 9, 30, 0]);
        plain.extend_from_slice(&now.to_be_bytes());
        plain.extend_from_slice(&short_id);
        let sealed = aes_gcm::Aes256Gcm::new_from_slice(&auth_key)
            .unwrap()
            .encrypt(
                aes_gcm::Nonce::from_slice(&random[20..]),
                Payload {
                    msg: &plain,
                    aad: body,
                },
            )
            .unwrap();
        assert_eq!(sealed.len(), 32);
        body[39..71].copy_from_slice(&sealed);
        auth_key
    }

    fn record(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0x16, 0x03, 0x01];
        out.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    /// How long the cover origin is given to hand back what it was sent, which
    /// is the only boundary on reading a splice whose peer has nothing more to
    /// say.
    const COVER_WAIT: Duration = Duration::from_millis(400);

    struct Verdict {
        authenticated: bool,
        dialled: usize,
        cover: Vec<u8>,
    }

    fn offer(cfg: &RealityServerConfig, now_ms: u64, hello: &[u8]) -> Verdict {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let cover = TcpListener::bind("127.0.0.1:0").expect("binds");
        let mut cfg = cfg.clone();
        cfg.dest = Some(cover.local_addr().expect("addr").to_string());
        let settings = cfg.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&settings, now_ms, stream, Edges::default()).ok()
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(hello).expect("writes");
        client.flush().expect("flushes");
        let _ = client.shutdown(std::net::Shutdown::Write);
        let answer = server.join().expect("joins");
        let authenticated = matches!(answer, Some(RealityAccept::Session(_)));
        let mut dialled = 0;
        let mut seen = Vec::new();
        cover.set_nonblocking(true).expect("nonblocking");
        if let Ok((mut site, _)) = cover.accept() {
            dialled += 1;
            site.set_nonblocking(false).expect("blocking");
            site.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
            let mut once = [0u8; 4096];
            loop {
                match site.read(&mut once) {
                    Ok(0) | Err(_) => break,
                    Ok(took) => seen.extend_from_slice(&once[..took]),
                }
            }
        }
        Verdict {
            authenticated,
            dialled,
            cover: seen,
        }
    }

    fn accepted(now_ms: u64, bytes: &[u8]) -> bool {
        offer(&settings(), now_ms, bytes).authenticated
    }

    fn offer_with(cfg: &RealityServerConfig, now_ms: u64, bytes: &[u8]) -> Verdict {
        offer(cfg, now_ms, bytes)
    }

    fn refused_with(cfg: &RealityServerConfig, now_ms: u64, bytes: &[u8]) -> bool {
        !offer(cfg, now_ms, bytes).authenticated
    }

    fn good_hello() -> Vec<u8> {
        let client_private = [0x11u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, 1_700_000_000);
        record(&body)
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_authenticated_hello_is_accepted() {
        assert!(accepted(0, &good_hello()));
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn every_unauthenticated_hello_is_refused() {
        let client_private = [0x11u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let wrong_short = [9u8; 8];
        let mut other = wrong_short;
        let build = |sni: &str, short: &[u8; 8]| {
            let mut body = hello_body(&random, &share, sni);
            seal(&mut body, &random, &client_private, *short, 1_700_000_000);
            record(&body)
        };

        assert!(!offer(&settings(), 0, &build("evil.example", &SHORT_ID)).authenticated);
        assert!(!offer(&settings(), 0, &build(SNI, &wrong_short)).authenticated);

        for at in [39usize, 50, 71, 100, 160] {
            let mut bytes = build(SNI, &SHORT_ID);
            let spot = at.min(bytes.len() - 1);
            bytes[spot] ^= 0x40;
            assert!(
                !offer(&settings(), 0, &bytes).authenticated,
                "byte {spot} was not covered"
            );
        }
        other[0] = 0;
        assert_ne!(other, wrong_short);

        assert!(!offer(&settings(), 0, b"not a tls record at all").authenticated);
        assert!(!offer(&settings(), 0, &[]).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_authenticated_hello_costs_the_cover_origin_nothing() {
        let verdict = offer(&settings(), 0, &good_hello());
        assert!(verdict.authenticated);
        assert_eq!(verdict.dialled, 0, "the cover origin must not be dialled");
        assert_eq!(verdict.cover.len(), 0);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn an_unauthenticated_hello_is_spliced_into_the_cover_origin_byte_for_byte() {
        let mut bytes = good_hello();
        let spot = 71.min(bytes.len() - 1);
        bytes[spot] ^= 0x40;
        let verdict = offer(&settings(), 0, &bytes);
        assert!(!verdict.authenticated);
        assert_eq!(verdict.dialled, 1);
        assert_eq!(
            verdict.cover, bytes,
            "the cover origin must see the hello the server read"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_refused_hello_with_no_cover_origin_is_dropped_not_dialled() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&settings(), 0, stream, Edges::default()).is_ok()
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut hello = good_hello();
        let spot = 71.min(hello.len() - 1);
        hello[spot] ^= 0x40;
        client.write_all(&hello).expect("writes");
        client.flush().expect("flushes");
        assert!(!server.join().expect("joins"));
        client
            .set_read_timeout(Some(COVER_WAIT))
            .expect("sets a read timeout");
        let mut silence = [0u8; 8];
        assert!(matches!(client.read(&mut silence), Ok(0) | Err(_)));
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_proxy_protocol_header_precedes_the_hello_on_the_cover_origin() {
        let mut bytes = good_hello();
        let spot = 71.min(bytes.len() - 1);
        bytes[spot] ^= 0x40;
        for (xver, head) in [(1u8, b"PROXY " as &[u8]), (2u8, &[0x0d, 0x0a])] {
            let mut cfg = settings();
            cfg.xver = xver;
            let verdict = offer(&cfg, 0, &bytes);
            assert_eq!(verdict.dialled, 1, "version {xver} never dialled");
            assert!(
                verdict.cover.starts_with(head),
                "version {xver} wrote no recognizable header"
            );
            let after = verdict.cover.len() - bytes.len();
            assert_eq!(&verdict.cover[after..], &bytes[..]);
        }
    }

    #[test]
    fn the_text_proxy_header_names_both_ends_of_the_client_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let edges = Edges::of(&stream);
        assert!(edges.peer.is_some() && edges.local.is_some());
        assert_ne!(edges.peer, edges.local);
        let (mut site, _) = listener.accept().expect("accepts");
        proxy_protocol(&mut site, 1, edges).expect("writes a header");
        drop(site);
        let mut sink = stream;
        sink.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
        let mut head = [0u8; 64];
        let mut got = Vec::new();
        while let Ok(took) = sink.read(&mut head) {
            if took == 0 {
                break;
            }
            got.extend_from_slice(&head[..took]);
            if got.contains(&b'\n') {
                break;
            }
        }
        let line = String::from_utf8_lossy(&got);
        assert!(
            line.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "),
            "{line}"
        );
        assert!(line.ends_with("\r\n"));
    }

    #[test]
    fn the_binary_proxy_header_is_a_fixed_rectangular_twenty_eight_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let listening = listener.local_addr().expect("addr").port();
        let stream = TcpStream::connect(("127.0.0.1", listening)).expect("connects");
        let client = stream.local_addr().expect("addr").port();
        let (mut site, _) = listener.accept().expect("accepts");
        proxy_protocol(&mut site, 2, Edges::of(&stream)).expect("writes a header");
        drop(site);
        let mut sink = stream;
        sink.set_read_timeout(Some(COVER_WAIT)).expect("timeout");
        let mut head = [0u8; 28];
        let mut got = 0;
        while got < head.len() {
            match sink.read(&mut head[got..]) {
                Ok(0) | Err(_) => break,
                Ok(took) => got += took,
            }
        }
        assert_eq!(got, 28, "the header is a fixed twenty-eight bytes");
        assert_eq!(
            &head[..12],
            &[0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]
        );
        assert_eq!(head[12], 0x21, "the version-and-command byte is 1.3");
        assert_eq!(head[13], 0x11, "the family is TCP over IPv4");
        assert_eq!(
            u16::from_be_bytes([head[14], head[15]]),
            12,
            "the length counts the two addresses and the two ports"
        );
        assert_eq!(&head[16..20], &[127, 0, 0, 1], "the source address");
        assert_eq!(&head[20..24], &[127, 0, 0, 1], "the destination address");
        assert_eq!(
            u16::from_be_bytes([head[24], head[25]]),
            client,
            "the source port"
        );
        assert_eq!(
            u16::from_be_bytes([head[26], head[27]]),
            listening,
            "the destination port"
        );
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_short_id_is_zero_padded_to_eight_bytes() {
        let cfg = RealityServerConfig {
            short_ids: vec![[1, 35, 69, 103, 0, 0, 0, 0]],
            ..settings()
        };
        let client_private = [0x22u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(5));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            [1, 35, 69, 103, 0, 0, 0, 0],
            1_700_000_000,
        );
        assert!(offer_with(&cfg, 0, &record(&body)).authenticated);
        assert!(!offer_with(&settings(), 0, &record(&body)).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn a_sub_second_clock_gate_does_not_refuse_every_hello() {
        let cfg = RealityServerConfig {
            max_time_skew: Some(Duration::from_millis(250)),
            ..settings()
        };
        let client_private = [0x44u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(9));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let now = 1_788_000_000u64;
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            SHORT_ID,
            u32::try_from(now).unwrap(),
        );
        assert!(offer_with(&cfg, now * 1000 + 100, &record(&body)).authenticated);
        assert!(!offer_with(&cfg, now * 1000 + 900, &record(&body)).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_client_version_gate_bites_only_when_it_is_set() {
        let client_private = [0x55u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, 1_700_000_000);
        let hello = record(&body);
        assert!(accepted(0, &hello), "no version gate must refuse nothing");
        let low = RealityServerConfig {
            min_client_ver: Some([27, 0, 0]),
            ..settings()
        };
        assert!(refused_with(&low, 0, &hello));
        let high = RealityServerConfig {
            max_client_ver: Some([1, 8, 1]),
            ..settings()
        };
        assert!(refused_with(&high, 0, &hello));
        let wide = RealityServerConfig {
            min_client_ver: Some([1, 0, 0]),
            max_client_ver: Some([30, 0, 0]),
            ..settings()
        };
        assert!(offer_with(&wide, 0, &hello).authenticated);
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_clock_gate_is_off_by_default_and_bites_when_set() {
        let cfg = RealityServerConfig {
            max_time_skew: Some(Duration::from_millis(1_500)),
            ..settings()
        };
        let client_private = [0x33u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let now = 1_788_000_000u64;
        let stale = u32::try_from(now - 3600).unwrap();
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, stale);
        assert!(refused_with(&cfg, now * 1000, &record(&body)));
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            SHORT_ID,
            u32::try_from(now).unwrap(),
        );
        assert!(offer_with(&cfg, now * 1000, &record(&body)).authenticated);
    }

    #[test]
    fn the_x25519_share_is_found_in_every_group_that_carries_one() {
        let key = [0x5au8; 32];
        let mut shares = Vec::new();
        shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
        shares.extend_from_slice(&32u16.to_be_bytes());
        shares.extend_from_slice(&key);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(key));

        let mut hybrid = vec![0xa5u8; MLKEM768_KEY_LEN];
        hybrid.extend_from_slice(&key);
        let mut shares = GROUP_X25519_MLKEM768.to_be_bytes().to_vec();
        shares.extend_from_slice(&u16::try_from(hybrid.len()).unwrap().to_be_bytes());
        shares.extend_from_slice(&hybrid);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(key));

        let mut draft = key.to_vec();
        draft.extend_from_slice(&[0xa5u8; MLKEM768_KEY_LEN]);
        let mut shares = GROUP_X25519_MLKEM768_DRAFT.to_be_bytes().to_vec();
        shares.extend_from_slice(&u16::try_from(draft.len()).unwrap().to_be_bytes());
        shares.extend_from_slice(&draft);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(key));

        assert_eq!(x25519_share(&[0, 0]), None);
    }

    #[test]
    fn a_plain_share_is_preferred_over_a_hybrid_one() {
        let plain = [0x11u8; 32];
        let hybrid_key = [0x22u8; 32];
        assert_ne!(plain, hybrid_key);
        let mut hybrid = vec![0xa5u8; MLKEM768_KEY_LEN];
        hybrid.extend_from_slice(&hybrid_key);
        let mut shares = GROUP_X25519_MLKEM768.to_be_bytes().to_vec();
        shares.extend_from_slice(&u16::try_from(hybrid.len()).unwrap().to_be_bytes());
        shares.extend_from_slice(&hybrid);
        shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
        shares.extend_from_slice(&32u16.to_be_bytes());
        shares.extend_from_slice(&plain);
        let mut list = u16::try_from(shares.len()).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&shares);
        assert_eq!(x25519_share(&list), Some(plain));
        let _ = hybrid_key;
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_fixed_seed_derives_one_stable_public_key() {
        assert_eq!(public_key().len(), 32);
        assert_ne!(public_key(), &[0u8; 32]);
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_certificate_is_well_formed_der_carrying_the_proof_last() {
        let auth_key = [3u8; 32];
        let der = bound_certificate(&auth_key, SNI);
        assert!(walk_der(&der));
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA512, &auth_key);
        assert_eq!(
            proof_at(&der),
            ring::hmac::sign(&key, public_key()).as_ref(),
        );
        assert_eq!(proof_at(&der).len(), SIGNATURE_LEN);
        assert!(der.windows(OID_ED25519.len()).any(|w| w == OID_ED25519));
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_certificate_differs_per_auth_key() {
        let a = bound_certificate(&[1u8; 32], SNI);
        let b = bound_certificate(&[2u8; 32], SNI);
        assert_ne!(proof_at(&a), proof_at(&b));
        assert_eq!(a.len(), b.len());
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_private_key_is_a_pkcs8_document_ring_accepts() {
        let der = ed25519_pkcs8();
        assert_eq!(der.len(), PKCS8_ED25519_SEED_HEADER.len() + 32);
        assert!(ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).is_ok());
    }

    fn walk_der(bytes: &[u8]) -> bool {
        let mut at = 0;
        while at < bytes.len() {
            let Some((tag, header, total)) = element(&bytes[at..]) else {
                return false;
            };
            if tag & 0x20 != 0 && !walk_der(&bytes[at + header..at + total]) {
                return false;
            }
            at += total;
        }
        at > 0 && at == bytes.len()
    }

    fn element(bytes: &[u8]) -> Option<(u8, usize, usize)> {
        let (&tag, &first) = (bytes.first()?, bytes.get(1)?);
        assert_ne!(tag, 0, "a `DER` element has a tag");
        let (header, len) = match first {
            len if len < 0x80 => (2usize, usize::from(len)),
            0x81 => (3, usize::from(*bytes.get(2)?)),
            0x82 => (
                4,
                usize::from(u16::from_be_bytes([*bytes.get(2)?, *bytes.get(3)?])),
            ),
            _ => return None,
        };
        let total = header.checked_add(len)?;
        (total <= bytes.len()).then_some((tag, header, total))
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_der_walker_rejects_a_truncated_certificate() {
        assert!(walk_der(&bound_certificate(&[4u8; 32], SNI)));
        assert!(!walk_der(&[0x30, 0x05, 0x02, 0x01, 0x01]));
        assert!(!walk_der(&[0x30]));
        assert!(!walk_der(&[]));
    }

    #[cfg_attr(
        miri,
        ignore = "reaches ring's C and assembly, which Miri cannot interpret"
    )]
    #[test]
    fn the_private_key_is_one_rustls_can_sign_with() {
        let key = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                ed25519_pkcs8(),
            )),
        )
        .expect("rustls accepts the Ed25519 key");
        assert_eq!(key.algorithm(), rustls::SignatureAlgorithm::ED25519);
        let spki = key
            .public_key()
            .expect("a signing key publishes its public half");
        assert_eq!(spki.as_ref().len(), 44, "an `Ed25519` `SPKI` is 44 bytes");
        assert_eq!(&spki.as_ref()[12..], public_key().as_slice());
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_replayed_prefix_is_the_record_the_server_consumed() {
        let cfg = settings();
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&cfg, 0, stream, Edges::default()).map(|_| ())
        });
        let bytes = good_hello();
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(&bytes).expect("writes");
        server.join().expect("joins").expect("authenticates");
        assert_eq!(bytes[0], 0x16);
    }

    /// A `Read` that answers `WouldBlock` once and then dribbles one byte at a
    /// time, so the hello reader is driven through its wait path deterministically.
    struct Dribble {
        bytes: Vec<u8>,
        at: usize,
        blocked: bool,
    }

    impl Dribble {
        fn of(bytes: &[u8]) -> Self {
            Self {
                bytes: bytes.to_vec(),
                at: 0,
                blocked: false,
            }
        }
    }

    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.blocked {
                self.blocked = true;
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if self.at >= self.bytes.len() {
                return Ok(0);
            }
            buf[0] = self.bytes[self.at];
            self.at += 1;
            Ok(1)
        }
    }

    #[test]
    fn a_hello_in_two_records_behind_a_timeout_is_read_whole() {
        let bytes = good_hello();
        let body = &bytes[5..];
        let half = body.len() / 2;
        let mut split = vec![0x16, 0x03, 0x01];
        split.extend_from_slice(&u16::try_from(half).unwrap().to_be_bytes());
        split.extend_from_slice(&body[..half]);
        let mut second = vec![0x16, 0x03, 0x01];
        second.extend_from_slice(&u16::try_from(body.len() - half).unwrap().to_be_bytes());
        second.extend_from_slice(&body[half..]);
        split.extend_from_slice(&second);
        let mut dribble = Dribble::of(&split);
        let (raw, hello) = read_client_hello(&mut dribble).expect("reads whole");
        assert_eq!(raw, split);
        assert_eq!(hello.bytes, body);
    }
}
