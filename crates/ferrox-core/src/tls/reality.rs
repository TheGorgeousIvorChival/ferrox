use std::io::{Read, Write};
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

#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    pub private_key: [u8; 32],
    pub short_ids: Vec<[u8; 8]>,
    pub server_names: Vec<String>,
    pub max_time_skew: Option<Duration>,
}

#[derive(Debug)]
pub struct RealityServer<S: Stream> {
    inner: RustlsServerProvider<Replay<S>>,
}

impl<S: Stream> RealityServer<S> {
    pub fn accept(cfg: &RealityServerConfig, now: u64, io: S) -> Result<Self, TlsError> {
        let mut replay = Replay::new(io);
        let (raw, hello) = read_client_hello(&mut replay)?;
        let auth_key = authenticate(cfg, &hello, now)?;
        let identity = super::TlsServerConfig {
            cert_chain: vec![bound_certificate(&auth_key, first_name(cfg))],
            key_der: ed25519_pkcs8(),
            key_kind: super::ServerKeyKind::Pkcs8,
        };
        replay.set_prefix(&raw);
        Ok(Self {
            inner: RustlsServerProvider::accept(&identity, replay)?,
        })
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
        if io.read_exact(&mut header).is_err() {
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
        if io.read_exact(&mut bytes[at..]).is_err() {
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
    now: u64,
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

    let short_id = std::array::from_fn(|i| plain[8 + i]);
    if !cfg.short_ids.contains(&short_id) {
        return Err(refused("short id"));
    }
    if let Some(skew) = cfg.max_time_skew {
        let sent = u64::from(u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]));
        if now.abs_diff(sent) > skew.as_secs() {
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

    fn offer(cfg: &RealityServerConfig, now: u64, bytes: &[u8]) -> bool {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let settings = cfg.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            RealityServer::accept(&settings, now, stream)
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(bytes).expect("writes");
        client.flush().expect("flushes");
        let _ = client.shutdown(std::net::Shutdown::Write);
        server.join().expect("joins").is_ok()
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
        assert!(offer(&settings(), 0, &good_hello()));
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

        assert!(!offer(&settings(), 0, &build("evil.example", &SHORT_ID)));
        assert!(!offer(&settings(), 0, &build(SNI, &wrong_short)));

        for at in [39usize, 50, 71, 100, 160] {
            let mut bytes = build(SNI, &SHORT_ID);
            let target = at.min(bytes.len() - 1);
            bytes[target] ^= 0x40;
            assert!(
                !offer(&settings(), 0, &bytes),
                "byte {target} was not covered"
            );
        }
        other[0] = 0;
        assert_ne!(other, wrong_short);

        assert!(!offer(&settings(), 0, b"not a tls record at all"));
        assert!(!offer(&settings(), 0, &[]));
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
        assert!(offer(&cfg, 0, &record(&body)));
        assert!(!offer(&settings(), 0, &record(&body)));
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn the_clock_gate_is_off_by_default_and_bites_when_set() {
        let cfg = RealityServerConfig {
            max_time_skew: Some(Duration::from_secs(60)),
            ..settings()
        };
        let client_private = [0x33u8; 32];
        let random: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(2));
        let mut base = [0u8; 32];
        base[0] = 9;
        let share = x25519_dalek::x25519(client_private, base);
        let now = 1_788_000_000;
        let stale = u32::try_from(now - 3600).unwrap();
        let mut body = hello_body(&random, &share, SNI);
        seal(&mut body, &random, &client_private, SHORT_ID, stale);
        assert!(!offer(&cfg, now, &record(&body)));
        let mut body = hello_body(&random, &share, SNI);
        seal(
            &mut body,
            &random,
            &client_private,
            SHORT_ID,
            u32::try_from(now).unwrap(),
        );
        assert!(offer(&cfg, now, &record(&body)));
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
            RealityServer::accept(&cfg, 0, stream).map(|_| ())
        });
        let bytes = good_hello();
        let mut client = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        client.write_all(&bytes).expect("writes");
        server.join().expect("joins").expect("authenticates");
        assert_eq!(bytes[0], 0x16);
    }
}
