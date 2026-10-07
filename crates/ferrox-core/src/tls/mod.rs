use crate::b64;
use std::fmt;

pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    pub roots: Vec<Vec<u8>>,
    /// Leaf keys to accept, checked after the chain has verified. Empty pins
    /// nothing and refuses nothing, which is the default because a lane with no
    /// pins is the ordinary case.
    pub pins: crate::foxy::pin::Pins,
}

pub trait TlsProvider: std::io::Read + std::io::Write {
    fn name() -> &'static str
    where
        Self: Sized;

    fn suites(&self) -> Vec<String>;

    fn handshake(&mut self) -> Result<(), TlsError>;

    fn alpn(&self) -> Option<&[u8]>;

    /// The leaf certificate the peer presented, once the handshake has
    /// completed. A provider that cannot reach it answers `None` rather than
    /// failing, because a lane with pins needs it and one without does not.
    fn peer_leaf(&self) -> Option<&[u8]> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    Timeout,
    BadCertificate,
    Closed,
    NoSharedCipher,
    Other(String),
}

impl TlsError {
    #[must_use]
    pub fn with_detail(self, detail: impl Into<String>) -> Self {
        match self {
            Self::Timeout => Self::Other(format!("timeout: {}", detail.into())),
            Self::BadCertificate => Self::Other(format!("bad certificate: {}", detail.into())),
            Self::Closed => Self::Other(format!("closed: {}", detail.into())),
            Self::NoSharedCipher => Self::Other(format!("no shared cipher: {}", detail.into())),
            Self::Other(why) => Self::Other(format!("{why}: {}", detail.into())),
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("handshake timed out"),
            Self::BadCertificate => f.write_str("certificate did not verify"),
            Self::Closed => f.write_str("connection closed by peer"),
            Self::NoSharedCipher => f.write_str("no shared cipher suite"),
            Self::Other(why) => write!(f, "backend error: {why}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<TlsError> for std::io::Error {
    fn from(e: TlsError) -> Self {
        std::io::Error::other(e)
    }
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Self::Timeout,
            std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => Self::Closed,
            _ => Self::Other(e.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    pub cert_chain: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
    pub key_kind: ServerKeyKind,
    /// The protocols to offer, in preference order. Empty means no ALPN, which
    /// is what a server that only ever carries one protocol leaves it at.
    pub alpn: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyKind {
    Pkcs8,
    Sec1,
    Pkcs1,
}

pub fn parse_pem_identity(cert_pem: &[u8], key_pem: &[u8]) -> Result<TlsServerConfig, TlsError> {
    let cert_chain = pem_blocks(cert_pem, "CERTIFICATE");
    if cert_chain.is_empty() {
        return Err(TlsError::Other(
            "tls certificate file holds no CERTIFICATE block".to_owned(),
        ));
    }
    let kinds = [
        ("PRIVATE KEY", ServerKeyKind::Pkcs8),
        ("EC PRIVATE KEY", ServerKeyKind::Sec1),
        ("RSA PRIVATE KEY", ServerKeyKind::Pkcs1),
    ];
    for (label, key_kind) in kinds {
        if let Some(key_der) = pem_blocks(key_pem, label).into_iter().next() {
            return Ok(TlsServerConfig {
                alpn: Vec::new(),
                cert_chain,
                key_der,
                key_kind,
            });
        }
    }
    Err(TlsError::Other(
        "tls key file holds no recognized private-key block".to_owned(),
    ))
}

fn pem_blocks(pem: &[u8], label: &str) -> Vec<Vec<u8>> {
    let open = format!("-----BEGIN {label}-----");
    let shut = format!("-----END {label}-----");
    let Ok(text) = std::str::from_utf8(pem) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some((_, after)) = rest.split_once(open.as_str()) {
        let Some((body, tail)) = after.split_once(shut.as_str()) else {
            break;
        };
        let Some(der) = b64::decode(body.as_bytes()) else {
            rest = tail;
            continue;
        };
        out.push(der);
        rest = tail;
    }
    out
}

mod rustls_backend;
pub use rustls_backend::{RustlsProvider, RustlsServerProvider};

pub mod reality;
pub use reality::{RealityServer, RealityServerConfig};

pub fn connect<S: Stream>(cfg: &TlsConfig, io: S) -> Result<impl TlsProvider + use<S>, TlsError> {
    RustlsProvider::connect(cfg, io)
}

pub fn accept<S: Stream + Send>(
    cfg: &TlsServerConfig,
    io: S,
) -> Result<impl TlsProvider + Send + use<S>, TlsError> {
    RustlsServerProvider::accept(cfg, io)
}

pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}
