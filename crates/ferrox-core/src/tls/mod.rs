//! The TLS surface every component in this workspace is written against.
//!
//! One backend implements it: `rustls`, pure Rust and auditable. Nothing above
//! this module knows which stack is active, because there is only one —
//! a benchmark drawn from above this layer measures the record path, not a
//! choice of stacks.
//!
//! Selecting rustls is not a cargo feature and not a runtime switch: it is the
//! only stack linked, so a missing backend cannot become a silent fallback to
//! plaintext — the failure mode a feature flag exists to prevent, and one that
//! no test would catch because a test asserting "no plaintext" would need
//! a plaintext path to assert against.
//!
//! # What the interface deliberately does not have
//!
//! No method whose answer could differ per stack. [`TlsError`] carries no
//! backend-specific detail, and [`TlsProvider::suites`] is read from rustls
//! rather than declared here, because a hand-written list would drift from the
//! stack it describes and a drifted list makes every comparison drawn from it
//! meaningless.

use std::fmt;

/// The transport rustls is written against.
///
/// A blanket impl, because rustls takes any
/// `Read + Write`: anything that can carry bytes can carry TLS over them, and
/// making this a real trait would only add a bound the stack never needs.
pub trait Stream: std::io::Read + std::io::Write {}
impl<T: std::io::Read + std::io::Write> Stream for T {}

/// Everything needed to open a client session, in terms neither stack knows.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// The name sent as SNI and checked against the certificate.
    pub server_name: String,
    /// ALPN protocols to offer, in preference order.
    pub alpn: Vec<Vec<u8>>,
    /// Extra trust anchors, DER-encoded.
    ///
    /// rustls also loads the platform's default roots; these are added on
    /// top, so a caller pinning its own CA does not lose the system ones.
    pub roots: Vec<Vec<u8>>,
}

/// What a component needs from a TLS stack.
///
/// Deliberately narrow, and the providers themselves implement `Read + Write`, so
/// a caller above this module moves encrypted bytes without knowing which stack
/// produced them.
pub trait TlsProvider: std::io::Read + std::io::Write {
    /// The stack's own name, for reports and benchmarks.
    fn name() -> &'static str
    where
        Self: Sized;

    /// The cipher suites this build will negotiate, in preference order, as the
    /// backend itself reports them.
    ///
    /// Read from the stack rather than written down here: a list in this file
    /// would be a claim about the stack rather than a report of it, and would go
    /// stale silently the next time the stack changed its defaults.
    fn suites(&self) -> Vec<String>;

    /// Drive the handshake to completion, doing I/O on the transport.
    fn handshake(&mut self) -> Result<(), TlsError>;

    /// The ALPN protocol the peer selected, if any.
    fn alpn(&self) -> Option<&[u8]>;
}

/// A backend could not complete a handshake or a record operation.
///
/// The variants carry no backend-specific detail on purpose: classification is
/// what a caller branches on, and mapping is the adapter's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsError {
    /// The peer did not complete the handshake in time.
    Timeout,
    /// The peer's certificate or signature did not verify.
    BadCertificate,
    /// The peer closed, or the record was truncated.
    Closed,
    /// The peer offered nothing this build will negotiate.
    NoSharedCipher,
    /// The backend reported a failure that does not map to the above.
    Other(String),
}

impl TlsError {
    /// Attach context while keeping the variant.
    ///
    /// A backend that reports a certificate failure but not which anchor rejected
    /// it leaves the caller unable to say anything useful. This keeps the
    /// classification — which is what a caller branches on — and adds the detail
    /// that the backend-neutral type deliberately has nowhere else to put.
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

/// So a `TlsError` raised while driving a handshake can propagate out of the
/// `Read` and `Write` impls, which are required to return `std::io::Error`.
///
/// The mapping is lossy in one direction and that is deliberate: a caller reading
/// through a provider sees an `io::Error`, and [`TlsError`] is recovered by
/// downcasting. Anything else would mean inventing an `io::ErrorKind` per
/// variant, and inventing one is how a caller ends up matching on a kind the
/// backend never actually reported.
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

/// A server identity: one leaf plus chain, DER-encoded, with its private key.
///
/// Built from the PEM files an Xray-shaped config names, so the binary reads
/// `certificateFile`/`keyFile` once per inbound rather than once per connection.
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    /// Leaf first, intermediates after, each DER-encoded.
    pub cert_chain: Vec<Vec<u8>>,
    /// Private-key DER bytes.
    pub key_der: Vec<u8>,
    /// Which encoding `key_der` uses.
    pub key_kind: ServerKeyKind,
}

/// The encoding of a PEM private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKeyKind {
    /// `PRIVATE KEY`.
    Pkcs8,
    /// `EC PRIVATE KEY`.
    Sec1,
    /// `RSA PRIVATE KEY`.
    Pkcs1,
}

/// Server identity from two PEM files' bytes: a `CERTIFICATE` chain plus one key.
///
/// Tries `PRIVATE KEY`, then `EC PRIVATE KEY`, then `RSA PRIVATE KEY`, and takes
/// the first block that decodes; anything else is `TlsError::Other`, never a guess.
///
/// # Errors
///
/// When no certificate block decodes or no recognized key block decodes.
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

/// Every DER payload under a PEM label, in order.
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
        if let Ok(der) = base64_decode(body.as_bytes()) {
            out.push(der);
        }
        rest = tail;
    }
    out
}

/// Standard-base64 value, `None` outside the alphabet.
fn b64val(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Standard base64, ignoring ASCII whitespace; `=` ends the input.
fn base64_decode(text: &[u8]) -> Result<Vec<u8>, TlsError> {
    let bad = || TlsError::Other("base64 block is not standard base64".to_owned());
    let clean: Vec<u8> = text
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if clean.is_empty() || !clean.len().is_multiple_of(4) {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    for group in clean.as_chunks::<4>().0 {
        let mut pad = 0usize;
        let mut vals = [0u8; 4];
        for (slot, &b) in vals.iter_mut().zip(group.iter()) {
            if b == b'=' {
                pad += 1;
            } else {
                if pad > 0 {
                    return Err(bad());
                }
                *slot = b64val(b).ok_or_else(bad)?;
            }
        }
        if pad > 2 {
            return Err(bad());
        }
        let word = (u32::from(vals[0]) << 18)
            | (u32::from(vals[1]) << 12)
            | (u32::from(vals[2]) << 6)
            | u32::from(vals[3]);
        out.push((word >> 16) as u8);
        if pad < 2 {
            out.push((word >> 8) as u8);
        }
        if pad < 1 {
            out.push(word as u8);
        }
    }
    Ok(out)
}

mod rustls_backend;
pub use rustls_backend::{RustlsProvider, RustlsServerProvider};

pub mod reality;
pub use reality::{RealityServer, RealityServerConfig};

/// Open a client session over `io`.
///
/// # Errors
///
/// Anything [`TlsProvider::handshake`] could return, plus a configuration the
/// stack rejected before any I/O.
pub fn connect<S: Stream>(cfg: &TlsConfig, io: S) -> Result<impl TlsProvider + use<S>, TlsError> {
    RustlsProvider::connect(cfg, io)
}

/// Accept a server session over `io`, without starting the handshake.
///
/// # Errors
///
/// If the identity is rejected before any I/O; a bad network surfaces from
/// [`TlsProvider::handshake`] instead, so it is never a bad config.
pub fn accept<S: Stream + Send>(
    cfg: &TlsServerConfig,
    io: S,
) -> Result<impl TlsProvider + Send + use<S>, TlsError> {
    RustlsServerProvider::accept(cfg, io)
}

/// The stack compiled into this build.
///
/// Used by benchmarks and reports to name the stack a number came from, so a
/// measurement can never be read without knowing what produced it.
pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}
