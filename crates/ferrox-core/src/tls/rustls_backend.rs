//! The `rustls` backend.
//!
//! Configuration, handshake and record path are all rustls's; nothing here
//! reimplements or wraps them. The job of this module is to turn a
//! [`TlsConfig`] into rustls's own types, to map rustls's errors onto
//! [`TlsError`] without inventing detail, and to hold the transport so a caller
//! can treat this like any other byte stream.

use super::{Stream, TlsConfig, TlsError, TlsProvider};
use std::io::{Read, Write};
use std::sync::Arc;

type RootStore = rustls::RootCertStore;

/// A client session on `rustls`.
pub struct RustlsProvider<S: Stream> {
    conn: rustls::ClientConnection,
    io: S,
}

/// Hand-written rather than derived: `derive(Debug)` would demand `S: Debug`, and
/// the whole point of `S` being any `Read + Write` is that it need not be.
///
/// The negotiated parameters are printed and the transport is not, because a
/// stream's `Debug` may be a formatter for a socket, a file or a test double, and
/// one of those is a reasonable thing to log while the others are not.
impl<S: Stream> std::fmt::Debug for RustlsProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsProvider")
            .field("alpn", &self.conn.alpn_protocol())
            .field("is_handshaking", &self.conn.is_handshaking())
            .finish_non_exhaustive()
    }
}

impl<S: Stream> RustlsProvider<S> {
    /// Build the stack's configuration from the backend-neutral one.
    ///
    /// The provider is passed explicitly rather than installed globally. rustls
    /// keeps a process-wide default, and a component that reads the global one
    /// would depend on whichever component happened to be initialised first —
    /// which is the difference between a benchmark that compares stacks and one
    /// that compares whichever stack won a race.
    fn config(cfg: &TlsConfig) -> Result<Arc<rustls::ClientConfig>, TlsError> {
        // `add` rather than `add_parsable_certificates`: these are anchors the
        // caller chose deliberately, so one that does not parse is a
        // configuration error worth reporting rather than a certificate to skip.
        let mut roots = RootStore::empty();
        for der in &cfg.roots {
            roots
                .add(rustls::pki_types::CertificateDer::from(der.as_slice()))
                .map_err(|e| TlsError::BadCertificate.with_detail(format!("trust anchor: {e}")))?;
        }

        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_root_certificates(roots);

        let mut config = builder.with_no_client_auth();
        config.alpn_protocols.clone_from(&cfg.alpn);
        Ok(Arc::new(config))
    }

    /// Open a client session over `io`, without starting the handshake.
    ///
    /// # Errors
    ///
    /// If the configuration or the server name is rejected. No I/O happens here,
    /// so a failure is a programming error rather than a network condition.
    pub fn connect(cfg: &TlsConfig, io: S) -> Result<Self, TlsError> {
        let name = rustls::pki_types::ServerName::try_from(cfg.server_name.clone())
            .map_err(|e| TlsError::Other(format!("rustls server name: {e}")))?;
        let conn =
            rustls::ClientConnection::new(Self::config(cfg)?, name).map_err(|e| map_error(&e))?;
        Ok(Self { conn, io })
    }

    /// Finish the handshake, reading and writing on the transport until it is
    /// done.
    fn drive(&mut self) -> Result<(), TlsError> {
        while self.conn.is_handshaking() {
            if let Err(e) = self.conn.complete_io(&mut self.io) {
                return Err(recover(e));
            }
        }
        // Leaving the loop is what flushes rustls' post-handshake key update,
        // which must happen before plaintext may be written. `complete_prior_io`
        // is only reachable through rustls' own `Stream` wrapper, which this
        // module does not use because it would put a second stream type between
        // the caller and the record path.
        Ok(())
    }

    /// The transport, once the handshake is done.
    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

impl<S: Stream> TlsProvider for RustlsProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        // Read from the provider, in the provider's own order. Writing this list
        // out by hand would be a claim about rustls rather than a report of it.
        rustls::crypto::ring::ALL_CIPHER_SUITES
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.drive()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }
}

impl<S: Stream> Read for RustlsProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.drive()?;
            match self.conn.reader().read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.conn.complete_io(&mut self.io).map_err(recover)?;
                }
                outcome => return outcome,
            }
        }
    }
}

impl<S: Stream> Write for RustlsProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        let len = self.conn.writer().write(buf)?;
        // Push records now, like `rustls::Stream`: buffered plaintext the peer never
        // receives is a hang wearing a successful write. Errors surface on flush.
        let _ = self.conn.complete_io(&mut self.io);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        self.conn.writer().flush()?;
        self.conn.complete_io(&mut self.io).map_err(recover)?;
        Ok(())
    }
}

/// A server session on `rustls`, built from the config files' identity.
pub struct RustlsServerProvider<S: Stream> {
    conn: rustls::ServerConnection,
    io: S,
}

/// Hand-written rather than derived, for the same transport reason as the client.
impl<S: Stream> std::fmt::Debug for RustlsServerProvider<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsServerProvider")
            .field("alpn", &self.conn.alpn_protocol())
            .field("is_handshaking", &self.conn.is_handshaking())
            .finish_non_exhaustive()
    }
}

impl<S: Stream> RustlsServerProvider<S> {
    /// Accept with one certificate chain and no ALPN gate, so a client that offers
    /// none handshakes and offered protocols are ignored rather than refused.
    ///
    /// # Errors
    ///
    /// If the identity is rejected. No I/O happens here.
    pub fn accept(cfg: &super::TlsServerConfig, io: S) -> Result<Self, TlsError> {
        use super::ServerKeyKind as Kind;
        let certs: Vec<rustls::pki_types::CertificateDer<'_>> = cfg
            .cert_chain
            .iter()
            .map(|der| rustls::pki_types::CertificateDer::from(der.clone()))
            .collect();
        let key = match cfg.key_kind {
            Kind::Pkcs8 => rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(cfg.key_der.clone()),
            ),
            Kind::Sec1 => rustls::pki_types::PrivateKeyDer::Sec1(
                rustls::pki_types::PrivateSec1KeyDer::from(cfg.key_der.clone()),
            ),
            Kind::Pkcs1 => rustls::pki_types::PrivateKeyDer::Pkcs1(
                rustls::pki_types::PrivatePkcs1KeyDer::from(cfg.key_der.clone()),
            ),
        };
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError::Other(format!("rustls protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Other(format!("rustls server identity: {e}")))?;
        let conn = rustls::ServerConnection::new(Arc::new(config)).map_err(|e| map_error(&e))?;
        Ok(Self { conn, io })
    }

    /// Finish the handshake, reading and writing on the transport until it is done.
    ///
    /// A read wait is a retry, not a refusal: the relay arms its socket with one,
    /// so a slow peer pauses the handshake rather than failing it.
    fn drive(&mut self) -> Result<(), TlsError> {
        while self.conn.is_handshaking() {
            if let Err(error) = self.conn.complete_io(&mut self.io) {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) {
                    continue;
                }
                return Err(recover(error));
            }
        }
        Ok(())
    }

    /// The transport underneath, for a caller that needs the socket itself.
    pub fn get_ref(&self) -> &S {
        &self.io
    }
}

impl<S: Stream> TlsProvider for RustlsServerProvider<S> {
    fn name() -> &'static str {
        "rustls"
    }

    fn suites(&self) -> Vec<String> {
        // Same report as the client: one stack, one list, read from the provider.
        rustls::crypto::ring::ALL_CIPHER_SUITES
            .iter()
            .map(|cs| format!("{:?}", cs.suite()))
            .collect()
    }

    fn handshake(&mut self) -> Result<(), TlsError> {
        self.drive()
    }

    fn alpn(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }
}

impl<S: Stream> Read for RustlsServerProvider<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            self.drive()?;
            match self.conn.reader().read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.conn.complete_io(&mut self.io).map_err(recover)?;
                }
                outcome => return outcome,
            }
        }
    }
}

impl<S: Stream> Write for RustlsServerProvider<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.drive()?;
        let len = self.conn.writer().write(buf)?;
        // Same push as the client: the relay writes once per chunk and never flushes.
        let _ = self.conn.complete_io(&mut self.io);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.drive()?;
        self.conn.writer().flush()?;
        self.conn.complete_io(&mut self.io).map_err(recover)?;
        Ok(())
    }
}

/// Recover the backend's classification from a transport error.
///
/// rustls wraps protocol errors in an `InvalidData` I/O error carrying itself
/// as the source, so the classification `map_error` computes is recoverable
/// without string matching; anything else keeps the transport mapping.
fn recover(e: std::io::Error) -> TlsError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        if let Some(inner) = e.get_ref().and_then(|s| s.downcast_ref::<rustls::Error>()) {
            return map_error(inner);
        }
    }
    TlsError::from(e)
}

/// Map a rustls error onto the backend-neutral set.
///
/// rustls exposes its causes as enum variants, so this is a real mapping rather
/// than a string match, and every variant it defines in the pinned version is
/// listed so that the classification is deliberate and reviewable rather than
/// whatever the last arm happened to catch.
///
/// # The wildcard is a real limitation
///
/// `rustls::Error` is `#[non_exhaustive]`, so the trailing `_` arm is mandatory.
/// That means a *new* rustls variant would land in `Other` instead of failing the
/// build — including a new certificate error, which is the case most likely to be
/// added and the one a caller most wants classified. So this mapping is re-read
/// when rustls is bumped, which is why the classification table lives in
/// `docs/function/tls-provider.md` rather than only here.
///
/// `TlsError::Timeout` is unreachable from this arm and reaches the caller through
/// [`TlsError`]'s `From<io::Error>` impl instead: rustls surfaces a timeout as the
/// transport's `io::Error`, not as a protocol error.
fn map_error(e: &rustls::Error) -> TlsError {
    use rustls::Error as E;
    match e {
        // Everything rustls can say about a chain it refused to trust.
        E::InvalidCertificate(_)
        | E::InvalidCertRevocationList(_)
        | E::NoCertificatesPresented
        | E::UnsupportedNameType => TlsError::BadCertificate,

        // Nothing mutually negotiable, as suites or as ALPN, bare or alerted.
        E::NoApplicationProtocol
        | E::AlertReceived(rustls::AlertDescription::NoApplicationProtocol)
        | E::PeerIncompatible(_)
        | E::PeerMisbehaved(_)
        | E::BadMaxFragmentSize => TlsError::NoSharedCipher,

        // A record that made no sense, or arrived after the handshake ended.
        // Grouped as `Closed` because the actionable response is the same: this
        // connection is finished, and writing more plaintext onto it will not help.
        E::DecryptError
        | E::EncryptError
        | E::InvalidMessage(_)
        | E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::HandshakeNotComplete
        | E::PeerSentOversizedRecord
        // A close_notify is how a peer hangs up politely, so it belongs with the
        // cases whose only correct response is to stop using the connection.
        | E::AlertReceived(rustls::AlertDescription::CloseNotify) => TlsError::Closed,

        // Any other alert is a refusal rather than a hangup, reported as such so a
        // caller can tell "the peer said no" from "the peer left".
        E::AlertReceived(other) => TlsError::Other(format!("rustls alert: {other:?}")),

        E::FailedToGetCurrentTime
        | E::FailedToGetRandomBytes
        | E::InvalidEncryptedClientHello(_)
        | E::InconsistentKeys(_)
        | E::General(_)
        | E::Other(_) => TlsError::Other(format!("rustls: {e:?}")),

        // Mandatory: `rustls::Error` is `#[non_exhaustive]`.
        _ => TlsError::Other(format!("rustls: unmapped error {e:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// Self-signed P-256 leaf for `tls.test`, valid to 2066; generated once
    /// with openssl and embedded so the test needs no network, no CA and no clock.
    const ANCHOR: &[u8] = &[
        0x30, 0x82, 0x01, 0x6c, 0x30, 0x82, 0x01, 0x11, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x6d, 0x8e, 0xc2, 0xf5, 0x42, 0x91, 0xda, 0xdb, 0x05, 0xc9, 0xb2, 0x00, 0x71, 0x8b, 0xfb,
        0x6a, 0x20, 0xf4, 0xa1, 0xf8, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
        0x74, 0x6c, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x31,
        0x30, 0x30, 0x33, 0x31, 0x32, 0x34, 0x38, 0x30, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x30, 0x36,
        0x36, 0x30, 0x39, 0x32, 0x33, 0x31, 0x32, 0x34, 0x38, 0x30, 0x32, 0x5a, 0x30, 0x13, 0x31,
        0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08, 0x74, 0x6c, 0x73, 0x2e, 0x74,
        0x65, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        0xe7, 0xc8, 0xba, 0x65, 0x0f, 0xe6, 0x76, 0xe9, 0x05, 0x43, 0xd0, 0x8a, 0x63, 0xd4, 0xc4,
        0xee, 0x19, 0x31, 0xbb, 0x2d, 0x39, 0xce, 0xd1, 0xb1, 0x9a, 0xc7, 0x5a, 0xf1, 0x34, 0x98,
        0x5e, 0xe4, 0x87, 0x83, 0xfe, 0x38, 0x68, 0x71, 0xbc, 0xef, 0xfa, 0x47, 0x67, 0x10, 0x69,
        0x58, 0x0b, 0x2c, 0xc5, 0xa5, 0xc8, 0xcf, 0xba, 0x0a, 0x7a, 0x8e, 0x14, 0x7d, 0x97, 0x3e,
        0xef, 0x18, 0x38, 0x94, 0xa3, 0x41, 0x30, 0x3f, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x1d, 0x11,
        0x04, 0x17, 0x30, 0x15, 0x82, 0x08, 0x74, 0x6c, 0x73, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x82,
        0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30, 0x1d, 0x06, 0x03, 0x55,
        0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x04, 0x37, 0x6a, 0x70, 0x40, 0x98, 0x48, 0xaf, 0x75,
        0xc5, 0xa8, 0x24, 0x77, 0xca, 0xe1, 0x2c, 0x0d, 0xf1, 0xee, 0x5a, 0x30, 0x0a, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21,
        0x00, 0xae, 0x33, 0xd8, 0x61, 0xdc, 0x06, 0xf9, 0x8b, 0x76, 0x18, 0xe9, 0xe7, 0x5d, 0xe2,
        0x57, 0x8e, 0x84, 0x33, 0x43, 0x0a, 0x43, 0x7b, 0x7b, 0xb9, 0x05, 0xa3, 0xd8, 0x27, 0xfd,
        0xa4, 0x51, 0x2e, 0x02, 0x21, 0x00, 0xda, 0x81, 0x2e, 0x43, 0x7c, 0xf6, 0xe8, 0x0a, 0x09,
        0x47, 0xb4, 0x81, 0x81, 0xa2, 0x38, 0x17, 0x55, 0x0f, 0xeb, 0x95, 0x8b, 0x66, 0x78, 0x21,
        0x05, 0x95, 0xb1, 0xf2, 0xe1, 0x67, 0x0d, 0x3e,
    ];

    /// Its PKCS#8 private key.
    const ANCHOR_KEY: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x32, 0x0d, 0x8c, 0x13, 0x2e, 0x2a, 0x61, 0x40, 0xf4,
        0x9c, 0x2b, 0xa1, 0x5a, 0x13, 0x8c, 0x28, 0xef, 0xcc, 0x66, 0x47, 0xde, 0xdd, 0x5a, 0x6d,
        0x60, 0x5e, 0x01, 0x73, 0xda, 0x6a, 0x21, 0x0a, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xe7,
        0xc8, 0xba, 0x65, 0x0f, 0xe6, 0x76, 0xe9, 0x05, 0x43, 0xd0, 0x8a, 0x63, 0xd4, 0xc4, 0xee,
        0x19, 0x31, 0xbb, 0x2d, 0x39, 0xce, 0xd1, 0xb1, 0x9a, 0xc7, 0x5a, 0xf1, 0x34, 0x98, 0x5e,
        0xe4, 0x87, 0x83, 0xfe, 0x38, 0x68, 0x71, 0xbc, 0xef, 0xfa, 0x47, 0x67, 0x10, 0x69, 0x58,
        0x0b, 0x2c, 0xc5, 0xa5, 0xc8, 0xcf, 0xba, 0x0a, 0x7a, 0x8e, 0x14, 0x7d, 0x97, 0x3e, 0xef,
        0x18, 0x38, 0x94,
    ];

    /// Client config trusting only the anchor, offering the test ALPN.
    fn client(name: &str, alpn: &[&[u8]]) -> TlsConfig {
        TlsConfig {
            server_name: name.to_owned(),
            alpn: alpn.iter().map(|p| p.to_vec()).collect(),
            roots: vec![ANCHOR.to_vec()],
        }
    }

    /// Loopback server speaking the anchor cert and requiring one ALPN.
    fn serve(listener: &TcpListener) {
        let cert = rustls::pki_types::CertificateDer::from(ANCHOR.to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ANCHOR_KEY.to_vec()),
        );
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("server versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server cert");
        config.alpn_protocols = vec![b"test-only".to_vec()];
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut conn = rustls::ServerConnection::new(Arc::new(config)).expect("server session");
        let mut tls = rustls::Stream::new(&mut conn, &mut stream);
        let mut buf = [0u8; 4];
        if tls.read_exact(&mut buf).is_err() {
            return;
        }
        let _ = tls.write_all(&buf);
    }

    /// Run one handshake case against a bound loopback server.
    fn case(dial: impl FnOnce(TcpStream)) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| serve(&listener));
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            dial(stream);
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn handshake_connects_and_echoes() {
        case(|stream| {
            let mut client = crate::tls::connect(&client("tls.test", &[b"test-only"]), stream)
                .expect("configures");
            client.handshake().expect("handshakes");
            assert_eq!(client.alpn(), Some(b"test-only".as_slice()));
            assert!(client.suites().len() > 1);
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn mismatched_certificate_name_fails() {
        case(|stream| {
            let mut client = crate::tls::connect(&client("wrong.test", &[b"test-only"]), stream)
                .expect("configures");
            let err = client.handshake().expect_err("wrong name must fail");
            assert!(matches!(err, TlsError::BadCertificate));
        });
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn refused_alpn_fails() {
        case(|stream| {
            let mut client =
                crate::tls::connect(&client("tls.test", &[b"nope"]), stream).expect("configures");
            let err = client.handshake().expect_err("refused ALPN must fail");
            assert!(
                matches!(err, TlsError::NoSharedCipher),
                "refused ALPN mapped to {err:?}"
            );
        });
    }

    /// PEM framing for DER bytes, the shape the identity parser must read back.
    fn anchor_pem(label: &str, der: &[u8]) -> Vec<u8> {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut body = String::new();
        for chunk in der.chunks(3) {
            let mut word = 0u32;
            for &byte in chunk {
                word = (word << 8) | u32::from(byte);
            }
            word <<= 8 * (3 - chunk.len());
            for i in 0..=chunk.len() {
                body.push(TABLE[((word >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
            for _ in chunk.len() + 1..4 {
                body.push('=');
            }
        }
        let mut pem = format!("-----BEGIN {label}-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
            pem.push('\n');
        }
        pem.push_str("-----END ");
        pem.push_str(label);
        pem.push_str("-----\n");
        pem.into_bytes()
    }

    #[cfg_attr(
        miri,
        ignore = "needs a loopback socket, and ring's assembly behind it"
    )]
    #[test]
    fn server_accepts_through_the_interface_and_echoes() {
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        let key_pem = anchor_pem("PRIVATE KEY", ANCHOR_KEY);
        let identity = crate::tls::parse_pem_identity(&cert_pem, &key_pem).expect("parses");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::scope(|scope| {
            scope.spawn(|| {
                let (stream, _) = listener.accept().expect("accepts");
                let mut server = crate::tls::accept(&identity, stream).expect("accepts");
                server.handshake().expect("handshakes");
                assert_eq!(server.alpn(), None);
                let mut buf = [0u8; 4];
                server.read_exact(&mut buf).expect("reads");
                server.write_all(&buf).expect("writes");
                server.flush().expect("flushes");
            });
            let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut client =
                crate::tls::connect(&client("tls.test", &[]), stream).expect("configures");
            client.handshake().expect("handshakes");
            client.write_all(b"ping").expect("writes");
            client.flush().expect("flushes");
            let mut buf = [0u8; 4];
            client.read_exact(&mut buf).expect("reads");
            assert_eq!(&buf, b"ping");
        });
    }

    #[test]
    fn pem_identity_rejects_blocks_it_does_not_know() {
        assert!(crate::tls::parse_pem_identity(b"nothing here", b"nothing here").is_err());
        let cert_pem = anchor_pem("CERTIFICATE", ANCHOR);
        assert!(crate::tls::parse_pem_identity(&cert_pem, b"nothing here").is_err());
    }
}
