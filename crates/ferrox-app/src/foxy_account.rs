//! The HTTP the account needs: one JSON request, one JSON answer, on a TLS
//! connection this opens and closes per call.
//!
//! The account plane is four calls at connect time and one every few minutes,
//! so a connection per call is the smaller thing and costs nothing that matters.
//! Everything below the socket — the request line, the header folding, the
//! chunked body, the status taxonomy — is separated from the transport so it can
//! be proved over a pipe.

use ferrox_core::foxy::account::{self, Signed};
use ferrox_core::foxy::{Failure, Pass};
use ferrox_core::tls::{RustlsProvider, TlsConfig, TlsProvider as _};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const IO_TIMEOUT: Duration = Duration::from_secs(20);
const USER_AGENT: &str = "MozillaVPN/2.35.0 (sys:linux; iap:true)";
const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Denied {
    /// The access token or the account is not accepted: sign in again.
    Token,
    /// The account has no quota left, and the answer says when it resets.
    Quota,
    /// The edge is asking for a client it considers a bot. Named, not guessed.
    Challenged(u16),
    /// Anything else, with the status it came back as.
    Other(u16),
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Token => f.write_str("the account token was refused"),
            Self::Quota => f.write_str("the account has no quota left"),
            Self::Challenged(status) => {
                write!(f, "the edge answered {status} and asked for a challenge")
            }
            Self::Other(status) => write!(f, "the account plane answered {status}"),
        }
    }
}

impl Denied {
    /// The statuses that mean the same thing whatever the body said.
    #[must_use]
    pub(crate) fn of(status: u16) -> Option<Self> {
        match status {
            401 | 403 => Some(Self::Token),
            406 => Some(Self::Challenged(status)),
            429 => Some(Self::Quota),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Auth {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
    pub(crate) expires_at: u64,
}

impl Auth {
    #[must_use]
    pub(crate) fn valid_at(&self, now: u64) -> bool {
        self.expires_at.saturating_sub(now) > 60
    }
}

/// A response with its head and body already split, which is what every caller
/// here wants and what a chunked body needs before it can be read at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Reply {
    #[must_use]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    #[must_use]
    pub(crate) fn field(&self, name: &str) -> Option<String> {
        let text = String::from_utf8_lossy(&self.body);
        let needle = format!("\"{name}\":");
        let at = text.find(&needle)? + needle.len();
        let rest = &text[at..];
        let value = match rest.strip_prefix('"') {
            Some(quoted) => quoted.split('"').next().unwrap_or_default(),
            None => rest
                .trim_start_matches([' ', '\n', '\r', '\t'])
                .split(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .next()
                .unwrap_or_default(),
        };
        (!value.is_empty() && value != "null").then(|| value.to_owned())
    }

    #[must_use]
    pub(crate) fn header_number(&self, name: &str) -> Option<u64> {
        self.header(name)
            .and_then(|value| value.trim().parse().ok())
    }
}

/// One request's bytes: the line, the headers in the order they were given, the
/// body, and nothing else. No folding, no defaults, no guessing.
#[must_use]
pub(crate) fn request(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\nUser-Agent: ");
    out.extend_from_slice(USER_AGENT.as_bytes());
    out.extend_from_slice(b"\r\nAccept: application/json\r\nConnection: close\r\n");
    for (name, value) in headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

/// Reads one response: the head to the blank line, then the body by whichever
/// of the three shapes the head declares.
pub(crate) fn read_reply<S: Read>(io: &mut S) -> Result<Reply, Failure> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(Failure::Frame);
        }
        if io.read(&mut byte).map_err(|_| Failure::Stream)? == 0 {
            return Err(Failure::Stream);
        }
        head.push(byte[0]);
    }
    let lines: Vec<&[u8]> = head[..head.len() - 4].split(|b| *b == b'\n').collect();
    let status = lines
        .first()
        .and_then(|line| {
            let mut parts = line.split(|b| *b == b' ');
            let version = parts.next()?;
            let code = parts.next()?;
            (version.starts_with(b"HTTP/1.") && code.len() == 3)
                .then(|| String::from_utf8_lossy(code).parse::<u16>().ok())
                .flatten()
        })
        .ok_or(Failure::Frame)?;
    let mut headers = Vec::new();
    for line in &lines[1..] {
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        headers.push((
            String::from_utf8_lossy(&line[..colon]).trim().to_owned(),
            String::from_utf8_lossy(&line[colon + 1..])
                .trim()
                .to_owned(),
        ));
    }
    let body = read_body(io, &headers)?;
    Ok(Reply {
        status,
        headers,
        body,
    })
}

fn read_line<S: Read>(io: &mut S) -> Result<Vec<u8>, Failure> {
    let mut line = Vec::with_capacity(16);
    let mut byte = [0u8; 1];
    loop {
        match io.read(&mut byte).map_err(|_| Failure::Stream)? {
            0 => return Err(Failure::Stream),
            _ if byte[0] == b'\n' => return Ok(line),
            _ => {
                if byte[0] != b'\r' {
                    line.push(byte[0]);
                }
                if line.len() > 64 {
                    return Err(Failure::Frame);
                }
            }
        }
    }
}

fn read_body<S: Read>(io: &mut S, headers: &[(String, String)]) -> Result<Vec<u8>, Failure> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    if header("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case("chunked")) {
        let mut body = Vec::new();
        loop {
            let line = read_line(io)?;
            let size =
                usize::from_str_radix(std::str::from_utf8(&line).map_err(|_| Failure::Frame)?, 16)
                    .map_err(|_| Failure::Frame)?;
            if size == 0 {
                let _ = read_line(io);
                return Ok(body);
            }
            if body.len() + size > MAX_BODY {
                return Err(Failure::Frame);
            }
            let mut chunk = vec![0u8; size + 2];
            io.read_exact(&mut chunk).map_err(|_| Failure::Stream)?;
            body.extend_from_slice(&chunk[..size]);
        }
    }
    let len = header("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY);
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).map_err(|_| Failure::Stream)?;
    Ok(body)
}

/// The endpoint one account-plane host answers on, split into the name TLS
/// verifies and the address the socket opens: a name resolves itself, a pinned
/// address is the poison-proof dial and never becomes the TLS name.
#[derive(Debug, Clone)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) address: Option<SocketAddr>,
    pub(crate) roots: Vec<Vec<u8>>,
}

impl Endpoint {
    #[must_use]
    pub(crate) fn parse(url: &str, roots: Vec<Vec<u8>>) -> Option<Self> {
        let rest = url.strip_prefix("https://")?;
        let (host, port) = match rest.split_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (rest, 443),
        };
        Some(Self {
            host: host.to_owned(),
            port,
            address: None,
            roots,
        })
    }

    #[must_use]
    pub(crate) fn origin(&self) -> String {
        self.host.clone()
    }

    fn tls(&self) -> TlsConfig {
        TlsConfig {
            server_name: self.host.clone(),
            alpn: Vec::new(),
            roots: self.roots.clone(),
            pins: ferrox_core::foxy::pin::Pins::default(),
        }
    }

    fn connect(&self) -> Result<RustlsProvider<TcpStream>, Failure> {
        let peer = match self.address {
            Some(address) => address,
            None => format!("{}:{}", self.host, self.port)
                .to_socket_addrs()
                .map_err(|_| Failure::Io)?
                .next()
                .ok_or(Failure::Io)?,
        };
        let stream = TcpStream::connect_timeout(&peer, IO_TIMEOUT).map_err(|_| Failure::Io)?;
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        let mut tls = RustlsProvider::connect(&self.tls(), stream).map_err(|_| Failure::Io)?;
        tls.handshake().map_err(|_| Failure::Io)?;
        Ok(tls)
    }
}

use std::net::ToSocketAddrs as _;

/// Sends one signed or plain request to an endpoint and reads the answer.
pub(crate) fn call(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Reply, Denied> {
    let mut tls = endpoint.connect().map_err(|_| Denied::Other(0))?;
    tls.write_all(&request(method, &endpoint.origin(), path, headers, body))
        .and_then(|()| tls.flush())
        .map_err(|_| Denied::Other(0))?;
    read_reply(&mut tls).map_err(|_| Denied::Other(0))
}

/// The `FxA` login, tried without the two-factor method first when the account has
/// none enrolled: the error the first attempt earns is the reason to drop it.
pub(crate) fn login(
    endpoint: &Endpoint,
    email: &str,
    password: &str,
    timestamp: u64,
) -> Result<(String, bool), Denied> {
    let _ = timestamp;
    let stretched = account::auth_pw(email, password);
    for method in [Some("email-2fa"), None] {
        let body = account::login_body(email, &stretched, method);
        let reply = call(endpoint, "POST", "/account/login", &[], &body)?;
        if let Some(errno) = errno(&reply) {
            if errno == 107 && method.is_some() {
                continue;
            }
            return Err(Denied::Other(reply.status));
        }
        if let Some(denied) = Denied::of(reply.status) {
            return Err(denied);
        }
        let token = reply.field("sessionToken").ok_or(Denied::Token)?;
        return Ok((token, reply.field("verified").is_some_and(|v| v == "true")));
    }
    Err(Denied::Token)
}

fn errno(reply: &Reply) -> Option<u64> {
    reply
        .field("errno")
        .and_then(|value| value.trim().parse().ok())
}

/// The token exchange. The credentials grant is Hawk-signed with the session
/// token; the refresh grant is not signed at all, which is the difference the
/// two calls have between them.
pub(crate) fn token(
    endpoint: &Endpoint,
    session_token: Option<&str>,
    refresh_token: Option<&str>,
    nonce: &str,
    timestamp: u64,
) -> Result<Auth, Denied> {
    let body = match (session_token, refresh_token) {
        (Some(_), _) => account::token_body("fxa-credentials", None),
        (None, Some(refresh)) => account::token_body("refresh_token", Some(refresh)),
        (None, None) => return Err(Denied::Token),
    };
    let authorization = session_token.and_then(|session| {
        let (id, mac) = account::hawk_credentials(session)?;
        Some(
            Signed {
                method: "POST",
                path: "/oauth/token",
                host: &endpoint.origin(),
                port: endpoint.port,
                body: &body,
                timestamp,
                nonce,
            }
            .header(&id, &mac),
        )
    });
    let headers: [(&str, &str); 1] = [("Authorization", authorization.as_deref().unwrap_or(""))];
    let reply = call(endpoint, "POST", "/oauth/token", &headers, &body)?;
    if let Some(denied) = Denied::of(reply.status) {
        return Err(denied);
    }
    if reply.status != 200 {
        return Err(Denied::Other(reply.status));
    }
    let access_token = reply.field("access_token").ok_or(Denied::Token)?;
    let refresh_token = reply
        .field("refresh_token")
        .or_else(|| refresh_token.map(str::to_owned))
        .ok_or(Denied::Token)?;
    let ttl = reply
        .field("expires_in")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(86_400);
    Ok(Auth {
        access_token,
        refresh_token,
        expires_at: timestamp + ttl,
    })
}

/// The pass the tunnel carries, read out of the token response and the quota
/// headers that come with it.
pub(crate) fn pass(endpoint: &Endpoint, access_token: &str) -> Result<Pass, Denied> {
    let bearer = format!("Bearer {access_token}");
    let reply = call(
        endpoint,
        "GET",
        "/api/v1/fpn/token",
        &[
            ("Authorization", &bearer),
            ("Content-Type", "application/json"),
        ],
        b"",
    )?;
    if let Some(denied) = Denied::of(reply.status) {
        return Err(denied);
    }
    if reply.status != 200 {
        return Err(Denied::Other(reply.status));
    }
    let token = reply
        .field("token")
        .filter(|t| !t.is_empty())
        .ok_or(Denied::Token)?;
    let expires_at = reply
        .field("expires_at")
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|at| *at > 0)
        .or_else(|| account::jwt_expiry(&token));
    Ok(Pass {
        token,
        expires_at,
        quota_remaining: reply.header_number("X-Quota-Remaining"),
        quota_reset: reply.header_number("X-Quota-Reset"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn piped(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn a_request_carries_the_line_the_host_the_agent_and_the_length() {
        let raw = request(
            "POST",
            "api.accounts.firefox.com",
            "/account/login",
            &[("X-A", "1")],
            b"{}",
        );
        let text = String::from_utf8(raw).expect("ascii");
        assert!(
            text.starts_with("POST /account/login HTTP/1.1\r\nHost: api.accounts.firefox.com\r\n")
        );
        assert!(text.contains("\r\nUser-Agent: MozillaVPN/2.35.0 (sys:linux; iap:true)\r\n"));
        assert!(text.contains("\r\nAccept: application/json\r\n"));
        assert!(text.contains("\r\nX-A: 1\r\n"));
        assert!(text.ends_with("\r\nContent-Length: 2\r\n\r\n{}"));
    }

    #[test]
    fn a_reply_splits_its_head_from_a_content_length_body() {
        let raw = piped(b"HTTP/1.1 200 OK\r\nX-Quota-Limit: 10\r\nContent-Length: 5\r\n\r\nhello");
        let reply = read_reply(&mut raw.as_slice()).expect("reads");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("x-quota-limit"), Some("10"));
        assert_eq!(reply.header_number("X-Quota-Limit"), Some(10));
        assert_eq!(reply.body, b"hello");
    }

    #[test]
    fn a_chunked_body_is_reassembled_before_it_is_read() {
        let raw = piped(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let reply = read_reply(&mut raw.as_slice()).expect("reads");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"hello world");
    }

    #[test]
    fn a_reply_without_a_length_is_a_head_and_nothing_else() {
        let raw = piped(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n");
        let reply = read_reply(&mut raw.as_slice()).expect("reads");
        assert_eq!(reply.status, 407);
        assert_eq!(reply.body, Vec::new());
        assert_eq!(reply.header_number("X-Quota-Reset"), None);
    }

    #[test]
    fn a_head_that_is_not_a_reply_is_refused_rather_than_guessed() {
        for raw in [
            &b"garbage\r\n\r\n"[..],
            &b"HTTP/2 200\r\n\r\n"[..],
            &b"HTTP/1.1 20 OK\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK"[..],
        ] {
            assert!(read_reply(&mut &raw[..]).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn a_json_field_is_read_as_a_string_or_a_number_and_nothing_else() {
        let reply = Reply {
            status: 200,
            headers: Vec::new(),
            body: br#"{"token":"a.b.c","expires_at":1735689600,"maxBytes":null,"flag":true}"#
                .to_vec(),
        };
        assert_eq!(reply.field("token").as_deref(), Some("a.b.c"));
        assert_eq!(reply.field("expires_at").as_deref(), Some("1735689600"));
        assert_eq!(reply.field("maxBytes"), None, "a null is not a value");
        assert_eq!(reply.field("flag").as_deref(), Some("true"));
        assert_eq!(reply.field("absent"), None);
    }

    #[test]
    fn the_status_taxonomy_is_the_one_the_references_name() {
        assert_eq!(Denied::of(401), Some(Denied::Token));
        assert_eq!(Denied::of(403), Some(Denied::Token));
        assert_eq!(Denied::of(406), Some(Denied::Challenged(406)));
        assert_eq!(Denied::of(429), Some(Denied::Quota));
        assert_eq!(Denied::of(500), None);
        assert!(Denied::of(406)
            .expect("challenged")
            .to_string()
            .contains("challenge"));
    }

    #[test]
    fn an_access_token_is_stale_before_it_expires_rather_than_at_it() {
        let auth = Auth {
            access_token: "t".to_owned(),
            refresh_token: "r".to_owned(),
            expires_at: 1_000,
        };
        assert!(auth.valid_at(900));
        assert!(!auth.valid_at(940), "the clock skew margin");
        assert!(!auth.valid_at(1_000));
    }

    #[test]
    fn an_endpoint_names_itself_and_keeps_the_address_out_of_the_tls_name() {
        let endpoint = Endpoint::parse("https://vpn.mozilla.org", Vec::new()).expect("parses");
        assert_eq!(endpoint.host, "vpn.mozilla.org");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.address, None);
        assert_eq!(endpoint.origin(), "vpn.mozilla.org");
        let pinned = Endpoint {
            address: Some("127.0.0.1:443".parse().expect("addr")),
            ..endpoint.clone()
        };
        assert_eq!(
            pinned.host, "vpn.mozilla.org",
            "the pin dial keeps the name"
        );
        assert!(Endpoint::parse("http://vpn.mozilla.org", Vec::new()).is_none());
        assert!(Endpoint::parse("vpn.mozilla.org", Vec::new()).is_none());
        assert_eq!(
            Endpoint::parse("https://host:8443", Vec::new())
                .expect("parses")
                .port,
            8443
        );
    }
}

/// The whole account, from a sign-in to a pass, with the renewal on a clock the
/// dial already knows how to read.
#[derive(Debug, Clone)]
pub(crate) struct Account {
    pub(crate) fxa: Endpoint,
    pub(crate) guardian: Endpoint,
    pub(crate) auth: std::sync::Arc<std::sync::Mutex<Auth>>,
    pub(crate) pass: std::sync::Arc<std::sync::Mutex<Pass>>,
}

fn epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn nonce() -> String {
    let mut raw = [0u8; 6];
    getrandom::getrandom(&mut raw).unwrap_or_default();
    ferrox_core::b64::encode(&raw)
}

impl Account {
    /// Signs in, exchanges the session token, and mints the first pass.
    pub(crate) fn sign_in(&self, email: &str, password: &str) -> Result<(), Denied> {
        let now = epoch();
        let (session, _verified) = login(&self.fxa, email, password, now)?;
        let auth = token(&self.fxa, Some(&session), None, &nonce(), now)?;
        *self.auth.lock().map_err(|_| Denied::Token)? = auth.clone();
        self.mint(&auth.access_token)
    }

    pub(crate) fn mint(&self, access_token: &str) -> Result<(), Denied> {
        let minted = pass(&self.guardian, access_token)?;
        *self.pass.lock().map_err(|_| Denied::Token)? = minted;
        Ok(())
    }

    /// Refreshes the access token when it is stale and mints a new pass. The
    /// pass is rotated in place: every new flow reads the current one, and no
    /// tunnel is rebuilt to carry it.
    pub(crate) fn renew(&self) -> Result<(), Denied> {
        let stale = self
            .auth
            .lock()
            .map_or(true, |auth| !auth.valid_at(epoch()));
        let access_token = if stale {
            let current = self.auth.lock().map_err(|_| Denied::Token)?.clone();
            let now = epoch();
            let fresh = token(&self.fxa, None, Some(&current.refresh_token), &nonce(), now)?;
            let access = fresh.access_token.clone();
            *self.auth.lock().map_err(|_| Denied::Token)? = fresh;
            access
        } else {
            self.auth
                .lock()
                .map_err(|_| Denied::Token)?
                .access_token
                .clone()
        };
        self.mint(&access_token)
    }

    /// How long until the current pass wants replacing.
    pub(crate) fn renews_in(&self) -> std::time::Duration {
        self.pass
            .lock()
            .map_or(std::time::Duration::from_secs(240), |pass| {
                pass.renews_in(epoch())
            })
    }

    pub(crate) fn current(&self) -> Pass {
        self.pass.lock().map_or_else(
            |_| Pass {
                token: String::new(),
                expires_at: None,
                quota_remaining: None,
                quota_reset: None,
            },
            |pass| pass.clone(),
        )
    }
}

#[cfg(test)]
mod renewal {
    use super::*;

    fn account_with(pass: Pass) -> Account {
        Account {
            fxa: Endpoint::parse("https://api.accounts.firefox.com/v1", Vec::new())
                .expect("parses"),
            guardian: Endpoint::parse("https://vpn.mozilla.org", Vec::new()).expect("parses"),
            auth: std::sync::Arc::new(std::sync::Mutex::new(Auth {
                access_token: "a".to_owned(),
                refresh_token: "r".to_owned(),
                expires_at: 0,
            })),
            pass: std::sync::Arc::new(std::sync::Mutex::new(pass)),
        }
    }

    #[test]
    fn the_clock_a_pass_asks_for_is_the_one_the_core_wrote() {
        let account = account_with(Pass {
            token: "t".to_owned(),
            expires_at: Some(epoch() + 600),
            quota_remaining: None,
            quota_reset: None,
        });
        let want = account.current().renews_in(epoch());
        assert_eq!(account.renews_in(), want);
    }

    #[test]
    fn an_unknown_expiry_asks_for_the_four_minute_fallback() {
        let account = account_with(Pass {
            token: "t".to_owned(),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
        });
        assert_eq!(account.renews_in(), std::time::Duration::from_secs(240));
        assert_eq!(account.current().token, "t");
    }
}
