//! The lane against the real service: sign in, mint, read the published
//! catalogue, and try every carrier against one edge of the pinned country.
//!
//! Everything here is an `#[ignore]`d test because it needs a Firefox account
//! and a network, and everything it prints is safe metadata — a country, an
//! edge, a status, a byte count. No token, no header, no password: the pass is
//! read out of the account and never formatted. The credentials come from the
//! environment, which is where CI puts its repository secrets:
//!
//! ```text
//! FOXY_EMAIL  the account to sign in with
//! FOXY_PASS   its password
//! FOXY_CODE   the emailed two-factor code, when the account asks for one
//! FOXY_COUNTRY the country to pin, United States when nothing says otherwise
//! ```
//!
//! What it answers is the question the loopback cannot: which carriers the edge
//! actually speaks, and whether QUIC is one of them.

use crate::foxy::{Carrier, FoxyDial, Tunnel};
use crate::foxy_account::{Account, Auth, Endpoint};
use crate::foxy_challenge::Jar;
use ferrox_core::foxy::Pass;
use std::io::{Read, Write};
use std::net::ToSocketAddrs as _;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const PROBE_HOST: &str = "api.ipify.org";
const PROBE_PATH: &str = "/";
const TRACE_HOST: &str = "www.cloudflare.com";
const TRACE_PATH: &str = "/cdn-cgi/trace";
const READ: Duration = Duration::from_secs(20);

fn account() -> Option<Account> {
    let roots = crate::quic::system_roots();
    Some(Account {
        fxa: Endpoint::parse(ferrox_core::foxy::account::FXA_SERVER, roots.clone())?,
        guardian: Endpoint::parse(ferrox_core::foxy::account::GUARDIAN_SERVER, roots)?,
        jar: std::sync::Arc::new(Mutex::new(Jar::default())),
        pending: std::sync::Arc::new(Mutex::new(None)),
        auth: std::sync::Arc::new(Mutex::new(Auth {
            access_token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
        })),
        pass: std::sync::Arc::new(Mutex::new(Pass {
            token: String::new(),
            expires_at: None,
            quota_remaining: None,
            quota_reset: None,
        })),
    })
}

/// One request through the tunnel, read back as its head: the tunnel is opaque
/// bytes to whoever dials it, which is the whole claim being made.
fn through_tunnel<T: Read + Write>(tunnel: &mut T, host: &str, path: &str) -> Option<String> {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tunnel.write_all(request.as_bytes()).ok()?;
    tunnel.flush().ok()?;
    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let deadline = Instant::now() + READ;
    while !head.windows(4).any(|pair| pair == b"\r\n\r\n") && Instant::now() < deadline {
        match tunnel.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(read) => head.extend_from_slice(&chunk[..read]),
        }
    }
    String::from_utf8(head).ok()
}

fn opened<T: Read + Write>(tunnel: &mut T, country: &str) -> Option<String> {
    let trace = through_tunnel(tunnel, TRACE_HOST, TRACE_PATH)?;
    let seen = crate::foxy::exit_country(trace.as_bytes())?;
    (seen.eq_ignore_ascii_case(country) || seen == "T1" || country == "REC").then_some(seen)
}

/// One carrier against one edge: the CONNECT, a request through it, and the
/// country it exits in. Everything it prints is what a reader needs to tell an
/// edge that refused from a network that could not reach it.
fn try_carrier(
    carrier: Carrier,
    edge: &ferrox_core::foxy::Candidate,
    pass: &Pass,
    country: &str,
) -> Result<String, String> {
    let dial = FoxyDial {
        host: edge.host.clone(),
        port: edge.port,
        address: None,
        carrier,
        roots: crate::quic::system_roots(),
        pins: ferrox_core::foxy::pin::Pins::default(),
        pass: pass.clone(),
    };
    let quic_dial = crate::quic::QuicDial {
        id: [0u8; 16],
        host: edge.host.clone(),
        address: edge.host.clone(),
        port: edge.port,
        roots: None,
    };
    let started = Instant::now();
    let quic = match carrier {
        Carrier::H3 => crate::quic::pooled_stream(&quic_dial),
        _ => None,
    };
    let stream = quic.as_ref().map(|(_, _, _, id)| *id);
    let mut tunnel = Tunnel::open(&dial, &format!("{PROBE_HOST}:80"), quic)
        .map_err(|failure| failure.to_string())?;
    let ip = through_tunnel(&mut tunnel, PROBE_HOST, PROBE_PATH)
        .ok_or_else(|| "no answer through the tunnel".to_owned())?;
    let seen = opened(&mut tunnel, country);
    if let (Some(id), Carrier::H3) = (stream, carrier) {
        crate::quic::release_stream(&quic_dial, id);
    }
    Ok(format!(
        "{} {} in {:?}, exit {}",
        ip.split_whitespace().last().unwrap_or("?"),
        edge.authority(),
        started.elapsed(),
        seen.unwrap_or_else(|| "unread".to_owned())
    ))
}

/// Signs in, mints a pass, reads the catalogue, and tries every carrier in the
/// order `auto` prefers them against the first edge of the pinned country.
///
/// The verdict is the carrier list: a lane whose every carrier is refused is a
/// lane this slice has not finished, and the run says so rather than exiting
/// quietly green.
#[test]
#[ignore = "needs a Firefox account and the network; run by foxy-live.yml"]
fn the_lane_carries_a_tunnel_on_the_carrier_the_edge_answers() {
    let email = std::env::var("FOXY_EMAIL").unwrap_or_default();
    let password = std::env::var("FOXY_PASS").unwrap_or_default();
    let country = std::env::var("FOXY_COUNTRY").unwrap_or_else(|_| "US".to_owned());
    assert!(
        !email.is_empty(),
        "FOXY_EMAIL is the account to sign in with"
    );
    assert!(!password.is_empty(), "FOXY_PASS is its password");

    println!("trust anchors read: {}", crate::quic::system_roots().len());
    let Some(account) = account() else {
        panic!("the account plane URLs are not the ones this tree knows");
    };
    account.sign_in(&email, &password).expect("signs in");
    if account.needs_code() {
        let code = std::env::var("FOXY_CODE").expect("FOXY_CODE is the emailed code");
        account.verify_code(&code).expect("verifies");
    }
    account.renew().expect("mints a pass");
    let pass = account.current();
    assert!(
        pass.token.len() > 32,
        "the pass is a token and not a refusal"
    );
    println!("pass minted, quota left {:?}", pass.quota_remaining);

    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let picked = ferrox_core::foxy::catalog::tier(&edges, &country, "", 3);
    assert!(
        !picked.is_empty(),
        "the catalogue publishes no edge for {country}"
    );
    let edge = &picked[0];
    println!(
        "country {country} edge {} city {} of {} published",
        edge.authority(),
        edge.city,
        edges.len()
    );

    let mut answered = Vec::new();
    for carrier in crate::foxy::carrier("auto").order() {
        match try_carrier(carrier, edge, &pass, &country) {
            Ok(report) => {
                println!("{carrier:?} {report}");
                answered.push(format!("{carrier:?}"));
                break;
            }
            Err(why) => println!("{carrier:?} refused: {why}"),
        }
    }
    assert!(
        !answered.is_empty(),
        "no carrier opened a tunnel to {country} (edge {})",
        edge.authority()
    );
}

/// The one thing the QUIC lane cannot be checked without: whether an edge names
/// a UDP port at all. The catalogue's `connect` entry is TCP, so a QUIC dial has
/// to use the same authority over UDP, and this reports what answered.
#[test]
#[ignore = "needs the network; run by foxy-live.yml"]
fn the_quic_lane_reaches_the_edge_over_udp_or_says_why_not() {
    let country = std::env::var("FOXY_COUNTRY").unwrap_or_else(|_| "US".to_owned());
    let edges = crate::foxy_catalog::edges(crate::quic::system_roots());
    let picked = ferrox_core::foxy::catalog::tier(&edges, &country, "", 1);
    let Some(edge) = picked.first() else {
        panic!("the catalogue publishes no edge for {country}");
    };
    let dial = crate::quic::QuicDial {
        id: [0u8; 16],
        host: edge.host.clone(),
        address: edge.host.clone(),
        port: edge.port,
        roots: None,
    };
    // The same authority over TCP, so a failure names the protocol rather than
    // the address: a host that answers CONNECT and ignores QUIC is a different
    // answer from a host that answers neither.
    let peer = format!("{}:{}", edge.host, edge.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next());
    let tcp = peer
        .and_then(|peer| std::net::TcpStream::connect_timeout(&peer, Duration::from_secs(10)).ok());
    println!(
        "tcp to {}: {}",
        edge.authority(),
        if tcp.is_some() { "answered" } else { "refused" }
    );
    match crate::quic::pooled_stream(&dial) {
        Some(_) => println!("h3 handshake completed with {}", edge.authority()),
        None => println!("no h3 handshake with {} over udp/{}", edge.host, edge.port),
    }
}
