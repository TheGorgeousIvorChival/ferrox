//! `ferrox-app` — the `ZeroNet` application built on the released core.
//!
//! `ZeroNet` (MIT) pastes a `vless://` link and connects. This binary does the
//! same, through `ferrox-core` at its *released* version (`version = "0.1.0"`
//! in `Cargo.toml`, with a path fallback for a checkout). No `Xray-core`,
//! `sing-box`, `xray-rust`, `PattNG` or `ZeroNet` source is copied here: links are
//! parsed by `ferrox_core::vless`, whose parser was written from the
//! user-facing string format.
//!
//! What `run` does today (rung 1 of the transport matrix):
//!
//! 1. parses the link and reports its [`Support`] — planned transports print
//!    their reason instead of failing silently;
//! 2. checks TCP reachability to `host:port` with a timeout (no credentials
//!    are sent);
//! 3. encodes the `VLESS` request header locally with the zero-alloc
//!    `encode_into` and reports its length.
//!
//! The `REALITY` handshake itself is the next rung, not this one: claiming a
//! connection without it would be a lie the differential test cannot catch.
//! See `docs/arch/superset.md` for the order.

mod grpc;
mod httpheader;
mod httpupgrade;
mod json;
mod proxy;
mod quic;
mod shadowsocks;
mod vision;
mod vmess;
mod ws;
mod xhttp;

use ferrox_core::transport::Support;
use std::io::Write as _;
use std::time::Duration;

fn usage() -> ! {
    eprintln!("usage:");
    eprintln!("  ferrox-app check <vless://...>   parse + support + header len (no network)");
    eprintln!("  ferrox-app run <vless://...>     check + TCP reachability (sends nothing)");
    eprintln!("  ferrox-app version                print the serving binary's version");
    eprintln!("  ferrox-app x25519                 print a fresh X25519 keypair");
    eprintln!("  ferrox-app run -c <config.json>   serve inbounds until killed");
    std::process::exit(2);
}

/// Redacted summary: everything needed to route, nothing that authenticates.
fn describe(link: &ferrox_core::vless::VlessLink) -> String {
    format!(
        "host={} port={} type={} security={} flow={} support=[{}]",
        link.host,
        link.port,
        link.param("type"),
        link.param("security"),
        link.flow(),
        link.support(),
    )
}

fn cmd_check(link_str: &str) {
    let link = ferrox_core::vless::VlessLink::parse(link_str).unwrap_or_else(|e| {
        eprintln!("bad link: {e}");
        std::process::exit(1);
    });
    println!("{}", describe(&link));
    let hdr = link.encode_request_header("example.com", 443);
    println!(
        "header_len={} header_prefix={:02x?}",
        hdr.len(),
        &hdr[..8.min(hdr.len())]
    );
    match link.support() {
        Support::Implemented { method } => {
            println!("diallable: {method} (run checks tcp reachability; sends nothing)");
        }
        Support::Planned { reason } => println!("not yet diallable: {reason}"),
        Support::UnsafeRequiresOptIn { reason } => {
            println!("needs explicit opt-in (policy::UnsafeOptIn): {reason}");
        }
    }
}

fn cmd_run(link_str: &str) {
    let link = ferrox_core::vless::VlessLink::parse(link_str).unwrap_or_else(|e| {
        eprintln!("bad link: {e}");
        std::process::exit(1);
    });
    println!("{}", describe(&link));
    match link.support() {
        Support::Implemented { .. } => {}
        other => {
            eprintln!("refusing to dial: {other}");
            eprintln!("(parse succeeded; the transport rung is not implemented yet)");
            std::process::exit(3);
        }
    }
    let addr = format!("{}:{}", link.host, link.port);
    let sock: std::net::SocketAddr = if let Ok(sock) = addr.parse() {
        sock
    } else {
        // DNS name: resolve first, then connect to the first address.
        use std::net::ToSocketAddrs as _;
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut it| it.next())
            .unwrap_or_else(|| {
                eprintln!("cannot resolve {addr}");
                std::process::exit(1);
            })
    };
    let t0 = std::time::Instant::now();
    match std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(8)) {
        Ok(stream) => {
            let dt = t0.elapsed();
            println!("tcp reachable in {dt:?} (no bytes sent; session handshake is the next rung)");
            drop(stream);
        }
        Err(e) => {
            eprintln!("tcp unreachable: {e}");
            std::process::exit(4);
        }
    }
    let hdr = link.encode_request_header("example.com", 443);
    println!("header_len={} (encoded locally, not sent)", hdr.len());
    let _ = std::io::stdout().flush();
}

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    match cmd.as_str() {
        "check" => {
            let link = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            cmd_check(&link);
        }
        "run" => {
            let next = args.next().unwrap_or_else(|| usage());
            if next == "-c" || next == "-config" {
                let file = args.next().unwrap_or_else(|| usage());
                if args.next().is_some() {
                    usage();
                }
                proxy::serve_file(&file);
            }
            if args.next().is_some() {
                usage();
            }
            cmd_run(&next);
        }
        "version" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_version();
        }
        "x25519" => {
            if args.next().is_some() {
                usage();
            }
            proxy::print_x25519();
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    /// Server passwords sit beside `method`, not under `clients` like the other
    /// protocols: reading the wrong nesting derives a wrong subkey silently.
    #[test]
    fn shadowsocks_server_password_shape() {
        let root = crate::json::parse(
            r#"{"inbounds": [{"protocol": "shadowsocks", "settings": {"method": "aes-256-gcm",
            "password": "an-example-shared-password"}}]}"#,
        )
        .expect("parses");
        let inbound = &root
            .get("inbounds")
            .expect("inbounds")
            .as_arr()
            .expect("array")[0];
        assert_eq!(
            crate::proxy::inbound_ss_password(inbound),
            "an-example-shared-password"
        );
    }

    #[test]
    fn brief_link_checks() {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#x",
        )
        .expect("parses");
        assert!(link.is_first_method());
    }
}
