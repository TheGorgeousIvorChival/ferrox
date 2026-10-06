//! Share-link to per-engine client configs for the live speedtest.
//!
//! A speedtest hands every core the same job — dial this link, expose SOCKS,
//! move bytes — so the translation from `vless://` to each engine's dialect
//! lives in exactly one place, tested here. The configs necessarily contain
//! the link's secrets (a config without the UUID authenticates nothing), so
//! they are local files only: the renderer and the report never see them, and
//! [`secret_tokens`] names every substring the redaction validator must not
//! find anywhere else.
//!
//! Learned, not copied: neither pinned harness is transcribed. The field names
//! are each engine's own config schema at its pin (`sing-box/option/*.go`,
//! `xray-core/transport/internet/reality/config.proto`, the xray-rust config
//! compatibility doc), read the same way `parity::Dialect` was.

use ferrox_core::vless::VlessLink;

use crate::json::Json;

/// An engine the speedtest can drive, by config dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFamily {
    Ferrox,
    XrayCore,
    XrayRust,
    Zeronet,
    SingBox,
}

impl EngineFamily {
    /// Parse the `--engine` name the driver passes.
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "ferrox" => Ok(Self::Ferrox),
            "xray-core" => Ok(Self::XrayCore),
            "xray-rust" => Ok(Self::XrayRust),
            "zeronet" | "zray" => Ok(Self::Zeronet),
            "sing-box" | "singbox" => Ok(Self::SingBox),
            other => Err(format!(
                "unknown speedtest engine `{other}`: ferrox, xray-core, \
                 xray-rust, zeronet, sing-box"
            )),
        }
    }

    /// Whether this engine reads the sing-box (`type`-keyed) dialect.
    const fn is_singbox(self) -> bool {
        matches!(self, Self::SingBox)
    }
}

/// What the link must carry for a speedtest row to exist.
///
/// VLESS over TCP or WebSocket with `none`, `tls` or `reality` security and
/// no (or Vision) flow — except on `ferrox`, which dials raw TCP without
/// a security layer today (`vless_security_supported` in
/// `ferrox-app/src/proxy.rs`; the REALITY/Vision row there is the
/// server side). Anything else is a named refusal, not a silent omission: a
/// row the driver cannot build reads as "not attempted", which is a fact
/// about the matrix, not a gap in it. When the client rung lands, the
/// `Ferrox` arm below is what goes.
fn check_supported(link: &VlessLink, engine: EngineFamily) -> Result<(), String> {
    if engine == EngineFamily::Ferrox {
        if link.transport_kind() != ferrox_core::transport::TransportKind::Tcp {
            return Err("ferrox dials raw TCP only: the row sits out with this reason".into());
        }
        if !matches!(link.security(), ferrox_core::transport::Security::None) {
            return Err(
                "ferrox dials no security layer yet (REALITY/Vision is the \
                 server side only): the row sits out with this reason"
                    .into(),
            );
        }
        return Ok(());
    }
    match link.transport_kind() {
        ferrox_core::transport::TransportKind::Tcp
        | ferrox_core::transport::TransportKind::Ws => {}
        _ => {
            return Err(format!(
                "speedtest supports vless over tcp or ws, got type=`{}`",
                link.param("type")
            ));
        }
    }
    match link.security() {
        ferrox_core::transport::Security::None
        | ferrox_core::transport::Security::Tls
        | ferrox_core::transport::Security::Reality => {}
        _ => {
            return Err(format!(
                "speedtest supports security none/tls/reality, got `{}`",
                link.param("security")
            ));
        }
    }
    if link.wants_unsafe_fingerprint() {
        return Err("speedtest refuses unsafe fingerprints: re-run with an explicit opt-in".into());
    }
    if link.flow() != "none" && link.flow() != "xtls-rprx-vision" {
        return Err(format!(
            "speedtest supports flow none or xtls-rprx-vision, got `{}`",
            link.flow()
        ));
    }
    if matches!(link.security(), ferrox_core::transport::Security::Reality) {
        if link.reality_pbk().is_empty() {
            return Err("a reality link without `pbk` names no server key".into());
        }
        if link.sni().is_empty() {
            return Err("a reality link without `sni` names no server name".into());
        }
    }
    if matches!(link.security(), ferrox_core::transport::Security::Tls) && link.sni().is_empty() {
        return Err("a tls link without `sni` names no server name".into());
    }
    Ok(())
}

/// `#n remark | type= security= flow=`: the row label. The remark is the
/// link's own fragment (user-chosen display text); the UUID, keys and host
/// never appear — see [`secret_tokens`].
pub fn redacted_label(link: &VlessLink, index: usize) -> String {
    let remark = if link.name.is_empty() {
        "-".to_owned()
    } else {
        link.name.clone()
    };
    format!(
        "#{index} {remark} | type={} security={} flow={}",
        link.param("type"),
        link.param("security"),
        link.flow(),
    )
}

/// Every credential substring that must not appear outside the engine config
/// files: the account UUID and the REALITY key material. The redaction
/// validator fails the run on any of them in any other artefact.
pub fn secret_tokens(link: &VlessLink) -> Vec<String> {
    let mut out = vec![link.uuid.clone()];
    for key in ["pbk", "sid", "spx", "password"] {
        let value = link.param(key);
        if !value.is_empty() {
            out.push(value.to_owned());
        }
    }
    out
}

/// SOCKS inbound in the engine's dialect, on loopback.
fn socks_inbound(engine: EngineFamily, port: u16) -> Json {
    let mut inbound = Json::object();
    if engine.is_singbox() {
        inbound.insert("type", Json::Str("socks".into()));
        inbound.insert("tag", Json::Str("socks-in".into()));
        inbound.insert("listen", Json::Str("127.0.0.1".into()));
        inbound.insert("listen_port", Json::Num(f64::from(port)));
        inbound.insert("users", Json::Arr(Vec::new()));
    } else {
        inbound.insert("tag", Json::Str("harness-socks".into()));
        inbound.insert("protocol", Json::Str("socks".into()));
        inbound.insert("listen", Json::Str("127.0.0.1".into()));
        inbound.insert("port", Json::Num(f64::from(port)));
        let mut settings = Json::object();
        settings.insert("auth", Json::Str("noauth".into()));
        settings.insert("udp", Json::Bool(false));
        inbound.insert("settings", settings);
    }
    inbound
}

/// The VLESS remote in Xray-dialect JSON.
fn xray_outbound(link: &VlessLink) -> Json {
    let mut outbound = Json::object();
    outbound.insert("protocol", Json::Str("vless".into()));
    let mut user = Json::object();
    user.insert("id", Json::Str(link.uuid.clone()));
    user.insert(
        "encryption",
        Json::Str({
            let e = link.param("encryption");
            if e.is_empty() {
                "none".into()
            } else {
                e.into()
            }
        }),
    );
    if link.flow() != "none" {
        user.insert("flow", Json::Str(link.flow().into()));
    }
    let mut vnext = Json::object();
    vnext.insert("address", Json::Str(link.host.clone()));
    vnext.insert("port", Json::Num(f64::from(link.port)));
    vnext.insert("users", Json::Arr(vec![user]));
    let mut settings = Json::object();
    settings.insert("vnext", Json::Arr(vec![vnext]));
    outbound.insert("settings", settings);
    outbound.insert("streamSettings", xray_stream(link));
    outbound
}

/// `streamSettings` for the link's transport and security.
///
/// Field names are Xray-core's at its pin (`realitySettings.serverName`,
/// `publicKey`, `shortId`, `spiderX`). Certificate verification stays on for
/// `tls`: the handshake a user performs is the one measured, and a test
/// server with a broken chain fails loudly rather than silently downgraded.
fn xray_stream(link: &VlessLink) -> Json {
    let mut stream = Json::object();
    let network = if link.param("type") == "ws" {
        "ws"
    } else {
        "tcp"
    };
    stream.insert("network", Json::Str(network.into()));
    match link.security() {
        ferrox_core::transport::Security::Reality => {
            stream.insert("security", Json::Str("reality".into()));
            let mut reality = Json::object();
            reality.insert("serverName", Json::Str(link.sni().into()));
            if !link.fingerprint().is_empty() {
                reality.insert("fingerprint", Json::Str(link.fingerprint().into()));
            }
            reality.insert("publicKey", Json::Str(link.reality_pbk().into()));
            if !link.reality_sid().is_empty() {
                reality.insert("shortId", Json::Str(link.reality_sid().into()));
            }
            if !link.param("spx").is_empty() {
                reality.insert("spiderX", Json::Str(link.param("spx").into()));
            }
            stream.insert("realitySettings", reality);
        }
        ferrox_core::transport::Security::Tls => {
            stream.insert("security", Json::Str("tls".into()));
            let mut tls = Json::object();
            tls.insert("serverName", Json::Str(link.sni().into()));
            if !link.fingerprint().is_empty() {
                tls.insert("fingerprint", Json::Str(link.fingerprint().into()));
            }
            stream.insert("tlsSettings", tls);
        }
        _ => {}
    }
    if network == "tcp" {
        let mut tcp = Json::object();
        let mut header = Json::object();
        header.insert("type", Json::Str(link.param("headerType").into()));
        tcp.insert("header", header);
        stream.insert("tcpSettings", tcp);
    } else {
        let mut ws = Json::object();
        ws.insert("path", Json::Str(link.param("path").into()));
        if !link.param("host").is_empty() {
            let mut headers = Json::object();
            headers.insert("Host", Json::Str(link.param("host").into()));
            ws.insert("headers", headers);
        }
        stream.insert("wsSettings", ws);
    }
    stream
}

/// The VLESS remote in sing-box-dialect JSON.
///
/// `spiderX` has no sing-box field and is dropped: stated here so a row that
/// differs between dialects differs for a named reason, not a silent one.
fn singbox_outbound(link: &VlessLink) -> Json {
    let mut outbound = Json::object();
    outbound.insert("type", Json::Str("vless".into()));
    outbound.insert("server", Json::Str(link.host.clone()));
    outbound.insert("server_port", Json::Num(f64::from(link.port)));
    outbound.insert("uuid", Json::Str(link.uuid.clone()));
    if link.flow() != "none" {
        outbound.insert("flow", Json::Str(link.flow().into()));
    }
    match link.security() {
        ferrox_core::transport::Security::Reality => {
            let mut tls = Json::object();
            tls.insert("enabled", Json::Bool(true));
            tls.insert("server_name", Json::Str(link.sni().into()));
            if !link.fingerprint().is_empty() {
                let mut utls = Json::object();
                utls.insert("enabled", Json::Bool(true));
                utls.insert("fingerprint", Json::Str(link.fingerprint().into()));
                tls.insert("utls", utls);
            }
            let mut reality = Json::object();
            reality.insert("enabled", Json::Bool(true));
            reality.insert("public_key", Json::Str(link.reality_pbk().into()));
            if !link.reality_sid().is_empty() {
                reality.insert("short_id", Json::Str(link.reality_sid().into()));
            }
            tls.insert("reality", reality);
            outbound.insert("tls", tls);
        }
        ferrox_core::transport::Security::Tls => {
            let mut tls = Json::object();
            tls.insert("enabled", Json::Bool(true));
            tls.insert("server_name", Json::Str(link.sni().into()));
            if !link.fingerprint().is_empty() {
                let mut utls = Json::object();
                utls.insert("enabled", Json::Bool(true));
                utls.insert("fingerprint", Json::Str(link.fingerprint().into()));
                tls.insert("utls", utls);
            }
            outbound.insert("tls", tls);
        }
        _ => {}
    }
    if link.param("type") == "ws" {
        let mut transport = Json::object();
        transport.insert("type", Json::Str("ws".into()));
        transport.insert("path", Json::Str(link.param("path").into()));
        if !link.param("host").is_empty() {
            let mut headers = Json::object();
            headers.insert("Host", Json::Str(link.param("host").into()));
            transport.insert("headers", headers);
        }
        outbound.insert("transport", transport);
    }
    outbound
}

/// The whole client document: SOCKS in, the remote out. One outbound and no
/// routing section, so the default route (first outbound) is the tunnel.
pub fn engine_config(
    link: &VlessLink,
    engine: EngineFamily,
    socks_port: u16,
) -> Result<String, String> {
    check_supported(link, engine)?;
    let mut root = Json::object();
    root.insert(
        "inbounds",
        Json::Arr(vec![socks_inbound(engine, socks_port)]),
    );
    let outbound = if engine.is_singbox() {
        singbox_outbound(link)
    } else {
        xray_outbound(link)
    };
    root.insert("outbounds", Json::Arr(vec![outbound]));
    if engine.is_singbox() {
        root.insert("route", Json::object());
    }
    root.to_string()
}

/// `linkconfig` CLI: `--link URL --engine NAME --socks-port N` prints the
/// engine document; `--describe --index N` prints the redacted row label;
/// `--tokens` prints the credential substrings for the redaction validator.
/// Secrets never reach stdout except inside the engine document itself (which
/// is redirected to a file the renderer never reads) and the `--tokens` list
/// (which the driver captures into a variable, never a log).
pub fn run(args: &[String]) -> i32 {
    for arg in args {
        if arg.starts_with("--")
            && ![
                "--link",
                "--engine",
                "--socks-port",
                "--describe",
                "--index",
                "--tokens",
            ]
            .contains(&arg.as_str())
        {
            eprintln!("linkconfig: unknown argument `{arg}`");
            return 2;
        }
    }
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let Some(link_str) = flag("--link") else {
        eprintln!("linkconfig needs --link <vless://...>");
        return 2;
    };
    let parsed = match VlessLink::parse(&link_str) {
        Ok(link) => link,
        Err(e) => {
            eprintln!("linkconfig: bad vless link: {e}");
            return 2;
        }
    };
    if args.contains(&"--describe".to_owned()) {
        let index = flag("--index").and_then(|v| v.parse().ok()).unwrap_or(0);
        println!("{}", redacted_label(&parsed, index));
        return 0;
    }
    if args.contains(&"--tokens".to_owned()) {
        for token in secret_tokens(&parsed) {
            println!("{token}");
        }
        return 0;
    }
    let (Some(engine_name), Some(port_str)) = (flag("--engine"), flag("--socks-port")) else {
        eprintln!("linkconfig needs --engine <name> --socks-port <port>");
        return 2;
    };
    let family = match EngineFamily::parse(&engine_name) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("linkconfig: {e}");
            return 2;
        }
    };
    let Ok(socks_port) = port_str.parse::<u16>() else {
        eprintln!("linkconfig: bad --socks-port `{port_str}`");
        return 2;
    };
    match engine_config(&parsed, family, socks_port) {
        Ok(doc) => {
            println!("{doc}");
            0
        }
        Err(e) => {
            eprintln!("linkconfig: {e}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic REALITY link: TEST-NET address, example SNI, made-up key
    /// material. Never a real credential (`scripts/check-fixture-safety.sh`
    /// enforces the address rule; the rule for keys is this comment).
    fn reality_link() -> VlessLink {
        VlessLink::parse(
            "vless://11111111-2222-4333-8444-555555555555@198.51.100.7:443\
             ?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             &fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=abcdef01#fixture",
        )
        .expect("the synthetic link parses")
    }

    fn doc_text(link: &VlessLink, engine: EngineFamily) -> String {
        engine_config(link, engine, 10801).expect("the synthetic link builds")
    }

    #[test]
    fn every_engine_builds_a_reality_config() {
        let link = reality_link();
        // Ferrox is absent on purpose: it sits reality out with the rung
        // reason (`ferrox_sits_out_what_it_cannot_dial` holds that side).
        for engine in [
            EngineFamily::XrayCore,
            EngineFamily::XrayRust,
            EngineFamily::Zeronet,
            EngineFamily::SingBox,
        ] {
            let doc = doc_text(&link, engine);
            let root = crate::json::parse(&doc).expect("the config is JSON");
            assert!(root.get("inbounds").is_some(), "{engine:?} names inbounds");
            assert!(
                root.get("outbounds").is_some(),
                "{engine:?} names outbounds"
            );
        }
    }

    #[test]
    fn the_xray_config_carries_the_reality_handshake() {
        let doc = doc_text(&reality_link(), EngineFamily::XrayCore);
        for needle in [
            "xtls-rprx-vision",
            "realitySettings",
            "serverName",
            "example.com",
            "fingerprint",
            "chrome",
            "publicKey",
            "shortId",
            "198.51.100.7",
        ] {
            assert!(doc.contains(needle), "the config names {needle}");
        }
    }

    #[test]
    fn the_singbox_config_is_type_keyed() {
        let doc = doc_text(&reality_link(), EngineFamily::SingBox);
        for needle in [
            "\"type\":\"vless\"",
            "server_name",
            "example.com",
            "public_key",
            "short_id",
            "listen_port",
        ] {
            assert!(doc.contains(needle), "the config names {needle}");
        }
        assert!(
            !doc.contains("realitySettings"),
            "no Xray spelling leaks in"
        );
    }

    #[test]
    fn the_redacted_label_names_no_secret() {
        let link = reality_link();
        let label = redacted_label(&link, 3);
        assert!(label.starts_with("#3"), "{label}");
        for secret in secret_tokens(&link) {
            assert!(!label.contains(&secret), "the label leaks a secret");
        }
        let described = crate::compare::describe_redacted(&link);
        for secret in secret_tokens(&link) {
            assert!(
                !described.contains(&secret),
                "the report line leaks a secret"
            );
        }
    }

    #[test]
    fn refusals_name_their_reason() {
        // No public key on a reality link.
        let no_pbk = VlessLink::parse(
            "vless://11111111-2222-4333-8444-555555555555@198.51.100.7:443\
             ?security=reality&encryption=none&fp=chrome&type=tcp\
             &flow=xtls-rprx-vision&sni=example.com&sid=abcdef01#x",
        )
        .expect("parses");
        assert!(engine_config(&no_pbk, EngineFamily::XrayCore, 10801)
            .expect_err("no pbk is refused")
            .contains("pbk"));
        // Wrong transport.
        let quic = VlessLink::parse(
            "vless://11111111-2222-4333-8444-555555555555@198.51.100.7:443\
             ?security=none&encryption=none&type=quic#x",
        )
        .expect("parses");
        assert!(engine_config(&quic, EngineFamily::XrayCore, 10801)
            .expect_err("quic is refused")
            .contains("tcp or ws"));
        // Unsafe fingerprint.
        let mut unsafe_fp = reality_link();
        unsafe_fp.params.insert("fp".into(), "unsafe-chrome".into());
        assert!(engine_config(&unsafe_fp, EngineFamily::XrayCore, 10801)
            .expect_err("unsafe fp is refused")
            .contains("unsafe"));
        // Unknown engine.
        assert!(EngineFamily::parse("quiche").is_err());
    }

    #[test]
    fn ferrox_sits_out_what_it_cannot_dial() {
        // REALITY is the server side only: a skip with the rung reason,
        // not a red row for a handshake that was never attempted.
        let err = engine_config(&reality_link(), EngineFamily::Ferrox, 10801)
            .expect_err("ferrox does not dial reality");
        assert!(err.contains("server side only"), "{err}");
        // Plain TCP to loopback dials.
        let plain = VlessLink::parse(
            "vless://11111111-2222-4333-8444-555555555555@127.0.0.1:443\
             ?security=none&encryption=none&type=tcp#x",
        )
        .expect("parses");
        engine_config(&plain, EngineFamily::Ferrox, 10801).expect("plain tcp dials");
    }
}
