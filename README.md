# Ferrox

FERROX — Fast Efficient Relay Router Overlay X. *ferro*, iron, for Rust; *X*, for Xray.

A from-scratch proxy core, built to be **bit-identical to the implementations it replaces** and **verifiably not slower than any of them**.

## Goals

1. **Prove everything shipped is faster and leaner.** Bit-identical output, fewer operations, zero surviving copies, no allocation. Counts prove, durations suggest: instruction counts are gated exact, so a diff that removes one operation changes a number every runner reproduces.
2. **Be a drop-in replacement for Xray-core.** Not "implement its protocols" — run its pinned test suites unmodified against a Ferrox binary in CI, plus every suite with a seam to inject it through.
3. **Be a drop-in replacement for zeptun**, the `tun2socks` engine: TUN to TCP/UDP/ICMP through a SOCKS5 or direct handler, `userspace` / `hybrid` / `system` stacks.
4. **Be feature-complete in what quiche, slipstream and aether are ahead on.** QUIC and MASQUE, DNS-tunnel carriers, nested tunnels, multi-path schedulers, domain fronting. Libraries and product surfaces, read for the technique and implemented on Ferrox's terms.
5. **Spoof SNI without root.** DPI circumvention by injecting a fake TLS ClientHello with an allowlisted SNI ahead of the real handshake. `VpnService` TUN plus a userspace TCP stack does it in user space. Nothing in CI checks this yet.

## How it is built

- **One algorithm, four widths.** The record layer is one generic function over a `Lanes` trait — portable arrays, NEON, SSE2, AVX2 — so backends execute the *same source* and cannot disagree. The portable path is safe Rust, so Miri interprets the ladder and the SIMD modules stay five instructions each whose only failure mode is a wrong answer.
- **Rewrite, not port.** The minimal subset covering the matrix, proven faster down to the parsing. One line of comment per item at most, no changelogs — checked by `scripts/check-comments.sh`. The shared protocol is `crates/ferrox-prompt/prompts.md`.
- **Counts prove, durations suggest.** Instruction counts are gated exact; allocation counts, copy counts and syscall counts are gated exactly too, and each method page names the checker for every number it states. A count nobody has measured is written `UNBLESSED`, which is a claim that is open, not a number.
- **One TLS stack, one interface.** `TlsProvider` is implemented by rustls, and the provider *is* `Read + Write`, so nothing above can depend on the stack underneath. No feature to select, no build without TLS.
- **quiche is the default QUIC, not a preference.** Whenever a rung needs QUIC and quiche is feasible, quiche; anything else must name the rung, the library, and the measurement that won.
- **The reference is not as fast as it looks.** Comparators often ship SIMD behind a cfg nothing sets, so part of any speedup is the baseline not using its path. Every report prints both backends in the header; a ratio quoted without both names is not a measurement.
- **Lints and operation counts are local; nothing connection-dependent is.** `./scripts/check.sh` before every push: fmt, clippy, docs, the policy checks, the exact instruction counts against `scripts/expected-ops.txt`, the prompt library, the tests. What needs a connection is CI-only — every developer machine is behind a VPN and a proxy, so a local benchmark measures a tunnel and a local conformance run measures somebody's exit node.
- **Nothing runs on a merge.** A merge cannot break what a pull request did not already prove, so every gate fires on the PR and `main` is covered by schedules: benches daily (one hour apart, so they never read each other's load as a regression), Miri weekly across six runners, pins and the dependency graph only when their inputs change.

## What is checked

| claim | checked by |
| --- | --- |
| compiles | `ci.yml`: `cargo test --workspace` on linux x86_64, macos aarch64, windows x86_64; clippy clean |
| bit-identical output | differential test against the pinned reference, run *before* any timing |
| no use-after-free, no leak | Miri nightly for safe-Rust paths; differential tests for SIMD |
| no allocation, no zero-fill | counting global allocator, gated at exactly 0 |
| no work generated and discarded | the ladder returns its blocks; gate 2 compares against `ceil(len / 64)` at every length and offset |
| no operation added or removed | exact instruction counts, `scripts/count-ops.sh` against `scripts/expected-ops.txt` — same number on every machine, so this one runs before the push |
| not slower at any measured length ≥ 65 B | benchmark gate; 1–64 B are a tie by construction, identity-checked only. One regressing length fails the job, after a re-measure |
| upstream conformance | pinned upstream suites run unmodified against `ferrox-app` |
| parsers never panic on untrusted bytes | seeded cases over every untrusted entry point, printed on failure so a red run replays anywhere |
| dependency licence and provenance | `deny.toml` + `scripts/check-dependency-policy.sh`; GPL/AGPL comparators are refused as dependencies |
| roadmap coherence | `ferrox-prompt check`: no duplicate id, no gate-less slice, no cycle, no renamed `**Touches:**` path |
| every method page's counts match one manifest | `scripts/check-method-docs.sh` against `scripts/method-counts.txt` — a number edited in a page without editing the manifest fails, and a manifest row with no page fails |

Not claimed: that this is the fastest implementation. A benchmark measures a configuration at a point in time and decays. What is built instead is the machinery that notices.

```bash
./scripts/check.sh    # fmt, clippy, docs, policy checks, operation counts, prompt library, tests
```

That is what `ci.yml` runs. Running it first is how a lint stops costing a queue.

## Method pages

Every connection method this tree implements has a page under
[`docs/function/`](docs/function). Each one carries the same four numbers —
**ops** (retired instructions), **syscalls**, **memory copies**, and **time** —
each with the name of the checker that produces it, a `graph TD` of the data
path, and what was removed against Xray-core, sing-box and ZeroNet.

Every number in those tables is a row in
[`scripts/method-counts.txt`](scripts/method-counts.txt), and
`scripts/check-method-docs.sh` fails if a page and that file disagree. That is
the whole mechanism: a count that is not in the manifest is not a claim, and a
claim with no checker is not made.

| method | page | syscalls | copies per byte | ops | time |
| --- | --- | --- | --- | --- | --- |
| record layer (ChaCha20) | [record-layer](docs/function/record-layer.md) | 0 | 0 (in place) | `UNBLESSED` | not measured |
| Shadowsocks AEAD | [shadowsocks](docs/function/shadowsocks.md) | **1 write per 16 KiB read**, 2 reads per chunk | 1 written, **0** read | `UNBLESSED` | not measured |
| VMess AEAD | [vmess](docs/function/vmess.md) | **1 write per 32 KiB read** (4 frames) | 1 written, **0** read | `UNBLESSED` | not measured |
| VLESS TCP | [vless](docs/function/vless.md) | 1 write per header, 0 framing after | 1 (the relay's own) | `UNBLESSED` | not measured |
| Trojan TCP | [trojan](docs/function/trojan.md) | 1 write per header, 0 framing after | 1 (the relay's own) | `UNBLESSED` | not measured |
| XTLS Vision | [xtls-vision](docs/function/xtls-vision.md) | 0 framing after the switch | **2** framed, **0** after the switch | `UNBLESSED` | not measured |
| Mux.Cool + XUDP | [mux-cool](docs/function/mux-cool.md) | 1 write per frame | **0** written, 1 read | `UNBLESSED` | not measured |
| WebSocket | [carrier-websocket](docs/function/carrier-websocket.md) | **1 read per 32 KiB window** (64 frames), 1 write per frame | 0 unmasked write, 1 masked | `UNBLESSED` | not measured |
| HTTPUpgrade | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | 1 read, 1 write | 1 (the relay's own) | `UNBLESSED` | not measured |
| HTTP masquerade | [carrier-httpheader](docs/function/carrier-httpheader.md) | 1 read, 1 write | 1 (the relay's own) | `UNBLESSED` | not measured |
| gRPC | [carrier-grpc](docs/function/carrier-grpc.md) | 1 write per message | 1 written, 1 read | `UNBLESSED` | not measured |
| xHTTP | [carrier-xhttp](docs/function/carrier-xhttp.md) | 1 write per chunk | 1 written | `UNBLESSED` | not measured |
| QUIC | [carrier-quic](docs/function/carrier-quic.md) | 1 handshake per server | quiche's | `UNBLESSED` | not measured |
| REALITY / TLS | [reality-tls](docs/function/reality-tls.md) | per handshake, rustls | per handshake, rustls | `UNBLESSED` | not measured |
| KCP | [kcp](docs/function/kcp.md) | 1 sendto per segment | in place | `UNBLESSED` | not measured |

Two columns read "not measured" on every row, and that is the honest state
rather than a gap in the table:

- **ops.** `scripts/expected-ops.txt` still blesses exactly one symbol in the
  whole tree, `der_to_pem 2653`, and it is a PEM formatting helper rather than a
  carrier. `scripts/method-ops.txt` is the open list: `ops.yml` measures every
  symbol on it on every run and publishes the numbers as the `method-ops`
  artefact, which is what turns a row from `UNBLESSED` into a number somebody
  can read and decide to bless. Blessing one means reading the diff that moved
  it, never copying a measurement to silence the gate.
- **time.** Every duration in this repository comes from a named runner:
  `bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml` and
  `benchmark-matrix.yml`. A number produced off a laptop behind a VPN is a
  measurement of the tunnel, so no page quotes one that no CI artefact has
  produced. The gates that *are* deterministic — allocation counts, copy counts,
  syscall counts — are gated, and those are the numbers the pages lead with.

## Connection methods

**Every method below parses.** A row is only as good as what a binary does with it, and there are two separate answers, so the table carries both:

| column | meaning |
| --- | --- |
| `link` | what `VlessLink::support()` reports — `Implemented`, `Planned { reason }` or `UnsafeRequiresOptIn { reason }` (`crates/ferrox-core/src/transport.rs:301`). This is a verdict about the *shape of the link*, computed offline. |
| `binary` | what `ferrox-app` actually dials or serves from a config — the only axis a connection ever exercises. |

They are not the same, and where they differ the table says so. `Support::Planned` exists because a cell that says why is evidence and a blank cell is not, so nothing here is silently dropped: a refusal always carries its reason string, which is the whole reason the refusal is worth reading.

`ferrox-app run <vless://…>` is deliberately *not* a dialler: it refuses unless the link is `Implemented`, then opens one TCP connection, reports the time and sends nothing. Real traffic goes through `run -c config.json`, which binds inbounds (`vless`, `trojan`, `vmess`, `shadowsocks`, `socks`) and needs a `freedom` outbound. `check <vless://…>` is fully offline.

### A — proxy protocols (the share-link world)

Every implemented row links to its page: the counts, the data-path graph, and
what was removed against the three pinned implementations live there, not here.
This table is the verdict; the page is the evidence.

| # | method | link | binary | page | notes |
| --- | --- | --- | --- | --- | --- |
| 1 | VLESS TCP REALITY `xtls-rprx-vision` | `vless-tcp-reality-vision` | **server only** | [vless](docs/function/vless.md) · [xtls-vision](docs/function/xtls-vision.md) · [reality-tls](docs/function/reality-tls.md) | Server role is complete: `shortId`/`X25519` auth (`crates/ferrox-core/src/tls/reality.rs:197`), Vision framing (`crates/ferrox-app/src/vision.rs`), over raw + gRPC + ws + xhttp + httpUpgrade + http header (`proxy.rs:1078`). No `dest`/`show` fallback, by design. The **client is not wired**: an outbound is only accepted when `security` is empty or `none` (`proxy.rs:4262`), so a REALITY outbound is skipped rather than dialled. `run` opens TCP and drops it. |
| 2 | VLESS TCP TLS (Vision optional) | planned — *"parses, dials after the reality rung lands"* | **server only** | [reality-tls](docs/function/reality-tls.md) | Serves `streamSettings.tlsSettings.certificates[0].{certificateFile,keyFile}` through rustls (`proxy.rs:991`, `proxy.rs:1443`), PEM in PKCS8/SEC1/PKCS1 (`tls/mod.rs:94`), Vision optional on `flow`. A rustls **client** role exists in core (`tls/mod.rs:199`) and is exercised by core tests; no config path dials it. |
| 3 | VLESS TCP none, private/loopback only | `vless-tcp-none` | implemented | [vless](docs/function/vless.md) | Both roles, TCP + UDP both directions, plus Mux: client `proxy.rs:1555`, server `proxy.rs:538`. Reachable only for hosts that fail `is_public_host` (`transport.rs:280`) — that check is the gate, not a heuristic. |
| 4 | VLESS/TROJAN `security=none` to public (PattNG ext.) | unsafe opt-in — *"security=none to a public address (`PattNG` extension): explicit opt-in required"* | refused | — | `Support::UnsafeRequiresOptIn`, `check` exits 3. The flag type exists (`policy.rs:17`, `UnsafeOptIn::allow_plaintext_to_public`) and nothing constructs it yet: the gate is parse-level only, so it has never been exercised with consent. |
| 5 | TROJAN TCP | *no `trojan://` link parser* | implemented, plaintext | [trojan](docs/function/trojan.md) | Both roles over raw + ws + httpUpgrade + gRPC + xhttp + http header, TCP and UDP (`proxy.rs:2283`, `proxy.rs:2074`). **`security` is never read** for trojan outbounds (`proxy.rs:3961`), so this row is plaintext TCP with a password — an earlier README here claimed "TROJAN TCP TLS" and was wrong. UDP is raw-carrier only. |
| 6 | VMess TCP (AEAD) | — (config-driven) | implemented | [vmess](docs/function/vmess.md) | Both roles; ciphers `aes-128-gcm` → AES-GCM, `chacha20-ietf-poly1305`/`chacha20-poly1305` → ChaCha, `none`/unknown → Auto = ChaCha (`vmess.rs:19`). UDP both roles, **raw carrier only** (`proxy.rs:1643` refuses anything else). Carriers implemented for VMess too: raw, ws, xhttp, http header, httpUpgrade, gRPC (`vmess.rs:1091`–`1185`). |
| 7 | Shadowsocks TCP/UDP | — (config-driven) | implemented | [shadowsocks](docs/function/shadowsocks.md) | `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` plus the Xray spellings (`shadowsocks.rs:17`); key length 16/32. **MD5 chain only** (`MasterKey::new`, `shadowsocks.rs:183`) — `2022-blake3-aes-256-gcm`, xchacha and rc4-md5 are rejected by name (`shadowsocks.rs:239`). UDP both roles, raw carrier only, per-datagram salt. |
| 8 | VLESS over ws | `vless-ws` | implemented | [carrier-websocket](docs/function/carrier-websocket.md) | Both roles (`proxy.rs:1491`, `proxy.rs:444`); TLS and REALITY layered underneath (`proxy.rs:1012`, `proxy.rs:1108`). |
| 9 | VLESS over xhttp | `vless-xhttp` | implemented, one mode | [carrier-xhttp](docs/function/carrier-xhttp.md) | Both roles. One mode only: POST plus `Transfer-Encoding: chunked` (`xhttp.rs:264`) — padding and placement rules per mode are not implemented. A slice in `prompts.md` still says this carrier has no implementation; that line is stale. |
| 10 | VLESS over gRPC | `vless-grpc` | implemented | [carrier-grpc](docs/function/carrier-grpc.md) | Both roles, full HTTP/2 + HPACK, `T_DATA`/`T_HEADERS`/`T_SETTINGS` (`grpc.rs`, 1292 lines). Path built as `/<service>/Tun`, default `/Tun` (`proxy.rs:4175`). |
| 11 | VLESS over httpUpgrade | `vless-httpupgrade` | implemented | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | Both roles (`proxy.rs:1502`, `proxy.rs:462`). |
| 12 | VLESS http masquerade / header | `vless-tcp` | implemented | [carrier-httpheader](docs/function/carrier-httpheader.md) | Both roles (`proxy.rs:1541`, `proxy.rs:516`); selected by `tcpSettings.header.type == "http"` (`proxy.rs:4206`). |
| 13 | VLESS over QUIC | `vless-quic` | client only | [carrier-quic](docs/function/carrier-quic.md) | Dial + pool, one handshake per server (`quic.rs:591`, `quic.rs:671`), quiche with ALPN `h3`, roots required from `caCertFile` — without them the dial returns `None` (`quic.rs:206`). The **server role is refused** (`refused_carriers!`, `proxy.rs:534`). Reached only from a SOCKS inbound without Mux. |
| 14 | KCP / mKCP | `vless-kcp` | implemented, TCP only | [kcp](docs/function/kcp.md) | Both roles for VLESS, VMess, Trojan and Shadowsocks over plaintext KCP, plus VLESS over KCP under TLS and REALITY (`proxy.rs` `serve_*_kcp`/`dial_*_kcp`); `kcpSettings` (`mtu`, `tti`, capacities, multiplier, window, both casings) parsed into `kcp::Config` (`proxy.rs` `kcp_config`). The core rung stays oracle-proven against pinned Go `xray-core/transport/internet/kcp` (`kcp/oracle.rs`). UDP and Mux stay raw-carrier-only tree-wide, so they refuse KCP like every other carrier. |
| 15 | `?ed=N` early data, ws | — | implemented, both roles | [carrier-websocket](docs/function/carrier-websocket.md) | One parse for both roles (`transport::EarlyData`), one allocation per encode; client adds the `Sec-WebSocket-Protocol` line (`ws.rs:435`), server decodes and replays it (`ws.rs:384`). |
| 16 | `?ed=N` early data, httpUpgrade | — | parsed, **not carried** | [carrier-httpupgrade](docs/function/carrier-httpupgrade.md) | `?ed=N` is stripped from the path (`proxy.rs:4146`) and the budget is a path-level test only (`httpupgrade.rs:109`); nothing sends or decodes early data on this carrier. The earlier README's "both roles" was true for ws only. |
| 17 | `cipherSuites` (PattNG ext.) | — | **not parsed** | — | Never read anywhere in `crates/`; survives only as an opaque entry of `VlessLink.params`. Parsed-but-carried was the claim; carried is not true. |
| 18 | `unsafe-*` fingerprints (PattNG ext.) | unsafe opt-in — *"unsafe fingerprint requested: re-run with explicit opt-in"* | refused | [reality-tls](docs/function/reality-tls.md) | `fp` starting `unsafe-`, or `allowUnsafeFp=1` (`vless.rs:90`). There is no uTLS or ClientHello shaping in this tree at all, so nothing would be spoofed even if consent were given. |
| 19 | Hysteria | planned — *"parses, dial needs its own QUIC stack and congestion glue"* | refused | — | Name only: `TransportKind::Hysteria` and `Carrier::Hysteria`, both in the refused set. |
| 20 | MASQUE CONNECT-IP (RFC 9484) | planned — *"parses, dial needs a QUIC stack"* | refused | [carrier-quic](docs/function/carrier-quic.md) | Name only: `TransportKind::Masque`, `Carrier::Masque`. quiche is pinned as the default stack for this rung when it lands. |
| 21 | TUIC / AnyTLS / ShadowTLS / Snell / Naive / SSH / OpenConnect / OpenVPN | parse to `TransportKind::Other` — *"unknown type: parses, transport not scheduled"* | refused | — | Zero occurrences in `crates/`. They are refused by falling into `Other`, not by a hand-written list, so there is no per-protocol reason string to quote for them. |
| 22 | Mux / XUDP / `multi` | — | implemented, **raw carrier only** | [mux-cool](docs/function/mux-cool.md) | The codec is complete — `Status`/`Network`/`Target`/`Outgoing`/`Incoming`, `global_id`, `CHUNK_MAX` (`mux.rs`) — and it is wired in both roles when `mux.enabled` is true. XUDP rides the mux: a `Network::Udp` target opens a UDP socket keyed by the frame's `global_id`, datagrams arrive as `Keep` frames carrying their own destination, and replies return as `Keep` frames carrying their source. The client sends one XUDP session per SOCKS association instead of dialling a carrier per destination. Both roles encode the mux request the way upstream does — command 3, no address (`vless_mux_header`) — so a real Xray peer agrees on the wire; `KeepAlive` is a no-op and the cap is `DEFAULT_CAP` 8 sessions. |

### B — PattNG in full (what the fork wires)

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 23 | `PROXYCHAIN` ordered member list | planned (see chaining) | PattNG only — at most one `AETHER` member per chain |
| 24 | `POLICYGROUP` / routing groups | planned | PattNG only |
| 25 | Psiphon as its own program (`AETHER_PSIPHON_BIN`) | planned | PattNG, mlmvpn |
| 26 | Pluggable transports via lyrebird (`obfs4`/`snowflake`/`webtunnel`/`meek`) | planned | PattNG, Aether |
| 27 | hev-socks5-tunnel TUN (`libhev-socks5-tunnel.so`) | planned | PattNG |

### C — VPN / tunnel carriers

| # | method | state | supported today by |
| --- | --- | --- | --- |
| 28 | WireGuard (UDP) | planned | Xray-core, sing-box, Aether, PattNG, ZeroNet WARP paths, mlmvpn |
| 29 | AmneziaWG | planned | amneziawg-go, amnezia-client, mlmvpn |
| 30 | MASQUE CONNECT-IP over QUIC | planned, quiche by default | mqvpn, Aether, sing-box, Xray-core, PattNG, configer |
| 31 | MASQUE over HTTP/3 vs HTTP/2 carriers | planned | Aether, mqvpn, configer |
| 32 | Multipath QUIC (`draft-ietf-quic-multipath`) | planned | mqvpn, slipstream, quiche |
| 33 | quiche itself: QUIC + HTTP/3, 0-RTT, migration, key updates, batched datagram I/O | provider, not a lane — in use for row 13 | quiche pin |
| 34 | Multipath schedulers `minrtt` / `wlb` / `wlb_udp_pin` / `backup-fec` | planned | mqvpn |
| 35 | Hybrid TCP lane (local termination over an H3 stream) | planned | mqvpn |
| 36 | Reorder buffer + reinjection (`deadline` / `idle` / `dgram`) | planned | mqvpn |
| 37 | Nested WireGuard (`gool`, two hops) | planned | Aether |
| 38 | Nested MASQUE (`mim`, tunnel in a tunnel) | planned | Aether |
| 39 | TCP-over-DNS covert channel (base32 domain + TXT) | planned | slipstream |
| 40 | Multi-resolver parallel + port-53 impersonation, DCUBIC/BBR | planned | slipstream |
| 41 | tun2socks engine (TUN → TCP/UDP/ICMP; `userspace`/`hybrid`/`system`) | planned — zeptun, one device away from row 3 | zeptun |

### D — DNS-tunnel ways (learned from CottenDNS / MasterDnsVPN, not pinned)

Custom ARQ, ~5–7 B header overhead, session multiplexing, compatibility kept across the MasterDNS/StormDNS/CottenDNS lineage (MIT).

| # | method | state | learned from |
| --- | --- | --- | --- |
| 42 | DNS carriers UDP/53 + TCP/53 + DoT/853 + DoH/443, per-resolver `auto`/`udp`/`tcp`/`dot`/`doh` + per-path override | planned | CottenDNS |
| 43 | Record-type rotation + QNAME reshaping + ID/cookie randomization | planned | CottenDNS |
| 44 | Reliability: ARQ + ACK/NACK, adaptive duplication, Reed-Solomon FEC, MTU discovery, ZSTD/LZ4/ZLIB, request packing | planned | CottenDNS, MasterDnsVPN |
| 45 | Balancing across resolvers: round-robin / least-loss / lowest-latency / hybrid + health checks, failover | planned | CottenDNS, MasterDnsVPN |
| 46 | Local DNS service + cache + DNS-over-SOCKS5 + hijack guards; SOCKS4/5 with auth; CIDR resolver lists | planned | CottenDNS, MasterDnsVPN |
| 47 | Server egress direct / upstream-SOCKS5 chaining + flood protection | planned | CottenDNS, MasterDnsVPN |
| 48 | Encryption methods 0–5 (none / XOR / ChaCha20 / AES-128/192/256-GCM) + auto-detect | planned | CottenDNS |

### E — circumvention engines (learned from mlmvpn_android, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 49 | SoftEther / L2TP + WireGuard via `kittoku`; VPN Gate public relays | planned | mlmvpn |
| 50 | GST / EDG relay engines; GitHub Tunnel + Quick Connect pool; OpenVPN with TunnelBear | planned | mlmvpn |
| 51 | MLM Adaptive Engine: per-app route learning on one Xray tunnel + 5-step repair ladder | planned | mlmvpn |
| 52 | Config Studio + Config Arena: one Cloudflare Worker panel raced across panels on a clean IP | planned | mlmvpn |
| 53 | Game Booster: DNS/latency racing + pass-through DNS-only VPN | planned | mlmvpn |
| 54 | Sanction-domain smart routing | planned | mlmvpn |
| 55 | Server-less domain fronting (on-device CA, local TLS termination, re-establish under unblocked SNI) | planned | mlmvpn |
| 56 | Serverless / mihomo / superdns / pdoq / openvpn / http-injector / tunnel-wg / oblivion / auto lanes | planned | configer |
| 57 | Three-tier Emergency fallback | planned | mlmvpn |

### F — configer `https-proxy` + `foxy` lanes (learned, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 58 | Free HTTPS-proxy lane: anonymous `POST /v3/launch/` mints a token, server list yields HTTPS proxies exported as `http://` URIs + Clash/sing-box profiles | planned | configer |
| 59 | Foxy lane: CONNECT to an account's edge over HTTP/1.1, HTTP/2 or HTTP/3, country-pinned at dial, per-flow Bearer, failover inside the country, SPKI pins, split-tunnel | in tree — H1/H2 loopback-proven and the FxA login, Hawk and Guardian mint in (`cargo test -p ferrox-app foxy`, `cargo test -p ferrox-core account`); the QUIC lane's socket proof is open (`P39`) | configer, FoxyVPN |

### G — chaining: lanes stack, not just single dials

Today exactly one method dials per hop. The engine to build stacks them as an ordered list of hops, each hop dialling through the previous hop's local SOCKS / HTTP CONNECT / TUN front. (The 8-hop cap and `global_id` reuse in `mux.rs` are the pieces this reuses.)

- `foxy` first, then a `vless://`: the VLESS dial goes through the Foxy H2 CONNECT tunnel, so the VLESS server sees the Foxy exit — the shape of Aether `--mim`/`--gool`, PattNG `PROXYCHAIN` ordering and Aether `--upstream`, generalized to every lane above.
- Rules taken from the references: the control plane stays DIRECT unless a hop explicitly chains; each hop names its own upstream; at most one core-needing member per chain; every hop verifies its own exit; teardown runs before redial; headless runs take the first attempt and log the reasoning.
- Anything chains with anything: `https-proxy` → `vless`, `foxy` → `trojan`, `tor` → `masque-h2` (Tor carries TCP only, so the upper hop must be a TCP carrier), `dns-tunnel` → `shadowsocks`. A chain needing a capability its carrier lacks is refused with the reason, never silently downgraded.

### H — arti (Tor) + onionmasq

- `arti`: Aether carries it (`tor` feature) for `--tor`, `--tor-reverse` (MASQUE-H2 only, since Tor carries TCP only) and `--tor-only`, with bridges from bridgedb and `lyrebird` transports. Ferrox would support the same three shapes plus configer's Tor-lane synthesis (`torrc` rendering, bridge lines, `ClientTransportPlugin`, entry/exit pinning, control port, SNI verdicts). Planned; nothing in this tree.
- `onionmasq` (MIT/Apache-2.0): the experimental TUN interface for Arti — userspace TCP/UDP over Tor on an `onion0` device with its own DNS resolver, the piece `oniux` uses for per-app namespace isolation. Planned as the Tor-family TUN lane with binary-level exit-country pinning.

### I — SNI spoofing without root (learned, not pinned)

| # | method | state | learned from |
| --- | --- | --- | --- |
| 60 | Fake-ClientHello SNI spoofing (DPI allowlist bypass, no root) | planned — nothing in CI checks it | `UAC-SNI-Spoofer-Android`; `sni-spoofing-rust` |

`VpnService` TUN intercepts device traffic and a userspace TCP stack owns the connection, so no `SOCK_RAW` is ever opened. The stack sends a fake ClientHello with a spoofed SNI and a deliberately wrong sequence number first: DPI sees the allowlist entry and permits the flow, the real server discards the bad-seq packet, and the legitimate handshake proceeds.

One day every box above is checked: a row keeps `planned` until its differential proof and its benchmark gate are green, exactly as rows 1–16 in table A already are — with the two gaps in that table named in place rather than rounded off.

### Conformance, per row

The oracle names live in `upstream/pins.toml`, and `scripts/run-upstream-suite.sh` is the checker: it builds the named binary, refuses a pin whose rev does not read the seam it claims, injects the binary through that seam and rejects a green run that executed no test. Two pins are enabled — `zeronet` (8 named `xray_oracle` tests, seam `ZRAY_XRAY_BINARY`) and `xray-rust` (7 named `local_xray_interop_tests`, seam `XRAY_VLESS_FULL_BINARY`); the other ten print `SKIPPED` with the rung that would enable them. Those suites are run in CI only.

Twelve upstream pins, all resolving, all re-derivable by `scripts/fetch-upstream.sh`, all licence-clean for execution rather than copying:
`xray-core` (`b26a91de`), `sing-box` (`c9922979`), `amneziawg-go` (`b5928efb`),
`amnezia-client` (`94b51df2`), `xray-rust` (`7a4fb2dd`, `crates/`), `pattng` (`ad6f747c`, `V2rayNG/`),
`zeronet` (`97a99734`, `crates/`), `mqvpn` (`b11a2f69`), `aether` (`21e7150a`),
`zeptun` (`5620e57c`), `slipstream` (`397850b1`), `quiche` (`3fc9bc1c`, `quiche/`, `master`).
Read but not pinned: `WhiteDNS/CottenDNS`, `masterking32/MasterDnsVPN`, `mlmvpn/mlmvpn_android`, local `configer`.

## Layout

```
crates/ferrox-core       record layer, ChaCha20 core, AES-GCM, TLS interface + rustls backend,
                         vless/vmess/shadowsocks parsers, transport superset, failure taxonomy
crates/ferrox-bench      counting allocator, gates, benchmark report, comparator
crates/ferrox-app        ZeroNet-compatible app on ferrox-core (MIT)
crates/ferrox-prompt     roadmap advisor; reads prompts.md, the only place a slice is written down
docs/function            one page per connection method: ops, syscalls, copies, time, data-path graph
upstream/                pins plus derived reading copies, re-fetched by scripts/fetch-upstream.sh
scripts/                 pin checking, upstream fetching, gate and policy checks, count manifests
```

## Adding a method, or changing one

A new connection method lands with its page, or the page and the code drift and
the checker says so. The page needs four numbers with a checker each, a
`graph TD` of the data path, and a `## Time` section that either cites a
workflow or says the number is not measured yet:

```bash
printf '%s %s %s %s\n' '<doc>' '<key>' '<value>' '<checker>' >> scripts/method-counts.txt
./scripts/check-method-docs.sh
```

`UNBLESSED` is the value this repository already uses for a count nobody has
measured: the named checker prints the real number on the next CI run and the
claim stays open until it has been read. It is not a number and must never be
quoted as one.

## Driving this with an agent

The roadmap is a file, `crates/ferrox-prompt/prompts.md`. Every slice carries a status, a leverage, an effort, the gates that would prove it finished, and the slices it blocks.

```bash
cargo run -p ferrox-prompt -- next        # the slice, the reason, prompt → clipboard
cargo run -p ferrox-prompt -- list        # the roadmap, with what is ready now
cargo run -p ferrox-prompt -- check       # is the library still coherent?
```

`next` refuses to hand over a slice whose inputs are unfilled, printing the exact `--set` command instead. Status is the only field to edit, and a slice is `done` when its gates are green, not when its diff looks finished.

Pinned checkouts under `upstream/` are for reading only: an agent starts every rung in the corresponding upstream implementation and ends in CI. A number produced off a named runner is not evidence about any runner.

## Contributing

```bash
./scripts/new-worktree.sh <name>      # isolated worktree: shared build cache, linked upstreams
./scripts/fetch-upstream.sh           # only what the links missed
cargo run -p ferrox-prompt -- next    # the slice
./scripts/check.sh                    # everything ci.yml runs, in seconds, before the push
```

Worktree first, so branches never share a working tree. Re-run the fetch whenever `upstream/pins.toml` changes under you. `check.sh` before every push is the whole friction policy: a lint found locally is free, a lint found in CI is a runner somebody else is waiting behind.

```bash
cargo run -p ferrox-bench -- --config 'vless://...'   # the comparison table for a link
cargo run -p ferrox-app -- check 'vless://...'       # parse offline; `run` dials TCP, sends nothing
```

## Licence

`MIT OR Apache-2.0` — see `LICENSE-MIT` and `LICENSE-APACHE`. Every dependency permits both, and Apache-2.0 contributes the express patent grant a cryptographic core should carry.