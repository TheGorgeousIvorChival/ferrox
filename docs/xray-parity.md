# Ferrox vs Xray-core feature map

Pinned reference: `upstream/xray-core` @ `7da5dae6` (`upstream/manifest.toml`).
This tree: `crates/ferrox-core`, `crates/ferrox-app`, `docs/function/`.

## What ferrox has that xray-core does not

| area | ferrox | xray-core |
| --- | --- | --- |
| Foxy / FoxyVPN lane | `ferrox-core/src/foxy/` — FxA login + 2FA, Hawk-signed exchange, bot challenge, Guardian token, Remote Settings catalog, country pin, SPKI pins, split tunnel, auto = QUIC → H2 → H1 | none (it is a separate product) |
| TUN as zeptun-style tun2socks | roadmap goal 3; zeptun pinned as comparator | `proxy/tun` exists, but oriented to gVisor stack only, no zeptun-style policy split documented here |
| Record layer, four widths, one source | `record.rs` + `Lanes` trait: portable/NEON/SSE2/AVX2 execute the same source | per-arch crypto with divergent implementations |
| Count-gated claims | exact ops/syscall/copy counts per method, `scripts/method-counts.txt` ⇔ pages | no equivalent gate |
| Single TLS stack | rustls behind `TlsProvider`, no feature flags | utls + stdlib TLS, selectable per config |
| Hysteria carried as VLESS transport | `protocol: hysteria` row wired in `ferrox-app` | transport `hysteria` exists, but proxy-level Hysteria is its own proxy, not a VLESS carrier row |
| KCP bit-exact oracle | `kcp::oracle` vs pinned Go KCP | KCP implementation, no cross-implementation oracle in-tree |

## What xray-core has that ferrox does not

### Proxy protocols

| xray-core | ferrox state |
| --- | --- |
| VMess (AEAD) — full matrix: UDP over ws/grpc/xhttp/tls, all encodings | partial: no UDP except raw carrier; no auth-length framing bits (matches client default only) |
| Trojan share-link `trojan://` parser | absent |
| Shadowsocks-2022 (`proxy/shadowsocks_2022/`) | refused by name (row 28) |
| HTTP proxy inbound/outbound (`proxy/http`) | absent — only SOCKS inbound |
| Dokodemo transparent inbound | refused (row 24) |
| Freedom — fragment/dialer freedom fields | present, but fragment option surface thin |
| DNS proxy + fakeDNS + hosts + DoH/DoQ/local nameservers (`app/dns`) | refused (row 26) |
| Blackhole outbound | refused (row 25) |
| Loopback | refused (row 27) |
| WireGuard proxy (`proxy/wireguard`, gVisor netstack) | absent |
| Hysteria v1 proxy (`proxy/hysteria`) | absent (only v2 as carrier) |
| MASQUE proxy (`proxy/masque`) | roadmap P33/P43, not implemented |
| TUN inbound (`proxy/tun`) | refused (row 29) |
| uTLS fingerprints per connection | refused (row 38) |
| ECH | refused (row 39) |
| VLESS stream encryption (`encryption` field, XOR/MLKEM) | refused (row 34) |
| XTLS Vision UDP-over-443 flow | refused (row 35) |
| REALITY client dial | refused (row 36) |

### Transports

| xray-core | ferrox state |
| --- | --- |
| TCP | done |
| WebSocket (`?ed=` both roles) | done |
| gRPC | done, own HTTP/2 |
| HTTPUpgrade | done; `?ed=` parsed, not carried |
| xHTTP / SplitHTTP modes (packet-up, stream-up, stream-one, padding/placement) | one mode only (POST + chunked) |
| KCP/mKCP + FinalMask (aes128gcm, header, original) | core done; finalmask refused (row 31) |
| Hysteria QUIC transport | done |
| MASQUE transport | refused (P33/P43) |
| XDrive | refused (row 32) |
| Browser dialer | absent |
| Tagged connections / observatory webhooks | absent |
| UDP `transport/internet/udp` fullcone/NAT behavior | mux-cool carries XUDP; no standalone UDP transport service parity |
| Unix sockets | refused (row 30) |

### Features / apps

| xray-core | ferrox state |
| --- | --- |
| DNS client: DoH, DoQ, local, cached, fakeDNS | refused (row 26) |
| Router with rules, balancers (leastload/leastping/random), webhook | absent — inbounds bind fixed ports, outbounds pick by protocol |
| Observatory / burst probe | partially: QUIC ladder climb/descend, no burst |
| Reverse portal / bridge | absent |
| Stats, metrics (Prometheus), policy manager | policy.rs is parse-level gate only; no stats/metrics service |
| `app/commander` gRPC API (config/inbound/outbound/log/router/stats) | absent |
| Geodata (.dat) loader/downloader | absent |
| Sniffer (HTTP/TLS/QUIC/bittorrent) + dispatcher sniffer | absent |
| Config schema for every protocol (`infra/conf`) | ferrox-app has its own smaller JSON config |
| OCSP, antireplay, time-window caches | absent |
| Freedom fragment, VLESS encryption fragment | refused |
| finalmask: fragment, header/custom, noise, realm (STUN hole-punch, portmap), salamander, sudoku, udphop, xdns, xicmp, xmc | refused (row 31) |

## What to implement next (stop refusing, build instead)

Each item names the roadmap slice that carries it; xhttp modes ride with P16, the rest are tracked in `crates/ferrox-prompt/prompts.md`.

Priority by user value ÷ amount of pinned-upstream knowledge already in-tree:

1. **SplitHTTP/xHTTP modes** — padding/placement modes + browser-client shape. The codec is already here; the modes are config surface (`proxy.rs:720` names this).
2. **DNS app + DoH/DoQ client + fakeDNS** — row 26 flips to implemented; enables real routing later. Pin is in `upstream/xray-core/app/dns`.
3. **Routing engine** — rules on domain/IP/port/network with balancers. Without it ferrox cannot be a drop-in for any multi-outbound config.
4. **REALITY client dial** — row 36; the server half and the crypto are already here.
5. **Shadowsocks-2022** — row 28; `proxy/shadowsocks_2022` pinned, KDF/replay logic is self-contained.
6. **blackhole + loopback** — rows 25/27; both are tiny outbounds/inbounds once the dispatcher has a seam.
7. **HTTP proxy inbound/outbound** — completes the "drop-in" inbound set next to socks.
8. **dokodemo + TUN inbound (via zeptun)** — rows 24/29; needed for the goal-3 tun2socks claim to be wired, not aspirational.
9. **Dokodemo → dispatcher sniffer** — HTTP/TLS/QUIC sniffing to feed the router.
10. **MASQUE CONNECT-IP / CONNECT-UDP** — pinned in `upstream/xray-core/proxy/masque`, quiche available.
11. **uTLS fingerprints + ECH** — rows 38/39; utls pinned upstream, pick by name the fingerprints we support.
12. **VLESS `encryption` (XOR/MLKEM) + Vision UDP-443** — rows 34/35.
13. **finalmask** — row 31; implement by name which masks we carry (salamander first: Hysteria already depends on it shape-wise).
14. **WireGuard proxy** — replace with a thin Noise IKpsk2 wrapper (`proxy/wireguard` pinned) or name it refused-permanent.
15. **Observatory/burst, stats, metrics, commander API, geodata, reverse portal** — one API slice at a time; start with stats + leastping balancer since balancers ride on stats.
16. **xdrive + browser dialer** — rows 32; only after MASQUE, both are "exotic carrier" tier.

Sequencing note: 2 then 3 then 1 unblock real-world configs; 4–6 are parity fillers; 8 is required for the zeptun goal to be real rather than a row.
