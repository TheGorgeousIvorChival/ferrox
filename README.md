# Ferrox

FERROX — Fast Efficient Relay Router Overlay X. *ferro*, iron, for Rust; *X*, for Xray.

A from-scratch proxy core, built to be **bit-identical to the implementations it replaces** and **verifiably not slower than any of them**.

## Goals

1. **Prove everything shipped is faster and leaner.** Bit-identical output, fewer operations, zero surviving copies, no allocation. Counts prove, durations suggest: instruction counts are gated exact, so a diff that removes one operation changes a number every runner reproduces.
2. **Be a drop-in replacement for Xray-core and sing-box.** Not "implement their protocols" — run *their* pinned test suites unmodified against a Ferrox binary in CI. Today 2 of 12 pins, both of the two with a seam.
3. **Be a drop-in replacement for zeptun**, the `tun2socks` engine: TUN to TCP/UDP/ICMP through a SOCKS5 or direct handler, `userspace` / `hybrid` / `system` stacks.
4. **Be feature-complete in what quiche, slipstream and aether are ahead on.** QUIC and MASQUE, DNS-tunnel carriers, nested tunnels, multi-path schedulers, domain fronting. Libraries and product surfaces, read for the technique and implemented on Ferrox's terms.
5. **Spoof SNI without root.** DPI circumvention by injecting a fake TLS ClientHello with an allowlisted SNI ahead of the real handshake. `VpnService` TUN plus a userspace TCP stack does it in user space. Nothing in CI checks this yet.

## How it is built

- **One algorithm, four widths.** The record layer is one generic function over a `Lanes` trait — portable arrays, NEON, SSE2, AVX2 — so backends execute the *same source* and cannot disagree. The portable path is safe Rust, so Miri interprets the ladder and the SIMD modules stay five instructions each whose only failure mode is a wrong answer.
- **Rewrite, not port.** The minimal subset covering the matrix, proven faster down to the parsing. One line of comment per item at most, no changelogs — checked by `scripts/check-comments.sh`. The shared protocol is `crates/ferrox-prompt/prompts.md`.
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

Not claimed: that this is the fastest implementation. A benchmark measures a configuration at a point in time and decays. What is built instead is the machinery that notices.

```bash
./scripts/check.sh    # fmt, clippy, docs, policy checks, the prompt library, tests
```

That is what `ci.yml` runs. Running it first is how a lint stops costing a queue.

## Connection methods

Every row parses; a row dials only with its differential proof and its benchmark gate. Full ladder in `crates/ferrox-prompt/prompts.md`.

| method | state |
| --- | --- |
| VLESS TCP REALITY `xtls-rprx-vision` | implemented |
| VLESS TCP none (private/loopback only) | implemented, TCP + UDP both roles |
| TROJAN TCP TLS | implemented, TCP + UDP both roles |
| VMess TCP (AEAD) | implemented, TCP + UDP both roles |
| Shadowsocks TCP/UDP (three ciphers) | implemented, every Xray-core spelling; no `2022` |
| VLESS over WS / XHTTP / gRPC / HTTPUpgrade / HTTP masquerade | implemented, one rung each |
| VLESS over QUIC | implemented, pooled one handshake per server |
| `?ed=N` early data on WS / HTTPUpgrade, both roles | implemented |
| KCP, Hysteria, TUIC, AnyTLS, ShadowTLS, SSH, OpenVPN | refused with a reason |
| `cipherSuites`, `unsafe-*` fingerprints, plaintext to public | unsafe opt-in, never default |
| WireGuard / AmneziaWG, MASQUE CONNECT-IP, tun2socks | planned |
| DNS-tunnel carriers, circumvention engines, lane chaining | planned |

Twelve upstream pins in `upstream/pins.toml`, all resolving, all re-derivable by `scripts/fetch-upstream.sh`. Upstream suites are executed, never copied — sing-box is GPL-3.0, Xray-core/xray-rust MPL-2.0, so a copied test would make this work's licence undecidable.

## Layout

```
crates/ferrox-core       record layer, ChaCha20 core, AES-GCM, TLS interface + rustls backend,
                         vless/vmess/shadowsocks parsers, transport superset, failure taxonomy
crates/ferrox-bench      counting allocator, gates, benchmark report, comparator
crates/ferrox-app        ZeroNet-compatible app on ferrox-core (MIT)
crates/ferrox-prompt     roadmap advisor; reads prompts.md, the only place a slice is written down
upstream/                pins plus derived reading copies, re-fetched by scripts/fetch-upstream.sh
scripts/                 pin checking, upstream fetching, gate and policy checks
```

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