# Conformance: all of their tests, enabled gradually

This project becomes a drop-in replacement (Goal 2) by running upstream suites *against* Ferrox binaries in CI — never by copying them here. sing-box is GPL-3.0, Xray-core / xray-rust are MPL-2.0 and PattNG / Aether are GPL-3.0 / AGPL-3.0; copying their tests would make this work's licence undecidable. Running them unmodified is both licence-clean and a stronger claim than a hand-rewritten vector. **Two of the twelve do that against this workspace**, both against `ferrox-app` through their own seam: `zeronet` runs 8 of the 17 `#[ignore]`d tests in `xray_oracle`, `xray-rust` runs 7 of the 23 in `local_xray_interop_tests` — five already green and the two `?ed=`-early-data rows the `EarlyData` rung named. The ten pins with no seam do not, each for the named reason below.

## The rule

Each source in `upstream/pins.toml` carries `test_enabled`:

- `true` — its suite runs in `conformance.yml`, which fires on a pull request touching the crates a suite exercises and on a weekly cron. It has no `push` leg: the pull request is where a break is cheap, and the weekly cron covers `main`.
- `false` — the CI job is created, skips, and prints the reason (unimplemented rung). Skipped is visible; absent would be silent.

A suite flips to `true` only when:

1. its transport rung reports `Support::Implemented`,
2. the differential proof for that rung is green at every length and offset,
3. the benchmark gate for that rung is green on all four ISA runners.

Ten entries are disabled and two (`zeronet`, `xray-rust`) are enabled. `xray-core` stays disabled because its suite runs upstream code only with no Ferrox binary wired yet, and `run-upstream-suite.sh` fails an enabled entry with none rather than printing PASS.

## The xray-core baseline (informational, never a gate)

`xray-baseline.yml` runs all of the pinned `xray-core`'s own Go tests against upstream itself and publishes the pass/fail totals plus the full log. Test failures never fail it; only infra failures go red. It is the behavior list the drop-in refactor works through, not conformance.

## What each suite is missing, measured

Reading the fetched trees at each pin for a point where an external binary could be injected — an environment variable naming a binary, which is the only shape a suite can be pointed at without editing it — gives:

| suite | pin | seam at that rev | what the seam demands of our binary |
| ----- | --- | --------------- | ------------------------------------ |
| xray-core | `b26a91de` | none | `./proxy/vless/...` is in-process Go; 0 `os/exec` in the package |
| sing-box | `c9922979` | none | no `*_test.go` under `protocol/shadowsocks` or `protocol/vless`; crypto is the out-of-tree `sagernet/sing-shadowsocks2` |
| amneziawg-go | `b5928efb` | none | `device/*_test.go` are in-process; the TUN path needs root |
| amnezia-client | `94b51df2` | none | C++/Qt; test material is Conan-installed, no binary harness |
| xray-rust | `7a4fb2dd` | `XRAY_VLESS_FULL_BINARY` | `run -config <file>`, `x25519`, and a VLESS **server** that listens |
| pattng | `ad6f747c` | none | Android/Gradle; the binary name is a `.so` constant, not an injection point |
| zeronet | `97a99734` | `ZRAY_XRAY_BINARY` | `version`, `run -c <file>`, `x25519`, `vlessenc`, and a VLESS **server** |
| mqvpn | `b11a2f69` | none | C `ctest` plus netns E2E; no env binary seam |
| aether | `21e7150a` | none | Rust CLI (`--masque` / `--wg` / `--gool` / `--mim`); no env binary seam — pinned directly, not via PattNG's `.so` |
| zeptun | `5620e57c` | none | `zig build test` plus netns integration; no env binary seam |
| slipstream | `397850b1` | none | client/server CLIs over DNS; no env binary seam |
| quiche | `3fc9bc1c` | none | library (QUIC + HTTP/3); no suite to inject into — the stack the rungs dial through |

Two of twelve have a seam, and both are the same shape: each spawns the binary as `run -config <file>` and waits for it to listen, so `ferrox-app` needs a **server** role. It has one — `version`, `x25519`, and `run -c` serving `vless`, `trojan`, `vmess`, `shadowsocks` and `socks` inbounds over raw `TCP`, `ws`, `httpupgrade` and `grpc`. It serves a `reality` inbound over raw `TCP` and `grpc` (`serve_vless_reality_inbound`, backed by `ferrox_core::tls::RealityServer`): the handshake authenticates and then the session cannot be completed, measured below and owned by P21. It still refuses to *dial* a `reality` outbound (`vless_security_supported`), so a `SOCKS` inbound has no `REALITY` upstream.

`run-upstream-suite.sh` checks this rather than trusting the pin: it refuses a `PASS` for a suite with no `ferrox_binary`, refuses one whose `seam` is absent, and refuses one whose declared `seam` the pinned tree never reads. Building a binary and not executing it is the failure mode those three checks exist to catch.

## Current state

| suite | pin | enabled | reason |
| ----- | --- | ------- | ------ |
| xray-core record/crypto | `b26a91de` | ❌ false | no seam at that rev: the suite is in-process Go, so no binary can be injected |
| sing-box crypto | `c9922979` | ❌ false | no seam; and no `_test.go` under `protocol/shadowsocks` or `protocol/vless` to run |
| amneziawg-go noise | `b5928efb` | ❌ false | no seam; `device/*_test.go` are in-process and the TUN path needs root |
| amnezia-client crypto | `94b51df2` | ❌ false | no seam; C++/Qt, test material is Conan-installed |
| xray-rust | `7a4fb2dd` | ✅ true | seam `XRAY_VLESS_FULL_BINARY` exists; the enabled command names 7 of the 23 `#[ignore]`d tests in `local_xray_interop_tests` — the plain-`TCP` `VLESS` server trio plus the `ws` and `httpupgrade` carriers, and since the `EarlyData` rung the two `?ed=`-early-data rows — and runs them unmodified against `ferrox-app`, checked by `conformance.yml`. The other 16 are named with their measured failure below |
| PattNG (v2rayNG fork) | `ad6f747c` | ❌ false | no seam; Android/Gradle, and the unsafe rows need `UnsafeOptIn` first |
| ZeroNet / Zray | `97a99734` | ✅ true | seam `ZRAY_XRAY_BINARY` exists; runs the raw-`TCP` `VLESS`, `trojan`, `shadowsocks` and `vmess` plus `VLESS`-over-`WebSocket`, `HTTPUpgrade` and `gRPC` plus `trojan`-over-`WebSocket` subset against `ferrox-app`, checked by `conformance.yml` |
| mqvpn MASQUE/MP-QUIC | `b11a2f69` | ❌ false | no seam; `ctest` plus netns E2E need root and a live server pair |
| Aether WARP core | `21e7150a` | ❌ false | no seam; open-source Rust core pinned directly — PattNG's `.so` is that core vendored, this pin is the source |
| zeptun tun2socks | `5620e57c` | ❌ false | no seam; `zig build test` plus TUN/netns integration, no proxy harness to inject |
| slipstream DNS tunnel | `397850b1` | ❌ false | no seam; client/server over DNS need a domain delegation, not a binary swap |
| quiche QUIC/H3 | `3fc9bc1c` | ❌ false | no seam; library only — compared by differential benchmark once a QUIC rung dials |

The `trojan_over_websocket` oracle row is green since the trojan `WS` carrier landed both directions, measured in `conformance.yml` run `37218430484` (8 passed, 1 failed, the failure below). The remaining `xray_oracle` test out of the enabled command is `vmess_over_websocket`: the serve direction works against the real peer but our dial stalls reading its response header — `echo timed out` on the first payload in the same run — so the row stays out until that rung lands; a subset that passes is a subset.

## The rung no suite can gate, and what stands in for it

Multiplexing is implemented (`mux.rs`, rung 11) and **no suite in the table above can check it**, for the same reason every other row on that list is disabled and with the seam measured rather than assumed:

- **xray-core** `common/mux` is in-process Go. Its tests build a `FrameMetadata` and call `WriteTo`/`UnmarshalFromBuffer` directly; none reads the environment for a path or takes a socket, so there is nowhere to inject a binary even in principle.
- **sing-box** keeps no framing in this tree at all. Its mux is three out-of-tree modules (`sing-mux`, `smux`, `yamux`), so a suite at the pinned commit has nothing of ours to differ against.
- **xray-rust** has no mux implementation, so the only coverage available is the config-parse rejection, which is a statement about its parser rather than about a wire format.
- **PattNG** configures Xray-core's codec rather than carrying it, and its `AndroidLibXrayLite` submodule is not checked out at the pin.

So this rung's identity claim rests on vectors **spelled out by hand from the format with their arithmetic shown** — `NEW_DOMAIN` in `mux::tests` and eight others, plus a dense round trip over all 256 domain lengths — and its cost claim on `bench.yml` gate 6, whose reference is built to the *shape* upstream has rather than from upstream. That is the same position gate 4 is in, and both say so in their own headers and in the report text. [`function/mux-frames.md`](function/mux-frames.md) has the full statement.

## Every `xray-rust` interop test, by name

`local_xray_interop_tests` at `7a4fb2dd` holds 23 `#[ignore]`d tests; all 23 use the `XRAY_VLESS_FULL_BINARY` seam to run `ferrox-app` as the `VLESS` **server**, and the `Rust` core or the pinned `Xray-core` build as the client. Widening the pin's `suite` to all 23 measured the rest in `conformance.yml` run `37125321800` on `ubuntu-latest`: **5 passed, 18 failed**, 41.6s. The five that passed are the enabled suite command; the eighteen are named below with the assertion each died on, so the gap is a list rather than a shrug. Two have since moved into that command — the `?ed=` rows, fixed by the `EarlyData` rung — which leaves **sixteen**.

| test | verdict | measured failure | lands in |
| ---- | ------- | ----------------- | ----- |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp` | ✅ | — | `proxy.rs` |
| `rust_round_robin_balancer_uses_each_local_xray_vless_member` | ✅ | — | P10 |
| `rust_two_hop_proxy_chain_reaches_echo_through_local_xray_vless_servers` | ✅ | — | P10 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws` | ✅ | — | — |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_early_data` | ✅ (run `37249695646`) | was `read echo failed: early eof` | `transport::EarlyData` |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_early_data` | ✅ (run `37249695646`) | was `socks connect rejected: [5, 1, 0, 1]` | `transport::EarlyData` |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade` | ✅ | — | — |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_tls` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P17 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_tls_vision` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision_selected_fingerprints` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P7 |
| `inner_tls_session_survives_vision_direct_switch_through_local_xray_reality_vision` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P7 |
| `rust_socks_clients_open_parallel_echo_flows_through_local_xray_vless_reality_vision_selected_fingerprints` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P7 |
| `xray_core_socks_clients_open_parallel_echo_flows_through_local_xray_vless_reality_vision_selected_fingerprints` | ❌ | `Xray-core client REALITY warmup probe failed: … Connection reset by peer` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_tls` | ❌ | `socks connect timeout: deadline has elapsed` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_tls` | ❌ | `socks connect timeout: deadline has elapsed` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc_tls` | ❌ | `socks connect rejected: [5, 1, 0, 1]` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc_reality` | ❌ | `REALITY server warmup retry failed … [5, 1, 0, 1]` | P7 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc` | ❌ | `read echo failed: early eof` | P15 |
| `rust_socks_client_reads_a_server_greeting_through_local_xray_vless_grpc` | ❌ | `read greeting: early eof` | P15 |
| `rust_socks_client_streams_bulk_echo_through_local_xray_vless_grpc_multi_mode` | ❌ | `bulk echo failed: read bulk echo: Connection reset by peer` | P15 |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases` | ❌ | `XHTTP bulk flow failed: read XHTTP bulk echo: Connection reset by peer` | P16 |
| `rust_socks_client_reaches_target_through_remote_xhttp_profile` | ❌ | `XRAY_REMOTE_XHTTP_CONFIG must name an owner-only file` | P16 |

### The two `?ed=` rows, and what they were failing on

Those two rows were the only ones in the table that named a *setting* rather than a transport, and both failed for one reason: **the configured path kept its `?ed=2048`.** Both oracles configure the inbound path as `/interop-ws?ed=2048` and ask the client for the bare `/interop-ws`, because `Xray-core` strips the key in its config parser and then matches a request's `URL.Path`, which has no query in it. Nothing here did, so the upgrade was refused — `[5, 1, 0, 1]` on `httpupgrade`, and on `ws` the socket simply closed after the SOCKS reply had already gone out.

Reading the two tests also settled two things a reading of the Go source alone would have got wrong. `xray-rust`'s client sends the whole first write or nothing, so a write one byte over the budget disables early data for the connection rather than truncating it — which is `Xray-core`'s rule and **not** `sing-box`'s, whose client slices `content[:max]` and sends the remainder after the `101`. And on `httpupgrade` the same test sets `early_data_bytes: 2048` on a client that parses the key and then *ignores* it, with the reason in its own parser warning: the peer strands whatever arrived with the request in a `bufio.Reader`. So the `httpupgrade` row needs the parse and nothing else, which is what `httpupgrade.rs` now does — it has no early-data code at all.

`ZeroNet`'s own `extract_early_data` is the fifth spelling and the closest to this one: one `strip_prefix("ed=")` loop over the query, empty pairs dropped, the **last** `ed` winning where `Xray-core`'s `Values.Get` takes the **first**, and `ed=` with an empty value emptying the key where `Xray-core` leaves the path alone. The two are the same for every input in the matrix.

### The `REALITY` rows are blocked on a certificate, not on the handshake

Measured against the pinned `Xray-core` `b26a91de` built from source, running as the client against this binary as the `REALITY` server over raw `TCP` with `flow: xtls-rprx-vision` and fingerprint `chrome`: the `ClientHello` is **authenticated** — `X25519` against `privateKey`, `HKDF-SHA256`, `AES-256-GCM` over the `session_id` with the hello as associated data, and the `shortId` from the sealed 16 bytes — and the session then fails to negotiate, because the certificate `REALITY` recognises has to carry an `Ed25519` key and **no `uTLS` fingerprint offers `Ed25519` in `signature_algorithms`**.

That is a property of the pinned fixtures, not of one browser: reading `upstream/xray-rust/tests/fixtures/reality/clienthello_raw_*.json` at `7a4fb2dd`, all eleven committed raw `ClientHello`s list 8 to 11 signature algorithms and **none** of them is `0x0807`. A `TLS` 1.3 `CertificateVerify` scheme must be one the peer offered and must match the certificate's key, and `REALITY`'s certificate has to be `Ed25519`, so there is no certificate this server can present that any of those peers will accept. `Xray-core` itself does not hit this because a server that authenticates its peer answers with the *cover origin's* certificate: `dest` is where the certificate comes from. P21 owns that.

Two wire details the same run established, both of which a reading of the Go source alone would have got wrong, and both of which are now what this tree implements:

- the `server_name` extension's name list is prefixed with a **two**-byte length, not the one RFC 6066 specifies — both the `uTLS` client fork (`u_tls_extensions.go:172`) and the `REALITY` server fork (`handshake_messages.go:478`) read it that way, so a conforming one-byte reader finds no name at all;
- the auth key is derived from the **plain** `X25519` share when the `ClientHello` offers one, because that is the share the peer holds (`u_parrots.go:3188` sets `KeyShareKeys.Ecdhe` from the first classical share). The pinned `REALITY` *server* prefers the hybrid share instead (`tls.go:225-239`), so a client fingerprint that offers a fresh classical share alongside the hybrid authenticates against one key and is checked against the other.

Three readings the table supports and a "TLS and `REALITY` are missing" summary does not:

- **`gRPC` passes one oracle and fails the other.** `vless_over_grpc_matches_the_oracle` is green against `ZeroNet`'s `xray_oracle`, and `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc` fails here with `early eof`. Two oracles, one carrier, two verdicts: the framing agrees with `ZeroNet` and not with `xray-rust`, so the carrier is not wrong, it is narrower than both. P15.
- **`ws` and `httpupgrade` without `TLS` are green, and now so are their early-data rows.** No oracle in the `zeronet` pin exercises early data, so the `ws`/`httpupgrade` slices shipped two rows no suite tested; the `xray-rust` pin has the two that do.
- **One failure is a harness requirement, not a transport gap.** `rust_socks_client_reaches_target_through_remote_xhttp_profile` asserts before it connects: it wants `XRAY_REMOTE_XHTTP_CONFIG` to name an owner-only file, which the suite command does not and should not write. P16 has to answer that before the row means anything.

### `--exact` is load-bearing, and CI is what notices

Narrowing this pin's `suite` from all 23 names to the 5 that pass still ran 9 tests, because `libtest` filters by substring: naming `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws` also runs its `_tls` and `_early_data` siblings, and naming `..._httpupgrade` also runs its `_tls` and `_early_data` siblings (run `37126222488`: `5 passed; 4 failed; 21 filtered out`, where 4 rows failed that the pin never named). `--exact` makes each filter an exact match; the next run printed `running 5 tests` and `5 passed; 0 failed; 25 filtered out` in 0.47s (`37126666770`).

The trap waits for any pin whose enabled names are prefixes of disabled ones, so the check is a count, not a word: a suite command that names `N` tests is only doing what it says if the `running N tests` line says `N` too. **`run-upstream-suite.sh` now reads that count and refuses the `PASS` when it disagrees** — the names are the words after the last ` -- ` that are not flags, the count is libtest's, and a command whose names total zero is refused outright because a filter renamed upstream still exits 0. So dropping `--exact` from the `xray-rust` command would be red at 11 against 7 rather than a quiet pass, and the `zeronet` command's eight names are compared on every run even though none of them is a prefix of another. It is checked on the self-test first: four synthetic outputs — exact, prefix-trapped, empty, and a harness with no count at all — are decided before any suite runs, so a `sed` pattern that stopped matching would be red on its own.

The ten pins with no seam were each read for a socket-taking harness instead — a test that dials an address the suite takes from the environment, the only shape usable without editing it — and none has one, measured against the fetched trees: `xray-core` `proxy/vless` tests never call `os/exec`; `sing-box` has no `_test.go` under `protocol/shadowsocks` or `protocol/vless`; `amneziawg-go` `device` tests are in-process; `amnezia-client` tests are `C++`/`Qt` model tests; `pattng` names its core as `.so` constants (`libaether.so`), not an injectable path — but that core is open source and is now pinned directly as `aether`; `mqvpn` tests are `ctest` plus netns E2E; `aether` is a CLI without a socket-taking test harness; `zeptun` is unit plus TUN/netns integration; `slipstream` needs a DNS delegation; `quiche` is a library. Driving any of them without its rung would mean editing their tests, which is inventing a runner outside their test rather than running it.

## Adding a suite

Add the pin with `test_enabled = false`, add the CI job that skips with the rung reason, and open the flip to `true` as its own PR with the differential proof attached. A conformance PR without the proof is closed — same as an `unsafe` PR without one. The flip must also set `ferrox_binary` to a binary the suite command executes; `run-upstream-suite.sh` fails the job otherwise.
