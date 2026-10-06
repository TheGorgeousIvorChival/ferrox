# Claims and their checkers

Every claim this repository makes, the thing that checks it, and what that thing last said. **A claim with no checker is not removed, it is marked** — "not yet proven" names the next slice.

Nothing here is checked by a run: the verdicts are transcriptions of named runs, read on 2026-10-03 at `main` = `94cd774`. A verdict goes stale the way a benchmark does.

| verdict | meaning |
| --- | --- |
| **green** | a named thing ran and passed |
| **red** | a named thing ran and failed; the claim is not established |
| **no checker** | nothing in this tree checks it |
| **vacuous** | a checker exists but cannot fail on this claim |
| **stale** | the checker, or the code, shows the sentence is no longer true |
| **read** | true by reading the pinned source or this tree; no run checks it |

## README status table

| claim | checked by | verdict |
| --- | --- | --- |
| `cargo test --workspace` green on linux x86_64, macos aarch64, windows x86_64 | `ci.yml` test jobs | green, all three |
| `clippy` clean under `pedantic`, `-D warnings` | `ci.yml` lint job; also `./scripts/check.sh` locally | green |
| `record::fill_exact` and `record::fill_exact_with_head` bit-identical at 7200 shapes on all four runners | `bench.yml` gate 1 (300 lengths x 6 offsets x 2 key pairs, both entry points) | green |
| `chacha::avx2`, `chacha::sse2` executed | `bench.yml` gates 1 and 2 on both `x86_64` runners | green |
| not slower at any **measured** length from 65 B up | `bench.yml` gate 3, 235 timed lengths, green on all four runners — worst 1.03x at 320 B on `linux x86_64`, 1.02x at 127 B on `linux aarch64`, 1.01x at 256 B on `windows x86_64`, none below the 0.95x bar | green at the bar the gate actually sets, which is 5% below the claim's wording |
| lengths 1-64 B, "a tie by construction and identity-checked only" | gate 1 checks those 64 lengths byte for byte; **gate 3 does not time them** (`TIMING_MIN = 65`) | green for the identity half; the timing half is **not measured anywhere**, by decision, and `TIMING_MIN` in `crates/ferrox-bench/src/main.rs` is the decision's record |
| gate 3's resolution at the short end, where its ratio sits near 1.0 | nothing measures it: six runs of **one unchanged build** put the worst ratio anywhere in 1.05x-1.08x and the worst *length* anywhere in 72-111 B | **no checker** — and the noise is between *processes*, not within one, so re-measuring at four times the budget does not tighten it (measured: six such runs spread 1.00x-1.07x, wider). Treat the short band as **not certified for sub-5% changes** |
| commit `2b980b1`'s stated verification, "over every length 0..=1100 against thirteen start blocks and two key pairs" | nothing matches it: gate 1 sweeps 300 lengths x **6** offsets x 2 key pairs, and `core.rs`'s test 44 x 6 x 2 | **stale** — the bytes are proved by gate 1; the stated coverage is roughly 2x the real offset count and names a length range no sweep uses. It lives only in the commit message, so it is marked here rather than rewritten in history |
| `GROUP_STATES`'s width for `aarch64` is 8, not 4 | `const _: () = assert!(GROUP_STATES * <Wide as Lanes>::CHUNKS == 8)` under `#[cfg(target_arch = "aarch64")]`, so a revert of the widening cannot build | green, by the assertion. The history shows a change taken back for no stated reason and silently restored; **the pin is now documented on the constant** |
| aarch64 AES-GCM runs the ARMv8-Crypto backends, and is bit-identical there | `--cfg aes_armv8 --cfg polyval_armv8` in the workflows and `scripts/new-worktree.sh`; 173 workspace tests under `-D warnings` with both cfgs on an M2, and the differential tests inside them | green locally. **The speed is claimed from a measurement nothing re-runs**: header seal 1228 → 101 ns, client request 10289 → 7101 ns, 8 KB frame 45008 → 3745 ns, `kdf` unmoved at 1130 ns. `bench.yml` cannot check it, because every gate there measures `ferrox-core`'s own ChaCha20/Poly1305 and `ferrox-core` depends on neither `aes` nor `polyval` |
| TLS backend `rustls`: handshake connects, refuses a wrong certificate name, refuses a refused ALPN | `ci.yml` builds it on three operating systems; `rustls_backend.rs` carries the three tests | green: one handshake and two negatives, all three failing when they should |
| twelve sources pinned; every one resolves | `./scripts/check-upstream-pins.sh` via `pins.yml`, one `ubuntu-latest` runner | green, 12 of 12 |
| twelve `upstream/` checkouts at exact revs | nothing — they are `.gitignore`d and re-derived by `fetch-upstream.sh`; presence was verified by hand | **no checker**, and the row says so |
| twelve pins' `path` fields each name a tree present at their rev | `run-upstream-suite.sh` path check: 12 `path ok`, 0 absent — repaired here: `xray-core` → `common/crypto`, `sing-box` → `protocol/shadowsocks`, `amneziawg-go` → `device`, `amnezia-client` → `common/crypto` | green |
| Miri nightly PASS 2026-10-03 | nothing in this repository: `safety.yml` has no completed runs here | **no verdict** — the quoted PASS predates this repo |
| first green CI run, all six jobs, run 37077244861 | that run, predating this repository; the comparable run here is 37098689265, six jobs green | green there, **stale** here |

## README claim table

| claim | checked by | verdict |
| --- | --- | --- |
| byte-identical output, every length, every device | `bench.yml` gate 1 before any timing, 7200 shapes over both `record` entry points; `core::tests::every_rung_matches_the_reference` at 528 shapes | green |
| not slower at any measured length from 65 B up | `bench.yml` gate 3 over 235 lengths | **the gate tolerates 5%**: `BAR = 0.95`, so a length at 0.96x passes while the row says "not slower". Two narrowing decisions are stacked — the band below 65 B is untimed by decision, and the bar is a 5% tolerance — and the claim names neither |
| no use-after-free, no leak | Miri for safe-Rust paths; the differential test for SIMD paths | **no run here** — `safety.yml` has no completed runs in this repository, so neither the safe paths nor the SIMD gap have a current verdict; a differential test proves the bytes, not the absence of UB |
| no work generated and discarded | `bench.yml` gate 2 over the ladder's own count at every length and 6 offsets; `record::tests::the_ladder_reports_the_blocks_the_caller_asked_for` | green, and it can fail: `xor_groups` returns the blocks it generated |
| no heap allocation, no zero-fill | `ferrox-bench`'s counting allocator, gate 2 | green, and it can fail: it counts `alloc`/`dealloc` and `write_zeroed` deltas |
| the `VLESS` request header encode is no slower than the encode it replaced, and writes the same bytes | `bench.yml` gate 4, three address families, each asserting equal length and bytes against `previous_encode_into` before either side is timed | **no CI verdict yet** — gate 4 landed with the encode it measures; measured on an M2 at 3.02x (IPv4), 2.87x (IPv6), 2.93x (domain) |
| the `ChaCha20`-`Poly1305` seal is no slower than the two-call seal it replaced, same bytes and tag | `bench.yml` gate 7, five lengths, each asserting equal ciphertext **and** tag against `chacha20_poly1305_seal_in_place_unfused` before timing | green — 1.07x-1.51x at 64 B, 1.03x-1.15x at 256 B, 1.01x-1.08x at 1 KiB, 1.00x-1.08x at 4 KiB, 1.00x at 16 KiB. The fused head deletes one *uninterleaved* single-chain pass, worth a lot on a short frame and amortising to nothing on a long one. Worst cell on any runner is 0.98x at 1 KiB on `macos aarch64`, above the bar and inside the same runner's 1.08x at 4 KiB, so it reads as noise |
| where the seal's time actually goes | `bench.yml` gate 7b, the keystream half and the `MAC` half timed apart, each row self-timed so the ratio is the harness's noise and the absolute is the cost | read, and it picks the next target. Poly1305's share of the seal is 33/39/36/33/32% on `linux x86_64`, **45/62/64/63/63% on `linux aarch64`**, 37/46/46/43/43% on `macos aarch64`, 28/42/48/47/46% on `windows x86_64`. Per byte it runs at 0.49-1.12 ns/B and is the *slower* half on `linux aarch64` at every length ≥ 256 B. **Not gated**, deliberately: a row measured against itself fails on noise |
| three 44-bit `u128` limbs instead of five 26-bit limbs — is `Poly1305` faster where it ships? | gate 7b's self-timed `MAC` half with gate 7b's **unchanged** `chacha20` rows as the drift control. Deciding pair: run 37266252879 on the pre-rewrite `main` against 37288184258 on the rewrite alone. Landing pair: 37290368488 on `main` against 37290341781 on the hybrid; through gate 5, `parity.yml` 37290354716 on `main` against 37290328145 on the hybrid | **landed, as a hybrid selected by length.** The rewrite alone was three runners gaining 1.03x-1.43x and `macos aarch64` losing on an unchanged control: `windows x86_64` 1.31x-1.37x, `linux x86_64` 1.34x-1.36x, `linux aarch64` 1.05x-1.29x, and `macos aarch64` 1.55x-1.61x at 64-256 B against **0.88x at 1 KiB, 0.68x at 4 KiB, 0.81x at 16 KiB**. That is what PR #56 measured, said should not merge, and named the fix for; #49 merged anyway, so `parity.yml` has been red on `macos aarch64` since — 37288184258 at `seal 1024B=0.805x`, 37290354716 at `16384B=0.949x`. **The dispatch**: below 512 B the three 44-bit limbs; 512 B and up on `aarch64` the two-way `NEON` path in five 26-bit limbs; everything else the three limbs. **What it bought**: `macos aarch64`'s gate-7 seal is 1.12x-1.37x faster than `main` at every length and back over the bar, and `parity.yml` 37290328145 is green there where 37290354716 was not. **What it cost**: `linux aarch64` gives up the 1.05x-1.18x the three limbs held from 1 KiB up and lands at 0.95x-0.98x of `main`, still above the bar |
| **gate 7c's two sides were measured in two separate blocks, and a quotient of two independent minima is not a measurement** | `crates/ferrox-bench/src/framing.rs`'s `timed_row`, now `paired`, with three tests on the shape of the measurement | **landed, and the evidence is four runs of one unchanged `poly1305.rs`.** Run **37357205328** on `main` (18:36, `sha c901186`) has all four runners green, with gate 7c at **1.30x-1.39x** on both `x86_64` — `linux x86_64` publishing `12440.2 ns` for the reference and `8939.8 ns` for this tree at 16 KiB, against `12436` and `8977` in run **37325906806** (14:35): two runs agreeing to within **0.3%** on both absolutes. Run **37337365219** (16:00) is the outlier: the same code published `5289.6` and `6084.5` and **0.87x**, and failed — its reference was **2.35x** faster than the other two while this tree was only **1.47x** faster, and gate 9's unchanged controls put the machine itself at only 1.24x-1.52x. **What was wrong**: `best_of` timed the reference through all five rounds and then this tree through all five, in two contiguous blocks, keeping each side's minimum separately — a quotient of two independent minima. **The wrong diagnostic twice**: modelling the runner as slowing steadily *across* the row makes the old code come out only 6% off, because a minimum defends perfectly against a ramp. The defect needs a **step** — the level changing once, between the blocks — and the first synthetic test used a constant added to each side, which made the raised level's own ratio wrong |
| the engine is not slower than the pinned Go core, as a process moving the same bytes | `parity.yml` gate 5 via `scripts/run-parity.sh`: five paired repeats, 95% bootstrap intervals, whole-interval gate at 5%. **A green run: 37357205313 on `main` (18:36, `sha c901186`), all four runners `success`, with the Win32 sampler in place** — so `windows x86_64` produced its three rows for the first time and now gates rather than reporting `unproven`. Measured on an M2 (macos aarch64, 5 repeats, 1 GiB per flow, `download`) versus pinned Xray-core: xray-core 3850, `zray` 4836, ferrox 5634 MiB/s; peak RSS 31.7 / 5.5 / 2.2 MiB; harness ceiling 7507 MiB/s, so all three sat between 51% and 75% of it and no row is generator-bound. **Quoting one run's ratio would be the wrong claim**: across five runs of the same build the ordering never changed and the magnitudes did — ferrox throughput **1.24x-1.55x**, CPU per GiB **1.69x-2.00x**, peak RSS **14.1x-14.8x**; zray throughput **1.06x-1.27x**, CPU per GiB **1.10x-1.27x**, peak RSS **5.8x-5.9x** |
| the ordering, as distinct from the magnitudes | the same five runs | green and stable: ferrox > zray > xray-core on throughput, CPU per GiB and peak RSS, in every run. **This is the part that survived run-to-run noise**, and the only part quoted as a ranking |
| ...and the run-to-run spread is not hidden | nothing aggregates across runs; each run publishes its own intervals | **the gate is per-run, so a favourable run and an unlucky one both pass.** A median-of-runs aggregation is not implemented, and until it is a ratio quoted from one run carries roughly the spread above. A real gap in the method, recorded as one |
| ...and the comparison covers all five cores the pins name | `scripts/run-parity.sh` builds each from its pin and skips an unbuildable one **with its reason** | **three of five.** `sing-box` needs Go >= 1.25.5 and `xray-rust` fails `aws-lc-sys` against this host's SDK; both errors are quoted in [`methodology.md`](methodology.md). Both are the host's toolchain rather than the pins |
| ...and the launch shapes differ per engine and are carried as data | `parity::ConfigArg`: `long` (`run -config`), `short` (`run -c`), `positional` (`run <path>`), with a test per shape | green. Guessing one shape would leave every engine but one failing to start |
| ...and only on the `SOCKS` relay path | the same gate and [`methodology.md`](methodology.md)'s coverage table | **the claim is narrower than it looks.** `TUN`, `UDP`, `REALITY`+Vision, gRPC/XHTTP and geodata routing are `not_covered`, each with its reason; two rows are `partial`. The `SOCKS`→direct path is the only process-level path measured, so this says nothing about a `VLESS` or Shadowsocks relay |
| ...and the gate's own rules are `ZeroNet`'s | `crates/ferrox-bench/src/stats.rs`, one constant per rule, with a test pinning each | green by reading: `TOLERANCE = 0.05`, `MIN_PAIRS = 2`, `MIN_RUNS = 3`, `HARNESS_BOUND = 0.85`, `BOOTSTRAP_RESAMPLES = 4000`, CPU floor 10 ms — each traceable to a line in `upstream/zeronet/` |
| ...and peak RSS is gated at **5%**, not ZeroNet's zero allowance | `stats::RSS_TOLERANCE` | **deliberately looser than the reference criterion**: a direction-only memory rule fails on any difference at all, including the allocator differing between a macOS and a Linux image. The hard gates are throughput and CPU |
| the four-way `Poly1305` absorb (`r^4`, one fold per four blocks) is faster than the scalar stride-two loop it replaced | `bench.yml` gate 7c's accumulator ratio against its fixed 26-bit reference, read against a **same-code control run**: `37385373909` and `37387574166` on `main` (pre-merge, same `poly1305.rs`) against `37385379698` on the branch and `37386799470` (main + the chacha `NEON` change only, same `poly1305.rs`) | **wins at 4 KiB and 16 KiB, loses below it, and the cross-run spread had been hiding the second half.** Normalised against the same-code controls: `macos aarch64` `3.00x`/`3.19x` against `2.06x`/`2.28x`/`2.29x` and `2.23x`/`2.43x`/`2.39x` — a 36% win; `linux x86_64` `1.81x`/`1.87x` against `1.69x`/`1.67x`/`1.61x` and `1.75x`/`1.74x`/`1.68x` — a 9% win. Below 4 KiB it is behind: `1.38x` at 1 KiB on `linux x86_64` against three same-code runs reading `1.49x`/`1.49x`/`1.41x`, and `1.30x` at 256 B on `windows x86_64` against `1.59x`/`1.58x`. So the dispatch now hands 4 KiB and above to the four-way path and everything from one pair to 4 KiB to the scalar stride-two loop on **every** architecture |
| the four-way absorb's thresholds are right, and what is left on `linux aarch64` at 4/16 KiB | the same gate 7c ratio, run `37391443290` on `main` after #107 against the same-code controls above | **the 256 B-2 KiB band is restored and one band is still short.** Restored: `linux x86_64` `1.69x` at 1 KiB against `1.49x`/`1.49x`/`1.41x`, `windows x86_64` `1.62x` against `1.46x`/`1.47x`, with the 4/16 KiB win intact (`macos aarch64` `2.99x`/`3.25x`, `linux x86_64` `1.80x`/`1.88x`). Still short: `linux aarch64` reads `1.51x`/`1.56x` where the pre-merge controls read `1.57x` three times and `1.63x` three times, about 4-5% behind. **This is not the four-way path's fault alone, and turning it off does not fix it**: #108 gated `NEON4_THRESHOLD_BYTES` to `usize::MAX` off `macos`, ran, and `linux aarch64` read `1.48x`/`1.49x` -- the scalar pair loop is behind the four-way path there too. What is missing is #100's scalar **two-lane** loop (`absorb_long`: two pairs per fold, `r^4`/`r^3`/`r^2`/`r` weights, one fold per four blocks, in the three 44-bit limbs), which the four-way absorb's whole-file replace dropped on every architecture and which is the shape that read `1.57x`/`1.63x`. Open work: port that loop back, and let the dispatch choose per runner |
| **cross-run absolute `ns/op` on these runners decides nothing, and a single control run hides it** | gate 7b's self-timed `noise` column, which times one side of a row against itself | **the runners are not comparable across runs, and the column that shows it is the one nobody reads.** Control run `37385373909` reads its two identical `macos aarch64` sides at `0.68x` at 16 KiB, and the same `poly1305.rs` reads `34%` apart between `37385373909` and `37386799470`; the `x86_64` runners reproduce to `2%` and `macos aarch64` to `10%` at 4 KiB but only `27%` at 1 KiB. Every cross-tree claim in this file is therefore a **ratio against a reference compiled into the same binary**, read against at least two same-code runs — a claim below that spread is not a claim |
| the relay is faster than it was, by 2.2x | the measurement `proxy.rs` records next to `RELAY_BUFFER` | green as a local measurement: with `io::copy`'s default 8 KiB the gate read 0.60x [0.54, 0.70]; with a 256 KiB buffer 1.36x [1.31, 1.41]. Both rows are `target/bench-report.md` from two gate-5 runs on the same host — and the row most likely to be quoted without its "single flow, download, `SOCKS` to direct" qualifier |
| the `VMess` auth id key schedule is built once per session | `vmess::AuthKey`; `expired_auth_ids_are_refused`, `auth_ids_round_trip_and_reject_damage` | green by reading; **no timed gate** — one `HMAC-SHA256` schedule and one `AES-128` key expansion removed per connection on each role, which is a count and not a measurement |

## The rest of the README

| claim | checked by | verdict |
| --- | --- | --- |
| "One algorithm, three widths", backend table listing three | `chacha/mod.rs`: four `Lanes` impls | **stale**, corrected |
| Miri interprets the ladder, the counter arithmetic, every store offset | `safety.yml` on `x86_64`, where `is_x86_feature_detected!("avx2")` is false under Miri and the portable path is taken | green for `portable`; the one-block tail on that runner is `sse2`, which a local Miri probe interprets but **no CI run has yet** |
| `chacha20` 0.9.1 selects NEON only behind a cfg nothing sets | `core.rs::backend()`; the pinned crate's `backends.rs` | read |
| every report prints both backends | `ferrox-bench`'s `build_report` | green, by construction |
| `TlsProvider` is `Read + Write` | the trait bound in `tls/mod.rs` | green, by construction |
| no feature selects a TLS stack; no build without TLS | no feature in `crates/ferrox-core/Cargo.toml`; `rustls` is a hard dependency | green, by construction |
| "TLS interface + 2 backends" (Layout) | one `impl TlsProvider`: `RustlsProvider` | **stale**, corrected |
| "the released ferrox-core" (Layout) | every crate is `publish = false` | **stale**, corrected |
| `.github/scripts/` per-OS provisioning (Layout) | the directory does not exist | **stale**, corrected |
| `upstream/<name>/` checkouts are never committed | `.gitignore`: `upstream/*`, `!upstream/pins.toml` | green |
| "Quiche is the default QUIC" | nothing: `quiche` is in no manifest | **no checker** — a decision rule for a rung that does not exist |
| every way PattNG can connect parses | `vless::tests::unknown_transports_parse_but_stay_planned`, plus `support()` | green for the rows a link can name; the 10-row matrix exists only in a benchmark report |
| one method dials at a time | `vless::support()` and `ferrox-app run`'s TCP reachability | green |
| upstream suites run against Ferrox binaries | `conformance.yml` via `run-upstream-suite.sh`: 2 of 12 enabled ran green, 10 skipped | green for the subset; the script still refuses a `PASS` naming a binary it did not execute, and now a `PASS` whose `running N tests` disagrees with the names its pin carries |
| a `REALITY` inbound authenticates the pinned peers' `ClientHello` | `tls::reality`'s own tests for every refusal path, plus the live measurement in [`conformance.md`](conformance.md): the pinned `Xray-core` gets past authentication with fingerprint `chrome` | **green for the handshake, red for the session**: the `TLS` handshake then cannot negotiate, because the certificate `REALITY` recognises must be `Ed25519` and no `uTLS` fingerprint offers `0x0807`. **No CI verdict** — the seven `reality`/`vision` rows were deliberately not added to the enabled suite command, because a command naming rows which fail makes `conformance.yml` red without adding evidence. P21 owns the certificate |
| the `Vision` framing is byte-identical to `Xray-core`'s | `vision`'s own tests over the frame layout, the three commands, split frames, truncation and the `TLS`-record boundary | green **by reading the pinned `proxy/proxy.go`** and by construction; **no differential run**, because the session that would carry it cannot complete a handshake |
| `ferrox-app check` parses offline, `run` dials TCP and sends nothing | the two verbs in `crates/ferrox-app/src/main.rs` | green, by reading; `version`, `x25519` and `run -c` are covered by `proxy::tests` and `json::tests` |
| every slice in `prompts.md` carries status, leverage, effort, gates, dependencies | `ferrox-prompt check`, run by `ci.yml` and `scripts/check.sh` | green, 0 errors |

## `methodology.md`

| claim | checked by | verdict |
| --- | --- | --- |
| the report is written before the gate is asserted | `ferrox-bench/src/main.rs`; `bench.yml`'s `publish the table` runs `if: always()` | green |
| best of five interleaved rounds per side | `measure_len`, `ROUNDS = 5` | green, by reading |
| a length under the bar is re-measured at 4x the budget | `measure_len`'s re-measure branch | green, by reading |
| gate 2 covers the record layer at every length and the rung-1 header encode across three address families | `gate_deterministic`, over `192.0.2.53`, `2001:db8::1`, `example.com` | green for the counts |
| `check-leak-surface.sh` is the static half: no DNS, no leak primitives, no printing, no wall clock | the script's four `git grep`s, run by `ci.yml` and `scripts/check.sh` | green |
| `check-upstream-pins.sh` fails on an unresolvable pin, a missing `rev`, or an unparseable file; each `rev` by depth-1 fetch, not `ls-remote` | the script; 12 of 12 resolve on `ubuntu-latest`, the single runner `pins.yml` names | green |
| `update-pins.sh` prints the diff and opens a PR rather than pushing | the script's `gh pr create` | green, imprecise: it does `git push` the branch it opens the PR from |
| every benchmark report ends with the per-method matrix | `methods::table()` appended in `build_report` | green |
| a SIMD backend is measured on one native runner per ISA | `bench.yml`'s four-runner matrix | green |

## `unsafe-policy.md`

| claim | checked by | verdict |
| --- | --- | --- |
| every `unsafe` block carries a `SAFETY:` comment, enforced by `undocumented_unsafe_blocks` | `[workspace.lints.clippy]`, run by `ci.yml` | green |
| `unsafe` is allowed only where the safe form was **measured** slower | nothing: no gate, script or test records that measurement | **no checker** |
| the seven wins listed under "what this has already bought" | six of the seven are safe-Rust changes; the `unsafe`-surface claim does not follow from them | **no checker** on the framing; each code change is visible in the tree |
| the differential sweep is 528 shapes in tests and 3600 in the gate, unchanged and green | `core::tests` and `bench.yml` gate 1 | green |
| the AVX2 probe leaves the hot loop, which "splits into two branch-free loops" | `xor_blocks` branches once around the whole ladder | **stale**, corrected |
| "`xor_block` tail: bounds-checked indexing only" | on `x86_64` the one-block tail is `chacha::sse2`, which is `unsafe` intrinsics | **stale**, corrected |
| `grep allow_plaintext_to_public` finds every plaintext path | the grep hits `policy.rs` and a report cell. The plaintext decision lives in `transport::Security::NoneToPublic` and does not mention the opt-in | **red**, corrected |
| no `unsafe` in `record::fill_exact` or `chacha::portable` | one `unsafe` in `chacha/mod.rs` (the AVX2 call), none in either named file | green |

## `arch/overview.md`

| claim | checked by | verdict |
| --- | --- | --- |
| the claim-to-gate map in the diagram, including "no discarded work — `fill_exact`'s own return value" | `bench.yml` gate 2 | **vacuous** |
| `chacha::xor_blocks` is "vector groups, then a scalar tail" | `xor_tail` runs the widest exact width; the single block is scalar only off `x86_64` | **stale**, corrected |
| one generic function instantiated for three backends | four | **stale**, corrected |
| keystream is "XORed in place, never staged" | a partial block's last sub-chunk is materialised in a 16-byte stack scratch, in both `xor_groups` and `portable::xor_block` | **stale** — corrected to name the exception |
| the counter advances only by blocks produced | the ladder advances it by what each pass produced; gate 2 cannot confirm it | green by reading, **vacuous** as a gate |
| 528 shapes in tests, 3600 in the gate | `core::tests` and `bench.yml` gate 1 | green |
| the reference is scalar on aarch64, AVX2 on x86_64 with AVX2, SSE2 without | `core::backend()` and the pinned crate's `backends.rs` | read |
| `bench.yml` runs daily and fails on any single regressing length | `bench.yml`'s cron and gate 3 | green |

## `arch/superset.md`

| claim | checked by | verdict |
| --- | --- | --- |
| every row parses, exactly one dials | `vless::support()`, generated into the report's per-method table; rows 5, 6, 9, 10 are static text in `methods.rs`, not read from the parser | green for the rows a link can express; **no checker** for the static rows |
| `VlessLink::parse` never fails on an unknown transport | `vless::tests::unknown_transports_parse_but_stay_planned` | green |
| the row statuses in the table | rows 1-4, 7, 8 come from `live_support()`; rows 5, 6, 9, 10 are written by hand | partly checked |
| `compare.yml` prints an offline table, and live columns with a secret | the workflow's `vless_link` and `live` inputs | green |
| `UnsafeOptIn` gates plaintext-to-public and unsafe fingerprints | `policy::UnsafeOptIn`; the two `pattng_*_needs_opt_in` tests | green |

## `conformance.md`

| claim | checked by | verdict |
| --- | --- | --- |
| "running upstream suites **against Ferrox binaries** in CI" | `zeronet` points its suite at `ferrox-app` via `ZRAY_XRAY_BINARY`, `xray-rust` at the same binary via `XRAY_VLESS_FULL_BINARY`; ten entries are `test_enabled = false` and skip | green for the 8-of-17 and 7-of-23 subsets — `run-upstream-suite.sh` compares each command's filter names against libtest's `running N tests`, so both counts are measured rather than asserted |
| `test_enabled = true` means the suite runs in `conformance.yml` | `conformance.yml` → `run-upstream-suite.sh`: `RUNNING: …`, then `PASS: … suite green against ferrox-app` | green, and the log line names the binary and the pin. **The workflow has no `push` leg** — it fires on a pull request touching the crates a suite exercises, on the weekly cron, and on dispatch, so "every push" would have been false and `conformance.md` says so |
| `test_enabled = false` means the job is created, skips, and prints the reason | the same log: ten `SKIPPED:` lines, each naming the pin | green |
| a suite flips to `true` only when the benchmark gate is green on all four ISA runners | `zeronet` is `true` on the oracle differential with no benchmark gate behind it | **exception, named** — `conformance.md`'s flip rule and the pin's `note` authorize it; the general rule holds for every other entry |
| the twelve revs and enabled bits in the current-state table | `upstream/pins.toml` | green: ten `false`, two `true`, all match |
| a suite `PASS` means the suite ran what its pin names | `run-upstream-suite.sh`'s `libtest_ran_named`, self-tested on four synthetic outputs before any suite runs | green — zero tests is refused, and `N` must equal the filter names. **A harness that prints no `running N tests` line is not counted at all** and says so; today's two suites are both `libtest` |

## `function/chacha-xor-blocks.md`

| claim | checked by | verdict |
| --- | --- | --- |
| one `quarter_round`, one `rounds`, generic over `Lanes`; three backends | four `Lanes` impls | **stale**, corrected |
| the group is `GROUP_STATES = 4`, i.e. 8 blocks on AVX2 and 4 on NEON and portable | `chacha/mod.rs` | green |
| the tail's single block goes to the scalar core | true off `x86_64`; on `x86_64` it is `chacha::sse2` | **stale**, corrected |
| Miri covers `portable` in full and `sse2` in full | `safety.yml`'s last completed run predates `chacha::sse2` | green for `portable`; **no CI run yet** for `sse2` |
| `rot_chunks` is `vpshufd` on AVX2 and `vextq_u32` on NEON | also `pshufd` in `sse2.rs` | **stale**, corrected |
| the `vpshufd` immediates are literals proved by `rot_imm` and a `const` assertion | `avx2.rs` | green |
| the differential test catches a lane mix-up at 3600 shapes | `bench.yml` gate 1 | green |
| the one-block band is a tie, with the numbers | the measurement was taken on one contributor's aarch64 machine and no named runner reproduces it | read, and the one claim in this file no CI run checks |

## `function/record-fill-exact.md`

| claim | checked by | verdict |
| --- | --- | --- |
| generating "exactly as many blocks as the buffer needs" | `bench.yml` gate 2 | **vacuous** |
| the counter-advance test calls the core, unlike the version before it | `record::tests::the_counter_advances_only_by_blocks_produced`, 20 lengths | green |
| 2 key pairs x 6 block offsets x **46** lengths | 44 lengths: 528 shapes | **stale**, corrected |
| `blocks_for` compared at 20 lengths | `record::tests` | green |
| no `unsafe` in this function or in `chacha::portable` | true of both | green |
| every store is derived by `chunks_exact_mut` | `as_chunks_mut`, since the partial-block path | **stale**, corrected |
| the counter is checked before any work, and the buffer is untouched when it panics | `record::tests::refuses_a_wrapping_counter` | green |
| Xray-core and sing-box take a four-block refill from an AEAD interface that cannot stream | the `upstream/` checkouts, which are `.gitignore`d and checked by nothing | **no checker** |
| the reference's AVX2 backend computes four blocks per call and uses one when asked for one | read in the pinned `chacha20-0.9.1` source under `~/.cargo/registry` | read |
| the reference table by target | `core::backend()` prints the backend that ran, in every report | green |

## `function/mux-frames.md`

| claim | checked by | verdict |
| --- | --- | --- |
| multiplexing is a connection method Xray-core, sing-box and `PattNG` all carry and this workspace had none of | read at the three pins; xray-rust has no mux and rejects `mux.enabled` in its config parser | read |
| the worked frame `00 14 00 01 01 01 01 00 50 02 0b "example.com" 00 04 "abcd"` is the format's | `mux::tests::a_new_frame_is_the_bytes_the_fields_add_up_to` | green for the derivation; **no oracle** |
| the frame bytes match Xray-core's at the pinned rev | **no checker** — `common/mux` has no environment seam and sing-box keeps no framing in-tree | **no checker**; stated in `mux-frames.md`, `conformance.md`, `muxframe.rs`'s header and its report text |
| every one of the 256 domain lengths round trips | `mux::tests::every_domain_length_survives_a_round_trip` | green |
| the decoder reads a strict superset of what the encoder writes | `the_decoder_reads_a_superset_of_what_the_encoder_writes`, and the bench's bridge row | green |
| an unknown status byte is refused rather than ignored | `the_decoder_refuses_only_what_it_cannot_frame`; upstream ignores it and then desynchronises, because the chunk length after the metadata is never read | green |
| `META_MAX` is 781 and 781 is accepted where upstream's reader stops at 512 | `a_frame_that_claims_more_than_the_format_holds_is_refused` | green |
| session ids are refused at the end of the field rather than wrapped | `ids_are_handed_out_once_each_and_refused_rather_than_wrapped`, all 65535 ids | green |
| the session table's size is a function of the cap, not of the id a peer sends | `an_id_a_peer_invents_costs_a_slot_it_already_paid_for`, `a_closed_slot_is_reused_rather_than_left_to_pile_up` | green |
| upstream's `u16` counter wraps and overwrites a live session with id 0 | read in `common/mux/session.go` at the pin | read |
| no allocation and no copy on either side of the codec | `bench.yml` gate 6, the counting allocator, on both sides of every row | green — run `37242106411`, 9 mux rows field-identical to their references and 0 allocs on both sides |
| not slower than a reference shaped like upstream's | `bench.yml` gate 6 | green for the gated rows; the rest are reported without being judged |
| the four gated *decode* rows clear 0.95x on every runner | gate 6: 1.52x-2.71x on all four runners | green on the numbers measured |
| the *encode* and *bridge* rows are printed and **not** gated | `muxframe::REPORTED_ONLY` | **deliberate, and here is the measurement.** For one identical twenty-byte frame this side is 9.4-11.6 ns across the four runners — a 1.23x spread — while the reference is 8.5-16.8 ns, a 1.98x spread, faster than the code under test on one runner and slower on three. A ten-nanosecond ratio is settled by inlining. Two references make the point from opposite ends: a pre-sized-slice reference is stable at 8.7-9.0 ns and puts this side at a reproducible 0.75x-0.87x; a `Vec` reference swings the same comparison from 0.78x to 1.51x. Neither separates a ten-percent regression from a compiler version. The **bridge decode** row fails the same test from the mirror image: *this* side moves 2.2x there while the reference holds 29.7-33.9 ns, a 1.14x spread, and it is the only shape whose decoded value carries a seventy-byte by-value `Reflection` |
| Miri interprets the mux codec | `safety.yml` runs `cargo miri test -p ferrox-core`, which reaches `mux::tests` | **no CI verdict yet.** The last verdict on `main` is FAIL (`d6b1647`, 2026-10-04), on a tree that did not contain this rung. The module is safe Rust with no `unsafe`, `transmute` or `from_raw_parts`, so the exposure is an out-of-bounds index panicking rather than undefined behaviour — but "should be fine" is not a Miri result |
| "the reference is built to the shape upstream has, not from upstream" | `muxframe.rs`'s header, restated in the report text | read |
| sing-box's mux keeps no framing in-tree | the pin has no `transport/v2ray/header/` and no mux codec; the framing is in three out-of-tree modules | read |

## `function/early-data.md`

| claim | checked by | verdict |
| --- | --- | --- |
| the `?ed=` rewrite is `Xray-core`'s, including `Atoi`'s ignored error and the `uint32` truncation | `transport::tests::early_data_split_matches_go_arithmetic` and `…atoi_reproduces_the_three_answers`, 22 vectors and 13 numbers | green by reading the pinned `infra/conf/transport_method.go` and by construction. **Not differential**: no upstream suite calls a config parser, and the vectors are hand-derived from Go's `url.Parse`/`Values.Get`/`strconv.Atoi` semantics |
| the digits are `RFC 4648` base64url, unpadded | `…base64url_matches_rfc_4648` and `…round_trips_every_length` over 0-192 | green |
| `?ed=` adds one header line and changes nothing else about the request | `ws::tests::early_data_adds_one_line_and_truncates_nothing` | green |
| the budget's bytes reach a server, with a budget that fits and one that does not | `ws::tests::early_data_reaches_the_server_with_and_without_a_budget_that_fits` at `ed=2048`, `ed=4`, `ed=3` | green over this tree's own two roles — **self-referential**: it proves the bytes and the arithmetic, not interop |
| `ed` moves no bytes on `httpupgrade` | `httpupgrade::tests::an_early_data_budget_leaves_the_request_unchanged`, four budgets including `0` and 2³²−1 | green by reading the pinned `transport/internet/httpupgrade/dialer.go` (it only skips an eager `101` read) and `xray-config/src/parser/stream.rs` (it parses `ed` and ignores it), and by construction |
| **under one allocation per encode**, where `ZeroNet`'s own shape makes two | `bench.yml` gate 8: counting global allocator over 64 encodes, this side under one per encode and the reference at two or more, both printed on every row. **The bar is deliberately not zero**: a release bench from `main()` with nothing else running reads 6 allocations / 8064 bytes in one window and **1 allocation of 8192 bytes** in a second identical window, and an 8 KiB block is not a `String` this code builds — its warmed buffer is 64 bytes and never grows | green in run `37251890402` — **6 allocations over 64 encodes here against 128, 256, 256 and 256** in the reference's shape, the same six at every payload length. P24 owns finding the 8 KiB block |
| not slower than `ZeroNet`'s shape | `bench.yml` gate 8, four rows at 8/120/256/2048 B, every row asserting the finished header line is equal and decodes back *before* either side is timed | green in run `37251890402`. **Ratios are not transcribed here**; `bench.yml` on four native runners is what publishes them |
| "the four cannot be run in-process to hand a `String` back to this binary" | the seam table in `conformance.md` | read |
| the setting was a real gap rather than a missing nicety | [`conformance.md`](conformance.md): two `xray-rust` oracle rows were red on it, and both died on the same defect | green — two named tests, each with its measured failure |
| "surviving pairs keep the order they were written" | `…matches_go_arithmetic` covers `/p?a=1&ed=4&b=2` | green for sorted queries, which is every query in the matrix. **Divergence, named:** `Xray-core` sorts them and writes a stray empty pair back as a bare `=`; the one input where the two answers differ is a path no peer serves |
| `xhttp.rs` still has its own header walk | P22, which is why it is a slice and not part of this change | read |

## `function/shadowsocks.md`

| claim | checked by | verdict |
| --- | --- | --- |
| the `method=` table is `Xray-core`'s spelling set for these three ciphers | `ferrox_core::shadowsocks::tests::the_method_table_is_xrays_spelling_set` — eight spellings accepted, ten neighbours refused | green by reading the pinned `infra/conf/shadowsocks.go` and by construction. **Not differential**: the vectors are hand-derived from that `switch` |
| the master key is the `MD5` chain `EVP_BytesToKey` specifies, at the method's length | `…the_master_key_is_the_value_written_down` and `…the_master_key_is_the_md5_chain_and_no_longer`, which walks both rounds | green |
| the session key is `HKDF-SHA1` over the **master** key, `ss-subkey`, truncated to the method's length | `…the_session_key_is_derived_at_the_methods_own_length` | green by reading `proxy/shadowsocks/config.go`. Load-bearing and not only a cost point: a 32-byte `HKDF` input is a different input than a 16-byte one, so the earlier always-32 derivation was wrong for `aes-128-gcm` and not merely wasteful |
| `aes-128-gcm` is `AES-128`, and the `AES-256` schedule cannot reach it | `…aes_gcm_refuses_the_other_methods_key_length` and `…aes_128_is_its_own_cipher_and_not_a_widened_key` | green, **after a correction this row records.** The first draft asserted `Aes256Gcm::new_from_slice` accepts 16 bytes and zero-extends them; run `37263819768` answered `InvalidLength`. `aes-gcm` is strict, which makes the hazard a **slice** rather than an acceptance: one 32-byte session key and `&key[..32]` for every method seals an `aes-128-gcm` link with the `AES-256` schedule, round-tripping between two endpoints of this tree and failing against every peer. The second test puts this crate's output next to `aes-gcm`'s keyed with the **session** key — its first draft compared against the *master* key and run `37264034762` disagreed on the first four bytes, which is the two-step derivation working |
| the nonce is a little-endian counter in the first eight bytes | `…the_nonce_is_a_little_endian_counter_in_the_first_eight_bytes`, at chunks 0/1/255/256/257/2³²−1 | green by reading `crypto/auth.go` and `SIP004`. **Already differential**: the `aes-256-gcm` conformance row proves it both directions against real `Xray-core` |
| each method seals and opens its own chunk and refuses a forged tag | `…every_method_round_trips_a_chunk_and_refuses_a_forged_tag` at six lengths, and `…the_methods_are_not_interchangeable` | green |
| `chacha20-ietf-poly1305` is byte-identical | it seals through [`ferrox_core::aead`], whose `is_byte_identical_to_the_crate_it_replaces` sweeps the pinned `chacha20poly1305` crate at every length | green, and **inherited**: this rung adds no cipher arithmetic of its own |
| the framing is byte-identical | `xray_oracle::shadowsocks_over_raw_tcp_matches_the_oracle`, `zeronet` at `97a99734`, both directions, `aes-256-gcm` | green in `conformance.yml`; the row does not yet name the two added methods, because the oracle's `protocol_settings` hard-codes `aes-256-gcm` |