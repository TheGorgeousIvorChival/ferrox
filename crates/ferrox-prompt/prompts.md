# Ferrox prompt library — single source of truth

`ferrox-prompt` reads this file and nothing else. No prompt prose lives in Rust, and a prompt is added by adding a section here: no code change, no recompile. If the tool and this file disagree, this file is right and the tool is broken — which is why `ferrox-prompt check` is a CI step.

## How to read this file

One prompt per `## P<n> · <title>` section. The numbers are the roadmap: the tool counts what each one unblocks rather than leaving it to be worked out by reading every heading. Every prompt carries these lines, and `check` fails if one is missing, because a prompt nobody can tell when to use, or cannot tell when it is finished, is a prompt that will be started and abandoned:

| line | required | meaning |
| --- | --- | --- |
| `**When to use:**` | yes | the situation that calls for this slice; if you cannot describe it, the slice is not ready to be listed |
| `**Status:**` | yes | `todo`, `doing`, `done` or `blocked` — the only field a contributor edits to record progress |
| `**Leverage:**` | yes | 1-5, how much this moves the rest of the roadmap; the advisor ranks on it |
| `**Effort:**` | yes | `small`, `medium` or `large`; ties are broken towards the smaller one, because a finished small slice unblocks more than a started large one |
| `**Gates:**` | yes | semicolon-separated checks this slice must pass, printed verbatim; wrap a command in backticks so it reads as a command |
| `**Depends on:**` | no | other prompt ids, comma-separated; a prompt is ready only when every one of them is `done` |
| `**Touches:**` | no | comma-separated paths this slice edits, `+` prefixed for one it creates; `check` verifies the first kind exists and the second does not |
| `**Random weight:**` | no | 0-9, for `--rotate`; 0 excludes it from draws, absent means 1 |
| `**Prompt protocol:**` | no | a rule that applies to this slice alone, layered under the shared protocol |

Paths under `upstream/<name>/` are pinned reading copies for agents, fetched by `scripts/fetch-upstream.sh`: `xray-core`, `sing-box`, `amneziawg-go`, `amnezia-client`, `xray-rust`, `pattng`, `zeronet`, `mqvpn`, `aether`, `zeptun`, `slipstream`, `quiche`. They never appear in `**Touches:**` — checkouts are derived artifacts, and a touch naming one fails the gate wherever it was never fetched.

Placeholders are `{name}` or `{name=default}`. A name with a default is filled by it. A name without one is a decision this tool refuses to invent: `next` prints the exact command to run and exits 2 rather than sending an agent a prompt with a hole in it, and `--allow-unfilled` renders the hole loudly at the top of the prompt instead of silently. The body is the single fenced block in the section: a second fenced block is an error rather than a fallback, because "first block" and "last block" are both guesswork that quietly renders the wrong text; add-ons are the extension mechanism and they are single lines:

```
**Add-on — <name>:** <one line of extra instruction>
```

## Shared protocol

```text
You are working on Ferrox, a from-scratch proxy core that claims two things and checks both: its output is byte-identical to the upstream implementation it replaces, and it is not slower than that implementation at any single measured length.

A claim in this repository is either checked by something that runs or it is not made. Never write a claim without naming the thing that checks it, and if there is no such thing, say so in the same sentence.

Two classes of check, and the split is not negotiable. Local, before every push: lints and exact operation counts — `./scripts/check.sh` runs fmt, clippy, doc, the policy checks, the counts and the workspace tests, because a lint found locally is free and an instruction count is the same number on every machine. Never local: anything connection-dependent. Every contributor machine sits behind a VPN and a proxy, so a local benchmark measures a tunnel, a local conformance run measures somebody's exit node, and a local dial measures neither this code nor the reference. Benchmarks, comparisons, upstream suites and Miri run in CI on a runner whose architecture is named in the job, or they do not run at all. Author locally, push, read CI.

Report tersely what happened and what did not work — verdicts, never a history of the diff. A slice that fails is worth more to the next contributor than a slice reported as done that quietly did half of its gates.

Report shape, every time: what changed, what was measured with numbers, what is still open.

Do not widen the scope of the change beyond the slice. If the slice exposes a larger problem, record it as a new prompt section in prompts.md rather than fixing it here, so the roadmap stays the honest description of what is left.

Every gate listed under Acceptance must be green before the slice is reported as done. If a gate cannot be run, say which one and why, and do not describe the slice as complete.

Rewrite, do not copy. No upstream line or test enters this tree: learn how each of the four implementations does it, find where it copies, branches, or refills needlessly, and write the smaller thing that is bit-identical and cheaper. Carry the minimal subset that covers the matrix — a superset of connection ways, a subset of code.

Faster, safer, leaner, or it does not land. Fewer operations, zero surviving copies: factor the math, fuse the passes, hoist the dispatch, narrow the parse. Even parsing and checking must be proven faster — benchmark them like everything else. Think in eliminated work, not added code. Count, don't time, when proving less work: an exact instruction count from `scripts/count-ops.sh` reproduces on every runner while a duration reproduces on none, so a diff that removes one operation changes a gated number in `scripts/expected-ops.txt`, blessed only after reading what the delta is. The count gate is one of the two things that run locally, because it is the check that needs no connection and the check whose number a contributor machine reproduces exactly.

Fixes leave no trace. One line of comment per function or item at most; no TODO, FIXME, or block comments (`scripts/check-comments.sh` fails them); no changelogs in chat.

Run `./scripts/check.sh` before every push: fmt, clippy, doc, the policy checks, the exact operation counts, the prompt library and the workspace tests. That is what `ci.yml` runs, and a lint or a count found locally is free while the same finding in CI is a runner somebody else is waiting behind. `scripts/count-ops.sh` needs `valgrind`; a machine without it does not get to skip the gate, it installs it.

No workflow here runs on a merge unless a merge can break it. `bench.yml`, `parity.yml`, `compare.yml` and `speedtest.yml` are dispatch-only plus a schedule: if this slice's **Gates:** name one of them, dispatch it and wait for it, because nothing else will produce that number. A commit that touches only Markdown outside `crates/ferrox-prompt/` starts nothing at all, so do not expect CI to tell you a prose edit was fine.

Simpler with less code wins every tie at equal performance: the explainable form ships, the clever one must prove it is faster to survive. No debt lands to be cleaned later — no second way of doing something, no abstraction for one implementation, no copy left for the next slice.

Unsafe only for a measured win, safe Rust whenever it ties: if the safe form is as fast, the safe form ships, and every `unsafe` block still carries its proof obligation in one line.

A finished rung runs every related suite with a seam against it — Xray-core where one exists, xray-rust, ZeroNet — unmodified, from the pins. Green here plus red there is not done.

Local checkouts under `upstream/` are for reading. They prove nothing about speed: a number produced off a named CI runner is not evidence about any runner.
```

## P1 · Prove the vector rungs on every ISA they compile for

**When to use:** The cores are in the tree and nothing has measured them yet. A vector core that is faster and differs at one offset is a different implementation, so identity comes first and speed second.
**Status:** doing
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p ferrox-bench`; CI: `bench.yml` gate 1 on every runner in the matrix
**Touches:** crates/ferrox-core/src/chacha/neon.rs, crates/ferrox-core/src/chacha/avx2.rs, crates/ferrox-bench/src/main.rs, +docs/function/chacha-rungs.md
**Random weight:** 5

```text
`ferrox_core::chacha` now has a portable core, an NEON core and an AVX2 core behind one `Lanes` trait. The round function is written once and instantiated per architecture, so bit-identity across architectures is structural rather than merely tested: three hand-written ChaCha20 cores would drift, and the differential test would then report a mismatch without saying which one is wrong.

What still has to be checked is that each `Lanes` impl means what it claims — the lane count, the chunk layout, and the store that writes four consecutive state words per 128-bit chunk. That is the differential test at every length and every block offset, and it has to run on a runner whose architecture is named in the job, because a width chosen on Neoverse and not measured on Firestorm is a width chosen on one machine.

Name both backends in the report on every row: `ferrox_core::chacha_backend()` says what this build dispatched to, and the reference's own backend says what it compiled to. On a build where this says "scalar" while the reference says "avx2", the ratio is not evidence about the algorithm.

Keep the two key pairs that differ in every byte. An all-equal key cannot distinguish a correct word order from a permuted one, and a key that is all zeros would quietly make a swap of two identical words look correct.

Write the page under `docs/function/` before the merge, not after: a per-architecture lane layout explained in a commit message is a layout the next person has to re-derive.
```

**Add-on — isa-matrix:** Add the runner per ISA you are measuring, in `bench.yml`, and name the runner in the job name. Do not summarise a matrix as one architecture.

**Add-on — key-policy:** Two key pairs differing in every byte, and a `core 0` versus `core 8` keystream inequality, are the minimum. State in the report which of these caught which bug.

**Add-on — bit-identity-first:** Run gate 1 before gate 3, always. A wrong core must never get to be a fast one, because the timing gate would have passed it.

**Add-on — upstream-simd:** Compare lane layouts in `upstream/xray-core/common/crypto/chacha20.go`, `upstream/sing-box/transport/` with `protocol/shadowsocks/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/zero-protocol/`; note each project's transpose cost, then beat it structurally.

## P2 · Make Miri's boundary a claim that is written down and kept

**When to use:** When someone asks what memory safety is proven here. `chacha/mod.rs` now states what Miri covers and what it cannot interpret, which is the right place for it — but a statement in a module document is checked by nobody.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo +nightly miri test -p ferrox-core`; CI: `safety.yml` daily check
**Touches:**, .github/workflows/safety.yml
**Random weight:** 2

```text
Miri runs on the pure-Rust paths and cannot interpret `core::arch` intrinsics or anything linking a C library, so the safe part of the ladder, the counter arithmetic and every store offset are interpreted while the NEON and AVX2 modules are not. Put that boundary in the README's status table as well as in the module document, because the README is what a reviewer reads first.

Then make it a check rather than a sentence. The safety job should list the paths it ran, and the report should say which modules it skipped and what covers them instead — for the vector cores that is the differential test at every length and offset, and for anything linking C it is currently nothing. Say "nothing" in those words; a named gap is a plan and an unnamed one is a surprise.

Report Miri's runtime alongside its verdict. A suite that has quietly stopped running its heavy paths looks exactly like one that passed them.

Keep the nightly pin visible in the job name. Miri's results move with the toolchain, so a claim about it is a claim about a version.
```

**Add-on — miri-limits:** If a path cannot be interpreted at all, say so in the job output. Silence there reads as coverage.

## P3 · Assert the `Lanes` contract per architecture

**When to use:** When a new `Lanes` impl is added or an existing one changes, which is the only place bit-identity can now break — the round function is shared, so a bug is a layout bug and nothing else.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test -p ferrox-core --all-features`; `cargo run --release -p ferrox-bench`
**Depends on:** P1
**Touches:** crates/ferrox-core/src/chacha/mod.rs, crates/ferrox-core/src/chacha/neon.rs, crates/ferrox-core/src/chacha/avx2.rs, crates/ferrox-core/src/chacha/portable.rs
**Random weight:** 4

```text
Writing the round function once and instantiating it per architecture turned "three ChaCha20 cores that drift" into "five primitives that must mean what they say". Audit those five: the lane count, the chunk layout, the add, the rotate, and the store that writes four consecutive state words per 128-bit chunk.

The layout is the part worth reading twice. Chunk `c` of register `g` holds words `4g..4g+3` of block `c * 4 + g`, which is what lets a store write consecutive output bytes with no transpose. A lane impl that produces the right bytes through a different layout would be right by accident, and the next change would make it wrong.

Make each of those a named constant or an assertion, not a comment. `LANES`, `CHUNKS` and the chunk-to-block mapping should be one expression evaluated per architecture, so the portable core and a vector core cannot disagree about the arithmetic and only the five primitives remain per-architecture.

Report what the audit found even when it found nothing. "Checked, unchanged" is a result; silence is indistinguishable from not having looked.
```

**Add-on — boundary-straddle:** Every length boundary still needs one length either side. The regression this repository has already had lived on a group boundary at 512 bytes and was invisible at 1024 bytes and above.

**Add-on — upstream-lanes:** Audit the five primitives against `upstream/xray-core/common/crypto/chacha20.go`, `upstream/sing-box/transport/` with `protocol/shadowsocks/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/zero-protocol/`; note each project's transpose cost, then name which project does each one worst.

## P4 · Gate the documentation instead of asking for it

**When to use:** When a function is added or its contract changes and the matching `docs/function` page does not exist yet — which is the moment it will not.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo doc --workspace --all-features --no-deps`; CI: `ci.yml` lint job
**Touches:** +scripts/check-docs.sh, .github/workflows/ci.yml
**Random weight:** 2

```text
Write `scripts/check-docs.sh`, and make `ci.yml` run it. Every `pub fn` in `ferrox-core` has a page under `docs/function/`, and the script fails when one does not.

Write the script before the pages, so the pages are written against a rule that already exists. A documentation gate added after the documentation exists is a gate nobody believes will fire.

Scope is a decision rather than a default, so this slice has no default for it: the only place {scope} may be filled is on the command line. Say in the script's own header what is in scope and what is deliberately not, because the next person will extend it and should know which way.

Make the check about public API, not about prose quality. A missing page is a fact; a badly-written one is a judgement, and a CI job that grades prose gets deleted the first time it is wrong.

Report the count of pages checked. A gate that silently checks nothing is worse than no gate, because it reads as coverage.
```

**Add-on — doc-drift:** Where a page states a number — shapes tested, lengths measured, allocation counts — check the number against the code or stop stating it. A documented constant that has moved is a lie with a citation.

## P5 · Security and memory audit of the record path

**When to use:** Before any surface that an untrusted network reaches, which is every surface this project intends to ship.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo +nightly miri test -p ferrox-core --all-features`; `cargo test --workspace --all-features`; `cargo clippy --workspace --all-targets --all-features -- -D warnings`
**Depends on:** P2
**Touches:** crates/ferrox-core/src/record.rs, crates/ferrox-core/src/core.rs
**Random weight:** 5

```text
Audit the record path for the properties a network-facing primitive needs: no read or write outside the caller's buffer, no use-after-free, no unbounded counter wrap, no secret left in a buffer that outlives the key.

Every write must be a sub-slice of the caller's buffer, so a write past the end is an index panic rather than a silent overrun. Check that each rung honours that, including the SIMD rungs where a vector store's width can exceed the remaining bytes — that is the bug a scalar audit misses.

The counter wrap check is the one that matters most: `fill_exact` refuses a start block that would wrap, and if a caller can reach it by arithmetic the assertion is the last line. Write the test that reaches it.

Report each finding with the rung, the length band and the input that triggers it. "Input-dependent" is not a severity.
```

**Add-on — audit-scope:** List the paths audited and the paths skipped. An audit that does not say where it stopped reads as a clean bill of health for the whole crate.

**Add-on — upstream-record:** Read `upstream/xray-core/common/crypto/chunk.go`, `upstream/sing-box/protocol/shadowsocks/`, `upstream/zeronet/bench/hotpath/` for how each bounds its writes; ours must be a sub-slice of the caller's buffer or it is wrong.

## P6 · Report the throughput ceiling of the record path

**When to use:** When someone asks how fast the record layer is in absolute terms, which the ratio-based gate cannot answer because it only ever compares two implementations.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo run --release -p ferrox-bench`; CI: `bench.yml` on every runner in the matrix
**Depends on:** P1
**Touches:** crates/ferrox-bench/src/main.rs
**Random weight:** 2

```text
Add absolute throughput to the bench report — bytes and records per second per length, next to the existing ratio — so the report says what the core does as well as how it compares.

Keep the two separate in the report. The ratio is what this project gates on and it is machine-independent in the sense that matters; the absolute number is context and it is a property of one runner at one moment. Mixing them invites the reader to treat the absolute figure as a claim.

State the reference's asymmetry in the same breath as any number you add: it is re-keyed and re-seeked on every call, which a stateful record layer would not do, and that flatters short lengths in particular. The 16384-byte row is the one closest to a real VMess or Shadowsocks record and should be called out as the headline.

A throughput ceiling that is reported honestly is more useful than one that is withheld, because a withheld number is invented by whoever estimates it.
```

**Add-on — timing-noise:** Give any sub-bar ratio the same four-times-budget re-measurement the gate gives it. A single noisy sample that becomes a permanent table entry is the failure mode of every benchmark table ever published.

**Add-on — upstream-ceilings:** Read `upstream/zeronet/docs/benchmarks/` with `bench/hotpath/` and `upstream/xray-rust/crates/xray-bench/` for how each reports ceilings; ours stays a ratio plus a headline row, never a bare absolute.

## P7 · Ship the VLESS surface end to end

**When to use:** When the primitives, the identity gate, the upstream comparison and the review are in place, which is the first moment a surface can be built on something already proved.
**Status:** doing
**Leverage:** 5
**Effort:** large
**Gates:** `./scripts/check.sh`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix
**Touches:** crates/ferrox-core/src/vless.rs
**Random weight:** 3

```text
`vless.rs` parses the share link a ZeroNet or v2rayNG user actually pastes, preserves every query key including PattNG's `unsafe-*` fingerprints, and reports a transport this core does not implement as unsupported-with-a-reason rather than by leaving the cell out. That distinction is the whole design and it must survive into whatever is built on it.

One surface. A drop-in for Xray-core is one compatibility surface with one wire format, one config schema and one API, and a surface built on an unproven primitive inherits its bugs and its silence. Other cores are read for technique, never claimed as surfaces.

So: take the one transport the parser reports as supported — `type=tcp + security=reality + flow=xtls-rprx-vision` — and make it actually carry a record through `record::fill_exact`. Then run the pinned upstream suite against the result, unmodified, and report the count honestly including the failures.

An unsupported cell that says why is worth more than a supported one that is wrong, and a comparison table that reads "empty with a reason" is evidence. Keep that property when the table grows.

The order is deliberate: primitives first, each proved, then a surface. If the surface exposes a primitive bug, the fix is in the primitive and the surface keeps its tests.
```

**Add-on — surface-first:** Document the wire format and the config schema before implementing it, so the compatibility target is a written contract rather than an implementation that is compared against itself.

**Add-on — unsupported-cells:** Every cell in the comparison table gets one of three values: a measured number, "unsupported" with a reason, or "not implemented" with a reason. A blank cell is the only forbidden one.

**Add-on — upstream-vless:** Wire-format sources, in order: `upstream/xray-core/proxy/vless/` under `encoding`, `inbound`, `outbound`, then `upstream/sing-box/protocol/vless/`, `upstream/xray-rust/crates/`, `upstream/zeronet/crates/zero-protocol/` with `zero-transport/`; implement the narrower parser and prove it faster per length.

**Add-on — upstream-tests-on-done:** When the rung dials, run the suites with a seam via `scripts/run-upstream-suite.sh` — `upstream/xray-rust/crates/`, `upstream/zeronet/crates/` — before calling it done.

## P8 · Rewrite for readability without making it slower

**When to use:** When a file has grown a second way of doing something, or a `cfg` fork has made one idea live in three places, and the next change to it will have to be made three times. Also when something is genuinely hard to read and nobody can say why.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p ferrox-bench`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix
**Touches:** crates/ferrox-core/src/core.rs, crates/ferrox-core/src/chacha/mod.rs, crates/ferrox-prompt/src/main.rs, scripts/check-comments.sh
**Random weight:** 4

```text
Make one file easier to read and easier to extend, and prove the rewrite changed nothing about what it does or how fast it is. This is a refactor, so the whole value is in the proof: a more readable file that is subtly slower, or that quietly changed a boundary case, is worse than the file it replaced.

Pick the duplication that is actually costing something. The candidates in this tree, at the time of writing: `core.rs::backend` repeats the same four backend-name strings across four mutually exclusive `cfg` blocks where two of the pairs differ only in `target_arch = "x86"` versus `"x86_64"`; `chacha/mod.rs` declares `vector_group` three times and `xor_blocks` twice under `cfg`, so a change to the vector path has to be made in every copy; and `ferrox-prompt`'s `main.rs` is one binary target with five verbs and the printing for all of them in a single file. Say which one you are taking and why that one, in the first line of your report.

The rules, because "cleanup" is how a codebase loses its gates:

- The diff must contain no behaviour change. If you find yourself adding a branch, adding a fallback, or reordering a computation, that is a bug fix or a feature — stop, and record it as its own slice in this file rather than folding it into a refactor nobody can review.
- No abstraction may exist for one implementation. An interface with a single implementor and no second one planned is a promise, and this repository has already shipped a version of that mistake: `tls.rs` was an interface nothing implemented, which is why the rustls backend slice exists at all. If you introduce a trait, name the second implementor in the same commit or do not introduce it.
- The output must be byte-identical. Run the differential sweep over every length and every block offset, not the tests that happen to be convenient. A refactor that changes a byte at one offset is not a refactor.
- The timing must not regress at any single measured length. A rewrite is allowed to be faster; it is not allowed to be slower anywhere, because "not slower than the reference" is a floor, not a target, and a reader who cannot see the split between this change and the next one has to assume the worse.

Prove it rather than asserting it. Attach the before and after benchmark tables side by side, name the machine both were measured on, and report the worst length's ratio in both. If a length moved, say by how much and whether it is inside the noise you would expect from a shared runner — and if you cannot tell, say that instead of calling it neutral. A refactor report that says "no performance impact" without a number is the same class of claim as a benchmark that never ran.

Scalability here means the next change costs one edit, not that the file got shorter. State the concrete thing that is now easier: which duplicated `cfg` fork is down to one copy, which function no longer has to be read alongside two others to be understood, which addition to `ferrox-prompt` no longer means editing a five-verb file. If you cannot name one of those, you have made the code tidier and not better, and the difference is worth saying out loud.

Leave the debt you did not pay. If a second duplication is visible but out of scope, add a slice for it here with the same fields every other slice has, so the next contributor inherits a plan rather than a suspicion. Do not leave a comment saying "TODO: dedupe" — a comment is not a task and it is checked by nothing.
```

**Add-on — cfg-forks:** When the duplication you are removing is `cfg`-gated copies of one function, count the copies before and after and say so. "Reduced three copies to one" is a claim a reader can check; "simplified" is not.

**Add-on — golden-diff:** When the rewrite touches anything with a byte-level output, diff the two builds' output over the full length and offset sweep and record the file. A refactor whose evidence is a passing test suite is relying on the suite to be complete, which it has already once failed to be.

**Add-on — no-new-allows:** Count the `#[allow]` attributes before and after. If the refactor needs one, the code it is refactoring was fighting something real and the honest move is to fix that thing rather than to silence the lint for the rest of the repository's life.

**Add-on — report-shape:** Write the report as: what was duplicated, what it cost, what changed, what was measured, what was not measured. The last section is the one everybody skips and the one that tells the next contributor whether to trust this.

**Add-on — trace-free:** No comment blocks and one line per item at most (`scripts/check-comments.sh` fails the rest); a refactor that needs a paragraph to explain is two changes.

**Add-on — simplicity-wins:** In a tie the shorter, more explainable form ships; the complex form survives only with a measured win in CI, never with an argument.

## P9 · Port one upstream suite to Rust and retire its toolchain

**When to use:** When an upstream suite's only job in CI is to need its toolchain — Go for the Go suites — while what it checks is behavior this tree could state itself.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Gates:** CI: `conformance.yml` green with the ported suite; the original suite still green beside it (parity); `cargo test --workspace --all-features`
**Touches:** scripts/run-upstream-suite.sh
**Random weight:** 2

```text
Take the smallest enabled suite and write it in Rust from its observed behavior: same inputs, same expectations, this tree's own words. Never transliterate — no upstream line enters this tree, so the port is read off the wire format and the failure modes, not off their files.

Run the port beside the original until parity holds for three consecutive green runs; only then does the original stop running for that suite. Retire exactly the toolchain the ported suite needed, and say which one in the report.
```

## P10 · Wire the xray-rust seam once REALITY dials

**When to use:** When P7's `reality`/`vision` rung carries a record. Measured in `conformance.yml` run `37125321800`: 5 of the 23 `#[ignore]`d tests in `local_xray_interop_tests` pass unmodified against `ferrox-app` and 18 do not, of which 11 are `TLS`/`REALITY` rows that need P7 and 7 belong to P15 (`gRPC` framing), the `ws`/`httpupgrade` early-data rows, and P16 (`xhttp`). The pin is already `test_enabled = true` with the five that pass, so what this slice has left is re-running the command as each of those three clears its rows.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** CI: `conformance.yml` green with the seam-injected run against `ferrox-app`, and the log line naming the binary and the pin
**Depends on:** P7
**Touches:** upstream/pins.toml
**Random weight:** 1

```text
Flip the `xray-rust` pin to `test_enabled = true` with `ferrox_binary = "ferrox-app"` and the suite command its interop tests need, injected via `XRAY_VLESS_FULL_BINARY` — the seam the pinned tree already reads. The binary already answers `run -config`; what was missing was the `REALITY` behavior P7 owns, so this slice contains no transport code, only the flip and the per-test report by name. A subset that passes is a subset.
```

## P11 · Timing benchmarks for protocol framings

**When to use:** When a protocol rung needs a wall-clock comparison and only has counts: VMess sealed/open throughput has no timed reference anywhere, only the exact-size assertions in `crates/ferrox-app/src/vmess.rs` (`frames_seal_to_stable_bytes`, `seal_open_round_trips_every_length_and_cipher`), so a framing change that keeps sizes identical while adding passes is invisible.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** CI: `bench.yml` green with a protocol framing section that fails on regression on every runner in the matrix; `cargo test --workspace`
**Touches:** crates/ferrox-bench/src/main.rs, .github/workflows/bench.yml
**Random weight:** 1

```text
Give the protocol framings a wall-clock comparison with a reference on every ISA runner, the way gate 3 compares the record layer against the chacha20 crate. The obstacle is structural and decided first: framing lives in application crates a bench crate cannot import, and no same-language reference exists for VMess AEAD framing, so this slice decides where the timed code lives and what it is measured against, then gates it with gate 3's remeasure discipline. Counts (the exact-size assertions in `crates/ferrox-app/src/vmess.rs`) catch added copies; only timing catches added passes at equal size. Until then the claim stays the narrowed one `docs/claims.md` makes: bit-identical framing with exact sizes, no speed claim.
```

## P12 · VMess over the ws carrier

**When to use:** When `vmess_over_websocket` is the last `xray_oracle` failure against this binary: it expects a `vmess` listener behind a `ws` carrier and gets a connection closed after the first byte.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `vmess_over_websocket_matches_the_oracle` executed against `ferrox-app`
**Touches:** crates/ferrox-app/src/vmess.rs, crates/ferrox-app/src/proxy.rs, upstream/pins.toml
**Random weight:** 2

```text
Carry `VMess` inside the `ws` carrier built for VLESS, in both roles, rather than a second carrier: the handshake and the framing are `crate::ws`'s, and the bytes inside them are `crate::vmess`'s, unchanged. Then every `xray_oracle` test is either enabled or named, and the sentence in `docs/conformance.md` that lists the failures can go rather than be maintained.

The `VMess` header is a hundred bytes of sealed material behind a timestamp, so this is also the first carrier that carries a header rather than a fixed-size prologue: read it to the byte, never to the packet. A carrier that hands the protocol a short read is a hang wearing a successful handshake.
```

## P13 · Make the gRPC loopback test stop failing one run in nine

**When to use:** Now, and before the next slice reads a red `cargo test --workspace` as its own: `grpc::tests::tunnel_carries_an_echo_over_loopback` failed 23 times in 200 runs of that one test with nothing else running, measured on a tree whose `grpc.rs` no slice in flight had touched. `grpc.rs` is not the next slice's business; the measurement is.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace` green on three consecutive runs; a loop of the single test over 200 runs with zero failures, printed by the test or the script rather than remembered
**Touches:** crates/ferrox-app/src/grpc.rs
**Random weight:** 2

```text
Find it with the trace rather than by reading, because reading says nothing about which of the two ends loses the frame. Instrument `read_head`, `read_body`, `emit` and `write_frame` with the peer's address, then loop the test until it fails. A failing run prints this, and the last two lines are the whole bug: the client reads the nine header bytes of the `pong` `DATA` frame and then `read_body` sees end of stream, so a frame header arrived without its body. That is a torn write or a reset with data in the receive queue, not a framing error, and the fix is whichever of the two it turns out to be.

Then make the test able to fail *deterministically*, because a test that fails one run in nine teaches the next contributor to re-run CI instead of reading it. A loopback test that needs a real socket to lose a race is testing the scheduler; the same assertion over an in-memory stream or a frame buffer fails every time it is wrong and never flakes.

Report the before and after as a rate over a stated number of runs. "Fixed" is not a rate.
```

## P14 · Take the third copy of the config and address walks out of `proxy.rs`

**When to use:** When the next slice touches a protocol role: `find_vless_outbound` (`crates/ferrox-app/src/proxy.rs:801`) and `find_vmess_outbound` (`:839`) walk the same `outbounds` → `settings.vnext[0]` → `users[0]` shape in two nearly identical loops, `shadowsocks::parse_addr_header` (`shadowsocks.rs:251`) and `vmess::decode_target` (`vmess.rs:592`) parse the same address triple in two orders, and `inbound_id` (`:672`) and `inbound_password` (`:717`) each walk `settings.clients[0]` themselves.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the enabled `zeronet` subset executed against `ferrox-app`
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-app/src/shadowsocks.rs, crates/ferrox-app/src/vmess.rs
**Random weight:** 2

```text
One `vnext` walker, one inbound-client reader, one in-memory address parser with each caller reading the port where its own wire format puts it — `shadowsocks` after the address, `VMess` before it — and nothing else changes. The proof is the enabled suite plus the workspace tests: a refactor that alters a byte on any wire is not a refactor, and `conformance.yml` is what says so.

Do not take the opportunity to shrink `vmess.rs` itself. It is 1,014 lines of code against a from-scratch equivalent written to this same prompt at 880, but it carries all four data ciphers where that one carried one, and a slice that trades capability for lines is a different slice with its own differential proof. If the smaller form is wanted, it is its own PR against the oracle, not a line count argued here.
```

## P15 · Make the gRPC carrier agree with both oracles

**When to use:** When the measurement in `docs/conformance.md` is the reason a `gRPC` row is red: `vless_over_grpc_matches_the_oracle` is green against `ZeroNet`'s `xray_oracle` and `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc` fails against `xray-rust`, so one carrier has two verdicts and the earlier HTTP-family work called it done on the first one.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `rust_socks_client_reaches_echo_server_through_local_xray_vless_grpc`, `rust_socks_client_reads_a_server_greeting_through_local_xray_vless_grpc` and `rust_socks_client_streams_bulk_echo_through_local_xray_vless_grpc_multi_mode` added to the enabled `xray-rust` suite command and executed unmodified
**Touches:** crates/ferrox-app/src/grpc.rs, upstream/pins.toml
**Random weight:** 2

```text
`grpc.rs` currently answers `ZeroNet`'s oracle and not `xray-rust`'s, both measured in `conformance.yml` run `37125321800`: the plain-`gRPC` row fails with `read echo failed: early eof`, the server-speaks-first row with `read greeting: early eof`, and the multi-mode bulk row with `Connection reset by peer`. Three failures, one carrier, two oracles — so the framing is narrower than both rather than wrong, and the narrower half is whatever `ZeroNet`'s oracle does not send.

Read both pinned implementations for what the other one sends: `upstream/xray-core/transport/internet/grpc/` and `upstream/xray-rust/crates/xray-transport/src/stream/grpc/`, then `upstream/zeronet/crates/zero-transport/src/grpc.rs`. The three named tests are the specification; add each to the `xray-rust` suite command in `upstream/pins.toml` only as it goes green, and keep `vless_over_grpc_matches_the_oracle` in the `zeronet` command so a fix that breaks the other oracle is caught by the same run. A carrier that passes one suite because the other was never run is the failure this slice exists to end.
```

## P16 · Answer the xhttp rows, including the one that needs a file it is not given

**When to use:** When `rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases` and `rust_socks_client_reaches_target_through_remote_xhttp_profile` are the last two red rows in the `xray-rust` table and the second of them fails before it connects, on `XRAY_REMOTE_XHTTP_CONFIG must name an owner-only file`.
**Status:** todo
**Leverage:** 2
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases` added to the enabled `xray-rust` suite command and executed unmodified
**Touches:** crates/ferrox-app/src/proxy.rs, upstream/pins.toml
**Random weight:** 1

```text
`xhttp` is the one carrier in this tree with no implementation at all, so `ferrox-app` serves a `network: xhttp` inbound as raw `TCP` and the bulk flow dies with `Connection reset by peer` — measured in `conformance.yml` run `37125321800`. The HTTPUpgrade/gRPC work named it as out of scope and said it gets its own; this is that.

The second row is a different kind of problem and must be settled before the first is claimed. `rust_socks_client_reaches_target_through_remote_xhttp_profile` reads its profile through `read_owner_only_text_from_env`, which panics unless `XRAY_REMOTE_XHTTP_CONFIG` names a regular file with no group or other bits — so a suite command that runs it has to write that file and set its mode, and `scripts/check-fixture-safety.sh` governs the committed tree, not a file the harness writes at run time. Answer that first: if the fixture cannot be produced from the harness without weakening the mode assertion the pinned tree ships, say so and leave the row named here rather than editing their test.

Read `upstream/xray-core/transport/internet/splithttp/` and `upstream/xray-rust/crates/xray-transport/src/stream/xhttp/`, then `upstream/zeronet/crates/zero-transport/src/xhttp.rs` and `xhttp_request.rs`, and implement the narrowest form that carries one `VLESS` request and one response. `xhttp` moves the payload across several HTTP requests with padding and placement rules per mode; a slice that implements one mode and names it is further along than a slice that stubs the carrier and reports the row green.
```

## P17 · Serve the `tls` rows with a rustls server role

**When to use:** When `rust_socks_client_reaches_echo_server_through_local_xray_vless_tls` is the next red row to clear: the test builds a real Xray Go server today and swaps in this binary via `XRAY_VLESS_FULL_BINARY`, and this binary binds nothing because `serve_file` refuses every `tls` inbound rather than serving it in the clear.
**Status:** doing
**Leverage:** 4
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with `rust_socks_client_reaches_echo_server_through_local_xray_vless_tls` added `--exact` to the enabled `xray-rust` suite command and executed unmodified
**Depends on:** P7
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-core/src/tls/mod.rs, crates/ferrox-core/src/tls/rustls_backend.rs, upstream/pins.toml
**Random weight:** 1

```text
Read the `certificateFile`/`keyFile` pair out of `streamSettings.tlsSettings.certificates` and serve `TLS` inside this binary through the existing `TlsProvider` interface, which today only opens client sessions: the test writes a self-signed pair per run and pins it on its own side, so there is no test CA to vendor and no fingerprint to mimic. `VLESS` decode and relay inside the session stay exactly what the raw-`TCP` path does; only the outer layer changes, which is why this slice flips one row and names it rather than claiming the carriers. The `ws_tls`, `httpupgrade_tls` and `grpc_tls` rows keep their `TLS` inside carriers this binary already frames, so each joins the suite command only with its own passing run, never batched onto this one.
```

## P18 · Serve the `REALITY` rows with a uTLS-parity handshake

**When to use:** When the seven `reality`/`vision` rows are all that is red in the `xray-rust` table and `P17` is green: the client opens with a fingerprinted `ClientHello`, authenticates by `shortId` against an `X25519` key, and expects `TLS`-shaped records after, none of which the `rustls` server role from `P17` produces on its own.
**Status:** doing
**Leverage:** 4
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the seven `reality`/`vision` rows added `--exact` to the enabled `xray-rust` suite command and executed unmodified
**Depends on:** P17
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-core/src/tls/mod.rs, crates/ferrox-core/src/tls/rustls_backend.rs, upstream/pins.toml
**Random weight:** 1

```text
Read `upstream/xray-core/transport/internet/reality/reality.go` for the exchange this has to match — ephemeral `X25519` against `realitySettings.privateKey`, `shortIds` authentication, session tickets — then `upstream/xray-rust/crates/xray-transport/tests/reality_rustls_tests.rs` and `utls_tls_shaping_tests.rs` for the exact shaping the tests assert, and write the smaller handshake that is byte-identical on the wire and carries no copied lines. `dest` fallback and `show` output stay out; a server that answers `REALITY` for its own `shortId` set and closes everything else is further along than one that dials out to check. The `vision` padding commands ride inside the session exactly as `Xray-core`'s `VisionReader`/`VisionWriter` frame them, which is a second framing to prove, not a flag to set.
```

## P19 · Dedupe the chacha ladder `cfg` forks without a new abstraction

**When to use:** When a change to the vector path in `chacha/mod.rs` has to be made in more than one `cfg` copy to stay correct.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p ferrox-bench`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix
**Depends on:** P8
**Touches:** crates/ferrox-core/src/chacha/mod.rs
**Random weight:** 2

```text
Collapse the `cfg` forks in `chacha/mod.rs` that name one idea twice: the two `xor_blocks` bodies, the two `one_block` bodies, and the per-arch `GROUP_STATES` and `Wide` pairs. Keep one copy behind `cfg(any(...))` where the bodies are identical and keep per-arch constants where the widths differ, so no new trait appears. A trait with a single implementor is out of scope here. Prove byte-identity with the full length and offset sweep and prove no length regressed with before and after bench tables side by side, naming the runner and the worst length ratio in both. The concrete win is named in the report: which fork went from two copies to one.
```

## P20 · Split `ferrox-prompt` printing per verb out of one file

**When to use:** When adding a verb or a flag to `ferrox-prompt` means editing a single binary file that owns parsing and printing for every verb.
**Status:** todo
**Leverage:** 2
**Effort:** medium
**Gates:** `cargo test --workspace --all-features`; `cargo run --release -p ferrox-bench`; CI: `bench.yml` gate 1 and gate 2 green on every runner in the matrix
**Depends on:** P8
**Touches:** crates/ferrox-prompt/src/main.rs
**Random weight:** 1

```text
Move each verb in `ferrox-prompt/src/main.rs` behind its own small module with the same behaviour and the same output bytes, so the next verb or flag costs one new module rather than another branch in a shared file. Add no verb, add no flag, reorder no output. Prove it with the workspace tests plus the prompt library check, and with the bench gates still green to show the crypto path was untouched. The report names the concrete win: which verb no longer requires reading the other verbs to change.
```

## P21 · Answer `REALITY` with a certificate the peer will accept

**When to use:** Now, and before P18 can be called: the handshake authenticates and the session will not negotiate, because the only certificate `REALITY` recognises has an `Ed25519` key and no `uTLS` fingerprint offers `Ed25519`. Measured against the pinned `Xray-core` `b26a91de` built from source, as the client, against `ferrox-app` as the `REALITY` server, fingerprint `chrome`: the `ClientHello` authenticates and the handshake then fails with no shared signature scheme. Reading `upstream/xray-rust/tests/fixtures/reality/clienthello_raw_*.json` at `7a4fb2dd`, all eleven committed raw `ClientHello`s list 8 to 11 signature algorithms and none is `0x0807`. A `TLS` 1.3 `CertificateVerify` scheme must be one the peer offered and must match the certificate's key, so no certificate exists that both satisfies the `HMAC-SHA512(auth_key, ed25519_public_key)` check and carries a scheme a `uTLS` peer accepts. The full measurement is in `docs/conformance.md`.
**Status:** todo
**Leverage:** 5
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with at least `rust_socks_client_reaches_echo_server_through_local_xray_vless_reality_vision` added `--exact` to the enabled `xray-rust` suite command and executed unmodified
**Depends on:** P18
**Touches:** crates/ferrox-core/src/tls/reality.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 5

```text
Where the certificate comes from is the whole question, and `Xray-core` answers it by dialling `dest` and answering with the cover origin's certificate — a real `ECDSA`/`RSA` chain the peer already trusts, with the `Ed25519` `HMAC` certificate used only when authentication *fails*, which is the one case where the connection is about to be forwarded anyway. That is why an `Ed25519`-only certificate is not a corner case upstream: it is the fallback, not the path.

Decide which of these this server is, and say it in the report:

- **Dial `dest`.** The narrow form: connect, send the `ClientHello` verbatim, read the `ServerHello` and the `Certificate`, and answer with the peer's own chain. Nothing is forged and nothing is trusted, because the chain is the origin's. The cost is one dial on a path a stranger can trigger, so it needs the `ServerNames` and `shortIds` gates in front of it — which this server already has — plus a bound on the dial, and the `Xray-core` behaviour of *not* answering at all when the gates refuse.
- **A certificate the peers trust.** Impossible offline and therefore not a choice; say so rather than shipping a fixture.
- **Something the peers accept that is still `REALITY`.** If one exists it is a finding worth more than the other two, and it should be looked for before either: read `upstream/xray-rust/crates/xray-transport/src/reality.rs` for exactly what its `verify_reality_certificate_der_with_mldsa65` requires of the leaf, then check whether any of those requirements can be met by a key type `0x0807` is not needed for. `Ed25519` is required for the public key half, so this is the narrow hope, but it is the only one that keeps the `dest` dial out.

Whichever it is, `Xray-core`'s own server is the oracle for the answer and it is pinned: `github.com/xtls/reality` in the module cache at the version `go.mod` names, `tls.go:200-300` for the gates and the dial, `handshake_server_tls13.go:100-180` for what it answers with. Run the seven rows against a real `Xray-core` client built from that pin before claiming any of them.
```

## P22 · Take the third copy of the header walk out of the carrier files

**When to use:** When `proxy::header_value` exists and two carriers still keep their own: `xhttp.rs` has a byte-identical copy and a head reader of its own, and `httpheader.rs` a third reader.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test --workspace`
**Touches:** crates/ferrox-app/src/xhttp.rs, crates/ferrox-app/src/httpheader.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 2

```text
The `EarlyData` rung deduplicated the header walk and the request-path walk out of `ws.rs` and `httpupgrade.rs` into `proxy.rs`, beside the `read_http_head` that was shared already. `xhttp.rs` was left alone on purpose: its rows are P16's and have a gate of their own, so folding them in here would have made a benchmark of one rung depend on a change to another. That is the right order for a gate and the wrong order forever, so this is the second half.

`xhttp.rs` keeps `header_value` verbatim and a `read_head` that reads rather than peeks, where the shared one peeks and leaves pipelined bytes in the kernel. Folding it in is therefore a behaviour change and not a move, and it has to be measured as one.
```

## P23 · Stop the two loopback tests that lose to the runner, not to the code

**When to use:** When a `cargo test` run on a shared runner goes red on something neither the change nor its diff touched. Both below were measured on the `EarlyData` branch, whose diff has no line in either file.
**Status:** doing
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test --workspace` green on three consecutive `ci.yml` runs
**Touches:** crates/ferrox-core/src/tls/reality.rs
**Random weight:** 3

```text
Both are a race between a test and a socket, and both are one `expect` away from being a real failure.

`tls::reality::tests::every_unauthenticated_hello_is_refused` half-closes with `client.shutdown(Shutdown::Write).expect("half-closes")` (`reality.rs:775`). When the server refuses the hello fast enough and closes first — which is the whole point of that test — `shutdown(2)` answers `ENOTCONN` and the `expect` fails on a refusal that worked. Measured in `conformance.yml` run 37248505844, 1 of 88 in `ferrox-core`; `pinned_main` was green on the same tree the run before. **This one is gone too**: the half-close is `let _ =` with the reason on it, which is what every production half-close in this workspace already did, so the `expect` was the only thing asserting a refusal had failed. It went on failing on PR #51, whose diff is `run-parity.sh`, which is what moved it off `todo`. `doing` and not `done` because the gate above asks for three consecutive green `ci.yml` runs and one green run is not three.

`ferrox-bench`'s `ps::tests::a_live_sample_reports_the_source_it_used` samples the live `ps` and asserts the source it got back. Measured in `ci.yml` run 37248886068 on `linux x86_64`, `left: 20, right: 30`. **This one is gone**: PRs #42, #43 and #46 replaced that sampler, which is why the `EarlyData` branch had to rebase before it could go green. Recorded because the rebase fixed the symptom and not the class, and the `reality` race is the same class as P13.

What is left is the same shape in the two loopback relay tests that still `expect` their half-close: `proxy.rs:3131`, which writes a payload and reads it back, and `proxy.rs:3326`, which does the same from a reader thread. Neither provokes a server-side refusal, so neither has been seen losing the race, and neither is in a diff that has gone red on it. They are `Touches` now rather than prose: the class is the same and the evidence is not, and a slice that fixes what it cannot reproduce is a slice that guesses.
```

## P24 · Find the 8 KiB block that lands inside a counting window

**When to use:** When a gate says "zero allocations" and the count is not zero. Gate 8 hit it on its first run and had to lower its bar to match what it can decide.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `bench.yml` gate 8 reporting `0` for this side on all four runners
**Touches:** crates/ferrox-bench/src/count.rs, crates/ferrox-bench/src/earlydata.rs, crates/ferrox-bench/src/muxframe.rs
**Random weight:** 4

```text
`count::measure` sets one process-wide `ACTIVE` flag, so it counts every allocation in the process while it is set, from every thread. Gate 8's window runs 64 encodes that provably never grow their buffer, and reads **6 allocations and 8064 bytes** (run 37250890100). A second identical window immediately after reads **1 allocation of 8192 bytes** (run 37251478949) — one 8 KiB block, once, in a loop that appends at most 39 bytes to a 64-byte buffer. A debug `cargo test` with a hundred tests in flight reads the same six, so it is not random traffic.

8192 is `std::io`'s default buffer and `io::copy`'s, and `std::thread`'s spawn path sizes a stack with `mmap` rather than the allocator, so the obvious suspects are std's I/O and not std's threads. Find it, then either fix it or make `count` narrow enough to exclude it — a per-thread flag, or counting only the thread that opened the window.

Until then gate 8 holds this side under one allocation per encode and the reference at two or more, both printed, and `docs/claims.md` says the bar is not zero and why. `muxframe.rs` hit this first and declined to assert on it too; two gates is a pattern and a pattern is a slice.
```

## P25 · Bless and extend the exact operation counts

**When to use:** When `ops.yml` fails listing a measured number beside `UNBLESSED`, or when a new hot function has no row and should.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test --workspace`; CI: `ops.yml` green
**Touches:** scripts/count-ops.sh, scripts/expected-ops.txt, .github/workflows/ops.yml
**Random weight:** 2

```text
Put the measured number in `scripts/expected-ops.txt` only after reading the diff that produced it and deciding every added or removed instruction is the change intended — never to silence the gate. To cover a new function, add one `symbol ir` row with `UNBLESSED`, name one exact unit test exercising it in the `ops.yml` invocation, and bless the number the same way. Symbols must stay unique substrings. The report names the concrete win: which operation stopped happening, and the count that proves it.
```

## P26 · Refuse a conformance run where no suite ran at all

**When to use:** When `conformance.yml` is green and the log says no upstream suite reached a Ferrox binary. `run-upstream-suite.sh` now refuses a per-suite `PASS` that ran zero tests or a different number than its pin names, and then prints its tally and exits 0 whatever that tally says — so a `pins.toml` edit that disables every pin leaves a green job whose entire upstream-conformance content is a line of skips.
**Status:** todo
**Leverage:** 4
**Effort:** small
**Gates:** `./scripts/check-upstream-pins.sh`; CI: `pins.yml` green, and `conformance.yml` refusing a tally of zero
**Touches:** scripts/run-upstream-suite.sh, .github/workflows/conformance.yml
**Random weight:** 4

```text
The per-suite hole and the aggregate one are the same defect at two levels, and only the lower one was closed. An enabled pin with no `ferrox_binary`, no `seam`, or a `seam` the pinned tree never reads already fails the job; a suite whose filter matches nothing already fails it. What is left is that `ran` is printed and never judged, so the job's verdict is independent of whether anything ran.

Decide what a zero tally means before changing the script, because the two answers are opposites. Failing it makes every pin's flip to `test_enabled = false` a red merge, which is the right price for a goal the README states as a coverage number. Failing nothing keeps green, and then the README's upstream-conformance row has to stop being a count and become a pointer at the log — which is a smaller claim and the one the tree can actually keep.

Whichever it is, put it in one place the script reads: a floor under `ran`, so a pin that is enabled must also have produced a green run, and a test or a self-test in the same shape as the count rule's — a rule that cannot fail is a rule that has not been written.
```

## P27 · Build the recovery ladder the failure taxonomy was cut for

**When to use:** When `failure::Stage` and `failure::Kind` exist and the next row in `docs/zeronet-comparison.md` §6 wants a second exit. `ferrox-core/src/failure.rs` types why a dial stopped and `proxy.rs` reports it, but nothing *acts* on it yet: `dial_or_report` counts and prints, and eleven arms still give up on the first failure.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `ci.yml` green on all three runners, and `conformance.yml` still refusing a tally of zero
**Touches:** crates/ferrox-core/src/failure.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 3

```text
`Failure::worth_retrying()` is the whole point of the type and nothing reads it yet. Land the ladder the pinned ZeroNet core runs (`upstream/zeronet/crates/zero-observatory/src/lib.rs:180-292`, read for the argument): ordered rungs, climb on success, descend only after N successes at a rung, and a compact `u8` for the runtime's path so the hot loop stays lock-free.

Two constraints this tree imposes that theirs does not. A rung here is a carrier, not a whole path, because there is no resolver and no balancer to make a rung set — so the ladder is `Raw → ws → xhttp → grpc → httpupgrade` and the question a rung answers is "does this carrier reach this server", not "which path to this host". And `Stage::is_useful_progress` is the gate: never climb on a rung that did not reach first byte, or the ladder redials a filtered route forever, which is the exact failure the threshold exists to prevent.

Store capability evidence and never destinations. The rung table is a property of the binary; the per-server verdicts are a property of the session. A `NetworkProfile` that learned a server address would be a routing table in a library that has no routing.

Every climb and every descend is logged with the `Stage` and `Kind` that caused it, because the report is how a user finds out their link was blocked and a bare "dial failed" is what we ship today. Report the fallback rate per rung: a rung nothing ever climbs past is a rung that should be refused rather than tried.
```

**Add-on — no-upstream-code:** Take the rung *order* and the descend rule; write the state machine. ZeroNet's is `tokio`-shaped and ours is thread-per-connection, so the code is a different program with the same argument.

**Add-on — measure-the-ladder:** A loopback test that fails the first rung and passes the second, proving the climb is wired and not just present. A ladder no test climbs is a ladder that may have its rungs in the wrong order.

**Add-on — bounded:** Cap the total climbs per session. A ladder with no ceiling on a network that fails every rung is a busy loop with extra steps.

## P28 · Read and write through one reusable stream buffer

**When to use:** Before the next carrier lands, because every carrier currently allocates its own per-connection buffer and the promotion in `proxy::RelayBuf` should be paid once rather than per copy loop.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; CI: `bench.yml` gate 2 green, and `bench.yml` gate 3 with no length regressing
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-app/src/vmess.rs
**Random weight:** 3

```text
The AEAD framings all parse "need N more bytes" state machines, and reading exactly N bytes per step costs one syscall per length field and another per payload. `RelayBuf` already promotes once; it does not yet *reuse* across frames, and it is not shared with the framing loops.

Read the pinned `io_util.rs` (`upstream/zeronet/crates/zero-protocol/src/io_util.rs`) for the shape: one `ReadBuffer` that reads opportunistically into reusable storage and lets the parser decrypt in place, so a single read yields several frames and the steady state allocates nothing. That is the same claim our counting allocator already proves for the record layer — this extends it to the stream layer, which is where the remaining allocations are.

Do not make it a `trait`. Two framings use it today and a third would be `vmess.rs`'s caller; an abstraction with one implementation is the thing `policy.rs` refuses. When a fourth appears, extract it then, and say in the diff what the fourth one needed.

Keep `RelayBuf`'s promotion where it is. A `ReadBuffer` that grew eagerly would pay 256 KiB per connection on a link that sends 200 bytes, which is the cost the promotion was added to remove.
```

## P29 · Wire the KCP carrier through the app

**When to use:** When an `mkcp` row is next to carry: the core is ported and oracle-proven, the carrier is named and parsed, and the proxy seam still refuses it.
**Status:** todo
**Leverage:** 4
**Effort:** large
**Gates:** `cargo test --workspace`; `cargo run -p ferrox-core --example kcp_interop`
**Touches:** crates/ferrox-core/src/kcp/mod.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 2

```text
`ferrox_core::kcp` re-derives the segments, windows, timers and retransmission arithmetic and proves the derivation bit-identical with the scripted-clock oracle against the pinned Go code; `Carrier::Kcp` names `kcp` and `mkcp` and parses their settings. What is missing is the stream seam the proxy comment names: serve and dial through the ported core, then carry a session end to end.

Prove it the way the core was proved: the oracle for the arithmetic, the loopback interop example for the bytes on a real socket. Name the conformance rows the run earns; rows that stay refused keep refusing with the reason, which is a verdict and not a gap.
```

## P30 · Prove the pooled QUIC sharing under an adversarial packet layer

**When to use:** When the pool test goes red on a diff that touches neither of its files: the sharing has a socket test and no adversarial proof, so a loss the protocol should survive reads as a failure.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace` green on three consecutive `ci.yml` runs
**Touches:** crates/ferrox-app/src/quic.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 2

```text
Two streams already share one handshake through `dial_pooled`, proved by the socket loopback. Extend the in-process ferry beside it with drop, duplicate and reorder, and run the sharing through that: the harness proves the protocol, the socket test proves the real sockets, and neither is asked to prove the other's half.

Then earn the gate the hard way: three consecutive green `ci.yml` runs with no change to either file between them. A socket test that passes twice and fails the third is testing the scheduler, and the fix is in the test's determinism, not in its budget.
```

## P31 · Put the security layer outside the carrier, where both references put it

**When to use:** When a `security: tls` or `security: reality` row over a stream carrier is next to carry, and a real Xray peer cannot complete the handshake: this tree serves the carrier first and runs the TLS session inside it, where both references run TLS first and build the carrier on top.
**Status:** todo
**Leverage:** 5
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with the `ws_tls`, `httpupgrade_tls` and `grpc_tls` rows executed against `ferrox-app`
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-app/src/ws.rs, crates/ferrox-app/src/httpupgrade.rs, crates/ferrox-app/src/grpc.rs, crates/ferrox-app/src/xhttp.rs
**Random weight:** 4

```text
The ordering is the whole bug and it is why the TLS rows are the ones that stay red. In `upstream/xray-core/transport/internet/websocket/hub.go` the listener is wrapped with `tls.NewListener` before the HTTP server sees a byte, and in `transport/internet/tcp/hub.go` each accepted connection is wrapped with `tls.Server` before the header authenticator runs; the dial side does the same, `internet.DialSystem` then the security conn then the transport dialer. This tree does it backwards: `serve_vless_tls` calls `crate::ws::accept`/`crate::grpc::accept` on the raw socket and then hands the carrier's reader and writer to `ferrox_core::tls::accept`, so the bytes on the wire are `HTTP/1.1 101` first and TLS records second. No Xray client opens with a plain HTTP request, so no Xray client completes; the same inversion is why no config path dials a TLS or REALITY outbound at all.

The obstacle is structural, not conceptual: the carrier `accept` functions take `TcpStream` because they split it with `try_clone`, set read timeouts, and peek. Push the security layer outside and they have to accept a `Read + Write` stream whose reader and writer are the same object — the seam `serve_carried_tls` already proves is possible, in the other direction. Count what that costs: one split abstraction and one trait bound per carrier, against a family of rows that currently cannot connect.

Do not carry both orders. A build that can serve carrier-inside-TLS and TLS-inside-carrier is two protocols wearing one config key, and the wrong one is the one a user's client will pick. The references agree on the order, so this tree agrees with them or it refuses the cell by name.

Prove the new order with a loopback pair in each direction and name the conformance rows it earns. REALITY is the same move with a different handshake, so one seam should carry both.
```

## P32 · Carry Hysteria, the first transport the pinned Xray-core has and this tree knows only by name

**When to use:** When a Hysteria row is next: `TransportKind::Hysteria` gives it a verdict in the link table and there is no implementation behind it, while the reference accepts `hysteria` and builds it on QUIC with its own congestion control.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with a `hysteria` row executed against `ferrox-app`
**Touches:** crates/ferrox-core/src/transport.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 2

```text
The accepted set is in `upstream/xray-core/infra/conf/transport_internet.go`: tcp, splithttp, mkcp, grpc, websocket, httpupgrade, hysteria, masque, xdrive. This tree implements all but the last three, and this is the first of them. Read `upstream/xray-core/transport/internet/hysteria/` for the framing and the congestion loop, then write the smaller thing — the pinned `upstream/quiche` is the QUIC stack, and the cryptography is `rustls` in `ferrox-core`, not a second TLS.

The obstacle is structural and all three of these rungs meet it: `crates/ferrox-app/src/quic.rs` is a client with a pool and no listener, and a carrier that owns its own congestion loop needs a server role the app does not have. Decide in the report whether one QUIC listener is shared by hysteria, masque and xdrive or whether each writes its own, because a second QUIC stack is the debt this repository refuses to land.

Report the rows this earns and the rows that stay refused, each with its reason. A refusal that names itself is a verdict; the refusal this slice replaces is a name with nothing behind it.
```

## P33 · Carry MASQUE CONNECT-IP

**When to use:** When the MASQUE row is next: RFC 9484 CONNECT-IP is named in the treemap, `Carrier::Masque` sits in the refused set, and the reference accepts `masque` over HTTP/3.
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with a `masque` row executed against `ferrox-app`
**Touches:** crates/ferrox-app/src/quic.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 1

```text
HTTP/3 with CONNECT-IP capsules, and `quiche` is already pinned as the stack for this rung. Read `upstream/xray-core/transport/internet/masque/` for the capsule framing before writing anything, and read `crates/ferrox-app/src/quic.rs` for what a `quiche` driver in this tree already looks like, so the new one is that shape rather than a second dialect beside it.

The UDP half is not optional: CONNECT-IP carries datagrams, and outside the mux this tree's UDP support is raw-carrier only. That is the part of this rung the mux does not cover, and it is the part to size before starting.

Name the modes implemented and the modes refused. One mode that carries a datagram is further along than a stub that reports the row green.
```

## P34 · Carry xdrive

**When to use:** When the xdrive row is next: it parses to a verdict and refuses, while the reference accepts `xdrive` and has an implementation directory behind it.
**Status:** todo
**Leverage:** 2
**Effort:** large
**Gates:** `cargo test --workspace`; CI: `conformance.yml` green with an `xdrive` row executed against `ferrox-app`
**Touches:** crates/ferrox-core/src/transport.rs, crates/ferrox-app/src/proxy.rs
**Random weight:** 1

```text
Read `upstream/xray-core/transport/internet/xdrive/` and the `xdriveSettings` key this tree already reads for its `host` only. Do not schedule it ahead of P32 and P33: all three are the same structural question — a QUIC-family carrier with no listener in this tree — and answering it once is what keeps this from being three stacks.

If the reading says this one is not a QUIC carrier, say so in the report and the `**Touches:**` of this section changes; a name is not evidence about its wire format.
```

## P35 · Decide whether `quic` stays a transport this tree dials

**When to use:** When the drop-in claim is next examined: the pinned Xray-core refuses the QUIC transport by name at config load, while this tree dials it and the link table calls it implemented.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; `cargo run -p ferrox-app -- check "<a type=quic link>"` printing the verdict this row should carry
**Touches:** crates/ferrox-core/src/transport.rs, crates/ferrox-app/src/proxy.rs, README.md
**Random weight:** 2

```text
Three things disagree today. `upstream/xray-core/infra/conf/transport_internet.go` answers `case "quic":` with `PrintRemovedFeatureError("QUIC transport (without web service, etc.)", ...)`, so a real Xray-core refuses the transport rather than serving it. `TransportKind::is_dialled()` lists `Quic`, so `VlessLink::support()` reports `Implemented { method: "vless-quic" }`. `Carrier::Quic` is in `refused_carriers!()`, so the server role refuses what the client role dials, and the dial is reachable only from a SOCKS inbound without Mux.

Pick the direction and say why. Either the transport is one this tree drops, in which case `is_dialled` loses a variant and `refused_carriers!()` keeps it, or it stays, in which case the claim it carries has to be narrower than `Implemented` — the reference states the replacement in the same error it uses to refuse, and a drop-in that accepts a config the reference rejects is a difference a user meets as a bug.

The ALPN is part of that answer and is measured here, not assumed. `crates/ferrox-app/src/quic.rs` offers `h3` and then writes a VLESS request header as the first bytes of the stream, which is not an HTTP/3 frame; `crates/ferrox-app/src/proxy.rs` now asserts the negotiated application protocol against what the carrier offers, because both sides used to set `h3` and nothing checked that anything was negotiated. Offering no ALPN at all fails the handshake and turns all four QUIC socket tests red, so an ALPN is required and its value is a decision: speak HTTP/3, name the raw-stream carrier honestly, or drop the transport.

Whichever way it goes, delete the disagreement rather than documenting it: one place that decides, and the other two reading it.
```

## P36 · Give the KCP config a consumer or stop naming the knobs

**When to use:** When `Carrier::Kcp` is next asked for its settings: `proxy.rs` reads `kcpSettings` only for `host`, which is not an mKCP setting, so `mtu`, `tti`, `uplinkCapacity`, `downlinkCapacity`, `cwndMultiplier` and `maxSendingWindow` are unreachable from any config file, and the `Config` arithmetic that would consume them has no validator anywhere in the tree.
**Status:** todo
**Leverage:** 3
**Effort:** small
**Gates:** `cargo test --workspace`
**Depends on:** P29
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-core/src/kcp/config.rs
**Random weight:** 2

```text
Parsing the six knobs before there is a dial path that uses them is a second way of reading a config, and `prompts.md` currently claims `Carrier::Kcp` "parses their settings" when it parses none of them. Either this slice parses all six into `ferrox_core::kcp::Config` and P29 hands that config to `Connection::new`, or it corrects the sentence in `prompts.md` and leaves the struct to P29. Say which.

Where the validation goes is upstream's answer read rather than invented: `infra/conf/transport_method.go:562-573` rejects `mtu < 21`, `tti` outside 10 to 1000, `cwndMultiplier < 1` and a `maxSendingWindow` below one MTU, in the config builder and not in the KCP package. Those four bounds are exactly the ones that keep `Config`'s derived sizes total, and `crates/ferrox-core/src/kcp/config.rs` now saturates instead of panicking, so the bounds are a rejection policy rather than a memory-safety requirement. Decide which this tree wants, because a setting that silently saturates and a setting that is refused are different user experiences.
```

## P37 · Cover the KCP connection, not only its arithmetic

**When to use:** When the next KCP change touches `connection.rs`: the oracle proves `SendingWindow`, `AckList`, `RoundTripInfo` and three serializers against the captured Go output, and proves nothing about the state machine, `flush`, `Ping`, `Terminate`, deadlines, or `read_segment` in the parse direction, which is only ever self-round-tripped.
**Status:** todo
**Leverage:** 4
**Effort:** medium
**Gates:** `cargo test --workspace`; `cargo run -p ferrox-core --example kcp_interop`
**Touches:** scripts/kcp-oracle/main.go, scripts/kcp-oracle/expected.txt, crates/ferrox-core/src/kcp/oracle.rs, scripts/check.sh
**Random weight:** 4

```text
Three holes are named by reading `oracle.rs` against the Go harness. `RoundTripInfo::default()` gives `min_rtt = 0` where `Connection::new` uses `RoundTripInfo::new(config.tti)`, so the `srtt < minRtt` clamp and the `minRtt < 4*variation` branch never run, and `on_packet_loss`'s `Timeout() == 0` guard always trips. `al_flush` passes `(1350 - 17) / 4` as a literal rather than going through the `mtu = mss + 18` and `limit = (mtu - 17) / 4` derivation `ReceivingWorker` uses, so a change to either leaves the oracle green. And `scripts/kcp-oracle/interop/main.go`, the Go echo server and client that would compare bytes over a real socket, is referenced by nothing: no script, no workflow, no `Cargo.toml` target.

Drive the estimator through the constructor the connection uses, derive the ack limit through `ReceivingWorker`, and put `interop/main.go` behind the same command that runs `crates/ferrox-core/examples/kcp_interop.rs`. Then the four bugs this tree's own suite found — the double ping, the missing wakeup, the close deadlock and the payload copy on a discarded segment — were all reachable by a rule that already existed, and the next one will be too.
```

## P38 · Give the pooled QUIC connection an owner that lets it go

**When to use:** When the next QUIC slice reads `quic.rs`: the pool is a process-global `OnceLock` keyed by `(address, port, host, roots)` with no eviction and no target or user in the key, so a connection outlives its last session for the life of the process, and `pump` holds the connection mutex across a `recv_from` that waits up to 500 ms.
**Status:** todo
**Leverage:** 3
**Effort:** medium
**Gates:** `cargo test --workspace` green on three consecutive `ci.yml` runs
**Depends on:** P30
**Touches:** crates/ferrox-app/src/quic.rs
**Random weight:** 2

```text
Two costs and one hang, in order of how much they cost a user. A pooled entry is removed only by `leave_session` when the last session ends, so a connection whose sessions all ended closes, but one opened with zero sessions and never re-entered sits in the map with an idle timeout ticking; key it by target and user id as well as server, and let the idle timeout be the reaper rather than a second thread. The `pump` lock is held across `pump_once`, which blocks in `recv_from` for up to `PUMP_POLL`, so a stalled peer stalls every other session sharing that connection; take the connection out of the lock, poll, and take it again, which is the same shape `quiche`'s `poll` wants. And `leave_session` flushes egress once and drops, so a lost CONNECTION_CLOSE leaves the peer to time out.

P30 wants the pool proved under an adversarial packet layer. This slice is what that proof should be pointed at, because a share that cannot be released is not a share a test can schedule around.
```

## Reading this file as a roadmap

The graph is the point, and it is not a decoration: `ferrox-prompt next` ranks ready slices by leverage, breaks ties towards the smaller one, leaves out the ones waiting on a decision, and reports what each slice unblocks. `P21` waits on `P18`, which waits on `P17`, which waits on `P7` — the longest chain in the file, which is the kind of thing that is obvious once and invisible otherwise.

Numbers do not go in prose here. This file's gate checks structure — ids, dependencies, files, gates — and a sentence saying "eleven of fourteen" is a claim no check can keep, so the counts live in fields and `ferrox-prompt list` prints them.

Rotate with `ferrox-prompt next --rotate` when the ranking is not the question you are asking. It draws from ready slices only, weighted by `**Random weight:**`, and records the draw in `.ferrox/slices.log` so the next few calls do not offer the same slice twice.

Statuses are the only field a contributor edits to record progress. Mark a slice `done` when its gates are green, not when its diff is finished: the gates are what the next contributor is entitled to trust.
