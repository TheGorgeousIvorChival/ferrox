# Architecture

What exists, what is claimed, and how each claim is checked.

```mermaid
graph td
    subgraph claims["What this project claims"]
        C1["Bit-identical<br/>byte for byte, every length"]
        C2["Not slower<br/>at any single length"]
        C3["No use-after-free<br/>no leak, in checked paths"]
        C4["No discarded work<br/>blocks generated == blocks needed"]
        C5["No allocation<br/>zero allocs and zero zero-fills"]
    end

    subgraph gates["What checks each claim"]
        G1["differential test<br/>vs pinned reference<br/>528 shapes in tests,<br/>3600 in the gate"]
        G2["benchmark gate<br/>re-measured before failing"]
        G3["Miri<br/>nightly, the safe-Rust core"]
        G4["the ladder's own count,<br/>every length and offset"]
        G5["counting global allocator"]
    end

    C1 --> G1
    C2 --> G2
    C3 --> G3
    C4 --> G4
    C5 --> G5

    subgraph core["ferrox-core"]
        R["record::fill_exact<br/>the public entry point"]
        X["chacha::xor_blocks<br/>the widest exact pass per block count"]
        V["chacha::xor_groups&lt;V, NST&gt;<br/>one algorithm, four backends"]
        P["portable::U4 — safe Rust"]
        N["neon::N4"]
        S["sse2::S4"]
        A["avx2::A8"]
        REF["core::reference_xor<br/>the pinned crate, tests only"]
        X --> V
        V --> P
        V --> N
        V --> S
        V --> A
        R --> X
    end

    G1 -.-> REF
    G2 -.-> R

    subgraph tls["tls — one interface, one stack"]
        T["TlsProvider"]
        RS["RustlsProvider"]
        T --> RS
    end
```

## The one idea

Every proxy stack pays the same tax in its record layer. A layer that needs *n* bytes derives keystream for a fixed larger unit — Xray-core and sing-box both take a four-block refill from a crate whose one-shot AEAD interface cannot stream — and copies out the part it wanted. Two costs follow, and neither shows up in a profile because each is spread thin across every call:

| cost | why it is invisible | how it is removed here |
| --- | --- | --- |
| work that is thrown away | rounds for bytes nobody reads | the counter advances only by blocks produced |
| a copy | spread across every call | keystream is XORed in place; the only staging is the 16 bytes of a partial block's last sub-chunk |

Removing both is only legitimate if the discarded work can be *proven* unnecessary. That proof is [`fill_exact`'s](../function/record-fill-exact.md) contract, and both halves are checked by something that runs: the benchmark compares the block count **the ladder reported** against `ceil(len / 64)` at every length and every block offset, and the differential test compares the bytes themselves. The count is an observation of the work rather than the length restated — `xor_groups` returns the blocks it generated — which is what lets the comparison fail ([`claims.md`](../claims.md)).

## The second idea: one algorithm, many widths

The keystream is one generic function over a `Lanes` trait, instantiated for portable arrays, NEON, SSE2 and AVX2. Four hand-written cores would drift; this way the algorithm cannot disagree with itself and the only thing a backend can get wrong is what its instructions mean.

That split is also what makes the safety claim checkable. The portable backend is safe Rust, so Miri interprets the ladder, the counter arithmetic and every store offset through it — the arithmetic the SIMD modules copy, which is where a memory-safety mistake would live. The SIMD modules are left with five instructions each, whose only failure mode is a wrong answer, and a wrong answer is what the differential test is for.

See [`function/chacha-xor-blocks.md`](../function/chacha-xor-blocks.md).

## The third idea: count, do not time — but say which is which

An allocation count is exact and identical on every machine. A duration is neither: it depends on the CPU, its frequency governor, and whatever else the runner is doing. So the gates are ordered with the deterministic ones first:

1. **Bit-identity** — panics on the first wrong byte.
2. **Deterministic properties** — blocks generated, heap allocations, zero-fills. All integers, all identical on every machine, all gated outright.
3. **Timing** — the only machine-dependent gate, and a length under the bar is re-measured at four times the budget before it is allowed to fail the job.

## The two backends are not the same thing

The reference this project compares against is a **crate**, not a speed. What it compiles to depends on the target, and on aarch64 it is not what you would guess:

| target | the reference runs | blocks per iteration |
| --- | --- | --- |
| x86_64 with AVX2 | its AVX2 backend | 4 |
| x86_64 without AVX2 | its SSE2 backend | 1 |
| **aarch64** | **its scalar `soft` backend** | **1** |

`chacha` 0.9.1 selects NEON only when a `chacha20_force_neon` cfg is set, and nothing sets it. So on an aarch64 runner a vector core wins by a lot, and a report that said only "vs chacha20 0.9.1" would be attributing that gap to this workspace's own work.

Every benchmark report therefore prints both sides: the backend the reference actually ran, and the core this build actually ran. A speedup is only attributable once both ends of it are named.

## The VLESS surface: one method framed, the dial owned elsewhere

The link a ZeroNet or v2rayNG user pastes is parsed once and never narrowed silently: every query key is preserved including `cipherSuites` and `unsafe-*`, checked by `vless::tests::parses_the_brief_link`.

Support is never a blank cell: `type=tcp + security=reality + flow=xtls-rprx-vision` reports `Implemented`, every other combination reports `Planned` with a reason, and plaintext-to-public plus `unsafe-*` report `UnsafeRequiresOptIn`, checked by `vless::tests::unknown_transports_parse_but_stay_planned` and the two `pattng_*_needs_opt_in` tests.

The request header is `version + UUID + addons + command + port + atyp + addr`, with Vision addons as the fixed 18-byte protobuf and one zero byte otherwise, checked by `vless::tests::first_method_header_is_stable` and `header_address_families_encode_stably`.

The Vision record carries through `record::fill_exact`: `VisionSeal` draws its padding lengths from pooled keystream refilled by `fill_exact`, checked by `vless::tests::seal_structure_matches_the_format` and `blocks_are_exactly_the_draws_taken`, and seal/open round-trips every listed length.

The end-to-end REALITY dial is not claimed here: `ferrox-app` refuses `tls` and `reality` inbounds rather than serving them in the clear, checked by `proxy::tests::vless_security_gate_keeps_plain_and_refuses_reality`, so the eleven TLS/REALITY rows in [`conformance.md`](../conformance.md) fail with no listener and belong to P17 then P18, which is stated here rather than fixed here.

No upstream VLESS suite verdict is claimed beyond the named rows: `xray-core` and `sing-box` have no seam at their pinned revs so no binary can be injected, a shape `run-upstream-suite.sh` refuses to PASS; the `xray-rust` REALITY rows are red as listed there; the header timing against `previous_encode_into` is checked by bench gate 4, which has no CI verdict yet.

## What is deliberately not claimed

That this is the fastest implementation. A benchmark is a measurement of a configuration at a point in time, and it decays: a new CPU, a new upstream release, or a new input distribution all move it. What is built here is the machinery that notices — `bench.yml` runs daily and fails on any single regressing length — so the claim is never older than the last measurement.

See [`methodology.md`](../methodology.md) for how to read the numbers, and [`function/tls-provider.md`](../function/tls-provider.md) for the interface.