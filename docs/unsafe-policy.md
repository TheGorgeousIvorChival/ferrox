# Unsafe policy: only when faster, only when proven harmless

`unsafe` here is a performance instrument with a proof obligation, not a coding style. It is allowed only on hot paths the benchmark gate covers, and only when the safe form is measured slower at some length. The second half is **not checked by anything** — no gate, script or test records that measurement, so it stands on review, not on CI ([`claims.md`](claims.md)). Every `unsafe` block carries a `SAFETY:` comment (enforced by `undocumented_unsafe_blocks`), and every assumption is discharged by one of:

1. **Differential proof.** Byte-identical output vs the pinned reference at every length and every block offset, both sides of every rung and group boundary.
2. **Miri** on nightly for every path it can interpret (the portable record path). SIMD intrinsics cannot be interpreted; their contract lives in `chacha::Lanes` and is discharged by (1).
3. **Counting proof.** Allocation and zero-fill counts from the counting allocator: integer facts, identical on every machine, gated outright.

## What this has already bought

- **Fused feed-forward** (`chacha/mod.rs`): the `init` add happens inside the store loop — one full pass over `regs` removed per 512 B group, same bytes.
- **Group-major stores**: `block / CHUNKS` and `block % CHUNKS` per block replaced by loop structure — the division is gone, the stores identical.
- **Hoisted AVX2 dispatch**: `is_x86_feature_detected!("avx2")` runs once per `xor_blocks` call, and the branch it guards wraps the whole ladder.
- **Fused round passes**: one loop per half-round instead of four — 10 passes over `regs` per group instead of 40. States are independent, so per-state order and the bytes are unchanged.
- **Direct register build**: `xor_groups` constructs each register via `from_fn` instead of building a zero array and overwriting every element — `NST * 4` dead constructions per group removed, safe Rust, same bytes.
- **Zero-alloc UUID** (`vless.rs`): nibbles parsed in place instead of collecting a 32-char `String` and running `from_str_radix` per byte — one heap allocation removed per header encode.
- **Single-parse address family** (`vless.rs`): `':'` membership decides which `IpAddr` parse to attempt — one failed parse fewer per header encode, same wire bytes on every input.

Each carries its proof: the differential sweep (528 shapes in tests, 3600 in the gate) is unchanged and green, because "same bytes, less work" is a fact or the build fails.

## What is still safe (and why it stays that way)

- `record::fill_exact` and the portable ChaCha core: no `unsafe` at all.
- one-block tail: bounds-checked indexing only on aarch64 (`portable`), `unsafe` SSE2 intrinsics on x86_64 — the one place `unsafe` reaches past the SIMD modules, and it is there because LLVM compiles the portable core to scalar code on that target.
- PattNG's `unsafe-*` fingerprints and plaintext-to-public: *parsed* always, *enabled* only through `policy::UnsafeOptIn`. The constructors are the audit points, and `grep allow_plaintext_to_public` finds them — it does **not** find the paths: the plaintext decision is `transport::Security::NoneToPublic`, and the two are only connected by a test.

A new `unsafe` needs the same treatment: the measurement showing the safe form regressing, the `SAFETY:` comment naming the assumption, and the green differential. A PR with `unsafe` and without all three is closed.
