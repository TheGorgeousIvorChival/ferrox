# Operation counts: proof that is not a stopwatch

A duration is a claim about one machine at one moment. An operation count is
a claim about the code: the same binary and input retire the same
instructions, allocate the same bytes, and issue the same syscalls on every
machine. That is why the gates below count before they time — a "1 less
operation" diff changes a count every runner reproduces, while a duration
only ever suggests.

## The three counters

| what | instrument | determinism | gate |
| --- | --- | --- | --- |
| retired instructions per function (`Ir`) | callgrind via `scripts/count-ops.sh`, enforced by `ops.yml` against `scripts/expected-ops.txt` | exact across machines for a fixed profile | exact match, human-blessed numbers only |
| heap allocations and bytes | the counting allocator in `crates/ferrox-bench/src/count.rs` | exact, single-threaded | exact `0` where claimed |
| syscalls per test | `strace -c` printed by the same script | informational: loader and allocator paths may vary it | never gated, always printed |

Wall time stays where it belongs: behind the counts, as a smell check. A
diff that lowers a count and raises a duration has found a worse instruction
mix, and the table below is where that contradiction gets investigated
instead of averaged away.

## How a number gets blessed

1. Write the faster code with the output bytes unchanged; the differential
   tests decide bit-identity, never the counter.
2. Run `ops.yml` (or the script): it fails listing `symbol Ir=<measured>`.
3. Read the diff that produced the delta. If every added or removed
   instruction is the change intended, put the measured number in
   `expected-ops.txt`. If any is not, the speedup is an accident wearing a
   smaller number — fix the code, not the file.

Counts are profile-specific: release, `--locked`, the flags in `ops.yml`.
A profile change re-blesses every row, loudly.

## Measured rows

| function (test filter) | before | after | what the delta is |
| --- | --- | --- | --- |
| `der_to_pem` (`quic::tests::pem_wraps_at_sixty_four_columns`) | intermediate 64-char buffer: 1 heap allocation plus a full second pass over the base64 text | none: 48 input bytes encode straight into the output line | one allocation and one `O(n)` copy removed; output bytes unchanged, proven by the wrap and round-trip tests. Ir: see `expected-ops.txt` (the 48-byte block helper it calls is fully inlined at release, so its cost lives inside this row) |

## On order-of-magnitude wins

No counting scheme produces a breakthrough; it only makes small wins
undeniable, and undeniable wins compound. A 10x comes from a different
algorithm or from hardware that runs it — `AES-GCM` on ARMv8-Crypto at 12x,
the zero-copy relay — and each of those is its own rung with its own gate,
not a line in this file. What this file refuses is the opposite failure:
ten thousand unmeasured operations, each too small to time, adding up to the
gap between this tree and the ones it replaces.
