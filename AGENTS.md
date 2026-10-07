# AGENTS.md

Rules for working in this repository. The shared protocol in
[`crates/ferrox-prompt/prompts.md`](crates/ferrox-prompt/prompts.md) is the
source of truth and says the same things at more length; if this file and that
one disagree, that one is right.

## What is checked locally, and what is never checked locally

The split is not negotiable.

| check | where |
| --- | --- |
| fmt, clippy, rustdoc | local, every push — `./scripts/check.sh` |
| policy checks: leak surface, dependency policy, comment trace, fixture safety, windows paths | local, every push |
| **exact operation counts** — `scripts/count-ops.sh` against `scripts/expected-ops.txt` | local, every push |
| prompt library — `cargo run -p ferrox-prompt -- check` | local, every push |
| `cargo test --workspace` | local, every push |
| benchmarks, ratios, comparisons (`bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml`, `benchmark-matrix.yml`) | **CI only** |
| upstream suites against `ferrox-app` (`conformance.yml`) | **CI only** |
| Miri (`safety.yml`) | **CI only** |

**Nothing connection-dependent runs on a contributor machine.** Every developer
is behind a VPN and a proxy, so a local benchmark measures a tunnel, a local
conformance run measures somebody's exit node, and a local dial measures
neither this code nor the reference. Push and read CI instead.

```bash
./scripts/check.sh    # everything above that is local, in one command
```

`scripts/count-ops.sh` needs `valgrind` (`apt-get install valgrind strace`, or
`brew install valgrind`). Without it the gate fails — it does not skip. Counts
are blessed in `scripts/expected-ops.txt` only after reading the diff that moved
them; never copy a measured number there to silence the gate.

## Reporting

Terse verdicts, never a history of the diff, and always in this shape: what
changed, what was measured with numbers, what is still open. A slice that fails
is worth more to the next contributor than one reported done that quietly
skipped half its gates. If a gate cannot be run, name it and say why, and do
not call the slice complete.

## Rules that shape a change

- A claim in this repository is either checked by something that runs or it is
  not made. Never write one without naming its checker.
- Rewrite, do not copy. No upstream line or test enters this tree — learn how
  the pinned implementations do it and write the smaller, cheaper thing.
- Faster, safer, leaner, or it does not land. Counts prove, durations suggest.
- Simpler with less code wins every tie at equal performance. No abstraction
  with one implementor, no second way of doing something, no debt.
- Unsafe only for a measured win; if the safe form ties, the safe form ships.
- Fixes leave no trace: one line of comment per item at most, no TODOs, no
  changelogs (`scripts/check-comments.sh` fails them).
- Do not widen a slice. If it exposes a larger problem, add a prompt section to
  `prompts.md` instead of fixing it here.
- Checkouts under `upstream/` are for reading and are never committed. Re-run
  `scripts/fetch-upstream.sh` whenever `upstream/pins.toml` changes under you.

## Roadmap

The roadmap is a file, `crates/ferrox-prompt/prompts.md`. Every slice carries a
status, a leverage, an effort, the gates that would prove it finished, and the
slices it blocks.

```bash
cargo run -p ferrox-prompt -- next        # the slice, the reason, prompt → clipboard
cargo run -p ferrox-prompt -- list        # the roadmap, with what is ready now
cargo run -p ferrox-prompt -- check       # is the library still coherent?
```

Status is the only field to edit, and a slice is `done` when its gates are
green, not when its diff looks finished.