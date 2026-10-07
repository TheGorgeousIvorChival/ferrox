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
| policy checks: leak surface, dependency policy, comment trace, fixture safety, windows paths, method docs | local, every push |
| **exact operation counts** — `scripts/count-ops.sh` against `scripts/expected-ops.txt` | local, every push |
| prompt library — `cargo run -p ferrox-prompt -- check` | local, every push |
| `cargo test --workspace` | local, every push |
| benchmarks, ratios, comparisons (`bench.yml`, `parity.yml`, `compare.yml`, `speedtest.yml`, `benchmark-matrix.yml`) | **CI only** |
| per-method instruction counts (`ops.yml`, artefact `method-ops`) | **CI only** — informational, never red |
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
`brew install valgrind`). Without it the gate fails — it does not skip. It also
does not exist on macOS/aarch64 at all, so on that machine the count gate is
CI-only in practice: name it and say why rather than skipping it quietly. Counts
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
- **A method page ships with the method, or with the change to it.** Every
  connection method under `docs/function/` carries four counts — ops, syscalls,
  memory copies, time — a `graph TD` of the data path, and what was removed
  against Xray-core, sing-box and ZeroNet. The numbers live in exactly one
  place, `scripts/method-counts.txt`, and `scripts/check-method-docs.sh` fails if
  a page and that file disagree in either direction. Editing a number in the
  page alone is the failure this gate exists to catch.
- `UNBLESSED` is the value for a count nobody has measured. It is a claim that
  is open, not a number, and it must never be quoted as one. `ops.yml` reports
  every symbol in `scripts/method-ops.txt` on each run; read that artefact before
  turning an `UNBLESSED` row into a figure.
- Name what was *not* removed. A page that lists only wins is not evidence, and
  the failures are the part a reader needs: rows that parse but are not dialled,
  a carrier refused by name, a benchmark gate that is an allocation count and not
  a clock.
- Rewrite, do not copy. No upstream line or test enters this tree — learn how
  the pinned implementations do it and write the smaller, cheaper thing.
- Faster, safer, leaner, or it does not land. Counts prove, durations suggest.
- Simpler with less code wins every tie at equal performance. No abstraction
  with one implementor, no second way of doing something, no debt.
- Unsafe only for a measured win; if the safe form ties, the safe form ships.
  Growing a `Vec` into its own uninitialised tail to skip a `memset` is that
  measured win, and it needs the same `truncate` on the error path as any other
  `set_len`.
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