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
- **A copy or an allocation claim is proved by pointer identity, not by
  reading the code.** `frames_reuse_the_callers_buffers` is the model: assert
  that the returned slice's pointer lies inside the caller's buffer, that the
  buffer's own pointer does not move, and that its capacity does not grow. That
  is what makes `user-space-copies-per-byte-written 1` a claim rather than an
  intention, and it is the gate to copy when a rewrite claims it removed a
  copy, a `memmove` or a per-record allocation.
- **The named checker has to observe the thing in the row.** Pointer identity
  observes copies and reallocations. A differential sweep against a reference
  crate observes *bytes*, not the operation count that produced them: it will
  happily pass while the code stages keystream, calls `update` twice or recurses
  into a dispatch with nothing to do. So a row like `staging-bytes-per-decrypt
  0` with a differential test beside it is a row with no checker, and the honest
  place for it is the page's prose. Nothing in this tree counts ChaCha blocks per
  open, stack bytes staged, or `absorb` calls, and `count::measure` hooks
  `alloc`/`alloc_zeroed`, so it would not see a stack staging buffer either.
- **A counter beats an argument when the counter already exists.** `kcp
  reader-wakeups-per-datagram 1` is gated because `Notifier::gen` is the very
  counter `read` snapshots and `wait_since` compares, so its delta *is* the
  wakeup count. Look for the quantity already lying around as state before
  writing a test that reconstructs it.
- **A blessed count is a claim about a gate, so audit the gate before the code.**
  Three rows on `main` were numbers nothing was checking: the VMess
  four-frame batch was swept by a test whose longest input produced three frames,
  its syscall row wrote into a `Vec` that cannot count syscalls, and the
  xtls-vision allocation row named a gate that drives a different
  implementation of the same framing. Before adding an optimisation to a file,
  read the test the manifest row names and ask what it actually executes — a row
  that has never been observed is worse than an `UNBLESSED` one, because it reads
  as a number.
- **An allocator claim is gated by capacity, and capacity catches the leak the
  change would otherwise ship.** `send-payload-reallocations-per-window 0` is
  witnessed by the arena's own `capacity()` over 64 push/acknowledge rounds: a
  per-segment `Vec` cannot hold capacity steady, and a trim that stopped firing
  shows up as a number that only goes up. The same test found that `trim()`
  returning early on `base == 0` made the reclaim branch unreachable. **Write the
  capacity assertion before the buffer, not after.**
- **A loopback test cannot gate a syscall count, and a scheduler-dependent count
  is not a gate at all.** Drive the counter from an in-memory stream that always
  answers the whole buffer, where the number is exact; assert only the bytes
  over a real socket. `xhttp` does both, and the first attempt at a hard bound on
  the real socket failed about one run in three because TCP segmentation moves
  with the scheduler.
- **Changing a read's granularity is a count change.** Reading a window instead of
  a two-byte read removes a syscall *and* changes how many times the caller's
  `Read::read` returns. Both are counted quantities in this tree, so both belong
  on the page — see `carrier-xhttp read-syscalls-per-16KiB-chunk`.
- **A rewrite that passes the test suite can still be a regression, so do the
  arithmetic on the case the tests do not reach.** Two on this branch looked
  like wins and were not, and the arithmetic found both without a benchmark.
  Widening the websocket mask stride from 16 to 64 bytes leaves the vector op
  count identical and pushes the *scalar remainder* from under 16 bytes to as
  much as 63, so every length that is not a multiple of 64 got worse. Pulling
  KCP segments out of the window one at a time instead of draining it lets
  `next_number` lag behind what a single `read` consumed, and `process_segment`
  refuses anything `window_size` ahead of `next_number` — at the default
  776-segment window a sender legitimately in flight starts losing segments.
  Neither was caught by a test, because the tests feed everything before they
  read. Before landing a rewrite, ask what the *worst* input does, and ask
  whether the change moves a cursor, a counter or a window that something else
  is measured against.
- **A rewrite that trades one pass for another says so, with both numbers.**
  The AEAD open path went from one fused ladder pass plus a staging buffer and a
  scalar loop to two passes and no staging, and the honest line is
  `keystream-passes-per-decrypt 2` beside `staging-bytes-per-decrypt 0`. Naming
  the pass that got worse is what keeps a "removal" from being a relocation.
- **Bit-identical means the block, byte and counter counts are unchanged too,
  not only the output.** A rewrite that generates the same bytes with a
  different number of keystream blocks, a different panic threshold, or a
  different number of 16-byte Poly1305 absorbs has changed the method, not
  tuned it. The differential sweep is the gate: `every_decrypt_matches_the_crate_it_replaces`
  and `every_payload_length_and_address_survives_the_round_trip` open against
  the pinned crate at every length and address family, and a forged tag has to
  leave the buffer still encrypted.
- `UNBLESSED` is the value for a count nobody has measured. It is a claim that
  is open, not a number, and it must never be quoted as one. `ops.yml` reports
  every symbol in `scripts/method-ops.txt` on each run; read that artefact before
  turning an `UNBLESSED` row into a figure.
- Name what was *not* removed. A page that lists only wins is not evidence, and
  the failures are the part a reader needs: rows that parse but are not dialled,
  a carrier refused by name, a benchmark gate that is an allocation count and not
  a clock. **A change that alters the bytes on the wire is not an optimisation,
  however many syscalls it saves** — KCP sends one datagram per segment because
  batching would change the datagram boundaries a peer sees, so it is named and
  left alone. Name it the same way you name a refused carrier.
- **Two worktrees share one `target-dir` on purpose, and that makes a bisect
  lie.** `scripts/new-worktree.sh` points every worktree at one
  `.ferrox-target` so dependencies compile once, so a `cargo test` can pick up an
  artefact another worktree just rebuilt, and "this change broke the test" can be
  an artefact of the rebuild rather than of the diff. When a bisect points at
  something absurd — a one-line capacity change failing a loopback test — rerun
  it with `CARGO_TARGET_DIR` of its own before believing it. And re-`git
  checkout` is how a bisect throws work away: snapshot the files to `/tmp`
  first, or take a patch against the base you started from.
- **Rebase onto `main` before trusting a long session.** `main` moves under a
  worktree; a `git checkout <file>` to bisect then silently reverts commits that
  landed in the meantime, and the result looks exactly like your own regression.
  Re-apply work as a patch (`diff` the base against your tree, `git apply` onto
  the new tip) so a three-way overlap is a conflict rather than a lost hunk.
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