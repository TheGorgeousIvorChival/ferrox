# P47 · The TLS-carrier loopback echo stall on linux

**Status:** landed as #16 (`7a2cdf1`) — plan recorded, cause confirmed by the fix and gate met
**Owner:** this slice
**Gate met:** `cargo test --workspace` green on three consecutive `ci.yml` runs
(run `37989420317`, attempts 1-3), all four OS jobs green. Before #16 the linux job failed
2-6 of 19 TLS loopback echo tests per run, a different subset each time; `main`'s own `ci`
was red on 8 of its last 10 runs including a commit with no Rust change.
**Touches:** crates/ferrox-app/src/proxy.rs, crates/ferrox-app/src/vmess.rs, scripts/*.sh, .github/workflows/*.yml

---

## 1. The symptom, measured

`ci.yml` goes red on linux x86_64 only. 2-6 of the 19 `*_over_tls_*` echo tests fail per run,
always a **different subset**. Each failure is identical in shape:

```
echoes: Os { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }
        after 120.575456107s; last dial: Some((127.0.0.1:1, Failure { stage: SocketConnected,
        kind: Refused, confidence: Observed }))
```

macos, windows and quiet local runs stay green. `main`'s own `ci` fails on 8 of its last 10
runs, including a commit with no Rust change — so the diff is never the cause.

## 2. What is proven

`FERROX_ECHO_TRACE=1` is already set in `ci.yml`, and `cargo test` only prints captured output
for **failing** tests, so every trace line below belongs to a failure. Two CI rounds of
`DIAG` traces on branch `fix/ci-green` (commit `e88b5cf`, PR #15 closed) gave:

Round one, 6 failures:

| stage | reached |
|---|---|
| `cli dialing` | 6/6 |
| `srv accepted` | 6/6 |
| `srv handshook` | 6/6 |
| `srv carrier up` | 6/6 |
| `srv header ok` | 6/6 |
| `srv response sent` | 3/6 |
| `relay start` | 4/6 |
| `relay fwd first read` | 2/6 |
| `srv ping read` | **0/6** |
| `relay bwd *` | **0/6** |

Round two, 4 failures:

```
t=1142  DIAG tst ping written
t=1185  DIAG bwd main up
t=1185  DIAG fwd thread up
t=1185  DIAG fwd read 4          <- the relay read the 4 ping bytes off the client socket
        ... silence for the full budget: uplink.send() never returns
```

**Conclusion the trace supports, and nothing beyond it:** the relay's forward write into the
carrier is the stalled call. `uplink.send(&buf[..4])` is entered and never returns. The echo
endpoint therefore never reads the ping (`ping read: 0` in every failure), and the backward
direction never produces a byte. It is a stuck forward write, not a slow relay.

A second, independent defect, provable by inspection: `read_echo`'s budget is
`Duration::from_secs(120)` and the socket's grain is `set_read_timeout(Some(Duration::from_secs(120)))`
(`proxy.rs:9239`). One `SO_RCVTIMEO` expiry therefore consumes the entire budget, so the
assert on `start.elapsed() < 120s` fires on the first timeout and the loop can never iterate
twice. The loop is dead code for every carrier that does not shrink the grain. This is a real
bug but **not the cause** — the grain is already shrinkable separately.

## 3. What is ruled out — do not re-litigate

1. **`TlsHalf`'s lock is not held for 120 s.** `RustlsProvider::read`
   (`crates/ferrox-core/src/tls/rustls_backend.rs:164`) returns `Err(WouldBlock)` when
   `complete_io` fails with a timeout, which releases the `Arc<Mutex<session>>` that
   `TlsHalf::locked_read` holds (`proxy.rs:3286`). `dial_tls_session` already sets
   `RELAY_POLL` on that socket at `proxy.rs:3168`, with a comment stating this exact reason.
   Contention is bounded at 20 ms.
2. **"Two threads on one TLS session" is not the discriminator.** `relay_stream`
   (`proxy.rs:1614`) also runs two threads over one TLS session, through
   `Half::read_once`/`write_once`, and the carriers that use it (`Carrier::Raw`) pass
   consistently. A patch that only removes a thread pair is not supported by the evidence.
3. **The dial is fine.** Zero `dial ... failed` traces, zero ladder retries, zero
   `<unnamed>` thread panics across all 10 failures.
4. **The echo is not "eventually late".** Raising the budget to 300 s with a 20 ms grain moved
   failures from 4-6 to 0-2 but left genuine stalls — `echoes: ... after 300.00494025s`.
   Budget is not a fix.

## 4. Phase 1 — what the instrumentation answered

Landed instead as PR #16 (`7a2cdf1`), whose commit message states the cause the
traces had narrowed to: *"A shared TLS session is read by one pump and written by another,
and the read waited for the whole poll grain holding the lock: the write pump then starves
behind it for as long as the peer is quiet."* That is the `DIAG fwd read 4` silence in §2,
and it falsifies §3.1 above — the lock wait is not bounded at 20 ms, it is bounded by the
whole grain, because `complete_io` spends the grain inside the read.

The fix: the socket read waits one tick and the read yields the session for the rest of the
grain, so the write reaches the lock while the read is quiet; and an idle read is no longer
a failed flush, because `complete_io` reads while it writes.

Phases 1 and 2 below are recorded as the reasoning, not as work still to do.

### Historical — Phase 1 — name the blocking syscall

The one thing still unknown is **where inside `uplink.send()` the 120 s is spent**. The traces
above stop one frame short. Until that is known, any fix is a guess, and this repo's rule is
that a claim is either checked by something that runs or it is not made.

Instrument, in one throwaway branch:

| where | trace |
|---|---|
| `CarrierSink::send` impls (`ws`, `grpc`, `httpheader`, `xhttp`) entry | `DIAG send enter <n>` |
| `TlsHalf::write` after `self.session.lock()` returns | `DIAG lock acquired after <elapsed>` |
| `RustlsProvider::write` before/after `complete_io` | `DIAG write io in/out` |
| `GrpcWriter::message` before/after `take_window` | `DIAG window in/out` |
| `WsReader::pull` per `is_timeout` retry | `DIAG ws pull retry` |

`DIAG lock acquired after <elapsed>` is the decisive line: if it prints a large elapsed, the
lock is the blocker and §3.1 was wrong for a case it does not cover; if it prints ~0, the
blocker is inside the TLS write, and `SO_SNDTIMEO` is the next suspect. `DIAG send enter`
tells us whether `send` is called at all for the httpheader family.

The DIAG commit `e88b5cf` on deleted `fix/ci-green` is the base — fetch it and extend.

## 5. Historical — Phase 2 — the menu Phase 1 made unnecessary

Ranked, with the condition that selects each:

- **1. `SO_SNDTIMEO` on the dial socket.** If Phase 1 shows `DIAG lock acquired after ~0`
  followed by silence in `DIAG write io out`, the block is a TCP write with no timeout set
  (`set_read_timeout` sets only `SO_RCVTIMEO`). Add a write grain in
  `dial_tls_session` beside the existing read grain, mirroring it.
- **2. Make the carrier write release the session lock between polls.** If the block is
  inside `TlsHalf::write` while the reader half's read is parked, give the write path the same
  bounded retry the read path has, so a quiet direction never parks another thread.
- **3. Propagate a genuine error instead of discarding it.** `RustlsProvider::write` ends with
  `let _ = self.conn.complete_io(&mut self.io);`, which discards a timeout error. If Phase 1
  shows `write` returning despite a failed flush, that is the bug: a lost flush makes `send`
  report success for bytes that never left.
- **4. Give the peer clone a `RELAY_POLL` grain** for the non-`Raw` carriers, exactly as the
  `Carrier::Raw` arm does at `proxy.rs:3368`. This is correct regardless of the above — the
  non-Raw arm passes `client` ungrained to `relay_sink`, which then clones it, so the relay's
  forward thread polls at 120 s instead of 20 ms. Cheap, safe, and needed in every branch.

Independent of Phase 1, fix **§2** in the same patch: give `read_echo` its own poll grain so
the budget is the only outer limit. It is a one-line change (`set_read_timeout(Some(RELAY_POLL))`
at the top of `read_echo`), the loop's retry then becomes reachable, and the failure message
names the error kind instead of burning the whole budget in one read.

## 6. Phase 3 — verification, and the order it must happen

Nothing here can be proven locally: the flake is linux-x86_64-under-load only, and
`benchmarks`, `parity`, `conformance`, `Miri` and the live foxy legs are CI-only by policy.
So verification is a CI loop.

1. `./scripts/check.sh` locally — fmt, clippy, rustdoc, leak surface, dependency policy,
   comment trace, fixture safety, windows binary paths, method docs (105 counts),
   prompt library, `cargo test --workspace`. `check.sh` may show the known P47 flake locally;
   it is not a signal either way.
2. Push the branch and let `ci.yml` run. Read the **job log of `test (linux x86_64)`**, not the
   summary — the per-test trace is only in the captured output of the failing tests. Note the
   log blob URL expires (~90 min); fetch it promptly or re-dispatch.
3. **Gate: three consecutive green `ci.yml` runs on linux x86_64.** P47's own recorded rate is
   8 of 10 red, so one green run is not evidence. Three is the gate this slice names.
4. `ops.yml` must stay green — it runs `count-ops.sh`, which cannot run on macOS/aarch64 and
   is therefore the only place the operation counts get honoured.
5. `benchmark-matrix.yml` stays green (it is, on `main`, since `23936d1`).
6. Only then merge to `main`, and only as a merge commit, matching how the repo merges.

## 7. Anti-goals

- **Do not raise `read_echo`'s 120 s budget as the fix.** It hides the stall for longer and
  produces the `after 300.00494025s` line, which is budget, not a fix.
- **Do not quarantine or `#[ignore]` the family.** The trace this slice exists to read would
  be thrown away.
- **Do not copy an upstream line.** Learn from xray-core/sing-box/zeronet how they multiplex a
  shared TLS session, then write the smaller thing here.
- **Do not widen into `p47-h2`'s files.** Another session is on this slice.

## 8. What this plan deliberately leaves open

The plan does not name the root cause, because the evidence stops one frame short of it.
Phase 1 exists to close that gap, and Phase 2 is a menu keyed on its single decisive output
line. Selecting a fix before that line exists is the failure mode this plan is written to
avoid.

One adjacent failure is out of scope here and still unexamined: `Foxy relay (live download
check)`. It is connection-dependent and therefore CI-only under this repo's rules; it needs its
own slice before it can be claimed either way.
