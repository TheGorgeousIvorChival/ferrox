#!/usr/bin/env bash
# Fails on leak-prone surface inside `ferrox-core`.
#
# Three things have no legitimate spelling in the core, and each one has caused
# a real incident in one of the projects this replaces:
#
# 1. DNS resolution. The parser splits `None` from `NoneToPublic` *without* a
#    resolver (the dial path re-checks), so a name that reaches a resolver from
#    inside the core is a DNS leak around the proxy, not a convenience.
# 2. Memory-leak primitives. `Box::leak`, `mem::forget`, `ManuallyDrop` and
#    `into_raw` have no use in a core whose allocation gate is zero: anything
#    reaching for them is laundering a lifetime the borrow checker refused.
# 3. Printing and wall-clock reads. The core is a library: `println!`/`dbg!`
#    in it is noise on every caller's stdout, and `Instant::now` in it makes a
#    supposedly deterministic function timing-dependent. Both live in
#    `ferrox-bench` and `ferrox-app`, never here.
#
#    Two named exceptions, and both are paths rather than patterns so a clock read
#    anywhere else in the core still fails this gate:
#
#    - `kcp/`. `KCP` is retransmission-timed by definition -- its RTO, its
#      four-tick update interval and its probe every N packets are all wall-clock
#      reads, and a congestion-controlled transport that ignored the clock would
#      not be `KCP`.
#    - `chacha/calibrate.rs`. One `ChaCha` block is a dependency chain with
#      nothing to overlap, so which instruction set reaches its end first is a
#      property of the microarchitecture and `CPUID` does not report it. This
#      module measures once and picks between two cores that run the same twenty
#      rounds through the same generic function, so the keystream is byte-identical
#      either way: the clock decides which correct core runs, and cannot reach the
#      output. It is a file of its own precisely so the exception stays this
#      narrow.
#
# `git grep` over tracked files only, so untracked scratch never fails the job.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

if git grep -I -n -E 'to_socket_addrs|lookup_host|getaddrinfo|hickory|trust-dns' -- crates/ferrox-core/src; then
  echo "::error::ferrox-core must not resolve DNS — the parser decides without a resolver (see transport.rs)"
  status=1
fi

if git grep -I -n -E 'Box::leak|mem::forget|::forget\(|ManuallyDrop|into_raw' -- crates/ferrox-core/src; then
  echo "::error::ferrox-core must not launder lifetimes — the allocation gate is zero, use borrows"
  status=1
fi

if git grep -I -n -E 'println!|print!|eprintln!|eprint!|dbg!' -- crates/ferrox-core/src; then
  echo "::error::ferrox-core is a library — printing lives in ferrox-bench/ferrox-app"
  status=1
fi

if git grep -I -n -E 'Instant::now|SystemTime::now' -- crates/ferrox-core/src \
    ':!crates/ferrox-core/src/kcp/**' \
    ':!crates/ferrox-core/src/chacha/calibrate.rs'; then
  echo "::error::ferrox-core must stay deterministic — wall-clock reads live in ferrox-bench (two named exceptions: kcp/ is retransmission-timed by definition, chacha/calibrate.rs picks between two byte-identical one-block cores)"
  status=1
fi

exit "$status"
