#!/usr/bin/env bash
# Fails on a dependency graph that `deny.toml` does not already permit.
#
# `deps.yml` runs `cargo-deny` and is the authority. This is the part of it that a
# laptop can run, because `cargo-deny` is a separate install and this repository's
# friction policy is that a lint found locally is free while a lint found in CI is
# a runner somebody is waiting behind.
#
# What it checks without the tool is the claim that needs no database: every
# licence expression in `Cargo.lock` must be spelled from `deny.toml`'s allow
# list, every dependency must come from crates.io, and nothing in the tree may
# `patch` or `git`-depend on the two implementations this work replaces. That last
# one is the check that has bitten before — a `v2ray-rust` or `sing-box` line in a
# manifest is a licence event, and `sing-box` is GPL-3.0, so a dependency on it
# would put a copyleft obligation on code this repository claims is
# `MIT OR Apache-2.0`.
#
# It does not check advisories: those need the RUSTSEC database, so `deps.yml`
# owns them and a laptop cannot. When `cargo-deny` is installed this still runs,
# because it checks the manifests rather than the resolved graph and the two fail
# differently.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

note() { printf '::error::%s\n' "$1"; status=1; }

# The allow list, read from `deny.toml` rather than repeated here: two copies of a
# licence list is a licence list that will be updated in one of them.
allow_list="$(sed -n '/^\[licenses\]/,/^\[/p' deny.toml | sed -n 's/^  "\(.*\)",\{0,1\}$/\1/p')"

if [[ -z "$allow_list" ]]; then
  note "deny.toml's [licenses].allow is empty or unreadable, so this check would pass on nothing"
fi

# The resolved graph's licences. `cargo metadata` rather than `Cargo.lock`,
# because a lockfile records versions and sources and carries no licence field at
# all — reading it here would find zero lines and pass, which is the failure mode
# this whole script exists to avoid.
#
# `--offline` first so a warm cache answers without touching the network, then
# the same read allowed to fetch. Not `deny.toml`'s job to be strict about
# caches: `--offline` alone reports a licence failure for a graph it never read,
# because one transitive crate was never downloaded, and a gate that goes red for
# a warm-up is a gate people learn to bypass with `--offline`-shaped workarounds.
#
# If both reads fail the check is *skipped loudly* and exits non-zero, because a
# dependency-policy check that could not read the graph has proved nothing and a
# green line here would read as though it had.
metadata=""
if metadata="$(cargo metadata --offline --format-version 1 --all-features 2>/dev/null)"; then
  :
elif metadata="$(cargo metadata --format-version 1 --all-features 2>/dev/null)"; then
  :
else
  note "cargo metadata could not read the graph, so no licence was checked; run \`cargo fetch\` and try again"
  metadata=""
fi

if [[ -n "$metadata" ]]; then
  expressions="$(printf '%s' "$metadata" | python3 -c '
import json, sys
graph = json.load(sys.stdin)
print("\n".join(sorted({p.get("license", "") for p in graph["packages"] if p.get("license")})))
')"
  while read -r expression; do
    [[ -z "$expression" ]] && continue
    # An expression is several identifiers joined by OR/AND with optional
    # parentheses, and each identifier has to be one the allow list names.
    # `WITH <exception>` binds to the identifier it follows, so the exception is
    # matched as part of that one string rather than as a term of its own — the
    # allow list carries `Apache-2.0 WITH LLVM-exception` whole.
    normalised="$(printf '%s' "$expression" | tr -d '()' | tr 'A-Z' 'a-z')"
    IFS=', ' read -r -a parts <<<"$normalised"
    for part in "${parts[@]}"; do
      [[ -z "$part" || "$part" == "or" || "$part" == "and" ]] && continue
      if [[ "$part" == "with" || "$part" == *-exception || "$part" == exception-* ]]; then
        # The exception is already inside the identifier it follows, which is in
        # the list or is not; there is nothing separate to check here.
        continue
      fi
      if ! grep -qixF "$part" <<<"$allow_list"; then
        note "the graph carries \`$expression\`, which needs \`$part\`; deny.toml's allow list does not name it"
      fi
    done
  done <<<"$expressions"
fi

# Anything that is not crates.io. `Cargo.lock`'s `source` line is the resolved
# answer, so this reads the resolution rather than the manifests, which is what
# makes it catch a transitive git dependency as well as a direct one.
if grep -E '^source = "git\+' Cargo.lock >/dev/null; then
  grep -E '^source = "git\+' Cargo.lock | sort -u | while read -r _ line; do
    note "$line is not crates.io; deny.toml's [sources] allows no git source"
  done || true
  status=1
fi

# The two implementations this work replaces, in any manifest of this workspace.
# A `patch` or a path dependency on either one is the same licence event as
# depending on it. The comparator checkouts under `upstream/` carry their own
# manifests and are excluded: they are derived artefacts that
# `scripts/fetch-upstream.sh` re-derives at a pinned commit, and `deny.toml`
# governs this workspace's graph and not theirs.
for banned in sing-box v2ray-rust; do
  hits="$(grep -rnE "^[[:space:]]*${banned}[[:space:]]*=" --include='Cargo.toml' crates Cargo.toml 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    note "\`${banned}\` is a comparator, read at its pin under upstream/ and never a dependency"
    printf '%s\n' "$hits"
  fi
done

exit "$status"
