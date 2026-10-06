#!/usr/bin/env bash
# Fails if any pinned upstream commit no longer resolves, or is unpinned.
#
# Without this, a force-push or a deleted branch upstream leaves the pins
# pointing at nothing and every comparison built on them quietly becomes a
# comparison against nothing. Cheap to check, expensive to discover later.
#
# A source with no `rev` is a hard error, not a skip. A pin check that tolerates
# the entries it exists to enforce reads as coverage while providing none.
#
# The commit is verified with a depth-1 fetch of the exact object, not with
# `ls-remote`: `ls-remote` only lists what refs point at, so a force-pushed
# branch whose old commit is now unreachable upstream would still "resolve" by
# name and the pin would be checked against nothing. GitHub serves any reachable
# object by id, so fetching the id is the check that means what it says.
set -euo pipefail

cd "$(dirname "$0")/.."

# Set CHECK_PINS=0 to make this a no-op, for a fork that mirrors the upstream
# repositories and cannot reach them. Unset means check; only an explicit 0
# skips, so the common mistake of forgetting to enable it fails closed.
if [[ "${CHECK_PINS:-1}" == "0" ]]; then
  echo "note: CHECK_PINS=0, upstream pins not verified"
  exit 0
fi

pins_file="upstream/pins.toml"
if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file is missing; nothing to verify"
  exit 1
fi

# Parse [sources.X] blocks into "name<TAB>repo<TAB>rev<TAB>branch" lines. This is
# a TOML subset, so it is read with awk rather than pulling in a TOML parser the
# runner may not have.
parsed="$(awk '
  /^\[sources\./ {
    name = $0
    sub(/^\[sources\./, "", name)
    sub(/\]$/, "", name)
    repo = ""; rev = ""; branch = ""
    next
  }
  /^repo[[:space:]]*=/ {
    repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next
  }
  /^rev[[:space:]]*=/ {
    rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next
  }
  /^default_branch[[:space:]]*=/ {
    branch = $0; sub(/^[^=]*=[[:space:]]*"/, "", branch); sub(/"[[:space:]]*$/, "", branch); next
  }
  /^$/ {
    if (name != "") print name "\t" repo "\t" rev "\t" branch
    name = ""
  }
  END { if (name != "") print name "\t" repo "\t" rev "\t" branch }
' "$pins_file")"

if [[ -z "$parsed" ]]; then
  echo "::error::no [sources.*] entries parsed from $pins_file; the checker is broken, not clean"
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

status=0
checked=0

# One source per line, in parallel.
#
# These checks are independent by construction — twelve separate shallow fetches
# against twelve separate remotes — so running them in sequence meant the wall
# time was the *sum* of twelve network latencies plus twelve shallow packs, on
# every runner of every workflow that checks pins. `bench.yml` does it on four
# runners, `parity.yml` on four more, and `benchmark-matrix.yml` on four more,
# daily. Concurrent is the same work at the wall time of the slowest one, and
# the depth-1 pack is unchanged: this is a parallel schedule, not a cheaper
# check.
#
# Each source writes its verdict to its own file and the loop below collects
# them, because the verdict has to stay per-source and in one place: a single
# `status` variable written by twelve background jobs would race, and the whole
# point of this script is that it says *which* pin failed.
#
# The number of concurrent fetches is capped. Uncapped, twelve depth-1 clones on
# a small runner are twelve simultaneous packfiles competing for a few cores and
# one network, which is slower than the sequence it replaced.
#
# The cap is the runner's core count, not a constant: these are network-bound, so
# the right amount of concurrency is however much download and pack the machine
# can absorb at once, and a fixed 4 would be too few on a large runner and too
# many on a small one. `nproc` is absent on macOS, where `sysctl` answers the same
# question; a runner always has `nproc`.
cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
[[ "$cores" =~ ^[0-9]+$ && "$cores" -ge 1 ]] || cores=4
# `wait -n` is the right primitive — it reclaims a slot the moment one fetch
# finishes rather than waiting for the slowest in the batch — but it arrived in
# bash 4.3 and macOS still ships 3.2, where it is a syntax error rather than a
# missing option. So the name of the reclaiming builtin is probed once and the
# fallback is a plain batch `wait`: same peak concurrency, slightly worse packing
# at the tail. It is a name and not a call because a bash function cannot be named
# `wait -n`.
reclaim="wait"
if help wait 2>/dev/null | grep -q -- '-n'; then
  reclaim="wait -n"
fi

check_one() {
  local name="$1" repo="$2" rev="$3" branch="$4"
  # The verdict goes in its own file, not as the last line of the log. `git fetch`
  # writes warnings to stderr — a redirect notice, a shallow-clone notice, a
  # `hint:` line — and those land *after* whatever was printed before them, so
  # "the last line is GOOD" was true only for the sources that happened to be
  # quiet. It reported 3 of 12 verified and exited 0 while ten pins resolved.
  local out="$tmp/$name.out" verdict="$tmp/$name.verdict"
  # Marking the failure is the caller's job to read back; `return` here leaves
  # the enclosing `{ ... }` group, so the remaining checks for this pin are
  # skipped rather than run against a rev that is already known to be wrong.
  bad() { echo BAD >"$verdict"; return; }
  {
    if [[ -z "$repo" ]]; then
      echo "::error::$name has no repo"
      bad
      return
    fi

    if [[ -z "$rev" ]]; then
      # Not a warning. An unpinned source is exactly the failure this job exists
      # to catch, so it fails the job.
      echo "::error::$name ($repo) is not pinned: no rev. A comparison against 'latest' is not a comparison."
      bad
      return
    fi

    if [[ ! "$rev" =~ ^[0-9a-f]{7,40}$ ]]; then
      echo "::error::$name rev '$rev' is not a commit id"
      bad
      return
    fi

    local dir="$tmp/repo-$name"
    if ! git init --quiet --bare "$dir" 2>/dev/null; then
      echo "::error::could not create a scratch repo for $name"
      bad
      return
    fi

    # `--depth 1` of one object, so the pack is small, but git's own diagnostics
    # are not sent to the log at all: this function's output is a verdict per
    # pin, and a `hint:` line about shallow clones is noise between two pins.
    if git -C "$dir" remote add origin "$repo" >/dev/null 2>&1 &&
       git -C "$dir" fetch --quiet --no-tags --depth 1 origin "$rev" >/dev/null 2>&1; then
      echo GOOD >"$verdict"
      echo "ok: $name $rev resolves on $repo"
    else
      echo "::error::$name rev $rev does not resolve on $repo (deleted, force-pushed, or the repo moved)"
      bad
      return
    fi

    if [[ -n "$branch" ]]; then
      # A pin can resolve and still be stale, which is fine — stale is a
      # deliberate, visible choice made by update-pins.sh. It is only worth
      # reporting, so this never fails the job.
      local head
      head="$(git ls-remote "$repo" "refs/heads/$branch" 2>/dev/null | cut -f1 || true)"
      if [[ -n "$head" && "$head" != "$rev" ]]; then
        echo "note: $name is pinned behind $branch ($head is the tip); refresh with scripts/update-pins.sh"
      fi
    fi
  } >"$out" 2>&1
}

running=0
while IFS=$'\t' read -r name repo rev branch; do
  [[ -n "$name" ]] || continue
  check_one "$name" "$repo" "$rev" "$branch" &
  running=$((running + 1))
  if [[ "$running" -ge "$cores" ]]; then
    $reclaim 2>/dev/null || wait
    running=$((running - 1))
  fi
done <<<"$parsed"
wait

# Collected in `pins.toml` order, not completion order, so a red run reads the
# same way twice and the first line of the output is always the same pin.
while IFS=$'\t' read -r name _ _ _; do
  [[ -n "$name" ]] || continue
  out="$tmp/$name.out"
  verdict_file="$tmp/$name.verdict"
  # No `.out` at all means the subshell died before it could write anything —
  # an OOM kill, a signal — and that is a failure, not a source to skip. A pin
  # whose checker never reported is a pin nobody verified.
  if [[ ! -f "$verdict_file" ]]; then
    echo "::error::$name was not checked; the check for it did not finish"
    [[ -f "$out" ]] && cat "$out"
    status=1
    continue
  fi
  [[ -f "$out" ]] && cat "$out"
  if [[ "$(cat "$verdict_file")" == "GOOD" ]]; then
    checked=$((checked + 1))
  else
    status=1
  fi
done <<<"$parsed"

if [[ "$checked" -eq 0 && "$status" -eq 0 ]]; then
  # Reaching here means the loop matched nothing, which means the parser and the
  # file disagree. Reporting "all good" would be a lie produced by a bug.
  echo "::error::parsed zero sources from $pins_file; refusing to report success"
  exit 1
fi

echo "verified $checked pinned upstream source(s)"
exit "$status"