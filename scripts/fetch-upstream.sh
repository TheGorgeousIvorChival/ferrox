#!/usr/bin/env bash
# Fetch every pinned upstream source into `upstream/<name>/` at its exact rev.
#
# Pinned, not tracked, is deliberate: a comparison against "latest" is not a
# comparison. So this script resolves `repo` plus `rev` from `upstream/pins.toml`
# and nothing else, checks out exactly that commit, verifies the checkout is at
# that commit, and writes `upstream/manifest.toml` saying what it got — so a
# reviewer re-derives the tree without trusting this machine.
#
# Rerunnable: an existing checkout that is already at its pin is left alone; one
# that drifted is rebuilt from scratch, because a checkout that disagrees with
# its pin is worse than no checkout.
#
# `--only a,b` fetches a subset. Twelve depth-1 clones is minutes of wall time,
# and a workflow that builds two comparators does not need the other ten: the
# unlisted pins are still *checked* by `check-upstream-pins.sh`, so nothing here
# is skipped silently — it is not fetched, and it is not used.
#
# Never copies anything into this repository. The checkouts are reading copies
# for agents (see `upstream/pins.toml`); suites run from them unmodified, and
# `upstream/*` stays out of version control — see `.gitignore`.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: fetch-upstream.sh [--only name[,name...]]" >&2
  exit 2
}

only_list=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only) [[ $# -ge 2 ]] || usage; only_list="$2"; shift 2 ;;
    -h | --help) usage ;;
    *) echo "::error::unknown argument $1" >&2; usage ;;
  esac
done

pins_file="upstream/pins.toml"
if [[ ! -f "$pins_file" ]]; then
  echo "::error::$pins_file is missing; nothing to fetch"
  exit 1
fi

# Same TOML subset `check-upstream-pins.sh` reads, plus `fallback_repo`: a
# second URL tried when the first answers nothing (ZeroNet's fork, then the
# official repo). A pin that resolves nowhere fails loudly below.
parsed="$(awk '
  /^\[sources\./ {
    name = $0
    sub(/^\[sources\./, "", name)
    sub(/\]$/, "", name)
    repo = ""; rev = ""; fallback = ""
    next
  }
  /^repo[[:space:]]*=/ {
    repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next
  }
  /^fallback_repo[[:space:]]*=/ {
    fallback = $0; sub(/^[^=]*=[[:space:]]*"/, "", fallback); sub(/"[[:space:]]*$/, "", fallback); next
  }
  /^rev[[:space:]]*=/ {
    rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next
  }
  /^$/ {
    if (name != "") print name "\t" repo "\t" rev "\t" fallback
    name = ""
  }
  END { if (name != "") print name "\t" repo "\t" rev "\t" fallback }
' "$pins_file")"

if [[ -z "$parsed" ]]; then
  echo "::error::no [sources.*] entries parsed from $pins_file"
  exit 1
fi

fetched=0
manifest="upstream/manifest.toml"
# Built aside and moved into place, so a run that dies partway leaves the
# previous manifest rather than a shorter one: a manifest that lists two of
# seven pins and stops reads as a complete account of what is on disk.
manifest_tmp="$manifest.part"
trap 'rm -f "$manifest_tmp"' EXIT
{
  echo "# Derived artifact. Do not edit: rerun scripts/fetch-upstream.sh."
  echo "# Each entry is the exact commit the named checkout holds."
} >"$manifest_tmp"

# Per-source, in a subshell, so two checkouts never share a `git init` and a
# `manifest_tmp` append. Twelve shallow fetches are independent network round
# trips; in sequence they cost the sum, which on `xray-core` and `sing-box` is
# most of a workflow's setup time for sources the caller may not even use.
#
# Each source writes its own manifest stanza and its own log, and the verdict is
# a file rather than the last line of the log — same reason as
# `check-upstream-pins.sh`: `git` writes its own diagnostics to stderr and
# "read the last line" reads whichever of those landed last.
fetch_one() {
  local name="$1" repo="$2" rev="$3" fallback="$4"
  local log="$tmp/$name.log" verdict="$tmp/$name.verdict"
  {
    if [[ -z "$repo" || -z "$rev" ]]; then
      echo "::error::$name is missing repo or rev; pin it before fetching"
      echo BAD >"$verdict"
      return 1
    fi

    local dir="upstream/$name" fetched_from
    fetched_from="cached (already at pin)"
    if [[ -d "$dir/.git" ]] && [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$rev" ]]; then
      echo "ok: $name already at $rev"
    else
      rm -rf "$dir"
      git init --quiet "$dir"
      fetched_from=""
      local candidate
      for candidate in "$repo" "$fallback"; do
        [[ -n "$candidate" ]] || continue
        git -C "$dir" remote add origin "$candidate" 2>/dev/null || git -C "$dir" remote set-url origin "$candidate"
        if git -C "$dir" fetch --quiet --no-tags --depth 1 origin "$rev"; then
          fetched_from="$candidate"
          break
        fi
      done
      if [[ -z "$fetched_from" ]]; then
        echo "::error::$name rev $rev resolves nowhere (tried primary and fallback)"
        echo BAD >"$verdict"
        return 1
      fi
      git -C "$dir" checkout --quiet FETCH_HEAD
      echo "fetched: $name at $rev from $fetched_from"
    fi

    local head
    head="$(git -C "$dir" rev-parse HEAD)"
    if [[ "$head" != "$rev" ]]; then
      echo "::error::$name holds $head, not its pin $rev"
      echo BAD >"$verdict"
      return 1
    fi

    # The stanza is assembled in its own file and moved in, so a reader of
    # `manifest.toml` never sees half an entry.
    {
      echo ""
      echo "[checkout.$name]"
      echo "repo = \"$repo\""
      echo "rev  = \"$rev\""
      echo "fetched_from = \"$fetched_from\""
    } >"$tmp/$name.stanza"
    echo GOOD >"$verdict"
  } >"$log" 2>&1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; rm -f "$manifest_tmp"' EXIT

# Peak concurrency is the core count, for the reason
# `check-upstream-pins.sh` gives: these are network-bound, so the right number is
# however much the machine can absorb at once. `wait -n` reclaims a slot as soon
# as one clone lands; macOS bash is 3.2 and does not have it, so the name is
# probed and the fallback is a batch `wait` at the same peak.
cores="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
[[ "$cores" =~ ^[0-9]+$ && "$cores" -ge 1 ]] || cores=4
reclaim="wait"
if help wait 2>/dev/null | grep -q -- '-n'; then
  reclaim="wait -n"
fi

selected=""
status=0
running=0
while IFS=$'\t' read -r name repo rev fallback; do
  [[ -n "$name" ]] || continue
  if [[ -n "$only_list" ]] && [[ ",$only_list," != *",$name,"* ]]; then
    continue
  fi
  fetch_one "$name" "$repo" "$rev" "$fallback" &
  running=$((running + 1))
  if [[ "$running" -ge "$cores" ]]; then
    $reclaim 2>/dev/null || wait
    running=$((running - 1))
  fi
  selected="$selected $name"
done <<<"$parsed"
wait

# Collected in pins.toml order, so a red run reads the same way twice.
for name in $selected; do
  [[ -f "$tmp/$name.log" ]] && cat "$tmp/$name.log"
  if [[ ! -f "$tmp/$name.verdict" || "$(cat "$tmp/$name.verdict")" != "GOOD" ]]; then
    echo "::error::$name was not fetched; see above"
    status=1
    continue
  fi
  cat "$tmp/$name.stanza" >>"$manifest_tmp"
  fetched=$((fetched + 1))
done

if [[ "$fetched" -eq 0 ]]; then
  echo "::error::fetched nothing; refusing to write a manifest that reads as a complete account"
  exit 1
fi

mv "$manifest_tmp" "$manifest"
echo "fetched $fetched pinned upstream source(s); manifest in $manifest"
exit "$status"
