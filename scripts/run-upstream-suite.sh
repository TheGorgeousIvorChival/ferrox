#!/usr/bin/env bash
# Runs one upstream suite against a Ferrox binary at the pinned commit, or skips
# it with the rung reason when no binary is wired yet.
#
# Upstream suites are NEVER copied into this repository (sing-box is GPL-3.0,
# Xray-core/xray-rust are MPL-2.0, PattNG is GPL-3.0): they run unmodified from
# the pinned commit. Each source in upstream/pins.toml carries `test_enabled`,
# a `suite` command run with the clone as its working directory, and
# `ferrox_binary` naming the Ferrox binary the suite executes. An enabled entry
# with no binary fails here instead of printing PASS, because a suite that ran no
# Ferrox binary proves nothing about this workspace. Usage: run-upstream-suite.sh
# [name] (default: every source).
set -euo pipefail

cd "$(dirname "$0")/.."

name_filter="${1:-}"
pins_file="upstream/pins.toml"
status=0
ran=0

# Whether a suite's own output shows it ran the tests its command names.
#
# libtest exits 0 when a filter matches nothing, so a name renamed upstream would
# print PASS over a suite no test in; and it filters by substring unless `--exact`
# is passed, so a name that is a prefix of a sibling runs tests the pin never
# named. `running N tests` is the count: above zero always, and equal to the
# filter names when the command carries any. An output carrying no such line has
# no count to read, so it is left to its exit code and says so rather than
# passing as though it had been checked.
libtest_ran_named() {
  local command="$1" log="$2" filters="" word count named=0 sum=0 saw=0
  if [[ "$command" == *" -- "* ]]; then
    filters="${command##* -- }"
  fi
  for word in $filters; do
    [[ "$word" == -* ]] || named=$((named + 1))
  done
  while IFS= read -r count; do
    saw=1
    sum=$((sum + count))
  done < <(sed -n 's/^running \([0-9][0-9]*\) tests\{0,1\}$/\1/p' "$log")
  if ((saw == 0)); then
    echo "note: no libtest test count in the output; its exit code is the only evidence"
    return 0
  fi
  if ((sum == 0)); then
    echo "::error::the suite ran no tests, so a zero exit says nothing about it"
    return 1
  fi
  if ((named > 0 && sum != named)); then
    echo "::error::the suite ran $sum tests and its command names $named; libtest filters by \
substring, so a name that prefixes a sibling runs tests the pin never named"
    return 1
  fi
}

# Self-test, every run: a count rule that stopped matching would leave every
# enabled suite vacuously accepted, so the four shapes are decided here first.
selftest="$(mktemp -d)"
selftest_names="cargo test --test t -- --ignored --exact one two"
printf 'running 2 tests\n' >"$selftest/exact.log"
printf 'running 5 tests\n' >"$selftest/prefix.log"
printf 'running 0 tests\n' >"$selftest/empty.log"
printf 'ok  pkg  0.01s\n' >"$selftest/other.log"
for shape in exact:accept prefix:refuse empty:refuse other:accept; do
  verdict=0
  libtest_ran_named "$selftest_names" "$selftest/${shape%%:*}.log" >/dev/null || verdict=$?
  if [[ "$verdict" -eq 0 && "${shape##*:}" == refuse ]] || [[ "$verdict" -ne 0 && "${shape##*:}" == accept ]]; then
    echo "::error::self-test: ${shape%%:*}.log is answered $verdict; it must be ${shape##*:}"
    status=1
  fi
done
rm -rf "$selftest"

# name<TAB>repo<TAB>rev<TAB>enabled<TAB>suite<TAB>binary<TAB>seam<TAB>path — same TOML
# subset the pin checker reads, plus the conformance fields and the checked path.
parse_pins() {
  awk '
    function f(v) { return v == "" ? "-" : v }
    /^\[sources\./ {
      if (name != "") print name "\t" repo "\t" rev "\t" enabled "\t" f(suite) "\t" f(binary) "\t" f(seam) "\t" f(path)
      name = $0; sub(/^\[sources\./, "", name); sub(/\]$/, "", name)
      repo = ""; rev = ""; enabled = ""; suite = ""; binary = ""; seam = ""; path = ""
      next
    }
    /^repo[[:space:]]*=/ { repo = $0; sub(/^[^=]*=[[:space:]]*"/, "", repo); sub(/"[[:space:]]*$/, "", repo); next }
    /^rev[[:space:]]*=/ { rev = $0; sub(/^[^=]*=[[:space:]]*"/, "", rev); sub(/"[[:space:]]*$/, "", rev); next }
    /^test_enabled[[:space:]]*=/ { enabled = $0; sub(/^[^=]*=[[:space:]]*/, "", enabled); next }
    /^suite[[:space:]]*=/ { suite = $0; sub(/^[^=]*=[[:space:]]*"/, "", suite); sub(/"[[:space:]]*$/, "", suite); next }
    /^ferrox_binary[[:space:]]*=/ { binary = $0; sub(/^[^=]*=[[:space:]]*"/, "", binary); sub(/"[[:space:]]*$/, "", binary); next }
    /^seam[[:space:]]*=/ { seam = $0; sub(/^[^=]*=[[:space:]]*"/, "", seam); sub(/"[[:space:]]*$/, "", seam); next }
    /^path[[:space:]]*=/ { path = $0; sub(/^[^=]*=[[:space:]]*"/, "", path); sub(/"[[:space:]]*$/, "", path); next }
    END { if (name != "") print name "\t" repo "\t" rev "\t" enabled "\t" f(suite) "\t" f(binary) "\t" f(seam) "\t" f(path) }
  ' "$pins_file"
}

workspace="$PWD"
while IFS=$'\t' read -r name repo rev enabled suite binary seam path; do
  [[ "$suite" == "-" ]] && suite=""
  [[ "$binary" == "-" ]] && binary=""
  [[ "$seam" == "-" ]] && seam=""
  [[ "$path" == "-" ]] && path=""
  [[ -n "$name" ]] || continue
  if [[ -n "$name_filter" && "$name" != "$name_filter" ]]; then
    continue
  fi
  # The pin's path names the tree the note describes, so it is resolved against
  # the pinned tree for every entry, enabled or not: the four values repaired
  # alongside this check rotted precisely because only enabled entries ever
  # cloned anything. Same depth-1 fetch the pin checker uses, plus a tree
  # lookup, so a path that names nothing fails here instead of rotting again.
  if [[ -n "${path:-}" ]]; then
    scratch="$(mktemp -d)"
    if git init --quiet --bare "$scratch" >/dev/null 2>&1 \
      && git -C "$scratch" remote add origin "$repo" >/dev/null 2>&1 \
      && git -C "$scratch" fetch --quiet --depth 1 origin "$rev" >/dev/null 2>&1 \
      && git -C "$scratch" cat-file -e "$rev:$path" 2>/dev/null; then
      echo "path ok: $name $path at ${rev:0:7}"
    else
      echo "::error::$name declares path $path but it is absent at $rev"
      status=1
      rm -rf "$scratch"
      continue
    fi
    rm -rf "$scratch"
  fi
  if [[ "$enabled" != "true" ]]; then
    echo "SKIPPED: $name @ ${rev:0:7} — no Ferrox binary wired yet (would need ${binary:-nothing exists for this rung yet}); rung not implemented (see docs/conformance.md)"
    continue
  fi
  if [[ -z "${binary:-}" ]]; then
    # Fail closed: an enabled suite with no binary would PASS on upstream code alone.
    echo "::error::$name is enabled with no ferrox_binary: refusing a PASS that ran no Ferrox binary"
    status=1
    continue
  fi
  if [[ -z "$suite" ]]; then
    # Enabled with no runnable suite: covered by the build matrix itself.
    echo "COVERED-BY-BUILD: $name @ ${rev:0:7} — no upstream suite; build matrix is the check"
    continue
  fi
  # Building the binary is not running it. Without a seam the suite has no way
  # to execute it, so a PASS here would name a binary that took no part in the
  # comparison — the exact claim this script exists to refuse.
  if [[ -z "$seam" ]]; then
    echo "::error::$name has no seam: its suite at $rev cannot execute $binary, so a PASS would name a binary that never ran"
    status=1
    continue
  fi
  echo "RUNNING: $name @ $rev against Ferrox binary $binary via $seam"
  echo "  suite: $suite"
  # The named binary must exist in this workspace, or the PASS below names nothing.
  if ! cargo build --locked -q -p "$binary" 2>/dev/null; then
    echo "::error::$name: Ferrox binary $binary does not build in this workspace"
    status=1
    continue
  fi
  dir="$(mktemp -d)"
  if ! git clone --quiet --no-checkout "$repo" "$dir" 2>/dev/null; then
    echo "::error::$name: could not clone $repo"
    rm -rf "$dir"
    status=1
    continue
  fi
  if ! git -C "$dir" checkout --quiet "$rev" 2>/dev/null; then
    echo "::error::$name: rev $rev does not resolve"
    rm -rf "$dir"
    status=1
    continue
  fi
  # A declared seam is still only a claim until the pinned tree reads it, so
  # check the variable is actually referenced at that rev before injecting it.
  if ! git -C "$dir" grep -qI -e "$seam" -- . 2>/dev/null; then
    echo "::error::$name declares seam $seam but $rev never reads it: nothing would execute $binary"
    rm -rf "$dir"
    status=1
    continue
  fi
  # The suite reads the binary out of the environment, so the seam carries the
  # absolute path: the clone runs from a temp directory, and a relative path
  # there would name a different binary than the one just built.
  log="$(mktemp)"
  passed=0
  if (cd "$dir" && env "$seam=$workspace/target/debug/$binary" bash -c "$suite") 2>&1 | tee "$log"; then
    passed=1
  fi
  if ((passed == 0)); then
    echo "::error::$name suite failed at $rev"
    status=1
  elif libtest_ran_named "$suite" "$log"; then
    echo "PASS: $name suite green against $binary at $rev (injected via $seam)"
    ran=$((ran + 1))
  else
    echo "::error::$name suite exited 0 without running what its command names"
    status=1
  fi
  rm -rf "$dir" "$log"
done < <(parse_pins)

echo "upstream suites: $ran ran green against Ferrox binaries (the rest skipped with reasons above)"
exit "$status"
