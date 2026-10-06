#!/usr/bin/env bash
# Fails on a benchmark script that names a built binary without the platform's suffix.
#
# `windows-latest` is a required leg of `benchmark-matrix.yml`, and on it every one
# of the standard tier's eleven cells died at gate 5 with:
#
#     gate 5 could not run: binary target/release/ferrox-app is not a file
#
# about a file that was there the whole time. The name was right on Linux and
# macOS and wrong only on Windows, which is why every other runner was green and
# the one leg that had never reported a throughput row stayed silent.
#
# The mechanism is MSYS, and it is a trap rather than a typo: a `stat` of `foo`
# answers with the contents of `foo.exe`, so `[[ -x foo ]]` **passes** for a name
# that does not exist under that name. The bare path therefore looks correct to
# every check on the platform that has the bug -- including a shellcheck, a
# `bash -n`, and the `[[ -x ]]` guard it is usually written behind. It is handed
# to `ferrox-bench`, a native Win32 process whose `Path::is_file` does no such
# lookup, and that is where it is found out.
#
# So the check is not "is the path spelled right" -- it cannot be, from a Unix
# shell on a Unix host. It is "is the name resolved by the one helper that knows
# the platform", which is `lib-engines.sh:built`. That helper asks for the
# suffixed spelling **first** and falls back to the bare one, which is the order
# that survives MSYS on the runner and is a no-op everywhere else.
#
# What fails the job: a literal `target/release/<crate>` in a benchmark script
# that is not on a line going through `built` or a `$(...)` around it. The
# resolution itself is `lib-engines.sh`'s and is exercised by `check.sh` on a
# simulated `OS=Windows_NT` tree.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

# The scripts that build binaries and hand their paths to a native process.
scripts=(
  scripts/run-benchmark-matrix.sh
  scripts/run-parity.sh
  scripts/run-live-speedtest.sh
)

# Lines that are *about* the path rather than *using* it: the prose that explains
# the trap, and the failure message that quotes the name. `grep -v` on a pattern
# rather than a shape test, because these are sentences and a sentence is not
# reliably distinguishable from code.
prose='^\s*#|"no executable|"[^"]*is not a file|\(\.exe\)'

for script in "${scripts[@]}"; do
  [[ -f "$script" ]] || continue
  # Every hit, with its line, so the failure names the line to change.
  while IFS=: read -r lineno text; do
    [[ -n "$lineno" ]] || continue
    # A line that resolves through `built`, directly or one call deep, is the
    # supported spelling.
    [[ "$text" == *'built '* ]] && continue
    # A variable assignment is not a use *provided the variable is resolved
    # somewhere*: the supported shape is `x="$(built y)"` and the two halves can
    # be on different lines. So the exemption is conditional, and the condition is
    # checked below -- an assignment that is never resolved is exactly the bug.
    is_assignment=0
    if [[ "$text" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)= ]]; then
      is_assignment=1
      assigned="${BASH_REMATCH[1]}"
    fi
    # A `-x`/`-f` test on a bare literal is the bug's own disguise: it passes on
    # the platform that has MSYS, which is why it survived every review of a
    # Linux-only diff. A test on a variable is fine, because that variable was
    # resolved by `built`.
    if ((is_assignment)) && [[ "$text" =~ [[:space:]]-[xf][[:space:]] ]]; then
      printf '::error file=%s,line=%s::a bare -x/-f probe passes on MSYS for a \
name that does not exist; resolve the path with `built` first: %s\n' \
        "$script" "$lineno" "$text" >&2
      status=1
      continue
    fi
    if ((is_assignment)); then
      # Resolved later? `built <name>` or `built "$<name>"` somewhere below.
      if grep -qE "built[[:space:]]+\"?\\\$\{?$assigned\b" "$script"; then
        continue
      fi
      printf '::error file=%s,line=%s::`%s` is assigned a bare target/release path \
and never passed through `built`; on windows-latest the name that reaches the \
native process is one MSYS can resolve and nothing else can: %s\n' \
        "$script" "$lineno" "$assigned" "$text" >&2
      status=1
      continue
    fi
    if [[ "$text" =~ $prose ]]; then continue; fi
    printf '::error file=%s,line=%s::binary path is not resolved through `built`; \
on windows-latest MSYS answers a stat of the bare name with the .exe, so this \
passes here and fails there: %s\n' \
      "$script" "$lineno" "$text" >&2
    status=1
  done < <(grep -nE 'target/release/[A-Za-z0-9_-]+' "$script" 2>/dev/null || true)
done

# The resolver has to work on a simulated Windows tree, or "use `built`" is an
# instruction with nothing behind it. Built into a temp dir so the check proves
# the suffix logic rather than this checkout's own binaries.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/target/release"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-app.exe"
chmod +x "$tmp/target/release/ferrox-app.exe"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-bench.exe"
chmod +x "$tmp/target/release/ferrox-bench.exe"

# `built` and `exe_suffix` come from lib-engines.sh, which is sourced rather than
# executed; only those two are needed and neither runs anything at source time.
exe_suffix() {
  case "${OS:-}" in
    Windows_NT) printf '.exe' ;;
    *) printf '' ;;
  esac
}
built() {
  if [[ -x "$1$(exe_suffix)" ]]; then
    printf '%s\n' "$1$(exe_suffix)"
  elif [[ -x "$1" ]]; then
    printf '%s\n' "$1"
  else
    return 1
  fi
}

cd "$tmp"
# Both spellings exist in the fixture, because the resolver's whole contract is
# which one it prefers: suffixed first, bare as the fallback. Testing only the
# `.exe` case would pass a `built` that ignored the platform entirely.
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-app"
chmod +x "$tmp/target/release/ferrox-app"
printf '#!/bin/sh\nexit 0\n' >"$tmp/target/release/ferrox-bench"
chmod +x "$tmp/target/release/ferrox-bench"

for os in Windows_NT Linux; do
  for crate in ferrox-app ferrox-bench; do
    got="$(OS=$os built "target/release/$crate")" || {
      printf '::error::built could not resolve target/release/%s under OS=%s\n' \
        "$crate" "$os" >&2
      status=1
      continue
    }
    want_suffix=''
    [[ "$os" == Windows_NT ]] && want_suffix='.exe'
    if [[ "$got" != "target/release/$crate$want_suffix" ]]; then
      printf '::error::under OS=%s, built answered %s for target/release/%s; \
expected the %s spelling\n' "$os" "$got" "$crate" "${want_suffix:-bare}" >&2
      status=1
    fi
  done
done

if ((status)); then
  echo "windows binary-path check failed" >&2
  exit 1
fi
echo "windows binary paths: resolved through built on both platforms"