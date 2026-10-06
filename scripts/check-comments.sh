#!/usr/bin/env bash
# Fails on comment traces; reports comment weight.
#
# Fixes leave no trace: no TODO, FIXME, XXX or HACK markers anywhere they would
# outlive the diff, and no `/* */` blocks (docs are `///` and `//!`, one line
# per item at most). A marker is how a fix advertises itself instead of being
# one; the roadmap lives in `prompts.md`, not in the code.
#
# Long `//` runs are reported, not failed: the tree predates the one-line rule,
# and a gate that fails on every file it ever passes gets deleted the first
# time it is wrong. Watch the count go down instead.
#
# `git grep` sees tracked files only, so the untracked reading copies under
# `upstream/` can carry whatever their authors wrote.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

# One pattern for every marker search below: a bare word, except `XXX` which
# must not be part of a longer `X` run, so a six-`X` `mktemp` template passes
# while a real marker still fails (`\b` is not it: git grep's engine ignores it).
markers='TODO|FIXME|HACK|(^|[^A-Za-z0-9_])XXX([^A-Za-z0-9_]|$)'

# Self-test, every run: the pattern must let the template through and still
# catch a bare marker, or this gate proves nothing. Plain POSIX `grep`, same
# pattern the `git grep` below runs; fixtures live in a temp dir, never in git.
selftest="$(mktemp -d)"
printf '%s\n' 'tmp="$(mktemp -d prefix.XXXXXX)"' > "$selftest/template.sh"
printf '%s\n' '// TODO: trace left behind' '// XXX: trace left behind' > "$selftest/marker.rs"
if grep -E -q "$markers" "$selftest/template.sh"; then
  echo "::error::self-test: the marker grep flags an mktemp template"
  status=1
fi
if ! grep -E -q "$markers" "$selftest/marker.rs"; then
  echo "::error::self-test: the marker grep misses a real marker"
  status=1
fi
rm -rf "$selftest"

# This file names the markers it searches for, so it excludes itself: without
# the exclusion the grep below matches its own prose and the gate never passes.
if git grep -I -n -E "$markers" -- '*.rs' 'scripts/*' '.github/**/*' ':!crates/ferrox-prompt/prompts.md' ':!scripts/check-comments.sh'; then
  echo "::error::trace markers do not land in this tree; the roadmap lives in prompts.md"
  status=1
fi

if git grep -I -n -E '^[[:space:]]*/\*' -- '*.rs'; then
  echo "::error::no /* */ blocks; docs are /// and //!, one line per item at most"
  status=1
fi

# Advisory: the longest `//` run per file. Doc comments (`///`, `//!`) and
# shell `#` headers are not counted; only inline explanation runs.
git ls-files '*.rs' | while IFS= read -r file; do
  longest="$(awk '/^[[:space:]]*\/\/[^!\/]/ {n++; if (n>m) m=n} !/^[[:space:]]*\/\/[^!\/]/ {n=0} END {print m+0}' "$file")"
  if [[ "$longest" -gt 1 ]]; then
    echo "note: $file longest // run is $longest line(s)"
  fi
done

exit "$status"
