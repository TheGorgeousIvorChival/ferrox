#!/usr/bin/env bash
# Everything CI checks that a laptop can check, in the order that fails fastest.
#
# This is the answer to "why is the queue so long": nothing in here needs a
# named runner, so finding a lint here costs seconds instead of the minutes a
# commit waits behind someone else's four-runner matrix. `ci.yml` then proves the
# same commands on runners whose architecture is stated.
#
# The two things it deliberately does not run are the ones a local machine cannot
# answer: a timing gate needs a runner nobody else is on, and a conformance run
# needs the upstream toolchains. Both are dispatched when a slice asks for them.
set -euo pipefail

cd "$(dirname "$0")/.."

# The same cfgs `ci.yml` uses, so the aarch64 hardware path is what compiles here.
export RUSTFLAGS="${RUSTFLAGS:--D warnings --cfg aes_armv8 --cfg polyval_armv8}"

step() { printf '\n=== %s ===\n' "$1"; }

step "fmt"
cargo fmt --all -- --check

step "clippy"
# `clippy::perf` and `clippy::suspicious` advise without failing, matching ci.yml:
# an advisory lint that cries wolf gets deleted and then advises nothing.
cargo clippy --workspace --all-targets --locked -- -D warnings -W clippy::perf -W clippy::suspicious

step "doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --no-deps

step "leak surface"
./scripts/check-leak-surface.sh

step "dependency policy"
./scripts/check-dependency-policy.sh

step "comment trace"
./scripts/check-comments.sh

step "fixture safety"
./scripts/check-fixture-safety.sh

step "windows binary paths"
./scripts/check-windows-binary-paths.sh

step "prompt library"
cargo run --locked --quiet -p ferrox-prompt -- check

step "tests"
cargo test --workspace --locked

printf '\nall local checks green\n'