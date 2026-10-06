#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export RUSTFLAGS="${RUSTFLAGS:--D warnings --cfg aes_armv8 --cfg polyval_armv8}"

step() { printf '\n=== %s ===\n' "$1"; }

step "fmt"
cargo fmt --all -- --check

step "clippy"
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

step "tests"
cargo test --workspace --locked

printf '\nall local checks green\n'