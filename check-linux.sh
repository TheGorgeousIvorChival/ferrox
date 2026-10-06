#!/usr/bin/env bash
# The Linux leg of `cross-gate.sh`, kept as its own name because that is what
# `docs/methodology.md` calls the gate.
exec "$(cd "$(dirname "$0")" && pwd)/cross-gate.sh" x86_64-unknown-linux-gnu "$@"
