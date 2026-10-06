#!/usr/bin/env bash
# The Windows leg of `cross-gate.sh`.
exec "$(cd "$(dirname "$0")" && pwd)/cross-gate.sh" x86_64-pc-windows-msvc "$@"
