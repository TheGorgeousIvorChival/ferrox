#!/usr/bin/env bash
# The benchmark matrix: every scenario in docs/benchmarks/matrix.md that the
# harness can run, against five pinned engines, with repeats.
#
# One invocation measures one tier and writes one directory: per-cell
# `<scenario>.json` comparison documents (from `ferrox-bench
# --json-report`), per-repeat `result.json` files beside them, plus
# `manifest.txt` (versions, digests, host, replay command) and `commands.sh`.
# `scripts/render-benchmark-charts.py` plots the directory;
# `scripts/validate-benchmark-matrix.py` re-derives it. Neither lives here, so
# a plotting bug cannot move a number and a measurement bug cannot move a plot.
#
# Topology per cell is a self-relay: each engine serves a protocol inbound and
# dials it through its own outbound to the harness echo sink, with the harness
# SOCKS inbound injected on top. Routing sends `harness-socks` to the protocol
# outbound and everything else to `freedom`; without both rules an engine whose
# default route is its first outbound would dial itself forever.
#
# Usage: run-benchmark-matrix.sh [--tier smoke|standard|full] [--out DIR]
#          [--engines a,b,...] [--repeats N] [--bench-bin PATH]
#          [--only SUB] [--exclude SUB] [--probe-only]
#   --engines names sources from upstream/pins.toml: ferrox is this
#     workspace's binary; the rest are built from their pins when missing.
#     A source may be replaced with a path (xray-core=/bin/xray), same as
#     run-parity.sh. Default: tier smoke runs ferrox,xray-core, the rest run
#     all five.
#   --only/--exclude filter scenario ids by substring, repeatable: `--only
#     vless-raw-tls` narrows a run to one connection type, the fast way to see
#     whether a change moved it (mirrors the pinned harnesses' `--only`).
#   --probe-only writes every engine config and lists the cells without moving
#     traffic: the fast answer to "would this scenario even start here".
set -euo pipefail

cd "$(dirname "$0")/.."

tier="standard"
out="target/benchmark-matrix"
engines_list=""
repeats=""
bench_bin="target/release/ferrox-bench"
only=()
exclude=()
probe_only=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --engines) engines_list="$2"; shift 2 ;;
    --repeats) repeats="$2"; shift 2 ;;
    --bench-bin) bench_bin="$2"; shift 2 ;;
    --only) only+=("$2"); shift 2 ;;
    --exclude) exclude+=("$2"); shift 2 ;;
    --probe-only) probe_only=1; shift ;;
    *) echo "::error::unknown argument $1" >&2; exit 2 ;;
  esac
done
case "$tier" in
  smoke | standard | full) ;;
  *) echo "::error::--tier needs smoke, standard or full, got $tier" >&2; exit 2 ;;
esac

pins_file="upstream/pins.toml"
engine_dir="target/parity-engines"
source "$(dirname "$0")/lib-engines.sh"
source "$(dirname "$0")/lib-matrix.sh"

main() {
mkdir -p "$out" "$engine_dir" "$out/cells"
[[ -f "$pins_file" ]] || fail "$pins_file is missing; refusing to guess a comparator"

# --- engines ---------------------------------------------------------------

if [[ -z "$engines_list" ]]; then
  if [[ "$tier" == "smoke" ]]; then
    engines_list="ferrox,xray-core"
  else
    engines_list="ferrox,xray-core,zeronet,sing-box,xray-rust"
  fi
fi
if [[ -z "$repeats" ]]; then
  if [[ "$tier" == "full" ]]; then repeats=5; else repeats=3; fi
fi

note "building the harness driver"
cargo build --locked --release -p ferrox-bench -p ferrox-app 2>&1 | tail -2 >&2
# Both resolved with `built`, not probed bare. MSYS answers a stat of `foo` with the
# contents of `foo.exe`, so `[[ -x foo ]]` passes on Windows for a name that does not
# exist under that name -- and the engine path is then handed to `ferrox-bench`, a
# native Win32 process, whose `Path::is_file` does no such lookup. Every cell on
# `windows-latest` died at gate 5 with `binary target/release/ferrox-app is not
# a file` about a file that was there the whole time. `run-parity.sh` resolves both the
# same way, which is why parity runs there and this did not. `lib-engines.sh:built`.
bench_bin="$(built "$bench_bin")" || fail \
  "no executable at $bench_bin(.exe) after the build above"
ferrox_bin="$(built target/release/ferrox-app)" || fail \
  "no executable at target/release/ferrox-app(.exe) after the build above"

# name=path lines; reference order is imposed below, not here.
engine_list="${engines_list//,/ }"
built=()
skipped=()
for entry in $engine_list; do
  label="${entry%%=*}"
  source="${entry#*=}"
  [[ "$label" != "$entry" ]] || label="$source"
  if [[ "$label" == "ferrox" ]]; then
    # Resolved once, above, and reused here: this is the path handed to
    # `ferrox-bench` and the one whose spelling has to survive MSYS.
    path="$ferrox_bin"
  elif [[ "$source" == /* ]]; then
    path="$source"
  else
    path="$(build "$source" 2>/dev/null)" || {
      skipped+=("$label (could not be built from its pin on this host)")
      continue
    }
  fi
  [[ -x "$path" ]] || {
    skipped+=("$label ($path is not executable)")
    continue
  }
  built+=("$label=$path")
done
# The reference is always first: every ratio in every cell reads against it,
# and the harness names the first engine the reference. Ordering the display
# list alone once shipped ferrox first and gated nothing; the argument list
# below is built from this order, not the other way round.
ordered=()
# `${arr[@]+"${arr[@]}"}` rather than `"${arr[@]}"`: the unguarded form on an
# empty array is an unbound variable under `set -u` on bash 3.2, which is what
# macos runners ship — and an empty engine list there must read as "no
# reference", not as a shell error.
for want in xray-core ferrox zeronet sing-box xray-rust; do
  for have in ${built[@]+"${built[@]}"}; do
    [[ "${have%%=*}" == "$want" ]] && ordered+=("$have")
  done
done
for have in ${built[@]+"${built[@]}"}; do
  seen=0
  for want in ${ordered[@]+"${ordered[@]}"}; do [[ "$want" == "$have" ]] && seen=1; done
  [[ "$seen" == "0" ]] && ordered+=("$have")
done
engines=(${ordered[@]+"${ordered[@]}"})
engine_args=()
for have in "${engines[@]}"; do
  label="${have%%=*}"
  engine_args+=(--engine "$have")
  shape="$(config_arg_for "$label")"
  [[ "$shape" == "long" ]] || engine_args+=(--config-arg "$label=$shape")
  # The binary defaults every engine to the Xray spelling; sing-box must be
  # named or it gets Xray-dialect documents it cannot parse.
  if [[ "$label" == "sing-box" ]]; then
    engine_args+=(--dialect "$label=sing-box")
  fi
done
[[ "${engines[0]%%=*}" == "xray-core" ]] || fail "no xray-core reference: a comparison without one is not a comparison"
ferrox_present=0
for have in "${engines[@]}"; do [[ "${have%%=*}" == "ferrox" ]] && ferrox_present=1; done
[[ "$ferrox_present" == "1" ]] || fail "no ferrox engine: the matrix gates nothing without it"

# --- run -------------------------------------------------------------------

manifest() {
  {
    echo "tier: $tier"
    echo "date: $(date -u +%F)"
    echo "runner: $(runner_slug)"
    echo "host: $(uname -a)"
    echo "cpu: $(cpu_model)"
    echo "memory: $(memory_total)"
    echo "load: $(load_average)"
    echo "rustc: $(rustc -vV | tr '\n' ' ')"
    echo "go: $(go version 2>/dev/null || echo 'no go toolchain')"
    echo "repeats: $repeats"
    ((${#only[@]})) && echo "only: ${only[*]}"
    ((${#exclude[@]})) && echo "exclude: ${exclude[*]}"
    ((probe_only)) && echo "probe-only: true"
    for have in "${engines[@]}"; do
      label="${have%%=*}"
      echo "engine $label: ${have#*=} sha256=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "${have#*=}") mib=$(python3 -c 'import os,sys;print(f"{os.path.getsize(sys.argv[1]) / 1048576:.1f}")' "${have#*=}")"
    done
    for pin in xray-core sing-box zeronet xray-rust; do
      echo "pin $pin: $(pin_of "$pin")"
    done
  } >"$out/manifest.txt"
}

# Stable per-runner directory name, so three runners' bundles combine without
# colliding and the README can show one section per runner. Derived from the
# kernel, never from a workflow input: a label passed by the caller is a second
# thing to keep in step with the machine that actually measured.
runner_slug() {
  local sys machine
  sys="$(uname -s)"
  machine="$(uname -m)"
  case "$sys" in
    Linux) sys="linux" ;;
    Darwin) sys="macos" ;;
    *) sys="unknown" ;;
  esac
  case "$machine" in
    x86_64 | amd64) machine="x86_64" ;;
    arm64 | aarch64) machine="aarch64" ;;
  esac
  echo "$sys-$machine"
}

# One line of /proc or sysctl, or the honest admission that it is unavailable.
cpu_model() {
  if [[ -f /proc/cpuinfo ]]; then
    grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | xargs || echo "unknown"
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

memory_total() {
  if [[ -f /proc/meminfo ]]; then
    grep -m1 MemTotal /proc/meminfo | awk '{print $2 " " $3}'
  elif command -v sysctl >/dev/null 2>&1; then
    echo "$((($(sysctl -n hw.memsize 2>/dev/null || echo 0) + 512) / 1048576)) MiB"
  else
    echo "unknown"
  fi
}

load_average() {
  if [[ -f /proc/loadavg ]]; then
    cut -d' ' -f1-3 /proc/loadavg
  elif command -v sysctl >/dev/null 2>&1; then
    sysctl -n vm.loadavg 2>/dev/null || echo "unknown"
  else
    echo "unknown"
  fi
}

status=0
cells_run=0
cells_failed=()

manifest
{
  echo "# Replay: tier $tier on $(date -u +%FT%TZ)"
  echo "# engines: ${engines[*]}"
  ((${#only[@]})) && echo "# only: ${only[*]}"
  ((${#exclude[@]})) && echo "# exclude: ${exclude[*]}"
  ((probe_only)) && echo "# probe-only: configs written, no traffic moved"
} >"$out/commands.sh"

# A scenario the filters keep, with the reason when they do not: a run that
# silently measured a subset would read as the whole matrix.
scenario_kept() {
  local id="$1" pattern
  for pattern in ${only[@]+"${only[@]}"}; do
    [[ "$id" == *"$pattern"* ]] || return 1
  done
  for pattern in ${exclude[@]+"${exclude[@]}"}; do
    [[ "$id" == *"$pattern"* ]] && return 1
  done
  return 0
}

while read -r id traffic connections iterations payload; do
  [[ -n "$id" ]] || continue
  if ! scenario_kept "$id"; then
    echo "# $id: skipped by --only/--exclude" >>"$out/commands.sh"
    continue
  fi
  note "cell $id ($traffic $connections flows)"
  # A fresh port per cell: see `matrix_srvport` in `lib-matrix.sh` for why a fixed
  # one cost this run real measurements rather than a style point.
  srvport="$(matrix_srvport)" || {
    cells_failed+=("$id (could not allocate a server port)")
    status=1
    continue
  }
  config="$(scenario_config "$id" "$srvport")" || {
    cells_failed+=("$id (unknown scenario)")
    status=1
    continue
  }
  celldir="$out/cells/$id"
  rm -rf "$celldir"
  mkdir -p "$celldir"
  echo "$config" >"$celldir/engine-config.json"
  if ((probe_only)); then
    cells_run=$((cells_run + 1))
    {
      echo "# $id: $traffic $connections flows, $iterations x $payload B, $repeats repeats (probe only)"
      echo "# config: cells/$id/engine-config.json"
    } >>"$out/commands.sh"
    continue
  fi
  if "$bench_bin" "${engine_args[@]}" \
    --traffic "$traffic" --connections "$connections" \
    --iterations "$iterations" --payload-size "$payload" \
    --repeats "$repeats" \
    --outbound-config "$config" \
    --output-dir "$celldir/runs" \
    --scenario "$id" \
    --json-report "$celldir/cell.json" >>"$celldir/stdout.log" 2>&1; then
    cells_run=$((cells_run + 1))
  else
    cells_failed+=("$id (exit $?)")
    status=1
  fi
  {
    echo "# $id: $traffic $connections flows, $iterations x $payload B, $repeats repeats"
    echo "# server port: $srvport (allocated per cell; see lib-matrix.sh)"
    echo "# config: cells/$id/engine-config.json ; report: cells/$id/cell.json"
  } >>"$out/commands.sh"
done < <(scenarios "$tier")

{
  echo "cells run: $cells_run"
  echo "cells failed: ${#cells_failed[@]}"
  for f in "${cells_failed[@]+"${cells_failed[@]}"}"; do echo "failed: $f"; done
  for s in "${skipped[@]+"${skipped[@]}"}"; do echo "skipped engine: $s"; done
} | tee "$out/summary.txt" >&2
return "$status"
}

# Sourced for its scenario and config functions without running anything;
# executed directly, it measures.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit "$?"
fi
