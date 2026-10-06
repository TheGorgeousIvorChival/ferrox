#!/usr/bin/env bash
# Gate 5: build every engine from its pin and run the process-level comparison.
#
# Why a script and not a step in the workflow: each comparator has to be built from
# its pin, on every ISA the claim covers, and a workflow that grows a `go build`
# line per runner is a workflow where one runner ends up measuring a different
# binary from the others. The pins live in upstream/pins.toml and the builds are
# here, so the two cannot drift.
#
# Xray-core is MPL-2.0 and ZeroNet is MIT: both are built from their pins and never
# copied into this tree, exactly as the conformance suites are run.
#
# An engine that cannot be built on this host is **skipped with its reason**, never
# silently dropped. A comparison that quietly measures three cores because the
# fourth would not compile reads as "the fourth is equal"; a row that says why it is
# missing is the honest one, and `docs/methodology.md` carries the same rule.
#
# Env:
#   ENGINES         space-separated label=source, comma-separated for the source:
#                     xray-core, zeronet, sing-box, xray-rust. Default: the first
#                     three (all buildable from a stock toolchain).
#                   A source may be replaced with a path, e.g. `xray-core=/bin/xray`,
#                   for a host where the pin cannot be built.
#   REPEATS         paired repeats per engine (default 5)
#   ITERATIONS      payload iterations per flow (default 131072, i.e. 8 GiB)
#   PAYLOAD_SIZE    bytes per iteration (default 65536)
#   CONNECTIONS     concurrent flows (default 1)
#   TRAFFIC         upload | download | full-duplex (default download)
set -euo pipefail

cd "$(dirname "$0")/.."

pins_file="upstream/pins.toml"
# Two directories on purpose: engines are built once and reused across runs, while
# every run writes its own directories that the request validator requires not to
# exist yet. Sharing one would make the second run fail on the first run's leftovers.
engine_dir="target/parity-engines"
out_dir="target/parity"
mkdir -p "$engine_dir" "$out_dir"

# The per-run half starts empty, and it has to: `target/` is inside the
# `Swatinem/rust-cache` cache, so a cache hit restores the *previous* run's
# `<engine>-run<N>` directories into a runner that has never run this script, and
# the request validator — correctly — refuses to read a stale directory as this
# run's result. That is not a theory: `parity.yml` failed with `gate 5 could not
# run: output target/parity/xray-core-run1 already exists` on `linux x86_64` and
# `macos aarch64` for every run since gate 5 landed, while `linux aarch64` — the
# one runner that missed the cache — measured normally. `engine_dir` is left alone
# on purpose: a cached comparator binary is the whole reason the cache is worth
# having here, and nothing reads it as a measurement.
rm -rf "${out_dir:?}"/*

note() { echo "note: $*" >&2; }
fail() { echo "::error::$*" >&2; exit 1; }

[[ -f "$pins_file" ]] || fail "$pins_file is missing; refusing to guess a comparator"

# The pinned commit for one source, read from upstream/pins.toml. Parsed rather than
# hardcoded so this script cannot build a different revision than the one the pins
# check verified.
pin_of() {
  awk -v want="$1" '
    /^\[sources\./ { in_source = ($0 == "[sources." want "]") }
    in_source && /^rev[[:space:]]*=/ {
      gsub(/^rev[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
      print; exit
    }
  ' "$pins_file"
}

# Verify a checkout is at its pin. A drifted checkout is worse than none: it is a
# comparison against a revision nobody wrote down.
verify_checkout() {
  local name="$1" rev
  rev="$(pin_of "$name")"
  [[ -n "$rev" ]] || fail "no rev for $name in $pins_file"
  [[ -d "upstream/$name/.git" ]] || fail "upstream/$name is missing; run scripts/fetch-upstream.sh"
  local have
  have="$(git -C "upstream/$name" rev-parse HEAD)"
  [[ "$have" == "$rev" ]] || fail "upstream/$name is at $have, not the pinned $rev"
}

# The suffix this host's toolchain gives a built binary, for the paths *this* script
# chooses rather than the ones it goes looking for.
#
# A question about the platform, and true before anything is built. A `cp` to a name
# built from the answer is how a `zray.exe` becomes a `zeronet` that the loader will
# not run.
exe_suffix() {
  case "${OS:-}" in
    Windows_NT) printf '.exe' ;;
    *) printf '' ;;
  esac
}

# Where a built binary actually is on this host, printed; nothing and a failure if
# it is nowhere.
#
# The suffixed name is asked for *first*, and that order is the whole function. MSYS
# resolves `foo` to `foo.exe` for `stat` and for `exec`, so on `windows-latest` a probe
# of the bare name succeeds against a file that does not exist under that name -- and
# the name it hands back is then one only MSYS can resolve. `ferrox-bench` is a
# native Win32 process, `Path::is_file` does not do that lookup, and gate 5 stopped
# with `binary target/release/ferrox-app is not a file` about a file that was
# there the whole time, one directory entry away from where it said it was not.
#
# So the platform decides the name and the other spelling is the fallback. On Linux
# and macOS `exe_suffix` is empty and both probes are the same path, so this is the
# two-line resolver it was before.
built() {
  if [[ -x "$1$(exe_suffix)" ]]; then
    printf '%s\n' "$1$(exe_suffix)"
  elif [[ -x "$1" ]]; then
    printf '%s\n' "$1"
  else
    return 1
  fi
}

# Build one engine, or print the reason it cannot be built here.
#
# Every function here prints progress on stderr and the binary path on stdout, or
# nothing on stdout and the reason on stderr: they are called in a command
# substitution, so a progress line on stdout would be captured as part of the path.
build() {
  local name="$1" rev binary cached
  rev="$(pin_of "$name")"
  binary="$engine_dir/$name$(exe_suffix)"
  if cached="$(built "$binary")"; then
    echo "$cached"
    return 0
  fi
  verify_checkout "$name"
  case "$name" in
    xray-core)
      note "building the pinned Xray-core at $rev"
      # CGO off and the Go environment neutralised: no C toolchain to depend on, and
      # the CPU figures are then the binary's own.
      (cd "upstream/$name" && GOENV=off GOWORK=off CGO_ENABLED=0 \
        go build -o "$OLDPWD/$binary" ./main) || return 1
      ;;
    sing-box)
      note "building the pinned sing-box at $rev"
      (cd "upstream/$name" && GOENV=off GOWORK=off CGO_ENABLED=0 \
        go build -tags "with_utls" -o "$OLDPWD/$binary" ./cmd/sing-box) || return 1
      ;;
    zeronet)
      note "building the pinned ZeroNet (zray) at $rev"
      # Its own target directory, so a build here cannot disturb the checkout's
      # state and a `cargo clean` in one does not empty the other.
      (cd "upstream/$name" && cargo build --release -p zray-cli --bin zray) || return 1
      local zray
      zray="$(built "upstream/$name/target/release/zray")" || return 1
      cp "$zray" "$binary" || return 1
      ;;
    xray-rust)
      note "building the pinned xray-rust at $rev (long: aws-lc-rs, quinn, prost)"
      (cd "upstream/$name" && CARGO_TARGET_DIR="$OLDPWD/$engine_dir/xray-rust-target" \
        cargo build --release -p xray-cli --bin xray-rust) || return 1
      local rust_cli
      rust_cli="$(built "$engine_dir/xray-rust-target/release/xray-rust")" || return 1
      cp "$rust_cli" "$binary" || return 1
      ;;
    *)
      fail "unknown engine source `$name`"
      ;;
  esac
  built "$binary"
}

# How each engine is told which config file to serve. They genuinely disagree:
# `run -config <path>`, `run -c <path>`, and `run <path>` respectively. See
# `parity::ConfigArg`, which is the same distinction as a Rust enum.
config_arg_for() {
  case "$1" in
    sing-box) echo short ;;
    zeronet) echo positional ;;
    *) echo long ;;
  esac
}

# The config language each engine parses. This is not the same question as which
# flag names the file, and getting it wrong is invisible: `sing-box` was handed the
# Xray spelling on every repeat of every run and answered `outbounds[0]: unknown
# outbound type: ` each time, which the report then published as `unproven` -- five
# empty rows per run, for as long as the comparison has existed. `sing-box` reads
# `type` where Xray reads `protocol`, and `listen_port` where Xray reads `port`
# (its legacy `port` is *rejected* since 1.13.0).
dialect_for() {
  case "$1" in
    sing-box) echo sing-box ;;
    *) echo xray ;;
  esac
}

engines=()
engine_args=()
config_shapes=()
skipped=()

# Commas and spaces both separate entries, so `ENGINES=a,b` and `ENGINES="a b"` are
# the same list. Shell word splitting alone would treat the whole comma-separated
# string as one name and then fail to build anything.
engine_list="${ENGINES:-xray-core,zeronet,sing-box}"
engine_list="${engine_list//,/ }"

for entry in $engine_list; do
  label="${entry%%=*}"
  source="${entry#*=}"
  [[ "$label" != "$entry" ]] || label="$source"

  if [[ "$source" == /* ]]; then
    path="$source"
  else
    path="$(build "$source" 2>/dev/null)" || {
      skipped+=("$label (could not be built from its pin on this host; see the log above)")
      continue
    }
  fi
  [[ -x "$path" ]] || { skipped+=("$label ($path is not executable)"); continue; }

  engines+=("$label=$path")
  engine_args+=(--engine "$label=$path")
  shape="$(config_arg_for "$source")"
  [[ "$shape" == "long" ]] || { engine_args+=(--config-arg "$label=$shape"); config_shapes+=("$shape"); }
  # Passed for every engine rather than only the ones that differ, so the report
  # names the dialect beside every row instead of leaving it to be inferred from
  # which engines are present.
  engine_args+=(--dialect "$label=$(dialect_for "$source")")
done

# This workspace's own binary is always measured; it is what the gate is about.
ferrox_path="$(built target/release/ferrox-app)" || fail \
  "no executable at target/release/ferrox-app(.exe); cargo build --locked --release -p ferrox-app"
engines+=("ferrox=$ferrox_path")
engine_args+=(--engine "ferrox=$ferrox_path")
engine_args+=(--dialect "ferrox=xray")

for entry in "${engines[@]}"; do
  path="${entry#*=}"
  built "$path" >/dev/null || fail "$path is not an executable; cargo build --release -p ferrox-app"
done

# The relay's splice pipe capacity, passed through to the engine rather than
# compiled in, because it is a number a measurement has to be able to move. See
# `proxy.rs`'s `SPLICE_PIPE_BYTES` and `docs/methodology.md`'s account of why the
# default is what it is.
if [[ -n "${SPLICE_PIPE:-}" ]]; then
  export FERROX_SPLICE_PIPE_BYTES="$SPLICE_PIPE"
  echo "note: relay splice pipe capacity overridden to ${SPLICE_PIPE} B" >&2
fi

# A blank dispatch input arrives as an empty string, which `${VAR:-default}` treats
# as unset and so takes the default -- but only if the default is written after the
# `:-`. These are written that way, and the `[[ -n ]]` line is here because an empty
# value is *set*, and `set -u` is on.
# The workflow's `timeout-minutes` and the harness's per-run cap, for the budget check
# below. Both are duplicated from `parity.yml` and `parity.rs` on purpose: a budget
# that read its own ceiling from the file that sets it could not refuse anything,
# because the file it reads is the one that would have to be wrong.
RUN_TIMEOUT_CAP=120
# A third of the slowest engine figure any run in docs/methodology.md records --
# zeronet at ~1.4 GiB/s -- so this floor refuses what cannot finish with margin rather
# than what is merely large.
#
# The margin was walked into in both directions. At a *tenth* of that figure this
# floor refused `connections=16 iterations=16384`, which is 16 GiB a repeat and has
# been measured at ~1.07 GiB/s -- inside the cap, and a run that works. A guard that
# refuses a request someone has already run successfully is worse than no guard, because
# it reads as the tool objecting rather than the tool being wrong.
FLOOR_MIB_S=500

for var in REPEATS CONNECTIONS TRAFFIC ITERATIONS; do
  if [[ -z "${!var:-}" ]]; then
    unset "$var"
  fi
done
repeats="${REPEATS:-5}"
iterations="${ITERATIONS:-131072}"
payload_size="${PAYLOAD_SIZE:-65536}"
connections="${CONNECTIONS:-1}"
traffic="${TRAFFIC:-download}"

# Why 8 GiB and not 1, in the two numbers that decide it.
#
# The CPU row is a delta over the transfer window against a 10 ms floor, so a row
# can only resolve a 5% difference when the window's CPU clears about 200 ms. At
# the ~70 ms/GiB a splicing relay costs, that is 3 GiB; 8 GiB leaves the CPU row
# with ~1.8% of quantisation error instead of 14% and ~60 ms instead of ~560 ms.
#
# Throughput is the same argument from the other side. A shared CI runner loses
# the CPU to a co-tenant for tens of milliseconds at a time; over a 0.25 s window
# that is a third of the measurement, which is the 2.7x spread
# `docs/methodology.md` records across eight runs of one unchanged tree. Over 8 GiB
# the same episode is about 2%. Nothing about the engine changed between those two
# -- only how long it was watched for, which is the difference between a gate that
# can see a 5% regression and one that reports the weather.
# One *flow* against the pinned schema's ceiling, which is what `parity.rs`'s
# `MAX_FLOW_BYTES` enforces. Per flow and not per run, because that is the unit the
# ceiling is written in: the pinned schema reaches 16 GiB by raising `connections`,
# so a run's total is allowed to exceed it and this must not read otherwise.
if (( iterations * payload_size > 16 * 1024 * 1024 * 1024 )); then
  fail "gate 5: one flow of $iterations x $payload_size B is \
$(( iterations * payload_size / 1024 / 1024 / 1024 )) GiB, above the 16 GiB ceiling \
one flow is allowed; a transfer that cannot finish inside the harness's \
${RUN_TIMEOUT_CAP}s cap would be reported as a truncated transfer"
fi

# The whole workload against the harness's own per-run cap, at a rate no measurement
# has come near.
#
# `connections * iterations * payload_size` is what one repeat of one engine has to
# move, and `RUN_TIMEOUT` is what the harness allows it. The floor is
# [`FLOOR_MIB_S`] above -- 500 MiB/s, a third of the slowest engine figure any run in
# `docs/methodology.md` records -- so the refusal fires only on a request that cannot
# finish inside the cap.
#
# Naming the constant rather than repeating its value is the whole point of this
# paragraph: it read "100 MiB/s, a tenth of the slowest engine figure" for one commit
# after `FLOOR_MIB_S` was raised from 100 to 500, because the edit that raised it had
# matched an escaped-backtick comment and changed nothing, and this paragraph was never
# in the diff. A guard whose comment quotes a number the guard does not use is a guard
# with two sources of truth, and the one that loses is the one nobody runs.
#
# A floor that needs a *rate* is the wrong shape, and this one still does not: every
# rate is a judgement about a runner that moves. What it buys is that the judgement is
# made once, above, next to the number, instead of once per guard. The failure this
# guards against was `repeats=7 connections=16` -- 3.5 TiB -- spending an hour of a
# runner and dying at the upload step with `No files were found`, which is a true report
# of a true failure and a useless place to learn it from. A certain floor catches that
# in the first second and says what to lower.
per_repeat_bytes=$(( connections * iterations * payload_size ))
if (( per_repeat_bytes / 1024 / 1024 > RUN_TIMEOUT_CAP * FLOOR_MIB_S )); then
  fail "gate 5: $connections flows x $iterations x $payload_size B is \
$(( per_repeat_bytes / 1024 / 1024 / 1024 )) GiB for one repeat of one engine, which \
cannot finish inside the harness's ${RUN_TIMEOUT_CAP}s cap even at ${FLOOR_MIB_S} \
MiB/s. Lower --iterations, or --connections, or both."
fi

engines_n=${#engines[@]}
# Printed on every run, because the size of the request is the first thing to check
# when two runs of the same tree disagree and the last thing a reader can see.
echo "note: $(( per_repeat_bytes / 1024 / 1024 / 1024 )) GiB per repeat per engine, \
x $engines_n engines x $repeats repeats, plus $repeats ceiling runs" >&2

echo "gate 5: ${#engines[@]} engines x $repeats paired repeats, $traffic, \
$connections x $iterations x $payload_size B \
($(( connections * iterations * payload_size / (1024 * 1024) )) MiB per flow)" >&2
for note_line in "${skipped[@]+"${skipped[@]}"}"; do
  echo "skipped: $note_line" >&2
done

bench_bin="$(built target/release/ferrox-bench)" || fail \
  "no executable at target/release/ferrox-bench(.exe); cargo build --locked --release -p ferrox-bench"

set +e
"$bench_bin" \
  "${engine_args[@]}" \
  --repeats "$repeats" \
  --iterations "$iterations" \
  --payload-size "$payload_size" \
  --connections "$connections" \
  --traffic "$traffic"
exit "$?"
