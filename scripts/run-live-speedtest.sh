#!/usr/bin/env bash
# Live speedtest: dial real share-links with every core, download one static
# file through each, report who moved it fastest.
#
# One config at a time, one core at a time, sequentially: the path and the
# server are shared, so parallel cores would measure each other's load, and a
# free server hammered by five simultaneous multi-gigabyte downloads is how a
# benchmark becomes a denial of service. The comparison that survives is
# within one config on one runner: same server, same path, same hour.
#
# What is measured per attempt: SOCKS up (or the stage that failed),
# time-to-first-byte, sustained throughput over the transfer window (total
# minus first byte, so setup is excluded the same way the matrix excludes
# it), CPU milliseconds per GiB from /proc deltas, peak RSS from VmHWM, and
# the SHA-256 of the bytes when an expected hash was given.
#
# Secrets: links live in variables and files, never in output. The engine
# configs necessarily contain the UUID and keys (a config without them
# authenticates nothing); they stay under $out/configs/ and are never
# uploaded, never rendered, never echoed. `validate-live-speedtest.py` scans
# every other artefact for the credential substrings and fails on any of
# them. A raw `echo` of a link anywhere in this file is a bug.
#
# Linux only: CPU comes from /proc/<pid>/stat and peak RSS from VmHWM, the
# same mechanism the matrix sampler reads. A run anywhere else would publish
# zeros as measurements.
#
# Usage: run-live-speedtest.sh --configs-file PATH --target-url URL
#          [--target-sha256 HEX] [--repeats N] [--cores a,b,...]
#          [--out DIR] [--bench-bin PATH] [--curl-max-time S]
#          [--stall-time S] [--stall-bytes N] [--socks-base PORT]
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "::error::live speedtest samples /proc, so it runs on Linux runners only" >&2
  exit 2
fi
for tool in curl python3 sha256sum md5sum; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "::error::live speedtest needs $tool on PATH" >&2
    exit 2
  }
done

configs_file=""
target_url=""
target_sha256=""
target_md5=""
repeats=2
cores_list=""
out="target/live-speedtest"
bench_bin="target/release/ferrox-bench"
curl_max_time=1500
stall_time=60
stall_bytes=10240
socks_base=11801
while [[ $# -gt 0 ]]; do
  case "$1" in
    --configs-file) configs_file="$2"; shift 2 ;;
    --target-url) target_url="$2"; shift 2 ;;
    --target-sha256) target_sha256="$2"; shift 2 ;;
    --target-md5) target_md5="$2"; shift 2 ;;
    --repeats) repeats="$2"; shift 2 ;;
    --cores) cores_list="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --bench-bin) bench_bin="$2"; shift 2 ;;
    --curl-max-time) curl_max_time="$2"; shift 2 ;;
    --stall-time) stall_time="$2"; shift 2 ;;
    --stall-bytes) stall_bytes="$2"; shift 2 ;;
    --socks-base) socks_base="$2"; shift 2 ;;
    *) echo "::error::unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$configs_file" && -f "$configs_file" ]] || {
  echo "::error::--configs-file needs a file with one vless:// per line" >&2
  exit 2
}
[[ -n "$target_url" ]] || {
  echo "::error::--target-url names the static file every core downloads" >&2
  exit 2
}
# Both digests or neither. A run that carries a SHA-256 and an MD5 has two
# sources of truth for the same bytes and no rule for which one wins; a run with
# neither is honest about being unverified, which is what the manifest already says
# when `target_sha256` is empty.
if [[ -n "$target_sha256" && -n "$target_md5" ]]; then
  echo "::error::pass --target-sha256 or --target-md5, not both" >&2
  exit 2
fi

pins_file="upstream/pins.toml"
engine_dir="target/live-engines"
# shellcheck disable=SC1091
source "$(dirname "$0")/lib-engines.sh"

ALL_CORES="ferrox xray-core zeronet sing-box xray-rust"

main() {
  mkdir -p "$out" "$engine_dir" "$out/configs" "$out/dl" "$out/attempts"
  [[ -f "$pins_file" ]] || fail "$pins_file is missing; refusing to guess a comparator"

  # The links, in order, skipping blanks and `#` comments. Count only: the
  # contents are never printed, never logged.
  mapfile -t links < <(grep -v '^[[:space:]]*\(#\|$\)' "$configs_file" || true)
  ((${#links[@]} > 0)) || fail "no configs in $configs_file"
  echo "note: ${#links[@]} config(s) to try" >&2

  if [[ -z "$cores_list" ]]; then
    cores_list="$ALL_CORES"
  fi
  # shellcheck disable=SC2206
  wanted=(${cores_list//,/ })

  note "building the harness driver"
  cargo build --locked --release -p ferrox-bench -p ferrox-app 2>&1 | tail -2 >&2
  # `built`, for the reason `lib-engines.sh` gives: MSYS answers a stat of the bare
  # name with the `.exe`, so a bare probe passes on `windows-latest` for a name that
  # does not exist under it, and the path then reaches a native process whose
  # `Path::is_file` does no such lookup.
  bench_bin="$(built "$bench_bin")" || fail \
    "no executable at $bench_bin(.exe) after the build above"
  ferrox_bin="$(built target/release/ferrox-app)" || fail \
    "no executable at target/release/ferrox-app(.exe) after the build above"

  # Resolve one binary per wanted core, recording why a core sits out rather
  # than silently narrowing the comparison.
  declare -A bin_of=()
  declare -A skip_reason=()
  for core in ${wanted[@]+"${wanted[@]}"}; do
    if [[ "$core" == "ferrox" ]]; then
      bin_of[$core]="$ferrox_bin"
      continue
    fi
    if path="$(build "$core" 2>/dev/null)"; then
      bin_of[$core]="$path"
    else
      skip_reason[$core]="could not be built from its pin on this host"
    fi
  done

  {
    echo "date: $(date -u +%FT%TZ)"
    echo "host: $(uname -a)"
    echo "target: $target_url"
    echo "target_sha256: ${target_sha256:-unverified}"
    echo "target_md5: ${target_md5:-unverified}"
    echo "repeats: $repeats"
    echo "cores: ${wanted[*]}"
    for core in ${wanted[@]+"${wanted[@]}"}; do
      if [[ -n "${bin_of[$core]:-}" ]]; then
        echo "engine $core: ${bin_of[$core]} sha256=$(sha256_of "${bin_of[$core]}")"
      else
        echo "engine $core: SKIPPED (${skip_reason[$core]:-unknown})"
      fi
    done
    for pin in xray-core sing-box zeronet xray-rust; do
      echo "pin $pin: $(pin_of "$pin")"
    done
  } >"$out/manifest.txt"

  : >"$out/records.jsonl"
  : >"$out/tokens.txt"
  chmod 600 "$out/tokens.txt"
  port="$socks_base"
  index=0
  for link in ${links[@]+"${links[@]}"}; do
    index=$((index + 1))
    # Tokens for the redaction validator. Written to a file the renderer and
    # the artifact upload never touch; validated, then left behind.
    "$bench_bin" linkconfig --tokens --link "$link" >>"$out/tokens.txt" 2>/dev/null \
      || fail "config #$index: unreadable link (not logged; check the paste)"
    label="$("$bench_bin" linkconfig --describe --index "$index" --link "$link" 2>/dev/null)" \
      || fail "config #$index: unreadable link (not logged; check the paste)"
    for core in ${wanted[@]+"${wanted[@]}"}; do
      if [[ -z "${bin_of[$core]:-}" ]]; then
        record "$index" "$label" "$core" 0 "skipped" \
          "${skip_reason[$core]:-unknown}" "" "" "" "" "" "" ""
        continue
      fi
      cfg="$out/configs/cfg${index}-${core}.json"
      if ! "$bench_bin" linkconfig --link "$link" --engine "$core" \
        --socks-port "$port" >"$cfg" 2>"$out/attempts/cfg${index}-${core}.gen.log"; then
        reason="$(head -c 300 "$out/attempts/cfg${index}-${core}.gen.log")"
        record "$index" "$label" "$core" 0 "skipped" "no $core config: $reason" \
          "" "" "" "" "" "" ""
        continue
      fi
      for ((r = 1; r <= repeats; r++)); do
        # Attempt failures are data, not harness faults: a red row with its
        # stage is the report, so the run completes and the validator judges
        # the artefacts rather than the exit code judging the servers.
        attempt "$index" "$label" "$core" "$r" "$cfg" "$port" "$link" || true
        port=$((port + 1))
      done
    done
  done
  local measured
  measured="$(wc -l <"$out/records.jsonl" | tr -d ' ')"
  {
    echo "configs: $index"
    echo "attempts: $measured"
  } | tee "$out/summary.txt" >&2
  # The only failure this exit code reports is "measured nothing": every
  # attempt recorded — green or red — is a completed measurement.
  [[ "$measured" != "0" ]]
}

sha256_of() {
  sha256sum "$1" | cut -d' ' -f1
}

# A file's digest under a named algorithm. `md5sum` is coreutils on the Linux
# runners this script already requires, and the branch is only reached when the
# caller supplied an MD5.
digest_of() {
  case "$2" in
    MD5) md5sum "$1" | cut -d' ' -f1 ;;
    *) sha256sum "$1" | cut -d' ' -f1 ;;
  esac
}

# One JSON record per attempt. Empty strings, never absent keys: the renderer
# reads every row with the same shape.
record() {
  python3 scripts/record-live-attempt.py "$@" >>"$out/records.jsonl"
}

# CPU jiffies (utime+stime) for a pid, or 0 when the process is gone.
jiffies() {
  awk '{print $14 + $15}' "/proc/$1/stat" 2>/dev/null || echo 0
}

# Peak RSS in KiB (VmHWM: the high-water mark over the process's life).
peak_rss_kib() {
  awk '/VmHWM/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0
}

# Run one download through one core. Prints nothing secret; returns nonzero
# when the attempt failed so the run's exit status says so.
attempt() {
  local index="$1" label="$2" core="$3" repeat="$4" cfg="$5" port="$6"
  local adir="$out/attempts/cfg${index}-${core}-r${repeat}"
  mkdir -p "$adir"
  local bin="${bin_of[$core]}"
  local shape
  shape="$(config_arg_for "$core")"

  # Spawn with the core's own config-arg spelling (see parity::ConfigArg).
  local -a cargs=("run")
  case "$shape" in
    long) cargs+=(-config "$cfg") ;;
    short) cargs+=(-c "$cfg") ;;
    positional) cargs+=("$cfg") ;;
  esac
  "$bin" "${cargs[@]}" >"$adir/stdout.log" 2>"$adir/stderr.log" &
  local pid=$!
  local waited=0
  while ! (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; do
    sleep 0.2
    waited=$((waited + 1))
    if ! kill -0 "$pid" 2>/dev/null; then
      record "$index" "$label" "$core" "$repeat" "error" "engine exited during startup" \
        "" "" "" "" "" "" ""
      wait "$pid" 2>/dev/null || true
      return 1
    fi
    if ((waited > 100)); then
      record "$index" "$label" "$core" "$repeat" "error" "SOCKS never listened" \
        "" "" "" "" "" "" ""
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
      return 1
    fi
  done

  local cpu_start cpu_end rss_kib
  cpu_start="$(jiffies "$pid")"
  local file="$out/dl/cfg${index}-${core}-r${repeat}.bin"
  local curl_json="$adir/curl.json"
  local curl_code=0
  curl -sS --socks5-hostname "127.0.0.1:$port" \
    --max-time "$curl_max_time" --speed-time "$stall_time" --speed-limit "$stall_bytes" \
    --retry 0 --fail \
    -o "$file" \
    -w '{"http_code":%{http_code},"size":%{size_download},"total":%{time_total},"starttransfer":%{time_starttransfer}}\n' \
    "$target_url" >"$curl_json" 2>"$adir/curl.err" || curl_code=$?
  cpu_end="$(jiffies "$pid")"
  rss_kib="$(peak_rss_kib "$pid")"
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  if ((curl_code != 0)); then
    local why
    why="$(head -c 300 "$adir/curl.err")"
    record "$index" "$label" "$core" "$repeat" "error" "curl exit $curl_code: $why" \
      "" "" "" "" "" "" ""
    return 1
  fi
  local size total starttransfer
  size="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["size"]))' "$curl_json")"
  total="$(python3 -c 'import json,sys; print(float(json.load(open(sys.argv[1]))["total"]))' "$curl_json")"
  starttransfer="$(python3 -c 'import json,sys; print(float(json.load(open(sys.argv[1]))["starttransfer"]))' "$curl_json")"
  local window
  window="$(python3 -c 'print(max(float(sys.argv[1]) - float(sys.argv[2]), 0.001))' "$total" "$starttransfer")"
  local mib_per_s
  mib_per_s="$(python3 -c 'print(float(sys.argv[1]) / 1048576.0 / float(sys.argv[2]))' "$size" "$window")"
  local cpu_ms gib
  cpu_ms="$(((cpu_end - cpu_start) * 10))"
  gib="$(python3 -c 'print(float(sys.argv[1]) / 1073741824.0)' "$size")"
  local cpu_per_gib
  cpu_per_gib="$(python3 -c 'print(float(sys.argv[1]) / float(sys.argv[2])) if float(sys.argv[2]) > 0 else print(0.0)' "$cpu_ms" "$gib")"
  local rss_mib
  rss_mib="$(python3 -c 'print(float(sys.argv[1]) / 1024.0)' "$rss_kib")"
  # The digest the caller supplied, checked under whichever name they gave it.
  # MD5 is here because public mirrors of large test files routinely publish only
  # MD5, and the alternative is a throughput number for bytes nobody has checked.
  # It is used as an *integrity* check on a file fetched over one TLS connection
  # from one host, which is what it is good for and all it is used for; nothing in
  # this repository authenticates anything with it.
  local hash="unverified"
  local want_hash="" want_algo=""
  if [[ -n "$target_sha256" ]]; then
    want_hash="$target_sha256"
    want_algo="SHA-256"
  elif [[ -n "$target_md5" ]]; then
    want_hash="$target_md5"
    want_algo="MD5"
  fi
  if [[ -n "$want_hash" ]]; then
    local have
    have="$(digest_of "$file" "$want_algo")"
    # Case-insensitive: every published digest for this file is lowercase, but a
    # digest is a hex string and its case is not part of its value.
    if [[ "${have,,}" == "${want_hash,,}" ]]; then
      hash="ok"
    else
      record "$index" "$label" "$core" "$repeat" "error" "$want_algo mismatch" \
        "$mib_per_s" "$cpu_per_gib" "$rss_mib" "$starttransfer" "$size" \
        "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_code"])' "$curl_json")" "mismatch"
      return 1
    fi
  fi
  record "$index" "$label" "$core" "$repeat" "ok" "" \
    "$mib_per_s" "$cpu_per_gib" "$rss_mib" "$starttransfer" "$size" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http_code"])' "$curl_json")" "$hash"
  return 0
}

# Sourced for its functions without running anything; executed directly, it measures.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit "$?"
fi
