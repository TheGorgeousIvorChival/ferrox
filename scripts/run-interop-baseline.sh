#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

filter="${1:-${BASELINE_SUITES:-all}}"
if [[ "$filter" != "all" && "$filter" != "zeronet" && "$filter" != "xray-rust" ]]; then
  echo "::error::unknown suite '$filter'; want all|zeronet|xray-rust"
  exit 1
fi
pins_file="upstream/pins.toml"
out_dir="target/interop-baseline"
report="$PWD/$out_dir/interop-baseline-summary.md"
mkdir -p "$out_dir"

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

pin_field() {
  parse_pins | awk -F'\t' -v n="$1" -v c="$2" '$1 == n { print $c }'
}

{
  echo "# interop baseline (upstream suites against ferrox-app)"
  echo
  echo "Every test each suite has, pass or fail, against this workspace's ferrox-app. Informational: failures never fail this job; infra failures (bad pin, no toolchain, unbuilt binary) do."
  echo
} >"$report"

if ! cargo build --locked -q -p ferrox-app 2>/dev/null; then
  echo "::error::ferrox-app does not build in this workspace"
  exit 1
fi

workspace="$PWD"
for name in zeronet xray-rust; do
  if [[ "$filter" != "all" && "$filter" != "$name" ]]; then
    continue
  fi
  repo="$(pin_field "$name" 2)"
  rev="$(pin_field "$name" 3)"
  suite="$(pin_field "$name" 5)"
  binary="$(pin_field "$name" 6)"
  seam="$(pin_field "$name" 7)"
  if [[ -z "$repo" || -z "$rev" || -z "$suite" || -z "$binary" || -z "$seam" ]]; then
    echo "::error::$name pin is missing repo/rev/suite/binary/seam"
    exit 1
  fi
  full="${suite%% --test-threads=1*} --test-threads=1"
  if [[ "$full" == "$suite" ]]; then
    echo "::error::$name suite carries no --test-threads=1 filter names to strip; refusing to rerun the conformance subset as a baseline"
    exit 1
  fi
  dir="$(mktemp -d)"
  if ! git clone --quiet --no-checkout "$repo" "$dir" 2>/dev/null || ! git -C "$dir" checkout --quiet "$rev" 2>/dev/null; then
    echo "::error::$name rev $rev does not resolve on $repo"
    rm -rf "$dir"
    exit 1
  fi
  if [[ "$(git -C "$dir" rev-parse HEAD)" != "$rev" ]]; then
    echo "::error::$name checkout is not at its pin $rev"
    rm -rf "$dir"
    exit 1
  fi
  if ! git -C "$dir" grep -qI -e "$seam" -- . 2>/dev/null; then
    echo "::error::$name declares seam $seam but $rev never reads it"
    rm -rf "$dir"
    exit 1
  fi
  log="$PWD/$out_dir/$name.log"
  echo "baseline: $name @ ${rev:0:7}, full suite against $workspace/target/debug/$binary via $seam"
  set +e
  (cd "$dir" && env "$seam=$workspace/target/debug/$binary" bash -c "$full" >"$log" 2>&1)
  test_rc=$?
  set -e
  rm -rf "$dir"
  ran="$(sed -n 's/^running \([0-9][0-9]*\) tests\{0,1\}$/\1/p' "$log" | head -1)"; ran="${ran:-0}"
  passed="$(grep -c '^test .* \.\.\. ok$' "$log" || true)"; passed="${passed:-0}"
  failed="$(grep -c '^test .* \.\.\. FAILED$' "$log" || true)"; failed="${failed:-0}"
  {
    echo "## $name @ \`${rev:0:7}\` (go exit $test_rc; libtest running $ran; $passed passed, $failed failed)"
    echo
    if ((failed > 0)); then
      echo "### failed"
      echo
      echo '```'
      grep '^test .* \.\.\. FAILED$' "$log" | sed 's/ \.\.\. FAILED$//' | sort -u || true
      echo '```'
      echo
      echo "### failure output (first 25 lines per test)"
      echo
      echo '```'
      awk '/^---- .* stdout ----$/{show=1; n=0; print; next} show && n < 25 {print; n++} show && n >= 25 {show=0}' "$log" || true
      echo '```'
      echo
    fi
    echo "### passed"
    echo
    echo '```'
    grep '^test .* \.\.\. ok$' "$log" | sed 's/ \.\.\. ok$//' | sort -u || true
    echo '```'
    echo
  } >>"$report"
  if ((failed > 0)) || ((test_rc != 0)); then
    echo "::warning::$name baseline: $passed passed, $failed failed; recorded, job stays green"
  else
    echo "$name baseline: all green ($passed passed)"
  fi
done

sing_rev="$(pin_field sing-box 3)"
sing_repo="$(pin_field sing-box 2)"
{
  echo "## sing-box @ \`${sing_rev:0:7}\`: no seam, not runnable against ferrox-app"
  echo
} >>"$report"
sdir="$(mktemp -d)"
if git clone --quiet --no-checkout "$sing_repo" "$sdir" 2>/dev/null && git -C "$sdir" checkout --quiet "$sing_rev" 2>/dev/null && [[ "$(git -C "$sdir" rev-parse HEAD)" == "$sing_rev" ]]; then
  proto_tests="$(find "$sdir/protocol/shadowsocks" "$sdir/protocol/vless" -name '*_test.go' 2>/dev/null | wc -l | tr -d ' ')"
  env_files="$(git -C "$sdir" grep -lI -e 'os.Getenv' -- test/ 2>/dev/null | wc -l | tr -d ' ')"
  {
    echo "Checked at the pin: $proto_tests _test.go files under protocol/shadowsocks and protocol/vless, and $env_files test files reading the environment (openconnect interop flag, DOCKER_HOST) — none injects an external proxy binary, so this suite can only run sing-box against itself. Running it here would measure upstream, not this workspace, and is left out rather than faked."
    echo
  } >>"$report"
else
  {
    echo "Pin did not resolve for a live check; verdict carried from docs/conformance.md: no seam, in-process Go tests only."
    echo
  } >>"$report"
fi
rm -rf "$sdir"

cat "$report"
exit 0
