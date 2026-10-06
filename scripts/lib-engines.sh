#!/usr/bin/env bash
# Shared engine builders for the benchmark scripts. Sourced, never executed:
# `run-benchmark-matrix.sh` (the dated matrix) builds the same pinned
# comparators `run-parity.sh` builds inline, and two copies of a build recipe is
# how a runner ends up measuring a different binary from the others. The two
# copies are kept character-identical on purpose: when `run-parity.sh` learns
# something about a platform, it is copied here the same merge.
#
# Every function prints progress on stderr and the binary path on stdout, or
# nothing on stdout and the reason on stderr: callers use command substitution,
# so a progress line on stdout would be captured as part of the path.
#
# Requires `pins_file` and `engine_dir` set by the caller before sourcing.

note() { echo "note: $*" >&2; }
fail() { echo "::error::$*" >&2; exit 1; }

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
