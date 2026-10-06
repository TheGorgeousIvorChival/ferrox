#!/usr/bin/env bash

note() { echo "note: $*" >&2; }
fail() { echo "::error::$*" >&2; exit 1; }

pin_of() {
  awk -v want="$1" '
    /^\[sources\./ { in_source = ($0 == "[sources." want "]") }
    in_source && /^rev[[:space:]]*=/ {
      gsub(/^rev[[:space:]]*=[[:space:]]*"|"[[:space:]]*$/, "")
      print; exit
    }
  ' "$pins_file"
}

verify_checkout() {
  local name="$1" rev
  rev="$(pin_of "$name")"
  [[ -n "$rev" ]] || fail "no rev for $name in $pins_file"
  [[ -d "upstream/$name/.git" ]] || fail "upstream/$name is missing; run scripts/fetch-upstream.sh"
  local have
  have="$(git -C "upstream/$name" rev-parse HEAD)"
  [[ "$have" == "$rev" ]] || fail "upstream/$name is at $have, not the pinned $rev"
}

exe_suffix() {
  case "${OS:-}" in
    Windows_NT) printf '.exe' ;;
    *) printf '' ;;
  esac
}

built() {
  if [[ -x "$1$(exe_suffix)" ]]; then
    printf '%s\n' "$1$(exe_suffix)"
  elif [[ -x "$1" ]]; then
    printf '%s\n' "$1"
  else
    return 1
  fi
}

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

config_arg_for() {
  case "$1" in
    sing-box) echo short ;;
    zeronet) echo positional ;;
    *) echo long ;;
  esac
}

dialect_for() {
  case "$1" in
    sing-box) echo sing-box ;;
    *) echo xray ;;
  esac
}
