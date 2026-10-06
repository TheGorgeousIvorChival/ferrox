#!/usr/bin/env bash
# Scenario catalog and config templates for the benchmark matrix. Sourced, never
# executed: pure functions with no side effects, so tests and shells can load
# them without measuring anything. `run-benchmark-matrix.sh` sources this after
# changing to the repository root.

UUID="f47ac10b-58cc-4372-a567-0e02b2c3d479"
PASSWORD="matrix-secret"
SS_PASSWORD="matrix-shadowsocks-password"

# The port a scenario's protocol **server** inbound listens on, and the port its
# matching client outbound dials.
#
# A function rather than a constant because it is now **allocated per cell**, and
# a fixed one was a real defect rather than a style choice. `45191` was hardcoded
# for every cell and every repeat, so two things went wrong with it. Two cells in
# the same run, or one cell and a stray engine from an earlier one, collide on the
# bind: the engine that loses exits, the harness reads that as a failed engine, and
# the cell publishes as if that engine could not do the protocol. It also made the
# runs non-reproducible in the strict sense — a number that depends on whether
# something else held the port is a number about the machine, not the engine.
#
# The allocator asks the kernel for a free port and drops the listener, which is
# racy in principle; the race is bounded and named, and readiness is then confirmed
# by the harness connecting, so a stolen port surfaces as an engine that never
# listens rather than as a silent mismeasurement.
matrix_srvport() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

# $1 protocol stanza for the server inbound, $2 the matching client outbound,
# $3 the port the server listens on.
# Routing is load-bearing: harness-socks goes to the protocol client, and the
# protocol server's own accepted flows fall through to freedom. Without the
# second rule an engine whose default route is its first outbound dials itself.
# Freedom carries the oracle's SSRF opt-out: the harness sink is a private
# address, which Xray's freedom blackholes by default, stalling the server
# side silently after the detour is taken. Disposable measurement configs only.
server_config() {
  local port="$3"
  cat <<EOF
{"inbounds": [{"tag": "matrix-server", "listen": "127.0.0.1", "port": $port, $1}],
 "outbounds": [{$2}, {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
 "routing": {"rules": [{"type": "field", "inboundTag": ["harness-socks"], "outboundTag": "proxy"}, {"type": "field", "inboundTag": ["matrix-server"], "outboundTag": "direct"}]}}
EOF
}

vless_server() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}$1"
}
vless_client() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"none\"}]}]}$1"
}
stream_json() {
  case "$1" in
    tcp) echo '"streamSettings": {"network": "tcp"}' ;;
    ws) echo '"streamSettings": {"network": "ws", "wsSettings": {"path": "/tunnel"}}' ;;
    grpc) echo '"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "TunnelService"}}' ;;
    xhttp) echo '"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}' ;;
  esac
}

# The config for one scenario. $1 is the scenario id, $2 the port to serve on.
scenario_config() {
  local port="$2"
  case "$1" in
    vless-raw-*) server_config "$(vless_server ', "streamSettings": {"network": "tcp"}')" "$(vless_client ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-ws-*) server_config "$(vless_server ", $(stream_json ws)")" "$(vless_client ", $(stream_json ws)" "$port")" "$port" ;;
    vless-grpc-*) server_config "$(vless_server ", $(stream_json grpc)")" "$(vless_client ", $(stream_json grpc)" "$port")" "$port" ;;
    vless-xhttp-*) server_config "$(vless_server ", $(stream_json xhttp)")" "$(vless_client ", $(stream_json xhttp)" "$port")" "$port" ;;
    vmess-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, \"streamSettings\": {\"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, \"streamSettings\": {\"network\": \"tcp\"}" "$port" ;;
    trojan-raw-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}" "$port" ;;
    shadowsocks-raw-*) server_config "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\", \"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\"}]}" "$port" ;;
    *) echo "::error::unknown scenario $1" >&2; return 1 ;;
  esac
}

# Bytes every bulk row moves per repeat, and why that number is not a matter of taste.
#
# 8 GiB per repeat across the cell's flows. The transfer window **is** the
# instrument, and a shared CI runner loses the CPU to a co-tenant for tens of
# milliseconds at a time: over 32 MiB that is a third of the measurement, over
# 8 GiB it is about 2% (`docs/methodology.md`, the section on the window). A
# smaller window is not faster, it is noisier.
#
# **This was the bug in the smoke tier, and it is worth stating precisely because
# the symptom looked like a win rather than a fault.** At 128 MiB per repeat the
# pinned Xray-core reads the self-relay at ~210 MiB/s and ferrox at ~1900, so the
# published ratio is ~8x. At 8 GiB the same two binaries on the same runner read
# 1300-1400 and 1700-1900, so the ratio is ~1.1x. The gap is not throughput at all:
# Xray-core's VLESS relay reaches its steady rate after a fixed start-up cost that
# a 128 MiB window does not amortise and an 8 GiB window does. **A window shorter
# than the ramp measures the ramp**, and the smoke tier was publishing exactly that
# as `throughput.png`.
#
# Measured on `macos aarch64`, this runner, three repeats per size, self-relay
# `vless-raw-down-1`:
#
# | bytes/repeat | xray-core | ferrox | ratio |
# | --- | ---: | ---: | ---: |
# | 128 MiB | 197-208 | 835-1262 | **4.2-6.4x** |
# | 512 MiB | 693-712 | 2331-2604 | 3.3-3.8x |
# | 2 GiB | 1021-1273 | 1670-2215 | 1.3-1.7x |
# | 8 GiB | 1272-1371 | 1289-1877 | **1.0-1.4x** |
#
# The smoke tier therefore moves the same 8 GiB as the standard tier and differs
# only in scenario count, engine count and repeats. It stays a fast job because
# those are what actually cost the time, not the bytes.
MIB=1024
KIb=$((1024 * MIB))
GIB=$((1024 * 1024))

# scenario traffic connections iterations payload_bytes
#
# Per-flow iterations scale with the flow count so the total stays 8 GiB: one flow
# of 131072, eight flows of 16384, sixteen of 8192. The ladder is `connections`
# capped at 16, which is the harness ceiling; a 64-flow row is refused with its
# reason until that bound moves with the thread-pool reasoning that justifies it.
standard_scenarios() {
  echo "vless-raw-down-1 download 1 131072 65536"
  echo "vless-raw-down-8 download 8 16384 65536"
  echo "vless-raw-up-1 upload 1 131072 65536"
  echo "vless-raw-duplex-8 full-duplex 8 8192 65536"
  echo "vless-ws-down-8 download 8 16384 65536"
  echo "vless-grpc-down-8 download 8 16384 65536"
  echo "vless-xhttp-down-8 download 8 16384 65536"
  echo "vmess-raw-down-8 download 8 16384 65536"
  echo "trojan-raw-down-8 download 8 16384 65536"
  echo "shadowsocks-raw-down-8 download 8 16384 65536"
  echo "vless-raw-setup-1k download 1 1000 8"
}

scenarios() {
  case "${1:-$tier}" in
    # One scenario, and it moves the same 8 GiB the standard tier's rows do. It is
    # a plumbing check on a *measurement*, so the window has to be one a
    # measurement can be taken over; see the table above for what a shorter one
    # published instead.
    smoke) echo "vless-raw-down-1 download 1 131072 65536" ;;
    standard) standard_scenarios ;;
    full)
      standard_scenarios
      # Sixteen is the harness ceiling (`connections` validates 1..=16): a
      # 64-flow ladder is refused with its reason until that bound moves with
      # the thread-pool reasoning that justifies it, not before.
      echo "vless-raw-down-16 download 16 8192 65536"
      echo "vless-ws-down-16 download 16 8192 65536"
      echo "vless-raw-duplex-16 full-duplex 16 4096 65536"
      ;;
  esac
}
