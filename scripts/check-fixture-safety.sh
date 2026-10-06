#!/usr/bin/env bash
# Fails on live credentials or routable endpoints committed to the tree.
#
# A benchmark/proxy repository is one pasted config away from publishing
# someone's live UUID, public key, or server. Tests and docs therefore use
# only RFC 5737 documentation addresses (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), RFC 1918 private addresses, loopback, and `example.*` /
# `*.test` names. A working `vless://` link arrives at CI as a masked
# dispatch input, never as a committed file — the report redacts it.
#
# What fails the job:
#   1. an IPv4 literal outside the allowlist below, in any tracked text file;
#   2. a `vless://`, `vmess://`, `trojan://` or `ss://` link whose host is not
#      a documentation/test name or address;
#   3. a PEM private key block anywhere.
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

# 1. IPv4 literals. Allowed: 0.0.0.0, loopback, RFC 1918, TEST-NET-1/2/3,
# broadcast. Everything else (a public server, a public DNS resolver used as
# anything but a comment) is a leak or a future leak.
python3 - <<'EOF'
import re, subprocess, sys
files = subprocess.run(
    ["git", "grep", "-I", "--name-only", "-E",
     r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "--", "."],
    capture_output=True, text=True, check=True).stdout.split()
ip = re.compile(r"([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})")
def allowed(a, b, c, d):
    if (a, b, c, d) == (0, 0, 0, 0) or (a, b, c, d) == (255, 255, 255, 255):
        return True
    if a == 127 or a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if (a, b) in ((192, 0), (198, 51), (203, 0)) and (
        (c == 2 and a == 192) or (c == 100 and a == 198) or (c == 113 and a == 203)):
        return True
    return False
bad = 0
for f in files:
    try:
        text = open(f, encoding="utf-8", errors="strict").read()
    except (UnicodeError, OSError):
        continue
    for n, line in enumerate(text.splitlines(), 1):
        for m in ip.finditer(line):
            a, b, c, d = (int(m.group(i)) for i in range(1, 5))
            if not all(x <= 255 for x in (a, b, c, d)):
                continue
            if not allowed(a, b, c, d):
                print(f"::error::{f}:{n}: routable IPv4 literal {m.group(0)} — use TEST-NET (192.0.2.0/24)")
                bad += 1
sys.exit(1 if bad else 0)
EOF
# `set -e` above already ends the script with the python block's exit code when
# it finds a leak, so there is nothing to fold into `status` here.

# 2. Share-link hosts. Only documentation/test names and addresses may appear
# in committed links; a real server can only arrive as masked CI input. The
# single-label `uuid`, `host` and `{host}` are the documentation placeholders the
# module docs and the error messages are written with: `vless://uuid@host:port`
# names no endpoint, so it is not one.
if git grep -I -n -E '(vless|vmess|trojan|ss)://[^@#? ]+@[^/:?# ]+' -- . \
  | grep -v -E '@(\[::1\]|(127|10)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|(192\.0\.2|198\.51\.100|203\.0\.113)\.[0-9]{1,3}|localhost|example\.[a-z]+|[A-Za-z0-9.-]+\.(test|invalid|localhost)|uuid|host|\{host\})([:/?#]|$)' \
  | grep -v '^Binary'; then
  echo "::error::share-link with a non-documentation host — working configs arrive as masked CI input only"
  status=1
fi

# 3. No private key material, committed ever, for any reason.
# The pattern itself is text in this file, so the file is excluded the way
# `check-comments.sh` excludes itself: a gate that cannot name what it forbids
# without matching itself forbids its own source.
if git grep -I -n -E -e '-----BEGIN .*PRIVATE KEY-----' -- . ':!scripts/check-fixture-safety.sh'; then
  echo "::error::private key block in the tree — test material is generated at runtime"
  status=1
fi

exit "$status"
