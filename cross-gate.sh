#!/usr/bin/env bash
# Lint a target this host is not, by building for it.
#
# # Why
#
# `#[cfg(target_os = "...")]` code is compiled out everywhere else, so a macOS
# `cargo clippy` cannot see it at all — not a wrong name, a wrong type, a constant
# nothing uses, a borrow the borrow checker rejects, or a platform struct declared
# with the wrong layout. Substituting the `cfg`s cannot recover that: with the gates
# flipped on, `libc::splice` does not exist on this host, the call fails at *name
# resolution*, and a hard error stops the build before clippy's lint pass runs. So a
# substitution check does not merely miss that code — it reports it **clean**.
#
# Building for the real target does see it, and it costs one `rustup target add` and a
# C compiler that can target the same machine, which `zig cc` is for both targets
# here.
#
# What it catches is bounded by what it cannot do: it type-checks and lints, it does
# not *run* anything. An x86-64 Linux or Windows binary does not execute here, so
# `cargo test` on those targets is still CI's job, and a runtime fault in platform
# code is still invisible to this. That limit is why the platform arithmetic in `ps`
# is written as portable functions with host-independent tests rather than inside the
# `unsafe` blocks: this gate proves the FFI *compiles and lints*, the tests prove the
# arithmetic, and only the runtime is left to a runner.
#
# If either dependency is missing this exits 2 rather than 0, so "did not run" is
# never mistaken for "passed", and there is deliberately no weaker fallback.
#
#   scripts/cross-gate.sh x86_64-unknown-linux-gnu
#   scripts/cross-gate.sh x86_64-pc-windows-msvc
set -euo pipefail
root="$(cd "$(dirname "$0")" && pwd)"
target="${1:?usage: cross-gate.sh <target-triple>}"
name="$(basename "$0")"

die() { printf '%s: %s\n' "$name" "$1" >&2; exit "${2:-2}"; }

command -v rustup >/dev/null || die "rustup is not on PATH"
rustup target list --installed | grep -qx "$target" ||
  die "the $target standard library is missing: run \`rustup target add $target\`"

# The C compiler `cc-rs` needs, as a target triple cargo can spell in an
# environment variable.
env_key="$(printf '%s' "$target" | tr -- '-' '_')"
normalised="$env_key"

zig="${ZIG:-}"
if [ -z "$zig" ]; then
  zig="$(command -v zig || true)"
  for candidate in "$HOME"/.local/opt/zig-*/zig "$HOME"/.local/bin/zig /opt/homebrew/bin/zig; do
    [ -x "$candidate" ] && { zig="$candidate"; break; }
  done
fi
[ -n "$zig" ] || die "no \`zig\` found, and \`ring\` will not build for $target without one; set ZIG=/path/to/zig"

# zig's own name for each target. Only two are spelled here, and both are the ones
# the local gates need; an unmapped target fails loudly rather than compiling for
# the wrong machine.
case "$target" in
  x86_64-unknown-linux-gnu) zig_target=x86_64-linux-gnu ;;
  x86_64-pc-windows-msvc) zig_target=x86_64-windows-gnu ;;
  *) die "$target has no zig target spelling in this script" ;;
esac

shim="$(mktemp -d)"
trap 'rm -rf "$shim"' EXIT

# `cc-rs` needs a compiler for the target whichever host runs it. `zig cc` is one,
# but cargo hands it a Rust triple it does not parse and `ring` asks for `-std=c1x`,
# the pre-standardisation name for C23 that current zig does not list. `c11` is the
# nearest it does.
cat >"$shim/cc" <<SHIM
#!/bin/sh
set -f
count=\$#
i=0
while [ "\$i" -lt "\$count" ]; do
  arg="\$1"; shift
  case "\$arg" in
    --target=$target) i=\$((i + 1)); continue ;;
    -std=c1x) set -- "\$@" -std=c11; i=\$((i + 1)); continue ;;
  esac
  set -- "\$@" "\$arg"
  i=\$((i + 1))
done
exec "$zig" cc -target $zig_target "\$@"
SHIM

# `cc-rs` reaches for the archiver in two dialects: `ar cq <archive> <objects>` on a
# unix target, and `lib.exe`-style `-out:<archive> -nologo <objects>` on an MSVC one.
# zig's `ar` is llvm-ar, which takes `rcs <archive> <objects...>` and has heard of
# neither. Both spellings are accepted here and neither target falls back to the
# other, because a silently-mismatched archiver is how a build gets a C archive the
# linker cannot read.
cat >"$shim/ar" <<SHIM
#!/bin/sh
out=""
rest=""
seen_archive=0
for arg in "\$@"; do
  case "\$arg" in
    -nologo) ;;
    -out:*) out="\${arg#-out:}" ;;
    c*) ;;   # `cq` and `cr`: the letters, which llvm-ar wants without the `q`.
    *)
      if [ "\$seen_archive" = 0 ] && [ -z "\$out" ]; then
        out="\$arg"
        seen_archive=1
      else
        rest="\$rest \$arg"
      fi
      ;;
  esac
done
[ -n "\$out" ] || { echo "ar: no archive named in: \$*" >&2; exit 2; }
exec "$zig" ar rcs "\$out" \$rest
SHIM
chmod +x "$shim/cc" "$shim/ar"

# The same flags as the `lint and docs` job, so this cannot pass where that fails.
#
# Both spellings, because `cc-rs` looks for the dashed form first and the underscored
# one second, and a script that exported only one of them would be relying on which
# lookup that crate happened to reach for.
export "CC_${env_key}=$shim/cc"
export "AR_${env_key}=$shim/ar"
# `dash` turns the triple's dashes into underscores without the shell refusing the
# name, which is the other half of why both forms are set.
export "CC_$normalised=$shim/cc"
export "AR_$normalised=$shim/ar"

if cargo clippy --workspace --all-targets --locked --target "$target" \
  --target-dir "$root/target/cross-gate" \
  -- -D warnings -W clippy::perf -W clippy::suspicious; then
  echo "$name: $target clean"
else
  status=$?
  echo "$name: $target has findings above" >&2
  exit "$status"
fi
