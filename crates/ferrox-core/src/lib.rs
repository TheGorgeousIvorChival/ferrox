//! `ferrox-core` — the primitives every other crate in this workspace is built on.
//!
//! # Why this crate exists
//!
//! Xray-core, sing-box, Amnezia and the Rust ports of each solve the same
//! problems: framing, record encryption, proxy protocols, connection handling.
//! Each does it in its own way, and each has its own performance and safety
//! record. This crate takes one primitive at a time and claims two things about
//! it, both of which are checked rather than asserted:
//!
//! 1. **Bit-identical.** The output is compared byte for byte against the
//!    upstream implementation it replaces. Not "equivalent" — identical, at
//!    every length and every offset, on every device CI runs.
//! 2. **Not slower.** The same comparison runs as a benchmark, and the job
//!    fails if any single length regresses.
//!
//! # What is not claimed
//!
//! That this is the fastest implementation, full stop. A benchmark is a
//! measurement of a configuration at a point in time, and it decays: a new CPU,
//! a new upstream release or a new input distribution moves it. What is built
//! here is the machinery that notices, so the claim is never stale — see the
//! `ferrox-bench` crate and `docs/methodology.md`.
//!
//! # Layout
//!
//! - [`tls`] — the one interface the rustls backend implements.
//! - [`record`] — the record layer, where framing and encryption meet.
//! - [`aead`] — `ChaCha20`-`Poly1305` on the record layer's own keystream core.
//! - [`aesgcm`] — `AES-128`/`AES-256`-GCM on this crate's own fused engine.
//! - [`shadowsocks`] — the `AEAD` chunk transport: its cipher table and keys.
//! - [`vless`] — the `vless://` link parser every app pastes.
//! - [`addr`] — the address codec both [`vless`] and [`mux`] write.
//! - [`mux`] — multiplexing: many streams inside one, and the sessions on it.
//! - [`transport`] — the superset matrix: every way `PattNG` can connect.
//! - [`failure`] — why an attempt stopped, in the form a recovery decision reads.
//! - [`policy`] — when `unsafe` and upstream suites may be enabled.
//! - [`crate::reference`] — the pinned upstream implementation, tests and gate only.

#![deny(missing_debug_implementations)]

pub mod addr;
pub mod aead;
pub mod aesgcm;
pub(crate) mod chacha;
pub mod core;
pub mod failure;
pub mod kcp;
pub mod mux;
pub mod policy;
pub mod poly1305;
pub mod record;
pub mod shadowsocks;
pub mod tls;
pub mod transport;
pub mod vless;

/// The reference implementation, reachable only by tests and the benchmark gate.
///
/// Compiled under `cfg(test)` or the `bench-reference` feature, so a shipped
/// build does not contain it. It lives in its own module rather than behind a
/// widened `pub(crate)` on [`core`], so that reaching the reference is a
/// visible act at the call site rather than a quietly loosened boundary.
#[cfg(any(test, feature = "bench-reference"))]
pub mod reference {
    pub use crate::core::{backend, reference_xor};
}

/// Compiled TLS backends, by name.
///
/// Used by benchmarks and reports to name the stack a number came from, so a
/// measurement can never be read without knowing what produced it.
///
/// The list is built from literals directly rather than by indexing per-backend
/// constants. Indexing a `&[&str]` is not a promotable constant expression, so
/// the array holding the results came out as a temporary and the function did
/// not compile — an ordinary-looking helper that was never built until now.
pub fn active_backends() -> &'static [&'static str] {
    &["rustls"]
}

/// Which core this build dispatches to, and how wide it is.
///
/// Reported next to the reference's own backend by the benchmark, because a
/// speedup is only attributable once both sides of it are named. On a build
/// where this says "scalar" while the reference says "avx2", no ratio here is
/// evidence about the algorithm.
pub const fn chacha_backend() -> &'static str {
    crate::chacha::backend()
}
