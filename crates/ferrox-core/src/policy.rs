//! Proof policy: what `unsafe` costs, and what a test costs.
//!
//! Goal 1 of this project is to *prove* every shipped byte is faster and leaner
//! — bit-identical output, fewer operations, zero copies that survive review.
//! Goal 2 is to become a drop-in replacement. In that order: a surface built on
//! an unproven primitive inherits its bugs and its silence.
//!
//! # `unsafe`
//!
//! Allowed only when *all* of these hold, and the `SAFETY:` comment on the
//! block names which one each line leans on:
//!
//! 1. **Performance matters and is measured.** The operation is on a hot path
//!    the benchmark gate covers (record layer, SIMD lanes, transport framing),
//!    and the gate shows the safe form regressing at some length.
//! 2. **No issue can be constructed.** The invariants are stated in the SIMD
//!    lane contract and the surrounding module docs, discharged by a
//!    differential test at every length and block offset (both sides of every
//!    boundary), and Miri-interpretable paths stay Miri-clean on nightly.
//! 3. **The assumption is written down.** What the code assumes that the
//!    compiler cannot check (alignment, `target_feature`, lane membership,
//!    lifetime of a `chunks_exact_mut` slice) is in the comment, so a reviewer
//!    can falsify it without re-deriving it.
//!
//! This is enforced by workspace lints (`undocumented_unsafe_blocks`,
//! `missing_safety_doc`, `unsafe_op_in_unsafe_fn` — see the root `Cargo.toml`)
//! and by review, not by counting `unsafe` blocks. The architecture modules
//! (`chacha/avx2.rs`, `chacha/neon.rs`) are the model: five single-instruction
//! primitives each, every one gated by the same differential test.
//!
//! `PattNG`'s `unsafe-*` fingerprints and `security=none`-to-public are
//! *parsed* unconditionally but *enabled* only here: a caller passes
//! [`UnsafeOptIn`] explicitly, which is a value rather than a flag so the
//! opt-in is visible at the call site and in the benchmark report.
//!
//! # Tests, gradually
//!
//! Upstream suites (Xray-core MPL-2.0, sing-box GPL-3.0, xray-rust MPL-2.0,
//! `PattNG` GPL-3.0) are **run against Ferrox binaries in CI, never copied
//! here** — copying them would make this work's licence undecidable (see
//! `docs/conformance.md`). Each suite has an `enabled` bit in
//! `upstream/pins.toml`; a suite flips to `enabled = true` only when its
//! transport rung is implemented *and* its differential proof is green. Until
//! then the CI job for it is created but skipped with the reason printed, so
//! coverage reads as a list of named gaps rather than a quiet absence.

/// Explicit opt-in for `PattNG`'s unsafe connection ways.
///
/// A value, not a `bool`, so `allow_plaintext_to_public()` and
/// `allow_unsafe_fingerprint()` read differently at the call site and in a
/// report. Constructing one is the audit point: grep for these constructors
/// and you have every place this core can speak plaintext to a public address
/// or an `unsafe-*` `ClientHello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsafeOptIn {
    plaintext_to_public: bool,
    unsafe_fingerprint: bool,
}

impl UnsafeOptIn {
    /// Nothing allowed. The default: every unsafe way stays
    /// [`crate::transport::Support::UnsafeRequiresOptIn`].
    #[must_use]
    pub const fn none() -> Self {
        Self {
            plaintext_to_public: false,
            unsafe_fingerprint: false,
        }
    }

    /// Allow `security=none` to a public address (the `PattNG` extension).
    ///
    /// The caller asserts they understand this is plaintext on a public
    /// network and have measured why they need it.
    #[must_use]
    pub const fn allow_plaintext_to_public(mut self) -> Self {
        self.plaintext_to_public = true;
        self
    }

    /// Allow `fp=unsafe-*` `ClientHello`s (the `PattNG` extension).
    #[must_use]
    pub const fn allow_unsafe_fingerprint(mut self) -> Self {
        self.unsafe_fingerprint = true;
        self
    }

    /// Whether plaintext-to-public is opted in.
    #[must_use]
    pub const fn plaintext_to_public(self) -> bool {
        self.plaintext_to_public
    }

    /// Whether `unsafe-*` fingerprints are opted in.
    #[must_use]
    pub const fn unsafe_fingerprint(self) -> bool {
        self.unsafe_fingerprint
    }
}

impl Default for UnsafeOptIn {
    fn default() -> Self {
        Self::none()
    }
}
