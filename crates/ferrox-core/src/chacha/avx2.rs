//! The AVX2 backend: eight blocks per iteration, two states per register.
//!
//! A `__m256i` carries two states' worth of one register — the low 128 bits are
//! state A's four words, the high 128 bits are state B's — so four `__m256i`
//! registers hold two complete states and sixteen hold eight. That is twice the
//! blocks in flight of a four-block AVX2 core.
//!
//! It works because every instruction used here is per-128-bit-lane:
//! `vpaddd`, `vpxor`, the shift pairs and `vpshufd` all operate independently on
//! each half, and `vpshufb` is defined per 128-bit lane as well. So the same
//! source runs both halves and neither can disturb the other.
//!
//! # The shuffles
//!
//! `rot_chunks` is `vpshufd`, which applies its pattern within each 128-bit lane —
//! exactly the "rotate the four words of the chunk" operation needed, for both
//! halves at once.
//!
//! `rotl16` and `rotl8` use `vpshufb` byte masks. These are the masks from the
//! `chacha20` crate's own AVX2 backend, verified to reproduce `rotl16` and `rotl8`
//! for all four words of a chunk before being reused here rather than
//! re-derived: deriving a rotate mask by hand is the kind of error that produces
//! output which is wrong at exactly one word position and therefore passes a spot
//! check.
//!
//! # What keeps this honest
//!
//! Nothing here is Miri-checkable — Miri cannot interpret these intrinsics. What
//! is checked is the contract this module owes [`super::Lanes`], by the
//! differential test against the pinned reference at every length and every block
//! offset, including both sides of every group boundary. A lane mix-up fails
//! there; it cannot reach a release.

use super::{as_i32_bits, Lanes};
// Glob-imported on purpose: the module is a flat list of intrinsics, and
// naming twenty of them by hand to satisfy a lint would be noise that hides
// the ones that matter. Every one used here is a single documented
// instruction; `Lanes` is what a reviewer checks, not this list.
#[allow(clippy::wildcard_imports)]
use core::arch::x86_64::*;

/// An AVX2 vector of eight 32-bit words: two states' worth of one register.
#[derive(Clone, Copy)]
pub(crate) struct A8(pub(crate) __m256i);

impl core::fmt::Debug for A8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 8];
        // SAFETY: 32 bytes written into a `[u32; 8]`, which is the exact width.
        unsafe { _mm256_storeu_si256(v.as_mut_ptr().cast(), self.0) };
        f.debug_tuple("A8").field(&v).finish()
    }
}

/// Byte mask for `rotl16`, as eight little-endian `i32`, two 128-bit lanes.
///
/// `vpshufb` zeroes any output byte whose mask byte has the high bit set, so every
/// index here is below 0x80 and the whole mask is a permutation. Each 32-bit word
/// becomes `(b2, b3, b0, b1)`, which is `rotl16`.
const ROTL16: [i32; 8] = [
    0x0100_0302,
    0x0504_0706,
    0x0908_0b0a,
    0x0d0c_0f0e,
    0x0100_0302,
    0x0504_0706,
    0x0908_0b0a,
    0x0d0c_0f0e,
];

/// Byte mask for `rotl8`. See [`ROTL16`] for how these were obtained.
const ROTL8: [i32; 8] = [
    0x0201_0003,
    0x0605_0407,
    0x0a09_080b,
    0x0e0d_0c0f,
    0x0201_0003,
    0x0605_0407,
    0x0a09_080b,
    0x0e0d_0c0f,
];

/// `_mm256_shuffle_epi32` immediate that rotates the four words of each 128-bit
/// lane left by `n`.
///
/// `vpshufd`'s destination lane `i` takes source lane `(i + n) % 4`, so the
/// immediate is `n | (n+1)<<2 | (n+2)<<4 | (n+3)<<6`, each term modulo four.
///
/// `vpshufd` wants a compile-time immediate, so the three values used are spelled
/// out below and this function exists only to prove the literals are what the
/// formula says. A hand-copied shuffle immediate is otherwise the kind of thing
/// that is right for one of the three rotations and wrong for the other two.
const fn rot_imm(n: i32) -> i32 {
    (n & 3) | (((n + 1) & 3) << 2) | (((n + 2) & 3) << 4) | (((n + 3) & 3) << 6)
}

const _: () = {
    assert!(rot_imm(1) == 0b00_11_10_01);
    assert!(rot_imm(2) == 0b01_00_11_10);
    assert!(rot_imm(3) == 0b10_01_00_11);
};

impl Lanes for A8 {
    const LANES: usize = 8;

    #[inline]
    fn from_lanes(words: &[u32]) -> Self {
        // SAFETY: `words` is `LANES` long at every call site, which the generic
        // core builds; `_mm256_loadu_si256` reads exactly 32 bytes and is
        // unaligned, so no alignment is assumed.
        Self(unsafe { _mm256_loadu_si256(words.as_ptr().cast()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm256_add_epi32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm256_xor_si256(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        // SAFETY: as above. `ROTL16` is 32 bytes and every mask byte is below 0x80,
        // so `vpshufb` writes all 32 output bytes from real source bytes.
        Self(unsafe { _mm256_shuffle_epi8(self.0, _mm256_loadu_si256(ROTL16.as_ptr().cast())) })
    }

    #[inline]
    fn rotl12(self) -> Self {
        // SAFETY: as above. A shift pair is three instructions where `vpshufb`
        // would be one, but `vpshufb` cannot express a rotate that is not a whole
        // number of bytes, and 12 is not.
        Self(unsafe {
            _mm256_or_si256(
                _mm256_slli_epi32::<12>(self.0),
                _mm256_srli_epi32::<20>(self.0),
            )
        })
    }

    #[inline]
    fn rotl8(self) -> Self {
        // SAFETY: as above.
        Self(unsafe { _mm256_shuffle_epi8(self.0, _mm256_loadu_si256(ROTL8.as_ptr().cast())) })
    }

    #[inline]
    fn rotl7(self) -> Self {
        // SAFETY: as above.
        Self(unsafe {
            _mm256_or_si256(
                _mm256_slli_epi32::<7>(self.0),
                _mm256_srli_epi32::<25>(self.0),
            )
        })
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        // `vpshufd` takes a compile-time immediate, so the three rotations the
        // round function uses are spelled out. Each is constant at every call site,
        // so the match folds away and this is three distinct shuffles with no
        // branch.
        //
        // SAFETY: as above. `vpshufd` applies within each 128-bit lane, so it
        // rotates both states' chunks independently.
        let v = unsafe {
            match n {
                1 => _mm256_shuffle_epi32::<0b00_11_10_01>(self.0),
                2 => _mm256_shuffle_epi32::<0b01_00_11_10>(self.0),
                _ => _mm256_shuffle_epi32::<0b10_01_00_11>(self.0),
            }
        };
        Self(v)
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        // Two `vpinsrd`, one per chunk's lane 0: lanes 0 and 4 of the vector.
        // `vpinsrd` is `AVX2`, which is the feature this module is only ever
        // reached under, and `with_counters` is therefore sound here.
        //
        // SAFETY: as above. Both lane indices are in range for a 256-bit vector,
        // and chunk `c`'s lane 0 is word `4c`.
        unsafe {
            let lo = _mm256_insert_epi32::<0>(self.0, as_i32_bits(first));
            Self(_mm256_insert_epi32::<4>(
                lo,
                as_i32_bits(first.wrapping_add(Self::CHUNKS as u32 - 1)),
            ))
        }
    }

    #[inline]
    fn xor_chunk(self, c: usize, dst: &mut [u8; 16]) {
        // SAFETY: `dst` is a 16-byte array. The 128-bit lane selected is the one
        // the caller asked for, and both the load and the store touch exactly
        // those 16 bytes of the caller's buffer — which the caller derived from a
        // `chunks_exact_mut` of that buffer, so it is live and owned here.
        unsafe {
            let cur = _mm_loadu_si128(dst.as_mut_ptr().cast());
            let ours = if c == 0 {
                _mm256_castsi256_si128(self.0)
            } else {
                _mm256_extracti128_si256::<1>(self.0)
            };
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, ours));
        }
    }
}

/// The whole ladder on AVX2, for any length; returns the blocks it generated.
///
/// # Safety
///
/// AVX2 must be available on the running CPU. The only caller checks
/// `is_x86_feature_detected!("avx2")` immediately before, which is what makes the
/// `target_feature` sound on a build that was not compiled with `+avx2`. The
/// probe is here rather than in the ladder because a CPUID-backed check per
/// 512-byte group would be a serialising instruction for every group.
#[target_feature(enable = "avx2")]
pub(crate) unsafe fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    out: &mut [u8],
) -> u32 {
    super::xor_ladder::<A8>(key, nonce, start, head, out)
}
