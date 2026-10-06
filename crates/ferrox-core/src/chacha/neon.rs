//! The NEON backend: four 128-bit words per register, eight states in flight.
//!
//! NEON is part of the aarch64 baseline — it is not an optional extension — so
//! there is no runtime check here and none is needed. The layout and the rotate
//! idioms follow the Crypto++ `chacha_simd` core that the `chacha20` crate's own
//! NEON backend is adapted from, which is why the rotate-by-8 is a four-way table
//! lookup and the rotate-by-16 is a `vrev32` rather than a shift pair.
//!
//! # Why this matters here
//!
//! The `chacha20` crate does **not** use this code on aarch64. Its
//! `backends.rs` only selects NEON when a `chacha20_force_neon` cfg is set, and
//! nothing sets it, so an aarch64 build silently runs a scalar one-block core.
//! A benchmark comparing against "chacha20 0.9" without naming the backend would
//! credit that gap to this workspace; `ferrox_core::reference::backend` names
//! the one that ran, in every benchmark report.

use super::Lanes;
// Glob-imported on purpose: the module is a flat list of intrinsics, and
// naming twenty of them by hand to satisfy a lint would be noise that hides
// the ones that matter. Every one used here is a single documented
// instruction; `Lanes` is what a reviewer checks, not this list.
#[allow(clippy::wildcard_imports)]
use core::arch::aarch64::*;

/// A NEON vector of four 32-bit words.
#[derive(Clone, Copy)]
pub(crate) struct N4(pub(crate) uint32x4_t);

impl core::fmt::Debug for N4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The raw vector is four u32s; printing them makes a failing differential
        // test name the lane that is wrong instead of just the length.
        let mut v = [0u32; 4];
        // SAFETY: `v` is exactly 16 bytes, which is `size_of::<uint32x4_t>()`, and
        // `v` is aligned as a `[u32; 4]`.
        unsafe { vst1q_u32(v.as_mut_ptr(), self.0) };
        f.debug_tuple("N4").field(&v).finish()
    }
}

/// Rotate a vector of four words left by 16.
///
/// `vrev32q_u16` reverses the byte order within each 16-bit half, which for four
/// 32-bit words is exactly a rotate by 16. One instruction, where a shift pair
/// would be three.
#[inline]
fn rotl16(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: NEON is baseline on aarch64; see the module docs.
    unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(v))) }
}

/// Rotate left by 8.
///
/// `vqtbl1q_u8` is a byte-table lookup: `out[i] = src[mask[i]]`. A rotate by 8
/// within each 32-bit word is not a byte permutation — the two bytes that meet
/// are OR'd together — so it cannot be written as one. The mask is therefore the
/// rotation order and the arithmetic has to happen in the same lane; this is the
/// idiomatic NEON form and the one the reference core uses.
#[inline]
fn rotl8(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: as above; the mask is a 16-byte constant.
    unsafe {
        let mask: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
        let table = vld1q_u8(mask.as_ptr());
        vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(v), table))
    }
}

/// Rotate left by `SH` bits, as a shift-right by `SHR` with the left half
/// inserted back on top: `VSLI` — shift left and insert — keeps the
/// destination's low `SH` bits and takes the shifted source above them, so a
/// rotate is two instructions where a shift pair and an `orr` are three.
///
/// NEON's shift-by-immediate takes the amount as a const generic, so this cannot
/// take a runtime `n` and still emit a single shift pair. Both amounts are
/// therefore const parameters rather than one amount and its complement: a const
/// parameter may not appear inside a const expression, so `32 - SH` is not
/// writable here. The rotation amounts are spelled out at the call site instead,
/// each a literal, so they fold at compile time.
#[inline]
fn rotl_n<const SH: i32, const SHR: i32>(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: NEON is baseline on aarch64; see the module docs. Both amounts are
    // 12/20 or 7/25, so each is strictly below 32 and in range for the intrinsic.
    unsafe {
        let top = vshrq_n_u32::<SHR>(v);
        vsliq_n_u32::<SH>(top, v)
    }
}

/// Rotate the four words of the vector left by `N`, where `1 <= N <= 3`.
///
/// `vextq_u32::<N>(v, v)` extracts from the concatenation `v:v` starting at lane
/// `N`, which for a vector against itself is a lane rotation.
#[inline]
fn rot_chunks<const N: i32>(v: uint32x4_t) -> uint32x4_t {
    // SAFETY: `N` is 1..=3, in range for `vextq`.
    unsafe { vextq_u32::<N>(v, v) }
}

impl Lanes for N4 {
    const LANES: usize = 4;

    fn from_lanes(words: &[u32]) -> Self {
        // SAFETY: `words` is always `LANES` long at every call site, which the
        // generic core builds; the slice is read, never dereferenced as a pointer
        // beyond its length.
        Self(unsafe { vld1q_u32(words.as_ptr()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        // SAFETY: as above.
        Self(unsafe { vaddq_u32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        // SAFETY: as above.
        Self(unsafe { veorq_u32(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        Self(rotl16(self.0))
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(rotl_n::<12, 20>(self.0))
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(rotl8(self.0))
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(rotl_n::<7, 25>(self.0))
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        Self(match n {
            1 => rot_chunks::<1>(self.0),
            2 => rot_chunks::<2>(self.0),
            _ => rot_chunks::<3>(self.0),
        })
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        // `mov v.s[0], w0`: one instruction, no memory. The nonce tail in lanes
        // 1..3 is not written, which is the whole obligation of this method.
        //
        // SAFETY: NEON is baseline on aarch64; see the module docs. Lane 0 of a
        // 128-bit vector is in range.
        Self(unsafe { vsetq_lane_u32::<0>(first, self.0) })
    }

    #[inline]
    fn xor_chunk(self, _c: usize, dst: &mut [u8; 16]) {
        // SAFETY: `dst` is a 16-byte array, so it is 16-byte aligned and exactly
        // the width of a NEON store. The load and the store cover the same 16
        // bytes of the caller's buffer, and the caller derived `dst` from a
        // `chunks_exact_mut` of that buffer, so it is live and owned here.
        unsafe {
            let cur = vld1q_u8(dst.as_mut_ptr());
            vst1q_u8(
                dst.as_mut_ptr(),
                veorq_u8(cur, vreinterpretq_u8_u32(self.0)),
            );
        }
    }
}
