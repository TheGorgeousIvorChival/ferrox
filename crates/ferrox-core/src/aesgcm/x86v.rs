//! The 256-bit `x86_64` backend: `VAES` + `VPCLMULQDQ`, two blocks per
//! register, eight in flight.
//!
//! # Why it is the same arithmetic twice as wide
//!
//! Every instruction the `GHASH` kernel and the `CTR` rounds are built from is
//! per-128-bit-lane: `VPCLMULQDQ`, `VPSHUFD`, `VPXOR`, `VPSHUFB`, the shift
//! pairs and `VAESENC` all compute two independent copies of the 128-bit
//! operation per instruction. So a `__m256i` carries two consecutive blocks —
//! the even one in the low lane — and the *same source shape* as [`super::x86`]
//! runs both at once: the four-register unreduced product accumulates two
//! blocks' products, one per lane, the lanes are combined right before the one
//! reduction, and the reduction itself is [`super::Lanes`]'s 128-bit one.
//!
//! The group is eight blocks because that is what four registers hold, and the
//! `H` powers are stored as per-lane pairs — `(H^8, H^7)` down to `(H^2, H^1)`
//! — so each product's two lanes multiply by their own positions' powers. The
//! tail below a whole group is the 128-bit module's own path, unchanged:
//! [`super`]'s `ctr_ghash`, `ghash`, `flush` and `finish` run on `__m128i`
//! with the engine's 128-bit round keys.
//!
//! # What keeps this honest
//!
//! The same as `x86.rs`: the differential sweep against the `aes-gcm` crate at
//! every length, on a runner that has the features — the gate's identity half
//! runs *this* path there and says so in the report's backend row.

use super::Lanes;
// Glob-imported on purpose: see `x86.rs` for the reasoning.
#[allow(clippy::wildcard_imports)]
use core::arch::x86_64::*;

/// The per-key state.
pub(crate) struct Engine {
    /// `AES-128`'s eleven round keys, 128-bit: the tail, the mask, the powers.
    rk: [__m128i; 11],
    /// The same keys broadcast to both lanes, for the group rounds.
    rk2: [__m256i; 11],
    /// `H^1 .. H^4` in the reflected representation, each as `(h, h ^ swap(h))`:
    /// the tail's powers.
    h: [(__m128i, __m128i); 4],
    /// The group powers, per lane: entry 3 is `(H^8, H^7)`, entry 0 is
    /// `(H^2, H^1)`, each lane paired with its `h ^ swap(h)`.
    hp: [(__m256i, __m256i); 4],
}

/// The byte-reversal mask, both lanes: `GHASH`'s operands enter the multiply
/// reversed.
const BSWAP2: [u8; 32] = [
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, //
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
];

/// The counter mask, both lanes: the nonce's twelve bytes untouched, the
/// counter's four reversed.
const CTRMASK2: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12, //
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12,
];

#[inline(always)]
fn loadu2(b: &[u8; 32]) -> __m256i {
    // SAFETY: `_mm256_loadu_si256` reads 32 bytes, unaligned; `b` is a
    // 32-byte array, live for the call.
    unsafe { _mm256_loadu_si256(b.as_ptr().cast()) }
}

/// Reverse the 16 bytes of each lane.
#[inline(always)]
fn bswap2(x: __m256i) -> __m256i {
    // SAFETY: pure register op; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe { _mm256_shuffle_epi8(x, loadu2(&BSWAP2)) }
}

/// Reverse the last four bytes of each lane: the native-order counter becomes
/// `GCM`'s big-endian block.
#[inline(always)]
fn cswap2(x: __m256i) -> __m256i {
    // SAFETY: as above.
    unsafe { _mm256_shuffle_epi8(x, loadu2(&CTRMASK2)) }
}

/// `acc ^= mul256(a, h)` per lane: the 128-bit [`super::Lanes::mul_add`],
/// doubled.
#[inline(always)]
fn mul_add2(acc: &mut [__m256i; 4], a: __m256i, h: __m256i, hxs: __m256i) {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        let a1 = _mm256_shuffle_epi32::<0x0E>(a);
        let a2 = _mm256_xor_si256(a, a1);
        let t0 = _mm256_clmulepi64_epi128::<0x00>(a, h);
        let t1 = _mm256_clmulepi64_epi128::<0x11>(a, h);
        let t2 = _mm256_clmulepi64_epi128::<0x00>(a2, hxs);
        let t2 = _mm256_xor_si256(t2, _mm256_xor_si256(t0, t1));
        acc[0] = _mm256_xor_si256(acc[0], t0);
        acc[1] = _mm256_xor_si256(
            acc[1],
            _mm256_xor_si256(_mm256_shuffle_epi32::<0x0E>(t0), t2),
        );
        acc[2] = _mm256_xor_si256(
            acc[2],
            _mm256_xor_si256(t1, _mm256_shuffle_epi32::<0x0E>(t2)),
        );
        acc[3] = _mm256_xor_si256(acc[3], _mm256_shuffle_epi32::<0x0E>(t1));
    }
}

/// Combine the two lanes of each accumulator register into the 128-bit
/// accumulator the reduction consumes: the products summed per lane, summed
/// once more across lanes — the same total, as linearity requires.
#[inline(always)]
fn combine(acc: [__m256i; 4]) -> [__m128i; 4] {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        acc.map(|r| _mm_xor_si128(_mm256_castsi256_si128(r), _mm256_extracti128_si256::<1>(r)))
    }
}

/// Eight consecutive counter blocks from the template, `ctr` first: each
/// register's lanes are two consecutive counters, in chain order.
#[inline(always)]
fn ctr8v(template: __m256i, ctr: u32) -> [__m256i; 4] {
    // The counter is the high 32 bits of each 128-bit lane: those are `e7`
    // and `e3` of `_mm256_set_epi32`'s eight arguments (named highest-first),
    // not the lane-leading `e4` and `e0`.
    //
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        let a0 = _mm256_add_epi32(
            template,
            _mm256_set_epi32((ctr + 1).cast_signed(), 0, 0, 0, ctr.cast_signed(), 0, 0, 0),
        );
        let two = _mm256_set_epi32(2, 0, 0, 0, 2, 0, 0, 0);
        let a1 = _mm256_add_epi32(a0, two);
        let a2 = _mm256_add_epi32(a1, two);
        let a3 = _mm256_add_epi32(a2, two);
        [cswap2(a0), cswap2(a1), cswap2(a2), cswap2(a3)]
    }
}

/// `AES-128` over four registers = eight independent blocks, in place.
#[inline(always)]
fn encrypt8(rk: &[__m256i; 11], s: &mut [__m256i; 4]) {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        for lane in s.iter_mut() {
            *lane = _mm256_xor_si256(*lane, rk[0]);
        }
        for k in &rk[1..10] {
            for lane in s.iter_mut() {
                *lane = _mm256_aesenc_epi128(*lane, *k);
            }
        }
        for lane in s.iter_mut() {
            *lane = _mm256_aesenclast_epi128(*lane, rk[10]);
        }
    }
}

/// `AES-256` over four registers = eight independent blocks, in place.
#[inline(always)]
fn encrypt8_256(rk: &[__m256i; 15], s: &mut [__m256i; 4]) {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        for lane in s.iter_mut() {
            *lane = _mm256_xor_si256(*lane, rk[0]);
        }
        for k in &rk[1..14] {
            for lane in s.iter_mut() {
                *lane = _mm256_aesenc_epi128(*lane, *k);
            }
        }
        for lane in s.iter_mut() {
            *lane = _mm256_aesenclast_epi128(*lane, rk[14]);
        }
    }
}

/// Eight blocks of the Horner chain as one reduction: the four pair-products
/// accumulate per lane, the lanes combine, and the 128-bit reduction runs
/// once. `pairs[0]`'s low lane must already carry the running `Y`.
#[inline(always)]
fn ghash_group8(hp: &[(__m256i, __m256i); 4], state: __m128i, pairs: [__m256i; 4]) -> __m128i {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        let ypair = _mm256_set_m128i(_mm_setzero_si128(), state);
        let mut acc = [_mm256_setzero_si256(); 4];
        mul_add2(
            &mut acc,
            _mm256_xor_si256(pairs[0], ypair),
            hp[3].0,
            hp[3].1,
        );
        mul_add2(&mut acc, pairs[1], hp[2].0, hp[2].1);
        mul_add2(&mut acc, pairs[2], hp[1].0, hp[1].1);
        mul_add2(&mut acc, pairs[3], hp[0].0, hp[0].1);
        <__m128i as Lanes>::reduce(combine(acc))
    }
}

/// The eight blocks of a group, loaded pairwise from the 128 bytes they cover.
#[inline(always)]
fn load_pairs(g: &[[u8; 16]; 8]) -> [__m256i; 4] {
    // SAFETY: each pair is 32 contiguous bytes of the group's 128, live for
    // the call; `_mm256_loadu_si256` is unaligned.
    unsafe {
        [
            _mm256_loadu_si256(g[0..].as_ptr().cast()),
            _mm256_loadu_si256(g[2..].as_ptr().cast()),
            _mm256_loadu_si256(g[4..].as_ptr().cast()),
            _mm256_loadu_si256(g[6..].as_ptr().cast()),
        ]
    }
}

/// The four ciphertext pairs of a group, stored back pairwise.
#[inline(always)]
fn store_pairs(g: &mut [[u8; 16]; 8], pairs: [__m256i; 4]) {
    // SAFETY: each pair is 32 contiguous bytes of the group's 128, live for
    // the call; `_mm256_storeu_si256` is unaligned.
    unsafe {
        for (pair, g2) in pairs.iter().zip(g.as_chunks_mut::<2>().0.iter_mut()) {
            _mm256_storeu_si256(g2.as_mut_ptr().cast(), *pair);
        }
    }
}

/// The bytes the group loop covered, counted before the buffer is split.
#[inline(always)]
fn grouped(blocks: &[[u8; 16]]) -> usize {
    blocks.len() / 8 * 128
}

impl Engine {
    /// Expand the key and build the `H` powers, both widths.
    ///
    /// # Safety
    ///
    /// `AVX2`, `VAES`, `VPCLMULQDQ` (and the 128-bit trio the tail uses) must
    /// be present. The only caller is [`super::Aes128Gcm::new`], which probes
    /// exactly those first.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn new(key: &[u8; 16]) -> Self {
        let rk = super::x86::expand(key);
        // The broadcast is a safe call here: this function carries `avx2`.
        let rk2 = rk.map(|k| _mm256_broadcastsi128_si256(k));
        let h = super::powers(&rk);
        // The group's pairs want `H^1..H^8`; the tail's four are computed,
        // the rest are one multiply each.
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let pair = |early: (__m128i, __m128i), late: (__m128i, __m128i)| {
            // The earlier block of a pair is the low lane and takes the higher
            // power; `_mm256_set_m128i` names the high lane first. Safe calls:
            // the closure shares this function's features.
            (
                _mm256_set_m128i(late.0, early.0),
                _mm256_set_m128i(late.1, early.1),
            )
        };
        let h5 = (h5, h5.xor(h5.swap_halves()));
        let h6 = (h6, h6.xor(h6.swap_halves()));
        let h7 = (h7, h7.xor(h7.swap_halves()));
        let h8 = (h8, h8.xor(h8.swap_halves()));
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, rk2, h, hp }
    }

    /// The fused eight-block loop, then the 128-bit module's own tail.
    #[inline(always)]
    fn ctr_ghash8(
        &self,
        template: __m128i,
        mut state: __m128i,
        buf: &mut [u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        // SAFETY: every load and store below is of a group inside `buf`, live
        // for the call; the rest are pure register ops under the caller's
        // `target_feature`.
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (blocks, _) = buf.as_chunks_mut::<16>();
            let done = grouped(blocks);
            let (groups, _) = blocks.as_chunks_mut::<8>();
            let mut ctr = 2u32;
            for g in groups {
                let mut ks = ctr8v(template2, ctr);
                encrypt8(&self.rk2, &mut ks);
                let pt = load_pairs(g);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                store_pairs(g, pairs);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            // The tail is the 128-bit module's: same arithmetic, narrower
            // registers, over the bytes the group loop left.
            super::ctr_ghash(
                &self.rk,
                &self.h,
                template,
                state,
                &mut buf[done..],
                tailq,
                ctr,
            )
        }
    }

    /// The ciphertext's `GHASH` pass: the group kernel without the `CTR` half,
    /// then the 128-bit module's tail.
    #[inline(always)]
    fn ghash8(&self, mut state: __m128i, data: &[u8], tailq: &mut super::Tail<__m128i>) -> __m128i {
        // Each load is of a pair inside `data` (see `load_pairs`), live for
        // the call; the helpers carry their own safety notes.
        let (blocks, _) = data.as_chunks::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks::<8>();
        for g in groups {
            let pt = load_pairs(g);
            state = ghash_group8(
                &self.hp,
                state,
                [bswap2(pt[0]), bswap2(pt[1]), bswap2(pt[2]), bswap2(pt[3])],
            );
        }
        super::ghash(&self.h, state, &data[done..], tailq)
    }

    /// Seal, on this engine's lanes.
    ///
    /// # Safety
    ///
    /// As [`Engine::new`]: the probe at construction covers the features.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ctr_ghash8(template, state, buf, &mut tailq);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        )
    }

    /// Open, on this engine's lanes.
    ///
    /// # Safety
    ///
    /// As [`Engine::new`]: the probe at construction covers the features.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        // The tag is computed over the ciphertext as it arrived and checked
        // before any byte is decrypted.
        let state = self.ghash8(state, buf, &mut tailq);
        let want = super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        );

        // Every byte, always: the running time must not say how much of a
        // forged tag was right.
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return None;
        }

        // Every load and store below is of a group inside `buf` (see
        // `load_pairs`/`store_pairs`), live for the call, and every call is a
        // safe one under this function's own features.
        let template2 = _mm256_broadcastsi128_si256(template);
        let (blocks, _) = buf.as_chunks_mut::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks_mut::<8>();
        let mut ctr = 2u32;
        for g in groups {
            let mut ks = ctr8v(template2, ctr);
            encrypt8(&self.rk2, &mut ks);
            let pt = load_pairs(g);
            let pairs = [
                _mm256_xor_si256(ks[0], pt[0]),
                _mm256_xor_si256(ks[1], pt[1]),
                _mm256_xor_si256(ks[2], pt[2]),
                _mm256_xor_si256(ks[3], pt[3]),
            ];
            store_pairs(g, pairs);
            ctr += 8;
        }
        super::ctr_only(&self.rk, template, &mut buf[done..], ctr);
        Some(buf.len())
    }
}

/// The `AES-256` per-key state: fifteen round keys in both widths, the `H`
/// powers for the tail, and the overlap powers for the eight-block groups.
pub(crate) struct Engine256 {
    rk: [__m128i; 15],
    rk2: [__m256i; 15],
    h: [(__m128i, __m128i); 4],
    hp: [(__m256i, __m256i); 4],
}

impl Engine256 {
    /// Expand the key in both widths and build the `H` powers, both sets.
    ///
    /// # Safety
    ///
    /// `AVX2`, `VAES`, `VPCLMULQDQ` (and the 128-bit trio the tail uses) must
    /// be present. The only caller is [`super::Aes256Gcm::new`], which probes
    /// exactly those first.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn new(key: &[u8; 32]) -> Self {
        let rk = super::x86::expand256(key);
        let rk2 = rk.map(|k| _mm256_broadcastsi128_si256(k));
        let h = super::powers_256(&rk);
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let pair = |early: (__m128i, __m128i), late: (__m128i, __m128i)| {
            (
                _mm256_set_m128i(late.0, early.0),
                _mm256_set_m128i(late.1, early.1),
            )
        };
        let h5 = (h5, h5.xor(h5.swap_halves()));
        let h6 = (h6, h6.xor(h6.swap_halves()));
        let h7 = (h7, h7.xor(h7.swap_halves()));
        let h8 = (h8, h8.xor(h8.swap_halves()));
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, rk2, h, hp }
    }

    /// The fused eight-block loop on `AES-256`, then the 128-bit module's tail.
    #[inline(always)]
    fn ctr_ghash8_256(
        &self,
        template: __m128i,
        mut state: __m128i,
        buf: &mut [u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        // SAFETY: every load and store below is of a group inside `buf`, live
        // for the call; the rest are pure register ops under the caller's
        // `target_feature`.
        unsafe {
            let template2 = _mm256_broadcastsi128_si256(template);
            let (blocks, _) = buf.as_chunks_mut::<16>();
            let done = grouped(blocks);
            let (groups, _) = blocks.as_chunks_mut::<8>();
            let mut ctr = 2u32;
            for g in groups {
                let mut ks = ctr8v(template2, ctr);
                encrypt8_256(&self.rk2, &mut ks);
                let pt = load_pairs(g);
                let pairs = [
                    _mm256_xor_si256(ks[0], pt[0]),
                    _mm256_xor_si256(ks[1], pt[1]),
                    _mm256_xor_si256(ks[2], pt[2]),
                    _mm256_xor_si256(ks[3], pt[3]),
                ];
                store_pairs(g, pairs);
                state = ghash_group8(
                    &self.hp,
                    state,
                    [
                        bswap2(pairs[0]),
                        bswap2(pairs[1]),
                        bswap2(pairs[2]),
                        bswap2(pairs[3]),
                    ],
                );
                ctr += 8;
            }
            super::ctr_ghash_256(
                &self.rk,
                &self.h,
                template,
                state,
                &mut buf[done..],
                tailq,
                ctr,
            )
        }
    }

    /// Seal, on this engine's lanes.
    ///
    /// # Safety
    ///
    /// As [`Engine256::new`]: the probe at construction covers the features.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v_256(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ctr_ghash8_256(template, state, buf, &mut tailq);
        super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        )
    }

    /// Open, on this engine's lanes.
    ///
    /// # Safety
    ///
    /// As [`Engine256::new`]: the probe at construction covers the features.
    #[target_feature(enable = "avx2,vaes,vpclmulqdq,aes,pclmulqdq,ssse3")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<__m128i>(nonce);
        let mask = <__m128i as Lanes>::encrypt1v_256(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <__m128i as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = self.ghash8_256(state, buf, &mut tailq);
        let want = super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        );
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return None;
        }
        let template2 = _mm256_broadcastsi128_si256(template);
        let (blocks, _) = buf.as_chunks_mut::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks_mut::<8>();
        let mut ctr = 2u32;
        for g in groups {
            let mut ks = ctr8v(template2, ctr);
            encrypt8_256(&self.rk2, &mut ks);
            let pt = load_pairs(g);
            let pairs = [
                _mm256_xor_si256(ks[0], pt[0]),
                _mm256_xor_si256(ks[1], pt[1]),
                _mm256_xor_si256(ks[2], pt[2]),
                _mm256_xor_si256(ks[3], pt[3]),
            ];
            store_pairs(g, pairs);
            ctr += 8;
        }
        super::ctr_only_256(&self.rk, template, &mut buf[done..], ctr);
        Some(buf.len())
    }

    /// The ciphertext's `GHASH` pass, on `AES-256`'s powers: key-independent
    /// arithmetic, only the powers differ.
    #[inline(always)]
    fn ghash8_256(
        &self,
        mut state: __m128i,
        data: &[u8],
        tailq: &mut super::Tail<__m128i>,
    ) -> __m128i {
        let (blocks, _) = data.as_chunks::<16>();
        let done = grouped(blocks);
        let (groups, _) = blocks.as_chunks::<8>();
        for g in groups {
            let pt = load_pairs(g);
            state = ghash_group8(
                &self.hp,
                state,
                [bswap2(pt[0]), bswap2(pt[1]), bswap2(pt[2]), bswap2(pt[3])],
            );
        }
        super::ghash(&self.h, state, &data[done..], tailq)
    }
}
