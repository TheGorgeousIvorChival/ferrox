//! The `aarch64` backend: `AESE`/`AESMC` for the `CTR` half, `PMULL` for the
//! `GHASH` half, eight blocks in flight.
//!
//! The eight-block head is the same arrangement the `VAES` path runs on
//! `x86_64`: every group does two lanes per register row, and a single
//! reduction covers all eight products. There is no two-hundred-fifty-six-bit
//! NEON type, so the two `uint8x16_t` lanes travel together as the pair
//! [`P`]. The group powers [`Engine::hp`] are the `H^1..H^8` ladder the
//! higher lanes demand, with the two of each pair at their own even/odd
//! power. The neutral signature of the change with the four-block route is
//! that the lumped accumulator is the sum (over `GF(2)`)'s individual
//! products, and reduction is linear over that sum.
//!
//! # Where the arithmetic comes from
//!
//! The `GHASH` kernel is transcribed from the `polyval` crate's `pmull.rs`:
//! the two-step Karatsuba (`karatsuba1` / `karatsuba2`) and the Montgomery
//! reduction with the `POLYVAL` polynomial, which is what `aes-gcm`'s `GHASH`
//! runs on this architecture. As on `x86_64`, the one change is structural:
//! the crate reduces after every block, and [`super::Lanes`] accumulates the
//! unreduced `(lo, hi)` products and reduces once per group — exact, because
//! reduction is linear.
//!
//! The `AES` rounds are the `aes` crate's `armv8` round structure: nine
//! `AESE`+`AESMC` pairs over the first nine round keys, a bare `AESE` with the
//! ninth, and the `XOR` with the tenth — `AESE` applies its round key *before*
//! `SubBytes`/`ShiftRows`, which is what makes that order the spec's order. The
//! key expansion is the `aes` crate's word recursion, with `SubWord` computed
//! by one `AESE` against a zero key, which on a word broadcast to all four
//! lanes is the S-box applied to the four bytes.
//!
//! # What keeps this honest
//!
//! Same as `x86.rs`: Miri cannot interpret these intrinsics; the contract with
//! [`super::Lanes`] is checked by the differential sweep against the `aes-gcm`
//! crate at every length.

use super::Lanes;
// Glob-imported on purpose: see `x86.rs` for the reasoning.
#[allow(clippy::wildcard_imports)]
use core::arch::aarch64::*;

/// The per-key state: the eleven round keys and the four `H` powers, each
/// paired with its Karatsuba middle-term constant `h ^ swap_halves(h)`.
pub(crate) struct Engine {
    /// `AES-128`'s eleven round keys, in `AESE` order.
    rk: [uint8x16_t; 11],
    /// `H^1 .. H^4` in the reflected representation, each as `(h, h ^ swap(h))`.
    h: [(uint8x16_t, uint8x16_t); 4],
    /// The eight-block group's powers, per half-lane: entry 3 is `(H^8, H^7)`,
    /// entry 0 is `(H^2, H^1)`, each with its `h ^ swap(h)`.
    hp: [(P, P); 4],
}

/// The `GHASH` tables, as [`Engine`] and [`Engine256`] hold them.
///
/// Both engines carry the same two tables — `H^1..H^4` and the eight-block group's
/// power ladder — and differ only in their round keys, which are eleven lanes for
/// `AES-128` and fifteen for `AES-256`. `ctr_ghash8`, `ctr_ghash8_256` and
/// `ghash8` are shared by both and want the tables alone, so they take this rather
/// than one engine and a `match` on which it was. It is also what took the
/// argument count back under the lint's bar: the two table parameters were two
/// fields of the same struct.
trait GhashTables {
    /// `H^1 .. H^4` in the reflected representation, each as `(h, h ^ swap(h))`.
    fn h(&self) -> &[(uint8x16_t, uint8x16_t); 4];
    /// The eight-block group's powers, per half-lane.
    fn hp(&self) -> &[(P, P); 4];
}

/// Two `uint8x16_t` lanes side by side: NEON has no two-hundred-fifty-six-bit
/// register type, so the eight-block head keeps the two lanes of a group row
/// together explicitly. `lo` is the earlier block of the pair.
#[derive(Clone, Copy)]
pub(crate) struct P {
    /// The earlier block's lane.
    lo: uint8x16_t,
    /// The later block's lane.
    hi: uint8x16_t,
}

/// `bswap` on both halves of a [`P`], block-wise.
#[inline(always)]
fn bswap_p(p: P) -> P {
    P {
        lo: <uint8x16_t as Lanes>::bswap(p.lo),
        hi: <uint8x16_t as Lanes>::bswap(p.hi),
    }
}

/// One group row's two product sums into [`P`] accumulators: the 128-bit
/// [`Lanes::mul_add`], doubled per half.
#[inline(always)]
fn mul_add_p(acc: &mut [[uint8x16_t; 4]; 2], a: P, h: P, hxs: P) {
    // The 128-bit [`Lanes::mul_add`], doubled per half.
    <uint8x16_t as Lanes>::mul_add(&mut acc[0], a.lo, h.lo, hxs.lo);
    <uint8x16_t as Lanes>::mul_add(&mut acc[1], a.hi, h.hi, hxs.hi);
}

/// Combine the two lanes' accumulators into the 128-bit accumulator the
/// reduction consumes: the unreduced products summed across lanes, the same
/// total, as linearity requires.
#[inline(always)]
fn combine_p(acc: [[uint8x16_t; 4]; 2]) -> [uint8x16_t; 4] {
    [
        <uint8x16_t as Lanes>::xor(acc[0][0], acc[1][0]),
        <uint8x16_t as Lanes>::xor(acc[0][1], acc[1][1]),
        <uint8x16_t as Lanes>::xor(acc[0][2], acc[1][2]),
        <uint8x16_t as Lanes>::xor(acc[0][3], acc[1][3]),
    ]
}

/// Eight blocks of the Horner chain as one reduction: the four pair-products
/// accumulate per lane, the lanes combine, and the 128-bit reduction runs
/// once. `pairs[0]`'s low lane must already carry the running `Y`.
///
/// # Safety
///
/// The `NEON` primitives reached through [`mul_add_p`] and
/// [`<uint8x16_t as Lanes>::reduce`] are `#[target_feature(enable = "aes,neon")]`,
/// and every path into this body arrives through an `Engine` or `Engine256`
/// method carrying that same attribute, behind the probe in [`Engine::new`].
#[inline(always)]
fn ghash_group8(hp: &[(P, P); 4], state: uint8x16_t, pairs: [P; 4]) -> uint8x16_t {
    // SAFETY: as the doc above; the operands are registers this function's own
    // caller holds, so nothing here loads or stores through a pointer.
    unsafe {
        let mut acc = [[vdupq_n_u8(0); 4]; 2];
        let ypair = P {
            lo: state,
            hi: vdupq_n_u8(0),
        };
        mul_add_p(
            &mut acc,
            P {
                lo: <uint8x16_t as Lanes>::xor(pairs[0].lo, ypair.lo),
                hi: <uint8x16_t as Lanes>::xor(pairs[0].hi, ypair.hi), // pairs[0].hi ^ 0
            },
            hp[3].0,
            hp[3].1,
        );
        mul_add_p(&mut acc, pairs[1], hp[2].0, hp[2].1);
        mul_add_p(&mut acc, pairs[2], hp[1].0, hp[1].1);
        mul_add_p(&mut acc, pairs[3], hp[0].0, hp[0].1);
        <uint8x16_t as Lanes>::reduce(combine_p(acc))
    }
}

/// Four ciphertext counter blocks per side, eight altogether: the two
/// four-block runs under one [`Lanes::ctr_add`]/`ctr_swap` chain, as
/// [`super`]'s own `ctr4v` is to [`super::ctr_ghash`].
#[inline(always)]
fn ctr8v_p(template: uint8x16_t, ctr: u32) -> [[uint8x16_t; 4]; 2] {
    let c0 = template.ctr_add(ctr).ctr_swap();
    let c1 = template.ctr_add(ctr + 1).ctr_swap();
    let c2 = template.ctr_add(ctr + 2).ctr_swap();
    let c3 = template.ctr_add(ctr + 3).ctr_swap();
    let c4 = template.ctr_add(ctr + 4).ctr_swap();
    let c5 = template.ctr_add(ctr + 5).ctr_swap();
    let c6 = template.ctr_add(ctr + 6).ctr_swap();
    let c7 = template.ctr_add(ctr + 7).ctr_swap();
    [[c0, c1, c2, c3], [c4, c5, c6, c7]]
}

/// The eight blocks of a group, loaded block at a time as [`P`] pairs.
#[inline(always)]
fn load_pairs(g: &[[u8; 16]; 8]) -> [P; 4] {
    [
        P {
            lo: <uint8x16_t as Lanes>::load(&g[0]),
            hi: <uint8x16_t as Lanes>::load(&g[1]),
        },
        P {
            lo: <uint8x16_t as Lanes>::load(&g[2]),
            hi: <uint8x16_t as Lanes>::load(&g[3]),
        },
        P {
            lo: <uint8x16_t as Lanes>::load(&g[4]),
            hi: <uint8x16_t as Lanes>::load(&g[5]),
        },
        P {
            lo: <uint8x16_t as Lanes>::load(&g[6]),
            hi: <uint8x16_t as Lanes>::load(&g[7]),
        },
    ]
}

/// The four ciphertext pairs of a group, stored back pairwise.
#[inline(always)]
fn store_pairs(g: &mut [[u8; 16]; 8], pairs: [P; 4]) {
    pairs[0].lo.store(&mut g[0]);
    pairs[0].hi.store(&mut g[1]);
    pairs[1].lo.store(&mut g[2]);
    pairs[1].hi.store(&mut g[3]);
    pairs[2].lo.store(&mut g[4]);
    pairs[2].hi.store(&mut g[5]);
    pairs[3].lo.store(&mut g[6]);
    pairs[3].hi.store(&mut g[7]);
}

/// `PMULL` of the low 64-bit lanes.
#[inline(always)]
fn pmull(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // SAFETY: pure register op; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry. The
    // `u128` product and `uint8x16_t` are both sixteen bytes.
    unsafe {
        core::mem::transmute::<u128, uint8x16_t>(vmull_p64(
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(a)),
            vgetq_lane_u64::<0>(vreinterpretq_u64_u8(b)),
        ))
    }
}

/// `PMULL` of the high 64-bit lanes.
#[inline(always)]
fn pmull2(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    // SAFETY: as above.
    unsafe {
        core::mem::transmute::<u128, uint8x16_t>(vmull_p64(
            vgetq_lane_u64::<1>(vreinterpretq_u64_u8(a)),
            vgetq_lane_u64::<1>(vreinterpretq_u64_u8(b)),
        ))
    }
}

/// The Karatsuba combine: `(lo, mid, hi)` products into the unreduced 256-bit
/// product as its two 128-bit halves, transcribed from `pmull.rs`.
#[inline(always)]
fn karatsuba2(h: uint8x16_t, m: uint8x16_t, l: uint8x16_t) -> (uint8x16_t, uint8x16_t) {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        let t = {
            let t0 = veorq_u8(m, vextq_u8::<8>(l, h));
            let t1 = veorq_u8(h, l);
            veorq_u8(t0, t1)
        };
        let x01 = vextq_u8::<8>(vextq_u8::<8>(l, l), t);
        let x23 = vextq_u8::<8>(t, vextq_u8::<8>(h, h));
        (x23, x01)
    }
}

impl Lanes for uint8x16_t {
    #[inline(always)]
    fn load(b: &[u8; 16]) -> Self {
        // SAFETY: `vld1q_u8` reads 16 bytes, unaligned; `b` is a 16-byte
        // array, live for the call.
        unsafe { vld1q_u8(b.as_ptr()) }
    }

    #[inline(always)]
    fn store(self, b: &mut [u8; 16]) {
        // SAFETY: `vst1q_u8` writes 16 bytes, unaligned; `b` is a 16-byte
        // array, live for the call.
        unsafe { vst1q_u8(b.as_mut_ptr(), self) }
    }

    #[inline(always)]
    fn xor(self, o: Self) -> Self {
        // SAFETY: pure register op; the feature cover is the caller's
        // `target_feature` function, reached only through the probed entry.
        unsafe { veorq_u8(self, o) }
    }

    #[inline(always)]
    fn bswap(self) -> Self {
        // Reverse the bytes of each 64-bit half, then exchange the halves: a
        // full sixteen-byte reversal.
        //
        // SAFETY: as above.
        unsafe {
            let r = vrev64q_u8(self);
            vextq_u8::<8>(r, r)
        }
    }

    #[inline(always)]
    fn swap_halves(self) -> Self {
        // SAFETY: as above.
        unsafe { vextq_u8::<8>(self, self) }
    }

    #[inline(always)]
    fn mul_add(acc: &mut [Self; 4], a: Self, h: Self, hxs: Self) {
        // The crate's `karatsuba1` with the `h`-side middle term precomputed
        // per power at setup — `hxs` is `h ^ swap(h)` — then the crate's
        // `karatsuba2`. The unreduced `(x01, x23)` product accumulates into
        // `acc[0]`/`acc[1]`; `acc[2..4]` stay zero, unused by `reduce` below.
        //
        // SAFETY: pure register ops; the feature cover is the caller's
        // `target_feature` function, reached only through the probed entry.
        unsafe {
            let m = pmull(veorq_u8(a, vextq_u8::<8>(a, a)), hxs);
            let hh = pmull2(a, h);
            let ll = pmull(a, h);
            let (x23, x01) = karatsuba2(hh, m, ll);
            acc[0] = veorq_u8(acc[0], x01);
            acc[1] = veorq_u8(acc[1], x23);
        }
    }

    #[inline(always)]
    fn reduce(acc: [Self; 4]) -> Self {
        // The crate's Montgomery reduction over the 256-bit `X`, verbatim:
        // `[A1:A0] = X0 * poly`, `[B] = [X0 ^ A1 : X1 ^ A0]`,
        // `[C] = B0 * poly`, out `[D1 ^ X3 : D0 ^ X2]`.
        //
        // SAFETY: pure register ops; the feature cover is the caller's
        // `target_feature` function, reached only through the probed entry.
        unsafe {
            let poly = vreinterpretq_u8_p128(
                (1u128 << 127)
                    | (1u128 << 126)
                    | (1u128 << 121)
                    | (1u128 << 63)
                    | (1u128 << 62)
                    | (1u128 << 57),
            );
            let x01 = acc[0];
            let x23 = acc[1];
            let a = pmull(x01, poly);
            let b = veorq_u8(x01, vextq_u8::<8>(a, a));
            let c = pmull2(b, poly);
            veorq_u8(x23, veorq_u8(c, b))
        }
    }

    #[inline(always)]
    fn ctr_add(self, n: u32) -> Self {
        // `n` lands in lane 3 alone: a broadcast would add it to the nonce's
        // lanes too.
        //
        // SAFETY: pure register op; the feature cover is the caller's
        // `target_feature` function, reached only through the probed entry.
        unsafe {
            vreinterpretq_u8_u32(vaddq_u32(
                vreinterpretq_u32_u8(self),
                vsetq_lane_u32::<3>(n, vdupq_n_u32(0)),
            ))
        }
    }

    #[inline(always)]
    fn ctr_swap(self) -> Self {
        /// The counter mask: the nonce's twelve bytes untouched, the
        /// counter's four reversed.
        const MASK: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 14, 13, 12];
        // SAFETY: as above. `vld1q_u8` reads the 16-byte mask constant.
        unsafe { vqtbl1q_u8(self, vld1q_u8(MASK.as_ptr())) }
    }

    #[inline(always)]
    fn encrypt4(rk: &[Self; 11], s: &mut [Self; 4]) {
        // Four independent chains: the `aes` crate's round structure, nine
        // fused `AESE`+`AESMC` pairs, the bare `AESE`, the final `XOR`.
        //
        // SAFETY: pure register ops; the feature cover is the caller's
        // `target_feature` function, reached only through the probed entry.
        unsafe {
            for k in &rk[..9] {
                for lane in s.iter_mut() {
                    *lane = vaesmcq_u8(vaeseq_u8(*lane, *k));
                }
            }
            for lane in s.iter_mut() {
                *lane = veorq_u8(vaeseq_u8(*lane, rk[9]), rk[10]);
            }
        }
    }

    #[inline(always)]
    fn encrypt1v(rk: &[Self; 11], mut s: Self) -> Self {
        // SAFETY: pure register ops under the caller's `target_feature`.
        unsafe {
            for k in &rk[..9] {
                s = vaesmcq_u8(vaeseq_u8(s, *k));
            }
            veorq_u8(vaeseq_u8(s, rk[9]), rk[10])
        }
    }

    #[inline(always)]
    fn encrypt4_256(rk: &[Self; 15], s: &mut [Self; 4]) {
        // Fourteen rounds: thirteen fused `AESE`+`AESMC` pairs, the bare
        // `AESE`, the final `XOR`.
        // SAFETY: `vaeseq_u8`, `vaesmcq_u8` and `veorq_u8` are `core::arch::aarch64`
        // intrinsics with no preconditions beyond their operands being `uint8x16_t`
        // values, which every lane of `s` and every `Self` in `rk` already is. They
        // write no memory and read no pointer, so there is nothing for the caller to
        // have got wrong. `rk` is `&[Self; 15]` and the loop stops at index 13, so the
        // fifteenth key is the one that closes the cipher rather than one past the end.
        unsafe {
            for k in &rk[..13] {
                for lane in s.iter_mut() {
                    *lane = vaesmcq_u8(vaeseq_u8(*lane, *k));
                }
            }
            for lane in s.iter_mut() {
                *lane = veorq_u8(vaeseq_u8(*lane, rk[13]), rk[14]);
            }
        }
    }

    #[inline(always)]
    fn encrypt1v_256(rk: &[Self; 15], mut s: Self) -> Self {
        // SAFETY: as `encrypt4_256` above, over one lane rather than four. `rk` is
        // `&[Self; 15]` and the loop stops at index 13.
        unsafe {
            for k in &rk[..13] {
                s = vaesmcq_u8(vaeseq_u8(s, *k));
            }
            veorq_u8(vaeseq_u8(s, rk[13]), rk[14])
        }
    }
}

/// The fused eight-block loop: `CTR`-encrypt `buf` in place and queue the
/// ciphertext's `GHASH` blocks through [`ghash_group8`], once per eight
/// blocks, each block consumed from the register it was produced in. The
/// arithmetic is [`super::ctr_ghash`]'s, widened.
///
/// `ghash` is a [`GhashTables`] rather than the two `GHASH` tables: it took eight
/// arguments, and two of them were fields of one struct three lines apart.
#[inline(always)]
fn ctr_ghash8(
    rk: &[uint8x16_t; 11],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    buf: &mut [u8],
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (blocks, _rest_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        store_pairs(g, ct);
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    // The tail is the four-block module's: same arithmetic, same state
    // channel, over the bytes the eight-block loop left.
    super::ctr_ghash(rk, h, template, state, &mut buf[done * 16..], tailq, ctr)
}

/// The `open` half's first pass over the ciphertext, eight blocks per
/// reduction: the queued-tail and partial-block discipline of [`super::ghash`].
#[inline(always)]
fn ghash8(
    ghash: &impl GhashTables,
    mut state: uint8x16_t,
    data: &[u8],
    tail: &mut super::Tail<uint8x16_t>,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (blocks, _rest_bytes) = data.as_chunks::<16>();
    let (groups, _rest) = blocks.as_chunks::<8>();
    let done = groups.len() * 8;
    for g in groups {
        let mut pairs = load_pairs(g);
        for p in &mut pairs {
            *p = bswap_p(*p);
        }
        state = ghash_group8(hp, state, pairs);
    }
    // The remainder takes the four-block module's grouping, which is also
    // where a section's under-eight tail is queued for [`super::flush`].
    super::ghash(h, state, &data[done * 16..], tail)
}

/// The open half's second pass, eight blocks per round: the counters walk
/// the buffer again and turn it into plaintext.
#[inline(always)]
fn ctr_only8(rk: &[uint8x16_t; 11], template: uint8x16_t, buf: &mut [u8], mut ctr: u32) {
    let (blocks, _tail_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(pair.lo, ks[i / 2][i % 2 * 2]);
            pair.hi = <uint8x16_t as Lanes>::xor(pair.hi, ks[i / 2][i % 2 * 2 + 1]);
        }
        store_pairs(g, ct);
        ctr += 8;
    }
    super::ctr_only(rk, template, &mut buf[done * 16..], ctr);
}

/// `SubWord` for the key expansion: one `AESE` against a zero key applies the
/// S-box to the word's four bytes, because a word broadcast to all four lanes
/// is unchanged by `ShiftRows`. The `aes` crate's `expand.rs` trick, copied.
#[inline(always)]
fn sub_word(w: u32) -> u32 {
    // SAFETY: pure register ops; the feature cover is the caller's
    // `target_feature` function, reached only through the probed entry.
    unsafe {
        let v = vreinterpretq_u8_u32(vdupq_n_u32(w));
        let s = vaeseq_u8(v, vdupq_n_u8(0));
        vgetq_lane_u32::<0>(vreinterpretq_u32_u8(s))
    }
}

/// The fused eight-block loop, `AES-256`'s fifteen round keys.
#[inline(always)]
fn ctr_ghash8_256(
    rk: &[uint8x16_t; 15],
    ghash: &impl GhashTables,
    template: uint8x16_t,
    mut state: uint8x16_t,
    buf: &mut [u8],
    tailq: &mut super::Tail<uint8x16_t>,
    mut ctr: u32,
) -> uint8x16_t {
    let (h, hp) = (ghash.h(), ghash.hp());
    let (blocks, _rest_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2], pair.lo);
            pair.hi = <uint8x16_t as Lanes>::xor(ks[i / 2][i % 2 * 2 + 1], pair.hi);
        }
        store_pairs(g, ct);
        state = ghash_group8(
            hp,
            state,
            [
                bswap_p(ct[0]),
                bswap_p(ct[1]),
                bswap_p(ct[2]),
                bswap_p(ct[3]),
            ],
        );
        ctr += 8;
    }
    super::ctr_ghash_256(rk, h, template, state, &mut buf[done * 16..], tailq, ctr)
}

/// The open half's second pass, eight blocks per round, `AES-256`.
#[inline(always)]
fn ctr_only8_256(rk: &[uint8x16_t; 15], template: uint8x16_t, buf: &mut [u8], mut ctr: u32) {
    let (blocks, _tail_bytes) = buf.as_chunks_mut::<16>();
    let (groups, _rest_blocks) = blocks.as_chunks_mut::<8>();
    let done = groups.len() * 8;
    for g in groups.iter_mut() {
        let mut ks = ctr8v_p(template, ctr);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[0]);
        <uint8x16_t as Lanes>::encrypt4_256(rk, &mut ks[1]);
        let mut ct = load_pairs(g);
        for (i, pair) in ct.iter_mut().enumerate() {
            pair.lo = <uint8x16_t as Lanes>::xor(pair.lo, ks[i / 2][i % 2 * 2]);
            pair.hi = <uint8x16_t as Lanes>::xor(pair.hi, ks[i / 2][i % 2 * 2 + 1]);
        }
        store_pairs(g, ct);
        ctr += 8;
    }
    super::ctr_only_256(rk, template, &mut buf[done * 16..], ctr);
}

impl Engine {
    /// Expand the key and build the `H` powers.
    ///
    /// # Safety
    ///
    /// The `AES` and `PMULL` (`neon`) extensions must be present. The only
    /// caller is [`super::Aes128Gcm::new`], which probes both first.
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn new(key: &[u8; 16]) -> Self {
        /// `AES-128`'s ten round constants.
        const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
        // The word recursion from "The Rijndael Block Cipher" section 4.1 with
        // `Nk = 4`: `w[i] = w[i-4] ^ (w[i-1] rotated and substituted, on every
        // fourth word)`.
        let mut words = [0u32; 44];
        for (i, w) in words[..4].iter_mut().enumerate() {
            *w = u32::from_ne_bytes(key[4 * i..4 * i + 4].try_into().expect("a word is 4 bytes"));
        }
        for i in 4..44 {
            let mut w = words[i - 1];
            if i % 4 == 0 {
                w = sub_word(w).rotate_right(8) ^ RCON[i / 4 - 1];
            }
            words[i] = words[i - 4] ^ w;
        }
        let rk: [uint8x16_t; 11] = core::array::from_fn(|r| {
            let mut b = [0u8; 16];
            // A new stable lint reads the constant `4` here as an invitation to
            // `as_chunks_mut::<4>()`, which is the same loop with a different type in
            // the tuple. Rewriting an AES round-key expansion to satisfy a style lint
            // trades a readable loop for a lifetime-indexed slice in a hot primitive,
            // so the lint is allowed here instead -- with the loop as it was, which
            // the byte-identity gates cover.
            #[allow(clippy::chunks_exact_to_as_chunks)]
            for (wb, w) in b.chunks_exact_mut(4).zip(words[4 * r..4 * r + 4].iter()) {
                wb.copy_from_slice(&w.to_ne_bytes());
            }
            // SAFETY: `vld1q_u8` reads 16 bytes, unaligned; `b` is a 16-byte
            // array, live for the call.
            unsafe { vld1q_u8(b.as_ptr()) }
        });
        let h = super::powers(&rk);
        // The group's pairs want `H^1..H^8`; the tail's four are computed,
        // the rest are one multiply each.
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let h5 = (h5, <uint8x16_t as Lanes>::xor(h5, h5.swap_halves()));
        let h6 = (h6, <uint8x16_t as Lanes>::xor(h6, h6.swap_halves()));
        let h7 = (h7, <uint8x16_t as Lanes>::xor(h7, h7.swap_halves()));
        let h8 = (h8, <uint8x16_t as Lanes>::xor(h8, h8.swap_halves()));
        let pair = |early: (uint8x16_t, uint8x16_t), late: (uint8x16_t, uint8x16_t)| -> (P, P) {
            (
                P {
                    lo: early.0,
                    hi: late.0,
                },
                P {
                    lo: early.1,
                    hi: late.1,
                },
            )
        };
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, h, hp }
    }

    /// Seal, on this engine's lanes.
    ///
    /// # Safety
    ///
    /// As [`Engine::new`]: the probe at construction covers the features.
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<uint8x16_t>(nonce);
        // `J0` is the template's counter at 1; the mask is independent of the
        // message, so it is issued first and overlaps the loop.
        let mask = <uint8x16_t as Lanes>::encrypt1v(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ctr_ghash8(&self.rk, self, template, state, buf, &mut tailq, 2);
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
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ghash8(self, state, buf, &mut tailq);
        let want = super::finish(
            &self.h,
            state,
            &mut tailq,
            aad.len() as u64,
            buf.len() as u64,
            mask,
        );

        // Every byte, always: the running time must not say how much of a forged
        // tag was right, and `want == tag` would say exactly that.
        let mut diff = 0u8;
        for (a, b) in want.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return None;
        }

        ctr_only8(&self.rk, template, buf, 2);
        Some(buf.len())
    }
}

/// The `AES-256` session state: fifteen round keys and the `H` powers.
pub(crate) struct Engine256 {
    rk: [uint8x16_t; 15],
    h: [(uint8x16_t, uint8x16_t); 4],
    hp: [(P, P); 4],
}

impl GhashTables for Engine {
    fn h(&self) -> &[(uint8x16_t, uint8x16_t); 4] {
        &self.h
    }
    fn hp(&self) -> &[(P, P); 4] {
        &self.hp
    }
}

impl GhashTables for Engine256 {
    fn h(&self) -> &[(uint8x16_t, uint8x16_t); 4] {
        &self.h
    }
    fn hp(&self) -> &[(P, P); 4] {
        &self.hp
    }
}

impl Engine256 {
    /// Expand the key and build the `H` powers.
    ///
    /// # Safety
    ///
    /// The `AES` and `PMULL` (`neon`) extensions must be present. The only
    /// caller is [`super::Aes256Gcm::new`], which probes both first.
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn new(key: &[u8; 32]) -> Self {
        /// `AES-256`'s seven used round constants.
        const RCON: [u32; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
        let mut words = [0u32; 60];
        for (i, w) in words[..8].iter_mut().enumerate() {
            *w = u32::from_ne_bytes(key[4 * i..4 * i + 4].try_into().expect("a word is 4 bytes"));
        }
        for i in 8..60 {
            let mut w = words[i - 1];
            if i % 8 == 0 {
                w = sub_word(w).rotate_right(8) ^ RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                w = sub_word(w);
            }
            words[i] = words[i - 8] ^ w;
        }
        let rk: [uint8x16_t; 15] = core::array::from_fn(|r| {
            let mut b = [0u8; 16];
            #[allow(clippy::chunks_exact_to_as_chunks)]
            for (wb, w) in b.chunks_exact_mut(4).zip(words[4 * r..4 * r + 4].iter()) {
                wb.copy_from_slice(&w.to_ne_bytes());
            }
            // SAFETY: `vld1q_u8` reads 16 bytes, unaligned; `b` is a
            // 16-byte array, live for the call.
            unsafe { vld1q_u8(b.as_ptr()) }
        });
        let h = super::powers_256(&rk);
        let h5 = super::mul1(h[3].0, h[0]);
        let h6 = super::mul1(h[3].0, h[1]);
        let h7 = super::mul1(h[3].0, h[2]);
        let h8 = super::mul1(h[3].0, h[3]);
        let h5 = (h5, <uint8x16_t as Lanes>::xor(h5, h5.swap_halves()));
        let h6 = (h6, <uint8x16_t as Lanes>::xor(h6, h6.swap_halves()));
        let h7 = (h7, <uint8x16_t as Lanes>::xor(h7, h7.swap_halves()));
        let h8 = (h8, <uint8x16_t as Lanes>::xor(h8, h8.swap_halves()));
        let pair = |early: (uint8x16_t, uint8x16_t), late: (uint8x16_t, uint8x16_t)| -> (P, P) {
            (
                P {
                    lo: early.0,
                    hi: late.0,
                },
                P {
                    lo: early.1,
                    hi: late.1,
                },
            )
        };
        let hp = [
            pair(h[1], h[0]),
            pair(h[3], h[2]),
            pair(h6, h5),
            pair(h8, h7),
        ];
        Self { rk, h, hp }
    }

    /// Seal, on this engine's lanes.
    ///
    /// # Safety
    ///
    /// As [`Engine256::new`]: the probe at construction covers the features.
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v_256(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ctr_ghash8_256(&self.rk, self, template, state, buf, &mut tailq, 2);
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
    #[target_feature(enable = "aes,neon")]
    pub(crate) unsafe fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        let template = super::counter_template::<uint8x16_t>(nonce);
        let mask = <uint8x16_t as Lanes>::encrypt1v_256(&self.rk, template.ctr_add(1).ctr_swap());
        let mut tailq = super::Tail::new();
        let state = super::ghash(
            &self.h,
            <uint8x16_t as Lanes>::load(&[0u8; 16]),
            aad,
            &mut tailq,
        );
        let state = super::flush(&self.h, state, &mut tailq);
        let state = ghash8(self, state, buf, &mut tailq);
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
        ctr_only8_256(&self.rk, template, buf, 2);
        Some(buf.len())
    }
}
