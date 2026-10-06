//! `Poly1305`, in three limbs of 44, 44 and 42 bits, on one portable path.
//!
//! # Why this is here
//!
//! `ChaCha20-Poly1305` is the data cipher `VMess` negotiates, and on `aarch64`
//! the `chacha20poly1305` crate runs it at 0.45 GB/s — because the `chacha20`
//! crate underneath it will not select its own NEON backend, so the keystream
//! half runs one dependent chain at a time. [`crate::aead`] pairs this with the
//! keystream core in [`crate::record`], which does the same twenty rounds at
//! 2.14 GB/s on the same machine.
//!
//! Gate 7b is what says how much is left to win here, and it says `Poly1305` is
//! 32-63% of an `RFC 8439` seal — and on `linux aarch64` the *majority* of it
//! from 256 bytes up, at 0.74 ns per byte against the keystream half's 0.41. It
//! was the slower of the two halves on the one architecture that had a vectorised
//! path for it.
//!
//! # The arithmetic
//!
//! The accumulator is `h mod (2^130 - 5)`, which is 130 bits and does not fit a
//! `u128`. It is held as three limbs of 44, 44 and 42 bits.
//!
//! The modulus is not a division. `x * r mod (2^130 - 5)` is computed as
//! `x * r` and then folded: the carry out of the top limb is multiplied by five
//! and added back at the bottom, because `2^130 = 5 (mod p)`. That is the whole
//! reduction.
//!
//! # Why 44 and not 26
//!
//! This file used to hold five 26-bit limbs, chosen so that one limb-pair
//! product plus a carried-in value stays inside a `u64`. That choice is sound and
//! it is expensive: it costs **twenty-five** `u64` products per sixteen-byte
//! block, and the old version of this header named its own wall — *"the wall is
//! products per cycle rather than code"*.
//!
//! Three 44-bit limbs hold the same 130 bits, and their **nine** products each
//! fit a `u128`, so the widening is one hardware instruction (`mulx`, `umulh`,
//! `UMULL`) instead of the source spelling it as two narrower multiplies and a
//! shift. Nine against twenty-five is the whole change, and it is arithmetic
//! rather than scheduling: nothing about the loop got cleverer.
//!
//! The second effect is that the fold stops being a chain. A 26-bit carry out of
//! limb `i` has to be in limb `i+1` before limb `i+1`'s product is known, so the
//! five multiply-accumulates are serialised against each other and a wide core
//! has nothing independent to issue between them. That is why the `aarch64`
//! two-way `NEON` path this file carried for years bought about 10% — it was
//! vectorising a recurrence it could not break, and the measurement that finally
//! settled it was gate 7b rather than another micro-optimisation.
//!
//! # What was tried and measured against this
//!
//! Three changes that a careful reader would suggest, all measured on an `M2`
//! against the **26-bit** accumulator and all *not* here, so that they do not get
//! proposed again:
//!
//! * **Fusing the two halves of the `AEAD`** — xoring each chunk of keystream
//!   and absorbing that chunk's ciphertext in one loop, so the two dependency
//!   chains sit in the reorder window together. The chains are independent, so
//!   this ought to turn the sum of the two halves into the larger of them. It
//!   does not: it is 20% *slower* at 256-byte chunks and no different at 512.
//!   Each chunk is a real call into `record::fill_exact`, and the two halves do
//!   not co-issue across it.
//! * **Pairing the products of each accumulator into a tree** instead of summing
//!   them left to right, to shorten the dependency chain. No measurable
//!   difference; the scheduler was already doing as well as the tree allows.
//! * **Stride-two Horner with a precomputed `r^2`** — regrouping two steps
//!   `(h + m0) * r^2 + m1 * r`, the same fifty products per pair but one fold
//!   instead of two. The regrouping is correct by construction (one fold of a sum
//!   is `((x mod p) + y) mod p`) and the oracle sweep agreed at every pair
//!   boundary, but it is slower where it counts: 1024 bytes at 778 ns against
//!   683 ns, 128 bytes at 89 ns against 83 ns, 8 KB at 5376 ns against 5529 ns
//!   (noise). The mechanism is registers: the five accumulators are scalars and
//!   live in registers across the block, while the regrouping holds two blocks'
//!   worth — about thirty-eight live values against thirty-odd usable registers —
//!   and spills. Factoring the block into array helpers cost the 16-byte path
//!   alone 14 ns to 28 ns, `#[inline(always)]` included.
//!
//! All three are *still* not worth trying, and the reason is sharper now than it
//! was: they are all rearrangements of a recurrence whose cost was its width.
//! Nine products is a different problem from twenty-five.
//!
//! The `aarch64` two-way `NEON` path is the fourth entry and the only one that
//! was ever *in* this file. It is gone, and [`tag_via_26_bit_horner`] is what
//! replaced it as this file's second implementation — not a vector path, the old
//! scalar one, kept whole because it is the only thing that can say whether the
//! three-limb rewrite is faster. See [`crate::aead`]'s gate 7c.
//!
//! # What is not claimed
//!
//! That this is faster than every other `Poly1305`. It is faster than the one
//! `VMess` was using, by the margin gate 7c measures, and it is bit-identical to
//! it at every length and every offset — which is the only claim that lets it be
//! swapped in at all.

/// Forty-four ones: the mask that keeps a limb inside `2^44`.
///
/// The limb width is not arbitrary. `2^44` is chosen so that the product of two
/// full limbs is `2^88`, which is below `2^128` with room for the three-way sum
/// the multiply folds into each of the three outputs — so every product in the
/// block loop is one hardware `64`-by-`64`-into-`128` instruction rather than a
/// widening pair of narrower multiplies. The five 26-bit limbs this replaced
/// needed twenty-five products per block to keep the same property; three limbs
/// need nine, and the ninth is the only one that crosses the top of the product.
const LIMB_MASK: u64 = (1 << 44) - 1;

/// [`LIMB_MASK`] with its top two bits clear: limb 2 is 42 bits wide, because
/// `2^42 * 2^88 = 2^130` and the modulus is `2^130 - 5`.
const LIMB2_MASK: u64 = (1 << 42) - 1;

/// The bit that stands in for `2^128` on every block that is not the last.
///
/// Bit 40 of limb 2. `2^128 = 2^40 * 2^88`, and limb 2 is the one that starts at
/// `2^88`, so this is the only place the message's implicit high bit fits in a
/// limb. A final partial block does not carry it: the `0x01` byte after the last
/// real byte of the message supplies it there instead.
const HIBIT: u64 = 1 << 40;

/// The low half of the clamp.
///
/// `r` as one 128-bit mask is `0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff`, and
/// these two constants are its two halves. They are *not* equal, and that is the
/// whole reason there are two of them: bits 0..31 of `r` are the low word and
/// keep 28 bits, while bits 32..63, 64..95 and 96..127 keep 26 each. The two
/// extra bits in the low word are real — `2^128` is above `2^130`, so `r`'s low
/// bits are not special — and masking all four words alike leaves bits 58, 59,
/// 90, 91, 122 and 123 of `r` set. Everything downstream of that stays
/// perfectly self-consistent and every tag is wrong.
const CLAMP_LO: u64 = 0x0fff_fffc_0fff_ffff;

/// `CLAMP_LO`'s other half: words one, two and three, twenty-six bits each.
const CLAMP_HI: u64 = 0x0fff_fffc_0fff_fffc;

/// Limb 2's low forty bits: everything below bit 128.
///
/// The complement of [`HIBIT`], and the reason the reduction below has to name
/// it. `h2 << 88` inside a `u128` is *not* `h2` moved up — a `u128` has no bits
/// at 128 and 129, so the shift silently throws away `h2`'s top two, and the
/// accumulator is off by up to `2^130` with nothing to show for it.
const LOW_40: u64 = (1 << 40) - 1;

/// Whole-block bytes at or above which `aarch64` hands the run to the two-way
/// `NEON` path instead of the three-limb loop below.
///
/// # Why there is a threshold at all
///
/// The three-limb accumulator is nine widening products per block where the
/// twenty-five of the five 26-bit ones were. That is a win on every runner that
/// has to issue them one at a time, and it is a loss on one that retires two per
/// instruction: `vmull`/`vmlal` are two `32`-by-32 products each, so the `NEON`
/// path's twenty-five come out as thirteen instructions against the scalar loop's
/// nine. Measured, drift-normalised by gate 7b's unchanged `chacha20 keystream`
/// control, run `37266252879` against run `37288184258`:
///
/// | runner | 64 B | 256 B | 1 KiB | 4 KiB | 16 KiB |
/// | --- | ---: | ---: | ---: | ---: | ---: |
/// | `windows x86_64` | 1.31x | 1.37x | 1.31x | 1.34x | 1.34x |
/// | `linux x86_64` | 1.36x | 1.34x | 1.35x | 1.36x | 1.36x |
/// | `linux aarch64` | 1.29x | 1.24x | 1.18x | 1.08x | 1.05x |
/// | `macos aarch64` | 1.61x | 1.55x | **0.88x** | **0.68x** | **0.81x** |
///
/// The three rows are wins everywhere. The fourth is the one that is not: the
/// three limbs win below a kilobyte and lose 12-32% above it, and that loss is
/// what turned `macos aarch64`'s gate 7 `4096 B` seal row red.
///
/// # Why 512
///
/// The crossover on `macos aarch64` is between 256 B and 1 KiB — three limbs at
/// 1.55x, `NEON` at 0.88x — so the threshold sits at 512, the midpoint rounded
/// down to the block size. Below it the three limbs are ahead on every runner
/// (`1.24x` on `linux aarch64`, `1.55x` on `macos`, both sides of 1.3x on x86),
/// and above it the `NEON` path is ahead on the core that has the two-lane
/// multiply, which is the only place this costs anything: `linux aarch64` gives
/// up the 1.05x-1.18x it held from 1 KiB up, and `macos aarch64` gets the 1.18x
/// it lost.
///
/// # Why nothing dispatches here any more
///
/// That table is about the *five* 26-bit limbs, and the read above put the
/// threshold between the three-limb chain and a vector path that was losing at
/// 1 KiB and 4 KiB on `macos aarch64`. The four-way absorb then changed the
/// question: it wins 36% over this file's own scalar stride-two at 4 KiB and
/// 16 KiB on `macos aarch64` (gate 7c, `3.00x`/`3.19x` against two same-code
/// controls reading `2.06x`/`2.28x` and `2.29x`/`2.39x`), and loses in the band
/// below it — `1.39x` at 1 KiB where the same-code controls read `1.51x` and
/// `1.92x`.
///
/// So the two-way path is no longer on the dispatch: at 512 B and above the
/// scalar stride-two loop runs until [`NEON4_THRESHOLD_BYTES`], and the vector
/// four-way path takes over there. The code stays, under `cfg(test)`, because
/// `the_neon_halves_are_the_three_limbs_at_every_length_around_the_threshold`
/// is the test that holds it to the three limbs — a path that is not shipped
/// should not be the one path in this file with no test.
///
/// `aarch64`-only, so no other architecture carries the constant, the powers or
/// the branch.
#[cfg(all(test, target_arch = "aarch64"))]
const NEON_THRESHOLD_BYTES: usize = 512;

/// Whole-block bytes at or above which the run goes to the stride-two loop
/// below instead of the one-block chain.
///
/// # Why stride two is a different problem from the one that failed before
///
/// [`Poly1305::absorb`]'s chain is `h <- (h + m) * r`, folded after every
/// block: the multiply of block `i + 1` cannot start until the fold of block
/// `i` finishes, and that latency is most of the loop. Two steps of the chain
/// re-associate to `(h + m0) * r^2 + m1 * r`, whose two multiplies are
/// *independent* — and whose folds fuse into one, because the fold is exact
/// arithmetic mod `p`: `fold(a) + fold(b)` and `fold(a + b)` agree mod `p`,
/// and the loop's own bounds keep every intermediate inside the range
/// [`reduce`] accepts. So a pair costs one fold instead of two and the two
/// multiply chains pipeline through the reorder window: the serial part of a
/// pair is close to the serial part of one block.
///
/// The previous attempt at this regrouping — recorded in this file's header —
/// failed on registers: it regrouped the *five* 26-bit accumulators, which is
/// about thirty-eight live values against the register file, and it spilled.
/// Three 44-bit limbs put the same regrouping at about two dozen.
///
/// `r^2` is one extra multiply per call, so the threshold is where the saved
/// folds outgrow it: a handful of blocks, rounded up to a full pair.
///
/// # Why every architecture, and why 128
///
/// This loop is scalar — `u128` products, no intrinsics — so nothing in it is
/// architecture-specific, and the four-way absorb removed the last reason to
/// keep it off `x86_64`: with the vector paths gated at [`NEON4_THRESHOLD_BYTES`]
/// and [`AVX2_THRESHOLD_BYTES`] there is nothing between the one-block chain and
/// this loop, and on `x86_64` the one-block chain is what a 128 B-4 KiB run used
/// to get after the four-way absorb replaced `PAIR_FROM` with an `aarch64`-only
/// gate. That cost `x86_64` 9% at 256 B and 5% at 1 KiB against the same-code
/// controls (`1.53x`/`1.49x` there, `1.37x`/`1.38x` on the branch), and 128 is
/// the threshold the scalar pair loop shipped with.
const STRIDE2_THRESHOLD_BYTES: usize = 128;

/// Whole-block bytes at or above which `aarch64` hands the run to the two-lane
/// path below instead of the scalar stride-two one.
///
/// # Why this exists, and what it cost to lose it
///
/// The four-way absorb deleted the two-lane loop that used to own this band, on
/// the evidence that it won at 4 KiB and 16 KiB. It took the band with it:
/// [`NEON4_THRESHOLD_BYTES`] starts at 4096, and the one scalar loop left below
/// it is a **single** chain, so 1 KiB fell from two lanes to one.
///
/// Measured on `linux aarch64` at gate 7c, reading the `3x44` column against its
/// unchanged 26-bit horner control across runs `37386799470`, `37387574166`,
/// `37388229170`, `37389269340` and `37389237345`. At 1 KiB the control reads
/// `612.4 612.0 612.2 612.2 612.9` — flat to three significant figures —
/// while `3x44` reads `435.7 435.7 437.0 435.9 557.9`, so the last row is
/// **+28%** against a control that did not move. `macos aarch64` has the same
/// shape with a noisier control (`326.0` against `504.5`).
///
/// The gate could not see it in either direction, which is the point worth
/// keeping: gate 7c's bar is a ratio against that 26-bit reference, and `557.9`
/// against `612.4` is `1.10x`, comfortably above the `0.95x` bar. A regression
/// this size passes because the thing it is measured against got slower too.
/// Reading the absolute column beside its own control is what caught it, and it
/// is why [`NEON4_THRESHOLD_BYTES`] is argued from crossing points rather than
/// from a ratio.
///
/// 1024 is the threshold the deleted loop shipped with and the first length the
/// gates measure inside the band, so it is the one the evidence supports rather
/// than the one that would be tidier.
#[cfg(target_arch = "aarch64")]
const TWO_LANE_THRESHOLD_BYTES: usize = 1024;

/// Whole-block bytes at or above which `aarch64` hands the run to the
/// four-way path below instead of the scalar stride-two one.
///
/// Same re-association as [`AVX2_THRESHOLD_BYTES`]: four lane-chains with
/// `r^4` as the multiplier, *multiply-then-add*, one fold per four blocks.
/// `NEON`'s widening multiply retires two scalar products per instruction
/// against `AVX2`'s four, so the win here is the quartered fold and the
/// deeper pipeline rather than the instruction count — the powers and the
/// combine are the same per-call cost, and the threshold is where the saved
/// folds outgrow them, which the gates measure per length.
///
/// # Why 4096 and not 2048
///
/// The gates measure the accumulator at 64 B, 256 B, 1 KiB, 4 KiB and 16 KiB, and
/// against same-code controls the four-way path wins at 4 KiB and 16 KiB and
/// loses below them (`linux x86_64` `1.81x`/`1.87x` at 4/16 KiB against
/// `1.69x`/`1.67x` and `1.61x`/`1.68x`; `macos aarch64` `3.00x`/`3.19x` against
/// `2.06x`/`2.28x` and `2.29x`/`2.39x`). 4096 is the first measured length that
/// wins. 2048 is not measured at all, so putting the threshold there would be
/// claiming a crossover nobody can see: the row that would justify it does not
/// exist in any report.
#[cfg(target_arch = "aarch64")]
const NEON4_THRESHOLD_BYTES: usize = 4096;

/// The twenty-six ones of the five-limb representation, which is what the
/// vector paths below work in.
///
/// Not [`LIMB_MASK`]: the same name in two widths is the sort of thing that reads
/// as interchangeable and is not, so the narrow one is spelled here and the
/// vector path is the only thing that refers to it.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const M26: u64 = 0x03ff_ffff;

/// [`M26`] at the width the five 26-bit limbs are stored in.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const M26_U32: u32 = 0x03ff_ffff;

/// The `2^128` bit in the five 26-bit limbs: bit 24 of limb 4, which is bit 128
/// of the block.
///
/// The same bit as [`HIBIT`], in a different width. Keeping them as two named
/// constants rather than deriving one from the other is deliberate: a block that
/// takes the `NEON` path carries this one, and it is compared against the
/// dispatch condition on the way in.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
const HIBIT26: u32 = 1 << 24;

/// A 130-bit value as `(bits 0..128, bits 128..130)`, reduced below `2^130`.
///
/// Both vector architectures: the only callers are [`to_26`] and [`from_26`].
///
/// # Why a repack needs this at all
///
/// Five 26-bit limbs hold 130 bits, and neither end of the repack is guaranteed
/// to be inside them. [`reduce`]'s own assertion says the three-limb loop can
/// leave limb 2 one above its mask, which is a value of exactly `2^130`; and
/// [`add_three_normalized`] — the `NEON` combine — leaves limb 1 one bit wide,
/// which puts the value a shade past `2^130` the other way. A repack that assumed
/// the value fitted dropped a whole `2^128` or `2^130` on the way through, and
/// every tag on `aarch64` was then wrong by a multiple of `2^128` — which is not
/// a multiple of `p`, so the other three architectures would never have noticed.
/// The limb-edge test found it on the first run in CI.
///
/// Subtracting `p` is discarding the `2^130` and adding five. `p` in this split is
/// `(3, 2^128 - 5)`, so "at or above `p`" is `over` above three, or `over == 3`
/// with a `low` that carries when five is added; the subtraction is then `+ 5` and
/// `- 2^130`, which is why `over` moves by four and not by one — `over` counts
/// `2^128`s, not `2^130`s.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn reduce_split(mut low: u128, mut over: u64) -> (u128, u64) {
    while over >= 4 || (over == 3 && low.overflowing_add(5).1) {
        let (sum, carry) = low.overflowing_add(5);
        low = sum;
        over = over + u64::from(carry) - 4;
    }
    (low, over)
}

/// The three-limb accumulator as five 26-bit limbs, for the `NEON` path.
///
/// Both vector architectures: the only callers are the vector absorbs.
///
/// Exact — the same integer in a different radix, put inside 130 bits by
/// [`reduce_split`] first. What makes it worth a test of its own is that neither
/// half is a shift: `h1` straddles the 64-bit line of the value, and limb 4
/// crosses bit 128, which is where a `u128` stops having bits.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn to_26(h: [u64; 3]) -> [u32; 5] {
    // Step one of `reduce` again: the loop's fold leaves limb 1 one bit wide, and
    // bit 44 of limb 1 is bit 0 of limb 2.
    let top = h[2] + (h[1] >> 44);
    let (wide, over) = reduce_split(
        u128::from(h[0]) | (u128::from(h[1] & LIMB_MASK) << 44) | (u128::from(top & LOW_40) << 88),
        top >> 40,
    );
    [
        (wide as u64 & M26) as u32,
        ((wide >> 26) as u64 & M26) as u32,
        ((wide >> 52) as u64 & M26) as u32,
        ((wide >> 78) as u64 & M26) as u32,
        ((wide >> 104) as u32 & 0x00ff_ffff) | ((over as u32) << 24),
    ]
}

/// Five 26-bit limbs back into three, the inverse of [`to_26`].
///
/// The `NEON` combine leaves limb 1 unmasked — 27 bits, the same deliberate
/// over-width the scalar five-limb loop leaves and `add_three_normalized`
/// documents — and limb 1's bit 26 is **value bit 52, which is limb 2's bit 0**.
/// So the limbs cannot be or-ed together: or-ing two fields that both claim bit
/// 52 keeps one where the value has two, and the accumulator comes out short by
/// `2^52`. The carry is propagated first, and the fields are only combined once
/// each owns its bits exclusively.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn from_26(h: [u32; 5]) -> [u64; 3] {
    let mut wide = u128::from(h[0]);
    let mut carry = u64::from(h[1] >> 26);
    wide += u128::from(h[1] & M26_U32) << 26;
    let mut limb2 = u64::from(h[2]) + carry;
    carry = limb2 >> 26;
    limb2 &= M26;
    wide += u128::from(limb2) << 52;
    let mut limb3 = u64::from(h[3]) + carry;
    carry = limb3 >> 26;
    limb3 &= M26;
    wide += u128::from(limb3) << 78;
    let limb4 = u64::from(h[4]) + carry;
    wide += u128::from(limb4 & 0x00ff_ffff) << 104;
    let (wide, over) = reduce_split(wide, limb4 >> 24);
    [
        (wide as u64) & LIMB_MASK,
        ((wide >> 44) as u64) & LIMB_MASK,
        (((wide >> 88) as u64) & LIMB2_MASK) | ((over & 0x3) << 40),
    ]
}

/// Whole-block bytes at or above which `x86_64` hands the run to the
/// four-way `AVX2` path below instead of the one-block chain.
///
/// # The shape, and why it is the same theorem again
///
/// The one-block chain is `h <- (h + m) * r` with a fold per block; four
/// steps re-associate to `h * r^4 + m0 * r^4 + m1 * r^3 + m2 * r^2 + m3 * r`,
/// whose four products are independent and whose folds fuse into one, because
/// the fold is exact arithmetic mod `p`. The four products run as four
/// `u32 x u32 -> u64` lanes of `vpmuludq` — the block's five limbs are the
/// lanes of five `ymm`, so one instruction retires four blocks' worth of one
/// limb-product, and the fold's carry chain runs once per four blocks.
///
/// `r^4` is the lanes' multiplier; `r^2` and `r^3` are the combine's other
/// weights; all three are computed once per call. A call whose accumulator is
/// still zero — every `VMess` and `shadowsocks` frame's one absorb — skips the
/// `r^n` term and its exponentiation, because `0 * r^n` is `0`.
///
/// The threshold is where the saved folds outgrow the powers and the combine,
/// which the gates measure per length; below it the scalar stride-two loop runs.
///
/// 4096 rather than 2048 for the reason [`NEON4_THRESHOLD_BYTES`] gives: 4 KiB
/// is the first length at which the four-way path beats the same-code controls
/// on either architecture, and 2048 is a length no gate measures.
#[cfg(target_arch = "x86_64")]
const AVX2_THRESHOLD_BYTES: usize = 4096;

/// The 26-bit fold on two 64-bit lanes at once: the scalar fold's carries,
/// each instruction covering both lanes — limb one left a bit wide, the same
/// shape the scalar loop leaves.
///
/// `aarch64`-only: the only callers are the `NEON` absorbs.
#[cfg(target_arch = "aarch64")]
#[inline]
#[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
fn fold64(
    d0: core::arch::aarch64::uint64x2_t,
    mut d1: core::arch::aarch64::uint64x2_t,
    mut d2: core::arch::aarch64::uint64x2_t,
    mut d3: core::arch::aarch64::uint64x2_t,
    mut d4: core::arch::aarch64::uint64x2_t,
    mask64: core::arch::aarch64::uint64x2_t,
) -> (
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
    core::arch::aarch64::uint64x2_t,
) {
    use core::arch::aarch64::*;
    // SAFETY: shifts, ands and adds are register-only; `NEON` is baseline on
    // `aarch64`.
    unsafe {
        let c = vshrq_n_u64::<26>(d0);
        let o0 = vandq_u64(d0, mask64);
        d1 = vaddq_u64(d1, c);
        let c = vshrq_n_u64::<26>(d1);
        let o1 = vandq_u64(d1, mask64);
        d2 = vaddq_u64(d2, c);
        let c = vshrq_n_u64::<26>(d2);
        let o2 = vandq_u64(d2, mask64);
        d3 = vaddq_u64(d3, c);
        let c = vshrq_n_u64::<26>(d3);
        let o3 = vandq_u64(d3, mask64);
        d4 = vaddq_u64(d4, c);
        let c = vshrq_n_u64::<26>(d4);
        let o4 = vandq_u64(d4, mask64);
        // `w = o0 + 5 * c`, limb zero masked, `w >> 26` into limb one.
        let wrapped = vaddq_u64(o0, vaddq_u64(vshlq_n_u64::<2>(c), c));
        let h0 = vandq_u64(wrapped, mask64);
        let h1 = vaddq_u64(o1, vshrq_n_u64::<26>(wrapped));
        (h0, h1, o2, o3, o4)
    }
}

/// The four-way combine, shared by both vector absorbs.
///
/// `lanes[j]` is lane `j`'s accumulator, whose chain advanced by `r^4` per
/// lane-step over `k` steps, and the lane weights are `r^4, r^3, r^2, r` — the
/// re-associated form of the `4k` serial steps. `h_in` is the caller's
/// accumulator in the three-limb form, or zero: a zero accumulator skips the
/// `r^(4k)` term and its exponentiation, which is the hot path's shape (every
/// `VMess` and `shadowsocks` frame absorbs once, from zero).
///
/// The powers are the per-call work: `r^2`, `r^3` and `r^4` are three field
/// multiplications, `r^(4k)` a short exponentiation when it is needed.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn combine4(
    h_in: [u64; 3],
    lanes: &[[u32; 5]; 4],
    r26: &[u32; 5],
    powers: &[[u32; 5]; 3],
    k: usize,
) -> [u64; 3] {
    let (r2, r3, r4) = (&powers[0], &powers[1], &powers[2]);
    let t0 = field_mul(&lanes[0], r4);
    let t1 = field_mul(&lanes[1], r3);
    let t2 = field_mul(&lanes[2], r2);
    let t3 = field_mul(&lanes[3], r26);
    let t4 = if h_in == [0; 3] {
        [0u32; 5]
    } else {
        field_mul(&to_26(h_in), &field_pow(*r4, k))
    };
    let joined = add_three_normalized(&add_three_normalized(&t0, &t1, &t2), &t3, &t4);
    from_26(joined)
}

/// `r^2`, `r^3` and `r^4`, in that order — the four-way's lane weights and
/// lane multiplier, three field multiplications per call.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn powers4(r26: &[u32; 5]) -> [[u32; 5]; 3] {
    let r2 = field_mul(r26, r26);
    let r3 = field_mul(&r2, r26);
    let r4 = field_mul(&r2, &r2);
    [r2, r3, r4]
}

/// `a * b mod (2^130 - 5)`, in the five 26-bit limbs the `NEON` path works in.
///
/// The multiply and the fold are the scalar loop's, without the `+ m`: `s_i` is
/// `5 * b_i` unreduced per limb rather than the limbs of `5 * b` reduced,
/// `w = o0 + 5 * c` rather than `4 * c`, and limb 1 is left unmasked the same way
/// [`to_26`]'s caller leaves it, because the result feeds another multiply.
///
/// Both vector architectures: the only callers are the vector combines and [`field_pow`].
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn field_mul(a: &[u32; 5], b: &[u32; 5]) -> [u32; 5] {
    let (r0, r1, r2, r3, r4) = (
        u64::from(b[0]),
        u64::from(b[1]),
        u64::from(b[2]),
        u64::from(b[3]),
        u64::from(b[4]),
    );
    let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
    let (h0, h1, h2, h3, h4) = (
        u64::from(a[0]),
        u64::from(a[1]),
        u64::from(a[2]),
        u64::from(a[3]),
        u64::from(a[4]),
    );
    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    let c = d0 >> 26;
    let o0 = d0 & M26;
    d1 += c;
    let c = d1 >> 26;
    let o1 = d1 & M26;
    d2 += c;
    let c = d2 >> 26;
    let o2 = d2 & M26;
    d3 += c;
    let c = d3 >> 26;
    let o3 = d3 & M26;
    d4 += c;
    let c = d4 >> 26;
    let o4 = d4 & M26;
    let wrapped = o0 + c * 5;
    [
        (wrapped as u32) & M26_U32,
        (o1 + (wrapped >> 26)) as u32,
        o2 as u32,
        o3 as u32,
        o4 as u32,
    ]
}

/// `base^exp mod (2^130 - 5)`, by binary exponentiation over [`field_mul`].
///
/// The exponent is a message length, which is public, so branching on its bits
/// is not a secret-dependent branch. `r` itself never branches.
///
/// Both vector architectures: the only callers are the vector combines.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn field_pow(mut base: [u32; 5], mut exp: usize) -> [u32; 5] {
    let mut acc = [0u32; 5];
    acc[0] = 1;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = field_mul(&acc, &base);
        }
        base = field_mul(&base, &base);
        exp >>= 1;
    }
    acc
}

/// `(a + b + c) mod (2^130 - 5)`, carried back into the five 26-bit limbs.
///
/// Each input is already reduced to at most 27 bits per limb, so their sum is at
/// most 29 bits per limb and still far from overflowing the next multiply's
/// `u64`s. One carry chain plus the top carry times five is therefore enough.
///
/// Both vector architectures: the only callers are the vector combines.
#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn add_three_normalized(a: &[u32; 5], b: &[u32; 5], c: &[u32; 5]) -> [u32; 5] {
    let mut v = [
        u64::from(a[0]) + u64::from(b[0]) + u64::from(c[0]),
        u64::from(a[1]) + u64::from(b[1]) + u64::from(c[1]),
        u64::from(a[2]) + u64::from(b[2]) + u64::from(c[2]),
        u64::from(a[3]) + u64::from(b[3]) + u64::from(c[3]),
        u64::from(a[4]) + u64::from(b[4]) + u64::from(c[4]),
    ];
    let mut carry = v[0] >> 26;
    v[0] &= M26;
    v[1] += carry;
    carry = v[1] >> 26;
    v[1] &= M26;
    v[2] += carry;
    carry = v[2] >> 26;
    v[2] &= M26;
    v[3] += carry;
    carry = v[3] >> 26;
    v[3] &= M26;
    v[4] += carry;
    carry = v[4] >> 26;
    v[4] &= M26;
    let wrapped = v[0] + carry * 5;
    [
        (wrapped as u32) & M26_U32,
        (v[1] + (wrapped >> 26)) as u32,
        v[2] as u32,
        v[3] as u32,
        v[4] as u32,
    ]
}

/// One accumulator plus the key it is keyed with.
///
/// `h` is the running value mod `p`; `r` and `pad` come from the key once and
/// are never touched again, because a data frame is one accumulator over one
/// key and rebuilding either per block would be per-block work for constants.
///
/// # Why three limbs and not five
///
/// The 26-bit basis this replaced was chosen so that one limb-pair product plus
/// a carried-in value stays inside a `u64`. It achieves that at the price of
/// twenty-five products per sixteen-byte block, and the file's own header names
/// that as the wall: *"the wall is products per cycle rather than code"*. Three
/// limbs of 44, 44 and 42 bits hold the same 130 bits, and their nine products
/// each fit a `u128`, so the hardware does the widening instead of the source
/// spelling it as two narrower multiplies and a shift.
///
/// `s1` and `s2` are `r` times twenty, folded once per message. They exist
/// because the 130-bit product has limbs 3 and 4 past the modulus: `2^132` is
/// `2^2 * 2^130`, and `2^130 = 5 (mod p)`, so `2^132 = 20 (mod p)`. The limb-3
/// terms (`h1*r2`, `h2*r1`) land at `2^132` and fold into limb 0 by twenty, and
/// the single limb-4 term (`h2*r2`) lands at `2^176 = 2^44 * 2^132` and so folds
/// into limb 1 by twenty. That is why `s2` appears in *both* `d0` and `d1`.
#[derive(Clone)]
pub struct Poly1305 {
    /// The clamped multiplier's limb 0, 44 bits.
    r0: u64,
    /// Its limb 1, 44 bits.
    r1: u64,
    /// Its limb 2, at most 36 bits: the clamp has cleared bits 124-127.
    r2: u64,
    /// `r1 * 20`, for the terms that cross the top of the 130-bit product.
    s1: u64,
    /// `r2 * 20`, likewise.
    s2: u64,
    /// The running accumulator, limbs of 44, 44 and 42 bits.
    h: [u64; 3],
    /// The low half of `key[16..32]`, added to the finished accumulator.
    pad: [u64; 2],
    /// Bytes of a block not yet consumed.
    buffer: [u8; 16],
    /// How much of `buffer` is live.
    held: usize,
}

impl core::fmt::Debug for Poly1305 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The accumulator only, not the key: printing `r` or `pad` would put a
        // one-time secret in a test failure message.
        f.debug_struct("Poly1305")
            .field("h", &self.h)
            .field("held", &self.held)
            .finish_non_exhaustive()
    }
}

impl Poly1305 {
    /// A fresh accumulator under `key`.
    ///
    /// The clamp is the specification's one 128-bit mask, applied as its two
    /// halves before `r` is split into limbs.
    ///
    /// The previous version masked all four 32-bit words with `0x0fff_ffff`,
    /// which reads as the obvious thing and is not: the mask is
    /// `0x0fff_ffff` for the low word and `0x0fff_fffc` for the three above it.
    /// See the comment on `CLAMP_LO` for why the words differ. The accumulator
    /// stays self-consistent under either, which is the trap — nothing in this
    /// file could have told the two apart except the clamp test, which checks
    /// the packed limbs against the one 128-bit constant rather than against
    /// this function's own shape.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        // Four loads by index rather than a `try_into().expect()` per word: a
        // 32-byte array indexed at constants has no failure case to document,
        // and `new` is off the block loop, so saying it plainly is free.
        let w0 = u64::from_le_bytes([
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        ]);
        let w1 = u64::from_le_bytes([
            key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
        ]);
        let w2 = u64::from_le_bytes([
            key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23],
        ]);
        let w3 = u64::from_le_bytes([
            key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31],
        ]);
        let lo = w0 & CLAMP_LO;
        let hi = w1 & CLAMP_HI;
        let r0 = lo & LIMB_MASK;
        let r1 = ((lo >> 44) | (hi << 20)) & LIMB_MASK;
        // `hi >> 24` is bits 88..127; the clamp cleared bits 124..127, so this is
        // at most 36 bits and fits the 42-bit limb with room for `h` to grow.
        let r2 = hi >> 24;
        Self {
            r0,
            r1,
            r2,
            s1: r1 * 20,
            s2: r2 * 20,
            h: [0; 3],
            pad: [w2, w3],
            buffer: [0; 16],
            held: 0,
        }
    }

    /// Absorb `data`.
    ///
    /// An empty `data` is a no-op, and returns before the prologue rather than
    /// reaching it. That is the common case rather than a corner: `RFC 8439`
    /// section 2.8 pads each `MAC` section to a block boundary with a second
    /// call, and when a section is already a multiple of sixteen — an empty
    /// `aad`, which is every `VMess` data frame — that padding is zero bytes.
    /// Both of those calls used to reach the absorb prologue on an empty slice,
    /// which reads the five limbs of `r`, widens them to `u64` and forms the four
    /// `5 * r_i` products before the loop discovers there is nothing to loop over.
    /// None of it can change `h`: with no whole block the loop body never runs and
    /// `self.h` is not written.
    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // A leftover block is completed rather than copied into the new data: the
        // two are one block, and building that block is four loads.
        if self.held > 0 {
            let take = data.len().min(16 - self.held);
            self.buffer[self.held..self.held + take].copy_from_slice(&data[..take]);
            self.held += take;
            data = &data[take..];
            if self.held < 16 {
                return;
            }
            let block = self.buffer;
            self.absorb(&block, HIBIT);
            self.held = 0;
        }
        let whole = data.len() / 16 * 16;
        self.absorb(&data[..whole], HIBIT);
        let rest = &data[whole..];
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.held = rest.len();
    }

    /// The sixteen-byte tag.
    #[must_use]
    pub fn finish(mut self) -> [u8; 16] {
        // A partial block gets a one byte after its last byte and zeros after
        // that — the 2^128 bit is *not* implicit here, because the padding byte
        // supplies it. Getting this backwards is the classic Poly1305 bug, and
        // the differential test covers every length that can reach it.
        if self.held > 0 {
            let n = self.held;
            self.buffer[n] = 1;
            for b in &mut self.buffer[n + 1..] {
                *b = 0;
            }
            let block = self.buffer;
            self.absorb(&block, 0);
        }

        let pad = u128::from(self.pad[0]) | (u128::from(self.pad[1]) << 64);

        let mut out = [0u8; 16];
        out.copy_from_slice(&reduce(self.h, pad).to_le_bytes());
        out
    }

    /// Every whole sixteen-byte block of `data`, times `r`, folded back mod `p`.
    ///
    /// # The block, in three limbs
    ///
    /// A block is two little-endian 64-bit words. Split at bit 44 rather than at
    /// 32, so the block crosses the limb boundary the same way `h` does:
    ///
    /// ```text
    ///            limb 0            limb 1            limb 2
    ///   t0        bits  0..43       bits 44..87       bits 88..127
    ///   t1                                       bits 88..127
    /// ```
    ///
    /// `t1`'s low 24 bits and `t0`'s high 20 bits are limb 1, which is the one
    /// place the split is not a copy. The message's implicit `2^128` goes into
    /// limb 2 at bit 40, the only position in any limb where it fits.
    ///
    /// # The multiply, in three products per output
    ///
    /// `h * r` is a 260-bit product folded down to 130. `d0`, `d1` and `d2` are
    /// its limbs 0, 1 and 2 with the limbs past the modulus — 3 and 4 — folded
    /// in by twenty, which is `2^132 mod p` and is why `s1` and `s2` are `r`
    /// times twenty rather than times five. Every term is one `u128` product of a
    /// 44-bit limb by a 44-bit constant.
    ///
    /// The loop is here rather than in [`Poly1305::update`] for the same reason
    /// the 26-bit version kept it there: with the multiply in a helper called
    /// once per block, `r` is reloaded across that call every sixteen bytes,
    /// which measured at about a tenth of the whole `AEAD` throughput. Here the
    /// loop carries the registers and `r` is widened once per message.
    ///
    /// The dispatch, and it is four branches:
    ///
    /// - a run of whole blocks at or above [`NEON4_THRESHOLD_BYTES`] on
    ///   `aarch64` goes to [`Poly1305::absorb_neon4`], and at or above
    ///   [`AVX2_THRESHOLD_BYTES`] on `x86_64` — `AVX2` probed — to
    ///   [`Poly1305::absorb_avx2`]. Both are the four-way path, and both
    ///   thresholds are the first length the gates measure where it wins.
    /// - a run at or above [`TWO_LANE_THRESHOLD_BYTES`] on `aarch64` goes to
    ///   [`Poly1305::absorb_two_lane`], which owns the band between the four-way
    ///   threshold and one pair: two stride-two lanes in lockstep, so the band
    ///   keeps the second dependency chain.
    /// - a run at or above [`STRIDE2_THRESHOLD_BYTES`] goes to
    ///   [`Poly1305::absorb_stride2`], on every architecture: scalar, two blocks
    ///   per fold, and the best single-chain loop in this file.
    /// - everything else — every architecture, every short message, and the final
    ///   padded block whose `hibit` is zero — stays on the one-block chain.
    ///
    /// The two-way `NEON` path is not on this list. It measured below its
    /// scalar replacement in the band it would own — the constant that used to
    /// put it there is 512 B and is kept under `cfg(test)`, where the test that
    /// holds it to the three limbs reads it — and the four-way path above wins
    /// at 4 KiB and 16 KiB.
    fn absorb(&mut self, data: &[u8], hibit: u64) {
        #[cfg(target_arch = "aarch64")]
        if hibit == HIBIT && data.len() >= NEON4_THRESHOLD_BYTES {
            self.absorb_neon4(data);
            return;
        }
        #[cfg(target_arch = "x86_64")]
        if hibit == HIBIT
            && data.len() >= AVX2_THRESHOLD_BYTES
            && std::is_x86_feature_detected!("avx2")
        {
            // SAFETY: the probe names the feature the path's `target_feature`
            // function carries.
            unsafe { self.absorb_avx2(data) };
            return;
        }
        #[cfg(target_arch = "aarch64")]
        if hibit == HIBIT && data.len() >= TWO_LANE_THRESHOLD_BYTES {
            self.absorb_two_lane(data);
            return;
        }
        if hibit == HIBIT && data.len() >= STRIDE2_THRESHOLD_BYTES {
            self.absorb_stride2(data);
            return;
        }
        self.absorb_one_block_chain(data, hibit);
    }

    /// The one-block chain: one `h * r + m` per sixteen bytes, one fold each.
    ///
    /// This is the loop every other loop in this file is measured against, so it
    /// is a named function rather than the tail of [`Poly1305::absorb`]. It has to
    /// be: the test that holds `absorb_stride2`, `absorb_two_lane`, `absorb_neon`
    /// and `absorb_neon4` to this chain reached it through `absorb`, and `absorb`
    /// **dispatches** — so from 1 KiB upward the test was handed
    /// `absorb_two_lane` as its own reference and compared the two-lane band with
    /// itself. A wrong band passed that test while failing end to end on every
    /// input. The reference must not be reachable only through the dispatcher that
    /// picks the subject.
    fn absorb_one_block_chain(&mut self, data: &[u8], hibit: u64) {
        let (r0, r1, r2, s1, s2) = (self.r0, self.r1, self.r2, self.s1, self.s2);
        let (mut h0, mut h1, mut h2) = (self.h[0], self.h[1], self.h[2]);

        let mut rest = data;
        while let Some(m) = rest.first_chunk::<16>() {
            let t0 = u64::from_le_bytes(m[0..8].try_into().expect("a whole 16-byte block"));
            let t1 = u64::from_le_bytes(m[8..16].try_into().expect("a whole 16-byte block"));

            h0 += t0 & LIMB_MASK;
            h1 += ((t0 >> 44) | (t1 << 20)) & LIMB_MASK;
            h2 += (t1 >> 24) & LIMB2_MASK;
            h2 += hibit;

            let (x0, x1, x2) = (h0 as u128, h1 as u128, h2 as u128);
            let (y0, y1, y2) = (r0 as u128, r1 as u128, r2 as u128);

            let d0 = x0 * y0 + x1 * (s2 as u128) + x2 * (s1 as u128);
            let mut d1 = x0 * y1 + x1 * y0 + x2 * (s2 as u128);
            let mut d2 = x0 * y2 + x1 * y1 + x2 * y0;

            // Partial fold: each limb's overflow goes to the next, and limb 2's
            // overflow goes back to limb 0 times five. `h` is left a few bits over
            // 130 bits — `h0` and `h2` masked, `h1` a bit wide — which costs the
            // loop one extra carry here and buys `finish` a reduction that fits
            // one `u128`. A block loop that finished the job itself would need the
            // second fold on every block instead, once per message.
            let c = (d0 >> 44) as u64;
            h0 = (d0 as u64) & LIMB_MASK;
            d1 += u128::from(c);
            let c = (d1 >> 44) as u64;
            h1 = (d1 as u64) & LIMB_MASK;
            d2 += u128::from(c);
            let c = (d2 >> 42) as u64;
            h2 = (d2 as u64) & LIMB2_MASK;
            h0 += c * 5;
            let c = h0 >> 44;
            h0 &= LIMB_MASK;
            h1 += c;

            rest = &rest[16..];
        }

        self.h = [h0, h1, h2];
    }

    /// `a * b mod (2^130 - 5)`, unfolded: the three product limbs as `u128`s,
    /// with the `2^132 = 20` terms folded in — exactly the block loop's
    /// multiply before its fold. The fold is deferred to the caller, which is
    /// the point: one fold covers a sum of these, by linearity.
    ///
    /// # `s` belongs to `y`, the multiplier
    ///
    /// `s` is `(y.1 * 20, y.2 * 20)` — the **right** operand's folded terms, never
    /// the left's. This is not a naming preference, it is the arithmetic: the
    /// `2^132` limbs of the full product are `x1*y2` and `x2*y1`, so limb 0 of the
    /// result is `x0*y0 + x1*(y2*20) + x2*(y1*20)`, and the `20` is attached to
    /// whichever side of each product the *power* sits on. Substituting `x`'s own
    /// limbs gives `x1*(x2*20) + x2*(x1*20)`, which is `40*x1*x2` where the
    /// product is `20*(x1*y2 + x2*y1)` — wrong for every input, and wrong in a way
    /// that stays a valid field element, so it returns a plausible tag instead of
    /// faulting.
    ///
    /// The one-block chain above is the reference for the convention: it spells
    /// the same two terms as `s1`/`s2`, which it derives from `r`, and `r` is
    /// always its `y`.
    ///
    /// The only callers are [`Poly1305::absorb_stride2`] and the vector
    /// combines' scalar helpers, on every architecture.
    #[inline]
    fn mul_unfolded(x: [u64; 3], y: (u64, u64, u64), s: (u64, u64)) -> [u128; 3] {
        let (y0, y1, y2) = (y.0 as u128, y.1 as u128, y.2 as u128);
        let (x0, x1, x2) = (x[0] as u128, x[1] as u128, x[2] as u128);
        let d0 = x0 * y0 + x1 * (s.1 as u128) + x2 * (s.0 as u128);
        let d1 = x0 * y1 + x1 * y0 + x2 * (s.1 as u128);
        let d2 = x0 * y2 + x1 * y1 + x2 * y0;
        [d0, d1, d2]
    }

    /// The block loop's partial fold of an unfolded product: carries down the
    /// limbs, the top carry back times five, limb 1 left a bit wide — the same
    /// shape the one-block loop leaves, so [`reduce`] accepts the result.
    ///
    #[inline]
    fn fold_unfolded(d: [u128; 3]) -> [u64; 3] {
        let c = (d[0] >> 44) as u64;
        let h0 = (d[0] as u64) & LIMB_MASK;
        let d1 = d[1] + u128::from(c);
        let c = (d1 >> 44) as u64;
        let h1 = (d1 as u64) & LIMB_MASK;
        let d2 = d[2] + u128::from(c);
        let c = (d2 >> 42) as u64;
        let h2 = (d2 as u64) & LIMB2_MASK;
        let h0 = h0 + c * 5;
        let c = h0 >> 44;
        [h0 & LIMB_MASK, h1 + c, h2]
    }

    /// Whole blocks two at a time: `(h + m0) * r^2 + m1 * r` per pair, one
    /// fold.
    ///
    /// See [`STRIDE2_THRESHOLD_BYTES`] for why this exists and why it runs on
    /// every architecture. `data` is whole blocks already; an odd count leaves
    /// the last block to the one-block chain, which is the same step the scalar
    /// loop would have taken there.
    fn absorb_stride2(&mut self, data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(16), "absorb takes whole blocks");
        // `r^2` and its `* 20` fold terms, once per call: the stride's whole
        // point is that the second step's multiplier is the square.
        let r2 = Self::fold_unfolded(Self::mul_unfolded(
            [self.r0, self.r1, self.r2],
            (self.r0, self.r1, self.r2),
            (self.s1, self.s2),
        ));
        let r2s = (r2[1].wrapping_mul(20), r2[2].wrapping_mul(20));

        let r = (self.r0, self.r1, self.r2);
        let rs = (self.s1, self.s2);
        let r2t = (r2[0], r2[1], r2[2]);
        let (mut h0, mut h1, mut h2) = (self.h[0], self.h[1], self.h[2]);

        let (pairs, rest) = data.as_chunks::<32>();
        for pair in pairs {
            let read = |m: &[u8]| {
                let t0 = u64::from_le_bytes(m[0..8].try_into().expect("whole block"));
                let t1 = u64::from_le_bytes(m[8..16].try_into().expect("whole block"));
                [
                    t0 & LIMB_MASK,
                    ((t0 >> 44) | (t1 << 20)) & LIMB_MASK,
                    ((t1 >> 24) & LIMB2_MASK) + HIBIT,
                ]
            };
            let b0 = read(&pair[..16]);
            let b1 = read(&pair[16..]);

            // The two independent products: the running value squared, and the
            // second block against `r`. One fold covers both, because the fold
            // is exact mod `p` and the sums stay inside `reduce`'s range.
            let d_a = Self::mul_unfolded([h0 + b0[0], h1 + b0[1], h2 + b0[2]], r2t, r2s);
            let d_b = Self::mul_unfolded(b1, r, rs);
            let d = [d_a[0] + d_b[0], d_a[1] + d_b[1], d_a[2] + d_b[2]];
            [h0, h1, h2] = Self::fold_unfolded(d);
        }
        // An odd block takes the one-block step, which is also what keeps the
        // odd block's `r` (not `r^2`) honest.
        if let Some(m) = rest.first_chunk::<16>() {
            let t0 = u64::from_le_bytes(m[0..8].try_into().expect("whole block"));
            let t1 = u64::from_le_bytes(m[8..16].try_into().expect("whole block"));
            let b = [
                t0 & LIMB_MASK,
                ((t0 >> 44) | (t1 << 20)) & LIMB_MASK,
                ((t1 >> 24) & LIMB2_MASK) + HIBIT,
            ];
            let d = Self::mul_unfolded([h0 + b[0], h1 + b[1], h2 + b[2]], r, rs);
            [h0, h1, h2] = Self::fold_unfolded(d);
        }

        self.h = [h0, h1, h2];
    }

    /// Whole blocks in two contiguous halves, each half on its own stride-two
    /// chain, run in lockstep.
    ///
    /// See [`TWO_LANE_THRESHOLD_BYTES`] for the band this owns and for the
    /// measurement that put it back. What this adds over
    /// [`Poly1305::absorb_stride2`] is one thing: a **second, independent**
    /// dependency chain, so the two halves' folds overlap. The stride-two step
    /// already halves the folds; this puts two of those side by side, which is
    /// the remaining half of the latency the products cannot fill.
    ///
    /// # The combine, exactly
    ///
    /// Lane one absorbs a prefix and lane two the rest, each under the same `r`,
    /// and lane one starts from the **incoming** accumulator rather than zero
    /// because [`Poly1305::update`] can be called several times per message
    /// (`aad`, its padding, the body, the lengths). Writing the full Horner sum
    /// out,
    ///
    /// ```text
    ///   h_n = sum over i of m_i * r^(n-1-i)
    /// ```
    ///
    /// a lane that hashed `k` blocks is `sum_{i<k} m_i r^(k-1-i)`, so
    /// multiplying it by `r^(n-k)` puts every one of its terms at exactly the
    /// exponent the full sum gives it, and lane two's own value needs no shift
    /// because it is already at the tail's exponents:
    ///
    /// ```text
    ///   h = A * r^(n-k) + B
    /// ```
    ///
    /// Seeding lane one with `self.h` rather than zero is the same identity
    /// rather than a new one — the combine holds for *any* starting `A` -- which
    /// is what makes a continuation correct. Starting both at zero was the first
    /// version's bug, and it cost every run that began after an earlier one.
    ///
    /// # Why contiguous halves and not interleaved blocks
    ///
    /// An even/odd interleave would need an extra factor of `r` on one lane to
    /// combine, which is a different combine and one more thing to get wrong.
    ///
    /// # Why two lanes and not three
    ///
    /// Measured: a third lane spills. Two lanes need `r` and `r^2` — ten
    /// registers — plus two accumulators; three add three accumulator registers
    /// and three for the staged blocks, and past that the fold's temporaries go
    /// to the stack on every iteration.
    #[cfg(target_arch = "aarch64")]
    #[allow(
        clippy::too_many_lines,
        reason = "one two-lane loop body; factoring the per-pair body into a helper would put a call per thirty-two bytes, the same cost the stride-two loop keeps inline"
    )]
    fn absorb_two_lane(&mut self, data: &[u8]) {
        let blocks = data.len() / 16;
        let pairs = blocks / 4;
        debug_assert!(
            pairs > 0,
            "the dispatch only sends four blocks or more here"
        );

        // The two per-call powers. Both are field multiplications in the same
        // three limbs the loop multiplies at, so they go through
        // `mul_unfolded`/`fold_unfolded` like every other step in this file.
        let r = (self.r0, self.r1, self.r2);
        let rs = (self.s1, self.s2);
        let q = Self::fold_unfolded(Self::mul_unfolded([r.0, r.1, r.2], r, rs));
        // `Self::mul_unfolded`'s third argument is the **multiplier's** `* 20`
        // terms — see that function's contract. Both powers below are fixed for
        // the whole call, so both pairs of terms are formed once here rather than
        // per block: `qs` for every multiply by `q`, `rs` for every one by `r`.
        let qs = (q[1].wrapping_mul(20), q[2].wrapping_mul(20));

        let cut = pairs * 32;
        let (left, right) = data.split_at(cut);
        let [mut a0, mut a1, mut a2] = self.h;
        let [mut b0, mut b1, mut b2] = [0u64; 3];

        // Both heads are split off **before** the loop rather than taken as the
        // iterators' remainders: `as_chunks` hands back the remainder as it was
        // *before* iteration, so zipping the chunk lists and then passing the
        // remainder to the tail drops every pair past the shorter lane.
        let l_pairs = (left.len() / 32).min(pairs);
        let r_pairs = (right.len() / 32).min(pairs);
        let (left_head, left_rest) = left.split_at(l_pairs * 32);
        let (right_head, right_rest) = right.split_at(r_pairs * 32);

        for (x, y) in left_head
            .as_chunks::<32>()
            .0
            .iter()
            .zip(right_head.as_chunks::<32>().0.iter())
        {
            let (x0, x1, x2) = Self::block_limbs3(&x[0..16]);
            let (x3, x4, x5) = Self::block_limbs3(&x[16..32]);
            let d_a = Self::mul_unfolded([a0 + x0, a1 + x1, a2 + x2], (q[0], q[1], q[2]), qs);
            let d_b = Self::mul_unfolded([x3, x4, x5], r, rs);
            [a0, a1, a2] = Self::fold_unfolded([d_a[0] + d_b[0], d_a[1] + d_b[1], d_a[2] + d_b[2]]);

            let (y0, y1, y2) = Self::block_limbs3(&y[0..16]);
            let (y3, y4, y5) = Self::block_limbs3(&y[16..32]);
            let d_a = Self::mul_unfolded([b0 + y0, b1 + y1, b2 + y2], (q[0], q[1], q[2]), qs);
            let d_b = Self::mul_unfolded([y3, y4, y5], r, rs);
            [b0, b1, b2] = Self::fold_unfolded([d_a[0] + d_b[0], d_a[1] + d_b[1], d_a[2] + d_b[2]]);
        }

        // Whatever is past the zipped pairs, per lane, still in pair arithmetic
        // and then at most one final single block. The right lane's remainder is
        // longer than one pair whenever the message has more than four blocks.
        let tail = |d: &[u8], [mut h0, mut h1, mut h2]: [u64; 3]| -> [u64; 3] {
            let mut rest = d;
            while let Some(p) = rest.first_chunk::<32>() {
                let (p0, p1, p2) = Self::block_limbs3(&p[0..16]);
                let (p3, p4, p5) = Self::block_limbs3(&p[16..32]);
                let d_a = Self::mul_unfolded([h0 + p0, h1 + p1, h2 + p2], (q[0], q[1], q[2]), qs);
                let d_b = Self::mul_unfolded([p3, p4, p5], r, rs);
                [h0, h1, h2] =
                    Self::fold_unfolded([d_a[0] + d_b[0], d_a[1] + d_b[1], d_a[2] + d_b[2]]);
                rest = &rest[32..];
            }
            if let Some(m) = rest.first_chunk::<16>() {
                let (b0, b1, b2) = Self::block_limbs3(m);
                let d = Self::mul_unfolded([h0 + b0, h1 + b1, h2 + b2], r, rs);
                [h0, h1, h2] = Self::fold_unfolded(d);
            }
            [h0, h1, h2]
        };
        debug_assert_eq!(left_rest.len() % 16, 0);
        debug_assert_eq!(right_rest.len() % 16, 0);
        [a0, a1, a2] = tail(left_rest, [a0, a1, a2]);
        [b0, b1, b2] = tail(right_rest, [b0, b1, b2]);

        // Lane one hashed `2 * pairs` **blocks** -- `pairs` counts pairs and a
        // pair is two blocks — and every block after it follows, so its shift is
        // by `blocks - 2 * pairs`. Writing `blocks - pairs` is a shift by roughly
        // twice as much, which produces a well-formed tag that is wrong.
        let rp = Self::field_pow3([r.0, r.1, r.2], (blocks - 2 * pairs) as u64);
        // The multiply is `A * rp`, so the `20`-fold terms are `rp`'s — it is the
        // multiplier. See [`Self::mul_unfolded`]'s contract.
        let rps = (rp[1].wrapping_mul(20), rp[2].wrapping_mul(20));
        let d = Self::mul_unfolded([a0, a1, a2], (rp[0], rp[1], rp[2]), rps);
        self.h = Self::fold_unfolded([
            d[0] + u128::from(b0),
            d[1] + u128::from(b1),
            d[2] + u128::from(b2),
        ]);
    }

    /// One sixteen-byte block as its three 44-bit limbs, plus the implicit
    /// `2^128` in limb 2.
    ///
    /// The split is at bit 44 to match the accumulator's, so the block crosses a
    /// limb boundary the same way `h` does. `m[8..16]`'s low 24 bits and
    /// `m[0..8]`'s high 20 bits are limb 1, which is the one place this is not a
    /// copy of a slice.
    ///
    /// Named apart from the twenty-six-bit [`field_pow`] because that one works
    /// in the vector paths' five limbs and this one in the accumulator's three.
    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn block_limbs3(m: &[u8]) -> (u64, u64, u64) {
        let t0 = u64::from_le_bytes(m[0..8].try_into().expect("a whole 16-byte block"));
        let t1 = u64::from_le_bytes(m[8..16].try_into().expect("a whole 16-byte block"));
        (
            t0 & LIMB_MASK,
            ((t0 >> 44) | (t1 << 20)) & LIMB_MASK,
            ((t1 >> 24) & LIMB2_MASK) + HIBIT,
        )
    }

    /// `base^exp` in the field, in the accumulator's three limbs, by binary
    /// exponentiation over [`Self::mul_unfolded`] and [`Self::fold_unfolded`].
    ///
    /// `exp` is a message length in blocks, which is public, so branching on its
    /// bits is not a secret-dependent branch. `r` itself never branches. One
    /// exponentiation per message rather than per block: at 1 KiB that is a
    /// handful of squares and multiplies against sixty-four blocks of work.
    ///
    /// The `20`-fold terms are recomputed from **each** right-hand operand
    /// rather than hoisted out of the loop. They are `2^132 mod p` for whichever
    /// value is being multiplied in, so one pair hoisted from `base` is right for
    /// the first square and wrong for every one after it — which is a
    /// well-formed tag of the wrong value rather than a crash, and therefore the
    /// kind of mistake only a per-loop comparison against the chain can catch.
    #[cfg(target_arch = "aarch64")]
    fn field_pow3(base: [u64; 3], mut exp: u64) -> [u64; 3] {
        // The `20`-fold terms belong to the **left** operand, as
        // [`Self::mul_unfolded`]'s `s` argument says and as the one-block chain
        // spells it out: `x1 * s2 + x2 * s1` with `s1, s2` derived from `x`.
        // Hoisting one pair for the whole loop is therefore wrong the moment the
        // left operand stops being `r` — which is every multiply after the
        // first — and it is wrong as a well-formed tag rather than a crash.
        let mul = |x: [u64; 3], y: [u64; 3]| {
            // `y`'s terms, because `y` is the multiplier here: `mul_unfolded`'s
            // third argument is the **right** operand's, which is the same thing
            // the one-block chain spells as `s1`/`s2` beside `r`. Taking them
            // from `x` instead is wrong for every input and agrees with the
            // schoolbook product on none, and it produced a well-formed tag
            // rather than a fault -- see [`Self::mul_unfolded`].
            let ys = (y[1].wrapping_mul(20), y[2].wrapping_mul(20));
            Self::fold_unfolded(Self::mul_unfolded(x, (y[0], y[1], y[2]), ys))
        };
        // The multiplicative identity in **this** basis is `[1, 0, 0]`. The
        // five-limb 26-bit representation uses `[1, 1, 1]` — every limb
        // initialised to one, because there `p = 5 * 2^130` folds a whole limb
        // at a time — and that seed carried over into a file whose other
        // exponentiation helper does not share the basis. It is not an identity
        // here: `[1,1,1] * y` is `y0 + 20*(y1 + y2)` in limb 0, so every
        // exponentiation came out as a well-formed field element that was simply
        // the wrong one.
        let mut acc = [1u64, 0, 0];
        let mut b = base;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = mul(acc, b);
            }
            b = mul(b, b);
            exp >>= 1;
        }
        acc
    }

    /// Whole `data` four blocks per group, four lanes in flight, on `AVX2`.
    ///
    /// See [`AVX2_THRESHOLD_BYTES`] for the shape. `data` is whole blocks
    /// already; a count that is not a multiple of four sends its leading
    /// blocks through the one-block chain first, so the lanes see a multiple
    /// of four and the lane weights stay `r^4, r^3, r^2, r`.
    ///
    /// # Safety
    ///
    /// `AVX2` must be present. The only caller probes it immediately before.
    #[cfg(target_arch = "x86_64")]
    #[allow(
        clippy::too_many_lines,
        reason = "one four-lane Horner step; factoring the per-group body into a helper would put a call per sixty-four bytes, the same cost the three-limb absorb keeps inline"
    )]
    #[target_feature(enable = "avx2")]
    unsafe fn absorb_avx2(&mut self, data: &[u8]) {
        // Glob-imported the way `chacha::avx2` is: the body is a flat list of
        // single-instruction lane primitives, and naming each one would hide
        // the Horner structure the reviewer is checking.
        #[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
        use core::arch::x86_64::*;

        debug_assert!(data.len().is_multiple_of(16), "absorb takes whole blocks");
        let n = data.len() / 16;
        let e = n % 4;

        // The leading `e` blocks take the one-block chain, so the vector run
        // is a multiple of four and lane `j`'s weight is `r^(4 - j)`.
        self.absorb(&data[..e * 16], HIBIT);

        let r26 = to_26([self.r0, self.r1, self.r2]);
        let powers = powers4(&r26);
        let r4 = &powers[2];

        // The lanes' multiplier is `r^4`: each lane's chain advances one block
        // of four, so four lane-steps cover sixteen chain-steps.
        let r0v = _mm256_set1_epi64x(r4[0].cast_signed().into());
        let r1v = _mm256_set1_epi64x(r4[1].cast_signed().into());
        let r2v = _mm256_set1_epi64x(r4[2].cast_signed().into());
        let r3v = _mm256_set1_epi64x(r4[3].cast_signed().into());
        let r4v = _mm256_set1_epi64x(r4[4].cast_signed().into());
        // `5 * r_i` unreduced per limb, as in the scalar fold.
        let s1v = _mm256_set1_epi64x(r4[1].wrapping_mul(5).cast_signed().into());
        let s2v = _mm256_set1_epi64x(r4[2].wrapping_mul(5).cast_signed().into());
        let s3v = _mm256_set1_epi64x(r4[3].wrapping_mul(5).cast_signed().into());
        let s4v = _mm256_set1_epi64x(r4[4].wrapping_mul(5).cast_signed().into());
        let mask26 = _mm256_set1_epi64x(M26.cast_signed());

        let mut hv = [_mm256_setzero_si256(); 5];

        let mut groups = &data[e * 16..];
        while let Some(g) = groups.first_chunk::<64>() {
            // Twenty-five four-lane products: `d_j` holds four blocks' `d_j`
            // at once, so one `vpmuludq` retires four scalar products. The
            // limbs are at most 29 bits, so each 55-bit product and each
            // five-term sum stays far below `2^64`.
            //
            // The lane is *multiply-then-add* (`h * r^4 + m`), not the scalar
            // chain's *add-then-multiply* (`(h + m) * r`): with the multiply
            // first, a block's weight in its lane is `r^4` per lane-step it
            // survives — which is what makes the combine's `r^4/r^3/r^2/r`
            // lane weights exact.
            let mut d0 = _mm256_mul_epu32(hv[0], r0v);
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[1], s4v));
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[2], s3v));
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[3], s2v));
            d0 = _mm256_add_epi64(d0, _mm256_mul_epu32(hv[4], s1v));
            let mut d1 = _mm256_mul_epu32(hv[0], r1v);
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[1], r0v));
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[2], s4v));
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[3], s3v));
            d1 = _mm256_add_epi64(d1, _mm256_mul_epu32(hv[4], s2v));
            let mut d2 = _mm256_mul_epu32(hv[0], r2v);
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[1], r1v));
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[2], r0v));
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[3], s4v));
            d2 = _mm256_add_epi64(d2, _mm256_mul_epu32(hv[4], s3v));
            let mut d3 = _mm256_mul_epu32(hv[0], r3v);
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[1], r2v));
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[2], r1v));
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[3], r0v));
            d3 = _mm256_add_epi64(d3, _mm256_mul_epu32(hv[4], s4v));
            let mut d4 = _mm256_mul_epu32(hv[0], r4v);
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[1], r3v));
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[2], r2v));
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[3], r1v));
            d4 = _mm256_add_epi64(d4, _mm256_mul_epu32(hv[4], r0v));

            // The fold, four lanes at once: the same carries as the scalar
            // fold, each instruction covering four blocks.
            let c = _mm256_srli_epi64::<26>(d0);
            let o0 = _mm256_and_si256(d0, mask26);
            d1 = _mm256_add_epi64(d1, c);
            let c = _mm256_srli_epi64::<26>(d1);
            let o1 = _mm256_and_si256(d1, mask26);
            d2 = _mm256_add_epi64(d2, c);
            let c = _mm256_srli_epi64::<26>(d2);
            let o2 = _mm256_and_si256(d2, mask26);
            d3 = _mm256_add_epi64(d3, c);
            let c = _mm256_srli_epi64::<26>(d3);
            let o3 = _mm256_and_si256(d3, mask26);
            d4 = _mm256_add_epi64(d4, c);
            let c = _mm256_srli_epi64::<26>(d4);
            let o4 = _mm256_and_si256(d4, mask26);
            // `w = o0 + 5 * c`, limb zero masked, `w >> 26` into limb one.
            let wrapped = _mm256_add_epi64(o0, _mm256_add_epi64(_mm256_slli_epi64::<2>(c), c));
            hv[0] = _mm256_and_si256(wrapped, mask26);
            hv[1] = _mm256_add_epi64(o1, _mm256_srli_epi64::<26>(wrapped));
            hv[2] = o2;
            hv[3] = o3;
            hv[4] = o4;

            // ...then add: this group's four blocks join the folded value,
            // lane `i` taking block `i`'s limbs.
            let w = |blk: &[u8], at: usize| {
                u32::from_le_bytes([blk[at], blk[at + 1], blk[at + 2], blk[at + 3]])
            };
            let limbs = |blk: &[u8]| {
                [
                    w(blk, 0) & M26_U32,
                    (w(blk, 3) >> 2) & M26_U32,
                    (w(blk, 6) >> 4) & M26_U32,
                    (w(blk, 9) >> 6) & M26_U32,
                    (w(blk, 12) >> 8) + HIBIT26,
                ]
            };
            let l0 = limbs(&g[0..16]);
            let l1 = limbs(&g[16..32]);
            let l2 = limbs(&g[32..48]);
            let l3 = limbs(&g[48..64]);
            for ((((hvp, a), b), c), d) in hv.iter_mut().zip(l0).zip(l1).zip(l2).zip(l3) {
                *hvp = _mm256_add_epi64(
                    *hvp,
                    _mm256_setr_epi64x(a.into(), b.into(), c.into(), d.into()),
                );
            }

            groups = &groups[64..];
        }

        // Back to scalars through stores: lane `i` of every limb vector is
        // lane `i`'s accumulator.
        let mut lanes = [[0u32; 5]; 4];
        for (j, lane) in hv.iter().enumerate() {
            let mut arr = [0u64; 4];
            // SAFETY: `_mm256_storeu_si256` writes 32 bytes into a `[u64; 4]`,
            // which is the exact width.
            unsafe { _mm256_storeu_si256(arr.as_mut_ptr().cast(), *lane) };
            lanes[0][j] = arr[0] as u32;
            lanes[1][j] = arr[1] as u32;
            lanes[2][j] = arr[2] as u32;
            lanes[3][j] = arr[3] as u32;
        }

        // The combine: lane `j`'s chain is whole, and its blocks' weights are
        // `r^(4 - j)` off the lane's own `r^4` steps. A zero accumulator skips
        // the `r^n` term, which is the hot path's shape.
        self.h = combine4(self.h, &lanes, &r26, &powers, n / 4);
    }

    /// Whole `data` four blocks per group, four lanes in flight, on `NEON`.
    ///
    /// See [`NEON4_THRESHOLD_BYTES`] for the shape. `data` is whole blocks
    /// already; a count that is not a multiple of four sends its leading
    /// blocks through the one-block chain first, so the lanes see a multiple
    /// of four and the lane weights stay `r^4, r^3, r^2, r`.
    #[cfg(target_arch = "aarch64")]
    #[allow(
        clippy::too_many_lines,
        reason = "one four-lane Horner step; factoring the per-group body into a helper would put a call per sixty-four bytes, the same cost the three-limb absorb keeps inline"
    )]
    fn absorb_neon4(&mut self, data: &[u8]) {
        // Glob-imported the way `chacha::neon` is: the body is a flat list of
        // single-instruction lane primitives, and naming each one would hide
        // the Horner structure the reviewer is checking. `NEON` is baseline on
        // `aarch64`, so no feature gate is needed.
        #[allow(clippy::wildcard_imports, reason = "flat lane primitives")]
        use core::arch::aarch64::*;

        debug_assert!(data.len().is_multiple_of(16), "absorb takes whole blocks");
        let n = data.len() / 16;
        let e = n % 4;

        // The leading `e` blocks take the one-block chain, so the vector run
        // is a multiple of four and lane `j`'s weight is `r^(4 - j)`.
        self.absorb(&data[..e * 16], HIBIT);

        let r26 = to_26([self.r0, self.r1, self.r2]);
        let powers = powers4(&r26);
        let r4 = &powers[2];

        // The lanes' multiplier is `r^4`, broadcast for the widening
        // multiplies. `NEON` multiplies two lanes per instruction, so the
        // limb vectors are held as `[uint32x4_t; 5]` and split per product.
        // SAFETY: `vdup_n_u32` writes no memory and reads no pointer; `NEON`
        // is baseline on `aarch64`.
        let (r0v, r1v, r2v, r3v, r4v, s1v, s2v, s3v, s4v, mask64) = unsafe {
            (
                vdup_n_u32(r4[0]),
                vdup_n_u32(r4[1]),
                vdup_n_u32(r4[2]),
                vdup_n_u32(r4[3]),
                vdup_n_u32(r4[4]),
                vdup_n_u32(r4[1].wrapping_mul(5)),
                vdup_n_u32(r4[2].wrapping_mul(5)),
                vdup_n_u32(r4[3].wrapping_mul(5)),
                vdup_n_u32(r4[4].wrapping_mul(5)),
                vdupq_n_u64(M26),
            )
        };

        // Five limb vectors, four lanes each: lane `i` of `hv[j]` is block
        // `i mod 4`'s limb `j`, the lane's whole accumulator.
        // SAFETY: a duplicated zero is four zero accumulators.
        let mut hv: [uint32x4_t; 5] = unsafe { [vdupq_n_u32(0); 5] };

        let mut groups = &data[e * 16..];
        while let Some(g) = groups.first_chunk::<64>() {
            // Twenty-five four-lane products, split into the low and high lane
            // pairs: `d_j_lo` holds blocks 0-1's `d_j`, `d_j_hi` blocks 2-3's.
            // The lane is *multiply-then-add* — see [`Self::absorb_avx2`].
            // SAFETY: `vmull_u32`/`vmlal_u32` are register-only widening
            // multiply-adds; inputs are at most 29 bits, so each 55-bit
            // product and each five-term sum stays far below `2^64`.
            let (d0_lo, d1_lo, d2_lo, d3_lo, d4_lo, d0_hi, d1_hi, d2_hi, d3_hi, d4_hi) = unsafe {
                let a0 = vget_low_u32(hv[0]);
                let a1 = vget_low_u32(hv[1]);
                let a2 = vget_low_u32(hv[2]);
                let a3 = vget_low_u32(hv[3]);
                let a4 = vget_low_u32(hv[4]);
                let b0 = vget_high_u32(hv[0]);
                let b1 = vget_high_u32(hv[1]);
                let b2 = vget_high_u32(hv[2]);
                let b3 = vget_high_u32(hv[3]);
                let b4 = vget_high_u32(hv[4]);
                let mut d0_lo = vmull_u32(a0, r0v);
                d0_lo = vmlal_u32(d0_lo, a1, s4v);
                d0_lo = vmlal_u32(d0_lo, a2, s3v);
                d0_lo = vmlal_u32(d0_lo, a3, s2v);
                d0_lo = vmlal_u32(d0_lo, a4, s1v);
                let mut d1_lo = vmull_u32(a0, r1v);
                d1_lo = vmlal_u32(d1_lo, a1, r0v);
                d1_lo = vmlal_u32(d1_lo, a2, s4v);
                d1_lo = vmlal_u32(d1_lo, a3, s3v);
                d1_lo = vmlal_u32(d1_lo, a4, s2v);
                let mut d2_lo = vmull_u32(a0, r2v);
                d2_lo = vmlal_u32(d2_lo, a1, r1v);
                d2_lo = vmlal_u32(d2_lo, a2, r0v);
                d2_lo = vmlal_u32(d2_lo, a3, s4v);
                d2_lo = vmlal_u32(d2_lo, a4, s3v);
                let mut d3_lo = vmull_u32(a0, r3v);
                d3_lo = vmlal_u32(d3_lo, a1, r2v);
                d3_lo = vmlal_u32(d3_lo, a2, r1v);
                d3_lo = vmlal_u32(d3_lo, a3, r0v);
                d3_lo = vmlal_u32(d3_lo, a4, s4v);
                let mut d4_lo = vmull_u32(a0, r4v);
                d4_lo = vmlal_u32(d4_lo, a1, r3v);
                d4_lo = vmlal_u32(d4_lo, a2, r2v);
                d4_lo = vmlal_u32(d4_lo, a3, r1v);
                d4_lo = vmlal_u32(d4_lo, a4, r0v);
                let mut d0_hi = vmull_u32(b0, r0v);
                d0_hi = vmlal_u32(d0_hi, b1, s4v);
                d0_hi = vmlal_u32(d0_hi, b2, s3v);
                d0_hi = vmlal_u32(d0_hi, b3, s2v);
                d0_hi = vmlal_u32(d0_hi, b4, s1v);
                let mut d1_hi = vmull_u32(b0, r1v);
                d1_hi = vmlal_u32(d1_hi, b1, r0v);
                d1_hi = vmlal_u32(d1_hi, b2, s4v);
                d1_hi = vmlal_u32(d1_hi, b3, s3v);
                d1_hi = vmlal_u32(d1_hi, b4, s2v);
                let mut d2_hi = vmull_u32(b0, r2v);
                d2_hi = vmlal_u32(d2_hi, b1, r1v);
                d2_hi = vmlal_u32(d2_hi, b2, r0v);
                d2_hi = vmlal_u32(d2_hi, b3, s4v);
                d2_hi = vmlal_u32(d2_hi, b4, s3v);
                let mut d3_hi = vmull_u32(b0, r3v);
                d3_hi = vmlal_u32(d3_hi, b1, r2v);
                d3_hi = vmlal_u32(d3_hi, b2, r1v);
                d3_hi = vmlal_u32(d3_hi, b3, r0v);
                d3_hi = vmlal_u32(d3_hi, b4, s4v);
                let mut d4_hi = vmull_u32(b0, r4v);
                d4_hi = vmlal_u32(d4_hi, b1, r3v);
                d4_hi = vmlal_u32(d4_hi, b2, r2v);
                d4_hi = vmlal_u32(d4_hi, b3, r1v);
                d4_hi = vmlal_u32(d4_hi, b4, r0v);
                (
                    d0_lo, d1_lo, d2_lo, d3_lo, d4_lo, d0_hi, d1_hi, d2_hi, d3_hi, d4_hi,
                )
            };

            // The fold, the same carries as the two-way's, once per half.
            let lo = fold64(d0_lo, d1_lo, d2_lo, d3_lo, d4_lo, mask64);
            let hi = fold64(d0_hi, d1_hi, d2_hi, d3_hi, d4_hi, mask64);
            // SAFETY: `vmovn_u64` and `vcombine_u32` are register-only; the
            // folded values are at most 27 bits, so the narrowing is exact.
            hv = unsafe {
                [
                    vcombine_u32(vmovn_u64(lo.0), vmovn_u64(hi.0)),
                    vcombine_u32(vmovn_u64(lo.1), vmovn_u64(hi.1)),
                    vcombine_u32(vmovn_u64(lo.2), vmovn_u64(hi.2)),
                    vcombine_u32(vmovn_u64(lo.3), vmovn_u64(hi.3)),
                    vcombine_u32(vmovn_u64(lo.4), vmovn_u64(hi.4)),
                ]
            };

            // ...then add: this group's four blocks join the folded value,
            // lane `i` taking block `i`'s limbs.
            let w = |blk: &[u8], at: usize| {
                u32::from_le_bytes([blk[at], blk[at + 1], blk[at + 2], blk[at + 3]])
            };
            let limbs = |blk: &[u8]| {
                [
                    w(blk, 0) & M26_U32,
                    (w(blk, 3) >> 2) & M26_U32,
                    (w(blk, 6) >> 4) & M26_U32,
                    (w(blk, 9) >> 6) & M26_U32,
                    (w(blk, 12) >> 8) + HIBIT26,
                ]
            };
            let l0 = limbs(&g[0..16]);
            let l1 = limbs(&g[16..32]);
            let l2 = limbs(&g[32..48]);
            let l3 = limbs(&g[48..64]);
            for (j, lane) in hv.iter_mut().enumerate() {
                let mv = [l0[j], l1[j], l2[j], l3[j]];
                // SAFETY: `vld1q_u32` reads 16 bytes from a stack `[u32; 4]`
                // that is live for the call; `vaddq_u32` is register-only.
                unsafe {
                    *lane = vaddq_u32(*lane, vld1q_u32(mv.as_ptr()));
                }
            }

            groups = &groups[64..];
        }

        // Back to scalars through stores: lane `i` of every limb vector is
        // lane `i`'s accumulator.
        let mut lanes = [[0u32; 5]; 4];
        for (j, lane) in hv.iter().enumerate() {
            let mut arr = [0u32; 4];
            // SAFETY: `vst1q_u32` writes 16 bytes into a `[u32; 4]`, which is
            // the exact width.
            unsafe { vst1q_u32(arr.as_mut_ptr(), *lane) };
            lanes[0][j] = arr[0];
            lanes[1][j] = arr[1];
            lanes[2][j] = arr[2];
            lanes[3][j] = arr[3];
        }

        // The combine: lane `j`'s chain is whole, and its blocks' weights are
        // `r^(4 - j)` off the lane's own `r^4` steps.
        self.h = combine4(self.h, &lanes, &r26, &powers, n / 4);
    }

    /// Whole `data` in two contiguous halves in lockstep, on `NEON`.
    ///
    /// # Not on the dispatch
    ///
    /// Measured against the scalar stride-two loop that now owns this band, the
    /// two-way path is behind at 512 B-2 KiB on both `aarch64` runners, and the
    /// four-way path above it wins at 4 KiB and 16 KiB. So nothing calls this in
    /// a shipped build; it is here, and compiled, because
    /// `the_neon_halves_are_the_three_limbs_at_every_length_around_the_threshold`
    /// is what keeps it honest for whenever [`NEON_THRESHOLD_BYTES`] becomes a
    /// threshold again. Deleting it would delete the only evidence in this file
    /// that the two-lane repacking is still correct.
    ///
    /// `data` is whole blocks already — [`Poly1305::update`] split them off —
    /// and every block here carries [`HIBIT26`], which is why the dispatch in
    /// [`Poly1305::absorb`] keeps the final padded block on the three-limb loop.
    /// With `n` blocks, `k1 = n / 2` and `k2 = n - k1`, the halves hash to `HA`
    /// and `HB` from zero under the same `r`, and the caller holds `h`, so the
    /// new accumulator is `h * r^n + HA * r^k2 + HB`. The two powers are the
    /// only per-message work beyond the blocks themselves, at about eleven scalar
    /// multiplies for eight kilobytes.
    ///
    /// The lanes hold contiguous runs rather than interleaved blocks: lane zero
    /// absorbs `data[0..k1]` and lane one absorbs the first `k1` blocks of the
    /// second half, with one scalar tail step when `n` is odd. Interleaved
    /// even/odd lanes would need a different combine — an extra factor of `r` on
    /// one lane — so they are wrong here rather than merely slower.
    ///
    /// # The accumulator crosses representations twice
    ///
    /// This path computes in five 26-bit limbs because that is the width `vmull`
    /// and `vmlal` widen from, while [`Poly1305`] stores three 44-bit ones
    /// because that is the width its own loop multiplies at. So `h` is repacked
    /// into 26 bits on the way in and back on the way out, once per `update`
    /// rather than once per block. Those are [`to_26`] and [`from_26`], and they
    /// are exact — the same integer in a different radix — so the only thing they
    /// can get wrong is a boundary, which is why each has a test of its own.
    #[cfg(all(test, target_arch = "aarch64"))]
    #[allow(
        clippy::too_many_lines,
        reason = "one two-lane Horner step; factoring the per-block body into a helper would put a call per thirty-two bytes, the same cost the three-limb absorb keeps inline"
    )]
    fn absorb_neon(&mut self, data: &[u8]) {
        // Glob-imported the way `chacha::neon` is: the body is a flat list of
        // single-instruction lane primitives, and naming each one would hide the
        // Horner structure the reviewer is checking.
        #[allow(
            clippy::wildcard_imports,
            reason = "flat lane primitives, as in chacha::neon"
        )]
        use core::arch::aarch64::*;

        let n = data.len() / 16;
        let k1 = n / 2;
        let k2 = n - k1;
        let (first, rest) = data.split_at(k1 * 16);
        let (second_prefix, tail) = rest.split_at(k1 * 16);

        let r = to_26([self.r0, self.r1, self.r2]);
        let h_in = to_26(self.h);
        let r0v;
        let r1v;
        let r2v;
        let r3v;
        let r4v;
        let s1v;
        let s2v;
        let s3v;
        let s4v;
        // SAFETY: `vdup_n_u32` writes no memory and reads no pointer; `NEON` is
        // baseline on `aarch64`, so no feature gate is needed. Duplicating one
        // limb into both lanes is what makes the two halves share one `r`: the
        // lanes differ only in their `h`, never in their multiplier.
        unsafe {
            r0v = vdup_n_u32(r[0]);
            r1v = vdup_n_u32(r[1]);
            r2v = vdup_n_u32(r[2]);
            r3v = vdup_n_u32(r[3]);
            r4v = vdup_n_u32(r[4]);
            // `5 * r_i` unreduced per limb, not the limbs of `5 * r` reduced:
            // the fold multiplies the top carry by five, so `s` must be five
            // times the limb that is actually multiplied.
            s1v = vdup_n_u32(r[1].wrapping_mul(5));
            s2v = vdup_n_u32(r[2].wrapping_mul(5));
            s3v = vdup_n_u32(r[3].wrapping_mul(5));
            s4v = vdup_n_u32(r[4].wrapping_mul(5));
        }

        // Five `u32x2` lanes, each `[HA_limb, HB_limb]`, from zero: the halves
        // start from zero and the caller's `h` joins at the combine, so no
        // secret enters the vectors except through the blocks below.
        // SAFETY: as above; a duplicated zero is two zero accumulators.
        let mut hv: [uint32x2_t; 5] = unsafe { [vdup_n_u32(0); 5] };
        // SAFETY: `vdupq_n_u64` is a register constant, as above.
        let mask64: uint64x2_t = unsafe { vdupq_n_u64(M26) };

        for i in 0..k1 {
            let a_blk: &[u8; 16] = first[i * 16..i * 16 + 16]
                .try_into()
                .expect("first half is whole blocks");
            let b_blk: &[u8; 16] = second_prefix[i * 16..i * 16 + 16]
                .try_into()
                .expect("second prefix is whole blocks");
            let w = |m: &[u8; 16], at: usize| {
                u32::from_le_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]])
            };
            let ma = [
                w(a_blk, 0) & M26_U32,
                (w(a_blk, 3) >> 2) & M26_U32,
                (w(a_blk, 6) >> 4) & M26_U32,
                (w(a_blk, 9) >> 6) & M26_U32,
                (w(a_blk, 12) >> 8) + HIBIT26,
            ];
            let mb = [
                w(b_blk, 0) & M26_U32,
                (w(b_blk, 3) >> 2) & M26_U32,
                (w(b_blk, 6) >> 4) & M26_U32,
                (w(b_blk, 9) >> 6) & M26_U32,
                (w(b_blk, 12) >> 8) + HIBIT26,
            ];
            // SAFETY: each `vld1_u32` reads two `u32`s from a stack `[u32; 2]`
            // that is live for the call, and `vadd_u32` is register-only. Lane
            // zero is the first half's block and lane one the second half's;
            // swapping them would swap the halves, which the combine's `r^k2`
            // would then scale the wrong way.
            unsafe {
                for (j, lane) in hv.iter_mut().enumerate() {
                    let pair = [ma[j], mb[j]];
                    let mv = vld1_u32(pair.as_ptr());
                    *lane = vadd_u32(*lane, mv);
                }
            }

            // Twenty-five two-wide products: `d_j` holds lane zero's and lane
            // one's `d_j` side by side, so one `vmlal_u32` retires two scalar
            // products. The five `d` groups are independent the way the scalar
            // loop's five accumulators are.
            //
            // SAFETY: `vmull_u32`/`vmlal_u32` are register-only widening
            // multiply-adds (`umlal.2d`); inputs are at most `29` bits, so each
            // `54`-bit product and each five-term sum stays far below `2^64`.
            let (d0, mut d1, mut d2, mut d3, mut d4) = unsafe {
                let mut d0 = vmull_u32(hv[0], r0v);
                d0 = vmlal_u32(d0, hv[1], s4v);
                d0 = vmlal_u32(d0, hv[2], s3v);
                d0 = vmlal_u32(d0, hv[3], s2v);
                d0 = vmlal_u32(d0, hv[4], s1v);
                let mut d1 = vmull_u32(hv[0], r1v);
                d1 = vmlal_u32(d1, hv[1], r0v);
                d1 = vmlal_u32(d1, hv[2], s4v);
                d1 = vmlal_u32(d1, hv[3], s3v);
                d1 = vmlal_u32(d1, hv[4], s2v);
                let mut d2 = vmull_u32(hv[0], r2v);
                d2 = vmlal_u32(d2, hv[1], r1v);
                d2 = vmlal_u32(d2, hv[2], r0v);
                d2 = vmlal_u32(d2, hv[3], s4v);
                d2 = vmlal_u32(d2, hv[4], s3v);
                let mut d3 = vmull_u32(hv[0], r3v);
                d3 = vmlal_u32(d3, hv[1], r2v);
                d3 = vmlal_u32(d3, hv[2], r1v);
                d3 = vmlal_u32(d3, hv[3], r0v);
                d3 = vmlal_u32(d3, hv[4], s4v);
                let mut d4 = vmull_u32(hv[0], r4v);
                d4 = vmlal_u32(d4, hv[1], r3v);
                d4 = vmlal_u32(d4, hv[2], r2v);
                d4 = vmlal_u32(d4, hv[3], r1v);
                d4 = vmlal_u32(d4, hv[4], r0v);
                (d0, d1, d2, d3, d4)
            };

            // The fold, two lanes at once. Carries run down the limbs the way
            // the three-limb fold's do; the lanes never interact, so the chain is
            // as serial as the scalar one and that serial latency is what caps
            // the speedup at about one-and-a-third.
            //
            // `w = o0 + 5 * c`, not `4 * c`, because `2^130 = 5 (mod p)`, and
            // limb zero takes `w` masked while limb one takes `w >> 26`: the
            // other way round leaves limb zero holding the carry. `c * 5` is
            // `(c << 2) + c` rather than a `64`-bit multiply.
            //
            // SAFETY: shifts, ands and adds are register-only; `mask64` keeps
            // each limb inside `2^26` exactly as `M26` does scalarly.
            unsafe {
                let c0 = vshrq_n_u64::<26>(d0);
                let o0 = vandq_u64(d0, mask64);
                d1 = vaddq_u64(d1, c0);
                let c1 = vshrq_n_u64::<26>(d1);
                let o1 = vandq_u64(d1, mask64);
                d2 = vaddq_u64(d2, c1);
                let c2 = vshrq_n_u64::<26>(d2);
                let o2 = vandq_u64(d2, mask64);
                d3 = vaddq_u64(d3, c2);
                let c3 = vshrq_n_u64::<26>(d3);
                let o3 = vandq_u64(d3, mask64);
                d4 = vaddq_u64(d4, c3);
                let c4 = vshrq_n_u64::<26>(d4);
                let o4 = vandq_u64(d4, mask64);
                let wrapped = vaddq_u64(o0, vaddq_u64(vshlq_n_u64::<2>(c4), c4));
                let wrapped_carry = vshrq_n_u64::<26>(wrapped);
                let wrapped_masked = vandq_u64(wrapped, mask64);
                hv[0] = vmovn_u64(wrapped_masked);
                hv[1] = vmovn_u64(vaddq_u64(o1, wrapped_carry));
                hv[2] = vmovn_u64(o2);
                hv[3] = vmovn_u64(o3);
                hv[4] = vmovn_u64(o4);
            }
        }

        // Back to scalars through stores, not lane extracts: a `uint64x2`'s
        // second lane is `32`-bit lane two, not one, so `vget_lane_u32(..., 1)`
        // on a reinterpreted vector names the middle of the high half. Stores
        // keep lane zero in `arr[0]` and lane one in `arr[1]` with no index to
        // get wrong.
        let mut ha = [0u32; 5];
        let mut hb_part = [0u32; 5];
        // SAFETY: each `vst1_u32` writes two `u32`s to a stack `[u32; 2]` that
        // is live for the call and never read as a vector again.
        unsafe {
            for (j, lane) in hv.iter().enumerate() {
                let mut pair = [0u32; 2];
                vst1_u32(pair.as_mut_ptr(), *lane);
                ha[j] = pair[0];
                hb_part[j] = pair[1];
            }
        }

        // Odd `n` leaves one block of the second half without a partner, which
        // the lockstep above never saw. It is one scalar `(h + m) * r` step,
        // the same step the scalar loop would have taken there.
        let mut hb = hb_part;
        if !tail.is_empty() {
            let tail_blk: &[u8; 16] = tail.try_into().expect("odd tail is one block");
            let w = |at: usize| {
                u32::from_le_bytes([
                    tail_blk[at],
                    tail_blk[at + 1],
                    tail_blk[at + 2],
                    tail_blk[at + 3],
                ])
            };
            let m = [
                w(0) & M26_U32,
                (w(3) >> 2) & M26_U32,
                (w(6) >> 4) & M26_U32,
                (w(9) >> 6) & M26_U32,
                (w(12) >> 8) + HIBIT26,
            ];
            let mut sum = [0u32; 5];
            for (i, limb) in sum.iter_mut().enumerate() {
                *limb = hb[i].wrapping_add(m[i]);
            }
            hb = field_mul(&sum, &r);
        }

        // The combine. `k2` is the second half's block count because the step
        // already multiplies by `r`: the first half's weights need exactly the
        // second half's steps, off by one either way is a different polynomial.
        // `n` is the whole run for the same reason, scaling the caller's `h`
        // past everything absorbed here. When `n` is even the halves match, so
        // one power plus one square gives both; when odd the second half is one
        // longer, so one power plus two multiplies does, sharing the squares
        // rather than exponentiating twice.
        let (r_pow_n, r_pow_k2) = if k1 == k2 {
            let rk = field_pow(r, k2);
            let rn = field_mul(&rk, &rk);
            (rn, rk)
        } else {
            let rk1 = field_pow(r, k1);
            let rk2 = field_mul(&rk1, &r);
            let rn = field_mul(&rk1, &rk2);
            (rn, rk2)
        };
        let t1 = field_mul(&h_in, &r_pow_n);
        let t2 = field_mul(&ha, &r_pow_k2);
        let joined = add_three_normalized(&t1, &t2, &hb);
        self.h = from_26(joined);
    }
}

/// `(h + pad) mod 2^128` — the tag — from the block loop's three limbs.
///
/// # Why this is its own function
///
/// Because the interesting part of the accumulator is the one part no
/// end-to-end test can reach. `h` is at most `2^130 + 2^44` and `p` is
/// `2^130 - 5`, so the accumulator sits in a band five values wide where the
/// conditional subtraction is decided: `h` between `p` and `2^130` has to lose
/// `p`, and `h` just below `p` must not. Getting the test wrong by five is
/// invisible to every other test in this file, because reaching it by accident
/// takes about `2^128` messages. So the reduction is a function with its own
/// test that walks each limb to its edges.
///
/// # The three steps
///
/// **One.** Limb 1 may hold one bit more than its width, because the loop's
/// fold ends on a carry into it. Folding that bit into limb 2 first — its
/// natural place, since limb 1's bit 44 *is* limb 2's bit 0 — gives a value of
/// `h0 + h1 * 2^44 + top * 2^88` with `top` at most `2^42`.
///
/// **Two.** Split that at bit 127 into `hi * 2^128 + low`. `low` is a `u128`
/// and `hi` is at most four, and the split is explicit because the obvious
/// spelling — `u128::from(h2) << 88` — drops `top`'s top two bits on the floor:
/// a `u128` has no bits at 128 and 129. That is not a subtlety in the extreme
/// case, it is every message where limb 2 lands above `2^40`, which is three
/// quarters of them.
///
/// **Three.** `p` is `2^130 - 5`, and `2^130` is four whole `2^128`s, so
/// subtracting `p` changes the low 128 bits by exactly `+5` and nothing else.
/// The whole 130-bit reduction is therefore a *test* — is `h` above `p`, which
/// is `h + 5` having a bit at 130 — and a masked add of five. The test reads
/// `hi` plus the carry out of `low + 5` rather than comparing against `2^130`,
/// because `h` being above `2^130` and `h` being above `p` are different
/// questions that differ by exactly the five values this spends its whole
/// existence on.
///
/// `2^130` is not a `u128`, which is why the third step is a test and an add
/// rather than a subtraction: no spelling of "subtract `2^130`" compiles.
fn reduce(h: [u64; 3], pad: u128) -> u128 {
    let [h0, h1, h2] = h;

    // Step one: limb 1's spare bit is limb 2's bit 0.
    let top = h2 + (h1 >> 44);
    debug_assert!(
        top <= LIMB2_MASK + 1,
        "the block loop's fold must keep h under 2^130 + 2^44"
    );

    // Step two: the split at bit 127, named rather than shifted away.
    let hi = top >> 40;
    let low =
        u128::from(h0) | (u128::from(h1 & LIMB_MASK) << 44) | (u128::from(top & LOW_40) << 88);

    // Step three: `p` is invisible below bit 128 except as five.
    //
    // `low + 5` genuinely can carry out of bit 127, and that carry is the test —
    // which is why this asks for it rather than shifting for it: a `u128` has
    // no bit 128 to shift down, so `lifted >> 128` does not compile and
    // `overflowing_add` hands over the carry instead.
    //
    // `hi` is at most four by the assertion in step one, so adding the carry
    // cannot leave four, and `h + 5` is above `p` exactly when it does.
    let (lifted, carry) = low.overflowing_add(5);
    let above_p = u128::from(hi).wrapping_add(u128::from(carry)) >= 4;
    // All ones when `h` was above `p`, all zeroes otherwise, from a subtract
    // rather than a shift of the comparison, so the select has one shape.
    let lift = 0u128.wrapping_sub(u128::from(above_p));
    let acc = (low & !lift) | (lifted & lift);

    // `+ pad`. The tag is `mod 2^128`, so the bit this add throws away is the
    // bit the modulus discards — which is also why none of the four-word carry
    // chain the 26-bit version needed, to avoid overflowing a `u64` a word at a
    // time, is needed here.
    acc.wrapping_add(pad)
}

/// The 26-bit Horner accumulator this replaced, kept whole and whole.
///
/// # Why it is still here
///
/// It is the only thing that can say whether the three-limb rewrite is *faster*.
/// A gate that compares the new accumulator against a specification proves
/// identity and nothing about speed; a gate that compares it against the pinned
/// `poly1305` crate measures someone else's code, which is a different claim.
/// So the code being replaced is kept verbatim here, and
/// [`tag_via_26_bit_horner`] is its tag — the same interface, the same bytes, the
/// same twenty-five products per block.
///
/// This is the shape the rest of this repository uses a reference in: gate 4's
/// `previous_encode_into`, gate 7's `chacha20_poly1305_seal_in_place_unfused`,
/// gate 6's mux references. Every one of them is the *previous* implementation,
/// not a re-implementation of the spec.
///
/// Not `#[inline]`-relevant and not on any hot path: nothing in `ferrox-core`
/// calls this, and the only caller is the benchmark's gate.
#[allow(
    clippy::too_many_lines,
    reason = "this is the previous implementation kept verbatim so it can measure the new one; splitting it would stop it being the same code"
)]
pub fn tag_via_26_bit_horner(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    const M: u64 = 0x03ff_ffff;
    // One of the four 32-bit words the five limbs are packed into below.
    const WORD: u64 = 0xffff_ffff;

    let word = |at: usize| u32::from_le_bytes([key[at], key[at + 1], key[at + 2], key[at + 3]]);
    let r = [
        word(0) & 0x03ff_ffff,
        (word(3) >> 2) & 0x03ff_ff03,
        (word(6) >> 4) & 0x03ff_c0ff,
        (word(9) >> 6) & 0x03f0_3fff,
        (word(12) >> 8) & 0x000f_ffff,
    ];
    let pad = [word(16), word(20), word(24), word(28)];
    let (s1, s2, s3, s4) = (
        u64::from(r[1]) * 5,
        u64::from(r[2]) * 5,
        u64::from(r[3]) * 5,
        u64::from(r[4]) * 5,
    );
    let r = [
        u64::from(r[0]),
        u64::from(r[1]),
        u64::from(r[2]),
        u64::from(r[3]),
        u64::from(r[4]),
    ];

    let mut h = [0u64; 5];

    // One closure, not a method: the reference has no `update`/`buffer`/`held`
    // plumbing because a one-shot tag over a contiguous `data` never needs a
    // leftover block — it splits the message here instead, exactly as
    // [`Poly1305::update`] splits it on the way in.
    let absorb = |data: &[u8], hibit: u64, h: &mut [u64; 5]| {
        let mut rest = data;
        while let Some(m) = rest.first_chunk::<16>() {
            let w = |at: usize| u32::from_le_bytes([m[at], m[at + 1], m[at + 2], m[at + 3]]);
            let h0 = h[0] + (u64::from(w(0)) & M);
            let h1 = h[1] + ((u64::from(w(3)) >> 2) & M);
            let h2 = h[2] + ((u64::from(w(6)) >> 4) & M);
            let h3 = h[3] + ((u64::from(w(9)) >> 6) & M);
            let h4 = h[4] + ((u64::from(w(12)) >> 8) & M) + hibit;

            let d0 = h0 * r[0] + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
            let mut d1 = h0 * r[1] + h1 * r[0] + h2 * s4 + h3 * s3 + h4 * s2;
            let mut d2 = h0 * r[2] + h1 * r[1] + h2 * r[0] + h3 * s4 + h4 * s3;
            let mut d3 = h0 * r[3] + h1 * r[2] + h2 * r[1] + h3 * r[0] + h4 * s4;
            let mut d4 = h0 * r[4] + h1 * r[3] + h2 * r[2] + h3 * r[1] + h4 * r[0];

            let c = d0 >> 26;
            let o0 = d0 & M;
            d1 += c;
            let c = d1 >> 26;
            let o1 = d1 & M;
            d2 += c;
            let c = d2 >> 26;
            let o2 = d2 & M;
            d3 += c;
            let c = d3 >> 26;
            let o3 = d3 & M;
            d4 += c;
            let c = d4 >> 26;
            let o4 = d4 & M;
            let wrapped = o0 + c * 5;
            *h = [wrapped & M, o1 + (wrapped >> 26), o2, o3, o4];
            rest = &rest[16..];
        }
    };

    let whole = data.len() / 16 * 16;
    absorb(&data[..whole], 1 << 24, &mut h);

    // A partial block gets a one byte after its last byte and zeros after that,
    // and no hibit — the same termination the shipped `finish` does, for the same
    // reason and with the same classic-bug caveat.
    let tail = &data[whole..];
    if !tail.is_empty() {
        let mut block = [0u8; 16];
        block[..tail.len()].copy_from_slice(tail);
        block[tail.len()] = 1;
        absorb(&block, 0, &mut h);
    }

    let [mut h0, mut h1, mut h2, mut h3, mut h4] = h;
    let mut c;
    c = h1 >> 26;
    h1 &= M;
    h2 += c;
    c = h2 >> 26;
    h2 &= M;
    h3 += c;
    c = h3 >> 26;
    h3 &= M;
    h4 += c;
    c = h4 >> 26;
    h4 &= M;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= M;
    h1 += c;

    let mut g0 = h0 + 5;
    c = g0 >> 26;
    g0 &= M;
    let mut g1 = h1 + c;
    c = g1 >> 26;
    g1 &= M;
    let mut g2 = h2 + c;
    c = g2 >> 26;
    g2 &= M;
    let mut g3 = h3 + c;
    c = g3 >> 26;
    g3 &= M;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);
    // `63`, not `31`: this file keeps `h` in `u64`s where the shipped version
    // kept it in `u32`s, and a `u64` that borrowed has its top bit set rather
    // than its thirty-first. Shifting by 31 here reads a bit that is set on
    // every non-borrowing case and clear on every borrowing one, which selects
    // `h + 5` exactly when it must not — the same failure as the inverted mask,
    // from a width change nobody wrote down.
    let mut mask = (g4 >> 63).wrapping_sub(1);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    let g4 = g4 & mask;
    mask = !mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    let h4 = (h4 & mask) | g4;

    // Five 26-bit limbs to four 32-bit words, and the mask to 32 bits is the
    // point of it. In the shipped version these were `u32`s and the truncation
    // was the assignment's; in `u64`s it has to be written, because without it
    // `f0` is thirty-two bits too wide and `carry >> 32` then hands the next
    // word a carry that is really limb 1's high bits arriving early.
    let f0 = (h0 | (h1 << 26)) & WORD;
    let f1 = ((h1 >> 6) | (h2 << 20)) & WORD;
    let f2 = ((h2 >> 12) | (h3 << 14)) & WORD;
    let f3 = ((h3 >> 18) | (h4 << 8)) & WORD;

    let mut carry = f0 + u64::from(pad[0]);
    let f0 = carry as u32;
    carry = f1 + u64::from(pad[1]) + (carry >> 32);
    let f1 = carry as u32;
    carry = f2 + u64::from(pad[2]) + (carry >> 32);
    let f2 = carry as u32;
    carry = f3 + u64::from(pad[3]) + (carry >> 32);
    let f3 = carry as u32;

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&f0.to_le_bytes());
    out[4..8].copy_from_slice(&f1.to_le_bytes());
    out[8..12].copy_from_slice(&f2.to_le_bytes());
    out[12..16].copy_from_slice(&f3.to_le_bytes());
    out
}

/// The tag over `data` under `key`, in one call.
///
/// The one-shot form, because a data frame is exactly this: one accumulator over
/// one message. [`Poly1305`] exists for a caller that has the pieces already.
#[must_use]
pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let mut state = Poly1305::new(key);
    state.update(data);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reduction, discharged on its own.
    ///
    /// `h` is at most `2^130 + 2^44` and `p` is `2^130 - 5`, so there is a band of
    /// five values where the conditional subtraction has to fire and one just
    /// below where it must not. A wrong answer there is off by exactly five and
    /// needs about `2^128` messages to turn up by accident, so no end-to-end
    /// test will ever find it — which is exactly why the reduction is a separate
    /// function and this test walks each limb to its edges instead.
    ///
    /// The reference is spelled differently on purpose: it compares the split
    /// `(hi, low)` against `p` as the lexicographic pair `(3, 2^128 - 5)`,
    /// where `reduce` adds `low + 5`'s carry to `hi` and asks for four.
    #[test]
    fn the_reduction_is_right_where_the_limbs_are_worst() {
        const EDGE0: [u64; 8] = [
            0,
            1,
            2,
            1 << 20,
            (1 << 43) - 1,
            LIMB_MASK - 1,
            LIMB_MASK - 2,
            LIMB_MASK,
        ];
        // `1 << 44` is reachable and is the whole reason step one of `reduce`
        // exists: the loop's fold leaves limb 1 one bit wide.
        const EDGE1: [u64; 9] = [
            0,
            1,
            2,
            1 << 20,
            (1 << 43) - 1,
            LIMB_MASK - 1,
            LIMB_MASK - 2,
            LIMB_MASK,
            1 << 44,
        ];
        const EDGE2: [u64; 10] = [
            0,
            1,
            2,
            1 << 20,
            (1 << 39) - 1,
            1 << 40,
            (1 << 40) + 1,
            (1 << 41) - 1,
            LIMB2_MASK - 1,
            LIMB2_MASK,
        ];

        let mut checked = 0usize;
        for &h0 in &EDGE0 {
            for &h1 in &EDGE1 {
                for &h2 in &EDGE2 {
                    checked += 1;
                    assert_eq!(
                        reduce([h0, h1, h2], 0),
                        reference([h0, h1, h2], 0),
                        "h0 {h0:#x} h1 {h1:#x} h2 {h2:#x}"
                    );
                    // The same triple with a pad that carries, which is the case
                    // where `acc + pad` crosses bit 127.
                    let pad = u128::MAX - u128::from(h0);
                    assert_eq!(
                        reduce([h0, h1, h2], pad),
                        reference([h0, h1, h2], pad),
                        "h0 {h0:#x} h1 {h1:#x} h2 {h2:#x} with a carrying pad"
                    );
                }
            }
        }
        assert!(checked >= 720, "the cross product is the sweep");
    }

    /// `(h + pad) mod 2^128`, computed the long way.
    ///
    /// Spelled as a lexicographic compare of the split `(hi, low)` against `p`
    /// written as `(3, 2^128 - 5)` — the same three steps `reduce` takes, in a
    /// different order and with a different formulation of each, so that the two
    /// can disagree.
    fn reference(h: [u64; 3], pad: u128) -> u128 {
        let [h0, h1, h2] = h;
        let top = h2 + (h1 >> 44);
        let hi = u128::from(top >> 40);
        let low =
            u128::from(h0) | (u128::from(h1 & LIMB_MASK) << 44) | (u128::from(top & LOW_40) << 88);
        // `p` is `2^130 - 5`, which is `3 * 2^128 + (2^128 - 5)`.
        let (p_hi, p_lo) = (3u128, u128::MAX - 4);
        let above = hi > p_hi || (hi == p_hi && low >= p_lo);
        let acc = if above { low.wrapping_add(5) } else { low };
        acc.wrapping_add(pad)
    }

    /// The three-limb accumulator and the twenty-five-product Horner chain it
    /// replaced are two implementations of one specification, so agreeing is
    /// necessary — and it is the check that matters most here, because every
    /// constant in the new fold is a fresh one.
    ///
    /// Swept at every length through two blocks plus the large lengths, because
    /// the limb boundary sits at bit 44 and the partial block's missing `2^128`
    /// only resolves in `finish`: a length at which the boundaries line up badly
    /// is exactly where a limb-width error would show, and those lengths are not
    /// random.
    #[test]
    fn three_limbs_agree_with_the_26_bit_horner_at_every_length() {
        let mut checked = 0usize;
        for seed in 0..4u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=200usize).chain([255, 256, 257, 512, 513, 1024, 8192]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                assert_eq!(
                    tag(&key, &data),
                    tag_via_26_bit_horner(&key, &data),
                    "seed {seed} length {len}"
                );
                checked += 1;
            }
        }
        assert!(checked > 800, "the sweep should be dense, not a sample");
    }

    /// A one-block message: the shape where the implicit 2^128 bit is the only
    /// thing separating a right answer from a right-looking wrong one, and where
    /// a mask that is off by a bit shows up as a tag that is off by one.
    #[test]
    fn one_block_and_one_byte_agree_with_the_split_form() {
        let key = [0x42u8; 32];
        for len in 0..=48usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(29)).collect();
            let one_shot = tag(&key, &data);
            // Fed in awkward pieces, which is what the leftover path is for.
            let mut split = Poly1305::new(&key);
            for chunk in data.chunks(7) {
                split.update(chunk);
            }
            assert_eq!(one_shot, split.finish(), "length {len} fed in sevens");
        }
    }

    /// `h` must be a real accumulator: absorbing in one call and byte by byte
    /// cannot differ, or the leftover path is quietly dropping or doubling data.
    #[test]
    fn byte_at_a_time_matches_one_shot() {
        let key = [0x11u8; 32];
        for len in 0..=80usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(251).wrapping_add(3))
                .collect();
            let mut dribble = Poly1305::new(&key);
            for byte in &data {
                dribble.update(std::slice::from_ref(byte));
            }
            assert_eq!(tag(&key, &data), dribble.finish(), "length {len}");
        }
    }

    /// Every dispatch threshold, from both sides, at every block parity.
    ///
    /// The dispatch is on length, and each threshold is a place where a
    /// length-dependent bug hides: the run at one byte below it stays on the
    /// one-block chain, the run one byte above hands the whole message to a
    /// vector loop, and the lengths between thresholds are where a vector loop's
    /// leftover block meets the chain. So the sweep crosses every threshold this
    /// architecture dispatches on, at `-32/-16/+16/+32` around it so both block
    /// parities are covered, and compares against the 26-bit chain rather than
    /// against itself.
    #[test]
    fn every_threshold_reaches_the_same_tag_from_both_sides() {
        let mut lengths: Vec<usize> = (0..=200usize).collect();
        // The thresholds this architecture dispatches on, named in one place so a
        // new one is a line here rather than a length nobody sweeps.
        #[cfg(target_arch = "aarch64")]
        let thresholds: [usize; 3] = [
            STRIDE2_THRESHOLD_BYTES,
            NEON_THRESHOLD_BYTES,
            NEON4_THRESHOLD_BYTES,
        ];
        #[cfg(target_arch = "x86_64")]
        let thresholds: [usize; 2] = [STRIDE2_THRESHOLD_BYTES, AVX2_THRESHOLD_BYTES];
        for threshold in thresholds {
            lengths.extend(
                [
                    threshold.saturating_sub(32),
                    threshold.saturating_sub(16),
                    threshold,
                    threshold + 16,
                    threshold + 32,
                    threshold + 48,
                ]
                .into_iter()
                .filter(|len| *len > 200),
            );
        }
        lengths.sort_unstable();
        lengths.dedup();

        let mut checked = 0usize;
        for seed in 0..4u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in &lengths {
                let data: Vec<u8> = (0..*len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                assert_eq!(
                    tag(&key, &data),
                    tag_via_26_bit_horner(&key, &data),
                    "seed {seed} length {len}"
                );
                checked += 1;
            }
        }
        // Every length at every seed, counted against the sweep itself: a floor
        // written as a number is a number that stops meaning anything when a
        // threshold moves, and this one has already been wrong once.
        assert_eq!(
            checked,
            lengths.len() * 4,
            "the sweep should be every length at every seed"
        );
    }

    /// Each loop in this file, reached directly, against the one-block chain at
    /// every block count — not only at the lengths the dispatch happens to pick.
    ///
    /// The dispatch is the only thing that decides which loop runs, so a loop
    /// that is wrong at a block count the dispatch never routes to it is a bug
    /// waiting for a threshold change, and the end-to-end sweep above cannot see
    /// it: those lengths never reach the loop. Both failure modes are silent —
    /// a lane weight off by one and a lane that lost a block both still produce
    /// a well-formed tag — so each loop is compared against the chain directly.
    #[test]
    fn every_loop_matches_the_one_block_chain_at_every_block_count() {
        let key = [0xa7u8; 32];
        for blocks in 0..108usize {
            let data: Vec<u8> = (0..blocks * 16)
                .map(|i| (i as u8).wrapping_mul(17))
                .collect();
            let mut chain = Poly1305::new(&key);
            // The chain itself, not `absorb`: `absorb` dispatches, so from 1 KiB up
            // it would hand back `absorb_two_lane` and every assertion below would
            // be comparing that band with itself.
            chain.absorb_one_block_chain(&data, HIBIT);
            let expected = chain.finish();

            #[cfg(target_arch = "aarch64")]
            {
                let mut stride2 = Poly1305::new(&key);
                stride2.absorb_stride2(&data);
                assert_eq!(
                    expected,
                    stride2.finish(),
                    "{blocks} blocks: stride-two must match the one-block chain"
                );

                // The two-way path hands its odd leading block to the one-block
                // chain itself, so every count is a valid argument.
                let mut two_way = Poly1305::new(&key);
                two_way.absorb_neon(&data);
                assert_eq!(
                    expected,
                    two_way.finish(),
                    "{blocks} blocks: the two-way NEON path must match the one-block chain"
                );

                // The two-lane path splits into halves and needs four blocks to
                // have four pairs, so it takes the same guard as the four-way.
                if blocks >= 4 {
                    let mut two_lane = Poly1305::new(&key);
                    two_lane.absorb_two_lane(&data);
                    assert_eq!(
                        expected,
                        two_lane.finish(),
                        "{blocks} blocks: the two-lane path must match the one-block chain"
                    );
                }

                // The four-way path needs four blocks to have four lanes.
                if blocks >= 4 {
                    let mut four_way = Poly1305::new(&key);
                    four_way.absorb_neon4(&data);
                    assert_eq!(
                        expected,
                        four_way.finish(),
                        "{blocks} blocks: the four-way NEON path must match the one-block chain"
                    );
                }
            }

            #[cfg(target_arch = "x86_64")]
            if std::is_x86_feature_detected!("avx2") && blocks >= 4 {
                let mut four_way = Poly1305::new(&key);
                // SAFETY: the probe above names the feature the path's
                // `target_feature` function carries.
                unsafe { four_way.absorb_avx2(&data) };
                assert_eq!(
                    expected,
                    four_way.finish(),
                    "{blocks} blocks: the four-way AVX2 path must match the one-block chain"
                );
            }
        }
    }

    /// `reduce`'s own `debug_assert`, discharged rather than assumed.
    ///
    /// A `debug_assert` that never fires is a claim nobody has watched, and the
    /// vector loops keep their accumulators in a different representation from
    /// the chain's, so the invariant has to be read back after each of them: the
    /// top limb is what `reduce` compares against `p`, and an unmasked limb one
    /// bit over is a tag that is wrong by a bit rather than by five.
    #[test]
    fn every_loop_leaves_the_invariant_reduce_asserts() {
        let keys: [[u8; 32]; 2] = [[0x5au8; 32], [0xa7u8; 32]];
        for key in &keys {
            for blocks in 0..70usize {
                let data: Vec<u8> = (0..blocks * 16)
                    .map(|i| (i as u8).wrapping_mul(53))
                    .collect();
                let mut chain = Poly1305::new(key);
                // The chain itself, not `absorb`: `absorb` dispatches, so from
                // 128 B up this lane would be the stride-two loop and from 1 KiB
                // the two-lane one -- and the lane this test exists to check, the
                // one `reduce`'s invariant is written against, would be the one
                // lane never measured. Same defect the per-loop test above had,
                // in the test that reads `reduce`'s own bound rather than a tag.
                chain.absorb_one_block_chain(&data, HIBIT);
                // The one-block chain first, then each loop that claims to be
                // the same arithmetic scheduled differently.
                let mut lanes: Vec<Poly1305> = vec![chain];

                #[cfg(target_arch = "aarch64")]
                {
                    let mut stride2 = Poly1305::new(key);
                    stride2.absorb_stride2(&data);
                    lanes.push(stride2);

                    let mut two_way = Poly1305::new(key);
                    two_way.absorb_neon(&data);
                    lanes.push(two_way);

                    if blocks >= 4 {
                        let mut four_way = Poly1305::new(key);
                        four_way.absorb_neon4(&data);
                        lanes.push(four_way);
                    }
                }

                #[cfg(target_arch = "x86_64")]
                if std::is_x86_feature_detected!("avx2") && blocks >= 4 {
                    let mut four_way = Poly1305::new(key);
                    // SAFETY: the probe above names the feature the path's
                    // `target_feature` function carries.
                    unsafe { four_way.absorb_avx2(&data) };
                    lanes.push(four_way);
                }

                for (lane, state) in lanes.iter().enumerate() {
                    let top = state.h[2] + (state.h[1] >> 44);
                    assert!(
                        top <= LIMB2_MASK + 1,
                        "lane {lane}, {blocks} blocks: top limb {top:#x} is over the \
                         invariant `reduce` asserts"
                    );
                    assert_eq!(state.h[0] & !LIMB_MASK, 0, "lane {lane}: h0 is unmasked");
                    assert_eq!(state.h[2] & !LIMB2_MASK, 0, "lane {lane}: h2 is unmasked");
                }
            }
        }
    }

    /// A run that starts after an earlier one is the same value as one run.
    ///
    /// This is the test that found the stride-two lanes seeding themselves from
    /// zero and dropping `self.h`, which is invisible in a one-shot message and
    /// wrong for every message whose body is absorbed after its `aad`. `update` is
    /// called up to four times per `RFC 8439` `MAC`, so "a run that starts after
    /// an earlier one" is the ordinary case and not a corner — and it is the only
    /// shape where the vector paths' repack of a *nonzero* accumulator is
    /// exercised at all, which is what the every-split sweeps in
    /// `the_neon_halves_are_the_three_limbs_at_every_length_around_the_threshold`
    /// and `large_lengths_and_awkward_splits_are_the_crate_too` also cover.
    #[test]
    fn several_updates_are_one_run() {
        let key = [0x5au8; 32];
        let mut checked = 0usize;
        for total in [128usize, 256, 2048, 4096, 8192] {
            let data: Vec<u8> = (0..total)
                .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                .collect();
            let mut one = Poly1305::new(&key);
            one.update(&data);
            let one = one.finish();
            // Every split that lands inside a block, on a block edge, and on each
            // dispatch threshold, plus a byte at a time for the short shape.
            for split in [
                1usize, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 511, 512, 513, 1023, 1024,
                1025, 2047, 2048, 2049, 4095, 4096,
            ] {
                if split >= total {
                    continue;
                }
                let mut two = Poly1305::new(&key);
                two.update(&data[..split]);
                two.update(&data[split..]);
                assert_eq!(
                    one,
                    two.finish(),
                    "total {total} split {split}: a continuation must absorb the same value"
                );
                checked += 1;
            }
            let mut dribbled = Poly1305::new(&key);
            for byte in &data {
                dribbled.update(std::slice::from_ref(byte));
            }
            assert_eq!(one, dribbled.finish(), "total {total}, one byte at a time");
        }
        assert!(
            checked > 60,
            "the split sweep should be dense, not a sample"
        );
    }

    /// The clamp is the one part of this that cannot be checked against itself:
    /// every limb's mask is an independent constant, and a mask that is wrong by
    /// one bit still produces a perfectly self-consistent accumulator. So it is
    /// checked against the specification's own single 128-bit constant —
    /// `0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff` — rather than against this
    /// implementation's shape, which is the only thing that can tell a right
    /// clamp from a plausible one.
    ///
    /// It already has: the four equal per-word masks this replaced leave bits
    /// 58, 59, 90, 91, 122 and 123 of `r` set, and every other test in this file
    /// passed with them, because nothing else here knows what `r` should be.
    #[test]
    fn the_clamp_is_the_specification_and_not_this_implementation() {
        for seed in 0..=255u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(seed));
            let wide = u128::from_le_bytes(key[..16].try_into().expect("16 bytes"));
            let clamped = wide & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff;

            let state = Poly1305::new(&key);
            // Pack the three 44-bit limbs back the way the mask unpacked them.
            // Limb 1 straddles the 64-bit line of `r`, so it contributes to both
            // halves and this is the one place the repack is not a shift.
            let packed =
                u128::from(state.r0) | (u128::from(state.r1) << 44) | (u128::from(state.r2) << 88);
            assert_eq!(packed, clamped, "clamp for key seed {seed}");
        }
    }

    /// The accumulator, against the crate that ships it.
    ///
    /// The `aead` sweep above already decides the thing that matters — that the
    /// `AEAD` is byte-identical to the one `VMess` was using — but it can only
    /// do that through the `AEAD`'s own framing. This one removes the framing:
    /// the accumulator is compared directly, over every length that reaches the
    /// leftover path, at every split point that reaches the carry-into-the-next-
    /// block path, and against three `r` keys chosen to have limbs that are
    /// large, small and mixed.
    #[test]
    fn the_accumulator_is_the_crate_it_replaces() {
        use poly1305::universal_hash::KeyInit as _;

        fn theirs(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
            let k: &poly1305::Key = poly1305::Key::from_slice(&key[..]);
            poly1305::Poly1305::new(k).compute_unpadded(data).into()
        }

        let mut checked = 0usize;
        for seed in 0..3u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            // `240` is fifteen blocks (below the `NEON` threshold), `256` is
            // sixteen (the first vector run, even), `272` seventeen (the first
            // odd vector run, with its one-block scalar tail), `512`/`528` the
            // same pair one rung up. Without the odd pair the tail step would
            // run only on short messages, where the scalar path takes it.
            for len in (0..=48usize).chain([
                63, 64, 65, 127, 128, 129, 240, 256, 272, 512, 528, 1024, 4097,
            ]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                assert_eq!(tag(&key, &data), want, "seed {seed} length {len}");
                // Every split point, so the leftover block is finished the same
                // way whether it arrives one byte early or fifteen.
                for split in 0..=len {
                    let mut state = Poly1305::new(&key);
                    state.update(&data[..split]);
                    state.update(&data[split..]);
                    assert_eq!(
                        state.finish(),
                        want,
                        "seed {seed} length {len} split {split}"
                    );
                }
                checked += 1;
            }
        }
        assert!(checked > 150, "the sweep should be dense, not a sample");
    }

    /// The two repackings, each against the same integer read three ways.
    ///
    /// `aarch64`-only, because that is the only architecture that crosses
    /// representations at all. What each direction can get wrong is a boundary
    /// rather than a value — limb 1 straddles the 64-bit line, limb 4 crosses bit
    /// 128 where a `u128` stops having bits, and the `NEON` combine hands back a
    /// limb 1 that is 27 bits wide on purpose. A repack that mishandles any of
    /// those stays perfectly self-consistent and every tag on `aarch64` is wrong
    /// while every tag on the other three architectures is right, which is the
    /// worst shape a bug in this file can take: it passes `cargo test` on the
    /// machine that wrote it.
    ///
    /// So the reference is the accumulator spelled as one integer per radix and
    /// compared in that integer's own terms, rather than compared against another
    /// copy of the same shift arithmetic.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_two_repackings_are_the_same_integer_three_ways() {
        /// One 130-bit accumulator as `(bits 0..128, bits 128..130)`, reduced
        /// mod `p` by subtraction.
        ///
        /// Spelled as shifts of the three limbs and a subtraction of `p`, rather
        /// than as [`reduce_split`], so that the functions under test are checked
        /// against the definition of the value and not against a second copy of
        /// themselves.
        fn reference(h: [u64; 3]) -> (u128, u64) {
            let top = h[2] + (h[1] >> 44);
            let mut low = u128::from(h[0])
                | (u128::from(h[1] & LIMB_MASK) << 44)
                | (u128::from(top & LOW_40) << 88);
            let mut over = top >> 40;
            while over >= 4 || (over == 3 && low.overflowing_add(5).1) {
                let (sum, carry) = low.overflowing_add(5);
                low = sum;
                over = over + u64::from(carry) - 4;
            }
            (low, over)
        }

        /// The same, read out of five 26-bit limbs.
        ///
        /// Limb 1 is allowed to be 27 bits wide, because the `NEON` combine leaves
        /// it that way; limb 1's bit 26 is value bit 52 and limb 2's bit 0 is the
        /// same bit, so the fields are added rather than or-ed. Reduced the same
        /// way `reference` reduces, spelled out again rather than called.
        fn value_of_five(f: [u32; 5]) -> (u128, u64) {
            let mut low = u128::from(f[0]);
            let mut carry = u64::from(f[1] >> 26);
            low += u128::from(f[1] & M26_U32) << 26;
            let mut limb2 = u64::from(f[2]) + carry;
            carry = limb2 >> 26;
            limb2 &= M26;
            low += u128::from(limb2) << 52;
            let mut limb3 = u64::from(f[3]) + carry;
            carry = limb3 >> 26;
            limb3 &= M26;
            low += u128::from(limb3) << 78;
            let limb4 = u64::from(f[4]) + carry;
            low += u128::from(limb4 & 0x00ff_ffff) << 104;
            let mut over = limb4 >> 24;
            while over >= 4 || (over == 3 && low.overflowing_add(5).1) {
                let (sum, c) = low.overflowing_add(5);
                low = sum;
                over = over + u64::from(c) - 4;
            }
            (low, over)
        }

        // The same edges `the_reduction_is_right_where_the_limbs_are_worst` walks,
        // because those are exactly the shapes that break a repack: a saturated
        // limb 0, limb 1 one bit wider than its mask, limb 2 at `2^40` so bit 128
        // is live, and limb 2 at its own maximum.
        //
        // The last entries of `EDGE1` and `EDGE2` are the point of the walk:
        // `h1 = 2^44` together with `h2 = LIMB2_MASK` is a value of exactly
        // `2^130`, which five 26-bit limbs cannot hold, so `to_26` has to reduce
        // before it repacks rather than assume the value fits. The first version
        // of this test assumed it, and CI failed it on that one combination on the
        // first run it was ever run.
        const EDGE0: [u64; 5] = [0, 1, (1 << 43) - 1, LIMB_MASK - 1, LIMB_MASK];
        const EDGE1: [u64; 6] = [0, 1, (1 << 43) - 1, LIMB_MASK - 1, LIMB_MASK, 1 << 44];
        const EDGE2: [u64; 6] = [0, 1, 1 << 40, (1 << 41) - 1, LIMB2_MASK - 1, LIMB2_MASK];

        let mut checked = 0usize;
        let mut over_130 = 0usize;
        for &h0 in &EDGE0 {
            for &h1 in &EDGE1 {
                for &h2 in &EDGE2 {
                    let three = [h0, h1, h2];
                    let five = to_26(three);
                    let want = reference(three);
                    // Counted on the *unreduced* value, because `want` has already
                    // been reduced and would make this zero.
                    if three[2] + (three[1] >> 44) >= 1 << 42 {
                        over_130 += 1;
                    }

                    assert_eq!(
                        value_of_five(five),
                        want,
                        "to_26 of {three:?} is a different integer"
                    );

                    // Each limb on its own, so a wrong boundary cannot cancel
                    // against a wrong one elsewhere in the repack.
                    let (low, over) = want;
                    for (limb, expected) in [
                        low as u32 & M26_U32,
                        (low >> 26) as u32 & M26_U32,
                        (low >> 52) as u32 & M26_U32,
                        (low >> 78) as u32 & M26_U32,
                        (low >> 104) as u32 | ((over as u32) << 24),
                    ]
                    .into_iter()
                    .enumerate()
                    {
                        assert_eq!(five[limb], expected, "limb {limb} of {three:?}");
                    }

                    // And back, which is the direction the `NEON` combine uses.
                    assert_eq!(reference(from_26(five)), want, "round trip of {three:?}");
                    checked += 1;
                }
            }
        }
        assert!(checked > 100, "the edge walk should be dense, not a sample");
        assert!(
            over_130 > 0,
            "the walk must include the values that need reducing before a repack, \
             or it is not testing the thing it exists for"
        );
    }

    /// The two-way path, against the three-limb path it replaces above the
    /// threshold.
    ///
    /// `aarch64`-only. The thresholds are the interesting numbers: 512 is the
    /// first length that takes the vector path and 528 the first odd block count
    /// above it, 1024 and 8208 the same pair one and two rungs up, and 500 and
    /// 511 the two lengths immediately below it, so a dispatch that is off by one
    /// block shows up as a disagreement rather than as a speed.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn the_neon_halves_are_the_three_limbs_at_every_length_around_the_threshold() {
        for seed in 0..3u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=64usize).chain([
                127, 128, 129, 143, 144, 145, 160, 496, 500, 511, 512, 513, 528, 1024, 2048, 8208,
            ]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();

                // The vector path, named so the test does not depend on the
                // dispatch being right in order to check the dispatch.
                let mut vector = Poly1305::new(&key);
                let whole = len / 16 * 16;
                vector.absorb_neon(&data[..whole]);
                if whole < len {
                    let mut block = [0u8; 16];
                    block[..len - whole].copy_from_slice(&data[whole..]);
                    block[len - whole] = 1;
                    vector.absorb(&block, 0);
                }
                let vector = vector.finish();

                // What the shipped dispatch actually does at this length.
                let shipped = tag(&key, &data);

                assert_eq!(shipped, vector, "seed {seed} length {len}");
                assert_eq!(
                    shipped,
                    tag_via_26_bit_horner(&key, &data),
                    "seed {seed} length {len} against the 26-bit horner"
                );

                // Every split point at and above the threshold, because a split
                // is how a caller hands the vector path an accumulator that is
                // *not* freshly zero: the first `update` leaves `h` at zero, and
                // only a second one puts a value through `to_26`. A repack that
                // is wrong about a nonzero accumulator is invisible to every
                // one-shot tag above.
                if len >= NEON_THRESHOLD_BYTES {
                    for split in 0..=len {
                        let mut split_state = Poly1305::new(&key);
                        split_state.update(&data[..split]);
                        split_state.update(&data[split..]);
                        assert_eq!(
                            split_state.finish(),
                            shipped,
                            "seed {seed} length {len} split {split}"
                        );
                    }
                }
            }
        }
    }

    /// The two-way path at large lengths, one-shot and at sampled splits.
    ///
    /// Eight kilobytes is five hundred twelve blocks (even) and `8208` is five
    /// hundred thirteen (odd); both run the `NEON` halves, where the
    /// every-split sweep above only reaches `4097`. Splits are sampled at the
    /// halves' boundaries rather than everywhere: the midpoint either side,
    /// the block edges, and the ends, which are the points where a run-weight
    /// off by one or a contiguous-versus-interleaved mix-up changes the tag.
    /// The eight-hundred-forty-four-length one-shot sweep is the shape the
    /// vector path was first measured on, four keys, against the same crate.
    #[test]
    fn large_lengths_and_awkward_splits_are_the_crate_too() {
        use poly1305::universal_hash::KeyInit as _;

        fn theirs(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
            let k: &poly1305::Key = poly1305::Key::from_slice(&key[..]);
            poly1305::Poly1305::new(k).compute_unpadded(data).into()
        }

        let mut checked = 0usize;
        for seed in 0..4u8 {
            let key: [u8; 32] =
                std::array::from_fn(|i| (i as u8).wrapping_mul(197).wrapping_add(seed * 61));
            for len in (0..=844usize).chain([2048, 4096, 8192, 8208]) {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                assert_eq!(tag(&key, &data), want, "seed {seed} length {len}");
                checked += 1;
            }
            for len in [2048usize, 4096, 8192, 8208] {
                let data: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
                    .collect();
                let want = theirs(&key, &data);
                let mut splits = vec![
                    0,
                    1,
                    15,
                    16,
                    17,
                    31,
                    32,
                    len - 17,
                    len - 16,
                    len - 15,
                    len - 1,
                    len,
                ];
                let half = len / 2;
                splits.extend([
                    half - 17,
                    half - 16,
                    half - 15,
                    half - 1,
                    half,
                    half + 1,
                    half + 15,
                    half + 16,
                    half + 17,
                ]);
                splits.sort_unstable();
                splits.dedup();
                for split in splits {
                    let mut state = Poly1305::new(&key);
                    state.update(&data[..split]);
                    state.update(&data[split..]);
                    assert_eq!(
                        state.finish(),
                        want,
                        "seed {seed} length {len} split {split}"
                    );
                }
            }
        }
        assert!(checked > 3000, "the sweep should be dense, not a sample");
    }
}
