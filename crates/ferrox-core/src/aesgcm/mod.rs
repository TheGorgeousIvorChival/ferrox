//! `AES-128-GCM`: the cipher `VMess` data frames and `aes-128-gcm` Shadowsocks
//! chunks are sealed with, on this crate's own fused engine.
//!
//! # Why it exists
//!
//! The call sites used to run the `aes-gcm` crate. That crate computes the two
//! halves of `GCM` in two passes over the message: a `CTR` pass that encrypts,
//! then a `GHASH` pass that re-reads the ciphertext one block at a time —
//! interleaving the two is a known open note in its own tracker
//! (`RustCrypto/AEADs#74`). And the `GHASH` pass is a serial chain: each
//! block's multiply cannot start until the previous block's reduction
//! finished, because `Y <- (Y ^ X) * H` is a recurrence.
//!
//! This module is the interleaved, widened version of exactly that arithmetic:
//!
//! * **Fused.** The `CTR` pass produces each ciphertext block in a register and
//!   the `GHASH` aggregation consumes it from the same register. The message is
//!   read once and written once; there is no second pass over it and no scratch
//!   buffer.
//! * **Four blocks per reduction — eight where the vectors are wide.** `GHASH`
//!   is a Horner chain in `GF(2^128)`, and Horner chains re-associate:
//!   `((((Y^X1)*H)^X2)*H^X3)*H... = Y*H^4 ^ X1*H^4 ^ X2*H^3 ^ X3*H^2 ^ X4*H`.
//!   The products on the right are *independent*, so the serial dependency the
//!   crate pays per block is paid here per group — and reduction, the most
//!   expensive step after the multiply itself, runs once per group instead of
//!   once per block. On a machine with `VAES` and `VPCLMULQDQ` every
//!   instruction does two blocks at once, so the group is eight. This is
//!   exact, not an approximation: polynomial reduction mod `p(x)` is a
//!   `GF(2)`-linear map, so `reduce(a ^ b) = reduce(a) ^ reduce(b)`, and the
//!   unreduced 256-bit products may be summed first and reduced once.
//!   Bit-identity with the one-block-at-a-time chain is a theorem, and the
//!   differential sweep below is its check.
//! * **Per-key powers.** The `H` powers are computed once per session key,
//!   against the grouped recurrence's need for them per message.
//! * **The tail aggregates too.** The last full blocks of a message, its
//!   padded partial and the lengths block fold in *one* reduction with the
//!   powers their positions demand, instead of one serial reduction each. And
//!   the tag mask `E(J0)` is issued before the message loop — it depends on
//!   the nonce alone, so its ten serial rounds overlap the loop instead of
//!   sitting on the critical path after it.
//!
//! # What is shared with the crate, verbatim
//!
//! The arithmetic *kernels* — the carryless multiply and the reduction — are
//! transcribed from the `polyval` crate's two hardware backends (`clmul.rs`
//! for `x86_64`, `pmull.rs` for `aarch64`), the same code `aes-gcm`'s `GHASH`
//! bottoms out in. `GHASH` is `POLYVAL` with the operands byte-reversed and `H`
//! pre-multiplied by `x` (`RFC 8452` appendix A), which is the whole content of
//! the `ghash` crate's adapter and is reproduced here unchanged: every block is
//! reversed before the multiply, `H` is reversed and `mulx`'d once at setup,
//! and the final state is reversed back. What changes is only *how many
//! multiplies are in flight per reduction* — the scheduling, never the
//! arithmetic.
//!
//! # The layout
//!
//! The `GCM` flow — `J0`, the `CTR` counters, the padding, the lengths block,
//! the tag — is written once, generically over the crate-private `Lanes`
//! trait, and each architecture module supplies the five primitives the flow
//! needs. That is the discipline `chacha` already uses: one algorithm, one
//! portable implementation, one thin layer per architecture, so the only thing
//! a backend can get wrong is a single instruction, and the differential sweep
//! is what checks them.
//!
//! # The fallback
//!
//! A machine without the hardware instructions keeps exactly what it has today:
//! the `aes-gcm` crate, held as the `Crate` variant of the dispatch enum. Every
//! target this workspace ships a timed claim about has the instructions, and CI
//! runs the sweep against the hardware path; the fallback is the same crate on
//! the same terms as before this module existed.

// Every function in this module that touches a lane primitive is
// `inline(always)`, for the reason `chacha/mod.rs` states: an outlined function
// does not inherit the `#[target_feature]` of its caller, so the intrinsics
// inside it would lose their feature. `inline` is a hint; this is a guarantee.
#![allow(
    clippy::inline_always,
    reason = "lane primitives are only sound inside the caller's target_feature function"
)]

#[cfg(target_arch = "aarch64")]
mod arm;
#[cfg(target_arch = "x86_64")]
mod x86;
#[cfg(target_arch = "x86_64")]
mod x86v;

/// A 128-bit lane: the four `GHASH` primitives and the two `AES` shapes the
/// generic flow is written against.
///
/// # Safety
///
/// An implementor must uphold all of the following, and the differential sweep
/// is what checks them:
///
/// - `load`/`store` move exactly 16 bytes, in memory order;
/// - `bswap` reverses the 16 bytes; `swap_halves` exchanges the two 64-bit
///   halves without reversing them;
/// - `mul_add` accumulates the unreduced 256-bit carryless product of `a` and
///   `h` into `acc`, where `hxs` is `h ^ swap_halves(h)`, in whatever shape
///   `reduce` consumes — the arithmetic is the `POLYVAL` field's, i.e. the
///   reflected representation the `ghash` crate's adapter expects;
/// - `reduce` maps the accumulated products back to the 128-bit field element,
///   and `reduce` over an `XOR` sum of products equals the `XOR` of their
///   individual reductions (linearity — the fact the four-wide aggregation
///   stands on);
/// - `encrypt4` is ten `AES-128` rounds over four independent blocks,
///   `encrypt1` the same over one block, both keyed by the schedule `new`
///   built.
pub(crate) trait Lanes: Copy {
    /// Load 16 bytes, unaligned.
    fn load(b: &[u8; 16]) -> Self;
    /// Store 16 bytes, unaligned.
    fn store(self, b: &mut [u8; 16]);
    /// Lane-wise `XOR`.
    fn xor(self, o: Self) -> Self;
    /// Reverse the 16 bytes.
    fn bswap(self) -> Self;
    /// Exchange the two 64-bit halves, bytes within a half untouched.
    fn swap_halves(self) -> Self;
    /// `acc ^= mul256(a, h)`: accumulate the unreduced product. `hxs` is
    /// `h ^ swap_halves(h)`, precomputed once per power.
    fn mul_add(acc: &mut [Self; 4], a: Self, h: Self, hxs: Self);
    /// Reduce the accumulated products to the field element.
    fn reduce(acc: [Self; 4]) -> Self;
    /// Add `n` to the low 32 bits, which are held in *native* order: the
    /// counter lives in the register for the whole message and the
    /// big-endian `GCM` wants is one `ctr_swap` per block rather than a
    /// store-load round trip per counter.
    fn ctr_add(self, n: u32) -> Self;
    /// Reverse the last four bytes, leaving the nonce's twelve alone: the
    /// native-order counter becomes `GCM`'s big-endian `inc32` block.
    fn ctr_swap(self) -> Self;
    /// `AES-128` encryption of four independent blocks, in place.
    fn encrypt4(rk: &[Self; 11], s: &mut [Self; 4]);
    /// `AES-128` encryption of one block, register in, register out.
    fn encrypt1v(rk: &[Self; 11], s: Self) -> Self;
    /// `AES-128` encryption of one block, bytes in, bytes out.
    #[inline(always)]
    fn encrypt1(rk: &[Self; 11], b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        Self::encrypt1v(rk, Self::load(b)).store(&mut out);
        out
    }
    /// `AES-256` encryption of four independent blocks, in place.
    fn encrypt4_256(rk: &[Self; 15], s: &mut [Self; 4]);
    /// `AES-256` encryption of one block, register in, register out.
    fn encrypt1v_256(rk: &[Self; 15], s: Self) -> Self;
    /// `AES-256` encryption of one block, bytes in, bytes out.
    #[inline(always)]
    fn encrypt1_256(rk: &[Self; 15], b: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        Self::encrypt1v_256(rk, Self::load(b)).store(&mut out);
        out
    }
}

/// The queued tail of a section: up to four `GHASH` blocks in chain order and
/// their count. Three full blocks plus one padded partial is the most a
/// section tail can hold; the lengths block joins them in [`finish`].
pub(crate) struct Tail<V> {
    /// The queued blocks.
    blocks: [V; 4],
    /// How many of them are live.
    len: usize,
}

impl<V: Lanes> Tail<V> {
    /// The empty queue.
    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self {
            blocks: [V::load(&[0u8; 16]); 4],
            len: 0,
        }
    }

    /// Queue one more block. The count never reaches five: a section tail is
    /// at most four blocks, and [`finish`] pre-folds before appending the
    /// lengths.
    #[inline(always)]
    pub(crate) fn push(&mut self, x: V) {
        self.blocks[self.len] = x;
        self.len += 1;
    }
}

/// The `mulX_POLYVAL()` doubling of `RFC 8452` appendix A, transcribed from the
/// `polyval` crate's `mulx.rs`: the one-time conversion of `GHASH`'s `H` into
/// the `POLYVAL` field element the multiply-and-reduce kernels operate on.
fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;
    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

/// Four consecutive counter blocks from the template, `ctr` first.
///
/// The template's low 32 bits are zero in *native* order; the first add makes
/// them `ctr` and each block after takes one more native increment, with the
/// big-endian reversal applied per block — `GCM`'s `inc32` is an add in the
/// native domain plus a four-byte reversal, rather than a store-load round
/// trip through a byte-built block per counter.
#[inline(always)]
fn ctr4v<V: Lanes>(template: V, ctr: u32) -> [V; 4] {
    let c = template.ctr_add(ctr);
    let c0 = c.ctr_swap();
    let c = c.ctr_add(1);
    let c1 = c.ctr_swap();
    let c = c.ctr_add(1);
    let c2 = c.ctr_swap();
    let c3 = c.ctr_add(1).ctr_swap();
    [c0, c1, c2, c3]
}

/// One field multiplication: `(y ^ x) * h`, reduced.
///
/// The single-block shape the power ladder and an over-full tail take:
/// nothing to aggregate, so the one reduction is paid for the one multiply,
/// exactly as the serial chain pays it.
#[inline(always)]
pub(crate) fn mul1<V: Lanes>(x: V, h: (V, V)) -> V {
    let mut acc = [V::load(&[0u8; 16]); 4];
    V::mul_add(&mut acc, x, h.0, h.1);
    V::reduce(acc)
}

/// Four blocks of the Horner chain as one reduction.
///
/// `x[0]` must already carry the running `Y` (`y ^ block_0`); the other three
/// are their blocks plain. The first block of a group is multiplied by `H^4`
/// and the last by `H`, which is the re-associated form of four serial steps.
#[inline(always)]
fn ghash_group<V: Lanes>(h: &[(V, V); 4], x: [V; 4]) -> V {
    let mut acc = [V::load(&[0u8; 16]); 4];
    V::mul_add(&mut acc, x[0], h[3].0, h[3].1);
    V::mul_add(&mut acc, x[1], h[2].0, h[2].1);
    V::mul_add(&mut acc, x[2], h[1].0, h[1].1);
    V::mul_add(&mut acc, x[3], h[0].0, h[0].1);
    V::reduce(acc)
}

/// `GHASH` over `data`: groups of four while they last; the remaining full
/// blocks and the zero-padded final partial block — `update_padded`'s padding,
/// which is no block at all for a multiple of sixteen — are *queued* for the
/// caller's next [`flush`] rather than reduced one at a time: the chain's last
/// few blocks aggregate with whatever follows them, one reduction for the lot.
///
/// The queue starts empty at every section: the caller flushes between
/// sections, so a group's first block is always the section's first.
#[inline(always)]
pub(crate) fn ghash<V: Lanes>(
    hp: &[(V, V); 4],
    mut state: V,
    data: &[u8],
    tail: &mut Tail<V>,
) -> V {
    let (blocks, rest_bytes) = data.as_chunks::<16>();
    let (groups, rest) = blocks.as_chunks::<4>();
    for quad in groups {
        state = ghash_group(
            hp,
            [
                state.xor(V::load(&quad[0]).bswap()),
                V::load(&quad[1]).bswap(),
                V::load(&quad[2]).bswap(),
                V::load(&quad[3]).bswap(),
            ],
        );
    }
    for blk in rest {
        tail.push(V::load(blk).bswap());
    }
    if !rest_bytes.is_empty() {
        let mut padded = [0u8; 16];
        padded[..rest_bytes.len()].copy_from_slice(rest_bytes);
        tail.push(V::load(&padded).bswap());
    }
    state
}

/// The queued tail of a section, folded into the chain with one reduction.
///
/// The oldest queued block is multiplied by `H^n` and the newest by `H`, the
/// re-associated form of the `n` serial steps the crate would take; the empty
/// queue is the identity. The queue is left empty.
#[inline(always)]
pub(crate) fn flush<V: Lanes>(hp: &[(V, V); 4], state: V, tail: &mut Tail<V>) -> V {
    if tail.len == 0 {
        return state;
    }
    let qlen = tail.len;
    tail.len = 0;
    let mut acc = [V::load(&[0u8; 16]); 4];
    for (i, blk) in tail.blocks[..qlen].iter().enumerate() {
        let blk = if i == 0 { state.xor(*blk) } else { *blk };
        V::mul_add(&mut acc, blk, hp[qlen - 1 - i].0, hp[qlen - 1 - i].1);
    }
    V::reduce(acc)
}

/// The fused half: `CTR`-encrypt `buf` in place and queue the ciphertext's
/// `GHASH` blocks, four blocks per pass, each block consumed from the register
/// it was produced in — the message is never re-read.
///
/// The keystream blocks are the counters `2, 3, 4, ...` under `E`, i.e.
/// `inc32(J0)` first, per `SP 800-38D` section 7.2.
#[inline(always)]
pub(crate) fn ctr_ghash<V: Lanes>(
    rk: &[V; 11],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    buf: &mut [u8],
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&quad[0])),
            ksv[1].xor(V::load(&quad[1])),
            ksv[2].xor(V::load(&quad[2])),
            ksv[3].xor(V::load(&quad[3])),
        ];
        ct4[0].store(&mut quad[0]);
        ct4[1].store(&mut quad[1]);
        ct4[2].store(&mut quad[2]);
        ct4[3].store(&mut quad[3]);
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v(rk, template.ctr_add(ctr).ctr_swap());
        let ct1 = ks1.xor(V::load(blk));
        ct1.store(blk);
        tailq.push(ct1.bswap());
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v(rk, template.ctr_add(ctr).ctr_swap());
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for ((xb, kb), pb) in tail.iter_mut().zip(ksb.iter()).zip(padded.iter_mut()) {
            let v = *xb ^ kb;
            *xb = v;
            *pb = v;
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

/// The open half's second pass: the tag has verified, so the counters walk the
/// buffer again and turn it into plaintext. Four blocks per pass, nothing else.
#[inline(always)]
pub(crate) fn ctr_only<V: Lanes>(rk: &[V; 11], template: V, buf: &mut [u8], mut ctr: u32) {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4(rk, &mut ksv);
        for (ks, gi) in ksv.iter().zip(quad.iter_mut()) {
            let ct1 = ks.xor(V::load(gi));
            ct1.store(gi);
        }
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v(rk, template.ctr_add(ctr).ctr_swap());
        ks1.xor(V::load(blk)).store(blk);
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v(rk, template.ctr_add(ctr).ctr_swap());
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        for (xb, kb) in tail.iter_mut().zip(ksb.iter()) {
            *xb ^= kb;
        }
    }
}

/// The lengths block joins the section's queued tail, the tail folds in one
/// reduction, and the tag is the state reversed back out of the reflected
/// representation, masked — `SP 800-38D` section 7.2's `GHASH(A || 0^v || C ||
/// 0^u || [len(A)]_64 || [len(C)]_64)` with the lengths as sixty-four-bit
/// big-endian *bit* counts.
///
/// The mask is `E(J0)`, computed by the caller *before* the message loop: it
/// depends on the nonce alone, and issuing it early lets it overlap the loop
/// instead of exposing its ten serial rounds after it.
#[inline(always)]
pub(crate) fn finish<V: Lanes>(
    hp: &[(V, V); 4],
    mut state: V,
    tailq: &mut Tail<V>,
    aad: u64,
    ct: u64,
    mask: V,
) -> [u8; 16] {
    if tailq.len == 4 {
        // Three full blocks, a padded partial and now the lengths: five blocks
        // will not aggregate under four powers, so the oldest folds singly.
        state = mul1(state.xor(tailq.blocks[0]), hp[0]);
        tailq.blocks.copy_within(1.., 0);
        tailq.len = 3;
    }
    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad * 8).to_be_bytes());
    lens[8..].copy_from_slice(&(ct * 8).to_be_bytes());
    tailq.push(V::load(&lens).bswap());
    let state = flush(hp, state, tailq);
    // `tag = reverse(state) ^ mask` per byte; the reverse commutes with the
    // xor, so it is one reversal of `state ^ reverse(mask)`.
    let mut tag = [0u8; 16];
    state.xor(mask.bswap()).store(&mut tag);
    tag.reverse();
    tag
}

/// The template both counter shapes are built from: the nonce with its low 32
/// bits zero in *native* order.
#[inline(always)]
pub(crate) fn counter_template<V: Lanes>(nonce: &[u8; 12]) -> V {
    let mut bytes = [0u8; 16];
    bytes[..12].copy_from_slice(nonce);
    V::load(&bytes)
}

/// Seal, on whichever lanes the engine carries.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn seal_impl<V: Lanes>(
    rk: &[V; 11],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let template = counter_template::<V>(nonce);
    // `J0` is the template's counter at 1; the mask is independent of the
    // message, so it is issued first and overlaps the loop.
    let mask = V::encrypt1v(rk, template.ctr_add(1).ctr_swap());
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ctr_ghash(rk, h, template, state, buf, &mut tailq, 2);
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        buf.len() as u64,
        mask,
    )
}

/// Open, on whichever lanes the engine carries: authenticate first, and only a
/// matching tag lets the buffer turn into plaintext.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn open_impl<V: Lanes>(
    rk: &[V; 11],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Option<usize> {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v(rk, template.ctr_add(1).ctr_swap());
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ghash(h, state, buf, &mut tailq);
    let want = finish(
        h,
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

    ctr_only(rk, template, buf, 2);
    Some(buf.len())
}

/// `H` and its first four powers, in the reflected representation the kernels
/// multiply in, each paired with its `h ^ swap_halves(h)` middle-term constant.
///
/// `H` itself is `E_K(0)` reversed and doubled (`mulx`), which is the `ghash`
/// crate's whole adapter to the `POLYVAL` field; the powers are ordinary field
/// multiplications of that element, so they are computed by the same kernels
/// the message sees.
#[inline(always)]
pub(crate) fn powers<V: Lanes>(rk: &[V; 11]) -> [(V, V); 4] {
    let h0 = {
        let mut reversed = V::encrypt1(rk, &[0u8; 16]);
        reversed.reverse();
        V::load(&mulx(&reversed))
    };
    let pair = |h: V| (h, h.xor(h.swap_halves()));
    let h1 = mul1(h0, pair(h0));
    let h2 = mul1(h1, pair(h0));
    let h3 = mul1(h1, pair(h1));
    [pair(h0), pair(h1), pair(h2), pair(h3)]
}

/// An `AES-128-GCM` session: the expanded key and the `H` powers, built once.
///
/// Built per session the way the crate's `Aes128Gcm` is built per session, and
/// sealed/opened against the same nonce rules. On a machine with the hardware
/// instructions this is the fused engine above; anywhere else it is the
/// `aes-gcm` crate itself, which is what those machines run today.
pub struct Aes128Gcm {
    inner: Inner,
}

/// The dispatch: one hardware engine where one exists, the crate elsewhere.
///
/// Every variant is boxed: the engines are three hundred bytes of round keys
/// and powers against the fallback's pointer, and a session is built once per
/// connection, so the one allocation at setup is the right trade for a small
/// `Aes128Gcm`.
enum Inner {
    /// `VAES` + `VPCLMULQDQ`, 256-bit: two blocks per register, eight in
    /// flight, on the `x86_64` machines that have it.
    #[cfg(target_arch = "x86_64")]
    X86V(Box<x86v::Engine>),
    /// `AES-NI` + `PCLMULQDQ` on `x86_64`.
    #[cfg(target_arch = "x86_64")]
    X86(Box<x86::Engine>),
    /// `ARMv8` `AES` + `PMULL` on `aarch64`.
    #[cfg(target_arch = "aarch64")]
    Arm(Box<arm::Engine>),
    /// The `aes-gcm` crate: what ran here before this module, kept for machines
    /// without the hardware instructions.
    Crate(Box<aes_gcm::Aes128Gcm>),
}

impl core::fmt::Debug for Aes128Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The backend name, never the key material.
        f.debug_struct("Aes128Gcm")
            .field("backend", &self.backend())
            .finish()
    }
}

impl Aes128Gcm {
    /// Build the session: expand the key, derive `H`, and precompute the four
    /// powers the grouped reduction consumes.
    ///
    /// The hardware engine is chosen by a runtime probe; without it the crate
    /// path is taken, which dispatches inside itself exactly as it does today.
    ///
    /// # Panics
    ///
    /// Never: the one fallible construction inside is the crate's key-length
    /// check, and a 16-byte key is valid `AES-128` by definition.
    #[must_use]
    pub fn new(key: &[u8; 16]) -> Self {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx2")
            && std::is_x86_feature_detected!("vaes")
            && std::is_x86_feature_detected!("vpclmulqdq")
            && std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            // SAFETY: the six probes name every feature the engine's
            // `target_feature` functions carry.
            let engine = unsafe { Box::new(x86v::Engine::new(key)) };
            return Self {
                inner: Inner::X86V(engine),
            };
        }
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            // SAFETY: the three probes name every feature the engine's
            // `target_feature` functions carry.
            let engine = unsafe { Box::new(x86::Engine::new(key)) };
            return Self {
                inner: Inner::X86(engine),
            };
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
            && std::arch::is_aarch64_feature_detected!("neon")
        {
            // SAFETY: the three probes name every feature the engine's
            // `target_feature` functions carry.
            let engine = unsafe { Box::new(arm::Engine::new(key)) };
            return Self {
                inner: Inner::Arm(engine),
            };
        }
        Self {
            inner: Inner::Crate(Box::new(
                aes_gcm::KeyInit::new_from_slice(key).expect("a 16-byte key is valid AES-128"),
            )),
        }
    }

    /// Which engine this session dispatches to, for the report: a number is
    /// only attributable when both sides of it are named.
    #[must_use]
    pub const fn backend(&self) -> &'static str {
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(_) => "vaes-256 + vpclmulqdq, fused 8-block, deferred reduction",
            #[cfg(target_arch = "x86_64")]
            Inner::X86(_) => "aes-ni + pclmulqdq, fused 4-block, deferred reduction",
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(_) => "armv8 aes + pmull, fused 8-block, deferred reduction",
            Inner::Crate(_) => "aes-gcm 0.10 (crate fallback)",
        }
    }

    /// Seal `buf` in place and return the sixteen-byte tag.
    ///
    /// One buffer rather than two, the shape [`crate::aead`] takes for the same
    /// reason: `C = P XOR GCTR(...)` means the plaintext already in the caller's
    /// buffer is turned into the ciphertext in place, and the tag is over the
    /// ciphertext, computed from the bytes now sitting in `buf`.
    ///
    /// # Panics
    ///
    /// If `buf` or `aad` exceeds the `GCM` limit of `2^32 - 2` blocks (about
    /// 64 GiB) or `2^61 - 1` bytes — the lengths the spec's counter and bit
    /// counts cannot express. The crate's interface refuses these with an
    /// error; this interface's callers (records and chunks of at most 16 KiB)
    /// never approach them, so they are asserted instead.
    #[must_use]
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.seal(nonce, aad, buf) }
            }
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.seal(nonce, aad, buf) }
            }
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.seal(nonce, aad, buf) }
            }
            Inner::Crate(c) => {
                use aes_gcm::aead::AeadInPlace as _;
                c.encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, buf)
                    .expect("the length limits above are the crate's own refusal conditions")
                    .into()
            }
        }
    }

    /// Open `buf`, which holds the ciphertext, in place, if `tag` is the tag
    /// for it.
    ///
    /// Returns the plaintext length on success and `None` on a tag that does
    /// not match. On `None` the contents of `buf` are unchanged: the tag is
    /// checked over the ciphertext as it arrived, and nothing is decrypted
    /// until it has matched.
    ///
    /// # Panics
    ///
    /// Under the same length limits as [`Aes128Gcm::seal_in_place`].
    #[must_use]
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM ciphertext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner::X86V(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.open(nonce, aad, buf, tag) }
            }
            #[cfg(target_arch = "x86_64")]
            Inner::X86(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.open(nonce, aad, buf, tag) }
            }
            #[cfg(target_arch = "aarch64")]
            Inner::Arm(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.open(nonce, aad, buf, tag) }
            }
            Inner::Crate(c) => {
                use aes_gcm::aead::AeadInPlace as _;
                c.decrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(nonce),
                    aad,
                    buf,
                    aes_gcm::Tag::from_slice(tag),
                )
                .ok()?;
                Some(buf.len())
            }
        }
    }
}

/// `H` and its first four powers, for a `256`-bit key: the re-association is
/// the same, and so is the Horner fold — only the encrypt rounds differ.
#[inline(always)]
pub(crate) fn powers_256<V: Lanes>(rk: &[V; 15]) -> [(V, V); 4] {
    let h0 = {
        let mut reversed = V::encrypt1_256(rk, &[0u8; 16]);
        reversed.reverse();
        V::load(&mulx(&reversed))
    };
    let pair = |h: V| (h, h.xor(h.swap_halves()));
    let h1 = mul1(h0, pair(h0));
    let h2 = mul1(h1, pair(h0));
    let h3 = mul1(h1, pair(h1));
    [pair(h0), pair(h1), pair(h2), pair(h3)]
}

/// The fused `CTR` + `GHASH` loop over `buf`, four blocks per pass, on
/// `AES-256`'s fifteen round keys.
#[inline(always)]
pub(crate) fn ctr_ghash_256<V: Lanes>(
    rk: &[V; 15],
    hp: &[(V, V); 4],
    template: V,
    mut state: V,
    buf: &mut [u8],
    tailq: &mut Tail<V>,
    mut ctr: u32,
) -> V {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4_256(rk, &mut ksv);
        let ct4 = [
            ksv[0].xor(V::load(&quad[0])),
            ksv[1].xor(V::load(&quad[1])),
            ksv[2].xor(V::load(&quad[2])),
            ksv[3].xor(V::load(&quad[3])),
        ];
        ct4[0].store(&mut quad[0]);
        ct4[1].store(&mut quad[1]);
        ct4[2].store(&mut quad[2]);
        ct4[3].store(&mut quad[3]);
        state = ghash_group(
            hp,
            [
                state.xor(ct4[0].bswap()),
                ct4[1].bswap(),
                ct4[2].bswap(),
                ct4[3].bswap(),
            ],
        );
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v_256(rk, template.ctr_add(ctr).ctr_swap());
        let ct1 = ks1.xor(V::load(blk));
        ct1.store(blk);
        tailq.push(ct1.bswap());
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v_256(rk, template.ctr_add(ctr).ctr_swap());
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        let mut padded = [0u8; 16];
        for ((xb, kb), pb) in tail.iter_mut().zip(ksb.iter()).zip(padded.iter_mut()) {
            let v = *xb ^ kb;
            *xb = v;
            *pb = v;
        }
        tailq.push(V::load(&padded).bswap());
    }
    state
}

/// The open half's second pass, on `AES-256`'s fifteen round keys.
#[inline(always)]
pub(crate) fn ctr_only_256<V: Lanes>(rk: &[V; 15], template: V, buf: &mut [u8], mut ctr: u32) {
    let (blocks, tail) = buf.as_chunks_mut::<16>();
    let (groups, rest) = blocks.as_chunks_mut::<4>();
    for quad in groups {
        let mut ksv = ctr4v(template, ctr);
        V::encrypt4_256(rk, &mut ksv);
        for (ks, gi) in ksv.iter().zip(quad.iter_mut()) {
            let ct1 = ks.xor(V::load(gi));
            ct1.store(gi);
        }
        ctr += 4;
    }
    for blk in rest {
        let ks1 = V::encrypt1v_256(rk, template.ctr_add(ctr).ctr_swap());
        ks1.xor(V::load(blk)).store(blk);
        ctr += 1;
    }
    if !tail.is_empty() {
        let ks1 = V::encrypt1v_256(rk, template.ctr_add(ctr).ctr_swap());
        let mut ksb = [0u8; 16];
        ks1.store(&mut ksb);
        for (xb, kb) in tail.iter_mut().zip(ksb.iter()) {
            *xb ^= kb;
        }
    }
}

/// Seal, on whichever lanes the engine carries, for a `256`-bit key.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn seal_impl_256<V: Lanes>(
    rk: &[V; 15],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v_256(rk, template.ctr_add(1).ctr_swap());
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ctr_ghash_256(rk, h, template, state, buf, &mut tailq, 2);
    finish(
        h,
        state,
        &mut tailq,
        aad.len() as u64,
        buf.len() as u64,
        mask,
    )
}

/// Open, on whichever lanes the engine carries, for a `256`-bit key.
#[inline(always)]
#[cfg(target_arch = "x86_64")]
pub(crate) fn open_impl_256<V: Lanes>(
    rk: &[V; 15],
    h: &[(V, V); 4],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Option<usize> {
    let template = counter_template::<V>(nonce);
    let mask = V::encrypt1v_256(rk, template.ctr_add(1).ctr_swap());
    let mut tailq = Tail::new();
    let state = ghash(h, V::load(&[0u8; 16]), aad, &mut tailq);
    let state = flush(h, state, &mut tailq);
    let state = ghash(h, state, buf, &mut tailq);
    let want = finish(
        h,
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
    ctr_only_256(rk, template, buf, 2);
    Some(buf.len())
}

/// An `AES-256-GCM` session: the expanded key and the `H` powers, built once.
///
/// Mirrors [`Aes128Gcm`] exactly, with the `256`-bit key schedule and its
/// fourteen rounds; on machines without the instructions it falls back to the
/// same `aes-gcm` crate everywhere else.
pub struct Aes256Gcm {
    inner: Inner256,
}

/// The dispatch, one hardware engine where one exists.
enum Inner256 {
    #[cfg(target_arch = "x86_64")]
    X86V(Box<x86v::Engine256>),
    #[cfg(target_arch = "x86_64")]
    X86(Box<x86::Engine256>),
    #[cfg(target_arch = "aarch64")]
    Arm(Box<arm::Engine256>),
    Crate(Box<aes_gcm::Aes256Gcm>),
}

impl core::fmt::Debug for Aes256Gcm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Aes256Gcm")
            .field("backend", &self.backend())
            .finish()
    }
}

impl Aes256Gcm {
    /// Build the session: expand the `256`-bit key, derive `H`, and
    /// precompute the four powers the grouped reduction consumes.
    ///
    /// # Panics
    ///
    /// Never: the one fallible construction inside is the crate's key-length
    /// check, and a 32-byte key is valid `AES-256` by definition.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("avx2")
            && std::is_x86_feature_detected!("vaes")
            && std::is_x86_feature_detected!("vpclmulqdq")
            && std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            // SAFETY: the six probes name every feature the engine's
            // `target_feature` functions carry.
            let engine = unsafe { Box::new(x86v::Engine256::new(key)) };
            return Self {
                inner: Inner256::X86V(engine),
            };
        }
        #[cfg(target_arch = "x86_64")]
        if std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3")
        {
            // SAFETY: the three probes name every feature the engine's
            // `target_feature` functions carry.
            let engine = unsafe { Box::new(x86::Engine256::new(key)) };
            return Self {
                inner: Inner256::X86(engine),
            };
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
            && std::arch::is_aarch64_feature_detected!("neon")
        {
            // SAFETY: the three probes name every feature the engine's
            // `target_feature` functions carry.
            let engine = unsafe { Box::new(arm::Engine256::new(key)) };
            return Self {
                inner: Inner256::Arm(engine),
            };
        }
        Self {
            inner: Inner256::Crate(Box::new(
                aes_gcm::KeyInit::new_from_slice(key).expect("a 32-byte key is valid AES-256"),
            )),
        }
    }

    /// Which engine this session dispatches to, for the report.
    #[must_use]
    pub const fn backend(&self) -> &'static str {
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(_) => "vaes-256 + vpclmulqdq, fused 8-block, deferred reduction",
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(_) => "aes-ni + pclmulqdq, fused 4-block, deferred reduction",
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(_) => "armv8 aes + pmull, fused 8-block, deferred reduction",
            Inner256::Crate(_) => "aes-gcm 0.10 (crate fallback)",
        }
    }

    /// Seal `buf` in place and return the sixteen-byte tag, under the same
    /// length limits as [`Aes128Gcm::seal_in_place`].
    ///
    /// # Panics
    ///
    /// Under the same length limits as the `128` path.
    #[must_use]
    pub fn seal_in_place(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM plaintext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.seal(nonce, aad, buf) }
            }
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => {
                // SAFETY: as above.
                unsafe { e.seal(nonce, aad, buf) }
            }
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                // SAFETY: as above.
                unsafe { e.seal(nonce, aad, buf) }
            }
            Inner256::Crate(c) => {
                use aes_gcm::aead::AeadInPlace as _;
                c.encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, buf)
                    .expect("the length limits above are the crate's own refusal conditions")
                    .into()
            }
        }
    }

    /// Open `buf` in place if `tag` matches; the buffer is unchanged on
    /// mismatch, under the same length limits as [`Aes128Gcm::open_in_place`].
    ///
    /// # Panics
    ///
    /// Under the same length limits as the `128` path.
    #[must_use]
    pub fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Option<usize> {
        assert!(
            (buf.len() as u64) <= (u64::from(u32::MAX) - 1) * 16,
            "GCM ciphertext is at most 2^32 - 2 blocks"
        );
        assert!(
            (aad.len() as u64) < (1u64 << 61),
            "GCM associated data is at most 2^61 - 1 bytes"
        );
        match &self.inner {
            #[cfg(target_arch = "x86_64")]
            Inner256::X86V(e) => {
                // SAFETY: the engine exists only because the probes passed.
                unsafe { e.open(nonce, aad, buf, tag) }
            }
            #[cfg(target_arch = "x86_64")]
            Inner256::X86(e) => {
                // SAFETY: as above.
                unsafe { e.open(nonce, aad, buf, tag) }
            }
            #[cfg(target_arch = "aarch64")]
            Inner256::Arm(e) => {
                // SAFETY: as above.
                unsafe { e.open(nonce, aad, buf, tag) }
            }
            Inner256::Crate(c) => {
                use aes_gcm::aead::AeadInPlace as _;
                c.decrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(nonce),
                    aad,
                    buf,
                    aes_gcm::Tag::from_slice(tag),
                )
                .ok()?;
                Some(buf.len())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;

    /// The reference: the `aes-gcm` crate's own seal, spelled out at each call
    /// site rather than imported once, so the comparison's other side is
    /// visible where it is made.
    fn crate_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        aes_gcm::Aes128Gcm::new_from_slice(key)
            .expect("key")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, buf)
            .expect("seals")
            .into()
    }

    /// The two `McGrew & Viega` zero-key cases: the `GCM` specification's own
    /// arithmetic, which no differential test against a crate can stand in for
    /// — a mistake the crate and this module *shared* would pass the sweep.
    ///
    /// These are Test Cases 1 and 2 of "The Galois/Counter Mode of Operation",
    /// the empty-message tag and the one-block all-zero ciphertext.
    #[test]
    fn the_gcm_spec_vectors() {
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let engine = Aes128Gcm::new(&key);

        let tag = engine.seal_in_place(&nonce, &[], &mut []);
        assert_eq!(
            tag,
            [
                0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61, 0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7,
                0x45, 0x5a
            ],
            "test case 1: the empty message's tag"
        );

        let mut buf = [0u8; 16];
        let tag = engine.seal_in_place(&nonce, &[], &mut buf);
        assert_eq!(
            buf,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2,
                0xfe, 0x78
            ],
            "test case 2: one zero block's ciphertext"
        );
        assert_eq!(
            tag,
            [
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57,
                0xbd, 0xdf
            ],
            "test case 2: one zero block's tag"
        );
    }

    /// The spec's `aad` case: three full blocks and a twelve-byte tail, with
    /// twenty bytes of `aad` exercising the padded partial block in front of
    /// them. (The four-wide aggregation's identity half is the sweep below:
    /// the spec's own vectors are all shorter than one group.)
    ///
    /// `McGrew & Viega`'s case with the `fe/ff`-patterned key.
    #[test]
    fn the_gcm_spec_vector_with_aad() {
        let key: [u8; 16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad: [u8; 20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let plain: [u8; 60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let want_ct: [u8; 60] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let want_tag = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12,
            0x1a, 0x47,
        ];
        let engine = Aes128Gcm::new(&key);
        let mut buf = plain;
        let tag = engine.seal_in_place(&nonce, &aad, &mut buf);
        assert_eq!(buf, want_ct, "the spec vector's ciphertext");
        assert_eq!(tag, want_tag, "the spec vector's tag");
        assert_eq!(
            engine.open_in_place(&nonce, &aad, &mut buf, &tag),
            Some(60),
            "the spec vector opens"
        );
        assert_eq!(buf, plain, "and opens to the spec's plaintext");
    }

    /// Every length, two keys, three nonces, and every `aad` length that
    /// changes the padding — against the crate, not against a vector.
    ///
    /// The dense prefix `0..=300` crosses every residue modulo 64, which is
    /// every (group, tail) shape the four-wide aggregation can take; the sparse
    /// tail crosses the record sizes the callers actually seal.
    #[test]
    fn is_byte_identical_to_the_crate_it_replaces() {
        let keys: [[u8; 16]; 2] = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let mut checked = 0usize;
        for key in &keys {
            let engine = Aes128Gcm::new(key);
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for len in (0..=300usize).chain([511, 512, 513, 1024, 1400, 4096, 8171, 16383])
                    {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut buf = plain.clone();
                        let tag = engine.seal_in_place(&nonce, &aad, &mut buf);

                        let mut want = plain.clone();
                        let want_tag = crate_seal(key, &nonce, &aad, &mut want);
                        assert_eq!(
                            buf, want,
                            "ciphertext: key {key:02x?} nonce {nonce:02x?} aad {aad_len} len {len}"
                        );
                        assert_eq!(tag, want_tag, "tag: aad {aad_len} len {len}");

                        // And opens, both directions: ours opens the crate's
                        // bytes, the crate opens ours.
                        let mut opened = want.clone();
                        assert_eq!(
                            engine.open_in_place(&nonce, &aad, &mut opened, &want_tag),
                            Some(len),
                            "ours opens the crate's seal at len {len}"
                        );
                        assert_eq!(opened, plain, "len {len} round trips");
                        let mut crate_opened = buf.clone();
                        assert!(
                            aes_gcm::Aes128Gcm::new_from_slice(key)
                                .expect("key")
                                .decrypt_in_place_detached(
                                    aes_gcm::Nonce::from_slice(&nonce),
                                    &aad,
                                    &mut crate_opened,
                                    aes_gcm::Tag::from_slice(&tag),
                                )
                                .is_ok(),
                            "the crate opens ours at len {len}"
                        );
                        assert_eq!(crate_opened, plain, "len {len} round trips the crate");
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 5_000, "the sweep should be dense, not a sample");
    }

    /// A tag one bit off is refused, and the buffer is left as the ciphertext
    /// it was: the check runs before any byte is decrypted.
    #[test]
    fn a_forged_tag_is_refused_and_nothing_is_decrypted() {
        let key = [0x11u8; 16];
        let nonce = [0x22u8; 12];
        let engine = Aes128Gcm::new(&key);
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut buf = plain.clone();
            let tag = engine.seal_in_place(&nonce, b"", &mut buf);
            let ciphertext = buf.clone();
            let mut bad = tag;
            bad[0] ^= 1;
            assert_eq!(
                engine.open_in_place(&nonce, b"", &mut buf, &bad),
                None,
                "length {len} refuses a changed tag"
            );
            assert_eq!(
                buf, ciphertext,
                "length {len}: a wrong tag must not decrypt"
            );
        }
    }

    /// `aad` is part of the tag, so changing it must break it.
    #[test]
    fn aad_is_authenticated() {
        let key = [0x55u8; 16];
        let nonce = [0x66u8; 12];
        let engine = Aes128Gcm::new(&key);
        let mut buf = b"payload".to_vec();
        let tag = engine.seal_in_place(&nonce, b"one", &mut buf);
        assert_eq!(
            engine.open_in_place(&nonce, b"two", &mut buf, &tag),
            None,
            "the tag must not verify under a different aad"
        );
    }

    /// The fallback is the crate, so it agrees with itself; the claim worth a
    /// test is that the *dispatch* builds the same bytes on both variants of
    /// `Inner` — sealing through the crate arm directly must equal the public
    /// interface's answer whatever the probe found.
    #[test]
    fn the_crate_fallback_agrees_with_the_dispatch() {
        let key = [0x77u8; 16];
        let nonce = [0x88u8; 12];
        let dispatched = Aes128Gcm::new(&key);
        let fallback = Aes128Gcm {
            inner: Inner::Crate(Box::new(
                aes_gcm::KeyInit::new_from_slice(&key).expect("key"),
            )),
        };
        for len in [0usize, 1, 64, 65, 512] {
            let plain: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut a = plain.clone();
            let mut b = plain;
            let ta = dispatched.seal_in_place(&nonce, b"ad", &mut a);
            let tb = fallback.seal_in_place(&nonce, b"ad", &mut b);
            assert_eq!((a, ta), (b, tb), "len {len}: dispatch and fallback agree");
        }
    }

    /// Both `x86_64` engines, driven directly: on a `VAES` machine the
    /// dispatch never builds the 128-bit engine, so the sweep alone would
    /// leave the fallback's own path unexercised.
    ///
    /// Every boundary of both group shapes is crossed: 63/64/65 for the
    /// 128-bit engine's four-block groups, 127/128/129 for the 256-bit one's
    /// eight-block groups, and the lengths where the eight-block loop hands
    /// its tail to the 128-bit module.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn both_x86_engines_agree_with_the_crate() {
        if !(std::is_x86_feature_detected!("aes")
            && std::is_x86_feature_detected!("pclmulqdq")
            && std::is_x86_feature_detected!("ssse3"))
        {
            return;
        }
        let key: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(61).wrapping_add(9));
        let nonce = [0xc3u8; 12];
        // SAFETY: the probe above names every feature this engine's
        // `target_feature` functions carry.
        let narrow = unsafe { x86::Engine::new(&key) };
        let wide = if std::is_x86_feature_detected!("avx2")
            && std::is_x86_feature_detected!("vaes")
            && std::is_x86_feature_detected!("vpclmulqdq")
        {
            // SAFETY: the probe above names every feature this engine's
            // `target_feature` functions carry.
            Some(unsafe { x86v::Engine::new(&key) })
        } else {
            None
        };

        for len in (0..=260usize).chain([511, 512, 513, 1024, 4096]) {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(29)).collect();
            let aad: Vec<u8> = (0..len % 40).map(|i| (i as u8).wrapping_mul(3)).collect();
            let mut want = plain.clone();
            let want_tag = crate_seal(&key, &nonce, &aad, &mut want);

            let mut got = plain.clone();
            // SAFETY: the probe at the top covers the features.
            let got_tag = unsafe { narrow.seal(&nonce, &aad, &mut got) };
            assert_eq!(got, want, "128-bit engine, len {len}");
            assert_eq!(got_tag, want_tag, "128-bit engine tag, len {len}");

            if let Some(wide) = &wide {
                let mut got = plain;
                // SAFETY: the probe at the top covers the features.
                let got_tag = unsafe { wide.seal(&nonce, &aad, &mut got) };
                assert_eq!(got, want, "256-bit engine, len {len}");
                assert_eq!(got_tag, want_tag, "256-bit engine tag, len {len}");
            }
        }
    }
}

#[cfg(test)]
mod tests_aes256 {
    use super::*;
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;

    fn crate_seal256(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        aes_gcm::Aes256Gcm::new_from_slice(key)
            .expect("key")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, buf)
            .expect("seals")
            .into()
    }

    /// The all-zero key, zero nonce, empty plaintext: `SP 800-38D`-adjacent
    /// vector shared by every GCM implementation's test suite, the
    /// discrimination check an implementation must not defer to the crate.
    #[test]
    fn the_gcm_spec_vector_for_256() {
        let engine = Aes256Gcm::new(&[0u8; 32]);
        let tag = engine.seal_in_place(&[0u8; 12], &[], &mut []);
        assert_eq!(
            tag,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb,
                0x73, 0x8b
            ],
            "all-zero key and nonce, empty message"
        );
    }

    #[test]
    fn is_byte_identical_to_the_crate_it_replaces() {
        let keys: [[u8; 32]; 2] = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let mut checked = 0usize;
        for key in &keys {
            let engine = Aes256Gcm::new(key);
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for len in (0..=300usize).chain([511, 512, 513, 1024, 1400, 4096, 8171, 16383])
                    {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut buf = plain.clone();
                        let tag = engine.seal_in_place(&nonce, &aad, &mut buf);

                        let mut want = plain.clone();
                        let want_tag = crate_seal256(key, &nonce, &aad, &mut want);
                        assert_eq!(buf, want, "ciphertext: aad {aad_len} len {len}");
                        assert_eq!(tag, want_tag, "tag: aad {aad_len} len {len}");

                        let mut opened = want.clone();
                        assert_eq!(
                            engine.open_in_place(&nonce, &aad, &mut opened, &want_tag),
                            Some(len),
                            "ours opens the crate's seal at len {len}"
                        );
                        assert_eq!(opened, plain, "len {len} round trips");
                        let mut crate_opened = buf.clone();
                        assert!(
                            aes_gcm::Aes256Gcm::new_from_slice(key)
                                .expect("key")
                                .decrypt_in_place_detached(
                                    aes_gcm::Nonce::from_slice(&nonce),
                                    &aad,
                                    &mut crate_opened,
                                    aes_gcm::Tag::from_slice(&tag),
                                )
                                .is_ok(),
                            "the crate opens ours at len {len}"
                        );
                        assert_eq!(crate_opened, plain, "len {len} round trips the crate");
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 5_000, "the sweep should be dense, not a sample");
    }
}
