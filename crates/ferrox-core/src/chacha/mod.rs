//! `ChaCha20` keystream: one algorithm, one portable implementation, one thin
//! layer per architecture.
//!
//! # Why there is only one algorithm
//!
//! Every backend implements the same [`Lanes`] trait and the round function is
//! written once, generically. A per-architecture core would be faster to write
//! and impossible to trust: three hand-written `ChaCha20` cores drift, and the
//! differential test then reports a mismatch without saying which one is wrong.
//! Written this way, the only thing that can differ between architectures is the
//! five primitives below, and every one of them is a single instruction on each
//! target.
//!
//! Bit-identity is therefore structural rather than merely tested: the portable
//! implementation and the NEON and AVX2 cores execute *the same source*, so they
//! cannot disagree about the algorithm. What still has to be checked is that each
//! `Lanes` impl means what it claims — which is what the differential test at
//! every length and every block offset is for.
//!
//! # What Miri covers, and what it does not
//!
//! [`portable`] is safe Rust, so Miri interprets the ladder, the counter
//! arithmetic, the group boundaries and every store offset. The architecture
//! modules contain no control flow and no pointer arithmetic beyond what Miri
//! cannot interpret anyway: they read and write through `core::arch` intrinsics,
//! whose safety rests on the `Lanes` contract, not on bounds. That contract is
//! discharged by the differential test rather than by Miri.
//!
//! # The lane layout
//!
//! A vector carries four consecutive state words per 128-bit *chunk*. Chunk `c`
//! of register `g` holds words `4g..4g+3` of block `c * 4 + g`, which is the
//! layout the Crypto++ core uses: no store-time transpose is needed, because each
//! register is already a run of consecutive output bytes.
//!
//! ```text
//!            register g=0        g=1          g=2          g=3
//!   chunk 0   words  0..3       words 4..7   words 8..11   words 12..15   -> block 0
//!   chunk 1   words  0..3       words 4..7   words 8..11   words 12..15   -> block 4
//! ```
//!
//! `NST` such groups run interleaved. Interleaving is the whole point: one
//! `ChaCha20` chain is a dependent add-xor-rotate chain with nothing to overlap, so
//! a wide out-of-order core stalls on it. Four independent chains fill the gap.

// Every function in this module that touches a lane primitive is
// `inline(always)`. The reason is one sentence: an outlined generic function does
// not inherit the `#[target_feature]` of the function that called it, so the
// AVX2 intrinsics inside it lose their feature, drop to 128-bit registers and
// spill the state to the stack on every call. The ladder instantiates its core
// over four widths, which is enough call sites for the inliner to make exactly
// that choice, and the AVX2 runners measured it as 0.16x at two blocks against
// 1.86x at four. `inline` is a hint; this is a guarantee.
#![allow(
    clippy::inline_always,
    reason = "lane primitives are only sound inside the caller's target_feature function"
)]

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(not(target_arch = "x86_64"))]
mod calibrate;
#[cfg(target_arch = "aarch64")]
mod neon;
mod portable;
#[cfg(target_arch = "x86_64")]
mod sse2;

/// A vector of 32-bit words, in the layout described in the module docs.
///
/// # Safety
///
/// An implementor must uphold all of the following, and the differential test is
/// what checks them:
///
/// - `LANES` words, and `CHUNKS = LANES / 4` independent 128-bit chunks;
/// - the four words of a chunk are consecutive state words of **one** block, in
///   increasing order;
/// - `add`, `bitxor` and the rotates are applied lane-wise, so chunk `c` of the
///   result depends only on chunk `c` of the inputs;
/// - `rot_chunks(n)` rotates the four words *within each chunk*, leaving chunk
///   membership alone;
/// - `with_counters` writes lane 0 of a chunk and no other lane of it, and
///   leaves the other three words exactly as they were;
pub(crate) trait Lanes: Copy {
    /// Words per vector: 4 for a 128-bit vector, 8 for a 256-bit one.
    const LANES: usize;
    /// Independent 128-bit chunks per vector, i.e. blocks in flight per register.
    const CHUNKS: usize = Self::LANES / 4;

    /// From exactly `LANES` words, in lane order.
    fn from_lanes(words: &[u32]) -> Self;

    fn add(self, o: Self) -> Self;
    fn bitxor(self, o: Self) -> Self;

    fn rotl16(self) -> Self;
    fn rotl12(self) -> Self;
    fn rotl8(self) -> Self;
    fn rotl7(self) -> Self;

    /// Rotate the four words of each chunk left by `n`, where `1 <= n <= 3`.
    fn rot_chunks(self, n: usize) -> Self;

    /// XOR chunk `c`'s four words into `dst` as 16 little-endian bytes.
    fn xor_chunk(self, c: usize, dst: &mut [u8; 16]);

    /// Word `4c` of chunk `c` — the block counter — replaced by `first + c`,
    /// every other word left exactly as it was.
    fn with_counters(self, first: u32) -> Self;
}

/// The same 32 bits in an `i32`, for the intrinsics that take one.
///
/// `_mm_cvtsi32_si128` and `_mm256_insert_epi32` both want an `i32` and write it
/// into a lane as a bit pattern, so the value is reinterpreted and never
/// interpreted — a counter above `2^31` is not a negative number here, it is the
/// lane's top bit set. Spelled through the byte round-trip rather than `as` so
/// that reading is explicit: `u32 as i32` reads as a sign conversion that
/// happens to be fine, and `clippy::cast_possible_wrap` reads it the same way,
/// which is why this function exists rather than three casts and an `allow`.
///
/// The inverse is `lane as u32`, which is the other half of the same fact: the
/// tests that read lanes back out of a vector are reinterpreting too.
///
/// `cfg(x86_64)` with its only two callers, `avx2` and `sse2`. `neon` reaches its
/// lane with `vsetq_lane_u32::<0>` and `portable` with `w[0] = first`, so neither
/// wants a bit reinterpretation and both would leave this unreferenced on
/// `aarch64` — which is a `-D warnings` failure there and nowhere else.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn as_i32_bits(word: u32) -> i32 {
    i32::from_le_bytes(word.to_le_bytes())
}

/// `expand 32-byte k`, the `ChaCha20` constants.
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// States the vector core interleaves per pass.
///
/// The cliff is the register file, and the register file is not the same size on
/// both architectures this builds for. `x86_64` has sixteen `ymm` and `aarch64`
/// thirty-two `q`; four registers per state, so four states fill `x86_64` exactly
/// and one more would spill the state to stack on every instruction of every
/// round, while `aarch64` has room for eight.
///
/// `aarch64` is pinned to eight by a `const _: () = assert!` below, and that pin
/// is load-bearing: it is why a revert of the widening cannot build rather than
/// quietly halving the width. What this constant costs is gate 3's row, not a
/// figure typed here — the `GB/s` pair that used to sit in this comment was the
/// width's throughput *before* the rounds were phased and survived the phasing, so
/// it understated the shipped core by about a seventh, and its "same sixteen
/// states" named sixteen *registers*, not a state count. Nothing checks a comment,
/// which is how it rotted silently through a widen, a revert and a re-widen in
/// one afternoon.
///
/// # Why eight on `aarch64`, and what seven measured
///
/// Eight states is four registers each, which is all thirty-two `q` registers,
/// and [`Base`] wants three more for the feed-forward. Thirty-five does not fit
/// in thirty-two, so the obvious reading is that a state spills and reloads on
/// every instruction of every round — and the keystream half on `linux aarch64`
/// runs at 1.03 ns per byte against `x86_64`'s 0.40 for the same twenty rounds,
/// which is a gap wide enough to be worth believing.
///
/// **It is not spills.** Seven states — twenty-eight registers, leaving the file's
/// last four for `Base` and the compiler's temporaries — were measured on both
/// `aarch64` runners, and they are **14–15% faster per pass**, consistently, in
/// the same direction and the same size on two independent machines. The
/// hypothesis was right about the cause.
///
/// And it is still a loss, because a pass covers `NST * CHUNKS * 64` bytes and
/// `CHUNKS` is 1 on a 128-bit vector: seven states cover 448 bytes where eight
/// cover 512. `bench.yml` run `37262944540` against `main` at `37261260425`, the
/// keystream half of gate 7b, best of 5, in nanoseconds:
///
/// | bytes | `linux aarch64` | | `macos aarch64` | |
/// |---|---:|---:|---:|---:|
/// | | eight | seven | eight | seven |
/// | 1024 | 1064.6 | 1125.8 | 726.4 | 748.2 |
/// | 4096 | 4230.7 | 4245.8 | 2378.2 | 2623.4 |
/// | 16384 | 16881.6 | 16768.8 | 10154.9 | 9921.3 |
///
/// 16384 bytes is 256 blocks: eight states take 32 passes, seven take 37. Seven
/// states come out **level** — `0.993x` and `0.977x` of eight's time — for 16%
/// more passes, which is to say the per-pass win is exactly cancelled by the
/// narrower pass and not one percent of it survives. At 4096 bytes, where 64
/// blocks are 8 passes against 10, `macos aarch64` reads `0.907x`.
///
/// The raw numbers cannot be read without the control, and the control is the
/// same rows on the two `x86_64` runners, which this constant cannot reach: it is
/// `#[cfg]`-gated to `aarch64` and both their binaries are byte-identical across
/// the two runs. `linux x86_64` moves `7109.6 → 6507.2` and `windows x86_64`
/// moves `7137.3 → 7819.3` — **+9% and −10%, in opposite directions.** A host is
/// worth about ten percent here, so a one-percent move is a measurement of the
/// weather.
///
/// Which leaves the real ceiling. A 128-bit vector holds four words, so a state
/// is four registers and eight states is the whole file: there is no width to
/// take, and `AVX2`'s two chunks per register — eight blocks in sixteen `ymm`,
/// versus eight blocks in thirty-two `q` — is the whole reason `x86_64` issues
/// half the ALU operations per byte. `aarch64` has no 256-bit `ASIMD` and
/// SVE-128 runners have no 256-bit SVE, so the two `aarch64` cores are at the
/// register file's floor already and a seventh state is the only lever, and the
/// lever is worth less than it costs. Eight it is, and the cost of knowing that
/// is this paragraph.
#[cfg(target_arch = "x86_64")]
const GROUP_STATES: usize = 4;
#[cfg(target_arch = "aarch64")]
const GROUP_STATES: usize = 8;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const GROUP_STATES: usize = 4;

/// The widest pass the tail can take: one state short of a whole group.
///
/// Capped at eight so the dispatch in [`xor_tail`] is one fixed list rather than a
/// list that has to be kept in step with this constant. The clamp here and the
/// arms there are the two halves of one contract, and a contract written twice
/// is a contract that can be broken once: a `TAIL_STATES` wider than the widest
/// arm asks [`xor_groups`] for a pass it never runs, and the bytes of the blocks
/// nobody generated come back zero — wrong at exactly the lengths where the tail
/// overshoots, and nowhere else.
const TAIL_STATES: usize = if GROUP_STATES < 8 { GROUP_STATES } else { 8 } - 1;

/// The 16-word state for `key` and `nonce`, with the counter left at zero.
#[inline]
fn base_state(key: &[u8; 32], nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CONSTANTS);
    for (i, word) in s[4..12].iter_mut().enumerate() {
        *word = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("key is 32 bytes"));
    }
    for (i, word) in s[13..16].iter_mut().enumerate() {
        *word = u32::from_le_bytes(
            nonce[i * 4..i * 4 + 4]
                .try_into()
                .expect("nonce is 12 bytes"),
        );
    }
    s
}

/// The part of a state that every block in a call shares.
///
/// Words 0..12 of the state are identical in every block; only word 12, the
/// counter, moves. Holding the shared part in registers for the whole call —
/// rather than rebuilding it per pass and keeping a full second copy of the
/// initial state alive for the feed-forward — is what stops the rounds from
/// competing with their own inputs for registers. Four registers: three
/// broadcast into every chunk, and the fourth holding the counter at zero above
/// the nonce tail, so that a pass's counters are this one register with its
/// lane 0 rewritten rather than a state built from the key and nonce again.
#[derive(Clone, Copy)]
pub(crate) struct Base<V> {
    /// Words 0..3, 4..7, 8..11 and 12..15, each broadcast into every chunk.
    ///
    /// `regs[3]` is the counter register: lane 0 of each chunk is word 12, which
    /// [`base_state`] leaves at zero, and lanes 1..3 are the nonce tail.
    regs: [V; 4],
}

/// Build [`Base`] once per call rather than once per pass.
///
/// The key and the nonce are the same for every block the call produces, so
/// parsing them per group is the same thirty-two key loads and twelve nonce
/// loads per 512 bytes of keystream, every one of them discarded at the end of
/// the pass.
///
/// Takes the sixteen state words rather than the key and nonce, because the words
/// are parsed once per call and a second width's base wants them too: the 128-bit
/// core that generates the last block of a tail on `x86_64` used to re-parse the key
/// and nonce for that one block, which at 320 bytes is most of what the second pass
/// costs over the reference's.
#[inline]
fn base<V: Lanes>(state: &[u32; 16]) -> Base<V> {
    // Word 12 is what makes `regs[3]` a counter at zero rather than a fourth
    // copy of a key word. `base_state` is the only producer and it never writes
    // it, and the differential test would fail on every length if it did.
    debug_assert_eq!(state[12], 0, "the counter register is only a base at zero");
    let mut lanes = [0u32; 16];
    let regs = core::array::from_fn(|g| {
        for c in 0..V::CHUNKS {
            lanes[4 * c..4 * c + 4].copy_from_slice(&state[4 * g..4 * g + 4]);
        }
        V::from_lanes(&lanes[..V::LANES])
    });
    Base { regs }
}

/// Word 12 of every chunk is the block counter, and state `s` of a pass holds
/// `start + s * CHUNKS + c` in chunk `c`.
///
/// So a counter register is [`Base`]'s fourth register with its lane 0 rewritten,
/// and nothing else: no sixteen-word buffer, no parsing, no second copy of the
/// nonce. This function used to build each one as a stack buffer with the counter
/// and the three nonce words written into it and the whole thing read back as a
/// vector, once per state for the rounds and once per state again for the
/// feed-forward, because the rounds destroy the state they are handed.
///
/// The `s * CHUNKS` is recomputed per state rather than carried from the one
/// before it, and that is the point rather than an oversight. Deriving each
/// counter by adding `CHUNKS` to its predecessor reads one instruction shorter
/// and is a dependency chain `NST` long sitting immediately in front of the first
/// quarter round: eight adds of four cycles each is thirty-two cycles of nothing
/// else happening, in the one place per pass where the rounds have not started to
/// hide it. Recomputing makes every state's counter independent, so all `NST` are
/// issued back to back and the pass starts when the first one lands.
///
/// Which is also why the buffers mattered beyond their instruction count: they
/// were being filled in the one window where every `NST * 4` state register is
/// already spoken for, and a core with thirty-two `q` registers and thirty-two
/// state registers has no scratch to lend one.
#[inline(always)]
fn counters<V: Lanes, const NST: usize>(base: &Base<V>, start: u32) -> [[V; 4]; NST] {
    core::array::from_fn(|s| {
        [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            base.regs[3].with_counters(start.wrapping_add((s * V::CHUNKS) as u32)),
        ]
    })
}

/// Eight quarter-round steps over the four registers of one state.
///
/// `r[0..4]` hold words `0..3`, `4..7`, `8..11` and `12..15`. Because each
/// register holds four consecutive words, one vector add does the work of four
/// scalar adds; that is the entire reason the core is vectorised this way round
/// rather than with one word per lane.
///
/// `inline(always)`: this is the innermost function that touches a lane
/// primitive, so it has to end up lexically inside whatever `#[target_feature]`
/// function reaches it. Outlined, it loses the feature with it — 128-bit
/// registers, the state spilled to the stack and reloaded on every call — which
/// is the 6x the AVX2 runner measured for two blocks against four on the same
/// core.
#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the lane intrinsics inside the caller's target_feature function"
)]
#[inline(always)]
fn quarter_round<V: Lanes>(r: &mut [V; 4]) {
    r[0] = r[0].add(r[1]);
    r[3] = r[3].bitxor(r[0]).rotl16();
    r[2] = r[2].add(r[3]);
    r[1] = r[1].bitxor(r[2]).rotl12();
    r[0] = r[0].add(r[1]);
    r[3] = r[3].bitxor(r[0]).rotl8();
    r[2] = r[2].add(r[3]);
    r[1] = r[1].bitxor(r[2]).rotl7();
}

/// Ten double rounds over `NST` interleaved states, with the register rotation
/// that turns the row round into the diagonal round and back.
///
/// Each phase is a separate pass over `regs` rather than one interleaved pass,
/// and the phases are different kinds of instruction: a quarter-round is adds,
/// xors and shifts, and a shuffle is a lane permutation. Interleaved, every
/// state alternates between the two, so the machine's issue ports alternate too
/// and each phase waits on the other's latency; phased, a whole group's adds and
/// xors are one run and its permutations are another. Same bytes, same order of
/// operations — every state is independent, so a quarter-round and a shuffle
/// commute across states — and a quarter of the passes over `regs` besides.
#[inline(always)]
fn rounds<V: Lanes, const NST: usize>(regs: &mut [[V; 4]; NST]) {
    for _ in 0..10 {
        for s in regs.iter_mut() {
            quarter_round(s);
        }
        for s in regs.iter_mut() {
            s[1] = s[1].rot_chunks(1);
            s[2] = s[2].rot_chunks(2);
            s[3] = s[3].rot_chunks(3);
        }
        for s in regs.iter_mut() {
            quarter_round(s);
        }
        for s in regs.iter_mut() {
            s[1] = s[1].rot_chunks(3);
            s[2] = s[2].rot_chunks(2);
            s[3] = s[3].rot_chunks(1);
        }
    }
}

/// Generate `NST * V::CHUNKS` blocks of keystream at `start` and XOR them into
/// `out`, which may be shorter than that if the caller's last block is partial.
///
/// Returns the blocks it generated: `NST * V::CHUNKS`, counted here because this
/// is the code that ran the rounds, not because the caller worked it out. A pass
/// handed more states than the caller's bytes need therefore reports the excess,
/// which is what makes "no discarded work" a fact about the ladder instead of a
/// restatement of the length.
///
/// A partial last block is generated with the block before it and stored short —
/// its twenty rounds run over the whole state whatever the caller keeps — so the
/// blocks generated are the blocks needed, rounded up to one, never more.
///
/// Every store is a sub-slice of `out` produced by `as_chunks_mut`, so a write
/// past the end is an index panic rather than a silent overrun.
#[inline(always)]
pub(crate) fn xor_groups<V: Lanes, const NST: usize>(
    base: &Base<V>,
    start: u32,
    out: &mut [u8],
    mut head: Option<&mut [u8; 32]>,
) -> u32 {
    // `NST * CHUNKS` blocks of 64 bytes, and `CHUNKS = LANES / 4`. With a head
    // this pass still *generates* that many blocks, but its leading one is the
    // head's and never reaches `out`, so `out` is one block shorter than a
    // headless pass of the same width.
    debug_assert!(out.len() + 64 * usize::from(head.is_some()) <= NST * V::LANES * 16);

    // Built directly rather than from a zero array: every register is produced
    // once here, so starting from zeros would be `NST * 4` dead vector
    // constructions per group. The three shared registers hold the *same* value
    // in every state, so they are copied rather than rebuilt, and the fourth is
    // derived from its predecessor rather than parsed again — see [`counters`].
    let mut regs = counters::<V, NST>(base, start);

    rounds::<V, NST>(&mut regs);

    // The leading 32 bytes of the leading block, when a head was asked for.
    //
    // `RFC 8439` section 2.6 takes the `Poly1305` one-time key from the first 32
    // bytes of `ChaCha20` block *zero* and starts the message itself at block
    // *one*, so the two are consecutive blocks of one keystream and the other 32
    // bytes of block zero belong to nobody. Generating the head separately, as
    // `fill_exact` did, costs a whole extra pass over the state — and on
    // `aarch64` that pass is the *scalar* one-block core, because a single chain
    // has nothing to interleave, which the ladder otherwise only uses for the
    // last block of a tail. Taking the head here instead puts block zero on the
    // wide core with seven other chains already in flight.
    //
    // Registers 0 and 1 of state 0, lane 0, are bytes `0..16` and `16..32` of this
    // pass's block zero, in that order, by the layout in the module docs;
    // registers 2 and 3 are bytes `32..64` of the same block and are dropped,
    // which is what the `RFC`'s own construction says to drop.
    let skips_first = head.is_some();
    if let Some(h) = head.take() {
        let (h, _) = h.as_chunks_mut::<16>();
        let ff = [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            base.regs[3].with_counters(start),
        ];
        let state = &mut regs[0];
        state[0].add(ff[0]).xor_chunk(0, &mut h[0]);
        state[1].add(ff[1]).xor_chunk(0, &mut h[1]);
    }

    // Feed-forward fused into the store: `reg[g].add(initial[g])` is lane-wise
    // pure, so `add-then-store` and `store(add(...))` are the same bytes. Doing
    // it here removes a whole pass over `regs` with no change in output.
    //
    // The loop is group-major (`s`, then `c`) rather than block-major, so
    // `group = block / CHUNKS` and `c = block % CHUNKS` are never computed: `s`
    // *is* the group and `c` *is* the lane. Same stores, no division.
    //
    // The store walks whole 64-byte blocks — four 16-byte chunks of a register,
    // which is what the lane load needs — so the test "is this block inside
    // `out`" is made once per 64 bytes rather than once per 16. The bytes that
    // do not fill a whole block are staged exactly as before, so a short `out`
    // still never has a byte written past its end.
    let (blocks, partial) = out.as_chunks_mut::<64>();
    let mut i = 0usize;
    'stores: for (s, state) in regs.iter_mut().enumerate() {
        // Rebuilt here rather than kept: four registers live at the store, not
        // `NST * 4` live across the rounds. And one counter at a time rather than
        // through [`counters`], which would keep an `NST` array of them live
        // across a loop that still holds all of `regs`.
        let ff = [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            base.regs[3].with_counters(start.wrapping_add((s * V::CHUNKS) as u32)),
        ];
        for c in 0..V::CHUNKS {
            // With a head, block zero of this pass is already spent, so `out`'s
            // block `i` takes this pass's block `i + 1`. Skipping the iteration
            // rather than shifting the index keeps the partial-tail arithmetic
            // below exactly as it was.
            if skips_first && s == 0 && c == 0 {
                continue;
            }
            let Some(block) = blocks.get_mut(i) else {
                // `out` is no longer than a whole group, so at most one block per
                // call is partial: this runs once and then stops.
                let (chunks, tail) = partial.as_chunks_mut::<16>();
                for (chunk, (reg, initial)) in
                    chunks.iter_mut().zip(state.iter_mut().zip(ff.iter()))
                {
                    reg.add(*initial).xor_chunk(c, chunk);
                }
                if !tail.is_empty() {
                    let mut staged = [0u8; 16];
                    let g = chunks.len();
                    state[g].add(ff[g]).xor_chunk(c, &mut staged);
                    xor_last_bytes(tail, &staged);
                }
                break 'stores;
            };
            let (chunks, _) = block.as_chunks_mut::<16>();
            for (chunk, (reg, initial)) in chunks.iter_mut().zip(state.iter_mut().zip(ff.iter())) {
                reg.add(*initial).xor_chunk(c, chunk);
            }
            i += 1;
        }
    }
    (NST * V::CHUNKS) as u32
}

/// `width` bytes from the front of `bytes`, little-endian, in a `u64`.
///
/// Zero-padded, so the caller can XOR a whole word and keep the bytes past `width`.
#[inline(always)]
fn read_le(bytes: &[u8], width: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(&bytes[..width]);
    u64::from_le_bytes(buf)
}

/// XOR the last one to fifteen bytes of a partial block with staged keystream.
///
/// Eight bytes at a time, then four, two and one, rather than one byte at a time. The
/// tail is at most fifteen bytes, so the byte loop is up to fifteen load/xor/store
/// triples where four wide ones do the same work. This is the only store path in the
/// file that is not a straight `xor_chunk` into the caller's buffer, because the
/// caller's buffer does not have the sixteen bytes left to write into — which is why
/// it is the length that pays: a buffer ending one byte short of a block boundary is
/// the only shape that lands here.
///
/// `dst` is the tail of the caller's own slice and `staged` is a full sixteen-byte
/// buffer the keystream was written into, so every read is in bounds of one or the
/// other and every write is inside `dst`. `at` only ever advances when `width` bytes
/// remain, so no step can run past the end.
fn xor_last_bytes(dst: &mut [u8], staged: &[u8; 16]) {
    let mut at = 0usize;
    for width in [8usize, 4, 2, 1] {
        if dst.len() - at >= width {
            let mixed = read_le(&dst[at..], width) ^ read_le(&staged[at..], width);
            let bytes = mixed.to_le_bytes();
            dst[at..at + width].copy_from_slice(&bytes[..width]);
            at += width;
        }
    }
    // Those four widths sum to fifteen, which is the most this can be handed: a
    // sixteen-byte slice chunks evenly and arrives with an empty tail. The step is
    // here anyway, because a function that quietly drops the sixteenth byte of a
    // sixteen-byte slice is one that has to be read rather than trusted, and the test
    // that checks it is the only thing that would notice.
    if at < dst.len() {
        dst[at] ^= staged[at];
    }
}

/// The bytes one pass of `V`'s core covers: `GROUP_STATES` states, `CHUNKS`
/// blocks each, 64 bytes a block.
const fn group_bytes<V: Lanes>() -> usize {
    GROUP_STATES * V::CHUNKS * 64
}

/// The blocks left after the group loop, on the widest core that covers them.
///
/// `xor_groups::<V, n>` generates exactly `n * V::CHUNKS` blocks, so the tail
/// runs the largest `n <= TAIL_STATES` that does not overshoot and comes back for
/// the rest; what is left when a single block is all that remains goes to the
/// scalar core, which is the only width that generates exactly one. Two blocks is
/// the floor for the vector core because one block is a single chain with nothing
/// to interleave, and at one block the vector core measures slower than scalar
/// code for the same 20 rounds.
///
/// The tail runs the *same* core as the group loop, on every architecture, and
/// that is measured rather than assumed. Moving the `x86_64` tail onto the 128-bit
/// core — the reading that a tail wants more chains because it is one pass either
/// way — was tried and reverted, because the pass a state covers is what decides
/// the count and the 128-bit core needs twice as many of them. Gate 3 on the two
/// `x86_64` runners, same tree either side of the change:
///
/// | length | 256-bit tail | 128-bit tail |
/// |---|---|---|
/// | 256 B (4 blocks) | one pass, 2 states | two passes, 3 states + 1 block |
/// | 768 B (12 blocks) | two passes, 6 blocks each | four passes, 3 blocks each |
/// | 320 B (5 blocks) | 0.919x | 0.846x |
/// | 256 B | not failing | 0.498x–0.545x |
/// | 768 B | not failing | 0.774x–0.887x |
///
/// The two lengths the 128-bit tail was supposed to rescue did not improve, and
/// three lengths that were passing went below the bar, with 256 B at half speed.
/// The argument it rested on also had the chain count backwards: `GROUP_STATES`
/// states of the 256-bit core are `GROUP_STATES` chains, not `GROUP_STATES` chains
/// over twice the blocks as separate work — each state is one chain, and it covers
/// twice the bytes for the same latency, which is the whole point of the width.
///
/// Returns what the passes reported, which is the same number the counter advanced
/// by: the report and the advance are one value read twice, so they cannot drift.
#[inline(always)]
fn xor_tail<V: Lanes>(
    state: &[u32; 16],
    base: &Base<V>,
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;
    // The head is one block of keystream that belongs to no `out` block, so while
    // it is still pending the pass has to cover 64 bytes more than `rest` does.
    // Once it has ridden a pass this is zero and the arithmetic below is exactly
    // what it was before.
    let mut owed = 64 * usize::from(head.is_some());
    while rest.len() + owed > 64 {
        let states = ((rest.len() + owed).div_ceil(64) / V::CHUNKS).clamp(1, TAIL_STATES);
        let (chunk, tail) = rest.split_at_mut((states * V::CHUNKS * 64 - owed).min(rest.len()));
        // One arm per width, up to the cap `TAIL_STATES` clamps to. Written as a
        // list rather than a `_ =>` catch-all so a width with no arm is a
        // compile-time hole rather than a silently unwritten tail.
        macro_rules! pass {
            ($($n:literal),+ $(,)?) => {
                match states {
                    $($n => xor_groups::<V, $n>(base, ctr, chunk, head.take()),)+
                    _ => unreachable!("`states` is clamped to TAIL_STATES"),
                }
            };
        }
        blocks += pass!(1, 2, 3, 4, 5, 6, 7);
        ctr = ctr.wrapping_add((states * V::CHUNKS) as u32);
        rest = tail;
        owed = 0;
    }
    if !rest.is_empty() || head.is_some() {
        // A head that no pass above could carry — a `buf` too short to fill a
        // pass even with the head's block added — and the last block after it.
        // The head is generated first because it is the lower counter, so the
        // counter only advances past it, and `blocks` counts it the same way
        // `fill_exact` would.
        if let Some(h) = head.take() {
            let mut block = [0u8; 64];
            blocks += one_block(state, ctr, &mut block);
            h.copy_from_slice(&block[..32]);
            ctr = ctr.wrapping_add(1);
        }
        if !rest.is_empty() {
            blocks += one_block(state, ctr, rest);
        }
    }
    blocks
}

/// The best one-block core this build has, for the last block of a tail.
///
/// `x86_64` gets [`sse2`] and everywhere else gets [`portable`], and the reason is
/// measured rather than assumed: on `x86_64` the portable core is compiled to
/// scalar code, while a 128-bit core keeps the state in registers, and on aarch64
/// the portable core is *faster* than NEON at one block because a single chain has
/// nothing to interleave (91.9 ns against 119.7 ns).
///
/// Both take the call's sixteen state words rather than the key and nonce, which is
/// what [`xor_tail`] already holds. Re-parsing them for one block is small against
/// twenty rounds and not nothing against the *second* pass of a call: at 320 bytes on
/// `linux x86_64` that pass is 112 ns against the reference's 98 ns, and the gap is
/// the size of a key parse.
///
/// The `x86_64` arm is a pass of the shared core rather than a call into [`sse2`],
/// which is what that module's `xor_block` was: `xor_groups::<S4, 1>` with a base
/// built from words the caller already has. One function for one block instead of
/// three spellings of it.
///
/// The `aarch64` arm asks [`one_block_prefers_lanes`] first, because on that
/// architecture the answer is not the same on every core: see [`one_block`].
#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn one_block(state: &[u32; 16], ctr: u32, out: &mut [u8]) -> u32 {
    xor_groups::<sse2::S4, 1>(&base::<sse2::S4>(state), ctr, out, None)
}

/// One block, on whichever one-block core this CPU measured faster.
///
/// `SSE2` on `x86_64` is not a choice — `portable` compiles to scalar `movl`/`roll`
/// there, and the AVX2 runners measured a five-block buffer at 0.86x with it against
/// 1.9x for the four-block pass in the same call. On `aarch64` it is a choice, and
/// [`calibrate`] is what makes it; the module is where the argument for measuring
/// rather than guessing lives, because the argument is about hardware and this
/// function is about dispatch.
#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn one_block(state: &[u32; 16], ctr: u32, out: &mut [u8]) -> u32 {
    if calibrate::verdict() {
        xor_groups::<Wide, 1>(&base::<Wide>(state), ctr, out, None)
    } else {
        portable::xor_block(state, ctr, out)
    }
}

/// XOR keystream over `buf` from block counter `start`, and return the blocks it
/// generated.
///
/// Whole vector groups while one still fits, then [`xor_tail`] for the blocks that
/// are left. The counter is advanced by the blocks each pass actually produced,
/// which is the single place the two offsets — the group offset and the block
/// offset — have to be added together. Deriving one of them from a byte index and
/// the other from a loop counter is how this went wrong before.
#[cfg(target_arch = "x86_64")]
pub(crate) fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    // SAFETY: the probe is what makes `avx2`'s `target_feature` sound on a build
    // that was not compiled with `+avx2`, and it is the same check the whole
    // ladder ran per group before it was hoisted out of the loop: hoisting it
    // cannot select a path the per-group check would not have taken.
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: delegated to this probe.
        unsafe { avx2::xor_blocks(key, nonce, start, head, buf) }
    } else {
        xor_ladder::<portable::U4>(key, nonce, start, head, buf)
    }
}

/// XOR keystream over `buf` from block counter `start`, and return the blocks it
/// generated.
///
/// Whole vector groups while one still fits, then [`xor_tail`] for the blocks that
/// are left. The counter is advanced by the blocks each pass actually produced,
/// which is the single place the two offsets — the group offset and the block
/// offset — have to be added together. Deriving one of them from a byte index and
/// the other from a loop counter is how this went wrong before.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    xor_ladder::<Wide>(key, nonce, start, head, buf)
}

/// The ladder for one core: whole groups, then the blocks that are left.
///
/// `#[inline]` because on `x86_64` this is only ever inlined into `avx2`'s
/// `#[target_feature]` function, and that is what makes the AVX2 primitives
/// reachable at all: they are only sound in code built with the feature on.
#[inline(always)]
fn xor_ladder<V: Lanes>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    // Once for the whole call, not once per pass, and once for the whole call
    // rather than once per width: the tail's last block needs a 128-bit base on
    // `x86_64` and it is built from these words.
    let state = base_state(key, nonce);
    let base = base::<V>(&state);
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;
    // As in the tail: a pending head is one block no `rest` block owns, so the
    // first group carries it and is one block shorter in `rest`.
    let mut owed = 64 * usize::from(head.is_some());
    while rest.len() + owed >= group_bytes::<V>() {
        let (chunk, tail) = rest.split_at_mut((group_bytes::<V>() - owed).min(rest.len()));
        blocks += xor_groups::<V, GROUP_STATES>(&base, ctr, chunk, head.take());
        ctr = ctr.wrapping_add((GROUP_STATES * V::CHUNKS) as u32);
        rest = tail;
        owed = 0;
    }
    blocks + xor_tail::<V>(&state, &base, ctr, head, rest)
}

/// The vector core this build dispatches to, named once so the ladder and the
/// group loop cannot disagree about which core they run.
#[cfg(target_arch = "aarch64")]
type Wide = neon::N4;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
type Wide = portable::U4;

/// Which core this build dispatches to, and how wide it is.
///
/// Reported next to the reference's own backend by the benchmark, because a
/// speedup is only attributable once both sides of it are named.
///
/// Both numbers are `match`ed against the constants that produce them rather
/// than typed into the string, because this is the one place a number can go
/// stale with nothing noticing. The seven-state build reported itself as eight
/// states, and it did so on the very `bench.yml` run that is the evidence for
/// the seven-state attempt: run `37262944540` labelled every one of its rows with
/// a width its binary did not have. A `const _: () = assert!` proves the pin; it
/// proved the pin and not this string, because the string was a literal.
pub const fn backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        match (GROUP_STATES, GROUP_STATES * <avx2::A8 as Lanes>::CHUNKS) {
            (4, 8) => {
                "4-lane core: AVX2, 4 states in flight, 8 blocks per iteration, at runtime-detected width"
            }
            _ => "x86_64: a width this build does not have",
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        match (GROUP_STATES, GROUP_STATES * <Wide as Lanes>::CHUNKS) {
            (8, 8) => "4-lane core: NEON, 8 states in flight, 8 blocks per iteration",
            _ => "aarch64: a width this build does not have",
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        match (GROUP_STATES, GROUP_STATES * <Wide as Lanes>::CHUNKS) {
            (4, 4) => "4-lane core: portable, 4 states in flight, 4 blocks per iteration",
            _ => "a width this build does not have",
        }
    }
}

/// The number `backend()` names, checked against the constant that produces it.
///
/// A string is the one place a number can go stale without anything noticing:
/// widening the `aarch64` group left this reporting four blocks per iteration
/// while the ladder was running eight, which is precisely the sort of
/// unattributable measurement the whole string exists to prevent. The literals
/// below are therefore proven against [`GROUP_STATES`], the same way `avx2`'s
/// shuffle immediates are proven against the formula that is supposed to produce
/// them.
///
/// Each arm names the core *that build actually runs*, which is why the `x86_64`
/// arm names two. `x86_64` picks `AVX2` or the portable core at runtime and has
/// no `Wide` to name: an earlier version of this asserted against `Wide` under
/// `#[cfg(target_arch = "x86_64")]`, which does not compile there at all — it was
/// caught by `test (linux x86_64)` and `test (windows x86_64)` on the pull
/// request, and by nothing at all on the `aarch64` machine that wrote it. The two
/// assertions are the two halves of "at runtime-detected width": eight blocks per
/// iteration on `AVX2`, four on the fallback.
///
/// The `aarch64` literal is eight and not seven because seven measured 14–15%
/// faster per pass and came out level, which [`GROUP_STATES`] carries in full.
#[cfg(target_arch = "aarch64")]
const _: () = assert!(GROUP_STATES * <Wide as Lanes>::CHUNKS == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(GROUP_STATES * <avx2::A8 as Lanes>::CHUNKS == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(GROUP_STATES * <portable::U4 as Lanes>::CHUNKS == 4);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const _: () = assert!(GROUP_STATES * <Wide as Lanes>::CHUNKS == 4);

#[cfg(test)]
mod counter_tests {
    use super::{base, base_state, counters, portable, Lanes};

    /// The counter induction must be the counter arithmetic it replaced.
    ///
    /// `with_counters` is a single-lane edit to a four-lane register: it writes
    /// lane 0 and leaves the nonce tail in lanes 1..3 alone. A chunk index off by
    /// one here is a wrong counter in every block after the first, which the
    /// differential test against the pinned reference also catches — but it catches
    /// it as "the keystream differs at length 128", which names none of this.
    ///
    /// `start` is walked to both ends of the `u32` range, because this wraps where
    /// the formula it replaced wrapped: a counter that stopped at `u32::MAX` would
    /// show up here and nowhere else.
    #[test]
    fn a_pass_s_counters_are_the_words_base_state_put_there() {
        type U4 = portable::U4;
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let state = base_state(&key, &nonce);
        assert_eq!(state[12], 0, "the counter base is only a base at zero");

        for start in [0u32, 1, 7, u32::MAX - 8, u32::MAX] {
            let base = base::<U4>(&state);
            let regs = counters::<U4, 8>(&base, start);
            for (s, reg) in regs.iter().enumerate() {
                let want = start.wrapping_add((s * U4::CHUNKS) as u32);
                assert_eq!(
                    reg[3].0[0], want,
                    "start {start} state {s}: lane 0 is the block counter"
                );
                assert_eq!(
                    reg[3].0[1..],
                    state[13..16],
                    "start {start} state {s}: lanes 1..4 are the nonce tail"
                );
                // Each of `state`'s first three registers, as an array rather
                // than a slice: an array of three `[u32; 4]` is what
                // `.iter()` needs, and an array of three `[u32]` does not
                // compile at all, which is the only thing wrong with the obvious
                // spelling here.
                let shared = [
                    <[u32; 4]>::try_from(&state[0..4]).expect("four words"),
                    <[u32; 4]>::try_from(&state[4..8]).expect("four words"),
                    <[u32; 4]>::try_from(&state[8..12]).expect("four words"),
                ];
                for (g, words) in shared.iter().enumerate() {
                    assert_eq!(
                        reg[g].0, *words,
                        "start {start} state {s}: register {g} is shared"
                    );
                }
            }
        }
    }
}

/// The two-chunk contract, on the only shipped vector that has two chunks.
///
/// `CHUNKS == 2` is the one stride that is not one, and it is the one the portable
/// core cannot check: two `vpinsrd`, one per chunk's lane 0, at indices 0 and 4. A
/// pass whose lanes were wrong that way would be self-consistent and every tag
/// wrong, and the differential test would report a keystream mismatch that names
/// neither.
///
/// So this reads the lanes. It runs under the same `#[target_feature]` and the
/// same runtime probe the ladder uses, because a `vpinsrd` outside one is
/// undefined behaviour rather than a compile error.
///
/// `cfg(test)` as well as `cfg(x86_64)`: the module holds only a test and the two
/// helpers it calls, so without the first the library build compiles all three
/// and finds every one of them unreferenced. `counter_tests` above has had both
/// attributes all along, and this module was written with only the second.
#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod avx2_counter_tests {
    use super::avx2::A8;
    use super::Lanes;

    /// The eight words of `v`, lane 0 first.
    ///
    /// # Safety
    ///
    /// AVX2 must be available; the only caller is behind that probe.
    #[target_feature(enable = "avx2")]
    unsafe fn lanes(v: A8) -> [u32; 8] {
        let mut out = [0u32; 8];
        // SAFETY: 32 bytes written into a `[u32; 8]`, the exact width, and `out` is
        // live and owned here.
        unsafe { core::arch::x86_64::_mm256_storeu_si256(out.as_mut_ptr().cast(), v.0) };
        out
    }

    #[test]
    fn avx2_counters_land_in_lane_zero_of_each_chunk() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        // SAFETY: the probe above is the same one the ladder makes immediately
        // before calling into `#[target_feature(enable = "avx2")]`, and everything
        // below it is lane arithmetic on a vector this test built.
        unsafe { the_two_chunk_contract() };
    }

    /// # Safety
    ///
    /// AVX2 must be available.
    #[target_feature(enable = "avx2")]
    unsafe fn the_two_chunk_contract() {
        let tail = [11u32, 22, 33];
        let both = A8::from_lanes(&[
            0, tail[0], tail[1], tail[2], //
            0, tail[0], tail[1], tail[2],
        ]);

        // `start` at the very top of the range, so the step has to wrap and a
        // saturating or checked add would show it.
        let first = u32::MAX;
        // SAFETY: this function is reached only through `avx2_counters_land_in_...`,
        // which probes for AVX2 and is itself entered inside an `unsafe` block, and
        // `lanes` is the same feature this function is compiled with.
        let got = unsafe { lanes(both.with_counters(first)) };
        assert_eq!(got[0], first, "chunk 0 lane 0 is `first`");
        assert_eq!(got[4], 0, "chunk 1 lane 0 is `first + 1`, wrapped");
        assert_eq!(&got[1..4], &tail, "chunk 0 keeps its nonce tail");
        assert_eq!(&got[5..8], &tail, "chunk 1 keeps its nonce tail");

        // And the second state's counter is the first one's plus `CHUNKS`, which
        // is the stride the two chunks sit at rather than the one each does.
        // SAFETY: as above.
        let second = unsafe { lanes(both.with_counters(first.wrapping_add(1))) };
        assert_eq!(second[0], 0, "chunk 0 of the next state");
        assert_eq!(second[4], 1, "chunk 1 of the next state");
        assert_eq!(&second[1..4], &tail, "and the tails do not move");
        assert_eq!(&second[5..8], &tail);
    }
}

/// The one-chunk contract, on the core that runs every tail's last block.
///
/// `SSE2` is the one backend that spells `with_counters` as a mask and an or
/// rather than as a single-lane insert, and a mask has a way to be backwards that
/// a single-lane insert does not: `0, 0, 0, -1` keeps lane 0 and clears the rest,
/// which is precisely inverted for a method whose job is to *replace* lane 0 and
/// keep the nonce tail in lanes 1..3.
///
/// That is what this test is for, and it is here because `aarch64` and the
/// portable core both passed without it: `with_counters` is correct in both, and
/// `S4` is reached only from `one_block`, so the wrong mask was green on two of
/// the four runners and broke `fill_exact` on the other two at every length that
/// ends in a one-block tail.
///
/// `SSE2` is baseline on `x86_64`, so there is no probe here — unlike the AVX2
/// module above, calling this needs no feature that can be absent.
#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod sse2_counter_tests {
    use super::sse2::S4;
    use super::Lanes;

    /// The four words of `v`, lane 0 first.
    ///
    /// Through a store rather than `vget_lane`: `__m128i` cannot be indexed, and
    /// a `u32x4`'s lane 1 is `32`-bit lane one here only because this is a
    /// 128-bit vector — the same reason the `AVX2` helper above stores instead of
    /// extracting.
    fn lanes(v: S4) -> [u32; 4] {
        let mut out = [0u32; 4];
        // SAFETY: 16 bytes written into a `[u32; 4]`, the exact width, and `out` is
        // live and owned here. `SSE2` is `x86_64` baseline, so no feature gate.
        unsafe { core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr().cast(), v.0) };
        out
    }

    #[test]
    fn sse2_replaces_lane_zero_and_keeps_the_nonce_tail() {
        let tail = [11u32, 22, 33];
        let v = S4::from_lanes(&[7, tail[0], tail[1], tail[2]]);

        // `first` at the very top of the range, so the write has to wrap and a
        // saturating or checked conversion would show it.
        for first in [0u32, 1, u32::MAX - 1, u32::MAX] {
            let got = lanes(v.with_counters(first));
            assert_eq!(got[0], first, "lane 0 is the counter");
            assert_eq!(
                &got[1..],
                &tail,
                "first {first}: lanes 1..3 are the nonce tail and must not move"
            );
        }

        // And the register it is handed is not read-modify-write on lane 0: a
        // stale counter in the base must not survive a write of a different one.
        let got = lanes(S4::from_lanes(&[99, tail[0], tail[1], tail[2]]).with_counters(5));
        assert_eq!(got[0], 5, "the old lane 0 is gone, not or-ed into");
    }
}

#[cfg(test)]
mod tail_store_tests {
    use super::xor_last_bytes;

    /// The wide tail store must agree with the byte loop it replaced, at every tail
    /// length the shape can produce.
    ///
    /// One to fifteen is the whole range the caller can produce:
    /// `out.as_chunks_mut::<64>()` hands the last block's remainder over as
    /// `as_chunks_mut::<16>()`, so what arrives is `len % 16` bytes with
    /// `len % 16 != 0`. Sixteen is tested too, and it caught the width steps summing
    /// to fifteen and dropping the last byte.
    #[test]
    fn the_wide_tail_xor_is_the_byte_loop_it_replaced() {
        let staged: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for len in 1..=16usize {
            let original: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(91).wrapping_add(5))
                .collect();
            let mut wide = original.clone();
            xor_last_bytes(&mut wide, &staged);
            let mut bytes = original;
            for (dst, ks) in bytes.iter_mut().zip(staged) {
                *dst ^= ks;
            }
            assert_eq!(wide, bytes, "len {len} must match the byte loop");
        }
    }

    /// The property the width steps exist for: nothing is written past the tail.
    ///
    /// A guard of 0xA5 around the tail, so a write one byte over would be visible
    /// rather than being a slice panic on a length that never occurs.
    #[test]
    fn the_wide_tail_xor_writes_nothing_past_the_tail() {
        let staged: [u8; 16] = [0xFF; 16];
        for len in 1..=15usize {
            let mut buf = vec![0xA5u8; len + 8];
            xor_last_bytes(&mut buf[..len], &staged);
            assert!(
                buf[len..].iter().all(|b| *b == 0xA5),
                "len {len} wrote past the tail: {buf:?}"
            );
        }
    }

    /// And a one-byte tail, which is the case the byte loop handled in one step and
    /// this one has to reach with its last width.
    #[test]
    fn a_single_tail_byte_is_xored_and_the_rest_is_not() {
        let staged = [0u8; 16];
        let mut buf = [0x5Au8];
        xor_last_bytes(&mut buf, &staged);
        assert_eq!(buf, [0x5Au8]);
        let staged = [0xFFu8; 16];
        let mut buf = [0x5Au8];
        xor_last_bytes(&mut buf, &staged);
        assert_eq!(buf, [0xA5u8]);
    }
}
