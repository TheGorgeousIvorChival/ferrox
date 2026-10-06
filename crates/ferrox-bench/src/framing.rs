//! Gate 4: the `VLESS` request header encode, timed against a reference build of
//! the same bytes.
//!
//! # Why this gate exists
//!
//! Gates 1-3 measure the record layer, which lives in `ferrox-core` and has a
//! pinned same-language reference to be compared against. The header encode had
//! no timed reference at all: gate 2 counted its allocations and gate 1 never saw
//! it, so a change that kept the bytes and the allocation count while adding a
//! second parse and a second query-map walk would have been invisible. This is a
//! per-dial path, so that is one parse and one walk wasted on every connection.
//!
//! # What the reference is
//!
//! [`previous_encode_into`] is the encode this row replaced, kept verbatim: same
//! interface, same caller buffer, same bytes, the same `flow()` walk and the same
//! `from_str_radix` UUID decode. Only the number of parses, the number of
//! query-map walks and the shape of the hex decode differ, which is the entire
//! claim. A reference that also skipped work the shipped path does would measure
//! something else — which is exactly what the first cut of this row did, and it
//! reported 1.05x for a change that is worth about four times that.
//!
//! Every row asserts byte equality *before* it is timed. A reference that
//! disagreed would panic rather than report a speedup, so the ratio cannot be
//! bought with different output.

use std::fmt::Write as _;
use std::time::Instant;

use ferrox_core::aead::{
    chacha20_poly1305_seal_in_place, chacha20_poly1305_seal_in_place_unfused,
};
use ferrox_core::poly1305::Poly1305;
use ferrox_core::vless::VlessLink;

use crate::count;

/// One timed framing: same bytes, two ways of producing them.
pub(crate) struct Row {
    /// What was timed, as the report prints it.
    pub(crate) name: String,
    /// Bytes both sides produced, asserted equal before either was timed.
    pub(crate) bytes: usize,
    /// Best seconds per call for the reference build.
    pub(crate) base: f64,
    /// Best seconds per call for this tree.
    pub(crate) ours: f64,
    /// Whether this row was re-measured at four times the budget because its
    /// first reading came out under the bar.
    ///
    /// [`timed_row`] sets it, and it means the two numbers above are one
    /// *confirmed* pass rather than the first sample: a row still under the bar
    /// after `CONFIRMATIONS` of them is a regression, not a disturbed
    /// runner, and is marked here so the report says which reading it published.
    pub(crate) remeasured: bool,
}

impl Row {
    /// `base / ours`, above 1.00 meaning this tree is faster.
    pub(crate) fn ratio(&self) -> f64 {
        self.base / self.ours
    }
}

/// Best of `ROUNDS` seconds per call, the same discipline gate 3 uses.
///
/// Shared with the mux gate so both framings are timed by one clock discipline
/// rather than by two that agree today.
///
/// # Where this is the wrong statistic, and what is used instead
///
/// It is right for a row with one side to time, and it is wrong for a row with two.
/// A **minimum** over five samples has the fattest tail of any order statistic at
/// that sample count: the published figure is whichever single round was luckiest,
/// and for two sides measured in two separate blocks those two luckiest rounds are
/// different rounds carrying different luck. Their quotient is not a measurement of
/// anything.
///
/// What that cost, on this repository, is written down in `docs/claims.md`: gate 7c's
/// `poly1305 3x44 vs 26-bit horner` published **1.28x-1.39x** on `linux x86_64` in run
/// `37325906806` and **0.87x** in run `37337365219`, on code `git diff` shows to be
/// byte-identical, and `windows x86_64` read the same 0.87x to within 2% — two
/// machines agreeing on a figure produced by a statistic with that tail. Gate 9's
/// control rows say the runner itself moved 1.24x-1.52x across those two runs, which
/// is the size of the effect the two independent minima could not see past.
///
/// So a two-sided row uses [`paired`], which measures the two sides inside the same
/// round and gates on the median *round* ratio. Gate 5, in this same binary, has always
/// done it this way — paired per-repeat measurements with intervals on the ratios —
/// and is the discipline that survived contact with these runners.
pub(crate) fn best_of<F: FnMut() -> usize>(iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..crate::ROUNDS {
        let t0 = Instant::now();
        for _ in 0..iters {
            std::hint::black_box(f());
        }
        best = best.min(t0.elapsed().as_secs_f64() / iters as f64);
    }
    best
}

/// How many times each side is measured inside one round of [`paired`].
///
/// Four, so a round is two slices of the reference and two of this tree, and the two
/// orders balance exactly: an odd number would leave one side measured first one more
/// time than the other, and a drift across the round would then land on it.
const SLICES: usize = 4;

/// One slice of `iters` calls, in seconds.
///
/// `&mut dyn` rather than a generic, so the two sides of a round go through one
/// function instead of being monomorphised into two: the whole point is that both
/// sides are timed by the same code, and a compiler that inlined one and not the
/// other would be a difference between them.
fn slice_seconds(iters: u64, f: &mut dyn FnMut() -> usize) -> f64 {
    let t0 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    t0.elapsed().as_secs_f64()
}

/// Both sides of a row, measured together, and the round that decided it.
///
/// Returns `(reference seconds per call, this tree's seconds per call)` from the round
/// whose **ratio** is the median of the `ROUNDS` rounds, so the two published numbers
/// are the two the verdict was taken on and not a median beside an unrelated pair.
///
/// # Why this instead of two [`best_of`] calls
///
/// Because the question a gated row answers is "are these two the same speed", which
/// is a statement about a *pair*, and the machine a pair was measured on is not
/// stationary. Three properties, each of which the two-independent-minima version lacks:
///
/// - **Adjacency.** The two sides are measured a few milliseconds apart rather than a
///   few seconds apart, so a runner that changes state mid-row changes both.
/// - **Alternation.** Which side goes first alternates slice by slice, so a machine
///   that gets steadily slower across a round cannot hand the cheaper side the earlier,
///   faster half every time. This is the property that produced the 1.39x-then-0.87x
///   pair in `docs/claims.md`: the reference was measured first, in full, and a
///   slowing runner made that look like a win.
/// - **A median rather than a minimum.** Five paired ratios, sorted, take the middle
///   one. One round decides the row, and it is a round where the two sides were
///   measured side by side.
///
/// The cost is the same work in the same wall time; only the boundaries move.
pub(crate) fn paired(
    iters: u64,
    base: &mut dyn FnMut() -> usize,
    ours: &mut dyn FnMut() -> usize,
) -> (f64, f64) {
    let slice = (iters / SLICES as u64).max(1);
    let calls = (slice * SLICES as u64) as f64;
    let mut rounds = Vec::with_capacity(crate::ROUNDS);
    for round in 0..crate::ROUNDS {
        let mut base_seconds = 0.0;
        let mut ours_seconds = 0.0;
        for slice_index in 0..SLICES {
            // `(round + slice_index) % 2` rather than `slice_index % 2` alone: the
            // alternation continues across rounds, so no round opens on the same side
            // as the round before it.
            if (round + slice_index) % 2 == 0 {
                base_seconds += slice_seconds(slice, base);
                ours_seconds += slice_seconds(slice, ours);
            } else {
                ours_seconds += slice_seconds(slice, ours);
                base_seconds += slice_seconds(slice, base);
            }
        }
        rounds.push((base_seconds / calls, ours_seconds / calls));
    }
    rounds.sort_by(|a, b| ratio_of(*a).total_cmp(&ratio_of(*b)));
    rounds[rounds.len() / 2]
}

/// `reference / ours` for a pair of seconds-per-call figures.
fn ratio_of(pair: (f64, f64)) -> f64 {
    pair.0 / pair.1
}

/// The line a gated table prints under itself when one of its rows was confirmed.
///
/// A confirmed row's published numbers are the median of `CONFIRMATIONS`
/// independent passes at four times the budget rather
/// than the first sample, so the reader is told which rows those are. A table
/// that silently published a re-read would be reporting a number whose provenance
/// the report does not carry, and the bar it was judged against is the whole
/// point of publishing it.
///
/// Empty for a clean run, which is every run that did not need the rule.
pub(crate) fn confirmation_note<'a>(rows: impl Iterator<Item = &'a Row>) -> String {
    let names: Vec<&str> = rows
        .filter(|r| r.remeasured)
        .map(|r| r.name.as_str())
        .collect();
    if names.is_empty() {
        return String::new();
    }
    format!(
        "\n**Confirmed: {}.** Each of these first read under {BAR:.2}x, so it was re-measured \
         at four times the budget and the median of {CONFIRMATIONS} independent passes is what \
         the table above and the gate below read. A row confirmed under the bar is a \
         regression, not a disturbed runner.\n",
        names.join(", "),
        BAR = crate::BAR,
        CONFIRMATIONS = crate::CONFIRMATIONS,
    )
}

/// One framed row: both sides timed, and a row under the bar confirmed before it
/// is allowed to fail the job.
///
/// # Why this exists, and why it is here rather than at the assert
///
/// Gate 3 has confirmed every reading under the bar since it learned to, at
/// `CONFIRMATIONS` independent passes of four times the budget, and
/// `docs/methodology.md` states the rule as a property of the bar rather than of
/// gate 3: *"One regressing length fails the job ... A length that comes out
/// under the bar is then re-measured at four times the budget before it is
/// allowed to fail."* The framings share that bar and the same `ROUNDS` of
/// best-of rounds, and had none of the confirmation, so a framing was decided by
/// one sample.
///
/// It decided `main`'s `windows x86_64` build at run `37325906810`, where
/// `early encode, 2048B` read **0.844x** and failed the job — on a row whose
/// code `PR #87` did not touch. The same row on the same runner one merge
/// earlier read **1.05x** (`37320161241`), the other three runners read
/// 1.07x/1.08x/1.11x, and the reference side of the pair moved 4268ns to 4339ns
/// while this side moved 4064ns to 5140ns. A 26% swing on unchanged bytes is the
/// runner, not a regression.
///
/// # What this cannot hide
///
/// A framing that is genuinely under the bar is under it in every pass, because
/// every pass runs the same code on the same machine; the rule decides a row only
/// when the median of independent passes agrees, and the median is taken over
/// *ratios* so the pair reported is the pair that was gated on. `#[inline(never)]`
/// on the references, the allocation counts and the byte equality all stay where
/// they were: this changes which reading of a row is allowed to fail, nothing
/// about what the row measures.
///
/// Shared with every gate that builds a `Row`, so this is one clock discipline
/// and one confirmation rule rather than two that agree today.
pub(crate) fn timed_row(
    name: String,
    bytes: usize,
    iters: u64,
    ours: &mut dyn FnMut() -> usize,
    base: &mut dyn FnMut() -> usize,
) -> Row {
    let first = paired(iters, base, ours);
    if ratio_of(first) >= crate::BAR {
        return Row {
            name,
            bytes,
            base: first.0,
            ours: first.1,
            remeasured: false,
        };
    }

    let heavy = iters.saturating_mul(4);
    let mut passes = Vec::with_capacity(crate::CONFIRMATIONS);
    for _ in 0..crate::CONFIRMATIONS {
        passes.push(paired(heavy, base, ours));
    }
    // The median *pass*, not the median ratio beside an unrelated pair: `ratio()`
    // is computed from `base`/`ours`, so the two numbers published have to be the
    // two the verdict was taken on, or the table reports one reading and the
    // assertion gates another.
    let (base, ours) = crate::confirmed_pass(&passes);
    Row {
        name,
        bytes,
        base,
        ours,
        remeasured: true,
    }
}

/// The synthetic rung-1 link every row encodes for: documentation addresses and
/// synthetic credentials, the same fixture the tests use.
const LINK: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8#x";

/// Gate 4: the header encode, over every address family, timed and byte-checked.
pub(crate) fn gate_framing() -> Vec<Row> {
    ["192.0.2.53", "2001:db8::1", "example.com"]
        .iter()
        .map(|host| header_row(host))
        .collect()
}

/// One address family's header encode, both sides checked equal before timing.
fn header_row(host: &str) -> Row {
    let link = VlessLink::parse(LINK).expect("synthetic rung-1 link parses");
    let port = 443u16;
    let mut fused = vec![0u8; link.request_header_len(host)];
    let mut was = vec![0u8; fused.len()];

    // Byte equality, and the allocation count, before either side is timed. The
    // buffers are allocated before the counting window opens, so the harness' own
    // `vec!` is not what gets counted.
    let bytes = {
        let n = link.encode_into(host, port, &mut fused);
        let m = previous_encode_into(&link, host, port, &mut was);
        assert_eq!(n, m, "{host}: the two encodes must write the same length");
        assert_eq!(&fused[..n], &was[..m], "{host}: and the same bytes");
        let ((), counts) = count::measure(|| {
            for _ in 0..64 {
                let n = link.encode_into(host, port, std::hint::black_box(&mut fused[..]));
                std::hint::black_box(n);
            }
        });
        assert_eq!(
            (counts.allocs, counts.bytes, counts.zeroed),
            (0, 0, 0),
            "the {host} header encode must not allocate"
        );
        n
    };

    let mut ours = || {
        let n = link.encode_into(host, port, std::hint::black_box(&mut fused[..]));
        std::hint::black_box(n)
    };
    let mut base = || {
        let n = previous_encode_into(&link, host, port, std::hint::black_box(&mut was[..]));
        std::hint::black_box(n)
    };

    timed_row(
        format!("vless header encode, {host}"),
        bytes,
        200_000,
        &mut ours,
        &mut base,
    )
}

/// Lengths the seal rows cover, in the shapes a `VMess` data frame arrives in.
///
/// A `VMess` data frame carries no associated data, which is the shape that makes
/// both of `RFC 8439` section 2.8's padding calls zero bytes: the `aad` section is
/// empty and the ciphertext is a whole number of blocks. That is the case the
/// fused keystream head was written for, so it is the case timed here.
const AEAD_LENGTHS: [usize; 5] = [64, 256, 1024, 4096, 16384];

/// Gate 7: the `ChaCha20`-`Poly1305` seal, against the two-call build it replaced.
///
/// Returns the same [`Row`] gate 4 returns, so the two gates share one bar, one
/// failure message and one clock discipline rather than agreeing by coincidence.
///
/// # What the reference is
///
/// [`ferrox_core::aead::chacha20_poly1305_seal_in_place_unfused`] is the seal as
/// it was before the head was fused: the `Poly1305` one-time key generated by its
/// own `fill_exact` over a 64-byte scratch, and the message encrypted by a second.
/// Same key, same nonce, same empty `aad`, same ciphertext, same tag — which
/// [`aead_seal_row`] asserts on every run before either side is timed, so the
/// ratio cannot be bought with output that differs.
pub(crate) fn gate_aead(key: &[u8; 32], nonce: &[u8; 12]) -> Vec<Row> {
    AEAD_LENGTHS
        .iter()
        .map(|&len| aead_seal_row(key, nonce, len))
        .collect()
}

/// One sealed length, both sides checked equal before either is timed.
///
/// The ciphertext is what leaves this function, so the equality assertion covers
/// the keystream *and* the `Poly1305` tag over it: a fused head that took the
/// wrong 32 bytes of block zero would still encrypt every byte and would fail
/// here on the tag alone.
fn aead_seal_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut fused = vec![0x5au8; len];
    let mut was = fused.clone();

    {
        let a = chacha20_poly1305_seal_in_place(key, nonce, &[], &mut fused);
        let b = chacha20_poly1305_seal_in_place_unfused(key, nonce, &[], &mut was);
        assert_eq!(
            fused, was,
            "len {len}: the two seals must encrypt identically"
        );
        assert_eq!(a, b, "len {len}: and produce the same tag");
    }

    // `len + 64` is the keystream both sides generate: the message's own blocks,
    // plus the block the one-time key is cut from. Charging the head to the
    // iteration count keeps the two sides on the same number of bytes.
    //
    // The nanosecond-per-byte figure is a guess, and only that: it sets the count
    // so every row spends about the same wall-clock in the clock, and a wrong
    // guess costs a row its resolution rather than its ratio. Both sides of every
    // row use the same count, so a wrong guess cannot favour either.
    let iters = u64::try_from((50_000_000 / (len + 64)).max(64)).expect("an iteration count");

    // Both closures hand back one byte of the tag, which is the type `best_of`
    // wants and is also the reason the work cannot be elided: the byte comes out of
    // the `Poly1305` state, so a dropped seal would change what the closure returns.
    let mut ours = || {
        let tag =
            chacha20_poly1305_seal_in_place(key, nonce, &[], std::hint::black_box(&mut fused[..]));
        usize::from(std::hint::black_box(tag)[0])
    };
    let mut base = || {
        let tag = chacha20_poly1305_seal_in_place_unfused(
            key,
            nonce,
            &[],
            std::hint::black_box(&mut was[..]),
        );
        usize::from(std::hint::black_box(tag)[0])
    };

    timed_row(
        format!("chacha20-poly1305 seal, {len}B"),
        len + 16,
        iters,
        &mut ours,
        &mut base,
    )
}

/// The seal's two halves, timed apart, over the same lengths.
///
/// # Why these rows exist
///
/// Gate 7 measures the seal as one thing, which is the right unit to *gate* and
/// the wrong one to *optimise*: a change to either half moves the total by
/// however much that half is worth, and until that is known the next change is
/// guesswork. So these rows separate them, and they are the answer to "which
/// half of the `ChaCha20`-`Poly1305` seal should the next change touch".
///
/// # Why both sides of a row run the same code
///
/// The point of these rows is the absolute nanoseconds, not a ratio — there is no
/// "before" for a half that has not changed yet. Timed twice, the two sides are
/// the same work, so their **ratio is this harness's own noise at that length**,
/// and the row is worth reading for that as much as for the absolute. A half
/// whose self-timed ratio sits at 0.97x is telling you that nothing smaller than
/// 3% could be measured there at all, which is the fact that decides whether an
/// optimisation of it can be gated.
///
/// They are reported and never gated, because gating a row against itself fails
/// on noise and a gate that cries wolf gets switched off.
pub(crate) fn aead_split(key: &[u8; 32], nonce: &[u8; 12]) -> Vec<Row> {
    AEAD_LENGTHS
        .iter()
        .flat_map(|&len| [keystream_row(key, nonce, len), mac_row(key, nonce, len)])
        .collect()
}

/// The keystream half alone: `fill_exact` over the same `len` bytes the seal
/// encrypts, which is `len + 64` blocks of the same core the seal spends on it.
fn keystream_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut buf = vec![0x5au8; len];
    let iters = u64::try_from((50_000_000 / (len + 64)).max(64)).expect("an iteration count");
    let mut run = || {
        ferrox_core::record::fill_exact(key, nonce, 1, std::hint::black_box(&mut buf[..]));
        0
    };
    self_timed(format!("chacha20 keystream, {len}B"), len, iters, &mut run)
}

/// The `MAC` half alone: the same `Poly1305` state, the same two padded sections
/// and the same length block `aead::mac` feeds it, over ciphertext this tree
/// produced. It is the whole second half of the seal including the one-time key
/// setup, which is per-message and not per-block.
///
/// `aead::mac` is private, so the section walk is written out here rather than
/// called. That is a duplication, and it is the honest kind: if `mac` ever stops
/// being `pad16` of each section followed by the length block, this row is
/// measuring something the seal no longer does, and the gate-7 total is the one
/// that catches it.
fn mac_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut buf = vec![0x5au8; len];
    // Only the ciphertext is wanted here; the seal's tag is gate 7's business.
    std::hint::black_box(chacha20_poly1305_seal_in_place(key, nonce, &[], &mut buf));
    let one_time = {
        let mut block = [0u8; 64];
        ferrox_core::record::fill_exact(key, nonce, 0, &mut block);
        block[..32].try_into().expect("32 bytes")
    };
    let mut lengths = [0u8; 16];
    lengths[8..].copy_from_slice(&(buf.len() as u64).to_le_bytes());

    let mut run = || {
        let mut state = Poly1305::new(std::hint::black_box(&one_time));
        for section in [&[][..], &buf[..]] {
            state.update(section);
            let slack = (16 - section.len() % 16) % 16;
            state.update(&[0u8; 16][..slack]);
        }
        state.update(&lengths);
        usize::from(state.finish()[0])
    };
    self_timed(
        format!("poly1305 mac, {len}B"),
        len + 16,
        u64::try_from((50_000_000 / (len + 16)).max(64)).expect("iters"),
        &mut run,
    )
}

/// One row whose two sides run the same closure, so the ratio is the harness's
/// own noise at this length and the absolute is the cost.
fn self_timed(name: String, bytes: usize, iters: u64, run: &mut dyn FnMut() -> usize) -> Row {
    // `best_of` takes its closure by value, and `run` is a `&mut dyn FnMut`, so
    // each side gets a reborrow of the same closure rather than the reference
    // itself — the whole point is that both sides run identical work.
    let first = best_of(iters, &mut *run);
    let second = best_of(iters, &mut *run);
    Row {
        name,
        bytes,
        base: first.min(second),
        ours: first.max(second),
        // Never confirmed, and deliberately so: both sides of this row are the
        // same closure, so its ratio is the harness's own noise by construction
        // and `timed_row`'s confirmation would be confirming a tie. This row is
        // reported and not gated, which is the whole reason it can carry a ratio
        // that means nothing.
        remeasured: false,
    }
}

/// Gate 7c: `Poly1305` alone, this tree's three-limb accumulator against the
/// twenty-five-product Horner chain it replaced.
///
/// # What the reference is
///
/// [`ferrox_core::poly1305::tag_via_26_bit_horner`] is the accumulator this
/// replaced, kept verbatim: five 26-bit limbs, `5 * r_i` precomputed once per
/// message, twenty-five `u64` products per sixteen-byte block. Same interface,
/// same tag. It is not a re-implementation of the specification and it is not a
/// third-party crate — it is the *previous* build, which is the only reference
/// that can say whether this change is faster.
///
/// # Why these rows are gated when gate 7b's are not
///
/// Gate 7b has no "before": both of its sides run the same code, so its ratio is
/// noise and gating it would fail at random. These rows do have a before, and it
/// is the code being replaced, so the same bar as gate 3 applies and a
/// regression here is a real regression.
///
/// Both sides assert the same tag before either is timed.
pub(crate) fn gate_mac(key: &[u8; 32], nonce: &[u8; 12]) -> Vec<Row> {
    AEAD_LENGTHS
        .iter()
        .map(|&len| mac_vs_horner_row(key, nonce, len))
        .collect()
}

/// One `Poly1305` length, both accumulators checked equal before either is timed.
fn mac_vs_horner_row(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let mut buf = vec![0x5au8; len];
    let one_time = {
        let mut block = [0u8; 64];
        ferrox_core::record::fill_exact(key, nonce, 0, &mut block);
        block[..32].try_into().expect("32 bytes")
    };

    // The message the two accumulators see is a real ciphertext, not a ramp, so
    // the test is over the bytes this seal actually MACs.
    std::hint::black_box(chacha20_poly1305_seal_in_place(key, nonce, &[], &mut buf));

    let mut ours_state = Poly1305::new(std::hint::black_box(&one_time));
    ours_state.update(std::hint::black_box(&buf[..]));
    let ours_bytes = ours_state.finish();

    let base_bytes = ferrox_core::poly1305::tag_via_26_bit_horner(
        std::hint::black_box(&one_time),
        std::hint::black_box(&buf[..]),
    );
    assert_eq!(
        ours_bytes, base_bytes,
        "len {len}: the three-limb accumulator must agree with the 26-bit Horner"
    );

    let iters = u64::try_from((50_000_000 / (len + 16)).max(64)).expect("an iteration count");

    let mut ours = || {
        let mut state = Poly1305::new(std::hint::black_box(&one_time));
        state.update(std::hint::black_box(&buf[..]));
        usize::from(std::hint::black_box(state.finish())[0])
    };
    let mut base = || {
        let tag = ferrox_core::poly1305::tag_via_26_bit_horner(
            std::hint::black_box(&one_time),
            std::hint::black_box(&buf[..]),
        );
        usize::from(std::hint::black_box(tag)[0])
    };

    timed_row(
        format!("poly1305 3x44 vs 26-bit horner, {len}B"),
        len + 16,
        iters,
        &mut ours,
        &mut base,
    )
}

/// Gate 7c's table.
pub(crate) fn mac_report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 7c — Poly1305, three limbs against five\n");
    let _ = writeln!(
        out,
        "The `Poly1305` accumulator alone, this tree's three 44-bit limbs with `u128`\n\
         products against the five 26-bit limbs it replaced — same interface, same tag,\n\
         asserted equal before either side is timed. The claim is arithmetic: three limbs\n\
         need nine hardware `64`-by-`64` products per block where five needed twenty-five,\n\
         and the fold stops depending on the block's *previous* limb. Best of {} rounds\n\
         per side, bar {:.2}x.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| accumulator | bytes | 26-bit ns/op | 3x44 ns/op | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if !rows.is_empty() {
        let worst = rows.iter().map(Row::ratio).fold(f64::INFINITY, f64::min);
        let _ = writeln!(out, "\n**Gate: worst {worst:.2}x.**");
        out.push_str(&confirmation_note(rows.iter()));
    }
    out
}

/// Gate 7's table.
pub(crate) fn aead_report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 7 — AEAD seal\n");
    let _ = writeln!(
        out,
        "The `ChaCha20`-`Poly1305` seal over an empty `aad`, which is what a `VMess` data\n\
         frame carries: this tree's fused keystream pass against the two-call build it\n\
         replaced, where the one-time key came out of its own 64-byte pass and the message\n\
         was encrypted by a second. Same ciphertext and same tag on both sides, asserted\n\
         before either is timed. Best of {} rounds per side. The bar is the same {:.2}x as\n\
         gate 3.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| seal | bytes | two-call ns/op | fused ns/op | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if !rows.is_empty() {
        let worst = rows.iter().map(Row::ratio).fold(f64::INFINITY, f64::min);
        let _ = writeln!(out, "\n**Gate: worst {worst:.2}x.**");
        out.push_str(&confirmation_note(rows.iter()));
    }
    out
}

/// The split table: the seal's two halves, timed apart, both sides running the
/// same code. Reported, never gated — see [`aead_split`].
pub(crate) fn aead_split_report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n### Gate 7b — where the seal's time goes\n");
    let _ = writeln!(
        out,
        "The same seal split into its two halves and timed apart, because gate 7 above\n\
         measures the seal as one thing and the next change has to know which half is\n\
         worth attacking. Both sides of every row run the *same* code, so the ratio\n\
         column is this harness's own run-to-run noise at that length and the absolute\n\
         column is the cost. A half whose self-timed ratio reads 0.97x cannot resolve a\n\
         change smaller than 3%, whatever the change is worth in isolation.\n\
         \n\
         These rows are reported and **not gated**: a row gated against itself fails on\n\
         noise, and a gate that cries wolf gets switched off.\n"
    );
    let _ = writeln!(out, "| half | bytes | ns/op | noise |");
    let _ = writeln!(out, "| --- | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.ours * 1e9,
            r.ratio()
        );
    }
    out
}

/// The header encode as it was before this change, kept verbatim.
///
/// Two parses of the target host per header, two `flow()` walks of the query map,
/// and a UUID decoded through an `Option` pairing state machine over all 36
/// characters. The shipped encode does one of each. Every byte it writes is the
/// same, which is what the equality assertion in [`header_row`] is there to prove
/// on every run.
fn previous_encode_into(link: &VlessLink, host: &str, port: u16, out: &mut [u8]) -> usize {
    let addons = if link.flow() == "xtls-rprx-vision" {
        1 + PREV_ADDONS.len()
    } else {
        1
    };
    let has_colon = host.contains(':');
    let addr = if !has_colon && host.parse::<std::net::Ipv4Addr>().is_ok() {
        1 + 4
    } else if has_colon && host.parse::<std::net::Ipv6Addr>().is_ok() {
        1 + 16
    } else {
        1 + 1 + host.len().min(255)
    };
    let need = 1 + 16 + addons + 1 + 2 + addr;
    assert!(out.len() >= need, "vless header buffer too short");
    let mut o = 0;
    out[o] = 0;
    o += 1;
    out[o..o + 16].copy_from_slice(&previous_uuid_bytes(&link.uuid));
    o += 16;
    if link.flow() == "xtls-rprx-vision" {
        out[o] = PREV_ADDONS.len() as u8;
        o += 1;
        out[o..o + PREV_ADDONS.len()].copy_from_slice(&PREV_ADDONS);
        o += PREV_ADDONS.len();
    } else {
        out[o] = 0;
        o += 1;
    }
    out[o] = 1;
    o += 1;
    out[o..o + 2].copy_from_slice(&port.to_be_bytes());
    o += 2;
    let has_colon = host.contains(':');
    let v4 = if has_colon {
        None
    } else {
        host.parse::<std::net::Ipv4Addr>().ok()
    };
    let v6 = if has_colon {
        host.parse::<std::net::Ipv6Addr>().ok()
    } else {
        None
    };
    if let Some(ipv4) = v4 {
        out[o] = 1;
        o += 1;
        out[o..o + 4].copy_from_slice(&ipv4.octets());
        o += 4;
    } else if let Some(ipv6) = v6 {
        out[o] = 3;
        o += 1;
        out[o..o + 16].copy_from_slice(&ipv6.octets());
        o += 16;
    } else {
        out[o] = 2;
        o += 1;
        let n = host.len().min(255);
        out[o] = n as u8;
        o += 1;
        out[o..o + n].copy_from_slice(&host.as_bytes()[..n]);
        o += n;
    }
    debug_assert_eq!(o, need);
    o
}

/// The marshaled Vision addons, spelled out so the reference does not depend on
/// the constant the shipped encode reads.
const PREV_ADDONS: [u8; 18] = *b"\x0A\x10xtls-rprx-vision";

/// `uuid_bytes` as it was: an `Option` pairing state machine over every character.
fn previous_uuid_bytes(uuid: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut idx = 0usize;
    let mut hi: Option<(u8, bool)> = None;
    for &b in uuid.as_bytes() {
        if b == b'-' {
            continue;
        }
        let (v, ok) = match b {
            b'0'..=b'9' => (b - b'0', true),
            b'a'..=b'f' => (b - b'a' + 10, true),
            b'A'..=b'F' => (b - b'A' + 10, true),
            _ => (0, false),
        };
        if let Some((h, hok)) = hi.take() {
            if idx < 16 {
                out[idx] = if hok && ok { (h << 4) | v } else { 0 };
                idx += 1;
            }
        } else {
            hi = Some((v, ok));
        }
        if idx >= 16 {
            break;
        }
    }
    out
}

/// The framing section of the report, appended after the gate-3 table.
pub(crate) fn report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 4 — protocol framing\n");
    let _ = writeln!(
        out,
        "The `VLESS` request header encode: this tree's fused encode against a reference\n\
         build of the same bytes — a fresh buffer per header, every field pushed\n\
         separately, the address family decided twice, and the UUID decoded a pair at a\n\
         time. Best of {} interleaved rounds per side. Every row asserts byte equality\n\
         before it is timed, so a ratio here cannot be bought with different output. The\n\
         bar is the same {:.2}x as gate 3.\n",
        crate::ROUNDS,
        crate::BAR
    );
    let _ = writeln!(
        out,
        "| framing | bytes | reference ns/op | ferrox ns/op | speedup |"
    );
    let _ = writeln!(out, "| --- | ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {} | {:.1} | {:.1} | {:.2}x |",
            r.name,
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        rows.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&confirmation_note(rows.iter()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// The number of times the two sides are entered, recorded in order, so a test can
    /// assert the *shape* of the measurement rather than trust a clock.
    #[derive(Default)]
    struct Trace {
        order: std::sync::Mutex<Vec<&'static str>>,
    }

    impl Trace {
        fn push(&self, side: &'static str) {
            self.order
                .lock()
                .expect("the trace lock is only held briefly")
                .push(side);
        }

        fn sides(&self) -> Vec<&'static str> {
            self.order
                .lock()
                .expect("the trace lock is only held briefly")
                .clone()
        }
    }

    /// Both sides of a round are measured the same number of times, and neither is
    /// measured first every time.
    ///
    /// This is the property the two-independent-`best_of` version could not have: it
    /// measured the reference five times in one block and then this tree five times in
    /// another, so whichever side went first got the earlier — and, on a runner that
    /// was slowing down, the faster — half of the row. Asserted on the order rather
    /// than on a timing, so it cannot flake.
    #[test]
    fn both_sides_are_measured_inside_every_round_and_neither_goes_first() {
        let trace = Trace::default();
        let mut base = || {
            trace.push("base");
            0
        };
        let mut ours = || {
            trace.push("ours");
            0
        };
        paired(4, &mut base, &mut ours);

        let sides = trace.sides();
        assert_eq!(
            sides.len(),
            crate::ROUNDS * SLICES * 2,
            "each round measures each side once per slice"
        );

        // Each slice is one call to each side, so the side measured *first* in a slice
        // is the side that went first in time. Reading it at the slice's own offset
        // makes this a statement about the measurement rather than about the sequence
        // of entries, which also holds the second side of every slice.
        let openings: Vec<&str> = (0..crate::ROUNDS * SLICES)
            .map(|slice| sides[slice * 2])
            .collect();
        assert_eq!(
            openings.iter().filter(|side| **side == "base").count(),
            openings.len() / 2,
            "half the slices measure the reference first: {openings:?}"
        );
        assert_eq!(
            openings.iter().filter(|side| **side == "ours").count(),
            openings.len() / 2,
            "and half measure this tree first: {openings:?}"
        );
    }

    /// The alternation continues across rounds, so no two consecutive rounds open on
    /// the same side.
    #[test]
    fn no_two_rounds_open_on_the_same_side() {
        let trace = Trace::default();
        let mut base = || {
            trace.push("base");
            0
        };
        let mut ours = || {
            trace.push("ours");
            0
        };
        paired(4, &mut base, &mut ours);
        let sides = trace.sides();
        let openings: Vec<&str> = sides.chunks(SLICES * 2).map(|round| round[0]).collect();
        assert_eq!(openings.len(), crate::ROUNDS);
        for (index, pair) in openings.windows(2).enumerate() {
            assert_ne!(
                pair[0],
                pair[1],
                "rounds {index} and {} both opened on {}",
                index + 1,
                pair[0]
            );
        }
    }

    /// Busy-work of `units` iterations, so a closure's cost is a real number of
    /// instructions rather than a claim about one.
    fn burn(units: u64) {
        let mut acc = 0u64;
        for i in 0..units {
            acc = acc.wrapping_add(i);
        }
        std::hint::black_box(acc);
    }

    /// A row measured correctly is a row whose ratio is the ratio, even when the
    /// machine it ran on changed state partway through.
    ///
    /// The change is synthesised, not hoped for. After `SWITCH_AFTER` calls the machine
    /// gets `STEP_PERCENT` *slower*, and stays there. That is a **step**, not a ramp,
    /// and the distinction is the whole argument: a ramp is what a minimum defends
    /// against, because each side's luckiest round is its earliest one and a ramp is
    /// cheapest there — which is why the drifting version of this test passed the old
    /// code. A step defeats a minimum completely, because each side's five rounds are
    /// internally homogeneous and the two blocks simply sit at different levels. A
    /// shared vCPU whose neighbour arrives is a step.
    ///
    /// **Proportional**, which the first version of this test got wrong in a way worth
    /// recording: it added a constant to each side's cost, which made the *slow* level's
    /// ratio 1300/850 = 1.53 rather than 2.0. The machine was then measuring a different
    /// question from the one the assertion asked, and `macos aarch64` read 1.559x
    /// against a "true" 2.0 and called the pairing wrong. A machine that gets slower by
    /// a factor is slower for all code equally, so both levels have the same ratio and
    /// only a measurement that compares different levels is wrong.
    ///
    /// The threshold sits so the step lands inside the *second* block of the unpaired
    /// measurement and inside one slice of one paired round, which is the arrangement
    /// that separates the two statistics.
    #[test]
    fn a_paired_ratio_survives_a_machine_that_changes_under_it() {
        // Sized so one measured slice is about a millisecond on every runner. At the
        // original 900/450 a call took under a microsecond, so the per-call figures
        // printed as `0.000ns` and on `windows x86_64` the two blocks came out within
        // noise of each other: the test measured nothing there.
        const TRUE_BASE: u64 = 20_000;
        const TRUE_OURS: u64 = 10_000;
        /// Calls per side per measurement.
        const ITERS: u64 = 200;
        /// How much slower every call gets, in percent, once the machine changes.
        ///
        /// 400, not 40. The step has to be larger than the load difference between
        /// the two `best_of` phases, or the fixture is measuring the machine: at 40 the
        /// unpaired blocks read anywhere from 1.43x to 1.91x against a true 2.000x
        /// depending on which phase got the quieter runner, and the run fails with the
        /// claim intact. At 400 the second side is five times the first and no amount
        /// of ordinary scheduling noise is the size of the thing being detected.
        const STEP_PERCENT: u64 = 400;
        /// Which call the machine changes on: the end of the first side's
        /// unpaired measurement, so that side is entirely fast and the second
        /// entirely slow. Derived from `ITERS` and `ROUNDS` rather than written
        /// down, because a literal here goes stale the moment either moves and the
        /// failure is two indistinguishable ratios.
        const SWITCH_AFTER: u64 = ITERS * crate::ROUNDS as u64;

        // Statics because both halves of the test need a counter their two closures can
        // share and reset between runs, and a `move` closure takes a counter with it.
        static CALLS: AtomicU64 = AtomicU64::new(0);
        fn make(base_units: u64) -> impl FnMut() -> usize {
            move || {
                let seen = CALLS.fetch_add(1, Ordering::Relaxed);
                let slower = if seen >= SWITCH_AFTER {
                    STEP_PERCENT
                } else {
                    0
                };
                burn(base_units + base_units * slower / 100);
                0
            }
        }
        let truth = TRUE_BASE as f64 / TRUE_OURS as f64;
        CALLS.store(0, Ordering::Relaxed);
        let (base_secs, ours_secs) = paired(ITERS, &mut make(TRUE_BASE), &mut make(TRUE_OURS));
        let ratio = base_secs / ours_secs;

        // The same machine, the same two sides, the old way: all of the reference's
        // rounds first and then all of this tree's, so the published ratio is mostly
        // the step and barely the code.
        CALLS.store(0, Ordering::Relaxed);
        let mut base = make(TRUE_BASE);
        let mut ours = make(TRUE_OURS);
        let unpaired = best_of(ITERS, &mut base) / best_of(ITERS, &mut ours);

        // Two assertions, both of which hold on a loaded runner as well as an idle
        // one, because the step is engineered rather than hoped for.
        //
        // The old form was `unpaired_error > paired_error * 5.0`, read off two idle
        // machines where the errors differ by a factor of eighty. On a shared
        // `macos aarch64` the same code reads 0.115x and 0.245x — a factor of two — and
        // fails with the claim holding. The factor was never a property of the code;
        // it was a property of how quiet the runner was.
        let paired_error = (ratio / truth - 1.0).abs();
        let unpaired_error = (unpaired / truth - 1.0).abs();

        // First: the step really landed. A five-times step read as two blocks moves the
        // ratio from 2.000x to about 0.400x, an error of 0.80x, so this threshold has
        // more than a factor of four of headroom and it fails only if the fixture
        // stopped arranging the measurement.
        assert!(
            unpaired_error > 0.5,
            "the step did not land, so this run proves nothing: the two blocks read \
             {unpaired:.3}x against a true {truth:.3}x, which is within the noise it \
             was supposed to be separated from"
        );

        // Then: pairing moved the answer towards the truth. A broken pairing measures
        // the reference entirely before the step and this tree entirely after it, so
        // both errors are the same size and this comparison is a tie — which is the
        // failure this test exists to catch, and it is caught without a factor.
        assert!(
            paired_error < unpaired_error,
            "pairing should be closer to the truth than two blocks: paired read \
             {ratio:.3}x and the two blocks read {unpaired:.3}x, against a true \
             {truth:.3}x"
        );
    }
}
