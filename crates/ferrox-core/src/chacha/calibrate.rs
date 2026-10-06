//! Which one-block core this CPU runs, measured once.
//!
//! A single `ChaCha` block is twenty rounds of quarter round and every round depends
//! on the one before it, so one block has no instruction-level parallelism to
//! exploit: the only question is which instruction set reaches the end of that
//! dependency chain first, and that is a property of the microarchitecture, not of
//! the ISA.
//!
//! On `x86_64` the answer is not a question — `SSE2` is baseline and `portable`
//! compiles to scalar `movl`/`roll` there, and the AVX2 runners measured a
//! five-block buffer at 0.86x with it against 1.9x for the four-block pass in the
//! same call. On `aarch64` it is a real choice, because the vector rotate-by-8 is
//! `vqtbl1q_u8` and the rotate-by-16 is `vrev32q_u16`: both sit between every pair
//! of rounds, on the critical path. A core with enough issue slots to overlap them
//! wins with SIMD; a core with one vector pipe pays for them in latency and loses.
//! Both are `aarch64`, and nothing in `CPUID`, `/proc/cpuinfo` or `uname` tells them
//! apart, and this crate targets aarch64 servers, phones and desktops at once.
//!
//! # Why this is a file and not a function in `mod.rs`
//!
//! `scripts/check-leak-surface.sh` fails a wall-clock read anywhere in
//! `ferrox-core` except `kcp/`, and it is right: a library that reads the clock
//! in a function a caller believes is deterministic is a surprise. This module is
//! the second named exception to that gate, and it earns the place for the same
//! reason `kcp/` does — not because timing here is harmless, but because the timing
//! *cannot reach the output*. [`verdict`] chooses between two cores that execute
//! the same twenty rounds through the same generic function, so the keystream is
//! byte-identical either way; what the clock decides is which of two correct cores
//! runs it. The exclusion is a path for exactly the same reason it is for `kcp/`:
//! a pattern would exempt every future clock read in the module tree, and a path
//! cannot.
//!
//! # Why being wrong is cheap
//!
//! A calibration that picked the slower core is a performance bug and never a
//! correctness one, which is the property that makes a measurement safe to take at
//! all. `one_block_calibration_tests` holds both cores to byte-identity at counters
//! across a chunk boundary and the `u32` wrap, so a core that disagreed would be
//! caught on the machine that has it rather than in a report on another.
//!
//! Licence-clean: re-derived from the argument above. The pinned `ZeroNet` core
//! measures the same thing for the same reason
//! (`upstream/zeronet/crates/zero-protocol/src/chacha20/mod.rs:296-340`, read for
//! the argument, not for code); no line and no constant is carried from it, and
//! this one is a path rather than seven hand-written cores.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use super::{base, base_state, portable, xor_groups, Wide};

/// The lanes core won.
const LANES_PREFERRED: u8 = 1;

/// The scalar core won.
const SCALAR_PREFERRED: u8 = 2;

/// Never measured: what [`ONE_BLOCK`] holds before anything has run.
const UNCALIBRATED: u8 = 0;

/// The one-block core this process chose, after [`measure`] once.
static ONE_BLOCK: AtomicU8 = AtomicU8::new(UNCALIBRATED);

/// A tie, or a win inside this fraction, goes to the scalar core.
///
/// The scalar core is the architecture-neutral one — the same code on every machine
/// this crate builds for, and the core Miri interprets, so a tie picks the one whose
/// correctness argument is the machine-checked one. `0.95` rather than a strict `>`
/// so a hair's-breadth win does not flip the answer on noise, which is what the
/// best-of-[`REPS`] below is for.
const TIE: f64 = 0.95;

/// Passes per core. Three, because the first pass on any core pays an instruction
/// cache miss for the code it just entered and one pass would measure that.
const REPS: usize = 3;

/// Blocks per pass. One block is the unit compared; 64 of them puts the loop and
/// the two clock reads both under a percent of the total.
const BLOCKS: usize = 64;

/// Whether this CPU runs one block faster through the lanes core.
///
/// One `AtomicU8` load per call after the first, which is what keeps the
/// measurement off the hot path: a memoised `bool` behind an atomic, because a
/// `static mut` is a data race and a `OnceLock` costs a branch the tail cannot
/// spare. `Relaxed` is the right ordering because there is exactly one writer and
/// every reader wants the same answer eventually, not the first one's.
#[inline]
pub(super) fn verdict() -> bool {
    // SAFETY: `AtomicU8::load`/`store` are the whole point of the type and need no
    // outer guarantee; the `static` is `Sync` because `AtomicU8` is.
    match ONE_BLOCK.load(Ordering::Relaxed) {
        LANES_PREFERRED => return true,
        SCALAR_PREFERRED => return false,
        _ => {}
    }
    let winner = if measure() {
        LANES_PREFERRED
    } else {
        SCALAR_PREFERRED
    };
    ONE_BLOCK.store(winner, Ordering::Relaxed);
    winner == LANES_PREFERRED
}

/// Whether the lanes core beats the scalar core for one block, on this machine.
///
/// Both cores run over the same key, nonce, counter and source into separate
/// outputs, best-of-[`REPS`] passes each, so the answer is a ratio of two *minima*
/// rather than two samples and one unlucky scheduling decision cannot decide it.
/// The outputs are compared before the verdict is used: a calibration that found
/// them differing would be timing a bug, and reading them here is how that surfaces
/// on the machine that has it.
///
/// Returns `false` when the clock read no usable time, which is the conservative
/// answer and the same one a tie gets.
fn measure() -> bool {
    let key = [0x5bu8; 32];
    let nonce = [0xa7u8; 12];
    let state = base_state(&key, &nonce);
    let mut lanes = [0u8; 64 * BLOCKS];
    let mut scalar = [0u8; 64 * BLOCKS];

    let mut lanes_time = f64::MAX;
    let mut scalar_time = f64::MAX;
    for _ in 0..REPS {
        let start = Instant::now();
        for block in 0..BLOCKS {
            let mut out = [0u8; 64];
            xor_groups::<Wide, 1>(&base::<Wide>(&state), block as u32, &mut out, None);
            lanes[block * 64..block * 64 + 64].copy_from_slice(&out);
        }
        lanes_time = lanes_time.min(start.elapsed().as_secs_f64());

        let start = Instant::now();
        for block in 0..BLOCKS {
            let mut out = [0u8; 64];
            portable::xor_block(&state, block as u32, &mut out);
            scalar[block * 64..block * 64 + 64].copy_from_slice(&out);
        }
        scalar_time = scalar_time.min(start.elapsed().as_secs_f64());
    }

    debug_assert_eq!(
        lanes, scalar,
        "the one-block cores disagree, so this measurement is timing a bug"
    );
    scalar_time > 0.0 && lanes_time < scalar_time * TIE
}

#[cfg(test)]
mod tests {
    use super::{
        base, base_state, portable, verdict, xor_groups, Wide, LANES_PREFERRED, ONE_BLOCK,
        SCALAR_PREFERRED, UNCALIBRATED,
    };
    use crate::chacha::one_block;
    use std::sync::atomic::Ordering;

    /// The memo has to actually memo, and it has to hold one of the three values
    /// rather than anything else — a fourth value would make `verdict` re-measure
    /// on every call, which is the one failure mode a `static` here can have that
    /// a `let` cannot.
    #[test]
    fn the_verdict_is_memoised_after_the_first_call() {
        let first = verdict();
        assert_eq!(
            ONE_BLOCK.load(Ordering::Relaxed),
            if first {
                LANES_PREFERRED
            } else {
                SCALAR_PREFERRED
            }
        );
        for _ in 0..8 {
            assert_eq!(verdict(), first, "the verdict changed between calls");
        }
        assert_ne!(ONE_BLOCK.load(Ordering::Relaxed), UNCALIBRATED);
    }

    /// A verdict of either kind must leave the keystream alone, which is the whole
    /// reason this file is allowed to read the clock.
    #[test]
    fn either_verdict_writes_the_same_keystream() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let state = base_state(&key, &nonce);
        let mut chosen = [0u8; 64];
        assert_eq!(one_block(&state, 9, &mut chosen), 1);
        let mut scalar = [0u8; 64];
        portable::xor_block(&state, 9, &mut scalar);
        assert_eq!(chosen, scalar, "the chosen core wrote something else");
    }

    /// The two cores are byte-identical by construction — same twenty rounds,
    /// same [`Lanes`] primitives — and this holds that rather than trusting it.
    /// The counters are walked to both ends of the `u32` range and across a chunk
    /// boundary, because a core that disagreed at exactly one counter would be
    /// caught here on the machine that has it instead of in a differential report
    /// from a runner that does not.
    #[test]
    fn the_two_one_block_cores_agree_at_every_tested_counter() {
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let state = base_state(&key, &nonce);
        for ctr in [0u32, 1, 3, 7, u32::MAX - 1, u32::MAX] {
            let mut lanes = [0u8; 64];
            let mut scalar = [0u8; 64];
            xor_groups::<Wide, 1>(&base::<Wide>(&state), ctr, &mut lanes, None);
            portable::xor_block(&state, ctr, &mut scalar);
            assert_eq!(lanes, scalar, "counter {ctr}: the two cores disagree");
        }
    }
}
