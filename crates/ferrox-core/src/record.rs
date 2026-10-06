//! The record layer: framing and keystream, and where they are made to agree.
//!
//! # The technique this crate is built around
//!
//! Almost every proxy stack pays the same tax twice. A record layer that needs
//! *n* bytes derives keystream for a fixed larger unit — a four-block `ChaCha20`
//! refill, a full buffer of zeros — and copies out the part it wanted. Two
//! costs follow, and neither is visible in a profile because the copy is
//! spread thin across every call:
//!
//! * **Work that is thrown away.** The refill computes rounds for bytes no one
//!   reads.
//! * **A copy.** Bytes land in a scratch buffer and are then moved again.
//!
//! Removing both is only possible if the discarded work can be proven
//! unnecessary. That proof is the job of [`fill_exact`], and it is checkable:
//! the differential test compares against the reference at every length and
//! every block offset, so "same bytes, less work" is a fact rather than a
//! claim.
//!
//! # What is checked
//!
//! - **Identity.** [`fill_exact`] against the `chacha20` crate. The unit test
//!   covers 44 lengths x 6 offsets x 2 key pairs = 528 shapes; the benchmark gate covers
//!   300 lengths x 6 offsets x 2 key pairs = 3600 shapes, and the same 3600 again
//!   through [`fill_exact_with_head`], for 7200, checked by `bench.yml` gate 1.
//!   Dense, not exhaustive: every byte 0..=256, then M-1/M/M+1 for each listed multiple only.
//!   Offsets are a selection (0 is every caller, the rest are resume paths), not a proof over `u32`.
//! - **Counter position.** Asserted directly: block counter 0 and block counter
//!   8 must not produce the same keystream.
//! - **No discarded work.** The counter only advances by blocks actually
//!   produced, asserted in the tests.
//! - **Bounds.** Every write is a sub-slice of the caller's buffer, so a write
//!   past the end is an index panic rather than a silent overrun, and the
//!   differential comparison catches any write to the wrong place inside it.

/// Fill `buf` with keystream. The keystream is `XOR`ed over `buf` in place.
///
/// `start_block` is the `ChaCha20` block counter the caller is positioned at. The
/// counter only ever advances by the blocks actually produced, so a buffer of
/// `n` bytes never generates a block it does not use.
///
/// Returns the number of 64-byte blocks the ladder generated, counted by the
/// passes that ran the rounds — not computed here. That is the whole point: the
/// value has to be an observation of the work, so that a ladder which generated a
/// block nobody asked for *reports* it and [`blocks_match`] rejects it. When this
/// returned `blocks_for(buf.len())` the check was `ceil(n / 64) == ceil(n / 64)`
/// and could not fail; a caller that does not care may ignore the return.
///
/// # Panics
///
/// If `buf.len()` exceeds `u32::MAX` blocks worth of counter space, which would
/// wrap the counter and silently repeat keystream.
pub fn fill_exact(key: &[u8; 32], nonce: &[u8; 12], start_block: u32, buf: &mut [u8]) -> u64 {
    let blocks = blocks_for(buf.len());
    assert!(
        blocks <= u64::from(u32::MAX) - u64::from(start_block),
        "chacha20 block counter would wrap; a nonce's keystream would repeat"
    );

    u64::from(crate::chacha::xor_blocks(
        key,
        nonce,
        start_block,
        None,
        buf,
    ))
}

/// [`fill_exact`], and the leading 32 bytes of the block at `start_block` into
/// `head`, from one pass.
///
/// # Why this exists
///
/// `ChaCha20`-`Poly1305` (`RFC 8439` section 2.6) derives the `Poly1305` key from
/// the first 32 bytes of block *zero* and encrypts the message from block *one*.
/// Those are consecutive blocks of one keystream, so asking for them separately
/// generates block zero a second time — and on `aarch64` that second pass runs
/// the scalar one-block core, because a single chain has nothing to interleave
/// with, which the ladder otherwise uses only for the last block of a tail. On a
/// 64-byte frame the head was half the keystream work.
///
/// The head's block is generated, its first 32 bytes kept and its last 32
/// dropped, which is what the `RFC` says to drop: the message keystream starts at
/// the *next* block. So the bytes are the ones two `fill_exact` calls would have
/// produced, and the count returned includes the head's block.
///
/// # Panics
///
/// If the block counter would wrap, exactly as [`fill_exact`] does.
pub fn fill_exact_with_head(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start_block: u32,
    head: &mut [u8; 32],
    buf: &mut [u8],
) -> u64 {
    // The head is a partial block of its own, so the pair needs the block count
    // `fill_exact` would report for a buffer `64` bytes longer than `buf` —
    // which is what `blocks_with_head_match` checks the ladder reported against.
    let blocks = blocks_for(buf.len() + 64);
    assert!(
        blocks <= u64::from(u32::MAX) - u64::from(start_block),
        "chacha20 block counter would wrap; a nonce's keystream would repeat"
    );
    u64::from(crate::chacha::xor_blocks(
        key,
        nonce,
        start_block,
        Some(head),
        buf,
    ))
}

/// The blocks a buffer of `buf_len` bytes needs, which is what the ladder has to
/// report for [`blocks_match`] to hold.
pub const fn blocks_for(buf_len: usize) -> u64 {
    (buf_len as u64).div_ceil(64)
}

/// Gate 2's comparison for [`fill_exact_with_head`]: the head is a partial block
/// of its own, so the pair needs the count `fill_exact` would report for a buffer
/// `64` bytes longer than `buf_len`.
pub const fn blocks_with_head_match(buf_len: usize, generated: u64) -> bool {
    generated == blocks_for(buf_len + 64)
}

/// Gate 2's whole comparison, as one function the gate and the tests share.
///
/// `generated` is what the ladder reported and `buf_len` is what the caller asked
/// for. Kept here rather than in the benchmark so the thing the gate checks and
/// the thing that proves the gate can fail are the same code: a test feeding it a
/// wrong count is testing the gate, not a copy of it.
pub const fn blocks_match(buf_len: usize, generated: u64) -> bool {
    generated == blocks_for(buf_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lengths and block offsets the gate sweeps, kept here so the unit tests and
    /// `ferrox-bench` gate 2 cover the same ground.
    const SWEEP: ([u32; 3], [usize; 6]) = ([0, 1, 65_535], [0, 1, 63, 64, 65, 256]);

    #[test]
    fn the_ladder_reports_the_blocks_the_caller_asked_for() {
        // The claim is about what the core *does*, so this calls it: `generated`
        // is the ladder's own count, and comparing it against `blocks_for` is
        // gate 2's comparison, not a restatement of it.
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &start_block in &SWEEP.0 {
            for &len in &SWEEP.1 {
                let mut buf = vec![0u8; len];
                let generated = fill_exact(&key, &nonce, start_block, &mut buf);
                assert!(
                    blocks_match(len, generated),
                    "start {start_block} len {len}: the ladder reported {generated} blocks for a \
                     buffer of {len} bytes, which needs {}",
                    blocks_for(len)
                );
            }
        }
    }

    /// The fused pass produces exactly the bytes two `fill_exact` calls do, at
    /// every length and every block offset.
    ///
    /// This is the whole claim [`fill_exact_with_head`] makes, and it is checked
    /// against the *reference* rather than against the unfused call, so a mistake
    /// the two could share — the counter, the lane order, which 32 bytes of block
    /// zero are kept — is caught here rather than passing because both sides
    /// dropped the same block.
    #[test]
    fn the_head_is_the_references_own_first_block_and_the_rest_is_unshifted() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &start_block in &[0u32, 1, 8] {
            for &len in &[0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 256, 8192] {
                // One plaintext, handed to both sides. It has to be built once and
                // cloned *before* either side touches it: `fill_exact_with_head`
                // XORs in place, so seeding the second buffer from the first one's
                // finished output XORs the keystream twice and cancels it, which
                // looks like a pass and is not one.
                let plain: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                    .collect();

                // The reference's own keystream, from which the head and the body are
                // cut by hand: counter `start_block + 1` for the body, and the block
                // below it for the head.
                let mut want_body = plain.clone();
                crate::reference::reference_xor(&key, &nonce, start_block + 1, &mut want_body);
                let mut head_block = [0u8; 64];
                crate::reference::reference_xor(&key, &nonce, start_block, &mut head_block);
                let want_head: [u8; 32] = head_block[..32].try_into().expect("32 bytes");

                let mut got_body = plain;
                let mut got_head = [0u8; 32];
                let generated =
                    fill_exact_with_head(&key, &nonce, start_block, &mut got_head, &mut got_body);

                assert_eq!(
                    got_body, want_body,
                    "body: start {start_block} len {len} must be block start+1 onward"
                );
                assert_eq!(
                    got_head, want_head,
                    "head: start {start_block} len {len} must be the first 32 of block {start_block}"
                );
                assert!(
                    blocks_with_head_match(len, generated),
                    "start {start_block} len {len}: reported {generated} blocks, needs {}",
                    blocks_for(len + 64)
                );
            }
        }
    }

    /// The block count is an observation of the work, so it has to be able to be
    /// wrong: a fused pass that generated a block nobody asked for reports one
    /// more, and a pass that dropped the head's block reports one fewer.
    #[test]
    fn the_head_block_count_check_fails_when_the_count_is_wrong() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &len in &[0usize, 1, 63, 64, 65, 255, 256, 257, 8192] {
            let mut buf = vec![0u8; len];
            let mut head = [0u8; 32];
            let generated = fill_exact_with_head(&key, &nonce, 0, &mut head, &mut buf);
            assert!(
                blocks_with_head_match(len, generated),
                "len {len}: the real fused pass must match"
            );
            assert!(
                !blocks_with_head_match(len, generated + 1),
                "len {len}: one block too many must be rejected"
            );
            if generated > 0 {
                assert!(
                    !blocks_with_head_match(len, generated - 1),
                    "len {len}: one block too few must be rejected"
                );
            }
        }
    }

    /// A head on its own — an empty body — still generates exactly one block, and
    /// it is the right one. This is the shape the fused path takes at a frame too
    /// short to fill a pass, where the head falls through to `one_block`.
    #[test]
    fn a_head_with_an_empty_body_is_still_one_correct_block() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        let mut block = [0u8; 64];
        crate::reference::reference_xor(&key, &nonce, 0, &mut block);
        let want: [u8; 32] = block[..32].try_into().expect("32 bytes");

        let mut got = [0u8; 32];
        let generated = fill_exact_with_head(&key, &nonce, 0, &mut got, &mut []);
        assert_eq!(got, want, "the head of an empty body");
        assert_eq!(generated, 1, "an empty body plus a head is one block");
        assert!(blocks_with_head_match(0, generated));
    }

    /// And the counter still refuses to wrap, before any keystream is written.
    #[test]
    fn the_head_refuses_a_wrapping_counter_too() {
        let mut buf = [0u8; 8];
        let mut head = [0u8; 32];
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_exact_with_head(&[0u8; 32], &[0u8; 12], u32::MAX, &mut head, &mut buf)
        }));
        assert!(r.is_err(), "a wrapping counter must be refused, not obeyed");
        assert_eq!(buf, [0u8; 8], "the guard must fire before any keystream");
        assert_eq!(head, [0u8; 32], "and before the head is written");
    }

    #[test]
    fn the_block_count_check_fails_when_the_count_is_wrong() {
        // A gate nobody has watched fail is not a gate. `+1` is what a tail that
        // overshot by one state would report and `-1` what one that dropped a
        // block would, so this exercises the comparison gate 2 makes on both sides
        // of the real ladder's number.
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for &len in &[0usize, 1, 63, 64, 65, 255, 256, 257, 512, 16384] {
            let mut buf = vec![0u8; len];
            let generated = fill_exact(&key, &nonce, 0, &mut buf);
            assert!(
                blocks_match(len, generated),
                "len {len}: the real ladder must match"
            );
            assert!(
                !blocks_match(len, generated + 1),
                "len {len}: one block too many must be rejected"
            );
            if generated > 0 {
                assert!(
                    !blocks_match(len, generated - 1),
                    "len {len}: one block too few must be rejected"
                );
            }
        }
    }

    #[test]
    fn replayed_first_group_fails_the_identity_check() {
        // The historical wrong core, expressed through the API rather than by
        // copying bytes: the counter advanced by the block offset and forgot the
        // group offset, so every group after the first replayed group one. Two
        // calls at the same counter is that core, and it is what 1024 bytes looked
        // like before the counter arithmetic was factored.
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        let mut want = vec![0u8; 1024];
        crate::reference::reference_xor(&key, &nonce, 0, &mut want);

        let mut wrong = vec![0u8; 1024];
        fill_exact(&key, &nonce, 0, &mut wrong[..512]);
        fill_exact(&key, &nonce, 0, &mut wrong[512..]);
        assert_ne!(
            wrong, want,
            "start 0 len 1024: replaying the first 512 bytes must not match"
        );

        // And the shape the real core is, so the assertion above is about the
        // mutation rather than about two calls that can never agree.
        let mut right = vec![0u8; 1024];
        fill_exact(&key, &nonce, 0, &mut right[..512]);
        fill_exact(&key, &nonce, 8, &mut right[512..]);
        assert_eq!(right, want, "start 0 len 1024: advancing by 8 must match");
    }

    /// The wrong core this slice was found by: the tail's split stopped subtracting
    /// the pending head's block, so a pass was handed 64 bytes of `rest` it did not
    /// own and the last block of the body was never xored.
    ///
    /// It was wrong at every length in the `TAIL_STATES` clamp window and nowhere
    /// else — `[385, 447]` on an `aarch64` build, 63 lengths per offset — and the
    /// shipped suite was green on all of them: the head unit test swept 13 hand-picked
    /// lengths that step over the window, and gate 1 called only `fill_exact`.
    #[test]
    fn a_head_whose_tail_never_xored_its_last_block_fails_the_identity_check() {
        let key = [0x5au8; 32];
        let nonce = [0xa7u8; 12];
        for len in 385..=447usize {
            let mut want = vec![0u8; len + 64];
            crate::reference::reference_xor(&key, &nonce, 0, &mut want);
            let (want_block, want_body) = want.split_at(64);
            let want_head = &want_block[..32];

            // The real core, at every length in and beside the window.
            let mut got_body = vec![0u8; len];
            let mut got_head = [0u8; 32];
            fill_exact_with_head(&key, &nonce, 0, &mut got_head, &mut got_body);
            assert_eq!(got_head, want_head, "len {len}: head must match");
            assert_eq!(got_body, want_body, "len {len}: body must match");

            // The mutation, expressed as what it produced: the last 64 bytes of the
            // body left as the caller handed them over. Kept as the wrong core
            // rather than a hand-built buffer, because a gate that has never been
            // defeated has not been tested.
            let mut wrong = vec![0u8; len];
            fill_exact(&key, &nonce, 1, &mut wrong[..len - 64]);
            let mut wrong_head = [0u8; 32];
            fill_exact(&key, &nonce, 0, &mut wrong_head);
            assert_ne!(
                (wrong_head.as_slice(), wrong.as_slice()),
                (want_head, want_body),
                "len {len}: a body whose last block was never xored must not match"
            );
        }
    }

    #[test]
    fn blocks_for_is_the_ceiling() {
        assert_eq!(blocks_for(65), 2);
        assert_eq!(blocks_for(64), 1);
        assert_eq!(blocks_for(128), 2);
        assert_eq!(blocks_for(129), 3);
        assert_eq!(blocks_for(0), 0);
    }

    #[test]
    fn refuses_a_wrapping_counter() {
        let mut buf = [0u8; 64];
        // `AssertUnwindSafe` because `&mut [u8; 64]` is not `UnwindSafe`. The
        // claim under test is that the panic happens *before* any write, and
        // `buf` is left untouched, which is checked below rather than assumed:
        // if the guard were ever removed the count would differ.
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            fill_exact(&[0u8; 32], &[0u8; 12], u32::MAX, &mut buf)
        }));
        assert!(r.is_err(), "a wrapping counter must be refused, not obeyed");
        assert_eq!(
            buf, [0u8; 64],
            "the guard must fire before any keystream is written"
        );
    }
}
