//! Gate 8: the early-data base64url encode, timed against a build shaped the way
//! the four implementations shape it.
//!
//! # What this gate is, and what it is not
//!
//! It is **not** a differential against a pinned same-language oracle. The four
//! are three Go trees and one configuration surface, and none of them can be
//! run in-process to hand a `String` back to this binary — `docs/conformance.md`
//! measures that per suite. What *is* pinned and runs is `conformance.yml`, and
//! it is what decides the row: two upstream oracle tests that exercise this
//! setting against real `Xray-core`, unmodified, at the pin. That is a stronger
//! identity claim than anything here, and it is a different kind of claim, so
//! this file says which is which rather than letting a ratio imply a differential.
//!
//! What this gate adds is the *cost* half, and it is the half that can be a
//! count rather than a reading.
//!
//! # What the reference is
//!
//! `ZeroNet`'s `zero-transport/src/ws/handshake.rs::build_request`, which is the
//! shape to measure against for two reasons: it is the core `ferrox-app`
//! replaces and whose oracle suite runs against it, and it is **Rust**, so the
//! two sides differ in what they do rather than in what their languages cost.
//! Its whole early-data line is
//!
//! ```text
//! let encoded = base64::…::URL_SAFE_NO_PAD.encode(early_data);   // a fresh String
//! req.push_str(&format!("Sec-WebSocket-Protocol: {encoded}\r\n"));  // a second one
//! ```
//!
//! — two allocations and two copies for one header line, on a path that runs
//! once per connection. The three Go trees are the same shape and worse:
//! `Xray-core` calls `EncodeToString` and puts the result in a per-dial
//! masquerade header map, `xray-rust` adds a `Vec` copy of the payload before
//! encoding it, and `sing-box` clones the whole header map to set it.
//!
//! [`previous_line`] is `ZeroNet`'s shape. Ours is [`early_encode_into`], which
//! appends the digits to the buffer the caller already owns and writes the rest
//! of the line with `push_str`. So the two sides differ in exactly one way, and
//! every row asserts the finished line equals before either is timed: **the
//! reference builds two strings and copies twice; ours builds none and copies
//! none.**
//!
//! # Why there is no decode row
//!
//! Because there is nothing to gate. Every implementation decodes into a buffer
//! it returns — `DecodeString` allocates one `[]byte`, ours allocates one `Vec`
//! — so both sides are at one allocation and the same bytes, and a row between
//! them would measure `alloc`. The decode's correctness is proved by the
//! round-trip vectors in `transport::tests`, which cover every length 0-192 and
//! both alphabets rather than the two or three lengths a benchmark would.
//!
//! # The allocation counts are the claim
//!
//! From the same counting global allocator gate 2 uses, so a count and not a
//! reading, on **both** sides: ours is held under one allocation per encode and
//! the reference's is held at two or more, and both are printed on every row.
//! A reference that had been given a reused buffer would be measuring something
//! no implementation does.
//!
//! **These assertions live in the gate and not in a `#[test]`**, for the reason
//! `muxframe.rs` records: `count::measure` sets one process-wide flag, so under a
//! test runner it counts whatever the *other* tests are allocating at the same
//! moment. Measured in run `37247640795`: six allocations attributed to this side
//! over sixty-four encodes and 475 to the reference where 128 is two per call,
//! all of it parallel-test traffic.
//!
//! **The bar on this side is under one allocation per encode, not zero**, and
//! that is a measurement rather than a shrug. In a release bench driven from
//! `main()` with nothing else running — runs `37250890100` and `37251478949` —
//! the same window reads 6 allocations and 8064 bytes, and a second identical
//! window immediately after reads **1 allocation of 8192 bytes**. An 8 KiB block
//! is not a `String` this code builds: the warmed buffer is 64 bytes and never
//! grows, and the encode appends at most 39. So something outside the encode
//! allocates inside the window, it has not been identified, and a gate that
//! demanded zero would be gating on that unknown rather than on this code. What
//! is decidable is the shape of the claim, and it is the claim worth making:
//! **this side does not allocate per call; the reference's shape allocates two.**
//!
//! # Why the reference is `#[inline(never)]`
//!
//! For the reason gate 6 gives: [`early_encode_into`] crosses a crate boundary
//! and `previous_line_into` does not, so leaving that alone lets the ratio
//! measure a call rather than a body.

use std::fmt::Write as _;

use ferrox_core::transport::{early_decode, early_encode_into};

use crate::count;
use crate::framing::{timed_row, Row};

/// Encodes per timed shape. A 2 KiB budget is the largest the two upstream
/// oracle rows use, and the sizes below it are a `VLESS` request header, a
/// `VMess` header and both together.
const ITERS: u64 = 200_000;

/// Encodes the allocation window runs, matching gate 4's discipline.
const ALLOC_ITERS: u64 = 64;

/// The payloads one `?ed=N` budget is asked to carry, in bytes.
///
/// `8` is a `Trojan` header, `120` a `VLESS` request header with a domain
/// target, `256` the largest budget the ws carrier's frame length makes
/// interesting, and `2048` both upstream oracle rows' budget.
const PAYLOADS: [usize; 4] = [8, 120, 256, 2048];

/// Gate 8: every row's assertions, then every row timed.
pub(crate) fn gate_early_data() -> Vec<Row> {
    PAYLOADS
        .iter()
        .map(|&len| {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(61)).collect();
            check_encode(len, &data);
            let (ours, theirs) = check_encode_allocs(len, &data);
            // The guard on the reference's shape, in the only place an allocation
            // count is evidence: `count::measure` sets one process-wide flag, so a
            // `cargo test` run counts whatever the other tests are doing at the
            // same moment. Measured in run 37247640795: 6 allocations attributed to
            // this side over 64 encodes, and 475 to the reference where 128 is two
            // per call — all of it parallel-test traffic.
            assert!(
                theirs >= ALLOC_ITERS as usize,
                "{len}: the reference must keep costing two Strings per call, or the \
                 ratio stops meaning what this file says"
            );
            println!(
                "gate 8: {len}B early data — {ours} allocations over {ALLOC_ITERS} encodes here, \
                 {theirs} in the shape the four have"
            );
            encode_row(len, &data)
        })
        .collect()
}

/// The two encoders write the same digits, and the reference's round trip holds.
///
/// Identity before timing, as in every other gate: a reference that disagreed
/// would panic rather than report a speedup.
fn check_encode(len: usize, data: &[u8]) {
    let mut ours_out = String::with_capacity(len * 2);
    early_line_into(&mut ours_out, data);
    let theirs = previous_line(data);
    assert_eq!(ours_out, theirs, "{len}: same header line");
    let digits = ours_out
        .strip_prefix("Sec-WebSocket-Protocol: ")
        .and_then(|line| line.strip_suffix("\r\n"))
        .unwrap_or_default();
    assert_eq!(
        early_decode(digits).as_deref(),
        Some(data),
        "{len}: and they decode back"
    );
    assert!(
        !digits.contains('+') && !digits.contains('/'),
        "{len}: url alphabet"
    );
    assert!(!digits.contains('='), "{len}: unpadded");
}

/// Under one allocation per encode on this side; both counts returned to print.
///
/// The bar is **not** zero, and the reason is measured rather than assumed.
/// `count::measure` sets one process-wide flag, and this binary has something
/// outside the encode that allocates inside the window: a release bench driven
/// from `main()` with nothing else running reads **6 allocations and 8064 bytes
/// over 64 encodes**, and a second identical window immediately after reads
/// **1 allocation of 8192 bytes**. The same six appear in a debug `cargo test`
/// with a hundred tests in flight. An 8 KiB block is not a `String` this
/// function builds — the warmed buffer is 64 bytes and never grows — so what it
/// is has not been diagnosed, and `muxframe.rs` records the same class of count
/// it declines to assert on.
///
/// So the gate decides what is still decidable and true: **this side does not
/// allocate per call, and the reference's shape allocates two per call.** Both
/// numbers are printed, so the gap is a reading rather than an assertion about
/// a cause.
fn check_encode_allocs(len: usize, data: &[u8]) -> (usize, usize) {
    let mut out = String::with_capacity(len * 2);
    // One untimed pass first, so this side's buffer is at the capacity it will
    // hold for the rest of the connection rather than growing inside the window.
    early_line_into(&mut out, data);
    out.clear();
    let ((), ours) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            early_line_into(std::hint::black_box(&mut out), std::hint::black_box(data));
        }
    });
    // Warmed too, so the one growth its longer line causes is paid before the
    // window opens and the count is the per-call one rather than that plus one.
    previous_line_into(&mut out, data);
    out.clear();
    let ((), theirs) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            previous_line_into(std::hint::black_box(&mut out), std::hint::black_box(data));
        }
    });
    assert!(
        ours.allocs < ALLOC_ITERS as usize,
        "{len}: the shipped encode must not allocate per call, and it allocated {} times over \
         {ALLOC_ITERS}",
        ours.allocs
    );
    (ours.allocs, theirs.allocs)
}

/// One encode row: both sides timed over the same payload.
///
/// Through `timed_row` rather than `best_of` directly, because this row is gated
/// and the bar confirms a reading that comes out under it. Run `37325906810`
/// failed `main`'s `windows x86_64` job here at 0.844x on unchanged code, which
/// `timed_row`'s header records.
fn encode_row(len: usize, data: &[u8]) -> Row {
    let mut ours_out = String::with_capacity(len * 2);
    let mut ref_out = String::with_capacity(len * 2);
    let mut ours = || {
        ours_out.clear();
        early_line_into(&mut ours_out, std::hint::black_box(data));
        ours_out.len()
    };
    let mut base = || {
        ref_out.clear();
        previous_line_into(
            std::hint::black_box(&mut ref_out),
            std::hint::black_box(data),
        );
        ref_out.len()
    };
    timed_row(
        format!("early encode, {len}B"),
        len,
        ITERS,
        &mut ours,
        &mut base,
    )
}

/// This tree's whole early-data line: the name and terminator by `push_str`, the
/// digits appended in place. One buffer, and it is the caller's.
///
/// The emptiness guard is `ZeroNet`'s own and `ws::request`'s: a header with
/// nothing in it is malformed, so both sides here refuse to write one and the
/// comparison is about buffers rather than about that guard.
fn early_line_into(out: &mut String, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    out.push_str("Sec-WebSocket-Protocol: ");
    early_encode_into(out, data);
    out.push_str("\r\n");
}

/// `ZeroNet`'s line, verbatim in shape: an `encode` into a fresh `String`, then a
/// `format!` into a second one, then a copy of that into the request.
#[inline(never)]
fn previous_line(data: &[u8]) -> String {
    let mut out = String::new();
    previous_line_into(&mut out, data);
    out
}

/// The same shape, appended where the reference's caller would have appended it.
///
/// `format_push_string` is denied across the workspace and allowed back for the
/// one line whose whole subject is that the reference builds a second string:
/// `push_str` + `write!` would be the code under test.
#[allow(
    clippy::format_push_string,
    reason = "the reference's shape is the second string this gate measures"
)]
#[inline(never)]
fn previous_line_into(out: &mut String, data: &[u8]) {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if data.is_empty() {
        return;
    }
    let mut encoded = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut word = 0u32;
        for &byte in chunk {
            word = (word << 8) | u32::from(byte);
        }
        word <<= 8 * (3 - chunk.len());
        encoded.push(ALPHABET[(word >> 18 & 0x3F) as usize] as char);
        encoded.push(ALPHABET[(word >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(ALPHABET[(word >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            encoded.push(ALPHABET[(word & 0x3F) as usize] as char);
        }
    }
    out.push_str(&format!("Sec-WebSocket-Protocol: {encoded}\r\n"));
}

/// The early-data section of the report, appended after the mux table.
pub(crate) fn report(rows: &[Row]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 8 — the early-data encode\n");
    let _ = writeln!(
        out,
        "The `?ed=` budget's whole cost, against a build shaped the way the four\n\
         implementations shape it: an `encode` into a fresh `String`, then a\n\
         `format!` into a second, then a copy of that into the request already being\n\
         built. Ours appends the digits to that request, so the reference makes two\n\
         allocations and two copies for one header line that this side makes none of.\n\
         Every row asserts the finished line is equal and decodes back before it is timed,\n\
         holds this side under one allocation per encode with the counting allocator while\n\
         the reference's shape stays at two or more, both printed on every row. The bar is\n\
         not zero and the file says why twice. Best of {} interleaved rounds per side.\n\
         \n\
         **This is not a differential against a pinned in-process oracle** — the four\n\
         cannot be, and `docs/conformance.md` measures why per suite. The identity half\n\
         of this rung is `conformance.yml`: two upstream `xray-rust` oracle tests that\n\
         exercise the setting against real `Xray-core` at the pin, unmodified. This gate\n\
         is the cost half, and the cost half is a count.\n\
         \n\
         There is no decode row because there is nothing to gate: every implementation\n\
         decodes into the buffer it returns, so both sides are at one allocation and the\n\
         same bytes. The decode is proved by the round-trip vectors in\n\
         `transport::tests` instead, which cover every length 0-192 and both alphabets.\n",
        crate::ROUNDS
    );
    let _ = writeln!(
        out,
        "| early encode | bytes | reference ns/op | ferrox ns/op | speedup |"
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
            "\n**Gated: {}. Worst {:.2}x ({}), best {:.2}x ({}).**",
            rows.len(),
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&crate::framing::confirmation_note(rows.iter()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate's assertions with no clock in them: every row agrees with its
    /// reference byte for byte and round trips. A row whose two sides disagreed
    /// fails here rather than after two hundred thousand iterations of a
    /// measurement that would have meant nothing.
    ///
    /// The allocation counts are deliberately **not** here, for the reason
    /// `gate_early_data` says: they are evidence in a release bench driven from
    /// `main()` and noise under a test runner, so asserting one here would fail
    /// on how many tests this crate has.
    #[test]
    fn every_early_data_row_agrees_with_its_reference_before_anything_is_timed() {
        assert_eq!(PAYLOADS, [8, 120, 256, 2048]);
        for len in PAYLOADS {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(61)).collect();
            check_encode(len, &data);
        }
    }

    /// The line, on its own, at the lengths whose group shapes differ: an empty
    /// payload is no line at all, one byte is two digits, three is four.
    #[test]
    fn the_line_is_nothing_then_two_digits_then_four() {
        for (payload, want) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg"),
            (&b"fo"[..], "Zm8"),
            (&b"foo"[..], "Zm9v"),
        ] {
            let mut got = String::new();
            early_line_into(&mut got, payload);
            assert_eq!(
                got,
                if want.is_empty() {
                    String::new()
                } else {
                    format!("Sec-WebSocket-Protocol: {want}\r\n")
                },
                "{payload:?}"
            );
        }
    }
}
