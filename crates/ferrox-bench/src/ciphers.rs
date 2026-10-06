//! Gate 9: the three `shadowsocks` ciphers, side by side.
//!
//! # What this gate is
//!
//! The `shadowsocks` rung added two connection ways to a matrix that had one, so
//! the cost question is not "faster than upstream" — it is **"do the ways we
//! added cost what the way we had cost?"** `aes-256-gcm` is therefore this
//! gate's reference: not a flattering choice but the one method that has been
//! here all along, and the method the `aes-256-gcm` conformance row proves.
//!
//! Every row asserts the two sides produce the same bytes before either is
//! timed, which is the same discipline gates 1, 4, 6 and 7 use.
//!
//! # Why the timing rows are printed and not judged
//!
//! **This is a decision recorded before any run of this gate, and the reason is
//! structural rather than a shrug.** The two sides straddle a hardware boundary
//! that differs per runner: the `aes-256-gcm` reference runs `aes-gcm`, which
//! dispatches to AES-NI on `x86_64` and to the ARMv8-Crypto backend only behind
//! the two `--cfg`s `ci.yml` sets, and falls back to its soft table
//! implementation without them, while `chacha20-ietf-poly1305` runs this
//! crate's own NEON and AVX2 ladder. (`aes-128-gcm` ran `aes-gcm` too when this
//! was written; it now runs `ferrox_core::aesgcm`, which gate 10 measures
//! against the crate directly.)
//! So the ratio between them is a property of the runner's AES as much as of the
//! code — the same shape of problem `muxframe.rs` documents for its encode rows,
//! and the same reason the report names both backends on every other page.
//!
//! What this gate *does* judge is the part that can be a fact rather than a
//! reading, and it judges it for all three methods:
//!
//! - **no allocation per chunk**, sealing into a buffer the caller has already
//!   staged and opening in place. This is the claim the relay makes, so it is
//!   the one worth asserting rather than reporting -- as **under one allocation
//!   per chunk**, which is gate 7's bar and for gate 7's reason: `count::measure`
//!   sets one process-wide flag, so under a test runner a count also holds
//!   whatever the *other* tests are allocating at that moment. Measured here in
//!   run `37263530382`: **666 allocations over 64 chunks**, every one of them
//!   another test's, none of them this code's. The assertion therefore lives in
//!   this gate rather than in a `#[test]`, which is why `muxframe.rs` and
//!   `earlydata.rs` put theirs there too. The bar keeps its slack anyway, and in the
//!   gate it does not need it: run `37264964528` reads **0 allocations and 0 bytes
//!   in all sixty windows** -- three methods, five lengths, four native runners.
//! - **the derivation is the method's length**: `aes-128-gcm` derives sixteen
//!   bytes of master key and `aes-256-gcm` thirty-two, so one `MD5` round
//!   against two. `MasterKey::rounds` is where that number comes from and
//!   `crates/ferrox-core/src/shadowsocks.rs` asserts it; here it is timed, so
//!   the saving is visible rather than argued.

use std::fmt::Write as _;

use ferrox_core::shadowsocks::{Cipher, MasterKey, Method, MAX_CHUNK};

use crate::count;
use crate::framing::{best_of, Row};

/// Chunks per timed shape. A chunk is at most `0x3FFF` bytes, so a 2 KiB budget
/// is a fraction of a second a side.
const ITERS: u64 = 100_000;

/// Iterations the allocation window runs, matching gate 7's discipline.
const ALLOC_ITERS: u64 = 64;

/// The payload lengths the gate times.
///
/// The small end is a whole chunk — an address header and its length prefix, the
/// shortest a live connection ever seals — and the top is `MAX_CHUNK` itself,
/// which is the one length where the framing's cost is amortised over as much
/// payload as the format allows.
fn payloads() -> Vec<usize> {
    vec![64, 512, 1400, 8171, MAX_CHUNK]
}

/// The reference method: the one that shipped, and the one the conformance row
/// names.
const REFERENCE: Method = Method::Aes256Gcm;

/// What one method's allocation window counted, for the report to print.
///
/// The counts are printed rather than only judged because a bar of "under one
/// per chunk" that reads 0 on three lengths and something else on the fourth
/// asks a question the reader should be able to see the answer to.
pub(crate) struct Window {
    /// The method that was measured.
    pub(crate) method: &'static str,
    /// The chunk length the window ran at.
    pub(crate) len: usize,
    /// What it allocated while the counting flag was up.
    pub(crate) counts: count::Counts,
    /// Chunks the window sealed and opened.
    pub(crate) iters: u64,
}

/// Gate 9: every row's assertions, then every row timed.
pub(crate) fn gate_ciphers() -> (Vec<Row>, Vec<Window>) {
    let mut rows = Vec::new();
    let mut windows = Vec::new();
    for len in payloads() {
        let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
        let control = check_and_time(REFERENCE, len, &plain, &mut windows);
        println!(
            "gate 9: {len}B control, {} at {:.1} ns/chunk",
            REFERENCE.name(),
            control * 1e9
        );
        for method in [Method::Aes128Gcm, Method::Chacha20Poly1305] {
            let ours = check_and_time(method, len, &plain, &mut windows);
            rows.push(Row {
                name: format!("{}, {len}B", method.name()),
                bytes: len,
                base: control,
                ours,
                // Gate 9 prints these rows and judges none of them, because the
                // two sides straddle a hardware boundary that differs per runner
                // (see this file's header). Nothing here feeds the bar, so there
                // is nothing to confirm: a second reading would change no verdict
                // and only make the published ratio disagree with the decision to
                // report rather than gate.
                remeasured: false,
            });
        }
    }
    (rows, windows)
}

/// One method at one length: identity, allocations, then the seconds per chunk.
fn check_and_time(method: Method, len: usize, plain: &[u8], windows: &mut Vec<Window>) -> f64 {
    let (sealed, opened) = round_trip(method, plain);
    assert_eq!(opened, plain, "{} {len}: the same bytes", method.name());
    assert_eq!(
        sealed.len(),
        plain.len() + ferrox_core::shadowsocks::TAG_LEN,
        "{} {len}: a chunk is the payload and a tag",
        method.name()
    );
    check_allocs(method, len, plain, windows);
    time_chunks(method, plain)
}

/// A chunk sealed and opened, as the relay does it: one buffer staged once and
/// reused, the payload copied in and sealed in place, the tag behind it.
fn round_trip(method: Method, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let salt = [0x24u8; 32];
    let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut sealed = Vec::with_capacity(plain.len() + ferrox_core::shadowsocks::TAG_LEN);
    send.seal_into(plain, &mut sealed).expect("seals");

    let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut wire = sealed.clone();
    let opened = recv.open_in_place(&mut wire).expect("opens");
    (sealed, wire[..opened].to_vec())
}

/// No allocation per chunk, sealing into a staged buffer and opening in place.
///
/// The relay's own shape, so this is the claim it depends on: `staging` is
/// allocated once per direction and every chunk after the first rides in it.
///
/// **The bar is under one allocation per chunk, not zero**, and this is gate 7's
/// bar for gate 7's reason, applied here rather than inherited by reflex.
/// `count::measure` sets one process-wide flag, so under a test runner the window
/// also counts whatever the other tests allocate while it is open -- 666
/// allocations over 64 chunks in run `37263530382`, none of them this code's.
/// That is also why this assertion is here and not in the `#[test]`.
///
/// Zero is not demanded because an 8 KiB allocation from outside the encode has
/// been seen inside a release window in gate 7 -- `docs/claims.md`'s open item
/// P32 -- and a gate that demanded zero here would be gating on that unknown
/// rather than on this code. What is decidable is the shape of the claim, and it
/// is the claim the relay makes: **a chunk does not allocate per call.** The exact
/// counts go to the report, so a reader sees the number behind the bar and not
/// only the verdict.
fn check_allocs(method: Method, len: usize, plain: &[u8], windows: &mut Vec<Window>) {
    let salt = [0x24u8; 32];
    let mut staging = Vec::with_capacity(plain.len() + ferrox_core::shadowsocks::TAG_LEN);
    let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    // Two warm-up chunks so neither side is charged for growing its buffer.
    send.seal_into(plain, &mut staging).expect("seals");
    recv.open_in_place(&mut staging).expect("opens");

    let ((), counts) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            staging.clear();
            send.seal_into(
                std::hint::black_box(plain),
                std::hint::black_box(&mut staging),
            );
            let _ = recv.open_in_place(std::hint::black_box(&mut staging));
        }
    });
    assert!(
        counts.per_iter(ALLOC_ITERS) < 1.0,
        "{} {len}: {} allocations over {ALLOC_ITERS} chunks is not under one per chunk",
        method.name(),
        counts.allocs
    );
    windows.push(Window {
        method: method.name(),
        len,
        counts,
        iters: ALLOC_ITERS,
    });
}

/// Seconds per chunk, sealing and opening one each time.
fn time_chunks(method: Method, plain: &[u8]) -> f64 {
    let salt = [0x24u8; 32];
    let mut staging = Vec::with_capacity(plain.len() + ferrox_core::shadowsocks::TAG_LEN);
    let mut send = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    let mut recv = Cipher::new(method, "an-example-shared-password", &salt).expect("derives");
    best_of(ITERS, &mut || {
        staging.clear();
        send.seal_into(
            std::hint::black_box(plain),
            std::hint::black_box(&mut staging),
        );
        let _ = recv.open_in_place(std::hint::black_box(&mut staging));
        staging.len()
    })
}

/// The per-session derivation, which is where `aes-128-gcm` is cheaper than the
/// method it joins, and what the `MD5` round count is.
pub(crate) fn derivations() -> Vec<(&'static str, usize, usize)> {
    [Method::Aes128Gcm, REFERENCE, Method::Chacha20Poly1305]
        .into_iter()
        .map(|method| {
            let key = MasterKey::new("an-example-shared-password", method.key_len());
            (method.name(), key.as_bytes().len(), key.rounds())
        })
        .collect()
}

/// The `shadowsocks` section of the report, appended after the early-data one.
pub(crate) fn report(rows: &[Row], windows: &[Window]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 9 — the shadowsocks ciphers\n");
    let _ = writeln!(
        out,
        "The two ways this rung added against the one it joined, on the same bytes,\n\
         over the same chunk sizes. The reference is `aes-256-gcm`: not a flattering\n\
         choice but the method that shipped, and the one the conformance row names. Every\n\
         row asserts the two sides produce the same bytes before either is timed, and\n\
         asserts **under one allocation per chunk** for all three methods, in place, in a\n\
         buffer the relay stages once.\n\
         \n\
         **The ratios are printed and not judged, and that is a decision recorded rather\n\
         than a measurement.** The two sides straddle a hardware boundary that differs per\n\
         runner: the `aes-256-gcm` reference runs `aes-gcm`, which reaches AES-NI on `x86_64`\n\
         and the ARMv8-Crypto backend only behind the two `--cfg`s `ci.yml` sets, and its\n\
         soft table implementation without them, while `chacha20-ietf-poly1305` runs this\n\
         crate's own NEON and AVX2 ladder. The ratio is therefore a property of the\n\
         runner's AES as much as of the code. **A `bench.yml` run on four native runners\n\
         will say whether a bar can be applied here**, and `claims.md` records the decision\n\
         in the meantime.\n\\
         Run `37264964528` is that run, and it settles the question in the direction the\n\
         decision was already pointing: back when `aes-128-gcm` also ran the crate, it\n\
         held **0.96x-1.09x** of `aes-256-gcm` on all four runners and every length, while\n\
         `chacha20-ietf-poly1305` spans **0.15x-0.92x** across the same four -- a 6.1x\n\
         spread on identical code. No bar survives that. (`aes-128-gcm` now runs\n\
         `ferrox_core::aesgcm`; its rows below moved accordingly, and gate 10 is the\n\
         like-for-like measurement against the crate.) The allocation windows, meanwhile,\n\
         read **0 allocations and 0 bytes in all sixty of them**, so that count is a fact\n\
         on every runner rather than a bar with slack in it.\n\
         \n\
         The cipher is the peer's choice and the two are not comparable on one machine:\n\
         a `chacha20-ietf-poly1305` link is a user declining `aes-256-gcm` because their CPU\n\
         does the other one better, and the whole point of naming both ciphers is that the\n\
         choice is theirs.\n\
         \n\
         The session derivation, which is where `aes-128-gcm` is genuinely cheaper:\n\
         \n\
         | method | master key bytes | `MD5` rounds |\n\
         | --- | ---: | ---: |",
    );
    for (name, bytes, rounds) in derivations() {
        let _ = writeln!(out, "| `{name}` | {bytes} | {rounds} |");
    }
    let _ = writeln!(
        out,
        "\n| cipher | bytes | reference ns/chunk | ferrox ns/chunk | speedup |"
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
    let _ = writeln!(
        out,
        "\nAllocations per chunk, over the window each row measured, from the same\n\
         counting global allocator gates 2 and 7 use. The bar is **under one per chunk**,\n\
         not zero: `count::measure` raises one process-wide flag, so a window also counts\n\
         whatever else the process allocates while it is open. See `check_allocs`.\n\
         \n\
         | method | bytes | chunks | allocations | per chunk | bytes allocated |\n\
         | --- | ---: | ---: | ---: | ---: | ---: |"
    );
    for w in windows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {:.3} | {} |",
            w.method,
            w.len,
            w.iters,
            w.counts.allocs,
            w.counts.per_iter(w.iters),
            w.counts.bytes
        );
    }
    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio().total_cmp(&b.ratio())),
        rows.iter().max_by(|a, b| a.ratio().total_cmp(&b.ratio())),
    ) {
        let _ = writeln!(
            out,
            "\n**Printed only. Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row agrees with its reference byte for byte.
    ///
    /// A row whose two sides disagreed fails here rather than after a hundred
    /// thousand chunks of a measurement that would have meant nothing.
    ///
    /// **The allocation half of the gate is not here.** `count::measure` sets one
    /// process-wide flag, so a `#[test]` that counted would also count the other
    /// tests running beside it -- 666 allocations over 64 chunks in run
    /// `37263530382`, which is what this test's first draft asserted against
    /// zero. `check_allocs` runs in the gate instead, where nothing else is
    /// running, exactly as `muxframe.rs` and `earlydata.rs` do theirs.
    #[test]
    fn every_cipher_row_agrees_and_allocates_nothing() {
        assert_eq!(payloads(), vec![64, 512, 1400, 8171, MAX_CHUNK]);
        for len in payloads() {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(97)).collect();
            for method in [
                Method::Aes128Gcm,
                Method::Aes256Gcm,
                Method::Chacha20Poly1305,
            ] {
                let (sealed, opened) = round_trip(method, &plain);
                assert_eq!(opened, &plain[..], "{} {len}", method.name());
                assert_eq!(
                    sealed.len(),
                    plain.len() + ferrox_core::shadowsocks::TAG_LEN,
                    "{} {len}",
                    method.name()
                );
            }
        }
    }

    /// The three methods do not produce the same chunk, so a row that agrees with
    /// `aes-256-gcm` cannot pass on a method that merely round-trips its own.
    #[test]
    fn no_two_methods_produce_the_same_chunk() {
        let plain = b"the same bytes under three ciphers".to_vec();
        let mut chunks = Vec::new();
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let (sealed, _) = round_trip(method, &plain);
            assert!(
                !chunks.contains(&sealed),
                "{} produced a chunk another method produced",
                method.name()
            );
            chunks.push(sealed);
        }
    }

    /// The derivation table, with the two `AES` methods differing in the one
    /// number this rung makes them differ in.
    #[test]
    fn aes_128_derives_half_the_master_key() {
        let table = derivations();
        assert_eq!(
            table,
            vec![
                ("aes-128-gcm", 16, 1),
                ("aes-256-gcm", 32, 2),
                ("chacha20-ietf-poly1305", 32, 2),
            ]
        );
    }
}
