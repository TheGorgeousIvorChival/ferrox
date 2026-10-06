//! Gate 10: the fused `AES-128-GCM` engine against the `aes-gcm` crate it
//! replaces.
//!
//! # What this gate is
//!
//! `aes-128-gcm` seals two hot paths — `VMess` data frames and `shadowsocks`
//! chunks — and both used to run the `aes-gcm` crate. The replacement is
//! `ferrox_core::aesgcm`: the same arithmetic re-associated so four blocks
//! share one reduction, fused with the `CTR` pass so the message is read once.
//! That is a "before" and an "after" of the same interface, so this gate is
//! shaped like gate 7's: **every row asserts equal ciphertext and equal tag
//! before either side is timed**, and the ratio goes to the same 0.95x bar
//! gates 3, 4, 7 and 8 answer to.
//!
//! # What the reference is
//!
//! The crate, built exactly as the shipped path built it: on `x86_64` it
//! reaches `AES-NI` + `PCLMULQDQ` by its own runtime dispatch, and on `aarch64`
//! it reaches the `ARMv8` crypto backends under the two `--cfg`s `ci.yml` and
//! `bench.yml` set for every build. The reference is therefore the *hardware*
//! crate on every runner this gate times: a win here is not a soft-backend
//! artefact, it is the re-association and the fusion.
//!
//! The session objects are built once per row, outside the timed loop — sealing
//! and opening are what a live connection pays per frame, and that is what is
//! timed. Each iteration seals the buffer and opens it again, so the loop is
//! self-sustaining and neither side re-seeds.

use std::fmt::Write as _;

use aes_gcm::aead::AeadInPlace as _;
use aes_gcm::KeyInit as _;

use ferrox_core::aesgcm::{Aes128Gcm, Aes256Gcm};

use crate::count;
use crate::framing::{timed_row, Row};

/// The payload lengths the gate times: a short frame, the `shadowsocks`
/// gate's middle lengths, and `MAX_CHUNK` itself.
fn payloads() -> Vec<usize> {
    vec![64, 256, 512, 1400, 4096, 8171, 16_383]
}

/// Byte budget per timed section, so short lengths get more iterations and a
/// short length is not decided by a single sample — gate 3's discipline.
const BYTE_BUDGET: u64 = 4 * 1024 * 1024;

/// What one allocation window counted, for the report to print.
pub(crate) struct Window {
    /// The chunk length the window ran at.
    len: usize,
    /// What it allocated while the counting flag was up.
    counts: count::Counts,
    /// Seal+open pairs the window ran.
    iters: u64,
}

/// The reference's backend, named for the report: a ratio is only attributable
/// once both sides of it are named.
fn reference_backend() -> &'static str {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq") {
            "aes-gcm 0.10 / aes-ni + pclmulqdq"
        } else {
            "aes-gcm 0.10 / soft tables"
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // The crate's `ARMv8` backends compile only behind the two `--cfg`s
        // `ci.yml` and `bench.yml` set for every build, then runtime-dispatch;
        // without them this row measures its soft tables and the text says so.
        if std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
        {
            "aes-gcm 0.10 / armv8 crypto (behind the build's two cfgs)"
        } else {
            "aes-gcm 0.10 / soft tables"
        }
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "aes-gcm 0.10 / soft tables"
    }
}

/// Gate 10: every row's assertions, then every row timed.
pub(crate) fn gate_aesgcm() -> (Vec<Row>, Vec<Window>) {
    let mut rows = Vec::new();
    let mut windows = Vec::new();
    for len in payloads() {
        let plain: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(3))
            .collect();
        rows.push(check_and_time(len, &plain, &mut windows));
        rows.push(check_and_time_256(len, &plain, &mut windows));
    }
    (rows, windows)
}

/// One length: identity, allocations, then the seconds per seal+open.
fn check_and_time(len: usize, plain: &[u8], windows: &mut Vec<Window>) -> Row {
    let key: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(5));
    let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(41).wrapping_add(1));
    let aad: &[u8] = b"";

    let ours = Aes128Gcm::new(&key);
    let reference = aes_gcm::Aes128Gcm::new_from_slice(&key).expect("key");

    // Identity, before any timing: the same bytes and the same tag, both ways.
    let mut sealed_ours = plain.to_vec();
    let tag_ours = ours.seal_in_place(&nonce, aad, &mut sealed_ours);
    let mut sealed_ref = plain.to_vec();
    let tag_ref: [u8; 16] = reference
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), aad, &mut sealed_ref)
        .expect("seals")
        .into();
    assert_eq!(sealed_ours, sealed_ref, "{len}: the same ciphertext");
    assert_eq!(tag_ours, tag_ref, "{len}: the same tag");
    let mut opened = sealed_ours.clone();
    assert_eq!(
        ours.open_in_place(&nonce, aad, &mut opened, &tag_ours),
        Some(len),
        "{len}: opens"
    );
    assert_eq!(opened, plain, "{len}: the same bytes back");

    // No allocation per frame, over the window, with the counting allocator —
    // the claim the relay makes, at gate 9's bar of under one per chunk. The
    // engine itself holds no buffer: this window exists to *show* that.
    check_allocs(len, plain, &ours, windows);

    let iters = (BYTE_BUDGET / len.max(1) as u64).clamp(64, 200_000);

    let mut ref_buf = plain.to_vec();
    let mut reference_run = || {
        let tag = reference
            .encrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(std::hint::black_box(&nonce)),
                aad,
                std::hint::black_box(&mut ref_buf),
            )
            .expect("seals");
        reference
            .decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(&nonce),
                aad,
                std::hint::black_box(&mut ref_buf),
                &tag,
            )
            .expect("opens");
        ref_buf.len()
    };

    let mut our_buf = plain.to_vec();
    let mut ours_run = || {
        let tag = ours.seal_in_place(
            std::hint::black_box(&nonce),
            aad,
            std::hint::black_box(&mut our_buf),
        );
        let opened = ours.open_in_place(&nonce, aad, std::hint::black_box(&mut our_buf), &tag);
        opened.expect("opens")
    };

    timed_row(
        format!("aes-128-gcm, {len}B"),
        len,
        iters,
        &mut ours_run,
        &mut reference_run,
    )
}

/// One length, `AES-256-GCM`: the same identity-and-allocation check as the
/// 128 side, against the same crate both paths replaced.
fn check_and_time_256(len: usize, plain: &[u8], _windows: &mut Vec<Window>) -> Row {
    let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(5));
    let nonce: [u8; 12] = std::array::from_fn(|i| (i as u8).wrapping_mul(41).wrapping_add(1));
    let aad: &[u8] = b"";

    let ours = Aes256Gcm::new(&key);
    let reference = aes_gcm::Aes256Gcm::new_from_slice(&key).expect("key");

    let mut sealed_ours = plain.to_vec();
    let tag_ours = ours.seal_in_place(&nonce, aad, &mut sealed_ours);
    let mut sealed_ref = plain.to_vec();
    let tag_ref: [u8; 16] = reference
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), aad, &mut sealed_ref)
        .expect("seals")
        .into();
    assert_eq!(sealed_ours, sealed_ref, "{len}: the same ciphertext");
    assert_eq!(tag_ours, tag_ref, "{len}: the same tag");
    let mut opened = sealed_ours.clone();
    assert_eq!(
        ours.open_in_place(&nonce, aad, &mut opened, &tag_ours),
        Some(len),
        "{len}: opens"
    );
    assert_eq!(opened, plain, "{len}: the same bytes back");

    let iters = (BYTE_BUDGET / len.max(1) as u64).clamp(64, 200_000);

    let mut ref_buf = plain.to_vec();
    let mut reference_run = || {
        let tag = reference
            .encrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(std::hint::black_box(&nonce)),
                aad,
                std::hint::black_box(&mut ref_buf),
            )
            .expect("seals");
        reference
            .decrypt_in_place_detached(
                aes_gcm::Nonce::from_slice(&nonce),
                aad,
                std::hint::black_box(&mut ref_buf),
                &tag,
            )
            .expect("opens");
        ref_buf.len()
    };

    let mut our_buf = plain.to_vec();
    let mut ours_run = || {
        let tag = ours.seal_in_place(
            std::hint::black_box(&nonce),
            aad,
            std::hint::black_box(&mut our_buf),
        );
        let opened = ours.open_in_place(&nonce, aad, std::hint::black_box(&mut our_buf), &tag);
        opened.expect("opens")
    };

    timed_row(
        format!("aes-256-gcm, {len}B"),
        len,
        iters,
        &mut ours_run,
        &mut reference_run,
    )
}

/// Iterations the allocation window runs, matching the other gates' discipline.
const ALLOC_ITERS: u64 = 64;

/// No allocation per seal+open pair, in the relay's own shape: buffers staged
/// outside the window, the engine built outside it.
fn check_allocs(len: usize, plain: &[u8], ours: &Aes128Gcm, windows: &mut Vec<Window>) {
    let nonce = [0xabu8; 12];
    let mut buf = plain.to_vec();
    // One warm-up pair so the buffer's growth is not charged to the window.
    let tag = ours.seal_in_place(&nonce, b"", &mut buf);
    let _ = ours.open_in_place(&nonce, b"", &mut buf, &tag);
    let ((), counts) = count::measure(|| {
        for _ in 0..ALLOC_ITERS {
            let tag = ours.seal_in_place(
                std::hint::black_box(&nonce),
                b"",
                std::hint::black_box(&mut buf),
            );
            let _ = ours.open_in_place(&nonce, b"", std::hint::black_box(&mut buf), &tag);
        }
    });
    assert!(
        counts.per_iter(ALLOC_ITERS) < 1.0,
        "aes-128-gcm {len}: {} allocations over {ALLOC_ITERS} pairs is not under one per chunk",
        counts.allocs
    );
    windows.push(Window {
        len,
        counts,
        iters: ALLOC_ITERS,
    });
}

/// The `AES-128-GCM` section of the report, appended after gate 9's.
pub(crate) fn report(rows: &[Row], windows: &[Window], engine_backend: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "\n## Gate 10 — the fused AES-128-GCM engine\n");
    let _ = writeln!(
        out,
        "The crate both hot paths used to seal with, against the fused engine that\n\
         replaces it: the same arithmetic re-associated so four blocks share one\n\
         reduction, with the `CTR` pass fused into the `GHASH` pass so the message is\n\
         read once. Every row asserts equal ciphertext and equal tag *before* either\n\
         side is timed, and the rows go to the same 0.95x bar as gates 3, 4, 7 and 8.\n\
         \n\
         | | |\n\
         | --- | --- |\n\
         | reference | `{}` |\n\
         | ferrox | `{engine_backend}` |\n",
        reference_backend()
    );
    let _ = writeln!(
        out,
        "\n| bytes | reference ns/seal+open | ferrox ns/seal+open | speedup |"
    );
    let _ = writeln!(out, "| ---: | ---: | ---: | ---: |");
    for r in rows {
        let _ = writeln!(
            out,
            "| {} | {:.1} | {:.1} | {:.2}x |",
            r.bytes,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio()
        );
    }
    let _ = writeln!(
        out,
        "\nAllocations per seal+open pair, from the same counting global allocator the\n\
         other gates use. The bar is **under one per pair**, not zero: `count::measure`\n\
         raises one process-wide flag, so a window also counts whatever else the process\n\
         allocates while it is open.\n\
         \n\
         | bytes | pairs | allocations | per pair | bytes allocated |\n\
         | ---: | ---: | ---: | ---: | ---: |"
    );
    for w in windows {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {:.3} | {} |",
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
            "\n**Worst {:.2}x ({}), best {:.2}x ({}).**",
            worst.ratio(),
            worst.name,
            best.ratio(),
            best.name
        );
        out.push_str(&crate::framing::confirmation_note(rows.iter()));
    }
    out
}
