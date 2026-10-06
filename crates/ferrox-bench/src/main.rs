//! Proves the shipped core is bit-identical to the reference and not slower.
//!
//! The record-layer gates, in this order, and the order is the point:
//!
//! 1. **Identity, before any timing.** Every length and every block offset is
//!    compared byte for byte against the reference. A wrong core never gets to
//!    be a fast one, because this panics first.
//! 2. **Deterministic properties, which are facts.** Blocks generated equals
//!    blocks needed; zero heap allocations; zero zero-fills. These are integer
//!    counts, identical on every machine, so they are gated outright.
//! 3. **Timing, which is a distribution.** The bar is 0.95x at any single timed
//!    length: 5% under is runner noise on shared runners. A length under the
//!    bar is re-measured at four times the budget before the job fails,
//!    because a shared runner is noisy enough that a gate which cries wolf
//!    gets switched off, and a gate that only fails on a number it has taken
//!    repeatedly does not.
//!
//! Gates 4, 6, 7 and 8 apply the same three steps to the framings — the `VLESS`
//! request header and the `ChaCha20`-`Poly1305` seal in `framing.rs`, the mux frame
//! codec in `muxframe.rs`, the early-data encode in `earlydata.rs` — each against a
//! reference built to the shape of the code it replaces, and each sharing gate 3's
//! bar and its failure message. None has a pinned *in-process* oracle to differ
//! against, and each says so in its own header rather than letting a ratio in the
//! report imply one; the early-data rung's identity half is `conformance.yml`
//! instead, which runs two upstream oracle tests against real `Xray-core`.
//!
//! Gate 5 is the process-level comparison against built comparators; it is last
//! because it is the only one that needs binaries rather than this workspace.
//!
//! The reference's own backend is named in the report. It matters: on aarch64
//! the `chacha20` crate falls back to a scalar one-block-at-a-time core, so a
//! comparison that did not say so would credit that gap to this workspace.

// A duration divided by an iteration count is a nanoseconds-per-call figure,
// which is what this binary exists to report; the conversion to `f64` is the
// point rather than an accident of the arithmetic. See `count.rs` for the same
// reasoning applied to the integer counts.
#![allow(clippy::cast_precision_loss)]

mod aesgcm;
mod ciphers;
mod compare;
mod compare_process;
mod count;
mod earlydata;
mod framing;
mod json;
mod linkconfig;
mod methods;
mod muxframe;
mod parity;
mod ps;
mod stats;

use count::Counting;
use std::fmt::Write as _;

/// Dense, not exhaustive: every byte 0..=256, then M-1/M/M+1 for each listed multiple.
///
/// Below 257 the claim is every length, so every block-count change there is tested at every byte.
/// Above 256 the claim is one length either side of each listed multiple, not every multiple in range.
/// Rung steps are every 64 B, with groups at 256 B (portable/NEON, 4 blocks) and 512 B (AVX2, 8 blocks).
/// Listed multiples are tail examples 320/384/448/576/640 and group steps 512/768/1024/1536/2048/4096/8192/16384/65536.
/// Unlisted multiples (704, 896, 1088, 2560, ...) are not covered; exhaustive 0..=65536 would be 786444 shapes, which gate 3 cannot afford.
/// Offsets 0/1/2/7/64/65535 are a selection (0 is every caller, the rest are resume paths), checked by gate 1, not a proof over u32.
fn lengths() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=256).collect();
    v.extend([
        257, 319, 320, 321, 383, 384, 385, 447, 448, 449, 511, 512, 513, 575, 576, 577, 639, 640,
        641, 767, 768, 769, 1023, 1024, 1025, 1535, 1536, 1537, 2047, 2048, 2049, 4095, 4096, 4097,
        8191, 8192, 8193, 16383, 16384, 16385, 65535, 65536, 65537,
    ]);
    v.sort_unstable();
    v.dedup();
    v
}

/// The bar. 0.95 means "no worse than 5% under the reference at any single
/// timed length". Five percent is runner noise on shared runners, not signal:
/// single lengths at 0.97-0.99x came back green on a plain rerun with no code
/// change, one full bench cycle later.
///
/// Runners are still noisy underneath, so the measurement stays robust instead
/// of the bar going lenient beyond this — best of 5 interleaved rounds per side
/// (the same five-run discipline the comparators publish), and anything under
/// the bar is re-measured at 4x the budget to confirm before it fails. A length
/// confirmed under 0.95x is a regression, not noise, and the job goes red.
const BAR: f64 = 0.95;

/// Rounds per side per length before the best is kept.
///
/// Five, like the five-run medians behind every published comparator chart: the
/// bar is strict, so the samples behind it are not thin.
const ROUNDS: usize = 5;

/// Independent passes a length under the bar is confirmed with.
///
/// Three, because one is not a confirmation and two cannot tell a tie from a
/// majority. Each pass re-times both sides from scratch at four times the budget,
/// so a pass that repeats a disturbance is a coincidence rather than a rule.
const CONFIRMATIONS: usize = 3;

/// Three is the floor, and it is a compile-time fact rather than a test that could
/// be deleted with the code it guards: two passes cannot tell a tie from a
/// majority, so with two the median is whichever of two samples happens to sort
/// second, which is the sample the rule exists to distrust.
const _: () = assert!(CONFIRMATIONS >= 3);

/// The confirmed pass for a length under the bar: the median, by ratio.
///
/// Separate from [`measure_len`] so the rule can be tested without a clock. A
/// median and not a minimum, because a minimum is the statistic that rewards the
/// disturbed pass, and not the single pass, because that is what brought
/// `0.84x` and `0.848x` here in the first place. A real regression is under the bar
/// in all of them.
///
/// The *pair*, not just the quotient: a row's published numbers are its two
/// absolute times, and a caller that gates on one reading and prints another is
/// reporting something it did not decide on. Gate 3 and every framing gate share
/// this, so the bar has exactly one definition of "confirmed".
fn confirmed_pass(passes: &[(f64, f64)]) -> (f64, f64) {
    let mut by_ratio = passes.to_vec();
    by_ratio.sort_by(|a, b| (a.0 / a.1).total_cmp(&(b.0 / b.1)));
    by_ratio[by_ratio.len() / 2]
}

/// First length the timing gate measures.
///
/// Lengths 1-64 are one 64-byte block, where both sides run the same twenty
/// rounds over the same state: a tie by construction that a 1.00x bar cannot
/// certify. They stay in `lengths()` so identity still covers them byte for
/// byte, but timing starts here.
const TIMING_MIN: usize = 65;

/// Byte budget per length per round, so short lengths get more iterations and a
/// short length is not decided by a single sample.
const BYTE_BUDGET: u64 = 4 * 1024 * 1024;

fn iters_for(n: usize) -> u64 {
    (BYTE_BUDGET / n.max(1) as u64).clamp(64, 200_000)
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// CLI args: `--reference <name>`, `--config <vless://...>`, and the gate-5
/// comparison flags.
///
/// `--config` hands CI a working link and gets the comparison table for it.
/// The link itself never reaches the report (see `compare.rs`): only the
/// redacted transport description does, so a secret pasted into a dispatch
/// input cannot leak through the summary.
///
/// `--engine <label>=<path>` adds one engine to the process-level comparison,
/// repeatable; the first is the reference every other is measured against.
/// `--repeats`, `--connections`, `--payload-size`, `--iterations` and
/// `--traffic` set the workload. `--outbound-config` replaces the default
/// `freedom` outbound with the JSON document the scenario names, so one binary
/// runs every matrix cell; `--output-dir` isolates a cell's artefacts so cells
/// can share a checkout. Gate 5 runs only when at least two engines are
/// named, so the default invocation is unchanged and gates 1-4 run exactly as
/// before.
struct Args {
    declared: String,
    config: Option<String>,
    engines: Vec<(String, String)>,
    /// Per-engine config-argument shape, as `label=shape`.
    config_shapes: Vec<(String, String)>,
    /// Per-engine config dialect, as `label=dialect`.
    dialects: Vec<(String, String)>,
    repeats: usize,
    connections: usize,
    payload_size: usize,
    iterations: usize,
    traffic: String,
    outbound_config: String,
    output_dir: String,
    /// Write [`compare_process::Comparison::comparison_json`] here when set, so
    /// one invocation serves one matrix cell without scraping its report.
    json_report: Option<String>,
    /// Scenario id the cell belongs to, recorded in `--json-report`.
    scenario: String,
    no_ceiling: bool,
}

/// Gate-5 workload defaults, chosen so a run finishes inside a CI job and still
/// moves enough bytes for a throughput figure to mean something.
///
/// 512 MiB per flow at 64 KiB per iteration, which is about 0.7 s of transfer on a
/// loopback that both engines manage at several hundred MiB/s. The size is set by
/// the *sampling* period, not by taste: `ps` is read every 100 ms, so a workload
/// that finishes in 20 ms puts one reading in the transfer window and the CPU
/// column becomes a single reading rather than a measurement. Three repeats of
/// 512 MiB is a few seconds per engine, which a CI job can afford.
const DEFAULT_REPEATS: usize = 3;
pub(crate) const DEFAULT_CONNECTIONS: usize = 1;
pub(crate) const DEFAULT_PAYLOAD_SIZE: usize = 65_536;
pub(crate) const DEFAULT_ITERATIONS: usize = 8192;

// The outbound half of the gate-5 config is `Dialect::base_config`: a `freedom`
// outbound in the Xray spelling and a `direct` one in sing-box's, which is the
// same behaviour under the name each engine reads. It is not a constant here any
// more precisely because a constant was the bug -- one spelling cannot be both
// dialects', and sing-box rejected it on every repeat of every run.
//
// The job it describes is still exactly the relay: the `VLESS` header and the
// record layer are exercised by gates 1-4 against a reference, in process, where
// the comparison is exact. A process-level row that also put a `VLESS` hop in the
// path would measure two engines' relays *and* two engines' protocol stacks at
// once, and the difference would not be attributable to either. Keeping the
// outbound at "send it straight out" is what lets `docs/methodology.md` state
// plainly that this row measures the relay, not the protocol.

/// The `--engine` label whose rows decide gate 5.
///
/// `scripts/run-parity.sh` appends this engine after the comparators it built from
/// their pins, and it is the only one of them this repository ships. Every other
/// label is a pinned third-party binary: measured and published, never gating,
/// because a comparator measuring worse than the reference is a fact about the
/// comparator. Naming it here rather than trusting the position in the list is what
/// makes the gate's subject explicit at the point the verdict is taken.
const GATE5_ENGINE: &str = "ferrox";

/// The inbound protocols one engine can serve, or an empty list for all of them.
///
/// This is a property of the **pin**, not of the engine's name, and it is written
/// here as a table rather than probed at runtime because the alternative is the
/// failure it replaces: hand the engine a config naming a protocol it does not
/// implement, let it exit during startup, and report that as a broken engine.
/// `xray-rust` at `7a4fb2dd` accepts `socks`, `http` and `tun` and rejects the rest
/// (`crates/xray-config/src/parser.rs:636`), so every protocol scenario in the
/// matrix was producing three red rows per cell on every runner for a binary that
/// was never going to serve them.
fn protocols_for(label: &str) -> &'static [&'static str] {
    match label {
        "xray-rust" => &["socks", "http", "tun"],
        _ => &[],
    }
}

/// Read the value after a flag, exiting with usage status when it is missing.
///
/// A free function rather than a closure inside `parse_args` so the parser
/// stays under the line-count lint while every flag keeps one call site.
fn flag_value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next().unwrap_or_else(|| {
        eprintln!("{flag} needs a value");
        std::process::exit(2);
    })
}

/// Read a positive whole number after a flag, exiting when it is not one.
fn flag_count(args: &mut impl Iterator<Item = String>, flag: &str) -> usize {
    let raw = flag_value(args, flag);
    match raw.parse::<usize>() {
        Ok(n) if n > 0 => n,
        _ => {
            eprintln!("{flag} needs a positive whole number, got `{raw}`");
            std::process::exit(2);
        }
    }
}

/// Validate one `<label>=<shape>` flag and push it, exiting on misuse.
///
/// `--config-arg` and `--dialect` share the shape. Parsed here so a typo is an
/// invocation error rather than a run that starts every engine with the wrong
/// flag and reports engines that will not serve.
fn push_labeled_shape(
    into: &mut Vec<(String, String)>,
    flag: &str,
    kind: &str,
    spec: &str,
    parse: impl FnOnce(&str) -> Result<(), String>,
) {
    let Some((label, shape)) = spec.split_once('=') else {
        eprintln!("{flag} needs <label>=<{kind}>, got `{spec}`");
        std::process::exit(2);
    };
    if let Err(e) = parse(shape) {
        eprintln!("{flag} {label}: {e}");
        std::process::exit(2);
    }
    into.push((label.to_owned(), shape.to_owned()));
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut declared = String::from("chacha20 0.9 (crates.io)");
    let mut config: Option<String> = None;
    let mut engines: Vec<(String, String)> = Vec::new();
    let mut config_shapes: Vec<(String, String)> = Vec::new();
    let mut dialects: Vec<(String, String)> = Vec::new();
    let mut repeats = DEFAULT_REPEATS;
    let mut connections = DEFAULT_CONNECTIONS;
    let mut payload_size = DEFAULT_PAYLOAD_SIZE;
    let mut iterations = DEFAULT_ITERATIONS;
    let mut traffic = String::from("download");
    let mut outbound_config = String::new();
    let mut output_dir = String::from("target/parity");
    let mut json_report: Option<String> = None;
    let mut scenario = String::from("gate5");
    let mut no_ceiling = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--reference" => declared = flag_value(&mut args, "--reference"),
            "--config" => config = Some(flag_value(&mut args, "--config")),
            "--config-arg" => push_labeled_shape(
                &mut config_shapes,
                "--config-arg",
                "shape",
                &flag_value(&mut args, "--config-arg"),
                |shape| {
                    parity::ConfigArg::parse(shape)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                },
            ),
            "--dialect" => push_labeled_shape(
                &mut dialects,
                "--dialect",
                "dialect",
                &flag_value(&mut args, "--dialect"),
                |shape| {
                    parity::Dialect::parse(shape)
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                },
            ),
            "--engine" => {
                let spec = flag_value(&mut args, "--engine");
                let Some((label, path)) = spec.split_once('=') else {
                    eprintln!("--engine needs <label>=<path>, got `{spec}`");
                    std::process::exit(2);
                };
                if label.is_empty() || path.is_empty() {
                    eprintln!("--engine needs a non-empty label and a non-empty path");
                    std::process::exit(2);
                }
                engines.push((label.to_owned(), path.to_owned()));
            }
            "--repeats" => repeats = flag_count(&mut args, "--repeats"),
            "--connections" => connections = flag_count(&mut args, "--connections"),
            "--payload-size" => payload_size = flag_count(&mut args, "--payload-size"),
            "--iterations" => iterations = flag_count(&mut args, "--iterations"),
            "--traffic" => traffic = flag_value(&mut args, "--traffic"),
            "--outbound-config" | "--output-dir" | "--json-report" | "--scenario" => {
                parse_matrix_arg(
                    &mut outbound_config,
                    &mut output_dir,
                    &mut json_report,
                    &mut scenario,
                    arg.as_str(),
                    flag_value(&mut args, arg.as_str()),
                );
            }
            "--no-harness-ceiling" => no_ceiling = true,
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    Args {
        declared,
        config,
        engines,
        config_shapes,
        dialects,
        repeats,
        connections,
        payload_size,
        iterations,
        traffic,
        outbound_config,
        output_dir,
        json_report,
        scenario,
        no_ceiling,
    }
}

/// Matrix-cell flags, split out so `parse_args` stays under the line budget.
///
/// Takes the flag and its already-read value: reading here would need the
/// argument iterator beside the `value` closure that owns it. `--outbound-config`
/// is parsed here so a typo is an invocation error rather than a cell that
/// starts every engine with no outbound and reports five engines that will
/// not serve.
fn parse_matrix_arg(
    outbound_config: &mut String,
    output_dir: &mut String,
    json_report: &mut Option<String>,
    scenario: &mut String,
    flag: &str,
    document: String,
) {
    match flag {
        "--outbound-config" => {
            if let Err(e) = json::parse(&document) {
                eprintln!("--outbound-config is not valid json: {e}");
                std::process::exit(2);
            }
            *outbound_config = document;
        }
        "--output-dir" => *output_dir = document,
        "--json-report" => *json_report = Some(document),
        "--scenario" => *scenario = document,
        _ => {
            eprintln!("unknown argument: {flag}");
            std::process::exit(2);
        }
    }
}

/// Best-of-`ROUNDS` seconds per call.
fn time_best<F: FnMut()>(iters: u64, mut f: F) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..ROUNDS {
        let t0 = std::time::Instant::now();
        f();
        best = best.min(t0.elapsed().as_secs_f64() / iters as f64);
    }
    best
}

/// Key and nonce pairs for the sweep.
///
/// Two of them, so nothing passes by being right for one constant input. Every
/// byte of one differs from every byte of the other, which is the property that
/// makes the sweep able to see a key laid out in the wrong order: an all-equal key
/// gives a permuted layout the same state, so it cannot detect the defect it
/// appears to be testing for.
fn keypairs() -> [([u8; 32], [u8; 12]); 2] {
    let a = (
        std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
        std::array::from_fn(|i| (i as u8).wrapping_mul(53).wrapping_add(7)),
    );
    let b = (
        std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        std::array::from_fn(|i| (i as u8).wrapping_mul(101).wrapping_add(61)),
    );
    [a, b]
}

/// Gate 1: byte-for-byte identity against the pinned reference, at every listed length and the 6 selected offsets. Panics on the first disagreement.
///
/// Both entry points are swept, because they are two different pieces of arithmetic:
/// `fill_exact` and `fill_exact_with_head` split the caller's bytes differently, and
/// the fused one carries a head block that has to be subtracted from the pass width.
/// A gate that swept only `fill_exact` passed a core whose head-path tail wrote the
/// wrong 64 bytes at every length in `[385, 447]`, which is the `TAIL_STATES` clamp
/// window on this build — 63 lengths the length list brackets at 385 and 447 and
/// therefore already named, at a path the gate never called.
fn gate_identity(pairs: &[([u8; 32], [u8; 12]); 2]) -> usize {
    let lengths = lengths();
    let mut shapes = 0usize;
    for (k, n) in pairs {
        for start in [0u32, 1, 2, 7, 64, 65_535] {
            for &len in &lengths {
                let mut want = vec![0u8; len];
                let mut got = vec![0u8; len];
                ferrox_core::reference::reference_xor(k, n, start, &mut want);
                ferrox_core::record::fill_exact(k, n, start, &mut got);
                assert_eq!(want, got, "bit-identity: start {start} len {len}");
                shapes += 1;
            }
            for &len in &lengths {
                // The head is block `start` and the body is `start + 1`, so one
                // reference pass over `len + 64` bytes carries both sides: the head
                // is the first 32 bytes of its block and the body is what follows.
                let mut want = vec![0u8; len + 64];
                ferrox_core::reference::reference_xor(k, n, start, &mut want);
                let (want_block, want_body) = want.split_at(64);
                let want_head = &want_block[..32];
                let mut got_body = vec![0u8; len];
                let mut got_head = [0u8; 32];
                ferrox_core::record::fill_exact_with_head(
                    k,
                    n,
                    start,
                    &mut got_head,
                    &mut got_body,
                );
                assert_eq!(
                    got_body, want_body,
                    "bit-identity with head, body: start {start} len {len}"
                );
                assert_eq!(
                    got_head, want_head,
                    "bit-identity with head, head: start {start} len {len}"
                );
                shapes += 1;
            }
        }
    }
    shapes
}

/// Gate 2: the properties that are integer counts rather than durations, so they
/// are identical on every machine and are gated outright.
///
/// * blocks generated equals blocks needed, at every listed length and the 6 selected offsets: the number is the ladder's own count, returned by the passes that
///   ran the rounds, so a ladder that generated a block nobody asked for reports
///   it. It used to return `blocks_for(len)` and be compared against it, which is
///   `ceil(n / 64) == ceil(n / 64)` and cannot fail;
/// * zero heap allocations per call;
/// * zero zero-fills per call.
fn gate_deterministic(key: &[u8; 32], nonce: &[u8; 12]) -> usize {
    let lengths = lengths();
    let mut block_failures: Vec<String> = Vec::new();
    let mut alloc_failures: Vec<String> = Vec::new();

    for &len in lengths.iter().filter(|&&l| l > 0) {
        let mut buf = vec![0u8; len];
        for start in [0u32, 1, 2, 7, 64, 65_535] {
            let produced = ferrox_core::record::fill_exact(key, nonce, start, &mut buf);
            if !ferrox_core::record::blocks_match(len, produced) {
                block_failures.push(format!(
                    "{len}B at start {start}: the ladder reported {produced}, needed {}",
                    ferrox_core::record::blocks_for(len)
                ));
            }
        }

        // The buffer is allocated *before* the counting window opens; measuring
        // the harness' own `vec!` would say nothing about the core.
        let iters = 64u64;
        let ((), counts) = count::measure(|| {
            for _ in 0..iters {
                ferrox_core::record::fill_exact(
                    key,
                    nonce,
                    0,
                    std::hint::black_box(&mut buf[..]),
                );
            }
        });
        if counts.allocs != 0 {
            alloc_failures.push(format!(
                "{len}B: {:.3} allocations per call",
                counts.per_iter(iters)
            ));
        }
        if counts.bytes != 0 {
            alloc_failures.push(format!(
                "{len}B: {:.1} bytes allocated per call",
                counts.bytes_per_iter(iters)
            ));
        }
        if counts.zeroed != 0 {
            alloc_failures.push(format!("{len}B: {} zero-fills per call", counts.zeroed));
        }
    }

    // Rung 1's hot path is gated the same way: header encode runs per connection,
    // so one allocation there is one per dial. `uuid_bytes` used to allocate a
    // 32-char `String` on exactly this path; the sweep below is what keeps it at
    // zero across all three address families. Buffers are allocated before the
    // counting window opens, same discipline as above.
    {
        let link = ferrox_core::vless::VlessLink::parse(
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@192.0.2.1:443?security=reality&encryption=none&type=tcp&flow=xtls-rprx-vision&fp=firefox&sni=example.com&sid=a8#x",
        )
        .expect("synthetic rung-1 link parses");
        for host in ["192.0.2.53", "2001:db8::1", "example.com"] {
            let need = link.request_header_len(host);
            let mut hdr = vec![0u8; need];
            let iters = 64u64;
            let ((), counts) = count::measure(|| {
                for _ in 0..iters {
                    let n = link.encode_into(host, 443, std::hint::black_box(&mut hdr[..]));
                    std::hint::black_box(n);
                }
            });
            if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
                alloc_failures.push(format!(
                    "header {host}: {} allocs, {} bytes, {} zero-fills per 64 encodes",
                    counts.allocs, counts.bytes, counts.zeroed
                ));
            }
        }
    }

    // Rung 1's record framing is gated the same way: seal/open run per record,
    // so one allocation there is one per record on a live stream. Sessions and
    // buffers live outside the window; only the framing is inside it.
    gate_vision_allocs(key, nonce, &mut alloc_failures);

    assert!(
        block_failures.is_empty(),
        "DISCARDED WORK: the ladder generated blocks the caller's length does not need at {} \
         length(s): {:?}",
        block_failures.len(),
        &block_failures[..block_failures.len().min(10)]
    );
    assert!(
        alloc_failures.is_empty(),
        "ALLOCATION: the core allocated or zero-filled at {} length(s): {:?}",
        alloc_failures.len(),
        &alloc_failures[..alloc_failures.len().min(10)]
    );

    lengths.len()
}

/// Gate 2's Vision-record half: seal/open allocate nothing per record.
fn gate_vision_allocs(key: &[u8; 32], nonce: &[u8; 12], alloc_failures: &mut Vec<String>) {
    let uuid = [0xabu8; 16];
    for len in [0usize, 1, 64, 1400, 8171] {
        let content = vec![0u8; len];
        let mut sealed = vec![0u8; 16 + 5 + len + 256];
        let mut opened = vec![0u8; 16 + 5 + len + 256];
        let iters = 64u64;
        let ((), counts) = count::measure(|| {
            let mut session = ferrox_core::vless::VisionSeal::new(key, nonce, &uuid);
            let mut stream = ferrox_core::vless::VisionOpen::new(&uuid);
            for _ in 0..iters {
                let n = session.seal(
                    std::hint::black_box(&mut sealed[..]),
                    std::hint::black_box(&content[..]),
                    ferrox_core::vless::VisionCommand::Continue,
                    false,
                );
                let (written, _) = stream.open(&sealed[..n], std::hint::black_box(&mut opened[..]));
                std::hint::black_box((n, written));
            }
        });
        if counts.allocs != 0 || counts.bytes != 0 || counts.zeroed != 0 {
            alloc_failures.push(format!(
                "vision {len}B: {} allocs, {} bytes, {} zero-fills per 64 seals",
                counts.allocs, counts.bytes, counts.zeroed
            ));
        }
    }
}

/// One timed length, on both sides, best of [`ROUNDS`] each.
///
/// The rounds interleave reference/ferrox/reference/ferrox rather than
/// running all of one side first: back-to-back rounds share the same thermal
/// and frequency conditions, so a slow drift across the run cannot favour
/// whichever side ran while the machine was cooler. Same samples as
/// sequential rounds, fairer pairing.
fn measure_len(key: &[u8; 32], nonce: &[u8; 12], len: usize) -> Row {
    let iters = iters_for(len);
    // One buffer for the whole run, reused: a per-iteration `vec!` adds the same
    // malloc and memset to both sides and dilutes the ratio towards 1.
    let mut buf = vec![0u8; len];

    let mut base = f64::MAX;
    let mut ours = f64::MAX;
    for _ in 0..ROUNDS {
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            ferrox_core::reference::reference_xor(
                key,
                nonce,
                0,
                std::hint::black_box(&mut buf[..]),
            );
        }
        base = base.min(t0.elapsed().as_secs_f64() / iters as f64);
        let t0 = std::time::Instant::now();
        for _ in 0..iters {
            ferrox_core::record::fill_exact(key, nonce, 0, std::hint::black_box(&mut buf[..]));
        }
        ours = ours.min(t0.elapsed().as_secs_f64() / iters as f64);
    }

    let ratio = base / ours;

    // Anything under the bar is confirmed before it fails the job, and the
    // confirmation is three independent passes at four times the budget with the
    // median taken. The bar is untouched; what changed is that one extra pass is not
    // a confirmation, and the measurements say so.
    //
    // Across fourteen runs of one tree, 319 B on `linux x86_64` read 1.01x-1.09x
    // thirteen times and 0.84x once. 125 B on `macos aarch64` read 1.08x-1.19x in
    // fourteen `bench.yml` runs and 0.848x in a `parity.yml` run of the same commit.
    // Both outliers survived the single four-times re-measure that used to stand
    // between a sample and a red build, which means that re-measure shared whatever
    // disturbed the first sample rather than being independent of it. Taking the
    // median of three independent passes reads the mode, which is what those
    // thirteen and fourteen runs are.
    //
    // This cannot hide a regression: a length that is genuinely under the bar is
    // under it in every pass, because every pass runs the same code on the same
    // machine. `confirmed_ratio` is where that is stated as arithmetic rather than as
    // intent, and it is tested both ways.
    if ratio < BAR {
        let heavy = iters * 4;
        let mut passes = Vec::with_capacity(CONFIRMATIONS);
        for _ in 0..CONFIRMATIONS {
            let base2 = time_best(heavy, || {
                for _ in 0..heavy {
                    ferrox_core::reference::reference_xor(
                        key,
                        nonce,
                        0,
                        std::hint::black_box(&mut buf[..]),
                    );
                }
            });
            let ours2 = time_best(heavy, || {
                for _ in 0..heavy {
                    ferrox_core::record::fill_exact(
                        key,
                        nonce,
                        0,
                        std::hint::black_box(&mut buf[..]),
                    );
                }
            });
            passes.push((base2, ours2));
        }
        let (base, ours) = confirmed_pass(&passes);
        let ratio = base / ours;
        return Row {
            len,
            base,
            ours,
            ratio,
            remeasured: true,
        };
    }

    Row {
        len,
        base,
        ours,
        ratio,
        remeasured: false,
    }
}

/// Assemble the report.
///
/// Separate from `main` so that the whole document exists before any of it is
/// written to disk. It did not used to: the summary was appended after the file
/// had been saved, so the file never contained it — and the summary is the line
/// a reader looks for first.
fn build_report(declared: &str, shapes: usize, measured_lengths: usize, rows: &[Row]) -> String {
    let mut report = String::new();
    let _ = writeln!(report, "# ferrox benchmark\n");

    // What was compared against, and what this build actually ran. Both are named
    // because a speedup is only attributable once both sides of it are.
    let _ = writeln!(report, "| | |");
    let _ = writeln!(report, "| --- | --- |");
    let _ = writeln!(report, "| declared reference | `{declared}` |");
    let _ = writeln!(
        report,
        "| reference actually ran | {} |",
        ferrox_core::reference::backend()
    );
    let _ = writeln!(
        report,
        "| ferrox core | {} |",
        ferrox_core::chacha_backend()
    );
    let _ = writeln!(report, "| target | `{}` |", std::env::consts::ARCH);
    let _ = writeln!(report);

    let _ = writeln!(report, "## Gate 1 — identity\n");
    let _ = writeln!(
        report,
        "**{shapes} shapes**, byte for byte, at every listed length and the 6 selected offsets: dense, not exhaustive (see `lengths`)."
    );

    let _ = writeln!(report, "\n## Gate 2 — deterministic properties\n");
    let _ = writeln!(
        report,
        "Across **{measured_lengths} lengths**: blocks generated equals blocks needed at every\n\
         one; **0** heap allocations per call; **0** zero-fills per call.\n\n\
         These are integer counts, so they are identical on every machine and are gated\n\
         outright rather than reported."
    );

    let _ = writeln!(report, "\n## Gate 3 — timing\n");
    let timed = rows.len();
    let listed = lengths().len();
    let _ = writeln!(
        report,
        "Best of {ROUNDS} interleaved rounds per side (reference/ferrox/reference/…,\n\
         so a thermal drift cannot favour one side). The bar is {BAR:.2}x: 5% is\n\
         runner noise, and any length under it is re-measured at 4x the budget\n\
         and marked `remeasured`, and still fails the job if it stays under the\n\
         bar. The re-measure confirms the number; it does not lower the bar.\n\n\
         {timed} of {listed} listed lengths are timed, starting at {TIMING_MIN} bytes:\n\
         lengths 1-64 are one block, a tie by construction, so they are covered\n\
         byte for byte in gate 1 and not timed here.\n"
    );
    let _ = writeln!(
        report,
        "| len | reference ns/op | ferrox ns/op | speedup | remeasured |"
    );
    let _ = writeln!(report, "|---:|---:|---:|---:|:--:|");
    for r in rows {
        let _ = writeln!(
            report,
            "| {} | {:.1} | {:.1} | {:.2}x | {} |",
            r.len,
            r.base * 1e9,
            r.ours * 1e9,
            r.ratio,
            if r.remeasured { "yes" } else { "" }
        );
    }

    if let (Some(worst), Some(best)) = (
        rows.iter().min_by(|a, b| a.ratio.total_cmp(&b.ratio)),
        rows.iter().max_by(|a, b| a.ratio.total_cmp(&b.ratio)),
    ) {
        let _ = writeln!(
            report,
            "\n**Gate: {} lengths, none below {BAR:.2}x.** Worst {:.2}x @ {}B, best {:.2}x @ {}B.",
            rows.len(),
            worst.ratio,
            worst.len,
            best.ratio,
            best.len
        );
    }

    let _ = writeln!(
        report,
        "\n> The reference is re-keyed and re-seeked on every call, which a stateful record\n\
         > layer would not do. That flatters short lengths in particular. The 16384 B row is\n\
         > the one closest to a real VMess/Shadowsocks record and should be read as the\n\
         > headline; the reference's own backend, named above, is what decides whether a\n\
         > ratio here reflects this workspace's work or the reference's fallback."
    );

    // Per-method matrix, every report: implemented cells carry numbers above,
    // the rest stay empty with their reason and their proof. See `methods.rs`.
    report.push_str(&methods::table());

    report
}

/// The slowest and fastest timed lengths, as `(worst, best)`.
///
/// Taken together rather than separately because the report prints them in one
/// sentence, and a report that computed them at two different moments could print
/// two numbers that were never true at the same time.
fn extremes(rows: &[Row]) -> (&Row, &Row) {
    let worst = rows
        .iter()
        .min_by(|a, b| a.ratio.total_cmp(&b.ratio))
        .expect("gate 3 always measures at least one length");
    let best = rows
        .iter()
        .max_by(|a, b| a.ratio.total_cmp(&b.ratio))
        .expect("gate 3 always measures at least one length");
    (worst, best)
}

/// The `--config` section, or an empty string when no link was given.
///
/// A link that does not parse exits here rather than appending an empty-with-reason
/// section: CI hands a link in to get a table, and an unreadable link is a mistake
/// in the invocation, not an unimplemented transport.
fn config_section(link: Option<&str>) -> String {
    let Some(link_str) = link else {
        return String::new();
    };
    match ferrox_core::vless::VlessLink::parse(link_str) {
        Ok(parsed) => {
            println!("config: {}", compare::describe_redacted(&parsed));
            compare::compare_offline(&parsed)
        }
        Err(e) => {
            eprintln!("--config: bad vless link: {e}");
            std::process::exit(2);
        }
    }
}

/// What gate 5 produced: the markdown it appends, and the comparison to assert on.
struct Gate5 {
    /// Markdown for the report. Empty when gate 5 did not run.
    report: String,
    /// `None` when fewer than two engines were named.
    comparison: Option<compare_process::Comparison>,
    engines: usize,
}

/// Run gate 5, or explain why it did not run.
///
/// A single named engine is reported rather than measured: one engine is a
/// measurement, not a comparison, and printing a table with a single row would
/// read as "nothing to beat" rather than as "no comparison was asked for".
fn gate5_section(args: &Args) -> Result<Gate5, String> {
    if args.engines.is_empty() {
        return Ok(Gate5 {
            report: String::new(),
            comparison: None,
            engines: 0,
        });
    }
    if args.engines.len() < 2 {
        return Err(
            "gate 5 needs at least two --engine arguments to have something to \
             compare against; one engine is a measurement, not a comparison. Gates \
             1-4 ran and their report is at target/bench-report.md."
                .to_owned(),
        );
    }
    let engines: Vec<compare_process::Engine> = args
        .engines
        .iter()
        .map(|(label, path)| {
            let shape = args
                .config_shapes
                .iter()
                .find(|(name, _)| name == label)
                .map_or("long", |(_, shape)| shape.as_str());
            let Ok(config_arg) = parity::ConfigArg::parse(shape) else {
                // Already checked in `parse_args`; unreachable, and failing loudly
                // beats silently defaulting to a flag the engine does not take.
                unreachable!("--config-arg was validated at parse time");
            };
            let dialect = args
                .dialects
                .iter()
                .find(|(name, _)| name == label)
                .map_or_else(
                    || {
                        // No `--dialect` for this engine means the Xray spelling,
                        // which is what four of the five pins read. Named in the
                        // report so a reader can see which shape each engine was
                        // handed rather than inferring it.
                        parity::Dialect::Xray
                    },
                    |(_, shape)| {
                        parity::Dialect::parse(shape).unwrap_or_else(|e| {
                            unreachable!("--dialect was validated at parse time: {e}")
                        })
                    },
                );
            compare_process::Engine {
                // The label lives as long as the process, which is what lets a
                // measurement cell name its engine without borrowing from a `Vec`
                // that is about to be dropped.
                name: Box::leak(label.clone().into_boxed_str()),
                path: path.into(),
                config_arg,
                dialect,
                gated: label == GATE5_ENGINE,
                // Which inbound protocols this engine serves. Empty means all of
                // them, which is what an engine parsing the whole Xray config
                // surface gets; `xray-rust` at its pin is the one that does not.
                protocols: protocols_for(label),
            }
        })
        .collect();
    let workload = compare_process::Workload {
        traffic: args.traffic.clone(),
        connections: args.connections,
        iterations: args.iterations,
        payload_size: args.payload_size,
        warmup: false,
        outbound_config: args.outbound_config.clone(),
        scenario: args.scenario.clone(),
    };
    let comparison = compare_process::run(
        &engines,
        &workload,
        args.repeats,
        std::path::Path::new(&args.output_dir),
        !args.no_ceiling,
    )
    .map_err(|e| e.to_string())?;
    let report = comparison.report();
    // Written beside the markdown, before any assertion on the gate, for the
    // same reason the report is: a red cell must still publish the numbers it
    // failed on, or there is nothing to plot and nothing to re-derive.
    if let Some(path) = &args.json_report {
        let document = comparison
            .comparison_json(&args.scenario)
            .map_err(|e| format!("--json-report: {e}"))?;
        std::fs::write(path, document).map_err(|e| format!("--json-report: {e}"))?;
    }
    Ok(Gate5 {
        report,
        comparison: Some(comparison),
        engines: engines.len(),
    })
}

/// Gate 6: the mux frame codec, against a reference shaped the way the four
/// implementations shape it. Field-checked before it is timed, like gate 4, and
/// with the limit stated in its own header: there is no pinned same-language oracle
/// for this format, so its identity half is the hand-derived vectors in
/// `mux::tests` rather than anything measured here.
/// Gate 4: the `VLESS` request header encode, against a reference built to the shape
/// of the encode it replaced.
fn gate_four(report: &mut String) -> Vec<framing::Row> {
    let frames = framing::gate_framing();
    println!(
        "gate 4 passed: {} framing rows, byte-identical",
        frames.len()
    );
    report.push_str(&framing::report(&frames));
    frames
}

/// Gate 7: the `ChaCha20`-`Poly1305` seal, against the two-call build it replaced.
///
/// The same three steps as gate 4 — field-checked before it is timed, against a
/// reference shaped the way the code it replaced was shaped — over the other half
/// of what a `VMess` data frame costs. Empty `aad` is the shape a `VMess` data
/// frame has, and it is the shape `RFC 8439` section 2.6's two keystream halves
/// arrive in: block zero's first 32 bytes, then block one onward.
fn gate_seven(key: &[u8; 32], nonce: &[u8; 12], report: &mut String) -> Vec<framing::Row> {
    let mut seals = framing::gate_aead(key, nonce);
    println!(
        "gate 7 passed: {} seal rows, ciphertext and tag identical to their references",
        seals.len()
    );
    report.push_str(&framing::aead_report(&seals));

    // Gate 7b: the same seal split into its two halves. Reported, not gated, and
    // not returned to the bar — its whole job is to say which half of the seal the
    // next change should touch, and it is a measurement of this tree rather than a
    // comparison against a reference.
    let split = framing::aead_split(key, nonce);
    println!(
        "gate 7b reported: {} split rows, self-timed, not gated",
        split.len()
    );
    report.push_str(&framing::aead_split_report(&split));

    // Gate 7c: the `Poly1305` accumulator on its own, against the twenty-five
    // product Horner chain it replaced. Gated, because unlike 7b these rows do
    // have a "before" and it is the code being replaced.
    let macs = framing::gate_mac(key, nonce);
    println!(
        "gate 7c passed: {} poly1305 rows, tag identical to the 26-bit horner",
        macs.len()
    );
    report.push_str(&framing::mac_report(&macs));

    // Into the bar, not just the report: gate 7c's rows have a real "before" and
    // so are gated at the same 0.95x gate 3 uses.
    seals.extend(macs);
    seals
}

fn gate_six(report: &mut String) -> Vec<framing::Row> {
    let muxed = muxframe::gate_mux();
    println!(
        "gate 6 passed: {} mux rows field-identical to their references and 0 allocs on both \
         sides; {} of them gated, the encode and bridge rows reported only",
        muxed.len(),
        muxframe::gated(&muxed).len()
    );
    report.push_str(&muxframe::report(&muxed));
    muxed
}

/// Gate 8: the `?ed=` encode, against a reference shaped the way `ZeroNet` shapes
/// it: an `encode` into a fresh `String`, then a `format!` into a second, then a
/// copy of that into the request. Field-checked and allocation-checked before it
/// is timed, like every other framing, and with the limit stated in its own
/// header: what decides this rung's identity is `conformance.yml`, not a
/// reference built to a shape.
fn gate_eight(report: &mut String) -> Vec<framing::Row> {
    let rows = earlydata::gate_early_data();
    println!(
        "gate 8 passed: {} early-data encode rows, byte-identical to their references, none \
         below {BAR:.2}x, and under one allocation per encode on this side",
        rows.len()
    );
    report.push_str(&earlydata::report(&rows));
    rows
}

/// The live speedtest's config generator, before the gates: it needs none of
/// them, and running four timing gates first would make a config typo cost
/// minutes rather than milliseconds.
fn linkconfig_exit() -> Option<i32> {
    if std::env::args().nth(1).as_deref() == Some("linkconfig") {
        Some(linkconfig::run(
            &std::env::args().skip(2).collect::<Vec<_>>(),
        ))
    } else {
        None
    }
}

/// Gate 9: the three `shadowsocks` ciphers against the one that shipped.
///
/// Identity- and allocation-checked before it is timed, like every other framing.
/// The timing rows are **printed and not judged**, and the reason is in
/// `ciphers.rs`: the two sides straddle a hardware boundary that differs per
/// runner, so the ratio is as much a property of the runner's AES as of the code.
/// Nothing here feeds the `BAR` assertion.
fn gate_nine(report: &mut String) {
    let (rows, windows) = ciphers::gate_ciphers();
    println!(
        "gate 9 passed: {} shadowsocks cipher rows, byte-identical to the reference and under \
         one allocation per chunk on all three methods; the timing rows are printed only",
        rows.len()
    );
    report.push_str(&ciphers::report(&rows, &windows));
}

/// Gate 10: the fused `AES-128-GCM` engine against the `aes-gcm` crate both hot
/// paths used to seal with. Identity- and allocation-checked before it is
/// timed, like every other framing; unlike gate 9 these rows have a true
/// "before", so they go to the bar.
fn gate_ten(report: &mut String) -> Vec<framing::Row> {
    let (rows, windows) = aesgcm::gate_aesgcm();
    println!(
        "gate 10 passed: {} aes-128/256-gcm rows, ciphertext and tag identical to the crate and \
         under one allocation per seal+open pair",
        rows.len()
    );
    let engine = ferrox_core::aesgcm::Aes128Gcm::new(&[7u8; 16]);
    report.push_str(&aesgcm::report(&rows, &windows, engine.backend()));
    rows
}

fn main() {
    if let Some(code) = linkconfig_exit() {
        std::process::exit(code);
    }
    let args = parse_args();
    let declared = args.declared.clone();
    let pairs = keypairs();
    let (key, nonce) = pairs[0];

    // Gate 1: identity, before any timing.
    let shapes = gate_identity(&pairs);
    println!("gate 1 passed: bit-identical at {shapes} shapes");

    // Gate 2: the properties that are counts rather than durations.
    let measured_lengths = gate_deterministic(&key, &nonce);
    println!(
        "gate 2 passed: 0 discarded blocks, 0 allocations, 0 zero-fills at {measured_lengths} lengths"
    );

    // Gate 3: timing, the only machine-dependent one. Lengths below TIMING_MIN
    // are a tie both sides cannot lose, so timing them would gate the runner.
    let rows: Vec<Row> = lengths()
        .iter()
        .filter(|&&l| l >= TIMING_MIN)
        .map(|&len| measure_len(&key, &nonce, len))
        .collect();

    let mut report = build_report(&declared, shapes, measured_lengths, &rows);

    // Gates 4, 6 and 7: the framings, which had no timed reference until gate 4, and
    // the AEAD seal, which had none at all. Each row is byte-checked against a
    // reference build before it is timed, so identity comes before timing here
    // exactly as in gate 1.
    let frames = gate_four(&mut report);
    let seals = gate_seven(&key, &nonce, &mut report);
    let muxed = gate_six(&mut report);
    let early = gate_eight(&mut report);
    gate_nine(&mut report);
    let aes_gcm_rows = gate_ten(&mut report);

    // Config comparison, after the proof gates: hand CI a working link and it
    // appends the redacted offline table (and the empty-with-reason live cells).
    // A bad link fails here, not silently.
    report.push_str(&config_section(args.config.as_deref()));

    // Gate 5: the process-level comparison, which runs only when at least two
    // engines were named. It is last because it is the slowest gate and the only
    // one that needs binaries rather than this workspace: gates 1-4 must be able
    // to publish their tables even when no comparator is available on the host.
    let gate5 = match gate5_section(&args) {
        Ok(section) => section,
        Err(message) => {
            eprintln!("gate 5 could not run: {message}");
            std::process::exit(2);
        }
    };
    report.push_str(&gate5.report);
    if gate5.comparison.is_some() {
        println!(
            "gate 5 measured: {} engines x {} repeats",
            gate5.engines, args.repeats
        );
    }

    // Written *before* the gate is asserted on, so a failing run still publishes
    // the table it failed on. Asserting first meant a red build printed "no
    // report", which is the one moment the numbers are wanted.
    std::fs::create_dir_all("target").expect("create target dir");
    std::fs::write("target/bench-report.md", &report).expect("write report");

    // Gate 4's rows, gate 6's *gated* rows and gate 8's share one bar and one
    // failure message, because they are the same claim about three framings: same
    // bytes, not slower. Gate 6's encode rows are printed with their absolutes and
    // not judged
    // — `muxframe::REPORTED_ONLY` says why, with the four-runner spread that
    // decided it, and `docs/claims.md` records it as a decision rather than a
    // preference.
    let slow_frames: Vec<&framing::Row> = frames
        .iter()
        .chain(seals.iter())
        .chain(muxframe::gated(&muxed))
        .chain(early.iter())
        .chain(aes_gcm_rows.iter())
        .filter(|r| r.ratio() < BAR)
        .collect();
    assert!(
        slow_frames.is_empty(),
        "FRAMING REGRESSION: a framing slower than its reference at {} row(s), worst {:.3}x: {}",
        slow_frames.len(),
        slow_frames
            .iter()
            .map(|r| r.ratio())
            .fold(f64::INFINITY, f64::min),
        slow_frames
            .iter()
            .map(|r| format!("{}={:.3}x", r.name, r.ratio()))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let failures: Vec<&Row> = rows.iter().filter(|r| r.ratio < BAR).collect();
    assert!(
        failures.is_empty(),
        "REGRESSION: slower than the reference at {} length(s), worst {:.3}x. Failing lengths: {}",
        failures.len(),
        failures
            .iter()
            .map(|r| r.ratio)
            .fold(f64::INFINITY, f64::min),
        failures
            .iter()
            .map(|r| format!("{}B={:.3}x", r.len, r.ratio))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let (worst, best) = extremes(&rows);
    println!(
        "gate 3 passed: {} lengths, none below {BAR:.2}x. Worst {:.2}x @ {}B, best {:.2}x @ {}B",
        rows.len(),
        worst.ratio,
        worst.len,
        best.ratio,
        best.len
    );
    // Gate 5's own assertion, after the report is on disk for the same reason the
    // others are: a red build must still publish the table it failed on. A run
    // that resolved nothing, or that had too few pairs, fails here rather than
    // reporting a pass it did not earn.
    assert_gate5(&gate5, shapes);
}

/// Gate 5's verdict, asserted after the report is on disk.
fn assert_gate5(gate5: &Gate5, shapes: usize) {
    if let Some(comparison) = &gate5.comparison {
        let gate = comparison.gate();
        assert!(
            gate.passed,
            "PROCESS REGRESSION: the process-level comparison did not pass.\n{}\n\
             The table it failed on is in target/bench-report.md and every run's \
             result.json is under target/parity/.",
            gate.lines.join("\n")
        );
        for line in &gate.lines {
            println!("gate 5: {line}");
        }
        println!("gate 5 passed: {}", gate.lines.len());
    }

    println!(
        "PASS: bit-identical at {shapes} shapes, no discarded work or allocation, and not slower at any length"
    );
}

/// One measured length, on both sides.
struct Row {
    len: usize,
    /// Best reference seconds per call.
    base: f64,
    /// Best ferrox seconds per call.
    ours: f64,
    /// `base / ours`. Above 1.00 means ferrox is faster.
    ratio: f64,
    /// Whether this length was re-measured at four times the budget.
    remeasured: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pass is `(reference seconds, ferrox seconds)`; the ratio is the first
    /// over the second, so a ferrox number above the reference is a regression.
    fn passes(ratios: &[f64]) -> Vec<(f64, f64)> {
        ratios.iter().map(|r| (250.0, 250.0 / r)).collect()
    }

    /// The rule has to survive the case it was written for.
    ///
    /// 319 B on `linux x86_64` read 0.84x once in fourteen runs of one tree and
    /// 1.01x-1.09x in the other thirteen, and the single outlier survived the old
    /// one-pass confirmation. A median of three independent passes reads the mode.
    #[test]
    fn one_disturbed_pass_does_not_fail_a_length_that_is_fine() {
        let (base, ours) = confirmed_pass(&passes(&[1.05, 1.07, 0.84]));
        let r = base / ours;
        assert!(
            r >= BAR,
            "one disturbed pass must not fail a sound length: {r}"
        );
        // And the pair published has to be the pair that was decided on, or the
        // table prints a reading the verdict never saw.
        assert!(
            passes(&[1.05, 1.07, 0.84]).contains(&(base, ours)),
            "the confirmed pair must be one of the passes"
        );
    }

    /// And the rule has to survive the case it must not break.
    ///
    /// A length that is genuinely slower is slower in every pass, because every
    /// pass runs the same code on the same machine, and the median says so.
    #[test]
    fn a_length_that_is_really_slower_still_fails() {
        for ratios in [
            [0.84, 0.85, 0.86],
            [0.90, 0.91, 0.92],
            [0.94, 0.94, 0.94],
            [0.84, 0.84, 1.09],
        ] {
            let (base, ours) = confirmed_pass(&passes(&ratios));
            let r = base / ours;
            assert!(r < BAR, "a real regression must fail: {ratios:?} read {r}");
        }
    }
}
