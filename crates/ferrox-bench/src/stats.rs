//! `ZeroNet`'s acceptance criteria, as a gate over process-level runs.
//!
//! # What is being taken, and why these particular rules
//!
//! `ZeroNet` measures itself against Xray-core, sing-box and xray-rust in CI
//! (`upstream/zeronet/.github/workflows/benchmark.yml`) and its harness carries
//! four rules and a set of thresholds that make a comparison mean something.
//! This module is those rules, expressed over the runs `parity.rs` produces, and
//! it is the half of the comparison that can *fail*: gates 1-3 of `main.rs`
//! compare this workspace's record layer against a same-language reference,
//! which says nothing about the process-level path where an engine actually runs.
//!
//! | rule | `ZeroNet` | here |
//! |---|---|---|
//! | regression tolerance | 5%, and only when the whole 95% interval is on the wrong side (`benchmark.yml:54`) | [`TOLERANCE`] |
//! | resolvable difference | 0.05, "not a claim about the cores; a claim about this host with this sample count" (`zbench/stats.py:125`) | [`TOLERANCE`] |
//! | pairs needed for a ratio | 2, else `unproven` (`zbench/stats.py:149`) | [`MIN_PAIRS`] |
//! | repeats worth reading | 3 (`docs/benchmarks/README.md:251`) | [`MIN_RUNS`] |
//! | harness ceiling | published; a row at 85% of it is generator-bound (`zbench/report.py:58`) | [`HARNESS_BOUND`] |
//! | CPU resolution floor | the mechanism's own, published: 10 ms on Linux from `/proc` and on macOS from `ps`, 1000 ms where `ps` prints whole seconds (`zbench/report.py:88` names 10 ms) | [`cpu_resolution_floor_millis`](crate::parity::cpu_resolution_floor_millis) |
//! | "nothing resolved" | not a pass (`zbench/report.py:968`) | [`Gate::nothing_resolved`] |
//! | empty comparison | fails (`zbench/report.py:895`) | [`Gate::no_comparison`] |
//! | aggregates | re-derived from raw cells; a disagreement fails (`zbench/validate_results.py:11`) | [`rederive`] |
//!
//! # The one place this is stricter than `ZeroNet`, and why
//!
//! `ZeroNet`'s RSS policy is direction-only — "strictly lower, zero allowance"
//! (`zbench/report.py:30`) — because it compares four cores whose memory
//! behaviour it knows. Comparing against a core whose every row is published
//! from a dated result group, a direction-only memory rule would fail on any
//! difference at all, including the runner's allocator varying between a macOS
//! and a Linux image. So RSS is *reported* with a tolerance
//! ([`RSS_TOLERANCE`]) and the hard gate is on throughput and CPU, which are the
//! two rows where a regression is a fact about the code rather than about the
//! host. Stated here because a stricter-sounding rule that is quietly relaxed is
//! worse than one that is openly narrower.
//!
//! # Pairing, which is the whole reason the interval is trustworthy
//!
//! Comparisons are paired on the repeat index, and the order of the engines is
//! rotated by the repeat and reversed on alternate repeats
//! (`zbench/benchmark` rule 4, `docs/benchmarks/README.md:233`). A ratio taken
//! from two independently aggregated medians "would divide away the correlation
//! between the two cores' samples, which is the whole reason for pairing"
//! (`zbench/stats.py:9`). So [`rotate`] produces the order, [`paired_ratios`]
//! produces one ratio per repeat, and [`bootstrap_ci`] resamples *those* pairs.

// A ratio of two measurements, and a percentile of a sample, are both `f64` by
// definition; every count behind them is far below 2^53.
#![allow(clippy::cast_precision_loss)]

use std::collections::BTreeMap;

/// Percent. A scenario fails when its whole 95% interval is worse than the
/// candidate by more than this — `ZeroNet`'s `gate_regression` default of 5
/// (`upstream/zeronet/.github/workflows/benchmark.yml:54`).
pub const TOLERANCE: f64 = 0.05;

/// The smallest difference this harness claims it can resolve at
/// [`MIN_RUNS`] repeats. `ZeroNet`'s `DEFAULT_TOLERANCE`, and the reason for its
/// comment: "a difference smaller than this is inside the run-to-run noise the
/// harness can actually resolve. It is not a claim about the cores; it is a claim
/// about this host with this sample count."
pub const RESOLVABLE: f64 = 0.05;

/// Paired repeats needed before a ratio is reported at all. Below this the
/// verdict is `unproven`, which is not a pass.
pub const MIN_PAIRS: usize = 2;

/// Repeats per cell. `ZeroNet`: "three is the minimum worth reading".
pub const MIN_RUNS: usize = 3;

/// A row at or above this fraction of the measured harness ceiling is bounded by
/// the generator rather than by the engine, and is marked as such.
pub const HARNESS_BOUND: f64 = 0.85;

/// Bootstrap resamples, and the seed that makes an interval reproducible.
pub const BOOTSTRAP_RESAMPLES: usize = 4000;
pub const BOOTSTRAP_SEED: u64 = 20_260_902;

/// Memory tolerance, as a fraction. See the module note: the hard gates are
/// throughput and CPU, and RSS is held to the same tolerance rather than to
/// `ZeroNet`'s stricter zero allowance.
pub const RSS_TOLERANCE: f64 = 0.05;

/// Which way is worse for a metric. Read from the metric, never from the sign of
/// the ratio (`zbench/report.py:890`) — the same ratio means opposite things for
/// throughput and for memory, and inferring it is how a report flips its own
/// conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// More is better: throughput.
    Higher,
    /// Less is better: CPU, memory, latency.
    Lower,
}

/// One measured metric in one repeat, for one engine.
///
/// Carries no engine name: the caller has already selected the cells for one
/// engine on each side, and a name here would invite matching the two sides by
/// name — which cannot work in the case that matters, where the candidate and the
/// reference are *different* engines.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cell {
    /// 1-based, matching `ZeroNet`'s `run_index`.
    pub run_index: usize,
    pub value: f64,
}

/// The order engines are measured in for a given repeat.
///
/// Rotated by the repeat index and reversed on alternate repeats, so a
/// systematic "the first engine measured is warmer" effect lands on both
/// engines equally often instead of always on one.
pub fn rotate(engines: &[&'static str], repeat: usize) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = engines.to_vec();
    if order.len() < 2 {
        return order;
    }
    let shift = repeat.saturating_sub(1) % order.len();
    order.rotate_left(shift);
    if repeat.is_multiple_of(2) {
        order.reverse();
    }
    order
}

/// One ratio per repeat, for every repeat that appears on both sides.
///
/// Returns `None` for any repeat missing from either side rather than
/// substituting a default, because a substituted value is a fabricated pair and
/// the interval built from it would be an interval around a fiction. A zero or
/// negative reference is likewise skipped: a ratio against it is not a ratio.
///
/// The ratio is **oriented so that above 1.0 always means better**, which is what
/// lets one threshold serve every metric. `Direction::Higher` divides candidate by
/// reference; `Direction::Lower` divides reference by candidate, so an engine
/// using half the memory scores 2.0x rather than 0.5x. Without this the same
/// interval is read as an improvement on one row and a regression on the next,
/// which is exactly the trap `ZeroNet`'s `point_target` exists to avoid
/// (`upstream/zeronet/docs/benchmarks/harness/zbench/summarize-v07-protocol-parity.py:28`).
pub fn paired_ratios(candidate: &[Cell], reference: &[Cell], direction: Direction) -> Vec<f64> {
    let mut by_repeat: BTreeMap<usize, f64> = BTreeMap::new();
    for cell in reference {
        by_repeat.entry(cell.run_index).or_insert(cell.value);
    }
    let mut ratios: Vec<f64> = candidate
        .iter()
        .filter_map(|cell| {
            let base = by_repeat.get(&cell.run_index)?;
            if *base <= 0.0 {
                return None;
            }
            Some(match direction {
                Direction::Higher => cell.value / *base,
                // `cell.value <= 0.0` is skipped rather than producing an infinity
                // or a division by zero: a metric that came out zero has no ratio.
                Direction::Lower if cell.value > 0.0 => *base / cell.value,
                Direction::Lower => return None,
            })
        })
        .collect();
    ratios.sort_by(f64::total_cmp);
    ratios
}

/// A bootstrap percentile interval over paired ratios.
///
/// Resamples the *pairs*, with replacement, and takes percentiles of the resampled
/// means. Seeded, so an interval is reproducible: an interval that moved between
/// two runs of the same data would be indistinguishable from a real change.
///
/// Returns `None` below [`MIN_PAIRS`], which is the "unproven" verdict rather
/// than a pass with a wide interval.
pub fn bootstrap_ci(ratios: &[f64]) -> Option<Interval> {
    if ratios.len() < MIN_PAIRS {
        return None;
    }
    let mut rng = Rng::new(BOOTSTRAP_SEED);
    let mut means = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    let n = ratios.len();
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let mut total = 0.0;
        for _ in 0..n {
            total += ratios[rng.below(n)];
        }
        means.push(total / n as f64);
    }
    means.sort_by(f64::total_cmp);
    Some(Interval {
        low: percentile(&means, 2.5),
        mid: percentile(&means, 50.0),
        high: percentile(&means, 97.5),
        pairs: n,
    })
}

/// A 95% bootstrap interval over the mean of a set of paired ratios.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Interval {
    pub low: f64,
    pub mid: f64,
    pub high: f64,
    pub pairs: usize,
}

impl Interval {
    /// Whether the **whole** interval says the candidate is worse than the
    /// reference by more than `tolerance`.
    ///
    /// This is the rule, and the reason for it (`zbench/report.py:885`): "A
    /// scenario fails when its whole interval lies on the wrong side of the
    /// tolerance. It is not enough for the point estimate to be worse: with three
    /// repeats a 4% regression and a 40% one look identical until the interval is
    /// read, and a gate that cannot tell them apart is a gate that fails at
    /// random."
    pub fn worse_than_reference(&self, tolerance: f64) -> bool {
        self.high < 1.0 - tolerance
    }

    /// Whether the **whole** interval says the candidate is better than the
    /// reference by more than `tolerance`.
    pub fn better_than_reference(&self, tolerance: f64) -> bool {
        self.low > 1.0 + tolerance
    }
}

/// The verdict on one row.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// The whole interval says the candidate is better by more than the
    /// tolerance.
    Better(Interval),
    /// The whole interval says the candidate is worse by more than the tolerance.
    Worse(Interval),
    /// The interval includes 1.0, or sits inside the tolerance. Not a claim of
    /// equality — a claim that this run cannot tell.
    WithinNoise(Interval),
    /// Fewer than [`MIN_PAIRS`] usable pairs, so no interval exists.
    Unproven,
}

impl Direction {
    /// The wire word for a matrix cell: `higher` reads "more is better".
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Higher => "higher",
            Self::Lower => "lower",
        }
    }
}

impl Verdict {
    /// The wire word for a matrix cell.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Better(_) => "better",
            Self::Worse(_) => "worse",
            Self::WithinNoise(_) => "within-noise",
            Self::Unproven => "unproven",
        }
    }
}

/// Read a verdict off an interval, using the metric's own direction.
///
/// The direction is what makes one ratio mean opposite things for throughput and
/// for memory: a ratio above `1.0` is an improvement in the first case and a
/// regression in the second. The comparison itself is symmetric — above `1.0` is
/// better in both — because the ratio is always candidate over reference, so
/// `Direction` records which rows are gated and how each is named, never how it is
/// read.
pub fn verdict(interval: Option<Interval>, direction: Direction) -> Verdict {
    let Some(i) = interval else {
        return Verdict::Unproven;
    };
    let _ = direction;
    if i.worse_than_reference(TOLERANCE) {
        Verdict::Worse(i)
    } else if i.better_than_reference(TOLERANCE) {
        Verdict::Better(i)
    } else {
        Verdict::WithinNoise(i)
    }
}

/// The gate over every row.
#[derive(Debug, Clone, PartialEq)]
pub struct Gate {
    pub passed: bool,
    /// One line per row, in report order.
    pub lines: Vec<String>,
}

impl Gate {
    /// A pass that gated nothing. Reported as a failure, not a success: "a gate
    /// that passes because nothing resolved anything is not a pass"
    /// (`zbench/report.py:968`).
    pub fn nothing_resolved(rows: usize) -> Self {
        Self {
            passed: false,
            lines: vec![format!(
                "no comparison: {rows} row(s) were measured and none resolved a \
                 difference of {:.0}% or more, so nothing was gated. That is a \
                 measurement too small to separate the two builds, not a finding \
                 of equality.",
                RESOLVABLE * 100.0
            )],
        }
    }

    /// An empty comparison. Fails, for the same reason.
    pub fn no_comparison() -> Self {
        Self {
            passed: false,
            lines: vec![
                "no comparison: no scenario produced a candidate/reference pair, so \
                 nothing could be gated"
                    .to_owned(),
            ],
        }
    }

    /// Rows were measured, but none of them gates.
    ///
    /// Its own line rather than `no_comparison`, because the two are different
    /// faults and a reader has to be able to tell them apart: this one means the
    /// run measured engines and then declined to judge any of them, which is a
    /// wiring mistake, where the other means it never got a pair at all.
    pub fn no_gated_row(rows: usize) -> Self {
        Self {
            passed: false,
            lines: vec![format!(
                "no gated row: {rows} row(s) were measured and every one of them is \
                 a pinned comparator, so the job's verdict had nothing to rest on. \
                 The engine under test has to be in the engine list."
            )],
        }
    }
}

/// One row of the gate: what it is, which way is better, its interval, and
/// whether the job's verdict depends on it.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub label: String,
    pub direction: Direction,
    pub interval: Option<Interval>,
    /// Whether a [`Verdict::Worse`] here fails the job.
    ///
    /// True for the engine this repository ships, and false for a pinned
    /// comparator. Both are published, because a reader who sees four engines and
    /// one verdict has to be able to tell which rows the verdict came from — but a
    /// comparator measuring slower than the reference is a fact about that
    /// comparator, not a regression in this tree. Gating on it hands the job's
    /// pass condition to a binary nobody here can change, and it did exactly that:
    /// from the run that added `zeronet` to the engine list onwards, `zeronet vs
    /// xray-core` read 0.51x–0.56x on `linux aarch64` in every run and failed
    /// every one of them, with no edit to this repository able to move it.
    pub gates: bool,
    /// Whether this row's inconclusiveness is attributable to the runner.
    ///
    /// Separate from [`Row::gates`] because the two answer different questions.
    /// `gates` asks whether the *subject* is this repository's to judge; this asks
    /// whether the *instrument* explains why a row could not tell.
    ///
    /// It never changes the verdict. A resolved row is resolved whatever the machine
    /// did and an unresolved row is unresolved; all this adds is the sentence "the
    /// runner moved further than the tolerance, which is why" beside a row that
    /// already said it could not tell. It exists because that attribution is
    /// otherwise missing: eight `linux x86_64` runs of one unchanged tree published
    /// throughput ratios from 0.696x to 1.126x and every one of them said only that
    /// it could not resolve.
    pub runner_blamed: bool,
}

impl Row {
    /// A row whose verdict decides the job.
    pub fn gating(
        label: impl Into<String>,
        direction: Direction,
        interval: Option<Interval>,
    ) -> Self {
        Self {
            label: label.into(),
            direction,
            interval,
            gates: true,
            runner_blamed: false,
        }
    }

    /// A row that is published and read, but does not decide the job.
    pub fn reported(
        label: impl Into<String>,
        direction: Direction,
        interval: Option<Interval>,
    ) -> Self {
        Self {
            label: label.into(),
            direction,
            interval,
            gates: false,
            runner_blamed: false,
        }
    }

    /// Note that this row could not tell *because the runner moved*, not because the
    /// engines were close.
    ///
    /// Takes and returns the row so a call site reads as a property of the row it is
    /// about rather than as a branch around it.
    pub fn runner_blamed(mut self) -> Self {
        self.runner_blamed = true;
        self
    }
}

/// Decide whether a candidate may land, from rows that say whether they gate.
///
/// Only [`Row::gates`] rows decide the verdict. A reported-only row is printed with
/// its own verdict and a `reported, not gated` marker, so the table and the gate
/// still cannot disagree about what was measured — the difference is only about
/// which rows the job's exit code depends on.
pub fn gate_rows(rows: &[Row]) -> Gate {
    if rows.is_empty() {
        return Gate::no_comparison();
    }
    let mut lines = Vec::new();
    let mut passed = true;
    let mut resolved = 0usize;
    let gated = rows.iter().filter(|r| r.gates).count();
    if gated == 0 {
        return Gate::no_gated_row(rows.len());
    }
    for row in rows {
        let v = verdict(row.interval, row.direction);
        let mut note = if row.gates {
            String::new()
        } else {
            " — reported, not gated: this row is a pinned comparator, so its \
             verdict is published and does not decide the job"
                .to_owned()
        };
        // Rendered here rather than trusted from the constructor: a marker attached
        // to a row that *did* resolve would say "this interval includes 1.0x" beside a
        // verdict saying it does not, which is worse than no marker. The invariant
        // holds because the renderer decides, not the call site.
        let inconclusive = matches!(v, Verdict::WithinNoise(_) | Verdict::Unproven);
        if row.runner_blamed && inconclusive {
            note.push_str(
                " — the runner's own throughput moved further than the tolerance above \
                 between repeats of one unchanged build, so this row cannot tell \
                 because of the machine rather than because the engines are close",
            );
        }
        // The marker changes nothing here. It is a sentence in the report, and a
        // row that carries it is inconclusive anyway -- the caller only attaches it
        // where the interval includes 1.0 -- so it cannot move the pass condition or
        // the resolved count. Saying so here is what keeps that true.
        let counts = row.gates;
        match v {
            Verdict::Better(i) => {
                if counts {
                    resolved += 1;
                }
                lines.push(format!(
                    "{}: better, 95% interval [{:.3}x, {:.3}x] over {} pairs \
                     (median {:.3}x), outside the {:.0}% tolerance{note}",
                    row.label,
                    i.low,
                    i.high,
                    i.pairs,
                    i.mid,
                    TOLERANCE * 100.0
                ));
            }
            Verdict::Worse(i) => {
                if counts {
                    resolved += 1;
                    passed = false;
                }
                lines.push(format!(
                    "{}: WORSE, 95% interval [{:.3}x, {:.3}x] over {} pairs \
                     (median {:.3}x). The whole interval is beyond the {:.0}% \
                     tolerance, so this is a resolved regression and not noise{note}",
                    row.label,
                    i.low,
                    i.high,
                    i.pairs,
                    i.mid,
                    TOLERANCE * 100.0
                ));
            }
            Verdict::WithinNoise(i) => lines.push(format!(
                "{}: within noise, 95% interval [{:.3}x, {:.3}x] over {} pairs \
                 (median {:.3}x) includes 1.0x, so this run cannot resolve a \
                 difference of {:.0}% or more{note}",
                row.label,
                i.low,
                i.high,
                i.pairs,
                i.mid,
                TOLERANCE * 100.0
            )),
            Verdict::Unproven => lines.push(format!(
                "{}: UNPROVEN, fewer than {MIN_PAIRS} usable pairs, so no \
                 interval exists. An unproven row is not a passing row{note}",
                row.label
            )),
        }
    }
    if resolved == 0 {
        return Gate::nothing_resolved(gated);
    }
    Gate { passed, lines }
}

/// Re-derive a run's aggregates from its raw samples and fail on any
/// disagreement.
///
/// `ZeroNet`'s `validate_results.py`, and its stated purpose: "What it deliberately
/// does *not* do is judge whether a number is good. A run where one core is three
/// times faster than another passes; a run where an aggregate does not match its
/// samples does not" (`zbench/validate_results.py:11`).
///
/// The median is re-implemented rather than imported, so a defect cannot appear
/// on both sides of the comparison.
pub fn rederive(raw: &[f64], reported_median: f64, reported_mean: f64) -> Result<(), String> {
    if raw.is_empty() {
        return Err("cannot re-derive an aggregate from no samples".to_owned());
    }
    let mut sorted = raw.to_vec();
    sorted.sort_by(f64::total_cmp);
    let median = if sorted.len().is_multiple_of(2) {
        // `midpoint` on the two middle values, which is the median on a sorted
        // slice and cannot overflow here: both are finite measurements.
        f64::midpoint(sorted[sorted.len() / 2 - 1], sorted[sorted.len() / 2])
    } else {
        sorted[sorted.len() / 2]
    };
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    if (median - reported_median).abs() > 1e-6 {
        return Err(format!(
            "the reported median {reported_median} does not match the samples' \
             median {median}"
        ));
    }
    if (mean - reported_mean).abs() > 1e-3 {
        return Err(format!(
            "the reported mean {reported_mean} does not match the samples' mean {mean}"
        ));
    }
    Ok(())
}

/// A xorshift64 generator, so a bootstrap interval is reproducible without a
/// dependency.
struct Rng {
    state: u64,
}

impl Rng {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// A value in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        assert!(n > 0, "below(0) has no answer");
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state % n as u64) as usize
    }
}

/// Percentile of a sorted slice by linear interpolation.
fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (pct / 100.0) * (sorted.len() - 1) as f64;
    let low = rank.floor() as usize;
    let high = rank.ceil() as usize;
    if low == high {
        return sorted[low];
    }
    sorted[low] + (rank - low as f64) * (sorted[high] - sorted[low])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every row gates, which is what the three-tuple form used to mean. Kept here
    /// rather than as a public wrapper so there is one gate function, not two.
    fn all_gating(rows: &[(String, Direction, Option<Interval>)]) -> Vec<Row> {
        rows.iter()
            .map(|(label, direction, interval)| Row::gating(label.clone(), *direction, *interval))
            .collect()
    }

    fn cell(run_index: usize, value: f64) -> Cell {
        Cell { run_index, value }
    }

    #[test]
    fn wire_words_name_direction_and_verdict() {
        assert_eq!(Direction::Higher.as_str(), "higher");
        assert_eq!(Direction::Lower.as_str(), "lower");
        let interval = Interval {
            low: 0.9,
            mid: 1.0,
            high: 1.1,
            pairs: 3,
        };
        assert_eq!(Verdict::Better(interval).as_str(), "better");
        assert_eq!(Verdict::Worse(interval).as_str(), "worse");
        assert_eq!(Verdict::WithinNoise(interval).as_str(), "within-noise");
        assert_eq!(Verdict::Unproven.as_str(), "unproven");
    }

    #[test]
    fn order_rotates_and_then_reverses() {
        let engines = ["a", "b", "c"];
        // Rotated by the repeat index, then reversed on alternate repeats, so no
        // engine is always measured first and none keeps the same relative
        // position across repeats.
        assert_eq!(rotate(&engines, 1), vec!["a", "b", "c"]);
        assert_eq!(rotate(&engines, 2), vec!["a", "c", "b"]);
        assert_eq!(rotate(&engines, 3), vec!["c", "a", "b"]);
        assert_eq!(rotate(&engines, 4), vec!["c", "b", "a"]);
        for repeat in 1..=6 {
            let order = rotate(&engines, repeat);
            assert_eq!(order.len(), 3);
            let mut sorted = order.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, engines.to_vec(), "every engine runs every repeat");
        }
    }

    #[test]
    fn order_of_one_engine_is_itself() {
        assert_eq!(rotate(&["only"], 1), vec!["only"]);
    }

    #[test]
    fn pairs_are_matched_by_repeat_index_not_by_order() {
        let candidate = vec![cell(1, 10.0), cell(2, 20.0), cell(3, 30.0)];
        let reference = vec![cell(1, 5.0), cell(3, 10.0)];
        let ratios = paired_ratios(&candidate, &reference, Direction::Higher);
        assert_eq!(ratios.len(), 2, "repeat 2 has no reference cell");
        assert!((ratios[0] - 2.0).abs() < 1e-9);
        assert!((ratios[1] - 3.0).abs() < 1e-9);
    }

    #[test]
    fn a_zero_reference_is_not_a_ratio() {
        let candidate = vec![cell(1, 10.0), cell(2, 20.0)];
        let reference = vec![cell(1, 0.0), cell(2, 0.0)];
        assert!(
            paired_ratios(&candidate, &reference, Direction::Higher).is_empty(),
            "a zero reference must produce no ratios at all"
        );
        assert!(
            paired_ratios(&candidate, &reference, Direction::Lower).is_empty(),
            "a zero candidate must produce no ratios for a lower-is-better metric"
        );
    }

    #[test]
    fn a_single_pair_is_unproven_not_a_pass() {
        let ratios = vec![1.5];
        assert!(bootstrap_ci(&ratios).is_none());
        assert_eq!(verdict(None, Direction::Higher), Verdict::Unproven);
    }

    /// The gate's own unit test, and the reason it exists: a 40% regression must
    /// fail and a 3% one must not, at the same tolerance.
    #[test]
    fn the_gate_separates_a_real_regression_from_the_tolerance_band() {
        // A clearly-better row alongside, so the gate has something to resolve and
        // is not judged on the row under test alone.
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let at = |offset: f64| Interval {
            low: 1.0 + offset,
            mid: 1.0 + offset,
            high: 1.0 + offset,
            pairs: 5,
        };
        let with = |i: Interval| {
            vec![
                ("throughput".into(), Direction::Higher, Some(i)),
                ("cpu".into(), Direction::Lower, Some(better)),
            ]
        };
        assert!(
            !gate_rows(&all_gating(&with(at(-0.40)))).passed,
            "a 40% regression must fail"
        );
        assert!(
            gate_rows(&all_gating(&with(at(-0.04)))).passed,
            "a 4% regression must pass a 5% gate"
        );
        assert!(gate_rows(&all_gating(&with(at(0.04)))).passed);
    }

    /// A wide interval that straddles 1.0 must not fail, however bad its point
    /// estimate looks. This is the difference between a gate that measures and a
    /// gate that fails at random.
    #[test]
    fn a_noisy_interval_with_a_bad_point_estimate_does_not_fail() {
        let noisy = Interval {
            low: 0.85,
            mid: 0.90,
            high: 1.10,
            pairs: 5,
        };
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let g = gate_rows(&all_gating(&[
            ("throughput".into(), Direction::Higher, Some(noisy)),
            ("cpu".into(), Direction::Lower, Some(better)),
        ]));
        assert!(g.passed, "{:?}", g.lines);
        assert!(g.lines[0].contains("within noise"));
    }

    #[test]
    fn an_empty_comparison_fails() {
        let g = gate_rows(&[]);
        assert!(!g.passed);
        assert!(g.lines[0].contains("no comparison"));
    }

    /// A gate that passes because nothing resolved is not a pass.
    #[test]
    fn resolving_nothing_fails_the_gate() {
        let tight = Interval {
            low: 0.99,
            mid: 1.0,
            high: 1.01,
            pairs: 5,
        };
        let g = gate_rows(&all_gating(&[(
            "throughput".into(),
            Direction::Higher,
            Some(tight),
        )]));
        assert!(!g.passed);
        assert!(g.lines[0].contains("none resolved"));
    }

    #[test]
    fn an_unproven_row_alone_does_not_pass() {
        let g = gate_rows(&all_gating(&[(
            "throughput".into(),
            Direction::Higher,
            None,
        )]));
        assert!(!g.passed);
    }

    #[test]
    fn one_bad_row_fails_the_whole_gate() {
        let good = Interval {
            low: 1.10,
            mid: 1.20,
            high: 1.30,
            pairs: 5,
        };
        let bad = Interval {
            low: 0.50,
            mid: 0.55,
            high: 0.60,
            pairs: 5,
        };
        let g = gate_rows(&all_gating(&[
            ("throughput".into(), Direction::Higher, Some(good)),
            ("cpu".into(), Direction::Lower, Some(bad)),
        ]));
        assert!(!g.passed);
        assert!(g.lines.iter().any(|l| l.contains("WORSE")));
    }

    /// A pinned comparator measuring worse is published and does not fail the job.
    ///
    /// The rule exists because the alternative handed this repository's verdict to
    /// `zeronet`: at 0.51x–0.56x of `xray-core` on `linux aarch64` it failed every
    /// run from the one that added it, and nothing in this tree can move it.
    #[test]
    fn a_reported_row_is_printed_but_does_not_decide_the_job() {
        let worse = Interval {
            low: 0.50,
            mid: 0.55,
            high: 0.60,
            pairs: 5,
        };
        let better = Interval {
            low: 1.10,
            mid: 1.20,
            high: 1.30,
            pairs: 5,
        };
        let ours = "throughput (ferrox vs xray-core)";
        let theirs = "throughput (zeronet vs xray-core)";
        let g = gate_rows(&[
            Row::gating(ours, Direction::Higher, Some(better)),
            Row::reported(theirs, Direction::Higher, Some(worse)),
        ]);
        assert!(g.passed, "{:?}", g.lines);
        let line = g
            .lines
            .iter()
            .find(|l| l.starts_with(theirs))
            .expect("the comparator row is published");
        assert!(line.contains("WORSE"), "{line}");
        assert!(line.contains("not gated"), "{line}");
    }

    /// The same interval, gated instead of reported, must still fail. Otherwise
    /// the rule above would be a way to switch the gate off.
    #[test]
    fn the_same_row_gated_still_fails() {
        let worse = Interval {
            low: 0.50,
            mid: 0.55,
            high: 0.60,
            pairs: 5,
        };
        let better = Interval {
            low: 1.10,
            mid: 1.20,
            high: 1.30,
            pairs: 5,
        };
        let ours = "throughput (ferrox vs xray-core)";
        let theirs = "throughput (other vs xray-core)";
        let g = gate_rows(&[
            Row::gating(ours, Direction::Higher, Some(better)),
            Row::gating(theirs, Direction::Higher, Some(worse)),
        ]);
        assert!(!g.passed, "{:?}", g.lines);
    }

    /// Measured rows and no gated row is a wiring fault, not a pass.
    #[test]
    fn rows_that_all_report_fail_the_gate() {
        let better = Interval {
            low: 1.20,
            mid: 1.30,
            high: 1.40,
            pairs: 5,
        };
        let theirs = "throughput (zeronet vs xray-core)";
        let g = gate_rows(&[Row::reported(theirs, Direction::Higher, Some(better))]);
        assert!(!g.passed);
        assert!(g.lines[0].contains("no gated row"), "{:?}", g.lines);
    }

    /// The marker this row carries must never contradict the verdict above it.
    ///
    /// It was built as a *veto* -- a row on a noisy runner got no verdict at all --
    /// and the first run it was measured on printed `better, 95% interval [1.221x,
    /// 1.632x]` and `NOT CERTIFIED` on the same line. A tight paired interval is
    /// better evidence than an unpaired best/worst ratio, so the marker now only
    /// ever *adds a reason* to a row that already said it could not tell.
    #[test]
    fn the_runner_marker_attaches_only_to_a_row_that_could_not_tell() {
        let resolved_better = Interval {
            low: 1.221,
            mid: 1.388,
            high: 1.632,
            pairs: 7,
        };
        let resolved_worse = Interval {
            low: 0.573,
            mid: 0.696,
            high: 0.897,
            pairs: 7,
        };
        let inconclusive = Interval {
            low: 0.623,
            mid: 0.857,
            high: 1.081,
            pairs: 7,
        };

        // A second, resolved row is present in every case because `gate_rows`
        // replaces its lines with a single "nothing resolved" when a run's only row
        // is inconclusive -- which is the same rule this test is about, one level up.
        let rss = Row::gating(
            "peak rss",
            Direction::Lower,
            Some(Interval {
                low: 10.9,
                mid: 11.0,
                high: 11.2,
                pairs: 7,
            }),
        );

        for interval in [resolved_better, resolved_worse] {
            let g = gate_rows(&[
                Row::runner_blamed(Row::gating("throughput", Direction::Higher, Some(interval))),
                rss.clone(),
            ]);
            let throughput = g
                .lines
                .iter()
                .find(|l| l.starts_with("throughput"))
                .expect("the throughput row is published");
            assert!(
                !throughput.contains("runner's own throughput moved"),
                "a resolved row must not be re-read as the runner's fault: {throughput}"
            );
            assert!(
                throughput.contains("better") || throughput.contains("WORSE"),
                "and must keep its own verdict: {throughput}"
            );
        }

        // And on an inconclusive row the marker says so without changing the verdict.
        let g = gate_rows(&[
            Row::runner_blamed(Row::gating(
                "throughput",
                Direction::Higher,
                Some(inconclusive),
            )),
            rss,
        ]);
        let throughput = g
            .lines
            .iter()
            .find(|l| l.starts_with("throughput"))
            .expect("the throughput row is published");
        assert!(throughput.contains("within noise"), "{throughput}");
        assert!(
            throughput.contains("runner's own throughput moved"),
            "an inconclusive row on a noisy runner must say whose fault that is: {throughput}"
        );
    }

    #[test]
    fn the_bootstrap_is_reproducible_and_brackets_the_mean() {
        let ratios = vec![1.02, 1.05, 0.99, 1.01, 1.03, 1.00, 1.04];
        let a = bootstrap_ci(&ratios).expect("interval");
        let b = bootstrap_ci(&ratios).expect("interval");
        assert_eq!(a, b, "the same data must give the same interval");
        assert!(a.low <= a.mid && a.mid <= a.high);
        assert!(a.low < 1.05 && a.high > 1.0, "{a:?}");
        assert_eq!(a.pairs, 7);
    }

    /// The trap this module exists to avoid: an engine using a sixteenth of the
    /// memory must not read as a sixteen-fold regression.
    #[test]
    fn a_lower_is_better_metric_is_oriented_so_more_is_better() {
        let candidate = vec![cell(1, 2.0), cell(2, 2.0), cell(3, 2.0)];
        let reference = vec![cell(1, 32.0), cell(2, 32.0), cell(3, 32.0)];
        let lower = paired_ratios(&candidate, &reference, Direction::Lower);
        assert!(
            lower.iter().all(|r| (*r - 16.0).abs() < 1e-9),
            "reference/candidate must be 16, not 1/16: {lower:?}"
        );
        assert!(matches!(
            verdict(bootstrap_ci(&lower), Direction::Lower),
            Verdict::Better(_)
        ));
        let higher = paired_ratios(&candidate, &reference, Direction::Higher);
        assert!(matches!(
            verdict(bootstrap_ci(&higher), Direction::Higher),
            Verdict::Worse(_)
        ));
    }

    #[test]
    fn a_consistent_regression_resolves_where_a_scatter_does_not() {
        let consistent = vec![0.60, 0.62, 0.59, 0.61, 0.60];
        let scattered = vec![0.60, 0.95, 0.75, 1.05, 0.65];
        assert_eq!(
            verdict(bootstrap_ci(&consistent), Direction::Higher),
            Verdict::Worse(bootstrap_ci(&consistent).expect("interval")),
        );
        assert!(matches!(
            verdict(bootstrap_ci(&scattered), Direction::Higher),
            Verdict::WithinNoise(_)
        ));
    }

    #[test]
    fn rederivation_catches_a_wrong_aggregate() {
        let raw = [1.0, 2.0, 3.0, 4.0];
        assert!(rederive(&raw, 2.5, 2.5).is_ok());
        assert!(
            rederive(&raw, 3.0, 2.5).is_err(),
            "a wrong median must fail"
        );
        assert!(rederive(&raw, 2.5, 9.0).is_err(), "a wrong mean must fail");
        assert!(rederive(&[], 0.0, 0.0).is_err(), "no samples must fail");
    }

    #[test]
    fn rederivation_uses_its_own_median() {
        // Even count: 2.5, and a mean of exactly 2.5.
        assert!(rederive(&[1.0, 2.0, 3.0, 4.0], 2.5, 2.5).is_ok());
        // Odd count: 3.
        assert!(rederive(&[1.0, 2.0, 3.0, 4.0, 5.0], 3.0, 3.0).is_ok());
    }

    #[test]
    fn the_generator_stays_in_range() {
        let mut rng = Rng::new(BOOTSTRAP_SEED);
        for _ in 0..1000 {
            assert!(rng.below(7) < 7, "the generator left 0..7");
        }
    }

    #[test]
    fn percentiles_interpolate() {
        assert_eq!(percentile(&[1.0], 50.0), 1.0);
        assert_eq!(percentile(&[], 50.0), 0.0);
        let v = percentile(&[0.0, 10.0], 50.0);
        assert!((v - 5.0).abs() < 1e-9);
    }

    /// The published constants are the point of this module; a silent change to
    /// one would change what the gate means without changing what it says.
    #[test]
    fn the_thresholds_are_the_published_ones() {
        assert_eq!(MIN_RUNS, 3);
        assert_eq!(MIN_PAIRS, 2);
        assert_eq!(BOOTSTRAP_RESAMPLES, 4000);
        assert_eq!(BOOTSTRAP_SEED, 20_260_902);
        assert!((TOLERANCE - 0.05).abs() < f64::EPSILON);
        assert!((RESOLVABLE - 0.05).abs() < f64::EPSILON);
        assert!((HARNESS_BOUND - 0.85).abs() < f64::EPSILON);
    }

    /// The CPU resolution the report publishes must be the resolution of the
    /// mechanism that produced the row beside it, on whichever host runs the test.
    ///
    /// It used to be asserted as the constant 10, which is what it is on Linux and
    /// macOS and what it must *not* claim to be on a host whose `ps` prints whole
    /// seconds -- that claim is the bug this whole change is about. So the identity
    /// is with the mechanism, and the two values it does resolve to are pinned here.
    #[test]
    fn the_cpu_resolution_is_the_mechanisms_not_a_typed_in_number() {
        let published = crate::parity::cpu_resolution_floor_millis();
        assert_eq!(
            published,
            crate::ps::CpuSource::current().resolution_millis()
        );
        assert!(published > 0, "a floor of zero resolves nothing");
        match crate::ps::Host::current() {
            crate::ps::Host::Linux => {
                assert_eq!(
                    crate::ps::CpuSource::current(),
                    crate::ps::CpuSource::ProcStat
                );
                assert_eq!(published, 10, "USER_HZ is 100 on every Linux");
            }
            crate::ps::Host::Macos => {
                assert_eq!(
                    crate::ps::CpuSource::current(),
                    crate::ps::CpuSource::PsTime
                );
                assert_eq!(published, 10, "BSD ps prints hundredths");
            }
            // Windows reads a 100-nanosecond counter, so it publishes the finest
            // floor in the matrix. It is the only runner that can resolve a transfer
            // shorter than 10 ms, which is what gate 5's default workload runs at.
            crate::ps::Host::Windows => assert_eq!(published, 1),
            // An unrecognised host is assumed to resolve *less*, so a floor it
            // publishes never overstates what it can see.
            crate::ps::Host::Other => assert_eq!(published, 1_000),
        }
    }
}
