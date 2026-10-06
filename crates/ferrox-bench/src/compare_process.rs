//! The comparison itself: several engines, one workload, `ZeroNet`'s gate.
//!
//! This is the part that answers the question the four gates in `main.rs` cannot.
//! Those gates compare this workspace's record layer against a same-language
//! reference, at nanoseconds per call, in one process. They say nothing about the
//! path an engine actually takes: accept a SOCKS connection, relay through a
//! `VLESS` header, copy bytes, and be resident while doing it. That path is where
//! a Rust core and a Go core differ, and it is the only one a user experiences.
//!
//! # What is measured and against whom
//!
//! Each engine is measured as a child process over the *same* validated workload
//! and the *same* config shape, and the comparison is paired on the repeat index
//! with the engine order rotated and reversed (`stats::rotate`). The engines come
//! from `upstream/pins.toml`, each built from its pin, so a number names the thing
//! it was measured against.
//!
//! # The rows, and which of them can fail
//!
//! | row | direction | gated |
//! |---|---|---|
//! | throughput | higher is better | yes |
//! | CPU per GiB | lower is better | yes |
//! | peak RSS | lower is better | with [`stats::RSS_TOLERANCE`] |
//! | setup, median | lower is better | reported |
//!
//! RSS is held to a tolerance rather than to `ZeroNet`'s zero allowance, for the
//! reason given in `stats`. The publish/report side is in [`Comparison::report`].

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::json::{self, Json};
use crate::parity::{self, ConfigArg, Error, Request, Run};
use crate::stats::{self, Cell, Direction};

/// What a gate-5 row is not, printed on every report.
///
/// The gaps are named rather than left out. `ZeroNet`'s coverage grid is explicit
/// that a row's absence must be marked as a gap and not silently dropped
/// (`upstream/zeronet/docs/benchmarks/harness/zbench/xrayrust_suite.py:19`), and
/// this is the same statement for this harness.
fn caveat() -> String {
    format!(
        "\n> **What this row is not.** `ps` samples RSS and CPU from outside the \
         > process, which is the only way a Go engine and a Rust engine are \
         > comparable at all, but it sees no allocation counts: those stay \
         > in-process and exact, in gates 2 and 4. A CPU delta under {n} ms reads \
         > as `0`, so a `0` in that column means \"below the kernel's resolution\", \
         > not \"free\". Only the `SOCKS` path is measured: `TUN`, DNS, geodata \
         > routing, and the `REALITY`/Vision TLS paths are the pinned harness's \
         > workloads and are **not** covered here — `docs/methodology.md` lists \
         > each one as `not_covered` with its reason, rather than leaving it out.\n",
        n = parity::cpu_resolution_floor_millis()
    )
}

/// Readings inside the transfer window below which the CPU column is a reading
/// rather than a measurement.
///
/// The sampling period is 100 ms and the kernel's CPU accounting resolution is
/// 10 ms, so three readings is the point at which a delta has more than one
/// interval in it. Below this the cell is printed in bold, which means "do not
/// read this as a CPU cost".
pub const MIN_TRAFFIC_SAMPLES: usize = 3;

/// One engine to measure.
#[derive(Debug, Clone)]
pub struct Engine {
    /// The label that appears in every table and in the pin it came from.
    pub name: &'static str,
    /// The executable.
    pub path: PathBuf,
    /// How this engine is told which config file to serve.
    pub config_arg: ConfigArg,
    /// Whether this is the engine under test, and so the one whose rows decide
    /// gate 5. False for a pinned comparator.
    pub gated: bool,
    /// The config shape this engine parses.
    pub dialect: parity::Dialect,
    /// The inbound protocols this engine can serve, as the scenario ids name them.
    ///
    /// An empty list means "every protocol", which is what an engine that parses
    /// the whole Xray config surface gets. A non-empty one is an engine that serves
    /// only some of them, and the matrix has one of those: `xray-rust` at its pin
    /// accepts `socks`, `http` and `tun` inbounds and rejects `vless`, `vmess`,
    /// `shadowsocks` and `trojan` outright (`crates/xray-config/src/parser.rs:636`).
    ///
    /// Without this, every protocol scenario handed it a config it could not parse,
    /// it exited during startup, and the harness reported that as a **failed
    /// engine** -- three red rows per cell, on every runner, for a binary that was
    /// never going to serve those protocols. The distinction the report draws
    /// between skipped and failed is exactly the one being lost: skipped is the
    /// roadmap, failed is a fault, and an engine that does not implement a protocol
    /// is the first of those.
    pub protocols: &'static [&'static str],
}

/// The workload every engine is measured against.
#[derive(Debug, Clone)]
pub struct Workload {
    pub traffic: String,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    /// Whether each engine gets a warmup connection before its measured run.
    pub warmup: bool,
    /// Full engine config used instead of the dialect default, empty for none.
    ///
    /// Custom scenario documents are Xray-dialect: only engines that read that
    /// spelling run them, and the rest sit the scenario out with a named
    /// reason rather than failing every repeat. The freedom default keeps its
    /// empty string, so gate 5 never touches this path.
    pub outbound_config: String,
    /// The scenario id this cell belongs to, whose leading rung names the protocol.
    ///
    /// `participant_names` reads it to decide which engines can serve the cell, so
    /// an engine that does not implement the scenario's protocol sits out with a
    /// reason instead of being handed a config it cannot parse and reported as
    /// broken. Empty for a workload with no scenario behind it.
    pub scenario: String,
}

impl Workload {
    /// Bytes each flow moves.
    fn flow_bytes(&self) -> u64 {
        (self.iterations * self.payload_size) as u64
    }

    /// Bytes the whole workload moves, **both directions of a full-duplex cell**.
    ///
    /// The report header prints this as "MiB total", so for `full-duplex` it was
    /// naming half the bytes the run actually moved -- the same miscount the
    /// harness itself had, which is what failed the duplex rows. `parity` decides
    /// what a run must actually deliver; this is the number a reader compares it
    /// against, and the two have to agree.
    fn total_bytes(&self) -> u64 {
        let directions = match self.traffic.as_str() {
            "full-duplex" => 2u64,
            _ => 1,
        };
        (self.flow_bytes() * self.connections as u64).saturating_mul(directions)
    }

    /// The request an engine is measured with, written to `output`.
    ///
    /// `output` must not exist, which the request validator enforces, so each
    /// repeat gets its own directory and a stale one cannot be read as a result.
    fn request(&self, engine: &Engine, output: &Path) -> String {
        let mut root = Json::object();
        root.insert("binary", Json::Str(engine.path.display().to_string()));
        // The config the engine is handed is built from its own dialect, so one
        // workload means the same work in four config languages and no engine is
        // asked to parse a document written for a different one. A scenario
        // document overrides that per engine that reads it; the rest sit out
        // with a reason in `run` rather than failing to parse.
        let config = if self.outbound_config.trim().is_empty() {
            engine
                .dialect
                .base_config()
                .to_string()
                .expect("a document built from strings and counts always serialises")
        } else {
            self.outbound_config.clone()
        };
        root.insert("config", Json::Str(config));
        root.insert("path", Json::Str("socks".into()));
        root.insert("traffic", Json::Str(self.traffic.clone()));
        root.insert("connections", Json::Num(self.connections as f64));
        root.insert("iterations", Json::Num(self.iterations as f64));
        root.insert("payload_size", Json::Num(self.payload_size as f64));
        root.insert("output", Json::Str(output.display().to_string()));
        root.insert("warmup", Json::Bool(self.warmup));
        root.to_string()
            .expect("a document built from strings and counts always serialises")
    }

    /// One line naming the workload, for the report header.
    fn describe(&self) -> String {
        format!(
            "{} x {} flows of {} iterations at {} B ({} MiB total)",
            self.traffic,
            self.connections,
            self.iterations,
            self.payload_size,
            self.total_bytes() as f64 / (1024.0 * 1024.0)
        )
    }
}

/// What one engine's repeats produced.
#[derive(Debug)]
pub struct EngineRuns {
    pub engine: &'static str,
    /// The config shape this engine was handed, kept beside its runs so the
    /// report can name it even when the engine produced none -- an engine that
    /// failed to start is precisely the one whose config shape a reader needs.
    pub dialect: parity::Dialect,
    pub runs: Vec<Run>,
}

/// Everything the report needs.
#[derive(Debug)]
pub struct Comparison {
    pub workload: Workload,
    pub repeats: usize,
    pub by_engine: Vec<EngineRuns>,
    /// One ceiling measurement per repeat, taken with no engine in the path and
    /// interleaved with that repeat's engines.
    ///
    /// A vector rather than one number because one number is a sample of the
    /// runner at one moment, and the runner is what varies: the same tree
    /// published 2220 to 5724 MiB/s of ceiling across eight `linux x86_64` runs.
    /// Per repeat, each engine has a ceiling measured seconds away from it, and
    /// the spread across repeats is the machine's own variance *measured* rather
    /// than assumed -- see [`Comparison::runner_spread`].
    pub ceilings_mib_s: Vec<f64>,
    /// The engine whose rows decide the gate, or `None` when the caller named no
    /// engine under test — which fails the gate rather than passing it vacuously.
    pub gated: Option<&'static str>,
    /// Errors, per engine, with the reason. A cell that failed is never blank.
    pub failures: Vec<(String, String)>,
    /// Engines that never attempted the scenario, with the reason. Custom
    /// scenario documents are Xray-dialect; an engine that reads another
    /// spelling sits out rather than failing to parse, which would measure a
    /// config error and report it as the engine. Skipped is gray, failed is
    /// red: one is the roadmap and the other is a fault.
    pub skipped: Vec<(String, String)>,
    pub machine: String,
}

/// One repeat as JSON: throughput plus the cost columns the charts need
/// beside it (peak threads, cold start, transfer window). All three are in
/// every result.json already; carrying them keeps the cell self-contained so
/// the renderer never re-globs the runs directory for a number beside the
/// medians. A run without a thread peak contributes null, never zero.
fn run_cell_json(run: &Run) -> Json {
    let mut cell = Json::object();
    cell.insert("throughput_mib_s", Json::Num(run.throughput_mib_s()));
    cell.insert("cpu_millis_per_gib", Json::Num(run.cpu_millis_per_gib()));
    cell.insert("rss_mib", Json::Num(run.rss_mib()));
    cell.insert(
        "threads_peak",
        match run.outcome.threads_peak {
            Some(t) => Json::Num(t as f64),
            None => Json::Null,
        },
    );
    cell.insert("startup_seconds", Json::Num(run.outcome.startup_seconds));
    cell.insert(
        "transfer_seconds",
        Json::Num(run.outcome.transfer.as_secs_f64()),
    );
    cell
}

impl Comparison {
    /// Throughput cells for one engine, one per repeat.
    fn throughput_cells(&self, engine: &str) -> Vec<Cell> {
        self.runs(engine)
            .iter()
            .enumerate()
            .map(|(i, run)| Cell {
                run_index: i + 1,
                value: run.throughput_mib_s(),
            })
            .collect()
    }

    /// CPU-per-GiB cells for one engine.
    fn cpu_cells(&self, engine: &str) -> Vec<Cell> {
        self.runs(engine)
            .iter()
            .enumerate()
            .map(|(i, run)| Cell {
                run_index: i + 1,
                value: run.cpu_millis_per_gib(),
            })
            .collect()
    }

    /// RSS cells for one engine.
    fn rss_cells(&self, engine: &str) -> Vec<Cell> {
        self.runs(engine)
            .iter()
            .enumerate()
            .map(|(i, run)| Cell {
                run_index: i + 1,
                value: run.rss_mib(),
            })
            .collect()
    }

    fn runs(&self, engine: &str) -> &[Run] {
        self.by_engine
            .iter()
            .find(|e| e.engine == engine)
            .map_or(&[], |e| e.runs.as_slice())
    }

    /// The engine every other engine is measured against: the first one, which
    /// the caller orders as the reference. Named in the report so a ratio cannot
    /// be read without knowing what it is against.
    fn reference(&self) -> Option<&'static str> {
        self.by_engine.first().map(|e| e.engine)
    }

    /// Every engine other than the reference.
    fn candidates(&self) -> Vec<&'static str> {
        let Some(reference) = self.reference() else {
            return Vec::new();
        };
        self.by_engine
            .iter()
            .map(|e| e.engine)
            .filter(|name| *name != reference)
            .collect()
    }

    /// Whether a throughput row that *could not tell* should say whose fault that is.
    ///
    /// The paired interval is the resolution measure and it alone decides the
    /// verdict; this never overrides it, in either direction. The raw ceiling spread
    /// is a coarser, unpaired number, and letting it overrule a tight interval is how
    /// one run printed `better, 95% interval [1.221x, 1.632x]` and `NOT CERTIFIED`
    /// on the same line.
    ///
    /// What it adds is the *reason* a row includes 1.0. Eight `linux x86_64` runs of
    /// one unchanged tree published throughput ratios from 0.696x to 1.126x while the
    /// runner's own ceiling moved 2.7x: with a ceiling spread in hand, "this run
    /// cannot tell" is attributable rather than merely stated. So the marker applies
    /// exactly when the interval is inconclusive *and* the machine moved further than
    /// the tolerance, which is additive and can never contradict the verdict above it.
    fn throughput_uncertain_because_of_the_runner(
        &self,
        interval: Option<stats::Interval>,
    ) -> bool {
        self.runner_spread()
            .is_some_and(|spread| spread > stats::TOLERANCE)
            && interval.is_some_and(|i| {
                !i.worse_than_reference(stats::TOLERANCE)
                    && !i.better_than_reference(stats::TOLERANCE)
            })
    }

    /// The gate: one row per metric, per engine, against the reference.
    ///
    /// Every engine is measured and every row is published; only the rows for the
    /// engine under test decide the verdict. Gating the comparators as well would
    /// be the same defect as printing a table of four and gating one: it makes the
    /// job's pass condition a property of a pinned binary this repository does not
    /// build. See [`stats::Row::gates`].
    ///
    /// A throughput row that cannot tell says whether the runner is why; see
    /// [`Comparison::throughput_uncertain_because_of_the_runner`].
    pub fn gate(&self) -> stats::Gate {
        if self.reference().is_none() {
            return stats::Gate::no_comparison();
        }
        let candidates = self.candidates();
        if candidates.is_empty() {
            return stats::Gate::no_comparison();
        }
        stats::gate_rows(&self.rows())
    }

    /// The gate rows without the verdict: the same rows [`Comparison::gate`]
    /// judges, for the machine-readable cell [`Comparison::comparison_json`]
    /// reports alongside the markdown.
    fn rows(&self) -> Vec<stats::Row> {
        let Some(reference) = self.reference() else {
            return Vec::new();
        };
        let candidates = self.candidates();
        if candidates.is_empty() {
            return Vec::new();
        }
        candidates
            .into_iter()
            .flat_map(|candidate| {
                let gates = Some(candidate) == self.gated;
                [
                    (
                        format!("throughput ({candidate} vs {reference})"),
                        Direction::Higher,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.throughput_cells(candidate),
                            &self.throughput_cells(reference),
                            Direction::Higher,
                        )),
                    ),
                    (
                        format!("cpu per GiB ({candidate} vs {reference})"),
                        Direction::Lower,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.cpu_cells(candidate),
                            &self.cpu_cells(reference),
                            Direction::Lower,
                        )),
                    ),
                    (
                        format!(
                            "peak rss ({candidate} vs {reference}, {:.0}% tolerance)",
                            stats::RSS_TOLERANCE * 100.0
                        ),
                        Direction::Lower,
                        stats::bootstrap_ci(&stats::paired_ratios(
                            &self.rss_cells(candidate),
                            &self.rss_cells(reference),
                            Direction::Lower,
                        )),
                    ),
                ]
                .into_iter()
                .map(move |(label, direction, interval)| {
                    let row = if gates {
                        stats::Row::gating(label.clone(), direction, interval)
                    } else {
                        stats::Row::reported(label.clone(), direction, interval)
                    };
                    if label.starts_with("throughput")
                        && self.throughput_uncertain_because_of_the_runner(interval)
                    {
                        stats::Row::runner_blamed(row)
                    } else {
                        row
                    }
                })
            })
            .collect()
    }

    /// One measured cell as machine-readable JSON, for the benchmark matrix.
    ///
    /// The markdown [`Comparison::report`] is for readers; this document is for
    /// `scripts/render-benchmark-charts.py`, which plots it, and
    /// `scripts/validate-benchmark-matrix.py`, which re-derives every verdict
    /// from the intervals here rather than trusting them. Verdicts come from the
    /// same [`Comparison::gate`] rows the report prints, so the two documents
    /// cannot disagree about what was measured.
    pub fn comparison_json(&self, scenario: &str) -> Result<String, String> {
        fn interval_json(interval: Option<stats::Interval>) -> Json {
            match interval {
                Some(i) => {
                    let mut o = Json::object();
                    o.insert("low", Json::Num(i.low));
                    o.insert("mid", Json::Num(i.mid));
                    o.insert("high", Json::Num(i.high));
                    o.insert("pairs", Json::Num(i.pairs as f64));
                    o
                }
                None => Json::Null,
            }
        }
        let mut root = Json::object();
        root.insert("scenario", Json::Str(scenario.to_owned()));
        let mut workload = Json::object();
        workload.insert("traffic", Json::Str(self.workload.traffic.clone()));
        workload.insert("connections", Json::Num(self.workload.connections as f64));
        workload.insert("iterations", Json::Num(self.workload.iterations as f64));
        workload.insert("payload_size", Json::Num(self.workload.payload_size as f64));
        workload.insert("repeats", Json::Num(self.repeats as f64));
        root.insert("workload", workload);
        root.insert("machine", Json::Str(self.machine.clone()));
        root.insert(
            "reference",
            self.reference()
                .map_or(Json::Null, |name| Json::Str(name.to_owned())),
        );
        let mut engines = Vec::new();
        for entry in &self.by_engine {
            let mut engine = Json::object();
            engine.insert("name", Json::Str(entry.engine.to_owned()));
            engine.insert(
                "binary_sha256",
                entry
                    .runs
                    .first()
                    .map_or(Json::Null, |run| Json::Str(run.engine_sha256.clone())),
            );
            let mut runs = Vec::new();
            for run in &entry.runs {
                runs.push(run_cell_json(run));
            }
            engine.insert("runs", Json::Arr(runs));
            engines.push(engine);
        }
        root.insert("engines", Json::Arr(engines));
        let gate = self.gate();
        let mut rows = Vec::new();
        for row in self.rows() {
            let mut item = Json::object();
            item.insert("label", Json::Str(row.label.clone()));
            item.insert("direction", Json::Str(row.direction.as_str().into()));
            item.insert("interval", interval_json(row.interval));
            item.insert(
                "verdict",
                Json::Str(stats::verdict(row.interval, row.direction).as_str().into()),
            );
            item.insert("gates", Json::Bool(row.gates));
            rows.push(item);
        }
        root.insert("rows", Json::Arr(rows));
        root.insert("gate_passed", Json::Bool(gate.passed));
        let mut failures = Vec::new();
        for (engine, reason) in &self.failures {
            let mut item = Json::object();
            item.insert("engine", Json::Str(engine.clone()));
            item.insert("reason", Json::Str(reason.clone()));
            failures.push(item);
        }
        root.insert("failures", Json::Arr(failures));
        let mut skipped = Vec::new();
        for (engine, reason) in &self.skipped {
            let mut item = Json::object();
            item.insert("engine", Json::Str(engine.clone()));
            item.insert("reason", Json::Str(reason.clone()));
            skipped.push(item);
        }
        root.insert("skipped", Json::Arr(skipped));
        root.insert(
            "harness_ceilings_mib_s",
            Json::Arr(
                self.ceilings_mib_s
                    .iter()
                    .map(|ceiling| Json::Num(*ceiling))
                    .collect(),
            ),
        );
        root.to_string()
    }

    /// The markdown section, appended to the benchmark report.
    /// The markdown section, appended to the benchmark report.
    ///
    /// Split into one method per table so each is readable on its own and a
    /// change to one does not have to be read past the other three.
    pub fn report(&self) -> String {
        let mut s = self.preamble();
        s.push_str(&self.failure_note());
        s.push_str(&self.headline_table());
        s.push_str(&self.per_repeat_table());
        s.push_str(&self.medians_table());
        s.push_str(&self.gate_section());
        s.push_str(&caveat());
        s
    }

    /// What was measured, against whom, and how.
    fn preamble(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "\n## Gate 5 — process-level comparison\n");
        let _ = writeln!(
            s,
            "Each engine runs as a child process over one validated workload, driven \
             through a `SOCKS5` inbound the harness injects — the contract the \
             pinned `xray-rust` harness defines \
             (`upstream/xray-rust/crates/xray-bench/src/protocol_bench.rs:122`) \
             and `ferrox-app` satisfies, so one request file measures either \
             binary. Their harness is `MPL-2.0` and is run from its pin rather than \
             copied; the request and result schemas are reproduced so the files mean \
             the same thing on both sides.\n"
        );
        let _ = writeln!(s, "| | |");
        let _ = writeln!(s, "| --- | --- |");
        let _ = writeln!(s, "| workload | {} |", self.workload.describe());
        let _ = writeln!(s, "| repeats | {} |", self.repeats);
        let _ = writeln!(
            s,
            "| engines and config dialects | {} |",
            self.by_engine
                .iter()
                .map(|e| format!("`{}` {}", e.engine, dialect_cell(e.dialect)))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = writeln!(s, "| machine | {} |", self.machine);
        let _ = writeln!(
            s,
            "| cpu resolution floor | {} ms (a delta below this reads 0) |",
            parity::cpu_resolution_floor_millis()
        );
        let _ = writeln!(
            s,
            "| one-hop ceiling | {} |",
            match self.ceiling_summary() {
                Some((median, low, high)) => format!(
                    "{median:.1} MiB/s with no engine in the path and **one** socket \
                     hop, {} per repeat, min {low:.1} max {high:.1}, spread {}. Every \
                     row below is a relay, which is **two** hops, so 100% here is \
                     the generator saturating rather than a ceiling being exceeded. \
                     ZeroNet's {:.0}% generator bound ([`stats::HARNESS_BOUND`]) \
                     applies to a row over the *same* hops as the ceiling and so \
                     does not apply to any row here",
                    self.ceilings_mib_s.len(),
                    spread_text((high - low) / median),
                    stats::HARNESS_BOUND * 100.0
                ),
                None => "not measured, so no row below can be called generator-saturated".into(),
            }
        );
        let _ = writeln!(
            s,
            "| runner spread | {} |",
            self.runner_spread().map_or_else(
                || "unmeasured, so no throughput row below can be certified".to_owned(),
                |spread| format!(
                    "the harness ceiling moved {} between repeats of one unchanged \
                     build, which {} the {:.0}% tolerance this gate decides \
                     at, so a throughput row on this runner is {}",
                    spread_text(spread),
                    if spread > stats::TOLERANCE {
                        "exceeds"
                    } else {
                        "is inside"
                    },
                    stats::TOLERANCE * 100.0,
                    if spread > stats::TOLERANCE {
                        "reported but not certified"
                    } else {
                        "decidable"
                    }
                )
            )
        );
        let _ = writeln!(s);
        s
    }

    /// The engines that produced nothing, each with the reason.
    ///
    /// Never omitted: a blank cell is indistinguishable from a cell nobody looked
    /// at, which is how a failed engine reads as parity
    /// (`upstream/zeronet/docs/benchmarks/harness/zbench/report.py:72`).
    fn failure_note(&self) -> String {
        if self.failures.is_empty() {
            return String::new();
        }
        let mut s = String::new();
        let _ = writeln!(
            s,
            "> **A cell is never blank.** Each engine below either produced runs or \
             carries the reason it did not:\n"
        );
        for (engine, reason) in &self.failures {
            let _ = writeln!(s, "> - `{engine}`: {reason}");
        }
        let _ = writeln!(s);
        s
    }

    /// Every run, not summarised, so the medians below are checkable against it.
    fn per_repeat_table(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "### Per-repeat measurements\n");
        let _ = writeln!(
            s,
            "| engine | run | throughput MiB/s | cpu ms/GiB | peak RSS MiB | threads | transfer s | traffic samples |"
        );
        let _ = writeln!(
            s,
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        );
        for entry in &self.by_engine {
            for (i, run) in entry.runs.iter().enumerate() {
                // A CPU figure with one reading behind it is a reading, not a
                // measurement, and is marked where it is printed.
                let cpu = if run.outcome.traffic_samples < MIN_TRAFFIC_SAMPLES {
                    format!("**{:.2}**", run.cpu_millis_per_gib())
                } else {
                    format!("{:.2}", run.cpu_millis_per_gib())
                };
                let _ = writeln!(
                    s,
                    "| {} | {} | {:.1} | {cpu} | {:.1} | {} | {:.3} | {} |",
                    entry.engine,
                    i + 1,
                    run.throughput_mib_s(),
                    run.rss_mib(),
                    run.outcome
                        .threads_peak
                        .map_or_else(|| "n/a".to_owned(), |t| t.to_string()),
                    run.outcome.transfer.as_secs_f64(),
                    run.outcome.traffic_samples,
                );
            }
        }
        s
    }

    /// Medians over the repeats, each re-derived from the table above it.
    fn medians_table(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "\n### Medians over {} repeats\n", self.repeats);
        let _ = writeln!(
            s,
            "| engine | throughput MiB/s | vs one-hop ceiling | cpu ms/GiB | peak RSS MiB | setup median us |"
        );
        let _ = writeln!(s, "| --- | ---: | ---: | ---: | ---: | ---: |");
        for entry in &self.by_engine {
            let m = self.medians(entry.engine);
            // Re-derive each published median from the cells in the table above it.
            // A disagreement prints the reason in place of the number, because an
            // aggregate a reader cannot reproduce is an assertion.
            let cell = |values: &[f64], median: f64, places: usize| -> String {
                match mean_of(values).and_then(|mean| stats::rederive(values, median, mean)) {
                    Ok(()) => format!("{median:.places$}"),
                    Err(e) => format!("**not re-derivable: {e}**"),
                }
            };
            let throughput = cell(&m.throughput_cells, m.throughput, 1);
            let bound = self.ceiling_fraction(m.throughput);
            let cpu = cell(&m.cpu_cells, m.cpu, 2);
            let rss = cell(&m.rss_cells, m.rss, 1);
            let _ = writeln!(
                s,
                "| {} | {throughput} | {bound} | {cpu} | {rss} | {} |",
                entry.engine, m.setup
            );
        }
        s
    }

    /// The row's share of the single-hop ceiling, with the right label.
    ///
    /// Against the *median* ceiling, because a median over repeats is the only
    /// summary of a noisy machine a reader can check against the per-repeat table.
    /// An engine's median and the ceiling's median come from different instants, so
    /// this is a marker on the row and not a measurement.
    ///
    /// The label is the part that was wrong. The ceiling is the same validated loop
    /// over **one** socket hop -- the driver talks to the sink -- while every row
    /// here is a **two**-hop relay: driver to engine to sink. A relay therefore
    /// moves every byte across the loopback twice, and it is entirely possible, and
    /// good, for it to reach the single-hop rate: on `linux x86_64` `sing-box`
    /// measured 137% of it. So a share at or above the ceiling is the *generator*
    /// saturating, not the ceiling being exceeded, and `ZeroNet`'s
    /// [`stats::HARNESS_BOUND`] -- a row at 85% of the harness rate is
    /// generator-bound -- is a rule about a single-hop row and does not apply here.
    /// Applying it inverted the meaning of the number: a relay at 81% of a
    /// single-hop rate was labelled as though it had hit a limit it never reached.
    fn ceiling_fraction(&self, throughput: f64) -> String {
        self.ceiling_summary().map_or_else(
            || "unknown".to_owned(),
            |(ceiling, _, _)| {
                let fraction = if ceiling > 0.0 {
                    throughput / ceiling
                } else {
                    0.0
                };
                if fraction >= 1.0 {
                    format!("**{:.0}% — at the one-hop ceiling**", fraction * 100.0)
                } else {
                    format!("{:.0}%", fraction * 100.0)
                }
            },
        )
    }

    /// The median, minimum and maximum of the per-repeat ceilings, or `None` when
    /// none was measured.
    fn ceiling_summary(&self) -> Option<(f64, f64, f64)> {
        if self.ceilings_mib_s.is_empty() {
            return None;
        }
        let mut sorted = self.ceilings_mib_s.clone();
        sorted.sort_by(f64::total_cmp);
        let low = sorted[0];
        let high = sorted[sorted.len() - 1];
        Some((median_of(&sorted), low, high))
    }

    /// How far this runner's own throughput moved between repeats: the spread of
    /// the ceilings as a fraction of their median.
    ///
    /// This is the number that decides whether a throughput row on this runner can
    /// mean anything. `docs/methodology.md` records eight `linux x86_64` runs of
    /// one unchanged tree whose throughput ratios ran 0.696x to 1.126x while this
    /// number ran 2.7x; a gate whose own instrument moves further than its
    /// tolerance cannot separate its subject from its runner, and the project
    /// already has the rule for that case: *a run that resolves nothing is a
    /// failure, not a pass*. Here it is neither -- the measurement is real and the
    /// instrument is not good enough -- so the row is reported and marked
    /// uncertified rather than being given a verdict.
    ///
    /// `None` when no ceiling was measured, which is the same verdict for a
    /// stronger reason.
    pub fn runner_spread(&self) -> Option<f64> {
        let (median, low, high) = self.ceiling_summary()?;
        if median <= 0.0 {
            return None;
        }
        Some((high - low) / median)
    }

    /// Every engine against the reference, one row each.
    ///
    /// This is the table a reader looks at first, so it comes before the per-repeat
    /// detail and it names the reference in its own header. A ratio without the
    /// engine it is against is not a comparison, and the gate lines below carry the
    /// intervals this table summarises.
    fn headline_table(&self) -> String {
        let Some(reference) = self.reference() else {
            return String::new();
        };
        let candidates = self.candidates();
        if candidates.is_empty() {
            return String::new();
        }
        let mut s = String::new();
        let _ = writeln!(s, "### Versus `{reference}`, paired on the repeat index\n");
        let _ = writeln!(
            s,
            "**Every ratio is oriented so that above `1.00x` is better**, and each cell \
             carries the absolute medians it came from. The absolute is not decoration: \
             a bare `2.00x` on a CPU row reads as *twice the CPU*, and it means the \
             opposite — half of it. A ratio that can be misread by a reasonable reader \
             is a reporting defect, not a compact one.\n"
        );
        let _ = writeln!(
            s,
            "`ns` marks a row whose interval includes 1.0: this run declining to tell, \
             not a tie.\n"
        );
        let _ = writeln!(
            s,
            "| engine | throughput (MiB/s) | cpu (ms/GiB, lower is better) | peak RSS (MiB, lower is better) | rows resolved |"
        );
        let _ = writeln!(s, "| --- | ---: | ---: | ---: | ---: |");
        for candidate in std::iter::once(reference).chain(candidates) {
            let absolute = self.medians(candidate);
            let (throughput_abs, cpu_abs, rss_abs) =
                (absolute.throughput, absolute.cpu, absolute.rss);
            if candidate == reference {
                let _ = writeln!(
                    s,
                    "| **{reference}** (the reference) | {throughput_abs:.0} | \
                     {cpu_abs:.0} | {rss_abs:.1} | — |"
                );
                continue;
            }
            // The ratio and the absolute together, so the direction of the number is
            // never something the reader has to infer from the row heading.
            let cell = |value: Option<stats::Interval>, absolute: String| -> String {
                match value {
                    // No interval at all is a different failure from an interval
                    // that straddles 1.0, and reads differently on purpose.
                    None => format!("{absolute} (**unproven**)"),
                    Some(i) if !resolved_verdict(Some(i)) => {
                        format!(
                            "{absolute} ({:.2}x [{:.2}, {:.2}] ns)",
                            i.mid, i.low, i.high
                        )
                    }
                    Some(i) => {
                        format!(
                            "{absolute} (**{:.2}x** [{:.2}, {:.2}])",
                            i.mid, i.low, i.high
                        )
                    }
                }
            };
            let throughput = stats::bootstrap_ci(&stats::paired_ratios(
                &self.throughput_cells(candidate),
                &self.throughput_cells(reference),
                Direction::Higher,
            ));
            let cpu = stats::bootstrap_ci(&stats::paired_ratios(
                &self.cpu_cells(candidate),
                &self.cpu_cells(reference),
                Direction::Lower,
            ));
            let rss = stats::bootstrap_ci(&stats::paired_ratios(
                &self.rss_cells(candidate),
                &self.rss_cells(reference),
                Direction::Lower,
            ));
            // How many of the three rows this run could actually resolve. Printed
            // per engine so a row that reads "within noise" everywhere is visibly
            // a run that separated nothing, not a set of three ties.
            let resolved = [throughput, cpu, rss]
                .into_iter()
                .filter(|i| resolved_verdict(*i))
                .count();
            let _ = writeln!(
                s,
                "| {candidate} | {} | {} | {} | {resolved}/3 |",
                cell(throughput, format!("{throughput_abs:.0}")),
                cell(cpu, format!("{cpu_abs:.0}")),
                cell(rss, format!("{rss_abs:.1}")),
            );
        }
        s.push('\n');
        s
    }

    /// The gate, and the rule that produced it.
    fn gate_section(&self) -> String {
        let gate = self.gate();
        let mut s = String::new();
        let _ = writeln!(s, "\n### Gate\n");
        let _ = writeln!(
            s,
            "Paired on the repeat index, engine order rotated and reversed, 95% \
             bootstrap interval over {} resamples at seed {}. A row fails only when \
             its **whole** interval is beyond the {:.0}% tolerance: with three repeats \
             a 4% regression and a 40% one look identical until the interval is read \
             (`upstream/zeronet/docs/benchmarks/harness/zbench/report.py:885`). Fewer \
             than {} usable pairs is `UNPROVEN`, which is not a pass. A run that \
             resolves nothing is a failure, not a pass \
             (`.../zbench/report.py:968`).\n\
             Only the rows for `{}` decide this gate. Every other engine here is a \
             pinned comparator: it is measured and published so a reader can see \
             where it sits, but a comparator measuring worse than the reference is \
             a fact about that comparator, and gating on it would make this job's \
             verdict a property of a binary this repository does not build. Those \
             rows carry a `reported, not gated` marker.\n",
            stats::BOOTSTRAP_RESAMPLES,
            stats::BOOTSTRAP_SEED,
            stats::TOLERANCE * 100.0,
            stats::MIN_PAIRS,
            self.gated.unwrap_or("(none)"),
        );
        for line in &gate.lines {
            let _ = writeln!(s, "- {line}");
        }
        let _ = writeln!(
            s,
            "\n**Gate: {}.**",
            if gate.passed {
                "pass"
            } else {
                "FAIL — see the rows above"
            }
        );
        s
    }

    /// The medians over an engine's repeats, each accompanied by the cells it was
    /// computed from.
    ///
    /// The cells come back because [`Comparison::report`] re-derives every
    /// published median from them and prints the reason instead of the number if
    /// they disagree. An aggregate a reader cannot reproduce from the table above
    /// it is an assertion, not a measurement.
    fn medians(&self, engine: &str) -> Medians {
        let runs = self.runs(engine);
        let throughput: Vec<f64> = runs.iter().map(Run::throughput_mib_s).collect();
        let cpu: Vec<f64> = runs.iter().map(Run::cpu_millis_per_gib).collect();
        let rss: Vec<f64> = runs.iter().map(Run::rss_mib).collect();
        let mut setup_samples: Vec<u128> = runs
            .iter()
            .flat_map(|r| r.outcome.setup.iter().map(|s| s.total_us))
            .collect();
        setup_samples.sort_unstable();
        Medians {
            throughput: median_of(&throughput),
            cpu: median_of(&cpu),
            rss: median_of(&rss),
            setup: parity::median(&setup_samples),
            throughput_cells: throughput,
            cpu_cells: cpu,
            rss_cells: rss,
        }
    }
}

/// A dialect as a report cell, spelling the two fields that differ.
fn dialect_cell(dialect: parity::Dialect) -> &'static str {
    match dialect {
        parity::Dialect::Xray => "(`protocol`, `port`)",
        parity::Dialect::SingBox => "(`type`, `listen_port`)",
    }
}

/// A spread as a readable multiple, `1.0x` for none at all.
///
/// `max/min` rather than `max-min`, because a spread is read as "the machine's
/// best was how many times its worst", and printing `0.42` for that invites the
/// reader to check it against the wrong number.
fn spread_text(spread: f64) -> String {
    format!("{:.2}x", 1.0 + spread.max(0.0))
}

/// Whether an interval resolved a difference beyond the tolerance.
///
/// Used for the "rows resolved" count, so the headline table and the gate below it
/// cannot disagree about what counted as resolved.
fn resolved_verdict(interval: Option<stats::Interval>) -> bool {
    !matches!(
        stats::verdict(interval, Direction::Higher),
        stats::Verdict::WithinNoise(_) | stats::Verdict::Unproven
    )
}

/// One engine's published medians and the cells they came from.
struct Medians {
    throughput: f64,
    cpu: f64,
    rss: f64,
    setup: u128,
    throughput_cells: Vec<f64>,
    cpu_cells: Vec<f64>,
    rss_cells: Vec<f64>,
}

/// Median of a sample, averaging the middle pair on an even count.
fn median_of(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        f64::midpoint(sorted[mid - 1], sorted[mid])
    } else {
        sorted[mid]
    }
}

/// Mean of a sample, or `None` when there are no samples — a mean of nothing is
/// not a number a re-derivation check can compare against.
fn mean_of(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() {
        return Err("there are no cells to average".to_owned());
    }
    Ok(values.iter().sum::<f64>() / values.len() as f64)
}

/// The protocols a scenario id's leading rung can name.
///
/// Two lists in one, because the question is the same either way: is this token
/// a protocol? `scripts/lib-matrix.sh:standard_scenarios` builds its cell ids as
/// `<protocol>-<carrier>-<direction>-<flows>`, so the leading rung of every
/// matrix cell is one of `vless`, `vmess`, `trojan` or `shadowsocks`; and
/// `xray-rust`'s own inbound table is `socks`, `http`, `tun`, so an id naming
/// one of those has to be recognisable as a protocol too or a scenario serving it
/// would slip past the filter that exists for it.
///
/// **A token that is not in here is not a protocol**, and saying so is the point
/// of the list. `--scenario` defaults to `gate5` and `run-parity.sh` never
/// overrides it, so the commonest id reaching [`protocol_of`] names a *run*, not
/// a transport. Treating that token as a protocol skips an engine and reports
/// "`gate5` is not served by xray-rust at its pin", a claim about the engine
/// that is not true.
///
/// The drift risk is named rather than handled: if the matrix grows a protocol
/// this list does not have, `protocol_of` returns `None` and that protocol goes
/// unfiltered -- which is the red rows this whole table exists to remove, so it
/// fails loudly instead of quietly. `every_matrix_scenario_id_names_a_protocol`
/// is what keeps the two in step.
const SCENARIO_PROTOCOLS: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "http",
    "tun",
];

/// The protocol a scenario id names, if it names one.
///
/// `vless-raw-down-8` is `vless`: only the leading rung is read, so a carrier
/// suffix (`-ws`, `-grpc`, `-xhttp`) does not hide the protocol behind it, and
/// the flows count at the end is not mistaken for one.
///
/// `None` for an id that names no protocol -- the default `gate5`, an empty
/// string, or a token outside [`SCENARIO_PROTOCOLS`]. The caller must then leave
/// every engine in: there is no protocol to sit one out on, and a skip needs a
/// reason that is true.
fn protocol_of(scenario: &str) -> Option<&str> {
    let rung = scenario.split('-').next().unwrap_or_default();
    SCENARIO_PROTOCOLS.contains(&rung).then_some(rung)
}

/// Engines that measure this workload, plus the ones sitting it out.
///
/// Custom scenario documents are Xray-dialect; an engine that reads another
/// spelling sits out with one named reason rather than failing every repeat,
/// which would measure a parse error and report it as the engine. The default
/// freedom shape runs everywhere, so this only ever triggers on a named
/// scenario. Split out so `run` stays under the line budget.
fn participant_names(
    engines: &[Engine],
    workload: &Workload,
) -> (Vec<&'static str>, Vec<(String, String)>) {
    let mut skipped = Vec::new();
    let custom = !workload.outbound_config.trim().is_empty();
    let protocol = protocol_of(&workload.scenario);
    let names = engines
        .iter()
        .filter(|e| {
            if custom && e.dialect != parity::Dialect::Xray {
                skipped.push((
                    e.name.to_owned(),
                    format!(
                        "custom scenario configs are Xray-dialect documents; {} reads {:?}",
                        e.name, e.dialect
                    ),
                ));
                return false;
            }
            // A protocol this engine does not serve is a roadmap row, not a fault.
            // Checked against the scenario rather than by trying to start the
            // engine, because the alternative is a startup failure whose message
            // names a config field and reads as the engine being broken.
            //
            // Gated on the scenario naming a protocol at all: with nothing to
            // compare against there is no reason to skip, and a reason that is
            // not true is worse than no skip.
            if let Some(protocol) = protocol.filter(|_| !e.protocols.is_empty()) {
                if !e.protocols.contains(&protocol) {
                    skipped.push((
                        e.name.to_owned(),
                        format!(
                            "{protocol} is not served by {} at its pin; it accepts {}",
                            e.name,
                            e.protocols.join(", ")
                        ),
                    ));
                    return false;
                }
            }
            true
        })
        .map(|e| e.name)
        .collect();
    (names, skipped)
}

/// Measure every engine against the workload, `repeats` times each.
///
/// The order is rotated and reversed by the repeat index (`stats::rotate`), so a
/// systematic "the first engine measured is warmer" effect lands on both engines
/// equally often. Each run writes its own `result.json` in the pinned harness's
/// schema, so a run can be re-read or handed to the other harness afterwards.
pub fn run(
    engines: &[Engine],
    workload: &Workload,
    repeats: usize,
    out_dir: &Path,
    measure_ceiling: bool,
) -> Result<Comparison, Error> {
    if engines.len() < 2 {
        return Err(Error::Invalid(format!(
            "a comparison needs at least two engines, got {}: with one there is \
             nothing to compare against",
            engines.len()
        )));
    }
    if repeats < stats::MIN_RUNS {
        return Err(Error::Invalid(format!(
            "{repeats} repeats cannot be read: {} is the minimum worth reading \
             (`upstream/zeronet/docs/benchmarks/README.md:251`), and below two \
             usable pairs a ratio has no interval at all, which is `unproven` \
             rather than a pass",
            stats::MIN_RUNS
        )));
    }

    // The ceiling is measured once per repeat, inside the loop below and
    // interleaved with the engines, so that each repeat's engines and its ceiling
    // are seconds apart rather than a sweep's worth of minutes apart.
    let mut ceilings: Vec<f64> = Vec::new();

    let mut by_engine: Vec<EngineRuns> = engines
        .iter()
        .map(|e| EngineRuns {
            engine: e.name,
            dialect: e.dialect,
            runs: Vec::with_capacity(repeats),
        })
        .collect();
    let mut failures = Vec::new();
    let (names, skipped) = participant_names(engines, workload);

    for repeat in 1..=repeats {
        if measure_ceiling {
            if let Ok(ceiling) = parity::harness_ceiling(
                workload.connections,
                workload.payload_size,
                workload.flow_bytes(),
            ) {
                ceilings.push(ceiling);
            }
        }
        for name in stats::rotate(&names, repeat) {
            // By name, not by position: `names` skips engines sitting the
            // scenario out, so its indices do not match `engines`. Every name
            // comes from `engines` two dozen lines above, so a miss would mean
            // the list changed under the loop; skipping keeps that from
            // measuring the wrong engine under the right name.
            let Some(engine) = engines.iter().find(|e| e.name == name) else {
                continue;
            };
            let output = out_dir.join(format!("{name}-run{repeat}"));
            std::fs::create_dir_all(out_dir).map_err(|source| Error::Io {
                action: format!("creating {}", out_dir.display()),
                source,
            })?;
            let request_path = out_dir.join(format!("{name}-run{repeat}.json"));
            std::fs::write(&request_path, workload.request(engine, &output)).map_err(|source| {
                Error::Io {
                    action: format!("writing {}", request_path.display()),
                    source,
                }
            })?;
            // Read the request back off disk rather than reusing the string that
            // was written. The file is the artefact — it is what a reader inspects
            // and what the other harness would be handed — so measuring from the
            // in-memory copy would leave the published file unproven.
            let request = Request::read(&request_path)?;
            match parity::measure(&request, engine.config_arg, engine.dialect) {
                Ok(run) => {
                    let result_path = output.join("result.json");
                    let result_text = run
                        .to_result_json(&request)
                        .to_string()
                        .map_err(|e| Error::Invalid(format!("result.json: {e}")))?;
                    std::fs::write(&result_path, result_text).map_err(|source| Error::Io {
                        action: "writing result.json".into(),
                        source,
                    })?;
                    // And read the result back, re-deriving every aggregate from
                    // the raw fields beside it. A report that cannot be
                    // re-derived from its own cells is a report nobody can check
                    // (`upstream/zeronet/docs/benchmarks/harness/zbench/validate_results.py:11`),
                    // so this runs on every run rather than in a test.
                    match revalidate(&result_path) {
                        Ok(checked) => {
                            debug_assert_eq!(
                                checked.engine_sha256, run.engine_sha256,
                                "the re-read result names a different binary"
                            );
                            // By name, like the engine lookup above: skipped
                            // engines keep an empty slot that must not collect
                            // another engine's runs.
                            let Some(slot) = by_engine.iter_mut().find(|e| e.engine == name) else {
                                continue;
                            };
                            slot.runs.push(run);
                        }
                        Err(e) => failures.push((
                            name.to_owned(),
                            format!("result.json did not re-derive: {e}"),
                        )),
                    }
                }
                Err(e) => failures.push((name.to_owned(), e.to_string())),
            }
        }
    }

    Ok(Comparison {
        workload: workload.clone(),
        repeats,
        by_engine,
        ceilings_mib_s: ceilings,
        gated: engines.iter().find(|e| e.gated).map(|e| e.name),
        failures,
        skipped,
        machine: machine_description(),
    })
}

/// The host, recorded with the number because a number without its host is not a
/// measurement.
///
/// Including the address every listener bound. That address comes from the
/// routing table, so it changes when a VPN comes up, and a report that named
/// only the OS and the CPU count would show two runs on the same runner as
/// indistinguishable while they were measured through different interfaces. See
/// [`parity::local_non_loopback_ipv4`].
fn machine_description() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let cpus = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    let bind = parity::local_non_loopback_ipv4().map_or_else(
        |e| format!("no usable non-loopback IPv4 ({e})"),
        |ip| format!("bound on {ip}"),
    );
    format!(
        "{os} {arch}, {cpus} logical CPUs, {bind}, cpu from `{}`",
        crate::ps::CpuSource::current().as_str()
    )
}

/// Read a `result.json` back into a [`Run`], re-deriving its aggregates from its
/// own raw fields and failing on any disagreement.
///
/// This is the counterpart to `ZeroNet`'s `validate_results.py` discipline: a stored
/// result is re-read and its aggregates re-derived rather than trusted, because a
/// report that cannot be re-derived from its own cells is a report nobody can
/// check. It is also what lets a dated result group be re-gated later without
/// re-measuring it.
pub fn revalidate(result_path: &Path) -> Result<Run, Error> {
    let text = std::fs::read_to_string(result_path).map_err(|source| Error::Io {
        action: format!("reading {}", result_path.display()),
        source,
    })?;
    let root = json::parse(&text)
        .map_err(|e| Error::Invalid(format!("{} is not valid json: {e}", result_path.display())))?;
    let num = |key: &str| -> Result<f64, Error> {
        root.get(key)
            .and_then(Json::as_num)
            .ok_or_else(|| Error::Invalid(format!("result.json has no number `{key}`")))
    };
    let status = root.get("status").and_then(Json::as_str).unwrap_or("");
    if status != "pass" {
        return Err(Error::Invalid(format!(
            "result.json status is `{status}`, not `pass`"
        )));
    }

    let bytes_sent = num("bytes_sent")?;
    let bytes_received = num("bytes_received")?;
    let seconds = num("transfer_seconds")?;
    let cpu_millis = num("cpu_millis")?;
    check_derived(&root, bytes_sent + bytes_received, seconds, cpu_millis)?;
    check_samples(&root, cpu_millis)?;

    let read_setup = |key: &str| -> u128 {
        root.get("setup")
            .and_then(|s| s.get(key))
            .and_then(|q| q.get("median"))
            .and_then(Json::as_num)
            .map_or(0, |n| n as u128)
    };
    let setup = vec![parity::Setup {
        tcp_connect_us: read_setup("tcp_connect_us"),
        socks_method_us: read_setup("socks_method_us"),
        socks_connect_us: read_setup("socks_connect_us"),
        socks_setup_us: read_setup("socks_setup_us"),
        total_us: read_setup("total_us"),
    }];

    let samples = read_samples(&root);
    Ok(Run {
        engine: root
            .get("engine_binary")
            .and_then(Json::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        engine_sha256: root
            .get("engine_sha256")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned(),
        outcome: parity::Outcome {
            bytes_sent: bytes_sent as u64,
            bytes_received: bytes_received as u64,
            transfer: std::time::Duration::from_secs_f64(seconds.max(0.0)),
            wall: std::time::Duration::from_secs_f64(
                root.get("wall_seconds")
                    .and_then(Json::as_num)
                    .unwrap_or(seconds)
                    .max(0.0),
            ),
            setup,
            peak_rss_kib: num("peak_rss_kib")? as u64,
            cpu_millis: cpu_millis as u64,
            traffic_samples: samples
                .iter()
                .filter(|(phase, _)| *phase == parity::Phase::Traffic)
                .count(),
            threads_peak: root
                .get("threads_peak")
                .and_then(Json::as_num)
                .map(|n| n as u64),
            startup_cpu_millis: num("client_startup_cpu_millis")? as u64,
            startup_seconds: num("client_startup_seconds")?,
            samples,
        },
    })
}

/// Re-derive the two published aggregates from the raw fields beside them.
///
/// The tolerance is relative, so a large throughput is not held to a tighter
/// absolute standard than a small one.
fn check_derived(root: &Json, moved: f64, seconds: f64, cpu_millis: f64) -> Result<(), Error> {
    let num = |key: &str| {
        root.get(key)
            .and_then(Json::as_num)
            .ok_or_else(|| Error::Invalid(format!("result.json has no number `{key}`")))
    };
    let rederived_throughput = if seconds > 0.0 {
        moved / (1024.0 * 1024.0) / seconds
    } else {
        0.0
    };
    let reported_throughput = num("throughput_mib_s")?;
    if (rederived_throughput - reported_throughput).abs()
        > 1e-6 * reported_throughput.abs().max(1.0)
    {
        return Err(Error::Invalid(format!(
            "throughput_mib_s {reported_throughput} does not match its own fields: \
             {moved} bytes over {seconds}s re-derives to {rederived_throughput}"
        )));
    }
    let rederived_cpu = if moved > 0.0 {
        cpu_millis / (moved / 1_073_741_824.0)
    } else {
        0.0
    };
    let reported_cpu = num("cpu_millis_per_gib")?;
    if (rederived_cpu - reported_cpu).abs() > 1e-6 * reported_cpu.abs().max(1.0) {
        return Err(Error::Invalid(format!(
            "cpu_millis_per_gib {reported_cpu} does not match its own fields: \
             {cpu_millis} ms over {moved} bytes re-derives to {rederived_cpu}"
        )));
    }
    Ok(())
}

/// Re-derive the summary figures from the raw `ps` readings beside them.
///
/// The peak RSS must be the samples' maximum and the CPU total their delta. A
/// summary that is not reachable from its own readings cannot be checked by
/// anyone, including by this harness the next time it reads the file.
fn check_samples(root: &Json, cpu_millis: f64) -> Result<(), Error> {
    let Some(items) = root.get("samples").and_then(Json::as_arr) else {
        return Err(Error::Invalid(
            "result.json carries no samples, so nothing in it can be re-derived".into(),
        ));
    };
    let rss: Vec<f64> = items
        .iter()
        .filter_map(|i| i.get("rss_kib").and_then(Json::as_num))
        .collect();
    let cpu: Vec<f64> = items
        .iter()
        .filter_map(|i| i.get("cpu_millis").and_then(Json::as_num))
        .collect();
    let peak = rss.iter().copied().fold(0.0f64, f64::max);
    let reported_peak = root
        .get("peak_rss_kib")
        .and_then(Json::as_num)
        .ok_or_else(|| Error::Invalid("result.json has no `peak_rss_kib`".into()))?;
    if (peak - reported_peak).abs() > 1e-6 * peak.max(1.0) {
        return Err(Error::Invalid(format!(
            "peak_rss_kib {reported_peak} does not match the samples' maximum {peak}"
        )));
    }
    let (Some(&first), Some(&last)) = (cpu.first(), cpu.last()) else {
        return Err(Error::Invalid(
            "result.json carries no cpu samples, so cpu_millis cannot be re-derived".into(),
        ));
    };
    let total = last - first;
    if (total - cpu_millis).abs() > f64::EPSILON * total.abs().max(1.0) {
        return Err(Error::Invalid(format!(
            "cpu_millis {cpu_millis} does not match its own samples' delta {total}"
        )));
    }
    Ok(())
}

/// The raw readings, as `ps` produced them.
fn read_samples(root: &Json) -> Vec<(parity::Phase, crate::ps::Sample)> {
    root.get("samples")
        .and_then(Json::as_arr)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let read = |key: &str| item.get(key).and_then(Json::as_num).unwrap_or(0.0);
                    let phase = match item.get("phase").and_then(Json::as_str) {
                        Some("startup") => parity::Phase::Startup,
                        Some("traffic") => parity::Phase::Traffic,
                        _ => parity::Phase::Settle,
                    };
                    (
                        phase,
                        crate::ps::Sample {
                            elapsed_ms: read("elapsed_ms") as u128,
                            rss_kib: read("rss_kib") as u64,
                            cpu_millis: read("cpu_millis") as u64,
                            threads: item.get("threads").and_then(Json::as_num).map(|n| n as u64),
                        },
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An engine in the Xray family, which is `run -config <path>`.
    fn engine(name: &'static str, path: &str) -> Engine {
        Engine {
            name,
            path: PathBuf::from(path),
            config_arg: ConfigArg::Long,
            gated: name == "ferrox",
            dialect: parity::Dialect::Xray,
            protocols: &[],
        }
    }

    fn workload() -> Workload {
        Workload {
            traffic: "upload".into(),
            connections: 1,
            iterations: 16,
            payload_size: 1024,
            warmup: false,
            outbound_config: String::new(),
            scenario: String::new(),
        }
    }

    #[test]
    fn a_comparison_needs_two_engines() {
        let err = run(
            &[engine("a", "/bin/true")],
            &workload(),
            1,
            Path::new("/tmp/x"),
            false,
        )
        .expect_err("one engine is not a comparison");
        assert!(err.to_string().contains("at least two engines"));
    }

    fn synth_run(mibs: u64, cpu_millis: u64, rss_kib: u64) -> parity::Run {
        parity::Run {
            engine: String::new(),
            engine_sha256: "abc".into(),
            outcome: parity::Outcome {
                bytes_sent: mibs * 1024 * 1024,
                bytes_received: 0,
                transfer: std::time::Duration::from_secs(1),
                wall: std::time::Duration::from_secs(1),
                setup: Vec::new(),
                peak_rss_kib: rss_kib,
                cpu_millis,
                traffic_samples: 10,
                threads_peak: None,
                startup_cpu_millis: 0,
                startup_seconds: 0.0,
                samples: Vec::new(),
            },
        }
    }

    fn dialect_engine(name: &'static str, dialect: parity::Dialect) -> Engine {
        Engine {
            name,
            path: PathBuf::from("/bin/false"),
            config_arg: ConfigArg::Long,
            gated: false,
            dialect,
            protocols: &[],
        }
    }

    #[test]
    fn custom_configs_sit_out_non_xray_engines_with_a_reason() {
        let engines = vec![
            dialect_engine("xray-core", parity::Dialect::Xray),
            dialect_engine("sing-box", parity::Dialect::SingBox),
        ];
        let custom = Workload {
            outbound_config: r#"{"outbounds":[]}"#.into(),
            ..workload()
        };
        let (names, skipped) = participant_names(&engines, &custom);
        assert_eq!(names, vec!["xray-core"]);
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "sing-box");
        assert!(
            skipped[0].1.contains("Xray-dialect"),
            "the reason names the mismatch: {}",
            skipped[0].1
        );
        let (names, skipped) = participant_names(&engines, &workload());
        assert_eq!(names, vec!["xray-core", "sing-box"]);
        assert_eq!(skipped, Vec::new());
    }

    /// The engine the protocol table was written for: `xray-rust` at its pin
    /// accepts `socks`, `http` and `tun` inbounds and rejects the rest
    /// (`upstream/xray-rust/crates/xray-config/src/parser.rs:626`, at
    /// `7a4fb2dd`).
    fn protocol_limited_engine() -> Engine {
        Engine {
            protocols: &["socks", "http", "tun"],
            ..dialect_engine("xray-rust", parity::Dialect::Xray)
        }
    }

    fn scenario_workload(scenario: &str) -> Workload {
        Workload {
            scenario: scenario.into(),
            ..workload()
        }
    }

    /// The bug this table was added for: a protocol scenario handed an engine
    /// that cannot parse it, it exits during startup, and the harness reports
    /// that as a **failed engine**.
    ///
    /// Asserted on the participant list, because that is where the report reads
    /// it: an engine that sits out is named under `skipped`, which is the
    /// roadmap, and one that starts and dies is named under the failures, which
    /// is a fault. The distinction is the whole point of the table.
    #[test]
    fn an_engine_that_cannot_serve_the_scenarios_protocol_sits_out_with_a_reason() {
        let engines = vec![
            protocol_limited_engine(),
            dialect_engine("xray-core", parity::Dialect::Xray),
        ];
        let (names, skipped) = participant_names(&engines, &scenario_workload("vless-raw-down-8"));
        assert_eq!(
            names,
            vec!["xray-core"],
            "an engine that cannot parse the inbound must not be measured"
        );
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, "xray-rust");
        let reason = &skipped[0].1;
        assert!(
            reason.contains("vless") && reason.contains("socks, http, tun"),
            "the reason names the protocol and what the pin does accept: {reason}"
        );

        // A carrier suffix is not part of the protocol: `vless-ws-down-8` is
        // still `vless`, and reading only the leading rung is what keeps the
        // transport out of the comparison.
        for id in [
            "vless-ws-down-8",
            "vless-grpc-down-8",
            "vless-xhttp-down-8",
            "vmess-raw-down-8",
            "trojan-raw-down-8",
            "shadowsocks-raw-down-8",
        ] {
            let (names, skipped) = participant_names(&engines, &scenario_workload(id));
            assert_eq!(
                names,
                vec!["xray-core"],
                "{id}: the protocol is the leading rung, whatever follows it"
            );
            assert!(
                skipped[0].1.starts_with(id.split('-').next().unwrap()),
                "{id}: the reason names the protocol it sat out on: {}",
                skipped[0].1
            );
        }

        // And it is not skipped from a scenario it *can* serve.
        let (names, skipped) = participant_names(&engines, &scenario_workload("socks-down-1"));
        assert_eq!(names, vec!["xray-rust", "xray-core"]);
        assert_eq!(skipped, Vec::new());
    }

    /// The case that makes the protocol table a trap if it is read naively.
    ///
    /// `--scenario` defaults to `gate5` (`main.rs`), and `run-parity.sh` --
    /// which is gate 5 -- never passes one. So the ids that reach this function
    /// are not all protocol-shaped: `gate5` is a *label for a run*, not a
    /// protocol, and reading its leading rung as one skips an engine with the
    /// reason "`gate5` is not served by xray-rust at its pin", which is a claim
    /// about the engine that is not true and cannot be made true.
    ///
    /// A skipped engine is not a red row, it is an absent one, so this would
    /// have cost gate 5 its comparator without going red: the worst way for a
    /// gate to be wrong. The same holds for an empty scenario, where the leading
    /// rung is the empty string.
    #[test]
    fn a_scenario_that_names_no_protocol_never_sits_an_engine_out() {
        let engines = vec![protocol_limited_engine()];
        for id in ["gate5", ""] {
            let (names, skipped) = participant_names(&engines, &scenario_workload(id));
            assert_eq!(
                names,
                vec!["xray-rust"],
                "{id:?}: no protocol is named, so there is nothing to sit out"
            );
            assert_eq!(skipped, Vec::new(), "{id:?}: and no reason may be invented");
        }
    }

    /// Every cell the matrix can run names a protocol [`protocol_of`] recognises.
    ///
    /// `SCENARIO_PROTOCOLS` is a second list next to the matrix that generates
    /// the ids, and a second list is a promise to keep them in step. This reads
    /// the ids back out of `scripts/lib-matrix.sh` rather than restating them
    /// here, because a copy in the test would agree with the copy in the source
    /// even when both had drifted from the shell.
    ///
    /// It reads the `echo` lines that name a cell: `<protocol>-<carrier>-...`
    /// followed by a traffic word. The `full` tier and `standard_scenarios` are
    /// both covered because both are read, and the smoke tier is one of them.
    #[test]
    fn every_matrix_scenario_id_names_a_protocol() {
        let script =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/lib-matrix.sh");
        let text = std::fs::read_to_string(&script)
            .unwrap_or_else(|e| panic!("reading {}: {e}", script.display()));
        let mut ids = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("echo \"") else {
                continue;
            };
            let Some(id) = rest.split(' ').next() else {
                continue;
            };
            // A cell id is `<protocol>-<carrier>-...`; the `echo` lines that are
            // not cells either end in a `.txt`/`.sh` path or hold prose.
            if id.split('-').count() >= 2 && !id.contains(['/', '"']) {
                ids.push(id.to_owned());
            }
        }
        assert!(
            ids.len() >= 11,
            "found only {} cell ids in {}: the reader has stopped matching the \
             script rather than the matrix having shrunk",
            ids.len(),
            script.display()
        );
        for id in &ids {
            assert!(
                protocol_of(id).is_some(),
                "{id}: the matrix runs this cell but `protocol_of` does not name \
                 a protocol for it, so an engine that cannot serve it would be \
                 started and reported as a fault instead of sitting out"
            );
        }
    }

    #[test]
    fn comparison_json_reports_rows_verdicts_and_cells() {
        let comparison = Comparison {
            workload: workload(),
            repeats: 3,
            by_engine: vec![
                EngineRuns {
                    engine: "xray-core",
                    dialect: parity::Dialect::Xray,
                    runs: vec![
                        synth_run(100, 300, 20480),
                        synth_run(110, 310, 20500),
                        synth_run(120, 320, 20600),
                    ],
                },
                EngineRuns {
                    engine: "ferrox",
                    dialect: parity::Dialect::Xray,
                    runs: vec![
                        synth_run(200, 150, 10240),
                        synth_run(220, 155, 10250),
                        synth_run(240, 160, 10260),
                    ],
                },
            ],
            ceilings_mib_s: vec![900.0, 950.0, 1000.0],
            gated: Some("ferrox"),
            failures: Vec::new(),
            skipped: Vec::new(),
            machine: "test".into(),
        };
        let text = comparison
            .comparison_json("vless-raw-down-1")
            .expect("synthetic cells always serialise");
        let root = json::parse(&text).expect("the document parses as json");
        let str_of = |doc: &Json, key: &str| {
            doc.get(key)
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(str_of(&root, "scenario"), "vless-raw-down-1");
        assert_eq!(str_of(&root, "reference"), "xray-core");
        let rows = root.get("rows").expect("rows");
        let pairs: Vec<(String, String, String)> = match rows {
            Json::Arr(items) => items
                .iter()
                .map(|row| {
                    (
                        str_of(row, "label"),
                        str_of(row, "direction"),
                        str_of(row, "verdict"),
                    )
                })
                .collect(),
            _ => panic!("rows is an array"),
        };
        // Twice as fast at half the CPU and memory: every row resolves better,
        // with throughput reading higher-is-better and the rest lower-is-better.
        assert_eq!(
            pairs
                .iter()
                .map(|(_, _, verdict)| verdict.clone())
                .collect::<Vec<_>>(),
            vec!["better", "better", "better"]
        );
        assert_eq!(pairs[0].1, "higher");
        assert_eq!(pairs[1].1, "lower");
        assert_eq!(pairs[2].1, "lower");
        assert!(root
            .get("gate_passed")
            .and_then(Json::as_bool)
            .unwrap_or(false));
        // The cost columns beside throughput: peak threads, cold start, and
        // the transfer window. The charts read them from the cell, so the
        // cell carries them even when a synthetic run has nothing to say.
        let engines = root.get("engines").expect("engines");
        let first_run = match engines {
            Json::Arr(items) => match items.first().expect("an engine").get("runs") {
                Some(Json::Arr(runs)) => runs.first().expect("a run").clone(),
                other => panic!("runs is an array, got {other:?}"),
            },
            _ => panic!("engines is an array"),
        };
        assert!(
            first_run.get("threads_peak").is_some(),
            "threads_peak travels with the cell"
        );
        assert_eq!(
            first_run.get("startup_seconds").and_then(Json::as_num),
            Some(0.0)
        );
        assert_eq!(
            first_run.get("transfer_seconds").and_then(Json::as_num),
            Some(1.0)
        );
    }

    #[test]
    fn too_few_repeats_is_refused() {
        let err = run(
            &[engine("a", "/bin/true"), engine("b", "/bin/true")],
            &workload(),
            0,
            Path::new("/tmp/x"),
            false,
        )
        .expect_err("too few repeats cannot be read");
        assert!(err.to_string().contains("minimum worth reading"), "{err}");
    }

    #[test]
    fn a_request_names_the_engine_and_the_workload() {
        let w = workload();
        let text = w.request(&engine("ferrox", "/bin/dv"), Path::new("/tmp/out"));
        let root = json::parse(&text).expect("valid json");
        assert_eq!(root.get("binary").and_then(Json::as_str), Some("/bin/dv"));
        assert_eq!(root.get("traffic").and_then(Json::as_str), Some("upload"));
        assert_eq!(root.get("connections").and_then(Json::as_num), Some(1.0));
        assert_eq!(root.get("iterations").and_then(Json::as_num), Some(16.0));
        assert_eq!(
            root.get("payload_size").and_then(Json::as_num),
            Some(1024.0)
        );
        assert_eq!(root.get("output").and_then(Json::as_str), Some("/tmp/out"));
        assert_eq!(root.get("warmup").and_then(Json::as_bool), Some(false));
    }

    /// The request the harness builds must be one its own validator accepts —
    /// otherwise the file it writes is not the file it would read back.
    #[test]
    fn the_request_it_writes_is_one_it_accepts() {
        let w = workload();
        // The test binary itself: the one file every runner is guaranteed to have.
        let exe = std::env::current_exe().expect("a test binary has a path");
        let text = w.request(
            &engine("ferrox", &exe.to_string_lossy()),
            Path::new("/tmp/ferrox-parity-test"),
        );
        let parsed = Request::parse(text.as_bytes()).expect("the harness accepts its own request");
        assert_eq!(parsed.connections, w.connections);
        assert_eq!(parsed.iterations, w.iterations);
        assert_eq!(parsed.payload_size, w.payload_size);
        assert_eq!(parsed.total_bytes(), w.total_bytes());
    }

    #[test]
    fn the_workload_description_names_the_bytes() {
        let w = workload();
        let described = w.describe();
        assert!(described.contains("16 MiB") || described.contains("MiB total"));
        assert!(described.contains("upload"));
    }

    #[test]
    fn byte_accounting_matches_the_request() {
        let mut w = workload();
        w.connections = 4;
        w.iterations = 100;
        w.payload_size = 16384;
        assert_eq!(w.flow_bytes(), 100 * 16_384);
        // `upload` is one direction, so four flows is four times `flow_bytes`.
        assert_eq!(w.total_bytes(), 4 * 100 * 16_384);

        // A full-duplex cell moves `flow_bytes` **each way**, so the total is
        // twice the single-direction figure. Reading it as the single-direction
        // number is what reported `moved 8589934592 of 4294967296` -- moved
        // exactly twice what was asked, and called a short transfer -- and it
        // failed six of the standard tier's eleven cells on every runner.
        let mut duplex = workload();
        duplex.traffic = "full-duplex".into();
        duplex.connections = 8;
        duplex.iterations = 16384;
        duplex.payload_size = 65536;
        assert_eq!(duplex.flow_bytes(), 16384 * 65536);
        assert_eq!(duplex.total_bytes(), 2 * 8 * 16384 * 65536);
        // The report header prints this same figure, so the two cannot disagree:
        // a reader comparing "MiB total" against what the run was asked for is
        // reading a number this method produced.
        assert!(
            duplex.describe().contains("(16384 MiB total)"),
            "the header names the same figure the accounting does: {}",
            duplex.describe()
        );

        // A download is one direction, and eight flows are eight times one flow:
        // at one connection the two readings coincide, which is why a
        // multi-connection bug here is invisible until a row uses eight.
        let mut down = workload();
        down.traffic = "download".into();
        down.connections = 1;
        assert_eq!(down.total_bytes(), down.flow_bytes());
        down.connections = 8;
        assert_eq!(down.total_bytes(), 8 * down.flow_bytes());
    }
}
