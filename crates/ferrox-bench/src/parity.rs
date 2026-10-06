//! The pinned comparators' process-level harness, reimplemented so one request
//! file measures either binary.
//!
//! # Why this is a reimplementation and not a copy
//!
//! `xray-rust` ships a process-level harness whose contract is a `JSON` request
//! naming an engine binary and a workload, and a `result.json` of validated
//! throughput, RSS and CPU (`upstream/xray-rust/crates/xray-bench/src/protocol_bench.rs:122`).
//! That contract is deliberately engine-agnostic: the measured engine is external
//! and only has to accept `<binary> run -config <path>` with its inbounds
//! injected. `ferrox-app` does, so **the same request file measures either
//! binary**, which is the property that makes this a comparison rather than two
//! benchmarks.
//!
//! Their harness is MPL-2.0 and is not copied here. `upstream/pins.toml` already
//! runs their suites unmodified from the pin, which is both licence-clean and a
//! stronger claim than a transcription. What is reproduced here is the *shape*:
//! the request fields and their bounds, the result fields, the 500 ms pre-sleep
//! and settle, the 100 ms `ps` sampling, the xorshift payload seed. So one
//! request and one report mean the same thing on both sides.
//! `scripts/run-parity.sh` hands the identical file to their binary when it is
//! built from the pin, and `docs/methodology.md` records which of their
//! workloads this covers and which it does not.
//!
//! # The four rules, which are `ZeroNet`'s and are why a number here is fair
//!
//! 1. **The payload is validated.** The sink writes a deterministic xorshift
//!    keystream and checks every byte, and concurrent flows use disjoint
//!    rotations of it, so a core that interleaves two sessions onto one carrier
//!    is caught rather than hidden behind a correct total.
//! 2. **The transfer window excludes setup.** Setup is timed in its own columns.
//!    An engine that answers SOCKS before it dials and one that dials first hide
//!    that difference inside a wall-clock rate, and the difference is exactly what
//!    a reader of these numbers wants to see.
//! 3. **The one-hop ceiling is published.** The same validated loop runs over a
//!    bare socket with no engine in the path, so every listener moves the same
//!    bytes by the same code. It is a **one**-socket-hop figure and every engine
//!    row is a **two**-hop relay, so a row reaching 100% of it is the generator
//!    saturating, not a ceiling exceeded -- which is what `sing-box` measures at
//!    137% on `linux x86_64`. `ZeroNet`'s 85% generator bound
//!    (`HARNESS_BOUND = 0.85`, `upstream/zeronet/docs/benchmarks/harness/zbench/report.py:58`)
//!    is a rule about a row over the same hops as the ceiling, and is published
//!    with the number rather than applied to rows it does not describe.
//! 4. **Order is rotated and then reversed**, and comparisons are paired on the
//!    repeat index, so the interval in `stats.rs` is over pairs rather than over
//!    two independently aggregated sets of samples.
//!
//! # What sampling from outside cannot see
//!
//! Stated rather than implied. `ps` gives RSS and CPU for a Go engine and a Rust
//! engine alike, which is the only way the two are comparable at all — but it
//! gives no allocation counts, so those stay in-process and exact in `count.rs`;
////! and it reports CPU at the kernel's tick resolution, so a delta under one tick
//! reads `0`. `ZeroNet` names the same floor
//! (`CPU_RESOLUTION_S = 0.010`, `.../zbench/report.py:88`) and
//! [`cpu_resolution_floor_millis`] carries the number into the report.

// Byte counts divided by 1 MiB or 1 GiB, and milliseconds divided by seconds,
// are the figures this module exists to report; the conversion is the point
// rather than an accident of the arithmetic. Every count here is orders of
// magnitude below 2^53, where an `f64` is exact.
#![allow(clippy::cast_precision_loss)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::json::{self, Json};
use crate::ps::{self, Host};

/// Identifies this harness in every `result.json`, so a consumer can tell which
/// implementation produced a file. The pinned harness does the same job with its
/// `provenance.harness_profile`.
pub const HARNESS_ID: &str = "ferrox-bench/protocol-run";

/// Seed for the validated payload: the pinned harness's own constant
/// (`upstream/xray-rust/crates/xray-bench/src/lib.rs:3888`).
///
/// Reused deliberately. It makes a payload mismatch reportable as *this harness
/// and that harness disagree about the bytes*, which is a far more useful
/// failure than a generic mismatch — and it means the two harnesses are
/// validating the same stream.
pub const BULK_PATTERN_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

/// Pre-work sleep, settle after the work, and the sampling period: the pinned
/// harness's values (`protocol_bench.rs:219-225`). Kept because a comparison
/// against a number produced with different constants is not a comparison.
const PRE_SLEEP: Duration = Duration::from_millis(500);
const SETTLE: Duration = Duration::from_millis(500);
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Ceiling on the whole workload (`protocol_bench.rs:269`), and on how long the
/// engine gets to answer before it is declared dead.
const RUN_TIMEOUT: Duration = Duration::from_secs(120);

/// Per-operation timeout on flow sockets.
///
/// `collect_flows` joins flow threads, and the run cap above is only checked
/// after the join — so a peer that stalls mid-transfer with no timeout hangs
/// the run forever rather than tripping the cap. Healthy loopback operations
/// complete in milliseconds, so thirty seconds only ever fires on a dead
/// peer, and when it does the flow records its stopped reason and returns
/// into the existing short-transfer error path instead of hanging the job.
const FLOW_IO_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Largest request document accepted (`protocol_bench.rs:127`).
const MAX_REQUEST_BYTES: usize = 262_144;

/// Iterations one flow may be asked for.
///
/// The pinned harness caps this at 16 384 and reaches 16 GiB by multiplying
/// `connections` instead (`protocol_bench.rs:68` and the same bounds on
/// `payload_size` and `connections` at `:65`-`:69`). That route is closed here on
/// purpose: the claim this row supports is about a *single* flow, and eight flows
/// are eight relays, eight flows' resident buffers and thirty-two threads on a
/// four-CPU runner -- a different workload wearing the same name, which is the
/// failure mode a pinned harness is supposed to prevent rather than permit.
///
/// So the bound moves and the shape does not: one flow, `iterations` up to
/// [`MAX_FLOW_BYTES`] bytes, `connections` still 1. The cost is that a request
/// above 16 384 iterations is one the pinned harness's validator would refuse,
/// which is why the *default* below stays inside it and `scripts/run-parity.sh`
/// is what asks for the long one. The field is in `result.json`, so a reader sees
/// which workload produced the numbers beside them.
const MAX_ITERATIONS: usize = 262_144;

/// Bytes one flow may move: 16 GiB, the same ceiling the pinned schema reaches.
const MAX_FLOW_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// How an engine is told which config file to serve.
///
/// One field, and it is per engine because the three engines this harness compares
/// genuinely disagree: `Xray-core` and `xray-rust` take `run -config <path>`,
/// `sing-box` takes `run -c <path>`, and `Zray` takes the path as a bare
/// positional after `run` (`upstream/zeronet/crates/zray-cli/src/main.rs:54`).
/// The pinned harness makes the same distinction — its `EngineKind` picks `-config`
/// or `-c` before spawning (`upstream/xray-rust/crates/xray-bench/src/lib.rs:8096`).
///
/// Guessing one shape for all of them would mean every engine but one fails to
/// start, which reads as an engine that cannot serve rather than a flag that was
/// wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigArg {
    /// `run -config <path>`: Xray-core, xray-rust, and this workspace's own binary.
    Long,
    /// `run -c <path>`: sing-box.
    Short,
    /// `run <path>`: Zray.
    Positional,
}

impl ConfigArg {
    /// Parse the spelling used on the command line.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "long" | "-config" | "--config" => Ok(Self::Long),
            "short" | "-c" => Ok(Self::Short),
            "positional" | "bare" => Ok(Self::Positional),
            other => Err(Error::Invalid(format!(
                "unknown config-argument shape `{other}`. Expected one of: long \
                 (`run -config <path>`), short (`run -c <path>`), positional \
                 (`run <path>`)"
            ))),
        }
    }

    /// The arguments that name `path`, given the subcommand the engine expects.
    fn args(self, path: &Path) -> Vec<String> {
        match self {
            Self::Long => vec!["run".into(), "-config".into(), path.display().to_string()],
            Self::Short => vec!["run".into(), "-c".into(), path.display().to_string()],
            Self::Positional => vec!["run".into(), path.display().to_string()],
        }
    }
}

/// The config shape an engine parses.
///
/// Two engines in the same comparison do not read the same document, and writing
/// one shape for both does not make them comparable -- it makes the one whose
/// dialect differs fail to start, and a failed start reads exactly like an engine
/// that cannot serve. Every `parity` run until now did that to `sing-box`: the
/// harness wrote `{"protocol": "freedom"}` and `{"protocol": "socks", "port": N}`,
/// and sing-box answered `outbounds[0]: unknown outbound type: ` on all five
/// repeats of all eight runs quoted in `docs/methodology.md`. Zero rows, five
/// times over, published as `unproven`.
///
/// So the dialect is data, named per engine, and parsed at the point the engine
/// list is built rather than inferred from a label. The two differ in both the
/// key and the port field, which is why guessing one is not a shortcut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// `protocol`-keyed with `port`: the Xray family, which is `Xray-core`,
    /// `xray-rust` and this workspace's own `ferrox-app`.
    Xray,
    /// `type`-keyed with `listen_port`: `sing-box`, whose `direct` outbound
    /// replaces `freedom` and whose legacy `port` field is *rejected* rather than
    /// ignored since 1.13.0 -- read at the pin, `option/inbound.go`:
    /// `// Legacy inbound fields are rejected since sing-box 1.13.0.` with
    /// `ListenOptions` carrying `listen` and `listen_port` and no `port`
    /// (`option/inbound.go:79`-`:81`), and `SocksInboundOptions` embedding exactly
    /// that (`option/simple.go:14`-`:18`).
    SingBox,
}

impl Dialect {
    /// Parse the spelling used on the command line.
    pub fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "xray" | "protocol" => Ok(Self::Xray),
            "sing-box" | "singbox" | "type" => Ok(Self::SingBox),
            other => Err(Error::Invalid(format!(
                "unknown config dialect `{other}`. Expected one of: `xray` \
                 (`protocol`-keyed, `port`), `sing-box` (`type`-keyed, \
                 `listen_port`)"
            ))),
        }
    }

    /// The `SOCKS` inbound this dialect reads, on `listen:port`.
    ///
    /// `noauth` in both dialects: the greeting is part of what is being measured,
    /// so authentication would add a rejection that has nothing to do with the
    /// relay. `udp` is only expressed in the Xray spelling because sing-box's
    /// inbound has no such switch to turn off -- see [`inject_inbound`].
    fn socks_inbound(self, listen: Ipv4Addr, port: u16) -> Json {
        let mut inbound = Json::object();
        match self {
            Self::Xray => {
                // Tagged so matrix configs can route this inbound to a protocol
                // outbound while the protocol's own server side falls through
                // to freedom; see `inject_inbound`.
                inbound.insert("tag", Json::Str("harness-socks".into()));
                inbound.insert("protocol", Json::Str("socks".into()));
            }
            Self::SingBox => {
                inbound.insert("type", Json::Str("socks".into()));
                inbound.insert("tag", Json::Str("socks-in".into()));
            }
        }
        inbound.insert("listen", Json::Str(listen.to_string()));
        match self {
            Self::Xray => {
                inbound.insert("port", Json::Num(f64::from(port)));
            }
            Self::SingBox => {
                inbound.insert("listen_port", Json::Num(f64::from(port)));
            }
        }
        let mut settings = Json::object();
        settings.insert("auth", Json::Str("noauth".into()));
        // UDP is off: nothing here measures UDP, and an engine that spawns a
        // responder for a path this harness never exercises would only add
        // resident memory to the RSS column.
        settings.insert("udp", Json::Bool(false));
        match self {
            Self::Xray => {
                inbound.insert("settings", settings);
            }
            Self::SingBox => {
                // sing-box puts nothing in a `settings` bag for this inbound; an
                // empty `users` list *is* "no authentication required"
                // (`docs/configuration/inbound/socks.md` at the pin), and an
                // unknown key is a startup failure rather than a warning.
                let _ = settings;
                inbound.insert("users", Json::Arr(Vec::new()));
            }
        }
        inbound
    }

    /// The "send it straight out" outbound this dialect reads.
    ///
    /// `freedom` in the Xray spelling and `direct` in sing-box's, which are the
    /// same behaviour under two names -- `sing-box/constant/proxy.go:7` at the
    /// pin defines `TypeDirect = "direct"` for exactly this.
    fn direct_outbound(self) -> Json {
        let mut outbound = Json::object();
        match self {
            Self::Xray => {
                outbound.insert("protocol", Json::Str("freedom".into()));
            }
            Self::SingBox => {
                outbound.insert("type", Json::Str("direct".into()));
                outbound.insert("tag", Json::Str("direct-out".into()));
            }
        }
        outbound
    }

    /// The whole document, before the inbound is injected.
    pub fn base_config(self) -> Json {
        let mut root = Json::object();
        root.insert("outbounds", Json::Arr(vec![self.direct_outbound()]));
        match self {
            Self::Xray => {}
            Self::SingBox => {
                // sing-box defaults `route.final` to the first outbound, so an
                // empty route block is enough and a populated one would be a
                // second thing to keep in step with the harness.
                root.insert("route", Json::object());
            }
        }
        root
    }
}

/// Every field a request may carry, and nothing else. `path` is accepted for the
/// pinned harness's schema and refused in [`Request::validate`], because
/// `ferrox-app` serves no TUN device; `idle_connections`,
/// `prepare_client` and `tun`-only fields are accepted and refused the same way,
/// so a request written for the other harness produces a stated reason rather
/// than a silently different workload.
const ACCEPTED_FIELDS: [&str; 13] = [
    "binary",
    "config",
    "path",
    "traffic",
    "connections",
    "iterations",
    "payload_size",
    "output",
    "warmup",
    "prepare_client",
    "idle_connections",
    "client_env",
    "tcp_latency_iterations",
];

/// One KiB, for the `ps` RSS field to MiB.
const KIB: f64 = 1024.0;

/// The finest CPU delta this host's sampling mechanism can report, in
/// milliseconds. A sample delta below this is not "no CPU was used", it is "the
/// mechanism does not count that finely", and naming it keeps a `0` in a CPU
/// column from being read as free work.
///
/// A function, not the constant it used to be. The constant said 10 ms, which is
/// what the *kernel* resolves, and the mechanism then threw it away: GNU `ps`
/// prints `TIME` in whole seconds, so every Linux run of gate 5 measured 0 ms of
/// CPU for every engine and the row read `UNPROVEN` in all of them. `ps` is still
/// what carries RSS and the thread count; CPU now comes from `/proc/<pid>/stat`,
/// which is where `ps` read it from before formatting it, so the published floor
/// is finally the resolution of the thing that produced the number. See [`ps`].
pub fn cpu_resolution_floor_millis() -> u64 {
    crate::ps::resolution_millis()
}

/// Phase tags, identical strings to `xray-bench`'s `BenchmarkPhase`
/// (`lib.rs:606`) so a consumer of both `result.json` files reads one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Startup,
    Traffic,
    Settle,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Traffic => "traffic",
            Self::Settle => "settle",
        }
    }
}

/// Direction of the measured traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Traffic {
    Upload,
    Download,
    FullDuplex,
}

impl Traffic {
    fn parse(raw: &str) -> Result<Self, Error> {
        match raw {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            "full-duplex" => Ok(Self::FullDuplex),
            other => Err(Error::Invalid(format!("unknown traffic `{other}`"))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::FullDuplex => "full-duplex",
        }
    }

    const fn uplink(self) -> bool {
        matches!(self, Self::Upload | Self::FullDuplex)
    }

    const fn downlink(self) -> bool {
        matches!(self, Self::Download | Self::FullDuplex)
    }
}

/// A parsed request. An unknown field is an error, as it is in the pinned
/// harness (`#[serde(deny_unknown_fields)]`, `protocol_bench.rs:8`): a field one
/// implementation reads and the other ignores is two different measurements of a
/// field name.
#[derive(Debug, Clone)]
pub struct Request {
    pub binary: PathBuf,
    /// Outbound-only configuration; the harness injects the SOCKS inbound.
    pub config: String,
    /// Accepted for the pinned harness's schema; only `"socks"` is implemented,
    /// and [`Request::validate`] refuses the rest with its reason.
    pub path: String,
    pub traffic: Traffic,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    /// Must not exist: the harness creates it, so a stale directory left by an
    /// aborted run cannot be read as this run's output.
    pub output: PathBuf,
    pub warmup: bool,
    /// Accepted for the pinned harness's schema, refused in
    /// [`Request::validate`] with its reason.
    pub idle_connections: usize,
    /// Accepted for the pinned harness's schema, refused in
    /// [`Request::validate`] with its reason.
    pub prepare_client: bool,
    pub client_env: BTreeMap<String, String>,
}

/// A request that cannot be honoured, with the reason.
#[derive(Debug)]
pub enum Error {
    /// A field outside the documented bounds, or an unreadable document.
    Invalid(String),
    Io {
        action: String,
        source: std::io::Error,
    },
    /// The engine binary would not start, or exited during startup.
    Engine { message: String },
    /// The workload did not complete correctly.
    Workload(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) => write!(f, "{m}"),
            Self::Io { action, source } => write!(f, "{action}: {source}"),
            Self::Engine { message } => write!(f, "engine: {message}"),
            Self::Workload(m) => write!(f, "workload: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Lift an I/O failure with the action that was being attempted, so an error
/// message says which of the harness's sockets failed rather than just "I/O error".
fn io(action: &'static str) -> impl FnOnce(std::io::Error) -> Error {
    move |source| Error::Io {
        action: action.to_owned(),
        source,
    }
}

impl Request {
    /// Read and validate a request file.
    pub fn read(path: &Path) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(io("reading the request"))?;
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(Error::Invalid(format!(
                "benchmark request exceeds {MAX_REQUEST_BYTES} bytes"
            )));
        }
        Self::parse(&bytes)
    }

    /// Validate an in-memory request document.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| Error::Invalid("request is not UTF-8".into()))?;
        let root = json::parse(text).map_err(|e| Error::Invalid(format!("bad request: {e}")))?;

        // `deny_unknown_fields`, as the pinned harness has it
        // (`#[serde(deny_unknown_fields)]`, `protocol_bench.rs:8`). The reason is
        // not tidiness: a request file is handed to *both* harnesses, and a field
        // one reads while the other ignores it means the two ran different
        // workloads under one name. Failing closed is the only way a request
        // means the same thing on both sides.
        if let Some(pairs) = root.as_obj() {
            for (key, _) in pairs {
                if !ACCEPTED_FIELDS.contains(&key.as_str()) {
                    return Err(Error::Invalid(format!(
                        "unknown request field `{key}`. Accepted: {}. An \
                         unrecognised field is an error rather than a shrug \
                         because the same file is read by the pinned harness too, \
                         and a field only one of them honours is two different \
                         measurements of one name.",
                        ACCEPTED_FIELDS.join(", ")
                    )));
                }
            }
        }

        let string = |key: &str| -> Result<String, Error> {
            root.get(key)
                .and_then(Json::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| Error::Invalid(format!("request needs a string `{key}`")))
        };
        let count = |key: &str| -> Result<usize, Error> {
            let n = root
                .get(key)
                .and_then(Json::as_num)
                .ok_or_else(|| Error::Invalid(format!("request needs a number `{key}`")))?;
            if n < 0.0 || n.fract() != 0.0 {
                return Err(Error::Invalid(format!("`{key}` must be a whole count")));
            }
            Ok(n as usize)
        };

        let request = Self {
            binary: PathBuf::from(string("binary")?),
            config: string("config")?,
            path: string("path")?,
            traffic: Traffic::parse(&string("traffic")?)?,
            connections: count("connections")?,
            iterations: count("iterations")?,
            payload_size: count("payload_size")?,
            output: PathBuf::from(string("output")?),
            warmup: matches!(root.get("warmup").and_then(Json::as_bool), Some(true)),
            idle_connections: root
                .get("idle_connections")
                .and_then(Json::as_num)
                .map_or(0, |n| n.max(0.0) as usize),
            prepare_client: matches!(
                root.get("prepare_client").and_then(Json::as_bool),
                Some(true)
            ),
            client_env: read_env(&root)?,
        };
        request.validate()?;
        Ok(request)
    }

    /// The bounds, and why they are the pinned harness's rather than chosen here.
    pub fn validate(&self) -> Result<(), Error> {
        // Fields the pinned harness accepts and this one cannot honour. Each is
        // refused with its reason rather than ignored: an ignored field is a
        // request that quietly measured something else.
        if self.path != "socks" {
            return Err(Error::Invalid(format!(
                "path `{}` is not implemented here: this harness drives a SOCKS \
                 inbound, because `ferrox-app` serves no TUN device. The \
                 pinned harness's `tun` workloads are listed as `not_covered` in \
                 docs/methodology.md",
                self.path
            )));
        }
        if self.idle_connections != 0 {
            return Err(Error::Invalid(format!(
                "idle_connections {} is not implemented here: this harness has no \
                 held-open workload, so the resident-memory-per-idle-flow \
                 measurement the pinned harness takes cannot be produced",
                self.idle_connections
            )));
        }
        if self.prepare_client {
            return Err(Error::Invalid(
                "prepare_client is not implemented here: it exists so a Go engine's \
                 launcher CPU does not bias its lifetime figure, and \
                 ferrox-app is exec'd directly with no launcher"
                    .into(),
            ));
        }
        if !(1..=16).contains(&self.connections) {
            return Err(Error::Invalid(format!(
                "connections {} is outside 1..=16",
                self.connections
            )));
        }
        if !(1..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::Invalid(format!(
                "iterations {} is outside 1..={MAX_ITERATIONS}",
                self.iterations
            )));
        }
        if !(1..=65_536).contains(&self.payload_size) {
            return Err(Error::Invalid(format!(
                "payload_size {} is outside 1..=65536",
                self.payload_size
            )));
        }
        if self.flow_bytes() > MAX_FLOW_BYTES {
            return Err(Error::Invalid(format!(
                "{} bytes per flow is above the {MAX_FLOW_BYTES} B ceiling: a run \
                 that cannot finish inside the {} s cap would report a truncated \
                 transfer as a rate",
                self.flow_bytes(),
                RUN_TIMEOUT.as_secs()
            )));
        }
        if self.output.exists() {
            return Err(Error::Invalid(format!(
                "output {} already exists; the harness creates it, so a stale \
                 directory cannot be read as this run's result",
                self.output.display()
            )));
        }
        if !self.binary.is_file() {
            return Err(Error::Invalid(format!(
                "binary {} is not a file",
                self.binary.display()
            )));
        }
        json::parse(&self.config)
            .map_err(|e| Error::Invalid(format!("config is not valid json: {e}")))?;
        Ok(())
    }

    /// Total payload one flow moves.
    ///
    /// Widened before it is multiplied: `payload_size * iterations` is at most
    /// 65536 * 262144 = 2^34, which a `usize` holds on every target here, but the
    /// product is a byte count against a `u64` cap and doing the arithmetic in
    /// the narrower type would make the cap a cap on the wrong quantity.
    pub fn flow_bytes(&self) -> u64 {
        u64::try_from(self.payload_size).unwrap_or(u64::MAX)
            * u64::try_from(self.iterations).unwrap_or(u64::MAX)
    }

    /// Total payload across every flow, **counting both directions of a
    /// full-duplex cell**.
    ///
    /// This is what a flow's `sent + received` must equal, and a full-duplex flow
    /// moves `flow_bytes` up *and* `flow_bytes` down. The doubled figure is the
    /// reason a duplex cell used to be reported as a short transfer in the one
    /// direction it could not be short in: it read `moved 8589934592 of
    /// 4294967296`, having moved exactly twice what was asked of it, and the
    /// reader -- correctly, from its own point of view -- called that a fault.
    pub fn total_bytes(&self) -> u64 {
        let per_flow = self.flow_bytes();
        let directions = u64::from(self.traffic.uplink()) + u64::from(self.traffic.downlink());
        per_flow
            .saturating_mul(u64::try_from(self.connections).unwrap_or(0))
            .saturating_mul(directions)
    }
}

/// Read `client_env`, rejecting a non-string value rather than stringifying it.
fn read_env(root: &Json) -> Result<BTreeMap<String, String>, Error> {
    let mut out = BTreeMap::new();
    let Some(env) = root.get("client_env") else {
        return Ok(out);
    };
    if env == &Json::Null {
        return Ok(out);
    }
    let pairs = env
        .as_obj()
        .ok_or_else(|| Error::Invalid("client_env must be an object".into()))?;
    for (key, value) in pairs {
        let text = value
            .as_str()
            .ok_or_else(|| Error::Invalid(format!("client_env.{key} must be a string")))?;
        out.insert(key.clone(), text.to_owned());
    }
    Ok(out)
}

/// One flow's setup, split into stages so a difference between two engines can be
/// attributed to a stage rather than to a single opaque total. Field-for-field
/// the pinned harness's `FlowSetupSample` (`lib.rs:804`).
///
/// The shared `_us` suffix is the pinned harness's own field naming and is kept
/// on purpose: it is what makes the `setup` object in a `result.json` written here
/// readable by a consumer written for their harness. The unit belongs in the name
/// rather than in the type because a `result.json` field has no type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub struct Setup {
    pub tcp_connect_us: u128,
    pub socks_method_us: u128,
    pub socks_connect_us: u128,
    pub socks_setup_us: u128,
    /// First byte on the wire to the flow being ready, which is not the same as
    /// the SOCKS reply: several engines acknowledge SOCKS before the transport
    /// handshake and the remote CONNECT have finished
    /// (`upstream/xray-rust/crates/xray-bench/src/stream_transport.rs:767`).
    ///
    /// The `_us` suffix is on every field on purpose: it is the pinned harness's
    /// own field naming (`FlowSetupSample`, `lib.rs:804`), and a request or a
    /// result file whose keys match theirs is the whole point of speaking their
    /// schema. The unit is in the name, not in the type.
    pub total_us: u128,
}

/// One setup stage and how to read it out of a [`Setup`].
///
/// A named type because the alternative is a bare `(&str, fn(&Setup) -> u128)`
/// pair repeated in two places, and a signature that has to be re-read to learn
/// which end is which is exactly the kind that gets transposed.
type SetupStage = (&'static str, fn(&Setup) -> u128);

/// A `min`/`median`/`p95`/`p99` summary, as `LatencySummary` (`lib.rs:788`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quartiles {
    pub min: u128,
    pub median: u128,
    pub p95: u128,
    pub p99: u128,
}

/// What one run measured.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Earliest flow's first validated byte to the latest flow's last. Setup is
    /// excluded from every flow's window, so this is a transfer window and not
    /// a wall clock.
    pub transfer: Duration,
    pub wall: Duration,
    pub setup: Vec<Setup>,
    pub peak_rss_kib: u64,
    pub cpu_millis: u64,
    /// How many readings landed inside the transfer window. Below a handful the CPU
    /// column is a single `ps` reading and is reported as such rather than as a
    /// measurement — the kernel's own resolution is 10 ms
    /// ([`cpu_resolution_floor_millis`]) and the sampling period is 100 ms, so a
    /// window shorter than a few intervals cannot be resolved.
    pub traffic_samples: usize,
    pub threads_peak: Option<u64>,
    /// Cumulative CPU at the first sample after the engine answered.
    pub startup_cpu_millis: u64,
    pub startup_seconds: f64,
    pub samples: Vec<(Phase, ps::Sample)>,
}

/// One complete run: the samples, the derived metrics, and the engine identity
/// the numbers are attributable to.
#[derive(Debug)]
pub struct Run {
    pub engine: String,
    pub engine_sha256: String,
    pub outcome: Outcome,
}

impl Run {
    /// `(sent + received) / MiB / seconds`: the pinned harness's
    /// `throughput_mib_s` (`protocol_bench.rs:301`).
    pub fn throughput_mib_s(&self) -> f64 {
        let seconds = self.outcome.transfer.as_secs_f64();
        if seconds <= 0.0 {
            return 0.0;
        }
        let total = (self.outcome.bytes_sent + self.outcome.bytes_received) as f64;
        total / (1024.0 * 1024.0) / seconds
    }

    /// CPU milliseconds per GiB moved: the metric both pinned harnesses chart
    /// (`upstream/zeronet/docs/benchmarks/harness/zbench/report.py:138`).
    pub fn cpu_millis_per_gib(&self) -> f64 {
        let bytes = self.outcome.bytes_sent + self.outcome.bytes_received;
        if bytes == 0 {
            return 0.0;
        }
        self.outcome.cpu_millis as f64 / (bytes as f64 / 1_073_741_824.0)
    }

    /// Peak RSS in MiB, the unit both harnesses chart.
    pub fn rss_mib(&self) -> f64 {
        self.outcome.peak_rss_kib as f64 / KIB
    }

    /// `min`/`median`/`p95`/`p99` of a stage, or `None` for no samples.
    fn quartiles(values: &[u128]) -> Option<Quartiles> {
        if values.is_empty() {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        Some(Quartiles {
            min: sorted[0],
            median: median(&sorted),
            p95: nearest_rank(&sorted, 95),
            p99: nearest_rank(&sorted, 99),
        })
    }

    /// Serialise to the pinned harness's `result.json` field set.
    ///
    /// Every field is present, with `null` rather than absence for the ones this
    /// harness cannot measure: a missing key and a `null` read differently to a
    /// script, and a script is what consumes this file. `tun_fd_buffers`,
    /// `idle_connections`, `prepare_client` and the latency percentiles are
    /// emitted because the schema has them, carrying the values that mean
    /// "not applicable to a SOCKS-path run" rather than being quietly dropped.
    pub fn to_result_json(&self, request: &Request) -> Json {
        let o = &self.outcome;
        let stages: [SetupStage; 5] = [
            ("tcp_connect_us", |s| s.tcp_connect_us),
            ("socks_method_us", |s| s.socks_method_us),
            ("socks_connect_us", |s| s.socks_connect_us),
            ("socks_setup_us", |s| s.socks_setup_us),
            ("total_us", |s| s.total_us),
        ];
        let mut setup = Json::object();
        for (key, read) in stages {
            let values: Vec<u128> = o.setup.iter().map(read).collect();
            setup.insert(key, optional_quartiles_json(Run::quartiles(&values)));
        }

        let mut samples = Vec::new();
        for (phase, s) in &o.samples {
            let mut item = Json::object();
            item.insert("elapsed_ms", Json::Num(s.elapsed_ms as f64));
            item.insert("rss_kib", Json::Num(s.rss_kib as f64));
            item.insert("cpu_millis", Json::Num(s.cpu_millis as f64));
            item.insert(
                "threads",
                match s.threads {
                    Some(t) => Json::Num(t as f64),
                    None => Json::Null,
                },
            );
            item.insert("phase", Json::Str(phase.as_str().to_owned()));
            samples.push(item);
        }

        let mut root = Json::object();
        root.insert("status", Json::Str("pass".into()));
        root.insert("harness", Json::Str(HARNESS_ID.into()));
        root.insert("path", Json::Str("socks".into()));
        root.insert("traffic", Json::Str(request.traffic.as_str().into()));
        root.insert("connections", Json::Num(request.connections as f64));
        root.insert("iterations", Json::Num(request.iterations as f64));
        root.insert("payload_size", Json::Num(request.payload_size as f64));
        root.insert("idle_connections", Json::Num(0.0));
        root.insert("concurrent_flows", Json::Num(request.connections as f64));
        root.insert("bytes_sent", Json::Num(o.bytes_sent as f64));
        root.insert("bytes_received", Json::Num(o.bytes_received as f64));
        root.insert("expected_bytes", Json::Num(request.total_bytes() as f64));
        root.insert("transfer_seconds", Json::Num(o.transfer.as_secs_f64()));
        root.insert("wall_seconds", Json::Num(o.wall.as_secs_f64()));
        root.insert("throughput_mib_s", Json::Num(self.throughput_mib_s()));
        root.insert("peak_rss_kib", Json::Num(o.peak_rss_kib as f64));
        root.insert("cpu_millis", Json::Num(o.cpu_millis as f64));
        root.insert("cpu_millis_per_gib", Json::Num(self.cpu_millis_per_gib()));
        root.insert(
            "cpu_resolution_floor_millis",
            Json::Num(cpu_resolution_floor_millis() as f64),
        );
        root.insert(
            "threads_peak",
            match o.threads_peak {
                Some(t) => Json::Num(t as f64),
                None => Json::Null,
            },
        );
        root.insert("warmup", Json::Bool(request.warmup));
        root.insert("prepare_client", Json::Bool(false));
        root.insert("client_startup_seconds", Json::Num(o.startup_seconds));
        root.insert(
            "client_startup_cpu_millis",
            Json::Num(o.startup_cpu_millis as f64),
        );
        root.insert("client_cpu_total_millis", Json::Num(o.cpu_millis as f64));
        root.insert("engine_binary", Json::Str(self.engine.clone()));
        root.insert("engine_sha256", Json::Str(self.engine_sha256.clone()));
        root.insert("setup", setup);
        // This harness measures throughput, not per-packet latency; the field is
        // present and null rather than absent.
        root.insert("latency_us", Json::Null);
        root.insert("tun_fd_buffers", Json::Null);
        root.insert("samples", Json::Arr(samples));
        root
    }
}

/// A `Quartiles` as JSON, or `null` when there were no samples. A stage with no
/// samples is `null` rather than a row of zeroes, so a consumer can tell "no
/// measurement" from "measured zero".
fn optional_quartiles_json(q: Option<Quartiles>) -> Json {
    q.map_or(Json::Null, quartiles_json)
}

fn quartiles_json(q: Quartiles) -> Json {
    let mut out = Json::object();
    out.insert("min", Json::Num(q.min as f64));
    out.insert("median", Json::Num(q.median as f64));
    out.insert("p95", Json::Num(q.p95 as f64));
    out.insert("p99", Json::Num(q.p99 as f64));
    out
}

/// Median of a slice, averaging the middle pair on an even count.
pub fn median(sorted: &[u128]) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        // `midpoint` cannot overflow for the latencies this measures: both are
        // microsecond counts far below `u128::MAX / 2`.
        u128::midpoint(sorted[mid - 1], sorted[mid])
    } else {
        sorted[mid]
    }
}

/// Nearest-rank percentile, as `percentile_nearest_rank` in the pinned harness.
pub fn nearest_rank(sorted: &[u128], pct: u128) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len() as u128).div_ceil(100);
    sorted[((rank.max(1) - 1) as usize).min(sorted.len() - 1)]
}

/// The deterministic payload template: an xorshift64 keystream.
///
/// Not a constant and not a repeated constant, for the reason the pinned
/// harnesses give: a constant payload cannot detect a core that moves the right
/// number of bytes in the wrong order.
pub fn bulk_pattern_template(payload_size: usize) -> Vec<u8> {
    let mut state = BULK_PATTERN_SEED;
    let mut out = Vec::with_capacity(payload_size);
    for _ in 0..payload_size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> 32) as u8);
    }
    out
}

/// The local non-loopback IPv4 address, so no engine's dial takes a loopback
/// shortcut the others do not.
///
/// The pinned harness's own rule (`lib.rs:5060`): a UDP socket is connected to a
/// public address purely to make the kernel pick the source address, and the
/// result is rejected unless it is a real unicast address. Everything bound to
/// `127.0.0.1` would let each engine take whichever loopback path suits it, and
/// the comparison would be a comparison of those choices.
///
/// # Which address, and why the report has to name it
///
/// This resolves through the *routing table* rather than through an interface
/// list, so what it returns is wherever the kernel would send a packet to the
/// public internet. With a VPN up that is the tunnel's address, and with it down
/// it is the ethernet's -- the same binary, the same workload, two different
/// measurements, and the report could not tell a reader which had happened because
/// it never said.
///
/// So the address is named on the machine line of every gate-5 report. That is the
/// whole fix: not a preference for one interface over another, which would be a
/// guess about which is faster, but the removal of a variable the report was
/// silently carrying.
pub fn local_non_loopback_ipv4() -> Result<Ipv4Addr, Error> {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(io("binding the probe socket"))?;
    socket
        .connect((Ipv4Addr::new(8, 8, 8, 8), 80))
        .map_err(io("probing the local non-loopback IPv4 address"))?;
    let SocketAddr::V4(addr) = socket
        .local_addr()
        .map_err(io("reading the probe address"))?
    else {
        return Err(Error::Invalid(
            "the probe socket has no IPv4 address".into(),
        ));
    };
    let ip = *addr.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Err(Error::Invalid(format!(
            "this host has no usable non-loopback IPv4 address (the probe gave {ip}); \
             a loopback-only host cannot run this benchmark, because the engines \
             would be measured over different loopback paths"
        )));
    }
    Ok(ip)
}

/// A port the kernel has just confirmed free.
///
/// Racy in principle and the comment in the pinned harness is honest about it: a
/// listener is bound and dropped, so the port is free at that instant. Used for
/// the fixture and inbound ports only; readiness is then confirmed by connecting,
/// so a stolen port shows up as an engine that never listens rather than as a
/// silent mismeasurement.
/// `count` consecutive free ports on `ip`, all held until the caller drops them.
///
/// **All of them are bound before any is returned**, and that is the point: a
/// range probed one port at a time can hand out a port the *next* probe is about
/// to take, which is how the sink and the engine ended up wanting one number.
fn allocate_port_range(count: usize) -> Result<Vec<u16>, Error> {
    let ip = local_non_loopback_ipv4()?;
    let mut held = Vec::with_capacity(count);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let listener = TcpListener::bind((ip, 0)).map_err(io("allocating a sink port"))?;
        let port = listener
            .local_addr()
            .map_err(io("reading a sink port"))?
            .port();
        held.push(listener);
        out.push(port);
    }
    Ok(out)
}

/// One free port on `ip` that is not in `taken`.
///
/// Binds and closes, which is racy in principle and bounded in practice: the
/// window is microseconds and readiness is confirmed afterwards by connecting,
/// so a port stolen in the meantime surfaces as an engine that never listens
/// rather than as a silent mismeasurement.
fn allocate_port_excluding(ip: Ipv4Addr, taken: &[u16]) -> Result<u16, Error> {
    for _ in 0..64 {
        let listener = TcpListener::bind((ip, 0)).map_err(io("allocating a port"))?;
        let port = listener.local_addr().map_err(io("reading a port"))?.port();
        drop(listener);
        if !taken.contains(&port) {
            return Ok(port);
        }
    }
    Err(Error::Workload(
        "could not find a free port clear of the sink's range".into(),
    ))
}

/// An engine that is killed and reaped on every exit path, including a failed
/// workload and an early return.
///
/// The same guard the pinned harness uses (`protocol_bench.rs:35-46`): a benchmark
/// that leaks its engine leaves a process holding the port, and the next repeat
/// then measures a different machine.
struct Engine {
    child: Child,
}

impl Engine {
    fn reap(&mut self) {
        // Failure to kill is not an error: the process may already have exited,
        // which is the outcome wanted.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.reap();
    }
}

/// Measure one engine against one request.
///
/// The measured process is the engine and only the engine: the sink is in this
/// process and is never sampled, exactly as the pinned harness excludes its
/// fixture (`upstream/xray-rust/docs/benchmarks.md:209-211`). Sampling the sink
/// too would charge our own driver to whichever engine happened to be slower.
pub fn measure(request: &Request, config_arg: ConfigArg, dialect: Dialect) -> Result<Run, Error> {
    let ip = local_non_loopback_ipv4()?;
    // Both ports are allocated on the address the harness actually binds, and the
    // sink's whole **range** is reserved before the engine's port is drawn.
    //
    // Two things were wrong and either alone breaks every multi-flow cell.
    //
    // `allocate_port` probed `127.0.0.1:0` while every listener is bound on the
    // non-loopback address, so the two were drawn from disjoint pools and the
    // number the kernel handed the engine was never checked against the number
    // the sink was about to take. And the sink takes `connections` consecutive
    // ports, not one, so even a same-address probe that only checked the sink's
    // *first* port would miss the engine sitting seven ports along inside the
    // range.
    //
    // The result was that at two flows the engine's `SOCKS` inbound and one of
    // the sink's per-flow listeners wanted the same port on the same address.
    // Whoever bound second lost: either the engine exits (`Address already in
    // use`) and every flow then reports "could not connect to the engine", or the
    // sink's listener is gone and its flow reports the engine closed the upload.
    // Both messages blame the engine, and the run takes the full start-up timeout
    // to say so.
    let sink_ports = allocate_port_range(request.connections)?;
    let sink_port = sink_ports[0];
    let engine_port = allocate_port_excluding(ip, &sink_ports)?;

    std::fs::create_dir_all(&request.output).map_err(io("creating the output directory"))?;
    let config_path = request.output.join("config.json");
    let stderr_path = request.output.join("stderr.log");
    let stdout_path = request.output.join("stdout.log");

    let sink_thread = spawn_sink(ip, &sink_ports, request)?;
    let config_text = inject_inbound(&request.config, ip, engine_port, dialect)?;
    std::fs::write(&config_path, &config_text).map_err(io("writing the engine config"))?;

    let started = Instant::now();
    let mut engine = spawn_engine(
        request,
        config_arg,
        &config_path,
        &stdout_path,
        &stderr_path,
    )?;
    let pid = engine.child.id();
    let socks = SocketAddr::from((ip, engine_port));
    if let Err(e) = wait_for_listener(&mut engine.child, socks, &stderr_path) {
        return Err(Error::Engine {
            message: format!("{e}; stderr tail: {}", tail(&stderr_path)),
        });
    }

    // Startup phase: the pre-work sleep, sampled, which is also where the startup
    // CPU figure is taken from.
    let startup_samples = sample_for(pid, Phase::Startup, PRE_SLEEP)?;
    let startup_cpu_millis = startup_samples
        .first()
        .map(|(_, s)| s.cpu_millis)
        .unwrap_or_default();
    // `startup_samples` is moved into the window below, so the CPU total is taken
    // against the same first reading the samples vector starts with.

    if request.warmup {
        warmup(socks, &bulk_pattern_template(request.payload_size))?;
    }

    let target = SocketAddr::from((ip, sink_port));
    let (flows, sampler_thread, stop, rx) = start_traffic(pid, request, socks, target);
    let wall = Instant::now();
    let moved = collect_flows(flows, &stop)?;
    let wall_elapsed = wall.elapsed();
    if wall_elapsed > RUN_TIMEOUT {
        stop.store(true, Ordering::Relaxed);
        return Err(Error::Workload(format!(
            "workload exceeded the {}s cap",
            RUN_TIMEOUT.as_secs()
        )));
    }

    // One last traffic-phase reading after the flows close, so a peak that appears
    // as the workload ends is inside the window rather than after it.
    std::thread::sleep(SAMPLE_INTERVAL + Duration::from_millis(20));
    stop.store(true, Ordering::Relaxed);
    let _ = sampler_thread.join();
    // The startup readings are part of the window, and they have to be in it: the
    // CPU figure is a delta from the first of them, so leaving them out of the
    // vector would make the published total unre-derivable from the published
    // samples. That is not a formatting preference — `revalidate` checks it.
    let mut samples = startup_samples;
    samples.extend(rx.try_iter());
    // Settle, then more readings, so the settled figure is in the samples too.
    samples.extend(sample_for(pid, Phase::Settle, SETTLE)?);

    engine.reap();
    let sink_reasons = sink_thread.reasons();
    sink_thread.join()?;

    let expected = request.total_bytes();
    if moved.sent + moved.received != expected {
        let mut why = if moved.all_stopped.is_empty() {
            vec!["no flow reported why it stopped".to_owned()]
        } else {
            moved.all_stopped.clone()
        };
        why.extend(sink_reasons);
        return Err(Error::Workload(format!(
            "moved {} of {expected} bytes: a short transfer is a fault in the \
             workload, not a number to report. {}",
            moved.sent + moved.received,
            why.join("; ")
        )));
    }

    let summary = summarise(&samples, &moved, startup_cpu_millis);
    Ok(Run {
        engine: request.binary.display().to_string(),
        engine_sha256: file_sha256(&request.binary),
        outcome: Outcome {
            bytes_sent: moved.sent,
            bytes_received: moved.received,
            transfer: summary.transfer,
            wall: wall_elapsed,
            setup: moved.setup,
            peak_rss_kib: summary.peak_rss_kib,
            cpu_millis: summary.cpu_millis,
            traffic_samples: summary.traffic_samples,
            threads_peak: summary.threads_peak,
            startup_cpu_millis,
            startup_seconds: started.elapsed().as_secs_f64(),
            samples,
        },
    })
}

/// What the sample vector says, once.
struct Summary {
    peak_rss_kib: u64,
    cpu_millis: u64,
    traffic_samples: usize,
    threads_peak: Option<u64>,
    transfer: Duration,
}

/// Fold the readings and the flows into the figures the report publishes.
///
/// The CPU total is a delta from the *first* reading, which is a startup reading:
/// it is what the engine had spent before the workload began. The union of the
/// flows' own windows is the transfer window, because each flow's window already
/// excludes that flow's setup — and with no flow having moved bytes there is no
/// window at all, and reporting zero would make throughput infinite.
fn summarise(samples: &[(Phase, ps::Sample)], moved: &Moved, startup_cpu_millis: u64) -> Summary {
    Summary {
        peak_rss_kib: samples
            .iter()
            .map(|(_, s)| s.rss_kib)
            .max()
            .unwrap_or_default(),
        cpu_millis: samples
            .last()
            .map(|(_, s)| s.cpu_millis)
            .unwrap_or_default()
            .saturating_sub(startup_cpu_millis),
        traffic_samples: samples
            .iter()
            .filter(|(phase, _)| *phase == Phase::Traffic)
            .count(),
        threads_peak: samples.iter().filter_map(|(_, s)| s.threads).max(),
        transfer: moved
            .window
            .map_or(Duration::ZERO, |(a, b)| b.saturating_duration_since(a)),
    }
}

/// Spawn the engine, with its output redirected to files in the run directory.
fn spawn_engine(
    request: &Request,
    config_arg: ConfigArg,
    config_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<Engine, Error> {
    let child = Command::new(&request.binary)
        .args(config_arg.args(config_path))
        .envs(&request.client_env)
        .stdout(Stdio::from(
            std::fs::File::create(stdout_path).map_err(io("creating stdout.log"))?,
        ))
        .stderr(Stdio::from(
            std::fs::File::create(stderr_path).map_err(io("creating stderr.log"))?,
        ))
        .spawn()
        .map_err(|e| Error::Engine {
            message: format!("cannot spawn {}: {e}", request.binary.display()),
        })?;
    Ok(Engine { child })
}

/// The traffic phase: one thread per flow and one sampling thread.
///
/// Flows are on their own threads so `full-duplex` is genuinely concurrent and a
/// slow flow cannot serialise the others behind it. The sampler reads `ps` on a
/// fixed interval for the whole window, exactly as the pinned harness's
/// `sample_while_phased` does at the traffic phase (`protocol_bench.rs:271`).
type TrafficPhase = (
    Vec<JoinHandle<FlowResult>>,
    JoinHandle<()>,
    Arc<AtomicBool>,
    mpsc::Receiver<(Phase, ps::Sample)>,
);

fn start_traffic(
    pid: u32,
    request: &Request,
    engine: SocketAddr,
    target: SocketAddr,
) -> TrafficPhase {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<(Phase, ps::Sample)>();
    let sampler_thread = spawn_sampler(pid, Arc::clone(&stop), tx);
    (
        spawn_flows(request, engine, target),
        sampler_thread,
        stop,
        rx,
    )
}

/// What every flow together moved.
struct Moved {
    sent: u64,
    received: u64,
    /// The union of the flows' own transfer windows.
    window: Option<(Instant, Instant)>,
    setup: Vec<Setup>,
    /// Why a flow stopped early, if one did.
    stopped: Option<String>,
    /// Every flow's reason, not just the first.
    ///
    /// With one flow the two are the same thing. With several, keeping only the
    /// first means the report names whichever flow happened to be collected first
    /// and drops the rest -- and those two can be *different faults*, one from
    /// the driver and one from the sink, which is exactly the case where naming
    /// one alone sends the reader after the wrong subsystem. It cost real time
    /// here: an upload cell at two flows reported "could not connect to the
    /// engine" from the driver while the sink had independently seen "the engine
    /// closed the upload after 0 bytes", and neither line explained the failure.
    all_stopped: Vec<String>,
}

/// Join every flow and fold their windows together.
///
/// A missing window on either side keeps the other: a flow that moved nothing is
/// absent from the window rather than collapsing it to zero.
fn collect_flows(
    flows: Vec<JoinHandle<FlowResult>>,
    stop: &Arc<AtomicBool>,
) -> Result<Moved, Error> {
    let mut moved = Moved {
        sent: 0,
        received: 0,
        window: None,
        setup: Vec::new(),
        stopped: None,
        all_stopped: Vec::new(),
    };
    for flow in flows {
        let result = flow
            .join()
            .map_err(|_| Error::Workload("a flow thread panicked".into()))?;
        moved.sent += result.bytes_sent;
        moved.received += result.bytes_received;
        moved.setup.push(result.setup);
        if let Some(reason) = result.stopped {
            moved.stopped.get_or_insert(reason.clone());
            moved.all_stopped.push(reason);
        }
        moved.window = match (moved.window, result.window) {
            (None, w) => w,
            (Some((a, b)), Some((c, d))) => Some((a.min(c), b.max(d))),
            (current, None) => current,
        };
    }
    let _ = stop;
    Ok(moved)
}

/// Read the last few lines of the engine's stderr, for a failure message.
fn tail(path: &Path) -> String {
    std::fs::read_to_string(path).map_or_else(
        |_| "<unreadable>".into(),
        |text| {
            let lines: Vec<&str> = text.lines().collect();
            if lines.is_empty() {
                return "<empty>".into();
            }
            lines[lines.len().saturating_sub(4)..].join(" | ")
        },
    )
}

/// Wait for the engine to answer on its SOCKS port.
///
/// Readiness is a successful connect, not a log line: the two engines log
/// differently and neither is required to log at all. A process that has exited
/// will never listen, so that is reported first rather than after the timeout.
fn wait_for_listener(child: &mut Child, addr: SocketAddr, stderr: &Path) -> Result<(), Error> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().map_err(io("polling the engine"))? {
            return Err(Error::Engine {
                message: format!(
                    "exited during startup with {status}; stderr tail: {}",
                    tail(stderr)
                ),
            });
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::Engine {
                message: format!("did not listen on {addr} within 20s"),
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Take `duration` worth of samples in one phase.
fn sample_for(
    pid: u32,
    phase: Phase,
    duration: Duration,
) -> Result<Vec<(Phase, ps::Sample)>, Error> {
    let host = Host::current();
    let start = Instant::now();
    let first = sample_at(host, pid, 0)?;
    let mut samples = vec![(phase, first)];
    while start.elapsed() < duration {
        // `saturating_sub` because the loop condition is checked against a
        // *fresh* `elapsed()`: the two reads can straddle the deadline, and a
        // panic on a subtraction that raced would be the worst possible report.
        let remaining = duration.saturating_sub(start.elapsed());
        std::thread::sleep(SAMPLE_INTERVAL.min(remaining));
        samples.push((phase, sample_at(host, pid, start.elapsed().as_millis())?));
    }
    Ok(samples)
}

fn sample_at(host: Host, pid: u32, elapsed_ms: u128) -> Result<ps::Sample, Error> {
    ps::sample(host, pid, elapsed_ms).map_err(|e| Error::Engine {
        message: format!("cannot sample the engine: {e}"),
    })
}

/// Sample the engine every interval until `stop`, tagging every reading
/// `Traffic`. The pinned harness's `sample_while_phased` at the traffic phase
/// (`protocol_bench.rs:271`).
fn spawn_sampler(
    pid: u32,
    stop: Arc<AtomicBool>,
    tx: mpsc::Sender<(Phase, ps::Sample)>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let host = Host::current();
        let start = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(SAMPLE_INTERVAL);
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Ok(sample) = ps::sample(host, pid, start.elapsed().as_millis()) {
                // A closed channel means the reader is gone; stop rather than
                // spin on a send that will never be received.
                if tx.send((Phase::Traffic, sample)).is_err() {
                    break;
                }
            }
        }
    })
}

/// One flow's validated outcome.
struct FlowResult {
    bytes_sent: u64,
    bytes_received: u64,
    /// This flow's own transfer window: first validated byte to last. Excludes
    /// this flow's setup, which is what makes the union of them a transfer window
    /// rather than a wall clock.
    window: Option<(Instant, Instant)>,
    setup: Setup,
    /// Why the flow stopped early, if it did. Recorded rather than inferred: a
    /// short transfer reported as a byte count sends the reader looking at the
    /// engine, when the fault may have been in the handshake, in this harness, or
    /// in the kernel.
    stopped: Option<String>,
}

/// What a flow needs, computed once on the calling thread.
struct FlowPlan {
    bytes: u64,
    /// The flow's rotation of the shared keystream: same length for every flow,
    /// different content, so two flows' bytes can never be mistaken for one
    /// another's.
    pattern: Vec<u8>,
    traffic: Traffic,
    /// The measured engine's `SOCKS` listener. The flow opens this.
    engine: SocketAddr,
    /// The validated sink, in this process. The flow asks the engine to dial
    /// *this* — naming the engine's own port here instead would have the engine
    /// connect to itself, which is a loop that never terminates and a hang that
    /// looks like a slow benchmark.
    target: SocketAddr,
    /// This flow's index, for the error message.
    index: usize,
}

/// The sink: an accept loop plus whatever the flows reported on their way out.
struct SinkThread {
    accept: JoinHandle<()>,
    /// One entry per flow that stopped early, with the reason.
    reasons: Arc<std::sync::Mutex<Vec<String>>>,
    /// Set when the run is over, so a listener nobody ever connected to stops
    /// polling instead of making `join` wait forever.
    ///
    /// **This is what made every multi-flow cell hang, and it is the second half
    /// of the same defect as the sequential accept loop.** A listener's job is to
    /// serve one flow; a flow that never connected -- because the engine refused
    /// the connection, or because the driver gave up on it -- leaves that listener
    /// with nothing to accept and nothing to time out against. Joining it is then
    /// an unbounded wait, which is the one way this harness hangs rather than
    /// fails. The flow's own reason is already recorded and reported; the listener
    /// only needs to stop.
    done: Arc<AtomicBool>,
}

impl SinkThread {
    /// Tell the accept loops the run is over, then wait for them.
    ///
    /// The flag is set **before** the join and not by a timeout: a bounded wait
    /// would still leave a thread running past the point the process reads its
    /// results, and the join would then race the flag. The loops poll every 20 ms,
    /// so the cost of finishing is bounded and small.
    fn join(self) -> Result<(), Error> {
        self.done.store(true, Ordering::Relaxed);
        self.accept
            .join()
            .map_err(|_| Error::Workload("the sink thread panicked".into()))?;
        Ok(())
    }

    /// Why a flow stopped early, if one did.
    fn reasons(&self) -> Vec<String> {
        self.reasons.lock().map(|r| r.clone()).unwrap_or_default()
    }
}

/// Spawn one thread per flow.
fn spawn_flows(
    request: &Request,
    engine: SocketAddr,
    target: SocketAddr,
) -> Vec<JoinHandle<FlowResult>> {
    let template = bulk_pattern_template(request.payload_size);
    (0..request.connections)
        .map(|index| {
            let plan = FlowPlan {
                bytes: request.flow_bytes(),
                pattern: rotate(&template, index, request.connections),
                traffic: request.traffic,
                engine,
                // The target carries this flow's index in its port. That is what lets
                // the sink know which rotation of the keystream this flow carries
                // without inferring it from the order connections arrived in -- which
                // is a thing the two ends cannot agree on, and did not.
                target: SocketAddr::new(target.ip(), sink_port_of(target.port(), index)),
                index,
            };
            std::thread::spawn(move || run_flow(&plan))
        })
        .collect()
}

/// A distinct rotation of the keystream per flow.
///
/// Rotating rather than slicing keeps every flow the same length, so two flows
/// move the same number of bytes and neither can be distinguished by count — only
/// by content, which is the property rule 1 needs.
fn rotate(template: &[u8], index: usize, flows: usize) -> Vec<u8> {
    if flows <= 1 || template.is_empty() {
        return template.to_vec();
    }
    // A stride coprime with nothing in particular is enough: the offsets differ,
    // so the byte sequences differ unless the template is periodic, which the
    // seed guarantees it is not.
    let shift = (index * 977) % template.len();
    let mut out = Vec::with_capacity(template.len());
    out.extend_from_slice(&template[shift..]);
    out.extend_from_slice(&template[..shift]);
    out
}

/// The `SOCKS5` greeting: offer no authentication, expect the engine to pick it.
///
/// A wrong answer is named rather than treated as a short read, because "the engine
/// answered `0502`" and "the engine said nothing" are different faults and the
/// reader needs to know which happened.
fn socks_greet(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(&[5, 1, 0])
        .map_err(|e| format!("socks greeting write failed: {e}"))?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|e| format!("socks greeting read failed: {e}"))?;
    if greeting != [5, 0] {
        return Err(format!(
            "the engine answered the socks greeting with {greeting:02x?}, not 0500"
        ));
    }
    Ok(())
}

/// Arm a flow socket with the I/O timeout, so a dead peer fails the flow
/// instead of hanging the join in [`collect_flows`].
///
/// Factored out rather than inlined so a test can assert the timeouts are set
/// without moving any bytes: a test that waited out the timeout would take
/// thirty seconds to prove anything.
fn apply_flow_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(FLOW_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(FLOW_IO_TIMEOUT));
}

/// Run one flow: connect, SOCKS5 handshake, then move validated bytes.
fn run_flow(plan: &FlowPlan) -> FlowResult {
    let mut result = FlowResult {
        bytes_sent: 0,
        bytes_received: 0,
        window: None,
        setup: Setup::default(),
        stopped: None,
    };

    let t0 = Instant::now();
    let Ok(mut stream) = TcpStream::connect_timeout(&plan.engine, Duration::from_secs(10)) else {
        result.stopped = Some(format!(
            "could not connect to the engine at {}",
            plan.engine
        ));
        return result;
    };
    // Nagle would batch the driver's writes and measure the coalescing rather
    // than the engine.
    let _ = stream.set_nodelay(true);
    apply_flow_timeouts(&stream);
    result.setup.tcp_connect_us = t0.elapsed().as_micros();

    // SOCKS5, no authentication: greeting, then CONNECT to the sink. A failure
    // here is not reported as an engine fault: the byte count check in `measure`
    // catches a flow that never moved, with the whole run's context.
    let t1 = Instant::now();
    if let Err(reason) = socks_greet(&mut stream) {
        result.stopped = Some(reason);
        return result;
    }
    result.setup.socks_method_us = t1.elapsed().as_micros();

    let t2 = Instant::now();
    // ATYP with the sink's real address. It has to be the address the sink is
    // *bound* to, not `127.0.0.1`: every listener in this harness is on the
    // non-loopback address (see [`local_non_loopback_ipv4`]), so asking an engine
    // to dial the loopback would either be refused outright or take a loopback
    // path the other engine did not, which is the whole thing that function
    // exists to prevent.
    let mut connect = vec![5, 1, 0];
    // The reply is variable-length with the address family, so the length is
    // known before the request is built rather than assumed afterwards.
    let reply_len = match plan.target.ip() {
        std::net::IpAddr::V4(v4) => {
            connect.push(1);
            connect.extend_from_slice(&v4.octets());
            10
        }
        std::net::IpAddr::V6(v6) => {
            connect.push(4);
            connect.extend_from_slice(&v6.octets());
            22
        }
    };
    connect.extend_from_slice(&plan.target.port().to_be_bytes());
    if let Err(e) = stream.write_all(&connect) {
        result.stopped = Some(format!("socks connect write failed: {e}"));
        return result;
    }
    let mut reply = vec![0u8; reply_len];
    match stream.read_exact(&mut reply) {
        Err(e) => {
            result.stopped = Some(format!("socks connect read failed: {e}"));
            return result;
        }
        Ok(()) if reply[1] != 0 => {
            result.stopped = Some(format!(
                "the engine refused the socks connect with reply code {}; the sink \
                 is at {}",
                reply[1], plan.target
            ));
            return result;
        }
        Ok(()) => {}
    }
    result.setup.socks_connect_us = t2.elapsed().as_micros();
    result.setup.socks_setup_us = t1.elapsed().as_micros();
    // Taken here, at the first end-to-end readiness point, which is not the same as
    // the end of the flow. Reading it after the transfer would report the whole
    // run's duration in a column named "setup", and the two engines' setup times
    // would differ only by how fast they moved bytes.
    result.setup.total_us = t0.elapsed().as_micros();

    // The transfer window opens here, after the handshake: rule 2.
    let window_start = Instant::now();
    if plan.traffic.uplink() {
        // Written in chunks rather than as one buffer. Materialising the whole
        // payload would put the entire workload in this process's heap — half a
        // gigabyte at the default size, and it is the *harness's* memory, which
        // would then show up in nothing and eventually in an OOM kill. The engine
        // still receives the bytes in whatever sizes its own relay reads them, so
        // chunking here does not change what is being measured.
        if let Err(e) = plan.stream_up(&mut stream, &mut result.bytes_sent) {
            result.stopped = Some(format!(
                "upload write failed after {} of {} bytes: {e}",
                result.bytes_sent, plan.bytes
            ));
            return result;
        }
    }

    if plan.traffic.downlink() {
        // `Err` is a short read, not a corrupt one: recorded as a reason like any
        // other and the flow returns, so `measure` reports it beside the sink's
        // own account of the same flow instead of the process dying here.
        match plan.stream_down(&mut stream) {
            Ok(received) => result.bytes_received = received,
            Err(why) => {
                result.stopped = Some(why);
                return result;
            }
        }
    }

    if (plan.traffic.uplink() || plan.traffic.downlink()) && result.stopped.is_none() {
        result.window = Some((window_start, Instant::now()));
    }
    // Both directions drained: a half-closed flow would leave the engine's relay
    // thread running and its buffers resident, which the next flow's RSS would
    // then measure.
    let _ = stream.shutdown(Shutdown::Both);
    result
}

/// How much of the payload is built in memory at once for an upload.
///
/// 1 MiB: large enough that the syscall count is not what is being measured, small
/// enough that the harness' own footprint stays a rounding error next to the
/// engines'.
const UPLOAD_CHUNK: usize = 1024 * 1024;

/// How much of a download the driver reads per `read(2)`.
///
/// 64 KiB, and that is the pinned harness's own figure
/// (`upstream/xray-rust/crates/xray-bench/src/protocol_bench.rs:436`), kept for
/// the same reason the payload size is: the number of syscalls the driver picks
/// must not be what the engines are measured against.
const DOWNLOAD_CHUNK: usize = 64 * 1024;

/// Read `bytes` from `stream`, checking every one against the ring `pattern`.
///
/// One function for both callers that read a validated download: the flow that
/// drives an engine, and [`ceiling_flow`], which measures the same loop with no
/// engine in the path. They have to be the same loop or the ceiling is not a
/// ceiling -- see [`ceiling_flow`].
///
/// A mismatch is an `Err` rather than a number, and every caller here turns it
/// into a harness fault that ends the process: a driver and a sink that disagree
/// invalidate every number beside them, so there is nothing to report and
/// something to stop.
///
/// The comparison itself allocates nothing. This used to materialise the expected
/// bytes into a fresh `Vec` per chunk and compare against that, which on this
/// thread -- the busiest one in the harness, inside the measured window -- meant
/// one 64 KiB allocation and one 64 KiB copy for every 64 KiB of payload: three
/// passes over the data where the read from the socket and one comparison
/// suffice. The guarantee is unchanged and so is the coverage; only the copies
/// are gone.
fn read_validated(stream: &mut TcpStream, pattern: &[u8], bytes: u64) -> Result<u64, String> {
    let mut chunk = vec![0u8; pattern.len().clamp(1, DOWNLOAD_CHUNK)];
    let mut read_total = 0u64;
    while read_total < bytes {
        let Some(want) = usize::try_from((bytes - read_total).min(chunk.len() as u64)).ok() else {
            break;
        };
        if let Err(e) = stream.read_exact(&mut chunk[..want]) {
            return Err(format!(
                "download read failed after {read_total} of {bytes} bytes: {e}"
            ));
        }
        if !matches_pattern(pattern, read_total as usize, &chunk[..want]) {
            return Err(format!(
                "bytes at offset {read_total} are not the validated pattern"
            ));
        }
        read_total += want as u64;
    }
    Ok(read_total)
}

/// Whether `chunk` is `pattern`'s ring at `offset`, without building it.
///
/// The pattern repeats, so a chunk at `offset` is at most two slices of it: the
/// tail from `start`, then the head. Each is compared where it lies, which is the
/// whole of the difference between one pass over the payload and three.
fn matches_pattern(pattern: &[u8], offset: usize, chunk: &[u8]) -> bool {
    let period = pattern.len();
    if period == 0 {
        return chunk.is_empty();
    }
    let tail = &pattern[offset % period..];
    let take = chunk.len().min(tail.len());
    if chunk[..take] != tail[..take] {
        return false;
    }
    let rest = &chunk[take..];
    rest.len() <= period && rest == &pattern[..rest.len()]
}

impl FlowPlan {
    /// Read this flow's download, checking every byte, and count what arrived.
    ///
    /// [`read_validated`] does the work. Its two failures are **not** the same
    /// fault and are no longer treated as one:
    ///
    /// - a byte that is not the pattern is a *disagreement* between the driver
    ///   and the sink. There is no engine that can fix it and no byte count worth
    ///   reporting beside it, so this still ends the process.
    /// - a stream that **ends early** is not a disagreement. The bytes that did
    ///   arrive were all correct; the flow simply stopped short, which is the same
    ///   shape as a flow whose engine hung up, and the sink already records a
    ///   reason for that on its own side.
    ///
    /// The second used to `exit(3)` here, which threw away the only evidence that
    /// could name a cause: `measure` reads `sink_thread.reasons()` *after* the
    /// flows are collected, so a process that exits inside a flow never reaches
    /// the line where the sink's reason is printed. What reached the log was
    /// `download read failed after 536805376 of 1073741824 bytes` and nothing
    /// else -- a byte count that says the transfer stopped and not who stopped it.
    /// It now returns `Err` and lets `measure` report it beside the sink's own
    /// account, which is the half that can name the cause.
    fn stream_down(&self, stream: &mut TcpStream) -> Result<u64, String> {
        read_validated(&mut *stream, &self.pattern, self.bytes).map_err(|why| {
            if why.starts_with("bytes at offset") {
                // Still fatal, still here rather than propagated: nothing that
                // follows can be trusted once the two ends disagree, so the run
                // stops now instead of collecting numbers beside a bad stream.
                eprintln!(
                    "harness fault: flow {} saw bytes that are not the validated \
                     pattern: {why}",
                    self.index
                );
                std::process::exit(3);
            }
            // An early end. Recorded like any other reason a flow stopped, so the
            // sink's account of the same flow is reported next to this one.
            format!("flow {} download stopped early: {why}", self.index)
        })
    }

    /// Write `bytes` of this flow's pattern, counting what the socket took.
    ///
    /// One `write_all` per [`UPLOAD_CHUNK`], not per iteration and not for the
    /// whole payload: the measurement is the engine's copy path, so neither the
    /// number of syscalls this driver picks nor the harness' own heap should
    /// decide it.
    fn stream_up(&self, stream: &mut TcpStream, sent: &mut u64) -> std::io::Result<()> {
        let mut chunk: Vec<u8> = Vec::with_capacity(UPLOAD_CHUNK);
        while chunk.len() < UPLOAD_CHUNK {
            chunk.extend_from_slice(&self.pattern);
        }
        while *sent < self.bytes {
            let take = usize::try_from((self.bytes - *sent).min(chunk.len() as u64))
                .unwrap_or(chunk.len());
            stream.write_all(&chunk[..take])?;
            *sent += take as u64;
        }
        Ok(())
    }
}

/// Start the validated sink on `ip:port`.
///
/// `expect_bytes` of zero means download-only, so the sink is a pure source. The
/// sink lives in this process and is deliberately never sampled.
fn spawn_sink(ip: Ipv4Addr, ports: &[u16], request: &Request) -> Result<SinkThread, Error> {
    // The ports were already reserved by `measure`, on this address, disjoint from
    // the engine's. Binding them here is the second half of that reservation; the
    // range is re-derived from `ports` rather than from a first port plus a count
    // so the two cannot drift apart.
    let listeners = per_flow_sink_ports(ip, ports)?;
    for listener in &listeners {
        listener
            .set_nonblocking(true)
            .map_err(io("making the sink non-blocking"))?;
    }
    let pattern = Arc::new(bulk_pattern_template(request.payload_size));
    let flows = request.connections;
    // Per **flow**, not per workload. `total_bytes` is the whole cell
    // (`flow_bytes * connections`) and each flow reads exactly `flow_bytes`, so
    // handing every flow the cell's total asks each one for `connections` times
    // what it is willing to send. At one connection the two are equal and the bug
    // is invisible; at eight the sink offers 64x the bytes the workload reads,
    // and the cell dies as a short transfer with the harness -- not the engine --
    // at fault. `docs/methodology.md` calls the eight-flow rows part of the matrix
    // and they had never run on a runner that reported it.
    //
    // A full-duplex flow moves `flow_bytes` each way, so `sent + received` is
    // `2 * flow_bytes` for it; that is the reader's accounting and is separate.
    let upload_bytes = if request.traffic.uplink() {
        request.flow_bytes()
    } else {
        0
    };
    let download_bytes = if request.traffic.downlink() {
        request.flow_bytes()
    } else {
        0
    };
    let reasons = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let accept_reasons = Arc::clone(&reasons);
    let done = Arc::new(AtomicBool::new(false));
    // One thread **per listener**, all accepting concurrently. The obvious
    // shape — one thread looping over the listeners in order — deadlocks every
    // multi-flow cell: flow 1 is not accepted until flow 0's `serve_flow`
    // returns, and on a download `serve_flow` cannot return until the driver has
    // read every byte, which needs flow 1's socket to have been accepted and be
    // emitting. Both wait for the other. At `connections = 1` there is no second
    // listener, so the deadlock is invisible -- which is why six of the standard
    // tier's eleven cells hung or timed out on every runner while the
    // single-flow rows were green, and why this is a test of the harness itself
    // rather than of any engine.
    let sink_done = Arc::clone(&done);
    let accept = std::thread::spawn(move || {
        let done = sink_done;
        let mut handles = Vec::with_capacity(listeners.len());
        for (index, listener) in listeners.into_iter().enumerate() {
            // This flow's own rotation, named by the port it dialled.
            let flow = Arc::new(rotate(&pattern, index, flows));
            let sink_reasons = Arc::clone(&accept_reasons);
            let thread_done = Arc::clone(&done);
            handles.push(std::thread::spawn(move || {
                // Non-blocking, and that is load-bearing. A blocking accept would
                // wait forever for a flow that never connected, and an unbounded
                // join is the one way this harness can hang rather than fail.
                // Polling costs nothing here: the accept fires the instant the
                // engine connects.
                let listener_done = thread_done;
                let (stream, _) = loop {
                    // Asked before the accept as well as after it, so a run that
                    // has already finished does not wait out one more poll.
                    if listener_done.load(Ordering::Relaxed) {
                        return;
                    }
                    match listener.accept() {
                        Ok(pair) => break pair,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(_) => return,
                    }
                };
                // A socket accepted from a non-blocking listener *inherits*
                // `O_NONBLOCK` on Linux and the BSDs, macOS included. Left alone,
                // every `write_all` in `emit` fails with `EAGAIN` the moment the
                // kernel's send buffer fills, which reads exactly like an engine
                // that hung up.
                if stream.set_nonblocking(false).is_err() {
                    return;
                }
                if let Some(reason) = serve_flow(stream, &flow, index, upload_bytes, download_bytes)
                {
                    if let Ok(mut slot) = sink_reasons.lock() {
                        slot.push(reason);
                    }
                }
            }));
        }
        for handle in handles {
            let _ = handle.join();
        }
    });
    Ok(SinkThread {
        accept,
        reasons,
        done,
    })
}

/// Serve one flow's sink end: validate an upload, produce a download.
///
/// Returns why it stopped, if it stopped early. A silent return here would look
/// identical to an engine that hung up, and the reader would blame the engine —
/// which is how a harness fault becomes an engine regression in a report.
fn serve_flow(
    stream: TcpStream,
    pattern: &Arc<Vec<u8>>,
    index: usize,
    upload_bytes: u64,
    download_bytes: u64,
) -> Option<String> {
    // The download is produced by a thread so an upload-only flow's sink does not
    // sit idle waiting for a write that will never come, and vice versa.
    let downloader = if download_bytes > 0 {
        let Ok(read_half) = stream.try_clone() else {
            return Some("the sink could not clone its socket".to_owned());
        };
        let pattern = Arc::clone(pattern);
        Some(std::thread::spawn(move || {
            emit(read_half, &pattern, index, download_bytes)
        }))
    } else {
        None
    };

    if upload_bytes > 0 {
        return validate(stream, pattern, index, upload_bytes);
    }
    match downloader {
        // A panicking sink thread has already taken the process down in every
        // other path; here it can only mean the flow ended for an unknown reason,
        // which is itself reported.
        Some(handle) => match handle.join() {
            Ok(reason) => reason,
            Err(_) => Some("the sink's flow thread panicked".to_owned()),
        },
        None => None,
    }
}

/// Check every uploaded byte against this flow's pattern.
///
/// Returns why it stopped early, if it did.
fn validate(
    mut stream: TcpStream,
    pattern: &Arc<Vec<u8>>,
    index: usize,
    expect: u64,
) -> Option<String> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut seen = 0u64;
    let mut offset = 0usize;
    while seen < expect {
        let n = match stream.read(&mut buffer) {
            Ok(0) => {
                return Some(format!(
                    "the engine closed the upload after {seen} of {expect} bytes"
                ));
            }
            Ok(n) => n,
            Err(e) => return Some(format!("the upload read failed after {seen} bytes: {e}")),
        };
        for (i, byte) in buffer[..n].iter().enumerate() {
            if *byte != pattern[(offset + i) % pattern.len()] {
                eprintln!(
                    "harness fault: flow {index} received a byte that is not the \
                     validated pattern, at byte {}",
                    seen + i as u64
                );
                std::process::exit(3);
            }
        }
        offset = (offset + n) % pattern.len();
        seen += n as u64;
    }
    None
}

/// Emit exactly `expect` bytes of this flow's pattern.
///
/// Returns why it stopped early, if it did. A silent `return` on a write error
/// here is indistinguishable from an engine that hung up, so the reader of a
/// short transfer would blame the engine for a fault in the harness — which is
/// how a harness bug becomes an engine regression in somebody's report.
///
/// Every byte handed to the socket is validated by construction: it comes from
/// the shared keystream. The check that matters is the reader's.
fn emit(
    mut stream: TcpStream,
    pattern: &Arc<Vec<u8>>,
    index: usize,
    expect: u64,
) -> Option<String> {
    let _ = index;
    let mut buffer = Vec::with_capacity(64 * 1024);
    while buffer.len() < 64 * 1024 {
        buffer.extend_from_slice(pattern);
    }
    let mut sent = 0u64;
    while sent < expect {
        let take =
            usize::try_from((expect - sent).min(buffer.len() as u64)).unwrap_or(buffer.len());
        if let Err(e) = stream.write_all(&buffer[..take]) {
            return Some(format!(
                "the sink could not write after {sent} of {expect} bytes: {e}"
            ));
        }
        sent += take as u64;
    }
    let _ = stream.flush();
    None
}

/// Open and close one flow, for a warmup connection.
///
/// Capped and its errors ignored: a warmup exists to page the engine in and to
/// let TCP window growth settle, so failing it should not decide the run. What
/// *is* reported is the case where the engine cannot complete a single flow at
/// all, because then every subsequent flow will fail and the run would be
/// reported as a short transfer with no explanation.
fn warmup(socks: SocketAddr, pattern: &[u8]) -> Result<(), Error> {
    let mut stream = TcpStream::connect_timeout(&socks, Duration::from_secs(10))
        .map_err(io("warmup connect"))?;
    let _ = stream.set_nodelay(true);
    stream
        .write_all(&[5, 1, 0])
        .map_err(io("warmup greeting"))?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(io("warmup greeting reply"))?;
    let mut connect = vec![5, 1, 0, 1, 127, 0, 0, 1];
    connect.extend_from_slice(&1u16.to_be_bytes());
    stream
        .write_all(&connect)
        .map_err(io("warmup connect request"))?;
    let mut reply = [0u8; 10];
    stream
        .read_exact(&mut reply)
        .map_err(io("warmup connect reply"))?;
    let chunk = &pattern[..pattern.len().min(1024)];
    stream.write_all(chunk).map_err(io("warmup write"))?;
    let mut echo = vec![0u8; chunk.len()];
    stream.read_exact(&mut echo).map_err(io("warmup echo"))?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

/// Add the harness's SOCKS inbound to a request's outbound-only config.
///
/// The inbound carries the tag `harness-socks`, so matrix configs can route
/// it to a protocol outbound while the protocol's own server side falls
/// through to `freedom`.
///
/// The request's own outbounds are kept, not replaced: the engine's whole job is
/// to dial through whatever outbound the request names, and dropping it would
/// measure a different configuration than the one a reader of the request expects.
pub fn inject_inbound(
    config: &str,
    listen: Ipv4Addr,
    port: u16,
    dialect: Dialect,
) -> Result<String, Error> {
    let mut root = json::parse(config)
        .map_err(|e| Error::Invalid(format!("config is not valid json: {e}")))?;
    let inbound = dialect.socks_inbound(listen, port);

    let mut list = match root.get("inbounds") {
        Some(Json::Arr(existing)) => existing.clone(),
        None => Vec::new(),
        _ => {
            return Err(Error::Invalid(
                "`inbounds` must be an array when present".into(),
            ))
        }
    };
    list.push(inbound);
    root.insert("inbounds", Json::Arr(list));
    root.to_string()
        .map_err(|e| Error::Invalid(format!("config cannot be re-serialised: {e}")))
}

/// SHA-256 of a file, so a number is attributable to a binary and not to a path.
///
/// Computed here rather than by shelling out, so the harness depends on neither
/// `sha256sum` (absent on macOS) nor `shasum` (absent on slim Linux images): a
/// missing tool must not turn into an unattributable measurement.
pub fn file_sha256(path: &Path) -> String {
    let mut state = Sha256::new();
    if let Ok(bytes) = std::fs::read(path) {
        state.update(&bytes);
    }
    state.hex()
}

/// Minimal SHA-256, so the harness needs no hashing dependency.
struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

/// The round constants from FIPS 180-4.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add((data.len() as u64) * 8);
        if self.buffered > 0 {
            let take = (64 - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        self.state = compress_block(&self.state, block);
    }

    /// Finalise. The padding is written through a path that does not disturb the
    /// message length, which is the one thing that is easy to get wrong here.
    fn hex(self) -> String {
        let bits = self.length;
        let mut padded = Vec::with_capacity(self.buffered + 72);
        padded.extend_from_slice(&self.buffer[..self.buffered]);
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&bits.to_be_bytes());

        let mut state = self.state;
        for block in padded.as_chunks::<64>().0 {
            state = compress_block(&state, block);
        }
        let mut out = String::with_capacity(64);
        for word in state {
            for byte in word.to_be_bytes() {
                out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
                out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap_or('0'));
            }
        }
        out
    }
}

/// One block of compression, as a function of state so finalisation can run it
/// without mutating a `Sha256` whose length field must not move.
/// One block of compression, FIPS 180-4 §6.2.2.
///
/// The working variables keep the specification's names: this is the one function
/// where `a` through `h` are the names the standard uses, and renaming them to
/// satisfy a lint would make the code harder to check against the standard
/// rather than easier.
#[allow(clippy::many_single_char_names)]
fn compress_block(state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let mut w = [0u32; 64];
    for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*chunk);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ]
}

/// The port flow `index` of a run whose first flow uses `first`.
///
/// `saturating_add`, so an index past the end of the range lands on the highest port
/// rather than wrapping onto an unrelated listener -- and [`per_flow_sink_ports`]
/// refuses to build that range in the first place.
fn sink_port_of(first: u16, index: usize) -> u16 {
    first.saturating_add(u16::try_from(index).unwrap_or(u16::MAX))
}

/// One listener per flow, on consecutive ports from `first`.
///
/// # Why a flow's identity is its port and not its place in the accept queue
///
/// The two ends of a flow have to agree on which rotation of the keystream it carries.
/// At `connections = 1` there is only one rotation, so nothing can disagree and nothing
/// is checked. At sixteen there are sixteen, and this is where it broke: the sink
/// numbered flows in **accept** order and the driver numbered them in **spawn** order,
/// so a flow could be validated against a different flow's bytes. What that looks like,
/// verbatim from `linux x86_64` at `connections=16`:
///
/// ```text
/// harness fault: flow 8 saw bytes that are not the validated pattern: bytes at
/// offset 0 are not the validated pattern
/// ```
///
/// which is a fault in the **harness**, not in the engine: the engine faithfully
/// relayed flow 8's bytes to a driver that was checking them against flow 9's
/// keystream. No engine change could have fixed it, and reading it as an engine fault
/// would have been the wrong conclusion from the right measurement.
///
/// Consecutive ports make the identity something both ends already know. The driver
/// asks for `first + index`; the sink owns `first + index`. Nothing then depends on
/// which connection arrives first, on thread scheduling, or on how many CPUs the
/// runner has -- which is the property that was missing and the reason a concurrency
/// number could not be trusted at all before this.
fn per_flow_sink_ports(ip: Ipv4Addr, ports: &[u16]) -> Result<Vec<TcpListener>, Error> {
    let mut listeners = Vec::with_capacity(ports.len());
    for &port in ports {
        listeners.push(TcpListener::bind((ip, port)).map_err(io("binding a per-flow sink port"))?);
    }
    Ok(listeners)
}

/// Run the same validated loop with no engine in the path: rule 3's ceiling.
///
/// One socket hop, no engine: the rate at which this process and the kernel move
/// the validated bytes over the shortest path the harness can give them.
///
/// Every engine row is a *two*-hop relay, so this is a reference point and not a
/// bound. An engine at or above it is not exceeding anything -- it is doing two
/// hops at one-hop speed, which is a good result -- and the report says so in
/// those words. See [`crate::compare_process::Comparison::ceiling_fraction`].
///
/// Measuring it is cheap and omitting it is how a chart comes to imply more
/// precision than the harness has.
///
/// Called once per repeat, interleaved with the engines rather than once before
/// them. One sample taken at the start of a thirty-second sweep is a sample of
/// the runner *at that moment*, and the runner moves: eight `linux x86_64` runs
/// of one tree published ceilings from 2220 to 5724 MiB/s, which is a 2.7x spread
/// in the machine alone, and the ceiling column that number is used for is then
/// not a bound on anything measured after it. Interleaved, the ceiling is a
/// covariate: the same repeat's engines and the same repeat's ceiling were
/// measured seconds apart, and [`crate::compare_process::Comparison::runner_spread`]
/// can read how far the machine moved between them rather than asserting that it did
/// not.
pub fn harness_ceiling(connections: usize, payload_size: usize, bytes: u64) -> Result<f64, Error> {
    let ip = local_non_loopback_ipv4()?;
    // The same reservation `measure` makes, for the same reason: the range is
    // bound before it is used, and it is drawn on the address it is bound to.
    let ports = allocate_port_range(connections)?;
    let port = ports[0];
    let listeners = per_flow_sink_ports(ip, &ports)?;
    let pattern = Arc::new(bulk_pattern_template(payload_size));

    // The sink is a pure source here: with no engine in the path there is nothing
    // to validate against a driver, so it emits and the driver checks.
    let sink = std::thread::spawn({
        let pattern = Arc::clone(&pattern);
        move || {
            for (index, listener) in listeners.into_iter().enumerate() {
                let Ok((stream, _)) = listener.accept() else {
                    return;
                };
                let flow = Arc::new(rotate(&pattern, index, connections));
                std::thread::spawn(move || emit(stream, &flow, index, bytes));
            }
        }
    });

    let mut flows = Vec::with_capacity(connections);
    for index in 0..connections {
        let addr = SocketAddr::from((ip, sink_port_of(port, index)));
        let template = Arc::clone(&pattern);
        flows.push(std::thread::spawn(move || {
            ceiling_flow(addr, &template, index, connections, bytes)
        }));
    }

    let mut best = 0.0f64;
    for flow in flows {
        let Ok(rate) = flow.join() else { continue };
        best = best.max(rate);
    }
    let _ = sink.join();
    if best <= 0.0 {
        return Err(Error::Workload(
            "the harness ceiling moved no bytes; a row compared against it would \
             be meaningless, so it is reported as unmeasured"
                .into(),
        ));
    }
    Ok(best)
}

/// One flow of the ceiling run: open a connection straight to the sink and read.
///
/// Returns MiB/s over the read window, or `0.0` for a flow that did not complete —
/// a zero is skipped by the caller rather than averaged in, because a flow that
/// never started is not a slow flow.
///
/// No `SOCKS` handshake here, and that is the point: the ceiling is the rate at
/// which this process and the kernel can move bytes with nothing else in the path.
/// Any handshake would put a parser back on the path and raise the ceiling above
/// what the engines are being compared against.
fn ceiling_flow(
    addr: SocketAddr,
    template: &Arc<Vec<u8>>,
    index: usize,
    flows: usize,
    bytes: u64,
) -> f64 {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(10)) else {
        return 0.0;
    };
    let _ = stream.set_nodelay(true);
    // This flow's own rotation, as an engine run's flow gets: the ceiling then
    // moves the same bytes the engines are asked to move, not a privileged set.
    let pattern = rotate(template, index, flows);
    let started = Instant::now();
    // The same validated loop the engines are measured through, not a cheaper one.
    //
    // This counted bytes and checked none of them, and a ceiling that skips work
    // the subject does is not a ceiling. That is how `xray-core` came to read
    // 1.4x *above* the published ceiling of the same run: it was above it because
    // the ceiling was measuring something easier, and "vs harness ceiling"
    // printed 141% as though it meant the ceiling had been exceeded. A run that
    // cannot validate its own bytes moved nothing that counts, so a failure here
    // reads `0.0` and the caller reports it unmeasured rather than publishing a
    // rate it cannot stand behind.
    let read_total = read_validated(&mut stream, &pattern, bytes).unwrap_or(0);
    let elapsed = started.elapsed();
    let _ = stream.shutdown(Shutdown::Both);
    if elapsed.is_zero() || read_total == 0 {
        return 0.0;
    }
    read_total as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_sockets_carry_the_io_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let addr = listener.local_addr().expect("addr");
        let stream = TcpStream::connect(addr).expect("connects");
        apply_flow_timeouts(&stream);
        assert_eq!(
            stream.read_timeout().expect("readable"),
            Some(FLOW_IO_TIMEOUT)
        );
        assert_eq!(
            stream.write_timeout().expect("readable"),
            Some(FLOW_IO_TIMEOUT)
        );
    }

    /// A complete, valid request with `overrides` applied afterwards.
    fn request_with(overrides: &[(&str, &str)]) -> String {
        let mut fields = base_fields();
        for (key, value) in overrides {
            fields.retain(|(k, _)| k != key);
            fields.push(((*key).to_owned(), (*value).to_owned()));
        }
        render(fields)
    }

    /// The same document with a `client_env` member.
    fn request_with_env(env: &str) -> String {
        let mut fields = base_fields();
        fields.push(("client_env".into(), env.to_owned()));
        render(fields)
    }

    /// A complete, valid request's fields. `path` is present because the
    /// validator requires it, even though only `"socks"` is implemented.
    fn base_fields() -> Vec<(String, String)> {
        vec![
            ("binary".into(), quote(&engine_path())),
            (
                "config".into(),
                quote(r#"{"outbounds":[{"protocol":"freedom"}]}"#),
            ),
            ("path".into(), quote("socks")),
            ("traffic".into(), quote("upload")),
            ("connections".into(), "1".into()),
            ("iterations".into(), "10".into()),
            ("payload_size".into(), "1024".into()),
            ("output".into(), quote(&out_dir())),
        ]
    }

    /// Fields to a document, sorted so the text is stable and an override lands in
    /// one place rather than two.
    fn render(mut fields: Vec<(String, String)>) -> String {
        fields.sort();
        let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
        format!("{{{}}}", body.join(","))
    }

    fn quote(s: &str) -> String {
        Json::Str(s.to_owned())
            .to_string()
            .expect("a string always has a json spelling")
    }

    /// Any readable file stands in for an engine: these tests exercise the
    /// request schema, not the spawn.
    fn engine_path() -> String {
        std::env::current_exe().map_or_else(|_| "/dev/null".to_owned(), |p| p.display().to_string())
    }

    /// A path under the target directory, which does not exist.
    fn out_dir() -> String {
        format!(
            "{}/ferrox-bench-request-test-{}-{}",
            env!("CARGO_MANIFEST_DIR"),
            std::process::id(),
            line!()
        )
    }

    #[test]
    fn accepts_a_minimal_request() {
        let r = Request::parse(request_with(&[]).as_bytes()).expect("valid request");
        assert_eq!(r.connections, 1);
        assert_eq!(r.iterations, 10);
        assert_eq!(r.payload_size, 1024);
        assert_eq!(r.traffic, Traffic::Upload);
        assert_eq!(r.total_bytes(), 10 * 1024);
        assert!(r.client_env.is_empty());
    }

    /// An unknown field is an error, not a shrug: a request one implementation
    /// reads and the other ignores is two different measurements of one name.
    #[test]
    fn rejects_an_unknown_field() {
        let doc = request_with(&[("iterations", "10"), ("somethingNew", "true")]);
        assert!(Request::parse(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_every_out_of_bounds_count() {
        for (field, value) in [
            ("connections", "0"),
            ("connections", "17"),
            ("iterations", "0"),
            ("iterations", "262145"),
            ("payload_size", "0"),
            ("payload_size", "65537"),
        ] {
            let doc = request_with(&[(field, value)]);
            assert!(
                Request::parse(doc.as_bytes()).is_err(),
                "{field}={value} must be rejected"
            );
        }
    }

    /// The ceiling is a byte count, not an iteration count: `payload_size` and
    /// `iterations` are separately bounded, so their product has to be bounded
    /// too. Without this a request can ask for a run that cannot finish inside
    /// `RUN_TIMEOUT`, and a truncated transfer is a fault rather than a rate.
    /// The allocation-free comparison must accept exactly the rotations of the
    /// pattern and reject everything else, at every phase and every wrap point.
    /// It replaced a `Vec`-building compare that agreed with it, so the
    /// interesting cases are the ones where a ring wraps mid-chunk.
    #[test]
    fn the_pattern_check_sees_every_phase_and_both_wrap_points() {
        let template = bulk_pattern_template(4096);
        let doubled: Vec<u8> = template.iter().chain(template.iter()).copied().collect();
        let period = template.len();
        // Phase zero, whole period.
        assert!(matches_pattern(&template, 0, &template[..]));
        // Every phase, at every chunk length that divides the period evenly and
        // at one that does not: the chunks a flow actually reads are a fixed size
        // that walks the ring by its own length, so the phase is arbitrary.
        for phase in (0..period).step_by(29) {
            for len in [1, 2, 63, 64 * 1024, period / 2, period - 1, period] {
                if phase + len > doubled.len() {
                    continue;
                }
                let want = &doubled[phase..phase + len];
                assert!(
                    matches_pattern(&template, phase, want),
                    "phase {phase}, {len} bytes"
                );
            }
        }
        // A chunk that straddles the end of the ring: taken from `doubled`, so it
        // is genuinely two pieces of the period.
        for over in [1, 2, 17, period / 2, period - 1] {
            let start = period - over;
            let len = (over * 2).min(doubled.len() - start);
            assert!(
                matches_pattern(&template, start, &doubled[start..start + len]),
                "chunk of {over} past the end of the ring"
            );
        }
        // One flipped bit anywhere is a failure, at the first and the last byte.
        for at in [0, period / 2, period - 1] {
            let mut bad = template.clone();
            bad[at] ^= 1;
            assert!(!matches_pattern(&template, 0, &bad), "flipped byte {at}");
        }
        // An empty chunk and an empty pattern are both vacuously true, and a
        // non-empty chunk against an empty pattern is not.
        assert!(matches_pattern(&template, 7, &[]));
        assert!(matches_pattern(&[], 0, &[]));
        assert!(!matches_pattern(&[], 0, &template[..1]));
        // Longer than one period: the ring is conceptually infinite, so a genuine
        // multi-period rotation still matches and a corrupted one still does not.
        // `read_validated` never asks for more than one period, so this is the
        // boundary rather than a case the gate can reach.
        assert!(matches_pattern(&template, 0, &doubled[..]));
        let mut stretched = doubled.clone();
        stretched[period + 7] ^= 1;
        assert!(!matches_pattern(&template, 0, &stretched[..]));
    }

    #[test]
    fn rejects_a_flow_above_the_byte_ceiling() {
        let doc = request_with(&[("iterations", "262144"), ("payload_size", "65536")]);
        assert!(
            Request::parse(doc.as_bytes()).is_ok(),
            "16 GiB is the ceiling, and the ceiling itself is allowed"
        );
        let doc = request_with(&[("iterations", "262145"), ("payload_size", "65536")]);
        assert!(Request::parse(doc.as_bytes()).is_err(), "above it is not");
        let doc = request_with(&[("iterations", "131072"), ("payload_size", "65536")]);
        assert!(
            Request::parse(doc.as_bytes()).is_ok(),
            "8 GiB is the window this harness needs and must accept"
        );
    }

    /// A download that stops short is reported as a reason, not as a process exit.
    ///
    /// This is the `macos-15` failure verbatim, from the standard tier at
    /// `connections = 8`:
    ///
    /// ```text
    /// harness fault: flow 2 saw bytes that are not the validated pattern: download
    /// read failed after 536805376 of 1073741824 bytes: failed to fill whole buffer
    /// ```
    ///
    /// and it is worth reading twice. Every byte that arrived *was* correct -- the
    /// check passed for all 8191 chunks read -- so this is not a disagreement
    /// between the driver and the sink and the "not the validated pattern"
    /// heading was simply wrong. It is a short transfer.
    ///
    /// Which is the whole problem: `measure` reads `sink_thread.reasons()` only
    /// *after* the flows are collected, so a flow that calls `process::exit` never
    /// reaches the code that prints the sink's own account of the same flow. The
    /// sink records a reason when a write fails or a stream ends -- the half of the
    /// evidence that can name a cause -- and it was being discarded. What reached
    /// the log was a byte count that says the transfer stopped, not who stopped it.
    ///
    /// Asserted as a pair of halves on one socket, because that is what the bug
    /// was: a real short read, and a message that does not blame the sink for
    /// something it can only be told about after the fact.
    #[test]
    fn a_download_that_stops_short_is_a_reason_and_not_a_process_exit() {
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return;
        };
        let addr = listener.local_addr().expect("has an address");
        let pattern = b"0123456789abcdef".to_vec();

        // A sink that sends three periods and then closes: every byte correct,
        // the stream simply ends before `bytes`.
        let sink = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("one flow");
            let _ = stream.write_all(&b"0123456789abcdef0123456789abcdef0123456789abcdef"[..48]);
            let _ = stream.shutdown(Shutdown::Both);
        });

        let mut client = TcpStream::connect(addr).expect("connects");
        let err = read_validated(&mut client, &pattern, 64)
            .expect_err("a stream that ends early must be an Err");
        assert!(
            err.starts_with("download read failed"),
            "a short read says the transfer stopped: {err}"
        );
        assert!(
            !err.contains("not the validated pattern"),
            "and must not be reported as a corrupt stream: {err}"
        );
        drop(client);
        let _ = sink.join();

        // The other half: bytes that are *wrong* still stop the process, because
        // nothing measured beside a stream the two ends disagree about is
        // trustworthy. That branch is `process::exit`, so it is asserted by
        // message rather than by running it -- `stream_down` is the only caller
        // that exits, and the split between the two is its contract.
        assert!(
            matches_pattern(&pattern, 0, &pattern),
            "the pattern matches itself at offset 0, or this test proves nothing"
        );
        assert!(
            !matches_pattern(&pattern, 0, &[b'z'; 16]),
            "a corrupt chunk does not, so the fatal branch has something to catch"
        );
    }

    /// The gate-5 default has to stay inside the pinned schema's own bound, or
    /// the claim that one request file measures either binary stops holding.
    ///
    /// A compile-time fact, so it is checked as one: the pinned bounds are read at
    /// `protocol_bench.rs:65`-`:69` and a default that drifted past them would
    /// only be caught by a pinned harness refusing a request this one wrote.
    #[test]
    fn the_default_request_is_one_the_pinned_harness_also_accepts() {
        const {
            assert!(crate::DEFAULT_ITERATIONS <= 16_384);
            assert!(crate::DEFAULT_CONNECTIONS <= 16);
            assert!(crate::DEFAULT_PAYLOAD_SIZE <= 65_536);
        }
    }

    #[test]
    fn rejects_a_non_whole_count() {
        for field in ["connections", "iterations", "payload_size"] {
            let doc = request_with(&[(field, "2.5")]);
            assert!(
                Request::parse(doc.as_bytes()).is_err(),
                "{field}=2.5 must be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_missing_required_field() {
        for field in [
            "binary",
            "config",
            "traffic",
            "connections",
            "iterations",
            "payload_size",
            "output",
        ] {
            let doc = request_with(&[]).replace(&format!("\"{field}\":"), "\"zz\":");
            assert!(
                Request::parse(doc.as_bytes()).is_err(),
                "{field} must be required"
            );
        }
    }

    #[test]
    fn rejects_an_unknown_traffic() {
        let doc = request_with(&[("traffic", "\"sideways\"")]);
        assert!(Request::parse(doc.as_bytes()).is_err());
    }

    #[test]
    fn reads_client_env_and_rejects_non_strings() {
        let r =
            Request::parse(request_with_env(r#"{"A":"1"}"#).as_bytes()).expect("valid with env");
        assert_eq!(r.client_env.get("A").map(String::as_str), Some("1"));

        // A non-string value is refused rather than stringified: `A: 1` and
        // `A: "1"` would set different environment values, and only one of them
        // is what the document says.
        assert!(Request::parse(request_with_env(r#"{"A":1}"#).as_bytes()).is_err());
        assert!(Request::parse(request_with_env("[1,2]").as_bytes()).is_err());
    }

    /// The pinned harness's payload rule, and this project's own: deterministic,
    /// and not a constant. A constant payload cannot detect a core that moves the
    /// right byte count in the wrong order.
    #[test]
    fn the_template_is_deterministic_and_non_constant() {
        let a = bulk_pattern_template(4096);
        assert_eq!(a, bulk_pattern_template(4096));
        assert_eq!(a.len(), 4096);
        assert!(a.iter().any(|&byte| byte != a[0]));
    }

    #[test]
    fn the_template_matches_the_seed_the_pinned_harness_uses() {
        // Recomputed from the constant, so a change to `BULK_PATTERN_SEED` cannot
        // silently stop this harness and the pinned one validating the same bytes.
        let mut state = BULK_PATTERN_SEED;
        let mut first = [0u8; 4];
        for slot in &mut first {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *slot = (state >> 32) as u8;
        }
        assert_eq!(&bulk_pattern_template(4)[..], &first);
    }

    /// Concurrent flows must not share bytes, or a core that interleaves two
    /// sessions onto one carrier would validate.
    /// A flow's identity has to be something both ends already know.
    ///
    /// The bug this is for: the sink numbered flows in **accept** order and the driver
    /// numbered them in **spawn** order, so at sixteen connections a flow could be
    /// validated against another flow's bytes -- `harness fault: flow 8 saw bytes that
    /// are not the validated pattern` -- with the engine innocent. Nothing at
    /// `connections = 1` can see it, which is why it survived.
    ///
    /// The property asserted is the one the fix rests on: flow `index` dials
    /// `first + index`, and the sink's listener `index` is that same port. If either
    /// side ever went back to counting arrivals, this fails.
    #[test]
    fn a_flows_identity_is_its_port_and_not_its_place_in_the_accept_queue() {
        assert_eq!(sink_port_of(40_000, 0), 40_000);
        assert_eq!(sink_port_of(40_000, 15), 40_015);
        // Distinct for every flow the schema allows, which is the property the old
        // accept-order numbering did not have.
        let ports: std::collections::BTreeSet<u16> =
            (0..16).map(|i| sink_port_of(40_000, i)).collect();
        assert_eq!(ports.len(), 16, "two flows must never share a sink port");
        // And it saturates rather than wrapping, because wrapping lands a flow on an
        // unrelated listener -- which is the same class of fault one level up.
        assert_eq!(sink_port_of(u16::MAX, 1), u16::MAX);
        assert_eq!(sink_port_of(u16::MAX, u16::MAX as usize + 5), u16::MAX);
    }

    /// One listener per flow, on ports reserved as a whole range, and disjoint
    /// from the engine's.
    ///
    /// The disjointness is the assertion that matters, and it is the one whose
    /// absence cost every multi-flow cell: the sink takes `connections` ports and
    /// the engine takes one more, all on the same address, and probing each in
    /// turn lets the engine be handed a number the sink's range is about to
    /// include. At two flows that is a coin flip, and the loser is always reported
    /// as an engine fault.
    #[test]
    fn the_sink_binds_one_listener_per_flow_clear_of_the_engine() {
        let Ok(ip) = local_non_loopback_ipv4() else {
            // A loopback-only host cannot run the benchmark at all; the port
            // arithmetic is still worth checking where there is an address.
            return;
        };
        let ports = allocate_port_range(4).expect("four free ports");
        let engine = allocate_port_excluding(ip, &ports).expect("a port clear of them");
        assert!(
            !ports.contains(&engine),
            "the engine's port {engine} is inside the sink's range {ports:?}"
        );

        let listeners = per_flow_sink_ports(ip, &ports).expect("the reserved range binds");
        assert_eq!(listeners.len(), 4, "one listener per flow");
        let bound: std::collections::BTreeSet<u16> = listeners
            .iter()
            .map(|l| l.local_addr().expect("has an address").port())
            .collect();
        assert_eq!(bound.len(), 4, "each flow's listener is its own port");
        assert_eq!(
            bound,
            ports.iter().copied().collect(),
            "and they are the ports that were reserved"
        );

        // The range is held for the whole allocation, so a second draw cannot
        // land inside the first -- the property `allocate_port_range` exists for.
        let again = allocate_port_range(4).expect("four more");
        assert!(
            again.iter().all(|p| !ports.contains(p)),
            "a second range overlaps the first: {again:?} vs {ports:?}"
        );
    }

    #[test]
    fn flow_regions_are_distinct_and_equal_length() {
        let template = bulk_pattern_template(1024);
        let a = rotate(&template, 0, 4);
        let b = rotate(&template, 1, 4);
        assert_ne!(a, b);
        assert_eq!(a.len(), template.len());
        assert_eq!(b.len(), template.len());
        // One flow is not rotated: there is nothing to be confused with.
        assert_eq!(rotate(&template, 0, 1), template);
    }

    #[test]
    fn the_socks_inbound_is_injected_and_the_outbounds_survive() {
        let base = Dialect::Xray.base_config().to_string().expect("serialises");
        let out = inject_inbound(&base, Ipv4Addr::new(192, 0, 2, 7), 1080, Dialect::Xray)
            .expect("injectable");
        let root = json::parse(&out).expect("valid json");
        let inbounds = root
            .get("inbounds")
            .and_then(Json::as_arr)
            .expect("inbounds");
        assert_eq!(inbounds.len(), 1);
        assert_eq!(
            inbounds[0].get("tag").and_then(Json::as_str),
            Some("harness-socks"),
            "routing rules address the injected inbound by tag"
        );
        assert_eq!(
            inbounds[0].get("listen").and_then(Json::as_str),
            Some("192.0.2.7")
        );
        assert_eq!(inbounds[0].get("port").and_then(Json::as_num), Some(1080.0));
        assert_eq!(
            inbounds[0]
                .get("settings")
                .and_then(|s| s.get("udp"))
                .and_then(Json::as_bool),
            Some(false)
        );
        assert_eq!(
            root.get("outbounds")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(1),
            "the request's own outbounds must survive"
        );
    }

    /// The defect this dialect exists for: one document, two config languages.
    ///
    /// `sing-box` was handed `{"protocol":"freedom"}` and `{"protocol":"socks",
    /// "port":N}` on every repeat of every run, and answered `outbounds[0]:
    /// unknown outbound type: ` — an empty type name, because `protocol` is not
    /// the key it reads. It also rejects `port` outright since 1.13.0, so a
    /// document with the right keys and the old port field would fail next. Both
    /// differences are pinned here against the field names read at the pin
    /// (`option/inbound.go:79`-`:81` and `constant/proxy.go:7`).
    #[test]
    fn each_dialect_writes_the_fields_that_engine_actually_reads() {
        for dialect in [Dialect::Xray, Dialect::SingBox] {
            let base = dialect.base_config().to_string().expect("serialises");
            let out = inject_inbound(&base, Ipv4Addr::new(192, 0, 2, 7), 1080, dialect)
                .expect("injectable");
            let root = json::parse(&out).expect("valid json");
            let outbound = &root
                .get("outbounds")
                .and_then(Json::as_arr)
                .expect("outbounds")[0];
            let inbound = &root
                .get("inbounds")
                .and_then(Json::as_arr)
                .expect("inbounds")[0];

            let (type_key, type_value) = match dialect {
                Dialect::Xray => ("protocol", "freedom"),
                Dialect::SingBox => ("type", "direct"),
            };
            assert_eq!(
                outbound.get(type_key).and_then(Json::as_str),
                Some(type_value),
                "{dialect:?} outbound names itself with `{type_key}`"
            );
            let (in_key, in_value) = match dialect {
                Dialect::Xray => ("protocol", "socks"),
                Dialect::SingBox => ("type", "socks"),
            };
            assert_eq!(inbound.get(in_key).and_then(Json::as_str), Some(in_value));

            let (port_key, port_value) = match dialect {
                Dialect::Xray => ("port", 1080.0),
                Dialect::SingBox => ("listen_port", 1080.0),
            };
            assert_eq!(
                inbound.get(port_key).and_then(Json::as_num),
                Some(port_value),
                "{dialect:?} listens on `{port_key}`"
            );

            // The two spellings must not leak into each other: a `port` in
            // sing-box's document is a startup failure there, not an ignored key.
            let foreign = match dialect {
                Dialect::Xray => ("type", "socks"),
                Dialect::SingBox => ("protocol", "socks"),
            };
            assert!(
                inbound.get(foreign.0).is_none(),
                "{dialect:?} must not carry a `{}` key",
                foreign.0
            );
            let foreign_port = match dialect {
                Dialect::Xray => "listen_port",
                Dialect::SingBox => "port",
            };
            assert!(
                inbound.get(foreign_port).is_none(),
                "{dialect:?} must not carry a `{foreign_port}` key"
            );
        }
    }

    #[test]
    fn a_dialect_parses_and_rejects_by_name() {
        let ok = |raw: &str| Dialect::parse(raw).ok();
        assert_eq!(ok("xray"), Some(Dialect::Xray));
        assert_eq!(ok("protocol"), Some(Dialect::Xray));
        assert_eq!(ok("sing-box"), Some(Dialect::SingBox));
        assert_eq!(ok("singbox"), Some(Dialect::SingBox));
        assert_eq!(ok("v2ray"), None);
        assert_eq!(ok(""), None);
    }

    #[test]
    fn an_existing_inbound_is_kept_rather_than_replaced() {
        let out = inject_inbound(
            r#"{"inbounds":[{"protocol":"vless"}],"outbounds":[]}"#,
            Ipv4Addr::LOCALHOST,
            1,
            Dialect::Xray,
        )
        .expect("injectable");
        let root = json::parse(&out).expect("valid json");
        assert_eq!(
            root.get("inbounds")
                .and_then(Json::as_arr)
                .map(<[Json]>::len),
            Some(2)
        );
    }

    #[test]
    fn an_inbound_that_is_not_an_array_is_an_error() {
        assert!(
            inject_inbound(r#"{"inbounds":7}"#, Ipv4Addr::LOCALHOST, 1, Dialect::Xray).is_err()
        );
    }

    #[test]
    fn sha256_matches_the_published_vectors() {
        for (input, want) in [
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let mut h = Sha256::new();
            h.update(input.as_bytes());
            assert_eq!(h.hex(), want, "sha256({input:?})");
        }
    }

    /// Longer than one block, so the buffered path and the padding path are both
    /// exercised rather than the single-shot one.
    #[test]
    fn sha256_handles_multi_block_input() {
        let mut h = Sha256::new();
        h.update(&b"a".repeat(1_000_000));
        assert_eq!(
            h.hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // Chunked updates must equal one big update.
        let mut h = Sha256::new();
        for chunk in b"abcdefghij".chunks(3) {
            h.update(chunk);
        }
        let mut once = Sha256::new();
        once.update(b"abcdefghij");
        assert_eq!(h.hex(), once.hex());
    }

    /// The three engines genuinely disagree about how a config file is named, and
    /// a harness that guessed one shape would leave the other two unable to start.
    #[test]
    fn each_config_argument_shape_names_the_file_the_way_its_engine_expects() {
        let path = Path::new("/tmp/cfg.json");
        let render = |shape: ConfigArg| {
            shape
                .args(path)
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(render(ConfigArg::Long), "run -config /tmp/cfg.json");
        assert_eq!(render(ConfigArg::Short), "run -c /tmp/cfg.json");
        assert_eq!(render(ConfigArg::Positional), "run /tmp/cfg.json");
    }

    #[test]
    fn config_argument_shapes_parse_and_reject() {
        for (raw, want) in [
            ("long", ConfigArg::Long),
            ("-config", ConfigArg::Long),
            ("--config", ConfigArg::Long),
            ("short", ConfigArg::Short),
            ("-c", ConfigArg::Short),
            ("positional", ConfigArg::Positional),
        ] {
            assert_eq!(ConfigArg::parse(raw).expect("parses"), want, "{raw}");
        }
        let err = ConfigArg::parse("--cfg").expect_err("an unknown shape is an error");
        assert!(
            err.to_string().contains("Expected one of"),
            "the error must list the shapes: {err}"
        );
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let sorted: Vec<u128> = (1..=100).collect();
        assert_eq!(nearest_rank(&sorted, 95), 95);
        assert_eq!(nearest_rank(&sorted, 99), 99);
        assert_eq!(nearest_rank(&[7], 95), 7);
        assert_eq!(nearest_rank(&[], 95), 0);
        assert_eq!(median(&[1, 2, 3]), 2);
        assert_eq!(median(&[1, 2, 3, 4]), 2);
        assert_eq!(median(&[]), 0);
    }

    #[test]
    fn a_short_transfer_is_a_fault_and_not_a_number() {
        // `measure` refuses to report fewer bytes than the request asked for, so
        // the request's own arithmetic is what the check compares against.
        let r =
            Request::parse(request_with(&[("iterations", "3"), ("payload_size", "7")]).as_bytes())
                .expect("valid");
        assert_eq!(r.flow_bytes(), 21);
        assert_eq!(r.total_bytes(), 21);
    }
}
