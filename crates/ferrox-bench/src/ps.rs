//! Reading a measured process from outside it: RSS, CPU and threads.
//!
//! Deliberately the same mechanism the pinned comparators use, so a number here
//! and a number there are the same kind of number. `xray-rust` samples
//! `ps -o rss= -o time= [-o nlwp=] -p PID`
//! (`upstream/xray-rust/crates/xray-bench/src/lib.rs:6333` and the
//! `ps_args` family at `:6371`), and `ZeroNet`'s harness samples the same way
//! (`upstream/zeronet/docs/benchmarks/harness/zbench/measure.py`). Sampling from
//! outside is the only way that compares a Go engine and a Rust engine at all:
//! `getrusage` would count the child for one and not the other.
//!
//! What that choice costs is stated rather than hidden: `ps` cannot see
//! allocations, so the allocation gates stay in-process in `count.rs` where they
//! are exact.
//!
//! # CPU, and the resolution it actually has
//!
//! `ps` is *not* where CPU is read from any more. GNU `ps` formats `TIME` as
//! `[[DD-]HH:]MM:SS` with no fractional part, so its finest reading is 1000 ms —
//! and a gate-5 transfer is a fifth of a second. That made the whole `cpu per
//! GiB` row read `0` on every Linux runner, which is one of the three rows the
//! gate decides on: it was `UNPROVEN` in all 40 engine-runs of the eight
//! `linux x86_64` runs quoted in `docs/methodology.md`, for every engine
//! including the ones that cannot possibly have been free (a `memcpy` relay of
//! 1 GiB costs a fifth of a second of user time on its own). The zero was the
//! format's resolution, not the process's cost.
//!
//! The fix is not a longer wait, it is a finer source. `ps` computes `TIME` from
//! fields 14 and 15 of `/proc/<pid>/stat` — `utime` and `stime`, in clock ticks —
//! and then rounds them to whole seconds on the way out. Reading the same two
//! fields directly keeps the kernel's accounting and drops only `ps`'s
//! formatting, which buys a hundredfold: `USER_HZ` is 100 on Linux, so a reading
//! is 10 ms and a `0` in a CPU column means what a reader expects it to mean
//! again. [`resolution_millis`] reports whichever source answered, so the
//! published floor is the mechanism's and not a number typed into a constant, and
//! `macos aarch64` keeps the `ps` path with its centisecond resolution.
//!
//! Reading the same fields `ps` reads also means this is still the same
//! *measurement*: same kernel counters, same child, sampled from outside.

use std::fmt;
use std::process::Command;
use std::sync::OnceLock;

/// Where the CPU column of a sample comes from, and what it resolves.
///
/// A function's answer, not a constant, because it is a fact about the running
/// host: [`sample`] takes the same branch, so the resolution
/// [`resolution_millis`] publishes is the resolution of the mechanism that
/// produced the row printed beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuSource {
    /// `utime + stime` from `/proc/<pid>/stat`, in `USER_HZ` clock ticks.
    ///
    /// Ten milliseconds on every Linux, because `USER_HZ` is 100 — the kernel
    /// scales `ns_to_clock_t` by it in `fs/proc/array.c` whatever `CONFIG_HZ` is,
    /// so the divisor is fixed rather than configurable.
    ProcStat,
    /// The `TIME` column of `ps`, which GNU formats in whole seconds and BSD
    /// `ps` in hundredths.
    PsTime,
    /// `GetProcessTimes`, which counts in 100-nanosecond units.
    GetProcessTimes,
}

impl CpuSource {
    /// The source `sample` uses on this host.
    ///
    /// A function rather than a constant because it is a fact about the running
    /// host: `sample` takes the same branch, so the resolution
    /// [`resolution_millis`] publishes is the resolution of the mechanism that
    /// produced the row printed beside it.
    pub fn current() -> Self {
        match Host::current() {
            Host::Linux => Self::ProcStat,
            // Windows has neither `/proc` nor a `ps` this can use, and answers with
            // the API instead. `GetProcessTimes` counts in 100-nanosecond units,
            // which is two orders of magnitude finer than the GNU `ps` a Linux runner
            // is limited to and is the reason this host can measure a transfer that
            // lasts a fifth of a second.
            Host::Windows => Self::GetProcessTimes,
            // An unknown host gets `ps` too, whose resolution depends on the `ps`
            // rather than on this build.
            Host::Macos | Host::Other => Self::PsTime,
        }
    }

    /// What the report names this source as, which is where the number came from.
    ///
    /// In the report rather than in a debug string, because the machine line is
    /// where a reader looks to find out what a number is a number *of* -- and a line
    /// that says `ps` on the host that reads `/proc`, or on the host that has no
    /// `ps` to sample with, names the wrong mechanism for a row whose whole
    /// existence is which one answered.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcStat => "/proc/<pid>/stat",
            Self::PsTime => "ps -o time=",
            Self::GetProcessTimes => "GetProcessTimes",
        }
    }

    /// The finest CPU delta this mechanism can report, in milliseconds.
    pub fn resolution_millis(self) -> u64 {
        match self {
            // `max(1)` on the *result* as well as the divisor: a `getconf` that
            // answered a large tick rate would otherwise divide to zero, and a floor
            // of zero says a `0` in a CPU column is exact when nothing resolves it.
            Self::ProcStat => (1_000 / clock_ticks_per_second().max(1)).max(1),
            // BSD `ps` prints hundredths. GNU `ps` prints whole seconds, and a host
            // this build cannot name is assumed to be the one that resolves less:
            // a floor that overstates what can be seen makes an `unproven` row
            // look measured.
            Self::PsTime if Host::current() == Host::Macos => 10,
            // A 100-nanosecond counter read into milliseconds: the rounding in
            // `ticks_to_millis` means a tenth of a millisecond can move the answer,
            // so the floor is a tenth rather than a whole one.
            Self::GetProcessTimes => 1,
            // An unknown host is assumed to be the one that resolves least: a floor
            // that overstates what can be seen makes an `unproven` row look measured.
            Self::PsTime => 1_000,
        }
    }
}

/// Milliseconds per clock tick in `/proc/<pid>/stat`: `USER_HZ`.
///
/// Not a guess and not a compile-time assumption: [`clock_ticks_per_second`]
/// asks the C library once through `getconf CLK_TCK`, which is the same answer
/// `USER_HZ` gives, and falls back to 100 — the value `fs/proc/array.c` uses —
/// if `getconf` is not on the image.
const FALLBACK_TICKS_PER_SECOND: u64 = 100;

/// `USER_HZ`, asked once per process.
///
/// `getconf CLK_TCK` is a POSIX query every Linux and BSD image carries in
/// coreutils, and asking beats assuming: a tick rate that were not 100 would
/// scale every CPU figure by the error, and a wrong CPU figure is worse than a
/// missing one because it still gates.
fn clock_ticks_per_second() -> u64 {
    static TICKS: OnceLock<u64> = OnceLock::new();
    *TICKS.get_or_init(|| {
        Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
            .filter(|t: &u64| *t > 0)
            .unwrap_or(FALLBACK_TICKS_PER_SECOND)
    })
}

/// Which process-stat fields the host's `ps` can answer.
///
/// Linux adds `nlwp`; macOS and the BSDs do not, so a thread count is reported
/// as absent rather than guessed. `xray-rust` gates the same field the same way
/// (`lib.rs:6371`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    Linux,
    Macos,
    Windows,
    Other,
}

impl Host {
    /// The host this build is running on.
    ///
    /// Not `const`: matching on `std::env::consts::OS` compares string slices,
    /// which is not yet a const operation on this toolchain, so a `const fn`
    /// here would be a promise the compiler cannot keep.
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            _ => Self::Other,
        }
    }

    /// The `ps` arguments this host needs.
    ///
    /// Never called on Windows, which has no `ps` to call: [`sample`] answers
    /// `NoSource` there before it reaches this. It stays defined so the test below
    /// can pin the spelling on the hosts that do use it.
    fn args(self, pid: u32) -> Vec<String> {
        let mut args = vec!["-o".into(), "rss=".into(), "-o".into(), "time=".into()];
        if self == Self::Linux {
            args.extend(["-o".into(), "nlwp=".into()]);
        }
        args.extend(["-p".into(), pid.to_string()]);
        args
    }
}

/// One reading of the measured process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Milliseconds since the measurement window opened.
    pub elapsed_ms: u128,
    /// Resident set size in KiB, as `ps` reports it.
    pub rss_kib: u64,
    /// Cumulative user+system CPU time in milliseconds.
    pub cpu_millis: u64,
    /// Thread count, or `None` on a host that cannot report it.
    pub threads: Option<u64>,
}

/// Why a sample could not be taken.
#[derive(Debug)]
pub enum SampleError {
    /// `ps` could not be run.
    Spawn(std::io::Error),
    /// `ps` ran and reported failure, or said nothing usable.
    Output { stderr: String },
    /// `ps` answered, and `/proc/<pid>/stat` was wanted but could not be read or
    /// understood. Kept apart from `Output` so the report can say which of the
    /// two mechanisms failed rather than that "ps reported no sample".
    Cpu { pid: u32, stderr: String },
    // Constructed only by the Windows sampler, so on the other three runners this
    // variant is a shape the enum has and nothing reaches -- and the Windows build is
    // the one where constructing it matters. The `Display` arm below is not enough to
    // keep it alive: dead-code analysis looks at construction, not at matching.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    /// A Win32 call the Windows sampler made returned zero.
    ///
    /// Named by call, with `GetLastError`'s code beside it, because "the sample
    /// failed" is not a diagnosis and `5` next to `OpenProcess` is. The codes are
    /// `WIN32_ERROR` values and are printed in decimal rather than translated: a
    /// message that named a cause the harness has not verified would be the same
    /// failure as the parse bug this variant exists to be distinguishable from.
    Win32 { call: &'static str, code: u32 },
}

impl fmt::Display for SampleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(e) => write!(f, "cannot run ps: {e}"),
            Self::Output { stderr } => write!(f, "ps reported no sample: {stderr}"),
            Self::Cpu { pid, stderr } => {
                write!(f, "cannot read cpu from /proc/{pid}/stat: {stderr}")
            }
            Self::Win32 { call, code } => write!(f, "{call} failed, GetLastError {code}"),
        }
    }
}

/// The finest CPU delta this host can report.
///
/// Published into every report so a `0` in a CPU column is read as "under the
/// resolution" rather than "was free", and so a reader can see *which* mechanism
/// produced the number rather than trusting that a resolution was configured.
pub fn resolution_millis() -> u64 {
    CpuSource::current().resolution_millis()
}

/// Sample the process once.
///
/// CPU comes from `/proc/<pid>/stat` where that is the host's mechanism, and from
/// `ps`'s `TIME` column everywhere else; RSS and the thread count come from `ps`,
/// which reports both with the resolution this needs and no finer.
///
/// The `ps` line is written space-separated, so its parse is positional: RSS
/// first, then the cumulative time, then the thread count on the hosts that have
/// one. The day field of `ps` time (`DD-HH:MM:SS`) is honoured rather than
/// skipped, because a 24-hour-old process is a real possibility on a long-lived
/// core and silently truncating its CPU to one day would understate a comparison.
pub fn sample(host: Host, pid: u32, elapsed_ms: u128) -> Result<Sample, SampleError> {
    // Windows is not a `ps` host and does not pretend to be one: the `ps` a Git-Bash
    // step finds on `windows-latest` answers `unknown option -- o`, so shelling out to
    // it produces a parse failure that is really a missing mechanism. It reads the
    // process through the API instead -- see [`win32`].
    #[cfg(target_os = "windows")]
    if host == Host::Windows {
        return win32::sample(pid, elapsed_ms);
    }
    let _ = host;
    let output = Command::new("ps")
        .args(host.args(pid))
        .output()
        .map_err(SampleError::Spawn)?;
    if !output.status.success() {
        return Err(SampleError::Output {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let line = raw
        .lines()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| SampleError::Output {
            stderr: format!("no sample line for pid {pid}"),
        })?;
    let mut sample = parse(line, elapsed_ms).ok_or(SampleError::Output {
        stderr: format!("unparsable ps sample `{line}`"),
    })?;
    if host == Host::Linux {
        // Not a fallback chain: on Linux the `ps` figure is second-resolution and
        // therefore useless for a sub-second window, so `/proc` failing is an
        // error the caller has to hear about rather than a `0` to be published.
        sample.cpu_millis = proc_stat_cpu(pid).ok_or(SampleError::Cpu {
            pid,
            stderr: format!("no utime/stime in /proc/{pid}/stat"),
        })?;
    }
    Ok(sample)
}

/// Parse one `ps` line. `None` for anything that does not have the shape.
///
/// Public because it is the part that can be wrong in a way a timing cannot:
/// parsing is a total function over strings and is tested directly.
pub fn parse(line: &str, elapsed_ms: u128) -> Option<Sample> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 2 {
        return None;
    }
    let rss_kib = fields[0].parse::<u64>().ok()?;
    let cpu_millis = parse_time_millis(fields[1])?;
    let threads = fields.get(2).and_then(|raw| raw.parse::<u64>().ok());
    Some(Sample {
        elapsed_ms,
        rss_kib,
        cpu_millis,
        threads,
    })
}

/// `ps` cumulative time to milliseconds: `SS`, `MM:SS`, `HH:MM:SS` or `DD-HH:MM:SS`.
///
/// Seconds may be fractional (`0.34`), which is why the seconds field is parsed
/// as a float and rounded rather than truncated: truncating every sample
/// downwards would make a busy process look cheaper than it was, which is the
/// one direction a CPU comparison must not err in.
pub fn parse_time_millis(raw: &str) -> Option<u64> {
    let (days, time) = match raw.split_once('-') {
        Some((days, time)) => (days.parse::<u64>().ok()?, time),
        None => (0, raw),
    };
    let parts: Vec<&str> = time.split(':').collect();
    // `ps` emits at most `HH:MM:SS` after the day field. Four fields is not a
    // longer time, it is a different thing, and guessing which field is which
    // would turn a parse failure into a wrong CPU figure.
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let seconds: f64 = parts.last()?.parse().ok()?;
    let mut total = days
        .checked_mul(86_400_000)?
        .checked_add((seconds * 1000.0).round() as u64)?;
    // Counted from the right: the last field is seconds, the one before it
    // minutes, then hours. Treating every leading field as minutes would turn
    // `1:02:03` into three minutes and one hundred and eighty-three seconds,
    // which is a CPU figure wrong by a factor of twenty.
    for (offset, part) in parts[..parts.len() - 1].iter().enumerate() {
        let scale = 60u64.checked_pow((parts.len() - 1 - offset) as u32)?;
        total = total.checked_add(
            part.parse::<u64>()
                .ok()?
                .checked_mul(scale)?
                .checked_mul(1000)?,
        )?;
    }
    Some(total)
}

/// Cumulative user+system CPU for `pid`, in milliseconds, from `/proc/<pid>/stat`.
///
/// The fields are the same ones `ps` sums -- `utime` and `stime`, fields 14 and 15 --
/// so this is the same kernel counter at the kernel's own resolution instead of
/// `ps`'s. `getconf CLK_TCK` is asked here rather than inside the parse because it
/// is the one fact here that is the host's: on `windows x86_64` `getconf` answers
/// MSYS2's emulated 1000, not Linux's 100.
///
/// `None` on any host with no `/proc`, and on a line that does not have the shape: a
/// caller that needs this must be able to tell "absent" from "zero", because "zero"
/// is a measurement and "absent" is a reason the row is unproven.
fn proc_stat_cpu(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    proc_stat_millis(&stat, clock_ticks_per_second())
}

/// `utime + stime` out of a `/proc/<pid>/stat` line, in milliseconds, at `ticks_per_second`.
///
/// Split out from [`proc_stat_cpu`] so the field arithmetic -- the part that can be
/// wrong by an order of magnitude without looking wrong -- is tested against real
/// kernel lines rather than trusted.
///
/// The divisor is a parameter because only one of the two facts here is the host's.
/// The arithmetic is the same on every host; `getconf CLK_TCK` is not, and on
/// `windows x86_64` it is MSYS2's emulated one, which is 1000. So a fixture that
/// says "9 + 4 ticks" says 130 ms and the caller that owns the divisor is the one
/// that knows what a tick is worth. Making it a parameter is also what lets these
/// run on every runner instead of only the one with a `/proc`.
fn proc_stat_millis(stat: &str, ticks_per_second: u64) -> Option<u64> {
    // The comm field is parenthesised and may itself contain spaces and
    // parentheses -- `ps` renames threads `(sd-pam)` and the like -- so the fields
    // after it are found from the *last* `)`, not by splitting the whole line.
    let (_, rest) = stat.rsplit_once(')')?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After comm, field 3 is `state`, so `utime` is index 11 and `stime` index 12.
    let ticks = fields
        .get(11)?
        .parse::<u64>()
        .ok()?
        .checked_add(fields.get(12)?.parse::<u64>().ok()?)?;
    let millis = ticks.checked_mul(1_000)?;
    millis.checked_div(ticks_per_second)
}

/// `USER_HZ` the `/proc` fixtures below are written at.
///
/// A Linux `USER_HZ` is 100 whatever `CONFIG_HZ` is -- the kernel scales
/// `ns_to_clock_t` by it in `fs/proc/array.c` -- so a fixture written in ticks says
/// the same thing on every machine, which is the property that lets these be
/// ordinary host-independent tests rather than a Linux-only corner.
#[cfg(test)]
const FIXTURE_HZ: u64 = 100;

/// The Windows sampler.
///
/// # Why this is a module and not four `extern` blocks
///
/// It was hand-declared here before, and it crashed the runner with
/// `STATUS_ACCESS_VIOLATION` — a hand-written `PROCESS_MEMORY_COUNTERS` is a layout
/// claim, and a wrong one is a wild pointer rather than a compile error. That is what
/// `windows-sys` removes: its declarations are generated from the SDK headers, so the
/// layouts and the signatures are right because the headers say so. The functions
/// themselves are still four `unsafe` calls, and they are the only part of this file
/// that cannot be exercised without a Windows host; the arithmetic around them —
/// `FILETIME` to milliseconds, the exit-time subtraction, the thread count — is
/// plain functions above this one and is tested on every runner.
///
/// # The three readings, and what each is for
///
/// - **CPU**: `GetProcessTimes`, whose kernel and user figures are separate amounts
///   of time and are summed. 100-nanosecond units, so a reading resolves to a
///   millisecond with room to spare — against the 1000 ms floor `ps` forces on Linux
///   and the 10 ms BSD `ps` gives macOS. A gate-5 transfer is a fifth of a second, so
///   this is the first mechanism in this file that can resolve one.
/// - **RSS**: `peakWorkingSetSize`, because the Linux row reads `ru_maxrss` and the two
///   are the same quantity — a peak, not a point reading.
/// - **Threads**: a `ToolHelp` snapshot walked for entries owned by the pid. This is
///   the one call that can fail for a reason unrelated to permissions, and it is
///   retried: a snapshot taken while the thread list is being updated comes back
///   `ERROR_BAD_LENGTH`, and that is a race rather than a fault.
#[cfg(target_os = "windows")]
mod win32 {
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{Sample, SampleError};

    /// A failed Win32 call, named.
    fn failed(call: &'static str) -> SampleError {
        // SAFETY: `GetLastError` reads thread-local state and writes nothing.
        let code = unsafe { GetLastError() };
        SampleError::Win32 { call, code }
    }

    /// Sample one process through the Win32 API.
    pub(super) fn sample(pid: u32, elapsed_ms: u128) -> Result<Sample, SampleError> {
        // SAFETY: `OpenProcess` takes a pid and returns a new handle; nothing is
        // dereferenced here, and the handle is closed on every path out below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle == 0 {
            return Err(failed("OpenProcess"));
        }
        // `CloseHandle` returns a `BOOL` this ignores on purpose: the handle is being
        // released either way, and a failed close is not a measurement to report.
        let sample = read(handle, pid, elapsed_ms);
        // SAFETY: `handle` came from `OpenProcess` above and is closed exactly once.
        unsafe {
            CloseHandle(handle);
        }
        sample
    }

    fn read(handle: HANDLE, pid: u32, elapsed_ms: u128) -> Result<Sample, SampleError> {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        // SAFETY: all four are live, initialised `FILETIME`s, which is what this
        // function writes through its out-parameters; `cb` is the count it reads
        // and the handles and pointers are valid for the duration of the call.
        let times = unsafe {
            GetProcessTimes(
                handle,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if times == 0 {
            return Err(failed("GetProcessTimes"));
        }

        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };
        // SAFETY: `counters` is a live, fully initialised struct whose `cb` is its own
        // size, which is the contract `GetProcessMemoryInfo` checks first.
        let memory = unsafe { GetProcessMemoryInfo(handle, &raw mut counters, counters.cb) };
        if memory == 0 {
            return Err(failed("GetProcessMemoryInfo"));
        }

        Ok(Sample {
            elapsed_ms,
            rss_kib: (counters.PeakWorkingSetSize / 1024) as u64,
            cpu_millis: super::cpu_millis_from_ticks(
                filetime_ticks(exit),
                filetime_ticks(kernel) + filetime_ticks(user),
            ),
            // Threads are a separate mechanism and a separate failure: the two
            // figures above are already read, so a snapshot this host refuses is
            // reported as an absent thread count rather than as a failed sample.
            threads: thread_count(pid).ok(),
        })
    }

    /// A `FILETIME`'s 100-nanosecond count.
    ///
    /// Takes the two halves rather than a `FILETIME` so the arithmetic it does is
    /// testable on a host that has no `FILETIME`.
    fn filetime_ticks(ft: FILETIME) -> u64 {
        super::ticks_from_parts(ft.dwHighDateTime, ft.dwLowDateTime)
    }

    /// How many threads the system snapshot attributes to `pid`.
    fn thread_count(pid: u32) -> Result<u64, SampleError> {
        // `CreateToolhelp32Snapshot` documents `ERROR_BAD_LENGTH` for a snapshot
        // taken while the thread list is being walked, which is a race with another
        // process starting a thread and not a fault in this one. Bounded retries, so
        // a permanently failing snapshot still ends rather than spinning.
        let snapshot = (0..4)
            .find_map(|_| {
                // SAFETY: the flags ask for a thread list and the pid is ignored for
                // a thread snapshot; nothing is dereferenced through the result.
                let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
                if handle == INVALID_HANDLE_VALUE || handle == 0 {
                    None
                } else {
                    Some(handle)
                }
            })
            .ok_or_else(|| failed("CreateToolhelp32Snapshot"))?;
        let count = count_threads(snapshot, pid);
        // SAFETY: `snapshot` is a live handle from the call above, closed once.
        unsafe {
            CloseHandle(snapshot);
        }
        count
    }

    fn count_threads(snapshot: HANDLE, pid: u32) -> Result<u64, SampleError> {
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };
        // SAFETY: `entry.dwSize` is set to its own size, which is the first field
        // `Thread32First` reads and the check that makes the walk well-defined.
        let first = unsafe { Thread32First(snapshot, &raw mut entry) };
        if first == 0 {
            return Err(failed("Thread32First"));
        }
        let mut owners = vec![entry.th32OwnerProcessID];
        loop {
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            // SAFETY: as above: a live, correctly sized entry and a live snapshot.
            // Reaching the end of the list is reported as a zero return, which is a
            // finished walk rather than an error, so it is not distinguished here.
            if unsafe { Thread32Next(snapshot, &raw mut entry) } == 0 {
                return Ok(super::count_owned(owners, pid));
            }
            owners.push(entry.th32OwnerProcessID);
        }
    }
}

/// A `FILETIME`'s two halves as one 100-nanosecond count.
///
/// High half first: `FILETIME` is `{ dwLowDateTime, dwHighDateTime }` and the count is
/// the high half shifted up by 32, so reading the fields in declaration order would be
/// a number off by a factor of 2^32.
#[cfg(any(target_os = "windows", test))]
pub fn ticks_from_parts(high: u32, low: u32) -> u64 {
    (u64::from(high) << 32) | u64::from(low)
}

/// 100-nanosecond units to milliseconds.
///
/// Rounded, never truncated: every sample rounded down would make a busy process look
/// cheaper than it was, which is the one direction a CPU comparison must not err in.
#[cfg(any(target_os = "windows", test))]
pub fn ticks_to_millis(ticks: u64) -> u64 {
    // 10_000 ticks to a millisecond. The remainder is promoted before the divide so
    // `ticks + 5_000` cannot overflow at the top of the range.
    (ticks / 10_000) + u64::from((ticks % 10_000) >= 5_000)
}

/// Cumulative CPU milliseconds a live process has used, from Win32's two figures.
///
/// `exit` is subtracted because it is a *point in time* and the other two are *amounts
/// of time* since the process was created; without the subtraction a process that ran
/// for an hour before the harness attached would publish an hour of CPU it was not
/// charged for. The saturating subtraction is what a process whose exit time is later
/// than its CPU total — a live one, where `lpExitTime` is undefined — gets.
#[cfg(any(target_os = "windows", test))]
pub fn cpu_millis_from_ticks(exit: u64, cpu: u64) -> u64 {
    ticks_to_millis(cpu.saturating_sub(exit))
}

/// Threads in a list of owner pids belonging to `pid`.
#[cfg(any(target_os = "windows", test))]
fn count_owned(owners: impl IntoIterator<Item = u32>, pid: u32) -> u64 {
    owners.into_iter().filter(|owner| *owner == pid).count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `FILETIME` halves are high-first in the count and low-first in the struct,
    /// which is the whole of what a 2^32 error would look like.
    #[test]
    fn a_filetime_is_its_high_half_shifted_up() {
        assert_eq!(ticks_from_parts(0, 1), 1);
        assert_eq!(ticks_from_parts(0, u32::MAX), u64::from(u32::MAX));
        assert_eq!(ticks_from_parts(1, 0), 1 << 32);
        // One second is ten million 100-nanosecond units, which is the figure MSDN
        // gives and the one every assertion below is anchored to.
        assert_eq!(ticks_from_parts(0, 10_000_000), 10_000_000);
    }

    /// Ten thousand units to a millisecond, rounded rather than truncated: every
    /// sample rounded down would make a busy process look cheaper than it was, which
    /// is the one direction a CPU comparison must not err in.
    #[test]
    fn ticks_round_to_the_nearest_millisecond() {
        assert_eq!(ticks_to_millis(0), 0);
        assert_eq!(ticks_to_millis(4_999), 0);
        assert_eq!(ticks_to_millis(5_000), 1, "half a millisecond rounds up");
        assert_eq!(ticks_to_millis(9_999), 1);
        assert_eq!(ticks_to_millis(10_000), 1);
        assert_eq!(ticks_to_millis(10_000_000), 1_000, "one second");
        // The remainder is promoted before the add, so the top of the range cannot
        // wrap. `u64::MAX` ticks is about 58_000 years.
        assert_eq!(ticks_to_millis(u64::MAX), ticks_to_millis(u64::MAX));
        assert!(ticks_to_millis(u64::MAX) > 0);
    }

    /// `lpExitTime` is a point in time and the other two are amounts of time, so
    /// the exit has to come off or a process that ran before the harness attached
    /// publishes CPU it was never charged for.
    #[test]
    fn cpu_excludes_what_the_process_had_already_spent() {
        // Ten seconds of CPU, created ten seconds ago and still running: the exit
        // time is undefined for a live process, which reads as zero here.
        assert_eq!(cpu_millis_from_ticks(0, 100_000_000), 10_000);
        // The same process measured one second after it started.
        assert_eq!(cpu_millis_from_ticks(10_000_000, 100_000_000), 9_000);
        // A live process whose kernel+user is smaller than the clock says is
        // saturated at zero rather than wrapped to a number near `u64::MAX`.
        assert_eq!(cpu_millis_from_ticks(20_000_000, 10_000_000), 0);
    }

    /// A thread belongs to the process that owns it, and the snapshot is a list of
    /// every thread on the machine, so the count has to filter rather than take the
    /// length.
    #[test]
    fn threads_are_counted_by_owner() {
        assert_eq!(count_owned(Vec::new(), 7), 0);
        assert_eq!(count_owned([7], 7), 1);
        assert_eq!(count_owned([7, 7, 7], 7), 3);
        assert_eq!(count_owned([1, 2, 7, 7, 9], 7), 2);
        assert_eq!(count_owned([1, 2, 3], 7), 0);
    }

    /// Windows reads a 100-nanosecond counter, which is finer than anything either
    /// `ps` path can offer, and it is the only host in the matrix that can resolve a
    /// transfer shorter than ten milliseconds.
    ///
    /// Compared against `PsTime` rather than `ProcStat`: `ProcStat`'s floor is
    /// `1000 / USER_HZ`, and `USER_HZ` comes from `getconf`, which is not on every
    /// image this builds for. Asserting against a host-dependent value would make
    /// this test a statement about the runner rather than about the mechanism.
    #[test]
    fn windows_resolves_far_more_finely_than_a_ps() {
        assert_eq!(CpuSource::GetProcessTimes.as_str(), "GetProcessTimes");
        assert_eq!(CpuSource::GetProcessTimes.resolution_millis(), 1);
        assert!(
            CpuSource::GetProcessTimes.resolution_millis() < CpuSource::PsTime.resolution_millis(),
            "a 100-nanosecond counter is finer than anything ps formats"
        );
    }

    #[test]
    fn parses_every_ps_time_shape() {
        assert_eq!(parse_time_millis("0.34"), Some(340));
        assert_eq!(parse_time_millis("1.50"), Some(1500));
        assert_eq!(parse_time_millis("12:34"), Some(754_000));
        assert_eq!(parse_time_millis("1:02:03"), Some(3_723_000));
        assert_eq!(parse_time_millis("2-00:00:00"), Some(172_800_000));
        assert_eq!(parse_time_millis("10-11:12:13"), Some(904_333_000));
        // A day field must not be truncated away: a process older than 24h whose
        // CPU silently reset to zero would read as idle in a memory comparison.
        assert!(parse_time_millis("10-00:00:01").unwrap() > 864_000_000);
    }

    #[test]
    fn rejects_time_it_cannot_read() {
        for bad in ["", "-", "abc", "1:2:3:4", "1:x", "x:00"] {
            assert_eq!(parse_time_millis(bad), None, "{bad} must not parse");
        }
    }

    #[test]
    fn reads_rss_time_and_threads_in_order() {
        let s = parse("  12345 0:01.23 17 ", 500).expect("sample");
        assert_eq!(s.rss_kib, 12_345);
        assert_eq!(s.cpu_millis, 1230);
        assert_eq!(s.threads, Some(17));
        assert_eq!(s.elapsed_ms, 500);
    }

    /// A macOS line has no thread field, so the count must be absent rather than
    /// silently reading the time column as a thread count.
    #[test]
    fn macos_line_reports_no_thread_count() {
        let s = parse(" 4096 0:00.50 ", 0).expect("sample");
        assert_eq!(s.rss_kib, 4096);
        assert_eq!(s.cpu_millis, 500);
        assert_eq!(s.threads, None);
    }

    #[test]
    fn a_truncated_line_is_not_a_sample() {
        assert_eq!(parse("", 0), None);
        assert_eq!(parse("4096", 0), None);
        assert_eq!(parse("x 0:00.01", 0), None);
    }

    #[test]
    fn linux_asks_for_threads_and_macos_does_not() {
        assert!(Host::Linux.args(7).contains(&"nlwp=".to_owned()));
        assert!(!Host::Macos.args(7).contains(&"nlwp=".to_owned()));
        assert!(
            !Host::Windows.args(7).contains(&"nlwp=".to_owned()),
            "and windows never gets as far as ps at all"
        );
        for host in [Host::Linux, Host::Macos, Host::Windows, Host::Other] {
            let args = host.args(7);
            assert_eq!(args.first().map(String::as_str), Some("-o"));
            assert_eq!(args.last().map(String::as_str), Some("7"));
        }
    }

    /// The whole point of reading `/proc`: a process that has used 130 ms of CPU
    /// must read as 130 ms, where `ps -o time=` prints `00:00:00`.
    ///
    /// The fixture is a real 52-field `/proc/<pid>/stat` line, with `utime` 9 and
    /// `stime` 4 at `USER_HZ` 100, because the arithmetic here is the reason the
    /// row exists at all and a token fixture would not catch a field being off by
    /// one.
    #[test]
    fn proc_stat_reads_a_sub_second_cpu_that_ps_rounds_away() {
        let line = "1234 (ferrox-zer) S 1 1234 1234 0 -1 4194304 5000 0 0 0 \
                    9 4 0 0 20 0 3 0 1000 2000 0 0 0 0 0 0 0 0 0 0 0 0 0 \
                    0 20 0 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(
            proc_stat_millis(line, FIXTURE_HZ),
            Some(130),
            "9 + 4 ticks at 100 Hz is 130 ms"
        );
        assert_eq!(
            parse_time_millis("00:00:00"),
            Some(0),
            "and this is the ps reading of the same process that it replaces"
        );
    }

    /// `comm` is free text and Linux puts spaces and parentheses in it, so the
    /// fields after it cannot be found by splitting from the front.
    #[test]
    fn proc_stat_finds_the_fields_past_a_comm_with_spaces_in_it() {
        let line = "1234 (Web Content (tab)) R 1 2 3 0 0 0 0 0 0 0 7 5 0 0 20 0 1 \
                    0 100 200 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 \
                    0 20 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0";
        assert_eq!(proc_stat_millis(line, FIXTURE_HZ), Some(120));
        assert_eq!(
            proc_stat_millis(line, 1_000),
            Some(12),
            "the same line at 1 kHz is a twelfth of it, so the divisor is used"
        );
    }

    #[test]
    fn proc_stat_rejects_a_line_it_cannot_read() {
        for bad in ["", "1234 (x", "1234 (x) S 1 2"] {
            assert_eq!(
                proc_stat_millis(bad, FIXTURE_HZ),
                None,
                "{bad} must not parse"
            );
        }
        assert_eq!(
            proc_stat_millis("1234 (x) S 1 2 3 0 0 0 0 0 0 0 9 4", 0),
            None,
            "a zero divisor resolves nothing"
        );
    }

    /// A live sample of this process must come from the source the report names,
    /// on whichever host runs the test.
    ///
    /// Unix, and the restriction is the mechanism's rather than the assertion's: the
    /// test shells out to `ps` and reads `/proc`, and the `ps` a `cargo test` step
    /// finds on `windows x86_64` is not the one `parity.yml`'s bash step finds, so
    /// running it there would be a statement about a shell. The published resolution
    /// is still checked on every host, because a floor that is zero, or that
    /// disagrees with the source judging every CPU row, is a property of this code
    /// and not of the operating system.
    #[cfg(unix)]
    #[test]
    fn a_live_sample_reports_the_source_it_used() {
        let pid = std::process::id();
        let s = sample(Host::current(), pid, 0).expect("this process is sampleable");
        let floor = resolution_millis();
        assert_eq!(CpuSource::current().resolution_millis(), floor);
        assert!(floor > 0, "a published resolution of zero resolves nothing");
        assert!(s.rss_kib > 0, "a running process has a resident set");
        match Host::current() {
            Host::Linux => {
                // **Between** two `/proc` readings, not equal to one.
                //
                // This process is running — it is inside a test — so its CPU time
                // grows while the test runs, and `sample` shells out to `ps` before
                // this reads `/proc`. The two readings are of a *changing*
                // quantity, so equality is a race that a loaded runner loses:
                // run `37306993580` read `ps` at 30 ms and `/proc` at 40 ms and
                // failed on `left: 30, right: 40`. `/proc`'s CPU total is
                // monotonic non-decreasing, so the only sound assertion is that
                // the `ps`-derived value lies between a `/proc` reading taken
                // before `sample` and one taken after — which is what the two
                // two samples are for, and which fails only if `ps` is not
                // reading the same counter at all.
                let before = proc_stat_cpu(pid).expect("this process has a /proc entry");
                let sampled = sample(Host::current(), pid, 0).expect("this process is sampleable");
                let after = proc_stat_cpu(pid).expect("this process has a /proc entry");
                assert!(
                    before <= sampled.cpu_millis && sampled.cpu_millis <= after,
                    "linux cpu comes from /proc only: {sampled:?} against {before}..={after}"
                );
                assert!(floor <= 10, "/proc resolves a tick, not a second");
                assert!(s.threads.is_some(), "linux ps can count threads");
            }
            Host::Macos => {
                assert_eq!(floor, 10, "macOS ps prints hundredths");
                assert!(s.threads.is_none(), "macOS ps cannot count threads");
            }
            #[cfg(target_os = "windows")]
            Host::Windows => {
                // The live sample is this very process, which is the one process on
                // this host that is guaranteed to exist and to be openable. The three
                // figures it asserts are the ones the gate reads, and each is checked
                // against something true of this process rather than against a
                // constant: CPU is below real elapsed time because a sampler spends
                // most of its life asleep, and RSS is above zero because there is a
                // running process here.
                let s = sample(host, pid, 0).expect("windows samples through the API");
                assert!(
                    s.cpu_millis < 60_000,
                    "this process has not used a CPU-minute"
                );
                assert!(s.rss_kib > 0, "a running process has a resident set");
                assert!(
                    s.threads.is_some(),
                    "ToolHelp counts this process's threads"
                );
            }
            #[cfg(not(target_os = "windows"))]
            Host::Windows => assert_eq!(floor, CpuSource::GetProcessTimes.resolution_millis()),
            Host::Other => assert_eq!(floor, 1_000),
        }
    }

    /// The resolution the report publishes is the current source's own, everywhere.
    ///
    /// The half of the live-sample invariant that is about this code rather than
    /// about the OS, and the half that decides whether a `0` in a CPU column is
    /// published as a measurement or as unproven.
    #[test]
    fn the_published_resolution_is_the_current_sources_own() {
        let source = CpuSource::current();
        assert_eq!(resolution_millis(), source.resolution_millis());
        assert!(resolution_millis() > 0, "a floor of zero resolves nothing");
        assert_eq!(
            source,
            match Host::current() {
                Host::Linux => CpuSource::ProcStat,
                Host::Windows => CpuSource::GetProcessTimes,
                Host::Macos | Host::Other => CpuSource::PsTime,
            },
            "the source a row names must be the branch sample() takes"
        );
    }
}
