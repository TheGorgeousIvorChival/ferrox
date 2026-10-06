# The benchmark matrix: every criterion the four projects report, plus ours

This is the catalog, not the results. Results live in dated bundles under `results/<date>/<runner>/`; the README shows the latest per runner. A scenario is a row here only with the harness knobs that run it and the reason when it cannot run: an omitted row reads as "not measured", which is how a weak row survives.

## Where this sits against the two pinned harnesses

ZeroNet's harness charts throughput, CPU per GiB, idle and peak memory,
connect time, round-trip percentiles, setup rate, thread count, server cost,
the harness ceiling, coverage, capability gaps and the run's own resolution;
xray-rust publishes throughput, CPU per GiB, latency, memory, tunnel
throughput, DNS and geodata series. The mapping is one row per criterion, and
a criterion without a chart names the knob that would earn it one:

| criterion | ZeroNet | xray-rust | here |
| --------- | ------- | --------- | ---- |
| bulk throughput | `*-throughput.png` | `throughput-*.svg` | `throughput.png`, five engines |
| CPU per GiB | `*-cpu-per-gb.png` | `cpu-per-gib-*.svg` | `cpu-per-gib.png` |
| peak RSS | `*-peak-memory.png` | `memory-rss-*.svg` | `memory-rss.png` |
| idle RSS | `*-idle-memory.png` | idle + held-flow series | empty: the harness refuses held-open flows (`idle_connections`), so no slope exists to chart |
| connect time | `*-connect-us.png` | setup stages | `setup-latency.png`: per-stage medians |
| round-trip latency | percentiles | `latency-*.svg` | empty: a throughput harness moves bulk bytes, not round trips (`latency_us` is null by schema); needs a latency knob |
| setup rate | connect-and-close/s | reconnect-burst | empty: stages are timed, not rated; needs a rate knob |
| thread count | peak column | — | `threads.png` |
| server cost | server process CPU/RSS | fixture notes | not applicable by design: every scenario is a self-relay, so both stacks live in the measured process and its CPU/RSS already include them |
| harness ceiling | ceiling + 85% bound | transfer-window notes | `ceiling.png`: per-repeat ceiling, runner spread, generator-bound marks |
| coverage | `run-coverage.png` | device results | `coverage.png`: measured pass / measured fail / named gap |
| capability gaps | `capability-surface.png`, `protocol-transport-grid.png` | config compat docs | partial: `coverage.png` plus the per-method proof table in every report (`methods.rs`); config-level probing against each engine's own validator is future |
| resolution | `resolution.png` | run ranges | the spread line on `ceiling.png` plus `runner_spread` in every cell |
| binary size | — | — | `binary-size.png`: nobody else charts what ships |
| cold start | — | — | `startup.png`: time to first listen |
| verdicts | 5% whole-interval gate | narrative | every row carries its interval and verdict; `validate-benchmark-matrix.py` re-derives them |

DNS, geodata and TUN series are xray-rust-only surfaces (local DNS extensions, real rule data, TUN devices): outside this matrix's scope, stated here rather than silently dropped.

## Engines

Five engines, each pinned and recorded with its binary digest in every bundle:

| engine | source | config dialect |
| ------ | ------ | -------------- |
| ferrox | this workspace | Xray-dialectK JSON, same surface it serves |
| xray-core | `upstream/pins.toml` `xray-core` | Xray JSON |
| zeronet | `upstream/pins.toml` `zeronet` | Xray JSON |
| xray-rust | `upstream/pins.toml` `xray-rust` | Xray JSON where accepted, else the cell names why not |
| sing-box | `upstream/pins.toml` `sing-box` | sing-box JSON; Xray-dialect cells name the translation |

The reference every ratio is measured against is `xray-core`, first engine in every cell. `ferrox` is the only gated engine: a comparator measuring worse is a fact about the comparator, published, never gating.

## Topology

Every scenario is a self-relay: the engine serves a protocol inbound and dials it through its own outbound to a loopback echo sink, with the harness SOCKS inbound injected on top. Client and server stacks of the same engine are both in the path, which is what a user pays for. Cross-engine pairs would measure two stacks at once and attribute the difference to neither.

## Groups and scenarios

`down`/`up`/`duplex` move bulk bytes; `setup` measures connection cost; `memory` measures resident size; `coverage` measures the matrix itself; `binary` measures what ships. `streams` is concurrent flows; `MiB` is total bytes per flow. Every scenario names its `ferrox-bench` knobs.

Every bulk row moves 8 GiB per repeat in total: the window is the instrument, and a shared runner that loses the CPU for tens of milliseconds reads a 32 MiB transfer as noise and an 8 GiB one as a number ([`../methodology.md`](../methodology.md): 2.7x runner spread down to 1.02x). Per-flow iterations scale with the flow count so the total stays 8 GiB.

### bulk

Same bytes every engine must forward; CPU and RSS are sampled per 100 ms.

| scenario | traffic | streams | iters/flow | MiB/flow | outbound |
| -------- | ------- | ------- | ---------- | -------- | -------- |
| vless-raw-down-{1,8} | download | 1, 8 | 131072, 16384 | 8192, 1024 | vless, tcp |
| vless-raw-up-1 | upload | 1 | 131072 | 8192 | vless, tcp |
| vless-raw-duplex-8 | full-duplex | 8 | 8192 | 512 | vless, tcp |
| vless-ws-down-8 | download | 8 | 16384 | 1024 | vless, ws `/tunnel` |
| vless-grpc-down-8 | download | 8 | 16384 | 1024 | vless, grpc `TunnelService` |
| vless-xhttp-down-8 | download | 8 | 16384 | 1024 | vless, xhttp `/share` |
| vmess-raw-down-8 | download | 8 | 16384 | 1024 | vmess, tcp, auto |
| trojan-raw-down-8 | download | 8 | 16384 | 1024 | trojan, tcp |
| shadowsocks-raw-down-8 | download | 8 | 16384 | 1024 | shadowsocks, aes-256-gcm, tcp |

The 16-flow ladders run in the `full` tier only. A 64-flow ladder is refused by the harness (`connections` validates 1..=16) until that bound moves with the thread-pool reasoning that justifies it. `httpupgrade`, `httpheader` and `vision` rows are future scenarios, named here rather than measured: each needs its template proven against every engine first, and an unproven row in the runner is a red cell with no owner.

### setup

Connection cost, from the harness `setup` quartiles every `result.json` already records (`tcp_connect_us`, `socks_method_us`, `socks_connect_us`, `socks_setup_us`, `total_us`): 1000 sequential connects of an 8-byte payload each, one flow, reporting per-stage medians. Plus a churn row of 2000 connect-and-close cycles, which needs a reconnect knob the harness does not have yet — empty with that reason, not silently dropped.

| scenario | workload | reports |
| -------- | -------- | ------- |
| vless-raw-setup-1k | 1000 × 8 B round trips, 1 flow | per-stage medians |
| vless-raw-churn-2k | 2000 connect-and-close cycles | empty: needs a reconnect knob |

### memory

Peak RSS per bulk cell, plus idle RSS with held-open flows. The hold needs an idle-connections knob the harness refuses today (`parity.rs` names it), so the scaling slope is empty with that reason and peak RSS is what is charted.

| scenario | workload | reports |
| -------- | -------- | ------- |
| *-peak-rss | every bulk cell | peak RSS, MiB |
| idle-rss-ladder | 1/16/128 held flows | empty: needs an idle-connections knob |

### coverage

The protocol-by-transport grid itself: each oracle/conformance row that names both ends. A cell is green (measured row), red (measured failure with the log attached), or empty with the rung reason. Rendered as a grid, not a number.

### binary

What ships, measured with a ruler rather than a stopwatch: release binary size in MiB and cold start to first listen in seconds, per engine, plus peak thread count beside peak RSS. Nobody else charts any of the three; all three decide real deployments.

### udp

Empty with the reason every other doc already states: no engine path here measures UDP, and an engine that spawns a responder for an unmeasured path would only add resident memory to the RSS column.

## Tiers

| tier | scenarios | engines | repeats | runs on |
| ---- | --------- | ------- | ------- | ------- |
| smoke | `vless-raw-down-1` (128 MiB probe window) | ferrox, xray-core | 3 | every PR, ubuntu only |
| standard | all rows above | all five | 3 | weekly schedule + dispatch, all runners |
| full | standard plus 16-flow ladders, churn when the knob lands | all five | 5 | dispatch only, all runners |

Repeats below three are not read (`stats::MIN_RUNS`): below two usable pairs a ratio has no interval at all, which is `unproven` rather than a pass.

## Runners

One native runner per OS/ISA the harness can sample: `linux-x86_64`, `linux-aarch64`, `macos-aarch64`. A throughput number is a number about a CPU, and a ratio measured on Neoverse and not on Firestorm is a ratio measured on one machine. Bundles are per runner (`results/<date>/<runner>/`), charts per runner (`charts/latest/<runner>/`), and the README shows one section per runner.

Windows is not in the set: a Windows leg would publish empty CPU/RSS columns as if they were measurements. The Win32 sampler in [`../methodology.md`](../methodology.md) is the knob that earns the fourth runner.

## Refresh

The weekly schedule measures the standard tier on all three runners and pushes the dated bundles, the charts and the README update to `main` directly: a benchmark whose front page waits on a manual merge is a claim without a date. Dispatch runs only prove (artefacts, no publish), because publishing a hand-picked tier as the standing benchmark would mislabel it. A week in which any runner is red publishes nothing rather than a subset.

## Honesty rules

They are the same rules as the gates, restated for plots: every cell runs at least three repeats; every ratio is a median with a 95% interval; a verdict needs the whole interval beyond 5% on one side; an `unproven` row is reported, never gated; an empty cell names its reason; every bundle carries binary digests, host, CPU, memory, load, versions and the replay command; `validate-benchmark-matrix.py` re-derives every aggregate from the raw cells and fails on disagreement; result bundles are dated and immutable, the README shows the latest per runner with its date.
