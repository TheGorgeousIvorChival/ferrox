# Benchmarks: the five-engine matrix

Every number here was measured in CI on a named runner, from pinned binaries, with repeats. Nothing was typed by hand: the charts and the README tables are rendered from `matrix-results.json`, and the validator re-derives them before any refresh lands.

## What is measured

[`matrix.md`](matrix.md) is the catalog: bulk throughput up/down/duplex, setup stages, peak RSS and threads, cold start, the harness ceiling, the coverage grid, and release binary sizes. Each cell runs at least three repeats over an 8 GiB window; every ratio is a median with a 95% interval; a verdict needs the whole interval beyond 5% on one side; anything unmeasured is `unproven`, never a pass; an empty cell names its reason. `matrix.md`'s mapping table says, for every chart ZeroNet and xray-rust publish, where it lives here — or the knob that would earn it one.

## How to reproduce

```sh
./scripts/run-benchmark-matrix.sh --tier standard --out /tmp/matrix
python3 scripts/render-benchmark-charts.py --input /tmp/matrix --charts /tmp/matrix/charts --results /tmp/matrix/matrix-results.json
python3 scripts/validate-benchmark-matrix.py --cells /tmp/matrix/cells --results /tmp/matrix/matrix-results.json --charts /tmp/matrix/charts
```

Tiers: `smoke` (one scenario, two engines, minutes — the PR signal), `standard` (weekly, all runners), `full` (16-flow ladders and everything behind a knob that does not exist yet).

Narrow a run without editing anything: `--only vless-raw`, `--exclude tls`, `--probe-only` (write every engine config and list the cells without moving traffic), `--engines`, `--repeats`. The manifest records every override, so a narrowed run cannot read as the whole matrix. Charts need `pip install -r scripts/requirements-benchmark.txt`; without it the run produces every number and no images.

## Results

Dated, immutable bundles live under `results/<date>/`, one directory per runner (`linux-x86_64`, `linux-aarch64`, `macos-aarch64`), each with `matrix-results.json`, `manifest.txt`, `commands.sh`, `cells/` and its charts. Per-runner charts also live under `charts/latest/<runner>/`, which is what the README embeds. The main README shows the latest bundle per runner with its date; history is never overwritten. The weekly schedule pushes the refresh to `main` directly; dispatch runs upload artefacts and publish nothing.

Three repeats is the floor worth reading: below two usable pairs a ratio has no interval at all, which is `unproven` rather than a pass (`stats::MIN_RUNS`).

## Live speedtest (dispatch-only, never in the README)

[`live-speedtest.md`](live-speedtest.md) is the road test to this page's laboratory: paste `vless://` links as a dispatch input and each core dials each link in turn, downloading one static file through its own tunnel while the runner samples CPU and RSS. Sequential, redacted, ungated — and never copied here, because live numbers decay the moment the server or the route changes.
