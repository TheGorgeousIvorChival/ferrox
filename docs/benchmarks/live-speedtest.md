# Live speedtest: your configs, every core, one file

`speedtest.yml` is dispatch-only. Paste `vless://` links, name a static file, and each core dials each link in turn and downloads the file through its own tunnel while the runner samples CPU and RSS from outside the process. The report is a job summary plus artefacts — never a README table.

## What it answers

"On this server, over this path, right now, which core moves bytes fastest?" That is an end-to-end number: server plus path plus core, in that order of likely dominance. It is not a core benchmark and it does not become one with more repeats. [`matrix.md`](matrix.md) is the core benchmark; this is the road test.

## How to run it

Actions → speedtest → Run workflow:

| input | default | notes |
| ----- | ------- | ----- |
| `configs` | (required) | one `vless://` per line, `#` comments allowed |
| `target_url` | Hetzner 1GB | any static file; larger is closer to the use case and ruder to the server |
| `target_sha256` | (empty) | expected hash; empty means bytes counted, validation `unverified` |
| `repeats` | 2 | attempts per config per core, sequential |
| `cores` | all five | comma-separated subset to drive |
| `curl_max_time` | 1500 s | one download slower than this is declared stalled |

For the "more than 4 GB" case the request names an Ubuntu ISO with its published hash: `target_url` = `https://releases.ubuntu.com/noble/ubuntu-24.04.3-desktop-amd64.iso`, `target_sha256` copied from that directory's `SHA256SUMS`. Five cores times two repeats of six gigabytes is sixty gigabytes through someone's server — only run that against servers you have permission to load that hard.

## Etiquette, which is load-bearing

Only test servers you have permission to measure. Cores run sequentially, never in parallel, and a stall aborts the attempt (60 s under 10 KiB/s by default) rather than sitting on the server's connection table. Free-server lists are shared infrastructure; a benchmark that reads as an attack is one that gets the runner's network blocked for everyone behind it.

## What each row means

Per config, per core: median MiB/s over the transfer window (total time minus first byte, so setup is excluded the way the matrix excludes it), CPU ms per GiB from `/proc` deltas, peak RSS from VmHWM, time to first byte. A core that never got the file gets `FAILED` with the stage that stopped it — engine exited, SOCKS never listened, curl exit code, short bytes, hash mismatch — or `skipped` with the reason (could not build, no config for the link's transport, or a capability the engine names as unimplemented). A red row is a measurement with a log attached, not an accusation: on a `reality` or `tls` link `ferrox` sits out with the client-handshake rung reason, which is the gap stated, not a surprise. The run stays green whenever attempts were recorded: red rows are the report, and only a run that measured nothing fails.

The two dialects differ in one documented place: `spiderX` has no sing-box field and is dropped from its configs. Certificate verification stays on for `tls` on both: the handshake a user performs is the one measured.

## Secrets

Links arrive as a dispatch input, one `::add-mask::` per line before anything runs. Engine configs necessarily contain the UUID and keys and stay on the runner under `target/live-speedtest/configs/`; downloaded bytes stay under `dl/`; the token list stays under `tokens.txt`. None of the three is uploaded, rendered or echoed. The validator scans every other artefact for the credential substrings and fails the run naming only the file, never the token. Server addresses may appear in connection diagnostics (debugging a failed dial needs to know which server failed); account credentials — UUID, public key, short id — never appear anywhere but the configs.

Prefer short-lived test credentials. A link pasted into a dispatch input is visible to anyone who can see the run's inputs; the report is clean, the input is not.

## Reproduce it

```sh
./scripts/run-live-speedtest.sh --configs-file links.txt \
  --target-url https://example.com/big.bin --repeats 2 --out /tmp/live
python3 scripts/render-live-speedtest.py --dir /tmp/live
python3 scripts/validate-live-speedtest.py --dir /tmp/live \
  --tokens /tmp/live/tokens.txt
```

`--probe` the shapes first without traffic: `ferrox-bench linkconfig --link 'vless://…' --engine sing-box --socks-port 10801` prints the exact document an engine would be handed (redirect it to a file; the terminal is a log too). `--describe --index 3` prints the redacted row label the report will show.
