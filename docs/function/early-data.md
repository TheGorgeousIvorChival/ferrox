# `ferrox_core::transport::EarlyData`

`?ed=N` on a `ws` or `httpupgrade` path: the layer above's first write, spent inside the upgrade handshake.

## Why this rung and not another

It is the one connection method **Xray-core and sing-box both carry that this workspace had none of**, and the only one with **two upstream oracle tests already written that fail here**:

| upstream test in `xray-rust`'s `local_xray_interop_tests` @ `7a4fb2dd` | before |
| --- | --- |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_ws_early_data` | ❌ `read echo failed: early eof` |
| `rust_socks_client_reaches_echo_server_through_local_xray_vless_httpupgrade_early_data` | ❌ `socks connect rejected: [5, 1, 0, 1]` |

Both are in [`../conformance.md`](../conformance.md)'s table of what each suite is missing, both were owned by the early-data slice that shipped them, and both failed for the same reason: **the configured path kept its `?ed=2048` and no `ws` or `httpupgrade` server anywhere matches a request whose path has no query in it.** `Xray-core` strips the key in its config parser (`infra/conf/transport_method.go:620-628` and `:669-677`); nothing here did.

Every other gap in the matrix is either much larger (`Hysteria2`, `MASQUE`, QUIC) or has no oracle to prove it (`type=http`, `type=kcp` — Xray-core removed both at its pin and no pinned suite speaks them). This one has a wire format, a proof and a benchmark, and it is one mechanism wearing two carriers.

## The setting

```text
path   := base [ "?" query ]
query  := pair[ "&" pair ]
pair   := "ed=" budget | anything-else
```

A client that sends it puts its **first write** in the handshake, as unpadded base64url in `Sec-WebSocket-Protocol`, and sends no frame for those bytes:

```text
GET /interop-ws HTTP/1.1
Host: oracle.example
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: <standard base64, padded>
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: <the first write, base64url, unpadded>

```

`N` is the whole budget and the boundary is inclusive. **Nothing is truncated**: a first write longer than `N` travels in a frame and early data is off for the rest of the connection. `0` is not a budget of zero bytes — it is the setting off.

Two base64 alphabets are in that one handshake, which is the trap: `Sec-WebSocket-Key` is standard base64 **with** padding, and the bytes beside it are url-safe **without**.

### The number, exactly

`Xray-core` writes `ed = uint32(strconv.Atoi(v))` and throws away `Atoi`'s error, so three different answers come out of one expression, and a peer that built its path with any of them is talking to us:

| `ed=` | budget | why |
| --- | --- | --- |
| `2048` | 2048 | the ordinary case |
| `+2048`, `002048` | 2048 | `Atoi` takes a sign and leading zeros |
| `abc`, `2048x` | 0 | `ErrSyntax` ignored |
| `-1` | 4294967295 | **not** refused: `uint32(-1)` is 2³²−1, a budget of four gigabytes |
| `4294967296` | 0 | the `uint32` conversion truncates |
| `99999999999999999999` | 4294967295 | `ErrRange` ignored, so the saturated bound, then truncated |
| *(absent)*, `ed=`, `ed` | 0, **and the path is untouched** | the `if u.Query().Get("ed") != ""` guard skips the rewrite entirely |

The last row looks like a bug and is not. `ed=abc` still *leaves* the path, because the guard tests the value being non-empty and not whether the number parsed — so an unparsable budget produces exactly the same rewrite as a parsable one, and a path that kept the key could never be served. All of it is `EarlyData::split` and `atoi`, with every row above a vector in `transport::tests`.

### Why the path has to lose `ed`

Both servers compare a request's `URL.Path` — which has no query — against the configured path, so `ed` is the only query key that can be there at all: any other surviving key leaves a path that `Xray-core`, `ZeroNet` and this tree all refuse. That is also why an empty pair is dropped rather than kept, and why the surviving pairs keep the order they were written: `Xray-core` re-encodes them through `url.Values.Encode`, which also sorts them, and the one input where sorted and written order differ is a path no peer serves.

## What each of the four implementations does here

| | `?ed=` read from | budget rule | where the digits go | cost per handshake |
| --- | --- | --- | --- | --- |
| **Xray-core** `b26a91de` | `url.Parse` + `Get`/`Atoi`/`Del`, **spelled twice** — `WebSocketConfig.Build` and `HttpUpgradeConfig.Build` | first write ≤ `N`, else dropped for the connection; no truncation | `base64.RawURLEncoding.EncodeToString` into a `header` map that `GetRequestHeader()` builds per dial | one `String` for the digits, the request `bytes.Buffer`, and the browser-masquerade header map — a fresh map per connection |
| **sing-box** `c9922979` | a **config field** (`max_early_data`, `early_data_header_name`), which no share link can spell | **truncates**: `content[:max]` early, `content[max:]` late | `EncodeToString`, then either `requestURL.Path += …` (a new URL string) or `headers.Clone()` and `Set` | one `String`, plus a URL re-allocation or a whole header-map clone; the payload is sliced, not copied |
| **xray-rust** `7a4fb2dd` | `split_early_data_from_path`, **spelled twice** — `parse_websocket_settings` and `parse_httpupgrade_settings` | first write ≤ `N`, else disabled; **refuses `ed` on `httpupgrade` outright**, with the reason in its own parser warning | `input.to_vec()` → `encode_early_data` → `String` → `serialize_request` → `Vec` | **three buffers and two copies of the payload** for one header line |
| **`ZeroNet`** `97a99734` | `extract_early_data`, one `strip_prefix("ed=")` loop; last `ed` wins, empty pairs dropped, `ed=` empties the key | first write ≤ `N`, else written normally afterwards | `URL_SAFE_NO_PAD.encode(early_data)` → `String`, then `format!("Sec-WebSocket-Protocol: {encoded}\r\n")` → a second `String`, then `push_str` | **two allocations and two copies** — and it is Rust |
| **`PattNG`** | none of its own; configures Xray-core's | — | — | — |

The three Go trees agree on the wire and disagree on the boundary: `Xray-core` and `xray-rust` drop early data for the connection when the first write is too long, and `sing-box` sends the first `N` bytes and the rest as a frame. `Xray-core` is the reference this tree is bit-identical to, so the drop-and-disable rule is the one implemented.

## What replaces it

One buffer, built once, written once.

- **The parse is spelled once.** `EarlyData::split` is called from both carriers. `Xray-core` writes the same `url.Parse`/`Get`/`Del`/`Encode` block twice and `xray-rust` writes its version twice; `sing-box` avoids the problem by not reading a query at all, at the cost of a setting no share link can express.
- **The digits are appended to the request, not built beside it.** The upgrade request is one `String` this module was making anyway; the early-data line is appended to its own tail with the final `\r\n\r\n` trimmed off and put back. Every implementation builds a second string and copies the digits in, and two of them copy the payload in first.
- **The payload is never copied at all.** The budget is decided by reading the caller's slice — `first.len() <= budget` — and the digits are encoded from that same slice. `Xray-core` aliases it, `xray-rust` copies it into a `Vec`, `sing-box` splits it into two slices.
- **`httpupgrade` gains no code.** On that carrier `ed` moves no bytes: `Xray-core` uses it only to return from `Dial` before the `101` arrives, and `xray-rust` declines to do even that because the peer's `bufio.Reader` strands whatever arrived with the request. So the path still loses `ed` — which is the whole of what makes the row servable — and the request builder has no branch on the setting, asserted by `an_early_data_budget_leaves_the_request_unchanged`.
- **One walk of the head instead of two.** The server read `Sec-WebSocket-Protocol` once to decode it and again to echo it. Now it reads it once.

Three copies of the header walk and two of the request-path walk came out of `ws.rs` and `httpupgrade.rs` and are now one of each in `proxy.rs`, beside the `read_http_head` already shared. `xhttp.rs` still keeps its own header walk; that is P30 rather than fixed here, because its rows have a gate of their own.

## Verification status

| claim | checked by | verdict |
| --- | --- | --- |
| the `?ed=` rewrite is `Xray-core`'s | `transport::tests::early_data_split_matches_go_arithmetic`, 22 vectors over the guard cases, the number's three answers, the `uint32` truncations and the fragment | green in `cargo test` |
| the digits are `RFC 4648`'s | `transport::tests::early_data_base64url_matches_rfc_4648` and `…round_trips_every_length` — the `f`…`foobar` vectors, the two digits the url alphabet exists for in both group shapes, and every length 0–192 round-tripped both ways | green in `cargo test` |
| a budget adds one header line and changes nothing else | `ws::tests::early_data_adds_one_line_and_truncates_nothing` — the request without the line is the request with it minus that line, and the boundary is checked on both sides of it at three payload sizes | green in `cargo test` |
| the budget's bytes reach a server, with and without one that fits | `ws::tests::early_data_reaches_the_server_with_and_without_a_budget_that_fits` over `ed=2048`, `ed=4` and `ed=3` against `accept` | green in `cargo test` |
| a configured budget serves the bare path | `ws::tests::a_configured_budget_serves_the_bare_path`, `httpupgrade::tests::a_configured_budget_serves_the_bare_path` | green in `cargo test` |
| `ed` moves no bytes on `httpupgrade` | `httpupgrade::tests::an_early_data_budget_leaves_the_request_unchanged` at four budgets including `0` and 2³²−1 | green in `cargo test` |
| **under one allocation per encode**, where the reference's shape allocates two | `bench.yml` gate 8, the counting global allocator over 64 encodes: this side held under one per encode and the reference at two or more, both printed on every row. **The bar is deliberately not zero**: a release bench from `main()` with nothing else running reads 6 allocations / 8064 bytes in the window and **1 allocation of 8192 bytes** in a second identical window, and an 8 KiB block is not a `String` this code builds | green in run `37251890402`: **6 here against 128, 256, 256 and 256** at 8/120/256/2048 B — the same six at every payload length, which is what says they are not the encode, since a per-call allocation would scale with the payload and the reference's does. P32 owns finding the 8 KiB block |
| not slower than `ZeroNet`'s shape | `bench.yml` gate 8, four rows at 8/120/256/2048 B, each asserting the finished header line is equal and decodes back before either side is timed | green in run `37251890402`: no row under the 0.95x bar. **The four ratios are in `target/bench-report.md` and are not transcribed here**, because `bench.yml` on four native runners is the run that publishes them |
| interop with a real peer | **two upstream oracle rows**, `conformance.yml` → `upstream/pins.toml`'s `xray-rust` suite, unmodified, against real `Xray-core` at the pin | green in `conformance.yml` run `37249695646`: `running 7 tests` … `7 passed; 0 failed; 23 filtered out`, then `PASS: xray-rust suite green against ferrox-app`. The `zeronet` suite stayed green beside it, `8 passed` |

### Why the identity half is a conformance row and not a reference

**This is not a differential against a pinned in-process oracle.** The four implementations cannot be run in-process to hand a `String` back to this binary, and [`../conformance.md`](../conformance.md) measures that per suite. What *is* pinned and does run is `conformance.yml`, and for this rung it is a stronger claim than a gate could be: two tests written by someone else, naming a wire format, executed against `Xray-core` at its pin with this binary in the middle.

That is why gate 8 is built against `ZeroNet`'s shape rather than a Go one even though the setting came from `Xray-core`: `ZeroNet` is the implementation `ferrox-app` replaces, the one whose oracle suite runs against this binary, and the one whose `extract_early_data` this parse is measured against — same language, so the ratio is about the code rather than about the languages.

## What is left out, and why that is a subset

- **`early_data_header_name`.** `sing-box`'s alternative spelling of the same channel, for a deployment that cannot use `Sec-WebSocket-Protocol`. It is a *different header*, so serving it is serving a second wire format for the same idea, and nothing in the matrix needs it.
- **Early data in the *path*.** `sing-box`'s default appends the digits to the configured path instead of sending a header. `Xray-core` does not read that, so a `ws` client that used it would fail against every other server in the matrix.
- **The deferred handshake.** `Xray-core` holds the socket back until the first write, and `xray-rust` reproduces that with a `JoinHandle` and a parked reader. Here the caller already has the bytes — a `VLESS`, `VMess` and `Trojan` request header is all built before the carrier is dialled — so they are passed in and the state machine is one argument instead of a deferred writer, a mutex-held `Option` and a reader that has to wait for a dial that may not have happened.
- **A server-side budget.** `Xray-core`'s server accepts any `Sec-WebSocket-Protocol` that decodes, and so does this one; sing-box's `maxEarlyData` bounds its *path* form only.

### Licence

A header name and an alphabet are a wire format, not an implementation. No Xray-core, sing-box, xray-rust, `PattNG` or `ZeroNet` line or test enters this tree; every vector is spelled out from the format with its arithmetic shown, and the upstream oracle tests stay in their own suite and run from their pin.