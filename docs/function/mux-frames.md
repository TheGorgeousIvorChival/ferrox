# `ferrox_core::mux`

Many logical streams inside one proxy stream, and the sessions on it.

## Why this rung and not another

It is the one connection method Xray-core, sing-box and `PattNG` all carry that this workspace had none of — and the one that **multiplies** the rest. Rows 1-10 of the superset matrix are each one way to reach a server; multiplexing puts many conversations inside one of them, so it composes with every row rather than competing with it. Landing it turns ten rows into ten families, which is why it is row 11 and not row 2.

xray-rust, the fourth implementation this project compares against, has no mux at all: it rejects `{"mux": {"enabled": true}}` at config-parse time. A refusal is the shape this gap had here until now, and a worse one — a cell in a matrix that reads as "measured, unsupported" where a working codec would read as a row.

## The format

```text
frame  := meta_len:u16be  meta[meta_len]  [ len:u16be  payload[len] ]
meta   := id:u16be  status:u8  option:u8  [ext]
```

`meta_len` counts the metadata and nothing else: not itself, not the chunk. Four bytes of it are fixed, so `meta_len == 4` is a frame with no address in it. `option` is a bitmask — bit 0 says a chunk follows, bit 1 says a sub-stream ended in error. `status` decides what `ext` may be, and nothing else does:

| status | `ext` |
| - | - |
| `New` (1) | `network(1) port(2) atyp(1) addr`, then one of: nothing, eight bytes of NAT identity on a UDP frame, or a reverse-mux bridge's source and local addresses |
| `Keep` (2) | nothing, or `network port atyp addr` again when a datagram brought its own destination — recognised by the network byte being `0x02` |
| `End` (3) | nothing |
| `KeepAlive` (4) | nothing, optionally followed by one chunk to discard |

`network` is `0x01` for `TCP` and `0x02` for `UDP`. The address field is [`crate::addr`]'s and the port sits immediately before the family byte — in this format and in `VLESS`'s, which is why one codec serves both.

## One worked frame, byte by byte

`New`, `TCP`, `example.com:80`, session 1, payload `abcd`:

```text
00 14 | 00 01 | 01 | 01 | 01 | 00 50 | 02 | 0b | "example.com" | 00 04 | "abcd"
^^^^   ^^^^^^   ^^   ^^   ^^   ^^^^^^   ^^   ^^   ^^^^^^^^^^^   ^^^^^^   ^^^^^^
20     1       New  DATA TCP  80       dom  11   11 bytes      4       payload
```

The 20 is the only number with any freedom in it, so it is the one worth doing out: two for the id, one for the status, one for the option, one for the network, two for the port, one for the family, one for the domain's own length, and eleven for the domain — twenty. The payload's length sits *after* the metadata and is counted by neither, which is why one length in hand is enough to read a frame. That vector is `NEW_DOMAIN` in `mux::tests`, written out from this table and not from the encoder that produces it.

## What each of the four implementations does here

| | frames | sessions | cost per frame |
| --- | --- | --- | --- |
| **Xray-core** `common/mux` | six copies of the address codec in one file; `meta_len` bytes copied into a fresh pooled 8 KiB buffer; a *second* pooled 8 KiB buffer per address, up to three per `New`, to pull ≤18 bytes through three reads; a third 8 KiB buffer per frame header of which 8-40 bytes are used, each becoming its own `writev` iovec; a 2-byte heap slice for the chunk length, both sides | `map[uint16]*Session`; a `u16` counter that wraps at 65536 and overwrites a live session with id 0; no server-side concurrency limit at all | 6 heap allocations, 2-4 pooled-buffer round trips, 4-6 O(n) `Len()`/`IsEmpty()` passes |
| **sing-box** `common/mux` | does not frame at all: delegates to a third-party stream multiplexer and adds a session handshake, a padding layer and a bandwidth exchange on top, in three wire protocols | third-party session table | whatever the delegated multiplexer costs, plus three layers |
| **xray-rust** | none; `mux.enabled = true` is a config error | — | — |
| **`PattNG`** | none of its own; writes Xray-core's four config fields | — | — |

## What replaces it

One pass over a borrowed slice in each direction. No allocation on either side, no copy of the metadata, and a metadata length computed in exactly one place — `Outgoing::meta_len` — with `encode_into` writing the number that function returns rather than back-patching a length after the fact the way upstream does.

`Sessions<T>` is the map that needs no hash. Ids are dense, monotonic and bounded by the concurrency cap, so upstream's hash is a function of a value handed out in order; this is a power-of-two table sized once from the cap, linear probing, the key compared as part of the probe. The important part is that **the id a peer sends is a key and never an index** — which is what makes the table's size a function of the cap rather than of the sixteen-bit id field. An id-indexed array would have to grow to 65536 slots because of one frame, and a test says so.

## Three upstream shapes that are not reproduced

They are bugs the format does not require, and each is now a named test rather than a comment:

| upstream | what it does | here |
| --- | --- | --- |
| `u16` session counter | wraps at 65536 and overwrites a live session with id 0; only the concurrency cap stands between a long-lived connection and that | `Ids` counts in `u32` and **refuses** at the last id — `ids_are_handed_out_once_each_and_refused_rather_than_wrapped` walks all 65535 |
| writer emits `meta_len` up to 781, reader rejects above 512 | a reverse-mux peer with long domains is disconnected by the reader for a frame its own writer made | `META_MAX` is 781 and is accepted — `a_frame_that_claims_more_than_the_format_holds_is_refused` |
| the `New` encoder's network-byte `switch` has no `default` | a target that is neither `TCP` nor `UDP` is written with **no network byte at all** | `Target::network` is an `Network`, so the frame is unrepresentable rather than guarded |

And one that is a hardening rather than a fix: upstream never checks whether an id is already live, so a peer that reuses one silently orphans the stream behind it. `Sessions::open` hands the displaced session back to the caller.

## What is left out, and why that is a subset

- **Reverse mux.** *Reading* one is four lines, so a peer that sends one is framed correctly instead of dropped. *Emitting* one is a bridge feature this core has no use for, and `Outgoing` cannot express it. `Incoming::to_outgoing` states the decoder's strict superset of the encoder as code rather than as a sentence.
- **`KeepAlive` frames.** Never written by any of the four — receive-only — and named here only so the reader handles one.
- **The NAT session map.** Eight bytes of a `New` frame's identity are carried because they are part of the frame; the global map that turns them into a reusable UDP association, with its sixty-second expiry, belongs to a UDP path this crate does not own.
- **Worker pools, round-robin pickers, backpressure pipes.** Runtime, not framing. `Ids` and `Sessions` are the bookkeeping a runtime needs and nothing more.

## Verification status

| claim | checked by | verdict |
| --- | --- | --- |
| the frame bytes are the format's | `mux::tests`, `NEW_DOMAIN` and nine others written out from the table above with their arithmetic shown; a dense round trip over all 256 domain lengths | green in `cargo test` |
| the decoder is a superset of the encoder | `the_decoder_reads_a_superset_of_what_the_encoder_writes` and `Incoming::to_outgoing` returning `None` for the one shape the encoder cannot write | green in `cargo test` |
| no allocation, no copy | `bench.yml` gate 6, the counting global allocator, on both sides | **no CI verdict yet** — the workflow has not run at this commit |
| not slower on the four gated decode rows | `bench.yml` gate 6, run `37242106411`: **1.52x–2.71x** on all four runners | green — the run is the verdict |
| not slower on the encode and bridge-decode rows | run `37242106411`, **not gated**, because on both one side does not hold still across the four runners. Encode: the reference moves 1.98x for the same twenty-byte frame (8.5–16.8 ns) where this side moves 1.23x (9.4–11.6 ns), faster than the code under test on one runner and slower on three — a ten-nanosecond ratio is settled by inlining. Bridge decode: the mirror image, *this* side moves 2.2x (16.3–35.1 ns) where the reference holds 1.14x (29.7–33.9 ns). Every row still asserts field-for-field identity and zero allocations on both sides; [`../claims.md`](../claims.md) records the decision |
| Miri interprets it | `safety.yml` runs `cargo miri test -p ferrox-core`, which reaches `mux::tests` | **no CI verdict yet.** `main`'s last verdict is FAIL (`d6b1647`, 2026-10-04) and was measured on a tree without this rung; the module is safe Rust with no `unsafe`, so the exposure is a panicking index rather than undefined behaviour — which is not a Miri result |
| interop with a real peer | **no checker** | see below |

### The gap that is not closed, and why it cannot be closed here

**No upstream suite can gate this rung, and the reason is measured per suite in [`../conformance.md`](../conformance.md)**: Xray-core's `common/mux` tests are in-process Go with no environment seam, so no Ferrox binary can be injected; sing-box has no `_test.go` at all under its mux paths because the framing lives in three out-of-tree modules; xray-rust's coverage is a config-parse rejection.

That leaves **no pinned same-language oracle for this format**, which is the same position gate 4 is in and is stated the same way: `muxframe.rs`'s header says in terms that its reference is *structural* — built to the shape upstream has, not built from upstream — so the identity half of this rung is the hand-derived vectors above and the gate contributes only the cost half. A reader who reads only the ratio table would otherwise credit the rung with a differential it does not have, which is why `muxframe.rs` repeats the disclaimer in the report text as well as in its own header.

### Licence

A frame layout is a wire format, not an implementation. No Xray-core, sing-box, xray-rust or `PattNG` line or test enters this tree; every golden vector is spelled out from the format with its arithmetic shown so a reviewer can check it against the pinned upstream by eye. The same note is on `crate::vless` and `crate::addr`.
