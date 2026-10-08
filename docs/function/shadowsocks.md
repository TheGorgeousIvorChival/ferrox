# Shadowsocks AEAD

The one method in this tree whose *whole* job is framing, so it is the rung
where the copies and the syscalls were easiest to remove.

A TCP chunk is `seal(2-byte length)` then `seal(payload)`, each with its own
16-byte tag, both under one per-direction nonce counter derived by HKDF-SHA1
from an MD5 chain over the password. That is SIP004, and the two seals per
chunk are not an implementation choice — a peer must not be able to tell which
chunk length we claim until after it has opened the length itself.

The AEAD sits on [`ferrox-core`'s own ChaCha20-Poly1305](../../crates/ferrox-core/src/aead.rs)
and, for `aes-128-gcm`/`aes-256-gcm`, on [our AES-GCM ladder](../../crates/ferrox-core/src/aesgcm/mod.rs).
`xchacha20-ietf-poly1305` derives a per-chunk subkey with HChaCha from the first
sixteen extended-nonce bytes and seals with the same IETF AEAD over an inner
nonce of four zero bytes plus the last eight. Neither takes a pointer to a scratch buffer: `seal_into` writes the plaintext
into the caller's buffer and encrypts it where it lies.

## Data path

```mermaid
graph TD
    A["plaintext read, 16 KiB<br/>one read syscall"] --> B["chunks of 16383 B<br/>a 16 KiB read is 2 chunks"]
    B --> C1["seal length, 2 B"]
    C1 --> C2["seal payload, 16383 B"]
    C2 --> D1["seal length, 2 B of the tail chunk"]
    D1 --> D2["seal payload, 1 B"]
    D2 --> E["one staging buffer<br/>copies of payload: 1 each"]
    E --> F["write_all, one write syscall"]
    F --> G(("wire"))
    H["wire, one read syscall per 18 B<br/>then one per size+16 B"] --> I["open the length chunk in place"]
    I --> J["read the payload chunk into<br/>the connection's own buffer"]
    J --> K["open in place, zero copies"]
    K --> L["write_all to the target"]
    M["wire datagram"] --> N["salt to the subkey, one copy in"]
    N --> O["open in place in the socket thread's<br/>own buffer, no allocation"]
    O --> P["payload is a subslice of that buffer:<br/>memmove 0, no third copy"]
    P --> Q(("target"))
```

## Measured

Every row is a claim with a checker that runs. `scripts/method-counts.txt`
holds the same rows and `scripts/check-method-docs.sh` fails if this page and
that file disagree.

<!-- counts:begin -->
| key | value | checked by |
| --- | --- | --- |
| ops-retired-instructions | UNBLESSED | scripts/count-ops.sh |
| aead-calls-per-chunk | 2 | ferrox-core-shadowsocks::tests::every_method_round_trips_a_chunk_and_refuses_a_forged_tag |
| maximum-payload-per-chunk | 16383 | ferrox-core-shadowsocks::tests::every_method_round_trips_a_chunk_and_refuses_a_forged_tag |
| write-syscalls-per-16KiB-relay-read | 1 | ferrox-app-shadowsocks::tests::one_relay_read_becomes_one_write_and_reads_back_whole |
| payload-chunks-per-16KiB-relay-read | 2 | ferrox-app-shadowsocks::tests::one_relay_read_becomes_one_write_and_reads_back_whole |
| user-space-copies-per-byte-written | 1 | ferrox-app-shadowsocks::tests::one_relay_read_becomes_one_write_and_reads_back_whole |
| user-space-copies-per-byte-read | 0 | ferrox-app-shadowsocks::tests::chunks_open_that_seal_sealed_and_reject_damage |
| zero-filled-bytes-per-chunk | 0 | ferrox-app-shadowsocks::tests::chunks_open_that_seal_sealed_and_reject_damage |
| chunk-buffer-allocations-per-connection | 1 | ferrox-app-shadowsocks::tests::chunks_open_that_seal_sealed_and_reject_damage |
| udp-payload-copies-per-byte | 1 | ferrox-app-shadowsocks::tests::an_opened_payload_is_the_datagrams_own_bytes |

| udp-datagram-reallocations-after-the-first | 0 | ferrox-app-shadowsocks::tests::an_opened_payload_is_the_datagrams_own_bytes |

| udp-payload-passes-through-the-returned-buffer | 1 | ferrox-app-shadowsocks::tests::an_opened_payload_is_the_datagrams_own_bytes |

| chunk-tag-copies-per-chunk | 0 | ferrox-core-shadowsocks::tests::every_method_round_trips_a_chunk_and_refuses_a_forged_tag |

| datagram-memmoves-per-payload | 0 | ferrox-app-shadowsocks::tests::an_opened_payload_is_the_datagrams_own_bytes |
<!-- counts:end -->

## Ops

```bash
./scripts/count-ops.sh report \
  shadowsocks::tests::one_relay_read_becomes_one_write_and_reads_back_whole \
  'shadowsocks::seal_all'
```

The row above is `UNBLESSED`: nobody has read a measured number for this
symbol out of a callgrind run, so this page does not state one. `scripts/expected-ops.txt`
still blesses exactly one symbol, `der_to_pem`. Blessing a count means reading
the diff that moved it, never copying a measurement to silence a gate.

## Time

**Not measured on this branch.** Wall clock for this method comes from
`ferrox-bench` gate 9 (`crates/ferrox-bench/src/ciphers.rs`), which seals the
same chunk lengths with the same four methods and compares bytes and
allocation counts against the pinned reference. `.github/workflows/bench.yml`
runs it on `linux x86_64`, `linux aarch64`, `macos aarch64` and
`windows x86_64` and publishes `target/bench-report.md` as an artefact. No
artefact from a run of this branch has been read, so this page quotes no
duration. Timing needs a named runner; a number from a laptop behind a VPN
measures the tunnel.

## What we removed

Read against the three pinned implementations, all of which are in
`upstream/` for reading and never copied:

- **Write syscalls, 4 to 1 per relay read.** Xray-core's
  `common/crypto/auth.go` seals each chunk into its own pooled 8 KiB buffer and
  hands the batch to `WriteMultiBuffer`, which coalesces with `writev`; but its
  *stream* path is entered once per `WriteMultiBuffer` call and takes a fresh
  `temp := buf.New()` scratch each time, so the batch size is the pipe's read
  granularity rather than a number chosen for syscalls. sing-box delegates the
  whole cipher to the out-of-tree `sagernet/sing-shadowsocks2`
  (`protocol/shadowsocks/outbound.go:15`), so what it batches is not readable in
  this pin and no threshold is claimed here. Zray sets
  `MAX_WRITE_BATCH = 4 × 16383` and
  drains once per batch. This tree seals the whole 16 KiB relay read, both
  seals of every chunk, into one buffer sized exactly for it by
  `staging_room`, and issues one `write_all`. The wire bytes are the same
  stream in the same order.
- **A zero-fill of up to 16 KiB per chunk read.** The reader used to do
  `chunk.resize(size + TAG_LEN, 0)` and then overwrite every byte of that range
  from the socket. The buffer is now sized once per connection (`wire_buffer`)
  and each read writes into a prefix of it, so nothing is re-zeroed after the
  first connection.
- **The read-side copy.** `Cipher::open_in_place` decrypts inside the caller's
  buffer and returns a subslice of it, so the read path moves a payload byte
  zero times in user space. Zray also decrypts in place, inside one reusable
  `ReadBuffer`; Xray's `readBuffer` path allocates a fresh `buf.Buffer` per
  chunk (`auth.go:137`) and, above the chunk padding, merges into a whole new
  `MultiBuffer` with `buf.MergeBytes` (`auth.go:202`), which is a second copy
  and a whole new `MultiBuffer` per chunk.
- **A branch per chunk length.** `open_chunk` refuses on
  `size + TAG_LEN > chunk.len()`, which for the one buffer size this method
  allocates is exactly the `size > MAX_CHUNK` check it replaced, without
  needing a second constant to stay honest.
- **A second vector path for the extended nonce.** HChaCha runs once per chunk
  as scalar integer math in `chacha::hchacha`; the payload still goes through
  the same AVX2/NEON/portable `Lanes` ladder as every other ChaCha chunk, so
  no second transpose and no second store exist. The subkey and the inner nonce
  live on the stack, and the method dispatch is one `match` on `Aead`, hoisted
  out of the per-byte loop rather than a string compare per chunk.
- **Two of the three copies every UDP payload made.** `open_udp_datagram` took
  the datagram's sealed tail with `to_vec` (a `malloc` plus a full `memcpy`),
  opened the AEAD in place, then `copy_within(used..len, 0)` moved the whole
  payload down to offset zero so the caller could hand it on — and the caller
  copied it a third time into its reply buffer. The salt and the address header
  both precede the payload, so one copy in is unavoidable; the `memmove` and the
  allocation were not. `Datagrams` now holds one `opened` and one `sealed`
  buffer per socket thread and returns `&opened[used..len]`, so the payload is
  a subslice of the buffer the datagram was opened in. The same holds for
  sealing: `seal_udp_datagram` allocated a fresh `Vec` per datagram, and the
  buffer is now the thread's own.
  `an_opened_payload_is_the_datagrams_own_bytes` is the gate — it asserts the
  returned pointer lies inside `opened`, and that `opened` neither moves nor
  grows over eight rounds, using the same pointer-identity idiom as
  `frames_reuse_the_callers_buffers`.
- **A 16-byte tag copy per chunk.** `Cipher::open_in_place` split the tag off
  with `split_at_mut` and then built a `[u8; TAG_LEN]` on the stack to pass by
  reference. It now borrows the sixteen bytes that are already there, which is
  the shape `vmess.rs` already used. Small next to the AEAD, but it is one
  `memcpy` per chunk and it is gone.
- **A second 16 KiB buffer alive for the whole connection.** The server's first
  chunk buffer was shadowed by the slice borrowed out of it, so it stayed live
  until the function returned while `pump_relay_carried` allocated its own;
  every Shadowsocks connection held 32 KiB where it needed 16. Both handoff
  paths now drop the head buffer once the address has been forwarded.

What is **not** removed, and is named rather than claimed: `2022-blake3-aes-128-gcm`,
`2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` and `rc4-md5` still
parse to `None` and are refused by name (`a_method_outside_the_rung_is_refused`
is the gate); the 2022 family needs a BLAKE3 key schedule this tree does not
carry, and `rc4-md5` stays refused because it is broken rather than missing.

## Pins

| what | where |
| --- | --- |
| AEAD chunking | `upstream/xray-core/common/crypto/auth.go`, `chunk.go` |
| AEAD chunking, delegated out of tree | `upstream/sing-box/protocol/shadowsocks/outbound.go` |
| AEAD chunking | `upstream/zeronet/crates/zero-protocol/src/shadowsocks.rs` |
| XChaCha AEAD, 32-byte salt | `upstream/xray-core/proxy/shadowsocks/config.go` |
| XChaCha spellings | `upstream/sing-box/option/shadowsocks.go` |
| method spellings, MD5 chain, HKDF info string | `ferrox-core-shadowsocks` |