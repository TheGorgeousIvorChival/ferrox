# `ferrox_core::shadowsocks`

The `AEAD` chunk transport: which ciphers a `ss://` link may name, the keys they imply, and the per-direction state that seals and opens a chunk.

## Why this rung and not another

It is the last row in the matrix where all four implementations are the limiting factor rather than one of them, and the only one where the *set* is the gap rather than a member of it.

| | `AEAD` ciphers it names |
| --- | --- |
| **Xray-core** `b26a91de` | four — `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305` — in three spellings each (`infra/conf/shadowsocks.go:14-27`) |
| **sing-box** `c9922979` | six inbound (`none`, `aes-128/192/256-gcm`, `chacha20-ietf-`, `xchacha20-ietf-`), plus the `2022` trio and eight legacy stream ciphers |
| **xray-rust** `7a4fb2dd` | none — it has no `shadowsocks` implementation |
| **ZeroNet** `97a99734` | three — `aes-128-gcm`, `aes-256-gcm`, `chacha20-ietf-poly1305` (`zero-protocol/src/shadowsocks.rs:42-46`) |
| **here, before this rung** | **one**, compared as a string: `if method != "aes-256-gcm" { return; }` |
| **here** | three, in a table, with every spelling |

`ZeroNet` is the interesting line in that table: it is the core `ferrox-app` replaces, the one whose oracle suite runs against this binary, and it was in exactly the same position. **The intersection of all four is `aes-128-gcm`, `aes-256-gcm` and `chacha20-ietf-poly1305`**, and that intersection is the whole rung.

## What the intersection excludes, and why that is a decision

| excluded | who has it | why not this rung |
| --- | --- | --- |
| `xchacha20-ietf-poly1305` | Xray-core, sing-box | **not in `ZeroNet`**, so it is not what all four name — and it needs `HChaCha20`, which is a primitive rather than a table row. Its own rung, with the pinned `chacha20` crate's `hchacha` as an oracle |
| `aes-192-gcm` | sing-box alone | three implementations' absence is not a gap this rung can close |
| eight legacy stream ciphers | sing-box alone | `rc4-md5` and friends are outbound-only there and were removed upstream long ago |
| `2022-blake3-*` | all three Go trees | **not a cipher choice but a different wire format**: a `keyLen` salt, `HKDF-SHA256` with `2022-blake3-<method>`, a per-chunk key and counter, a pre-shared key, and a keyed `BLAKE3` payload digest. Its own rung |
| `none` | sing-box inbound | a cipher that is its absence |

## The wire format

```text
session := salt[32]  (one direction)   |   chunk*

chunk   := sealed[ len:u16be ][ tag:16 ][ ciphertext[len] tag:16 ]
```

Two details a reading of the cipher list alone would get wrong:

- **The length is sealed as a chunk of its own.** Every chunk costs two `AEAD` invocations and one of them is over two bytes. All four implementations do it; it is not an implementation's choice.
- **Two base64 alphabets, one handshake.** `Sec-WebSocket-Key` is standard base64 with padding; `Sec-WebSocket-Protocol` in the same request is url-safe without. That is row 12's trap and the same shape of trap here: the cipher table has two alphabets' worth of "what encoding is this".

## The two derivations, and the bytes they must not produce

`Xray-core` (`proxy/shadowsocks/config.go:181-207`) derives a session key in two steps, and **each is truncated to the method's key length**:

1. `EVP_BytesToKey` with an empty salt: `MD5(password)`, then while the key is short, `MD5(previous || password)`. Sixteen bytes is **one** `MD5` round and thirty-two is **two**.
2. `HKDF-SHA1` with that as the input keying material, the salt as the salt and `"ss-subkey"` as the info — again truncated to the key length.

Both truncations are load-bearing. The earlier cut derived 32 bytes of master key and 32 bytes of session key for every method, so an `aes-128-gcm` connection did **twice the `MD5` work and threw half of it away**, and — the part that is a correctness bug and not only a cost one — fed `HKDF` a 32-byte input key where the peer's `HKDF` input is 16 bytes. `MasterKey::rounds` returns the count, so "one round against two" is a number a test checks rather than a claim.

## The nonce, and the bug this shape exists to prevent

Twelve bytes, with a little-endian counter in the first eight and zeros in the last four. `SIP004` states that byte order and `Xray-core` reaches the same sequence by filling a buffer with `0xFF` and incrementing it byte-wise from the low end (`common/crypto/auth.go:30-49`).

A **big**-endian counter agrees with that at chunk zero and nowhere else, so a stream built that way completes its first chunk and fails every chunk after it — which reads like a framing bug rather than the byte-order bug it is. The vectors assert chunks 0, 1, 255, 256, 257 and 2³²−1, because 255→256 is where the two orders first disagree.

## `AES-128` is not `AES-256`, and the mistake is a slice

`aes-gcm` is strict: `Aes128Gcm` refuses a 32-byte key and `Aes256Gcm` refuses a 16-byte one, both with `InvalidLength`. This page's first draft claimed the opposite and run `37263819768` answered `InvalidLength`, so the claim is now a test in the other direction: `tests::aes_gcm_refuses_the_other_methods_key_length`.

That is the better shape for the hazard anyway. A loud `InvalidLength` cannot ship; the quiet version is a **slice**. Hold the session key in one 32-byte array and hand every method `&key[..32]`, and an `aes-128-gcm` link is sealed with the `AES-256` schedule — which round-trips perfectly between two endpoints of this tree and fails against every peer, the worst way for it to fail. `Aead` is two `AES` variants so the length is chosen by the method rather than by the slice, and `tests::aes_128_is_its_own_cipher_and_not_a_widened_key` puts this crate's output next to `aes-gcm`'s on the same key, salt, nonce and plaintext for both key lengths.

## Where the pieces live, and why

| | | why |
| --- | --- | --- |
| the cipher table, `key_len`, `MasterKey`, `Cipher` | `ferrox_core::shadowsocks` | this is the wire format, and it is where the proofs are |
| `chacha20-ietf-poly1305` arithmetic | [`ferrox_core::aead`] | already swept byte-for-byte against the pinned `chacha20poly1305` crate at every length, and held to `RFC 8439`'s own vector. **This rung adds no cipher arithmetic**; it routes to the one `VMess` already proves |
| `aes-128-gcm` arithmetic | `ferrox_core::aesgcm` | this crate's own fused engine, swept byte-for-byte against the `aes-gcm` crate and timed against it in gate 10; the crate remains the fallback on machines without the instructions |
| `aes-256-gcm` arithmetic | `aes-gcm` | the crate the `aes-256-gcm` conformance row already proves against real `Xray-core` |
| socket half, address header, relay | `ferrox_app::shadowsocks` | it is a transport, and `mux.rs` is where that lives |

`aes-gcm` and `hkdf` were already `ferrox-core` dependencies. `md5` and `sha1` joined them and were already in the graph through `ferrox-app`, so **no new crate compiles**; `sha1` is added plain, without its `asm` backend, for the reason the `sha2` note in that manifest already gives.

## What it costs, measured

`bench.yml` run `37264964528`, four native runners, five chunk lengths, every row asserting byte-identity before either side is timed. The `aes-128-gcm` row is from when it also ran the crate; it now runs `ferrox_core::aesgcm`, and gate 10's run `37316533412` is the like-for-like number.

| | vs `aes-256-gcm` | |
| --- | --- | --- |
| `aes-128-gcm`, on the crate | **0.96x-1.09x** | fewer rounds, as expected, and stable enough to say so |
| `aes-128-gcm`, on the fused engine | **1.92x-4.10x** | gate 10's re-associated reduction plus one pass over the message |
| `chacha20-ietf-poly1305` | **0.15x-0.92x** | a 6.1x spread across four runners on identical code |

So the report-only decision holds, and it holds for the reason it was made: the second row is not a slow implementation so much as a measurement whose value is decided by which AES the runner has. Two things follow. **This tree's `chacha20-ietf-poly1305` is slower than `aes-gcm`'s AES for the same bytes on all four runners** — the `VMess` rows prove the ChaCha core is fast against another ChaCha, which is a different comparison. And **the cipher is the peer's choice**: a `chacha20-ietf-poly1305` link is a user declining `aes-256-gcm` because their CPU does the other one better, so what this rung owes them is that naming it costs nothing — which is the allocation row, at 0 in all sixty windows.

The saving genuinely this rung's is in the derivation, not the chunk: one `MD5` round for `aes-128-gcm` against two, printed in every report.

## What replaces it, and what it does not

The per-chunk path is one in-place `AEAD` over the caller's staged buffer, the same shape it was before this rung — what changed is the per-session setup and the width of the table:

- **the derivation is the method's length.** One `MD5` round against two, and `HKDF` output truncated to what the cipher takes. Gate 9 prints the table.
- **nothing is derived past the key.** The 32-byte array is sized so the three methods share one shape, and the bytes past `key_len` are never written.
- **the password is turned into a master key once per connection**, not once per direction: `Cipher::from_master_key` takes the key the caller already derived, and `Recv::Waiting` carries it to the direction whose salt has not arrived.

## Three upstream shapes that are not reproduced

| upstream | what it does | here |
| --- | --- | --- |
| `Xray-core`'s `AEADCipher` is a seven-method interface | a method per operation, and `NewEncryptionWriter`/`NewDecryptionReader` each build a fresh `crypto.AEADChunkSizeParser` around the authenticator — per writer, per reader, per session | `Cipher` has two operations and one nonce counter, and the framing walk is this crate's |
| `Xray-core`'s nonce | `GenerateAEADNonceWithSize` allocates a buffer per authenticator and returns a closure that hands out the *same* buffer on every call | `nonce()` returns a fresh `[u8; 12]` per chunk, which costs nothing and cannot alias |
| `sing-box`'s `chacha20-ietf-poly1305` | **truncates at the budget**: `content[:max]` travels early and `content[max:]` after the handshake, so the two halves of one write split across the upgrade | one `write` is one chunk or a frame, never both |

## Verification status

| claim | checked by | verdict |
| --- | --- | --- |
| the cipher table and its spellings | `transport.rs`'s `the_method_table_is_xrays_spelling_set` | green in `cargo test` |
| the key derivation, the nonce byte order, `AES-128` being `AES-128`, `aes-gcm` refusing a wrong-length key, and a forged tag being refused with the chunk untouched | the eight vectors in this module | green in `cargo test` |
| the framing, against a real peer | `xray_oracle::shadowsocks_over_raw_tcp_matches_the_oracle` | green in `conformance.yml`; it names `aes-256-gcm` only, because the oracle's own `protocol_settings` hard-codes it |
| both roles agree over a socket, for every method and spelling | `every_named_method_and_spelling_relays_an_echo`, eight pairs | green in `cargo test`, and self-referential — both peers are this tree |
| no allocation per chunk | `bench.yml` gate 9, counting allocator, all three methods, counts printed beside the bar | green in `bench.yml` as **under one allocation per chunk**; the bar and its reason are in `ciphers.rs` and [`../claims.md`](../claims.md), and the assertion is in the gate rather than in a `#[test]` because `count::measure`'s flag is process-wide |
| the added ways cost what the existing one costs | `bench.yml` gate 9 | **printed, not judged**, and run `37264964528` is the measurement that settles it: `aes-128-gcm` holds 0.96x-1.09x of `aes-256-gcm` on four runners while `chacha20-ietf-poly1305` spans 0.15x-0.92x, a 6.1x spread on identical code |
| no allocation per chunk, measured | the same run's sixty windows | 0 allocations and 0 bytes in every one: three methods, five lengths, four runners |

### Licence

A cipher name, a key length and an `MD5` chain are a wire format, not an implementation. No `Xray-core`, sing-box, xray-rust, `PattNG` or `ZeroNet` line or test enters this tree; every vector is spelled out from the format, and the `ZeroNet` oracle runs unmodified from its pin.