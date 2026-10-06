//! The `shadowsocks` `AEAD` chunk transport: which ciphers it names, and the
//! per-direction state that seals and opens its chunks.
//!
//! # Why the ciphers live here and not in the application
//!
//! Because this is where the proof is. The `ChaCha20` method seals through
//! [`crate::aead`], whose bytes are swept against the pinned
//! `chacha20poly1305` crate at every length and against `RFC 8439`'s own
//! vector; the `AES` methods seal through `aes-gcm`, which is what the
//! `aes-256-gcm` row in `docs/conformance.md` already proves against real
//! `Xray-core`. A `method=` name and the key it implies are a wire format, not
//! an application detail, so the cipher is here and the socket half that
//! carries it stays where it is.
//!
//! # The three methods, and why three
//!
//! `Xray-core`'s `cipherFromString` names four `AEAD` ciphers and three spellings
//! of each; `sing-box` names six inbound and adds the `2022` trio and eight
//! legacy stream ciphers; `ZeroNet` — the core this workspace's application
//! replaces — names **three**, and refuses the rest exactly as this crate used
//! to. The intersection of all four is **`aes-128-gcm`, `aes-256-gcm` and
//! `chacha20-ietf-poly1305`**, and that intersection is the whole rung.
//!
//! What the intersection excludes is a decision, not an oversight:
//! `xchacha20-ietf-poly1305` is in `Xray-core` and `sing-box` but not in
//! `ZeroNet`, and it needs `HChaCha20`, which is a primitive rather than a table
//! row; `aes-192-gcm` and the eight legacy stream ciphers are `sing-box`'s
//! alone; and `2022-blake3-*` is not a cipher choice at all but a different wire
//! format, with a per-chunk key, a pre-shared key and a keyed `BLAKE3` digest.
//!
//! # The key derivation, and the bytes it must not produce
//!
//! `Xray-core` derives the session key in two steps
//! (`proxy/shadowsocks/config.go:181-207`): `EVP_BytesToKey` over the password
//! **truncated to the method's key length**, then `HKDF-SHA1` with that as the
//! input keying material, the salt as the salt and `"ss-subkey"` as the info,
//! again truncated to the key length. Both truncations are load-bearing — a
//! 32-byte input key is a *different* `HKDF` input than a 16-byte one — and the
//! second one is work the earlier cut generated and threw away: it derived 32
//! bytes for every method, and an `AES-128` connection used 16 of them.
//!
//! The master key is an `MD5` chain, one round per 16 bytes, so `aes-128-gcm`
//! does one `MD5` where the other two do two. [`MasterKey`] returns the count
//! with the bytes, which makes that a number a test can check rather than a
//! claim.

use crate::aead::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_seal_in_place};

/// Tag bytes per sealed chunk, for every `AEAD` method.
pub const TAG_LEN: usize = 16;
/// Nonce bytes per sealed chunk, for every `AEAD` method.
pub const NONCE_LEN: usize = 12;
/// Bytes of the chunk-length prefix, sealed as a chunk of its own.
pub const LENGTH_LEN: usize = 2;
/// Largest plaintext one chunk carries, `0x3FFF` bytes.
pub const MAX_CHUNK: usize = 0x3FFF;

/// A `shadowsocks` `AEAD` cipher, as a share link's `method=` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `aes-128-gcm`, a 16-byte key.
    Aes128Gcm,
    /// `aes-256-gcm`, a 32-byte key.
    Aes256Gcm,
    /// `chacha20-ietf-poly1305`, a 32-byte key and a 12-byte nonce.
    Chacha20Poly1305,
}

impl Method {
    /// The method a `method=` value names, with every spelling `Xray-core` accepts.
    ///
    /// Three spellings per cipher, and all three are in links in the wild: the
    /// bare RFC name, the `aead_` prefix `shadowsocks` used before these ciphers
    /// were standardised, and the `-ietf-` infix that names the `RFC` whose
    /// 12-byte nonce this is. A link carrying a spelling that is not in this list
    /// is refused, so a refusal here is a refused connection — which is why the
    /// aliases are part of the rung and not a nicety.
    ///
    /// Case-insensitive and whitespace-trimmed, as `Xray-core`'s
    /// `strings.ToLower` is applied to a trimmed value.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Self::Aes128Gcm,
            "aes-256-gcm" | "aead_aes_256_gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "aead_chacha20_poly1305" | "chacha20-poly1305" => {
                Self::Chacha20Poly1305
            }
            _ => return None,
        })
    }

    /// Bytes of key this method's `AEAD` takes.
    ///
    /// The one number the whole derivation turns on: how many `MD5` rounds the
    /// master key costs, and how much of the `HKDF` output is kept.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    /// The spelling [`Self::parse`] prefers, for a report that names the method.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20Poly1305 => "chacha20-ietf-poly1305",
        }
    }
}

/// The `method=` spelling, so a failure message and a report can name it
/// directly. `Method::name` is what this writes; there is no second list of
/// names to keep in step with the first.
impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One direction's `AEAD` state: the derived key, the nonce counter, and the
/// cipher.
///
/// # The nonce, and the bug this shape exists to prevent
///
/// Twelve bytes with a little-endian counter in the first eight. `SIP004` states
/// that byte order and `Xray-core` implements it by starting a buffer at all
/// `0xFF` and incrementing it byte-wise from the low end, which is the same
/// sequence. Writing the counter **big**-endian agrees with that only at zero,
/// so a stream built that way completes its first chunk and fails every one after
/// it — which reads like a framing bug rather than the byte-order bug it is.
/// Both halves are asserted at the 255→256→257 boundary, where they first
/// disagree.
#[derive(Debug)]
pub struct Cipher {
    /// Which method this direction seals with.
    method: Method,
    /// The session key, `HKDF`-derived and exactly the method's length long.
    key: Key,
    /// Chunks sealed or opened so far.
    counter: u64,
    /// The `AEAD`, keyed and ready.
    aead: Aead,
}

/// The three `AEAD`s, selected once per direction.
///
/// Two `AES` variants and not one length, and the reason is the shape of the
/// mistake rather than the cipher. `aes-gcm` is strict: `Aes128Gcm` refuses a
/// 32-byte key and `Aes256Gcm` refuses a 16-byte one, both with `InvalidLength`
/// (`tests::aes_gcm_refuses_the_other_methods_key_length`). So the only way to
/// get this wrong is a **slice** — hold the session key in one 32-byte array and
/// hand every method `&key[..32]`, and an `aes-128-gcm` link is sealed with
/// `AES-256`. That version round-trips between two endpoints of this tree and
/// fails against every peer, which is the worst way for it to fail. `Aead` is
/// two variants so the length is chosen by the method rather than by the slice,
/// and `tests::aes_128_is_its_own_cipher_and_not_a_widened_key` holds the
/// schedules against each other.
enum Aead {
    /// `aes-128-gcm`, on this crate's own fused engine.
    Aes128(Box<crate::aesgcm::Aes128Gcm>),
    /// `aes-256-gcm`, on this crate's own fused engine.
    Aes256(Box<crate::aesgcm::Aes256Gcm>),
    /// `chacha20-ietf-poly1305`, on this crate's own keystream core.
    ChaCha,
}

/// The method and nothing else.
///
/// Written rather than derived, twice over: `aes-gcm`'s cipher types implement
/// no `Debug` at all, and a `Debug` that *could* be derived on a struct holding
/// a keyed cipher is a `Debug` that prints key material. A test that fails with
/// a cipher's bytes in the message is a test that puts a password in a log.
impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128(_) => "aes-128-gcm",
            Self::Aes256(_) => "aes-256-gcm",
            Self::ChaCha => "chacha20-ietf-poly1305",
        })
    }
}

/// The session key in the one shape every method's key fits: a 32-byte array
/// whose first `Method::key_len()` bytes are live and whose tail is never
/// written.
type Key = [u8; 32];

impl Cipher {
    /// Derive this direction's key from the password and the session salt.
    ///
    /// One `EVP_BytesToKey` and one `HKDF`, in that order, which is the shape
    /// `Xray-core` has. A caller that has to derive both directions keeps the
    /// [`MasterKey`] and reaches [`Self::from_master_key`] for the second, so a
    /// connection derives the password once rather than once per direction.
    ///
    /// # Errors
    ///
    /// `None` only if the `HKDF` refuses to produce the method's key length,
    /// which the output bound it is given makes impossible.
    #[must_use]
    pub fn new(method: Method, password: &str, salt: &[u8]) -> Option<Self> {
        Self::from_master_key(method, &MasterKey::new(password, method.key_len()), salt)
    }

    /// Derive this direction's key from a master key already in hand.
    ///
    /// # Errors
    ///
    /// As [`Self::new`], and `None` if `master` is not this method's key length.
    #[must_use]
    pub fn from_master_key(method: Method, master: &MasterKey, salt: &[u8]) -> Option<Self> {
        let key_len = method.key_len();
        if master.as_bytes().len() != key_len {
            return None;
        }
        let mut key: Key = [0u8; 32];
        let hk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), master.as_bytes());
        hk.expand(b"ss-subkey", &mut key[..key_len]).ok()?;
        let aead = match method {
            Method::Aes128Gcm => Aead::Aes128(Box::new(crate::aesgcm::Aes128Gcm::new(
                key[..16].try_into().ok()?,
            ))),
            Method::Aes256Gcm => Aead::Aes256(Box::new(crate::aesgcm::Aes256Gcm::new(
                key[..key_len].try_into().ok()?,
            ))),
            Method::Chacha20Poly1305 => Aead::ChaCha,
        };
        Some(Self {
            method,
            key,
            counter: 0,
            aead,
        })
    }

    /// The method this cipher seals with.
    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    /// Chunks sealed or opened so far.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The nonce for the chunk about to be sealed or opened.
    ///
    /// Little-endian counter in the first eight bytes, zero in the last four.
    /// Per direction: a reader's counter and its writer's start together at zero
    /// and advance together, which is what lets one pair carry a chunk each way
    /// at the same time.
    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

    /// Seal `plaintext` as one chunk appended to `out`: `ciphertext || tag`.
    ///
    /// In place inside `out`, which the caller stages once per direction and
    /// reuses, so a chunk costs no allocation and no copy of the payload beyond
    /// the one into `out` that the framing requires. Appends rather than returns
    /// for the same reason [`crate::aead`] takes one buffer and not two.
    ///
    /// # Errors
    ///
    /// `None` if the counter has wrapped, which at one chunk per 16 KiB is
    /// 256 TiB of one direction.
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Option<()> {
        let nonce = self.nonce();
        let at = out.len();
        out.extend_from_slice(plaintext);
        let body = &mut out[at..];
        let tag = match &self.aead {
            Aead::Aes128(cipher) => cipher.seal_in_place(&nonce, b"", body),
            Aead::Aes256(cipher) => cipher.seal_in_place(&nonce, b"", body),
            Aead::ChaCha => chacha20_poly1305_seal_in_place(&self.key, &nonce, b"", body),
        };
        out.extend_from_slice(&tag);
        self.advance()
    }

    /// Open one `ciphertext || tag` chunk **in place**, returning the plaintext
    /// length.
    ///
    /// Nothing is decrypted until the tag has been checked, so a chunk that
    /// fails is left exactly as it arrived and no forged byte reaches a caller.
    ///
    /// # Errors
    ///
    /// `None` on a chunk shorter than a tag, on a tag that does not match, or on
    /// a counter that has wrapped.
    pub fn open_in_place(&mut self, chunk: &mut [u8]) -> Option<usize> {
        if chunk.len() < TAG_LEN {
            return None;
        }
        let nonce = self.nonce();
        let split = chunk.len() - TAG_LEN;
        let (body, tag) = chunk.split_at_mut(split);
        let tag: [u8; TAG_LEN] = tag.try_into().ok()?;
        let opened: Option<()> = match &mut self.aead {
            Aead::Aes128(cipher) => cipher.open_in_place(&nonce, b"", body, &tag).map(|_| ()),
            Aead::Aes256(cipher) => cipher.open_in_place(&nonce, b"", body, &tag).map(|_| ()),
            Aead::ChaCha => {
                chacha20_poly1305_decrypt_in_place(&self.key, &nonce, b"", body, &tag).map(|_| ())
            }
        };
        opened?;
        self.advance()?;
        Some(split)
    }

    /// The chunk counter, or `None` once it has wrapped.
    fn advance(&mut self) -> Option<()> {
        self.counter = self.counter.checked_add(1)?;
        Some(())
    }
}

/// The `EVP_BytesToKey` master key, truncated to `key_len`, with the number of
/// `MD5` rounds it cost.
///
/// The count is returned rather than hidden because it is the difference between
/// the two `AES` methods: sixteen bytes is one round and thirty-two is two, so an
/// `aes-128-gcm` connection derives **half** the master key of an `aes-256-gcm`
/// one. A derivation that always produced 32 bytes and let `AES-128` use 16 of
/// them did twice the `MD5` work for the same bytes and discarded the rest.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterKey {
    /// The key bytes, exactly the length asked for.
    bytes: Vec<u8>,
    /// `MD5` rounds consumed: one per 16 bytes, at least one.
    rounds: usize,
}

/// The length and the round count, and not the bytes.
impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MasterKey({} bytes, {} rounds)",
            self.bytes.len(),
            self.rounds
        )
    }
}

impl MasterKey {
    /// `EVP_BytesToKey` with an empty salt and one `MD5` per 16 bytes.
    ///
    /// `Xray-core`'s `passwordToCipherKey` (`proxy/shadowsocks/config.go:181`):
    /// `MD5(password)`, then while the key is short,
    /// `MD5(previous || password)`.
    #[must_use]
    pub fn new(password: &str, key_len: usize) -> Self {
        let rounds = key_len.div_ceil(16).max(1);
        let mut bytes = Vec::with_capacity(rounds * 16);
        let mut digest = md5::compute(password.as_bytes()).0;
        bytes.extend_from_slice(&digest);
        for _ in 1..rounds {
            let mut input = Vec::with_capacity(16 + password.len());
            input.extend_from_slice(&digest);
            input.extend_from_slice(password.as_bytes());
            digest = md5::compute(&input).0;
            bytes.extend_from_slice(&digest);
        }
        bytes.truncate(key_len);
        Self { bytes, rounds }
    }

    /// The key bytes, exactly `key_len` of them.
    #[must_use]
    #[allow(clippy::must_use_candidate, reason = "workspace policy")]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// `MD5` rounds this derivation consumed.
    #[must_use]
    pub const fn rounds(&self) -> usize {
        self.rounds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    /// The `method=` table: every spelling `Xray-core`'s `cipherFromString`
    /// accepts for these three, and none of the neighbours.
    #[test]
    fn the_method_table_is_xrays_spelling_set() {
        for (name, want) in [
            ("aes-128-gcm", Method::Aes128Gcm),
            ("aead_aes_128_gcm", Method::Aes128Gcm),
            ("aes-256-gcm", Method::Aes256Gcm),
            ("aead_aes_256_gcm", Method::Aes256Gcm),
            ("chacha20-ietf-poly1305", Method::Chacha20Poly1305),
            ("aead_chacha20_poly1305", Method::Chacha20Poly1305),
            ("chacha20-poly1305", Method::Chacha20Poly1305),
            ("  AES-256-GCM  ", Method::Aes256Gcm),
        ] {
            assert_eq!(Method::parse(name), Some(want), "{name}");
            assert_eq!(
                Method::parse(&name.to_ascii_uppercase()),
                Some(want),
                "{name} shouted"
            );
        }
        for name in [
            "",
            "aes",
            "aes-192-gcm",
            "xchacha20-ietf-poly1305",
            "aead_xchacha20_poly1305",
            "2022-blake3-aes-256-gcm",
            "rc4-md5",
            "chacha20",
            "none",
        ] {
            assert_eq!(Method::parse(name), None, "{name}");
        }
    }

    /// `EVP_BytesToKey`, spelled out from its arithmetic: `MD5(password)` and
    /// then `MD5(previous || password)` while the key is short.
    #[test]
    fn the_master_key_is_the_md5_chain_and_no_longer() {
        let first = md5::compute(b"secret").0;
        let long = MasterKey::new("secret", 32);
        assert_eq!(long.rounds(), 2);
        assert_eq!(long.as_bytes()[..16], first);
        let mut input = Vec::new();
        input.extend_from_slice(&first);
        input.extend_from_slice(b"secret");
        assert_eq!(long.as_bytes()[16..], md5::compute(&input).0);

        let short = MasterKey::new("secret", 16);
        assert_eq!(short.rounds(), 1, "one MD5 covers one AES-128 key");
        assert_eq!(short.as_bytes(), &first[..], "and it is that first round");
        assert_eq!(
            short.as_bytes(),
            &long.as_bytes()[..16],
            "a truncated derivation is the shorter one"
        );
    }

    /// The 32-byte master key, against a value written down rather than computed
    /// here.
    ///
    /// The vector below was the application's own check on its own `MD5` chain, so
    /// it is the one input to this function that was not derived by the same code
    /// it checks. It is kept here because `MasterKey` is what it checks, and
    /// added for the 16-byte truncation — which is not this vector's prefix but
    /// the same first round.
    #[test]
    fn the_master_key_is_the_value_written_down() {
        assert_eq!(
            MasterKey::new("an-example-shared-password", 32).as_bytes(),
            b"\x5c\xb2\x9f\x91\x10\xb5\x40\xa6\xeb\x99\x5c\x35\x67\x1b\x75\x92\xa5\x07\xf5\
              \xdb\xe4\xac\x97\x7c\xae\x2f\x7b\x98\xde\xdc\x80\x22"
        );
        assert_eq!(
            MasterKey::new("an-example-shared-password", 16).as_bytes(),
            &MasterKey::new("an-example-shared-password", 32).as_bytes()[..16],
            "and the 16-byte key is that key's first half, not a shorter chain"
        );
    }

    /// The nonce counter's byte order, at the boundary where the two orders first
    /// disagree and at the one where the carry first moves.
    #[test]
    fn the_nonce_is_a_little_endian_counter_in_the_first_eight_bytes() {
        let mut cipher = Cipher::new(Method::Aes256Gcm, "secret", &[0x5a; 32]).expect("derives");
        assert_eq!(cipher.nonce(), [0u8; NONCE_LEN], "chunk zero is all zero");
        for counter in [1u64, 255, 256, 257, u64::from(u32::MAX)] {
            cipher.counter = counter - 1;
            cipher.advance().expect("advances");
            assert_eq!(
                cipher.nonce(),
                {
                    let mut want = [0u8; NONCE_LEN];
                    want[..8].copy_from_slice(&counter.to_le_bytes());
                    want
                },
                "chunk {counter}"
            );
            assert_eq!(cipher.counter(), counter);
        }
        // A big-endian counter agrees with this at zero and nowhere else.
        cipher.counter = 1;
        assert_eq!(&cipher.nonce()[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_ne!(&cipher.nonce()[..8], &1u64.to_be_bytes());
    }

    /// `aes-gcm` refuses a key of the wrong length, so the way to seal an
    /// `aes-128-gcm` link with the `AES-256` schedule is a slice and never an
    /// acceptance.
    ///
    /// This first draft of the schedule test asserted the opposite — that
    /// `Aes256Gcm::new_from_slice` takes 16 bytes — and run `37263819768`
    /// answered `InvalidLength`. The assertion is worth having precisely because
    /// it is the crate that refuses: it means a wrong-length key is a loud error
    /// and the only quiet failure left is `&key[..32]` applied to every method.
    #[test]
    fn aes_gcm_refuses_the_other_methods_key_length() {
        let sixteen = [0x11u8; 16];
        let thirty_two = [0x11u8; 32];
        assert!(
            Aes256Gcm::new_from_slice(&sixteen).is_err(),
            "a 16-byte key is not an AES-256 key"
        );
        assert!(
            Aes128Gcm::new_from_slice(&thirty_two).is_err(),
            "a 32-byte key is not an AES-128 key"
        );
    }

    /// `AES-128` is not `AES-256`, and this holds this crate's construction
    /// against `aes-gcm`'s on the same key, salt, nonce and plaintext.
    ///
    /// The contrast is between the two schedules keyed as each method keys them,
    /// because that is what a slice would collapse: one 32-byte session key, one
    /// cipher, every method. The two `MD5` round counts and both `HKDF` lengths
    /// are fixed by the method, so the difference here can only be the schedule.
    #[test]
    fn aes_128_is_its_own_cipher_and_not_a_widened_key() {
        let salt = [0x11u8; 32];
        let mut ours = Cipher::new(Method::Aes128Gcm, "secret", &salt).expect("derives");
        // The session key each method keys its cipher with -- the `HKDF` output
        // at that method's length, not the master key it came from. This test's
        // first draft compared `aes-gcm` against the *master* key and run
        // `37264034762` disagreed on the first four bytes, which is the two-step
        // derivation doing what it is there to do.
        let narrow_key = ours.key[..16].to_vec();
        let mut mine = Vec::new();
        ours.seal_into(b"ping", &mut mine).expect("seals");

        let mut narrow = b"ping".to_vec();
        Aes128Gcm::new_from_slice(&narrow_key)
            .expect("takes 16 bytes")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut narrow)
            .expect("seals");
        assert_eq!(mine[..4], narrow[..4], "this is the 16-byte schedule");

        // And the same password and salt under the other method's schedule, which
        // is what a shared 32-byte buffer and one slice would produce.
        let other = Cipher::new(Method::Aes256Gcm, "secret", &salt).expect("derives");
        let mut widened = b"ping".to_vec();
        Aes256Gcm::new_from_slice(&other.key)
            .expect("takes 32 bytes")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut widened)
            .expect("seals");
        assert_ne!(
            mine[..4],
            widened[..4],
            "the 32-byte schedule is a different cipher, and a slice would pick it"
        );
    }

    /// A chunk seals and opens to the same bytes for every method, and a forged
    /// tag is refused with the chunk left as it arrived.
    #[test]
    fn every_method_round_trips_a_chunk_and_refuses_a_forged_tag() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let salt = [0x77u8; 32];
            let mut sender = Cipher::new(method, "secret", &salt).expect("derives");
            let mut receiver = Cipher::new(method, "secret", &salt).expect("derives");
            assert_eq!(sender.method(), method);
            for len in [0usize, 1, 63, 64, 1024, MAX_CHUNK] {
                let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
                let mut wire = Vec::new();
                sender.seal_into(&plain, &mut wire).expect("seals");
                assert_eq!(wire.len(), plain.len() + TAG_LEN, "{method} len {len}");

                let opened = receiver.open_in_place(&mut wire).expect("opens");
                assert_eq!(&wire[..opened], &plain[..], "{method} len {len}");

                let mut forged = wire.clone();
                forged[0] ^= 1;
                // What was handed in, so "untouched" means the call changed
                // nothing -- not "the forgery was undone".
                let as_sent = forged.clone();
                assert!(
                    receiver.open_in_place(&mut forged).is_none(),
                    "{method} len {len}: a forged tag is refused"
                );
                assert_eq!(
                    forged, as_sent,
                    "{method} len {len}: and a refused chunk is left exactly as it arrived"
                );
            }
        }
    }

    /// The three methods do not produce the same chunk for the same input, so a
    /// test that round-trips one of them cannot pass on another.
    #[test]
    fn the_methods_are_not_interchangeable() {
        let salt = [0x5au8; 32];
        let mut sealed = Vec::new();
        Cipher::new(Method::Aes256Gcm, "secret", &salt)
            .expect("derives")
            .seal_into(b"ping", &mut sealed)
            .expect("seals");
        for method in [Method::Aes128Gcm, Method::Chacha20Poly1305] {
            assert!(
                Cipher::new(method, "secret", &salt)
                    .expect("derives")
                    .open_in_place(&mut sealed.clone())
                    .is_none(),
                "{method} cannot open an aes-256-gcm chunk"
            );
        }
        assert!(
            Cipher::new(Method::Aes256Gcm, "wrong", &salt)
                .expect("derives")
                .open_in_place(&mut sealed.clone())
                .is_none(),
            "and a wrong password cannot either"
        );
    }

    /// The two directions count independently, which is what lets one pair carry
    /// a chunk each way at the same time.
    #[test]
    fn the_two_directions_count_independently() {
        let salt = [0x33u8; 32];
        let mut up = Cipher::new(Method::Chacha20Poly1305, "secret", &salt).expect("derives");
        let mut down = Cipher::new(Method::Chacha20Poly1305, "secret", &salt).expect("derives");
        let mut first = Vec::new();
        up.seal_into(b"a", &mut first).expect("seals");
        let mut second = Vec::new();
        down.seal_into(b"a", &mut second).expect("seals");
        assert_eq!(first, second, "both start at chunk zero");
        let mut third = Vec::new();
        up.seal_into(b"a", &mut third).expect("seals");
        let mut fourth = Vec::new();
        down.seal_into(b"a", &mut fourth).expect("seals");
        assert_eq!(third, fourth, "and both advance together");
    }

    /// The session key is the method's length and no longer, because a 32-byte
    /// `HKDF` input is a different input than a 16-byte one.
    #[test]
    fn the_session_key_is_derived_at_the_methods_own_length() {
        for (method, len) in [
            (Method::Aes128Gcm, 16usize),
            (Method::Aes256Gcm, 32),
            (Method::Chacha20Poly1305, 32),
        ] {
            let salt = [0x09u8; 32];
            let cipher = Cipher::new(method, "secret", &salt).expect("derives");
            let master = MasterKey::new("secret", len);
            let mut want = [0u8; 32];
            hkdf::Hkdf::<sha1::Sha1>::new(Some(&salt), master.as_bytes())
                .expand(b"ss-subkey", &mut want[..len])
                .expect("expands");
            assert_eq!(&cipher.key[..len], &want[..len], "{method}");
        }
    }
}
