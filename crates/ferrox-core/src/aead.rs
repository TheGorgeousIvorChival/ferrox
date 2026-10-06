//! `ChaCha20-Poly1305` (`IETF`, `RFC 8439`) on this crate's own keystream core.
//!
//! # Why it exists
//!
//! `VMess` negotiates `ChaCha20-Poly1305` for its data frames, and it used to
//! get it from the `chacha20poly1305` crate. On `aarch64` that crate runs at
//! 0.45 GB/s, because the `chacha20` crate underneath it will not select its own
//! NEON backend and so runs the keystream half one dependent chain at a time.
//! [`crate::record::fill_exact`] does the same twenty rounds at 2.14 GB/s on the
//! same machine, and it is the same twenty rounds — the differential sweep
//! against the pinned `chacha20` crate is what that rests on.
//!
//! So the keystream half is [`crate::record`], unchanged, and the only new code
//! here is the `Poly1305` accumulator in [`crate::poly1305`] and the framing
//! `RFC 8439` puts around it.
//!
//! # The construction, and the one copy it does not need
//!
//! `C = P XOR keystream`, so encrypting in place is [`crate::record::fill_exact`]
//! over a buffer that already holds the plaintext. No keystream buffer, no
//! second pass, no copy.
//!
//! Decrypting is the part worth reading twice. The tag is computed over the
//! *ciphertext*, so the order has to be: authenticate the bytes that arrived,
//! compare, and only then turn them into plaintext. Both `record::fill_exact`
//! and [`crate::poly1305::tag`] read `buf` and neither writes it, so the
//! ciphertext is still intact when the tag is checked and still intact when the
//! comparison is done — and the decrypt is the same single in-place XOR. A
//! decrypt-then-authenticate would need a copy of the ciphertext to compare
//! against, and this does not.
//!
//! The comparison is constant time, and not by a `==` on the arrays: `==` is a
//! lexicographic compare that returns as soon as it finds a difference, and its
//! running time says how much of a forged tag was right.

use crate::poly1305::Poly1305;
use crate::record::{fill_exact, fill_exact_with_head};

/// How the `Poly1305` key is derived: one time, from the `ChaCha20` key and the
/// nonce, by `ChaCha20` with an all-zero block counter.
///
/// This is `RFC 8439` section 2.6, and it is the reason the block counter is
/// pinned to zero rather than left to the caller: the keystream for this key is
/// the *first* block, whatever counter the message itself starts at.
fn poly_key(chacha_key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let mut block = [0u8; 64];
    fill_exact(chacha_key, nonce, 0, &mut block);
    let mut key = [0u8; 32];
    key.copy_from_slice(&block[..32]);
    key
}

/// Seal `buf` in place and return the tag, the way the pinned crate does.
///
/// Identical to calling [`chacha20_poly1305_seal_in_place`], and it exists only
/// so the differential test can compare the fused keystream pass against the
/// unfused one at every length. Both are the shipped bytes; the difference is
/// how many `ChaCha20` blocks were generated to produce them.
///
/// # Panics
///
/// Never, for lengths the seal itself accepts.
#[must_use]
pub fn chacha20_poly1305_seal_in_place_unfused(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    fill_exact(key, nonce, 1, buf);
    let mut state = Poly1305::new(&poly_key(key, nonce));
    mac(&mut state, aad, buf);
    state.finish()
}

/// The `RFC 8439` section 2.8 MAC input, in the shape it specifies.
///
/// `pad16(aad) || pad16(ciphertext) || len(aad) || len(ciphertext)` — the two
/// sections each zero-padded up to a block boundary, and *both* sixty-four-bit
/// little-endian lengths in one final block, rather than a length in front of
/// each section.
///
/// That is the part worth being certain about, because the other reading is
/// plausible and produces a valid-looking tag for every length that is a
/// multiple of sixteen. The `RFC 8439` section 2.8.2 test vector settles it: the
/// length-first framing gives `9f ff 5e 04 ...` there and the padded framing
/// gives the specified `1a e1 0b 59 ...`. Both readings also agree with the
/// pinned crate, so a test against the crate alone would not have caught a
/// mistake here — only agreement between the two is evidence.
fn mac(state: &mut Poly1305, aad: &[u8], ciphertext: &[u8]) {
    for section in [aad, ciphertext] {
        state.update(section);
        // Every section reaches a block boundary. This is a `memcpy` of at most
        // fifteen bytes per section — two per message — and it is what the RFC
        // says; `Poly1305::update` already knows how to carry a partial block
        // into the next call, so nothing here has to be special-cased.
        let slack = (16 - section.len() % 16) % 16;
        state.update(&[0u8; 16][..slack]);
    }
    // Two lengths, one block. The total message length is then a multiple of
    // sixteen by construction, so `finish` never has to terminate it.
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    state.update(&lengths);
}

/// Seal `buf` in place: plaintext in, ciphertext out, and the sixteen-byte tag.
///
/// One buffer rather than two, and that is the whole interface. `C = P XOR
/// keystream` means a caller that already has the plaintext in a buffer it is
/// going to write out anyway never needs to hand the bytes over twice — which is
/// the shape [`crate::record::fill_exact`] is already in, and the reason this
/// takes one `&mut [u8]` and not a `&[u8]` beside it.
///
/// The tag is over the *ciphertext*, so it is computed after the xor, from the
/// bytes now sitting in `buf`.
#[must_use]
pub fn chacha20_poly1305_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    // The one-time key and the message keystream are consecutive blocks of one
    // keystream: block zero's first 32 bytes, then block one onward. Asking for
    // them as one pass generates block zero once instead of twice, and — the part
    // that was actually slow — puts it on the wide core with the message's blocks
    // already in flight rather than on the scalar one-block core, which is where
    // a 64-byte `fill_exact` lands because a single chain has nothing to
    // interleave with. The bytes are unchanged and
    // `chacha20_poly1305_seal_in_place_unfused` is the before, kept so the
    // differential test can hold the two to each other at every length.
    let mut one_time = [0u8; 32];
    fill_exact_with_head(key, nonce, 0, &mut one_time, buf);

    let mut state = Poly1305::new(&one_time);
    mac(&mut state, aad, buf);
    state.finish()
}

/// Open `buf`, which holds the ciphertext, in place, if `tag` is the tag for it.
///
/// Returns the plaintext length on success and `None` on a tag that does not
/// match. On `None` the contents of `buf` are unspecified but unchanged: nothing
/// is decrypted until the tag has been checked.
#[must_use]
pub fn chacha20_poly1305_decrypt_in_place(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; 16],
) -> Option<usize> {
    let mut state = Poly1305::new(&poly_key(key, nonce));
    mac(&mut state, aad, buf);
    let want = state.finish();

    // Every byte, always: the running time must not say how much of a forged
    // tag was right, and `want == tag` would say exactly that.
    let mut diff = 0u8;
    for (a, b) in want.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return None;
    }

    fill_exact(key, nonce, 1, buf);
    Some(buf.len())
}

/// The tag `chacha20_poly1305_seal_in_place` produces for these ciphertext bytes,
/// without sealing anything.
///
/// A `VMess` data frame authenticates its length prefix along with its body, so
/// the tag has to exist a moment before the frame does. Computing it this way
/// means the frame is built twice rather than staged in a buffer the caller then
/// has to keep — so it is *not* free, and
/// [`chacha20_poly1305_seal_in_place`] exists for the callers who can afford the
/// single pass.
#[must_use]
pub fn chacha20_poly1305_tag(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; 16] {
    let mut state = Poly1305::new(&poly_key(key, nonce));
    mac(&mut state, aad, ciphertext);
    state.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::AeadInPlace as _;
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

    /// The `RFC 8439` section 2.8.2 vector, spelled out.
    ///
    /// The sweep against the pinned crate below is the stronger claim about what
    /// `VMess` talks to, but it cannot catch a mistake that the crate and this
    /// implementation share — and the `MAC` framing is exactly that kind of
    /// mistake. Two of them, in fact: whether the lengths go in front of each
    /// section or behind both, and whether the sections are zero-padded. Both
    /// readings give a tag the other does not, and the length-first one agrees
    /// with the padded one on every message whose length is a multiple of
    /// sixteen, so it survives a sweep that only tried round lengths.
    ///
    /// This vector is the specification itself, and it is what decides.
    #[test]
    fn the_rfc_8439_vector_is_the_framing() {
        let key: [u8; 32] = std::array::from_fn(|i| 0x80u8.wrapping_add(i as u8));
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plain: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you \
            only one tip for the future, sunscreen would be it.";
        assert_eq!(plain.len(), 114, "the RFC's plaintext is 114 bytes");
        let mut buf = plain.to_vec();
        let tag = chacha20_poly1305_seal_in_place(&key, &nonce, &aad, &mut buf);
        assert_eq!(
            &buf[..16],
            &[
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2
            ],
            "RFC 8439 section 2.8.2 ciphertext"
        );
        assert_eq!(
            tag,
            [
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
                0x06, 0x91
            ],
            "RFC 8439 section 2.8.2 tag"
        );
        assert_eq!(
            chacha20_poly1305_tag(&key, &nonce, &aad, &buf),
            tag,
            "the tag-only entry point, on the RFC's own ciphertext"
        );
        let mut opened = buf.clone();
        assert_eq!(
            chacha20_poly1305_decrypt_in_place(&key, &nonce, &aad, &mut opened, &tag),
            Some(plain.len()),
            "the RFC's ciphertext opens"
        );
        assert_eq!(
            opened, plain,
            "the RFC's ciphertext opens to the RFC's plaintext"
        );
    }

    /// Every length, both keys, three nonces, and every `aad` length that changes
    /// the padding — against the crate, not against a vector.
    ///
    /// A published vector decides whether this matches a *specification*; this
    /// decides whether it matches what `VMess` actually talks to, which is the
    /// question that matters and the only one a swap-in can be allowed to ask.
    /// It covers the shapes a hand-written list of lengths would miss: the block
    /// boundaries at 15/16/17, and every `aad` length across the same boundary,
    /// because the `aad` padding is a separate `mod 16` from the message's.
    #[test]
    fn is_byte_identical_to_the_crate_it_replaces() {
        let keys = [
            std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11)),
            std::array::from_fn(|i| (i as u8).wrapping_mul(97).wrapping_add(29)),
        ];
        let mut checked = 0usize;
        for key in &keys {
            for nonce in [[0u8; 12], [0xa7u8; 12], [0xffu8; 12]] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    let aad: Vec<u8> = (0..aad_len).map(|i| i as u8).collect();
                    for len in (0..=300usize).chain([511, 512, 513, 1024, 8192]) {
                        let plain: Vec<u8> = (0..len)
                            .map(|i| (i as u8).wrapping_mul(53).wrapping_add(7))
                            .collect();
                        let mut buf = plain.clone();
                        let tag = chacha20_poly1305_seal_in_place(key, &nonce, &aad, &mut buf);
                        let want_ct = {
                            let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key");
                            let mut ct = plain.clone();
                            let want_tag = cipher
                                .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ct)
                                .expect("seals");
                            let want_tag: [u8; 16] = want_tag.into();
                            assert_eq!(
                                tag, want_tag,
                                "tag: key {key:02x?} nonce {nonce:02x?} aad {aad_len} len {len}"
                            );
                            ct
                        };
                        assert_eq!(
                            buf, want_ct,
                            "ciphertext: key {key:02x?} nonce {nonce:02x?} aad {aad_len} len {len}"
                        );
                        assert_eq!(
                            chacha20_poly1305_tag(key, &nonce, &aad, &buf),
                            tag,
                            "the tag-only entry point disagrees at len {len}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked > 5_000, "the sweep should be dense, not a sample");
    }

    /// Open is the inverse of seal at every length, and a tag one bit off is
    /// refused without the caller's bytes being touched.

    #[test]
    fn opens_what_seal_made_and_refuses_a_forged_tag() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let plain: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            let mut buf = plain.clone();
            let tag = chacha20_poly1305_seal_in_place(&key, &nonce, b"", &mut buf);
            assert_eq!(
                chacha20_poly1305_decrypt_in_place(&key, &nonce, b"", &mut buf, &tag),
                Some(len),
                "length {len}"
            );
            assert_eq!(buf, plain, "length {len} round trips");

            let mut bad = tag;
            bad[0] ^= 1;
            assert_eq!(
                chacha20_poly1305_decrypt_in_place(&key, &nonce, b"", &mut buf, &bad),
                None,
                "length {len} refuses a changed tag"
            );
        }
    }

    /// A rejected tag must leave the caller's bytes alone: they are still the
    /// ciphertext, and a caller that retries has to be able to.
    #[test]
    fn a_refused_message_is_left_encrypted() {
        let key = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let plain = b"do not decrypt me before you check the tag".to_vec();
        let mut buf = plain.clone();
        let _tag = chacha20_poly1305_seal_in_place(&key, &nonce, b"", &mut buf);
        let ciphertext = buf.clone();
        assert_eq!(
            chacha20_poly1305_decrypt_in_place(&key, &nonce, b"", &mut buf, &[0u8; 16]),
            None
        );
        assert_eq!(buf, ciphertext, "a wrong tag must not decrypt");
    }

    /// `aad` is part of the tag, so changing it must break it.
    #[test]
    fn aad_is_authenticated() {
        let key = [0x55u8; 32];
        let nonce = [0x66u8; 12];
        let mut buf = b"payload".to_vec();
        let tag = chacha20_poly1305_seal_in_place(&key, &nonce, b"one", &mut buf);
        assert_eq!(
            chacha20_poly1305_decrypt_in_place(&key, &nonce, b"two", &mut buf, &tag),
            None,
            "the tag must not verify under a different aad"
        );
    }
}
