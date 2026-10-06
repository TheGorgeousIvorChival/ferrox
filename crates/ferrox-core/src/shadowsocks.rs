use crate::aead::{chacha20_poly1305_decrypt_in_place, chacha20_poly1305_seal_in_place};

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const LENGTH_LEN: usize = 2;
pub const MAX_CHUNK: usize = 0x3FFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Method {
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

    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::Chacha20Poly1305 => 32,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "aes-128-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::Chacha20Poly1305 => "chacha20-ietf-poly1305",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug)]
pub struct Cipher {
    method: Method,
    key: Key,
    counter: u64,
    aead: Aead,
}

enum Aead {
    Aes128(Box<crate::aesgcm::Aes128Gcm>),
    Aes256(Box<crate::aesgcm::Aes256Gcm>),
    ChaCha,
}

impl std::fmt::Debug for Aead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128(_) => "aes-128-gcm",
            Self::Aes256(_) => "aes-256-gcm",
            Self::ChaCha => "chacha20-ietf-poly1305",
        })
    }
}

type Key = [u8; 32];

impl Cipher {
    #[must_use]
    pub fn new(method: Method, password: &str, salt: &[u8]) -> Option<Self> {
        Self::from_master_key(method, &MasterKey::new(password, method.key_len()), salt)
    }

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

    #[must_use]
    pub const fn method(&self) -> Method {
        self.method
    }

    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    fn nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.counter.to_le_bytes());
        nonce
    }

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

    fn advance(&mut self) -> Option<()> {
        self.counter = self.counter.checked_add(1)?;
        Some(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MasterKey {
    bytes: Vec<u8>,
    rounds: usize,
}

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

    #[must_use]
    #[allow(clippy::must_use_candidate, reason = "workspace policy")]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

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
        cipher.counter = 1;
        assert_eq!(&cipher.nonce()[..8], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_ne!(&cipher.nonce()[..8], &1u64.to_be_bytes());
    }

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

    #[test]
    fn aes_128_is_its_own_cipher_and_not_a_widened_key() {
        let salt = [0x11u8; 32];
        let mut ours = Cipher::new(Method::Aes128Gcm, "secret", &salt).expect("derives");
        let narrow_key = ours.key[..16].to_vec();
        let mut mine = Vec::new();
        ours.seal_into(b"ping", &mut mine).expect("seals");

        let mut narrow = b"ping".to_vec();
        Aes128Gcm::new_from_slice(&narrow_key)
            .expect("takes 16 bytes")
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&[0u8; 12]), b"", &mut narrow)
            .expect("seals");
        assert_eq!(mine[..4], narrow[..4], "this is the 16-byte schedule");

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
