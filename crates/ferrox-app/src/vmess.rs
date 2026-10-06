//! `VMess` `AEAD` framing over blocking `TCP`, both roles.
//!
//! Request header, response header and length-masked data frames; the `TCP`
//! and `UDP` commands exist here, anything else closes fast rather than
//! hanging a suite. `UDP` is one sealed frame per datagram each way.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::proxy::read_exact;

/// Wire auth id bytes.
const AUTH_LEN: usize = 16;
/// `AEAD` tag bytes per sealed block.
const TAG_LEN: usize = 16;
/// Largest plaintext bytes per data frame, matching the oracle's framing.
const MAX_PLAIN: usize = 8192;
/// Frames staged into one `write`, and so one syscall.
///
/// Four, not one, because a `write` costs the same whether it carries one frame
/// or eight — see [`stage_frames`]. Four is where the measured curve flattens:
/// eight frames of 8 KB are within noise of four, and eight would double the
/// staging buffer for nothing.
const FRAMES_PER_WRITE: usize = 4;
/// Plaintext read in one go, so a fast source can fill [`FRAMES_PER_WRITE`]
/// frames and pay one syscall for all of them.
const READ_PLAIN: usize = MAX_PLAIN * FRAMES_PER_WRITE;
/// Option bits that change data framing.
const OPT_STREAM: u8 = 0x01;
/// Option bit for `SHAKE`-masked lengths.
const OPT_MASK: u8 = 0x04;
/// Option bit for cleartext padding after each frame.
const OPT_PAD: u8 = 0x08;

/// Data cipher negotiated in the request header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    /// Negotiate, always sent as `ChaCha20-Poly1305` like the oracle client does.
    Auto,
    /// `AES-128-GCM` data frames.
    Aes,
    /// `ChaCha20-Poly1305` data frames.
    Chacha,
    /// Plaintext frames with no `AEAD`.
    None,
}

impl Cipher {
    /// Parse a config `security` word, defaulting to `Auto`.
    pub(crate) fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes,
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Self::Chacha,
            "none" => Self::None,
            _ => Self::Auto,
        }
    }
    /// Wire code actually sent, with `Auto` resolved.
    fn code(self) -> u8 {
        match self {
            Self::Auto | Self::Chacha => 4,
            Self::Aes => 3,
            Self::None => 5,
        }
    }
    /// Cipher from a wire code, `None` on any other value.
    fn from_code(value: u8) -> Option<Self> {
        match value {
            3 => Some(Self::Aes),
            4 => Some(Self::Chacha),
            5 => Some(Self::None),
            _ => None,
        }
    }
}

/// Seen auth ids, rejecting verbatim replays within this process.
fn replay_seen(id: &[u8; AUTH_LEN]) -> bool {
    static SEEN: OnceLock<Mutex<HashSet<[u8; AUTH_LEN]>>> = OnceLock::new();
    let mut guard = SEEN
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    !guard.insert(*id)
}

/// `HMAC-SHA256` pads for a key.
fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    use sha2::Digest as _;
    let mut flat = [0u8; 64];
    if key.len() > 64 {
        flat[..32].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        flat[..key.len()].copy_from_slice(key);
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for i in 0..64 {
        inner[i] ^= flat[i];
        outer[i] ^= flat[i];
    }
    (inner, outer)
}

/// One `HMAC-SHA256` with restartable state.
struct Hmac {
    /// Inner hash with its pad already fed.
    inner: sha2::Sha256,
    /// Outer hash with its pad already fed.
    outer: sha2::Sha256,
    /// Fresh inner for restarts.
    fresh_inner: sha2::Sha256,
    /// Fresh outer for restarts.
    fresh_outer: sha2::Sha256,
}

impl Hmac {
    /// New `HMAC` under `key`.
    fn fresh(key: &[u8]) -> Self {
        use sha2::Digest as _;
        let (ipad, opad) = hmac_pads(key);
        let mut inner = sha2::Sha256::new();
        let mut outer = sha2::Sha256::new();
        inner.update(ipad);
        outer.update(opad);
        Self {
            fresh_inner: inner.clone(),
            fresh_outer: outer.clone(),
            inner,
            outer,
        }
    }
    /// Feed bytes to the inner hash.
    fn push(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        self.inner.update(data);
    }
    /// Restore the post-pad state.
    fn restart(&mut self) {
        self.inner = self.fresh_inner.clone();
        self.outer = self.fresh_outer.clone();
    }
    /// Finalize the `HMAC`.
    fn digest(&mut self) -> [u8; 32] {
        use sha2::Digest as _;
        let mid = self.inner.clone().finalize();
        let mut outer = self.outer.clone();
        outer.update(mid);
        outer.finalize().into()
    }
}

/// Nested `VMess` key schedule, one link per path element.
///
/// # Why this costs `2^n` hashes for `n` path elements, and why it stays
///
/// `digest` on a link digests below twice — once for `mid`, once for the
/// `seal_out || mid` close — so a depth-`n` schedule evaluates `2^n` salted
/// `HMAC`s: one path element is `H_S(opad || H_S(ipad || key))`, two are
/// `H_S(opad_A || H_S(ipad_A || opad_B || H_S(opad_A || H_S(ipad_A || ipad_B
/// || key))))`, and three (every request-header schedule) are eight. Upstream
/// Go pays the same tree through the same hash-function injection, and the
/// oracle vectors pin the outputs, so the work is the specification rather
/// than an implementation choice.
///
/// No regrouping removes it: each of the `2^n` leaves hashes a distinct input
/// (inner pads versus outer pads interleaved per layer), and `SHA-256` gives
/// no relation between distinct inputs to factor through — collapsing any two
/// leaves would be a collision argument, not an optimisation. What removes
/// work instead is never doing it: the per-user schedules ([`cached_keys`])
/// and the hardware `SHA-256` behind `sha2/asm`, which is what makes the
/// eight-leaf schedules affordable rather than cheap.
enum Kdf {
    /// Bottom link keyed by the fixed salt.
    Root(Box<Hmac>),
    /// Upper link keyed by one path element over the link below.
    Link {
        below: Box<Kdf>,
        seal_in: [u8; 64],
        seal_out: [u8; 64],
    },
}

impl Kdf {
    /// Bottom link under the fixed salt.
    fn root() -> Self {
        Self::Root(Box::new(Hmac::fresh(b"VMess AEAD KDF")))
    }
    /// Wrap the schedule with one more path element.
    fn wrap(mut self, key: &[u8]) -> Self {
        let (seal_in, seal_out) = hmac_pads(key);
        self.push(&seal_in);
        Self::Link {
            below: Box::new(self),
            seal_in,
            seal_out,
        }
    }
    /// Feed bytes through to the bottom link.
    fn push(&mut self, data: &[u8]) {
        match self {
            Self::Root(h) => h.push(data),
            Self::Link { below, .. } => below.push(data),
        }
    }
    /// Restore every link to its post-pad state.
    fn restart(&mut self) {
        match self {
            Self::Root(h) => h.restart(),
            Self::Link { below, seal_in, .. } => {
                below.restart();
                below.push(seal_in);
            }
        }
    }
    /// Finalize the whole schedule.
    fn digest(&mut self) -> [u8; 32] {
        match self {
            Self::Root(h) => h.digest(),
            Self::Link {
                below, seal_out, ..
            } => {
                let mid = below.digest();
                below.restart();
                below.push(seal_out);
                below.push(&mid);
                below.digest()
            }
        }
    }
}

/// `VMess` key schedule over `key` and `path`.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut chain = Kdf::root();
    for layer in path {
        chain = chain.wrap(layer);
    }
    chain.push(key);
    chain.digest()
}

/// First sixteen bytes of the schedule.
fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

/// `MD5` of two slices concatenated.
fn md5_two(first: &[u8], second: &[u8]) -> [u8; 16] {
    let mut input = [0u8; 52];
    let head = first.len().min(input.len());
    let tail = second.len().min(input.len() - head);
    input[..head].copy_from_slice(&first[..head]);
    input[head..head + tail].copy_from_slice(&second[..tail]);
    md5::compute(&input[..head + tail]).0
}

/// Instruction key: `MD5` of the uuid bytes plus the fixed magic.
fn instruction_key(uuid: &[u8; 16]) -> [u8; 16] {
    md5_two(uuid, b"c48619fe-8f02-49e0-b9e9-edf763e17e21")
}

/// Thirty-two-byte `ChaCha` key from a sixteen-byte data key.
fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5::compute(key).0;
    let second = md5::compute(first).0;
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

/// Entry `i` is what eight bit-steps of the reflected polynomial do to `i`.
///
/// Built at compile time by the same eight bit-steps the old loop ran, so the
/// table is not a description of `CRC-32` — it *is* the old loop, folded. The
/// reflected polynomial `0xedb8_8320` and the `!0` seed and `!` finish are the
/// same three values, so the checksum over a given twelve bytes is the same
/// `u32` as before, and `crc32_matches_the_bit_at_a_time_loop` is what checks it.
const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// The eight bit-steps, once each, as data.
const CRC_TABLE: [u32; 256] = crc_table();

/// `IEEE CRC-32`, one byte at a time through [`CRC_TABLE`].
///
/// The bit-at-a-time form this replaces was eight iterations of a branch and a
/// shift per byte, and it ran twice per request — once to seal the auth id and
/// once to check it — over twelve bytes, so ninety-six unpredictable branches for
/// a checksum the table answers in twelve loads. The auth id is small, so this is
/// not a throughput path; it is on the per-request path, and ninety-six branches
/// there is a misprediction every time.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = (crc >> 8) ^ CRC_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize];
    }
    !crc
}

/// `FNV-1a` over the clear request header.
fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Fill a buffer with portable randomness, false when the platform has none.
fn random_into(buf: &mut [u8]) -> bool {
    getrandom::getrandom(buf).is_ok()
}

/// Batched padding randomness: one `getrandom` per ~64 frames, not one per frame.
///
/// A frame carries up to 63 random trailing bytes nobody reads, and they were a
/// fresh `getrandom` syscall each time — a syscall for ~32 average bytes, per
/// frame, on the hot path. The bytes are still `getrandom` bytes, from the same
/// source, still fresh per frame; they are just drawn 2048 at a time and sliced.
/// The receiver discards padding without reading it, and the oracle does too,
/// so batching changes no wire byte the peer checks — it only removes the
/// syscall. `take` returns `None` when the platform has no entropy, which is
/// what `random_into`'s `false` meant and what `write_frame` already reports.
pub(crate) struct PadSource {
    /// 2048 fresh bytes, sliced `at..` per frame.
    buf: [u8; 2048],
    /// Next unused offset into `buf`.
    at: usize,
}

impl PadSource {
    /// Fresh batch: one syscall per connection, not one per frame.
    pub(crate) fn fresh() -> Option<Self> {
        let mut buf = [0u8; 2048];
        if !random_into(&mut buf) {
            return None;
        }
        Some(Self { buf, at: 0 })
    }

    /// `n` fresh random bytes, refilling the batch when fewer than `n` remain.
    ///
    /// `n` is at most 63 (the largest padding a frame carries), so the refill
    /// runs at most once per 32 frames and amortizes to ~0.03 syscalls per
    /// frame. Returns `None` when the refill finds no entropy.
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        debug_assert!(n <= 64, "padding is at most 63 bytes");
        if self.at + n > self.buf.len() {
            if !random_into(&mut self.buf) {
                return None;
            }
            self.at = 0;
        }
        let bytes = &self.buf[self.at..self.at + n];
        self.at += n;
        Some(bytes)
    }
}

/// Current unix seconds, zero when the clock is before the epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The auth id's `AES-128-ECB` key schedule, built once and kept.
///
/// `aes::Aes128::new_from_slice` expands the key: ten rounds of S-box lookups and
/// a round-key copy per block it can ever touch. Deriving it where the auth id was
/// sealed meant expanding the key per auth id, and deriving the key bytes at all
/// meant an `HMAC-SHA256` schedule per auth id — for a key that depends on the user
/// and nothing else. An auth id is made once per connection on the client and
/// checked once per connection on the server, so that was a key expansion and a
/// full `KDF` chain on both sides of every dial.
#[derive(Clone)]
struct AuthKey(aes::Aes128);

impl std::fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthKey").finish_non_exhaustive()
    }
}

impl AuthKey {
    /// The key an auth id is sealed under: `KDF16` of the instruction key.
    fn new(instruction: &[u8; 16]) -> Self {
        use aes::cipher::KeyInit as _;
        let bytes = kdf16(instruction, &[b"AES Auth ID Encryption"]);
        Self(aes::Aes128::new_from_slice(&bytes).expect("sixteen bytes is a key"))
    }

    /// Seal one block in place.
    fn seal(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockEncrypt as _;
        let cell = aes::cipher::generic_array::GenericArray::from_mut_slice(block.as_mut_slice());
        self.0.encrypt_block(cell);
    }

    /// Open one block in place.
    fn open(&self, block: &mut [u8; 16]) {
        use aes::cipher::BlockDecrypt as _;
        let cell = aes::cipher::generic_array::GenericArray::from_mut_slice(block.as_mut_slice());
        self.0.decrypt_block(cell);
    }
}

/// Cached per-user keys: instruction plus expanded auth-id schedule.
type CachedUserKeys = ([u8; 16], AuthKey);

/// Per-UUID table of [`CachedUserKeys`], bounded at 64 users (see [`cached_keys`]).
type UserKeyCache = std::collections::HashMap<[u8; 16], CachedUserKeys>;

/// The instruction key plus the auth-id key schedule for one user, cached.
///
/// Both derive from the user's UUID and nothing else: `instruction_key` is one
/// `MD5`, and `AuthKey::new` is one `KDF` (four `SHA256`) plus one `AES-128`
/// key expansion. They were recomputed per connection on both roles — per dial
/// on the client (`request_bytes`), per accept on the server (`accept_request`)
/// — for bytes that never change while the user does. A server with one user
/// handling 10k connections recomputed the same two values 10k times.
///
/// The cache is keyed by UUID and holds at most 64 users; beyond that it is
/// cleared rather than grown, so a peer that sends a fresh UUID per dial pays
/// recompute instead of this process paying unbounded memory. Clearing is
/// always correct — it only discards work that is redone — and legitimate
/// deployments (one or a few users) never reach it. The `Mutex` is per lookup,
/// ~0.1µs for a clone of 32 bytes, against ~5µs of `MD5` + `KDF` + expansion
/// it replaces.
fn cached_keys(uuid: &[u8; 16]) -> CachedUserKeys {
    static CACHE: OnceLock<Mutex<UserKeyCache>> = OnceLock::new();
    let mut guard = CACHE
        .get_or_init(|| Mutex::new(UserKeyCache::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(found) = guard.get(uuid) {
        return found.clone();
    }
    let instruction = instruction_key(uuid);
    let key = AuthKey::new(&instruction);
    let entry = (instruction, key);
    if guard.len() >= 64 {
        guard.clear();
    }
    guard.insert(*uuid, entry.clone());
    entry
}

/// Seal a header block under `AES-128-GCM`.
fn seal_header(key: &[u8; 16], nonce: &[u8; 12], plain: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let mut body = plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(nonce), aad, &mut body)
        .ok()?;
    body.extend_from_slice(&tag);
    Some(body)
}

/// Open a header block sealed the same way.
fn open_header(key: &[u8; 16], nonce: &[u8; 12], sealed: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    use aes_gcm::aead::AeadInPlace as _;
    use aes_gcm::KeyInit as _;
    if sealed.len() < TAG_LEN {
        return None;
    }
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).ok()?;
    let split = sealed.len() - TAG_LEN;
    let mut body = sealed[..split].to_vec();
    cipher
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(nonce),
            aad,
            &mut body,
            aes_gcm::Tag::from_slice(&sealed[split..]),
        )
        .ok()?;
    Some(body)
}

/// Response key and iv from the data key and iv.
fn response_material(data_iv: &[u8; 16], data_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    use sha2::Digest as _;
    let iv: [u8; 16] = sha2::Sha256::digest(data_iv)[..16].try_into().unwrap();
    let key: [u8; 16] = sha2::Sha256::digest(data_key)[..16].try_into().unwrap();
    (key, iv)
}

/// Sealed response prefix the server sends right after the request.
fn response_prefix(response_key: &[u8; 16], response_iv: &[u8; 16], auth: u8) -> Option<Vec<u8>> {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut out = seal_header(&len_key, &len_nonce, &[0, 4], &[])?;
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    out.extend_from_slice(&seal_header(&body_key, &body_nonce, &[auth, 0, 0, 0], &[])?);
    Some(out)
}

/// Fresh auth id for one request.
fn make_auth_id(key: &AuthKey) -> Option<[u8; 16]> {
    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&now_secs().to_be_bytes());
    if !random_into(&mut plain[8..12]) {
        return None;
    }
    let checksum = crc32(&plain[..12]).to_be_bytes();
    plain[12..].copy_from_slice(&checksum);
    key.seal(&mut plain);
    Some(plain)
}

/// Whether an auth id decrypts, checksums and sits inside the time window.
fn valid_auth_id(key: &AuthKey, auth_id: &[u8; 16]) -> bool {
    let mut plain = *auth_id;
    key.open(&mut plain);
    if crc32(&plain[..12]) != u32::from_be_bytes(plain[12..].try_into().unwrap()) {
        return false;
    }
    u64::from_be_bytes(plain[..8].try_into().unwrap()).abs_diff(now_secs()) <= 120
}

/// Length-masking `SHAKE128` stream, one per direction when negotiated.
struct Shake {
    /// Expanding reader seeded with that direction's iv.
    reader: sha3::Shake128Reader,
    /// Whether trailing padding lengths are drawn.
    padding: bool,
}

impl Shake {
    /// Seed the stream with a direction iv.
    fn fresh(iv: &[u8; 16], padding: bool) -> Self {
        use sha3::digest::{ExtendableOutput as _, Update as _};
        let mut shake = sha3::Shake128::default();
        shake.update(iv);
        Self {
            reader: shake.finalize_xof(),
            padding,
        }
    }
    /// Next two-byte draw.
    fn draw(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        sha3::digest::XofReader::read(&mut self.reader, &mut buf);
        u16::from_be_bytes(buf)
    }
    /// Padding length first, then the caller draws the mask.
    ///
    /// Test oracle only: the hot paths take both draws from
    /// [`Shake::pad_and_mask`] or [`Shake::draws`] in one squeeze, and this
    /// stays as the two-call spelling those are proved against.
    #[cfg(test)]
    fn pad_len(&mut self) -> u16 {
        if self.padding {
            self.draw() % 64
        } else {
            0
        }
    }
    /// Padding length and mask draw from a single four-byte squeeze.
    ///
    /// The `XOF` output is a byte stream, so one four-byte read is the same
    /// four bytes as two two-byte reads in order: the first two are the pad
    /// draw `pad_len` would take and the next two the mask draw `draw` would
    /// take. Same stream position afterwards, one call instead of two. When
    /// padding is off the pad draw takes no bytes, so this takes two —
    /// exactly what the two calls would have taken.
    fn pad_and_mask(&mut self, wire: u16) -> (usize, u16) {
        if self.padding {
            let mut buf = [0u8; 4];
            sha3::digest::XofReader::read(&mut self.reader, &mut buf);
            let pad = usize::from(u16::from_be_bytes([buf[0], buf[1]]) % 64);
            let mask = u16::from_be_bytes([buf[2], buf[3]]);
            (pad, mask ^ wire)
        } else {
            (0, self.draw() ^ wire)
        }
    }
    /// Raw pad and mask draws from a single squeeze, before the total is known.
    ///
    /// [`Shake::pad_and_mask`] takes the wire the mask is xored with, but the
    /// write path computes that wire *from* the padding — the total is the
    /// sealed length plus the padding — so it needs both draws first. Same
    /// bytes in the same order as the two calls, one squeeze instead of two;
    /// when padding is off the first half takes no bytes and is zero.
    fn draws(&mut self) -> (u16, u16) {
        if self.padding {
            let mut buf = [0u8; 4];
            sha3::digest::XofReader::read(&mut self.reader, &mut buf);
            (
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
            )
        } else {
            (0, self.draw())
        }
    }
}

/// One direction's data cipher plus its counter and optional masker.
pub(crate) struct Flow {
    /// Negotiated cipher for this direction.
    cipher: Cipher,
    /// `AES` cipher when negotiated.
    aes: Option<ferrox_core::aesgcm::Aes128Gcm>,
    /// `ChaCha20-Poly1305` key when negotiated.
    ///
    /// The key, not a cipher object: [`ferrox_core::aead`] takes the key and
    /// the nonce per frame and derives the `Poly1305` key itself, which is what
    /// `RFC 8439` section 2.6 asks for and what the crate did too. Holding an
    /// object here would mean holding state this path never reads.
    chacha: Option<[u8; 32]>,
    /// Direction iv, seeding nonces and masking.
    iv: [u8; 16],
    /// Frames sealed or opened so far.
    counter: u16,
    /// Masking stream when the peer negotiated it.
    shake: Option<Shake>,
}

impl Flow {
    /// Build a direction from the negotiated cipher, key, iv and options.
    fn fresh(
        cipher: Cipher,
        key: &[u8; 16],
        iv: &[u8; 16],
        options: u8,
        mask_seed: &[u8; 16],
    ) -> Option<Self> {
        let masking = options & OPT_MASK != 0;
        let padding = options & OPT_PAD != 0;
        let actual = match cipher {
            Cipher::Auto => Cipher::Chacha,
            other => other,
        };
        let (aes, chacha) = match actual {
            Cipher::Aes => (Some(ferrox_core::aesgcm::Aes128Gcm::new(key)), None),
            // `chacha_key` cannot fail: it is two `MD5`s into a `[u8; 32]`.
            Cipher::Chacha => (None, Some(chacha_key(key))),
            Cipher::None => (None, None),
            Cipher::Auto => return None,
        };
        let shake = masking.then(|| Shake::fresh(mask_seed, padding));
        Some(Self {
            cipher: actual,
            aes,
            chacha,
            iv: *iv,
            counter: 0,
            shake,
        })
    }
    /// Nonce for the current counter.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..2].copy_from_slice(&self.counter.to_be_bytes());
        nonce[2..].copy_from_slice(&self.iv[2..12]);
        nonce
    }
    /// Seal one plaintext slice onto `out`.
    fn seal_onto(&mut self, plain: &[u8], out: &mut Vec<u8>) -> bool {
        let at = out.len();
        out.extend_from_slice(plain);
        let sealed = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                // Sealed in place: `out[at..]` already holds the plaintext, and
                // the fused engine turns it into the ciphertext where it sits.
                let nonce = self.nonce();
                let tag = aes.seal_in_place(&nonce, b"", &mut out[at..]);
                out.extend_from_slice(&tag);
                true
            }
            (None, Some(key)) => {
                // Sealed in place: `out[at..]` already holds the plaintext, and
                // `C = P XOR keystream` means it does not have to be handed over
                // twice to be turned into the ciphertext that goes out.
                let nonce = self.nonce();
                let tag = ferrox_core::aead::chacha20_poly1305_seal_in_place(
                    key,
                    &nonce,
                    b"",
                    &mut out[at..],
                );
                out.extend_from_slice(&tag);
                true
            }
            (None, None) => true,
            _ => false,
        };
        if !sealed {
            out.truncate(at);
            return false;
        }
        if self.counter == u16::MAX {
            out.truncate(at);
            return false;
        }
        self.counter += 1;
        true
    }
    /// Open one sealed chunk in place, returning its plaintext length.
    fn open_chunk(&mut self, chunk: &mut [u8]) -> Option<usize> {
        let plain_len = match (&self.aes, &self.chacha) {
            (Some(aes), None) => {
                if chunk.len() < TAG_LEN {
                    return None;
                }
                let nonce = self.nonce();
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                // `split` is `chunk.len() - TAG_LEN`, so `tag` is exactly
                // sixteen bytes; `try_into` is the check that says so rather
                // than an assertion.
                let tag: &[u8; TAG_LEN] = <&[u8; TAG_LEN]>::try_from(&*tag).ok()?;
                aes.open_in_place(&nonce, b"", body, tag)?;
                split
            }
            (None, Some(key)) => {
                if chunk.len() < TAG_LEN {
                    return None;
                }
                let nonce = self.nonce();
                let split = chunk.len() - TAG_LEN;
                let (body, tag) = chunk.split_at_mut(split);
                // `split` is `chunk.len() - TAG_LEN`, so `tag` is exactly
                // sixteen bytes; `try_into` is the check that says so rather
                // than an assertion.
                let tag: &[u8; TAG_LEN] = <&[u8; TAG_LEN]>::try_from(&*tag).ok()?;
                ferrox_core::aead::chacha20_poly1305_decrypt_in_place(
                    key, &nonce, b"", body, tag,
                )?;
                split
            }
            (None, None) => chunk.len(),
            _ => return None,
        };
        if self.counter == u16::MAX {
            return None;
        }
        self.counter += 1;
        Some(plain_len)
    }
}

/// Encode port plus address in the order the header carries them.
fn encode_target(out: &mut Vec<u8>, target: &SocketAddr) {
    out.extend_from_slice(&target.port().to_be_bytes());
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
}

/// Decode the same encoding, resolving domain names where they appear.
fn decode_target(header: &[u8], cursor: &mut usize) -> Option<SocketAddr> {
    if *cursor + 3 > header.len() {
        return None;
    }
    let port = u16::from_be_bytes([header[*cursor], header[*cursor + 1]]);
    *cursor += 2;
    match header[*cursor] {
        1 => {
            *cursor += 1;
            if *cursor + 4 > header.len() {
                return None;
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&header[*cursor..*cursor + 4]);
            *cursor += 4;
            Some(SocketAddr::new(std::net::IpAddr::V4(ip.into()), port))
        }
        2 => {
            *cursor += 1;
            let len = usize::from(*header.get(*cursor)?);
            *cursor += 1;
            if *cursor + len > header.len() {
                return None;
            }
            let host = std::str::from_utf8(&header[*cursor..*cursor + len]).ok()?;
            *cursor += len;
            format!("{host}:{port}").to_socket_addrs().ok()?.next()
        }
        3 => {
            *cursor += 1;
            if *cursor + 16 > header.len() {
                return None;
            }
            let ip: [u8; 16] = header[*cursor..*cursor + 16].try_into().unwrap();
            *cursor += 16;
            Some(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port))
        }
        _ => None,
    }
}

/// Request bytes plus the session keys they were sealed under.
type RequestParts = (Vec<u8>, [u8; 16], [u8; 16], u8);

/// Build a client request and its session keys, for one command.
fn request_bytes(
    uuid: &[u8; 16],
    cipher: Cipher,
    target: &SocketAddr,
    cmd: u8,
) -> Option<RequestParts> {
    // Cached per user: the instruction is one `MD5` and the auth key one `KDF`
    // plus one `AES` expansion, all of the UUID and nothing else.
    let (instruction, auth_key) = cached_keys(uuid);
    let auth_id = make_auth_id(&auth_key)?;
    // One entropy call for every fixed field: six calls here used to mean six
    // syscalls per dial, all for bytes one call already returns uniformly.
    let mut rand = [0u8; 16 + 16 + 1 + 8 + 1];
    if !random_into(&mut rand) {
        return None;
    }
    let mut data_iv = [0u8; 16];
    let mut data_key = [0u8; 16];
    data_iv.copy_from_slice(&rand[..16]);
    data_key.copy_from_slice(&rand[16..32]);
    let auth = [rand[32]];
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&rand[33..41]);
    let pad_len = usize::from(rand[41] % 16);
    let options = OPT_STREAM | OPT_MASK | OPT_PAD;
    let mut clear = Vec::with_capacity(64);
    clear.push(1);
    clear.extend_from_slice(&data_iv);
    clear.extend_from_slice(&data_key);
    clear.push(auth[0]);
    clear.push(options);
    clear.push((pad_len as u8) << 4 | cipher.code());
    clear.push(0);
    clear.push(cmd);
    encode_target(&mut clear, target);
    if pad_len > 0 {
        // Stack, not heap: the old per-request `Vec` allocated to hold bytes
        // nobody reads, then zeroed them just to overwrite them with random.
        let mut pad = [0u8; 15];
        if !random_into(&mut pad[..pad_len]) {
            return None;
        }
        clear.extend_from_slice(&pad[..pad_len]);
    }
    clear.extend_from_slice(&fnv1a(&clear).to_be_bytes());
    let len_key = kdf16(
        &instruction,
        &[b"VMess Header AEAD Key_Length", &auth_id, &nonce],
    );
    let len_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce_Length", &auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let sealed_len = seal_header(
        &len_key,
        &len_nonce,
        &(clear.len() as u16).to_be_bytes(),
        &auth_id,
    )?;
    let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, &nonce]);
    let head_full = kdf(
        &instruction,
        &[b"VMess Header AEAD Nonce", &auth_id, &nonce],
    );
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    let sealed_head = seal_header(&head_key, &head_nonce, &clear, &auth_id)?;
    let mut request = Vec::with_capacity(16 + 18 + 8 + sealed_head.len());
    request.extend_from_slice(&auth_id);
    request.extend_from_slice(&sealed_len);
    request.extend_from_slice(&nonce);
    request.extend_from_slice(&sealed_head);
    Some((request, data_key, data_iv, auth[0]))
}

/// Read one sealed length plus its padding draws.
fn read_wire_len(stream: &mut dyn Read, shake: Option<&mut Shake>) -> Option<(usize, usize)> {
    let mut prefix = [0u8; 2];
    read_exact(stream, &mut prefix).ok()?;
    let wire = u16::from_be_bytes(prefix);
    match shake {
        None => Some((usize::from(wire), 0)),
        Some(sizes) => {
            let (padding, total) = sizes.pad_and_mask(wire);
            Some((usize::from(total), padding))
        }
    }
}

/// Write one data frame carrying `plain`, in a single write.
///
/// `staging` is the caller's buffer, reused across frames: this used to build a
/// fresh `Vec` per frame, so every 8 KB frame cost one allocation on the way out
/// as well as on the way in. The `AEAD` interface encrypts *in place*, so the
/// plaintext still has to be laid down in a buffer the cipher owns — that copy is
/// the interface's, not this function's — but it is now a copy into a warm buffer
/// rather than a copy into a cold one.
///
/// The wire length rides in front of the sealed body in the same buffer, and the
/// padding rides behind it, so the three `write_all` calls this used to make —
/// length, body, padding — are one `write_all` of one contiguous buffer. Three
/// syscalls per frame on a socket, where each is ~1µs and an 8 KB seal is ~4µs;
/// for 100-byte frames the syscalls were 95% of the frame. The bytes are the
/// same three slices concatenated, so a peer that read them as three reads sees
/// the same stream; on a message-framed carrier the single write plus the flush
/// below is still one message per frame, exactly as before.
///
/// `pad` is the caller's batched randomness (see [`PadSource`]): the padding
/// bytes are still fresh `getrandom` bytes per frame, just drawn from a batch
/// rather than a syscall each.
pub(crate) fn write_frame(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    staging.clear();
    if !stage_frame(send, plain, staging, pad) {
        return false;
    }
    write_frames(stream, staging)
}

/// Append one data frame carrying `plain` to `staging`, which must be empty.
///
/// Split from the `write` so that several frames can be staged and sent in one
/// call — see [`stage_frames`]. The frame is `len` (2 bytes), sealed body, tag,
/// padding, laid out in one buffer: the same bytes in the same order as the
/// three separate `write_all`s this replaced.
fn stage_frame(send: &mut Flow, plain: &[u8], staging: &mut Vec<u8>, pad: &mut PadSource) -> bool {
    // `at` is where this frame starts and `body` where its ciphertext starts. The
    // two bytes between them hold the length, which is not known until the padding
    // has been drawn and is written into them afterwards — at *this frame's* two
    // bytes, so a second frame in the same buffer does not overwrite the first's.
    let at = staging.len();
    let body = at + 2;
    // Two placeholder bytes for the wire length. `seal_onto` appends after them
    // (`at = out.len()`), so they are never encrypted — they are the length
    // prefix, not the body.
    staging.extend_from_slice(&[0u8; 2]);
    if !send.seal_onto(plain, staging) {
        staging.truncate(at);
        return false;
    }
    let encrypted = staging.len() - body;
    let (padding, mask_raw, masked) = match send.shake.as_mut() {
        None => (0, 0, false),
        Some(s) => {
            let (pad_raw, mask_raw) = s.draws();
            (usize::from(pad_raw % 64), mask_raw, true)
        }
    };
    let total = encrypted + padding;
    if total > u16::MAX as usize {
        staging.truncate(at);
        return false;
    }
    let wire = if masked {
        mask_raw ^ total as u16
    } else {
        total as u16
    };
    staging[at..body].copy_from_slice(&wire.to_be_bytes());
    if padding > 0 {
        let Some(bytes) = pad.take(padding) else {
            staging.truncate(at);
            return false;
        };
        staging.extend_from_slice(bytes);
    }
    true
}

/// Stage up to [`FRAMES_PER_WRITE`] frames from `plain` and send them in one
/// `write`.
///
/// # Why several frames go out together
///
/// The `write` above costs the same whether it carries one frame or eight — on
/// this machine ~2.2 µs on a socket with a reader on the other end, measured at
/// every length from 2 bytes to 8 KB — so what a frame pays is per *frame* rather
/// than per byte. Four frames of 8 KB in one call measured 12269 ns a frame
/// against 14836 written one at a time, and four frames of 1500 B measured 3504
/// against 4904.
///
/// The byte stream is what makes this safe: a frame is `len || sealed || pad` and
/// the reader is a byte reader, so `[frame][frame]` in one `write` and in two are
/// the same bytes in the same order. Nothing on the wire changes and nothing can
/// tell, which is the property the length-masked framing already relies on. It is
/// the same reason [`write_frame`] could stop writing three times.
///
/// The batch is flushed as soon as the plaintext runs out, so a connection
/// carrying a byte at a time still writes a frame per byte: only a source that
/// arrives faster than the seal does gets more than one frame per syscall.
fn stage_frames(
    stream: &mut dyn Write,
    send: &mut Flow,
    plain: &[u8],
    staging: &mut Vec<u8>,
    pad: &mut PadSource,
) -> bool {
    staging.clear();
    // An empty run still carries one frame: `write_frame` sends an empty frame for
    // the close signal, and a batch that dropped it would make the two paths
    // disagree about what "no plaintext" means.
    if plain.is_empty() {
        if !stage_frame(send, plain, staging, pad) {
            return false;
        }
    } else {
        let mut rest = plain;
        for _ in 0..FRAMES_PER_WRITE {
            let (frame, tail) = rest.split_at(MAX_PLAIN.min(rest.len()));
            if !stage_frame(send, frame, staging, pad) {
                return false;
            }
            rest = tail;
            if rest.is_empty() {
                break;
            }
        }
    }
    if staging.is_empty() {
        return true;
    }
    write_frames(stream, staging)
}

/// Send everything staged, in one `write` and one `flush`.
///
/// The flush is what makes the carrier's message boundary the batch boundary on a
/// message-framed carrier, which is what the peer's reader expects: it reads a
/// byte stream out of the messages and never looks at the boundary.
fn write_frames(stream: &mut dyn Write, staging: &[u8]) -> bool {
    if stream.write_all(staging).is_err() {
        return false;
    }
    stream.flush().is_ok()
}

/// Read one data frame into `scratch`, returning its plaintext length.
///
/// This is the hot read of the protocol and it used to do three things per frame
/// that no frame needed. It allocated a zeroed buffer of the frame's length — a
/// full-length memset of bytes that the very next `read_exact` overwrites
/// wholesale, so on an 8 KB frame eight kilobytes were written twice. It then
/// decrypted in place into that buffer and *allocated a second buffer and copied
/// the plaintext out of it*, so the plaintext was moved once for no reason. And a
/// padding-only frame allocated a third, to hold bytes it was about to discard.
///
/// `scratch` is the caller's, reused: after the first frame at a given length
/// there is no allocation and no memset. The resize is the only memset left and it
/// runs only when a frame is longer than every frame before it.
///
/// The return is a *borrow of `scratch`*, which is the part that matters: a
/// function that returns `&'a [u8]` tied to `&'a mut Vec<u8>` cannot also have
/// copied the plaintext somewhere, because there is nowhere to return it from. The
/// copy that used to be here was not caught by a test asserting on buffer
/// identity — it was caught by changing the return type, which is what a claim
/// worth making should look like.
pub(crate) fn read_frame<'a>(
    stream: &mut dyn Read,
    recv: &mut Flow,
    scratch: &'a mut Vec<u8>,
) -> Option<&'a [u8]> {
    let (total, padding) = read_wire_len(stream, recv.shake.as_mut())?;
    if total <= padding {
        // Padding with no payload: read it to stay in step and keep none of it.
        let mut discard = [0u8; 64];
        let mut left = total;
        while left > 0 {
            let take = left.min(discard.len());
            read_exact(stream, &mut discard[..take]).ok()?;
            left -= take;
        }
        scratch.clear();
        return Some(&scratch[..0]);
    }
    if total - padding
        < match recv.cipher {
            Cipher::None => 0,
            _ => TAG_LEN,
        }
    {
        return None;
    }
    if scratch.len() < total {
        scratch.resize(total, 0);
    }
    read_exact(stream, &mut scratch[..total]).ok()?;
    let payload = total - padding;
    let len = recv.open_chunk(&mut scratch[..payload])?;
    Some(&scratch[..len])
}

/// Client session: both directions plus the response keys to consume.
pub(crate) type ClientSession = (Flow, Flow, [u8; 16], [u8; 16], u8);

/// Request bytes plus the session they were sealed under, for dialing.
pub(crate) type ClientRequest = (Vec<u8>, Flow, Flow, [u8; 16], [u8; 16], u8);

/// Request bytes plus the session they were sealed under, for dialing.
///
/// [`client_handshake`] writes the request to the socket itself; a carried
/// dial has no socket yet, only the carrier halves, so this returns the
/// request to send through the carrier and the session around it. The caller
/// answers with [`read_response`] through the carrier's reader before the
/// relay starts, exactly as [`client_handshake`]'s caller does on the socket.
pub(crate) fn client_request(
    id: &[u8; 16],
    cipher: Cipher,
    target: &SocketAddr,
    cmd: u8,
) -> Option<ClientRequest> {
    let (request, data_key, data_iv, auth) = request_bytes(id, cipher, target, cmd)?;
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let options = OPT_STREAM | OPT_MASK | OPT_PAD;
    let actual = match cipher {
        Cipher::Auto => Cipher::Chacha,
        other => other,
    };
    let send = Flow::fresh(actual, &data_key, &data_iv, options, &data_iv)?;
    let recv = Flow::fresh(actual, &response_key, &response_iv, options, &response_iv)?;
    Some((request, send, recv, response_key, response_iv, auth))
}

/// Dial a `VMess` server for a target, returning the two directions.
pub(crate) fn client_handshake(
    uplink: &mut TcpStream,
    id: &[u8; 16],
    cipher: Cipher,
    target: &SocketAddr,
) -> Option<ClientSession> {
    let (request, send, recv, response_key, response_iv, auth) =
        client_request(id, cipher, target, 1)?;
    if uplink.write_all(&request).is_err() {
        return None;
    }
    Some((send, recv, response_key, response_iv, auth))
}

/// Read and check the server's response header on a client stream.
pub(crate) fn read_response(
    stream: &mut dyn Read,
    response_key: &[u8; 16],
    response_iv: &[u8; 16],
    auth: u8,
) -> bool {
    let len_key = kdf16(response_key, &[b"AEAD Resp Header Len Key"]);
    let len_full = kdf(response_iv, &[b"AEAD Resp Header Len IV"]);
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    if read_exact(stream, &mut sealed_len).is_err() {
        return false;
    }
    let Some(clear_len) = open_header(&len_key, &len_nonce, &sealed_len, &[]) else {
        return false;
    };
    if clear_len.len() != 2 {
        return false;
    }
    let body_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if body_len > 64 {
        return false;
    }
    let mut sealed_body = vec![0u8; body_len + TAG_LEN];
    if read_exact(stream, &mut sealed_body).is_err() {
        return false;
    }
    let body_key = kdf16(response_key, &[b"AEAD Resp Header Key"]);
    let body_full = kdf(response_iv, &[b"AEAD Resp Header IV"]);
    let body_nonce: [u8; 12] = body_full[..12].try_into().unwrap();
    let Some(clear_body) = open_header(&body_key, &body_nonce, &sealed_body, &[]) else {
        return false;
    };
    clear_body.len() == 4 && clear_body[0] == auth
}

/// Read and open one sealed request header, returning its clear bytes.
fn read_open_header(
    stream: &mut dyn Read,
    instruction: &[u8; 16],
    auth_id: &[u8; AUTH_LEN],
) -> Option<Vec<u8>> {
    let mut sealed_len = [0u8; 2 + TAG_LEN];
    read_exact(stream, &mut sealed_len).ok()?;
    let mut nonce = [0u8; 8];
    read_exact(stream, &mut nonce).ok()?;
    let len_key = kdf16(
        instruction,
        &[b"VMess Header AEAD Key_Length", auth_id, &nonce],
    );
    let len_full = kdf(
        instruction,
        &[b"VMess Header AEAD Nonce_Length", auth_id, &nonce],
    );
    let len_nonce: [u8; 12] = len_full[..12].try_into().unwrap();
    let clear_len = open_header(&len_key, &len_nonce, &sealed_len, auth_id)?;
    if clear_len.len() != 2 {
        return None;
    }
    let head_len = usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]]));
    if !(38..=4096).contains(&head_len) {
        return None;
    }
    let mut sealed_head = vec![0u8; head_len + TAG_LEN];
    read_exact(stream, &mut sealed_head).ok()?;
    let head_key = kdf16(instruction, &[b"VMess Header AEAD Key", auth_id, &nonce]);
    let head_full = kdf(instruction, &[b"VMess Header AEAD Nonce", auth_id, &nonce]);
    let head_nonce: [u8; 12] = head_full[..12].try_into().unwrap();
    open_header(&head_key, &head_nonce, &sealed_head, auth_id)
}
/// Decode clear header bytes into its target, flows, response prefix and command.
fn decode_header(header: &[u8]) -> Option<(SocketAddr, Flow, Flow, Vec<u8>, u8)> {
    if header.len() < 38 || header[0] != 1 || header[34] & OPT_STREAM == 0 {
        return None;
    }
    let cmd = header[37];
    if cmd != 1 && cmd != 2 {
        return None;
    }
    let cipher = Cipher::from_code(header[35] & 0x0f)?;
    let options = header[34];
    let mut cursor = 38;
    let target = decode_target(header, &mut cursor)?;
    let margin = usize::from(header[35] >> 4);
    if cursor + margin + 4 > header.len() {
        return None;
    }
    cursor += margin;
    if fnv1a(&header[..cursor])
        != u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap())
    {
        return None;
    }
    let data_iv: [u8; 16] = header[1..17].try_into().unwrap();
    let data_key: [u8; 16] = header[17..33].try_into().unwrap();
    let auth = header[33];
    let (response_key, response_iv) = response_material(&data_iv, &data_key);
    let prefix = response_prefix(&response_key, &response_iv, auth)?;
    let recv = Flow::fresh(cipher, &data_key, &data_iv, options, &data_iv)?;
    let send = Flow::fresh(cipher, &response_key, &response_iv, options, &response_iv)?;
    Some((target, send, recv, prefix, cmd))
}
/// Read and check one request, returning its target, both directions and command.
fn accept_request(
    stream: &mut dyn Read,
    id: &[u8; 16],
) -> Option<(SocketAddr, Flow, Flow, Vec<u8>, u8)> {
    let mut auth_id = [0u8; AUTH_LEN];
    read_exact(stream, &mut auth_id).ok()?;
    // Cached per user, as on the client: the same UUID maps to the same
    // instruction and the same expanded key, every connection.
    let (instruction, auth_key) = cached_keys(id);
    if !valid_auth_id(&auth_key, &auth_id) || replay_seen(&auth_id) {
        return None;
    }
    let header = read_open_header(stream, &instruction, &auth_id)?;
    decode_header(&header)
}

/// A [`Write`] sink that turns each flush into one `WebSocket` binary message.
///
/// `VMess` frames are written as several `write_all` calls — length, body,
/// padding — and the `ws` carrier is message-framed rather than byte-framed, so
/// without this each of those calls would become its own message and a single
/// frame would arrive as three. Buffering until `flush` makes the carrier's
/// message boundary the frame boundary, which is what the peer's reader expects:
/// it reads a byte stream out of the messages and never looks at the boundary.
///
/// `pub(crate)` because the carried dial builds its sink where the
/// carrier is known, one module over.
pub(crate) struct WsSink {
    /// Carrier the message goes out through.
    writer: crate::ws::WsWriter,
    /// Bytes written since the last flush, one message's worth.
    staged: Vec<u8>,
}

impl WsSink {
    /// One message per relay read: a read stages at most [`FRAMES_PER_WRITE`]
    /// frames, so the message boundary stays the batch boundary.
    pub(crate) fn carried(writer: crate::ws::WsWriter) -> Self {
        Self {
            writer,
            staged: Vec::with_capacity(READ_PLAIN + FRAMES_PER_WRITE * (TAG_LEN + 2 + 64)),
        }
    }
}

impl std::io::Write for WsSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.staged.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.staged.is_empty() {
            return Ok(());
        }
        let sent = self.writer.send(&self.staged);
        self.staged.clear();
        if sent {
            Ok(())
        } else {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
    }
}

/// Relay sealed both ways where the sealed side is a carrier rather than a
/// socket.
///
/// The frame logic is [`pump_relay`]'s, unchanged: `read_frame` and
/// `write_frame` take `dyn Read` and `dyn Write`, so the carrier substitutes for
/// the socket and nothing above them can tell which it was. What differs is only
/// the plumbing — a carrier has a reader half and a writer half rather than one
/// object that clones four ways, and closing it is a close frame (or a zero
/// chunk, or a shutdown) instead of a `shutdown`.
///
/// `writer` is the whole write side, moved into the uplink thread that owns it.
/// `close` runs at both ends because either direction can end first, so it must
/// be idempotent — every carrier's close is — and shared, because the thread
/// that did not take `writer` still has to be able to end the carrier.
pub(crate) fn pump_relay_carried<R, W>(
    plain: &TcpStream,
    mut reader: R,
    mut writer: W,
    close: &std::sync::Arc<dyn Fn() + Send + Sync>,
    send: Flow,
    recv: Flow,
) where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut plain_write = plain_write;

    let mut send = send;
    let thread_close = std::sync::Arc::clone(close);
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; READ_PLAIN];
        // Every frame of one read — `FRAMES_PER_WRITE` of them, each a `MAX_PLAIN`
        // body plus its two-byte wire prefix, tag and up to 63 bytes of padding.
        // Nothing here grows per frame.
        let batched = READ_PLAIN + FRAMES_PER_WRITE * (TAG_LEN + 2 + 64);
        let mut staging = Vec::with_capacity(batched);
        let Some(mut pad) = PadSource::fresh() else {
            return;
        };
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                let _ = write_frame(&mut writer, &mut send, &[], &mut staging, &mut pad);
                break;
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + READ_PLAIN).min(read);
                if !stage_frames(
                    &mut writer,
                    &mut send,
                    &buf[at..end],
                    &mut staging,
                    &mut pad,
                ) {
                    ok = false;
                    break;
                }
                at = end;
            }
            if !ok {
                break;
            }
        }
        thread_close();
        let _ = plain_read.shutdown(Shutdown::Both);
    });

    let mut recv = recv;
    let mut scratch = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 64);
    while let Some(chunk) = read_frame(&mut reader, &mut recv, &mut scratch) {
        if chunk.is_empty() || plain_write.write_all(chunk).is_err() {
            break;
        }
    }
    close();
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

/// Accept one `VMess` connection inside a `ws` carrier, dial and relay.
///
/// The header is a hundred bytes or so of sealed material behind an eight-byte
/// auth id, so it is read to the byte and never to the packet: the carrier's
/// reader is a byte stream over messages, and a short read here is a hang wearing
/// a successful handshake.
pub(crate) fn serve_ws(stream: TcpStream, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, writer)) = crate::ws::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if !writer.send(&prefix) {
        return;
    }
    // One batch per message: the sink's staging is what makes the message
    // boundary the batch boundary, exactly as before this pump took a sink.
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, WsSink::carried(writer), &close, send, recv);
}

/// Accept one `VMess` connection inside a `gRPC` tunnel, dial and relay.
pub(crate) fn serve_grpc(stream: TcpStream, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, writer)) = crate::grpc::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if !writer.send(&prefix) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || closer.close());
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Accept one `VMess` connection inside an `XHTTP` carrier, dial and relay.
///
/// The chunked bodies are a byte stream, so this is [`serve_ws`]'s shape with
/// the upload writer in place of the message sink: no per-message staging,
/// because there are no messages. The download is buffered for the same reason the raw path is —
/// the two-byte wire prefix and the body it names should come from one syscall
/// when they arrive together, not one syscall for two bytes and another for
/// the body.
pub(crate) fn serve_xhttp(stream: TcpStream, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, writer)) = crate::xhttp::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if !writer.send(&prefix) {
        return;
    }
    let closer = writer.clone();
    let close: std::sync::Arc<dyn Fn() + Send + Sync> =
        std::sync::Arc::new(move || closer.finish());
    let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
    pump_relay_carried(&uplink, reader, writer, &close, send, recv);
}

/// Accept one `VMess` connection behind the `HTTP` camouflage, dial and relay.
///
/// Past the `GET` and the `200` this is raw bytes both ways, so the write side
/// is the socket itself and the close is a shutdown — [`pump_relay`]'s shape
/// over the carrier's reader.
pub(crate) fn serve_httpheader(stream: TcpStream, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, write)) = crate::httpheader::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    let Ok(down) = write.try_clone() else {
        return;
    };
    let mut down = down;
    if down.write_all(&prefix).is_err() {
        return;
    }
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, write, &close, send, recv);
}

/// Accept one `VMess` connection past the `HTTPUpgrade` `101`, dial and relay.
pub(crate) fn serve_httpupgrade(stream: TcpStream, path: &str, id: &[u8; 16], freedom: bool) {
    let Some((mut reader, write)) = crate::httpupgrade::accept(stream, path) else {
        return;
    };
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut reader, id) else {
        return;
    };
    if !freedom || cmd != 1 {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    let Ok(down) = write.try_clone() else {
        return;
    };
    let mut down = down;
    if down.write_all(&prefix).is_err() {
        return;
    }
    let Ok(closer) = write.try_clone() else {
        return;
    };
    let close: std::sync::Arc<dyn Fn() + Send + Sync> = std::sync::Arc::new(move || {
        let _ = closer.shutdown(Shutdown::Both);
    });
    pump_relay_carried(&uplink, reader, write, &close, send, recv);
}

/// Accept one `VMess` connection, dial its target and relay sealed both ways.
pub(crate) fn serve(mut stream: TcpStream, id: &[u8; 16], freedom: bool) {
    let Some((target, send, recv, prefix, cmd)) = accept_request(&mut stream, id) else {
        return;
    };
    if !freedom {
        return;
    }
    if cmd == 2 {
        return serve_vmess_udp(stream, &target, send, recv, &prefix);
    }
    if cmd != 1 {
        return;
    }
    let Ok(uplink) = TcpStream::connect_timeout(&target, Duration::from_secs(8)) else {
        return;
    };
    if stream.write_all(&prefix).is_err() {
        return;
    }
    pump_relay(&uplink, &stream, send, recv, None);
}

/// Serve one `VMess` `UDP` flow over raw `TCP`: dial the target, answer the
/// response prefix, then pump sealed datagram frames both ways.
///
/// One sealed frame per datagram each way, which is the packet-mode framing
/// every peer writes: the length mask delimits frames, so no extra prefix is
/// needed and none is added. The target is fixed by the header, so like the
/// `VLESS` pump there is nothing to re-dial.
pub(crate) fn serve_vmess_udp(
    stream: TcpStream,
    target: &SocketAddr,
    send: Flow,
    recv: Flow,
    prefix: &[u8],
) {
    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(udp) = UdpSocket::bind(bind) else {
        return;
    };
    if udp.connect(target).is_err() {
        return;
    }
    let mut stream = stream;
    if stream.write_all(prefix).is_err() {
        return;
    }
    crate::proxy::pump_vmess_udp(&stream, &udp, send, recv);
}

/// Response keys the client still has to consume, read on first reply.
pub(crate) type PendingResponse = ([u8; 16], [u8; 16], u8);

/// Relay plaintext one side against sealed frames the other, both ways to close.
pub(crate) fn pump_relay(
    plain: &TcpStream,
    sealed: &TcpStream,
    send: Flow,
    recv: Flow,
    pending: Option<PendingResponse>,
) {
    let Ok(plain_read) = plain.try_clone() else {
        return;
    };
    let Ok(sealed_write) = sealed.try_clone() else {
        return;
    };
    let Ok(sealed_read) = sealed.try_clone() else {
        return;
    };
    let Ok(plain_write) = plain.try_clone() else {
        return;
    };
    let mut plain_read = plain_read;
    let mut sealed_write = sealed_write;
    let sealed_read = sealed_read;
    let mut plain_write = plain_write;
    let mut send = send;
    let done = thread::spawn(move || {
        let mut buf = vec![0u8; READ_PLAIN];
        // Both of these outlive the loop on purpose: the staging buffer holds every
        // frame of one read — `FRAMES_PER_WRITE` of them, each a `MAX_PLAIN` body
        // plus its two-byte wire prefix, tag and up to 63 bytes of padding — and one
        // batch of padding randomness is enough for every frame this connection
        // sends. Nothing here grows per frame.
        let mut staging = Vec::with_capacity(READ_PLAIN + FRAMES_PER_WRITE * (TAG_LEN + 2 + 64));
        let Some(mut pad) = PadSource::fresh() else {
            return;
        };
        while let Ok(read) = plain_read.read(&mut buf) {
            if read == 0 {
                let _ = write_frame(&mut sealed_write, &mut send, &[], &mut staging, &mut pad);
                break;
            }
            let mut at = 0;
            let mut ok = true;
            while at < read {
                let end = (at + READ_PLAIN).min(read);
                if !stage_frames(
                    &mut sealed_write,
                    &mut send,
                    &buf[at..end],
                    &mut staging,
                    &mut pad,
                ) {
                    ok = false;
                    break;
                }
                at = end;
            }
            if !ok {
                break;
            }
        }
        let _ = plain_read.shutdown(Shutdown::Both);
        let _ = sealed_write.shutdown(Shutdown::Both);
    });
    let mut recv = recv;
    // Buffered so the two-byte wire prefix and the body it names come from one
    // syscall when they arrive together — which they do, because `write_frame`
    // sends them as one write. Unbuffered, every frame paid a syscall for two
    // bytes and another for the body; for 100-byte frames that was 95% of the
    // read path. The buffer adds a copy (into `scratch` via the buffer), but a
    // 16 KB copy is ~0.8µs and the syscall it removes is ~1µs — and one syscall
    // now serves ~160 hundred-byte frames instead of half of one.
    let mut sealed_reader = std::io::BufReader::with_capacity(16 * 1024, sealed_read);
    if let Some((response_key, response_iv, auth)) = pending {
        if !read_response(&mut sealed_reader, &response_key, &response_iv, auth) {
            let _ = sealed_reader.get_ref().shutdown(Shutdown::Both);
            let _ = plain_write.shutdown(Shutdown::Both);
            let _ = done.join();
            return;
        }
    }
    // One buffer for every frame this connection receives, decrypted where it
    // lands and written straight out from there.
    let mut scratch = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 64);
    while let Some(chunk) = read_frame(&mut sealed_reader, &mut recv, &mut scratch) {
        if chunk.is_empty() || plain_write.write_all(chunk).is_err() {
            break;
        }
    }
    let _ = sealed_reader.get_ref().shutdown(Shutdown::Both);
    let _ = plain_write.shutdown(Shutdown::Both);
    let _ = done.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn instruction_splits_uuid_and_magic() {
        let uuid = [0x11u8; 16];
        assert_ne!(instruction_key(&uuid), uuid);
        assert_eq!(instruction_key(&uuid), instruction_key(&uuid));
    }

    #[test]
    fn auth_ids_round_trip_and_reject_damage() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = AuthKey::new(&instruction);
        let id = make_auth_id(&key).expect("makes");
        assert!(valid_auth_id(&key, &id));
        let mut bad = id;
        bad[0] ^= 1;
        assert!(!valid_auth_id(&key, &bad));
    }

    #[test]
    fn headers_open_that_seal_sealed() {
        let key = [0x33u8; 16];
        let nonce = [0x44u8; 12];
        let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
        let back = open_header(&key, &nonce, &sealed, b"aad").expect("opens");
        assert_eq!(back, b"length-is-framing");
        let mut cut = sealed.clone();
        cut.pop();
        assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
    }

    #[test]
    fn frames_carry_an_echo_both_ways() {
        let cipher = Cipher::Chacha;
        let key = [0x55u8; 16];
        let iv = [0x66u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let writer = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut scratch = Vec::new();
            let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
            chunk.to_vec()
        });
        let mut reader = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(write_frame(
            &mut reader,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        assert_eq!(writer.join().expect("joins"), b"ping");
    }

    /// `VMess` inside the `ws` carrier, both roles, end to end.
    ///
    /// This is the row that could not be carried before: the framing was written
    /// against `&mut TcpStream` at every level, so a `ws` listener had no path
    /// into it. The request is a sealed header, not a fixed-size prologue, so the
    /// carrier's reader has to hand it over to the byte — a short read here is a
    /// hang wearing a successful handshake, which is exactly what the raw-`TCP`
    /// oracle reported when it pointed this binary at a `ws` listener.
    #[test]
    fn vmess_carries_over_the_ws_carrier_both_ways() {
        // An echo server to be the tunnel target.
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });

        let id = [0x5au8; 16];
        let path = "/vmess-ws";
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let server_id = id;
        let server_path = path.to_string();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_ws(stream, &server_path, &server_id, true);
        });

        // Client side: the same handshake the socket path builds, sent as ws
        // messages instead of written to the socket.
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, writer) =
            crate::ws::connect(stream, &format!("127.0.0.1:{port}"), path, 0, &[])
                .expect("carries");

        let (request, data_key, data_iv, auth) =
            request_bytes(&id, Cipher::Chacha, &target, 1).expect("request");
        assert!(writer.send(&request), "request goes out as one message");

        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(
            read_response(&mut reader, &response_key, &response_iv, auth),
            "the server's response header opens over the carrier"
        );

        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");

        let mut sink = WsSink {
            writer: writer.clone(),
            staged: Vec::new(),
        };
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();

        assert!(
            write_frame(&mut sink, &mut send, b"ping", &mut staging, &mut pad),
            "a sealed frame goes out over the carrier"
        );
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping", "the echo came back through the carrier");
    }

    /// `VMess` over one byte-stream carrier, both roles, end to end.
    ///
    /// `serve` accepts one carrier connection and serves `VMess` on it;
    /// `connect` dials the same carrier back as boxed halves, so this one
    /// function covers every carrier whose reader is a byte stream. The
    /// handshake and one sealed frame go through the carrier exactly as they
    /// go through the socket: the same [`request_bytes`], the same
    /// [`read_response`], the same sealed `ping` and its echo.
    fn vmess_over_byte_carrier(
        path: &str,
        serve: impl FnOnce(TcpStream, [u8; 16]) + Send + 'static,
        connect: impl FnOnce(TcpStream) -> Option<(Box<dyn Read + Send>, Box<dyn Write + Send>)>,
    ) {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });

        let id = [0x5au8; 16];
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve(stream, id);
        });

        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) = connect(stream).expect("carries");

        let (request, data_key, data_iv, auth) =
            request_bytes(&id, Cipher::Chacha, &target, 1).expect("request");
        writer.write_all(&request).expect("requests");
        writer.flush().expect("flushes");

        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(
            read_response(&mut reader, &response_key, &response_iv, auth),
            "the server's response header opens over {path}"
        );

        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");

        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();
        assert!(
            write_frame(&mut writer, &mut send, b"ping", &mut staging, &mut pad),
            "a sealed frame goes out over {path}"
        );
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping", "the echo came back through {path}");
    }

    #[test]
    fn vmess_carries_over_the_xhttp_carrier_both_ways() {
        vmess_over_byte_carrier(
            "/vmess-xhttp",
            |stream, id| serve_xhttp(stream, "/vmess-xhttp", &id, true),
            |stream| {
                let (reader, writer) = crate::xhttp::connect(stream, "127.0.0.1", "/vmess-xhttp")?;
                let reader = std::io::BufReader::with_capacity(32 * 1024, reader);
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn vmess_carries_behind_the_http_camouflage_both_ways() {
        vmess_over_byte_carrier(
            "/vmess-camouflage",
            |stream, id| serve_httpheader(stream, "/vmess-camouflage", &id, true),
            |stream| {
                let (reader, writer) =
                    crate::httpheader::connect(stream, "127.0.0.1", "/vmess-camouflage")?;
                Some((
                    Box::new(reader) as Box<dyn Read + Send>,
                    Box::new(writer) as Box<dyn Write + Send>,
                ))
            },
        );
    }

    #[test]
    fn vmess_carries_over_the_grpc_tunnel_both_ways() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds echo");
        let echo_port = echo.local_addr().expect("echo addr").port();
        thread::spawn(move || {
            for stream in echo.incoming().take(1) {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 256];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        });
        let id = [0x5au8; 16];
        let path = "/TunnelService/Tun";
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accepts");
            serve_grpc(stream, path, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("target");
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut reader, mut writer) =
            crate::grpc::connect(stream, "127.0.0.1", path).expect("carries");
        let (request, data_key, data_iv, auth) =
            request_bytes(&id, Cipher::Chacha, &target, 1).expect("request");
        assert!(writer.send(&request));
        let (response_key, response_iv) = response_material(&data_iv, &data_key);
        assert!(read_response(
            &mut reader,
            &response_key,
            &response_iv,
            auth
        ));
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send =
            Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv).expect("sends");
        let mut recv = Flow::fresh(
            Cipher::Chacha,
            &response_key,
            &response_iv,
            options,
            &response_iv,
        )
        .expect("recvs");
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        let mut scratch = Vec::new();
        assert!(write_frame(
            &mut writer,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let back = read_frame(&mut reader, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    /// The table and the loop it replaced have to agree, and agreeing with each
    /// other is not enough: both would be wrong together if the polynomial were
    /// mistyped once. So every one of the 256 entries is reached, several lengths
    /// are compared against the loop, and the published check value is asserted.
    #[test]
    fn crc32_is_the_bit_at_a_time_loop_folded() {
        fn bit_at_a_time(data: &[u8]) -> u32 {
            let mut crc = !0u32;
            for &byte in data {
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 == 1 {
                        (crc >> 1) ^ 0xedb8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }

        for a in 0..=255u8 {
            assert_eq!(crc32(&[a]), bit_at_a_time(&[a]), "single byte {a}");
        }
        for len in 0..=40usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(97).wrapping_add(13))
                .collect();
            assert_eq!(crc32(&data), bit_at_a_time(&data), "length {len}");
        }
        // The published `CRC-32` check value: the table is this polynomial, not
        // merely the one the old loop happened to implement.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    /// Coalescing frames into one `write` must not change one byte on the wire.
    ///
    /// This is the whole claim [`stage_frames`] rests on: a frame is
    /// `len || sealed || padding`, the reader is a byte reader, so four frames
    /// written in one call and written one call each are the same bytes in the same
    /// order. So this compares the two frame by frame, over the shapes the batching
    /// actually sees: one frame, several, exactly [`FRAMES_PER_WRITE`], and a short
    /// body that is one frame with a partial one behind it.
    ///
    /// The padding is random by construction, so the two streams cannot be equal as
    /// bytes and are not meant to be. What has to match is every frame's length
    /// prefix, its sealed body, and its padding *length*; both directions draw from
    /// the same `SHAKE` stream over the same iv and the same frame counter, so a
    /// third stream over the same seed walks both without reading a padding byte.
    #[test]
    fn a_batch_on_the_wire_is_the_frames_written_one_at_a_time() {
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let key = [0x3cu8; 16];
        let iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        for &run_len in &[
            1usize,
            2,
            63,
            64,
            4096,
            MAX_PLAIN,
            MAX_PLAIN + 1,
            3 * MAX_PLAIN,
        ] {
            let body: Vec<u8> = (0..run_len)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(11))
                .collect();

            // A run is a byte stream, so the frames are whole `MAX_PLAIN` bodies
            // with a short last one, at most `FRAMES_PER_WRITE` of them. `apart` is
            // that run framed one `stage_frame` call at a time, which is the only
            // thing the two paths are allowed to disagree about.
            let chunks: Vec<&[u8]> = body.chunks(MAX_PLAIN).take(FRAMES_PER_WRITE).collect();
            let mut send = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            let mut apart = Vec::new();
            for frame in &chunks {
                staging.clear();
                assert!(stage_frame(&mut send, frame, &mut staging, &mut pad));
                apart.extend_from_slice(&staging);
            }

            let mut batched = Flow::fresh(Cipher::Chacha, &key, &iv, options, &iv).expect("sends");
            let mut whole = Vec::new();
            let mut batch_pad = PadSource::fresh().expect("entropy");
            assert!(stage_frames(
                &mut Vec::new(),
                &mut batched,
                &body,
                &mut whole,
                &mut batch_pad,
            ));

            let mut mask = Shake::fresh(&iv, true);
            let (mut a, mut b) = (0usize, 0usize);
            for (frame, chunk) in chunks.iter().enumerate() {
                let padding = usize::from(mask.pad_len());
                let wire = u16::from_be_bytes([apart[a], apart[a + 1]]);
                assert_eq!(
                    wire,
                    u16::from_be_bytes([whole[b], whole[b + 1]]),
                    "run of {run_len}: frame {frame} length prefix"
                );
                let masked = usize::from(mask.draw() ^ wire);
                let sealed = masked - padding;
                assert_eq!(
                    chunk.len() + TAG_LEN,
                    sealed,
                    "run of {run_len}: frame {frame} sealed length"
                );
                assert_eq!(
                    &apart[a + 2..a + 2 + sealed],
                    &whole[b + 2..b + 2 + sealed],
                    "run of {run_len}: frame {frame} sealed body"
                );
                a += 2 + masked;
                b += 2 + masked;
            }
            assert_eq!(
                a,
                apart.len(),
                "the one-at-a-time run is exactly its frames"
            );
            assert_eq!(b, whole.len(), "the batch is exactly the same frames");
        }
    }

    /// Neither frame path may allocate, and neither may hand back a copy.
    ///
    /// Both buffers are the caller's, pre-sized the way `pump_relay` sizes them,
    /// and both keep the same address and the same capacity for every frame of a
    /// run. A frame that allocated would move one of them; a frame that copied the
    /// plaintext out would move the other, because the length returned would not
    /// be the length of the caller's own bytes. This is the deterministic half of
    /// the claim: it is the same on every machine, where a duration is not.
    #[test]
    fn frames_reuse_the_callers_buffers() {
        let cipher = Cipher::Chacha;
        let key = [0x77u8; 16];
        let iv = [0x88u8; 16];
        let options = OPT_STREAM | OPT_MASK | OPT_PAD;
        let mut send = Flow::fresh(cipher, &key, &iv, options, &iv).expect("sends");
        let mut recv = Flow::fresh(cipher, &key, &iv, options, &iv).expect("recvs");
        // Ascending, and every length below the pre-sized capacity, so no frame
        // asks the buffer to grow — a grow is a reallocation by another name and
        // this test is about the frames, not about `Vec`.
        let lens = [1usize, 4, 63, 64, 65, 512, 1500, 4096];
        let payloads: Vec<Vec<u8>> = lens
            .iter()
            .map(|n| {
                (0..*n)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(7))
                    .collect()
            })
            .collect();

        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = listener.local_addr().expect("addr").port();
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accepts");
            let mut scratch = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 64);
            let addr = scratch.as_ptr() as usize;
            let cap = scratch.capacity();
            let mut got = Vec::new();
            for want in &lens {
                // Read the addresses *before* the call: while `chunk` is alive the
                // borrow checker will not let this test look at `scratch` at all,
                // which is the design working, not the test working around it.
                let was_at = scratch.as_ptr() as usize;
                let had = scratch.capacity();
                let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
                assert_eq!(chunk.len(), *want, "plaintext length");
                assert_eq!(
                    chunk.as_ptr() as usize,
                    was_at,
                    "the plaintext was copied out of the caller's buffer"
                );
                assert_eq!(was_at, addr, "the read buffer moved: read_frame allocated");
                assert_eq!(had, cap, "the read buffer grew: read_frame allocated");
                got.extend_from_slice(chunk);
            }
            got
        });

        let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        // Wire prefix plus padding ride in the same buffer now, so the
        // capacity covers them: without the `+ 2 + 64` a full-size frame would
        // grow the buffer it was meant to reuse.
        let mut staging = Vec::with_capacity(MAX_PLAIN + TAG_LEN + 2 + 64);
        let mut pad = PadSource::fresh().expect("entropy");
        let addr = staging.as_ptr() as usize;
        let cap = staging.capacity();
        let mut want = Vec::new();
        for plain in &payloads {
            assert!(write_frame(
                &mut uplink,
                &mut send,
                plain,
                &mut staging,
                &mut pad
            ));
            assert_eq!(
                staging.as_ptr() as usize,
                addr,
                "the write buffer moved: write_frame allocated"
            );
            assert_eq!(
                staging.capacity(),
                cap,
                "the write buffer grew: write_frame allocated"
            );
            want.extend_from_slice(plain);
        }
        assert_eq!(reader.join().expect("joins"), want);
    }

    #[test]
    fn kdf_is_stable_and_keyed() {
        let a = kdf(b"key", &[b"path"]);
        assert_eq!(a, kdf(b"key", &[b"path"]));
        assert_ne!(a, kdf(b"other", &[b"path"]));
        assert_ne!(a, kdf(b"key", &[b"other"]));
    }

    #[test]
    fn kdf_matches_the_oracle_vectors() {
        fn hex(bytes: &[u8]) -> String {
            let mut out = String::new();
            for b in bytes {
                out.push("0123456789abcdef".as_bytes()[(b >> 4) as usize] as char);
                out.push("0123456789abcdef".as_bytes()[(b & 15) as usize] as char);
            }
            out
        }
        assert_eq!(
            hex(&md5::compute(b"abc").0),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex(&kdf(b"key", &[b"path"])),
            "f5952ea326376193226ffe760d8aa2ad8587c6a0cc7c32efeda02eb0b5d430ed"
        );
        assert_eq!(
            hex(&kdf(
                b"key",
                &[
                    b"VMess Header AEAD Key_Length",
                    b"authid1234567890",
                    b"nonce123"
                ]
            )),
            "fa9ff42e922d36e727fe11148c5bfae1e57feb2a8bc5671be1014e8a5554c70a"
        );
        assert_eq!(
            hex(&kdf16(b"test-instruction-16", &[b"AES Auth ID Encryption"])),
            "a69474c1eddf8c94283389cc76ac64be"
        );
        let uuid: [u8; 16] = [
            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3,
            0x08, 0x11,
        ];
        assert_eq!(
            hex(&instruction_key(&uuid)),
            "b50d916ac0cec067981af8e5f38a758f"
        );
    }

    #[test]
    fn handshake_relay_round_trips() {
        use std::io::{Read as _, Write as _};
        let id = [0xabu8; 16];
        let echo = TcpListener::bind("127.0.0.1:0").expect("binds");
        let echo_port = echo.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("accepts");
            let mut buf = [0u8; 1024];
            loop {
                let Ok(read) = stream.read(&mut buf) else {
                    return;
                };
                if read == 0 {
                    return;
                }
                if stream.write_all(&buf[..read]).is_err() {
                    return;
                }
            }
        });
        let server = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            let (stream, _) = server.accept().expect("accepts");
            super::serve(stream, &id, true);
        });
        let target: SocketAddr = format!("127.0.0.1:{echo_port}").parse().expect("addr");
        let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
        let (mut send, mut recv, response_key, response_iv, auth) =
            super::client_handshake(&mut uplink, &id, Cipher::Auto, &target).expect("handshakes");
        assert!(super::read_response(
            &mut uplink,
            &response_key,
            &response_iv,
            auth
        ));
        let mut staging = Vec::new();
        let mut pad = PadSource::fresh().expect("entropy");
        assert!(write_frame(
            &mut uplink,
            &mut send,
            b"ping",
            &mut staging,
            &mut pad
        ));
        let mut scratch = Vec::new();
        let back = read_frame(&mut uplink, &mut recv, &mut scratch).expect("reads");
        assert_eq!(back, b"ping");
    }

    #[test]
    fn response_prefix_is_stable() {
        let prefix = response_prefix(&[0x71u8; 16], &[0x72u8; 16], 0xAB).expect("prefixes");
        assert_eq!(prefix.len(), 38);
        assert_eq!(
            prefix,
            [
                0xab, 0xe4, 0x1f, 0x65, 0xdb, 0xa0, 0x80, 0xd4, 0xcc, 0x9d, 0x50, 0xd3, 0x0a, 0xda,
                0x8b, 0x09, 0xaa, 0x89, 0x82, 0xf9, 0xa8, 0xfe, 0x3d, 0xf3, 0x20, 0xc3, 0x7b, 0x61,
                0xcd, 0x45, 0x4e, 0x47, 0x98, 0x8d, 0x4a, 0xf9, 0x11, 0xd7,
            ]
        );
    }

    #[test]
    fn frames_seal_to_stable_bytes() {
        let cases = [
            (
                Cipher::Chacha,
                [
                    0x15, 0xe6, 0x71, 0x0e, 0x43, 0x79, 0x84, 0x37, 0x1c, 0xc5, 0xf6, 0x4d, 0xd4,
                    0x8f, 0x7c, 0xc4, 0x58, 0x69, 0xc8, 0xeb, 0xec,
                ],
            ),
            (
                Cipher::Aes,
                [
                    0xc9, 0x02, 0x32, 0x56, 0x14, 0x1e, 0xff, 0x1c, 0xe0, 0xfc, 0x09, 0xbf, 0x9f,
                    0xc1, 0xa9, 0x16, 0xfc, 0xeb, 0x35, 0xbd, 0x5a,
                ],
            ),
        ];
        for (cipher, golden) in cases {
            let mut flow = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let mut sealed = Vec::new();
            assert!(flow.seal_onto(b"hello", &mut sealed));
            assert_eq!(sealed, golden);
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("fresh");
            let back = recv.open_chunk(&mut sealed).expect("opens");
            assert_eq!(&sealed[..back], b"hello");
        }
    }

    #[test]
    fn seal_open_round_trips_every_length_and_cipher() {
        let lens = [
            0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1000, 1023, 1024, 4095,
            4096, 8191, 8192, 8193, 16383, 16384, 20000,
        ];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let tag = if cipher == Cipher::None { 0 } else { TAG_LEN };
            for &len in &lens {
                let plain: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                let mut sealed = Vec::new();
                assert!(send.seal_onto(&plain, &mut sealed));
                assert_eq!(sealed.len(), plain.len() + tag);
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(back, plain.len());
                assert_eq!(&sealed[..back], &plain[..]);
            }
        }
    }

    #[test]
    fn masked_frames_carry_every_length() {
        let lens = [0, 1, 100, 8191, 8192, 8193, 20000];
        for cipher in [Cipher::Chacha, Cipher::Aes, Cipher::None] {
            let options = OPT_STREAM | OPT_MASK | OPT_PAD;
            let payloads: Vec<Vec<u8>> = lens
                .iter()
                .map(|&len| (0..len).map(|i| (i % 251) as u8).collect())
                .collect();
            let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
            let port = listener.local_addr().expect("addr").port();
            let writer = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accepts");
                let mut recv =
                    Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                        .expect("recvs");
                let mut all = Vec::new();
                let mut scratch = Vec::new();
                for _ in &lens {
                    let chunk = read_frame(&mut stream, &mut recv, &mut scratch).expect("reads");
                    all.extend_from_slice(chunk);
                }
                all
            });
            let mut uplink = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            let mut send =
                Flow::fresh(cipher, &[0x55u8; 16], &[0x66u8; 16], options, &[0x66u8; 16])
                    .expect("sends");
            let mut want = Vec::new();
            let mut staging = Vec::new();
            let mut pad = PadSource::fresh().expect("entropy");
            for plain in &payloads {
                assert!(write_frame(
                    &mut uplink,
                    &mut send,
                    plain,
                    &mut staging,
                    &mut pad
                ));
                want.extend_from_slice(plain);
            }
            assert_eq!(writer.join().expect("joins"), want);
        }
    }

    #[test]
    fn counters_advance_one_per_frame_at_any_offset() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            for &at in &[0u16, 1, 255, 256, 1000, 32767, 32768, 65533, 65534] {
                let mut send = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("sends");
                let mut recv = Flow::fresh(
                    cipher,
                    &[0x55u8; 16],
                    &[0x66u8; 16],
                    OPT_STREAM,
                    &[0x66u8; 16],
                )
                .expect("recvs");
                send.counter = at;
                recv.counter = at;
                let mut first = [0u8; 12];
                first.copy_from_slice(&send.nonce());
                let mut sealed = Vec::new();
                assert!(send.seal_onto(b"ping", &mut sealed));
                let back = recv.open_chunk(&mut sealed).expect("opens");
                assert_eq!(&sealed[..back], b"ping");
                assert_eq!(send.counter, at.wrapping_add(1));
                assert_eq!(recv.counter, at.wrapping_add(1));
                assert_ne!(send.nonce(), first);
            }
        }
    }

    #[test]
    fn counter_wrap_is_refused_not_reused() {
        let mut flow = Flow::fresh(
            Cipher::Chacha,
            &[0x55u8; 16],
            &[0x66u8; 16],
            OPT_STREAM,
            &[0x66u8; 16],
        )
        .expect("fresh");
        flow.counter = u16::MAX;
        let mut sealed = vec![0xAAu8; 4];
        assert!(!flow.seal_onto(b"ping", &mut sealed));
        assert_eq!(sealed, [0xAAu8; 4]);
        assert!(flow.open_chunk(&mut sealed).is_none());
    }

    #[test]
    fn wire_codes_and_security_words_map_exactly() {
        assert_eq!(Cipher::from_code(3), Some(Cipher::Aes));
        assert_eq!(Cipher::from_code(4), Some(Cipher::Chacha));
        assert_eq!(Cipher::from_code(5), Some(Cipher::None));
        for code in [0, 1, 2, 6, 7, 255] {
            assert!(Cipher::from_code(code).is_none());
        }
        assert_eq!(Cipher::parse("auto"), Cipher::Auto);
        assert_eq!(Cipher::parse("AUTO"), Cipher::Auto);
        assert_eq!(Cipher::parse("aes-128-gcm"), Cipher::Aes);
        assert_eq!(Cipher::parse("AES-128-GCM"), Cipher::Aes);
        assert_eq!(Cipher::parse("chacha20-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("chacha20-ietf-poly1305"), Cipher::Chacha);
        assert_eq!(Cipher::parse("none"), Cipher::None);
        assert_eq!(Cipher::parse("NONE"), Cipher::None);
        assert_eq!(Cipher::parse("garbage"), Cipher::Auto);
        assert_eq!(Cipher::parse(""), Cipher::Auto);
    }

    #[test]
    fn tampered_seals_do_not_open() {
        for cipher in [Cipher::Chacha, Cipher::Aes] {
            let key = [0x33u8; 16];
            let nonce = [0x44u8; 12];
            let sealed = seal_header(&key, &nonce, b"length-is-framing", b"aad").expect("seals");
            for at in [0, sealed.len() / 2, sealed.len() - 1] {
                let mut cut = sealed.clone();
                cut[at] ^= 1;
                assert!(open_header(&key, &nonce, &cut, b"aad").is_none());
            }
            assert!(open_header(&key, &nonce, &sealed, b"wrong").is_none());
            assert!(open_header(&[0x34u8; 16], &nonce, &sealed, b"aad").is_none());
            assert!(open_header(&key, &nonce, &sealed[..sealed.len() - 1], b"aad").is_none());
            let mut send = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("sends");
            let mut frame = Vec::new();
            assert!(send.seal_onto(b"ping", &mut frame));
            let mut recv = Flow::fresh(
                cipher,
                &[0x55u8; 16],
                &[0x66u8; 16],
                OPT_STREAM,
                &[0x66u8; 16],
            )
            .expect("recvs");
            frame[0] ^= 1;
            assert!(recv.open_chunk(&mut frame).is_none());
        }
    }

    #[test]
    fn expired_auth_ids_are_refused() {
        let instruction = instruction_key(&[0x22u8; 16]);
        let key = AuthKey::new(&instruction);
        let seal = |ago: u64| {
            let mut plain = [0u8; 16];
            plain[..8].copy_from_slice(&now_secs().saturating_sub(ago).to_be_bytes());
            plain[8..12].copy_from_slice(&[9u8, 8, 7, 6]);
            let checksum = crc32(&plain[..12]).to_be_bytes();
            plain[12..].copy_from_slice(&checksum);
            key.seal(&mut plain);
            plain
        };
        assert!(valid_auth_id(&key, &seal(0)));
        assert!(valid_auth_id(&key, &seal(119)));
        assert!(!valid_auth_id(&key, &seal(121)));
        assert!(!valid_auth_id(&key, &seal(3600)));
    }

    #[test]
    fn replays_close_on_second_use() {
        let id = [0x77u8; AUTH_LEN];
        assert!(!replay_seen(&id));
        assert!(replay_seen(&id));
    }

    #[test]
    fn clear_headers_decode_and_reject() {
        let target: SocketAddr = "127.0.0.1:8080".parse().expect("addr");
        let mut header = vec![1u8];
        header.extend_from_slice(&[0x01u8; 16]);
        header.extend_from_slice(&[0x02u8; 16]);
        header.push(0x03);
        header.push(OPT_STREAM | OPT_MASK | OPT_PAD);
        header.push(0x04);
        header.push(0);
        header.push(1);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.push(1);
        header.extend_from_slice(&[127, 0, 0, 1]);
        header.extend_from_slice(&fnv1a(&header).to_be_bytes());
        let (got, _send, _recv, prefix, cmd) = decode_header(&header).expect("decodes");
        assert_eq!(got, target);
        assert_eq!(cmd, 1);
        assert_eq!(prefix.len(), 38);
        let mut bad = header.clone();
        bad[0] = 2;
        assert!(decode_header(&bad).is_none());
        let mut udp = header.clone();
        udp[37] = 2;
        // The checksum covers the command byte, so the mutation must be
        // re-sealed: flipping cmd to 2 without recomputing fails the check.
        let cut = udp.len() - 4;
        let sum = fnv1a(&udp[..cut]);
        udp[cut..].copy_from_slice(&sum.to_be_bytes());
        let (got, _, _, _, cmd) = decode_header(&udp).expect("decodes udp");
        assert_eq!(got, target);
        assert_eq!(cmd, 2);
        let mut bad = header.clone();
        bad[37] = 5;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0x07;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[34] &= !OPT_STREAM;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decode_header(&bad).is_none());
        let mut bad = header.clone();
        bad[35] = 0xF4;
        assert!(decode_header(&bad).is_none());
        assert!(decode_header(&header[..header.len() - 1]).is_none());
    }

    #[test]
    fn requests_open_to_their_own_lengths_and_targets() {
        let uuid = [0xabu8; 16];
        let targets = [
            "127.0.0.1:8080".parse().expect("addr"),
            "[::1]:443".parse().expect("addr"),
        ];
        for cipher in [Cipher::Auto, Cipher::Aes, Cipher::Chacha, Cipher::None] {
            for target in targets {
                let (request, _, _, _) = request_bytes(&uuid, cipher, &target, 1).expect("builds");
                assert!(request.len() > 42 + TAG_LEN);
                let instruction = instruction_key(&uuid);
                let auth_id: [u8; AUTH_LEN] = request[..AUTH_LEN].try_into().expect("auth");
                let nonce = &request[16 + 18..16 + 18 + 8];
                let len_key = kdf16(
                    &instruction,
                    &[b"VMess Header AEAD Key_Length", &auth_id, nonce],
                );
                let len_full = kdf(
                    &instruction,
                    &[b"VMess Header AEAD Nonce_Length", &auth_id, nonce],
                );
                let len_nonce: [u8; 12] = len_full[..12].try_into().expect("nonce");
                let clear_len =
                    open_header(&len_key, &len_nonce, &request[16..34], &auth_id).expect("opens");
                assert_eq!(
                    usize::from(u16::from_be_bytes([clear_len[0], clear_len[1]])),
                    request.len() - 42 - TAG_LEN
                );
                let head_key = kdf16(&instruction, &[b"VMess Header AEAD Key", &auth_id, nonce]);
                let head_full = kdf(&instruction, &[b"VMess Header AEAD Nonce", &auth_id, nonce]);
                let head_nonce: [u8; 12] = head_full[..12].try_into().expect("nonce");
                let clear =
                    open_header(&head_key, &head_nonce, &request[42..], &auth_id).expect("opens");
                let (got, _, _, _, _) = decode_header(&clear).expect("decodes");
                assert_eq!(got, target);
            }
        }
    }

    #[test]
    fn garbage_short_and_wrong_user_close_fast() {
        let id = [0xabu8; 16];
        let server = TcpListener::bind("127.0.0.1:0").expect("binds");
        let port = server.local_addr().expect("addr").port();
        thread::spawn(move || {
            for stream in server.incoming().take(3) {
                let Ok(stream) = stream else { continue };
                thread::spawn(move || super::serve(stream, &id, true));
            }
        });
        let mut refused = 0;
        for body in [
            vec![0u8; 16],
            request_bytes(
                &[0xccu8; 16],
                Cipher::Auto,
                &"127.0.0.1:1".parse().expect("addr"),
                1,
            )
            .expect("builds")
            .0,
            request_bytes(&id, Cipher::Auto, &"127.0.0.1:1".parse().expect("addr"), 1)
                .expect("builds")
                .0[..20]
                .to_vec(),
        ] {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connects");
            stream.write_all(&body).expect("writes");
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut back = [0u8; 1];
            match stream.read(&mut back) {
                Ok(0) | Err(_) => refused += 1,
                Ok(_) => {}
            }
        }
        assert_eq!(refused, 3);
    }

    /// The `ChaCha20-Poly1305` data path, against the crate it replaced.
    ///
    /// The rest of these tests round-trip a `Flow` against another `Flow`, which
    /// is a real test of the framing and of the counter, and cannot tell whether
    /// the bytes on the wire are the bytes `VMess` peers expect. This one does:
    /// the same frame sealed here, and sealed by `chacha20poly1305` under the
    /// same key and nonce, have to be the same sixteen bytes plus the same tag.
    ///
    /// The key expansion and the nonce construction are the two places `VMess`
    /// is specific — `MD5` twice into a 32-byte key, and the frame counter in
    /// the first two bytes big-endian — so both are used from the same
    /// functions the shipped path uses rather than retyped here.
    #[test]
    fn the_chacha_data_frames_are_the_crate_it_replaced() {
        use chacha20poly1305::aead::AeadInPlace;
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _, Nonce};

        let data_key = [0x3cu8; 16];
        // Distinct bytes, so a slice that starts one byte early or one byte late
        // is a different nonce rather than the same one.
        let data_iv: [u8; 16] = std::array::from_fn(|i| 0x10u8.wrapping_add(i as u8));
        let options = OPT_STREAM | OPT_MASK;

        // The two `VMess`-specific inputs, pinned rather than recomputed.
        //
        // Recomputing them here from `chacha_key` and from `Flow::nonce` would
        // make this a test of the `AEAD` alone: a frame counter in the wrong
        // byte order, or an `iv` slice off by one, would change both sides at
        // once and the comparison would still pass. These are the bytes, so a
        // change to either function has to be a change to this list too.
        let want_key: [u8; 32] = [
            0x8c, 0xad, 0xb9, 0xb0, 0x5f, 0xd7, 0x0f, 0x16, 0xab, 0x6b, 0xea, 0xd8, 0x48, 0x90,
            0x14, 0x5d, 0xf7, 0xa8, 0xe4, 0xab, 0xb4, 0x63, 0x92, 0x9f, 0x06, 0x32, 0x00, 0xed,
            0x60, 0x0b, 0xf6, 0xa5,
        ];
        assert_eq!(
            chacha_key(&data_key),
            want_key,
            "the data key is md5(key) then md5 of that, concatenated"
        );

        for len in (0..=40usize).chain([63, 64, 65, 127, 128, 129, 1024, 4096]) {
            let plain: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(61).wrapping_add(5))
                .collect();

            // Several frames off *one* flow, not one frame per flow: the frame
            // counter is part of the nonce, so a test that only ever seals
            // counter zero cannot tell a big-endian counter from a little-endian
            // one, or a counter that fails to advance from one that does not.
            let mut flow = Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv)
                .expect("a chacha flow");
            let cipher = ChaCha20Poly1305::new_from_slice(&want_key).expect("crate key");

            for frame in 0..3u8 {
                // The nonce this frame uses, read *before* sealing: `seal_onto`
                // advances the counter, and the frame on the wire is the one with
                // the counter it had going in.
                let nonce = flow.nonce();
                let mut want_nonce = [0u8; 12];
                want_nonce[..2].copy_from_slice(&(frame as u16).to_be_bytes());
                want_nonce[2..].copy_from_slice(&data_iv[2..12]);
                assert_eq!(nonce, want_nonce, "frame {frame}: counter then the iv tail");
                let mut ours = Vec::new();
                assert!(flow.seal_onto(&plain, &mut ours), "seals frame {len}");

                // What the crate puts on the wire for the same frame.
                let mut want = plain.clone();
                let want_tag = cipher
                    .encrypt_in_place_detached(Nonce::from_slice(&want_nonce), b"", &mut want)
                    .expect("crate seals");
                assert_eq!(
                    ours,
                    [want.as_slice(), want_tag.as_slice()].concat(),
                    "length {len} frame {frame} is the crate's bytes"
                );

                // And it opens back to the plaintext, which is what the other
                // direction does with it.
                let mut recv = Flow::fresh(Cipher::Chacha, &data_key, &data_iv, options, &data_iv)
                    .expect("a chacha flow");
                for _ in 0..frame {
                    recv.counter += 1;
                }
                let n = recv.open_chunk(&mut ours).expect("opens");
                assert_eq!(n, len, "length {len} frame {frame} opens to its own length");
                assert_eq!(recv.iv, data_iv, "opening does not disturb the iv");
            }
        }
    }
}
