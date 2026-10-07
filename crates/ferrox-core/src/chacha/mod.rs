#![allow(
    clippy::inline_always,
    reason = "lane primitives are only sound inside the caller's target_feature function"
)]

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(not(target_arch = "x86_64"))]
mod calibrate;
#[cfg(target_arch = "aarch64")]
mod neon;
mod portable;
#[cfg(target_arch = "x86_64")]
mod sse2;

pub(crate) trait Lanes: Copy {
    const LANES: usize;
    const CHUNKS: usize = Self::LANES / 4;

    fn from_lanes(words: &[u32]) -> Self;

    fn add(self, o: Self) -> Self;
    fn bitxor(self, o: Self) -> Self;

    fn rotl16(self) -> Self;
    fn rotl12(self) -> Self;
    fn rotl8(self) -> Self;
    fn rotl7(self) -> Self;

    fn rot_chunks(self, n: usize) -> Self;

    fn xor_chunk(self, c: usize, dst: &mut [u8; 16]);

    fn with_counters(self, first: u32) -> Self;
}

#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn as_i32_bits(word: u32) -> i32 {
    i32::from_le_bytes(word.to_le_bytes())
}

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub(crate) fn hchacha(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CONSTANTS);
    for (i, w) in s[4..12].iter_mut().enumerate() {
        *w = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("key is 32 bytes"));
    }
    for (i, w) in s[12..].iter_mut().enumerate() {
        *w = u32::from_le_bytes(
            input[i * 4..i * 4 + 4]
                .try_into()
                .expect("input is 16 bytes"),
        );
    }
    for _ in 0..10 {
        qr(&mut s, 0, 4, 8, 12);
        qr(&mut s, 1, 5, 9, 13);
        qr(&mut s, 2, 6, 10, 14);
        qr(&mut s, 3, 7, 11, 15);
        qr(&mut s, 0, 5, 10, 15);
        qr(&mut s, 1, 6, 11, 12);
        qr(&mut s, 2, 7, 8, 13);
        qr(&mut s, 3, 4, 9, 14);
    }
    let mut out = [0u8; 32];
    for (i, w) in s[..4].iter().chain(s[12..].iter()).enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn qr(s: &mut [u32; 16], idx_a: usize, idx_b: usize, idx_c: usize, idx_d: usize) {
    s[idx_a] = s[idx_a].wrapping_add(s[idx_b]);
    s[idx_d] = (s[idx_d] ^ s[idx_a]).rotate_left(16);
    s[idx_c] = s[idx_c].wrapping_add(s[idx_d]);
    s[idx_b] = (s[idx_b] ^ s[idx_c]).rotate_left(12);
    s[idx_a] = s[idx_a].wrapping_add(s[idx_b]);
    s[idx_d] = (s[idx_d] ^ s[idx_a]).rotate_left(8);
    s[idx_c] = s[idx_c].wrapping_add(s[idx_d]);
    s[idx_b] = (s[idx_b] ^ s[idx_c]).rotate_left(7);
}

#[cfg(target_arch = "x86_64")]
const GROUP_STATES: usize = 4;
#[cfg(target_arch = "aarch64")]
const GROUP_STATES: usize = 8;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const GROUP_STATES: usize = 4;

const TAIL_STATES: usize = if GROUP_STATES < 8 { GROUP_STATES } else { 8 } - 1;

#[inline]
fn base_state(key: &[u8; 32], nonce: &[u8; 12]) -> [u32; 16] {
    let mut s = [0u32; 16];
    s[..4].copy_from_slice(&CONSTANTS);
    for (i, word) in s[4..12].iter_mut().enumerate() {
        *word = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().expect("key is 32 bytes"));
    }
    for (i, word) in s[13..16].iter_mut().enumerate() {
        *word = u32::from_le_bytes(
            nonce[i * 4..i * 4 + 4]
                .try_into()
                .expect("nonce is 12 bytes"),
        );
    }
    s
}

#[derive(Clone, Copy)]
pub(crate) struct Base<V> {
    regs: [V; 4],
}

#[inline]
fn base<V: Lanes>(state: &[u32; 16]) -> Base<V> {
    debug_assert_eq!(state[12], 0, "the counter register is only a base at zero");
    let mut lanes = [0u32; 16];
    let regs = core::array::from_fn(|g| {
        for c in 0..V::CHUNKS {
            lanes[4 * c..4 * c + 4].copy_from_slice(&state[4 * g..4 * g + 4]);
        }
        V::from_lanes(&lanes[..V::LANES])
    });
    Base { regs }
}

#[inline(always)]
fn counters<V: Lanes, const NST: usize>(base: &Base<V>, start: u32) -> [[V; 4]; NST] {
    core::array::from_fn(|s| {
        [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            base.regs[3].with_counters(start.wrapping_add((s * V::CHUNKS) as u32)),
        ]
    })
}

#[allow(
    clippy::inline_always,
    reason = "load-bearing: keeps the lane intrinsics inside the caller's target_feature function"
)]
#[inline(always)]
fn quarter_round<V: Lanes>(r: &mut [V; 4]) {
    r[0] = r[0].add(r[1]);
    r[3] = r[3].bitxor(r[0]).rotl16();
    r[2] = r[2].add(r[3]);
    r[1] = r[1].bitxor(r[2]).rotl12();
    r[0] = r[0].add(r[1]);
    r[3] = r[3].bitxor(r[0]).rotl8();
    r[2] = r[2].add(r[3]);
    r[1] = r[1].bitxor(r[2]).rotl7();
}

#[inline(always)]
fn rounds<V: Lanes, const NST: usize>(regs: &mut [[V; 4]; NST]) {
    for _ in 0..10 {
        for s in regs.iter_mut() {
            quarter_round(s);
        }
        for s in regs.iter_mut() {
            s[1] = s[1].rot_chunks(1);
            s[2] = s[2].rot_chunks(2);
            s[3] = s[3].rot_chunks(3);
        }
        for s in regs.iter_mut() {
            quarter_round(s);
        }
        for s in regs.iter_mut() {
            s[1] = s[1].rot_chunks(3);
            s[2] = s[2].rot_chunks(2);
            s[3] = s[3].rot_chunks(1);
        }
    }
}

#[inline(always)]
pub(crate) fn xor_groups<V: Lanes, const NST: usize>(
    base: &Base<V>,
    start: u32,
    out: &mut [u8],
    mut head: Option<&mut [u8; 32]>,
) -> u32 {
    debug_assert!(out.len() + 64 * usize::from(head.is_some()) <= NST * V::LANES * 16);

    let mut regs = counters::<V, NST>(base, start);

    rounds::<V, NST>(&mut regs);

    let skips_first = head.is_some();
    if let Some(h) = head.take() {
        let (h, _) = h.as_chunks_mut::<16>();
        let ff = [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            base.regs[3].with_counters(start),
        ];
        let state = &mut regs[0];
        state[0].add(ff[0]).xor_chunk(0, &mut h[0]);
        state[1].add(ff[1]).xor_chunk(0, &mut h[1]);
    }

    let (blocks, partial) = out.as_chunks_mut::<64>();
    let mut i = 0usize;
    'stores: for (s, state) in regs.iter_mut().enumerate() {
        let ff = [
            base.regs[0],
            base.regs[1],
            base.regs[2],
            base.regs[3].with_counters(start.wrapping_add((s * V::CHUNKS) as u32)),
        ];
        for c in 0..V::CHUNKS {
            if skips_first && s == 0 && c == 0 {
                continue;
            }
            let Some(block) = blocks.get_mut(i) else {
                let (chunks, tail) = partial.as_chunks_mut::<16>();
                for (chunk, (reg, initial)) in
                    chunks.iter_mut().zip(state.iter_mut().zip(ff.iter()))
                {
                    reg.add(*initial).xor_chunk(c, chunk);
                }
                if !tail.is_empty() {
                    let mut staged = [0u8; 16];
                    let g = chunks.len();
                    state[g].add(ff[g]).xor_chunk(c, &mut staged);
                    xor_last_bytes(tail, &staged);
                }
                break 'stores;
            };
            let (chunks, _) = block.as_chunks_mut::<16>();
            for (chunk, (reg, initial)) in chunks.iter_mut().zip(state.iter_mut().zip(ff.iter())) {
                reg.add(*initial).xor_chunk(c, chunk);
            }
            i += 1;
        }
    }
    (NST * V::CHUNKS) as u32
}

#[inline(always)]
fn read_le(bytes: &[u8], width: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf[..width].copy_from_slice(&bytes[..width]);
    u64::from_le_bytes(buf)
}

fn xor_last_bytes(dst: &mut [u8], staged: &[u8; 16]) {
    let mut at = 0usize;
    for width in [8usize, 4, 2, 1] {
        if dst.len() - at >= width {
            let mixed = read_le(&dst[at..], width) ^ read_le(&staged[at..], width);
            let bytes = mixed.to_le_bytes();
            dst[at..at + width].copy_from_slice(&bytes[..width]);
            at += width;
        }
    }
    if at < dst.len() {
        dst[at] ^= staged[at];
    }
}

const fn group_bytes<V: Lanes>() -> usize {
    GROUP_STATES * V::CHUNKS * 64
}

#[inline(always)]
fn xor_tail<V: Lanes>(
    state: &[u32; 16],
    base: &Base<V>,
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;
    let mut owed = 64 * usize::from(head.is_some());
    while rest.len() + owed > 64 {
        let states = ((rest.len() + owed).div_ceil(64) / V::CHUNKS).clamp(1, TAIL_STATES);
        let (chunk, tail) = rest.split_at_mut((states * V::CHUNKS * 64 - owed).min(rest.len()));
        macro_rules! pass {
            ($($n:literal),+ $(,)?) => {
                match states {
                    $($n => xor_groups::<V, $n>(base, ctr, chunk, head.take()),)+
                    _ => unreachable!("`states` is clamped to TAIL_STATES"),
                }
            };
        }
        blocks += pass!(1, 2, 3, 4, 5, 6, 7);
        ctr = ctr.wrapping_add((states * V::CHUNKS) as u32);
        rest = tail;
        owed = 0;
    }
    if !rest.is_empty() || head.is_some() {
        if let Some(h) = head.take() {
            let mut block = [0u8; 64];
            blocks += one_block(state, ctr, &mut block);
            h.copy_from_slice(&block[..32]);
            ctr = ctr.wrapping_add(1);
        }
        if !rest.is_empty() {
            blocks += one_block(state, ctr, rest);
        }
    }
    blocks
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn one_block(state: &[u32; 16], ctr: u32, out: &mut [u8]) -> u32 {
    xor_groups::<sse2::S4, 1>(&base::<sse2::S4>(state), ctr, out, None)
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn one_block(state: &[u32; 16], ctr: u32, out: &mut [u8]) -> u32 {
    if calibrate::verdict() {
        xor_groups::<Wide, 1>(&base::<Wide>(state), ctr, out, None)
    } else {
        portable::xor_block(state, ctr, out)
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    if std::is_x86_feature_detected!("avx2") {
        unsafe { avx2::xor_blocks(key, nonce, start, head, buf) }
    } else {
        xor_ladder::<portable::U4>(key, nonce, start, head, buf)
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    xor_ladder::<Wide>(key, nonce, start, head, buf)
}

#[inline(always)]
fn xor_ladder<V: Lanes>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    mut head: Option<&mut [u8; 32]>,
    buf: &mut [u8],
) -> u32 {
    let state = base_state(key, nonce);
    let base = base::<V>(&state);
    let mut ctr = start;
    let mut rest = buf;
    let mut blocks = 0u32;
    let mut owed = 64 * usize::from(head.is_some());
    while rest.len() + owed >= group_bytes::<V>() {
        let (chunk, tail) = rest.split_at_mut((group_bytes::<V>() - owed).min(rest.len()));
        blocks += xor_groups::<V, GROUP_STATES>(&base, ctr, chunk, head.take());
        ctr = ctr.wrapping_add((GROUP_STATES * V::CHUNKS) as u32);
        rest = tail;
        owed = 0;
    }
    blocks + xor_tail::<V>(&state, &base, ctr, head, rest)
}

#[cfg(target_arch = "aarch64")]
type Wide = neon::N4;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
type Wide = portable::U4;

pub const fn backend() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        match (GROUP_STATES, GROUP_STATES * <avx2::A8 as Lanes>::CHUNKS) {
            (4, 8) => {
                "4-lane core: AVX2, 4 states in flight, 8 blocks per iteration, at runtime-detected width"
            }
            _ => "x86_64: a width this build does not have",
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        match (GROUP_STATES, GROUP_STATES * <Wide as Lanes>::CHUNKS) {
            (8, 8) => "4-lane core: NEON, 8 states in flight, 8 blocks per iteration",
            _ => "aarch64: a width this build does not have",
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        match (GROUP_STATES, GROUP_STATES * <Wide as Lanes>::CHUNKS) {
            (4, 4) => "4-lane core: portable, 4 states in flight, 4 blocks per iteration",
            _ => "a width this build does not have",
        }
    }
}

#[cfg(target_arch = "aarch64")]
const _: () = assert!(GROUP_STATES * <Wide as Lanes>::CHUNKS == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(GROUP_STATES * <avx2::A8 as Lanes>::CHUNKS == 8);
#[cfg(target_arch = "x86_64")]
const _: () = assert!(GROUP_STATES * <portable::U4 as Lanes>::CHUNKS == 4);
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const _: () = assert!(GROUP_STATES * <Wide as Lanes>::CHUNKS == 4);

#[cfg(test)]
mod counter_tests {
    use super::{base, base_state, counters, portable, Lanes};

    #[test]
    fn a_pass_s_counters_are_the_words_base_state_put_there() {
        type U4 = portable::U4;
        let key = [0x5bu8; 32];
        let nonce = [0xa7u8; 12];
        let state = base_state(&key, &nonce);
        assert_eq!(state[12], 0, "the counter base is only a base at zero");

        for start in [0u32, 1, 7, u32::MAX - 8, u32::MAX] {
            let base = base::<U4>(&state);
            let regs = counters::<U4, 8>(&base, start);
            for (s, reg) in regs.iter().enumerate() {
                let want = start.wrapping_add((s * U4::CHUNKS) as u32);
                assert_eq!(
                    reg[3].0[0], want,
                    "start {start} state {s}: lane 0 is the block counter"
                );
                assert_eq!(
                    reg[3].0[1..],
                    state[13..16],
                    "start {start} state {s}: lanes 1..4 are the nonce tail"
                );
                let shared = [
                    <[u32; 4]>::try_from(&state[0..4]).expect("four words"),
                    <[u32; 4]>::try_from(&state[4..8]).expect("four words"),
                    <[u32; 4]>::try_from(&state[8..12]).expect("four words"),
                ];
                for (g, words) in shared.iter().enumerate() {
                    assert_eq!(
                        reg[g].0, *words,
                        "start {start} state {s}: register {g} is shared"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod avx2_counter_tests {
    use super::avx2::A8;
    use super::Lanes;

    #[target_feature(enable = "avx2")]
    unsafe fn lanes(v: A8) -> [u32; 8] {
        let mut out = [0u32; 8];
        unsafe { core::arch::x86_64::_mm256_storeu_si256(out.as_mut_ptr().cast(), v.0) };
        out
    }

    #[test]
    fn avx2_counters_land_in_lane_zero_of_each_chunk() {
        if !is_x86_feature_detected!("avx2") {
            return;
        }
        unsafe { the_two_chunk_contract() };
    }

    #[target_feature(enable = "avx2")]
    unsafe fn the_two_chunk_contract() {
        let tail = [11u32, 22, 33];
        let both = A8::from_lanes(&[
            0, tail[0], tail[1], tail[2], //
            0, tail[0], tail[1], tail[2],
        ]);

        let first = u32::MAX;
        let got = unsafe { lanes(both.with_counters(first)) };
        assert_eq!(got[0], first, "chunk 0 lane 0 is `first`");
        assert_eq!(got[4], 0, "chunk 1 lane 0 is `first + 1`, wrapped");
        assert_eq!(&got[1..4], &tail, "chunk 0 keeps its nonce tail");
        assert_eq!(&got[5..8], &tail, "chunk 1 keeps its nonce tail");

        let second = unsafe { lanes(both.with_counters(first.wrapping_add(1))) };
        assert_eq!(second[0], 0, "chunk 0 of the next state");
        assert_eq!(second[4], 1, "chunk 1 of the next state");
        assert_eq!(&second[1..4], &tail, "and the tails do not move");
        assert_eq!(&second[5..8], &tail);
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
mod sse2_counter_tests {
    use super::sse2::S4;
    use super::Lanes;

    fn lanes(v: S4) -> [u32; 4] {
        let mut out = [0u32; 4];
        unsafe { core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr().cast(), v.0) };
        out
    }

    #[test]
    fn sse2_replaces_lane_zero_and_keeps_the_nonce_tail() {
        let tail = [11u32, 22, 33];
        let v = S4::from_lanes(&[7, tail[0], tail[1], tail[2]]);

        for first in [0u32, 1, u32::MAX - 1, u32::MAX] {
            let got = lanes(v.with_counters(first));
            assert_eq!(got[0], first, "lane 0 is the counter");
            assert_eq!(
                &got[1..],
                &tail,
                "first {first}: lanes 1..3 are the nonce tail and must not move"
            );
        }

        let got = lanes(S4::from_lanes(&[99, tail[0], tail[1], tail[2]]).with_counters(5));
        assert_eq!(got[0], 5, "the old lane 0 is gone, not or-ed into");
    }
}

#[cfg(test)]
mod tail_store_tests {
    use super::xor_last_bytes;

    #[test]
    fn the_wide_tail_xor_is_the_byte_loop_it_replaced() {
        let staged: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        for len in 1..=16usize {
            let original: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(91).wrapping_add(5))
                .collect();
            let mut wide = original.clone();
            xor_last_bytes(&mut wide, &staged);
            let mut bytes = original;
            for (dst, ks) in bytes.iter_mut().zip(staged) {
                *dst ^= ks;
            }
            assert_eq!(wide, bytes, "len {len} must match the byte loop");
        }
    }

    #[test]
    fn the_wide_tail_xor_writes_nothing_past_the_tail() {
        let staged: [u8; 16] = [0xFF; 16];
        for len in 1..=15usize {
            let mut buf = vec![0xA5u8; len + 8];
            xor_last_bytes(&mut buf[..len], &staged);
            assert!(
                buf[len..].iter().all(|b| *b == 0xA5),
                "len {len} wrote past the tail: {buf:?}"
            );
        }
    }

    #[test]
    fn a_single_tail_byte_is_xored_and_the_rest_is_not() {
        let staged = [0u8; 16];
        let mut buf = [0x5Au8];
        xor_last_bytes(&mut buf, &staged);
        assert_eq!(buf, [0x5Au8]);
        let staged = [0xFFu8; 16];
        let mut buf = [0x5Au8];
        xor_last_bytes(&mut buf, &staged);
        assert_eq!(buf, [0xA5u8]);
    }
}
