use super::{as_i32_bits, Lanes};
#[allow(clippy::wildcard_imports)]
use core::arch::x86_64::*;

#[derive(Clone, Copy)]
pub(crate) struct A8(pub(crate) __m256i);

impl core::fmt::Debug for A8 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut v = [0u32; 8];
        unsafe { _mm256_storeu_si256(v.as_mut_ptr().cast(), self.0) };
        f.debug_tuple("A8").field(&v).finish()
    }
}

const ROTL16: [i32; 8] = [
    0x0100_0302,
    0x0504_0706,
    0x0908_0b0a,
    0x0d0c_0f0e,
    0x0100_0302,
    0x0504_0706,
    0x0908_0b0a,
    0x0d0c_0f0e,
];

const ROTL8: [i32; 8] = [
    0x0201_0003,
    0x0605_0407,
    0x0a09_080b,
    0x0e0d_0c0f,
    0x0201_0003,
    0x0605_0407,
    0x0a09_080b,
    0x0e0d_0c0f,
];

const fn rot_imm(n: i32) -> i32 {
    (n & 3) | (((n + 1) & 3) << 2) | (((n + 2) & 3) << 4) | (((n + 3) & 3) << 6)
}

const _: () = {
    assert!(rot_imm(1) == 0b00_11_10_01);
    assert!(rot_imm(2) == 0b01_00_11_10);
    assert!(rot_imm(3) == 0b10_01_00_11);
};

impl Lanes for A8 {
    const LANES: usize = 8;

    #[inline]
    fn from_lanes(words: &[u32]) -> Self {
        Self(unsafe { _mm256_loadu_si256(words.as_ptr().cast()) })
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self(unsafe { _mm256_add_epi32(self.0, o.0) })
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self(unsafe { _mm256_xor_si256(self.0, o.0) })
    }

    #[inline]
    fn rotl16(self) -> Self {
        // through a black-boxed pointer: as a plain constant LLVM prefers two
        // lane swaps over one byte shuffle, and the swap pair costs a register
        let mask = core::hint::black_box(ROTL16.as_ptr().cast::<i8>());
        Self(unsafe { _mm256_shuffle_epi8(self.0, _mm256_loadu_si256(mask.cast())) })
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(unsafe {
            _mm256_or_si256(
                _mm256_slli_epi32::<12>(self.0),
                _mm256_srli_epi32::<20>(self.0),
            )
        })
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(unsafe { _mm256_shuffle_epi8(self.0, _mm256_loadu_si256(ROTL8.as_ptr().cast())) })
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(unsafe {
            _mm256_or_si256(
                _mm256_slli_epi32::<7>(self.0),
                _mm256_srli_epi32::<25>(self.0),
            )
        })
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        let v = unsafe {
            match n {
                1 => _mm256_shuffle_epi32::<0b00_11_10_01>(self.0),
                2 => _mm256_shuffle_epi32::<0b01_00_11_10>(self.0),
                _ => _mm256_shuffle_epi32::<0b10_01_00_11>(self.0),
            }
        };
        Self(v)
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        unsafe {
            let lo = _mm256_insert_epi32::<0>(self.0, as_i32_bits(first));
            Self(_mm256_insert_epi32::<4>(
                lo,
                as_i32_bits(first.wrapping_add(Self::CHUNKS as u32 - 1)),
            ))
        }
    }

    #[inline]
    fn xor_chunk(self, c: usize, dst: &mut [u8; 16]) {
        unsafe {
            let cur = _mm_loadu_si128(dst.as_mut_ptr().cast());
            let ours = if c == 0 {
                _mm256_castsi256_si128(self.0)
            } else {
                _mm256_extracti128_si256::<1>(self.0)
            };
            _mm_storeu_si128(dst.as_mut_ptr().cast(), _mm_xor_si128(cur, ours));
        }
    }
}

#[target_feature(enable = "avx2")]
pub(crate) unsafe fn xor_blocks(
    key: &[u8; 32],
    nonce: &[u8; 12],
    start: u32,
    head: Option<&mut [u8; 32]>,
    out: &mut [u8],
) -> u32 {
    super::xor_ladder::<A8>(key, nonce, start, head, out)
}
