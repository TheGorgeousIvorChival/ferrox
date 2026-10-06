//! The portable backend: four words per register, in plain arrays.
//!
//! This is the only backend with no `unsafe` in it, which is the point. Miri
//! interprets the whole of it — the ladder, the counter arithmetic, the group
//! boundaries, every store offset — so the arithmetic the other backends copy is
//! machine-checked for use-after-free, out-of-bounds access and leaks without
//! needing a target-specific interpreter. The architecture modules are then thin
//! enough to review as five instructions each.

use super::Lanes;

/// `rotate_left` as a function value, for `array::map`.
///
/// `u32::rotate_left::<N>` cannot be turbofished as a path — it names the method,
/// not a value — so each rotation needs its own monomorphised shim.
macro_rules! rols {
    ($($name:ident => $n:expr),* $(,)?) => {
        $(
            #[inline]
            fn $name(x: u32) -> u32 { x.rotate_left($n) }
        )*
    };
}
rols!(rotl16 => 16, rotl12 => 12, rotl8 => 8, rotl7 => 7);

/// Four 32-bit words: one register of one state.
#[derive(Clone, Copy)]
pub(crate) struct U4(pub(crate) [u32; 4]);

impl core::fmt::Debug for U4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("U4").field(&self.0).finish()
    }
}

impl Lanes for U4 {
    const LANES: usize = 4;

    fn from_lanes(words: &[u32]) -> Self {
        let w: [u32; 4] = words[..4].try_into().expect("U4 needs 4 lanes");
        Self(w)
    }

    #[inline]
    fn add(self, o: Self) -> Self {
        Self([
            self.0[0].wrapping_add(o.0[0]),
            self.0[1].wrapping_add(o.0[1]),
            self.0[2].wrapping_add(o.0[2]),
            self.0[3].wrapping_add(o.0[3]),
        ])
    }

    #[inline]
    fn bitxor(self, o: Self) -> Self {
        Self([
            self.0[0] ^ o.0[0],
            self.0[1] ^ o.0[1],
            self.0[2] ^ o.0[2],
            self.0[3] ^ o.0[3],
        ])
    }

    #[inline]
    fn rotl16(self) -> Self {
        Self(self.0.map(rotl16))
    }

    #[inline]
    fn rotl12(self) -> Self {
        Self(self.0.map(rotl12))
    }

    #[inline]
    fn rotl8(self) -> Self {
        Self(self.0.map(rotl8))
    }

    #[inline]
    fn rotl7(self) -> Self {
        Self(self.0.map(rotl7))
    }

    #[inline]
    fn rot_chunks(self, n: usize) -> Self {
        let a = self.0;
        // `n` is one of three literals at every call site, so the modulo folds
        // away and this is a fixed shuffle.
        Self([a[n % 4], a[(n + 1) % 4], a[(n + 2) % 4], a[(n + 3) % 4]])
    }

    #[inline]
    fn with_counters(self, first: u32) -> Self {
        let mut w = self.0;
        w[0] = first;
        Self(w)
    }

    #[inline]
    fn xor_chunk(self, _c: usize, dst: &mut [u8; 16]) {
        let (words, _) = dst.as_chunks_mut::<4>();
        for (d, w) in words.iter_mut().zip(self.0) {
            for (d, k) in d.iter_mut().zip(w.to_le_bytes()) {
                *d ^= k;
            }
        }
    }
}

/// XOR one block of keystream at `counter` over `out`, which may be shorter than
/// 64 bytes, and return the one block it generated.
///
/// This is the tail of every rung, so it is the one place a partial block is
/// produced. Generating a whole block and copying out the part that was wanted is
/// the cost the record layer exists to remove, so a short `out` is rounded *down*:
/// only the words that fall inside `out` are touched, and no keystream beyond the
/// caller's buffer is ever computed for it.
///
/// Not compiled on `x86_64`, where [`super::sse2`] is the one-block core: the
/// portable one is scalar code there, and nothing else in this module needs a
/// one-block entry.
#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn xor_block(state: &[u32; 16], counter: u32, out: &mut [u8]) -> u32 {
    let mut state = *state;
    state[12] = counter;

    let mut regs = [[U4([0; 4]); 4]; 1];
    for g in 0..4 {
        regs[0][g] = U4(state[4 * g..4 * g + 4].try_into().expect("4 words"));
    }
    let init = regs;

    super::rounds::<U4, 1>(&mut regs);

    for g in 0..4 {
        regs[0][g] = regs[0][g].add(init[0][g]);
    }

    // Sixteen bytes at a time while a whole chunk is inside `out`, then the words
    // that are left, one at a time, so a tail ending mid-word touches only the
    // bytes it owns. Every index is bounded by `out.len()`, so a write past the
    // end is an index panic rather than a silent overrun.
    let (chunks, tail) = out.as_chunks_mut::<16>();
    for (chunk, reg) in chunks.iter_mut().zip(regs[0].iter()) {
        reg.xor_chunk(0, chunk);
    }
    let rest = tail.len();
    for (i, word) in regs[0]
        .iter()
        .flat_map(|r| r.0.iter())
        .skip(chunks.len() * 4)
        .enumerate()
    {
        let off = i * 4;
        if off >= rest {
            break;
        }
        let ks = word.to_le_bytes();
        let n = 4.min(rest - off);
        for (dst, k) in tail[off..off + n].iter_mut().zip(ks) {
            *dst ^= k;
        }
    }
    // One block of rounds ran, whatever fraction of it the caller had room for.
    1
}
