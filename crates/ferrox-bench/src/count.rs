//! A counting global allocator, so a claim about allocations is a fact.
//!
//! An allocation count is exact and identical on every machine. A duration is
//! not: it depends on the CPU, the frequency governor and whatever else the
//! runner is doing. So the gates in `main.rs` are ordered with the deterministic
//! ones first, and the timing bar is the only machine-dependent one.
//!
//! The counting is deliberately simple — one active flag, relaxed atomics —
//! because it is only ever correct while single-threaded, and every caller here
//! measures on the main thread with nothing else running.

// A count divided by an iteration count is a ratio, and a ratio is what this
// module exists to report. Both sides are converted to `f64` deliberately:
// below 2^53 an `f64` is exact, and every count this harness produces is orders
// of magnitude below that. Refusing the conversion would mean doing the division
// in integers to obtain a number that still has to become an `f64` to print.
#![allow(clippy::cast_precision_loss)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Non-zero while a measurement is in progress, so the harness's own
/// bookkeeping never lands inside a count.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
/// Allocations the allocator had to zero, i.e. that the caller then overwrote.
/// Counted apart because a zeroed allocation is a `memset` the caller did not
/// ask for, and an allocation count alone cannot see it.
static ZEROED: AtomicUsize = AtomicUsize::new(0);

pub struct Counting;

#[inline]
fn tally(size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

/// A counting global allocator.
///
// SAFETY: every method forwards to [`System`] unchanged — same layouts, same
// pointers, same ownership. The only thing added is a tally taken *before* the
// call, and the tally touches four `AtomicUsize`s rather than anything the caller
// owns, so it cannot invalidate what `System` is about to be handed. `dealloc` is
// not counted at all, so nothing observes a pointer the allocator has already
// freed.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tally(layout.size());
        // SAFETY: `layout` is passed through untouched, so the contract
        // `GlobalAlloc::alloc` requires of `layout` is the one `System` already
        // requires and upholds.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ACTIVE.load(Ordering::Relaxed) != 0 {
            ZEROED.fetch_add(1, Ordering::Relaxed);
        }
        tally(layout.size());
        // SAFETY: as above; `alloc_zeroed` takes the same `layout` contract as
        // `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` and `layout` come from the caller unchanged, and a pointer
        // handed back by `System::alloc`/`alloc_zeroed` is freed with the same
        // allocator and the same layout. Nothing here touches `ptr` first.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Counts collected across one measurement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub allocs: usize,
    pub bytes: usize,
    pub zeroed: usize,
}

impl Counts {
    /// Allocations per iteration.
    pub fn per_iter(&self, iters: u64) -> f64 {
        self.allocs as f64 / iters as f64
    }

    /// Bytes allocated per iteration.
    pub fn bytes_per_iter(&self, iters: u64) -> f64 {
        self.bytes as f64 / iters as f64
    }
}

/// Runs `f` with counting on and returns what it allocated.
///
/// `f` must run its own iteration loop. Taking the iteration count here instead
/// would only invite the two sides of a comparison to be measured over
/// different amounts of work.
pub fn measure<R>(f: impl FnOnce() -> R) -> (R, Counts) {
    // Reset first, so a previous measurement cannot leak into this one.
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    ZEROED.store(0, Ordering::Relaxed);
    ACTIVE.store(1, Ordering::Relaxed);
    let out = f();
    ACTIVE.store(0, Ordering::Relaxed);
    (
        out,
        Counts {
            allocs: ALLOCS.load(Ordering::Relaxed),
            bytes: BYTES.load(Ordering::Relaxed),
            zeroed: ZEROED.load(Ordering::Relaxed),
        },
    )
}
