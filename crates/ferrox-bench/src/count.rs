#![allow(clippy::cast_precision_loss)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static ZEROED: AtomicUsize = AtomicUsize::new(0);

pub struct Counting;

#[inline]
fn tally(size: usize) {
    if ACTIVE.load(Ordering::Relaxed) != 0 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        tally(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if ACTIVE.load(Ordering::Relaxed) != 0 {
            ZEROED.fetch_add(1, Ordering::Relaxed);
        }
        tally(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub allocs: usize,
    pub bytes: usize,
    pub zeroed: usize,
}

impl Counts {
    pub fn per_iter(&self, iters: u64) -> f64 {
        self.allocs as f64 / iters as f64
    }

    pub fn bytes_per_iter(&self, iters: u64) -> f64 {
        self.bytes as f64 / iters as f64
    }
}

pub fn measure<R>(f: impl FnOnce() -> R) -> (R, Counts) {
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
