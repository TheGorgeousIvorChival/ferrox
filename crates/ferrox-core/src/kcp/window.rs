use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};

use super::segment::{AckSegment, DataSegment, OutgoingHeader, SegmentOption};

/// One segment the sender still owes the wire. The payload is a half-open range
/// into `SendingWindow::arena` rather than an owned buffer: at the default
/// 1 332-byte MSS that was one `malloc` and one `free` per 1 332 bytes sent,
/// which at 100 Mbps is about 9 400 pairs a second per direction.
#[derive(Debug, Clone, Copy)]
struct Outgoing {
    header: OutgoingHeader,
    transmit: u32,
    timeout: u32,
    start: usize,
    end: usize,
}

#[derive(Debug, Default)]
pub struct SendingWindow {
    cache: VecDeque<Outgoing>,
    arena: Vec<u8>,
    /// Bytes at the front of `arena` that no cached segment refers to any more.
    base: usize,
    total_in_flight: u32,
}

impl SendingWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> u32 {
        self.cache.len() as u32
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn push(&mut self, number: u32, payload: &[u8]) {
        let start = self.arena.len();
        self.arena.extend_from_slice(payload);
        self.cache.push_back(Outgoing {
            header: OutgoingHeader {
                conv: 0,
                option: SegmentOption::default(),
                timestamp: 0,
                number,
                sending_next: 0,
            },
            transmit: 0,
            timeout: 0,
            start,
            end: self.arena.len(),
        });
    }

    /// Drops the arena prefix no cached segment points into, once it is at least
    /// half the arena, so trimming is amortised rather than per segment.
    fn trim(&mut self) {
        // Nothing live means the whole arena is garbage, and that has to be
        // checked before `base`: a window that is acknowledged down to empty
        // between bursts has `base == 0` and would otherwise never reclaim.
        if self.cache.is_empty() {
            self.arena.clear();
            self.base = 0;
            return;
        }
        if self.base == 0 {
            return;
        }
        if self.base * 2 < self.arena.len() {
            return;
        }
        self.arena.drain(..self.base);
        for seg in &mut self.cache {
            seg.start -= self.base;
            seg.end -= self.base;
        }
        self.base = 0;
    }

    #[must_use]
    pub fn arena_capacity(&self) -> usize {
        self.arena.capacity()
    }

    #[must_use]
    pub fn arena_base(&self) -> usize {
        self.base
    }

    #[must_use]
    pub fn first_number(&self) -> u32 {
        self.cache.front().map_or(0, |s| s.header.number)
    }

    pub fn clear(&mut self, una: u32) {
        while let Some(seg) = self.cache.front() {
            if seg.header.number >= una {
                break;
            }
            self.cache.pop_front();
        }
        self.trim();
    }

    pub fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        let third = rto / 3;
        for seg in &mut self.cache {
            if seg.header.number == number || number.wrapping_sub(seg.header.number) > 0x7FFF_FFFF {
                return;
            }
            if seg.transmit > 0 && seg.timeout > third {
                seg.timeout -= third;
            }
        }
    }

    pub fn remove(&mut self, number: u32) -> bool {
        let Some(index) = self.cache.iter().position(|s| s.header.number >= number) else {
            return false;
        };
        if self.cache[index].header.number != number {
            return false;
        }
        if self.total_in_flight > 0 {
            self.total_in_flight -= 1;
        }
        self.cache.remove(index);
        self.trim();
        true
    }

    pub fn release(&mut self) {
        self.cache.clear();
        self.arena.clear();
        self.base = 0;
        self.total_in_flight = 0;
    }

    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        max_in_flight: u32,
        write: &mut dyn FnMut(OutgoingHeader, &[u8]),
    ) -> Option<u32> {
        let mut lost = 0u32;
        let mut in_flight = 0u32;
        // `self.cache` and `self.arena` are disjoint fields, so the payload can
        // be borrowed out of the arena while the entry it came from is updated.
        for seg in &mut self.cache {
            if current.wrapping_sub(seg.timeout) >= 0x7FFF_FFFF {
                continue;
            }
            if seg.transmit == 0 {
                self.total_in_flight += 1;
            } else {
                lost += 1;
            }
            seg.timeout = current + rto;
            seg.header.timestamp = current;
            seg.transmit += 1;
            write(seg.header, &self.arena[seg.start..seg.end]);
            in_flight += 1;
            if in_flight >= max_in_flight {
                break;
            }
        }
        if in_flight > 0 && self.total_in_flight != 0 {
            Some(lost * 100 / self.total_in_flight)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct ReceivingWindow {
    cache: HashMap<u32, DataSegment>,
}

impl ReceivingWindow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, id: u32, value: DataSegment) -> bool {
        match self.cache.entry(id) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(value);
                true
            }
        }
    }

    #[must_use]
    pub fn has(&self, id: u32) -> bool {
        self.cache.contains_key(&id)
    }

    pub fn remove(&mut self, id: u32) -> Option<DataSegment> {
        self.cache.remove(&id)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct AckEntry {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

// Upstream bounds an ack's number list and the deferred-candidate buffer
// separately, and they are separate limits that happen to share a value.
const FLUSH_CANDIDATES: usize = 128;

#[derive(Debug, Default)]
pub struct AckList {
    entries: Vec<AckEntry>,
    candidates: Vec<u32>,
    dirty: bool,
}

impl AckList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, number: u32, timestamp: u32) {
        self.entries.push(AckEntry {
            number,
            timestamp,
            next_flush: 0,
        });
        self.dirty = true;
    }

    pub fn clear(&mut self, una: u32) {
        let mut kept = 0;
        for i in 0..self.entries.len() {
            if self.entries[i].number < una {
                continue;
            }
            if i != kept {
                self.entries[kept] = self.entries[i];
            }
            kept += 1;
        }
        if kept < self.entries.len() {
            self.entries.truncate(kept);
            self.dirty = true;
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        limit: usize,
        write: &mut impl FnMut(&mut AckSegment),
    ) {
        let mut seg = AckSegment::new(limit);
        let timeout = (rto / 2).max(20);
        self.candidates.clear();
        for entry in &mut self.entries {
            if entry.next_flush > current {
                if self.candidates.len() < FLUSH_CANDIDATES {
                    self.candidates.push(entry.number);
                }
                continue;
            }
            seg.put_number(entry.number);
            seg.put_timestamp(entry.timestamp);
            entry.next_flush = current + timeout;
            if seg.is_full() {
                write(&mut seg);
                seg = AckSegment::new(limit);
                self.dirty = false;
            }
        }
        if self.dirty || !seg.is_empty() {
            for index in 0..self.candidates.len() {
                if seg.is_full() {
                    break;
                }
                seg.put_number(self.candidates[index]);
            }
            write(&mut seg);
            self.dirty = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_not_due_until_current_reaches_timeout() {
        let mut w = SendingWindow::new();
        w.push(1, b"hello");
        let mut emitted = Vec::new();
        w.flush(0, 100, 16, &mut |h, p| {
            emitted.push(payload_of(h, p));
        });
        assert_eq!(emitted.len(), 1);
        emitted.clear();
        w.flush(50, 100, 16, &mut |h, p| {
            emitted.push(payload_of(h, p));
        });
        assert_eq!(emitted.len(), 0);
        w.flush(100, 100, 16, &mut |h, p| {
            emitted.push(payload_of(h, p));
        });
        assert_eq!(emitted.len(), 1);
    }

    fn payload_of(header: OutgoingHeader, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::kcp::segment::serialize_data(header, payload, &mut buf);
        buf
    }

    #[test]
    fn fast_ack_cuts_the_timeout_of_earlier_segments() {
        let mut w = SendingWindow::new();
        w.push(1, b"a");
        w.push(2, b"b");
        let before = {
            let mut out = Vec::new();
            w.flush(0, 300, 16, &mut |header, _| {
                out.push(header.number);
            });
            w.cache.front().unwrap().timeout
        };
        w.handle_fast_ack(2, 300);
        assert_eq!(w.cache.front().unwrap().timeout, before - 100);
    }
    /// The claim this window makes: one buffer serves every segment, so a send
    /// costs no allocation per segment. Capacity is the witness — a per-segment
    /// `Vec` would need a fresh allocation every 1 332 bytes, and this never
    /// exceeds the high-water mark of its first few rounds.
    #[test]
    fn the_arena_serves_every_segment_without_growing() {
        let mut w = SendingWindow::new();
        let mut high = 0usize;
        for round in 0..64u32 {
            let base = round * 8;
            for n in base..base + 8 {
                w.push(n, &[n as u8; 1332]);
            }
            high = high.max(w.arena_capacity());
            assert_eq!(w.len(), 8, "round {round}");
            w.flush(100 + round, 200, 64, &mut |_, _| {});
            w.clear(base + 8);
        }
        assert!(
            high <= 8 * 1332 * 3,
            "the arena reached {high} bytes for 8 live segments of 1332"
        );
        assert_eq!(w.len(), 0, "every round acknowledged its eight");
        // one buffer, reused: not one per segment, and not one that grows forever
        assert!(high >= 8 * 1332);
    }

    /// Trimming shifts every live range down by the trimmed prefix. If that
    /// arithmetic is wrong, a segment goes out carrying another segment's bytes,
    /// so every emitted payload must still be its own — at every offset.
    #[test]
    fn trimming_never_moves_a_live_payload() {
        for trim in [0u32, 1, 7, 8, 15, 16, 31] {
            let mut w = SendingWindow::new();
            for n in 0..32u32 {
                w.push(n, &[n as u8; 64]);
            }
            w.clear(trim);
            let mut live = Vec::new();
            w.flush(100, 200, 64, &mut |h, p| {
                live.push((h.number, p.to_vec()));
            });
            assert_eq!(live.len(), (32 - trim) as usize, "trim {trim}");
            for (number, payload) in &live {
                assert_eq!(payload.len(), 64, "trim {trim}: segment {number}");
                assert!(
                    payload.iter().all(|&b| b == *number as u8),
                    "trim {trim}: segment {number} carries {:?}",
                    &payload[..8]
                );
            }
            if let Some((first, _)) = live.first() {
                assert_eq!(*first, trim, "trim {trim}: wrong first segment");
            }
        }
    }

    /// The wrapped case: numbers near `u32::MAX` must not collide in the arena.
    #[test]
    fn the_arena_does_not_confuse_wrapped_segment_numbers() {
        let mut w = SendingWindow::new();
        w.push(u32::MAX, &[0xAA; 16]);
        w.push(0, &[0xBB; 16]);
        w.clear(u32::MAX);
        let mut live = Vec::new();
        w.flush(10, 20, 8, &mut |h, p| {
            live.push((h.number, p[0]));
        });
        assert_eq!(live, vec![(u32::MAX, 0xAA), (0, 0xBB)]);
    }

    #[test]
    fn release_empties_the_window_where_clear_at_the_wrap_would_not() {
        let mut w = SendingWindow::new();
        w.push(u32::MAX, b"last");
        w.push(0, b"first");
        w.clear(u32::MAX);
        assert_eq!(w.len(), 2);

        let mut w = SendingWindow::new();
        w.push(u32::MAX, b"last");
        w.push(0, b"first");
        w.release();
        assert!(w.is_empty());
        assert_eq!(w.len(), 0);
    }

    #[test]
    fn removing_beyond_the_window_is_not_a_removal() {
        let mut w = SendingWindow::new();
        w.push(4, b"a");
        w.push(5, b"b");
        assert!(!w.remove(3));
        assert!(!w.remove(6));
        assert!(w.remove(5));
        assert!(!w.remove(5));
        assert!(w.remove(4));
        assert!(w.is_empty());
    }

    #[test]
    fn ack_list_clear_drops_the_acknowledged_prefix() {
        let mut l = AckList::new();
        l.add(5, 10);
        l.add(7, 20);
        l.clear(7);
        assert_eq!(
            l.entries.iter().map(|e| e.number).collect::<Vec<_>>(),
            vec![7]
        );
        assert_eq!(l.entries[0].timestamp, 20);
    }

    #[test]
    fn the_ack_list_reuses_its_scratch_across_flushes() {
        let mut l = AckList::new();
        l.add(1, 100);
        l.add(2, 110);
        l.flush(0, 100, 300, &mut |_: &mut AckSegment| {});
        for current in 1..50u32 {
            l.flush(current, 100, 300, &mut |_: &mut AckSegment| {});
            assert_eq!(l.candidates, vec![1, 2]);
        }
        l.flush(50, 100, 300, &mut |_: &mut AckSegment| {});
        let scratch = l.candidates.as_ptr();
        for current in 51..100u32 {
            l.flush(current, 100, 300, &mut |_: &mut AckSegment| {});
            assert_eq!(l.candidates, vec![1, 2]);
        }
        assert_eq!(l.candidates.as_ptr(), scratch);
        assert_eq!(l.entries.len(), 2);
    }

    #[test]
    fn ack_list_flush_emits_every_known_number_on_the_first_round() {
        let mut l = AckList::new();
        l.add(1, 100);
        l.add(2, 110);
        let mut emitted = Vec::new();
        l.flush(0, 100, 300, &mut |seg: &mut AckSegment| {
            emitted.push(seg.clone());
        });
        assert_eq!(emitted.len(), 1);
        assert_eq!(emitted[0].numbers, vec![1, 2]);
        assert_eq!(emitted[0].timestamp, 110);
    }
}
