use std::collections::{HashMap, VecDeque};

use super::segment::{AckSegment, DataSegment};

#[derive(Debug, Default)]
pub struct SendingWindow {
    cache: VecDeque<DataSegment>,
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

    pub fn push(&mut self, number: u32, payload: Vec<u8>) {
        self.cache.push_back(DataSegment {
            number,
            payload,
            ..Default::default()
        });
    }

    #[must_use]
    pub fn first_number(&self) -> u32 {
        self.cache.front().map_or(0, |s| s.number)
    }

    pub fn clear(&mut self, una: u32) {
        while let Some(seg) = self.cache.front() {
            if seg.number >= una {
                break;
            }
            self.cache.pop_front();
        }
    }

    pub fn handle_fast_ack(&mut self, number: u32, rto: u32) {
        for seg in &mut self.cache {
            if seg.number == number || number.wrapping_sub(seg.number) > 0x7FFF_FFFF {
                return;
            }
            if seg.transmit > 0 && seg.timeout > rto / 3 {
                seg.timeout -= rto / 3;
            }
        }
    }

    pub fn remove(&mut self, number: u32) -> bool {
        for i in 0..self.cache.len() {
            if self.cache[i].number > number {
                return false;
            }
            if self.cache[i].number == number {
                if self.total_in_flight > 0 {
                    self.total_in_flight -= 1;
                }
                self.cache.remove(i);
                return true;
            }
        }
        false
    }

    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        max_in_flight: u32,
        write: &mut impl FnMut(&mut DataSegment),
    ) -> Option<u32> {
        let mut lost = 0u32;
        let mut in_flight = 0u32;
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
            seg.timestamp = current;
            seg.transmit += 1;
            write(seg);
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
        if self.cache.contains_key(&id) {
            return false;
        }
        self.cache.insert(id, value);
        true
    }

    #[must_use]
    pub fn has(&self, id: u32) -> bool {
        self.cache.contains_key(&id)
    }

    pub fn remove(&mut self, id: u32) -> Option<DataSegment> {
        self.cache.remove(&id)
    }
}

#[derive(Debug, Default)]
pub struct AckList {
    numbers: Vec<u32>,
    timestamps: Vec<u32>,
    next_flush: Vec<u32>,
    staging: Vec<u32>,
    dirty: bool,
}

impl AckList {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, number: u32, timestamp: u32) {
        self.numbers.push(number);
        self.timestamps.push(timestamp);
        self.next_flush.push(0);
        self.dirty = true;
    }

    pub fn clear(&mut self, una: u32) {
        let mut count = 0usize;
        for i in 0..self.numbers.len() {
            if self.numbers[i] < una {
                continue;
            }
            if i != count {
                self.numbers[count] = self.numbers[i];
                self.timestamps[count] = self.timestamps[i];
                self.next_flush[count] = self.next_flush[i];
            }
            count += 1;
        }
        if count < self.numbers.len() {
            self.numbers.truncate(count);
            self.timestamps.truncate(count);
            self.next_flush.truncate(count);
            self.dirty = true;
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        !self.numbers.is_empty()
    }

    pub fn flush(
        &mut self,
        current: u32,
        rto: u32,
        limit: usize,
        write: &mut impl FnMut(&mut AckSegment),
    ) {
        let mut candidates = std::mem::take(&mut self.staging);
        candidates.clear();
        let mut seg = AckSegment::new(limit);
        for i in 0..self.numbers.len() {
            if self.next_flush[i] > current {
                if candidates.len() < 128 {
                    candidates.push(self.numbers[i]);
                }
                continue;
            }
            seg.put_number(self.numbers[i]);
            seg.put_timestamp(self.timestamps[i]);
            let mut timeout = rto / 2;
            if timeout < 20 {
                timeout = 20;
            }
            self.next_flush[i] = current + timeout;
            if seg.is_full() {
                write(&mut seg);
                seg = AckSegment::new(limit);
                self.dirty = false;
            }
        }
        if self.dirty || !seg.is_empty() {
            for number in candidates.drain(..) {
                if seg.is_full() {
                    break;
                }
                seg.put_number(number);
            }
            write(&mut seg);
            self.dirty = false;
        }
        self.staging = candidates;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_is_not_due_until_current_reaches_timeout() {
        let mut w = SendingWindow::new();
        w.push(1, b"hello".to_vec());
        let mut emitted = Vec::new();
        w.flush(0, 100, 16, &mut |seg: &mut DataSegment| {
            emitted.push(serialize_data(seg));
        });
        assert_eq!(emitted.len(), 1);
        emitted.clear();
        w.flush(50, 100, 16, &mut |seg: &mut DataSegment| {
            emitted.push(serialize_data(seg));
        });
        assert_eq!(emitted.len(), 0);
        w.flush(100, 100, 16, &mut |seg: &mut DataSegment| {
            emitted.push(serialize_data(seg));
        });
        assert_eq!(emitted.len(), 1);
    }

    fn serialize_data(seg: &DataSegment) -> Vec<u8> {
        let mut buf = Vec::new();
        crate::kcp::segment::Segment::Data(seg.clone()).serialize(&mut buf);
        buf
    }

    #[test]
    fn fast_ack_cuts_the_timeout_of_earlier_segments() {
        let mut w = SendingWindow::new();
        w.push(1, b"a".to_vec());
        w.push(2, b"b".to_vec());
        let before = {
            let mut out = Vec::new();
            w.flush(0, 300, 16, &mut |seg: &mut DataSegment| {
                out.push(seg.number);
            });
            w.cache.front().unwrap().timeout
        };
        w.handle_fast_ack(2, 300);
        assert_eq!(w.cache.front().unwrap().timeout, before - 100);
    }
    #[test]
    fn ack_list_clear_drops_the_acknowledged_prefix() {
        let mut l = AckList::new();
        l.add(5, 10);
        l.add(7, 20);
        l.clear(7);
        assert_eq!(l.numbers, vec![7]);
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
