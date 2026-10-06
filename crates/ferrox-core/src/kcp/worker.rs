#![allow(clippy::missing_panics_doc)]
// poisoned-lock panics: lock PoisonError paths are never expected; documenting them would only repeat itself.

//! The two workers, ported one for one: they own the queues and the ack
//! scheduler, and the connection drives them with an explicit clock.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::config::Config;
use super::connection::{Ctx, State};
use super::segment::{AckSegment, DataSegment, SegmentOption};
use super::window::{AckList, ReceivingWindow, SendingWindow};

/// The send side: a window of unacknowledged segments, a sequence counter,
/// and the loss-driven congestion window.
pub struct SendingWorker {
    ctx: Arc<Ctx>,
    window: SendingWindow,
    first_unacknowledged: u32,
    next_number: u32,
    remote_next_number: u32,
    control_window: u32,
    window_size: u32,
    first_unacknowledged_updated: bool,
    closed: bool,
}

impl std::fmt::Debug for SendingWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendingWorker").finish_non_exhaustive()
    }
}

impl SendingWorker {
    pub(crate) fn new(config: Config, ctx: Arc<Ctx>) -> Self {
        Self {
            ctx,
            window: SendingWindow::new(),
            first_unacknowledged: 0,
            next_number: 0,
            remote_next_number: 32,
            control_window: config.sending_in_flight_size(),
            window_size: config.sending_buffer_size(),
            first_unacknowledged_updated: false,
            closed: false,
        }
    }

    /// Whether the tick thread should flush.
    #[must_use]
    pub fn update_necessary(&self) -> bool {
        !self.window.is_empty()
    }

    /// Whether nothing is unacknowledged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// First number not yet acked.
    #[must_use]
    pub fn first_unacknowledged(&self) -> u32 {
        self.first_unacknowledged
    }

    /// The peer's window advanced, so the window may be retired.
    pub fn process_receiving_next(&mut self, next_number: u32) {
        self.window.clear(next_number);
        self.find_first_unacknowledged();
    }

    fn find_first_unacknowledged(&mut self) {
        let first = self.first_unacknowledged;
        self.first_unacknowledged = if self.window.is_empty() {
            self.next_number
        } else {
            self.window.first_number()
        };
        if first != self.first_unacknowledged {
            self.first_unacknowledged_updated = true;
        }
    }

    fn process_ack(&mut self, number: u32) -> bool {
        // Only [first_unacknowledged, next_number) is live.
        if number.wrapping_sub(self.first_unacknowledged) > 0x7FFF_FFFF
            || number.wrapping_sub(self.next_number) < 0x7FFF_FFFF
        {
            return false;
        }
        let removed = self.window.remove(number);
        if removed {
            self.find_first_unacknowledged();
        }
        removed
    }

    /// An incoming ack batch.
    pub fn process_segment(&mut self, current: u32, seg: &AckSegment, rto: u32) {
        if self.closed {
            return;
        }
        if self.remote_next_number < seg.receiving_window {
            self.remote_next_number = seg.receiving_window;
        }
        self.window.clear(seg.receiving_next);
        self.find_first_unacknowledged();
        if seg.numbers.is_empty() {
            return;
        }
        let mut maxack = 0u32;
        let mut maxack_removed = false;
        for &number in &seg.numbers {
            let removed = self.process_ack(number);
            if maxack < number {
                maxack = number;
                maxack_removed = removed;
            }
        }
        if maxack_removed {
            self.window.handle_fast_ack(maxack, rto);
            if current.wrapping_sub(seg.timestamp) < 10000 {
                self.ctx
                    .round_trip
                    .lock()
                    .unwrap()
                    .update(current.wrapping_sub(seg.timestamp), current);
            }
        }
    }

    /// Queue one payload.
    pub fn push(&mut self, payload: Vec<u8>) -> bool {
        if self.closed {
            return false;
        }
        if self.window.len() > self.window_size {
            return false;
        }
        self.window.push(self.next_number, payload);
        self.next_number += 1;
        true
    }

    /// Shrink or grow the congestion window from a loss rate.
    pub fn on_packet_loss(&mut self, loss_rate: u32) {
        if self.ctx.round_trip.lock().unwrap().timeout() == 0 {
            return;
        }
        if loss_rate >= 15 {
            self.control_window = 3 * self.control_window / 4;
        }
        if loss_rate <= 5 {
            self.control_window += self.control_window / 4;
        }
        if self.control_window < 16 {
            self.control_window = 16;
        }
        let cwnd = self.ctx.config.sending_in_flight_size();
        if self.control_window > cwnd {
            self.control_window = cwnd;
        }
    }

    /// Retransmit due segments; returns whether the connection should ping
    /// (the first-unacknowledged pointer moved).
    pub fn flush(&mut self, current: u32) -> bool {
        if self.closed {
            return false;
        }
        let mut cwnd = self.ctx.config.sending_in_flight_size();
        let rest = self
            .remote_next_number
            .wrapping_sub(self.first_unacknowledged);
        if cwnd > rest {
            cwnd = rest;
        }
        if cwnd > self.control_window {
            cwnd = self.control_window;
        }
        cwnd *= self.ctx.config.cwnd_multiplier;
        if !self.window.is_empty() {
            let rto = self.ctx.round_trip.lock().unwrap().timeout();
            let first_unack = self.first_unacknowledged;
            let ctx = Arc::clone(&self.ctx);
            let rate = self
                .window
                .flush(current, rto, cwnd, &mut |d: &mut DataSegment| {
                    // Stamp right before emitting, the way Go's
                    // `SendingWorker::Write` does; the cached segment keeps
                    // the stamped fields, as in Go.
                    d.conv = ctx.meta.conversation;
                    d.sending_next = first_unack;
                    d.option = if ctx.state.load(Ordering::SeqCst) == State::ReadyToClose as i32 {
                        SegmentOption::CLOSE
                    } else {
                        SegmentOption::NONE
                    };
                    let _ = ctx.emit_data(d);
                });
            if let Some(rate) = rate {
                self.on_packet_loss(rate);
            }
            self.first_unacknowledged_updated = false;
        }
        let updated = self.first_unacknowledged_updated;
        self.first_unacknowledged_updated = false;
        updated
    }

    /// Close the queue of outbound bytes.
    pub fn close_write(&mut self) {
        self.window.clear(u32::MAX);
    }

    /// Release: drop queued segments and refuse new work.
    pub fn release(&mut self) {
        while !self.window.is_empty() {
            self.window.remove(self.window.first_number());
        }
        self.closed = true;
    }
}

/// The receive side: a reassembly window, the ack scheduler, and the
/// byte-stream reassembly on top of both.
pub struct ReceivingWorker {
    ctx: Arc<Ctx>,
    left_over: VecDeque<Vec<u8>>,
    left_over_off: usize,
    window: ReceivingWindow,
    acklist: AckList,
    next_number: u32,
    window_size: u32,
    mtu: u32,
}

impl std::fmt::Debug for ReceivingWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceivingWorker").finish_non_exhaustive()
    }
}

impl ReceivingWorker {
    pub(crate) fn new(config: Config, mss: u32, ctx: Arc<Ctx>) -> Self {
        let window_size = config.receiving_in_flight_size();
        Self {
            ctx,
            left_over: VecDeque::new(),
            left_over_off: 0,
            window: ReceivingWindow::new(),
            acklist: AckList::new(),
            next_number: 0,
            window_size,
            mtu: mss + super::segment::DATA_SEGMENT_OVERHEAD,
        }
    }

    /// Whether an ack is pending.
    #[must_use]
    pub fn update_necessary(&self) -> bool {
        self.acklist.is_pending()
    }

    /// Highest contiguous number delivered, plus one.
    #[must_use]
    pub fn next_number(&self) -> u32 {
        self.next_number
    }

    /// Whether the head segment is present.
    #[must_use]
    pub fn is_data_available(&self) -> bool {
        self.window.has(self.next_number)
    }

    /// The peer retired its window; drop the ack bookkeeping for it.
    pub fn process_sending_next(&mut self, next_number: u32) {
        self.acklist.clear(next_number);
    }

    /// A data segment arrived.
    pub fn process_segment(&mut self, seg: DataSegment) {
        let number = seg.number;
        let idx = number.wrapping_sub(self.next_number);
        if idx >= self.window_size {
            return;
        }
        self.acklist.clear(seg.sending_next);
        self.acklist.add(number, seg.timestamp);
        if !self.window.set(number, seg) {
            // A duplicate: upstream releases it; drop it here.
        }
    }

    /// Pop the contiguous prefix as a set of payload buffers.
    pub fn read_multi_buffer(&mut self) -> Vec<Vec<u8>> {
        if !self.left_over.is_empty() {
            let mut out = self.left_over.drain(..).collect::<Vec<_>>();
            if self.left_over_off > 0 {
                let tail = out[0].split_off(self.left_over_off);
                out[0] = tail;
                self.left_over_off = 0;
            }
            return out;
        }
        let mut mb = Vec::new();
        while let Some(mut seg) = self.window.remove(self.next_number) {
            self.next_number += 1;
            mb.push(std::mem::take(&mut seg.payload));
        }
        mb
    }

    /// Fill `b` from the contiguous stream: drain the leftover partial
    /// payloads first, then the contiguous head of the window.
    pub fn read(&mut self, b: &mut [u8]) -> usize {
        if self.left_over.is_empty() {
            let mb = self.read_multi_buffer();
            if mb.is_empty() {
                return 0;
            }
            self.left_over.extend(mb);
        }
        let mut n = 0;
        while n < b.len() && !self.left_over.is_empty() {
            let start = self.left_over_off;
            let head = &self.left_over[0];
            let take = (b.len() - n).min(head.len() - start);
            b[n..n + take].copy_from_slice(&head[start..start + take]);
            n += take;
            self.left_over_off += take;
            if self.left_over_off == self.left_over[0].len() {
                self.left_over.pop_front();
                self.left_over_off = 0;
            }
        }
        n
    }

    /// Emit the pending acks.
    pub fn flush(&mut self, current: u32) {
        let rto = self.ctx.round_trip.lock().unwrap().timeout();
        let limit = (self.mtu as usize - 17) / 4;
        let ctx = Arc::clone(&self.ctx);
        let window_size = self.window_size;
        let next_number = self.next_number;
        self.acklist
            .flush(current, rto, limit, &mut |a: &mut AckSegment| {
                // Stamp the way Go's `ReceivingWorker::Write` does.
                a.conv = ctx.meta.conversation;
                a.receiving_next = next_number;
                a.receiving_window = next_number + window_size;
                a.option = if ctx.state.load(Ordering::SeqCst) == State::ReadyToClose as i32 {
                    SegmentOption::CLOSE
                } else {
                    SegmentOption::NONE
                };
                let _ = ctx.emit_ack(a);
            });
    }

    /// No-op upstream.
    pub fn close_read(&mut self) {}

    /// Release: drop the reassembly buffer.
    pub fn release(&mut self) {
        self.left_over.clear();
        self.left_over_off = 0;
        self.window = ReceivingWindow::new();
    }
}
