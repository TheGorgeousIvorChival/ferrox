//! A from-scratch port of the ARQ transport `Xray-core` calls `mkcp`.
//!
//! The upstream lives in `upstream/xray-core/transport/internet/kcp`
//! (MPL-2.0, its own Golang port of skywind3000's KCP). Nothing from that
//! tree is copied: this module re-derives the same segments, windows, timers
//! and retransmission arithmetic, and proves the derivation bit-identical
//! with a scripted-clock oracle run against the pinned Go code.
//!
//! The proof shape: the arithmetic that decides *when* and *what* to put on
//! the wire — the segment codec, the RTO update, the sending window's
//! `Flush`, the ack list's `Flush`, the loss accounting — is deterministic
//! given an explicit clock, so that subset is driven with a fake writer and
//! compared byte for byte. The parts that are not deterministic by nature
//! (the tick thread, the updater goroutines, the UDP sockets) are held to
//! the weaker, honest claim of passing the same bytes while interoperating
//! with the pinned `Xray-core` over a real `UDP` loopback.

mod config;
mod connection;
mod listener;
mod roundtrip;
mod segment;
mod window;
mod worker;

#[cfg(test)]
mod oracle;

pub use config::Config;
pub use connection::{ConnError, ConnMetadata, Connection, State};
pub use listener::{dial, fresh_conversation, Listener};
pub use segment::{
    AckSegment, CmdOnlySegment, Command, DataSegment, Segment, SegmentOption, DATA_SEGMENT_OVERHEAD,
};

pub use roundtrip::RoundTripInfo;
pub use segment::read_segment;
pub use window::{AckList, ReceivingWindow, SendingWindow};
pub use worker::{ReceivingWorker, SendingWorker};
