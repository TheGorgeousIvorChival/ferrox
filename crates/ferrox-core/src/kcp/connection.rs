#![allow(clippy::missing_panics_doc)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use super::config::Config;
use super::roundtrip::RoundTripInfo;
use super::segment::{AckSegment, CmdOnlySegment, Command, DataSegment, Segment, SegmentOption};
use super::worker::{ReceivingWorker, SendingWorker};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Active,
    ReadyToClose,
    PeerClosed,
    Terminating,
    PeerTerminating,
    Terminated,
}

impl State {
    fn from_int(v: i32) -> Self {
        match v {
            0 => Self::Active,
            1 => Self::ReadyToClose,
            2 => Self::PeerClosed,
            3 => Self::Terminating,
            4 => Self::PeerTerminating,
            _ => Self::Terminated,
        }
    }
}

type Writer = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;

struct OutputSink {
    buf: Vec<u8>,
    write: Writer,
}

type Closer = dyn FnOnce() + Send;

#[derive(Debug, Clone, Copy)]
pub struct ConnMetadata {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub conversation: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    IoTimeout,
    Closed,
}

impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoTimeout => write!(f, "read/write timeout"),
            Self::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for ConnError {}

#[derive(Default)]
struct Notifier {
    generation: Mutex<u64>,
    condvar: Condvar,
}

impl Notifier {
    fn new() -> Self {
        Self::default()
    }

    fn gen(&self) -> u64 {
        *self.generation.lock().unwrap()
    }

    fn signal(&self) {
        *self.generation.lock().unwrap() += 1;
        self.condvar.notify_all();
    }

    fn wait_since(&self, snapshot: u64, timeout: Option<Duration>) -> bool {
        let mut g = self.generation.lock().unwrap();
        loop {
            if *g != snapshot {
                return true;
            }
            match timeout {
                Some(d) => {
                    let (guard, r) = self.condvar.wait_timeout(g, d).unwrap();
                    g = guard;
                    if r.timed_out() && *g == snapshot {
                        return false;
                    }
                }
                None => {
                    g = self.condvar.wait(g).unwrap();
                }
            }
        }
    }
}

pub(crate) struct Ctx {
    pub meta: ConnMetadata,
    pub config: Config,
    pub state: AtomicI32,
    pub round_trip: Mutex<RoundTripInfo>,
    output: Mutex<OutputSink>,
}

const WRITE_ATTEMPTS: u32 = 5;
const WRITE_RETRY_MS: u64 = 100;

impl Ctx {
    fn emit(&self, mut enc: impl FnMut(&mut Vec<u8>)) -> io::Result<()> {
        let mut last = None;
        for attempt in 0..WRITE_ATTEMPTS {
            let outcome = {
                let mut sink = self.output.lock().unwrap();
                let OutputSink { buf, write } = &mut *sink;
                buf.clear();
                enc(buf);
                write(buf)
            };
            match outcome {
                Ok(()) => return Ok(()),
                Err(e) => last = Some(e),
            }
            if attempt + 1 < WRITE_ATTEMPTS {
                thread::sleep(Duration::from_millis(WRITE_RETRY_MS));
            }
        }
        Err(last.unwrap_or_else(|| io::Error::other("segment write")))
    }

    pub(crate) fn emit_data(&self, d: &DataSegment) -> io::Result<()> {
        self.emit(|buf| d.serialize(buf))
    }

    pub(crate) fn emit_ack(&self, a: &AckSegment) -> io::Result<()> {
        self.emit(|buf| a.serialize(buf))
    }

    pub(crate) fn emit_cmd(&self, c: &CmdOnlySegment) -> io::Result<()> {
        self.emit(|buf| c.serialize(buf))
    }
}

impl std::fmt::Debug for Ctx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ctx").finish_non_exhaustive()
    }
}

pub struct Connection {
    ctx: Arc<Ctx>,
    state_begin_time: AtomicU32,
    last_incoming_time: AtomicU32,
    last_ping_time: AtomicU32,
    since: Instant,
    data_input: Notifier,
    data_output: Notifier,
    update: Notifier,
    rd: Mutex<Option<Instant>>,
    wd: Mutex<Option<Instant>>,
    mss: u32,
    receiving: Mutex<ReceivingWorker>,
    sending: Mutex<SendingWorker>,
    closer: Mutex<Option<Box<Closer>>>,
    terminated: AtomicBool,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Connection {
    #[must_use]
    pub fn new(
        meta: ConnMetadata,
        writer: Writer,
        closer: Box<dyn FnOnce() + Send>,
        config: Config,
    ) -> Arc<Self> {
        let mss = config.mtu - super::segment::DATA_SEGMENT_OVERHEAD;
        let ctx = Arc::new(Ctx {
            meta,
            config,
            state: AtomicI32::new(0),
            round_trip: Mutex::new(RoundTripInfo::new(config.tti)),
            output: Mutex::new(OutputSink {
                buf: Vec::new(),
                write: writer,
            }),
        });
        let conn = Arc::new(Self {
            ctx: Arc::clone(&ctx),
            state_begin_time: AtomicU32::new(0),
            last_incoming_time: AtomicU32::new(0),
            last_ping_time: AtomicU32::new(0),
            since: Instant::now(),
            data_input: Notifier::new(),
            data_output: Notifier::new(),
            update: Notifier::new(),
            rd: Mutex::new(None),
            wd: Mutex::new(None),
            mss,
            receiving: Mutex::new(ReceivingWorker::new(config, mss, Arc::clone(&ctx))),
            sending: Mutex::new(SendingWorker::new(config, Arc::clone(&ctx))),
            closer: Mutex::new(Some(closer)),
            terminated: AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&conn);
        thread::spawn(move || {
            let mut last_uncond = Instant::now();
            let mut seen = u64::MAX;
            loop {
                let Some(conn) = weak.upgrade() else { break };
                let draining =
                    conn.state() == State::Terminating || conn.state() == State::PeerTerminating;
                let idle = if draining {
                    Duration::from_secs(1)
                } else {
                    Duration::from_millis(u64::from(config.tti))
                };
                if conn.update.gen() == seen {
                    conn.update.wait_since(seen, Some(idle));
                }
                seen = conn.update.gen();
                if conn.state() == State::Terminated {
                    break;
                }
                let necessary = conn.sending.lock().unwrap().update_necessary()
                    || conn.receiving.lock().unwrap().update_necessary();
                if draining || necessary || last_uncond.elapsed() >= Duration::from_secs(5) {
                    conn.flush();
                    last_uncond = Instant::now();
                }
                drop(conn);
            }
        });
        conn
    }

    #[must_use]
    pub fn state(&self) -> State {
        State::from_int(self.ctx.state.load(Ordering::SeqCst))
    }

    fn set_state(&self, state: State) {
        let current = self.elapsed();
        self.ctx.state.store(state as i32, Ordering::SeqCst);
        self.state_begin_time.store(current, Ordering::SeqCst);
        match state {
            State::ReadyToClose => {
                self.receiving.lock().unwrap().close_read();
            }
            State::PeerClosed | State::PeerTerminating => {
                self.sending.lock().unwrap().close_write();
            }
            State::Terminating => {
                self.receiving.lock().unwrap().close_read();
                self.sending.lock().unwrap().close_write();
            }
            State::Terminated => {
                self.receiving.lock().unwrap().close_read();
                self.sending.lock().unwrap().close_write();
                self.data_input.signal();
                self.data_output.signal();
                self.wake_update();
                self.terminated.store(true, Ordering::SeqCst);
                self.terminate();
            }
            State::Active => {}
        }
    }

    fn elapsed(&self) -> u32 {
        self.since.elapsed().as_millis() as u32
    }

    #[must_use]
    pub fn round_trip_timeout(&self) -> u32 {
        self.ctx.round_trip.lock().unwrap().timeout()
    }

    pub fn input(&self, segments: &[Segment]) {
        let current = self.elapsed();
        self.last_incoming_time.store(current, Ordering::SeqCst);
        for seg in segments {
            if seg.conversation() != self.ctx.meta.conversation {
                break;
            }
            if seg.option().is_close() {
                self.on_peer_closed();
            }
            match seg {
                Segment::Data(d) => {
                    self.receiving.lock().unwrap().process_segment(d.clone());
                    if self.receiving.lock().unwrap().is_data_available() {
                        self.data_input.signal();
                    }
                }
                Segment::Ack(a) => {
                    let rto = self.ctx.round_trip.lock().unwrap().timeout();
                    self.sending
                        .lock()
                        .unwrap()
                        .process_segment(current, a, rto);
                    self.data_output.signal();
                }
                Segment::CmdOnly(c) => {
                    if c.kind() == Some(Command::Terminate) {
                        match self.state() {
                            State::Active | State::PeerClosed => {
                                self.set_state(State::PeerTerminating);
                            }
                            State::ReadyToClose => self.set_state(State::Terminating),
                            State::Terminating => self.set_state(State::Terminated),
                            _ => {}
                        }
                    }
                    if c.option.is_close() || c.kind() == Some(Command::Terminate) {
                        self.data_input.signal();
                        self.data_output.signal();
                    }
                    self.sending
                        .lock()
                        .unwrap()
                        .process_receiving_next(c.receiving_next);
                    self.receiving
                        .lock()
                        .unwrap()
                        .process_sending_next(c.sending_next);
                    self.ctx
                        .round_trip
                        .lock()
                        .unwrap()
                        .update_peer_rto(c.peer_rto, current);
                }
            }
        }
        self.wake_update();
    }
}

const PING_INTERVAL_MS: u32 = 3000;

// A ping resets `last_ping_time`, so a worker ping already satisfies the interval.
fn ping_due(current: u32, last_ping: u32, worker_pinged: bool) -> bool {
    worker_pinged || current.wrapping_sub(last_ping) >= PING_INTERVAL_MS
}

impl Connection {
    pub fn flush(&self) {
        let current = self.elapsed();
        if self.state() == State::Terminated {
            return;
        }
        if self.state() == State::Active
            && current.wrapping_sub(self.last_incoming_time.load(Ordering::SeqCst)) >= 30000
        {
            self.close();
        }
        if self.state() == State::ReadyToClose && self.sending.lock().unwrap().is_empty() {
            self.set_state(State::Terminating);
        }
        if self.state() == State::Terminating {
            self.ping(current, Command::Terminate);
            if current.wrapping_sub(self.state_begin_time.load(Ordering::SeqCst)) > 8000 {
                self.set_state(State::Terminated);
            }
            return;
        }
        if self.state() == State::PeerTerminating
            && current.wrapping_sub(self.state_begin_time.load(Ordering::SeqCst)) > 4000
        {
            self.set_state(State::Terminating);
        }
        if self.state() == State::ReadyToClose
            && current.wrapping_sub(self.state_begin_time.load(Ordering::SeqCst)) > 15000
        {
            self.set_state(State::Terminating);
        }
        self.receiving.lock().unwrap().flush(current);
        let worker_pinged = self.sending.lock().unwrap().flush(current);
        if ping_due(
            current,
            self.last_ping_time.load(Ordering::SeqCst),
            worker_pinged,
        ) {
            self.ping(current, Command::Ping);
        }
    }

    pub fn ping(&self, current: u32, cmd: Command) {
        let seg = CmdOnlySegment {
            conv: self.ctx.meta.conversation,
            cmd: cmd.to_byte(),
            option: if self.state() == State::ReadyToClose {
                SegmentOption::CLOSE
            } else {
                SegmentOption::NONE
            },
            receiving_next: self.receiving.lock().unwrap().next_number(),
            sending_next: self.sending.lock().unwrap().first_unacknowledged(),
            peer_rto: self.ctx.round_trip.lock().unwrap().timeout(),
        };
        let _ = self.ctx.emit_cmd(&seg);
        self.last_ping_time.store(current, Ordering::SeqCst);
    }

    pub fn on_peer_closed(&self) {
        match self.state() {
            State::ReadyToClose => self.set_state(State::Terminating),
            State::Active => self.set_state(State::PeerClosed),
            _ => {}
        }
    }

    pub fn close(&self) {
        self.data_input.signal();
        self.data_output.signal();
        match self.state() {
            State::ReadyToClose | State::Terminating | State::Terminated => {}
            State::Active => self.set_state(State::ReadyToClose),
            State::PeerClosed => self.set_state(State::Terminating),
            State::PeerTerminating => self.set_state(State::Terminated),
        }
    }

    pub fn terminate(&self) {
        self.data_input.signal();
        self.data_output.signal();
        if let Some(closer) = self.closer.lock().unwrap().take() {
            closer();
        }
        self.sending.lock().unwrap().release();
        self.receiving.lock().unwrap().release();
    }

    pub fn read(&self, b: &mut [u8]) -> Result<usize, ConnError> {
        loop {
            if self.state() == State::ReadyToClose
                || self.state() == State::Terminating
                || self.state() == State::Terminated
            {
                return Err(ConnError::Closed);
            }
            let snap = self.data_input.gen();
            let n = self.receiving.lock().unwrap().read(b);
            if n > 0 {
                return Ok(n);
            }
            if self.state() == State::PeerTerminating {
                return Err(ConnError::Closed);
            }
            self.wait_for_data_input(snap)?;
        }
    }

    fn wait_for_data_input(&self, snap: u64) -> Result<(), ConnError> {
        if self
            .rd
            .lock()
            .unwrap()
            .map(|t| t <= Instant::now())
            .unwrap_or(false)
        {
            return Err(ConnError::IoTimeout);
        }
        let duration = match *self.rd.lock().unwrap() {
            Some(t) => t.saturating_duration_since(Instant::now()),
            None => Duration::from_secs(16),
        };
        if !self.data_input.wait_since(snap, Some(duration))
            && self
                .rd
                .lock()
                .unwrap()
                .map(|t| t <= Instant::now())
                .unwrap_or(false)
        {
            return Err(ConnError::IoTimeout);
        }
        Ok(())
    }

    fn wait_for_data_output(&self, snap: u64) -> Result<(), ConnError> {
        if self
            .wd
            .lock()
            .unwrap()
            .map(|t| t <= Instant::now())
            .unwrap_or(false)
        {
            return Err(ConnError::IoTimeout);
        }
        let duration = match *self.wd.lock().unwrap() {
            Some(t) => t.saturating_duration_since(Instant::now()),
            None => Duration::from_secs(16),
        };
        if !self.data_output.wait_since(snap, Some(duration))
            && self
                .wd
                .lock()
                .unwrap()
                .map(|t| t <= Instant::now())
                .unwrap_or(false)
        {
            return Err(ConnError::IoTimeout);
        }
        Ok(())
    }

    pub fn write(&self, b: &[u8]) -> Result<usize, ConnError> {
        let mut offset = 0;
        let mut pushed = false;
        while offset < b.len() {
            if self.state() != State::Active {
                return Err(ConnError::Closed);
            }
            let snap = self.data_output.gen();
            let n = (b.len() - offset).min(self.mss as usize);
            if !self
                .sending
                .lock()
                .unwrap()
                .push(b[offset..offset + n].to_vec())
            {
                if pushed {
                    self.wake_update();
                    pushed = false;
                }
                self.wait_for_data_output(snap)?;
                continue;
            }
            pushed = true;
            offset += n;
        }
        if pushed {
            self.wake_update();
        }
        Ok(b.len())
    }

    pub fn set_read_deadline(&self, t: Instant) {
        *self.rd.lock().unwrap() = Some(t);
    }

    pub fn set_write_deadline(&self, t: Instant) {
        *self.wd.lock().unwrap() = Some(t);
    }

    #[must_use]
    pub fn conversation(&self) -> u16 {
        self.ctx.meta.conversation
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.ctx.meta.local
    }

    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.ctx.meta.remote
    }

    fn wake_update(&self) {
        self.update.signal();
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    use super::{
        ping_due, CmdOnlySegment, Command, Config, ConnMetadata, Connection, PING_INTERVAL_MS,
        WRITE_ATTEMPTS,
    };

    fn counting_writer(
        fail_times: u32,
    ) -> (
        Arc<AtomicU32>,
        Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
        impl FnMut(&[u8]) -> io::Result<()> + Send,
    ) {
        let attempts = Arc::new(AtomicU32::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (a, s) = (Arc::clone(&attempts), Arc::clone(&seen));
        (attempts, seen, move |data: &[u8]| {
            let n = a.fetch_add(1, Ordering::SeqCst);
            s.lock().unwrap().push(data.to_vec());
            if n < fail_times {
                Err(io::Error::other("transient"))
            } else {
                Ok(())
            }
        })
    }

    #[test]
    fn a_failed_write_is_retried_with_the_same_bytes() {
        let local = ([127, 0, 0, 1], 1).into();
        let (attempts, seen, write) = counting_writer(2);
        let conn = Connection::new(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(write),
            Box::new(|| {}),
            Config::default(),
        );
        conn.ping(1, Command::Terminate);
        let seen = seen.lock().unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], seen[1]);
        assert_eq!(seen[1], seen[2]);
        assert_eq!(seen[0].len(), CmdOnlySegment::byte_size());
    }

    #[test]
    fn a_write_that_never_succeeds_stops_at_the_attempt_limit() {
        let local = ([127, 0, 0, 1], 1).into();
        let (attempts, _, write) = counting_writer(u32::MAX);
        let conn = Connection::new(
            ConnMetadata {
                local,
                remote: local,
                conversation: 4,
            },
            Box::new(write),
            Box::new(|| {}),
            Config::default(),
        );
        conn.ping(1, Command::Ping);
        assert_eq!(attempts.load(Ordering::SeqCst), WRITE_ATTEMPTS);
    }

    #[test]
    fn one_tick_pings_at_most_once() {
        for last in [0, 1, 500, 12_500] {
            for gap in [0, 1, 42, PING_INTERVAL_MS - 1, PING_INTERVAL_MS, 90_000] {
                assert!(ping_due(last + gap, last, true));
                assert_eq!(ping_due(last + gap, last, false), gap >= PING_INTERVAL_MS);
            }
        }
    }

    #[test]
    fn the_interval_wraps_instead_of_underflowing() {
        let before = u32::MAX - (PING_INTERVAL_MS - 2);
        assert!(!ping_due(
            before.wrapping_add(PING_INTERVAL_MS - 1),
            before,
            false
        ));
        assert!(ping_due(
            before.wrapping_add(PING_INTERVAL_MS),
            before,
            false
        ));
    }
}
