#![allow(clippy::missing_panics_doc)]
//! The two ways a mkcp connection starts: client `dial` and server
//! `Listener`. Both sit on plain `UDP` sockets, demux datagrams into
//! segments, and hand each conversation to its own [`Connection`].

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use super::config::Config;

use super::connection::{ConnMetadata, Connection, State};
use super::segment::{read_segment, Command, Segment};

/// The one-datagram writer injected per session.
type Writer = Box<dyn FnMut(&[u8]) -> io::Result<()> + Send>;

static NEXT_CONVERSATION: AtomicU16 = AtomicU16::new(1);

fn next_conversation() -> u16 {
    NEXT_CONVERSATION.fetch_add(1, Ordering::Relaxed).max(1)
}

/// Every datagram in one input buffer, parsed front to back.
fn parse_segments(buf: &[u8]) -> Vec<Segment> {
    let mut out = Vec::new();
    let mut rest = buf;
    while let Some((seg, tail)) = read_segment(rest) {
        out.push(seg);
        rest = tail;
    }
    out
}

/// Read loop for one connected UDP socket backing one conversation.
fn feed(sock: &UdpSocket, conn: &Connection) {
    let mut buf = vec![0u8; 65536];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => conn.input(&parse_segments(&buf[..n])),
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if conn.state() == State::Terminated {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

/// Dial one peer: a connected `UDP` socket, one conversation, one reader
/// thread. `conv` is the caller's conversation id — upstream picks one
/// from a global counter; the caller now picks its own scheme.
#[allow(clippy::missing_panics_doc)]
pub fn dial(addr: SocketAddr, config: Config, conv: u16) -> io::Result<Arc<Connection>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(addr)?;
    let local = sock.local_addr()?;
    let sock_w = sock.try_clone()?;
    let writer = Box::new(move |data: &[u8]| sock_w.send(data).map(|_| ()));
    let sock_c = sock.try_clone()?;
    let closer = Box::new(move || drop(sock_c));
    let connection = Connection::new(
        ConnMetadata {
            local,
            remote: addr,
            conversation: conv,
        },
        writer,
        closer,
        config,
    );
    let sock_r = sock.try_clone()?;
    sock_r.set_read_timeout(Some(Duration::from_millis(50)))?;
    let c2 = Arc::clone(&connection);
    thread::spawn(move || feed(&sock_r, &c2));
    Ok(connection)
}

/// A process-wide conversation counter for callers that do not care
/// which, mirroring the upstream's atomic global.
#[must_use]
pub fn fresh_conversation() -> u16 {
    next_conversation()
}

/// The server side: one `UDP` socket, one `Connection` per (peer,
/// conversation) pair.
pub struct Listener {
    inner: Arc<ListenerInner>,
}

struct ListenerInner {
    sessions: Mutex<HashMap<(SocketAddr, u16), Arc<Connection>>>,
    ready: Mutex<VecDeque<Arc<Connection>>>,
    ready_cv: Condvar,
    config: Config,
    closed: AtomicBool,
    addr: SocketAddr,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").finish_non_exhaustive()
    }
}

impl Listener {
    /// Bind a `UDP` socket and start routing.
    pub fn bind(addr: SocketAddr, config: Config) -> io::Result<Self> {
        let sock = UdpSocket::bind(addr)?;
        let local = sock.local_addr()?;
        let inner = Arc::new(ListenerInner {
            sessions: Mutex::new(HashMap::new()),
            ready: Mutex::new(VecDeque::new()),
            ready_cv: Condvar::new(),
            config,
            closed: AtomicBool::new(false),
            addr: local,
        });
        let sock_r = sock.try_clone()?;
        sock_r.set_read_timeout(Some(Duration::from_millis(50)))?;
        let weak = Arc::downgrade(&inner);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            loop {
                {
                    let Some(inner) = weak.upgrade() else { break };
                    if inner.closed.load(Ordering::SeqCst) {
                        break;
                    }
                }
                match sock_r.recv_from(&mut buf) {
                    Ok((n, src)) => {
                        let Some(inner) = weak.upgrade() else { break };
                        let segs = parse_segments(&buf[..n]);
                        if segs.is_empty() {
                            continue;
                        }
                        let conv = segs[0].conversation();
                        let key = (src, conv);
                        let existing = inner.sessions.lock().unwrap().get(&key).cloned();
                        if let Some(session) = existing {
                            session.input(&segs);
                            continue;
                        }
                        if segs[0].command() == Some(Command::Terminate) {
                            continue;
                        }
                        let Ok(sock_w) = sock_r.try_clone() else {
                            continue;
                        };
                        let writer: Writer =
                            Box::new(move |data: &[u8]| sock_w.send_to(data, src).map(|_| ()));
                        let sessions_slot = Arc::downgrade(&inner);
                        let closer: Box<dyn FnOnce() + Send> = Box::new(move || {
                            if let Some(inner) = sessions_slot.upgrade() {
                                inner.sessions.lock().unwrap().remove(&key);
                            }
                        });
                        let local = inner.addr;
                        let session = Connection::new(
                            ConnMetadata {
                                local,
                                remote: src,
                                conversation: conv,
                            },
                            writer,
                            closer,
                            inner.config,
                        );
                        inner
                            .sessions
                            .lock()
                            .unwrap()
                            .insert(key, Arc::clone(&session));
                        session.input(&segs);
                        inner.ready.lock().unwrap().push_back(session);
                        inner.ready_cv.notify_all();
                    }
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        });
        Ok(Self { inner })
    }

    /// Local socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// Block until a new connection arrives; `Err` once closed.
    pub fn accept(&self) -> io::Result<Arc<Connection>> {
        let mut ready = self.inner.ready.lock().unwrap();
        loop {
            if let Some(conn) = ready.pop_front() {
                return Ok(conn);
            }
            if self.inner.closed.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "listener closed"));
            }
            ready = self.inner.ready_cv.wait(ready).unwrap();
        }
    }

    /// Stop: close every session and refuse new ones.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        let mut sessions = self.inner.sessions.lock().unwrap();
        for (_, conn) in sessions.drain() {
            conn.terminate();
        }
        self.inner.ready_cv.notify_all();
    }
}
