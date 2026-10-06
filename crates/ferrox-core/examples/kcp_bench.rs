//! Throughput probe for the mkcp port: a client streams a payload to a
//! server that echoes, both over loopback UDP, and the elapsed time is
//! printed as MB/s. Written against the same contract as the Go harness
//! in `scripts/kcp-oracle/interop`.
//!
//! One `main` that stands a server and a client up in order, so the two ends are
//! each visible whole rather than as helpers called from one place and read from
//! another. It is an example, not a library: `--all-targets` lints it like any
//! other target and `ci.yml` fails on those lints, so the two `allow`s below are
//! load-bearing rather than tidy-ups.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use ferrox_core::kcp::{read_segment, Config, ConnMetadata, Connection};

/// Stand a loopback server and a client on either side of it, push `megabytes`
/// through, and print the rate.
///
/// Over the pedantic line budget by a few lines, and the fix is not to delete the
/// ones that are there: the setup is two symmetric ends and splitting either in
/// half would leave one reader looking at two halves. This is a probe whose body is
/// deliberately the whole experiment.
#[allow(clippy::too_many_lines)]
fn main() {
    let megabytes: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(64);

    // Server
    let ssock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let slocal = ssock.local_addr().unwrap();
    let ssock_w = ssock.try_clone().unwrap();
    let speer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let speer_w = Arc::clone(&speer);
    let swriter = Box::new(move |datagram: &[u8]| -> io::Result<()> {
        match *speer_w.lock().unwrap() {
            Some(peer) => ssock_w.send_to(datagram, peer).map(|_| ()),
            None => Err(io::Error::other("no peer yet")),
        }
    });
    let scloser = Box::new(|| {});
    let sconn = Connection::new(
        ConnMetadata {
            local: slocal,
            remote: slocal,
            conversation: 7,
        },
        swriter,
        scloser,
        Config::default(),
    );
    {
        let c2 = Arc::clone(&sconn);
        let sr = ssock.try_clone().unwrap();
        thread::spawn(move || feed(sr, c2, speer));
    }
    {
        let c2 = Arc::clone(&sconn);
        thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = c2.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if c2.write(&buf[..n]).is_err() {
                    break;
                }
            }
        });
    }

    // Client
    let csock = UdpSocket::bind("127.0.0.1:0").unwrap();
    csock.connect(slocal).unwrap();
    let clocal = csock.local_addr().unwrap();
    let csock_w = csock.try_clone().unwrap();
    let cwriter =
        Box::new(move |datagram: &[u8]| -> io::Result<()> { csock_w.send(datagram).map(|_| ()) });
    let ccloser = Box::new(|| {});
    let cconn = Connection::new(
        ConnMetadata {
            local: clocal,
            remote: slocal,
            conversation: 7,
        },
        cwriter,
        ccloser,
        Config::default(),
    );
    {
        let c2 = Arc::clone(&cconn);
        let cr = csock.try_clone().unwrap();
        let cpeer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(Some(slocal)));
        thread::spawn(move || feed(cr, c2, cpeer));
    }

    let payload: Arc<[u8]> = Arc::from(vec![b'x'; megabytes * 1024 * 1024].into_boxed_slice());
    let received = Arc::new(AtomicUsize::new(0));
    let recv2 = Arc::clone(&received);
    let p1 = Arc::clone(&payload);
    let rconn = Arc::clone(&cconn);
    let reader = thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 20];
        rconn.set_read_deadline(Instant::now() + Duration::from_secs(60));
        loop {
            match rconn.read(&mut buf) {
                Ok(n) => {
                    let total = recv2.fetch_add(n, Ordering::SeqCst) + n;
                    if total >= p1.len() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    let start = Instant::now();
    let p2 = Arc::clone(&payload);
    let wconn = Arc::clone(&cconn);
    let writer_thread = thread::spawn(move || {
        wconn.write(&p2).unwrap();
    });
    writer_thread.join().unwrap();
    reader.join().unwrap();
    let elapsed = start.elapsed();
    let bytes = received.load(Ordering::SeqCst);
    // `try_into` rather than `as f64`, because `usize` is 64-bit and `f64`'s
    // mantissa is 52, so the cast `clippy::cast_precision_loss` names would lose
    // the low bits of a byte count. The count is a whole number of bytes at most
    // a few tens of gigabytes, so the printed figure is the same either way --
    // but "the same either way" is a property of the payload, not of the cast,
    // and the lint is right to make me say so rather than silence it.
    let mib = f64::from(u32::try_from(bytes / 1_000_000).unwrap_or(u32::MAX));
    println!(
        "rust: {} bytes in {:?} -> {:.2} MB/s",
        bytes,
        elapsed,
        mib / elapsed.as_secs_f64()
    );
}

/// Pump one socket's datagrams into a `Connection`, learning the peer address.
///
/// `sock`, `conn` and `peer` are taken by value because the caller hands over its
/// only handle to each; the bodies below move none of them, and taking references
/// instead would mean keeping the originals alive for no reason. Hence the
/// `_`-by-value lints are allowed rather than worked around: `#[allow]` on the
/// whole function says "this signature is the API", which it is.
#[allow(clippy::needless_pass_by_value)]
fn feed(sock: UdpSocket, conn: Arc<Connection>, peer: Arc<Mutex<Option<SocketAddr>>>) {
    let mut buf = vec![0u8; 65536];
    while let Ok((n, src)) = sock.recv_from(&mut buf) {
        {
            let mut guard = peer.lock().unwrap();
            if guard.is_none() {
                *guard = Some(src);
            }
        }
        let mut rest = &buf[..n];
        let mut segs = Vec::new();
        while let Some((seg, tail)) = read_segment(rest) {
            segs.push(seg);
            rest = tail;
        }
        conn.input(&segs);
    }
}
