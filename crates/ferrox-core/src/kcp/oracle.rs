//! The scripted-clock oracle: the same script the Go harness runs, the same
//! recorder output format. The expected text is produced by the pinned Go
//! code in `scripts/kcp-oracle` and checked in, so this test runs without
//! Go; regenerating it is one command.

#![allow(clippy::missing_panics_doc)]

use std::fmt::Write as _;
use std::path::PathBuf;

use super::roundtrip::RoundTripInfo;
use super::segment::{AckSegment, DataSegment, Segment};
use super::window::{AckList, SendingWindow};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn emit_data(lines: &mut Vec<String>, seg: &mut DataSegment) {
    let mut buf = Vec::new();
    Segment::Data(seg.clone()).serialize(&mut buf);
    lines.push(format!("SEG {}", hex(&buf)));
}

fn emit_ack(lines: &mut Vec<String>, seg: &mut AckSegment) {
    let mut buf = Vec::new();
    Segment::Ack(seg.clone()).serialize(&mut buf);
    lines.push(format!("SEG {}", hex(&buf)));
}

#[test]
fn the_scripted_core_matches_the_pinned_go() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/kcp-oracle");
    let script = std::fs::read_to_string(root.join("script.txt")).expect("script");
    let expected = std::fs::read_to_string(root.join("expected.txt")).expect("expected");

    let mut sw = SendingWindow::default();
    let mut al = AckList::default();
    let mut rtt = RoundTripInfo::default();
    let mut lines = Vec::new();

    for line in script.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "sw_new" => {
                sw = SendingWindow::new();
            }
            "sw_push" => {
                let n: u32 = parts[1].parse().unwrap();
                sw.push(n, parts[2..].join(" ").into_bytes());
            }
            "sw_flush" => {
                let cur: u32 = parts[1].parse().unwrap();
                let rto: u32 = parts[2].parse().unwrap();
                let max: u32 = parts[3].parse().unwrap();
                let rate = sw.flush(cur, rto, max, &mut |seg: &mut DataSegment| {
                    emit_data(&mut lines, seg);
                });
                if let Some(rate) = rate {
                    lines.push(format!("loss {rate}"));
                }
            }
            "sw_fastack" => {
                let n: u32 = parts[1].parse().unwrap();
                let rto: u32 = parts[2].parse().unwrap();
                sw.handle_fast_ack(n, rto);
            }
            "sw_remove" => {
                let n: u32 = parts[1].parse().unwrap();
                lines.push(format!("removed {}", sw.remove(n)));
            }
            "sw_clear" => {
                let una: u32 = parts[1].parse().unwrap();
                sw.clear(una);
            }
            "sw_len" => {
                lines.push(format!("len {}", sw.len()));
            }
            "sw_first" => {
                lines.push(format!("first {}", sw.first_number()));
            }
            "al_new" => {
                al = AckList::new();
            }
            "al_add" => {
                let n: u32 = parts[1].parse().unwrap();
                let ts: u32 = parts[2].parse().unwrap();
                al.add(n, ts);
            }
            "al_clear" => {
                let una: u32 = parts[1].parse().unwrap();
                al.clear(una);
            }
            "al_flush" => {
                let cur: u32 = parts[1].parse().unwrap();
                let rto: u32 = parts[2].parse().unwrap();
                al.flush(cur, rto, (1350 - 17) / 4, &mut |seg: &mut AckSegment| {
                    emit_ack(&mut lines, seg);
                });
            }
            "rtt_update" => {
                let a: u32 = parts[1].parse().unwrap();
                let b: u32 = parts[2].parse().unwrap();
                rtt.update(a, b);
            }
            "rtt_peer" => {
                let a: u32 = parts[1].parse().unwrap();
                let b: u32 = parts[2].parse().unwrap();
                rtt.update_peer_rto(a, b);
            }
            "rtt_timeout" => {
                lines.push(format!("timeout {}", rtt.timeout()));
            }
            other => panic!("unknown op {other}"),
        }
    }
    assert_eq!(lines.join("\n") + "\n", expected);
}
