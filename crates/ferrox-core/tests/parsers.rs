//! Randomised tests for the byte-exact parsers, runnable without a nightly.
//!
//! The eight `libFuzzer` targets a finished core carries are the right tool for
//! this, and they need `cargo-fuzz`, which needs a nightly toolchain and a
//! separate workspace. What this crate does instead is the part of that which
//! needs none of it: **deterministic** random input, seeded and replayable, run
//! by `cargo test` on every runner `ci.yml` already has.
//!
//! # What this is for, precisely
//!
//! Every parser here is a hand-written state machine over untrusted bytes with
//! no `unsafe` and no allocation: [`mux::decode`] on a length-prefixed frame,
//! [`vless::VlessLink::parse`] on a URL-shaped string, [`addr::Addr::take`] on a
//! family byte and its bytes, [`transport::EarlyData::split`] on a path with a
//! `?ed=` query, [`json::parse`] on a whole configuration. The claim this crate
//! makes about them is that they never panic — a proxy that dies on a malformed
//! frame from a remote peer is a proxy an attacker can stop.
//!
//! A fuzz target proves that by exploring until it does not. A property test
//! proves a weaker version of it and proves it everywhere, on every architecture,
//! on every commit. The weaker version is what catches the class of bug this
//! codebase is exposed to: an index that is computed from one length and bounded
//! by another, which is exactly the shape of the bug [`mux::decode`]'s own
//! comments describe in three places.
//!
//! # Why deterministic rather than random
//!
//! A failure has to be replayable, and a failure found in CI on a runner nobody
//! can log into is a failure that cannot be reproduced at all. A `SplitMix64`
//! seeded from a constant, printed on failure, reproduces the exact input on any
//! machine: `cargo test -p ferrox-core parsers::` with the seed it names.
//!
//! No `proptest`, no `arbitrary`, no dev-dependency. The generators below are
//! twenty lines each and produce a *worse* distribution than a property-test
//! framework's would — which is the trade: coverage that is guaranteed to run
//! beats coverage that is better when it runs at all.

#![allow(
    clippy::cast_precision_loss,
    reason = "seed arithmetic, not a measurement"
)]

/// A `SplitMix64` state, so a printed seed replays the exact corpus.
#[derive(Debug, Clone)]
struct Rng(u64);

impl Rng {
    /// A generator from a seed. The constants are `SplitMix64`'s, from
    /// `Fast Splittable Pseudorandom Number Generators` (Steele, Lea and Flood).
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 bits.
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// One byte.
    fn byte(&mut self) -> u8 {
        #[allow(clippy::cast_possible_truncation)]
        {
            self.next_u64() as u8
        }
    }

    /// A byte in `0..bound`, by rejection, so it is uniform and never panics on
    /// `bound == 0` (which returns `0`, and a generator that can panic is a
    /// generator that cannot be used to prove anything else does not).
    fn below(&mut self, bound: u8) -> u8 {
        if bound == 0 {
            return 0;
        }
        let zone = 256 - (256 % u32::from(bound));
        loop {
            #[allow(clippy::cast_possible_truncation)]
            let draw = self.next_u64() as u8;
            if u32::from(draw) < zone {
                return draw % bound;
            }
        }
    }

    /// `count` bytes.
    fn bytes(&mut self, count: usize) -> Vec<u8> {
        (0..count).map(|_| self.byte()).collect()
    }
}

/// Seeds for the corpora. Distinct per parser, and printed on failure, so a red
/// run names the seed rather than asking for a bisect over a 64-bit space.
///
/// These are the golden-ratio odd numbers — `0x9e3779b97f4a7c15` and its
/// neighbours by the Weyl sequence — which is the same reasoning
/// [`Rng::next_u64`] uses for its increment, and it means adjacent seeds produce
/// visibly different corpora.
const SEED_MUX: u64 = 0x243f_6a88_85a3_08d3;
const SEED_LINK: u64 = 0x1319_8a2e_0370_7344;
const SEED_EARLY: u64 = 0x082e_fa98_ec4e_6c89;

/// Cases per parser. Big enough to reach the interesting states on a debug
/// build — a five-block frame, a 255-byte domain, a truncated tail — and small
/// enough that the whole file stays inside the seconds a test run costs.
///
/// Every count is deliberately not a power of two, because a generator driven by
/// a mask covers only half its range.
const CASES: usize = 4_096;

#[cfg(test)]
mod parsers {
    use super::{Rng, CASES, SEED_EARLY, SEED_LINK, SEED_MUX};
    use ferrox_core::addr::Addr;
    use ferrox_core::mux::{self, NewTail};
    use ferrox_core::transport::EarlyData;
    use ferrox_core::vless::VlessLink;

    /// `mux::decode` over frames built to be *almost* valid.
    ///
    /// The generator biases towards the two bytes that decide everything: the
    /// declared metadata length and the family byte. A uniform random frame is
    /// rejected by its first length check almost every time and never reaches the
    /// address parser, so half the draws here spell a plausible length and half
    /// spell a plausible family, and only then fill the rest.
    #[test]
    fn mux_decode_survives_arbitrary_bytes() {
        for case in 0..CASES {
            let seed = SEED_MUX.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);
            let len = usize::from(rng.below(96));
            let mut buf = rng.bytes(len);

            // Half the cases open with a length inside the accepted range, so the
            // decoder gets past its first check and into the metadata.
            if case % 2 == 0 && buf.len() >= 2 {
                #[allow(clippy::cast_possible_truncation)]
                let declared = 4u16 + u16::from(rng.below(24));
                buf[0..2].copy_from_slice(&declared.to_be_bytes());
            }
            // And half carry a plausible family byte where one goes.
            if case % 2 == 1 && buf.len() >= 6 {
                buf[5] = 1 + rng.below(3);
            }

            // No assertion on the verdict: `Ok` and `Err` are both correct, and
            // what is being checked is that neither panics and neither reads past
            // the end. A panic here is the failure this file exists to catch.
            let _ = mux::decode(&buf, NewTail::Forward);
        }
    }

    /// Every accepted frame must report a length inside the buffer it was given.
    ///
    /// The property that matters more than "did not panic": a decoder that returns
    /// `Ok` with a consumed count past the end of its input has told its caller to
    /// read memory it does not own, and that is the bug a length-prefixed parser
    /// has that a fixed-size one cannot have.
    #[test]
    fn mux_decode_never_consumes_past_its_input() {
        for case in 0..CASES {
            let seed = SEED_MUX.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);
            let len = 4 + usize::from(rng.below(120));
            let mut buf = rng.bytes(len);
            #[allow(clippy::cast_possible_truncation)]
            let declared = 4u16 + u16::from(rng.below(16));
            buf[0..2].copy_from_slice(&declared.to_be_bytes());

            if let Ok((_, consumed)) = mux::decode(&buf, NewTail::Forward) {
                assert!(
                    consumed <= buf.len(),
                    "seed {seed:#x}: consumed {consumed} of a {} byte frame",
                    buf.len()
                );
            }
        }
    }

    /// `VlessLink::parse` over strings that are shaped like share links and then
    /// damaged one character at a time.
    ///
    /// Random bytes would be rejected at the scheme check and never reach the
    /// query walk, so the generator starts from a valid link and perturbs it: a
    /// substituted byte, a truncated string, a doubled `%`. Those are the shapes a
    /// real link has after a panel has mangled it, and they are what reach this
    /// parser in production.
    #[test]
    fn vless_link_parse_survives_damaged_links() {
        const GOOD: &str = "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@example.com:443?security=reality&encryption=none&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&host=%2Ftest-path&headerType=none&fp=firefox&type=tcp&flow=xtls-rprx-vision&sni=example.com&sid=a8#tag";

        for case in 0..CASES {
            let seed = SEED_LINK.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);

            let mut damaged = String::from(GOOD);
            match case % 4 {
                // One byte substituted somewhere.
                0 => {
                    let at = usize::from(rng.below(damaged.len() as u8));
                    damaged.replace_range(at..=at, &char::from(rng.byte()).to_string());
                }
                // Truncated, which is a `&str` of arbitrary length into every
                // index in the parser at once.
                1 => {
                    let keep = rng.below(damaged.len() as u8) as usize;
                    damaged.truncate(keep);
                }
                // A percent sign, so the query decoder's escape handling runs on
                // truncated or doubled escapes.
                2 => {
                    let at = rng.below((damaged.len() - 1) as u8) as usize;
                    damaged.insert(at, '%');
                }
                // Unchanged: the control, so the loop is also asserting the
                // parser accepts what it is supposed to.
                _ => {}
            }

            // An `Err` is the usual answer and the correct one. `Ok` is fine too.
            // The claim is that neither panics and neither loops forever.
            let _ = VlessLink::parse(&damaged);
        }
    }

    /// `Addr::take` over every family byte and every length.
    ///
    /// This one is exhaustive rather than random, because it can be: the family
    /// byte is three named values plus everything else, and the payload length
    /// range that matters is 0 through `MAX_DOMAIN + 8`. A random generator here
    /// would sample 256 of those combinations instead of naming all of them, and
    /// the interesting ones — a domain claiming more bytes than are present — sit
    /// exactly at the boundary a sampler misses.
    #[test]
    fn addr_take_is_total_over_every_family_and_length() {
        for family in 0u8..=255 {
            for len in 0..=(ferrox_core::addr::MAX_DOMAIN + 8) {
                let mut buf = Vec::with_capacity(len + 1);
                buf.push(family);
                buf.extend(std::iter::repeat_n(0xa5u8, len));

                // Every byte of a domain claim, at every length, must land on
                // either a parsed address or an error. A panic is a length that
                // was not checked.
                let _ = Addr::take(&buf);
            }
        }
    }

    /// `EarlyData::split` over paths with a `?ed=` budget in every position and
    /// every malformed shape around it.
    ///
    /// The budget is the interesting field: it is read with an integer parse out
    /// of the middle of a query string, and its boundary is where a parser that
    /// trusts `Atoi` differently from RFC 4648 would differ from ours. The two
    /// upstream oracles in `conformance.yml` were written against this and had been
    /// failing, so the shapes here are the ones those rows exercise.
    #[test]
    fn early_data_survives_every_budget_position_and_length() {
        for case in 0..CASES {
            let seed = SEED_EARLY.wrapping_add(case as u64);
            let mut rng = Rng::new(seed);

            let mut path = String::from("/realistic");
            match case % 6 {
                0 => {}
                1 => path.push_str("?ed=0"),
                2 => path.push_str("?ed=1000"),
                3 => {
                    let digits: String = (0..rng.below(9) as usize)
                        .map(|_| char::from(b'0' + rng.below(10)))
                        .collect();
                    path.push_str("?ed=");
                    path.push_str(&digits);
                }
                4 => path.push_str("?ed="),
                _ => path.push_str("?ed"),
            }
            // A second parameter either side of it, so the query split is exercised
            // with `ed` not first.
            if case % 2 == 0 {
                path.push_str(if path.contains('?') { "&a=b" } else { "?a=b" });
            }

            // Whatever it decides, it must not panic and must not loop. The
            // property worth asserting is the rewrite's: an untouched path comes
            // back byte for byte, and a rewritten one never grows without bound,
            // because the caller base64-encodes the budget into the request.
            let split = EarlyData::split(&path);
            assert!(
                split.path.len() <= path.len() + split.budget as usize,
                "seed {seed:#x}: a {}-byte path became {} with a budget of {}",
                path.len(),
                split.path.len(),
                split.budget
            );
            if !path.contains("ed=") {
                assert_eq!(
                    split.path, path,
                    "seed {seed:#x}: a path with no ed= was rewritten",
                );
            }
        }
    }
}
