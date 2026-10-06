//! Why a connection attempt failed, in the form a recovery decision needs.
//!
//! [`std::io::Error`] answers "what did the operating system say", which is not
//! the question a proxy asks. The question is whether *trying this again, or
//! trying something else, could plausibly work* — and an `errno` cannot answer
//! that, because the same `ECONNREFUSED` means one thing from a dead server and
//! another from a path that was closed by a middlebox, and the proxy cannot tell
//! which it got.
//!
//! So an attempt reports two things the errno does not carry: how far it got
//! ([`Stage`]), and how much the observation is worth ([`Confidence`]).
//!
//! # The ladder, and the one line that matters
//!
//! A completed `TCP` handshake means almost nothing on a filtered network, so
//! the stages are ordered by evidence and [`Stage::is_useful_progress`] is the
//! threshold at which a stage is worth believing:
//!
//! ```text
//! Resolving < SocketConnected < TlsStarted < TlsCompleted
//!           < RequestSent < FirstByte < PayloadTransferred
//! ```
//!
//! Everything below `FirstByte` is *possible* progress, not proof. A path that
//! completes a handshake and then drops every byte looks identical to a path
//! that never connected, and any recovery policy that treats them alike will
//! redial a filtered route forever. This is why the stage is stored rather than
//! inferred from the error: the error arrives too late to know where the attempt
//! stopped.
//!
//! # Why these variants and not the ones a full implementation wants
//!
//! This is the minimal subset that covers the transport superset in
//! [`crate::transport`], not the taxonomy a finished product needs. A finished
//! one distinguishes `DNS` interference from `DNS` NXDOMAIN, `TCP` unreachable
//! from `TCP` refused, and `TLS` certificate failure from `TLS` alert, because
//! its resolver and its balancer can act on the difference. This core has no
//! resolver — [`crate::vless`] and `ferrox-app` hand a name to the
//! platform's resolver and take what comes back, which is itself a leak surface
//! `scripts/check-leak-surface.sh` exists to keep out of the core, and so named
//! here in prose rather than in code — so a `DnsTimeout` variant here
//! would name a stage no caller in this tree can reach. Carried anyway would be
//! dead weight; left out, the next slice that lands a resolver adds the variants
//! its own decisions need, with tests that pin them.
//!
//! What is here is what every rung in the matrix can already observe:
//!
//! - [`Stage`] — the ladder above, six rungs, `is_useful_progress` on it.
//! - [`Kind`] — what refused, at the granularity this tree's sockets report.
//! - [`Confidence`] — observed directly, or inferred from a timeout.
//!
//! # Licence
//!
//! Re-derived, not translated. A failure taxonomy is a set of decisions, not an
//! implementation; the pinned `ZeroNet` core has its own (`upstream/zeronet/`,
//! `crates/zero-core/src/error.rs`, read for the argument that a `Stage` ladder
//! is worth having). No line and no variant list is carried from it. What that
//! file has and this does not — thirty-odd `Kind` variants, a
//! `Confidence::Likely` middle rung — is what a finished recovery engine needs
//! and this core cannot yet act on; see `docs/zeronet-comparison.md` §4.1.

use std::fmt;

/// How far an attempt got before it failed.
///
/// Ordered by evidence rather than by chronology: a later stage is strictly more
/// informative than an earlier one, which is what makes `>=` the right comparison
/// and [`Stage::is_useful_progress`] the right threshold. The discriminants are
/// explicit so the ordering is a property of the type and not of the declaration
/// order in this file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Stage {
    /// A name is being resolved. Not yet a network fact.
    Resolving = 0,
    /// The socket is connected. Proves a three-way handshake completed, which on
    /// a filtered network proves very little.
    SocketConnected = 1,
    /// Bytes have been sent to the peer and none has come back.
    RequestSent = 2,
    /// The first response byte arrived. The threshold: past here, bytes moved
    /// both ways and the path is working.
    FirstByte = 3,
    /// Payload has moved in both directions.
    PayloadTransferred = 4,
    /// The session ended cleanly.
    Completed = 5,
}

impl Stage {
    /// The stage's position on the ladder.
    ///
    /// A `const fn` reading the discriminant, because `PartialOrd`'s derived
    /// comparison is not `const` and both thresholds below are wanted in constant
    /// context. One definition of the order, used by the ordering the derives give
    /// and by the two predicates, so the two cannot disagree.
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    /// Whether reaching this stage justifies treating the path as working.
    ///
    /// One comparison against [`Stage::rank`], so the threshold cannot drift as
    /// stages are added. This is the single most load-bearing line in the file:
    /// every recovery policy reads it, and a policy that believed
    /// [`Stage::SocketConnected`] would redial a filtered route indefinitely.
    #[must_use]
    pub const fn is_useful_progress(self) -> bool {
        self.rank() >= Self::FirstByte.rank()
    }

    /// Every stage, ascending. The iteration order a report or a test wants.
    pub const ALL: [Self; 6] = [
        Self::Resolving,
        Self::SocketConnected,
        Self::RequestSent,
        Self::FirstByte,
        Self::PayloadTransferred,
        Self::Completed,
    ];

    /// The stage's name, for reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Resolving => "resolving",
            Self::SocketConnected => "socket-connected",
            Self::RequestSent => "request-sent",
            Self::FirstByte => "first-byte",
            Self::PayloadTransferred => "payload-transferred",
            Self::Completed => "completed",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What refused, at the granularity this tree's sockets report.
///
/// Coarse on purpose. [`std::io::ErrorKind`] is already a flat list that every
/// platform fills in inconsistently — `ErrorKind::Other` is where anything
/// unmapped lands, and on Windows it absorbs most of them — so a finer taxonomy
/// here would be a finer taxonomy over a source that cannot support it. The
/// distinction that survives every platform is *who* refused and *whether it
/// said anything on the way out*, and that is what these five variants are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Nothing answered. A timeout, or a black hole: no reset, no response, no
    /// evidence either way. Indistinguishable from a filtered path, which is why
    /// it carries [`Confidence::Inferred`] wherever it is produced.
    Unreachable,
    /// The peer actively refused: `ECONNREFUSED`, or a `RST` before any byte.
    Refused,
    /// The peer accepted and then the path died: reset mid-stream, or a
    /// middlebox closing an established flow. Different from [`Self::Refused`]
    /// because the path demonstrably worked first.
    Dropped,
    /// A name did not resolve. Only reachable from a caller that resolves; see
    /// the module docs on why this core has no resolver.
    Dns,
    /// The peer's answer did not parse as this protocol, or its credentials were
    /// refused. The attempt got far enough to be *answered wrongly*, which is a
    /// different problem from being unable to reach it.
    Rejected,
    /// The local end could not start: no socket, no file descriptor, or the
    /// address was not one this tree can dial.
    Local,
}

impl Kind {
    /// The kind's name, for reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Refused => "refused",
            Self::Dropped => "dropped",
            Self::Dns => "dns",
            Self::Rejected => "rejected",
            Self::Local => "local",
        }
    }

    /// Classify an `io::Error` into the coarsest kind that is still actionable.
    ///
    /// The mapping is total and lossy on purpose: every `ErrorKind` lands
    /// somewhere, because a classification that returns nothing gives the caller
    /// nothing to branch on and pushes the guess back to the call site. An
    /// unmapped kind becomes [`Kind::Unreachable`], which is the conservative
    /// choice — it is the kind that never claims more than it knows.
    #[must_use]
    pub fn of(error: &std::io::Error) -> Self {
        use std::io::ErrorKind as E;
        match error.kind() {
            E::ConnectionRefused => Self::Refused,
            E::ConnectionReset | E::ConnectionAborted | E::BrokenPipe => Self::Dropped,
            // `NotFound` covers `EAI_NONAME` as much as a missing file, and this
            // core's callers hand names to a resolver, so the DNS reading is the
            // one that can occur.
            E::NotFound => Self::Dns,
            E::PermissionDenied | E::AddrNotAvailable | E::InvalidInput => Self::Local,
            // `TimedOut` with everything unmapped: a timeout proves nothing
            // arrived, which is exactly what `Unreachable` means, and on Windows
            // `ErrorKind::Other` absorbs most of the specific failures anyway.
            _ => Self::Unreachable,
        }
    }

    /// Whether a retry of the *same* attempt could plausibly succeed.
    ///
    /// The distinction a caller makes first, because it is the one that decides
    /// between waiting and changing something. [`Self::Refused`] and
    /// [`Self::Dns`] say the target is not serving: waiting does not help.
    /// [`Self::Dropped`] and [`Self::Unreachable`] say nothing about the target,
    /// only about the path, and a path can come back.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(self, Self::Dropped | Self::Unreachable)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How much a failure observation should be trusted.
///
/// A two-rung scale, not a three. A middle "probably interference" would need a
/// caller that can act differently on it, and there is no such caller here: the
/// only question a rung in the matrix asks is whether to try again, and both
/// rungs of a three-rung scale answer it identically. A rung appears when a
/// decision appears.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Inferred from the absence of an event. A timeout proves nothing arrived,
    /// which is not the same as proving something blocked it.
    Inferred,
    /// Directly observed: a reset, a refused connection, a malformed reply.
    Observed,
}

/// One failed attempt: how far it got, what refused, and how much that is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Failure {
    /// The furthest stage the attempt reached.
    pub stage: Stage,
    /// What refused.
    pub kind: Kind,
    /// How the observation was made.
    pub confidence: Confidence,
}

impl Failure {
    /// A failure at `stage` from `kind`, with the confidence `kind` implies.
    ///
    /// [`Kind::Unreachable`] is the only kind that can be produced by the absence
    /// of an event, so it is the only one that gets [`Confidence::Inferred`];
    /// every other kind was observed directly by definition.
    #[must_use]
    pub const fn new(stage: Stage, kind: Kind) -> Self {
        Self {
            stage,
            kind,
            confidence: match kind {
                Kind::Unreachable => Confidence::Inferred,
                _ => Confidence::Observed,
            },
        }
    }

    /// Whether the path is worth redialling as it is.
    ///
    /// Both conditions must hold, and they are independent: a refused connection
    /// after a byte arrived is not worth retrying because nothing was actually
    /// refused, and an unreachable path that never got a byte is not worth
    /// retrying because the evidence says nothing went wrong.
    #[must_use]
    pub const fn worth_retrying(&self) -> bool {
        self.kind.retryable() && self.stage.rank() < Stage::FirstByte.rank()
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.kind, self.stage)?;
        if self.confidence == Confidence::Inferred {
            f.write_str(" (inferred)")
        } else {
            Ok(())
        }
    }
}

impl std::error::Error for Failure {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Support, TransportKind};
    use crate::vless::VlessLink;
    use std::io::{Error, ErrorKind};

    #[test]
    fn stage_order_is_evidence_order() {
        for pair in Stage::ALL.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{:?} must sort below {:?}",
                pair[0],
                pair[1]
            );
            assert!(
                pair[0].is_useful_progress() <= pair[1].is_useful_progress(),
                "the threshold must be monotone or it is not a threshold"
            );
        }
    }

    #[test]
    fn first_byte_is_the_threshold_and_nothing_earlier_is() {
        for stage in Stage::ALL {
            assert_eq!(
                stage.is_useful_progress(),
                stage >= Stage::FirstByte,
                "{stage} disagrees with the ladder"
            );
        }
        assert!(!Stage::SocketConnected.is_useful_progress());
        assert!(Stage::FirstByte.is_useful_progress());
    }

    #[test]
    fn every_stage_has_a_distinct_name() {
        let mut names: Vec<&str> = Stage::ALL.iter().map(|s| s.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            count,
            "two stages share a name, so a report cannot tell them apart"
        );
        for stage in Stage::ALL {
            assert_eq!(stage.to_string(), stage.name());
        }
    }

    #[test]
    fn every_error_kind_lands_somewhere_and_the_unmapped_one_is_conservative() {
        // `of` is total by contract: it returns a `Kind` and not an `Option`, so
        // every one of these lands. The assertion is that the landed kind is one
        // the taxonomy names, checked through `Display` rather than by re-listing
        // the arms — a kind with no name would print as an empty string.
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::PermissionDenied,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::AddrNotAvailable,
            ErrorKind::BrokenPipe,
            ErrorKind::TimedOut,
            ErrorKind::Interrupted,
            ErrorKind::InvalidInput,
            ErrorKind::WouldBlock,
            ErrorKind::UnexpectedEof,
        ] {
            let name = Kind::of(&Error::new(kind, "x")).to_string();
            assert!(!name.is_empty(), "{kind:?} landed on an unnamed kind");
        }
        // And the unmapped kinds all take the conservative one: an observation
        // that claims nothing is the only safe landing for something we cannot read.
        for error in [Error::other("x"), Error::new(ErrorKind::Interrupted, "x")] {
            assert_eq!(Kind::of(&error), Kind::Unreachable);
        }
    }

    #[test]
    fn each_error_kind_maps_to_the_kind_named_for_it() {
        let of = |k| Kind::of(&Error::new(k, "x"));
        assert_eq!(of(ErrorKind::ConnectionRefused), Kind::Refused);
        assert_eq!(of(ErrorKind::ConnectionReset), Kind::Dropped);
        assert_eq!(of(ErrorKind::ConnectionAborted), Kind::Dropped);
        assert_eq!(of(ErrorKind::BrokenPipe), Kind::Dropped);
        assert_eq!(of(ErrorKind::TimedOut), Kind::Unreachable);
        assert_eq!(of(ErrorKind::NotFound), Kind::Dns);
        assert_eq!(of(ErrorKind::AddrNotAvailable), Kind::Local);
        assert_eq!(of(ErrorKind::PermissionDenied), Kind::Local);
        assert_eq!(of(ErrorKind::InvalidInput), Kind::Local);
    }

    #[test]
    fn only_the_silent_kind_is_inferred() {
        for kind in [
            Kind::Unreachable,
            Kind::Refused,
            Kind::Dropped,
            Kind::Dns,
            Kind::Rejected,
            Kind::Local,
        ] {
            let failure = Failure::new(Stage::SocketConnected, kind);
            assert_eq!(
                failure.confidence,
                if kind == Kind::Unreachable {
                    Confidence::Inferred
                } else {
                    Confidence::Observed
                },
                "{kind} carries the wrong confidence"
            );
        }
    }

    #[test]
    fn worth_retrying_needs_both_halves_of_the_argument() {
        // Neither condition alone is enough, which is the whole point of asking
        // both: a retryable kind after first byte is a peer that answered and then
        // stopped, and a dead path before first byte is not a filter verdict.
        assert!(Failure::new(Stage::SocketConnected, Kind::Unreachable).worth_retrying());
        assert!(Failure::new(Stage::Resolving, Kind::Dropped).worth_retrying());
        assert!(!Failure::new(Stage::FirstByte, Kind::Dropped).worth_retrying());
        assert!(!Failure::new(Stage::SocketConnected, Kind::Refused).worth_retrying());
        assert!(!Failure::new(Stage::SocketConnected, Kind::Dns).worth_retrying());
        assert!(!Failure::new(Stage::FirstByte, Kind::Rejected).worth_retrying());
        assert!(!Failure::new(Stage::Resolving, Kind::Local).worth_retrying());
    }

    #[test]
    fn a_completed_stage_is_never_a_failure_but_names_anyway() {
        // `Completed` is in `ALL` so a report can print a success ladder, and a
        // failure carrying it must be refused by the retry rule rather than
        // silently retryable.
        assert!(!Failure::new(Stage::Completed, Kind::Dropped).worth_retrying());
        assert!(Stage::Completed.is_useful_progress());
        assert_eq!(Stage::Completed.name(), "completed");
    }

    #[test]
    fn display_names_the_stage_the_kind_and_the_hedge_only_when_it_applies() {
        assert_eq!(
            Failure::new(Stage::SocketConnected, Kind::Refused).to_string(),
            "refused at socket-connected"
        );
        assert_eq!(
            Failure::new(Stage::Resolving, Kind::Unreachable).to_string(),
            "unreachable at resolving (inferred)"
        );
        assert_eq!(Kind::Rejected.to_string(), "rejected");
    }

    #[test]
    fn every_stage_is_reachable_and_ordered_by_its_discriminant() {
        let mut sorted = Stage::ALL;
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            Stage::ALL,
            "the discriminants and the order disagree"
        );
        assert_eq!(Stage::ALL[0], Stage::Resolving);
        assert_eq!(Stage::ALL[Stage::ALL.len() - 1], Stage::Completed);
    }

    /// The registry and the dial path cannot drift again, because this walks the
    /// carriers `TransportKind::is_dialled` claims and asks each one for the rung
    /// name `VlessLink::support` reports. The stale registry this replaces called
    /// `ws`, `xhttp`, `grpc` and `httpupgrade` `planned: scheduled after tcp-tls`
    /// while `proxy.rs` carried a `match` arm for every one of them, so a `ws`
    /// link exited 3 from `run` on a carrier that works.
    #[test]
    fn every_dialled_carrier_reports_implemented_not_planned() {
        for (kind, query) in [
            (TransportKind::Tcp, "type=tcp"),
            (TransportKind::Ws, "type=ws"),
            (TransportKind::Xhttp, "type=xhttp"),
            (TransportKind::Grpc, "type=grpc"),
            (TransportKind::HttpUpgrade, "type=httpupgrade"),
        ] {
            assert!(kind.is_dialled(), "{kind:?} is claimed dialled");
            let link = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&{query}#rung"
            ))
            .expect("a synthetic rung link parses");
            assert!(
                matches!(link.support(), Support::Implemented { .. }),
                "{query} is dialled by proxy.rs, so support() must say so: {:?}",
                link.support()
            );
        }
    }

    /// The converse, which is what makes the list a gate rather than a comment:
    /// a carrier with no `match` arm stays `Planned` with its reason, and never
    /// becomes `Implemented` because the loop above is over a different set.
    #[test]
    fn an_undialled_carrier_stays_planned_with_its_reason() {
        for query in [
            "type=kcp",
            "type=hysteria",
            "type=masque",
            "type=xdrive",
            "type=made-up",
        ] {
            let link = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&{query}#rung"
            ))
            .expect("a synthetic rung link parses");
            assert!(
                matches!(link.support(), Support::Planned { reason } if !reason.is_empty()),
                "{query} has no dial arm and must stay planned with a reason"
            );
        }
    }

    #[test]
    fn every_transport_kind_is_either_dialled_or_planned_with_a_reason() {
        // The matrix is a superset by construction, so the two exhaustive sets
        // must partition it. A kind that was neither would be a blank cell, which
        // is the one thing a superset matrix may not contain.
        for kind in TransportKind::ALL {
            assert_eq!(
                TransportKind::from_link(link_name(kind)),
                kind,
                "link_name and from_link disagree, so this walks the wrong cell"
            );
            let link = VlessLink::parse(&format!(
                "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@127.0.0.1:80?security=none&encryption=none&type={}#rung",
                link_name(kind)
            ))
            .expect("a synthetic rung link parses");
            match link.support() {
                Support::Implemented { .. } => assert!(kind.is_dialled(), "{kind:?} dials nothing"),
                Support::Planned { reason } => {
                    assert!(!kind.is_dialled(), "{kind:?} has a dial arm");
                    assert!(!reason.is_empty(), "{kind:?} is blank");
                }
                Support::UnsafeRequiresOptIn { reason } => assert_ne!(reason, ""),
            }
        }
    }

    /// The `type=` spelling of a kind, for a synthetic link.
    fn link_name(kind: TransportKind) -> &'static str {
        match kind {
            TransportKind::Tcp => "tcp",
            TransportKind::Ws => "ws",
            TransportKind::Xhttp => "xhttp",
            TransportKind::Grpc => "grpc",
            TransportKind::Quic => "quic",
            TransportKind::HttpUpgrade => "httpupgrade",
            TransportKind::Kcp => "kcp",
            TransportKind::Hysteria => "hysteria",
            TransportKind::Masque => "masque",
            TransportKind::Xdrive => "xdrive",
            TransportKind::Other => "made-up",
        }
    }
}
