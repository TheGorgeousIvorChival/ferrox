use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Stage {
    Resolving = 0,
    SocketConnected = 1,
    RequestSent = 2,
    FirstByte = 3,
    PayloadTransferred = 4,
    Completed = 5,
}

impl Stage {
    #[must_use]
    pub const fn rank(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn is_useful_progress(self) -> bool {
        self.rank() >= Self::FirstByte.rank()
    }

    pub const ALL: [Self; 6] = [
        Self::Resolving,
        Self::SocketConnected,
        Self::RequestSent,
        Self::FirstByte,
        Self::PayloadTransferred,
        Self::Completed,
    ];

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Unreachable,
    Refused,
    Dropped,
    Dns,
    Rejected,
    Local,
}

impl Kind {
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

    #[must_use]
    pub fn of(error: &std::io::Error) -> Self {
        use std::io::ErrorKind as E;
        match error.kind() {
            E::ConnectionRefused => Self::Refused,
            E::ConnectionReset | E::ConnectionAborted | E::BrokenPipe => Self::Dropped,
            E::NotFound => Self::Dns,
            E::PermissionDenied | E::AddrNotAvailable | E::InvalidInput => Self::Local,
            _ => Self::Unreachable,
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Inferred,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Failure {
    pub stage: Stage,
    pub kind: Kind,
    pub confidence: Confidence,
}

impl Failure {
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
