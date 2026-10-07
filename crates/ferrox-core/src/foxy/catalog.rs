//! The catalogue the lane picks an edge out of: which countries exist, and which
//! of them a pinned country resolves to.
//!
//! The list itself is published unauthenticated by Mozilla's Remote Settings, so
//! choosing a country needs no account and no dial — which is what lets a link
//! carry only a country code and still reach an edge. Parsing the envelope is
//! the app's job, where the JSON reader lives; everything here is the choice,
//! which is the part that has to be right and is worth proving on its own.

use crate::foxy::Candidate;

/// The country code the catalogue uses for "wherever is best", which is a real
/// country in the list rather than a mode: `REC` is a row like any other.
pub const RECOMMENDED: &str = "REC";

/// One country pinned at dial, in the shape `dial_order` consumes.
#[must_use]
pub fn pinned(edges: &[Candidate], country: &str) -> Vec<Candidate> {
    edges
        .iter()
        .filter(|edge| edge.country.eq_ignore_ascii_case(country))
        .cloned()
        .collect()
}

/// The edges of one country, the named city's first and one alternate more than
/// the caller asked for.
///
/// A failover inside the city is a failover the user cannot see, and one that
/// leaves the city is a failover to a worse exit, so the city is a tier rather
/// than a filter. `REC` is one country code among many and needs no branch of
/// its own, which is why recommended and pinned travel the same road.
#[must_use]
pub fn tier(
    edges: &[Candidate],
    country: &str,
    city: &str,
    max_alternates: usize,
) -> Vec<Candidate> {
    let cap = max_alternates.saturating_add(1);
    let in_city = |edge: &Candidate| !city.is_empty() && edge.city.eq_ignore_ascii_case(city);
    let mut out: Vec<Candidate> = Vec::new();
    for want_city in [true, false] {
        if out.len() >= cap {
            break;
        }
        for edge in edges
            .iter()
            .filter(|edge| edge.country.eq_ignore_ascii_case(country))
        {
            if out.len() >= cap {
                break;
            }
            if in_city(edge) != want_city
                || out.iter().any(|kept| kept.authority() == edge.authority())
            {
                continue;
            }
            out.push(edge.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(host: &str, country: &str, city: &str) -> Candidate {
        Candidate {
            host: host.to_owned(),
            port: 443,
            country: country.to_owned(),
            city: city.to_owned(),
        }
    }

    fn world() -> Vec<Candidate> {
        vec![
            edge("de1", "DE", "berlin"),
            edge("us1", "US", "nyc"),
            edge("de2", "de", "berlin"),
            edge("us2", "US", "sf"),
            edge("us3", "US", "nyc"),
            edge("us4", "US", "sf"),
        ]
    }

    fn hosts(edges: &[Candidate]) -> Vec<&str> {
        edges.iter().map(|edge| edge.host.as_str()).collect()
    }

    #[test]
    fn the_city_is_a_tier_and_not_a_filter() {
        assert_eq!(
            hosts(&tier(&world(), "us", "nyc", 2)),
            ["us1", "us3", "us2"]
        );
        assert_eq!(
            hosts(&tier(&world(), "us", "", 1)),
            ["us1", "us2"],
            "no city asked for: catalogue order, one alternate"
        );
    }

    #[test]
    fn a_country_nobody_published_is_an_empty_list_rather_than_a_guess() {
        assert_eq!(tier(&world(), "FR", "", 3), Vec::new());
        assert_eq!(pinned(&world(), "fr"), Vec::new());
    }

    #[test]
    fn recommended_is_a_country_code_and_needs_no_branch() {
        let edges = vec![
            edge("rec", RECOMMENDED, "anycast"),
            edge("us1", "US", "nyc"),
        ];
        assert_eq!(hosts(&tier(&edges, RECOMMENDED, "", 3)), ["rec"]);
        assert_eq!(
            hosts(&tier(&edges, "rec", "anycast", 3)),
            ["rec"],
            "and lower case, because a link may be typed by hand"
        );
    }

    #[test]
    fn one_edge_is_never_dialed_twice_under_two_names() {
        let twice = vec![edge("us1", "US", "nyc"), edge("us1", "US", "sf")];
        assert_eq!(hosts(&tier(&twice, "US", "", 3)), ["us1"]);
    }

    #[test]
    fn the_cap_counts_the_first_edge_and_not_just_the_alternates() {
        for (alts, want) in [(0usize, 1usize), (1, 2), (2, 3), (9, 4)] {
            assert_eq!(
                tier(&world(), "US", "", alts).len(),
                want,
                "{alts} alternates"
            );
        }
    }
}
