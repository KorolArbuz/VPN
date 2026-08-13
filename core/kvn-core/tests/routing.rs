//! Routing foundation (spec tests 17, 18, 19, 20, 21).

use kvn_core::routing::{RouteAction, RouteQuery, RouteRule, RuleMatcher};
use kvn_core::KvnCore;

fn table() -> KvnCore {
    let mut core = KvnCore::default();
    core.set_routing_rules(vec![
        RouteRule::new(
            RuleMatcher::ExactDomain("example.com".into()),
            RouteAction::Direct,
            10,
        ),
        RouteRule::new(
            RuleMatcher::SuffixDomain("ads.net".into()),
            RouteAction::Block,
            20,
        ),
        RouteRule::new(
            RuleMatcher::Cidr("10.0.0.0/8".into()),
            RouteAction::Direct,
            30,
        ),
        RouteRule::new(
            RuleMatcher::Cidr("2001:db8::/32".into()),
            RouteAction::Direct,
            31,
        ),
        RouteRule::new(RuleMatcher::CatchAll, RouteAction::Vpn, 1000),
    ]);
    core
}

fn domain_query(domain: &str) -> RouteQuery {
    RouteQuery {
        domain: Some(domain.into()),
        ..Default::default()
    }
}

fn ip_query(ip: &str) -> RouteQuery {
    RouteQuery {
        ip: Some(ip.into()),
        ..Default::default()
    }
}

// 17. Exact domain match.
#[test]
fn routing_exact_domain() {
    let core = table();
    assert_eq!(
        core.resolve_route(&domain_query("example.com")),
        Some(RouteAction::Direct)
    );
    // A subdomain is NOT an exact match, so it falls through to catch-all.
    assert_eq!(
        core.resolve_route(&domain_query("www.example.com")),
        Some(RouteAction::Vpn)
    );
}

// 18. Suffix domain match.
#[test]
fn routing_suffix_domain() {
    let core = table();
    assert_eq!(
        core.resolve_route(&domain_query("ads.net")),
        Some(RouteAction::Block)
    );
    assert_eq!(
        core.resolve_route(&domain_query("tracker.ads.net")),
        Some(RouteAction::Block)
    );
    // Not a subdomain boundary match.
    assert_eq!(
        core.resolve_route(&domain_query("badads.net")),
        Some(RouteAction::Vpn)
    );
}

// 19. CIDR match (v4 and v6).
#[test]
fn routing_cidr() {
    let core = table();
    assert_eq!(
        core.resolve_route(&ip_query("10.1.2.3")),
        Some(RouteAction::Direct)
    );
    assert_eq!(
        core.resolve_route(&ip_query("11.0.0.1")),
        Some(RouteAction::Vpn)
    );
    assert_eq!(
        core.resolve_route(&ip_query("2001:db8::1")),
        Some(RouteAction::Direct)
    );
    assert_eq!(
        core.resolve_route(&ip_query("2001:dead::1")),
        Some(RouteAction::Vpn)
    );
}

// 20. Block action.
#[test]
fn routing_block() {
    let core = table();
    assert_eq!(
        core.resolve_route(&domain_query("tracker.ads.net")),
        Some(RouteAction::Block)
    );
}

// 21. Catch-all applies when nothing else matches.
#[test]
fn routing_catch_all() {
    let core = table();
    assert_eq!(
        core.resolve_route(&domain_query("unknown.org")),
        Some(RouteAction::Vpn)
    );

    // With no catch-all, an unmatched query resolves to None.
    let mut bare = KvnCore::default();
    bare.set_routing_rules(vec![RouteRule::new(
        RuleMatcher::ExactDomain("only.com".into()),
        RouteAction::Direct,
        1,
    )]);
    assert_eq!(bare.resolve_route(&domain_query("other.com")), None);
}
