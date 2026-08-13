//! Deterministic routing foundation. Rules are pre-normalized by the platform
//! (lowercased domains, parsed IPs); no GeoIP database is bundled here.

use crate::error::{CoreError, CoreResult};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

/// What to do with traffic that matches a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Vpn,
    Block,
}

/// The matcher portion of a rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum RuleMatcher {
    /// Exact, case-insensitive domain match.
    ExactDomain(String),
    /// Matches the domain or any subdomain of it.
    SuffixDomain(String),
    /// CIDR block, e.g. "10.0.0.0/8" or "2001:db8::/32".
    Cidr(String),
    /// Matches a region/country tag carried in the query.
    RegionTag(String),
    /// Matches an application identifier tag.
    AppTag(String),
    /// Matches everything (lowest priority sentinel).
    CatchAll,
}

/// A routing rule with an explicit deterministic priority (lower first).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteRule {
    pub matcher: RuleMatcher,
    pub action: RouteAction,
    pub priority: i32,
}

impl RouteRule {
    pub fn new(matcher: RuleMatcher, action: RouteAction, priority: i32) -> Self {
        Self {
            matcher,
            action,
            priority,
        }
    }
}

/// The normalized lookup input. All strings are expected lowercased by the
/// caller; domain comparison also lowercases defensively.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RouteQuery {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub app: Option<String>,
}

/// An ordered, deterministic set of routing rules.
#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    rules: Vec<RouteRule>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Replaces all rules, sorting by `(priority, insertion order)` so matching
    /// is fully deterministic.
    pub fn set_rules(&mut self, mut rules: Vec<RouteRule>) {
        // Stable sort preserves insertion order among equal priorities.
        rules.sort_by_key(|r| r.priority);
        self.rules = rules;
    }

    pub fn rules(&self) -> &[RouteRule] {
        &self.rules
    }

    /// Returns the action of the first matching rule by priority, or `None`
    /// when nothing (not even a catch-all) matches.
    pub fn resolve(&self, query: &RouteQuery) -> Option<RouteAction> {
        self.rules
            .iter()
            .find(|rule| Self::matches(&rule.matcher, query))
            .map(|rule| rule.action)
    }

    fn matches(matcher: &RuleMatcher, query: &RouteQuery) -> bool {
        match matcher {
            RuleMatcher::ExactDomain(domain) => query
                .domain
                .as_deref()
                .is_some_and(|q| q.eq_ignore_ascii_case(domain)),
            RuleMatcher::SuffixDomain(suffix) => query
                .domain
                .as_deref()
                .is_some_and(|q| domain_matches_suffix(q, suffix)),
            RuleMatcher::Cidr(cidr) => query
                .ip
                .as_deref()
                .and_then(|ip| IpAddr::from_str(ip).ok())
                .is_some_and(|ip| cidr_contains(cidr, ip).unwrap_or(false)),
            RuleMatcher::RegionTag(tag) => query
                .region
                .as_deref()
                .is_some_and(|q| q.eq_ignore_ascii_case(tag)),
            RuleMatcher::AppTag(tag) => query
                .app
                .as_deref()
                .is_some_and(|q| q.eq_ignore_ascii_case(tag)),
            RuleMatcher::CatchAll => true,
        }
    }
}

/// True when `domain` equals `suffix` or is a subdomain of it.
fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    let suffix = suffix.trim_start_matches('.').trim_end_matches('.');
    if domain.eq_ignore_ascii_case(suffix) {
        return true;
    }
    domain.len() > suffix.len()
        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
        && domain[domain.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

/// Parses `a.b.c.d/n` (or IPv6 equivalent) and tests membership. Returns an
/// error only for a malformed CIDR string.
fn cidr_contains(cidr: &str, ip: IpAddr) -> CoreResult<bool> {
    let (network_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| CoreError::InvalidInput("cidr missing '/'".into()))?;
    let network = IpAddr::from_str(network_str.trim())
        .map_err(|_| CoreError::InvalidInput("cidr network parse".into()))?;
    let prefix: u32 = prefix_str
        .trim()
        .parse()
        .map_err(|_| CoreError::InvalidInput("cidr prefix parse".into()))?;

    match (network, ip) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            if prefix > 32 {
                return Err(CoreError::InvalidInput("ipv4 prefix > 32".into()));
            }
            Ok(bits_match(
                u32::from(net) as u128,
                u32::from(addr) as u128,
                prefix,
                32,
            ))
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            if prefix > 128 {
                return Err(CoreError::InvalidInput("ipv6 prefix > 128".into()));
            }
            Ok(bits_match(u128::from(net), u128::from(addr), prefix, 128))
        }
        // Mixed families never match.
        _ => Ok(false),
    }
}

fn bits_match(network: u128, addr: u128, prefix: u32, width: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = width - prefix;
    let mask = if shift >= 128 { 0 } else { u128::MAX << shift };
    (network & mask) == (addr & mask)
}
