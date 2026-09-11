//! Scope rules ported from the previous toolkit's `check_scope.py`.
//!
//! Precedence is most-specific-wins: default-deny first, then an exclusion removes a host, and only
//! an *exact* target entry for that host can override an exclusion. A broad target (a parent domain
//! or any CIDR) can never punch a hole in an exclusion.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Domain,
    Ip,
    Cidr,
    Url,
}

#[derive(Debug, Clone)]
pub struct ScopeEntry {
    pub kind: EntryKind,
    pub value: String,
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub targets: Vec<ScopeEntry>,
    pub exclusions: Vec<ScopeEntry>,
}

pub fn is_in_scope(target: &str, scope: &Scope) -> bool {
    let host = target_host(target);

    if !scope.targets.iter().any(|entry| host_matches(&host, entry)) {
        return false;
    }

    if scope
        .exclusions
        .iter()
        .any(|entry| host_matches(&host, entry))
    {
        return scope
            .targets
            .iter()
            .any(|entry| host_matches_exact(&host, entry));
    }

    true
}

fn target_host(target: &str) -> String {
    let Some(index) = target.find("://") else {
        if let Ok(ip) = target.parse::<IpAddr>() {
            return ip.to_string();
        }
        return target.split(':').next().unwrap_or(target).to_string();
    };
    let authority = target[index + 3..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = match host_port.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(h, _)| h).unwrap_or(rest),
        None => host_port.split(':').next().unwrap_or(host_port),
    };
    host.to_ascii_lowercase()
}

fn host_matches(host: &str, entry: &ScopeEntry) -> bool {
    match entry.kind {
        EntryKind::Domain => host == entry.value || host.ends_with(&format!(".{}", entry.value)),
        EntryKind::Ip | EntryKind::Cidr => ip_in_network(host, &entry.value),
        EntryKind::Url => host == target_host(&entry.value),
    }
}

fn host_matches_exact(host: &str, entry: &ScopeEntry) -> bool {
    match entry.kind {
        EntryKind::Domain => host == entry.value,
        EntryKind::Url => host == target_host(&entry.value),
        EntryKind::Ip => ip_equal(host, &entry.value),
        EntryKind::Cidr => false,
    }
}

fn ip_equal(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

fn ip_in_network(host: &str, value: &str) -> bool {
    let (network_str, prefix) = match value.split_once('/') {
        Some((addr, bits)) => match bits.parse::<u32>() {
            Ok(bits) => (addr, Some(bits)),
            Err(_) => return false,
        },
        None => (value, None),
    };
    let (Ok(network), Ok(address)) = (network_str.parse::<IpAddr>(), host.parse::<IpAddr>()) else {
        return false;
    };
    match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => {
            let bits = prefix.unwrap_or(32);
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(network) & mask) == (u32::from(address) & mask)
        }
        (IpAddr::V6(network), IpAddr::V6(address)) => {
            let bits = prefix.unwrap_or(128);
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(network) & mask) == (u128::from(address) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: EntryKind, value: &str) -> ScopeEntry {
        ScopeEntry {
            kind,
            value: value.to_string(),
        }
    }

    fn scope() -> Scope {
        Scope {
            targets: vec![
                entry(EntryKind::Domain, "staging.example.com"),
                entry(EntryKind::Cidr, "10.20.0.0/24"),
            ],
            exclusions: vec![entry(EntryKind::Domain, "billing.staging.example.com")],
        }
    }

    #[test]
    fn an_exact_domain_target_is_in_scope() {
        assert!(is_in_scope("staging.example.com", &scope()));
    }

    #[test]
    fn a_subdomain_matches_by_suffix() {
        assert!(is_in_scope("api.staging.example.com", &scope()));
    }

    #[test]
    fn an_unlisted_host_is_out_by_default() {
        assert!(!is_in_scope("evil.example.org", &scope()));
    }

    #[test]
    fn an_address_inside_the_cidr_is_in_scope() {
        assert!(is_in_scope("10.20.0.5", &scope()));
    }

    #[test]
    fn an_address_outside_the_cidr_is_out() {
        assert!(!is_in_scope("10.20.1.5", &scope()));
    }

    #[test]
    fn a_url_target_resolves_to_its_host() {
        assert!(is_in_scope(
            "https://api.staging.example.com/login",
            &scope()
        ));
    }

    #[test]
    fn an_excluded_host_is_out() {
        assert!(!is_in_scope("billing.staging.example.com", &scope()));
    }

    #[test]
    fn an_exclusion_is_rescued_by_an_exact_target() {
        let mut scope = scope();
        scope
            .targets
            .push(entry(EntryKind::Domain, "billing.staging.example.com"));
        assert!(is_in_scope("billing.staging.example.com", &scope));
    }

    #[test]
    fn a_broad_target_cannot_rescue_an_exclusion() {
        let scope = Scope {
            targets: vec![entry(EntryKind::Domain, "example.com")],
            exclusions: vec![entry(EntryKind::Domain, "secret.example.com")],
        };
        assert!(!is_in_scope("secret.example.com", &scope));
    }

    #[test]
    fn an_ipv6_address_inside_its_network_is_in_scope() {
        let scope = Scope {
            targets: vec![entry(EntryKind::Cidr, "2001:db8::/32")],
            exclusions: vec![],
        };
        assert!(is_in_scope("2001:db8::1", &scope));
        assert!(!is_in_scope("2001:dead::1", &scope));
    }

    #[test]
    fn a_url_with_userinfo_and_port_resolves_to_the_host() {
        assert_eq!(
            target_host("https://user:pass@Staging.Example.com:8443/x"),
            "staging.example.com"
        );
    }
}
