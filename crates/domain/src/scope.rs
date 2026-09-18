//! Scope rules. A target is one of several kinds — a network host, a file, a person, or an OSINT
//! domain. Only host targets are network-addressable, so only they carry a port and are matched by
//! [`is_host_in_scope`]; the other kinds are recognised here and gain their own matching when a
//! capability that consumes them lands.
//!
//! Host precedence is most-specific-wins, ported from the previous toolkit's `check_scope.py`:
//! default-deny first, then an exclusion removes a host, and only an *exact* host entry can override
//! an exclusion. A broad target (a parent domain or any CIDR) can never punch a hole in an exclusion.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostForm {
    Domain,
    Ip,
    Cidr,
    Url,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeEntry {
    Host {
        form: HostForm,
        value: String,
        port: Option<u16>,
    },
    File {
        value: String,
    },
    Person {
        value: String,
    },
    OsintDomain {
        value: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Scope {
    pub targets: Vec<ScopeEntry>,
    pub exclusions: Vec<ScopeEntry>,
}

/// The read-only in-container mount point for a source-tree target. A tool whose invocation needs a
/// sub-path or a language-specific pattern (e.g. Go's `/src/...`) builds it from this constant.
pub const SOURCE_MOUNT: &str = "/src";

/// A source-tree target, written `src:<workspace-relative-path>`. Static-analysis tools read a local
/// source tree rather than a network host; the app enforces workspace confinement and mounts it at
/// [`SOURCE_MOUNT`], so the gate treats a recognised source target as in scope and authorises it on the
/// ROE allow-list alone.
pub fn source_target(target: &str) -> Option<&str> {
    target.strip_prefix("src:")
}

/// The writable in-container mount point for a run's output directory. A tool that produces files points
/// its output flag at an `out:` token, which the app rewrites to this path.
pub const OUTPUT_MOUNT: &str = "/out";

/// A tool-output mount token, written `out:[<sub>]`. The app mounts the run's output directory writable
/// at [`OUTPUT_MOUNT`] and rewrites the token there (appending `<sub>` when present).
pub fn output_target(arg: &str) -> Option<&str> {
    arg.strip_prefix("out:")
}

pub fn is_host_in_scope(target: &str, scope: &Scope) -> bool {
    let host = target_host(target);
    let port = target_port(target);

    if !scope
        .targets
        .iter()
        .any(|entry| host_matches(&host, port, entry))
    {
        return false;
    }

    if scope
        .exclusions
        .iter()
        .any(|entry| host_matches(&host, port, entry))
    {
        return scope
            .targets
            .iter()
            .any(|entry| host_matches_exact(&host, port, entry));
    }

    true
}

/// When a target is refused as out of scope but its host is already named by an in-scope host entry
/// (only a pinned port kept it out), or it is a loopback alias of such a host, suggest the `host`
/// scope entries the operator can add so host-level techniques (e.g. T1046/nmap, which need a bare
/// host, never a URL) can run. Returns `None` when the target is in scope or genuinely foreign. searu
/// never widens scope on its own — this only tells the operator what to add.
pub fn suggest_addition(target: &str, scope: &Scope) -> Option<String> {
    if is_host_in_scope(target, scope) {
        return None;
    }
    let host = target_host(target);
    let names_host = scope
        .targets
        .iter()
        .any(|entry| entry_names_host(&host, entry));
    let loopback_in_scope = is_loopback(&host)
        && scope
            .targets
            .iter()
            .any(|entry| entry_host(entry).is_some_and(|h| is_loopback(&h)));
    if !names_host && !loopback_in_scope {
        return None;
    }
    let hosts = if is_loopback(&host) {
        "localhost and 127.0.0.1".to_string()
    } else {
        host.clone()
    };
    Some(format!(
        "{host} is named by an in-scope target but reachable only on a pinned port. To run host-level \
         techniques (e.g. T1046/nmap), add {hosts} to the ROE scope as host entries."
    ))
}

fn entry_names_host(host: &str, entry: &ScopeEntry) -> bool {
    match entry {
        ScopeEntry::Host { form, value, .. } => host_form_matches(host, *form, value),
        _ => false,
    }
}

fn entry_host(entry: &ScopeEntry) -> Option<String> {
    match entry {
        ScopeEntry::Host {
            form: HostForm::Url,
            value,
            ..
        } => Some(target_host(value)),
        ScopeEntry::Host {
            form: HostForm::Domain | HostForm::Ip,
            value,
            ..
        } => Some(value.to_ascii_lowercase()),
        _ => None,
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

fn host_matches(host: &str, port: Option<u16>, entry: &ScopeEntry) -> bool {
    match entry {
        ScopeEntry::Host {
            form,
            value,
            port: entry_port,
        } => port_allowed(port, *entry_port) && host_form_matches(host, *form, value),
        _ => false,
    }
}

fn host_matches_exact(host: &str, port: Option<u16>, entry: &ScopeEntry) -> bool {
    match entry {
        ScopeEntry::Host {
            form,
            value,
            port: entry_port,
        } => port_allowed(port, *entry_port) && host_form_matches_exact(host, *form, value),
        _ => false,
    }
}

fn host_form_matches(host: &str, form: HostForm, value: &str) -> bool {
    match form {
        HostForm::Domain => host == value || host.ends_with(&format!(".{value}")),
        HostForm::Ip | HostForm::Cidr => ip_in_network(host, value),
        HostForm::Url => host == target_host(value),
    }
}

fn host_form_matches_exact(host: &str, form: HostForm, value: &str) -> bool {
    match form {
        HostForm::Domain => host == value,
        HostForm::Url => host == target_host(value),
        HostForm::Ip => ip_equal(host, value),
        HostForm::Cidr => false,
    }
}

fn port_allowed(target_port: Option<u16>, entry_port: Option<u16>) -> bool {
    match entry_port {
        None => true,
        Some(port) => target_port == Some(port),
    }
}

/// The host portion of a target — the authority of a URL, the host of a `host:port`, or a bare host —
/// lower-cased. Shared with the asset model so scope matching and host identity agree on what "the host"
/// of a target is.
pub fn target_host(target: &str) -> String {
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

/// The port of a target: explicit if given, else the scheme default for a URL, else none.
pub fn target_port(target: &str) -> Option<u16> {
    if let Some(index) = target.find("://") {
        let scheme = &target[..index];
        let authority = target[index + 3..]
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        let explicit = if let Some(rest) = host_port.strip_prefix('[') {
            rest.split_once(']')
                .and_then(|(_, after)| after.strip_prefix(':'))
        } else {
            host_port.rsplit_once(':').map(|(_, port)| port)
        };
        return match explicit {
            Some(port) => port.parse::<u16>().ok(),
            None => match scheme.to_ascii_lowercase().as_str() {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            },
        };
    }

    if target.parse::<IpAddr>().is_ok() {
        return None;
    }
    target
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
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

    fn host(form: HostForm, value: &str) -> ScopeEntry {
        ScopeEntry::Host {
            form,
            value: value.to_string(),
            port: None,
        }
    }

    fn host_on_port(form: HostForm, value: &str, port: u16) -> ScopeEntry {
        ScopeEntry::Host {
            form,
            value: value.to_string(),
            port: Some(port),
        }
    }

    fn scope() -> Scope {
        Scope {
            targets: vec![
                host(HostForm::Domain, "staging.example.com"),
                host(HostForm::Cidr, "10.20.0.0/24"),
            ],
            exclusions: vec![host(HostForm::Domain, "billing.staging.example.com")],
        }
    }

    #[test]
    fn an_exact_domain_target_is_in_scope() {
        assert!(is_host_in_scope("staging.example.com", &scope()));
    }

    #[test]
    fn a_subdomain_matches_by_suffix() {
        assert!(is_host_in_scope("api.staging.example.com", &scope()));
    }

    #[test]
    fn an_unlisted_host_is_out_by_default() {
        assert!(!is_host_in_scope("evil.example.org", &scope()));
    }

    #[test]
    fn an_address_inside_the_cidr_is_in_scope() {
        assert!(is_host_in_scope("10.20.0.5", &scope()));
    }

    #[test]
    fn an_address_outside_the_cidr_is_out() {
        assert!(!is_host_in_scope("10.20.1.5", &scope()));
    }

    #[test]
    fn a_url_target_resolves_to_its_host() {
        assert!(is_host_in_scope(
            "https://api.staging.example.com/login",
            &scope()
        ));
    }

    #[test]
    fn an_excluded_host_is_out() {
        assert!(!is_host_in_scope("billing.staging.example.com", &scope()));
    }

    #[test]
    fn an_exclusion_is_rescued_by_an_exact_target() {
        let mut scope = scope();
        scope
            .targets
            .push(host(HostForm::Domain, "billing.staging.example.com"));
        assert!(is_host_in_scope("billing.staging.example.com", &scope));
    }

    #[test]
    fn a_broad_target_cannot_rescue_an_exclusion() {
        let scope = Scope {
            targets: vec![host(HostForm::Domain, "example.com")],
            exclusions: vec![host(HostForm::Domain, "secret.example.com")],
        };
        assert!(!is_host_in_scope("secret.example.com", &scope));
    }

    #[test]
    fn an_ipv6_address_inside_its_network_is_in_scope() {
        let scope = Scope {
            targets: vec![host(HostForm::Cidr, "2001:db8::/32")],
            exclusions: vec![],
        };
        assert!(is_host_in_scope("2001:db8::1", &scope));
        assert!(!is_host_in_scope("2001:dead::1", &scope));
    }

    #[test]
    fn a_url_with_userinfo_and_port_resolves_to_the_host() {
        assert_eq!(
            target_host("https://user:pass@Staging.Example.com:8443/x"),
            "staging.example.com"
        );
    }

    #[test]
    fn a_port_limited_target_matches_only_that_port() {
        let scope = Scope {
            targets: vec![host_on_port(HostForm::Ip, "127.0.0.1", 5000)],
            exclusions: vec![],
        };
        assert!(is_host_in_scope("http://127.0.0.1:5000/cmd/dig", &scope));
        assert!(is_host_in_scope("127.0.0.1:5000", &scope));
        assert!(!is_host_in_scope("http://127.0.0.1:8080/cmd/dig", &scope));
        assert!(!is_host_in_scope("http://127.0.0.1/cmd/dig", &scope));
        assert!(!is_host_in_scope("127.0.0.1", &scope));
    }

    #[test]
    fn an_unrestricted_entry_allows_any_port() {
        let scope = Scope {
            targets: vec![host(HostForm::Domain, "staging.example.com")],
            exclusions: vec![],
        };
        assert!(is_host_in_scope(
            "https://staging.example.com:8443/x",
            &scope
        ));
        assert!(is_host_in_scope("staging.example.com", &scope));
    }

    #[test]
    fn non_host_entries_never_grant_network_scope() {
        let scope = Scope {
            targets: vec![
                ScopeEntry::Person {
                    value: "Joe Bloggs".to_string(),
                },
                ScopeEntry::File {
                    value: "/etc/passwd".to_string(),
                },
                ScopeEntry::OsintDomain {
                    value: "example.com".to_string(),
                },
            ],
            exclusions: vec![],
        };
        assert!(!is_host_in_scope("http://example.com/x", &scope));
    }

    #[test]
    fn target_port_reads_scheme_defaults_and_explicit_ports() {
        assert_eq!(target_port("http://localhost/x"), Some(80));
        assert_eq!(target_port("https://localhost/x"), Some(443));
        assert_eq!(target_port("http://localhost:5000/x"), Some(5000));
        assert_eq!(target_port("localhost:5000"), Some(5000));
        assert_eq!(target_port("127.0.0.1"), None);
    }

    fn loopback_url_scope() -> Scope {
        Scope {
            targets: vec![host_on_port(HostForm::Url, "http://localhost:3000/", 3000)],
            exclusions: vec![],
        }
    }

    #[test]
    fn a_bare_loopback_host_refused_on_port_suggests_adding_both_aliases() {
        let hint = suggest_addition("localhost", &loopback_url_scope()).expect("a suggestion");
        assert!(hint.contains("localhost and 127.0.0.1"));
        assert!(hint.contains("host entries"));
    }

    #[test]
    fn the_other_loopback_alias_is_also_suggested() {
        assert!(suggest_addition("127.0.0.1", &loopback_url_scope()).is_some());
    }

    #[test]
    fn an_in_scope_target_needs_no_suggestion() {
        assert!(suggest_addition("http://localhost:3000/x", &loopback_url_scope()).is_none());
    }

    #[test]
    fn a_foreign_host_gets_no_suggestion() {
        assert!(suggest_addition("evil.example.org", &loopback_url_scope()).is_none());
    }

    #[test]
    fn a_named_host_refused_only_on_port_is_suggested() {
        let scope = Scope {
            targets: vec![host_on_port(HostForm::Domain, "staging.example.com", 443)],
            exclusions: vec![],
        };
        let hint = suggest_addition("staging.example.com", &scope).expect("a suggestion");
        assert!(hint.contains("staging.example.com"));
    }
}
