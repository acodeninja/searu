//! The asset model: a host is an opaque identity derived from its strongest stable *claim* (an SSH
//! host-key, a TLS SPKI, a machine-id, …) — never from an IP, because the same address means different
//! machines on different networks and the same machine wears different addresses. A host owns
//! addresses and services; the host graph is a projection derived from the stored records, not a
//! separate store.

use crate::scope::{output_target, source_target, target_host, target_port};

pub const INTERNET: &str = "internet";

/// The kinds of stable identity claim, strongest first. `Ord` follows declaration order, so the
/// strongest claim is the minimum — a cryptographic host-key outranks a hostname, which anything can
/// share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimKind {
    SshHostKey,
    TlsSpki,
    MachineId,
    ProductUuid,
    MacSet,
    Hostname,
}

impl ClaimKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ClaimKind::SshHostKey => "ssh-host-key",
            ClaimKind::TlsSpki => "tls-spki",
            ClaimKind::MachineId => "machine-id",
            ClaimKind::ProductUuid => "product-uuid",
            ClaimKind::MacSet => "mac-set",
            ClaimKind::Hostname => "hostname",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "ssh-host-key" => ClaimKind::SshHostKey,
            "tls-spki" => ClaimKind::TlsSpki,
            "machine-id" => ClaimKind::MachineId,
            "product-uuid" => ClaimKind::ProductUuid,
            "mac-set" => ClaimKind::MacSet,
            "hostname" => ClaimKind::Hostname,
            _ => return None,
        })
    }

    /// A strong claim uniquely identifies a machine, so two hosts sharing one are the same host. A
    /// hostname is weak — vhosts and load balancers share it — so it never merges distinct hosts.
    pub fn is_strong(&self) -> bool {
        !matches!(self, ClaimKind::Hostname)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityClaim {
    pub kind: ClaimKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub network: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub port: u16,
    pub protocol: String,
    pub product: Option<String>,
}

impl Service {
    /// The compact `protocol/port` label stored on a record's `service` column.
    pub fn label(&self) -> String {
        format!("{}/{}", self.protocol, self.port)
    }
}

/// Parse a `protocol/port` service label back into a [`Service`] (product is not carried on the label).
pub fn parse_service(label: &str) -> Option<Service> {
    let (protocol, port) = label.split_once('/')?;
    Some(Service {
        port: port.parse().ok()?,
        protocol: protocol.to_string(),
        product: None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    InScope,
    Candidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub id: String,
    pub addresses: Vec<Address>,
    pub claims: Vec<IdentityClaim>,
    pub services: Vec<Service>,
    pub status: HostStatus,
}

fn fnv1a(input: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn hashed(claim_kind: &str, value: &str) -> String {
    format!("host-{:016x}", fnv1a(&format!("{claim_kind}:{value}")))
}

/// The strongest claim, or `None` if the host has none yet.
pub fn strongest(claims: &[IdentityClaim]) -> Option<&IdentityClaim> {
    claims.iter().min_by_key(|claim| claim.kind)
}

/// The id derived from the strongest claim, or `None` when there are no claims (use a provisional id).
pub fn derive_id(claims: &[IdentityClaim]) -> Option<String> {
    strongest(claims).map(|claim| hashed(claim.kind.as_str(), &claim.value))
}

/// A provisional id keyed on `(network, value)` — used until a strong claim appears and re-keys the
/// host.
pub fn provisional_id(address: &Address) -> String {
    hashed("addr", &format!("{}:{}", address.network, address.value))
}

/// The id for a host known by these claims at this address: the strongest claim's id, else provisional.
pub fn host_id(claims: &[IdentityClaim], address: &Address) -> String {
    derive_id(claims).unwrap_or_else(|| provisional_id(address))
}

/// The hostname claim a bare host value implies — none for an IP literal, which is not an identity.
pub fn value_claims(value: &str) -> Vec<IdentityClaim> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        Vec::new()
    } else {
        vec![IdentityClaim {
            kind: ClaimKind::Hostname,
            value: value.to_string(),
        }]
    }
}

/// The host id a bare `--host <value>` filter refers to, derived the same way a run derives it, so the
/// filter matches the records a run stored.
pub fn host_id_for(value: &str) -> String {
    let value = value.to_ascii_lowercase();
    let address = Address {
        network: INTERNET.to_string(),
        value: value.clone(),
    };
    host_id(&value_claims(&value), &address)
}

/// A network target resolved into the asset model: its address, the service it names (if any), and the
/// claims the target itself yields (its hostname). Source-tree (`src:`) and output (`out:`) targets are
/// not network hosts and resolve to `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub address: Address,
    pub service: Option<Service>,
    pub claims: Vec<IdentityClaim>,
}

impl ResolvedTarget {
    pub fn host_id(&self) -> String {
        host_id(&self.claims, &self.address)
    }
}

pub fn resolve_target(target: &str) -> Option<ResolvedTarget> {
    if source_target(target).is_some() || output_target(target).is_some() {
        return None;
    }
    let value = target_host(target);
    if value.is_empty() {
        return None;
    }
    let address = Address {
        network: INTERNET.to_string(),
        value: value.clone(),
    };
    let service = target_port(target).map(|port| Service {
        port,
        protocol: "tcp".to_string(),
        product: scheme_of(target),
    });
    let claims = value_claims(&value);
    Some(ResolvedTarget {
        address,
        service,
        claims,
    })
}

fn scheme_of(target: &str) -> Option<String> {
    target
        .find("://")
        .map(|index| target[..index].to_ascii_lowercase())
}

/// One record's contribution to the host graph: which host it names, at what address, exposing what
/// service, with what claims. The projection folds these into hosts.
#[derive(Debug, Clone)]
pub struct Attribution {
    pub host: String,
    pub address: Option<Address>,
    pub service: Option<Service>,
    pub claims: Vec<IdentityClaim>,
    pub status: HostStatus,
}

/// Fold record attributions into the host graph: group by host id, then merge any two hosts that share
/// a strong claim (the same machine reached two ways). In-scope status wins over candidate.
pub fn project(attributions: Vec<Attribution>) -> Vec<Host> {
    let mut hosts: Vec<Host> = Vec::new();
    for attribution in attributions {
        let index = hosts
            .iter()
            .position(|host| {
                host.id == attribution.host
                    || shares_strong_claim(&host.claims, &attribution.claims)
            })
            .unwrap_or_else(|| {
                hosts.push(Host {
                    id: attribution.host.clone(),
                    addresses: Vec::new(),
                    claims: Vec::new(),
                    services: Vec::new(),
                    status: HostStatus::Candidate,
                });
                hosts.len() - 1
            });
        let host = &mut hosts[index];
        if let Some(address) = attribution.address {
            if !host.addresses.contains(&address) {
                host.addresses.push(address);
            }
        }
        for claim in attribution.claims {
            if !host.claims.contains(&claim) {
                host.claims.push(claim);
            }
        }
        if let Some(service) = attribution.service {
            if !host.services.contains(&service) {
                host.services.push(service);
            }
        }
        if attribution.status == HostStatus::InScope {
            host.status = HostStatus::InScope;
        }
        if let Some(id) = derive_id(&host.claims) {
            host.id = id;
        }
    }
    hosts
}

fn shares_strong_claim(a: &[IdentityClaim], b: &[IdentityClaim]) -> bool {
    a.iter()
        .filter(|claim| claim.kind.is_strong())
        .any(|claim| b.contains(claim))
}

/// Two hosts share a strong claim but sit in different networks — a *possible clone* (shared VM image or
/// load-balancer certificate). The operator decides whether to split or merge; searu never auto-merges
/// across this signal.
pub fn possible_clone(a: &Host, b: &Host) -> bool {
    shares_strong_claim(&a.claims, &b.claims) && !share_network(a, b)
}

fn share_network(a: &Host, b: &Host) -> bool {
    a.addresses
        .iter()
        .any(|x| b.addresses.iter().any(|y| x.network == y.network))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(kind: ClaimKind, value: &str) -> IdentityClaim {
        IdentityClaim {
            kind,
            value: value.to_string(),
        }
    }

    #[test]
    fn derive_id_uses_the_strongest_claim() {
        let claims = vec![
            claim(ClaimKind::Hostname, "web.example.com"),
            claim(ClaimKind::SshHostKey, "AAAA...key"),
        ];
        assert_eq!(
            derive_id(&claims).unwrap(),
            hashed("ssh-host-key", "AAAA...key")
        );
    }

    #[test]
    fn a_claimless_host_falls_back_to_a_provisional_address_id() {
        let address = Address {
            network: INTERNET.to_string(),
            value: "192.168.56.1".to_string(),
        };
        assert_eq!(host_id(&[], &address), provisional_id(&address));
    }

    #[test]
    fn an_ip_target_yields_no_hostname_claim() {
        assert!(value_claims("192.168.56.1").is_empty());
        assert_eq!(value_claims("web.example.com").len(), 1);
    }

    #[test]
    fn resolve_target_reads_the_host_port_and_hostname_claim() {
        let resolved = resolve_target("http://staging.example.com:5000/cmd").unwrap();
        assert_eq!(resolved.address.value, "staging.example.com");
        assert_eq!(resolved.service.as_ref().unwrap().port, 5000);
        assert_eq!(resolved.claims.len(), 1);
        assert!(resolve_target("src:app/web").is_none());
    }

    #[test]
    fn a_bare_host_filter_matches_the_id_a_run_stored() {
        let resolved = resolve_target("http://staging.example.com:5000/x").unwrap();
        assert_eq!(resolved.host_id(), host_id_for("staging.example.com"));
        assert_eq!(resolved.host_id(), host_id_for("STAGING.example.com"));
    }

    #[test]
    fn two_addresses_sharing_a_strong_claim_project_to_one_host() {
        let key = claim(ClaimKind::SshHostKey, "shared-key");
        let hosts = project(vec![
            Attribution {
                host: "host-a".to_string(),
                address: Some(Address {
                    network: INTERNET.to_string(),
                    value: "1.2.3.4".to_string(),
                }),
                service: parse_service("tcp/22"),
                claims: vec![key.clone()],
                status: HostStatus::InScope,
            },
            Attribution {
                host: "host-b".to_string(),
                address: Some(Address {
                    network: "behind:host-a".to_string(),
                    value: "10.0.0.9".to_string(),
                }),
                service: parse_service("tcp/80"),
                claims: vec![key.clone()],
                status: HostStatus::Candidate,
            },
        ]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].addresses.len(), 2);
        assert_eq!(hosts[0].services.len(), 2);
        assert_eq!(hosts[0].status, HostStatus::InScope);
    }

    #[test]
    fn a_weak_hostname_claim_does_not_merge_distinct_hosts() {
        let name = claim(ClaimKind::Hostname, "shared-vhost");
        let hosts = project(vec![
            Attribution {
                host: "host-a".to_string(),
                address: None,
                service: None,
                claims: vec![name.clone()],
                status: HostStatus::InScope,
            },
            Attribution {
                host: "host-b".to_string(),
                address: None,
                service: None,
                claims: vec![name.clone()],
                status: HostStatus::InScope,
            },
        ]);
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn records_on_the_same_id_collapse_to_one_host() {
        let attribution = |service: &str| Attribution {
            host: host_id_for("box"),
            address: Some(Address {
                network: INTERNET.to_string(),
                value: "box".to_string(),
            }),
            service: parse_service(service),
            claims: value_claims("box"),
            status: HostStatus::InScope,
        };
        let hosts = project(vec![attribution("tcp/80"), attribution("tcp/443")]);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].services.len(), 2);
    }

    #[test]
    fn a_shared_strong_claim_across_networks_is_a_possible_clone() {
        let key = claim(ClaimKind::TlsSpki, "spki");
        let a = Host {
            id: "a".to_string(),
            addresses: vec![Address {
                network: INTERNET.to_string(),
                value: "1.1.1.1".to_string(),
            }],
            claims: vec![key.clone()],
            services: vec![],
            status: HostStatus::InScope,
        };
        let mut b = a.clone();
        b.id = "b".to_string();
        b.addresses = vec![Address {
            network: "behind:a".to_string(),
            value: "10.0.0.1".to_string(),
        }];
        assert!(possible_clone(&a, &b));
    }
}
