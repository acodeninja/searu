//! The authorisation gate. Scope is the one absolute gate; the ROE's exact ATT&CK allow-list and the
//! tier's requirement unlock execution. Listing a technique in the ROE is the sole way to authorise
//! it — matching is exact and sub-technique-specific, so a parent never implies a child.

use crate::capability::{Capability, Tier};
use crate::ports::Roe;
use crate::scope::is_in_scope;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Authorised,
    OutOfScope,
    TechniqueNotAllowed(String),
    ExploitationNotAuthorised,
    DestructiveNotAuthorised,
}

pub fn decide(roe: &Roe, capability: &Capability, target: &str) -> Decision {
    if !is_in_scope(target, &roe.scope) {
        return Decision::OutOfScope;
    }

    for id in capability.attack_ids {
        if !roe.authorises(id) {
            return Decision::TechniqueNotAllowed((*id).to_string());
        }
    }

    match capability.tier {
        Tier::Passive | Tier::Active => Decision::Authorised,
        Tier::Exploitation => {
            if roe.authorisation.exploitation_authorised_by.is_some() {
                Decision::Authorised
            } else {
                Decision::ExploitationNotAuthorised
            }
        }
        Tier::Destructive => {
            if roe.authorisation.exploitation_authorised_by.is_some()
                && roe.authorisation.destructive_authorised
            {
                Decision::Authorised
            } else {
                Decision::DestructiveNotAuthorised
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::{Authorisation, Authoriser};
    use crate::scope::{EntryKind, Scope, ScopeEntry};

    fn localhost_scope() -> Scope {
        Scope {
            targets: vec![ScopeEntry {
                kind: EntryKind::Url,
                value: "http://localhost:5000".to_string(),
            }],
            exclusions: vec![],
        }
    }

    fn roe(allowed: &[&str], authoriser: bool, destructive: bool) -> Roe {
        Roe {
            scope: localhost_scope(),
            allowed_techniques: allowed.iter().map(|s| s.to_string()).collect(),
            authorisation: Authorisation {
                exploitation_authorised_by: authoriser.then(|| Authoriser {
                    name: "Jane Tester".to_string(),
                    email: "jane@example.com".to_string(),
                }),
                destructive_authorised: destructive,
            },
        }
    }

    const CMD_INJECTION: Capability = Capability {
        id: "command-injection",
        attack_ids: &["T1190", "T1059"],
        tier: Tier::Exploitation,
        tools: &["commix"],
    };

    const SERVICE_DETECTION: Capability = Capability {
        id: "service-detection",
        attack_ids: &["T1046"],
        tier: Tier::Active,
        tools: &["nmap"],
    };

    const NETWORK_FLOOD: Capability = Capability {
        id: "network-flood",
        attack_ids: &["T1498.001"],
        tier: Tier::Destructive,
        tools: &["hping3"],
    };

    #[test]
    fn an_out_of_scope_target_is_refused_before_anything_else() {
        let roe = roe(&["T1190", "T1059"], true, true);
        assert_eq!(
            decide(&roe, &CMD_INJECTION, "http://evil.example.org"),
            Decision::OutOfScope
        );
    }

    #[test]
    fn every_attack_id_must_be_allow_listed() {
        let roe = roe(&["T1190"], true, false);
        assert_eq!(
            decide(&roe, &CMD_INJECTION, "http://localhost:5000"),
            Decision::TechniqueNotAllowed("T1059".to_string())
        );
    }

    #[test]
    fn an_active_technique_needs_only_its_allow_listing() {
        let roe = roe(&["T1046"], false, false);
        assert_eq!(
            decide(&roe, &SERVICE_DETECTION, "http://localhost:5000"),
            Decision::Authorised
        );
    }

    #[test]
    fn exploitation_needs_a_named_authoriser() {
        let roe = roe(&["T1190", "T1059"], false, false);
        assert_eq!(
            decide(&roe, &CMD_INJECTION, "http://localhost:5000"),
            Decision::ExploitationNotAuthorised
        );
    }

    #[test]
    fn exploitation_runs_when_authorised() {
        let roe = roe(&["T1190", "T1059"], true, false);
        assert_eq!(
            decide(&roe, &CMD_INJECTION, "http://localhost:5000"),
            Decision::Authorised
        );
    }

    #[test]
    fn destructive_needs_the_explicit_flag_as_well_as_an_authoriser() {
        let roe = roe(&["T1498.001"], true, false);
        assert_eq!(
            decide(&roe, &NETWORK_FLOOD, "http://localhost:5000"),
            Decision::DestructiveNotAuthorised
        );
    }

    #[test]
    fn destructive_runs_with_an_authoriser_and_the_flag() {
        let roe = roe(&["T1498.001"], true, true);
        assert_eq!(
            decide(&roe, &NETWORK_FLOOD, "http://localhost:5000"),
            Decision::Authorised
        );
    }

    #[test]
    fn allow_listing_a_parent_does_not_authorise_a_sub_technique() {
        let roe = roe(&["T1498"], true, true);
        assert_eq!(
            decide(&roe, &NETWORK_FLOOD, "http://localhost:5000"),
            Decision::TechniqueNotAllowed("T1498.001".to_string())
        );
    }
}
