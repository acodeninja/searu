//! The authorisation gate. Scope is the one absolute gate; the ROE's exact ATT&CK allow-list plus the
//! technique's tier unlock execution. Listing a technique in the ROE is the sole authorisation, and
//! matching is exact and sub-technique-specific, so a parent never implies a child.

use crate::ports::Roe;
use crate::scope::is_host_in_scope;
use crate::technique::{tier_of, Tier};

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Authorised,
    OutOfScope,
    TechniqueNotAllowed(String),
    ExploitationNotAuthorised,
    DestructiveNotAuthorised,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Authorised => write!(f, "authorised"),
            Decision::OutOfScope => write!(f, "OUT OF SCOPE"),
            Decision::TechniqueNotAllowed(id) => {
                write!(f, "technique not authorised in the ROE: {id}")
            }
            Decision::ExploitationNotAuthorised => write!(
                f,
                "exploitation not authorised: name an authoriser in the ROE"
            ),
            Decision::DestructiveNotAuthorised => write!(
                f,
                "destructive action not authorised: set destructive_authorised and name an authoriser"
            ),
        }
    }
}

pub fn decide(roe: &Roe, technique: &str, target: &str) -> Decision {
    if !is_host_in_scope(target, &roe.scope) {
        return Decision::OutOfScope;
    }
    if !roe.authorises(technique) {
        return Decision::TechniqueNotAllowed(technique.to_string());
    }
    match tier_of(technique) {
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
    use crate::ports::{Authorisation, Authoriser, Roe};
    use crate::scope::{HostForm, Scope, ScopeEntry};

    fn roe(allowed: &[&str], authoriser: bool, destructive: bool) -> Roe {
        Roe {
            scope: Scope {
                targets: vec![ScopeEntry::Host {
                    form: HostForm::Url,
                    value: "http://localhost:5000".to_string(),
                    port: None,
                }],
                exclusions: vec![],
            },
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

    const LOCAL: &str = "http://localhost:5000/cmd/dig?ip_addr=1";

    #[test]
    fn out_of_scope_is_refused_first() {
        assert_eq!(
            decide(
                &roe(&["T1190"], true, true),
                "T1190",
                "http://evil.example.org"
            ),
            Decision::OutOfScope
        );
    }

    #[test]
    fn the_technique_must_be_allow_listed() {
        assert_eq!(
            decide(&roe(&[], false, false), "T1190", LOCAL),
            Decision::TechniqueNotAllowed("T1190".to_string())
        );
    }

    #[test]
    fn an_active_technique_needs_only_allow_listing() {
        assert_eq!(
            decide(&roe(&["T1082"], false, false), "T1082", LOCAL),
            Decision::Authorised
        );
    }

    #[test]
    fn exploitation_needs_a_named_authoriser() {
        assert_eq!(
            decide(&roe(&["T1190"], false, false), "T1190", LOCAL),
            Decision::ExploitationNotAuthorised
        );
    }

    #[test]
    fn exploitation_runs_when_authorised() {
        assert_eq!(
            decide(&roe(&["T1190"], true, false), "T1190", LOCAL),
            Decision::Authorised
        );
    }

    #[test]
    fn destructive_needs_the_flag_as_well_as_an_authoriser() {
        assert_eq!(
            decide(&roe(&["T1485"], true, false), "T1485", LOCAL),
            Decision::DestructiveNotAuthorised
        );
    }

    #[test]
    fn destructive_runs_with_authoriser_and_flag() {
        assert_eq!(
            decide(&roe(&["T1485"], true, true), "T1485", LOCAL),
            Decision::Authorised
        );
    }

    #[test]
    fn allow_listing_is_exact_and_sub_technique_specific() {
        assert_eq!(
            decide(&roe(&["T1498"], true, true), "T1498.001", LOCAL),
            Decision::TechniqueNotAllowed("T1498.001".to_string())
        );
    }
}
