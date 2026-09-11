//! The MITRE ATT&CK Enterprise matrix, embedded at build time and served offline.

mod generated;

pub struct AttackTactic {
    pub id: &'static str,
    pub name: &'static str,
}

pub struct AttackTechnique {
    pub id: &'static str,
    pub name: &'static str,
    pub tactics: &'static [&'static str],
    pub parent: Option<&'static str>,
}

pub fn tactics() -> &'static [AttackTactic] {
    generated::TACTICS
}

pub fn techniques() -> &'static [AttackTechnique] {
    generated::TECHNIQUES
}

pub fn tactic(id: &str) -> Option<&'static AttackTactic> {
    generated::TACTICS.iter().find(|t| t.id == id)
}

pub fn technique(id: &str) -> Option<&'static AttackTechnique> {
    generated::TECHNIQUES.iter().find(|t| t.id == id)
}

pub fn techniques_in_tactic(
    tactic_id: &str,
) -> impl Iterator<Item = &'static AttackTechnique> + '_ {
    // `contains(&tactic_id)` cannot typecheck: the elements are `&'static str` but the argument is
    // a borrowed `&str`, so the comparison is written out by hand.
    #[allow(clippy::manual_contains)]
    generated::TECHNIQUES
        .iter()
        .filter(move |t| t.tactics.iter().any(|s| *s == tactic_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_a_technique_by_id() {
        assert_eq!(
            technique("T1046").unwrap().name,
            "Network Service Discovery"
        );
    }

    #[test]
    fn a_technique_carries_its_tactics() {
        assert!(technique("T1046").unwrap().tactics.contains(&"TA0007"));
    }

    #[test]
    fn a_subtechnique_knows_its_parent() {
        let sub = technique("T1595.002").unwrap();
        assert_eq!(sub.name, "Vulnerability Scanning");
        assert_eq!(sub.parent, Some("T1595"));
    }

    #[test]
    fn a_top_level_technique_has_no_parent() {
        assert_eq!(technique("T1595").unwrap().parent, None);
    }

    #[test]
    fn resolves_a_tactic_name() {
        assert_eq!(tactic("TA0043").unwrap().name, "Reconnaissance");
    }

    #[test]
    fn the_full_enterprise_matrix_is_embedded() {
        assert!(tactics().len() >= 14);
        assert!(techniques().len() > 600);
    }

    #[test]
    fn lists_techniques_within_a_tactic() {
        assert!(techniques_in_tactic("TA0043").any(|t| t.id == "T1595"));
    }

    #[test]
    fn an_unknown_id_resolves_to_nothing() {
        assert!(technique("T9999").is_none());
        assert!(tactic("TA9999").is_none());
    }
}
