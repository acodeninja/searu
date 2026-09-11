//! Intrusiveness/impact tiers (NIST SP 800-115, extended with `Destructive`) and the classification
//! of ATT&CK techniques into them. The tier decides what extra authorisation a technique needs; the
//! ROE allow-list still gates every technique regardless of tier. Unknown techniques default to the
//! most restrictive tier so a novel technique is never run on allow-listing alone.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Passive,
    Active,
    Exploitation,
    Destructive,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Tier::Passive => "Passive",
            Tier::Active => "Active",
            Tier::Exploitation => "Exploitation",
            Tier::Destructive => "Destructive",
        })
    }
}

pub fn tier_of(technique_id: &str) -> Tier {
    let base = technique_id.split('.').next().unwrap_or(technique_id);
    match base {
        // Passive — OSINT and third-party gathering; no packets to the target.
        "T1589" | "T1590" | "T1591" | "T1592" | "T1593" | "T1596" | "T1597" | "T1598" => {
            Tier::Passive
        }
        // Active — interacts with the target but read-only (scanning, discovery, enumeration).
        "T1595" | "T1046" | "T1049" | "T1057" | "T1069" | "T1082" | "T1083" | "T1087" | "T1518" => {
            Tier::Active
        }
        // Destructive — may modify, degrade, or deny.
        "T1485" | "T1486" | "T1490" | "T1491" | "T1498" | "T1499" | "T1531" | "T1561" => {
            Tier::Destructive
        }
        // Exploitation — validate a weakness, gain access, or take credentials.
        "T1059" | "T1068" | "T1110" | "T1190" | "T1212" | "T1552" | "T1606" => Tier::Exploitation,
        // Unknown — most restrictive by default.
        _ => Tier::Exploitation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers_display_in_title_case() {
        assert_eq!(Tier::Exploitation.to_string(), "Exploitation");
        assert_eq!(Tier::Passive.to_string(), "Passive");
    }

    #[test]
    fn classifies_common_techniques() {
        assert_eq!(tier_of("T1190"), Tier::Exploitation);
        assert_eq!(tier_of("T1059"), Tier::Exploitation);
        assert_eq!(tier_of("T1552"), Tier::Exploitation);
        assert_eq!(tier_of("T1082"), Tier::Active);
        assert_eq!(tier_of("T1595.002"), Tier::Active);
        assert_eq!(tier_of("T1596"), Tier::Passive);
        assert_eq!(tier_of("T1485"), Tier::Destructive);
    }

    #[test]
    fn an_unknown_technique_defaults_to_exploitation() {
        assert_eq!(tier_of("T9999"), Tier::Exploitation);
    }
}
