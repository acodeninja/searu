//! The capability overlay: the ATT&CK cells searu can actually operate, each bound to its tools and
//! intrusiveness tier. It grows as tools are added; the full matrix already lives in [`crate::attack`].

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

pub struct Capability {
    pub id: &'static str,
    pub attack_ids: &'static [&'static str],
    pub tier: Tier,
    pub tools: &'static [&'static str],
}

static CAPABILITIES: &[Capability] = &[Capability {
    id: "command-injection",
    attack_ids: &["T1190", "T1059"],
    tier: Tier::Exploitation,
    tools: &["commix"],
}];

pub fn capabilities() -> &'static [Capability] {
    CAPABILITIES
}

pub fn capability(id: &str) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|c| c.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_injection_capability_is_registered() {
        let capability = capability("command-injection").unwrap();
        assert_eq!(capability.tier, Tier::Exploitation);
        assert_eq!(capability.attack_ids, &["T1190", "T1059"]);
        assert_eq!(capability.tools, &["commix"]);
    }

    #[test]
    fn tiers_display_in_title_case() {
        assert_eq!(Tier::Exploitation.to_string(), "Exploitation");
        assert_eq!(Tier::Passive.to_string(), "Passive");
    }

    #[test]
    fn an_unknown_capability_resolves_to_nothing() {
        assert!(capability("does-not-exist").is_none());
    }
}
