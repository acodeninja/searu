//! Tools denied outright for the duration of an engagement so that no uncontrolled network egress
//! can reach a target without passing through `searu`. These become a project-scoped
//! `permissions.deny` list, the one tool-restriction mechanism Claude Code enforces — and, unlike a
//! skill-frontmatter hook, one that reaches a spawned specialist. Alongside the egress *tools* it
//! deny-lists the target-reaching Bash *programs* a specialist must never invoke directly (it reaches
//! a target only through `searu run`), a coarse enforced backstop to the scope-hook allowlist.

pub const DENIED_EGRESS: &[&str] = &[
    "WebFetch",
    "WebSearch",
    "mcp__*",
    "Bash(docker:*)",
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(nc:*)",
    "Bash(ncat:*)",
    "Bash(socat:*)",
];

pub fn merge_deny(existing: &[String]) -> Vec<String> {
    let mut merged = existing.to_vec();
    for tool in DENIED_EGRESS {
        if !merged.iter().any(|entry| entry.as_str() == *tool) {
            merged.push((*tool).to_string());
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deny(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn merging_into_empty_adds_every_denied_tool() {
        assert_eq!(
            merge_deny(&[]),
            deny(&[
                "WebFetch",
                "WebSearch",
                "mcp__*",
                "Bash(docker:*)",
                "Bash(curl:*)",
                "Bash(wget:*)",
                "Bash(nc:*)",
                "Bash(ncat:*)",
                "Bash(socat:*)",
            ])
        );
    }

    #[test]
    fn merging_denies_direct_target_reaching_bash_programs() {
        let merged = merge_deny(&[]);
        for program in ["docker", "curl", "wget", "nc", "ncat", "socat"] {
            assert!(
                merged
                    .iter()
                    .any(|entry| entry == &format!("Bash({program}:*)")),
                "expected a deny entry for Bash {program}"
            );
        }
    }

    #[test]
    fn merging_preserves_existing_entries_and_adds_only_the_missing() {
        let existing = deny(&["Bash(rm *)", "WebFetch"]);
        assert_eq!(
            merge_deny(&existing),
            deny(&[
                "Bash(rm *)",
                "WebFetch",
                "WebSearch",
                "mcp__*",
                "Bash(docker:*)",
                "Bash(curl:*)",
                "Bash(wget:*)",
                "Bash(nc:*)",
                "Bash(ncat:*)",
                "Bash(socat:*)",
            ])
        );
    }

    #[test]
    fn merging_is_idempotent() {
        let once = merge_deny(&[]);
        assert_eq!(merge_deny(&once), once);
    }
}
