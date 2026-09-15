//! Tools denied outright for the duration of an engagement so that no uncontrolled network egress
//! can reach a target without passing through `searu`. These become a project-scoped
//! `permissions.deny` list, the one tool-restriction mechanism Claude Code enforces.

pub const DENIED_EGRESS: &[&str] = &["WebFetch", "WebSearch", "mcp__*"];

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
        assert_eq!(merge_deny(&[]), deny(&["WebFetch", "WebSearch", "mcp__*"]));
    }

    #[test]
    fn merging_preserves_existing_entries_and_adds_only_the_missing() {
        let existing = deny(&["Bash(rm *)", "WebFetch"]);
        assert_eq!(
            merge_deny(&existing),
            deny(&["Bash(rm *)", "WebFetch", "WebSearch", "mcp__*"])
        );
    }

    #[test]
    fn merging_is_idempotent() {
        let once = merge_deny(&[]);
        assert_eq!(merge_deny(&once), once);
    }
}
