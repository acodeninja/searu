//! The PreToolUse allowlist backstop: force target-facing actions through `searu`. It does not read
//! the rules of engagement; its only job is to stop an agent bypassing `searu run`.

pub enum HookDecision {
    Allow,
    Block(String),
}

pub fn decide(tool_name: &str, command: Option<&str>) -> HookDecision {
    if tool_name != "Bash" {
        return HookDecision::Allow;
    }
    match command.and_then(program) {
        Some(program) if is_searu(&program) => HookDecision::Allow,
        _ => HookDecision::Block(
            "searu scope-hook: only `searu` commands are permitted in Bash; run tools via `searu run`"
                .to_string(),
        ),
    }
}

fn program(command: &str) -> Option<String> {
    command
        .split_whitespace()
        .find(|token| !is_assignment(token))
        .map(basename)
}

fn is_assignment(token: &str) -> bool {
    match token.split_once('=') {
        Some((name, _)) => {
            let mut chars = name.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

fn basename(token: &str) -> String {
    token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .to_string()
}

fn is_searu(program: &str) -> bool {
    program.eq_ignore_ascii_case("searu") || program.eq_ignore_ascii_case("searu.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_allowed(decision: HookDecision) -> bool {
        matches!(decision, HookDecision::Allow)
    }

    #[test]
    fn a_searu_command_passes() {
        assert!(is_allowed(decide(
            "Bash",
            Some("searu run commix --technique T1190 --target http://localhost:5000")
        )));
    }

    #[test]
    fn an_absolute_searu_path_passes() {
        assert!(is_allowed(decide(
            "Bash",
            Some("/usr/local/bin/searu findings")
        )));
    }

    #[test]
    fn env_prefixed_searu_passes() {
        assert!(is_allowed(decide(
            "Bash",
            Some("FOO=bar searu attack list")
        )));
    }

    #[test]
    fn a_raw_scanner_is_blocked() {
        assert!(!is_allowed(decide("Bash", Some("docker run alpine"))));
        assert!(!is_allowed(decide(
            "Bash",
            Some("curl http://localhost:5000")
        )));
    }

    #[test]
    fn benign_shell_is_blocked_too() {
        assert!(!is_allowed(decide("Bash", Some("ls -la"))));
    }

    #[test]
    fn an_empty_or_missing_command_is_blocked() {
        assert!(!is_allowed(decide("Bash", Some("   "))));
        assert!(!is_allowed(decide("Bash", None)));
    }

    #[test]
    fn non_bash_tools_pass() {
        assert!(is_allowed(decide("Read", None)));
        assert!(is_allowed(decide("Grep", Some("pattern"))));
    }
}
