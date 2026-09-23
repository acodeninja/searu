//! The PreToolUse allowlist backstop: force target-facing actions through `searu`. It does not read
//! the rules of engagement; its only job is to stop an agent bypassing `searu run`.

pub enum HookDecision {
    Allow,
    Block(String),
}

pub fn decide(tool_name: &str, command: Option<&str>) -> HookDecision {
    if is_shell(tool_name) {
        return match command.and_then(program) {
            Some(program) if is_searu(&program) => HookDecision::Allow,
            _ => HookDecision::Block(
                "searu scope-hook: only `searu` commands are permitted in a shell; run tools via `searu run`"
                    .to_string(),
            ),
        };
    }
    if is_allowed_local(tool_name) {
        HookDecision::Allow
    } else {
        HookDecision::Block(format!(
            "searu scope-hook: `{tool_name}` cannot reach a target during an engagement; reach targets only via `searu run`"
        ))
    }
}

/// The shell tools that execute an arbitrary command: on Windows the agent's shell is `PowerShell`, so
/// it must be gated exactly like `Bash` — a `searu` command passes, anything else is blocked.
fn is_shell(tool_name: &str) -> bool {
    matches!(tool_name, "Bash" | "PowerShell" | "pwsh")
}

fn is_allowed_local(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "Read"
            | "Write"
            | "Edit"
            | "Grep"
            | "Glob"
            | "Agent"
            | "Task"
            | "TodoWrite"
            | "NotebookEdit"
            | "AskUserQuestion"
            | "ExitPlanMode"
            | "EnterPlanMode"
            | "ScheduleWakeup"
            | "TaskCreate"
            | "TaskUpdate"
            | "TaskList"
            | "TaskGet"
            | "TaskOutput"
            | "TaskStop"
            | "BashOutput"
            | "KillShell"
            | "KillBash"
    )
}

fn program(command: &str) -> Option<String> {
    command
        .split_whitespace()
        .find(|token| !is_assignment(token) && *token != "&")
        .map(|token| basename(strip_quotes(token)))
}

/// PowerShell invokes an executable at a quoted path with the call operator, e.g.
/// `& "C:\…\searu.exe" run …`; strip the surrounding quotes so the basename resolves to `searu.exe`.
fn strip_quotes(token: &str) -> &str {
    token.trim_matches(['"', '\'']).trim()
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
    fn a_searu_command_via_powershell_passes() {
        assert!(is_allowed(decide(
            "PowerShell",
            Some("searu run katana --technique T1595 --target http://localhost:3000")
        )));
        assert!(is_allowed(decide("pwsh", Some("searu findings"))));
    }

    #[test]
    fn a_raw_scanner_via_powershell_is_blocked() {
        assert!(!is_allowed(decide("PowerShell", Some("docker run alpine"))));
        assert!(!is_allowed(decide("PowerShell", Some("Get-ChildItem"))));
    }

    #[test]
    fn a_windows_searu_exe_path_passes_in_either_shell() {
        let command = r"C:\Users\Lawrence\.cargo\bin\searu.exe run sqlmap --technique T1190 --target http://localhost:3000";
        assert!(is_allowed(decide("Bash", Some(command))));
        assert!(is_allowed(decide("PowerShell", Some(command))));
    }

    #[test]
    fn a_powershell_call_operator_invocation_passes() {
        assert!(is_allowed(decide(
            "PowerShell",
            Some(
                r#"& "C:\Users\Lawrence\.cargo\bin\searu.exe" run hydra --technique T1110 --target host"#
            )
        )));
    }

    #[test]
    fn background_shell_management_tools_pass() {
        assert!(is_allowed(decide("BashOutput", None)));
        assert!(is_allowed(decide("KillShell", None)));
        assert!(is_allowed(decide("KillBash", None)));
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
    fn local_file_tools_pass() {
        assert!(is_allowed(decide("Read", None)));
        assert!(is_allowed(decide("Grep", Some("pattern"))));
        assert!(is_allowed(decide("Glob", None)));
    }

    #[test]
    fn editing_and_spawning_tools_pass() {
        assert!(is_allowed(decide("Write", None)));
        assert!(is_allowed(decide("Edit", None)));
        assert!(is_allowed(decide("Agent", None)));
        assert!(is_allowed(decide("Task", None)));
        assert!(is_allowed(decide("TodoWrite", None)));
    }

    #[test]
    fn local_ui_and_task_tools_pass() {
        for tool in [
            "AskUserQuestion",
            "ExitPlanMode",
            "EnterPlanMode",
            "ScheduleWakeup",
            "TaskCreate",
            "TaskUpdate",
            "TaskList",
            "TaskGet",
            "TaskOutput",
            "TaskStop",
        ] {
            assert!(is_allowed(decide(tool, None)), "{tool} should be allowed");
        }
    }

    #[test]
    fn network_capable_tools_are_blocked() {
        assert!(!is_allowed(decide("WebFetch", None)));
        assert!(!is_allowed(decide("WebSearch", None)));
        assert!(!is_allowed(decide("Skill", None)));
        assert!(!is_allowed(decide("mcp__acme__fetch_url", None)));
    }

    #[test]
    fn an_unknown_tool_is_blocked() {
        assert!(!is_allowed(decide("SomeFutureTool", None)));
        assert!(!is_allowed(decide("", None)));
    }
}
