use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const LAB_ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "localhost", "port": 5000 } ] },
    "allowed_techniques": ["T1190", "T1059"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab", "email": "lab@example.com" } }
}"#;

const UNAUTHORISED_ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "localhost", "port": 5000 } ] },
    "allowed_techniques": ["T1190", "T1059"]
}"#;

const BOGUS_TECHNIQUE_ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "localhost", "port": 5000 } ] },
    "allowed_techniques": ["T1190", "T9999"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab", "email": "lab@example.com" } }
}"#;

const LOOPBACK_URL_ROE: &str = r#"{
    "scope": { "targets": [ { "type": "url", "value": "http://localhost:3000/", "port": 3000 } ] },
    "allowed_techniques": ["T1046"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab", "email": "lab@example.com" } }
}"#;

fn roe_file(content: &str) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules-of-engagement.json");
    std::fs::write(&path, content).unwrap();
    let path = path.to_str().unwrap().to_string();
    (dir, path)
}

#[test]
fn version_flag_reports_the_package_version() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(VERSION));
}

#[test]
fn bare_invocation_lists_the_subcommands() {
    Command::cargo_bin("searu")
        .unwrap()
        .assert()
        .success()
        .stdout(contains("run"))
        .stdout(contains("attack"))
        .stdout(contains("findings"))
        .stdout(contains("loot"));
}

#[test]
fn attack_show_prints_the_technique_name() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["attack", "show", "T1046"])
        .assert()
        .success()
        .stdout(contains("Network Service Discovery"));
}

#[test]
fn attack_list_filters_by_tactic() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["attack", "list", "--tactic", "TA0043"])
        .assert()
        .success()
        .stdout(contains("T1595"));
}

#[test]
fn run_refuses_an_out_of_scope_target() {
    let (dir, roe) = roe_file(LAB_ROE);
    Command::cargo_bin("searu")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "run",
            "commix",
            "--technique",
            "T1190",
            "--target",
            "http://evil.example.org/cmd/dig?ip_addr=1",
            "--roe",
            &roe,
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("OUT OF SCOPE"));

    let audit = std::fs::read_to_string(dir.path().join("pentest").join("audit.jsonl")).unwrap();
    assert!(audit.contains("OUT OF SCOPE"));
    assert!(audit.contains("evil.example.org"));
}

#[test]
fn a_host_only_target_of_a_url_scope_is_refused_with_a_scope_hint() {
    let (dir, roe) = roe_file(LOOPBACK_URL_ROE);
    Command::cargo_bin("searu")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "run",
            "nmap",
            "--technique",
            "T1046",
            "--target",
            "localhost",
            "--roe",
            &roe,
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("OUT OF SCOPE"))
        .stderr(contains("hint:"))
        .stderr(contains("localhost and 127.0.0.1"));
}

#[test]
fn run_refuses_exploitation_without_an_authoriser() {
    let (dir, roe) = roe_file(UNAUTHORISED_ROE);
    Command::cargo_bin("searu")
        .unwrap()
        .current_dir(dir.path())
        .args([
            "run",
            "commix",
            "--technique",
            "T1190",
            "--target",
            "http://localhost:5000/cmd/dig?ip_addr=1",
            "--roe",
            &roe,
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("exploitation not authorised"));

    let audit = std::fs::read_to_string(dir.path().join("pentest").join("audit.jsonl")).unwrap();
    assert!(audit.contains("exploitation not authorised"));
}

#[test]
fn run_rejects_a_technique_outside_the_tool_repertoire() {
    let (_dir, roe) = roe_file(LAB_ROE);
    Command::cargo_bin("searu")
        .unwrap()
        .args([
            "run",
            "commix",
            "--technique",
            "T9999",
            "--target",
            "http://localhost:5000/cmd/dig?ip_addr=1",
            "--roe",
            &roe,
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("cannot perform"));
}

#[test]
fn tool_list_includes_commix() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["tool", "list"])
        .assert()
        .success()
        .stdout(contains("commix"))
        .stdout(contains("T1190"));
}

#[test]
fn tool_list_by_phase_lists_only_that_phases_tools() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["tool", "list", "--phase", "discovery"])
        .assert()
        .success()
        .stdout(contains("ffuf"))
        .stdout(contains("commix").not());
}

#[test]
fn tool_list_rejects_an_unknown_phase() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["tool", "list", "--phase", "bogus"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("valid phases"));
}

#[test]
fn tool_advice_renders_the_manifest() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["tool", "advice", "commix"])
        .assert()
        .success()
        .stdout(contains("invoke:"))
        .stdout(contains("searu run commix"));
}

#[test]
fn findings_and_loot_are_empty_on_a_fresh_engagement() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("searu")
        .unwrap()
        .current_dir(&dir)
        .arg("findings")
        .assert()
        .success()
        .stdout("");
    Command::cargo_bin("searu")
        .unwrap()
        .current_dir(&dir)
        .arg("loot")
        .assert()
        .success()
        .stdout("");
}

#[test]
fn validate_roe_accepts_a_good_file() {
    let (_dir, roe) = roe_file(LAB_ROE);
    Command::cargo_bin("searu")
        .unwrap()
        .args(["validate-roe", "--roe", &roe])
        .assert()
        .success()
        .stdout(contains("OK"));
}

#[test]
fn validate_roe_rejects_an_unknown_technique() {
    let (_dir, roe) = roe_file(BOGUS_TECHNIQUE_ROE);
    Command::cargo_bin("searu")
        .unwrap()
        .args(["validate-roe", "--roe", &roe])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("T9999"));
}

#[test]
fn validate_roe_reports_a_missing_file() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["validate-roe", "--roe", "does/not/exist.json"])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn scope_hook_allows_a_searu_command() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"searu run commix --technique T1190 --target http://localhost:5000"}}"#,
        )
        .assert()
        .success()
        .stdout(contains(r#""permissionDecision":"allow""#));
}

#[test]
fn scope_hook_blocks_a_raw_docker_command() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(r#"{"tool_name":"Bash","tool_input":{"command":"docker run alpine"}}"#)
        .assert()
        .failure()
        .code(2)
        .stderr(contains("searu"));
}

#[test]
fn scope_hook_allows_a_searu_command_via_powershell() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(
            r#"{"tool_name":"PowerShell","tool_input":{"command":"searu run katana --technique T1595 --target http://localhost:3000"}}"#,
        )
        .assert()
        .success()
        .stdout(contains(r#""permissionDecision":"allow""#));
}

#[test]
fn scope_hook_blocks_a_raw_command_via_powershell() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(r#"{"tool_name":"PowerShell","tool_input":{"command":"docker run alpine"}}"#)
        .assert()
        .failure()
        .code(2)
        .stderr(contains("searu"));
}

#[test]
fn scope_hook_allows_a_file_read_tool() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#)
        .assert()
        .success()
        .stdout(contains(r#""permissionDecision":"allow""#));
}

#[test]
fn scope_hook_blocks_a_network_tool() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(r#"{"tool_name":"WebFetch","tool_input":{"url":"http://localhost:5000"}}"#)
        .assert()
        .failure()
        .code(2)
        .stderr(contains("searu"));
}

#[test]
fn harden_writes_an_idempotent_egress_deny_list() {
    let dir = tempfile::tempdir().unwrap();
    let settings = dir.path().join(".claude").join("settings.json");

    Command::cargo_bin("searu")
        .unwrap()
        .arg("harden")
        .arg("--dir")
        .arg(dir.path())
        .assert()
        .success();

    let text = std::fs::read_to_string(&settings).unwrap();
    assert!(text.contains("WebFetch"));
    assert!(text.contains("WebSearch"));
    assert!(text.contains("mcp__*"));
    assert!(text.contains("Bash(docker:*)"));

    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    let hook = &document["hooks"]["PreToolUse"][0];
    assert_eq!(hook["matcher"], "*");
    assert!(hook["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .contains("scope-hook"));

    Command::cargo_bin("searu")
        .unwrap()
        .arg("harden")
        .arg("--dir")
        .arg(dir.path())
        .assert()
        .success();

    let text = std::fs::read_to_string(&settings).unwrap();
    assert_eq!(text.matches("WebFetch").count(), 1);
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
}

fn install_skill_into(home: &std::path::Path) {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("install-skill")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .assert()
        .success();
}

#[test]
fn install_skill_writes_the_payload() {
    let home = tempfile::tempdir().unwrap();
    install_skill_into(home.path());
    let base = home.path().join(".claude").join("skills").join("searu");
    assert!(base.join("SKILL.md").is_file());
    assert!(base.join("sections").join("manifest.json").is_file());
    assert!(base.join("specialists").join("T1190-sqlmap.md").is_file());
    assert!(base.join(".searu-owned").is_file());
}

#[test]
fn install_skill_rewrites_the_hook_to_the_binary_path() {
    let home = tempfile::tempdir().unwrap();
    install_skill_into(home.path());
    let skill = std::fs::read_to_string(
        home.path()
            .join(".claude")
            .join("skills")
            .join("searu")
            .join("SKILL.md"),
    )
    .unwrap();
    let exe = assert_cmd::cargo::cargo_bin("searu");
    assert!(skill.contains("scope-hook"));
    assert!(
        !skill.contains(r#"command: "searu scope-hook""#),
        "the bare template hook must be rewritten"
    );
    assert!(
        skill.contains(exe.to_str().unwrap()),
        "the hook must reference the absolute binary path"
    );
}

#[test]
fn install_skill_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    install_skill_into(home.path());
    install_skill_into(home.path());
    assert!(home
        .path()
        .join(".claude")
        .join("skills")
        .join("searu")
        .join("SKILL.md")
        .is_file());
}

#[test]
fn install_skill_installs_the_upgrade_command() {
    let home = tempfile::tempdir().unwrap();
    install_skill_into(home.path());
    let command = home
        .path()
        .join(".claude")
        .join("commands")
        .join("searu-upgrade.md");
    assert!(command.is_file());
    assert!(std::fs::read_to_string(&command)
        .unwrap()
        .contains("searu-owned"));
}

#[test]
fn install_skill_preserves_a_users_own_upgrade_command() {
    let home = tempfile::tempdir().unwrap();
    let commands = home.path().join(".claude").join("commands");
    std::fs::create_dir_all(&commands).unwrap();
    let command = commands.join("searu-upgrade.md");
    std::fs::write(&command, "my own command").unwrap();
    install_skill_into(home.path());
    assert_eq!(std::fs::read_to_string(&command).unwrap(), "my own command");
    assert!(commands.join("searu-upgrade.md.searu-backup").is_file());
}

#[test]
fn playbook_flags_the_matching_technology_and_lists_gaps() {
    let work = tempfile::tempdir().unwrap();
    let pentest = work.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(
        pentest.join("observations.jsonl"),
        "{\"kind\":\"tech\",\"value\":\"Angular\"}\n{\"kind\":\"tech\",\"value\":\"Svelte\"}\n",
    )
    .unwrap();

    let playbooks = tempfile::tempdir().unwrap();
    std::fs::write(playbooks.path().join("angular.md"), "# Angular").unwrap();
    std::fs::write(playbooks.path().join("php.md"), "# PHP").unwrap();
    std::fs::write(playbooks.path().join("README.md"), "index").unwrap();

    Command::cargo_bin("searu")
        .unwrap()
        .arg("playbook")
        .current_dir(work.path())
        .env("SEARU_PLAYBOOKS_DIR", playbooks.path())
        .assert()
        .success()
        .stdout(
            contains("angular")
                .and(contains("php"))
                .and(contains("Angular")),
        )
        .stdout(contains("angular.md"))
        .stdout(contains("svelte"))
        .stdout(contains("README").not());
}

#[test]
fn install_skill_preserves_a_users_own_skill() {
    let home = tempfile::tempdir().unwrap();
    let base = home.path().join(".claude").join("skills").join("searu");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("SKILL.md"), "my own skill").unwrap();
    install_skill_into(home.path());
    assert_eq!(
        std::fs::read_to_string(base.join("SKILL.md")).unwrap(),
        "my own skill"
    );
    assert!(base.join("SKILL.md.searu-backup").is_file());
}
