use assert_cmd::Command;
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
    let (_dir, roe) = roe_file(LAB_ROE);
    Command::cargo_bin("searu")
        .unwrap()
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
}

#[test]
fn run_refuses_exploitation_without_an_authoriser() {
    let (_dir, roe) = roe_file(UNAUTHORISED_ROE);
    Command::cargo_bin("searu")
        .unwrap()
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
fn tool_advice_prints_guidance() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["tool", "advice", "commix"])
        .assert()
        .success()
        .stdout(contains("commix"));
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
        .success();
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
fn scope_hook_allows_a_file_read_tool() {
    Command::cargo_bin("searu")
        .unwrap()
        .arg("scope-hook")
        .write_stdin(r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#)
        .assert()
        .success();
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
