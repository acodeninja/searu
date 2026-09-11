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
