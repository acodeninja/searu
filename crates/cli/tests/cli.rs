use assert_cmd::Command;
use predicates::boolean::PredicateBooleanExt;
use predicates::str::contains;

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
        .stdout(contains("attack"));
}

const SAMPLE_ROE: &str = r#"{
    "scope": {
        "targets": [
            { "type": "domain", "value": "staging.example.com" },
            { "type": "cidr", "value": "10.20.0.0/24" }
        ],
        "exclusions": [
            { "type": "domain", "value": "billing.staging.example.com" }
        ]
    }
}"#;

#[test]
fn capability_list_shows_command_injection() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["capability", "list"])
        .assert()
        .success()
        .stdout(contains("command-injection"))
        .stdout(contains("T1190"));
}

#[test]
fn capability_list_can_filter_to_a_tier() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["capability", "list", "--tier", "exploitation"])
        .assert()
        .success()
        .stdout(contains("command-injection"));
}

#[test]
fn capability_list_excludes_other_tiers() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["capability", "list", "--tier", "passive"])
        .assert()
        .success()
        .stdout(contains("command-injection").not());
}

#[test]
fn run_refuses_an_out_of_scope_target() {
    let dir = tempfile::tempdir().unwrap();
    let roe = dir.path().join("rules-of-engagement.json");
    std::fs::write(&roe, SAMPLE_ROE).unwrap();

    Command::cargo_bin("searu")
        .unwrap()
        .args([
            "run",
            "scan",
            "--roe",
            roe.to_str().unwrap(),
            "--target",
            "evil.example.org",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("OUT OF SCOPE"));
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
fn attack_show_reports_the_parent_of_a_subtechnique() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["attack", "show", "T1595.002"])
        .assert()
        .success()
        .stdout(contains("Sub-technique of: T1595"));
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
fn attack_show_rejects_an_unknown_technique() {
    Command::cargo_bin("searu")
        .unwrap()
        .args(["attack", "show", "T9999"])
        .assert()
        .failure();
}
