use assert_cmd::Command;
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
        .stdout(contains("check-scope"));
}
