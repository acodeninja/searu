//! Live brakeman run against a minimal vulnerable Rails app: the image builds, brakeman scans the
//! read-only `/src` mount and records a SQL-injection warning tagged T1593.003. Ignored by default:
//! needs the Docker daemon and builds the brakeman image. Run with
//! `cargo test -p searu --test brakeman_live -- --ignored`.

use assert_cmd::Command;

const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'rails'\n";
const ROUTES: &str = "Vuln::Application.routes.draw do\nend\n";
const CONTROLLER: &str =
    "class UsersController < ApplicationController\n  def show\n    User.where(\"name = '#{params[:name]}'\")\n  end\nend\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the brakeman image"]
fn brakeman_flags_a_vulnerable_rails_app() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let app = dir.path().join("code");
    std::fs::create_dir_all(app.join("app/controllers")).unwrap();
    std::fs::create_dir_all(app.join("config")).unwrap();
    std::fs::write(app.join("Gemfile"), GEMFILE).unwrap();
    std::fs::write(app.join("config/routes.rb"), ROUTES).unwrap();
    std::fs::write(app.join("app/controllers/users_controller.rb"), CONTROLLER).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "brakeman",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "brakeman"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "brakeman run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("brakeman"),
        "no brakeman finding recorded for the vulnerable Rails app; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
