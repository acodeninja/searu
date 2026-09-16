//! Live osv-scanner run against a source tree with a vulnerable dependency lockfile: the image builds,
//! osv-scanner matches it against the OSV database and records vulnerability findings tagged T1593.003.
//! Ignored by default: needs the Docker daemon and network, and builds the osv-scanner image. Run with
//! `cargo test -p searu --test osv_scanner_live -- --ignored`.

use assert_cmd::Command;

const REQUIREMENTS: &str = "requests==2.19.0\ndjango==2.2.0\npyyaml==5.1\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the osv-scanner image"]
fn osv_scanner_flags_vulnerable_dependencies() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("requirements.txt"), REQUIREMENTS).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "osv-scanner",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "osv-scanner"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "osv-scanner run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("osv-scanner"),
        "no osv-scanner finding recorded for the vulnerable dependencies; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
