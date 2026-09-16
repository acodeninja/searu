//! Live gosec run against a vulnerable Go module: the image builds, gosec scans the read-only `/src`
//! mount with the `/src/...` package pattern and records findings tagged T1593.003. Ignored by default:
//! needs the Docker daemon and builds the gosec image. Run with
//! `cargo test -p searu --test gosec_live -- --ignored`.

use assert_cmd::Command;

const GO_MOD: &str = "module vuln\n\ngo 1.21\n";
const MAIN_GO: &str =
    "package main\n\nimport \"os/exec\"\n\nfunc run(c string) error {\n\treturn exec.Command(\"sh\", \"-c\", c).Run()\n}\n\nfunc main() {}\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the gosec image"]
fn gosec_flags_a_vulnerable_go_module() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("go.mod"), GO_MOD).unwrap();
    std::fs::write(code.join("main.go"), MAIN_GO).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "gosec",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "gosec"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "gosec run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("gosec"),
        "no gosec finding recorded for the vulnerable Go module; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
