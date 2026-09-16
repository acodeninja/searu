//! Live njsscan run against a vulnerable Node.js source tree: the image builds, njsscan scans the
//! read-only `/src` mount and records a command-injection finding tagged T1593.003. Ignored by default:
//! needs the Docker daemon and builds the njsscan image. Run with
//! `cargo test -p searu --test njsscan_live -- --ignored`.

use assert_cmd::Command;

const VULN_JS: &str =
    "const child_process = require('child_process');\n\napp.get('/exec', function (req, res) {\n  child_process.exec('ls -la ' + req.query.path, function (err, out) {\n    res.send(out);\n  });\n});\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the njsscan image"]
fn njsscan_flags_vulnerable_javascript() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("app.js"), VULN_JS).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "njsscan",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "njsscan"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "njsscan run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("njsscan"),
        "no njsscan finding recorded for the vulnerable JavaScript; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
