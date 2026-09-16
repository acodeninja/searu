//! Live gau run against a real domain: the image builds, gau mines the web archives and records
//! endpoint observations. This is a smoke test — gau queries third-party archives, so results are not
//! fully deterministic, but a well-known domain reliably yields archived URLs. Ignored by default: needs
//! the Docker daemon and network, and builds the gau image. Run with
//! `cargo test -p searu --test gau_live -- --ignored`.

use assert_cmd::Command;

const DOMAIN: &str = "owasp.org";

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "owasp.org" } ] },
    "allowed_techniques": ["T1593"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the gau image"]
fn gau_mines_historical_urls() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let scan = searu(&dir)
        .args(["run", "gau", "--technique", "T1593", "--target", DOMAIN])
        .output()
        .unwrap();
    let observations = searu(&dir)
        .args(["observations", "--kind", "endpoint"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "gau run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        observations.contains("owasp.org"),
        "no historical-URL observations recorded for {DOMAIN}; observations were:\n{observations}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
