//! Live subfinder run against a real domain: the image builds, subfinder queries its OSINT sources and
//! records subdomain observations. This is a smoke test — passive enumeration reaches third-party
//! sources, so results are not fully deterministic, but a well-known domain reliably yields subdomains.
//! Ignored by default: needs the Docker daemon and network, and builds the subfinder image. Run with
//! `cargo test -p searu --test subfinder_live -- --ignored`.

use assert_cmd::Command;

const DOMAIN: &str = "owasp.org";

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "owasp.org" } ] },
    "allowed_techniques": ["T1590"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the subfinder image"]
fn subfinder_enumerates_subdomains() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "subfinder",
            "--technique",
            "T1590",
            "--target",
            DOMAIN,
        ])
        .output()
        .unwrap();
    let observations = searu(&dir)
        .args(["observations", "--kind", "subdomain"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "subfinder run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        observations.contains(".owasp.org"),
        "no subdomain observations recorded for {DOMAIN}; observations were:\n{observations}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
