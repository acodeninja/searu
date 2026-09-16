//! Live tlsx run against a well-known TLS endpoint: the image builds, tlsx reads the certificate and
//! records a TLS observation. Cloudflare's `one.one.one.one:443` presents a stable `cloudflare-dns.com`
//! certificate, so the assertion is deterministic. Ignored by default: needs the Docker daemon and
//! network, and builds the tlsx image. Run with `cargo test -p searu --test tlsx_live -- --ignored`.

use assert_cmd::Command;

const ENDPOINT: &str = "one.one.one.one:443";

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "one.one.one.one", "port": 443 } ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the tlsx image"]
fn tlsx_reads_a_known_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let scan = searu(&dir)
        .args(["run", "tlsx", "--technique", "T1595", "--target", ENDPOINT])
        .output()
        .unwrap();
    let observations = searu(&dir)
        .args(["observations", "--kind", "tls"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "tlsx run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        observations.contains("cloudflare-dns.com"),
        "tlsx did not read the expected certificate for {ENDPOINT}; observations were:\n{observations}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
