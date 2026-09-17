//! Live git-dumper run against a self-provisioned git-over-HTTP lab: the test generates a git repo,
//! serves its exposed `.git` over HTTP, and git-dumper reconstructs the source into the run's writable
//! output directory — recording a source-disclosure finding and leaving the recovered tree in the
//! workspace (ready for `src:` SAST). Ignored by default: needs the Docker daemon and network, and
//! builds the git-dumper image. Run with `cargo test -p searu --test git_dumper_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::path::Path;
use std::process::Command as Process;
use std::time::Duration;

const HTTP_CONTAINER: &str = "searu-githttp-it";
const HOST_PORT: u16 = 5098;

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "localhost" } ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the git-dumper image"]
fn git_dumper_reconstructs_an_exposed_repository() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();

    // Generate a git repo with a committed secret; its `.git` becomes the exposed directory.
    let init = Process::new("docker")
        .args([
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            "-v",
            &format!("{}:/r", repo.display()),
            "-w",
            "/r",
            "alpine/git",
            "-c",
            "git init -q && git config user.email a@b.c && git config user.name t && \
             printf 'SECRET=hunter2\\n' > config.py && git add -A && git commit -q -m init",
        ])
        .output()
        .expect("docker run git init");
    assert!(
        init.status.success() && repo.join(".git/HEAD").exists(),
        "failed to seed the git repo: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let _ = Process::new("docker")
        .args(["rm", "-f", HTTP_CONTAINER])
        .output();
    let serve = Process::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            HTTP_CONTAINER,
            "-v",
            &format!("{}:/srv:ro", repo.display()),
            "-w",
            "/srv",
            "-p",
            &format!("{HOST_PORT}:8000"),
            "python:3.13-slim",
            "python",
            "-m",
            "http.server",
            "8000",
        ])
        .output()
        .expect("docker run http.server");
    assert!(
        serve.status.success(),
        "failed to serve the repo: {}",
        String::from_utf8_lossy(&serve.stderr)
    );
    wait_for_port();

    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let target = format!("http://localhost:{HOST_PORT}/.git");

    let scan = searu(&dir)
        .args([
            "run",
            "git-dumper",
            "--technique",
            "T1595",
            "--target",
            &target,
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "git-dumper"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", HTTP_CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "git-dumper run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1595") && findings.contains("Source code disclosure"),
        "no source-disclosure finding recorded; findings were:\n{findings}"
    );
    // The reconstructed source file must exist in the run's output directory.
    let recovered = walk(&pentest.join("outputs"))
        .into_iter()
        .any(|p| p.file_name().map(|n| n == "config.py").unwrap_or(false));
    assert!(
        recovered,
        "git-dumper did not reconstruct config.py into the output directory"
    );
}

fn walk(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}

fn wait_for_port() {
    for _ in 0..30 {
        if TcpStream::connect(("127.0.0.1", HOST_PORT)).is_ok() {
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = Process::new("docker")
        .args(["rm", "-f", HTTP_CONTAINER])
        .output();
    panic!("the git-http lab never bound port {HOST_PORT}");
}
