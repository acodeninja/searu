//! Runs a tool in a container via the Docker CLI: builds the tool's embedded Dockerfile on first use,
//! runs it with host networking so it can reach a host-published target, and captures its output.

use searu_domain::ports::{
    Mount, RunnerError, ToolInvocation, ToolOutcome, ToolRunner, WordlistError, WordlistProvider,
};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const CURL_IMAGE: &str = "curlimages/curl:8.22.0";
const SECLISTS_REF: &str = "2026.1";

pub struct DockerToolRunner {
    pub version: String,
}

impl Default for DockerToolRunner {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

pub fn image_tag(tool: &str, version: &str) -> String {
    format!("searu-{tool}:{version}")
}

/// Rewrite a host-local target so a tool *inside a container* can reach it on the host.
pub fn reachable(target: &str) -> String {
    target
        .replace("127.0.0.1", "host.docker.internal")
        .replace("localhost", "host.docker.internal")
}

pub fn docker_run_argv(image: &str, args: &[String], mounts: &[Mount]) -> Vec<String> {
    let mut argv = vec![
        "run".to_string(),
        "-i".to_string(),
        "--rm".to_string(),
        "--add-host".to_string(),
        "host.docker.internal:host-gateway".to_string(),
    ];
    for mount in mounts {
        argv.push("-v".to_string());
        argv.push(if mount.readonly {
            format!("{}:{}:ro", mount.host, mount.container)
        } else {
            format!("{}:{}", mount.host, mount.container)
        });
    }
    argv.push(image.to_string());
    argv.extend(args.iter().cloned());
    argv
}

impl DockerToolRunner {
    fn ensure_image(&self, image: &str, tool: &str, dockerfile: &str) -> Result<(), RunnerError> {
        if docker_ok(["image", "inspect", image]) {
            return Ok(());
        }
        let dir = std::env::temp_dir().join(format!("searu-build-{tool}"));
        std::fs::create_dir_all(&dir).map_err(|e| RunnerError::Launch(e.to_string()))?;
        std::fs::write(dir.join("Dockerfile"), dockerfile)
            .map_err(|e| RunnerError::Launch(e.to_string()))?;
        let built = Command::new("docker")
            .arg("build")
            .arg("-t")
            .arg(image)
            .arg(&dir)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if built {
            Ok(())
        } else {
            Err(RunnerError::Launch(format!(
                "could not build image {image}"
            )))
        }
    }
}

fn docker_ok<const N: usize>(args: [&str; N]) -> bool {
    Command::new("docker")
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

impl ToolRunner for DockerToolRunner {
    fn run(&self, invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError> {
        let image = image_tag(invocation.tool, &self.version);
        self.ensure_image(&image, invocation.tool, invocation.dockerfile)?;

        let reachable_target = reachable(invocation.target);
        let args: Vec<String> = invocation
            .args
            .iter()
            .map(|arg| {
                if arg == invocation.target {
                    reachable_target.clone()
                } else {
                    arg.clone()
                }
            })
            .collect();

        // The reachable target is fed on the tool's stdin (commix reads its target list there); a
        // tool that takes the target as an argument simply ignores the extra line.
        let mut child = Command::new("docker")
            .args(docker_run_argv(&image, &args, invocation.mounts))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| RunnerError::Launch(e.to_string()))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(format!("{reachable_target}\n").as_bytes());
        }
        let output = child
            .wait_with_output()
            .map_err(|e| RunnerError::Launch(e.to_string()))?;
        Ok(ToolOutcome {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// Fetches individual SecLists wordlists once into a shared cache, using a pinned `curl` container so
/// searu itself keeps no host-side HTTP dependency. The cache is what a tool container mounts.
pub struct DockerWordlistProvider {
    pub root: PathBuf,
    pub curl_image: String,
    pub reference: String,
}

impl Default for DockerWordlistProvider {
    fn default() -> Self {
        Self {
            root: searu_home().join("wordlists"),
            curl_image: CURL_IMAGE.to_string(),
            reference: SECLISTS_REF.to_string(),
        }
    }
}

fn searu_home() -> PathBuf {
    if let Ok(dir) = std::env::var("SEARU_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".searu")
}

impl WordlistProvider for DockerWordlistProvider {
    fn root(&self) -> String {
        self.root.to_string_lossy().into_owned()
    }

    fn ensure(&self, relative: &str) -> Result<(), WordlistError> {
        if relative
            .split(['/', '\\'])
            .any(|segment| segment == ".." || segment.is_empty())
        {
            return Err(WordlistError::Fetch(format!(
                "invalid wordlist path: {relative}"
            )));
        }
        let destination = self.root.join(relative);
        if destination.exists() {
            return Ok(());
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(|e| WordlistError::Fetch(e.to_string()))?;
        }
        let url = format!(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/{}/{relative}",
            self.reference
        );
        let output = Command::new("docker")
            .args(["run", "--rm", &self.curl_image, "-sSfL", &url])
            .output()
            .map_err(|e| WordlistError::Fetch(e.to_string()))?;
        if !output.status.success() {
            return Err(WordlistError::Fetch(format!(
                "curl failed for {url}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        if output.stdout.is_empty() {
            return Err(WordlistError::Fetch(format!("empty wordlist at {url}")));
        }
        std::fs::write(&destination, &output.stdout)
            .map_err(|e| WordlistError::Fetch(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_a_local_image_tag() {
        assert_eq!(image_tag("commix", "0.0.1"), "searu-commix:0.0.1");
    }

    #[test]
    fn rewrites_host_local_targets_for_the_container() {
        assert_eq!(
            reachable("http://localhost:5000/cmd/dig?ip_addr=1"),
            "http://host.docker.internal:5000/cmd/dig?ip_addr=1"
        );
        assert_eq!(
            reachable("http://127.0.0.1:5000/"),
            "http://host.docker.internal:5000/"
        );
    }

    #[test]
    fn run_argv_adds_the_host_gateway() {
        let argv = docker_run_argv(
            "searu-commix:0.0.1",
            &["-u".to_string(), "x".to_string()],
            &[],
        );
        assert_eq!(
            argv,
            vec![
                "run",
                "-i",
                "--rm",
                "--add-host",
                "host.docker.internal:host-gateway",
                "searu-commix:0.0.1",
                "-u",
                "x"
            ]
        );
    }

    #[test]
    fn run_argv_mounts_read_only_before_the_image() {
        let argv = docker_run_argv(
            "searu-ffuf:0.0.1",
            &["-w".to_string(), "/seclists/x.txt".to_string()],
            &[Mount {
                host: "/home/u/.searu/wordlists".to_string(),
                container: "/seclists".to_string(),
                readonly: true,
            }],
        );
        let dash_v = argv.iter().position(|a| a == "-v").unwrap();
        assert_eq!(argv[dash_v + 1], "/home/u/.searu/wordlists:/seclists:ro");
        assert!(dash_v < argv.iter().position(|a| a == "searu-ffuf:0.0.1").unwrap());
    }

    #[test]
    fn run_argv_renders_a_writable_output_mount_without_ro() {
        let argv = docker_run_argv(
            "searu-gowitness:0.0.1",
            &["scan".to_string(), "single".to_string()],
            &[Mount {
                host: "/work/pentest/outputs/gowitness/0001".to_string(),
                container: "/out".to_string(),
                readonly: false,
            }],
        );
        let dash_v = argv.iter().position(|a| a == "-v").unwrap();
        assert_eq!(
            argv[dash_v + 1],
            "/work/pentest/outputs/gowitness/0001:/out"
        );
    }

    #[test]
    fn a_wordlist_path_with_dot_dot_is_rejected() {
        let provider = DockerWordlistProvider::default();
        assert!(provider.ensure("../../etc/passwd").is_err());
        assert!(provider.ensure("Fuzzing/../../../etc/passwd").is_err());
    }
}
