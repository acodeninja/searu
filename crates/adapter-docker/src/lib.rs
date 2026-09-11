//! Runs a tool in a container via the Docker CLI: builds the tool's embedded Dockerfile on first use,
//! runs it with host networking so it can reach a host-published target, and captures its output.

use searu_domain::ports::{RunnerError, ToolInvocation, ToolOutcome, ToolRunner};
use std::io::Write;
use std::process::{Command, Stdio};

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

pub fn docker_run_argv(image: &str, args: &[String]) -> Vec<String> {
    let mut argv = vec![
        "run".to_string(),
        "-i".to_string(),
        "--rm".to_string(),
        "--add-host".to_string(),
        "host.docker.internal:host-gateway".to_string(),
        image.to_string(),
    ];
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
            .args(docker_run_argv(&image, &args))
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
        let argv = docker_run_argv("searu-commix:0.0.1", &["-u".to_string(), "x".to_string()]);
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
}
