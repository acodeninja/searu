//! Runs a tool image via the Docker CLI, capturing its output.

use searu_domain::ports::{RunnerError, ToolInvocation, ToolOutcome, ToolRunner};
use std::path::PathBuf;
use std::process::Command;

pub fn docker_argv(image: &str, args: &[String]) -> Vec<String> {
    let mut argv = vec!["run".to_string(), "--rm".to_string(), image.to_string()];
    argv.extend(args.iter().cloned());
    argv
}

pub struct DockerToolRunner {
    pub registry: String,
    pub version: String,
    pub images_dir: PathBuf,
}

impl Default for DockerToolRunner {
    fn default() -> Self {
        let registry =
            std::env::var("SEARU_REGISTRY").unwrap_or_else(|_| "ghcr.io/searu".to_string());
        Self {
            registry,
            version: env!("CARGO_PKG_VERSION").to_string(),
            images_dir: PathBuf::from("images"),
        }
    }
}

impl DockerToolRunner {
    pub fn image_for(&self, tool: &str) -> String {
        format!("{}/searu-{}:{}", self.registry, tool, self.version)
    }

    fn ensure_image(&self, image: &str, tool: &str) -> Result<(), RunnerError> {
        if docker_ok(["image", "inspect", image]) {
            return Ok(());
        }
        if docker_ok(["pull", image]) {
            return Ok(());
        }
        let dockerfile = self.images_dir.join(format!("{tool}.Dockerfile"));
        if !dockerfile.exists() {
            return Err(RunnerError::Launch(format!(
                "image {image} is not available and there is no {}",
                dockerfile.display()
            )));
        }
        let built = Command::new("docker")
            .arg("build")
            .arg("-t")
            .arg(image)
            .arg("-f")
            .arg(&dockerfile)
            .arg(&self.images_dir)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if built {
            Ok(())
        } else {
            Err(RunnerError::Launch(format!(
                "could not build {image} from {}",
                dockerfile.display()
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
        let image = self.image_for(invocation.tool);
        self.ensure_image(&image, invocation.tool)?;
        let argv = docker_argv(&image, invocation.args);
        let output = Command::new("docker")
            .args(&argv)
            .output()
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
    fn builds_a_disposable_run_argv() {
        let argv = docker_argv("img", &["-x".to_string(), "y".to_string()]);
        assert_eq!(argv, vec!["run", "--rm", "img", "-x", "y"]);
    }

    #[test]
    fn names_a_tool_image_under_the_registry() {
        let runner = DockerToolRunner {
            registry: "ghcr.io/example".to_string(),
            version: "1.2.3".to_string(),
            images_dir: PathBuf::from("images"),
        };
        assert_eq!(
            runner.image_for("commix"),
            "ghcr.io/example/searu-commix:1.2.3"
        );
    }
}
