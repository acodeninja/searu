//! Runs a tool image via the Docker CLI.

use searu_domain::ports::{RunnerError, ToolInvocation, ToolRunner};
use std::process::Command;

pub fn docker_argv(image: &str, args: &[String]) -> Vec<String> {
    let mut argv = vec!["run".to_string(), "--rm".to_string(), image.to_string()];
    argv.extend(args.iter().cloned());
    argv
}

pub struct DockerToolRunner {
    pub registry: String,
    pub version: String,
}

impl Default for DockerToolRunner {
    fn default() -> Self {
        let registry =
            std::env::var("SEARU_REGISTRY").unwrap_or_else(|_| "ghcr.io/searu".to_string());
        Self {
            registry,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl DockerToolRunner {
    pub fn image_for(&self, tool: &str) -> String {
        format!("{}/searu-{}:{}", self.registry, tool, self.version)
    }
}

impl ToolRunner for DockerToolRunner {
    fn run(&self, invocation: &ToolInvocation) -> Result<i32, RunnerError> {
        let image = self.image_for(invocation.tool);
        let argv = docker_argv(&image, invocation.args);
        let status = Command::new("docker")
            .args(&argv)
            .status()
            .map_err(|e| RunnerError::Launch(e.to_string()))?;
        Ok(status.code().unwrap_or(-1))
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
        };
        assert_eq!(
            runner.image_for("commix"),
            "ghcr.io/example/searu-commix:1.2.3"
        );
    }
}
