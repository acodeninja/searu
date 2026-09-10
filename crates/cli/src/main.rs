use clap::Command;

fn cli() -> Command {
    Command::new("searu")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authorisation-gated pen-testing toolkit")
        .subcommand(
            Command::new("check-scope").about("Check whether a target is in scope for an ROE"),
        )
        .subcommand(
            Command::new("validate-roe").about("Validate an engagement's rules of engagement"),
        )
        .subcommand(Command::new("scope-hook").about("PreToolUse scope gate for tool commands"))
        .subcommand(
            Command::new("run").about("Run a scanner in a container against an in-scope target"),
        )
        .subcommand(
            Command::new("emit-finding").about("Append a validated finding to the findings log"),
        )
        .subcommand(Command::new("report").about("Compile findings into a client report"))
}

fn main() {
    let mut cmd = cli();
    match cmd.clone().get_matches().subcommand() {
        Some((name, _)) => {
            eprintln!("searu: '{name}' is not implemented yet");
            std::process::exit(1);
        }
        None => {
            cmd.print_help().expect("render help");
            println!();
        }
    }
}
