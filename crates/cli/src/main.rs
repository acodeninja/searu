use clap::{Arg, ArgMatches, Command};

fn cli() -> Command {
    Command::new("searu")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Authorisation-gated pen-testing toolkit")
        .subcommand(
            Command::new("attack")
                .about("Browse the embedded MITRE ATT&CK matrix")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List techniques, optionally within a tactic")
                        .arg(
                            Arg::new("tactic")
                                .long("tactic")
                                .value_name("TAxxxx")
                                .help("Restrict the listing to one tactic"),
                        ),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show a technique by its ATT&CK ID")
                        .arg(
                            Arg::new("technique")
                                .required(true)
                                .value_name("Txxxx")
                                .help("The ATT&CK technique or sub-technique ID"),
                        ),
                ),
        )
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
        Some(("attack", matches)) => std::process::exit(run_attack(matches)),
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

fn run_attack(matches: &ArgMatches) -> i32 {
    use searu_domain::attack;
    match matches.subcommand() {
        Some(("show", args)) => {
            let id = args
                .get_one::<String>("technique")
                .expect("required argument");
            let Some(technique) = attack::technique(id) else {
                eprintln!("unknown ATT&CK technique: {id}");
                return 1;
            };
            println!("{}  {}", technique.id, technique.name);
            if let Some(parent) = technique.parent {
                let parent_name = attack::technique(parent)
                    .map(|t| t.name)
                    .unwrap_or_default();
                println!("Sub-technique of: {parent}  {parent_name}");
            }
            let tactics: Vec<String> = technique
                .tactics
                .iter()
                .map(|ta| {
                    let name = attack::tactic(ta).map(|t| t.name).unwrap_or_default();
                    format!("{ta} {name}")
                })
                .collect();
            println!("Tactics: {}", tactics.join(", "));
            0
        }
        Some(("list", args)) => {
            let techniques: Vec<&attack::AttackTechnique> = match args.get_one::<String>("tactic") {
                Some(tactic) => attack::techniques_in_tactic(tactic).collect(),
                None => attack::techniques().iter().collect(),
            };
            for technique in techniques {
                println!("{}\t{}", technique.id, technique.name);
            }
            0
        }
        _ => {
            eprintln!("searu attack: unknown subcommand");
            2
        }
    }
}
