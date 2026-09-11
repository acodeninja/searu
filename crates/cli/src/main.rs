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
            Command::new("run")
                .about("Run a tool in a container against an in-scope target")
                .arg(
                    Arg::new("tool")
                        .required(true)
                        .value_name("TOOL")
                        .help("The tool to run"),
                )
                .arg(
                    Arg::new("roe")
                        .long("roe")
                        .required(true)
                        .value_name("PATH")
                        .help("Path to the rules-of-engagement JSON"),
                )
                .arg(
                    Arg::new("target")
                        .long("target")
                        .required(true)
                        .value_name("TARGET")
                        .help("The target to run against"),
                )
                .arg(
                    Arg::new("args")
                        .last(true)
                        .num_args(0..)
                        .value_name("ARG")
                        .help("Arguments passed through to the tool"),
                ),
        )
        .subcommand(
            Command::new("capability")
                .about("List the security capabilities searu can run")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List capabilities, optionally within a tier")
                        .arg(Arg::new("tier").long("tier").value_name("TIER").help(
                            "Restrict to a tier: passive, active, exploitation, destructive",
                        )),
                ),
        )
        .subcommand(
            Command::new("validate-roe").about("Validate an engagement's rules of engagement"),
        )
        .subcommand(Command::new("scope-hook").about("PreToolUse scope gate for tool commands"))
        .subcommand(
            Command::new("emit-finding").about("Append a validated finding to the findings log"),
        )
        .subcommand(Command::new("report").about("Compile findings into a client report"))
}

fn main() {
    let mut cmd = cli();
    match cmd.clone().get_matches().subcommand() {
        Some(("attack", matches)) => std::process::exit(run_attack(matches)),
        Some(("capability", matches)) => std::process::exit(run_capability(matches)),
        Some(("run", matches)) => std::process::exit(run_tool(matches)),
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

fn run_capability(matches: &ArgMatches) -> i32 {
    use searu_domain::capability;
    match matches.subcommand() {
        Some(("list", args)) => {
            let tier = args
                .get_one::<String>("tier")
                .map(|t| t.to_ascii_lowercase());
            for capability in capability::capabilities() {
                if let Some(tier) = &tier {
                    if capability.tier.to_string().to_ascii_lowercase() != *tier {
                        continue;
                    }
                }
                println!(
                    "{}\t{}\t{}\t{}",
                    capability.id,
                    capability.tier,
                    capability.attack_ids.join(","),
                    capability.tools.join(",")
                );
            }
            0
        }
        _ => {
            eprintln!("searu capability: unknown subcommand");
            2
        }
    }
}

fn run_tool(matches: &ArgMatches) -> i32 {
    use searu_adapter_docker::DockerToolRunner;
    use searu_adapter_store::JsonRoeRepository;
    use searu_app::{RunError, RunTool};

    let tool = matches
        .get_one::<String>("tool")
        .expect("required argument");
    let roe = matches.get_one::<String>("roe").expect("required argument");
    let target = matches
        .get_one::<String>("target")
        .expect("required argument");
    let args: Vec<String> = matches
        .get_many::<String>("args")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    let use_case = RunTool {
        roe: JsonRoeRepository::new(roe),
        runner: DockerToolRunner::default(),
    };
    match use_case.execute(tool, target, &args) {
        Ok(outcome) => {
            print!("{}", outcome.stdout);
            eprint!("{}", outcome.stderr);
            outcome.code
        }
        Err(RunError::OutOfScope(target)) => {
            eprintln!("OUT OF SCOPE: {target}");
            1
        }
        Err(RunError::Repo(error)) => {
            eprintln!("{error}");
            1
        }
        Err(RunError::Runner(error)) => {
            eprintln!("{error}");
            1
        }
    }
}
