use clap::{Arg, ArgAction, ArgMatches, Command};

const DEFAULT_ROE: &str = "pentest/rules-of-engagement.json";
const ENGAGEMENT_DIR: &str = "pentest";

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
                        .arg(Arg::new("tactic").long("tactic").value_name("TAxxxx")),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show a technique by its ATT&CK ID")
                        .arg(Arg::new("technique").required(true).value_name("Txxxx")),
                ),
        )
        .subcommand(
            Command::new("run")
                .about("Run a tool against an in-scope, authorised target")
                .arg(Arg::new("tool").required(true).value_name("TOOL"))
                .arg(
                    Arg::new("technique")
                        .long("technique")
                        .required(true)
                        .value_name("Txxxx")
                        .help("The ATT&CK technique this action performs"),
                )
                .arg(
                    Arg::new("target")
                        .long("target")
                        .required(true)
                        .value_name("TARGET"),
                )
                .arg(
                    Arg::new("roe").long("roe").value_name("PATH").help(
                        "Rules-of-engagement JSON (default: pentest/rules-of-engagement.json)",
                    ),
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
            Command::new("findings")
                .about("Query recorded findings")
                .arg(Arg::new("technique").long("technique").value_name("Txxxx"))
                .arg(Arg::new("severity").long("severity").value_name("SEVERITY"))
                .arg(Arg::new("tool").long("tool").value_name("TOOL")),
        )
        .subcommand(
            Command::new("loot")
                .about("Query recorded loot")
                .arg(Arg::new("category").long("category").value_name("CATEGORY"))
                .arg(
                    Arg::new("reveal")
                        .long("reveal")
                        .action(ArgAction::SetTrue)
                        .help("Show captured values, not just fingerprints"),
                ),
        )
        .subcommand(
            Command::new("observations")
                .about("Query recorded recon observations")
                .arg(Arg::new("kind").long("kind").value_name("KIND")),
        )
        .subcommand(
            Command::new("tool")
                .about("Inspect the available tools")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list").about("List tools and the techniques they perform"),
                )
                .subcommand(
                    Command::new("advice")
                        .about("Print how Claude should drive a tool")
                        .arg(Arg::new("tool").required(true).value_name("TOOL")),
                ),
        )
}

fn main() {
    let mut cmd = cli();
    match cmd.clone().get_matches().subcommand() {
        Some(("attack", matches)) => std::process::exit(run_attack(matches)),
        Some(("run", matches)) => std::process::exit(run_action(matches)),
        Some(("findings", matches)) => std::process::exit(run_findings(matches)),
        Some(("loot", matches)) => std::process::exit(run_loot(matches)),
        Some(("observations", matches)) => std::process::exit(run_observations(matches)),
        Some(("tool", matches)) => std::process::exit(run_tool(matches)),
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

fn run_action(matches: &ArgMatches) -> i32 {
    use searu_adapter_docker::{DockerToolRunner, DockerWordlistProvider};
    use searu_adapter_store::{
        JsonRoeRepository, JsonlFindingsStore, JsonlLootStore, JsonlObservationStore,
    };
    use searu_app::{RunAction, RunError, RunReport};
    use searu_tool_registry::Registry;

    let tool = matches
        .get_one::<String>("tool")
        .expect("required argument");
    let technique = matches
        .get_one::<String>("technique")
        .expect("required argument");
    let target = matches
        .get_one::<String>("target")
        .expect("required argument");
    let roe = matches
        .get_one::<String>("roe")
        .map(String::as_str)
        .unwrap_or(DEFAULT_ROE);
    let args: Vec<String> = matches
        .get_many::<String>("args")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    let use_case = RunAction {
        roe: JsonRoeRepository::new(roe),
        registry: Registry,
        runner: DockerToolRunner::default(),
        findings: JsonlFindingsStore::new(ENGAGEMENT_DIR),
        loot: JsonlLootStore::new(ENGAGEMENT_DIR),
        observations: JsonlObservationStore::new(ENGAGEMENT_DIR),
        wordlists: DockerWordlistProvider::default(),
    };
    match use_case.run(tool, technique, target, &args) {
        Ok(RunReport::Ran {
            outcome,
            findings,
            loot,
            observations,
        }) => {
            print!("{}", outcome.stdout);
            eprint!("{}", outcome.stderr);
            eprintln!(
                "recorded {findings} finding(s), {loot} loot item(s), {observations} observation(s) in {ENGAGEMENT_DIR}/"
            );
            outcome.code
        }
        Ok(RunReport::Refused(decision)) => {
            eprintln!("REFUSED: {decision}");
            1
        }
        Err(RunError::Repo(error)) => {
            eprintln!("{error}");
            1
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_findings(matches: &ArgMatches) -> i32 {
    use searu_adapter_store::JsonlFindingsStore;
    use searu_app::QueryFindings;

    let query = QueryFindings {
        findings: JsonlFindingsStore::new(ENGAGEMENT_DIR),
    };
    let result = query.filtered(
        matches.get_one::<String>("technique").map(String::as_str),
        matches.get_one::<String>("severity").map(String::as_str),
        matches.get_one::<String>("tool").map(String::as_str),
    );
    match result {
        Ok(findings) => {
            for finding in findings {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    finding.severity.as_str(),
                    finding.status.as_str(),
                    finding.attack_technique.join(","),
                    finding.tool,
                    finding.title
                );
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_loot(matches: &ArgMatches) -> i32 {
    use searu_adapter_store::JsonlLootStore;
    use searu_app::QueryLoot;

    let query = QueryLoot {
        loot: JsonlLootStore::new(ENGAGEMENT_DIR),
    };
    let reveal = matches.get_flag("reveal");
    match query.filtered(matches.get_one::<String>("category").map(String::as_str)) {
        Ok(loot) => {
            for item in loot {
                if reveal {
                    println!("{}\t{}\t{}", item.category, item.fingerprint, item.value);
                } else {
                    println!("{}\t{}", item.category, item.fingerprint);
                }
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_observations(matches: &ArgMatches) -> i32 {
    use searu_adapter_store::JsonlObservationStore;
    use searu_app::QueryObservations;

    let query = QueryObservations {
        observations: JsonlObservationStore::new(ENGAGEMENT_DIR),
    };
    match query.filtered(matches.get_one::<String>("kind").map(String::as_str)) {
        Ok(observations) => {
            for observation in observations {
                match &observation.detail {
                    Some(detail) => {
                        println!("{}\t{}\t{}", observation.kind, observation.value, detail)
                    }
                    None => println!("{}\t{}", observation.kind, observation.value),
                }
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_tool(matches: &ArgMatches) -> i32 {
    use searu_domain::tools::ToolRegistry;
    use searu_tool_registry::Registry;

    match matches.subcommand() {
        Some(("list", _)) => {
            for tool in Registry.all() {
                println!("{}\t{}", tool.name(), tool.techniques().join(","));
            }
            0
        }
        Some(("advice", args)) => {
            let name = args.get_one::<String>("tool").expect("required argument");
            match Registry.tool(name) {
                Some(tool) => {
                    println!("{}", tool.advice());
                    0
                }
                None => {
                    eprintln!("unknown tool: {name}");
                    1
                }
            }
        }
        _ => {
            eprintln!("searu tool: unknown subcommand");
            2
        }
    }
}
