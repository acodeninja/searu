use clap::{Arg, ArgAction, ArgMatches, Command};
use include_dir::{include_dir, Dir};
use std::path::Path;

const DEFAULT_ROE: &str = "pentest/rules-of-engagement.json";
const ENGAGEMENT_DIR: &str = "pentest";
static SKILL_PAYLOAD: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../skills/searu");
const UPGRADE_COMMAND: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../commands/searu-upgrade.md"
));

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
            Command::new("validate-roe")
                .about("Validate a rules-of-engagement file")
                .arg(
                    Arg::new("roe").long("roe").value_name("PATH").help(
                        "Rules-of-engagement JSON (default: pentest/rules-of-engagement.json)",
                    ),
                ),
        )
        .subcommand(
            Command::new("scope-hook")
                .about("PreToolUse allowlist backstop; reads a hook payload on stdin"),
        )
        .subcommand(
            Command::new("harden")
                .about(
                    "Deny uncontrolled network egress for this engagement (.claude/settings.json)",
                )
                .arg(
                    Arg::new("dir")
                        .long("dir")
                        .value_name("DIR")
                        .help("Engagement directory to harden (default: current directory)"),
                ),
        )
        .subcommand(
            Command::new("install-skill")
                .about("Install the /searu skill into ~/.claude/skills/searu"),
        )
        .subcommand(
            Command::new("findings")
                .about("Query recorded findings")
                .arg(Arg::new("technique").long("technique").value_name("Txxxx"))
                .arg(Arg::new("severity").long("severity").value_name("SEVERITY"))
                .arg(Arg::new("tool").long("tool").value_name("TOOL"))
                .arg(host_filter_arg()),
        )
        .subcommand(
            Command::new("loot")
                .about("Query recorded loot")
                .arg(Arg::new("category").long("category").value_name("CATEGORY"))
                .arg(host_filter_arg())
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
                .arg(Arg::new("kind").long("kind").value_name("KIND"))
                .arg(host_filter_arg()),
        )
        .subcommand(Command::new("hosts").about("List the hosts discovered across the engagement"))
        .subcommand(
            Command::new("tool")
                .about("Inspect the available tools")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("list")
                        .about("List tools; with --phase, the phase's tools and when to use each")
                        .arg(Arg::new("phase").long("phase").value_name("PHASE")),
                )
                .subcommand(
                    Command::new("advice")
                        .about("How to drive a tool: invoke, interpret, chain (per phase)")
                        .arg(Arg::new("tool").required(true).value_name("TOOL"))
                        .arg(Arg::new("phase").long("phase").value_name("PHASE")),
                ),
        )
}

fn main() {
    let mut cmd = cli();
    match cmd.clone().get_matches().subcommand() {
        Some(("attack", matches)) => std::process::exit(run_attack(matches)),
        Some(("run", matches)) => std::process::exit(run_action(matches)),
        Some(("validate-roe", matches)) => std::process::exit(run_validate_roe(matches)),
        Some(("scope-hook", _)) => std::process::exit(run_scope_hook()),
        Some(("harden", matches)) => std::process::exit(run_harden(matches)),
        Some(("install-skill", _)) => std::process::exit(run_install_skill()),
        Some(("findings", matches)) => std::process::exit(run_findings(matches)),
        Some(("loot", matches)) => std::process::exit(run_loot(matches)),
        Some(("observations", matches)) => std::process::exit(run_observations(matches)),
        Some(("hosts", _)) => std::process::exit(run_hosts()),
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
        FsOutputStore, FsSourceProvider, JsonRoeRepository, JsonlAuditLog, JsonlFindingsStore,
        JsonlLootStore, JsonlObservationStore,
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
        audit: JsonlAuditLog::new(ENGAGEMENT_DIR),
        source: FsSourceProvider::default(),
        outputs: FsOutputStore::new(ENGAGEMENT_DIR),
    };
    match use_case.run(tool, technique, target, &args) {
        Ok(RunReport::Ran {
            outcome,
            findings,
            loot,
            observations,
            outputs,
        }) => {
            print!("{}", outcome.stdout);
            eprint!("{}", outcome.stderr);
            eprintln!(
                "recorded {findings} finding(s), {loot} loot item(s), {observations} observation(s) in {ENGAGEMENT_DIR}/; raw output in {outputs}/"
            );
            outcome.code
        }
        Ok(RunReport::Refused(decision)) => {
            eprintln!("REFUSED: {decision}");
            if matches!(decision, searu_domain::gate::Decision::OutOfScope) {
                use searu_domain::ports::RoeRepository;
                if let Ok(loaded) = JsonRoeRepository::new(roe).load() {
                    if let Some(hint) = searu_domain::scope::suggest_addition(target, &loaded.scope)
                    {
                        eprintln!("hint: {hint}");
                    }
                }
            }
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

fn run_validate_roe(matches: &ArgMatches) -> i32 {
    use searu_adapter_store::JsonRoeRepository;
    use searu_app::ValidateRoe;

    let roe = matches
        .get_one::<String>("roe")
        .map(String::as_str)
        .unwrap_or(DEFAULT_ROE);
    let use_case = ValidateRoe {
        roe: JsonRoeRepository::new(roe),
    };
    match use_case.validate() {
        Err(error) => {
            eprintln!("{error}");
            1
        }
        Ok(report) if !report.is_valid() => {
            eprintln!(
                "unknown ATT&CK technique(s): {}",
                report.unknown_techniques.join(", ")
            );
            1
        }
        Ok(report) => {
            if report.targets == 0 {
                eprintln!("warning: no targets in scope; every target will be refused");
            }
            println!(
                "OK: {} target(s) in scope, {} technique(s) allowed",
                report.targets, report.allowed
            );
            0
        }
    }
}

fn run_install_skill() -> i32 {
    let Some(home) = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
    else {
        eprintln!("cannot locate the home directory (set HOME or USERPROFILE)");
        return 1;
    };
    let dest = home.join(".claude").join("skills").join("searu");

    if dest.exists() && !dest.join(".searu-owned").exists() {
        let skill = dest.join("SKILL.md");
        if skill.is_file() {
            let _ = std::fs::copy(&skill, dest.join("SKILL.md.searu-backup"));
        }
        eprintln!(
            "warning: {} is not searu-owned; leaving it untouched (backed up SKILL.md)",
            dest.display()
        );
        return 0;
    }

    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("searu"));
    let hook = format!("command: '\"{}\" scope-hook'", exe.display());

    if let Err(error) = write_skill_payload(&dest, &hook) {
        eprintln!("could not install the skill to {}: {error}", dest.display());
        return 1;
    }
    if let Err(error) = install_upgrade_command(&home) {
        eprintln!("could not install the /searu-upgrade command: {error}");
        return 1;
    }
    println!("installed the /searu skill to {}", dest.display());
    0
}

fn install_upgrade_command(home: &Path) -> std::io::Result<()> {
    let dir = home.join(".claude").join("commands");
    let dest = dir.join("searu-upgrade.md");
    if dest.exists()
        && !std::fs::read_to_string(&dest)
            .unwrap_or_default()
            .contains("searu-owned")
    {
        std::fs::copy(&dest, dir.join("searu-upgrade.md.searu-backup"))?;
        eprintln!(
            "warning: {} is not searu-owned; leaving it untouched (backed up)",
            dest.display()
        );
        return Ok(());
    }
    std::fs::create_dir_all(&dir)?;
    std::fs::write(&dest, UPGRADE_COMMAND)
}

fn write_skill_payload(dest: &Path, hook: &str) -> std::io::Result<()> {
    if dest.exists() {
        std::fs::remove_dir_all(dest)?;
    }
    std::fs::create_dir_all(dest)?;
    write_skill_dir(&SKILL_PAYLOAD, dest, hook)?;
    std::fs::write(
        dest.join(".searu-owned"),
        b"installed by: searu install-skill\n",
    )
}

fn write_skill_dir(dir: &Dir, dest: &Path, hook: &str) -> std::io::Result<()> {
    for file in dir.files() {
        let out = dest.join(file.path());
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if file.path() == Path::new("SKILL.md") {
            let template = file.contents_utf8().expect("SKILL.md is UTF-8");
            std::fs::write(
                &out,
                template.replace(r#"command: "searu scope-hook""#, hook),
            )?;
        } else {
            std::fs::write(&out, file.contents())?;
        }
    }
    for sub in dir.dirs() {
        write_skill_dir(sub, dest, hook)?;
    }
    Ok(())
}

fn run_scope_hook() -> i32 {
    use searu_domain::scope_hook::{decide, HookDecision};
    use std::io::Read;

    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        return 0;
    }
    let payload: serde_json::Value =
        serde_json::from_str(&input).unwrap_or(serde_json::Value::Null);
    let tool_name = payload
        .get("tool_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let command = payload
        .get("tool_input")
        .and_then(|tool_input| tool_input.get("command"))
        .and_then(serde_json::Value::as_str);
    match decide(tool_name, command) {
        HookDecision::Allow => {
            println!(
                r#"{{"hookSpecificOutput":{{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"searu: sanctioned local or scoped action"}}}}"#
            );
            0
        }
        HookDecision::Block(reason) => {
            eprintln!("{reason}");
            2
        }
    }
}

fn run_harden(matches: &ArgMatches) -> i32 {
    use searu_adapter_store::FileProjectSettings;
    use searu_app::HardenProject;

    let dir = matches
        .get_one::<String>("dir")
        .map(String::as_str)
        .unwrap_or(".");
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("searu"));
    let hook_command = format!("\"{}\" scope-hook", exe.display());
    let use_case = HardenProject {
        settings: FileProjectSettings::new(dir),
        hook_command,
    };
    match use_case.harden() {
        Ok(report) => {
            println!(
                "egress guard: {} added, {} denied plus the scope-hook in {dir}/.claude/settings.json",
                report.added, report.total
            );
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn host_filter_arg() -> Arg {
    Arg::new("host")
        .long("host")
        .value_name("ADDRESS")
        .help("Only records bound to this host (by address or hostname)")
}

fn host_id_filter(matches: &ArgMatches) -> Option<String> {
    matches
        .get_one::<String>("host")
        .map(|value| searu_domain::assets::host_id_for(value))
}

fn run_findings(matches: &ArgMatches) -> i32 {
    use searu_adapter_store::JsonlFindingsStore;
    use searu_app::QueryFindings;

    let query = QueryFindings {
        findings: JsonlFindingsStore::new(ENGAGEMENT_DIR),
    };
    let host = host_id_filter(matches);
    let result = query.filtered(
        matches.get_one::<String>("technique").map(String::as_str),
        matches.get_one::<String>("severity").map(String::as_str),
        matches.get_one::<String>("tool").map(String::as_str),
        host.as_deref(),
    );
    match result {
        Ok(findings) => {
            for stored in findings {
                let finding = &stored.finding;
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
    let host = host_id_filter(matches);
    match query.filtered(
        matches.get_one::<String>("category").map(String::as_str),
        host.as_deref(),
    ) {
        Ok(loot) => {
            for stored in loot {
                let item = &stored.loot;
                let subject = match (&item.principal, &item.authenticates) {
                    (Some(principal), Some(authenticates)) => {
                        format!("\t{principal}@{authenticates}")
                    }
                    (Some(principal), None) => format!("\t{principal}"),
                    _ => String::new(),
                };
                if reveal {
                    println!(
                        "{}\t{}\t{}{subject}",
                        item.category, item.fingerprint, item.value
                    );
                } else {
                    println!("{}\t{}{subject}", item.category, item.fingerprint);
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
    let host = host_id_filter(matches);
    match query.filtered(
        matches.get_one::<String>("kind").map(String::as_str),
        host.as_deref(),
    ) {
        Ok(observations) => {
            for stored in observations {
                let observation = &stored.observation;
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

fn run_hosts() -> i32 {
    use searu_adapter_store::{JsonlFindingsStore, JsonlLootStore, JsonlObservationStore};
    use searu_app::QueryHosts;

    let query = QueryHosts {
        findings: JsonlFindingsStore::new(ENGAGEMENT_DIR),
        loot: JsonlLootStore::new(ENGAGEMENT_DIR),
        observations: JsonlObservationStore::new(ENGAGEMENT_DIR),
    };
    match query.list() {
        Ok(hosts) => {
            for host in hosts {
                let status = match host.status {
                    searu_domain::assets::HostStatus::InScope => "in-scope",
                    searu_domain::assets::HostStatus::Candidate => "candidate",
                };
                let addresses = host
                    .addresses
                    .iter()
                    .map(|address| format!("{}@{}", address.value, address.network))
                    .collect::<Vec<_>>()
                    .join(",");
                let services = host
                    .services
                    .iter()
                    .map(|service| service.label())
                    .collect::<Vec<_>>()
                    .join(",");
                let claims = host
                    .claims
                    .iter()
                    .map(|claim| format!("{}:{}", claim.kind.as_str(), claim.value))
                    .collect::<Vec<_>>()
                    .join(",");
                println!("{}\t{status}\t{addresses}\t{services}\t{claims}", host.id);
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
    use searu_domain::tools::{Phase, ToolRegistry};
    use searu_tool_registry::Registry;

    match matches.subcommand() {
        Some(("list", args)) => match args.get_one::<String>("phase") {
            None => {
                for tool in Registry.all() {
                    let phases: Vec<&str> =
                        tool.uses().iter().map(|entry| entry.phase.id()).collect();
                    println!(
                        "{}\t{}\t{}",
                        tool.name(),
                        tool.techniques().join(","),
                        phases.join(",")
                    );
                }
                0
            }
            Some(name) => {
                let Some(phase) = Phase::parse(name) else {
                    eprintln!("unknown phase: {name}");
                    eprintln!("valid phases: {}", valid_phases());
                    return 2;
                };
                for tool in Registry.all() {
                    if let Some(entry) = tool.uses().iter().find(|entry| entry.phase == phase) {
                        println!("{}\t{}", tool.name(), entry.when);
                    }
                }
                0
            }
        },
        Some(("advice", args)) => {
            let name = args.get_one::<String>("tool").expect("required argument");
            let Some(tool) = Registry.tool(name) else {
                eprintln!("unknown tool: {name}");
                return 1;
            };
            let phase = match args.get_one::<String>("phase") {
                None => None,
                Some(id) => match Phase::parse(id) {
                    Some(phase) => Some(phase),
                    None => {
                        eprintln!("unknown phase: {id}");
                        eprintln!("valid phases: {}", valid_phases());
                        return 2;
                    }
                },
            };
            let mut printed = false;
            for entry in tool.uses() {
                if phase.is_some_and(|wanted| wanted != entry.phase) {
                    continue;
                }
                if printed {
                    println!();
                }
                println!("{} — {}", tool.name(), entry.phase);
                println!("  when:      {}", entry.when);
                println!("  invoke:    {}", entry.invoke);
                println!("  interpret: {}", entry.interpret);
                println!("  chain:     {}", entry.chain);
                printed = true;
            }
            if !printed {
                eprintln!("{name} has no advice for that phase");
                return 1;
            }
            0
        }
        _ => {
            eprintln!("searu tool: unknown subcommand");
            2
        }
    }
}

fn valid_phases() -> String {
    searu_domain::tools::Phase::ALL
        .iter()
        .map(|phase| phase.id())
        .collect::<Vec<_>>()
        .join(", ")
}
