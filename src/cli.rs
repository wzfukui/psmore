use crate::model::{HotspotMetric, HotspotScope};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchMode {
    Tui,
    Table,
    Json,
    CheckTable,
    CheckJson,
    InspectTable,
    InspectJson,
    MemoryTable,
    MemoryJson,
    ExeTable,
    ExeJson,
    StaleTable,
    StaleJson,
    ServiceTable,
    ServiceJson,
    LogsTable,
    LogsJson,
    ExplainTable,
    ExplainJson,
    PortTable,
    PortJson,
    ListenTable,
    ListenJson,
    TreeTable,
    TreeJson,
    WatchTable,
    WatchJsonl,
    TraceTable,
    TraceJsonl,
    RunTable,
    RunJson,
    CgroupTable,
    CgroupJson,
    DeletedTable,
    DeletedJson,
    FileTable,
    FileJson,
    FdTable,
    FdJson,
    TopTable,
    TopJson,
    OomTable,
    OomJson,
    NetTable,
    NetJson,
    DoctorTable,
    DoctorJson,
    DiffTable,
    DiffJson,
    Completion,
    Help,
    Version,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HelpTopic {
    Check,
    Inspect,
    Memory,
    Exe,
    Stale,
    Service,
    Logs,
    Explain,
    Port,
    Listen,
    Tree,
    Watch,
    Trace,
    Run,
    Cgroup,
    Deleted,
    File,
    Fd,
    Top,
    Oom,
    Net,
    Doctor,
    Diff,
    Completion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
}

#[cfg(test)]
impl CompletionShell {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum PortProtocol {
    #[default]
    Any,
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ListenProtocol {
    #[default]
    Any,
    Tcp,
    Udp,
    Unix,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum LogScope {
    #[default]
    Auto,
    Process,
    Service,
}

impl LogScope {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Process => "process",
            Self::Service => "service",
        }
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Auto => Self::Process,
            Self::Process => Self::Service,
            Self::Service => Self::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum LogPriority {
    Error,
    Warning,
    #[default]
    Info,
    Debug,
}

impl LogPriority {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Error => Self::Warning,
            Self::Warning => Self::Info,
            Self::Info => Self::Debug,
            Self::Debug => Self::Error,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn syslog_max(self) -> u8 {
        match self {
            Self::Error => 3,
            Self::Warning => 4,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn includes_macos(self, priority: &str) -> bool {
        let rank = match priority.to_ascii_lowercase().as_str() {
            "fault" => 0,
            "error" => 1,
            "default" => 2,
            "info" => 3,
            "debug" => 4,
            _ => 2,
        };
        let maximum = match self {
            Self::Error => 1,
            Self::Warning => 2,
            Self::Info => 3,
            Self::Debug => 4,
        };
        rank <= maximum
    }
}

impl ListenProtocol {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Unix => "unix",
        }
    }
}

impl PortProtocol {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum CheckExpectation {
    #[default]
    None,
    Any,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum CgroupSort {
    Cpu,
    #[default]
    Memory,
    Pressure,
    Processes,
}

impl CgroupSort {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Pressure => "pressure",
            Self::Processes => "processes",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DoctorFailOn {
    #[default]
    Never,
    Warning,
    Critical,
}

impl DoctorFailOn {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DiffFailOn {
    #[default]
    Never,
    Regression,
}

impl DiffFailOn {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Regression => "regression",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiffPolicyStatus {
    Passed,
    Violated,
}

impl DiffPolicyStatus {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Passed => "pass",
            Self::Violated => "fail",
        }
    }

    pub(crate) fn passed(self) -> bool {
        self == Self::Passed
    }
}

impl CheckExpectation {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::None => "no matches",
            Self::Any => "at least one match",
        }
    }

    pub(crate) fn passes(self, matched: usize) -> bool {
        match self {
            Self::None => matched == 0,
            Self::Any => matched > 0,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Cli {
    pub(crate) mode: LaunchMode,
    pub(crate) help_topic: Option<HelpTopic>,
    pub(crate) completion_shell: Option<CompletionShell>,
    pub(crate) query: String,
    pub(crate) tui_no_tips: bool,
    pub(crate) sample_ms: u64,
    pub(crate) diff_paths: Option<(String, String)>,
    pub(crate) diff_fail_on: DiffFailOn,
    pub(crate) diff_output: Option<String>,
    pub(crate) diff_force: bool,
    pub(crate) inspect_pid: Option<u32>,
    pub(crate) memory_pid: Option<u32>,
    pub(crate) memory_limit: Option<usize>,
    pub(crate) exe_pid: Option<u32>,
    pub(crate) exe_hash: bool,
    pub(crate) stale_limit: Option<usize>,
    pub(crate) stale_expectation: Option<CheckExpectation>,
    pub(crate) service_pid: Option<u32>,
    pub(crate) logs_pid: Option<u32>,
    pub(crate) logs_scope: LogScope,
    pub(crate) logs_priority: LogPriority,
    pub(crate) logs_since_seconds: u64,
    pub(crate) logs_limit: usize,
    pub(crate) explain_pid: Option<u32>,
    pub(crate) explain_include_logs: bool,
    pub(crate) explain_output: Option<String>,
    pub(crate) explain_force: bool,
    pub(crate) port: Option<u16>,
    pub(crate) port_protocol: PortProtocol,
    pub(crate) port_all: bool,
    pub(crate) port_expectation: Option<CheckExpectation>,
    pub(crate) listen_protocol: ListenProtocol,
    pub(crate) listen_exposed: bool,
    pub(crate) listen_limit: Option<usize>,
    pub(crate) listen_expectation: Option<CheckExpectation>,
    pub(crate) tree_pid: Option<u32>,
    pub(crate) tree_depth: Option<usize>,
    pub(crate) watch_interval_ms: u64,
    pub(crate) watch_count: Option<usize>,
    pub(crate) trace_pid: Option<u32>,
    pub(crate) trace_interval_ms: u64,
    pub(crate) trace_count: Option<usize>,
    pub(crate) run_command: Vec<String>,
    pub(crate) run_interval_ms: u64,
    pub(crate) run_descendant_grace_ms: u64,
    pub(crate) run_output: Option<String>,
    pub(crate) run_force: bool,
    pub(crate) cgroup_sort: CgroupSort,
    pub(crate) cgroup_limit: Option<usize>,
    pub(crate) deleted_min_size: u64,
    pub(crate) deleted_expectation: Option<CheckExpectation>,
    pub(crate) file_path: Option<String>,
    pub(crate) file_recursive: bool,
    pub(crate) file_limit: Option<usize>,
    pub(crate) file_expectation: Option<CheckExpectation>,
    pub(crate) fd_min_count: usize,
    pub(crate) fd_min_percent: Option<u16>,
    pub(crate) fd_limit: Option<usize>,
    pub(crate) fd_expectation: Option<CheckExpectation>,
    pub(crate) top_metric: HotspotMetric,
    pub(crate) top_scope: HotspotScope,
    pub(crate) top_limit: Option<usize>,
    pub(crate) oom_min_score: u16,
    pub(crate) oom_limit: Option<usize>,
    pub(crate) oom_expectation: Option<CheckExpectation>,
    pub(crate) net_protocol: ListenProtocol,
    pub(crate) net_connected_only: bool,
    pub(crate) net_state: Option<String>,
    pub(crate) net_limit: Option<usize>,
    pub(crate) net_expectation: Option<CheckExpectation>,
    pub(crate) doctor_limit: Option<usize>,
    pub(crate) doctor_fail_on: DoctorFailOn,
    pub(crate) doctor_deep: bool,
    pub(crate) doctor_output: Option<String>,
    pub(crate) doctor_force: bool,
    pub(crate) redact_secrets: bool,
    pub(crate) check_expectation: CheckExpectation,
    pub(crate) check_wait_ms: Option<u64>,
    pub(crate) check_interval_ms: u64,
    pub(crate) check_stable_samples: usize,
    pub(crate) quiet: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            mode: LaunchMode::Tui,
            help_topic: None,
            completion_shell: None,
            query: String::new(),
            tui_no_tips: false,
            sample_ms: 500,
            diff_paths: None,
            diff_fail_on: DiffFailOn::Never,
            diff_output: None,
            diff_force: false,
            inspect_pid: None,
            memory_pid: None,
            memory_limit: Some(20),
            exe_pid: None,
            exe_hash: true,
            stale_limit: Some(100),
            stale_expectation: None,
            service_pid: None,
            logs_pid: None,
            logs_scope: LogScope::Auto,
            logs_priority: LogPriority::Info,
            logs_since_seconds: 15 * 60,
            logs_limit: 100,
            explain_pid: None,
            explain_include_logs: true,
            explain_output: None,
            explain_force: false,
            port: None,
            port_protocol: PortProtocol::Any,
            port_all: false,
            port_expectation: None,
            listen_protocol: ListenProtocol::Any,
            listen_exposed: false,
            listen_limit: Some(100),
            listen_expectation: None,
            tree_pid: None,
            tree_depth: None,
            watch_interval_ms: 1_000,
            watch_count: None,
            trace_pid: None,
            trace_interval_ms: 1_000,
            trace_count: None,
            run_command: Vec::new(),
            run_interval_ms: 100,
            run_descendant_grace_ms: 1_000,
            run_output: None,
            run_force: false,
            cgroup_sort: CgroupSort::Memory,
            cgroup_limit: Some(20),
            deleted_min_size: 0,
            deleted_expectation: None,
            file_path: None,
            file_recursive: false,
            file_limit: Some(100),
            file_expectation: None,
            fd_min_count: 1,
            fd_min_percent: None,
            fd_limit: Some(20),
            fd_expectation: None,
            top_metric: HotspotMetric::Cpu,
            top_scope: HotspotScope::Process,
            top_limit: Some(20),
            oom_min_score: 1,
            oom_limit: Some(20),
            oom_expectation: None,
            net_protocol: ListenProtocol::Any,
            net_connected_only: false,
            net_state: None,
            net_limit: Some(100),
            net_expectation: None,
            doctor_limit: Some(5),
            doctor_fail_on: DoctorFailOn::Never,
            doctor_deep: false,
            doctor_output: None,
            doctor_force: false,
            redact_secrets: false,
            check_expectation: CheckExpectation::None,
            check_wait_ms: None,
            check_interval_ms: 1_000,
            check_stable_samples: 1,
            quiet: false,
        }
    }
}

impl Cli {
    pub(crate) fn parse<I, S>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut arguments: Vec<String> = args.into_iter().map(Into::into).collect();
        let redact_secrets = extract_secret_redaction(&mut arguments)?;
        if let Some(command) = arguments.first().map(String::as_str) {
            let parsed = match command {
                "watch" => Some((parse_watch(&arguments[1..]), HelpTopic::Watch)),
                "trace" => Some((parse_trace(&arguments[1..]), HelpTopic::Trace)),
                "run" => Some((parse_run(&arguments[1..]), HelpTopic::Run)),
                "cgroup" => Some((parse_cgroup(&arguments[1..]), HelpTopic::Cgroup)),
                "deleted" => Some((parse_deleted(&arguments[1..]), HelpTopic::Deleted)),
                "file" => Some((parse_file(&arguments[1..]), HelpTopic::File)),
                "fd" => Some((parse_fd(&arguments[1..]), HelpTopic::Fd)),
                "top" => Some((parse_top(&arguments[1..]), HelpTopic::Top)),
                "oom" => Some((parse_oom(&arguments[1..]), HelpTopic::Oom)),
                "net" => Some((parse_net(&arguments[1..]), HelpTopic::Net)),
                "doctor" => Some((parse_doctor(&arguments[1..]), HelpTopic::Doctor)),
                "check" => Some((parse_check(&arguments[1..]), HelpTopic::Check)),
                "listen" => Some((parse_listen(&arguments[1..]), HelpTopic::Listen)),
                "inspect" => Some((parse_inspect(&arguments[1..]), HelpTopic::Inspect)),
                "memory" => Some((parse_memory(&arguments[1..]), HelpTopic::Memory)),
                "exe" => Some((parse_exe(&arguments[1..]), HelpTopic::Exe)),
                "stale" => Some((parse_stale(&arguments[1..]), HelpTopic::Stale)),
                "service" => Some((parse_service(&arguments[1..]), HelpTopic::Service)),
                "logs" => Some((parse_logs(&arguments[1..]), HelpTopic::Logs)),
                "explain" => Some((parse_explain(&arguments[1..]), HelpTopic::Explain)),
                "port" => Some((parse_port(&arguments[1..]), HelpTopic::Port)),
                "tree" => Some((parse_tree(&arguments[1..]), HelpTopic::Tree)),
                "diff" => Some((parse_diff(&arguments[1..]), HelpTopic::Diff)),
                "completion" => Some((parse_completion(&arguments[1..]), HelpTopic::Completion)),
                _ => None,
            };
            if let Some((parsed, topic)) = parsed {
                return with_help_topic(parsed, topic)
                    .and_then(|cli| apply_secret_redaction(cli, redact_secrets));
            }
        }
        let mut cli = Self::default();
        let mut args = arguments.into_iter().peekable();
        let mut query_set = false;
        let mut sample_set = false;

        while let Some(argument) = args.next() {
            match argument.as_str() {
                "-h" | "--help" => cli.mode = LaunchMode::Help,
                "-V" | "--version" => cli.mode = LaunchMode::Version,
                "--table" => set_output_mode(&mut cli, LaunchMode::Table)?,
                "--json" => set_output_mode(&mut cli, LaunchMode::Json)?,
                "--no-tips" | "--no-onboarding" => {
                    if cli.tui_no_tips {
                        return Err("--no-tips may only be specified once".into());
                    }
                    cli.tui_no_tips = true;
                }
                "-q" | "--query" => {
                    let value = args
                        .next()
                        .ok_or_else(|| format!("{argument} requires a value"))?;
                    set_query(&mut cli, &mut query_set, value)?;
                }
                "--sample-ms" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                    set_sample_ms(&mut cli, &mut sample_set, &value)?;
                }
                _ if argument.starts_with("--query=") => {
                    let value = argument.trim_start_matches("--query=").to_string();
                    set_query(&mut cli, &mut query_set, value)?;
                }
                _ if argument.starts_with("--sample-ms=") => {
                    let value = argument.trim_start_matches("--sample-ms=");
                    set_sample_ms(&mut cli, &mut sample_set, value)?;
                }
                _ if argument.starts_with('-') => {
                    return Err(format!("unknown option: {argument}"));
                }
                _ => {
                    return Err(format!(
                        "unexpected argument: {argument}; use --query to pass a query"
                    ));
                }
            }
        }

        if sample_set && cli.mode == LaunchMode::Tui {
            return Err("--sample-ms requires --table or --json".into());
        }
        if cli.tui_no_tips
            && !matches!(
                cli.mode,
                LaunchMode::Tui | LaunchMode::Help | LaunchMode::Version
            )
        {
            return Err("--no-tips only applies to the interactive TUI".into());
        }
        apply_secret_redaction(cli, redact_secrets)
    }
}

fn extract_secret_redaction(arguments: &mut Vec<String>) -> Result<bool, String> {
    const VALUE_OPTIONS: [&str; 23] = [
        "-q",
        "--query",
        "--sample-ms",
        "--expect",
        "--protocol",
        "--limit",
        "--min-count",
        "--min-percent",
        "--min-size",
        "--interval-ms",
        "--count",
        "--depth",
        "--by",
        "--scope",
        "--min-score",
        "--state",
        "--output",
        "--fail-on",
        "--wait",
        "--stable",
        "--since",
        "--priority",
        "--scope",
    ];
    let mut enabled = false;
    let mut expects_value = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if argument == "--" {
            break;
        }
        if expects_value {
            expects_value = false;
            index += 1;
            continue;
        }
        if matches!(argument, "--redact" | "--redact-secrets") {
            if enabled {
                return Err("--redact may only be specified once".into());
            }
            arguments.remove(index);
            enabled = true;
            continue;
        }
        expects_value = VALUE_OPTIONS.contains(&argument);
        index += 1;
    }
    Ok(enabled)
}

fn apply_secret_redaction(mut cli: Cli, enabled: bool) -> Result<Cli, String> {
    if enabled && cli.mode == LaunchMode::Tui {
        return Err("--redact requires a non-interactive command or --table/--json".into());
    }
    cli.redact_secrets = enabled;
    Ok(cli)
}

fn with_help_topic(result: Result<Cli, String>, topic: HelpTopic) -> Result<Cli, String> {
    result.map(|mut cli| {
        if cli.mode == LaunchMode::Help {
            cli.help_topic = Some(topic);
        }
        cli
    })
}

fn parse_completion(arguments: &[String]) -> Result<Cli, String> {
    let mut mode = LaunchMode::Completion;
    let mut shells = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => mode = LaunchMode::Help,
            "-V" | "--version" => mode = LaunchMode::Version,
            _ if argument.starts_with('-') => {
                return Err(format!("unknown completion option: {argument}"));
            }
            _ => shells.push(argument),
        }
    }
    if matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(Cli {
            mode,
            ..Cli::default()
        });
    }
    if shells.len() != 1 {
        return Err(format!(
            "completion requires exactly one shell: bash, zsh, or fish; received {}",
            shells.len()
        ));
    }
    let completion_shell = match shells[0].to_ascii_lowercase().as_str() {
        "bash" => CompletionShell::Bash,
        "zsh" => CompletionShell::Zsh,
        "fish" => CompletionShell::Fish,
        value => {
            return Err(format!(
                "unsupported completion shell: {value}; use bash, zsh, or fish"
            ));
        }
    };
    Ok(Cli {
        mode,
        completion_shell: Some(completion_shell),
        ..Cli::default()
    })
}

fn parse_doctor(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::DoctorTable,
        ..Cli::default()
    };
    let mut output_mode = false;
    let mut query_set = false;
    let mut sample_set = false;
    let mut limit_set = false;
    let mut fail_on_set = false;
    let mut output_path_set = false;
    let mut positional_query = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_doctor_output(&mut cli.mode, &mut output_mode, LaunchMode::DoctorTable)?
            }
            "--json" => set_doctor_output(&mut cli.mode, &mut output_mode, LaunchMode::DoctorJson)?,
            "--quiet" => cli.quiet = true,
            "--deep" => cli.doctor_deep = true,
            "--force" => cli.doctor_force = true,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_doctor_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--fail-on" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--fail-on requires never, warning, or critical".to_string())?;
                set_doctor_fail_on(&mut cli, &mut fail_on_set, &value)?;
            }
            "--output" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--output requires a file path".to_string())?;
                set_doctor_output_path(&mut cli, &mut output_path_set, value)?;
            }
            _ if argument.starts_with("--query=") => {
                set_query(
                    &mut cli,
                    &mut query_set,
                    argument.trim_start_matches("--query=").to_string(),
                )?;
            }
            _ if argument.starts_with("--sample-ms=") => {
                set_sample_ms(
                    &mut cli,
                    &mut sample_set,
                    argument.trim_start_matches("--sample-ms="),
                )?;
            }
            _ if argument.starts_with("--limit=") => {
                set_doctor_limit(
                    &mut cli,
                    &mut limit_set,
                    argument.trim_start_matches("--limit="),
                )?;
            }
            _ if argument.starts_with("--fail-on=") => {
                set_doctor_fail_on(
                    &mut cli,
                    &mut fail_on_set,
                    argument.trim_start_matches("--fail-on="),
                )?;
            }
            _ if argument.starts_with("--output=") => {
                set_doctor_output_path(
                    &mut cli,
                    &mut output_path_set,
                    argument.trim_start_matches("--output=").to_string(),
                )?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown doctor option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if !positional_query.is_empty() {
        if query_set {
            return Err("doctor query may be positional or passed with --query, not both".into());
        }
        cli.query = positional_query.join(" ");
    }
    if cli.doctor_output.is_some() {
        if output_mode && cli.mode == LaunchMode::DoctorTable {
            return Err("doctor --output writes JSON and cannot be combined with --table".into());
        }
        cli.mode = LaunchMode::DoctorJson;
    }
    if cli.doctor_force && cli.doctor_output.is_none() {
        return Err("doctor --force requires --output FILE".into());
    }
    if cli.quiet && cli.doctor_fail_on == DoctorFailOn::Never && cli.doctor_output.is_none() {
        return Err("doctor --quiet requires --fail-on warning or --fail-on critical".into());
    }
    Ok(cli)
}

fn set_doctor_output_path(
    cli: &mut Cli,
    value_set: &mut bool,
    value: String,
) -> Result<(), String> {
    if *value_set {
        return Err("doctor --output may only be specified once".into());
    }
    if value.is_empty() || value == "-" {
        return Err("doctor --output requires a file path; use --json for stdout".into());
    }
    cli.doctor_output = Some(value);
    *value_set = true;
    Ok(())
}

fn set_doctor_output(
    mode: &mut LaunchMode,
    output_set: &mut bool,
    value: LaunchMode,
) -> Result<(), String> {
    if *output_set {
        return Err("doctor --table and --json cannot be used together or repeated".into());
    }
    *mode = value;
    *output_set = true;
    Ok(())
}

fn set_doctor_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("doctor --limit may only be specified once".into());
    }
    cli.doctor_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid doctor --limit value: {value}"))?;
        if limit == 0 {
            return Err("doctor --limit must be positive or all".into());
        }
        if limit > 10_000 {
            return Err("doctor --limit must be at most 10000 or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_doctor_fail_on(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("doctor --fail-on may only be specified once".into());
    }
    cli.doctor_fail_on = match value.to_ascii_lowercase().as_str() {
        "never" | "none" => DoctorFailOn::Never,
        "warning" | "warn" => DoctorFailOn::Warning,
        "critical" | "crit" => DoctorFailOn::Critical,
        _ => {
            return Err(format!(
                "invalid doctor --fail-on value: {value}; use never, warning, or critical"
            ));
        }
    };
    *value_set = true;
    Ok(())
}

fn parse_top(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::TopTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut query_set = false;
    let mut sample_set = false;
    let mut metric_set = false;
    let mut scope_set = false;
    let mut limit_set = false;
    let mut positional_query = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_top_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::TopTable)?
            }
            "--json" => set_top_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::TopJson)?,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--by" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--by requires cpu, memory, read, or write".to_string())?;
                set_top_metric(&mut cli, &mut metric_set, &value)?;
            }
            "--scope" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--scope requires process or tree".to_string())?;
                set_top_scope(&mut cli, &mut scope_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_top_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            _ if argument.starts_with("--query=") => {
                let value = argument.trim_start_matches("--query=").to_string();
                set_query(&mut cli, &mut query_set, value)?;
            }
            _ if argument.starts_with("--by=") => {
                set_top_metric(
                    &mut cli,
                    &mut metric_set,
                    argument.trim_start_matches("--by="),
                )?;
            }
            _ if argument.starts_with("--scope=") => {
                set_top_scope(
                    &mut cli,
                    &mut scope_set,
                    argument.trim_start_matches("--scope="),
                )?;
            }
            _ if argument.starts_with("--limit=") => {
                set_top_limit(
                    &mut cli,
                    &mut limit_set,
                    argument.trim_start_matches("--limit="),
                )?;
            }
            _ if argument.starts_with("--sample-ms=") => {
                set_sample_ms(
                    &mut cli,
                    &mut sample_set,
                    argument.trim_start_matches("--sample-ms="),
                )?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown top option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if !positional_query.is_empty() {
        if query_set {
            return Err("top query may be positional or passed with --query, not both".into());
        }
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    Ok(cli)
}

fn set_top_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    value: LaunchMode,
) -> Result<(), String> {
    if output_mode.replace(value).is_some() {
        return Err("top output mode may only be specified once".into());
    }
    *mode = value;
    Ok(())
}

fn set_top_metric(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--by may only be specified once".into());
    }
    cli.top_metric = match value.to_ascii_lowercase().as_str() {
        "cpu" => HotspotMetric::Cpu,
        "memory" | "mem" => HotspotMetric::Memory,
        "read" | "read-rate" => HotspotMetric::Read,
        "write" | "write-rate" => HotspotMetric::Write,
        _ => return Err("--by requires cpu, memory, read, or write".into()),
    };
    *value_set = true;
    Ok(())
}

fn set_top_scope(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--scope may only be specified once".into());
    }
    cli.top_scope = match value.to_ascii_lowercase().as_str() {
        "process" | "self" | "own" => HotspotScope::Process,
        "tree" | "subtree" | "service" => HotspotScope::Subtree,
        _ => return Err("--scope requires process or tree".into()),
    };
    *value_set = true;
    Ok(())
}

fn set_top_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--limit may only be specified once".into());
    }
    cli.top_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| "--limit requires a positive integer or all".to_string())?;
        if !(1..=10_000).contains(&limit) {
            return Err("--limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn parse_oom(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::OomTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut query_set = false;
    let mut sample_set = false;
    let mut min_score_set = false;
    let mut limit_set = false;
    let mut expectation_set = false;
    let mut positional_query = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_oom_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::OomTable)?
            }
            "--json" => set_oom_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::OomJson)?,
            "--quiet" => cli.quiet = true,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--min-score" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--min-score requires an integer from 0 to 1000".to_string())?;
                set_oom_min_score(&mut cli, &mut min_score_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_oom_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_oom_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            _ if argument.starts_with("--query=") => {
                set_query(
                    &mut cli,
                    &mut query_set,
                    argument.trim_start_matches("--query=").to_string(),
                )?;
            }
            _ if argument.starts_with("--min-score=") => {
                set_oom_min_score(
                    &mut cli,
                    &mut min_score_set,
                    argument.trim_start_matches("--min-score="),
                )?;
            }
            _ if argument.starts_with("--limit=") => {
                set_oom_limit(
                    &mut cli,
                    &mut limit_set,
                    argument.trim_start_matches("--limit="),
                )?;
            }
            _ if argument.starts_with("--expect=") => {
                set_oom_expectation(
                    &mut cli,
                    &mut expectation_set,
                    argument.trim_start_matches("--expect="),
                )?;
            }
            _ if argument.starts_with("--sample-ms=") => {
                set_sample_ms(
                    &mut cli,
                    &mut sample_set,
                    argument.trim_start_matches("--sample-ms="),
                )?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown oom option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if !positional_query.is_empty() {
        if query_set {
            return Err("oom query may be positional or passed with --query, not both".into());
        }
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    if cli.quiet && cli.oom_expectation.is_none() {
        return Err("oom --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_oom_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    value: LaunchMode,
) -> Result<(), String> {
    if output_mode.replace(value).is_some() {
        return Err("oom output mode may only be specified once".into());
    }
    *mode = value;
    Ok(())
}

fn set_oom_min_score(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--min-score may only be specified once".into());
    }
    let score = value
        .parse::<u16>()
        .map_err(|_| "--min-score requires an integer from 0 to 1000".to_string())?;
    if score > 1_000 {
        return Err("--min-score must be between 0 and 1000".into());
    }
    cli.oom_min_score = score;
    *value_set = true;
    Ok(())
}

fn set_oom_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--limit may only be specified once".into());
    }
    cli.oom_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| "--limit requires a positive integer or all".to_string())?;
        if !(1..=10_000).contains(&limit) {
            return Err("--limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_oom_expectation(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--expect may only be specified once".into());
    }
    cli.oom_expectation = Some(parse_expectation(value)?);
    *value_set = true;
    Ok(())
}

fn parse_net(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::NetTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut query_set = false;
    let mut protocol_set = false;
    let mut state_set = false;
    let mut limit_set = false;
    let mut expectation_set = false;
    let mut positional_query = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_net_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::NetTable)?
            }
            "--json" => set_net_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::NetJson)?,
            "--connected" | "--peers" => cli.net_connected_only = true,
            "--quiet" => cli.quiet = true,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--protocol" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--protocol requires tcp, udp, unix, or any".to_string())?;
                set_net_protocol(&mut cli, &mut protocol_set, &value)?;
            }
            "--state" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--state requires a socket state".to_string())?;
                set_net_state(&mut cli, &mut state_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_net_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_net_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            _ if argument.starts_with("--query=") => {
                set_query(
                    &mut cli,
                    &mut query_set,
                    argument.trim_start_matches("--query=").to_string(),
                )?;
            }
            _ if argument.starts_with("--protocol=") => {
                set_net_protocol(
                    &mut cli,
                    &mut protocol_set,
                    argument.trim_start_matches("--protocol="),
                )?;
            }
            _ if argument.starts_with("--state=") => {
                set_net_state(
                    &mut cli,
                    &mut state_set,
                    argument.trim_start_matches("--state="),
                )?;
            }
            _ if argument.starts_with("--limit=") => {
                set_net_limit(
                    &mut cli,
                    &mut limit_set,
                    argument.trim_start_matches("--limit="),
                )?;
            }
            _ if argument.starts_with("--expect=") => {
                set_net_expectation(
                    &mut cli,
                    &mut expectation_set,
                    argument.trim_start_matches("--expect="),
                )?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown net option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if query_set && !positional_query.is_empty() {
        return Err("net filter must be positional or passed with --query, not both".into());
    }
    if !query_set && !positional_query.is_empty() {
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    if cli.quiet && cli.net_expectation.is_none() {
        return Err("net --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_net_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("net --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_net_protocol(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--protocol may only be specified once".into());
    }
    cli.net_protocol = match value.to_ascii_lowercase().as_str() {
        "any" => ListenProtocol::Any,
        "tcp" => ListenProtocol::Tcp,
        "udp" => ListenProtocol::Udp,
        "unix" => ListenProtocol::Unix,
        _ => {
            return Err(format!(
                "invalid net protocol: {value}; use tcp, udp, unix, or any"
            ));
        }
    };
    *value_set = true;
    Ok(())
}

fn set_net_state(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--state may only be specified once".into());
    }
    let normalized = value.trim().to_ascii_uppercase().replace('-', "_");
    if normalized.is_empty()
        || normalized.len() > 64
        || !normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err("--state must be a non-empty socket state such as ESTABLISHED".into());
    }
    cli.net_state = Some(normalized);
    *value_set = true;
    Ok(())
}

fn set_net_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--limit may only be specified once".into());
    }
    cli.net_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid --limit value: {value}; use 1-10000 or all"))?;
        if !(1..=10_000).contains(&limit) {
            return Err("--limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_net_expectation(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--expect may only be specified once".into());
    }
    cli.net_expectation = Some(parse_expectation(value)?);
    *value_set = true;
    Ok(())
}

fn parse_file(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::FileTable,
        ..Cli::default()
    };
    let mut paths = Vec::new();
    let mut output_mode = None;
    let mut limit_set = false;
    let mut expectation_set = false;
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_file_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::FileTable)?
            }
            "--json" => {
                set_file_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::FileJson)?
            }
            "--recursive" => cli.file_recursive = true,
            "--quiet" => cli.quiet = true,
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "file --limit requires a positive integer or all".to_string())?;
                set_file_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "file --expect requires none or any".to_string())?;
                set_file_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            "--" => {
                paths.extend(arguments);
                break;
            }
            _ if argument.starts_with("--limit=") => {
                set_file_limit(
                    &mut cli,
                    &mut limit_set,
                    argument.trim_start_matches("--limit="),
                )?;
            }
            _ if argument.starts_with("--expect=") => {
                set_file_expectation(
                    &mut cli,
                    &mut expectation_set,
                    argument.trim_start_matches("--expect="),
                )?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!(
                    "unknown file option: {argument}; use -- before a path beginning with -"
                ));
            }
            _ => paths.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if paths.len() != 1 || paths[0].is_empty() {
        return Err(format!(
            "file requires exactly one non-empty PATH; received {}",
            paths.len()
        ));
    }
    cli.file_path = paths.pop();
    if cli.quiet && cli.file_expectation.is_none() {
        return Err("file --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_file_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("file --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_file_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("file --limit may only be specified once".into());
    }
    cli.file_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid file --limit value: {value}; use 1-10000 or all"))?;
        if !(1..=10_000).contains(&limit) {
            return Err("file --limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_file_expectation(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("file --expect may only be specified once".into());
    }
    cli.file_expectation = Some(parse_expectation(value)?);
    *value_set = true;
    Ok(())
}

fn parse_fd(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::FdTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut min_count_set = false;
    let mut min_percent_set = false;
    let mut limit_set = false;
    let mut expectation_set = false;
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => set_fd_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::FdTable)?,
            "--json" => set_fd_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::FdJson)?,
            "--quiet" => cli.quiet = true,
            "--min-count" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--min-count requires a non-negative integer".to_string())?;
                set_fd_min_count(&mut cli, &mut min_count_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_fd_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--min-percent" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--min-percent requires an integer from 1 to 100".to_string())?;
                set_fd_min_percent(&mut cli, &mut min_percent_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_fd_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            _ if argument.starts_with("--min-count=") => {
                let value = argument.trim_start_matches("--min-count=");
                set_fd_min_count(&mut cli, &mut min_count_set, value)?;
            }
            _ if argument.starts_with("--limit=") => {
                let value = argument.trim_start_matches("--limit=");
                set_fd_limit(&mut cli, &mut limit_set, value)?;
            }
            _ if argument.starts_with("--min-percent=") => {
                let value = argument.trim_start_matches("--min-percent=");
                set_fd_min_percent(&mut cli, &mut min_percent_set, value)?;
            }
            _ if argument.starts_with("--expect=") => {
                let value = argument.trim_start_matches("--expect=");
                set_fd_expectation(&mut cli, &mut expectation_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown fd option: {argument}"));
            }
            _ => return Err(format!("unexpected fd argument: {argument}")),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if cli.quiet && cli.fd_expectation.is_none() {
        return Err("fd --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_fd_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("fd --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_fd_min_count(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--min-count may only be specified once".into());
    }
    cli.fd_min_count = value
        .parse::<usize>()
        .map_err(|_| format!("invalid --min-count value: {value}"))?;
    *value_set = true;
    Ok(())
}

fn set_fd_min_percent(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--min-percent may only be specified once".into());
    }
    let percent = value
        .parse::<u16>()
        .map_err(|_| format!("invalid --min-percent value: {value}; use 1-100"))?;
    if !(1..=100).contains(&percent) {
        return Err("--min-percent must be between 1 and 100".into());
    }
    cli.fd_min_percent = Some(percent);
    *value_set = true;
    Ok(())
}

fn set_fd_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--limit may only be specified once".into());
    }
    cli.fd_limit = if value == "all" {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid --limit value: {value}; use 1-10000 or all"))?;
        if !(1..=10_000).contains(&limit) {
            return Err("--limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_fd_expectation(
    cli: &mut Cli,
    expectation_set: &mut bool,
    value: &str,
) -> Result<(), String> {
    if *expectation_set {
        return Err("--expect may only be specified once".into());
    }
    cli.fd_expectation = Some(parse_expectation(value)?);
    *expectation_set = true;
    Ok(())
}

fn parse_deleted(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::DeletedTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut min_size_set = false;
    let mut expectation_set = false;
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_deleted_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::DeletedTable)?
            }
            "--json" => {
                set_deleted_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::DeletedJson)?
            }
            "--quiet" => cli.quiet = true,
            "--min-size" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--min-size requires a byte size".to_string())?;
                set_deleted_min_size(&mut cli, &mut min_size_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_deleted_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            _ if argument.starts_with("--min-size=") => {
                let value = argument.trim_start_matches("--min-size=");
                set_deleted_min_size(&mut cli, &mut min_size_set, value)?;
            }
            _ if argument.starts_with("--expect=") => {
                let value = argument.trim_start_matches("--expect=");
                set_deleted_expectation(&mut cli, &mut expectation_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown deleted option: {argument}"));
            }
            _ => return Err(format!("unexpected deleted argument: {argument}")),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if cli.quiet && cli.deleted_expectation.is_none() {
        return Err("deleted --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_deleted_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("deleted --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_deleted_min_size(cli: &mut Cli, size_set: &mut bool, value: &str) -> Result<(), String> {
    if *size_set {
        return Err("--min-size may only be specified once".into());
    }
    cli.deleted_min_size = parse_byte_size(value)?;
    *size_set = true;
    Ok(())
}

fn set_deleted_expectation(
    cli: &mut Cli,
    expectation_set: &mut bool,
    value: &str,
) -> Result<(), String> {
    if *expectation_set {
        return Err("--expect may only be specified once".into());
    }
    cli.deleted_expectation = Some(parse_expectation(value)?);
    *expectation_set = true;
    Ok(())
}

fn parse_byte_size(value: &str) -> Result<u64, String> {
    let normalized = value.trim().to_ascii_lowercase();
    let units = [
        ("tib", 1024_f64.powi(4)),
        ("tb", 1024_f64.powi(4)),
        ("t", 1024_f64.powi(4)),
        ("gib", 1024_f64.powi(3)),
        ("gb", 1024_f64.powi(3)),
        ("g", 1024_f64.powi(3)),
        ("mib", 1024_f64.powi(2)),
        ("mb", 1024_f64.powi(2)),
        ("m", 1024_f64.powi(2)),
        ("kib", 1024_f64),
        ("kb", 1024_f64),
        ("k", 1024_f64),
        ("b", 1_f64),
    ];
    let (number, multiplier) = units
        .iter()
        .find_map(|(suffix, multiplier)| {
            normalized
                .strip_suffix(suffix)
                .map(|number| (number, *multiplier))
        })
        .unwrap_or((normalized.as_str(), 1.0));
    let number = number
        .parse::<f64>()
        .map_err(|_| format!("invalid byte size: {value}"))?;
    let bytes = number * multiplier;
    if !bytes.is_finite() || bytes < 0.0 || bytes > u64::MAX as f64 {
        return Err(format!("invalid byte size: {value}"));
    }
    Ok(bytes.round() as u64)
}

fn parse_trace(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::TraceTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut interval_set = false;
    let mut count_set = false;
    let mut pids = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_trace_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::TraceTable)?
            }
            "--jsonl" => {
                set_trace_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::TraceJsonl)?
            }
            "--interval-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--interval-ms requires a value".to_string())?;
                set_trace_interval(&mut cli, &mut interval_set, &value)?;
            }
            "--count" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--count requires a value".to_string())?;
                set_trace_count(&mut cli, &mut count_set, &value)?;
            }
            _ if argument.starts_with("--interval-ms=") => {
                let value = argument.trim_start_matches("--interval-ms=");
                set_trace_interval(&mut cli, &mut interval_set, value)?;
            }
            _ if argument.starts_with("--count=") => {
                let value = argument.trim_start_matches("--count=");
                set_trace_count(&mut cli, &mut count_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown trace option: {argument}"));
            }
            _ => pids.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "trace requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("trace requires a real process PID greater than zero".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.trace_pid = Some(pid);
    Ok(cli)
}

fn set_trace_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("trace --table and --jsonl cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_trace_interval(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--interval-ms may only be specified once".into());
    }
    let interval = value
        .parse::<u64>()
        .map_err(|_| format!("invalid --interval-ms value: {value}"))?;
    if !(100..=60_000).contains(&interval) {
        return Err("--interval-ms must be between 100 and 60000".into());
    }
    cli.trace_interval_ms = interval;
    *value_set = true;
    Ok(())
}

fn set_trace_count(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--count may only be specified once".into());
    }
    let count = value
        .parse::<usize>()
        .map_err(|_| format!("invalid --count value: {value}"))?;
    if !(1..=1_000_000).contains(&count) {
        return Err("--count must be between 1 and 1000000".into());
    }
    cli.trace_count = Some(count);
    *value_set = true;
    Ok(())
}

fn parse_run(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::RunTable,
        ..Cli::default()
    };
    let separator = arguments.iter().position(|argument| argument == "--");
    let option_arguments = separator
        .map(|index| &arguments[..index])
        .unwrap_or(arguments);
    let mut output_mode = None;
    let mut interval_set = false;
    let mut grace_set = false;
    let mut report_path_set = false;
    let mut options = option_arguments.iter().cloned().peekable();
    while let Some(argument) = options.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_run_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::RunTable)?
            }
            "--json" => set_run_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::RunJson)?,
            "--interval-ms" => {
                let value = options
                    .next()
                    .ok_or_else(|| "--interval-ms requires a value".to_string())?;
                set_run_interval(&mut cli, &mut interval_set, &value)?;
            }
            "--linger-ms" => {
                let value = options
                    .next()
                    .ok_or_else(|| "--linger-ms requires a value".to_string())?;
                set_run_grace(&mut cli, &mut grace_set, &value)?;
            }
            "--output" => {
                let value = options
                    .next()
                    .ok_or_else(|| "--output requires a value".to_string())?;
                set_run_report_path(&mut cli, &mut output_mode, &mut report_path_set, value)?;
            }
            "--force" => {
                if cli.run_force {
                    return Err("--force may only be specified once".into());
                }
                cli.run_force = true;
            }
            _ if argument.starts_with("--interval-ms=") => {
                set_run_interval(
                    &mut cli,
                    &mut interval_set,
                    argument.trim_start_matches("--interval-ms="),
                )?;
            }
            _ if argument.starts_with("--linger-ms=") => {
                set_run_grace(
                    &mut cli,
                    &mut grace_set,
                    argument.trim_start_matches("--linger-ms="),
                )?;
            }
            _ if argument.starts_with("--output=") => {
                set_run_report_path(
                    &mut cli,
                    &mut output_mode,
                    &mut report_path_set,
                    argument.trim_start_matches("--output=").to_string(),
                )?;
            }
            _ => {
                return Err(format!(
                    "unknown run option: {argument}; place the command after --"
                ));
            }
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if cli.run_force && cli.run_output.is_none() {
        return Err("run --force requires --output FILE".into());
    }
    let Some(separator) = separator else {
        return Err("run requires -- before COMMAND and its arguments".into());
    };
    cli.run_command = arguments[separator + 1..].to_vec();
    if cli.run_command.is_empty() {
        return Err("run requires COMMAND after --".into());
    }
    Ok(cli)
}

fn set_run_report_path(
    cli: &mut Cli,
    output_mode: &mut Option<LaunchMode>,
    path_set: &mut bool,
    path: String,
) -> Result<(), String> {
    if *path_set {
        return Err("--output may only be specified once".into());
    }
    if path.is_empty() || path == "-" {
        return Err("run --output requires a file path other than '-'".into());
    }
    set_run_output_mode(&mut cli.mode, output_mode, LaunchMode::RunJson)?;
    cli.run_output = Some(path);
    *path_set = true;
    Ok(())
}

fn set_run_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("run --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_run_interval(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--interval-ms may only be specified once".into());
    }
    let interval = value
        .parse::<u64>()
        .map_err(|_| format!("invalid --interval-ms value: {value}"))?;
    if !(100..=60_000).contains(&interval) {
        return Err("--interval-ms must be between 100 and 60000".into());
    }
    cli.run_interval_ms = interval;
    *value_set = true;
    Ok(())
}

fn set_run_grace(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--linger-ms may only be specified once".into());
    }
    let grace = value
        .parse::<u64>()
        .map_err(|_| format!("invalid --linger-ms value: {value}"))?;
    if grace > 60_000 {
        return Err("--linger-ms must be between 0 and 60000".into());
    }
    cli.run_descendant_grace_ms = grace;
    *value_set = true;
    Ok(())
}

fn parse_cgroup(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::CgroupTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut query_set = false;
    let mut sort_set = false;
    let mut limit_set = false;
    let mut sample_set = false;
    let mut positional_filter = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_cgroup_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::CgroupTable)?
            }
            "--json" => {
                set_cgroup_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::CgroupJson)?
            }
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--by" => {
                let value = arguments.next().ok_or_else(|| {
                    "--by requires cpu, memory, pressure, or processes".to_string()
                })?;
                set_cgroup_sort(&mut cli, &mut sort_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_cgroup_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            _ if argument.starts_with("--query=") => set_query(
                &mut cli,
                &mut query_set,
                argument.trim_start_matches("--query=").to_string(),
            )?,
            _ if argument.starts_with("--by=") => set_cgroup_sort(
                &mut cli,
                &mut sort_set,
                argument.trim_start_matches("--by="),
            )?,
            _ if argument.starts_with("--limit=") => set_cgroup_limit(
                &mut cli,
                &mut limit_set,
                argument.trim_start_matches("--limit="),
            )?,
            _ if argument.starts_with("--sample-ms=") => set_sample_ms(
                &mut cli,
                &mut sample_set,
                argument.trim_start_matches("--sample-ms="),
            )?,
            _ if argument.starts_with('-') => {
                return Err(format!("unknown cgroup option: {argument}"));
            }
            _ => positional_filter.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if !positional_filter.is_empty() {
        if query_set {
            return Err("cgroup filter may be positional or passed with --query, not both".into());
        }
        set_query(&mut cli, &mut query_set, positional_filter.join(" "))?;
    }
    Ok(cli)
}

fn set_cgroup_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.replace(requested).is_some() {
        return Err("cgroup output mode may only be specified once".into());
    }
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_cgroup_sort(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--by may only be specified once".into());
    }
    cli.cgroup_sort = match value.to_ascii_lowercase().as_str() {
        "cpu" => CgroupSort::Cpu,
        "memory" | "mem" => CgroupSort::Memory,
        "pressure" | "percent" | "utilization" => CgroupSort::Pressure,
        "processes" | "procs" | "pids" => CgroupSort::Processes,
        _ => return Err("--by requires cpu, memory, pressure, or processes".into()),
    };
    *value_set = true;
    Ok(())
}

fn set_cgroup_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--limit may only be specified once".into());
    }
    cli.cgroup_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| "--limit requires a positive integer or all".to_string())?;
        if !(1..=10_000).contains(&limit) {
            return Err("--limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn parse_watch(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::WatchTable,
        ..Cli::default()
    };
    let mut positional_query = Vec::new();
    let mut query_set = false;
    let mut output_mode = None;
    let mut interval_set = false;
    let mut count_set = false;
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_watch_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::WatchTable)?
            }
            "--jsonl" => {
                set_watch_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::WatchJsonl)?
            }
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--interval-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--interval-ms requires a value".to_string())?;
                set_watch_interval(&mut cli, &mut interval_set, &value)?;
            }
            "--count" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--count requires a value".to_string())?;
                set_watch_count(&mut cli, &mut count_set, &value)?;
            }
            _ if argument.starts_with("--query=") => {
                let value = argument.trim_start_matches("--query=").to_string();
                set_query(&mut cli, &mut query_set, value)?;
            }
            _ if argument.starts_with("--interval-ms=") => {
                let value = argument.trim_start_matches("--interval-ms=");
                set_watch_interval(&mut cli, &mut interval_set, value)?;
            }
            _ if argument.starts_with("--count=") => {
                let value = argument.trim_start_matches("--count=");
                set_watch_count(&mut cli, &mut count_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown watch option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if query_set && !positional_query.is_empty() {
        return Err("watch query must be positional or passed with --query, not both".into());
    }
    if !query_set && !positional_query.is_empty() {
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    Ok(cli)
}

fn set_watch_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("watch --table and --jsonl cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_watch_interval(cli: &mut Cli, interval_set: &mut bool, value: &str) -> Result<(), String> {
    if *interval_set {
        return Err("--interval-ms may only be specified once".into());
    }
    let interval = value
        .parse::<u64>()
        .map_err(|_| format!("invalid --interval-ms value: {value}"))?;
    if !(100..=60_000).contains(&interval) {
        return Err("--interval-ms must be between 100 and 60000".into());
    }
    cli.watch_interval_ms = interval;
    *interval_set = true;
    Ok(())
}

fn set_watch_count(cli: &mut Cli, count_set: &mut bool, value: &str) -> Result<(), String> {
    if *count_set {
        return Err("--count may only be specified once".into());
    }
    let count = value
        .parse::<usize>()
        .map_err(|_| format!("invalid --count value: {value}"))?;
    if !(1..=1_000_000).contains(&count) {
        return Err("--count must be between 1 and 1000000".into());
    }
    cli.watch_count = Some(count);
    *count_set = true;
    Ok(())
}

fn parse_tree(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::TreeTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut depth_set = false;
    let mut sample_set = false;
    let mut pids = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_tree_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::TreeTable)?
            }
            "--json" => {
                set_tree_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::TreeJson)?
            }
            "--depth" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--depth requires 0-128 or all".to_string())?;
                set_tree_depth(&mut cli, &mut depth_set, &value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            _ if argument.starts_with("--depth=") => {
                let value = argument.trim_start_matches("--depth=");
                set_tree_depth(&mut cli, &mut depth_set, value)?;
            }
            _ if argument.starts_with("--sample-ms=") => {
                let value = argument.trim_start_matches("--sample-ms=");
                set_sample_ms(&mut cli, &mut sample_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown tree option: {argument}"));
            }
            _ => pids.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "tree requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.tree_pid = Some(pid);
    Ok(cli)
}

fn set_tree_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("tree --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_tree_depth(cli: &mut Cli, depth_set: &mut bool, value: &str) -> Result<(), String> {
    if *depth_set {
        return Err("--depth may only be specified once".into());
    }
    cli.tree_depth = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let depth = value
            .parse::<usize>()
            .map_err(|_| format!("invalid --depth value: {value}; use 0-128 or all"))?;
        if depth > 128 {
            return Err("--depth must be between 0 and 128, or all".into());
        }
        Some(depth)
    };
    *depth_set = true;
    Ok(())
}

fn parse_listen(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::ListenTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut query_set = false;
    let mut protocol_set = false;
    let mut limit_set = false;
    let mut expectation_set = false;
    let mut positional_query = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_listen_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ListenTable)?
            }
            "--json" => {
                set_listen_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ListenJson)?
            }
            "--exposed" => cli.listen_exposed = true,
            "--quiet" => cli.quiet = true,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--protocol" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--protocol requires tcp, udp, unix, or any".to_string())?;
                set_listen_protocol(&mut cli, &mut protocol_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--limit requires a positive integer or all".to_string())?;
                set_listen_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_listen_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            _ if argument.starts_with("--query=") => {
                let value = argument.trim_start_matches("--query=").to_string();
                set_query(&mut cli, &mut query_set, value)?;
            }
            _ if argument.starts_with("--protocol=") => {
                let value = argument.trim_start_matches("--protocol=");
                set_listen_protocol(&mut cli, &mut protocol_set, value)?;
            }
            _ if argument.starts_with("--limit=") => {
                let value = argument.trim_start_matches("--limit=");
                set_listen_limit(&mut cli, &mut limit_set, value)?;
            }
            _ if argument.starts_with("--expect=") => {
                let value = argument.trim_start_matches("--expect=");
                set_listen_expectation(&mut cli, &mut expectation_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown listen option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if query_set && !positional_query.is_empty() {
        return Err("listen filter must be positional or passed with --query, not both".into());
    }
    if !query_set && !positional_query.is_empty() {
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    if cli.quiet && cli.listen_expectation.is_none() {
        return Err("listen --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_listen_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("listen --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_listen_protocol(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--protocol may only be specified once".into());
    }
    cli.listen_protocol = match value.to_ascii_lowercase().as_str() {
        "any" => ListenProtocol::Any,
        "tcp" => ListenProtocol::Tcp,
        "udp" => ListenProtocol::Udp,
        "unix" => ListenProtocol::Unix,
        _ => {
            return Err(format!(
                "invalid listen protocol: {value}; use tcp, udp, unix, or any"
            ));
        }
    };
    *value_set = true;
    Ok(())
}

fn set_listen_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("--limit may only be specified once".into());
    }
    cli.listen_limit = if value == "all" {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid --limit value: {value}; use 1-10000 or all"))?;
        if !(1..=10_000).contains(&limit) {
            return Err("--limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_listen_expectation(
    cli: &mut Cli,
    expectation_set: &mut bool,
    value: &str,
) -> Result<(), String> {
    if *expectation_set {
        return Err("--expect may only be specified once".into());
    }
    cli.listen_expectation = Some(parse_expectation(value)?);
    *expectation_set = true;
    Ok(())
}

fn parse_port(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::PortTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut protocol_set = false;
    let mut expectation_set = false;
    let mut ports = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_port_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::PortTable)?
            }
            "--json" => {
                set_port_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::PortJson)?
            }
            "--all" => cli.port_all = true,
            "--quiet" => cli.quiet = true,
            "--protocol" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--protocol requires tcp, udp, or any".to_string())?;
                set_port_protocol(&mut cli, &mut protocol_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_port_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            _ if argument.starts_with("--protocol=") => {
                let value = argument.trim_start_matches("--protocol=");
                set_port_protocol(&mut cli, &mut protocol_set, value)?;
            }
            _ if argument.starts_with("--expect=") => {
                let value = argument.trim_start_matches("--expect=");
                set_port_expectation(&mut cli, &mut expectation_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown port option: {argument}"));
            }
            _ => ports.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if ports.len() != 1 {
        return Err(format!(
            "port requires exactly one local port number; received {}",
            ports.len()
        ));
    }
    let port = ports[0]
        .parse::<u16>()
        .map_err(|_| format!("invalid port: {}; expected 1-65535", ports[0]))?;
    if port == 0 {
        return Err("port must be between 1 and 65535".into());
    }
    if cli.quiet && cli.port_expectation.is_none() {
        return Err("port --quiet requires --expect any or --expect none".into());
    }
    cli.port = Some(port);
    Ok(cli)
}

fn set_port_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("port --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_port_protocol(cli: &mut Cli, protocol_set: &mut bool, value: &str) -> Result<(), String> {
    if *protocol_set {
        return Err("--protocol may only be specified once".into());
    }
    cli.port_protocol = match value.to_ascii_lowercase().as_str() {
        "any" => PortProtocol::Any,
        "tcp" => PortProtocol::Tcp,
        "udp" => PortProtocol::Udp,
        _ => {
            return Err(format!(
                "invalid --protocol value: {value}; use tcp, udp, or any"
            ));
        }
    };
    *protocol_set = true;
    Ok(())
}

fn set_port_expectation(
    cli: &mut Cli,
    expectation_set: &mut bool,
    value: &str,
) -> Result<(), String> {
    if *expectation_set {
        return Err("--expect may only be specified once".into());
    }
    cli.port_expectation = Some(parse_expectation(value)?);
    *expectation_set = true;
    Ok(())
}

fn parse_inspect(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::InspectTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut sample_set = false;
    let mut pids = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_inspect_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::InspectTable)?
            }
            "--json" => {
                set_inspect_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::InspectJson)?
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            _ if argument.starts_with("--sample-ms=") => {
                let value = argument.trim_start_matches("--sample-ms=");
                set_sample_ms(&mut cli, &mut sample_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown inspect option: {argument}"));
            }
            _ => pids.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "inspect requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("inspect requires a real process PID greater than 0".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.inspect_pid = Some(pid);
    Ok(cli)
}

fn set_inspect_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("inspect --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn parse_memory(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::MemoryTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut limit_set = false;
    let mut pids = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_memory_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::MemoryTable)?
            }
            "--json" => {
                set_memory_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::MemoryJson)?
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "memory --limit requires 1-10000 or all".to_string())?;
                set_memory_limit(&mut cli, &mut limit_set, &value)?;
            }
            _ if argument.starts_with("--limit=") => set_memory_limit(
                &mut cli,
                &mut limit_set,
                argument.trim_start_matches("--limit="),
            )?,
            _ if argument.starts_with('-') => {
                return Err(format!("unknown memory option: {argument}"));
            }
            _ => pids.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "memory requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("memory requires a real process PID greater than 0".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.memory_pid = Some(pid);
    Ok(cli)
}

fn set_memory_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("memory --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_memory_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("memory --limit may only be specified once".into());
    }
    cli.memory_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid memory --limit value: {value}; use 1-10000 or all"))?;
        if !(1..=10_000).contains(&limit) {
            return Err("memory --limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn parse_exe(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::ExeTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut pids = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_exe_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ExeTable)?
            }
            "--json" => set_exe_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ExeJson)?,
            "--no-hash" => {
                if !cli.exe_hash {
                    return Err("exe --no-hash may only be specified once".into());
                }
                cli.exe_hash = false;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown exe option: {argument}"));
            }
            _ => pids.push(argument.clone()),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "exe requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("exe requires a real process PID greater than 0".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.exe_pid = Some(pid);
    Ok(cli)
}

fn set_exe_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("exe --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn parse_stale(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::StaleTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut query_set = false;
    let mut sample_set = false;
    let mut limit_set = false;
    let mut expectation_set = false;
    let mut positional_query = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_stale_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::StaleTable)?
            }
            "--json" => {
                set_stale_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::StaleJson)?
            }
            "--quiet" => cli.quiet = true,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "stale --limit requires 1-10000 or all".to_string())?;
                set_stale_limit(&mut cli, &mut limit_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "stale --expect requires none or any".to_string())?;
                set_stale_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            _ if argument.starts_with("--query=") => set_query(
                &mut cli,
                &mut query_set,
                argument.trim_start_matches("--query=").to_string(),
            )?,
            _ if argument.starts_with("--sample-ms=") => set_sample_ms(
                &mut cli,
                &mut sample_set,
                argument.trim_start_matches("--sample-ms="),
            )?,
            _ if argument.starts_with("--limit=") => set_stale_limit(
                &mut cli,
                &mut limit_set,
                argument.trim_start_matches("--limit="),
            )?,
            _ if argument.starts_with("--expect=") => set_stale_expectation(
                &mut cli,
                &mut expectation_set,
                argument.trim_start_matches("--expect="),
            )?,
            _ if argument.starts_with('-') => {
                return Err(format!("unknown stale option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if !positional_query.is_empty() {
        if query_set {
            return Err("stale query may be positional or passed with --query, not both".into());
        }
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    if cli.quiet && cli.stale_expectation.is_none() {
        return Err("stale --quiet requires --expect any or --expect none".into());
    }
    Ok(cli)
}

fn set_stale_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("stale --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_stale_limit(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("stale --limit may only be specified once".into());
    }
    cli.stale_limit = if value.eq_ignore_ascii_case("all") {
        None
    } else {
        let limit = value
            .parse::<usize>()
            .map_err(|_| format!("invalid stale --limit value: {value}; use 1-10000 or all"))?;
        if !(1..=10_000).contains(&limit) {
            return Err("stale --limit must be between 1 and 10000, or all".into());
        }
        Some(limit)
    };
    *value_set = true;
    Ok(())
}

fn set_stale_expectation(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("stale --expect may only be specified once".into());
    }
    cli.stale_expectation = Some(parse_expectation(value)?);
    *value_set = true;
    Ok(())
}

fn parse_service(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::ServiceTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut pids = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_service_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ServiceTable)?
            }
            "--json" => {
                set_service_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ServiceJson)?
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown service option: {argument}"));
            }
            _ => pids.push(argument.clone()),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "service requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("service requires a real process PID greater than 0".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.service_pid = Some(pid);
    Ok(cli)
}

fn set_service_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("service --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn parse_explain(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::ExplainTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut output_path_set = false;
    let mut force_set = false;
    let mut sample_set = false;
    let mut scope_set = false;
    let mut priority_set = false;
    let mut since_set = false;
    let mut limit_set = false;
    let mut hash_disabled = false;
    let mut logs_disabled = false;
    let mut pids = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_explain_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ExplainTable)?
            }
            "--json" => {
                set_explain_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::ExplainJson)?
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "explain --sample-ms requires an integer".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            "--no-hash" => {
                if hash_disabled {
                    return Err("explain --no-hash may only be specified once".into());
                }
                cli.exe_hash = false;
                hash_disabled = true;
            }
            "--no-logs" => {
                if logs_disabled {
                    return Err("explain --no-logs may only be specified once".into());
                }
                cli.explain_include_logs = false;
                logs_disabled = true;
            }
            "--scope" => {
                let value = arguments.next().ok_or_else(|| {
                    "explain --scope requires auto, process, or service".to_string()
                })?;
                set_logs_scope(&mut cli, &mut scope_set, &value, "explain")?;
            }
            "--priority" => {
                let value = arguments.next().ok_or_else(|| {
                    "explain --priority requires error, warning, info, or debug".to_string()
                })?;
                set_logs_priority(&mut cli, &mut priority_set, &value, "explain")?;
            }
            "--since" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "explain --since requires a duration".to_string())?;
                set_logs_since(&mut cli, &mut since_set, &value, "explain")?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "explain --limit requires an integer".to_string())?;
                set_logs_limit(&mut cli, &mut limit_set, &value, "explain")?;
            }
            "--output" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "explain --output requires a file path".to_string())?;
                set_explain_output_path(&mut cli, &mut output_mode, &mut output_path_set, value)?;
            }
            "--force" => {
                if force_set {
                    return Err("explain --force may only be specified once".into());
                }
                cli.explain_force = true;
                force_set = true;
            }
            _ if argument.starts_with("--sample-ms=") => set_sample_ms(
                &mut cli,
                &mut sample_set,
                argument.trim_start_matches("--sample-ms="),
            )?,
            _ if argument.starts_with("--scope=") => set_logs_scope(
                &mut cli,
                &mut scope_set,
                argument.trim_start_matches("--scope="),
                "explain",
            )?,
            _ if argument.starts_with("--priority=") => set_logs_priority(
                &mut cli,
                &mut priority_set,
                argument.trim_start_matches("--priority="),
                "explain",
            )?,
            _ if argument.starts_with("--since=") => set_logs_since(
                &mut cli,
                &mut since_set,
                argument.trim_start_matches("--since="),
                "explain",
            )?,
            _ if argument.starts_with("--limit=") => set_logs_limit(
                &mut cli,
                &mut limit_set,
                argument.trim_start_matches("--limit="),
                "explain",
            )?,
            _ if argument.starts_with("--output=") => set_explain_output_path(
                &mut cli,
                &mut output_mode,
                &mut output_path_set,
                argument.trim_start_matches("--output=").to_string(),
            )?,
            _ if argument.starts_with('-') => {
                return Err(format!("unknown explain option: {argument}"));
            }
            _ => pids.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "explain requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("explain requires a real process PID greater than 0".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    if !cli.explain_include_logs && (scope_set || priority_set || since_set || limit_set) {
        return Err(
            "explain --no-logs cannot be combined with --scope, --priority, --since, or --limit"
                .into(),
        );
    }
    if cli.explain_force && cli.explain_output.is_none() {
        return Err("explain --force requires --output FILE".into());
    }
    cli.explain_pid = Some(pid);
    Ok(cli)
}

fn set_explain_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("explain --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_explain_output_path(
    cli: &mut Cli,
    output_mode: &mut Option<LaunchMode>,
    value_set: &mut bool,
    path: String,
) -> Result<(), String> {
    if *value_set {
        return Err("explain --output may only be specified once".into());
    }
    if path.trim().is_empty() || path == "-" {
        return Err("explain --output requires a filesystem path, not stdout".into());
    }
    set_explain_output_mode(&mut cli.mode, output_mode, LaunchMode::ExplainJson)?;
    cli.explain_output = Some(path);
    *value_set = true;
    Ok(())
}

fn parse_logs(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::LogsTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut scope_set = false;
    let mut priority_set = false;
    let mut since_set = false;
    let mut limit_set = false;
    let mut pids = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_logs_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::LogsTable)?
            }
            "--json" => {
                set_logs_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::LogsJson)?
            }
            "--scope" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "logs --scope requires auto, process, or service".to_string())?;
                set_logs_scope(&mut cli, &mut scope_set, &value, "logs")?;
            }
            "--priority" => {
                let value = arguments.next().ok_or_else(|| {
                    "logs --priority requires error, warning, info, or debug".to_string()
                })?;
                set_logs_priority(&mut cli, &mut priority_set, &value, "logs")?;
            }
            "--since" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "logs --since requires a duration".to_string())?;
                set_logs_since(&mut cli, &mut since_set, &value, "logs")?;
            }
            "--limit" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "logs --limit requires an integer".to_string())?;
                set_logs_limit(&mut cli, &mut limit_set, &value, "logs")?;
            }
            _ if argument.starts_with("--scope=") => set_logs_scope(
                &mut cli,
                &mut scope_set,
                argument.trim_start_matches("--scope="),
                "logs",
            )?,
            _ if argument.starts_with("--priority=") => set_logs_priority(
                &mut cli,
                &mut priority_set,
                argument.trim_start_matches("--priority="),
                "logs",
            )?,
            _ if argument.starts_with("--since=") => set_logs_since(
                &mut cli,
                &mut since_set,
                argument.trim_start_matches("--since="),
                "logs",
            )?,
            _ if argument.starts_with("--limit=") => set_logs_limit(
                &mut cli,
                &mut limit_set,
                argument.trim_start_matches("--limit="),
                "logs",
            )?,
            _ if argument.starts_with('-') => {
                return Err(format!("unknown logs option: {argument}"));
            }
            _ => pids.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if pids.len() != 1 {
        return Err(format!(
            "logs requires exactly one PID; received {}",
            pids.len()
        ));
    }
    let pid = pids[0]
        .parse::<u32>()
        .map_err(|_| format!("invalid PID: {}", pids[0]))?;
    if pid == 0 {
        return Err("logs requires a real process PID greater than 0".into());
    }
    if pid > i32::MAX as u32 {
        return Err(format!("PID {pid} exceeds the supported system PID range"));
    }
    cli.logs_pid = Some(pid);
    Ok(cli)
}

fn set_logs_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("logs --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_logs_scope(
    cli: &mut Cli,
    value_set: &mut bool,
    value: &str,
    command: &str,
) -> Result<(), String> {
    if *value_set {
        return Err(format!("{command} --scope may only be specified once"));
    }
    cli.logs_scope = match value.to_ascii_lowercase().as_str() {
        "auto" => LogScope::Auto,
        "process" | "pid" => LogScope::Process,
        "service" | "unit" => LogScope::Service,
        _ => {
            return Err(format!(
                "invalid {command} scope: {value}; use auto, process, or service"
            ));
        }
    };
    *value_set = true;
    Ok(())
}

fn set_logs_priority(
    cli: &mut Cli,
    value_set: &mut bool,
    value: &str,
    command: &str,
) -> Result<(), String> {
    if *value_set {
        return Err(format!("{command} --priority may only be specified once"));
    }
    cli.logs_priority = match value.to_ascii_lowercase().as_str() {
        "error" | "err" => LogPriority::Error,
        "warning" | "warn" => LogPriority::Warning,
        "info" => LogPriority::Info,
        "debug" => LogPriority::Debug,
        _ => {
            return Err(format!(
                "invalid {command} priority: {value}; use error, warning, info, or debug"
            ));
        }
    };
    *value_set = true;
    Ok(())
}

fn set_logs_since(
    cli: &mut Cli,
    value_set: &mut bool,
    value: &str,
    command: &str,
) -> Result<(), String> {
    if *value_set {
        return Err(format!("{command} --since may only be specified once"));
    }
    cli.logs_since_seconds = parse_logs_duration_seconds(value, command)?;
    *value_set = true;
    Ok(())
}

fn parse_logs_duration_seconds(value: &str, command: &str) -> Result<u64, String> {
    let normalized = value.trim().to_ascii_lowercase();
    let (number, multiplier) = if let Some(number) = normalized.strip_suffix('s') {
        (number, 1.0)
    } else if let Some(number) = normalized.strip_suffix('m') {
        (number, 60.0)
    } else if let Some(number) = normalized.strip_suffix('h') {
        (number, 3_600.0)
    } else if let Some(number) = normalized.strip_suffix('d') {
        (number, 86_400.0)
    } else {
        return Err(format!(
            "invalid {command} --since duration: {value}; include s, m, h, or d"
        ));
    };
    let amount = number
        .parse::<f64>()
        .map_err(|_| format!("invalid {command} --since duration: {value}"))?;
    let seconds = amount * multiplier;
    if !seconds.is_finite() || !(1.0..=604_800.0).contains(&seconds) {
        return Err(format!("{command} --since must be between 1s and 7d"));
    }
    Ok(seconds.ceil() as u64)
}

fn set_logs_limit(
    cli: &mut Cli,
    value_set: &mut bool,
    value: &str,
    command: &str,
) -> Result<(), String> {
    if *value_set {
        return Err(format!("{command} --limit may only be specified once"));
    }
    let limit = value
        .parse::<usize>()
        .map_err(|_| format!("invalid {command} --limit value: {value}"))?;
    if !(1..=1_000).contains(&limit) {
        return Err(format!("{command} --limit must be between 1 and 1000"));
    }
    cli.logs_limit = limit;
    *value_set = true;
    Ok(())
}

fn parse_check(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::CheckTable,
        ..Cli::default()
    };
    let mut positional_query = Vec::new();
    let mut query_set = false;
    let mut sample_set = false;
    let mut output_mode = None;
    let mut expectation_set = false;
    let mut wait_set = false;
    let mut interval_set = false;
    let mut stable_set = false;
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_check_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::CheckTable)?
            }
            "--json" => {
                set_check_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::CheckJson)?
            }
            "--quiet" => cli.quiet = true,
            "-q" | "--query" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                set_query(&mut cli, &mut query_set, value)?;
            }
            "--sample-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--sample-ms requires a value".to_string())?;
                set_sample_ms(&mut cli, &mut sample_set, &value)?;
            }
            "--expect" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--expect requires none or any".to_string())?;
                set_check_expectation(&mut cli, &mut expectation_set, &value)?;
            }
            "--wait" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--wait requires a duration such as 30s or 2m".to_string())?;
                set_check_wait(&mut cli, &mut wait_set, &value)?;
            }
            "--interval-ms" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--interval-ms requires a value".to_string())?;
                set_check_interval(&mut cli, &mut interval_set, &value)?;
            }
            "--stable" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--stable requires a positive sample count".to_string())?;
                set_check_stable(&mut cli, &mut stable_set, &value)?;
            }
            _ if argument.starts_with("--query=") => {
                let value = argument.trim_start_matches("--query=").to_string();
                set_query(&mut cli, &mut query_set, value)?;
            }
            _ if argument.starts_with("--sample-ms=") => {
                let value = argument.trim_start_matches("--sample-ms=");
                set_sample_ms(&mut cli, &mut sample_set, value)?;
            }
            _ if argument.starts_with("--expect=") => {
                let value = argument.trim_start_matches("--expect=");
                set_check_expectation(&mut cli, &mut expectation_set, value)?;
            }
            _ if argument.starts_with("--wait=") => {
                let value = argument.trim_start_matches("--wait=");
                set_check_wait(&mut cli, &mut wait_set, value)?;
            }
            _ if argument.starts_with("--interval-ms=") => {
                let value = argument.trim_start_matches("--interval-ms=");
                set_check_interval(&mut cli, &mut interval_set, value)?;
            }
            _ if argument.starts_with("--stable=") => {
                let value = argument.trim_start_matches("--stable=");
                set_check_stable(&mut cli, &mut stable_set, value)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown check option: {argument}"));
            }
            _ => positional_query.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if query_set && !positional_query.is_empty() {
        return Err("check query must be positional or passed with --query, not both".into());
    }
    if !query_set {
        set_query(&mut cli, &mut query_set, positional_query.join(" "))?;
    }
    if cli.check_wait_ms.is_none() && (interval_set || stable_set) {
        return Err("check --interval-ms and --stable require --wait DURATION".into());
    }
    if cli
        .check_wait_ms
        .is_some_and(|wait_ms| wait_ms < cli.sample_ms)
    {
        return Err("check --wait must be at least as long as --sample-ms".into());
    }
    Ok(cli)
}

fn set_check_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("check --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_check_expectation(
    cli: &mut Cli,
    expectation_set: &mut bool,
    value: &str,
) -> Result<(), String> {
    if *expectation_set {
        return Err("--expect may only be specified once".into());
    }
    cli.check_expectation = parse_expectation(value)?;
    *expectation_set = true;
    Ok(())
}

fn set_check_wait(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("check --wait may only be specified once".into());
    }
    cli.check_wait_ms = Some(parse_check_duration_ms(value)?);
    *value_set = true;
    Ok(())
}

fn parse_check_duration_ms(value: &str) -> Result<u64, String> {
    let normalized = value.trim().to_ascii_lowercase();
    let (number, multiplier) = if let Some(number) = normalized.strip_suffix("ms") {
        (number, 1.0)
    } else if let Some(number) = normalized.strip_suffix('s') {
        (number, 1_000.0)
    } else if let Some(number) = normalized.strip_suffix('m') {
        (number, 60_000.0)
    } else if let Some(number) = normalized.strip_suffix('h') {
        (number, 3_600_000.0)
    } else {
        return Err(format!(
            "invalid check --wait duration: {value}; include ms, s, m, or h"
        ));
    };
    let amount = number
        .parse::<f64>()
        .map_err(|_| format!("invalid check --wait duration: {value}"))?;
    let milliseconds = amount * multiplier;
    if !milliseconds.is_finite() || !(100.0..=86_400_000.0).contains(&milliseconds) {
        return Err("check --wait must be between 100ms and 24h".into());
    }
    Ok(milliseconds.ceil() as u64)
}

fn set_check_interval(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("check --interval-ms may only be specified once".into());
    }
    let interval = value
        .parse::<u64>()
        .map_err(|_| format!("invalid check --interval-ms value: {value}"))?;
    if !(100..=60_000).contains(&interval) {
        return Err("check --interval-ms must be between 100 and 60000".into());
    }
    cli.check_interval_ms = interval;
    *value_set = true;
    Ok(())
}

fn set_check_stable(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("check --stable may only be specified once".into());
    }
    let samples = value
        .parse::<usize>()
        .map_err(|_| format!("invalid check --stable value: {value}"))?;
    if !(1..=1_000).contains(&samples) {
        return Err("check --stable must be between 1 and 1000".into());
    }
    cli.check_stable_samples = samples;
    *value_set = true;
    Ok(())
}

fn parse_expectation(value: &str) -> Result<CheckExpectation, String> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(CheckExpectation::None),
        "any" => Ok(CheckExpectation::Any),
        _ => Err(format!("invalid --expect value: {value}; use none or any")),
    }
}

fn parse_diff(arguments: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        mode: LaunchMode::DiffTable,
        ..Cli::default()
    };
    let mut output_mode = None;
    let mut fail_on_set = false;
    let mut output_path_set = false;
    let mut paths = Vec::new();
    let mut arguments = arguments.iter().cloned().peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "-h" | "--help" => cli.mode = LaunchMode::Help,
            "-V" | "--version" => cli.mode = LaunchMode::Version,
            "--table" => {
                set_diff_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::DiffTable)?
            }
            "--json" => {
                set_diff_output_mode(&mut cli.mode, &mut output_mode, LaunchMode::DiffJson)?;
            }
            "--quiet" => cli.quiet = true,
            "--force" => cli.diff_force = true,
            "--fail-on" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "diff --fail-on requires never or regression".to_string())?;
                set_diff_fail_on(&mut cli, &mut fail_on_set, &value)?;
            }
            "--output" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "diff --output requires a file path".to_string())?;
                set_diff_output_path(&mut cli, &mut output_path_set, value)?;
            }
            _ if argument.starts_with("--fail-on=") => {
                set_diff_fail_on(
                    &mut cli,
                    &mut fail_on_set,
                    argument.trim_start_matches("--fail-on="),
                )?;
            }
            _ if argument.starts_with("--output=") => {
                set_diff_output_path(
                    &mut cli,
                    &mut output_path_set,
                    argument.trim_start_matches("--output=").to_string(),
                )?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown diff option: {argument}"));
            }
            _ => paths.push(argument),
        }
    }
    if matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(cli);
    }
    if paths.len() != 2 {
        return Err(format!(
            "diff requires BEFORE.json and AFTER.json; received {} path(s)",
            paths.len()
        ));
    }
    if cli.diff_output.is_some() {
        if output_mode == Some(LaunchMode::DiffTable) {
            return Err("diff --output writes JSON and cannot be combined with --table".into());
        }
        cli.mode = LaunchMode::DiffJson;
    }
    if cli.diff_force && cli.diff_output.is_none() {
        return Err("diff --force requires --output FILE".into());
    }
    if cli.quiet && cli.diff_fail_on == DiffFailOn::Never && cli.diff_output.is_none() {
        return Err("diff --quiet requires --fail-on regression or --output FILE".into());
    }
    cli.diff_paths = Some((paths.remove(0), paths.remove(0)));
    Ok(cli)
}

fn set_diff_fail_on(cli: &mut Cli, value_set: &mut bool, value: &str) -> Result<(), String> {
    if *value_set {
        return Err("diff --fail-on may only be specified once".into());
    }
    cli.diff_fail_on = match value.to_ascii_lowercase().as_str() {
        "never" | "none" => DiffFailOn::Never,
        "regression" | "regress" => DiffFailOn::Regression,
        _ => {
            return Err(format!(
                "invalid diff --fail-on value: {value}; use never or regression"
            ));
        }
    };
    *value_set = true;
    Ok(())
}

fn set_diff_output_path(cli: &mut Cli, value_set: &mut bool, value: String) -> Result<(), String> {
    if *value_set {
        return Err("diff --output may only be specified once".into());
    }
    if value.is_empty() || value == "-" {
        return Err("diff --output requires a file path; use --json for stdout".into());
    }
    cli.diff_output = Some(value);
    *value_set = true;
    Ok(())
}

fn set_diff_output_mode(
    mode: &mut LaunchMode,
    output_mode: &mut Option<LaunchMode>,
    requested: LaunchMode,
) -> Result<(), String> {
    if output_mode.is_some_and(|existing| existing != requested) {
        return Err("diff --table and --json cannot be used together".into());
    }
    *output_mode = Some(requested);
    if !matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        *mode = requested;
    }
    Ok(())
}

fn set_output_mode(cli: &mut Cli, mode: LaunchMode) -> Result<(), String> {
    if matches!(cli.mode, LaunchMode::Table | LaunchMode::Json) && cli.mode != mode {
        return Err("--table and --json cannot be used together".into());
    }
    if !matches!(cli.mode, LaunchMode::Help | LaunchMode::Version) {
        cli.mode = mode;
    }
    Ok(())
}

fn set_query(cli: &mut Cli, query_set: &mut bool, value: String) -> Result<(), String> {
    if *query_set {
        return Err("--query may only be specified once".into());
    }
    if value.trim().is_empty() {
        return Err("--query requires a non-empty value".into());
    }
    cli.query = value;
    *query_set = true;
    Ok(())
}

fn set_sample_ms(cli: &mut Cli, sample_set: &mut bool, value: &str) -> Result<(), String> {
    if *sample_set {
        return Err("--sample-ms may only be specified once".into());
    }
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("invalid --sample-ms value: {value}"))?;
    if !(100..=60_000).contains(&milliseconds) {
        return Err("--sample-ms must be between 100 and 60000".into());
    }
    cli.sample_ms = milliseconds;
    *sample_set = true;
    Ok(())
}

pub(crate) fn help_text(topic: Option<HelpTopic>) -> &'static str {
    match topic {
        None => {
            "psmore - cross-platform process relationship diagnostics

USAGE:
  psmore [--query QUERY]
  psmore --table|--json [--query QUERY] [--sample-ms MS]
  psmore COMMAND [OPTIONS]

COMMANDS:
  check       Evaluate a process query as an operations health gate
  inspect     Inspect one process, threads, sockets, files, and context
  memory      Attribute one process RSS, PSS, swap, regions, and mappings
  explain     Build one prioritized process dossier from multiple evidence sources
  exe         Verify a process executable, disk drift, package, and signing
  stale       Find Linux processes still holding deleted or replaced executables
  service     Resolve a PID to its systemd or launchd service context
  logs        Read bounded native logs for one process or service instance
  port        Find the process and socket using a local port
  listen      Inventory listeners and classify non-loopback exposure
  net         Search all listeners and peer connections with process context
  tree        Print one PID's complete ancestor and descendant context
  watch       Stream process lifecycle and query transition events
  trace       Record process and complete-subtree resource time series
  run         Launch a command and profile its complete process subtree
  deleted     Find deleted files that processes still hold open
  file        Find processes executing, mapped to, or holding a path
  fd          Rank processes by open file-descriptor pressure
  top         Rank current CPU, memory, and disk I/O hotspots
  oom         Diagnose Linux memory pressure and OOM kill priority
  cgroup      Inventory Linux systemd/container resource boundaries
  doctor      Run conservative host and process triage in one command
  diff        Compare two process snapshots or host-doctor reports
  completion  Generate shell completion for bash, zsh, or fish

GLOBAL OPTIONS:
  -q, --query QUERY   Start the TUI filtered, or filter snapshot rows
      --no-tips       Skip first-run help or the startup tip for this TUI run
      --table         Print a human-readable process snapshot and exit
      --json          Print a versioned JSON process snapshot and exit
      --sample-ms MS  CPU and I/O sampling interval, 100-60000 [default: 500]
      --redact        Mask common secret values in emitted command lines
  -h, --help          Print help
  -V, --version       Print version

Run 'psmore COMMAND --help' for command-specific options and examples.
Query examples: 'name:python cpu>20'  'user:deploy mem>500m'  'tree.procs>=10'
"
        }
        Some(HelpTopic::Check) => {
            "psmore check - evaluate a process query as a health gate

USAGE:
  psmore check QUERY [--expect none|any] [--wait DURATION [--stable N]]
                     [--interval-ms MS] [--table|--json|--quiet] [--sample-ms MS]

OPTIONS:
      --expect MODE   none: require zero matches; any: require >=1 [default: none]
      --table         Human-readable result [default]
      --json          psmore.check-result JSON
      --quiet         Suppress output and use only the exit code
      --sample-ms MS  Sampling interval, 100-60000 [default: 500]
      --wait DURATION Retry until policy passes or 100ms-24h expires; >= sample-ms
      --interval-ms M Evaluation cadence while waiting, 100-60000 [default: 1000]
      --stable N      Require N consecutive passing evaluations, 1-1000 [default: 1]
      --redact        Mask common secret values in emitted command lines

The collector process is excluded from matching and ancestor tree aggregates,
so a psmore query cannot satisfy or violate its own gate.
EXIT: 0 policy passed, 1 runtime error, 2 usage/query error, 3 policy violated
EXAMPLES:
  psmore check 'state:zombie'
  psmore check 'name:api user:deploy' --expect any --quiet
  psmore check 'name:api user:deploy' --expect any --wait 30s --stable 3 --quiet
"
        }
        Some(HelpTopic::Inspect) => {
            "psmore inspect - deep inspection for one process instance

USAGE:
  psmore inspect PID [--table|--json] [--sample-ms MS]

OPTIONS:
      --table         Human-readable process, thread, socket, file, and context report [default]
      --json          psmore.process-inspection JSON
      --sample-ms MS  Process resource sampling interval, 100-60000 [default: 500]
      --redact        Mask common secret values in emitted command lines

The PID identity is revalidated after collection; confirmed PID reuse is refused.
EXAMPLES:
  psmore inspect 1234
  psmore inspect 1234 --json > process-1234.json
"
        }
        Some(HelpTopic::Memory) => {
            "psmore memory - attribute memory for one process instance

USAGE:
  psmore memory PID [--limit N|all] [--table|--json]

OPTIONS:
      --limit N|all  Maximum category and mapped-file rows per section [default: 20]
      --table        Human-readable summary, findings, categories, and mappings [default]
      --json         Versioned psmore.process-memory JSON
      --redact       Mask common secret values in the process command line

Linux reads smaps_rollup, status, and maps for RSS/PSS, anonymous/file/shared
resident memory, swap, limits, virtual categories, and top file mappings.
macOS uses vmmap summary evidence for physical footprint and resident/dirty/
swapped region categories. Linux mapped-file bytes are virtual, not resident;
macOS summary mode does not claim per-file attribution.
PID identity is revalidated and confirmed reuse is refused.
EXAMPLES:
  psmore memory 1234
  psmore memory 1234 --limit all --json > memory-1234.json
"
        }
        Some(HelpTopic::Explain) => {
            "psmore explain - build a prioritized evidence dossier for one process

USAGE:
  psmore explain PID [--no-logs] [--scope auto|process|service]
                     [--since DURATION] [--priority LEVEL] [--limit N]
                     [--no-hash] [--sample-ms MS] [--table|--json]
                     [--output FILE [--force]]

OPTIONS:
      --no-logs        Skip native logs; cannot combine with log filter options
      --scope SCOPE    Native-log scope: auto, process, or service [default: auto]
      --since DURATION Native-log window, 1s-7d [default: 15m]
      --priority LEVEL Native-log verbosity: error, warning, info, debug [default: info]
      --limit N        Maximum native-log entries, 1-1000 [default: 100]
      --no-hash        Skip executable SHA-256 while retaining identity/provenance
      --sample-ms MS   Process/thread sampling interval [default: 500]
      --table          Prioritized signals followed by original evidence [default]
      --json           psmore.process-dossier JSON with nested source reports
      --output FILE    Atomically write private JSON instead of printing it
      --force          Replace an existing --output regular file atomically
      --redact         Best-effort masking across commands and optional log messages

Inspection, service-manager context, and executable provenance are collected in
parallel with bounded native logs. Every section keeps its original versioned
report, coverage, and identity evidence; ranked signals link back to JSON
evidence paths and are review priorities, not asserted root causes. Use
--no-logs when log collection is too sensitive or unnecessary.
EXAMPLES:
  psmore explain 1234
  psmore explain 1234 --since 30m --priority warning
  psmore explain 1234 --output process-1234.dossier.json --redact
"
        }
        Some(HelpTopic::Exe) => {
            "psmore exe - verify the executable image held by one process

USAGE:
  psmore exe PID [--table|--json] [--no-hash]

OPTIONS:
      --table    Human-readable image identity and provenance report [default]
      --json     psmore.executable-image JSON
      --no-hash  Skip SHA-256 reads; file identity and package/signing remain
      --redact   Mask common secret values in the process command line

Linux compares /proc/PID/exe device/inode and hash evidence with the current
disk path, detecting unlinked or replaced running images. macOS verifies the
current path's code signature and reports that independent mapped-image identity
is unavailable. Hashing is capped at 1 GiB per image and PID identity is
revalidated after collection.
EXAMPLES:
  psmore exe 1234
  psmore exe 1234 --json > executable-1234.json
  psmore exe 1234 --no-hash
"
        }
        Some(HelpTopic::Stale) => {
            "psmore stale - find Linux processes that still hold obsolete executables

USAGE:
  psmore stale [QUERY] [--limit N|all] [--table|--json]
               [--expect none|any] [--quiet] [--sample-ms MS]

OPTIONS:
  -q, --query QUERY  Positional QUERY alternative; full psmore query language
      --limit N|all  Maximum returned stale processes [default: 100]
      --table        Human-readable restart-review list [default]
      --json         psmore.stale-executables JSON
      --expect MODE  Apply none/any health-gate policy before truncation
      --quiet        Suppress output; requires --expect
      --sample-ms M  Process query sampling interval [default: 500]
      --redact       Mask common secret values in process command lines

Linux only. /proc/PID/exe is compared with the current disk path by device and
inode. A zero-match none policy is inconclusive when any query-eligible image
was unreadable or raced with collection. psmore prints service owners and
per-PID `psmore exe` follow-ups but never restarts a process.
EXIT: 0 success/pass, 1 unsupported/error/inconclusive, 2 usage, 3 violation
EXAMPLES:
  psmore stale
  psmore stale 'user:deploy age>5m' --limit all
  psmore stale --expect none --quiet
"
        }
        Some(HelpTopic::Service) => {
            "psmore service - resolve one process to its service-manager context

USAGE:
  psmore service PID [--table|--json]

OPTIONS:
      --table   Human-readable manager, state, config, resources, and next steps [default]
      --json    psmore.service-context JSON
      --redact  Mask common secret values in the process command line

Linux reads the process cgroup and queries systemd's machine-readable show
properties. macOS maps the process ancestor chain through the current launchd
bootstrap namespace. Collection is read-only and PID identity is revalidated.
EXAMPLES:
  psmore service 1234
  psmore service 1234 --json > service-1234.json
"
        }
        Some(HelpTopic::Logs) => {
            "psmore logs - read bounded native logs for one process or service

USAGE:
  psmore logs PID [--scope auto|process|service] [--since DURATION]
                  [--priority error|warning|info|debug] [--limit N]
                  [--table|--json]

OPTIONS:
      --scope SCOPE    Linux auto selects a systemd unit when available; process
                       forces exact PID logs; service requires a managed unit
                       [default: auto]
      --since DURATION Recent time window, 1s-7d [default: 15m]
      --priority LEVEL Maximum verbosity [default: info]
      --limit N        Newest entries to retain, 1-1000 [default: 100]
      --table          Human-readable newest-first log context [default]
      --json           psmore.process-logs JSON
      --redact         Best-effort masking of common secret values in messages

Linux reads journald and auto-correlates the PID's cgroup with its systemd unit,
so restarts inside the selected window remain visible. macOS reads Unified
Logging for the exact PID and clamps the window to the process start time.
Collection is read-only, bounded, and revalidates PID identity afterward.
EXAMPLES:
  psmore logs 1234
  psmore logs 1234 --scope process --since 2m --priority debug
  psmore logs 1234 --json --redact > logs-1234.safe.json
"
        }
        Some(HelpTopic::Port) => {
            "psmore port - inspect one exact local TCP/UDP port

USAGE:
  psmore port PORT [--protocol tcp|udp|any] [--all] [--table|--json]
                   [--expect none|any] [--quiet]

OPTIONS:
      --protocol P   tcp, udp, or any [default: any]
      --all          Include non-listening local connections
      --expect MODE  Apply none/any health-gate policy
      --quiet        Suppress output; requires --expect
      --redact       Mask common secret values in emitted command lines

EXIT: 0 success/pass, 1 error or inconclusive absence, 2 usage, 3 violation
EXAMPLES:
  psmore port 8080
  psmore port 53 --protocol udp --json
  psmore port 8080 --expect any --quiet
"
        }
        Some(HelpTopic::Listen) => {
            "psmore listen - inventory listeners and host exposure

USAGE:
  psmore listen [FILTER] [--protocol tcp|udp|unix|any] [--exposed]
                 [--limit N|all] [--table|--json] [--expect none|any] [--quiet]

OPTIONS:
  -q, --query TEXT   FILTER alternative; searches owner, command, address, and namespace
      --protocol P   tcp, udp, unix, or any [default: any]
      --exposed      Keep wildcard and non-loopback network binds only
      --limit N|all  Maximum returned socket references [default: 100]
      --expect MODE  Apply none/any health-gate policy
      --quiet        Suppress output; requires --expect
      --redact       Mask common secret values in emitted command lines

EXAMPLES:
  psmore listen --exposed --protocol tcp
  psmore listen nginx --limit all --json
  psmore listen debug --exposed --expect none --quiet
"
        }
        Some(HelpTopic::Net) => {
            "psmore net - search all sockets, peer endpoints, and process owners

USAGE:
  psmore net [FILTER] [--protocol tcp|udp|unix|any] [--connected]
             [--state STATE] [--limit N|all] [--table|--json]
             [--expect none|any] [--quiet]

OPTIONS:
  -q, --query TEXT  FILTER alternative; searches routes, owners, commands, and namespace
      --protocol P  tcp, udp, unix, or any [default: any]
      --connected   Keep non-terminal peer connections; exclude listeners, binds, and CLOSED
      --state S     Exact normalized state, e.g. ESTABLISHED, TIME_WAIT, CONNECTED
      --limit N|all Maximum returned socket references [default: 100]
      --table       Human-readable route and owner evidence [default]
      --json        Versioned psmore.network-connections JSON
      --expect MODE Apply none/any health-gate policy to all matches
      --quiet       Suppress output; requires --expect
      --redact      Mask common secret values in emitted command lines

Local and peer endpoints are kernel evidence. psmore does not guess whether an
established route was initiated inbound or outbound without packet/flow state.
EXAMPLES:
  psmore net --connected --protocol tcp
  psmore net 203.0.113.10 --state established
  psmore net worker --connected --limit all --json
  psmore net 198.51.100.20 --expect none --quiet
"
        }
        Some(HelpTopic::Tree) => {
            "psmore tree - print one process relationship context

USAGE:
  psmore tree PID [--depth 0-128|all] [--table|--json] [--sample-ms MS]

OPTIONS:
      --depth N      Descendant depth; ancestors remain complete [default: all]
      --table        Directory-style tree with own/subtree resources [default]
      --json         Nested psmore.process-tree JSON
      --sample-ms MS Sampling interval, 100-60000 [default: 500]
      --redact       Mask common secret values in emitted command lines

EXAMPLES:
  psmore tree 1234 --depth 2
  psmore tree 0 --depth 3 --json
"
        }
        Some(HelpTopic::Watch) => {
            "psmore watch - stream lifecycle and query transition events

USAGE:
  psmore watch [QUERY] [--table|--jsonl] [--interval-ms MS] [--count N]

OPTIONS:
  -q, --query QUERY  Positional QUERY alternative
      --table        Human-readable event stream [default]
      --jsonl        One psmore.process-watch-event document per record
      --interval-ms  Refresh interval, 100-60000 [default: 1000]
      --count N      Stop after N post-baseline refreshes [default: unlimited]
      --redact       Mask common secret values in emitted command lines

EXAMPLES:
  psmore watch 'cpu>80 age>5s' --interval-ms 250
  psmore watch name:api --jsonl --count 20
"
        }
        Some(HelpTopic::Trace) => {
            "psmore trace - record one process and service-subtree time series

USAGE:
  psmore trace PID [--table|--jsonl] [--interval-ms MS] [--count N]

OPTIONS:
      --table        Live own/subtree CPU, memory, growth, and I/O rows [default]
      --jsonl        Baseline, sample, lifecycle, and complete JSON records
      --interval-ms  Target refresh interval, 100-60000 [default: 1000]
      --count N      Stop after N post-baseline samples [default: unlimited]
      --redact       Mask common secret values in emitted command lines

Trace never follows a reused PID into a new process instance.
EXAMPLES:
  psmore trace 1234 --interval-ms 250 --count 40
  psmore trace 1234 --jsonl > trace-1234.jsonl
"
        }
        Some(HelpTopic::Run) => {
            "psmore run - launch a command and profile its complete process subtree

USAGE:
  psmore run [--table|--json] [--interval-ms MS] [--linger-ms MS] -- COMMAND [ARG...]
  psmore run --output REPORT.json [--force] [OPTIONS] -- COMMAND [ARG...]

OPTIONS:
      --table          Human-readable final profile [default]
      --json           psmore.command-profile JSON
      --interval-ms MS Sampling interval, 100-60000 [default: 100]
      --linger-ms MS   Observe descendants this long after COMMAND exits, 0-60000 [default: 1000]
      --output FILE    Atomically write a private JSON report; refuses overwrite
      --force          Allow --output to replace an existing regular file
      --redact          Mask common secret values in the emitted command lines

COMMAND inherits stdin, stdout, and stderr. The profile is written to psmore's
stderr so command stdout remains safe for pipes. psmore mirrors COMMAND's exit
code; a Unix signal is reported using the conventional 128+signal status.
With --output, COMMAND stderr remains untouched and the JSON report is mode 0600.
Sampling is observational and explicitly reports short-process blind spots.
EXAMPLES:
  psmore run -- make test
  psmore run --interval-ms 250 -- ./server --config ./dev.toml
  psmore run --output profile.json -- sh -c 'worker & wait'
"
        }
        Some(HelpTopic::Deleted) => {
            "psmore deleted - find deleted files still held open

USAGE:
  psmore deleted [--min-size SIZE] [--table|--json] [--expect none|any] [--quiet]

OPTIONS:
      --min-size SIZE Filter estimated reclaimable bytes; accepts k/m/g/t units
      --table         Human-readable owner and file evidence [default]
      --json          psmore.deleted-open-files JSON
      --expect MODE   Apply none/any policy to unique matching files
      --quiet         Suppress output; requires --expect
      --redact        Mask common secret values in emitted command lines

EXIT: 0 success/pass, 1 error or inconclusive absence, 2 usage, 3 violation
EXAMPLES:
  psmore deleted --min-size 100m
  psmore deleted --min-size 1g --expect none --quiet
"
        }
        Some(HelpTopic::File) => {
            "psmore file - find processes using a file or directory

USAGE:
  psmore file PATH [--recursive] [--limit N|all] [--table|--json]
                   [--expect none|any] [--quiet]

OPTIONS:
      --recursive  Match PATH and every descendant (useful for mounts/directories)
      --limit N    Maximum evidence rows [default: 100; all disables truncation]
      --table      Human-readable EXEC/CWD/ROOT/OPEN/MAPPED evidence [default]
      --json       psmore.file-usage JSON
      --expect M   Apply none/any policy to all matches before --limit
      --quiet      Suppress output; requires --expect
      --redact     Mask common secret values in emitted command lines

Relative paths are resolved from the current directory. Existing targets are
canonicalized, and exact file matching also recognizes the same device/inode.
The psmore collector and its helpers are excluded. Zero visible matches with
incomplete process coverage are inconclusive and exit 1, never a false pass.
EXIT: 0 success/pass, 1 runtime/inconclusive, 2 usage, 3 policy violation
EXAMPLES:
  psmore file ./config.yaml
  psmore file /Volumes/data --recursive --limit all
  psmore file /srv/release --recursive --expect none --quiet
"
        }
        Some(HelpTopic::Fd) => {
            "psmore fd - rank open file-descriptor pressure

USAGE:
  psmore fd [--min-count N] [--min-percent P] [--limit N|all]
            [--table|--json] [--expect none|any] [--quiet]

OPTIONS:
      --min-count N    Require at least N open descriptors [default: 1]
      --min-percent P  Require 1-100% soft-limit utilization
      --limit N|all    Maximum returned process rows [default: 20]
      --expect MODE    Apply none/any policy to all matches
      --quiet          Suppress output; requires --expect
      --redact         Mask common secret values in emitted command lines

Count and percent filters use AND semantics. Linux exposes per-process limits;
macOS reports limit utilization as unknown rather than inventing a percentage.
EXAMPLES:
  psmore fd --min-percent 80
  psmore fd --min-count 4096 --expect none --quiet
"
        }
        Some(HelpTopic::Top) => {
            "psmore top - rank current process and service-tree hotspots

USAGE:
  psmore top [QUERY] [--by cpu|memory|read|write] [--scope process|tree]
             [--limit N|all] [--table|--json] [--sample-ms MS]

OPTIONS:
  -q, --query QUERY  Positional QUERY alternative; uses the full query language
      --by METRIC    Ranking metric [default: cpu]
      --scope SCOPE  Rank process self or complete service subtree [default: process]
      --limit N|all  Maximum returned rows [default: 20]
      --table        Human-readable ranked evidence [default]
      --json         Versioned psmore.process-top JSON
      --sample-ms MS CPU and I/O sampling interval, 100-60000 [default: 500]
      --redact       Mask common secret values in emitted command lines

The psmore collector process is excluded from ranking. Ties use name then PID.
EXAMPLES:
  psmore top --by memory --limit 10
  psmore top 'user:deploy age>1m' --by cpu
  psmore top name:api --scope tree --by write --json
"
        }
        Some(HelpTopic::Oom) => {
            "psmore oom - diagnose Linux memory pressure and OOM selection priority

USAGE:
  psmore oom [QUERY] [--min-score 0-1000] [--limit N|all]
             [--table|--json] [--expect none|any] [--quiet] [--sample-ms MS]

OPTIONS:
  -q, --query QUERY  Positional QUERY alternative; uses the full query language
      --min-score N  Minimum kernel oom_score [default: 1]
      --limit N|all  Maximum returned candidates [default: 20]
      --table         Human-readable host pressure and candidate evidence [default]
      --json          Versioned psmore.oom-diagnostics JSON
      --expect MODE   Apply none/any health-gate policy to all matching candidates
      --quiet         Suppress output; requires --expect
      --sample-ms MS  Process sampling interval, 100-60000 [default: 500]
      --redact        Mask common secret values in emitted command lines

Linux only. A high oom_score describes relative kill selection priority; host
PSI, available memory, swap, and OOM event counters determine actual pressure.
EXIT: 0 success/pass, 1 unsupported/error/inconclusive, 2 usage, 3 violation
EXAMPLES:
  psmore oom --limit 10
  psmore oom 'user:deploy tree.mem>1g' --min-score 500
  psmore oom name:api --min-score 700 --expect none --quiet
"
        }
        Some(HelpTopic::Cgroup) => {
            "psmore cgroup - inventory Linux systemd/container resource boundaries

USAGE:
  psmore cgroup [FILTER] [--by cpu|memory|pressure|processes]
                 [--limit N|all] [--table|--json] [--sample-ms MS]

OPTIONS:
  -q, --query TEXT  FILTER alternative; searches group and process context
      --by METRIC   Sort by sampled CPU, kernel memory, limit pressure, or PIDs
                    [default: memory]
      --limit N|all Maximum returned leaf groups [default: 20]
      --table       Human-readable boundary and member evidence [default]
      --json        Versioned psmore.linux-cgroups JSON
      --sample-ms M Process CPU and I/O sampling interval [default: 500]
      --redact      Mask common secret values in process command lines

Linux only. Process RSS and rates sum visible direct members; memory.current,
limits, PID counts, CPU/I/O totals, and OOM events are hierarchical kernel
evidence. Missing membership is reported as partial rather than ignored.
EXAMPLES:
  psmore cgroup
  psmore cgroup docker --by pressure --limit all
  psmore cgroup api.service --json
"
        }
        Some(HelpTopic::Doctor) => {
            "psmore doctor - run conservative host and process triage

USAGE:
  psmore doctor [QUERY] [--deep] [--limit N|all] [--table|--json]
                [--output FILE [--force]] [--fail-on never|warning|critical]
                [--quiet] [--sample-ms MS]

OPTIONS:
  -q, --query QUERY  Scope quick process signals/hotspots; host/deep checks stay global
      --deep         Also scan exposure, FD pressure, deleted files, and Linux OOM/PSI
      --limit N|all  Maximum process evidence rows per section [default: 5]
      --table        Human-readable findings, evidence, and hotspots [default]
      --json         Versioned psmore.host-doctor JSON
      --output FILE  Atomically write private JSON instead of the report to stdout
      --force        Atomically replace FILE; default refuses an existing path
      --fail-on L    Exit 3 at warning or critical severity [default: never]
      --quiet        Suppress stdout; requires a gate threshold or --output
      --sample-ms MS CPU and I/O sampling interval, 100-60000 [default: 500]
      --redact       Mask common secret values in emitted command lines

Doctor reports sampled signals, not confirmed root causes. Default mode checks
effective memory, swap, load, process states/resources, and four hotspot lists.
Deep scans run concurrently and may expose additional permission gaps.
EXIT: 0 report/pass, 1 runtime error, 2 usage/query error, 3 threshold reached
EXAMPLES:
  psmore doctor
  psmore doctor 'user:deploy' --limit 10
  psmore doctor --deep
  psmore doctor --json --redact > doctor.json
  psmore doctor --deep --redact --output doctor.safe.json
  psmore doctor --fail-on critical --quiet
"
        }
        Some(HelpTopic::Diff) => {
            "psmore diff - compare two persistent diagnostic reports

USAGE:
  psmore diff BEFORE.json AFTER.json [--table|--json]
              [--output FILE [--force]] [--fail-on never|regression] [--quiet]

OPTIONS:
      --table      Human-readable lifecycle or health-evidence delta [default]
      --json       Versioned machine-readable difference
      --output F   Atomically write private JSON instead of the report to stdout
      --force      Atomically replace F; default refuses an existing path
      --fail-on L  Exit 3 for a doctor regression [default: never]
      --quiet      Suppress stdout; requires --fail-on regression or --output
      --redact     Mask common secret values in emitted command lines

Inputs may be either two psmore.process-snapshot v1 documents or two
psmore.host-doctor v1 documents. They must have the same host, platform, query
scope, and report kind, with AFTER not older than BEFORE. Doctor reports must
also both use --deep or both omit it.
For doctor reports, regression means any newly observed finding or warning to
critical escalation. A disappearance under incomplete deep evidence is marked
unconfirmed and never claimed as a resolution. Snapshot diffs do not accept
--fail-on regression because resource movement has no universal failure meaning.
EXIT: 0 report/pass, 1 read/write error, 2 usage/input-policy error, 3 regression
EXAMPLES:
  psmore --json > before.json
  psmore --json > after.json
  psmore diff before.json after.json
  psmore doctor --deep --output doctor-before.json
  psmore doctor --deep --output doctor-after.json
  psmore diff doctor-before.json doctor-after.json
  psmore diff doctor-before.json doctor-after.json --fail-on regression --quiet
  psmore diff doctor-before.json doctor-after.json --fail-on regression \
    --output doctor-regression.json
"
        }
        Some(HelpTopic::Completion) => {
            "psmore completion - generate shell completion

USAGE:
  psmore completion bash|zsh|fish

EXAMPLES:
  source <(psmore completion bash)
  psmore completion zsh > ~/.zfunc/_psmore
  psmore completion fish > ~/.config/fish/completions/psmore.fish

Generated scripts include all commands, command-specific options, and enum
values such as protocols, expectations, output formats, and 'all' limits.
"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tui_and_headless_modes_without_changing_defaults() {
        assert_eq!(Cli::parse(Vec::<String>::new()).unwrap(), Cli::default());
        assert_eq!(
            Cli::parse(["--query", "name:python cpu>20"]).unwrap(),
            Cli {
                query: "name:python cpu>20".into(),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["--json", "--query=user:deploy", "--sample-ms=1200"]).unwrap(),
            Cli {
                mode: LaunchMode::Json,
                help_topic: None,
                completion_shell: None,
                query: "user:deploy".into(),
                tui_no_tips: false,
                sample_ms: 1_200,
                diff_paths: None,
                diff_fail_on: DiffFailOn::Never,
                diff_output: None,
                diff_force: false,
                inspect_pid: None,
                memory_pid: None,
                memory_limit: Some(20),
                exe_pid: None,
                exe_hash: true,
                stale_limit: Some(100),
                stale_expectation: None,
                service_pid: None,
                logs_pid: None,
                logs_scope: LogScope::Auto,
                logs_priority: LogPriority::Info,
                logs_since_seconds: 900,
                logs_limit: 100,
                explain_pid: None,
                explain_include_logs: true,
                explain_output: None,
                explain_force: false,
                port: None,
                port_protocol: PortProtocol::Any,
                port_all: false,
                port_expectation: None,
                listen_protocol: ListenProtocol::Any,
                listen_exposed: false,
                listen_limit: Some(100),
                listen_expectation: None,
                tree_pid: None,
                tree_depth: None,
                watch_interval_ms: 1_000,
                watch_count: None,
                trace_pid: None,
                trace_interval_ms: 1_000,
                trace_count: None,
                run_command: Vec::new(),
                run_interval_ms: 100,
                run_descendant_grace_ms: 1_000,
                run_output: None,
                run_force: false,
                cgroup_sort: CgroupSort::Memory,
                cgroup_limit: Some(20),
                deleted_min_size: 0,
                deleted_expectation: None,
                file_path: None,
                file_recursive: false,
                file_limit: Some(100),
                file_expectation: None,
                fd_min_count: 1,
                fd_min_percent: None,
                fd_limit: Some(20),
                fd_expectation: None,
                top_metric: HotspotMetric::Cpu,
                top_scope: HotspotScope::Process,
                top_limit: Some(20),
                oom_min_score: 1,
                oom_limit: Some(20),
                oom_expectation: None,
                net_protocol: ListenProtocol::Any,
                net_connected_only: false,
                net_state: None,
                net_limit: Some(100),
                net_expectation: None,
                doctor_limit: Some(5),
                doctor_fail_on: DoctorFailOn::Never,
                doctor_deep: false,
                doctor_output: None,
                doctor_force: false,
                redact_secrets: false,
                check_expectation: CheckExpectation::None,
                check_wait_ms: None,
                check_interval_ms: 1_000,
                check_stable_samples: 1,
                quiet: false,
            }
        );
        assert_eq!(
            Cli::parse([
                "check",
                "state:zombie",
                "cpu>20",
                "--expect",
                "any",
                "--json",
                "--sample-ms=750"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::CheckJson,
                query: "state:zombie cpu>20".into(),
                sample_ms: 750,
                check_expectation: CheckExpectation::Any,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "check",
                "name:api",
                "--expect=any",
                "--wait",
                "1.5s",
                "--interval-ms=250",
                "--stable",
                "3",
                "--quiet"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::CheckTable,
                query: "name:api".into(),
                check_expectation: CheckExpectation::Any,
                check_wait_ms: Some(1_500),
                check_interval_ms: 250,
                check_stable_samples: 3,
                quiet: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["deleted", "--min-size=1.5g", "--json", "--expect", "none"]).unwrap(),
            Cli {
                mode: LaunchMode::DeletedJson,
                deleted_min_size: 1_610_612_736,
                deleted_expectation: Some(CheckExpectation::None),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "file",
                "./config",
                "--recursive",
                "--limit=all",
                "--json",
                "--expect=any",
                "--quiet"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::FileJson,
                file_path: Some("./config".into()),
                file_recursive: true,
                file_limit: None,
                file_expectation: Some(CheckExpectation::Any),
                quiet: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["file", "--", "--strange-path"])
                .unwrap()
                .file_path
                .as_deref(),
            Some("--strange-path")
        );
        let literal_redact = Cli::parse(["file", "--", "--redact"]).unwrap();
        assert_eq!(literal_redact.file_path.as_deref(), Some("--redact"));
        assert!(!literal_redact.redact_secrets);
        let redacted_literal = Cli::parse(["file", "--redact", "--", "--redact"]).unwrap();
        assert_eq!(redacted_literal.file_path.as_deref(), Some("--redact"));
        assert!(redacted_literal.redact_secrets);
        assert_eq!(
            Cli::parse([
                "fd",
                "--min-count=256",
                "--min-percent=80",
                "--limit",
                "all",
                "--json",
                "--expect",
                "none"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::FdJson,
                fd_min_count: 256,
                fd_min_percent: Some(80),
                fd_limit: None,
                fd_expectation: Some(CheckExpectation::None),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["tree", "42", "--depth=3", "--json", "--sample-ms", "250"]).unwrap(),
            Cli {
                mode: LaunchMode::TreeJson,
                sample_ms: 250,
                tree_pid: Some(42),
                tree_depth: Some(3),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["tree", "0", "--depth", "all"])
                .unwrap()
                .tree_pid,
            Some(0)
        );
        assert_eq!(
            Cli::parse([
                "watch",
                "name:worker",
                "cpu>20",
                "--jsonl",
                "--interval-ms=250",
                "--count",
                "4"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::WatchJsonl,
                query: "name:worker cpu>20".into(),
                watch_interval_ms: 250,
                watch_count: Some(4),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "trace",
                "4242",
                "--jsonl",
                "--interval-ms=250",
                "--count",
                "4"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::TraceJsonl,
                trace_pid: Some(4_242),
                trace_interval_ms: 250,
                trace_count: Some(4),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "run",
                "--json",
                "--interval-ms=250",
                "--linger-ms",
                "2000",
                "--",
                "worker",
                "--token",
                "literal"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::RunJson,
                run_command: vec!["worker".into(), "--token".into(), "literal".into()],
                run_interval_ms: 250,
                run_descendant_grace_ms: 2_000,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "cgroup",
                "docker",
                "api",
                "--by=pressure",
                "--limit",
                "all",
                "--json",
                "--sample-ms=750"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::CgroupJson,
                query: "docker api".into(),
                sample_ms: 750,
                cgroup_sort: CgroupSort::Pressure,
                cgroup_limit: None,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "run",
                "--output=profile.json",
                "--force",
                "--redact",
                "--",
                "worker",
                "--redact"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::RunJson,
                run_command: vec!["worker".into(), "--redact".into()],
                run_output: Some("profile.json".into()),
                run_force: true,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["diff", "before.json", "after.json", "--json"]).unwrap(),
            Cli {
                mode: LaunchMode::DiffJson,
                diff_paths: Some(("before.json".into(), "after.json".into())),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "diff",
                "before.json",
                "after.json",
                "--fail-on=regression",
                "--output",
                "diff.json",
                "--force",
                "--quiet"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::DiffJson,
                diff_paths: Some(("before.json".into(), "after.json".into())),
                diff_fail_on: DiffFailOn::Regression,
                diff_output: Some("diff.json".into()),
                diff_force: true,
                quiet: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["inspect", "1234", "--json", "--sample-ms=300"]).unwrap(),
            Cli {
                mode: LaunchMode::InspectJson,
                sample_ms: 300,
                inspect_pid: Some(1_234),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "explain",
                "4321",
                "--scope=service",
                "--since=30m",
                "--priority=warning",
                "--limit=40",
                "--sample-ms=750",
                "--no-hash",
                "--output=process-4321.dossier.json",
                "--force",
                "--redact",
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::ExplainJson,
                sample_ms: 750,
                exe_hash: false,
                logs_scope: LogScope::Service,
                logs_priority: LogPriority::Warning,
                logs_since_seconds: 1_800,
                logs_limit: 40,
                explain_pid: Some(4_321),
                explain_output: Some("process-4321.dossier.json".into()),
                explain_force: true,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["explain", "4321", "--no-logs", "--no-hash"]).unwrap(),
            Cli {
                mode: LaunchMode::ExplainTable,
                exe_hash: false,
                explain_pid: Some(4_321),
                explain_include_logs: false,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["service", "4321", "--json", "--redact"]).unwrap(),
            Cli {
                mode: LaunchMode::ServiceJson,
                service_pid: Some(4_321),
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "logs",
                "4321",
                "--scope=process",
                "--since",
                "2.5m",
                "--priority=debug",
                "--limit=250",
                "--json",
                "--redact",
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::LogsJson,
                logs_pid: Some(4_321),
                logs_scope: LogScope::Process,
                logs_priority: LogPriority::Debug,
                logs_since_seconds: 150,
                logs_limit: 250,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "explain",
                "4321",
                "--scope=service",
                "--since=2h",
                "--priority=warning",
                "--limit=250",
                "--no-hash",
                "--sample-ms=300",
                "--output=incident.json",
                "--force",
                "--redact",
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::ExplainJson,
                sample_ms: 300,
                exe_hash: false,
                logs_scope: LogScope::Service,
                logs_priority: LogPriority::Warning,
                logs_since_seconds: 7_200,
                logs_limit: 250,
                explain_pid: Some(4_321),
                explain_output: Some("incident.json".into()),
                explain_force: true,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["exe", "4321", "--json", "--no-hash", "--redact"]).unwrap(),
            Cli {
                mode: LaunchMode::ExeJson,
                exe_pid: Some(4_321),
                exe_hash: false,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "stale",
                "user:deploy",
                "age>5m",
                "--limit=all",
                "--json",
                "--expect=none",
                "--sample-ms=750",
                "--redact",
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::StaleJson,
                query: "user:deploy age>5m".into(),
                sample_ms: 750,
                stale_limit: None,
                stale_expectation: Some(CheckExpectation::None),
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "port",
                "8080",
                "--protocol=tcp",
                "--all",
                "--json",
                "--expect",
                "any"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::PortJson,
                port: Some(8_080),
                port_protocol: PortProtocol::Tcp,
                port_all: true,
                port_expectation: Some(CheckExpectation::Any),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "listen",
                "api server",
                "--protocol=tcp",
                "--exposed",
                "--limit=all",
                "--json",
                "--expect=any"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::ListenJson,
                query: "api server".into(),
                listen_protocol: ListenProtocol::Tcp,
                listen_exposed: true,
                listen_limit: None,
                listen_expectation: Some(CheckExpectation::Any),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["completion", "zsh"]).unwrap(),
            Cli {
                mode: LaunchMode::Completion,
                completion_shell: Some(CompletionShell::Zsh),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["--redact", "top", "--by", "memory"]).unwrap(),
            Cli {
                mode: LaunchMode::TopTable,
                top_metric: HotspotMetric::Memory,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["--table", "--query", "--redact"])
                .unwrap()
                .query,
            "--redact"
        );
        assert!(Cli::parse(["--no-tips"]).unwrap().tui_no_tips);
        assert!(Cli::parse(["--no-onboarding"]).unwrap().tui_no_tips);
        assert_eq!(
            Cli::parse([
                "top",
                "user:deploy",
                "age>1m",
                "--by=mem",
                "--scope",
                "tree",
                "--limit=all",
                "--json",
                "--sample-ms",
                "750"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::TopJson,
                query: "user:deploy age>1m".into(),
                sample_ms: 750,
                top_metric: HotspotMetric::Memory,
                top_scope: HotspotScope::Subtree,
                top_limit: None,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "oom",
                "user:deploy",
                "tree.mem>1g",
                "--min-score=500",
                "--limit",
                "all",
                "--json",
                "--expect=none",
                "--sample-ms=750"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::OomJson,
                query: "user:deploy tree.mem>1g".into(),
                sample_ms: 750,
                oom_min_score: 500,
                oom_limit: None,
                oom_expectation: Some(CheckExpectation::None),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "net",
                "203.0.113.10",
                "--protocol=tcp",
                "--connected",
                "--state",
                "time-wait",
                "--limit=all",
                "--json",
                "--expect=any"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::NetJson,
                query: "203.0.113.10".into(),
                net_protocol: ListenProtocol::Tcp,
                net_connected_only: true,
                net_state: Some("TIME_WAIT".into()),
                net_limit: None,
                net_expectation: Some(CheckExpectation::Any),
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse([
                "doctor",
                "user:deploy",
                "age>1m",
                "--limit=all",
                "--json",
                "--fail-on=critical",
                "--sample-ms=750",
                "--deep",
                "--output=incident.json",
                "--force",
                "--redact"
            ])
            .unwrap(),
            Cli {
                mode: LaunchMode::DoctorJson,
                query: "user:deploy age>1m".into(),
                sample_ms: 750,
                doctor_limit: None,
                doctor_fail_on: DoctorFailOn::Critical,
                doctor_deep: true,
                doctor_output: Some("incident.json".into()),
                doctor_force: true,
                redact_secrets: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["doctor", "--fail-on", "warning", "--quiet"]).unwrap(),
            Cli {
                mode: LaunchMode::DoctorTable,
                doctor_fail_on: DoctorFailOn::Warning,
                quiet: true,
                ..Cli::default()
            }
        );
        assert_eq!(
            Cli::parse(["doctor", "--output", "doctor.json", "--quiet"]).unwrap(),
            Cli {
                mode: LaunchMode::DoctorJson,
                doctor_output: Some("doctor.json".into()),
                quiet: true,
                ..Cli::default()
            }
        );
        for (command, topic) in [
            ("check", HelpTopic::Check),
            ("inspect", HelpTopic::Inspect),
            ("memory", HelpTopic::Memory),
            ("explain", HelpTopic::Explain),
            ("exe", HelpTopic::Exe),
            ("stale", HelpTopic::Stale),
            ("service", HelpTopic::Service),
            ("logs", HelpTopic::Logs),
            ("port", HelpTopic::Port),
            ("listen", HelpTopic::Listen),
            ("tree", HelpTopic::Tree),
            ("watch", HelpTopic::Watch),
            ("trace", HelpTopic::Trace),
            ("run", HelpTopic::Run),
            ("cgroup", HelpTopic::Cgroup),
            ("deleted", HelpTopic::Deleted),
            ("file", HelpTopic::File),
            ("fd", HelpTopic::Fd),
            ("top", HelpTopic::Top),
            ("oom", HelpTopic::Oom),
            ("net", HelpTopic::Net),
            ("doctor", HelpTopic::Doctor),
            ("diff", HelpTopic::Diff),
            ("completion", HelpTopic::Completion),
        ] {
            let cli = Cli::parse([command, "--help"]).unwrap();
            assert_eq!(cli.mode, LaunchMode::Help);
            assert_eq!(cli.help_topic, Some(topic));
        }
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_cli_combinations() {
        assert!(Cli::parse(["--json", "--table"]).is_err());
        assert!(Cli::parse(["--sample-ms", "500"]).is_err());
        assert!(Cli::parse(["--table", "--sample-ms", "0"]).is_err());
        assert!(Cli::parse(["--query", ""]).is_err());
        assert!(Cli::parse(["python"]).is_err());
        assert!(Cli::parse(["--unknown"]).is_err());
        assert!(Cli::parse(["diff", "before.json"]).is_err());
        assert!(Cli::parse(["diff", "before.json", "after.json", "extra.json"]).is_err());
        assert!(Cli::parse(["diff", "before.json", "after.json", "--query=x"]).is_err());
        assert!(Cli::parse(["diff", "before.json", "after.json", "--table", "--json"]).is_err());
        assert!(Cli::parse(["check"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--expect=all"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--query", "name:worker"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--table", "--json"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=30"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=99ms"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=100ms"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=100ms", "--sample-ms=100"]).is_ok());
        assert!(Cli::parse(["check", "name:api", "--wait=25h"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=1s", "--wait=2s"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--interval-ms=250"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--stable=2"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=1s", "--stable=0"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=1s", "--stable=1001"]).is_err());
        assert!(Cli::parse(["check", "name:api", "--wait=1s", "--interval-ms=99"]).is_err());
        assert!(Cli::parse(["inspect"]).is_err());
        assert!(Cli::parse(["inspect", "0"]).is_err());
        assert!(Cli::parse(["inspect", "nope"]).is_err());
        assert!(Cli::parse(["inspect", "4294967294"]).is_err());
        assert!(Cli::parse(["inspect", "1", "2"]).is_err());
        assert!(Cli::parse(["inspect", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["port"]).is_err());
        assert!(Cli::parse(["port", "0"]).is_err());
        assert!(Cli::parse(["port", "65536"]).is_err());
        assert!(Cli::parse(["port", "80", "81"]).is_err());
        assert!(Cli::parse(["port", "80", "--protocol=sctp"]).is_err());
        assert!(Cli::parse(["port", "80", "--table", "--json"]).is_err());
        assert!(Cli::parse(["port", "80", "--quiet"]).is_err());
        assert!(Cli::parse(["listen", "--protocol=sctp"]).is_err());
        assert!(Cli::parse(["listen", "--table", "--json"]).is_err());
        assert!(Cli::parse(["listen", "--limit=0"]).is_err());
        assert!(Cli::parse(["listen", "--limit=10001"]).is_err());
        assert!(Cli::parse(["listen", "api", "--query=worker"]).is_err());
        assert!(Cli::parse(["listen", "--quiet"]).is_err());
        assert!(Cli::parse(["listen", "--expect=all"]).is_err());
        assert!(Cli::parse(["tree"]).is_err());
        assert!(Cli::parse(["tree", "nope"]).is_err());
        assert!(Cli::parse(["tree", "1", "2"]).is_err());
        assert!(Cli::parse(["tree", "1", "--depth=129"]).is_err());
        assert!(Cli::parse(["tree", "1", "--depth=all", "--depth=2"]).is_err());
        assert!(Cli::parse(["tree", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["watch", "--table", "--jsonl"]).is_err());
        assert!(Cli::parse(["watch", "--interval-ms=99"]).is_err());
        assert!(Cli::parse(["watch", "--count=0"]).is_err());
        assert!(Cli::parse(["watch", "name:a", "--query", "name:b"]).is_err());
        assert!(Cli::parse(["trace"]).is_err());
        assert!(Cli::parse(["trace", "0"]).is_err());
        assert!(Cli::parse(["trace", "nope"]).is_err());
        assert!(Cli::parse(["trace", "1", "2"]).is_err());
        assert!(Cli::parse(["trace", "1", "--table", "--jsonl"]).is_err());
        assert!(Cli::parse(["trace", "1", "--interval-ms=99"]).is_err());
        assert!(Cli::parse(["trace", "1", "--count=0"]).is_err());
        assert!(Cli::parse(["run"]).is_err());
        assert!(Cli::parse(["run", "worker"]).is_err());
        assert!(Cli::parse(["run", "--"]).is_err());
        assert!(Cli::parse(["run", "--table", "--json", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--interval-ms=99", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--linger-ms=60001", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--unknown", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--output=-", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--output=", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--output=a", "--output=b", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--force", "--", "worker"]).is_err());
        assert!(Cli::parse(["run", "--table", "--output=a", "--", "worker"]).is_err());
        assert!(Cli::parse(["service"]).is_err());
        assert!(Cli::parse(["service", "0"]).is_err());
        assert!(Cli::parse(["service", "nope"]).is_err());
        assert!(Cli::parse(["service", "1", "2"]).is_err());
        assert!(Cli::parse(["service", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["logs"]).is_err());
        assert!(Cli::parse(["logs", "0"]).is_err());
        assert!(Cli::parse(["logs", "nope"]).is_err());
        assert!(Cli::parse(["logs", "1", "2"]).is_err());
        assert!(Cli::parse(["logs", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["logs", "1", "--scope=host"]).is_err());
        assert!(Cli::parse(["logs", "1", "--priority=trace"]).is_err());
        assert!(Cli::parse(["logs", "1", "--since=0s"]).is_err());
        assert!(Cli::parse(["logs", "1", "--since=8d"]).is_err());
        assert!(Cli::parse(["logs", "1", "--limit=0"]).is_err());
        assert!(Cli::parse(["logs", "1", "--limit=1001"]).is_err());
        assert!(Cli::parse(["explain"]).is_err());
        assert!(Cli::parse(["explain", "0"]).is_err());
        assert!(Cli::parse(["explain", "nope"]).is_err());
        assert!(Cli::parse(["explain", "1", "2"]).is_err());
        assert!(Cli::parse(["explain", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["explain", "1", "--table", "--output=a.json"]).is_err());
        assert!(Cli::parse(["explain", "1", "--force"]).is_err());
        assert!(Cli::parse(["explain", "1", "--output=-"]).is_err());
        assert!(Cli::parse(["explain", "1", "--no-logs", "--no-logs"]).is_err());
        assert!(Cli::parse(["explain", "1", "--no-logs", "--scope=process"]).is_err());
        assert!(Cli::parse(["explain", "1", "--no-hash", "--no-hash"]).is_err());
        assert!(Cli::parse(["explain", "1", "--scope=host"]).is_err());
        assert!(Cli::parse(["explain", "1", "--since=8d"]).is_err());
        assert!(Cli::parse(["explain", "1", "--no-logs", "--since=1m"]).is_err());
        assert!(Cli::parse(["explain", "1", "--no-logs", "--priority=error"]).is_err());
        assert!(Cli::parse(["explain", "1", "--no-logs", "--limit=1"]).is_err());
        assert!(Cli::parse(["explain", "1", "--output="]).is_err());
        assert!(Cli::parse(["explain", "1", "--output=a", "--output=b"]).is_err());
        assert!(Cli::parse(["explain", "1", "--output=a", "--table"]).is_err());
        assert!(Cli::parse(["exe"]).is_err());
        assert!(Cli::parse(["exe", "0"]).is_err());
        assert!(Cli::parse(["exe", "nope"]).is_err());
        assert!(Cli::parse(["exe", "1", "2"]).is_err());
        assert!(Cli::parse(["exe", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["exe", "1", "--no-hash", "--no-hash"]).is_err());
        assert!(Cli::parse(["stale", "--table", "--json"]).is_err());
        assert!(Cli::parse(["stale", "api", "--query=worker"]).is_err());
        assert!(Cli::parse(["stale", "--limit=0"]).is_err());
        assert!(Cli::parse(["stale", "--limit=10001"]).is_err());
        assert!(Cli::parse(["stale", "--limit=1", "--limit=all"]).is_err());
        assert!(Cli::parse(["stale", "--sample-ms=99"]).is_err());
        assert!(Cli::parse(["stale", "--expect=all"]).is_err());
        assert!(Cli::parse(["stale", "--quiet"]).is_err());
        assert!(Cli::parse(["cgroup", "--by=io"]).is_err());
        assert!(Cli::parse(["cgroup", "--limit=0"]).is_err());
        assert!(Cli::parse(["cgroup", "--limit=10001"]).is_err());
        assert!(Cli::parse(["cgroup", "--table", "--json"]).is_err());
        assert!(Cli::parse(["cgroup", "api", "--query=worker"]).is_err());
        assert!(Cli::parse(["cgroup", "--sample-ms=99"]).is_err());
        assert!(Cli::parse(["deleted", "extra"]).is_err());
        assert!(Cli::parse(["deleted", "--min-size=nope"]).is_err());
        assert!(Cli::parse(["deleted", "--table", "--json"]).is_err());
        assert!(Cli::parse(["deleted", "--quiet"]).is_err());
        assert!(Cli::parse(["deleted", "--expect=all"]).is_err());
        assert!(Cli::parse(["fd", "extra"]).is_err());
        assert!(Cli::parse(["file"]).is_err());
        assert!(Cli::parse(["file", "a", "b"]).is_err());
        assert!(Cli::parse(["file", "a", "--table", "--json"]).is_err());
        assert!(Cli::parse(["file", "a", "--limit=0"]).is_err());
        assert!(Cli::parse(["file", "a", "--limit=10001"]).is_err());
        assert!(Cli::parse(["file", "a", "--limit=1", "--limit=all"]).is_err());
        assert!(Cli::parse(["file", "a", "--expect=all"]).is_err());
        assert!(Cli::parse(["file", "a", "--quiet"]).is_err());
        assert!(Cli::parse(["fd", "--min-count=nope"]).is_err());
        assert!(Cli::parse(["fd", "--min-percent=0"]).is_err());
        assert!(Cli::parse(["fd", "--min-percent=101"]).is_err());
        assert!(Cli::parse(["fd", "--min-percent=80", "--min-percent=90"]).is_err());
        assert!(Cli::parse(["fd", "--limit=0"]).is_err());
        assert!(Cli::parse(["fd", "--limit=10001"]).is_err());
        assert!(Cli::parse(["fd", "--limit=all", "--limit=20"]).is_err());
        assert!(Cli::parse(["fd", "--table", "--json"]).is_err());
        assert!(Cli::parse(["fd", "--quiet"]).is_err());
        assert!(Cli::parse(["fd", "--expect=all"]).is_err());
        assert!(Cli::parse(["top", "--by=load"]).is_err());
        assert!(Cli::parse(["top", "--scope=host"]).is_err());
        assert!(Cli::parse(["top", "--limit=0"]).is_err());
        assert!(Cli::parse(["top", "--limit=10001"]).is_err());
        assert!(Cli::parse(["top", "--limit=10", "--limit=all"]).is_err());
        assert!(Cli::parse(["top", "--table", "--json"]).is_err());
        assert!(Cli::parse(["top", "name:api", "--query=name:worker"]).is_err());
        assert!(Cli::parse(["top", "--sample-ms=99"]).is_err());
        assert!(Cli::parse(["oom", "--min-score=nope"]).is_err());
        assert!(Cli::parse(["oom", "--min-score=1001"]).is_err());
        assert!(Cli::parse(["oom", "--min-score=1", "--min-score=2"]).is_err());
        assert!(Cli::parse(["oom", "--limit=0"]).is_err());
        assert!(Cli::parse(["oom", "--limit=10001"]).is_err());
        assert!(Cli::parse(["oom", "--table", "--json"]).is_err());
        assert!(Cli::parse(["oom", "name:api", "--query=name:worker"]).is_err());
        assert!(Cli::parse(["oom", "--sample-ms=99"]).is_err());
        assert!(Cli::parse(["oom", "--expect=all"]).is_err());
        assert!(Cli::parse(["oom", "--quiet"]).is_err());
        assert!(Cli::parse(["net", "--protocol=sctp"]).is_err());
        assert!(Cli::parse(["net", "--state="]).is_err());
        assert!(Cli::parse(["net", "--state=bad state"]).is_err());
        assert!(Cli::parse(["net", "--state=x", "--state=y"]).is_err());
        assert!(Cli::parse(["net", "--limit=0"]).is_err());
        assert!(Cli::parse(["net", "--limit=10001"]).is_err());
        assert!(Cli::parse(["net", "--table", "--json"]).is_err());
        assert!(Cli::parse(["net", "api", "--query=worker"]).is_err());
        assert!(Cli::parse(["net", "--expect=all"]).is_err());
        assert!(Cli::parse(["net", "--quiet"]).is_err());
        assert!(Cli::parse(["doctor", "--limit=0"]).is_err());
        assert!(Cli::parse(["doctor", "--limit=10001"]).is_err());
        assert!(Cli::parse(["doctor", "--limit=1", "--limit=all"]).is_err());
        assert!(Cli::parse(["doctor", "--table", "--json"]).is_err());
        assert!(Cli::parse(["doctor", "api", "--query=worker"]).is_err());
        assert!(Cli::parse(["doctor", "--fail-on=error"]).is_err());
        assert!(Cli::parse(["doctor", "--fail-on=warning", "--fail-on=critical"]).is_err());
        assert!(Cli::parse(["doctor", "--quiet"]).is_err());
        assert!(Cli::parse(["doctor", "--sample-ms=99"]).is_err());
        assert!(Cli::parse(["doctor", "--output", "-"]).is_err());
        assert!(Cli::parse(["doctor", "--output="]).is_err());
        assert!(Cli::parse(["doctor", "--output=a", "--output=b"]).is_err());
        assert!(Cli::parse(["doctor", "--output=a", "--table"]).is_err());
        assert!(Cli::parse(["doctor", "--force"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--fail-on=warning"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--fail-on=never", "--fail-on=regression"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--quiet"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--force"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--output=-"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--output="]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--output=x", "--table"]).is_err());
        assert!(Cli::parse(["diff", "a", "b", "--output=x", "--output=y"]).is_err());
        assert!(Cli::parse(["--no-tips", "--no-tips"]).is_err());
        assert!(Cli::parse(["--no-tips", "--table"]).is_err());
        assert!(Cli::parse(["--redact"]).is_err());
        assert!(Cli::parse(["--redact", "--redact", "--table"]).is_err());
        assert!(Cli::parse(["completion"]).is_err());
        assert!(Cli::parse(["completion", "powershell"]).is_err());
        assert!(Cli::parse(["completion", "bash", "zsh"]).is_err());
        assert!(Cli::parse(["completion", "--unknown"]).is_err());
        assert!(Cli::parse(["memory"]).is_err());
        assert!(Cli::parse(["memory", "0"]).is_err());
        assert!(Cli::parse(["memory", "1", "2"]).is_err());
        assert!(Cli::parse(["memory", "1", "--table", "--json"]).is_err());
        assert!(Cli::parse(["memory", "1", "--limit=0"]).is_err());
        assert!(Cli::parse(["memory", "1", "--limit=10001"]).is_err());
        assert!(Cli::parse(["memory", "1", "--limit=1", "--limit=all"]).is_err());
    }

    #[test]
    fn contextual_help_is_command_specific_and_keeps_global_discovery() {
        let global = help_text(None);
        assert!(global.contains("psmore COMMAND [OPTIONS]"));
        assert!(global.contains("psmore COMMAND --help"));
        for (topic, command) in [
            (HelpTopic::Check, "check"),
            (HelpTopic::Inspect, "inspect"),
            (HelpTopic::Memory, "memory"),
            (HelpTopic::Explain, "explain"),
            (HelpTopic::Exe, "exe"),
            (HelpTopic::Stale, "stale"),
            (HelpTopic::Service, "service"),
            (HelpTopic::Port, "port"),
            (HelpTopic::Listen, "listen"),
            (HelpTopic::Tree, "tree"),
            (HelpTopic::Watch, "watch"),
            (HelpTopic::Trace, "trace"),
            (HelpTopic::Run, "run"),
            (HelpTopic::Cgroup, "cgroup"),
            (HelpTopic::Deleted, "deleted"),
            (HelpTopic::File, "file"),
            (HelpTopic::Fd, "fd"),
            (HelpTopic::Top, "top"),
            (HelpTopic::Oom, "oom"),
            (HelpTopic::Net, "net"),
            (HelpTopic::Doctor, "doctor"),
            (HelpTopic::Diff, "diff"),
            (HelpTopic::Completion, "completion"),
        ] {
            let help = help_text(Some(topic));
            assert!(help.starts_with(&format!("psmore {command} ")));
            assert!(help.contains("USAGE:"));
            assert_ne!(help, global);
        }
    }
}
