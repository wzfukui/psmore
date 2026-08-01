#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchMode {
    Tui,
    Table,
    Json,
    CheckTable,
    CheckJson,
    InspectTable,
    InspectJson,
    PortTable,
    PortJson,
    TreeTable,
    TreeJson,
    WatchTable,
    WatchJsonl,
    DeletedTable,
    DeletedJson,
    DiffTable,
    DiffJson,
    Help,
    Version,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum PortProtocol {
    #[default]
    Any,
    Tcp,
    Udp,
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
    pub(crate) query: String,
    pub(crate) sample_ms: u64,
    pub(crate) diff_paths: Option<(String, String)>,
    pub(crate) inspect_pid: Option<u32>,
    pub(crate) port: Option<u16>,
    pub(crate) port_protocol: PortProtocol,
    pub(crate) port_all: bool,
    pub(crate) port_expectation: Option<CheckExpectation>,
    pub(crate) tree_pid: Option<u32>,
    pub(crate) tree_depth: Option<usize>,
    pub(crate) watch_interval_ms: u64,
    pub(crate) watch_count: Option<usize>,
    pub(crate) deleted_min_size: u64,
    pub(crate) deleted_expectation: Option<CheckExpectation>,
    pub(crate) check_expectation: CheckExpectation,
    pub(crate) quiet: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            mode: LaunchMode::Tui,
            query: String::new(),
            sample_ms: 500,
            diff_paths: None,
            inspect_pid: None,
            port: None,
            port_protocol: PortProtocol::Any,
            port_all: false,
            port_expectation: None,
            tree_pid: None,
            tree_depth: None,
            watch_interval_ms: 1_000,
            watch_count: None,
            deleted_min_size: 0,
            deleted_expectation: None,
            check_expectation: CheckExpectation::None,
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
        let arguments: Vec<String> = args.into_iter().map(Into::into).collect();
        if arguments.first().map(String::as_str) == Some("watch") {
            return parse_watch(&arguments[1..]);
        }
        if arguments.first().map(String::as_str) == Some("deleted") {
            return parse_deleted(&arguments[1..]);
        }
        if arguments.first().map(String::as_str) == Some("check") {
            return parse_check(&arguments[1..]);
        }
        if arguments.first().map(String::as_str) == Some("inspect") {
            return parse_inspect(&arguments[1..]);
        }
        if arguments.first().map(String::as_str) == Some("port") {
            return parse_port(&arguments[1..]);
        }
        if arguments.first().map(String::as_str) == Some("tree") {
            return parse_tree(&arguments[1..]);
        }
        if arguments.first().map(String::as_str) == Some("diff") {
            return parse_diff(&arguments[1..]);
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
        Ok(cli)
    }
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

fn parse_expectation(value: &str) -> Result<CheckExpectation, String> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(CheckExpectation::None),
        "any" => Ok(CheckExpectation::Any),
        _ => Err(format!("invalid --expect value: {value}; use none or any")),
    }
}

fn parse_diff(arguments: &[String]) -> Result<Cli, String> {
    let mut mode = LaunchMode::DiffTable;
    let mut output_mode = None;
    let mut paths = Vec::new();
    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => mode = LaunchMode::Help,
            "-V" | "--version" => mode = LaunchMode::Version,
            "--table" => set_diff_output_mode(&mut mode, &mut output_mode, LaunchMode::DiffTable)?,
            "--json" => {
                set_diff_output_mode(&mut mode, &mut output_mode, LaunchMode::DiffJson)?;
            }
            _ if argument.starts_with('-') => {
                return Err(format!("unknown diff option: {argument}"));
            }
            _ => paths.push(argument.clone()),
        }
    }
    if matches!(mode, LaunchMode::Help | LaunchMode::Version) {
        return Ok(Cli {
            mode,
            ..Cli::default()
        });
    }
    if paths.len() != 2 {
        return Err(format!(
            "diff requires BEFORE.json and AFTER.json; received {} path(s)",
            paths.len()
        ));
    }
    Ok(Cli {
        mode,
        diff_paths: Some((paths.remove(0), paths.remove(0))),
        ..Cli::default()
    })
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

pub(crate) fn help_text() -> &'static str {
    "psmore - cross-platform process relationship diagnostics

USAGE:
  psmore [--query QUERY]
  psmore --table [--query QUERY] [--sample-ms MS]
  psmore --json  [--query QUERY] [--sample-ms MS]
  psmore check QUERY [--expect none|any] [--table|--json|--quiet]
  psmore inspect PID [--table|--json] [--sample-ms MS]
  psmore port PORT [--protocol tcp|udp|any] [--all] [--table|--json]
  psmore tree PID [--depth 0-128|all] [--table|--json] [--sample-ms MS]
  psmore watch [QUERY] [--table|--jsonl] [--interval-ms MS] [--count N]
  psmore deleted [--min-size SIZE] [--table|--json] [--expect none|any]
  psmore diff BEFORE.json AFTER.json [--table|--json]

OPTIONS:
  -q, --query QUERY   Start the TUI filtered, or filter snapshot rows
      --table         Print a human-readable process snapshot and exit
      --json          Print a versioned JSON process snapshot and exit
      --sample-ms MS  Sampling interval for CPU and I/O rates [default: 500]
      check QUERY     Evaluate a query as a CI/operations health gate
      --expect MODE   Check/port expectation: none or any
      --quiet         Check/port policy only: suppress output, use exit code
      inspect PID     Inspect one process: threads, sockets, files, and context
      port PORT       Find the process and sockets using a local port
      --protocol P    Port only: tcp, udp, or any [default: any]
      --all           Port only: include non-listening local connections
      tree PID        Print the PID's ancestor chain and descendant tree
      --depth N       Tree descendant depth, 0-128 or all [default: all]
      watch [QUERY]   Stream lifecycle and query-match changes
      --jsonl         Watch only: emit one JSON document per event
      --interval-ms   Watch refresh interval, 100-60000 [default: 1000]
      --count N       Watch only: stop after N refreshes [default: unlimited]
      deleted         Find deleted files still held open by processes
      --min-size SIZE Deleted only: filter estimated reclaimable bytes
      diff            Compare two psmore.process-snapshot v1 files
  -h, --help          Print help
  -V, --version       Print version

QUERY EXAMPLES:
  'name:python cpu>20'  'user:deploy mem>500m'  'tree.procs>=10'
"
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
                query: "user:deploy".into(),
                sample_ms: 1_200,
                diff_paths: None,
                inspect_pid: None,
                port: None,
                port_protocol: PortProtocol::Any,
                port_all: false,
                port_expectation: None,
                tree_pid: None,
                tree_depth: None,
                watch_interval_ms: 1_000,
                watch_count: None,
                deleted_min_size: 0,
                deleted_expectation: None,
                check_expectation: CheckExpectation::None,
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
            Cli::parse(["deleted", "--min-size=1.5g", "--json", "--expect", "none"]).unwrap(),
            Cli {
                mode: LaunchMode::DeletedJson,
                deleted_min_size: 1_610_612_736,
                deleted_expectation: Some(CheckExpectation::None),
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
            Cli::parse(["diff", "before.json", "after.json", "--json"]).unwrap(),
            Cli {
                mode: LaunchMode::DiffJson,
                diff_paths: Some(("before.json".into(), "after.json".into())),
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
        assert!(Cli::parse(["deleted", "extra"]).is_err());
        assert!(Cli::parse(["deleted", "--min-size=nope"]).is_err());
        assert!(Cli::parse(["deleted", "--table", "--json"]).is_err());
        assert!(Cli::parse(["deleted", "--quiet"]).is_err());
        assert!(Cli::parse(["deleted", "--expect=all"]).is_err());
    }
}
