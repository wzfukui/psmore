#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchMode {
    Tui,
    Table,
    Json,
    CheckTable,
    CheckJson,
    DiffTable,
    DiffJson,
    Help,
    Version,
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
        if arguments.first().map(String::as_str) == Some("check") {
            return parse_check(&arguments[1..]);
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
    cli.check_expectation = match value {
        "none" => CheckExpectation::None,
        "any" => CheckExpectation::Any,
        _ => return Err(format!("invalid --expect value: {value}; use none or any")),
    };
    *expectation_set = true;
    Ok(())
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
  psmore diff BEFORE.json AFTER.json [--table|--json]

OPTIONS:
  -q, --query QUERY   Start the TUI filtered, or filter snapshot rows
      --table         Print a human-readable process snapshot and exit
      --json          Print a versioned JSON process snapshot and exit
      --sample-ms MS  Sampling interval for CPU and I/O rates [default: 500]
      check QUERY     Evaluate a query as a CI/operations health gate
      --expect MODE   Check expectation: none (default) or any
      --quiet         Check only: suppress output and use the exit code
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
            Cli::parse(["diff", "before.json", "after.json", "--json"]).unwrap(),
            Cli {
                mode: LaunchMode::DiffJson,
                diff_paths: Some(("before.json".into(), "after.json".into())),
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
    }
}
