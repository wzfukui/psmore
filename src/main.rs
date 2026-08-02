mod actions;
mod app;
mod cli;
mod completion;
mod headless;
mod headless_deleted;
mod headless_diff;
mod headless_fd;
mod headless_inspect;
mod headless_listen;
mod headless_net;
mod headless_oom;
mod headless_port;
mod headless_top;
mod headless_trace;
mod headless_tree;
mod headless_watch;
mod history;
mod inspection;
mod model;
mod network;
mod provider;
mod query;
mod report;
mod snapshot;
mod ui;

use std::{
    env,
    error::Error,
    io::{self, IsTerminal, Write},
    process::ExitCode,
    time::Duration,
};

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::{
    app::App,
    cli::{Cli, LaunchMode, help_text},
    completion::completion_script,
    headless::{
        capture_snapshot, matching_process_count, render_check_json, render_check_table,
        render_json, render_table, validate_query,
    },
    headless_deleted::{
        DeletedPolicyStatus, capture_deleted_files, render_deleted_json, render_deleted_table,
    },
    headless_diff::{load_comparison, render_diff_json, render_diff_table},
    headless_fd::{FdPolicyStatus, capture_fd_usage, render_fd_json, render_fd_table},
    headless_inspect::{capture_inspection, render_inspection_json, render_inspection_table},
    headless_listen::{
        ListenPolicyStatus, capture_listeners, render_listeners_json, render_listeners_table,
    },
    headless_net::{
        NetPolicyStatus, capture_network_connections, render_network_json, render_network_table,
    },
    headless_oom::{OomPolicyStatus, capture_oom_diagnostics, render_oom_json, render_oom_table},
    headless_port::{PortPolicyStatus, capture_port, render_port_json, render_port_table},
    headless_top::{render_top_json, render_top_table},
    headless_trace::{TraceOutput, TraceRunStatus, run_trace},
    headless_tree::{build_tree, render_tree_json, render_tree_table},
    headless_watch::{WatchOutput, run_watch},
    model::set_output_secret_redaction,
    ui::draw,
};

fn handle_pending_input(app: &mut App) -> io::Result<bool> {
    if !event::poll(Duration::from_millis(250))? {
        return Ok(false);
    }
    match event::read()? {
        Event::Key(key) => Ok(app.on_key(key)),
        _ => Ok(false),
    }
}

fn run_tui(initial_query: String) -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error.into());
    }
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = if initial_query.is_empty() {
        App::new()
    } else {
        App::new_with_query(initial_query)
    };
    let result: io::Result<()> = (|| {
        loop {
            app.poll_background_jobs();
            terminal.draw(|frame| draw(frame, &mut app))?;
            if handle_pending_input(&mut app)? {
                break Ok(());
            }
            if !app.paused && app.last_refresh.elapsed() >= Duration::from_secs(2) {
                app.refresh();
            }
        }
    })();
    // Attempt every cleanup step even when an earlier one fails, so a runtime
    // error is less likely to leave the caller's terminal in an unusable state.
    let raw_mode_result = disable_raw_mode();
    let alternate_screen_result = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let cursor_result = terminal.show_cursor();
    result?;
    raw_mode_result?;
    alternate_screen_result?;
    cursor_result?;
    Ok(())
}

fn write_stdout(output: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(output.as_bytes())?;
    if !output.ends_with('\n') {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()
}

fn runtime_result(result: Result<(), Box<dyn Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .map(|error| error.kind() == io::ErrorKind::BrokenPipe)
                .unwrap_or(false) =>
        {
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("psmore: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("psmore: {message}\nTry 'psmore --help' for more information.");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let cli = match Cli::parse(env::args().skip(1)) {
        Ok(cli) => cli,
        Err(error) => return usage_error(&error),
    };
    set_output_secret_redaction(cli.redact_secrets);
    match cli.mode {
        LaunchMode::Help => {
            runtime_result(write_stdout(help_text(cli.help_topic)).map_err(Into::into))
        }
        LaunchMode::Completion => {
            let Some(shell) = cli.completion_shell else {
                return usage_error("completion requires bash, zsh, or fish");
            };
            runtime_result(write_stdout(completion_script(shell)).map_err(Into::into))
        }
        LaunchMode::Version => runtime_result(
            write_stdout(&format!("psmore {}", env!("CARGO_PKG_VERSION"))).map_err(Into::into),
        ),
        LaunchMode::Tui => {
            if let Err(error) = validate_query(&cli.query) {
                return usage_error(&format!("invalid query: {error}"));
            }
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
                return usage_error("interactive mode requires a terminal; use --table or --json");
            }
            runtime_result(run_tui(cli.query))
        }
        LaunchMode::Table | LaunchMode::Json => {
            if let Err(error) = validate_query(&cli.query) {
                return usage_error(&format!("invalid query: {error}"));
            }
            let result = (|| -> Result<(), Box<dyn Error>> {
                let snapshot = capture_snapshot(cli.sample_ms);
                let output = match cli.mode {
                    LaunchMode::Table => render_table(&snapshot, &cli.query),
                    LaunchMode::Json => render_json(&snapshot, &cli.query),
                    _ => unreachable!(),
                }
                .map_err(io::Error::other)?;
                write_stdout(&output)?;
                Ok(())
            })();
            runtime_result(result)
        }
        LaunchMode::CheckTable | LaunchMode::CheckJson => {
            if let Err(error) = validate_query(&cli.query) {
                return usage_error(&format!("invalid query: {error}"));
            }
            let result = (|| -> Result<bool, Box<dyn Error>> {
                let snapshot = capture_snapshot(cli.sample_ms);
                let matched =
                    matching_process_count(&snapshot, &cli.query).map_err(io::Error::other)?;
                let passed = cli.check_expectation.passes(matched);
                if !cli.quiet {
                    let output = match cli.mode {
                        LaunchMode::CheckTable => render_check_table(
                            &snapshot,
                            &cli.query,
                            cli.check_expectation.label(),
                            matched,
                            passed,
                        ),
                        LaunchMode::CheckJson => render_check_json(
                            &snapshot,
                            &cli.query,
                            cli.check_expectation.label(),
                            matched,
                            passed,
                        ),
                        _ => unreachable!(),
                    }
                    .map_err(io::Error::other)?;
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                Ok(passed)
            })();
            match result {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::from(3),
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::InspectTable | LaunchMode::InspectJson => {
            let Some(pid) = cli.inspect_pid else {
                return usage_error("inspect requires exactly one PID");
            };
            let result = (|| -> Result<(), Box<dyn Error>> {
                let inspection =
                    capture_inspection(pid, cli.sample_ms).map_err(io::Error::other)?;
                let output = match cli.mode {
                    LaunchMode::InspectTable => render_inspection_table(&inspection),
                    LaunchMode::InspectJson => {
                        render_inspection_json(&inspection).map_err(io::Error::other)?
                    }
                    _ => unreachable!(),
                };
                write_stdout(&output)?;
                Ok(())
            })();
            runtime_result(result)
        }
        LaunchMode::PortTable | LaunchMode::PortJson => {
            let Some(port) = cli.port else {
                return usage_error("port requires exactly one local port number");
            };
            let result = (|| -> Result<Option<PortPolicyStatus>, Box<dyn Error>> {
                let captured = capture_port(port, cli.port_protocol, cli.port_all);
                let policy_status = cli
                    .port_expectation
                    .map(|expectation| captured.evaluate_policy(expectation));
                if !cli.quiet {
                    let expectation = cli.port_expectation.map(|value| value.label());
                    let output = match cli.mode {
                        LaunchMode::PortTable => {
                            render_port_table(&captured, expectation, policy_status)
                        }
                        LaunchMode::PortJson => {
                            render_port_json(&captured, expectation, policy_status)
                                .map_err(io::Error::other)?
                        }
                        _ => unreachable!(),
                    };
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                Ok(policy_status)
            })();
            match result {
                Ok(None | Some(PortPolicyStatus::Passed)) => ExitCode::SUCCESS,
                Ok(Some(PortPolicyStatus::Violated)) => ExitCode::from(3),
                Ok(Some(PortPolicyStatus::Inconclusive)) => ExitCode::FAILURE,
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::ListenTable | LaunchMode::ListenJson => {
            let result = (|| -> Result<Option<ListenPolicyStatus>, Box<dyn Error>> {
                let captured = capture_listeners(
                    &cli.query,
                    cli.listen_protocol,
                    cli.listen_exposed,
                    cli.listen_limit,
                );
                let policy_status = cli
                    .listen_expectation
                    .map(|expectation| captured.evaluate_policy(expectation));
                if !cli.quiet {
                    let expectation = cli.listen_expectation.map(|value| value.label());
                    let output = match cli.mode {
                        LaunchMode::ListenTable => {
                            render_listeners_table(&captured, expectation, policy_status)
                        }
                        LaunchMode::ListenJson => {
                            render_listeners_json(&captured, expectation, policy_status)
                                .map_err(io::Error::other)?
                        }
                        _ => unreachable!(),
                    };
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                Ok(policy_status)
            })();
            match result {
                Ok(None | Some(ListenPolicyStatus::Passed)) => ExitCode::SUCCESS,
                Ok(Some(ListenPolicyStatus::Violated)) => ExitCode::from(3),
                Ok(Some(ListenPolicyStatus::Inconclusive)) => ExitCode::FAILURE,
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::NetTable | LaunchMode::NetJson => {
            let result = (|| -> Result<Option<NetPolicyStatus>, Box<dyn Error>> {
                let captured = capture_network_connections(
                    &cli.query,
                    cli.net_protocol,
                    cli.net_connected_only,
                    cli.net_state.as_deref(),
                    cli.net_limit,
                );
                let policy_status = cli
                    .net_expectation
                    .map(|expectation| captured.evaluate_policy(expectation));
                if !cli.quiet {
                    let expectation = cli.net_expectation.map(|value| value.label());
                    let output = match cli.mode {
                        LaunchMode::NetTable => {
                            render_network_table(&captured, expectation, policy_status)
                        }
                        LaunchMode::NetJson => {
                            render_network_json(&captured, expectation, policy_status)
                                .map_err(io::Error::other)?
                        }
                        _ => unreachable!(),
                    };
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                Ok(policy_status)
            })();
            match result {
                Ok(None | Some(NetPolicyStatus::Passed)) => ExitCode::SUCCESS,
                Ok(Some(NetPolicyStatus::Violated)) => ExitCode::from(3),
                Ok(Some(NetPolicyStatus::Inconclusive)) => ExitCode::FAILURE,
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::TreeTable | LaunchMode::TreeJson => {
            let Some(pid) = cli.tree_pid else {
                return usage_error("tree requires exactly one PID");
            };
            let result = (|| -> Result<(), Box<dyn Error>> {
                let snapshot = capture_snapshot(cli.sample_ms);
                let tree = build_tree(&snapshot, pid, cli.tree_depth).map_err(io::Error::other)?;
                let output = match cli.mode {
                    LaunchMode::TreeTable => render_tree_table(&tree),
                    LaunchMode::TreeJson => render_tree_json(&tree).map_err(io::Error::other)?,
                    _ => unreachable!(),
                };
                write_stdout(&output)?;
                Ok(())
            })();
            runtime_result(result)
        }
        LaunchMode::WatchTable | LaunchMode::WatchJsonl => {
            if let Err(error) = validate_query(&cli.query) {
                return usage_error(&format!("invalid query: {error}"));
            }
            let result = (|| -> Result<(), Box<dyn Error>> {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                let output = if cli.mode == LaunchMode::WatchJsonl {
                    WatchOutput::Jsonl
                } else {
                    WatchOutput::Table
                };
                run_watch(
                    &mut stdout,
                    &cli.query,
                    cli.watch_interval_ms,
                    cli.watch_count,
                    output,
                )?;
                Ok(())
            })();
            runtime_result(result)
        }
        LaunchMode::TraceTable | LaunchMode::TraceJsonl => {
            let Some(pid) = cli.trace_pid else {
                return usage_error("trace requires exactly one PID");
            };
            let result = (|| -> Result<TraceRunStatus, Box<dyn Error>> {
                let stdout = io::stdout();
                let mut stdout = stdout.lock();
                let output = if cli.mode == LaunchMode::TraceJsonl {
                    TraceOutput::Jsonl
                } else {
                    TraceOutput::Table
                };
                let status = run_trace(
                    &mut stdout,
                    pid,
                    cli.trace_interval_ms,
                    cli.trace_count,
                    output,
                )?;
                Ok(status)
            })();
            match result {
                Ok(TraceRunStatus::Complete) => ExitCode::SUCCESS,
                Ok(TraceRunStatus::Inconclusive) => ExitCode::FAILURE,
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::DeletedTable | LaunchMode::DeletedJson => {
            let result = (|| -> Result<bool, Box<dyn Error>> {
                let captured = capture_deleted_files(cli.deleted_min_size);
                let policy_status = cli
                    .deleted_expectation
                    .map(|expectation| captured.evaluate_policy(expectation));
                if !cli.quiet {
                    let expectation = cli.deleted_expectation.map(|value| value.label());
                    let output = match cli.mode {
                        LaunchMode::DeletedTable => {
                            render_deleted_table(&captured, expectation, policy_status)
                        }
                        LaunchMode::DeletedJson => {
                            render_deleted_json(&captured, expectation, policy_status)
                                .map_err(io::Error::other)?
                        }
                        _ => unreachable!(),
                    };
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                match policy_status {
                    None | Some(DeletedPolicyStatus::Passed) => Ok(true),
                    Some(DeletedPolicyStatus::Violated) => Ok(false),
                    Some(DeletedPolicyStatus::Inconclusive) => Err(io::Error::other(
                        "deleted-file policy is inconclusive because collection was incomplete",
                    )
                    .into()),
                }
            })();
            match result {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::from(3),
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::FdTable | LaunchMode::FdJson => {
            let result = (|| -> Result<Option<FdPolicyStatus>, Box<dyn Error>> {
                let captured = capture_fd_usage(cli.fd_min_count, cli.fd_min_percent, cli.fd_limit);
                let policy_status = cli
                    .fd_expectation
                    .map(|expectation| captured.evaluate_policy(expectation));
                if !cli.quiet {
                    let expectation = cli.fd_expectation.map(|value| value.label());
                    let output = match cli.mode {
                        LaunchMode::FdTable => {
                            render_fd_table(&captured, expectation, policy_status)
                        }
                        LaunchMode::FdJson => render_fd_json(&captured, expectation, policy_status)
                            .map_err(io::Error::other)?,
                        _ => unreachable!(),
                    };
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                Ok(policy_status)
            })();
            match result {
                Ok(None | Some(FdPolicyStatus::Passed)) => ExitCode::SUCCESS,
                Ok(Some(FdPolicyStatus::Violated)) => ExitCode::from(3),
                Ok(Some(FdPolicyStatus::Inconclusive)) => ExitCode::FAILURE,
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::TopTable | LaunchMode::TopJson => {
            if let Err(error) = validate_query(&cli.query) {
                return usage_error(&format!("invalid query: {error}"));
            }
            let result = (|| -> Result<(), Box<dyn Error>> {
                let snapshot = capture_snapshot(cli.sample_ms);
                let output = match cli.mode {
                    LaunchMode::TopTable => render_top_table(
                        &snapshot,
                        &cli.query,
                        cli.top_metric,
                        cli.top_scope,
                        cli.top_limit,
                    ),
                    LaunchMode::TopJson => render_top_json(
                        &snapshot,
                        &cli.query,
                        cli.top_metric,
                        cli.top_scope,
                        cli.top_limit,
                    ),
                    _ => unreachable!(),
                }
                .map_err(io::Error::other)?;
                write_stdout(&output)?;
                Ok(())
            })();
            runtime_result(result)
        }
        LaunchMode::OomTable | LaunchMode::OomJson => {
            if let Err(error) = validate_query(&cli.query) {
                return usage_error(&format!("invalid query: {error}"));
            }
            let result = (|| -> Result<Option<OomPolicyStatus>, Box<dyn Error>> {
                let captured = capture_oom_diagnostics(
                    &cli.query,
                    cli.sample_ms,
                    cli.oom_min_score,
                    cli.oom_limit,
                )?;
                let policy_status = cli
                    .oom_expectation
                    .map(|expectation| captured.evaluate_policy(expectation));
                if !cli.quiet {
                    let expectation = cli.oom_expectation.map(|value| value.label());
                    let output = match cli.mode {
                        LaunchMode::OomTable => {
                            render_oom_table(&captured, expectation, policy_status)
                        }
                        LaunchMode::OomJson => {
                            render_oom_json(&captured, expectation, policy_status)
                                .map_err(io::Error::other)?
                        }
                        _ => unreachable!(),
                    };
                    if let Err(error) = write_stdout(&output) {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            return Err(error.into());
                        }
                    }
                }
                Ok(policy_status)
            })();
            match result {
                Ok(None | Some(OomPolicyStatus::Passed)) => ExitCode::SUCCESS,
                Ok(Some(OomPolicyStatus::Violated)) => ExitCode::from(3),
                Ok(Some(OomPolicyStatus::Inconclusive)) => ExitCode::FAILURE,
                Err(error) => runtime_result(Err(error)),
            }
        }
        LaunchMode::DiffTable | LaunchMode::DiffJson => {
            let Some((before_path, after_path)) = cli.diff_paths else {
                return usage_error("diff requires BEFORE.json and AFTER.json");
            };
            let result = (|| -> Result<(), Box<dyn Error>> {
                let comparison = load_comparison(before_path.as_ref(), after_path.as_ref())
                    .map_err(io::Error::other)?;
                let output = match cli.mode {
                    LaunchMode::DiffTable => render_diff_table(&comparison),
                    LaunchMode::DiffJson => {
                        render_diff_json(&comparison).map_err(io::Error::other)?
                    }
                    _ => unreachable!(),
                };
                write_stdout(&output)?;
                Ok(())
            })();
            runtime_result(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        fs,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use sysinfo::Pid;

    #[cfg(not(target_os = "linux"))]
    use crate::inspection::parse_lsof_output;
    #[cfg(target_os = "linux")]
    use crate::inspection::{
        decode_linux_capabilities, parse_linux_cgroup, parse_linux_limits, parse_linux_status,
        parse_proc_endpoint, proc_socket_state,
    };
    #[cfg(not(target_os = "linux"))]
    use crate::model::{OpenFileInfo, SocketInfo};
    #[cfg(not(target_os = "linux"))]
    use crate::network::parse_lsof_network_output;
    #[cfg(target_os = "linux")]
    use crate::network::{parse_linux_inet_sockets, parse_linux_unix_sockets};
    use crate::{
        actions::{
            ProcessActionKind, ProcessActionOutcome, ProcessActionRecord, ProcessActionTarget,
        },
        app::{aggregate_resources, rank_attention_findings, rank_hotspots, sort_processes},
        history::ResourceHistory,
        model::{
            AttentionFinding, AttentionSeverity, HotspotMetric, HotspotScope, ProcessChange,
            ProcessEvent, ProcessInfo, ProcessInspection, ResourceAggregate, SortMode, ThreadInfo,
            diff_processes, process_path,
        },
        network::{NetworkEndpoint, NetworkScan, NetworkScope},
        provider::{bytes_per_second, is_sampler_process, parse_ps_snapshot, platform_name},
        report::{ReportInput, export_report},
        snapshot::BaselineSnapshot,
    };

    fn test_process(pid: u32, parent: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: Some(Pid::from_u32(parent)),
            name: name.into(),
            command: format!("/usr/bin/{name}"),
            executable: format!("/usr/bin/{name}"),
            user: "tester".into(),
            cwd: "/tmp".into(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: pid as u64,
            runtime: 0,
            status: "Sleep".into(),
        }
    }

    #[test]
    fn parses_linux_and_macos_ps_rows_without_losing_arguments() {
        let output = b"    1       0 S /lib/systemd/systemd --system --deserialize 48\n\
                       2       0 I [kthreadd]\n\
                   32550       1 S /Applications/Otty.app/Contents/MacOS/Otty --flag value\n";

        let snapshot = parse_ps_snapshot(output);

        assert_eq!(snapshot[&1].ppid, 0);
        assert_eq!(
            snapshot[&1].command,
            "/lib/systemd/systemd --system --deserialize 48"
        );
        assert_eq!(snapshot[&2].state, "I");
        assert_eq!(snapshot[&2].command, "[kthreadd]");
        assert_eq!(
            snapshot[&32550].command,
            "/Applications/Otty.app/Contents/MacOS/Otty --flag value"
        );
    }

    #[test]
    fn ignores_malformed_ps_rows() {
        let snapshot = parse_ps_snapshot(b"PID PPID STAT COMMAND\n 42 1 S /usr/bin/test\n");

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[&42].ppid, 1);
    }

    #[test]
    fn normalizes_process_io_deltas_to_bytes_per_second() {
        assert_eq!(bytes_per_second(4_096, Duration::from_secs(2)), 2_048);
        assert_eq!(bytes_per_second(4_096, Duration::from_millis(500)), 8_192);
        assert_eq!(bytes_per_second(4_096, Duration::ZERO), 0);
        assert_eq!(bytes_per_second(0, Duration::from_secs(2)), 0);
    }

    #[test]
    fn does_not_label_an_unreadable_process_as_system_root() {
        let process = ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: "restricted".into(),
            command: String::new(),
            executable: String::new(),
            user: String::new(),
            cwd: String::new(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: 1,
            runtime: 0,
            status: "Sleep".into(),
        };

        assert_eq!(process_path(&process), "[path unavailable]");
    }

    #[test]
    fn network_listener_filter_matches_port_process_pid_and_namespace() {
        let listener = NetworkEndpoint {
            pid: Some(Pid::from_u32(42)),
            process: "api-server".into(),
            fd: "7".into(),
            protocol: "TCP".into(),
            local_endpoint: "127.0.0.1:8080".into(),
            remote_endpoint: "10.0.0.8:443".into(),
            state: "LISTEN".into(),
            namespace: "net:[1234]".into(),
        };

        assert!(listener.matches("8080"));
        assert!(listener.matches("10.0.0.8"));
        assert!(listener.matches("API"));
        assert!(listener.matches("42"));
        assert!(listener.matches("1234"));
        assert!(!listener.matches("postgres"));
    }

    #[test]
    fn detects_started_exited_and_reparented_processes() {
        let previous = [
            test_process(10, 1, "stable"),
            test_process(11, 1, "exited"),
            test_process(12, 1, "adopted"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        let current = [
            test_process(10, 1, "stable"),
            test_process(12, 2, "adopted"),
            test_process(13, 1, "started"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();

        assert_eq!(
            diff_processes(&previous, &current),
            vec![
                ProcessChange::Exited {
                    pid: Pid::from_u32(11),
                    name: "exited".into(),
                    command: "/usr/bin/exited".into(),
                },
                ProcessChange::Reparented {
                    pid: Pid::from_u32(12),
                    name: "adopted".into(),
                    command: "/usr/bin/adopted".into(),
                    old_parent: Some(Pid::from_u32(1)),
                    new_parent: Some(Pid::from_u32(2)),
                },
                ProcessChange::Started {
                    pid: Pid::from_u32(13),
                    name: "started".into(),
                    command: "/usr/bin/started".into(),
                    parent: Some(Pid::from_u32(1)),
                },
            ]
        );
    }

    #[test]
    fn treats_pid_reuse_as_exit_then_start() {
        let previous_process = test_process(42, 1, "old-worker");
        let mut current_process = test_process(42, 1, "new-worker");
        current_process.start_time += 1;
        let previous = HashMap::from([(previous_process.pid, previous_process)]);
        let current = HashMap::from([(current_process.pid, current_process)]);

        assert!(matches!(
            diff_processes(&previous, &current).as_slice(),
            [ProcessChange::Exited { .. }, ProcessChange::Started { .. }]
        ));
    }

    #[test]
    fn identifies_only_psmore_owned_sampler_processes() {
        let mut sampler = test_process(43, std::process::id(), "ps");
        assert!(is_sampler_process(&sampler, &HashSet::new()));

        sampler.parent = Some(Pid::from_u32(1));
        assert!(!is_sampler_process(&sampler, &HashSet::new()));

        sampler.name = "(ps)".into();
        sampler.parent = Some(Pid::from_u32(500));
        assert!(is_sampler_process(
            &sampler,
            &HashSet::from([Pid::from_u32(500)])
        ));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn parses_lsof_process_files_and_network_sockets() {
        let process = test_process(42, 1, "server");
        let output = b"p42\ncserver\nu501\nLalice\n\
fcwd\na \ntDIR\nn/opt/service\n\
f3u\nau\ntIPv4\nPTCP\nn127.0.0.1:8080\nTST=LISTEN\n\
f5u\nau\ntunix\nn/var/run/service.sock\n\
f4r\nar\ntREG\nn/opt/service/config.toml\n";

        let inspection = parse_lsof_output(output, &process);

        assert_eq!(inspection.user, "alice");
        assert_eq!(inspection.cwd, "/opt/service");
        assert_eq!(
            inspection.sockets,
            vec![
                SocketInfo {
                    fd: "3u".into(),
                    protocol: "TCP".into(),
                    endpoint: "127.0.0.1:8080".into(),
                    state: "LISTEN".into(),
                },
                SocketInfo {
                    fd: "5u".into(),
                    protocol: "UNIX".into(),
                    endpoint: "/var/run/service.sock".into(),
                    state: String::new(),
                },
            ]
        );
        assert_eq!(
            inspection.files,
            vec![OpenFileInfo {
                fd: "4r".into(),
                kind: "REG".into(),
                access: "r".into(),
                name: "/opt/service/config.toml".into(),
            }]
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn parses_lsof_tcp_and_udp_listeners() {
        let output = b"p42\ncserver\nf3u\nPTCP\nn127.0.0.1:8080\nTST=LISTEN\n\
f4u\nPUDP\nn*:5353\n\
f5u\nPTCP\nn127.0.0.1:50000->10.0.0.8:443\nTST=ESTABLISHED\n";

        let listeners = parse_lsof_network_output(output);

        assert_eq!(listeners.len(), 3);
        assert_eq!(listeners[0].pid, Some(Pid::from_u32(42)));
        assert_eq!(listeners[0].protocol, "TCP");
        assert_eq!(listeners[0].local_endpoint, "127.0.0.1:8080");
        assert!(listeners[0].remote_endpoint.is_empty());
        assert_eq!(listeners[0].state, "LISTEN");
        assert_eq!(listeners[1].protocol, "UDP");
        assert_eq!(listeners[1].state, "BOUND");
        assert_eq!(listeners[2].local_endpoint, "127.0.0.1:50000");
        assert_eq!(listeners[2].remote_endpoint, "10.0.0.8:443");
        assert_eq!(listeners[2].state, "ESTABLISHED");
        assert!(!listeners[2].is_listener());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_ipv4_and_ipv6_endpoints() {
        assert_eq!(
            parse_proc_endpoint("0100007F:494E", false),
            Some(("127.0.0.1:18766".into(), false, 18766))
        );
        assert_eq!(
            parse_proc_endpoint("00000000000000000000000001000000:0016", true),
            Some(("[::1]:22".into(), false, 22))
        );
        assert_eq!(proc_socket_state("TCP", "0A"), "LISTEN");
        assert_eq!(proc_socket_state("UDP", "07"), "UNCONN");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_tcp_udp_and_unix_listeners() {
        let tcp = "  sl  local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n\
0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n\
1: 0100007F:1F91 0100007F:1234 01 00000000:00000000 00:00000000 00000000 1000 0 12346\n";
        let udp = "  sl  local_address rem_address st tx_queue tr tm->when retrnsmt uid timeout inode\n\
0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 22345\n";
        let unix = "Num RefCount Protocol Flags Type St Inode Path\n\
00000000: 00000002 00000000 00010000 0001 01 32345 /run/test.sock\n\
00000001: 00000003 00000000 00000000 0001 03 32346\n";

        let tcp = parse_linux_inet_sockets(tcp, "TCP", false, "net:[1]");
        let udp = parse_linux_inet_sockets(udp, "UDP", false, "net:[1]");
        let unix = parse_linux_unix_sockets(unix, "net:[1]");

        assert_eq!(tcp.len(), 2);
        assert_eq!(tcp[0].local_endpoint, "127.0.0.1:8080");
        assert!(tcp[0].remote_endpoint.is_empty());
        assert_eq!(tcp[0].inode, "12345");
        assert_eq!(tcp[1].state, "ESTABLISHED");
        assert_eq!(tcp[1].remote_endpoint, "127.0.0.1:4660");
        assert_eq!(udp.len(), 1);
        assert_eq!(udp[0].local_endpoint, "0.0.0.0:53");
        assert_eq!(udp[0].state, "BOUND");
        assert_eq!(unix.len(), 2);
        assert_eq!(unix[0].local_endpoint, "/run/test.sock");
        assert_eq!(unix[0].state, "LISTEN");
        assert_eq!(unix[1].state, "CONNECTED");
        assert!(!unix[1].local_endpoint.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_runtime_security_and_capabilities() {
        let status = "State:\tS (sleeping)\nThreads:\t7\nVmRSS:\t2048 kB\nVmSwap:\t128 kB\n\
Uid:\t1000\t1000\t1000\t1000\nNSpid:\t42\t7\nNoNewPrivs:\t1\nSeccomp:\t2\n\
Seccomp_filters:\t1\nCapEff:\t0000000000000400\nCapBnd:\t0000000000000000\n";

        let (runtime, security) = parse_linux_status(status);

        assert!(
            runtime
                .iter()
                .any(|field| field.label == "THREADS" && field.value == "7")
        );
        assert!(
            runtime
                .iter()
                .any(|field| field.label == "NESTED PIDS" && field.value == "42\t7")
        );
        assert!(
            security
                .iter()
                .any(|field| field.label == "SECCOMP" && field.value == "filter")
        );
        assert!(security.iter().any(|field| {
            field.label == "CAPABILITIES effective" && field.value.contains("NET_BIND_SERVICE")
        }));
        assert_eq!(decode_linux_capabilities("0"), "0x0 (none)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recognizes_linux_cgroup_container_and_resource_limits() {
        let cgroup = "0::/system.slice/docker-0123456789abcdef0123456789abcdef.scope\n";
        let fields = parse_linux_cgroup(cgroup);

        assert!(fields.iter().any(|field| {
            field.label == "SYSTEMD UNIT"
                && field.value == "docker-0123456789abcdef0123456789abcdef.scope"
        }));
        assert!(
            fields
                .iter()
                .any(|field| field.label == "CONTAINER" && field.value == "docker 0123456789ab")
        );

        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
Max open files            1024                 4096                 files\n\
Max processes             2048                 4096                 processes\n\
Max address space         unlimited            unlimited            bytes\n";
        let limits = parse_linux_limits(limits);
        assert!(limits.iter().any(|field| {
            field.label == "OPEN FILES" && field.value == "soft 1024 / hard 4096 files"
        }));
        assert!(limits.iter().any(|field| {
            field.label == "ADDRESS SPACE" && field.value == "soft unlimited / hard unlimited bytes"
        }));
    }

    #[test]
    fn aggregates_resources_for_the_complete_process_subtree() {
        let root = test_process(0, 0, "root");
        let mut service = test_process(10, 0, "service");
        service.cpu = 2.5;
        service.memory = 10 * 1024 * 1024;
        service.read_rate = 100;
        service.write_rate = 200;
        let mut worker = test_process(11, 10, "worker");
        worker.cpu = 7.5;
        worker.memory = 30 * 1024 * 1024;
        worker.read_rate = 300;
        worker.write_rate = 400;
        let mut sidecar = test_process(12, 10, "sidecar");
        sidecar.cpu = 1.0;
        sidecar.memory = 5 * 1024 * 1024;
        sidecar.read_rate = 500;
        sidecar.write_rate = 600;
        let processes = [root, service, worker, sidecar]
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        let children = HashMap::from([
            (Some(Pid::from_u32(0)), vec![Pid::from_u32(10)]),
            (
                Some(Pid::from_u32(10)),
                vec![Pid::from_u32(11), Pid::from_u32(12)],
            ),
        ]);

        let resources = aggregate_resources(&processes, &children);

        assert_eq!(
            resources[&Pid::from_u32(10)],
            ResourceAggregate {
                cpu: 11.0,
                memory: 45 * 1024 * 1024,
                read_rate: 900,
                write_rate: 1_200,
                process_count: 3,
            }
        );
        assert_eq!(resources[&Pid::from_u32(0)].process_count, 3);
    }

    #[test]
    fn orders_siblings_by_stable_cpu_memory_and_io_hotspots() {
        let mut low_cpu = test_process(10, 0, "alpha");
        low_cpu.cpu = 1.0;
        low_cpu.memory = 50 * 1024 * 1024;
        let mut high_cpu = test_process(20, 0, "zeta");
        high_cpu.cpu = 80.0;
        high_cpu.memory = 5 * 1024 * 1024;
        let processes = [low_cpu, high_cpu]
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        let resources = HashMap::from([
            (
                Pid::from_u32(10),
                ResourceAggregate {
                    cpu: 1.0,
                    memory: 50 * 1024 * 1024,
                    read_rate: 1_000,
                    write_rate: 8_000,
                    process_count: 1,
                },
            ),
            (
                Pid::from_u32(20),
                ResourceAggregate {
                    cpu: 80.0,
                    memory: 5 * 1024 * 1024,
                    read_rate: 9_000,
                    write_rate: 2_000,
                    process_count: 1,
                },
            ),
        ]);
        let mut pids = vec![Pid::from_u32(20), Pid::from_u32(10)];

        sort_processes(&mut pids, SortMode::Stable, &processes, &resources);
        assert_eq!(pids, vec![Pid::from_u32(10), Pid::from_u32(20)]);

        sort_processes(&mut pids, SortMode::SubtreeCpu, &processes, &resources);
        assert_eq!(pids, vec![Pid::from_u32(20), Pid::from_u32(10)]);

        sort_processes(&mut pids, SortMode::SubtreeMemory, &processes, &resources);
        assert_eq!(pids, vec![Pid::from_u32(10), Pid::from_u32(20)]);

        sort_processes(&mut pids, SortMode::SubtreeRead, &processes, &resources);
        assert_eq!(pids, vec![Pid::from_u32(20), Pid::from_u32(10)]);

        sort_processes(&mut pids, SortMode::SubtreeWrite, &processes, &resources);
        assert_eq!(pids, vec![Pid::from_u32(10), Pid::from_u32(20)]);
    }

    #[test]
    fn ranks_hotspots_by_process_self_or_complete_service_subtree() {
        let mut service = test_process(10, 0, "service");
        service.cpu = 1.0;
        service.memory = 10;
        service.read_rate = 100;
        service.write_rate = 200;
        let mut worker = test_process(11, 10, "worker");
        worker.cpu = 50.0;
        worker.memory = 70;
        worker.read_rate = 900;
        worker.write_rate = 800;
        let mut database = test_process(20, 0, "database");
        database.cpu = 20.0;
        database.memory = 100;
        database.read_rate = 500;
        database.write_rate = 2_000;
        let processes = [service, worker, database]
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        let resources = HashMap::from([
            (
                Pid::from_u32(10),
                ResourceAggregate {
                    cpu: 51.0,
                    memory: 80,
                    read_rate: 1_000,
                    write_rate: 1_000,
                    process_count: 2,
                },
            ),
            (
                Pid::from_u32(11),
                ResourceAggregate {
                    cpu: 50.0,
                    memory: 70,
                    read_rate: 900,
                    write_rate: 800,
                    process_count: 1,
                },
            ),
            (
                Pid::from_u32(20),
                ResourceAggregate {
                    cpu: 20.0,
                    memory: 100,
                    read_rate: 500,
                    write_rate: 2_000,
                    process_count: 1,
                },
            ),
        ]);

        assert_eq!(
            rank_hotspots(
                &processes,
                &resources,
                HotspotMetric::Cpu,
                HotspotScope::Process,
            ),
            vec![Pid::from_u32(11), Pid::from_u32(20), Pid::from_u32(10)]
        );
        assert_eq!(
            rank_hotspots(
                &processes,
                &resources,
                HotspotMetric::Cpu,
                HotspotScope::Subtree,
            ),
            vec![Pid::from_u32(10), Pid::from_u32(11), Pid::from_u32(20)]
        );
        assert_eq!(
            rank_hotspots(
                &processes,
                &resources,
                HotspotMetric::Write,
                HotspotScope::Process,
            ),
            vec![Pid::from_u32(20), Pid::from_u32(11), Pid::from_u32(10)]
        );
        assert_eq!(
            rank_hotspots(
                &processes,
                &resources,
                HotspotMetric::Read,
                HotspotScope::Subtree,
            ),
            vec![Pid::from_u32(10), Pid::from_u32(11), Pid::from_u32(20)]
        );
    }

    #[test]
    fn ranks_explainable_attention_findings_from_state_churn_and_history() {
        let mut zombie = test_process(10, 1, "zombie-worker");
        zombie.status = "Zombie".into();
        let flapping = test_process(11, 1, "flapping-worker");
        let mut busy = test_process(12, 1, "busy-worker");
        busy.cpu = 65.0;
        busy.write_rate = 20 * 1024 * 1024;
        let mut grower = test_process(13, 1, "growing-worker");
        grower.memory = 64 * 1024 * 1024;
        let mut quiet = test_process(14, 1, "quiet-worker");
        quiet.cpu = 0.2;
        let flicker = test_process(15, 1, "visibility-flicker");
        let mut processes: HashMap<Pid, ProcessInfo> =
            [zombie, flapping, busy, grower, quiet, flicker]
                .into_iter()
                .map(|process| (process.pid, process))
                .collect();
        let resources: HashMap<Pid, ResourceAggregate> = processes
            .keys()
            .map(|pid| (*pid, ResourceAggregate::default()))
            .collect();
        let started = Instant::now();
        let mut history = ResourceHistory::with_sample_limit(30);
        history.record(&processes, &resources, started);
        processes.get_mut(&Pid::from_u32(13)).unwrap().memory = 256 * 1024 * 1024;
        for step in 1..=3 {
            history.record(
                &processes,
                &resources,
                started + Duration::from_secs(step * 2),
            );
        }
        let mut events = Vec::new();
        for offset in 0..3 {
            let restarted_pid = Pid::from_u32(101 + offset);
            events.push(ProcessEvent {
                change: ProcessChange::Started {
                    pid: restarted_pid,
                    name: "flapping-worker".into(),
                    command: "/usr/bin/flapping-worker".into(),
                    parent: Some(Pid::from_u32(1)),
                },
                observed_at: Instant::now(),
            });
            events.push(ProcessEvent {
                change: ProcessChange::Exited {
                    pid: restarted_pid,
                    name: "flapping-worker".into(),
                    command: "/usr/bin/flapping-worker".into(),
                },
                observed_at: Instant::now(),
            });
        }
        for _ in 0..3 {
            events.push(ProcessEvent {
                change: ProcessChange::Started {
                    pid: Pid::from_u32(15),
                    name: "visibility-flicker".into(),
                    command: "/usr/bin/visibility-flicker".into(),
                    parent: Some(Pid::from_u32(1)),
                },
                observed_at: Instant::now(),
            });
            events.push(ProcessEvent {
                change: ProcessChange::Exited {
                    pid: Pid::from_u32(15),
                    name: "visibility-flicker".into(),
                    command: "/usr/bin/visibility-flicker".into(),
                },
                observed_at: Instant::now(),
            });
        }

        let findings = rank_attention_findings(&processes, &history, &events);

        assert_eq!(findings[0].pid, Pid::from_u32(10));
        assert_eq!(findings[0].severity, AttentionSeverity::Critical);
        assert_eq!(findings[0].score, 100);
        let flapping = findings
            .iter()
            .find(|finding| finding.pid == Pid::from_u32(11))
            .expect("flapping finding");
        assert_eq!(flapping.severity, AttentionSeverity::Watch);
        assert!(
            flapping
                .reasons
                .iter()
                .any(|reason| reason.contains("3 distinct starts / 3 exits"))
        );
        let busy = findings
            .iter()
            .find(|finding| finding.pid == Pid::from_u32(12))
            .expect("busy finding");
        assert!(
            busy.reasons
                .iter()
                .any(|reason| reason.contains("sustained CPU"))
        );
        assert!(
            busy.reasons
                .iter()
                .any(|reason| reason.contains("write I/O"))
        );
        let grower = findings
            .iter()
            .find(|finding| finding.pid == Pid::from_u32(13))
            .expect("memory growth finding");
        assert!(
            grower
                .reasons
                .iter()
                .any(|reason| reason.contains("memory grew"))
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.pid != Pid::from_u32(14))
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.pid != Pid::from_u32(15))
        );
    }

    #[test]
    fn resource_history_is_bounded_and_resets_when_a_pid_is_reused() {
        let pid = Pid::from_u32(42);
        let mut process = test_process(42, 1, "worker");
        let aggregate = ResourceAggregate {
            cpu: 0.0,
            memory: 20 * 1024 * 1024,
            read_rate: 10,
            write_rate: 20,
            process_count: 2,
        };
        let resources = HashMap::from([(pid, aggregate)]);
        let started = Instant::now();
        let mut history = ResourceHistory::with_sample_limit(3);

        for step in 0..5 {
            process.cpu = step as f32;
            history.record(
                &HashMap::from([(pid, process.clone())]),
                &resources,
                started + Duration::from_secs(step),
            );
        }

        let samples = history.samples(pid).expect("active process history");
        assert_eq!(samples.len(), 3);
        assert_eq!(samples.front().map(|sample| sample.own_cpu), Some(2.0));
        assert_eq!(
            samples.back().map(|sample| sample.subtree_read_rate),
            Some(10)
        );
        assert_eq!(
            samples.back().map(|sample| sample.subtree_write_rate),
            Some(20)
        );

        process.start_time += 1;
        process.cpu = 99.0;
        history.record(
            &HashMap::from([(pid, process)]),
            &resources,
            started + Duration::from_secs(6),
        );
        let samples = history.samples(pid).expect("reused PID history");
        assert_eq!(samples.len(), 1);
        assert_eq!(samples.front().map(|sample| sample.own_cpu), Some(99.0));
    }

    #[test]
    fn exited_process_history_remains_briefly_then_expires() {
        let pid = Pid::from_u32(42);
        let process = test_process(42, 1, "short-lived");
        let resources = HashMap::from([(
            pid,
            ResourceAggregate {
                cpu: 5.0,
                memory: 1024,
                read_rate: 0,
                write_rate: 0,
                process_count: 1,
            },
        )]);
        let started = Instant::now();
        let mut history = ResourceHistory::with_sample_limit(3);
        history.record(&HashMap::from([(pid, process)]), &resources, started);

        history.record(
            &HashMap::new(),
            &HashMap::new(),
            started + Duration::from_secs(60),
        );
        assert!(history.samples(pid).is_some());

        history.record(
            &HashMap::new(),
            &HashMap::new(),
            started + Duration::from_secs(301),
        );
        assert!(history.samples(pid).is_none());
    }

    #[test]
    fn baseline_diff_detects_process_lifecycle_reparenting_and_pid_reuse() {
        let mut root = test_process(0, 0, "root");
        root.parent = None;
        let baseline_processes: HashMap<Pid, ProcessInfo> = [
            root.clone(),
            test_process(10, 0, "stable"),
            test_process(11, 0, "exited"),
            test_process(12, 0, "adopted"),
            test_process(42, 0, "old-worker"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        let baseline_resources = baseline_processes
            .keys()
            .map(|pid| (*pid, ResourceAggregate::default()))
            .collect();
        let baseline =
            BaselineSnapshot::capture(&baseline_processes, &baseline_resources, Instant::now());

        let mut reused = test_process(42, 0, "new-worker");
        reused.start_time += 100;
        let current_processes: HashMap<Pid, ProcessInfo> = [
            root,
            test_process(10, 0, "stable"),
            test_process(12, 10, "adopted"),
            test_process(13, 0, "started"),
            reused,
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        let current_resources = current_processes
            .keys()
            .map(|pid| (*pid, ResourceAggregate::default()))
            .collect();

        let diff = baseline.diff(&current_processes, &current_resources);

        assert_eq!(
            diff.started
                .iter()
                .map(|entry| entry.pid.as_u32())
                .collect::<Vec<_>>(),
            vec![13, 42]
        );
        assert_eq!(
            diff.exited
                .iter()
                .map(|entry| entry.pid.as_u32())
                .collect::<Vec<_>>(),
            vec![11, 42]
        );
        assert_eq!(diff.reparented.len(), 1);
        assert_eq!(diff.reparented[0].pid, Pid::from_u32(12));
        assert_eq!(diff.reparented[0].old_parent, Some(Pid::from_u32(0)));
        assert_eq!(diff.reparented[0].new_parent, Some(Pid::from_u32(10)));
        assert_eq!(baseline.len(), 4);
    }

    #[test]
    fn baseline_diff_reports_own_subtree_and_system_resource_growth() {
        let mut root = test_process(0, 0, "root");
        root.parent = None;
        let mut service = test_process(10, 0, "service");
        service.cpu = 2.0;
        service.memory = 10 * 1024 * 1024;
        service.read_rate = 1_000;
        service.write_rate = 2_000;
        let baseline_processes =
            HashMap::from([(root.pid, root.clone()), (service.pid, service.clone())]);
        let baseline_resources = HashMap::from([
            (
                root.pid,
                ResourceAggregate {
                    cpu: 5.0,
                    memory: 100 * 1024 * 1024,
                    read_rate: 10_000,
                    write_rate: 20_000,
                    process_count: 1,
                },
            ),
            (
                service.pid,
                ResourceAggregate {
                    cpu: 5.0,
                    memory: 30 * 1024 * 1024,
                    read_rate: 3_000,
                    write_rate: 4_000,
                    process_count: 2,
                },
            ),
        ]);
        let baseline =
            BaselineSnapshot::capture(&baseline_processes, &baseline_resources, Instant::now());

        service.cpu = 4.5;
        service.memory = 15 * 1024 * 1024;
        service.read_rate = 5_000;
        service.write_rate = 7_000;
        let current_processes = HashMap::from([(root.pid, root), (service.pid, service)]);
        let current_resources = HashMap::from([
            (
                Pid::from_u32(0),
                ResourceAggregate {
                    cpu: 20.0,
                    memory: 125 * 1024 * 1024,
                    read_rate: 30_000,
                    write_rate: 50_000,
                    process_count: 2,
                },
            ),
            (
                Pid::from_u32(10),
                ResourceAggregate {
                    cpu: 15.0,
                    memory: 50 * 1024 * 1024,
                    read_rate: 13_000,
                    write_rate: 24_000,
                    process_count: 3,
                },
            ),
        ]);

        let diff = baseline.diff(&current_processes, &current_resources);
        let service_delta = diff
            .resource_deltas
            .iter()
            .find(|delta| delta.pid == Pid::from_u32(10))
            .expect("service delta");
        assert_eq!(service_delta.own_cpu, 2.5);
        assert_eq!(service_delta.subtree_cpu, 10.0);
        assert_eq!(service_delta.own_memory, 5 * 1024 * 1024);
        assert_eq!(service_delta.subtree_memory, 20 * 1024 * 1024);
        assert_eq!(service_delta.own_read_rate, 4_000);
        assert_eq!(service_delta.own_write_rate, 5_000);
        assert_eq!(service_delta.subtree_read_rate, 10_000);
        assert_eq!(service_delta.subtree_write_rate, 20_000);
        assert_eq!(service_delta.subtree_processes, 1);

        let system_delta = diff.system_delta.expect("system delta");
        assert_eq!(system_delta.subtree_cpu, 15.0);
        assert_eq!(system_delta.subtree_memory, 25 * 1024 * 1024);
        assert_eq!(system_delta.subtree_read_rate, 20_000);
        assert_eq!(system_delta.subtree_write_rate, 30_000);
        assert_eq!(system_delta.subtree_processes, 1);
    }

    #[test]
    fn exports_a_versioned_deterministic_private_json_report() {
        let mut root = test_process(0, 0, "kernel / system");
        root.parent = None;
        let mut later = test_process(42, 0, "worker");
        later.read_rate = 4_096;
        later.write_rate = 8_192;
        let earlier = test_process(9, 0, "service");
        let processes: HashMap<Pid, ProcessInfo> = [root, later, earlier]
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        let resources = HashMap::from([
            (
                Pid::from_u32(0),
                ResourceAggregate {
                    cpu: 3.5,
                    memory: 12_345,
                    read_rate: 4_096,
                    write_rate: 8_192,
                    process_count: 2,
                },
            ),
            (Pid::from_u32(9), ResourceAggregate::default()),
            (
                Pid::from_u32(42),
                ResourceAggregate {
                    cpu: 1.5,
                    memory: 4_096,
                    read_rate: 4_096,
                    write_rate: 8_192,
                    process_count: 1,
                },
            ),
        ]);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "psmore-report-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create report test directory");
        let attention_findings = vec![AttentionFinding {
            pid: Pid::from_u32(42),
            severity: AttentionSeverity::Warning,
            score: 55,
            reasons: vec!["sustained CPU 55.0% avg".into()],
        }];
        let network_scan = NetworkScan {
            endpoints: vec![NetworkEndpoint {
                pid: Some(Pid::from_u32(42)),
                process: "worker".into(),
                fd: "7".into(),
                protocol: "TCP".into(),
                local_endpoint: "127.0.0.1:50000".into(),
                remote_endpoint: "10.0.0.8:443".into(),
                state: "ESTABLISHED".into(),
                namespace: String::new(),
            }],
            warning: None,
        };
        let action_history = vec![ProcessActionRecord {
            observed_at: Instant::now(),
            target: ProcessActionTarget {
                pid: Pid::from_u32(42),
                name: "worker".into(),
                command: "/usr/bin/worker".into(),
                start_time: 42,
            },
            action: ProcessActionKind::Terminate,
            outcome: ProcessActionOutcome::Sent,
        }];
        let inspection = ProcessInspection {
            pid: Pid::from_u32(42),
            name: "worker".into(),
            user: "tester".into(),
            cwd: "/tmp".into(),
            threads: vec![ThreadInfo {
                id: 4_242,
                name: "worker-hot-loop".into(),
                state: "Running".into(),
                cpu_percent: 87.5,
                priority: 20,
                nice: Some(0),
                processor: Some(3),
            }],
            thread_count: 1,
            thread_sample_ms: 250,
            ..ProcessInspection::default()
        };

        let path = export_report(
            ReportInput {
                platform: platform_name(),
                selected_pid: Some(Pid::from_u32(42)),
                query: "mem>1k !name:service",
                query_editing: true,
                query_error: None,
                query_matches: 1,
                paused: true,
                sort_mode: SortMode::Stable,
                processes: &processes,
                resources: &resources,
                events: &[],
                attention_findings: &attention_findings,
                network: Some(&network_scan),
                network_scope: NetworkScope::All,
                network_scan_in_progress: false,
                inspection: Some(&inspection),
                inspection_in_progress: false,
                action_history: &action_history,
                baseline: None,
            },
            &directory,
        )
        .expect("export report");
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read exported report"))
                .expect("parse exported report");

        assert_eq!(report["schema"], "psmore.diagnostic-report");
        assert_eq!(report["schema_version"], 3);
        assert_eq!(report["tool"]["name"], "psmore");
        assert_eq!(report["platform"], platform_name());
        assert_eq!(report["selected_pid"], 42);
        assert_eq!(report["active_query"]["input"], "mem>1k !name:service");
        assert_eq!(report["active_query"]["valid"], true);
        assert_eq!(report["active_query"]["matched_process_count"], 1);
        assert_eq!(report["paused"], true);
        assert_eq!(
            report["collection_status"]["network_scan_in_progress"],
            false
        );
        assert_eq!(report["process_count"], 2);
        assert_eq!(report["system"]["write_bytes_per_second"], 8_192);
        assert_eq!(report["processes"][0]["pid"], 0);
        assert_eq!(report["processes"][1]["pid"], 9);
        assert_eq!(report["processes"][2]["pid"], 42);
        assert_eq!(report["processes"][2]["read_bytes_per_second"], 4_096);
        assert!(report["privacy_notice"].as_str().is_some());
        assert_eq!(report["attention_findings"][0]["pid"], 42);
        assert_eq!(report["attention_findings"][0]["severity"], "WARN");
        assert_eq!(report["attention_findings"][0]["score"], 55);
        assert_eq!(report["network_scan"]["scope"], "all connections");
        assert_eq!(
            report["network_scan"]["endpoints"][0]["remote_endpoint"],
            "10.0.0.8:443"
        );
        assert_eq!(report["network_scan"]["endpoints"][0]["listener"], false);
        assert_eq!(report["process_actions"][0]["pid"], 42);
        assert_eq!(report["process_actions"][0]["action"], "TERM");
        assert_eq!(report["process_actions"][0]["outcome"], "sent");
        assert_eq!(report["selected_inspection"]["thread_count"], 1);
        assert_eq!(
            report["selected_inspection"]["thread_sample_interval_ms"],
            250
        );
        assert_eq!(
            report["selected_inspection"]["thread_rows_truncated"],
            false
        );
        assert_eq!(report["selected_inspection"]["threads"][0]["id"], 4_242);
        assert_eq!(
            report["selected_inspection"]["threads"][0]["cpu_percent"],
            87.5
        );
        assert!(report["baseline"].is_null());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path)
                .expect("report metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::read_dir(&directory)
                .expect("list report directory")
                .filter_map(Result::ok)
                .count(),
            1
        );

        fs::remove_file(path).expect("remove test report");
        fs::remove_dir(directory).expect("remove report test directory");
    }
}
