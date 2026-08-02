use std::{
    collections::BTreeMap,
    fmt::Write as _,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "macos")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::fs;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    headless::human_bytes,
    model::{ProcessInfo, process_command_for_output, process_path, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const SERVICE_SCHEMA: &str = "psmore.service-context";
const SERVICE_SCHEMA_VERSION: u32 = 1;

#[cfg(target_os = "linux")]
const SYSTEMD_PROPERTIES: &str = "Id,Names,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,ControlGroup,MainPID,ExecMainPID,ExecMainCode,ExecMainStatus,Result,Restart,NRestarts,TasksCurrent,MemoryCurrent,CPUUsageNSec,NeedDaemonReload,InvocationID";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityStatus {
    Verified,
    Unverified,
    ExitedDuringCollection,
}

impl IdentityStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
            Self::ExitedDuringCollection => "exited_during_collection",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ServiceProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    path: String,
    command: String,
    start_time_unix_seconds: u64,
}

impl From<&ProcessInfo> for ServiceProcess {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: sanitize_terminal_text(&process.name),
            user: sanitize_terminal_text(&process.user),
            path: sanitize_terminal_text(&process_path(process)),
            command: sanitize_terminal_text(&process_command_for_output(process)),
            start_time_unix_seconds: process.start_time,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct ServiceState {
    description: Option<String>,
    load_state: Option<String>,
    active_state: Option<String>,
    sub_state: Option<String>,
    result: Option<String>,
    unit_file_state: Option<String>,
    main_pid: Option<u32>,
    exec_main_pid: Option<u32>,
    exec_main_code: Option<i32>,
    exec_main_status: Option<i32>,
    restart_policy: Option<String>,
    restart_count: Option<u64>,
    need_daemon_reload: Option<bool>,
    invocation_id: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ServiceConfiguration {
    origin_path: Option<String>,
    drop_in_paths: Vec<String>,
    program: Option<String>,
    arguments: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ServiceResources {
    control_group: Option<String>,
    tasks_current: Option<u64>,
    memory_current_bytes: Option<u64>,
    cpu_usage_nanoseconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct SuggestedCommand {
    purpose: &'static str,
    command: String,
}

#[derive(Clone, Debug, Serialize)]
struct CollectionEvidence {
    complete: bool,
    sources: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ManagerContext {
    manager: &'static str,
    scope: String,
    managed: bool,
    identifier: Option<String>,
    service_target: Option<String>,
    service_root_pid: Option<u32>,
    aliases: Vec<String>,
    state: ServiceState,
    configuration: ServiceConfiguration,
    resources: ServiceResources,
    collection: CollectionEvidence,
    suggested_commands: Vec<SuggestedCommand>,
}

#[derive(Clone, Debug)]
pub(crate) struct CapturedService {
    generated_at_unix_ms: u64,
    hostname: Option<String>,
    identity_status: IdentityStatus,
    identity_warning: Option<String>,
    process: ServiceProcess,
    manager: ManagerContext,
}

#[derive(Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct JsonServiceReport<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<&'a str>,
    process_identity: &'static str,
    process_identity_warning: Option<&'a str>,
    process: &'a ServiceProcess,
    service: &'a ManagerContext,
}

fn verify_instance(
    before: &ProcessInfo,
    after: Option<&ProcessInfo>,
) -> Result<(IdentityStatus, Option<String>), String> {
    let Some(after) = after else {
        return Ok((
            IdentityStatus::ExitedDuringCollection,
            Some(format!(
                "PID {} exited while service context was being collected",
                before.pid
            )),
        ));
    };
    if before.start_time > 0 && after.start_time > 0 {
        if before.start_time != after.start_time {
            return Err(format!(
                "PID {} was reused during service inspection; refusing to combine different process instances",
                before.pid
            ));
        }
        return Ok((IdentityStatus::Verified, None));
    }
    if before.name != after.name
        || process_command_for_output(before) != process_command_for_output(after)
    {
        return Err(format!(
            "PID {} changed identity while service context was being collected",
            before.pid
        ));
    }
    Ok((
        IdentityStatus::Unverified,
        Some(format!(
            "PID {} start time is unavailable; identity was checked using name and command fallback",
            before.pid
        )),
    ))
}

pub(crate) fn capture_service_context(pid: u32) -> Result<CapturedService, String> {
    if pid == 0 {
        return Err("PID 0 is a virtual root and has no service-manager context".into());
    }
    let pid = Pid::from_u32(pid);
    let mut provider = NativeProcessProvider::new();
    let processes = provider.refresh();
    let process = processes
        .iter()
        .find(|process| process.pid == pid)
        .cloned()
        .ok_or_else(|| format!("PID {pid} was not found"))?;

    let manager = collect_manager_context(&process, &processes);
    let after = provider.refresh();
    let (identity_status, identity_warning) = verify_instance(
        &process,
        after.iter().find(|candidate| candidate.pid == pid),
    )?;

    Ok(CapturedService {
        generated_at_unix_ms: unix_millis(),
        hostname: System::host_name().map(|value| sanitize_terminal_text(&value)),
        identity_status,
        identity_warning,
        process: ServiceProcess::from(&process),
        manager,
    })
}

#[cfg(target_os = "linux")]
fn collect_manager_context(process: &ProcessInfo, _processes: &[ProcessInfo]) -> ManagerContext {
    collect_systemd_context(process.pid.as_u32())
}

#[cfg(target_os = "macos")]
fn collect_manager_context(process: &ProcessInfo, processes: &[ProcessInfo]) -> ManagerContext {
    collect_launchd_context(process, processes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_manager_context(_process: &ProcessInfo, _processes: &[ProcessInfo]) -> ManagerContext {
    ManagerContext {
        manager: "unsupported",
        scope: "unknown".into(),
        managed: false,
        identifier: None,
        service_target: None,
        service_root_pid: None,
        aliases: Vec::new(),
        state: ServiceState::default(),
        configuration: ServiceConfiguration::default(),
        resources: ServiceResources::default(),
        collection: CollectionEvidence {
            complete: false,
            sources: Vec::new(),
            warnings: vec!["service-manager inspection is supported on Linux and macOS".into()],
        },
        suggested_commands: Vec::new(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_paths(content: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in content.lines() {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next();
        let controllers = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default().trim();
        if path.is_empty() {
            continue;
        }
        if controllers.is_empty() || controllers.split(',').any(|value| value == "name=systemd") {
            paths.push(path.to_string());
        }
    }
    if paths.is_empty() {
        for line in content.lines() {
            if let Some(path) = line.splitn(3, ':').nth(2).map(str::trim) {
                if !path.is_empty() {
                    paths.push(path.to_string());
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(any(target_os = "linux", test))]
fn select_systemd_unit(paths: &[String]) -> Option<(String, &'static str, String)> {
    let mut selected: Option<(usize, String, &'static str, String)> = None;
    for path in paths {
        let components: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
        let user_manager = components
            .iter()
            .position(|value| value.starts_with("user@") && value.ends_with(".service"));
        for (index, component) in components.iter().enumerate() {
            if !(component.ends_with(".service") || component.ends_with(".scope")) {
                continue;
            }
            let scope = if user_manager.is_some_and(|manager| index > manager) {
                "user"
            } else {
                "system"
            };
            let candidate = (index, (*component).to_string(), scope, path.clone());
            if selected
                .as_ref()
                .is_none_or(|current| candidate.0 > current.0)
            {
                selected = Some(candidate);
            }
        }
    }
    selected.map(|(_, unit, scope, path)| (unit, scope, path))
}

#[cfg(any(target_os = "linux", test))]
fn parse_key_value_lines(content: &str) -> BTreeMap<String, String> {
    content
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            Some((key.to_string(), sanitize_terminal_text(value.trim())))
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn optional_string(properties: &BTreeMap<String, String>, key: &str) -> Option<String> {
    properties
        .get(key)
        .filter(|value| !value.is_empty() && value.as_str() != "[not set]")
        .cloned()
}

#[cfg(any(target_os = "linux", test))]
fn optional_u32(properties: &BTreeMap<String, String>, key: &str) -> Option<u32> {
    properties
        .get(key)
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value > 0)
}

#[cfg(any(target_os = "linux", test))]
fn optional_u64(properties: &BTreeMap<String, String>, key: &str) -> Option<u64> {
    properties
        .get(key)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != u64::MAX)
}

#[cfg(target_os = "linux")]
fn optional_i32(properties: &BTreeMap<String, String>, key: &str) -> Option<i32> {
    properties.get(key).and_then(|value| value.parse().ok())
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_@%+=:,./-".contains(character))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn first_error_line(stderr: &[u8]) -> String {
    let rendered = sanitize_terminal_text(&String::from_utf8_lossy(stderr));
    rendered
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("command failed without an error message")
        .chars()
        .take(500)
        .collect()
}

#[cfg(target_os = "linux")]
fn proc_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

#[cfg(target_os = "linux")]
fn systemctl_show(unit: &str, user_scope: bool) -> Result<BTreeMap<String, String>, String> {
    let mut command = Command::new("systemctl");
    if user_scope {
        command.arg("--user");
    }
    let output = command
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .env("SYSTEMD_PAGER", "cat")
        .args([
            "show",
            "--no-pager",
            "--no-ask-password",
            &format!("--property={SYSTEMD_PROPERTIES}"),
            unit,
        ])
        .output()
        .map_err(|error| format!("cannot run systemctl: {error}"))?;
    if !output.status.success() {
        return Err(first_error_line(&output.stderr));
    }
    Ok(parse_key_value_lines(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

#[cfg(target_os = "linux")]
fn collect_systemd_context(pid: u32) -> ManagerContext {
    let source = format!("/proc/{pid}/cgroup");
    let mut warnings = Vec::new();
    let cgroup = match fs::read_to_string(&source) {
        Ok(content) => content,
        Err(error) => {
            return ManagerContext {
                manager: "systemd",
                scope: "unknown".into(),
                managed: false,
                identifier: None,
                service_target: None,
                service_root_pid: None,
                aliases: Vec::new(),
                state: ServiceState::default(),
                configuration: ServiceConfiguration::default(),
                resources: ServiceResources::default(),
                collection: CollectionEvidence {
                    complete: false,
                    sources: vec![source],
                    warnings: vec![format!("cannot read process cgroup: {error}")],
                },
                suggested_commands: Vec::new(),
            };
        }
    };
    let paths = parse_cgroup_paths(&cgroup);
    let Some((unit, scope, selected_path)) = select_systemd_unit(&paths) else {
        return ManagerContext {
            manager: "systemd",
            scope: "none".into(),
            managed: false,
            identifier: None,
            service_target: None,
            service_root_pid: None,
            aliases: Vec::new(),
            state: ServiceState::default(),
            configuration: ServiceConfiguration::default(),
            resources: ServiceResources {
                control_group: paths.first().cloned(),
                ..ServiceResources::default()
            },
            collection: CollectionEvidence {
                complete: true,
                sources: vec![source],
                warnings: vec![
                    "no .service or .scope component was present in the process cgroup".into(),
                ],
            },
            suggested_commands: Vec::new(),
        };
    };

    let user_scope = scope == "user";
    let can_query = if user_scope {
        match (proc_uid(pid), proc_uid(std::process::id())) {
            (Some(target), Some(current)) if target == current => true,
            (Some(target), Some(current)) => {
                warnings.push(format!(
                    "user unit belongs to UID {target}; current UID {current} cannot query that user manager without changing credentials"
                ));
                false
            }
            _ => {
                warnings.push("could not verify the UID needed to query the user manager".into());
                false
            }
        }
    } else {
        true
    };

    let properties = if can_query {
        match systemctl_show(&unit, user_scope) {
            Ok(properties) => Some(properties),
            Err(error) => {
                warnings.push(format!("systemctl show failed: {error}"));
                None
            }
        }
    } else {
        None
    };

    let mut sources = vec![source];
    if properties.is_some() {
        sources.push(format!(
            "systemctl {}show {}",
            if user_scope { "--user " } else { "" },
            unit
        ));
    }
    let properties = properties.unwrap_or_default();
    let fragment_path = optional_string(&properties, "FragmentPath");
    let aliases = optional_string(&properties, "Names")
        .map(|value| value.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    let command_prefix = if user_scope {
        "systemctl --user"
    } else {
        "systemctl"
    };
    let journal_prefix = if user_scope {
        "journalctl --user"
    } else {
        "journalctl"
    };
    let quoted_unit = shell_quote(&unit);
    let mut commands = vec![
        SuggestedCommand {
            purpose: "status",
            command: format!("{command_prefix} status --no-pager --full {quoted_unit}"),
        },
        SuggestedCommand {
            purpose: "recent logs",
            command: format!("{journal_prefix} -u {quoted_unit} -n 100 --no-pager"),
        },
    ];
    if fragment_path.is_some() {
        commands.push(SuggestedCommand {
            purpose: "effective configuration",
            command: format!("{command_prefix} cat {quoted_unit}"),
        });
    }

    ManagerContext {
        manager: "systemd",
        scope: scope.into(),
        managed: true,
        identifier: Some(unit.clone()),
        service_target: Some(unit),
        service_root_pid: optional_u32(&properties, "MainPID"),
        aliases,
        state: ServiceState {
            description: optional_string(&properties, "Description"),
            load_state: optional_string(&properties, "LoadState"),
            active_state: optional_string(&properties, "ActiveState"),
            sub_state: optional_string(&properties, "SubState"),
            result: optional_string(&properties, "Result"),
            unit_file_state: optional_string(&properties, "UnitFileState"),
            main_pid: optional_u32(&properties, "MainPID"),
            exec_main_pid: optional_u32(&properties, "ExecMainPID"),
            exec_main_code: optional_i32(&properties, "ExecMainCode"),
            exec_main_status: optional_i32(&properties, "ExecMainStatus"),
            restart_policy: optional_string(&properties, "Restart"),
            restart_count: optional_u64(&properties, "NRestarts"),
            need_daemon_reload: properties
                .get("NeedDaemonReload")
                .map(|value| value == "yes"),
            invocation_id: optional_string(&properties, "InvocationID"),
        },
        configuration: ServiceConfiguration {
            origin_path: fragment_path,
            drop_in_paths: optional_string(&properties, "DropInPaths")
                .map(|value| value.split_whitespace().map(str::to_string).collect())
                .unwrap_or_default(),
            program: None,
            arguments: Vec::new(),
        },
        resources: ServiceResources {
            control_group: optional_string(&properties, "ControlGroup").or(Some(selected_path)),
            tasks_current: optional_u64(&properties, "TasksCurrent"),
            memory_current_bytes: optional_u64(&properties, "MemoryCurrent"),
            cpu_usage_nanoseconds: optional_u64(&properties, "CPUUsageNSec"),
        },
        collection: CollectionEvidence {
            complete: !properties.is_empty(),
            sources,
            warnings,
        },
        suggested_commands: commands,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn systemd_unit_for_pid(pid: u32) -> Result<Option<(String, &'static str)>, String> {
    let source = format!("/proc/{pid}/cgroup");
    let content =
        fs::read_to_string(&source).map_err(|error| format!("cannot read {source}: {error}"))?;
    Ok(
        select_systemd_unit(&parse_cgroup_paths(&content))
            .map(|(unit, scope, _path)| (unit, scope)),
    )
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LaunchdListEntry {
    pid: Option<u32>,
    last_exit_status: Option<i32>,
    label: String,
}

#[cfg(any(target_os = "macos", test))]
fn parse_launchctl_list(content: &str) -> Vec<LaunchdListEntry> {
    content
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 3 || fields[0] == "PID" {
                return None;
            }
            Some(LaunchdListEntry {
                pid: fields[0].parse().ok(),
                last_exit_status: fields[1].parse().ok(),
                label: sanitize_terminal_text(fields[2]),
            })
        })
        .collect()
}

#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
struct LaunchdDetails {
    scalars: BTreeMap<String, String>,
    arguments: Vec<String>,
}

#[cfg(any(target_os = "macos", test))]
fn unquote_launchd_value(value: &str) -> String {
    let value = value.trim().trim_end_matches(';').trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .to_string()
}

#[cfg(any(target_os = "macos", test))]
fn parse_launchctl_details(content: &str) -> LaunchdDetails {
    let mut details = LaunchdDetails::default();
    let mut arguments = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if arguments {
            if trimmed == ");" {
                arguments = false;
            } else if trimmed.starts_with('"') {
                details
                    .arguments
                    .push(sanitize_terminal_text(&unquote_launchd_value(trimmed)));
            }
            continue;
        }
        if trimmed == "\"ProgramArguments\" = (" {
            arguments = true;
            continue;
        }
        let Some((key, value)) = trimmed.split_once(" = ") else {
            continue;
        };
        let Some(key) = key
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            continue;
        };
        if matches!(
            key,
            "Label" | "PID" | "LastExitStatus" | "Program" | "OnDemand"
        ) {
            details.scalars.insert(
                key.into(),
                sanitize_terminal_text(&unquote_launchd_value(value)),
            );
        }
    }
    details
}

#[cfg(any(target_os = "macos", test))]
fn parse_launchctl_print_scalars(content: &str) -> BTreeMap<String, String> {
    const KEYS: [&str; 10] = [
        "path",
        "state",
        "bundle id",
        "program",
        "domain",
        "managed_by",
        "runs",
        "pid",
        "last exit code",
        "job state",
    ];
    content
        .lines()
        .filter_map(|line| {
            let line = line.strip_prefix('\t')?;
            if line.starts_with(['\t', ' ']) {
                return None;
            }
            let (key, value) = line.split_once(" = ")?;
            KEYS.contains(&key).then(|| {
                (
                    key.to_string(),
                    sanitize_terminal_text(value.trim().trim_matches('"')),
                )
            })
        })
        .collect()
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_resource_coalition(content: &str) -> (Option<String>, Option<String>) {
    let mut in_resource = false;
    let mut name = None;
    let mut bundle = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "resource coalition = {" {
            in_resource = true;
            continue;
        }
        if in_resource && trimmed == "}" {
            break;
        }
        if !in_resource {
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("name = ") {
            name = Some(sanitize_terminal_text(value.trim_matches('"')));
        }
        if let Some(value) = trimmed.strip_prefix("bundle ID = ") {
            bundle = Some(sanitize_terminal_text(value.trim_matches('"')));
        }
    }
    (name, bundle)
}

#[cfg(target_os = "macos")]
fn launchctl_output(arguments: &[&str]) -> Result<std::process::Output, String> {
    Command::new("launchctl")
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot run launchctl: {error}"))
}

#[cfg(target_os = "macos")]
fn discover_launchd_target(label: &str, uid: Option<u32>) -> (Option<String>, Option<String>) {
    let mut candidates = Vec::new();
    if let Some(uid) = uid {
        candidates.push(format!("gui/{uid}/{label}"));
        candidates.push(format!("user/{uid}/{label}"));
    }
    candidates.push(format!("system/{label}"));
    for candidate in candidates {
        if let Ok(output) = launchctl_output(&["print", &candidate]) {
            if output.status.success() {
                return (
                    Some(candidate),
                    Some(String::from_utf8_lossy(&output.stdout).into_owned()),
                );
            }
        }
    }
    (None, None)
}

#[cfg(target_os = "macos")]
fn current_launchd_uid() -> Option<u32> {
    let output = launchctl_output(&["manageruid"]).ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
        .flatten()
}

#[cfg(target_os = "macos")]
fn ancestor_pids(process: &ProcessInfo, processes: &[ProcessInfo]) -> Vec<u32> {
    let by_pid: HashMap<Pid, &ProcessInfo> = processes
        .iter()
        .map(|candidate| (candidate.pid, candidate))
        .collect();
    let mut result = Vec::new();
    let mut current = Some(process.pid);
    let mut seen = HashSet::new();
    while let Some(pid) = current {
        if !seen.insert(pid) {
            break;
        }
        result.push(pid.as_u32());
        current = by_pid.get(&pid).and_then(|candidate| candidate.parent);
    }
    result
}

#[cfg(target_os = "macos")]
fn collect_launchd_context(process: &ProcessInfo, processes: &[ProcessInfo]) -> ManagerContext {
    let mut sources = Vec::new();
    let mut warnings = Vec::new();
    let list_output = match launchctl_output(&["list"]) {
        Ok(output) if output.status.success() => {
            sources.push("launchctl list".into());
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
        Ok(output) => {
            warnings.push(format!(
                "launchctl list failed: {}",
                first_error_line(&output.stderr)
            ));
            String::new()
        }
        Err(error) => {
            warnings.push(error);
            String::new()
        }
    };
    let entries = parse_launchctl_list(&list_output);
    let ancestors = ancestor_pids(process, processes);
    let mut entry = ancestors
        .iter()
        .find_map(|pid| entries.iter().find(|entry| entry.pid == Some(*pid)))
        .cloned();

    let pid_target = format!("pid/{}", process.pid.as_u32());
    let pid_context = launchctl_output(&["print", &pid_target])
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            sources.push(format!("launchctl print {pid_target}"));
            String::from_utf8_lossy(&output.stdout).into_owned()
        });
    let (coalition_name, bundle_id) = pid_context
        .as_deref()
        .map(parse_resource_coalition)
        .unwrap_or_default();

    if entry.is_none() {
        if let Some(label) = coalition_name.as_deref() {
            if let Ok(output) = launchctl_output(&["list", label]) {
                if output.status.success() {
                    entry = Some(LaunchdListEntry {
                        pid: None,
                        last_exit_status: None,
                        label: label.into(),
                    });
                }
            }
        }
    }

    let Some(entry) = entry else {
        warnings.push(
            "no loaded launchd job in the current bootstrap namespace matched the process ancestor chain"
                .into(),
        );
        return ManagerContext {
            manager: "launchd",
            scope: "current_bootstrap".into(),
            managed: false,
            identifier: coalition_name,
            service_target: None,
            service_root_pid: None,
            aliases: bundle_id.into_iter().collect(),
            state: ServiceState::default(),
            configuration: ServiceConfiguration::default(),
            resources: ServiceResources::default(),
            collection: CollectionEvidence {
                complete: false,
                sources,
                warnings,
            },
            suggested_commands: vec![SuggestedCommand {
                purpose: "process launch context",
                command: format!("launchctl print {pid_target}"),
            }],
        };
    };

    let details_output = launchctl_output(&["list", &entry.label])
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            sources.push(format!("launchctl list {}", entry.label));
            String::from_utf8_lossy(&output.stdout).into_owned()
        });
    let details = details_output
        .as_deref()
        .map(parse_launchctl_details)
        .unwrap_or_default();
    if details_output.is_none() {
        warnings.push("launchctl could identify the job but not read its details".into());
    }

    let uid = current_launchd_uid();
    let (target, print_output) = discover_launchd_target(&entry.label, uid);
    if let Some(target) = target.as_deref() {
        sources.push(format!("launchctl print {target}"));
    }
    let print_scalars = print_output
        .as_deref()
        .map(parse_launchctl_print_scalars)
        .unwrap_or_default();
    let scope = target
        .as_deref()
        .and_then(|value| value.split('/').next())
        .unwrap_or("current_bootstrap")
        .to_string();
    let main_pid = details
        .scalars
        .get("PID")
        .and_then(|value| value.parse().ok())
        .or(entry.pid)
        .or_else(|| {
            print_scalars
                .get("pid")
                .and_then(|value| value.parse().ok())
        });
    let last_exit_status = details
        .scalars
        .get("LastExitStatus")
        .and_then(|value| value.parse::<i32>().ok())
        .or(entry.last_exit_status);
    let active = main_pid.is_some();
    let origin_path = print_scalars
        .get("path")
        .filter(|value| value.starts_with('/'))
        .cloned();
    let program = details
        .scalars
        .get("Program")
        .cloned()
        .or_else(|| print_scalars.get("program").cloned());
    let quoted_label = shell_quote(&entry.label);
    let mut commands = vec![SuggestedCommand {
        purpose: "status",
        command: target
            .as_deref()
            .map(|target| format!("launchctl print {}", shell_quote(target)))
            .unwrap_or_else(|| format!("launchctl list {quoted_label}")),
    }];
    if let Some(target) = target.as_deref() {
        commands.push(SuggestedCommand {
            purpose: "why running",
            command: format!("launchctl blame {}", shell_quote(target)),
        });
    }
    if let Some(pid) = main_pid {
        commands.push(SuggestedCommand {
            purpose: "live unified logs",
            command: format!("log stream --style compact --predicate 'processIdentifier == {pid}'"),
        });
    }
    if let Some(path) = origin_path.as_deref() {
        commands.push(SuggestedCommand {
            purpose: "configuration",
            command: format!("plutil -p {}", shell_quote(path)),
        });
    }

    ManagerContext {
        manager: "launchd",
        scope,
        managed: true,
        identifier: Some(entry.label.clone()),
        service_target: target,
        service_root_pid: main_pid,
        aliases: bundle_id.into_iter().collect(),
        state: ServiceState {
            description: print_scalars.get("bundle id").cloned(),
            load_state: Some("loaded".into()),
            active_state: Some(if active { "active" } else { "inactive" }.into()),
            sub_state: print_scalars
                .get("job state")
                .or_else(|| print_scalars.get("state"))
                .cloned()
                .or_else(|| active.then(|| "running".into())),
            result: last_exit_status.map(|status| {
                if status == 0 {
                    "success".into()
                } else {
                    format!("exit-status-{status}")
                }
            }),
            unit_file_state: None,
            main_pid,
            exec_main_pid: main_pid,
            exec_main_code: None,
            exec_main_status: last_exit_status,
            restart_policy: details
                .scalars
                .get("OnDemand")
                .filter(|value| value.as_str() == "true")
                .map(|_| "on-demand".into()),
            restart_count: print_scalars
                .get("runs")
                .and_then(|value| value.parse().ok()),
            need_daemon_reload: None,
            invocation_id: None,
        },
        configuration: ServiceConfiguration {
            origin_path,
            drop_in_paths: Vec::new(),
            program,
            arguments: details.arguments,
        },
        resources: ServiceResources::default(),
        collection: CollectionEvidence {
            complete: details_output.is_some(),
            sources,
            warnings,
        },
        suggested_commands: commands,
    }
}

pub(crate) fn render_service_json(captured: &CapturedService) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&JsonServiceReport {
        schema: SERVICE_SCHEMA,
        schema_version: SERVICE_SCHEMA_VERSION,
        privacy_notice: "Contains process command, path, user, service identifiers, configuration paths, host information, and operational commands; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: captured.hostname.as_deref(),
        process_identity: captured.identity_status.label(),
        process_identity_warning: captured.identity_warning.as_deref(),
        process: &captured.process,
        service: &captured.manager,
    })
}

fn optional(value: Option<&str>) -> &str {
    value.filter(|value| !value.is_empty()).unwrap_or("unknown")
}

pub(crate) fn render_service_table(captured: &CapturedService) -> String {
    let mut output = String::new();
    let manager = &captured.manager;
    let _ = writeln!(output, "PSMORE SERVICE CONTEXT");
    let _ = writeln!(
        output,
        "process {}  {}  user {}  identity {}",
        captured.process.pid,
        captured.process.name,
        optional(Some(&captured.process.user)),
        captured.identity_status.label(),
    );
    let _ = writeln!(output, "command {}", captured.process.command);
    let _ = writeln!(
        output,
        "manager {}  scope {}  managed {}  coverage {}",
        manager.manager,
        manager.scope,
        if manager.managed { "yes" } else { "no" },
        if manager.collection.complete {
            "complete"
        } else {
            "partial"
        },
    );
    if let Some(identifier) = manager.identifier.as_deref() {
        let _ = writeln!(
            output,
            "service {}  target {}  root PID {}",
            identifier,
            optional(manager.service_target.as_deref()),
            manager
                .service_root_pid
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("none"),
        );
    }
    let state = &manager.state;
    if manager.managed {
        let _ = writeln!(
            output,
            "state {}/{}  load {}  result {}  enabled {}",
            optional(state.active_state.as_deref()),
            optional(state.sub_state.as_deref()),
            optional(state.load_state.as_deref()),
            optional(state.result.as_deref()),
            optional(state.unit_file_state.as_deref()),
        );
        if let Some(description) = state.description.as_deref() {
            let _ = writeln!(output, "description {description}");
        }
        let _ = writeln!(
            output,
            "restart {}  count {}  exec status {}",
            optional(state.restart_policy.as_deref()),
            state
                .restart_count
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("unknown"),
            state
                .exec_main_status
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("unknown"),
        );
    }
    let config = &manager.configuration;
    if config.origin_path.is_some() || config.program.is_some() || !config.drop_in_paths.is_empty()
    {
        let _ = writeln!(
            output,
            "config {}  program {}",
            optional(config.origin_path.as_deref()),
            optional(config.program.as_deref()),
        );
        if !config.drop_in_paths.is_empty() {
            let _ = writeln!(output, "drop-ins {}", config.drop_in_paths.join(" "));
        }
    }
    let resources = &manager.resources;
    if resources.control_group.is_some()
        || resources.tasks_current.is_some()
        || resources.memory_current_bytes.is_some()
    {
        let _ = writeln!(
            output,
            "cgroup {}  tasks {}  memory {}  CPU {:.3}s",
            optional(resources.control_group.as_deref()),
            resources
                .tasks_current
                .map(|value| value.to_string())
                .as_deref()
                .unwrap_or("unknown"),
            resources
                .memory_current_bytes
                .map(human_bytes)
                .as_deref()
                .unwrap_or("unknown"),
            resources.cpu_usage_nanoseconds.unwrap_or(0) as f64 / 1_000_000_000.0,
        );
    }
    if !manager.collection.sources.is_empty() {
        let _ = writeln!(
            output,
            "evidence {}",
            manager.collection.sources.join(" | ")
        );
    }
    if let Some(warning) = captured.identity_warning.as_deref() {
        let _ = writeln!(output, "warning {warning}");
    }
    for warning in &manager.collection.warnings {
        let _ = writeln!(output, "warning {warning}");
    }
    for command in &manager.suggested_commands {
        let _ = writeln!(output, "next {}: {}", command.purpose, command.command);
    }
    output
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_deepest_system_and_user_units_from_cgroups() {
        let paths = parse_cgroup_paths("0::/system.slice/ssh.service\n");
        assert_eq!(
            select_systemd_unit(&paths),
            Some((
                "ssh.service".into(),
                "system",
                "/system.slice/ssh.service".into()
            ))
        );
        let paths = parse_cgroup_paths(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/api.service\n",
        );
        assert_eq!(
            select_systemd_unit(&paths),
            Some((
                "api.service".into(),
                "user",
                "/user.slice/user-1000.slice/user@1000.service/app.slice/api.service".into()
            ))
        );
        let paths = parse_cgroup_paths(
            "2:cpu:/legacy\n1:name=systemd:/user.slice/user-1000.slice/session-7.scope\n",
        );
        assert_eq!(select_systemd_unit(&paths).unwrap().0, "session-7.scope");
    }

    #[test]
    fn parses_systemctl_properties_without_order_assumptions() {
        let properties = parse_key_value_lines(
            "Restart=on-failure\nMainPID=42\nDescription=API service\nActiveState=active\nMemoryCurrent=4096\nNeedDaemonReload=no\n",
        );
        assert_eq!(optional_u32(&properties, "MainPID"), Some(42));
        assert_eq!(optional_u64(&properties, "MemoryCurrent"), Some(4096));
        assert_eq!(
            optional_string(&properties, "ActiveState").as_deref(),
            Some("active")
        );
        assert_eq!(properties["NeedDaemonReload"], "no");
    }

    #[test]
    fn parses_launchctl_stable_list_and_allowlisted_details() {
        let entries = parse_launchctl_list(
            "PID\tStatus\tLabel\n82554\t0\tapplication.com.example\n-\t-9\tcom.example.worker\n",
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].pid, Some(82554));
        assert_eq!(entries[1].last_exit_status, Some(-9));

        let details = parse_launchctl_details(
            "{\n\t\"Label\" = \"com.example.api\";\n\t\"EnvironmentVariables\" = {\n\t\t\"TOKEN\" = \"must-not-escape\";\n\t};\n\t\"PID\" = 42;\n\t\"Program\" = \"/opt/api\";\n\t\"ProgramArguments\" = (\n\t\t\"/opt/api\";\n\t\t\"--serve\";\n\t);\n}\n",
        );
        assert_eq!(details.scalars["Label"], "com.example.api");
        assert_eq!(details.scalars["PID"], "42");
        assert_eq!(details.arguments, ["/opt/api", "--serve"]);
        assert!(
            !details
                .scalars
                .values()
                .any(|value| value.contains("must-not-escape"))
        );
    }

    #[test]
    fn parses_launchctl_print_without_collecting_nested_environment() {
        let output = "gui/501/com.example.api = {\n\tstate = running\n\tprogram = /opt/api\n\tenvironment = {\n\t\tTOKEN => secret\n\t}\n\truns = 3\n\tpid = 42\n}\n";
        let values = parse_launchctl_print_scalars(output);
        assert_eq!(values["state"], "running");
        assert_eq!(values["program"], "/opt/api");
        assert_eq!(values["runs"], "3");
        assert!(!values.values().any(|value| value.contains("secret")));
    }

    #[test]
    fn parses_only_resource_coalition_identity() {
        let output = "environment = {\n\tTOKEN = secret\n}\nresource coalition = {\n\tID = 7\n\tname = application.com.example\n\tbundle ID = com.example.app\n}\njetsam coalition = {\n\tname = unrelated\n}\n";
        assert_eq!(
            parse_resource_coalition(output),
            (
                Some("application.com.example".into()),
                Some("com.example.app".into())
            )
        );
    }
}
