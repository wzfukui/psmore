use std::{
    fmt::Write as _,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "macos")]
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader},
    process::Stdio,
};

use serde::Serialize;
use serde_json::Value;
use sysinfo::{Pid, System};

use crate::{
    cli::{LogPriority, LogScope},
    model::{
        ProcessInfo, command_for_output, process_command_for_output, process_path,
        sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

#[cfg(target_os = "linux")]
use crate::headless_service::systemd_unit_for_pid;

const LOGS_SCHEMA: &str = "psmore.process-logs";
const LOGS_SCHEMA_VERSION: u32 = 1;

fn bounded_log_start(requested: u64, process_start: u64, service_scope: bool) -> u64 {
    if service_scope || process_start == 0 {
        requested
    } else {
        requested.max(process_start)
    }
}

#[cfg(any(target_os = "linux", test))]
fn select_log_unit(
    requested_scope: LogScope,
    unit: Option<(String, &'static str)>,
) -> Option<(String, &'static str)> {
    match requested_scope {
        LogScope::Process => None,
        LogScope::Auto => unit.filter(|(name, _scope)| name.ends_with(".service")),
        LogScope::Service => unit,
    }
}

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
struct LogProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    path: String,
    command: String,
    start_time_unix_seconds: u64,
}

impl From<&ProcessInfo> for LogProcess {
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

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LogEntry {
    timestamp: String,
    timestamp_unix_microseconds: Option<u64>,
    priority: String,
    process_id: Option<u32>,
    process: String,
    service: Option<String>,
    subsystem: Option<String>,
    category: Option<String>,
    message: String,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct LogSource {
    backend: &'static str,
    requested_scope: &'static str,
    effective_scope: &'static str,
    selector: String,
    service: Option<String>,
    service_scope: Option<String>,
    start_unix_seconds: u64,
    end_unix_seconds: u64,
    priority: &'static str,
    limit: usize,
    returned_count: usize,
    truncated: bool,
    complete: bool,
    warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CapturedLogs {
    generated_at_unix_ms: u64,
    hostname: Option<String>,
    identity_status: IdentityStatus,
    identity_warning: Option<String>,
    process: LogProcess,
    source: LogSource,
    entries: Vec<LogEntry>,
}

#[derive(Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct JsonLogsReport<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<&'a str>,
    process_identity: &'static str,
    process_identity_warning: Option<&'a str>,
    process: &'a LogProcess,
    source: &'a LogSource,
    entries: &'a [LogEntry],
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn verify_instance(
    before: &ProcessInfo,
    after: Option<&ProcessInfo>,
) -> Result<(IdentityStatus, Option<String>), String> {
    let Some(after) = after else {
        return Ok((
            IdentityStatus::ExitedDuringCollection,
            Some(format!(
                "PID {} exited while logs were being collected; entries remain bounded by the original process start time",
                before.pid
            )),
        ));
    };
    if before.start_time > 0 && after.start_time > 0 {
        if before.start_time != after.start_time {
            return Err(format!(
                "PID {} was reused during log collection; refusing to attribute entries to a different process instance",
                before.pid
            ));
        }
        return Ok((IdentityStatus::Verified, None));
    }
    if before.name != after.name
        || process_command_for_output(before) != process_command_for_output(after)
    {
        return Err(format!(
            "PID {} changed identity while logs were being collected",
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

fn json_string(value: Option<&Value>) -> Option<String> {
    let value = value?;
    if let Some(value) = value.as_str() {
        return Some(value.to_string());
    }
    if let Some(bytes) = value.as_array().and_then(|values| {
        values
            .iter()
            .map(|value| value.as_u64().and_then(|value| u8::try_from(value).ok()))
            .collect::<Option<Vec<_>>>()
    }) {
        return Some(String::from_utf8_lossy(&bytes).into_owned());
    }
    (!value.is_null()).then(|| value.to_string())
}

fn safe_text(value: impl AsRef<str>) -> String {
    command_for_output(&sanitize_terminal_text(value.as_ref()))
}

fn optional_safe(value: Option<String>) -> Option<String> {
    value.map(safe_text).filter(|value| !value.is_empty())
}

#[cfg(any(target_os = "linux", test))]
fn priority_label(value: Option<&str>) -> String {
    match value.and_then(|value| value.parse::<u8>().ok()) {
        Some(0) => "emergency",
        Some(1) => "alert",
        Some(2) => "critical",
        Some(3) => "error",
        Some(4) => "warning",
        Some(5) => "notice",
        Some(6) => "info",
        Some(7) => "debug",
        _ => "unknown",
    }
    .into()
}

#[cfg(any(target_os = "linux", test))]
fn journal_permission_limited(stderr: &str) -> bool {
    let normalized = stderr.to_ascii_lowercase();
    normalized.contains("insufficient permissions")
        || normalized.contains("permission denied")
        || normalized.contains("not seeing messages from other users")
}

#[cfg(any(target_os = "linux", test))]
fn format_unix_microseconds_utc(microseconds: u64) -> String {
    let seconds = microseconds / 1_000_000;
    let millis = (microseconds % 1_000_000) / 1_000;
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;

    // Proleptic Gregorian conversion from days since 1970-01-01.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

#[cfg(any(target_os = "linux", test))]
fn parse_journal_entry(line: &str) -> Option<LogEntry> {
    let value: Value = serde_json::from_str(line).ok()?;
    let message = safe_text(json_string(value.get("MESSAGE"))?);
    let timestamp_unix_microseconds =
        json_string(value.get("__REALTIME_TIMESTAMP")).and_then(|value| value.parse().ok());
    let timestamp = timestamp_unix_microseconds
        .map(format_unix_microseconds_utc)
        .unwrap_or_else(|| "unknown-time".into());
    let process_id = json_string(value.get("_PID")).and_then(|value| value.parse().ok());
    let process = optional_safe(
        json_string(value.get("SYSLOG_IDENTIFIER")).or_else(|| json_string(value.get("_COMM"))),
    )
    .unwrap_or_else(|| "unknown".into());
    Some(LogEntry {
        timestamp,
        timestamp_unix_microseconds,
        priority: priority_label(json_string(value.get("PRIORITY")).as_deref()),
        process_id,
        process,
        service: optional_safe(
            json_string(value.get("_SYSTEMD_UNIT"))
                .or_else(|| json_string(value.get("_SYSTEMD_USER_UNIT"))),
        ),
        subsystem: None,
        category: None,
        message,
        cursor: optional_safe(json_string(value.get("__CURSOR"))),
    })
}

#[cfg(any(target_os = "macos", test))]
fn mac_priority_label(value: Option<&str>) -> String {
    value
        .map(|value| value.to_ascii_lowercase())
        // Unified Log omits `messageType` for many default-level activity
        // events. `log show` already applies the requested verbosity bound,
        // so treating the absent field as default is more accurate than
        // presenting those ordinary records as an unknown severity.
        .unwrap_or_else(|| "default".into())
}

#[cfg(any(target_os = "macos", test))]
fn parse_unified_log_entry(line: &str) -> Option<LogEntry> {
    let value: Value = serde_json::from_str(line).ok()?;
    if value.get("finished").is_some() {
        return None;
    }
    let message = safe_text(json_string(value.get("eventMessage"))?);
    Some(LogEntry {
        timestamp: optional_safe(json_string(value.get("timestamp")))
            .unwrap_or_else(|| "unknown-time".into()),
        timestamp_unix_microseconds: None,
        priority: mac_priority_label(json_string(value.get("messageType")).as_deref()),
        process_id: value
            .get("processID")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok()),
        process: optional_safe(
            json_string(value.get("processImagePath"))
                .map(|path| path.rsplit('/').next().unwrap_or(path.as_str()).to_string()),
        )
        .unwrap_or_else(|| "unknown".into()),
        service: None,
        subsystem: optional_safe(json_string(value.get("subsystem"))),
        category: optional_safe(json_string(value.get("category"))),
        message,
        cursor: None,
    })
}

#[cfg(target_os = "linux")]
fn collect_native_logs(
    pid: u32,
    requested_scope: LogScope,
    priority: LogPriority,
    requested_start_unix_seconds: u64,
    process_start_unix_seconds: u64,
    end_unix_seconds: u64,
    limit: usize,
) -> Result<(LogSource, Vec<LogEntry>), String> {
    let mut warnings = Vec::new();
    let unit = match requested_scope {
        LogScope::Process => None,
        LogScope::Auto | LogScope::Service => match systemd_unit_for_pid(pid) {
            // Automatic selection broadens from one PID only for an actual
            // service. Generic login/session scopes can contain unrelated
            // applications and would make an innocent `psmore logs PID`
            // disclose a much wider journal than the user asked for.
            Ok(unit) => select_log_unit(requested_scope, unit),
            Err(error) => {
                warnings.push(error);
                None
            }
        },
    };
    if requested_scope == LogScope::Service && unit.is_none() {
        return Err(format!(
            "PID {pid} is not inside a readable systemd service or scope; use --scope process"
        ));
    }
    let (effective_scope, selector, service, service_scope) = if let Some((unit, scope)) = unit {
        (
            "service",
            if scope == "user" {
                format!("_SYSTEMD_USER_UNIT={unit}")
            } else {
                format!("_SYSTEMD_UNIT={unit}")
            },
            Some(unit),
            Some(scope.to_string()),
        )
    } else {
        ("process", format!("_PID={pid}"), None, None)
    };
    let start_unix_seconds = bounded_log_start(
        requested_start_unix_seconds,
        process_start_unix_seconds,
        effective_scope == "service",
    );

    let mut command = Command::new("journalctl");
    command.env("LC_ALL", "C").env("SYSTEMD_COLORS", "0").args([
        "--no-pager",
        "--output=json",
        "--reverse",
        &format!("--lines={}", limit.saturating_add(1)),
        &format!("--since=@{start_unix_seconds}"),
        &format!("--until=@{end_unix_seconds}"),
        &format!("--priority=0..{}", priority.syslog_max()),
    ]);
    if let Some(unit) = service.as_deref() {
        if service_scope.as_deref() == Some("user") {
            command.arg(format!("--user-unit={unit}"));
        } else {
            command.arg(format!("--unit={unit}"));
        }
    } else {
        command.arg(format!("_PID={pid}"));
    }
    let output = command
        .output()
        .map_err(|error| format!("cannot run journalctl: {error}"))?;
    let stderr = sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr));
    let permission_limited = journal_permission_limited(&stderr);
    if !output.status.success() && !permission_limited {
        return Err(format!(
            "journalctl failed: {}",
            stderr.lines().next().unwrap_or("unknown error")
        ));
    }
    if let Some(warning) = stderr.lines().find(|line| !line.trim().is_empty()) {
        warnings.push(format!(
            "journalctl reported: {}",
            warning.chars().take(500).collect::<String>()
        ));
    }
    let mut entries: Vec<_> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_journal_entry)
        .collect();
    let truncated = entries.len() > limit;
    entries.truncate(limit);
    let complete = warnings.is_empty();
    Ok((
        LogSource {
            backend: "journald",
            requested_scope: requested_scope.label(),
            effective_scope,
            selector,
            service,
            service_scope,
            start_unix_seconds,
            end_unix_seconds,
            priority: priority.label(),
            limit,
            returned_count: entries.len(),
            truncated,
            complete,
            warnings,
        },
        entries,
    ))
}

#[cfg(target_os = "macos")]
fn collect_native_logs(
    pid: u32,
    requested_scope: LogScope,
    priority: LogPriority,
    requested_start_unix_seconds: u64,
    process_start_unix_seconds: u64,
    end_unix_seconds: u64,
    limit: usize,
) -> Result<(LogSource, Vec<LogEntry>), String> {
    if requested_scope == LogScope::Service {
        return Err("macOS unified logging cannot safely reconstruct historical logs for every process generation of a launchd job; use --scope process".into());
    }
    let start_unix_seconds = bounded_log_start(
        requested_start_unix_seconds,
        process_start_unix_seconds,
        false,
    );
    let mut command = Command::new("/usr/bin/log");
    command.args([
        "show",
        "--no-pager",
        "--style",
        "ndjson",
        "--start",
        &format!("@{start_unix_seconds}"),
        "--end",
        &format!("@{end_unix_seconds}"),
        "--process",
        &pid.to_string(),
    ]);
    if matches!(priority, LogPriority::Info | LogPriority::Debug) {
        command.arg("--info");
    }
    if priority == LogPriority::Debug {
        command.arg("--debug");
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run macOS log show: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "cannot read macOS log output".to_string())?;
    let mut retained = VecDeque::with_capacity(limit.saturating_add(1));
    let mut parsed_count = 0usize;
    for line in BufReader::new(stdout).lines() {
        let line = line.map_err(|error| format!("cannot read macOS log output: {error}"))?;
        if let Some(entry) = parse_unified_log_entry(&line) {
            if priority.includes_macos(&entry.priority) {
                parsed_count = parsed_count.saturating_add(1);
                retained.push_back(entry);
                if retained.len() > limit {
                    retained.pop_front();
                }
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot finish macOS log show: {error}"))?;
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "macOS log show failed: {}",
            sanitize_terminal_text(error.lines().next().unwrap_or("unknown error"))
        ));
    }
    let entries = retained.into_iter().rev().collect::<Vec<_>>();
    Ok((
        LogSource {
            backend: "unified-log",
            requested_scope: requested_scope.label(),
            effective_scope: "process",
            selector: format!("processIdentifier == {pid}"),
            service: None,
            service_scope: None,
            start_unix_seconds,
            end_unix_seconds,
            priority: priority.label(),
            limit,
            returned_count: entries.len(),
            truncated: parsed_count > limit,
            complete: true,
            warnings: Vec::new(),
        },
        entries,
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_native_logs(
    _pid: u32,
    _requested_scope: LogScope,
    _priority: LogPriority,
    _requested_start_unix_seconds: u64,
    _process_start_unix_seconds: u64,
    _end_unix_seconds: u64,
    _limit: usize,
) -> Result<(LogSource, Vec<LogEntry>), String> {
    Err("process log collection is supported on Linux and macOS".into())
}

pub(crate) fn capture_logs(
    pid: u32,
    requested_scope: LogScope,
    priority: LogPriority,
    since_seconds: u64,
    limit: usize,
) -> Result<CapturedLogs, String> {
    if pid == 0 {
        return Err("PID 0 is a virtual root and has no process log identity".into());
    }
    let pid_value = Pid::from_u32(pid);
    let mut provider = NativeProcessProvider::new();
    let processes = provider.refresh();
    let process = processes
        .iter()
        .find(|process| process.pid == pid_value)
        .cloned()
        .ok_or_else(|| format!("PID {pid} was not found"))?;
    let end_unix_seconds = unix_seconds();
    let requested_start = end_unix_seconds.saturating_sub(since_seconds);
    let (source, entries) = collect_native_logs(
        pid,
        requested_scope,
        priority,
        requested_start,
        process.start_time,
        end_unix_seconds,
        limit,
    )?;
    let after = provider.refresh();
    let (identity_status, identity_warning) = verify_instance(
        &process,
        after.iter().find(|candidate| candidate.pid == pid_value),
    )?;
    Ok(CapturedLogs {
        generated_at_unix_ms: unix_millis(),
        hostname: System::host_name().map(|value| sanitize_terminal_text(&value)),
        identity_status,
        identity_warning,
        process: LogProcess::from(&process),
        source,
        entries,
    })
}

pub(crate) fn render_logs_json(captured: &CapturedLogs) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&JsonLogsReport {
        schema: LOGS_SCHEMA,
        schema_version: LOGS_SCHEMA_VERSION,
        privacy_notice: "Contains process identity, service identifiers, host information, and application or system log messages that may include sensitive data; review before sharing.",
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
        source: &captured.source,
        entries: &captured.entries,
    })
}

pub(crate) fn render_logs_table(captured: &CapturedLogs) -> String {
    let mut output = String::new();
    let source = &captured.source;
    let _ = writeln!(output, "PSMORE PROCESS LOGS");
    let _ = writeln!(
        output,
        "process {}  {}  user {}  identity {}",
        captured.process.pid,
        captured.process.name,
        if captured.process.user.is_empty() {
            "unknown"
        } else {
            &captured.process.user
        },
        captured.identity_status.label()
    );
    let _ = writeln!(output, "command {}", captured.process.command);
    let _ = writeln!(
        output,
        "source {}  scope {} -> {}  selector {}",
        source.backend, source.requested_scope, source.effective_scope, source.selector
    );
    let _ = writeln!(
        output,
        "window {}..{}  priority <= {}  rows {}/{}  truncated {}  coverage {}",
        source.start_unix_seconds,
        source.end_unix_seconds,
        source.priority,
        source.returned_count,
        source.limit,
        if source.truncated { "yes" } else { "no" },
        if source.complete {
            "complete"
        } else {
            "partial"
        }
    );
    if let Some(service) = source.service.as_deref() {
        let _ = writeln!(
            output,
            "service {}  scope {}",
            service,
            source.service_scope.as_deref().unwrap_or("unknown")
        );
    }
    if let Some(warning) = captured.identity_warning.as_deref() {
        let _ = writeln!(output, "warning {warning}");
    }
    for warning in &source.warnings {
        let _ = writeln!(output, "warning {warning}");
    }
    if captured.entries.is_empty() {
        let _ = writeln!(output, "\nNo matching log entries in the selected window.");
        return output;
    }
    let _ = writeln!(
        output,
        "\nTIME                         LEVEL     SOURCE[PID]            MESSAGE"
    );
    for entry in &captured.entries {
        let pid = entry
            .process_id
            .map(|pid| format!("[{}]", pid))
            .unwrap_or_default();
        let source = format!("{}{}", entry.process, pid);
        let _ = writeln!(
            output,
            "{:<28} {:<9} {:<22} {}",
            entry.timestamp, entry.priority, source, entry.message
        );
        if let Some(context) = entry
            .subsystem
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(
                |subsystem| match entry.category.as_deref().filter(|value| !value.is_empty()) {
                    Some(category) => format!("{subsystem}/{category}"),
                    None => subsystem.to_string(),
                },
            )
        {
            let _ = writeln!(output, "                             context   {context}");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn automatic_scope_never_broadens_to_a_generic_systemd_scope() {
        assert_eq!(
            select_log_unit(LogScope::Auto, Some(("api.service".into(), "system"))),
            Some(("api.service".into(), "system"))
        );
        assert_eq!(
            select_log_unit(LogScope::Auto, Some(("session-42.scope".into(), "system"))),
            None
        );
        assert_eq!(
            select_log_unit(
                LogScope::Service,
                Some(("session-42.scope".into(), "system"))
            ),
            Some(("session-42.scope".into(), "system"))
        );
    }

    #[test]
    fn process_windows_are_clamped_but_service_windows_keep_restart_history() {
        assert_eq!(bounded_log_start(100, 150, false), 150);
        assert_eq!(bounded_log_start(100, 150, true), 100);
        assert_eq!(bounded_log_start(100, 0, false), 100);
    }

    #[test]
    fn journald_permission_messages_are_partial_evidence_not_parser_failures() {
        assert!(journal_permission_limited(
            "No journal files were opened due to insufficient permissions."
        ));
        assert!(journal_permission_limited(
            "Hint: You are currently not seeing messages from other users."
        ));
        assert!(!journal_permission_limited(
            "Failed to parse timestamp: definitely-not-a-time"
        ));
    }

    #[test]
    fn parses_journald_json_and_binary_messages_safely() {
        let entry = parse_journal_entry(
            r#"{"__REALTIME_TIMESTAMP":"1704067200123456","PRIORITY":"4","_PID":"42","SYSLOG_IDENTIFIER":"api","_SYSTEMD_UNIT":"api.service","MESSAGE":"token=secret ready\nnext"}"#,
        )
        .expect("journal entry");
        assert_eq!(entry.timestamp, "2024-01-01T00:00:00.123Z");
        assert_eq!(entry.priority, "warning");
        assert_eq!(entry.process_id, Some(42));
        assert_eq!(entry.service.as_deref(), Some("api.service"));
        assert_eq!(entry.message, "token=secret ready next");

        let bytes =
            parse_journal_entry(r#"{"__REALTIME_TIMESTAMP":"1","MESSAGE":[104,101,108,108,111]}"#)
                .expect("binary journal entry");
        assert_eq!(bytes.message, "hello");
    }

    #[test]
    fn parses_unified_log_ndjson_and_ignores_footer() {
        let entry = parse_unified_log_entry(
            r#"{"timestamp":"2026-08-02 11:51:55.640684+0800","messageType":"Default","processID":1,"processImagePath":"/sbin/launchd","subsystem":"com.example","category":"lifecycle","eventMessage":"service state: running"}"#,
        )
        .expect("unified log entry");
        assert_eq!(entry.process, "launchd");
        assert_eq!(entry.priority, "default");
        assert_eq!(entry.category.as_deref(), Some("lifecycle"));
        let ordinary = parse_unified_log_entry(
            r#"{"timestamp":"time","processID":2,"processImagePath":"/bin/zsh","eventMessage":"activity"}"#,
        )
        .expect("ordinary unified log entry");
        assert_eq!(ordinary.priority, "default");
        assert!(parse_unified_log_entry(r#"{"count":0,"finished":1}"#).is_none());
    }

    #[test]
    fn json_contract_exposes_selector_bounds_and_entries() {
        let captured = CapturedLogs {
            generated_at_unix_ms: 1,
            hostname: Some("host".into()),
            identity_status: IdentityStatus::Verified,
            identity_warning: None,
            process: LogProcess {
                pid: 42,
                parent_pid: Some(1),
                name: "api".into(),
                user: "deploy".into(),
                path: "/usr/bin/api".into(),
                command: "/usr/bin/api --serve".into(),
                start_time_unix_seconds: 1,
            },
            source: LogSource {
                backend: "journald",
                requested_scope: "auto",
                effective_scope: "service",
                selector: "_SYSTEMD_UNIT=api.service".into(),
                service: Some("api.service".into()),
                service_scope: Some("system".into()),
                start_unix_seconds: 10,
                end_unix_seconds: 20,
                priority: "info",
                limit: 100,
                returned_count: 1,
                truncated: false,
                complete: true,
                warnings: Vec::new(),
            },
            entries: vec![LogEntry {
                timestamp: "time".into(),
                timestamp_unix_microseconds: Some(1),
                priority: "info".into(),
                process_id: Some(42),
                process: "api".into(),
                service: Some("api.service".into()),
                subsystem: None,
                category: None,
                message: "ready".into(),
                cursor: Some("cursor".into()),
            }],
        };
        let report: Value = serde_json::from_str(&render_logs_json(&captured).unwrap()).unwrap();
        assert_eq!(report["schema"], LOGS_SCHEMA);
        assert_eq!(report["source"]["effective_scope"], "service");
        assert_eq!(report["source"]["returned_count"], 1);
        assert_eq!(report["entries"][0]["message"], "ready");
        assert!(render_logs_table(&captured).contains("api.service"));
    }
}
