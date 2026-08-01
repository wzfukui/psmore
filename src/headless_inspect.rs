use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    inspection::inspect_process,
    model::{
        InspectionField, OpenFileInfo, ProcessInfo, ProcessInspection, SocketInfo, ThreadInfo,
        process_command_line, process_path, sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const INSPECTION_SCHEMA: &str = "psmore.process-inspection";
const INSPECTION_SCHEMA_VERSION: u32 = 1;

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

pub(crate) struct CapturedInspection {
    process: ProcessInfo,
    inspection: ProcessInspection,
    sample_ms: u64,
    generated_at_unix_ms: u64,
    identity_status: IdentityStatus,
    identity_warning: Option<String>,
}

fn verify_instance(
    before: &ProcessInfo,
    after: Option<&ProcessInfo>,
) -> Result<(IdentityStatus, Option<String>), String> {
    let Some(after) = after else {
        return Ok((
            IdentityStatus::ExitedDuringCollection,
            Some(format!(
                "PID {} exited while the inspection was being collected",
                before.pid
            )),
        ));
    };
    if before.start_time > 0 && after.start_time > 0 {
        if before.start_time != after.start_time {
            return Err(format!(
                "PID {} was reused during inspection; refusing to combine different process instances",
                before.pid
            ));
        }
        return Ok((IdentityStatus::Verified, None));
    }
    Ok((
        IdentityStatus::Unverified,
        Some(format!(
            "PID {} start time is unavailable; process identity could not be fully revalidated",
            before.pid
        )),
    ))
}

pub(crate) fn capture_inspection(pid: u32, sample_ms: u64) -> Result<CapturedInspection, String> {
    if pid == 0 {
        return Err("PID 0 is a virtual root and cannot be inspected".into());
    }
    let pid = Pid::from_u32(pid);
    let mut provider = NativeProcessProvider::new();
    let _ = provider.refresh();
    thread::sleep(Duration::from_millis(sample_ms));
    let processes = provider.refresh();
    let process = processes
        .into_iter()
        .find(|process| process.pid == pid)
        .ok_or_else(|| format!("PID {pid} was not found"))?;
    let inspection = inspect_process(&process);
    let after = provider.refresh();
    let (identity_status, identity_warning) = verify_instance(
        &process,
        after.iter().find(|candidate| candidate.pid == pid),
    )?;
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    Ok(CapturedInspection {
        process,
        inspection,
        sample_ms,
        generated_at_unix_ms,
        identity_status,
        identity_warning,
    })
}

#[derive(Debug, Serialize)]
struct JsonInspection<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    process_sample_interval_ms: u64,
    process_identity: &'static str,
    process_identity_warning: Option<&'a str>,
    process: JsonProcess,
    runtime_context: Vec<JsonField>,
    security: Vec<JsonField>,
    namespaces: Vec<JsonField>,
    resource_limits: Vec<JsonField>,
    hot_threads: JsonThreads,
    sockets: Vec<JsonSocket>,
    open_files: Vec<JsonOpenFile>,
    collection_warning: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    path: String,
    command: String,
    executable: String,
    user: String,
    cwd: String,
    status: String,
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    start_time_unix_seconds: u64,
    runtime_seconds: u64,
}

impl From<&ProcessInfo> for JsonProcess {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: process.name.clone(),
            path: process_path(process),
            command: process_command_line(process),
            executable: process.executable.clone(),
            user: process.user.clone(),
            cwd: process.cwd.clone(),
            status: process.status.clone(),
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            read_bytes_per_second: process.read_rate,
            write_bytes_per_second: process.write_rate,
            start_time_unix_seconds: process.start_time,
            runtime_seconds: process.runtime,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonField {
    label: String,
    value: String,
}

impl From<&InspectionField> for JsonField {
    fn from(field: &InspectionField) -> Self {
        Self {
            label: field.label.clone(),
            value: field.value.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonThreads {
    total_count: usize,
    returned_count: usize,
    cpu_measurement: &'static str,
    sample_interval_ms: u64,
    rows_truncated: bool,
    warning: Option<String>,
    rows: Vec<JsonThread>,
}

#[derive(Debug, Serialize)]
struct JsonThread {
    id: u64,
    name: String,
    state: String,
    cpu_percent: f32,
    priority: i32,
    nice: Option<i32>,
    processor: Option<i32>,
}

impl From<&ThreadInfo> for JsonThread {
    fn from(thread: &ThreadInfo) -> Self {
        Self {
            id: thread.id,
            name: thread.name.clone(),
            state: thread.state.clone(),
            cpu_percent: finite(thread.cpu_percent),
            priority: thread.priority,
            nice: thread.nice,
            processor: thread.processor,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonSocket {
    fd: String,
    protocol: String,
    endpoint: String,
    state: String,
}

impl From<&SocketInfo> for JsonSocket {
    fn from(socket: &SocketInfo) -> Self {
        Self {
            fd: socket.fd.clone(),
            protocol: socket.protocol.clone(),
            endpoint: socket.endpoint.clone(),
            state: socket.state.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonOpenFile {
    fd: String,
    kind: String,
    access: String,
    name: String,
}

impl From<&OpenFileInfo> for JsonOpenFile {
    fn from(file: &OpenFileInfo) -> Self {
        Self {
            fd: file.fd.clone(),
            kind: file.kind.clone(),
            access: file.access.clone(),
            name: file.name.clone(),
        }
    }
}

pub(crate) fn render_inspection_json(captured: &CapturedInspection) -> Result<String, String> {
    let inspection = &captured.inspection;
    serde_json::to_string_pretty(&JsonInspection {
        schema: INSPECTION_SCHEMA,
        schema_version: INSPECTION_SCHEMA_VERSION,
        privacy_notice: "Contains process arguments, paths, user names, sockets, files, thread names, and host information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        process_sample_interval_ms: captured.sample_ms,
        process_identity: captured.identity_status.label(),
        process_identity_warning: captured.identity_warning.as_deref(),
        process: (&captured.process).into(),
        runtime_context: inspection.runtime.iter().map(JsonField::from).collect(),
        security: inspection.security.iter().map(JsonField::from).collect(),
        namespaces: inspection.namespaces.iter().map(JsonField::from).collect(),
        resource_limits: inspection.limits.iter().map(JsonField::from).collect(),
        hot_threads: JsonThreads {
            total_count: inspection.thread_count,
            returned_count: inspection.threads.len(),
            cpu_measurement: if inspection.thread_sample_ms > 0 {
                "sample_delta"
            } else {
                "scheduler_estimate"
            },
            sample_interval_ms: inspection.thread_sample_ms,
            rows_truncated: inspection.thread_truncated,
            warning: inspection.thread_warning.clone(),
            rows: inspection.threads.iter().map(JsonThread::from).collect(),
        },
        sockets: inspection.sockets.iter().map(JsonSocket::from).collect(),
        open_files: inspection.files.iter().map(JsonOpenFile::from).collect(),
        collection_warning: inspection.warning.as_deref(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_inspection_table(captured: &CapturedInspection) -> String {
    let process = &captured.process;
    let inspection = &captured.inspection;
    let mut output = String::from("PSMORE PROCESS INSPECTION\n");
    output.push_str(&format!(
        "PID {}  PPID {}  NAME {}  STATUS {}  IDENTITY {}\n",
        process.pid,
        process.parent.map(Pid::as_u32).unwrap_or(0),
        sanitize_terminal_text(&process.name),
        sanitize_terminal_text(&process.status),
        captured.identity_status.label(),
    ));
    output.push_str(&format!(
        "CPU {:.1}%  MEM {}  READ {}  WRITE {}  AGE {}  SAMPLE {}ms\n",
        finite(process.cpu),
        human_bytes(process.memory),
        human_rate(process.read_rate),
        human_rate(process.write_rate),
        human_duration(process.runtime),
        captured.sample_ms,
    ));
    output.push_str(&format!(
        "USER     {}\n",
        sanitize_terminal_text(&inspection.user)
    ));
    output.push_str(&format!(
        "CWD      {}\n",
        sanitize_terminal_text(&inspection.cwd)
    ));
    output.push_str(&format!(
        "PATH     {}\n",
        sanitize_terminal_text(&process_path(process))
    ));
    output.push_str(&format!(
        "COMMAND  {}\n",
        sanitize_terminal_text(&process_command_line(process))
    ));

    push_fields(&mut output, "RUNTIME CONTEXT", &inspection.runtime);
    push_fields(&mut output, "SECURITY", &inspection.security);
    push_fields(&mut output, "NAMESPACES", &inspection.namespaces);
    push_fields(&mut output, "RESOURCE LIMITS", &inspection.limits);

    let thread_measurement = if inspection.thread_sample_ms > 0 {
        format!("{}ms sample", inspection.thread_sample_ms)
    } else {
        "scheduler estimate".into()
    };
    output.push_str(&format!(
        "\nHOT THREADS ({}/{} returned; {thread_measurement}{})\n",
        inspection.threads.len(),
        inspection.thread_count,
        if inspection.thread_truncated {
            "; truncated"
        } else {
            ""
        }
    ));
    if inspection.threads.is_empty() {
        output.push_str("  [no thread details visible]\n");
    } else {
        output.push_str("             TID   CPU% STATE          PRI NICE CORE NAME\n");
        for thread in &inspection.threads {
            output.push_str(&format!(
                "  {:>14} {:>6.1} {:<14} {:>3} {:>4} {:>4} {}\n",
                thread.id,
                finite(thread.cpu_percent),
                sanitize_terminal_text(&thread.state),
                thread.priority,
                optional_number(thread.nice),
                optional_number(thread.processor),
                if thread.name.is_empty() {
                    "[unnamed]".into()
                } else {
                    sanitize_terminal_text(&thread.name)
                },
            ));
        }
    }

    output.push_str(&format!("\nSOCKETS ({})\n", inspection.sockets.len()));
    if inspection.sockets.is_empty() {
        output.push_str("  [none visible]\n");
    } else {
        output.push_str("  FD       PROTO    STATE          ENDPOINT\n");
        for socket in &inspection.sockets {
            output.push_str(&format!(
                "  {:<8} {:<8} {:<14} {}\n",
                sanitize_terminal_text(&socket.fd),
                sanitize_terminal_text(&socket.protocol),
                sanitize_terminal_text(&socket.state),
                sanitize_terminal_text(&socket.endpoint),
            ));
        }
    }

    output.push_str(&format!("\nOPEN FILES ({})\n", inspection.files.len()));
    if inspection.files.is_empty() {
        output.push_str("  [none visible]\n");
    } else {
        output.push_str("  FD       KIND     ACCESS NAME\n");
        for file in &inspection.files {
            output.push_str(&format!(
                "  {:<8} {:<8} {:<6} {}\n",
                sanitize_terminal_text(&file.fd),
                sanitize_terminal_text(&file.kind),
                sanitize_terminal_text(&file.access),
                sanitize_terminal_text(&file.name),
            ));
        }
    }

    let warnings = [
        captured.identity_warning.as_deref(),
        inspection.thread_warning.as_deref(),
        inspection.warning.as_deref(),
    ];
    if warnings.iter().any(Option::is_some) {
        output.push_str("\nWARNINGS\n");
        for warning in warnings.into_iter().flatten() {
            output.push_str(&format!("  - {}\n", sanitize_terminal_text(warning)));
        }
    }
    output
}

fn push_fields(output: &mut String, title: &str, fields: &[InspectionField]) {
    if fields.is_empty() {
        return;
    }
    output.push_str(&format!("\n{title}\n"));
    for field in fields {
        output.push_str(&format!(
            "  {:<20} {}\n",
            sanitize_terminal_text(&field.label),
            sanitize_terminal_text(&field.value)
        ));
    }
}

fn optional_number(value: Option<i32>) -> String {
    value.map_or_else(|| "-".into(), |value| value.to_string())
}

fn finite(value: f32) -> f32 {
    if value.is_finite() { value } else { 0.0 }
}

fn human_rate(value: u64) -> String {
    format!("{}/s", human_bytes(value))
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value}B")
    } else if amount >= 100.0 {
        format!("{amount:.0}{}", UNITS[unit])
    } else if amount >= 10.0 {
        format!("{amount:.1}{}", UNITS[unit])
    } else {
        format!("{amount:.2}{}", UNITS[unit])
    }
}

fn human_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn process(start_time: u64) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: "api\nserver".into(),
            command: "/srv/api\n--listen 8080".into(),
            executable: "/srv/api".into(),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: 12.5,
            memory: 64 * 1024 * 1024,
            read_rate: 1024,
            write_rate: 2048,
            start_time,
            runtime: 65,
            status: "Sleep".into(),
        }
    }

    fn captured() -> CapturedInspection {
        CapturedInspection {
            process: process(100),
            inspection: ProcessInspection {
                pid: Pid::from_u32(42),
                name: "api".into(),
                user: "deploy".into(),
                cwd: "/srv".into(),
                runtime: vec![InspectionField {
                    label: "RSS / SWAP".into(),
                    value: "64 MiB / 0 B".into(),
                }],
                threads: vec![ThreadInfo {
                    id: 99,
                    name: "worker".into(),
                    state: "Running".into(),
                    cpu_percent: 50.0,
                    priority: 20,
                    nice: Some(0),
                    processor: Some(3),
                }],
                thread_count: 1,
                thread_sample_ms: 250,
                sockets: vec![SocketInfo {
                    fd: "7".into(),
                    protocol: "TCP".into(),
                    endpoint: "*:8080".into(),
                    state: "LISTEN".into(),
                }],
                files: vec![OpenFileInfo {
                    fd: "8".into(),
                    kind: "REG".into(),
                    access: "r".into(),
                    name: "/srv/config.json".into(),
                }],
                ..ProcessInspection::default()
            },
            sample_ms: 500,
            generated_at_unix_ms: 1_700_000_000_000,
            identity_status: IdentityStatus::Verified,
            identity_warning: None,
        }
    }

    #[test]
    fn identity_validation_detects_exit_reuse_and_unverified_instances() {
        let before = process(100);
        assert_eq!(
            verify_instance(&before, Some(&process(100))).unwrap().0,
            IdentityStatus::Verified
        );
        assert!(verify_instance(&before, Some(&process(101))).is_err());
        assert_eq!(
            verify_instance(&before, None).unwrap().0,
            IdentityStatus::ExitedDuringCollection
        );
        assert_eq!(
            verify_instance(&process(0), Some(&process(0))).unwrap().0,
            IdentityStatus::Unverified
        );
    }

    #[test]
    fn inspection_outputs_are_complete_versioned_and_safe_for_terminals() {
        let captured = captured();
        let table = render_inspection_table(&captured);
        assert!(table.starts_with("PSMORE PROCESS INSPECTION"));
        assert!(table.contains("COMMAND  /srv/api --listen 8080"));
        assert!(table.contains("HOT THREADS (1/1 returned; 250ms sample)"));
        assert!(table.contains("*:8080"));
        assert!(!table.contains("api\nserver"));

        let json: Value =
            serde_json::from_str(&render_inspection_json(&captured).unwrap()).unwrap();
        assert_eq!(json["schema"], INSPECTION_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["process_identity"], "verified");
        assert_eq!(json["process"]["pid"], 42);
        assert_eq!(json["hot_threads"]["rows"][0]["id"], 99);
        assert_eq!(json["hot_threads"]["cpu_measurement"], "sample_delta");
        assert_eq!(json["sockets"][0]["state"], "LISTEN");
        assert_eq!(json["open_files"][0]["name"], "/srv/config.json");
    }
}
