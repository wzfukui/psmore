use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    actions::{ProcessActionOutcome, ProcessActionRecord},
    model::{
        AttentionFinding, InspectionField, OpenFileInfo, ProcessChange, ProcessEvent, ProcessInfo,
        ProcessInspection, ResourceAggregate, SocketInfo, SortMode, ThreadInfo,
        process_command_line, process_path,
    },
    network::{NetworkEndpoint, NetworkScan, NetworkScope},
    snapshot::{BaselineSnapshot, ProcessSnapshotEntry, SnapshotResourceDelta},
};

const REPORT_SCHEMA: &str = "psmore.diagnostic-report";
const REPORT_SCHEMA_VERSION: u32 = 8;

pub(crate) struct ReportInput<'a> {
    pub(crate) platform: &'static str,
    pub(crate) selected_pid: Option<Pid>,
    pub(crate) query: &'a str,
    pub(crate) query_editing: bool,
    pub(crate) query_error: Option<&'a str>,
    pub(crate) query_matches: usize,
    pub(crate) paused: bool,
    pub(crate) sort_mode: SortMode,
    pub(crate) processes: &'a HashMap<Pid, ProcessInfo>,
    pub(crate) resources: &'a HashMap<Pid, ResourceAggregate>,
    pub(crate) events: &'a [ProcessEvent],
    pub(crate) attention_findings: &'a [AttentionFinding],
    pub(crate) network: Option<&'a NetworkScan>,
    pub(crate) network_scope: NetworkScope,
    pub(crate) network_scan_in_progress: bool,
    pub(crate) inspection: Option<&'a ProcessInspection>,
    pub(crate) inspection_in_progress: bool,
    pub(crate) service_context: Option<&'a serde_json::Value>,
    pub(crate) service_context_in_progress: bool,
    pub(crate) executable_context: Option<&'a serde_json::Value>,
    pub(crate) executable_context_in_progress: bool,
    pub(crate) memory_context: Option<&'a serde_json::Value>,
    pub(crate) memory_context_in_progress: bool,
    pub(crate) logs_context: Option<&'a serde_json::Value>,
    pub(crate) logs_context_in_progress: bool,
    pub(crate) dossier_context: Option<&'a serde_json::Value>,
    pub(crate) dossier_context_in_progress: bool,
    pub(crate) action_history: &'a [ProcessActionRecord],
    pub(crate) baseline: Option<&'a BaselineSnapshot>,
}

#[derive(Debug, Serialize)]
struct DiagnosticReport {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: ToolReport,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    selected_pid: Option<u32>,
    active_query: Option<QueryReport>,
    paused: bool,
    collection_status: CollectionStatusReport,
    sort_mode: &'static str,
    process_count: usize,
    system: AggregateReport,
    processes: Vec<ProcessReport>,
    recent_events: Vec<EventReport>,
    process_actions: Vec<ProcessActionReport>,
    attention_findings: Vec<AttentionReport>,
    network_scan: Option<NetworkReport>,
    selected_inspection: Option<InspectionReport>,
    selected_service_context: Option<serde_json::Value>,
    selected_executable_context: Option<serde_json::Value>,
    selected_memory_context: Option<serde_json::Value>,
    selected_logs_context: Option<serde_json::Value>,
    selected_process_dossier: Option<serde_json::Value>,
    baseline: Option<BaselineReport>,
}

#[derive(Debug, Serialize)]
struct ToolReport {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct CollectionStatusReport {
    network_scan_in_progress: bool,
    inspection_in_progress: bool,
    service_context_in_progress: bool,
    executable_context_in_progress: bool,
    memory_context_in_progress: bool,
    logs_context_in_progress: bool,
    dossier_context_in_progress: bool,
}

#[derive(Debug, Serialize)]
struct QueryReport {
    input: String,
    editing: bool,
    valid: bool,
    error: Option<String>,
    matched_process_count: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct AggregateReport {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

impl From<ResourceAggregate> for AggregateReport {
    fn from(value: ResourceAggregate) -> Self {
        Self {
            cpu_percent: finite(value.cpu),
            memory_bytes: value.memory,
            read_bytes_per_second: value.read_rate,
            write_bytes_per_second: value.write_rate,
            process_count: value.process_count,
        }
    }
}

#[derive(Debug, Serialize)]
struct ProcessReport {
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
    subtree: AggregateReport,
    virtual_process: bool,
}

#[derive(Debug, Serialize)]
struct EventReport {
    observed_at_unix_ms: u64,
    kind: &'static str,
    pid: u32,
    name: String,
    command: String,
    parent_pid: Option<u32>,
    old_parent_pid: Option<u32>,
    new_parent_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AttentionReport {
    pid: u32,
    severity: &'static str,
    score: u16,
    reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ProcessActionReport {
    observed_at_unix_ms: u64,
    pid: u32,
    name: String,
    command: String,
    start_time_unix_seconds: u64,
    action: &'static str,
    outcome: &'static str,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct NetworkReport {
    scope: &'static str,
    warning: Option<String>,
    endpoints: Vec<NetworkEndpointReport>,
}

#[derive(Debug, Serialize)]
struct NetworkEndpointReport {
    pid: Option<u32>,
    process: String,
    fd: String,
    protocol: String,
    local_endpoint: String,
    remote_endpoint: String,
    state: String,
    namespace: String,
    listener: bool,
}

impl From<&NetworkEndpoint> for NetworkEndpointReport {
    fn from(value: &NetworkEndpoint) -> Self {
        Self {
            pid: value.pid.map(Pid::as_u32),
            process: value.process.clone(),
            fd: value.fd.clone(),
            protocol: value.protocol.clone(),
            local_endpoint: value.local_endpoint.clone(),
            remote_endpoint: value.remote_endpoint.clone(),
            state: value.state.clone(),
            namespace: value.namespace.clone(),
            listener: value.is_listener(),
        }
    }
}

#[derive(Debug, Serialize)]
struct InspectionReport {
    pid: u32,
    name: String,
    user: String,
    cwd: String,
    runtime: Vec<FieldReport>,
    security: Vec<FieldReport>,
    namespaces: Vec<FieldReport>,
    resource_limits: Vec<FieldReport>,
    thread_count: usize,
    thread_sample_interval_ms: u64,
    thread_rows_truncated: bool,
    thread_warning: Option<String>,
    threads: Vec<ThreadReport>,
    sockets: Vec<SocketReport>,
    open_files: Vec<OpenFileReport>,
    warning: Option<String>,
}

#[derive(Debug, Serialize)]
struct ThreadReport {
    id: u64,
    name: String,
    state: String,
    cpu_percent: f32,
    priority: i32,
    nice: Option<i32>,
    processor: Option<i32>,
}

impl From<&ThreadInfo> for ThreadReport {
    fn from(value: &ThreadInfo) -> Self {
        Self {
            id: value.id,
            name: value.name.clone(),
            state: value.state.clone(),
            cpu_percent: finite(value.cpu_percent),
            priority: value.priority,
            nice: value.nice,
            processor: value.processor,
        }
    }
}

#[derive(Debug, Serialize)]
struct FieldReport {
    label: String,
    value: String,
}

impl From<&InspectionField> for FieldReport {
    fn from(value: &InspectionField) -> Self {
        Self {
            label: value.label.clone(),
            value: value.value.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct SocketReport {
    fd: String,
    protocol: String,
    endpoint: String,
    state: String,
}

impl From<&SocketInfo> for SocketReport {
    fn from(value: &SocketInfo) -> Self {
        Self {
            fd: value.fd.clone(),
            protocol: value.protocol.clone(),
            endpoint: value.endpoint.clone(),
            state: value.state.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct OpenFileReport {
    fd: String,
    kind: String,
    access: String,
    name: String,
}

impl From<&OpenFileInfo> for OpenFileReport {
    fn from(value: &OpenFileInfo) -> Self {
        Self {
            fd: value.fd.clone(),
            kind: value.kind.clone(),
            access: value.access.clone(),
            name: value.name.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct BaselineReport {
    captured_age_ms: u64,
    process_count: usize,
    started: Vec<BaselineProcessReport>,
    exited: Vec<BaselineProcessReport>,
    reparented: Vec<ReparentedReport>,
    resource_deltas: Vec<ResourceDeltaReport>,
    system_delta: Option<ResourceDeltaReport>,
}

#[derive(Debug, Serialize)]
struct BaselineProcessReport {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    command: String,
    start_time_unix_seconds: u64,
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    subtree: AggregateReport,
}

impl From<&ProcessSnapshotEntry> for BaselineProcessReport {
    fn from(value: &ProcessSnapshotEntry) -> Self {
        Self {
            pid: value.pid.as_u32(),
            parent_pid: value.parent.map(Pid::as_u32),
            name: value.name.clone(),
            command: value.command.clone(),
            start_time_unix_seconds: value.start_time,
            cpu_percent: finite(value.own_cpu),
            memory_bytes: value.own_memory,
            read_bytes_per_second: value.own_read_rate,
            write_bytes_per_second: value.own_write_rate,
            subtree: value.subtree.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ReparentedReport {
    pid: u32,
    name: String,
    old_parent_pid: Option<u32>,
    new_parent_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ResourceDeltaReport {
    pid: u32,
    name: String,
    own_cpu_percent: f32,
    subtree_cpu_percent: f32,
    own_memory_bytes: i64,
    subtree_memory_bytes: i64,
    own_read_bytes_per_second: i64,
    own_write_bytes_per_second: i64,
    subtree_read_bytes_per_second: i64,
    subtree_write_bytes_per_second: i64,
    subtree_processes: i64,
    current_subtree: AggregateReport,
}

impl From<&SnapshotResourceDelta> for ResourceDeltaReport {
    fn from(value: &SnapshotResourceDelta) -> Self {
        Self {
            pid: value.pid.as_u32(),
            name: value.name.clone(),
            own_cpu_percent: finite(value.own_cpu),
            subtree_cpu_percent: finite(value.subtree_cpu),
            own_memory_bytes: clamp_i128(value.own_memory),
            subtree_memory_bytes: clamp_i128(value.subtree_memory),
            own_read_bytes_per_second: clamp_i128(value.own_read_rate),
            own_write_bytes_per_second: clamp_i128(value.own_write_rate),
            subtree_read_bytes_per_second: clamp_i128(value.subtree_read_rate),
            subtree_write_bytes_per_second: clamp_i128(value.subtree_write_rate),
            subtree_processes: clamp_i128(value.subtree_processes),
            current_subtree: value.current_subtree.into(),
        }
    }
}

fn finite(value: f32) -> f32 {
    if value.is_finite() { value } else { 0.0 }
}

fn clamp_i128(value: i128) -> i64 {
    value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn unix_millis() -> io::Result<u64> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    Ok(millis.min(u128::from(u64::MAX)) as u64)
}

fn elapsed_millis(elapsed: std::time::Duration) -> u64 {
    elapsed.as_millis().min(u128::from(u64::MAX)) as u64
}

fn event_report(event: &ProcessEvent, generated_at: u64) -> EventReport {
    let observed_at = generated_at.saturating_sub(elapsed_millis(event.observed_at.elapsed()));
    match &event.change {
        ProcessChange::Started {
            pid,
            name,
            command,
            parent,
        } => EventReport {
            observed_at_unix_ms: observed_at,
            kind: "started",
            pid: pid.as_u32(),
            name: name.clone(),
            command: command.clone(),
            parent_pid: parent.map(Pid::as_u32),
            old_parent_pid: None,
            new_parent_pid: None,
        },
        ProcessChange::Exited { pid, name, command } => EventReport {
            observed_at_unix_ms: observed_at,
            kind: "exited",
            pid: pid.as_u32(),
            name: name.clone(),
            command: command.clone(),
            parent_pid: None,
            old_parent_pid: None,
            new_parent_pid: None,
        },
        ProcessChange::Reparented {
            pid,
            name,
            command,
            old_parent,
            new_parent,
        } => EventReport {
            observed_at_unix_ms: observed_at,
            kind: "reparented",
            pid: pid.as_u32(),
            name: name.clone(),
            command: command.clone(),
            parent_pid: None,
            old_parent_pid: old_parent.map(Pid::as_u32),
            new_parent_pid: new_parent.map(Pid::as_u32),
        },
    }
}

fn inspection_report(value: &ProcessInspection) -> InspectionReport {
    InspectionReport {
        pid: value.pid.as_u32(),
        name: value.name.clone(),
        user: value.user.clone(),
        cwd: value.cwd.clone(),
        runtime: value.runtime.iter().map(FieldReport::from).collect(),
        security: value.security.iter().map(FieldReport::from).collect(),
        namespaces: value.namespaces.iter().map(FieldReport::from).collect(),
        resource_limits: value.limits.iter().map(FieldReport::from).collect(),
        thread_count: value.thread_count,
        thread_sample_interval_ms: value.thread_sample_ms,
        thread_rows_truncated: value.thread_truncated,
        thread_warning: value.thread_warning.clone(),
        threads: value.threads.iter().map(ThreadReport::from).collect(),
        sockets: value.sockets.iter().map(SocketReport::from).collect(),
        open_files: value.files.iter().map(OpenFileReport::from).collect(),
        warning: value.warning.clone(),
    }
}

fn process_action_report(record: &ProcessActionRecord, generated_at: u64) -> ProcessActionReport {
    let detail = match &record.outcome {
        ProcessActionOutcome::Sent => None,
        ProcessActionOutcome::Refused(detail) | ProcessActionOutcome::Failed(detail) => {
            Some(detail.clone())
        }
    };
    ProcessActionReport {
        observed_at_unix_ms: generated_at
            .saturating_sub(elapsed_millis(record.observed_at.elapsed())),
        pid: record.target.pid.as_u32(),
        name: record.target.name.clone(),
        command: record.target.command.clone(),
        start_time_unix_seconds: record.target.start_time,
        action: record.action.label(),
        outcome: record.outcome.label(),
        detail,
    }
}

fn baseline_report(input: &ReportInput<'_>, baseline: &BaselineSnapshot) -> BaselineReport {
    let diff = baseline.diff(input.processes, input.resources);
    BaselineReport {
        captured_age_ms: elapsed_millis(baseline.captured_at.elapsed()),
        process_count: baseline.len(),
        started: diff
            .started
            .iter()
            .map(BaselineProcessReport::from)
            .collect(),
        exited: diff
            .exited
            .iter()
            .map(BaselineProcessReport::from)
            .collect(),
        reparented: diff
            .reparented
            .iter()
            .map(|value| ReparentedReport {
                pid: value.pid.as_u32(),
                name: value.name.clone(),
                old_parent_pid: value.old_parent.map(Pid::as_u32),
                new_parent_pid: value.new_parent.map(Pid::as_u32),
            })
            .collect(),
        resource_deltas: diff
            .resource_deltas
            .iter()
            .map(ResourceDeltaReport::from)
            .collect(),
        system_delta: diff.system_delta.as_ref().map(ResourceDeltaReport::from),
    }
}

fn build_report(input: ReportInput<'_>, generated_at: u64) -> DiagnosticReport {
    let mut pids: Vec<Pid> = input.processes.keys().copied().collect();
    pids.sort_by_key(|pid| pid.as_u32());
    let processes = pids
        .into_iter()
        .filter_map(|pid| {
            let process = input.processes.get(&pid)?;
            let subtree = input.resources.get(&pid).copied().unwrap_or_default();
            Some(ProcessReport {
                pid: pid.as_u32(),
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
                subtree: subtree.into(),
                virtual_process: pid.as_u32() == 0,
            })
        })
        .collect();
    let root = input
        .resources
        .get(&Pid::from_u32(0))
        .copied()
        .unwrap_or_default();
    let network_scan = input.network.map(|scan| NetworkReport {
        scope: input.network_scope.label(),
        warning: scan.warning.clone(),
        endpoints: scan
            .endpoints
            .iter()
            .map(NetworkEndpointReport::from)
            .collect(),
    });
    let baseline = input
        .baseline
        .map(|snapshot| baseline_report(&input, snapshot));
    DiagnosticReport {
        schema: REPORT_SCHEMA,
        schema_version: REPORT_SCHEMA_VERSION,
        privacy_notice: "May contain command lines, paths, user names, host names, thread names, socket endpoints, memory layout and mapped-file evidence, service context, executable hashes, signatures, and captured native log messages; review before sharing.",
        tool: ToolReport {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: generated_at,
        platform: input.platform,
        hostname: System::host_name(),
        selected_pid: input.selected_pid.map(Pid::as_u32),
        active_query: (!input.query.is_empty()).then(|| QueryReport {
            input: input.query.to_string(),
            editing: input.query_editing,
            valid: input.query_error.is_none(),
            error: input.query_error.map(str::to_string),
            matched_process_count: input.query_matches,
        }),
        paused: input.paused,
        collection_status: CollectionStatusReport {
            network_scan_in_progress: input.network_scan_in_progress,
            inspection_in_progress: input.inspection_in_progress,
            service_context_in_progress: input.service_context_in_progress,
            executable_context_in_progress: input.executable_context_in_progress,
            memory_context_in_progress: input.memory_context_in_progress,
            logs_context_in_progress: input.logs_context_in_progress,
            dossier_context_in_progress: input.dossier_context_in_progress,
        },
        sort_mode: input.sort_mode.label(),
        process_count: input.processes.len().saturating_sub(1),
        system: root.into(),
        processes,
        recent_events: input
            .events
            .iter()
            .map(|event| event_report(event, generated_at))
            .collect(),
        process_actions: input
            .action_history
            .iter()
            .map(|record| process_action_report(record, generated_at))
            .collect(),
        attention_findings: input
            .attention_findings
            .iter()
            .map(|finding| AttentionReport {
                pid: finding.pid.as_u32(),
                severity: finding.severity.label(),
                score: finding.score,
                reasons: finding.reasons.clone(),
            })
            .collect(),
        network_scan,
        selected_inspection: input.inspection.map(inspection_report),
        selected_service_context: input.service_context.cloned(),
        selected_executable_context: input.executable_context.cloned(),
        selected_memory_context: input.memory_context.cloned(),
        selected_logs_context: input.logs_context.cloned(),
        selected_process_dossier: input.dossier_context.cloned(),
        baseline,
    }
}

fn report_paths(directory: &Path, generated_at: u64) -> io::Result<(PathBuf, PathBuf)> {
    for attempt in 0..1_000_u32 {
        let suffix = if attempt == 0 {
            String::new()
        } else {
            format!("-{attempt}")
        };
        let filename = format!(
            "psmore-report-{generated_at}-{}{}.json",
            std::process::id(),
            suffix
        );
        let final_path = directory.join(&filename);
        let temporary_path = directory.join(format!(".{filename}.tmp"));
        if !final_path.exists() && !temporary_path.exists() {
            return Ok((temporary_path, final_path));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "cannot allocate a unique report filename",
    ))
}

pub(crate) fn export_report(input: ReportInput<'_>, directory: &Path) -> io::Result<PathBuf> {
    let generated_at = unix_millis()?;
    let report = build_report(input, generated_at);
    let (temporary_path, final_path) = report_paths(directory, generated_at)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| {
        let mut file = options.open(&temporary_path)?;
        serde_json::to_writer_pretty(&mut file, &report).map_err(io::Error::other)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary_path, &final_path)?;
        Ok(final_path.clone())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}
