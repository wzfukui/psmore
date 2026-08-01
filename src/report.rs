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
    model::{
        InspectionField, OpenFileInfo, ProcessChange, ProcessEvent, ProcessInfo, ProcessInspection,
        ResourceAggregate, SocketInfo, SortMode, process_command_line, process_path,
    },
    network::{NetworkListener, NetworkScan},
    snapshot::{BaselineSnapshot, ProcessSnapshotEntry, SnapshotResourceDelta},
};

const REPORT_SCHEMA: &str = "psmore.diagnostic-report";
const REPORT_SCHEMA_VERSION: u32 = 1;

pub(crate) struct ReportInput<'a> {
    pub(crate) platform: &'static str,
    pub(crate) selected_pid: Option<Pid>,
    pub(crate) paused: bool,
    pub(crate) sort_mode: SortMode,
    pub(crate) processes: &'a HashMap<Pid, ProcessInfo>,
    pub(crate) resources: &'a HashMap<Pid, ResourceAggregate>,
    pub(crate) events: &'a [ProcessEvent],
    pub(crate) network: Option<&'a NetworkScan>,
    pub(crate) inspection: Option<&'a ProcessInspection>,
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
    paused: bool,
    sort_mode: &'static str,
    process_count: usize,
    system: AggregateReport,
    processes: Vec<ProcessReport>,
    recent_events: Vec<EventReport>,
    network_scan: Option<NetworkReport>,
    selected_inspection: Option<InspectionReport>,
    baseline: Option<BaselineReport>,
}

#[derive(Debug, Serialize)]
struct ToolReport {
    name: &'static str,
    version: &'static str,
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
    parent_pid: Option<u32>,
    old_parent_pid: Option<u32>,
    new_parent_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
struct NetworkReport {
    warning: Option<String>,
    listeners: Vec<NetworkListenerReport>,
}

#[derive(Debug, Serialize)]
struct NetworkListenerReport {
    pid: Option<u32>,
    process: String,
    fd: String,
    protocol: String,
    endpoint: String,
    state: String,
    namespace: String,
}

impl From<&NetworkListener> for NetworkListenerReport {
    fn from(value: &NetworkListener) -> Self {
        Self {
            pid: value.pid.map(Pid::as_u32),
            process: value.process.clone(),
            fd: value.fd.clone(),
            protocol: value.protocol.clone(),
            endpoint: value.endpoint.clone(),
            state: value.state.clone(),
            namespace: value.namespace.clone(),
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
    sockets: Vec<SocketReport>,
    open_files: Vec<OpenFileReport>,
    warning: Option<String>,
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
        ProcessChange::Started { pid, name, parent } => EventReport {
            observed_at_unix_ms: observed_at,
            kind: "started",
            pid: pid.as_u32(),
            name: name.clone(),
            parent_pid: parent.map(Pid::as_u32),
            old_parent_pid: None,
            new_parent_pid: None,
        },
        ProcessChange::Exited { pid, name } => EventReport {
            observed_at_unix_ms: observed_at,
            kind: "exited",
            pid: pid.as_u32(),
            name: name.clone(),
            parent_pid: None,
            old_parent_pid: None,
            new_parent_pid: None,
        },
        ProcessChange::Reparented {
            pid,
            name,
            old_parent,
            new_parent,
        } => EventReport {
            observed_at_unix_ms: observed_at,
            kind: "reparented",
            pid: pid.as_u32(),
            name: name.clone(),
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
        sockets: value.sockets.iter().map(SocketReport::from).collect(),
        open_files: value.files.iter().map(OpenFileReport::from).collect(),
        warning: value.warning.clone(),
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
        warning: scan.warning.clone(),
        listeners: scan
            .listeners
            .iter()
            .map(NetworkListenerReport::from)
            .collect(),
    });
    let baseline = input
        .baseline
        .map(|snapshot| baseline_report(&input, snapshot));
    DiagnosticReport {
        schema: REPORT_SCHEMA,
        schema_version: REPORT_SCHEMA_VERSION,
        privacy_notice: "May contain command lines, paths, user names, host names, and socket endpoints; review before sharing.",
        tool: ToolReport {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: generated_at,
        platform: input.platform,
        hostname: System::host_name(),
        selected_pid: input.selected_pid.map(Pid::as_u32),
        paused: input.paused,
        sort_mode: input.sort_mode.label(),
        process_count: input.processes.len().saturating_sub(1),
        system: root.into(),
        processes,
        recent_events: input
            .events
            .iter()
            .map(|event| event_report(event, generated_at))
            .collect(),
        network_scan,
        selected_inspection: input.inspection.map(inspection_report),
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
