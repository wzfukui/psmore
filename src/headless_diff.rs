use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    cli::{DiffFailOn, DiffPolicyStatus},
    headless_doctor_diff::{
        DOCTOR_SCHEMA, DoctorComparison, compare_doctor_contents, render_doctor_diff_json,
        render_doctor_diff_table,
    },
    model::{command_for_output, sanitize_terminal_text},
};

const SNAPSHOT_SCHEMA: &str = "psmore.process-snapshot";
const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const DIFF_SCHEMA: &str = "psmore.snapshot-diff";
const DIFF_SCHEMA_VERSION: u32 = 1;
const TABLE_CHANGE_LIMIT: usize = 50;
const TABLE_RESOURCE_LIMIT: usize = 10;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredQuery {
    input: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
struct StoredAggregate {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct StoredProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    command: String,
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    start_time_unix_seconds: u64,
    subtree: StoredAggregate,
}

#[derive(Clone, Debug, Deserialize)]
struct StoredSnapshot {
    schema: String,
    schema_version: u32,
    generated_at_unix_ms: u64,
    platform: String,
    hostname: Option<String>,
    sample_interval_ms: u64,
    query: Option<StoredQuery>,
    system_process_count: usize,
    matched_process_count: usize,
    processes: Vec<StoredProcess>,
}

#[derive(Clone, Debug, Serialize)]
struct SnapshotSource {
    generated_at_unix_ms: u64,
    sample_interval_ms: u64,
    system_process_count: usize,
    matched_process_count: usize,
}

impl From<&StoredSnapshot> for SnapshotSource {
    fn from(snapshot: &StoredSnapshot) -> Self {
        Self {
            generated_at_unix_ms: snapshot.generated_at_unix_ms,
            sample_interval_ms: snapshot.sample_interval_ms,
            system_process_count: snapshot.system_process_count,
            matched_process_count: snapshot.matched_process_count,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct SelectionScope {
    complete_process_list: bool,
    query: Option<String>,
    lifecycle_interpretation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ProcessIdentity {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    command: String,
    start_time_unix_seconds: u64,
}

impl From<&StoredProcess> for ProcessIdentity {
    fn from(process: &StoredProcess) -> Self {
        Self {
            pid: process.pid,
            parent_pid: process.parent_pid,
            name: process.name.clone(),
            command: process.command.clone(),
            start_time_unix_seconds: process.start_time_unix_seconds,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct PidReuse {
    pid: u32,
    before: ProcessIdentity,
    after: ProcessIdentity,
}

#[derive(Clone, Debug, Serialize)]
struct ReparentedProcess {
    pid: u32,
    name: String,
    old_parent_pid: Option<u32>,
    new_parent_pid: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct MetricDelta {
    cpu_percent: f32,
    memory_bytes: i64,
    read_bytes_per_second: i64,
    write_bytes_per_second: i64,
    process_count: i64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct CurrentMetrics {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

#[derive(Clone, Debug, Serialize)]
struct ResourceDelta {
    pid: u32,
    name: String,
    own_delta: MetricDelta,
    subtree_delta: MetricDelta,
    current_own: CurrentMetrics,
    current_subtree: CurrentMetrics,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct DiffSummary {
    appeared: usize,
    disappeared: usize,
    pid_reused: usize,
    reparented: usize,
    system_process_count_delta: i64,
    matched_process_count_delta: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SnapshotComparison {
    platform: String,
    hostname: String,
    elapsed_ms: u64,
    before: SnapshotSource,
    after: SnapshotSource,
    selection: SelectionScope,
    summary: DiffSummary,
    appeared: Vec<ProcessIdentity>,
    disappeared: Vec<ProcessIdentity>,
    pid_reused: Vec<PidReuse>,
    reparented: Vec<ReparentedProcess>,
    resource_deltas: Vec<ResourceDelta>,
}

fn parse_snapshot(contents: &str, label: &str) -> Result<StoredSnapshot, String> {
    let snapshot: StoredSnapshot = serde_json::from_str(contents)
        .map_err(|error| format!("cannot parse {label} snapshot: {error}"))?;
    validate_snapshot(&snapshot, label)?;
    Ok(snapshot)
}

fn validate_snapshot(snapshot: &StoredSnapshot, label: &str) -> Result<(), String> {
    if snapshot.schema != SNAPSHOT_SCHEMA {
        return Err(format!(
            "{label} uses unsupported schema {}; expected {SNAPSHOT_SCHEMA}",
            snapshot.schema
        ));
    }
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(format!(
            "{label} uses unsupported schema version {}; expected {SNAPSHOT_SCHEMA_VERSION}",
            snapshot.schema_version
        ));
    }
    if snapshot.hostname.as_deref().unwrap_or("").is_empty() {
        return Err(format!("{label} snapshot has no hostname"));
    }
    if snapshot.matched_process_count != snapshot.processes.len() {
        return Err(format!(
            "{label} matched_process_count is {}, but it contains {} process rows",
            snapshot.matched_process_count,
            snapshot.processes.len()
        ));
    }
    if snapshot.system_process_count < snapshot.matched_process_count {
        return Err(format!(
            "{label} system_process_count is smaller than matched_process_count"
        ));
    }
    let mut pids = HashSet::with_capacity(snapshot.processes.len());
    for process in &snapshot.processes {
        if process.pid == 0 {
            return Err(format!("{label} contains the virtual PID 0 row"));
        }
        if !pids.insert(process.pid) {
            return Err(format!("{label} contains duplicate PID {}", process.pid));
        }
        if !process.cpu_percent.is_finite() || !process.subtree.cpu_percent.is_finite() {
            return Err(format!(
                "{label} contains a non-finite CPU value for PID {}",
                process.pid
            ));
        }
    }
    Ok(())
}

fn same_instance(before: &StoredProcess, after: &StoredProcess) -> bool {
    if before.start_time_unix_seconds != 0 || after.start_time_unix_seconds != 0 {
        before.start_time_unix_seconds != 0
            && after.start_time_unix_seconds != 0
            && before.start_time_unix_seconds == after.start_time_unix_seconds
    } else {
        before.name == after.name && before.command == after.command
    }
}

fn signed_delta(after: u64, before: u64) -> i64 {
    i128::from(after)
        .saturating_sub(i128::from(before))
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn count_delta(after: usize, before: usize) -> i64 {
    let after = i128::try_from(after).unwrap_or(i128::MAX);
    let before = i128::try_from(before).unwrap_or(i128::MAX);
    after
        .saturating_sub(before)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn current_own(process: &StoredProcess) -> CurrentMetrics {
    CurrentMetrics {
        cpu_percent: process.cpu_percent,
        memory_bytes: process.memory_bytes,
        read_bytes_per_second: process.read_bytes_per_second,
        write_bytes_per_second: process.write_bytes_per_second,
        process_count: 1,
    }
}

fn current_subtree(process: &StoredProcess) -> CurrentMetrics {
    CurrentMetrics {
        cpu_percent: process.subtree.cpu_percent,
        memory_bytes: process.subtree.memory_bytes,
        read_bytes_per_second: process.subtree.read_bytes_per_second,
        write_bytes_per_second: process.subtree.write_bytes_per_second,
        process_count: process.subtree.process_count,
    }
}

fn resource_delta(before: &StoredProcess, after: &StoredProcess) -> ResourceDelta {
    ResourceDelta {
        pid: after.pid,
        name: after.name.clone(),
        own_delta: MetricDelta {
            cpu_percent: after.cpu_percent - before.cpu_percent,
            memory_bytes: signed_delta(after.memory_bytes, before.memory_bytes),
            read_bytes_per_second: signed_delta(
                after.read_bytes_per_second,
                before.read_bytes_per_second,
            ),
            write_bytes_per_second: signed_delta(
                after.write_bytes_per_second,
                before.write_bytes_per_second,
            ),
            process_count: 0,
        },
        subtree_delta: MetricDelta {
            cpu_percent: after.subtree.cpu_percent - before.subtree.cpu_percent,
            memory_bytes: signed_delta(after.subtree.memory_bytes, before.subtree.memory_bytes),
            read_bytes_per_second: signed_delta(
                after.subtree.read_bytes_per_second,
                before.subtree.read_bytes_per_second,
            ),
            write_bytes_per_second: signed_delta(
                after.subtree.write_bytes_per_second,
                before.subtree.write_bytes_per_second,
            ),
            process_count: count_delta(after.subtree.process_count, before.subtree.process_count),
        },
        current_own: current_own(after),
        current_subtree: current_subtree(after),
    }
}

fn compare_snapshots(
    before: StoredSnapshot,
    after: StoredSnapshot,
) -> Result<SnapshotComparison, String> {
    if before.platform != after.platform {
        return Err(format!(
            "platform mismatch: before is {}, after is {}",
            before.platform, after.platform
        ));
    }
    if before.hostname != after.hostname {
        return Err(format!(
            "hostname mismatch: before is {:?}, after is {:?}",
            before.hostname, after.hostname
        ));
    }
    if before.query != after.query {
        return Err("query mismatch: snapshots must use the exact same filter".into());
    }
    if after.generated_at_unix_ms < before.generated_at_unix_ms {
        return Err("snapshot order is reversed: AFTER is older than BEFORE".into());
    }

    let before_rows: BTreeMap<u32, &StoredProcess> = before
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let after_rows: BTreeMap<u32, &StoredProcess> = after
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut pids: Vec<u32> = before_rows
        .keys()
        .chain(after_rows.keys())
        .copied()
        .collect();
    pids.sort_unstable();
    pids.dedup();

    let mut appeared = Vec::new();
    let mut disappeared = Vec::new();
    let mut pid_reused = Vec::new();
    let mut reparented = Vec::new();
    let mut resource_deltas = Vec::new();
    for pid in pids {
        match (before_rows.get(&pid), after_rows.get(&pid)) {
            (None, Some(after_process)) => appeared.push(ProcessIdentity::from(*after_process)),
            (Some(before_process), None) => {
                disappeared.push(ProcessIdentity::from(*before_process));
            }
            (Some(before_process), Some(after_process))
                if !same_instance(before_process, after_process) =>
            {
                pid_reused.push(PidReuse {
                    pid,
                    before: ProcessIdentity::from(*before_process),
                    after: ProcessIdentity::from(*after_process),
                });
            }
            (Some(before_process), Some(after_process)) => {
                if before_process.parent_pid != after_process.parent_pid {
                    reparented.push(ReparentedProcess {
                        pid,
                        name: after_process.name.clone(),
                        old_parent_pid: before_process.parent_pid,
                        new_parent_pid: after_process.parent_pid,
                    });
                }
                resource_deltas.push(resource_delta(before_process, after_process));
            }
            (None, None) => {}
        }
    }

    let complete_process_list = before.query.is_none();
    let query = before.query.as_ref().map(|query| query.input.clone());
    let summary = DiffSummary {
        appeared: appeared.len(),
        disappeared: disappeared.len(),
        pid_reused: pid_reused.len(),
        reparented: reparented.len(),
        system_process_count_delta: count_delta(
            after.system_process_count,
            before.system_process_count,
        ),
        matched_process_count_delta: count_delta(
            after.matched_process_count,
            before.matched_process_count,
        ),
    };
    Ok(SnapshotComparison {
        platform: before.platform.clone(),
        hostname: before.hostname.clone().unwrap_or_default(),
        elapsed_ms: after
            .generated_at_unix_ms
            .saturating_sub(before.generated_at_unix_ms),
        before: SnapshotSource::from(&before),
        after: SnapshotSource::from(&after),
        selection: SelectionScope {
            complete_process_list,
            query,
            lifecycle_interpretation: if complete_process_list {
                "appeared/disappeared rows represent process starts/exits"
            } else {
                "appeared/disappeared rows may represent entering/leaving the query result"
            },
        },
        summary,
        appeared,
        disappeared,
        pid_reused,
        reparented,
        resource_deltas,
    })
}

#[derive(Debug, Deserialize)]
struct StoredEnvelope {
    schema: String,
}

pub(crate) enum PersistentComparison {
    Snapshot(Box<SnapshotComparison>),
    Doctor(Box<DoctorComparison>),
}

impl PersistentComparison {
    pub(crate) fn evaluate_policy(
        &self,
        fail_on: DiffFailOn,
    ) -> Result<Option<DiffPolicyStatus>, String> {
        match fail_on {
            DiffFailOn::Never => Ok(None),
            DiffFailOn::Regression => match self {
                Self::Doctor(comparison) => Ok(Some(if comparison.regression_detected() {
                    DiffPolicyStatus::Violated
                } else {
                    DiffPolicyStatus::Passed
                })),
                Self::Snapshot(_) => Err(
                    "diff --fail-on regression requires two psmore.host-doctor reports; process snapshot resource changes have no universal failure meaning"
                        .into(),
                ),
            },
        }
    }

    pub(crate) fn summary_line(&self) -> String {
        match self {
            Self::Snapshot(comparison) => format!(
                "snapshot changes +{} -{} reused {} reparented {}",
                comparison.summary.appeared,
                comparison.summary.disappeared,
                comparison.summary.pid_reused,
                comparison.summary.reparented,
            ),
            Self::Doctor(comparison) => comparison.summary_line(),
        }
    }

    pub(crate) fn report_kind(&self) -> &'static str {
        match self {
            Self::Snapshot(_) => "process_snapshot",
            Self::Doctor(_) => "host_doctor",
        }
    }

    pub(crate) fn regression_count(&self) -> Option<usize> {
        match self {
            Self::Snapshot(_) => None,
            Self::Doctor(comparison) => Some(comparison.regression_count()),
        }
    }
}

fn parse_envelope(contents: &str, label: &str) -> Result<StoredEnvelope, String> {
    serde_json::from_str(contents)
        .map_err(|error| format!("cannot identify {label} report schema: {error}"))
}

pub(crate) fn load_comparison(
    before_path: &Path,
    after_path: &Path,
) -> Result<PersistentComparison, String> {
    let before_contents = fs::read_to_string(before_path)
        .map_err(|error| format!("cannot read {}: {error}", before_path.display()))?;
    let after_contents = fs::read_to_string(after_path)
        .map_err(|error| format!("cannot read {}: {error}", after_path.display()))?;
    let before_envelope = parse_envelope(&before_contents, "BEFORE")?;
    let after_envelope = parse_envelope(&after_contents, "AFTER")?;
    if before_envelope.schema != after_envelope.schema {
        return Err(format!(
            "schema mismatch: before is {}, after is {}; compare two reports of the same kind",
            before_envelope.schema, after_envelope.schema
        ));
    }
    match before_envelope.schema.as_str() {
        SNAPSHOT_SCHEMA => {
            let before = parse_snapshot(&before_contents, "BEFORE")?;
            let after = parse_snapshot(&after_contents, "AFTER")?;
            compare_snapshots(before, after)
                .map(Box::new)
                .map(PersistentComparison::Snapshot)
        }
        DOCTOR_SCHEMA => compare_doctor_contents(&before_contents, &after_contents)
            .map(Box::new)
            .map(PersistentComparison::Doctor),
        schema => Err(format!(
            "unsupported diff input schema {schema}; expected {SNAPSHOT_SCHEMA} or {DOCTOR_SCHEMA}"
        )),
    }
}

#[derive(Serialize)]
struct JsonDiff<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    policy: JsonPolicy,
    comparison: &'a SnapshotComparison,
}

#[derive(Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct JsonPolicy {
    fail_on: &'static str,
    passed: Option<bool>,
    status: Option<&'static str>,
    rule: &'static str,
}

fn render_snapshot_diff_json(
    comparison: &SnapshotComparison,
    fail_on: DiffFailOn,
    policy_status: Option<DiffPolicyStatus>,
) -> Result<String, String> {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    let mut output_comparison = comparison.clone();
    for identity in output_comparison
        .appeared
        .iter_mut()
        .chain(output_comparison.disappeared.iter_mut())
    {
        identity.command = command_for_output(&identity.command);
    }
    for reused in &mut output_comparison.pid_reused {
        reused.before.command = command_for_output(&reused.before.command);
        reused.after.command = command_for_output(&reused.after.command);
    }
    serde_json::to_string_pretty(&JsonDiff {
        schema: DIFF_SCHEMA,
        schema_version: DIFF_SCHEMA_VERSION,
        privacy_notice: "May contain command lines, process names, and host names from both snapshots; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms,
        policy: JsonPolicy {
            fail_on: fail_on.label(),
            passed: policy_status.map(DiffPolicyStatus::passed),
            status: policy_status.map(DiffPolicyStatus::label),
            rule: "process snapshot diffs do not define a universal regression policy",
        },
        comparison: &output_comparison,
    })
    .map_err(|error| error.to_string())
}

fn parent_label(parent: Option<u32>) -> String {
    parent
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "-".into())
}

fn signed_bytes(value: i64) -> String {
    let sign = if value > 0 {
        "+"
    } else if value < 0 {
        "-"
    } else {
        ""
    };
    format!("{sign}{}", human_bytes(value.unsigned_abs()))
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

fn append_identity_rows(
    output: &mut String,
    title: &str,
    marker: &str,
    entries: &[ProcessIdentity],
) {
    if entries.is_empty() {
        return;
    }
    output.push_str(&format!("\n{title} ({})\n", entries.len()));
    for entry in entries.iter().take(TABLE_CHANGE_LIMIT) {
        output.push_str(&format!(
            "{marker} {:>7} ppid {:>7} {:<20} {}\n",
            entry.pid,
            parent_label(entry.parent_pid),
            sanitize_terminal_text(&entry.name),
            sanitize_terminal_text(&command_for_output(&entry.command))
        ));
    }
    if entries.len() > TABLE_CHANGE_LIMIT {
        output.push_str(&format!(
            "  ... {} more rows; use --json for the complete list\n",
            entries.len() - TABLE_CHANGE_LIMIT
        ));
    }
}

fn append_cpu_growth(output: &mut String, deltas: &[ResourceDelta]) {
    let mut rows: Vec<&ResourceDelta> = deltas
        .iter()
        .filter(|delta| delta.subtree_delta.cpu_percent > 0.05)
        .collect();
    rows.sort_by(|left, right| {
        right
            .subtree_delta
            .cpu_percent
            .total_cmp(&left.subtree_delta.cpu_percent)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    if rows.is_empty() {
        return;
    }
    output.push_str("\nTOP SUBTREE CPU INCREASE\n");
    output.push_str("    PID NAME                    SELF Δ    TREE Δ  TREE NOW\n");
    for delta in rows.into_iter().take(TABLE_RESOURCE_LIMIT) {
        output.push_str(&format!(
            "{:>7} {:<22} {:+8.1}% {:+8.1}% {:>8.1}%\n",
            delta.pid,
            sanitize_terminal_text(&delta.name),
            delta.own_delta.cpu_percent,
            delta.subtree_delta.cpu_percent,
            delta.current_subtree.cpu_percent
        ));
    }
}

fn append_memory_growth(output: &mut String, deltas: &[ResourceDelta]) {
    let mut rows: Vec<&ResourceDelta> = deltas
        .iter()
        .filter(|delta| delta.subtree_delta.memory_bytes > 0)
        .collect();
    rows.sort_by(|left, right| {
        right
            .subtree_delta
            .memory_bytes
            .cmp(&left.subtree_delta.memory_bytes)
            .then_with(|| left.pid.cmp(&right.pid))
    });
    if rows.is_empty() {
        return;
    }
    output.push_str("\nTOP SUBTREE MEMORY GROWTH\n");
    output.push_str("    PID NAME                     SELF Δ      TREE Δ    TREE NOW  ΔPROCS\n");
    for delta in rows.into_iter().take(TABLE_RESOURCE_LIMIT) {
        output.push_str(&format!(
            "{:>7} {:<22} {:>11} {:>11} {:>11} {:+7}\n",
            delta.pid,
            sanitize_terminal_text(&delta.name),
            signed_bytes(delta.own_delta.memory_bytes),
            signed_bytes(delta.subtree_delta.memory_bytes),
            human_bytes(delta.current_subtree.memory_bytes),
            delta.subtree_delta.process_count
        ));
    }
}

fn positive_io(delta: &ResourceDelta) -> i128 {
    i128::from(delta.subtree_delta.read_bytes_per_second.max(0))
        + i128::from(delta.subtree_delta.write_bytes_per_second.max(0))
}

fn append_io_growth(output: &mut String, deltas: &[ResourceDelta]) {
    let mut rows: Vec<&ResourceDelta> = deltas
        .iter()
        .filter(|delta| positive_io(delta) > 0)
        .collect();
    rows.sort_by(|left, right| {
        positive_io(right)
            .cmp(&positive_io(left))
            .then_with(|| left.pid.cmp(&right.pid))
    });
    if rows.is_empty() {
        return;
    }
    output.push_str("\nTOP SUBTREE I/O RATE INCREASE\n");
    output.push_str("    PID NAME                    TREE READ Δ   TREE WRITE Δ\n");
    for delta in rows.into_iter().take(TABLE_RESOURCE_LIMIT) {
        output.push_str(&format!(
            "{:>7} {:<22} {:>13}/s {:>14}/s\n",
            delta.pid,
            sanitize_terminal_text(&delta.name),
            signed_bytes(delta.subtree_delta.read_bytes_per_second),
            signed_bytes(delta.subtree_delta.write_bytes_per_second)
        ));
    }
}

fn render_snapshot_diff_table(
    comparison: &SnapshotComparison,
    fail_on: DiffFailOn,
    policy_status: Option<DiffPolicyStatus>,
) -> String {
    let mut output = String::new();
    output.push_str("PSMORE SNAPSHOT DIFF\n");
    output.push_str(&format!(
        "host {}  platform {}  window {:.3}s\n",
        comparison.hostname,
        comparison.platform,
        comparison.elapsed_ms as f64 / 1000.0
    ));
    if let Some(query) = &comparison.selection.query {
        output.push_str(&format!(
            "scope query: {}  (appearance means entering/leaving the result)\n",
            sanitize_terminal_text(query)
        ));
    } else {
        output.push_str("scope all processes  (appearance means process start/exit)\n");
    }
    if let Some(policy_status) = policy_status {
        output.push_str(&format!(
            "policy {}  fail-on {}\n",
            policy_status.label().to_ascii_uppercase(),
            fail_on.label(),
        ));
    }
    output.push_str(&format!(
        "system processes {} -> {} ({:+}); matched rows {} -> {} ({:+})\n",
        comparison.before.system_process_count,
        comparison.after.system_process_count,
        comparison.summary.system_process_count_delta,
        comparison.before.matched_process_count,
        comparison.after.matched_process_count,
        comparison.summary.matched_process_count_delta
    ));
    output.push_str(&format!(
        "changes +{}  -{}  reused {}  reparented {}\n",
        comparison.summary.appeared,
        comparison.summary.disappeared,
        comparison.summary.pid_reused,
        comparison.summary.reparented
    ));

    let appeared_title = if comparison.selection.complete_process_list {
        "STARTED"
    } else {
        "APPEARED IN QUERY"
    };
    let disappeared_title = if comparison.selection.complete_process_list {
        "EXITED"
    } else {
        "DISAPPEARED FROM QUERY"
    };
    append_identity_rows(&mut output, appeared_title, "+", &comparison.appeared);
    append_identity_rows(&mut output, disappeared_title, "-", &comparison.disappeared);

    if !comparison.pid_reused.is_empty() {
        output.push_str(&format!("\nPID REUSED ({})\n", comparison.pid_reused.len()));
        for reuse in comparison.pid_reused.iter().take(TABLE_CHANGE_LIMIT) {
            output.push_str(&format!(
                "! {:>7} {} [{}] -> {} [{}]\n",
                reuse.pid,
                sanitize_terminal_text(&reuse.before.name),
                reuse.before.start_time_unix_seconds,
                sanitize_terminal_text(&reuse.after.name),
                reuse.after.start_time_unix_seconds
            ));
        }
        if comparison.pid_reused.len() > TABLE_CHANGE_LIMIT {
            output.push_str(&format!(
                "  ... {} more rows; use --json for the complete list\n",
                comparison.pid_reused.len() - TABLE_CHANGE_LIMIT
            ));
        }
    }
    if !comparison.reparented.is_empty() {
        output.push_str(&format!("\nREPARENTED ({})\n", comparison.reparented.len()));
        for process in comparison.reparented.iter().take(TABLE_CHANGE_LIMIT) {
            output.push_str(&format!(
                "↪ {:>7} {:<20} {} -> {}\n",
                process.pid,
                sanitize_terminal_text(&process.name),
                parent_label(process.old_parent_pid),
                parent_label(process.new_parent_pid)
            ));
        }
        if comparison.reparented.len() > TABLE_CHANGE_LIMIT {
            output.push_str(&format!(
                "  ... {} more rows; use --json for the complete list\n",
                comparison.reparented.len() - TABLE_CHANGE_LIMIT
            ));
        }
    }

    append_cpu_growth(&mut output, &comparison.resource_deltas);
    append_memory_growth(&mut output, &comparison.resource_deltas);
    append_io_growth(&mut output, &comparison.resource_deltas);
    output
}

pub(crate) fn render_diff_json(
    comparison: &PersistentComparison,
    fail_on: DiffFailOn,
    policy_status: Option<DiffPolicyStatus>,
) -> Result<String, String> {
    match comparison {
        PersistentComparison::Snapshot(comparison) => {
            render_snapshot_diff_json(comparison, fail_on, policy_status)
        }
        PersistentComparison::Doctor(comparison) => {
            render_doctor_diff_json(comparison, fail_on, policy_status)
        }
    }
}

pub(crate) fn render_diff_table(
    comparison: &PersistentComparison,
    fail_on: DiffFailOn,
    policy_status: Option<DiffPolicyStatus>,
) -> String {
    match comparison {
        PersistentComparison::Snapshot(comparison) => {
            render_snapshot_diff_table(comparison, fail_on, policy_status)
        }
        PersistentComparison::Doctor(comparison) => {
            render_doctor_diff_table(comparison, fail_on, policy_status)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn process(pid: u32, parent: u32, name: &str, start: u64, cpu: f32, memory: u64) -> Value {
        json!({
            "pid": pid,
            "parent_pid": parent,
            "name": name,
            "path": format!("/srv/{name}"),
            "command": format!("/srv/{name}"),
            "executable": format!("/srv/{name}"),
            "user": "deploy",
            "cwd": "/srv",
            "status": "Sleep",
            "cpu_percent": cpu,
            "memory_bytes": memory,
            "read_bytes_per_second": 100,
            "write_bytes_per_second": 200,
            "start_time_unix_seconds": start,
            "runtime_seconds": 60,
            "direct_child_count": 0,
            "subtree": {
                "cpu_percent": cpu,
                "memory_bytes": memory,
                "read_bytes_per_second": 100,
                "write_bytes_per_second": 200,
                "process_count": 1
            }
        })
    }

    fn snapshot(timestamp: u64, query: Option<&str>, processes: Vec<Value>) -> String {
        serde_json::to_string(&json!({
            "schema": SNAPSHOT_SCHEMA,
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "generated_at_unix_ms": timestamp,
            "platform": "Linux",
            "hostname": "host-a",
            "sample_interval_ms": 500,
            "query": query.map(|input| json!({"input": input})),
            "system_process_count": processes.len(),
            "matched_process_count": processes.len(),
            "processes": processes
        }))
        .unwrap()
    }

    #[test]
    fn detects_lifecycle_pid_reuse_reparenting_and_resource_changes() {
        let before = snapshot(
            1_000,
            None,
            vec![
                process(10, 1, "api", 100, 10.0, 100),
                process(20, 1, "old", 200, 1.0, 20),
                process(40, 1, "gone", 400, 1.0, 40),
            ],
        );
        let after = snapshot(
            2_500,
            None,
            vec![
                process(10, 2, "api", 100, 30.0, 160),
                process(20, 1, "new", 201, 2.0, 25),
                process(30, 1, "born", 300, 3.0, 30),
            ],
        );
        let comparison = compare_snapshots(
            parse_snapshot(&before, "BEFORE").unwrap(),
            parse_snapshot(&after, "AFTER").unwrap(),
        )
        .unwrap();
        assert_eq!(comparison.elapsed_ms, 1_500);
        assert_eq!(comparison.appeared[0].pid, 30);
        assert_eq!(comparison.disappeared[0].pid, 40);
        assert_eq!(comparison.pid_reused[0].pid, 20);
        assert_eq!(comparison.reparented[0].pid, 10);
        assert_eq!(comparison.resource_deltas[0].own_delta.memory_bytes, 60);
        assert_eq!(comparison.resource_deltas[0].own_delta.cpu_percent, 20.0);
        let table = render_snapshot_diff_table(&comparison, DiffFailOn::Never, None);
        assert!(table.contains("STARTED (1)"));
        assert!(table.contains("PID REUSED (1)"));
        assert!(table.contains("TOP SUBTREE MEMORY GROWTH"));
        let json: Value = serde_json::from_str(
            &render_snapshot_diff_json(&comparison, DiffFailOn::Never, None).unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], DIFF_SCHEMA);
        assert_eq!(json["comparison"]["summary"]["pid_reused"], 1);
        let persistent = PersistentComparison::Snapshot(Box::new(comparison));
        assert!(
            persistent
                .evaluate_policy(DiffFailOn::Regression)
                .unwrap_err()
                .contains("requires two psmore.host-doctor reports")
        );
    }

    #[test]
    fn refuses_cross_source_or_malformed_comparisons() {
        let valid = snapshot(
            1_000,
            Some("name:api"),
            vec![process(10, 1, "api", 100, 1.0, 1)],
        );
        let mut hostname_mismatch: Value = serde_json::from_str(&valid).unwrap();
        hostname_mismatch["hostname"] = json!("host-b");
        let mut query_mismatch: Value = serde_json::from_str(&valid).unwrap();
        query_mismatch["query"] = json!({"input": "name:worker"});
        let mut duplicate: Value = serde_json::from_str(&valid).unwrap();
        duplicate["processes"] = json!([
            process(10, 1, "api", 100, 1.0, 1),
            process(10, 1, "api", 100, 1.0, 1)
        ]);
        duplicate["matched_process_count"] = json!(2);
        duplicate["system_process_count"] = json!(2);

        let before = parse_snapshot(&valid, "BEFORE").unwrap();
        let after = parse_snapshot(&hostname_mismatch.to_string(), "AFTER").unwrap();
        assert!(
            compare_snapshots(before, after)
                .unwrap_err()
                .contains("hostname mismatch")
        );
        let before = parse_snapshot(&valid, "BEFORE").unwrap();
        let after = parse_snapshot(&query_mismatch.to_string(), "AFTER").unwrap();
        assert!(
            compare_snapshots(before, after)
                .unwrap_err()
                .contains("query mismatch")
        );
        assert!(
            parse_snapshot(&duplicate.to_string(), "BEFORE")
                .unwrap_err()
                .contains("duplicate PID")
        );
    }

    #[test]
    fn filtered_diff_uses_selection_language_not_lifecycle_claims() {
        let before = snapshot(1_000, Some("cpu>10"), Vec::new());
        let after = snapshot(
            2_000,
            Some("cpu>10"),
            vec![process(10, 1, "api", 100, 20.0, 1)],
        );
        let comparison = compare_snapshots(
            parse_snapshot(&before, "BEFORE").unwrap(),
            parse_snapshot(&after, "AFTER").unwrap(),
        )
        .unwrap();
        let table = render_snapshot_diff_table(&comparison, DiffFailOn::Never, None);
        assert!(table.contains("APPEARED IN QUERY"));
        assert!(!table.contains("STARTED"));
    }
}
