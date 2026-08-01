use std::{
    io::{self, Write},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    headless::ProcessSnapshot,
    model::{
        ProcessInfo, ResourceAggregate, process_command_line, process_path, sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const TRACE_SCHEMA: &str = "psmore.process-trace-record";
const TRACE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceOutput {
    Table,
    Jsonl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceRunStatus {
    Complete,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityContinuity {
    Confirmed,
    Fallback,
    PidReused,
    Unverifiable,
}

impl IdentityContinuity {
    fn label(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Fallback => "unverified_fallback",
            Self::PidReused => "pid_reused",
            Self::Unverifiable => "identity_unverifiable",
        }
    }
}

fn identity_continuity(baseline: &ProcessInfo, current: &ProcessInfo) -> IdentityContinuity {
    match (baseline.start_time, current.start_time) {
        (baseline_start, current_start) if baseline_start > 0 && current_start > 0 => {
            if baseline_start == current_start {
                IdentityContinuity::Confirmed
            } else {
                IdentityContinuity::PidReused
            }
        }
        (0, 0)
            if baseline.name == current.name
                && process_command_line(baseline) == process_command_line(current) =>
        {
            IdentityContinuity::Fallback
        }
        (0, 0) => IdentityContinuity::PidReused,
        _ => IdentityContinuity::Unverifiable,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceTermination {
    CountReached,
    Exited,
    PidReused,
    IdentityUnverifiable,
}

impl TraceTermination {
    fn label(self) -> &'static str {
        match self {
            Self::CountReached => "count_reached",
            Self::Exited => "exited",
            Self::PidReused => "pid_reused",
            Self::IdentityUnverifiable => "identity_unverifiable",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SampleDelta {
    own_memory_from_baseline: i64,
    own_memory_from_previous: i64,
    subtree_memory_from_baseline: i64,
    subtree_memory_from_previous: i64,
    subtree_processes_from_baseline: i64,
    subtree_processes_from_previous: i64,
}

impl SampleDelta {
    fn between(
        baseline_process: &ProcessInfo,
        baseline_aggregate: ResourceAggregate,
        previous_process: &ProcessInfo,
        previous_aggregate: ResourceAggregate,
        current_process: &ProcessInfo,
        current_aggregate: ResourceAggregate,
    ) -> Self {
        Self {
            own_memory_from_baseline: signed_delta_u64(
                current_process.memory,
                baseline_process.memory,
            ),
            own_memory_from_previous: signed_delta_u64(
                current_process.memory,
                previous_process.memory,
            ),
            subtree_memory_from_baseline: signed_delta_u64(
                current_aggregate.memory,
                baseline_aggregate.memory,
            ),
            subtree_memory_from_previous: signed_delta_u64(
                current_aggregate.memory,
                previous_aggregate.memory,
            ),
            subtree_processes_from_baseline: signed_delta_usize(
                current_aggregate.process_count,
                baseline_aggregate.process_count,
            ),
            subtree_processes_from_previous: signed_delta_usize(
                current_aggregate.process_count,
                previous_aggregate.process_count,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TraceStats {
    baseline_own_memory: u64,
    baseline_subtree_memory: u64,
    final_own_memory: u64,
    final_subtree_memory: u64,
    sample_count: usize,
    peak_own_cpu: f32,
    peak_subtree_cpu: f32,
    peak_own_memory: u64,
    peak_subtree_memory: u64,
    peak_own_read_rate: u64,
    peak_own_write_rate: u64,
    peak_subtree_read_rate: u64,
    peak_subtree_write_rate: u64,
}

impl TraceStats {
    fn new(process: &ProcessInfo, aggregate: ResourceAggregate) -> Self {
        Self {
            baseline_own_memory: process.memory,
            baseline_subtree_memory: aggregate.memory,
            final_own_memory: process.memory,
            final_subtree_memory: aggregate.memory,
            sample_count: 0,
            peak_own_cpu: finite(process.cpu),
            peak_subtree_cpu: finite(aggregate.cpu),
            peak_own_memory: process.memory,
            peak_subtree_memory: aggregate.memory,
            peak_own_read_rate: process.read_rate,
            peak_own_write_rate: process.write_rate,
            peak_subtree_read_rate: aggregate.read_rate,
            peak_subtree_write_rate: aggregate.write_rate,
        }
    }

    fn record(&mut self, process: &ProcessInfo, aggregate: ResourceAggregate) {
        self.sample_count = self.sample_count.saturating_add(1);
        self.final_own_memory = process.memory;
        self.final_subtree_memory = aggregate.memory;
        self.peak_own_cpu = self.peak_own_cpu.max(finite(process.cpu));
        self.peak_subtree_cpu = self.peak_subtree_cpu.max(finite(aggregate.cpu));
        self.peak_own_memory = self.peak_own_memory.max(process.memory);
        self.peak_subtree_memory = self.peak_subtree_memory.max(aggregate.memory);
        self.peak_own_read_rate = self.peak_own_read_rate.max(process.read_rate);
        self.peak_own_write_rate = self.peak_own_write_rate.max(process.write_rate);
        self.peak_subtree_read_rate = self.peak_subtree_read_rate.max(aggregate.read_rate);
        self.peak_subtree_write_rate = self.peak_subtree_write_rate.max(aggregate.write_rate);
    }
}

#[derive(Debug, Serialize)]
struct JsonTraceRecord {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    sequence: u64,
    kind: &'static str,
    observed_at_unix_ms: u64,
    elapsed_ms: u64,
    configured_interval_ms: u64,
    actual_interval_ms: u64,
    sample_index: usize,
    platform: &'static str,
    hostname: Option<String>,
    system_process_count: usize,
    target: JsonTargetIdentity,
    process: Option<JsonTraceProcess>,
    delta: Option<JsonDelta>,
    termination_reason: Option<&'static str>,
    summary: Option<JsonSummary>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct JsonTargetIdentity {
    pid: u32,
    start_time_unix_seconds: u64,
    identity_verified: bool,
    name: String,
    path: String,
    command: String,
    user: String,
}

impl From<&ProcessInfo> for JsonTargetIdentity {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            start_time_unix_seconds: process.start_time,
            identity_verified: process.start_time > 0,
            name: sanitize_terminal_text(&process.name),
            path: sanitize_terminal_text(&process_path(process)),
            command: sanitize_terminal_text(&process_command_line(process)),
            user: sanitize_terminal_text(&process.user),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonTraceProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    path: String,
    command: String,
    user: String,
    status: String,
    start_time_unix_seconds: u64,
    runtime_seconds: u64,
    identity_continuity: &'static str,
    own: JsonResources,
    subtree: JsonSubtreeResources,
}

#[derive(Debug, Serialize)]
struct JsonResources {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
}

#[derive(Debug, Serialize)]
struct JsonSubtreeResources {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

#[derive(Debug, Serialize)]
struct JsonDelta {
    own_memory_from_baseline_bytes: i64,
    own_memory_from_previous_bytes: i64,
    subtree_memory_from_baseline_bytes: i64,
    subtree_memory_from_previous_bytes: i64,
    subtree_processes_from_baseline: i64,
    subtree_processes_from_previous: i64,
}

impl From<SampleDelta> for JsonDelta {
    fn from(delta: SampleDelta) -> Self {
        Self {
            own_memory_from_baseline_bytes: delta.own_memory_from_baseline,
            own_memory_from_previous_bytes: delta.own_memory_from_previous,
            subtree_memory_from_baseline_bytes: delta.subtree_memory_from_baseline,
            subtree_memory_from_previous_bytes: delta.subtree_memory_from_previous,
            subtree_processes_from_baseline: delta.subtree_processes_from_baseline,
            subtree_processes_from_previous: delta.subtree_processes_from_previous,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonSummary {
    refresh_count: usize,
    emitted_sample_count: usize,
    baseline_own_memory_bytes: u64,
    final_own_memory_bytes: u64,
    own_memory_growth_bytes: i64,
    baseline_subtree_memory_bytes: u64,
    final_subtree_memory_bytes: u64,
    subtree_memory_growth_bytes: i64,
    peak_own_cpu_percent: f32,
    peak_subtree_cpu_percent: f32,
    peak_own_memory_bytes: u64,
    peak_subtree_memory_bytes: u64,
    peak_own_read_bytes_per_second: u64,
    peak_own_write_bytes_per_second: u64,
    peak_subtree_read_bytes_per_second: u64,
    peak_subtree_write_bytes_per_second: u64,
}

fn json_process(
    process: &ProcessInfo,
    aggregate: ResourceAggregate,
    continuity: IdentityContinuity,
) -> JsonTraceProcess {
    JsonTraceProcess {
        pid: process.pid.as_u32(),
        parent_pid: process.parent.map(Pid::as_u32),
        name: sanitize_terminal_text(&process.name),
        path: sanitize_terminal_text(&process_path(process)),
        command: sanitize_terminal_text(&process_command_line(process)),
        user: sanitize_terminal_text(&process.user),
        status: sanitize_terminal_text(&process.status),
        start_time_unix_seconds: process.start_time,
        runtime_seconds: process.runtime,
        identity_continuity: continuity.label(),
        own: JsonResources {
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            read_bytes_per_second: process.read_rate,
            write_bytes_per_second: process.write_rate,
        },
        subtree: JsonSubtreeResources {
            cpu_percent: finite(aggregate.cpu),
            memory_bytes: aggregate.memory,
            read_bytes_per_second: aggregate.read_rate,
            write_bytes_per_second: aggregate.write_rate,
            process_count: aggregate.process_count,
        },
    }
}

fn json_summary(stats: TraceStats, refresh_count: usize) -> JsonSummary {
    JsonSummary {
        refresh_count,
        emitted_sample_count: stats.sample_count,
        baseline_own_memory_bytes: stats.baseline_own_memory,
        final_own_memory_bytes: stats.final_own_memory,
        own_memory_growth_bytes: signed_delta_u64(
            stats.final_own_memory,
            stats.baseline_own_memory,
        ),
        baseline_subtree_memory_bytes: stats.baseline_subtree_memory,
        final_subtree_memory_bytes: stats.final_subtree_memory,
        subtree_memory_growth_bytes: signed_delta_u64(
            stats.final_subtree_memory,
            stats.baseline_subtree_memory,
        ),
        peak_own_cpu_percent: finite(stats.peak_own_cpu),
        peak_subtree_cpu_percent: finite(stats.peak_subtree_cpu),
        peak_own_memory_bytes: stats.peak_own_memory,
        peak_subtree_memory_bytes: stats.peak_subtree_memory,
        peak_own_read_bytes_per_second: stats.peak_own_read_rate,
        peak_own_write_bytes_per_second: stats.peak_own_write_rate,
        peak_subtree_read_bytes_per_second: stats.peak_subtree_read_rate,
        peak_subtree_write_bytes_per_second: stats.peak_subtree_write_rate,
    }
}

struct JsonRecordInput<'a> {
    sequence: u64,
    kind: &'static str,
    started_at: Instant,
    configured_interval_ms: u64,
    actual_interval: Duration,
    sample_index: usize,
    hostname: &'a Option<String>,
    system_process_count: usize,
    target: &'a JsonTargetIdentity,
    process: Option<(&'a ProcessInfo, ResourceAggregate, IdentityContinuity)>,
    delta: Option<SampleDelta>,
    termination: Option<TraceTermination>,
    summary: Option<(TraceStats, usize)>,
}

fn json_record(input: JsonRecordInput<'_>) -> JsonTraceRecord {
    JsonTraceRecord {
        schema: TRACE_SCHEMA,
        schema_version: TRACE_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, path, user, relationship, and resource time-series information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        sequence: input.sequence,
        kind: input.kind,
        observed_at_unix_ms: unix_millis(),
        elapsed_ms: elapsed_millis(input.started_at.elapsed()),
        configured_interval_ms: input.configured_interval_ms,
        actual_interval_ms: elapsed_millis(input.actual_interval),
        sample_index: input.sample_index,
        platform: platform_name(),
        hostname: input.hostname.clone(),
        system_process_count: input.system_process_count,
        target: input.target.clone(),
        process: input
            .process
            .map(|(process, aggregate, continuity)| json_process(process, aggregate, continuity)),
        delta: input.delta.map(JsonDelta::from),
        termination_reason: input.termination.map(TraceTermination::label),
        summary: input
            .summary
            .map(|(stats, refresh_count)| json_summary(stats, refresh_count)),
    }
}

fn write_json_record<W: Write>(writer: &mut W, record: &JsonTraceRecord) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, record).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

fn write_table_header<W: Write>(
    writer: &mut W,
    process: &ProcessInfo,
    aggregate: ResourceAggregate,
    interval_ms: u64,
) -> io::Result<()> {
    writeln!(writer, "PSMORE PROCESS TRACE")?;
    writeln!(
        writer,
        "target {} [{}]  parent {}  user {}  started {}  interval {}ms",
        sanitize_terminal_text(&process.name),
        process.pid.as_u32(),
        process.parent.map(Pid::as_u32).unwrap_or(0),
        sanitize_terminal_text(&process.user),
        if process.start_time > 0 {
            process.start_time.to_string()
        } else {
            "[unverified]".into()
        },
        interval_ms,
    )?;
    writeln!(
        writer,
        "command {}",
        sanitize_terminal_text(&process_command_line(process))
    )?;
    writeln!(
        writer,
        "baseline memory {}/{}  subtree {} process(es)",
        human_bytes(process.memory),
        human_bytes(aggregate.memory),
        aggregate.process_count,
    )?;
    writeln!(
        writer,
        "ELAPSED   SAMPLE CPU%/TREE       MEM/TREE        ΔBASE/TREE      READ/TREE       WRITE/TREE      PROCS STATUS"
    )
}

fn write_table_sample<W: Write>(
    writer: &mut W,
    elapsed: Duration,
    sample_index: usize,
    process: &ProcessInfo,
    aggregate: ResourceAggregate,
    delta: SampleDelta,
) -> io::Result<()> {
    writeln!(
        writer,
        "+{:>7.3}s {:>6} {:>5.1}/{:<5.1} {:>9}/{:<9} {:>9}/{:<9} {:>9}/{:<9} {:>9}/{:<9} {:>5} {}",
        elapsed.as_secs_f64(),
        sample_index,
        finite(process.cpu),
        finite(aggregate.cpu),
        human_bytes(process.memory),
        human_bytes(aggregate.memory),
        signed_human_bytes(delta.own_memory_from_baseline),
        signed_human_bytes(delta.subtree_memory_from_baseline),
        human_bytes(process.read_rate),
        human_bytes(aggregate.read_rate),
        human_bytes(process.write_rate),
        human_bytes(aggregate.write_rate),
        aggregate.process_count,
        sanitize_terminal_text(&process.status),
    )
}

fn write_table_terminal<W: Write>(
    writer: &mut W,
    elapsed: Duration,
    termination: TraceTermination,
    current: Option<&ProcessInfo>,
) -> io::Result<()> {
    match current {
        Some(process) => writeln!(
            writer,
            "+{:>7.3}s  {}  current {} [{}] started {}",
            elapsed.as_secs_f64(),
            termination.label().to_ascii_uppercase(),
            sanitize_terminal_text(&process.name),
            process.pid.as_u32(),
            process.start_time,
        ),
        None => writeln!(
            writer,
            "+{:>7.3}s  {}  target is no longer visible",
            elapsed.as_secs_f64(),
            termination.label().to_ascii_uppercase(),
        ),
    }
}

fn write_table_complete<W: Write>(
    writer: &mut W,
    termination: TraceTermination,
    refresh_count: usize,
    stats: TraceStats,
) -> io::Result<()> {
    writeln!(
        writer,
        "COMPLETE  reason {}  {} refresh(es), {} sample(s)  peak CPU {:.1}/{:.1}%  memory growth {}/{}",
        termination.label(),
        refresh_count,
        stats.sample_count,
        finite(stats.peak_own_cpu),
        finite(stats.peak_subtree_cpu),
        signed_human_bytes(signed_delta_u64(
            stats.final_own_memory,
            stats.baseline_own_memory,
        )),
        signed_human_bytes(signed_delta_u64(
            stats.final_subtree_memory,
            stats.baseline_subtree_memory,
        )),
    )
}

pub(crate) fn run_trace<W: Write>(
    writer: &mut W,
    pid: u32,
    interval_ms: u64,
    count: Option<usize>,
    output: TraceOutput,
) -> io::Result<TraceRunStatus> {
    let pid = Pid::from_u32(pid);
    let started_at = Instant::now();
    let hostname = System::host_name();
    let mut provider = NativeProcessProvider::new();
    let baseline_snapshot = ProcessSnapshot::build(provider.refresh(), interval_ms, unix_millis());
    let baseline_process = baseline_snapshot.process(pid).cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("PID {} is not visible", pid.as_u32()),
        )
    })?;
    let baseline_aggregate = baseline_snapshot.resource(pid);
    let target = JsonTargetIdentity::from(&baseline_process);
    let baseline_continuity = if baseline_process.start_time > 0 {
        IdentityContinuity::Confirmed
    } else {
        IdentityContinuity::Fallback
    };
    let mut stats = TraceStats::new(&baseline_process, baseline_aggregate);

    match output {
        TraceOutput::Table => {
            write_table_header(writer, &baseline_process, baseline_aggregate, interval_ms)?
        }
        TraceOutput::Jsonl => write_json_record(
            writer,
            &json_record(JsonRecordInput {
                sequence: 0,
                kind: "baseline",
                started_at,
                configured_interval_ms: interval_ms,
                actual_interval: Duration::ZERO,
                sample_index: 0,
                hostname: &hostname,
                system_process_count: baseline_snapshot.real_process_count(),
                target: &target,
                process: Some((&baseline_process, baseline_aggregate, baseline_continuity)),
                delta: Some(SampleDelta::between(
                    &baseline_process,
                    baseline_aggregate,
                    &baseline_process,
                    baseline_aggregate,
                    &baseline_process,
                    baseline_aggregate,
                )),
                termination: None,
                summary: None,
            }),
        )?,
    }
    writer.flush()?;

    let mut previous_process = baseline_process.clone();
    let mut previous_aggregate = baseline_aggregate;
    let mut previous_observed_at = Instant::now();
    let mut refresh_count = 0_usize;
    let mut sequence = 0_u64;
    let mut last_system_process_count = baseline_snapshot.real_process_count();
    let termination = loop {
        if count.is_some_and(|count| stats.sample_count >= count) {
            break TraceTermination::CountReached;
        }
        thread::sleep(Duration::from_millis(interval_ms));
        refresh_count = refresh_count.saturating_add(1);
        let processes = provider.refresh();
        let observed_at = Instant::now();
        let actual_interval = observed_at.saturating_duration_since(previous_observed_at);
        previous_observed_at = observed_at;
        let snapshot = ProcessSnapshot::build(processes, interval_ms, unix_millis());
        last_system_process_count = snapshot.real_process_count();
        let Some(current_process) = snapshot.process(pid).cloned() else {
            sequence = sequence.saturating_add(1);
            match output {
                TraceOutput::Table => write_table_terminal(
                    writer,
                    started_at.elapsed(),
                    TraceTermination::Exited,
                    None,
                )?,
                TraceOutput::Jsonl => write_json_record(
                    writer,
                    &json_record(JsonRecordInput {
                        sequence,
                        kind: "exited",
                        started_at,
                        configured_interval_ms: interval_ms,
                        actual_interval,
                        sample_index: stats.sample_count,
                        hostname: &hostname,
                        system_process_count: snapshot.real_process_count(),
                        target: &target,
                        process: None,
                        delta: None,
                        termination: Some(TraceTermination::Exited),
                        summary: None,
                    }),
                )?,
            }
            writer.flush()?;
            break TraceTermination::Exited;
        };
        let current_aggregate = snapshot.resource(pid);
        let continuity = identity_continuity(&baseline_process, &current_process);
        let terminal = match continuity {
            IdentityContinuity::PidReused => Some(TraceTermination::PidReused),
            IdentityContinuity::Unverifiable => Some(TraceTermination::IdentityUnverifiable),
            IdentityContinuity::Confirmed | IdentityContinuity::Fallback => None,
        };
        if let Some(terminal) = terminal {
            sequence = sequence.saturating_add(1);
            match output {
                TraceOutput::Table => write_table_terminal(
                    writer,
                    started_at.elapsed(),
                    terminal,
                    Some(&current_process),
                )?,
                TraceOutput::Jsonl => write_json_record(
                    writer,
                    &json_record(JsonRecordInput {
                        sequence,
                        kind: terminal.label(),
                        started_at,
                        configured_interval_ms: interval_ms,
                        actual_interval,
                        sample_index: stats.sample_count,
                        hostname: &hostname,
                        system_process_count: snapshot.real_process_count(),
                        target: &target,
                        process: Some((&current_process, current_aggregate, continuity)),
                        delta: None,
                        termination: Some(terminal),
                        summary: None,
                    }),
                )?,
            }
            writer.flush()?;
            break terminal;
        }

        let delta = SampleDelta::between(
            &baseline_process,
            baseline_aggregate,
            &previous_process,
            previous_aggregate,
            &current_process,
            current_aggregate,
        );
        stats.record(&current_process, current_aggregate);
        sequence = sequence.saturating_add(1);
        match output {
            TraceOutput::Table => write_table_sample(
                writer,
                started_at.elapsed(),
                stats.sample_count,
                &current_process,
                current_aggregate,
                delta,
            )?,
            TraceOutput::Jsonl => write_json_record(
                writer,
                &json_record(JsonRecordInput {
                    sequence,
                    kind: "sample",
                    started_at,
                    configured_interval_ms: interval_ms,
                    actual_interval,
                    sample_index: stats.sample_count,
                    hostname: &hostname,
                    system_process_count: snapshot.real_process_count(),
                    target: &target,
                    process: Some((&current_process, current_aggregate, continuity)),
                    delta: Some(delta),
                    termination: None,
                    summary: None,
                }),
            )?,
        }
        writer.flush()?;
        previous_process = current_process;
        previous_aggregate = current_aggregate;
    };

    sequence = sequence.saturating_add(1);
    match output {
        TraceOutput::Table => write_table_complete(writer, termination, refresh_count, stats)?,
        TraceOutput::Jsonl => write_json_record(
            writer,
            &json_record(JsonRecordInput {
                sequence,
                kind: "complete",
                started_at,
                configured_interval_ms: interval_ms,
                actual_interval: Duration::ZERO,
                sample_index: stats.sample_count,
                hostname: &hostname,
                system_process_count: last_system_process_count,
                target: &target,
                process: None,
                delta: None,
                termination: Some(termination),
                summary: Some((stats, refresh_count)),
            }),
        )?,
    }
    writer.flush()?;
    Ok(if termination == TraceTermination::IdentityUnverifiable {
        TraceRunStatus::Inconclusive
    } else {
        TraceRunStatus::Complete
    })
}

fn signed_delta_u64(current: u64, baseline: u64) -> i64 {
    if current >= baseline {
        current.saturating_sub(baseline).min(i64::MAX as u64) as i64
    } else {
        -(baseline.saturating_sub(current).min(i64::MAX as u64) as i64)
    }
}

fn signed_delta_usize(current: usize, baseline: usize) -> i64 {
    if current >= baseline {
        current.saturating_sub(baseline).min(i64::MAX as usize) as i64
    } else {
        -(baseline.saturating_sub(current).min(i64::MAX as usize) as i64)
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn finite(value: f32) -> f32 {
    if value.is_finite() { value } else { 0.0 }
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

fn signed_human_bytes(value: i64) -> String {
    if value > 0 {
        format!("+{}", human_bytes(value as u64))
    } else if value < 0 {
        format!("-{}", human_bytes(value.unsigned_abs()))
    } else {
        "0B".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(start_time: u64, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: name.into(),
            command: format!("/srv/{name}\n--worker"),
            executable: format!("/srv/{name}"),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: 10.0,
            memory: 1024,
            read_rate: 2048,
            write_rate: 4096,
            start_time,
            runtime: 10,
            status: "Sleep".into(),
        }
    }

    #[test]
    fn identity_tracking_never_silently_crosses_process_instances() {
        assert_eq!(
            identity_continuity(&process(100, "api"), &process(100, "api")),
            IdentityContinuity::Confirmed
        );
        assert_eq!(
            identity_continuity(&process(100, "api"), &process(101, "api")),
            IdentityContinuity::PidReused
        );
        assert_eq!(
            identity_continuity(&process(0, "api"), &process(0, "api")),
            IdentityContinuity::Fallback
        );
        assert_eq!(
            identity_continuity(&process(0, "api"), &process(0, "worker")),
            IdentityContinuity::PidReused
        );
        assert_eq!(
            identity_continuity(&process(100, "api"), &process(0, "api")),
            IdentityContinuity::Unverifiable
        );
    }

    #[test]
    fn deltas_are_signed_and_relative_to_baseline_and_previous() {
        let baseline = process(100, "api");
        let mut previous = baseline.clone();
        previous.memory = 2_048;
        let mut current = baseline.clone();
        current.memory = 1_536;
        let baseline_aggregate = ResourceAggregate {
            memory: 4_096,
            process_count: 2,
            ..ResourceAggregate::default()
        };
        let previous_aggregate = ResourceAggregate {
            memory: 8_192,
            process_count: 4,
            ..ResourceAggregate::default()
        };
        let current_aggregate = ResourceAggregate {
            memory: 6_144,
            process_count: 3,
            ..ResourceAggregate::default()
        };
        let delta = SampleDelta::between(
            &baseline,
            baseline_aggregate,
            &previous,
            previous_aggregate,
            &current,
            current_aggregate,
        );
        assert_eq!(delta.own_memory_from_baseline, 512);
        assert_eq!(delta.own_memory_from_previous, -512);
        assert_eq!(delta.subtree_memory_from_baseline, 2_048);
        assert_eq!(delta.subtree_memory_from_previous, -2_048);
        assert_eq!(delta.subtree_processes_from_baseline, 1);
        assert_eq!(delta.subtree_processes_from_previous, -1);
    }

    #[test]
    fn finite_trace_emits_baseline_samples_and_summary_jsonl() {
        let mut output = Vec::new();
        run_trace(
            &mut output,
            std::process::id(),
            100,
            Some(1),
            TraceOutput::Jsonl,
        )
        .unwrap();
        let records: Vec<serde_json::Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["schema"], TRACE_SCHEMA);
        assert_eq!(records[0]["kind"], "baseline");
        assert_eq!(records[1]["kind"], "sample");
        assert_eq!(records[1]["sample_index"], 1);
        assert_eq!(records[2]["kind"], "complete");
        assert_eq!(records[2]["termination_reason"], "count_reached");
        assert_eq!(records[2]["summary"]["emitted_sample_count"], 1);
        assert_eq!(records[0]["target"]["pid"], std::process::id());
    }
}
