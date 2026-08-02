use std::{
    collections::HashSet,
    io::{self, Write},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    headless::ProcessSnapshot,
    model::{
        ProcessChange, ProcessInfo, ResourceAggregate, diff_processes, process_command_for_output,
        process_path, sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
    query::ProcessQuery,
};

const WATCH_SCHEMA: &str = "psmore.process-watch-event";
const WATCH_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WatchOutput {
    Table,
    Jsonl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WatchEventKind {
    Started,
    Exited,
    Reparented,
    Matched,
    Unmatched,
}

impl WatchEventKind {
    fn label(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Exited => "exited",
            Self::Reparented => "reparented",
            Self::Matched => "matched",
            Self::Unmatched => "unmatched",
        }
    }

    fn table_label(self) -> &'static str {
        match self {
            Self::Started => "START",
            Self::Exited => "EXIT",
            Self::Reparented => "REPARENT",
            Self::Matched => "MATCH",
            Self::Unmatched => "UNMATCH",
        }
    }
}

#[derive(Clone, Debug)]
struct WatchEvent {
    kind: WatchEventKind,
    process: ProcessInfo,
    aggregate: ResourceAggregate,
    old_parent: Option<Pid>,
    new_parent: Option<Pid>,
}

fn process_event(
    kind: WatchEventKind,
    pid: Pid,
    snapshot: &ProcessSnapshot,
    old_parent: Option<Pid>,
    new_parent: Option<Pid>,
) -> Option<WatchEvent> {
    Some(WatchEvent {
        kind,
        process: snapshot.process(pid)?.clone(),
        aggregate: snapshot.resource(pid),
        old_parent,
        new_parent,
    })
}

fn events_between(
    previous: &ProcessSnapshot,
    current: &ProcessSnapshot,
    previous_matches: &HashSet<Pid>,
    current_matches: &HashSet<Pid>,
) -> Vec<WatchEvent> {
    let changes = diff_processes(previous.processes(), current.processes());
    let mut replaced_or_lifecycle = HashSet::new();
    let mut events = Vec::new();
    for change in changes {
        let pid = change.pid();
        match change {
            ProcessChange::Started { .. } => {
                replaced_or_lifecycle.insert(pid);
                if current_matches.contains(&pid) {
                    if let Some(event) = process_event(
                        WatchEventKind::Started,
                        pid,
                        current,
                        None,
                        current.process(pid).and_then(|process| process.parent),
                    ) {
                        events.push(event);
                    }
                }
            }
            ProcessChange::Exited { .. } => {
                replaced_or_lifecycle.insert(pid);
                if previous_matches.contains(&pid) {
                    if let Some(event) = process_event(
                        WatchEventKind::Exited,
                        pid,
                        previous,
                        previous.process(pid).and_then(|process| process.parent),
                        None,
                    ) {
                        events.push(event);
                    }
                }
            }
            ProcessChange::Reparented {
                old_parent,
                new_parent,
                ..
            } => {
                if previous_matches.contains(&pid) || current_matches.contains(&pid) {
                    if let Some(event) = process_event(
                        WatchEventKind::Reparented,
                        pid,
                        current,
                        old_parent,
                        new_parent,
                    ) {
                        events.push(event);
                    }
                }
            }
        }
    }

    let mut persistent: Vec<Pid> = previous
        .processes()
        .keys()
        .filter(|pid| current.processes().contains_key(pid))
        .filter(|pid| !replaced_or_lifecycle.contains(pid))
        .copied()
        .collect();
    persistent.sort_by_key(|pid| pid.as_u32());
    for pid in persistent {
        match (
            previous_matches.contains(&pid),
            current_matches.contains(&pid),
        ) {
            (false, true) => {
                if let Some(event) = process_event(
                    WatchEventKind::Matched,
                    pid,
                    current,
                    current.process(pid).and_then(|process| process.parent),
                    current.process(pid).and_then(|process| process.parent),
                ) {
                    events.push(event);
                }
            }
            (true, false) => {
                if let Some(event) = process_event(
                    WatchEventKind::Unmatched,
                    pid,
                    current,
                    current.process(pid).and_then(|process| process.parent),
                    current.process(pid).and_then(|process| process.parent),
                ) {
                    events.push(event);
                }
            }
            _ => {}
        }
    }
    events
}

fn watch_matches(snapshot: &ProcessSnapshot, query: &ProcessQuery) -> HashSet<Pid> {
    let mut matches = snapshot.matching_pid_set(query);
    matches.remove(&Pid::from_u32(std::process::id()));
    matches
}

#[derive(Debug, Serialize)]
struct JsonWatchRecord {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    sequence: u64,
    observed_at_unix_ms: u64,
    elapsed_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    query: Option<String>,
    interval_ms: u64,
    sample_index: usize,
    kind: &'static str,
    system_process_count: usize,
    matched_process_count: usize,
    emitted_process_event_count: Option<usize>,
    process: Option<JsonWatchProcess>,
    old_parent_pid: Option<u32>,
    new_parent_pid: Option<u32>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonWatchProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    path: String,
    command: String,
    user: String,
    status: String,
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    start_time_unix_seconds: u64,
    runtime_seconds: u64,
    subtree: JsonAggregate,
}

#[derive(Debug, Serialize)]
struct JsonAggregate {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

impl From<ResourceAggregate> for JsonAggregate {
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

impl From<&WatchEvent> for JsonWatchProcess {
    fn from(event: &WatchEvent) -> Self {
        let process = &event.process;
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: process.name.clone(),
            path: process_path(process),
            command: process_command_for_output(process),
            user: process.user.clone(),
            status: process.status.clone(),
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            read_bytes_per_second: process.read_rate,
            write_bytes_per_second: process.write_rate,
            start_time_unix_seconds: process.start_time,
            runtime_seconds: process.runtime,
            subtree: event.aggregate.into(),
        }
    }
}

struct RecordContext<'a> {
    query: &'a str,
    interval_ms: u64,
    started_at: Instant,
    hostname: &'a Option<String>,
}

struct RecordState<'a> {
    sequence: u64,
    sample_index: usize,
    kind: &'static str,
    snapshot: &'a ProcessSnapshot,
    matched_process_count: usize,
    emitted_process_event_count: Option<usize>,
    event: Option<&'a WatchEvent>,
}

fn json_record(context: &RecordContext<'_>, state: RecordState<'_>) -> JsonWatchRecord {
    JsonWatchRecord {
        schema: WATCH_SCHEMA,
        schema_version: WATCH_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, path, user, relationship, and resource information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        sequence: state.sequence,
        observed_at_unix_ms: unix_millis(),
        elapsed_ms: elapsed_millis(context.started_at.elapsed()),
        platform: platform_name(),
        hostname: context.hostname.clone(),
        query: (!context.query.is_empty()).then(|| context.query.to_string()),
        interval_ms: context.interval_ms,
        sample_index: state.sample_index,
        kind: state.kind,
        system_process_count: state.snapshot.real_process_count(),
        matched_process_count: state.matched_process_count,
        emitted_process_event_count: state.emitted_process_event_count,
        process: state.event.map(JsonWatchProcess::from),
        old_parent_pid: state
            .event
            .and_then(|event| event.old_parent.map(Pid::as_u32)),
        new_parent_pid: state
            .event
            .and_then(|event| event.new_parent.map(Pid::as_u32)),
    }
}

fn write_json_record<W: Write>(writer: &mut W, record: &JsonWatchRecord) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, record).map_err(io::Error::other)?;
    writer.write_all(b"\n")
}

fn write_table_header<W: Write>(
    writer: &mut W,
    query: &str,
    interval_ms: u64,
    snapshot: &ProcessSnapshot,
    matched: usize,
) -> io::Result<()> {
    writeln!(writer, "PSMORE PROCESS WATCH")?;
    writeln!(
        writer,
        "interval {interval_ms}ms  query {}  baseline {} process(es), {matched} matched",
        if query.is_empty() { "[all]" } else { query },
        snapshot.real_process_count(),
    )?;
    writeln!(
        writer,
        "ELAPSED    EVENT     PID     PPID   CPU%/TREE       MEM/TREE   PROCS NAME         COMMAND"
    )
}

fn write_table_event<W: Write>(
    writer: &mut W,
    elapsed: Duration,
    event: &WatchEvent,
) -> io::Result<()> {
    let process = &event.process;
    let relationship = if event.kind == WatchEventKind::Reparented {
        format!(
            " parent {}→{}",
            parent_label(event.old_parent),
            parent_label(event.new_parent)
        )
    } else {
        String::new()
    };
    writeln!(
        writer,
        "+{:>7.3}s  {:<8} {:>7} {:>7} {:>5.1}/{:<5.1} {:>9}/{:<9} {:>5} {:<12} {}{}",
        elapsed.as_secs_f64(),
        event.kind.table_label(),
        process.pid.as_u32(),
        process.parent.map(Pid::as_u32).unwrap_or(0),
        finite(process.cpu),
        finite(event.aggregate.cpu),
        human_bytes(process.memory),
        human_bytes(event.aggregate.memory),
        event.aggregate.process_count,
        sanitize_terminal_text(&process.name),
        sanitize_terminal_text(&process_command_for_output(process)),
        relationship,
    )
}

pub(crate) fn run_watch<W: Write>(
    writer: &mut W,
    query_input: &str,
    interval_ms: u64,
    count: Option<usize>,
    output: WatchOutput,
) -> io::Result<()> {
    let query = ProcessQuery::parse(query_input).map_err(io::Error::other)?;
    let started_at = Instant::now();
    let hostname = System::host_name();
    let context = RecordContext {
        query: query_input,
        interval_ms,
        started_at,
        hostname: &hostname,
    };
    let mut provider = NativeProcessProvider::new();
    let mut previous = ProcessSnapshot::build(provider.refresh(), interval_ms, unix_millis());
    let mut previous_matches = watch_matches(&previous, &query);
    match output {
        WatchOutput::Table => write_table_header(
            writer,
            query_input,
            interval_ms,
            &previous,
            previous_matches.len(),
        )?,
        WatchOutput::Jsonl => write_json_record(
            writer,
            &json_record(
                &context,
                RecordState {
                    sequence: 0,
                    sample_index: 0,
                    kind: "baseline",
                    snapshot: &previous,
                    matched_process_count: previous_matches.len(),
                    emitted_process_event_count: None,
                    event: None,
                },
            ),
        )?,
    }
    writer.flush()?;

    let mut sample_index = 0_usize;
    let mut sequence = 0_u64;
    let mut emitted_events = 0_usize;
    loop {
        if count.is_some_and(|count| sample_index >= count) {
            break;
        }
        thread::sleep(Duration::from_millis(interval_ms));
        sample_index += 1;
        let current = ProcessSnapshot::build(provider.refresh(), interval_ms, unix_millis());
        let current_matches = watch_matches(&current, &query);
        let events = events_between(&previous, &current, &previous_matches, &current_matches);
        for event in events {
            sequence = sequence.saturating_add(1);
            emitted_events = emitted_events.saturating_add(1);
            match output {
                WatchOutput::Table => {
                    write_table_event(writer, started_at.elapsed(), &event)?;
                }
                WatchOutput::Jsonl => write_json_record(
                    writer,
                    &json_record(
                        &context,
                        RecordState {
                            sequence,
                            sample_index,
                            kind: event.kind.label(),
                            snapshot: &current,
                            matched_process_count: current_matches.len(),
                            emitted_process_event_count: None,
                            event: Some(&event),
                        },
                    ),
                )?,
            }
        }
        writer.flush()?;
        previous = current;
        previous_matches = current_matches;
    }

    sequence = sequence.saturating_add(1);
    match output {
        WatchOutput::Table => writeln!(
            writer,
            "COMPLETE  {sample_index} refresh(es), {emitted_events} process event(s)"
        )?,
        WatchOutput::Jsonl => write_json_record(
            writer,
            &json_record(
                &context,
                RecordState {
                    sequence,
                    sample_index,
                    kind: "complete",
                    snapshot: &previous,
                    matched_process_count: previous_matches.len(),
                    emitted_process_event_count: Some(emitted_events),
                    event: None,
                },
            ),
        )?,
    }
    writer.flush()
}

fn parent_label(parent: Option<Pid>) -> String {
    parent
        .map(|pid| pid.as_u32().to_string())
        .unwrap_or_else(|| "-".into())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent: u32, name: &str, cpu: f32, start_time: u64) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: (pid != 0).then(|| Pid::from_u32(parent)),
            name: name.into(),
            command: format!("/srv/{name}\n--pid {pid}"),
            executable: format!("/srv/{name}"),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu,
            memory: 1024,
            read_rate: 0,
            write_rate: 0,
            start_time,
            runtime: 10,
            status: "Sleep".into(),
        }
    }

    fn snapshot(processes: Vec<ProcessInfo>) -> ProcessSnapshot {
        ProcessSnapshot::build(processes, 500, 1_700_000_000_000)
    }

    #[test]
    fn watch_detects_lifecycle_reparenting_and_query_transitions() {
        let previous = snapshot(vec![
            process(0, 0, "root", 0.0, 1),
            process(1, 0, "init", 0.0, 1),
            process(10, 1, "api", 5.0, 100),
            process(20, 1, "old", 30.0, 100),
            process(30, 1, "reused-old", 40.0, 100),
        ]);
        let current = snapshot(vec![
            process(0, 0, "root", 0.0, 1),
            process(1, 0, "init", 0.0, 1),
            process(2, 0, "other-parent", 0.0, 100),
            process(10, 2, "api", 50.0, 100),
            process(30, 1, "reused-new", 60.0, 101),
            process(40, 1, "new", 70.0, 100),
        ]);
        let query = ProcessQuery::parse("cpu>20").unwrap();
        let previous_matches = previous.matching_pid_set(&query);
        let current_matches = current.matching_pid_set(&query);
        let events = events_between(&previous, &current, &previous_matches, &current_matches);
        let kinds: Vec<(u32, WatchEventKind)> = events
            .iter()
            .map(|event| (event.process.pid.as_u32(), event.kind))
            .collect();
        assert!(kinds.contains(&(20, WatchEventKind::Exited)));
        assert!(kinds.contains(&(30, WatchEventKind::Exited)));
        assert!(kinds.contains(&(30, WatchEventKind::Started)));
        assert!(kinds.contains(&(40, WatchEventKind::Started)));
        assert!(kinds.contains(&(10, WatchEventKind::Reparented)));
        assert!(kinds.contains(&(10, WatchEventKind::Matched)));
        assert!(!kinds.contains(&(30, WatchEventKind::Matched)));
    }

    #[test]
    fn finite_watch_emits_versioned_baseline_and_complete_jsonl() {
        let mut output = Vec::new();
        run_watch(&mut output, "pid:999999", 100, Some(1), WatchOutput::Jsonl).unwrap();
        let lines: Vec<serde_json::Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.first().unwrap()["schema"], WATCH_SCHEMA);
        assert_eq!(lines.first().unwrap()["kind"], "baseline");
        assert_eq!(lines.last().unwrap()["kind"], "complete");
        assert_eq!(lines.last().unwrap()["sample_index"], 1);
        assert!(lines.last().unwrap()["emitted_process_event_count"].is_number());
    }
}
