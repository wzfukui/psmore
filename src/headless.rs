use std::{
    collections::{HashMap, HashSet},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    app::aggregate_resources,
    model::{
        ProcessInfo, ResourceAggregate, process_command_for_output, process_path,
        sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
    query::ProcessQuery,
};

const SNAPSHOT_SCHEMA: &str = "psmore.process-snapshot";
const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

pub(crate) struct ProcessSnapshot {
    processes: HashMap<Pid, ProcessInfo>,
    children: HashMap<Option<Pid>, Vec<Pid>>,
    resources: HashMap<Pid, ResourceAggregate>,
    sample_ms: u64,
    generated_at_unix_ms: u64,
}

impl ProcessSnapshot {
    #[cfg(test)]
    pub(crate) fn from_processes(processes: Vec<ProcessInfo>, sample_ms: u64) -> Self {
        Self::build(processes, sample_ms, 1_700_000_000_000)
    }

    pub(crate) fn build(
        processes: Vec<ProcessInfo>,
        sample_ms: u64,
        generated_at_unix_ms: u64,
    ) -> Self {
        let processes: HashMap<Pid, ProcessInfo> = processes
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        let mut children: HashMap<Option<Pid>, Vec<Pid>> = HashMap::new();
        for process in processes.values() {
            children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        let resources = aggregate_resources(&processes, &children);
        Self {
            processes,
            children,
            resources,
            sample_ms,
            generated_at_unix_ms,
        }
    }

    pub(crate) fn process(&self, pid: Pid) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    pub(crate) fn processes(&self) -> &HashMap<Pid, ProcessInfo> {
        &self.processes
    }

    pub(crate) fn children_of(&self, pid: Pid) -> &[Pid] {
        self.children
            .get(&Some(pid))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub(crate) fn resource(&self, pid: Pid) -> ResourceAggregate {
        self.resources.get(&pid).copied().unwrap_or_default()
    }

    pub(crate) fn sample_ms(&self) -> u64 {
        self.sample_ms
    }

    pub(crate) fn generated_at_unix_ms(&self) -> u64 {
        self.generated_at_unix_ms
    }

    pub(crate) fn real_process_count(&self) -> usize {
        self.processes.len().saturating_sub(1)
    }

    pub(crate) fn matching_pid_set(&self, query: &ProcessQuery) -> HashSet<Pid> {
        let root = Pid::from_u32(0);
        self.processes
            .values()
            .filter(|process| process.pid != root)
            .filter(|process| {
                let subtree = self.resource(process.pid);
                let direct_children = self.children_of(process.pid).len();
                query.matches(process, subtree, direct_children)
            })
            .map(|process| process.pid)
            .collect()
    }
}

pub(crate) struct CurrentProcessExclusion {
    parent: Option<Pid>,
    subtree: ResourceAggregate,
    ancestors: HashSet<Pid>,
    collector_processes: HashSet<Pid>,
}

impl CurrentProcessExclusion {
    pub(crate) fn capture(snapshot: &ProcessSnapshot) -> Self {
        let pid = Pid::from_u32(std::process::id());
        let parent = snapshot.process(pid).and_then(|process| process.parent);
        let subtree = snapshot.resource(pid);
        let mut collector_processes = HashSet::new();
        let mut pending = vec![pid];
        while let Some(candidate) = pending.pop() {
            if !collector_processes.insert(candidate) {
                continue;
            }
            pending.extend_from_slice(snapshot.children_of(candidate));
        }
        let mut ancestors = HashSet::new();
        let mut current = Some(pid);
        while let Some(candidate) = current {
            if !ancestors.insert(candidate) {
                break;
            }
            current = snapshot
                .process(candidate)
                .and_then(|process| process.parent);
        }
        Self {
            parent,
            subtree,
            ancestors,
            collector_processes,
        }
    }

    pub(crate) fn adjust_subtree(
        &self,
        pid: Pid,
        mut resources: ResourceAggregate,
    ) -> ResourceAggregate {
        if self.ancestors.contains(&pid) {
            resources.cpu = (finite(resources.cpu) - finite(self.subtree.cpu)).max(0.0);
            resources.memory = resources.memory.saturating_sub(self.subtree.memory);
            resources.read_rate = resources.read_rate.saturating_sub(self.subtree.read_rate);
            resources.write_rate = resources.write_rate.saturating_sub(self.subtree.write_rate);
            resources.process_count = resources
                .process_count
                .saturating_sub(self.subtree.process_count);
        }
        resources
    }

    pub(crate) fn adjust_direct_children(&self, pid: Pid, count: usize) -> usize {
        if self.parent == Some(pid) {
            count.saturating_sub(1)
        } else {
            count
        }
    }

    pub(crate) fn matching_pid_set(
        &self,
        snapshot: &ProcessSnapshot,
        query: &ProcessQuery,
    ) -> HashSet<Pid> {
        let root = Pid::from_u32(0);
        snapshot
            .processes()
            .values()
            .filter(|process| {
                process.pid != root && !self.collector_processes.contains(&process.pid)
            })
            .filter(|process| {
                let subtree = self.adjust_subtree(process.pid, snapshot.resource(process.pid));
                let direct_children = self
                    .adjust_direct_children(process.pid, snapshot.children_of(process.pid).len());
                query.matches(process, subtree, direct_children)
            })
            .map(|process| process.pid)
            .collect()
    }
}

pub(crate) fn validate_query(query: &str) -> Result<(), String> {
    ProcessQuery::parse(query).map(|_| ())
}

pub(crate) fn capture_snapshot(sample_ms: u64) -> ProcessSnapshot {
    let mut provider = NativeProcessProvider::new();
    let _ = provider.refresh();
    thread::sleep(Duration::from_millis(sample_ms));
    let processes = provider.refresh();
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    ProcessSnapshot::build(processes, sample_ms, generated_at_unix_ms)
}

#[cfg(test)]
fn matching_pids(snapshot: &ProcessSnapshot, query: &str) -> Result<Vec<Pid>, String> {
    matching_pids_for_view(snapshot, query, None)
}

fn matching_pids_for_view(
    snapshot: &ProcessSnapshot,
    query: &str,
    collector: Option<&CurrentProcessExclusion>,
) -> Result<Vec<Pid>, String> {
    let query = ProcessQuery::parse(query)?;
    let matches = collector
        .map(|collector| collector.matching_pid_set(snapshot, &query))
        .unwrap_or_else(|| snapshot.matching_pid_set(&query));
    let mut pids: Vec<Pid> = matches.into_iter().collect();
    pids.sort_by_key(|pid| pid.as_u32());
    Ok(pids)
}

#[cfg(test)]
pub(crate) fn matching_process_count(
    snapshot: &ProcessSnapshot,
    query: &str,
) -> Result<usize, String> {
    matching_pids(snapshot, query).map(|pids| pids.len())
}

pub(crate) fn matching_process_count_excluding_collector(
    snapshot: &ProcessSnapshot,
    query: &str,
    collector: &CurrentProcessExclusion,
) -> Result<usize, String> {
    matching_pids_for_view(snapshot, query, Some(collector)).map(|pids| pids.len())
}

#[derive(Debug, Serialize)]
struct JsonSnapshot {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    sample_interval_ms: u64,
    query: Option<JsonQuery>,
    system_process_count: usize,
    matched_process_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    collector_process_excluded: Option<bool>,
    processes: Vec<JsonProcess>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonQuery {
    input: String,
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
    direct_child_count: usize,
    subtree: JsonAggregate,
}

#[derive(Clone, Copy, Debug, Serialize)]
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

pub(crate) fn render_json(snapshot: &ProcessSnapshot, query: &str) -> Result<String, String> {
    render_json_for_view(snapshot, query, None)
}

fn render_json_for_view(
    snapshot: &ProcessSnapshot,
    query: &str,
    collector: Option<&CurrentProcessExclusion>,
) -> Result<String, String> {
    let pids = matching_pids_for_view(snapshot, query, collector)?;
    let processes = pids
        .iter()
        .filter_map(|pid| {
            let process = snapshot.processes.get(pid)?;
            let subtree = collector
                .map(|collector| collector.adjust_subtree(*pid, snapshot.resource(*pid)))
                .unwrap_or_else(|| snapshot.resource(*pid));
            let direct_child_count = collector
                .map(|collector| {
                    collector.adjust_direct_children(*pid, snapshot.children_of(*pid).len())
                })
                .unwrap_or_else(|| snapshot.children_of(*pid).len());
            Some(JsonProcess {
                pid: pid.as_u32(),
                parent_pid: process.parent.map(Pid::as_u32),
                name: process.name.clone(),
                path: process_path(process),
                command: process_command_for_output(process),
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
                direct_child_count,
                subtree: subtree.into(),
            })
        })
        .collect();
    let output = JsonSnapshot {
        schema: SNAPSHOT_SCHEMA,
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        privacy_notice: "May contain command lines, paths, user names, and host names; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: snapshot.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        sample_interval_ms: snapshot.sample_ms,
        query: (!query.is_empty()).then(|| JsonQuery {
            input: query.to_string(),
        }),
        system_process_count: snapshot.processes.len().saturating_sub(1),
        matched_process_count: pids.len(),
        collector_process_excluded: collector.map(|_| true),
        processes,
    };
    serde_json::to_string_pretty(&output).map_err(|error| error.to_string())
}

pub(crate) fn render_table(snapshot: &ProcessSnapshot, query: &str) -> Result<String, String> {
    render_table_for_view(snapshot, query, None)
}

fn render_table_for_view(
    snapshot: &ProcessSnapshot,
    query: &str,
    collector: Option<&CurrentProcessExclusion>,
) -> Result<String, String> {
    let pids = matching_pids_for_view(snapshot, query, collector)?;
    let mut output = String::from(
        "    PID    PPID   CPU%       MEM  TCPU%      TMEM TPROCS       R/s       W/s USER         STATE        COMMAND\n",
    );
    for pid in pids {
        let Some(process) = snapshot.processes.get(&pid) else {
            continue;
        };
        let subtree = collector
            .map(|collector| collector.adjust_subtree(pid, snapshot.resource(pid)))
            .unwrap_or_else(|| snapshot.resource(pid));
        output.push_str(&format!(
            "{:>7} {:>7} {:>6.1} {:>9} {:>6.1} {:>9} {:>6} {:>9} {:>9} {:<12} {:<12} {}\n",
            pid.as_u32(),
            process.parent.map(Pid::as_u32).unwrap_or(0),
            finite(process.cpu),
            human_bytes(process.memory),
            finite(subtree.cpu),
            human_bytes(subtree.memory),
            subtree.process_count,
            human_rate(process.read_rate),
            human_rate(process.write_rate),
            sanitize_terminal_text(&process.user),
            sanitize_terminal_text(&process.status),
            sanitize_terminal_text(&process_command_for_output(process)),
        ));
    }
    Ok(output)
}

#[derive(Debug, Serialize)]
struct JsonCheckResult {
    schema: &'static str,
    schema_version: u32,
    passed: bool,
    expectation: String,
    query: String,
    matched_process_count: usize,
    collector_process_excluded: bool,
    evaluation: CheckObservation,
    snapshot: serde_json::Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct CheckObservation {
    pub(crate) attempts: usize,
    pub(crate) required_consecutive_passes: usize,
    pub(crate) consecutive_passes: usize,
    pub(crate) wait_timeout_ms: Option<u64>,
    pub(crate) elapsed_ms: u64,
    pub(crate) timed_out: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CheckStability {
    required: usize,
    attempts: usize,
    consecutive_passes: usize,
}

impl CheckStability {
    pub(crate) fn new(required: usize) -> Self {
        Self {
            required: required.max(1),
            attempts: 0,
            consecutive_passes: 0,
        }
    }

    pub(crate) fn record(&mut self, passed: bool) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        self.consecutive_passes = if passed {
            self.consecutive_passes.saturating_add(1)
        } else {
            0
        };
        self.consecutive_passes >= self.required
    }

    pub(crate) fn observation(
        self,
        wait_timeout_ms: Option<u64>,
        elapsed_ms: u64,
        timed_out: bool,
    ) -> CheckObservation {
        CheckObservation {
            attempts: self.attempts,
            required_consecutive_passes: self.required,
            consecutive_passes: self.consecutive_passes,
            wait_timeout_ms,
            elapsed_ms,
            timed_out,
        }
    }
}

pub(crate) fn render_check_json(
    snapshot: &ProcessSnapshot,
    collector: &CurrentProcessExclusion,
    query: &str,
    expectation: &str,
    matched: usize,
    passed: bool,
    observation: CheckObservation,
) -> Result<String, String> {
    let snapshot = serde_json::from_str(&render_json_for_view(snapshot, query, Some(collector))?)
        .map_err(|error| error.to_string())?;
    serde_json::to_string_pretty(&JsonCheckResult {
        schema: "psmore.check-result",
        schema_version: 1,
        passed,
        expectation: expectation.to_string(),
        query: query.to_string(),
        matched_process_count: matched,
        collector_process_excluded: true,
        evaluation: observation,
        snapshot,
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_check_table(
    snapshot: &ProcessSnapshot,
    collector: &CurrentProcessExclusion,
    query: &str,
    expectation: &str,
    matched: usize,
    passed: bool,
    observation: CheckObservation,
) -> Result<String, String> {
    let status = if passed { "PASS" } else { "FAIL" };
    let timeout = observation
        .wait_timeout_ms
        .map(|milliseconds| format!(", timeout {milliseconds}ms"))
        .unwrap_or_default();
    let mut output = format!(
        "CHECK {status}  expected {expectation}; matched {matched} process(es)\nquery: {query}\nevaluation: {} attempt(s), stable {}/{}, elapsed {}ms{timeout}{}; collector excluded\n",
        observation.attempts,
        observation.consecutive_passes,
        observation.required_consecutive_passes,
        observation.elapsed_ms,
        if observation.timed_out {
            " (timeout reached)"
        } else {
            ""
        },
    );
    if matched > 0 {
        output.push('\n');
        output.push_str(&render_table_for_view(snapshot, query, Some(collector))?);
    }
    Ok(output)
}

pub(crate) fn finite(value: f32) -> f32 {
    if value.is_finite() { value } else { 0.0 }
}

pub(crate) fn human_rate(value: u64) -> String {
    format!("{}/s", human_bytes(value))
}

pub(crate) fn human_bytes(value: u64) -> String {
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
    use serde_json::Value;

    fn process(pid: u32, parent: u32, name: &str, memory: u64) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: (pid != 0).then(|| Pid::from_u32(parent)),
            name: name.into(),
            command: format!("/srv/{name} --pid {pid}"),
            executable: format!("/srv/{name}"),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: pid as f32,
            memory,
            read_rate: pid as u64 * 1024,
            write_rate: 0,
            start_time: 100,
            runtime: 3_600,
            status: "Sleep".into(),
        }
    }

    fn snapshot() -> ProcessSnapshot {
        ProcessSnapshot::from_processes(
            vec![
                process(0, 0, "kernel / system", 0),
                process(10, 0, "api", 100 * 1024 * 1024),
                process(11, 10, "worker", 50 * 1024 * 1024),
                process(20, 0, "cache", 25 * 1024 * 1024),
            ],
            500,
        )
    }

    #[test]
    fn json_snapshot_is_versioned_filtered_and_keeps_subtree_context() {
        let json = render_json(&snapshot(), "name:api tree.procs>=2").unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schema"], SNAPSHOT_SCHEMA);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["sample_interval_ms"], 500);
        assert_eq!(value["system_process_count"], 3);
        assert_eq!(value["matched_process_count"], 1);
        assert_eq!(value["processes"][0]["pid"], 10);
        assert_eq!(value["processes"][0]["direct_child_count"], 1);
        assert_eq!(value["processes"][0]["subtree"]["process_count"], 2);
        assert_eq!(
            value["processes"][0]["subtree"]["memory_bytes"],
            150 * 1024 * 1024
        );
    }

    #[test]
    fn table_snapshot_is_pid_stable_and_sanitizes_process_text() {
        let mut snapshot = snapshot();
        snapshot
            .processes
            .get_mut(&Pid::from_u32(11))
            .unwrap()
            .command = "/srv/worker\n--unsafe\targument".into();
        let table = render_table(&snapshot, "user:deploy").unwrap();
        let rows: Vec<&str> = table.lines().collect();
        assert!(rows[0].contains("TCPU%"));
        assert!(rows[1].contains("     10"));
        assert!(rows[2].contains("     11"));
        assert!(rows[3].contains("     20"));
        assert!(rows[2].contains("/srv/worker --unsafe argument"));
    }

    #[test]
    fn health_check_outputs_are_explicit_and_machine_readable() {
        let snapshot = snapshot();
        let collector = CurrentProcessExclusion::capture(&snapshot);
        let matched = matching_process_count(&snapshot, "name:api").unwrap();
        assert_eq!(matched, 1);
        let observation = CheckObservation {
            attempts: 3,
            required_consecutive_passes: 2,
            consecutive_passes: 0,
            wait_timeout_ms: Some(2_000),
            elapsed_ms: 2_001,
            timed_out: true,
        };
        let table = render_check_table(
            &snapshot,
            &collector,
            "name:api",
            "no matches",
            matched,
            false,
            observation,
        )
        .expect("render check table");
        assert!(table.starts_with("CHECK FAIL"));
        assert!(table.contains("3 attempt(s), stable 0/2"));
        assert!(table.contains("timeout reached"));
        assert!(table.contains("collector excluded"));
        assert!(table.contains("/srv/api --pid 10"));

        let json: Value = serde_json::from_str(
            &render_check_json(
                &snapshot,
                &collector,
                "name:api",
                "no matches",
                matched,
                false,
                observation,
            )
            .expect("render check JSON"),
        )
        .unwrap();
        assert_eq!(json["schema"], "psmore.check-result");
        assert_eq!(json["passed"], false);
        assert_eq!(json["matched_process_count"], 1);
        assert_eq!(json["collector_process_excluded"], true);
        assert_eq!(json["evaluation"]["attempts"], 3);
        assert_eq!(json["evaluation"]["timed_out"], true);
        assert_eq!(json["snapshot"]["collector_process_excluded"], true);
        assert_eq!(json["snapshot"]["processes"][0]["pid"], 10);
    }

    #[test]
    fn health_check_excludes_its_collector_and_its_ancestor_resource_contribution() {
        let collector_pid = std::process::id();
        let collector_child_pid = collector_pid.saturating_add(1);
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                process(0, 0, "kernel / system", 0),
                process(10, 0, "api", 100 * 1024 * 1024),
                process(11, 10, "worker", 50 * 1024 * 1024),
                process(collector_pid, 10, "psmore", 25 * 1024 * 1024),
                process(
                    collector_child_pid,
                    collector_pid,
                    "collector-helper",
                    5 * 1024 * 1024,
                ),
            ],
            500,
        );
        let collector = CurrentProcessExclusion::capture(&snapshot);

        assert_eq!(
            matching_process_count_excluding_collector(&snapshot, "name:psmore", &collector)
                .unwrap(),
            0
        );
        assert_eq!(
            matching_process_count_excluding_collector(
                &snapshot,
                "name:collector-helper",
                &collector,
            )
            .unwrap(),
            0
        );
        assert_eq!(
            matching_process_count_excluding_collector(
                &snapshot,
                "name:api tree.procs=2 children=1 tree.mem=150m",
                &collector,
            )
            .unwrap(),
            1
        );
        let json: Value = serde_json::from_str(
            &render_json_for_view(&snapshot, "name:api", Some(&collector)).unwrap(),
        )
        .unwrap();
        assert_eq!(json["processes"][0]["direct_child_count"], 1);
        assert_eq!(json["processes"][0]["subtree"]["process_count"], 2);
        assert_eq!(
            json["processes"][0]["subtree"]["memory_bytes"],
            150 * 1024 * 1024
        );
    }

    #[test]
    fn check_stability_requires_consecutive_passing_samples() {
        let mut stability = CheckStability::new(3);
        assert!(!stability.record(true));
        assert!(!stability.record(true));
        assert!(!stability.record(false));
        assert!(!stability.record(true));
        assert!(!stability.record(true));
        assert!(stability.record(true));
        assert_eq!(
            stability.observation(Some(10_000), 4_200, false),
            CheckObservation {
                attempts: 6,
                required_consecutive_passes: 3,
                consecutive_passes: 3,
                wait_timeout_ms: Some(10_000),
                elapsed_ms: 4_200,
                timed_out: false,
            }
        );
    }
}
