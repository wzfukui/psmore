use std::cmp::Ordering;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    headless::{CurrentProcessExclusion, ProcessSnapshot, finite, human_bytes, human_rate},
    model::{
        HotspotMetric, HotspotScope, ProcessInfo, ResourceAggregate, process_command_for_output,
        process_path, sanitize_terminal_text,
    },
    provider::platform_name,
    query::ProcessQuery,
};

const TOP_SCHEMA: &str = "psmore.process-top";
const TOP_SCHEMA_VERSION: u32 = 1;

fn metric_label(metric: HotspotMetric) -> &'static str {
    match metric {
        HotspotMetric::Cpu => "cpu",
        HotspotMetric::Memory => "memory",
        HotspotMetric::Read => "read",
        HotspotMetric::Write => "write",
    }
}

fn scope_label(scope: HotspotScope) -> &'static str {
    match scope {
        HotspotScope::Process => "process",
        HotspotScope::Subtree => "tree",
    }
}

fn metric_unit(metric: HotspotMetric) -> &'static str {
    match metric {
        HotspotMetric::Cpu => "percent",
        HotspotMetric::Memory => "bytes",
        HotspotMetric::Read | HotspotMetric::Write => "bytes_per_second",
    }
}

fn compare_metric(
    metric: HotspotMetric,
    scope: HotspotScope,
    left_process: &ProcessInfo,
    left_tree: ResourceAggregate,
    right_process: &ProcessInfo,
    right_tree: ResourceAggregate,
) -> Ordering {
    match (metric, scope) {
        (HotspotMetric::Cpu, HotspotScope::Process) => {
            finite(right_process.cpu).total_cmp(&finite(left_process.cpu))
        }
        (HotspotMetric::Cpu, HotspotScope::Subtree) => {
            finite(right_tree.cpu).total_cmp(&finite(left_tree.cpu))
        }
        (HotspotMetric::Memory, HotspotScope::Process) => {
            right_process.memory.cmp(&left_process.memory)
        }
        (HotspotMetric::Memory, HotspotScope::Subtree) => right_tree.memory.cmp(&left_tree.memory),
        (HotspotMetric::Read, HotspotScope::Process) => {
            right_process.read_rate.cmp(&left_process.read_rate)
        }
        (HotspotMetric::Read, HotspotScope::Subtree) => {
            right_tree.read_rate.cmp(&left_tree.read_rate)
        }
        (HotspotMetric::Write, HotspotScope::Process) => {
            right_process.write_rate.cmp(&left_process.write_rate)
        }
        (HotspotMetric::Write, HotspotScope::Subtree) => {
            right_tree.write_rate.cmp(&left_tree.write_rate)
        }
    }
}

fn ranked_pids(
    snapshot: &ProcessSnapshot,
    query: &str,
    metric: HotspotMetric,
    scope: HotspotScope,
) -> Result<Vec<Pid>, String> {
    let query = ProcessQuery::parse(query)?;
    let collector = CurrentProcessExclusion::capture(snapshot);
    let mut pids: Vec<Pid> = collector
        .matching_pid_set(snapshot, &query)
        .into_iter()
        .collect();
    pids.sort_by(|left, right| {
        let Some(left_process) = snapshot.process(*left) else {
            return Ordering::Greater;
        };
        let Some(right_process) = snapshot.process(*right) else {
            return Ordering::Less;
        };
        compare_metric(
            metric,
            scope,
            left_process,
            collector.adjust_subtree(*left, snapshot.resource(*left)),
            right_process,
            collector.adjust_subtree(*right, snapshot.resource(*right)),
        )
        .then_with(|| {
            (left_process.name.to_lowercase(), left.as_u32())
                .cmp(&(right_process.name.to_lowercase(), right.as_u32()))
        })
    });
    Ok(pids)
}

fn limited_pids(pids: &[Pid], limit: Option<usize>) -> &[Pid] {
    &pids[..limit.unwrap_or(pids.len()).min(pids.len())]
}

#[derive(Debug, Serialize)]
struct JsonTop {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    sample_interval_ms: u64,
    collector_process_excluded: bool,
    query: Option<JsonQuery>,
    ranking: JsonRanking,
    system_process_count: usize,
    matched_process_count: usize,
    returned_process_count: usize,
    truncated: bool,
    items: Vec<JsonTopItem>,
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
struct JsonRanking {
    metric: &'static str,
    scope: &'static str,
    unit: &'static str,
    direction: &'static str,
    tie_breakers: [&'static str; 2],
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct JsonTopItem {
    rank: usize,
    ranking_value: JsonRankingValue,
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    status: String,
    path: String,
    command: String,
    own: JsonResources,
    subtree: JsonResources,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum JsonRankingValue {
    Percent(f32),
    Bytes(u64),
}

#[derive(Clone, Copy, Debug, Serialize)]
struct JsonResources {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

impl JsonResources {
    fn own(process: &ProcessInfo) -> Self {
        Self {
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            read_bytes_per_second: process.read_rate,
            write_bytes_per_second: process.write_rate,
            process_count: 1,
        }
    }

    fn subtree(resources: ResourceAggregate) -> Self {
        Self {
            cpu_percent: finite(resources.cpu),
            memory_bytes: resources.memory,
            read_bytes_per_second: resources.read_rate,
            write_bytes_per_second: resources.write_rate,
            process_count: resources.process_count,
        }
    }
}

fn ranking_value(
    metric: HotspotMetric,
    scope: HotspotScope,
    process: &ProcessInfo,
    subtree: ResourceAggregate,
) -> JsonRankingValue {
    match (metric, scope) {
        (HotspotMetric::Cpu, HotspotScope::Process) => {
            JsonRankingValue::Percent(finite(process.cpu))
        }
        (HotspotMetric::Cpu, HotspotScope::Subtree) => {
            JsonRankingValue::Percent(finite(subtree.cpu))
        }
        (HotspotMetric::Memory, HotspotScope::Process) => JsonRankingValue::Bytes(process.memory),
        (HotspotMetric::Memory, HotspotScope::Subtree) => JsonRankingValue::Bytes(subtree.memory),
        (HotspotMetric::Read, HotspotScope::Process) => JsonRankingValue::Bytes(process.read_rate),
        (HotspotMetric::Read, HotspotScope::Subtree) => JsonRankingValue::Bytes(subtree.read_rate),
        (HotspotMetric::Write, HotspotScope::Process) => {
            JsonRankingValue::Bytes(process.write_rate)
        }
        (HotspotMetric::Write, HotspotScope::Subtree) => {
            JsonRankingValue::Bytes(subtree.write_rate)
        }
    }
}

pub(crate) fn render_top_json(
    snapshot: &ProcessSnapshot,
    query: &str,
    metric: HotspotMetric,
    scope: HotspotScope,
    limit: Option<usize>,
) -> Result<String, String> {
    let pids = ranked_pids(snapshot, query, metric, scope)?;
    let collector = CurrentProcessExclusion::capture(snapshot);
    let visible = limited_pids(&pids, limit);
    let items = visible
        .iter()
        .enumerate()
        .filter_map(|(index, pid)| {
            let process = snapshot.process(*pid)?;
            let subtree = collector.adjust_subtree(*pid, snapshot.resource(*pid));
            Some(JsonTopItem {
                rank: index + 1,
                ranking_value: ranking_value(metric, scope, process, subtree),
                pid: pid.as_u32(),
                parent_pid: process.parent.map(Pid::as_u32),
                name: process.name.clone(),
                user: process.user.clone(),
                status: process.status.clone(),
                path: process_path(process),
                command: process_command_for_output(process),
                own: JsonResources::own(process),
                subtree: JsonResources::subtree(subtree),
            })
        })
        .collect();
    serde_json::to_string_pretty(&JsonTop {
        schema: TOP_SCHEMA,
        schema_version: TOP_SCHEMA_VERSION,
        privacy_notice: "May contain command lines, paths, user names, and host names; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: snapshot.generated_at_unix_ms(),
        platform: platform_name(),
        hostname: System::host_name(),
        sample_interval_ms: snapshot.sample_ms(),
        collector_process_excluded: true,
        query: (!query.is_empty()).then(|| JsonQuery {
            input: query.to_string(),
        }),
        ranking: JsonRanking {
            metric: metric_label(metric),
            scope: scope_label(scope),
            unit: metric_unit(metric),
            direction: "descending",
            tie_breakers: ["name_ascending", "pid_ascending"],
            limit,
        },
        system_process_count: snapshot.real_process_count(),
        matched_process_count: pids.len(),
        returned_process_count: visible.len(),
        truncated: visible.len() < pids.len(),
        items,
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_top_table(
    snapshot: &ProcessSnapshot,
    query: &str,
    metric: HotspotMetric,
    scope: HotspotScope,
    limit: Option<usize>,
) -> Result<String, String> {
    let pids = ranked_pids(snapshot, query, metric, scope)?;
    let collector = CurrentProcessExclusion::capture(snapshot);
    let visible = limited_pids(&pids, limit);
    let mut output = format!(
        "TOP {} / {}  matched {}, showing {}  sample {}ms\n",
        metric_label(metric).to_ascii_uppercase(),
        scope_label(scope).to_ascii_uppercase(),
        pids.len(),
        visible.len(),
        snapshot.sample_ms(),
    );
    if !query.is_empty() {
        output.push_str(&format!("query: {}\n", sanitize_terminal_text(query)));
    }
    output.push_str(
        " RANK     PID    PPID   CPU%  TCPU%       MEM      TMEM       R/s      TR/s       W/s      TW/s TPROCS USER         COMMAND\n",
    );
    for (index, pid) in visible.iter().enumerate() {
        let Some(process) = snapshot.process(*pid) else {
            continue;
        };
        let subtree = collector.adjust_subtree(*pid, snapshot.resource(*pid));
        output.push_str(&format!(
            "{:>5} {:>7} {:>7} {:>6.1} {:>6.1} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9} {:>6} {:<12} {}\n",
            index + 1,
            pid.as_u32(),
            process.parent.map(Pid::as_u32).unwrap_or(0),
            finite(process.cpu),
            finite(subtree.cpu),
            human_bytes(process.memory),
            human_bytes(subtree.memory),
            human_rate(process.read_rate),
            human_rate(subtree.read_rate),
            human_rate(process.write_rate),
            human_rate(subtree.write_rate),
            subtree.process_count,
            sanitize_terminal_text(&process.user),
            sanitize_terminal_text(&process_command_for_output(process)),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn process(
        pid: u32,
        parent: u32,
        name: &str,
        cpu: f32,
        memory: u64,
        read_rate: u64,
        write_rate: u64,
    ) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: (pid != 0).then(|| Pid::from_u32(parent)),
            name: name.into(),
            command: format!("/srv/{name} --pid {pid}"),
            executable: format!("/srv/{name}"),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu,
            memory,
            read_rate,
            write_rate,
            start_time: 100,
            runtime: 3_600,
            status: "Sleep".into(),
        }
    }

    fn snapshot() -> ProcessSnapshot {
        ProcessSnapshot::from_processes(
            vec![
                process(0, 0, "kernel / system", 0.0, 0, 0, 0),
                process(10, 0, "api", 5.0, 100, 1_000, 10),
                process(11, 10, "worker", 20.0, 50, 3_000, 30),
                process(20, 0, "cache", 5.0, 200, 2_000, 20),
            ],
            500,
        )
    }

    #[test]
    fn ranking_supports_own_and_subtree_metrics_with_stable_ties() {
        let snapshot = snapshot();
        let own = ranked_pids(&snapshot, "", HotspotMetric::Cpu, HotspotScope::Process).unwrap();
        assert_eq!(own, [11, 10, 20].map(Pid::from_u32));

        let tree = ranked_pids(&snapshot, "", HotspotMetric::Cpu, HotspotScope::Subtree).unwrap();
        assert_eq!(tree, [10, 11, 20].map(Pid::from_u32));

        let memory =
            ranked_pids(&snapshot, "", HotspotMetric::Memory, HotspotScope::Process).unwrap();
        assert_eq!(memory, [20, 10, 11].map(Pid::from_u32));
    }

    #[test]
    fn query_limit_and_json_contract_are_explicit() {
        let json = render_top_json(
            &snapshot(),
            "user:deploy",
            HotspotMetric::Read,
            HotspotScope::Process,
            Some(2),
        )
        .unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["schema"], TOP_SCHEMA);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["ranking"]["metric"], "read");
        assert_eq!(value["ranking"]["scope"], "process");
        assert_eq!(value["ranking"]["unit"], "bytes_per_second");
        assert_eq!(value["matched_process_count"], 3);
        assert_eq!(value["returned_process_count"], 2);
        assert_eq!(value["truncated"], true);
        assert_eq!(value["items"][0]["pid"], 11);
        assert_eq!(value["items"][0]["ranking_value"], 3_000);
        assert_eq!(value["items"][0]["rank"], 1);
    }

    #[test]
    fn table_explains_ranking_and_sanitizes_process_text() {
        let mut cache = process(20, 0, "cache", 5.0, 200, 2_000, 20);
        cache.command = "/srv/cache\n--unsafe\targ".into();
        let snapshot = ProcessSnapshot::from_processes(
            vec![process(0, 0, "kernel / system", 0.0, 0, 0, 0), cache],
            500,
        );
        let table = render_top_table(
            &snapshot,
            "name:cache",
            HotspotMetric::Memory,
            HotspotScope::Process,
            Some(10),
        )
        .unwrap();
        assert!(table.starts_with("TOP MEMORY / PROCESS"));
        assert!(table.contains("matched 1, showing 1"));
        assert!(table.contains("query: name:cache"));
        assert!(table.contains("/srv/cache --unsafe arg"));
    }

    #[test]
    fn collector_process_is_not_ranked() {
        let own_pid = std::process::id();
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                process(0, 0, "kernel / system", 0.0, 0, 0, 0),
                process(50, 0, "shell", 1.0, 10, 0, 0),
                process(own_pid, 50, "psmore", 100.0, 1_000, 0, 0),
                process(42, 50, "service", 2.0, 20, 0, 0),
            ],
            500,
        );
        let pids = ranked_pids(&snapshot, "", HotspotMetric::Cpu, HotspotScope::Process).unwrap();
        assert_eq!(pids, [42, 50].map(Pid::from_u32));

        let tree = ranked_pids(
            &snapshot,
            "tree.cpu>50",
            HotspotMetric::Cpu,
            HotspotScope::Subtree,
        )
        .unwrap();
        assert!(tree.is_empty());
        let children = ranked_pids(
            &snapshot,
            "children>=2",
            HotspotMetric::Cpu,
            HotspotScope::Subtree,
        )
        .unwrap();
        assert!(children.is_empty());
    }
}
