use std::{
    collections::{HashMap, HashSet},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use sysinfo::Pid;
use unicode_width::UnicodeWidthStr;

use crate::{
    actions::{
        ProcessActionDialog, ProcessActionDialogMode, ProcessActionKind, ProcessActionOutcome,
        ProcessActionRecord, ProcessActionTarget, execute_process_action,
    },
    cli::{LogPriority, LogScope},
    filters::{CompiledProcessFilters, FilterAction, ProcessFilterRule},
    headless_exe::{capture_executable, render_executable_json, render_executable_table},
    headless_explain::{
        ExplainOptions, capture_dossier, render_dossier_json, render_dossier_summary_table,
    },
    headless_logs::{capture_logs, render_logs_json, render_logs_table},
    headless_memory::{capture_memory, render_memory_json, render_memory_table},
    headless_service::{capture_service_context, render_service_json, render_service_table},
    history::ResourceHistory,
    i18n::{UiLanguage, text},
    inspection::inspect_process,
    model::{
        AttentionFinding, AttentionSeverity, ChangeSummary, HotspotMetric, HotspotScope,
        MarqueePhase, ProcessChange, ProcessEvent, ProcessInfo, ProcessInspection,
        ResourceAggregate, SortMode, StatusNotice, TreeRow, TrendView, diff_processes,
        process_path,
    },
    network::{NetworkScan, NetworkScope, scan_network},
    onboarding::{Guidance, GuidanceOverlay},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
    query::ProcessQuery,
    report::{ReportInput, export_report},
    snapshot::BaselineSnapshot,
};

pub(crate) fn aggregate_resources(
    processes: &HashMap<Pid, ProcessInfo>,
    children: &HashMap<Option<Pid>, Vec<Pid>>,
) -> HashMap<Pid, ResourceAggregate> {
    fn visit(
        pid: Pid,
        processes: &HashMap<Pid, ProcessInfo>,
        children: &HashMap<Option<Pid>, Vec<Pid>>,
        cache: &mut HashMap<Pid, ResourceAggregate>,
        visiting: &mut HashSet<Pid>,
    ) -> ResourceAggregate {
        if let Some(total) = cache.get(&pid) {
            return *total;
        }
        if !visiting.insert(pid) {
            return ResourceAggregate::default();
        }
        let mut total = processes
            .get(&pid)
            .map(|process| ResourceAggregate {
                cpu: process.cpu,
                memory: process.memory,
                read_rate: process.read_rate,
                write_rate: process.write_rate,
                process_count: usize::from(pid.as_u32() != 0),
            })
            .unwrap_or_default();
        if let Some(descendants) = children.get(&Some(pid)) {
            for child in descendants {
                if *child != pid {
                    total.add(visit(*child, processes, children, cache, visiting));
                }
            }
        }
        visiting.remove(&pid);
        cache.insert(pid, total);
        total
    }

    let mut resources = HashMap::with_capacity(processes.len());
    let mut visiting = HashSet::new();
    let mut pids: Vec<Pid> = processes.keys().copied().collect();
    pids.sort_by_key(|pid| pid.as_u32());
    for pid in pids {
        visit(pid, processes, children, &mut resources, &mut visiting);
    }
    resources
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    fn process(pid: u32, parent: Option<u32>, name: &str, executable: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: parent.map(Pid::from_u32),
            name: name.into(),
            command: executable.into(),
            executable: executable.into(),
            user: "joe".into(),
            cwd: "/".into(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: 1,
            runtime: 1,
            status: "Sleep".into(),
        }
    }

    #[test]
    fn persistent_filters_run_before_search_and_keep_only_required_ancestors() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.processes = [
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
            process(
                10,
                Some(1),
                "ChatGPT",
                "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
            ),
            process(
                11,
                Some(10),
                "Helper",
                "/Applications/ChatGPT.app/Contents/MacOS/Helper",
            ),
            process(12, Some(1), "node", "/opt/homebrew/bin/node"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = [0, 1, 10, 11, 12].into_iter().map(Pid::from_u32).collect();
        app.process_filters = vec![
            ProcessFilterRule {
                action: FilterAction::Include,
                expression: "path:/Applications".into(),
                enabled: true,
            },
            ProcessFilterRule {
                action: FilterAction::Exclude,
                expression: "name~^Helper$".into(),
                enabled: true,
            },
        ];
        app.search.clear();
        app.rebuild_visible();

        assert_eq!(app.filtered_processes, 1);
        assert_eq!(
            app.visible
                .iter()
                .map(|row| row.pid.as_u32())
                .collect::<Vec<_>>(),
            vec![0, 1, 10]
        );

        app.search = "name:node".into();
        app.rebuild_visible();
        assert_eq!(app.search_matches, 0);
        assert!(app.visible.is_empty());

        app.search = "name:ChatGPT".into();
        app.rebuild_visible();
        assert_eq!(app.search_matches, 1);
        assert_eq!(
            app.visible
                .iter()
                .map(|row| row.pid.as_u32())
                .collect::<Vec<_>>(),
            vec![0, 1, 10]
        );
    }
}

pub(crate) fn sort_processes(
    pids: &mut [Pid],
    mode: SortMode,
    processes: &HashMap<Pid, ProcessInfo>,
    resources: &HashMap<Pid, ResourceAggregate>,
) {
    pids.sort_by(|left, right| {
        let left_resource = resources.get(left).copied().unwrap_or_default();
        let right_resource = resources.get(right).copied().unwrap_or_default();
        let hot_order = match mode {
            SortMode::Stable => std::cmp::Ordering::Equal,
            SortMode::SubtreeCpu => right_resource.cpu.total_cmp(&left_resource.cpu),
            SortMode::SubtreeMemory => right_resource.memory.cmp(&left_resource.memory),
            SortMode::SubtreeRead => right_resource.read_rate.cmp(&left_resource.read_rate),
            SortMode::SubtreeWrite => right_resource.write_rate.cmp(&left_resource.write_rate),
        };
        hot_order.then_with(|| {
            let left_name = processes
                .get(left)
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            let right_name = processes
                .get(right)
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            (left_name, left.as_u32()).cmp(&(right_name, right.as_u32()))
        })
    });
}

pub(crate) fn rank_hotspots(
    processes: &HashMap<Pid, ProcessInfo>,
    resources: &HashMap<Pid, ResourceAggregate>,
    metric: HotspotMetric,
    scope: HotspotScope,
) -> Vec<Pid> {
    let root = Pid::from_u32(0);
    let mut pids: Vec<Pid> = processes
        .keys()
        .filter(|pid| **pid != root)
        .copied()
        .collect();
    pids.sort_by(|left, right| {
        let left_process = processes.get(left);
        let right_process = processes.get(right);
        let left_tree = resources.get(left).copied().unwrap_or_default();
        let right_tree = resources.get(right).copied().unwrap_or_default();
        let metric_order = match (metric, scope) {
            (HotspotMetric::Cpu, HotspotScope::Process) => right_process
                .map(|process| process.cpu)
                .unwrap_or_default()
                .total_cmp(&left_process.map(|process| process.cpu).unwrap_or_default()),
            (HotspotMetric::Cpu, HotspotScope::Subtree) => right_tree.cpu.total_cmp(&left_tree.cpu),
            (HotspotMetric::Memory, HotspotScope::Process) => right_process
                .map(|process| process.memory)
                .unwrap_or_default()
                .cmp(
                    &left_process
                        .map(|process| process.memory)
                        .unwrap_or_default(),
                ),
            (HotspotMetric::Memory, HotspotScope::Subtree) => {
                right_tree.memory.cmp(&left_tree.memory)
            }
            (HotspotMetric::Read, HotspotScope::Process) => right_process
                .map(|process| process.read_rate)
                .unwrap_or_default()
                .cmp(
                    &left_process
                        .map(|process| process.read_rate)
                        .unwrap_or_default(),
                ),
            (HotspotMetric::Read, HotspotScope::Subtree) => {
                right_tree.read_rate.cmp(&left_tree.read_rate)
            }
            (HotspotMetric::Write, HotspotScope::Process) => right_process
                .map(|process| process.write_rate)
                .unwrap_or_default()
                .cmp(
                    &left_process
                        .map(|process| process.write_rate)
                        .unwrap_or_default(),
                ),
            (HotspotMetric::Write, HotspotScope::Subtree) => {
                right_tree.write_rate.cmp(&left_tree.write_rate)
            }
        };
        metric_order.then_with(|| {
            let left_name = left_process
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            let right_name = right_process
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            (left_name, left.as_u32()).cmp(&(right_name, right.as_u32()))
        })
    });
    pids
}

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const ATTENTION_ACTIVITY_SAMPLES: usize = 5;
const ATTENTION_GROWTH_SAMPLES: usize = 30;
const ATTENTION_CHURN_WINDOW: Duration = Duration::from_secs(60);

fn attention_bytes(value: u64) -> String {
    if value >= GIB {
        format!("{:.1} GiB", value as f64 / GIB as f64)
    } else {
        format!("{:.1} MiB", value as f64 / MIB as f64)
    }
}

fn attention_rate(value: u64) -> String {
    format!("{}/s", attention_bytes(value))
}

pub(crate) fn rank_attention_findings(
    processes: &HashMap<Pid, ProcessInfo>,
    history: &ResourceHistory,
    events: &[ProcessEvent],
) -> Vec<AttentionFinding> {
    let mut churn: HashMap<String, (HashSet<Pid>, HashSet<Pid>)> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event.observed_at.elapsed() <= ATTENTION_CHURN_WINDOW)
    {
        match &event.change {
            ProcessChange::Started { pid, command, .. } => {
                churn
                    .entry(command.to_lowercase())
                    .or_default()
                    .0
                    .insert(*pid);
            }
            ProcessChange::Exited { pid, command, .. } => {
                churn
                    .entry(command.to_lowercase())
                    .or_default()
                    .1
                    .insert(*pid);
            }
            ProcessChange::Reparented { .. } => {}
        }
    }
    let mut churn_representatives: HashMap<String, Pid> = HashMap::new();
    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0)
    {
        let identity = crate::model::process_command_line(process).to_lowercase();
        churn_representatives
            .entry(identity)
            .and_modify(|pid| {
                if process.pid.as_u32() < pid.as_u32() {
                    *pid = process.pid;
                }
            })
            .or_insert(process.pid);
    }

    let mut findings = Vec::new();
    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0)
    {
        let mut reasons = Vec::new();
        let mut score = 0_u16;
        let status = process.status.trim();
        let normalized_status = status.to_lowercase();
        let state_is_critical = normalized_status == "z"
            || normalized_status.starts_with("zombie")
            || normalized_status.starts_with("dead");
        if state_is_critical {
            score = 100;
            reasons.push(format!("unhealthy process state: {status}"));
        } else if normalized_status == "t"
            || normalized_status.starts_with('t')
            || normalized_status.contains("stop")
        {
            score = score.saturating_add(70);
            reasons.push(format!("stopped or traced process state: {status}"));
        }

        let process_identity = crate::model::process_command_line(process).to_lowercase();
        let represents_identity =
            churn_representatives.get(&process_identity) == Some(&process.pid);
        if let Some((started_pids, exited_pids)) = churn
            .get(&process_identity)
            .filter(|(started, exited)| started.len() >= 2 && exited.len() >= 2)
            .filter(|_| represents_identity)
        {
            let starts = started_pids.len();
            let exits = exited_pids.len();
            let cycles = starts.min(exits);
            score = score.saturating_add(if cycles >= 10 {
                60
            } else if cycles >= 4 {
                35
            } else {
                25
            });
            reasons.push(format!(
                "lifecycle churn: {starts} distinct starts / {exits} exits in 60s"
            ));
        }

        let samples = history.samples(process.pid);
        let activity: Vec<_> = samples
            .into_iter()
            .flat_map(|samples| samples.iter().rev().take(ATTENTION_ACTIVITY_SAMPLES))
            .collect();
        let sample_count = activity.len();
        let (average_cpu, average_read, average_write) = if sample_count > 0 {
            let count = sample_count as f64;
            (
                activity
                    .iter()
                    .map(|sample| f64::from(sample.own_cpu))
                    .sum::<f64>()
                    / count,
                activity
                    .iter()
                    .map(|sample| sample.own_read_rate as u128)
                    .sum::<u128>()
                    / sample_count as u128,
                activity
                    .iter()
                    .map(|sample| sample.own_write_rate as u128)
                    .sum::<u128>()
                    / sample_count as u128,
            )
        } else {
            (
                f64::from(process.cpu),
                u128::from(process.read_rate),
                u128::from(process.write_rate),
            )
        };
        let average_read = average_read.min(u128::from(u64::MAX)) as u64;
        let average_write = average_write.min(u128::from(u64::MAX)) as u64;
        let cpu_is_sustained = sample_count >= 3;
        let report_cpu = if cpu_is_sustained {
            average_cpu
        } else {
            f64::from(process.cpu)
        };
        if report_cpu >= 25.0 {
            score = score.saturating_add(if report_cpu >= 80.0 {
                45
            } else if report_cpu >= 50.0 {
                30
            } else {
                20
            });
            reasons.push(if cpu_is_sustained {
                format!(
                    "sustained CPU {average_cpu:.1}% avg (now {:.1}%)",
                    process.cpu
                )
            } else {
                format!("CPU {:.1}% in the current sample", process.cpu)
            });
        }

        if process.memory >= 512 * MIB {
            score = score.saturating_add(if process.memory >= 4 * GIB {
                35
            } else if process.memory >= GIB {
                20
            } else {
                10
            });
            reasons.push(format!(
                "memory footprint {}",
                attention_bytes(process.memory)
            ));
        }

        let memory_window = samples.and_then(|samples| {
            let newest = samples.back()?;
            let oldest = samples.get(samples.len().saturating_sub(ATTENTION_GROWTH_SAMPLES))?;
            Some((newest, oldest))
        });
        let memory_growth = memory_window.and_then(|(newest, oldest)| {
            let growth = newest.own_memory.saturating_sub(oldest.own_memory);
            let meaningful_ratio = oldest.own_memory >= 32 * MIB
                && newest.own_memory >= oldest.own_memory.saturating_add(oldest.own_memory / 5);
            if growth >= 128 * MIB && meaningful_ratio {
                Some((newest, oldest, growth))
            } else {
                None
            }
        });
        if let Some((newest, oldest, growth)) = memory_growth {
            score = score.saturating_add(if growth >= 512 * MIB { 45 } else { 25 });
            let elapsed = newest
                .observed_at
                .saturating_duration_since(oldest.observed_at)
                .as_secs();
            reasons.push(format!(
                "memory grew {} in {}s",
                attention_bytes(growth),
                elapsed.max(1)
            ));
        }

        for (label, rate) in [("read", average_read), ("write", average_write)] {
            if rate < MIB {
                continue;
            }
            score = score.saturating_add(if rate >= 100 * MIB {
                35
            } else if rate >= 10 * MIB {
                20
            } else {
                10
            });
            reasons.push(format!("{label} I/O {} avg", attention_rate(rate)));
        }

        if reasons.is_empty() {
            continue;
        }
        let score = score.min(100);
        let severity = if state_is_critical || score >= 80 {
            AttentionSeverity::Critical
        } else if score >= 40 {
            AttentionSeverity::Warning
        } else {
            AttentionSeverity::Watch
        };
        findings.push(AttentionFinding {
            pid: process.pid,
            severity,
            score,
            reasons,
        });
    }
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.score.cmp(&left.score))
            .then_with(|| {
                let left_name = processes
                    .get(&left.pid)
                    .map(|process| process.name.to_lowercase())
                    .unwrap_or_default();
                let right_name = processes
                    .get(&right.pid)
                    .map(|process| process.name.to_lowercase())
                    .unwrap_or_default();
                (left_name, left.pid.as_u32()).cmp(&(right_name, right.pid.as_u32()))
            })
    });
    findings
}

struct NetworkTask {
    receiver: Receiver<NetworkScan>,
    started_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum InspectionTab {
    #[default]
    Overview,
    Threads,
    Ports,
    Files,
}

impl InspectionTab {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Threads => 1,
            Self::Ports => 2,
            Self::Files => 3,
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::Overview => Self::Threads,
            Self::Threads => Self::Ports,
            Self::Ports => Self::Files,
            Self::Files => Self::Overview,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Overview => Self::Files,
            Self::Threads => Self::Overview,
            Self::Ports => Self::Threads,
            Self::Files => Self::Ports,
        }
    }
}

struct InspectionTask {
    receiver: Receiver<ProcessInspection>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct ServiceContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct ExecutableContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct MemoryContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct LogsContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct DossierContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ServiceContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutableContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
    pub(crate) hash: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct LogsContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
    pub(crate) scope: LogScope,
    pub(crate) priority: LogPriority,
    pub(crate) since_seconds: u64,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct DossierContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
    pub(crate) include_logs: bool,
    pub(crate) hash: bool,
    pub(crate) scope: LogScope,
    pub(crate) priority: LogPriority,
    pub(crate) since_seconds: u64,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct FilterEditor {
    pub(crate) action: FilterAction,
    pub(crate) input: String,
    pub(crate) error: Option<String>,
    pub(crate) editing_index: Option<usize>,
    enabled: bool,
}

struct TreeSelection<'a> {
    matched: &'a HashSet<Pid>,
    allowed: &'a HashSet<Pid>,
    restricted: bool,
    filter_applied: bool,
    search_active: bool,
}

pub(crate) struct App {
    pub(crate) provider: NativeProcessProvider,
    pub(crate) processes: HashMap<Pid, ProcessInfo>,
    pub(crate) children: HashMap<Option<Pid>, Vec<Pid>>,
    pub(crate) resources: HashMap<Pid, ResourceAggregate>,
    pub(crate) history: ResourceHistory,
    pub(crate) trend_pid: Option<Pid>,
    pub(crate) trend_view: TrendView,
    pub(crate) show_hotspots: bool,
    pub(crate) hotspot_metric: HotspotMetric,
    pub(crate) hotspot_scope: HotspotScope,
    pub(crate) hotspot_selected: Option<Pid>,
    pub(crate) show_attention: bool,
    pub(crate) attention_selected: Option<Pid>,
    pub(crate) baseline: Option<BaselineSnapshot>,
    pub(crate) show_snapshot_diff: bool,
    pub(crate) snapshot_diff_scroll: u16,
    pub(crate) network_scan: Option<NetworkScan>,
    pub(crate) show_network: bool,
    network_task: Option<NetworkTask>,
    pub(crate) network_scope: NetworkScope,
    pub(crate) network_selected: usize,
    pub(crate) network_filter: String,
    pub(crate) network_searching: bool,
    pub(crate) sort_mode: SortMode,
    pub(crate) visible: Vec<TreeRow>,
    pub(crate) selected: usize,
    pub(crate) expanded: HashSet<Pid>,
    pub(crate) collapsed: HashSet<Pid>,
    pub(crate) search: String,
    pub(crate) searching: bool,
    pub(crate) search_input: String,
    pub(crate) search_error: Option<String>,
    pub(crate) search_matches: usize,
    pub(crate) process_filters: Vec<ProcessFilterRule>,
    pub(crate) show_filter_manager: bool,
    pub(crate) filter_selected: usize,
    pub(crate) filter_editor: Option<FilterEditor>,
    pub(crate) filter_error: Option<String>,
    pub(crate) filtered_processes: usize,
    pub(crate) pid_input: Option<String>,
    pub(crate) pid_input_error: Option<String>,
    pub(crate) focus: Option<Pid>,
    pub(crate) last_refresh: Instant,
    pub(crate) marquee_offset: usize,
    pub(crate) last_marquee: Instant,
    pub(crate) marquee_pid: Option<Pid>,
    pub(crate) marquee_phase: MarqueePhase,
    pub(crate) page_size: usize,
    pub(crate) error: Option<String>,
    pub(crate) notice: Option<StatusNotice>,
    pub(crate) paused: bool,
    pub(crate) show_events: bool,
    pub(crate) events: Vec<ProcessEvent>,
    pub(crate) last_changes: ChangeSummary,
    pub(crate) inspection: Option<ProcessInspection>,
    inspection_task: Option<InspectionTask>,
    pub(crate) inspection_tab: InspectionTab,
    pub(crate) inspection_scroll: u16,
    pub(crate) service_context: Option<ServiceContextPanel>,
    service_context_task: Option<ServiceContextTask>,
    pub(crate) service_context_scroll: u16,
    pub(crate) executable_context: Option<ExecutableContextPanel>,
    executable_context_task: Option<ExecutableContextTask>,
    pub(crate) executable_context_scroll: u16,
    pub(crate) memory_context: Option<MemoryContextPanel>,
    memory_context_task: Option<MemoryContextTask>,
    pub(crate) memory_context_scroll: u16,
    pub(crate) logs_context: Option<LogsContextPanel>,
    logs_context_task: Option<LogsContextTask>,
    pub(crate) logs_context_scroll: u16,
    pub(crate) dossier_context: Option<DossierContextPanel>,
    dossier_context_task: Option<DossierContextTask>,
    pub(crate) dossier_context_scroll: u16,
    pub(crate) process_action: Option<ProcessActionDialog>,
    pub(crate) action_history: Vec<ProcessActionRecord>,
    pub(crate) guidance: Guidance,
}

impl App {
    #[cfg(test)]
    pub(crate) fn new_for_test(guidance: Guidance) -> Self {
        Self::new_with_guidance(String::new(), guidance)
    }

    pub(crate) fn new_for_tui(query: String, suppress_guidance: bool) -> Self {
        Self::new_with_guidance(query, Guidance::load_default(suppress_guidance))
    }

    pub(crate) fn language(&self) -> UiLanguage {
        self.guidance.language()
    }

    fn toggle_language(&mut self) {
        let result = self.guidance.toggle_language();
        let language = self.guidance.language();
        self.notice = Some(StatusNotice {
            message: match &result {
                Ok(_) => match language {
                    UiLanguage::Chinese => "界面语言已切换为中文".into(),
                    UiLanguage::English => "Interface language changed to English".into(),
                },
                Err(error) => format!(
                    "{}: {error}",
                    text(
                        language,
                        "language changed, but the preference could not be saved",
                        "语言已切换，但无法保存偏好"
                    )
                ),
            },
            is_error: result.is_err(),
            observed_at: Instant::now(),
        });
    }

    fn new_with_guidance(query: String, mut guidance: Guidance) -> Self {
        let has_initial_query = !query.is_empty();
        let guidance_warning = guidance.take_warning();
        let process_filters = guidance.filters().to_vec();
        let mut app = Self {
            provider: NativeProcessProvider::new(),
            processes: HashMap::new(),
            children: HashMap::new(),
            resources: HashMap::new(),
            history: ResourceHistory::default(),
            trend_pid: None,
            trend_view: TrendView::default(),
            show_hotspots: false,
            hotspot_metric: HotspotMetric::default(),
            hotspot_scope: HotspotScope::default(),
            hotspot_selected: None,
            show_attention: false,
            attention_selected: None,
            baseline: None,
            show_snapshot_diff: false,
            snapshot_diff_scroll: 0,
            network_scan: None,
            show_network: false,
            network_task: None,
            network_scope: NetworkScope::default(),
            network_selected: 0,
            network_filter: String::new(),
            network_searching: false,
            sort_mode: SortMode::Stable,
            visible: Vec::new(),
            selected: 0,
            expanded: HashSet::new(),
            collapsed: HashSet::new(),
            search: query,
            searching: false,
            search_input: String::new(),
            search_error: None,
            search_matches: 0,
            process_filters,
            show_filter_manager: false,
            filter_selected: 0,
            filter_editor: None,
            filter_error: None,
            filtered_processes: 0,
            pid_input: None,
            pid_input_error: None,
            focus: None,
            last_refresh: Instant::now(),
            marquee_offset: 0,
            last_marquee: Instant::now(),
            marquee_pid: None,
            marquee_phase: MarqueePhase::Scrolling,
            page_size: 10,
            error: None,
            notice: None,
            paused: false,
            show_events: false,
            events: Vec::new(),
            last_changes: ChangeSummary::default(),
            inspection: None,
            inspection_task: None,
            inspection_tab: InspectionTab::default(),
            inspection_scroll: 0,
            service_context: None,
            service_context_task: None,
            service_context_scroll: 0,
            executable_context: None,
            executable_context_task: None,
            executable_context_scroll: 0,
            memory_context: None,
            memory_context_task: None,
            memory_context_scroll: 0,
            logs_context: None,
            logs_context_task: None,
            logs_context_scroll: 0,
            dossier_context: None,
            dossier_context_task: None,
            dossier_context_scroll: 0,
            process_action: None,
            action_history: Vec::new(),
            guidance,
        };
        if let Some(message) = guidance_warning {
            app.notice = Some(StatusNotice {
                message,
                is_error: true,
                observed_at: Instant::now(),
            });
        }
        app.refresh();
        if has_initial_query {
            app.select_first_match();
        }
        app
    }

    pub(crate) fn refresh(&mut self) {
        let next_processes: HashMap<Pid, ProcessInfo> = self
            .provider
            .refresh()
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        let changes = if self.processes.is_empty() {
            Vec::new()
        } else {
            diff_processes(&self.processes, &next_processes)
        };
        self.processes = next_processes;
        self.record_changes(changes);
        self.children.clear();
        for process in self.processes.values() {
            self.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        self.resources = aggregate_resources(&self.processes, &self.children);
        let observed_at = Instant::now();
        self.history
            .record(&self.processes, &self.resources, observed_at);
        self.sort_children();
        if self.expanded.is_empty() {
            self.expanded.insert(Pid::from_u32(0));
            self.expanded.extend(
                self.children
                    .values()
                    .flatten()
                    .filter(|pid| {
                        self.children
                            .get(&Some(**pid))
                            .map(|c| !c.is_empty())
                            .unwrap_or(false)
                    })
                    .copied(),
            );
        }
        self.rebuild_visible();
        if self.show_hotspots {
            self.ensure_hotspot_selection();
        }
        if self.show_attention {
            self.ensure_attention_selection();
        }
        self.last_refresh = observed_at;
        self.error = None;
    }

    pub(crate) fn poll_background_jobs(&mut self) {
        let network_result = self
            .network_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match network_result {
            Some(Ok(scan)) => {
                let elapsed = self
                    .network_task
                    .take()
                    .map(|task| task.started_at.elapsed())
                    .unwrap_or_default();
                let endpoint_count = scan.endpoints.len();
                self.network_scan = Some(scan);
                let visible = self.network_visible_indices();
                self.network_selected = self.network_selected.min(visible.len().saturating_sub(1));
                self.notice = Some(StatusNotice {
                    message: match self.language() {
                        UiLanguage::English => format!(
                            "network scan complete: {endpoint_count} endpoints in {:.1}s",
                            elapsed.as_secs_f64()
                        ),
                        UiLanguage::Chinese => format!(
                            "网络扫描完成：{endpoint_count} 个端点，耗时 {:.1}s",
                            elapsed.as_secs_f64()
                        ),
                    },
                    is_error: false,
                    observed_at: Instant::now(),
                });
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.network_task = None;
                if self.network_scan.is_none() {
                    self.show_network = false;
                }
                self.notice = Some(StatusNotice {
                    message: text(
                        self.language(),
                        "network scan failed: background worker stopped",
                        "网络扫描失败：后台任务已停止",
                    )
                    .into(),
                    is_error: true,
                    observed_at: Instant::now(),
                });
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let inspection_result = self
            .inspection_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match inspection_result {
            Some(Ok(mut inspection)) => {
                let task = self.inspection_task.take();
                if let Some(task) = task {
                    let same_instance = self
                        .processes
                        .get(&task.pid)
                        .map(|process| {
                            task.start_time == 0
                                || process.start_time == 0
                                || process.start_time == task.start_time
                        })
                        .unwrap_or(false);
                    if !same_instance {
                        let warning =
                            "process exited or PID was reused while inspection was running";
                        inspection.warning = Some(match inspection.warning {
                            Some(existing) => format!("{existing}; {warning}"),
                            None => warning.into(),
                        });
                    }
                }
                self.inspection = Some(inspection);
                self.inspection_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.inspection_task = None;
                if let Some(inspection) = &mut self.inspection {
                    inspection.warning = Some("inspection background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let service_result = self
            .service_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match service_result {
            Some(Ok(result)) => {
                let task = self.service_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.service_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while service context was collected"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                            }
                            Err(error) => panel.warning = Some(error),
                        }
                    }
                }
                self.service_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.service_context_task = None;
                if let Some(panel) = &mut self.service_context {
                    panel.warning = Some("service context background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let executable_result = self
            .executable_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match executable_result {
            Some(Ok(result)) => {
                let task = self.executable_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.executable_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while executable image was verified"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                            }
                            Err(error) => panel.warning = Some(error),
                        }
                    }
                }
                self.executable_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.executable_context_task = None;
                if let Some(panel) = &mut self.executable_context {
                    panel.warning =
                        Some("executable verification background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let memory_result = self
            .memory_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match memory_result {
            Some(Ok(result)) => {
                let task = self.memory_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.memory_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while memory evidence was collected"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                                panel.warning = None;
                            }
                            Err(error) => {
                                panel.content.clear();
                                panel.report = None;
                                panel.warning = Some(error);
                            }
                        }
                    }
                }
                self.memory_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.memory_context_task = None;
                if let Some(panel) = &mut self.memory_context {
                    panel.warning = Some("memory evidence background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let logs_result = self
            .logs_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match logs_result {
            Some(Ok(result)) => {
                let task = self.logs_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.logs_context {
                    match result {
                        Ok((content, report)) => {
                            panel.content = content;
                            panel.report = Some(report);
                            panel.warning = (!same_instance).then(|| {
                                "process exited or changed after collection; showing the bounded report for the originally selected process instance".into()
                            });
                        }
                        Err(error) => {
                            panel.content.clear();
                            panel.report = None;
                            panel.warning = Some(error);
                        }
                    }
                }
                self.logs_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.logs_context_task = None;
                if let Some(panel) = &mut self.logs_context {
                    panel.warning = Some("native log background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let dossier_result = self
            .dossier_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match dossier_result {
            Some(Ok(result)) => {
                let task = self.dossier_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.dossier_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while the dossier was collected"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                                panel.warning = None;
                            }
                            Err(error) => {
                                panel.content.clear();
                                panel.report = None;
                                panel.warning = Some(error);
                            }
                        }
                    }
                }
                self.dossier_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.dossier_context_task = None;
                if let Some(panel) = &mut self.dossier_context {
                    panel.warning = Some("dossier background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
    }

    pub(crate) fn network_is_scanning(&self) -> bool {
        self.network_task.is_some()
    }

    pub(crate) fn network_scan_elapsed(&self) -> Duration {
        self.network_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn inspection_is_scanning(&self) -> bool {
        self.inspection_task.is_some()
    }

    pub(crate) fn inspection_elapsed(&self) -> Duration {
        self.inspection_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn service_context_is_scanning(&self) -> bool {
        self.service_context_task.is_some()
    }

    pub(crate) fn service_context_elapsed(&self) -> Duration {
        self.service_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn executable_context_is_scanning(&self) -> bool {
        self.executable_context_task.is_some()
    }

    pub(crate) fn executable_context_elapsed(&self) -> Duration {
        self.executable_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn memory_context_is_scanning(&self) -> bool {
        self.memory_context_task.is_some()
    }

    pub(crate) fn memory_context_elapsed(&self) -> Duration {
        self.memory_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn logs_context_is_scanning(&self) -> bool {
        self.logs_context_task.is_some()
    }

    pub(crate) fn logs_context_elapsed(&self) -> Duration {
        self.logs_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn dossier_context_is_scanning(&self) -> bool {
        self.dossier_context_task.is_some()
    }

    pub(crate) fn dossier_context_elapsed(&self) -> Duration {
        self.dossier_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    fn record_changes(&mut self, changes: Vec<ProcessChange>) {
        let mut summary = ChangeSummary::default();
        let now = Instant::now();
        for change in changes {
            match &change {
                ProcessChange::Started { .. } => summary.started += 1,
                ProcessChange::Exited { .. } => summary.exited += 1,
                ProcessChange::Reparented { .. } => summary.reparented += 1,
            }
            self.events.push(ProcessEvent {
                change,
                observed_at: now,
            });
        }
        self.last_changes = summary;
        const MAX_EVENTS: usize = 200;
        if self.events.len() > MAX_EVENTS {
            self.events.drain(..self.events.len() - MAX_EVENTS);
        }
    }

    pub(crate) fn recent_change(&self, pid: Pid) -> Option<&ProcessChange> {
        self.events
            .iter()
            .rev()
            .find(|event| {
                event.change.pid() == pid && event.observed_at.elapsed() <= Duration::from_secs(5)
            })
            .map(|event| &event.change)
    }

    fn toggle_paused(&mut self) {
        self.paused = !self.paused;
        if !self.paused {
            self.refresh();
        }
    }

    fn close_dossier_context(&mut self) {
        self.dossier_context = None;
        self.dossier_context_task = None;
        self.dossier_context_scroll = 0;
    }

    fn close_memory_context(&mut self) {
        self.memory_context = None;
        self.memory_context_task = None;
        self.memory_context_scroll = 0;
    }

    fn start_inspection(&mut self, process: ProcessInfo, clear_previous: bool) {
        if self.inspection_task.is_some() {
            return;
        }
        if clear_previous {
            self.inspection = Some(ProcessInspection {
                pid: process.pid,
                name: process.name.clone(),
                user: process.user.clone(),
                cwd: process.cwd.clone(),
                ..ProcessInspection::default()
            });
            self.inspection_tab = InspectionTab::default();
            self.inspection_scroll = 0;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-inspect-{}", pid.as_u32()))
            .spawn(move || {
                let _ = sender.send(inspect_process(&process));
            }) {
            Ok(_) => {
                self.inspection_task = Some(InspectionTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(inspection) = &mut self.inspection {
                    inspection.warning = Some(format!("cannot start inspection: {error}"));
                }
            }
        }
    }

    fn open_inspection(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_events = false;
        self.close_memory_context();
        self.close_dossier_context();
        self.start_inspection(process, true);
    }

    fn refresh_inspection(&mut self) {
        if self.inspection_task.is_some() {
            return;
        }
        let Some(pid) = self.inspection.as_ref().map(|inspection| inspection.pid) else {
            self.open_inspection();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(inspection) = &mut self.inspection {
                inspection.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_inspection(process, false);
    }

    fn start_service_context(&mut self, process: ProcessInfo, clear_previous: bool) {
        if self.service_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.service_context = Some(ServiceContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
            });
            self.service_context_scroll = 0;
        } else if let Some(panel) = &mut self.service_context {
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-service-context-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_service_context(pid.as_u32()).and_then(|captured| {
                    let table = render_service_table(&captured);
                    let json = render_service_json(&captured)
                        .map_err(|error| format!("cannot serialize service context: {error}"))?;
                    let report = serde_json::from_str(&json)
                        .map_err(|error| format!("cannot serialize service context: {error}"))?;
                    Ok((table, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.service_context_task = Some(ServiceContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.service_context {
                    panel.warning = Some(format!("cannot start service context: {error}"));
                }
            }
        }
    }

    fn open_service_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_memory_context();
        self.close_dossier_context();
        self.show_events = false;
        self.start_service_context(process, true);
    }

    fn refresh_service_context(&mut self) {
        if self.service_context_task.is_some() {
            return;
        }
        let Some(pid) = self.service_context.as_ref().map(|panel| panel.pid) else {
            self.open_service_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.service_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_service_context(process, false);
    }

    fn start_executable_context(&mut self, process: ProcessInfo, hash: bool, clear_previous: bool) {
        if self.executable_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.executable_context = Some(ExecutableContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
                hash,
            });
            self.executable_context_scroll = 0;
        } else if let Some(panel) = &mut self.executable_context {
            panel.warning = None;
            panel.report = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-executable-context-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_executable(pid.as_u32(), hash).and_then(|captured| {
                    let table = render_executable_table(&captured);
                    let json = render_executable_json(&captured)
                        .map_err(|error| format!("cannot serialize executable context: {error}"))?;
                    let report = serde_json::from_str(&json).map_err(|error| {
                        format!("cannot parse executable context JSON: {error}")
                    })?;
                    Ok((table, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.executable_context_task = Some(ExecutableContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.executable_context {
                    panel.warning = Some(format!("cannot start executable verification: {error}"));
                }
            }
        }
    }

    fn open_executable_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_memory_context();
        self.close_dossier_context();
        self.show_events = false;
        self.start_executable_context(process, true, true);
    }

    fn refresh_executable_context(&mut self) {
        if self.executable_context_task.is_some() {
            return;
        }
        let Some((pid, hash)) = self
            .executable_context
            .as_ref()
            .map(|panel| (panel.pid, panel.hash))
        else {
            self.open_executable_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.executable_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_executable_context(process, hash, false);
    }

    fn toggle_executable_hash(&mut self) {
        if self.executable_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.executable_context {
            panel.hash = !panel.hash;
            panel.content.clear();
            panel.report = None;
        }
        self.refresh_executable_context();
    }

    fn start_memory_context(&mut self, process: ProcessInfo, clear_previous: bool) {
        if self.memory_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.memory_context = Some(MemoryContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
            });
            self.memory_context_scroll = 0;
        } else if let Some(panel) = &mut self.memory_context {
            panel.content.clear();
            panel.report = None;
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-memory-context-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_memory(pid.as_u32(), Some(20)).and_then(|captured| {
                    let table = render_memory_table(&captured);
                    let json = render_memory_json(&captured)
                        .map_err(|error| format!("cannot serialize memory evidence: {error}"))?;
                    let report = serde_json::from_str(&json)
                        .map_err(|error| format!("cannot parse memory evidence JSON: {error}"))?;
                    Ok((table, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.memory_context_task = Some(MemoryContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.memory_context {
                    panel.warning = Some(format!("cannot start memory collection: {error}"));
                }
            }
        }
    }

    fn open_memory_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_dossier_context();
        self.show_events = false;
        self.start_memory_context(process, true);
    }

    fn refresh_memory_context(&mut self) {
        if self.memory_context_task.is_some() {
            return;
        }
        let Some(pid) = self.memory_context.as_ref().map(|panel| panel.pid) else {
            self.open_memory_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.memory_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_memory_context(process, false);
    }

    fn start_logs_context(
        &mut self,
        process: ProcessInfo,
        scope: LogScope,
        priority: LogPriority,
        since_seconds: u64,
        limit: usize,
        clear_previous: bool,
    ) {
        if self.logs_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.logs_context = Some(LogsContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
                scope,
                priority,
                since_seconds,
                limit,
            });
            self.logs_context_scroll = 0;
        } else if let Some(panel) = &mut self.logs_context {
            panel.content.clear();
            panel.report = None;
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-native-logs-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_logs(pid.as_u32(), scope, priority, since_seconds, limit)
                    .and_then(|captured| {
                        let table = render_logs_table(&captured);
                        let json = render_logs_json(&captured)
                            .map_err(|error| format!("cannot serialize native logs: {error}"))?;
                        let report = serde_json::from_str(&json)
                            .map_err(|error| format!("cannot parse native log JSON: {error}"))?;
                        Ok((table, report))
                    });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.logs_context_task = Some(LogsContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.logs_context {
                    panel.warning = Some(format!("cannot start native log collection: {error}"));
                }
            }
        }
    }

    fn open_logs_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.close_memory_context();
        self.close_dossier_context();
        self.show_events = false;
        self.start_logs_context(
            process,
            LogScope::Auto,
            LogPriority::Info,
            15 * 60,
            100,
            true,
        );
    }

    fn refresh_logs_context(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        let Some((pid, scope, priority, since_seconds, limit)) =
            self.logs_context.as_ref().map(|panel| {
                (
                    panel.pid,
                    panel.scope,
                    panel.priority,
                    panel.since_seconds,
                    panel.limit,
                )
            })
        else {
            self.open_logs_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.logs_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_logs_context(process, scope, priority, since_seconds, limit, false);
    }

    fn cycle_logs_scope(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.logs_context {
            panel.scope = panel.scope.next();
        }
        self.refresh_logs_context();
    }

    fn cycle_logs_priority(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.logs_context {
            panel.priority = panel.priority.next();
        }
        self.refresh_logs_context();
    }

    fn cycle_logs_window(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.logs_context {
            panel.since_seconds = match panel.since_seconds {
                0..=300 => 15 * 60,
                301..=900 => 60 * 60,
                901..=3_600 => 6 * 60 * 60,
                _ => 5 * 60,
            };
        }
        self.refresh_logs_context();
    }

    #[allow(clippy::too_many_arguments)]
    fn start_dossier_context(
        &mut self,
        process: ProcessInfo,
        include_logs: bool,
        hash: bool,
        scope: LogScope,
        priority: LogPriority,
        since_seconds: u64,
        limit: usize,
        clear_previous: bool,
    ) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.dossier_context = Some(DossierContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
                include_logs,
                hash,
                scope,
                priority,
                since_seconds,
                limit,
            });
            self.dossier_context_scroll = 0;
        } else if let Some(panel) = &mut self.dossier_context {
            panel.content.clear();
            panel.report = None;
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-dossier-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_dossier(
                    pid.as_u32(),
                    ExplainOptions {
                        sample_ms: 500,
                        hash,
                        include_logs,
                        logs_scope: scope,
                        logs_priority: priority,
                        logs_since_seconds: since_seconds,
                        logs_limit: limit,
                    },
                )
                .and_then(|captured| {
                    let content = render_dossier_summary_table(&captured);
                    let json = render_dossier_json(&captured)
                        .map_err(|error| format!("cannot serialize process dossier: {error}"))?;
                    let report = serde_json::from_str(&json)
                        .map_err(|error| format!("cannot parse process dossier JSON: {error}"))?;
                    Ok((content, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.dossier_context_task = Some(DossierContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.dossier_context {
                    panel.warning = Some(format!("cannot start dossier collection: {error}"));
                }
            }
        }
    }

    fn open_dossier_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_memory_context();
        self.show_events = false;
        self.start_dossier_context(
            process,
            true,
            true,
            LogScope::Auto,
            LogPriority::Info,
            15 * 60,
            100,
            true,
        );
    }

    fn refresh_dossier_context(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        let Some((pid, include_logs, hash, scope, priority, since_seconds, limit)) =
            self.dossier_context.as_ref().map(|panel| {
                (
                    panel.pid,
                    panel.include_logs,
                    panel.hash,
                    panel.scope,
                    panel.priority,
                    panel.since_seconds,
                    panel.limit,
                )
            })
        else {
            self.open_dossier_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.dossier_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_dossier_context(
            process,
            include_logs,
            hash,
            scope,
            priority,
            since_seconds,
            limit,
            false,
        );
    }

    fn cycle_dossier_scope(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.scope = panel.scope.next();
            panel.include_logs = true;
        }
        self.refresh_dossier_context();
    }

    fn cycle_dossier_priority(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.priority = panel.priority.next();
            panel.include_logs = true;
        }
        self.refresh_dossier_context();
    }

    fn cycle_dossier_window(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.since_seconds = match panel.since_seconds {
                0..=300 => 15 * 60,
                301..=900 => 60 * 60,
                901..=3_600 => 6 * 60 * 60,
                _ => 5 * 60,
            };
            panel.include_logs = true;
        }
        self.refresh_dossier_context();
    }

    fn toggle_dossier_hash(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.hash = !panel.hash;
        }
        self.refresh_dossier_context();
    }

    fn toggle_dossier_logs(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.include_logs = !panel.include_logs;
        }
        self.refresh_dossier_context();
    }

    fn rebuild_visible(&mut self) {
        let old_pid = self.visible.get(self.selected).map(|row| row.pid);
        self.visible.clear();
        let active_filters = self
            .process_filters
            .iter()
            .filter(|rule| rule.enabled)
            .count();
        let compiled_filters = match CompiledProcessFilters::compile(&self.process_filters) {
            Ok(filters) => {
                self.filter_error = None;
                Some(filters)
            }
            Err(error) => {
                // Fail open: a malformed persisted rule must never hide the
                // process table during an incident.
                self.filter_error = Some(error);
                None
            }
        };
        let filter_applied = active_filters > 0 && compiled_filters.is_some();
        let allowed: HashSet<Pid> = self
            .processes
            .values()
            .filter(|process| {
                let subtree = self
                    .resources
                    .get(&process.pid)
                    .copied()
                    .unwrap_or_default();
                let direct_children = self
                    .children
                    .get(&Some(process.pid))
                    .map(Vec::len)
                    .unwrap_or(0);
                compiled_filters
                    .as_ref()
                    .map(|filters| filters.matches(process, subtree, direct_children))
                    .unwrap_or(true)
            })
            .map(|process| process.pid)
            .collect();
        self.filtered_processes = allowed.iter().filter(|pid| pid.as_u32() != 0).count();

        let query = ProcessQuery::parse(&self.search);
        let matched: HashSet<Pid> = match query {
            Ok(query) => {
                self.search_error = None;
                allowed
                    .iter()
                    .filter_map(|pid| self.processes.get(pid))
                    .filter(|process| {
                        let subtree = self
                            .resources
                            .get(&process.pid)
                            .copied()
                            .unwrap_or_default();
                        let direct_children = self
                            .children
                            .get(&Some(process.pid))
                            .map(Vec::len)
                            .unwrap_or(0);
                        query.matches(process, subtree, direct_children)
                    })
                    .map(|process| process.pid)
                    .collect()
            }
            Err(error) => {
                self.search_error = Some(error);
                HashSet::new()
            }
        };
        self.search_matches = if self.search.is_empty() {
            0
        } else {
            matched.iter().filter(|pid| pid.as_u32() != 0).count()
        };
        let restricted = filter_applied || !self.search.is_empty();
        let search_active = !self.search.is_empty();
        let tree_selection = TreeSelection {
            matched: &matched,
            allowed: &allowed,
            restricted,
            filter_applied,
            search_active,
        };

        if let Some(focus) = self.focus {
            let mut chain = Vec::new();
            let mut current = Some(focus);
            while let Some(pid) = current {
                chain.push(pid);
                current = self.processes.get(&pid).and_then(|p| p.parent);
            }
            chain.reverse();
            for (depth, pid) in chain.iter().enumerate() {
                self.visible.push(TreeRow {
                    pid: *pid,
                    depth,
                    last_path: vec![false; depth],
                    is_last: depth == chain.len().saturating_sub(1),
                });
            }
            self.walk_children(
                focus,
                chain.len(),
                vec![false; chain.len()],
                &tree_selection,
            );
        } else {
            let roots = [Pid::from_u32(0)];
            for (index, pid) in roots.iter().enumerate() {
                self.walk(*pid, Vec::new(), index == roots.len() - 1, &tree_selection);
            }
        }
        if self.visible.is_empty() && !self.processes.is_empty() {
            let mut all: Vec<Pid> = self.processes.keys().copied().collect();
            all.sort_by_key(|p| p.as_u32());
            for pid in all {
                if matched.contains(&pid) {
                    self.visible.push(TreeRow {
                        pid,
                        depth: 0,
                        last_path: Vec::new(),
                        is_last: true,
                    });
                }
            }
        }
        self.selected = old_pid
            .and_then(|pid| self.visible.iter().position(|row| row.pid == pid))
            .unwrap_or(self.selected.min(self.visible.len().saturating_sub(1)));
    }

    fn walk(
        &mut self,
        pid: Pid,
        last_path: Vec<bool>,
        is_last: bool,
        selection: &TreeSelection<'_>,
    ) {
        let has_match = selection.matched.contains(&pid);
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let descendant_match = descendants
            .iter()
            .any(|child| self.has_matching_descendant(*child, selection.matched));
        if has_match || descendant_match || !selection.restricted {
            let depth = last_path.len();
            self.visible.push(TreeRow {
                pid,
                depth,
                last_path: last_path.clone(),
                is_last,
            });
            if self.expanded.contains(&pid)
                || (selection.restricted && descendant_match && !self.collapsed.contains(&pid))
            {
                let visible_children: Vec<Pid> = descendants
                    .into_iter()
                    .filter(|child| {
                        if selection.search_active && has_match {
                            !selection.filter_applied
                                || self.has_matching_descendant(*child, selection.allowed)
                        } else {
                            !selection.restricted
                                || self.has_matching_descendant(*child, selection.matched)
                        }
                    })
                    .collect();
                for (index, child) in visible_children.iter().enumerate() {
                    let mut child_path = last_path.clone();
                    child_path.push(is_last);
                    if selection.search_active && has_match {
                        self.walk_context(
                            *child,
                            child_path,
                            index == visible_children.len() - 1,
                            selection,
                        );
                    } else {
                        self.walk(
                            *child,
                            child_path,
                            index == visible_children.len() - 1,
                            selection,
                        );
                    }
                }
            }
        }
    }

    /// Once a search hit is visible, show its complete descendant context.
    /// Search still filters the ancestors and unrelated branches, but it must
    /// not hide the children that explain what the matched process owns.
    fn walk_context(
        &mut self,
        pid: Pid,
        last_path: Vec<bool>,
        is_last: bool,
        selection: &TreeSelection<'_>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        if selection.filter_applied && !self.has_matching_descendant(pid, selection.allowed) {
            return;
        }
        let depth = last_path.len();
        self.visible.push(TreeRow {
            pid,
            depth,
            last_path: last_path.clone(),
            is_last,
        });
        if self.expanded.contains(&pid) && !self.collapsed.contains(&pid) {
            let visible_children: Vec<Pid> = descendants
                .into_iter()
                .filter(|child| {
                    !selection.filter_applied
                        || self.has_matching_descendant(*child, selection.allowed)
                })
                .collect();
            for (index, child) in visible_children.iter().enumerate() {
                let mut child_path = last_path.clone();
                child_path.push(is_last);
                self.walk_context(
                    *child,
                    child_path,
                    index == visible_children.len() - 1,
                    selection,
                );
            }
        }
    }

    fn walk_children(
        &mut self,
        pid: Pid,
        depth: usize,
        last_path: Vec<bool>,
        selection: &TreeSelection<'_>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let visible_children: Vec<Pid> = descendants
            .into_iter()
            .filter(|child| {
                !selection.restricted || self.has_matching_descendant(*child, selection.matched)
            })
            .collect();
        for (index, child) in visible_children.iter().enumerate() {
            let mut child_path = last_path.clone();
            child_path.push(index == visible_children.len() - 1);
            self.visible.push(TreeRow {
                pid: *child,
                depth,
                last_path: child_path.clone(),
                is_last: index == visible_children.len() - 1,
            });
            if self.expanded.contains(child)
                || (!selection.restricted && !self.collapsed.contains(child))
                || (selection.restricted
                    && self.has_matching_descendant(*child, selection.matched)
                    && !self.collapsed.contains(child))
            {
                if selection.search_active && selection.matched.contains(child) {
                    let grandchildren = self
                        .children
                        .get(&Some(*child))
                        .cloned()
                        .unwrap_or_default();
                    let visible_grandchildren: Vec<Pid> = grandchildren
                        .into_iter()
                        .filter(|grandchild| {
                            !selection.filter_applied
                                || self.has_matching_descendant(*grandchild, selection.allowed)
                        })
                        .collect();
                    for (grandchild_index, grandchild) in visible_grandchildren.iter().enumerate() {
                        let mut grandchild_path = child_path.clone();
                        grandchild_path.push(index == visible_children.len() - 1);
                        self.walk_context(
                            *grandchild,
                            grandchild_path,
                            grandchild_index == visible_grandchildren.len() - 1,
                            selection,
                        );
                    }
                } else {
                    self.walk_children(*child, depth + 1, child_path, selection);
                }
            }
        }
    }

    fn has_matching_descendant(&self, pid: Pid, matched: &HashSet<Pid>) -> bool {
        if matched.contains(&pid) {
            return true;
        }
        self.children
            .get(&Some(pid))
            .map(|children| {
                children
                    .iter()
                    .any(|p| self.has_matching_descendant(*p, matched))
            })
            .unwrap_or(false)
    }

    pub(crate) fn selected_pid(&self) -> Option<Pid> {
        self.visible.get(self.selected).map(|row| row.pid)
    }

    fn selected_context(&self) -> Option<String> {
        let pid = self.selected_pid()?;
        let process = self.processes.get(&pid)?;
        Some(process_path(process))
    }

    pub(crate) fn advance_marquee(&mut self, width: usize) {
        let selected = self.selected_pid();
        if self.marquee_pid != selected {
            self.marquee_pid = selected;
            self.marquee_offset = 0;
            self.marquee_phase = MarqueePhase::Scrolling;
            self.last_marquee = Instant::now();
        }
        let Some(context) = self.selected_context() else {
            return;
        };
        let max_offset = context.width().saturating_sub(width);
        if width == 0 || max_offset == 0 {
            self.marquee_offset = 0;
            self.marquee_phase = MarqueePhase::Scrolling;
            return;
        }
        let now = Instant::now();
        match self.marquee_phase {
            MarqueePhase::Scrolling => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(125) {
                    self.marquee_offset = self.marquee_offset.saturating_add(1);
                    self.last_marquee = now;
                    if self.marquee_offset >= max_offset {
                        self.marquee_offset = max_offset;
                        self.marquee_phase = MarqueePhase::TailPause;
                    }
                }
            }
            MarqueePhase::TailPause => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(2500) {
                    self.marquee_offset = 0;
                    self.marquee_phase = MarqueePhase::ResetPause;
                    self.last_marquee = now;
                }
            }
            MarqueePhase::ResetPause => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(1000) {
                    self.marquee_phase = MarqueePhase::Scrolling;
                    self.last_marquee = now;
                }
            }
        }
    }

    fn select_first_match(&mut self) {
        if self.search.is_empty() {
            return;
        }
        let Ok(query) = ProcessQuery::parse(&self.search) else {
            return;
        };
        let filters = CompiledProcessFilters::compile(&self.process_filters).ok();
        if let Some(index) = self.visible.iter().position(|row| {
            self.processes
                .get(&row.pid)
                .map(|process| {
                    let subtree = self
                        .resources
                        .get(&process.pid)
                        .copied()
                        .unwrap_or_default();
                    let direct_children = self
                        .children
                        .get(&Some(process.pid))
                        .map(Vec::len)
                        .unwrap_or(0);
                    filters
                        .as_ref()
                        .map(|filters| filters.matches(process, subtree, direct_children))
                        .unwrap_or(true)
                        && query.matches(process, subtree, direct_children)
                })
                .unwrap_or(false)
        }) {
            self.selected = index;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let max = self.visible.len() - 1;
        self.selected = (self.selected as isize + delta).clamp(0, max as isize) as usize;
    }

    fn toggle_focus(&mut self) {
        self.focus = if self.focus == self.selected_pid() {
            None
        } else {
            self.selected_pid()
        };
        self.selected = 0;
        self.rebuild_visible();
    }

    fn toggle_selected_expanded(&mut self) {
        let Some(pid) = self.selected_pid() else {
            return;
        };
        if self
            .children
            .get(&Some(pid))
            .map(|c| !c.is_empty())
            .unwrap_or(false)
        {
            if !self.expanded.insert(pid) {
                self.expanded.remove(&pid);
                self.collapsed.insert(pid);
            } else {
                self.collapsed.remove(&pid);
            }
            self.rebuild_visible();
        }
    }

    fn sort_children(&mut self) {
        for children in self.children.values_mut() {
            sort_processes(children, self.sort_mode, &self.processes, &self.resources);
        }
    }

    fn cycle_sort_mode(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.sort_children();
        self.rebuild_visible();
    }

    fn reveal_parent(&mut self) {
        let Some(pid) = self.selected_pid() else {
            return;
        };
        let Some(parent) = self.processes.get(&pid).and_then(|p| p.parent) else {
            return;
        };

        // Expose the complete ancestor path, but keep the parent's other branches collapsed.
        let mut current = Some(parent);
        while let Some(ancestor) = current {
            self.expanded.insert(ancestor);
            self.collapsed.remove(&ancestor);
            current = self.processes.get(&ancestor).and_then(|p| p.parent);
        }
        if let Some(siblings) = self.children.get(&Some(parent)).cloned() {
            for sibling in siblings {
                if sibling != pid {
                    self.expanded.remove(&sibling);
                    self.collapsed.insert(sibling);
                }
            }
        }
        self.rebuild_visible();
        if let Some(index) = self.visible.iter().position(|row| row.pid == parent) {
            self.selected = index;
        }
    }

    fn apply_search_input(&mut self) {
        if !self.searching {
            return;
        }
        self.searching = false;
        self.search = std::mem::take(&mut self.search_input);
        self.rebuild_visible();
        self.select_first_match();
    }

    pub(crate) fn active_filter_count(&self) -> usize {
        self.process_filters
            .iter()
            .filter(|rule| rule.enabled)
            .count()
    }

    fn persist_process_filters(&mut self) {
        if let Err(error) = self.guidance.save_filters(&self.process_filters) {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => {
                        format!("filters changed, but the preference could not be saved: {error}")
                    }
                    UiLanguage::Chinese => format!("过滤规则已更改，但无法保存偏好：{error}"),
                },
                is_error: true,
                observed_at: Instant::now(),
            });
        }
    }

    fn open_filter_manager(&mut self) {
        self.show_filter_manager = true;
        self.filter_editor = None;
        self.filter_selected = self
            .filter_selected
            .min(self.process_filters.len().saturating_sub(1));
    }

    fn close_filter_manager(&mut self) {
        self.show_filter_manager = false;
        self.filter_editor = None;
    }

    fn start_filter_editor(&mut self, action: FilterAction) {
        self.filter_editor = Some(FilterEditor {
            action,
            input: String::new(),
            error: None,
            editing_index: None,
            enabled: true,
        });
    }

    fn edit_selected_filter(&mut self) {
        let Some(rule) = self.process_filters.get(self.filter_selected) else {
            return;
        };
        self.filter_editor = Some(FilterEditor {
            action: rule.action,
            input: rule.expression.clone(),
            error: None,
            editing_index: Some(self.filter_selected),
            enabled: rule.enabled,
        });
    }

    fn apply_filter_editor(&mut self) {
        let language = self.language();
        let Some(editor) = &mut self.filter_editor else {
            return;
        };
        let expression = editor.input.trim();
        if expression.is_empty() {
            editor.error = Some(
                text(
                    language,
                    "filter expression cannot be empty",
                    "过滤表达式不能为空",
                )
                .into(),
            );
            return;
        }
        if let Err(error) = ProcessQuery::parse(expression) {
            editor.error = Some(error);
            return;
        }
        let rule = ProcessFilterRule {
            action: editor.action,
            expression: expression.into(),
            enabled: editor.enabled,
        };
        if let Some(index) = editor.editing_index {
            self.process_filters[index] = rule;
            self.filter_selected = index;
        } else {
            self.process_filters.push(rule);
            self.filter_selected = self.process_filters.len() - 1;
        }
        self.filter_editor = None;
        self.persist_process_filters();
        self.rebuild_visible();
    }

    fn toggle_selected_filter(&mut self) {
        let Some(rule) = self.process_filters.get_mut(self.filter_selected) else {
            return;
        };
        rule.enabled = !rule.enabled;
        if let Err(error) = CompiledProcessFilters::compile(&self.process_filters) {
            if let Some(rule) = self.process_filters.get_mut(self.filter_selected) {
                rule.enabled = !rule.enabled;
            }
            self.filter_error = Some(error);
            return;
        }
        self.persist_process_filters();
        self.rebuild_visible();
    }

    fn remove_selected_filter(&mut self) {
        if self.process_filters.is_empty() {
            return;
        }
        self.process_filters.remove(self.filter_selected);
        self.filter_selected = self
            .filter_selected
            .min(self.process_filters.len().saturating_sub(1));
        self.persist_process_filters();
        self.rebuild_visible();
    }

    fn capture_baseline(&mut self) {
        self.baseline = Some(BaselineSnapshot::capture(
            &self.processes,
            &self.resources,
            Instant::now(),
        ));
        self.snapshot_diff_scroll = 0;
    }

    fn export_diagnostic_report(&mut self) {
        let attention_findings = self.attention_findings();
        let result = std::env::current_dir().and_then(|directory| {
            export_report(
                ReportInput {
                    platform: platform_name(),
                    selected_pid: self.selected_pid(),
                    query: &self.search,
                    query_editing: self.searching,
                    query_error: self.search_error.as_deref(),
                    query_matches: self.search_matches,
                    process_filters: &self.process_filters,
                    filter_error: self.filter_error.as_deref(),
                    filtered_processes: self.filtered_processes,
                    paused: self.paused,
                    sort_mode: self.sort_mode,
                    processes: &self.processes,
                    resources: &self.resources,
                    events: &self.events,
                    attention_findings: &attention_findings,
                    network: self.network_scan.as_ref(),
                    network_scope: self.network_scope,
                    network_scan_in_progress: self.network_is_scanning(),
                    inspection: self.inspection.as_ref(),
                    inspection_in_progress: self.inspection_is_scanning(),
                    service_context: self
                        .service_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    service_context_in_progress: self.service_context_is_scanning(),
                    executable_context: self
                        .executable_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    executable_context_in_progress: self.executable_context_is_scanning(),
                    memory_context: self
                        .memory_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    memory_context_in_progress: self.memory_context_is_scanning(),
                    logs_context: self
                        .logs_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    logs_context_in_progress: self.logs_context_is_scanning(),
                    dossier_context: self
                        .dossier_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    dossier_context_in_progress: self.dossier_context_is_scanning(),
                    action_history: &self.action_history,
                    baseline: self.baseline.as_ref(),
                },
                &directory,
            )
        });
        self.notice = Some(match result {
            Ok(path) => StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!("report saved: {}", path.display()),
                    UiLanguage::Chinese => format!("报告已保存：{}", path.display()),
                },
                is_error: false,
                observed_at: Instant::now(),
            },
            Err(error) => StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!("report export failed: {error}"),
                    UiLanguage::Chinese => format!("报告导出失败：{error}"),
                },
                is_error: true,
                observed_at: Instant::now(),
            },
        });
    }

    fn start_network_scan(&mut self, clear_previous: bool) {
        if self.network_task.is_some() {
            return;
        }
        if clear_previous {
            self.network_scan = None;
        }
        let processes = self.processes.clone();
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name("psmore-network-scan".into())
            .spawn(move || {
                let _ = sender.send(scan_network(&processes));
            }) {
            Ok(_) => {
                self.network_task = Some(NetworkTask {
                    receiver,
                    started_at: Instant::now(),
                });
            }
            Err(error) => {
                self.show_network = false;
                self.notice = Some(StatusNotice {
                    message: match self.language() {
                        UiLanguage::English => format!("cannot start network scan: {error}"),
                        UiLanguage::Chinese => format!("无法启动网络扫描：{error}"),
                    },
                    is_error: true,
                    observed_at: Instant::now(),
                });
            }
        }
    }

    fn open_network(&mut self) {
        self.show_network = true;
        self.start_network_scan(true);
        self.network_scope = NetworkScope::default();
        self.network_selected = 0;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_events = false;
        self.inspection = None;
        self.inspection_task = None;
        self.trend_pid = None;
        self.show_snapshot_diff = false;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_attention = false;
        self.attention_selected = None;
    }

    fn open_hotspots(&mut self) {
        self.show_hotspots = true;
        self.hotspot_metric = HotspotMetric::default();
        self.hotspot_scope = HotspotScope::default();
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_events = false;
        self.inspection = None;
        self.inspection_task = None;
        self.trend_pid = None;
        self.show_snapshot_diff = false;
        self.show_attention = false;
        self.attention_selected = None;
        self.reset_hotspot_selection();
    }

    fn open_attention(&mut self) {
        self.show_attention = true;
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_events = false;
        self.inspection = None;
        self.inspection_task = None;
        self.trend_pid = None;
        self.show_snapshot_diff = false;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.reset_attention_selection();
    }

    pub(crate) fn attention_findings(&self) -> Vec<AttentionFinding> {
        rank_attention_findings(&self.processes, &self.history, &self.events)
    }

    fn reset_attention_selection(&mut self) {
        self.attention_selected = self.attention_findings().first().map(|finding| finding.pid);
    }

    fn ensure_attention_selection(&mut self) {
        let findings = self.attention_findings();
        let selection_is_visible = self
            .attention_selected
            .map(|pid| findings.iter().any(|finding| finding.pid == pid))
            .unwrap_or(false);
        if !selection_is_visible {
            self.attention_selected = findings.first().map(|finding| finding.pid);
        }
    }

    fn move_attention_selection(&mut self, delta: isize) {
        let findings = self.attention_findings();
        if findings.is_empty() {
            self.attention_selected = None;
            return;
        }
        let current = self
            .attention_selected
            .and_then(|pid| findings.iter().position(|finding| finding.pid == pid))
            .unwrap_or(0);
        let next =
            (current as isize + delta).clamp(0, findings.len().saturating_sub(1) as isize) as usize;
        self.attention_selected = findings.get(next).map(|finding| finding.pid);
    }

    fn open_attention_trend(&mut self) {
        let Some(pid) = self.attention_selected else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.trend_pid = Some(pid);
        self.trend_view = TrendView::default();
    }

    fn inspect_attention_process(&mut self) {
        let Some(pid) = self.attention_selected else {
            return;
        };
        self.jump_to_process(pid);
        self.open_inspection();
    }

    pub(crate) fn hotspot_ranked(&self, metric: HotspotMetric) -> Vec<Pid> {
        rank_hotspots(&self.processes, &self.resources, metric, self.hotspot_scope)
    }

    fn reset_hotspot_selection(&mut self) {
        self.hotspot_selected = self.hotspot_ranked(self.hotspot_metric).first().copied();
    }

    fn ensure_hotspot_selection(&mut self) {
        let selected_is_alive = self
            .hotspot_selected
            .map(|pid| self.processes.contains_key(&pid))
            .unwrap_or(false);
        if !selected_is_alive {
            self.reset_hotspot_selection();
        }
    }

    fn select_hotspot_metric(&mut self, metric: HotspotMetric) {
        self.hotspot_metric = metric;
        self.reset_hotspot_selection();
    }

    fn move_hotspot_selection(&mut self, delta: isize) {
        let ranked = self.hotspot_ranked(self.hotspot_metric);
        if ranked.is_empty() {
            self.hotspot_selected = None;
            return;
        }
        let current = self
            .hotspot_selected
            .and_then(|pid| ranked.iter().position(|candidate| *candidate == pid))
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, ranked.len().saturating_sub(1) as isize);
        self.hotspot_selected = ranked.get(next as usize).copied();
    }

    fn refresh_network(&mut self) {
        self.start_network_scan(false);
    }

    pub(crate) fn network_visible_indices(&self) -> Vec<usize> {
        self.network_scan
            .as_ref()
            .map(|scan| {
                scan.endpoints
                    .iter()
                    .enumerate()
                    .filter(|(_, endpoint)| self.network_scope.includes(endpoint))
                    .filter(|(_, endpoint)| endpoint.matches(&self.network_filter))
                    .map(|(index, _)| index)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn move_network_selection(&mut self, delta: isize) {
        let visible_len = self.network_visible_indices().len();
        if visible_len == 0 {
            self.network_selected = 0;
            return;
        }
        self.network_selected = (self.network_selected as isize + delta)
            .clamp(0, visible_len.saturating_sub(1) as isize)
            as usize;
    }

    fn jump_to_process(&mut self, pid: Pid) {
        if !self.processes.contains_key(&pid) {
            return;
        }
        self.show_network = false;
        self.network_filter.clear();
        self.network_searching = false;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_attention = false;
        self.attention_selected = None;
        self.search.clear();
        self.searching = false;
        self.search_input.clear();
        self.pid_input = None;
        self.pid_input_error = None;
        self.focus = None;
        let mut current = Some(pid);
        while let Some(process_pid) = current {
            self.expanded.insert(process_pid);
            self.collapsed.remove(&process_pid);
            current = self
                .processes
                .get(&process_pid)
                .and_then(|process| process.parent);
        }
        self.rebuild_visible();
        if let Some(index) = self.visible.iter().position(|row| row.pid == pid) {
            self.selected = index;
        }
    }

    fn open_process_action_for_mode(&mut self, pid: Pid, mode: ProcessActionDialogMode) {
        let Some(process) = self.processes.get(&pid) else {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => {
                        format!("cannot control PID {pid}: process is no longer visible")
                    }
                    UiLanguage::Chinese => format!("无法操作 PID {pid}：进程已不可见"),
                },
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        };
        if pid.as_u32() <= 1 || pid.as_u32() == std::process::id() {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!(
                        "cannot control {} [{}]: protected process",
                        process.name, pid
                    ),
                    UiLanguage::Chinese => {
                        format!("无法操作 {} [{}]：受保护进程", process.name, pid)
                    }
                },
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        }
        if process.start_time == 0 {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!(
                        "cannot control {} [{}]: process instance identity is unavailable",
                        process.name, pid
                    ),
                    UiLanguage::Chinese => {
                        format!("无法操作 {} [{}]：无法确认进程实例身份", process.name, pid)
                    }
                },
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        }
        self.process_action = Some(ProcessActionDialog {
            target: ProcessActionTarget::from(process),
            selected: 0,
            confirming: false,
            mode,
        });
    }

    fn open_process_action_for(&mut self, pid: Pid) {
        self.open_process_action_for_mode(pid, ProcessActionDialogMode::All);
    }

    fn open_selected_process_action(&mut self) {
        if let Some(pid) = self.selected_pid() {
            self.open_process_action_for(pid);
        }
    }

    fn open_selected_process_termination(&mut self) {
        if let Some(pid) = self.selected_pid() {
            self.open_process_action_for_mode(pid, ProcessActionDialogMode::Termination);
        }
    }

    fn move_process_action_selection(&mut self, delta: isize) {
        let Some(dialog) = &mut self.process_action else {
            return;
        };
        let action_count = dialog.actions().len();
        dialog.selected = (dialog.selected as isize + delta)
            .clamp(0, action_count.saturating_sub(1) as isize) as usize;
        dialog.confirming = false;
    }

    fn choose_process_action(&mut self, action: ProcessActionKind) {
        let Some(dialog) = &mut self.process_action else {
            return;
        };
        if let Some(index) = dialog
            .actions()
            .iter()
            .position(|candidate| *candidate == action)
        {
            dialog.selected = index;
            dialog.confirming = true;
        }
    }

    fn execute_confirmed_process_action(&mut self) {
        let Some(dialog) = self.process_action.take() else {
            return;
        };
        let action = dialog.selected_action();
        let target = dialog.target;
        let outcome = execute_process_action(&target, action);
        let detail = outcome
            .detail()
            .map(|detail| format!(": {detail}"))
            .unwrap_or_default();
        self.notice = Some(StatusNotice {
            message: match self.language() {
                UiLanguage::English => format!(
                    "{} {} to {} [{}]{}",
                    outcome.label(),
                    action.label(),
                    target.name,
                    target.pid,
                    detail
                ),
                UiLanguage::Chinese => format!(
                    "{} {} 至 {} [{}]{}",
                    match &outcome {
                        ProcessActionOutcome::Sent => "已发送",
                        ProcessActionOutcome::Refused(_) => "已拒绝",
                        ProcessActionOutcome::Failed(_) => "失败",
                    },
                    action.label(),
                    target.name,
                    target.pid,
                    detail
                ),
            },
            is_error: outcome.is_error(),
            observed_at: Instant::now(),
        });
        self.action_history.push(ProcessActionRecord {
            observed_at: Instant::now(),
            target,
            action,
            outcome,
        });
        const MAX_ACTION_HISTORY: usize = 100;
        if self.action_history.len() > MAX_ACTION_HISTORY {
            self.action_history
                .drain(..self.action_history.len() - MAX_ACTION_HISTORY);
        }
        if !self.paused {
            self.refresh();
        }
    }

    fn begin_pid_input(&mut self, digit: char) {
        self.pid_input = Some(digit.to_string());
        self.pid_input_error = None;
    }

    fn process_passes_filters(&self, pid: Pid) -> bool {
        let Some(process) = self.processes.get(&pid) else {
            return false;
        };
        let Ok(filters) = CompiledProcessFilters::compile(&self.process_filters) else {
            return true;
        };
        let subtree = self.resources.get(&pid).copied().unwrap_or_default();
        let direct_children = self.children.get(&Some(pid)).map(Vec::len).unwrap_or(0);
        filters.matches(process, subtree, direct_children)
    }

    fn finish_pid_input(&mut self) {
        let Some(input) = self.pid_input.as_deref() else {
            return;
        };
        let pid_number = match input.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => {
                self.pid_input_error = Some(
                    text(
                        self.language(),
                        "PID must fit in an unsigned 32-bit number",
                        "PID 必须是有效的 32 位无符号整数",
                    )
                    .into(),
                );
                return;
            }
        };
        let pid = Pid::from_u32(pid_number);
        if !self.processes.contains_key(&pid) {
            self.pid_input_error = Some(match self.language() {
                UiLanguage::English => format!("PID {pid_number} is not visible"),
                UiLanguage::Chinese => format!("PID {pid_number} 当前不可见"),
            });
            return;
        }
        if !self.process_passes_filters(pid) {
            self.pid_input_error = Some(match self.language() {
                UiLanguage::English => {
                    format!("PID {pid_number} is hidden by process filters; press Esc then F")
                }
                UiLanguage::Chinese => {
                    format!("PID {pid_number} 已被进程过滤器隐藏；按 Esc 后再按 F 管理")
                }
            });
            return;
        }
        self.jump_to_process(pid);
    }

    fn guidance_error_notice(
        &mut self,
        english_action: &str,
        chinese_action: &str,
        error: std::io::Error,
    ) {
        self.notice = Some(StatusNotice {
            message: match self.language() {
                UiLanguage::English => {
                    format!("{english_action}, but the preference could not be saved: {error}")
                }
                UiLanguage::Chinese => format!("{chinese_action}，但无法保存偏好：{error}"),
            },
            is_error: true,
            observed_at: Instant::now(),
        });
    }

    fn dismiss_guidance(&mut self) {
        if let Err(error) = self.guidance.dismiss() {
            self.guidance_error_notice("Guidance closed", "引导已关闭", error);
        }
    }

    fn disable_startup_guidance(&mut self) {
        if let Err(error) = self.guidance.disable_startup() {
            self.guidance_error_notice(
                "Startup cards disabled for this session",
                "本次启动卡片已关闭",
                error,
            );
        } else {
            self.notice = Some(StatusNotice {
                message: text(
                    self.language(),
                    "Startup help and tips disabled; press ? then T to enable tips again",
                    "启动手册和提示已停用；按 ? 后再按 T 可重新启用",
                )
                .into(),
                is_error: false,
                observed_at: Instant::now(),
            });
        }
    }

    fn toggle_startup_tips(&mut self) {
        match self.guidance.toggle_tips() {
            Ok(enabled) => {
                self.notice = Some(StatusNotice {
                    message: match self.language() {
                        UiLanguage::English => format!(
                            "Startup tips {}",
                            if enabled { "enabled" } else { "disabled" }
                        ),
                        UiLanguage::Chinese => {
                            format!("启动提示已{}", if enabled { "启用" } else { "停用" })
                        }
                    },
                    is_error: false,
                    observed_at: Instant::now(),
                });
            }
            Err(error) => self.guidance_error_notice(
                "Tip preference changed for this session",
                "本次提示偏好已更改",
                error,
            ),
        }
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if key.code == KeyCode::F(2) && key.modifiers.is_empty() {
            self.toggle_language();
            return false;
        }
        if let Some(overlay) = self.guidance.overlay {
            if matches!(overlay, GuidanceOverlay::Tip(_)) {
                match key.code {
                    KeyCode::Char('q') => return true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    KeyCode::Esc | KeyCode::Enter => {
                        self.dismiss_guidance();
                        return false;
                    }
                    KeyCode::Char('d' | 'D') => {
                        self.disable_startup_guidance();
                        return false;
                    }
                    KeyCode::Char('t' | 'T') => {
                        self.toggle_startup_tips();
                        return false;
                    }
                    KeyCode::Char('?') => {
                        self.guidance.open_help();
                        return false;
                    }
                    KeyCode::Char('L') => {
                        self.toggle_language();
                        return false;
                    }
                    _ => self.dismiss_guidance(),
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => return true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    KeyCode::Esc | KeyCode::Enter => self.dismiss_guidance(),
                    KeyCode::Left | KeyCode::Up => self.guidance.previous_page(),
                    KeyCode::Right | KeyCode::Down | KeyCode::Tab => self.guidance.next_page(),
                    KeyCode::Char('d' | 'D') => self.disable_startup_guidance(),
                    KeyCode::Char('t' | 'T') => self.toggle_startup_tips(),
                    KeyCode::Char('L') => self.toggle_language(),
                    KeyCode::Char('?') if overlay == GuidanceOverlay::Help => {
                        self.dismiss_guidance();
                    }
                    _ => {}
                }
                return false;
            }
        }
        if !self.searching
            && !self.network_searching
            && !self.show_filter_manager
            && self.pid_input.is_none()
            && key.modifiers.is_empty()
            && key.code == KeyCode::Char('o')
        {
            self.export_diagnostic_report();
            return false;
        }
        if self.process_action.is_some() {
            let confirming = self
                .process_action
                .as_ref()
                .map(|dialog| dialog.confirming)
                .unwrap_or(false);
            if confirming {
                match key.code {
                    KeyCode::Char('q') => return true,
                    KeyCode::Esc => {
                        if let Some(dialog) = &mut self.process_action {
                            dialog.confirming = false;
                        }
                    }
                    KeyCode::Char('y') => self.execute_confirmed_process_action(),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => return true,
                    KeyCode::Esc => self.process_action = None,
                    KeyCode::Char('p')
                        if self
                            .process_action
                            .as_ref()
                            .is_some_and(|dialog| !dialog.is_termination_only()) =>
                    {
                        self.process_action = None;
                    }
                    KeyCode::Down | KeyCode::Tab => {
                        self.move_process_action_selection(1);
                    }
                    KeyCode::Up => self.move_process_action_selection(-1),
                    KeyCode::Enter => {
                        if let Some(dialog) = &mut self.process_action {
                            dialog.confirming = true;
                        }
                    }
                    KeyCode::Char('t') => {
                        self.choose_process_action(ProcessActionKind::Terminate);
                    }
                    KeyCode::Char('k') => self.choose_process_action(ProcessActionKind::Kill),
                    KeyCode::Char('s') => self.choose_process_action(ProcessActionKind::Stop),
                    KeyCode::Char('c') if key.modifiers.is_empty() => {
                        self.choose_process_action(ProcessActionKind::Continue);
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
            }
            return false;
        }
        if self.pid_input.is_some() {
            match key.code {
                KeyCode::Esc => {
                    self.pid_input = None;
                    self.pid_input_error = None;
                }
                KeyCode::Enter => self.finish_pid_input(),
                KeyCode::Backspace => {
                    if let Some(input) = &mut self.pid_input {
                        input.pop();
                    }
                    self.pid_input_error = None;
                }
                KeyCode::Char(c) if c.is_ascii_digit() && key.modifiers.is_empty() => {
                    if let Some(input) = &mut self.pid_input {
                        input.push(c);
                    }
                    self.pid_input_error = None;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return true;
                }
                _ => {}
            }
            return false;
        }
        if self.show_filter_manager {
            if let Some(editor) = &mut self.filter_editor {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    KeyCode::Esc => self.filter_editor = None,
                    KeyCode::Enter => self.apply_filter_editor(),
                    KeyCode::Tab => editor.action = editor.action.toggle(),
                    KeyCode::Backspace => {
                        editor.input.pop();
                        editor.error = None;
                    }
                    KeyCode::Char(character) if key.modifiers.is_empty() => {
                        editor.input.push(character);
                        editor.error = None;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => return true,
                    KeyCode::Esc | KeyCode::Char('F') => self.close_filter_manager(),
                    KeyCode::Char('a') => self.start_filter_editor(FilterAction::Include),
                    KeyCode::Char('x') => self.start_filter_editor(FilterAction::Exclude),
                    KeyCode::Char('e') | KeyCode::Enter => self.edit_selected_filter(),
                    KeyCode::Char(' ') => self.toggle_selected_filter(),
                    KeyCode::Char('d') | KeyCode::Delete => self.remove_selected_filter(),
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.filter_selected = (self.filter_selected + 1)
                            .min(self.process_filters.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.filter_selected = self.filter_selected.saturating_sub(1);
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
            }
            return false;
        }
        if self.show_attention {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('a') => {
                    self.show_attention = false;
                    self.attention_selected = None;
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_attention_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_attention_selection(-1),
                KeyCode::PageDown => self.move_attention_selection(10),
                KeyCode::PageUp => self.move_attention_selection(-10),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Enter => {
                    if let Some(pid) = self.attention_selected {
                        self.jump_to_process(pid);
                    }
                }
                KeyCode::Char('t') => self.open_attention_trend(),
                KeyCode::Char('i') => self.inspect_attention_process(),
                KeyCode::Char('p') => {
                    if let Some(pid) = self.attention_selected {
                        self.open_process_action_for(pid);
                    }
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_hotspots {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('h') => {
                    self.show_hotspots = false;
                    self.hotspot_selected = None;
                }
                KeyCode::Left => {
                    self.select_hotspot_metric(self.hotspot_metric.previous());
                }
                KeyCode::Right | KeyCode::Tab => {
                    self.select_hotspot_metric(self.hotspot_metric.next());
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_hotspot_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_hotspot_selection(-1),
                KeyCode::PageDown => self.move_hotspot_selection(10),
                KeyCode::PageUp => self.move_hotspot_selection(-10),
                KeyCode::Char('v') => {
                    self.hotspot_scope.toggle();
                    self.reset_hotspot_selection();
                }
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Enter => {
                    if let Some(pid) = self.hotspot_selected {
                        self.jump_to_process(pid);
                    }
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_snapshot_diff {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('d') => {
                    self.show_snapshot_diff = false;
                    self.snapshot_diff_scroll = 0;
                }
                KeyCode::Char('b') => self.capture_baseline(),
                KeyCode::Char('x') => {
                    self.baseline = None;
                    self.show_snapshot_diff = false;
                    self.snapshot_diff_scroll = 0;
                }
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_sub(10);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_network {
            if self.network_searching {
                match key.code {
                    KeyCode::Esc => {
                        self.network_searching = false;
                        self.network_filter.clear();
                        self.network_selected = 0;
                    }
                    KeyCode::Enter => self.network_searching = false,
                    KeyCode::Backspace => {
                        self.network_filter.pop();
                        self.network_selected = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => self.move_network_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => self.move_network_selection(-1),
                    KeyCode::PageDown => self.move_network_selection(10),
                    KeyCode::PageUp => self.move_network_selection(-10),
                    KeyCode::Char(c) if key.modifiers.is_empty() => {
                        self.network_filter.push(c);
                        self.network_selected = 0;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
                return false;
            }
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('n') => {
                    self.show_network = false;
                    self.network_filter.clear();
                    self.network_searching = false;
                }
                KeyCode::Char('r') => self.refresh_network(),
                KeyCode::Char('/') => {
                    self.network_searching = true;
                    self.network_filter.clear();
                    self.network_selected = 0;
                }
                KeyCode::Char('x') => {
                    self.network_filter.clear();
                    self.network_selected = 0;
                }
                KeyCode::Char('v') => {
                    self.network_scope.toggle();
                    self.network_selected = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_network_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_network_selection(-1),
                KeyCode::PageDown => self.move_network_selection(10),
                KeyCode::PageUp => self.move_network_selection(-10),
                KeyCode::Enter => {
                    let pid = self
                        .network_visible_indices()
                        .get(self.network_selected)
                        .and_then(|index| {
                            self.network_scan
                                .as_ref()
                                .and_then(|scan| scan.endpoints.get(*index))
                        })
                        .and_then(|listener| listener.pid);
                    if let Some(pid) = pid {
                        self.jump_to_process(pid);
                    }
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.trend_pid.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('t') => self.trend_pid = None,
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char('i') => self.trend_view.toggle(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.dossier_context.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('D') => self.close_dossier_context(),
                KeyCode::Char('i') => {
                    self.close_dossier_context();
                    self.open_inspection();
                }
                KeyCode::Char('m') => {
                    self.close_dossier_context();
                    self.open_service_context();
                }
                KeyCode::Char('v') => {
                    self.close_dossier_context();
                    self.open_executable_context();
                }
                KeyCode::Char('l') => {
                    self.close_dossier_context();
                    self.open_logs_context();
                }
                KeyCode::Char('M') => {
                    self.close_dossier_context();
                    self.open_memory_context();
                }
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_dossier_context(),
                KeyCode::Char('h') => self.toggle_dossier_hash(),
                KeyCode::Char('L') => self.toggle_dossier_logs(),
                KeyCode::Char('s') => self.cycle_dossier_scope(),
                KeyCode::Char('p') => self.cycle_dossier_priority(),
                KeyCode::Char('w') => self.cycle_dossier_window(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.memory_context.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('M') => self.close_memory_context(),
                KeyCode::Char('D') => {
                    self.close_memory_context();
                    self.open_dossier_context();
                }
                KeyCode::Char('i') => {
                    self.close_memory_context();
                    self.open_inspection();
                }
                KeyCode::Char('m') => {
                    self.close_memory_context();
                    self.open_service_context();
                }
                KeyCode::Char('v') => {
                    self.close_memory_context();
                    self.open_executable_context();
                }
                KeyCode::Char('l') => {
                    self.close_memory_context();
                    self.open_logs_context();
                }
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_memory_context(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.logs_context.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('l') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                }
                KeyCode::Char('m') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                    self.open_service_context();
                }
                KeyCode::Char('v') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                    self.open_executable_context();
                }
                KeyCode::Char('D') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_logs_context(),
                KeyCode::Char('s') => self.cycle_logs_scope(),
                KeyCode::Char('p') => self.cycle_logs_priority(),
                KeyCode::Char('w') => self.cycle_logs_window(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.service_context.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('m') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                }
                KeyCode::Char('v') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                    self.open_executable_context();
                }
                KeyCode::Char('l') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                    self.open_logs_context();
                }
                KeyCode::Char('D') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_service_context(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.service_context_scroll = self.service_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.service_context_scroll = self.service_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.service_context_scroll = self.service_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.service_context_scroll = self.service_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.executable_context.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('v') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                }
                KeyCode::Char('m') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                    self.open_service_context();
                }
                KeyCode::Char('l') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                    self.open_logs_context();
                }
                KeyCode::Char('D') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_executable_context(),
                KeyCode::Char('h') => self.toggle_executable_hash(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.inspection.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc => {
                    self.inspection = None;
                    self.inspection_task = None;
                    self.inspection_scroll = 0;
                }
                KeyCode::Char('D') => {
                    self.inspection = None;
                    self.inspection_task = None;
                    self.inspection_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_inspection(),
                KeyCode::Tab => {
                    self.inspection_tab = self.inspection_tab.next();
                    self.inspection_scroll = 0;
                }
                KeyCode::BackTab => {
                    self.inspection_tab = self.inspection_tab.previous();
                    self.inspection_scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.inspection_scroll = self.inspection_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.inspection_scroll = self.inspection_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.inspection_scroll = self.inspection_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.inspection_scroll = self.inspection_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_events {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('e') => self.show_events = false,
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.search_input.clear();
                }
                KeyCode::Enter => self.apply_search_input(),
                KeyCode::Backspace => {
                    self.search_input.pop();
                }
                KeyCode::Char(c) if key.modifiers.is_empty() => {
                    self.search_input.push(c);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Esc if !self.search.is_empty() => {
                self.search.clear();
                self.rebuild_visible();
            }
            KeyCode::Char('q') => return true,
            // Escape is intentionally inert on the bare process tree. It is
            // reserved for cancelling input, clearing search, and closing
            // overlays so an extra key press cannot terminate psmore.
            KeyCode::Esc => {}
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.page_size as isize),
            KeyCode::PageUp => self.move_selection(-(self.page_size as isize)),
            KeyCode::Left => {
                self.reveal_parent();
            }
            KeyCode::Right => self.toggle_selected_expanded(),
            KeyCode::Char('/') => {
                self.searching = true;
                self.search_input.clear();
            }
            KeyCode::Char(c) if c.is_ascii_digit() && key.modifiers.is_empty() => {
                self.begin_pid_input(c);
            }
            KeyCode::Char('f') => self.toggle_focus(),
            KeyCode::Char('F') => self.open_filter_manager(),
            KeyCode::Char('s') => self.cycle_sort_mode(),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char(' ') => self.toggle_paused(),
            KeyCode::Char('e') => {
                self.show_events = true;
                self.inspection = None;
                self.inspection_task = None;
            }
            KeyCode::Char('t') => {
                self.trend_pid = self.selected_pid();
                self.trend_view = TrendView::default();
                self.show_events = false;
                self.inspection = None;
                self.inspection_task = None;
            }
            KeyCode::Char('b') => self.capture_baseline(),
            KeyCode::Char('d') if self.baseline.is_some() => {
                self.show_snapshot_diff = true;
                self.snapshot_diff_scroll = 0;
                self.show_events = false;
                self.inspection = None;
                self.inspection_task = None;
                self.trend_pid = None;
            }
            KeyCode::Char('x') => {
                self.baseline = None;
                self.show_snapshot_diff = false;
                self.snapshot_diff_scroll = 0;
            }
            KeyCode::Char('n') => self.open_network(),
            KeyCode::Char('h') => self.open_hotspots(),
            KeyCode::Char('a') => self.open_attention(),
            KeyCode::Char('D') => self.open_dossier_context(),
            KeyCode::Char('M') => self.open_memory_context(),
            KeyCode::Char('m') => self.open_service_context(),
            KeyCode::Char('v') => self.open_executable_context(),
            KeyCode::Char('l') => self.open_logs_context(),
            KeyCode::Char('L') => self.toggle_language(),
            KeyCode::Char('k') => self.open_selected_process_termination(),
            KeyCode::Char('p') => self.open_selected_process_action(),
            KeyCode::Char('?') => self.guidance.open_help(),
            KeyCode::Enter => self.open_inspection(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        false
    }
}
