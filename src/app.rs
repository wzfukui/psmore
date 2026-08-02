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
        ProcessActionDialog, ProcessActionKind, ProcessActionRecord, ProcessActionTarget,
        execute_process_action,
    },
    history::ResourceHistory,
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

struct InspectionTask {
    receiver: Receiver<ProcessInspection>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
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
    pub(crate) search_error: Option<String>,
    pub(crate) search_matches: usize,
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
    pub(crate) inspection_scroll: u16,
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

    fn new_with_guidance(query: String, mut guidance: Guidance) -> Self {
        let has_initial_query = !query.is_empty();
        let guidance_warning = guidance.take_warning();
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
            search_error: None,
            search_matches: 0,
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
            inspection_scroll: 0,
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
                    message: format!(
                        "network scan complete: {endpoint_count} endpoints in {:.1}s",
                        elapsed.as_secs_f64()
                    ),
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
                    message: "network scan failed: background worker stopped".into(),
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

    fn rebuild_visible(&mut self) {
        let old_pid = self.visible.get(self.selected).map(|row| row.pid);
        self.visible.clear();
        let query = ProcessQuery::parse(&self.search);
        let matched: HashSet<Pid> = match query {
            Ok(query) => {
                self.search_error = None;
                self.processes
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
            self.walk_children(focus, chain.len(), vec![false; chain.len()], &matched);
        } else {
            let roots = [Pid::from_u32(0)];
            for (index, pid) in roots.iter().enumerate() {
                self.walk(*pid, Vec::new(), index == roots.len() - 1, &matched);
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

    fn walk(&mut self, pid: Pid, last_path: Vec<bool>, is_last: bool, matched: &HashSet<Pid>) {
        let has_match = matched.contains(&pid);
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let descendant_match = descendants
            .iter()
            .any(|child| self.has_matching_descendant(*child, matched));
        if has_match || descendant_match || self.search.is_empty() {
            let depth = last_path.len();
            self.visible.push(TreeRow {
                pid,
                depth,
                last_path: last_path.clone(),
                is_last,
            });
            if self.expanded.contains(&pid)
                || (!self.search.is_empty() && descendant_match && !self.collapsed.contains(&pid))
            {
                for (index, child) in descendants.iter().enumerate() {
                    let mut child_path = last_path.clone();
                    child_path.push(is_last);
                    if !self.search.is_empty() && has_match {
                        self.walk_context(*child, child_path, index == descendants.len() - 1);
                    } else {
                        self.walk(*child, child_path, index == descendants.len() - 1, matched);
                    }
                }
            }
        }
    }

    /// Once a search hit is visible, show its complete descendant context.
    /// Search still filters the ancestors and unrelated branches, but it must
    /// not hide the children that explain what the matched process owns.
    fn walk_context(&mut self, pid: Pid, last_path: Vec<bool>, is_last: bool) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let depth = last_path.len();
        self.visible.push(TreeRow {
            pid,
            depth,
            last_path: last_path.clone(),
            is_last,
        });
        if self.expanded.contains(&pid) && !self.collapsed.contains(&pid) {
            for (index, child) in descendants.iter().enumerate() {
                let mut child_path = last_path.clone();
                child_path.push(is_last);
                self.walk_context(*child, child_path, index == descendants.len() - 1);
            }
        }
    }

    fn walk_children(
        &mut self,
        pid: Pid,
        depth: usize,
        last_path: Vec<bool>,
        matched: &HashSet<Pid>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        for (index, child) in descendants.iter().enumerate() {
            if matched.contains(child)
                || self.search.is_empty()
                || self.has_matching_descendant(*child, matched)
            {
                let mut child_path = last_path.clone();
                child_path.push(index == descendants.len() - 1);
                self.visible.push(TreeRow {
                    pid: *child,
                    depth,
                    last_path: child_path.clone(),
                    is_last: index == descendants.len() - 1,
                });
                if self.expanded.contains(child)
                    || (self.search.is_empty() && !self.collapsed.contains(child))
                    || (!self.search.is_empty()
                        && self.has_matching_descendant(*child, matched)
                        && !self.collapsed.contains(child))
                {
                    self.walk_children(*child, depth + 1, child_path, matched);
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
                    query.matches(process, subtree, direct_children)
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

    fn finish_search(&mut self) {
        if !self.searching {
            return;
        }
        self.searching = false;
        self.search.clear();
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
                    action_history: &self.action_history,
                    baseline: self.baseline.as_ref(),
                },
                &directory,
            )
        });
        self.notice = Some(match result {
            Ok(path) => StatusNotice {
                message: format!("report saved: {}", path.display()),
                is_error: false,
                observed_at: Instant::now(),
            },
            Err(error) => StatusNotice {
                message: format!("report export failed: {error}"),
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
                    message: format!("cannot start network scan: {error}"),
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

    fn open_process_action_for(&mut self, pid: Pid) {
        let Some(process) = self.processes.get(&pid) else {
            self.notice = Some(StatusNotice {
                message: format!("cannot control PID {pid}: process is no longer visible"),
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        };
        if pid.as_u32() <= 1 || pid.as_u32() == std::process::id() {
            self.notice = Some(StatusNotice {
                message: format!(
                    "cannot control {} [{}]: protected process",
                    process.name, pid
                ),
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        }
        if process.start_time == 0 {
            self.notice = Some(StatusNotice {
                message: format!(
                    "cannot control {} [{}]: process instance identity is unavailable",
                    process.name, pid
                ),
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        }
        self.process_action = Some(ProcessActionDialog {
            target: ProcessActionTarget::from(process),
            selected: 0,
            confirming: false,
        });
    }

    fn open_selected_process_action(&mut self) {
        if let Some(pid) = self.selected_pid() {
            self.open_process_action_for(pid);
        }
    }

    fn move_process_action_selection(&mut self, delta: isize) {
        let Some(dialog) = &mut self.process_action else {
            return;
        };
        dialog.selected = (dialog.selected as isize + delta)
            .clamp(0, ProcessActionKind::ALL.len().saturating_sub(1) as isize)
            as usize;
        dialog.confirming = false;
    }

    fn choose_process_action(&mut self, action: ProcessActionKind) {
        let Some(dialog) = &mut self.process_action else {
            return;
        };
        if let Some(index) = ProcessActionKind::ALL
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
            message: format!(
                "{} {} to {} [{}]{}",
                outcome.label(),
                action.label(),
                target.name,
                target.pid,
                detail
            ),
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

    fn guidance_error_notice(&mut self, action: &str, error: std::io::Error) {
        self.notice = Some(StatusNotice {
            message: format!("{action}, but the preference could not be saved: {error}"),
            is_error: true,
            observed_at: Instant::now(),
        });
    }

    fn dismiss_guidance(&mut self) {
        if let Err(error) = self.guidance.dismiss() {
            self.guidance_error_notice("Guidance closed", error);
        }
    }

    fn disable_startup_guidance(&mut self) {
        if let Err(error) = self.guidance.disable_startup() {
            self.guidance_error_notice("Startup cards disabled for this session", error);
        } else {
            self.notice = Some(StatusNotice {
                message: "Startup help and tips disabled; press ? then T to enable tips again"
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
                    message: format!(
                        "Startup tips {}",
                        if enabled { "enabled" } else { "disabled" }
                    ),
                    is_error: false,
                    observed_at: Instant::now(),
                });
            }
            Err(error) => {
                self.guidance_error_notice("Tip preference changed for this session", error)
            }
        }
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
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
                    KeyCode::Esc | KeyCode::Char('p') => self.process_action = None,
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
        if self.inspection.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc => {
                    self.inspection = None;
                    self.inspection_task = None;
                    self.inspection_scroll = 0;
                }
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_inspection(),
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
                    self.search.clear();
                    self.rebuild_visible();
                }
                KeyCode::Enter => {
                    // `/` is a transient locator. Keep the selected process,
                    // then restore the complete tree for relationship work.
                    self.finish_search();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_selection(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_selection(-1);
                }
                KeyCode::PageDown => {
                    self.move_selection(self.page_size as isize);
                }
                KeyCode::PageUp => {
                    self.move_selection(-(self.page_size as isize));
                }
                KeyCode::Left => {
                    self.reveal_parent();
                }
                KeyCode::Right => {
                    self.toggle_selected_expanded();
                }
                KeyCode::Backspace => {
                    self.search.pop();
                    self.rebuild_visible();
                }
                KeyCode::Char(c) if key.modifiers.is_empty() => {
                    self.search.push(c);
                    self.rebuild_visible();
                    self.select_first_match();
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.page_size as isize),
            KeyCode::PageUp => self.move_selection(-(self.page_size as isize)),
            KeyCode::Left => {
                self.reveal_parent();
            }
            KeyCode::Right => self.toggle_selected_expanded(),
            KeyCode::Char('/') => {
                self.searching = true;
                self.search.clear();
                self.rebuild_visible();
            }
            KeyCode::Char('f') => self.toggle_focus(),
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
            KeyCode::Char('p') => self.open_selected_process_action(),
            KeyCode::Char('?') => self.guidance.open_help(),
            KeyCode::Enter => self.open_inspection(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        false
    }
}
