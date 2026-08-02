#[cfg(target_os = "linux")]
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::System;

use crate::{
    cli::CheckExpectation,
    headless::human_bytes,
    model::{command_for_output, sanitize_terminal_text},
    provider::platform_name,
};

#[cfg(target_os = "linux")]
use crate::{
    headless::{CurrentProcessExclusion, capture_snapshot},
    model::{process_command_line, process_path},
    query::ProcessQuery,
};

const OOM_SCHEMA: &str = "psmore.oom-diagnostics";
const OOM_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OomPolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl OomPolicyStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Passed => "pass",
            Self::Violated => "fail",
            Self::Inconclusive => "inconclusive",
        }
    }

    fn passed(self) -> Option<bool> {
        match self {
            Self::Passed => Some(true),
            Self::Violated => Some(false),
            Self::Inconclusive => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionPriority {
    Protected,
    VeryHigh,
    High,
    Elevated,
    Low,
}

impl SelectionPriority {
    fn classify(score: u16, adjustment: Option<i16>) -> Self {
        if adjustment == Some(-1_000) {
            Self::Protected
        } else if score >= 750 {
            Self::VeryHigh
        } else if score >= 500 {
            Self::High
        } else if score >= 250 {
            Self::Elevated
        } else {
            Self::Low
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Protected => "protected",
            Self::VeryHigh => "very_high",
            Self::High => "high",
            Self::Elevated => "elevated",
            Self::Low => "low",
        }
    }

    fn table_label(self) -> &'static str {
        match self {
            Self::Protected => "PROTECTED",
            Self::VeryHigh => "VERY_HIGH",
            Self::High => "HIGH",
            Self::Elevated => "ELEVATED",
            Self::Low => "low",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
struct HostMemoryEvidence {
    total_bytes: Option<u64>,
    available_bytes: Option<u64>,
    swap_total_bytes: Option<u64>,
    swap_free_bytes: Option<u64>,
    pressure: Option<MemoryPressure>,
    oom_kill_count_since_boot: Option<u64>,
}

impl HostMemoryEvidence {
    fn available_percent(&self) -> Option<f64> {
        let total = self.total_bytes?;
        let available = self.available_bytes?;
        (total > 0).then_some(available as f64 * 100.0 / total as f64)
    }

    fn swap_used_bytes(&self) -> Option<u64> {
        Some(self.swap_total_bytes?.saturating_sub(self.swap_free_bytes?))
    }
}

#[derive(Clone, Debug, PartialEq)]
struct MemoryPressure {
    some: PressureSample,
    full: PressureSample,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct PressureSample {
    avg10: f64,
    avg60: f64,
    avg300: f64,
    total_stall_microseconds: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct CgroupMemoryEvidence {
    path: String,
    current_bytes: Option<u64>,
    maximum_bytes: Option<u64>,
    maximum_unlimited: bool,
    oom_event_count: Option<u64>,
    oom_kill_count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
struct OomCandidate {
    pid: u32,
    parent_pid: Option<u32>,
    process: String,
    command: String,
    path: String,
    user: String,
    status: String,
    oom_score: u16,
    oom_score_adj: Option<i16>,
    rss_bytes: u64,
    swap_bytes: Option<u64>,
    cgroup: Option<CgroupMemoryEvidence>,
}

impl OomCandidate {
    fn priority(&self) -> SelectionPriority {
        SelectionPriority::classify(self.oom_score, self.oom_score_adj)
    }
}

pub(crate) struct CapturedOomDiagnostics {
    generated_at_unix_ms: u64,
    sample_interval_ms: u64,
    query: String,
    minimum_score: u16,
    result_limit: Option<usize>,
    system_process_count: usize,
    query_matched_process_count: usize,
    score_inspected_process_count: usize,
    score_selection_complete: bool,
    adjustment_coverage_count: usize,
    swap_coverage_count: usize,
    cgroup_coverage_count: usize,
    host: HostMemoryEvidence,
    entries: Vec<OomCandidate>,
    warning: Option<String>,
}

impl CapturedOomDiagnostics {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> OomPolicyStatus {
        if !self.entries.is_empty() {
            if expectation.passes(self.entries.len()) {
                OomPolicyStatus::Passed
            } else {
                OomPolicyStatus::Violated
            }
        } else if !self.score_selection_complete {
            OomPolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            OomPolicyStatus::Passed
        } else {
            OomPolicyStatus::Violated
        }
    }

    fn returned_count(&self) -> usize {
        self.result_limit
            .unwrap_or(self.entries.len())
            .min(self.entries.len())
    }

    fn visible_entries(&self) -> impl Iterator<Item = &OomCandidate> {
        self.entries.iter().take(self.returned_count())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn diagnostic_summary(&self) -> OomDiagnosticSummary {
        OomDiagnosticSummary {
            available_memory_bytes: self.host.available_bytes,
            available_memory_percent: self.host.available_percent(),
            oom_kill_count_since_boot: self.host.oom_kill_count_since_boot,
            pressure: self
                .host
                .pressure
                .as_ref()
                .map(|pressure| OomPressureSummary {
                    some_avg10_percent: pressure.some.avg10,
                    some_avg60_percent: pressure.some.avg60,
                    full_avg10_percent: pressure.full.avg10,
                    full_avg60_percent: pressure.full.avg60,
                }),
            matched_candidate_count: self.entries.len(),
            score_inspected_process_count: self.score_inspected_process_count,
            score_selection_complete: self.score_selection_complete,
            warning: self.warning.clone(),
            candidates: self
                .visible_entries()
                .map(|candidate| OomDiagnosticCandidate {
                    pid: candidate.pid,
                    process: candidate.process.clone(),
                    user: candidate.user.clone(),
                    command: candidate.command.clone(),
                    oom_score: candidate.oom_score,
                    oom_score_adj: candidate.oom_score_adj,
                    selection_priority: candidate.priority().label(),
                    rss_bytes: candidate.rss_bytes,
                    swap_bytes: candidate.swap_bytes,
                    cgroup_path: candidate.cgroup.as_ref().map(|cgroup| cgroup.path.clone()),
                    cgroup_oom_event_count: candidate
                        .cgroup
                        .as_ref()
                        .and_then(|cgroup| cgroup.oom_event_count),
                    cgroup_oom_kill_count: candidate
                        .cgroup
                        .as_ref()
                        .and_then(|cgroup| cgroup.oom_kill_count),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OomDiagnosticSummary {
    pub(crate) available_memory_bytes: Option<u64>,
    pub(crate) available_memory_percent: Option<f64>,
    pub(crate) oom_kill_count_since_boot: Option<u64>,
    pub(crate) pressure: Option<OomPressureSummary>,
    pub(crate) matched_candidate_count: usize,
    pub(crate) score_inspected_process_count: usize,
    pub(crate) score_selection_complete: bool,
    pub(crate) warning: Option<String>,
    pub(crate) candidates: Vec<OomDiagnosticCandidate>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OomPressureSummary {
    pub(crate) some_avg10_percent: f64,
    pub(crate) some_avg60_percent: f64,
    pub(crate) full_avg10_percent: f64,
    pub(crate) full_avg60_percent: f64,
}

#[derive(Clone, Debug)]
pub(crate) struct OomDiagnosticCandidate {
    pub(crate) pid: u32,
    pub(crate) process: String,
    pub(crate) user: String,
    pub(crate) command: String,
    pub(crate) oom_score: u16,
    pub(crate) oom_score_adj: Option<i16>,
    pub(crate) selection_priority: &'static str,
    pub(crate) rss_bytes: u64,
    pub(crate) swap_bytes: Option<u64>,
    pub(crate) cgroup_path: Option<String>,
    pub(crate) cgroup_oom_event_count: Option<u64>,
    pub(crate) cgroup_oom_kill_count: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
fn parse_kib_value(value: &str) -> Option<u64> {
    let mut fields = value.split_whitespace();
    let amount = fields.next()?.parse::<u64>().ok()?;
    let unit = fields.next().unwrap_or("kB");
    match unit {
        "kB" | "KB" | "kb" => amount.checked_mul(1_024),
        "B" | "b" => Some(amount),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_meminfo(content: &str) -> HostMemoryEvidence {
    let mut evidence = HostMemoryEvidence::default();
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key {
            "MemTotal" => evidence.total_bytes = parse_kib_value(value),
            "MemAvailable" => evidence.available_bytes = parse_kib_value(value),
            "SwapTotal" => evidence.swap_total_bytes = parse_kib_value(value),
            "SwapFree" => evidence.swap_free_bytes = parse_kib_value(value),
            _ => {}
        }
    }
    evidence
}

#[cfg(any(target_os = "linux", test))]
fn parse_pressure_sample(line: &str, expected_kind: &str) -> Option<PressureSample> {
    let mut fields = line.split_whitespace();
    if fields.next()? != expected_kind {
        return None;
    }
    let mut sample = PressureSample::default();
    let mut seen = 0_u8;
    for field in fields {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "avg10" => {
                sample.avg10 = value.parse().ok()?;
                seen |= 1;
            }
            "avg60" => {
                sample.avg60 = value.parse().ok()?;
                seen |= 2;
            }
            "avg300" => {
                sample.avg300 = value.parse().ok()?;
                seen |= 4;
            }
            "total" => {
                sample.total_stall_microseconds = value.parse().ok()?;
                seen |= 8;
            }
            _ => {}
        }
    }
    (seen == 15).then_some(sample)
}

#[cfg(any(target_os = "linux", test))]
fn parse_memory_pressure(content: &str) -> Option<MemoryPressure> {
    let some = content
        .lines()
        .find_map(|line| parse_pressure_sample(line, "some"))?;
    let full = content
        .lines()
        .find_map(|line| parse_pressure_sample(line, "full"))?;
    Some(MemoryPressure { some, full })
}

#[cfg(any(target_os = "linux", test))]
fn parse_vmstat_oom_kill(content: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "oom_kill")
            .then(|| fields.next()?.parse().ok())
            .flatten()
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_status_swap(content: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == "VmSwap").then(|| parse_kib_value(value)).flatten()
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_path(content: &str) -> Option<(String, bool)> {
    let mut v1_memory = None;
    for line in content.lines() {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        if controllers.is_empty() {
            return Some((path.to_string(), true));
        }
        if controllers
            .split(',')
            .any(|controller| controller == "memory")
        {
            v1_memory = Some((path.to_string(), false));
        }
    }
    v1_memory
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_events(content: &str) -> (Option<u64>, Option<u64>) {
    let mut oom = None;
    let mut oom_kill = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        match fields.next() {
            Some("oom") => oom = fields.next().and_then(|value| value.parse().ok()),
            Some("oom_kill") => oom_kill = fields.next().and_then(|value| value.parse().ok()),
            _ => {}
        }
    }
    (oom, oom_kill)
}

#[cfg(target_os = "linux")]
fn read_number(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn cgroup_root(path: &str, unified: bool) -> PathBuf {
    let mut root = if unified {
        PathBuf::from("/sys/fs/cgroup")
    } else {
        PathBuf::from("/sys/fs/cgroup/memory")
    };
    let relative = path.trim_start_matches('/');
    if !relative.is_empty() {
        root.push(relative);
    }
    root
}

#[cfg(target_os = "linux")]
fn collect_cgroup_memory(
    pid: u32,
    cache: &mut HashMap<(String, bool), CgroupMemoryEvidence>,
) -> Option<CgroupMemoryEvidence> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let (path, unified) = parse_cgroup_path(&cgroup)?;
    if let Some(cached) = cache.get(&(path.clone(), unified)) {
        return Some(cached.clone());
    }
    let root = cgroup_root(&path, unified);
    let (current_name, maximum_name) = if unified {
        ("memory.current", "memory.max")
    } else {
        ("memory.usage_in_bytes", "memory.limit_in_bytes")
    };
    let maximum_raw = fs::read_to_string(root.join(maximum_name)).ok();
    let maximum_unlimited = maximum_raw
        .as_deref()
        .map(str::trim)
        .map(|value| value == "max")
        .unwrap_or(false);
    let maximum_bytes = maximum_raw
        .as_deref()
        .map(str::trim)
        .and_then(|value| value.parse().ok());
    let (oom_event_count, oom_kill_count) = if unified {
        fs::read_to_string(root.join("memory.events"))
            .ok()
            .map(|events| parse_cgroup_events(&events))
            .unwrap_or_default()
    } else {
        (read_number(&root.join("memory.failcnt")), None)
    };
    let evidence = CgroupMemoryEvidence {
        path: path.clone(),
        current_bytes: read_number(&root.join(current_name)),
        maximum_bytes,
        maximum_unlimited,
        oom_event_count,
        oom_kill_count,
    };
    cache.insert((path, unified), evidence.clone());
    Some(evidence)
}

#[cfg(target_os = "linux")]
fn collect_host_memory() -> HostMemoryEvidence {
    let mut evidence = fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|content| parse_meminfo(&content))
        .unwrap_or_default();
    evidence.pressure = fs::read_to_string("/proc/pressure/memory")
        .ok()
        .and_then(|content| parse_memory_pressure(&content));
    evidence.oom_kill_count_since_boot = fs::read_to_string("/proc/vmstat")
        .ok()
        .and_then(|content| parse_vmstat_oom_kill(&content));
    evidence
}

#[cfg(target_os = "linux")]
fn read_oom_score(pid: u32) -> io::Result<u16> {
    let raw = fs::read_to_string(format!("/proc/{pid}/oom_score"))?;
    raw.trim().parse::<u16>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid oom_score for PID {pid}: {error}"),
        )
    })
}

#[cfg(target_os = "linux")]
fn read_oom_score_adj(pid: u32) -> Option<i16> {
    fs::read_to_string(format!("/proc/{pid}/oom_score_adj"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn capture_linux(
    query: &str,
    sample_interval_ms: u64,
    minimum_score: u16,
    result_limit: Option<usize>,
) -> Result<CapturedOomDiagnostics, String> {
    let parsed_query = ProcessQuery::parse(query)?;
    let snapshot = capture_snapshot(sample_interval_ms);
    let collector = CurrentProcessExclusion::capture(&snapshot);
    let mut matching_pids: Vec<_> = collector
        .matching_pid_set(&snapshot, &parsed_query)
        .into_iter()
        .collect();
    matching_pids.sort_by_key(|pid| pid.as_u32());
    let query_matched_process_count = matching_pids.len();
    let mut score_inspected_process_count = 0_usize;
    let mut score_unavailable = 0_usize;
    let mut adjustment_coverage_count = 0_usize;
    let mut swap_coverage_count = 0_usize;
    let mut cgroup_coverage_count = 0_usize;
    let mut cgroup_cache = HashMap::new();
    let mut entries = Vec::new();
    for pid in matching_pids {
        let pid_u32 = pid.as_u32();
        let score = match read_oom_score(pid_u32) {
            Ok(score) => {
                score_inspected_process_count += 1;
                score
            }
            Err(_) => {
                score_unavailable += 1;
                continue;
            }
        };
        if score < minimum_score {
            continue;
        }
        let Some(process) = snapshot.process(pid) else {
            score_unavailable += 1;
            continue;
        };
        let oom_score_adj = read_oom_score_adj(pid_u32);
        adjustment_coverage_count += usize::from(oom_score_adj.is_some());
        let swap_bytes = fs::read_to_string(format!("/proc/{pid_u32}/status"))
            .ok()
            .and_then(|status| parse_status_swap(&status));
        swap_coverage_count += usize::from(swap_bytes.is_some());
        let cgroup = collect_cgroup_memory(pid_u32, &mut cgroup_cache);
        cgroup_coverage_count += usize::from(cgroup.is_some());
        entries.push(OomCandidate {
            pid: pid_u32,
            parent_pid: process.parent.map(sysinfo::Pid::as_u32),
            process: process.name.clone(),
            command: process_command_line(process),
            path: process_path(process),
            user: process.user.clone(),
            status: process.status.clone(),
            oom_score: score,
            oom_score_adj,
            rss_bytes: process.memory,
            swap_bytes,
            cgroup,
        });
    }
    entries.sort_by(|left, right| {
        right
            .oom_score
            .cmp(&left.oom_score)
            .then_with(|| right.oom_score_adj.cmp(&left.oom_score_adj))
            .then_with(|| {
                right
                    .rss_bytes
                    .saturating_add(right.swap_bytes.unwrap_or(0))
                    .cmp(&left.rss_bytes.saturating_add(left.swap_bytes.unwrap_or(0)))
            })
            .then_with(|| {
                (left.process.to_lowercase(), left.pid)
                    .cmp(&(right.process.to_lowercase(), right.pid))
            })
    });
    let warning = (score_unavailable > 0).then(|| {
        format!(
            "oom_score became unreadable for {score_unavailable} query-matched process(es); zero matches cannot prove absence"
        )
    });
    Ok(CapturedOomDiagnostics {
        generated_at_unix_ms: unix_millis(),
        sample_interval_ms,
        query: query.to_string(),
        minimum_score,
        result_limit,
        system_process_count: snapshot.real_process_count().saturating_sub(usize::from(
            snapshot
                .process(sysinfo::Pid::from_u32(std::process::id()))
                .is_some(),
        )),
        query_matched_process_count,
        score_inspected_process_count,
        score_selection_complete: score_unavailable == 0,
        adjustment_coverage_count,
        swap_coverage_count,
        cgroup_coverage_count,
        host: collect_host_memory(),
        entries,
        warning,
    })
}

pub(crate) fn capture_oom_diagnostics(
    query: &str,
    sample_interval_ms: u64,
    minimum_score: u16,
    result_limit: Option<usize>,
) -> Result<CapturedOomDiagnostics, String> {
    #[cfg(target_os = "linux")]
    {
        capture_linux(query, sample_interval_ms, minimum_score, result_limit)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (query, sample_interval_ms, minimum_score, result_limit);
        Err("oom diagnostics are only supported on Linux; use 'psmore top --by memory' on this platform".into())
    }
}

#[derive(Debug, Serialize)]
struct JsonOomDiagnostics<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    sample_interval_ms: u64,
    query: Option<JsonQuery>,
    minimum_oom_score: u16,
    result_limit: Option<usize>,
    system_process_count: usize,
    query_matched_process_count: usize,
    score_inspected_process_count: usize,
    matched_candidate_count: usize,
    returned_candidate_count: usize,
    rows_truncated: bool,
    score_selection_complete: bool,
    adjustment_coverage_count: usize,
    swap_coverage_count: usize,
    cgroup_coverage_count: usize,
    interpretation: &'static str,
    host_memory: JsonHostMemory,
    policy: Option<JsonPolicy<'a>>,
    warning: Option<&'a str>,
    candidates: Vec<JsonCandidate<'a>>,
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
struct JsonPolicy<'a> {
    expectation: &'a str,
    status: &'static str,
    passed: Option<bool>,
    detail: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct JsonHostMemory {
    total_bytes: Option<u64>,
    available_bytes: Option<u64>,
    available_percent: Option<f64>,
    swap_total_bytes: Option<u64>,
    swap_free_bytes: Option<u64>,
    swap_used_bytes: Option<u64>,
    pressure: Option<JsonMemoryPressure>,
    oom_kill_count_since_boot: Option<u64>,
}

#[derive(Debug, Serialize)]
struct JsonMemoryPressure {
    some: JsonPressureSample,
    full: JsonPressureSample,
}

#[derive(Debug, Serialize)]
struct JsonPressureSample {
    avg10_percent: f64,
    avg60_percent: f64,
    avg300_percent: f64,
    total_stall_microseconds: u64,
}

impl From<&PressureSample> for JsonPressureSample {
    fn from(sample: &PressureSample) -> Self {
        Self {
            avg10_percent: sample.avg10,
            avg60_percent: sample.avg60,
            avg300_percent: sample.avg300,
            total_stall_microseconds: sample.total_stall_microseconds,
        }
    }
}

impl From<&HostMemoryEvidence> for JsonHostMemory {
    fn from(host: &HostMemoryEvidence) -> Self {
        Self {
            total_bytes: host.total_bytes,
            available_bytes: host.available_bytes,
            available_percent: host.available_percent(),
            swap_total_bytes: host.swap_total_bytes,
            swap_free_bytes: host.swap_free_bytes,
            swap_used_bytes: host.swap_used_bytes(),
            pressure: host.pressure.as_ref().map(|pressure| JsonMemoryPressure {
                some: (&pressure.some).into(),
                full: (&pressure.full).into(),
            }),
            oom_kill_count_since_boot: host.oom_kill_count_since_boot,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonCandidate<'a> {
    rank: usize,
    selection_priority: &'static str,
    oom_score: u16,
    oom_score_adj: Option<i16>,
    pid: u32,
    parent_pid: Option<u32>,
    process: &'a str,
    user: &'a str,
    status: &'a str,
    path: &'a str,
    command: String,
    rss_bytes: u64,
    swap_bytes: Option<u64>,
    cgroup: Option<JsonCgroup<'a>>,
}

#[derive(Debug, Serialize)]
struct JsonCgroup<'a> {
    path: &'a str,
    memory_current_bytes: Option<u64>,
    memory_maximum_bytes: Option<u64>,
    memory_maximum_unlimited: bool,
    oom_event_count: Option<u64>,
    oom_kill_count: Option<u64>,
}

pub(crate) fn render_oom_json(
    captured: &CapturedOomDiagnostics,
    expectation: Option<&str>,
    policy_status: Option<OomPolicyStatus>,
) -> Result<String, String> {
    let candidates = captured
        .visible_entries()
        .enumerate()
        .map(|(index, candidate)| JsonCandidate {
            rank: index + 1,
            selection_priority: candidate.priority().label(),
            oom_score: candidate.oom_score,
            oom_score_adj: candidate.oom_score_adj,
            pid: candidate.pid,
            parent_pid: candidate.parent_pid,
            process: &candidate.process,
            user: &candidate.user,
            status: &candidate.status,
            path: &candidate.path,
            command: command_for_output(&candidate.command),
            rss_bytes: candidate.rss_bytes,
            swap_bytes: candidate.swap_bytes,
            cgroup: candidate.cgroup.as_ref().map(|cgroup| JsonCgroup {
                path: &cgroup.path,
                memory_current_bytes: cgroup.current_bytes,
                memory_maximum_bytes: cgroup.maximum_bytes,
                memory_maximum_unlimited: cgroup.maximum_unlimited,
                oom_event_count: cgroup.oom_event_count,
                oom_kill_count: cgroup.oom_kill_count,
            }),
        })
        .collect();
    serde_json::to_string_pretty(&JsonOomDiagnostics {
        schema: OOM_SCHEMA,
        schema_version: OOM_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, path, and cgroup information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        sample_interval_ms: captured.sample_interval_ms,
        query: (!captured.query.is_empty()).then(|| JsonQuery {
            input: captured.query.clone(),
        }),
        minimum_oom_score: captured.minimum_score,
        result_limit: captured.result_limit,
        system_process_count: captured.system_process_count,
        query_matched_process_count: captured.query_matched_process_count,
        score_inspected_process_count: captured.score_inspected_process_count,
        matched_candidate_count: captured.entries.len(),
        returned_candidate_count: captured.returned_count(),
        rows_truncated: captured.returned_count() < captured.entries.len(),
        score_selection_complete: captured.score_selection_complete,
        adjustment_coverage_count: captured.adjustment_coverage_count,
        swap_coverage_count: captured.swap_coverage_count,
        cgroup_coverage_count: captured.cgroup_coverage_count,
        interpretation: "oom_score is relative kernel kill-selection priority, not proof that memory pressure or an OOM kill is occurring",
        host_memory: (&captured.host).into(),
        policy: expectation
            .zip(policy_status)
            .map(|(expectation, status)| JsonPolicy {
                expectation,
                status: status.label(),
                passed: status.passed(),
                detail: (status == OomPolicyStatus::Inconclusive).then_some(
                    "zero visible candidates cannot prove absence because oom_score collection was incomplete",
                ),
            }),
        warning: captured.warning.as_deref(),
        candidates,
    })
    .map_err(|error| error.to_string())
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map(human_bytes).unwrap_or_else(|| "-".into())
}

fn optional_number<T: ToString>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

pub(crate) fn render_oom_table(
    captured: &CapturedOomDiagnostics,
    expectation: Option<&str>,
    policy_status: Option<OomPolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        output.push_str(&format!(
            "OOM CHECK {}  expected {}; matched {} candidate(s)\n",
            match status {
                OomPolicyStatus::Passed => "PASS",
                OomPolicyStatus::Violated => "FAIL",
                OomPolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.entries.len(),
        ));
    }
    let available = optional_bytes(captured.host.available_bytes);
    let total = optional_bytes(captured.host.total_bytes);
    let available_percent = captured
        .host
        .available_percent()
        .map(|value| format!("{value:.1}%"))
        .unwrap_or_else(|| "-".into());
    let swap_used = optional_bytes(captured.host.swap_used_bytes());
    let swap_total = optional_bytes(captured.host.swap_total_bytes);
    output.push_str(&format!(
        "HOST MEMORY  available {available}/{total} ({available_percent})  swap used {swap_used}/{swap_total}  oom_kill since boot {}\n",
        optional_number(captured.host.oom_kill_count_since_boot),
    ));
    if let Some(pressure) = &captured.host.pressure {
        output.push_str(&format!(
            "MEMORY PSI   some avg10/60/300 {:.2}/{:.2}/{:.2}%  full {:.2}/{:.2}/{:.2}%\n",
            pressure.some.avg10,
            pressure.some.avg60,
            pressure.some.avg300,
            pressure.full.avg10,
            pressure.full.avg60,
            pressure.full.avg300,
        ));
    } else {
        output.push_str("MEMORY PSI   unavailable\n");
    }
    output.push_str(&format!(
        "OOM CANDIDATES  {} matched / {} score-inspected / {} query-matched / {} system, showing {}, score >= {}\n",
        captured.entries.len(),
        captured.score_inspected_process_count,
        captured.query_matched_process_count,
        captured.system_process_count,
        captured.returned_count(),
        captured.minimum_score,
    ));
    output.push_str(&format!(
        "CONTEXT COVERAGE  adjustment {} / swap {} / cgroup {} candidate(s); score selection {}\n",
        captured.adjustment_coverage_count,
        captured.swap_coverage_count,
        captured.cgroup_coverage_count,
        if captured.score_selection_complete {
            "complete"
        } else {
            "incomplete"
        },
    ));
    if !captured.query.is_empty() {
        output.push_str(&format!(
            "query: {}\n",
            sanitize_terminal_text(&captured.query)
        ));
    }
    if captured.entries.is_empty() {
        output.push_str("  [no matching OOM candidate visible]\n");
    } else {
        output.push_str(
            " SCORE    ADJ PRIORITY         RSS      SWAP     PID    PPID USER         PROCESS      COMMAND\n",
        );
        for candidate in captured.visible_entries() {
            output.push_str(&format!(
                "{:>6} {:>6} {:<10} {:>9} {:>9} {:>7} {:>7} {:<12} {:<12} {}\n",
                candidate.oom_score,
                optional_number(candidate.oom_score_adj),
                candidate.priority().table_label(),
                human_bytes(candidate.rss_bytes),
                optional_bytes(candidate.swap_bytes),
                candidate.pid,
                candidate.parent_pid.unwrap_or(0),
                sanitize_terminal_text(&candidate.user),
                sanitize_terminal_text(&candidate.process),
                sanitize_terminal_text(&command_for_output(&candidate.command)),
            ));
            if let Some(cgroup) = &candidate.cgroup {
                let maximum = if cgroup.maximum_unlimited {
                    "unlimited".into()
                } else {
                    optional_bytes(cgroup.maximum_bytes)
                };
                output.push_str(&format!(
                    "        cgroup {}  memory {}/{}  events oom={} oom_kill={}\n",
                    sanitize_terminal_text(&cgroup.path),
                    optional_bytes(cgroup.current_bytes),
                    maximum,
                    optional_number(cgroup.oom_event_count),
                    optional_number(cgroup.oom_kill_count),
                ));
            }
        }
        if captured.returned_count() < captured.entries.len() {
            output.push_str(&format!(
                "  ... {} additional candidate(s) hidden; use --limit all\n",
                captured.entries.len() - captured.returned_count()
            ));
        }
    }
    output.push_str(
        "INTERPRET  oom_score ranks relative kill selection only. Confirm pressure with MemAvailable/PSI and confirm incidents with host or cgroup OOM counters.\n",
    );
    if let Some(warning) = &captured.warning {
        output.push_str(&format!("WARNING  {}\n", sanitize_terminal_text(warning)));
    }
    output
}

#[cfg(target_os = "linux")]
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn host() -> HostMemoryEvidence {
        HostMemoryEvidence {
            total_bytes: Some(8 * 1024 * 1024 * 1024),
            available_bytes: Some(2 * 1024 * 1024 * 1024),
            swap_total_bytes: Some(1024 * 1024 * 1024),
            swap_free_bytes: Some(256 * 1024 * 1024),
            pressure: Some(MemoryPressure {
                some: PressureSample {
                    avg10: 1.25,
                    avg60: 0.5,
                    avg300: 0.1,
                    total_stall_microseconds: 123,
                },
                full: PressureSample {
                    avg10: 0.25,
                    avg60: 0.1,
                    avg300: 0.0,
                    total_stall_microseconds: 45,
                },
            }),
            oom_kill_count_since_boot: Some(3),
        }
    }

    fn candidate(pid: u32, score: u16, adjustment: Option<i16>) -> OomCandidate {
        OomCandidate {
            pid,
            parent_pid: Some(1),
            process: "worker".into(),
            command: "/srv/worker\n--queue critical".into(),
            path: "/srv/worker".into(),
            user: "deploy".into(),
            status: "Sleep".into(),
            oom_score: score,
            oom_score_adj: adjustment,
            rss_bytes: 512 * 1024 * 1024,
            swap_bytes: Some(64 * 1024 * 1024),
            cgroup: Some(CgroupMemoryEvidence {
                path: "/system.slice/api.service".into(),
                current_bytes: Some(768 * 1024 * 1024),
                maximum_bytes: Some(1024 * 1024 * 1024),
                maximum_unlimited: false,
                oom_event_count: Some(2),
                oom_kill_count: Some(1),
            }),
        }
    }

    fn captured(entries: Vec<OomCandidate>, complete: bool) -> CapturedOomDiagnostics {
        CapturedOomDiagnostics {
            generated_at_unix_ms: 1_700_000_000_000,
            sample_interval_ms: 500,
            query: "user:deploy".into(),
            minimum_score: 500,
            result_limit: Some(1),
            system_process_count: 10,
            query_matched_process_count: 3,
            score_inspected_process_count: 3,
            score_selection_complete: complete,
            adjustment_coverage_count: 1,
            swap_coverage_count: 1,
            cgroup_coverage_count: 1,
            host: host(),
            entries,
            warning: (!complete).then(|| "one score unavailable".into()),
        }
    }

    #[test]
    fn parses_linux_memory_psi_status_and_cgroup_evidence() {
        let memory = parse_meminfo(
            "MemTotal:       8192 kB\nMemAvailable:   2048 kB\nSwapTotal:      1024 kB\nSwapFree:        256 kB\n",
        );
        assert_eq!(memory.total_bytes, Some(8 * 1024 * 1024));
        assert_eq!(memory.available_percent(), Some(25.0));
        assert_eq!(memory.swap_used_bytes(), Some(768 * 1024));

        let pressure = parse_memory_pressure(
            "some avg10=1.25 avg60=0.50 avg300=0.10 total=123\nfull avg10=0.25 avg60=0.10 avg300=0.00 total=45\n",
        )
        .unwrap();
        assert_eq!(pressure.some.avg10, 1.25);
        assert_eq!(pressure.full.total_stall_microseconds, 45);
        assert_eq!(parse_vmstat_oom_kill("pgfault 9\noom_kill 7\n"), Some(7));
        assert_eq!(
            parse_status_swap("Name:\tapi\nVmSwap:\t64 kB\n"),
            Some(65_536)
        );
        assert_eq!(
            parse_cgroup_path("0::/system.slice/api.service\n"),
            Some(("/system.slice/api.service".into(), true))
        );
        assert_eq!(
            parse_cgroup_events("oom 2\noom_kill 1\n"),
            (Some(2), Some(1))
        );
    }

    #[test]
    fn priority_is_explicitly_selection_not_fault_severity() {
        assert_eq!(
            SelectionPriority::classify(900, None),
            SelectionPriority::VeryHigh
        );
        assert_eq!(
            SelectionPriority::classify(600, Some(500)),
            SelectionPriority::High
        );
        assert_eq!(
            SelectionPriority::classify(300, None),
            SelectionPriority::Elevated
        );
        assert_eq!(
            SelectionPriority::classify(0, Some(-1_000)),
            SelectionPriority::Protected
        );
    }

    #[test]
    fn json_and_table_keep_host_candidate_and_cgroup_evidence() {
        let captured = captured(vec![candidate(42, 800, Some(500))], true);
        let json: Value = serde_json::from_str(
            &render_oom_json(
                &captured,
                Some("no matches"),
                Some(OomPolicyStatus::Violated),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], OOM_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["host_memory"]["available_percent"], 25.0);
        assert_eq!(
            json["host_memory"]["pressure"]["some"]["avg10_percent"],
            1.25
        );
        assert_eq!(json["candidates"][0]["selection_priority"], "very_high");
        assert_eq!(json["candidates"][0]["cgroup"]["oom_kill_count"], 1);
        assert_eq!(json["policy"]["passed"], false);

        let table = render_oom_table(&captured, None, None);
        assert!(table.contains("HOST MEMORY"));
        assert!(table.contains("MEMORY PSI"));
        assert!(table.contains("VERY_HIGH"));
        assert!(table.contains("/srv/worker --queue critical"));
        assert!(table.contains("events oom=2 oom_kill=1"));
        assert!(table.contains("relative kill selection only"));
    }

    #[test]
    fn zero_match_policy_is_inconclusive_when_score_coverage_is_incomplete() {
        let incomplete = captured(Vec::new(), false);
        assert_eq!(
            incomplete.evaluate_policy(CheckExpectation::None),
            OomPolicyStatus::Inconclusive
        );
        let complete = captured(Vec::new(), true);
        assert_eq!(
            complete.evaluate_policy(CheckExpectation::None),
            OomPolicyStatus::Passed
        );
        assert_eq!(
            complete.evaluate_policy(CheckExpectation::Any),
            OomPolicyStatus::Violated
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_linux_self_oom_files_are_readable() {
        let pid = std::process::id();
        assert!(read_oom_score(pid).is_ok());
        assert!(read_oom_score_adj(pid).is_some());
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(parse_status_swap(&status).is_some());
    }
}
