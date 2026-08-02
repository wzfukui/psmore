use std::{
    cmp::Ordering,
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(any(not(target_os = "linux"), test))]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(not(target_os = "linux"))]
use std::process::Command;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    cli::CheckExpectation,
    model::{ProcessInfo, command_for_output, process_command_line, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const FD_SCHEMA: &str = "psmore.fd-pressure";
const FD_SCHEMA_VERSION: u32 = 1;

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimitValue {
    Value(u64),
    Unlimited,
    Unknown,
}

impl LimitValue {
    fn numeric(self) -> Option<u64> {
        match self {
            Self::Value(value) => Some(value),
            Self::Unlimited | Self::Unknown => None,
        }
    }

    fn is_unlimited(self) -> bool {
        self == Self::Unlimited
    }

    fn table_label(self) -> String {
        match self {
            Self::Value(value) => value.to_string(),
            Self::Unlimited => "unlimited".into(),
            Self::Unknown => "-".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FdPressure {
    Critical,
    Warning,
    Elevated,
    Normal,
    Unknown,
}

impl FdPressure {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::Warning => "warning",
            Self::Elevated => "elevated",
            Self::Normal => "normal",
            Self::Unknown => "unknown",
        }
    }

    fn table_label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::Warning => "WARNING",
            Self::Elevated => "ELEVATED",
            Self::Normal => "normal",
            Self::Unknown => "unknown",
        }
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::Critical => 3,
            Self::Warning => 2,
            Self::Elevated => 1,
            Self::Normal | Self::Unknown => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct FdUsage {
    pid: u32,
    process: String,
    command: String,
    user: String,
    open_fd_count: usize,
    soft_limit: LimitValue,
    hard_limit: LimitValue,
}

impl FdUsage {
    fn utilization_percent(&self) -> Option<f64> {
        match self.soft_limit {
            LimitValue::Value(0) if self.open_fd_count > 0 => Some(f64::INFINITY),
            LimitValue::Value(0) => Some(0.0),
            LimitValue::Value(limit) => Some((self.open_fd_count as f64 * 100.0) / limit as f64),
            LimitValue::Unlimited | LimitValue::Unknown => None,
        }
    }

    fn pressure(&self) -> FdPressure {
        let Some(percent) = self.utilization_percent() else {
            return if self.soft_limit == LimitValue::Unlimited {
                FdPressure::Normal
            } else {
                FdPressure::Unknown
            };
        };
        if percent >= 90.0 {
            FdPressure::Critical
        } else if percent >= 75.0 {
            FdPressure::Warning
        } else if percent >= 50.0 {
            FdPressure::Elevated
        } else {
            FdPressure::Normal
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FdPolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl FdPolicyStatus {
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

pub(crate) struct CapturedFdUsage {
    generated_at_unix_ms: u64,
    minimum_count: usize,
    minimum_percent: Option<u16>,
    result_limit: Option<usize>,
    system_process_count: usize,
    inspected_process_count: usize,
    limit_coverage_count: usize,
    collection_complete: bool,
    selection_complete: bool,
    entries: Vec<FdUsage>,
    warning: Option<String>,
}

impl CapturedFdUsage {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> FdPolicyStatus {
        if !self.entries.is_empty() {
            if expectation.passes(self.entries.len()) {
                FdPolicyStatus::Passed
            } else {
                FdPolicyStatus::Violated
            }
        } else if !self.selection_complete {
            FdPolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            FdPolicyStatus::Passed
        } else {
            FdPolicyStatus::Violated
        }
    }

    fn returned_count(&self) -> usize {
        self.result_limit
            .map(|limit| self.entries.len().min(limit))
            .unwrap_or(self.entries.len())
    }

    fn visible_entries(&self) -> impl Iterator<Item = &FdUsage> {
        self.entries
            .iter()
            .take(self.result_limit.unwrap_or(self.entries.len()))
    }
}

#[derive(Default)]
struct NativeFdCollection {
    counts: HashMap<u32, usize>,
    limits: HashMap<u32, (LimitValue, LimitValue)>,
    inspected_process_count: usize,
    collection_complete: bool,
    warning: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
fn parse_limit_value(value: &str) -> LimitValue {
    if value == "unlimited" {
        LimitValue::Unlimited
    } else {
        value
            .parse::<u64>()
            .map(LimitValue::Value)
            .unwrap_or(LimitValue::Unknown)
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_open_file_limits(contents: &str) -> (LimitValue, LimitValue) {
    contents
        .lines()
        .find_map(|line| {
            let values = line.strip_prefix("Max open files")?;
            let mut values = values.split_whitespace();
            Some((
                parse_limit_value(values.next()?),
                parse_limit_value(values.next()?),
            ))
        })
        .unwrap_or((LimitValue::Unknown, LimitValue::Unknown))
}

#[cfg(target_os = "linux")]
fn collect_native(processes: &HashMap<Pid, ProcessInfo>) -> NativeFdCollection {
    let mut counts = HashMap::new();
    let mut limits = HashMap::new();
    let mut unreadable_processes = 0_usize;
    let mut raced_entries = 0_usize;
    let mut unreadable_limits = 0_usize;

    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0 && process.pid.as_u32() != std::process::id())
    {
        let pid = process.pid.as_u32();
        let fd_root = format!("/proc/{pid}/fd");
        let descriptors = match fs::read_dir(fd_root) {
            Ok(descriptors) => descriptors,
            Err(_) => {
                unreadable_processes += 1;
                continue;
            }
        };
        let mut count = 0_usize;
        for descriptor in descriptors {
            if descriptor.is_ok() {
                count = count.saturating_add(1);
            } else {
                raced_entries = raced_entries.saturating_add(1);
            }
        }
        counts.insert(pid, count);

        match fs::read_to_string(format!("/proc/{pid}/limits")) {
            Ok(contents) => {
                limits.insert(pid, parse_linux_open_file_limits(&contents));
            }
            Err(_) => unreadable_limits += 1,
        }
    }

    let mut warnings = Vec::new();
    if unreadable_processes > 0 {
        warnings.push(format!(
            "fd tables were unreadable or disappeared for {unreadable_processes} process(es)"
        ));
    }
    if raced_entries > 0 {
        warnings.push(format!(
            "{raced_entries} fd directory entry read(s) raced with process activity"
        ));
    }
    if unreadable_limits > 0 {
        warnings.push(format!(
            "open-file limits were unreadable for {unreadable_limits} inspected process(es)"
        ));
    }
    NativeFdCollection {
        inspected_process_count: counts.len(),
        collection_complete: unreadable_processes == 0 && raced_entries == 0,
        counts,
        limits,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_lsof_fd_counts(output: &[u8]) -> (HashMap<u32, usize>, HashSet<u32>) {
    let mut counts = HashMap::new();
    let mut seen = HashSet::new();
    let mut current_pid = None;
    for line in String::from_utf8_lossy(output).lines() {
        if let Some(value) = line.strip_prefix('p') {
            current_pid = value.parse::<u32>().ok();
            if let Some(pid) = current_pid {
                seen.insert(pid);
                counts.entry(pid).or_insert(0_usize);
            }
        } else if let (Some(pid), Some(value)) = (current_pid, line.strip_prefix('f')) {
            if value.starts_with(|character: char| character.is_ascii_digit()) {
                counts
                    .entry(pid)
                    .and_modify(|count| *count = count.saturating_add(1));
            }
        }
    }
    (counts, seen)
}

#[cfg(not(target_os = "linux"))]
fn collect_native(processes: &HashMap<Pid, ProcessInfo>) -> NativeFdCollection {
    match Command::new("lsof").args(["-nP", "-Fpcuf"]).output() {
        Ok(output) => {
            let (mut counts, seen) = parse_lsof_fd_counts(&output.stdout);
            counts.retain(|pid, _| {
                *pid != std::process::id() && processes.contains_key(&Pid::from_u32(*pid))
            });
            let missing_processes = processes
                .keys()
                .filter(|pid| {
                    pid.as_u32() != 0
                        && pid.as_u32() != std::process::id()
                        && !seen.contains(&pid.as_u32())
                })
                .count();
            let mut warnings = Vec::new();
            if !output.status.success() {
                let detail = String::from_utf8_lossy(&output.stderr);
                warnings.push(format!(
                    "lsof did not complete fd collection: {}",
                    detail.trim()
                ));
            }
            if missing_processes > 0 {
                warnings.push(format!(
                    "lsof returned no fd table for {missing_processes} visible process(es)"
                ));
            }
            NativeFdCollection {
                inspected_process_count: counts.len(),
                collection_complete: output.status.success() && missing_processes == 0,
                counts,
                limits: HashMap::new(),
                warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
            }
        }
        Err(error) => NativeFdCollection {
            collection_complete: false,
            warning: Some(format!("cannot run lsof: {error}")),
            ..NativeFdCollection::default()
        },
    }
}

pub(crate) fn capture_fd_usage(
    minimum_count: usize,
    minimum_percent: Option<u16>,
    result_limit: Option<usize>,
) -> CapturedFdUsage {
    let mut provider = NativeProcessProvider::new();
    let processes: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let collected = collect_native(&processes);
    let mut entries: Vec<FdUsage> = collected
        .counts
        .iter()
        .filter_map(|(pid, count)| {
            let process = processes.get(&Pid::from_u32(*pid))?;
            let (soft_limit, hard_limit) = collected
                .limits
                .get(pid)
                .copied()
                .unwrap_or((LimitValue::Unknown, LimitValue::Unknown));
            Some(FdUsage {
                pid: *pid,
                process: process.name.clone(),
                command: process_command_line(process),
                user: process.user.clone(),
                open_fd_count: *count,
                soft_limit,
                hard_limit,
            })
        })
        .filter(|usage| usage.open_fd_count >= minimum_count)
        .filter(|usage| {
            minimum_percent
                .map(|threshold| {
                    usage
                        .utilization_percent()
                        .map(|percent| percent >= f64::from(threshold))
                        .unwrap_or(false)
                })
                .unwrap_or(true)
        })
        .collect();
    entries.sort_by(|left, right| {
        right
            .pressure()
            .sort_rank()
            .cmp(&left.pressure().sort_rank())
            .then_with(|| right.open_fd_count.cmp(&left.open_fd_count))
            .then_with(|| {
                right
                    .utilization_percent()
                    .partial_cmp(&left.utilization_percent())
                    .unwrap_or(Ordering::Equal)
            })
            .then_with(|| left.pid.cmp(&right.pid))
    });
    let limit_coverage_count = collected
        .limits
        .values()
        .filter(|(soft, _)| *soft != LimitValue::Unknown)
        .count();
    let missing_limit_count = collected
        .inspected_process_count
        .saturating_sub(limit_coverage_count);
    let selection_complete =
        collected.collection_complete && (minimum_percent.is_none() || missing_limit_count == 0);
    let mut warnings: Vec<String> = collected.warning.into_iter().collect();
    if minimum_percent.is_some() && missing_limit_count > 0 {
        warnings.push(format!(
            "soft-limit utilization was unavailable for {missing_limit_count} inspected process(es)"
        ));
    }
    CapturedFdUsage {
        generated_at_unix_ms: unix_millis(),
        minimum_count,
        minimum_percent,
        result_limit,
        system_process_count: processes
            .len()
            .saturating_sub(usize::from(processes.contains_key(&Pid::from_u32(0))))
            .saturating_sub(usize::from(
                processes.contains_key(&Pid::from_u32(std::process::id())),
            )),
        inspected_process_count: collected.inspected_process_count,
        limit_coverage_count,
        collection_complete: collected.collection_complete,
        selection_complete,
        entries,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    }
}

#[derive(Debug, Serialize)]
struct JsonFdUsage<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    minimum_count: usize,
    minimum_percent: Option<u16>,
    result_limit: Option<usize>,
    system_process_count: usize,
    inspected_process_count: usize,
    limit_coverage_count: usize,
    matched_process_count: usize,
    returned_process_count: usize,
    rows_truncated: bool,
    collection_complete: bool,
    selection_complete: bool,
    policy: Option<JsonPolicy<'a>>,
    warning: Option<&'a str>,
    processes: Vec<JsonProcess>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonPolicy<'a> {
    expectation: &'a str,
    status: &'static str,
    passed: Option<bool>,
    detail: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct JsonProcess {
    pid: u32,
    process: String,
    command: String,
    user: String,
    open_fd_count: usize,
    soft_limit: Option<u64>,
    soft_limit_unlimited: bool,
    hard_limit: Option<u64>,
    hard_limit_unlimited: bool,
    utilization_percent: Option<f64>,
    pressure: &'static str,
}

impl From<&FdUsage> for JsonProcess {
    fn from(usage: &FdUsage) -> Self {
        let utilization_percent = usage
            .utilization_percent()
            .filter(|percent| percent.is_finite());
        Self {
            pid: usage.pid,
            process: sanitize_terminal_text(&usage.process),
            command: sanitize_terminal_text(&command_for_output(&usage.command)),
            user: sanitize_terminal_text(&usage.user),
            open_fd_count: usage.open_fd_count,
            soft_limit: usage.soft_limit.numeric(),
            soft_limit_unlimited: usage.soft_limit.is_unlimited(),
            hard_limit: usage.hard_limit.numeric(),
            hard_limit_unlimited: usage.hard_limit.is_unlimited(),
            utilization_percent,
            pressure: usage.pressure().label(),
        }
    }
}

pub(crate) fn render_fd_json(
    captured: &CapturedFdUsage,
    expectation: Option<&str>,
    policy_status: Option<FdPolicyStatus>,
) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonFdUsage {
        schema: FD_SCHEMA,
        schema_version: FD_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, and resource-limit information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        minimum_count: captured.minimum_count,
        minimum_percent: captured.minimum_percent,
        result_limit: captured.result_limit,
        system_process_count: captured.system_process_count,
        inspected_process_count: captured.inspected_process_count,
        limit_coverage_count: captured.limit_coverage_count,
        matched_process_count: captured.entries.len(),
        returned_process_count: captured.returned_count(),
        rows_truncated: captured.returned_count() < captured.entries.len(),
        collection_complete: captured.collection_complete,
        selection_complete: captured.selection_complete,
        policy: expectation
            .zip(policy_status)
            .map(|(expectation, status)| JsonPolicy {
                expectation,
                status: status.label(),
                passed: status.passed(),
                detail: (status == FdPolicyStatus::Inconclusive).then_some(
                    "zero visible matches cannot prove absence because required fd or limit data was incomplete",
                ),
            }),
        warning: captured.warning.as_deref(),
        processes: captured.visible_entries().map(JsonProcess::from).collect(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_fd_table(
    captured: &CapturedFdUsage,
    expectation: Option<&str>,
    policy_status: Option<FdPolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        output.push_str(&format!(
            "FD CHECK {}  expected {}; matched {} process(es)\n",
            match status {
                FdPolicyStatus::Passed => "PASS",
                FdPolicyStatus::Violated => "FAIL",
                FdPolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.entries.len()
        ));
    }
    output.push_str(&format!(
        "FD PRESSURE  {} matched / {} inspected / {} system process(es), showing {}, threshold {}\n",
        captured.entries.len(),
        captured.inspected_process_count,
        captured.system_process_count,
        captured.returned_count(),
        match captured.minimum_percent {
            Some(percent) => format!(">= {} fd(s) and >= {percent}% soft limit", captured.minimum_count),
            None => format!(">= {} fd(s)", captured.minimum_count),
        },
    ));
    output.push_str(&format!(
        "limit coverage {} process(es)  fd collection {}  selection {}\n",
        captured.limit_coverage_count,
        if captured.collection_complete {
            "complete"
        } else {
            "incomplete"
        },
        if captured.selection_complete {
            "complete"
        } else {
            "incomplete"
        }
    ));
    if captured.entries.is_empty() {
        output.push_str("  [no matching process visible]\n");
    } else {
        output.push_str(
            "     FDS       SOFT       HARD     USE% PRESSURE      PID USER         PROCESS      COMMAND\n",
        );
        for usage in captured.visible_entries() {
            let percent = usage
                .utilization_percent()
                .filter(|percent| percent.is_finite())
                .map(|percent| format!("{percent:.1}%"))
                .unwrap_or_else(|| "-".into());
            output.push_str(&format!(
                "{:>8} {:>10} {:>10} {:>8} {:<9} {:>7} {:<12} {:<12} {}\n",
                usage.open_fd_count,
                usage.soft_limit.table_label(),
                usage.hard_limit.table_label(),
                percent,
                usage.pressure().table_label(),
                usage.pid,
                sanitize_terminal_text(&usage.user),
                sanitize_terminal_text(&usage.process),
                sanitize_terminal_text(&command_for_output(&usage.command)),
            ));
        }
        if captured.returned_count() < captured.entries.len() {
            output.push_str(&format!(
                "  ... {} additional matching process(es) hidden; use --limit all\n",
                captured.entries.len() - captured.returned_count()
            ));
        }
        output.push_str(
            "ACTION  Investigate sustained growth or high utilization before raising limits; close leaked descriptors or restart the owning service safely.\n",
        );
    }
    if let Some(warning) = &captured.warning {
        output.push_str(&format!("WARNING  {}\n", sanitize_terminal_text(warning)));
    }
    output
}

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

    fn usage(pid: u32, count: usize, soft: LimitValue) -> FdUsage {
        FdUsage {
            pid,
            process: format!("worker-{pid}"),
            command: format!("/srv/worker\n--id={pid}"),
            user: "deploy".into(),
            open_fd_count: count,
            soft_limit: soft,
            hard_limit: LimitValue::Value(4096),
        }
    }

    fn captured(entries: Vec<FdUsage>, complete: bool) -> CapturedFdUsage {
        CapturedFdUsage {
            generated_at_unix_ms: 1_700_000_000_000,
            minimum_count: 50,
            minimum_percent: None,
            result_limit: Some(1),
            system_process_count: 10,
            inspected_process_count: 8,
            limit_coverage_count: 2,
            collection_complete: complete,
            selection_complete: complete,
            entries,
            warning: (!complete).then(|| "one protected process".into()),
        }
    }

    #[test]
    fn parses_linux_limits_and_lsof_numeric_descriptors() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\nMax open files            128                  4096                 files\n";
        assert_eq!(
            parse_linux_open_file_limits(limits),
            (LimitValue::Value(128), LimitValue::Value(4096))
        );
        assert_eq!(
            parse_linux_open_file_limits("Max open files unlimited unlimited files"),
            (LimitValue::Unlimited, LimitValue::Unlimited)
        );

        let (counts, seen) = parse_lsof_fd_counts(
            b"p42\ncworker\nfcwd\nftxt\nf0r\nf1w\nf12u\np43\nchelper\nferr\nf2u\n",
        );
        assert_eq!(counts.get(&42), Some(&3));
        assert_eq!(counts.get(&43), Some(&1));
        assert_eq!(seen, HashSet::from([42, 43]));
    }

    #[test]
    fn classifies_pressure_and_keeps_unknown_limits_explicit() {
        assert_eq!(
            usage(1, 116, LimitValue::Value(128)).pressure(),
            FdPressure::Critical
        );
        assert_eq!(
            usage(1, 100, LimitValue::Value(128)).pressure(),
            FdPressure::Warning
        );
        assert_eq!(
            usage(1, 70, LimitValue::Value(128)).pressure(),
            FdPressure::Elevated
        );
        assert_eq!(
            usage(1, 1000, LimitValue::Unknown).pressure(),
            FdPressure::Unknown
        );
        assert_eq!(
            usage(1, 1000, LimitValue::Unlimited).pressure(),
            FdPressure::Normal
        );
    }

    #[test]
    fn zero_matches_with_incomplete_collection_is_not_a_false_pass() {
        let incomplete = captured(Vec::new(), false);
        assert_eq!(
            incomplete.evaluate_policy(CheckExpectation::None),
            FdPolicyStatus::Inconclusive
        );
        assert_eq!(
            incomplete.evaluate_policy(CheckExpectation::Any),
            FdPolicyStatus::Inconclusive
        );

        let mut missing_limits = captured(Vec::new(), true);
        missing_limits.minimum_percent = Some(80);
        missing_limits.selection_complete = false;
        assert_eq!(
            missing_limits.evaluate_policy(CheckExpectation::None),
            FdPolicyStatus::Inconclusive
        );
    }

    #[test]
    fn renders_versioned_bounded_and_terminal_safe_outputs() {
        let captured = captured(
            vec![
                usage(42, 120, LimitValue::Value(128)),
                usage(43, 80, LimitValue::Value(128)),
            ],
            true,
        );
        let json: Value = serde_json::from_str(
            &render_fd_json(
                &captured,
                Some("no matches"),
                Some(FdPolicyStatus::Violated),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], FD_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["matched_process_count"], 2);
        assert_eq!(json["returned_process_count"], 1);
        assert_eq!(json["rows_truncated"], true);
        assert_eq!(json["processes"].as_array().unwrap().len(), 1);
        assert_eq!(json["processes"][0]["command"], "/srv/worker --id=42");
        assert_eq!(json["processes"][0]["pressure"], "critical");

        let table = render_fd_table(
            &captured,
            Some("no matches"),
            Some(FdPolicyStatus::Violated),
        );
        assert!(table.contains("FD CHECK FAIL"));
        assert!(table.contains("CRITICAL"));
        assert!(table.contains("use --limit all"));
        assert!(!table.contains("worker\n--id"));
    }
}
