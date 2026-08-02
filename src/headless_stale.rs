use std::fmt::Write as _;

#[cfg(target_os = "linux")]
use std::{cmp::Ordering, collections::HashMap, fs, os::unix::fs::MetadataExt, path::Path};

use serde::Serialize;
use sysinfo::System;

#[cfg(any(target_os = "linux", test))]
use sysinfo::Pid;

use crate::{
    cli::CheckExpectation, headless::ProcessSnapshot, headless_exe::PackageEvidence,
    provider::platform_name,
};

#[cfg(target_os = "linux")]
use crate::{
    headless::CurrentProcessExclusion,
    headless_exe::detect_package,
    model::{process_command_for_output, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider},
    query::ProcessQuery,
};

#[cfg(any(target_os = "linux", test))]
use crate::model::ProcessInfo;

const STALE_SCHEMA: &str = "psmore.stale-executables";
const STALE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum StaleStatus {
    ReplacedOnDisk,
    RunningImageDeleted,
    DiskImageMissing,
}

impl StaleStatus {
    fn label(self) -> &'static str {
        match self {
            Self::ReplacedOnDisk => "replaced_on_disk",
            Self::RunningImageDeleted => "running_image_deleted",
            Self::DiskImageMissing => "disk_image_missing",
        }
    }

    #[cfg(target_os = "linux")]
    fn rank(self) -> u8 {
        match self {
            Self::ReplacedOnDisk => 0,
            Self::RunningImageDeleted => 1,
            Self::DiskImageMissing => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StalePolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl StalePolicyStatus {
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

#[derive(Clone, Debug, Serialize)]
struct StaleProcess {
    status: StaleStatus,
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    command: String,
    start_time_unix_seconds: u64,
    running_target: String,
    disk_path: String,
    disk_exists: bool,
    running_device: u64,
    running_inode: u64,
    disk_device: Option<u64>,
    disk_inode: Option<u64>,
    service_unit: Option<String>,
    package: Option<PackageEvidence>,
}

#[cfg(target_os = "linux")]
impl StaleProcess {
    fn from_evidence(process: &ProcessInfo, evidence: ImageEvidence) -> Self {
        let disk_path = evidence.disk_path;
        let package = detect_package(Path::new(&disk_path));
        Self {
            status: evidence.status,
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: sanitize_terminal_text(&process.name),
            user: sanitize_terminal_text(&process.user),
            command: sanitize_terminal_text(&process_command_for_output(process)),
            start_time_unix_seconds: process.start_time,
            running_target: sanitize_terminal_text(&evidence.running_target),
            disk_path: sanitize_terminal_text(&disk_path),
            disk_exists: evidence.disk_exists,
            running_device: evidence.running_device,
            running_inode: evidence.running_inode,
            disk_device: evidence.disk_device,
            disk_inode: evidence.disk_inode,
            service_unit: linux_service_unit(process.pid.as_u32()),
            package,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg(target_os = "linux")]
struct ImageEvidence {
    status: StaleStatus,
    running_target: String,
    disk_path: String,
    disk_exists: bool,
    running_device: u64,
    running_inode: u64,
    disk_device: Option<u64>,
    disk_inode: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
struct Coverage {
    eligible_process_count: usize,
    scanned_executable_count: usize,
    process_without_executable_count: usize,
    exited_during_collection_count: usize,
    unreadable_process_count: usize,
    racing_process_count: usize,
    collector_process_excluded: bool,
    complete: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct Selection {
    matched_stale_process_count: usize,
    returned_process_count: usize,
    truncated: bool,
    limit: Option<usize>,
}

pub(crate) struct CapturedStale {
    generated_at_unix_ms: u64,
    sample_interval_ms: u64,
    query: String,
    coverage: Coverage,
    selection: Selection,
    processes: Vec<StaleProcess>,
}

impl CapturedStale {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> StalePolicyStatus {
        let matched = self.selection.matched_stale_process_count;
        if matched > 0 {
            if expectation.passes(matched) {
                StalePolicyStatus::Passed
            } else {
                StalePolicyStatus::Violated
            }
        } else if !self.coverage.complete {
            StalePolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            StalePolicyStatus::Passed
        } else {
            StalePolicyStatus::Violated
        }
    }
}

#[derive(Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct JsonQuery<'a> {
    input: &'a str,
    language: &'static str,
}

#[derive(Serialize)]
struct JsonPolicy<'a> {
    expectation: &'a str,
    status: &'static str,
    passed: Option<bool>,
    detail: Option<&'static str>,
}

#[derive(Serialize)]
struct JsonStaleReport<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    sample_interval_ms: u64,
    query: Option<JsonQuery<'a>>,
    evidence_semantics: [&'static str; 3],
    coverage: Coverage,
    selection: Selection,
    policy: Option<JsonPolicy<'a>>,
    processes: &'a [StaleProcess],
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_stale(
    snapshot: &ProcessSnapshot,
    query: &str,
    limit: Option<usize>,
) -> Result<CapturedStale, String> {
    let query_definition = ProcessQuery::parse(query)?;
    let collector = CurrentProcessExclusion::capture(snapshot);
    let mut eligible: Vec<Pid> = collector
        .matching_pid_set(snapshot, &query_definition)
        .into_iter()
        .collect();
    eligible.sort_by_key(|pid| pid.as_u32());

    let mut coverage = Coverage {
        eligible_process_count: eligible.len(),
        collector_process_excluded: true,
        ..Coverage::default()
    };
    let mut candidates = Vec::new();
    for pid in eligible {
        let Some(process) = snapshot.process(pid) else {
            coverage.racing_process_count = coverage.racing_process_count.saturating_add(1);
            continue;
        };
        if is_linux_kernel_thread(process) {
            coverage.process_without_executable_count =
                coverage.process_without_executable_count.saturating_add(1);
            continue;
        }
        match inspect_image(pid.as_u32()) {
            Ok(Some(evidence)) => {
                coverage.scanned_executable_count =
                    coverage.scanned_executable_count.saturating_add(1);
                candidates.push((process.clone(), evidence));
            }
            Ok(None) => {
                coverage.scanned_executable_count =
                    coverage.scanned_executable_count.saturating_add(1);
            }
            Err(ScanError::NoExecutable) => {
                coverage.process_without_executable_count =
                    coverage.process_without_executable_count.saturating_add(1);
            }
            Err(ScanError::Unreadable) => {
                coverage.unreadable_process_count =
                    coverage.unreadable_process_count.saturating_add(1);
            }
            Err(ScanError::Exited) => {
                coverage.exited_during_collection_count =
                    coverage.exited_during_collection_count.saturating_add(1);
            }
            Err(ScanError::Racing) => {
                coverage.racing_process_count = coverage.racing_process_count.saturating_add(1);
            }
        }
    }

    let mut provider = NativeProcessProvider::new();
    let after: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut processes = Vec::new();
    for (before, evidence) in candidates {
        let Some(current) = after.get(&before.pid) else {
            coverage.exited_during_collection_count =
                coverage.exited_during_collection_count.saturating_add(1);
            continue;
        };
        if !same_process_instance(&before, current) {
            coverage.racing_process_count = coverage.racing_process_count.saturating_add(1);
            continue;
        }
        processes.push(StaleProcess::from_evidence(&before, evidence));
    }
    processes.sort_by(compare_processes);
    let matched_stale_process_count = processes.len();
    processes.truncate(limit.unwrap_or(processes.len()).min(processes.len()));
    coverage.complete =
        coverage.unreadable_process_count == 0 && coverage.racing_process_count == 0;
    Ok(CapturedStale {
        generated_at_unix_ms: snapshot.generated_at_unix_ms(),
        sample_interval_ms: snapshot.sample_ms(),
        query: query.trim().to_string(),
        coverage,
        selection: Selection {
            matched_stale_process_count,
            returned_process_count: processes.len(),
            truncated: processes.len() < matched_stale_process_count,
            limit,
        },
        processes,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn capture_stale(
    _snapshot: &ProcessSnapshot,
    _query: &str,
    _limit: Option<usize>,
) -> Result<CapturedStale, String> {
    Err("stale executable scanning requires Linux /proc/PID/exe mapped-image evidence".into())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScanError {
    NoExecutable,
    Unreadable,
    Exited,
    Racing,
}

#[cfg(target_os = "linux")]
fn inspect_image(pid: u32) -> Result<Option<ImageEvidence>, ScanError> {
    let proc_dir = format!("/proc/{pid}");
    let proc_exe = format!("{proc_dir}/exe");
    let running_target = match fs::read_link(&proc_exe) {
        Ok(target) => target.to_string_lossy().to_string(),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return if fs::read(format!("{proc_dir}/cmdline")).is_ok_and(|value| value.is_empty()) {
                Err(ScanError::NoExecutable)
            } else {
                Err(ScanError::Unreadable)
            };
        }
        Err(_) if Path::new(&proc_dir).exists() => return Err(ScanError::NoExecutable),
        Err(_) => return Err(ScanError::Exited),
    };
    let running = fs::metadata(&proc_exe).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            ScanError::Unreadable
        } else if Path::new(&proc_dir).exists() {
            ScanError::Racing
        } else {
            ScanError::Exited
        }
    })?;
    let deleted = running_target.ends_with(" (deleted)");
    let disk_path = running_target
        .strip_suffix(" (deleted)")
        .unwrap_or(&running_target)
        .to_string();
    if !disk_path.starts_with('/') {
        return Err(ScanError::Unreadable);
    }
    let disk = fs::metadata(&disk_path).ok();
    let same_identity = disk
        .as_ref()
        .map(|disk| running.dev() == disk.dev() && running.ino() == disk.ino());
    let status = if deleted && same_identity == Some(false) {
        Some(StaleStatus::ReplacedOnDisk)
    } else if deleted {
        Some(StaleStatus::RunningImageDeleted)
    } else if disk.is_none() {
        Some(StaleStatus::DiskImageMissing)
    } else if same_identity == Some(false) {
        Some(StaleStatus::ReplacedOnDisk)
    } else {
        None
    };
    Ok(status.map(|status| ImageEvidence {
        status,
        running_target,
        disk_path,
        disk_exists: disk.is_some(),
        running_device: running.dev(),
        running_inode: running.ino(),
        disk_device: disk.as_ref().map(MetadataExt::dev),
        disk_inode: disk.as_ref().map(MetadataExt::ino),
    }))
}

#[cfg(target_os = "linux")]
fn same_process_instance(before: &ProcessInfo, after: &ProcessInfo) -> bool {
    if before.start_time > 0 && after.start_time > 0 {
        before.start_time == after.start_time
    } else {
        before.name == after.name
            && process_command_for_output(before) == process_command_for_output(after)
    }
}

#[cfg(any(target_os = "linux", test))]
fn is_linux_kernel_thread(process: &ProcessInfo) -> bool {
    let command = process.command.trim();
    process.executable.is_empty() && command.starts_with('[') && command.ends_with(']')
}

#[cfg(target_os = "linux")]
fn compare_processes(left: &StaleProcess, right: &StaleProcess) -> Ordering {
    left.status
        .rank()
        .cmp(&right.status.rank())
        .then_with(|| left.service_unit.cmp(&right.service_unit))
        .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        .then_with(|| left.pid.cmp(&right.pid))
}

#[cfg(target_os = "linux")]
fn linux_service_unit(pid: u32) -> Option<String> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_service_unit(&content)
}

#[cfg(any(target_os = "linux", test))]
fn parse_service_unit(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let path = line.splitn(3, ':').nth(2)?;
        path.split('/').rev().find_map(|component| {
            (component.ends_with(".service") || component.ends_with(".scope"))
                .then(|| component.to_string())
        })
    })
}

pub(crate) fn render_stale_json(
    captured: &CapturedStale,
    expectation: Option<&str>,
    policy_status: Option<StalePolicyStatus>,
) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonStaleReport {
        schema: STALE_SCHEMA,
        schema_version: STALE_SCHEMA_VERSION,
        privacy_notice: "Contains host, process command, user, executable paths, file identities, package, and service information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        sample_interval_ms: captured.sample_interval_ms,
        query: (!captured.query.is_empty()).then_some(JsonQuery {
            input: &captured.query,
            language: "psmore process query",
        }),
        evidence_semantics: [
            "Linux /proc/PID/exe is the running mapped-image handle; the current disk path is compared by device and inode",
            "replaced_on_disk means the process holds an old unlinked image while the original path now identifies another file",
            "processes that exit during collection no longer require restart and do not make zero matches inconclusive; unreadable or identity-changing processes do",
        ],
        coverage: captured.coverage,
        selection: captured.selection,
        policy: expectation.zip(policy_status).map(|(expectation, status)| JsonPolicy {
            expectation,
            status: status.label(),
            passed: status.passed(),
            detail: (status == StalePolicyStatus::Inconclusive).then_some(
                "zero visible stale images cannot prove absence because collection was incomplete",
            ),
        }),
        processes: &captured.processes,
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_stale_table(
    captured: &CapturedStale,
    expectation: Option<&str>,
    policy_status: Option<StalePolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        let _ = writeln!(
            output,
            "STALE CHECK {}  expected {}; matched {} process(es)",
            match status {
                StalePolicyStatus::Passed => "PASS",
                StalePolicyStatus::Violated => "FAIL",
                StalePolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.selection.matched_stale_process_count
        );
    }
    let _ = writeln!(
        output,
        "STALE EXECUTABLES  {} returned / {} matched  query eligible {}  coverage {}",
        captured.selection.returned_process_count,
        captured.selection.matched_stale_process_count,
        captured.coverage.eligible_process_count,
        if captured.coverage.complete {
            "complete"
        } else {
            "partial"
        }
    );
    let _ = writeln!(
        output,
        "scan executable {}  no-executable {}  exited {}  unreadable {}  identity-race {}",
        captured.coverage.scanned_executable_count,
        captured.coverage.process_without_executable_count,
        captured.coverage.exited_during_collection_count,
        captured.coverage.unreadable_process_count,
        captured.coverage.racing_process_count
    );
    if captured.processes.is_empty() {
        output.push_str("  [no stale executable visible]\n");
    } else {
        output.push_str(
            "STATUS                    PID USER         PROCESS          OWNER / PACKAGE\n",
        );
        for process in &captured.processes {
            let owner = process
                .service_unit
                .as_deref()
                .or_else(|| {
                    process
                        .package
                        .as_ref()
                        .map(|package| package.name.as_str())
                })
                .unwrap_or("-");
            let _ = writeln!(
                output,
                "{:<23} {:>7} {:<12} {:<16} {}",
                process.status.label(),
                process.pid,
                process.user,
                process.name,
                owner
            );
            let _ = writeln!(output, "  running {}", process.running_target);
            let _ = writeln!(
                output,
                "  disk    {}  exists {}  identity {}:{} -> {}:{}",
                process.disk_path,
                if process.disk_exists { "yes" } else { "no" },
                process.running_device,
                process.running_inode,
                process
                    .disk_device
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into()),
                process
                    .disk_inode
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "?".into())
            );
            let _ = writeln!(output, "  command {}", process.command);
            if let Some(package) = process.package.as_ref() {
                let _ = writeln!(
                    output,
                    "  package {} {}{}",
                    package.manager,
                    package.name,
                    package
                        .version
                        .as_deref()
                        .map(|version| format!(" {version}"))
                        .unwrap_or_default()
                );
            }
            let _ = writeln!(output, "  verify  psmore exe {}", process.pid);
        }
        output.push_str("ACTION  Review service impact, verify each PID, then restart through its service manager; psmore does not restart processes.\n");
    }
    if !captured.coverage.complete {
        let _ = writeln!(
            output,
            "WARNING  unreadable {}  raced {}  no executable {}",
            captured.coverage.unreadable_process_count,
            captured.coverage.racing_process_count,
            captured.coverage.process_without_executable_count
        );
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(command: &str, executable: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(2),
            parent: Some(Pid::from_u32(0)),
            name: "kthreadd".into(),
            command: command.into(),
            executable: executable.into(),
            user: "root".into(),
            cwd: String::new(),
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
    fn kernel_thread_detection_does_not_hide_permission_sensitive_user_processes() {
        assert!(is_linux_kernel_thread(&process("[kthreadd]", "")));
        assert!(!is_linux_kernel_thread(&process("sshd: root@pts/0", "")));
        assert!(!is_linux_kernel_thread(&process(
            "[ordinary-name]",
            "/usr/bin/app"
        )));
    }

    #[test]
    fn policy_never_claims_clean_when_zero_match_collection_is_partial() {
        let captured = CapturedStale {
            generated_at_unix_ms: 1,
            sample_interval_ms: 500,
            query: String::new(),
            coverage: Coverage {
                complete: false,
                unreadable_process_count: 1,
                ..Coverage::default()
            },
            selection: Selection {
                matched_stale_process_count: 0,
                returned_process_count: 0,
                truncated: false,
                limit: Some(100),
            },
            processes: Vec::new(),
        };
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::None),
            StalePolicyStatus::Inconclusive
        );
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::Any),
            StalePolicyStatus::Inconclusive
        );
    }

    #[test]
    fn exited_processes_do_not_turn_a_clean_current_host_into_inconclusive() {
        let captured = CapturedStale {
            generated_at_unix_ms: 1,
            sample_interval_ms: 500,
            query: String::new(),
            coverage: Coverage {
                eligible_process_count: 1,
                exited_during_collection_count: 1,
                collector_process_excluded: true,
                complete: true,
                ..Coverage::default()
            },
            selection: Selection {
                matched_stale_process_count: 0,
                returned_process_count: 0,
                truncated: false,
                limit: Some(100),
            },
            processes: Vec::new(),
        };
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::None),
            StalePolicyStatus::Passed
        );
    }

    #[test]
    fn service_unit_parser_prefers_the_leaf_manager_boundary() {
        assert_eq!(
            parse_service_unit("0::/system.slice/docker.service/worker.scope\n").as_deref(),
            Some("worker.scope")
        );
        assert_eq!(parse_service_unit("0::/user.slice/user-1000.slice\n"), None);
    }

    #[test]
    fn json_contract_exposes_coverage_selection_and_policy() {
        let captured = CapturedStale {
            generated_at_unix_ms: 1,
            sample_interval_ms: 500,
            query: "user:deploy".into(),
            coverage: Coverage {
                eligible_process_count: 3,
                scanned_executable_count: 3,
                collector_process_excluded: true,
                complete: true,
                ..Coverage::default()
            },
            selection: Selection {
                matched_stale_process_count: 0,
                returned_process_count: 0,
                truncated: false,
                limit: Some(100),
            },
            processes: Vec::new(),
        };
        let status = captured.evaluate_policy(CheckExpectation::None);
        let value: serde_json::Value = serde_json::from_str(
            &render_stale_json(&captured, Some("no stale executables"), Some(status)).unwrap(),
        )
        .unwrap();
        assert_eq!(value["schema"], STALE_SCHEMA);
        assert_eq!(value["schema_version"], STALE_SCHEMA_VERSION);
        assert_eq!(value["coverage"]["complete"], true);
        assert_eq!(value["selection"]["matched_stale_process_count"], 0);
        assert_eq!(value["policy"]["status"], "pass");
    }
}
