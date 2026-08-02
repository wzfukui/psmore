use std::{cmp::Ordering, thread, time::Instant};

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    cli::{DoctorFailOn, ListenProtocol},
    headless::{CurrentProcessExclusion, ProcessSnapshot, finite, human_bytes, human_rate},
    headless_deleted::{DeletedDiagnosticSummary, capture_deleted_files},
    headless_fd::{FdDiagnosticSummary, capture_fd_usage},
    headless_listen::{ListenerDiagnosticSummary, capture_listeners},
    headless_oom::OomDiagnosticSummary,
    model::{
        ProcessInfo, ResourceAggregate, command_for_output, output_secret_redaction_enabled,
        sanitize_terminal_text,
    },
    provider::platform_name,
    query::ProcessQuery,
};

#[cfg(target_os = "linux")]
use crate::headless_oom::capture_oom_diagnostics;

const DOCTOR_SCHEMA: &str = "psmore.host-doctor";
const DOCTOR_SCHEMA_VERSION: u32 = 1;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorSeverity {
    Warning,
    Critical,
}

impl DoctorSeverity {
    fn table_label(self) -> &'static str {
        match self {
            Self::Warning => "WARN",
            Self::Critical => "CRIT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DoctorPolicyStatus {
    Passed,
    Violated,
}

impl DoctorPolicyStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Passed => "pass",
            Self::Violated => "fail",
        }
    }

    fn passed(self) -> bool {
        self == Self::Passed
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct HostEvidence {
    physical_memory_total_bytes: u64,
    physical_memory_available_bytes: u64,
    effective_memory_total_bytes: u64,
    effective_memory_available_bytes: u64,
    memory_available_source: &'static str,
    cgroup_memory_limit_applied: bool,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
    logical_cpu_count: usize,
    load_one: f64,
    load_five: f64,
    load_fifteen: f64,
    uptime_seconds: u64,
}

impl HostEvidence {
    fn capture() -> Self {
        let mut system = System::new();
        system.refresh_memory();
        let physical_total = system.total_memory();
        let (physical_available, physical_available_source) =
            host_available_memory(physical_total, system.available_memory());
        let cgroup = system.cgroup_limits().filter(|limits| {
            limits.total_memory > 0 && physical_total > 0 && limits.total_memory < physical_total
        });
        let (effective_total, effective_available, memory_source, cgroup_applied) = cgroup
            .map(|limits| {
                (
                    limits.total_memory,
                    limits.free_memory.min(limits.total_memory),
                    "cgroup",
                    true,
                )
            })
            .unwrap_or((
                physical_total,
                physical_available,
                physical_available_source,
                false,
            ));
        let load = System::load_average();
        Self {
            physical_memory_total_bytes: physical_total,
            physical_memory_available_bytes: physical_available,
            effective_memory_total_bytes: effective_total,
            effective_memory_available_bytes: effective_available,
            memory_available_source: memory_source,
            cgroup_memory_limit_applied: cgroup_applied,
            swap_total_bytes: system.total_swap(),
            swap_used_bytes: system.used_swap(),
            logical_cpu_count: thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1),
            load_one: load.one,
            load_five: load.five,
            load_fifteen: load.fifteen,
            uptime_seconds: System::uptime(),
        }
    }

    fn memory_available_percent(self) -> Option<f64> {
        (self.effective_memory_total_bytes > 0 && self.memory_available_source != "unavailable")
            .then(|| {
                self.effective_memory_available_bytes as f64 * 100.0
                    / self.effective_memory_total_bytes as f64
            })
    }

    fn swap_used_percent(self) -> Option<f64> {
        (self.swap_total_bytes > 0)
            .then(|| self.swap_used_bytes as f64 * 100.0 / self.swap_total_bytes as f64)
    }

    fn normalized_load_fifteen(self) -> f64 {
        self.load_fifteen / self.logical_cpu_count.max(1) as f64
    }
}

#[cfg(target_os = "macos")]
fn host_available_memory(total_bytes: u64, fallback_bytes: u64) -> (u64, &'static str) {
    if let Ok(output) = Command::new("memory_pressure").arg("-Q").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(percent) = parse_memory_pressure_free_percent(&text) {
                let available = (total_bytes as f64 * percent / 100.0)
                    .round()
                    .clamp(0.0, total_bytes as f64) as u64;
                return (available, "macos_memory_pressure");
            }
        }
    }
    if let Ok(output) = Command::new("vm_stat").output() {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(available) = parse_vm_stat_available_bytes(&text) {
                return (available.min(total_bytes), "macos_vm_stat");
            }
        }
    }
    if fallback_bytes > 0 || total_bytes == 0 {
        (fallback_bytes, "sysinfo")
    } else {
        (0, "unavailable")
    }
}

#[cfg(not(target_os = "macos"))]
fn host_available_memory(_total_bytes: u64, fallback_bytes: u64) -> (u64, &'static str) {
    (fallback_bytes, "sysinfo")
}

#[cfg(any(target_os = "macos", test))]
fn parse_memory_pressure_free_percent(content: &str) -> Option<f64> {
    content.lines().find_map(|line| {
        line.trim()
            .strip_prefix("System-wide memory free percentage:")?
            .trim()
            .strip_suffix('%')?
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|percent| (0.0..=100.0).contains(percent))
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_vm_stat_available_bytes(content: &str) -> Option<u64> {
    let first_line = content.lines().next()?;
    let page_size = first_line
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    let mut pages = 0_u64;
    let mut matched = false;
    for line in content.lines().skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if matches!(
            key.trim(),
            "Pages free" | "Pages inactive" | "Pages speculative"
        ) {
            let value = value.trim().trim_end_matches('.').parse::<u64>().ok()?;
            pages = pages.saturating_add(value);
            matched = true;
        }
    }
    matched.then(|| pages.saturating_mul(page_size))
}

#[derive(Clone, Debug)]
struct ProcessEvidence {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    status: String,
    command: String,
    cpu_percent: f32,
    memory_bytes: u64,
    memory_percent: Option<f64>,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    runtime_seconds: u64,
    subtree_process_count: usize,
}

impl ProcessEvidence {
    fn from_process(
        process: &ProcessInfo,
        subtree: ResourceAggregate,
        effective_memory_total_bytes: u64,
    ) -> Self {
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: sanitize_terminal_text(&process.name),
            user: sanitize_terminal_text(&process.user),
            status: sanitize_terminal_text(&process.status),
            command: crate::model::process_command_line(process),
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            memory_percent: (effective_memory_total_bytes > 0)
                .then(|| process.memory as f64 * 100.0 / effective_memory_total_bytes as f64),
            read_bytes_per_second: process.read_rate,
            write_bytes_per_second: process.write_rate,
            runtime_seconds: process.runtime,
            subtree_process_count: subtree.process_count,
        }
    }
}

#[derive(Clone, Debug)]
struct DoctorFinding {
    code: &'static str,
    severity: DoctorSeverity,
    title: &'static str,
    summary: String,
    evidence: Vec<ProcessEvidence>,
    next_command: &'static str,
}

#[derive(Clone, Debug, Default)]
struct DoctorHotspots {
    cpu: Vec<ProcessEvidence>,
    memory: Vec<ProcessEvidence>,
    read: Vec<ProcessEvidence>,
    write: Vec<ProcessEvidence>,
}

struct DoctorDeepEvidence {
    elapsed_ms: u64,
    listeners: ListenerDiagnosticSummary,
    fd: FdDiagnosticSummary,
    deleted: DeletedDiagnosticSummary,
    oom: Option<OomDiagnosticSummary>,
    oom_supported: bool,
    oom_error: Option<String>,
}

pub(crate) struct CapturedDoctor {
    generated_at_unix_ms: u64,
    sample_interval_ms: u64,
    query: String,
    system_process_count: usize,
    scoped_process_count: usize,
    result_limit: Option<usize>,
    host: HostEvidence,
    findings: Vec<DoctorFinding>,
    hotspots: DoctorHotspots,
    deep: Option<DoctorDeepEvidence>,
    notes: Vec<String>,
}

impl CapturedDoctor {
    pub(crate) fn evaluate_policy(&self, fail_on: DoctorFailOn) -> Option<DoctorPolicyStatus> {
        let violated = match fail_on {
            DoctorFailOn::Never => return None,
            DoctorFailOn::Warning => !self.findings.is_empty(),
            DoctorFailOn::Critical => self
                .findings
                .iter()
                .any(|finding| finding.severity == DoctorSeverity::Critical),
        };
        Some(if violated {
            DoctorPolicyStatus::Violated
        } else {
            DoctorPolicyStatus::Passed
        })
    }

    pub(crate) fn critical_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == DoctorSeverity::Critical)
            .count()
    }

    pub(crate) fn warning_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == DoctorSeverity::Warning)
            .count()
    }

    pub(crate) fn status_label(&self) -> &'static str {
        if self.critical_count() > 0 {
            "critical_signals"
        } else if self.warning_count() > 0 {
            "warning_signals"
        } else {
            "no_configured_signals"
        }
    }
}

fn is_zombie(status: &str) -> bool {
    let status = status.trim().to_ascii_lowercase();
    status.contains("zombie") || status == "z" || status.starts_with("z+")
}

fn is_stopped(status: &str) -> bool {
    let status = status.trim().to_ascii_lowercase();
    status.contains("stop")
        || status.contains("tracing")
        || status == "t"
        || status.starts_with("t+")
}

fn stable_process_tie(left: &ProcessEvidence, right: &ProcessEvidence) -> Ordering {
    (left.name.to_ascii_lowercase(), left.pid).cmp(&(right.name.to_ascii_lowercase(), right.pid))
}

fn limited(mut evidence: Vec<ProcessEvidence>, limit: Option<usize>) -> Vec<ProcessEvidence> {
    evidence.truncate(limit.unwrap_or(evidence.len()).min(evidence.len()));
    evidence
}

fn summarize_pids(evidence: &[ProcessEvidence]) -> String {
    let preview = evidence
        .iter()
        .take(5)
        .map(|process| format!("{}[{}]", process.name, process.pid))
        .collect::<Vec<_>>()
        .join(", ");
    if evidence.len() > 5 {
        format!("{preview}, +{} more", evidence.len() - 5)
    } else {
        preview
    }
}

fn capture_deep_evidence(
    sample_interval_ms: u64,
    limit: Option<usize>,
) -> Result<DoctorDeepEvidence, String> {
    #[cfg(not(target_os = "linux"))]
    let _ = sample_interval_ms;
    let started = Instant::now();
    let (listeners, fd, deleted, oom_result) = thread::scope(|scope| {
        let listeners = scope.spawn(|| capture_listeners("", ListenProtocol::Any, true, limit));
        let fd = scope.spawn(|| capture_fd_usage(1, Some(75), limit));
        let deleted = scope.spawn(|| capture_deleted_files(100 * MIB));
        #[cfg(target_os = "linux")]
        let oom = scope.spawn(|| {
            capture_oom_diagnostics("", sample_interval_ms, 500, limit)
                .map(|captured| captured.diagnostic_summary())
        });

        let listeners = listeners
            .join()
            .map_err(|_| "deep listener collection panicked".to_string())?
            .diagnostic_summary();
        let fd = fd
            .join()
            .map_err(|_| "deep fd collection panicked".to_string())?
            .diagnostic_summary();
        let deleted = deleted
            .join()
            .map_err(|_| "deep deleted-file collection panicked".to_string())?
            .diagnostic_summary(limit);
        #[cfg(target_os = "linux")]
        let oom_result = oom
            .join()
            .map_err(|_| "deep OOM collection panicked".to_string())?;
        #[cfg(not(target_os = "linux"))]
        let oom_result: Result<OomDiagnosticSummary, String> =
            Err("OOM priority and PSI evidence are only available on Linux".to_string());
        Ok::<_, String>((listeners, fd, deleted, oom_result))
    })?;
    let (oom, oom_error) = match oom_result {
        Ok(oom) => (Some(oom), None),
        Err(error) => (None, Some(error)),
    };
    Ok(DoctorDeepEvidence {
        elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
        listeners,
        fd,
        deleted,
        oom,
        oom_supported: cfg!(target_os = "linux"),
        oom_error,
    })
}

fn append_deep_findings(captured: &mut CapturedDoctor, deep: &DoctorDeepEvidence) {
    if !deep.fd.processes.is_empty() {
        let critical = deep
            .fd
            .processes
            .iter()
            .any(|process| process.pressure == "critical");
        let highest = deep
            .fd
            .processes
            .iter()
            .filter_map(|process| process.utilization_percent)
            .max_by(f64::total_cmp);
        captured.findings.push(DoctorFinding {
            code: "file_descriptor_pressure",
            severity: if critical {
                DoctorSeverity::Critical
            } else {
                DoctorSeverity::Warning
            },
            title: "Processes are near their open-file limit",
            summary: format!(
                "{} process(es) are at or above 75% soft-limit utilization; highest {}",
                deep.fd.matched_process_count,
                optional_percent(highest)
            ),
            evidence: Vec::new(),
            next_command: "psmore fd --min-percent 75 --limit all",
        });
    }

    if deep.deleted.estimated_reclaimable_bytes >= 100 * MIB && deep.deleted.unique_file_count > 0 {
        captured.findings.push(DoctorFinding {
            code: "deleted_open_files",
            severity: if deep.deleted.estimated_reclaimable_bytes >= GIB {
                DoctorSeverity::Critical
            } else {
                DoctorSeverity::Warning
            },
            title: "Deleted files are still held open",
            summary: format!(
                "{} unique file(s) across {} process(es) retain approximately {}",
                deep.deleted.unique_file_count,
                deep.deleted.process_count,
                human_bytes(deep.deleted.estimated_reclaimable_bytes)
            ),
            evidence: Vec::new(),
            next_command: "psmore deleted --min-size 100m",
        });
    }

    if let Some(pressure) = deep.oom.as_ref().and_then(|oom| oom.pressure) {
        let severity = if pressure.full_avg10_percent >= 5.0 || pressure.some_avg10_percent >= 50.0
        {
            Some(DoctorSeverity::Critical)
        } else if pressure.full_avg10_percent >= 1.0 || pressure.some_avg10_percent >= 20.0 {
            Some(DoctorSeverity::Warning)
        } else {
            None
        };
        if let Some(severity) = severity {
            captured.findings.push(DoctorFinding {
                code: "linux_memory_psi",
                severity,
                title: "Linux reports current memory stall pressure",
                summary: format!(
                    "PSI avg10 some {:.2}% / full {:.2}% (avg60 {:.2}% / {:.2}%)",
                    pressure.some_avg10_percent,
                    pressure.full_avg10_percent,
                    pressure.some_avg60_percent,
                    pressure.full_avg60_percent
                ),
                evidence: Vec::new(),
                next_command: "psmore oom --limit 20",
            });
        }
    }

    captured.findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.code.cmp(right.code))
    });
    captured
        .notes
        .retain(|note| !note.starts_with("run psmore listen --exposed"));
    captured.notes.push(format!(
        "deep checks scanned exposed listeners, fd pressure, deleted-open files{} in {}ms",
        if deep.oom_supported {
            ", Linux OOM priority, and PSI"
        } else {
            ""
        },
        deep.elapsed_ms
    ));
    if deep.listeners.unresolved_socket_count > 0 {
        captured.notes.push(format!(
            "{} exposed socket reference(s) had no visible owner; this is an ownership visibility gap, not proof of an orphan socket",
            deep.listeners.unresolved_socket_count
        ));
    }
    let mut warnings = vec![
        deep.listeners.warning.as_deref(),
        deep.fd.warning.as_deref(),
        deep.deleted.warning.as_deref(),
        deep.oom.as_ref().and_then(|oom| oom.warning.as_deref()),
    ];
    if deep.oom_supported {
        warnings.push(deep.oom_error.as_deref());
    }
    for warning in warnings.into_iter().flatten() {
        captured.notes.push(format!("deep collection: {warning}"));
    }
}

fn analyze_doctor(
    snapshot: &ProcessSnapshot,
    query: &str,
    host: HostEvidence,
    limit: Option<usize>,
) -> Result<CapturedDoctor, String> {
    let query_expression = ProcessQuery::parse(query)?;
    let collector = CurrentProcessExclusion::capture(snapshot);
    let matching = collector.matching_pid_set(snapshot, &query_expression);
    let mut processes = matching
        .iter()
        .filter_map(|pid| {
            let process = snapshot.process(*pid)?;
            Some(ProcessEvidence::from_process(
                process,
                collector.adjust_subtree(*pid, snapshot.resource(*pid)),
                host.effective_memory_total_bytes,
            ))
        })
        .collect::<Vec<_>>();
    processes.sort_by(stable_process_tie);

    let mut findings = Vec::new();
    if let Some(available_percent) = host.memory_available_percent() {
        let severity = if available_percent <= 5.0 {
            Some(DoctorSeverity::Critical)
        } else if available_percent <= 10.0 {
            Some(DoctorSeverity::Warning)
        } else {
            None
        };
        if let Some(severity) = severity {
            let scope = if host.cgroup_memory_limit_applied {
                "effective cgroup"
            } else {
                "host"
            };
            findings.push(DoctorFinding {
                code: "low_available_memory",
                severity,
                title: "Low available memory",
                summary: format!(
                    "{scope} memory available is {:.1}% ({}/{})",
                    available_percent,
                    human_bytes(host.effective_memory_available_bytes),
                    human_bytes(host.effective_memory_total_bytes)
                ),
                evidence: Vec::new(),
                next_command: "psmore top --by memory --scope tree",
            });
        }
    }
    if let Some(swap_percent) = host.swap_used_percent() {
        let available_percent = host.memory_available_percent().unwrap_or(100.0);
        if host.swap_used_bytes >= 512 * MIB && swap_percent >= 50.0 && available_percent <= 20.0 {
            findings.push(DoctorFinding {
                code: "swap_pressure",
                severity: if swap_percent >= 90.0 && available_percent <= 10.0 {
                    DoctorSeverity::Critical
                } else {
                    DoctorSeverity::Warning
                },
                title: "Swap utilization is elevated",
                summary: format!(
                    "swap used is {:.1}% ({}/{}) while effective memory available is {:.1}%",
                    swap_percent,
                    human_bytes(host.swap_used_bytes),
                    human_bytes(host.swap_total_bytes),
                    available_percent
                ),
                evidence: Vec::new(),
                next_command: if cfg!(target_os = "linux") {
                    "psmore oom --limit 10"
                } else {
                    "psmore top --by memory --limit 10"
                },
            });
        }
    }
    let normalized_load = host.normalized_load_fifteen();
    if normalized_load >= 1.0 {
        findings.push(DoctorFinding {
            code: "sustained_load",
            severity: if normalized_load >= 2.0 {
                DoctorSeverity::Critical
            } else {
                DoctorSeverity::Warning
            },
            title: "Sustained host load is elevated",
            summary: format!(
                "15-minute load {:.2} across {} logical CPU(s), normalized {:.2}",
                host.load_fifteen, host.logical_cpu_count, normalized_load
            ),
            evidence: Vec::new(),
            next_command: "psmore top --by cpu --scope tree",
        });
    }

    let zombies = processes
        .iter()
        .filter(|process| is_zombie(&process.status))
        .cloned()
        .collect::<Vec<_>>();
    if !zombies.is_empty() {
        findings.push(DoctorFinding {
            code: "zombie_processes",
            severity: if zombies.len() >= 5 {
                DoctorSeverity::Critical
            } else {
                DoctorSeverity::Warning
            },
            title: "Zombie processes are present",
            summary: format!("{} zombie(s): {}", zombies.len(), summarize_pids(&zombies)),
            evidence: limited(zombies, limit),
            next_command: "psmore check 'state:zombie' --table",
        });
    }
    let stopped = processes
        .iter()
        .filter(|process| is_stopped(&process.status))
        .cloned()
        .collect::<Vec<_>>();
    if !stopped.is_empty() {
        findings.push(DoctorFinding {
            code: "stopped_processes",
            severity: DoctorSeverity::Warning,
            title: "Stopped or traced processes are present",
            summary: format!(
                "{} process(es): {}",
                stopped.len(),
                summarize_pids(&stopped)
            ),
            evidence: limited(stopped, limit),
            next_command: "psmore check 'state:stopped' --table",
        });
    }

    let mut large_memory = processes
        .iter()
        .filter(|process| {
            process
                .memory_percent
                .is_some_and(|percent| percent >= 25.0)
        })
        .cloned()
        .collect::<Vec<_>>();
    large_memory.sort_by(|left, right| {
        right
            .memory_bytes
            .cmp(&left.memory_bytes)
            .then_with(|| stable_process_tie(left, right))
    });
    if !large_memory.is_empty() {
        let severity = if large_memory.iter().any(|process| {
            process
                .memory_percent
                .is_some_and(|percent| percent >= 50.0)
        }) {
            DoctorSeverity::Critical
        } else {
            DoctorSeverity::Warning
        };
        findings.push(DoctorFinding {
            code: "large_process_memory_share",
            severity,
            title: "A process holds a large share of effective memory",
            summary: format!(
                "{} process(es) use at least 25% individually; highest is {:.1}%",
                large_memory.len(),
                large_memory[0].memory_percent.unwrap_or_default()
            ),
            evidence: limited(large_memory, limit),
            next_command: "psmore top --by memory --scope tree",
        });
    }

    let mut high_cpu = processes
        .iter()
        .filter(|process| process.cpu_percent >= 90.0 && process.runtime_seconds >= 60)
        .cloned()
        .collect::<Vec<_>>();
    high_cpu.sort_by(|left, right| {
        finite(right.cpu_percent)
            .total_cmp(&finite(left.cpu_percent))
            .then_with(|| stable_process_tie(left, right))
    });
    if !high_cpu.is_empty() {
        findings.push(DoctorFinding {
            code: "high_cpu_sample",
            severity: DoctorSeverity::Warning,
            title: "Long-running processes sampled at high CPU",
            summary: format!(
                "{} process(es) older than 60s sampled at >=90% CPU; this is a sample, not proof of sustained saturation",
                high_cpu.len()
            ),
            evidence: limited(high_cpu, limit),
            next_command: "psmore trace PID --interval-ms 500 --count 20",
        });
    }

    let mut high_io = processes
        .iter()
        .filter(|process| {
            process.runtime_seconds >= 30
                && process
                    .read_bytes_per_second
                    .saturating_add(process.write_bytes_per_second)
                    >= 100 * MIB
        })
        .cloned()
        .collect::<Vec<_>>();
    high_io.sort_by(|left, right| {
        right
            .read_bytes_per_second
            .saturating_add(right.write_bytes_per_second)
            .cmp(
                &left
                    .read_bytes_per_second
                    .saturating_add(left.write_bytes_per_second),
            )
            .then_with(|| stable_process_tie(left, right))
    });
    if !high_io.is_empty() {
        findings.push(DoctorFinding {
            code: "high_io_sample",
            severity: DoctorSeverity::Warning,
            title: "Long-running processes sampled at high disk I/O",
            summary: format!(
                "{} process(es) older than 30s sampled at >=100 MiB/s combined read/write",
                high_io.len()
            ),
            evidence: limited(high_io, limit),
            next_command: "psmore top --by write --scope tree",
        });
    }

    let mut large_trees = processes
        .iter()
        .filter(|process| process.pid > 1 && process.subtree_process_count >= 250)
        .cloned()
        .collect::<Vec<_>>();
    large_trees.sort_by(|left, right| {
        right
            .subtree_process_count
            .cmp(&left.subtree_process_count)
            .then_with(|| stable_process_tie(left, right))
    });
    if !large_trees.is_empty() {
        let severity = if large_trees
            .iter()
            .any(|process| process.subtree_process_count >= 1_000)
        {
            DoctorSeverity::Critical
        } else {
            DoctorSeverity::Warning
        };
        findings.push(DoctorFinding {
            code: "large_service_tree",
            severity,
            title: "A service tree contains many processes",
            summary: format!(
                "{} tree(s) contain at least 250 processes; largest contains {}",
                large_trees.len(),
                large_trees[0].subtree_process_count
            ),
            evidence: limited(large_trees, limit),
            next_command: "psmore tree PID --depth 3",
        });
    }

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.code.cmp(right.code))
    });

    let hotspot = |metric: fn(&ProcessEvidence) -> u64, include_zero: bool| {
        let mut ranked = processes.clone();
        ranked.retain(|process| include_zero || metric(process) > 0);
        ranked.sort_by(|left, right| {
            metric(right)
                .cmp(&metric(left))
                .then_with(|| stable_process_tie(left, right))
        });
        limited(ranked, limit)
    };
    let mut cpu = processes.clone();
    cpu.retain(|process| process.cpu_percent > 0.0);
    cpu.sort_by(|left, right| {
        finite(right.cpu_percent)
            .total_cmp(&finite(left.cpu_percent))
            .then_with(|| stable_process_tie(left, right))
    });
    cpu = limited(cpu, limit);
    let hotspots = DoctorHotspots {
        cpu,
        memory: hotspot(|process| process.memory_bytes, true),
        read: hotspot(|process| process.read_bytes_per_second, false),
        write: hotspot(|process| process.write_bytes_per_second, false),
    };

    let mut notes = vec![
        "doctor reports sampled signals, not confirmed root causes".to_string(),
        "run psmore listen --exposed, psmore fd --min-percent 75, and psmore deleted --min-size 100m for deeper host checks".to_string(),
    ];
    if matching.is_empty() && !query.trim().is_empty() {
        notes.push(
            "the process query matched no processes; host-level checks still ran".to_string(),
        );
    }
    if host.effective_memory_total_bytes == 0 {
        notes.push(
            "effective memory capacity was unavailable; memory percentage checks were skipped"
                .to_string(),
        );
    }

    Ok(CapturedDoctor {
        generated_at_unix_ms: snapshot.generated_at_unix_ms(),
        sample_interval_ms: snapshot.sample_ms(),
        query: query.to_string(),
        system_process_count: snapshot.real_process_count(),
        scoped_process_count: processes.len(),
        result_limit: limit,
        host,
        findings,
        hotspots,
        deep: None,
        notes,
    })
}

pub(crate) fn capture_doctor(
    snapshot: &ProcessSnapshot,
    query: &str,
    limit: Option<usize>,
    deep: bool,
) -> Result<CapturedDoctor, String> {
    let mut captured = analyze_doctor(snapshot, query, HostEvidence::capture(), limit)?;
    if deep {
        let evidence = capture_deep_evidence(snapshot.sample_ms(), limit)?;
        append_deep_findings(&mut captured, &evidence);
        captured.deep = Some(evidence);
    }
    Ok(captured)
}

#[derive(Serialize)]
struct JsonDoctor<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    secrets_redacted: bool,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    sample_interval_ms: u64,
    status: &'static str,
    policy: JsonPolicy,
    query: Option<JsonQuery<'a>>,
    system_process_count: usize,
    scoped_process_count: usize,
    finding_count: usize,
    critical_finding_count: usize,
    warning_finding_count: usize,
    result_limit_per_section: Option<usize>,
    host: JsonHost,
    findings: Vec<JsonFinding>,
    hotspots: JsonHotspots,
    deep: Option<JsonDeep>,
    notes: &'a [String],
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
}

#[derive(Serialize)]
struct JsonQuery<'a> {
    input: &'a str,
    scope: &'static str,
}

#[derive(Serialize)]
struct JsonHost {
    physical_memory_total_bytes: u64,
    physical_memory_available_bytes: u64,
    effective_memory_total_bytes: u64,
    effective_memory_available_bytes: u64,
    effective_memory_available_percent: Option<f64>,
    memory_available_source: &'static str,
    cgroup_memory_limit_applied: bool,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
    swap_used_percent: Option<f64>,
    logical_cpu_count: usize,
    load_average: JsonLoadAverage,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct JsonLoadAverage {
    one: f64,
    five: f64,
    fifteen: f64,
    normalized_fifteen_per_logical_cpu: f64,
}

#[derive(Serialize)]
struct JsonFinding {
    code: &'static str,
    severity: DoctorSeverity,
    title: &'static str,
    summary: String,
    evidence: Vec<JsonProcessEvidence>,
    next_command: &'static str,
}

#[derive(Serialize)]
struct JsonProcessEvidence {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    status: String,
    command: String,
    cpu_percent: f32,
    memory_bytes: u64,
    memory_percent: Option<f64>,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    runtime_seconds: u64,
    subtree_process_count: usize,
}

#[derive(Serialize)]
struct JsonHotspots {
    cpu: Vec<JsonProcessEvidence>,
    memory: Vec<JsonProcessEvidence>,
    read: Vec<JsonProcessEvidence>,
    write: Vec<JsonProcessEvidence>,
}

#[derive(Serialize)]
struct JsonDeep {
    elapsed_ms: u64,
    exposed_listeners: JsonDeepListeners,
    file_descriptors: JsonDeepFd,
    deleted_open_files: JsonDeepDeleted,
    linux_oom: JsonDeepOom,
}

#[derive(Serialize)]
struct JsonDeepListeners {
    exposed_bind_count: usize,
    socket_reference_count: usize,
    known_owner_count: usize,
    unresolved_socket_count: usize,
    collection_complete: bool,
    warning: Option<String>,
    listeners: Vec<JsonDeepListener>,
}

#[derive(Serialize)]
struct JsonDeepListener {
    exposure: &'static str,
    protocol: String,
    local_endpoint: String,
    pid: Option<u32>,
    process: String,
    user: Option<String>,
    command: Option<String>,
    namespace: Option<String>,
}

#[derive(Serialize)]
struct JsonDeepFd {
    threshold_percent: u16,
    matched_process_count: usize,
    inspected_process_count: usize,
    limit_coverage_count: usize,
    collection_complete: bool,
    selection_complete: bool,
    warning: Option<String>,
    processes: Vec<JsonDeepFdProcess>,
}

#[derive(Serialize)]
struct JsonDeepFdProcess {
    pid: u32,
    process: String,
    user: String,
    command: String,
    open_fd_count: usize,
    soft_limit: Option<u64>,
    soft_limit_unlimited: bool,
    utilization_percent: Option<f64>,
    pressure: &'static str,
}

#[derive(Serialize)]
struct JsonDeepDeleted {
    minimum_reclaimable_bytes: u64,
    unique_file_count: usize,
    fd_reference_count: usize,
    process_count: usize,
    logical_bytes: u64,
    estimated_reclaimable_bytes: u64,
    estimate_basis: &'static str,
    warning: Option<String>,
    files: Vec<JsonDeepDeletedFile>,
}

#[derive(Serialize)]
struct JsonDeepDeletedFile {
    pid: u32,
    process: String,
    user: String,
    command: String,
    fd: String,
    path: String,
    logical_size_bytes: u64,
    estimated_reclaimable_bytes: u64,
}

#[derive(Serialize)]
struct JsonDeepOom {
    supported: bool,
    error: Option<String>,
    available_memory_bytes: Option<u64>,
    available_memory_percent: Option<f64>,
    oom_kill_count_since_boot: Option<u64>,
    pressure: Option<JsonDeepOomPressure>,
    minimum_oom_score: u16,
    matched_candidate_count: usize,
    score_inspected_process_count: usize,
    score_selection_complete: Option<bool>,
    warning: Option<String>,
    candidates: Vec<JsonDeepOomCandidate>,
}

#[derive(Serialize)]
struct JsonDeepOomPressure {
    some_avg10_percent: f64,
    some_avg60_percent: f64,
    full_avg10_percent: f64,
    full_avg60_percent: f64,
}

#[derive(Serialize)]
struct JsonDeepOomCandidate {
    pid: u32,
    process: String,
    user: String,
    command: String,
    oom_score: u16,
    oom_score_adj: Option<i16>,
    selection_priority: &'static str,
    rss_bytes: u64,
    swap_bytes: Option<u64>,
    cgroup_path: Option<String>,
    cgroup_oom_event_count: Option<u64>,
    cgroup_oom_kill_count: Option<u64>,
}

fn json_process(process: &ProcessEvidence) -> JsonProcessEvidence {
    JsonProcessEvidence {
        pid: process.pid,
        parent_pid: process.parent_pid,
        name: process.name.clone(),
        user: process.user.clone(),
        status: process.status.clone(),
        command: crate::model::command_for_output(&process.command),
        cpu_percent: process.cpu_percent,
        memory_bytes: process.memory_bytes,
        memory_percent: process.memory_percent,
        read_bytes_per_second: process.read_bytes_per_second,
        write_bytes_per_second: process.write_bytes_per_second,
        runtime_seconds: process.runtime_seconds,
        subtree_process_count: process.subtree_process_count,
    }
}

fn json_processes(processes: &[ProcessEvidence]) -> Vec<JsonProcessEvidence> {
    processes.iter().map(json_process).collect()
}

fn json_deep(deep: &DoctorDeepEvidence) -> JsonDeep {
    let oom = deep.oom.as_ref();
    JsonDeep {
        elapsed_ms: deep.elapsed_ms,
        exposed_listeners: JsonDeepListeners {
            exposed_bind_count: deep.listeners.exposed_bind_count,
            socket_reference_count: deep.listeners.socket_reference_count,
            known_owner_count: deep.listeners.known_owner_count,
            unresolved_socket_count: deep.listeners.unresolved_socket_count,
            collection_complete: deep.listeners.collection_complete,
            warning: deep.listeners.warning.clone(),
            listeners: deep
                .listeners
                .listeners
                .iter()
                .map(|listener| JsonDeepListener {
                    exposure: listener.exposure,
                    protocol: sanitize_terminal_text(&listener.protocol),
                    local_endpoint: sanitize_terminal_text(&listener.local_endpoint),
                    pid: listener.pid,
                    process: sanitize_terminal_text(&listener.process),
                    user: listener.user.as_deref().map(sanitize_terminal_text),
                    command: listener
                        .command
                        .as_deref()
                        .map(command_for_output)
                        .map(|command| sanitize_terminal_text(&command)),
                    namespace: listener.namespace.as_deref().map(sanitize_terminal_text),
                })
                .collect(),
        },
        file_descriptors: JsonDeepFd {
            threshold_percent: 75,
            matched_process_count: deep.fd.matched_process_count,
            inspected_process_count: deep.fd.inspected_process_count,
            limit_coverage_count: deep.fd.limit_coverage_count,
            collection_complete: deep.fd.collection_complete,
            selection_complete: deep.fd.selection_complete,
            warning: deep.fd.warning.clone(),
            processes: deep
                .fd
                .processes
                .iter()
                .map(|process| JsonDeepFdProcess {
                    pid: process.pid,
                    process: sanitize_terminal_text(&process.process),
                    user: sanitize_terminal_text(&process.user),
                    command: sanitize_terminal_text(&command_for_output(&process.command)),
                    open_fd_count: process.open_fd_count,
                    soft_limit: process.soft_limit,
                    soft_limit_unlimited: process.soft_limit_unlimited,
                    utilization_percent: process.utilization_percent,
                    pressure: process.pressure,
                })
                .collect(),
        },
        deleted_open_files: JsonDeepDeleted {
            minimum_reclaimable_bytes: 100 * MIB,
            unique_file_count: deep.deleted.unique_file_count,
            fd_reference_count: deep.deleted.fd_reference_count,
            process_count: deep.deleted.process_count,
            logical_bytes: deep.deleted.logical_bytes,
            estimated_reclaimable_bytes: deep.deleted.estimated_reclaimable_bytes,
            estimate_basis: deep.deleted.estimate_basis,
            warning: deep.deleted.warning.clone(),
            files: deep
                .deleted
                .files
                .iter()
                .map(|file| JsonDeepDeletedFile {
                    pid: file.pid,
                    process: sanitize_terminal_text(&file.process),
                    user: sanitize_terminal_text(&file.user),
                    command: sanitize_terminal_text(&command_for_output(&file.command)),
                    fd: sanitize_terminal_text(&file.fd),
                    path: sanitize_terminal_text(&file.path),
                    logical_size_bytes: file.logical_size_bytes,
                    estimated_reclaimable_bytes: file.estimated_reclaimable_bytes,
                })
                .collect(),
        },
        linux_oom: JsonDeepOom {
            supported: deep.oom_supported,
            error: deep.oom_error.clone(),
            available_memory_bytes: oom.and_then(|oom| oom.available_memory_bytes),
            available_memory_percent: oom.and_then(|oom| oom.available_memory_percent),
            oom_kill_count_since_boot: oom.and_then(|oom| oom.oom_kill_count_since_boot),
            pressure: oom
                .and_then(|oom| oom.pressure)
                .map(|pressure| JsonDeepOomPressure {
                    some_avg10_percent: pressure.some_avg10_percent,
                    some_avg60_percent: pressure.some_avg60_percent,
                    full_avg10_percent: pressure.full_avg10_percent,
                    full_avg60_percent: pressure.full_avg60_percent,
                }),
            minimum_oom_score: 500,
            matched_candidate_count: oom.map_or(0, |oom| oom.matched_candidate_count),
            score_inspected_process_count: oom.map_or(0, |oom| oom.score_inspected_process_count),
            score_selection_complete: oom.map(|oom| oom.score_selection_complete),
            warning: oom.and_then(|oom| oom.warning.clone()),
            candidates: oom
                .map(|oom| {
                    oom.candidates
                        .iter()
                        .map(|candidate| JsonDeepOomCandidate {
                            pid: candidate.pid,
                            process: sanitize_terminal_text(&candidate.process),
                            user: sanitize_terminal_text(&candidate.user),
                            command: sanitize_terminal_text(&command_for_output(
                                &candidate.command,
                            )),
                            oom_score: candidate.oom_score,
                            oom_score_adj: candidate.oom_score_adj,
                            selection_priority: candidate.selection_priority,
                            rss_bytes: candidate.rss_bytes,
                            swap_bytes: candidate.swap_bytes,
                            cgroup_path: candidate
                                .cgroup_path
                                .as_deref()
                                .map(sanitize_terminal_text),
                            cgroup_oom_event_count: candidate.cgroup_oom_event_count,
                            cgroup_oom_kill_count: candidate.cgroup_oom_kill_count,
                        })
                        .collect()
                })
                .unwrap_or_default(),
        },
    }
}

pub(crate) fn render_doctor_json(
    captured: &CapturedDoctor,
    fail_on: DoctorFailOn,
    policy_status: Option<DoctorPolicyStatus>,
) -> Result<String, String> {
    let host = captured.host;
    let document = JsonDoctor {
        schema: DOCTOR_SCHEMA,
        schema_version: DOCTOR_SCHEMA_VERSION,
        privacy_notice: "Process command lines, paths, users, hostnames, and network metadata may contain sensitive information. Use --redact and review before sharing.",
        secrets_redacted: output_secret_redaction_enabled(),
        tool: JsonTool {
            name: "psmore",
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        sample_interval_ms: captured.sample_interval_ms,
        status: captured.status_label(),
        policy: JsonPolicy {
            fail_on: fail_on.label(),
            passed: policy_status.map(DoctorPolicyStatus::passed),
            status: policy_status.map(DoctorPolicyStatus::label),
        },
        query: (!captured.query.trim().is_empty()).then_some(JsonQuery {
            input: &captured.query,
            scope: "process_signals_and_hotspots_only",
        }),
        system_process_count: captured.system_process_count,
        scoped_process_count: captured.scoped_process_count,
        finding_count: captured.findings.len(),
        critical_finding_count: captured.critical_count(),
        warning_finding_count: captured.warning_count(),
        result_limit_per_section: captured.result_limit,
        host: JsonHost {
            physical_memory_total_bytes: host.physical_memory_total_bytes,
            physical_memory_available_bytes: host.physical_memory_available_bytes,
            effective_memory_total_bytes: host.effective_memory_total_bytes,
            effective_memory_available_bytes: host.effective_memory_available_bytes,
            effective_memory_available_percent: host.memory_available_percent(),
            memory_available_source: host.memory_available_source,
            cgroup_memory_limit_applied: host.cgroup_memory_limit_applied,
            swap_total_bytes: host.swap_total_bytes,
            swap_used_bytes: host.swap_used_bytes,
            swap_used_percent: host.swap_used_percent(),
            logical_cpu_count: host.logical_cpu_count,
            load_average: JsonLoadAverage {
                one: host.load_one,
                five: host.load_five,
                fifteen: host.load_fifteen,
                normalized_fifteen_per_logical_cpu: host.normalized_load_fifteen(),
            },
            uptime_seconds: host.uptime_seconds,
        },
        findings: captured
            .findings
            .iter()
            .map(|finding| JsonFinding {
                code: finding.code,
                severity: finding.severity,
                title: finding.title,
                summary: finding.summary.clone(),
                evidence: json_processes(&finding.evidence),
                next_command: finding.next_command,
            })
            .collect(),
        hotspots: JsonHotspots {
            cpu: json_processes(&captured.hotspots.cpu),
            memory: json_processes(&captured.hotspots.memory),
            read: json_processes(&captured.hotspots.read),
            write: json_processes(&captured.hotspots.write),
        },
        deep: captured.deep.as_ref().map(json_deep),
        notes: &captured.notes,
    };
    serde_json::to_string_pretty(&document)
        .map_err(|error| format!("failed to serialize doctor report: {error}"))
}

fn optional_percent(value: Option<f64>) -> String {
    value
        .map(|percent| format!("{percent:.1}%"))
        .unwrap_or_else(|| "-".to_string())
}

fn render_evidence(process: &ProcessEvidence) -> String {
    format!(
        "      pid {:>6}  {:<16} cpu {:>6.1}%  mem {:>8} ({:>6})  io {:>9}/{:<9}  state {:<10}  {}",
        process.pid,
        process.name,
        process.cpu_percent,
        human_bytes(process.memory_bytes),
        optional_percent(process.memory_percent),
        human_rate(process.read_bytes_per_second),
        human_rate(process.write_bytes_per_second),
        process.status,
        command_for_output(&process.command)
    )
}

fn render_hotspot_section(
    output: &mut String,
    label: &str,
    processes: &[ProcessEvidence],
    value: impl Fn(&ProcessEvidence) -> String,
) {
    output.push_str(&format!("{label}\n"));
    if processes.is_empty() {
        output.push_str("  (no non-zero samples)\n");
        return;
    }
    for (index, process) in processes.iter().enumerate() {
        output.push_str(&format!(
            "  {:>2}. {:>10}  pid {:>6}  {:<18}  {}\n",
            index + 1,
            value(process),
            process.pid,
            process.name,
            crate::model::command_for_output(&process.command)
        ));
    }
}

fn collection_label(complete: bool) -> &'static str {
    if complete { "complete" } else { "partial" }
}

fn render_deep_table(output: &mut String, deep: &DoctorDeepEvidence) {
    output.push_str(&format!("\nDEEP CHECKS  elapsed {}ms\n", deep.elapsed_ms));
    output.push_str(&format!(
        "EXPOSED LISTENERS  {} bind(s), {} socket reference(s), {} owner(s), {} unresolved, showing {}  collection {}\n",
        deep.listeners.exposed_bind_count,
        deep.listeners.socket_reference_count,
        deep.listeners.known_owner_count,
        deep.listeners.unresolved_socket_count,
        deep.listeners.listeners.len(),
        collection_label(deep.listeners.collection_complete),
    ));
    if deep.listeners.listeners.is_empty() {
        output.push_str("  (no exposed listener visible)\n");
    }
    for listener in &deep.listeners.listeners {
        output.push_str(&format!(
            "  {:<8} {:<5} {:<30} pid {:>7}  {:<14} {}\n",
            listener.exposure.to_ascii_uppercase(),
            sanitize_terminal_text(&listener.protocol),
            sanitize_terminal_text(&listener.local_endpoint),
            listener
                .pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_string()),
            sanitize_terminal_text(&listener.process),
            listener
                .command
                .as_deref()
                .map(command_for_output)
                .unwrap_or_else(|| "[command unavailable]".to_string()),
        ));
    }

    output.push_str(&format!(
        "FD PRESSURE >=75%  {} matched / {} inspected, limits known for {}, showing {}  collection {}, selection {}\n",
        deep.fd.matched_process_count,
        deep.fd.inspected_process_count,
        deep.fd.limit_coverage_count,
        deep.fd.processes.len(),
        collection_label(deep.fd.collection_complete),
        collection_label(deep.fd.selection_complete),
    ));
    if deep.fd.processes.is_empty() {
        output.push_str("  (no visible process proven at or above 75%)\n");
    }
    for process in &deep.fd.processes {
        output.push_str(&format!(
            "  {:<8} pid {:>7}  fd {:>7}/{:<10} {:>7}  {:<14} {}\n",
            process.pressure.to_ascii_uppercase(),
            process.pid,
            process.open_fd_count,
            process
                .soft_limit
                .map(|limit| limit.to_string())
                .unwrap_or_else(|| {
                    if process.soft_limit_unlimited {
                        "unlimited".to_string()
                    } else {
                        "-".to_string()
                    }
                }),
            optional_percent(process.utilization_percent),
            sanitize_terminal_text(&process.process),
            command_for_output(&process.command),
        ));
    }

    output.push_str(&format!(
        "DELETED OPEN FILES >=100MiB  {} unique / {} fd reference(s) / {} process(es), reclaim approximately {}, showing {}, basis {}\n",
        deep.deleted.unique_file_count,
        deep.deleted.fd_reference_count,
        deep.deleted.process_count,
        human_bytes(deep.deleted.estimated_reclaimable_bytes),
        deep.deleted.files.len(),
        deep.deleted.estimate_basis,
    ));
    if deep.deleted.files.is_empty() {
        output.push_str("  (no matching deleted-open file visible)\n");
    }
    for file in &deep.deleted.files {
        output.push_str(&format!(
            "  {:>9}  pid {:>7} fd {:<7} {:<14} {}\n      {}\n",
            human_bytes(file.estimated_reclaimable_bytes),
            file.pid,
            sanitize_terminal_text(&file.fd),
            sanitize_terminal_text(&file.process),
            sanitize_terminal_text(&file.path),
            command_for_output(&file.command),
        ));
    }

    if let Some(oom) = &deep.oom {
        output.push_str(&format!(
            "LINUX OOM/PSI  {} candidate(s) score>=500 / {} inspected, showing {}, score selection {}  available {}  oom_kill since boot {}\n",
            oom.matched_candidate_count,
            oom.score_inspected_process_count,
            oom.candidates.len(),
            collection_label(oom.score_selection_complete),
            optional_percent(oom.available_memory_percent),
            oom.oom_kill_count_since_boot
                .map(|count| count.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ));
        if let Some(pressure) = oom.pressure {
            output.push_str(&format!(
                "  PSI some avg10/60 {:.2}/{:.2}%  full {:.2}/{:.2}%\n",
                pressure.some_avg10_percent,
                pressure.some_avg60_percent,
                pressure.full_avg10_percent,
                pressure.full_avg60_percent,
            ));
        } else {
            output.push_str("  PSI unavailable\n");
        }
        for candidate in &oom.candidates {
            output.push_str(&format!(
                "  {:<10} score {:>4} adj {:>5}  rss {:>9} swap {:>9}  pid {:>7} {:<14} {}\n",
                candidate.selection_priority.to_ascii_uppercase(),
                candidate.oom_score,
                candidate
                    .oom_score_adj
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                human_bytes(candidate.rss_bytes),
                candidate
                    .swap_bytes
                    .map(human_bytes)
                    .unwrap_or_else(|| "-".to_string()),
                candidate.pid,
                sanitize_terminal_text(&candidate.process),
                command_for_output(&candidate.command),
            ));
        }
    } else {
        output.push_str(&format!(
            "LINUX OOM/PSI  {}\n",
            deep.oom_error.as_deref().unwrap_or("unavailable")
        ));
    }
}

pub(crate) fn render_doctor_table(
    captured: &CapturedDoctor,
    fail_on: DoctorFailOn,
    policy_status: Option<DoctorPolicyStatus>,
) -> String {
    let status = if captured.critical_count() > 0 {
        "CRITICAL SIGNALS"
    } else if captured.warning_count() > 0 {
        "WARNING SIGNALS"
    } else {
        "NO CONFIGURED SIGNALS"
    };
    let mut output = format!(
        "PSMORE DOCTOR  {status}  findings {} (critical {}, warning {})  processes {}/{}  sample {}ms\n",
        captured.findings.len(),
        captured.critical_count(),
        captured.warning_count(),
        captured.scoped_process_count,
        captured.system_process_count,
        captured.sample_interval_ms
    );
    if let Some(policy) = policy_status {
        output.push_str(&format!(
            "POLICY {}  fail-on {}\n",
            policy.label().to_ascii_uppercase(),
            fail_on.label()
        ));
    }
    if !captured.query.trim().is_empty() {
        output.push_str(&format!(
            "PROCESS SCOPE  {}  (host checks remain global)\n",
            sanitize_terminal_text(&captured.query)
        ));
    }
    let host = captured.host;
    let memory_scope = if host.cgroup_memory_limit_applied {
        "cgroup"
    } else {
        "host"
    };
    output.push_str(&format!(
        "HOST  memory {}/{} available ({}, {memory_scope}, source {})  swap {}/{} used ({})\n",
        human_bytes(host.effective_memory_available_bytes),
        human_bytes(host.effective_memory_total_bytes),
        optional_percent(host.memory_available_percent()),
        host.memory_available_source,
        human_bytes(host.swap_used_bytes),
        human_bytes(host.swap_total_bytes),
        optional_percent(host.swap_used_percent()),
    ));
    output.push_str(&format!(
        "LOAD  {:.2} {:.2} {:.2}  logical CPUs {}  normalized 15m {:.2}  uptime {}s\n",
        host.load_one,
        host.load_five,
        host.load_fifteen,
        host.logical_cpu_count,
        host.normalized_load_fifteen(),
        host.uptime_seconds
    ));

    output.push_str("\nFINDINGS\n");
    if captured.findings.is_empty() {
        output.push_str(
            "  No configured warning or critical signals were observed in this sample.\n",
        );
    }
    for finding in &captured.findings {
        output.push_str(&format!(
            "  {}  {}  [{}]\n      {}\n",
            finding.severity.table_label(),
            finding.title,
            finding.code,
            finding.summary
        ));
        for process in &finding.evidence {
            output.push_str(&render_evidence(process));
            output.push('\n');
        }
        output.push_str(&format!("      next: {}\n", finding.next_command));
    }

    output.push_str("\nHOTSPOTS (process self, collector excluded)\n");
    render_hotspot_section(&mut output, "CPU", &captured.hotspots.cpu, |process| {
        format!("{:.1}%", process.cpu_percent)
    });
    render_hotspot_section(
        &mut output,
        "MEMORY",
        &captured.hotspots.memory,
        |process| human_bytes(process.memory_bytes),
    );
    render_hotspot_section(&mut output, "READ", &captured.hotspots.read, |process| {
        human_rate(process.read_bytes_per_second)
    });
    render_hotspot_section(&mut output, "WRITE", &captured.hotspots.write, |process| {
        human_rate(process.write_bytes_per_second)
    });

    if let Some(deep) = &captured.deep {
        render_deep_table(&mut output, deep);
    }

    output.push_str("\nNOTES\n");
    for note in &captured.notes {
        output.push_str(&format!("  - {note}\n"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn process(pid: u32, status: &str, cpu: f32, memory: u64) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: Some(Pid::from_u32(1)),
            name: format!("process-{pid}"),
            command: format!("worker --token secret-{pid}"),
            executable: "/usr/bin/worker".into(),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu,
            memory,
            read_rate: 0,
            write_rate: 0,
            start_time: 1_699_999_000,
            runtime: 120,
            status: status.into(),
        }
    }

    fn host() -> HostEvidence {
        HostEvidence {
            physical_memory_total_bytes: 8 * GIB,
            physical_memory_available_bytes: 4 * GIB,
            effective_memory_total_bytes: 8 * GIB,
            effective_memory_available_bytes: 4 * GIB,
            memory_available_source: "test",
            cgroup_memory_limit_applied: false,
            swap_total_bytes: 2 * GIB,
            swap_used_bytes: 0,
            logical_cpu_count: 4,
            load_one: 1.0,
            load_five: 1.0,
            load_fifteen: 1.0,
            uptime_seconds: 3_600,
        }
    }

    #[test]
    fn classifies_host_and_process_signals_conservatively() {
        let mut pressured_host = host();
        pressured_host.effective_memory_available_bytes = 300 * MIB;
        pressured_host.load_fifteen = 9.0;
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                process(1, "Sleep", 0.0, MIB),
                process(10, "Zombie", 0.0, MIB),
                process(20, "Run", 120.0, 3 * GIB),
            ],
            500,
        );
        let captured = analyze_doctor(&snapshot, "", pressured_host, Some(5)).unwrap();
        let codes = captured
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<HashSet<_>>();
        assert!(codes.contains("low_available_memory"));
        assert!(codes.contains("sustained_load"));
        assert!(codes.contains("zombie_processes"));
        assert!(codes.contains("large_process_memory_share"));
        assert!(codes.contains("high_cpu_sample"));
        assert_eq!(captured.critical_count(), 2);
        assert_eq!(
            captured.evaluate_policy(DoctorFailOn::Critical),
            Some(DoctorPolicyStatus::Violated)
        );
    }

    #[test]
    fn query_scopes_process_checks_but_not_host_checks() {
        let mut pressured_host = host();
        pressured_host.effective_memory_available_bytes = 100 * MIB;
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                process(1, "Sleep", 0.0, MIB),
                process(10, "Zombie", 0.0, MIB),
            ],
            500,
        );
        let captured =
            analyze_doctor(&snapshot, "name:not-found", pressured_host, Some(5)).unwrap();
        assert_eq!(captured.scoped_process_count, 0);
        assert!(
            captured
                .findings
                .iter()
                .any(|finding| finding.code == "low_available_memory")
        );
        assert!(
            captured
                .findings
                .iter()
                .all(|finding| finding.code != "zombie_processes")
        );
    }

    #[test]
    fn swap_occupancy_only_warns_with_current_memory_pressure() {
        let snapshot = ProcessSnapshot::from_processes(vec![process(1, "Sleep", 0.0, MIB)], 500);
        let mut evidence = host();
        evidence.swap_used_bytes = 3 * GIB / 2;
        let healthy = analyze_doctor(&snapshot, "", evidence, Some(5)).unwrap();
        assert!(
            healthy
                .findings
                .iter()
                .all(|finding| finding.code != "swap_pressure")
        );

        evidence.effective_memory_available_bytes = GIB;
        let pressured = analyze_doctor(&snapshot, "", evidence, Some(5)).unwrap();
        assert!(
            pressured
                .findings
                .iter()
                .any(|finding| finding.code == "swap_pressure")
        );
    }

    #[test]
    fn stable_hotspots_respect_limit_and_json_schema() {
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                process(1, "Sleep", 0.0, MIB),
                process(10, "Run", 10.0, 2 * GIB),
                process(20, "Run", 20.0, GIB),
            ],
            500,
        );
        let captured = analyze_doctor(&snapshot, "", host(), Some(1)).unwrap();
        assert_eq!(captured.hotspots.cpu[0].pid, 20);
        assert_eq!(captured.hotspots.memory[0].pid, 10);
        assert_eq!(captured.hotspots.cpu.len(), 1);
        let json = render_doctor_json(&captured, DoctorFailOn::Never, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["schema"], DOCTOR_SCHEMA);
        assert_eq!(parsed["schema_version"], DOCTOR_SCHEMA_VERSION);
        assert_eq!(parsed["policy"]["passed"], serde_json::Value::Null);
    }

    #[test]
    fn deep_evidence_adds_only_actionable_findings_and_serializes_details() {
        let snapshot = ProcessSnapshot::from_processes(
            vec![
                process(1, "Sleep", 0.0, MIB),
                process(10, "Run", 10.0, 128 * MIB),
            ],
            500,
        );
        let mut captured = analyze_doctor(&snapshot, "", host(), Some(5)).unwrap();
        let deep = DoctorDeepEvidence {
            elapsed_ms: 321,
            listeners: ListenerDiagnosticSummary {
                exposed_bind_count: 1,
                socket_reference_count: 1,
                known_owner_count: 1,
                unresolved_socket_count: 0,
                collection_complete: true,
                warning: None,
                listeners: vec![crate::headless_listen::ListenerDiagnosticItem {
                    exposure: "wildcard",
                    protocol: "TCP".into(),
                    local_endpoint: "0.0.0.0:8080".into(),
                    pid: Some(10),
                    process: "api".into(),
                    user: Some("deploy".into()),
                    command: Some("api --token secret".into()),
                    namespace: None,
                }],
            },
            fd: FdDiagnosticSummary {
                matched_process_count: 1,
                inspected_process_count: 2,
                limit_coverage_count: 2,
                collection_complete: true,
                selection_complete: true,
                warning: None,
                processes: vec![crate::headless_fd::FdDiagnosticItem {
                    pid: 10,
                    process: "api".into(),
                    user: "deploy".into(),
                    command: "api --token secret".into(),
                    open_fd_count: 52,
                    soft_limit: Some(64),
                    soft_limit_unlimited: false,
                    utilization_percent: Some(81.25),
                    pressure: "warning",
                }],
            },
            deleted: DeletedDiagnosticSummary {
                unique_file_count: 1,
                fd_reference_count: 1,
                process_count: 1,
                logical_bytes: 200 * MIB,
                estimated_reclaimable_bytes: 200 * MIB,
                estimate_basis: "allocated_blocks",
                warning: None,
                files: vec![crate::headless_deleted::DeletedDiagnosticItem {
                    pid: 10,
                    process: "api".into(),
                    user: "deploy".into(),
                    command: "api --token secret".into(),
                    fd: "7".into(),
                    path: "/tmp/api.log".into(),
                    logical_size_bytes: 200 * MIB,
                    estimated_reclaimable_bytes: 200 * MIB,
                }],
            },
            oom: Some(OomDiagnosticSummary {
                available_memory_bytes: Some(4 * GIB),
                available_memory_percent: Some(50.0),
                oom_kill_count_since_boot: Some(2),
                pressure: Some(crate::headless_oom::OomPressureSummary {
                    some_avg10_percent: 25.0,
                    some_avg60_percent: 8.0,
                    full_avg10_percent: 0.0,
                    full_avg60_percent: 0.0,
                }),
                matched_candidate_count: 1,
                score_inspected_process_count: 2,
                score_selection_complete: true,
                warning: None,
                candidates: vec![crate::headless_oom::OomDiagnosticCandidate {
                    pid: 10,
                    process: "api".into(),
                    user: "deploy".into(),
                    command: "api --token secret".into(),
                    oom_score: 600,
                    oom_score_adj: Some(0),
                    selection_priority: "high",
                    rss_bytes: 128 * MIB,
                    swap_bytes: Some(0),
                    cgroup_path: Some("/api".into()),
                    cgroup_oom_event_count: Some(1),
                    cgroup_oom_kill_count: Some(0),
                }],
            }),
            oom_supported: true,
            oom_error: None,
        };
        append_deep_findings(&mut captured, &deep);
        let codes = captured
            .findings
            .iter()
            .map(|finding| finding.code)
            .collect::<HashSet<_>>();
        assert!(codes.contains("file_descriptor_pressure"));
        assert!(codes.contains("deleted_open_files"));
        assert!(codes.contains("linux_memory_psi"));
        assert!(!codes.contains("exposed_listeners"));
        captured.deep = Some(deep);

        let json = render_doctor_json(&captured, DoctorFailOn::Never, None).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["deep"]["elapsed_ms"], 321);
        assert_eq!(parsed["deep"]["exposed_listeners"]["exposed_bind_count"], 1);
        assert_eq!(
            parsed["deep"]["file_descriptors"]["processes"][0]["open_fd_count"],
            52
        );
        assert_eq!(
            parsed["deep"]["linux_oom"]["pressure"]["some_avg10_percent"],
            25.0
        );
        let table = render_doctor_table(&captured, DoctorFailOn::Never, None);
        assert!(table.contains("DEEP CHECKS  elapsed 321ms"));
        assert!(table.contains("DELETED OPEN FILES >=100MiB"));
    }

    #[test]
    fn status_helpers_cover_native_and_sysinfo_labels() {
        assert!(is_zombie("Zombie"));
        assert!(is_zombie("Z+"));
        assert!(is_stopped("Stopped"));
        assert!(is_stopped("T+"));
        assert!(!is_zombie("Sleep"));
        assert!(!is_stopped("Run"));
    }

    #[test]
    fn parses_macos_memory_pressure_and_vm_stat_fallback() {
        assert_eq!(
            parse_memory_pressure_free_percent(
                "The system has 17179869184 bytes.\nSystem-wide memory free percentage: 44%\n"
            ),
            Some(44.0)
        );
        assert_eq!(
            parse_vm_stat_available_bytes(
                "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
                 Pages free: 10.\n\
                 Pages active: 999.\n\
                 Pages inactive: 20.\n\
                 Pages speculative: 5.\n"
            ),
            Some(35 * 16_384)
        );
    }
}
