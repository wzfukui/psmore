use std::{
    fmt::Write as _,
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::Value;
use sysinfo::{Pid, System};

use crate::{
    cli::{LogPriority, LogScope},
    headless_exe::{capture_executable, render_executable_json, render_executable_table},
    headless_inspect::{capture_inspection, render_inspection_json, render_inspection_table},
    headless_logs::{capture_logs, render_logs_json, render_logs_table},
    headless_service::{capture_service_context, render_service_json, render_service_table},
    model::{ProcessInfo, process_command_for_output, process_path, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const DOSSIER_SCHEMA: &str = "psmore.process-dossier";
const DOSSIER_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExplainOptions {
    pub(crate) sample_ms: u64,
    pub(crate) hash: bool,
    pub(crate) include_logs: bool,
    pub(crate) logs_scope: LogScope,
    pub(crate) logs_priority: LogPriority,
    pub(crate) logs_since_seconds: u64,
    pub(crate) logs_limit: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum SignalSeverity {
    Ok,
    Notice,
    Warning,
    Critical,
}

impl SignalSeverity {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    fn table_label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Notice => "NOTE",
            Self::Warning => "WARN",
            Self::Critical => "CRIT",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct DossierSignal {
    severity: SignalSeverity,
    code: &'static str,
    summary: String,
    evidence_path: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SectionStatus {
    Complete,
    Partial,
    Failed,
    Skipped,
}

impl SectionStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct EvidenceSection {
    status: SectionStatus,
    duration_ms: u64,
    error: Option<String>,
    report: Option<Value>,
    #[serde(skip)]
    table: Option<String>,
}

impl EvidenceSection {
    fn skipped() -> Self {
        Self {
            status: SectionStatus::Skipped,
            duration_ms: 0,
            error: None,
            report: None,
            table: None,
        }
    }

    fn failed(duration_ms: u64, error: String) -> Self {
        Self {
            status: SectionStatus::Failed,
            duration_ms,
            error: Some(sanitize_terminal_text(&error)),
            report: None,
            table: None,
        }
    }

    fn invalidate(&mut self, error: String) {
        self.status = SectionStatus::Failed;
        self.error = Some(sanitize_terminal_text(&error));
        self.report = None;
        self.table = None;
    }
}

fn elapsed_millis(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn capture_section<T, C, J, R, E>(capture: C, json: J, table: R) -> EvidenceSection
where
    C: FnOnce() -> Result<T, String>,
    J: FnOnce(&T) -> Result<String, E>,
    R: FnOnce(&T) -> String,
    E: ToString,
{
    let started = Instant::now();
    let captured = match capture() {
        Ok(captured) => captured,
        Err(error) => return EvidenceSection::failed(elapsed_millis(started), error),
    };
    let json = match json(&captured) {
        Ok(json) => json,
        Err(error) => return EvidenceSection::failed(elapsed_millis(started), error.to_string()),
    };
    let report = match serde_json::from_str(&json) {
        Ok(report) => report,
        Err(error) => {
            return EvidenceSection::failed(
                elapsed_millis(started),
                format!("could not parse the generated evidence report: {error}"),
            );
        }
    };
    EvidenceSection {
        status: SectionStatus::Complete,
        duration_ms: elapsed_millis(started),
        error: None,
        report: Some(report),
        table: Some(table(&captured)),
    }
}

#[derive(Clone, Debug, Serialize)]
struct DossierTarget {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    status: String,
    path: String,
    command: String,
    start_time_unix_seconds: u64,
    runtime_seconds: u64,
}

impl From<&ProcessInfo> for DossierTarget {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: sanitize_terminal_text(&process.name),
            user: sanitize_terminal_text(&process.user),
            status: sanitize_terminal_text(&process.status),
            path: sanitize_terminal_text(&process_path(process)),
            command: sanitize_terminal_text(&process_command_for_output(process)),
            start_time_unix_seconds: process.start_time,
            runtime_seconds: process.runtime,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DossierIdentity {
    Verified,
    Unverified,
    ExitedDuringCollection,
}

impl DossierIdentity {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
            Self::ExitedDuringCollection => "exited_during_collection",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct DossierCollection {
    parallel: bool,
    duration_ms: u64,
    process_sample_interval_ms: u64,
    executable_hashing: bool,
    logs_requested: bool,
    logs_scope: &'static str,
    logs_priority: &'static str,
    logs_since_seconds: u64,
    logs_limit: usize,
    requested_sections: usize,
    complete_sections: usize,
    partial_sections: usize,
    failed_sections: usize,
}

#[derive(Clone, Debug, Serialize)]
struct DossierSummary {
    status: &'static str,
    critical_count: usize,
    warning_count: usize,
    notice_count: usize,
}

#[derive(Clone, Debug, Serialize)]
struct DossierEvidence {
    inspection: EvidenceSection,
    service_context: EvidenceSection,
    executable_image: EvidenceSection,
    native_logs: EvidenceSection,
}

impl DossierEvidence {
    fn sections(&self) -> [(&'static str, &EvidenceSection); 4] {
        [
            ("inspection", &self.inspection),
            ("service_context", &self.service_context),
            ("executable_image", &self.executable_image),
            ("native_logs", &self.native_logs),
        ]
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CapturedDossier {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: DossierTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    process_identity: DossierIdentity,
    process_identity_warning: Option<String>,
    target: DossierTarget,
    collection: DossierCollection,
    summary: DossierSummary,
    signals: Vec<DossierSignal>,
    evidence: DossierEvidence,
}

#[derive(Clone, Debug, Serialize)]
struct DossierTool {
    name: &'static str,
    version: &'static str,
}

fn report_string<'a>(report: &'a Value, pointer: &str) -> Option<&'a str> {
    report.pointer(pointer).and_then(Value::as_str)
}

fn report_u64(report: &Value, pointer: &str) -> Option<u64> {
    report.pointer(pointer).and_then(Value::as_u64)
}

fn report_f64(report: &Value, pointer: &str) -> Option<f64> {
    report.pointer(pointer).and_then(Value::as_f64)
}

fn inspection_field_value<'a>(report: &'a Value, label: &str) -> Option<&'a str> {
    report
        .pointer("/resource_limits")
        .and_then(Value::as_array)?
        .iter()
        .find(|field| report_string(field, "/label") == Some(label))
        .and_then(|field| report_string(field, "/value"))
}

fn parse_soft_limit(value: &str) -> Option<u64> {
    let value = value.strip_prefix("soft ")?;
    let value = value.split_whitespace().next()?;
    if value.eq_ignore_ascii_case("unlimited") {
        None
    } else {
        value.parse().ok()
    }
}

fn array_len(report: &Value, pointer: &str) -> usize {
    report
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("TiB", 1 << 40),
        ("GiB", 1 << 30),
        ("MiB", 1 << 20),
        ("KiB", 1 << 10),
    ];
    for (unit, divisor) in UNITS {
        if bytes >= divisor {
            return format!("{:.1} {unit}", bytes as f64 / divisor as f64);
        }
    }
    format!("{bytes} B")
}

fn limit_ratio(current: u64, maximum: u64) -> Option<f64> {
    if maximum == 0 {
        (current > 0).then_some(f64::INFINITY)
    } else {
        Some(current as f64 / maximum as f64)
    }
}

fn section_contract_complete(name: &str, report: &Value) -> bool {
    if report_string(report, "/process_identity") != Some("verified") {
        return false;
    }
    match name {
        "inspection" => {
            report
                .pointer("/collection_warning")
                .is_none_or(Value::is_null)
                && report
                    .pointer("/hot_threads/warning")
                    .is_none_or(Value::is_null)
        }
        "service_context" => report
            .pointer("/service/collection/complete")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "executable_image" => report
            .pointer("/collection/complete")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "native_logs" => report
            .pointer("/source/complete")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

fn validate_section_identity(name: &str, section: &mut EvidenceSection, target: &DossierTarget) {
    let Some(report) = section.report.as_ref() else {
        return;
    };
    let report_pid = report_u64(report, "/process/pid").and_then(|pid| u32::try_from(pid).ok());
    if report_pid != Some(target.pid) {
        section.invalidate(format!(
            "{name} evidence identified PID {:?}, expected {}; refusing cross-process attribution",
            report_pid, target.pid
        ));
        return;
    }
    let report_start = report_u64(report, "/process/start_time_unix_seconds");
    if target.start_time_unix_seconds > 0 && report_start != Some(target.start_time_unix_seconds) {
        section.invalidate(format!(
            "{name} evidence has start time {:?}, expected {}; refusing to combine different process instances",
            report_start, target.start_time_unix_seconds
        ));
        return;
    }
    section.status = if section_contract_complete(name, report) {
        SectionStatus::Complete
    } else {
        SectionStatus::Partial
    };
}

fn signal(
    signals: &mut Vec<DossierSignal>,
    severity: SignalSeverity,
    code: &'static str,
    summary: impl Into<String>,
    evidence_path: &'static str,
) {
    signals.push(DossierSignal {
        severity,
        code,
        summary: sanitize_terminal_text(&summary.into()),
        evidence_path,
    });
}

fn collect_signals(target: &DossierTarget, evidence: &DossierEvidence) -> Vec<DossierSignal> {
    let mut signals = Vec::new();
    let status = target.status.to_ascii_lowercase();
    if status.contains("zombie") || status == "z" {
        signal(
            &mut signals,
            SignalSeverity::Critical,
            "process.zombie",
            "process is a zombie and is waiting for its parent to reap it",
            "/target/status",
        );
    } else if status.contains("stop") || status == "t" {
        signal(
            &mut signals,
            SignalSeverity::Warning,
            "process.stopped",
            "process is stopped rather than runnable",
            "/target/status",
        );
    }

    if let Some(report) = evidence.inspection.report.as_ref() {
        if let Some(cpu_percent) = report_f64(report, "/process/cpu_percent") {
            if cpu_percent >= 80.0 {
                signal(
                    &mut signals,
                    SignalSeverity::Notice,
                    "resource.cpu_hot_sample",
                    format!(
                        "process used {cpu_percent:.1}% CPU during the dossier sample; confirm with a longer trace if unexpected"
                    ),
                    "/evidence/inspection/report/process/cpu_percent",
                );
            }
        }

        let thread_count = report_u64(report, "/hot_threads/total_count").unwrap_or(0);
        if thread_count >= 500 {
            signal(
                &mut signals,
                if thread_count >= 2_000 {
                    SignalSeverity::Warning
                } else {
                    SignalSeverity::Notice
                },
                "resource.thread_volume",
                format!("process has {thread_count} threads; review growth and scheduler pressure"),
                "/evidence/inspection/report/hot_threads/total_count",
            );
        }

        let socket_count = array_len(report, "/sockets") as u64;
        if socket_count >= 250 {
            signal(
                &mut signals,
                if socket_count >= 1_000 {
                    SignalSeverity::Warning
                } else {
                    SignalSeverity::Notice
                },
                "resource.socket_volume",
                format!("process has at least {socket_count} visible socket descriptors"),
                "/evidence/inspection/report/sockets",
            );
        }

        let visible_descriptors =
            socket_count.saturating_add(array_len(report, "/open_files") as u64);
        if let Some(soft_limit) =
            inspection_field_value(report, "OPEN FILES").and_then(parse_soft_limit)
        {
            if let Some(ratio) = limit_ratio(visible_descriptors, soft_limit) {
                let severity = if ratio >= 1.0 {
                    Some(SignalSeverity::Critical)
                } else if ratio >= 0.90 {
                    Some(SignalSeverity::Warning)
                } else if ratio >= 0.75 {
                    Some(SignalSeverity::Notice)
                } else {
                    None
                };
                if let Some(severity) = severity {
                    signal(
                        &mut signals,
                        severity,
                        if ratio >= 1.0 {
                            "resource.fd_limit_exhausted"
                        } else {
                            "resource.fd_limit_pressure"
                        },
                        format!(
                            "at least {visible_descriptors} visible descriptors use {:.1}% of the soft open-file limit {soft_limit}",
                            ratio * 100.0
                        ),
                        "/evidence/inspection/report/resource_limits",
                    );
                }
            }
        }
    }

    if let Some(report) = evidence.executable_image.report.as_ref() {
        if report
            .pointer("/comparison/attention_required")
            .and_then(Value::as_bool)
            == Some(true)
        {
            let image_status = report_string(report, "/comparison/status").unwrap_or("unverified");
            signal(
                &mut signals,
                SignalSeverity::Warning,
                "executable.image_attention",
                format!("running executable image requires attention: {image_status}"),
                "/evidence/executable_image/report/comparison",
            );
        }
        if report.pointer("/signing/signed").and_then(Value::as_bool) == Some(true)
            && report.pointer("/signing/valid").and_then(Value::as_bool) == Some(false)
        {
            signal(
                &mut signals,
                SignalSeverity::Critical,
                "executable.invalid_signature",
                "the executable is signed but strict signature verification failed",
                "/evidence/executable_image/report/signing",
            );
        }
    }

    if let Some(report) = evidence.service_context.report.as_ref() {
        let active = report_string(report, "/service/state/active_state");
        let result = report_string(report, "/service/state/result");
        if active == Some("failed") || result == Some("failed") {
            signal(
                &mut signals,
                SignalSeverity::Critical,
                "service.failed",
                format!(
                    "owning service reports active={} result={}",
                    active.unwrap_or("unknown"),
                    result.unwrap_or("unknown")
                ),
                "/evidence/service_context/report/service/state",
            );
        }
        if report
            .pointer("/service/state/need_daemon_reload")
            .and_then(Value::as_bool)
            == Some(true)
        {
            signal(
                &mut signals,
                SignalSeverity::Warning,
                "service.daemon_reload_needed",
                "service manager reports that unit configuration changed on disk",
                "/evidence/service_context/report/service/state/need_daemon_reload",
            );
        }
        if let Some(exit_status) = report_u64(report, "/service/state/exec_main_status") {
            if exit_status != 0 {
                signal(
                    &mut signals,
                    SignalSeverity::Warning,
                    "service.nonzero_exit",
                    format!("service manager recorded main-process exit status {exit_status}"),
                    "/evidence/service_context/report/service/state/exec_main_status",
                );
            }
        }
        if let Some(restarts) = report_u64(report, "/service/state/restart_count") {
            if restarts > 0 {
                signal(
                    &mut signals,
                    if restarts >= 3 {
                        SignalSeverity::Warning
                    } else {
                        SignalSeverity::Notice
                    },
                    "service.restarts",
                    format!("service manager recorded {restarts} restart(s)"),
                    "/evidence/service_context/report/service/state/restart_count",
                );
            }
        }
        if let (Some(current), Some(maximum)) = (
            report_u64(report, "/service/resources/tasks_current"),
            report_u64(report, "/service/resources/tasks_max/value"),
        ) {
            if let Some(ratio) = limit_ratio(current, maximum) {
                let severity = if ratio >= 1.0 {
                    Some(SignalSeverity::Critical)
                } else if ratio >= 0.90 {
                    Some(SignalSeverity::Warning)
                } else if ratio >= 0.75 {
                    Some(SignalSeverity::Notice)
                } else {
                    None
                };
                if let Some(severity) = severity {
                    signal(
                        &mut signals,
                        severity,
                        if ratio >= 1.0 {
                            "resource.task_limit_exhausted"
                        } else {
                            "resource.task_limit_pressure"
                        },
                        format!(
                            "owning service uses {current}/{maximum} tasks ({:.1}% of TasksMax)",
                            ratio * 100.0
                        ),
                        "/evidence/service_context/report/service/resources/tasks_max",
                    );
                }
            }
        }
        if let (Some(current), Some(maximum)) = (
            report_u64(report, "/service/resources/memory_current_bytes"),
            report_u64(report, "/service/resources/memory_max_bytes/value"),
        ) {
            if let Some(ratio) = limit_ratio(current, maximum) {
                let severity = if ratio >= 1.0 {
                    Some(SignalSeverity::Critical)
                } else if ratio >= 0.90 {
                    Some(SignalSeverity::Warning)
                } else if ratio >= 0.80 {
                    Some(SignalSeverity::Notice)
                } else {
                    None
                };
                if let Some(severity) = severity {
                    signal(
                        &mut signals,
                        severity,
                        if ratio >= 1.0 {
                            "resource.memory_limit_exhausted"
                        } else {
                            "resource.memory_limit_pressure"
                        },
                        format!(
                            "owning service uses {}/{} ({:.1}% of MemoryMax)",
                            human_bytes(current),
                            human_bytes(maximum),
                            ratio * 100.0
                        ),
                        "/evidence/service_context/report/service/resources/memory_max_bytes",
                    );
                }
            }
        }
    }

    if let Some(report) = evidence.native_logs.report.as_ref() {
        let mut errors = 0usize;
        let mut warnings = 0usize;
        if let Some(entries) = report.pointer("/entries").and_then(Value::as_array) {
            for entry in entries {
                match report_string(entry, "/priority")
                    .unwrap_or("")
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "emerg" | "alert" | "crit" | "critical" | "err" | "error" | "fault" => {
                        errors += 1;
                    }
                    "warning" | "warn" => warnings += 1,
                    _ => {}
                }
            }
        }
        if errors > 0 {
            signal(
                &mut signals,
                SignalSeverity::Warning,
                "logs.errors",
                format!("selected log window contains {errors} error-level entry/entries"),
                "/evidence/native_logs/report/entries",
            );
        } else if warnings > 0 {
            signal(
                &mut signals,
                SignalSeverity::Notice,
                "logs.warnings",
                format!("selected log window contains {warnings} warning-level entry/entries"),
                "/evidence/native_logs/report/entries",
            );
        }
        if report.pointer("/source/truncated").and_then(Value::as_bool) == Some(true) {
            signal(
                &mut signals,
                SignalSeverity::Notice,
                "logs.truncated",
                "native log results reached the requested row limit",
                "/evidence/native_logs/report/source/truncated",
            );
        }
    }

    for (name, section) in evidence.sections() {
        match section.status {
            SectionStatus::Failed => signal(
                &mut signals,
                SignalSeverity::Warning,
                "collection.section_failed",
                format!(
                    "{name} evidence failed: {}",
                    section.error.as_deref().unwrap_or("unknown error")
                ),
                "/evidence",
            ),
            SectionStatus::Partial => signal(
                &mut signals,
                SignalSeverity::Notice,
                "collection.section_partial",
                format!(
                    "{name} evidence is partial; inspect its warnings before concluding absence"
                ),
                "/evidence",
            ),
            SectionStatus::Complete | SectionStatus::Skipped => {}
        }
    }

    signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.summary.cmp(&right.summary))
    });
    signals
}

fn summarize(signals: &[DossierSignal]) -> DossierSummary {
    let critical_count = signals
        .iter()
        .filter(|signal| signal.severity == SignalSeverity::Critical)
        .count();
    let warning_count = signals
        .iter()
        .filter(|signal| signal.severity == SignalSeverity::Warning)
        .count();
    let notice_count = signals
        .iter()
        .filter(|signal| signal.severity == SignalSeverity::Notice)
        .count();
    let status = signals
        .iter()
        .map(|signal| signal.severity)
        .max()
        .unwrap_or(SignalSeverity::Ok)
        .label();
    DossierSummary {
        status,
        critical_count,
        warning_count,
        notice_count,
    }
}

fn verify_final_identity(
    initial: &ProcessInfo,
    final_process: Option<&ProcessInfo>,
) -> Result<(DossierIdentity, Option<String>), String> {
    let Some(final_process) = final_process else {
        return Ok((
            DossierIdentity::ExitedDuringCollection,
            Some(format!(
                "PID {} exited during dossier collection; evidence remains tied to its original start time",
                initial.pid
            )),
        ));
    };
    if initial.start_time > 0 && final_process.start_time > 0 {
        if initial.start_time != final_process.start_time {
            return Err(format!(
                "PID {} was reused during dossier collection; refusing to combine different process instances",
                initial.pid
            ));
        }
        return Ok((DossierIdentity::Verified, None));
    }
    if initial.name != final_process.name
        || process_command_for_output(initial) != process_command_for_output(final_process)
    {
        return Err(format!(
            "PID {} changed identity during dossier collection",
            initial.pid
        ));
    }
    Ok((
        DossierIdentity::Unverified,
        Some(format!(
            "PID {} start time is unavailable; identity was checked using name and command fallback",
            initial.pid
        )),
    ))
}

pub(crate) fn capture_dossier(
    pid: u32,
    options: ExplainOptions,
) -> Result<CapturedDossier, String> {
    if pid == 0 {
        return Err("PID 0 is a virtual root and cannot produce a process dossier".into());
    }
    let started = Instant::now();
    let pid_value = Pid::from_u32(pid);
    let mut provider = NativeProcessProvider::new();
    let processes = provider.refresh();
    let initial = processes
        .into_iter()
        .find(|process| process.pid == pid_value)
        .ok_or_else(|| format!("PID {pid} was not found"))?;
    let target = DossierTarget::from(&initial);

    let (mut inspection, mut service_context, mut executable_image, mut native_logs) =
        thread::scope(|scope| {
            let inspection = scope.spawn(|| {
                capture_section(
                    || capture_inspection(pid, options.sample_ms),
                    render_inspection_json,
                    render_inspection_table,
                )
            });
            let service = scope.spawn(|| {
                capture_section(
                    || capture_service_context(pid),
                    render_service_json,
                    render_service_table,
                )
            });
            let executable = scope.spawn(|| {
                capture_section(
                    || capture_executable(pid, options.hash),
                    render_executable_json,
                    render_executable_table,
                )
            });
            let logs = options.include_logs.then(|| {
                scope.spawn(|| {
                    capture_section(
                        || {
                            capture_logs(
                                pid,
                                options.logs_scope,
                                options.logs_priority,
                                options.logs_since_seconds,
                                options.logs_limit,
                            )
                        },
                        render_logs_json,
                        render_logs_table,
                    )
                })
            });
            (
                inspection.join().unwrap_or_else(|_| {
                    EvidenceSection::failed(0, "inspection collector panicked".into())
                }),
                service.join().unwrap_or_else(|_| {
                    EvidenceSection::failed(0, "service-context collector panicked".into())
                }),
                executable.join().unwrap_or_else(|_| {
                    EvidenceSection::failed(0, "executable-image collector panicked".into())
                }),
                logs.map_or_else(EvidenceSection::skipped, |logs| {
                    logs.join().unwrap_or_else(|_| {
                        EvidenceSection::failed(0, "native-log collector panicked".into())
                    })
                }),
            )
        });

    validate_section_identity("inspection", &mut inspection, &target);
    validate_section_identity("service_context", &mut service_context, &target);
    validate_section_identity("executable_image", &mut executable_image, &target);
    validate_section_identity("native_logs", &mut native_logs, &target);

    let final_processes = provider.refresh();
    let (process_identity, process_identity_warning) = verify_final_identity(
        &initial,
        final_processes
            .iter()
            .find(|process| process.pid == pid_value),
    )?;
    let evidence = DossierEvidence {
        inspection,
        service_context,
        executable_image,
        native_logs,
    };
    let signals = collect_signals(&target, &evidence);
    let summary = summarize(&signals);
    let requested_sections = evidence
        .sections()
        .iter()
        .filter(|(_, section)| section.status != SectionStatus::Skipped)
        .count();
    let complete_sections = evidence
        .sections()
        .iter()
        .filter(|(_, section)| section.status == SectionStatus::Complete)
        .count();
    let partial_sections = evidence
        .sections()
        .iter()
        .filter(|(_, section)| section.status == SectionStatus::Partial)
        .count();
    let failed_sections = evidence
        .sections()
        .iter()
        .filter(|(_, section)| section.status == SectionStatus::Failed)
        .count();

    Ok(CapturedDossier {
        schema: DOSSIER_SCHEMA,
        schema_version: DOSSIER_SCHEMA_VERSION,
        privacy_notice: "Contains process arguments, paths, users, host data, open resources, service configuration, executable hashes or signing data, and native log messages; use --redact and review before sharing.",
        tool: DossierTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64,
        platform: platform_name(),
        hostname: System::host_name().map(|hostname| sanitize_terminal_text(&hostname)),
        process_identity,
        process_identity_warning,
        target,
        collection: DossierCollection {
            parallel: true,
            duration_ms: elapsed_millis(started),
            process_sample_interval_ms: options.sample_ms,
            executable_hashing: options.hash,
            logs_requested: options.include_logs,
            logs_scope: options.logs_scope.label(),
            logs_priority: options.logs_priority.label(),
            logs_since_seconds: options.logs_since_seconds,
            logs_limit: options.logs_limit,
            requested_sections,
            complete_sections,
            partial_sections,
            failed_sections,
        },
        summary,
        signals,
        evidence,
    })
}

pub(crate) fn render_dossier_json(captured: &CapturedDossier) -> Result<String, String> {
    serde_json::to_string_pretty(captured).map_err(|error| error.to_string())
}

pub(crate) fn dossier_summary_line(captured: &CapturedDossier) -> String {
    format!(
        "status {}  signals {} (critical {}, warning {}, notice {})  evidence {}/{} complete",
        captured.summary.status,
        captured.signals.len(),
        captured.summary.critical_count,
        captured.summary.warning_count,
        captured.summary.notice_count,
        captured.collection.complete_sections,
        captured.collection.requested_sections,
    )
}

pub(crate) fn render_dossier_summary_table(captured: &CapturedDossier) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "PSMORE PROCESS DOSSIER");
    let _ = writeln!(
        output,
        "process {} [{}]  user {}  status {}  identity {}",
        captured.target.name,
        captured.target.pid,
        if captured.target.user.is_empty() {
            "unknown"
        } else {
            &captured.target.user
        },
        captured.target.status,
        captured.process_identity.label(),
    );
    let _ = writeln!(output, "path {}", captured.target.path);
    let _ = writeln!(output, "command {}", captured.target.command);
    let _ = writeln!(output, "{}", dossier_summary_line(captured));
    let _ = writeln!(
        output,
        "collection {}ms in parallel  partial {}  failed {}",
        captured.collection.duration_ms,
        captured.collection.partial_sections,
        captured.collection.failed_sections,
    );
    if let Some(warning) = captured.process_identity_warning.as_deref() {
        let _ = writeln!(output, "identity warning {warning}");
    }

    let _ = writeln!(output, "\nPRIORITIZED SIGNALS");
    if captured.signals.is_empty() {
        let _ = writeln!(output, "  [no actionable signals in collected evidence]");
    } else {
        for signal in &captured.signals {
            let _ = writeln!(
                output,
                "  {:<4} {:<31} {}",
                signal.severity.table_label(),
                signal.code,
                signal.summary,
            );
        }
    }

    let _ = writeln!(output, "\nEVIDENCE OVERVIEW");
    for (name, section) in captured.evidence.sections() {
        let _ = writeln!(
            output,
            "  {:<18} {:<8} {:>6}ms{}",
            name,
            section.status.label(),
            section.duration_ms,
            section
                .error
                .as_deref()
                .map(|error| format!("  {error}"))
                .unwrap_or_default(),
        );
    }
    output
}

pub(crate) fn render_dossier_table(captured: &CapturedDossier) -> String {
    let mut output = render_dossier_summary_table(captured);
    for (name, section) in captured.evidence.sections() {
        let _ = writeln!(output, "\n--- {} [{}] ---", name, section.status.label());
        if let Some(table) = section.table.as_deref() {
            output.push_str(table.trim_end());
            output.push('\n');
        } else if section.status == SectionStatus::Skipped {
            let _ = writeln!(output, "not requested");
        } else {
            let _ = writeln!(
                output,
                "{}",
                section.error.as_deref().unwrap_or("evidence unavailable")
            );
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn section(report: Value) -> EvidenceSection {
        EvidenceSection {
            status: SectionStatus::Complete,
            duration_ms: 7,
            error: None,
            report: Some(report),
            table: Some("details".into()),
        }
    }

    fn target() -> DossierTarget {
        DossierTarget {
            pid: 42,
            parent_pid: Some(1),
            name: "api".into(),
            user: "deploy".into(),
            status: "Run".into(),
            path: "/srv/api".into(),
            command: "/srv/api --serve".into(),
            start_time_unix_seconds: 1_234,
            runtime_seconds: 30,
        }
    }

    #[test]
    fn identity_mismatch_refuses_cross_process_evidence() {
        let mut evidence = section(json!({
            "process_identity": "verified",
            "process": { "pid": 42, "start_time_unix_seconds": 999 }
        }));
        validate_section_identity("inspection", &mut evidence, &target());
        assert_eq!(evidence.status, SectionStatus::Failed);
        assert!(evidence.report.is_none());
        assert!(
            evidence
                .error
                .unwrap()
                .contains("different process instances")
        );
    }

    #[test]
    fn prioritizes_runtime_service_image_and_log_findings() {
        let mut target = target();
        target.status = "Zombie".into();
        let evidence = DossierEvidence {
            inspection: section(json!({})),
            service_context: section(json!({
                "service": { "state": {
                    "active_state": "failed", "result": "failed", "restart_count": 8
                }}
            })),
            executable_image: section(json!({
                "comparison": { "attention_required": true, "status": "replaced_on_disk" },
                "signing": { "signed": true, "valid": false }
            })),
            native_logs: section(json!({
                "source": { "truncated": true },
                "entries": [{ "priority": "error" }]
            })),
        };
        let signals = collect_signals(&target, &evidence);
        assert_eq!(signals.first().unwrap().severity, SignalSeverity::Critical);
        assert_eq!(
            signals
                .iter()
                .filter(|item| item.severity == SignalSeverity::Critical)
                .count(),
            3
        );
        assert!(signals.iter().any(|item| item.code == "logs.errors"));
        assert!(signals.iter().any(|item| item.code == "service.restarts"));
    }

    #[test]
    fn derives_pressure_signals_only_from_bounded_evidence() {
        let inspection = section(json!({
            "process": { "cpu_percent": 92.5 },
            "resource_limits": [
                { "label": "OPEN FILES", "value": "soft 10 / hard 20 files" }
            ],
            "hot_threads": { "total_count": 500 },
            "sockets": [
                { "fd": "1" }, { "fd": "2" }, { "fd": "3" }
            ],
            "open_files": [
                { "fd": "4" }, { "fd": "5" }, { "fd": "6" },
                { "fd": "7" }, { "fd": "8" }, { "fd": "9" }
            ]
        }));
        let service = section(json!({
            "service": {
                "state": {},
                "resources": {
                    "tasks_current": 95,
                    "tasks_max": { "value": 100, "unlimited": false },
                    "memory_current_bytes": 950,
                    "memory_max_bytes": { "value": 1000, "unlimited": false }
                }
            }
        }));
        let evidence = DossierEvidence {
            inspection,
            service_context: service,
            executable_image: EvidenceSection::skipped(),
            native_logs: EvidenceSection::skipped(),
        };
        let signals = collect_signals(&target(), &evidence);
        for code in [
            "resource.cpu_hot_sample",
            "resource.thread_volume",
            "resource.fd_limit_pressure",
            "resource.task_limit_pressure",
            "resource.memory_limit_pressure",
        ] {
            assert!(
                signals.iter().any(|signal| signal.code == code),
                "missing {code}"
            );
        }
        assert_eq!(
            signals
                .iter()
                .find(|signal| signal.code == "resource.fd_limit_pressure")
                .unwrap()
                .severity,
            SignalSeverity::Warning
        );
        assert_eq!(
            signals
                .iter()
                .find(|signal| signal.code == "resource.memory_limit_pressure")
                .unwrap()
                .severity,
            SignalSeverity::Warning
        );
    }

    #[test]
    fn pressure_thresholds_ignore_normal_and_unlimited_resources() {
        let inspection = section(json!({
            "process": { "cpu_percent": 79.9 },
            "resource_limits": [
                { "label": "OPEN FILES", "value": "soft unlimited / hard unlimited files" }
            ],
            "hot_threads": { "total_count": 499 },
            "sockets": [],
            "open_files": []
        }));
        let service = section(json!({
            "service": {
                "state": {},
                "resources": {
                    "tasks_current": 74,
                    "tasks_max": { "value": 100, "unlimited": false },
                    "memory_current_bytes": 79,
                    "memory_max_bytes": { "value": 100, "unlimited": false }
                }
            }
        }));
        let evidence = DossierEvidence {
            inspection,
            service_context: service,
            executable_image: EvidenceSection::skipped(),
            native_logs: EvidenceSection::skipped(),
        };
        assert!(
            collect_signals(&target(), &evidence)
                .iter()
                .all(|signal| !signal.code.starts_with("resource."))
        );
        assert_eq!(parse_soft_limit("soft 1024 / hard 4096 files"), Some(1024));
        assert_eq!(
            parse_soft_limit("soft unlimited / hard unlimited files"),
            None
        );
    }

    #[test]
    fn json_and_table_expose_summary_and_raw_evidence() {
        let evidence = DossierEvidence {
            inspection: section(json!({"schema": "psmore.process-inspection"})),
            service_context: EvidenceSection::skipped(),
            executable_image: EvidenceSection::skipped(),
            native_logs: EvidenceSection::skipped(),
        };
        let captured = CapturedDossier {
            schema: DOSSIER_SCHEMA,
            schema_version: DOSSIER_SCHEMA_VERSION,
            privacy_notice: "private",
            tool: DossierTool {
                name: "psmore",
                version: "test",
            },
            generated_at_unix_ms: 1,
            platform: "test",
            hostname: Some("host".into()),
            process_identity: DossierIdentity::Verified,
            process_identity_warning: None,
            target: target(),
            collection: DossierCollection {
                parallel: true,
                duration_ms: 10,
                process_sample_interval_ms: 100,
                executable_hashing: false,
                logs_requested: false,
                logs_scope: "auto",
                logs_priority: "info",
                logs_since_seconds: 900,
                logs_limit: 100,
                requested_sections: 1,
                complete_sections: 1,
                partial_sections: 0,
                failed_sections: 0,
            },
            summary: DossierSummary {
                status: "ok",
                critical_count: 0,
                warning_count: 0,
                notice_count: 0,
            },
            signals: Vec::new(),
            evidence,
        };
        let json: Value = serde_json::from_str(&render_dossier_json(&captured).unwrap()).unwrap();
        assert_eq!(json["schema"], DOSSIER_SCHEMA);
        assert_eq!(json["target"]["pid"], 42);
        assert_eq!(
            json["evidence"]["inspection"]["report"]["schema"],
            "psmore.process-inspection"
        );
        assert!(json["evidence"]["inspection"].get("table").is_none());
        let table = render_dossier_table(&captured);
        assert!(table.contains("PSMORE PROCESS DOSSIER"));
        assert!(table.contains("PRIORITIZED SIGNALS"));
        assert!(table.contains("inspection"));
        let summary = render_dossier_summary_table(&captured);
        assert!(!summary.contains("--- inspection"));
    }
}
