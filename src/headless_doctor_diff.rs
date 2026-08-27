use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::{
    cli::{DiffFailOn, DiffPolicyStatus},
    model::sanitize_terminal_text,
};

pub(crate) const DOCTOR_SCHEMA: &str = "psmore.host-doctor";
const DOCTOR_SCHEMA_VERSION: u32 = 1;
const DOCTOR_DIFF_SCHEMA: &str = "psmore.host-doctor-diff";
const DOCTOR_DIFF_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct StoredQuery {
    input: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredSeverity {
    Warning,
    Critical,
}

impl StoredSeverity {
    fn table_label(self) -> &'static str {
        match self {
            Self::Warning => "WARN",
            Self::Critical => "CRIT",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredFinding {
    code: String,
    severity: StoredSeverity,
    title: String,
    summary: String,
    next_command: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct StoredLoadAverage {
    normalized_fifteen_per_logical_cpu: f64,
}

#[derive(Clone, Debug, Deserialize)]
struct StoredHost {
    effective_memory_total_bytes: u64,
    effective_memory_available_bytes: u64,
    effective_memory_available_percent: Option<f64>,
    memory_available_source: String,
    cgroup_memory_limit_applied: bool,
    swap_total_bytes: u64,
    swap_used_bytes: u64,
    swap_used_percent: Option<f64>,
    logical_cpu_count: usize,
    load_average: StoredLoadAverage,
    uptime_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct StoredDeepListeners {
    exposed_bind_count: usize,
    unresolved_socket_count: usize,
    collection_complete: bool,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct StoredDeepFd {
    matched_process_count: usize,
    inspected_process_count: usize,
    limit_coverage_count: usize,
    collection_complete: bool,
    selection_complete: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct StoredDeepDeleted {
    unique_file_count: usize,
    process_count: usize,
    estimated_reclaimable_bytes: u64,
    warning: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct StoredPressure {
    some_avg10_percent: f64,
    full_avg10_percent: f64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct StoredDeepOom {
    supported: bool,
    available_memory_percent: Option<f64>,
    oom_kill_count_since_boot: Option<u64>,
    pressure: Option<StoredPressure>,
    matched_candidate_count: usize,
    score_inspected_process_count: usize,
    score_selection_complete: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
struct StoredDeep {
    exposed_listeners: StoredDeepListeners,
    file_descriptors: StoredDeepFd,
    deleted_open_files: StoredDeepDeleted,
    linux_oom: StoredDeepOom,
}

#[derive(Clone, Debug, Deserialize)]
struct StoredDoctor {
    schema: String,
    schema_version: u32,
    generated_at_unix_ms: u64,
    platform: String,
    hostname: Option<String>,
    sample_interval_ms: u64,
    status: String,
    query: Option<StoredQuery>,
    system_process_count: usize,
    scoped_process_count: usize,
    finding_count: usize,
    critical_finding_count: usize,
    warning_finding_count: usize,
    host: StoredHost,
    findings: Vec<StoredFinding>,
    deep: Option<StoredDeep>,
}

#[derive(Clone, Debug, Serialize)]
struct DoctorSource {
    generated_at_unix_ms: u64,
    sample_interval_ms: u64,
    status: String,
    system_process_count: usize,
    scoped_process_count: usize,
    finding_count: usize,
    critical_finding_count: usize,
    warning_finding_count: usize,
}

impl From<&StoredDoctor> for DoctorSource {
    fn from(report: &StoredDoctor) -> Self {
        Self {
            generated_at_unix_ms: report.generated_at_unix_ms,
            sample_interval_ms: report.sample_interval_ms,
            status: report.status.clone(),
            system_process_count: report.system_process_count,
            scoped_process_count: report.scoped_process_count,
            finding_count: report.finding_count,
            critical_finding_count: report.critical_finding_count,
            warning_finding_count: report.warning_finding_count,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct DoctorScope {
    query: Option<String>,
    deep_checks: bool,
    interpretation: &'static str,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct CountChange {
    before: usize,
    after: usize,
    delta: i64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct U64Change {
    before: u64,
    after: u64,
    delta: i64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct FloatChange {
    before: f64,
    after: f64,
    delta: f64,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct OptionalFloatChange {
    before: Option<f64>,
    after: Option<f64>,
    delta: Option<f64>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct OptionalCountChange {
    before: Option<u64>,
    after: Option<u64>,
    delta: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
struct HostChange {
    effective_memory_total_bytes: U64Change,
    effective_memory_available_bytes: U64Change,
    effective_memory_available_percent: OptionalFloatChange,
    memory_available_source_before: String,
    memory_available_source_after: String,
    cgroup_memory_limit_applied: CoverageChange,
    swap_total_bytes: U64Change,
    swap_used_bytes: U64Change,
    swap_used_percent: OptionalFloatChange,
    normalized_fifteen_per_logical_cpu: FloatChange,
    logical_cpu_count: CountChange,
    uptime_seconds: U64Change,
    reboot_detected: bool,
    system_process_count: CountChange,
    scoped_process_count: CountChange,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct CoverageChange {
    before: bool,
    after: bool,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct DoctorDeepChange {
    exposed_bind_count: CountChange,
    unresolved_socket_count: CountChange,
    listener_collection_complete: CoverageChange,
    fd_pressure_process_count: CountChange,
    fd_inspected_process_count: CountChange,
    fd_limit_coverage_count: CountChange,
    fd_collection_complete: CoverageChange,
    fd_selection_complete: CoverageChange,
    deleted_unique_file_count: CountChange,
    deleted_process_count: CountChange,
    deleted_estimated_reclaimable_bytes: U64Change,
    deleted_collection_complete: CoverageChange,
    linux_oom_supported: CoverageChange,
    linux_available_memory_percent: OptionalFloatChange,
    linux_oom_kill_count_since_boot: OptionalCountChange,
    linux_psi_some_avg10_percent: OptionalFloatChange,
    linux_psi_full_avg10_percent: OptionalFloatChange,
    linux_oom_candidate_count: CountChange,
    linux_oom_score_inspected_process_count: CountChange,
    linux_oom_score_selection_complete: Option<CoverageChange>,
}

#[derive(Clone, Debug, Serialize)]
struct FindingTransition {
    code: String,
    title: String,
    before_severity: StoredSeverity,
    after_severity: StoredSeverity,
    before_summary: String,
    after_summary: String,
    next_command: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct DoctorDiffSummary {
    new_findings: usize,
    resolved_findings: usize,
    no_longer_observed_findings: usize,
    persistent_findings: usize,
    severity_changes: usize,
    severity_escalations: usize,
    severity_improvements: usize,
    regression_count: usize,
    finding_count_delta: i64,
    critical_finding_count_delta: i64,
    warning_finding_count_delta: i64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DoctorComparison {
    platform: String,
    hostname: String,
    elapsed_ms: u64,
    before: DoctorSource,
    after: DoctorSource,
    scope: DoctorScope,
    summary: DoctorDiffSummary,
    host: HostChange,
    new_findings: Vec<StoredFinding>,
    resolved_findings: Vec<StoredFinding>,
    no_longer_observed_findings: Vec<StoredFinding>,
    persistent_findings: Vec<FindingTransition>,
    severity_changes: Vec<FindingTransition>,
    deep: Option<DoctorDeepChange>,
}

impl DoctorComparison {
    pub(crate) fn regression_detected(&self) -> bool {
        self.summary.regression_count > 0
    }

    pub(crate) fn regression_count(&self) -> usize {
        self.summary.regression_count
    }

    pub(crate) fn summary_line(&self) -> String {
        format!(
            "regressions {} (new {}, escalated {}), resolved {}, no-longer-observed {}",
            self.summary.regression_count,
            self.summary.new_findings,
            self.summary.severity_escalations,
            self.summary.resolved_findings,
            self.summary.no_longer_observed_findings,
        )
    }
}

fn signed_delta(after: u64, before: u64) -> i64 {
    i128::from(after)
        .saturating_sub(i128::from(before))
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn count_delta(after: usize, before: usize) -> i64 {
    let after = i128::try_from(after).unwrap_or(i128::MAX);
    let before = i128::try_from(before).unwrap_or(i128::MAX);
    after
        .saturating_sub(before)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn count_change(before: usize, after: usize) -> CountChange {
    CountChange {
        before,
        after,
        delta: count_delta(after, before),
    }
}

fn u64_change(before: u64, after: u64) -> U64Change {
    U64Change {
        before,
        after,
        delta: signed_delta(after, before),
    }
}

fn float_change(before: f64, after: f64) -> FloatChange {
    FloatChange {
        before,
        after,
        delta: after - before,
    }
}

fn optional_float_change(before: Option<f64>, after: Option<f64>) -> OptionalFloatChange {
    OptionalFloatChange {
        before,
        after,
        delta: before.zip(after).map(|(before, after)| after - before),
    }
}

fn optional_count_change(before: Option<u64>, after: Option<u64>) -> OptionalCountChange {
    OptionalCountChange {
        before,
        after,
        delta: before
            .zip(after)
            .map(|(before, after)| signed_delta(after, before)),
    }
}

fn parse_doctor(contents: &str, label: &str) -> Result<StoredDoctor, String> {
    let report: StoredDoctor = serde_json::from_str(contents)
        .map_err(|error| format!("cannot parse {label} doctor report: {error}"))?;
    validate_doctor(&report, label)?;
    Ok(report)
}

fn valid_percent(value: Option<f64>) -> bool {
    value.is_none_or(|value| value.is_finite() && (0.0..=100.0).contains(&value))
}

fn validate_doctor(report: &StoredDoctor, label: &str) -> Result<(), String> {
    if report.schema != DOCTOR_SCHEMA {
        return Err(format!(
            "{label} uses unsupported schema {}; expected {DOCTOR_SCHEMA}",
            report.schema
        ));
    }
    if report.schema_version != DOCTOR_SCHEMA_VERSION {
        return Err(format!(
            "{label} uses unsupported doctor schema version {}; expected {DOCTOR_SCHEMA_VERSION}",
            report.schema_version
        ));
    }
    if report.hostname.as_deref().unwrap_or("").is_empty() {
        return Err(format!("{label} doctor report has no hostname"));
    }
    if report.scoped_process_count > report.system_process_count {
        return Err(format!(
            "{label} scoped_process_count is larger than system_process_count"
        ));
    }
    if report.finding_count != report.findings.len() {
        return Err(format!(
            "{label} finding_count is {}, but it contains {} findings",
            report.finding_count,
            report.findings.len()
        ));
    }
    let actual_critical = report
        .findings
        .iter()
        .filter(|finding| finding.severity == StoredSeverity::Critical)
        .count();
    let actual_warning = report.findings.len().saturating_sub(actual_critical);
    if report.critical_finding_count != actual_critical
        || report.warning_finding_count != actual_warning
    {
        return Err(format!(
            "{label} finding severity counts do not match its findings"
        ));
    }
    let expected_status = if actual_critical > 0 {
        "critical_signals"
    } else if actual_warning > 0 {
        "warning_signals"
    } else {
        "no_configured_signals"
    };
    if report.status != expected_status {
        return Err(format!(
            "{label} status is {}, but its findings require {expected_status}",
            report.status
        ));
    }
    let mut codes = std::collections::HashSet::with_capacity(report.findings.len());
    for finding in &report.findings {
        if finding.code.trim().is_empty() {
            return Err(format!("{label} contains an empty finding code"));
        }
        if !codes.insert(&finding.code) {
            return Err(format!(
                "{label} contains duplicate finding code {}",
                finding.code
            ));
        }
    }
    let host = &report.host;
    if host.memory_available_source.trim().is_empty() {
        return Err(format!("{label} contains an empty memory evidence source"));
    }
    if host.effective_memory_available_bytes > host.effective_memory_total_bytes {
        return Err(format!(
            "{label} effective available memory is larger than its total"
        ));
    }
    if host.swap_used_bytes > host.swap_total_bytes {
        return Err(format!("{label} used swap is larger than total swap"));
    }
    if host.logical_cpu_count == 0 {
        return Err(format!("{label} logical CPU count is zero"));
    }
    if !valid_percent(host.effective_memory_available_percent)
        || !valid_percent(host.swap_used_percent)
        || !host
            .load_average
            .normalized_fifteen_per_logical_cpu
            .is_finite()
        || host.load_average.normalized_fifteen_per_logical_cpu < 0.0
    {
        return Err(format!("{label} contains an invalid host metric"));
    }
    if let Some(deep) = report.deep.as_ref() {
        let oom = deep.linux_oom;
        if deep.file_descriptors.matched_process_count
            > deep.file_descriptors.inspected_process_count
            || deep.file_descriptors.limit_coverage_count
                > deep.file_descriptors.inspected_process_count
        {
            return Err(format!("{label} contains inconsistent FD deep counts"));
        }
        if oom.matched_candidate_count > oom.score_inspected_process_count {
            return Err(format!("{label} contains inconsistent OOM deep counts"));
        }
        if !valid_percent(oom.available_memory_percent)
            || oom.pressure.is_some_and(|pressure| {
                !valid_percent(Some(pressure.some_avg10_percent))
                    || !valid_percent(Some(pressure.full_avg10_percent))
            })
        {
            return Err(format!("{label} contains an invalid deep metric"));
        }
    }
    Ok(())
}

fn host_change(before: &StoredDoctor, after: &StoredDoctor) -> HostChange {
    let before_host = &before.host;
    let after_host = &after.host;
    HostChange {
        effective_memory_total_bytes: u64_change(
            before_host.effective_memory_total_bytes,
            after_host.effective_memory_total_bytes,
        ),
        effective_memory_available_bytes: u64_change(
            before_host.effective_memory_available_bytes,
            after_host.effective_memory_available_bytes,
        ),
        effective_memory_available_percent: optional_float_change(
            before_host.effective_memory_available_percent,
            after_host.effective_memory_available_percent,
        ),
        memory_available_source_before: before_host.memory_available_source.clone(),
        memory_available_source_after: after_host.memory_available_source.clone(),
        cgroup_memory_limit_applied: CoverageChange {
            before: before_host.cgroup_memory_limit_applied,
            after: after_host.cgroup_memory_limit_applied,
        },
        swap_total_bytes: u64_change(before_host.swap_total_bytes, after_host.swap_total_bytes),
        swap_used_bytes: u64_change(before_host.swap_used_bytes, after_host.swap_used_bytes),
        swap_used_percent: optional_float_change(
            before_host.swap_used_percent,
            after_host.swap_used_percent,
        ),
        normalized_fifteen_per_logical_cpu: float_change(
            before_host.load_average.normalized_fifteen_per_logical_cpu,
            after_host.load_average.normalized_fifteen_per_logical_cpu,
        ),
        logical_cpu_count: count_change(
            before_host.logical_cpu_count,
            after_host.logical_cpu_count,
        ),
        uptime_seconds: u64_change(before_host.uptime_seconds, after_host.uptime_seconds),
        reboot_detected: after_host.uptime_seconds < before_host.uptime_seconds,
        system_process_count: count_change(before.system_process_count, after.system_process_count),
        scoped_process_count: count_change(before.scoped_process_count, after.scoped_process_count),
    }
}

fn optional_coverage_change(before: Option<bool>, after: Option<bool>) -> Option<CoverageChange> {
    before
        .zip(after)
        .map(|(before, after)| CoverageChange { before, after })
}

fn deep_change(before: &StoredDeep, after: &StoredDeep, reboot_detected: bool) -> DoctorDeepChange {
    DoctorDeepChange {
        exposed_bind_count: count_change(
            before.exposed_listeners.exposed_bind_count,
            after.exposed_listeners.exposed_bind_count,
        ),
        unresolved_socket_count: count_change(
            before.exposed_listeners.unresolved_socket_count,
            after.exposed_listeners.unresolved_socket_count,
        ),
        listener_collection_complete: CoverageChange {
            before: before.exposed_listeners.collection_complete,
            after: after.exposed_listeners.collection_complete,
        },
        fd_pressure_process_count: count_change(
            before.file_descriptors.matched_process_count,
            after.file_descriptors.matched_process_count,
        ),
        fd_inspected_process_count: count_change(
            before.file_descriptors.inspected_process_count,
            after.file_descriptors.inspected_process_count,
        ),
        fd_limit_coverage_count: count_change(
            before.file_descriptors.limit_coverage_count,
            after.file_descriptors.limit_coverage_count,
        ),
        fd_collection_complete: CoverageChange {
            before: before.file_descriptors.collection_complete,
            after: after.file_descriptors.collection_complete,
        },
        fd_selection_complete: CoverageChange {
            before: before.file_descriptors.selection_complete,
            after: after.file_descriptors.selection_complete,
        },
        deleted_unique_file_count: count_change(
            before.deleted_open_files.unique_file_count,
            after.deleted_open_files.unique_file_count,
        ),
        deleted_process_count: count_change(
            before.deleted_open_files.process_count,
            after.deleted_open_files.process_count,
        ),
        deleted_estimated_reclaimable_bytes: u64_change(
            before.deleted_open_files.estimated_reclaimable_bytes,
            after.deleted_open_files.estimated_reclaimable_bytes,
        ),
        deleted_collection_complete: CoverageChange {
            before: before.deleted_open_files.warning.is_none(),
            after: after.deleted_open_files.warning.is_none(),
        },
        linux_oom_supported: CoverageChange {
            before: before.linux_oom.supported,
            after: after.linux_oom.supported,
        },
        linux_available_memory_percent: optional_float_change(
            before.linux_oom.available_memory_percent,
            after.linux_oom.available_memory_percent,
        ),
        linux_oom_kill_count_since_boot: if reboot_detected {
            OptionalCountChange {
                before: before.linux_oom.oom_kill_count_since_boot,
                after: after.linux_oom.oom_kill_count_since_boot,
                delta: None,
            }
        } else {
            optional_count_change(
                before.linux_oom.oom_kill_count_since_boot,
                after.linux_oom.oom_kill_count_since_boot,
            )
        },
        linux_psi_some_avg10_percent: optional_float_change(
            before
                .linux_oom
                .pressure
                .map(|pressure| pressure.some_avg10_percent),
            after
                .linux_oom
                .pressure
                .map(|pressure| pressure.some_avg10_percent),
        ),
        linux_psi_full_avg10_percent: optional_float_change(
            before
                .linux_oom
                .pressure
                .map(|pressure| pressure.full_avg10_percent),
            after
                .linux_oom
                .pressure
                .map(|pressure| pressure.full_avg10_percent),
        ),
        linux_oom_candidate_count: count_change(
            before.linux_oom.matched_candidate_count,
            after.linux_oom.matched_candidate_count,
        ),
        linux_oom_score_inspected_process_count: count_change(
            before.linux_oom.score_inspected_process_count,
            after.linux_oom.score_inspected_process_count,
        ),
        linux_oom_score_selection_complete: optional_coverage_change(
            before.linux_oom.score_selection_complete,
            after.linux_oom.score_selection_complete,
        ),
    }
}

fn resolution_is_confirmed(code: &str, after: &StoredDoctor) -> bool {
    match code {
        "file_descriptor_pressure" => after.deep.as_ref().is_some_and(|deep| {
            deep.file_descriptors.collection_complete && deep.file_descriptors.selection_complete
        }),
        "deleted_open_files" => after
            .deep
            .as_ref()
            .is_some_and(|deep| deep.deleted_open_files.warning.is_none()),
        "linux_memory_psi" => after
            .deep
            .as_ref()
            .is_some_and(|deep| deep.linux_oom.supported && deep.linux_oom.pressure.is_some()),
        _ => true,
    }
}

fn compare_doctors(before: StoredDoctor, after: StoredDoctor) -> Result<DoctorComparison, String> {
    if before.platform != after.platform {
        return Err(format!(
            "platform mismatch: before is {}, after is {}",
            before.platform, after.platform
        ));
    }
    if before.hostname != after.hostname {
        return Err(format!(
            "hostname mismatch: before is {:?}, after is {:?}",
            before.hostname, after.hostname
        ));
    }
    if before.query != after.query {
        return Err("query mismatch: doctor reports must use the exact same process scope".into());
    }
    if before.deep.is_some() != after.deep.is_some() {
        return Err(
            "deep-check mismatch: both doctor reports must use --deep or neither may use it".into(),
        );
    }
    if after.generated_at_unix_ms < before.generated_at_unix_ms {
        return Err("doctor report order is reversed: AFTER is older than BEFORE".into());
    }

    let before_findings: std::collections::BTreeMap<&str, &StoredFinding> = before
        .findings
        .iter()
        .map(|finding| (finding.code.as_str(), finding))
        .collect();
    let after_findings: std::collections::BTreeMap<&str, &StoredFinding> = after
        .findings
        .iter()
        .map(|finding| (finding.code.as_str(), finding))
        .collect();
    let mut new_findings = Vec::new();
    let mut resolved_findings = Vec::new();
    let mut no_longer_observed_findings = Vec::new();
    let mut persistent_findings = Vec::new();
    let mut severity_changes = Vec::new();
    let mut severity_escalations = 0;
    let mut severity_improvements = 0;
    for (code, finding) in &after_findings {
        match before_findings.get(code) {
            None => new_findings.push((*finding).clone()),
            Some(before_finding) => {
                let transition = FindingTransition {
                    code: (*code).to_string(),
                    title: finding.title.clone(),
                    before_severity: before_finding.severity,
                    after_severity: finding.severity,
                    before_summary: before_finding.summary.clone(),
                    after_summary: finding.summary.clone(),
                    next_command: finding.next_command.clone(),
                };
                if transition.before_severity != transition.after_severity {
                    if transition.after_severity > transition.before_severity {
                        severity_escalations += 1;
                    } else {
                        severity_improvements += 1;
                    }
                    severity_changes.push(transition.clone());
                }
                persistent_findings.push(transition);
            }
        }
    }
    for (code, finding) in &before_findings {
        if !after_findings.contains_key(code) {
            if resolution_is_confirmed(code, &after) {
                resolved_findings.push((*finding).clone());
            } else {
                no_longer_observed_findings.push((*finding).clone());
            }
        }
    }

    let summary = DoctorDiffSummary {
        new_findings: new_findings.len(),
        resolved_findings: resolved_findings.len(),
        no_longer_observed_findings: no_longer_observed_findings.len(),
        persistent_findings: persistent_findings.len(),
        severity_changes: severity_changes.len(),
        severity_escalations,
        severity_improvements,
        regression_count: new_findings.len().saturating_add(severity_escalations),
        finding_count_delta: count_delta(after.finding_count, before.finding_count),
        critical_finding_count_delta: count_delta(
            after.critical_finding_count,
            before.critical_finding_count,
        ),
        warning_finding_count_delta: count_delta(
            after.warning_finding_count,
            before.warning_finding_count,
        ),
    };
    let host = host_change(&before, &after);
    let deep = before
        .deep
        .as_ref()
        .zip(after.deep.as_ref())
        .map(|(before, after)| deep_change(before, after, host.reboot_detected));
    Ok(DoctorComparison {
        platform: before.platform.clone(),
        hostname: before.hostname.clone().unwrap_or_default(),
        elapsed_ms: after
            .generated_at_unix_ms
            .saturating_sub(before.generated_at_unix_ms),
        before: DoctorSource::from(&before),
        after: DoctorSource::from(&after),
        scope: DoctorScope {
            query: before.query.as_ref().map(|query| query.input.clone()),
            deep_checks: before.deep.is_some(),
            interpretation: "changes are sampled evidence, not confirmed root causes",
        },
        summary,
        host,
        new_findings,
        resolved_findings,
        no_longer_observed_findings,
        persistent_findings,
        severity_changes,
        deep,
    })
}

pub(crate) fn compare_doctor_contents(
    before_contents: &str,
    after_contents: &str,
) -> Result<DoctorComparison, String> {
    compare_doctors(
        parse_doctor(before_contents, "BEFORE")?,
        parse_doctor(after_contents, "AFTER")?,
    )
}

#[derive(Serialize)]
struct JsonDoctorDiff<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    policy: JsonPolicy,
    comparison: &'a DoctorComparison,
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
    rule: &'static str,
}

pub(crate) fn render_doctor_diff_json(
    comparison: &DoctorComparison,
    fail_on: DiffFailOn,
    policy_status: Option<DiffPolicyStatus>,
) -> Result<String, String> {
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    serde_json::to_string_pretty(&JsonDoctorDiff {
        schema: DOCTOR_DIFF_SCHEMA,
        schema_version: DOCTOR_DIFF_SCHEMA_VERSION,
        privacy_notice: "May contain host names, process names, finding summaries, and diagnostic metadata from both doctor reports; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms,
        policy: JsonPolicy {
            fail_on: fail_on.label(),
            passed: policy_status.map(DiffPolicyStatus::passed),
            status: policy_status.map(DiffPolicyStatus::label),
            rule: "regression means any newly observed finding or severity escalation",
        },
        comparison,
    })
    .map_err(|error| error.to_string())
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

fn signed_bytes(value: i64) -> String {
    let sign = match value.cmp(&0) {
        std::cmp::Ordering::Greater => "+",
        std::cmp::Ordering::Less => "-",
        std::cmp::Ordering::Equal => "",
    };
    format!("{sign}{}", human_bytes(value.unsigned_abs()))
}

fn optional_percent(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1}%"))
        .unwrap_or_else(|| "-".to_string())
}

fn optional_delta(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:+.1}pp"))
        .unwrap_or_else(|| "-".to_string())
}

fn append_findings(output: &mut String, title: &str, marker: &str, findings: &[StoredFinding]) {
    if findings.is_empty() {
        return;
    }
    output.push_str(&format!("\n{title} ({})\n", findings.len()));
    for finding in findings {
        output.push_str(&format!(
            "{marker} {:<4} {:<28} {}\n    {}\n    next: {}\n",
            finding.severity.table_label(),
            sanitize_terminal_text(&finding.code),
            sanitize_terminal_text(&finding.title),
            sanitize_terminal_text(&finding.summary),
            sanitize_terminal_text(&finding.next_command),
        ));
    }
}

fn coverage_label(change: CoverageChange) -> &'static str {
    if change.before && change.after {
        "complete"
    } else {
        "partial evidence"
    }
}

pub(crate) fn render_doctor_diff_table(
    comparison: &DoctorComparison,
    fail_on: DiffFailOn,
    policy_status: Option<DiffPolicyStatus>,
) -> String {
    let mut output = String::new();
    output.push_str("PSMORE DOCTOR DIFF\n");
    output.push_str(&format!(
        "host {}  platform {}  window {:.3}s  deep {}\n",
        sanitize_terminal_text(&comparison.hostname),
        sanitize_terminal_text(&comparison.platform),
        comparison.elapsed_ms as f64 / 1000.0,
        if comparison.scope.deep_checks {
            "yes"
        } else {
            "no"
        },
    ));
    if let Some(query) = &comparison.scope.query {
        output.push_str(&format!(
            "process scope {}  (host checks remain global)\n",
            sanitize_terminal_text(query)
        ));
    } else {
        output.push_str("process scope all visible processes\n");
    }
    if let Some(policy_status) = policy_status {
        output.push_str(&format!(
            "policy {}  fail-on {}  (newly observed finding or severity escalation)\n",
            policy_status.label().to_ascii_uppercase(),
            fail_on.label(),
        ));
    }
    output.push_str(&format!(
        "status {} -> {}  findings {} -> {} ({:+}); newly observed {}  resolved {}  no longer observed {}  persistent {}\n",
        sanitize_terminal_text(&comparison.before.status),
        sanitize_terminal_text(&comparison.after.status),
        comparison.before.finding_count,
        comparison.after.finding_count,
        comparison.summary.finding_count_delta,
        comparison.summary.new_findings,
        comparison.summary.resolved_findings,
        comparison.summary.no_longer_observed_findings,
        comparison.summary.persistent_findings,
    ));
    output.push_str(&format!(
        "regressions {} (newly observed {} + escalated {}); severity improved {}\n",
        comparison.summary.regression_count,
        comparison.summary.new_findings,
        comparison.summary.severity_escalations,
        comparison.summary.severity_improvements,
    ));

    output.push_str("\nHOST CHANGE\n");
    output.push_str(&format!(
        "memory evidence {} -> {}; cgroup limit {} -> {}; effective total {} -> {} ({})\n",
        sanitize_terminal_text(&comparison.host.memory_available_source_before),
        sanitize_terminal_text(&comparison.host.memory_available_source_after),
        comparison.host.cgroup_memory_limit_applied.before,
        comparison.host.cgroup_memory_limit_applied.after,
        human_bytes(comparison.host.effective_memory_total_bytes.before),
        human_bytes(comparison.host.effective_memory_total_bytes.after),
        signed_bytes(comparison.host.effective_memory_total_bytes.delta),
    ));
    output.push_str(&format!(
        "effective memory available {} ({}) -> {} ({})  bytes {}  percent {}\n",
        human_bytes(comparison.host.effective_memory_available_bytes.before),
        optional_percent(comparison.host.effective_memory_available_percent.before),
        human_bytes(comparison.host.effective_memory_available_bytes.after),
        optional_percent(comparison.host.effective_memory_available_percent.after),
        signed_bytes(comparison.host.effective_memory_available_bytes.delta),
        optional_delta(comparison.host.effective_memory_available_percent.delta),
    ));
    output.push_str(&format!(
        "swap used {} ({}) -> {} ({})  bytes {}  percent {}\n",
        human_bytes(comparison.host.swap_used_bytes.before),
        optional_percent(comparison.host.swap_used_percent.before),
        human_bytes(comparison.host.swap_used_bytes.after),
        optional_percent(comparison.host.swap_used_percent.after),
        signed_bytes(comparison.host.swap_used_bytes.delta),
        optional_delta(comparison.host.swap_used_percent.delta),
    ));
    output.push_str(&format!(
        "normalized load15 {:.3} -> {:.3} ({:+.3}); processes {} -> {} ({:+})\n",
        comparison.host.normalized_fifteen_per_logical_cpu.before,
        comparison.host.normalized_fifteen_per_logical_cpu.after,
        comparison.host.normalized_fifteen_per_logical_cpu.delta,
        comparison.host.system_process_count.before,
        comparison.host.system_process_count.after,
        comparison.host.system_process_count.delta,
    ));
    output.push_str(&format!(
        "uptime {}s -> {}s ({:+}s)  reboot detected {}\n",
        comparison.host.uptime_seconds.before,
        comparison.host.uptime_seconds.after,
        comparison.host.uptime_seconds.delta,
        comparison.host.reboot_detected,
    ));

    append_findings(
        &mut output,
        "NEWLY OBSERVED FINDINGS",
        "+",
        &comparison.new_findings,
    );
    append_findings(
        &mut output,
        "RESOLVED FINDINGS",
        "-",
        &comparison.resolved_findings,
    );
    append_findings(
        &mut output,
        "NO LONGER OBSERVED (PARTIAL EVIDENCE; RESOLUTION UNCONFIRMED)",
        "?",
        &comparison.no_longer_observed_findings,
    );
    if !comparison.severity_changes.is_empty() {
        output.push_str(&format!(
            "\nSEVERITY CHANGES ({})\n",
            comparison.severity_changes.len()
        ));
        for finding in &comparison.severity_changes {
            output.push_str(&format!(
                "! {}  {} -> {}  {}\n    before: {}\n    after:  {}\n",
                sanitize_terminal_text(&finding.code),
                finding.before_severity.table_label(),
                finding.after_severity.table_label(),
                sanitize_terminal_text(&finding.title),
                sanitize_terminal_text(&finding.before_summary),
                sanitize_terminal_text(&finding.after_summary),
            ));
        }
    }

    if let Some(deep) = comparison.deep {
        output.push_str("\nDEEP EVIDENCE CHANGE\n");
        output.push_str(&format!(
            "exposed binds {} -> {} ({:+}); unresolved {} -> {} ({:+})  {}\n",
            deep.exposed_bind_count.before,
            deep.exposed_bind_count.after,
            deep.exposed_bind_count.delta,
            deep.unresolved_socket_count.before,
            deep.unresolved_socket_count.after,
            deep.unresolved_socket_count.delta,
            coverage_label(deep.listener_collection_complete),
        ));
        output.push_str(&format!(
            "FD pressure processes {} -> {} ({:+}); inspected {} -> {} ({:+})  collection {}, selection {}\n",
            deep.fd_pressure_process_count.before,
            deep.fd_pressure_process_count.after,
            deep.fd_pressure_process_count.delta,
            deep.fd_inspected_process_count.before,
            deep.fd_inspected_process_count.after,
            deep.fd_inspected_process_count.delta,
            coverage_label(deep.fd_collection_complete),
            coverage_label(deep.fd_selection_complete),
        ));
        output.push_str(&format!(
            "deleted-open files {} -> {} ({:+}); reclaim {} -> {} ({})  {}\n",
            deep.deleted_unique_file_count.before,
            deep.deleted_unique_file_count.after,
            deep.deleted_unique_file_count.delta,
            human_bytes(deep.deleted_estimated_reclaimable_bytes.before),
            human_bytes(deep.deleted_estimated_reclaimable_bytes.after),
            signed_bytes(deep.deleted_estimated_reclaimable_bytes.delta),
            coverage_label(deep.deleted_collection_complete),
        ));
        if deep.linux_oom_supported.before && deep.linux_oom_supported.after {
            output.push_str(&format!(
                "Linux OOM candidates {} -> {} ({:+}); oom_kill since boot {} -> {} ({})\n",
                deep.linux_oom_candidate_count.before,
                deep.linux_oom_candidate_count.after,
                deep.linux_oom_candidate_count.delta,
                deep.linux_oom_kill_count_since_boot
                    .before
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                deep.linux_oom_kill_count_since_boot
                    .after
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                deep.linux_oom_kill_count_since_boot.delta.map_or_else(
                    || {
                        if comparison.host.reboot_detected {
                            "not comparable after reboot".to_string()
                        } else {
                            "-".to_string()
                        }
                    },
                    |value| format!("{value:+}"),
                ),
            ));
            output.push_str(&format!(
                "Linux PSI avg10 some {} -> {} ({})  full {} -> {} ({})\n",
                optional_percent(deep.linux_psi_some_avg10_percent.before),
                optional_percent(deep.linux_psi_some_avg10_percent.after),
                optional_delta(deep.linux_psi_some_avg10_percent.delta),
                optional_percent(deep.linux_psi_full_avg10_percent.before),
                optional_percent(deep.linux_psi_full_avg10_percent.after),
                optional_delta(deep.linux_psi_full_avg10_percent.delta),
            ));
        } else {
            output.push_str("Linux OOM/PSI unsupported in one or both reports\n");
        }
    }
    output.push_str("\nInterpretation: changes are sampled evidence, not confirmed root causes.\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn report(timestamp: u64, findings: Vec<Value>, deep: bool) -> String {
        let critical = findings
            .iter()
            .filter(|finding| finding["severity"] == "critical")
            .count();
        let warning = findings.len() - critical;
        serde_json::to_string(&json!({
            "schema": DOCTOR_SCHEMA,
            "schema_version": DOCTOR_SCHEMA_VERSION,
            "generated_at_unix_ms": timestamp,
            "platform": "Linux",
            "hostname": "host-a",
            "sample_interval_ms": 500,
            "status": if critical > 0 { "critical_signals" } else if warning > 0 { "warning_signals" } else { "no_configured_signals" },
            "query": null,
            "system_process_count": 20,
            "scoped_process_count": 20,
            "finding_count": findings.len(),
            "critical_finding_count": critical,
            "warning_finding_count": warning,
            "host": {
                "effective_memory_total_bytes": 1_000,
                "effective_memory_available_bytes": if timestamp == 1_000 { 700 } else { 400 },
                "effective_memory_available_percent": if timestamp == 1_000 { 70.0 } else { 40.0 },
                "memory_available_source": "linux_meminfo",
                "cgroup_memory_limit_applied": false,
                "swap_total_bytes": 100,
                "swap_used_bytes": if timestamp == 1_000 { 10 } else { 30 },
                "swap_used_percent": if timestamp == 1_000 { 10.0 } else { 30.0 },
                "logical_cpu_count": 4,
                "load_average": { "normalized_fifteen_per_logical_cpu": if timestamp == 1_000 { 0.2 } else { 0.8 } },
                "uptime_seconds": timestamp / 10
            },
            "findings": findings,
            "deep": deep.then(|| json!({
                "exposed_listeners": { "exposed_bind_count": 1, "unresolved_socket_count": 0, "collection_complete": true },
                "file_descriptors": { "matched_process_count": 0, "inspected_process_count": 20, "limit_coverage_count": 20, "collection_complete": true, "selection_complete": true },
                "deleted_open_files": { "unique_file_count": 0, "process_count": 0, "estimated_reclaimable_bytes": 0 },
                "linux_oom": { "supported": true, "available_memory_percent": 40.0, "oom_kill_count_since_boot": 0, "pressure": { "some_avg10_percent": 0.1, "full_avg10_percent": 0.0 }, "matched_candidate_count": 0, "score_inspected_process_count": 20, "score_selection_complete": true }
            }))
        }))
        .unwrap()
    }

    fn finding(code: &str, severity: &str, summary: &str) -> Value {
        json!({
            "code": code,
            "severity": severity,
            "title": format!("{code} title"),
            "summary": summary,
            "next_command": format!("psmore inspect {code}")
        })
    }

    #[test]
    fn compares_new_resolved_persistent_and_severity_changes() {
        let before = report(
            1_000,
            vec![
                finding("resolved", "warning", "old"),
                finding("escalated", "warning", "before"),
            ],
            true,
        );
        let after = report(
            2_000,
            vec![
                finding("escalated", "critical", "after"),
                finding("new", "warning", "new"),
            ],
            true,
        );
        let comparison = compare_doctor_contents(&before, &after).unwrap();
        assert_eq!(comparison.summary.new_findings, 1);
        assert_eq!(comparison.summary.resolved_findings, 1);
        assert_eq!(comparison.summary.no_longer_observed_findings, 0);
        assert_eq!(comparison.summary.persistent_findings, 1);
        assert_eq!(comparison.summary.severity_changes, 1);
        assert_eq!(comparison.summary.severity_escalations, 1);
        assert_eq!(comparison.summary.regression_count, 2);
        assert_eq!(comparison.host.effective_memory_available_bytes.delta, -300);
        let table = render_doctor_diff_table(&comparison, DiffFailOn::Never, None);
        assert!(table.contains("NEWLY OBSERVED FINDINGS (1)"));
        assert!(table.contains("RESOLVED FINDINGS (1)"));
        assert!(table.contains("WARN -> CRIT"));
        assert!(table.contains("DEEP EVIDENCE CHANGE"));
        let json: Value = serde_json::from_str(
            &render_doctor_diff_json(&comparison, DiffFailOn::Never, None).unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], DOCTOR_DIFF_SCHEMA);
        assert_eq!(json["comparison"]["summary"]["severity_changes"], 1);
        let gated_json: Value = serde_json::from_str(
            &render_doctor_diff_json(
                &comparison,
                DiffFailOn::Regression,
                Some(DiffPolicyStatus::Violated),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(gated_json["policy"]["fail_on"], "regression");
        assert_eq!(gated_json["policy"]["passed"], false);
        assert!(
            render_doctor_diff_table(
                &comparison,
                DiffFailOn::Regression,
                Some(DiffPolicyStatus::Violated),
            )
            .contains("policy FAIL")
        );
    }

    #[test]
    fn incomplete_deep_scan_does_not_claim_a_resolution() {
        let before = report(
            1_000,
            vec![finding("deleted_open_files", "warning", "120 MiB held")],
            true,
        );
        let mut after: Value = serde_json::from_str(&report(2_000, vec![], true)).unwrap();
        after["deep"]["deleted_open_files"]["warning"] =
            json!("some process file descriptors were not readable");

        let comparison = compare_doctor_contents(&before, &after.to_string()).unwrap();
        assert_eq!(comparison.summary.resolved_findings, 0);
        assert_eq!(comparison.summary.no_longer_observed_findings, 1);
        let table = render_doctor_diff_table(&comparison, DiffFailOn::Never, None);
        assert!(table.contains("RESOLUTION UNCONFIRMED"));
        assert!(!table.contains("RESOLVED FINDINGS"));
    }

    #[test]
    fn severity_improvement_is_not_a_regression() {
        let before = report(
            1_000,
            vec![finding("pressure", "critical", "critical before")],
            false,
        );
        let after = report(
            2_000,
            vec![finding("pressure", "warning", "warning after")],
            false,
        );
        let comparison = compare_doctor_contents(&before, &after).unwrap();
        assert_eq!(comparison.summary.severity_improvements, 1);
        assert_eq!(comparison.summary.severity_escalations, 0);
        assert!(!comparison.regression_detected());
    }

    #[test]
    fn refuses_incompatible_or_malformed_doctor_reports() {
        let before = report(1_000, vec![], false);
        let mut wrong_host: Value = serde_json::from_str(&report(2_000, vec![], false)).unwrap();
        wrong_host["hostname"] = json!("host-b");
        let error = compare_doctor_contents(&before, &wrong_host.to_string()).unwrap_err();
        assert!(error.contains("hostname mismatch"));

        let deep_after = report(2_000, vec![], true);
        assert!(
            compare_doctor_contents(&before, &deep_after)
                .unwrap_err()
                .contains("deep-check mismatch")
        );

        let mut malformed: Value = serde_json::from_str(&before).unwrap();
        malformed["finding_count"] = json!(1);
        assert!(
            compare_doctor_contents(&malformed.to_string(), &report(2_000, vec![], false))
                .unwrap_err()
                .contains("finding_count")
        );

        let mut wrong_status: Value = serde_json::from_str(&before).unwrap();
        wrong_status["status"] = json!("critical_signals");
        assert!(
            compare_doctor_contents(&wrong_status.to_string(), &report(2_000, vec![], false))
                .unwrap_err()
                .contains("findings require")
        );

        let mut invalid_memory: Value = serde_json::from_str(&before).unwrap();
        invalid_memory["host"]["effective_memory_available_bytes"] = json!(2_000);
        assert!(
            compare_doctor_contents(&invalid_memory.to_string(), &report(2_000, vec![], false))
                .unwrap_err()
                .contains("larger than its total")
        );
    }

    #[test]
    fn detects_reboot_and_does_not_delta_since_boot_oom_counts() {
        let mut before: Value = serde_json::from_str(&report(1_000, vec![], true)).unwrap();
        let mut after: Value = serde_json::from_str(&report(2_000, vec![], true)).unwrap();
        before["host"]["uptime_seconds"] = json!(50_000);
        after["host"]["uptime_seconds"] = json!(30);
        before["deep"]["linux_oom"]["oom_kill_count_since_boot"] = json!(7);
        after["deep"]["linux_oom"]["oom_kill_count_since_boot"] = json!(1);

        let comparison = compare_doctor_contents(&before.to_string(), &after.to_string()).unwrap();
        assert!(comparison.host.reboot_detected);
        assert_eq!(
            comparison
                .deep
                .unwrap()
                .linux_oom_kill_count_since_boot
                .delta,
            None
        );
        assert!(
            render_doctor_diff_table(&comparison, DiffFailOn::Never, None)
                .contains("not comparable after reboot")
        );
    }
}
