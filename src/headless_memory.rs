use std::{
    fmt::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(any(target_os = "linux", test))]
use std::collections::{BTreeMap, HashMap};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "macos")]
use std::process::Command;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    model::{ProcessInfo, process_command_for_output, process_path, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const MEMORY_SCHEMA: &str = "psmore.process-memory";
const MEMORY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum IdentityStatus {
    Verified,
    Unverified,
    ExitedDuringCollection,
}

impl IdentityStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unverified => "unverified",
            Self::ExitedDuringCollection => "exited_during_collection",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceStatus {
    Complete,
    Partial,
    Unavailable,
}

impl SourceStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct SourceEvidence {
    source: String,
    status: SourceStatus,
    detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct MemorySummary {
    resident_bytes: Option<u64>,
    proportional_set_size_bytes: Option<u64>,
    physical_footprint_bytes: Option<u64>,
    vmmap_region_resident_bytes_including_shared: Option<u64>,
    peak_resident_bytes: Option<u64>,
    peak_physical_footprint_bytes: Option<u64>,
    virtual_bytes: Option<u64>,
    anonymous_resident_bytes: Option<u64>,
    file_resident_bytes: Option<u64>,
    shared_memory_resident_bytes: Option<u64>,
    private_resident_bytes: Option<u64>,
    shared_resident_bytes: Option<u64>,
    swap_bytes: Option<u64>,
    locked_bytes: Option<u64>,
    data_virtual_bytes: Option<u64>,
    stack_virtual_bytes: Option<u64>,
    executable_virtual_bytes: Option<u64>,
    library_virtual_bytes: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct MemoryRegion {
    category: String,
    virtual_bytes: u64,
    resident_bytes: Option<u64>,
    dirty_bytes: Option<u64>,
    swapped_bytes: Option<u64>,
    region_count: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
struct MappedFile {
    path: String,
    virtual_bytes: u64,
    mapping_count: usize,
    executable: bool,
    deleted: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
enum FindingSeverity {
    Notice,
    Warning,
}

impl FindingSeverity {
    fn label(self) -> &'static str {
        match self {
            Self::Notice => "NOTE",
            Self::Warning => "WARN",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct MemoryFinding {
    severity: FindingSeverity,
    code: String,
    message: String,
    evidence_path: String,
}

#[derive(Clone, Debug, Default)]
struct PlatformMemory {
    summary: MemorySummary,
    regions: Vec<MemoryRegion>,
    category_total: usize,
    categories_truncated: bool,
    mapped_files: Vec<MappedFile>,
    mapped_file_total: usize,
    mapped_files_truncated: bool,
    deleted_mapping_count: usize,
    deleted_mapping_bytes: u64,
    sources: Vec<SourceEvidence>,
    warnings: Vec<String>,
}

pub(crate) struct CapturedMemory {
    process: ProcessInfo,
    generated_at_unix_ms: u64,
    identity_status: IdentityStatus,
    identity_warning: Option<String>,
    evidence: PlatformMemory,
    findings: Vec<MemoryFinding>,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
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
    status: String,
    sampled_rss_bytes: u64,
    start_time_unix_seconds: u64,
    runtime_seconds: u64,
}

impl From<&ProcessInfo> for JsonProcess {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: process.name.clone(),
            path: process_path(process),
            command: process_command_for_output(process),
            executable: process.executable.clone(),
            user: process.user.clone(),
            status: process.status.clone(),
            sampled_rss_bytes: process.memory,
            start_time_unix_seconds: process.start_time,
            runtime_seconds: process.runtime,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonCollection<'a> {
    status: &'static str,
    sources: &'a [SourceEvidence],
    warnings: &'a [String],
}

#[derive(Debug, Serialize)]
struct JsonMappings<'a> {
    category_basis: &'static str,
    category_total: usize,
    category_returned: usize,
    categories_truncated: bool,
    categories: &'a [MemoryRegion],
    mapped_file_basis: &'static str,
    mapped_file_total: usize,
    mapped_file_returned: usize,
    mapped_files_truncated: bool,
    deleted_mapping_count: usize,
    deleted_mapping_virtual_bytes: u64,
    files: &'a [MappedFile],
}

#[derive(Debug, Serialize)]
struct JsonMemory<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    process_identity: &'static str,
    process_identity_warning: Option<&'a str>,
    process: JsonProcess,
    collection: JsonCollection<'a>,
    summary: &'a MemorySummary,
    findings: &'a [MemoryFinding],
    mappings: JsonMappings<'a>,
}

fn collection_status(sources: &[SourceEvidence]) -> &'static str {
    if !sources.is_empty()
        && sources
            .iter()
            .all(|source| source.status == SourceStatus::Complete)
    {
        "complete"
    } else if sources
        .iter()
        .any(|source| source.status != SourceStatus::Unavailable)
    {
        "partial"
    } else {
        "unavailable"
    }
}

fn verify_instance(
    before: &ProcessInfo,
    after: Option<&ProcessInfo>,
) -> Result<(IdentityStatus, Option<String>), String> {
    let Some(after) = after else {
        return Ok((
            IdentityStatus::ExitedDuringCollection,
            Some(format!(
                "PID {} exited while memory evidence was being collected",
                before.pid
            )),
        ));
    };
    if before.start_time > 0 && after.start_time > 0 {
        if before.start_time != after.start_time {
            return Err(format!(
                "PID {} was reused during memory collection; refusing to combine different process instances",
                before.pid
            ));
        }
        return Ok((IdentityStatus::Verified, None));
    }
    if before.name != after.name || before.command != after.command {
        return Err(format!(
            "PID {} changed identity while memory evidence was being collected",
            before.pid
        ));
    }
    Ok((
        IdentityStatus::Unverified,
        Some(format!(
            "PID {} start time is unavailable; identity was checked using name and command fallback",
            before.pid
        )),
    ))
}

fn generated_at_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn rank_findings(evidence: &PlatformMemory) -> Vec<MemoryFinding> {
    let mut findings = Vec::new();
    if let Some(swap) = evidence.summary.swap_bytes.filter(|value| *value > 0) {
        let resident = evidence.summary.resident_bytes.unwrap_or(0);
        let severity = if swap >= 64 * 1024 * 1024 && (resident == 0 || swap >= resident / 4) {
            FindingSeverity::Warning
        } else {
            FindingSeverity::Notice
        };
        findings.push(MemoryFinding {
            severity,
            code: "memory.swap_present".into(),
            message: format!(
                "{} of this process memory is swapped; correlate with host pressure and latency",
                human_bytes(swap)
            ),
            evidence_path: "/summary/swap_bytes".into(),
        });
    }
    if evidence.deleted_mapping_count > 0 {
        findings.push(MemoryFinding {
            severity: FindingSeverity::Warning,
            code: "memory.deleted_mappings".into(),
            message: format!(
                "{} deleted file mapping(s) still reserve {} of virtual address space",
                evidence.deleted_mapping_count,
                human_bytes(evidence.deleted_mapping_bytes)
            ),
            evidence_path: "/mappings/deleted_mapping_count".into(),
        });
    }
    if let Some(locked) = evidence.summary.locked_bytes.filter(|value| *value > 0) {
        findings.push(MemoryFinding {
            severity: FindingSeverity::Notice,
            code: "memory.locked_pages".into(),
            message: format!(
                "{} is locked and cannot be reclaimed or swapped",
                human_bytes(locked)
            ),
            evidence_path: "/summary/locked_bytes".into(),
        });
    }
    if let (Some(resident), Some(anonymous)) = (
        evidence.summary.resident_bytes,
        evidence.summary.anonymous_resident_bytes,
    ) {
        if resident >= 512 * 1024 * 1024
            && anonymous.saturating_mul(100) >= resident.saturating_mul(80)
        {
            findings.push(MemoryFinding {
                severity: FindingSeverity::Notice,
                code: "memory.anonymous_dominant".into(),
                message: format!(
                    "anonymous memory is {:.1}% of resident memory; review heap/cache growth",
                    anonymous as f64 * 100.0 / resident as f64
                ),
                evidence_path: "/summary/anonymous_resident_bytes".into(),
            });
        }
    }
    if let (Some(current), Some(peak)) = (
        evidence.summary.resident_bytes,
        evidence.summary.peak_resident_bytes,
    ) {
        if peak > current.saturating_mul(2) && peak.saturating_sub(current) >= 256 * 1024 * 1024 {
            findings.push(MemoryFinding {
                severity: FindingSeverity::Notice,
                code: "memory.peak_far_above_current".into(),
                message: format!(
                    "resident peak {} is far above current {}; investigate burst allocation history",
                    human_bytes(peak),
                    human_bytes(current)
                ),
                evidence_path: "/summary/peak_resident_bytes".into(),
            });
        }
    }
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.code.cmp(&right.code))
    });
    findings
}

pub(crate) fn capture_memory(pid: u32, limit: Option<usize>) -> Result<CapturedMemory, String> {
    if pid == 0 {
        return Err("PID 0 is a virtual root and has no process memory identity".into());
    }
    let pid = Pid::from_u32(pid);
    let mut provider = NativeProcessProvider::new();
    let processes = provider.refresh();
    let process = processes
        .into_iter()
        .find(|process| process.pid == pid)
        .ok_or_else(|| format!("PID {pid} was not found"))?;
    let mut evidence = collect_platform_memory(pid.as_u32());
    evidence.mapped_file_total = evidence.mapped_files.len();
    evidence.category_total = evidence.regions.len();
    if let Some(limit) = limit {
        if evidence.regions.len() > limit {
            evidence.regions.truncate(limit);
            evidence.categories_truncated = true;
        }
        if evidence.mapped_files.len() > limit {
            evidence.mapped_files.truncate(limit);
            evidence.mapped_files_truncated = true;
        }
    }
    let after = provider.refresh();
    let (identity_status, identity_warning) = verify_instance(
        &process,
        after.iter().find(|candidate| candidate.pid == pid),
    )?;
    let findings = rank_findings(&evidence);
    Ok(CapturedMemory {
        process,
        generated_at_unix_ms: generated_at_unix_ms(),
        identity_status,
        identity_warning,
        evidence,
        findings,
    })
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map(human_bytes).unwrap_or_else(|| "unknown".into())
}

fn json_memory(captured: &CapturedMemory) -> JsonMemory<'_> {
    JsonMemory {
        schema: MEMORY_SCHEMA,
        schema_version: MEMORY_SCHEMA_VERSION,
        privacy_notice: "Contains host, process command, user, executable path, memory layout, and mapped file paths; review before sharing.",
        tool: JsonTool {
            name: "psmore",
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        process_identity: captured.identity_status.label(),
        process_identity_warning: captured.identity_warning.as_deref(),
        process: JsonProcess::from(&captured.process),
        collection: JsonCollection {
            status: collection_status(&captured.evidence.sources),
            sources: &captured.evidence.sources,
            warnings: &captured.evidence.warnings,
        },
        summary: &captured.evidence.summary,
        findings: &captured.findings,
        mappings: JsonMappings {
            category_basis: if cfg!(target_os = "macos") {
                "vmmap category virtual/resident/dirty/swapped bytes; resident includes shared mappings"
            } else {
                "/proc/PID/maps virtual address bytes; category resident bytes unavailable"
            },
            category_total: captured.evidence.category_total,
            category_returned: captured.evidence.regions.len(),
            categories_truncated: captured.evidence.categories_truncated,
            categories: &captured.evidence.regions,
            mapped_file_basis: if cfg!(target_os = "linux") {
                "/proc/PID/maps virtual address bytes; not resident memory"
            } else {
                "mapped file paths are not collected from vmmap summary mode"
            },
            mapped_file_total: captured.evidence.mapped_file_total,
            mapped_file_returned: captured.evidence.mapped_files.len(),
            mapped_files_truncated: captured.evidence.mapped_files_truncated,
            deleted_mapping_count: captured.evidence.deleted_mapping_count,
            deleted_mapping_virtual_bytes: captured.evidence.deleted_mapping_bytes,
            files: &captured.evidence.mapped_files,
        },
    }
}

pub(crate) fn render_memory_json(captured: &CapturedMemory) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&json_memory(captured))
}

pub(crate) fn render_memory_table(captured: &CapturedMemory) -> String {
    let mut output = String::new();
    let evidence = &captured.evidence;
    let summary = &evidence.summary;
    let _ = writeln!(output, "PSMORE PROCESS MEMORY");
    let _ = writeln!(
        output,
        "process {} [{}]  user {}  state {}  identity {}",
        sanitize_terminal_text(&captured.process.name),
        captured.process.pid,
        sanitize_terminal_text(&captured.process.user),
        sanitize_terminal_text(&captured.process.status),
        captured.identity_status.label(),
    );
    let _ = writeln!(
        output,
        "command {}",
        sanitize_terminal_text(&process_command_for_output(&captured.process))
    );
    let _ = writeln!(
        output,
        "collection {}  sources {}/{}",
        collection_status(&evidence.sources),
        evidence
            .sources
            .iter()
            .filter(|source| source.status == SourceStatus::Complete)
            .count(),
        evidence.sources.len()
    );
    let _ = writeln!(
        output,
        "sampled RSS {}  precise RSS {}  PSS {}  footprint {}  virtual {}",
        human_bytes(captured.process.memory),
        optional_bytes(summary.resident_bytes),
        optional_bytes(summary.proportional_set_size_bytes),
        optional_bytes(summary.physical_footprint_bytes),
        optional_bytes(summary.virtual_bytes),
    );
    if summary.peak_resident_bytes.is_some()
        || summary.peak_physical_footprint_bytes.is_some()
        || summary
            .vmmap_region_resident_bytes_including_shared
            .is_some()
    {
        let _ = writeln!(
            output,
            "peak RSS {}  peak footprint {}  vmmap region resident incl. shared {}",
            optional_bytes(summary.peak_resident_bytes),
            optional_bytes(summary.peak_physical_footprint_bytes),
            optional_bytes(summary.vmmap_region_resident_bytes_including_shared),
        );
    }
    let _ = writeln!(
        output,
        "anonymous {}  file {}  shmem {}  private {}  shared {}  swap {}  locked {}",
        optional_bytes(summary.anonymous_resident_bytes),
        optional_bytes(summary.file_resident_bytes),
        optional_bytes(summary.shared_memory_resident_bytes),
        optional_bytes(summary.private_resident_bytes),
        optional_bytes(summary.shared_resident_bytes),
        optional_bytes(summary.swap_bytes),
        optional_bytes(summary.locked_bytes),
    );
    if summary.data_virtual_bytes.is_some()
        || summary.stack_virtual_bytes.is_some()
        || summary.executable_virtual_bytes.is_some()
        || summary.library_virtual_bytes.is_some()
    {
        let _ = writeln!(
            output,
            "virtual layout  data {}  stack {}  executable {}  libraries {}",
            optional_bytes(summary.data_virtual_bytes),
            optional_bytes(summary.stack_virtual_bytes),
            optional_bytes(summary.executable_virtual_bytes),
            optional_bytes(summary.library_virtual_bytes),
        );
    }

    if !captured.findings.is_empty() {
        let _ = writeln!(output, "\nATTENTION");
        for finding in &captured.findings {
            let _ = writeln!(
                output,
                "  {:<4} {:<32} {}",
                finding.severity.label(),
                finding.code,
                sanitize_terminal_text(&finding.message)
            );
        }
    }

    if !evidence.regions.is_empty() {
        let _ = writeln!(
            output,
            "\nMEMORY CATEGORIES  returned {}/{}{}",
            evidence.regions.len(),
            evidence.category_total,
            if evidence.categories_truncated {
                " truncated"
            } else {
                ""
            }
        );
        let _ = writeln!(
            output,
            "  {:<30} {:>12} {:>12} {:>12} {:>12} {:>8}",
            "CATEGORY", "VIRTUAL", "RESIDENT", "DIRTY", "SWAPPED", "REGIONS"
        );
        for region in &evidence.regions {
            let _ = writeln!(
                output,
                "  {:<30} {:>12} {:>12} {:>12} {:>12} {:>8}",
                truncate_text(&sanitize_terminal_text(&region.category), 30),
                human_bytes(region.virtual_bytes),
                optional_bytes(region.resident_bytes),
                optional_bytes(region.dirty_bytes),
                optional_bytes(region.swapped_bytes),
                region.region_count,
            );
        }
    }

    if !evidence.mapped_files.is_empty() {
        let _ = writeln!(
            output,
            "\nTOP FILE MAPPINGS (virtual bytes, not resident)  returned {}/{}{}",
            evidence.mapped_files.len(),
            evidence.mapped_file_total,
            if evidence.mapped_files_truncated {
                " truncated"
            } else {
                ""
            }
        );
        let _ = writeln!(
            output,
            "  {:>12} {:>7} {:<5} PATH",
            "VIRTUAL", "MAPS", "EXEC"
        );
        for file in &evidence.mapped_files {
            let _ = writeln!(
                output,
                "  {:>12} {:>7} {:<5} {}{}",
                human_bytes(file.virtual_bytes),
                file.mapping_count,
                if file.executable { "yes" } else { "no" },
                sanitize_terminal_text(&file.path),
                if file.deleted { "  [deleted]" } else { "" },
            );
        }
    }

    let _ = writeln!(output, "\nCOLLECTION SOURCES");
    for source in &evidence.sources {
        let _ = writeln!(
            output,
            "  {:<20} {:<11} {}",
            sanitize_terminal_text(&source.source),
            source.status.label(),
            sanitize_terminal_text(&source.detail)
        );
    }
    if let Some(warning) = captured.identity_warning.as_deref() {
        let _ = writeln!(output, "warning {}", sanitize_terminal_text(warning));
    }
    for warning in &evidence.warnings {
        let _ = writeln!(output, "warning {}", sanitize_terminal_text(warning));
    }
    output
}

fn truncate_text(value: &str, width: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= width {
        return value.to_string();
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let mut output = chars[..width - 1].iter().collect::<String>();
    output.push('…');
    output
}

#[cfg(any(target_os = "linux", test))]
fn parse_kib_fields(input: &str) -> BTreeMap<String, u64> {
    let mut fields = BTreeMap::new();
    for line in input.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let mut parts = value.split_whitespace();
        let Some(number) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        let multiplier = match parts.next().unwrap_or("B").to_ascii_lowercase().as_str() {
            "kb" => 1024,
            "mb" => 1024 * 1024,
            _ => 1,
        };
        fields.insert(key.trim().to_string(), number.saturating_mul(multiplier));
    }
    fields
}

#[cfg(any(target_os = "linux", test))]
fn field(fields: &BTreeMap<String, u64>, name: &str) -> Option<u64> {
    fields.get(name).copied()
}

#[cfg(any(target_os = "linux", test))]
fn sum_fields(fields: &BTreeMap<String, u64>, names: &[&str]) -> Option<u64> {
    let mut found = false;
    let mut total = 0u64;
    for name in names {
        if let Some(value) = field(fields, name) {
            found = true;
            total = total.saturating_add(value);
        }
    }
    found.then_some(total)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_maps(input: &str) -> (Vec<MemoryRegion>, Vec<MappedFile>, usize, u64) {
    let mut categories: HashMap<String, MemoryRegion> = HashMap::new();
    let mut files: HashMap<String, MappedFile> = HashMap::new();
    let mut deleted_count = 0usize;
    let mut deleted_bytes = 0u64;
    for line in input.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 5 {
            continue;
        }
        let Some((start, end)) = parts[0].split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let bytes = end.saturating_sub(start);
        let permissions = parts[1];
        let raw_path = if parts.len() > 5 {
            parts[5..].join(" ")
        } else {
            String::new()
        };
        let deleted = raw_path.ends_with(" (deleted)");
        let path = raw_path
            .strip_suffix(" (deleted)")
            .unwrap_or(&raw_path)
            .to_string();
        let category = if path.is_empty() || path.starts_with("[anon:") {
            "anonymous"
        } else if path == "[heap]" {
            "heap"
        } else if path.starts_with("[stack") {
            "stack"
        } else if matches!(path.as_str(), "[vdso]" | "[vvar]" | "[vsyscall]") {
            "kernel helper"
        } else if path.starts_with("/dev/shm/")
            || path.starts_with("/SYSV")
            || path.starts_with("memfd:")
        {
            "shared memory"
        } else if path.starts_with('[') {
            "other pseudo"
        } else if permissions.contains('x') {
            "file executable"
        } else {
            "file mapped"
        };
        let region = categories
            .entry(category.into())
            .or_insert_with(|| MemoryRegion {
                category: category.into(),
                ..MemoryRegion::default()
            });
        region.virtual_bytes = region.virtual_bytes.saturating_add(bytes);
        region.region_count = region.region_count.saturating_add(1);
        if deleted {
            deleted_count = deleted_count.saturating_add(1);
            deleted_bytes = deleted_bytes.saturating_add(bytes);
        }
        if !path.is_empty() && !path.starts_with('[') {
            let mapped = files.entry(path.clone()).or_insert_with(|| MappedFile {
                path,
                ..MappedFile::default()
            });
            mapped.virtual_bytes = mapped.virtual_bytes.saturating_add(bytes);
            mapped.mapping_count = mapped.mapping_count.saturating_add(1);
            mapped.executable |= permissions.contains('x');
            mapped.deleted |= deleted;
        }
    }
    let mut categories = categories.into_values().collect::<Vec<_>>();
    categories.sort_by(|left, right| {
        right
            .virtual_bytes
            .cmp(&left.virtual_bytes)
            .then_with(|| left.category.cmp(&right.category))
    });
    let mut files = files.into_values().collect::<Vec<_>>();
    files.sort_by(|left, right| {
        right
            .virtual_bytes
            .cmp(&left.virtual_bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    (categories, files, deleted_count, deleted_bytes)
}

#[cfg(target_os = "linux")]
fn read_proc_source(pid: u32, name: &str) -> (Option<String>, SourceEvidence, Option<String>) {
    let path = format!("/proc/{pid}/{name}");
    match fs::read_to_string(&path) {
        Ok(content) if content.trim().is_empty() => (
            Some(content),
            SourceEvidence {
                source: path.clone(),
                status: SourceStatus::Partial,
                detail: "read successfully but returned no fields".into(),
            },
            Some(format!("{path} was readable but returned no evidence")),
        ),
        Ok(content) => (
            Some(content),
            SourceEvidence {
                source: path,
                status: SourceStatus::Complete,
                detail: "read successfully".into(),
            },
            None,
        ),
        Err(error) => (
            None,
            SourceEvidence {
                source: path.clone(),
                status: SourceStatus::Unavailable,
                detail: error.to_string(),
            },
            Some(format!("cannot read {path}: {error}")),
        ),
    }
}

#[cfg(target_os = "linux")]
fn collect_platform_memory(pid: u32) -> PlatformMemory {
    let (smaps, mut smaps_source, smaps_warning) = read_proc_source(pid, "smaps_rollup");
    let (status, mut status_source, status_warning) = read_proc_source(pid, "status");
    let (maps, maps_source, maps_warning) = read_proc_source(pid, "maps");
    let smaps_fields = smaps.as_deref().map(parse_kib_fields).unwrap_or_default();
    let status_fields = status.as_deref().map(parse_kib_fields).unwrap_or_default();
    let mut parse_warnings = Vec::new();
    if smaps.is_some() && !smaps_fields.contains_key("Rss") && !smaps_fields.contains_key("Pss") {
        smaps_source.status = SourceStatus::Partial;
        smaps_source.detail = "read successfully but no RSS/PSS fields were recognized".into();
        parse_warnings.push(format!(
            "cannot parse RSS/PSS fields from /proc/{pid}/smaps_rollup"
        ));
    }
    if status.is_some()
        && !status_fields.contains_key("VmRSS")
        && !status_fields.contains_key("VmSize")
        && !status_fields.contains_key("VmHWM")
    {
        status_source.status = SourceStatus::Partial;
        status_source.detail =
            "read successfully but no VmRSS, VmSize, or VmHWM fields were recognized".into();
        parse_warnings.push(format!(
            "cannot parse process memory fields from /proc/{pid}/status"
        ));
    }
    let (regions, mapped_files, deleted_mapping_count, deleted_mapping_bytes) =
        maps.as_deref().map(parse_linux_maps).unwrap_or_default();
    let summary = MemorySummary {
        resident_bytes: field(&smaps_fields, "Rss").or_else(|| field(&status_fields, "VmRSS")),
        proportional_set_size_bytes: field(&smaps_fields, "Pss"),
        physical_footprint_bytes: None,
        peak_resident_bytes: field(&status_fields, "VmHWM"),
        peak_physical_footprint_bytes: None,
        virtual_bytes: field(&status_fields, "VmSize"),
        vmmap_region_resident_bytes_including_shared: None,
        anonymous_resident_bytes: field(&status_fields, "RssAnon")
            .or_else(|| field(&smaps_fields, "Anonymous")),
        file_resident_bytes: field(&status_fields, "RssFile"),
        shared_memory_resident_bytes: field(&status_fields, "RssShmem"),
        private_resident_bytes: sum_fields(&smaps_fields, &["Private_Clean", "Private_Dirty"]),
        shared_resident_bytes: sum_fields(&smaps_fields, &["Shared_Clean", "Shared_Dirty"]),
        swap_bytes: field(&smaps_fields, "Swap").or_else(|| field(&status_fields, "VmSwap")),
        locked_bytes: field(&smaps_fields, "Locked").or_else(|| field(&status_fields, "VmLck")),
        data_virtual_bytes: field(&status_fields, "VmData"),
        stack_virtual_bytes: field(&status_fields, "VmStk"),
        executable_virtual_bytes: field(&status_fields, "VmExe"),
        library_virtual_bytes: field(&status_fields, "VmLib"),
    };
    PlatformMemory {
        summary,
        regions,
        category_total: 0,
        categories_truncated: false,
        mapped_files,
        mapped_file_total: 0,
        mapped_files_truncated: false,
        deleted_mapping_count,
        deleted_mapping_bytes,
        sources: vec![smaps_source, status_source, maps_source],
        warnings: [smaps_warning, status_warning, maps_warning]
            .into_iter()
            .flatten()
            .chain(parse_warnings)
            .collect(),
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_vmmap_size(value: &str) -> Option<u64> {
    let value = value.trim().trim_end_matches(',').replace(',', "");
    if value == "---" || value.is_empty() {
        return None;
    }
    let split = value
        .char_indices()
        .find(|(_, character)| character.is_ascii_alphabetic())
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    let number = value[..split].parse::<f64>().ok()?;
    let unit = value[split..].to_ascii_uppercase();
    let multiplier = match unit.as_str() {
        "" | "B" => 1.0,
        "K" | "KB" => 1024.0,
        "M" | "MB" => 1024_f64.powi(2),
        "G" | "GB" => 1024_f64.powi(3),
        "T" | "TB" => 1024_f64.powi(4),
        _ => return None,
    };
    let bytes = number * multiplier;
    (bytes.is_finite() && bytes >= 0.0 && bytes <= u64::MAX as f64).then_some(bytes.round() as u64)
}

#[cfg(any(target_os = "macos", test))]
fn parse_vmmap_summary(input: &str) -> (MemorySummary, Vec<MemoryRegion>) {
    let mut summary = MemorySummary::default();
    let mut regions = Vec::new();
    let mut in_regions = false;
    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Physical footprint:") {
            summary.physical_footprint_bytes = parse_vmmap_size(value.trim());
        } else if let Some(value) = trimmed.strip_prefix("Physical footprint (peak):") {
            summary.peak_physical_footprint_bytes = parse_vmmap_size(value.trim());
        }
        if trimmed.starts_with("REGION TYPE") {
            in_regions = true;
            continue;
        }
        if !in_regions || trimmed.is_empty() || trimmed.starts_with("===") {
            continue;
        }
        let tokens = trimmed.split_whitespace().collect::<Vec<_>>();
        let Some(first_size) = tokens
            .iter()
            .position(|token| parse_vmmap_size(token).is_some())
        else {
            continue;
        };
        if first_size == 0 || tokens.len() < first_size + 8 {
            continue;
        }
        let sizes = &tokens[first_size..first_size + 7];
        let Some(values) = sizes
            .iter()
            .map(|value| parse_vmmap_size(value))
            .collect::<Option<Vec<_>>>()
        else {
            continue;
        };
        let Ok(region_count) = tokens[first_size + 7].parse::<usize>() else {
            continue;
        };
        let category = tokens[..first_size].join(" ");
        let region = MemoryRegion {
            category: category.clone(),
            virtual_bytes: values[0],
            resident_bytes: Some(values[1]),
            dirty_bytes: Some(values[2]),
            swapped_bytes: Some(values[3]),
            region_count,
        };
        if category == "TOTAL" {
            summary.virtual_bytes = Some(values[0]);
            summary.vmmap_region_resident_bytes_including_shared = Some(values[1]);
            summary.swap_bytes = Some(values[3]);
            break;
        }
        regions.push(region);
    }
    regions.sort_by(|left, right| {
        right
            .resident_bytes
            .unwrap_or(0)
            .cmp(&left.resident_bytes.unwrap_or(0))
            .then_with(|| right.virtual_bytes.cmp(&left.virtual_bytes))
            .then_with(|| left.category.cmp(&right.category))
    });
    (summary, regions)
}

#[cfg(target_os = "macos")]
fn collect_platform_memory(pid: u32) -> PlatformMemory {
    let output = Command::new("/usr/bin/vmmap")
        .args(["-summary", &pid.to_string()])
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = sanitize_terminal_text(&String::from_utf8_lossy(&output.stderr));
            let (summary, regions) = parse_vmmap_summary(&stdout);
            let parsed = summary
                .vmmap_region_resident_bytes_including_shared
                .is_some()
                || summary.physical_footprint_bytes.is_some()
                || !regions.is_empty();
            let status = if output.status.success() && parsed {
                SourceStatus::Complete
            } else if parsed {
                SourceStatus::Partial
            } else {
                SourceStatus::Unavailable
            };
            let detail = if stderr.trim().is_empty() {
                format!(
                    "vmmap exited with {}; parsed {} categories",
                    output.status,
                    regions.len()
                )
            } else {
                format!(
                    "vmmap exited with {}; {}",
                    output.status,
                    truncate_text(stderr.trim(), 240)
                )
            };
            let mut warnings = Vec::new();
            if status != SourceStatus::Complete {
                warnings.push(format!(
                    "vmmap memory evidence is {}: {detail}",
                    status.label()
                ));
            }
            PlatformMemory {
                summary,
                regions,
                sources: vec![SourceEvidence {
                    source: "/usr/bin/vmmap -summary".into(),
                    status,
                    detail,
                }],
                warnings,
                ..PlatformMemory::default()
            }
        }
        Err(error) => PlatformMemory {
            sources: vec![SourceEvidence {
                source: "/usr/bin/vmmap -summary".into(),
                status: SourceStatus::Unavailable,
                detail: error.to_string(),
            }],
            warnings: vec![format!("cannot run vmmap: {error}")],
            ..PlatformMemory::default()
        },
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_platform_memory(_pid: u32) -> PlatformMemory {
    PlatformMemory {
        sources: vec![SourceEvidence {
            source: "platform memory collector".into(),
            status: SourceStatus::Unavailable,
            detail: "process memory attribution is supported on Linux and macOS".into(),
        }],
        warnings: vec!["process memory attribution is unsupported on this platform".into()],
        ..PlatformMemory::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_rollup_status_and_mapping_evidence() {
        let fields = parse_kib_fields(
            "Rss: 4096 kB\nPss: 2048 kB\nPrivate_Clean: 512 kB\nPrivate_Dirty: 256 kB\nSwap: 64 kB\n",
        );
        assert_eq!(field(&fields, "Rss"), Some(4 * 1024 * 1024));
        assert_eq!(
            sum_fields(&fields, &["Private_Clean", "Private_Dirty"]),
            Some(768 * 1024)
        );

        let maps = concat!(
            "1000-2000 r-xp 00000000 08:01 1 /opt/app/bin/worker\n",
            "2000-4000 r--p 00001000 08:01 1 /opt/app/bin/worker\n",
            "4000-5000 rw-p 00000000 00:00 0 [heap]\n",
            "5000-7000 r--p 00000000 08:01 2 /opt/app/old.so (deleted)\n",
            "7000-8000 rw-p 00000000 00:00 0\n",
        );
        let (categories, files, deleted_count, deleted_bytes) = parse_linux_maps(maps);
        assert!(categories.iter().any(|region| region.category == "heap"));
        assert_eq!(files[0].path, "/opt/app/bin/worker");
        assert_eq!(files[0].virtual_bytes, 0x3000);
        assert!(files[0].executable);
        assert_eq!(deleted_count, 1);
        assert_eq!(deleted_bytes, 0x2000);
        assert!(files.iter().any(|file| file.deleted));
    }

    #[test]
    fn parses_vmmap_summary_without_tying_to_one_os_release() {
        let report = r#"
Physical footprint:         1584K
Physical footprint (peak):  2048K
                                VIRTUAL RESIDENT    DIRTY  SWAPPED VOLATILE   NONVOL    EMPTY   REGION
REGION TYPE                        SIZE     SIZE     SIZE     SIZE     SIZE     SIZE     SIZE    COUNT (non-coalesced)
===========                     ======= ========    =====  ======= ========   ======    =====  =======
MALLOC metadata                    784K     320K     320K       0K       0K       0K       0K        4
MALLOC_SMALL                      16.0M     336K     336K       0K       0K       0K       0K        4
Stack                             8176K      32K      32K       0K       0K       0K       0K        1
===========                     ======= ========    =====  ======= ========   ======    =====  =======
TOTAL                            816.2M    56.9M    1600K      16K       0K      16K       0K      294
"#;
        let (summary, regions) = parse_vmmap_summary(report);
        assert_eq!(summary.physical_footprint_bytes, Some(1584 * 1024));
        assert_eq!(summary.peak_physical_footprint_bytes, Some(2048 * 1024));
        assert_eq!(
            summary.vmmap_region_resident_bytes_including_shared,
            Some((56.9_f64 * 1024_f64 * 1024_f64).round() as u64)
        );
        assert_eq!(summary.swap_bytes, Some(16 * 1024));
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].category, "MALLOC_SMALL");
        assert_eq!(regions[0].resident_bytes, Some(336 * 1024));
    }

    #[test]
    fn findings_are_conservative_and_evidence_linked() {
        let evidence = PlatformMemory {
            summary: MemorySummary {
                resident_bytes: Some(256 * 1024 * 1024),
                swap_bytes: Some(128 * 1024 * 1024),
                locked_bytes: Some(4096),
                ..MemorySummary::default()
            },
            deleted_mapping_count: 2,
            deleted_mapping_bytes: 8192,
            ..PlatformMemory::default()
        };
        let findings = rank_findings(&evidence);
        assert_eq!(findings[0].severity, FindingSeverity::Warning);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == "memory.swap_present")
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.evidence_path.starts_with('/'))
        );
    }
}
