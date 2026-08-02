use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(not(target_os = "linux"))]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{fs, os::unix::fs::MetadataExt};

use serde::Serialize;
use sysinfo::{Pid, System};

#[cfg(target_os = "linux")]
use crate::inspection::linux_fd_access;
use crate::{
    cli::CheckExpectation,
    model::{ProcessInfo, command_for_output, process_command_line, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const DELETED_SCHEMA: &str = "psmore.deleted-open-files";
const DELETED_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeletedOpenFile {
    pid: u32,
    process: String,
    command: String,
    user: String,
    fd: String,
    access: String,
    kind: String,
    path: String,
    kernel_target: String,
    logical_size: u64,
    allocated_bytes: Option<u64>,
    device: Option<String>,
    inode: Option<String>,
}

impl DeletedOpenFile {
    fn estimated_reclaimable_bytes(&self) -> u64 {
        self.allocated_bytes.unwrap_or(self.logical_size)
    }

    fn identity_key(&self) -> String {
        match (&self.device, &self.inode) {
            (Some(device), Some(inode)) if !device.is_empty() && !inode.is_empty() => {
                format!("{device}:{inode}")
            }
            _ => format!("pid:{}:fd:{}:path:{}", self.pid, self.fd, self.path),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DeletedSummary {
    unique_file_count: usize,
    fd_reference_count: usize,
    process_count: usize,
    logical_bytes: u64,
    estimated_reclaimable_bytes: u64,
}

fn summarize(entries: &[DeletedOpenFile]) -> DeletedSummary {
    let mut unique: HashMap<String, (u64, u64)> = HashMap::new();
    let mut processes = HashSet::new();
    for entry in entries {
        processes.insert(entry.pid);
        let values = unique.entry(entry.identity_key()).or_default();
        values.0 = values.0.max(entry.logical_size);
        values.1 = values.1.max(entry.estimated_reclaimable_bytes());
    }
    DeletedSummary {
        unique_file_count: unique.len(),
        fd_reference_count: entries.len(),
        process_count: processes.len(),
        logical_bytes: unique
            .values()
            .fold(0_u64, |total, (size, _)| total.saturating_add(*size)),
        estimated_reclaimable_bytes: unique
            .values()
            .fold(0_u64, |total, (_, size)| total.saturating_add(*size)),
    }
}

pub(crate) struct CapturedDeletedFiles {
    generated_at_unix_ms: u64,
    minimum_size_bytes: u64,
    system_process_count: usize,
    estimate_basis: &'static str,
    entries: Vec<DeletedOpenFile>,
    summary: DeletedSummary,
    warning: Option<String>,
}

impl CapturedDeletedFiles {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> DeletedPolicyStatus {
        if self.summary.unique_file_count > 0 {
            if expectation.passes(self.summary.unique_file_count) {
                DeletedPolicyStatus::Passed
            } else {
                DeletedPolicyStatus::Violated
            }
        } else if self.warning.is_some() {
            DeletedPolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            DeletedPolicyStatus::Passed
        } else {
            DeletedPolicyStatus::Violated
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeletedPolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl DeletedPolicyStatus {
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

#[cfg(target_os = "linux")]
fn collect_native(processes: &HashMap<Pid, ProcessInfo>) -> (Vec<DeletedOpenFile>, Option<String>) {
    let mut entries = Vec::new();
    let mut protected_processes = 0_usize;
    let mut raced_fds = 0_usize;
    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0)
    {
        let fd_root = format!("/proc/{}/fd", process.pid);
        let fds = match fs::read_dir(&fd_root) {
            Ok(fds) => fds,
            Err(_) => {
                protected_processes += 1;
                continue;
            }
        };
        for entry in fds.flatten() {
            let target = match fs::read_link(entry.path()) {
                Ok(target) => target.to_string_lossy().into_owned(),
                Err(_) => {
                    raced_fds += 1;
                    continue;
                }
            };
            let Some(path) = target.strip_suffix(" (deleted)") else {
                continue;
            };
            let metadata = match fs::metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(_) => {
                    raced_fds += 1;
                    continue;
                }
            };
            let fd = entry.file_name().to_string_lossy().into_owned();
            entries.push(DeletedOpenFile {
                pid: process.pid.as_u32(),
                process: process.name.clone(),
                command: process_command_line(process),
                user: process.user.clone(),
                fd: fd.clone(),
                access: linux_fd_access(process.pid, &fd),
                kind: if metadata.is_file() { "REG" } else { "FILE" }.into(),
                path: path.into(),
                kernel_target: target,
                logical_size: metadata.len(),
                allocated_bytes: Some(metadata.blocks().saturating_mul(512)),
                device: Some(format!("{:x}", metadata.dev())),
                inode: Some(metadata.ino().to_string()),
            });
        }
    }
    let mut warnings = Vec::new();
    if protected_processes > 0 {
        warnings.push(format!(
            "fd tables were unreadable for {protected_processes} protected process(es)"
        ));
    }
    if raced_fds > 0 {
        warnings.push(format!(
            "{raced_fds} fd entry or metadata read(s) raced with process activity"
        ));
    }
    (entries, (!warnings.is_empty()).then(|| warnings.join("; ")))
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct LsofProcessRecord {
    pid: Option<u32>,
    command: String,
    user: String,
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct LsofDeletedRecord {
    fd: String,
    access: String,
    kind: String,
    size: u64,
    link_count: Option<u64>,
    device: Option<String>,
    inode: Option<String>,
    name: String,
}

#[cfg(not(target_os = "linux"))]
fn flush_lsof_deleted(
    process: &LsofProcessRecord,
    record: &mut Option<LsofDeletedRecord>,
    processes: &HashMap<Pid, ProcessInfo>,
    output: &mut Vec<DeletedOpenFile>,
) {
    let Some(record) = record.take() else {
        return;
    };
    let Some(pid) = process.pid else {
        return;
    };
    if record.link_count != Some(0)
        || !record
            .fd
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
    {
        return;
    }
    let process_info = processes.get(&Pid::from_u32(pid));
    output.push(DeletedOpenFile {
        pid,
        process: process_info
            .map(|process| process.name.clone())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| process.command.clone()),
        command: process_info
            .map(process_command_line)
            .unwrap_or_else(|| process.command.clone()),
        user: process_info
            .map(|process| process.user.clone())
            .filter(|user| !user.is_empty())
            .unwrap_or_else(|| process.user.clone()),
        fd: record.fd,
        access: record.access,
        kind: record.kind,
        path: record.name.clone(),
        kernel_target: record.name,
        logical_size: record.size,
        allocated_bytes: None,
        device: record.device,
        inode: record.inode,
    });
}

#[cfg(not(target_os = "linux"))]
fn parse_lsof_deleted_output(
    input: &[u8],
    processes: &HashMap<Pid, ProcessInfo>,
) -> Vec<DeletedOpenFile> {
    let mut process = LsofProcessRecord::default();
    let mut record = None;
    let mut entries = Vec::new();
    for line in String::from_utf8_lossy(input).lines() {
        let Some((field, value)) = line.split_at_checked(1) else {
            continue;
        };
        match field {
            "p" => {
                flush_lsof_deleted(&process, &mut record, processes, &mut entries);
                process = LsofProcessRecord {
                    pid: value.parse().ok(),
                    ..LsofProcessRecord::default()
                };
            }
            "c" => process.command = value.into(),
            "L" if !value.is_empty() => process.user = value.into(),
            "u" if process.user.is_empty() => process.user = value.into(),
            "f" => {
                flush_lsof_deleted(&process, &mut record, processes, &mut entries);
                record = Some(LsofDeletedRecord {
                    fd: value.into(),
                    ..LsofDeletedRecord::default()
                });
            }
            "a" => {
                if let Some(record) = &mut record {
                    record.access = value.into();
                }
            }
            "t" => {
                if let Some(record) = &mut record {
                    record.kind = value.into();
                }
            }
            "s" => {
                if let Some(record) = &mut record {
                    record.size = value.parse().unwrap_or(0);
                }
            }
            "k" => {
                if let Some(record) = &mut record {
                    record.link_count = value.parse().ok();
                }
            }
            "D" => {
                if let Some(record) = &mut record {
                    record.device = Some(value.into());
                }
            }
            "i" => {
                if let Some(record) = &mut record {
                    record.inode = Some(value.into());
                }
            }
            "n" => {
                if let Some(record) = &mut record {
                    record.name = value.into();
                }
            }
            _ => {}
        }
    }
    flush_lsof_deleted(&process, &mut record, processes, &mut entries);
    entries
}

#[cfg(not(target_os = "linux"))]
fn collect_native(processes: &HashMap<Pid, ProcessInfo>) -> (Vec<DeletedOpenFile>, Option<String>) {
    match Command::new("lsof")
        .args(["-nP", "+L1", "-FpcuLftaskDin"])
        .output()
    {
        Ok(output) => {
            let entries = parse_lsof_deleted_output(&output.stdout, processes);
            let warning = if output.status.success() || output.stdout.is_empty() {
                None
            } else {
                Some(format!(
                    "lsof could not complete deleted-file collection: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ))
            };
            (entries, warning)
        }
        Err(error) => (Vec::new(), Some(format!("cannot run lsof: {error}"))),
    }
}

pub(crate) fn capture_deleted_files(minimum_size_bytes: u64) -> CapturedDeletedFiles {
    let mut provider = NativeProcessProvider::new();
    let processes: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let (mut entries, warning) = collect_native(&processes);
    entries.retain(|entry| entry.estimated_reclaimable_bytes() >= minimum_size_bytes);
    entries.sort_by(|left, right| {
        right
            .estimated_reclaimable_bytes()
            .cmp(&left.estimated_reclaimable_bytes())
            .then_with(|| left.pid.cmp(&right.pid))
            .then_with(|| left.fd.cmp(&right.fd))
            .then_with(|| left.path.cmp(&right.path))
    });
    let summary = summarize(&entries);
    CapturedDeletedFiles {
        generated_at_unix_ms: unix_millis(),
        minimum_size_bytes,
        system_process_count: processes
            .len()
            .saturating_sub(usize::from(processes.contains_key(&Pid::from_u32(0)))),
        estimate_basis: if cfg!(target_os = "linux") {
            "allocated_blocks"
        } else {
            "logical_size_upper_bound"
        },
        entries,
        summary,
        warning,
    }
}

#[derive(Debug, Serialize)]
struct JsonDeletedFiles<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    minimum_size_bytes: u64,
    estimate_basis: &'static str,
    system_process_count: usize,
    unique_file_count: usize,
    fd_reference_count: usize,
    process_count: usize,
    logical_bytes: u64,
    estimated_reclaimable_bytes: u64,
    policy: Option<JsonPolicy<'a>>,
    warning: Option<&'a str>,
    files: Vec<JsonDeletedFile>,
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
struct JsonDeletedFile {
    pid: u32,
    process: String,
    command: String,
    user: String,
    fd: String,
    access: String,
    kind: String,
    path: String,
    kernel_target: String,
    logical_size_bytes: u64,
    allocated_bytes: Option<u64>,
    estimated_reclaimable_bytes: u64,
    device: Option<String>,
    inode: Option<String>,
}

impl From<&DeletedOpenFile> for JsonDeletedFile {
    fn from(file: &DeletedOpenFile) -> Self {
        Self {
            pid: file.pid,
            process: file.process.clone(),
            command: command_for_output(&file.command),
            user: file.user.clone(),
            fd: file.fd.clone(),
            access: file.access.clone(),
            kind: file.kind.clone(),
            path: file.path.clone(),
            kernel_target: file.kernel_target.clone(),
            logical_size_bytes: file.logical_size,
            allocated_bytes: file.allocated_bytes,
            estimated_reclaimable_bytes: file.estimated_reclaimable_bytes(),
            device: file.device.clone(),
            inode: file.inode.clone(),
        }
    }
}

pub(crate) fn render_deleted_json(
    captured: &CapturedDeletedFiles,
    expectation: Option<&str>,
    policy_status: Option<DeletedPolicyStatus>,
) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonDeletedFiles {
        schema: DELETED_SCHEMA,
        schema_version: DELETED_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, file path, device, and inode information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        minimum_size_bytes: captured.minimum_size_bytes,
        estimate_basis: captured.estimate_basis,
        system_process_count: captured.system_process_count,
        unique_file_count: captured.summary.unique_file_count,
        fd_reference_count: captured.summary.fd_reference_count,
        process_count: captured.summary.process_count,
        logical_bytes: captured.summary.logical_bytes,
        estimated_reclaimable_bytes: captured.summary.estimated_reclaimable_bytes,
        policy: expectation
            .zip(policy_status)
            .map(|(expectation, status)| JsonPolicy {
                expectation,
                status: status.label(),
                passed: status.passed(),
                detail: (status == DeletedPolicyStatus::Inconclusive).then_some(
                    "zero visible matches cannot prove absence because collection was incomplete",
                ),
            }),
        warning: captured.warning.as_deref(),
        files: captured.entries.iter().map(JsonDeletedFile::from).collect(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_deleted_table(
    captured: &CapturedDeletedFiles,
    expectation: Option<&str>,
    policy_status: Option<DeletedPolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        output.push_str(&format!(
            "DELETED CHECK {}  expected {}; matched {} unique file(s)\n",
            match status {
                DeletedPolicyStatus::Passed => "PASS",
                DeletedPolicyStatus::Violated => "FAIL",
                DeletedPolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.summary.unique_file_count
        ));
    }
    output.push_str(&format!(
        "DELETED OPEN FILES  {} unique, {} fd reference(s), {} process(es)  estimated reclaim {}  logical {}\n",
        captured.summary.unique_file_count,
        captured.summary.fd_reference_count,
        captured.summary.process_count,
        human_bytes(captured.summary.estimated_reclaimable_bytes),
        human_bytes(captured.summary.logical_bytes),
    ));
    output.push_str(&format!(
        "minimum {}  estimate basis {}\n",
        human_bytes(captured.minimum_size_bytes),
        captured.estimate_basis
    ));
    if captured.entries.is_empty() {
        output.push_str("  [no matching deleted-open file visible]\n");
    } else {
        output.push_str(
            "   RECLAIM    LOGICAL     PID FD       ACCESS USER         PROCESS      PATH\n",
        );
        for entry in &captured.entries {
            output.push_str(&format!(
                "{:>10} {:>10} {:>7} {:<8} {:<6} {:<12} {:<12} {}\n",
                human_bytes(entry.estimated_reclaimable_bytes()),
                human_bytes(entry.logical_size),
                entry.pid,
                sanitize_terminal_text(&entry.fd),
                sanitize_terminal_text(&entry.access),
                sanitize_terminal_text(&entry.user),
                sanitize_terminal_text(&entry.process),
                sanitize_terminal_text(&entry.path),
            ));
            output.push_str(&format!(
                "                       command {}\n",
                sanitize_terminal_text(&command_for_output(&entry.command))
            ));
        }
        output.push_str(
            "ACTION  Restart or close the owning process after confirming service impact; psmore does not modify the FD.\n",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn file(pid: u32, fd: &str, device: &str, inode: &str, size: u64) -> DeletedOpenFile {
        DeletedOpenFile {
            pid,
            process: "api".into(),
            command: "/srv/api\n--serve".into(),
            user: "deploy".into(),
            fd: fd.into(),
            access: "w".into(),
            kind: "REG".into(),
            path: "/var/log/api.log".into(),
            kernel_target: "/var/log/api.log (deleted)".into(),
            logical_size: size,
            allocated_bytes: Some(size / 2),
            device: Some(device.into()),
            inode: Some(inode.into()),
        }
    }

    #[test]
    fn summary_deduplicates_the_same_inode_across_fds_and_processes() {
        let entries = vec![
            file(10, "3", "1", "99", 1024),
            file(10, "4", "1", "99", 1024),
            file(20, "8", "1", "99", 1024),
            file(20, "9", "1", "100", 2048),
        ];
        let summary = summarize(&entries);
        assert_eq!(summary.unique_file_count, 2);
        assert_eq!(summary.fd_reference_count, 4);
        assert_eq!(summary.process_count, 2);
        assert_eq!(summary.logical_bytes, 3072);
        assert_eq!(summary.estimated_reclaimable_bytes, 1536);
    }

    #[test]
    fn deleted_outputs_are_versioned_explicit_and_terminal_safe() {
        let entries = vec![file(10, "3", "1", "99", 2048)];
        let captured = CapturedDeletedFiles {
            generated_at_unix_ms: 1_700_000_000_000,
            minimum_size_bytes: 1024,
            system_process_count: 20,
            estimate_basis: "allocated_blocks",
            summary: summarize(&entries),
            entries,
            warning: None,
        };
        let table = render_deleted_table(
            &captured,
            Some("no matches"),
            Some(DeletedPolicyStatus::Violated),
        );
        assert!(table.starts_with("DELETED CHECK FAIL"));
        assert!(table.contains("/srv/api --serve"));
        assert!(!table.contains("/srv/api\n--serve"));

        let json: Value = serde_json::from_str(
            &render_deleted_json(
                &captured,
                Some("no matches"),
                Some(DeletedPolicyStatus::Violated),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], DELETED_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["unique_file_count"], 1);
        assert_eq!(json["estimated_reclaimable_bytes"], 1024);
        assert_eq!(json["policy"]["passed"], false);
        assert_eq!(json["files"][0]["inode"], "99");
    }

    #[test]
    fn zero_matches_with_incomplete_collection_is_not_a_false_pass() {
        let captured = CapturedDeletedFiles {
            generated_at_unix_ms: 1,
            minimum_size_bytes: 0,
            system_process_count: 10,
            estimate_basis: "allocated_blocks",
            entries: Vec::new(),
            summary: DeletedSummary::default(),
            warning: Some("one protected process".into()),
        };
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::None),
            DeletedPolicyStatus::Inconclusive
        );
        let json: Value = serde_json::from_str(
            &render_deleted_json(
                &captured,
                Some("no matches"),
                Some(DeletedPolicyStatus::Inconclusive),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["policy"]["status"], "inconclusive");
        assert!(json["policy"]["passed"].is_null());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn parses_lsof_link_count_size_identity_and_owner() {
        let input = b"p42\ncPython\nu501\nLjoe\nf3\nau\ntREG\ns2097275\nk0\nD0x1000004\ni123\nn/private/tmp/gone.log\n";
        let entries = parse_lsof_deleted_output(input, &HashMap::new());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pid, 42);
        assert_eq!(entries[0].user, "joe");
        assert_eq!(entries[0].logical_size, 2_097_275);
        assert_eq!(entries[0].device.as_deref(), Some("0x1000004"));
        assert_eq!(entries[0].inode.as_deref(), Some("123"));
    }
}
