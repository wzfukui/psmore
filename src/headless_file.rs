use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(not(target_os = "linux"))]
use std::process::{Command, Stdio};

use serde::Serialize;
use sysinfo::{Pid, System};

#[cfg(target_os = "linux")]
use crate::inspection::linux_fd_access;
use crate::{
    cli::CheckExpectation,
    model::{
        ProcessInfo, command_for_output, output_secret_redaction_enabled, process_command_line,
        sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const FILE_SCHEMA: &str = "psmore.file-usage";
const FILE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn metadata_identity(_metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: 0,
        inode: 0,
    }
}

fn identity_for_path(path: &Path) -> Option<FileIdentity> {
    fs::metadata(path)
        .ok()
        .map(|metadata| metadata_identity(&metadata))
}

fn lexical_absolute(path: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot resolve current directory: {error}"))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new("/")),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized != Path::new("/") {
                    normalized.pop();
                }
            }
            Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn normalized_path(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).or_else(|_| lexical_absolute(path))
}

fn path_without_deleted_suffix(path: &str) -> &str {
    path.strip_suffix(" (deleted)").unwrap_or(path)
}

#[derive(Clone, Debug)]
struct FileMatcher {
    path: PathBuf,
    identity: Option<FileIdentity>,
    recursive: bool,
}

impl FileMatcher {
    fn new(path: &str, recursive: bool) -> Result<Self, String> {
        let path = normalized_path(Path::new(path))?;
        let identity = identity_for_path(&path);
        Ok(Self {
            path,
            identity,
            recursive,
        })
    }

    fn matches(&self, candidate: &str, identity: Option<FileIdentity>) -> bool {
        if self.identity.is_some() && self.identity == identity {
            return true;
        }
        let candidate = path_without_deleted_suffix(candidate);
        if candidate.is_empty() || !Path::new(candidate).is_absolute() {
            return false;
        }
        let candidate =
            normalized_path(Path::new(candidate)).unwrap_or_else(|_| PathBuf::from(candidate));
        if self.recursive {
            candidate.starts_with(&self.path)
        } else {
            candidate == self.path
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileUsage {
    pid: u32,
    process: String,
    command: String,
    user: String,
    relation: String,
    descriptor: String,
    access: String,
    kind: String,
    path: String,
    kernel_target: String,
    identity: Option<FileIdentity>,
}

fn usage_key(usage: &FileUsage) -> (u32, &str, &str, &str) {
    (
        usage.pid,
        usage.relation.as_str(),
        usage.descriptor.as_str(),
        usage.kernel_target.as_str(),
    )
}

fn relation_rank(relation: &str) -> u8 {
    match relation {
        "EXEC" => 0,
        "CWD" => 1,
        "ROOT" => 2,
        "OPEN" => 3,
        "MAPPED" => 4,
        _ => 5,
    }
}

fn collector_processes(processes: &HashMap<Pid, ProcessInfo>) -> HashSet<Pid> {
    let current = Pid::from_u32(std::process::id());
    let mut collector = HashSet::from([current]);
    loop {
        let before = collector.len();
        for process in processes.values() {
            if process
                .parent
                .is_some_and(|parent| collector.contains(&parent))
            {
                collector.insert(process.pid);
            }
        }
        if collector.len() == before {
            return collector;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_if_matching(
    output: &mut Vec<FileUsage>,
    matcher: &FileMatcher,
    process: Option<&ProcessInfo>,
    pid: u32,
    fallback_process: &str,
    fallback_user: &str,
    relation: &str,
    descriptor: &str,
    access: &str,
    kind: &str,
    path: &str,
    kernel_target: &str,
    identity: Option<FileIdentity>,
) {
    if !matcher.matches(path, identity) {
        return;
    }
    let process_name = process
        .map(|process| process.name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| fallback_process.to_string());
    let command = process
        .map(process_command_line)
        .unwrap_or_else(|| fallback_process.to_string());
    let user = process
        .map(|process| process.user.clone())
        .filter(|user| !user.is_empty())
        .unwrap_or_else(|| fallback_user.to_string());
    output.push(FileUsage {
        pid,
        process: process_name,
        command,
        user,
        relation: relation.into(),
        descriptor: descriptor.into(),
        access: access.trim().into(),
        kind: kind.into(),
        path: path_without_deleted_suffix(path).into(),
        kernel_target: kernel_target.into(),
        identity,
    });
}

struct NativeCollection {
    entries: Vec<FileUsage>,
    eligible_process_count: usize,
    inspected_process_count: usize,
    collection_complete: bool,
    warning: Option<String>,
}

#[cfg(target_os = "linux")]
fn linux_file_kind(path: &Path) -> &'static str {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => "DIR",
        Ok(metadata) if metadata.is_file() => "REG",
        Ok(_) => "FILE",
        Err(_) => "FILE",
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_map_line(line: &str) -> Option<(String, String)> {
    let bytes = line.as_bytes();
    let mut cursor = 0_usize;
    let mut access = None;
    for field_index in 0..5 {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            cursor += 1;
        }
        if start == cursor {
            return None;
        }
        if field_index == 1 {
            access = Some(line[start..cursor].to_string());
        }
    }
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let path = line.get(cursor..)?.to_string();
    path.starts_with('/').then_some((access?, path))
}

#[cfg(target_os = "linux")]
fn collect_native(
    processes: &HashMap<Pid, ProcessInfo>,
    matcher: &FileMatcher,
) -> NativeCollection {
    let collector = collector_processes(processes);
    let eligible: Vec<&ProcessInfo> = processes
        .values()
        .filter(|process| process.pid.as_u32() != 0 && !collector.contains(&process.pid))
        .collect();
    let mut entries = Vec::new();
    let mut inspected_process_count = 0_usize;
    let mut incomplete_processes = 0_usize;
    let mut raced_entries = 0_usize;

    for process in &eligible {
        let pid = process.pid.as_u32();
        let proc_root = PathBuf::from(format!("/proc/{pid}"));
        let mut complete = true;

        for (name, relation, descriptor, access, fallback) in [
            ("exe", "EXEC", "exe", "x", process.executable.as_str()),
            ("cwd", "CWD", "cwd", "", process.cwd.as_str()),
            ("root", "ROOT", "root", "", ""),
        ] {
            let proc_link = proc_root.join(name);
            match fs::read_link(&proc_link) {
                Ok(target) => {
                    let target = target.to_string_lossy().into_owned();
                    let identity = identity_for_path(&proc_link);
                    push_if_matching(
                        &mut entries,
                        matcher,
                        Some(process),
                        pid,
                        &process.name,
                        &process.user,
                        relation,
                        descriptor,
                        access,
                        linux_file_kind(&proc_link),
                        &target,
                        &target,
                        identity,
                    );
                }
                Err(_) => {
                    complete = false;
                    if !fallback.is_empty() {
                        push_if_matching(
                            &mut entries,
                            matcher,
                            Some(process),
                            pid,
                            &process.name,
                            &process.user,
                            relation,
                            descriptor,
                            access,
                            linux_file_kind(Path::new(fallback)),
                            fallback,
                            fallback,
                            identity_for_path(Path::new(fallback)),
                        );
                    }
                }
            }
        }

        match fs::read_dir(proc_root.join("fd")) {
            Ok(fds) => {
                for entry in fds.flatten() {
                    let descriptor = entry.file_name().to_string_lossy().into_owned();
                    match fs::read_link(entry.path()) {
                        Ok(target) => {
                            let kernel_target = target.to_string_lossy().into_owned();
                            let path = path_without_deleted_suffix(&kernel_target);
                            let identity = identity_for_path(&entry.path());
                            push_if_matching(
                                &mut entries,
                                matcher,
                                Some(process),
                                pid,
                                &process.name,
                                &process.user,
                                "OPEN",
                                &descriptor,
                                &linux_fd_access(process.pid, &descriptor),
                                linux_file_kind(&entry.path()),
                                path,
                                &kernel_target,
                                identity,
                            );
                        }
                        Err(_) => {
                            complete = false;
                            raced_entries = raced_entries.saturating_add(1);
                        }
                    }
                }
            }
            Err(_) => complete = false,
        }

        match fs::read_to_string(proc_root.join("maps")) {
            Ok(maps) => {
                for (access, path) in maps.lines().filter_map(parse_linux_map_line) {
                    push_if_matching(
                        &mut entries,
                        matcher,
                        Some(process),
                        pid,
                        &process.name,
                        &process.user,
                        "MAPPED",
                        "maps",
                        &access,
                        linux_file_kind(Path::new(&path)),
                        &path,
                        &path,
                        identity_for_path(Path::new(&path)),
                    );
                }
            }
            Err(_) => complete = false,
        }

        if complete {
            inspected_process_count = inspected_process_count.saturating_add(1);
        } else {
            incomplete_processes = incomplete_processes.saturating_add(1);
        }
    }

    let mut warnings = Vec::new();
    if incomplete_processes > 0 {
        warnings.push(format!(
            "file context was incomplete for {incomplete_processes} protected, exited, or racing process(es)"
        ));
    }
    if raced_entries > 0 {
        warnings.push(format!(
            "{raced_entries} file descriptor read(s) raced with process activity"
        ));
    }
    NativeCollection {
        entries,
        eligible_process_count: eligible.len(),
        inspected_process_count,
        collection_complete: incomplete_processes == 0 && raced_entries == 0,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    }
}

#[cfg(any(not(target_os = "linux"), test))]
#[derive(Default)]
struct LsofProcessRecord {
    pid: Option<u32>,
    command: String,
    user: String,
}

#[cfg(any(not(target_os = "linux"), test))]
#[derive(Default)]
struct LsofFileRecord {
    descriptor: String,
    access: String,
    kind: String,
    device: Option<String>,
    inode: Option<String>,
    name: String,
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_lsof_device(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .or_else(|| value.parse().ok())
}

#[cfg(any(not(target_os = "linux"), test))]
fn lsof_identity(record: &LsofFileRecord) -> Option<FileIdentity> {
    Some(FileIdentity {
        device: parse_lsof_device(record.device.as_deref()?)?,
        inode: record.inode.as_deref()?.parse().ok()?,
    })
}

#[cfg(any(not(target_os = "linux"), test))]
fn same_path(left: &str, right: &str) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    normalized_path(Path::new(left)).ok() == normalized_path(Path::new(right)).ok()
}

#[cfg(any(not(target_os = "linux"), test))]
fn flush_lsof_file(
    process: &LsofProcessRecord,
    record: &mut Option<LsofFileRecord>,
    processes: &HashMap<Pid, ProcessInfo>,
    matcher: &FileMatcher,
    excluded: &HashSet<u32>,
    first_text_seen: &mut HashSet<u32>,
    entries: &mut Vec<FileUsage>,
) {
    let Some(record) = record.take() else {
        return;
    };
    let Some(pid) = process.pid.filter(|pid| !excluded.contains(pid)) else {
        return;
    };
    let process_info = processes.get(&Pid::from_u32(pid));
    let relation = match record.descriptor.as_str() {
        "cwd" => "CWD",
        "rtd" => "ROOT",
        "mem" => "MAPPED",
        "txt" => {
            let executable_match =
                process_info.is_some_and(|process| same_path(&record.name, &process.executable));
            if executable_match || first_text_seen.insert(pid) {
                "EXEC"
            } else {
                "MAPPED"
            }
        }
        descriptor
            if descriptor
                .chars()
                .next()
                .is_some_and(|character| character.is_ascii_digit()) =>
        {
            "OPEN"
        }
        _ => return,
    };
    push_if_matching(
        entries,
        matcher,
        process_info,
        pid,
        &process.command,
        &process.user,
        relation,
        &record.descriptor,
        &record.access,
        &record.kind,
        &record.name,
        &record.name,
        lsof_identity(&record),
    );
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_lsof_output(
    input: &[u8],
    processes: &HashMap<Pid, ProcessInfo>,
    matcher: &FileMatcher,
    excluded: &HashSet<u32>,
) -> (Vec<FileUsage>, HashSet<u32>) {
    let mut process = LsofProcessRecord::default();
    let mut record = None;
    let mut entries = Vec::new();
    let mut seen_processes = HashSet::new();
    let mut first_text_seen = HashSet::new();
    for raw in input.split(|byte| *byte == 0) {
        let raw = raw.strip_prefix(b"\n").unwrap_or(raw);
        let Some((&field, value)) = raw.split_first() else {
            continue;
        };
        let value = String::from_utf8_lossy(value).into_owned();
        match field {
            b'p' => {
                flush_lsof_file(
                    &process,
                    &mut record,
                    processes,
                    matcher,
                    excluded,
                    &mut first_text_seen,
                    &mut entries,
                );
                process = LsofProcessRecord {
                    pid: value.parse().ok(),
                    ..LsofProcessRecord::default()
                };
                if let Some(pid) = process.pid.filter(|pid| !excluded.contains(pid)) {
                    seen_processes.insert(pid);
                }
            }
            b'c' => process.command = value,
            b'L' if !value.is_empty() => process.user = value,
            b'u' if process.user.is_empty() => process.user = value,
            b'f' => {
                flush_lsof_file(
                    &process,
                    &mut record,
                    processes,
                    matcher,
                    excluded,
                    &mut first_text_seen,
                    &mut entries,
                );
                record = Some(LsofFileRecord {
                    descriptor: value,
                    ..LsofFileRecord::default()
                });
            }
            b'a' => {
                if let Some(record) = &mut record {
                    record.access = value;
                }
            }
            b't' => {
                if let Some(record) = &mut record {
                    record.kind = value;
                }
            }
            b'D' => {
                if let Some(record) = &mut record {
                    record.device = Some(value);
                }
            }
            b'i' => {
                if let Some(record) = &mut record {
                    record.inode = Some(value);
                }
            }
            b'n' => {
                if let Some(record) = &mut record {
                    record.name = value;
                }
            }
            _ => {}
        }
    }
    flush_lsof_file(
        &process,
        &mut record,
        processes,
        matcher,
        excluded,
        &mut first_text_seen,
        &mut entries,
    );
    (entries, seen_processes)
}

#[cfg(not(target_os = "linux"))]
fn collect_native(
    processes: &HashMap<Pid, ProcessInfo>,
    matcher: &FileMatcher,
) -> NativeCollection {
    let collector = collector_processes(processes);
    let eligible: HashSet<u32> = processes
        .values()
        .filter(|process| process.pid.as_u32() != 0 && !collector.contains(&process.pid))
        .map(|process| process.pid.as_u32())
        .collect();
    let mut command = Command::new("lsof");
    command
        .args(["-nP", "-F0pcuLftanDi"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return NativeCollection {
                entries: Vec::new(),
                eligible_process_count: eligible.len(),
                inspected_process_count: 0,
                collection_complete: false,
                warning: Some(format!("cannot run lsof: {error}")),
            };
        }
    };
    let helper_pid = child.id();
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            return NativeCollection {
                entries: Vec::new(),
                eligible_process_count: eligible.len(),
                inspected_process_count: 0,
                collection_complete: false,
                warning: Some(format!("cannot read lsof output: {error}")),
            };
        }
    };
    let excluded: HashSet<u32> = collector
        .into_iter()
        .map(Pid::as_u32)
        .chain(std::iter::once(helper_pid))
        .collect();
    let (entries, seen) = parse_lsof_output(&output.stdout, processes, matcher, &excluded);
    let inspected_process_count = seen.intersection(&eligible).count();
    let mut warnings = Vec::new();
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        warnings.push(if detail.is_empty() {
            format!("lsof exited with status {}", output.status)
        } else {
            format!("lsof collection was incomplete: {detail}")
        });
    }
    if inspected_process_count < eligible.len() {
        warnings.push(format!(
            "lsof exposed file context for {inspected_process_count} of {} eligible process(es)",
            eligible.len()
        ));
    }
    NativeCollection {
        entries,
        eligible_process_count: eligible.len(),
        inspected_process_count,
        collection_complete: warnings.is_empty(),
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FilePolicyStatus {
    Passed,
    Violated,
    Inconclusive,
}

impl FilePolicyStatus {
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

pub(crate) struct CapturedFileUsage {
    generated_at_unix_ms: u64,
    input_path: String,
    resolved_path: String,
    target_exists: bool,
    target_kind: String,
    target_identity: Option<FileIdentity>,
    recursive: bool,
    result_limit: Option<usize>,
    system_process_count: usize,
    eligible_process_count: usize,
    inspected_process_count: usize,
    collection_complete: bool,
    entries: Vec<FileUsage>,
    process_count: usize,
    warning: Option<String>,
}

impl CapturedFileUsage {
    pub(crate) fn evaluate_policy(&self, expectation: CheckExpectation) -> FilePolicyStatus {
        if !self.entries.is_empty() {
            if expectation.passes(self.entries.len()) {
                FilePolicyStatus::Passed
            } else {
                FilePolicyStatus::Violated
            }
        } else if !self.collection_complete {
            FilePolicyStatus::Inconclusive
        } else if expectation.passes(0) {
            FilePolicyStatus::Passed
        } else {
            FilePolicyStatus::Violated
        }
    }

    fn visible_entries(&self) -> impl Iterator<Item = &FileUsage> {
        self.entries
            .iter()
            .take(self.result_limit.unwrap_or(self.entries.len()))
    }

    fn returned_count(&self) -> usize {
        self.result_limit
            .map(|limit| self.entries.len().min(limit))
            .unwrap_or(self.entries.len())
    }
}

pub(crate) fn capture_file_usage(
    path: &str,
    recursive: bool,
    result_limit: Option<usize>,
) -> Result<CapturedFileUsage, String> {
    let matcher = FileMatcher::new(path, recursive)?;
    let metadata = fs::metadata(&matcher.path).ok();
    let target_kind = match metadata.as_ref() {
        Some(metadata) if metadata.is_dir() => "directory",
        Some(metadata) if metadata.is_file() => "file",
        Some(_) => "other",
        None => "missing",
    };
    let mut provider = NativeProcessProvider::new();
    let processes: HashMap<Pid, ProcessInfo> = provider
        .refresh()
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
    let system_process_count = processes
        .len()
        .saturating_sub(usize::from(processes.contains_key(&Pid::from_u32(0))));
    let mut native = collect_native(&processes, &matcher);
    native.entries.sort_by(|left, right| {
        left.pid
            .cmp(&right.pid)
            .then_with(|| relation_rank(&left.relation).cmp(&relation_rank(&right.relation)))
            .then_with(|| left.descriptor.cmp(&right.descriptor))
            .then_with(|| left.path.cmp(&right.path))
    });
    native
        .entries
        .dedup_by(|left, right| usage_key(left) == usage_key(right));
    let process_count = native
        .entries
        .iter()
        .map(|entry| entry.pid)
        .collect::<HashSet<_>>()
        .len();
    Ok(CapturedFileUsage {
        generated_at_unix_ms: unix_millis(),
        input_path: path.into(),
        resolved_path: matcher.path.to_string_lossy().into_owned(),
        target_exists: metadata.is_some(),
        target_kind: target_kind.into(),
        target_identity: matcher.identity,
        recursive,
        result_limit,
        system_process_count,
        eligible_process_count: native.eligible_process_count,
        inspected_process_count: native.inspected_process_count,
        collection_complete: native.collection_complete,
        entries: native.entries,
        process_count,
        warning: native.warning,
    })
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonTarget<'a> {
    input_path: &'a str,
    resolved_path: &'a str,
    exists: bool,
    kind: &'a str,
    recursive: bool,
    identity: Option<FileIdentity>,
}

#[derive(Debug, Serialize)]
struct JsonCoverage<'a> {
    system_process_count: usize,
    eligible_process_count: usize,
    inspected_process_count: usize,
    collection_complete: bool,
    collector_process_excluded: bool,
    warning: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct JsonPolicy<'a> {
    expectation: &'a str,
    status: &'static str,
    passed: Option<bool>,
    detail: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct JsonFileUsage {
    pid: u32,
    process: String,
    command: String,
    user: String,
    relation: String,
    descriptor: String,
    access: String,
    kind: String,
    path: String,
    kernel_target: String,
    identity: Option<FileIdentity>,
}

impl From<&FileUsage> for JsonFileUsage {
    fn from(usage: &FileUsage) -> Self {
        Self {
            pid: usage.pid,
            process: usage.process.clone(),
            command: command_for_output(&usage.command),
            user: usage.user.clone(),
            relation: usage.relation.clone(),
            descriptor: usage.descriptor.clone(),
            access: usage.access.clone(),
            kind: usage.kind.clone(),
            path: usage.path.clone(),
            kernel_target: usage.kernel_target.clone(),
            identity: usage.identity,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonFileReport<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    secrets_redacted: bool,
    target: JsonTarget<'a>,
    coverage: JsonCoverage<'a>,
    match_count: usize,
    process_count: usize,
    returned_count: usize,
    truncated: bool,
    policy: Option<JsonPolicy<'a>>,
    usages: Vec<JsonFileUsage>,
}

pub(crate) fn render_file_json(
    captured: &CapturedFileUsage,
    expectation: Option<&str>,
    policy_status: Option<FilePolicyStatus>,
) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonFileReport {
        schema: FILE_SCHEMA,
        schema_version: FILE_SCHEMA_VERSION,
        privacy_notice: "Contains host, process, command-line, user, file path, device, and inode information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        secrets_redacted: output_secret_redaction_enabled(),
        target: JsonTarget {
            input_path: &captured.input_path,
            resolved_path: &captured.resolved_path,
            exists: captured.target_exists,
            kind: &captured.target_kind,
            recursive: captured.recursive,
            identity: captured.target_identity,
        },
        coverage: JsonCoverage {
            system_process_count: captured.system_process_count,
            eligible_process_count: captured.eligible_process_count,
            inspected_process_count: captured.inspected_process_count,
            collection_complete: captured.collection_complete,
            collector_process_excluded: true,
            warning: captured.warning.as_deref(),
        },
        match_count: captured.entries.len(),
        process_count: captured.process_count,
        returned_count: captured.returned_count(),
        truncated: captured.returned_count() < captured.entries.len(),
        policy: expectation
            .zip(policy_status)
            .map(|(expectation, status)| JsonPolicy {
                expectation,
                status: status.label(),
                passed: status.passed(),
                detail: (status == FilePolicyStatus::Inconclusive).then_some(
                    "zero visible matches cannot prove absence because process file coverage was incomplete",
                ),
            }),
        usages: captured
            .visible_entries()
            .map(JsonFileUsage::from)
            .collect(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_file_table(
    captured: &CapturedFileUsage,
    expectation: Option<&str>,
    policy_status: Option<FilePolicyStatus>,
) -> String {
    let mut output = String::new();
    if let Some((expectation, status)) = expectation.zip(policy_status) {
        output.push_str(&format!(
            "FILE CHECK {}  expected {}; matched {} evidence row(s)\n",
            match status {
                FilePolicyStatus::Passed => "PASS",
                FilePolicyStatus::Violated => "FAIL",
                FilePolicyStatus::Inconclusive => "INCONCLUSIVE",
            },
            expectation,
            captured.entries.len(),
        ));
    }
    output.push_str(&format!(
        "FILE USAGE  {}  target {} ({}){}\n",
        if captured.collection_complete {
            "complete"
        } else {
            "partial"
        },
        sanitize_terminal_text(&captured.resolved_path),
        captured.target_kind,
        if captured.recursive { " recursive" } else { "" },
    ));
    output.push_str(&format!(
        "matches {} evidence row(s), {} process(es), returned {}{}  coverage {}/{} eligible (system {})\n",
        captured.entries.len(),
        captured.process_count,
        captured.returned_count(),
        if captured.returned_count() < captured.entries.len() {
            " (truncated)"
        } else {
            ""
        },
        captured.inspected_process_count,
        captured.eligible_process_count,
        captured.system_process_count,
    ));
    if captured.entries.is_empty() {
        output.push_str("  [no matching file usage visible]\n");
    } else {
        output.push_str("    PID RELATION FD       ACCESS KIND USER         PROCESS      PATH\n");
        for usage in captured.visible_entries() {
            output.push_str(&format!(
                "{:>7} {:<8} {:<8} {:<6} {:<4} {:<12} {:<12} {}\n",
                usage.pid,
                sanitize_terminal_text(&usage.relation),
                sanitize_terminal_text(&usage.descriptor),
                sanitize_terminal_text(&usage.access),
                sanitize_terminal_text(&usage.kind),
                sanitize_terminal_text(&usage.user),
                sanitize_terminal_text(&usage.process),
                sanitize_terminal_text(&usage.path),
            ));
            output.push_str(&format!(
                "                       command {}\n",
                sanitize_terminal_text(&command_for_output(&usage.command)),
            ));
        }
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

    fn process(pid: u32, executable: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: Some(Pid::from_u32(1)),
            name: "api".into(),
            command: format!("{executable} --token secret\n--serve"),
            executable: executable.into(),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: 0,
            runtime: 0,
            status: "Sleep".into(),
        }
    }

    fn usage(pid: u32, relation: &str, path: &str) -> FileUsage {
        FileUsage {
            pid,
            process: "api".into(),
            command: "/srv/api\n--serve".into(),
            user: "deploy".into(),
            relation: relation.into(),
            descriptor: "3".into(),
            access: "r".into(),
            kind: "REG".into(),
            path: path.into(),
            kernel_target: path.into(),
            identity: None,
        }
    }

    #[test]
    fn path_matching_is_component_aware_and_identity_aware() {
        let matcher = FileMatcher {
            path: PathBuf::from("/srv/data"),
            identity: Some(FileIdentity {
                device: 1,
                inode: 2,
            }),
            recursive: true,
        };
        assert!(matcher.matches("/srv/data/a.log", None));
        assert!(!matcher.matches("/srv/database/a.log", None));
        assert!(matcher.matches(
            "/different/hard-link",
            Some(FileIdentity {
                device: 1,
                inode: 2,
            })
        ));
        let exact = FileMatcher {
            recursive: false,
            ..matcher
        };
        assert!(exact.matches("/srv/data (deleted)", None));
        assert!(!exact.matches("/srv/data/a.log", None));
    }

    #[test]
    fn parses_linux_maps_without_matching_pseudo_mappings() {
        assert_eq!(
            parse_linux_map_line("7f00-7f10 r-xp 00000000 08:01 42 /srv/My  Application/lib.so"),
            Some(("r-xp".into(), "/srv/My  Application/lib.so".into()))
        );
        assert_eq!(
            parse_linux_map_line("7f00-7f10 rw-p 00000000 00:00 0 [heap]"),
            None
        );
        assert_eq!(
            lexical_absolute(Path::new("/../tmp")).unwrap(),
            Path::new("/tmp")
        );
    }

    #[test]
    fn parses_nul_lsof_records_and_classifies_relations() {
        let processes = HashMap::from([(Pid::from_u32(10), process(10, "/srv/api"))]);
        let matcher = FileMatcher {
            path: PathBuf::from("/srv"),
            identity: None,
            recursive: true,
        };
        let input = b"p10\0capi\0Ldeploy\0\nftxt\0tREG\0D0x1\0i2\0n/srv/api\0\nf3\0ar\0tREG\0D0x1\0i3\0n/srv/data.db\0";
        let (entries, seen) = parse_lsof_output(input, &processes, &matcher, &HashSet::new());
        assert_eq!(seen, HashSet::from([10]));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].relation, "EXEC");
        assert_eq!(entries[1].relation, "OPEN");
        assert_eq!(entries[1].path, "/srv/data.db");
    }

    #[test]
    fn incomplete_zero_match_policy_is_inconclusive_and_outputs_are_bounded() {
        let captured = CapturedFileUsage {
            generated_at_unix_ms: 1,
            input_path: "./data".into(),
            resolved_path: "/srv/data".into(),
            target_exists: true,
            target_kind: "directory".into(),
            target_identity: None,
            recursive: true,
            result_limit: Some(1),
            system_process_count: 4,
            eligible_process_count: 3,
            inspected_process_count: 2,
            collection_complete: false,
            entries: Vec::new(),
            process_count: 0,
            warning: Some("one protected process".into()),
        };
        assert_eq!(
            captured.evaluate_policy(CheckExpectation::None),
            FilePolicyStatus::Inconclusive
        );
        let json: Value = serde_json::from_str(
            &render_file_json(
                &captured,
                Some("no matches"),
                Some(FilePolicyStatus::Inconclusive),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(json["schema"], FILE_SCHEMA);
        assert_eq!(json["coverage"]["collection_complete"], false);
        assert_eq!(json["policy"]["passed"], Value::Null);

        let mut bounded = captured;
        bounded.entries = vec![
            usage(20, "OPEN", "/srv/data/a"),
            usage(21, "MAPPED", "/srv/data/b"),
        ];
        bounded.process_count = 2;
        let json: Value =
            serde_json::from_str(&render_file_json(&bounded, None, None).unwrap()).unwrap();
        assert_eq!(json["match_count"], 2);
        assert_eq!(json["returned_count"], 1);
        assert_eq!(json["truncated"], true);
        assert_eq!(json["usages"].as_array().unwrap().len(), 1);
        let table = render_file_table(&bounded, None, None);
        assert!(table.contains("returned 1 (truncated)"));
        assert!(!table.contains("/srv/data/b"));
    }
}
