use std::{
    fmt::Write as _,
    fs::{self, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use serde::Serialize;
use sha2::{Digest, Sha256};
use sysinfo::{Pid, System};

use crate::{
    headless::human_bytes,
    model::{ProcessInfo, process_command_for_output, process_path, sanitize_terminal_text},
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const EXE_SCHEMA: &str = "psmore.executable-image";
const EXE_SCHEMA_VERSION: u32 = 1;
const HASH_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Serialize)]
struct ExeProcess {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    user: String,
    path: String,
    command: String,
    start_time_unix_seconds: u64,
}

impl From<&ProcessInfo> for ExeProcess {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: sanitize_terminal_text(&process.name),
            user: sanitize_terminal_text(&process.user),
            path: sanitize_terminal_text(&process_path(process)),
            command: sanitize_terminal_text(&process_command_for_output(process)),
            start_time_unix_seconds: process.start_time,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct FileEvidence {
    source: &'static str,
    path: String,
    exists: bool,
    deleted: bool,
    readable: bool,
    size_bytes: Option<u64>,
    device: Option<u64>,
    inode: Option<u64>,
    mode_octal: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    modified_unix_seconds: Option<u64>,
    sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ImageComparison {
    status: &'static str,
    attention_required: bool,
    mapped_identity_available: bool,
    same_device_inode: Option<bool>,
    same_sha256: Option<bool>,
    explanation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PackageEvidence {
    pub(crate) manager: &'static str,
    pub(crate) name: String,
    pub(crate) version: Option<String>,
    pub(crate) architecture: Option<String>,
    pub(crate) evidence: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct SigningEvidence {
    signed: bool,
    valid: bool,
    identifier: Option<String>,
    team_identifier: Option<String>,
    authorities: Vec<String>,
    format: Option<String>,
    flags: Option<String>,
    diagnostic: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CollectionEvidence {
    complete: bool,
    sources: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct CapturedExecutable {
    generated_at_unix_ms: u64,
    hostname: Option<String>,
    identity_status: IdentityStatus,
    identity_warning: Option<String>,
    process: ExeProcess,
    running: FileEvidence,
    disk: Option<FileEvidence>,
    comparison: ImageComparison,
    package: Option<PackageEvidence>,
    signing: Option<SigningEvidence>,
    collection: CollectionEvidence,
    hashing_enabled: bool,
}

#[derive(Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct JsonExecutableReport<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<&'a str>,
    process_identity: &'static str,
    process_identity_warning: Option<&'a str>,
    hashing_enabled: bool,
    hash_limit_bytes: u64,
    process: &'a ExeProcess,
    running_image: &'a FileEvidence,
    disk_image: Option<&'a FileEvidence>,
    comparison: &'a ImageComparison,
    package: Option<&'a PackageEvidence>,
    signing: Option<&'a SigningEvidence>,
    collection: &'a CollectionEvidence,
}

pub(crate) fn capture_executable(pid: u32, hash: bool) -> Result<CapturedExecutable, String> {
    if pid == 0 {
        return Err("PID 0 is a virtual root and has no executable image".into());
    }
    let pid = Pid::from_u32(pid);
    let mut provider = NativeProcessProvider::new();
    let processes = provider.refresh();
    let process = processes
        .iter()
        .find(|process| process.pid == pid)
        .cloned()
        .ok_or_else(|| format!("PID {pid} was not found"))?;

    let mut warnings = Vec::new();
    let mut sources = vec![format!("process snapshot for PID {}", pid.as_u32())];
    let (running_path, running_display, running_deleted, mapped_identity_available) =
        running_image_path(&process, &mut warnings, &mut sources);
    let mut running = collect_file_evidence(
        "running_process_image",
        &running_path,
        &running_display,
        running_deleted,
        hash,
        &mut warnings,
    );

    let disk_path = disk_image_path(&process, &running_display);
    let mut disk = disk_path.as_ref().map(|path| {
        collect_file_evidence(
            "current_disk_path",
            path,
            &path.to_string_lossy(),
            false,
            false,
            &mut warnings,
        )
    });
    if let Some(disk) = &mut disk {
        if hash && disk.exists {
            if same_file_identity(&running, disk) == Some(true) {
                disk.sha256.clone_from(&running.sha256);
            } else if let Some(path) = disk_path.as_deref() {
                collect_hash_for_evidence(disk, path, &mut warnings);
            }
        }
    }

    let comparison = compare_images(&running, disk.as_ref(), mapped_identity_available);
    let package = disk_path
        .as_deref()
        .and_then(|path| collect_package(path, &mut sources, &mut warnings));
    let signing = disk
        .as_ref()
        .filter(|file| file.exists)
        .and_then(|file| collect_signing(Path::new(&file.path), &mut sources));

    let after = provider.refresh();
    let (identity_status, identity_warning) = verify_instance(
        &process,
        after.iter().find(|candidate| candidate.pid == pid),
    )?;
    if let Some(warning) = identity_warning.as_ref() {
        warnings.push(warning.clone());
    }

    let complete = running.exists
        && !matches!(identity_status, IdentityStatus::ExitedDuringCollection)
        && !matches!(comparison.status, "unverified")
        && (!cfg!(target_os = "linux") || mapped_identity_available);
    if running.path.is_empty() {
        running.path = "[path unavailable]".into();
    }
    Ok(CapturedExecutable {
        generated_at_unix_ms: unix_millis(),
        hostname: System::host_name().map(|value| sanitize_terminal_text(&value)),
        identity_status,
        identity_warning,
        process: ExeProcess::from(&process),
        running,
        disk,
        comparison,
        package,
        signing,
        collection: CollectionEvidence {
            complete,
            sources,
            warnings,
        },
        hashing_enabled: hash,
    })
}

fn verify_instance(
    before: &ProcessInfo,
    after: Option<&ProcessInfo>,
) -> Result<(IdentityStatus, Option<String>), String> {
    let Some(after) = after else {
        return Ok((
            IdentityStatus::ExitedDuringCollection,
            Some(format!(
                "PID {} exited while executable evidence was being collected",
                before.pid
            )),
        ));
    };
    if before.start_time > 0 && after.start_time > 0 {
        if before.start_time != after.start_time {
            return Err(format!(
                "PID {} was reused during executable inspection; refusing to combine different process instances",
                before.pid
            ));
        }
        return Ok((IdentityStatus::Verified, None));
    }
    if before.name != after.name
        || process_command_for_output(before) != process_command_for_output(after)
    {
        return Err(format!(
            "PID {} changed identity while executable evidence was being collected",
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

#[cfg(target_os = "linux")]
fn running_image_path(
    process: &ProcessInfo,
    warnings: &mut Vec<String>,
    sources: &mut Vec<String>,
) -> (PathBuf, String, bool, bool) {
    let proc_path = PathBuf::from(format!("/proc/{}/exe", process.pid.as_u32()));
    sources.push(proc_path.display().to_string());
    match fs::read_link(&proc_path) {
        Ok(target) => {
            let display = target.to_string_lossy().to_string();
            let deleted = display.ends_with(" (deleted)");
            (proc_path, display, deleted, true)
        }
        Err(error) => {
            warnings.push(format!(
                "cannot resolve {}: {error}; falling back to the process snapshot path",
                proc_path.display()
            ));
            let display = process_path(process);
            (PathBuf::from(&display), display, false, false)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn running_image_path(
    process: &ProcessInfo,
    _warnings: &mut Vec<String>,
    sources: &mut Vec<String>,
) -> (PathBuf, String, bool, bool) {
    let display = process_path(process);
    sources.push("process snapshot executable path".into());
    (PathBuf::from(&display), display, false, false)
}

fn disk_image_path(process: &ProcessInfo, running_display: &str) -> Option<PathBuf> {
    let from_running = running_display
        .strip_suffix(" (deleted)")
        .unwrap_or(running_display)
        .trim();
    if from_running.starts_with('/') {
        return Some(PathBuf::from(from_running));
    }
    let from_snapshot = process_path(process);
    from_snapshot
        .starts_with('/')
        .then(|| PathBuf::from(from_snapshot))
}

fn collect_file_evidence(
    source: &'static str,
    access_path: &Path,
    display_path: &str,
    deleted: bool,
    hash: bool,
    warnings: &mut Vec<String>,
) -> FileEvidence {
    let mut evidence = FileEvidence {
        source,
        path: sanitize_terminal_text(display_path),
        deleted,
        ..FileEvidence::default()
    };
    let metadata = match fs::metadata(access_path) {
        Ok(metadata) => metadata,
        Err(error) => {
            if source != "current_disk_path" || error.kind() != std::io::ErrorKind::NotFound {
                warnings.push(format!(
                    "cannot read metadata for {}: {error}",
                    sanitize_terminal_text(display_path)
                ));
            }
            return evidence;
        }
    };
    evidence.exists = true;
    evidence.size_bytes = Some(metadata.len());
    evidence.modified_unix_seconds = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_secs());
    apply_unix_metadata(&mut evidence, &metadata);
    if hash {
        collect_hash_for_evidence(&mut evidence, access_path, warnings);
    } else {
        evidence.readable = File::open(access_path).is_ok();
    }
    evidence
}

fn collect_hash_for_evidence(
    evidence: &mut FileEvidence,
    access_path: &Path,
    warnings: &mut Vec<String>,
) {
    let size = evidence.size_bytes.unwrap_or_default();
    if size > HASH_LIMIT_BYTES {
        warnings.push(format!(
            "skipped SHA-256 for {} because {} exceeds the {} safety limit",
            evidence.path,
            human_bytes(size),
            human_bytes(HASH_LIMIT_BYTES)
        ));
        evidence.readable = File::open(access_path).is_ok();
        return;
    }
    match hash_file(access_path) {
        Ok(digest) => {
            evidence.readable = true;
            evidence.sha256 = Some(digest);
        }
        Err(error) => warnings.push(format!("cannot hash {}: {error}", evidence.path)),
    }
}

#[cfg(unix)]
fn apply_unix_metadata(evidence: &mut FileEvidence, metadata: &fs::Metadata) {
    evidence.device = Some(metadata.dev());
    evidence.inode = Some(metadata.ino());
    evidence.mode_octal = Some(format!("{:04o}", metadata.mode() & 0o7777));
    evidence.uid = Some(metadata.uid());
    evidence.gid = Some(metadata.gid());
}

#[cfg(not(unix))]
fn apply_unix_metadata(_evidence: &mut FileEvidence, _metadata: &fs::Metadata) {}

fn hash_file(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn same_file_identity(left: &FileEvidence, right: &FileEvidence) -> Option<bool> {
    Some(left.device? == right.device? && left.inode? == right.inode?)
}

fn same_hash(left: &FileEvidence, right: &FileEvidence) -> Option<bool> {
    Some(left.sha256.as_ref()? == right.sha256.as_ref()?)
}

fn compare_images(
    running: &FileEvidence,
    disk: Option<&FileEvidence>,
    mapped_identity_available: bool,
) -> ImageComparison {
    let same_device_inode = disk.and_then(|disk| same_file_identity(running, disk));
    let same_sha256 = disk.and_then(|disk| same_hash(running, disk));
    if running.deleted {
        if disk.is_some_and(|disk| disk.exists) && same_device_inode == Some(false) {
            return ImageComparison {
                status: "replaced_on_disk",
                attention_required: true,
                mapped_identity_available,
                same_device_inode,
                same_sha256,
                explanation: "the process holds an unlinked old executable while the original path now points to a different file",
            };
        }
        return ImageComparison {
            status: "running_image_deleted",
            attention_required: true,
            mapped_identity_available,
            same_device_inode,
            same_sha256,
            explanation: "the process still holds an executable that has been unlinked from its original path",
        };
    }
    let Some(disk) = disk else {
        return ImageComparison {
            status: "disk_path_unavailable",
            attention_required: true,
            mapped_identity_available,
            same_device_inode,
            same_sha256,
            explanation: "no absolute current disk path was available for comparison",
        };
    };
    if !disk.exists {
        return ImageComparison {
            status: "disk_image_missing",
            attention_required: true,
            mapped_identity_available,
            same_device_inode,
            same_sha256,
            explanation: "the process executable path no longer exists on disk",
        };
    }
    if mapped_identity_available {
        return match same_device_inode.or(same_sha256) {
            Some(true) => ImageComparison {
                status: "same_image",
                attention_required: false,
                mapped_identity_available,
                same_device_inode,
                same_sha256,
                explanation: "the running image and current disk path identify the same file",
            },
            Some(false) => ImageComparison {
                status: "replaced_on_disk",
                attention_required: true,
                mapped_identity_available,
                same_device_inode,
                same_sha256,
                explanation: "the path now points to a different file than the executable held by the process",
            },
            None => ImageComparison {
                status: "unverified",
                attention_required: true,
                mapped_identity_available,
                same_device_inode,
                same_sha256,
                explanation: "the running and disk images could not be compared by file identity or hash",
            },
        };
    }
    ImageComparison {
        status: "current_path_only",
        attention_required: false,
        mapped_identity_available,
        same_device_inode,
        same_sha256,
        explanation: "this platform exposes the current executable path but not an independent mapped-image file identity",
    }
}

#[cfg(target_os = "linux")]
fn collect_package(
    path: &Path,
    sources: &mut Vec<String>,
    _warnings: &mut [String],
) -> Option<PackageEvidence> {
    let path = path.to_str()?;
    if let Some(package) = query_dpkg(path) {
        sources.push("dpkg-query package ownership".into());
        return Some(package);
    }
    if let Some(package) = query_rpm(path) {
        sources.push("rpm package ownership".into());
        return Some(package);
    }
    if let Some(package) = query_apk(path) {
        sources.push("apk package ownership".into());
        return Some(package);
    }
    None
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn detect_package(path: &Path) -> Option<PackageEvidence> {
    let mut sources = Vec::new();
    let mut warnings = Vec::new();
    collect_package(path, &mut sources, &mut warnings)
}

#[cfg(target_os = "macos")]
fn collect_package(
    path: &Path,
    sources: &mut Vec<String>,
    _warnings: &mut [String],
) -> Option<PackageEvidence> {
    if let Some(package) = homebrew_package(path) {
        sources.push("Homebrew Cellar path".into());
        return Some(package);
    }
    if let Some(package) = app_bundle_package(path) {
        sources.push("application bundle Info.plist".into());
        return Some(package);
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn collect_package(
    _path: &Path,
    _sources: &mut [String],
    _warnings: &mut [String],
) -> Option<PackageEvidence> {
    None
}

#[cfg(target_os = "linux")]
fn query_dpkg(path: &str) -> Option<PackageEvidence> {
    let (queried_path, output) = dpkg_path_candidates(path)
        .into_iter()
        .find_map(|candidate| {
            let output = Command::new("dpkg-query")
                .args(["-S", &candidate])
                .output()
                .ok()?;
            output.status.success().then_some((candidate, output))
        })?;
    let ownership = String::from_utf8_lossy(&output.stdout);
    let ownership_line = ownership.lines().next()?;
    let package = ownership_line.split_once(": ")?.0.trim();
    let details = Command::new("dpkg-query")
        .args([
            "-W",
            "-f=${Package}\t${Version}\t${Architecture}\n",
            package,
        ])
        .output()
        .ok()?;
    if !details.status.success() {
        return None;
    }
    let fields = String::from_utf8_lossy(&details.stdout);
    let mut fields = fields.trim().split('\t');
    let name = fields.next().unwrap_or(package).trim();
    Some(PackageEvidence {
        manager: "dpkg",
        name: sanitize_terminal_text(name),
        version: optional_text(fields.next()),
        architecture: optional_text(fields.next()),
        evidence: sanitize_terminal_text(&format!("{ownership_line} (queried {queried_path})")),
    })
}

#[cfg(any(target_os = "linux", test))]
fn dpkg_path_candidates(path: &str) -> Vec<String> {
    let mut candidates = vec![path.to_string()];
    for (modern, legacy) in [
        ("/usr/bin/", "/bin/"),
        ("/usr/sbin/", "/sbin/"),
        ("/usr/lib/", "/lib/"),
        ("/usr/lib32/", "/lib32/"),
        ("/usr/lib64/", "/lib64/"),
    ] {
        if let Some(suffix) = path.strip_prefix(modern) {
            candidates.push(format!("{legacy}{suffix}"));
        } else if let Some(suffix) = path.strip_prefix(legacy) {
            candidates.push(format!("{modern}{suffix}"));
        }
    }
    candidates
}

#[cfg(target_os = "linux")]
fn query_rpm(path: &str) -> Option<PackageEvidence> {
    let output = Command::new("rpm")
        .args([
            "-qf",
            "--qf",
            "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
            path,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout);
    let mut fields = value.trim().split('\t');
    Some(PackageEvidence {
        manager: "rpm",
        name: sanitize_terminal_text(fields.next()?),
        version: optional_text(fields.next()),
        architecture: optional_text(fields.next()),
        evidence: sanitize_terminal_text(value.trim()),
    })
}

#[cfg(target_os = "linux")]
fn query_apk(path: &str) -> Option<PackageEvidence> {
    let output = Command::new("apk")
        .args(["info", "--who-owns", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout);
    let line = value.lines().next()?.trim();
    let package = line.split_whitespace().next()?;
    Some(PackageEvidence {
        manager: "apk",
        name: sanitize_terminal_text(package),
        version: None,
        architecture: None,
        evidence: sanitize_terminal_text(line),
    })
}

#[cfg(target_os = "linux")]
fn optional_text(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(sanitize_terminal_text)
}

#[cfg(target_os = "macos")]
fn homebrew_package(path: &Path) -> Option<PackageEvidence> {
    let components: Vec<String> = path
        .components()
        .map(|value| value.as_os_str().to_string_lossy().to_string())
        .collect();
    let index = components.iter().position(|value| value == "Cellar")?;
    let name = components.get(index + 1)?.clone();
    let version = components.get(index + 2).cloned();
    Some(PackageEvidence {
        manager: "homebrew",
        name,
        version,
        architecture: Some(std::env::consts::ARCH.into()),
        evidence: sanitize_terminal_text(&path.to_string_lossy()),
    })
}

#[cfg(target_os = "macos")]
fn app_bundle_package(path: &Path) -> Option<PackageEvidence> {
    let mut bundle = PathBuf::new();
    let mut found = None;
    for component in path.components() {
        bundle.push(component.as_os_str());
        if component.as_os_str().to_string_lossy().ends_with(".app") {
            found = Some(bundle.clone());
        }
    }
    let bundle = found?;
    let plist = bundle.join("Contents/Info.plist");
    let name = plist_value(&plist, "CFBundleIdentifier").or_else(|| {
        bundle
            .file_stem()
            .map(|value| value.to_string_lossy().to_string())
    })?;
    Some(PackageEvidence {
        manager: "app_bundle",
        name,
        version: plist_value(&plist, "CFBundleShortVersionString")
            .or_else(|| plist_value(&plist, "CFBundleVersion")),
        architecture: Some(std::env::consts::ARCH.into()),
        evidence: sanitize_terminal_text(&bundle.to_string_lossy()),
    })
}

#[cfg(target_os = "macos")]
fn plist_value(plist: &Path, key: &str) -> Option<String> {
    let output = Command::new("/usr/libexec/PlistBuddy")
        .args(["-c", &format!("Print :{key}"), plist.to_str()?])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| sanitize_terminal_text(String::from_utf8_lossy(&output.stdout).trim()))
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "macos")]
fn collect_signing(path: &Path, sources: &mut Vec<String>) -> Option<SigningEvidence> {
    let path = path.to_str()?;
    let details = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4", "--", path])
        .output()
        .ok()?;
    let detail_text = combined_output(&details);
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2", "--", path])
        .output()
        .ok()?;
    let signed = details.status.success();
    sources.push("codesign display and strict verification".into());
    Some(SigningEvidence {
        signed,
        valid: signed && verify.status.success(),
        identifier: parse_prefixed(&detail_text, "Identifier="),
        team_identifier: parse_prefixed(&detail_text, "TeamIdentifier=")
            .filter(|value| value != "not set"),
        authorities: detail_text
            .lines()
            .filter_map(|line| line.strip_prefix("Authority="))
            .map(sanitize_terminal_text)
            .collect(),
        format: parse_prefixed(&detail_text, "Format="),
        flags: parse_prefixed(&detail_text, "CodeDirectory v=").and_then(|value| {
            value
                .split_whitespace()
                .find(|part| part.starts_with("flags="))
                .map(sanitize_terminal_text)
        }),
        diagnostic: (!verify.status.success())
            .then(|| sanitize_terminal_text(&combined_output(&verify)))
            .filter(|value| !value.is_empty()),
    })
}

#[cfg(not(target_os = "macos"))]
fn collect_signing(_path: &Path, _sources: &mut [String]) -> Option<SigningEvidence> {
    None
}

#[cfg(target_os = "macos")]
fn combined_output(output: &std::process::Output) -> String {
    let mut value = String::from_utf8_lossy(&output.stderr).to_string();
    value.push_str(&String::from_utf8_lossy(&output.stdout));
    value
}

#[cfg(any(target_os = "macos", test))]
fn parse_prefixed(text: &str, prefix: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.trim().strip_prefix(prefix))
        .map(sanitize_terminal_text)
        .filter(|value| !value.is_empty())
}

pub(crate) fn render_executable_json(captured: &CapturedExecutable) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonExecutableReport {
        schema: EXE_SCHEMA,
        schema_version: EXE_SCHEMA_VERSION,
        privacy_notice: "Contains host, process command, executable path, file ownership, hashes, package, and signing information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: captured.hostname.as_deref(),
        process_identity: captured.identity_status.label(),
        process_identity_warning: captured.identity_warning.as_deref(),
        hashing_enabled: captured.hashing_enabled,
        hash_limit_bytes: HASH_LIMIT_BYTES,
        process: &captured.process,
        running_image: &captured.running,
        disk_image: captured.disk.as_ref(),
        comparison: &captured.comparison,
        package: captured.package.as_ref(),
        signing: captured.signing.as_ref(),
        collection: &captured.collection,
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_executable_table(captured: &CapturedExecutable) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "PSMORE EXECUTABLE IMAGE");
    let _ = writeln!(
        output,
        "process {} [{}]  user {}  identity {}",
        captured.process.name,
        captured.process.pid,
        captured.process.user,
        captured.identity_status.label()
    );
    let _ = writeln!(output, "command {}", captured.process.command);
    let _ = writeln!(
        output,
        "status {}  attention {}",
        captured.comparison.status,
        if captured.comparison.attention_required {
            "yes"
        } else {
            "no"
        }
    );
    let _ = writeln!(output, "reason {}", captured.comparison.explanation);
    write_file_table(&mut output, "running", &captured.running);
    if let Some(disk) = captured.disk.as_ref() {
        write_file_table(&mut output, "disk", disk);
    }
    if let Some(package) = captured.package.as_ref() {
        let _ = writeln!(
            output,
            "package {} {}{}{}",
            package.manager,
            package.name,
            package
                .version
                .as_deref()
                .map(|value| format!(" {value}"))
                .unwrap_or_default(),
            package
                .architecture
                .as_deref()
                .map(|value| format!(" ({value})"))
                .unwrap_or_default()
        );
        let _ = writeln!(output, "package evidence {}", package.evidence);
    } else {
        let _ = writeln!(output, "package not identified");
    }
    if let Some(signing) = captured.signing.as_ref() {
        let _ = writeln!(
            output,
            "signing signed {}  valid {}  identifier {}  team {}",
            yes_no(signing.signed),
            yes_no(signing.valid),
            signing.identifier.as_deref().unwrap_or("-"),
            signing.team_identifier.as_deref().unwrap_or("-")
        );
        if !signing.authorities.is_empty() {
            let _ = writeln!(output, "authority {}", signing.authorities.join(" -> "));
        }
        if let Some(diagnostic) = signing.diagnostic.as_deref() {
            let _ = writeln!(output, "signing diagnostic {diagnostic}");
        }
    }
    let _ = writeln!(
        output,
        "coverage {}  sources {}  warnings {}",
        if captured.collection.complete {
            "complete"
        } else {
            "partial"
        },
        captured.collection.sources.len(),
        captured.collection.warnings.len()
    );
    for warning in &captured.collection.warnings {
        let _ = writeln!(output, "warning {warning}");
    }
    output
}

fn write_file_table(output: &mut String, label: &str, file: &FileEvidence) {
    let _ = writeln!(
        output,
        "{label} {}  exists {}  deleted {}  readable {}",
        file.path,
        yes_no(file.exists),
        yes_no(file.deleted),
        yes_no(file.readable)
    );
    if file.exists {
        let _ = writeln!(
            output,
            "{label} file {}  dev:inode {}:{}  mode {}  uid:gid {}:{}",
            file.size_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "?".into()),
            optional_number(file.device),
            optional_number(file.inode),
            file.mode_octal.as_deref().unwrap_or("?"),
            optional_number(file.uid),
            optional_number(file.gid)
        );
    }
    let _ = writeln!(
        output,
        "{label} sha256 {}",
        file.sha256.as_deref().unwrap_or(if file.exists {
            "not collected"
        } else {
            "unavailable"
        })
    );
}

fn optional_number<T: ToString>(value: Option<T>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".into())
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
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

    fn file(device: u64, inode: u64, hash: Option<&str>) -> FileEvidence {
        FileEvidence {
            source: "test",
            path: "/tmp/app".into(),
            exists: true,
            readable: true,
            device: Some(device),
            inode: Some(inode),
            sha256: hash.map(str::to_string),
            ..FileEvidence::default()
        }
    }

    #[test]
    fn comparison_distinguishes_same_replaced_deleted_and_path_only() {
        let running = file(1, 2, Some("abc"));
        let disk = file(1, 2, Some("abc"));
        assert_eq!(
            compare_images(&running, Some(&disk), true).status,
            "same_image"
        );

        let replaced = file(1, 3, Some("def"));
        let result = compare_images(&running, Some(&replaced), true);
        assert_eq!(result.status, "replaced_on_disk");
        assert!(result.attention_required);

        let mut deleted = running.clone();
        deleted.deleted = true;
        assert_eq!(
            compare_images(&deleted, Some(&replaced), true).status,
            "replaced_on_disk"
        );
        assert_eq!(
            compare_images(&deleted, None, true).status,
            "running_image_deleted"
        );
        assert_eq!(
            compare_images(&running, Some(&disk), false).status,
            "current_path_only"
        );
    }

    #[test]
    fn parses_codesign_fields_without_copying_unrelated_output() {
        let text = "Executable=/tmp/app\nIdentifier=com.example.app\nFormat=Mach-O thin\nAuthority=Developer ID Application: Example\nTeamIdentifier=TEAM123\n";
        assert_eq!(
            parse_prefixed(text, "Identifier=").as_deref(),
            Some("com.example.app")
        );
        assert_eq!(
            parse_prefixed(text, "TeamIdentifier=").as_deref(),
            Some("TEAM123")
        );
        assert_eq!(parse_prefixed(text, "Unknown="), None);
    }

    #[test]
    fn dpkg_candidates_cover_usrmerge_aliases_without_changing_other_paths() {
        assert_eq!(
            dpkg_path_candidates("/usr/bin/bash"),
            vec!["/usr/bin/bash", "/bin/bash"]
        );
        assert_eq!(
            dpkg_path_candidates("/sbin/init"),
            vec!["/sbin/init", "/usr/sbin/init"]
        );
        assert_eq!(
            dpkg_path_candidates("/opt/app/bin/api"),
            vec!["/opt/app/bin/api"]
        );
    }

    #[test]
    fn json_contract_preserves_comparison_and_collection_semantics() {
        let running = file(1, 2, Some("abc"));
        let disk = file(1, 3, Some("def"));
        let captured = CapturedExecutable {
            generated_at_unix_ms: 1,
            hostname: Some("host".into()),
            identity_status: IdentityStatus::Verified,
            identity_warning: None,
            process: ExeProcess {
                pid: 42,
                parent_pid: Some(1),
                name: "api".into(),
                user: "deploy".into(),
                path: "/tmp/app".into(),
                command: "/tmp/app --serve".into(),
                start_time_unix_seconds: 1,
            },
            comparison: compare_images(&running, Some(&disk), true),
            running,
            disk: Some(disk),
            package: None,
            signing: None,
            collection: CollectionEvidence {
                complete: true,
                sources: vec!["test".into()],
                warnings: Vec::new(),
            },
            hashing_enabled: true,
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_executable_json(&captured).unwrap()).unwrap();
        assert_eq!(value["schema"], EXE_SCHEMA);
        assert_eq!(value["schema_version"], EXE_SCHEMA_VERSION);
        assert_eq!(value["process_identity"], "verified");
        assert_eq!(value["comparison"]["status"], "replaced_on_disk");
        assert_eq!(value["collection"]["complete"], true);
    }
}
