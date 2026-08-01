#[cfg(not(target_os = "linux"))]
use std::process::Command;

#[cfg(target_os = "macos")]
use std::{ffi::c_void, mem::MaybeUninit};

#[cfg(target_os = "linux")]
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::FileTypeExt,
    path::Path,
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use sysinfo::Pid;

#[cfg(target_os = "linux")]
use crate::model::InspectionField;
#[cfg(not(target_os = "linux"))]
use crate::model::LsofFileRecord;
use crate::model::{OpenFileInfo, ProcessInfo, ProcessInspection, SocketInfo, ThreadInfo};

const MAX_THREAD_ROWS: usize = 50;

#[cfg(target_os = "macos")]
const PROC_PIDTHREADINFO: i32 = 5;
#[cfg(target_os = "macos")]
const PROC_PIDLISTTHREADS: i32 = 6;
#[cfg(target_os = "macos")]
const MAXTHREADNAMESIZE: usize = 64;

#[cfg(target_os = "macos")]
#[repr(C)]
struct MacProcThreadInfo {
    user_time: u64,
    system_time: u64,
    cpu_usage: i32,
    policy: i32,
    run_state: i32,
    flags: i32,
    sleep_time: i32,
    current_priority: i32,
    priority: i32,
    max_priority: i32,
    name: [i8; MAXTHREADNAMESIZE],
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn proc_pidinfo(pid: i32, flavor: i32, arg: u64, buffer: *mut c_void, buffer_size: i32) -> i32;
}

#[cfg(target_os = "macos")]
fn mac_thread_state(state: i32) -> &'static str {
    match state {
        1 => "Running",
        2 => "Stopped",
        3 => "Waiting",
        4 => "Uninterruptible",
        5 => "Halted",
        _ => "Unknown",
    }
}

#[cfg(target_os = "macos")]
fn mac_thread_name(raw: &[i8; MAXTHREADNAMESIZE]) -> String {
    let length = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
    let bytes: Vec<u8> = raw[..length].iter().map(|byte| *byte as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(target_os = "macos")]
fn mac_thread_ids(pid: i32) -> Result<Vec<u64>, String> {
    let mut capacity = 64_usize;
    loop {
        let mut ids = vec![0_u64; capacity];
        let buffer_size = ids
            .len()
            .checked_mul(std::mem::size_of::<u64>())
            .and_then(|size| i32::try_from(size).ok())
            .ok_or_else(|| "thread list is too large".to_string())?;
        // SAFETY: `ids` is a writable buffer of exactly `buffer_size` bytes,
        // and libproc only writes thread IDs for the requested live PID.
        let bytes = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDLISTTHREADS,
                0,
                ids.as_mut_ptr().cast(),
                buffer_size,
            )
        };
        if bytes <= 0 {
            return Err(format!(
                "cannot list macOS threads: {}",
                std::io::Error::last_os_error()
            ));
        }
        let count = bytes as usize / std::mem::size_of::<u64>();
        if count < capacity || capacity >= 65_536 {
            ids.truncate(count.min(capacity));
            ids.retain(|thread_id| *thread_id != 0);
            ids.sort_unstable();
            ids.dedup();
            return Ok(ids);
        }
        capacity = capacity.saturating_mul(2);
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_threads(pid: i32) -> Result<(Vec<ThreadInfo>, usize, Option<String>), String> {
    let ids = mac_thread_ids(pid)?;
    let thread_count = ids.len();
    let mut unreadable = 0_usize;
    let mut last_failure = None;
    let mut threads = Vec::with_capacity(thread_count.min(MAX_THREAD_ROWS));
    for thread_id in ids {
        let mut raw = MaybeUninit::<MacProcThreadInfo>::uninit();
        let expected = i32::try_from(std::mem::size_of::<MacProcThreadInfo>())
            .map_err(|_| "macOS thread structure size overflow".to_string())?;
        // SAFETY: `raw` points to an uninitialized buffer with the exact C
        // struct layout and size required by PROC_PIDTHREADINFO. The value
        // is read only after libproc reports a complete structure.
        let bytes = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTHREADINFO,
                thread_id,
                raw.as_mut_ptr().cast(),
                expected,
            )
        };
        if bytes != expected {
            unreadable += 1;
            last_failure = Some(format!(
                "returned {bytes}/{expected} bytes ({})",
                std::io::Error::last_os_error()
            ));
            continue;
        }
        // SAFETY: the successful call above initialized every byte of `raw`.
        let raw = unsafe { raw.assume_init() };
        threads.push(ThreadInfo {
            id: thread_id,
            name: mac_thread_name(&raw.name),
            state: mac_thread_state(raw.run_state).into(),
            // libproc uses TH_USAGE_SCALE=1000, where 1000 means one CPU.
            cpu_percent: (raw.cpu_usage.max(0) as f32 / 10.0).min(100.0),
            priority: raw.current_priority,
            nice: None,
            processor: None,
        });
    }
    threads.sort_by(|left, right| {
        right
            .cpu_percent
            .total_cmp(&left.cpu_percent)
            .then_with(|| left.id.cmp(&right.id))
    });
    threads.truncate(MAX_THREAD_ROWS);
    let warning = (unreadable > 0).then(|| {
        let detail = last_failure
            .map(|failure| format!("; last failure {failure}"))
            .unwrap_or_default();
        format!("{unreadable} macOS threads exited or became unreadable during collection{detail}")
    });
    Ok((threads, thread_count, warning))
}

#[cfg(target_os = "macos")]
fn attach_macos_threads(inspection: &mut ProcessInspection) {
    match collect_macos_threads(inspection.pid.as_u32() as i32) {
        Ok((threads, thread_count, warning)) => {
            inspection.threads = threads;
            inspection.thread_count = thread_count;
            inspection.thread_truncated = thread_count > MAX_THREAD_ROWS;
            inspection.thread_warning = warning;
        }
        Err(error) => inspection.thread_warning = Some(error),
    }
}

#[cfg(not(target_os = "linux"))]
fn flush_lsof_record(record: &mut Option<LsofFileRecord>, inspection: &mut ProcessInspection) {
    let Some(record) = record.take() else {
        return;
    };
    if record.fd == "cwd" {
        if !record.name.is_empty() {
            inspection.cwd = record.name;
        }
        return;
    }
    if record.protocol == "TCP"
        || record.protocol == "UDP"
        || record.kind == "IPv4"
        || record.kind == "IPv6"
        || record.kind.eq_ignore_ascii_case("unix")
    {
        inspection.sockets.push(SocketInfo {
            fd: record.fd,
            protocol: if record.protocol.is_empty() {
                if record.kind.eq_ignore_ascii_case("unix") {
                    "UNIX".into()
                } else {
                    record.kind
                }
            } else {
                record.protocol
            },
            endpoint: record.name,
            state: record.state,
        });
    } else if record
        .fd
        .chars()
        .next()
        .map(|ch| ch.is_ascii_digit())
        .unwrap_or(false)
    {
        inspection.files.push(OpenFileInfo {
            fd: record.fd,
            kind: record.kind,
            access: record.access,
            name: record.name,
        });
    }
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn parse_lsof_output(output: &[u8], process: &ProcessInfo) -> ProcessInspection {
    let mut inspection = ProcessInspection {
        pid: process.pid,
        name: process.name.clone(),
        user: process.user.clone(),
        cwd: process.cwd.clone(),
        ..ProcessInspection::default()
    };
    let mut record: Option<LsofFileRecord> = None;
    let mut numeric_user = None;
    for line in String::from_utf8_lossy(output).lines() {
        let Some((field, value)) = line.split_at_checked(1) else {
            continue;
        };
        match field {
            "L" if !value.is_empty() => inspection.user = value.to_string(),
            "u" if !value.is_empty() => numeric_user = Some(value.to_string()),
            "f" => {
                flush_lsof_record(&mut record, &mut inspection);
                record = Some(LsofFileRecord {
                    fd: value.to_string(),
                    ..LsofFileRecord::default()
                });
            }
            "a" => {
                if let Some(record) = &mut record {
                    record.access = value.trim().to_string();
                }
            }
            "t" => {
                if let Some(record) = &mut record {
                    record.kind = value.to_string();
                }
            }
            "n" => {
                if let Some(record) = &mut record {
                    record.name = value.to_string();
                }
            }
            "P" => {
                if let Some(record) = &mut record {
                    record.protocol = value.to_string();
                }
            }
            "T" if value.starts_with("ST=") => {
                if let Some(record) = &mut record {
                    record.state = value[3..].to_string();
                }
            }
            _ => {}
        }
    }
    flush_lsof_record(&mut record, &mut inspection);
    if inspection.user.is_empty() {
        inspection.user = numeric_user.unwrap_or_else(|| "[unavailable]".into());
    }
    if inspection.cwd.is_empty() {
        inspection.cwd = "[unavailable]".into();
    }
    inspection.sockets.sort_by(|left, right| {
        (&left.protocol, &left.endpoint).cmp(&(&right.protocol, &right.endpoint))
    });
    inspection
        .files
        .sort_by(|left, right| (&left.fd, &left.name).cmp(&(&right.fd, &right.name)));
    inspection
}

#[cfg(not(target_os = "linux"))]
fn inspect_process_lsof(process: &ProcessInfo) -> ProcessInspection {
    let output = Command::new("lsof")
        .args([
            "-nP",
            "-w",
            "-a",
            "-p",
            &process.pid.to_string(),
            "-d",
            "cwd,0-9999",
            "-F",
            "pcuLftanPT",
        ])
        .output();
    match output {
        Ok(output) => {
            let mut inspection = parse_lsof_output(&output.stdout, process);
            if !output.status.success() {
                inspection.warning = Some(
                    "lsof could not inspect this process; it may have exited or be protected"
                        .into(),
                );
            }
            #[cfg(target_os = "macos")]
            attach_macos_threads(&mut inspection);
            inspection
        }
        Err(error) => {
            let mut inspection = ProcessInspection {
                pid: process.pid,
                name: process.name.clone(),
                user: if process.user.is_empty() {
                    "[unavailable]".into()
                } else {
                    process.user.clone()
                },
                cwd: if process.cwd.is_empty() {
                    "[unavailable]".into()
                } else {
                    process.cwd.clone()
                },
                warning: Some(format!("cannot run lsof: {error}")),
                ..ProcessInspection::default()
            };
            #[cfg(target_os = "macos")]
            attach_macos_threads(&mut inspection);
            inspection
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, PartialEq)]
struct LinuxThreadSample {
    id: u64,
    name: String,
    state: String,
    cpu_ticks: u64,
    start_time_ticks: u64,
    priority: i32,
    nice: i32,
    processor: Option<i32>,
}

#[cfg(target_os = "linux")]
fn linux_thread_state(state: char) -> &'static str {
    match state {
        'R' => "Running",
        'S' => "Sleeping",
        'D' => "Uninterruptible",
        'T' => "Stopped",
        't' => "Tracing",
        'Z' => "Zombie",
        'X' | 'x' => "Dead",
        'I' => "Idle",
        'P' => "Parked",
        _ => "Unknown",
    }
}

#[cfg(target_os = "linux")]
fn parse_linux_thread_stat(content: &str) -> Option<LinuxThreadSample> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close <= open {
        return None;
    }
    let id = content[..open].trim().parse().ok()?;
    let name = content[open + 1..close].to_string();
    let fields: Vec<&str> = content[close + 1..].split_whitespace().collect();
    if fields.len() <= 36 {
        return None;
    }
    let state = fields[0].chars().next()?;
    let user_ticks: u64 = fields[11].parse().ok()?;
    let system_ticks: u64 = fields[12].parse().ok()?;
    Some(LinuxThreadSample {
        id,
        name,
        state: linux_thread_state(state).into(),
        cpu_ticks: user_ticks.saturating_add(system_ticks),
        start_time_ticks: fields[19].parse().ok()?,
        priority: fields[15].parse().ok()?,
        nice: fields[16].parse().ok()?,
        processor: fields[36].parse().ok(),
    })
}

#[cfg(target_os = "linux")]
struct LinuxThreadSampleSet {
    rows: Vec<LinuxThreadSample>,
    entries: usize,
    unreadable: usize,
}

#[cfg(target_os = "linux")]
fn read_linux_thread_samples(proc_root: &str) -> Result<LinuxThreadSampleSet, String> {
    let task_root = format!("{proc_root}/task");
    let entries =
        fs::read_dir(&task_root).map_err(|error| format!("cannot read {task_root}: {error}"))?;
    let mut rows = Vec::new();
    let mut entry_count = 0_usize;
    let mut unreadable = 0_usize;
    for entry in entries {
        let Ok(entry) = entry else {
            unreadable += 1;
            continue;
        };
        entry_count += 1;
        let stat_path = entry.path().join("stat");
        let sample = fs::read_to_string(&stat_path)
            .ok()
            .and_then(|content| parse_linux_thread_stat(&content));
        match sample {
            Some(sample) => rows.push(sample),
            None => unreadable += 1,
        }
    }
    rows.sort_by_key(|sample| sample.id);
    Ok(LinuxThreadSampleSet {
        rows,
        entries: entry_count,
        unreadable,
    })
}

#[cfg(target_os = "linux")]
fn linux_clock_ticks_per_second() -> Result<f64, String> {
    // SAFETY: sysconf with _SC_CLK_TCK has no pointer arguments or side effects.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        Err("cannot determine Linux CLK_TCK".into())
    } else {
        Ok(ticks as f64)
    }
}

#[cfg(target_os = "linux")]
fn build_linux_thread_rows(
    before: &[LinuxThreadSample],
    after: &[LinuxThreadSample],
    elapsed: Duration,
    ticks_per_second: f64,
) -> Vec<ThreadInfo> {
    let before: HashMap<u64, &LinuxThreadSample> =
        before.iter().map(|sample| (sample.id, sample)).collect();
    let elapsed_seconds = elapsed.as_secs_f64();
    let mut rows: Vec<ThreadInfo> = after
        .iter()
        .map(|sample| {
            let delta_ticks = before
                .get(&sample.id)
                .filter(|previous| previous.start_time_ticks == sample.start_time_ticks)
                .map(|previous| sample.cpu_ticks.saturating_sub(previous.cpu_ticks))
                .unwrap_or(0);
            let cpu_percent = if elapsed_seconds > 0.0 && ticks_per_second > 0.0 {
                (delta_ticks as f64 / ticks_per_second / elapsed_seconds * 100.0) as f32
            } else {
                0.0
            };
            ThreadInfo {
                id: sample.id,
                name: sample.name.clone(),
                state: sample.state.clone(),
                cpu_percent: if cpu_percent.is_finite() {
                    cpu_percent.max(0.0)
                } else {
                    0.0
                },
                priority: sample.priority,
                nice: Some(sample.nice),
                processor: sample.processor,
            }
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .cpu_percent
            .total_cmp(&left.cpu_percent)
            .then_with(|| left.id.cmp(&right.id))
    });
    rows.truncate(MAX_THREAD_ROWS);
    rows
}

#[cfg(target_os = "linux")]
fn attach_linux_threads(proc_root: &str, inspection: &mut ProcessInspection) {
    let before = match read_linux_thread_samples(proc_root) {
        Ok(samples) => samples,
        Err(error) => {
            inspection.thread_warning = Some(error);
            return;
        }
    };
    let started_at = Instant::now();
    thread::sleep(Duration::from_millis(250));
    let after = match read_linux_thread_samples(proc_root) {
        Ok(samples) => samples,
        Err(error) => {
            inspection.thread_warning = Some(error);
            return;
        }
    };
    let elapsed = started_at.elapsed();
    let ticks_per_second = match linux_clock_ticks_per_second() {
        Ok(ticks) => ticks,
        Err(error) => {
            inspection.thread_warning = Some(error);
            return;
        }
    };
    inspection.threads =
        build_linux_thread_rows(&before.rows, &after.rows, elapsed, ticks_per_second);
    inspection.thread_count = after.entries;
    inspection.thread_sample_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
    inspection.thread_truncated = after.rows.len() > MAX_THREAD_ROWS;
    let unreadable = before.unreadable.saturating_add(after.unreadable);
    if unreadable > 0 {
        inspection.thread_warning = Some(format!(
            "{unreadable} Linux thread samples were unreadable during collection"
        ));
    }
}

#[cfg(target_os = "linux")]
fn linux_fd_access(pid: Pid, fd: &str) -> String {
    let path = format!("/proc/{pid}/fdinfo/{fd}");
    fs::read_to_string(path)
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let flags = line.strip_prefix("flags:")?.trim();
                let flags = u32::from_str_radix(flags, 8).ok()?;
                Some(match flags & 0b11 {
                    0 => "r",
                    1 => "w",
                    2 => "u",
                    _ => "",
                })
            })
        })
        .unwrap_or("")
        .to_string()
}

#[cfg(target_os = "linux")]
fn linux_file_kind(path: &Path, target: &str) -> String {
    if target.starts_with("pipe:") {
        return "PIPE".into();
    }
    if target.starts_with("anon_inode:") {
        return "ANON".into();
    }
    let Ok(metadata) = fs::metadata(path) else {
        return "FILE".into();
    };
    let kind = metadata.file_type();
    if kind.is_dir() {
        "DIR"
    } else if kind.is_file() {
        "REG"
    } else if kind.is_char_device() {
        "CHR"
    } else if kind.is_block_device() {
        "BLK"
    } else if kind.is_fifo() {
        "FIFO"
    } else if kind.is_socket() {
        "SOCK"
    } else {
        "FILE"
    }
    .into()
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_proc_endpoint(value: &str, ipv6: bool) -> Option<(String, bool, u16)> {
    let (address, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    if ipv6 {
        if address.len() != 32 {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
            let chunk = std::str::from_utf8(chunk).ok()?;
            let word = u32::from_str_radix(chunk, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        let address = Ipv6Addr::from(bytes);
        Some((
            format!("[{address}]:{port}"),
            address.is_unspecified(),
            port,
        ))
    } else {
        let raw = u32::from_str_radix(address, 16).ok()?;
        let address = Ipv4Addr::from(raw.to_le_bytes());
        Some((format!("{address}:{port}"), address.is_unspecified(), port))
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn proc_socket_state(protocol: &str, state: &str) -> &'static str {
    if protocol == "UDP" && state == "07" {
        return "UNCONN";
    }
    match state {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_inet_sockets(
    path: &str,
    protocol: &str,
    ipv6: bool,
    socket_fds: &HashMap<String, Vec<String>>,
    matched: &mut HashSet<String>,
    sockets: &mut Vec<SocketInfo>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(remote), Some(state), Some(inode)) =
            (fields.get(1), fields.get(2), fields.get(3), fields.get(9))
        else {
            continue;
        };
        let Some(fds) = socket_fds.get(*inode) else {
            continue;
        };
        let Some((local, _, _)) = parse_proc_endpoint(local, ipv6) else {
            continue;
        };
        let Some((remote, remote_unspecified, remote_port)) = parse_proc_endpoint(remote, ipv6)
        else {
            continue;
        };
        let state = proc_socket_state(protocol, state);
        let endpoint = if state == "LISTEN" || (remote_unspecified && remote_port == 0) {
            local
        } else {
            format!("{local}->{remote}")
        };
        for fd in fds {
            sockets.push(SocketInfo {
                fd: fd.clone(),
                protocol: protocol.into(),
                endpoint: endpoint.clone(),
                state: state.into(),
            });
        }
        matched.insert((*inode).to_string());
    }
}

#[cfg(target_os = "linux")]
fn collect_linux_unix_sockets(
    path: &str,
    socket_fds: &HashMap<String, Vec<String>>,
    matched: &mut HashSet<String>,
    sockets: &mut Vec<SocketInfo>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(flags), Some(inode)) = (fields.get(3), fields.get(6)) else {
            continue;
        };
        let Some(fds) = socket_fds.get(*inode) else {
            continue;
        };
        let listening = u32::from_str_radix(flags, 16)
            .map(|flags| flags & 0x0001_0000 != 0)
            .unwrap_or(false);
        let endpoint = fields
            .get(7..)
            .map(|parts| parts.join(" "))
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| format!("socket:[{inode}]"));
        for fd in fds {
            sockets.push(SocketInfo {
                fd: fd.clone(),
                protocol: "UNIX".into(),
                endpoint: endpoint.clone(),
                state: if listening { "LISTEN" } else { "-" }.into(),
            });
        }
        matched.insert((*inode).to_string());
    }
}

#[cfg(target_os = "linux")]
fn inspection_field(label: &str, value: impl Into<String>) -> InspectionField {
    InspectionField {
        label: label.into(),
        value: value.into(),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn decode_linux_capabilities(value: &str) -> String {
    const CAPABILITIES: [&str; 41] = [
        "CHOWN",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "FOWNER",
        "FSETID",
        "KILL",
        "SETGID",
        "SETUID",
        "SETPCAP",
        "LINUX_IMMUTABLE",
        "NET_BIND_SERVICE",
        "NET_BROADCAST",
        "NET_ADMIN",
        "NET_RAW",
        "IPC_LOCK",
        "IPC_OWNER",
        "SYS_MODULE",
        "SYS_RAWIO",
        "SYS_CHROOT",
        "SYS_PTRACE",
        "SYS_PACCT",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_NICE",
        "SYS_RESOURCE",
        "SYS_TIME",
        "SYS_TTY_CONFIG",
        "MKNOD",
        "LEASE",
        "AUDIT_WRITE",
        "AUDIT_CONTROL",
        "SETFCAP",
        "MAC_OVERRIDE",
        "MAC_ADMIN",
        "SYSLOG",
        "WAKE_ALARM",
        "BLOCK_SUSPEND",
        "AUDIT_READ",
        "PERFMON",
        "BPF",
        "CHECKPOINT_RESTORE",
    ];
    let Ok(bits) = u64::from_str_radix(value.trim_start_matches("0x"), 16) else {
        return value.to_string();
    };
    if bits == 0 {
        return format!("0x{bits:x} (none)");
    }
    let names = CAPABILITIES
        .iter()
        .enumerate()
        .filter(|(bit, _)| bits & (1_u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(",");
    format!("0x{bits:x} ({names})")
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_status(content: &str) -> (Vec<InspectionField>, Vec<InspectionField>) {
    let mut runtime = Vec::new();
    let mut security = Vec::new();
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "State" => runtime.push(inspection_field("STATE", value)),
            "Threads" => runtime.push(inspection_field("THREADS", value)),
            "VmSize" => runtime.push(inspection_field("VIRTUAL MEM", value)),
            "VmRSS" => runtime.push(inspection_field("RSS", value)),
            "VmSwap" => runtime.push(inspection_field("SWAP", value)),
            "FDSize" => runtime.push(inspection_field("FD TABLE", value)),
            "NSpid" => runtime.push(inspection_field("NESTED PIDS", value)),
            "Uid" => runtime.push(inspection_field("UID r/e/s/fs", value)),
            "Gid" => runtime.push(inspection_field("GID r/e/s/fs", value)),
            "voluntary_ctxt_switches" => {
                runtime.push(inspection_field("CTX SWITCH voluntary", value));
            }
            "nonvoluntary_ctxt_switches" => {
                runtime.push(inspection_field("CTX SWITCH forced", value));
            }
            "NoNewPrivs" => security.push(inspection_field(
                "NO NEW PRIVS",
                if value == "1" { "enabled" } else { "disabled" },
            )),
            "Seccomp" => security.push(inspection_field(
                "SECCOMP",
                match value {
                    "0" => "disabled",
                    "1" => "strict",
                    "2" => "filter",
                    _ => value,
                },
            )),
            "Seccomp_filters" => security.push(inspection_field("SECCOMP FILTERS", value)),
            "CapEff" => security.push(inspection_field(
                "CAPABILITIES effective",
                decode_linux_capabilities(value),
            )),
            "CapBnd" => security.push(inspection_field(
                "CAPABILITIES bounding",
                decode_linux_capabilities(value),
            )),
            _ => {}
        }
    }
    (runtime, security)
}

#[cfg(target_os = "linux")]
fn short_container_id(value: &str) -> String {
    value.chars().take(12).collect()
}

#[cfg(target_os = "linux")]
fn container_hint(paths: &[String]) -> Option<String> {
    for path in paths {
        let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        for (index, component) in components.iter().enumerate() {
            let unit = component.strip_suffix(".scope").unwrap_or(component);
            for (prefix, runtime) in [
                ("docker-", "docker"),
                ("cri-containerd-", "containerd"),
                ("crio-", "cri-o"),
                ("libpod-", "podman"),
            ] {
                if let Some(id) = unit.strip_prefix(prefix) {
                    return Some(format!("{runtime} {}", short_container_id(id)));
                }
            }
            if matches!(*component, "docker" | "containers") {
                let Some(id) = components.get(index + 1) else {
                    continue;
                };
                if id.len() >= 12 {
                    return Some(format!("container {}", short_container_id(id)));
                }
            }
        }
        if path.contains("kubepods") {
            return Some("kubernetes cgroup".into());
        }
    }
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_cgroup(content: &str) -> Vec<InspectionField> {
    let mut paths = content
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Vec::new();
    }
    let mut fields = vec![inspection_field("CGROUP", paths.join(" | "))];
    if let Some(unit) = paths
        .iter()
        .flat_map(|path| path.split('/'))
        .rev()
        .find(|component| component.ends_with(".service") || component.ends_with(".scope"))
    {
        fields.push(inspection_field("SYSTEMD UNIT", unit));
    }
    if let Some(container) = container_hint(&paths) {
        fields.push(inspection_field("CONTAINER", container));
    }
    fields
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_limits(content: &str) -> Vec<InspectionField> {
    const LIMITS: [(&str, &str); 8] = [
        ("Max open files", "OPEN FILES"),
        ("Max processes", "PROCESSES"),
        ("Max locked memory", "LOCKED MEMORY"),
        ("Max address space", "ADDRESS SPACE"),
        ("Max core file size", "CORE FILE"),
        ("Max file size", "FILE SIZE"),
        ("Max stack size", "STACK"),
        ("Max pending signals", "PENDING SIGNALS"),
    ];
    let mut fields = Vec::new();
    for (prefix, label) in LIMITS {
        let Some(rest) = content
            .lines()
            .find_map(|line| line.strip_prefix(prefix).map(str::trim))
        else {
            continue;
        };
        let values: Vec<&str> = rest.split_whitespace().collect();
        if values.len() < 2 {
            continue;
        }
        let units = values.get(2).copied().unwrap_or("");
        let value = if units.is_empty() {
            format!("soft {} / hard {}", values[0], values[1])
        } else {
            format!("soft {} / hard {} {units}", values[0], values[1])
        };
        fields.push(inspection_field(label, value));
    }
    fields
}

#[cfg(target_os = "linux")]
fn collect_linux_context(proc_root: &str, inspection: &mut ProcessInspection) {
    if let Ok(status) = fs::read_to_string(format!("{proc_root}/status")) {
        let (runtime, security) = parse_linux_status(&status);
        inspection.runtime.extend(runtime);
        inspection.security.extend(security);
    }
    if let Ok(cgroup) = fs::read_to_string(format!("{proc_root}/cgroup")) {
        inspection.runtime.extend(parse_linux_cgroup(&cgroup));
    }
    if let Ok(limits) = fs::read_to_string(format!("{proc_root}/limits")) {
        inspection.limits = parse_linux_limits(&limits);
    }
    for namespace in [
        "cgroup",
        "ipc",
        "mnt",
        "net",
        "pid",
        "pid_for_children",
        "time",
        "time_for_children",
        "user",
        "uts",
    ] {
        if let Ok(target) = fs::read_link(format!("{proc_root}/ns/{namespace}")) {
            inspection.namespaces.push(inspection_field(
                &namespace.to_uppercase(),
                target.to_string_lossy(),
            ));
        }
    }
}

#[cfg(target_os = "linux")]
fn inspect_process_linux(process: &ProcessInfo) -> ProcessInspection {
    let mut inspection = ProcessInspection {
        pid: process.pid,
        name: process.name.clone(),
        user: if process.user.is_empty() {
            "[unavailable]".into()
        } else {
            process.user.clone()
        },
        cwd: process.cwd.clone(),
        ..ProcessInspection::default()
    };
    let proc_root = format!("/proc/{}", process.pid);
    if let Ok(cwd) = fs::read_link(format!("{proc_root}/cwd")) {
        inspection.cwd = cwd.display().to_string();
    }
    if inspection.cwd.is_empty() {
        inspection.cwd = "[unavailable]".into();
    }
    collect_linux_context(&proc_root, &mut inspection);
    attach_linux_threads(&proc_root, &mut inspection);

    let fd_root = format!("{proc_root}/fd");
    let entries = match fs::read_dir(&fd_root) {
        Ok(entries) => entries,
        Err(error) => {
            inspection.warning = Some(format!("cannot read {fd_root}: {error}"));
            return inspection;
        }
    };
    let mut socket_fds: HashMap<String, Vec<String>> = HashMap::new();
    for entry in entries.flatten() {
        let fd = entry.file_name().to_string_lossy().into_owned();
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|target| target.strip_suffix(']'))
        {
            socket_fds.entry(inode.to_string()).or_default().push(fd);
            continue;
        }
        inspection.files.push(OpenFileInfo {
            fd: fd.clone(),
            kind: linux_file_kind(&entry.path(), &target),
            access: linux_fd_access(process.pid, &fd),
            name: target,
        });
    }

    let mut matched = HashSet::new();
    collect_linux_inet_sockets(
        &format!("{proc_root}/net/tcp"),
        "TCP",
        false,
        &socket_fds,
        &mut matched,
        &mut inspection.sockets,
    );
    collect_linux_inet_sockets(
        &format!("{proc_root}/net/tcp6"),
        "TCP",
        true,
        &socket_fds,
        &mut matched,
        &mut inspection.sockets,
    );
    collect_linux_inet_sockets(
        &format!("{proc_root}/net/udp"),
        "UDP",
        false,
        &socket_fds,
        &mut matched,
        &mut inspection.sockets,
    );
    collect_linux_inet_sockets(
        &format!("{proc_root}/net/udp6"),
        "UDP",
        true,
        &socket_fds,
        &mut matched,
        &mut inspection.sockets,
    );
    collect_linux_unix_sockets(
        &format!("{proc_root}/net/unix"),
        &socket_fds,
        &mut matched,
        &mut inspection.sockets,
    );
    for (inode, fds) in socket_fds {
        if matched.contains(&inode) {
            continue;
        }
        for fd in fds {
            inspection.sockets.push(SocketInfo {
                fd,
                protocol: "SOCKET".into(),
                endpoint: format!("socket:[{inode}]"),
                state: "UNRESOLVED".into(),
            });
        }
    }
    inspection.sockets.sort_by(|left, right| {
        (&left.protocol, &left.endpoint).cmp(&(&right.protocol, &right.endpoint))
    });
    inspection
        .files
        .sort_by(|left, right| (&left.fd, &left.name).cmp(&(&right.fd, &right.name)));
    inspection
}

pub(crate) fn inspect_process(process: &ProcessInfo) -> ProcessInspection {
    #[cfg(target_os = "linux")]
    {
        inspect_process_linux(process)
    }
    #[cfg(not(target_os = "linux"))]
    {
        inspect_process_lsof(process)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_thread_tests {
    use super::*;

    #[test]
    fn libproc_lists_the_current_process_threads() {
        let (threads, total, warning) =
            collect_macos_threads(std::process::id() as i32).expect("collect current threads");
        assert!(total >= 1);
        assert!(
            !threads.is_empty(),
            "libproc listed {total} threads but returned no details: {warning:?}"
        );
        assert!(threads.iter().all(|thread| {
            thread.id != 0
                && thread.cpu_percent.is_finite()
                && (0.0..=100.0).contains(&thread.cpu_percent)
        }));
        assert!(threads.len() <= total);
        if let Some(warning) = warning {
            assert!(warning.contains("exited or became unreadable"));
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_thread_tests {
    use super::*;

    #[test]
    fn parses_proc_thread_stat_with_spaces_and_computes_cpu_delta() {
        let stat = "123 (worker pool) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37";
        let before = parse_linux_thread_stat(stat).expect("parse thread stat");
        assert_eq!(before.id, 123);
        assert_eq!(before.name, "worker pool");
        assert_eq!(before.cpu_ticks, 23);
        assert_eq!(before.start_time_ticks, 19);
        assert_eq!(before.priority, 15);
        assert_eq!(before.nice, 16);
        assert_eq!(before.processor, Some(36));

        let mut after = before.clone();
        after.cpu_ticks += 25;
        let rows = build_linux_thread_rows(
            &[before.clone()],
            &[after.clone()],
            Duration::from_millis(250),
            100.0,
        );
        assert_eq!(rows.len(), 1);
        assert!((rows[0].cpu_percent - 100.0).abs() < 0.01);

        let mut reused = after;
        reused.start_time_ticks += 1;
        reused.cpu_ticks += 100;
        let rows = build_linux_thread_rows(
            &[LinuxThreadSample {
                id: 123,
                name: "worker pool".into(),
                state: "Running".into(),
                cpu_ticks: 23,
                start_time_ticks: 19,
                priority: 15,
                nice: 16,
                processor: Some(36),
            }],
            &[reused],
            Duration::from_millis(250),
            100.0,
        );
        assert_eq!(rows[0].cpu_percent, 0.0);
    }
}
