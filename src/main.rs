use std::{
    collections::{HashMap, HashSet},
    io,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use std::{
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::FileTypeExt,
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: Pid,
    parent: Option<Pid>,
    name: String,
    command: String,
    executable: String,
    user: String,
    cwd: String,
    cpu: f32,
    memory: u64,
    start_time: u64,
    runtime: u64,
    status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessChange {
    Started {
        pid: Pid,
        name: String,
        parent: Option<Pid>,
    },
    Exited {
        pid: Pid,
        name: String,
    },
    Reparented {
        pid: Pid,
        name: String,
        old_parent: Option<Pid>,
        new_parent: Option<Pid>,
    },
}

impl ProcessChange {
    fn pid(&self) -> Pid {
        match self {
            Self::Started { pid, .. } | Self::Exited { pid, .. } | Self::Reparented { pid, .. } => {
                *pid
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ProcessEvent {
    change: ProcessChange,
    observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChangeSummary {
    started: usize,
    exited: usize,
    reparented: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct OpenFileInfo {
    fd: String,
    kind: String,
    access: String,
    name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SocketInfo {
    fd: String,
    protocol: String,
    endpoint: String,
    state: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessInspection {
    pid: Pid,
    name: String,
    user: String,
    cwd: String,
    sockets: Vec<SocketInfo>,
    files: Vec<OpenFileInfo>,
    warning: Option<String>,
}

impl Default for ProcessInspection {
    fn default() -> Self {
        Self {
            pid: Pid::from_u32(0),
            name: String::new(),
            user: String::new(),
            cwd: String::new(),
            sockets: Vec::new(),
            files: Vec::new(),
            warning: None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Default)]
struct LsofFileRecord {
    fd: String,
    kind: String,
    access: String,
    name: String,
    protocol: String,
    state: String,
}

fn process_instance_changed(old: &ProcessInfo, new: &ProcessInfo) -> bool {
    old.start_time != 0 && new.start_time != 0 && old.start_time != new.start_time
}

fn diff_processes(
    previous: &HashMap<Pid, ProcessInfo>,
    current: &HashMap<Pid, ProcessInfo>,
) -> Vec<ProcessChange> {
    let root = Pid::from_u32(0);
    let mut pids: Vec<Pid> = previous.keys().chain(current.keys()).copied().collect();
    pids.sort_by_key(|pid| pid.as_u32());
    pids.dedup();

    let mut changes = Vec::new();
    for pid in pids {
        if pid == root {
            continue;
        }
        match (previous.get(&pid), current.get(&pid)) {
            (None, Some(process)) => changes.push(ProcessChange::Started {
                pid,
                name: process.name.clone(),
                parent: process.parent,
            }),
            (Some(process), None) => changes.push(ProcessChange::Exited {
                pid,
                name: process.name.clone(),
            }),
            (Some(old), Some(new)) if process_instance_changed(old, new) => {
                changes.push(ProcessChange::Exited {
                    pid,
                    name: old.name.clone(),
                });
                changes.push(ProcessChange::Started {
                    pid,
                    name: new.name.clone(),
                    parent: new.parent,
                });
            }
            (Some(old), Some(new)) if old.parent != new.parent => {
                changes.push(ProcessChange::Reparented {
                    pid,
                    name: new.name.clone(),
                    old_parent: old.parent,
                    new_parent: new.parent,
                });
            }
            _ => {}
        }
    }
    changes
}

#[derive(Clone, Debug)]
struct TreeRow {
    pid: Pid,
    depth: usize,
    // For each ancestor, whether that ancestor is the last sibling.
    last_path: Vec<bool>,
    is_last: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarqueePhase {
    Scrolling,
    TailPause,
    ResetPause,
}

trait ProcessProvider {
    fn refresh(&mut self) -> Vec<ProcessInfo>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeProcessSnapshot {
    ppid: u32,
    state: String,
    command: String,
}

fn parse_ps_snapshot(output: &[u8]) -> HashMap<u32, NativeProcessSnapshot> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| {
            let (pid, rest) = take_ps_field(line)?;
            let (ppid, rest) = take_ps_field(rest)?;
            let (state, command) = take_ps_field(rest)?;
            Some((
                pid.parse().ok()?,
                NativeProcessSnapshot {
                    ppid: ppid.parse().ok()?,
                    state: state.to_string(),
                    command: command.trim().to_string(),
                },
            ))
        })
        .collect()
}

fn take_ps_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    let end = input.find(char::is_whitespace).unwrap_or(input.len());
    Some((&input[..end], &input[end..]))
}

fn native_process_snapshot() -> HashMap<u32, NativeProcessSnapshot> {
    let Ok(child) = Command::new("ps")
        .args(["-ww", "-axo", "pid=,ppid=,state=,command="])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return HashMap::new();
    };
    let sampler_pid = child.id();
    let Ok(output) = child.wait_with_output() else {
        return HashMap::new();
    };
    let mut snapshot = parse_ps_snapshot(&output.stdout);
    // Do not report psmore's own sampling command as a new process every
    // refresh; it has already exited by the time the snapshot is consumed.
    snapshot.remove(&sampler_pid);
    snapshot
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
fn parse_lsof_output(output: &[u8], process: &ProcessInfo) -> ProcessInspection {
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
            inspection
        }
        Err(error) => ProcessInspection {
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
        },
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
fn parse_proc_endpoint(value: &str, ipv6: bool) -> Option<(String, bool, u16)> {
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
fn proc_socket_state(protocol: &str, state: &str) -> &'static str {
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

fn inspect_process(process: &ProcessInfo) -> ProcessInspection {
    #[cfg(target_os = "linux")]
    {
        inspect_process_linux(process)
    }
    #[cfg(not(target_os = "linux"))]
    {
        inspect_process_lsof(process)
    }
}

fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

fn is_sampler_process(process: &ProcessInfo) -> bool {
    process.parent == Some(Pid::from_u32(std::process::id())) && process.name == "ps"
}

struct NativeProcessProvider {
    system: System,
    users: Users,
}

impl NativeProcessProvider {
    fn new() -> Self {
        Self {
            system: System::new(),
            users: Users::new_with_refreshed_list(),
        }
    }
}

impl ProcessProvider for NativeProcessProvider {
    fn refresh(&mut self) -> Vec<ProcessInfo> {
        // A process relationship tool should not silently mix Linux tasks
        // (threads) into the process tree. Besides being noisy, task IDs are
        // short-lived and can look like stale child processes between samples.
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_memory()
                .with_cpu()
                .with_user(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::Always)
                .with_exe(UpdateKind::OnlyIfNotSet)
                .without_tasks(),
        );
        let mut processes: Vec<ProcessInfo> = self
            .system
            .processes()
            .values()
            .map(|process| ProcessInfo {
                pid: process.pid(),
                parent: process.parent(),
                name: process.name().to_string_lossy().into_owned(),
                command: process
                    .cmd()
                    .iter()
                    .map(|part| part.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
                executable: process
                    .exe()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                user: process
                    .user_id()
                    .map(|user_id| {
                        self.users
                            .get_user_by_id(user_id)
                            .map(|user| user.name().to_string())
                            .unwrap_or_else(|| user_id.to_string())
                    })
                    .unwrap_or_default(),
                cwd: process
                    .cwd()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                cpu: process.cpu_usage(),
                memory: process.memory(),
                start_time: process.start_time(),
                runtime: process.run_time(),
                status: format!("{:?}", process.status()),
            })
            .collect();

        // One native snapshot complements sysinfo on both macOS and Linux:
        // it preserves the original command line and fills short-lived or
        // permission-sensitive processes that sysinfo may omit.
        let ps_processes = native_process_snapshot();
        for process in &mut processes {
            if let Some(snapshot) = ps_processes.get(&process.pid.as_u32()) {
                if !snapshot.command.is_empty() {
                    process.command = snapshot.command.clone();
                }
                process.parent = Some(Pid::from_u32(snapshot.ppid));
            }
        }

        let known_pids: HashSet<u32> = processes
            .iter()
            .map(|process| process.pid.as_u32())
            .collect();
        for (pid, snapshot) in ps_processes {
            if known_pids.contains(&pid) || pid == 0 {
                continue;
            }
            let NativeProcessSnapshot {
                ppid,
                state,
                command,
            } = snapshot;
            let executable = command.split_whitespace().next().unwrap_or("").to_string();
            let name = Path::new(&executable)
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or(&executable)
                .to_string();
            processes.push(ProcessInfo {
                pid: Pid::from_u32(pid),
                parent: Some(Pid::from_u32(ppid)),
                name,
                command,
                executable,
                user: String::new(),
                cwd: String::new(),
                cpu: 0.0,
                memory: 0,
                start_time: 0,
                runtime: 0,
                status: state,
            });
        }
        // sysinfo can observe the previous native sampler during a narrow
        // macOS timing window. It is an implementation detail, not a process
        // event the user should have to reason about.
        processes.retain(|process| !is_sampler_process(process));

        // Keep parentless or raced-out processes under a synthetic PID 0 root
        // so the tree remains navigable on both supported platforms.
        let root = Pid::from_u32(0);
        let available_pids: HashSet<Pid> = processes.iter().map(|process| process.pid).collect();
        for process in &mut processes {
            process.parent = match process.parent {
                Some(parent)
                    if parent == root
                        || (parent != process.pid && available_pids.contains(&parent)) =>
                {
                    Some(parent)
                }
                _ => Some(root),
            };
        }
        processes.push(ProcessInfo {
            pid: root,
            parent: None,
            name: "kernel / system".into(),
            command: String::new(),
            executable: String::new(),
            user: String::new(),
            cwd: String::new(),
            cpu: 0.0,
            memory: 0,
            start_time: 0,
            runtime: 0,
            status: "VirtualRoot".into(),
        });
        processes
    }
}

struct App {
    provider: NativeProcessProvider,
    processes: HashMap<Pid, ProcessInfo>,
    children: HashMap<Option<Pid>, Vec<Pid>>,
    visible: Vec<TreeRow>,
    selected: usize,
    expanded: HashSet<Pid>,
    collapsed: HashSet<Pid>,
    search: String,
    searching: bool,
    focus: Option<Pid>,
    last_refresh: Instant,
    marquee_offset: usize,
    last_marquee: Instant,
    marquee_pid: Option<Pid>,
    marquee_phase: MarqueePhase,
    page_size: usize,
    error: Option<String>,
    paused: bool,
    show_events: bool,
    events: Vec<ProcessEvent>,
    last_changes: ChangeSummary,
    inspection: Option<ProcessInspection>,
    inspection_scroll: u16,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            provider: NativeProcessProvider::new(),
            processes: HashMap::new(),
            children: HashMap::new(),
            visible: Vec::new(),
            selected: 0,
            expanded: HashSet::new(),
            collapsed: HashSet::new(),
            search: String::new(),
            searching: false,
            focus: None,
            last_refresh: Instant::now(),
            marquee_offset: 0,
            last_marquee: Instant::now(),
            marquee_pid: None,
            marquee_phase: MarqueePhase::Scrolling,
            page_size: 10,
            error: None,
            paused: false,
            show_events: false,
            events: Vec::new(),
            last_changes: ChangeSummary::default(),
            inspection: None,
            inspection_scroll: 0,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        let next_processes: HashMap<Pid, ProcessInfo> = self
            .provider
            .refresh()
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        let changes = if self.processes.is_empty() {
            Vec::new()
        } else {
            diff_processes(&self.processes, &next_processes)
        };
        self.processes = next_processes;
        self.record_changes(changes);
        self.children.clear();
        for process in self.processes.values() {
            self.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        for children in self.children.values_mut() {
            // Name groups remain readable, while PID makes the order
            // deterministic across refreshes and for same-named processes.
            children.sort_by_key(|pid| {
                self.processes
                    .get(pid)
                    .map(|p| (p.name.to_lowercase(), pid.as_u32()))
            });
        }
        if self.expanded.is_empty() {
            self.expanded.insert(Pid::from_u32(0));
            self.expanded.extend(
                self.children
                    .values()
                    .flatten()
                    .filter(|pid| {
                        self.children
                            .get(&Some(**pid))
                            .map(|c| !c.is_empty())
                            .unwrap_or(false)
                    })
                    .copied(),
            );
        }
        self.rebuild_visible();
        self.last_refresh = Instant::now();
        self.error = None;
    }

    fn record_changes(&mut self, changes: Vec<ProcessChange>) {
        let mut summary = ChangeSummary::default();
        let now = Instant::now();
        for change in changes {
            match &change {
                ProcessChange::Started { .. } => summary.started += 1,
                ProcessChange::Exited { .. } => summary.exited += 1,
                ProcessChange::Reparented { .. } => summary.reparented += 1,
            }
            self.events.push(ProcessEvent {
                change,
                observed_at: now,
            });
        }
        self.last_changes = summary;
        const MAX_EVENTS: usize = 200;
        if self.events.len() > MAX_EVENTS {
            self.events.drain(..self.events.len() - MAX_EVENTS);
        }
    }

    fn recent_change(&self, pid: Pid) -> Option<&ProcessChange> {
        self.events
            .iter()
            .rev()
            .find(|event| {
                event.change.pid() == pid && event.observed_at.elapsed() <= Duration::from_secs(5)
            })
            .map(|event| &event.change)
    }

    fn toggle_paused(&mut self) {
        self.paused = !self.paused;
        if !self.paused {
            self.refresh();
        }
    }

    fn open_inspection(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_events = false;
        self.inspection = Some(inspect_process(&process));
        self.inspection_scroll = 0;
    }

    fn refresh_inspection(&mut self) {
        let Some(pid) = self.inspection.as_ref().map(|inspection| inspection.pid) else {
            self.open_inspection();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(inspection) = &mut self.inspection {
                inspection.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.inspection = Some(inspect_process(&process));
        self.inspection_scroll = 0;
    }

    fn rebuild_visible(&mut self) {
        let old_pid = self.visible.get(self.selected).map(|row| row.pid);
        self.visible.clear();
        let matched: HashSet<Pid> = self
            .processes
            .values()
            .filter(|p| {
                self.search.is_empty()
                    || format!("{} {} {}", p.name, p.command, p.pid)
                        .to_lowercase()
                        .contains(&self.search.to_lowercase())
            })
            .map(|p| p.pid)
            .collect();

        if let Some(focus) = self.focus {
            let mut chain = Vec::new();
            let mut current = Some(focus);
            while let Some(pid) = current {
                chain.push(pid);
                current = self.processes.get(&pid).and_then(|p| p.parent);
            }
            chain.reverse();
            for (depth, pid) in chain.iter().enumerate() {
                self.visible.push(TreeRow {
                    pid: *pid,
                    depth,
                    last_path: vec![false; depth],
                    is_last: depth == chain.len().saturating_sub(1),
                });
            }
            self.walk_children(focus, chain.len(), vec![false; chain.len()], &matched);
        } else {
            let roots = [Pid::from_u32(0)];
            for (index, pid) in roots.iter().enumerate() {
                self.walk(*pid, Vec::new(), index == roots.len() - 1, &matched);
            }
        }
        if self.visible.is_empty() && !self.processes.is_empty() {
            let mut all: Vec<Pid> = self.processes.keys().copied().collect();
            all.sort_by_key(|p| p.as_u32());
            for pid in all {
                if matched.contains(&pid) {
                    self.visible.push(TreeRow {
                        pid,
                        depth: 0,
                        last_path: Vec::new(),
                        is_last: true,
                    });
                }
            }
        }
        self.selected = old_pid
            .and_then(|pid| self.visible.iter().position(|row| row.pid == pid))
            .unwrap_or(self.selected.min(self.visible.len().saturating_sub(1)));
    }

    fn walk(&mut self, pid: Pid, last_path: Vec<bool>, is_last: bool, matched: &HashSet<Pid>) {
        let has_match = matched.contains(&pid);
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let descendant_match = descendants
            .iter()
            .any(|child| self.has_matching_descendant(*child, matched));
        if has_match || descendant_match || self.search.is_empty() {
            let depth = last_path.len();
            self.visible.push(TreeRow {
                pid,
                depth,
                last_path: last_path.clone(),
                is_last,
            });
            if self.expanded.contains(&pid)
                || (!self.search.is_empty() && descendant_match && !self.collapsed.contains(&pid))
            {
                for (index, child) in descendants.iter().enumerate() {
                    let mut child_path = last_path.clone();
                    child_path.push(is_last);
                    if !self.search.is_empty() && has_match {
                        self.walk_context(*child, child_path, index == descendants.len() - 1);
                    } else {
                        self.walk(*child, child_path, index == descendants.len() - 1, matched);
                    }
                }
            }
        }
    }

    /// Once a search hit is visible, show its complete descendant context.
    /// Search still filters the ancestors and unrelated branches, but it must
    /// not hide the children that explain what the matched process owns.
    fn walk_context(&mut self, pid: Pid, last_path: Vec<bool>, is_last: bool) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let depth = last_path.len();
        self.visible.push(TreeRow {
            pid,
            depth,
            last_path: last_path.clone(),
            is_last,
        });
        if self.expanded.contains(&pid) && !self.collapsed.contains(&pid) {
            for (index, child) in descendants.iter().enumerate() {
                let mut child_path = last_path.clone();
                child_path.push(is_last);
                self.walk_context(*child, child_path, index == descendants.len() - 1);
            }
        }
    }

    fn walk_children(
        &mut self,
        pid: Pid,
        depth: usize,
        last_path: Vec<bool>,
        matched: &HashSet<Pid>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        for (index, child) in descendants.iter().enumerate() {
            if matched.contains(child)
                || self.search.is_empty()
                || self.has_matching_descendant(*child, matched)
            {
                let mut child_path = last_path.clone();
                child_path.push(index == descendants.len() - 1);
                self.visible.push(TreeRow {
                    pid: *child,
                    depth,
                    last_path: child_path.clone(),
                    is_last: index == descendants.len() - 1,
                });
                if self.expanded.contains(child)
                    || (self.search.is_empty() && !self.collapsed.contains(child))
                    || (!self.search.is_empty()
                        && self.has_matching_descendant(*child, matched)
                        && !self.collapsed.contains(child))
                {
                    self.walk_children(*child, depth + 1, child_path, matched);
                }
            }
        }
    }

    fn has_matching_descendant(&self, pid: Pid, matched: &HashSet<Pid>) -> bool {
        if matched.contains(&pid) {
            return true;
        }
        self.children
            .get(&Some(pid))
            .map(|children| {
                children
                    .iter()
                    .any(|p| self.has_matching_descendant(*p, matched))
            })
            .unwrap_or(false)
    }

    fn selected_pid(&self) -> Option<Pid> {
        self.visible.get(self.selected).map(|row| row.pid)
    }

    fn selected_context(&self) -> Option<String> {
        let pid = self.selected_pid()?;
        let process = self.processes.get(&pid)?;
        Some(process_path(process))
    }

    fn advance_marquee(&mut self, width: usize) {
        let selected = self.selected_pid();
        if self.marquee_pid != selected {
            self.marquee_pid = selected;
            self.marquee_offset = 0;
            self.marquee_phase = MarqueePhase::Scrolling;
            self.last_marquee = Instant::now();
        }
        let Some(context) = self.selected_context() else {
            return;
        };
        let max_offset = context.width().saturating_sub(width);
        if width == 0 || max_offset == 0 {
            self.marquee_offset = 0;
            self.marquee_phase = MarqueePhase::Scrolling;
            return;
        }
        let now = Instant::now();
        match self.marquee_phase {
            MarqueePhase::Scrolling => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(125) {
                    self.marquee_offset = self.marquee_offset.saturating_add(1);
                    self.last_marquee = now;
                    if self.marquee_offset >= max_offset {
                        self.marquee_offset = max_offset;
                        self.marquee_phase = MarqueePhase::TailPause;
                    }
                }
            }
            MarqueePhase::TailPause => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(2500) {
                    self.marquee_offset = 0;
                    self.marquee_phase = MarqueePhase::ResetPause;
                    self.last_marquee = now;
                }
            }
            MarqueePhase::ResetPause => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(1000) {
                    self.marquee_phase = MarqueePhase::Scrolling;
                    self.last_marquee = now;
                }
            }
        }
    }

    fn select_first_match(&mut self) {
        if self.search.is_empty() {
            return;
        }
        let query = self.search.to_lowercase();
        if let Some(index) = self.visible.iter().position(|row| {
            self.processes
                .get(&row.pid)
                .map(|p| {
                    format!("{} {} {}", p.name, p.command, p.pid)
                        .to_lowercase()
                        .contains(&query)
                })
                .unwrap_or(false)
        }) {
            self.selected = index;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let max = self.visible.len() - 1;
        self.selected = (self.selected as isize + delta).clamp(0, max as isize) as usize;
    }

    fn toggle_focus(&mut self) {
        self.focus = if self.focus == self.selected_pid() {
            None
        } else {
            self.selected_pid()
        };
        self.selected = 0;
        self.rebuild_visible();
    }

    fn toggle_selected_expanded(&mut self) {
        if let Some(pid) = self.selected_pid()
            && self
                .children
                .get(&Some(pid))
                .map(|c| !c.is_empty())
                .unwrap_or(false)
        {
            if !self.expanded.insert(pid) {
                self.expanded.remove(&pid);
                self.collapsed.insert(pid);
            } else {
                self.collapsed.remove(&pid);
            }
            self.rebuild_visible();
        }
    }

    fn reveal_parent(&mut self) {
        let Some(pid) = self.selected_pid() else {
            return;
        };
        let Some(parent) = self.processes.get(&pid).and_then(|p| p.parent) else {
            return;
        };

        // Expose the complete ancestor path, but keep the parent's other branches collapsed.
        let mut current = Some(parent);
        while let Some(ancestor) = current {
            self.expanded.insert(ancestor);
            self.collapsed.remove(&ancestor);
            current = self.processes.get(&ancestor).and_then(|p| p.parent);
        }
        if let Some(siblings) = self.children.get(&Some(parent)).cloned() {
            for sibling in siblings {
                if sibling != pid {
                    self.expanded.remove(&sibling);
                    self.collapsed.insert(sibling);
                }
            }
        }
        self.rebuild_visible();
        if let Some(index) = self.visible.iter().position(|row| row.pid == parent) {
            self.selected = index;
        }
    }

    fn finish_search(&mut self) {
        if !self.searching {
            return;
        }
        self.searching = false;
        self.search.clear();
        self.rebuild_visible();
    }

    fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if self.inspection.is_some() {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc => {
                    self.inspection = None;
                    self.inspection_scroll = 0;
                }
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_inspection(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.inspection_scroll = self.inspection_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.inspection_scroll = self.inspection_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.inspection_scroll = self.inspection_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.inspection_scroll = self.inspection_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_events {
            match key.code {
                KeyCode::Char('q') => return true,
                KeyCode::Esc | KeyCode::Char('e') => self.show_events = false,
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.search.clear();
                    self.rebuild_visible();
                }
                KeyCode::Enter => {
                    // `/` is a transient locator. Keep the selected process,
                    // then restore the complete tree for relationship work.
                    self.finish_search();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_selection(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_selection(-1);
                }
                KeyCode::PageDown => {
                    self.move_selection(self.page_size as isize);
                }
                KeyCode::PageUp => {
                    self.move_selection(-(self.page_size as isize));
                }
                KeyCode::Left => {
                    self.reveal_parent();
                }
                KeyCode::Right => {
                    self.toggle_selected_expanded();
                }
                KeyCode::Backspace => {
                    self.search.pop();
                    self.rebuild_visible();
                }
                KeyCode::Char(c) if key.modifiers.is_empty() => {
                    self.search.push(c);
                    self.rebuild_visible();
                    self.select_first_match();
                }
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.page_size as isize),
            KeyCode::PageUp => self.move_selection(-(self.page_size as isize)),
            KeyCode::Left => {
                self.reveal_parent();
            }
            KeyCode::Right => self.toggle_selected_expanded(),
            KeyCode::Char('/') => {
                self.searching = true;
                self.search.clear();
            }
            KeyCode::Char('f') => self.toggle_focus(),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char(' ') => self.toggle_paused(),
            KeyCode::Char('e') => {
                self.show_events = true;
                self.inspection = None;
            }
            KeyCode::Enter => self.open_inspection(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        false
    }
}

fn row_label_and_context(app: &App, row: &TreeRow) -> (String, String) {
    let p = &app.processes[&row.pid];
    let child_count = app
        .children
        .get(&Some(row.pid))
        .map(|c| c.len())
        .unwrap_or(0);
    let marker = if app
        .children
        .get(&Some(row.pid))
        .map(|c| !c.is_empty())
        .unwrap_or(false)
    {
        if app.expanded.contains(&row.pid) {
            "▾"
        } else {
            "▸"
        }
    } else {
        "·"
    };
    let mut prefix = String::new();
    for is_last in row
        .last_path
        .iter()
        .skip(1)
        .take(row.depth.saturating_sub(1))
    {
        prefix.push_str(if *is_last { "  " } else { "│ " });
    }
    if row.depth > 0 {
        prefix.push_str(if row.is_last { "└─" } else { "├─" });
    }
    let context = process_path(p);
    let name = if child_count > 0 && !app.expanded.contains(&row.pid) {
        format!("{} ({})", p.name, child_count)
    } else {
        p.name.clone()
    };
    (
        format!("{}{} {}  [{}]", prefix, marker, name, row.pid),
        context,
    )
}

fn process_path(process: &ProcessInfo) -> String {
    if !process.executable.is_empty() {
        process.executable.clone()
    } else if let Some(first) = process.command.split_whitespace().next() {
        first.to_string()
    } else if process.pid.as_u32() == 0 {
        "system root".into()
    } else {
        "[path unavailable]".into()
    }
}

fn process_command_line(process: &ProcessInfo) -> String {
    if !process.command.is_empty() {
        process.command.clone()
    } else {
        process_path(process)
    }
}

fn marquee(text: &str, offset: usize, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.width() <= width {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let start = offset.min(chars.len().saturating_sub(1));
    let mut result = String::new();
    let mut used = 0;
    let mut index = start;
    while used < width {
        let ch = chars[index];
        let char_width = ch.width().unwrap_or(1);
        if used + char_width > width {
            break;
        }
        result.push(ch);
        used += char_width;
        index += 1;
        if index >= chars.len() {
            break;
        }
    }
    result
}

fn wrapped_lines(text: &str, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    text.width().max(1).div_ceil(width)
}

fn detail_height(app: &App, area: ratatui::layout::Rect) -> u16 {
    let Some(pid) = app.selected_pid() else {
        return 4;
    };
    let Some(process) = app.processes.get(&pid) else {
        return 4;
    };
    let width = area.width.saturating_sub(2).max(1) as usize;
    let command = process_command_line(process);
    let content_lines = 1 + wrapped_lines(&command, width);
    let desired = (content_lines + 2).max(4) as u16;
    desired.min(area.height.saturating_sub(5).max(4))
}

fn parent_label(parent: Option<Pid>) -> String {
    parent
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "-".into())
}

fn event_line(event: &ProcessEvent) -> Line<'static> {
    let age = event.observed_at.elapsed().as_secs();
    let (color, text) = match &event.change {
        ProcessChange::Started { pid, name, parent } => (
            Color::LightGreen,
            format!(
                "{:>4}s  + {} [{}]  parent {}",
                age,
                name,
                pid,
                parent_label(*parent)
            ),
        ),
        ProcessChange::Exited { pid, name } => (
            Color::LightRed,
            format!("{:>4}s  - {} [{}]", age, name, pid),
        ),
        ProcessChange::Reparented {
            pid,
            name,
            old_parent,
            new_parent,
        } => (
            Color::LightYellow,
            format!(
                "{:>4}s  ↪ {} [{}]  {} → {}",
                age,
                name,
                pid,
                parent_label(*old_parent),
                parent_label(*new_parent)
            ),
        ),
    };
    Line::from(Span::styled(text, Style::default().fg(color)))
}

fn draw_event_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let width = area.width.saturating_sub(2).clamp(1, 100);
    let height = area.height.saturating_sub(2).clamp(1, 18);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let line_limit = height.saturating_sub(2) as usize;
    let lines = if app.events.is_empty() {
        vec![Line::from(" No process changes captured yet ")]
    } else {
        app.events
            .iter()
            .rev()
            .take(line_limit)
            .map(event_line)
            .collect()
    };
    let title = format!(" process changes ({})  Esc/e close ", app.events.len());
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn inspection_lines(inspection: &ProcessInspection) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("USER ", Style::default().fg(Color::Cyan)),
            Span::raw(inspection.user.clone()),
        ]),
        Line::from(vec![
            Span::styled("CWD  ", Style::default().fg(Color::Cyan)),
            Span::raw(inspection.cwd.clone()),
        ]),
    ];
    if let Some(warning) = &inspection.warning {
        lines.push(Line::from(Span::styled(
            format!("WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("NETWORK ({})", inspection.sockets.len()),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if inspection.sockets.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No sockets visible",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for socket in &inspection.sockets {
            let state = if socket.state.is_empty() {
                "-"
            } else {
                &socket.state
            };
            lines.push(Line::from(format!(
                "  {:<6} {:<12} fd {:<6} {}",
                socket.protocol, state, socket.fd, socket.endpoint
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("OPEN FILE DESCRIPTORS ({})", inspection.files.len()),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if inspection.files.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No file descriptors visible",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for file in &inspection.files {
            lines.push(Line::from(format!(
                "  fd {:<6} {:<6} {:<2} {}",
                file.fd, file.kind, file.access, file.name
            )));
        }
    }
    lines
}

fn draw_inspection_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(inspection) = &app.inspection else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 140);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let lines = inspection_lines(inspection);
    let content_height = height.saturating_sub(2) as usize;
    let max_scroll = lines
        .len()
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.inspection_scroll = app.inspection_scroll.min(max_scroll);
    let title = format!(
        " inspect {} [{}]  Enter/r refresh  ↑↓ scroll  Esc close ",
        inspection.name, inspection.pid
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.inspection_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let detail_height = detail_height(app, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(detail_height),
            Constraint::Length(2),
        ])
        .split(area);
    app.page_size = chunks[0].height.saturating_sub(2).max(1) as usize;
    let mut title = match (&app.focus, app.searching) {
        (Some(pid), true) => format!(" psmore  focus={}  search: {}", pid, app.search),
        (Some(pid), false) if !app.search.is_empty() => {
            format!(" psmore  focus={}  filter: {}", pid, app.search)
        }
        (Some(pid), false) => format!(" psmore  focus={} ", pid),
        (None, true) => format!(" psmore  search: {}", app.search),
        (None, false) if !app.search.is_empty() => format!(" psmore  filter: {}", app.search),
        (None, false) => format!(" psmore  {} process relationships ", platform_name()),
    };
    if app.paused {
        title.push_str(" PAUSED ");
    }
    let selected_pid = app.selected_pid();
    let selected_parent =
        selected_pid.and_then(|pid| app.processes.get(&pid).and_then(|p| p.parent));
    let selected_depth = app.visible.get(app.selected).map(|row| row.depth);
    let selected_name =
        selected_pid.and_then(|pid| app.processes.get(&pid).map(|process| process.name.clone()));
    let row_parts: Vec<(String, String)> = app
        .visible
        .iter()
        .map(|row| row_label_and_context(app, row))
        .collect();
    let path_column = row_parts
        .iter()
        .map(|(label, _)| label.width())
        .max()
        .unwrap_or(0)
        + 2;
    let tree_width = chunks[0].width.saturating_sub(2) as usize;
    let path_width = tree_width.saturating_sub(path_column);
    app.advance_marquee(path_width);
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .zip(row_parts.iter())
        .map(|(row, (label, context))| {
            let p = &app.processes[&row.pid];
            let line = format!(
                "{}{}{}",
                label,
                " ".repeat(path_column.saturating_sub(label.width())),
                marquee(
                    context,
                    if Some(row.pid) == selected_pid {
                        app.marquee_offset
                    } else {
                        0
                    },
                    path_width,
                )
            );
            let same_name_as_selected = app.searching
                && Some(row.pid) != selected_pid
                && selected_name
                    .as_deref()
                    .map(|name| name == p.name)
                    .unwrap_or(false);
            let recent_change = app.recent_change(row.pid);
            let sibling_background_allowed = selected_depth.map(|depth| depth > 2).unwrap_or(false);
            let style = if Some(row.pid) == selected_pid {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if same_name_as_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(recent_change, Some(ProcessChange::Started { .. })) {
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(recent_change, Some(ProcessChange::Reparented { .. })) {
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::BOLD)
            } else if sibling_background_allowed
                && selected_parent.is_some()
                && p.parent == selected_parent
                && Some(row.pid) != selected_pid
            {
                // Crossterm has no portable alpha channel. Dim cyan gives
                // sibling rows a clear, approximately 30% emphasis.
                Style::default()
                    .fg(Color::Cyan)
                    .bg(Color::Rgb(0, 64, 72))
                    .add_modifier(Modifier::DIM)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(line).style(style)
        })
        .collect();
    let tree = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    let mut tree_state = ListState::default();
    tree_state.select(Some(app.selected));
    frame.render_stateful_widget(tree, chunks[0], &mut tree_state);

    let detail = if let Some(pid) = app.selected_pid() {
        let p = &app.processes[&pid];
        let command = process_command_line(p);
        let children = app.children.get(&Some(pid)).map(|c| c.len()).unwrap_or(0);
        let mut detail_lines = vec![Line::from(vec![
            Span::styled(
                format!("PID {}", pid),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  PPID {}  children {}  status {}  CPU {:.1}%  MEM {} MB  runtime {}s",
                p.parent
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                children,
                p.status,
                p.cpu,
                p.memory / 1024 / 1024,
                p.runtime
            )),
        ])];
        detail_lines.push(Line::from(command));
        Text::from(detail_lines)
    } else {
        Text::from("No processes found")
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" selected process "),
            )
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    let total_processes = app.processes.len().saturating_sub(1);
    let total_pages = app.visible.len().div_ceil(app.page_size);
    let total_pages = total_pages.max(1);
    let current_page = (app.selected / app.page_size + 1).min(total_pages);
    let live_state = if app.paused { "PAUSED" } else { "LIVE" };
    let footer = Paragraph::new(vec![
        Line::from(format!(
            " {} proc | page {}/{} | {} | +{} -{} ↪{} | Space pause | e changes | q quit ",
            total_processes,
            current_page,
            total_pages,
            live_state,
            app.last_changes.started,
            app.last_changes.exited,
            app.last_changes.reparented,
        )),
        Line::from(" ↑↓/jk move | PgUp/Dn page | ←/→ tree | / find | Enter inspect "),
    ])
    .style(Style::default().fg(if app.paused {
        Color::Yellow
    } else {
        Color::DarkGray
    }));
    frame.render_widget(footer, chunks[2]);

    if app.inspection.is_some() {
        draw_inspection_overlay(frame, app, area);
    } else if app.show_events {
        draw_event_overlay(frame, app, area);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let result = loop {
        terminal.draw(|frame| draw(frame, &mut app))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && app.on_key(key)
        {
            break Ok(());
        }
        if !app.paused && app.last_refresh.elapsed() >= Duration::from_secs(2) {
            app.refresh();
        }
    };
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_process(pid: u32, parent: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: Some(Pid::from_u32(parent)),
            name: name.into(),
            command: format!("/usr/bin/{name}"),
            executable: format!("/usr/bin/{name}"),
            user: "tester".into(),
            cwd: "/tmp".into(),
            cpu: 0.0,
            memory: 0,
            start_time: pid as u64,
            runtime: 0,
            status: "Sleep".into(),
        }
    }

    #[test]
    fn parses_linux_and_macos_ps_rows_without_losing_arguments() {
        let output = b"    1       0 S /lib/systemd/systemd --system --deserialize 48\n\
                       2       0 I [kthreadd]\n\
                   32550       1 S /Applications/Otty.app/Contents/MacOS/Otty --flag value\n";

        let snapshot = parse_ps_snapshot(output);

        assert_eq!(snapshot[&1].ppid, 0);
        assert_eq!(
            snapshot[&1].command,
            "/lib/systemd/systemd --system --deserialize 48"
        );
        assert_eq!(snapshot[&2].state, "I");
        assert_eq!(snapshot[&2].command, "[kthreadd]");
        assert_eq!(
            snapshot[&32550].command,
            "/Applications/Otty.app/Contents/MacOS/Otty --flag value"
        );
    }

    #[test]
    fn ignores_malformed_ps_rows() {
        let snapshot = parse_ps_snapshot(b"PID PPID STAT COMMAND\n 42 1 S /usr/bin/test\n");

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[&42].ppid, 1);
    }

    #[test]
    fn does_not_label_an_unreadable_process_as_system_root() {
        let process = ProcessInfo {
            pid: Pid::from_u32(42),
            parent: Some(Pid::from_u32(1)),
            name: "restricted".into(),
            command: String::new(),
            executable: String::new(),
            user: String::new(),
            cwd: String::new(),
            cpu: 0.0,
            memory: 0,
            start_time: 1,
            runtime: 0,
            status: "Sleep".into(),
        };

        assert_eq!(process_path(&process), "[path unavailable]");
    }

    #[test]
    fn detects_started_exited_and_reparented_processes() {
        let previous = [
            test_process(10, 1, "stable"),
            test_process(11, 1, "exited"),
            test_process(12, 1, "adopted"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        let current = [
            test_process(10, 1, "stable"),
            test_process(12, 2, "adopted"),
            test_process(13, 1, "started"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();

        assert_eq!(
            diff_processes(&previous, &current),
            vec![
                ProcessChange::Exited {
                    pid: Pid::from_u32(11),
                    name: "exited".into(),
                },
                ProcessChange::Reparented {
                    pid: Pid::from_u32(12),
                    name: "adopted".into(),
                    old_parent: Some(Pid::from_u32(1)),
                    new_parent: Some(Pid::from_u32(2)),
                },
                ProcessChange::Started {
                    pid: Pid::from_u32(13),
                    name: "started".into(),
                    parent: Some(Pid::from_u32(1)),
                },
            ]
        );
    }

    #[test]
    fn treats_pid_reuse_as_exit_then_start() {
        let previous_process = test_process(42, 1, "old-worker");
        let mut current_process = test_process(42, 1, "new-worker");
        current_process.start_time += 1;
        let previous = HashMap::from([(previous_process.pid, previous_process)]);
        let current = HashMap::from([(current_process.pid, current_process)]);

        assert!(matches!(
            diff_processes(&previous, &current).as_slice(),
            [ProcessChange::Exited { .. }, ProcessChange::Started { .. }]
        ));
    }

    #[test]
    fn identifies_only_psmore_owned_sampler_processes() {
        let mut sampler = test_process(43, std::process::id(), "ps");
        assert!(is_sampler_process(&sampler));

        sampler.parent = Some(Pid::from_u32(1));
        assert!(!is_sampler_process(&sampler));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn parses_lsof_process_files_and_network_sockets() {
        let process = test_process(42, 1, "server");
        let output = b"p42\ncserver\nu501\nLalice\n\
fcwd\na \ntDIR\nn/opt/service\n\
f3u\nau\ntIPv4\nPTCP\nn127.0.0.1:8080\nTST=LISTEN\n\
f5u\nau\ntunix\nn/var/run/service.sock\n\
f4r\nar\ntREG\nn/opt/service/config.toml\n";

        let inspection = parse_lsof_output(output, &process);

        assert_eq!(inspection.user, "alice");
        assert_eq!(inspection.cwd, "/opt/service");
        assert_eq!(
            inspection.sockets,
            vec![
                SocketInfo {
                    fd: "3u".into(),
                    protocol: "TCP".into(),
                    endpoint: "127.0.0.1:8080".into(),
                    state: "LISTEN".into(),
                },
                SocketInfo {
                    fd: "5u".into(),
                    protocol: "UNIX".into(),
                    endpoint: "/var/run/service.sock".into(),
                    state: String::new(),
                },
            ]
        );
        assert_eq!(
            inspection.files,
            vec![OpenFileInfo {
                fd: "4r".into(),
                kind: "REG".into(),
                access: "r".into(),
                name: "/opt/service/config.toml".into(),
            }]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_ipv4_and_ipv6_endpoints() {
        assert_eq!(
            parse_proc_endpoint("0100007F:494E", false),
            Some(("127.0.0.1:18766".into(), false, 18766))
        );
        assert_eq!(
            parse_proc_endpoint("00000000000000000000000001000000:0016", true),
            Some(("[::1]:22".into(), false, 22))
        );
        assert_eq!(proc_socket_state("TCP", "0A"), "LISTEN");
        assert_eq!(proc_socket_state("UDP", "07"), "UNCONN");
    }
}
