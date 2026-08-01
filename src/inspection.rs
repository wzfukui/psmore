#[cfg(not(target_os = "linux"))]
use std::process::Command;

#[cfg(target_os = "linux")]
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::FileTypeExt,
    path::Path,
};

#[cfg(target_os = "linux")]
use sysinfo::Pid;

#[cfg(target_os = "linux")]
use crate::model::InspectionField;
#[cfg(not(target_os = "linux"))]
use crate::model::LsofFileRecord;
use crate::model::{OpenFileInfo, ProcessInfo, ProcessInspection, SocketInfo};

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
