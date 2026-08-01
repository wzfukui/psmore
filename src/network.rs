use std::collections::HashMap;

#[cfg(not(target_os = "linux"))]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{collections::HashSet, fs};

use sysinfo::Pid;

#[cfg(target_os = "linux")]
use crate::inspection::{parse_proc_endpoint, proc_socket_state};
use crate::model::ProcessInfo;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NetworkEndpoint {
    pub(crate) pid: Option<Pid>,
    pub(crate) process: String,
    pub(crate) fd: String,
    pub(crate) protocol: String,
    pub(crate) local_endpoint: String,
    pub(crate) remote_endpoint: String,
    pub(crate) state: String,
    pub(crate) namespace: String,
}

impl NetworkEndpoint {
    pub(crate) fn is_listener(&self) -> bool {
        self.state == "LISTEN"
            || (self.protocol == "UDP"
                && self.remote_endpoint.is_empty()
                && matches!(self.state.as_str(), "BOUND" | "UNCONN"))
    }

    pub(crate) fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        query.is_empty()
            || format!(
                "{} {} {} {} {} {} {} {}",
                self.protocol,
                self.local_endpoint,
                self.remote_endpoint,
                self.state,
                self.process,
                self.pid.map(|pid| pid.to_string()).unwrap_or_default(),
                self.fd,
                self.namespace
            )
            .to_lowercase()
            .contains(&query)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum NetworkScope {
    #[default]
    Listeners,
    All,
}

impl NetworkScope {
    pub(crate) fn toggle(&mut self) {
        *self = match self {
            Self::Listeners => Self::All,
            Self::All => Self::Listeners,
        };
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Listeners => "listeners",
            Self::All => "all connections",
        }
    }

    pub(crate) fn includes(self, endpoint: &NetworkEndpoint) -> bool {
        self == Self::All || endpoint.is_listener()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NetworkScan {
    pub(crate) endpoints: Vec<NetworkEndpoint>,
    pub(crate) warning: Option<String>,
}

fn sort_endpoints(endpoints: &mut [NetworkEndpoint]) {
    endpoints.sort_by(|left, right| {
        (
            &left.protocol,
            &left.local_endpoint,
            &left.remote_endpoint,
            &left.state,
            &left.namespace,
            left.pid.map(Pid::as_u32),
            &left.fd,
        )
            .cmp(&(
                &right.protocol,
                &right.local_endpoint,
                &right.remote_endpoint,
                &right.state,
                &right.namespace,
                right.pid.map(Pid::as_u32),
                &right.fd,
            ))
    });
}

#[cfg(not(target_os = "linux"))]
#[derive(Default)]
struct LsofNetworkRecord {
    pid: Option<Pid>,
    process: String,
    fd: String,
    protocol: String,
    endpoint: String,
    state: String,
}

#[cfg(not(target_os = "linux"))]
fn flush_lsof_endpoint(record: &mut LsofNetworkRecord, endpoints: &mut Vec<NetworkEndpoint>) {
    if record.pid.is_some() && !record.protocol.is_empty() && !record.endpoint.is_empty() {
        let (local_endpoint, remote_endpoint) = record
            .endpoint
            .split_once("->")
            .map(|(local, remote)| (local.to_string(), remote.to_string()))
            .unwrap_or_else(|| (record.endpoint.clone(), String::new()));
        endpoints.push(NetworkEndpoint {
            pid: record.pid,
            process: record.process.clone(),
            fd: record.fd.clone(),
            protocol: record.protocol.clone(),
            local_endpoint,
            remote_endpoint: remote_endpoint.clone(),
            state: if record.state.is_empty() {
                if !remote_endpoint.is_empty() {
                    "CONNECTED".into()
                } else if record.protocol == "UDP" {
                    "BOUND".into()
                } else if record.protocol == "UNIX" {
                    "OPEN".into()
                } else {
                    "-".into()
                }
            } else {
                record.state.clone()
            },
            namespace: String::new(),
        });
    }
    record.fd.clear();
    record.protocol.clear();
    record.endpoint.clear();
    record.state.clear();
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn parse_lsof_network_output(output: &[u8]) -> Vec<NetworkEndpoint> {
    let mut endpoints = Vec::new();
    let mut record = LsofNetworkRecord::default();
    for line in String::from_utf8_lossy(output).lines() {
        if line.is_empty() {
            continue;
        }
        let (field, value) = line.split_at(1);
        match field {
            "p" => {
                flush_lsof_endpoint(&mut record, &mut endpoints);
                record.pid = value.parse::<u32>().ok().map(Pid::from_u32);
                record.process.clear();
            }
            "c" => record.process = value.to_string(),
            "f" => {
                flush_lsof_endpoint(&mut record, &mut endpoints);
                record.fd = value.to_string();
            }
            "P" => record.protocol = value.to_string(),
            "n" => record.endpoint = value.to_string(),
            "T" => {
                if let Some(state) = value.strip_prefix("ST=") {
                    record.state = state.to_string();
                }
            }
            _ => {}
        }
    }
    flush_lsof_endpoint(&mut record, &mut endpoints);
    endpoints
}

#[cfg(not(target_os = "linux"))]
fn scan_network_native(_processes: &HashMap<Pid, ProcessInfo>) -> NetworkScan {
    let mut endpoints = Vec::new();
    let mut errors = Vec::new();
    for args in [
        ["-nP", "-iTCP", "-FpcfPnT"].as_slice(),
        ["-nP", "-iUDP", "-FpcfPnT"].as_slice(),
        ["-nP", "-U", "-FpcfPnT"].as_slice(),
    ] {
        match Command::new("lsof").args(args).output() {
            Ok(output) => {
                endpoints.extend(parse_lsof_network_output(&output.stdout));
                let detail = String::from_utf8_lossy(&output.stderr);
                if !output.status.success() && !detail.trim().is_empty() {
                    errors.push(detail.trim().to_string());
                }
            }
            Err(error) => errors.push(error.to_string()),
        }
    }
    endpoints.sort_by(|left, right| {
        (
            left.pid.map(Pid::as_u32),
            &left.fd,
            &left.protocol,
            &left.local_endpoint,
            &left.remote_endpoint,
        )
            .cmp(&(
                right.pid.map(Pid::as_u32),
                &right.fd,
                &right.protocol,
                &right.local_endpoint,
                &right.remote_endpoint,
            ))
    });
    endpoints.dedup();
    sort_endpoints(&mut endpoints);
    NetworkScan {
        endpoints,
        warning: (!errors.is_empty()).then(|| format!("cannot run lsof: {}", errors.join("; "))),
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
struct LinuxSocketOwner {
    pid: Pid,
    process: String,
    fd: String,
    namespace: String,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct LinuxRawSocket {
    pub(crate) protocol: String,
    pub(crate) local_endpoint: String,
    pub(crate) remote_endpoint: String,
    pub(crate) state: String,
    pub(crate) inode: String,
    pub(crate) namespace: String,
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_inet_sockets(
    content: &str,
    protocol: &str,
    ipv6: bool,
    namespace: &str,
) -> Vec<LinuxRawSocket> {
    let mut sockets = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(remote), Some(state), Some(inode)) =
            (fields.get(1), fields.get(2), fields.get(3), fields.get(9))
        else {
            continue;
        };
        let Some((local_endpoint, _, port)) = parse_proc_endpoint(local, ipv6) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let Some((remote_endpoint, remote_unspecified, remote_port)) =
            parse_proc_endpoint(remote, ipv6)
        else {
            continue;
        };
        let remote_endpoint = if remote_unspecified && remote_port == 0 {
            String::new()
        } else {
            remote_endpoint
        };
        sockets.push(LinuxRawSocket {
            protocol: protocol.into(),
            local_endpoint,
            remote_endpoint: remote_endpoint.clone(),
            state: if protocol == "UDP" && remote_endpoint.is_empty() && *state == "07" {
                "BOUND".into()
            } else {
                proc_socket_state(protocol, state).into()
            },
            inode: (*inode).into(),
            namespace: namespace.into(),
        });
    }
    sockets
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_unix_sockets(content: &str, namespace: &str) -> Vec<LinuxRawSocket> {
    let mut sockets = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(flags), Some(state), Some(inode)) = (fields.get(3), fields.get(5), fields.get(6))
        else {
            continue;
        };
        let listening = u32::from_str_radix(flags, 16)
            .map(|flags| flags & 0x0001_0000 != 0)
            .unwrap_or(false);
        sockets.push(LinuxRawSocket {
            protocol: "UNIX".into(),
            local_endpoint: fields
                .get(7..)
                .map(|parts| parts.join(" "))
                .filter(|path| !path.is_empty())
                .unwrap_or_else(|| format!("socket:[{inode}]")),
            remote_endpoint: String::new(),
            state: if listening {
                "LISTEN"
            } else {
                match *state {
                    "03" => "CONNECTED",
                    "02" => "CONNECTING",
                    "01" => "OPEN",
                    _ => "UNKNOWN",
                }
            }
            .into(),
            inode: (*inode).into(),
            namespace: namespace.into(),
        });
    }
    sockets
}

#[cfg(target_os = "linux")]
fn scan_network_native(processes: &HashMap<Pid, ProcessInfo>) -> NetworkScan {
    let mut owners: HashMap<String, Vec<LinuxSocketOwner>> = HashMap::new();
    let mut namespace_representatives: HashMap<String, Pid> = HashMap::new();
    let mut protected_processes = 0_usize;
    let mut unknown_namespaces = 0_usize;
    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0)
    {
        let proc_root = format!("/proc/{}", process.pid);
        let namespace = fs::read_link(format!("{proc_root}/ns/net"))
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !namespace.is_empty() {
            namespace_representatives
                .entry(namespace.clone())
                .or_insert(process.pid);
        } else {
            unknown_namespaces += 1;
        }
        let Ok(entries) = fs::read_dir(format!("{proc_root}/fd")) else {
            protected_processes += 1;
            continue;
        };
        for entry in entries.flatten() {
            let Ok(target) = fs::read_link(entry.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|value| value.strip_suffix(']'))
            else {
                continue;
            };
            owners
                .entry(inode.into())
                .or_default()
                .push(LinuxSocketOwner {
                    pid: process.pid,
                    process: process.name.clone(),
                    fd: entry.file_name().to_string_lossy().into_owned(),
                    namespace: namespace.clone(),
                });
        }
    }

    let mut raw = HashSet::new();
    let mut unreadable_tables = 0_usize;
    for (namespace, pid) in namespace_representatives {
        let net_root = format!("/proc/{pid}/net");
        for (file, protocol, ipv6) in [
            ("tcp", "TCP", false),
            ("tcp6", "TCP", true),
            ("udp", "UDP", false),
            ("udp6", "UDP", true),
        ] {
            match fs::read_to_string(format!("{net_root}/{file}")) {
                Ok(content) => raw.extend(parse_linux_inet_sockets(
                    &content, protocol, ipv6, &namespace,
                )),
                Err(_) => unreadable_tables += 1,
            }
        }
        match fs::read_to_string(format!("{net_root}/unix")) {
            Ok(content) => raw.extend(parse_linux_unix_sockets(&content, &namespace)),
            Err(_) => unreadable_tables += 1,
        }
    }

    let mut endpoints = Vec::new();
    for endpoint in raw {
        let matching_owners = owners
            .get(&endpoint.inode)
            .map(|owners| {
                owners
                    .iter()
                    .filter(|owner| owner.namespace == endpoint.namespace)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if matching_owners.is_empty() {
            endpoints.push(NetworkEndpoint {
                pid: None,
                process: "[owner unavailable]".into(),
                fd: "-".into(),
                protocol: endpoint.protocol,
                local_endpoint: endpoint.local_endpoint,
                remote_endpoint: endpoint.remote_endpoint,
                state: endpoint.state,
                namespace: endpoint.namespace,
            });
        } else {
            for owner in matching_owners {
                endpoints.push(NetworkEndpoint {
                    pid: Some(owner.pid),
                    process: owner.process.clone(),
                    fd: owner.fd.clone(),
                    protocol: endpoint.protocol.clone(),
                    local_endpoint: endpoint.local_endpoint.clone(),
                    remote_endpoint: endpoint.remote_endpoint.clone(),
                    state: endpoint.state.clone(),
                    namespace: endpoint.namespace.clone(),
                });
            }
        }
    }
    sort_endpoints(&mut endpoints);
    let mut warnings = Vec::new();
    if protected_processes > 0 && protected_processes == unknown_namespaces {
        warnings.push(format!(
            "socket ownership and network namespace were hidden or disappeared for {protected_processes} processes"
        ));
    } else {
        if protected_processes > 0 {
            warnings.push(format!(
                "socket ownership hidden for {protected_processes} protected processes"
            ));
        }
        if unknown_namespaces > 0 {
            warnings.push(format!(
                "network namespace was unreadable or disappeared for {unknown_namespaces} processes"
            ));
        }
    }
    if unreadable_tables > 0 {
        warnings.push(format!(
            "{unreadable_tables} network namespace socket table(s) were unreadable"
        ));
    }
    NetworkScan {
        endpoints,
        warning: (!warnings.is_empty()).then(|| warnings.join("; ")),
    }
}

pub(crate) fn scan_network(processes: &HashMap<Pid, ProcessInfo>) -> NetworkScan {
    scan_network_native(processes)
}
