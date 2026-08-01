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
pub(crate) struct NetworkListener {
    pub(crate) pid: Option<Pid>,
    pub(crate) process: String,
    pub(crate) fd: String,
    pub(crate) protocol: String,
    pub(crate) endpoint: String,
    pub(crate) state: String,
    pub(crate) namespace: String,
}

impl NetworkListener {
    pub(crate) fn matches(&self, query: &str) -> bool {
        let query = query.to_lowercase();
        query.is_empty()
            || format!(
                "{} {} {} {} {} {} {}",
                self.protocol,
                self.endpoint,
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NetworkScan {
    pub(crate) listeners: Vec<NetworkListener>,
    pub(crate) warning: Option<String>,
}

fn sort_listeners(listeners: &mut [NetworkListener]) {
    listeners.sort_by(|left, right| {
        (
            &left.protocol,
            &left.endpoint,
            &left.namespace,
            left.pid.map(Pid::as_u32),
            &left.fd,
        )
            .cmp(&(
                &right.protocol,
                &right.endpoint,
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
fn flush_lsof_listener(record: &mut LsofNetworkRecord, listeners: &mut Vec<NetworkListener>) {
    if record.pid.is_some() && !record.protocol.is_empty() && !record.endpoint.is_empty() {
        listeners.push(NetworkListener {
            pid: record.pid,
            process: record.process.clone(),
            fd: record.fd.clone(),
            protocol: record.protocol.clone(),
            endpoint: record.endpoint.clone(),
            state: if record.state.is_empty() {
                if record.protocol == "UDP" {
                    "BOUND".into()
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
pub(crate) fn parse_lsof_network_output(output: &[u8]) -> Vec<NetworkListener> {
    let mut listeners = Vec::new();
    let mut record = LsofNetworkRecord::default();
    for line in String::from_utf8_lossy(output).lines() {
        if line.is_empty() {
            continue;
        }
        let (field, value) = line.split_at(1);
        match field {
            "p" => {
                flush_lsof_listener(&mut record, &mut listeners);
                record.pid = value.parse::<u32>().ok().map(Pid::from_u32);
                record.process.clear();
            }
            "c" => record.process = value.to_string(),
            "f" => {
                flush_lsof_listener(&mut record, &mut listeners);
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
    flush_lsof_listener(&mut record, &mut listeners);
    listeners
}

#[cfg(not(target_os = "linux"))]
fn scan_network_native(_processes: &HashMap<Pid, ProcessInfo>) -> NetworkScan {
    let mut listeners = Vec::new();
    let mut errors = Vec::new();
    for args in [
        ["-nP", "-iTCP", "-sTCP:LISTEN", "-FpcfPnT"].as_slice(),
        ["-nP", "-iUDP", "-FpcfPnT"].as_slice(),
    ] {
        match Command::new("lsof").args(args).output() {
            Ok(output) => listeners.extend(parse_lsof_network_output(&output.stdout)),
            Err(error) => errors.push(error.to_string()),
        }
    }
    listeners.sort_by(|left, right| {
        (
            left.pid.map(Pid::as_u32),
            &left.fd,
            &left.protocol,
            &left.endpoint,
        )
            .cmp(&(
                right.pid.map(Pid::as_u32),
                &right.fd,
                &right.protocol,
                &right.endpoint,
            ))
    });
    listeners.dedup();
    sort_listeners(&mut listeners);
    NetworkScan {
        listeners,
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
pub(crate) struct LinuxRawListener {
    pub(crate) protocol: String,
    pub(crate) endpoint: String,
    pub(crate) state: String,
    pub(crate) inode: String,
    pub(crate) namespace: String,
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_inet_listeners(
    content: &str,
    protocol: &str,
    ipv6: bool,
    namespace: &str,
) -> Vec<LinuxRawListener> {
    let mut listeners = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(state), Some(inode)) = (fields.get(1), fields.get(3), fields.get(9))
        else {
            continue;
        };
        if protocol == "TCP" && *state != "0A" {
            continue;
        }
        let Some((endpoint, _, port)) = parse_proc_endpoint(local, ipv6) else {
            continue;
        };
        if port == 0 {
            continue;
        }
        listeners.push(LinuxRawListener {
            protocol: protocol.into(),
            endpoint,
            state: if protocol == "UDP" {
                if *state == "07" {
                    "BOUND".into()
                } else {
                    proc_socket_state(protocol, state).into()
                }
            } else {
                "LISTEN".into()
            },
            inode: (*inode).into(),
            namespace: namespace.into(),
        });
    }
    listeners
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_linux_unix_listeners(content: &str, namespace: &str) -> Vec<LinuxRawListener> {
    let mut listeners = Vec::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(flags), Some(inode)) = (fields.get(3), fields.get(6)) else {
            continue;
        };
        let listening = u32::from_str_radix(flags, 16)
            .map(|flags| flags & 0x0001_0000 != 0)
            .unwrap_or(false);
        if !listening {
            continue;
        }
        listeners.push(LinuxRawListener {
            protocol: "UNIX".into(),
            endpoint: fields
                .get(7..)
                .map(|parts| parts.join(" "))
                .filter(|path| !path.is_empty())
                .unwrap_or_else(|| format!("socket:[{inode}]")),
            state: "LISTEN".into(),
            inode: (*inode).into(),
            namespace: namespace.into(),
        });
    }
    listeners
}

#[cfg(target_os = "linux")]
fn scan_network_native(processes: &HashMap<Pid, ProcessInfo>) -> NetworkScan {
    let mut owners: HashMap<String, Vec<LinuxSocketOwner>> = HashMap::new();
    let mut namespace_representatives: HashMap<String, Pid> = HashMap::new();
    let mut protected_processes = 0_usize;
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
    for (namespace, pid) in namespace_representatives {
        let net_root = format!("/proc/{pid}/net");
        for (file, protocol, ipv6) in [
            ("tcp", "TCP", false),
            ("tcp6", "TCP", true),
            ("udp", "UDP", false),
            ("udp6", "UDP", true),
        ] {
            if let Ok(content) = fs::read_to_string(format!("{net_root}/{file}")) {
                raw.extend(parse_linux_inet_listeners(
                    &content, protocol, ipv6, &namespace,
                ));
            }
        }
        if let Ok(content) = fs::read_to_string(format!("{net_root}/unix")) {
            raw.extend(parse_linux_unix_listeners(&content, &namespace));
        }
    }

    let mut listeners = Vec::new();
    for listener in raw {
        let matching_owners = owners
            .get(&listener.inode)
            .map(|owners| {
                owners
                    .iter()
                    .filter(|owner| owner.namespace == listener.namespace)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if matching_owners.is_empty() {
            listeners.push(NetworkListener {
                pid: None,
                process: "[owner unavailable]".into(),
                fd: "-".into(),
                protocol: listener.protocol,
                endpoint: listener.endpoint,
                state: listener.state,
                namespace: listener.namespace,
            });
        } else {
            for owner in matching_owners {
                listeners.push(NetworkListener {
                    pid: Some(owner.pid),
                    process: owner.process.clone(),
                    fd: owner.fd.clone(),
                    protocol: listener.protocol.clone(),
                    endpoint: listener.endpoint.clone(),
                    state: listener.state.clone(),
                    namespace: listener.namespace.clone(),
                });
            }
        }
    }
    sort_listeners(&mut listeners);
    NetworkScan {
        listeners,
        warning: (protected_processes > 0).then(|| {
            format!("socket ownership hidden for {protected_processes} protected processes")
        }),
    }
}

pub(crate) fn scan_network(processes: &HashMap<Pid, ProcessInfo>) -> NetworkScan {
    scan_network_native(processes)
}
