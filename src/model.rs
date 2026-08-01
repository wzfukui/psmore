use std::{collections::HashMap, time::Instant};

use sysinfo::Pid;

#[derive(Clone, Debug)]
pub(crate) struct ProcessInfo {
    pub(crate) pid: Pid,
    pub(crate) parent: Option<Pid>,
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) executable: String,
    pub(crate) user: String,
    pub(crate) cwd: String,
    pub(crate) cpu: f32,
    pub(crate) memory: u64,
    pub(crate) read_rate: u64,
    pub(crate) write_rate: u64,
    pub(crate) start_time: u64,
    pub(crate) runtime: u64,
    pub(crate) status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProcessChange {
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
    pub(crate) fn pid(&self) -> Pid {
        match self {
            Self::Started { pid, .. } | Self::Exited { pid, .. } | Self::Reparented { pid, .. } => {
                *pid
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessEvent {
    pub(crate) change: ProcessChange,
    pub(crate) observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChangeSummary {
    pub(crate) started: usize,
    pub(crate) exited: usize,
    pub(crate) reparented: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct StatusNotice {
    pub(crate) message: String,
    pub(crate) is_error: bool,
    pub(crate) observed_at: Instant,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct OpenFileInfo {
    pub(crate) fd: String,
    pub(crate) kind: String,
    pub(crate) access: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SocketInfo {
    pub(crate) fd: String,
    pub(crate) protocol: String,
    pub(crate) endpoint: String,
    pub(crate) state: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InspectionField {
    pub(crate) label: String,
    pub(crate) value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessInspection {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) cwd: String,
    pub(crate) runtime: Vec<InspectionField>,
    pub(crate) security: Vec<InspectionField>,
    pub(crate) namespaces: Vec<InspectionField>,
    pub(crate) limits: Vec<InspectionField>,
    pub(crate) sockets: Vec<SocketInfo>,
    pub(crate) files: Vec<OpenFileInfo>,
    pub(crate) warning: Option<String>,
}

impl Default for ProcessInspection {
    fn default() -> Self {
        Self {
            pid: Pid::from_u32(0),
            name: String::new(),
            user: String::new(),
            cwd: String::new(),
            runtime: Vec::new(),
            security: Vec::new(),
            namespaces: Vec::new(),
            limits: Vec::new(),
            sockets: Vec::new(),
            files: Vec::new(),
            warning: None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Default)]
pub(crate) struct LsofFileRecord {
    pub(crate) fd: String,
    pub(crate) kind: String,
    pub(crate) access: String,
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) state: String,
}

fn process_instance_changed(old: &ProcessInfo, new: &ProcessInfo) -> bool {
    old.start_time != 0 && new.start_time != 0 && old.start_time != new.start_time
}

pub(crate) fn diff_processes(
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
pub(crate) struct TreeRow {
    pub(crate) pid: Pid,
    pub(crate) depth: usize,
    // For each ancestor, whether that ancestor is the last sibling.
    pub(crate) last_path: Vec<bool>,
    pub(crate) is_last: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarqueePhase {
    Scrolling,
    TailPause,
    ResetPause,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ResourceAggregate {
    pub(crate) cpu: f32,
    pub(crate) memory: u64,
    pub(crate) read_rate: u64,
    pub(crate) write_rate: u64,
    pub(crate) process_count: usize,
}

impl ResourceAggregate {
    pub(crate) fn add(&mut self, other: Self) {
        self.cpu += other.cpu;
        self.memory = self.memory.saturating_add(other.memory);
        self.read_rate = self.read_rate.saturating_add(other.read_rate);
        self.write_rate = self.write_rate.saturating_add(other.write_rate);
        self.process_count = self.process_count.saturating_add(other.process_count);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum SortMode {
    #[default]
    Stable,
    SubtreeCpu,
    SubtreeMemory,
    SubtreeRead,
    SubtreeWrite,
}

impl SortMode {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Stable => Self::SubtreeCpu,
            Self::SubtreeCpu => Self::SubtreeMemory,
            Self::SubtreeMemory => Self::SubtreeRead,
            Self::SubtreeRead => Self::SubtreeWrite,
            Self::SubtreeWrite => Self::Stable,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::SubtreeCpu => "hot CPU",
            Self::SubtreeMemory => "hot MEM",
            Self::SubtreeRead => "hot READ",
            Self::SubtreeWrite => "hot WRITE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TrendView {
    #[default]
    Compute,
    Io,
}

impl TrendView {
    pub(crate) fn toggle(&mut self) {
        *self = match self {
            Self::Compute => Self::Io,
            Self::Io => Self::Compute,
        };
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Compute => "CPU/MEM",
            Self::Io => "I/O",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum HotspotMetric {
    #[default]
    Cpu,
    Memory,
    Read,
    Write,
}

impl HotspotMetric {
    pub(crate) const ALL: [Self; 4] = [Self::Cpu, Self::Memory, Self::Read, Self::Write];

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Cpu => Self::Memory,
            Self::Memory => Self::Read,
            Self::Read => Self::Write,
            Self::Write => Self::Cpu,
        }
    }

    pub(crate) fn previous(self) -> Self {
        match self {
            Self::Cpu => Self::Write,
            Self::Memory => Self::Cpu,
            Self::Read => Self::Memory,
            Self::Write => Self::Read,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Memory => "MEMORY",
            Self::Read => "DISK READ",
            Self::Write => "DISK WRITE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum HotspotScope {
    #[default]
    Process,
    Subtree,
}

impl HotspotScope {
    pub(crate) fn toggle(&mut self) {
        *self = match self {
            Self::Process => Self::Subtree,
            Self::Subtree => Self::Process,
        };
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Process => "process self",
            Self::Subtree => "service subtree",
        }
    }
}

pub(crate) fn process_path(process: &ProcessInfo) -> String {
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

pub(crate) fn process_command_line(process: &ProcessInfo) -> String {
    if !process.command.is_empty() {
        process.command.clone()
    } else {
        process_path(process)
    }
}
