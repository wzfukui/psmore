use std::{collections::HashMap, time::Instant};

use sysinfo::Pid;

use crate::model::{ProcessInfo, ResourceAggregate};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProcessSnapshotEntry {
    pub(crate) pid: Pid,
    pub(crate) parent: Option<Pid>,
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) start_time: u64,
    pub(crate) own_cpu: f32,
    pub(crate) own_memory: u64,
    pub(crate) own_read_rate: u64,
    pub(crate) own_write_rate: u64,
    pub(crate) subtree: ResourceAggregate,
}

impl ProcessSnapshotEntry {
    fn capture(process: &ProcessInfo, subtree: ResourceAggregate) -> Self {
        Self {
            pid: process.pid,
            parent: process.parent,
            name: process.name.clone(),
            command: process.command.clone(),
            start_time: process.start_time,
            own_cpu: process.cpu,
            own_memory: process.memory,
            own_read_rate: process.read_rate,
            own_write_rate: process.write_rate,
            subtree,
        }
    }

    fn same_instance(&self, process: &ProcessInfo) -> bool {
        if self.start_time != 0 || process.start_time != 0 {
            self.start_time != 0 && process.start_time != 0 && self.start_time == process.start_time
        } else {
            self.name == process.name && self.command == process.command
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BaselineSnapshot {
    pub(crate) captured_at: Instant,
    entries: HashMap<Pid, ProcessSnapshotEntry>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReparentedSnapshotEntry {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) old_parent: Option<Pid>,
    pub(crate) new_parent: Option<Pid>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SnapshotResourceDelta {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) own_cpu: f32,
    pub(crate) subtree_cpu: f32,
    pub(crate) own_memory: i128,
    pub(crate) subtree_memory: i128,
    pub(crate) own_read_rate: i128,
    pub(crate) own_write_rate: i128,
    pub(crate) subtree_read_rate: i128,
    pub(crate) subtree_write_rate: i128,
    pub(crate) subtree_processes: i128,
    pub(crate) current_subtree: ResourceAggregate,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SnapshotDiff {
    pub(crate) started: Vec<ProcessSnapshotEntry>,
    pub(crate) exited: Vec<ProcessSnapshotEntry>,
    pub(crate) reparented: Vec<ReparentedSnapshotEntry>,
    pub(crate) resource_deltas: Vec<SnapshotResourceDelta>,
    pub(crate) system_delta: Option<SnapshotResourceDelta>,
}

fn unsigned_delta(current: u64, baseline: u64) -> i128 {
    i128::from(current) - i128::from(baseline)
}

fn count_delta(current: usize, baseline: usize) -> i128 {
    i128::try_from(current).unwrap_or(i128::MAX) - i128::try_from(baseline).unwrap_or(i128::MAX)
}

impl BaselineSnapshot {
    pub(crate) fn capture(
        processes: &HashMap<Pid, ProcessInfo>,
        resources: &HashMap<Pid, ResourceAggregate>,
        captured_at: Instant,
    ) -> Self {
        let entries = processes
            .values()
            .map(|process| {
                let subtree = resources.get(&process.pid).copied().unwrap_or_default();
                (process.pid, ProcessSnapshotEntry::capture(process, subtree))
            })
            .collect();
        Self {
            captured_at,
            entries,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len().saturating_sub(1)
    }

    pub(crate) fn diff(
        &self,
        processes: &HashMap<Pid, ProcessInfo>,
        resources: &HashMap<Pid, ResourceAggregate>,
    ) -> SnapshotDiff {
        let root = Pid::from_u32(0);
        let mut pids: Vec<Pid> = self
            .entries
            .keys()
            .chain(processes.keys())
            .copied()
            .collect();
        pids.sort_by_key(|pid| pid.as_u32());
        pids.dedup();

        let mut diff = SnapshotDiff::default();
        for pid in pids {
            match (self.entries.get(&pid), processes.get(&pid)) {
                (None, Some(process)) => {
                    if pid != root {
                        diff.started.push(ProcessSnapshotEntry::capture(
                            process,
                            resources.get(&pid).copied().unwrap_or_default(),
                        ));
                    }
                }
                (Some(entry), None) => {
                    if pid != root {
                        diff.exited.push(entry.clone());
                    }
                }
                (Some(entry), Some(process)) if !entry.same_instance(process) => {
                    if pid != root {
                        diff.exited.push(entry.clone());
                        diff.started.push(ProcessSnapshotEntry::capture(
                            process,
                            resources.get(&pid).copied().unwrap_or_default(),
                        ));
                    }
                }
                (Some(entry), Some(process)) => {
                    if pid != root && entry.parent != process.parent {
                        diff.reparented.push(ReparentedSnapshotEntry {
                            pid,
                            name: process.name.clone(),
                            old_parent: entry.parent,
                            new_parent: process.parent,
                        });
                    }
                    let current_subtree = resources.get(&pid).copied().unwrap_or_default();
                    let delta = SnapshotResourceDelta {
                        pid,
                        name: process.name.clone(),
                        own_cpu: process.cpu - entry.own_cpu,
                        subtree_cpu: current_subtree.cpu - entry.subtree.cpu,
                        own_memory: unsigned_delta(process.memory, entry.own_memory),
                        subtree_memory: unsigned_delta(
                            current_subtree.memory,
                            entry.subtree.memory,
                        ),
                        own_read_rate: unsigned_delta(process.read_rate, entry.own_read_rate),
                        own_write_rate: unsigned_delta(process.write_rate, entry.own_write_rate),
                        subtree_read_rate: unsigned_delta(
                            current_subtree.read_rate,
                            entry.subtree.read_rate,
                        ),
                        subtree_write_rate: unsigned_delta(
                            current_subtree.write_rate,
                            entry.subtree.write_rate,
                        ),
                        subtree_processes: count_delta(
                            current_subtree.process_count,
                            entry.subtree.process_count,
                        ),
                        current_subtree,
                    };
                    if pid == root {
                        diff.system_delta = Some(delta);
                    } else {
                        diff.resource_deltas.push(delta);
                    }
                }
                (None, None) => {}
            }
        }
        diff
    }
}
