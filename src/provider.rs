use std::{
    collections::{HashMap, HashSet},
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::model::ProcessInfo;

// sysinfo refreshes the user list through libc's getpwent/setpwent/endpwent,
// which are not thread-safe: concurrent calls race on a shared static FILE.
// glibc happens to survive the race; musl segfaults inside its stdio locking.
// Serialize refreshes so concurrent capture threads stay safe on both.
static USERS_REFRESH_LOCK: Mutex<()> = Mutex::new(());

fn refreshed_users() -> Users {
    let _guard = USERS_REFRESH_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Users::new_with_refreshed_list()
}

pub(crate) trait ProcessProvider {
    fn refresh(&mut self) -> Vec<ProcessInfo>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeProcessSnapshot {
    pub(crate) ppid: u32,
    pub(crate) state: String,
    pub(crate) command: String,
}

pub(crate) fn parse_ps_snapshot(output: &[u8]) -> HashMap<u32, NativeProcessSnapshot> {
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

pub(crate) fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

pub(crate) fn is_sampler_process(process: &ProcessInfo, psmore_pids: &HashSet<Pid>) -> bool {
    let is_ps = process.name.trim_matches(['(', ')']) == "ps";
    let parent_is_psmore = process
        .parent
        .map(|parent| parent == Pid::from_u32(std::process::id()) || psmore_pids.contains(&parent))
        .unwrap_or(false);
    is_ps && parent_is_psmore
}

pub(crate) struct NativeProcessProvider {
    system: System,
    users: Users,
    io_instances: HashMap<Pid, u64>,
    last_sample: Option<Instant>,
}

#[derive(Clone, Debug)]
pub(crate) struct HostMetrics {
    pub(crate) hostname: String,
    pub(crate) load_one: f64,
    pub(crate) cpu_percent: f32,
    pub(crate) memory_used: u64,
    pub(crate) memory_total: u64,
    pub(crate) swap_used: u64,
    pub(crate) swap_total: u64,
}

impl NativeProcessProvider {
    pub(crate) fn new() -> Self {
        Self {
            system: System::new(),
            users: refreshed_users(),
            io_instances: HashMap::new(),
            last_sample: None,
        }
    }

    pub(crate) fn host_metrics(&self) -> HostMetrics {
        HostMetrics {
            // Absence stays an empty sentinel so the UI can localize the
            // fallback label in the user's language.
            hostname: System::host_name().unwrap_or_default(),
            load_one: System::load_average().one,
            cpu_percent: self.system.global_cpu_usage(),
            memory_used: self.system.used_memory(),
            memory_total: self.system.total_memory(),
            swap_used: self.system.used_swap(),
            swap_total: self.system.total_swap(),
        }
    }
}

pub(crate) fn bytes_per_second(bytes: u64, elapsed: Duration) -> u64 {
    if bytes == 0 || elapsed.is_zero() {
        return 0;
    }
    (bytes as f64 / elapsed.as_secs_f64())
        .round()
        .clamp(0.0, u64::MAX as f64) as u64
}

impl ProcessProvider for NativeProcessProvider {
    fn refresh(&mut self) -> Vec<ProcessInfo> {
        let sampled_at = Instant::now();
        let elapsed = self
            .last_sample
            .replace(sampled_at)
            .map(|previous| sampled_at.saturating_duration_since(previous));
        // Host-wide CPU and memory ride the same refresh cycle as the
        // process list so the status bar never needs a second System.
        self.system.refresh_memory();
        self.system.refresh_cpu_usage();
        // A process relationship tool should not silently mix Linux tasks
        // (threads) into the process tree. Besides being noisy, task IDs are
        // short-lived and can look like stale child processes between samples.
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_memory()
                .with_cpu()
                .with_disk_usage()
                .with_user(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::Always)
                .with_exe(UpdateKind::OnlyIfNotSet)
                .without_tasks(),
        );
        let mut active_instances = HashSet::new();
        let mut processes = Vec::with_capacity(self.system.processes().len());
        for process in self.system.processes().values() {
            let instance_is_known = self
                .io_instances
                .get(&process.pid())
                .map(|start_time| *start_time == process.start_time())
                .unwrap_or(false);
            let disk = process.disk_usage();
            let (read_rate, write_rate) = if instance_is_known {
                elapsed
                    .map(|elapsed| {
                        (
                            bytes_per_second(disk.read_bytes, elapsed),
                            bytes_per_second(disk.written_bytes, elapsed),
                        )
                    })
                    .unwrap_or_default()
            } else {
                (0, 0)
            };
            self.io_instances
                .insert(process.pid(), process.start_time());
            active_instances.insert(process.pid());
            processes.push(ProcessInfo {
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
                read_rate,
                write_rate,
                start_time: process.start_time(),
                runtime: process.run_time(),
                status: format!("{:?}", process.status()),
            });
        }
        self.io_instances
            .retain(|pid, _| active_instances.contains(pid));

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
                read_rate: 0,
                write_rate: 0,
                start_time: 0,
                runtime: 0,
                status: state,
            });
        }
        // sysinfo can observe a native sampler from this or another psmore
        // instance during a narrow timing window. It is an implementation
        // detail, not a process event the user should have to reason about.
        let psmore_pids: HashSet<Pid> = processes
            .iter()
            .filter(|process| process.name == "psmore")
            .map(|process| process.pid)
            .collect();
        processes.retain(|process| !is_sampler_process(process, &psmore_pids));

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
            read_rate: 0,
            write_rate: 0,
            start_time: 0,
            runtime: 0,
            status: "VirtualRoot".into(),
        });
        processes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn concurrent_provider_construction_does_not_crash() {
        // Regression test: concurrent sysinfo user-list refreshes race on
        // libc's non-thread-safe passwd iteration and segfault on musl.
        let handles: Vec<_> = (0..8)
            .map(|_| thread::spawn(NativeProcessProvider::new))
            .collect();
        for handle in handles {
            handle.join().expect("provider construction panicked");
        }
    }
}
