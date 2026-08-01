use std::{
    collections::{HashMap, HashSet},
    path::Path,
    process::{Command, Stdio},
};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

use crate::model::ProcessInfo;

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
}

impl NativeProcessProvider {
    pub(crate) fn new() -> Self {
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
            start_time: 0,
            runtime: 0,
            status: "VirtualRoot".into(),
        });
        processes
    }
}
