use std::{fmt, time::Instant};

use sysinfo::{Pid, ProcessesToUpdate, Signal, System};

use crate::model::{ProcessInfo, process_command_line};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessActionKind {
    Terminate,
    Kill,
    Stop,
    Continue,
}

impl ProcessActionKind {
    pub(crate) const ALL: [Self; 4] = [Self::Terminate, Self::Kill, Self::Stop, Self::Continue];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Terminate => "TERM",
            Self::Kill => "KILL",
            Self::Stop => "STOP",
            Self::Continue => "CONT",
        }
    }

    pub(crate) fn description(self) -> &'static str {
        match self {
            Self::Terminate => "request a graceful shutdown",
            Self::Kill => "force immediate termination",
            Self::Stop => "suspend process execution",
            Self::Continue => "resume a stopped process",
        }
    }

    pub(crate) fn shortcut(self) -> char {
        match self {
            Self::Terminate => 't',
            Self::Kill => 'k',
            Self::Stop => 's',
            Self::Continue => 'c',
        }
    }

    fn signal(self) -> Signal {
        match self {
            Self::Terminate => Signal::Term,
            Self::Kill => Signal::Kill,
            Self::Stop => Signal::Stop,
            Self::Continue => Signal::Continue,
        }
    }
}

impl fmt::Display for ProcessActionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessActionTarget {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) start_time: u64,
}

impl From<&ProcessInfo> for ProcessActionTarget {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid,
            name: process.name.clone(),
            command: process_command_line(process),
            start_time: process.start_time,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessActionDialog {
    pub(crate) target: ProcessActionTarget,
    pub(crate) selected: usize,
    pub(crate) confirming: bool,
}

impl ProcessActionDialog {
    pub(crate) fn selected_action(&self) -> ProcessActionKind {
        ProcessActionKind::ALL[self.selected.min(ProcessActionKind::ALL.len() - 1)]
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProcessActionOutcome {
    Sent,
    Refused(String),
    Failed(String),
}

impl ProcessActionOutcome {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Refused(_) => "refused",
            Self::Failed(_) => "failed",
        }
    }

    pub(crate) fn detail(&self) -> Option<&str> {
        match self {
            Self::Sent => None,
            Self::Refused(detail) | Self::Failed(detail) => Some(detail),
        }
    }

    pub(crate) fn is_error(&self) -> bool {
        !matches!(self, Self::Sent)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessActionRecord {
    pub(crate) observed_at: Instant,
    pub(crate) target: ProcessActionTarget,
    pub(crate) action: ProcessActionKind,
    pub(crate) outcome: ProcessActionOutcome,
}

fn validate_process_instance(
    target: &ProcessActionTarget,
    current_start_time: Option<u64>,
    own_pid: u32,
) -> Result<(), String> {
    let pid = target.pid.as_u32();
    if pid <= 1 {
        return Err(format!("PID {pid} is a protected system process"));
    }
    if pid == own_pid {
        return Err("psmore cannot signal its own process".into());
    }
    let Some(current_start_time) = current_start_time else {
        return Err("process exited before the action was confirmed".into());
    };
    if target.start_time == 0 || current_start_time == 0 {
        return Err("process instance identity is unavailable; refusing an unsafe action".into());
    }
    if target.start_time != current_start_time {
        return Err("PID was reused by a different process instance".into());
    }
    Ok(())
}

pub(crate) fn execute_process_action(
    target: &ProcessActionTarget,
    action: ProcessActionKind,
) -> ProcessActionOutcome {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[target.pid]), true);
    let process = system.process(target.pid);
    if let Err(reason) = validate_process_instance(
        target,
        process.map(|process| process.start_time()),
        std::process::id(),
    ) {
        return ProcessActionOutcome::Refused(reason);
    }
    match process.and_then(|process| process.kill_with(action.signal())) {
        Some(true) => ProcessActionOutcome::Sent,
        Some(false) => ProcessActionOutcome::Failed(
            "the operating system rejected the signal (check ownership and privileges)".into(),
        ),
        None => ProcessActionOutcome::Failed(format!(
            "{} is not supported on this platform",
            action.label()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::{
        process::{Child, Command},
        thread,
        time::Duration,
    };

    fn target(pid: u32, start_time: u64) -> ProcessActionTarget {
        ProcessActionTarget {
            pid: Pid::from_u32(pid),
            name: "worker".into(),
            command: "worker --serve".into(),
            start_time,
        }
    }

    #[test]
    fn protects_system_self_missing_and_reused_processes() {
        assert!(validate_process_instance(&target(0, 10), Some(10), 99).is_err());
        assert!(validate_process_instance(&target(1, 10), Some(10), 99).is_err());
        assert!(validate_process_instance(&target(99, 10), Some(10), 99).is_err());
        assert!(validate_process_instance(&target(42, 10), None, 99).is_err());
        assert!(validate_process_instance(&target(42, 10), Some(11), 99).is_err());
        assert!(validate_process_instance(&target(42, 0), Some(10), 99).is_err());
        assert!(validate_process_instance(&target(42, 10), Some(10), 99).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_stale_instance_then_terminates_the_matching_child() {
        struct ChildGuard(Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let mut child = ChildGuard(
            Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn isolated test process"),
        );
        let pid = Pid::from_u32(child.0.id());
        let mut system = System::new();
        let start_time = (0..20)
            .find_map(|_| {
                system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
                let found = system.process(pid).map(|process| process.start_time());
                if found.is_none() {
                    thread::sleep(Duration::from_millis(10));
                }
                found
            })
            .expect("observe isolated test process");
        let stale = target(pid.as_u32(), start_time.saturating_add(1));
        assert!(matches!(
            execute_process_action(&stale, ProcessActionKind::Terminate),
            ProcessActionOutcome::Refused(_)
        ));
        assert!(child.0.try_wait().expect("check stale target").is_none());

        let matching = target(pid.as_u32(), start_time);
        assert_eq!(
            execute_process_action(&matching, ProcessActionKind::Terminate),
            ProcessActionOutcome::Sent
        );
        let exited = (0..50).any(|_| {
            if child
                .0
                .try_wait()
                .expect("check terminated target")
                .is_some()
            {
                true
            } else {
                thread::sleep(Duration::from_millis(10));
                false
            }
        });
        assert!(exited, "isolated test process did not terminate");
    }
}
