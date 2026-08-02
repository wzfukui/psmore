use std::{
    collections::{HashMap, HashSet},
    io::{self, Write},
    process::{Command, ExitStatus},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    headless::{ProcessSnapshot, finite, human_bytes, human_rate},
    model::{
        ProcessInfo, command_for_output, process_command_for_output, process_path,
        sanitize_terminal_text,
    },
    provider::{NativeProcessProvider, ProcessProvider, platform_name},
};

const RUN_SCHEMA: &str = "psmore.command-profile";
const RUN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RunOutput {
    Table,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MonitorTermination {
    DescendantsDrained,
    GraceExpired,
}

impl MonitorTermination {
    fn label(self) -> &'static str {
        match self {
            Self::DescendantsDrained => "descendants_drained",
            Self::GraceExpired => "grace_expired",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct ExitEvidence {
    success: bool,
    code: Option<i32>,
    signal: Option<i32>,
    mirrored_exit_code: u8,
}

impl ExitEvidence {
    fn from_status(status: ExitStatus) -> Self {
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt;
            status.signal()
        };
        #[cfg(not(unix))]
        let signal = None;

        let mirrored_exit_code = status
            .code()
            .map(|code| code.clamp(0, u8::MAX as i32) as u8)
            .or_else(|| {
                signal.map(|signal| {
                    128_u16
                        .saturating_add(signal.max(0) as u16)
                        .min(u8::MAX as u16) as u8
                })
            })
            .unwrap_or(1);
        Self {
            success: status.success(),
            code: status.code(),
            signal,
            mirrored_exit_code,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct PeakResources {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
}

impl PeakResources {
    fn record_process(&mut self, process: &ProcessInfo) {
        self.cpu_percent = self.cpu_percent.max(finite(process.cpu));
        self.memory_bytes = self.memory_bytes.max(process.memory);
        self.read_bytes_per_second = self.read_bytes_per_second.max(process.read_rate);
        self.write_bytes_per_second = self.write_bytes_per_second.max(process.write_rate);
    }

    fn record_sample(&mut self, sample: &SampleResources) {
        self.cpu_percent = self.cpu_percent.max(finite(sample.cpu_percent));
        self.memory_bytes = self.memory_bytes.max(sample.memory_bytes);
        self.read_bytes_per_second = self.read_bytes_per_second.max(sample.read_bytes_per_second);
        self.write_bytes_per_second = self
            .write_bytes_per_second
            .max(sample.write_bytes_per_second);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct SampleResources {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
}

impl SampleResources {
    fn add(&mut self, process: &ProcessInfo) {
        self.cpu_percent += finite(process.cpu);
        self.memory_bytes = self.memory_bytes.saturating_add(process.memory);
        self.read_bytes_per_second = self.read_bytes_per_second.saturating_add(process.read_rate);
        self.write_bytes_per_second = self
            .write_bytes_per_second
            .saturating_add(process.write_rate);
    }
}

#[derive(Clone, Debug, Serialize)]
struct ObservedProcess {
    pid: u32,
    start_time_unix_seconds: u64,
    identity_verified: bool,
    parent_pid_when_first_seen: Option<u32>,
    name: String,
    path: String,
    command: String,
    user: String,
    first_seen_ms: u64,
    last_seen_ms: u64,
    samples_seen: usize,
    peak: PeakResources,
}

impl ObservedProcess {
    fn new(process: &ProcessInfo, elapsed_ms: u64) -> Self {
        let mut peak = PeakResources::default();
        peak.record_process(process);
        Self {
            pid: process.pid.as_u32(),
            start_time_unix_seconds: process.start_time,
            identity_verified: process.start_time > 0,
            parent_pid_when_first_seen: process.parent.map(Pid::as_u32),
            name: sanitize_terminal_text(&process.name),
            path: sanitize_terminal_text(&process_path(process)),
            command: sanitize_terminal_text(&process_command_for_output(process)),
            user: sanitize_terminal_text(&process.user),
            first_seen_ms: elapsed_ms,
            last_seen_ms: elapsed_ms,
            samples_seen: 1,
            peak,
        }
    }

    fn same_instance(&self, process: &ProcessInfo) -> bool {
        if self.pid != process.pid.as_u32() {
            return false;
        }
        match (self.start_time_unix_seconds, process.start_time) {
            (expected, current) if expected > 0 && current > 0 => expected == current,
            (0, _) | (_, 0) => {
                self.name == sanitize_terminal_text(&process.name)
                    && self.command == sanitize_terminal_text(&process_command_for_output(process))
            }
            _ => false,
        }
    }

    fn record(&mut self, process: &ProcessInfo, elapsed_ms: u64) {
        if self.start_time_unix_seconds == 0 && process.start_time > 0 {
            self.start_time_unix_seconds = process.start_time;
            self.identity_verified = true;
            let path = sanitize_terminal_text(&process_path(process));
            if !path.is_empty() {
                self.path = path;
            }
            let user = sanitize_terminal_text(&process.user);
            if !user.is_empty() {
                self.user = user;
            }
        }
        self.last_seen_ms = elapsed_ms;
        self.samples_seen = self.samples_seen.saturating_add(1);
        self.peak.record_process(process);
    }
}

#[derive(Debug, Default)]
struct RunTracker {
    root_pid: u32,
    root_observed: bool,
    observations: Vec<ObservedProcess>,
    active_observations: HashMap<Pid, usize>,
    sample_count: usize,
    peak_active_process_count: usize,
    peak_subtree: PeakResources,
    first_observation_ms: Option<u64>,
}

impl RunTracker {
    fn new(root_pid: u32) -> Self {
        Self {
            root_pid,
            ..Self::default()
        }
    }

    fn record_snapshot(&mut self, snapshot: &ProcessSnapshot, elapsed_ms: u64) {
        self.sample_count = self.sample_count.saturating_add(1);
        let root_pid = Pid::from_u32(self.root_pid);
        let mut active = HashSet::new();

        if let Some(root) = snapshot.process(root_pid) {
            let root_matches = self
                .active_observations
                .get(&root_pid)
                .and_then(|index| self.observations.get(*index))
                .map(|observation| observation.same_instance(root))
                .unwrap_or(!self.root_observed);
            if root_matches {
                self.root_observed = true;
                active.insert(root_pid);
            }
        }

        // Keep already identified descendants even after their parent exits and
        // the kernel reparents them. Confirm identity before following the PID.
        for (pid, index) in &self.active_observations {
            if snapshot
                .process(*pid)
                .zip(self.observations.get(*index))
                .is_some_and(|(process, observation)| observation.same_instance(process))
            {
                active.insert(*pid);
            }
        }

        // Discover the full currently visible descendant closure. Iteration is
        // deliberate because providers do not guarantee parent-before-child order.
        loop {
            let before = active.len();
            for process in snapshot.processes().values() {
                if process.pid != Pid::from_u32(0)
                    && process
                        .parent
                        .is_some_and(|parent| active.contains(&parent))
                {
                    active.insert(process.pid);
                }
            }
            if active.len() == before {
                break;
            }
        }

        let mut next_active = HashMap::new();
        let mut sample = SampleResources::default();
        let mut active_pids: Vec<Pid> = active.into_iter().collect();
        active_pids.sort_unstable_by_key(|pid| pid.as_u32());
        for pid in active_pids {
            let Some(process) = snapshot.process(pid) else {
                continue;
            };
            sample.add(process);
            let existing = self
                .active_observations
                .get(&pid)
                .copied()
                .filter(|index| self.observations[*index].same_instance(process));
            let index = match existing {
                Some(index) => {
                    self.observations[index].record(process, elapsed_ms);
                    index
                }
                None => {
                    let index = self.observations.len();
                    self.observations
                        .push(ObservedProcess::new(process, elapsed_ms));
                    index
                }
            };
            next_active.insert(pid, index);
        }
        self.active_observations = next_active;
        self.first_observation_ms = self
            .first_observation_ms
            .or_else(|| (!self.active_observations.is_empty()).then_some(elapsed_ms));
        self.peak_active_process_count = self
            .peak_active_process_count
            .max(self.active_observations.len());
        self.peak_subtree.record_sample(&sample);
    }

    fn has_active_processes(&self) -> bool {
        !self.active_observations.is_empty()
    }

    fn into_processes(mut self) -> Vec<ObservedProcess> {
        self.observations.sort_by(|left, right| {
            (left.pid != self.root_pid)
                .cmp(&(right.pid != self.root_pid))
                .then_with(|| left.first_seen_ms.cmp(&right.first_seen_ms))
                .then_with(|| left.pid.cmp(&right.pid))
        });
        self.observations
    }
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonCommand {
    display: String,
    root_pid: u32,
    started_at_unix_ms: u64,
    command_duration_ms: u64,
    monitor_duration_ms: u64,
    exit: ExitEvidence,
}

#[derive(Debug, Serialize)]
struct JsonSampling {
    configured_interval_ms: u64,
    descendant_grace_ms: u64,
    sample_count: usize,
    root_observed: bool,
    first_observation_ms: Option<u64>,
    monitor_termination: MonitorTermination,
    observed_lifecycle_complete: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonSubtree {
    observed_process_instance_count: usize,
    peak_active_process_count: usize,
    peak: PeakResources,
    processes: Vec<ObservedProcess>,
}

#[derive(Debug, Serialize)]
struct JsonRunReport {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    platform: &'static str,
    hostname: Option<String>,
    command: JsonCommand,
    sampling: JsonSampling,
    subtree: JsonSubtree,
}

#[derive(Debug)]
pub(crate) struct RunOutcome {
    pub(crate) exit_code: u8,
}

pub(crate) fn run_command_profile<W: Write>(
    writer: &mut W,
    command: &[String],
    interval_ms: u64,
    descendant_grace_ms: u64,
    output: RunOutput,
) -> io::Result<RunOutcome> {
    let (program, arguments) = command
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "run command is empty"))?;
    let display = command_display(command);
    let mut provider = NativeProcessProvider::new();
    // Prime CPU and I/O deltas before the child exists so its first measurable
    // follow-up sample is not confused with psmore startup work.
    let _ = provider.refresh();

    let started_at_unix_ms = unix_millis();
    let started_at = Instant::now();
    let mut child = Command::new(program)
        .args(arguments)
        .spawn()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot start {}: {error}", sanitize_terminal_text(program)),
            )
        })?;
    let root_pid = child.id();
    let mut tracker = RunTracker::new(root_pid);
    let mut child_status = None;
    let mut command_duration = None;
    let mut exited_at = None;

    let termination = loop {
        let observed_at = Instant::now();
        let snapshot = ProcessSnapshot::build(provider.refresh(), interval_ms, unix_millis());
        tracker.record_snapshot(&snapshot, elapsed_millis(started_at.elapsed()));

        if child_status.is_none() {
            child_status = child.try_wait()?;
            if child_status.is_some() {
                command_duration = Some(started_at.elapsed());
                exited_at = Some(Instant::now());
            }
        }
        if child_status.is_some() {
            if !tracker.has_active_processes() {
                break MonitorTermination::DescendantsDrained;
            }
            if exited_at.is_some_and(|exited| {
                exited.elapsed() >= Duration::from_millis(descendant_grace_ms)
            }) {
                break MonitorTermination::GraceExpired;
            }
        }

        let spent = observed_at.elapsed();
        let interval = Duration::from_millis(interval_ms);
        if spent < interval {
            thread::sleep(interval - spent);
        }
    };

    let status = match child_status {
        Some(status) => status,
        None => {
            let status = child.wait()?;
            command_duration = Some(started_at.elapsed());
            status
        }
    };
    let exit = ExitEvidence::from_status(status);
    let monitor_duration = started_at.elapsed();
    let command_duration = command_duration.unwrap_or(monitor_duration);
    let root_observed = tracker.root_observed;
    let sample_count = tracker.sample_count;
    let first_observation_ms = tracker.first_observation_ms;
    let peak_active_process_count = tracker.peak_active_process_count;
    let peak_subtree = tracker.peak_subtree.clone();
    let processes = tracker.into_processes();
    let mut warnings = Vec::new();
    if !root_observed {
        warnings.push(
            "the command exited before its root process was visible; resource evidence is incomplete"
                .into(),
        );
    }
    if termination == MonitorTermination::GraceExpired {
        warnings.push(format!(
            "descendants were still running after the {descendant_grace_ms}ms observation grace"
        ));
    }
    warnings.push(format!(
        "sampling can miss processes and resource peaks shorter than {interval_ms}ms"
    ));
    let observed_lifecycle_complete =
        root_observed && termination == MonitorTermination::DescendantsDrained;
    let report = JsonRunReport {
        schema: RUN_SCHEMA,
        schema_version: RUN_SCHEMA_VERSION,
        privacy_notice: "Contains the launched command, arguments, paths, users, process relationships, host information, and resource observations; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        platform: platform_name(),
        hostname: System::host_name(),
        command: JsonCommand {
            display: sanitize_terminal_text(&command_for_output(&display)),
            root_pid,
            started_at_unix_ms,
            command_duration_ms: elapsed_millis(command_duration),
            monitor_duration_ms: elapsed_millis(monitor_duration),
            exit: exit.clone(),
        },
        sampling: JsonSampling {
            configured_interval_ms: interval_ms,
            descendant_grace_ms,
            sample_count,
            root_observed,
            first_observation_ms,
            monitor_termination: termination,
            observed_lifecycle_complete,
            warnings,
        },
        subtree: JsonSubtree {
            observed_process_instance_count: processes.len(),
            peak_active_process_count,
            peak: peak_subtree,
            processes,
        },
    };

    match output {
        RunOutput::Table => render_table(writer, &report)?,
        RunOutput::Json => {
            serde_json::to_writer_pretty(&mut *writer, &report).map_err(io::Error::other)?;
            writer.write_all(b"\n")?;
        }
    }
    writer.flush()?;
    Ok(RunOutcome {
        exit_code: exit.mirrored_exit_code,
    })
}

fn render_table<W: Write>(writer: &mut W, report: &JsonRunReport) -> io::Result<()> {
    writeln!(writer, "PSMORE COMMAND PROFILE")?;
    writeln!(writer, "command {}", report.command.display)?;
    let exit = &report.command.exit;
    let exit_label = match (exit.code, exit.signal) {
        (Some(code), _) => format!("code {code}"),
        (_, Some(signal)) => format!("signal {signal}"),
        _ => "unknown".into(),
    };
    writeln!(
        writer,
        "result {}  duration {:.3}s  monitor {:.3}s  root PID {}",
        exit_label,
        report.command.command_duration_ms as f64 / 1_000.0,
        report.command.monitor_duration_ms as f64 / 1_000.0,
        report.command.root_pid,
    )?;
    writeln!(
        writer,
        "sampling {}ms  {} sample(s)  {} process instance(s)  peak active {}  lifecycle {} ({})",
        report.sampling.configured_interval_ms,
        report.sampling.sample_count,
        report.subtree.observed_process_instance_count,
        report.subtree.peak_active_process_count,
        if report.sampling.observed_lifecycle_complete {
            "complete"
        } else {
            "partial"
        },
        report.sampling.monitor_termination.label(),
    )?;
    writeln!(
        writer,
        "peak subtree CPU {:.1}%  memory {}  read {}  write {}",
        finite(report.subtree.peak.cpu_percent),
        human_bytes(report.subtree.peak.memory_bytes),
        human_rate(report.subtree.peak.read_bytes_per_second),
        human_rate(report.subtree.peak.write_bytes_per_second),
    )?;
    if !report.subtree.processes.is_empty() {
        writeln!(
            writer,
            "PID      FIRST-LAST SAMPLES PEAK CPU PEAK MEM  COMMAND"
        )?;
        for process in &report.subtree.processes {
            writeln!(
                writer,
                "{:<8} {:>5}-{:>5} {:>7} {:>7.1}% {:>8}  {}",
                process.pid,
                process.first_seen_ms,
                process.last_seen_ms,
                process.samples_seen,
                finite(process.peak.cpu_percent),
                human_bytes(process.peak.memory_bytes),
                process.command,
            )?;
        }
    }
    for warning in &report.sampling.warnings {
        writeln!(writer, "warning {}", sanitize_terminal_text(warning))?;
    }
    Ok(())
}

fn command_display(command: &[String]) -> String {
    command
        .iter()
        .map(|argument| shell_quote(argument))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_@%+=:,./-".contains(character))
    {
        argument.to_string()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn elapsed_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32, parent: u32, name: &str, start_time: u64) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: Some(Pid::from_u32(parent)),
            name: name.into(),
            command: format!("/srv/{name}"),
            executable: format!("/srv/{name}"),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: pid as f32,
            memory: u64::from(pid) * 1_024,
            read_rate: u64::from(pid) * 10,
            write_rate: u64::from(pid) * 20,
            start_time,
            runtime: 1,
            status: "Run".into(),
        }
    }

    #[test]
    fn tracker_follows_descendants_after_reparenting_and_rejects_pid_reuse() {
        let mut tracker = RunTracker::new(10);
        tracker.record_snapshot(
            &ProcessSnapshot::from_processes(
                vec![
                    process(10, 1, "root", 100),
                    process(11, 10, "worker", 101),
                    process(12, 11, "leaf", 102),
                ],
                100,
            ),
            0,
        );
        assert_eq!(tracker.active_observations.len(), 3);
        assert_eq!(tracker.peak_active_process_count, 3);

        tracker.record_snapshot(
            &ProcessSnapshot::from_processes(vec![process(11, 1, "worker", 101)], 100),
            100,
        );
        assert_eq!(tracker.active_observations.len(), 1);

        tracker.record_snapshot(
            &ProcessSnapshot::from_processes(vec![process(11, 1, "other", 999)], 100),
            200,
        );
        assert!(!tracker.has_active_processes());
        assert_eq!(tracker.observations.len(), 3);
    }

    #[test]
    fn command_display_quotes_shell_metacharacters_without_losing_arguments() {
        assert_eq!(
            command_display(&["printf".into(), "%s\\n".into(), "a b".into(), "x'y".into()]),
            "printf '%s\\n' 'a b' 'x'\\''y'"
        );
    }

    #[test]
    fn real_profile_reports_subtree_and_preserves_nonzero_exit() {
        let mut output = Vec::new();
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            "sleep 0.25 & wait; exit 7".into(),
        ];
        let outcome = run_command_profile(&mut output, &command, 100, 200, RunOutput::Json)
            .expect("profile command");
        assert_eq!(outcome.exit_code, 7);
        let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(report["schema"], RUN_SCHEMA);
        assert_eq!(report["command"]["exit"]["code"], 7);
        assert_eq!(report["sampling"]["root_observed"], true);
        assert!(report["sampling"]["sample_count"].as_u64().unwrap() >= 2);
        assert!(
            report["subtree"]["observed_process_instance_count"]
                .as_u64()
                .unwrap()
                >= 1
        );
    }
}
