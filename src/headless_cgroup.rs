#[cfg(any(target_os = "linux", test))]
use std::cmp::Ordering;

#[cfg(target_os = "linux")]
use std::{collections::HashMap, fs, path::PathBuf};

use serde::Serialize;
#[cfg(target_os = "linux")]
use sysinfo::Pid;
use sysinfo::System;

use crate::{
    cli::CgroupSort,
    headless::{ProcessSnapshot, finite, human_bytes, human_rate},
    model::{ProcessInfo, process_command_for_output, sanitize_terminal_text},
    provider::platform_name,
};

const CGROUP_SCHEMA: &str = "psmore.linux-cgroups";
const CGROUP_SCHEMA_VERSION: u32 = 1;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct CgroupMembership {
    version: u8,
    path: String,
    memory_path: Option<String>,
    pids_path: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct MemoryEvents {
    low: Option<u64>,
    high: Option<u64>,
    max: Option<u64>,
    oom: Option<u64>,
    oom_kill: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct KernelEvidence {
    memory_current_bytes: Option<u64>,
    memory_maximum_bytes: Option<u64>,
    memory_maximum_unlimited: bool,
    memory_utilization_percent: Option<f64>,
    pids_current: Option<u64>,
    pids_maximum: Option<u64>,
    pids_maximum_unlimited: bool,
    pids_utilization_percent: Option<f64>,
    cpu_usage_usec: Option<u64>,
    io_read_bytes: Option<u64>,
    io_write_bytes: Option<u64>,
    memory_events: MemoryEvents,
}

#[derive(Clone, Debug, Serialize)]
struct ProcessReference {
    pid: u32,
    name: String,
    user: String,
    command: String,
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
}

impl From<&ProcessInfo> for ProcessReference {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid.as_u32(),
            name: sanitize_terminal_text(&process.name),
            user: sanitize_terminal_text(&process.user),
            command: sanitize_terminal_text(&process_command_for_output(process)),
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            read_bytes_per_second: process.read_rate,
            write_bytes_per_second: process.write_rate,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
struct GroupResources {
    cpu_percent: f32,
    process_rss_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
}

impl GroupResources {
    #[cfg(target_os = "linux")]
    fn add(&mut self, process: &ProcessInfo) {
        self.cpu_percent += finite(process.cpu);
        self.process_rss_bytes = self.process_rss_bytes.saturating_add(process.memory);
        self.read_bytes_per_second = self.read_bytes_per_second.saturating_add(process.read_rate);
        self.write_bytes_per_second = self
            .write_bytes_per_second
            .saturating_add(process.write_rate);
    }
}

#[derive(Clone, Debug, Serialize)]
struct CgroupRow {
    cgroup_version: u8,
    path: String,
    systemd_unit: Option<String>,
    container: Option<String>,
    risk: &'static str,
    visible_process_count: usize,
    resources: GroupResources,
    kernel: KernelEvidence,
    processes: Vec<ProcessReference>,
}

impl CgroupRow {
    #[cfg(any(target_os = "linux", test))]
    fn new(membership: &CgroupMembership) -> Self {
        Self {
            cgroup_version: membership.version,
            path: membership.path.clone(),
            systemd_unit: systemd_unit(&membership.path),
            container: container_hint(&membership.path),
            risk: "none",
            visible_process_count: 0,
            resources: GroupResources::default(),
            kernel: KernelEvidence::default(),
            processes: Vec::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn finish(&mut self, membership: &CgroupMembership) {
        self.visible_process_count = self.processes.len();
        self.processes.sort_by(|left, right| {
            right
                .memory_bytes
                .cmp(&left.memory_bytes)
                .then_with(|| right.cpu_percent.total_cmp(&left.cpu_percent))
                .then_with(|| left.pid.cmp(&right.pid))
        });
        self.kernel = collect_kernel_evidence(membership);
        self.risk = risk_label(&self.kernel);
    }

    #[cfg(target_os = "linux")]
    fn search_text(&self) -> String {
        let mut values = vec![
            self.path.clone(),
            self.systemd_unit.clone().unwrap_or_default(),
            self.container.clone().unwrap_or_default(),
            self.risk.to_string(),
        ];
        for process in &self.processes {
            values.extend([
                process.pid.to_string(),
                process.name.clone(),
                process.user.clone(),
                process.command.clone(),
            ]);
        }
        values.join(" ").to_lowercase()
    }
}

#[derive(Debug)]
pub(crate) struct CapturedCgroups {
    generated_at_unix_ms: u64,
    sample_interval_ms: u64,
    filter: String,
    sort: CgroupSort,
    limit: Option<usize>,
    eligible_process_count: usize,
    attributed_process_count: usize,
    unreadable_or_racing_process_count: usize,
    total_group_count: usize,
    matched_group_count: usize,
    rows: Vec<CgroupRow>,
    kernel_evidence_group_count: usize,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonFilter<'a> {
    input: &'a str,
    fields: [&'static str; 8],
}

#[derive(Debug, Serialize)]
struct JsonCollection {
    eligible_process_count: usize,
    attributed_process_count: usize,
    unreadable_or_racing_process_count: usize,
    kernel_evidence_group_count: usize,
    complete: bool,
    warning: Option<String>,
}

#[derive(Debug, Serialize)]
struct JsonResultSummary {
    total_group_count: usize,
    matched_group_count: usize,
    returned_group_count: usize,
    truncated: bool,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct JsonCgroups<'a> {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    cgroup_mode: &'static str,
    sample_interval_ms: u64,
    collector_excluded_from_visible_members: bool,
    resource_semantics: [&'static str; 3],
    filter: Option<JsonFilter<'a>>,
    sort: &'static str,
    coverage: JsonCollection,
    selection: JsonResultSummary,
    groups: &'a [CgroupRow],
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_cgroups(
    snapshot: &ProcessSnapshot,
    filter: &str,
    sort: CgroupSort,
    limit: Option<usize>,
) -> Result<CapturedCgroups, String> {
    let current_pid = std::process::id();
    let mut eligible_process_count = 0_usize;
    let mut attributed_process_count = 0_usize;
    let mut unreadable_or_racing_process_count = 0_usize;
    let mut groups: HashMap<String, (CgroupMembership, CgroupRow)> = HashMap::new();
    let mut processes: Vec<&ProcessInfo> = snapshot
        .processes()
        .values()
        .filter(|process| process.pid != Pid::from_u32(0))
        .filter(|process| process.pid.as_u32() != current_pid)
        .collect();
    processes.sort_by_key(|process| process.pid.as_u32());

    for process in processes {
        eligible_process_count = eligible_process_count.saturating_add(1);
        let path = format!("/proc/{}/cgroup", process.pid.as_u32());
        let Ok(content) = fs::read_to_string(path) else {
            unreadable_or_racing_process_count =
                unreadable_or_racing_process_count.saturating_add(1);
            continue;
        };
        let Some(membership) = parse_proc_cgroup(&content) else {
            unreadable_or_racing_process_count =
                unreadable_or_racing_process_count.saturating_add(1);
            continue;
        };
        attributed_process_count = attributed_process_count.saturating_add(1);
        let entry = groups
            .entry(membership.path.clone())
            .or_insert_with(|| (membership.clone(), CgroupRow::new(&membership)));
        entry.1.resources.add(process);
        entry.1.processes.push(ProcessReference::from(process));
    }

    let total_group_count = groups.len();
    let mut rows: Vec<CgroupRow> = groups
        .into_values()
        .map(|(membership, mut row)| {
            row.finish(&membership);
            row
        })
        .collect();
    let kernel_evidence_group_count = rows
        .iter()
        .filter(|row| {
            row.kernel.memory_current_bytes.is_some()
                || row.kernel.pids_current.is_some()
                || row.kernel.cpu_usage_usec.is_some()
        })
        .count();
    let normalized_filter = filter.trim().to_lowercase();
    if !normalized_filter.is_empty() {
        rows.retain(|row| row.search_text().contains(&normalized_filter));
    }
    let matched_group_count = rows.len();
    rows.sort_by(|left, right| compare_groups(sort, left, right));
    rows.truncate(limit.unwrap_or(rows.len()).min(rows.len()));
    Ok(CapturedCgroups {
        generated_at_unix_ms: snapshot.generated_at_unix_ms(),
        sample_interval_ms: snapshot.sample_ms(),
        filter: filter.trim().to_string(),
        sort,
        limit,
        eligible_process_count,
        attributed_process_count,
        unreadable_or_racing_process_count,
        total_group_count,
        matched_group_count,
        rows,
        kernel_evidence_group_count,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn capture_cgroups(
    _snapshot: &ProcessSnapshot,
    _filter: &str,
    _sort: CgroupSort,
    _limit: Option<usize>,
) -> Result<CapturedCgroups, String> {
    Err(
        "cgroup diagnostics are available on Linux only; macOS has no Linux cgroup hierarchy"
            .into(),
    )
}

pub(crate) fn render_cgroups_json(captured: &CapturedCgroups) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonCgroups {
        schema: CGROUP_SCHEMA,
        schema_version: CGROUP_SCHEMA_VERSION,
        privacy_notice: "Contains host, cgroup, systemd, container, process, command-line, path, and user information; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        cgroup_mode: "leaf_membership",
        sample_interval_ms: captured.sample_interval_ms,
        collector_excluded_from_visible_members: true,
        resource_semantics: [
            "process CPU, RSS, and I/O rates are sums of visible direct members over the psmore sample interval, excluding the psmore collector",
            "cgroup memory.current, pids.current, CPU usage, I/O totals, and events are raw hierarchical kernel evidence and can include the collector when it shares that cgroup",
            "OOM and limit counters are cumulative evidence and do not by themselves prove current pressure",
        ],
        filter: (!captured.filter.is_empty()).then_some(JsonFilter {
            input: &captured.filter,
            fields: [
                "path", "systemd_unit", "container", "risk", "pid", "process_name",
                "user", "command",
            ],
        }),
        sort: captured.sort.label(),
        coverage: JsonCollection {
            eligible_process_count: captured.eligible_process_count,
            attributed_process_count: captured.attributed_process_count,
            unreadable_or_racing_process_count: captured.unreadable_or_racing_process_count,
            kernel_evidence_group_count: captured.kernel_evidence_group_count,
            complete: captured.unreadable_or_racing_process_count == 0,
            warning: collection_warning(captured),
        },
        selection: JsonResultSummary {
            total_group_count: captured.total_group_count,
            matched_group_count: captured.matched_group_count,
            returned_group_count: captured.rows.len(),
            truncated: captured.rows.len() < captured.matched_group_count,
            limit: captured.limit,
        },
        groups: &captured.rows,
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_cgroups_table(captured: &CapturedCgroups) -> String {
    let mut output = format!(
        "PSMORE LINUX CGROUPS  sort {}  groups {}/{}  processes {}/{}  sample {}ms\n",
        captured.sort.label(),
        captured.rows.len(),
        captured.matched_group_count,
        captured.attributed_process_count,
        captured.eligible_process_count,
        captured.sample_interval_ms,
    );
    if !captured.filter.is_empty() {
        output.push_str(&format!(
            "filter {}  total groups before filter {}\n",
            sanitize_terminal_text(&captured.filter),
            captured.total_group_count,
        ));
    }
    output.push_str(
        "RANK RISK       PROCS  PIDS   CPU%       RSS      CGMEM / MAX          MEM%       R/s       W/s  BOUNDARY\n",
    );
    for (index, row) in captured.rows.iter().enumerate() {
        let memory = optional_bytes(row.kernel.memory_current_bytes);
        let maximum = if row.kernel.memory_maximum_unlimited {
            "max".into()
        } else {
            optional_bytes(row.kernel.memory_maximum_bytes)
        };
        let boundary = row
            .systemd_unit
            .as_deref()
            .or(row.container.as_deref())
            .unwrap_or(&row.path);
        output.push_str(&format!(
            "{:>4} {:<10} {:>5} {:>5} {:>6.1} {:>9} {:>9} / {:<9} {:>7} {:>9} {:>9}  {}\n",
            index + 1,
            row.risk,
            row.visible_process_count,
            optional_number(row.kernel.pids_current),
            finite(row.resources.cpu_percent),
            human_bytes(row.resources.process_rss_bytes),
            memory,
            maximum,
            optional_percent(row.kernel.memory_utilization_percent),
            human_rate(row.resources.read_bytes_per_second),
            human_rate(row.resources.write_bytes_per_second),
            sanitize_terminal_text(boundary),
        ));
        if boundary != row.path {
            output.push_str(&format!(
                "     path {}{}\n",
                sanitize_terminal_text(&row.path),
                row.container
                    .as_deref()
                    .filter(|container| Some(*container) != row.systemd_unit.as_deref())
                    .map(|container| format!("  container {}", sanitize_terminal_text(container)))
                    .unwrap_or_default(),
            ));
        }
        output.push_str(&format!(
            "     members {}\n",
            member_summary(&row.processes, 4)
        ));
        if row.kernel.memory_events.oom.unwrap_or(0) > 0
            || row.kernel.memory_events.oom_kill.unwrap_or(0) > 0
        {
            output.push_str(&format!(
                "     memory events high={} max={} oom={} oom_kill={}\n",
                optional_number(row.kernel.memory_events.high),
                optional_number(row.kernel.memory_events.max),
                optional_number(row.kernel.memory_events.oom),
                optional_number(row.kernel.memory_events.oom_kill),
            ));
        }
    }
    if captured.rows.is_empty() {
        output.push_str("No cgroups matched.\n");
    }
    if let Some(warning) = collection_warning(captured) {
        output.push_str(&format!("WARNING  {}\n", sanitize_terminal_text(&warning)));
    }
    output.push_str(
        "INTERPRET  RSS/rates sum visible direct members; CGMEM/MAX and counters are hierarchical kernel evidence.\n",
    );
    output
}

fn collection_warning(captured: &CapturedCgroups) -> Option<String> {
    (captured.unreadable_or_racing_process_count > 0).then(|| {
        format!(
            "cgroup membership was unreadable or raced with exit for {} process(es)",
            captured.unreadable_or_racing_process_count
        )
    })
}

#[cfg(any(target_os = "linux", test))]
fn compare_groups(sort: CgroupSort, left: &CgroupRow, right: &CgroupRow) -> Ordering {
    let order = match sort {
        CgroupSort::Cpu => {
            finite(right.resources.cpu_percent).total_cmp(&finite(left.resources.cpu_percent))
        }
        CgroupSort::Memory => right
            .kernel
            .memory_current_bytes
            .unwrap_or(right.resources.process_rss_bytes)
            .cmp(
                &left
                    .kernel
                    .memory_current_bytes
                    .unwrap_or(left.resources.process_rss_bytes),
            ),
        CgroupSort::Pressure => compare_optional_f64_descending(
            left.kernel.memory_utilization_percent,
            right.kernel.memory_utilization_percent,
        ),
        CgroupSort::Processes => right
            .kernel
            .pids_current
            .unwrap_or(right.visible_process_count as u64)
            .cmp(
                &left
                    .kernel
                    .pids_current
                    .unwrap_or(left.visible_process_count as u64),
            ),
    };
    order.then_with(|| left.path.cmp(&right.path))
}

#[cfg(any(target_os = "linux", test))]
fn compare_optional_f64_descending(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => right.total_cmp(&left),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(any(target_os = "linux", test))]
fn risk_label(kernel: &KernelEvidence) -> &'static str {
    if kernel.memory_events.oom_kill.unwrap_or(0) > 0 {
        "OOM_HISTORY"
    } else if kernel
        .memory_utilization_percent
        .is_some_and(|percent| percent >= 90.0)
    {
        "MEM_CRIT"
    } else if kernel
        .pids_utilization_percent
        .is_some_and(|percent| percent >= 90.0)
    {
        "PIDS_CRIT"
    } else if kernel
        .memory_utilization_percent
        .is_some_and(|percent| percent >= 75.0)
    {
        "MEM_WARN"
    } else if kernel
        .pids_utilization_percent
        .is_some_and(|percent| percent >= 75.0)
    {
        "PIDS_WARN"
    } else {
        "none"
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_cgroup(content: &str) -> Option<CgroupMembership> {
    let mut unified = None;
    let mut systemd = None;
    let mut memory = None;
    let mut pids = None;
    let mut first = None;
    for line in content.lines() {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = normalize_cgroup_path(fields.next()?);
        if controllers.is_empty() {
            unified = Some(path.clone());
        }
        let controllers: Vec<&str> = controllers.split(',').collect();
        if controllers.contains(&"name=systemd") {
            systemd = Some(path.clone());
        }
        if controllers.contains(&"memory") {
            memory = Some(path.clone());
        }
        if controllers.contains(&"pids") {
            pids = Some(path.clone());
        }
        first.get_or_insert(path);
    }
    if let Some(path) = unified {
        return Some(CgroupMembership {
            version: 2,
            memory_path: Some(path.clone()),
            pids_path: Some(path.clone()),
            path,
        });
    }
    let path = systemd.or_else(|| memory.clone()).or(first)?;
    Some(CgroupMembership {
        version: 1,
        path,
        memory_path: memory,
        pids_path: pids,
    })
}

#[cfg(any(target_os = "linux", test))]
fn normalize_cgroup_path(path: &str) -> String {
    let path = path.trim();
    if path.is_empty() || path == "/" {
        "/".into()
    } else {
        format!("/{}", path.trim_matches('/'))
    }
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit(path: &str) -> Option<String> {
    path.split('/').rev().find_map(|component| {
        [".service", ".scope", ".slice", ".socket", ".mount", ".swap"]
            .iter()
            .any(|suffix| component.ends_with(suffix))
            .then(|| component.to_string())
    })
}

#[cfg(any(target_os = "linux", test))]
fn container_hint(path: &str) -> Option<String> {
    for component in path.split('/') {
        for (prefix, runtime) in [
            ("docker-", "docker"),
            ("cri-containerd-", "containerd"),
            ("libpod-", "podman"),
            ("crio-", "cri-o"),
        ] {
            if let Some(id) = component
                .strip_prefix(prefix)
                .and_then(|value| value.strip_suffix(".scope").or(Some(value)))
                .filter(|value| value.len() >= 12 && value.chars().all(|ch| ch.is_ascii_hexdigit()))
            {
                return Some(format!("{runtime} {}", &id[..12]));
            }
        }
        if let Some(pod) = component.strip_prefix("kubepods") {
            let qos = pod.trim_matches(['-', '_']);
            return Some(if qos.is_empty() {
                "kubernetes".into()
            } else {
                format!("kubernetes {qos}")
            });
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn collect_kernel_evidence(membership: &CgroupMembership) -> KernelEvidence {
    if membership.version == 2 {
        let root = cgroup_path("/sys/fs/cgroup", &membership.path);
        let (memory_maximum_bytes, memory_maximum_unlimited) = read_limit(root.join("memory.max"));
        let memory_current_bytes = read_number(root.join("memory.current"));
        let (pids_maximum, pids_maximum_unlimited) = read_limit(root.join("pids.max"));
        let pids_current = read_number(root.join("pids.current"));
        return KernelEvidence {
            memory_current_bytes,
            memory_maximum_bytes,
            memory_maximum_unlimited,
            memory_utilization_percent: utilization(memory_current_bytes, memory_maximum_bytes),
            pids_current,
            pids_maximum,
            pids_maximum_unlimited,
            pids_utilization_percent: utilization(pids_current, pids_maximum),
            cpu_usage_usec: read_keyed_number(root.join("cpu.stat"), "usage_usec"),
            io_read_bytes: read_io_total(root.join("io.stat"), "rbytes"),
            io_write_bytes: read_io_total(root.join("io.stat"), "wbytes"),
            memory_events: read_memory_events(root.join("memory.events")),
        };
    }
    let memory_root = membership
        .memory_path
        .as_deref()
        .map(|path| cgroup_path("/sys/fs/cgroup/memory", path));
    let pids_root = membership
        .pids_path
        .as_deref()
        .map(|path| cgroup_path("/sys/fs/cgroup/pids", path));
    let memory_current_bytes = memory_root
        .as_ref()
        .and_then(|root| read_number(root.join("memory.usage_in_bytes")));
    let memory_maximum_bytes = memory_root
        .as_ref()
        .and_then(|root| read_number(root.join("memory.limit_in_bytes")));
    let pids_current = pids_root
        .as_ref()
        .and_then(|root| read_number(root.join("pids.current")));
    let (pids_maximum, pids_maximum_unlimited) = pids_root
        .as_ref()
        .map(|root| read_limit(root.join("pids.max")))
        .unwrap_or((None, false));
    KernelEvidence {
        memory_current_bytes,
        memory_maximum_bytes,
        memory_maximum_unlimited: false,
        memory_utilization_percent: utilization(memory_current_bytes, memory_maximum_bytes),
        pids_current,
        pids_maximum,
        pids_maximum_unlimited,
        pids_utilization_percent: utilization(pids_current, pids_maximum),
        ..KernelEvidence::default()
    }
}

#[cfg(target_os = "linux")]
fn cgroup_path(root: &str, path: &str) -> PathBuf {
    PathBuf::from(root).join(path.trim_start_matches('/'))
}

#[cfg(target_os = "linux")]
fn read_number(path: PathBuf) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(target_os = "linux")]
fn read_limit(path: PathBuf) -> (Option<u64>, bool) {
    let Ok(content) = fs::read_to_string(path) else {
        return (None, false);
    };
    let value = content.trim();
    if value == "max" {
        (None, true)
    } else {
        (value.parse().ok(), false)
    }
}

#[cfg(target_os = "linux")]
fn read_keyed_number(path: PathBuf, key: &str) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    content.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == key).then(|| fields.next()?.parse().ok())?
    })
}

#[cfg(target_os = "linux")]
fn read_io_total(path: PathBuf, key: &str) -> Option<u64> {
    let content = fs::read_to_string(path).ok()?;
    let mut found = false;
    let mut total = 0_u64;
    for field in content.split_whitespace() {
        if let Some(value) = field.strip_prefix(&format!("{key}=")) {
            if let Ok(value) = value.parse::<u64>() {
                total = total.saturating_add(value);
                found = true;
            }
        }
    }
    found.then_some(total)
}

#[cfg(target_os = "linux")]
fn read_memory_events(path: PathBuf) -> MemoryEvents {
    let Ok(content) = fs::read_to_string(path) else {
        return MemoryEvents::default();
    };
    let mut events = MemoryEvents::default();
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else {
            continue;
        };
        let value = fields.next().and_then(|value| value.parse().ok());
        match key {
            "low" => events.low = value,
            "high" => events.high = value,
            "max" => events.max = value,
            "oom" => events.oom = value,
            "oom_kill" => events.oom_kill = value,
            _ => {}
        }
    }
    events
}

#[cfg(target_os = "linux")]
fn utilization(current: Option<u64>, maximum: Option<u64>) -> Option<f64> {
    match (current, maximum) {
        (Some(current), Some(maximum)) if maximum > 0 => {
            Some((current as f64 * 100.0 / maximum as f64).max(0.0))
        }
        _ => None,
    }
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map(human_bytes).unwrap_or_else(|| "?".into())
}

fn optional_number(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".into())
}

fn optional_percent(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1}%"))
        .unwrap_or_else(|| "?".into())
}

fn member_summary(processes: &[ProcessReference], limit: usize) -> String {
    let mut values: Vec<String> = processes
        .iter()
        .take(limit)
        .map(|process| format!("{}[{}]", process.name, process.pid))
        .collect();
    if processes.len() > limit {
        values.push(format!("+{}", processes.len() - limit));
    }
    if values.is_empty() {
        "[none visible]".into()
    } else {
        values.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_v2_and_v1_memberships_without_losing_controller_paths() {
        assert_eq!(
            parse_proc_cgroup("0::/system.slice/api.service\n"),
            Some(CgroupMembership {
                version: 2,
                path: "/system.slice/api.service".into(),
                memory_path: Some("/system.slice/api.service".into()),
                pids_path: Some("/system.slice/api.service".into()),
            })
        );
        assert_eq!(
            parse_proc_cgroup(
                "9:memory:/docker/abc\n5:pids:/docker/abc\n1:name=systemd:/system.slice/docker-abc.scope\n"
            ),
            Some(CgroupMembership {
                version: 1,
                path: "/system.slice/docker-abc.scope".into(),
                memory_path: Some("/docker/abc".into()),
                pids_path: Some("/docker/abc".into()),
            })
        );
    }

    #[test]
    fn identifies_systemd_container_and_limit_risk() {
        assert_eq!(
            systemd_unit("/system.slice/api.service"),
            Some("api.service".into())
        );
        assert_eq!(
            container_hint("/system.slice/docker-0123456789abcdef0123456789abcdef.scope"),
            Some("docker 0123456789ab".into())
        );
        let kernel = KernelEvidence {
            memory_utilization_percent: Some(91.0),
            ..KernelEvidence::default()
        };
        assert_eq!(risk_label(&kernel), "MEM_CRIT");
        let kernel = KernelEvidence {
            memory_events: MemoryEvents {
                oom_kill: Some(1),
                ..MemoryEvents::default()
            },
            ..KernelEvidence::default()
        };
        assert_eq!(risk_label(&kernel), "OOM_HISTORY");
    }

    #[test]
    fn pressure_sort_keeps_unknown_values_after_known_values() {
        let membership = CgroupMembership {
            version: 2,
            path: "/a".into(),
            memory_path: Some("/a".into()),
            pids_path: Some("/a".into()),
        };
        let mut known = CgroupRow::new(&membership);
        known.kernel.memory_utilization_percent = Some(50.0);
        let mut unknown = CgroupRow::new(&CgroupMembership {
            path: "/b".into(),
            ..membership
        });
        unknown.kernel.memory_utilization_percent = None;
        assert_eq!(
            compare_groups(CgroupSort::Pressure, &known, &unknown),
            Ordering::Less
        );
    }
}
