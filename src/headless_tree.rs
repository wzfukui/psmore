use std::collections::HashSet;

use serde::Serialize;
use sysinfo::{Pid, System};

use crate::{
    headless::ProcessSnapshot,
    model::{
        ProcessInfo, ResourceAggregate, process_command_for_output, process_path,
        sanitize_terminal_text,
    },
    provider::platform_name,
};

const TREE_SCHEMA: &str = "psmore.process-tree";
const TREE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug)]
struct TreeNode {
    process: ProcessInfo,
    aggregate: ResourceAggregate,
    children: Vec<TreeNode>,
    hidden_descendant_count: usize,
}

impl TreeNode {
    fn visible_count(&self) -> usize {
        1 + self.children.iter().map(Self::visible_count).sum::<usize>()
    }

    fn visible_process_count(&self) -> usize {
        usize::from(self.process.pid.as_u32() != 0)
            + self
                .children
                .iter()
                .map(Self::visible_process_count)
                .sum::<usize>()
    }

    fn hidden_count(&self) -> usize {
        self.hidden_descendant_count + self.children.iter().map(Self::hidden_count).sum::<usize>()
    }
}

pub(crate) struct CapturedTree {
    ancestors: Vec<TreeNode>,
    tree: TreeNode,
    depth_limit: Option<usize>,
    sample_ms: u64,
    generated_at_unix_ms: u64,
    system_process_count: usize,
}

fn sorted_children(snapshot: &ProcessSnapshot, pid: Pid) -> Vec<Pid> {
    let mut children = snapshot.children_of(pid).to_vec();
    children.sort_by(|left, right| {
        let left_process = snapshot.process(*left);
        let right_process = snapshot.process(*right);
        let left_name = left_process
            .map(|process| process.name.to_lowercase())
            .unwrap_or_default();
        let right_name = right_process
            .map(|process| process.name.to_lowercase())
            .unwrap_or_default();
        left_name
            .cmp(&right_name)
            .then_with(|| left.as_u32().cmp(&right.as_u32()))
    });
    children
}

fn build_node(
    snapshot: &ProcessSnapshot,
    pid: Pid,
    depth: usize,
    depth_limit: Option<usize>,
) -> Result<TreeNode, String> {
    let process = snapshot
        .process(pid)
        .cloned()
        .ok_or_else(|| format!("PID {pid} disappeared from the captured process tree"))?;
    let aggregate = snapshot.resource(pid);
    let at_limit = depth_limit.is_some_and(|limit| depth >= limit);
    let children = if at_limit {
        Vec::new()
    } else {
        sorted_children(snapshot, pid)
            .into_iter()
            .map(|child| build_node(snapshot, child, depth.saturating_add(1), depth_limit))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(TreeNode {
        process,
        aggregate,
        children,
        hidden_descendant_count: if at_limit {
            aggregate.process_count.saturating_sub(1)
        } else {
            0
        },
    })
}

fn build_ancestors(snapshot: &ProcessSnapshot, target: Pid) -> Result<Vec<TreeNode>, String> {
    let mut ancestors = Vec::new();
    let mut current = snapshot.process(target).and_then(|process| process.parent);
    let mut visited = HashSet::from([target]);
    while let Some(pid) = current {
        if !visited.insert(pid) {
            return Err(format!(
                "process parent cycle detected while following PID {target}"
            ));
        }
        let process = snapshot
            .process(pid)
            .cloned()
            .ok_or_else(|| format!("parent PID {pid} is missing from the captured process tree"))?;
        current = process.parent;
        ancestors.push(TreeNode {
            aggregate: snapshot.resource(pid),
            process,
            children: Vec::new(),
            hidden_descendant_count: 0,
        });
    }
    ancestors.reverse();
    Ok(ancestors)
}

pub(crate) fn build_tree(
    snapshot: &ProcessSnapshot,
    target_pid: u32,
    depth_limit: Option<usize>,
) -> Result<CapturedTree, String> {
    let target = Pid::from_u32(target_pid);
    if snapshot.process(target).is_none() {
        return Err(format!("PID {target_pid} was not found"));
    }
    Ok(CapturedTree {
        ancestors: build_ancestors(snapshot, target)?,
        tree: build_node(snapshot, target, 0, depth_limit)?,
        depth_limit,
        sample_ms: snapshot.sample_ms(),
        generated_at_unix_ms: snapshot.generated_at_unix_ms(),
        system_process_count: snapshot.real_process_count(),
    })
}

#[derive(Debug, Serialize)]
struct JsonTreeDocument {
    schema: &'static str,
    schema_version: u32,
    privacy_notice: &'static str,
    tool: JsonTool,
    generated_at_unix_ms: u64,
    platform: &'static str,
    hostname: Option<String>,
    process_sample_interval_ms: u64,
    target_pid: u32,
    descendant_depth_limit: Option<usize>,
    system_process_count: usize,
    visible_node_count: usize,
    visible_process_count: usize,
    hidden_descendant_count: usize,
    ancestors: Vec<JsonNodeSummary>,
    tree: JsonTreeNode,
}

#[derive(Debug, Serialize)]
struct JsonTool {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct JsonAggregate {
    cpu_percent: f32,
    memory_bytes: u64,
    read_bytes_per_second: u64,
    write_bytes_per_second: u64,
    process_count: usize,
}

impl From<ResourceAggregate> for JsonAggregate {
    fn from(value: ResourceAggregate) -> Self {
        Self {
            cpu_percent: finite(value.cpu),
            memory_bytes: value.memory,
            read_bytes_per_second: value.read_rate,
            write_bytes_per_second: value.write_rate,
            process_count: value.process_count,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonNodeSummary {
    pid: u32,
    parent_pid: Option<u32>,
    name: String,
    path: String,
    command: String,
    user: String,
    status: String,
    cpu_percent: f32,
    memory_bytes: u64,
    subtree: JsonAggregate,
}

impl From<&TreeNode> for JsonNodeSummary {
    fn from(node: &TreeNode) -> Self {
        let process = &node.process;
        Self {
            pid: process.pid.as_u32(),
            parent_pid: process.parent.map(Pid::as_u32),
            name: process.name.clone(),
            path: process_path(process),
            command: process_command_for_output(process),
            user: process.user.clone(),
            status: process.status.clone(),
            cpu_percent: finite(process.cpu),
            memory_bytes: process.memory,
            subtree: node.aggregate.into(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonTreeNode {
    #[serde(flatten)]
    process: JsonNodeSummary,
    hidden_descendant_count: usize,
    children: Vec<JsonTreeNode>,
}

impl From<&TreeNode> for JsonTreeNode {
    fn from(node: &TreeNode) -> Self {
        Self {
            process: node.into(),
            hidden_descendant_count: node.hidden_descendant_count,
            children: node.children.iter().map(Self::from).collect(),
        }
    }
}

pub(crate) fn render_tree_json(captured: &CapturedTree) -> Result<String, String> {
    serde_json::to_string_pretty(&JsonTreeDocument {
        schema: TREE_SCHEMA,
        schema_version: TREE_SCHEMA_VERSION,
        privacy_notice: "Contains process names, command lines, paths, users, host information, and resource metrics; review before sharing.",
        tool: JsonTool {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        },
        generated_at_unix_ms: captured.generated_at_unix_ms,
        platform: platform_name(),
        hostname: System::host_name(),
        process_sample_interval_ms: captured.sample_ms,
        target_pid: captured.tree.process.pid.as_u32(),
        descendant_depth_limit: captured.depth_limit,
        system_process_count: captured.system_process_count,
        visible_node_count: captured.ancestors.len() + captured.tree.visible_count(),
        visible_process_count: captured
            .ancestors
            .iter()
            .filter(|node| node.process.pid.as_u32() != 0)
            .count()
            + captured.tree.visible_process_count(),
        hidden_descendant_count: captured.tree.hidden_count(),
        ancestors: captured
            .ancestors
            .iter()
            .map(JsonNodeSummary::from)
            .collect(),
        tree: (&captured.tree).into(),
    })
    .map_err(|error| error.to_string())
}

pub(crate) fn render_tree_table(captured: &CapturedTree) -> String {
    let visible = captured.ancestors.len() + captured.tree.visible_count();
    let hidden = captured.tree.hidden_count();
    let depth = captured
        .depth_limit
        .map(|depth| depth.to_string())
        .unwrap_or_else(|| "all".into());
    let mut output = format!(
        "PSMORE PROCESS TREE\ntarget PID {}  descendant depth {}  showing {} node(s), {} hidden  system {} process(es)  sample {}ms\n",
        captured.tree.process.pid,
        depth,
        visible,
        hidden,
        captured.system_process_count,
        captured.sample_ms,
    );
    output.push_str("TREE  CPU%/TREE       MEM/TREE   PROCS USER         STATE        COMMAND\n");

    for (index, ancestor) in captured.ancestors.iter().enumerate() {
        let prefix = if index == 0 {
            String::new()
        } else {
            format!("{}└─ ", "   ".repeat(index.saturating_sub(1)))
        };
        push_node_line(&mut output, &prefix, ancestor, false);
    }
    let target_prefix = if captured.ancestors.is_empty() {
        String::new()
    } else {
        format!(
            "{}└─ ",
            "   ".repeat(captured.ancestors.len().saturating_sub(1))
        )
    };
    push_node_line(&mut output, &target_prefix, &captured.tree, true);
    let child_prefix = "   ".repeat(captured.ancestors.len());
    push_child_lines(&mut output, &captured.tree, &child_prefix);
    output
}

fn push_node_line(output: &mut String, prefix: &str, node: &TreeNode, target: bool) {
    let process = &node.process;
    let marker = if target { "▶ " } else { "" };
    output.push_str(&format!(
        "{prefix}{marker}{} [{}]  {:>5.1}/{:<5.1} {:>9}/{:<9} {:>5} {:<12} {:<12} {}\n",
        sanitize_terminal_text(&process.name),
        process.pid,
        finite(process.cpu),
        finite(node.aggregate.cpu),
        human_bytes(process.memory),
        human_bytes(node.aggregate.memory),
        node.aggregate.process_count,
        sanitize_terminal_text(&process.user),
        sanitize_terminal_text(&process.status),
        sanitize_terminal_text(&process_command_for_output(process)),
    ));
}

fn push_child_lines(output: &mut String, node: &TreeNode, prefix: &str) {
    let item_count = node.children.len() + usize::from(node.hidden_descendant_count > 0);
    for (index, child) in node.children.iter().enumerate() {
        let last = index + 1 == item_count;
        let connector = if last { "└─ " } else { "├─ " };
        push_node_line(output, &format!("{prefix}{connector}"), child, false);
        let next_prefix = format!("{prefix}{}", if last { "   " } else { "│  " });
        push_child_lines(output, child, &next_prefix);
    }
    if node.hidden_descendant_count > 0 {
        output.push_str(&format!(
            "{prefix}└─ … {} descendant(s) hidden by --depth\n",
            node.hidden_descendant_count
        ));
    }
}

fn finite(value: f32) -> f32 {
    if value.is_finite() { value } else { 0.0 }
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut amount = value as f64;
    let mut unit = 0;
    while amount >= 1024.0 && unit < UNITS.len() - 1 {
        amount /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value}B")
    } else if amount >= 100.0 {
        format!("{amount:.0}{}", UNITS[unit])
    } else if amount >= 10.0 {
        format!("{amount:.1}{}", UNITS[unit])
    } else {
        format!("{amount:.2}{}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn process(pid: u32, parent: Option<u32>, name: &str, memory: u64) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: parent.map(Pid::from_u32),
            name: name.into(),
            command: format!("/srv/{name}\n--pid {pid}"),
            executable: format!("/srv/{name}"),
            user: "deploy".into(),
            cwd: "/srv".into(),
            cpu: pid as f32,
            memory,
            read_rate: 0,
            write_rate: 0,
            start_time: 100,
            runtime: 10,
            status: "Sleep".into(),
        }
    }

    fn snapshot() -> ProcessSnapshot {
        ProcessSnapshot::from_processes(
            vec![
                process(0, None, "kernel", 0),
                process(1, Some(0), "init", 10),
                process(10, Some(1), "api", 100),
                process(11, Some(10), "z-worker", 50),
                process(12, Some(10), "a-worker", 40),
                process(13, Some(12), "helper", 20),
            ],
            500,
        )
    }

    #[test]
    fn tree_keeps_ancestors_stable_children_and_explicit_truncation() {
        let captured = build_tree(&snapshot(), 10, Some(1)).unwrap();
        assert_eq!(captured.ancestors.len(), 2);
        assert_eq!(captured.ancestors[0].process.pid, Pid::from_u32(0));
        assert_eq!(captured.tree.children[0].process.pid, Pid::from_u32(12));
        assert_eq!(captured.tree.children[0].hidden_descendant_count, 1);
        assert_eq!(captured.tree.hidden_count(), 1);

        let table = render_tree_table(&captured);
        assert!(table.contains("▶ api [10]"));
        assert!(table.contains("├─ a-worker [12]"));
        assert!(table.contains("└─ … 1 descendant(s) hidden by --depth"));
        assert!(table.contains("/srv/api --pid 10"));
        assert!(!table.contains("/srv/api\n--pid"));
    }

    #[test]
    fn tree_json_is_nested_versioned_and_reports_counts() {
        let captured = build_tree(&snapshot(), 10, None).unwrap();
        let json: Value = serde_json::from_str(&render_tree_json(&captured).unwrap()).unwrap();
        assert_eq!(json["schema"], TREE_SCHEMA);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["target_pid"], 10);
        assert_eq!(json["visible_node_count"], 6);
        assert_eq!(json["visible_process_count"], 5);
        assert_eq!(json["hidden_descendant_count"], 0);
        assert_eq!(json["ancestors"][1]["pid"], 1);
        assert_eq!(json["tree"]["children"][0]["pid"], 12);
        assert_eq!(json["tree"]["children"][0]["children"][0]["pid"], 13);
        assert_eq!(json["tree"]["subtree"]["process_count"], 4);
    }
}
