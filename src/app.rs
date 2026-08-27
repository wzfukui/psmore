use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::{Duration, Instant},
};

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use sysinfo::Pid;
use unicode_width::UnicodeWidthStr;

use crate::{
    actions::{
        ProcessActionDialog, ProcessActionDialogMode, ProcessActionKind, ProcessActionOutcome,
        ProcessActionRecord, ProcessActionTarget, execute_process_action,
    },
    cli::{LogPriority, LogScope},
    filters::{CompiledProcessFilters, FilterAction, ProcessFilterRule},
    headless_exe::{capture_executable, render_executable_json, render_executable_table},
    headless_explain::{
        ExplainOptions, capture_dossier, render_dossier_json, render_dossier_summary_table,
    },
    headless_logs::{capture_logs, render_logs_json, render_logs_table},
    headless_memory::{capture_memory, render_memory_json, render_memory_table},
    headless_service::{capture_service_context, render_service_json, render_service_table},
    history::ResourceHistory,
    i18n::{UiLanguage, text},
    inspection::inspect_process,
    model::{
        AttentionFinding, AttentionSeverity, ChangeSummary, HotspotMetric, HotspotScope,
        MarqueePhase, ProcessChange, ProcessEvent, ProcessInfo, ProcessInspection,
        ResourceAggregate, SortMode, StatusNotice, TreeRow, TrendView, diff_processes,
        process_path,
    },
    network::{NetworkScan, NetworkScope, scan_network},
    onboarding::{Guidance, GuidanceOverlay},
    provider::{HostMetrics, NativeProcessProvider, ProcessProvider, platform_name},
    query::ProcessQuery,
    report::{ReportInput, export_report},
    snapshot::BaselineSnapshot,
    theme::{GlyphMode, Glyphs, Theme, ThemeId, resolve_glyph_mode, resolve_theme_id},
};

pub(crate) fn aggregate_resources(
    processes: &HashMap<Pid, ProcessInfo>,
    children: &HashMap<Option<Pid>, Vec<Pid>>,
) -> HashMap<Pid, ResourceAggregate> {
    fn visit(
        pid: Pid,
        processes: &HashMap<Pid, ProcessInfo>,
        children: &HashMap<Option<Pid>, Vec<Pid>>,
        cache: &mut HashMap<Pid, ResourceAggregate>,
        visiting: &mut HashSet<Pid>,
    ) -> ResourceAggregate {
        if let Some(total) = cache.get(&pid) {
            return *total;
        }
        if !visiting.insert(pid) {
            return ResourceAggregate::default();
        }
        let mut total = processes
            .get(&pid)
            .map(|process| ResourceAggregate {
                cpu: process.cpu,
                memory: process.memory,
                read_rate: process.read_rate,
                write_rate: process.write_rate,
                process_count: usize::from(pid.as_u32() != 0),
            })
            .unwrap_or_default();
        if let Some(descendants) = children.get(&Some(pid)) {
            for child in descendants {
                if *child != pid {
                    total.add(visit(*child, processes, children, cache, visiting));
                }
            }
        }
        visiting.remove(&pid);
        cache.insert(pid, total);
        total
    }

    let mut resources = HashMap::with_capacity(processes.len());
    let mut visiting = HashSet::new();
    let mut pids: Vec<Pid> = processes.keys().copied().collect();
    pids.sort_by_key(|pid| pid.as_u32());
    for pid in pids {
        visit(pid, processes, children, &mut resources, &mut visiting);
    }
    resources
}

#[cfg(test)]
mod filter_tests {
    use super::*;
    use crate::network::NetworkEndpoint;

    fn process(pid: u32, parent: Option<u32>, name: &str, executable: &str) -> ProcessInfo {
        ProcessInfo {
            pid: Pid::from_u32(pid),
            parent: parent.map(Pid::from_u32),
            name: name.into(),
            command: executable.into(),
            executable: executable.into(),
            user: "joe".into(),
            cwd: "/".into(),
            cpu: 0.0,
            memory: 0,
            read_rate: 0,
            write_rate: 0,
            start_time: 1,
            runtime: 1,
            status: "Sleep".into(),
        }
    }

    #[test]
    fn persistent_filters_run_before_search_and_keep_only_required_ancestors() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.processes = [
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
            process(
                10,
                Some(1),
                "ChatGPT",
                "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT",
            ),
            process(
                11,
                Some(10),
                "Helper",
                "/Applications/ChatGPT.app/Contents/MacOS/Helper",
            ),
            process(12, Some(1), "node", "/opt/homebrew/bin/node"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = [0, 1, 10, 11, 12].into_iter().map(Pid::from_u32).collect();
        app.process_filters = vec![
            ProcessFilterRule {
                action: FilterAction::Include,
                expression: "path:/Applications".into(),
                enabled: true,
            },
            ProcessFilterRule {
                action: FilterAction::Exclude,
                expression: "name~^Helper$".into(),
                enabled: true,
            },
        ];
        app.search.clear();
        app.rebuild_visible();

        assert_eq!(app.filtered_processes, 1);
        assert_eq!(
            app.visible
                .iter()
                .map(|row| row.pid.as_u32())
                .collect::<Vec<_>>(),
            vec![0, 1, 10]
        );

        app.search = "name:node".into();
        app.rebuild_visible();
        assert_eq!(app.search_matches, 0);
        assert!(app.visible.is_empty());

        app.search = "name:ChatGPT".into();
        app.rebuild_visible();
        assert_eq!(app.search_matches, 1);
        assert_eq!(
            app.visible
                .iter()
                .map(|row| row.pid.as_u32())
                .collect::<Vec<_>>(),
            vec![0, 1, 10]
        );
    }

    #[test]
    fn clear_search_keeps_selected_pid_visible_in_full_tree() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.processes = [
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
            process(200, Some(1), "herdr", "/usr/bin/herdr"),
            process(300, Some(200), "zsh", "/bin/zsh"),
            process(400, Some(300), "claude", "/usr/local/bin/claude"),
            process(500, Some(1), "another", "/usr/bin/another"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = [0].into_iter().map(Pid::from_u32).collect();
        app.search = "name:herdr".into();
        app.rebuild_visible();

        let herdr = Pid::from_u32(200);
        assert!(app.visible.iter().any(|row| row.pid == herdr));
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == herdr)
            .expect("herdr should be visible in search mode");

        // In normal (non-search) mode herdr is hidden due a collapsed ancestor.
        app.collapsed.insert(Pid::from_u32(1));

        let anchor = app
            .selected_pid()
            .expect("search selection should have anchor pid");
        app.search.clear();
        app.ensure_visible_ancestor_chain(anchor);
        app.rebuild_visible();
        let visible_index = app.visible.iter().position(|row| row.pid == anchor);
        if let Some(index) = visible_index {
            app.selected = index;
        } else {
            app.selected = app.selected.min(app.visible.len().saturating_sub(1));
        }

        assert_eq!(app.selected_pid(), Some(herdr));
        assert!(app.visible.iter().any(|row| row.pid == Pid::from_u32(1)));
        assert!(!app.collapsed.contains(&Pid::from_u32(1)));
        assert!(app.expanded.contains(&Pid::from_u32(1)));
    }

    #[test]
    fn clear_search_esc_keeps_anchor_in_place_even_with_many_siblings() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let herdr_pid = Pid::from_u32(200);
        let mut processes = vec![
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
        ];

        for i in 10..80 {
            processes.push(process(i, Some(1), "other", &format!("/usr/bin/other{i}")));
        }
        processes.push(process(
            herdr_pid.as_u32(),
            Some(1),
            "herdr",
            "/usr/bin/herdr",
        ));
        for i in 81..120 {
            processes.push(process(i, Some(1), "other", &format!("/usr/bin/other{i}")));
        }
        processes.push(process(300, Some(herdr_pid.as_u32()), "zsh", "/bin/zsh"));

        app.processes = processes
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);

        // 默认展开足够多，以便搜索上下文完整展示。
        app.expanded = [0, 1, 200].into_iter().map(Pid::from_u32).collect();

        app.search = "name:herdr".into();
        app.rebuild_visible();

        let search_anchor = app
            .visible
            .iter()
            .position(|row| row.pid == herdr_pid)
            .expect("herdr should be visible in search mode");
        app.selected = search_anchor;

        app.collapsed.insert(Pid::from_u32(1));

        let anchor_pid = app.selected_pid();
        app.search.clear();
        if let Some(anchor_pid) = anchor_pid {
            app.ensure_visible_ancestor_chain(anchor_pid);
        }
        app.rebuild_visible();
        if let Some(anchor_pid) = anchor_pid {
            app.restore_selection_to_anchor(anchor_pid);
        }

        let full_anchor = app
            .visible
            .iter()
            .position(|row| row.pid == herdr_pid)
            .expect("herdr should return in full tree");
        let visible_after = app.visible.len();
        assert_eq!(app.selected_pid(), Some(herdr_pid));
        assert_eq!(app.selected, full_anchor);
        assert!(full_anchor < visible_after - 1);
        assert!(app.expanded.contains(&Pid::from_u32(1)));
        assert!(!app.collapsed.contains(&Pid::from_u32(1)));
    }

    #[test]
    fn clear_search_esc_keeps_selected_descendant_of_match() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let herdr_pid = Pid::from_u32(200);
        let grand_pid = Pid::from_u32(220);
        let mut processes = vec![
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
            process(herdr_pid.as_u32(), Some(1), "herdr", "/usr/bin/herdr"),
            process(215, Some(herdr_pid.as_u32()), "node", "/opt/bin/node"),
            process(grand_pid.as_u32(), Some(215), "codex", "/usr/bin/codex"),
            process(300, Some(grand_pid.as_u32()), "worker", "/usr/bin/worker"),
            process(301, Some(grand_pid.as_u32()), "worker", "/usr/bin/worker"),
        ];
        for i in 10..140 {
            processes.push(process(i, Some(1), "other", &format!("/usr/bin/other{i}")));
        }
        app.processes = processes
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = [0, 1, herdr_pid.as_u32(), 215]
            .into_iter()
            .map(Pid::from_u32)
            .collect();

        app.search = "name:herdr".into();
        app.rebuild_visible();
        let anchor = grand_pid;
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == anchor)
            .expect("selected descendant should be visible in search result");
        app.collapsed.insert(Pid::from_u32(1));

        let anchor_pid = app.selected_pid().expect("ancestor chain anchor exists");
        app.search.clear();
        app.ensure_visible_ancestor_chain(anchor_pid);
        app.rebuild_visible();
        let visible_index = app.visible.iter().position(|row| row.pid == anchor_pid);
        assert!(visible_index.is_some());
        app.restore_selection_to_anchor(anchor_pid);
        assert_eq!(app.selected_pid(), Some(anchor));
        assert_eq!(
            app.visible.iter().position(|row| row.pid == anchor),
            Some(app.selected)
        );
        assert!(!app.expanded.is_empty());
        assert!(app.expanded.contains(&Pid::from_u32(1)));
        assert!(!app.collapsed.contains(&Pid::from_u32(1)));
    }

    #[test]
    fn clear_search_esc_keeps_anchor_visible_row_position() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let herdr_pid = Pid::from_u32(3210);
        let mut processes = vec![
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
        ];

        for i in 10..110 {
            processes.push(process(i, Some(1), "other", &format!("/usr/bin/other{i}")));
        }
        processes.push(process(
            herdr_pid.as_u32(),
            Some(1),
            "herdr",
            "/usr/bin/herdr",
        ));
        for i in 111..140 {
            processes.push(process(i, Some(1), "other", &format!("/usr/bin/other{i}")));
        }

        app.processes = processes
            .into_iter()
            .map(|process| (process.pid, process))
            .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.sort_mode = SortMode::Stable;
        app.expanded = [0, 1].into_iter().map(Pid::from_u32).collect();

        app.search = "name:herdr".into();
        app.rebuild_visible();
        let search_herdr = app
            .visible
            .iter()
            .position(|row| row.pid == herdr_pid)
            .expect("herdr should be visible while searching");
        app.selected = search_herdr;
        app.tree_offset = search_herdr.saturating_sub(2);

        app.page_size = 10;
        app.collapsed.insert(Pid::from_u32(1));
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        let full_herdr = app
            .visible
            .iter()
            .position(|row| row.pid == herdr_pid)
            .expect("herdr should remain visible after clear");
        let visible_row = full_herdr.saturating_sub(app.tree_offset);
        assert_eq!(app.selected, full_herdr);
        assert_eq!(visible_row, 2);
        assert_eq!(app.selected_pid(), Some(herdr_pid));
    }

    #[test]
    fn next_starred_with_empty_filtered_view_notices_instead_of_panicking() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.processes = [
            process(0, None, "kernel / system", ""),
            process(1, Some(0), "launchd", "/sbin/launchd"),
            process(2, Some(1), "worker", "/usr/bin/worker"),
        ]
        .into_iter()
        .map(|process| (process.pid, process))
        .collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = [0, 1].into_iter().map(Pid::from_u32).collect();
        app.rebuild_visible();

        // Star the selected process, then hide every row behind a
        // zero-result search.
        app.on_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE));
        assert_eq!(app.marks.len(), 1);
        app.search = "name:no-such-process".into();
        app.rebuild_visible();
        assert!(app.visible.is_empty());

        app.on_key(KeyEvent::new(KeyCode::Char('\''), KeyModifiers::NONE));
        let notice = app.notice.as_ref().expect("not-visible notice");
        assert!(notice.message.contains("not visible"));
    }

    #[test]
    fn palette_pause_pauses_without_touching_the_filter_manager() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.process_filters = vec![ProcessFilterRule {
            action: FilterAction::Include,
            expression: "name:node".into(),
            enabled: true,
        }];
        app.on_key(KeyEvent::new(KeyCode::Char('F'), KeyModifiers::NONE));
        assert!(app.show_filter_manager);

        // Palette Pause must pause from every context; replaying Space here
        // would toggle the selected rule instead.
        let quit = app.execute_palette_command(PaletteCommandId::Pause);
        assert!(!quit);
        assert!(app.paused);
        assert!(app.show_filter_manager);
        assert!(app.process_filters[0].enabled);

        // Contrast: a real Space in the filter manager toggles the rule and
        // leaves the pause state alone.
        app.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(!app.process_filters[0].enabled);
        assert!(app.paused);

        // And from the bare tree, palette Pause still toggles back.
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.show_filter_manager);
        app.execute_palette_command(PaletteCommandId::Pause);
        assert!(!app.paused);
    }

    #[test]
    fn search_completion_advances_past_multibyte_whitespace() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        // U+3000 (ideographic space) is three UTF-8 bytes; the token boundary
        // must start after the whole character, not one byte into it.
        app.search_input = "cpu>20\u{3000}n".into();
        app.complete_search_field();
        assert_eq!(app.search_input, "cpu>20\u{3000}name:");
        // Cycling with a single candidate keeps the completed token.
        app.complete_search_field();
        assert_eq!(app.search_input, "cpu>20\u{3000}name:");
    }

    #[test]
    fn pending_port_lookup_applies_when_the_initial_scan_completes() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.show_network = true;
        // The first background scan is still running: no snapshot yet.
        assert!(app.network_scan.is_none());
        app.network_port_input = Some("8080".into());
        app.finish_network_port_input();
        assert_eq!(app.network_port_filter, None);
        assert_eq!(app.network_pending_port, Some(8080));
        let notice = app.notice.as_ref().expect("pending notice");
        assert!(notice.message.contains("when the scan completes"));

        let scan = NetworkScan {
            endpoints: vec![NetworkEndpoint {
                pid: Some(Pid::from_u32(2)),
                process: "worker".into(),
                fd: "12".into(),
                protocol: "TCP".into(),
                local_endpoint: "127.0.0.1:8080".into(),
                remote_endpoint: String::new(),
                state: "LISTEN".into(),
                namespace: String::new(),
            }],
            warning: None,
        };
        let (sender, receiver) = mpsc::channel();
        sender.send(scan).unwrap();
        app.network_task = Some(NetworkTask {
            receiver,
            started_at: Instant::now(),
        });
        app.poll_background_jobs();
        assert_eq!(app.network_pending_port, None);
        assert_eq!(app.network_port_filter, Some(8080));
        assert_eq!(app.network_visible_indices().len(), 1);
    }

    #[test]
    fn pending_port_lookup_reports_no_endpoint_after_the_scan() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.show_network = true;
        app.network_port_input = Some("9".into());
        app.finish_network_port_input();
        assert_eq!(app.network_pending_port, Some(9));

        let (sender, receiver) = mpsc::channel();
        sender
            .send(NetworkScan {
                endpoints: vec![],
                warning: None,
            })
            .unwrap();
        app.network_task = Some(NetworkTask {
            receiver,
            started_at: Instant::now(),
        });
        app.poll_background_jobs();
        assert_eq!(app.network_pending_port, None);
        assert_eq!(app.network_port_filter, None);
        let notice = app.notice.as_ref().expect("no-match notice");
        assert!(notice.message.contains("no endpoint on port 9"));
    }

    #[test]
    fn clicks_reach_inspection_tabs_only_without_a_higher_modal() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.inspection = Some(ProcessInspection::default());
        app.inspection_tab_regions = vec![(Rect::new(0, 0, 10, 1), InspectionTab::Threads)];
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: 0,
            modifiers: KeyModifiers::NONE,
        };

        // The palette owns the screen: the click must not switch the hidden
        // inspection tab underneath.
        app.show_palette = true;
        app.on_mouse(click);
        assert_eq!(app.inspection_tab, InspectionTab::Overview);

        app.show_palette = false;
        app.on_mouse(click);
        assert_eq!(app.inspection_tab, InspectionTab::Threads);

        // The process-action dialog is modal too.
        app.inspection_tab_regions = vec![(Rect::new(0, 0, 10, 1), InspectionTab::Ports)];
        app.process_action = Some(ProcessActionDialog {
            target: ProcessActionTarget {
                pid: Pid::from_u32(2),
                name: "worker".into(),
                command: "/usr/bin/worker".into(),
                start_time: 1,
            },
            selected: 0,
            confirming: false,
            mode: ProcessActionDialogMode::All,
        });
        app.on_mouse(click);
        assert_eq!(app.inspection_tab, InspectionTab::Threads);
        app.process_action = None;
        app.on_mouse(click);
        assert_eq!(app.inspection_tab, InspectionTab::Ports);
    }
}

pub(crate) fn sort_processes(
    pids: &mut [Pid],
    mode: SortMode,
    processes: &HashMap<Pid, ProcessInfo>,
    resources: &HashMap<Pid, ResourceAggregate>,
) {
    pids.sort_by(|left, right| {
        let left_resource = resources.get(left).copied().unwrap_or_default();
        let right_resource = resources.get(right).copied().unwrap_or_default();
        let hot_order = match mode {
            SortMode::Stable => std::cmp::Ordering::Equal,
            SortMode::SubtreeCpu => right_resource.cpu.total_cmp(&left_resource.cpu),
            SortMode::SubtreeMemory => right_resource.memory.cmp(&left_resource.memory),
            SortMode::SubtreeRead => right_resource.read_rate.cmp(&left_resource.read_rate),
            SortMode::SubtreeWrite => right_resource.write_rate.cmp(&left_resource.write_rate),
        };
        hot_order.then_with(|| {
            let left_name = processes
                .get(left)
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            let right_name = processes
                .get(right)
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            (left_name, left.as_u32()).cmp(&(right_name, right.as_u32()))
        })
    });
}

pub(crate) fn rank_hotspots(
    processes: &HashMap<Pid, ProcessInfo>,
    resources: &HashMap<Pid, ResourceAggregate>,
    metric: HotspotMetric,
    scope: HotspotScope,
) -> Vec<Pid> {
    let root = Pid::from_u32(0);
    let mut pids: Vec<Pid> = processes
        .keys()
        .filter(|pid| **pid != root)
        .copied()
        .collect();
    pids.sort_by(|left, right| {
        let left_process = processes.get(left);
        let right_process = processes.get(right);
        let left_tree = resources.get(left).copied().unwrap_or_default();
        let right_tree = resources.get(right).copied().unwrap_or_default();
        let metric_order = match (metric, scope) {
            (HotspotMetric::Cpu, HotspotScope::Process) => right_process
                .map(|process| process.cpu)
                .unwrap_or_default()
                .total_cmp(&left_process.map(|process| process.cpu).unwrap_or_default()),
            (HotspotMetric::Cpu, HotspotScope::Subtree) => right_tree.cpu.total_cmp(&left_tree.cpu),
            (HotspotMetric::Memory, HotspotScope::Process) => right_process
                .map(|process| process.memory)
                .unwrap_or_default()
                .cmp(
                    &left_process
                        .map(|process| process.memory)
                        .unwrap_or_default(),
                ),
            (HotspotMetric::Memory, HotspotScope::Subtree) => {
                right_tree.memory.cmp(&left_tree.memory)
            }
            (HotspotMetric::Read, HotspotScope::Process) => right_process
                .map(|process| process.read_rate)
                .unwrap_or_default()
                .cmp(
                    &left_process
                        .map(|process| process.read_rate)
                        .unwrap_or_default(),
                ),
            (HotspotMetric::Read, HotspotScope::Subtree) => {
                right_tree.read_rate.cmp(&left_tree.read_rate)
            }
            (HotspotMetric::Write, HotspotScope::Process) => right_process
                .map(|process| process.write_rate)
                .unwrap_or_default()
                .cmp(
                    &left_process
                        .map(|process| process.write_rate)
                        .unwrap_or_default(),
                ),
            (HotspotMetric::Write, HotspotScope::Subtree) => {
                right_tree.write_rate.cmp(&left_tree.write_rate)
            }
        };
        metric_order.then_with(|| {
            let left_name = left_process
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            let right_name = right_process
                .map(|process| process.name.to_lowercase())
                .unwrap_or_default();
            (left_name, left.as_u32()).cmp(&(right_name, right.as_u32()))
        })
    });
    pids
}

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const ATTENTION_ACTIVITY_SAMPLES: usize = 5;
const ATTENTION_GROWTH_SAMPLES: usize = 30;
const ATTENTION_CHURN_WINDOW: Duration = Duration::from_secs(60);
const LOAD_HISTORY_SAMPLES: usize = 10;

fn attention_bytes(value: u64) -> String {
    if value >= GIB {
        format!("{:.1} GiB", value as f64 / GIB as f64)
    } else {
        format!("{:.1} MiB", value as f64 / MIB as f64)
    }
}

fn attention_rate(value: u64) -> String {
    format!("{}/s", attention_bytes(value))
}

pub(crate) fn rank_attention_findings(
    processes: &HashMap<Pid, ProcessInfo>,
    history: &ResourceHistory,
    events: &[ProcessEvent],
) -> Vec<AttentionFinding> {
    let mut churn: HashMap<String, (HashSet<Pid>, HashSet<Pid>)> = HashMap::new();
    for event in events
        .iter()
        .filter(|event| event.observed_at.elapsed() <= ATTENTION_CHURN_WINDOW)
    {
        match &event.change {
            ProcessChange::Started { pid, command, .. } => {
                churn
                    .entry(command.to_lowercase())
                    .or_default()
                    .0
                    .insert(*pid);
            }
            ProcessChange::Exited { pid, command, .. } => {
                churn
                    .entry(command.to_lowercase())
                    .or_default()
                    .1
                    .insert(*pid);
            }
            ProcessChange::Reparented { .. } => {}
        }
    }
    let mut churn_representatives: HashMap<String, Pid> = HashMap::new();
    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0)
    {
        let identity = crate::model::process_command_line(process).to_lowercase();
        churn_representatives
            .entry(identity)
            .and_modify(|pid| {
                if process.pid.as_u32() < pid.as_u32() {
                    *pid = process.pid;
                }
            })
            .or_insert(process.pid);
    }

    let mut findings = Vec::new();
    for process in processes
        .values()
        .filter(|process| process.pid.as_u32() != 0)
    {
        let mut reasons = Vec::new();
        let mut score = 0_u16;
        let status = process.status.trim();
        let normalized_status = status.to_lowercase();
        let state_is_critical = normalized_status == "z"
            || normalized_status.starts_with("zombie")
            || normalized_status.starts_with("dead");
        if state_is_critical {
            score = 100;
            reasons.push(format!("unhealthy process state: {status}"));
        } else if normalized_status == "t"
            || normalized_status.starts_with('t')
            || normalized_status.contains("stop")
        {
            score = score.saturating_add(70);
            reasons.push(format!("stopped or traced process state: {status}"));
        }

        let process_identity = crate::model::process_command_line(process).to_lowercase();
        let represents_identity =
            churn_representatives.get(&process_identity) == Some(&process.pid);
        if let Some((started_pids, exited_pids)) = churn
            .get(&process_identity)
            .filter(|(started, exited)| started.len() >= 2 && exited.len() >= 2)
            .filter(|_| represents_identity)
        {
            let starts = started_pids.len();
            let exits = exited_pids.len();
            let cycles = starts.min(exits);
            score = score.saturating_add(if cycles >= 10 {
                60
            } else if cycles >= 4 {
                35
            } else {
                25
            });
            reasons.push(format!(
                "lifecycle churn: {starts} distinct starts / {exits} exits in 60s"
            ));
        }

        let samples = history.samples(process.pid);
        let activity: Vec<_> = samples
            .into_iter()
            .flat_map(|samples| samples.iter().rev().take(ATTENTION_ACTIVITY_SAMPLES))
            .collect();
        let sample_count = activity.len();
        let (average_cpu, average_read, average_write) = if sample_count > 0 {
            let count = sample_count as f64;
            (
                activity
                    .iter()
                    .map(|sample| f64::from(sample.own_cpu))
                    .sum::<f64>()
                    / count,
                activity
                    .iter()
                    .map(|sample| sample.own_read_rate as u128)
                    .sum::<u128>()
                    / sample_count as u128,
                activity
                    .iter()
                    .map(|sample| sample.own_write_rate as u128)
                    .sum::<u128>()
                    / sample_count as u128,
            )
        } else {
            (
                f64::from(process.cpu),
                u128::from(process.read_rate),
                u128::from(process.write_rate),
            )
        };
        let average_read = average_read.min(u128::from(u64::MAX)) as u64;
        let average_write = average_write.min(u128::from(u64::MAX)) as u64;
        let cpu_is_sustained = sample_count >= 3;
        let report_cpu = if cpu_is_sustained {
            average_cpu
        } else {
            f64::from(process.cpu)
        };
        if report_cpu >= 25.0 {
            score = score.saturating_add(if report_cpu >= 80.0 {
                45
            } else if report_cpu >= 50.0 {
                30
            } else {
                20
            });
            reasons.push(if cpu_is_sustained {
                format!(
                    "sustained CPU {average_cpu:.1}% avg (now {:.1}%)",
                    process.cpu
                )
            } else {
                format!("CPU {:.1}% in the current sample", process.cpu)
            });
        }

        if process.memory >= 512 * MIB {
            score = score.saturating_add(if process.memory >= 4 * GIB {
                35
            } else if process.memory >= GIB {
                20
            } else {
                10
            });
            reasons.push(format!(
                "memory footprint {}",
                attention_bytes(process.memory)
            ));
        }

        let memory_window = samples.and_then(|samples| {
            let newest = samples.back()?;
            let oldest = samples.get(samples.len().saturating_sub(ATTENTION_GROWTH_SAMPLES))?;
            Some((newest, oldest))
        });
        let memory_growth = memory_window.and_then(|(newest, oldest)| {
            let growth = newest.own_memory.saturating_sub(oldest.own_memory);
            let meaningful_ratio = oldest.own_memory >= 32 * MIB
                && newest.own_memory >= oldest.own_memory.saturating_add(oldest.own_memory / 5);
            if growth >= 128 * MIB && meaningful_ratio {
                Some((newest, oldest, growth))
            } else {
                None
            }
        });
        if let Some((newest, oldest, growth)) = memory_growth {
            score = score.saturating_add(if growth >= 512 * MIB { 45 } else { 25 });
            let elapsed = newest
                .observed_at
                .saturating_duration_since(oldest.observed_at)
                .as_secs();
            reasons.push(format!(
                "memory grew {} in {}s",
                attention_bytes(growth),
                elapsed.max(1)
            ));
        }

        for (label, rate) in [("read", average_read), ("write", average_write)] {
            if rate < MIB {
                continue;
            }
            score = score.saturating_add(if rate >= 100 * MIB {
                35
            } else if rate >= 10 * MIB {
                20
            } else {
                10
            });
            reasons.push(format!("{label} I/O {} avg", attention_rate(rate)));
        }

        if reasons.is_empty() {
            continue;
        }
        let score = score.min(100);
        let severity = if state_is_critical || score >= 80 {
            AttentionSeverity::Critical
        } else if score >= 40 {
            AttentionSeverity::Warning
        } else {
            AttentionSeverity::Watch
        };
        findings.push(AttentionFinding {
            pid: process.pid,
            severity,
            score,
            reasons,
        });
    }
    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| right.score.cmp(&left.score))
            .then_with(|| {
                let left_name = processes
                    .get(&left.pid)
                    .map(|process| process.name.to_lowercase())
                    .unwrap_or_default();
                let right_name = processes
                    .get(&right.pid)
                    .map(|process| process.name.to_lowercase())
                    .unwrap_or_default();
                (left_name, left.pid.as_u32()).cmp(&(right_name, right.pid.as_u32()))
            })
    });
    findings
}

struct NetworkTask {
    receiver: Receiver<NetworkScan>,
    started_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum InspectionTab {
    #[default]
    Overview,
    Threads,
    Ports,
    Files,
}

impl InspectionTab {
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Overview => 0,
            Self::Threads => 1,
            Self::Ports => 2,
            Self::Files => 3,
        }
    }

    pub(crate) const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Overview),
            1 => Some(Self::Threads),
            2 => Some(Self::Ports),
            3 => Some(Self::Files),
            _ => None,
        }
    }

    const fn next(self) -> Self {
        match self {
            Self::Overview => Self::Threads,
            Self::Threads => Self::Ports,
            Self::Ports => Self::Files,
            Self::Files => Self::Overview,
        }
    }

    const fn previous(self) -> Self {
        match self {
            Self::Overview => Self::Files,
            Self::Threads => Self::Overview,
            Self::Ports => Self::Threads,
            Self::Files => Self::Ports,
        }
    }
}

struct InspectionTask {
    receiver: Receiver<ProcessInspection>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct ServiceContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct ExecutableContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct MemoryContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct LogsContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

struct DossierContextTask {
    receiver: Receiver<Result<(String, serde_json::Value), String>>,
    started_at: Instant,
    pid: Pid,
    start_time: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct ServiceContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutableContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
    pub(crate) hash: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct LogsContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
    pub(crate) scope: LogScope,
    pub(crate) priority: LogPriority,
    pub(crate) since_seconds: u64,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct DossierContextPanel {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) content: String,
    pub(crate) report: Option<serde_json::Value>,
    pub(crate) warning: Option<String>,
    pub(crate) include_logs: bool,
    pub(crate) hash: bool,
    pub(crate) scope: LogScope,
    pub(crate) priority: LogPriority,
    pub(crate) since_seconds: u64,
    pub(crate) limit: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct FilterEditor {
    pub(crate) action: FilterAction,
    pub(crate) input: String,
    pub(crate) error: Option<String>,
    pub(crate) editing_index: Option<usize>,
    enabled: bool,
}

/// A starred process instance: the star dies with the instance, so PID reuse
/// (same PID, different start time) never shows a stale marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ProcessMark {
    pub(crate) pid: Pid,
    pub(crate) start_time: u64,
}

/// Tab-completion cycle state inside `/` search: the token that triggered the
/// cycle plus the matching candidates, so repeated Tab walks the same list.
#[derive(Clone, Debug)]
struct SearchCompletion {
    token_start: usize,
    candidates: Vec<&'static str>,
    index: usize,
}

/// Query field starters offered by Tab completion in `/` search.
const QUERY_FIELD_STARTERS: &[&str] = &[
    "name:",
    "cmd:",
    "path:",
    "user:",
    "state:",
    "pid:",
    "ppid:",
    "cpu>",
    "cpu<",
    "mem>",
    "mem<",
    "tree.cpu>",
    "tree.mem>",
    "age>",
    "read>",
    "write>",
    "!state:",
];

const MAX_QUERY_HISTORY: usize = 20;

struct TreeSelection<'a> {
    matched: &'a HashSet<Pid>,
    allowed: &'a HashSet<Pid>,
    restricted: bool,
    filter_applied: bool,
    search_active: bool,
}

/// One entry in the `:` command palette. The catalog stays data-only so new
/// commands are a one-line addition; dispatch replays the real key press.
#[derive(Clone, Copy)]
pub(crate) struct PaletteCommand {
    pub(crate) id: PaletteCommandId,
    pub(crate) en_name: &'static str,
    pub(crate) zh_name: &'static str,
    pub(crate) en_description: &'static str,
    pub(crate) zh_description: &'static str,
    pub(crate) key_hint: &'static str,
    pub(crate) keywords: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PaletteCommandId {
    Inspect,
    Search,
    ToggleStar,
    NextStarred,
    Actions,
    Dossier,
    Memory,
    Service,
    Verify,
    Logs,
    Network,
    FindPort,
    Hotspots,
    Attention,
    Trend,
    Events,
    Filters,
    Focus,
    Sort,
    Pause,
    Refresh,
    CaptureBaseline,
    SnapshotDiff,
    ClearBaseline,
    ExportReport,
    Language,
    CycleTheme,
    ToggleGlyphs,
    Help,
    Quit,
}

static PALETTE_COMMANDS: &[PaletteCommand] = &[
    PaletteCommand {
        id: PaletteCommandId::Inspect,
        en_name: "Inspect process",
        zh_name: "深度检查",
        en_description: "Threads, sockets, files, and runtime context",
        zh_description: "线程、套接字、文件和运行上下文",
        key_hint: "Enter",
        keywords: &["inspect", "details", "enter", "检查", "详情", "深检"],
    },
    PaletteCommand {
        id: PaletteCommandId::Search,
        en_name: "Search processes",
        zh_name: "搜索进程",
        en_description: "Filter the tree with a query",
        zh_description: "用查询过滤进程树",
        key_hint: "/",
        keywords: &["search", "filter", "query", "搜索", "查询", "过滤"],
    },
    PaletteCommand {
        id: PaletteCommandId::ToggleStar,
        en_name: "Toggle star",
        zh_name: "切换星标",
        en_description: "Star or unstar the selected process",
        zh_description: "为选中进程加星标或取消星标",
        key_hint: "*",
        keywords: &["star", "mark", "星标", "标记"],
    },
    PaletteCommand {
        id: PaletteCommandId::NextStarred,
        en_name: "Next starred",
        zh_name: "下一个星标",
        en_description: "Jump to the next starred process",
        zh_description: "跳到下一个星标进程",
        key_hint: "'",
        keywords: &["star", "mark", "next", "jump", "星标", "下一个", "跳转"],
    },
    PaletteCommand {
        id: PaletteCommandId::Actions,
        en_name: "Process actions",
        zh_name: "进程操作",
        en_description: "TERM, KILL, STOP, or CONT with confirmation",
        zh_description: "经明确确认发送 TERM/KILL/STOP/CONT",
        key_hint: "p",
        keywords: &["actions", "kill", "term", "signal", "操作", "终止", "信号"],
    },
    PaletteCommand {
        id: PaletteCommandId::Dossier,
        en_name: "Process dossier",
        zh_name: "进程档案",
        en_description: "One dossier with prioritized evidence",
        zh_description: "带优先级线索的单进程档案",
        key_hint: "D",
        keywords: &["dossier", "evidence", "档案", "线索"],
    },
    PaletteCommand {
        id: PaletteCommandId::Memory,
        en_name: "Memory attribution",
        zh_name: "内存归因",
        en_description: "RSS, PSS, swap, regions, and mapped files",
        zh_description: "归因 RSS、PSS、Swap、区域和映射",
        key_hint: "M",
        keywords: &["memory", "mem", "rss", "pss", "swap", "内存", "归因"],
    },
    PaletteCommand {
        id: PaletteCommandId::Service,
        en_name: "Service context",
        zh_name: "服务归属",
        en_description: "systemd or launchd ownership and state",
        zh_description: "systemd/launchd 归属、状态和配置",
        key_hint: "m",
        keywords: &["service", "systemd", "launchd", "服务", "归属"],
    },
    PaletteCommand {
        id: PaletteCommandId::Verify,
        en_name: "Verify executable",
        zh_name: "验证映像",
        en_description: "Image identity, package, hash, and signature",
        zh_description: "运行映像、软件包、哈希和代码签名",
        key_hint: "v",
        keywords: &[
            "verify",
            "executable",
            "image",
            "hash",
            "signature",
            "验证",
            "映像",
            "签名",
        ],
    },
    PaletteCommand {
        id: PaletteCommandId::Logs,
        en_name: "Process logs",
        zh_name: "进程日志",
        en_description: "Bounded native logs for process or service",
        zh_description: "进程或服务的有界原生日志",
        key_hint: "l",
        keywords: &["logs", "log", "journal", "日志"],
    },
    PaletteCommand {
        id: PaletteCommandId::Network,
        en_name: "Network workspace",
        zh_name: "网络面板",
        en_description: "Listeners, connections, peers, and owners",
        zh_description: "监听、连接、对端和所有者",
        key_hint: "n",
        keywords: &[
            "network",
            "net",
            "ports",
            "connections",
            "网络",
            "端口",
            "连接",
        ],
    },
    PaletteCommand {
        id: PaletteCommandId::FindPort,
        en_name: "Find port…",
        zh_name: "查找端口…",
        en_description: "Open the network workspace on a port lookup",
        zh_description: "打开网络面板并直接定位端口",
        key_hint: "n → p",
        keywords: &["port", "find", "locate", "端口", "查找", "定位"],
    },
    PaletteCommand {
        id: PaletteCommandId::Hotspots,
        en_name: "Hotspots",
        zh_name: "热点",
        en_description: "CPU, memory, read, and write ranking",
        zh_description: "CPU、内存、读写排行",
        key_hint: "h",
        keywords: &["hotspots", "hot", "cpu", "热点", "排行"],
    },
    PaletteCommand {
        id: PaletteCommandId::Attention,
        en_name: "Attention",
        zh_name: "关注事项",
        en_description: "Unhealthy state, churn, pressure, and growth",
        zh_description: "异常状态、抖动、压力和增长",
        key_hint: "a",
        keywords: &["attention", "alerts", "关注", "告警", "异常"],
    },
    PaletteCommand {
        id: PaletteCommandId::Trend,
        en_name: "Resource trend",
        zh_name: "资源趋势",
        en_description: "Recent own and complete-subtree trend",
        zh_description: "自身及完整子树的近期趋势",
        key_hint: "t",
        keywords: &["trend", "chart", "趋势", "曲线"],
    },
    PaletteCommand {
        id: PaletteCommandId::Events,
        en_name: "Recent events",
        zh_name: "近期事件",
        en_description: "Process changes and action audit",
        zh_description: "进程变化和操作审计",
        key_hint: "e",
        keywords: &["events", "audit", "changes", "事件", "审计"],
    },
    PaletteCommand {
        id: PaletteCommandId::Filters,
        en_name: "Process filters",
        zh_name: "进程过滤器",
        en_description: "Persistent allow/deny rules before search",
        zh_description: "先于搜索的持久包含/排除规则",
        key_hint: "F",
        keywords: &["filters", "allow", "deny", "rules", "过滤器", "规则"],
    },
    PaletteCommand {
        id: PaletteCommandId::Focus,
        en_name: "Toggle focus",
        zh_name: "聚焦切换",
        en_description: "Focus the selected parent chain and subtree",
        zh_description: "聚焦选中进程的父链和服务子树",
        key_hint: "f",
        keywords: &["focus", "聚焦"],
    },
    PaletteCommand {
        id: PaletteCommandId::Sort,
        en_name: "Cycle sort mode",
        zh_name: "切换排序",
        en_description: "Stable and service-tree hotspot sorting",
        zh_description: "稳定排序和服务树热点排序",
        key_hint: "s",
        keywords: &["sort", "排序"],
    },
    PaletteCommand {
        id: PaletteCommandId::Pause,
        en_name: "Pause or resume",
        zh_name: "暂停或恢复",
        en_description: "Freeze or resume live refresh",
        zh_description: "冻结或恢复实时刷新",
        key_hint: "Space",
        keywords: &["pause", "resume", "freeze", "space", "暂停", "恢复", "冻结"],
    },
    PaletteCommand {
        id: PaletteCommandId::Refresh,
        en_name: "Refresh now",
        zh_name: "立即刷新",
        en_description: "Sample processes manually",
        zh_description: "手工采样一次进程",
        key_hint: "r",
        keywords: &["refresh", "reload", "sample", "刷新", "采样"],
    },
    PaletteCommand {
        id: PaletteCommandId::CaptureBaseline,
        en_name: "Capture baseline",
        zh_name: "捕获基线",
        en_description: "Snapshot resources for later comparison",
        zh_description: "为后续对比捕获资源快照",
        key_hint: "b",
        keywords: &["baseline", "capture", "基线", "捕获"],
    },
    PaletteCommand {
        id: PaletteCommandId::SnapshotDiff,
        en_name: "Snapshot diff",
        zh_name: "快照对比",
        en_description: "Compare against the captured baseline",
        zh_description: "与已捕获的基线对比",
        key_hint: "d",
        keywords: &["diff", "snapshot", "compare", "对比", "快照"],
    },
    PaletteCommand {
        id: PaletteCommandId::ClearBaseline,
        en_name: "Clear baseline",
        zh_name: "清除基线",
        en_description: "Drop the captured baseline",
        zh_description: "丢弃已捕获的基线",
        key_hint: "x",
        keywords: &["clear", "drop", "清除", "丢弃"],
    },
    PaletteCommand {
        id: PaletteCommandId::ExportReport,
        en_name: "Export report",
        zh_name: "导出报告",
        en_description: "Private, versioned diagnostic report",
        zh_description: "私有、版本化诊断报告",
        key_hint: "o",
        keywords: &["export", "report", "导出", "报告"],
    },
    PaletteCommand {
        id: PaletteCommandId::Language,
        en_name: "Switch language",
        zh_name: "切换语言",
        en_description: "English ↔ 中文",
        zh_description: "中文 ↔ English",
        key_hint: "L",
        keywords: &["language", "english", "chinese", "语言", "中文", "英文"],
    },
    PaletteCommand {
        id: PaletteCommandId::CycleTheme,
        en_name: "Cycle theme",
        zh_name: "切换主题",
        en_description: "Rotate dark, light, and high-contrast",
        zh_description: "轮换深色、浅色和高对比主题",
        key_hint: ":",
        keywords: &[
            "theme", "color", "dark", "light", "contrast", "主题", "颜色",
        ],
    },
    PaletteCommand {
        id: PaletteCommandId::ToggleGlyphs,
        en_name: "Toggle ASCII glyphs",
        zh_name: "切换字符集",
        en_description: "Unicode ↔ ASCII tree and status glyphs",
        zh_description: "Unicode ↔ ASCII 树形与状态字符",
        key_hint: ":",
        keywords: &["glyphs", "ascii", "unicode", "charset", "字符", "字符集"],
    },
    PaletteCommand {
        id: PaletteCommandId::Help,
        en_name: "Field guide",
        zh_name: "现场手册",
        en_description: "Open the interactive help",
        zh_description: "打开交互式帮助",
        key_hint: "?",
        keywords: &["help", "guide", "帮助", "手册"],
    },
    PaletteCommand {
        id: PaletteCommandId::Quit,
        en_name: "Quit psmore",
        zh_name: "退出 psmore",
        en_description: "Exit the TUI",
        zh_description: "退出交互界面",
        key_hint: "q",
        keywords: &["quit", "exit", "退出"],
    },
];

/// Case-insensitive subsequence match; every query character must appear in
/// the target in order. Works for Chinese because lowercase is a no-op there.
fn subsequence_match(query: &str, target: &str) -> bool {
    let target: Vec<char> = target.to_lowercase().chars().collect();
    let mut position = 0;
    for needle in query.to_lowercase().chars() {
        let mut found = false;
        while position < target.len() {
            let candidate = target[position];
            position += 1;
            if candidate == needle {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

pub(crate) struct App {
    pub(crate) provider: NativeProcessProvider,
    pub(crate) processes: HashMap<Pid, ProcessInfo>,
    pub(crate) children: HashMap<Option<Pid>, Vec<Pid>>,
    pub(crate) resources: HashMap<Pid, ResourceAggregate>,
    pub(crate) history: ResourceHistory,
    pub(crate) trend_pid: Option<Pid>,
    pub(crate) trend_view: TrendView,
    pub(crate) show_hotspots: bool,
    pub(crate) hotspot_metric: HotspotMetric,
    pub(crate) hotspot_scope: HotspotScope,
    pub(crate) hotspot_selected: Option<Pid>,
    pub(crate) show_attention: bool,
    pub(crate) attention_selected: Option<Pid>,
    pub(crate) baseline: Option<BaselineSnapshot>,
    pub(crate) show_snapshot_diff: bool,
    pub(crate) snapshot_diff_scroll: u16,
    pub(crate) network_scan: Option<NetworkScan>,
    pub(crate) show_network: bool,
    network_task: Option<NetworkTask>,
    pub(crate) network_scope: NetworkScope,
    pub(crate) network_selected: usize,
    pub(crate) network_filter: String,
    pub(crate) network_searching: bool,
    pub(crate) network_port_input: Option<String>,
    pub(crate) network_port_filter: Option<u16>,
    /// Port lookup submitted while the first background scan is still
    /// running; applied as soon as a snapshot arrives.
    pub(crate) network_pending_port: Option<u16>,
    pub(crate) sort_mode: SortMode,
    pub(crate) visible: Vec<TreeRow>,
    pub(crate) selected: usize,
    pub(crate) expanded: HashSet<Pid>,
    pub(crate) collapsed: HashSet<Pid>,
    pub(crate) tree_offset: usize,
    pub(crate) search: String,
    pub(crate) searching: bool,
    pub(crate) search_input: String,
    pub(crate) search_error: Option<String>,
    pub(crate) search_matches: usize,
    /// Applied `/` queries, most recent first, persisted via ui-state.json.
    pub(crate) query_history: Vec<String>,
    /// Shell-style history walk: `None` sits on the in-progress draft.
    search_history_index: Option<usize>,
    search_draft: String,
    search_completion: Option<SearchCompletion>,
    /// Session-only starred processes keyed by PID + start time, so a reused
    /// PID never inherits another instance's star.
    pub(crate) marks: HashSet<ProcessMark>,
    pub(crate) process_filters: Vec<ProcessFilterRule>,
    pub(crate) show_filter_manager: bool,
    pub(crate) filter_selected: usize,
    pub(crate) filter_editor: Option<FilterEditor>,
    pub(crate) filter_error: Option<String>,
    pub(crate) filtered_processes: usize,
    pub(crate) pid_input: Option<String>,
    pub(crate) pid_input_error: Option<String>,
    pub(crate) focus: Option<Pid>,
    pub(crate) last_refresh: Instant,
    pub(crate) marquee_offset: usize,
    pub(crate) last_marquee: Instant,
    pub(crate) marquee_pid: Option<Pid>,
    pub(crate) marquee_phase: MarqueePhase,
    pub(crate) page_size: usize,
    pub(crate) error: Option<String>,
    pub(crate) notice: Option<StatusNotice>,
    pub(crate) paused: bool,
    pub(crate) show_events: bool,
    pub(crate) events: Vec<ProcessEvent>,
    pub(crate) last_changes: ChangeSummary,
    pub(crate) inspection: Option<ProcessInspection>,
    inspection_task: Option<InspectionTask>,
    pub(crate) inspection_tab: InspectionTab,
    pub(crate) inspection_scroll: u16,
    pub(crate) service_context: Option<ServiceContextPanel>,
    service_context_task: Option<ServiceContextTask>,
    pub(crate) service_context_scroll: u16,
    pub(crate) executable_context: Option<ExecutableContextPanel>,
    executable_context_task: Option<ExecutableContextTask>,
    pub(crate) executable_context_scroll: u16,
    pub(crate) memory_context: Option<MemoryContextPanel>,
    memory_context_task: Option<MemoryContextTask>,
    pub(crate) memory_context_scroll: u16,
    pub(crate) logs_context: Option<LogsContextPanel>,
    logs_context_task: Option<LogsContextTask>,
    pub(crate) logs_context_scroll: u16,
    pub(crate) dossier_context: Option<DossierContextPanel>,
    dossier_context_task: Option<DossierContextTask>,
    pub(crate) dossier_context_scroll: u16,
    pub(crate) process_action: Option<ProcessActionDialog>,
    pub(crate) action_history: Vec<ProcessActionRecord>,
    pub(crate) host_metrics: HostMetrics,
    pub(crate) load_history: VecDeque<f64>,
    pub(crate) guidance: Guidance,
    pub(crate) show_palette: bool,
    pub(crate) palette_query: String,
    pub(crate) palette_selected: usize,
    pub(crate) theme_id: ThemeId,
    pub(crate) theme: Theme,
    pub(crate) glyph_mode: GlyphMode,
    pub(crate) glyphs: Glyphs,
    /// Screen regions recorded by the last draw so mouse clicks can be mapped
    /// back to tree rows and inspection tabs.
    pub(crate) tree_area: Rect,
    pub(crate) inspection_tab_regions: Vec<(Rect, InspectionTab)>,
}

impl App {
    #[cfg(test)]
    pub(crate) fn new_for_test(guidance: Guidance) -> Self {
        // Tests pin dark/unicode so rendering assertions never depend on the
        // host environment; production resolves the real precedence chain.
        Self::new_with_guidance(
            String::new(),
            guidance,
            Some(ThemeId::Dark),
            Some(GlyphMode::Unicode),
        )
    }

    pub(crate) fn new_for_tui(
        query: String,
        suppress_guidance: bool,
        theme_override: Option<ThemeId>,
        glyph_override: Option<GlyphMode>,
    ) -> Self {
        Self::new_with_guidance(
            query,
            Guidance::load_default(suppress_guidance),
            theme_override,
            glyph_override,
        )
    }

    pub(crate) fn language(&self) -> UiLanguage {
        self.guidance.language()
    }

    fn toggle_language(&mut self) {
        let result = self.guidance.toggle_language();
        let language = self.guidance.language();
        self.notice = Some(StatusNotice {
            message: match &result {
                Ok(_) => match language {
                    UiLanguage::Chinese => "界面语言已切换为中文".into(),
                    UiLanguage::English => "Interface language changed to English".into(),
                },
                Err(error) => format!(
                    "{}: {error}",
                    text(
                        language,
                        "language changed, but the preference could not be saved",
                        "语言已切换，但无法保存偏好"
                    )
                ),
            },
            is_error: result.is_err(),
            observed_at: Instant::now(),
        });
    }

    fn new_with_guidance(
        query: String,
        mut guidance: Guidance,
        theme_override: Option<ThemeId>,
        glyph_override: Option<GlyphMode>,
    ) -> Self {
        let has_initial_query = !query.is_empty();
        let guidance_warning = guidance.take_warning();
        let process_filters = guidance.filters().to_vec();
        // Theme/glyph resolution keeps the resolved id next to the resolved
        // struct so runtime switching is a one-field update plus persist.
        let env_theme = std::env::var("PSMORE_THEME")
            .ok()
            .and_then(|value| ThemeId::parse(&value));
        let theme_id = resolve_theme_id(theme_override, env_theme, guidance.theme());
        let env_glyphs = std::env::var("PSMORE_GLYPHS")
            .ok()
            .and_then(|value| GlyphMode::parse(&value));
        let locales = ["LC_ALL", "LC_CTYPE", "LANG"]
            .into_iter()
            .map(|key| std::env::var(key).ok())
            .collect::<Vec<_>>();
        let glyph_mode = resolve_glyph_mode(
            glyph_override,
            env_glyphs,
            guidance.glyphs(),
            std::env::var("TERM").ok().as_deref(),
            &locales,
        );
        let mut app = Self {
            provider: NativeProcessProvider::new(),
            processes: HashMap::new(),
            children: HashMap::new(),
            resources: HashMap::new(),
            history: ResourceHistory::default(),
            trend_pid: None,
            trend_view: TrendView::default(),
            show_hotspots: false,
            hotspot_metric: HotspotMetric::default(),
            hotspot_scope: HotspotScope::default(),
            hotspot_selected: None,
            show_attention: false,
            attention_selected: None,
            baseline: None,
            show_snapshot_diff: false,
            snapshot_diff_scroll: 0,
            network_scan: None,
            show_network: false,
            network_task: None,
            network_scope: NetworkScope::default(),
            network_selected: 0,
            network_filter: String::new(),
            network_searching: false,
            network_port_input: None,
            network_port_filter: None,
            network_pending_port: None,
            sort_mode: SortMode::Stable,
            visible: Vec::new(),
            selected: 0,
            expanded: HashSet::new(),
            collapsed: HashSet::new(),
            tree_offset: 0,
            search: query,
            searching: false,
            search_input: String::new(),
            search_error: None,
            search_matches: 0,
            query_history: guidance.query_history().to_vec(),
            search_history_index: None,
            search_draft: String::new(),
            search_completion: None,
            marks: HashSet::new(),
            process_filters,
            show_filter_manager: false,
            filter_selected: 0,
            filter_editor: None,
            filter_error: None,
            filtered_processes: 0,
            pid_input: None,
            pid_input_error: None,
            focus: None,
            last_refresh: Instant::now(),
            marquee_offset: 0,
            last_marquee: Instant::now(),
            marquee_pid: None,
            marquee_phase: MarqueePhase::Scrolling,
            page_size: 10,
            error: None,
            notice: None,
            paused: false,
            show_events: false,
            events: Vec::new(),
            last_changes: ChangeSummary::default(),
            inspection: None,
            inspection_task: None,
            inspection_tab: InspectionTab::default(),
            inspection_scroll: 0,
            service_context: None,
            service_context_task: None,
            service_context_scroll: 0,
            executable_context: None,
            executable_context_task: None,
            executable_context_scroll: 0,
            memory_context: None,
            memory_context_task: None,
            memory_context_scroll: 0,
            logs_context: None,
            logs_context_task: None,
            logs_context_scroll: 0,
            dossier_context: None,
            dossier_context_task: None,
            dossier_context_scroll: 0,
            process_action: None,
            action_history: Vec::new(),
            host_metrics: HostMetrics {
                hostname: String::new(),
                load_one: 0.0,
                cpu_percent: 0.0,
                memory_used: 0,
                memory_total: 0,
                swap_used: 0,
                swap_total: 0,
            },
            load_history: VecDeque::new(),
            guidance,
            show_palette: false,
            palette_query: String::new(),
            palette_selected: 0,
            theme_id,
            theme: theme_id.theme(),
            glyph_mode,
            glyphs: glyph_mode.glyphs(),
            tree_area: Rect::default(),
            inspection_tab_regions: Vec::new(),
        };
        if let Some(message) = guidance_warning {
            app.notice = Some(StatusNotice {
                message,
                is_error: true,
                observed_at: Instant::now(),
            });
        }
        app.refresh();
        if has_initial_query {
            app.select_first_match();
        }
        app
    }

    pub(crate) fn refresh(&mut self) {
        let next_processes: HashMap<Pid, ProcessInfo> = self
            .provider
            .refresh()
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        self.host_metrics = self.provider.host_metrics();
        self.load_history.push_back(self.host_metrics.load_one);
        while self.load_history.len() > LOAD_HISTORY_SAMPLES {
            self.load_history.pop_front();
        }
        let changes = if self.processes.is_empty() {
            Vec::new()
        } else {
            diff_processes(&self.processes, &next_processes)
        };
        self.processes = next_processes;
        self.record_changes(changes);
        self.children.clear();
        for process in self.processes.values() {
            self.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        self.resources = aggregate_resources(&self.processes, &self.children);
        let observed_at = Instant::now();
        self.history
            .record(&self.processes, &self.resources, observed_at);
        self.sort_children();
        if self.expanded.is_empty() {
            self.expanded.insert(Pid::from_u32(0));
            self.expanded.extend(
                self.children
                    .values()
                    .flatten()
                    .filter(|pid| {
                        self.children
                            .get(&Some(**pid))
                            .map(|c| !c.is_empty())
                            .unwrap_or(false)
                    })
                    .copied(),
            );
        }
        self.rebuild_visible();
        if self.show_hotspots {
            self.ensure_hotspot_selection();
        }
        if self.show_attention {
            self.ensure_attention_selection();
        }
        self.last_refresh = observed_at;
        self.error = None;
    }

    pub(crate) fn poll_background_jobs(&mut self) {
        let network_result = self
            .network_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match network_result {
            Some(Ok(scan)) => {
                let elapsed = self
                    .network_task
                    .take()
                    .map(|task| task.started_at.elapsed())
                    .unwrap_or_default();
                let endpoint_count = scan.endpoints.len();
                self.network_scan = Some(scan);
                let visible = self.network_visible_indices();
                self.network_selected = self.network_selected.min(visible.len().saturating_sub(1));
                self.notice = Some(StatusNotice {
                    message: match self.language() {
                        UiLanguage::English => format!(
                            "network scan complete: {endpoint_count} endpoints in {:.1}s",
                            elapsed.as_secs_f64()
                        ),
                        UiLanguage::Chinese => format!(
                            "网络扫描完成：{endpoint_count} 个端点，耗时 {:.1}s",
                            elapsed.as_secs_f64()
                        ),
                    },
                    is_error: false,
                    observed_at: Instant::now(),
                });
                // A port lookup submitted before the first snapshot arrived
                // can now be resolved against real data.
                if let Some(port) = self.network_pending_port.take() {
                    self.apply_network_port_filter(port);
                }
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.network_task = None;
                self.network_pending_port = None;
                if self.network_scan.is_none() {
                    self.show_network = false;
                }
                self.notice = Some(StatusNotice {
                    message: text(
                        self.language(),
                        "network scan failed: background worker stopped",
                        "网络扫描失败：后台任务已停止",
                    )
                    .into(),
                    is_error: true,
                    observed_at: Instant::now(),
                });
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let inspection_result = self
            .inspection_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match inspection_result {
            Some(Ok(mut inspection)) => {
                let task = self.inspection_task.take();
                if let Some(task) = task {
                    let same_instance = self
                        .processes
                        .get(&task.pid)
                        .map(|process| {
                            task.start_time == 0
                                || process.start_time == 0
                                || process.start_time == task.start_time
                        })
                        .unwrap_or(false);
                    if !same_instance {
                        let warning =
                            "process exited or PID was reused while inspection was running";
                        inspection.warning = Some(match inspection.warning {
                            Some(existing) => format!("{existing}; {warning}"),
                            None => warning.into(),
                        });
                    }
                }
                self.inspection = Some(inspection);
                self.inspection_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.inspection_task = None;
                if let Some(inspection) = &mut self.inspection {
                    inspection.warning = Some("inspection background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let service_result = self
            .service_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match service_result {
            Some(Ok(result)) => {
                let task = self.service_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.service_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while service context was collected"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                            }
                            Err(error) => panel.warning = Some(error),
                        }
                    }
                }
                self.service_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.service_context_task = None;
                if let Some(panel) = &mut self.service_context {
                    panel.warning = Some("service context background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let executable_result = self
            .executable_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match executable_result {
            Some(Ok(result)) => {
                let task = self.executable_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.executable_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while executable image was verified"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                            }
                            Err(error) => panel.warning = Some(error),
                        }
                    }
                }
                self.executable_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.executable_context_task = None;
                if let Some(panel) = &mut self.executable_context {
                    panel.warning =
                        Some("executable verification background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let memory_result = self
            .memory_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match memory_result {
            Some(Ok(result)) => {
                let task = self.memory_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.memory_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while memory evidence was collected"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                                panel.warning = None;
                            }
                            Err(error) => {
                                panel.content.clear();
                                panel.report = None;
                                panel.warning = Some(error);
                            }
                        }
                    }
                }
                self.memory_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.memory_context_task = None;
                if let Some(panel) = &mut self.memory_context {
                    panel.warning = Some("memory evidence background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let logs_result = self
            .logs_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match logs_result {
            Some(Ok(result)) => {
                let task = self.logs_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.logs_context {
                    match result {
                        Ok((content, report)) => {
                            panel.content = content;
                            panel.report = Some(report);
                            panel.warning = (!same_instance).then(|| {
                                "process exited or changed after collection; showing the bounded report for the originally selected process instance".into()
                            });
                        }
                        Err(error) => {
                            panel.content.clear();
                            panel.report = None;
                            panel.warning = Some(error);
                        }
                    }
                }
                self.logs_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.logs_context_task = None;
                if let Some(panel) = &mut self.logs_context {
                    panel.warning = Some("native log background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }

        let dossier_result = self
            .dossier_context_task
            .as_ref()
            .map(|task| task.receiver.try_recv());
        match dossier_result {
            Some(Ok(result)) => {
                let task = self.dossier_context_task.take();
                let same_instance = task
                    .as_ref()
                    .map(|task| {
                        self.processes
                            .get(&task.pid)
                            .map(|process| {
                                task.start_time == 0
                                    || process.start_time == 0
                                    || process.start_time == task.start_time
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if let Some(panel) = &mut self.dossier_context {
                    if !same_instance {
                        panel.content.clear();
                        panel.report = None;
                        panel.warning = Some(
                            "process exited or PID was reused while the dossier was collected"
                                .into(),
                        );
                    } else {
                        match result {
                            Ok((content, report)) => {
                                panel.content = content;
                                panel.report = Some(report);
                                panel.warning = None;
                            }
                            Err(error) => {
                                panel.content.clear();
                                panel.report = None;
                                panel.warning = Some(error);
                            }
                        }
                    }
                }
                self.dossier_context_scroll = 0;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.dossier_context_task = None;
                if let Some(panel) = &mut self.dossier_context {
                    panel.warning = Some("dossier background worker stopped".into());
                }
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
    }

    pub(crate) fn network_is_scanning(&self) -> bool {
        self.network_task.is_some()
    }

    pub(crate) fn network_scan_elapsed(&self) -> Duration {
        self.network_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn inspection_is_scanning(&self) -> bool {
        self.inspection_task.is_some()
    }

    pub(crate) fn inspection_elapsed(&self) -> Duration {
        self.inspection_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn service_context_is_scanning(&self) -> bool {
        self.service_context_task.is_some()
    }

    pub(crate) fn service_context_elapsed(&self) -> Duration {
        self.service_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn executable_context_is_scanning(&self) -> bool {
        self.executable_context_task.is_some()
    }

    pub(crate) fn executable_context_elapsed(&self) -> Duration {
        self.executable_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn memory_context_is_scanning(&self) -> bool {
        self.memory_context_task.is_some()
    }

    pub(crate) fn memory_context_elapsed(&self) -> Duration {
        self.memory_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn logs_context_is_scanning(&self) -> bool {
        self.logs_context_task.is_some()
    }

    pub(crate) fn logs_context_elapsed(&self) -> Duration {
        self.logs_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    pub(crate) fn dossier_context_is_scanning(&self) -> bool {
        self.dossier_context_task.is_some()
    }

    pub(crate) fn dossier_context_elapsed(&self) -> Duration {
        self.dossier_context_task
            .as_ref()
            .map(|task| task.started_at.elapsed())
            .unwrap_or_default()
    }

    fn record_changes(&mut self, changes: Vec<ProcessChange>) {
        let mut summary = ChangeSummary::default();
        let now = Instant::now();
        for change in changes {
            match &change {
                ProcessChange::Started { .. } => summary.started += 1,
                ProcessChange::Exited { .. } => summary.exited += 1,
                ProcessChange::Reparented { .. } => summary.reparented += 1,
            }
            self.events.push(ProcessEvent {
                change,
                observed_at: now,
            });
        }
        self.last_changes = summary;
        const MAX_EVENTS: usize = 200;
        if self.events.len() > MAX_EVENTS {
            self.events.drain(..self.events.len() - MAX_EVENTS);
        }
    }

    pub(crate) fn recent_change(&self, pid: Pid) -> Option<&ProcessChange> {
        self.events
            .iter()
            .rev()
            .find(|event| {
                event.change.pid() == pid && event.observed_at.elapsed() <= Duration::from_secs(5)
            })
            .map(|event| &event.change)
    }

    fn toggle_paused(&mut self) {
        self.paused = !self.paused;
        if !self.paused {
            self.refresh();
        }
    }

    fn close_dossier_context(&mut self) {
        self.dossier_context = None;
        self.dossier_context_task = None;
        self.dossier_context_scroll = 0;
    }

    fn close_memory_context(&mut self) {
        self.memory_context = None;
        self.memory_context_task = None;
        self.memory_context_scroll = 0;
    }

    fn start_inspection(&mut self, process: ProcessInfo, clear_previous: bool) {
        if self.inspection_task.is_some() {
            return;
        }
        if clear_previous {
            self.inspection = Some(ProcessInspection {
                pid: process.pid,
                name: process.name.clone(),
                user: process.user.clone(),
                cwd: process.cwd.clone(),
                ..ProcessInspection::default()
            });
            self.inspection_tab = InspectionTab::default();
            self.inspection_scroll = 0;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-inspect-{}", pid.as_u32()))
            .spawn(move || {
                let _ = sender.send(inspect_process(&process));
            }) {
            Ok(_) => {
                self.inspection_task = Some(InspectionTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(inspection) = &mut self.inspection {
                    inspection.warning = Some(format!("cannot start inspection: {error}"));
                }
            }
        }
    }

    fn open_inspection(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_events = false;
        self.close_memory_context();
        self.close_dossier_context();
        self.start_inspection(process, true);
    }

    fn refresh_inspection(&mut self) {
        if self.inspection_task.is_some() {
            return;
        }
        let Some(pid) = self.inspection.as_ref().map(|inspection| inspection.pid) else {
            self.open_inspection();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(inspection) = &mut self.inspection {
                inspection.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_inspection(process, false);
    }

    fn start_service_context(&mut self, process: ProcessInfo, clear_previous: bool) {
        if self.service_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.service_context = Some(ServiceContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
            });
            self.service_context_scroll = 0;
        } else if let Some(panel) = &mut self.service_context {
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-service-context-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_service_context(pid.as_u32()).and_then(|captured| {
                    let table = render_service_table(&captured);
                    let json = render_service_json(&captured)
                        .map_err(|error| format!("cannot serialize service context: {error}"))?;
                    let report = serde_json::from_str(&json)
                        .map_err(|error| format!("cannot serialize service context: {error}"))?;
                    Ok((table, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.service_context_task = Some(ServiceContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.service_context {
                    panel.warning = Some(format!("cannot start service context: {error}"));
                }
            }
        }
    }

    fn open_service_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.clear_network_filters();
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_memory_context();
        self.close_dossier_context();
        self.show_events = false;
        self.start_service_context(process, true);
    }

    fn refresh_service_context(&mut self) {
        if self.service_context_task.is_some() {
            return;
        }
        let Some(pid) = self.service_context.as_ref().map(|panel| panel.pid) else {
            self.open_service_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.service_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_service_context(process, false);
    }

    fn start_executable_context(&mut self, process: ProcessInfo, hash: bool, clear_previous: bool) {
        if self.executable_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.executable_context = Some(ExecutableContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
                hash,
            });
            self.executable_context_scroll = 0;
        } else if let Some(panel) = &mut self.executable_context {
            panel.warning = None;
            panel.report = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-executable-context-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_executable(pid.as_u32(), hash).and_then(|captured| {
                    let table = render_executable_table(&captured);
                    let json = render_executable_json(&captured)
                        .map_err(|error| format!("cannot serialize executable context: {error}"))?;
                    let report = serde_json::from_str(&json).map_err(|error| {
                        format!("cannot parse executable context JSON: {error}")
                    })?;
                    Ok((table, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.executable_context_task = Some(ExecutableContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.executable_context {
                    panel.warning = Some(format!("cannot start executable verification: {error}"));
                }
            }
        }
    }

    fn open_executable_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.clear_network_filters();
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_memory_context();
        self.close_dossier_context();
        self.show_events = false;
        self.start_executable_context(process, true, true);
    }

    fn refresh_executable_context(&mut self) {
        if self.executable_context_task.is_some() {
            return;
        }
        let Some((pid, hash)) = self
            .executable_context
            .as_ref()
            .map(|panel| (panel.pid, panel.hash))
        else {
            self.open_executable_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.executable_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_executable_context(process, hash, false);
    }

    fn toggle_executable_hash(&mut self) {
        if self.executable_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.executable_context {
            panel.hash = !panel.hash;
            panel.content.clear();
            panel.report = None;
        }
        self.refresh_executable_context();
    }

    fn start_memory_context(&mut self, process: ProcessInfo, clear_previous: bool) {
        if self.memory_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.memory_context = Some(MemoryContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
            });
            self.memory_context_scroll = 0;
        } else if let Some(panel) = &mut self.memory_context {
            panel.content.clear();
            panel.report = None;
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-memory-context-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_memory(pid.as_u32(), Some(20)).and_then(|captured| {
                    let table = render_memory_table(&captured);
                    let json = render_memory_json(&captured)
                        .map_err(|error| format!("cannot serialize memory evidence: {error}"))?;
                    let report = serde_json::from_str(&json)
                        .map_err(|error| format!("cannot parse memory evidence JSON: {error}"))?;
                    Ok((table, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.memory_context_task = Some(MemoryContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.memory_context {
                    panel.warning = Some(format!("cannot start memory collection: {error}"));
                }
            }
        }
    }

    fn open_memory_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.clear_network_filters();
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_dossier_context();
        self.show_events = false;
        self.start_memory_context(process, true);
    }

    fn refresh_memory_context(&mut self) {
        if self.memory_context_task.is_some() {
            return;
        }
        let Some(pid) = self.memory_context.as_ref().map(|panel| panel.pid) else {
            self.open_memory_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.memory_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_memory_context(process, false);
    }

    fn start_logs_context(
        &mut self,
        process: ProcessInfo,
        scope: LogScope,
        priority: LogPriority,
        since_seconds: u64,
        limit: usize,
        clear_previous: bool,
    ) {
        if self.logs_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.logs_context = Some(LogsContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
                scope,
                priority,
                since_seconds,
                limit,
            });
            self.logs_context_scroll = 0;
        } else if let Some(panel) = &mut self.logs_context {
            panel.content.clear();
            panel.report = None;
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-native-logs-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_logs(pid.as_u32(), scope, priority, since_seconds, limit)
                    .and_then(|captured| {
                        let table = render_logs_table(&captured);
                        let json = render_logs_json(&captured)
                            .map_err(|error| format!("cannot serialize native logs: {error}"))?;
                        let report = serde_json::from_str(&json)
                            .map_err(|error| format!("cannot parse native log JSON: {error}"))?;
                        Ok((table, report))
                    });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.logs_context_task = Some(LogsContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.logs_context {
                    panel.warning = Some(format!("cannot start native log collection: {error}"));
                }
            }
        }
    }

    fn open_logs_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.clear_network_filters();
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.close_memory_context();
        self.close_dossier_context();
        self.show_events = false;
        self.start_logs_context(
            process,
            LogScope::Auto,
            LogPriority::Info,
            15 * 60,
            100,
            true,
        );
    }

    fn refresh_logs_context(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        let Some((pid, scope, priority, since_seconds, limit)) =
            self.logs_context.as_ref().map(|panel| {
                (
                    panel.pid,
                    panel.scope,
                    panel.priority,
                    panel.since_seconds,
                    panel.limit,
                )
            })
        else {
            self.open_logs_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.logs_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_logs_context(process, scope, priority, since_seconds, limit, false);
    }

    fn cycle_logs_scope(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.logs_context {
            panel.scope = panel.scope.next();
        }
        self.refresh_logs_context();
    }

    fn cycle_logs_priority(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.logs_context {
            panel.priority = panel.priority.next();
        }
        self.refresh_logs_context();
    }

    fn cycle_logs_window(&mut self) {
        if self.logs_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.logs_context {
            panel.since_seconds = match panel.since_seconds {
                0..=300 => 15 * 60,
                301..=900 => 60 * 60,
                901..=3_600 => 6 * 60 * 60,
                _ => 5 * 60,
            };
        }
        self.refresh_logs_context();
    }

    #[allow(clippy::too_many_arguments)]
    fn start_dossier_context(
        &mut self,
        process: ProcessInfo,
        include_logs: bool,
        hash: bool,
        scope: LogScope,
        priority: LogPriority,
        since_seconds: u64,
        limit: usize,
        clear_previous: bool,
    ) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if clear_previous {
            self.dossier_context = Some(DossierContextPanel {
                pid: process.pid,
                name: process.name.clone(),
                content: String::new(),
                report: None,
                warning: None,
                include_logs,
                hash,
                scope,
                priority,
                since_seconds,
                limit,
            });
            self.dossier_context_scroll = 0;
        } else if let Some(panel) = &mut self.dossier_context {
            panel.content.clear();
            panel.report = None;
            panel.warning = None;
        }
        let pid = process.pid;
        let start_time = process.start_time;
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name(format!("psmore-dossier-{}", pid.as_u32()))
            .spawn(move || {
                let result = capture_dossier(
                    pid.as_u32(),
                    ExplainOptions {
                        sample_ms: 500,
                        hash,
                        include_logs,
                        logs_scope: scope,
                        logs_priority: priority,
                        logs_since_seconds: since_seconds,
                        logs_limit: limit,
                    },
                )
                .and_then(|captured| {
                    let content = render_dossier_summary_table(&captured);
                    let json = render_dossier_json(&captured)
                        .map_err(|error| format!("cannot serialize process dossier: {error}"))?;
                    let report = serde_json::from_str(&json)
                        .map_err(|error| format!("cannot parse process dossier JSON: {error}"))?;
                    Ok((content, report))
                });
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.dossier_context_task = Some(DossierContextTask {
                    receiver,
                    started_at: Instant::now(),
                    pid,
                    start_time,
                });
            }
            Err(error) => {
                if let Some(panel) = &mut self.dossier_context {
                    panel.warning = Some(format!("cannot start dossier collection: {error}"));
                }
            }
        }
    }

    fn open_dossier_context(&mut self) {
        let Some(process) = self
            .selected_pid()
            .and_then(|pid| self.processes.get(&pid))
            .cloned()
        else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.clear_network_filters();
        self.show_snapshot_diff = false;
        self.trend_pid = None;
        self.inspection = None;
        self.inspection_task = None;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.close_memory_context();
        self.show_events = false;
        self.start_dossier_context(
            process,
            true,
            true,
            LogScope::Auto,
            LogPriority::Info,
            15 * 60,
            100,
            true,
        );
    }

    fn refresh_dossier_context(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        let Some((pid, include_logs, hash, scope, priority, since_seconds, limit)) =
            self.dossier_context.as_ref().map(|panel| {
                (
                    panel.pid,
                    panel.include_logs,
                    panel.hash,
                    panel.scope,
                    panel.priority,
                    panel.since_seconds,
                    panel.limit,
                )
            })
        else {
            self.open_dossier_context();
            return;
        };
        let Some(process) = self.processes.get(&pid).cloned() else {
            if let Some(panel) = &mut self.dossier_context {
                panel.warning = Some("process has exited since this snapshot".into());
            }
            return;
        };
        self.start_dossier_context(
            process,
            include_logs,
            hash,
            scope,
            priority,
            since_seconds,
            limit,
            false,
        );
    }

    fn cycle_dossier_scope(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.scope = panel.scope.next();
            panel.include_logs = true;
        }
        self.refresh_dossier_context();
    }

    fn cycle_dossier_priority(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.priority = panel.priority.next();
            panel.include_logs = true;
        }
        self.refresh_dossier_context();
    }

    fn cycle_dossier_window(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.since_seconds = match panel.since_seconds {
                0..=300 => 15 * 60,
                301..=900 => 60 * 60,
                901..=3_600 => 6 * 60 * 60,
                _ => 5 * 60,
            };
            panel.include_logs = true;
        }
        self.refresh_dossier_context();
    }

    fn toggle_dossier_hash(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.hash = !panel.hash;
        }
        self.refresh_dossier_context();
    }

    fn toggle_dossier_logs(&mut self) {
        if self.dossier_context_task.is_some() {
            return;
        }
        if let Some(panel) = &mut self.dossier_context {
            panel.include_logs = !panel.include_logs;
        }
        self.refresh_dossier_context();
    }

    fn rebuild_visible(&mut self) {
        let old_pid = self.visible.get(self.selected).map(|row| row.pid);
        self.visible.clear();
        let active_filters = self
            .process_filters
            .iter()
            .filter(|rule| rule.enabled)
            .count();
        let compiled_filters = match CompiledProcessFilters::compile(&self.process_filters) {
            Ok(filters) => {
                self.filter_error = None;
                Some(filters)
            }
            Err(error) => {
                // Fail open: a malformed persisted rule must never hide the
                // process table during an incident.
                self.filter_error = Some(error);
                None
            }
        };
        let filter_applied = active_filters > 0 && compiled_filters.is_some();
        let allowed: HashSet<Pid> = self
            .processes
            .values()
            .filter(|process| {
                let subtree = self
                    .resources
                    .get(&process.pid)
                    .copied()
                    .unwrap_or_default();
                let direct_children = self
                    .children
                    .get(&Some(process.pid))
                    .map(Vec::len)
                    .unwrap_or(0);
                compiled_filters
                    .as_ref()
                    .map(|filters| filters.matches(process, subtree, direct_children))
                    .unwrap_or(true)
            })
            .map(|process| process.pid)
            .collect();
        self.filtered_processes = allowed.iter().filter(|pid| pid.as_u32() != 0).count();

        let query = ProcessQuery::parse(&self.search);
        let matched: HashSet<Pid> = match query {
            Ok(query) => {
                self.search_error = None;
                allowed
                    .iter()
                    .filter_map(|pid| self.processes.get(pid))
                    .filter(|process| {
                        let subtree = self
                            .resources
                            .get(&process.pid)
                            .copied()
                            .unwrap_or_default();
                        let direct_children = self
                            .children
                            .get(&Some(process.pid))
                            .map(Vec::len)
                            .unwrap_or(0);
                        query.matches(process, subtree, direct_children)
                    })
                    .map(|process| process.pid)
                    .collect()
            }
            Err(error) => {
                self.search_error = Some(error);
                HashSet::new()
            }
        };
        self.search_matches = if self.search.is_empty() {
            0
        } else {
            matched.iter().filter(|pid| pid.as_u32() != 0).count()
        };
        let restricted = filter_applied || !self.search.is_empty();
        let search_active = !self.search.is_empty();
        let tree_selection = TreeSelection {
            matched: &matched,
            allowed: &allowed,
            restricted,
            filter_applied,
            search_active,
        };

        if let Some(focus) = self.focus {
            let mut chain = Vec::new();
            let mut current = Some(focus);
            while let Some(pid) = current {
                chain.push(pid);
                current = self.processes.get(&pid).and_then(|p| p.parent);
            }
            chain.reverse();
            for (depth, pid) in chain.iter().enumerate() {
                self.visible.push(TreeRow {
                    pid: *pid,
                    depth,
                    last_path: vec![false; depth],
                    is_last: depth == chain.len().saturating_sub(1),
                });
            }
            self.walk_children(
                focus,
                chain.len(),
                vec![false; chain.len()],
                &tree_selection,
            );
        } else {
            let roots = [Pid::from_u32(0)];
            for (index, pid) in roots.iter().enumerate() {
                self.walk(*pid, Vec::new(), index == roots.len() - 1, &tree_selection);
            }
        }
        if self.visible.is_empty() && !self.processes.is_empty() {
            let mut all: Vec<Pid> = self.processes.keys().copied().collect();
            all.sort_by_key(|p| p.as_u32());
            for pid in all {
                if matched.contains(&pid) {
                    self.visible.push(TreeRow {
                        pid,
                        depth: 0,
                        last_path: Vec::new(),
                        is_last: true,
                    });
                }
            }
        }
        self.selected = old_pid
            .and_then(|pid| self.visible.iter().position(|row| row.pid == pid))
            .unwrap_or(self.selected.min(self.visible.len().saturating_sub(1)));
    }

    fn walk(
        &mut self,
        pid: Pid,
        last_path: Vec<bool>,
        is_last: bool,
        selection: &TreeSelection<'_>,
    ) {
        let has_match = selection.matched.contains(&pid);
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let descendant_match = descendants
            .iter()
            .any(|child| self.has_matching_descendant(*child, selection.matched));
        if has_match || descendant_match || !selection.restricted {
            let depth = last_path.len();
            self.visible.push(TreeRow {
                pid,
                depth,
                last_path: last_path.clone(),
                is_last,
            });
            if self.expanded.contains(&pid)
                || (selection.restricted && descendant_match && !self.collapsed.contains(&pid))
            {
                let visible_children: Vec<Pid> = descendants
                    .into_iter()
                    .filter(|child| {
                        if selection.search_active && has_match {
                            !selection.filter_applied
                                || self.has_matching_descendant(*child, selection.allowed)
                        } else {
                            !selection.restricted
                                || self.has_matching_descendant(*child, selection.matched)
                        }
                    })
                    .collect();
                for (index, child) in visible_children.iter().enumerate() {
                    let mut child_path = last_path.clone();
                    child_path.push(is_last);
                    if selection.search_active && has_match {
                        self.walk_context(
                            *child,
                            child_path,
                            index == visible_children.len() - 1,
                            selection,
                        );
                    } else {
                        self.walk(
                            *child,
                            child_path,
                            index == visible_children.len() - 1,
                            selection,
                        );
                    }
                }
            }
        }
    }

    /// Once a search hit is visible, show its complete descendant context.
    /// Search still filters the ancestors and unrelated branches, but it must
    /// not hide the children that explain what the matched process owns.
    fn walk_context(
        &mut self,
        pid: Pid,
        last_path: Vec<bool>,
        is_last: bool,
        selection: &TreeSelection<'_>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        if selection.filter_applied && !self.has_matching_descendant(pid, selection.allowed) {
            return;
        }
        let depth = last_path.len();
        self.visible.push(TreeRow {
            pid,
            depth,
            last_path: last_path.clone(),
            is_last,
        });
        if self.expanded.contains(&pid) && !self.collapsed.contains(&pid) {
            let visible_children: Vec<Pid> = descendants
                .into_iter()
                .filter(|child| {
                    !selection.filter_applied
                        || self.has_matching_descendant(*child, selection.allowed)
                })
                .collect();
            for (index, child) in visible_children.iter().enumerate() {
                let mut child_path = last_path.clone();
                child_path.push(is_last);
                self.walk_context(
                    *child,
                    child_path,
                    index == visible_children.len() - 1,
                    selection,
                );
            }
        }
    }

    fn walk_children(
        &mut self,
        pid: Pid,
        depth: usize,
        last_path: Vec<bool>,
        selection: &TreeSelection<'_>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let visible_children: Vec<Pid> = descendants
            .into_iter()
            .filter(|child| {
                !selection.restricted || self.has_matching_descendant(*child, selection.matched)
            })
            .collect();
        for (index, child) in visible_children.iter().enumerate() {
            let mut child_path = last_path.clone();
            child_path.push(index == visible_children.len() - 1);
            self.visible.push(TreeRow {
                pid: *child,
                depth,
                last_path: child_path.clone(),
                is_last: index == visible_children.len() - 1,
            });
            if self.expanded.contains(child)
                || (!selection.restricted && !self.collapsed.contains(child))
                || (selection.restricted
                    && self.has_matching_descendant(*child, selection.matched)
                    && !self.collapsed.contains(child))
            {
                if selection.search_active && selection.matched.contains(child) {
                    let grandchildren = self
                        .children
                        .get(&Some(*child))
                        .cloned()
                        .unwrap_or_default();
                    let visible_grandchildren: Vec<Pid> = grandchildren
                        .into_iter()
                        .filter(|grandchild| {
                            !selection.filter_applied
                                || self.has_matching_descendant(*grandchild, selection.allowed)
                        })
                        .collect();
                    for (grandchild_index, grandchild) in visible_grandchildren.iter().enumerate() {
                        let mut grandchild_path = child_path.clone();
                        grandchild_path.push(index == visible_children.len() - 1);
                        self.walk_context(
                            *grandchild,
                            grandchild_path,
                            grandchild_index == visible_grandchildren.len() - 1,
                            selection,
                        );
                    }
                } else {
                    self.walk_children(*child, depth + 1, child_path, selection);
                }
            }
        }
    }

    fn has_matching_descendant(&self, pid: Pid, matched: &HashSet<Pid>) -> bool {
        if matched.contains(&pid) {
            return true;
        }
        self.children
            .get(&Some(pid))
            .map(|children| {
                children
                    .iter()
                    .any(|p| self.has_matching_descendant(*p, matched))
            })
            .unwrap_or(false)
    }

    pub(crate) fn selected_pid(&self) -> Option<Pid> {
        self.visible.get(self.selected).map(|row| row.pid)
    }

    fn ensure_visible_ancestor_chain(&mut self, pid: Pid) {
        let mut current = Some(pid);
        let mut seen = HashSet::new();
        while let Some(current_pid) = current {
            if !seen.insert(current_pid) {
                break;
            }
            self.expanded.insert(current_pid);
            self.collapsed.remove(&current_pid);
            current = self
                .processes
                .get(&current_pid)
                .and_then(|process| process.parent);
        }
    }

    fn restore_selection_to_anchor(&mut self, anchor_pid: Pid) {
        if let Some(index) = self.visible.iter().position(|row| row.pid == anchor_pid) {
            self.selected = index;
            return;
        }
        self.focus = None;
        self.ensure_visible_ancestor_chain(anchor_pid);
        self.rebuild_visible();
        self.selected = self
            .visible
            .iter()
            .position(|row| row.pid == anchor_pid)
            .unwrap_or(self.selected.min(self.visible.len().saturating_sub(1)));
    }

    fn ensure_tree_view_row(&mut self, preferred_row: usize) {
        let view_height = self.page_size.max(1);
        let target_row = preferred_row.min(view_height.saturating_sub(1));
        let max_offset = self.visible.len().saturating_sub(view_height);
        self.tree_offset = self.selected.saturating_sub(target_row).min(max_offset);
    }

    fn selected_context(&self) -> Option<String> {
        let pid = self.selected_pid()?;
        let process = self.processes.get(&pid)?;
        Some(process_path(process))
    }

    pub(crate) fn advance_marquee(&mut self, width: usize) {
        let selected = self.selected_pid();
        if self.marquee_pid != selected {
            self.marquee_pid = selected;
            self.marquee_offset = 0;
            self.marquee_phase = MarqueePhase::Scrolling;
            self.last_marquee = Instant::now();
        }
        let Some(context) = self.selected_context() else {
            return;
        };
        let max_offset = context.width().saturating_sub(width);
        if width == 0 || max_offset == 0 {
            self.marquee_offset = 0;
            self.marquee_phase = MarqueePhase::Scrolling;
            return;
        }
        let now = Instant::now();
        match self.marquee_phase {
            MarqueePhase::Scrolling => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(125) {
                    self.marquee_offset = self.marquee_offset.saturating_add(1);
                    self.last_marquee = now;
                    if self.marquee_offset >= max_offset {
                        self.marquee_offset = max_offset;
                        self.marquee_phase = MarqueePhase::TailPause;
                    }
                }
            }
            MarqueePhase::TailPause => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(2500) {
                    self.marquee_offset = 0;
                    self.marquee_phase = MarqueePhase::ResetPause;
                    self.last_marquee = now;
                }
            }
            MarqueePhase::ResetPause => {
                if now.duration_since(self.last_marquee) >= Duration::from_millis(1000) {
                    self.marquee_phase = MarqueePhase::Scrolling;
                    self.last_marquee = now;
                }
            }
        }
    }

    fn select_first_match(&mut self) {
        if self.search.is_empty() {
            return;
        }
        let Ok(query) = ProcessQuery::parse(&self.search) else {
            return;
        };
        let filters = CompiledProcessFilters::compile(&self.process_filters).ok();
        if let Some(index) = self.visible.iter().position(|row| {
            self.processes
                .get(&row.pid)
                .map(|process| {
                    let subtree = self
                        .resources
                        .get(&process.pid)
                        .copied()
                        .unwrap_or_default();
                    let direct_children = self
                        .children
                        .get(&Some(process.pid))
                        .map(Vec::len)
                        .unwrap_or(0);
                    filters
                        .as_ref()
                        .map(|filters| filters.matches(process, subtree, direct_children))
                        .unwrap_or(true)
                        && query.matches(process, subtree, direct_children)
                })
                .unwrap_or(false)
        }) {
            self.selected = index;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if self.visible.is_empty() {
            return;
        }
        let max = self.visible.len() - 1;
        self.selected = (self.selected as isize + delta).clamp(0, max as isize) as usize;
    }

    fn toggle_focus(&mut self) {
        self.focus = if self.focus == self.selected_pid() {
            None
        } else {
            self.selected_pid()
        };
        self.selected = 0;
        self.rebuild_visible();
    }

    pub(crate) fn is_starred(&self, pid: Pid) -> bool {
        self.processes
            .get(&pid)
            .map(|process| {
                self.marks.contains(&ProcessMark {
                    pid,
                    start_time: process.start_time,
                })
            })
            .unwrap_or(false)
    }

    fn toggle_star(&mut self) {
        let Some(pid) = self.selected_pid() else {
            return;
        };
        let Some(process) = self.processes.get(&pid) else {
            return;
        };
        let mark = ProcessMark {
            pid,
            start_time: process.start_time,
        };
        let starred = self.marks.insert(mark);
        if !starred {
            self.marks.remove(&mark);
        }
        let name = process.name.clone();
        self.notice = Some(StatusNotice {
            message: match (self.language(), starred) {
                (UiLanguage::English, true) => format!("starred {name} [{pid}]"),
                (UiLanguage::English, false) => format!("unstarred {name} [{pid}]"),
                (UiLanguage::Chinese, true) => format!("已加星标 {name} [{pid}]"),
                (UiLanguage::Chinese, false) => format!("已取消星标 {name} [{pid}]"),
            },
            is_error: false,
            observed_at: Instant::now(),
        });
    }

    /// Jump to the next starred row in the current tree view, wrapping around.
    /// Stars live by process identity, so rebuilds, collapse, and filtering
    /// simply decide whether a starred row is currently visible.
    fn jump_to_next_starred(&mut self) {
        if self.marks.is_empty() {
            self.notice = Some(StatusNotice {
                message: text(
                    self.language(),
                    "no starred processes; press * to star the selected one",
                    "暂无星标进程；按 * 为选中进程加星标",
                )
                .into(),
                is_error: false,
                observed_at: Instant::now(),
            });
            return;
        }
        // An empty view (e.g. a search with zero hits) has no row to land
        // on; iterating it would also divide by zero in the wrap-around.
        if self.visible.is_empty() {
            self.notice = Some(StatusNotice {
                message: text(
                    self.language(),
                    "starred process is not visible in the current view",
                    "星标进程在当前视图中不可见",
                )
                .into(),
                is_error: false,
                observed_at: Instant::now(),
            });
            return;
        }
        let count = self.visible.len();
        for step in 1..=count {
            let index = (self.selected + step) % count;
            if self.is_starred(self.visible[index].pid) {
                self.selected = index;
                return;
            }
        }
        self.notice = Some(StatusNotice {
            message: text(
                self.language(),
                "starred process is not visible in the current view",
                "星标进程在当前视图中不可见",
            )
            .into(),
            is_error: false,
            observed_at: Instant::now(),
        });
    }

    fn toggle_selected_expanded(&mut self) {
        let Some(pid) = self.selected_pid() else {
            return;
        };
        if self
            .children
            .get(&Some(pid))
            .map(|c| !c.is_empty())
            .unwrap_or(false)
        {
            if !self.expanded.insert(pid) {
                self.expanded.remove(&pid);
                self.collapsed.insert(pid);
            } else {
                self.collapsed.remove(&pid);
            }
            self.rebuild_visible();
        }
    }

    fn sort_children(&mut self) {
        for children in self.children.values_mut() {
            sort_processes(children, self.sort_mode, &self.processes, &self.resources);
        }
    }

    fn cycle_sort_mode(&mut self) {
        self.sort_mode = self.sort_mode.next();
        self.sort_children();
        self.rebuild_visible();
    }

    fn reveal_parent(&mut self) {
        let Some(pid) = self.selected_pid() else {
            return;
        };
        let Some(parent) = self.processes.get(&pid).and_then(|p| p.parent) else {
            return;
        };

        // Expose the complete ancestor path, but keep the parent's other branches collapsed.
        let mut current = Some(parent);
        while let Some(ancestor) = current {
            self.expanded.insert(ancestor);
            self.collapsed.remove(&ancestor);
            current = self.processes.get(&ancestor).and_then(|p| p.parent);
        }
        if let Some(siblings) = self.children.get(&Some(parent)).cloned() {
            for sibling in siblings {
                if sibling != pid {
                    self.expanded.remove(&sibling);
                    self.collapsed.insert(sibling);
                }
            }
        }
        self.rebuild_visible();
        if let Some(index) = self.visible.iter().position(|row| row.pid == parent) {
            self.selected = index;
        }
    }

    fn apply_search_input(&mut self) {
        if !self.searching {
            return;
        }
        self.searching = false;
        self.search_history_index = None;
        self.search_completion = None;
        self.search = std::mem::take(&mut self.search_input);
        self.record_query_history();
        self.rebuild_visible();
        self.select_first_match();
    }

    /// Remember the just-applied query (dedup, most recent first, capped) and
    /// persist it next to the other private UI preferences.
    fn record_query_history(&mut self) {
        let query = self.search.trim();
        if query.is_empty() {
            return;
        }
        self.query_history.retain(|entry| entry != query);
        self.query_history.insert(0, query.to_string());
        self.query_history.truncate(MAX_QUERY_HISTORY);
        if let Err(error) = self.guidance.save_query_history(&self.query_history) {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => {
                        format!("query applied, but the history could not be saved: {error}")
                    }
                    UiLanguage::Chinese => format!("查询已应用，但无法保存历史：{error}"),
                },
                is_error: true,
                observed_at: Instant::now(),
            });
        }
    }

    /// `↑` in search mode walks towards older queries; the first press saves
    /// the in-progress draft so `↓` can return to it.
    fn search_history_previous(&mut self) {
        if self.query_history.is_empty() {
            return;
        }
        match self.search_history_index {
            None => {
                self.search_draft = self.search_input.clone();
                self.search_history_index = Some(0);
            }
            Some(index) if index + 1 < self.query_history.len() => {
                self.search_history_index = Some(index + 1);
            }
            Some(_) => return,
        }
        if let Some(index) = self.search_history_index {
            self.search_input = self.query_history[index].clone();
        }
        self.search_completion = None;
    }

    /// `↓` walks back towards newer queries and finally restores the draft.
    fn search_history_next(&mut self) {
        match self.search_history_index {
            Some(0) => {
                self.search_history_index = None;
                self.search_input = self.search_draft.clone();
            }
            Some(index) => {
                self.search_history_index = Some(index - 1);
                self.search_input = self.query_history[index - 1].clone();
            }
            None => {}
        }
        self.search_completion = None;
    }

    /// `Tab` completes the current token against query field starters.
    /// Repeated presses cycle the candidates for the original partial token;
    /// any other edit ends the cycle.
    fn complete_search_field(&mut self) {
        // Find the byte index just past the last whitespace. `rfind` returns
        // the whitespace's byte offset, so stepping one byte forward would
        // land inside a multi-byte whitespace such as U+3000; advance by the
        // character's full UTF-8 length instead.
        let token_start = self
            .search_input
            .char_indices()
            .rev()
            .find(|(_, c)| c.is_whitespace())
            .map(|(index, c)| index + c.len_utf8())
            .unwrap_or(0);
        let token = &self.search_input[token_start..];
        let cycling = self
            .search_completion
            .as_ref()
            .filter(|state| {
                state.token_start == token_start && token == state.candidates[state.index]
            })
            .map(|state| {
                (
                    state.candidates.clone(),
                    (state.index + 1) % state.candidates.len(),
                )
            });
        let (candidates, index) = match cycling {
            Some(next) => next,
            None => {
                if !token.is_empty() && !QUERY_FIELD_STARTERS.iter().any(|s| s.starts_with(token)) {
                    self.search_completion = None;
                    return;
                }
                let candidates: Vec<&'static str> = QUERY_FIELD_STARTERS
                    .iter()
                    .copied()
                    .filter(|starter| starter.starts_with(token))
                    .collect();
                if candidates.is_empty() {
                    self.search_completion = None;
                    return;
                }
                (candidates, 0)
            }
        };
        let candidate = candidates[index];
        self.search_input.replace_range(token_start.., candidate);
        self.search_completion = Some(SearchCompletion {
            token_start,
            candidates,
            index,
        });
    }

    pub(crate) fn active_filter_count(&self) -> usize {
        self.process_filters
            .iter()
            .filter(|rule| rule.enabled)
            .count()
    }

    fn persist_process_filters(&mut self) {
        if let Err(error) = self.guidance.save_filters(&self.process_filters) {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => {
                        format!("filters changed, but the preference could not be saved: {error}")
                    }
                    UiLanguage::Chinese => format!("过滤规则已更改，但无法保存偏好：{error}"),
                },
                is_error: true,
                observed_at: Instant::now(),
            });
        }
    }

    fn open_filter_manager(&mut self) {
        self.show_filter_manager = true;
        self.filter_editor = None;
        self.filter_selected = self
            .filter_selected
            .min(self.process_filters.len().saturating_sub(1));
    }

    fn close_filter_manager(&mut self) {
        self.show_filter_manager = false;
        self.filter_editor = None;
    }

    fn start_filter_editor(&mut self, action: FilterAction) {
        self.filter_editor = Some(FilterEditor {
            action,
            input: String::new(),
            error: None,
            editing_index: None,
            enabled: true,
        });
    }

    fn edit_selected_filter(&mut self) {
        let Some(rule) = self.process_filters.get(self.filter_selected) else {
            return;
        };
        self.filter_editor = Some(FilterEditor {
            action: rule.action,
            input: rule.expression.clone(),
            error: None,
            editing_index: Some(self.filter_selected),
            enabled: rule.enabled,
        });
    }

    fn apply_filter_editor(&mut self) {
        let language = self.language();
        let Some(editor) = &mut self.filter_editor else {
            return;
        };
        let expression = editor.input.trim();
        if expression.is_empty() {
            editor.error = Some(
                text(
                    language,
                    "filter expression cannot be empty",
                    "过滤表达式不能为空",
                )
                .into(),
            );
            return;
        }
        if let Err(error) = ProcessQuery::parse(expression) {
            editor.error = Some(error);
            return;
        }
        let rule = ProcessFilterRule {
            action: editor.action,
            expression: expression.into(),
            enabled: editor.enabled,
        };
        if let Some(index) = editor.editing_index {
            self.process_filters[index] = rule;
            self.filter_selected = index;
        } else {
            self.process_filters.push(rule);
            self.filter_selected = self.process_filters.len() - 1;
        }
        self.filter_editor = None;
        self.persist_process_filters();
        self.rebuild_visible();
    }

    fn toggle_selected_filter(&mut self) {
        let Some(rule) = self.process_filters.get_mut(self.filter_selected) else {
            return;
        };
        rule.enabled = !rule.enabled;
        if let Err(error) = CompiledProcessFilters::compile(&self.process_filters) {
            if let Some(rule) = self.process_filters.get_mut(self.filter_selected) {
                rule.enabled = !rule.enabled;
            }
            self.filter_error = Some(error);
            return;
        }
        self.persist_process_filters();
        self.rebuild_visible();
    }

    fn remove_selected_filter(&mut self) {
        if self.process_filters.is_empty() {
            return;
        }
        self.process_filters.remove(self.filter_selected);
        self.filter_selected = self
            .filter_selected
            .min(self.process_filters.len().saturating_sub(1));
        self.persist_process_filters();
        self.rebuild_visible();
    }

    fn capture_baseline(&mut self) {
        self.baseline = Some(BaselineSnapshot::capture(
            &self.processes,
            &self.resources,
            Instant::now(),
        ));
        self.snapshot_diff_scroll = 0;
    }

    fn export_diagnostic_report(&mut self) {
        let attention_findings = self.attention_findings();
        let result = std::env::current_dir().and_then(|directory| {
            export_report(
                ReportInput {
                    platform: platform_name(),
                    selected_pid: self.selected_pid(),
                    query: &self.search,
                    query_editing: self.searching,
                    query_error: self.search_error.as_deref(),
                    query_matches: self.search_matches,
                    process_filters: &self.process_filters,
                    filter_error: self.filter_error.as_deref(),
                    filtered_processes: self.filtered_processes,
                    paused: self.paused,
                    sort_mode: self.sort_mode,
                    processes: &self.processes,
                    resources: &self.resources,
                    events: &self.events,
                    attention_findings: &attention_findings,
                    network: self.network_scan.as_ref(),
                    network_scope: self.network_scope,
                    network_scan_in_progress: self.network_is_scanning(),
                    inspection: self.inspection.as_ref(),
                    inspection_in_progress: self.inspection_is_scanning(),
                    service_context: self
                        .service_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    service_context_in_progress: self.service_context_is_scanning(),
                    executable_context: self
                        .executable_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    executable_context_in_progress: self.executable_context_is_scanning(),
                    memory_context: self
                        .memory_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    memory_context_in_progress: self.memory_context_is_scanning(),
                    logs_context: self
                        .logs_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    logs_context_in_progress: self.logs_context_is_scanning(),
                    dossier_context: self
                        .dossier_context
                        .as_ref()
                        .and_then(|panel| panel.report.as_ref()),
                    dossier_context_in_progress: self.dossier_context_is_scanning(),
                    action_history: &self.action_history,
                    baseline: self.baseline.as_ref(),
                },
                &directory,
            )
        });
        self.notice = Some(match result {
            Ok(path) => StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!("report saved: {}", path.display()),
                    UiLanguage::Chinese => format!("报告已保存：{}", path.display()),
                },
                is_error: false,
                observed_at: Instant::now(),
            },
            Err(error) => StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!("report export failed: {error}"),
                    UiLanguage::Chinese => format!("报告导出失败：{error}"),
                },
                is_error: true,
                observed_at: Instant::now(),
            },
        });
    }

    fn start_network_scan(&mut self, clear_previous: bool) {
        if self.network_task.is_some() {
            return;
        }
        if clear_previous {
            self.network_scan = None;
        }
        let processes = self.processes.clone();
        let (sender, receiver) = mpsc::channel();
        match thread::Builder::new()
            .name("psmore-network-scan".into())
            .spawn(move || {
                let _ = sender.send(scan_network(&processes));
            }) {
            Ok(_) => {
                self.network_task = Some(NetworkTask {
                    receiver,
                    started_at: Instant::now(),
                });
            }
            Err(error) => {
                self.show_network = false;
                self.notice = Some(StatusNotice {
                    message: match self.language() {
                        UiLanguage::English => format!("cannot start network scan: {error}"),
                        UiLanguage::Chinese => format!("无法启动网络扫描：{error}"),
                    },
                    is_error: true,
                    observed_at: Instant::now(),
                });
            }
        }
    }

    fn open_network(&mut self) {
        self.show_network = true;
        self.start_network_scan(true);
        self.network_scope = NetworkScope::default();
        self.network_selected = 0;
        self.clear_network_filters();
        self.show_events = false;
        self.inspection = None;
        self.inspection_task = None;
        self.trend_pid = None;
        self.show_snapshot_diff = false;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_attention = false;
        self.attention_selected = None;
    }

    fn open_hotspots(&mut self) {
        self.show_hotspots = true;
        self.hotspot_metric = HotspotMetric::default();
        self.hotspot_scope = HotspotScope::default();
        self.show_network = false;
        self.clear_network_filters();
        self.show_events = false;
        self.inspection = None;
        self.inspection_task = None;
        self.trend_pid = None;
        self.show_snapshot_diff = false;
        self.show_attention = false;
        self.attention_selected = None;
        self.reset_hotspot_selection();
    }

    fn open_attention(&mut self) {
        self.show_attention = true;
        self.show_network = false;
        self.clear_network_filters();
        self.show_events = false;
        self.inspection = None;
        self.inspection_task = None;
        self.trend_pid = None;
        self.show_snapshot_diff = false;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.reset_attention_selection();
    }

    pub(crate) fn attention_findings(&self) -> Vec<AttentionFinding> {
        rank_attention_findings(&self.processes, &self.history, &self.events)
    }

    fn reset_attention_selection(&mut self) {
        self.attention_selected = self.attention_findings().first().map(|finding| finding.pid);
    }

    fn ensure_attention_selection(&mut self) {
        let findings = self.attention_findings();
        let selection_is_visible = self
            .attention_selected
            .map(|pid| findings.iter().any(|finding| finding.pid == pid))
            .unwrap_or(false);
        if !selection_is_visible {
            self.attention_selected = findings.first().map(|finding| finding.pid);
        }
    }

    fn move_attention_selection(&mut self, delta: isize) {
        let findings = self.attention_findings();
        if findings.is_empty() {
            self.attention_selected = None;
            return;
        }
        let current = self
            .attention_selected
            .and_then(|pid| findings.iter().position(|finding| finding.pid == pid))
            .unwrap_or(0);
        let next =
            (current as isize + delta).clamp(0, findings.len().saturating_sub(1) as isize) as usize;
        self.attention_selected = findings.get(next).map(|finding| finding.pid);
    }

    fn open_attention_trend(&mut self) {
        let Some(pid) = self.attention_selected else {
            return;
        };
        self.show_attention = false;
        self.attention_selected = None;
        self.trend_pid = Some(pid);
        self.trend_view = TrendView::default();
    }

    fn inspect_attention_process(&mut self) {
        let Some(pid) = self.attention_selected else {
            return;
        };
        self.jump_to_process(pid);
        self.open_inspection();
    }

    pub(crate) fn hotspot_ranked(&self, metric: HotspotMetric) -> Vec<Pid> {
        rank_hotspots(&self.processes, &self.resources, metric, self.hotspot_scope)
    }

    fn reset_hotspot_selection(&mut self) {
        self.hotspot_selected = self.hotspot_ranked(self.hotspot_metric).first().copied();
    }

    fn ensure_hotspot_selection(&mut self) {
        let selected_is_alive = self
            .hotspot_selected
            .map(|pid| self.processes.contains_key(&pid))
            .unwrap_or(false);
        if !selected_is_alive {
            self.reset_hotspot_selection();
        }
    }

    fn select_hotspot_metric(&mut self, metric: HotspotMetric) {
        self.hotspot_metric = metric;
        self.reset_hotspot_selection();
    }

    fn move_hotspot_selection(&mut self, delta: isize) {
        let ranked = self.hotspot_ranked(self.hotspot_metric);
        if ranked.is_empty() {
            self.hotspot_selected = None;
            return;
        }
        let current = self
            .hotspot_selected
            .and_then(|pid| ranked.iter().position(|candidate| *candidate == pid))
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, ranked.len().saturating_sub(1) as isize);
        self.hotspot_selected = ranked.get(next as usize).copied();
    }

    fn refresh_network(&mut self) {
        self.start_network_scan(false);
    }

    pub(crate) fn network_visible_indices(&self) -> Vec<usize> {
        self.network_scan
            .as_ref()
            .map(|scan| {
                scan.endpoints
                    .iter()
                    .enumerate()
                    .filter(|(_, endpoint)| self.network_scope.includes(endpoint))
                    .filter(|(_, endpoint)| endpoint.matches(&self.network_filter))
                    .filter(|(_, endpoint)| {
                        self.network_port_filter
                            .map(|port| endpoint.has_port(port))
                            .unwrap_or(true)
                    })
                    .map(|(index, _)| index)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reset every network-list narrowing (text filter, port filter, and any
    /// pending port input) so cross-links land on the bare endpoint list.
    fn clear_network_filters(&mut self) {
        self.network_filter.clear();
        self.network_searching = false;
        self.network_port_input = None;
        self.network_port_filter = None;
        self.network_pending_port = None;
    }

    fn finish_network_port_input(&mut self) {
        let Some(input) = self.network_port_input.take() else {
            return;
        };
        let port = match input.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                self.notice = Some(StatusNotice {
                    message: text(
                        self.language(),
                        "port must be a number between 0 and 65535",
                        "端口必须是 0-65535 之间的数字",
                    )
                    .into(),
                    is_error: true,
                    observed_at: Instant::now(),
                });
                return;
            }
        };
        // The port filter replaces the text filter: an exact lookup should
        // never be silently narrowed by an older substring.
        self.network_filter.clear();
        if self.network_scan.is_none() {
            // The initial background scan is still running, so there is no
            // snapshot to look the port up in. Keep it pending and apply it
            // when the scan completes instead of reporting a false negative.
            self.network_pending_port = Some(port);
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => {
                        format!("port {port} lookup will apply when the scan completes")
                    }
                    UiLanguage::Chinese => format!("将在扫描完成后查找端口 {port}"),
                },
                is_error: false,
                observed_at: Instant::now(),
            });
            return;
        }
        self.apply_network_port_filter(port);
    }

    /// Narrow the endpoint list to `port`, or report that no visible endpoint
    /// uses it. Requires a completed scan snapshot.
    fn apply_network_port_filter(&mut self, port: u16) {
        let found = self
            .network_scan
            .as_ref()
            .map(|scan| {
                scan.endpoints
                    .iter()
                    .filter(|endpoint| self.network_scope.includes(endpoint))
                    .any(|endpoint| endpoint.has_port(port))
            })
            .unwrap_or(false);
        if found {
            self.network_port_filter = Some(port);
            self.network_selected = 0;
        } else {
            self.network_port_filter = None;
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!("no endpoint on port {port}"),
                    UiLanguage::Chinese => format!("端口 {port} 上没有端点"),
                },
                is_error: false,
                observed_at: Instant::now(),
            });
        }
    }

    fn move_network_selection(&mut self, delta: isize) {
        let visible_len = self.network_visible_indices().len();
        if visible_len == 0 {
            self.network_selected = 0;
            return;
        }
        self.network_selected = (self.network_selected as isize + delta)
            .clamp(0, visible_len.saturating_sub(1) as isize)
            as usize;
    }

    fn jump_to_process(&mut self, pid: Pid) {
        if !self.processes.contains_key(&pid) {
            return;
        }
        self.show_network = false;
        self.clear_network_filters();
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_attention = false;
        self.attention_selected = None;
        self.search.clear();
        self.searching = false;
        self.search_input.clear();
        self.pid_input = None;
        self.pid_input_error = None;
        self.focus = None;
        let mut current = Some(pid);
        while let Some(process_pid) = current {
            self.expanded.insert(process_pid);
            self.collapsed.remove(&process_pid);
            current = self
                .processes
                .get(&process_pid)
                .and_then(|process| process.parent);
        }
        self.rebuild_visible();
        if let Some(index) = self.visible.iter().position(|row| row.pid == pid) {
            self.selected = index;
        }
    }

    fn open_process_action_for_mode(&mut self, pid: Pid, mode: ProcessActionDialogMode) {
        let Some(process) = self.processes.get(&pid) else {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => {
                        format!("cannot control PID {pid}: process is no longer visible")
                    }
                    UiLanguage::Chinese => format!("无法操作 PID {pid}：进程已不可见"),
                },
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        };
        if pid.as_u32() <= 1 || pid.as_u32() == std::process::id() {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!(
                        "cannot control {} [{}]: protected process",
                        process.name, pid
                    ),
                    UiLanguage::Chinese => {
                        format!("无法操作 {} [{}]：受保护进程", process.name, pid)
                    }
                },
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        }
        if process.start_time == 0 {
            self.notice = Some(StatusNotice {
                message: match self.language() {
                    UiLanguage::English => format!(
                        "cannot control {} [{}]: process instance identity is unavailable",
                        process.name, pid
                    ),
                    UiLanguage::Chinese => {
                        format!("无法操作 {} [{}]：无法确认进程实例身份", process.name, pid)
                    }
                },
                is_error: true,
                observed_at: Instant::now(),
            });
            return;
        }
        self.process_action = Some(ProcessActionDialog {
            target: ProcessActionTarget::from(process),
            selected: 0,
            confirming: false,
            mode,
        });
    }

    fn open_process_action_for(&mut self, pid: Pid) {
        self.open_process_action_for_mode(pid, ProcessActionDialogMode::All);
    }

    fn open_selected_process_action(&mut self) {
        if let Some(pid) = self.selected_pid() {
            self.open_process_action_for(pid);
        }
    }

    fn move_process_action_selection(&mut self, delta: isize) {
        let Some(dialog) = &mut self.process_action else {
            return;
        };
        let action_count = dialog.actions().len();
        dialog.selected = (dialog.selected as isize + delta)
            .clamp(0, action_count.saturating_sub(1) as isize) as usize;
        dialog.confirming = false;
    }

    fn choose_process_action(&mut self, action: ProcessActionKind) {
        let Some(dialog) = &mut self.process_action else {
            return;
        };
        if let Some(index) = dialog
            .actions()
            .iter()
            .position(|candidate| *candidate == action)
        {
            dialog.selected = index;
            dialog.confirming = true;
        }
    }

    fn execute_confirmed_process_action(&mut self) {
        let Some(dialog) = self.process_action.take() else {
            return;
        };
        let action = dialog.selected_action();
        let target = dialog.target;
        let outcome = execute_process_action(&target, action);
        let detail = outcome
            .detail()
            .map(|detail| format!(": {detail}"))
            .unwrap_or_default();
        self.notice = Some(StatusNotice {
            message: match self.language() {
                UiLanguage::English => format!(
                    "{} {} to {} [{}]{}",
                    outcome.label(),
                    action.label(),
                    target.name,
                    target.pid,
                    detail
                ),
                UiLanguage::Chinese => format!(
                    "{} {} 至 {} [{}]{}",
                    match &outcome {
                        ProcessActionOutcome::Sent => "已发送",
                        ProcessActionOutcome::Refused(_) => "已拒绝",
                        ProcessActionOutcome::Failed(_) => "失败",
                    },
                    action.label(),
                    target.name,
                    target.pid,
                    detail
                ),
            },
            is_error: outcome.is_error(),
            observed_at: Instant::now(),
        });
        self.action_history.push(ProcessActionRecord {
            observed_at: Instant::now(),
            target,
            action,
            outcome,
        });
        const MAX_ACTION_HISTORY: usize = 100;
        if self.action_history.len() > MAX_ACTION_HISTORY {
            self.action_history
                .drain(..self.action_history.len() - MAX_ACTION_HISTORY);
        }
        if !self.paused {
            self.refresh();
        }
    }

    fn begin_pid_input(&mut self, digit: char) {
        self.pid_input = Some(digit.to_string());
        self.pid_input_error = None;
    }

    fn process_passes_filters(&self, pid: Pid) -> bool {
        let Some(process) = self.processes.get(&pid) else {
            return false;
        };
        let Ok(filters) = CompiledProcessFilters::compile(&self.process_filters) else {
            return true;
        };
        let subtree = self.resources.get(&pid).copied().unwrap_or_default();
        let direct_children = self.children.get(&Some(pid)).map(Vec::len).unwrap_or(0);
        filters.matches(process, subtree, direct_children)
    }

    fn finish_pid_input(&mut self) {
        let Some(input) = self.pid_input.as_deref() else {
            return;
        };
        let pid_number = match input.parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => {
                self.pid_input_error = Some(
                    text(
                        self.language(),
                        "PID must fit in an unsigned 32-bit number",
                        "PID 必须是有效的 32 位无符号整数",
                    )
                    .into(),
                );
                return;
            }
        };
        let pid = Pid::from_u32(pid_number);
        if !self.processes.contains_key(&pid) {
            self.pid_input_error = Some(match self.language() {
                UiLanguage::English => format!("PID {pid_number} is not visible"),
                UiLanguage::Chinese => format!("PID {pid_number} 当前不可见"),
            });
            return;
        }
        if !self.process_passes_filters(pid) {
            self.pid_input_error = Some(match self.language() {
                UiLanguage::English => {
                    format!("PID {pid_number} is hidden by process filters; press Esc then F")
                }
                UiLanguage::Chinese => {
                    format!("PID {pid_number} 已被进程过滤器隐藏；按 Esc 后再按 F 管理")
                }
            });
            return;
        }
        self.jump_to_process(pid);
    }

    fn guidance_error_notice(
        &mut self,
        english_action: &str,
        chinese_action: &str,
        error: std::io::Error,
    ) {
        self.notice = Some(StatusNotice {
            message: match self.language() {
                UiLanguage::English => {
                    format!("{english_action}, but the preference could not be saved: {error}")
                }
                UiLanguage::Chinese => format!("{chinese_action}，但无法保存偏好：{error}"),
            },
            is_error: true,
            observed_at: Instant::now(),
        });
    }

    fn dismiss_guidance(&mut self) {
        if let Err(error) = self.guidance.dismiss() {
            self.guidance_error_notice("Guidance closed", "引导已关闭", error);
        }
    }

    fn disable_startup_guidance(&mut self) {
        if let Err(error) = self.guidance.disable_startup() {
            self.guidance_error_notice(
                "Startup cards disabled for this session",
                "本次启动卡片已关闭",
                error,
            );
        } else {
            self.notice = Some(StatusNotice {
                message: text(
                    self.language(),
                    "Startup help and tips disabled; press ? then T to enable tips again",
                    "启动手册和提示已停用；按 ? 后再按 T 可重新启用",
                )
                .into(),
                is_error: false,
                observed_at: Instant::now(),
            });
        }
    }

    fn toggle_startup_tips(&mut self) {
        match self.guidance.toggle_tips() {
            Ok(enabled) => {
                self.notice = Some(StatusNotice {
                    message: match self.language() {
                        UiLanguage::English => format!(
                            "Startup tips {}",
                            if enabled { "enabled" } else { "disabled" }
                        ),
                        UiLanguage::Chinese => {
                            format!("启动提示已{}", if enabled { "启用" } else { "停用" })
                        }
                    },
                    is_error: false,
                    observed_at: Instant::now(),
                });
            }
            Err(error) => self.guidance_error_notice(
                "Tip preference changed for this session",
                "本次提示偏好已更改",
                error,
            ),
        }
    }

    /// Rotate dark → light → high-contrast, persist the choice, and confirm
    /// through the notice bar. A failed save still applies the theme for the
    /// current session, matching the language-toggle behavior.
    pub(crate) fn cycle_theme(&mut self) {
        self.theme_id = self.theme_id.next();
        self.theme = self.theme_id.theme();
        let result = self.guidance.set_theme(self.theme_id);
        let language = self.language();
        self.notice = Some(StatusNotice {
            message: match &result {
                Ok(_) => match language {
                    UiLanguage::English => format!("Theme: {}", self.theme_id.label()),
                    UiLanguage::Chinese => format!(
                        "主题：{}",
                        match self.theme_id {
                            ThemeId::Dark => "深色",
                            ThemeId::Light => "浅色",
                            ThemeId::HighContrast => "高对比",
                        }
                    ),
                },
                Err(error) => format!(
                    "{}: {error}",
                    text(
                        language,
                        "theme changed, but the preference could not be saved",
                        "主题已切换，但无法保存偏好"
                    )
                ),
            },
            is_error: result.is_err(),
            observed_at: Instant::now(),
        });
    }

    /// Flip the unicode ↔ ASCII glyph repertoire, persist, and confirm.
    pub(crate) fn toggle_glyphs(&mut self) {
        self.glyph_mode = self.glyph_mode.next();
        self.glyphs = self.glyph_mode.glyphs();
        let result = self.guidance.set_glyphs(self.glyph_mode);
        let language = self.language();
        self.notice = Some(StatusNotice {
            message: match &result {
                Ok(_) => match language {
                    UiLanguage::English => format!("Glyphs: {}", self.glyph_mode.label()),
                    UiLanguage::Chinese => format!(
                        "字符集：{}",
                        match self.glyph_mode {
                            GlyphMode::Unicode => "Unicode",
                            GlyphMode::Ascii => "ASCII",
                        }
                    ),
                },
                Err(error) => format!(
                    "{}: {error}",
                    text(
                        language,
                        "glyph set changed, but the preference could not be saved",
                        "字符集已切换，但无法保存偏好"
                    )
                ),
            },
            is_error: result.is_err(),
            observed_at: Instant::now(),
        });
    }

    fn open_palette(&mut self) {
        self.show_palette = true;
        self.palette_query.clear();
        self.palette_selected = 0;
    }

    fn close_palette(&mut self) {
        self.show_palette = false;
        self.palette_query.clear();
        self.palette_selected = 0;
    }

    /// Commands matching the current palette query, in catalog order. An
    /// empty query lists everything; matching is a case-insensitive
    /// subsequence test against both languages' names plus the keywords.
    pub(crate) fn palette_matches(&self) -> Vec<&'static PaletteCommand> {
        let query = self.palette_query.trim();
        PALETTE_COMMANDS
            .iter()
            .filter(|command| {
                query.is_empty()
                    || subsequence_match(query, command.en_name)
                    || subsequence_match(query, command.zh_name)
                    || command
                        .keywords
                        .iter()
                        .any(|keyword| subsequence_match(query, keyword))
            })
            .collect()
    }

    fn move_palette_selection(&mut self, delta: isize) {
        let count = self.palette_matches().len();
        if count == 0 {
            self.palette_selected = 0;
            return;
        }
        let current = self.palette_selected.min(count - 1) as isize;
        self.palette_selected = (current + delta).rem_euclid(count as isize) as usize;
    }

    /// Close every overlay, workspace, and dialog so a palette command runs
    /// against the bare process tree, exactly like its key press would.
    fn close_all_overlays(&mut self) {
        self.show_filter_manager = false;
        self.filter_editor = None;
        self.show_attention = false;
        self.attention_selected = None;
        self.show_hotspots = false;
        self.hotspot_selected = None;
        self.show_network = false;
        self.clear_network_filters();
        self.show_snapshot_diff = false;
        self.snapshot_diff_scroll = 0;
        self.trend_pid = None;
        self.dossier_context = None;
        self.dossier_context_task = None;
        self.dossier_context_scroll = 0;
        self.memory_context = None;
        self.memory_context_task = None;
        self.memory_context_scroll = 0;
        self.logs_context = None;
        self.logs_context_task = None;
        self.logs_context_scroll = 0;
        self.service_context = None;
        self.service_context_task = None;
        self.service_context_scroll = 0;
        self.executable_context = None;
        self.executable_context_task = None;
        self.executable_context_scroll = 0;
        self.inspection = None;
        self.inspection_task = None;
        self.inspection_scroll = 0;
        self.show_events = false;
        self.process_action = None;
    }

    /// Run a palette command by replaying the real key press through the
    /// normal handler, so palette behavior always matches key behavior.
    /// Stateless toggles keep the current workspace; everything else first
    /// closes open overlays, mirroring the existing cross-link exclusivity.
    fn execute_palette_command(&mut self, id: PaletteCommandId) -> bool {
        let keep_workspace = matches!(
            id,
            PaletteCommandId::Pause
                | PaletteCommandId::Language
                | PaletteCommandId::CycleTheme
                | PaletteCommandId::ToggleGlyphs
        );
        if !keep_workspace {
            self.close_all_overlays();
        }
        // Theme and glyph switching have no dedicated key press; they run
        // directly instead of replaying through the key handler. Pause runs
        // directly too: replaying Space would keep the current workspace and
        // hit that workspace's own Space binding (the filter manager toggles
        // the selected rule, the action dialog ignores it) instead of
        // pausing, so the command must behave identically from every context.
        match id {
            PaletteCommandId::CycleTheme => {
                self.cycle_theme();
                return false;
            }
            PaletteCommandId::ToggleGlyphs => {
                self.toggle_glyphs();
                return false;
            }
            PaletteCommandId::Pause => {
                self.toggle_paused();
                return false;
            }
            // Port lookup is a two-step flow: open the network workspace,
            // then start its digit-only port input.
            PaletteCommandId::FindPort => {
                self.on_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
                self.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
                return false;
            }
            _ => {}
        }
        let key = match id {
            PaletteCommandId::Inspect => KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            PaletteCommandId::Search => KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
            PaletteCommandId::ToggleStar => KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE),
            PaletteCommandId::NextStarred => KeyEvent::new(KeyCode::Char('\''), KeyModifiers::NONE),
            PaletteCommandId::Actions => KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE),
            PaletteCommandId::Dossier => KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE),
            PaletteCommandId::Memory => KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE),
            PaletteCommandId::Service => KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
            PaletteCommandId::Verify => KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE),
            PaletteCommandId::Logs => KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE),
            PaletteCommandId::Network => KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
            PaletteCommandId::Hotspots => KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE),
            PaletteCommandId::Attention => KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
            PaletteCommandId::Trend => KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE),
            PaletteCommandId::Events => KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
            PaletteCommandId::Filters => KeyEvent::new(KeyCode::Char('F'), KeyModifiers::NONE),
            PaletteCommandId::Focus => KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE),
            PaletteCommandId::Sort => KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
            PaletteCommandId::Refresh => KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
            PaletteCommandId::CaptureBaseline => {
                KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE)
            }
            PaletteCommandId::SnapshotDiff => KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
            PaletteCommandId::ClearBaseline => {
                KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)
            }
            PaletteCommandId::ExportReport => KeyEvent::new(KeyCode::Char('o'), KeyModifiers::NONE),
            PaletteCommandId::Language => KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE),
            PaletteCommandId::Help => KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
            PaletteCommandId::Quit => KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            // Handled above without a single key replay.
            PaletteCommandId::CycleTheme
            | PaletteCommandId::ToggleGlyphs
            | PaletteCommandId::Pause
            | PaletteCommandId::FindPort => unreachable!(),
        };
        self.on_key(key)
    }

    pub(crate) fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        // Language switching is global, except while a text editor owns the
        // keyboard (search, network filter, and the filter rule editor all
        // accept `L` as ordinary input). Crossterm reports uppercase letters
        // with SHIFT on most terminals, so accept NONE|SHIFT but reject
        // Ctrl/Alt chords.
        if key.code == KeyCode::Char('L')
            && matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT)
            && !self.searching
            && !self.network_searching
            && self.network_port_input.is_none()
            && self.filter_editor.is_none()
            && !self.show_palette
        {
            self.toggle_language();
            return false;
        }
        if let Some(overlay) = self.guidance.overlay {
            if matches!(overlay, GuidanceOverlay::Tip(_)) {
                match key.code {
                    KeyCode::Char('q') => {
                        self.dismiss_guidance();
                        return false;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    KeyCode::Esc | KeyCode::Enter => {
                        self.dismiss_guidance();
                        return false;
                    }
                    KeyCode::Char('d' | 'D') => {
                        self.disable_startup_guidance();
                        return false;
                    }
                    KeyCode::Char('t' | 'T') => {
                        self.toggle_startup_tips();
                        return false;
                    }
                    KeyCode::Char('?') => {
                        self.guidance.open_help();
                        return false;
                    }
                    _ => self.dismiss_guidance(),
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => self.dismiss_guidance(),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    KeyCode::Esc | KeyCode::Enter => self.dismiss_guidance(),
                    KeyCode::Left | KeyCode::Up => self.guidance.previous_page(),
                    KeyCode::Right | KeyCode::Down | KeyCode::Tab => self.guidance.next_page(),
                    KeyCode::Char('d' | 'D') => self.disable_startup_guidance(),
                    KeyCode::Char('t' | 'T') => self.toggle_startup_tips(),
                    KeyCode::Char('?') if overlay == GuidanceOverlay::Help => {
                        self.dismiss_guidance();
                    }
                    _ => {}
                }
                return false;
            }
        }
        // The command palette owns the keyboard while open: typed characters
        // edit the query, arrows move the selection, Enter runs the command,
        // and Esc (or q on an empty query, following the layered-q
        // convention) closes it without executing anything.
        if self.show_palette {
            match key.code {
                KeyCode::Esc => self.close_palette(),
                KeyCode::Enter => {
                    let command = self
                        .palette_matches()
                        .get(self.palette_selected)
                        .map(|command| command.id);
                    self.close_palette();
                    if let Some(id) = command {
                        return self.execute_palette_command(id);
                    }
                }
                KeyCode::Down => self.move_palette_selection(1),
                KeyCode::Up => self.move_palette_selection(-1),
                KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.move_palette_selection(1);
                }
                KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.move_palette_selection(-1);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return true;
                }
                KeyCode::Backspace => {
                    self.palette_query.pop();
                    self.palette_selected = 0;
                }
                KeyCode::Char('q') if key.modifiers.is_empty() && self.palette_query.is_empty() => {
                    self.close_palette();
                }
                KeyCode::Char(character)
                    if matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) =>
                {
                    self.palette_query.push(character);
                    self.palette_selected = 0;
                }
                _ => {}
            }
            return false;
        }
        // `:` opens the command palette anywhere the global L toggle is
        // allowed; text editors (search, network filter, rule editor, PID
        // entry) keep `:` as ordinary input.
        if key.code == KeyCode::Char(':')
            && matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT)
            && !self.searching
            && !self.network_searching
            && self.filter_editor.is_none()
            && self.pid_input.is_none()
            && self.network_port_input.is_none()
        {
            self.open_palette();
            return false;
        }
        if !self.searching
            && !self.network_searching
            && !self.show_filter_manager
            && self.pid_input.is_none()
            && self.network_port_input.is_none()
            && key.modifiers.is_empty()
            && key.code == KeyCode::Char('o')
        {
            self.export_diagnostic_report();
            return false;
        }
        if self.process_action.is_some() {
            let confirming = self
                .process_action
                .as_ref()
                .map(|dialog| dialog.confirming)
                .unwrap_or(false);
            if confirming {
                match key.code {
                    // q steps back out of the confirmation, exactly like Esc;
                    // only the bare process tree lets q quit psmore.
                    KeyCode::Char('q') => {
                        if let Some(dialog) = &mut self.process_action {
                            dialog.confirming = false;
                        }
                    }
                    KeyCode::Esc => {
                        if let Some(dialog) = &mut self.process_action {
                            dialog.confirming = false;
                        }
                    }
                    KeyCode::Char('y') => self.execute_confirmed_process_action(),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => self.process_action = None,
                    KeyCode::Esc => self.process_action = None,
                    KeyCode::Char('p')
                        if self
                            .process_action
                            .as_ref()
                            .is_some_and(|dialog| !dialog.is_termination_only()) =>
                    {
                        self.process_action = None;
                    }
                    KeyCode::Down | KeyCode::Tab => {
                        self.move_process_action_selection(1);
                    }
                    KeyCode::Up => self.move_process_action_selection(-1),
                    KeyCode::Enter => {
                        if let Some(dialog) = &mut self.process_action {
                            dialog.confirming = true;
                        }
                    }
                    KeyCode::Char('t') => {
                        self.choose_process_action(ProcessActionKind::Terminate);
                    }
                    KeyCode::Char('k') => self.choose_process_action(ProcessActionKind::Kill),
                    KeyCode::Char('s') => self.choose_process_action(ProcessActionKind::Stop),
                    KeyCode::Char('c') if key.modifiers.is_empty() => {
                        self.choose_process_action(ProcessActionKind::Continue);
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
            }
            return false;
        }
        if self.pid_input.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.pid_input = None;
                    self.pid_input_error = None;
                }
                KeyCode::Enter => self.finish_pid_input(),
                KeyCode::Backspace => {
                    if let Some(input) = &mut self.pid_input {
                        input.pop();
                    }
                    self.pid_input_error = None;
                }
                KeyCode::Char(c) if c.is_ascii_digit() && key.modifiers.is_empty() => {
                    if let Some(input) = &mut self.pid_input {
                        input.push(c);
                    }
                    self.pid_input_error = None;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return true;
                }
                _ => {}
            }
            return false;
        }
        if self.show_filter_manager {
            if let Some(editor) = &mut self.filter_editor {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    KeyCode::Esc => self.filter_editor = None,
                    KeyCode::Enter => self.apply_filter_editor(),
                    KeyCode::Tab => editor.action = editor.action.toggle(),
                    KeyCode::Backspace => {
                        editor.input.pop();
                        editor.error = None;
                    }
                    KeyCode::Char(character) if key.modifiers.is_empty() => {
                        editor.input.push(character);
                        editor.error = None;
                    }
                    _ => {}
                }
            } else {
                match key.code {
                    KeyCode::Char('q') => self.close_filter_manager(),
                    KeyCode::Esc | KeyCode::Char('F') => self.close_filter_manager(),
                    KeyCode::Char('a') => self.start_filter_editor(FilterAction::Include),
                    KeyCode::Char('x') => self.start_filter_editor(FilterAction::Exclude),
                    KeyCode::Char('e') | KeyCode::Enter => self.edit_selected_filter(),
                    KeyCode::Char(' ') => self.toggle_selected_filter(),
                    KeyCode::Char('d') | KeyCode::Delete => self.remove_selected_filter(),
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.filter_selected = (self.filter_selected + 1)
                            .min(self.process_filters.len().saturating_sub(1));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.filter_selected = self.filter_selected.saturating_sub(1);
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
            }
            return false;
        }
        if self.show_attention {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('a') => {
                    self.show_attention = false;
                    self.attention_selected = None;
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_attention_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_attention_selection(-1),
                KeyCode::PageDown => self.move_attention_selection(10),
                KeyCode::PageUp => self.move_attention_selection(-10),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Enter => {
                    if let Some(pid) = self.attention_selected {
                        self.jump_to_process(pid);
                    }
                }
                KeyCode::Char('t') => self.open_attention_trend(),
                KeyCode::Char('i') => self.inspect_attention_process(),
                KeyCode::Char('p') => {
                    if let Some(pid) = self.attention_selected {
                        self.open_process_action_for(pid);
                    }
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_hotspots {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('h') => {
                    self.show_hotspots = false;
                    self.hotspot_selected = None;
                }
                KeyCode::Left => {
                    self.select_hotspot_metric(self.hotspot_metric.previous());
                }
                KeyCode::Right | KeyCode::Tab => {
                    self.select_hotspot_metric(self.hotspot_metric.next());
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_hotspot_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_hotspot_selection(-1),
                KeyCode::PageDown => self.move_hotspot_selection(10),
                KeyCode::PageUp => self.move_hotspot_selection(-10),
                KeyCode::Char('v') => {
                    self.hotspot_scope.toggle();
                    self.reset_hotspot_selection();
                }
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Enter => {
                    if let Some(pid) = self.hotspot_selected {
                        self.jump_to_process(pid);
                    }
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_snapshot_diff {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('d') => {
                    self.show_snapshot_diff = false;
                    self.snapshot_diff_scroll = 0;
                }
                KeyCode::Char('b') => self.capture_baseline(),
                KeyCode::Char('x') => {
                    self.baseline = None;
                    self.show_snapshot_diff = false;
                    self.snapshot_diff_scroll = 0;
                }
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.snapshot_diff_scroll = self.snapshot_diff_scroll.saturating_sub(10);
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_network {
            // The digit-only port locator owns the keyboard while open, just
            // like the PID locator does on the bare tree.
            if self.network_port_input.is_some() {
                match key.code {
                    KeyCode::Esc => {
                        // Cancel the lookup and restore the unfiltered list.
                        self.network_port_input = None;
                        self.network_port_filter = None;
                        self.network_pending_port = None;
                        self.network_selected = 0;
                    }
                    KeyCode::Char('q') => self.network_port_input = None,
                    KeyCode::Enter => self.finish_network_port_input(),
                    KeyCode::Backspace => {
                        if let Some(input) = &mut self.network_port_input {
                            input.pop();
                        }
                    }
                    KeyCode::Char(c) if c.is_ascii_digit() && key.modifiers.is_empty() => {
                        if let Some(input) = &mut self.network_port_input {
                            input.push(c);
                        }
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
                return false;
            }
            if self.network_searching {
                match key.code {
                    KeyCode::Esc => {
                        self.network_searching = false;
                        self.network_filter.clear();
                        self.network_selected = 0;
                    }
                    KeyCode::Enter => self.network_searching = false,
                    KeyCode::Backspace => {
                        self.network_filter.pop();
                        self.network_selected = 0;
                    }
                    KeyCode::Down | KeyCode::Char('j') => self.move_network_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => self.move_network_selection(-1),
                    KeyCode::PageDown => self.move_network_selection(10),
                    KeyCode::PageUp => self.move_network_selection(-10),
                    KeyCode::Char(c) if key.modifiers.is_empty() => {
                        self.network_filter.push(c);
                        self.network_selected = 0;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return true;
                    }
                    _ => {}
                }
                return false;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('n') => {
                    self.show_network = false;
                    self.clear_network_filters();
                }
                KeyCode::Char('r') => self.refresh_network(),
                KeyCode::Char('/') => {
                    self.network_searching = true;
                    self.network_filter.clear();
                    self.network_selected = 0;
                }
                KeyCode::Char('p') => {
                    self.network_port_input = Some(String::new());
                }
                KeyCode::Char('x') => {
                    self.network_filter.clear();
                    self.network_port_filter = None;
                    self.network_pending_port = None;
                    self.network_selected = 0;
                }
                KeyCode::Char('v') => {
                    self.network_scope.toggle();
                    self.network_selected = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => self.move_network_selection(1),
                KeyCode::Up | KeyCode::Char('k') => self.move_network_selection(-1),
                KeyCode::PageDown => self.move_network_selection(10),
                KeyCode::PageUp => self.move_network_selection(-10),
                KeyCode::Enter => {
                    let pid = self
                        .network_visible_indices()
                        .get(self.network_selected)
                        .and_then(|index| {
                            self.network_scan
                                .as_ref()
                                .and_then(|scan| scan.endpoints.get(*index))
                        })
                        .and_then(|listener| listener.pid);
                    if let Some(pid) = pid {
                        self.jump_to_process(pid);
                    }
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.trend_pid.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('t') => self.trend_pid = None,
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char('i') => self.trend_view.toggle(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.dossier_context.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('D') => {
                    self.close_dossier_context()
                }
                KeyCode::Char('i') => {
                    self.close_dossier_context();
                    self.open_inspection();
                }
                KeyCode::Char('m') => {
                    self.close_dossier_context();
                    self.open_service_context();
                }
                KeyCode::Char('v') => {
                    self.close_dossier_context();
                    self.open_executable_context();
                }
                KeyCode::Char('l') => {
                    self.close_dossier_context();
                    self.open_logs_context();
                }
                KeyCode::Char('M') => {
                    self.close_dossier_context();
                    self.open_memory_context();
                }
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_dossier_context(),
                KeyCode::Char('h') => self.toggle_dossier_hash(),
                KeyCode::Char('g') => self.toggle_dossier_logs(),
                KeyCode::Char('s') => self.cycle_dossier_scope(),
                KeyCode::Char('p') => self.cycle_dossier_priority(),
                KeyCode::Char('w') => self.cycle_dossier_window(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.dossier_context_scroll = self.dossier_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.memory_context.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('M') => {
                    self.close_memory_context()
                }
                KeyCode::Char('D') => {
                    self.close_memory_context();
                    self.open_dossier_context();
                }
                KeyCode::Char('i') => {
                    self.close_memory_context();
                    self.open_inspection();
                }
                KeyCode::Char('m') => {
                    self.close_memory_context();
                    self.open_service_context();
                }
                KeyCode::Char('v') => {
                    self.close_memory_context();
                    self.open_executable_context();
                }
                KeyCode::Char('l') => {
                    self.close_memory_context();
                    self.open_logs_context();
                }
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_memory_context(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.memory_context_scroll = self.memory_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.logs_context.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('l') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                }
                KeyCode::Char('m') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                    self.open_service_context();
                }
                KeyCode::Char('v') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                    self.open_executable_context();
                }
                KeyCode::Char('D') => {
                    self.logs_context = None;
                    self.logs_context_task = None;
                    self.logs_context_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_logs_context(),
                KeyCode::Char('s') => self.cycle_logs_scope(),
                KeyCode::Char('p') => self.cycle_logs_priority(),
                KeyCode::Char('w') => self.cycle_logs_window(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.logs_context_scroll = self.logs_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.service_context.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('m') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                }
                KeyCode::Char('v') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                    self.open_executable_context();
                }
                KeyCode::Char('l') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                    self.open_logs_context();
                }
                KeyCode::Char('D') => {
                    self.service_context = None;
                    self.service_context_task = None;
                    self.service_context_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_service_context(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.service_context_scroll = self.service_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.service_context_scroll = self.service_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.service_context_scroll = self.service_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.service_context_scroll = self.service_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.executable_context.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('v') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                }
                KeyCode::Char('m') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                    self.open_service_context();
                }
                KeyCode::Char('l') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                    self.open_logs_context();
                }
                KeyCode::Char('D') => {
                    self.executable_context = None;
                    self.executable_context_task = None;
                    self.executable_context_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_executable_context(),
                KeyCode::Char('h') => self.toggle_executable_hash(),
                KeyCode::Down | KeyCode::Char('j') => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.executable_context_scroll =
                        self.executable_context_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.inspection.is_some() {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    self.inspection = None;
                    self.inspection_task = None;
                    self.inspection_scroll = 0;
                }
                KeyCode::Char('D') => {
                    self.inspection = None;
                    self.inspection_task = None;
                    self.inspection_scroll = 0;
                    self.open_dossier_context();
                }
                KeyCode::Char('M') => self.open_memory_context(),
                KeyCode::Enter | KeyCode::Char('r') => self.refresh_inspection(),
                KeyCode::Tab | KeyCode::Right => {
                    self.inspection_tab = self.inspection_tab.next();
                    self.inspection_scroll = 0;
                }
                KeyCode::BackTab | KeyCode::Left => {
                    self.inspection_tab = self.inspection_tab.previous();
                    self.inspection_scroll = 0;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.inspection_scroll = self.inspection_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.inspection_scroll = self.inspection_scroll.saturating_sub(1);
                }
                KeyCode::PageDown => {
                    self.inspection_scroll = self.inspection_scroll.saturating_add(10);
                }
                KeyCode::PageUp => {
                    self.inspection_scroll = self.inspection_scroll.saturating_sub(10);
                }
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.show_events {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc | KeyCode::Char('e') => self.show_events = false,
                KeyCode::Char(' ') => self.toggle_paused(),
                KeyCode::Char('r') => self.refresh(),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.search_input.clear();
                    self.search_history_index = None;
                    self.search_completion = None;
                }
                KeyCode::Enter => self.apply_search_input(),
                KeyCode::Up => self.search_history_previous(),
                KeyCode::Down => self.search_history_next(),
                KeyCode::Tab => self.complete_search_field(),
                KeyCode::Backspace => {
                    self.search_input.pop();
                    self.search_completion = None;
                }
                KeyCode::Char(c) if key.modifiers.is_empty() => {
                    self.search_input.push(c);
                    self.search_completion = None;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Esc if !self.search.is_empty() => {
                let anchor_pid = self.selected_pid();
                let current_row = self
                    .selected
                    .saturating_sub(self.tree_offset.min(self.selected));
                self.search.clear();
                if let Some(anchor_pid) = anchor_pid {
                    self.ensure_visible_ancestor_chain(anchor_pid);
                }
                self.rebuild_visible();
                if let Some(anchor_pid) = anchor_pid {
                    self.restore_selection_to_anchor(anchor_pid);
                    self.ensure_tree_view_row(current_row);
                }
            }
            KeyCode::Char('q') => return true,
            // Escape is intentionally inert on the bare process tree. It is
            // reserved for cancelling input, clearing search, and closing
            // overlays so an extra key press cannot terminate psmore.
            KeyCode::Esc => {}
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.page_size as isize),
            KeyCode::PageUp => self.move_selection(-(self.page_size as isize)),
            KeyCode::Left => {
                self.reveal_parent();
            }
            KeyCode::Right => self.toggle_selected_expanded(),
            KeyCode::Char('/') => {
                self.searching = true;
                self.search_input.clear();
                self.search_history_index = None;
                self.search_draft.clear();
                self.search_completion = None;
            }
            KeyCode::Char(c) if c.is_ascii_digit() && key.modifiers.is_empty() => {
                self.begin_pid_input(c);
            }
            KeyCode::Char('f') => self.toggle_focus(),
            KeyCode::Char('*') => self.toggle_star(),
            KeyCode::Char('\'') => self.jump_to_next_starred(),
            KeyCode::Char('F') => self.open_filter_manager(),
            KeyCode::Char('s') => self.cycle_sort_mode(),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char(' ') => self.toggle_paused(),
            KeyCode::Char('e') => {
                self.show_events = true;
                self.inspection = None;
                self.inspection_task = None;
            }
            KeyCode::Char('t') => {
                self.trend_pid = self.selected_pid();
                self.trend_view = TrendView::default();
                self.show_events = false;
                self.inspection = None;
                self.inspection_task = None;
            }
            KeyCode::Char('b') => self.capture_baseline(),
            KeyCode::Char('d') if self.baseline.is_some() => {
                self.show_snapshot_diff = true;
                self.snapshot_diff_scroll = 0;
                self.show_events = false;
                self.inspection = None;
                self.inspection_task = None;
                self.trend_pid = None;
            }
            KeyCode::Char('d') => {
                self.notice = Some(StatusNotice {
                    message: text(
                        self.language(),
                        "Capture a baseline first with b",
                        "先按 b 捕获基线，再按 d 对比",
                    )
                    .into(),
                    is_error: false,
                    observed_at: Instant::now(),
                });
            }
            KeyCode::Char('x') => {
                self.baseline = None;
                self.show_snapshot_diff = false;
                self.snapshot_diff_scroll = 0;
            }
            KeyCode::Char('n') => self.open_network(),
            KeyCode::Char('h') => self.open_hotspots(),
            KeyCode::Char('a') => self.open_attention(),
            KeyCode::Char('D') => self.open_dossier_context(),
            KeyCode::Char('M') => self.open_memory_context(),
            KeyCode::Char('m') => self.open_service_context(),
            KeyCode::Char('v') => self.open_executable_context(),
            KeyCode::Char('l') => self.open_logs_context(),
            KeyCode::Char('p') => self.open_selected_process_action(),
            KeyCode::Char('?') => self.guidance.open_help(),
            KeyCode::Enter => self.open_inspection(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        false
    }

    /// Mouse input. The wheel replays the matching arrow key so every overlay
    /// scrolls exactly like j/k; left clicks act only on the bare process
    /// tree (select row, or open inspection when the row is already selected)
    /// and on the inspection tab bar.
    pub(crate) fn on_mouse(&mut self, mouse: MouseEvent) {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                self.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
            }
            MouseEventKind::ScrollDown => {
                self.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
            }
            MouseEventKind::Down(MouseButton::Left) => {
                self.handle_mouse_click(mouse.column, mouse.row);
            }
            _ => {}
        }
    }

    fn handle_mouse_click(&mut self, column: u16, row: u16) {
        // A higher modal opened over the inspection workspace (palette,
        // action dialog, guidance, or any text editor) owns the screen; a
        // click must not reach the inspection tab bar hidden beneath it.
        if self.guidance.overlay.is_some()
            || self.show_palette
            || self.process_action.is_some()
            || self.pid_input.is_some()
            || self.filter_editor.is_some()
            || self.searching
            || self.network_searching
            || self.network_port_input.is_some()
        {
            return;
        }
        if self.inspection.is_some() {
            let tab = self
                .inspection_tab_regions
                .iter()
                .find(|(region, _)| {
                    row == region.y
                        && column >= region.x
                        && column < region.x.saturating_add(region.width)
                })
                .map(|(_, tab)| *tab);
            if let Some(tab) = tab {
                if tab != self.inspection_tab {
                    self.inspection_tab = tab;
                    self.inspection_scroll = 0;
                }
            }
            return;
        }
        if self.any_overlay_open() {
            return;
        }
        let area = self.tree_area;
        if area.height < 3 {
            return;
        }
        if column < area.x || column >= area.x.saturating_add(area.width) {
            return;
        }
        // Rows live between the top and bottom borders of the tree block.
        if row <= area.y || row >= area.y.saturating_add(area.height - 1) {
            return;
        }
        let index = self.tree_offset + usize::from(row - area.y - 1);
        if index >= self.visible.len() {
            return;
        }
        if index == self.selected {
            // Second click on the selected row acts like Enter; no double
            // click timing involved.
            self.open_inspection();
        } else {
            self.selected = index;
        }
    }

    /// True when any workspace, dialog, or text input owns the screen, so
    /// tree clicks underneath it must be ignored.
    fn any_overlay_open(&self) -> bool {
        self.guidance.overlay.is_some()
            || self.show_palette
            || self.process_action.is_some()
            || self.pid_input.is_some()
            || self.show_filter_manager
            || self.show_attention
            || self.show_hotspots
            || self.show_snapshot_diff
            || self.show_network
            || self.trend_pid.is_some()
            || self.dossier_context.is_some()
            || self.memory_context.is_some()
            || self.logs_context.is_some()
            || self.service_context.is_some()
            || self.executable_context.is_some()
            || self.show_events
            || self.searching
    }
}
