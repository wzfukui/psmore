use std::time::Duration;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Sparkline, Wrap},
};
use sysinfo::Pid;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::{
    actions::{ProcessActionKind, ProcessActionOutcome, ProcessActionRecord},
    app::App,
    model::{
        AttentionSeverity, HotspotMetric, HotspotScope, InspectionField, ProcessChange,
        ProcessEvent, ProcessInspection, TreeRow, TrendView, process_command_line, process_path,
    },
    network::NetworkEndpoint,
    onboarding::{GUIDANCE_PAGE_COUNT, GuidanceOverlay, TIPS},
    provider::platform_name,
    snapshot::{ProcessSnapshotEntry, SnapshotDiff},
};

fn row_label_and_context(app: &App, row: &TreeRow) -> (String, String) {
    let p = &app.processes[&row.pid];
    let child_count = app
        .children
        .get(&Some(row.pid))
        .map(|c| c.len())
        .unwrap_or(0);
    let marker = if app
        .children
        .get(&Some(row.pid))
        .map(|c| !c.is_empty())
        .unwrap_or(false)
    {
        if app.expanded.contains(&row.pid) {
            "▾"
        } else {
            "▸"
        }
    } else {
        "·"
    };
    let mut prefix = String::new();
    for is_last in row
        .last_path
        .iter()
        .skip(1)
        .take(row.depth.saturating_sub(1))
    {
        prefix.push_str(if *is_last { "  " } else { "│ " });
    }
    if row.depth > 0 {
        prefix.push_str(if row.is_last { "└─" } else { "├─" });
    }
    let context = process_path(p);
    let name = if child_count > 0 && !app.expanded.contains(&row.pid) {
        format!("{} ({})", p.name, child_count)
    } else {
        p.name.clone()
    };
    (
        format!("{}{} {}  [{}]", prefix, marker, name, row.pid),
        context,
    )
}

fn marquee(text: &str, offset: usize, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.width() <= width {
        return text.to_string();
    }
    let chars: Vec<char> = text.chars().collect();
    let start = offset.min(chars.len().saturating_sub(1));
    let mut result = String::new();
    let mut used = 0;
    let mut index = start;
    while used < width {
        let ch = chars[index];
        let char_width = ch.width().unwrap_or(1);
        if used + char_width > width {
            break;
        }
        result.push(ch);
        used += char_width;
        index += 1;
        if index >= chars.len() {
            break;
        }
    }
    result
}

fn wrapped_lines(text: &str, width: usize) -> usize {
    if width == 0 {
        return 1;
    }
    text.width().max(1).div_ceil(width)
}

fn detail_height(app: &App, area: ratatui::layout::Rect) -> u16 {
    let Some(pid) = app.selected_pid() else {
        return 4;
    };
    let Some(process) = app.processes.get(&pid) else {
        return 4;
    };
    let width = area.width.saturating_sub(2).max(1) as usize;
    let command = process_command_line(process);
    let children = app
        .children
        .get(&Some(pid))
        .map(|items| items.len())
        .unwrap_or(0);
    let subtree = app.resources.get(&pid).copied().unwrap_or_default();
    let summary = format!(
        "PID {}  PPID {}  children {}  status {}  CPU {:.1}%  MEM {} MB  R {}  W {}  runtime {}s",
        pid,
        process
            .parent
            .map(|parent| parent.to_string())
            .unwrap_or_else(|| "-".into()),
        children,
        process.status,
        process.cpu,
        process.memory / 1024 / 1024,
        format_bytes_rate(process.read_rate),
        format_bytes_rate(process.write_rate),
        process.runtime
    );
    let tree = format!(
        "TREE {} proc (self + descendants)  CPU {:.1}%  MEM {} MB  R {}  W {}",
        subtree.process_count,
        subtree.cpu,
        subtree.memory / 1024 / 1024,
        format_bytes_rate(subtree.read_rate),
        format_bytes_rate(subtree.write_rate)
    );
    let content_lines = wrapped_lines(&summary, width)
        + wrapped_lines(&tree, width)
        + wrapped_lines(&command, width);
    let desired = (content_lines + 2).max(4) as u16;
    desired.min(area.height.saturating_sub(5).max(4))
}

fn parent_label(parent: Option<Pid>) -> String {
    parent
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "-".into())
}

fn event_line(event: &ProcessEvent) -> Line<'static> {
    let age = event.observed_at.elapsed().as_secs();
    let (color, text) = match &event.change {
        ProcessChange::Started {
            pid, name, parent, ..
        } => (
            Color::LightGreen,
            format!(
                "{:>4}s  + {} [{}]  parent {}",
                age,
                name,
                pid,
                parent_label(*parent)
            ),
        ),
        ProcessChange::Exited { pid, name, .. } => (
            Color::LightRed,
            format!("{:>4}s  - {} [{}]", age, name, pid),
        ),
        ProcessChange::Reparented {
            pid,
            name,
            old_parent,
            new_parent,
            ..
        } => (
            Color::LightYellow,
            format!(
                "{:>4}s  ↪ {} [{}]  {} → {}",
                age,
                name,
                pid,
                parent_label(*old_parent),
                parent_label(*new_parent)
            ),
        ),
    };
    Line::from(Span::styled(text, Style::default().fg(color)))
}

fn action_line(record: &ProcessActionRecord) -> Line<'static> {
    let age = record.observed_at.elapsed().as_secs();
    let (color, marker) = match &record.outcome {
        ProcessActionOutcome::Sent => (Color::LightGreen, "✓"),
        ProcessActionOutcome::Refused(_) => (Color::LightYellow, "!"),
        ProcessActionOutcome::Failed(_) => (Color::LightRed, "×"),
    };
    let detail = record
        .outcome
        .detail()
        .map(|detail| format!("  {detail}"))
        .unwrap_or_default();
    Line::from(Span::styled(
        format!(
            "{:>4}s  {marker} {} {} [{}]  {}{}",
            age,
            record.action.label(),
            record.target.name,
            record.target.pid,
            record.outcome.label(),
            detail
        ),
        Style::default().fg(color),
    ))
}

fn draw_event_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let width = area.width.saturating_sub(2).clamp(1, 100);
    let height = area.height.saturating_sub(2).clamp(1, 18);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let line_limit = height.saturating_sub(2) as usize;
    let mut lines = Vec::with_capacity(line_limit);
    if !app.action_history.is_empty() && line_limit > 0 {
        lines.push(Line::from(Span::styled(
            " ACTIONS",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let action_limit = line_limit.saturating_sub(1).min(5);
        lines.extend(
            app.action_history
                .iter()
                .rev()
                .take(action_limit)
                .map(action_line),
        );
    }
    if !app.events.is_empty() && lines.len() < line_limit {
        lines.push(Line::from(Span::styled(
            " PROCESS CHANGES",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let remaining = line_limit.saturating_sub(lines.len());
        lines.extend(app.events.iter().rev().take(remaining).map(event_line));
    }
    if lines.is_empty() {
        lines.push(Line::from(" No process changes or actions captured yet "));
    }
    let title = format!(
        " activity  changes {} / actions {}  Esc/e close ",
        app.events.len(),
        app.action_history.len()
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn process_action_color(action: ProcessActionKind) -> Color {
    match action {
        ProcessActionKind::Terminate => Color::LightYellow,
        ProcessActionKind::Kill => Color::LightRed,
        ProcessActionKind::Stop => Color::LightMagenta,
        ProcessActionKind::Continue => Color::LightGreen,
    }
}

fn draw_process_action_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let Some(dialog) = &app.process_action else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 92);
    let height = area.height.saturating_sub(2).clamp(1, 17);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let target = &dialog.target;
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{} [{}]", target.name, target.pid),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  started {}", target.start_time)),
        ]),
        Line::from(Span::styled(
            marquee(&target.command, 0, width.saturating_sub(4).max(1) as usize),
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
    ];
    let title;
    if dialog.confirming {
        let action = dialog.selected_action();
        title = format!(" confirm {}  Esc back ", action.label());
        lines.extend([
            Line::from(vec![
                Span::styled(
                    format!("{}  ", action.label()),
                    Style::default()
                        .fg(process_action_color(action))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(action.description()),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                if action == ProcessActionKind::Kill {
                    "KILL cannot be handled or cleaned up by the target process."
                } else {
                    "This changes the live process and may affect its complete service tree."
                },
                Style::default().fg(Color::LightRed),
            )),
            Line::from(
                "Before sending, psmore will re-check the PID start time and refuse PID reuse.",
            ),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    "Press y to send the signal",
                    Style::default()
                        .fg(Color::LightYellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  ·  Esc returns without changing the process"),
            ]),
        ]);
    } else {
        title = " process actions  ↑↓/Tab choose  Enter confirm  Esc/p close ".into();
        for (index, action) in ProcessActionKind::ALL.iter().copied().enumerate() {
            let marker = if index == dialog.selected { "▸" } else { " " };
            let style = if index == dialog.selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(process_action_color(action))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(process_action_color(action))
            };
            lines.push(Line::from(Span::styled(
                format!(
                    " {marker} [{}] {:<5}  {}",
                    action.shortcut(),
                    action.label(),
                    action.description()
                ),
                style,
            )));
        }
        lines.extend([
            Line::from(""),
            Line::from(Span::styled(
                "Every action requires a separate y confirmation and is recorded in activity/report.",
                Style::default().fg(Color::DarkGray),
            )),
        ]);
    }
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn push_inspection_fields(lines: &mut Vec<Line<'static>>, title: &str, fields: &[InspectionField]) {
    if fields.is_empty() {
        return;
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("{title} ({})", fields.len()),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    for field in fields {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {:<24}", field.label),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(field.value.clone()),
        ]));
    }
}

fn thread_cpu_style(cpu_percent: f32) -> Style {
    let color = if cpu_percent >= 50.0 {
        Color::LightRed
    } else if cpu_percent >= 10.0 {
        Color::LightYellow
    } else if cpu_percent > 0.0 {
        Color::LightGreen
    } else {
        Color::DarkGray
    };
    Style::default().fg(color)
}

fn safe_thread_name(name: &str) -> String {
    if name.is_empty() {
        return "[unnamed]".into();
    }
    name.chars()
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect()
}

fn push_thread_lines(lines: &mut Vec<Line<'static>>, inspection: &ProcessInspection) {
    if inspection.thread_count == 0 && inspection.thread_warning.is_none() {
        return;
    }
    lines.push(Line::from(""));
    let sampling = if inspection.thread_sample_ms > 0 {
        format!("{}ms sample", inspection.thread_sample_ms)
    } else {
        "scheduler estimate".into()
    };
    lines.push(Line::from(Span::styled(
        format!(
            "HOT THREADS (showing {}/{}; {sampling})",
            inspection.threads.len(),
            inspection.thread_count
        ),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if let Some(warning) = &inspection.thread_warning {
        lines.push(Line::from(Span::styled(
            format!("  WARNING  {warning}"),
            Style::default().fg(Color::LightYellow),
        )));
    }
    if inspection.threads.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No thread details visible",
            Style::default().fg(Color::DarkGray),
        )));
        return;
    }
    lines.push(Line::from(Span::styled(
        "           TID    CPU  STATE            PRI  NI CORE  NAME",
        Style::default().fg(Color::DarkGray),
    )));
    for thread in &inspection.threads {
        let nice = thread
            .nice
            .map(|nice| nice.to_string())
            .unwrap_or_else(|| "-".into());
        let processor = thread
            .processor
            .map(|processor| processor.to_string())
            .unwrap_or_else(|| "-".into());
        lines.push(Line::from(vec![
            Span::raw(format!("  {:>12} ", thread.id)),
            Span::styled(
                format!("{:>6.1}%", thread.cpu_percent),
                thread_cpu_style(thread.cpu_percent),
            ),
            Span::raw(format!(
                "  {:<15} {:>3} {:>3} {:>4}  {}",
                thread.state,
                thread.priority,
                nice,
                processor,
                safe_thread_name(&thread.name)
            )),
        ]));
    }
}

fn inspection_lines(inspection: &ProcessInspection) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled("USER ", Style::default().fg(Color::Cyan)),
            Span::raw(inspection.user.clone()),
        ]),
        Line::from(vec![
            Span::styled("CWD  ", Style::default().fg(Color::Cyan)),
            Span::raw(inspection.cwd.clone()),
        ]),
    ];
    if let Some(warning) = &inspection.warning {
        lines.push(Line::from(Span::styled(
            format!("WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
    }
    push_thread_lines(&mut lines, inspection);
    push_inspection_fields(&mut lines, "RUNTIME CONTEXT", &inspection.runtime);
    push_inspection_fields(&mut lines, "SECURITY", &inspection.security);
    push_inspection_fields(&mut lines, "NAMESPACES", &inspection.namespaces);
    push_inspection_fields(&mut lines, "RESOURCE LIMITS", &inspection.limits);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("NETWORK ({})", inspection.sockets.len()),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if inspection.sockets.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No sockets visible",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for socket in &inspection.sockets {
            let state = if socket.state.is_empty() {
                "-"
            } else {
                &socket.state
            };
            lines.push(Line::from(format!(
                "  {:<6} {:<12} fd {:<6} {}",
                socket.protocol, state, socket.fd, socket.endpoint
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("OPEN FILE DESCRIPTORS ({})", inspection.files.len()),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if inspection.files.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No file descriptors visible",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for file in &inspection.files {
            lines.push(Line::from(format!(
                "  fd {:<6} {:<6} {:<2} {}",
                file.fd, file.kind, file.access, file.name
            )));
        }
    }
    lines
}

fn draw_inspection_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(inspection) = &app.inspection else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 140);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let mut lines = inspection_lines(inspection);
    let inspection_status = if app.inspection_is_scanning() {
        let elapsed = app.inspection_elapsed();
        lines.insert(0, Line::from(""));
        lines.insert(
            0,
            Line::from(Span::styled(
                format!(
                    " {} collecting process context in the background ({:.1}s)",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        );
        "  scanning"
    } else {
        ""
    };
    let content_height = height.saturating_sub(2) as usize;
    let content_width = width.saturating_sub(2).max(1) as usize;
    let visual_lines = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(content_width))
        .sum::<usize>();
    let max_scroll = visual_lines
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.inspection_scroll = app.inspection_scroll.min(max_scroll);
    let title = format!(
        " inspect {} [{}]{}  Enter/r refresh  ↑↓ scroll  D dossier  Esc close ",
        inspection.name, inspection.pid, inspection_status
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.inspection_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_dossier_context_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(panel) = app.dossier_context.clone() else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 160);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let mut lines = Vec::new();
    if app.dossier_context_is_scanning() {
        let elapsed = app.dossier_context_elapsed();
        lines.push(Line::from(Span::styled(
            format!(
                " {} collecting process dossier in parallel ({:.1}s)",
                activity_spinner(elapsed),
                elapsed.as_secs_f64()
            ),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    if let Some(warning) = panel.warning.as_deref() {
        lines.push(Line::from(Span::styled(
            format!(" WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
        lines.push(Line::from(""));
    }
    for line in panel.content.lines() {
        let trimmed = line.trim_start();
        let style = if trimmed.starts_with("CRIT") {
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD)
        } else if trimmed.starts_with("WARN") {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if trimmed.starts_with("NOTE") {
            Style::default().fg(Color::LightCyan)
        } else if line.starts_with("status ") {
            if line.contains("status critical") || line.contains("status warning") {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else if line.contains("status notice") {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD)
            }
        } else if matches!(line, "PRIORITIZED SIGNALS" | "EVIDENCE OVERVIEW") {
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD)
        } else if trimmed.contains("partial") || trimmed.contains("failed") {
            Style::default().fg(Color::Yellow)
        } else if trimmed.contains("complete") {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(line.to_owned(), style)));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No process dossier available",
            Style::default().fg(Color::DarkGray),
        )));
    }
    let content_height = height.saturating_sub(2) as usize;
    let content_width = width.saturating_sub(2).max(1) as usize;
    let visual_lines = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(content_width))
        .sum::<usize>();
    let max_scroll = visual_lines
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.dossier_context_scroll = app.dossier_context_scroll.min(max_scroll);
    let scanning = if app.dossier_context_is_scanning() {
        " scanning"
    } else {
        ""
    };
    let logs = if panel.include_logs {
        format!(
            "logs on {} <= {} {}",
            panel.scope.label(),
            panel.priority.label(),
            compact_duration(panel.since_seconds)
        )
    } else {
        "logs off".into()
    };
    let hash = if panel.hash { "hash on" } else { "hash off" };
    let title = format!(
        " dossier {} [{}]{}  {}  {}  r refresh  s/p/w logs  h hash  L logs  i/m/v/l evidence  D/Esc close ",
        panel.name, panel.pid, scanning, logs, hash
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.dossier_context_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_service_context_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(panel) = app.service_context.clone() else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 140);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let mut lines = Vec::new();
    if app.service_context_is_scanning() {
        let elapsed = app.service_context_elapsed();
        lines.push(Line::from(Span::styled(
            format!(
                " {} resolving systemd/launchd ownership in the background ({:.1}s)",
                activity_spinner(elapsed),
                elapsed.as_secs_f64()
            ),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    if let Some(warning) = panel.warning.as_deref() {
        lines.push(Line::from(Span::styled(
            format!(" WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
        lines.push(Line::from(""));
    }
    for line in panel.content.lines() {
        let style = if line.starts_with("service ") {
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("state ") {
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("warning ") {
            Style::default().fg(Color::LightRed)
        } else if line.starts_with("next ") {
            Style::default().fg(Color::Yellow)
        } else if line.starts_with("evidence ") {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(line.to_owned(), style)));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No service context available",
            Style::default().fg(Color::DarkGray),
        )));
    }
    let content_height = height.saturating_sub(2) as usize;
    let content_width = width.saturating_sub(2).max(1) as usize;
    let visual_lines = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(content_width))
        .sum::<usize>();
    let max_scroll = visual_lines
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.service_context_scroll = app.service_context_scroll.min(max_scroll);
    let scanning = if app.service_context_is_scanning() {
        "  scanning"
    } else {
        ""
    };
    let title = format!(
        " manager {} [{}]{}  Enter/r refresh  ↑↓ scroll  D dossier  v verify  l logs  m/Esc close ",
        panel.name, panel.pid, scanning
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.service_context_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_executable_context_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(panel) = app.executable_context.clone() else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 140);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let mut lines = Vec::new();
    if app.executable_context_is_scanning() {
        let elapsed = app.executable_context_elapsed();
        lines.push(Line::from(Span::styled(
            format!(
                " {} verifying executable image and provenance in the background ({:.1}s)",
                activity_spinner(elapsed),
                elapsed.as_secs_f64()
            ),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    if let Some(warning) = panel.warning.as_deref() {
        lines.push(Line::from(Span::styled(
            format!(" WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
        lines.push(Line::from(""));
    }
    for line in panel.content.lines() {
        let style = if line.starts_with("status ") {
            if line.contains("attention yes") {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD)
            }
        } else if line.starts_with("running ") || line.starts_with("disk ") {
            Style::default().fg(Color::LightCyan)
        } else if line.starts_with("package ") {
            Style::default().fg(Color::LightMagenta)
        } else if line.starts_with("signing ") {
            if line.contains("valid no") {
                Style::default().fg(Color::LightRed)
            } else {
                Style::default().fg(Color::LightGreen)
            }
        } else if line.starts_with("warning ") {
            Style::default().fg(Color::LightRed)
        } else if line.starts_with("coverage ") {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(line.to_owned(), style)));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No executable image evidence available",
            Style::default().fg(Color::DarkGray),
        )));
    }
    let content_height = height.saturating_sub(2) as usize;
    let content_width = width.saturating_sub(2).max(1) as usize;
    let visual_lines = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(content_width))
        .sum::<usize>();
    let max_scroll = visual_lines
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.executable_context_scroll = app.executable_context_scroll.min(max_scroll);
    let scanning = if app.executable_context_is_scanning() {
        "  scanning"
    } else {
        ""
    };
    let hash = if panel.hash { "hash on" } else { "hash off" };
    let title = format!(
        " verify image {} [{}]{}  {}  Enter/r refresh  h hash  D dossier  m manager  l logs  v/Esc close ",
        panel.name, panel.pid, scanning, hash
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.executable_context_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn compact_duration(seconds: u64) -> String {
    if seconds % 3_600 == 0 {
        format!("{}h", seconds / 3_600)
    } else if seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn draw_logs_context_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(panel) = app.logs_context.clone() else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 160);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let mut lines = Vec::new();
    if app.logs_context_is_scanning() {
        let elapsed = app.logs_context_elapsed();
        lines.push(Line::from(Span::styled(
            format!(
                " {} reading bounded native logs in the background ({:.1}s)",
                activity_spinner(elapsed),
                elapsed.as_secs_f64()
            ),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(""));
    }
    if let Some(warning) = panel.warning.as_deref() {
        lines.push(Line::from(Span::styled(
            format!(" WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
        lines.push(Line::from(""));
    }
    for line in panel.content.lines() {
        let style = if line.starts_with("source ") || line.starts_with("service ") {
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
        } else if line.starts_with("window ") {
            Style::default().fg(Color::LightCyan)
        } else if line.starts_with("warning ") {
            Style::default().fg(Color::LightRed)
        } else if line.starts_with("TIME ") || line.starts_with("context ") {
            Style::default().fg(Color::DarkGray)
        } else if line.contains(" critical ")
            || line.contains(" emergency ")
            || line.contains(" alert ")
            || line.contains(" error ")
        {
            Style::default().fg(Color::LightRed)
        } else if line.contains(" warning ") {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(line.to_owned(), style)));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            " No native log evidence available",
            Style::default().fg(Color::DarkGray),
        )));
    }
    let content_height = height.saturating_sub(2) as usize;
    let content_width = width.saturating_sub(2).max(1) as usize;
    let visual_lines = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(content_width))
        .sum::<usize>();
    let max_scroll = visual_lines
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.logs_context_scroll = app.logs_context_scroll.min(max_scroll);
    let scanning = if app.logs_context_is_scanning() {
        "  scanning"
    } else {
        ""
    };
    let title = format!(
        " logs {} [{}]{}  scope {}  <= {}  {}  r refresh  s scope  p level  w window  D dossier  m/v context  l/Esc close ",
        panel.name,
        panel.pid,
        scanning,
        panel.scope.label(),
        panel.priority.label(),
        compact_duration(panel.since_seconds),
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.logs_context_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn f32_stats(values: &[f32]) -> (f32, f32, f32) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let current = *values.last().unwrap_or(&0.0);
    let average = values.iter().copied().sum::<f32>() / values.len() as f32;
    let maximum = values.iter().copied().fold(0.0_f32, f32::max);
    (current, average, maximum)
}

fn memory_stats(values: &[u64]) -> (u64, u64, u64) {
    if values.is_empty() {
        return (0, 0, 0);
    }
    let current = *values.last().unwrap_or(&0);
    let average =
        (values.iter().map(|value| *value as u128).sum::<u128>() / values.len() as u128) as u64;
    let maximum = values.iter().copied().max().unwrap_or(0);
    (current, average, maximum)
}

fn cpu_sparkline_data(values: &[f32]) -> Vec<u64> {
    values
        .iter()
        .map(|value| (value.max(0.0) * 100.0).round() as u64)
        .collect()
}

fn memory_sparkline_data(values: &[u64]) -> Vec<u64> {
    values
        .iter()
        .map(|value| ((*value as f64 / 1024.0 / 1024.0) * 10.0).round() as u64)
        .collect()
}

fn draw_trend_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let Some(pid) = app.trend_pid else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 120);
    let height = area.height.saturating_sub(2).clamp(1, 22);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let name = app
        .processes
        .get(&pid)
        .map(|process| process.name.as_str())
        .or_else(|| app.history.name(pid))
        .unwrap_or("exited process");
    let title = format!(
        " trends {name} [{pid}]  {}  i switch  t/Esc close  r sample ",
        app.trend_view.label()
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let Some(samples) = app.history.samples(pid) else {
        frame.render_widget(Paragraph::new("No samples available"), inner);
        return;
    };
    if inner.height < 10 || inner.width < 10 {
        frame.render_widget(
            Paragraph::new(format!(
                "{} samples; enlarge terminal for charts",
                samples.len()
            )),
            inner,
        );
        return;
    }

    let window = samples
        .front()
        .zip(samples.back())
        .map(|(first, last)| {
            last.observed_at
                .saturating_duration_since(first.observed_at)
                .as_secs()
        })
        .unwrap_or(0);
    let subtree_processes = samples
        .back()
        .map(|sample| sample.subtree_processes)
        .unwrap_or(0);

    let chunks = Layout::vertical([
        Constraint::Length(2),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .split(inner);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                " {} samples / {}s window | subtree {} proc | newest at right",
                samples.len(),
                window,
                subtree_processes
            )),
            Line::from(if app.trend_view == TrendView::Io {
                " shared I/O scale: read/write and self/tree charts are directly comparable"
            } else {
                " shared scale per metric: self and tree charts are directly comparable"
            }),
        ]),
        chunks[0],
    );

    if app.trend_view == TrendView::Io {
        let own_read: Vec<u64> = samples.iter().map(|sample| sample.own_read_rate).collect();
        let tree_read: Vec<u64> = samples
            .iter()
            .map(|sample| sample.subtree_read_rate)
            .collect();
        let own_write: Vec<u64> = samples.iter().map(|sample| sample.own_write_rate).collect();
        let tree_write: Vec<u64> = samples
            .iter()
            .map(|sample| sample.subtree_write_rate)
            .collect();
        let io_scale = own_read
            .iter()
            .chain(&tree_read)
            .chain(&own_write)
            .chain(&tree_write)
            .copied()
            .max()
            .unwrap_or(1)
            .max(1);
        let series = [
            ("READ self", own_read, Color::Cyan),
            ("READ tree", tree_read, Color::LightCyan),
            ("WRITE self", own_write, Color::Yellow),
            ("WRITE tree", tree_write, Color::LightRed),
        ];
        for (index, (label, values, color)) in series.into_iter().enumerate() {
            let (now, average, maximum) = memory_stats(&values);
            frame.render_widget(
                Sparkline::default()
                    .block(Block::default().borders(Borders::TOP).title(format!(
                        " {label:<10} now {}  avg {}  max {} ",
                        format_bytes_rate(now),
                        format_bytes_rate(average),
                        format_bytes_rate(maximum)
                    )))
                    .data(&values)
                    .max(io_scale)
                    .bar_set(symbols::bar::NINE_LEVELS)
                    .style(Style::default().fg(color)),
                chunks[index + 1],
            );
        }
        return;
    }

    let own_cpu: Vec<f32> = samples.iter().map(|sample| sample.own_cpu).collect();
    let subtree_cpu: Vec<f32> = samples.iter().map(|sample| sample.subtree_cpu).collect();
    let own_memory: Vec<u64> = samples.iter().map(|sample| sample.own_memory).collect();
    let subtree_memory: Vec<u64> = samples.iter().map(|sample| sample.subtree_memory).collect();
    let own_cpu_data = cpu_sparkline_data(&own_cpu);
    let subtree_cpu_data = cpu_sparkline_data(&subtree_cpu);
    let own_memory_data = memory_sparkline_data(&own_memory);
    let subtree_memory_data = memory_sparkline_data(&subtree_memory);
    let cpu_scale = own_cpu_data
        .iter()
        .chain(&subtree_cpu_data)
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);
    let memory_scale = own_memory_data
        .iter()
        .chain(&subtree_memory_data)
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);
    let (own_cpu_now, own_cpu_avg, own_cpu_max) = f32_stats(&own_cpu);
    let (tree_cpu_now, tree_cpu_avg, tree_cpu_max) = f32_stats(&subtree_cpu);
    let (own_mem_now, own_mem_avg, own_mem_max) = memory_stats(&own_memory);
    let (tree_mem_now, tree_mem_avg, tree_mem_max) = memory_stats(&subtree_memory);
    frame.render_widget(
        Sparkline::default()
            .block(Block::default().borders(Borders::TOP).title(format!(
                " CPU self   now {own_cpu_now:.1}%  avg {own_cpu_avg:.1}%  max {own_cpu_max:.1}% "
            )))
            .data(&own_cpu_data)
            .max(cpu_scale)
            .bar_set(symbols::bar::NINE_LEVELS)
            .style(Style::default().fg(Color::Yellow)),
        chunks[1],
    );
    frame.render_widget(
        Sparkline::default()
            .block(Block::default().borders(Borders::TOP).title(format!(
                " CPU tree   now {tree_cpu_now:.1}%  avg {tree_cpu_avg:.1}%  max {tree_cpu_max:.1}% "
            )))
            .data(&subtree_cpu_data)
            .max(cpu_scale)
            .bar_set(symbols::bar::NINE_LEVELS)
            .style(Style::default().fg(Color::LightRed)),
        chunks[2],
    );
    frame.render_widget(
        Sparkline::default()
            .block(Block::default().borders(Borders::TOP).title(format!(
                " MEM self   now {} MB  avg {} MB  max {} MB ",
                own_mem_now / 1024 / 1024,
                own_mem_avg / 1024 / 1024,
                own_mem_max / 1024 / 1024
            )))
            .data(&own_memory_data)
            .max(memory_scale)
            .bar_set(symbols::bar::NINE_LEVELS)
            .style(Style::default().fg(Color::Cyan)),
        chunks[3],
    );
    frame.render_widget(
        Sparkline::default()
            .block(Block::default().borders(Borders::TOP).title(format!(
                " MEM tree   now {} MB  avg {} MB  max {} MB ",
                tree_mem_now / 1024 / 1024,
                tree_mem_avg / 1024 / 1024,
                tree_mem_max / 1024 / 1024
            )))
            .data(&subtree_memory_data)
            .max(memory_scale)
            .bar_set(symbols::bar::NINE_LEVELS)
            .style(Style::default().fg(Color::LightMagenta)),
        chunks[4],
    );
}

fn format_signed_bytes(delta: i128) -> String {
    let sign = if delta >= 0 { "+" } else { "-" };
    let bytes = delta.unsigned_abs();
    if bytes >= 1024 * 1024 {
        format!("{sign}{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{sign}{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{sign}{bytes} B")
    }
}

fn format_bytes_rate(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB/s", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB/s", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB/s", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B/s")
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn format_signed_rate(delta: i128) -> String {
    let sign = if delta >= 0 { "+" } else { "-" };
    let value = delta.unsigned_abs().min(u128::from(u64::MAX)) as u64;
    format!("{sign}{}", format_bytes_rate(value))
}

fn snapshot_entry_line(prefix: &str, entry: &ProcessSnapshotEntry, color: Color) -> Line<'static> {
    let parent = parent_label(entry.parent);
    let command = if entry.command.is_empty() {
        "[command unavailable]".to_string()
    } else {
        entry.command.clone()
    };
    Line::from(Span::styled(
        format!(
            " {prefix} {} [{}] parent {} | tree {} proc {} MB | {}",
            entry.name,
            entry.pid,
            parent,
            entry.subtree.process_count,
            entry.subtree.memory / 1024 / 1024,
            command
        ),
        Style::default().fg(color),
    ))
}

fn snapshot_diff_lines(diff: &SnapshotDiff) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        format!(
            "PROCESS CHANGES  +{} started  -{} exited  ↪{} reparented",
            diff.started.len(),
            diff.exited.len(),
            diff.reparented.len()
        ),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if diff.started.is_empty() && diff.exited.is_empty() && diff.reparented.is_empty() {
        lines.push(Line::from(Span::styled(
            " no process identity or relationship changes",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for entry in &diff.started {
            lines.push(snapshot_entry_line("+", entry, Color::LightGreen));
        }
        for entry in &diff.exited {
            lines.push(snapshot_entry_line("-", entry, Color::LightRed));
        }
        for entry in &diff.reparented {
            lines.push(Line::from(Span::styled(
                format!(
                    " ↪ {} [{}] parent {} → {}",
                    entry.name,
                    entry.pid,
                    parent_label(entry.old_parent),
                    parent_label(entry.new_parent)
                ),
                Style::default().fg(Color::LightYellow),
            )));
        }
    }

    let mut memory_growth: Vec<_> = diff
        .resource_deltas
        .iter()
        .filter(|delta| delta.subtree_memory > 0)
        .collect();
    memory_growth.sort_by_key(|delta| std::cmp::Reverse(delta.subtree_memory));
    let memory_growth_count = memory_growth.len();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if memory_growth_count > 50 {
            format!("TOP TREE MEMORY GROWTH ({memory_growth_count}, showing 50)")
        } else {
            format!("TOP TREE MEMORY GROWTH ({memory_growth_count})")
        },
        Style::default()
            .fg(Color::LightMagenta)
            .add_modifier(Modifier::BOLD),
    )));
    if memory_growth.is_empty() {
        lines.push(Line::from(Span::styled(
            " no surviving process subtree increased memory",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for delta in memory_growth.into_iter().take(50) {
            lines.push(Line::from(Span::styled(
                format!(
                    " {}  {} [{}] | now {} MB | own {} | children {:+}",
                    format_signed_bytes(delta.subtree_memory),
                    delta.name,
                    delta.pid,
                    delta.current_subtree.memory / 1024 / 1024,
                    format_signed_bytes(delta.own_memory),
                    delta.subtree_processes
                ),
                Style::default().fg(Color::LightMagenta),
            )));
        }
    }

    let mut cpu_growth: Vec<_> = diff
        .resource_deltas
        .iter()
        .filter(|delta| delta.subtree_cpu > 0.1)
        .collect();
    cpu_growth.sort_by(|left, right| right.subtree_cpu.total_cmp(&left.subtree_cpu));
    let cpu_growth_count = cpu_growth.len();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        if cpu_growth_count > 50 {
            format!("TOP TREE CPU INCREASE ({cpu_growth_count}, showing 50)")
        } else {
            format!("TOP TREE CPU INCREASE ({cpu_growth_count})")
        },
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
    )));
    if cpu_growth.is_empty() {
        lines.push(Line::from(Span::styled(
            " no surviving process subtree increased CPU by more than 0.1%",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for delta in cpu_growth.into_iter().take(50) {
            lines.push(Line::from(Span::styled(
                format!(
                    " {:+.1}%  {} [{}] | now {:.1}% | own {:+.1}%",
                    delta.subtree_cpu,
                    delta.name,
                    delta.pid,
                    delta.current_subtree.cpu,
                    delta.own_cpu
                ),
                Style::default().fg(Color::LightRed),
            )));
        }
    }

    for (title, empty, is_read) in [
        (
            "TOP TREE READ RATE INCREASE",
            " no surviving process subtree increased disk reads",
            true,
        ),
        (
            "TOP TREE WRITE RATE INCREASE",
            " no surviving process subtree increased disk writes",
            false,
        ),
    ] {
        let mut growth: Vec<_> = diff
            .resource_deltas
            .iter()
            .filter(|delta| {
                if is_read {
                    delta.subtree_read_rate > 0
                } else {
                    delta.subtree_write_rate > 0
                }
            })
            .collect();
        growth.sort_by_key(|delta| {
            std::cmp::Reverse(if is_read {
                delta.subtree_read_rate
            } else {
                delta.subtree_write_rate
            })
        });
        let count = growth.len();
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            if count > 50 {
                format!("{title} ({count}, showing 50)")
            } else {
                format!("{title} ({count})")
            },
            Style::default()
                .fg(if is_read {
                    Color::LightCyan
                } else {
                    Color::Yellow
                })
                .add_modifier(Modifier::BOLD),
        )));
        if growth.is_empty() {
            lines.push(Line::from(Span::styled(
                empty,
                Style::default().fg(Color::DarkGray),
            )));
        } else {
            for delta in growth.into_iter().take(50) {
                let (tree_delta, own_delta, current) = if is_read {
                    (
                        delta.subtree_read_rate,
                        delta.own_read_rate,
                        delta.current_subtree.read_rate,
                    )
                } else {
                    (
                        delta.subtree_write_rate,
                        delta.own_write_rate,
                        delta.current_subtree.write_rate,
                    )
                };
                lines.push(Line::from(Span::styled(
                    format!(
                        " {}  {} [{}] | now {} | own {}",
                        format_signed_rate(tree_delta),
                        delta.name,
                        delta.pid,
                        format_bytes_rate(current),
                        format_signed_rate(own_delta)
                    ),
                    Style::default().fg(if is_read {
                        Color::LightCyan
                    } else {
                        Color::Yellow
                    }),
                )));
            }
        }
    }
    lines
}

fn draw_snapshot_diff_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(baseline) = &app.baseline else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 140);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let diff = baseline.diff(&app.processes, &app.resources);
    let lines = snapshot_diff_lines(&diff);
    let content_height = height.saturating_sub(4) as usize;
    let max_scroll = lines
        .len()
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.snapshot_diff_scroll = app.snapshot_diff_scroll.min(max_scroll);
    let age = baseline.captured_at.elapsed().as_secs();
    let current_count = app.processes.len().saturating_sub(1);
    let system = diff
        .system_delta
        .as_ref()
        .map(|delta| {
            format!(
                "system ΔCPU {:+.1}% ΔMEM {} ΔR {} ΔW {} proc {:+}",
                delta.subtree_cpu,
                format_signed_bytes(delta.subtree_memory),
                format_signed_rate(delta.subtree_read_rate),
                format_signed_rate(delta.subtree_write_rate),
                delta.subtree_processes
            )
        })
        .unwrap_or_else(|| "system totals unavailable".into());
    let title = format!(
        " baseline diff {}s  {}→{} proc  {}  ↑↓ scroll  b reset  x clear  d/Esc close ",
        age,
        baseline.len(),
        current_count,
        system
    );
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.snapshot_diff_scroll, 0)),
        popup,
    );
}

fn network_endpoint_line(endpoint: &NetworkEndpoint) -> String {
    let owner = endpoint
        .pid
        .map(|pid| format!("{} [{pid}]", endpoint.process))
        .unwrap_or_else(|| endpoint.process.clone());
    let namespace = if endpoint.namespace.is_empty() {
        String::new()
    } else {
        format!(" | {}", endpoint.namespace)
    };
    let route = if endpoint.remote_endpoint.is_empty() {
        endpoint.local_endpoint.clone()
    } else {
        format!("{} → {}", endpoint.local_endpoint, endpoint.remote_endpoint)
    };
    format!(
        " {:<4} {:<11} {:<45} | {} | fd {}{}",
        endpoint.protocol, endpoint.state, route, owner, endpoint.fd, namespace
    )
}

fn activity_spinner(elapsed: Duration) -> &'static str {
    const FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
    let index = (elapsed.as_millis() / 125) as usize % FRAMES.len();
    FRAMES[index]
}

fn draw_network_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, popup);
    let Some(scan) = &app.network_scan else {
        let elapsed = app.network_scan_elapsed();
        let spinner = activity_spinner(elapsed);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        " {spinner} collecting TCP, UDP and Unix endpoints in the background ({:.1}s)",
                        elapsed.as_secs_f64()
                    ),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    " The process tree remains live. Press n/Esc to close; the scan may finish in the background.",
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" network scan "),
            ),
            popup,
        );
        return;
    };
    let chunks = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(popup);
    let visible = app.network_visible_indices();
    app.network_selected = app.network_selected.min(visible.len().saturating_sub(1));
    let items = visible
        .iter()
        .filter_map(|index| scan.endpoints.get(*index))
        .map(|endpoint| {
            let style = if endpoint.pid.is_some() {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            ListItem::new(network_endpoint_line(endpoint)).style(style)
        })
        .collect::<Vec<_>>();
    let mode = if app.network_searching {
        format!(" find: {}_", app.network_filter)
    } else if app.network_filter.is_empty() {
        String::new()
    } else {
        format!(" filter: {}", app.network_filter)
    };
    let scanning = if app.network_is_scanning() {
        let elapsed = app.network_scan_elapsed();
        format!(
            "  {} rescanning {:.1}s",
            activity_spinner(elapsed),
            elapsed.as_secs_f64()
        )
    } else {
        String::new()
    };
    let title = format!(
        " network {} {}/{}{}{} ",
        app.network_scope.label(),
        visible.len(),
        scan.endpoints.len(),
        mode,
        scanning,
    );
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default();
    if !visible.is_empty() {
        state.select(Some(app.network_selected));
    }
    frame.render_stateful_widget(list, chunks[0], &mut state);
    let warning = if app.network_is_scanning() {
        "showing the previous snapshot while a fresh scan runs"
    } else {
        scan.warning
            .as_deref()
            .unwrap_or("ownership complete for visible processes")
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(
                " ↑↓/jk move | v listeners/all | / find | Enter jump | r rescan | x clear | n/Esc close ",
            ),
            Line::from(Span::styled(
                format!(" {warning}"),
                Style::default().fg(if scan.warning.is_some() || app.network_is_scanning() {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }),
            )),
        ]),
        chunks[1],
    );
}

fn hotspot_color(metric: HotspotMetric) -> Color {
    match metric {
        HotspotMetric::Cpu => Color::LightRed,
        HotspotMetric::Memory => Color::LightMagenta,
        HotspotMetric::Read => Color::LightCyan,
        HotspotMetric::Write => Color::Yellow,
    }
}

fn attention_color(severity: AttentionSeverity) -> Color {
    match severity {
        AttentionSeverity::Critical => Color::LightRed,
        AttentionSeverity::Warning => Color::Yellow,
        AttentionSeverity::Watch => Color::LightBlue,
    }
}

fn draw_attention_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" attention cockpit ");
    let inner = block.inner(popup);
    let sections = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(6),
    ])
    .split(inner);
    let findings = app.attention_findings();
    let critical = findings
        .iter()
        .filter(|finding| finding.severity == AttentionSeverity::Critical)
        .count();
    let warning = findings
        .iter()
        .filter(|finding| finding.severity == AttentionSeverity::Warning)
        .count();
    let watch = findings.len().saturating_sub(critical + warning);
    let selected_index = app
        .attention_selected
        .and_then(|pid| findings.iter().position(|finding| finding.pid == pid));
    let capacity = sections[1].height.max(1) as usize;
    let offset = selected_index
        .map(|index| index.saturating_sub(capacity.saturating_sub(1)))
        .unwrap_or(0);
    let items: Vec<ListItem> =
        if findings.is_empty() {
            vec![ListItem::new(
            " no current findings — no unhealthy state, churn, sustained load, or rapid growth",
        )
        .style(Style::default().fg(Color::DarkGray))]
        } else {
            findings
                .iter()
                .skip(offset)
                .take(capacity)
                .filter_map(|finding| {
                    let process = app.processes.get(&finding.pid)?;
                    let first_reason = finding.reasons.first().map(String::as_str).unwrap_or("");
                    Some(
                        ListItem::new(format!(
                            " {:<5} {:>3}  {} [{}]  {}",
                            finding.severity.label(),
                            finding.score,
                            process.name,
                            finding.pid,
                            first_reason
                        ))
                        .style(Style::default().fg(attention_color(finding.severity))),
                    )
                })
                .collect()
        };
    let list = List::new(items).highlight_style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ListState::default();
    if let Some(index) = selected_index {
        state.select(Some(index.saturating_sub(offset)));
    }
    let detail = selected_index
        .and_then(|index| findings.get(index))
        .and_then(|finding| {
            let process = app.processes.get(&finding.pid)?;
            let mut lines = vec![Line::from(vec![
                Span::styled(
                    format!(
                        " {} {} score {} ",
                        finding.severity.label(),
                        process.name,
                        finding.score
                    ),
                    Style::default()
                        .fg(attention_color(finding.severity))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("PID {}  {}", finding.pid, process_path(process))),
            ])];
            for reason in &finding.reasons {
                lines.push(Line::from(format!(" • {reason}")));
            }
            lines.push(Line::from(Span::styled(
                format!(" command: {}", process_command_line(process)),
                Style::default().fg(Color::DarkGray),
            )));
            Some(lines)
        })
        .unwrap_or_else(|| {
            vec![
                Line::from(" No process currently requires attention."),
                Line::from(Span::styled(
                    " Findings are evidence-based hints, not a claim that a process is faulty.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        });
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(
                    format!(" CRIT {critical} "),
                    Style::default().fg(Color::LightRed),
                ),
                Span::styled(
                    format!(" WARN {warning} "),
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!(" WATCH {watch} "),
                    Style::default().fg(Color::LightBlue),
                ),
                Span::raw(" — explainable signals from state, lifecycle, resource history"),
            ]),
            Line::from(
                " ↑↓/jk move | Enter jump | t trend | i inspect | p actions | r sample | Space pause | a/Esc close",
            ),
        ]),
        sections[0],
    );
    frame.render_stateful_widget(list, sections[1], &mut state);
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::TOP).title(" evidence "))
            .wrap(Wrap { trim: false }),
        sections[2],
    );
}

fn hotspot_value(app: &App, pid: Pid, metric: HotspotMetric) -> (String, usize) {
    let process = app.processes.get(&pid);
    let subtree = app.resources.get(&pid).copied().unwrap_or_default();
    let process_count = if app.hotspot_scope == HotspotScope::Subtree {
        subtree.process_count
    } else {
        1
    };
    let value = match (metric, app.hotspot_scope) {
        (HotspotMetric::Cpu, HotspotScope::Process) => {
            format!("{:.1}%", process.map(|item| item.cpu).unwrap_or_default())
        }
        (HotspotMetric::Cpu, HotspotScope::Subtree) => format!("{:.1}%", subtree.cpu),
        (HotspotMetric::Memory, HotspotScope::Process) => {
            format_bytes(process.map(|item| item.memory).unwrap_or_default())
        }
        (HotspotMetric::Memory, HotspotScope::Subtree) => format_bytes(subtree.memory),
        (HotspotMetric::Read, HotspotScope::Process) => {
            format_bytes_rate(process.map(|item| item.read_rate).unwrap_or_default())
        }
        (HotspotMetric::Read, HotspotScope::Subtree) => format_bytes_rate(subtree.read_rate),
        (HotspotMetric::Write, HotspotScope::Process) => {
            format_bytes_rate(process.map(|item| item.write_rate).unwrap_or_default())
        }
        (HotspotMetric::Write, HotspotScope::Subtree) => format_bytes_rate(subtree.write_rate),
    };
    (value, process_count)
}

fn hotspot_is_active(app: &App, pid: Pid, metric: HotspotMetric) -> bool {
    let process = app.processes.get(&pid);
    let subtree = app.resources.get(&pid).copied().unwrap_or_default();
    match (metric, app.hotspot_scope) {
        (HotspotMetric::Cpu, HotspotScope::Process) => {
            process.map(|item| item.cpu > 0.0).unwrap_or(false)
        }
        (HotspotMetric::Cpu, HotspotScope::Subtree) => subtree.cpu > 0.0,
        (HotspotMetric::Memory, HotspotScope::Process) => {
            process.map(|item| item.memory > 0).unwrap_or(false)
        }
        (HotspotMetric::Memory, HotspotScope::Subtree) => subtree.memory > 0,
        (HotspotMetric::Read, HotspotScope::Process) => {
            process.map(|item| item.read_rate > 0).unwrap_or(false)
        }
        (HotspotMetric::Read, HotspotScope::Subtree) => subtree.read_rate > 0,
        (HotspotMetric::Write, HotspotScope::Process) => {
            process.map(|item| item.write_rate > 0).unwrap_or(false)
        }
        (HotspotMetric::Write, HotspotScope::Subtree) => subtree.write_rate > 0,
    }
}

fn draw_hotspot_panel(frame: &mut Frame, app: &App, area: Rect, metric: HotspotMetric) {
    let ranked = app.hotspot_ranked(metric);
    let active = app.hotspot_metric == metric;
    let selected_rank = if active {
        app.hotspot_selected
            .and_then(|pid| ranked.iter().position(|candidate| *candidate == pid))
    } else {
        None
    };
    let capacity = area.height.saturating_sub(2).max(1) as usize;
    let offset = selected_rank
        .map(|rank| rank.saturating_sub(capacity.saturating_sub(1)))
        .unwrap_or(0);
    let mut items: Vec<ListItem> = ranked
        .iter()
        .enumerate()
        .skip(offset)
        .filter(|(_, pid)| hotspot_is_active(app, **pid, metric))
        .take(capacity)
        .filter_map(|(rank, pid)| {
            let process = app.processes.get(pid)?;
            let (value, process_count) = hotspot_value(app, *pid, metric);
            let scope = if app.hotspot_scope == HotspotScope::Subtree {
                format!(" {:>3}p", process_count)
            } else {
                String::new()
            };
            Some(ListItem::new(format!(
                " #{:<3} {:>10}{}  {} [{}]  {}",
                rank + 1,
                value,
                scope,
                process.name,
                pid,
                process_path(process)
            )))
        })
        .collect();
    let color = hotspot_color(metric);
    if items.is_empty() {
        items.push(
            ListItem::new(" no activity in the current sample")
                .style(Style::default().fg(Color::DarkGray)),
        );
    }
    let title = if active {
        format!(" {}  ACTIVE ", metric.label())
    } else {
        format!(" {} ", metric.label())
    };
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(if active { color } else { Color::DarkGray })),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default();
    match selected_rank {
        Some(rank) if rank >= offset && rank < offset + capacity => {
            state.select(Some(rank - offset));
        }
        _ => {}
    }
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_hotspot_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" hotspot cockpit ");
    let inner = block.inner(popup);
    let rows = Layout::vertical([
        Constraint::Length(2),
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(inner);
    let top =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[1]);
    let bottom =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(rows[2]);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::raw(" scope: "),
                Span::styled(
                    app.hotspot_scope.label(),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw("  | selected panel: "),
                Span::styled(
                    app.hotspot_metric.label(),
                    Style::default()
                        .fg(hotspot_color(app.hotspot_metric))
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(" ↑↓ rank | ←→ metric | v self/tree | Enter jump | r sample | Esc close"),
        ]),
        rows[0],
    );
    for (metric, panel) in HotspotMetric::ALL
        .into_iter()
        .zip([top[0], top[1], bottom[0], bottom[1]])
    {
        draw_hotspot_panel(frame, app, panel, metric);
    }
}

fn draw_notice(frame: &mut Frame, app: &App, area: Rect) {
    let Some(notice) = app
        .notice
        .as_ref()
        .filter(|notice| notice.observed_at.elapsed() <= Duration::from_secs(10))
    else {
        return;
    };
    let notice_area = Rect::new(
        area.x,
        area.y.saturating_add(area.height.saturating_sub(1)),
        area.width,
        1,
    );
    let style = if notice.is_error {
        Style::default().fg(Color::White).bg(Color::Red)
    } else {
        Style::default().fg(Color::Black).bg(Color::Green)
    }
    .add_modifier(Modifier::BOLD);
    frame.render_widget(Clear, notice_area);
    frame.render_widget(
        Paragraph::new(format!(" {} ", notice.message)).style(style),
        notice_area,
    );
}

fn guidance_key(key: &'static str, description: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {key:<12}"),
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(description, Style::default().fg(Color::White)),
    ])
}

fn guidance_section(title: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        format!(" {title}"),
        Style::default()
            .fg(Color::LightMagenta)
            .add_modifier(Modifier::BOLD),
    ))
}

fn guidance_page(page: usize) -> Vec<Line<'static>> {
    match page % GUIDANCE_PAGE_COUNT {
        0 => vec![
            Line::from(""),
            guidance_section("UNDERSTAND THE PROCESS TREE"),
            Line::from(Span::styled(
                " See who started it, what it owns, and the cost of the complete service.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key("↑↓ / j k", "move through stable process rows"),
            guidance_key("← / →", "reveal parent; expand or collapse children"),
            guidance_key(
                "/",
                "find by text or query CPU, memory, age, user, and subtree",
            ),
            guidance_key("f", "focus the selected parent chain and service subtree"),
            guidance_key(
                "Enter",
                "inspect threads, sockets, files, and runtime context",
            ),
            Line::from(""),
            Line::from(Span::styled(
                " Query example:  user:deploy tree.mem>2g !state:zombie",
                Style::default().fg(Color::Yellow),
            )),
        ],
        1 => vec![
            Line::from(""),
            guidance_section("MOVE FROM SYMPTOM TO EVIDENCE"),
            Line::from(Span::styled(
                " Workspaces keep process ownership attached to every signal.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(
                "a",
                "attention: unhealthy state, churn, pressure, and growth",
            ),
            guidance_key("h", "CPU, memory, read, and write hotspot workbench"),
            guidance_key("t", "recent own and complete-subtree resource trend"),
            guidance_key("n", "listeners, connections, peers, owners, and namespaces"),
            guidance_key(
                "v",
                "verify executable image, package, hash, and code signature",
            ),
            guidance_key(
                "m",
                "systemd or launchd ownership, state, config, and next commands",
            ),
            guidance_key("l", "bounded native logs for this process or service"),
            guidance_key("D", "one process dossier with prioritized evidence"),
            guidance_key("b / d / x", "capture baseline, compare, and clear"),
            guidance_key("Space / r", "freeze the scene; sample manually"),
            Line::from(""),
            Line::from(Span::styled(
                " Tip: D collects manager, image, logs, and process evidence in parallel.",
                Style::default().fg(Color::Yellow),
            )),
        ],
        _ => vec![
            Line::from(""),
            guidance_section("OPERATE CAREFULLY · SHARE USEFULLY"),
            Line::from(Span::styled(
                " Actions are confirmed and identity-checked; reports preserve your context.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key("p", "TERM, KILL, STOP, or CONT with explicit confirmation"),
            guidance_key("e", "recent process changes and action audit"),
            guidance_key("o", "export a private, versioned diagnostic report"),
            guidance_key("s", "cycle stable and service-tree hotspot sorting"),
            guidance_key("?", "open this field guide at any time"),
            guidance_key("q / Ctrl-C", "leave psmore"),
            Line::from(""),
            Line::from(Span::styled(
                " CLI companions: doctor, explain, inspect, exe, service, logs, tree, net, trace, diff",
                Style::default().fg(Color::Yellow),
            )),
        ],
    }
}

fn draw_guidance_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let Some(overlay) = app.guidance.overlay else {
        return;
    };
    let is_tip = matches!(overlay, GuidanceOverlay::Tip(_));
    let max_width = if is_tip { 72 } else { 100 };
    let max_height = if is_tip { 11 } else { 24 };
    let width = area.width.saturating_sub(2).min(max_width).max(1);
    let height = area.height.saturating_sub(2).min(max_height).max(1);
    let popup = if is_tip {
        Rect::new(
            area.x
                .saturating_add(area.width.saturating_sub(width).saturating_sub(1)),
            area.y
                .saturating_add(area.height.saturating_sub(height).saturating_sub(2)),
            width,
            height,
        )
    } else {
        Rect::new(
            area.x + area.width.saturating_sub(width) / 2,
            area.y + area.height.saturating_sub(height) / 2,
            width,
            height,
        )
    };
    let border_color = if is_tip {
        Color::LightMagenta
    } else {
        Color::LightCyan
    };
    let title = match overlay {
        GuidanceOverlay::Welcome => " WELCOME TO PSMORE · SEE THE SYSTEM THROUGH ITS PROCESSES ",
        GuidanceOverlay::Help => " PSMORE FIELD GUIDE ",
        GuidanceOverlay::Tip(index) => {
            let title = format!(" PSMORE TIP {}/{} ", index + 1, TIPS.len());
            frame.render_widget(Clear, popup);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .title(Span::styled(
                    title,
                    Style::default()
                        .fg(Color::LightMagenta)
                        .add_modifier(Modifier::BOLD),
                ));
            let Some(tip) = app.guidance.tip() else {
                frame.render_widget(block, popup);
                return;
            };
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!(" {}", tip.title),
                    Style::default()
                        .fg(Color::LightCyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(format!(" {}", tip.body)),
                Line::from(""),
                Line::from(Span::styled(
                    format!(" {}", tip.keys),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    format!(
                        " Any other key continues · ? guide · T future tips {} · D disable",
                        if app.guidance.tips_enabled() {
                            "ON"
                        } else {
                            "OFF"
                        }
                    ),
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            frame.render_widget(
                Paragraph::new(lines)
                    .block(block)
                    .wrap(Wrap { trim: false }),
                popup,
            );
            return;
        }
    };
    let mut lines = guidance_page(app.guidance.page);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            " ←/→ page {}/{} · Enter/Esc close · T tips {} · D never show startup cards{}",
            app.guidance.page + 1,
            GUIDANCE_PAGE_COUNT,
            if app.guidance.tips_enabled() {
                "ON"
            } else {
                "OFF"
            },
            if matches!(overlay, GuidanceOverlay::Help) {
                " · ? close"
            } else {
                ""
            },
        ),
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title(Span::styled(
                        title,
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    )),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

pub(crate) fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.width == 0 || area.height == 0 {
        return;
    }
    let detail_height = detail_height(app, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(detail_height),
            Constraint::Length(2),
        ])
        .split(area);
    app.page_size = chunks[0].height.saturating_sub(2).max(1) as usize;
    let mut title = match (&app.focus, app.searching) {
        (Some(pid), true) => format!(" psmore  focus={}  search: {}", pid, app.search),
        (Some(pid), false) if !app.search.is_empty() => {
            format!(" psmore  focus={}  filter: {}", pid, app.search)
        }
        (Some(pid), false) => format!(" psmore  focus={} ", pid),
        (None, true) => format!(" psmore  search: {}", app.search),
        (None, false) if !app.search.is_empty() => format!(" psmore  filter: {}", app.search),
        (None, false) => format!(" psmore  {} process relationships ", platform_name()),
    };
    if !app.search.is_empty() {
        if let Some(error) = &app.search_error {
            title.push_str(&format!("  query error: {error} "));
        } else {
            title.push_str(&format!("  {} hits ", app.search_matches));
        }
    }
    if app.paused {
        title.push_str(" PAUSED ");
    }
    title.push_str(&format!(" sort={} ", app.sort_mode.label()));
    let selected_pid = app.selected_pid();
    let selected_parent =
        selected_pid.and_then(|pid| app.processes.get(&pid).and_then(|p| p.parent));
    let selected_depth = app.visible.get(app.selected).map(|row| row.depth);
    let selected_name =
        selected_pid.and_then(|pid| app.processes.get(&pid).map(|process| process.name.clone()));
    let row_parts: Vec<(String, String)> = app
        .visible
        .iter()
        .map(|row| row_label_and_context(app, row))
        .collect();
    let path_column = row_parts
        .iter()
        .map(|(label, _)| label.width())
        .max()
        .unwrap_or(0)
        + 2;
    let tree_width = chunks[0].width.saturating_sub(2) as usize;
    let path_width = tree_width.saturating_sub(path_column);
    app.advance_marquee(path_width);
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .zip(row_parts.iter())
        .map(|(row, (label, context))| {
            let p = &app.processes[&row.pid];
            let line = format!(
                "{}{}{}",
                label,
                " ".repeat(path_column.saturating_sub(label.width())),
                marquee(
                    context,
                    if Some(row.pid) == selected_pid {
                        app.marquee_offset
                    } else {
                        0
                    },
                    path_width,
                )
            );
            let same_name_as_selected = app.searching
                && Some(row.pid) != selected_pid
                && selected_name
                    .as_deref()
                    .map(|name| name == p.name)
                    .unwrap_or(false);
            let recent_change = app.recent_change(row.pid);
            let sibling_background_allowed = selected_depth.map(|depth| depth > 2).unwrap_or(false);
            let style = if Some(row.pid) == selected_pid {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if same_name_as_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(recent_change, Some(ProcessChange::Started { .. })) {
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(recent_change, Some(ProcessChange::Reparented { .. })) {
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::BOLD)
            } else if sibling_background_allowed
                && selected_parent.is_some()
                && p.parent == selected_parent
                && Some(row.pid) != selected_pid
            {
                // Crossterm has no portable alpha channel. Dim cyan gives
                // sibling rows a clear, approximately 30% emphasis.
                Style::default()
                    .fg(Color::Cyan)
                    .bg(Color::Rgb(0, 64, 72))
                    .add_modifier(Modifier::DIM)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(line).style(style)
        })
        .collect();
    let tree = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    let mut tree_state = ListState::default();
    tree_state.select(Some(app.selected));
    frame.render_stateful_widget(tree, chunks[0], &mut tree_state);

    let detail = if let Some(pid) = app.selected_pid() {
        let p = &app.processes[&pid];
        let command = process_command_line(p);
        let children = app.children.get(&Some(pid)).map(|c| c.len()).unwrap_or(0);
        let subtree = app.resources.get(&pid).copied().unwrap_or_default();
        let mut detail_lines = vec![Line::from(vec![
            Span::styled(
                format!("PID {}", pid),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  PPID {}  children {}  status {}  CPU {:.1}%  MEM {} MB  R {}  W {}  runtime {}s",
                p.parent
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                children,
                p.status,
                p.cpu,
                p.memory / 1024 / 1024,
                format_bytes_rate(p.read_rate),
                format_bytes_rate(p.write_rate),
                p.runtime
            )),
        ])];
        detail_lines.push(Line::from(vec![
            Span::styled(
                "TREE",
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " {} proc (self + descendants)  CPU {:.1}%  MEM {} MB  R {}  W {}",
                subtree.process_count,
                subtree.cpu,
                subtree.memory / 1024 / 1024,
                format_bytes_rate(subtree.read_rate),
                format_bytes_rate(subtree.write_rate)
            )),
        ]));
        detail_lines.push(Line::from(command));
        Text::from(detail_lines)
    } else {
        Text::from("No processes found")
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" selected process "),
            )
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    let total_processes = app.processes.len().saturating_sub(1);
    let total_pages = app.visible.len().div_ceil(app.page_size);
    let total_pages = total_pages.max(1);
    let current_page = (app.selected / app.page_size + 1).min(total_pages);
    let live_state = if app.paused { "PAUSED" } else { "LIVE" };
    let baseline_state = app
        .baseline
        .as_ref()
        .map(|baseline| format!("base {}s", baseline.captured_at.elapsed().as_secs()))
        .unwrap_or_else(|| "no base".into());
    let shortcut_line = if app.searching {
        if let Some(error) = &app.search_error {
            format!(" query error: {error} | Backspace edit | Enter finish | Esc clear ")
        } else {
            " query: words | name:/user:/state: | cpu>20 | mem>500m | tree.mem>2g | !negate | Enter finish | Esc clear ".into()
        }
    } else if !app.search.is_empty() {
        " filter active | / new search or clear | ↑↓/jk move | Enter inspect | q quit ".into()
    } else {
        " ↑↓/jk move | ←/→ tree | / find | D dossier | a attention | h hot | m manager | v image | l logs | p actions | t trend | n network | b base | d diff | o report | ? help ".into()
    };
    let footer = Paragraph::new(vec![
        Line::from(format!(
            " {} proc | page {}/{} | {} | {} | sort {} | +{} -{} ↪{} | q quit ",
            total_processes,
            current_page,
            total_pages,
            live_state,
            baseline_state,
            app.sort_mode.label(),
            app.last_changes.started,
            app.last_changes.exited,
            app.last_changes.reparented,
        )),
        Line::from(shortcut_line),
    ])
    .style(Style::default().fg(if app.paused {
        Color::Yellow
    } else {
        Color::DarkGray
    }));
    frame.render_widget(footer, chunks[2]);

    if app.show_attention {
        draw_attention_overlay(frame, app, area);
    } else if app.show_hotspots {
        draw_hotspot_overlay(frame, app, area);
    } else if app.show_network {
        draw_network_overlay(frame, app, area);
    } else if app.show_snapshot_diff {
        draw_snapshot_diff_overlay(frame, app, area);
    } else if app.trend_pid.is_some() {
        draw_trend_overlay(frame, app, area);
    } else if app.dossier_context.is_some() {
        draw_dossier_context_overlay(frame, app, area);
    } else if app.logs_context.is_some() {
        draw_logs_context_overlay(frame, app, area);
    } else if app.executable_context.is_some() {
        draw_executable_context_overlay(frame, app, area);
    } else if app.service_context.is_some() {
        draw_service_context_overlay(frame, app, area);
    } else if app.inspection.is_some() {
        draw_inspection_overlay(frame, app, area);
    } else if app.show_events {
        draw_event_overlay(frame, app, area);
    }
    if app.process_action.is_some() {
        draw_process_action_overlay(frame, app, area);
    }
    draw_notice(frame, app, area);
    draw_guidance_overlay(frame, app, area);
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::{
        app::{DossierContextPanel, ExecutableContextPanel, LogsContextPanel, ServiceContextPanel},
        cli::{LogPriority, LogScope},
        onboarding::{Guidance, TIPS},
    };

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let mut output = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                if let Some(cell) = buffer.cell((x, y)) {
                    output.push_str(cell.symbol());
                }
            }
            output.push('\n');
        }
        output
    }

    #[test]
    fn welcome_and_tip_overlays_render_and_handle_navigation() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let backend = TestBackend::new(100, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let first_page = buffer_text(&terminal);
        assert!(first_page.contains("WELCOME TO PSMORE"));
        assert!(first_page.contains("UNDERSTAND THE PROCESS TREE"));
        assert!(first_page.contains("page 1/3"));

        app.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let second_page = buffer_text(&terminal);
        assert!(second_page.contains("MOVE FROM SYMPTOM TO EVIDENCE"));
        assert!(second_page.contains("page 2/3"));

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.guidance.is_open());

        app.guidance = Guidance::tip_for_test(0);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let tip = buffer_text(&terminal);
        let tip_title = format!("PSMORE TIP 1/{}", TIPS.len());
        assert!(tip.contains(&tip_title));
        assert!(tip.contains("Reveal the real parent chain"));
        assert!(tip.contains("Any other key continues"));
        let tip_row = tip
            .lines()
            .position(|line| line.contains(&tip_title))
            .unwrap();
        assert!(
            tip_row >= 14,
            "tip should stay near the bottom: row {tip_row}"
        );

        app.on_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(buffer_text(&terminal).contains("PSMORE FIELD GUIDE"));
    }

    #[test]
    fn welcome_is_modal_but_a_tip_never_steals_the_first_working_key() {
        let mut welcome = App::new_for_test(Guidance::welcome_for_test());
        welcome.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(welcome.guidance.is_open());
        assert!(!welcome.paused);

        let mut tip = App::new_for_test(Guidance::tip_for_test(0));
        tip.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(!tip.guidance.is_open());
        assert!(tip.paused);
    }

    #[test]
    fn service_context_overlay_renders_scrolls_and_closes() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.service_context = Some(ServiceContextPanel {
            pid: Pid::from_u32(4321),
            name: "worker".into(),
            content: [
                "manager systemd (system)  managed yes  coverage complete",
                "service example.service  target system/example.service  root PID 4321",
                "state active/running  load loaded  result success  enabled enabled",
                "config /etc/systemd/system/example.service  program /usr/bin/example",
                "next logs: journalctl --unit example.service --since -1h",
            ]
            .join("\n"),
            report: None,
            warning: None,
        });
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let output = buffer_text(&terminal);
        assert!(output.contains("manager worker [4321]"));
        assert!(output.contains("example.service"));
        assert!(output.contains("journalctl"));

        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.service_context_scroll, 1);
        app.on_key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
        assert!(app.service_context.is_none());
        assert_eq!(app.service_context_scroll, 0);
    }

    #[test]
    fn manager_key_opens_context_for_the_selected_process() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == current_pid)
            .expect("current test process should be visible");

        app.on_key(KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE));
        let panel = app
            .service_context
            .as_ref()
            .expect("manager key should open service context");
        assert_eq!(panel.pid, current_pid);
        assert!(app.service_context_is_scanning());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.service_context.is_none());
        assert!(!app.service_context_is_scanning());
    }

    #[test]
    fn dossier_overlay_renders_controls_and_closes() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.dossier_context = Some(DossierContextPanel {
            pid: current_pid,
            name: "worker".into(),
            content: [
                "PSMORE PROCESS DOSSIER",
                "process worker [42]  user deploy  status Run  identity verified",
                "status warning  signals 2 (critical 0, warning 1, notice 1)",
                "PRIORITIZED SIGNALS",
                "  WARN resource.fd_limit_pressure      92% of soft limit",
                "  NOTE resource.cpu_hot_sample         sampled CPU is high",
                "EVIDENCE OVERVIEW",
                "  inspection         complete      20ms",
                "  service_context    partial       40ms",
            ]
            .join("\n"),
            report: Some(serde_json::json!({"schema": "psmore.process-dossier"})),
            warning: None,
            include_logs: true,
            hash: true,
            scope: LogScope::Auto,
            priority: LogPriority::Info,
            since_seconds: 900,
            limit: 100,
        });
        let backend = TestBackend::new(110, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let output = buffer_text(&terminal);
        assert!(output.contains(&format!("dossier worker [{current_pid}]")));
        assert!(output.contains("resource.fd_limit_pressure"));
        assert!(output.contains("logs on auto <= info 15m"));

        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        assert!(!app.dossier_context.as_ref().unwrap().include_logs);
        assert!(app.dossier_context_is_scanning());
        app.on_key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));
        assert!(app.dossier_context.is_none());
        assert!(!app.dossier_context_is_scanning());
    }

    #[test]
    fn dossier_key_opens_context_for_the_selected_process() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == current_pid)
            .expect("current test process should be visible");

        app.on_key(KeyEvent::new(KeyCode::Char('D'), KeyModifiers::NONE));
        let panel = app
            .dossier_context
            .as_ref()
            .expect("D should open process dossier");
        assert_eq!(panel.pid, current_pid);
        assert!(panel.include_logs);
        assert!(panel.hash);
        assert!(app.dossier_context_is_scanning());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.dossier_context.is_none());
        assert!(!app.dossier_context_is_scanning());
    }

    #[test]
    fn executable_context_overlay_renders_toggles_hash_and_closes() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.executable_context = Some(ExecutableContextPanel {
            pid: current_pid,
            name: "worker".into(),
            content: [
                "PSMORE EXECUTABLE IMAGE",
                "process worker [4321]  user deploy  identity verified",
                "status replaced_on_disk  attention yes",
                "running /opt/worker.old  exists yes  deleted yes  readable yes",
                "disk /opt/worker  exists yes  deleted no  readable yes",
                "package dpkg worker 1.2.3 (amd64)",
                "coverage complete  sources 3  warnings 0",
            ]
            .join("\n"),
            report: None,
            warning: None,
            hash: true,
        });
        let backend = TestBackend::new(110, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let output = buffer_text(&terminal);
        assert!(output.contains(&format!("verify image worker [{current_pid}]")));
        assert!(output.contains("replaced_on_disk"));
        assert!(output.contains("package dpkg worker"));

        app.on_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        assert!(!app.executable_context.as_ref().unwrap().hash);
        assert!(app.executable_context_is_scanning());
        app.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        assert!(app.executable_context.is_none());
        assert!(!app.executable_context_is_scanning());
    }

    #[test]
    fn verify_image_key_opens_context_for_the_selected_process() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == current_pid)
            .expect("current test process should be visible");

        app.on_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        let panel = app
            .executable_context
            .as_ref()
            .expect("verify image key should open executable context");
        assert_eq!(panel.pid, current_pid);
        assert!(panel.hash);
        assert!(app.executable_context_is_scanning());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.executable_context.is_none());
        assert!(!app.executable_context_is_scanning());
    }

    #[test]
    fn logs_context_overlay_renders_controls_and_closes() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.logs_context = Some(LogsContextPanel {
            pid: current_pid,
            name: "worker".into(),
            content: [
                "PSMORE PROCESS LOGS",
                "source journald  scope auto -> service  selector _SYSTEMD_UNIT=worker.service",
                "window 10..20  priority <= info  rows 1/100  truncated no  coverage complete",
                "service worker.service  scope system",
                "TIME                         LEVEL     SOURCE[PID]            MESSAGE",
                "2026-08-02T00:00:00.000Z error     worker[4321]           request failed",
            ]
            .join("\n"),
            report: None,
            warning: None,
            scope: LogScope::Auto,
            priority: LogPriority::Info,
            since_seconds: 900,
            limit: 100,
        });
        let backend = TestBackend::new(130, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let output = buffer_text(&terminal);
        assert!(output.contains(&format!("logs worker [{current_pid}]")));
        assert!(output.contains("worker.service"));
        assert!(output.contains("request failed"));
        assert!(output.contains("scope auto"));

        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.logs_context_scroll, 1);
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(
            app.logs_context.as_ref().unwrap().priority,
            LogPriority::Debug
        );
        assert!(app.logs_context_is_scanning());
        app.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        assert!(app.logs_context.is_none());
        assert!(!app.logs_context_is_scanning());
    }

    #[test]
    fn logs_key_opens_context_for_the_selected_process() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == current_pid)
            .expect("current test process should be visible");

        app.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        let panel = app
            .logs_context
            .as_ref()
            .expect("logs key should open native log context");
        assert_eq!(panel.pid, current_pid);
        assert_eq!(panel.scope, LogScope::Auto);
        assert_eq!(panel.priority, LogPriority::Info);
        assert_eq!(panel.since_seconds, 900);
        assert!(app.logs_context_is_scanning());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.logs_context.is_none());
        assert!(!app.logs_context_is_scanning());
    }

    #[test]
    fn zero_sized_terminal_does_not_panic() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let backend = TestBackend::new(0, 0);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    }
}
