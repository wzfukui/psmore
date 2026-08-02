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
    filters::FilterAction,
    i18n::{UiLanguage, text},
    model::{
        AttentionSeverity, HotspotMetric, HotspotScope, InspectionField, ProcessChange,
        ProcessEvent, ProcessInspection, SortMode, TreeRow, TrendView, process_command_line,
        process_path,
    },
    network::{NetworkEndpoint, NetworkScope},
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
    let language = app.language();
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
            text(language, " ACTIONS", " 操作记录"),
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
            text(language, " PROCESS CHANGES", " 进程变化"),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        let remaining = line_limit.saturating_sub(lines.len());
        lines.extend(app.events.iter().rev().take(remaining).map(event_line));
    }
    if lines.is_empty() {
        lines.push(Line::from(text(
            language,
            " No process changes or actions captured yet ",
            " 尚未捕获进程变化或人工操作 ",
        )));
    }
    let title = match language {
        UiLanguage::English => format!(
            " activity  changes {} / actions {}  Esc/e close ",
            app.events.len(),
            app.action_history.len()
        ),
        UiLanguage::Chinese => format!(
            " 活动审计  变化 {} / 操作 {}  Esc/e 关闭 ",
            app.events.len(),
            app.action_history.len()
        ),
    };
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

fn process_action_description(language: UiLanguage, action: ProcessActionKind) -> &'static str {
    match action {
        ProcessActionKind::Terminate => {
            text(language, "request a graceful shutdown", "请求进程正常退出")
        }
        ProcessActionKind::Kill => text(language, "force immediate termination", "强制立即终止"),
        ProcessActionKind::Stop => text(language, "suspend process execution", "暂停进程执行"),
        ProcessActionKind::Continue => text(language, "resume a stopped process", "恢复已暂停进程"),
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
    let language = app.language();
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
        title = format!(
            " {} {}  Esc {} ",
            text(language, "confirm", "确认"),
            action.label(),
            text(language, "back", "返回")
        );
        lines.extend([
            Line::from(vec![
                Span::styled(
                    format!("{}  ", action.label()),
                    Style::default()
                        .fg(process_action_color(action))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(process_action_description(language, action)),
            ]),
            Line::from(""),
            Line::from(Span::styled(
                if action == ProcessActionKind::Kill {
                    text(
                        language,
                        "KILL cannot be handled or cleaned up by the target process.",
                        "KILL 无法被目标进程捕获，也不会给它清理资源的机会。",
                    )
                } else {
                    text(
                        language,
                        "This changes the live process and may affect its complete service tree.",
                        "该操作会改变正在运行的进程，并可能影响其完整服务树。",
                    )
                },
                Style::default().fg(Color::LightRed),
            )),
            Line::from(text(
                language,
                "Before sending, psmore will re-check the PID start time and refuse PID reuse.",
                "发送前 psmore 会重新核对 PID 启动时间，发现 PID 复用时拒绝操作。",
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    text(language, "Press y to send the signal", "按 y 发送信号"),
                    Style::default()
                        .fg(Color::LightYellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(text(
                    language,
                    "  ·  Esc returns without changing the process",
                    "  ·  Esc 返回且不改变进程",
                )),
            ]),
        ]);
    } else {
        title = if dialog.is_termination_only() {
            text(
                language,
                " end process  ↑↓/Tab choose  Enter review  Esc close ",
                " 结束进程  ↑↓/Tab 选择  Enter 复核  Esc 关闭 ",
            )
            .into()
        } else {
            text(
                language,
                " process actions  ↑↓/Tab choose  Enter review  Esc/p close ",
                " 进程操作  ↑↓/Tab 选择  Enter 复核  Esc/p 关闭 ",
            )
            .into()
        };
        for (index, action) in dialog.actions().iter().copied().enumerate() {
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
                    process_action_description(language, action)
                ),
                style,
            )));
        }
        lines.extend([
            Line::from(""),
            Line::from(Span::styled(
                text(
                    language,
                    "No signal is sent here: review the next screen, then press y to confirm.",
                    "此处不会发送信号：请在下一页复核，然后按 y 确认。",
                ),
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

fn filter_action_label(language: UiLanguage, action: FilterAction) -> &'static str {
    match action {
        FilterAction::Include => text(language, "ALLOW", "包含"),
        FilterAction::Exclude => text(language, "DENY", "排除"),
    }
}

fn draw_filter_manager_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let language = app.language();
    let width = area.width.saturating_sub(2).clamp(1, 132);
    let height = area.height.saturating_sub(2).clamp(1, 22);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, popup);

    if let Some(editor) = &app.filter_editor {
        let operation = if editor.editing_index.is_some() {
            text(language, "edit", "编辑")
        } else {
            text(language, "add", "新增")
        };
        let title = format!(
            " {} {} {}  Tab {}  Enter {}  Esc {} ",
            operation,
            filter_action_label(language, editor.action),
            text(language, "filter", "规则"),
            text(language, "allow/deny", "包含/排除"),
            text(language, "save", "保存"),
            text(language, "cancel", "取消")
        );
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                text(
                    language,
                    "One rule is an AND expression. Multiple ALLOW rules are OR; any DENY rule wins.",
                    "单条规则内部为 AND；多条包含规则之间为 OR；任一排除规则命中即隐藏。",
                ),
                Style::default().fg(Color::LightCyan),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled(
                    format!(" {}  ", filter_action_label(language, editor.action)),
                    Style::default()
                        .fg(if editor.action == FilterAction::Include {
                            Color::LightGreen
                        } else {
                            Color::LightRed
                        })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{}▏", editor.input)),
            ]),
            Line::from(""),
            Line::from(text(
                language,
                " Text: path:/System/Library  ·  combined: path:/opt name:python",
                " 文本：path:/System/Library  ·  组合：path:/opt name:python",
            )),
            Line::from(text(
                language,
                r" Regex: path~^/Applications/(ChatGPT|Otty)\.app/  (case-sensitive; (?i) supported)",
                r" 正则：path~^/Applications/(ChatGPT|Otty)\.app/（区分大小写；支持 (?i)）",
            )),
            Line::from(text(
                language,
                " Spaces: path:\"/Applications/Google Chrome.app\"  ·  fields: any/name/cmd/path/user/state",
                " 空格：path:\"/Applications/Google Chrome.app\"  ·  字段：any/name/cmd/path/user/state",
            )),
        ];
        if let Some(error) = &editor.error {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(" {}: {error}", text(language, "error", "错误")),
                Style::default().fg(Color::LightRed),
            )));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(title))
                .wrap(Wrap { trim: false }),
            popup,
        );
        return;
    }

    let footer_height = 5;
    let chunks =
        Layout::vertical([Constraint::Min(3), Constraint::Length(footer_height)]).split(popup);
    let items: Vec<ListItem> = if app.process_filters.is_empty() {
        vec![
            ListItem::new(text(
                language,
                " No filters. Press a to add an ALLOW rule or x to add a DENY rule.",
                " 暂无过滤规则。按 a 新增包含规则，或按 x 新增排除规则。",
            ))
            .style(Style::default().fg(Color::DarkGray)),
        ]
    } else {
        app.process_filters
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let enabled = if rule.enabled { "●" } else { "○" };
                let style = if rule.enabled {
                    Style::default().fg(if rule.action == FilterAction::Include {
                        Color::LightGreen
                    } else {
                        Color::LightRed
                    })
                } else {
                    Style::default().fg(Color::DarkGray)
                };
                ListItem::new(format!(
                    " {:>2}. {enabled} {:<5}  {}",
                    index + 1,
                    filter_action_label(language, rule.action),
                    rule.expression
                ))
                .style(style)
            })
            .collect()
    };
    let title = format!(
        " {}  {} {}/{}  {} {}/{} ",
        text(language, "process filters", "进程过滤器"),
        text(language, "active", "启用"),
        app.active_filter_count(),
        app.process_filters.len(),
        text(language, "passing", "通过"),
        app.filtered_processes,
        app.processes.len().saturating_sub(1)
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
    if !app.process_filters.is_empty() {
        state.select(Some(app.filter_selected));
    }
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let error_style = if app.filter_error.is_some() {
        Style::default().fg(Color::LightRed)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let error = app
        .filter_error
        .as_ref()
        .map(|error| format!(" {}: {error}", text(language, "error", "错误")))
        .unwrap_or_else(|| {
            text(
                language,
                " Rules run before / search; parent rows may remain as relationship context.",
                " 规则先于 / 搜索执行；父进程行可能作为关系上下文保留。",
            )
            .into()
        });
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(text(
                language,
                " a allow  x deny  Enter/e edit  Space enable  d delete  ↑↓ move  F/Esc close",
                " a 包含  x 排除  Enter/e 编辑  Space 启停  d 删除  ↑↓ 移动  F/Esc 关闭",
            )),
            Line::from(Span::styled(error, error_style)),
            Line::from(text(
                language,
                " Text matching is case-insensitive. Regex is case-sensitive unless it uses (?i).",
                " 文本匹配不区分大小写；正则默认区分大小写，可使用 (?i)。",
            )),
        ]),
        chunks[1],
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
    let language = app.language();
    let mut lines = inspection_lines(inspection);
    let inspection_status = if app.inspection_is_scanning() {
        let elapsed = app.inspection_elapsed();
        lines.insert(0, Line::from(""));
        lines.insert(
            0,
            Line::from(Span::styled(
                match language {
                    UiLanguage::English => format!(
                        " {} collecting process context in the background ({:.1}s)",
                        activity_spinner(elapsed),
                        elapsed.as_secs_f64()
                    ),
                    UiLanguage::Chinese => format!(
                        " {} 正在后台采集进程上下文（{:.1}s）",
                        activity_spinner(elapsed),
                        elapsed.as_secs_f64()
                    ),
                },
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
        );
        text(language, "  scanning", "  采集中")
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
    let title = match language {
        UiLanguage::English => format!(
            " inspect {} [{}]{}  Enter/r refresh  ↑↓ scroll  M memory  D dossier  Esc close ",
            inspection.name, inspection.pid, inspection_status
        ),
        UiLanguage::Chinese => format!(
            " 深度检查 {} [{}]{}  Enter/r 刷新  ↑↓ 滚动  M 内存  D 档案  Esc 关闭 ",
            inspection.name, inspection.pid, inspection_status
        ),
    };
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
    let language = app.language();
    let mut lines = Vec::new();
    if app.dossier_context_is_scanning() {
        let elapsed = app.dossier_context_elapsed();
        lines.push(Line::from(Span::styled(
            match language {
                UiLanguage::English => format!(
                    " {} collecting process dossier in parallel ({:.1}s)",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在并行采集进程档案（{:.1}s）",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
            },
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
            text(language, " No process dossier available", " 暂无进程档案"),
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
        text(language, " scanning", " 采集中")
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
    let title = match language {
        UiLanguage::English => format!(
            " dossier {} [{}]{}  {}  {}  r refresh  s/p/w logs  h hash  L logs  i/M/m/v/l evidence  D/Esc close ",
            panel.name, panel.pid, scanning, logs, hash
        ),
        UiLanguage::Chinese => format!(
            " 进程档案 {} [{}]{}  {}  {}  r 刷新  s/p/w 日志  h 哈希  L 日志开关  i/M/m/v/l 证据  D/Esc 关闭 ",
            panel.name, panel.pid, scanning, logs, hash
        ),
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.dossier_context_scroll, 0))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn draw_memory_context_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let Some(panel) = app.memory_context.clone() else {
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
    let language = app.language();
    let mut lines = Vec::new();
    if app.memory_context_is_scanning() {
        let elapsed = app.memory_context_elapsed();
        lines.push(Line::from(Span::styled(
            match language {
                UiLanguage::English => format!(
                    " {} attributing process memory in the background ({:.1}s)",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台归因进程内存（{:.1}s）",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
            },
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
        let style = if line.starts_with("PSMORE PROCESS MEMORY")
            || matches!(line, "ATTENTION" | "COLLECTION SOURCES")
            || line.starts_with("MEMORY CATEGORIES")
            || line.starts_with("TOP FILE MAPPINGS")
        {
            Style::default()
                .fg(Color::LightMagenta)
                .add_modifier(Modifier::BOLD)
        } else if trimmed.starts_with("WARN") || line.starts_with("warning ") {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else if trimmed.starts_with("NOTE") {
            Style::default().fg(Color::LightCyan)
        } else if line.starts_with("process ")
            || line.starts_with("collection ")
            || line.starts_with("sampled RSS ")
            || line.starts_with("peak RSS ")
            || line.starts_with("anonymous ")
            || line.starts_with("virtual layout ")
        {
            Style::default().fg(Color::LightGreen)
        } else if trimmed.starts_with("CATEGORY") || trimmed.starts_with("VIRTUAL") {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(line.to_owned(), style)));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            text(
                language,
                " No process memory evidence available",
                " 暂无进程内存证据",
            ),
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
    app.memory_context_scroll = app.memory_context_scroll.min(max_scroll);
    let scanning = if app.memory_context_is_scanning() {
        text(language, "  scanning", "  采集中")
    } else {
        ""
    };
    let title = match language {
        UiLanguage::English => format!(
            " memory {} [{}]{}  Enter/r refresh  ↑↓ scroll  D dossier  i/m/v/l evidence  M/Esc close ",
            panel.name, panel.pid, scanning
        ),
        UiLanguage::Chinese => format!(
            " 内存归因 {} [{}]{}  Enter/r 刷新  ↑↓ 滚动  D 档案  i/m/v/l 证据  M/Esc 关闭 ",
            panel.name, panel.pid, scanning
        ),
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((app.memory_context_scroll, 0))
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
    let language = app.language();
    let mut lines = Vec::new();
    if app.service_context_is_scanning() {
        let elapsed = app.service_context_elapsed();
        lines.push(Line::from(Span::styled(
            match language {
                UiLanguage::English => format!(
                    " {} resolving systemd/launchd ownership in the background ({:.1}s)",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台解析 systemd/launchd 归属（{:.1}s）",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
            },
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
            text(
                language,
                " No service context available",
                " 暂无服务管理上下文",
            ),
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
        text(language, "  scanning", "  采集中")
    } else {
        ""
    };
    let title = match language {
        UiLanguage::English => format!(
            " manager {} [{}]{}  Enter/r refresh  ↑↓ scroll  M memory  D dossier  v verify  l logs  m/Esc close ",
            panel.name, panel.pid, scanning
        ),
        UiLanguage::Chinese => format!(
            " 服务管理 {} [{}]{}  Enter/r 刷新  ↑↓ 滚动  M 内存  D 档案  v 映像  l 日志  m/Esc 关闭 ",
            panel.name, panel.pid, scanning
        ),
    };
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
    let language = app.language();
    let mut lines = Vec::new();
    if app.executable_context_is_scanning() {
        let elapsed = app.executable_context_elapsed();
        lines.push(Line::from(Span::styled(
            match language {
                UiLanguage::English => format!(
                    " {} verifying executable image and provenance in the background ({:.1}s)",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台验证运行映像及来源（{:.1}s）",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
            },
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
            text(
                language,
                " No executable image evidence available",
                " 暂无运行映像证据",
            ),
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
        text(language, "  scanning", "  采集中")
    } else {
        ""
    };
    let hash = if panel.hash { "hash on" } else { "hash off" };
    let title = match language {
        UiLanguage::English => format!(
            " verify image {} [{}]{}  {}  Enter/r refresh  h hash  M memory  D dossier  m manager  l logs  v/Esc close ",
            panel.name, panel.pid, scanning, hash
        ),
        UiLanguage::Chinese => format!(
            " 验证映像 {} [{}]{}  {}  Enter/r 刷新  h 哈希  M 内存  D 档案  m 管理器  l 日志  v/Esc 关闭 ",
            panel.name, panel.pid, scanning, hash
        ),
    };
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
    let language = app.language();
    let mut lines = Vec::new();
    if app.logs_context_is_scanning() {
        let elapsed = app.logs_context_elapsed();
        lines.push(Line::from(Span::styled(
            match language {
                UiLanguage::English => format!(
                    " {} reading bounded native logs in the background ({:.1}s)",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台读取有界原生日志（{:.1}s）",
                    activity_spinner(elapsed),
                    elapsed.as_secs_f64()
                ),
            },
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
            text(
                language,
                " No native log evidence available",
                " 暂无原生日志证据",
            ),
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
        text(language, "  scanning", "  采集中")
    } else {
        ""
    };
    let title = match language {
        UiLanguage::English => format!(
            " logs {} [{}]{}  scope {}  <= {}  {}  r refresh  s scope  p level  w window  M memory  D dossier  m/v context  l/Esc close ",
            panel.name,
            panel.pid,
            scanning,
            panel.scope.label(),
            panel.priority.label(),
            compact_duration(panel.since_seconds),
        ),
        UiLanguage::Chinese => format!(
            " 日志 {} [{}]{}  范围 {}  <= {}  {}  r 刷新  s 范围  p 等级  w 窗口  M 内存  D 档案  m/v 上下文  l/Esc 关闭 ",
            panel.name,
            panel.pid,
            scanning,
            panel.scope.label(),
            panel.priority.label(),
            compact_duration(panel.since_seconds),
        ),
    };
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
    let language = app.language();
    let name = app
        .processes
        .get(&pid)
        .map(|process| process.name.as_str())
        .or_else(|| app.history.name(pid))
        .unwrap_or(text(language, "exited process", "已退出进程"));
    let title = match language {
        UiLanguage::English => format!(
            " trends {name} [{pid}]  {}  i switch  t/Esc close  r sample ",
            app.trend_view.label()
        ),
        UiLanguage::Chinese => format!(
            " 趋势 {name} [{pid}]  {}  i 切换  t/Esc 关闭  r 采样 ",
            app.trend_view.label()
        ),
    };
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(popup);
    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let Some(samples) = app.history.samples(pid) else {
        frame.render_widget(
            Paragraph::new(text(language, "No samples available", "暂无样本")),
            inner,
        );
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

fn sort_label(language: UiLanguage, mode: SortMode) -> &'static str {
    match (language, mode) {
        (UiLanguage::English, _) => mode.label(),
        (UiLanguage::Chinese, SortMode::Stable) => "稳定",
        (UiLanguage::Chinese, SortMode::SubtreeCpu) => "子树 CPU",
        (UiLanguage::Chinese, SortMode::SubtreeMemory) => "子树内存",
        (UiLanguage::Chinese, SortMode::SubtreeRead) => "子树读",
        (UiLanguage::Chinese, SortMode::SubtreeWrite) => "子树写",
    }
}

fn hotspot_metric_label(language: UiLanguage, metric: HotspotMetric) -> &'static str {
    match (language, metric) {
        (UiLanguage::English, _) => metric.label(),
        (UiLanguage::Chinese, HotspotMetric::Cpu) => "CPU",
        (UiLanguage::Chinese, HotspotMetric::Memory) => "内存",
        (UiLanguage::Chinese, HotspotMetric::Read) => "磁盘读",
        (UiLanguage::Chinese, HotspotMetric::Write) => "磁盘写",
    }
}

fn hotspot_scope_label(language: UiLanguage, scope: HotspotScope) -> &'static str {
    match (language, scope) {
        (UiLanguage::English, _) => scope.label(),
        (UiLanguage::Chinese, HotspotScope::Process) => "进程自身",
        (UiLanguage::Chinese, HotspotScope::Subtree) => "服务子树",
    }
}

fn network_scope_label(language: UiLanguage, scope: NetworkScope) -> &'static str {
    match (language, scope) {
        (UiLanguage::English, _) => scope.label(),
        (UiLanguage::Chinese, NetworkScope::Listeners) => "监听",
        (UiLanguage::Chinese, NetworkScope::All) => "全部连接",
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
    let language = app.language();
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
    let title = match language {
        UiLanguage::English => format!(
            " baseline diff {}s  {}→{} proc  {}  ↑↓ scroll  b reset  x clear  d/Esc close ",
            age,
            baseline.len(),
            current_count,
            system
        ),
        UiLanguage::Chinese => format!(
            " 基线对比 {}s  {}→{} 进程  {}  ↑↓ 滚动  b 重置  x 清除  d/Esc 关闭 ",
            age,
            baseline.len(),
            current_count,
            system
        ),
    };
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
    let language = app.language();
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
                    match language {
                        UiLanguage::English => format!(
                            " {spinner} collecting TCP, UDP and Unix endpoints in the background ({:.1}s)",
                            elapsed.as_secs_f64()
                        ),
                        UiLanguage::Chinese => format!(
                            " {spinner} 正在后台采集 TCP、UDP 和 Unix 端点（{:.1}s）",
                            elapsed.as_secs_f64()
                        ),
                    },
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    text(
                        language,
                        " The process tree remains live. Press n/Esc to close; the scan may finish in the background.",
                        " 进程树仍保持实时。按 n/Esc 关闭；扫描可继续在后台完成。",
                    ),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(text(language, " network scan ", " 网络扫描 ")),
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
        format!(
            " {}: {}_",
            text(language, "find", "查找"),
            app.network_filter
        )
    } else if app.network_filter.is_empty() {
        String::new()
    } else {
        format!(
            " {}: {}",
            text(language, "filter", "过滤"),
            app.network_filter
        )
    };
    let scanning = if app.network_is_scanning() {
        let elapsed = app.network_scan_elapsed();
        format!(
            "  {} {} {:.1}s",
            activity_spinner(elapsed),
            text(language, "rescanning", "重新扫描"),
            elapsed.as_secs_f64()
        )
    } else {
        String::new()
    };
    let title = format!(
        " {} {} {}/{}{}{} ",
        text(language, "network", "网络"),
        network_scope_label(language, app.network_scope),
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
        text(
            language,
            "showing the previous snapshot while a fresh scan runs",
            "新扫描运行期间显示上一份快照",
        )
    } else {
        scan.warning.as_deref().unwrap_or(text(
            language,
            "ownership complete for visible processes",
            "可见进程的归属信息完整",
        ))
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(text(
                language,
                " ↑↓/jk move | v listeners/all | / find | Enter jump | r rescan | x clear | n/Esc close ",
                " ↑↓/jk 移动 | v 监听/全部 | / 查找 | Enter 跳转 | r 重扫 | x 清除 | n/Esc 关闭 ",
            )),
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
    let language = app.language();
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = Block::default().borders(Borders::ALL).title(text(
        language,
        " attention cockpit ",
        " 关注事项 ",
    ));
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
            vec![ListItem::new(text(
                language,
                " no current findings — no unhealthy state, churn, sustained load, or rapid growth",
                " 当前没有发现异常状态、抖动、持续负载或快速增长",
            ))
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
                Line::from(text(
                    language,
                    " No process currently requires attention.",
                    " 当前没有需要关注的进程。",
                )),
                Line::from(Span::styled(
                    text(
                        language,
                        " Findings are evidence-based hints, not a claim that a process is faulty.",
                        " 这些发现是基于证据的线索，不代表进程已被认定有故障。",
                    ),
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
                Span::raw(text(
                    language,
                    " — explainable signals from state, lifecycle, resource history",
                    " — 来自状态、生命周期和资源历史的可解释信号",
                )),
            ]),
            Line::from(text(
                language,
                " ↑↓/jk move | Enter jump | t trend | i inspect | p actions | r sample | Space pause | a/Esc close",
                " ↑↓/jk 移动 | Enter 跳转 | t 趋势 | i 深检 | p 操作 | r 采样 | Space 暂停 | a/Esc 关闭",
            )),
        ]),
        sections[0],
    );
    frame.render_stateful_widget(list, sections[1], &mut state);
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::TOP).title(text(
                language,
                " evidence ",
                " 证据 ",
            )))
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
    let language = app.language();
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
            ListItem::new(text(
                language,
                " no activity in the current sample",
                " 当前样本没有活动",
            ))
            .style(Style::default().fg(Color::DarkGray)),
        );
    }
    let title = if active {
        format!(
            " {}  {} ",
            hotspot_metric_label(language, metric),
            text(language, "ACTIVE", "当前")
        )
    } else {
        format!(" {} ", hotspot_metric_label(language, metric))
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
    let language = app.language();
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = Block::default().borders(Borders::ALL).title(text(
        language,
        " hotspot cockpit ",
        " 热点工作台 ",
    ));
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
                Span::raw(text(language, " scope: ", " 范围：")),
                Span::styled(
                    hotspot_scope_label(language, app.hotspot_scope),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(text(language, "  | selected panel: ", "  | 当前面板：")),
                Span::styled(
                    hotspot_metric_label(language, app.hotspot_metric),
                    Style::default()
                        .fg(hotspot_color(app.hotspot_metric))
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(text(
                language,
                " ↑↓ rank | ←→ metric | v self/tree | Enter jump | r sample | Esc close",
                " ↑↓ 排名 | ←→ 指标 | v 自身/子树 | Enter 跳转 | r 采样 | Esc 关闭",
            )),
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

fn guidance_page_en(page: usize) -> Vec<Line<'static>> {
    match page % GUIDANCE_PAGE_COUNT {
        0 => vec![
            Line::from(""),
            guidance_section("UNDERSTAND THE PROCESS TREE"),
            Line::from(Span::styled(
                " See who started it, what it owns, and the cost of the complete service.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key("↑ / ↓", "move through stable process rows"),
            guidance_key("← / →", "reveal parent; expand or collapse children"),
            guidance_key("0-9", "type a PID, then press Enter to locate it directly"),
            guidance_key(
                "/",
                "type a query, then Enter to apply it and select results",
            ),
            guidance_key("F", "manage persistent allow/deny filters before search"),
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
            guidance_key("M", "attribute RSS, PSS, swap, regions, and mapped files"),
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
            guidance_key("k", "end the selected process through a two-step dialog"),
            guidance_key("p", "TERM, KILL, STOP, or CONT with explicit confirmation"),
            guidance_key("e", "recent process changes and action audit"),
            guidance_key("o", "export a private, versioned diagnostic report"),
            guidance_key("s", "cycle stable and service-tree hotspot sorting"),
            guidance_key("?", "open this field guide at any time"),
            guidance_key("q / Ctrl-C", "leave psmore"),
            Line::from(""),
            Line::from(Span::styled(
                " CLI companions: doctor, explain, inspect, memory, exe, service, logs, tree, net, trace, diff",
                Style::default().fg(Color::Yellow),
            )),
        ],
    }
}

fn guidance_page_zh(page: usize) -> Vec<Line<'static>> {
    match page % GUIDANCE_PAGE_COUNT {
        0 => vec![
            Line::from(""),
            guidance_section("理解进程树"),
            Line::from(Span::styled(
                " 看清谁启动了进程、它拥有什么，以及完整服务的资源成本。",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key("↑ / ↓", "在稳定排序的进程行之间移动"),
            guidance_key("← / →", "显示父进程；展开或折叠子进程"),
            guidance_key("0-9", "直接输入 PID，再按 Enter 精确定位"),
            guidance_key("/", "输入查询，按 Enter 后应用并选择结果"),
            guidance_key("F", "管理先于搜索执行的持久包含/排除规则"),
            guidance_key("f", "聚焦选中进程的父链和服务子树"),
            guidance_key("Enter", "检查线程、套接字、文件和运行上下文"),
            Line::from(""),
            Line::from(Span::styled(
                " 查询示例：user:deploy tree.mem>2g !state:zombie",
                Style::default().fg(Color::Yellow),
            )),
        ],
        1 => vec![
            Line::from(""),
            guidance_section("从症状走向证据"),
            Line::from(Span::styled(
                " 每个诊断工作区都会保留进程归属关系。",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key("a", "关注异常状态、抖动、压力和增长"),
            guidance_key("h", "CPU、内存、读写热点工作台"),
            guidance_key("t", "进程自身及完整子树的近期趋势"),
            guidance_key("n", "监听、连接、对端、所有者和命名空间"),
            guidance_key("v", "验证运行映像、软件包、哈希和代码签名"),
            guidance_key("m", "systemd/launchd 归属、状态、配置和命令"),
            guidance_key("l", "读取当前进程或服务的有界原生日志"),
            guidance_key("M", "归因 RSS、PSS、Swap、区域和映射"),
            guidance_key("D", "建立带优先级线索的单进程事故档案"),
            guidance_key("b / d / x", "捕获基线、比较并清除"),
            guidance_key("Space / r", "冻结现场；手工采样"),
            Line::from(""),
            Line::from(Span::styled(
                " 提示：D 会并行采集管理器、映像、日志和进程证据。",
                Style::default().fg(Color::Yellow),
            )),
        ],
        _ => vec![
            Line::from(""),
            guidance_section("谨慎操作 · 有效分享"),
            Line::from(Span::styled(
                " 操作需要确认和身份校验；报告会保留当前调查上下文。",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key("k", "通过两阶段弹窗结束选中进程"),
            guidance_key("p", "经明确确认发送 TERM/KILL/STOP/CONT"),
            guidance_key("e", "查看近期进程变化和操作审计"),
            guidance_key("o", "导出私有、版本化诊断报告"),
            guidance_key("s", "切换稳定排序和服务树热点排序"),
            guidance_key("L / F2", "切换中文或英文界面"),
            guidance_key("?", "随时打开本现场手册"),
            guidance_key("q / Ctrl-C", "退出 psmore"),
            Line::from(""),
            Line::from(Span::styled(
                " CLI 工具：doctor、explain、inspect、memory、exe、service、logs、tree、net、trace、diff",
                Style::default().fg(Color::Yellow),
            )),
        ],
    }
}

fn guidance_page(page: usize, language: UiLanguage) -> Vec<Line<'static>> {
    match language {
        UiLanguage::Chinese => guidance_page_zh(page),
        UiLanguage::English => guidance_page_en(page),
    }
}

fn draw_guidance_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let Some(overlay) = app.guidance.overlay else {
        return;
    };
    let is_tip = matches!(overlay, GuidanceOverlay::Tip(_));
    let language = app.language();
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
        GuidanceOverlay::Welcome => text(
            language,
            " WELCOME TO PSMORE · SEE THE SYSTEM THROUGH ITS PROCESSES ",
            " 欢迎使用 PSMORE · 通过进程看清系统 ",
        ),
        GuidanceOverlay::Help => text(language, " PSMORE FIELD GUIDE ", " PSMORE 现场手册 "),
        GuidanceOverlay::Tip(index) => {
            let title = format!(
                " PSMORE {} {}/{} ",
                text(language, "TIP", "提示"),
                index + 1,
                TIPS.len()
            );
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
                        " {} · ? {} · T {} {} · D {} · L {}",
                        text(language, "Any other key continues", "按其他键继续"),
                        text(language, "guide", "手册"),
                        text(language, "future tips", "启动提示"),
                        if app.guidance.tips_enabled() {
                            text(language, "ON", "开")
                        } else {
                            text(language, "OFF", "关")
                        },
                        text(language, "disable", "停用"),
                        text(language, "language", "语言")
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
    let mut lines = guidance_page(app.guidance.page, language);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            " ←/→ {} {}/{} · Enter/Esc {} · T {} {} · D {} · L/F2 {}{}",
            text(language, "page", "页"),
            app.guidance.page + 1,
            GUIDANCE_PAGE_COUNT,
            text(language, "close", "关闭"),
            text(language, "tips", "提示"),
            if app.guidance.tips_enabled() {
                text(language, "ON", "开")
            } else {
                text(language, "OFF", "关")
            },
            text(language, "never show startup cards", "不再显示启动卡片"),
            text(language, "language", "语言"),
            if matches!(overlay, GuidanceOverlay::Help) {
                text(language, " · ? close", " · ? 关闭")
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
    let language = app.language();
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
    let mut title = if let Some(pid_input) = &app.pid_input {
        format!(
            " psmore  {} PID: {pid_input}",
            text(language, "locate", "定位")
        )
    } else {
        match (&app.focus, app.searching) {
            (Some(pid), true) => {
                format!(
                    " psmore  {}={}  {}: {}",
                    text(language, "focus", "聚焦"),
                    pid,
                    text(language, "search input", "搜索输入"),
                    app.search_input
                )
            }
            (Some(pid), false) if !app.search.is_empty() => {
                format!(
                    " psmore  {}={}  {}: {}",
                    text(language, "focus", "聚焦"),
                    pid,
                    text(language, "filter", "过滤"),
                    app.search
                )
            }
            (Some(pid), false) => {
                format!(" psmore  {}={} ", text(language, "focus", "聚焦"), pid)
            }
            (None, true) => format!(
                " psmore  {}: {}",
                text(language, "search input", "搜索输入"),
                app.search_input
            ),
            (None, false) if !app.search.is_empty() => format!(
                " psmore  {}: {}",
                text(language, "filter", "过滤"),
                app.search
            ),
            (None, false) => format!(
                " psmore  {} {} ",
                platform_name(),
                text(language, "process relationships", "进程关系")
            ),
        }
    };
    if let Some(error) = &app.pid_input_error {
        title.push_str(&format!("  {error} "));
    } else if !app.searching && !app.search.is_empty() {
        if let Some(error) = &app.search_error {
            title.push_str(&format!(
                "  {}: {error} ",
                text(language, "query error", "查询错误")
            ));
        } else {
            title.push_str(&format!(
                "  {} {} ",
                app.search_matches,
                text(language, "hits", "个结果")
            ));
        }
    }
    if app.paused {
        title.push_str(text(language, " PAUSED ", " 已暂停 "));
    }
    title.push_str(&format!(
        " {}={} ",
        text(language, "sort", "排序"),
        sort_label(language, app.sort_mode)
    ));
    if app.active_filter_count() > 0 {
        title.push_str(&format!(
            " {}={}/{} ",
            text(language, "filtered", "过滤"),
            app.filtered_processes,
            app.processes.len().saturating_sub(1)
        ));
    }
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
            let same_name_as_selected = !app.search.is_empty()
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
                "  PPID {}  {} {}  {} {}  CPU {:.1}%  {} {} MB  {} {}  {} {}  {} {}s",
                p.parent
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                text(language, "children", "子进程"),
                children,
                text(language, "status", "状态"),
                p.status,
                p.cpu,
                text(language, "MEM", "内存"),
                p.memory / 1024 / 1024,
                text(language, "R", "读"),
                format_bytes_rate(p.read_rate),
                text(language, "W", "写"),
                format_bytes_rate(p.write_rate),
                text(language, "runtime", "运行"),
                p.runtime
            )),
        ])];
        detail_lines.push(Line::from(vec![
            Span::styled(
                text(language, "TREE", "子树"),
                Style::default()
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                " {} {} ({})  CPU {:.1}%  {} {} MB  {} {}  {} {}",
                subtree.process_count,
                text(language, "proc", "进程"),
                text(language, "self + descendants", "自身及后代"),
                subtree.cpu,
                text(language, "MEM", "内存"),
                subtree.memory / 1024 / 1024,
                text(language, "R", "读"),
                format_bytes_rate(subtree.read_rate),
                text(language, "W", "写"),
                format_bytes_rate(subtree.write_rate)
            )),
        ]));
        detail_lines.push(Line::from(command));
        Text::from(detail_lines)
    } else {
        Text::from(text(language, "No processes found", "没有找到进程"))
    };
    frame.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(text(
                language,
                " selected process ",
                " 当前进程 ",
            )))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );
    let total_processes = app.processes.len().saturating_sub(1);
    let total_pages = app.visible.len().div_ceil(app.page_size);
    let total_pages = total_pages.max(1);
    let current_page = (app.selected / app.page_size + 1).min(total_pages);
    let live_state = if app.paused {
        text(language, "PAUSED", "暂停")
    } else {
        text(language, "LIVE", "实时")
    };
    let baseline_state = app
        .baseline
        .as_ref()
        .map(|baseline| {
            format!(
                "{} {}s",
                text(language, "base", "基线"),
                baseline.captured_at.elapsed().as_secs()
            )
        })
        .unwrap_or_else(|| text(language, "no base", "无基线").into());
    let shortcut_line: String = if app.pid_input.is_some() {
        text(
            language,
            " PID: type digits | Enter locate | Backspace edit | Esc cancel ",
            " PID：输入数字 | Enter 定位 | Backspace 编辑 | Esc 取消 ",
        )
        .into()
    } else if app.searching {
        text(language, " search input (tree unchanged): words | name:/user:/state: | cpu>20 | mem>500m | tree.mem>2g | Enter apply | Esc cancel ", " 搜索输入（进程树不变）：文字 | name:/user:/state: | cpu>20 | mem>500m | tree.mem>2g | Enter 应用 | Esc 取消 ").into()
    } else if !app.search.is_empty() {
        text(language, " search active | ↑↓ move | k end selected | / new search | Esc clear | Enter inspect | q quit ", " 搜索已生效 | ↑↓ 移动 | k 结束选中进程 | / 新搜索 | Esc 清除 | Enter 深检 | q 退出 ").into()
    } else {
        text(language, " ↑↓ move | ←/→ tree | digits PID | / find | F filters | k end | p actions | D dossier | M memory | a attention | h hot | m manager | v image | l logs | L language | ? help ", " ↑↓ 移动 | ←/→ 进程树 | 数字定位 PID | / 搜索 | F 过滤器 | k 结束 | p 操作 | D 档案 | M 内存 | a 关注 | h 热点 | m 管理器 | v 映像 | l 日志 | L 语言 | ? 帮助 ").into()
    };
    let footer = Paragraph::new(vec![
        Line::from(format!(
            " {} {} | {} {}/{} | {} | {} | {} {} | +{} -{} ↪{} | F2 {} | q {} ",
            total_processes,
            text(language, "proc", "进程"),
            text(language, "page", "页"),
            current_page,
            total_pages,
            live_state,
            baseline_state,
            text(language, "sort", "排序"),
            sort_label(language, app.sort_mode),
            app.last_changes.started,
            app.last_changes.exited,
            app.last_changes.reparented,
            language.label(),
            text(language, "quit", "退出"),
        )),
        Line::from(shortcut_line),
    ])
    .style(Style::default().fg(if app.paused {
        Color::Yellow
    } else {
        Color::DarkGray
    }));
    frame.render_widget(footer, chunks[2]);

    if app.show_filter_manager {
        draw_filter_manager_overlay(frame, app, area);
    } else if app.show_attention {
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
    } else if app.memory_context.is_some() {
        draw_memory_context_overlay(frame, app, area);
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
    use std::{
        process::{Child, Command},
        thread,
        time::Duration,
    };

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::{
        app::{
            DossierContextPanel, ExecutableContextPanel, LogsContextPanel, MemoryContextPanel,
            ServiceContextPanel,
        },
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

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
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
    fn f2_switches_the_complete_guidance_surface_between_languages() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let backend = TestBackend::new(100, 28);
        let mut terminal = Terminal::new(backend).unwrap();

        app.on_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let chinese = buffer_text(&terminal);
        let compact_chinese = chinese.replace(' ', "");
        assert!(compact_chinese.contains("欢迎使用PSMORE"));
        assert!(compact_chinese.contains("理解进程树"));
        assert!(compact_chinese.contains("页1/3"));

        app.on_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let english = buffer_text(&terminal);
        assert!(english.contains("WELCOME TO PSMORE"));
        assert!(english.contains("UNDERSTAND THE PROCESS TREE"));
    }

    #[test]
    fn filter_manager_adds_toggles_edits_and_removes_rules() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let backend = TestBackend::new(132, 26);
        let mut terminal = Terminal::new(backend).unwrap();

        app.on_key(KeyEvent::new(KeyCode::Char('F'), KeyModifiers::NONE));
        assert!(app.show_filter_manager);
        app.on_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        for character in "path~^/System/Library/original$".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert_eq!(app.process_filters.len(), 1);
        assert_eq!(app.process_filters[0].action, FilterAction::Exclude);
        assert!(app.process_filters[0].enabled);
        assert_eq!(
            app.process_filters[0].expression,
            "path~^/System/Library/original$"
        );
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let output = buffer_text(&terminal);
        assert!(output.contains("process filters"));
        assert!(output.contains("path~^/System/Library/original$"));

        app.on_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(!app.process_filters[0].enabled);
        app.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(app.filter_editor.is_some());
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(
            app.filter_editor.as_ref().unwrap().action,
            FilterAction::Include
        );
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(app.process_filters.is_empty());

        app.on_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        let backend = TestBackend::new(132, 26);
        let mut chinese_terminal = Terminal::new(backend).unwrap();
        chinese_terminal
            .draw(|frame| draw(frame, &mut app))
            .unwrap();
        assert!(
            buffer_text(&chinese_terminal)
                .replace(' ', "")
                .contains("进程过滤器")
        );
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
    fn memory_context_overlay_renders_scrolls_and_closes() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.memory_context = Some(MemoryContextPanel {
            pid: current_pid,
            name: "worker".into(),
            content: [
                "PSMORE PROCESS MEMORY",
                "process worker [42]  user deploy  state Run  identity verified",
                "collection complete  sources 3/3",
                "sampled RSS 640 MiB  precise RSS 638 MiB  PSS 600 MiB  footprint unknown  virtual 2.00 GiB",
                "anonymous 600 MiB  file 38 MiB  shmem 0 B  private 610 MiB  shared 28 MiB  swap 64 MiB  locked 0 B",
                "ATTENTION",
                "  WARN memory.swap_present              64 MiB is swapped",
                "MEMORY CATEGORIES  returned 2/2",
                "  heap                              1.00 GiB      unknown      unknown      unknown       20",
            ]
            .join("\n"),
            report: Some(serde_json::json!({"schema": "psmore.process-memory"})),
            warning: None,
        });
        let backend = TestBackend::new(130, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let output = buffer_text(&terminal);
        assert!(output.contains(&format!("memory worker [{current_pid}]")));
        assert!(output.contains("memory.swap_present"));
        assert!(output.contains("MEMORY CATEGORIES"));

        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.memory_context_scroll, 1);
        app.on_key(KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE));
        assert!(app.memory_context.is_none());
        assert!(!app.memory_context_is_scanning());
    }

    #[test]
    fn memory_key_opens_context_for_the_selected_process() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == current_pid)
            .expect("current test process should be visible");

        app.on_key(KeyEvent::new(KeyCode::Char('M'), KeyModifiers::NONE));
        let panel = app
            .memory_context
            .as_ref()
            .expect("M should open process memory context");
        assert_eq!(panel.pid, current_pid);
        assert!(app.memory_context_is_scanning());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.memory_context.is_none());
        assert!(!app.memory_context_is_scanning());
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
    fn typing_digits_locates_an_exact_pid_and_restores_the_full_tree() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let current_pid = sysinfo::get_current_pid().unwrap();
        let current_pid_text = current_pid.to_string();

        for digit in current_pid_text.chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(digit), KeyModifiers::NONE));
        }
        assert_eq!(app.pid_input.as_deref(), Some(current_pid_text.as_str()));

        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(buffer_text(&terminal).contains("locate PID:"));

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.pid_input.is_none());
        assert!(app.search.is_empty());
        assert_eq!(app.selected_pid(), Some(current_pid));
        assert!(app.visible.iter().any(|row| row.pid == current_pid));
    }

    #[test]
    fn search_editing_treats_j_and_k_as_text_not_process_shortcuts() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let visible_before: Vec<Pid> = app.visible.iter().map(|row| row.pid).collect();
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "jdk".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }

        assert!(app.searching);
        assert_eq!(app.search_input, "jdk");
        assert!(app.search.is_empty());
        assert_eq!(
            app.visible.iter().map(|row| row.pid).collect::<Vec<_>>(),
            visible_before
        );
        assert!(app.process_action.is_none());

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!app.searching);
        assert!(app.search_input.is_empty());
        assert_eq!(app.search, "jdk");
        assert!(app.process_action.is_none());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.search.is_empty());
    }

    #[test]
    fn missing_pid_stays_editable_until_cancelled() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        for digit in u32::MAX.to_string().chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(digit), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.pid_input.is_some());
        assert!(
            app.pid_input_error
                .as_deref()
                .is_some_and(|error| error.contains("not visible"))
        );

        app.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(app.pid_input_error.is_none());
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.pid_input.is_none());
    }

    #[test]
    fn kill_key_requires_second_confirmation_before_sending_a_signal() {
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn isolated target process");
        let mut child = ChildGuard(child);
        let pid = Pid::from_u32(child.0.id());
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.refresh();
        let visible_before: Vec<Pid> = app.visible.iter().map(|row| row.pid).collect();
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in format!("pid:{pid}").chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        assert!(app.search.is_empty());
        assert_eq!(
            app.visible.iter().map(|row| row.pid).collect::<Vec<_>>(),
            visible_before
        );
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.selected_pid(), Some(pid));
        assert!(!app.searching);

        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        let dialog = app.process_action.as_ref().expect("k should open a dialog");
        assert!(dialog.is_termination_only());
        assert_eq!(dialog.actions(), &ProcessActionKind::TERMINATION);
        assert_eq!(dialog.selected_action(), ProcessActionKind::Terminate);
        assert!(!dialog.confirming);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.process_action.as_ref().unwrap().confirming);
        assert!(child.0.try_wait().expect("check child").is_none());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        let dialog = app.process_action.as_ref().unwrap();
        assert_eq!(dialog.selected_action(), ProcessActionKind::Kill);
        assert!(dialog.confirming);
        assert!(child.0.try_wait().expect("check child again").is_none());

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.process_action.is_none());
        assert!(app.action_history.is_empty());

        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(child.0.try_wait().expect("check before y").is_none());
        app.on_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(app.process_action.is_none());
        assert_eq!(app.action_history.len(), 1);
        assert_eq!(app.action_history[0].outcome, ProcessActionOutcome::Sent);
        let exited = (0..50).any(|_| {
            if child
                .0
                .try_wait()
                .expect("check confirmed target")
                .is_some()
            {
                true
            } else {
                thread::sleep(Duration::from_millis(10));
                false
            }
        });
        assert!(exited, "confirmed TERM did not stop the isolated target");
    }

    #[test]
    fn zero_sized_terminal_does_not_panic() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let backend = TestBackend::new(0, 0);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    }
}
