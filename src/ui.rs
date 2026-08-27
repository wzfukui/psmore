use std::{collections::VecDeque, time::Duration};

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span, Text},
    widgets::block::Title,
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Sparkline, Wrap},
};
use sysinfo::Pid;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::{
    actions::{ProcessActionKind, ProcessActionOutcome, ProcessActionRecord},
    app::{App, InspectionTab},
    cli::{LogPriority, LogScope},
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
    theme::{GlyphMode, Glyphs, Theme},
};

/// Border set for the ASCII glyph fallback: plain `-`, `|`, `+` instead of
/// Unicode line symbols, so every block edge stays pure ASCII.
const ASCII_BORDERS: symbols::border::Set = symbols::border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

/// Sparkline bars for the ASCII glyph fallback: a `.`/`:`/`=`/`#` ramp
/// instead of the Unicode eighth-block levels.
const ASCII_BARS: symbols::bar::Set = symbols::bar::Set {
    full: "#",
    seven_eighths: "#",
    three_quarters: "=",
    five_eighths: "=",
    half: ":",
    three_eighths: ":",
    one_quarter: ".",
    one_eighth: ".",
    empty: " ",
};

/// Swap a block's border set for the ASCII one when the glyph fallback is
/// active; Unicode mode keeps ratatui's default line symbols untouched.
fn glyph_block(block: Block<'_>, mode: GlyphMode) -> Block<'_> {
    match mode {
        GlyphMode::Ascii => block.border_set(ASCII_BORDERS),
        GlyphMode::Unicode => block,
    }
}

/// The sparkline bar set for the active glyph repertoire.
fn sparkline_bars(mode: GlyphMode) -> symbols::bar::Set {
    match mode {
        GlyphMode::Ascii => ASCII_BARS,
        GlyphMode::Unicode => symbols::bar::NINE_LEVELS,
    }
}

/// Translate decorative Unicode chrome (box-drawing separators, arrows,
/// markers) in titles and hint bars to ASCII when the glyph fallback is
/// active. Unicode mode returns the text unchanged.
fn chrome(mode: GlyphMode, text: String) -> String {
    if mode != GlyphMode::Ascii {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '│' | '┃' => out.push('|'),
            '─' | '━' => out.push('-'),
            '┌' | '┐' | '└' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' => out.push('+'),
            '→' => out.push_str("->"),
            '←' => out.push_str("<-"),
            '↑' => out.push('^'),
            '↓' => out.push('v'),
            '↪' => out.push('>'),
            '·' | '•' => out.push('.'),
            '▾' => out.push('v'),
            '▸' => out.push('>'),
            '●' => out.push('*'),
            '○' => out.push('o'),
            '×' => out.push('x'),
            '▲' => out.push('!'),
            '✓' => out.push('+'),
            '★' => out.push('*'),
            _ => out.push(c),
        }
    }
    out
}

fn row_label_and_context(app: &App, row: &TreeRow) -> (String, String) {
    let p = &app.processes[&row.pid];
    let glyphs = &app.glyphs;
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
            glyphs.expand_open
        } else {
            glyphs.expand_closed
        }
    } else {
        glyphs.expand_leaf
    };
    let mut prefix = String::new();
    for is_last in row
        .last_path
        .iter()
        .skip(1)
        .take(row.depth.saturating_sub(1))
    {
        prefix.push_str(if *is_last { "  " } else { glyphs.tree_vertical });
    }
    if row.depth > 0 {
        prefix.push_str(if row.is_last {
            glyphs.tree_last
        } else {
            glyphs.tree_branch
        });
    }
    let context = process_path(p);
    let name = if child_count > 0 && !app.expanded.contains(&row.pid) {
        format!("{} ({})", p.name, child_count)
    } else {
        p.name.clone()
    };
    // The star sits between the expand marker and the name; its width is part
    // of the label, so the path-column math below stays correct.
    let star = if app.is_starred(row.pid) {
        format!("{} ", glyphs.star)
    } else {
        String::new()
    };
    (
        format!("{}{} {}{}  [{}]", prefix, marker, star, name, row.pid),
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

fn wrap_text_lines(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![String::new()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut used = 0usize;

    for ch in text.chars() {
        let char_width = ch.width().unwrap_or(1);
        if !current.is_empty() && used.saturating_add(char_width) > width {
            lines.push(current);
            current = String::new();
            used = 0;
        }
        current.push(ch);
        used = used.saturating_add(char_width);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn selected_process_detail_lines(app: &App, language: UiLanguage, width: usize) -> Vec<String> {
    let pid = match app.selected_pid() {
        Some(pid) => pid,
        None => {
            return vec![text(language, "No processes found", "没有找到进程").to_string()];
        }
    };
    let Some(p) = app.processes.get(&pid) else {
        return vec![text(language, "No processes found", "没有找到进程").to_string()];
    };
    let command = process_command_line(p);
    let children = app.children.get(&Some(pid)).map(|c| c.len()).unwrap_or(0);
    let subtree = app.resources.get(&pid).copied().unwrap_or_default();

    let self_summary = format!(
        "PID {}  PPID {}  {} {}  {} {}  CPU {:.1}%  {} {} MB  {} {}  {} {}  {} {}s",
        pid,
        p.parent
            .map(|parent| parent.to_string())
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
    );
    let tree_summary = format!(
        "{} {} {} ({})  CPU {:.1}%  {} {} MB  {} {}  {} {}",
        text(language, "TREE", "子树"),
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
    );

    let merged_line = format!("{self_summary}  |  {tree_summary}");
    let mut lines = if width == 0 || merged_line.width() <= width {
        vec![merged_line]
    } else {
        vec![self_summary, tree_summary]
    };
    lines.extend(wrap_text_lines(&command, width));
    lines
}

fn detail_height(app: &App, area: ratatui::layout::Rect) -> u16 {
    let Some(pid) = app.selected_pid() else {
        return 4;
    };
    if !app.processes.contains_key(&pid) {
        return 4;
    }
    let width = area.width.saturating_sub(2).max(1) as usize;
    let language = app.language();
    let lines = selected_process_detail_lines(app, language, width);
    let content_lines: usize = lines.iter().map(|line| wrapped_lines(line, width)).sum();
    let desired = (content_lines + 2).max(4) as u16;
    desired.min(area.height.saturating_sub(5).max(4))
}

fn parent_label(parent: Option<Pid>) -> String {
    parent
        .map(|pid| pid.to_string())
        .unwrap_or_else(|| "-".into())
}

fn event_line(
    language: UiLanguage,
    event: &ProcessEvent,
    theme: &Theme,
    glyphs: &Glyphs,
) -> Line<'static> {
    let age = event.observed_at.elapsed().as_secs();
    let (color, content) = match &event.change {
        ProcessChange::Started {
            pid, name, parent, ..
        } => (
            theme.started_fg,
            format!(
                "{:>4}s  + {} [{}]  {} {}",
                age,
                name,
                pid,
                text(language, "parent", "父"),
                parent_label(*parent)
            ),
        ),
        ProcessChange::Exited { pid, name, .. } => (
            theme.severity_crit,
            format!("{:>4}s  - {} [{}]", age, name, pid),
        ),
        ProcessChange::Reparented {
            pid,
            name,
            old_parent,
            new_parent,
            ..
        } => (
            theme.reparented_fg,
            format!(
                "{:>4}s  {} {} [{}]  {} {} {}",
                age,
                glyphs.reparent,
                name,
                pid,
                parent_label(*old_parent),
                glyphs.arrow_right,
                parent_label(*new_parent)
            ),
        ),
    };
    Line::from(Span::styled(content, Style::default().fg(color)))
}

fn action_outcome_label(language: UiLanguage, outcome: &ProcessActionOutcome) -> &'static str {
    match (language, outcome) {
        (UiLanguage::English, _) => outcome.label(),
        (UiLanguage::Chinese, ProcessActionOutcome::Sent) => "已发送",
        (UiLanguage::Chinese, ProcessActionOutcome::Refused(_)) => "已拒绝",
        (UiLanguage::Chinese, ProcessActionOutcome::Failed(_)) => "失败",
    }
}

fn action_line(
    language: UiLanguage,
    record: &ProcessActionRecord,
    theme: &Theme,
    glyphs: &Glyphs,
    mode: GlyphMode,
) -> Line<'static> {
    let age = record.observed_at.elapsed().as_secs();
    let (color, marker) = match &record.outcome {
        ProcessActionOutcome::Sent => (theme.severity_info, glyphs.ok),
        ProcessActionOutcome::Refused(_) => (Color::LightYellow, "!"),
        ProcessActionOutcome::Failed(_) => (theme.severity_crit, "×"),
    };
    let detail = record
        .outcome
        .detail()
        .map(|detail| format!("  {detail}"))
        .unwrap_or_default();
    Line::from(Span::styled(
        chrome(
            mode,
            format!(
                "{:>4}s  {marker} {} {} [{}]  {}{}",
                age,
                record.action.label(),
                record.target.name,
                record.target.pid,
                action_outcome_label(language, &record.outcome),
                detail
            ),
        ),
        Style::default().fg(color),
    ))
}

fn draw_event_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let language = app.language();
    let theme = &app.theme;
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
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        let action_limit = line_limit.saturating_sub(1).min(5);
        lines.extend(
            app.action_history
                .iter()
                .rev()
                .take(action_limit)
                .map(|record| action_line(language, record, theme, &app.glyphs, app.glyph_mode)),
        );
    }
    if !app.events.is_empty() && lines.len() < line_limit {
        lines.push(Line::from(Span::styled(
            text(language, " PROCESS CHANGES", " 进程变化"),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )));
        let remaining = line_limit.saturating_sub(lines.len());
        lines.extend(
            app.events
                .iter()
                .rev()
                .take(remaining)
                .map(|event| event_line(language, event, theme, &app.glyphs)),
        );
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
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
    let theme = &app.theme;
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("{} [{}]", target.name, target.pid),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {} {}",
                text(language, "started", "启动于"),
                target.start_time
            )),
        ]),
        Line::from(Span::styled(
            marquee(&target.command, 0, width.saturating_sub(4).max(1) as usize),
            Style::default().fg(theme.dim),
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
                Style::default().fg(theme.severity_crit),
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
                Span::raw(chrome(
                    app.glyph_mode,
                    text(
                        language,
                        "  ·  Esc returns without changing the process",
                        "  ·  Esc 返回且不改变进程",
                    )
                    .to_string(),
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
            let marker = if index == dialog.selected {
                app.glyphs.expand_closed
            } else {
                " "
            };
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
                Style::default().fg(theme.dim),
            )),
        ]);
    }
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
    let theme = &app.theme;
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
                            theme.severity_info
                        } else {
                            theme.severity_crit
                        })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{}{}", editor.input, app.glyphs.cursor)),
            ]),
            Line::from(""),
            Line::from(chrome(
                app.glyph_mode,
                text(
                    language,
                    " Text: path:/System/Library  ·  combined: path:/opt name:python",
                    " 文本：path:/System/Library  ·  组合：path:/opt name:python",
                )
                .to_string(),
            )),
            Line::from(text(
                language,
                r" Regex: path~^/Applications/(ChatGPT|Otty)\.app/  (case-sensitive; (?i) supported)",
                r" 正则：path~^/Applications/(ChatGPT|Otty)\.app/（区分大小写；支持 (?i)）",
            )),
            Line::from(chrome(
                app.glyph_mode,
                text(
                    language,
                    " Spaces: path:\"/Applications/Google Chrome.app\"  ·  fields: any/name/cmd/path/user/state",
                    " 空格：path:\"/Applications/Google Chrome.app\"  ·  字段：any/name/cmd/path/user/state",
                )
                .to_string(),
            )),
        ];
        if let Some(error) = &editor.error {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(" {}: {error}", text(language, "error", "错误")),
                Style::default().fg(theme.severity_crit),
            )));
        }
        frame.render_widget(
            Paragraph::new(lines)
                .block(glyph_block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(chrome(app.glyph_mode, title)),
                    app.glyph_mode,
                ))
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
            .style(Style::default().fg(theme.dim)),
        ]
    } else {
        app.process_filters
            .iter()
            .enumerate()
            .map(|(index, rule)| {
                let enabled = if rule.enabled {
                    app.glyphs.filter_on
                } else {
                    app.glyphs.filter_off
                };
                let style = if rule.enabled {
                    Style::default().fg(if rule.action == FilterAction::Include {
                        theme.severity_info
                    } else {
                        theme.severity_crit
                    })
                } else {
                    Style::default().fg(theme.dim)
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
        .block(glyph_block(
            Block::default()
                .borders(Borders::ALL)
                .title(chrome(app.glyph_mode, title)),
            app.glyph_mode,
        ))
        .highlight_style(theme.selection());
    let mut state = ListState::default();
    if !app.process_filters.is_empty() {
        state.select(Some(app.filter_selected));
    }
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let error_style = if app.filter_error.is_some() {
        Style::default().fg(theme.severity_crit)
    } else {
        Style::default().fg(theme.dim)
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
            Line::from(chrome(
                app.glyph_mode,
                text(
                    language,
                    " a allow  x deny  Enter/e edit  Space enable  d delete  ↑↓ move  F/Esc close",
                    " a 包含  x 排除  Enter/e 编辑  Space 启停  d 删除  ↑↓ 移动  F/Esc 关闭",
                )
                .to_string(),
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

fn draw_palette_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let language = app.language();
    let theme = &app.theme;
    let width = area.width.saturating_sub(2).clamp(1, 72);
    let height = area.height.saturating_sub(2).clamp(1, 16);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    frame.render_widget(Clear, popup);
    let block = glyph_block(
        Block::default().borders(Borders::ALL).title(text(
            language,
            " command palette ",
            " 命令面板 ",
        )),
        app.glyph_mode,
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let chunks = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .split(inner);

    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(":", Style::default().fg(Color::LightCyan)),
            Span::raw(format!("{}{}", app.palette_query, app.glyphs.cursor)),
        ])),
        chunks[0],
    );

    let matches = app.palette_matches();
    let inner_width = chunks[1].width as usize;
    let visible_rows = chunks[1].height as usize;
    let selected = app.palette_selected.min(matches.len().saturating_sub(1));
    let start = if selected < visible_rows {
        0
    } else {
        selected - visible_rows + 1
    };
    let lines: Vec<Line> = if matches.is_empty() {
        vec![Line::from(Span::styled(
            text(language, " no matching commands ", " 无匹配命令 "),
            Style::default().fg(theme.dim),
        ))]
    } else {
        // Descriptions need room to be useful; below ~50 columns the row is
        // just the command name and its key hint.
        let show_description = inner_width >= 50;
        matches
            .iter()
            .enumerate()
            .skip(start)
            .take(visible_rows)
            .map(|(index, command)| {
                let name = text(language, command.en_name, command.zh_name);
                let mut row = format!(" {name}");
                row.push_str(&" ".repeat(22_usize.saturating_sub(name.width())));
                let hint = command.key_hint;
                if show_description {
                    // The right-aligned hint always keeps one column of gap;
                    // the description is clipped by display width to fit.
                    let description =
                        text(language, command.en_description, command.zh_description);
                    let budget = inner_width.saturating_sub(row.width() + hint.width() + 2);
                    let mut used = 0;
                    for character in description.chars() {
                        let width = character.width().unwrap_or(0);
                        if used + width > budget {
                            break;
                        }
                        used += width;
                        row.push(character);
                    }
                }
                let gap = inner_width.saturating_sub(row.width() + hint.width() + 1);
                row.push_str(&" ".repeat(gap));
                row.push_str(hint);
                let style = if index == selected {
                    theme.selection()
                } else {
                    Style::default().fg(theme.tree_fg)
                };
                Line::from(Span::styled(row, style))
            })
            .collect()
    };
    frame.render_widget(Paragraph::new(lines), chunks[1]);

    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            chrome(
                app.glyph_mode,
                format!(
                    " {} ",
                    text(
                        language,
                        "↑↓ select · Enter run · Esc close",
                        "↑↓ 选择 · Enter 执行 · Esc 关闭",
                    )
                ),
            ),
            Style::default().fg(theme.dim),
        ))),
        chunks[2],
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

fn push_thread_lines(
    lines: &mut Vec<Line<'static>>,
    inspection: &ProcessInspection,
    language: UiLanguage,
) {
    let sampling = if inspection.thread_sample_ms > 0 {
        match language {
            UiLanguage::English => format!("{}ms sample", inspection.thread_sample_ms),
            UiLanguage::Chinese => format!("{}ms 采样", inspection.thread_sample_ms),
        }
    } else {
        text(language, "scheduler estimate", "调度器估值").into()
    };
    lines.push(Line::from(Span::styled(
        match language {
            UiLanguage::English => format!(
                "HOT THREADS (showing {}/{}; {sampling})",
                inspection.threads.len(),
                inspection.thread_count
            ),
            UiLanguage::Chinese => format!(
                "热点线程（显示 {}/{}；{sampling}）",
                inspection.threads.len(),
                inspection.thread_count
            ),
        },
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
            text(
                language,
                "  No thread details visible",
                "  暂无可见线程详情",
            ),
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

fn inspection_lines(
    inspection: &ProcessInspection,
    tab: InspectionTab,
    language: UiLanguage,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(warning) = &inspection.warning {
        lines.push(Line::from(Span::styled(
            format!("WARNING  {warning}"),
            Style::default().fg(Color::LightRed),
        )));
        lines.push(Line::from(""));
    }

    match tab {
        InspectionTab::Overview => {
            lines.push(Line::from(vec![
                Span::styled(
                    text(language, "USER ", "用户 "),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(inspection.user.clone()),
            ]));
            lines.push(Line::from(vec![
                Span::styled(
                    text(language, "CWD  ", "目录 "),
                    Style::default().fg(Color::Cyan),
                ),
                Span::raw(inspection.cwd.clone()),
            ]));
            push_inspection_fields(
                &mut lines,
                text(language, "RUNTIME CONTEXT", "运行上下文"),
                &inspection.runtime,
            );
            push_inspection_fields(
                &mut lines,
                text(language, "SECURITY", "安全上下文"),
                &inspection.security,
            );
            push_inspection_fields(
                &mut lines,
                text(language, "NAMESPACES", "命名空间"),
                &inspection.namespaces,
            );
            push_inspection_fields(
                &mut lines,
                text(language, "RESOURCE LIMITS", "资源限制"),
                &inspection.limits,
            );
        }
        InspectionTab::Threads => push_thread_lines(&mut lines, inspection, language),
        InspectionTab::Ports => {
            lines.push(Line::from(Span::styled(
                match language {
                    UiLanguage::English => {
                        format!("PORTS & CONNECTIONS ({})", inspection.sockets.len())
                    }
                    UiLanguage::Chinese => {
                        format!("端口与连接（{}）", inspection.sockets.len())
                    }
                },
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )));
            if inspection.sockets.is_empty() {
                lines.push(Line::from(Span::styled(
                    text(language, "  No sockets visible", "  暂无可见端口或连接"),
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
        }
        InspectionTab::Files => {
            lines.push(Line::from(Span::styled(
                match language {
                    UiLanguage::English => {
                        format!("OPEN FILE DESCRIPTORS ({})", inspection.files.len())
                    }
                    UiLanguage::Chinese => {
                        format!("打开的文件描述符（{}）", inspection.files.len())
                    }
                },
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            )));
            if inspection.files.is_empty() {
                lines.push(Line::from(Span::styled(
                    text(
                        language,
                        "  No file descriptors visible",
                        "  暂无可见文件描述符",
                    ),
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
        }
    }
    lines
}

/// The full tab labels with live counts, independent of width.
fn inspection_full_labels(inspection: &ProcessInspection, language: UiLanguage) -> [String; 4] {
    [
        text(language, "Overview", "概览").to_string(),
        format!(
            "{} {}",
            text(language, "Threads", "线程"),
            inspection.thread_count
        ),
        format!(
            "{} {}",
            text(language, "Ports", "端口"),
            inspection.sockets.len()
        ),
        format!(
            "{} {}",
            text(language, "Files", "文件"),
            inspection.files.len()
        ),
    ]
}

/// Display width of a rendered tab bar: each label padded by one cell on
/// both sides, joined by three-cell separators. CJK labels are double-width,
/// so this must be measured, not assumed.
fn inspection_tab_bar_width(labels: &[String]) -> usize {
    labels.iter().map(|label| label.width() + 2).sum::<usize>() + labels.len().saturating_sub(1) * 3
}

/// The visible tab labels for the current width, or `None` when the terminal
/// is so narrow that only the active tab is shown (no clickable tab bar).
/// Full labels are preferred from 58 columns up, compact below that, but a
/// set is only used when its measured width actually fits; oversized
/// count-bearing labels degrade gracefully instead of clipping.
fn inspection_tab_labels(
    inspection: &ProcessInspection,
    language: UiLanguage,
    available_width: u16,
) -> Option<Vec<String>> {
    let full_labels = inspection_full_labels(inspection, language);
    let compact_labels = [
        text(language, "Info", "概览").to_string(),
        text(language, "Thr", "线程").to_string(),
        text(language, "Net", "端口").to_string(),
        text(language, "File", "文件").to_string(),
    ];
    let available_width = usize::from(available_width);
    if available_width >= 58 && inspection_tab_bar_width(&full_labels) <= available_width {
        return Some(full_labels.into());
    }
    if inspection_tab_bar_width(&compact_labels) <= available_width {
        return Some(compact_labels.into());
    }
    None
}

fn inspection_tabs_line(
    inspection: &ProcessInspection,
    active: InspectionTab,
    language: UiLanguage,
    available_width: u16,
    theme: &Theme,
    mode: GlyphMode,
) -> Line<'static> {
    let Some(labels) = inspection_tab_labels(inspection, language, available_width) else {
        let active_label = inspection_full_labels(inspection, language);
        return Line::from(vec![
            Span::styled(
                format!(" {}/4 ", active.index() + 1),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                active_label[active.index()].clone(),
                Style::default()
                    .fg(Color::LightCyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                chrome(mode, " · Tab →".to_string()),
                Style::default().fg(theme.dim),
            ),
        ]);
    };
    let mut spans = Vec::new();
    for (index, label) in labels.into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(
                chrome(mode, " │ ".to_string()),
                Style::default().fg(theme.dim),
            ));
        }
        let style = if index == active.index() {
            Style::default()
                .fg(Color::Black)
                .bg(Color::LightCyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.muted)
        };
        spans.push(Span::styled(format!(" {label} "), style));
    }
    Line::from(spans)
}

fn draw_inspection_overlay(frame: &mut Frame, app: &mut App, area: Rect, tree_area: Rect) {
    let Some(inspection) = &app.inspection else {
        return;
    };
    let width = area.width.saturating_sub(2).clamp(1, 140);
    // On tall terminals the popup hugs the process-tree block so its bottom
    // border never dips into the selected-process pane below; on cramped
    // ones keep the legacy full-height layout so content still fits.
    let (popup_y, popup_height) = if area.height >= 20 {
        (tree_area.y, tree_area.height.max(1))
    } else {
        let height = area.height.saturating_sub(2).max(1);
        (area.y + area.height.saturating_sub(height) / 2, height)
    };
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        popup_y,
        width,
        popup_height,
    );
    let language = app.language();
    let active_tab = app.inspection_tab;
    let theme = app.theme;
    let mut lines = inspection_lines(inspection, active_tab, language);
    let inspection_status = if app.inspection_is_scanning() {
        let elapsed = app.inspection_elapsed();
        lines.insert(0, Line::from(""));
        lines.insert(
            0,
            Line::from(Span::styled(
                match language {
                    UiLanguage::English => format!(
                        " {} collecting process context in the background ({:.1}s)",
                        activity_spinner(elapsed, &app.glyphs),
                        elapsed.as_secs_f64()
                    ),
                    UiLanguage::Chinese => format!(
                        " {} 正在后台采集进程上下文（{:.1}s）",
                        activity_spinner(elapsed, &app.glyphs),
                        elapsed.as_secs_f64()
                    ),
                },
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )),
        );
        text(language, "  scanning", "  采集中")
    } else {
        ""
    };
    let title = match language {
        UiLanguage::English => format!(
            " inspect {} [{}]{} ",
            inspection.name, inspection.pid, inspection_status
        ),
        UiLanguage::Chinese => format!(
            " 深度检查 {} [{}]{} ",
            inspection.name, inspection.pid, inspection_status
        ),
    };
    frame.render_widget(Clear, popup);
    let block = glyph_block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border_focused))
            .title(title),
        app.glyph_mode,
    );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(inspection_tabs_line(
            inspection,
            active_tab,
            language,
            sections[0].width,
            &theme,
            app.glyph_mode,
        )),
        sections[0],
    );
    // Record each tab label's clickable region (label plus its padding,
    // excluding the separators) for mouse tab switching, clipped to the
    // tab-bar rect actually on screen.
    app.inspection_tab_regions.clear();
    if let Some(labels) = inspection_tab_labels(inspection, language, sections[0].width) {
        let bar_end = sections[0].x.saturating_add(sections[0].width);
        let mut x = sections[0].x;
        for (index, label) in labels.iter().enumerate() {
            if index > 0 {
                x = x.saturating_add(3);
            }
            let width = label.width() as u16 + 2;
            let clipped = width.min(bar_end.saturating_sub(x));
            if clipped > 0 {
                if let Some(tab) = InspectionTab::from_index(index) {
                    app.inspection_tab_regions
                        .push((Rect::new(x, sections[0].y, clipped, 1), tab));
                }
            }
            x = x.saturating_add(width);
        }
    }
    let content_height = sections[1].height as usize;
    let content_width = sections[1].width.max(1) as usize;
    let visual_lines = lines
        .iter()
        .map(|line| line.width().max(1).div_ceil(content_width))
        .sum::<usize>();
    let max_scroll = visual_lines
        .saturating_sub(content_height)
        .min(u16::MAX as usize) as u16;
    app.inspection_scroll = app.inspection_scroll.min(max_scroll);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.inspection_scroll, 0))
            .wrap(Wrap { trim: false }),
        sections[1],
    );
    frame.render_widget(
        Paragraph::new(chrome(
            app.glyph_mode,
            text(
                language,
                " Tab/←→ card · ↑↓ scroll · Enter/r refresh · M memory · D dossier · Esc close",
                " Tab/←→ 切换卡片 · ↑↓ 滚动 · Enter/r 刷新 · M 内存 · D 档案 · Esc 关闭",
            )
            .to_string(),
        ))
        .style(Style::default().fg(theme.dim)),
        sections[2],
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
                    activity_spinner(elapsed, &app.glyphs),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在并行采集进程档案（{:.1}s）",
                    activity_spinner(elapsed, &app.glyphs),
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
            Style::default().fg(app.theme.tree_fg)
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
        match language {
            UiLanguage::English => format!(
                "logs on {} <= {} {}",
                log_scope_label(language, panel.scope),
                log_priority_label(language, panel.priority),
                compact_duration(panel.since_seconds)
            ),
            UiLanguage::Chinese => format!(
                "日志开 {} <= {} {}",
                log_scope_label(language, panel.scope),
                log_priority_label(language, panel.priority),
                compact_duration(panel.since_seconds)
            ),
        }
    } else {
        text(language, "logs off", "日志关").into()
    };
    let hash = if panel.hash {
        text(language, "hash on", "哈希开")
    } else {
        text(language, "hash off", "哈希关")
    };
    let title = match language {
        UiLanguage::English => format!(
            " dossier {} [{}]{}  {}  {}  r refresh  s/p/w logs  h hash  g logs  i/M/m/v/l evidence  D/Esc close ",
            panel.name, panel.pid, scanning, logs, hash
        ),
        UiLanguage::Chinese => format!(
            " 进程档案 {} [{}]{}  {}  {}  r 刷新  s/p/w 日志  h 哈希  g 日志开关  i/M/m/v/l 证据  D/Esc 关闭 ",
            panel.name, panel.pid, scanning, logs, hash
        ),
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
                    activity_spinner(elapsed, &app.glyphs),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台归因进程内存（{:.1}s）",
                    activity_spinner(elapsed, &app.glyphs),
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
            Style::default().fg(app.theme.tree_fg)
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
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
                    activity_spinner(elapsed, &app.glyphs),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台解析 systemd/launchd 归属（{:.1}s）",
                    activity_spinner(elapsed, &app.glyphs),
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
            Style::default().fg(app.theme.tree_fg)
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
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
                    activity_spinner(elapsed, &app.glyphs),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台验证运行映像及来源（{:.1}s）",
                    activity_spinner(elapsed, &app.glyphs),
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
            Style::default().fg(app.theme.tree_fg)
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
    let hash = if panel.hash {
        text(language, "hash on", "哈希开")
    } else {
        text(language, "hash off", "哈希关")
    };
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
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
                    activity_spinner(elapsed, &app.glyphs),
                    elapsed.as_secs_f64()
                ),
                UiLanguage::Chinese => format!(
                    " {} 正在后台读取有界原生日志（{:.1}s）",
                    activity_spinner(elapsed, &app.glyphs),
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
            Style::default().fg(app.theme.tree_fg)
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
            log_scope_label(language, panel.scope),
            log_priority_label(language, panel.priority),
            compact_duration(panel.since_seconds),
        ),
        UiLanguage::Chinese => format!(
            " 日志 {} [{}]{}  范围 {}  <= {}  {}  r 刷新  s 范围  p 等级  w 窗口  M 内存  D 档案  m/v 上下文  l/Esc 关闭 ",
            panel.name,
            panel.pid,
            scanning,
            log_scope_label(language, panel.scope),
            log_priority_label(language, panel.priority),
            compact_duration(panel.since_seconds),
        ),
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
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
    let block = glyph_block(
        Block::default().borders(Borders::ALL).title(title),
        app.glyph_mode,
    );
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
            Paragraph::new(text(
                language,
                "enlarge terminal for charts",
                "放大终端以显示图表",
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
            Line::from(match language {
                UiLanguage::English => format!(
                    " {} samples / {}s window | subtree {} proc | newest at right",
                    samples.len(),
                    window,
                    subtree_processes
                ),
                UiLanguage::Chinese => format!(
                    " {} 个样本 / {}s 窗口 | 子树 {} 进程 | 最新在右",
                    samples.len(),
                    window,
                    subtree_processes
                ),
            }),
            Line::from(if app.trend_view == TrendView::Io {
                text(
                    language,
                    " shared I/O scale: read/write and self/tree charts are directly comparable",
                    " 读写共用刻度：读/写与自身/子树图表可直接对比",
                )
            } else {
                text(
                    language,
                    " shared scale per metric: self and tree charts are directly comparable",
                    " 每项指标共用刻度：自身与子树图表可直接对比",
                )
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
            (
                text(language, "READ self", "读 自身"),
                own_read.as_slice(),
                Color::Cyan,
            ),
            (
                text(language, "READ tree", "读 子树"),
                tree_read.as_slice(),
                Color::LightCyan,
            ),
            (
                text(language, "WRITE self", "写 自身"),
                own_write.as_slice(),
                Color::Yellow,
            ),
            (
                text(language, "WRITE tree", "写 子树"),
                tree_write.as_slice(),
                Color::LightRed,
            ),
        ];
        for (index, (label, values, color)) in series.iter().enumerate() {
            let (label, values, color) = (*label, *values, *color);
            let (now, average, maximum) = memory_stats(values);
            let title = match language {
                UiLanguage::English => format!(
                    " {label:<10} now {}  avg {}  max {} ",
                    format_bytes_rate(now),
                    format_bytes_rate(average),
                    format_bytes_rate(maximum)
                ),
                UiLanguage::Chinese => format!(
                    " {label}  当前 {}  均值 {}  峰值 {} ",
                    format_bytes_rate(now),
                    format_bytes_rate(average),
                    format_bytes_rate(maximum)
                ),
            };
            frame.render_widget(
                Sparkline::default()
                    .block(glyph_block(
                        Block::default().borders(Borders::TOP).title(title),
                        app.glyph_mode,
                    ))
                    .data(values)
                    .max(io_scale)
                    .bar_set(sparkline_bars(app.glyph_mode))
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
    let cpu_self_title = match language {
        UiLanguage::English => format!(
            " CPU self   now {own_cpu_now:.1}%  avg {own_cpu_avg:.1}%  max {own_cpu_max:.1}% "
        ),
        UiLanguage::Chinese => format!(
            " CPU 自身  当前 {own_cpu_now:.1}%  均值 {own_cpu_avg:.1}%  峰值 {own_cpu_max:.1}% "
        ),
    };
    frame.render_widget(
        Sparkline::default()
            .block(glyph_block(
                Block::default().borders(Borders::TOP).title(cpu_self_title),
                app.glyph_mode,
            ))
            .data(&own_cpu_data)
            .max(cpu_scale)
            .bar_set(sparkline_bars(app.glyph_mode))
            .style(Style::default().fg(Color::Yellow)),
        chunks[1],
    );
    let cpu_tree_title = match language {
        UiLanguage::English => format!(
            " CPU tree   now {tree_cpu_now:.1}%  avg {tree_cpu_avg:.1}%  max {tree_cpu_max:.1}% "
        ),
        UiLanguage::Chinese => format!(
            " CPU 子树  当前 {tree_cpu_now:.1}%  均值 {tree_cpu_avg:.1}%  峰值 {tree_cpu_max:.1}% "
        ),
    };
    frame.render_widget(
        Sparkline::default()
            .block(glyph_block(
                Block::default().borders(Borders::TOP).title(cpu_tree_title),
                app.glyph_mode,
            ))
            .data(&subtree_cpu_data)
            .max(cpu_scale)
            .bar_set(sparkline_bars(app.glyph_mode))
            .style(Style::default().fg(Color::LightRed)),
        chunks[2],
    );
    let mem_self_title = match language {
        UiLanguage::English => format!(
            " MEM self   now {} MB  avg {} MB  max {} MB ",
            own_mem_now / 1024 / 1024,
            own_mem_avg / 1024 / 1024,
            own_mem_max / 1024 / 1024
        ),
        UiLanguage::Chinese => format!(
            " 内存 自身  当前 {} MB  均值 {} MB  峰值 {} MB ",
            own_mem_now / 1024 / 1024,
            own_mem_avg / 1024 / 1024,
            own_mem_max / 1024 / 1024
        ),
    };
    frame.render_widget(
        Sparkline::default()
            .block(glyph_block(
                Block::default().borders(Borders::TOP).title(mem_self_title),
                app.glyph_mode,
            ))
            .data(&own_memory_data)
            .max(memory_scale)
            .bar_set(sparkline_bars(app.glyph_mode))
            .style(Style::default().fg(Color::Cyan)),
        chunks[3],
    );
    let mem_tree_title = match language {
        UiLanguage::English => format!(
            " MEM tree   now {} MB  avg {} MB  max {} MB ",
            tree_mem_now / 1024 / 1024,
            tree_mem_avg / 1024 / 1024,
            tree_mem_max / 1024 / 1024
        ),
        UiLanguage::Chinese => format!(
            " 内存 子树  当前 {} MB  均值 {} MB  峰值 {} MB ",
            tree_mem_now / 1024 / 1024,
            tree_mem_avg / 1024 / 1024,
            tree_mem_max / 1024 / 1024
        ),
    };
    frame.render_widget(
        Sparkline::default()
            .block(glyph_block(
                Block::default().borders(Borders::TOP).title(mem_tree_title),
                app.glyph_mode,
            ))
            .data(&subtree_memory_data)
            .max(memory_scale)
            .bar_set(sparkline_bars(app.glyph_mode))
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

// Compact human units for the status bar and the tree MEM column, where
// horizontal space is scarce: "512M", "12.1G". Every branch stays within
// five display cells for any input, including u64::MAX ("16E"), so the
// column width math in the tree stays exact.
fn format_compact_bytes(bytes: u64) -> String {
    const EIB: u64 = 1024 * 1024 * 1024 * 1024 * 1024 * 1024;
    const TIB: u64 = 1024 * 1024 * 1024 * 1024;
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= EIB {
        format!("{:.0}E", bytes as f64 / EIB as f64)
    } else if bytes >= 100 * TIB {
        format!("{:.0}T", bytes as f64 / TIB as f64)
    } else if bytes >= 100 * GIB {
        let tib = bytes as f64 / TIB as f64;
        // "{:.1}" can round 99.96 up to "100.0T" (six cells); fall back to
        // the zero-decimal form at the boundary to hold the five-cell cap.
        if tib >= 99.95 {
            format!("{:.0}T", tib)
        } else {
            format!("{:.1}T", tib)
        }
    } else if bytes >= GIB {
        let gib = bytes as f64 / GIB as f64;
        if gib >= 99.95 {
            format!("{:.1}T", bytes as f64 / TIB as f64)
        } else {
            format!("{:.1}G", gib)
        }
    } else if bytes >= MIB {
        format!("{:.0}M", bytes as f64 / MIB as f64)
    } else if bytes >= 1024 {
        format!("{:.0}K", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

fn load_trend_arrow(history: &VecDeque<f64>, glyphs: &Glyphs) -> &'static str {
    if history.len() < 2 {
        return glyphs.trend_flat;
    }
    let first = history.front().copied().unwrap_or(0.0);
    let last = history.back().copied().unwrap_or(0.0);
    let delta = last - first;
    if delta > 0.05 {
        glyphs.trend_up
    } else if delta < -0.05 {
        glyphs.trend_down
    } else {
        glyphs.trend_flat
    }
}

fn draw_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let language = app.language();
    let theme = &app.theme;
    let metrics = &app.host_metrics;
    let label_style = Style::default().fg(theme.accent);
    let findings = app.attention_findings();
    let worst = findings.iter().map(|finding| finding.severity).max();
    let (alert_text, alert_style) = match worst {
        Some(severity) => (
            format!(
                "{} {} {} ",
                app.glyphs.alert,
                findings.len(),
                text(language, "alerts", "条告警")
            ),
            theme.severity_style(severity).add_modifier(Modifier::BOLD),
        ),
        None => (
            format!("{} ", text(language, "✓ ok", "✓ 正常")).replace('✓', app.glyphs.ok),
            Style::default().fg(theme.dim),
        ),
    };
    // The alert count is the most decision-relevant field: reserve its space
    // first, then admit host metrics in priority order while they fit. The
    // hostname identifies the machine, so it is clipped rather than dropped.
    let mut budget = (area.width as usize).saturating_sub(alert_text.width());
    let hostname = if metrics.hostname.is_empty() {
        text(language, "unknown", "未知主机")
    } else {
        metrics.hostname.as_str()
    };
    let host_label = format!(" {hostname}  ");
    let host_width = host_label.width().min(budget);
    let mut spans = vec![Span::styled(
        marquee(&host_label, 0, host_width),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    let mut used = host_width;
    budget = budget.saturating_sub(used);
    let mut segments: Vec<Vec<Span>> = vec![
        vec![
            Span::styled("CPU ", label_style),
            Span::raw(format!("{:.0}%  ", metrics.cpu_percent)),
        ],
        vec![
            Span::styled(text(language, "MEM ", "内存 "), label_style),
            Span::raw(format!(
                "{}/{}  ",
                format_compact_bytes(metrics.memory_used),
                format_compact_bytes(metrics.memory_total)
            )),
        ],
        vec![
            Span::styled(text(language, "load ", "负载 "), label_style),
            Span::raw(format!(
                "{:.2}{}  ",
                metrics.load_one,
                load_trend_arrow(&app.load_history, &app.glyphs)
            )),
        ],
    ];
    if metrics.swap_total > 0 {
        let swap_percent = metrics.swap_used as f64 * 100.0 / metrics.swap_total as f64;
        segments.push(vec![
            Span::styled(text(language, "SWAP ", "交换 "), label_style),
            Span::raw(format!("{swap_percent:.0}%  ")),
        ]);
    }
    for segment in segments {
        let width: usize = segment.iter().map(|span| span.content.width()).sum();
        if width <= budget {
            spans.extend(segment);
            used += width;
            budget -= width;
        }
    }
    let padding = (area.width as usize).saturating_sub(used + alert_text.width());
    spans.push(Span::raw(" ".repeat(padding)));
    spans.push(Span::styled(alert_text, alert_style));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
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

fn log_scope_label(language: UiLanguage, scope: LogScope) -> &'static str {
    match (language, scope) {
        (UiLanguage::English, _) => scope.label(),
        (UiLanguage::Chinese, LogScope::Auto) => "自动",
        (UiLanguage::Chinese, LogScope::Process) => "进程",
        (UiLanguage::Chinese, LogScope::Service) => "服务",
    }
}

fn log_priority_label(language: UiLanguage, priority: LogPriority) -> &'static str {
    match (language, priority) {
        (UiLanguage::English, _) => priority.label(),
        (UiLanguage::Chinese, LogPriority::Error) => "错误",
        (UiLanguage::Chinese, LogPriority::Warning) => "警告",
        (UiLanguage::Chinese, LogPriority::Info) => "信息",
        (UiLanguage::Chinese, LogPriority::Debug) => "调试",
    }
}

fn format_signed_rate(delta: i128) -> String {
    let sign = if delta >= 0 { "+" } else { "-" };
    let value = delta.unsigned_abs().min(u128::from(u64::MAX)) as u64;
    format!("{sign}{}", format_bytes_rate(value))
}

fn snapshot_entry_line(
    language: UiLanguage,
    prefix: &str,
    entry: &ProcessSnapshotEntry,
    color: Color,
) -> Line<'static> {
    let parent = parent_label(entry.parent);
    let command = if entry.command.is_empty() {
        text(language, "[command unavailable]", "[命令不可用]").to_string()
    } else {
        entry.command.clone()
    };
    Line::from(Span::styled(
        match language {
            UiLanguage::English => format!(
                " {prefix} {} [{}] parent {} | tree {} proc {} MB | {}",
                entry.name,
                entry.pid,
                parent,
                entry.subtree.process_count,
                entry.subtree.memory / 1024 / 1024,
                command
            ),
            UiLanguage::Chinese => format!(
                " {prefix} {} [{}] 父 {} | 子树 {} 进程 {} MB | {}",
                entry.name,
                entry.pid,
                parent,
                entry.subtree.process_count,
                entry.subtree.memory / 1024 / 1024,
                command
            ),
        },
        Style::default().fg(color),
    ))
}

fn snapshot_diff_lines(
    language: UiLanguage,
    diff: &SnapshotDiff,
    theme: &Theme,
    glyphs: &Glyphs,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        match language {
            UiLanguage::English => format!(
                "PROCESS CHANGES  +{} started  -{} exited  {}{} reparented",
                diff.started.len(),
                diff.exited.len(),
                glyphs.reparent,
                diff.reparented.len()
            ),
            UiLanguage::Chinese => format!(
                "进程变化  +{} 新增  -{} 退出  {}{} 换父",
                diff.started.len(),
                diff.exited.len(),
                glyphs.reparent,
                diff.reparented.len()
            ),
        },
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    )));
    if diff.started.is_empty() && diff.exited.is_empty() && diff.reparented.is_empty() {
        lines.push(Line::from(Span::styled(
            text(
                language,
                " no process identity or relationship changes",
                " 进程身份与关系均无变化",
            ),
            Style::default().fg(theme.dim),
        )));
    } else {
        for entry in &diff.started {
            lines.push(snapshot_entry_line(language, "+", entry, theme.started_fg));
        }
        for entry in &diff.exited {
            lines.push(snapshot_entry_line(
                language,
                "-",
                entry,
                theme.severity_crit,
            ));
        }
        for entry in &diff.reparented {
            lines.push(Line::from(Span::styled(
                match language {
                    UiLanguage::English => format!(
                        " {} {} [{}] parent {} {} {}",
                        glyphs.reparent,
                        entry.name,
                        entry.pid,
                        parent_label(entry.old_parent),
                        glyphs.arrow_right,
                        parent_label(entry.new_parent)
                    ),
                    UiLanguage::Chinese => format!(
                        " {} {} [{}] 父 {} {} {}",
                        glyphs.reparent,
                        entry.name,
                        entry.pid,
                        parent_label(entry.old_parent),
                        glyphs.arrow_right,
                        parent_label(entry.new_parent)
                    ),
                },
                Style::default().fg(theme.reparented_fg),
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
        match (language, memory_growth_count > 50) {
            (UiLanguage::English, true) => {
                format!("TOP TREE MEMORY GROWTH ({memory_growth_count}, showing 50)")
            }
            (UiLanguage::English, false) => {
                format!("TOP TREE MEMORY GROWTH ({memory_growth_count})")
            }
            (UiLanguage::Chinese, true) => {
                format!("子树内存增长 TOP（{memory_growth_count}，显示前 50）")
            }
            (UiLanguage::Chinese, false) => {
                format!("子树内存增长 TOP（{memory_growth_count}）")
            }
        },
        Style::default()
            .fg(Color::LightMagenta)
            .add_modifier(Modifier::BOLD),
    )));
    if memory_growth.is_empty() {
        lines.push(Line::from(Span::styled(
            text(
                language,
                " no surviving process subtree increased memory",
                " 没有存活进程子树的内存增长",
            ),
            Style::default().fg(theme.dim),
        )));
    } else {
        for delta in memory_growth.into_iter().take(50) {
            lines.push(Line::from(Span::styled(
                match language {
                    UiLanguage::English => format!(
                        " {}  {} [{}] | now {} MB | own {} | children {:+}",
                        format_signed_bytes(delta.subtree_memory),
                        delta.name,
                        delta.pid,
                        delta.current_subtree.memory / 1024 / 1024,
                        format_signed_bytes(delta.own_memory),
                        delta.subtree_processes
                    ),
                    UiLanguage::Chinese => format!(
                        " {}  {} [{}] | 当前 {} MB | 自身 {} | 子进程 {:+}",
                        format_signed_bytes(delta.subtree_memory),
                        delta.name,
                        delta.pid,
                        delta.current_subtree.memory / 1024 / 1024,
                        format_signed_bytes(delta.own_memory),
                        delta.subtree_processes
                    ),
                },
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
        match (language, cpu_growth_count > 50) {
            (UiLanguage::English, true) => {
                format!("TOP TREE CPU INCREASE ({cpu_growth_count}, showing 50)")
            }
            (UiLanguage::English, false) => {
                format!("TOP TREE CPU INCREASE ({cpu_growth_count})")
            }
            (UiLanguage::Chinese, true) => {
                format!("子树 CPU 增长 TOP（{cpu_growth_count}，显示前 50）")
            }
            (UiLanguage::Chinese, false) => {
                format!("子树 CPU 增长 TOP（{cpu_growth_count}）")
            }
        },
        Style::default()
            .fg(Color::LightRed)
            .add_modifier(Modifier::BOLD),
    )));
    if cpu_growth.is_empty() {
        lines.push(Line::from(Span::styled(
            text(
                language,
                " no surviving process subtree increased CPU by more than 0.1%",
                " 没有存活进程子树的 CPU 增幅超过 0.1%",
            ),
            Style::default().fg(theme.dim),
        )));
    } else {
        for delta in cpu_growth.into_iter().take(50) {
            lines.push(Line::from(Span::styled(
                match language {
                    UiLanguage::English => format!(
                        " {:+.1}%  {} [{}] | now {:.1}% | own {:+.1}%",
                        delta.subtree_cpu,
                        delta.name,
                        delta.pid,
                        delta.current_subtree.cpu,
                        delta.own_cpu
                    ),
                    UiLanguage::Chinese => format!(
                        " {:+.1}%  {} [{}] | 当前 {:.1}% | 自身 {:+.1}%",
                        delta.subtree_cpu,
                        delta.name,
                        delta.pid,
                        delta.current_subtree.cpu,
                        delta.own_cpu
                    ),
                },
                Style::default().fg(Color::LightRed),
            )));
        }
    }

    for (title, empty, is_read) in [
        (
            text(
                language,
                "TOP TREE READ RATE INCREASE",
                "子树读速率增长 TOP",
            ),
            text(
                language,
                " no surviving process subtree increased disk reads",
                " 没有存活进程子树的磁盘读增加",
            ),
            true,
        ),
        (
            text(
                language,
                "TOP TREE WRITE RATE INCREASE",
                "子树写速率增长 TOP",
            ),
            text(
                language,
                " no surviving process subtree increased disk writes",
                " 没有存活进程子树的磁盘写增加",
            ),
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
            match (language, count > 50) {
                (UiLanguage::English, true) => format!("{title} ({count}, showing 50)"),
                (UiLanguage::English, false) => format!("{title} ({count})"),
                (UiLanguage::Chinese, true) => format!("{title}（{count}，显示前 50）"),
                (UiLanguage::Chinese, false) => format!("{title}（{count}）"),
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
                Style::default().fg(theme.dim),
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
                    match language {
                        UiLanguage::English => format!(
                            " {}  {} [{}] | now {} | own {}",
                            format_signed_rate(tree_delta),
                            delta.name,
                            delta.pid,
                            format_bytes_rate(current),
                            format_signed_rate(own_delta)
                        ),
                        UiLanguage::Chinese => format!(
                            " {}  {} [{}] | 当前 {} | 自身 {}",
                            format_signed_rate(tree_delta),
                            delta.name,
                            delta.pid,
                            format_bytes_rate(current),
                            format_signed_rate(own_delta)
                        ),
                    },
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
    let lines = snapshot_diff_lines(language, &diff, &app.theme, &app.glyphs);
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
        .map(|delta| match language {
            UiLanguage::English => format!(
                "system ΔCPU {:+.1}% ΔMEM {} ΔR {} ΔW {} proc {:+}",
                delta.subtree_cpu,
                format_signed_bytes(delta.subtree_memory),
                format_signed_rate(delta.subtree_read_rate),
                format_signed_rate(delta.subtree_write_rate),
                delta.subtree_processes
            ),
            UiLanguage::Chinese => format!(
                "系统 ΔCPU {:+.1}% ΔMEM {} Δ读 {} Δ写 {} 进程 {:+}",
                delta.subtree_cpu,
                format_signed_bytes(delta.subtree_memory),
                format_signed_rate(delta.subtree_read_rate),
                format_signed_rate(delta.subtree_write_rate),
                delta.subtree_processes
            ),
        })
        .unwrap_or_else(|| text(language, "system totals unavailable", "系统总量不可用").into());
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
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(chrome(app.glyph_mode, title)),
                app.glyph_mode,
            ))
            .scroll((app.snapshot_diff_scroll, 0)),
        popup,
    );
}

fn network_endpoint_line(endpoint: &NetworkEndpoint, glyphs: &Glyphs) -> String {
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
        format!(
            "{} {} {}",
            endpoint.local_endpoint, glyphs.arrow_right, endpoint.remote_endpoint
        )
    };
    format!(
        " {:<4} {:<11} {:<45} | {} | fd {}{}",
        endpoint.protocol, endpoint.state, route, owner, endpoint.fd, namespace
    )
}

fn activity_spinner(elapsed: Duration, glyphs: &Glyphs) -> &'static str {
    let frames = glyphs.spinner;
    let index = (elapsed.as_millis() / 125) as usize % frames.len();
    frames[index]
}

fn draw_network_overlay(frame: &mut Frame, app: &mut App, area: Rect) {
    let language = app.language();
    let theme = app.theme;
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
        let spinner = activity_spinner(elapsed, &app.glyphs);
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
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    text(
                        language,
                        " The process tree remains live. Press n/Esc to close; the scan may finish in the background.",
                        " 进程树仍保持实时。按 n/Esc 关闭；扫描可继续在后台完成。",
                    ),
                    Style::default().fg(theme.dim),
                )),
            ])
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(text(language, " network scan ", " 网络扫描 ")),
                app.glyph_mode,
            )),
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
                Style::default().fg(theme.tree_fg)
            } else {
                Style::default().fg(theme.dim)
            };
            ListItem::new(network_endpoint_line(endpoint, &app.glyphs)).style(style)
        })
        .collect::<Vec<_>>();
    let mode = if let Some(input) = &app.network_port_input {
        format!(" {}: {}_", text(language, "port", "端口"), input)
    } else if app.network_searching {
        format!(
            " {}: {}_",
            text(language, "find", "查找"),
            app.network_filter
        )
    } else if let Some(port) = app.network_port_filter {
        format!(" {}={port}", text(language, "port", "端口"))
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
            activity_spinner(elapsed, &app.glyphs),
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
        .block(glyph_block(
            Block::default()
                .borders(Borders::ALL)
                .title(chrome(app.glyph_mode, title)),
            app.glyph_mode,
        ))
        .highlight_style(theme.selection());
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
            Line::from(if app.network_port_input.is_some() {
                text(
                    language,
                    " port: digits | Enter locate | Esc cancel ",
                    " 端口：输入数字 | Enter 定位 | Esc 取消 ",
                )
                .into()
            } else {
                chrome(
                    app.glyph_mode,
                    text(
                        language,
                        " ↑↓/jk move | v listeners/all | / find | p port | Enter jump | r rescan | x clear | n/Esc close ",
                        " ↑↓/jk 移动 | v 监听/全部 | / 查找 | p 端口 | Enter 跳转 | r 重扫 | x 清除 | n/Esc 关闭 ",
                    )
                    .to_string(),
                )
            }),
            Line::from(Span::styled(
                format!(" {warning}"),
                Style::default().fg(if scan.warning.is_some() || app.network_is_scanning() {
                    theme.severity_warn
                } else {
                    theme.dim
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

fn draw_attention_overlay(frame: &mut Frame, app: &App, area: Rect) {
    let language = app.language();
    let theme = &app.theme;
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = glyph_block(
        Block::default().borders(Borders::ALL).title(text(
            language,
            " attention cockpit ",
            " 关注事项 ",
        )),
        app.glyph_mode,
    );
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
            .style(Style::default().fg(theme.dim))]
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
                        .style(theme.severity_style(finding.severity)),
                    )
                })
                .collect()
        };
    let list = List::new(items).highlight_style(theme.selection());
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
                    theme
                        .severity_style(finding.severity)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("PID {}  {}", finding.pid, process_path(process))),
            ])];
            for reason in &finding.reasons {
                lines.push(Line::from(chrome(app.glyph_mode, format!(" • {reason}"))));
            }
            lines.push(Line::from(Span::styled(
                format!(" command: {}", process_command_line(process)),
                Style::default().fg(theme.dim),
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
                    Style::default().fg(theme.dim),
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
                    theme.severity_style(AttentionSeverity::Critical),
                ),
                Span::styled(
                    format!(" WARN {warning} "),
                    theme.severity_style(AttentionSeverity::Warning),
                ),
                Span::styled(
                    format!(" WATCH {watch} "),
                    theme.severity_style(AttentionSeverity::Watch),
                ),
                Span::raw(text(
                    language,
                    " — explainable signals from state, lifecycle, resource history",
                    " — 来自状态、生命周期和资源历史的可解释信号",
                )),
            ]),
            Line::from(chrome(
                app.glyph_mode,
                text(
                    language,
                    " ↑↓/jk move | Enter jump | t trend | i inspect | p actions | r sample | Space pause | a/Esc close",
                    " ↑↓/jk 移动 | Enter 跳转 | t 趋势 | i 深检 | p 操作 | r 采样 | Space 暂停 | a/Esc 关闭",
                )
                .to_string(),
            )),
        ]),
        sections[0],
    );
    frame.render_stateful_widget(list, sections[1], &mut state);
    frame.render_widget(
        Paragraph::new(detail)
            .block(glyph_block(
                Block::default().borders(Borders::TOP).title(text(
                    language,
                    " evidence ",
                    " 证据 ",
                )),
                app.glyph_mode,
            ))
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
    let theme = &app.theme;
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
            .style(Style::default().fg(theme.dim)),
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
        .block(glyph_block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(if active {
                    color
                } else {
                    theme.border_unfocused
                })),
            app.glyph_mode,
        ))
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
    let theme = &app.theme;
    let width = area.width.saturating_sub(2).clamp(1, 150);
    let height = area.height.saturating_sub(2).max(1);
    let popup = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let block = glyph_block(
        Block::default().borders(Borders::ALL).title(text(
            language,
            " hotspot cockpit ",
            " 热点工作台 ",
        )),
        app.glyph_mode,
    );
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
                        .fg(theme.accent)
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
            Line::from(chrome(
                app.glyph_mode,
                text(
                    language,
                    " ↑↓ rank | ←→ metric | v self/tree | Enter jump | r sample | Esc close",
                    " ↑↓ 排名 | ←→ 指标 | v 自身/子树 | Enter 跳转 | r 采样 | Esc 关闭",
                )
                .to_string(),
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
        app.theme.notice_error
    } else {
        app.theme.notice_success
    }
    .add_modifier(Modifier::BOLD);
    frame.render_widget(Clear, notice_area);
    frame.render_widget(
        Paragraph::new(format!(" {} ", notice.message)).style(style),
        notice_area,
    );
}

fn guidance_key(
    theme: &Theme,
    mode: GlyphMode,
    key: &'static str,
    description: &'static str,
) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:<12}", chrome(mode, key.to_string())),
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(description, Style::default().fg(theme.tree_fg)),
    ])
}

fn guidance_section(mode: GlyphMode, title: &'static str) -> Line<'static> {
    Line::from(Span::styled(
        format!(" {}", chrome(mode, title.to_string())),
        Style::default()
            .fg(Color::LightMagenta)
            .add_modifier(Modifier::BOLD),
    ))
}

fn guidance_page_en(page: usize, theme: &Theme, mode: GlyphMode) -> Vec<Line<'static>> {
    match page % GUIDANCE_PAGE_COUNT {
        0 => vec![
            Line::from(""),
            guidance_section(mode, "UNDERSTAND THE PROCESS TREE"),
            Line::from(Span::styled(
                " See who started it, what it owns, and the cost of the complete service.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(
                theme,
                mode,
                "↑ / ↓ / j / k",
                "move through stable process rows",
            ),
            guidance_key(
                theme,
                mode,
                "← / →",
                "reveal parent; expand or collapse children",
            ),
            guidance_key(
                theme,
                mode,
                "0-9",
                "type a PID, then press Enter to locate it directly",
            ),
            guidance_key(
                theme,
                mode,
                "/",
                "type a query, then Enter to apply it and select results",
            ),
            guidance_key(
                theme,
                mode,
                ":",
                "command palette: fuzzy-find and run any feature",
            ),
            guidance_key(
                theme,
                mode,
                "F",
                "manage persistent allow/deny filters before search",
            ),
            guidance_key(
                theme,
                mode,
                "f",
                "focus the selected parent chain and service subtree",
            ),
            guidance_key(
                theme,
                mode,
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
            guidance_section(mode, "MOVE FROM SYMPTOM TO EVIDENCE"),
            Line::from(Span::styled(
                " Workspaces keep process ownership attached to every signal.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(
                theme,
                mode,
                "a",
                "attention: unhealthy state, churn, pressure, and growth",
            ),
            guidance_key(
                theme,
                mode,
                "h",
                "CPU, memory, read, and write hotspot workbench",
            ),
            guidance_key(
                theme,
                mode,
                "t",
                "recent own and complete-subtree resource trend",
            ),
            guidance_key(
                theme,
                mode,
                "n",
                "listeners, connections, peers, owners, and namespaces",
            ),
            guidance_key(
                theme,
                mode,
                "v",
                "verify executable image, package, hash, and code signature",
            ),
            guidance_key(
                theme,
                mode,
                "m",
                "systemd or launchd ownership, state, config, and next commands",
            ),
            guidance_key(
                theme,
                mode,
                "l",
                "bounded native logs for this process or service",
            ),
            guidance_key(
                theme,
                mode,
                "M",
                "attribute RSS, PSS, swap, regions, and mapped files",
            ),
            guidance_key(
                theme,
                mode,
                "D",
                "one process dossier with prioritized evidence",
            ),
            guidance_key(
                theme,
                mode,
                "b / d / x",
                "capture baseline, compare, and clear",
            ),
            guidance_key(
                theme,
                mode,
                "Space / r",
                "freeze the scene; sample manually",
            ),
            Line::from(""),
            Line::from(Span::styled(
                " Tip: D collects manager, image, logs, and process evidence in parallel.",
                Style::default().fg(Color::Yellow),
            )),
        ],
        _ => vec![
            Line::from(""),
            guidance_section(mode, "OPERATE CAREFULLY · SHARE USEFULLY"),
            Line::from(Span::styled(
                " Actions are confirmed and identity-checked; reports preserve your context.",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(
                theme,
                mode,
                "p",
                "TERM, KILL, STOP, or CONT with explicit confirmation",
            ),
            guidance_key(theme, mode, "e", "recent process changes and action audit"),
            guidance_key(
                theme,
                mode,
                "o",
                "export a private, versioned diagnostic report",
            ),
            guidance_key(
                theme,
                mode,
                "s",
                "cycle stable and service-tree hotspot sorting",
            ),
            guidance_key(theme, mode, "L", "switch between English and Chinese"),
            guidance_key(theme, mode, "?", "open this field guide at any time"),
            guidance_key(
                theme,
                mode,
                "q / Ctrl-C",
                "q closes a pane, quits on the tree; Ctrl-C always quits",
            ),
            Line::from(""),
            Line::from(Span::styled(
                " CLI companions: doctor, explain (the D dossier), inspect, memory, exe, service, logs, tree, net, trace, diff",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            guidance_section(mode, "ABOUT PSMORE"),
            Line::from(chrome(
                mode,
                format!(
                    " v{} · wzfukui · fukui@wuzhi-ai.com",
                    env!("CARGO_PKG_VERSION")
                ),
            )),
            Line::from(" https://github.com/wzfukui/psmore"),
        ],
    }
}

fn guidance_page_zh(page: usize, theme: &Theme, mode: GlyphMode) -> Vec<Line<'static>> {
    match page % GUIDANCE_PAGE_COUNT {
        0 => vec![
            Line::from(""),
            guidance_section(mode, "理解进程树"),
            Line::from(Span::styled(
                " 看清谁启动了进程、它拥有什么，以及完整服务的资源成本。",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(theme, mode, "↑ / ↓ / j / k", "在稳定排序的进程行之间移动"),
            guidance_key(theme, mode, "← / →", "显示父进程；展开或折叠子进程"),
            guidance_key(theme, mode, "0-9", "直接输入 PID，再按 Enter 精确定位"),
            guidance_key(theme, mode, "/", "输入查询，按 Enter 后应用并选择结果"),
            guidance_key(theme, mode, ":", "命令面板：模糊查找并执行任意功能"),
            guidance_key(theme, mode, "F", "管理先于搜索执行的持久包含/排除规则"),
            guidance_key(theme, mode, "f", "聚焦选中进程的父链和服务子树"),
            guidance_key(theme, mode, "Enter", "检查线程、套接字、文件和运行上下文"),
            Line::from(""),
            Line::from(Span::styled(
                " 查询示例：user:deploy tree.mem>2g !state:zombie",
                Style::default().fg(Color::Yellow),
            )),
        ],
        1 => vec![
            Line::from(""),
            guidance_section(mode, "从症状走向证据"),
            Line::from(Span::styled(
                " 每个诊断工作区都会保留进程归属关系。",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(theme, mode, "a", "关注异常状态、抖动、压力和增长"),
            guidance_key(theme, mode, "h", "CPU、内存、读写热点工作台"),
            guidance_key(theme, mode, "t", "进程自身及完整子树的近期趋势"),
            guidance_key(theme, mode, "n", "监听、连接、对端、所有者和命名空间"),
            guidance_key(theme, mode, "v", "验证运行映像、软件包、哈希和代码签名"),
            guidance_key(theme, mode, "m", "systemd/launchd 归属、状态、配置和命令"),
            guidance_key(theme, mode, "l", "读取当前进程或服务的有界原生日志"),
            guidance_key(theme, mode, "M", "归因 RSS、PSS、Swap、区域和映射"),
            guidance_key(theme, mode, "D", "建立带优先级线索的单进程事故档案"),
            guidance_key(theme, mode, "b / d / x", "捕获基线、比较并清除"),
            guidance_key(theme, mode, "Space / r", "冻结现场；手工采样"),
            Line::from(""),
            Line::from(Span::styled(
                " 提示：D 会并行采集管理器、映像、日志和进程证据。",
                Style::default().fg(Color::Yellow),
            )),
        ],
        _ => vec![
            Line::from(""),
            guidance_section(mode, "谨慎操作 · 有效分享"),
            Line::from(Span::styled(
                " 操作需要确认和身份校验；报告会保留当前调查上下文。",
                Style::default().fg(Color::Gray),
            )),
            Line::from(""),
            guidance_key(theme, mode, "p", "经明确确认发送 TERM/KILL/STOP/CONT"),
            guidance_key(theme, mode, "e", "查看近期进程变化和操作审计"),
            guidance_key(theme, mode, "o", "导出私有、版本化诊断报告"),
            guidance_key(theme, mode, "s", "切换稳定排序和服务树热点排序"),
            guidance_key(theme, mode, "L", "切换中文或英文界面"),
            guidance_key(theme, mode, "?", "随时打开本现场手册"),
            guidance_key(
                theme,
                mode,
                "q / Ctrl-C",
                "q 关闭面板，在进程树退出；Ctrl-C 始终退出",
            ),
            Line::from(""),
            Line::from(Span::styled(
                " CLI 工具：doctor、explain（即 D 档案）、inspect、memory、exe、service、logs、tree、net、trace、diff",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            guidance_section(mode, "关于 PSMORE"),
            Line::from(chrome(
                mode,
                format!(
                    " v{} · wzfukui · fukui@wuzhi-ai.com",
                    env!("CARGO_PKG_VERSION")
                ),
            )),
            Line::from(" https://github.com/wzfukui/psmore"),
        ],
    }
}

fn guidance_page(
    page: usize,
    language: UiLanguage,
    theme: &Theme,
    mode: GlyphMode,
) -> Vec<Line<'static>> {
    match language {
        UiLanguage::Chinese => guidance_page_zh(page, theme, mode),
        UiLanguage::English => guidance_page_en(page, theme, mode),
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
    let glyph_mode = app.glyph_mode;
    let title = match overlay {
        GuidanceOverlay::Welcome => chrome(
            glyph_mode,
            text(
                language,
                " WELCOME TO PSMORE · SEE THE SYSTEM THROUGH ITS PROCESSES ",
                " 欢迎使用 PSMORE · 通过进程看清系统 ",
            )
            .to_string(),
        ),
        GuidanceOverlay::Help => text(language, " PSMORE FIELD GUIDE ", " PSMORE 现场手册 ").into(),
        GuidanceOverlay::Tip(index) => {
            let title = format!(
                " PSMORE {} {}/{} ",
                text(language, "TIP", "提示"),
                index + 1,
                TIPS.len()
            );
            frame.render_widget(Clear, popup);
            let block = glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title(Span::styled(
                        title,
                        Style::default()
                            .fg(Color::LightMagenta)
                            .add_modifier(Modifier::BOLD),
                    )),
                glyph_mode,
            );
            let Some(tip) = app.guidance.tip() else {
                frame.render_widget(block, popup);
                return;
            };
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    chrome(glyph_mode, format!(" {}", tip.title)),
                    Style::default()
                        .fg(Color::LightCyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(chrome(glyph_mode, format!(" {}", tip.body))),
                Line::from(""),
                Line::from(Span::styled(
                    chrome(glyph_mode, format!(" {}", tip.keys)),
                    Style::default().fg(Color::Yellow),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    chrome(
                        glyph_mode,
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
    let mut lines = guidance_page(app.guidance.page, language, &app.theme, glyph_mode);
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        chrome(
            glyph_mode,
            format!(
                " ←/→ {} {}/{} · Enter/Esc {} · T {} {} · D {} · L {}{}",
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
        ),
        Style::default().fg(Color::DarkGray),
    )));
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .block(glyph_block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(border_color))
                    .title(Span::styled(
                        title,
                        Style::default()
                            .fg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    )),
                glyph_mode,
            ))
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
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(detail_height),
            Constraint::Length(1),
        ])
        .split(area);
    draw_status_bar(frame, app, chunks[0]);
    app.page_size = chunks[1].height.saturating_sub(2).max(1) as usize;
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
    // Right-aligned metric columns adapt to the terminal: below 100 columns
    // MEM goes first, below 80 both are dropped and the layout matches the
    // original two pseudo-column tree.
    let show_cpu_column = area.width >= 80;
    let show_mem_column = area.width >= 100;
    let metrics_width = match (show_cpu_column, show_mem_column) {
        (true, true) => 12,
        (true, false) => 6,
        _ => 0,
    };
    let tree_width = chunks[1].width.saturating_sub(2) as usize;
    let path_width = tree_width.saturating_sub(path_column + metrics_width);
    app.advance_marquee(path_width);
    let items: Vec<ListItem> = app
        .visible
        .iter()
        .zip(row_parts.iter())
        .map(|(row, (label, context))| {
            let p = &app.processes[&row.pid];
            let theme = &app.theme;
            let is_selected = Some(row.pid) == selected_pid;
            let mut spans = vec![
                Span::raw(label.clone()),
                Span::raw(" ".repeat(path_column.saturating_sub(label.width()))),
            ];
            if show_cpu_column {
                let cpu_style = if is_selected {
                    Style::default()
                } else {
                    theme.hot_cpu_style(p.cpu).unwrap_or_default()
                };
                spans.push(Span::styled(
                    format!("{:>5} ", format!("{:.1}", p.cpu.min(999.9))),
                    cpu_style,
                ));
            }
            if show_mem_column {
                spans.push(Span::raw(format!("{:>5} ", format_compact_bytes(p.memory))));
            }
            spans.push(Span::raw(marquee(
                context,
                if is_selected { app.marquee_offset } else { 0 },
                path_width,
            )));
            let same_name_as_selected = !app.search.is_empty()
                && Some(row.pid) != selected_pid
                && selected_name
                    .as_deref()
                    .map(|name| name == p.name)
                    .unwrap_or(false);
            let recent_change = app.recent_change(row.pid);
            let sibling_background_allowed = selected_depth.map(|depth| depth > 2).unwrap_or(false);
            let style = if Some(row.pid) == selected_pid {
                theme.selection()
            } else if same_name_as_selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(recent_change, Some(ProcessChange::Started { .. })) {
                Style::default()
                    .fg(theme.started_fg)
                    .add_modifier(Modifier::BOLD)
            } else if matches!(recent_change, Some(ProcessChange::Reparented { .. })) {
                Style::default()
                    .fg(theme.reparented_fg)
                    .add_modifier(Modifier::BOLD)
            } else if sibling_background_allowed
                && selected_parent.is_some()
                && p.parent == selected_parent
                && Some(row.pid) != selected_pid
            {
                theme.sibling_style()
            } else {
                Style::default().fg(theme.tree_fg)
            };
            ListItem::new(Line::from(spans)).style(style)
        })
        .collect();
    let mut tree_block = glyph_block(
        Block::default().borders(Borders::ALL).title(title),
        app.glyph_mode,
    );
    if show_cpu_column {
        tree_block = tree_block.title(Title {
            content: Line::from(if show_mem_column {
                " CPU%  MEM "
            } else {
                " CPU% "
            }),
            alignment: Some(Alignment::Right),
            position: None,
        });
    }
    let tree = List::new(items).block(tree_block);
    let mut tree_state = if app.visible.is_empty() {
        ListState::default()
    } else {
        ListState::default()
            .with_offset(app.tree_offset.min(app.visible.len().saturating_sub(1)))
            .with_selected(Some(app.selected))
    };
    tree_state.select(Some(app.selected));
    // Record the tree block's screen region so mouse clicks can be mapped
    // back to visible rows using the same scroll offset as the List.
    app.tree_area = chunks[1];
    frame.render_stateful_widget(tree, chunks[1], &mut tree_state);
    app.tree_offset = tree_state.offset();

    let detail_width = chunks[2].width.saturating_sub(2).max(1) as usize;
    let detail = Text::from(
        selected_process_detail_lines(app, language, detail_width)
            .into_iter()
            .map(Line::from)
            .collect::<Vec<_>>(),
    );
    frame.render_widget(
        Paragraph::new(detail)
            .block(glyph_block(
                Block::default().borders(Borders::ALL).title(text(
                    language,
                    " selected process ",
                    " 当前进程 ",
                )),
                app.glyph_mode,
            ))
            .wrap(Wrap { trim: false }),
        chunks[2],
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
    let hint_line: String = if app.pid_input.is_some() {
        text(
            language,
            " PID: type digits | Enter locate | Backspace edit | Esc cancel ",
            " PID：输入数字 | Enter 定位 | Backspace 编辑 | Esc 取消 ",
        )
        .into()
    } else if app.searching {
        text(language, " search: words | name:/state: | cpu>20 mem>500m | ↑↓ history | Tab field | Enter apply | Esc cancel ", " 搜索（树不变）：文字 | name:/state: | cpu>20 mem>500m | ↑↓ 历史 | Tab 字段 | Enter 应用 | Esc 取消 ").into()
    } else if !app.search.is_empty() {
        text(language, " search active | ↑↓/jk move | p actions | / new search | Esc clear | Enter inspect | q quit ", " 搜索已生效 | ↑↓/jk 移动 | p 操作 | / 新搜索 | Esc 清除 | Enter 深检 | q 退出 ").into()
    } else {
        text(
            language,
            " Enter details · / search · : commands · a alerts · p actions · ? help · q quit ",
            " Enter 详情 · / 搜索 · : 命令 · a 关注 · p 操作 · ? 帮助 · q 退出 ",
        )
        .into()
    };
    let hint_line = chrome(app.glyph_mode, hint_line);
    // The footer is a single line. Wide terminals get the full stats plus the
    // shortcut hints; as width shrinks the stats degrade to a compact form
    // and finally yield the whole line to the hints (the hint text is the
    // part that teaches keys, so it is clipped last). Text-entry modes
    // (search, PID input) already replaced the hint with input help and skip
    // stats entirely.
    let full_stats = format!(
        " {} {} | {} {}/{} | {} | {} | {} {} | +{} -{} {}{} | L {}",
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
        app.glyphs.reparent,
        app.last_changes.reparented,
        language.label(),
    );
    let compact_stats = format!(
        " {} {} · {} · +{} -{} {}{}",
        total_processes,
        text(language, "proc", "进程"),
        live_state,
        app.last_changes.started,
        app.last_changes.exited,
        app.glyphs.reparent,
        app.last_changes.reparented,
    );
    let footer_width = chunks[3].width as usize;
    let show_stats = !app.searching && app.pid_input.is_none();
    let combined = if show_stats && (full_stats.width() + 2 + hint_line.width()) <= footer_width {
        format!("{full_stats} |{hint_line}")
    } else if show_stats && (compact_stats.width() + 2 + hint_line.width()) <= footer_width {
        format!("{compact_stats} |{hint_line}")
    } else {
        hint_line
    };
    let footer = Paragraph::new(Line::from(marquee(&combined, 0, footer_width))).style(
        Style::default().fg(if app.paused {
            app.theme.severity_warn
        } else {
            app.theme.dim
        }),
    );
    frame.render_widget(footer, chunks[3]);

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
        draw_inspection_overlay(frame, app, area, chunks[1]);
    } else if app.show_events {
        draw_event_overlay(frame, app, area);
    }
    if app.process_action.is_some() {
        draw_process_action_overlay(frame, app, area);
    }
    // The palette draws above every overlay and dialog (the action dialog
    // lives outside the if-else chain) but below the notice and guidance.
    if app.show_palette {
        draw_palette_overlay(frame, app, area);
    }
    draw_notice(frame, app, area);
    draw_guidance_overlay(frame, app, area);
}

#[cfg(test)]
mod tests {
    use std::{
        process::{Child, Command},
        thread,
        time::{Duration, Instant},
    };

    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::{
        app::{
            DossierContextPanel, ExecutableContextPanel, LogsContextPanel, MemoryContextPanel,
            ServiceContextPanel, aggregate_resources,
        },
        cli::{LogPriority, LogScope},
        i18n::UiLanguage,
        model::{OpenFileInfo, ProcessInfo, ProcessInspection, SocketInfo, ThreadInfo},
        network::NetworkScan,
        onboarding::{Guidance, TIPS},
        provider::HostMetrics,
        query::ProcessQuery,
        snapshot::BaselineSnapshot,
        theme::{GlyphMode, ThemeId},
    };

    fn ui_process(pid: u32, parent: Option<u32>, name: &str, executable: &str) -> ProcessInfo {
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

        app.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let third_page = buffer_text(&terminal);
        assert!(third_page.contains("ABOUT PSMORE"));
        assert!(third_page.contains(env!("CARGO_PKG_VERSION")));
        assert!(third_page.contains("github.com/wzfukui/psmore"));
        assert!(third_page.contains("fukui@wuzhi-ai.com"));

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
    fn l_switches_the_complete_guidance_surface_between_languages() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let backend = TestBackend::new(100, 28);
        let mut terminal = Terminal::new(backend).unwrap();

        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let chinese = buffer_text(&terminal);
        let compact_chinese = chinese.replace(' ', "");
        assert!(compact_chinese.contains("欢迎使用PSMORE"));
        assert!(compact_chinese.contains("理解进程树"));
        assert!(compact_chinese.contains("页1/3"));

        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let english = buffer_text(&terminal);
        assert!(english.contains("WELCOME TO PSMORE"));
        assert!(english.contains("UNDERSTAND THE PROCESS TREE"));
    }

    #[test]
    fn inspection_uses_separate_tabbed_cards_for_context_threads_ports_and_files() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.inspection = Some(ProcessInspection {
            pid: Pid::from_u32(42),
            name: "worker".into(),
            user: "deploy".into(),
            cwd: "/srv/worker".into(),
            threads: vec![ThreadInfo {
                id: 4201,
                name: "worker-loop".into(),
                state: "Running".into(),
                cpu_percent: 12.5,
                priority: 20,
                nice: Some(0),
                processor: Some(3),
            }],
            thread_count: 3,
            sockets: vec![SocketInfo {
                fd: "7".into(),
                protocol: "TCP".into(),
                endpoint: "127.0.0.1:8080".into(),
                state: "LISTEN".into(),
            }],
            files: vec![OpenFileInfo {
                fd: "9".into(),
                kind: "REG".into(),
                access: "r".into(),
                name: "/tmp/example.log".into(),
            }],
            ..ProcessInspection::default()
        });
        let backend = TestBackend::new(72, 14);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let overview = buffer_text(&terminal);
        assert!(overview.contains("Overview"));
        assert!(overview.contains("Threads 3"));
        assert!(overview.contains("Ports 1"));
        assert!(overview.contains("Files 1"));
        assert!(overview.contains("/srv/worker"));
        assert!(!overview.contains("worker-loop"));

        app.inspection_scroll = 5;
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.inspection_tab, InspectionTab::Threads);
        assert_eq!(app.inspection_scroll, 0);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let threads = buffer_text(&terminal);
        assert!(threads.contains("HOT THREADS"));
        assert!(threads.contains("worker-loop"));
        assert!(!threads.contains("127.0.0.1:8080"));

        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.inspection_tab, InspectionTab::Ports);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let ports = buffer_text(&terminal);
        assert!(ports.contains("PORTS & CONNECTIONS"));
        assert!(ports.contains("127.0.0.1:8080"));
        assert!(!ports.contains("/tmp/example.log"));

        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.inspection_tab, InspectionTab::Files);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let files = buffer_text(&terminal);
        assert!(files.contains("OPEN FILE DESCRIPTORS"));
        assert!(files.contains("/tmp/example.log"));
        assert!(!files.contains("worker-loop"));

        app.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(app.inspection_tab, InspectionTab::Ports);

        let compact_backend = TestBackend::new(40, 9);
        let mut compact_terminal = Terminal::new(compact_backend).unwrap();
        compact_terminal
            .draw(|frame| draw(frame, &mut app))
            .unwrap();
        let compact = buffer_text(&compact_terminal);
        assert!(compact.contains("Info"));
        assert!(compact.contains("Thr"));
        assert!(compact.contains("Net"));
        assert!(compact.contains("File"));
        assert!(compact.contains("127.0.0.1:8080"));

        let tiny_backend = TestBackend::new(28, 8);
        let mut tiny_terminal = Terminal::new(tiny_backend).unwrap();
        tiny_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let tiny = buffer_text(&tiny_terminal);
        assert!(tiny.contains("3/4"));
        assert!(tiny.contains("Ports 1"));
    }

    #[test]
    fn inspection_arrow_keys_switch_tabs_and_stay_above_the_footer() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.inspection = Some(ProcessInspection {
            pid: Pid::from_u32(42),
            name: "worker".into(),
            ..ProcessInspection::default()
        });

        // Left/right arrows mirror Tab/Shift-Tab, including the scroll reset.
        app.inspection_scroll = 4;
        app.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.inspection_tab, InspectionTab::Threads);
        assert_eq!(app.inspection_scroll, 0);
        app.on_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.inspection_tab, InspectionTab::Ports);
        app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(app.inspection_tab, InspectionTab::Threads);

        // The popup hugs the process-tree block: its bottom border (at x=1,
        // since the popup is horizontally inset) sits on the row directly
        // above the selected-process pane's top border (at x=0), never
        // dipping into that pane, and the footer keeps its hints.
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let footer_row = buffer_row(&terminal, 29);
        assert!(
            footer_row.contains("p actions"),
            "inspection popup covers the footer: {footer_row:?}"
        );
        let popup_bottom = (0..30u16)
            .rfind(|row| buffer_row(&terminal, *row).chars().nth(1) == Some('└'))
            .expect("inspection popup bottom border should be visible");
        let detail_top = (0..30u16)
            .rfind(|row| buffer_row(&terminal, *row).starts_with('┌'))
            .expect("selected-process pane border should be visible");
        assert_eq!(
            popup_bottom + 1,
            detail_top,
            "inspection popup should end flush with the process tree's bottom border"
        );
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

        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
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
    fn escape_never_quits_from_the_bare_process_tree() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        assert!(!app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
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

        app.on_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
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
    fn selected_process_detail_lines_adapt_to_width_for_merge_vs_wrap() {
        let app = App::new_for_test(Guidance::welcome_for_test());
        let wide_lines = selected_process_detail_lines(&app, UiLanguage::English, 260);
        let narrow_lines = selected_process_detail_lines(&app, UiLanguage::English, 60);

        assert!(!wide_lines.is_empty());
        assert!(wide_lines[0].contains(" | "));
        assert!(wide_lines[0].contains("PID "));
        assert!(!narrow_lines.is_empty());
        assert!(narrow_lines[0].contains("PID "));
        assert!(!narrow_lines[0].contains(" | "));
        assert!(narrow_lines[1].contains("TREE"));
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
    fn on_key_esc_keeps_anchor_when_search_filter_is_cleared() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let herdr_pid = Pid::from_u32(200);
        let mut processes = vec![
            ui_process(0, None, "kernel / system", ""),
            ui_process(1, Some(0), "launchd", "/sbin/launchd"),
            ui_process(herdr_pid.as_u32(), Some(1), "herdr", "/usr/bin/herdr"),
            ui_process(300, Some(herdr_pid.as_u32()), "zsh", "/bin/zsh"),
            ui_process(
                301,
                Some(herdr_pid.as_u32()),
                "claude",
                "/usr/local/bin/claude",
            ),
        ];
        for i in 10..120 {
            processes.push(ui_process(
                i,
                Some(herdr_pid.as_u32()),
                "worker",
                &format!("/usr/bin/worker{i}"),
            ));
        }
        app.processes = processes.into_iter().map(|p| (p.pid, p)).collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = [0, 1, 200].into_iter().map(Pid::from_u32).collect();

        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for character in "name:herdr".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == herdr_pid)
            .expect("herdr should be visible when search is active");
        assert_eq!(app.search, "name:herdr");

        app.collapsed.insert(Pid::from_u32(1));
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        let visible_herdr = app
            .visible
            .iter()
            .position(|row| row.pid == herdr_pid)
            .expect("herdr should remain visible after clearing search");
        assert_eq!(app.search, "");
        assert_eq!(app.selected, visible_herdr);
        assert_eq!(app.selected_pid(), Some(herdr_pid));
        assert!(!app.expanded.is_empty());
        assert!(app.expanded.contains(&Pid::from_u32(1)));
        assert!(!app.collapsed.contains(&Pid::from_u32(1)));
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
    fn action_dialog_requires_second_confirmation_before_sending_a_signal() {
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

        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        let dialog = app.process_action.as_ref().expect("p should open a dialog");
        assert!(!dialog.is_termination_only());
        assert_eq!(dialog.actions(), &ProcessActionKind::ALL);
        assert_eq!(dialog.selected_action(), ProcessActionKind::Terminate);
        assert!(!dialog.confirming);

        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.process_action.as_ref().unwrap().confirming);
        assert!(child.0.try_wait().expect("check child").is_none());

        // q steps out of the confirmation, then closes the dialog; the app
        // keeps running because only the bare tree lets q quit.
        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.process_action.as_ref().unwrap().confirming);
        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        let dialog = app.process_action.as_ref().unwrap();
        assert_eq!(dialog.selected_action(), ProcessActionKind::Kill);
        assert!(dialog.confirming);
        assert!(child.0.try_wait().expect("check child again").is_none());

        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.process_action.is_none());
        assert!(app.action_history.is_empty());

        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
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

    /// Fixed seeded main screen, rendered with the default dark/unicode
    /// configuration. The snapshot was captured before the theme system
    /// existed; any change to default rendering fails this test.
    fn seeded_main_screen_terminal() -> Terminal<TestBackend> {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.host_metrics = HostMetrics {
            hostname: "testhost".into(),
            load_one: 0.82,
            cpu_percent: 42.0,
            memory_used: 13_000_000_000,
            memory_total: 17_179_869_184,
            swap_used: 1_000_000_000,
            swap_total: 4_000_000_000,
        };
        let mut hot = ui_process(2, Some(1), "worker", "/usr/bin/worker");
        hot.cpu = 91.5;
        hot.memory = 512 * 1024 * 1024;
        let mut warm = ui_process(3, Some(1), "helper", "/usr/bin/helper");
        warm.cpu = 62.0;
        warm.memory = 64 * 1024 * 1024;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                hot,
                warm,
                ui_process(4, Some(2), "child", "/usr/bin/child"),
            ],
        );
        let backend = TestBackend::new(110, 28);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        terminal
    }

    #[test]
    fn default_main_screen_matches_pre_theme_snapshot() {
        let terminal = seeded_main_screen_terminal();
        // Regenerate the fixture after intentional layout changes:
        // PSMORE_REGEN_SNAPSHOT=1 cargo test default_main_screen_matches
        if std::env::var_os("PSMORE_REGEN_SNAPSHOT").is_some() {
            std::fs::write(
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/src/ui_main_screen_snapshot.txt"
                ),
                buffer_text(&terminal),
            )
            .expect("snapshot fixture should be writable");
            return;
        }
        assert_eq!(
            buffer_text(&terminal),
            include_str!("ui_main_screen_snapshot.txt")
        );
        // Key styles are also pinned: the selected row stays white-on-blue
        // bold, and the status-bar CPU label stays cyan.
        let buffer = terminal.backend().buffer();
        let selected = buffer.cell((1, 2)).expect("selected tree row cell");
        assert_eq!(selected.fg, Color::White);
        assert_eq!(selected.bg, Color::Blue);
        assert!(selected.modifier.contains(Modifier::BOLD));
        let cpu_label = buffer
            .cell((12, 0))
            .expect("status bar CPU label cell")
            .clone();
        assert_eq!(cpu_label.fg, Color::Cyan);
        // The hot worker's CPU metric stays LightRed at the 85% threshold.
        let hot_cpu = (0..buffer.area.width)
            .filter_map(|x| buffer.cell((x, 4)))
            .find(|cell| cell.symbol() == "9")
            .expect("hot worker CPU cell")
            .clone();
        assert_eq!(hot_cpu.fg, Color::LightRed);
    }

    #[test]
    fn cycling_the_theme_via_the_palette_repaints_and_persists() {
        let directory = std::env::temp_dir().join(format!(
            "psmore-theme-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        let state_path = directory.join("ui-state.json");
        let mut app = App::new_for_test(Guidance::load_from_path(state_path.clone(), true));
        app.guidance.overlay = None;
        assert_eq!(app.theme_id, ThemeId::Dark);

        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        type_palette_query(&mut app, "cycle theme");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!app.show_palette);
        assert_eq!(app.theme_id, ThemeId::Light);
        assert_eq!(
            app.notice.as_ref().map(|notice| notice.message.as_str()),
            Some("Theme: light")
        );

        app.cycle_theme();
        assert_eq!(app.theme_id, ThemeId::HighContrast);
        app.cycle_theme();
        assert_eq!(app.theme_id, ThemeId::Dark);

        // The resolved struct tracks the id, and the selection style differs
        // between presets.
        app.cycle_theme();
        app.cycle_theme();
        assert_eq!(app.theme.selection_fg, Color::Black);
        assert_eq!(app.theme.selection_bg, Color::White);
        assert_ne!(app.theme.selection(), Theme::dark().selection());

        // Palette switching persisted the final choice to ui-state.json.
        let reloaded = Guidance::load_from_path(state_path.clone(), true);
        assert_eq!(reloaded.theme(), Some(ThemeId::HighContrast));

        std::fs::remove_file(state_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn ascii_glyphs_replace_unicode_tree_and_status_marks() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.host_metrics = HostMetrics {
            hostname: "testhost".into(),
            load_one: 0.0,
            cpu_percent: 0.0,
            memory_used: 1_000_000_000,
            memory_total: 2_000_000_000,
            swap_used: 0,
            swap_total: 0,
        };
        let mut zombie = ui_process(2, Some(1), "zombie-worker", "/bin/zombie-worker");
        zombie.status = "Zombie".into();
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                zombie,
                ui_process(3, Some(2), "child", "/usr/bin/child"),
                ui_process(4, Some(1), "helper", "/usr/bin/helper"),
            ],
        );
        let backend = TestBackend::new(100, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let unicode = buffer_text(&terminal);
        assert!(unicode.contains("├─"));
        assert!(unicode.contains("└─"));
        assert!(unicode.contains("▲ 1 alerts"));

        app.toggle_glyphs();
        assert_eq!(app.glyph_mode, GlyphMode::Ascii);
        let mut ascii_terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
        ascii_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let ascii = buffer_text(&ascii_terminal);
        assert!(ascii.contains("|-"));
        assert!(ascii.contains("`-"));
        // Block borders switch to the ASCII set too: no Unicode line symbols
        // survive anywhere on the main screen.
        assert!(!ascii.contains('├'));
        assert!(!ascii.contains('▾'));
        assert!(!ascii.contains('─'));
        assert!(!ascii.contains('│'));
        assert!(ascii.contains("! 1 alerts"));
        // The test guidance has no state path, so the notice reports the
        // save failure; the onboarding tests cover the persisted round-trip.
        let notice = app.notice.as_ref().expect("glyph toggle notice");
        assert!(notice.message.to_lowercase().contains("glyph"));
    }

    #[test]
    fn ascii_mode_keeps_main_screen_and_trend_overlay_pure_ascii() {
        // Decorative chrome must never leak Unicode in ASCII glyph mode.
        // CJK text content is exempt by design and not rendered here.
        const FORBIDDEN: &[char] = &[
            '│', '┃', '├', '┤', '└', '┌', '┐', '┘', '─', '━', '▾', '▸', '●', '○', '↪', '▲', '✓',
            '↑', '↓', '→', '←', '·', '•', '×', '★', '⠋',
        ];
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.host_metrics = HostMetrics {
            hostname: "testhost".into(),
            load_one: 0.82,
            cpu_percent: 42.0,
            memory_used: 1_000_000_000,
            memory_total: 2_000_000_000,
            swap_used: 0,
            swap_total: 0,
        };
        let mut zombie = ui_process(2, Some(1), "zombie-worker", "/bin/zombie-worker");
        zombie.status = "Zombie".into();
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                zombie,
            ],
        );
        for _ in 0..3 {
            app.history
                .record(&app.processes, &app.resources, Instant::now());
        }
        app.toggle_glyphs();

        // Main screen.
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let main = buffer_text(&terminal);
        for c in FORBIDDEN {
            assert!(!main.contains(*c), "main screen leaked {c:?}: {main:?}");
        }

        // Trend overlay with live sparklines on top.
        app.trend_pid = Some(Pid::from_u32(2));
        app.trend_view = TrendView::Io;
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let trend = buffer_text(&terminal);
        for c in FORBIDDEN {
            assert!(!trend.contains(*c), "trend overlay leaked {c:?}: {trend:?}");
        }
        assert!(trend.contains("trends zombie-worker [2]"));
    }

    #[test]
    fn overlay_body_text_uses_the_theme_foreground() {
        fn dossier_app() -> App {
            let mut app = App::new_for_test(Guidance::welcome_for_test());
            app.guidance.overlay = None;
            let current_pid = sysinfo::get_current_pid().unwrap();
            app.dossier_context = Some(DossierContextPanel {
                pid: current_pid,
                name: "worker".into(),
                content: [
                    "PSMORE PROCESS DOSSIER",
                    "process worker [42]  user deploy  status Run  identity verified",
                    "EVIDENCE OVERVIEW",
                    "  inspection         complete      20ms",
                ]
                .join("\n"),
                report: None,
                warning: None,
                include_logs: false,
                hash: false,
                scope: LogScope::Auto,
                priority: LogPriority::Info,
                since_seconds: 900,
                limit: 100,
            });
            app
        }
        // Foreground of the first character of the row containing `needle`.
        fn body_fg(terminal: &Terminal<TestBackend>, needle: &str) -> Color {
            let buffer = terminal.backend().buffer();
            for y in 0..buffer.area.height {
                let row: String = (0..buffer.area.width)
                    .filter_map(|x| buffer.cell((x, y)))
                    .map(|cell| cell.symbol())
                    .collect();
                if let Some(byte_index) = row.find(needle) {
                    let x = row[..byte_index].chars().count() as u16;
                    return buffer
                        .cell((x, y))
                        .map(|cell| cell.fg)
                        .unwrap_or(Color::Reset);
                }
            }
            panic!("row {needle:?} not rendered");
        }

        // Dark must stay pixel-identical to the pre-theme code: White body.
        let mut app = dossier_app();
        let mut terminal = Terminal::new(TestBackend::new(110, 18)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(body_fg(&terminal, "process worker [42]"), Color::White);

        // Light theme routes the same body text through the theme token.
        let mut app = dossier_app();
        app.theme_id = ThemeId::Light;
        app.theme = Theme::light();
        let mut terminal = Terminal::new(TestBackend::new(110, 18)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(
            body_fg(&terminal, "process worker [42]"),
            Theme::light().tree_fg
        );
    }

    #[test]
    fn inspection_tab_labels_fit_their_measured_width() {
        let inspection = ProcessInspection::default();
        // English compact bar measures 31 cells: fits at 32.
        assert!(inspection_tab_labels(&inspection, UiLanguage::English, 32).is_some());
        // The four Chinese compact labels are double-width and measure 33
        // cells: 32 degrades to the single active tab instead of clipping,
        // and 33 fits exactly.
        assert!(inspection_tab_labels(&inspection, UiLanguage::Chinese, 32).is_none());
        let labels = inspection_tab_labels(&inspection, UiLanguage::Chinese, 33)
            .expect("Chinese compact labels fit at 33");
        assert_eq!(inspection_tab_bar_width(&labels), 33);
        // Full labels are preferred from 58 columns up when they fit.
        let full = inspection_tab_labels(&inspection, UiLanguage::English, 58)
            .expect("full labels fit at 58");
        assert!(full[0].contains("Overview"));
        // Counts that outgrow the full bar fall back to compact labels.
        let busy = ProcessInspection {
            thread_count: 999_999_999_999,
            ..ProcessInspection::default()
        };
        let labels = inspection_tab_labels(&busy, UiLanguage::English, 58)
            .expect("compact fallback fits at 58");
        assert_eq!(labels[0], "Info");
    }

    #[test]
    fn inspection_tab_click_regions_stay_inside_the_tab_bar() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.guidance.set_language_for_test(UiLanguage::Chinese);
        app.inspection = Some(ProcessInspection {
            pid: Pid::from_u32(42),
            name: "worker".into(),
            ..ProcessInspection::default()
        });
        // area 36 -> popup 34 -> tab bar 32 cells: the Chinese compact bar
        // (33 cells) does not fit, so only the active tab shows and no
        // clickable regions are recorded.
        let mut terminal = Terminal::new(TestBackend::new(36, 14)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(app.inspection_tab_regions.is_empty());
        let output = buffer_text(&terminal);
        assert!(output.contains("1/4"));

        // area 37 -> popup 35 -> tab bar 33 cells: the Chinese compact bar
        // fits exactly and every recorded region stays inside the bar.
        let mut terminal = Terminal::new(TestBackend::new(37, 14)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(app.inspection_tab_regions.len(), 4);
        let bar_end = app
            .inspection_tab_regions
            .iter()
            .map(|(region, _)| region.x + region.width)
            .max()
            .unwrap();
        // The 33-cell bar starts at inner x = 2 and ends at x = 35.
        assert!(bar_end <= 35, "regions escaped the tab bar: {bar_end}");
    }

    #[test]
    fn network_port_filter_label_is_bilingual() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.show_network = true;
        app.network_scan = Some(network_fixture());
        app.network_port_filter = Some(8080);

        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert!(buffer_text(&terminal).contains("port=8080"));

        app.guidance.set_language_for_test(UiLanguage::Chinese);
        // A fresh backend: TestBackend keeps stale symbols in the
        // continuation cells of wide CJK glyphs after a redraw.
        let mut terminal = Terminal::new(TestBackend::new(120, 24)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        // TestBackend pads the continuation cell of every wide CJK glyph
        // with a blank, so compare Chinese substrings without whitespace.
        let compact: String = buffer_text(&terminal)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        assert!(compact.contains("端口=8080"));
    }

    #[test]
    fn zero_sized_terminal_does_not_panic() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        let backend = TestBackend::new(0, 0);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    }

    fn buffer_row(terminal: &Terminal<TestBackend>, row: u16) -> String {
        let buffer = terminal.backend().buffer();
        let mut output = String::new();
        for x in 0..buffer.area.width {
            if let Some(cell) = buffer.cell((x, row)) {
                output.push_str(cell.symbol());
            }
        }
        output
    }

    fn seed_processes(app: &mut App, processes: Vec<ProcessInfo>) {
        app.processes = processes.into_iter().map(|p| (p.pid, p)).collect();
        app.children.clear();
        for process in app.processes.values() {
            app.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        app.resources = aggregate_resources(&app.processes, &app.children);
        app.expanded = app
            .children
            .iter()
            .filter(|(pid, kids)| pid.is_some() && !kids.is_empty())
            .filter_map(|(pid, _)| *pid)
            .collect();
        // cycle_sort_mode rebuilds the visible rows from the seeded map.
        app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        app.selected = 0;
    }

    #[test]
    fn status_bar_renders_host_metrics_alerts_and_survives_narrow_terminals() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.host_metrics = HostMetrics {
            hostname: "testhost".into(),
            load_one: 0.82,
            cpu_percent: 42.0,
            memory_used: 13_000_000_000,
            memory_total: 17_179_869_184,
            swap_used: 1_000_000_000,
            swap_total: 4_000_000_000,
        };
        let mut zombie = ui_process(7654, Some(1), "zombie-worker", "/bin/zombie-worker");
        zombie.status = "Zombie".into();
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                zombie,
            ],
        );

        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let status = buffer_row(&terminal, 0);
        assert!(status.contains("testhost"));
        assert!(status.contains("load 0.82"));
        assert!(status.contains("CPU 42%"));
        assert!(status.contains("12.1G/16.0G"));
        assert!(status.contains("SWAP 25%"));
        assert!(status.contains("▲ 1 alerts"));

        let narrow = TestBackend::new(40, 12);
        let mut narrow_terminal = Terminal::new(narrow).unwrap();
        narrow_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let narrow_status = buffer_row(&narrow_terminal, 0);
        assert!(narrow_status.contains("testhost"));
        // The alert count is the most decision-relevant field: it must
        // survive even when host metrics are dropped for lack of width.
        assert!(narrow_status.contains("alerts"));
    }

    #[test]
    fn metric_columns_adapt_to_terminal_width() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.host_metrics = HostMetrics {
            hostname: "testhost".into(),
            load_one: 0.0,
            cpu_percent: 0.0,
            memory_used: 2_000_000_000,
            memory_total: 17_179_869_184,
            swap_used: 0,
            swap_total: 0,
        };
        let mut hot = ui_process(2, Some(1), "worker", "/usr/bin/worker");
        hot.cpu = 34.2;
        hot.memory = 512 * 1024 * 1024;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                hot,
                ui_process(3, Some(1), "shell", "/bin/zsh"),
            ],
        );
        // Keep the detail pane on the idle shell so the hot worker's metrics
        // can only come from the tree columns.
        app.selected = app
            .visible
            .iter()
            .position(|row| row.pid == Pid::from_u32(3))
            .expect("shell should be visible");

        let wide = TestBackend::new(120, 20);
        let mut wide_terminal = Terminal::new(wide).unwrap();
        wide_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let wide_text = buffer_text(&wide_terminal);
        assert!(wide_text.contains("34.2"));
        assert!(wide_text.contains("512M"));
        let wide_border = buffer_row(&wide_terminal, 1);
        assert!(wide_border.contains("CPU%"));
        assert!(wide_border.contains("MEM"));

        let medium = TestBackend::new(90, 20);
        let mut medium_terminal = Terminal::new(medium).unwrap();
        medium_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let medium_text = buffer_text(&medium_terminal);
        assert!(medium_text.contains("34.2"));
        assert!(!medium_text.contains("512M"));
        let medium_border = buffer_row(&medium_terminal, 1);
        assert!(medium_border.contains("CPU%"));
        assert!(!medium_border.contains("MEM"));

        let narrow = TestBackend::new(70, 20);
        let mut narrow_terminal = Terminal::new(narrow).unwrap();
        narrow_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let narrow_text = buffer_text(&narrow_terminal);
        assert!(!narrow_text.contains("34.2"));
        assert!(!narrow_text.contains("512M"));
        assert!(!buffer_row(&narrow_terminal, 1).contains("CPU%"));
    }

    #[test]
    fn footer_hint_line_stays_short_in_both_languages() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        let backend = TestBackend::new(160, 30);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let english = buffer_text(&terminal);
        let english_row = english
            .lines()
            .find(|line| line.contains("p actions"))
            .expect("English footer should show the hint line");
        // Wide terminals merge stats and hints onto one row; measure only
        // the hint segment (from the first hint entry onward) so the length
        // budget still guards the hint text.
        let english_hint = english_row
            .find("Enter details")
            .map(|index| &english_row[index..])
            .unwrap_or(english_row);
        assert!(
            english_hint.trim_end().chars().count() <= 80,
            "English hint line too long: {english_hint:?}"
        );

        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        // The language-change confirmation notice overlays the footer.
        app.notice = None;
        // A fresh terminal avoids TestBackend's stale-cell artifacts when
        // English cells are replaced by narrower Chinese labels.
        let backend = TestBackend::new(160, 30);
        let mut chinese_terminal = Terminal::new(backend).unwrap();
        chinese_terminal
            .draw(|frame| draw(frame, &mut app))
            .unwrap();
        let chinese = buffer_text(&chinese_terminal);
        let chinese_row = chinese
            .lines()
            .find(|line| line.replace(' ', "").contains("p操作"))
            .expect("Chinese footer should show the hint line");
        // TestBackend pads wide CJK glyphs with blank continuation cells, so
        // anchor on the ASCII "Enter" rather than the spaced-out 详情.
        let chinese_hint = chinese_row
            .find("Enter")
            .map(|index| &chinese_row[index..])
            .unwrap_or(chinese_row);
        assert!(
            chinese_hint.trim_end().chars().count() <= 80,
            "Chinese hint line too long: {chinese_hint:?}"
        );
    }

    fn type_palette_query(app: &mut App, query: &str) {
        for character in query.chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE));
        }
    }

    #[test]
    fn colon_opens_the_command_palette_and_esc_closes_it() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        assert!(app.show_palette);
        assert!(app.palette_query.is_empty());
        // An empty query lists the full catalog.
        assert_eq!(app.palette_matches().len(), 30);

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let rendered = buffer_text(&terminal);
        assert!(rendered.contains("command palette"));
        assert!(rendered.contains("Memory attribution"));
        assert!(rendered.contains("Enter run"));

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.show_palette);
    }

    #[test]
    fn palette_query_fuzzy_matches_both_languages() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));

        type_palette_query(&mut app, "mem");
        let names: Vec<&str> = app
            .palette_matches()
            .iter()
            .map(|command| command.en_name)
            .collect();
        assert!(
            names.contains(&"Memory attribution"),
            "\"mem\" should match memory attribution: {names:?}"
        );

        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        // Chinese keywords match even while the UI is in English.
        type_palette_query(&mut app, "档案");
        let names: Vec<&str> = app
            .palette_matches()
            .iter()
            .map(|command| command.en_name)
            .collect();
        assert_eq!(names, vec!["Process dossier"]);

        // Backspace edits the query and resets the selection.
        app.on_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.palette_query, "档");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.show_palette);
    }

    #[test]
    fn palette_enter_executes_exactly_like_the_key() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        // events: same as pressing e on the bare tree.
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        type_palette_query(&mut app, "events");
        let quit = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!quit);
        assert!(!app.show_palette);
        assert!(app.show_events);
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.show_events);

        // language: same as pressing L.
        assert_eq!(app.language(), UiLanguage::English);
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        type_palette_query(&mut app, "language");
        let quit = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!quit);
        assert_eq!(app.language(), UiLanguage::Chinese);
        app.notice = None;
        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        assert_eq!(app.language(), UiLanguage::English);
    }

    #[test]
    fn palette_execution_closes_other_overlays_first() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        app.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(app.show_events);
        // The palette opens over the events overlay without touching it.
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        assert!(app.show_palette);
        assert!(app.show_events);

        type_palette_query(&mut app, "attention");
        let quit = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!quit);
        // Exclusivity: executing a workspace command closes the old overlay.
        assert!(app.show_attention);
        assert!(!app.show_events);
    }

    #[test]
    fn palette_q_closes_without_quitting_and_colon_is_text_in_search() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        assert!(app.show_palette);
        // Layered-q: q closes the palette layer, it does not quit psmore.
        let quit = app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!quit);
        assert!(!app.show_palette);

        // With a query typed, q is ordinary input instead.
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        type_palette_query(&mut app, "e");
        app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.show_palette);
        assert_eq!(app.palette_query, "eq");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        // While searching, `:` belongs to the search input.
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(app.searching);
        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        assert!(app.searching);
        assert!(!app.show_palette);
        assert_eq!(app.search_input, ":");
    }

    #[test]
    fn k_moves_selection_up_and_p_opens_the_action_dialog() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "worker", "/usr/bin/worker"),
            ],
        );
        app.selected = 2;

        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.selected, 1);
        assert!(app.process_action.is_none());
        app.on_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.selected, 2);
        assert!(app.process_action.is_none());

        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        let dialog = app.process_action.as_ref().expect("p should open a dialog");
        assert_eq!(dialog.actions(), &ProcessActionKind::ALL);
        assert_eq!(dialog.target.pid, Pid::from_u32(2));
        assert!(!app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(app.process_action.is_none());
    }

    fn apply_search(app: &mut App, query: &str) {
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        type_palette_query(app, query);
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    }

    fn click(column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn search_history_recalls_applied_queries_and_restores_the_draft() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "worker", "/usr/bin/worker"),
            ],
        );

        apply_search(&mut app, "name:worker");
        assert_eq!(app.search, "name:worker");
        apply_search(&mut app, "cpu>20");
        assert_eq!(app.query_history, vec!["cpu>20", "name:worker"]);

        // A cancelled query is not recorded.
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        type_palette_query(&mut app, "name:draft");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.query_history, vec!["cpu>20", "name:worker"]);

        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        type_palette_query(&mut app, "mem");
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.search_input, "cpu>20");
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.search_input, "name:worker");
        // Walking past the oldest entry stays on it.
        app.on_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(app.search_input, "name:worker");
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.search_input, "cpu>20");
        // Down past the newest entry returns to the in-progress draft.
        app.on_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
        assert_eq!(app.search_input, "mem");
        // The tree only changes once the query is applied.
        assert!(app.search.is_empty() || app.search == "cpu>20");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    }

    #[test]
    fn query_history_dedups_and_caps_at_twenty() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
            ],
        );

        apply_search(&mut app, "name:first");
        apply_search(&mut app, "name:second");
        apply_search(&mut app, "name:first");
        assert_eq!(app.query_history, vec!["name:first", "name:second"]);

        for index in 0..25 {
            apply_search(&mut app, &format!("pid:{index}"));
        }
        assert_eq!(app.query_history.len(), 20);
        assert_eq!(app.query_history[0], "pid:24");
        assert_eq!(app.query_history[19], "pid:5");
    }

    #[test]
    fn tab_completes_field_starters_and_cycles_candidates() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
            ],
        );

        // Empty token: Tab cycles through every field starter.
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.search_input, "name:");
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.search_input, "cmd:");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        // Mid-token partial: only candidates with that prefix, token replaced.
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        type_palette_query(&mut app, "us");
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.search_input, "user:");
        // Typing ends the cycle; the completed starter takes a value and the
        // finished query still parses.
        type_palette_query(&mut app, "joe");
        assert!(ProcessQuery::parse(&app.search_input).is_ok());
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

        // Completion replaces only the current token, keeping earlier terms.
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        type_palette_query(&mut app, "name:launchd cp");
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.search_input, "name:launchd cpu>");
        type_palette_query(&mut app, "20");
        assert!(ProcessQuery::parse(&app.search_input).is_ok());

        // A token that prefixes no starter is left alone.
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        type_palette_query(&mut app, "zzz");
        app.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.search_input, "zzz");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    }

    #[test]
    fn star_toggles_marker_and_survives_tree_rebuilds() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "worker", "/usr/bin/worker"),
            ],
        );
        app.selected = 2;

        app.on_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE));
        assert!(app.is_starred(Pid::from_u32(2)));
        assert_eq!(app.marks.len(), 1);

        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let worker_row = buffer_text(&terminal)
            .lines()
            .find(|line| line.contains("worker"))
            .expect("worker row should render")
            .to_string();
        assert!(worker_row.contains("★"), "starred row: {worker_row:?}");

        // A rebuild (here: cycling the sort mode) keeps the star.
        app.on_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
        assert!(app.is_starred(Pid::from_u32(2)));

        // Toggling again removes the star.
        app.on_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE));
        assert!(!app.is_starred(Pid::from_u32(2)));
        assert!(app.marks.is_empty());
    }

    #[test]
    fn reused_pid_does_not_inherit_the_star() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "worker", "/usr/bin/worker"),
            ],
        );
        app.selected = 2;
        app.on_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE));
        assert!(app.is_starred(Pid::from_u32(2)));

        // The PID comes back as a different instance (new start time): the
        // star must not follow the reused PID.
        app.processes
            .get_mut(&Pid::from_u32(2))
            .expect("worker is seeded")
            .start_time = 999;
        assert!(!app.is_starred(Pid::from_u32(2)));
    }

    #[test]
    fn quote_jumps_between_starred_processes_with_wrap_and_notices() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "alpha", "/usr/bin/alpha"),
                ui_process(3, Some(1), "beta", "/usr/bin/beta"),
                ui_process(4, Some(1), "gamma", "/usr/bin/gamma"),
            ],
        );

        // No stars yet: ' shows a bilingual notice instead of jumping.
        app.on_key(KeyEvent::new(KeyCode::Char('\''), KeyModifiers::NONE));
        let notice = app.notice.as_ref().expect("notice for empty star list");
        assert!(notice.message.contains("no starred processes"));
        assert!(!notice.is_error);

        // Star gamma (index 4) and alpha (index 2).
        app.selected = 4;
        app.on_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE));
        app.selected = 2;
        app.on_key(KeyEvent::new(KeyCode::Char('*'), KeyModifiers::NONE));

        // From alpha: next starred is gamma; from gamma it wraps to alpha.
        app.on_key(KeyEvent::new(KeyCode::Char('\''), KeyModifiers::NONE));
        assert_eq!(app.selected, 4);
        app.on_key(KeyEvent::new(KeyCode::Char('\''), KeyModifiers::NONE));
        assert_eq!(app.selected, 2);
    }

    fn network_fixture() -> NetworkScan {
        NetworkScan {
            endpoints: vec![
                NetworkEndpoint {
                    pid: Some(Pid::from_u32(2)),
                    process: "worker".into(),
                    fd: "12".into(),
                    protocol: "TCP".into(),
                    local_endpoint: "127.0.0.1:8080".into(),
                    remote_endpoint: String::new(),
                    state: "LISTEN".into(),
                    namespace: String::new(),
                },
                NetworkEndpoint {
                    pid: Some(Pid::from_u32(3)),
                    process: "sshd".into(),
                    fd: "5".into(),
                    protocol: "TCP".into(),
                    local_endpoint: "0.0.0.0:22".into(),
                    remote_endpoint: String::new(),
                    state: "LISTEN".into(),
                    namespace: String::new(),
                },
            ],
            warning: None,
        }
    }

    #[test]
    fn network_port_input_filters_selects_and_x_restores() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        app.show_network = true;
        app.network_scan = Some(network_fixture());

        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(app.network_port_input.as_deref(), Some(""));
        type_palette_query(&mut app, "8080");
        // Digits are the only accepted input.
        app.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert_eq!(app.network_port_input.as_deref(), Some("8080"));
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.network_port_filter, Some(8080));
        assert_eq!(app.network_port_input, None);
        let visible = app.network_visible_indices();
        assert_eq!(visible.len(), 1);
        assert_eq!(app.network_selected, 0);
        assert_eq!(
            app.network_scan.as_ref().unwrap().endpoints[visible[0]].local_endpoint,
            "127.0.0.1:8080"
        );

        // x clears the port filter together with the text filter.
        app.on_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert_eq!(app.network_port_filter, None);
        assert_eq!(app.network_visible_indices().len(), 2);

        // A port with no endpoint keeps the list and shows a notice.
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        type_palette_query(&mut app, "9");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.network_port_filter, None);
        let notice = app.notice.as_ref().expect("no-match notice");
        assert!(notice.message.contains("no endpoint on port 9"));
        assert_eq!(app.network_visible_indices().len(), 2);

        // Esc cancels the input and restores the unfiltered list.
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        type_palette_query(&mut app, "8080");
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.network_port_filter, Some(8080));
        app.on_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        type_palette_query(&mut app, "22");
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.network_port_input, None);
        assert_eq!(app.network_port_filter, None);
        assert_eq!(app.network_visible_indices().len(), 2);
    }

    #[test]
    fn palette_find_port_opens_network_with_port_input() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        app.on_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        type_palette_query(&mut app, "find port");
        let quit = app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!quit);
        assert!(app.show_network);
        assert_eq!(app.network_port_input.as_deref(), Some(""));
        // Clean up the background scan started by opening the workspace.
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        app.on_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!app.show_network);
    }

    #[test]
    fn mouse_click_selects_row_and_second_click_opens_inspection() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "alpha", "/usr/bin/alpha"),
                ui_process(3, Some(1), "beta", "/usr/bin/beta"),
                ui_process(4, Some(1), "gamma", "/usr/bin/gamma"),
            ],
        );
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();

        let area = app.tree_area;
        // Click the third visible row (index 2 = alpha): border row + offset.
        app.on_mouse(click(area.x + 3, area.y + 1 + 2));
        assert_eq!(app.selected, 2);
        assert_eq!(app.selected_pid(), Some(Pid::from_u32(2)));
        assert!(app.inspection.is_none());

        // Clicking the already-selected row acts like Enter.
        app.on_mouse(click(area.x + 3, area.y + 1 + 2));
        assert!(app.inspection.is_some());
        app.inspection = None;
        app.inspection_tab_regions.clear();

        // Clicks on the border or below the last row are ignored.
        app.on_mouse(click(area.x + 3, area.y));
        assert_eq!(app.selected, 2);
        app.on_mouse(click(area.x + 3, area.y + 1 + 5));
        assert_eq!(app.selected, 2);
    }

    #[test]
    fn mouse_wheel_moves_the_tree_selection() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "alpha", "/usr/bin/alpha"),
            ],
        );
        assert_eq!(app.selected, 0);
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 5,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.selected, 1);
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::ScrollUp,
            column: 5,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.selected, 0);
    }

    #[test]
    fn mouse_click_on_inspection_tab_bar_switches_tabs() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "worker", "/usr/bin/worker"),
            ],
        );
        app.selected = 2;
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.inspection.is_some());

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();

        assert_eq!(app.inspection_tab, InspectionTab::Overview);
        let (region, tab) = app
            .inspection_tab_regions
            .iter()
            .find(|(_, tab)| *tab == InspectionTab::Ports)
            .copied()
            .expect("ports tab region should be recorded");
        app.on_mouse(click(region.x + 1, region.y));
        assert_eq!(app.inspection_tab, InspectionTab::Ports);
        // Clicking the active tab again is a no-op but harmless.
        app.on_mouse(click(region.x + 1, region.y));
        assert_eq!(app.inspection_tab, InspectionTab::Ports);
        let _ = tab;
    }

    #[test]
    fn mouse_clicks_are_ignored_under_overlays() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(2, Some(1), "alpha", "/usr/bin/alpha"),
            ],
        );
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let area = app.tree_area;

        app.show_events = true;
        app.on_mouse(click(area.x + 3, area.y + 1 + 2));
        assert_eq!(app.selected, 0);
        app.show_events = false;

        // The wheel still works under overlays, scrolling like j/k.
        app.show_network = true;
        app.network_scan = Some(network_fixture());
        app.on_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 5,
            row: 5,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(app.network_selected, 1);
        app.show_network = false;
    }

    #[test]
    fn q_closes_overlays_and_only_quits_on_the_bare_tree() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        app.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(app.show_events);
        assert!(!app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(!app.show_events);

        app.on_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(app.show_attention);
        assert!(!app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
        assert!(!app.show_attention);

        assert!(app.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)));
    }

    #[test]
    fn d_without_baseline_shows_a_notice() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        assert!(app.baseline.is_none());

        app.on_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(!app.show_snapshot_diff);
        let notice = app.notice.as_ref().expect("d should explain itself");
        assert!(notice.message.contains("baseline"));

        app.on_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert!(app.baseline.is_some());
        app.on_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(app.show_snapshot_diff);
    }

    #[test]
    fn l_toggles_language_inside_overlays_but_f2_does_not() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        assert_eq!(app.language(), UiLanguage::English);

        app.on_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(app.show_events);
        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE));
        assert_eq!(app.language(), UiLanguage::Chinese);
        assert!(app.show_events);

        app.on_key(KeyEvent::new(KeyCode::F(2), KeyModifiers::NONE));
        assert_eq!(app.language(), UiLanguage::Chinese);
        assert!(app.show_events);
    }

    #[test]
    fn l_toggles_language_with_shift_modifier_but_not_ctrl() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        assert_eq!(app.language(), UiLanguage::English);

        // Real terminals report uppercase letters with the SHIFT modifier.
        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::SHIFT));
        assert_eq!(app.language(), UiLanguage::Chinese);
        app.on_key(KeyEvent::new(KeyCode::Char('L'), KeyModifiers::CONTROL));
        assert_eq!(app.language(), UiLanguage::Chinese);
    }

    #[test]
    fn trend_overlay_renders_bilingual_labels() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(42, Some(1), "worker", "/usr/bin/worker"),
            ],
        );
        for _ in 0..3 {
            app.history
                .record(&app.processes, &app.resources, Instant::now());
        }
        app.trend_pid = Some(Pid::from_u32(42));
        app.trend_view = TrendView::Io;

        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let english = buffer_text(&terminal);
        assert!(english.contains("trends worker [42]"));
        assert!(english.contains("READ self"));
        assert!(english.contains("WRITE tree"));
        assert!(english.contains("samples /"));
        assert!(!english.contains("读 自身"));

        app.guidance.set_language_for_test(UiLanguage::Chinese);
        // A fresh backend: TestBackend keeps stale symbols in the
        // continuation cells of wide CJK glyphs after a redraw.
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let chinese = buffer_text(&terminal);
        // TestBackend pads the continuation cell of every wide CJK glyph
        // with a blank, so compare Chinese substrings without whitespace.
        let compact: String = chinese.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(compact.contains("趋势worker[42]"));
        assert!(compact.contains("读自身"));
        assert!(compact.contains("写子树"));
        assert!(compact.contains("个样本"));
        assert!(compact.contains("当前"));
        assert!(!chinese.contains("READ self"));
        assert!(!chinese.contains("avg"));
    }

    #[test]
    fn snapshot_diff_overlay_renders_bilingual_labels() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                ui_process(1, Some(0), "launchd", "/sbin/launchd"),
                ui_process(42, Some(1), "worker", "/usr/bin/worker"),
            ],
        );
        app.baseline = Some(BaselineSnapshot::capture(
            &app.processes,
            &app.resources,
            Instant::now(),
        ));
        // One exit, one start, and memory growth on a survivor.
        let mut grown = ui_process(1, Some(0), "launchd", "/sbin/launchd");
        grown.memory = 64 * 1024 * 1024;
        seed_processes(
            &mut app,
            vec![
                ui_process(0, None, "kernel / system", ""),
                grown,
                ui_process(77, Some(1), "new-worker", "/usr/bin/new-worker"),
            ],
        );
        app.show_snapshot_diff = true;

        let backend = TestBackend::new(140, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let english = buffer_text(&terminal);
        assert!(english.contains("baseline diff"));
        assert!(english.contains("PROCESS CHANGES"));
        assert!(english.contains("started"));
        assert!(english.contains("parent"));
        assert!(english.contains("TOP TREE MEMORY GROWTH"));
        assert!(!english.contains("进程变化"));

        app.guidance.set_language_for_test(UiLanguage::Chinese);
        // A fresh backend: TestBackend keeps stale symbols in the
        // continuation cells of wide CJK glyphs after a redraw.
        let backend = TestBackend::new(140, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let chinese = buffer_text(&terminal);
        // TestBackend pads the continuation cell of every wide CJK glyph
        // with a blank, so compare Chinese substrings without whitespace.
        let compact: String = chinese.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(compact.contains("基线对比"));
        assert!(compact.contains("进程变化"));
        assert!(compact.contains("新增"));
        assert!(compact.contains("退出"));
        assert!(compact.contains("子树内存增长"));
        assert!(!chinese.contains("PROCESS CHANGES"));
        assert!(!chinese.contains("TOP TREE MEMORY GROWTH"));
    }

    #[test]
    fn footer_merges_stats_and_hints_on_one_line() {
        let mut app = App::new_for_test(Guidance::welcome_for_test());
        app.guidance.overlay = None;

        // Wide terminal: full stats and hints share the single footer row.
        let wide = TestBackend::new(160, 30);
        let mut wide_terminal = Terminal::new(wide).unwrap();
        wide_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let wide_row = buffer_row(&wide_terminal, 29);
        assert!(wide_row.contains("proc"), "stats lost: {wide_row:?}");
        assert!(wide_row.contains("page"), "page stats lost: {wide_row:?}");
        assert!(
            wide_row.contains("Enter details"),
            "hints lost: {wide_row:?}"
        );

        // Medium terminal: stats degrade to the compact form, hints stay.
        let medium = TestBackend::new(120, 30);
        let mut medium_terminal = Terminal::new(medium).unwrap();
        medium_terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let medium_row = buffer_row(&medium_terminal, 29);
        assert!(medium_row.contains("proc"), "stats lost: {medium_row:?}");
        assert!(
            medium_row.contains("Enter details"),
            "hints lost: {medium_row:?}"
        );

        // Narrow terminal: the hints own the whole line and are clipped in
        // place rather than pushed below the viewport.
        for (width, height) in [(40u16, 12u16), (28, 10)] {
            let backend = TestBackend::new(width, height);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            let hint_row = buffer_row(&terminal, height - 1);
            assert!(
                hint_row.contains("Enter details"),
                "hint line lost at {width} columns: {hint_row:?}"
            );
        }
    }

    #[test]
    fn compact_bytes_stay_within_five_cells() {
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;
        const TIB: u64 = GIB * 1024;
        const PIB: u64 = TIB * 1024;
        const EIB: u64 = PIB * 1024;
        let cases = [
            0,
            1,
            1023,
            KIB,
            MIB,
            512 * MIB,
            GIB,
            10 * GIB,
            99 * GIB,
            100 * GIB - 1,
            100 * GIB,
            TIB,
            100 * TIB - 1,
            100 * TIB,
            PIB,
            EIB,
            u64::MAX,
        ];
        for bytes in cases {
            let compact = format_compact_bytes(bytes);
            assert!(
                compact.chars().count() <= 5,
                "{bytes} rendered as {compact:?} ({} cells)",
                compact.chars().count()
            );
        }
        assert_eq!(format_compact_bytes(512 * MIB), "512M");
        assert_eq!(format_compact_bytes(13_000_000_000), "12.1G");
        assert_eq!(format_compact_bytes(100 * GIB - 1), "0.1T");
        assert_eq!(format_compact_bytes(u64::MAX), "16E");
    }
}
