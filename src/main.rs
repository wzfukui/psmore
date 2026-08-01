use std::{
    collections::{HashMap, HashSet},
    io,
    process::Command,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use sysinfo::{Pid, ProcessesToUpdate, System};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Clone, Debug)]
struct ProcessInfo {
    pid: Pid,
    parent: Option<Pid>,
    name: String,
    command: String,
    executable: String,
    cpu: f32,
    memory: u64,
    runtime: u64,
    status: String,
}

#[derive(Clone, Debug)]
struct TreeRow {
    pid: Pid,
    depth: usize,
    // For each ancestor, whether that ancestor is the last sibling.
    last_path: Vec<bool>,
    is_last: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MarqueePhase {
    Scrolling,
    TailPause,
    ResetPause,
}

trait ProcessProvider {
    fn refresh(&mut self) -> Vec<ProcessInfo>;
}

struct MacOsProcessProvider {
    system: System,
}

impl MacOsProcessProvider {
    fn new() -> Self {
        Self {
            system: System::new(),
        }
    }
}

impl ProcessProvider for MacOsProcessProvider {
    fn refresh(&mut self) -> Vec<ProcessInfo> {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
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
                cpu: process.cpu_usage(),
                memory: process.memory(),
                runtime: process.run_time(),
                status: format!("{:?}", process.status()),
            })
            .collect();

        let command_by_pid: HashMap<u32, String> = Command::new("ps")
            .args(["-ww", "-axo", "pid=,command="])
            .output()
            .ok()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter_map(|line| {
                        let mut fields = line.trim_start().splitn(2, char::is_whitespace);
                        let pid = fields.next()?.parse().ok()?;
                        let command = fields.next().unwrap_or("").trim().to_string();
                        Some((pid, command))
                    })
                    .collect()
            })
            .unwrap_or_default();
        for process in &mut processes {
            if let Some(command) = command_by_pid.get(&process.pid.as_u32()) {
                if !command.is_empty() {
                    process.command = command.clone();
                }
            }
        }

        // sysinfo can omit PPID for ordinary macOS readers.  The native ps
        // view is more reliable here, so use it as the macOS provider's
        // authoritative parent relationship.
        let ppid_by_pid: HashMap<u32, u32> = Command::new("ps")
            .args(["-axo", "pid=,ppid="])
            .output()
            .ok()
            .map(|output| {
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .filter_map(|line| {
                        let mut fields = line.split_whitespace();
                        Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
                    })
                    .collect()
            })
            .unwrap_or_default();

        // macOS may hide the parent of a process from an unprivileged reader.
        // Keep those processes under a synthetic PID 0 root so the tree remains
        // navigable and the missing relationship is explicit rather than lost.
        let root = Pid::from_u32(0);
        for process in &mut processes {
            process.parent = ppid_by_pid
                .get(&process.pid.as_u32())
                .copied()
                .map(Pid::from_u32)
                .or(process.parent)
                .or(Some(root));
        }
        processes.push(ProcessInfo {
            pid: root,
            parent: None,
            name: "kernel / system".into(),
            command: String::new(),
            executable: String::new(),
            cpu: 0.0,
            memory: 0,
            runtime: 0,
            status: "VirtualRoot".into(),
        });
        processes
    }
}

struct App {
    provider: MacOsProcessProvider,
    processes: HashMap<Pid, ProcessInfo>,
    children: HashMap<Option<Pid>, Vec<Pid>>,
    visible: Vec<TreeRow>,
    selected: usize,
    expanded: HashSet<Pid>,
    collapsed: HashSet<Pid>,
    search: String,
    searching: bool,
    focus: Option<Pid>,
    last_refresh: Instant,
    marquee_offset: usize,
    last_marquee: Instant,
    marquee_pid: Option<Pid>,
    marquee_phase: MarqueePhase,
    page_size: usize,
    error: Option<String>,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            provider: MacOsProcessProvider::new(),
            processes: HashMap::new(),
            children: HashMap::new(),
            visible: Vec::new(),
            selected: 0,
            expanded: HashSet::new(),
            collapsed: HashSet::new(),
            search: String::new(),
            searching: false,
            focus: None,
            last_refresh: Instant::now(),
            marquee_offset: 0,
            last_marquee: Instant::now(),
            marquee_pid: None,
            marquee_phase: MarqueePhase::Scrolling,
            page_size: 10,
            error: None,
        };
        app.refresh();
        app
    }

    fn refresh(&mut self) {
        self.processes = self
            .provider
            .refresh()
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        self.children.clear();
        for process in self.processes.values() {
            self.children
                .entry(process.parent)
                .or_default()
                .push(process.pid);
        }
        for children in self.children.values_mut() {
            // Name groups remain readable, while PID makes the order
            // deterministic across refreshes and for same-named processes.
            children.sort_by_key(|pid| {
                self.processes
                    .get(pid)
                    .map(|p| (p.name.to_lowercase(), pid.as_u32()))
            });
        }
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
        self.last_refresh = Instant::now();
        self.error = None;
    }

    fn rebuild_visible(&mut self) {
        let old_pid = self.visible.get(self.selected).map(|row| row.pid);
        self.visible.clear();
        let matched: HashSet<Pid> = self
            .processes
            .values()
            .filter(|p| {
                self.search.is_empty()
                    || format!("{} {} {}", p.name, p.command, p.pid)
                        .to_lowercase()
                        .contains(&self.search.to_lowercase())
            })
            .map(|p| p.pid)
            .collect();

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
            self.walk_children(focus, chain.len(), vec![false; chain.len()], &matched);
        } else {
            let roots = vec![Pid::from_u32(0)];
            for (index, pid) in roots.iter().enumerate() {
                self.walk(*pid, Vec::new(), index == roots.len() - 1, &matched);
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

    fn walk(&mut self, pid: Pid, last_path: Vec<bool>, is_last: bool, matched: &HashSet<Pid>) {
        let has_match = matched.contains(&pid);
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        let descendant_match = descendants
            .iter()
            .any(|child| self.has_matching_descendant(*child, matched));
        if has_match || descendant_match || self.search.is_empty() {
            let depth = last_path.len();
            self.visible.push(TreeRow {
                pid,
                depth,
                last_path: last_path.clone(),
                is_last,
            });
            if self.expanded.contains(&pid)
                || (!self.search.is_empty() && descendant_match && !self.collapsed.contains(&pid))
            {
                for (index, child) in descendants.iter().enumerate() {
                    let mut child_path = last_path.clone();
                    child_path.push(is_last);
                    self.walk(*child, child_path, index == descendants.len() - 1, matched);
                }
            }
        }
    }

    fn walk_children(
        &mut self,
        pid: Pid,
        depth: usize,
        last_path: Vec<bool>,
        matched: &HashSet<Pid>,
    ) {
        let descendants = self.children.get(&Some(pid)).cloned().unwrap_or_default();
        for (index, child) in descendants.iter().enumerate() {
            if matched.contains(child)
                || self.search.is_empty()
                || self.has_matching_descendant(*child, matched)
            {
                let mut child_path = last_path.clone();
                child_path.push(index == descendants.len() - 1);
                self.visible.push(TreeRow {
                    pid: *child,
                    depth,
                    last_path: child_path.clone(),
                    is_last: index == descendants.len() - 1,
                });
                if self.expanded.contains(child)
                    || (self.search.is_empty() && !self.collapsed.contains(child))
                    || (!self.search.is_empty()
                        && self.has_matching_descendant(*child, matched)
                        && !self.collapsed.contains(child))
                {
                    self.walk_children(*child, depth + 1, child_path, matched);
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

    fn selected_pid(&self) -> Option<Pid> {
        self.visible.get(self.selected).map(|row| row.pid)
    }

    fn selected_context(&self) -> Option<String> {
        let pid = self.selected_pid()?;
        let process = self.processes.get(&pid)?;
        Some(process_path(process))
    }

    fn advance_marquee(&mut self, width: usize) {
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
        let query = self.search.to_lowercase();
        if let Some(index) = self.visible.iter().position(|row| {
            self.processes
                .get(&row.pid)
                .map(|p| {
                    format!("{} {} {}", p.name, p.command, p.pid)
                        .to_lowercase()
                        .contains(&query)
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

    fn toggle_selected_expanded(&mut self) {
        if let Some(pid) = self.selected_pid() {
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

    fn finish_search(&mut self) {
        if !self.searching {
            return;
        }
        self.searching = false;
        self.search.clear();
        self.rebuild_visible();
    }

    fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }
        if self.searching {
            match key.code {
                KeyCode::Esc => {
                    self.searching = false;
                    self.search.clear();
                    self.rebuild_visible();
                }
                KeyCode::Enter => {
                    // `/` is a transient locator. Keep the selected process,
                    // then restore the complete tree for relationship work.
                    self.finish_search();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.move_selection(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.move_selection(-1);
                }
                KeyCode::PageDown => {
                    self.move_selection(self.page_size as isize);
                }
                KeyCode::PageUp => {
                    self.move_selection(-(self.page_size as isize));
                }
                KeyCode::Left => {
                    self.reveal_parent();
                }
                KeyCode::Right => {
                    self.toggle_selected_expanded();
                }
                KeyCode::Backspace => {
                    self.search.pop();
                    self.rebuild_visible();
                }
                KeyCode::Char(c) if key.modifiers.is_empty() => {
                    self.search.push(c);
                    self.rebuild_visible();
                    self.select_first_match();
                }
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
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
                self.search.clear();
            }
            KeyCode::Char('f') => self.toggle_focus(),
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        false
    }
}

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

fn process_path(process: &ProcessInfo) -> String {
    if !process.executable.is_empty() {
        process.executable.clone()
    } else if let Some(first) = process.command.split_whitespace().next() {
        first.to_string()
    } else {
        "system root".into()
    }
}

fn process_command_line(process: &ProcessInfo) -> String {
    if !process.command.is_empty() {
        process.command.clone()
    } else {
        process_path(process)
    }
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
    (text.width().max(1) + width - 1) / width
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
    let content_lines = 1 + wrapped_lines(&command, width);
    let desired = (content_lines + 2).max(4) as u16;
    desired.min(area.height.saturating_sub(4).max(4))
}

fn draw(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let detail_height = detail_height(app, area);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(detail_height),
            Constraint::Length(1),
        ])
        .split(area);
    app.page_size = chunks[0].height.saturating_sub(2).max(1) as usize;
    let title = match (&app.focus, app.searching) {
        (Some(pid), true) => format!(" psmore  focus={}  search: {}", pid, app.search),
        (Some(pid), false) if !app.search.is_empty() => {
            format!(" psmore  focus={}  filter: {}", pid, app.search)
        }
        (Some(pid), false) => format!(" psmore  focus={} ", pid),
        (None, true) => format!(" psmore  search: {}", app.search),
        (None, false) if !app.search.is_empty() => format!(" psmore  filter: {}", app.search),
        (None, false) => " psmore  macOS process relationships ".into(),
    };
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
        let mut detail_lines = vec![Line::from(vec![
            Span::styled(
                format!("PID {}", pid),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  PPID {}  children {}  status {}  CPU {:.1}%  MEM {} MB  runtime {}s",
                p.parent
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                children,
                p.status,
                p.cpu,
                p.memory / 1024 / 1024,
                p.runtime
            )),
        ])];
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
    let total_pages = (app.visible.len() + app.page_size - 1) / app.page_size;
    let total_pages = total_pages.max(1);
    let current_page = (app.selected / app.page_size + 1).min(total_pages);
    let footer = Paragraph::new(Line::from(format!(
        " {} proc | page {}/{} | ↑↓/jk move | PgUp/Dn page | ←/→ tree | / find | q quit ",
        total_processes, current_page, total_pages
    )))
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, chunks[2]);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let result = loop {
        terminal.draw(|frame| draw(frame, &mut app))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if app.on_key(key) {
                    break Ok(());
                }
            }
        }
        if app.last_refresh.elapsed() >= Duration::from_secs(2) {
            app.refresh();
        }
    };
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
