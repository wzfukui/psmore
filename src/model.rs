use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use sysinfo::Pid;

pub(crate) fn sanitize_terminal_text(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] == '\\' {
            let slash_start = index;
            while index < characters.len() && characters[index] == '\\' {
                index += 1;
            }
            let slash_count = index - slash_start;
            let escaped_whitespace = characters
                .get(index..index.saturating_add(3))
                .map(|digits| matches!(digits, ['0', '1', '1' | '2' | '5']))
                .unwrap_or(false);
            if slash_count % 2 == 1 && escaped_whitespace {
                output.extend(std::iter::repeat_n('\\', slash_count - 1));
                output.push(' ');
                index += 3;
                continue;
            }
            output.extend(std::iter::repeat_n('\\', slash_count));
            continue;
        }
        let character = characters[index];
        output.push(match character {
            '\n' | '\r' | '\t' => ' ',
            character if character.is_control() => '\u{fffd}',
            character => character,
        });
        index += 1;
    }
    output
}

static REDACT_OUTPUT_SECRETS: AtomicBool = AtomicBool::new(false);
const REDACTED: &str = "[REDACTED]";

pub(crate) fn set_output_secret_redaction(enabled: bool) {
    REDACT_OUTPUT_SECRETS.store(enabled, Ordering::Relaxed);
}

pub(crate) fn output_secret_redaction_enabled() -> bool {
    REDACT_OUTPUT_SECRETS.load(Ordering::Relaxed)
}

pub(crate) fn command_for_output(value: &str) -> String {
    if output_secret_redaction_enabled() {
        redact_command_secrets(value)
    } else {
        value.to_string()
    }
}

pub(crate) fn process_command_for_output(process: &ProcessInfo) -> String {
    command_for_output(&process_command_line(process))
}

fn command_token_ranges(value: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if start.is_none() {
            if character.is_whitespace() {
                continue;
            }
            start = Some(index);
        }
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        match quote {
            Some(active) if character == active => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character.is_whitespace() => {
                if let Some(start) = start.take() {
                    ranges.push((start, index));
                }
            }
            None => {}
        }
    }
    if let Some(start) = start {
        ranges.push((start, value.len()));
    }
    ranges
}

fn whitespace_token_ranges(value: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut start = None;
    for (index, character) in value.char_indices() {
        if character.is_whitespace() {
            if let Some(start) = start.take() {
                ranges.push((start, index));
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(start) = start {
        ranges.push((start, value.len()));
    }
    ranges
}

fn unquoted(value: &str) -> &str {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if matches!(first, b'\'' | b'"') && first == last {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn normalized_secret_key(value: &str) -> String {
    value
        .trim_matches(['\'', '"'])
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-")
}

fn is_secret_key(value: &str) -> bool {
    let key = normalized_secret_key(value);
    matches!(
        key.as_str(),
        "password"
            | "passwd"
            | "passphrase"
            | "token"
            | "api-key"
            | "apikey"
            | "access-token"
            | "refresh-token"
            | "id-token"
            | "secret"
            | "client-secret"
            | "secret-key"
            | "access-key"
            | "private-key"
            | "authorization"
            | "auth-token"
            | "auth"
            | "cookie"
            | "session-token"
            | "credential"
    ) || key.ends_with("-password")
        || key.ends_with("-passwd")
        || key.ends_with("-token")
        || key.ends_with("-api-key")
        || key.ends_with("-secret")
        || key.ends_with("-secret-key")
        || key.ends_with("-access-key")
}

fn redacted_token(value: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if matches!(first, b'\'' | b'"') && first == last {
            let quote = first as char;
            return format!("{quote}{REDACTED}{quote}");
        }
    }
    REDACTED.into()
}

fn redact_assignment(value: &str) -> Option<String> {
    let inner = unquoted(value);
    let assignment = inner.find('=')?;
    if inner[..assignment]
        .chars()
        .any(|character| matches!(character, '?' | '&'))
        || inner[..assignment].contains("://")
    {
        return None;
    }
    if !is_secret_key(&inner[..assignment]) {
        return None;
    }
    let assignment = value.find('=')?;
    let prefix = &value[..=assignment];
    let assigned_value = &value[assignment + 1..];
    if assigned_value.len() >= 2 {
        let first = assigned_value.as_bytes()[0];
        let last = assigned_value.as_bytes()[assigned_value.len() - 1];
        if matches!(first, b'\'' | b'"') && first == last {
            let quote = first as char;
            return Some(format!("{prefix}{quote}{REDACTED}{quote}"));
        }
    }
    let trailing_quote = value
        .chars()
        .last()
        .filter(|quote| matches!(quote, '\'' | '"') && value.starts_with(*quote));
    Some(match trailing_quote {
        Some(quote) => format!("{prefix}{REDACTED}{quote}"),
        None => format!("{prefix}{REDACTED}"),
    })
}

fn redact_header(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    for header in [
        "authorization:",
        "proxy-authorization:",
        "cookie:",
        "x-api-key:",
    ] {
        if let Some(start) = lower.find(header) {
            let end = start + header.len();
            let trailing_quote = value
                .chars()
                .last()
                .filter(|quote| matches!(quote, '\'' | '"') && value.starts_with(*quote));
            return match trailing_quote {
                Some(quote) => format!("{}{REDACTED}{quote}", &value[..end]),
                None => format!("{}{REDACTED}", &value[..end]),
            };
        }
    }
    value.to_string()
}

fn redact_url_userinfo(value: &str) -> String {
    let mut output = value.to_string();
    let mut cursor = 0;
    while let Some(relative_scheme) = output[cursor..].find("://") {
        let authority_start = cursor + relative_scheme + 3;
        let authority_end = output[authority_start..]
            .char_indices()
            .find(|(_, character)| {
                matches!(character, '/' | '?' | '#' | '\'' | '"') || character.is_whitespace()
            })
            .map(|(index, _)| authority_start + index)
            .unwrap_or(output.len());
        let authority = &output[authority_start..authority_end];
        let Some(at) = authority.rfind('@') else {
            cursor = authority_end;
            continue;
        };
        let Some(colon) = authority[..at].rfind(':') else {
            cursor = authority_end;
            continue;
        };
        let secret_start = authority_start + colon + 1;
        let secret_end = authority_start + at;
        output.replace_range(secret_start..secret_end, REDACTED);
        cursor = secret_start + REDACTED.len() + 1;
    }
    output
}

fn redact_url_query(value: &str) -> String {
    let mut output = value.to_string();
    let mut cursor = 0;
    while cursor < output.len() {
        let Some(relative_start) = output[cursor..].find(['?', '&']) else {
            break;
        };
        let key_start = cursor + relative_start + 1;
        let Some(relative_equals) = output[key_start..].find('=') else {
            break;
        };
        let equals = key_start + relative_equals;
        let key = &output[key_start..equals];
        let value_start = equals + 1;
        let value_end = output[value_start..]
            .char_indices()
            .find(|(_, character)| {
                matches!(character, '&' | '#' | '\'' | '"') || character.is_whitespace()
            })
            .map(|(index, _)| value_start + index)
            .unwrap_or(output.len());
        if is_secret_key(key) {
            output.replace_range(value_start..value_end, REDACTED);
            cursor = value_start + REDACTED.len();
        } else {
            cursor = value_end.max(value_start);
        }
    }
    output
}

fn redact_token_ranges(value: &str, ranges: Vec<(usize, usize)>) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_end = 0;
    let mut redact_next = false;
    for (start, end) in ranges {
        output.push_str(&value[previous_end..start]);
        let token = &value[start..end];
        let rendered = if redact_next {
            redact_next = false;
            redacted_token(token)
        } else if let Some(redacted) = redact_assignment(token) {
            redacted
        } else {
            let flag = unquoted(token);
            if !flag.contains('=') && is_secret_key(flag) {
                redact_next = true;
            }
            let token = redact_header(token);
            let token = redact_url_userinfo(&token);
            redact_url_query(&token)
        };
        output.push_str(&rendered);
        previous_end = end;
    }
    output.push_str(&value[previous_end..]);
    output
}

fn redact_embedded_assignments(value: &str) -> String {
    let mut output = value.to_string();
    let mut cursor = 0_usize;
    while cursor < output.len() {
        let Some(relative_equals) = output[cursor..].find('=') else {
            break;
        };
        let equals = cursor + relative_equals;
        let key_start = output[..equals]
            .char_indices()
            .rev()
            .take_while(|(_, character)| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
            })
            .last()
            .map(|(index, _)| index)
            .unwrap_or(equals);
        if key_start == equals || !is_secret_key(&output[key_start..equals]) {
            cursor = equals + 1;
            continue;
        }
        let value_start = equals + 1;
        if value_start >= output.len() {
            break;
        }
        let first = output[value_start..].chars().next();
        let (secret_start, secret_end) = match first {
            Some(quote @ ('\'' | '"')) => {
                let secret_start = value_start + quote.len_utf8();
                let secret_end = output[secret_start..]
                    .find(quote)
                    .map(|relative| secret_start + relative)
                    .unwrap_or(output.len());
                (secret_start, secret_end)
            }
            Some(_) => {
                let secret_end = output[value_start..]
                    .char_indices()
                    .find(|(_, character)| {
                        character.is_whitespace()
                            || matches!(character, '&' | '#' | '\'' | '"' | ';')
                    })
                    .map(|(relative, _)| value_start + relative)
                    .unwrap_or(output.len());
                (value_start, secret_end)
            }
            None => break,
        };
        if secret_start < secret_end && &output[secret_start..secret_end] != REDACTED {
            output.replace_range(secret_start..secret_end, REDACTED);
            cursor = secret_start + REDACTED.len();
        } else {
            cursor = secret_end.max(equals + 1);
        }
    }
    output
}

pub(crate) fn redact_command_secrets(value: &str) -> String {
    let structured = redact_token_ranges(value, command_token_ranges(value));
    // Process APIs expose argv as a reconstructed display string, not a shell
    // source line. Embedded code (for example `python -c`) can therefore make
    // quote characters look unbalanced. A second, conservative pass ignores
    // quote state so later standalone secret flags cannot escape redaction.
    let ranges = whitespace_token_ranges(&structured);
    let conservative = redact_token_ranges(&structured, ranges);
    redact_embedded_assignments(&conservative)
}

#[cfg(test)]
mod terminal_text_tests {
    use super::{redact_command_secrets, sanitize_terminal_text};

    #[test]
    fn normalizes_controls_and_ps_octal_whitespace_escapes() {
        assert_eq!(
            sanitize_terminal_text("one\\012two\nthree\\011four\tfive\\015six"),
            "one two three four five six"
        );
        assert_eq!(sanitize_terminal_text("bad\u{7}text"), "bad\u{fffd}text");
        assert_eq!(
            sanitize_terminal_text(r"literal\\012value"),
            r"literal\\012value"
        );
    }

    #[test]
    fn redacts_secret_flags_assignments_headers_urls_and_query_values() {
        let command = "server --password hunter2 --token='abc def' OPENAI_API_KEY=sk-live \
            relay+tls://user:pass@host:443/api?access_token=url-token&mode=fast \
            --header=\"Authorization: Bearer header-token\" --port 8080";
        let redacted = redact_command_secrets(command);
        for secret in ["hunter2", "abc def", "sk-live", "url-token", "header-token"] {
            assert!(
                !redacted.contains(secret),
                "secret remained visible: {secret}"
            );
        }
        assert!(!redacted.contains("user:pass@"));
        assert!(redacted.contains("--password [REDACTED]"));
        assert!(redacted.contains("--token='[REDACTED]'"));
        assert!(redacted.contains("OPENAI_API_KEY=[REDACTED]"));
        assert!(redacted.contains("relay+tls://user:[REDACTED]@host:443"));
        assert!(redacted.contains("access_token=[REDACTED]&mode=fast"));
        assert!(redacted.contains("Authorization:[REDACTED]"));
        assert!(redacted.contains("--port 8080"));
    }

    #[test]
    fn preserves_non_secret_arguments_and_handles_unterminated_quotes() {
        assert_eq!(
            redact_command_secrets(
                "api --user deploy --path '/srv/my app' --password 'open secret"
            ),
            "api --user deploy --path '/srv/my app' --password [REDACTED]"
        );
        assert_eq!(
            redact_command_secrets("curl https://example.test/?page=2&sort=name"),
            "curl https://example.test/?page=2&sort=name"
        );
        let reconstructed =
            "python3 -c \"print('unterminated) --password hidden-one --token=hidden-two";
        let redacted = redact_command_secrets(reconstructed);
        assert!(!redacted.contains("hidden-one"));
        assert!(!redacted.contains("hidden-two"));
        assert!(redacted.contains("--password [REDACTED]"));
        assert!(redacted.contains("--token=[REDACTED]"));
        let embedded = redact_command_secrets(
            "python -c code-fragment--token=hidden-three;next OPENAI_API_KEY='hidden four'",
        );
        assert!(!embedded.contains("hidden-three"));
        assert!(!embedded.contains("hidden four"));
        assert!(embedded.contains("code-fragment--token=[REDACTED]"));
        assert!(embedded.contains("OPENAI_API_KEY='[REDACTED]'"));
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessInfo {
    pub(crate) pid: Pid,
    pub(crate) parent: Option<Pid>,
    pub(crate) name: String,
    pub(crate) command: String,
    pub(crate) executable: String,
    pub(crate) user: String,
    pub(crate) cwd: String,
    pub(crate) cpu: f32,
    pub(crate) memory: u64,
    pub(crate) read_rate: u64,
    pub(crate) write_rate: u64,
    pub(crate) start_time: u64,
    pub(crate) runtime: u64,
    pub(crate) status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ProcessChange {
    Started {
        pid: Pid,
        name: String,
        command: String,
        parent: Option<Pid>,
    },
    Exited {
        pid: Pid,
        name: String,
        command: String,
    },
    Reparented {
        pid: Pid,
        name: String,
        command: String,
        old_parent: Option<Pid>,
        new_parent: Option<Pid>,
    },
}

impl ProcessChange {
    pub(crate) fn pid(&self) -> Pid {
        match self {
            Self::Started { pid, .. } | Self::Exited { pid, .. } | Self::Reparented { pid, .. } => {
                *pid
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessEvent {
    pub(crate) change: ProcessChange,
    pub(crate) observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ChangeSummary {
    pub(crate) started: usize,
    pub(crate) exited: usize,
    pub(crate) reparented: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct StatusNotice {
    pub(crate) message: String,
    pub(crate) is_error: bool,
    pub(crate) observed_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AttentionSeverity {
    Watch,
    Warning,
    Critical,
}

impl AttentionSeverity {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Watch => "WATCH",
            Self::Warning => "WARN",
            Self::Critical => "CRIT",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AttentionFinding {
    pub(crate) pid: Pid,
    pub(crate) severity: AttentionSeverity,
    pub(crate) score: u16,
    pub(crate) reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct OpenFileInfo {
    pub(crate) fd: String,
    pub(crate) kind: String,
    pub(crate) access: String,
    pub(crate) name: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SocketInfo {
    pub(crate) fd: String,
    pub(crate) protocol: String,
    pub(crate) endpoint: String,
    pub(crate) state: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct InspectionField {
    pub(crate) label: String,
    pub(crate) value: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ThreadInfo {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) state: String,
    pub(crate) cpu_percent: f32,
    pub(crate) priority: i32,
    pub(crate) nice: Option<i32>,
    pub(crate) processor: Option<i32>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProcessInspection {
    pub(crate) pid: Pid,
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) cwd: String,
    pub(crate) runtime: Vec<InspectionField>,
    pub(crate) security: Vec<InspectionField>,
    pub(crate) namespaces: Vec<InspectionField>,
    pub(crate) limits: Vec<InspectionField>,
    pub(crate) threads: Vec<ThreadInfo>,
    pub(crate) thread_count: usize,
    pub(crate) thread_sample_ms: u64,
    pub(crate) thread_truncated: bool,
    pub(crate) thread_warning: Option<String>,
    pub(crate) sockets: Vec<SocketInfo>,
    pub(crate) files: Vec<OpenFileInfo>,
    pub(crate) warning: Option<String>,
}

impl Default for ProcessInspection {
    fn default() -> Self {
        Self {
            pid: Pid::from_u32(0),
            name: String::new(),
            user: String::new(),
            cwd: String::new(),
            runtime: Vec::new(),
            security: Vec::new(),
            namespaces: Vec::new(),
            limits: Vec::new(),
            threads: Vec::new(),
            thread_count: 0,
            thread_sample_ms: 0,
            thread_truncated: false,
            thread_warning: None,
            sockets: Vec::new(),
            files: Vec::new(),
            warning: None,
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Debug, Default)]
pub(crate) struct LsofFileRecord {
    pub(crate) fd: String,
    pub(crate) kind: String,
    pub(crate) access: String,
    pub(crate) name: String,
    pub(crate) protocol: String,
    pub(crate) state: String,
}

fn process_instance_changed(old: &ProcessInfo, new: &ProcessInfo) -> bool {
    old.start_time != 0 && new.start_time != 0 && old.start_time != new.start_time
}

pub(crate) fn diff_processes(
    previous: &HashMap<Pid, ProcessInfo>,
    current: &HashMap<Pid, ProcessInfo>,
) -> Vec<ProcessChange> {
    let root = Pid::from_u32(0);
    let mut pids: Vec<Pid> = previous.keys().chain(current.keys()).copied().collect();
    pids.sort_by_key(|pid| pid.as_u32());
    pids.dedup();

    let mut changes = Vec::new();
    for pid in pids {
        if pid == root {
            continue;
        }
        match (previous.get(&pid), current.get(&pid)) {
            (None, Some(process)) => changes.push(ProcessChange::Started {
                pid,
                name: process.name.clone(),
                command: process_command_line(process),
                parent: process.parent,
            }),
            (Some(process), None) => changes.push(ProcessChange::Exited {
                pid,
                name: process.name.clone(),
                command: process_command_line(process),
            }),
            (Some(old), Some(new)) if process_instance_changed(old, new) => {
                changes.push(ProcessChange::Exited {
                    pid,
                    name: old.name.clone(),
                    command: process_command_line(old),
                });
                changes.push(ProcessChange::Started {
                    pid,
                    name: new.name.clone(),
                    command: process_command_line(new),
                    parent: new.parent,
                });
            }
            (Some(old), Some(new)) if old.parent != new.parent => {
                changes.push(ProcessChange::Reparented {
                    pid,
                    name: new.name.clone(),
                    command: process_command_line(new),
                    old_parent: old.parent,
                    new_parent: new.parent,
                });
            }
            _ => {}
        }
    }
    changes
}

#[derive(Clone, Debug)]
pub(crate) struct TreeRow {
    pub(crate) pid: Pid,
    pub(crate) depth: usize,
    // For each ancestor, whether that ancestor is the last sibling.
    pub(crate) last_path: Vec<bool>,
    pub(crate) is_last: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MarqueePhase {
    Scrolling,
    TailPause,
    ResetPause,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ResourceAggregate {
    pub(crate) cpu: f32,
    pub(crate) memory: u64,
    pub(crate) read_rate: u64,
    pub(crate) write_rate: u64,
    pub(crate) process_count: usize,
}

impl ResourceAggregate {
    pub(crate) fn add(&mut self, other: Self) {
        self.cpu += other.cpu;
        self.memory = self.memory.saturating_add(other.memory);
        self.read_rate = self.read_rate.saturating_add(other.read_rate);
        self.write_rate = self.write_rate.saturating_add(other.write_rate);
        self.process_count = self.process_count.saturating_add(other.process_count);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum SortMode {
    #[default]
    Stable,
    SubtreeCpu,
    SubtreeMemory,
    SubtreeRead,
    SubtreeWrite,
}

impl SortMode {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Stable => Self::SubtreeCpu,
            Self::SubtreeCpu => Self::SubtreeMemory,
            Self::SubtreeMemory => Self::SubtreeRead,
            Self::SubtreeRead => Self::SubtreeWrite,
            Self::SubtreeWrite => Self::Stable,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::SubtreeCpu => "hot CPU",
            Self::SubtreeMemory => "hot MEM",
            Self::SubtreeRead => "hot READ",
            Self::SubtreeWrite => "hot WRITE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum TrendView {
    #[default]
    Compute,
    Io,
}

impl TrendView {
    pub(crate) fn toggle(&mut self) {
        *self = match self {
            Self::Compute => Self::Io,
            Self::Io => Self::Compute,
        };
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Compute => "CPU/MEM",
            Self::Io => "I/O",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum HotspotMetric {
    #[default]
    Cpu,
    Memory,
    Read,
    Write,
}

impl HotspotMetric {
    pub(crate) const ALL: [Self; 4] = [Self::Cpu, Self::Memory, Self::Read, Self::Write];

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Cpu => Self::Memory,
            Self::Memory => Self::Read,
            Self::Read => Self::Write,
            Self::Write => Self::Cpu,
        }
    }

    pub(crate) fn previous(self) -> Self {
        match self {
            Self::Cpu => Self::Write,
            Self::Memory => Self::Cpu,
            Self::Read => Self::Memory,
            Self::Write => Self::Read,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Cpu => "CPU",
            Self::Memory => "MEMORY",
            Self::Read => "DISK READ",
            Self::Write => "DISK WRITE",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum HotspotScope {
    #[default]
    Process,
    Subtree,
}

impl HotspotScope {
    pub(crate) fn toggle(&mut self) {
        *self = match self {
            Self::Process => Self::Subtree,
            Self::Subtree => Self::Process,
        };
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Process => "process self",
            Self::Subtree => "service subtree",
        }
    }
}

pub(crate) fn process_path(process: &ProcessInfo) -> String {
    if !process.executable.is_empty() {
        process.executable.clone()
    } else if let Some(first) = process.command.split_whitespace().next() {
        first.to_string()
    } else if process.pid.as_u32() == 0 {
        "system root".into()
    } else {
        "[path unavailable]".into()
    }
}

pub(crate) fn process_command_line(process: &ProcessInfo) -> String {
    if !process.command.is_empty() {
        process.command.clone()
    } else {
        process_path(process)
    }
}
