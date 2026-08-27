use ratatui::style::{Color, Modifier, Style};
use serde::{Deserialize, Serialize};

use crate::model::AttentionSeverity;

/// Named color schemes. `dark` reproduces the historical hardcoded palette
/// exactly; `light` keeps the same semantics readable on light terminal
/// backgrounds; `high-contrast` maximizes legibility with pure black/white
/// pairs and inverted severity chips.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ThemeId {
    #[default]
    Dark,
    Light,
    HighContrast,
}

impl ThemeId {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Dark => Self::Light,
            Self::Light => Self::HighContrast,
            Self::HighContrast => Self::Dark,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Dark => "dark",
            Self::Light => "light",
            Self::HighContrast => "high-contrast",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "high-contrast" | "high_contrast" | "highcontrast" => Some(Self::HighContrast),
            _ => None,
        }
    }

    pub(crate) fn theme(self) -> Theme {
        match self {
            Self::Dark => Theme::dark(),
            Self::Light => Theme::light(),
            Self::HighContrast => Theme::high_contrast(),
        }
    }
}

/// Core palette for the main screen and the major overlays. Decorative
/// one-off colors (sparkline series, hotspot panel identity colors, per-action
/// signal colors) intentionally stay hardcoded at their call sites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Theme {
    pub(crate) selection_fg: Color,
    pub(crate) selection_bg: Color,
    /// Accent for labels, section headers, and the status-bar labels.
    pub(crate) accent: Color,
    pub(crate) border_focused: Color,
    pub(crate) border_unfocused: Color,
    pub(crate) tree_fg: Color,
    pub(crate) dim: Color,
    pub(crate) muted: Color,
    pub(crate) severity_crit: Color,
    pub(crate) severity_warn: Color,
    pub(crate) severity_watch: Color,
    pub(crate) severity_info: Color,
    pub(crate) hot_warn: Color,
    pub(crate) hot_crit: Color,
    pub(crate) started_fg: Color,
    pub(crate) reparented_fg: Color,
    pub(crate) sibling_fg: Color,
    pub(crate) sibling_bg: Color,
    pub(crate) notice_success: Style,
    pub(crate) notice_error: Style,
    /// Inverted severity chips (black text on the severity color) for the
    /// high-contrast preset; dark/light use a plain foreground.
    severity_inverted: bool,
}

impl Theme {
    /// The historical hardcoded palette. Rendering with this theme must be
    /// pixel-identical to the pre-theme code.
    pub(crate) fn dark() -> Self {
        Self {
            selection_fg: Color::White,
            selection_bg: Color::Blue,
            accent: Color::Cyan,
            border_focused: Color::LightCyan,
            border_unfocused: Color::DarkGray,
            tree_fg: Color::White,
            dim: Color::DarkGray,
            muted: Color::Gray,
            severity_crit: Color::LightRed,
            severity_warn: Color::Yellow,
            severity_watch: Color::LightBlue,
            severity_info: Color::LightGreen,
            hot_warn: Color::Yellow,
            hot_crit: Color::LightRed,
            started_fg: Color::LightGreen,
            reparented_fg: Color::LightYellow,
            sibling_fg: Color::Cyan,
            sibling_bg: Color::Rgb(0, 64, 72),
            notice_success: Style::default().fg(Color::Black).bg(Color::Green),
            notice_error: Style::default().fg(Color::White).bg(Color::Red),
            severity_inverted: false,
        }
    }

    /// Readable on light terminal backgrounds: dark text accents and the dark
    /// variants of the severity colors (ANSI Yellow is already a dark olive).
    pub(crate) fn light() -> Self {
        Self {
            selection_fg: Color::White,
            selection_bg: Color::Blue,
            accent: Color::Blue,
            border_focused: Color::Blue,
            border_unfocused: Color::Gray,
            tree_fg: Color::Black,
            dim: Color::DarkGray,
            muted: Color::Gray,
            severity_crit: Color::Red,
            severity_warn: Color::Yellow,
            severity_watch: Color::Blue,
            severity_info: Color::Green,
            hot_warn: Color::Yellow,
            hot_crit: Color::Red,
            started_fg: Color::Green,
            reparented_fg: Color::Yellow,
            sibling_fg: Color::Blue,
            sibling_bg: Color::Rgb(204, 238, 242),
            notice_success: Style::default().fg(Color::Black).bg(Color::Green),
            notice_error: Style::default().fg(Color::White).bg(Color::Red),
            severity_inverted: false,
        }
    }

    /// Maximum legibility: pure white/black pairs, a bold inverted selection,
    /// and severity rendered as black-on-color chips.
    pub(crate) fn high_contrast() -> Self {
        Self {
            selection_fg: Color::Black,
            selection_bg: Color::White,
            accent: Color::White,
            border_focused: Color::White,
            border_unfocused: Color::Gray,
            tree_fg: Color::White,
            dim: Color::Gray,
            muted: Color::Gray,
            severity_crit: Color::LightRed,
            severity_warn: Color::LightYellow,
            severity_watch: Color::LightCyan,
            severity_info: Color::LightGreen,
            hot_warn: Color::LightYellow,
            hot_crit: Color::LightRed,
            started_fg: Color::LightGreen,
            reparented_fg: Color::LightYellow,
            sibling_fg: Color::Black,
            sibling_bg: Color::LightCyan,
            notice_success: Style::default().fg(Color::Black).bg(Color::LightGreen),
            notice_error: Style::default().fg(Color::Black).bg(Color::LightRed),
            severity_inverted: true,
        }
    }

    /// Selection highlight that stays readable across terminal themes. White
    /// on blue pairs an always-light and an always-dark ANSI color; black on
    /// cyan collapses to a dark-on-dark row in palettes with a dark cyan.
    pub(crate) fn selection(&self) -> Style {
        Style::default()
            .fg(self.selection_fg)
            .bg(self.selection_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub(crate) fn severity_color(&self, severity: AttentionSeverity) -> Color {
        match severity {
            AttentionSeverity::Critical => self.severity_crit,
            AttentionSeverity::Warning => self.severity_warn,
            AttentionSeverity::Watch => self.severity_watch,
        }
    }

    /// Severity styling: a colored foreground for dark/light, an inverted
    /// black-on-color chip for high contrast.
    pub(crate) fn severity_style(&self, severity: AttentionSeverity) -> Style {
        let color = self.severity_color(severity);
        if self.severity_inverted {
            Style::default().fg(Color::Black).bg(color)
        } else {
            Style::default().fg(color)
        }
    }

    /// Hot-CPU styling for the tree metric column; `None` below the warning
    /// threshold (50%), warning from 50%, critical from 85%.
    pub(crate) fn hot_cpu_style(&self, cpu: f32) -> Option<Style> {
        let color = if cpu >= 85.0 {
            self.hot_crit
        } else if cpu >= 50.0 {
            self.hot_warn
        } else {
            return None;
        };
        Some(if self.severity_inverted {
            Style::default().fg(Color::Black).bg(color)
        } else {
            Style::default().fg(color)
        })
    }

    /// Sibling-row highlight. Crossterm has no portable alpha channel, so the
    /// dark preset uses dim cyan for an approximately 30% emphasis.
    pub(crate) fn sibling_style(&self) -> Style {
        Style::default()
            .fg(self.sibling_fg)
            .bg(self.sibling_bg)
            .add_modifier(Modifier::DIM)
    }
}

/// Glyph repertoire: the historical Unicode set, or a pure-ASCII fallback for
/// terminals without Unicode rendering.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GlyphMode {
    #[default]
    Unicode,
    Ascii,
}

impl GlyphMode {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Unicode => Self::Ascii,
            Self::Ascii => Self::Unicode,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Unicode => "unicode",
            Self::Ascii => "ascii",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "unicode" => Some(Self::Unicode),
            "ascii" => Some(Self::Ascii),
            _ => None,
        }
    }

    pub(crate) fn glyphs(self) -> Glyphs {
        match self {
            Self::Unicode => Glyphs::UNICODE,
            Self::Ascii => Glyphs::ASCII,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Glyphs {
    pub(crate) tree_vertical: &'static str,
    pub(crate) tree_branch: &'static str,
    pub(crate) tree_last: &'static str,
    pub(crate) expand_open: &'static str,
    pub(crate) expand_closed: &'static str,
    pub(crate) expand_leaf: &'static str,
    pub(crate) filter_on: &'static str,
    pub(crate) filter_off: &'static str,
    pub(crate) reparent: &'static str,
    pub(crate) arrow_right: &'static str,
    pub(crate) cursor: &'static str,
    pub(crate) alert: &'static str,
    pub(crate) ok: &'static str,
    pub(crate) trend_up: &'static str,
    pub(crate) trend_down: &'static str,
    pub(crate) trend_flat: &'static str,
    pub(crate) middot: &'static str,
    pub(crate) star: &'static str,
    pub(crate) spinner: &'static [&'static str],
}

impl Glyphs {
    pub(crate) const UNICODE: Self = Self {
        tree_vertical: "│ ",
        tree_branch: "├─",
        tree_last: "└─",
        expand_open: "▾",
        expand_closed: "▸",
        expand_leaf: "·",
        filter_on: "●",
        filter_off: "○",
        reparent: "↪",
        arrow_right: "→",
        cursor: "▏",
        alert: "▲",
        ok: "✓",
        trend_up: "↑",
        trend_down: "↓",
        trend_flat: "→",
        middot: "·",
        star: "★",
        spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"],
    };

    pub(crate) const ASCII: Self = Self {
        tree_vertical: "| ",
        tree_branch: "|-",
        tree_last: "`-",
        expand_open: "v",
        expand_closed: ">",
        expand_leaf: ".",
        filter_on: "*",
        filter_off: "o",
        reparent: ">",
        arrow_right: "->",
        cursor: "|",
        alert: "!",
        ok: "+",
        trend_up: "^",
        trend_down: "v",
        trend_flat: "-",
        middot: ".",
        star: "*",
        spinner: &["-", "\\", "|", "/"],
    };
}

/// Auto-detect the glyph repertoire from the terminal and locale. ASCII when
/// `TERM` is `dumb` or `linux`, or when the governing locale variable does
/// not mention UTF-8. Locale variables use the standard precedence — the
/// first set of `LC_ALL`/`LC_CTYPE`/`LANG` (passed in that order) wins — so
/// `LC_ALL=C` overrides a UTF-8 `LANG` instead of being outvoted by it.
pub(crate) fn detect_glyph_mode(term: Option<&str>, locales: &[Option<String>]) -> GlyphMode {
    if let Some(term) = term {
        let term = term.trim().to_ascii_lowercase();
        if term == "dumb" || term == "linux" {
            return GlyphMode::Ascii;
        }
    }
    let has_utf8_locale = locales
        .iter()
        .flatten()
        .next()
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.contains("utf-8") || value.contains("utf8")
        })
        .unwrap_or(false);
    if has_utf8_locale {
        GlyphMode::Unicode
    } else {
        GlyphMode::Ascii
    }
}

/// Theme precedence: CLI flag > `PSMORE_THEME` > persisted ui-state > dark.
/// Unrecognized env values are treated as unset.
pub(crate) fn resolve_theme_id(
    cli: Option<ThemeId>,
    env: Option<ThemeId>,
    persisted: Option<ThemeId>,
) -> ThemeId {
    cli.or(env).or(persisted).unwrap_or_default()
}

/// Glyph precedence: CLI flag > `PSMORE_GLYPHS` > persisted ui-state >
/// auto-detection from `TERM` and the locale variables.
pub(crate) fn resolve_glyph_mode(
    cli: Option<GlyphMode>,
    env: Option<GlyphMode>,
    persisted: Option<GlyphMode>,
    term: Option<&str>,
    locales: &[Option<String>],
) -> GlyphMode {
    cli.or(env)
        .or(persisted)
        .unwrap_or_else(|| detect_glyph_mode(term, locales))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dark_theme_reproduces_the_legacy_hardcoded_styles() {
        let theme = Theme::dark();
        assert_eq!(
            theme.selection(),
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        );
        assert_eq!(theme.accent, Color::Cyan);
        assert_eq!(theme.tree_fg, Color::White);
        assert_eq!(theme.dim, Color::DarkGray);
        assert_eq!(theme.muted, Color::Gray);
        assert_eq!(theme.severity_crit, Color::LightRed);
        assert_eq!(theme.severity_warn, Color::Yellow);
        assert_eq!(theme.severity_watch, Color::LightBlue);
        assert_eq!(theme.severity_info, Color::LightGreen);
        assert_eq!(
            theme.hot_cpu_style(90.0),
            Some(Style::default().fg(Color::LightRed))
        );
        assert_eq!(
            theme.hot_cpu_style(60.0),
            Some(Style::default().fg(Color::Yellow))
        );
        assert_eq!(theme.hot_cpu_style(10.0), None);
        assert_eq!(theme.started_fg, Color::LightGreen);
        assert_eq!(theme.reparented_fg, Color::LightYellow);
        assert_eq!(
            theme.sibling_style(),
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::Rgb(0, 64, 72))
                .add_modifier(Modifier::DIM)
        );
        assert_eq!(
            theme.notice_success,
            Style::default().fg(Color::Black).bg(Color::Green)
        );
        assert_eq!(
            theme.notice_error,
            Style::default().fg(Color::White).bg(Color::Red)
        );
        // Dark severities are foreground-only, exactly like the old code.
        assert_eq!(
            theme.severity_style(AttentionSeverity::Critical),
            Style::default().fg(Color::LightRed)
        );
    }

    #[test]
    fn high_contrast_inverts_severity_and_selection() {
        let theme = Theme::high_contrast();
        assert_eq!(
            theme.selection(),
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            theme.severity_style(AttentionSeverity::Critical),
            Style::default().fg(Color::Black).bg(Color::LightRed)
        );
        assert_ne!(theme.selection(), Theme::dark().selection());
    }

    #[test]
    fn theme_ids_cycle_and_parse() {
        assert_eq!(ThemeId::Dark.next(), ThemeId::Light);
        assert_eq!(ThemeId::Light.next(), ThemeId::HighContrast);
        assert_eq!(ThemeId::HighContrast.next(), ThemeId::Dark);
        assert_eq!(ThemeId::parse("light"), Some(ThemeId::Light));
        assert_eq!(ThemeId::parse("high-contrast"), Some(ThemeId::HighContrast));
        assert_eq!(ThemeId::parse("neon"), None);
    }

    #[test]
    fn glyph_modes_parse_and_provide_distinct_sets() {
        assert_eq!(GlyphMode::parse("ascii"), Some(GlyphMode::Ascii));
        assert_eq!(GlyphMode::parse("unicode"), Some(GlyphMode::Unicode));
        assert_eq!(GlyphMode::parse("emoji"), None);
        assert_eq!(GlyphMode::Unicode.next(), GlyphMode::Ascii);
        assert_ne!(Glyphs::UNICODE.tree_branch, Glyphs::ASCII.tree_branch);
        assert_eq!(Glyphs::ASCII.tree_branch, "|-");
        assert_eq!(Glyphs::ASCII.tree_last, "`-");
    }

    #[test]
    fn auto_detection_falls_back_to_ascii_without_utf8() {
        let utf8 = [Some("en_US.UTF-8".to_string())];
        assert_eq!(
            detect_glyph_mode(Some("xterm-256color"), &utf8),
            GlyphMode::Unicode
        );
        assert_eq!(detect_glyph_mode(Some("dumb"), &utf8), GlyphMode::Ascii);
        assert_eq!(detect_glyph_mode(Some("linux"), &utf8), GlyphMode::Ascii);
        assert_eq!(
            detect_glyph_mode(Some("xterm"), &[Some("C".to_string())]),
            GlyphMode::Ascii
        );
        assert_eq!(
            detect_glyph_mode(Some("xterm"), &[None, Some("POSIX".to_string()), None]),
            GlyphMode::Ascii
        );
        // Locale precedence: the first set variable governs, so LC_ALL=C
        // overrides a UTF-8 LANG and LC_ALL=UTF-8 overrides a C LANG.
        assert_eq!(
            detect_glyph_mode(
                Some("xterm"),
                &[Some("C".to_string()), Some("en_US.UTF-8".to_string())]
            ),
            GlyphMode::Ascii
        );
        assert_eq!(
            detect_glyph_mode(
                Some("xterm"),
                &[None, Some("en_US.UTF-8".to_string()), Some("C".to_string())]
            ),
            GlyphMode::Unicode
        );
        assert_eq!(
            detect_glyph_mode(
                Some("xterm"),
                &[Some("en_US.UTF-8".to_string()), Some("C".to_string())]
            ),
            GlyphMode::Unicode
        );
        assert_eq!(
            detect_glyph_mode(None, &[None, None, None]),
            GlyphMode::Ascii
        );
        assert_eq!(
            detect_glyph_mode(Some("xterm"), &[Some("zh_CN.utf8".to_string())]),
            GlyphMode::Unicode
        );
    }

    #[test]
    fn resolution_honors_the_configured_precedence() {
        assert_eq!(
            resolve_theme_id(
                Some(ThemeId::Light),
                Some(ThemeId::HighContrast),
                Some(ThemeId::Dark)
            ),
            ThemeId::Light
        );
        assert_eq!(
            resolve_theme_id(None, Some(ThemeId::HighContrast), Some(ThemeId::Light)),
            ThemeId::HighContrast
        );
        assert_eq!(
            resolve_theme_id(None, None, Some(ThemeId::Light)),
            ThemeId::Light
        );
        assert_eq!(resolve_theme_id(None, None, None), ThemeId::Dark);

        let utf8 = [Some("en_US.UTF-8".to_string())];
        assert_eq!(
            resolve_glyph_mode(
                Some(GlyphMode::Unicode),
                Some(GlyphMode::Ascii),
                None,
                Some("dumb"),
                &utf8
            ),
            GlyphMode::Unicode
        );
        assert_eq!(
            resolve_glyph_mode(None, Some(GlyphMode::Ascii), None, Some("xterm"), &utf8),
            GlyphMode::Ascii
        );
        assert_eq!(
            resolve_glyph_mode(None, None, Some(GlyphMode::Ascii), Some("xterm"), &utf8),
            GlyphMode::Ascii
        );
        assert_eq!(
            resolve_glyph_mode(None, None, None, Some("xterm"), &utf8),
            GlyphMode::Unicode
        );
    }
}
