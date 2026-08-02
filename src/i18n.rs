use std::env;

#[cfg(target_os = "macos")]
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UiLanguage {
    Chinese,
    #[default]
    English,
}

impl UiLanguage {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Chinese => Self::English,
            Self::English => Self::Chinese,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Chinese => "中文",
            Self::English => "English",
        }
    }
}

pub(crate) fn text(
    language: UiLanguage,
    english: &'static str,
    chinese: &'static str,
) -> &'static str {
    match language {
        UiLanguage::Chinese => chinese,
        UiLanguage::English => english,
    }
}

fn language_from_locale(value: &str) -> Option<UiLanguage> {
    let normalized = value
        .trim()
        .trim_matches(|character| matches!(character, '"' | '\'' | '(' | ')' | ','))
        .to_ascii_lowercase();
    if normalized.is_empty() || matches!(normalized.as_str(), "c" | "posix") {
        return None;
    }
    if normalized.starts_with("zh")
        || normalized.contains("chinese")
        || normalized.starts_with("hans")
        || normalized.starts_with("hant")
    {
        Some(UiLanguage::Chinese)
    } else {
        Some(UiLanguage::English)
    }
}

fn environment_language(keys: &[&str]) -> Option<UiLanguage> {
    keys.iter()
        .filter_map(|key| env::var(key).ok())
        .flat_map(|value| value.split(':').map(str::to_owned).collect::<Vec<_>>())
        .find_map(|value| language_from_locale(&value))
}

#[cfg(target_os = "macos")]
fn macos_language() -> Option<UiLanguage> {
    for key in ["AppleLanguages", "AppleLocale"] {
        let output = Command::new("/usr/bin/defaults")
            .args(["read", "-g", key])
            .output()
            .ok()?;
        if !output.status.success() {
            continue;
        }
        let value = String::from_utf8_lossy(&output.stdout);
        if let Some(language) = value.lines().find_map(language_from_locale) {
            return Some(language);
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn macos_language() -> Option<UiLanguage> {
    None
}

pub(crate) fn detect_system_language() -> UiLanguage {
    environment_language(&["PSMORE_LANG"])
        .or_else(macos_language)
        .or_else(|| environment_language(&["LC_ALL", "LC_MESSAGES"]))
        .or_else(|| environment_language(&["LANGUAGE", "LANG"]))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_chinese_and_english_locale_families() {
        assert_eq!(
            language_from_locale("zh_CN.UTF-8"),
            Some(UiLanguage::Chinese)
        );
        assert_eq!(language_from_locale("zh-Hant"), Some(UiLanguage::Chinese));
        assert_eq!(
            language_from_locale("Chinese (Simplified)"),
            Some(UiLanguage::Chinese)
        );
        assert_eq!(
            language_from_locale("en_US.UTF-8"),
            Some(UiLanguage::English)
        );
        assert_eq!(
            language_from_locale("de_DE.UTF-8"),
            Some(UiLanguage::English)
        );
        assert_eq!(language_from_locale("C"), None);
    }

    #[test]
    fn language_toggle_is_reversible() {
        assert_eq!(UiLanguage::Chinese.next(), UiLanguage::English);
        assert_eq!(UiLanguage::English.next(), UiLanguage::Chinese);
    }
}
