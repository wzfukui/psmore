use std::{env, fs, io, path::PathBuf};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use serde::{Deserialize, Serialize};

use crate::{
    filters::ProcessFilterRule,
    i18n::{UiLanguage, detect_system_language},
    secure_output::write_secure_atomic,
};

const STATE_SCHEMA_VERSION: u32 = 1;
const STATE_FILE_NAME: &str = "ui-state.json";
pub(crate) const GUIDANCE_PAGE_COUNT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuidanceOverlay {
    Welcome,
    Tip(usize),
    Help,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Tip {
    pub(crate) title: &'static str,
    pub(crate) body: &'static str,
    pub(crate) keys: &'static str,
}

pub(crate) const TIPS: &[Tip] = &[
    Tip {
        title: "Reveal the real parent chain",
        body: "Select any process and press Left. psmore exposes its parent and siblings without expanding unrelated branches.",
        keys: "Left reveal parent  |  Right expand or collapse",
    },
    Tip {
        title: "Query the whole service tree",
        body: "Use F for persistent allow/deny rules, then / for a temporary query. Both understand fields, regex, and descendant aggregates.",
        keys: "F persistent filters  |  / temporary search  |  Enter apply",
    },
    Tip {
        title: "Find evidence before guessing",
        body: "The attention workspace combines unhealthy states, churn, sustained CPU or I/O, and memory growth into reviewable evidence.",
        keys: "a attention  |  Enter jump to process",
    },
    Tip {
        title: "Rank complete services, not only workers",
        body: "The hotspot workspace can switch between a process itself and its complete descendant tree, preserving ownership context.",
        keys: "h hotspots  |  v process/tree scope",
    },
    Tip {
        title: "Capture a before/after baseline",
        body: "Take a baseline before a deploy or reproduction, then compare lifecycle and resource movement without leaving the TUI.",
        keys: "b baseline  |  d diff  |  x clear",
    },
    Tip {
        title: "Inspect the process behind a connection",
        body: "The network workspace connects listening and peer endpoints back to PID, FD, namespace, user, and command context.",
        keys: "n network  |  v listeners/all  |  Enter jump",
    },
    Tip {
        title: "Freeze the scene without losing navigation",
        body: "Pause automatic refresh while investigating a fast-changing tree. Navigation and manual refresh remain available.",
        keys: "Space pause/resume  |  r sample now",
    },
    Tip {
        title: "Follow a process trend",
        body: "psmore keeps recent own and subtree samples, detects PID reuse, and briefly retains evidence after a process exits.",
        keys: "t trend  |  i CPU/memory or I/O",
    },
    Tip {
        title: "Verify what is actually running",
        body: "Compare the selected process image with the current disk path, package, hash, and code signature after a deploy.",
        keys: "v verify image  |  h hash on/off  |  m service context",
    },
    Tip {
        title: "Read the evidence the process emitted",
        body: "Open bounded native logs without losing process ownership. Linux follows the systemd unit when available; macOS stays inside the current PID lifetime.",
        keys: "l logs  |  s scope  |  p priority  |  w window",
    },
    Tip {
        title: "Attribute memory instead of guessing",
        body: "Separate RSS, PSS, physical footprint, anonymous/file/shared pages, swap, and virtual mappings. Linux also ranks mapped files; macOS ranks vmmap regions.",
        keys: "M memory  |  r refresh  |  Up/Down scroll",
    },
    Tip {
        title: "Build one process dossier",
        body: "Collect process, service-manager, executable-image, and bounded log evidence in parallel, then review prioritized signals without losing their source paths.",
        keys: "D dossier  |  r refresh  |  L logs on/off  |  h hash",
    },
    Tip {
        title: "Export the context you already collected",
        body: "The report includes the current tree, query, attention findings, events, actions, and any opened diagnostic panels.",
        keys: "o private JSON report",
    },
    Tip {
        title: "Process actions are identity-safe",
        body: "Use k for the focused TERM/KILL dialog or p for all actions. Every signal requires a separate confirmation and a PID start-time re-check.",
        keys: "k end  |  p actions  |  y confirm  |  Esc cancel",
    },
];

const TIPS_ZH: &[Tip] = &[
    Tip {
        title: "还原真实父进程链",
        body: "选中任意进程并按左方向键。psmore 会显示其父进程和兄弟进程，但不会展开无关分支。",
        keys: "← 显示父进程  |  → 展开或折叠",
    },
    Tip {
        title: "查询完整服务树",
        body: "用 F 管理持久包含/排除规则，再用 / 临时搜索；两层都支持字段、正则和后代聚合指标。",
        keys: "F 持久过滤  |  / 临时搜索  |  Enter 应用",
    },
    Tip {
        title: "先找证据，再作判断",
        body: "关注事项工作台汇总异常状态、进程抖动、持续 CPU/I/O 和内存增长，形成可复核线索。",
        keys: "a 关注事项  |  Enter 跳到进程",
    },
    Tip {
        title: "按完整服务排名",
        body: "热点工作台可在单个进程与完整后代树之间切换，同时保留进程归属上下文。",
        keys: "h 热点  |  v 进程/子树口径",
    },
    Tip {
        title: "捕获前后基线",
        body: "在发布或复现前保存基线，再直接比较生命周期和资源变化。",
        keys: "b 基线  |  d 对比  |  x 清除",
    },
    Tip {
        title: "定位连接背后的进程",
        body: "网络工作台把监听和对端连接关联到 PID、FD、命名空间、用户和命令。",
        keys: "n 网络  |  v 监听/全部  |  Enter 跳转",
    },
    Tip {
        title: "冻结现场但保留导航",
        body: "调查快速变化的进程树时可暂停自动刷新，导航和手工刷新仍然可用。",
        keys: "Space 暂停/恢复  |  r 立即采样",
    },
    Tip {
        title: "跟踪进程趋势",
        body: "psmore 保存进程自身和子树的近期样本，识别 PID 复用，并短暂保留退出进程证据。",
        keys: "t 趋势  |  i CPU/内存或 I/O",
    },
    Tip {
        title: "验证实际运行映像",
        body: "发布后核对运行映像与磁盘路径、软件包、哈希和代码签名。",
        keys: "v 验证映像  |  h 哈希开关  |  m 服务上下文",
    },
    Tip {
        title: "读取进程产生的证据",
        body: "在不丢失进程归属的前提下读取有界原生日志。Linux 可跟随 systemd 单元，macOS 限定在当前 PID 生命周期。",
        keys: "l 日志  |  s 范围  |  p 等级  |  w 时间窗",
    },
    Tip {
        title: "归因内存，而不是猜测",
        body: "区分 RSS、PSS、physical footprint、匿名/文件/共享页、Swap 和虚拟映射。",
        keys: "M 内存  |  r 刷新  |  ↑/↓ 滚动",
    },
    Tip {
        title: "建立单进程事故档案",
        body: "并行采集进程、服务管理器、运行映像和有界日志证据，再按优先级复核。",
        keys: "D 档案  |  r 刷新  |  L 日志开关  |  h 哈希",
    },
    Tip {
        title: "导出已经取得的上下文",
        body: "报告包含当前进程树、查询、关注事项、事件、操作以及已经打开的诊断面板。",
        keys: "o 私有 JSON 报告",
    },
    Tip {
        title: "进程操作校验实例身份",
        body: "k 打开 TERM/KILL 专用弹窗，p 打开全部操作。每次发送都需要独立确认并重新核对 PID 启动时间。",
        keys: "k 结束  |  p 操作  |  y 确认  |  Esc 取消",
    },
];

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredState {
    schema_version: u32,
    first_run_completed: bool,
    tips_enabled: bool,
    next_tip_index: usize,
    #[serde(default)]
    language: Option<UiLanguage>,
    #[serde(default)]
    filters: Vec<ProcessFilterRule>,
}

impl Default for StoredState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            first_run_completed: false,
            tips_enabled: true,
            next_tip_index: 0,
            language: None,
            filters: Vec::new(),
        }
    }
}

pub(crate) struct Guidance {
    pub(crate) overlay: Option<GuidanceOverlay>,
    pub(crate) page: usize,
    state: StoredState,
    path: Option<PathBuf>,
    warning: Option<String>,
    language: UiLanguage,
}

impl Guidance {
    #[cfg(test)]
    pub(crate) fn welcome_for_test() -> Self {
        let mut guidance = Self::from_state(StoredState::default(), None, false);
        guidance.language = UiLanguage::English;
        guidance
    }

    #[cfg(test)]
    pub(crate) fn tip_for_test(index: usize) -> Self {
        Self {
            overlay: Some(GuidanceOverlay::Tip(index % TIPS.len())),
            page: 0,
            state: StoredState {
                first_run_completed: true,
                tips_enabled: true,
                next_tip_index: (index + 1) % TIPS.len(),
                ..StoredState::default()
            },
            path: None,
            warning: None,
            language: UiLanguage::English,
        }
    }

    pub(crate) fn load_default(suppress_for_this_run: bool) -> Self {
        match default_state_path() {
            Some(path) => Self::load_from_path(path, suppress_for_this_run),
            None => {
                let mut guidance =
                    Self::from_state(StoredState::default(), None, suppress_for_this_run);
                guidance.warning = Some(
                    "startup guidance preferences cannot be saved because no config directory is available"
                        .into(),
                );
                guidance
            }
        }
    }

    fn load_from_path(path: PathBuf, suppress_for_this_run: bool) -> Self {
        let (state, warning) = match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str::<StoredState>(&contents) {
                Ok(state) if state.schema_version == STATE_SCHEMA_VERSION => (state, None),
                Ok(state) => (
                    StoredState::default(),
                    Some(format!(
                        "startup guidance state schema {} is unsupported; defaults are active",
                        state.schema_version
                    )),
                ),
                Err(error) => (
                    StoredState::default(),
                    Some(format!("startup guidance state is invalid: {error}")),
                ),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (StoredState::default(), None),
            Err(error) => (
                StoredState::default(),
                Some(format!("cannot read startup guidance state: {error}")),
            ),
        };
        let mut guidance = Self::from_state(state, Some(path), suppress_for_this_run);
        if warning.is_some() {
            guidance.warning = warning;
        }
        guidance
    }

    fn from_state(
        mut state: StoredState,
        path: Option<PathBuf>,
        suppress_for_this_run: bool,
    ) -> Self {
        let overlay = if suppress_for_this_run {
            None
        } else if !state.first_run_completed {
            Some(GuidanceOverlay::Welcome)
        } else if state.tips_enabled && !TIPS.is_empty() {
            let index = state.next_tip_index % TIPS.len();
            state.next_tip_index = (index + 1) % TIPS.len();
            Some(GuidanceOverlay::Tip(index))
        } else {
            None
        };
        let language = state.language.unwrap_or_else(detect_system_language);
        let mut guidance = Self {
            overlay,
            page: 0,
            state,
            path,
            warning: None,
            language,
        };
        if matches!(overlay, Some(GuidanceOverlay::Tip(_))) {
            if let Err(error) = guidance.persist() {
                guidance.warning = Some(format!("cannot rotate startup tip: {error}"));
            }
        }
        guidance
    }

    #[cfg(test)]
    pub(crate) fn is_open(&self) -> bool {
        self.overlay.is_some()
    }

    pub(crate) fn tips_enabled(&self) -> bool {
        self.state.tips_enabled
    }

    pub(crate) fn tip(&self) -> Option<Tip> {
        match self.overlay {
            Some(GuidanceOverlay::Tip(index)) => match self.language {
                UiLanguage::Chinese => TIPS_ZH.get(index).copied(),
                UiLanguage::English => TIPS.get(index).copied(),
            },
            _ => None,
        }
    }

    pub(crate) fn language(&self) -> UiLanguage {
        self.language
    }

    pub(crate) fn toggle_language(&mut self) -> io::Result<UiLanguage> {
        self.language = self.language.next();
        self.state.language = Some(self.language);
        self.persist()?;
        Ok(self.language)
    }

    pub(crate) fn filters(&self) -> &[ProcessFilterRule] {
        &self.state.filters
    }

    pub(crate) fn save_filters(&mut self, filters: &[ProcessFilterRule]) -> io::Result<()> {
        self.state.filters = filters.to_vec();
        self.persist()
    }

    pub(crate) fn open_help(&mut self) {
        self.overlay = Some(GuidanceOverlay::Help);
        self.page = 0;
    }

    pub(crate) fn dismiss(&mut self) -> io::Result<()> {
        let result = if self.overlay == Some(GuidanceOverlay::Welcome) {
            self.state.first_run_completed = true;
            self.persist()
        } else {
            Ok(())
        };
        self.overlay = None;
        self.page = 0;
        result
    }

    pub(crate) fn disable_startup(&mut self) -> io::Result<()> {
        self.state.first_run_completed = true;
        self.state.tips_enabled = false;
        self.overlay = None;
        self.page = 0;
        self.persist()
    }

    pub(crate) fn toggle_tips(&mut self) -> io::Result<bool> {
        self.state.tips_enabled = !self.state.tips_enabled;
        self.persist()?;
        Ok(self.state.tips_enabled)
    }

    pub(crate) fn next_page(&mut self) {
        self.page = (self.page + 1) % GUIDANCE_PAGE_COUNT;
    }

    pub(crate) fn previous_page(&mut self) {
        self.page = (self.page + GUIDANCE_PAGE_COUNT - 1) % GUIDANCE_PAGE_COUNT;
    }

    pub(crate) fn take_warning(&mut self) -> Option<String> {
        self.warning.take()
    }

    fn persist(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no startup guidance state path is available",
            ));
        };
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "guidance state path has no parent",
            )
        })?;
        if !parent.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(parent)?;
        }
        let document = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| io::Error::other(error.to_string()))?;
        write_secure_atomic(path, &document, true)
    }
}

fn default_state_path() -> Option<PathBuf> {
    if let Some(directory) = env::var_os("PSMORE_CONFIG_DIR").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(directory).join(STATE_FILE_NAME));
    }
    if let Some(directory) = env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Some(
            PathBuf::from(directory)
                .join("psmore")
                .join(STATE_FILE_NAME),
        );
    }
    let home = env::var_os("HOME").filter(|value| !value.is_empty())?;
    #[cfg(target_os = "macos")]
    let directory = PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("psmore");
    #[cfg(not(target_os = "macos"))]
    let directory = PathBuf::from(home).join(".config").join("psmore");
    Some(directory.join(STATE_FILE_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "psmore-guidance-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn first_run_becomes_rotating_tips_after_dismissal() {
        let directory = test_directory("rotation");
        let path = directory.join(STATE_FILE_NAME);
        let mut first = Guidance::load_from_path(path.clone(), false);
        assert_eq!(first.overlay, Some(GuidanceOverlay::Welcome));
        first.dismiss().unwrap();

        let second = Guidance::load_from_path(path.clone(), false);
        assert_eq!(second.overlay, Some(GuidanceOverlay::Tip(0)));
        let third = Guidance::load_from_path(path.clone(), false);
        assert_eq!(third.overlay, Some(GuidanceOverlay::Tip(1)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn chinese_and_english_tip_catalogs_stay_in_sync() {
        assert_eq!(TIPS_ZH.len(), TIPS.len());
    }

    #[test]
    fn manual_language_choice_is_persisted() {
        let directory = test_directory("language");
        let path = directory.join(STATE_FILE_NAME);
        let mut guidance = Guidance::load_from_path(path.clone(), true);
        let initial = guidance.language();
        let selected = guidance.toggle_language().unwrap();
        assert_eq!(selected, initial.next());

        let reloaded = Guidance::load_from_path(path.clone(), true);
        assert_eq!(reloaded.language(), selected);

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn process_filters_are_persisted_with_private_ui_preferences() {
        use crate::filters::FilterAction;

        let directory = test_directory("filters");
        let path = directory.join(STATE_FILE_NAME);
        let filters = vec![ProcessFilterRule {
            action: FilterAction::Exclude,
            expression: "path~^/System/Library/".into(),
            enabled: true,
        }];
        let mut guidance = Guidance::load_from_path(path.clone(), true);
        guidance.save_filters(&filters).unwrap();

        let reloaded = Guidance::load_from_path(path.clone(), true);
        assert_eq!(reloaded.filters(), filters);

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn startup_cards_can_be_disabled_or_suppressed_for_one_run() {
        let directory = test_directory("disable");
        let path = directory.join(STATE_FILE_NAME);
        let suppressed = Guidance::load_from_path(path.clone(), true);
        assert_eq!(suppressed.overlay, None);
        assert!(!path.exists());

        let mut first = Guidance::load_from_path(path.clone(), false);
        first.disable_startup().unwrap();
        let disabled = Guidance::load_from_path(path.clone(), false);
        assert_eq!(disabled.overlay, None);
        assert!(!disabled.tips_enabled());

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn manual_help_can_reenable_tips() {
        let directory = test_directory("toggle");
        let path = directory.join(STATE_FILE_NAME);
        let mut guidance = Guidance::load_from_path(path.clone(), false);
        guidance.disable_startup().unwrap();
        guidance.open_help();
        assert!(guidance.toggle_tips().unwrap());

        let reloaded = Guidance::load_from_path(path.clone(), false);
        assert_eq!(reloaded.overlay, Some(GuidanceOverlay::Tip(0)));

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn progressive_tips_keep_rotating_until_the_user_disables_them() {
        let directory = test_directory("continuous-rotation");
        let path = directory.join(STATE_FILE_NAME);
        let mut first = Guidance::load_from_path(path.clone(), false);
        first.dismiss().unwrap();

        for index in 0..TIPS.len() {
            let guidance = Guidance::load_from_path(path.clone(), false);
            assert_eq!(guidance.overlay, Some(GuidanceOverlay::Tip(index)));
        }
        let wrapped = Guidance::load_from_path(path.clone(), false);
        assert_eq!(wrapped.overlay, Some(GuidanceOverlay::Tip(0)));
        assert!(wrapped.tips_enabled());

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn invalid_state_is_visible_and_recoverable() {
        let directory = test_directory("invalid");
        fs::create_dir(&directory).unwrap();
        let path = directory.join(STATE_FILE_NAME);
        fs::write(&path, b"{not valid json").unwrap();

        let mut guidance = Guidance::load_from_path(path.clone(), false);
        assert_eq!(guidance.overlay, Some(GuidanceOverlay::Welcome));
        assert!(
            guidance
                .take_warning()
                .unwrap()
                .contains("startup guidance state is invalid")
        );
        guidance.dismiss().unwrap();
        let mut recovered = Guidance::load_from_path(path.clone(), true);
        assert_eq!(recovered.overlay, None);
        assert!(recovered.take_warning().is_none());

        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
