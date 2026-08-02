use std::{env, fs, io, path::PathBuf};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

use serde::{Deserialize, Serialize};

use crate::secure_output::write_secure_atomic;

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
        body: "Filters understand aggregated descendants. Try tree.mem>2g or tree.procs>=20 to find heavyweight service boundaries.",
        keys: "/ query  |  Enter finish locator",
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
        body: "TERM, KILL, STOP, and CONT require a second confirmation and re-check PID start time before sending a signal.",
        keys: "p actions  |  y confirm  |  Esc cancel",
    },
];

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredState {
    schema_version: u32,
    first_run_completed: bool,
    tips_enabled: bool,
    next_tip_index: usize,
}

impl Default for StoredState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA_VERSION,
            first_run_completed: false,
            tips_enabled: true,
            next_tip_index: 0,
        }
    }
}

pub(crate) struct Guidance {
    pub(crate) overlay: Option<GuidanceOverlay>,
    pub(crate) page: usize,
    state: StoredState,
    path: Option<PathBuf>,
    warning: Option<String>,
}

impl Guidance {
    #[cfg(test)]
    pub(crate) fn welcome_for_test() -> Self {
        Self::from_state(StoredState::default(), None, false)
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
        let mut guidance = Self {
            overlay,
            page: 0,
            state,
            path,
            warning: None,
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
            Some(GuidanceOverlay::Tip(index)) => TIPS.get(index).copied(),
            _ => None,
        }
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
