# Changelog

All notable changes to psmore are documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-09-04

### Added

- Add statically linked Linux release archives for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, built and verified in the CI and Release matrices, so older distributions (Ubuntu 22.04/20.04, CentOS, …) can install a prebuilt binary without any glibc version constraint.

### Fixed

- Serialize sysinfo user-list refreshes behind a process-wide lock: concurrent capture threads raced on libc's non-thread-safe `getpwent`/`setpwent`/`endpwent`, which segfaults under musl (glibc only survives by chance). Found by the new musl CI jobs, fixed with a regression test.

## [0.2.0] - 2026-08-27

### Breaking changes

- Rework keybindings toward the mainstream set: `k` now moves the selection up (the standalone `k` end-process dialog is removed; `p` is the only signal entry point), `q` closes the current overlay/dialog layer and only quits on the bare process tree, `d` without a baseline explains itself with a notice, and `L` toggles the interface language from any state outside text-entry modes like search and filter editing (the dossier log toggle moved to `g`; the `F2` binding was removed).

### Highlights

- Add a top system status bar to the TUI: hostname, 1-minute load with a trend arrow, global CPU, memory and swap usage, and a right-aligned attention alert count colored by worst severity.
- Add right-aligned per-process `CPU%` and `MEM` columns to the process tree on wide terminals (MEM drops below 100 columns, both drop below 80); hot CPU values are highlighted and the tree border carries the column header.
- Merge the footer into a single line in both languages: wide terminals show full stats plus shortcut hints, narrower ones degrade the stats to a compact form and finally yield the line to the hints.
- Align the deep-inspection popup with the process-tree block so its bottom border never dips into the selected-process pane, and let Left/Right arrows switch its cards (mirrors Tab/Shift-Tab).
- Add a `:` command palette to the TUI: fuzzy-match every feature by its English or Chinese name and keywords, then run it with Enter — execution replays the real key press, so palette behavior always matches key behavior; the footer hint line and the field guide advertise it.
- Add a TUI theme system with `dark` (default, identical to the historical palette), `light`, and `high-contrast` presets, selected by `--theme`, `PSMORE_THEME`, or the persisted ui-state preference, and switchable at runtime through the bilingual command-palette entry "Cycle theme"/"切换主题".
- Add an ASCII glyph fallback for the tree connectors, filter states, cursors, alerts, trend arrows, and spinner: `--glyphs unicode|ascii`, `PSMORE_GLYPHS`, a persisted ui-state preference, auto-detection on `TERM=dumb`/`linux` or non-UTF-8 locales, and a "Toggle ASCII glyphs"/"切换字符集" palette entry.
- Unify user-facing terminology on "dossier" (档案): the CLI `explain` subcommand and JSON schema names stay unchanged, while help text, the man page, the field guide, and the READMEs now state that `psmore explain PID` and the TUI `D` overlay are the same evidence dossier.
- Complete Chinese coverage for the remaining English-only UI strings: the trend overlay (sample counts, self/subtree series labels, now/avg/max), the snapshot-diff overlay (section headlines, row labels, system deltas), log scope/priority and logs/hash toggle labels in the dossier, logs, and image-verification titles, and the action dialog start-time label.
- Add `/` search query history and field completion: applied queries are remembered (most recent first, deduplicated, capped at 20, persisted in `ui-state.json` as `query_history`), `↑`/`↓` walk the history shell-style with draft restore, and `Tab` completes query field starters (`name:`, `user:`, `cpu>`, `tree.mem>`, …) with cycling.
- Add session-only process stars: `*` toggles a star bound to the process instance (PID + start time, so PID reuse never inherits it), starred rows show a `★`/`*` marker, and `'` jumps to the next starred process with wraparound; palette entries "Toggle star"/"切换星标" and "Next starred"/"下一个星标" mirror the keys.
- Add exact-port lookup to the TUI network workspace: `p` opens a digit-only port input that narrows the endpoint list to local/remote port matches and selects the first hit, `x` clears it together with the text filter, and the palette entry "Find port…"/"查找端口…" jumps straight into the flow.
- Add mouse support to the TUI: click a tree row to select it (click the selected row to open inspection), click inspection tab labels to switch cards, and scroll the wheel to move/scroll exactly like `↑`/`↓`; capture is enabled on start and always released on exit.

## [0.1.2] - 2026-08-10

### Highlights

- Introduce bilingual documentation structure with English as the default GitHub page.
- Add `README.md` (English default) and `README.zh-CN.md` (Chinese full copy), with explicit language switch links.
- Add `docs/RELEASING.md` English default and `docs/RELEASING.zh-CN.md` Chinese version.
- Keep release/version references aligned with the new default-language documentation layout.

## [0.1.1] - 2026-08-10

### Highlights

- Optimize the selected-process detail section in the interactive view by adapting to terminal width.
- Merge process/self summary and subtree summary into one line when space allows; otherwise auto-wrap into compact two-line layout.
- Wrap long command/path lines cleanly on the bottom detail panel to make narrow terminal usage readable.
- Keep changelog and version metadata aligned for this release.

## [0.1.0] - 2026-08-10

Initial public release.

### Highlights

- Relationship-first process tree for macOS and Linux with stable navigation, filtering, search, resource aggregation, and command context.
- Interactive diagnostics for threads, ports, open files, memory attribution, service ownership, executable identity, logs, trends, baselines, and incident dossiers.
- Scriptable commands for snapshots, health checks, process inspection, networking, files, cgroups, OOM pressure, tracing, and release gates.
- Safe process actions with PID-instance validation and explicit confirmation.
- Chinese and English interfaces, native release archives, shell completions, man page, and private atomic diagnostic exports.

[0.1.2]: https://github.com/wzfukui/psmore/releases/tag/v0.1.2
[0.1.1]: https://github.com/wzfukui/psmore/releases/tag/v0.1.1
[0.1.0]: https://github.com/wzfukui/psmore/releases/tag/v0.1.0
