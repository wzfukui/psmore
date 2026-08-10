# psmore

`psmore` is a relationship-first process diagnostics workbench for macOS and Linux.

[English](README.md) · [中文（简体）](README.zh-CN.md)

## Project information

- Repository: https://github.com/wzfukui/psmore
- Author: wzfukui (fukui@wuzhi-ai.com)
- License: MIT
- Current version: from `psmore --version`

`psmore` combines an interactive process-tree TUI with scripted diagnostics for CLI environments (SSH, CI, incident scripts). It unifies process context, resource metrics, and relationship evidence (parent/child/sibling/subtree) across macOS and Linux.

## What users get

- Process tree view with explicit parent-child structure and stable sibling ordering
- Structured search and filtering with rich query language (`name:`, `cmd:`, `path:`, `user:`, `cpu>`, `tree.mem>=`, etc.)
- Persistent include/exclude filters with text/regex and allow/deny composition
- Focus-aware navigation with jump-to-parent/sibling controls and auto-scroll behavior
- Multi-pane diagnostics:
  - interactive thread, port, file, log, service, executable image, memory attribution, and incident dossier workflows
  - script-friendly output for non-interactive environments (`--table`, `--json`, `--jsonl`)
- Built-in safety controls (`k` terminate, `p` process action center, two-step confirmation, identity re-check)
- Baseline capture and diff (`b`) for before/after diagnosis workflows
- Security-aware export with redaction (`--redact`) for external sharing

## Language (localization) policy

This repository is now defaulted to English.

- Default runtime language in TUI is chosen from OS locale.
- Manual switch is available (`L` in main screen, `F2` in any workspace) and persisted.
- `PSMORE_LANG` can be used to force first-run language if needed.
- Command output from non-interactive mode remains English-first, stable for scripts and automation.

## Installation

### Homebrew (recommended on macOS and Linux)

```bash
brew install wzfukui/tap/psmore
```

### Cargo

```bash
cargo install psmore --locked
psmore --version
```

### GitHub Release archive

```bash
# Linux
sha256sum -c psmore-v0.1.2-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf psmore-v0.1.2-x86_64-unknown-linux-gnu.tar.gz
cd psmore-v0.1.2-x86_64-unknown-linux-gnu
./install.sh --dry-run
./install.sh
```

For local-source install:

```bash
cargo install --path . --locked
psmore --help
```

## Quick start

```bash
psmore
```

Interactive mode opens quickly:

- `↑/↓` / `j/k`: move selection
- `←/→`: expose parent / expand children
- `/`: query mode
- `F` filter manager
- `Enter`: deep inspection
- `s`: hotspot sort
- `q`: quit

If you already know a PID:

```bash
psmore --query 'pid:1234'
```

If you need a non-interactive snapshot:

```bash
psmore --table --query 'user:deploy cpu>5'
psmore --json --query 'state:zombie'
```

## Core command reference (selection)

- `psmore check QUERY` — CI-safe health gate (`--expect`, `--wait`, `--stable`)
- `psmore inspect PID` — full process deep inspection
- `psmore memory PID` — per-instance memory attribution
- `psmore explain PID` — evidence dossier (inspection, service, image, logs)
- `psmore exe PID` — executable-image verification
- `psmore stale [QUERY]` — find processes holding replaced/deleted images (Linux)
- `psmore service PID` — resolve to launchd/systemd context
- `psmore logs PID` — native logs in bounded window
- `psmore port PORT` — identify listeners/owners
- `psmore listen` — global listening/socket exposure
- `psmore net [FILTER]` — connected sockets and Unix peer links
- `psmore tree PID` — ancestry and descendants in text
- `psmore top [QUERY]` — process/subtree hotspot ranking
- `psmore watch [QUERY]` — watch lifecycle changes as stream
- `psmore diff BEFORE AFTER` — compare snapshots or hosts
- `psmore doctor` — quick host health baseline + optional deep checks
- `psmore deleted`, `psmore fd`, `psmore file`, `psmore oom`, `psmore cgroup`, `psmore run`

For the full command list and detailed behavior, see:
- [README in Chinese](README.zh-CN.md) (comprehensive)
- [Release docs](docs/RELEASING.md)

## Security and sharing

`psmore` does not expose secrets automatically and does not execute destructive operations without explicit confirmation.

For safe sharing, use `--redact`:

```bash
psmore inspect 1234 --json --redact > process-1234.safe.json
psmore doctor --deep --json --redact > doctor.safe.json
```

Redaction strips recognized secrets in common patterns but does not perform full anonymization.

## Release process

Please refer to:
- [docs/RELEASING.md](docs/RELEASING.md) — release packaging and distribution workflow
- [CHANGELOG.md](CHANGELOG.md) — notable changes

## Contributing

Issues, PRs, and test notes are welcome. Prefer actionable cases, reproducible examples, and environment details (`psmore --version`, OS, locale) in bug reports.

`psmore` is developed with best-effort support for bilingual project documentation and will keep feature coverage synchronized between English and Chinese as updates continue.
