# Changelog

All notable changes to psmore are documented in this file.

The project follows [Semantic Versioning](https://semver.org/).

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

[0.1.1]: https://github.com/wzfukui/psmore/releases/tag/v0.1.1
[0.1.0]: https://github.com/wzfukui/psmore/releases/tag/v0.1.0
