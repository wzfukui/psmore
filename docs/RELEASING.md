# psmore Release Handbook

Release language policy: this document is maintained in English (default) and has a Chinese version at [`RELEASING.zh-CN.md`](RELEASING.zh-CN.md).

## Supported binary targets

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Each target is built and verified on its native architecture runner.

Every release archive includes:

- `psmore` binary
- `LICENSE`
- `CHANGELOG.md`
- `docs/psmore.1` man page
- bash/zsh/fish completions
- install/uninstall scripts
- build provenance (`BUILD-INFO`)

Installations target `~/.local` by default (no shell startup file modification). User diagnostics and preferences are preserved.

`SHA256SUMS` is for integrity checks only. It is **not** a publication identity proof. Always download release artifacts from the official GitHub release page; add signatures or trusted metadata in a future release if required.

## Local release package and verify

```bash
scripts/package-release.sh
scripts/verify-release-package.sh dist/psmore-v*-$(rustc -vV | sed -n 's/^host: //p').tar.gz
```

Set `SOURCE_DATE_EPOCH` for deterministic rebuilds.

Packaging keeps file order, ownership, permissions, and gzip metadata deterministic. For identical source, target, toolchain, and packaging settings, checksum output should be reproducible.

`BUILD-INFO` records:

- source commit
- dirty working tree state
- target
- Rust version

## GitHub release

1. Ensure CI is green and your local branch is clean.
2. Update `Cargo.toml` version, then commit.
3. Create and push an annotated tag that exactly matches the target version, e.g. `vX.Y.Z`.
4. GitHub Release workflow builds all four native targets, runs self-install/uninstall verification.
5. The publish step collects artifacts + checksums and publishes release assets.
6. Manually verify:
   - `SHA256SUMS`
   - `BUILD-INFO`
   - `psmore --version` for at least two platforms.

Workflow permissions are minimal: repository `contents: write` permission is enabled only in the upload phase.

## crates.io

Before first publish:

```bash
cargo package --locked
cargo publish --locked --dry-run
```

After `v` tag and GitHub release point to the same commit, run:

```bash
cargo publish --locked
```

`Cargo` package versions are immutable. Ensure version/changelog/license/package metadata are fully aligned before publishing.

If/when trusted publishing is configured for GitHub OIDC, release steps can move from manual token-based publishing to signed CI publishing.

## Homebrew tap

`wzfukui/homebrew-tap` is used as the upstream tap repository.

- Formula path: `Formula/psmore.rb`
- Formula should pull source tarball from an immutable tag (`vX.Y.Z`)
- Declare `license "MIT"`
- `test do` should validate with `psmore --version`

Per-release update steps:

1. Fetch tag tarball digest and update `url`, `sha256`, and version in Formula.
2. Run:

   ```bash
   brew audit --strict --online psmore
   ```

3. Validate from clean environment:

   ```bash
   brew install --build-from-source wzfukui/tap/psmore
   brew test wzfukui/tap/psmore
   ```

4. Push tap update, then confirm installation flow in user docs.

After this tap is stable, prepare for Homebrew/core submission only after sustained stability and evidence completeness.

## License

psmore is distributed under MIT License. `LICENSE` is complete in repository root, and `Cargo.toml` uses SPDX `MIT`. Both source and GitHub release artifacts include the license file.
