# psmore 发布说明

[English](RELEASING.md) · [中文（简体）](RELEASING.zh-CN.md)

## 支持的二进制目标

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

每个目标都在同架构的原生 runner 上构建和验证。归档包括 `psmore`、MIT 许可证、变更记录、man page、bash/zsh/fish 补全、安装/卸载脚本、版本及构建来源信息。安装器默认写入 `~/.local`，不会修改 shell 启动文件，也不会删除用户偏好或诊断报告。

SHA-256 证明归档与校验清单一致，但不是发布者身份签名。用户必须从可信的 Release 页面取得两者；在正式建立代码签名或签名清单之前，不应宣称资产具备来源认证。

## 本地生成和验证

```bash
scripts/package-release.sh
scripts/verify-release-package.sh dist/psmore-v*-$(rustc -vV | sed -n 's/^host: //p').tar.gz
```

可用 `SOURCE_DATE_EPOCH` 固定归档时间。脚本固定文件顺序、owner、权限和 gzip header；在相同源码、目标、Rust 工具链和归档实现下应产生相同 SHA-256。`BUILD-INFO` 会明确记录源码 commit、工作区是否有未提交内容、目标和 Rust 版本。

## GitHub Release

1. 保证 `main` 的 CI 全绿且工作区干净。
2. 将 `Cargo.toml` 中的版本更新为目标版本并提交。
3. 创建并推送完全匹配的 annotated tag，例如 `v0.1.0`。
4. `Release` workflow 在四个原生 runner 上构建并自安装、自卸载验证。
5. 发布 job 汇总四个归档、各自校验文件和总 `SHA256SUMS`，然后创建 GitHub Release。
6. 下载发布资产，人工复核 `SHA256SUMS`、`BUILD-INFO` 和两个平台的 `psmore --version`。

工作流只使用 GitHub 官方 Actions 和 runner 自带的 `gh` CLI；发布 job 的 `contents: write` 权限只在上传资产时启用。

## crates.io

首个版本发布前确认名称仍可用，并执行与 CI 相同的本地检查：

```bash
cargo package --locked
cargo publish --locked --dry-run
```

确认 GitHub Release 和 tag 对应同一 commit 后，再运行 `cargo publish --locked`。crates.io 的版本不可覆盖，因此只有 Cargo 版本、tag、变更记录、许可证和打包清单全部一致时才发布。

首发完成后，在 crates.io 为 GitHub 仓库配置 Trusted Publishing。后续可由 tag workflow 使用 GitHub OIDC 发布，避免维护长期 `CARGO_REGISTRY_TOKEN`；在受信发布者配置完成前，保持 crate 发布为人工明确步骤。

## Homebrew Tap

个人 Tap 使用独立仓库 `wzfukui/homebrew-tap`，Formula 路径为 `Formula/psmore.rb`。Formula 从 GitHub 上不可变的 `vX.Y.Z` tag 源码构建，声明 `license "MIT"` 和构建期 Rust 依赖，并在 `test do` 中验证 `psmore --version`。

每次发布后的更新步骤：

1. 取得 tag 源码归档的 SHA-256，更新 Formula 的 `url`、`sha256` 和版本断言。
2. 在 Tap 仓库运行 `brew audit --strict --online psmore`。
3. 从干净环境运行 `brew install --build-from-source wzfukui/tap/psmore` 和 `brew test wzfukui/tap/psmore`。
4. 推送 Tap 后，再把 `brew install wzfukui/tap/psmore` 作为正式安装入口。

个人 Tap 稳定后，可向 Homebrew/core 提交 Formula。core 接收前仍应保持源码构建、稳定 tag、双平台测试和独立 Tap，不把二进制归档当成长期 Formula 来源。

## 许可证

psmore 以 MIT License 发布。根目录 `LICENSE` 是完整许可证文本，`Cargo.toml` 使用 SPDX 标识 `MIT`；源码 crate 和 GitHub 二进制归档都必须包含该文件。
