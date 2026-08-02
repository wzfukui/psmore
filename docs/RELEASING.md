# psmore 发布说明

## 支持的二进制目标

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

每个目标都在同架构的原生 runner 上构建和验证。归档包括 `psmore`、man page、bash/zsh/fish 补全、安装/卸载脚本、版本及构建来源信息。安装器默认写入 `~/.local`，不会修改 shell 启动文件，也不会删除用户偏好或诊断报告。

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

## 许可证边界

仓库当前没有 `LICENSE`，`Cargo.toml` 也设置了 `publish = false`。这不是一个待脚本猜测的技术默认值：公开分发、对外称为开源或发布到 crates.io 前，必须由权利人明确选择许可证或其他分发条款。
