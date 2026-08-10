# psmore

`psmore` 是一个面向开发者和运维人员的跨平台进程关系 TUI：用可导航的树帮助你理解进程的父子关系、启动上下文和运行状态。

当前支持 macOS 和 Linux。两端共用同一套进程模型与交互，数据层结合 `sysinfo` 和系统原生 `ps`，兼顾资源指标、准确的父子关系以及完整启动参数。

## 项目信息

- 当前构建版本：运行 `psmore --version` 查看
- 作者：wzfukui（fukui@wuzhi-ai.com）
- GitHub：[github.com/wzfukui/psmore](https://github.com/wzfukui/psmore)

CLI 的 `--help` 和 TUI 内按 `?` 打开的现场手册也会展示这些信息；版本号始终取自构建时的 `Cargo.toml`，避免界面与二进制版本不一致。

## 特性

当前原型验证的产品靶子：

- 上方以树展示进程父子关系，PID 0 是用于承接系统根、不可见父进程和采集期间消失进程的虚拟根节点
- 下方显示当前节点的 PID、PPID、子进程数、状态、CPU、内存、磁盘读写速率、运行时间、路径和命令
- 下方同时聚合当前进程与全部后代的进程数、CPU、内存和磁盘 I/O，便于判断一个完整服务树的真实资源占用
- 首次进入 TUI 显示三页可翻阅的现场手册；随后每次启动显示一条不阻塞键盘的高级 tip，14 条循环轮播，直到用户主动关闭，并可随时按 `?` 重新打开
- TUI 内置中文和英文：首次按 macOS/Linux 系统语言选择，主界面按 `L` 或任意工作区按 `F2` 手工切换并持久保存
- 按 `F` 管理持久包含/排除过滤器，支持文本、正则、组合表达式、逐条启停和必要父链上下文，再在过滤结果上应用临时 `/` 搜索
- 每一行在 PID 后显示命令行，若命令行不可用则显示可执行文件路径
- 同级进程按名称、PID 确定性排序，刷新时不会因 HashMap 或同名进程导致顺序漂移
- 键盘导航和结构化搜索/过滤；也可直接键入 PID 精确定位并自动暴露父链
- `/` 查询兼容原有名称、命令和 PID 模糊定位，并支持多个 AND 条件：字段搜索、资源阈值、子树聚合、单位换算和 `!` 否定；标题实时显示命中数或具体语法错误
- 使用 `├─`、`└─`、`│` 连接线表达目录式层级
- 父节点仍有后续兄弟时，子树会持续显示 `│`，避免子进程连接线悬空
- 选中一个进程后，其同级兄弟以低亮度提示，当前进程保持强高亮
- 选中 L1/L2 进程时不显示兄弟背景高亮；搜索状态下，同名进程使用文本高亮
- `←` 暴露父进程并收起同级其他分支，`→` 展开当前进程
- 选中项移动到窗口边缘时，树列表自动滚动
- 底部状态栏显示真实进程总数、当前页和总页数；PageUp/PageDown 按当前窗口高度翻页
- `→` 在展开/折叠当前子进程之间切换，折叠时显示隐藏的直接子进程数，例如 `node (3)`
- 底部详情始终显示完整启动命令和参数，并按终端宽度自动扩展换行
- 实时记录进程启动、退出和父进程变化；新进程短暂显示为绿色，父进程变化显示为黄色
- `Space` 暂停/恢复自动刷新，暂停后进程树完全静止，仍可导航、搜索并按 `r` 手动采样
- `e` 打开活动审计面板；内存中保留最近 100 次人工进程操作和 200 条进程变化，最新操作固定显示在变化列表上方，避免被高频短命进程淹没
- `Enter` 深度检查选中进程，将概览、热点线程、端口/连接和打开文件拆成四张信息卡片；`Tab`/`Shift+Tab` 前后切换，每张卡片独立从顶部开始滚动，减少小屏幕中的信息拥挤
- `D` 为选中进程建立一键事故档案：并行汇总深检、服务归属、可执行映像和有界原生日志，先展示带证据路径的优先级线索，再可跳入四类原始证据
- `M` 为选中进程后台采集内存归因：区分采样 RSS、精确 RSS/PSS 或 footprint、Swap、类别与映射，并可在诊断工作区之间互相跳转
- 深度检查按 CPU 从高到低展示热点线程：macOS 通过系统 `libproc` 获取 64 位线程 ID、名称、状态和调度器 CPU 估值；Linux 对 `/proc/<pid>/task` 做约 250 ms 差分采样，并显示 TID、状态、优先级、nice 值和所在 CPU 核
- 线程列表最多展示最热的 50 行，但始终保留真实线程总数、采样间隔、截断状态和采集警告；线程采集与其他深度检查一起在后台运行，不阻塞进程树
- Linux 深度检查进一步展示线程、RSS/Swap、上下文切换、cgroup、systemd 单元、Docker/containerd/Podman/Kubernetes 线索、命名空间、Seccomp、能力位和关键资源限制
- `s` 在稳定排序、子树 CPU、子树内存、子树读速率和子树写速率热点之间循环；热点模式保留父子层级，只重排同级进程
- `h` 打开四象限热点工作台，同时展示 CPU、内存、磁盘读、磁盘写 Top 进程；按 `v` 在进程自身与完整服务子树之间切换，并可直接跳回进程树
- `a` 打开关注事项工作台，将僵尸/停止状态、60 秒内反复启停、持续 CPU/I/O、较大内存占用和短期内存增长合并排序，并逐条给出可核对的证据
- 关注事项分为 `CRIT`、`WARN`、`WATCH`，分数只用于排列检查优先级，不把启发式信号伪装成已确认故障；可直接跳转进程、查看趋势或进入深度检查
- 为每个进程实例保留最近 90 次资源采样；`t` 展示进程自身及完整子树的 CPU/内存趋势，按 `i` 切换读写 I/O 趋势，均提供当前值、平均值和峰值
- PID 被复用时自动开启新的历史序列；已退出进程的趋势短暂保留 5 分钟，避免短命进程刚退出就丢失诊断线索
- `b` 捕获内存中的系统基线，`d` 对比当前状态：集中列出新增、退出、PID 复用、父进程变化，以及子树 CPU、内存、读写速率增长排行
- 基线对比以进程启动时间区分同一 PID 的不同实例，并显示全系统进程数、CPU 和内存变化，适合发布、压测或故障前后核对
- `n` 按需扫描全局 TCP/UDP/Unix socket；默认聚焦监听端口，按 `v` 切换到全部连接，展示本地到远端路由、状态、PID、FD 与网络命名空间，并可直接跳回所有者进程树
- 全局网络扫描、进程深度检查、内存归因、Service Context、原生日志和可执行映像验证都在后台执行；耗时采集会显示动画与已用时间，期间进程树继续刷新，键盘关闭面板和退出始终可用
- `k` 打开专用 TERM/KILL 结束弹窗，`p` 打开完整进程操作中心；两者选择操作后都必须另按 `y` 确认，执行前会重新校验 PID 与启动时间，避免把信号发给复用该 PID 的新进程
- PID 0、PID 1 和 `psmore` 自身受强制保护；每次已发送、被安全策略拒绝或被操作系统拒绝的结果都会进入活动审计
- `o` 将当前诊断上下文导出为带版本号的 JSON 报告，包括完整进程清单、资源聚合、当前查询及命中数、关注事项、最近事件和进程操作审计；已经打开的网络扫描、深度检查、内存归因、Dossier、Service Context、原生日志、可执行映像证据及已捕获基线会一并写入，但导出本身不会触发额外扫描
- 支持无交互快照模式：`--table` 输出适合 SSH 现场查看的稳定表格，`--json` 输出带版本号的机器可读快照；两者复用 TUI 的完整查询语法与子树资源聚合
- 无交互模式执行两次采样，默认间隔 500 ms，使 CPU 与磁盘 I/O 速率具有实际意义；可用 `--sample-ms` 在 100–60000 ms 之间调整
- 所有无交互表格、JSON 和 JSONL 输出支持 `--redact`：在保留命令结构的同时遮盖常见密码、token、API key、认证 header、URL userinfo 和敏感查询参数
- `psmore doctor` 提供一条命令的保守主机体检：快速模式结合有效内存、Swap、持续负载、异常进程状态和四类热点榜；显式 `--deep` 再并行扫描网络暴露、FD 压力、已删除仍占用文件及 Linux OOM/PSI 证据
- `psmore diff BEFORE.json AFTER.json` 自动识别进程快照或主机体检报告：前者对比启动/退出、PID 复用、父进程与资源增量，后者对比新观察到/恢复/持续信号、严重度以及主机和 deep 证据变化；支持 `--fail-on regression --quiet` 发布门禁和 `--output` 私有原子归档
- `psmore check QUERY` 将任意结构化查询变成 CI/运维健康门禁：排除检查器自身及其对子树聚合的干扰，默认期望零命中，`--expect any` 可反向要求服务存在；`--wait` 等待发布/恢复收敛，`--stable` 要求连续多个样本通过
- `psmore inspect PID` 将 TUI 深度检查直接带到 SSH、脚本和事故工单：一次输出进程身份、完整命令、热点线程、socket、打开文件及平台运行上下文，也可导出 `psmore.process-inspection` JSON
- `psmore memory PID` 将进程内存拆成可归因证据：Linux 展示精确 RSS、PSS、匿名/文件/共享/私有页、Swap、峰值、虚拟区域和文件映射，macOS 展示 physical footprint、峰值及 `vmmap` resident/dirty/swapped 类别
- `psmore explain PID` 是面向事故现场的一键进程档案：并行拼合深检、服务归属、可执行映像和原生日志，再按严重程度列出可追溯到原始证据的关注事项
- `psmore exe PID` 核对进程实际持有的可执行映像与当前磁盘路径，识别发布后仍运行旧映像、文件已删除或被替换，并补充软件包和代码签名来源
- `psmore stale [QUERY]` 在 Linux 整机扫描仍持有已删除或已替换可执行映像的进程，关联 systemd unit/软件包，并可作为发布后的保守健康门禁
- `psmore service PID` 将任意进程反查到 Linux systemd unit 或 macOS launchd job，展示状态、重启、配置来源、资源边界和可复制的下一步只读诊断命令
- `psmore logs PID` 直接读取目标进程的原生日志：Linux 自动关联 journald 中的 systemd service，macOS 使用 Unified Logging；时间窗、等级、条数和进程/服务边界均可显式控制
- `psmore port PORT` 直接回答“谁占用了这个端口”：将 TCP/UDP 本地端点关联到 PID、用户、完整命令、FD 和 Linux 网络 namespace，并可作为端口存在/释放健康门禁
- `psmore listen` 从全局监听面反查进程和启动上下文，并将 wildcard、非回环网络、loopback 与 Unix socket 分类；`--exposed` 可直接聚焦需要安全复核的主机暴露面
- `psmore net [FILTER]` 检索全局监听、已建立 TCP/UDP 对端和 Unix 连接，展示本地到对端路由、状态、PID/FD、完整进程上下文和 Linux 网络 namespace，并支持状态门禁
- `psmore tree PID` 在非交互环境输出目标的完整父链和后代树，保留目录连接线、稳定同级排序、进程自身/完整子树资源及显式深度截断，也可导出嵌套 JSON
- `psmore watch [QUERY]` 建立进程基线后持续输出启动、退出、PID 复用、父进程变化及动态查询进入/离开事件；支持实时刷新的表格和每行一个文档的版本化 JSONL
- `psmore trace PID` 连续记录单个进程及完整服务子树的 CPU、内存和 I/O，给出相对基线/上一采样的增长、实际采样间隔和峰值汇总；进程退出或 PID 复用时安全终止
- `psmore run -- COMMAND` 从启动瞬间跟踪命令及完整后代树，汇总真实退出状态、耗时、进程构成和 CPU/内存/I/O 峰值；命令标准输出保持可管道使用
- `psmore top [QUERY]` 将 TUI 热点排名带到 SSH 和脚本：按 CPU、内存、磁盘读或写排序，可在进程自身与完整服务子树口径之间切换，并输出稳定表格或版本化 JSON
- `psmore oom [QUERY]` 在 Linux 上联合展示主机 MemAvailable/Swap、memory PSI、OOM kill 计数与进程 `oom_score`/调整值/cgroup 内存事件，区分“杀进程优先级”和“正在发生内存压力”
- `psmore cgroup [FILTER]` 将 Linux 进程按实际 systemd/容器 cgroup 边界分组，并列展示可见成员资源、内核层级内存/PID 上限及累计 OOM 事件
- `psmore file PATH` 反查谁正在执行、映射、打开或以 cwd/root 使用某个文件；`--recursive` 可定位目录或挂载点下的全部使用者，并可作为发布替换、卸载和清理前的安全门禁
- `psmore deleted` 定位“文件已删除但进程仍占用”的磁盘空间泄漏：展示 PID、FD、用户、完整命令、文件身份与大小，并按 device+inode 去重估算真正可释放空间
- `psmore fd` 对全系统打开的文件描述符做风险排名：展示 PID、用户、完整命令、FD 数量以及 Linux 软/硬限制和使用率，可直接作为 FD 泄漏或耗尽的巡检门禁
- 深度检查仅在打开或手动刷新面板时启动后台采样：macOS 调用一次 `lsof`，Linux 直接读取目标进程的 `/proc`，不会加入两秒一次的全局刷新
- 每 2 秒从系统进程数据刷新一次

### 首次使用与渐进提示

psmore 的交互界面内置中文和英文。第一次启动时自动读取操作系统语言：macOS 使用全局 `AppleLanguages`/`AppleLocale`，Linux 和其他 Unix 环境使用标准 locale；中文环境启用中文，其他语言环境回退英文。之后可在主界面按 `L`，或在任意工作区按 `F2`，立即切换语言。手工选择会写入同一份私有偏好文件，并在后续启动时优先于系统语言。临时指定首次语言可设置 `PSMORE_LANG=zh_CN` 或 `PSMORE_LANG=en_US`。命令行表格、JSON schema、查询字段和脚本输出继续使用稳定英文，避免破坏自动化。

第一次进入交互界面时，psmore 会展示三页现场手册，将主要能力按“理解进程树 → 从症状找到证据 → 安全操作与分享”组织起来。使用 `←`/`→`、`↑`/`↓` 或 `Tab` 翻页，`Enter`/`Esc` 开始工作；`q` 和 `Ctrl-C` 始终可以直接退出。

完成首次手册后，每次启动会在右下角展示一条高级 tip，覆盖子树查询、热点、基线、网络、趋势、内存归因、Dossier、原生日志、映像验证和安全操作；14 条完成后从第一条继续轮播，直到用户主动关闭。Tip 不会抢走工作键：除 `Enter`、`Esc`、`?`、`T`、`D` 外，按下任意键都会关闭 tip 并继续执行该键原本的操作，例如 `Space` 仍会立即暂停、`/` 仍会开始查询。

任何时候按 `?` 都能打开完整现场手册。引导内按 `T` 切换未来启动 tip，按 `D` 永久关闭启动卡片；只想本次跳过可运行：

```bash
psmore --no-tips
```

偏好以 schema 化 JSON 私有保存：macOS 位于 `~/Library/Application Support/psmore/ui-state.json`，Linux 位于 `${XDG_CONFIG_HOME:-~/.config}/psmore/ui-state.json`。目录新建时权限为 `0700`，状态文件通过同目录临时文件原子写入并使用 `0600`；测试、便携环境或受管部署可用 `PSMORE_CONFIG_DIR` 改变目录。状态损坏、版本不兼容或不可写时，TUI 仍会启动，并把问题显示为可见提示，不会因为教学功能阻断诊断工作。

### 持久包含/排除过滤器

主界面按 `F` 打开进程过滤器。过滤器先于临时 `/` 搜索执行，适合长期隐藏系统噪声，或只保留一组应用和服务；`a` 新增包含（ALLOW）规则，`x` 新增排除（DENY）规则，`Enter`/`e` 编辑，`Space` 临时启停，`d` 删除。规则会写入上述私有偏好文件并在下次启动恢复。

每条规则使用与进程查询相同的表达式，规则内部的多个条件为 AND；多条包含规则之间为 OR；任意排除规则命中都会覆盖包含结果。没有启用包含规则时默认允许全部进程。被保留进程的必要父链仍会显示为关系上下文，但不会计入“通过”数量：

```text
ALLOW  path:/Applications name:ChatGPT
ALLOW  path:/opt/homebrew
DENY   path:/System/Library
DENY   name~^(Updater|Helper)$
```

`field:value` 是不区分大小写的文本包含；`field~regex` 使用标准 Rust 正则，默认区分大小写，可用 `(?i)` 切换；包含空格时使用引号，例如 `path:"/Applications/Google Chrome.app"`。正则可限定到 `any`、`name`、`cmd`、`path`、`user` 或 `state` 字段。无效规则不能保存；如果偏好文件被外部修改成无效规则，psmore 会明确报错并采用 fail-open 策略展示全部进程，避免事故处理中因配置错误隐藏证据。

## 结构化查询

按 `/` 后输入文本，进程树在编辑期间保持不变；按 `Enter` 才应用搜索并回到进程选择模式，例如 `/codex` `Enter` 或 `/8080` `Enter`。多个条件用空格连接，必须同时满足：

查询同样支持 `field~regex` 正则和带引号的空格值，例如 `name~^(python|node)$` 或 `path:"/Applications/Google Chrome.app"`。

| 示例 | 含义 |
| --- | --- |
| `user:joe state:sleep` | 用户为 joe 且状态包含 sleep |
| `name:python !cmd:jupyter` | 名称包含 python，但命令行不含 jupyter |
| `pid:1234`、`ppid:1` | 精确匹配 PID 或 PPID |
| `cpu>20 mem>=500m` | CPU 超过 20%，内存至少 500 MiB |
| `read>1mb/s write<500k` | 每秒读写速率阈值 |
| `age>2h children>=3` | 已运行超过两小时，至少三个直接子进程 |
| `tree.cpu>80 tree.mem>2g` | 当前进程及全部后代的聚合资源阈值 |
| `tree.procs>=10` | 完整进程子树至少包含十个进程 |

文本字段包括 `name:`、`cmd:`、`path:`、`user:`、`state:`；数值比较支持 `>`、`>=`、`<`、`<=`、`=`。内存和 I/O 支持 `k`、`m`、`g`、`t`，运行时间支持 `s`、`m`、`h`、`d`。任意条件前加 `!` 表示排除。

## 安装

发布归档不要求目标机器安装 Rust。下载与系统架构匹配的 `psmore-vVERSION-TARGET.tar.gz` 及同名 `.sha256` 后，先校验再安装：

```bash
# Linux；macOS 将 sha256sum 换成 shasum -a 256
sha256sum -c psmore-v0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf psmore-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd psmore-v0.1.0-x86_64-unknown-linux-gnu

# 默认安装到 ~/.local，不使用 sudo，不修改 shell 启动文件
./install.sh --dry-run
./install.sh
~/.local/bin/psmore --version

# 精确删除二进制、man page 和补全；用户状态与诊断报告会保留
~/.local/share/psmore/uninstall.sh --dry-run
~/.local/share/psmore/uninstall.sh
```

可以用 `--prefix /absolute/path` 指定安装位置，或设置 `PSMORE_PREFIX`；`--no-completions` 只安装二进制、man page 和卸载器。安装后的 man page 位于 `$PREFIX/share/man/man1/psmore.1`，bash、zsh、fish 补全分别安装到各自约定的 `$PREFIX/share` 目录。若 `~/.local/bin` 尚未加入 `PATH`，安装器会给出明确提示。

从当前源码安装需要 Rust 1.85 或更高版本：

```bash
cargo install --path . --locked
psmore --version
psmore --help
```

默认目标通常是 `~/.cargo/bin/psmore`；请确保 `~/.cargo/bin` 已加入 `PATH`。开发中的本地覆盖安装可使用 `cargo install --path . --locked --force`。psmore 不要求 root；以更高权限运行只会扩大受操作系统权限控制的进程、FD 和网络可见范围。

源码仓库可为当前机器生成与 CI 相同结构的原生归档，并执行隔离的安装/卸载验证：

```bash
scripts/package-release.sh
scripts/verify-release-package.sh dist/psmore-v*.tar.gz
```

发布归档记录源码 commit、dirty 状态、目标架构、Rust 版本和固定时间源，并生成 SHA-256 校验文件。SHA-256 用于确认下载完整性，不代替发布者身份签名；应从可信的发布页面同时取得归档和校验文件。详细发布流程和许可证边界见 [`docs/RELEASING.md`](docs/RELEASING.md)。

## 运行

需要 Rust 1.85 或更高版本，以及系统自带的 `ps`（Linux 通常由 `procps` 提供）。macOS 深度检查使用系统 `lsof`；Linux 直接读取 `/proc`，不需要额外诊断工具。缺少诊断数据源时进程树仍可正常使用，检查面板会明确提示原因。

```bash
cargo run --release
```

首次进入交互界面会打开 `psmore field guide`，用三页说明进程树、诊断工作台和安全操作。按 `←`/`→` 翻页，`Enter` 或 `Esc` 开始使用；后续启动只显示一条轮换 tip，并持续循环直到用户主动关闭，不会每次遮住整个界面：

```bash
# 只跳过本次启动的欢迎页或 tip，不改变持久偏好
psmore --no-tips

# 也接受语义更完整的别名
psmore --no-onboarding
```

在欢迎页、tip 或按 `?` 打开的帮助中，按 `T` 切换后续启动 tips，按 `D` 永久关闭所有启动卡片；关闭后仍可按 `?` 打开帮助并用 `T` 重新启用。偏好状态使用私有原子文件：macOS 默认位于 `~/Library/Application Support/psmore/ui-state.json`，Linux 默认位于 `${XDG_CONFIG_HOME:-~/.config}/psmore/ui-state.json`；测试、便携安装或受管环境可用 `PSMORE_CONFIG_DIR` 指定目录。状态文件不保存进程信息，Unix 权限为 `0600`。

源码安装后也可以按需手工启用命令、选项和枚举值补全；发布归档的安装器会自动放置这些文件：

```bash
# zsh：持久安装；确保 ~/.zfunc 在 fpath 中并已执行 compinit
mkdir -p ~/.zfunc
psmore completion zsh > ~/.zfunc/_psmore

# bash：当前会话，或写入系统所用的 bash-completion 目录
eval "$(psmore completion bash)"

# fish：持久安装
mkdir -p ~/.config/fish/completions
psmore completion fish > ~/.config/fish/completions/psmore.fish
```

`psmore COMMAND --help` 显示对应命令的精简用法、参数、退出码和示例，不再重复整页全局帮助。`psmore completion --help` 给出各 shell 的安装入口；生成脚本只输出到标准输出，不会自行修改 shell 配置。

也可以直接在 SSH、Shell 管道或巡检脚本中采集一次快照：

```bash
# 人工快速查看：PID 顺序稳定，保留自身与完整子树资源
cargo run --release -- --table --query 'user:deploy cpu>5'

# 自动化采集：JSON 只包含匹配项，并记录查询、平台、主机和采样间隔
cargo run --release -- --json --query 'tree.mem>1g !state:zombie' > snapshot.json

# 以指定筛选条件直接进入交互界面
cargo run --release -- --query 'name:python children>=1'
```

安装后的二进制可将上述 `cargo run --release --` 简写为 `psmore`。`--table` 表头中的 `TCPU%`、`TMEM`、`TPROCS` 分别表示当前进程及全部后代的聚合 CPU、内存和进程数。`--json` 使用 `psmore.process-snapshot` schema v1，进程按 PID 稳定排序，并同时提供自身指标、直接子进程数和 `subtree` 聚合指标。命令行、路径、用户名和主机名可能包含敏感信息；对外分享时建议启用 `--redact` 并人工复核。

无交互模式的退出码约定：成功为 `0`，采集/输出错误为 `1`，参数或查询错误为 `2`，`check` 策略违反为 `3`。若输出管道的读取端提前关闭（例如 `psmore --table | head`），不会打印 Broken pipe 错误；`check` 仍保留原本的策略退出码。

### 安全分享与命令脱敏

`--redact` 可放在任意无交互命令前后，只影响最终输出，不改变进程匹配、身份校验、排序或差异判断：

```bash
# 分享单个进程诊断，隐藏 --password、--token、API_KEY 等常见密钥值
psmore inspect 1234 --json --redact > process-1234.safe.json

# 分享连接证据，同时遮盖进程命令中的 URL 密码和认证参数
psmore net --connected --redact

# 快照、流式事件和持久快照对比同样支持
psmore --table --query name:api --redact
psmore watch name:worker --jsonl --redact
psmore diff before.json after.json --redact
```

脱敏会将识别到的值替换为 `[REDACTED]`，并尽量保留原有参数名、引号和 URL 结构。它是便于事故工单和团队协作的尽力保护，不是完整匿名化：主机名、用户名、文件路径、普通查询参数、IP 和端口仍会保留，分享前仍应检查输出。交互式 TUI 不接受 `--redact`，因为 TUI 不产生可直接分享的命令输出文件。

### 一键主机体检

刚登录一台陌生主机、还不知道该从 PID、端口还是资源入手时，可以先运行：

```bash
# 主机证据、风险信号以及 CPU/内存/读/写四类热点
psmore doctor

# 主机检查仍保持全局，仅把进程信号与热点限定到部署用户
psmore doctor 'user:deploy' --limit 10

# 显式执行较重的全局扫描，并把结果合并到同一份报告
psmore doctor --deep

# 生成适合工单归档的版本化、安全分享 JSON
psmore doctor --json --redact > doctor.safe.json

# 更安全的归档方式：同目录临时文件、0600、完整写入后原子发布
psmore doctor --deep --redact --output doctor.safe.json

# 自动化门禁：仅发现 critical 信号时退出 3，正常时完全静默
psmore doctor --fail-on critical --quiet
```

`doctor` 有意采用保守语义：它报告的是需要核对的采样信号，不把启发式判断包装成已确认根因。快速模式检查有效内存可用比例、Swap 与当前低内存的组合压力、按逻辑 CPU 数归一化的 15 分钟负载、僵尸/停止进程、单进程内存占比、运行超过一定时间后的高 CPU 或高 I/O 样本，以及超过 250 个进程的服务树。Linux 容器内优先采用当前 cgroup 的内存限额；macOS 使用系统 `memory_pressure`，失败后再回退到 `vm_stat`，表格和 JSON 都会标明内存证据来源。

`--deep` 明确表示接受额外扫描成本：网络暴露、FD、删除文件和 Linux OOM 采集会并行执行，并记录总耗时、完整性和权限警告。暴露端口和累计 OOM 次数本身只作为观察证据，不会因为“存在”就判定故障；只有 FD 使用率达到 75%、至少 100 MiB 的已删除文件仍被持有，或 Linux PSI 显示当前内存停顿时才新增 warning/critical 信号。macOS 无法可靠取得所有进程的 soft FD limit 时会显示 `partial`，不会把未知伪装成安全。OOM/PSI 在非 Linux 平台明确标为不支持。

`--output FILE` 自动选择 JSON，并在目标目录写入 `0600` 临时文件，完成写入和 `sync_all` 后再原子发布；不指定 `--force` 时通过 no-replace 发布拒绝覆盖已有路径，指定后才原子替换。写入成功后标准输出只显示文件路径和 findings 摘要，不再重复整份 JSON；配合 `--quiet` 可完全静默。`--table` 与 `--output` 冲突，`--output -` 也会拒绝并提示直接使用 `--json`。JSON 的 `secrets_redacted` 字段明确记录本次是否启用了 `--redact`。

默认 `--fail-on never`，所以发现信号也会成功退出，适合人工体检。显式使用 `--fail-on warning` 或 `--fail-on critical` 后，达到阈值退出 `3`；`--quiet` 必须配合这两个阈值之一。查询只作用于快速进程信号和热点，主机内存、Swap、负载以及所有 deep 检查始终保持全局，避免把“筛选不到进程”误解为“主机健康”。JSON 使用 `psmore.host-doctor` schema v1；未启用时 `deep` 为 `null`，启用后包含四类采集证据。

快速体检结果底部会建议继续运行独立诊断命令或改用 `--deep`。全局 socket、文件描述符和删除文件扫描不会被悄悄塞进默认体检耗时中。

### 查询健康门禁

`check` 使用与 TUI 完全相同的字段、单位、否定条件和子树聚合，不需要维护第二套监控表达式：

```bash
# 发现任意僵尸进程即失败，命中时退出 3
psmore check 'state:zombie'

# 要求部署用户的 API 至少存在一个，否则退出 3
psmore check 'name:api user:deploy' --expect any

# 发布后最多等待 30 秒，并要求连续 3 次采样都看到 API 才通过
psmore check 'name:api user:deploy' --expect any \
  --wait 30s --interval-ms 1000 --stable 3 --quiet

# 等待旧 worker 完全退出；条件收敛即提前返回
psmore check 'name:old-worker' --expect none --wait 2m --stable 2

# 限制完整服务树内存，并输出适合 CI 归档的单一 JSON 文档
psmore check 'tree.mem>2g' --json > memory-gate.json

# cron/探针只关心退出码，不产生标准输出
psmore check 'cpu>90 age>5m' --quiet
```

默认 expectation 是 `none`，即零命中才通过；`--expect any` 表示至少一个命中才通过。默认只评估一次；指定 `--wait 30s`、`--wait 500ms`、`--wait 2m` 或 `--wait 1h` 后，会按 `--interval-ms` 节拍重试，条件满足即提前返回，超时仍不满足则退出 `3`。等待时间必须不短于 `--sample-ms`。`--stable N` 要求连续 N 次评估通过，中间任意失败都会把连续计数清零，适合等待滚动发布真正稳定，而不是被一个瞬时进程骗过。

每次评估仍对 CPU 与 I/O 执行两次采样，默认间隔 500 ms，可用 `--sample-ms` 调整；`--interval-ms` 控制评估开始节拍，两者职责不同。截止前已经开始的最后一次原子采样会完整结束，因此 JSON 中的实际 `elapsed_ms` 可能略高于配置的 timeout。检查器自己的 PID 永远不会参与查询；若 psmore 是某个 shell、CI runner 或服务树的子进程，它的 CPU、内存、I/O 和进程数也会从该祖先的 `tree.*` 与 `children` 条件中扣除，避免探针改变被测对象。表格明确显示尝试次数、连续通过数、耗时、超时状态以及 collector exclusion；`psmore.check-result` JSON 在 `evaluation` 中提供同样的机器可读证据，并保留最后一次过滤快照。

### 无交互进程深检

知道异常 PID 后，无需进入 TUI 再定位，可以直接取得适合现场阅读或归档的完整上下文：

```bash
# SSH 现场阅读：完整命令、资源、线程、socket、文件和平台上下文
psmore inspect 1234

# 机器可读输出，可附到事故工单或交给 jq/其他诊断程序
psmore inspect 1234 --json > process-1234.json

# 调整进程 CPU 与 I/O 的采样间隔；Linux 热点线程仍使用自身约 250ms 差分
psmore inspect 1234 --sample-ms 1000
```

表格不截断命令、socket 或文件路径；终端自行换行。JSON 使用 `psmore.process-inspection` schema v1，包含采集主机、进程资源、运行上下文、安全信息、namespace、资源限制、热点线程、socket 和打开文件。macOS 的线程 CPU 明确标记为 `scheduler_estimate`，Linux 标记为 `sample_delta` 并记录实际采样毫秒数。

命令在深检前后重新采集目标 PID：若确认发生 PID 复用，会拒绝合并两个进程实例并以退出码 `1` 失败；若目标在采集中正常退出，则保留已经取得的诊断结果，同时将身份标记为 `exited_during_collection`。无法取得启动时间时会标记为 `unverified`，不会伪装成已经确认。输出可能包含敏感参数、路径、用户名、线程名和网络端点，分享前应检查。

### 单进程内存归因

发现一个大内存进程后，RSS 只能说明当前采样规模，不能回答内存主要来自匿名堆、共享页、文件映射还是已经换出。`memory` 对一个确定的进程实例做只读归因：

```bash
# 默认每节返回前 20 行，适合 SSH 现场阅读
psmore memory 1234

# 保留全部类别和文件映射，输出版本化 JSON
psmore memory 1234 --limit all --json > memory-1234.json

# 分享前遮盖命令行中的常见 secret；映射路径仍需人工复核
psmore memory 1234 --json --redact > memory-1234.safe.json
```

Linux 读取 `/proc/<pid>/smaps_rollup`、`status` 和 `maps`：RSS/PSS、匿名页、文件页、共享内存、private/shared、Swap 和 locked 是物理内存证据；类别和逐文件映射的大小来自虚拟地址范围，只说明预留或映射空间，不能当作 resident。已删除映射、明显 Swap、locked pages、匿名内存占优和峰值远高于当前值会作为带 JSON evidence path 的保守复核线索。权限不足或采集竞态会逐项标为 unavailable/partial，不把缺失证据当成零。

macOS 使用系统 `vmmap -summary`：physical footprint 是更适合判断进程实际内存成本的指标；类别 resident 包含共享映射，因此与 footprint 口径不同，二者会分别命名，不做错误等同。summary 模式不提供可靠的逐文件归因，所以该列表明确为空。`--limit N|all` 同时控制类别和文件映射两节的最大返回行数，默认 20。

JSON 使用 `psmore.process-memory` schema v1，记录采集来源、完整性、截断总数和 PID 身份。命令采集前后重新确认启动时间；确认 PID 复用时拒绝拼接两个实例。报告包含完整命令、用户名、内存布局和 Linux 映射路径，`--redact` 只对常见命令行 secret 做尽力遮盖，对外分享前仍需人工检查。

### 一条命令建立进程事故档案

现场看到一个可疑 PID 时，通常还要依次检查运行上下文、服务管理器、磁盘上的程序是否已替换，以及最近日志。`explain` 把这四段只读证据并行采集成一个 dossier，并先给出按 `critical / warning / notice` 排序的线索，再附上每个原始报告：

```bash
# 默认包含最近 15 分钟原生日志和可执行文件 SHA-256
psmore explain 1234

# 快速元数据档案，不读取日志内容和大文件哈希
psmore explain 1234 --no-logs --no-hash --sample-ms 100

# 调整日志边界；Linux 的 service scope 可保留重启前的同服务日志
psmore explain 1234 --scope service --since 2h --priority warning --limit 250

# 私有原子归档；默认拒绝覆盖，确需替换时显式加 --force
psmore explain 1234 --redact --output incident-1234.json
```

四个采集器共享初始 PID 和启动时间作为 dossier 身份，完成后还会再次刷新目标；任何分段 PID/启动时间不一致都会被拒绝归因，整个采集期间确认 PID 复用则整份报告失败。某项因权限、平台能力或竞争条件只得到部分证据时，section 会标记 `partial`，不会把“未看到”解释成“不存在”。

JSON 使用 `psmore.process-dossier` schema v1。每条汇总信号都有稳定 code 和 `evidence_path`，便于工单系统或自动化定位对应原始字段；除服务失败、映像漂移和日志等级外，还会保守提示单次 CPU 热点、线程/socket 规模、可见 FD 对 `RLIMIT_NOFILE` 的占用，以及 Linux 服务对 `TasksMax`/`MemoryMax` 的余量。FD 在 75%/90%/100%、TasksMax 在 75%/90%/100%、MemoryMax 在 80%/90%/100% 分别提高关注级别；单次 CPU 只产生 notice，并明确建议用 `trace` 确认持续性。所有信号只表示复核优先级，不武断宣称根因。

TUI 中选中进程按 `D` 打开同一份摘要；`s`/`p`/`w` 调整日志边界，`L` 开关日志，`h` 开关哈希，`i`/`m`/`v`/`l` 跳到四类原始证据。采集始终在后台进行，`o` 会把已完成的 dossier 嵌入诊断报告但不会为了导出额外触发采集。CLI 的 `--output` 强制写 JSON，使用 mode `0600` 的私有原子文件并默认拒绝覆盖。指定 `--no-logs` 后不能再同时指定 `--scope`、`--since`、`--priority` 或 `--limit`，避免接受实际不会生效的参数。档案可能包含命令参数、路径、用户、文件/网络资源、服务配置、哈希、签名和业务日志；对外分享前应使用 `--redact`，并再次人工检查。

### 进程实际运行的是哪个可执行映像

发布完成但服务没有真正加载新二进制、磁盘文件已被覆盖而旧进程仍存活，或者需要确认程序来自哪个包和签名主体时，可以从 PID 直接核对。在 TUI 中选中进程按 `v` 可直接打开同一份 Verify Image 工作区：

```bash
# 默认比较文件身份并计算 SHA-256
psmore exe 1234

# 机器可读的证据报告；大型文件或只需快速核对时可跳过哈希
psmore exe 1234 --json > executable-1234.json
psmore exe 1234 --no-hash
```

Linux 通过 `/proc/<pid>/exe` 读取进程实际持有的映像，再与命令路径当前指向的磁盘文件比较 device/inode 和 SHA-256，可区分 `same_image`、`replaced_on_disk`、`running_image_deleted`、`disk_image_missing` 与证据不足；同时尽力查询 dpkg、RPM 或 APK 的包名、版本和架构。这样不会把“路径名称相同”误当成“进程已经运行新版本”。

macOS 能验证当前可执行路径、Homebrew Cellar 或 `.app` bundle 来源，并使用系统 `codesign` 展示严格验签结果、identifier、Team ID 和证书链。macOS 普通用户接口不能像 Linux `/proc/<pid>/exe` 那样独立打开进程持有的 Mach-O 映像，因此报告明确使用 `current_path_only`，不会声称已证明运行中 inode 与磁盘文件一致。

默认每个映像最多读取 1 GiB 用于 SHA-256，超过上限会跳过并给出 warning；`--no-hash` 仍保留文件身份、软件包和签名证据。采集前后重新校验 PID 实例，确认复用时拒绝合并。JSON 使用 `psmore.executable-image` schema v1。命令只读，不修改文件、不重启进程；报告含完整命令、路径、所有者、哈希、包和签名信息，分享前应使用 `--redact` 并复核。

TUI 默认同样计算 SHA-256，但采集在后台执行，不阻塞进程树。面板内按 `h` 可在完整哈希与快速身份核对之间切换，按 `Enter`/`r` 重新采集，按 `m` 直接切到同一 PID 的 Service Context，按 `v`/`Esc` 返回进程树；在 Service Context 内按 `v` 可以切回来。

### Linux 整机排查仍运行旧映像的进程

单个 PID 用 `exe` 深挖；发布完成后要确认整台 Linux 主机是否还有服务持有旧二进制，可直接扫描所有可见进程：

```bash
# 列出已替换、已删除或磁盘路径已消失的运行映像
psmore stale

# 只看目标用户/服务范围，并保留全部结果
psmore stale 'user:deploy age>5m' --limit all

# 发布门禁：确认没有可见旧映像；通过 0、违反 3、证据不完整 1
psmore stale --expect none --quiet
```

Linux 使用 `/proc/<pid>/exe` 作为进程实际持有的映像句柄，将其 device/inode 与当前磁盘路径比较。`replaced_on_disk` 表示原路径已经指向另一个文件，`running_image_deleted` 表示旧映像已 unlink 且原路径没有可比较的新文件，`disk_image_missing` 表示磁盘路径消失。结果关联最具体的 systemd service/scope、dpkg/RPM/APK 软件包和可复制的 `psmore exe PID` 深检入口，但不会自动重启进程。

筛选使用完整 psmore 查询语言，`--limit` 只截断返回行，不影响策略对全部匹配项的判断。普通用户无法读取其他用户或受保护进程的 `/proc/<pid>/exe` 时，coverage 会标为 partial；零命中的 `--expect none` 因此返回 inconclusive 和退出码 `1`，不会把“看不见”误报为“整机已清理”。需要整机发布门禁时，应以足够权限运行，或用 `user:`/服务范围把检查限定到当前有权验证的进程。JSON 使用 `psmore.stale-executables` schema v1；macOS 会明确返回不支持。

### 从 PID 追到 systemd 或 launchd 服务

知道进程有问题之后，下一步通常是确认“谁负责拉起它、配置在哪里、为什么会重启、日志该从哪里看”。`service` 将这条管理链直接补到 PID 上；在交互进程树中也可以选中任意进程按 `m`，不离开 TUI 即可打开同一份 Service Context：

```bash
# 人读报告：管理器、unit/job、状态、配置、资源和下一步命令
psmore service 1234

# 适合工单和自动化分析的版本化报告
psmore service 1234 --json --redact > service-1234.safe.json
```

Linux 从目标 `/proc/<pid>/cgroup` 选择最具体的 `.service` 或 `.scope`，区分 system/user manager，再使用 `systemctl show` 获取 ActiveState/SubState、Result、MainPID、重启策略/次数、unit 文件、drop-in、TasksCurrent/TasksMax、MemoryCurrent/MemoryMax 和累计 CPU。`infinity`、有限数值和不可见字段会分别保留，不把未知说成无限制。若当前用户无权访问其他用户的 user manager，仍保留内核 cgroup 归属并明确标为 partial。报告会给出可复制但不会自动执行的 `systemctl status`、`journalctl` 和 `systemctl cat` 命令。

macOS 沿目标父链匹配当前 bootstrap namespace 中已加载的 launchd job，并结合 `launchctl print pid/PID`、job label 和可访问的 `gui/user/system` target，展示 label、运行状态、最近退出状态、程序参数和 plist 来源；下一步提供 `launchctl print`、`launchctl blame`、统一日志及 `plutil` 命令。普通 App 或未能映射到当前 namespace 的进程会明确显示 unmanaged/partial，不猜测不存在的 job。

采集前后会重新验证 PID 实例，确认复用时拒绝合并。JSON 使用 `psmore.service-context` schema v1；输出可能含完整命令、配置路径、用户、主机、service identifier 和建议命令，分享前应使用 `--redact` 并复核。该命令只读，不启动、停止、重启或修改任何服务。

TUI 中的采集在后台执行，进程树与键盘输入不会被 `systemctl` 或 `launchctl` 阻塞。面板内按 `Enter`/`r` 重新采集，使用方向键、`j/k` 或 PageUp/PageDown 滚动，按 `m`/`Esc` 返回进程树；采集期间会持续显示耗时，并在目标退出或 PID 被复用时明确警告。

### 从进程直接读取原生日志

服务归属只能回答“谁管理它”，真正定位异常通常还要继续找日志。`logs` 将这一步收进同一个 PID 工作流；在 TUI 中选中进程按 `l` 即可后台打开，`s` 切换进程/服务边界，`p` 调整等级，`w` 在 5 分钟、15 分钟、1 小时和 6 小时时间窗间循环：

```bash
# 默认最近 15 分钟、info 及以上、最多 100 条，新日志在前
psmore logs 1234

# 严格限定当前进程实例，适合排查单个 worker
psmore logs 1234 --scope process --since 2m --priority debug --limit 250

# 显式读取所属 systemd unit；服务重启后的多个 PID 世代仍在时间窗内
psmore logs 1234 --scope service --since 2h

# 日志可能包含业务数据，分享前进行常见密钥脱敏并再次人工复核
psmore logs 1234 --json --redact > logs-1234.safe.json
```

Linux 使用目标 `/proc/<pid>/cgroup` 解析 systemd unit，再调用 `journalctl` 的机器可读 JSON 输出。默认 `auto` 仅在发现真正的 `.service` 时扩大到服务边界；普通 `session-*.scope` 不会被静默扩大，否则查询一个 shell 可能意外带出整个登录会话的日志。`--scope service` 是显式扩大授权，可读取 `.service` 或 `.scope`；`--scope process` 始终使用 `_PID` 精确选择器。服务边界保留完整请求时间窗，因而能看到当前 PID 启动前的重启线索；进程边界则夹紧到目标启动时间，降低 PID 历史复用造成的误归因。

macOS 使用 `/usr/bin/log show --style ndjson --process PID`，并同样把时间窗夹紧到进程启动时间。Unified Logging 无法可靠地按任意 launchd job 重建所有历史进程世代，因此 macOS 明确拒绝 `--scope service`，不会把猜测当作证据。两平台采集前后都验证 PID 身份；日志条数在内存和输出中有界，JSON 使用 `psmore.process-logs` schema v1，并记录后端、实际选择器、时间边界、完整性、截断状态和身份验证结果。journald 权限提示会令 coverage 标为 partial，而不是把空结果说成“没有日志”。

### 端口占用诊断

端口命令按本地端口精确匹配，不会把 `8080` 错配到 `18080`，默认同时检查 TCP 监听和 UDP 绑定：

```bash
# 查明谁监听/绑定了 8080，并展示 PID、用户、FD 和完整命令
psmore port 8080

# 只查 UDP；--all 还会包含该本地端口上的非监听连接
psmore port 53 --protocol udp
psmore port 443 --protocol tcp --all

# 供自动化消费的版本化 JSON
psmore port 8080 --json | jq '.endpoints[]'

# 要求服务端口存在，或要求发布前端口已经释放
psmore port 8080 --expect any --quiet
psmore port 8080 --expect none
```

不指定 `--expect` 时，端口不存在也属于成功诊断，表格会明确显示零命中。指定 `--expect any|none` 后，策略不满足时退出 `3`；如果零命中但权限或采集错误使结果无法证明，策略状态为 `inconclusive`、`passed` 为 `null` 并退出 `1`。`--quiet` 必须与 expectation 一起使用且完全静默。JSON 使用 `psmore.port-inspection` schema v1，包含匹配端点数、已知所有者数、无法关联所有者的端点数和采集警告。Linux 会扫描各网络 namespace 并通过 socket inode 反查 PID/FD；macOS 使用一次性 `lsof`。权限不足时不会把未知所有者误标成“端口空闲”。

### 全局监听与暴露面

不知道端口号，或者需要核对一台主机在发布后究竟开放了什么时，直接扫描全部监听：

```bash
# TCP、UDP 和 Unix socket 全部监听，默认最多展示 100 条引用
psmore listen

# 只看 wildcard 与非回环 TCP 绑定，即需要进一步复核的网络暴露面
psmore listen --exposed --protocol tcp

# FILTER 同时搜索地址、端口、PID、用户、进程名、路径、完整命令和 namespace
psmore listen nginx
psmore listen 'tri-boost' --exposed

# 返回全部匹配引用及版本化 JSON
psmore listen --exposed --limit all --json

# 安全基线：不允许任何匹配筛选条件的暴露监听
psmore listen debug --exposed --expect none --quiet
```

psmore 将 `0.0.0.0`、`::` 和 `*` 标为 `WILDCARD`，将绑定在任意非回环 IP 的监听标为 `NETWORK`，回环地址标为 `loopback`，Unix socket 标为 `local`。`--exposed` 只保留前两类。这里的“暴露”表示进程绑定允许来自回环之外的流量，并不等于已经可以从公网访问；主机防火墙、安全组、路由、容器端口映射和应用鉴权仍决定实际可达性。

一个 bind 可能因多个 FD、进程或 `SO_REUSEPORT` 产生多条证据。汇总中的 `unique_bind_count` 按协议、地址和 Linux 网络 namespace 去重，`socket_reference_count` 保留每条 PID/FD 证据。JSON 使用 `psmore.listeners` schema v1，并明确记录暴露分类、筛选条件、已知所有者、无法关联的 socket、截断状态和采集完整性。

指定 `--expect any|none` 后，确认违反策略时退出 `3`；零命中但权限或采集错误导致扫描不完整时返回 `inconclusive` 并退出 `1`，不会将不可见监听误判为不存在。`--quiet` 必须和 expectation 一起使用且完全静默。Linux 会跨可见网络 namespace 读取 `/proc` socket 表并按 inode 反查 PID/FD；macOS 使用系统 `lsof`。建议以与目标服务相同的用户运行，必要时再通过经过授权的提权方式扩大可见范围。

### 全局连接与远端端点

`listen` 回答“本机开放了什么”；需要继续回答“哪些进程正在与什么对端通信、连接处于什么状态”时，使用 `net`：

```bash
# TCP、UDP、Unix 的所有监听、绑定、打开和 peer 连接
psmore net

# 只保留具有远端端点或 connected 状态的连接，排除纯监听/绑定
psmore net --connected

# 精确筛选 TCP 状态，并按远端 IP、端口、进程或命令继续搜索
psmore net --protocol tcp --state established
psmore net 203.0.113.10 --connected
psmore net worker --state close-wait

# 返回所有匹配 socket 引用和完整进程上下文
psmore net 443 --connected --limit all --json

# egress/依赖基线：不允许任何可见进程连接到指定地址
psmore net 198.51.100.20 --connected --expect none --quiet
```

FILTER 同时搜索协议、本地端点、对端端点、状态、PID、FD、进程名、用户、路径、完整命令、工作目录和 Linux network namespace。地址保持系统提供的数字形式，不执行 DNS 反查，避免现场命令被 DNS 延迟或名称漂移影响。`--state` 做大小写无关的精确匹配，并将 `time-wait` 规范化为 `TIME_WAIT`；常见状态包括 `ESTABLISHED`、`TIME_WAIT`、`CLOSE_WAIT`、`SYN_SENT`、`CONNECTED`、`BOUND` 和 `LISTEN`。

`--connected` 的含义是“存在非终态 peer 证据”：TCP/UDP 有非空远端端点，或 Unix socket 状态为 connected/connecting，同时排除 `CLOSED`、`CLOSE`、`UNKNOWN`。不加该选项时这些仍会作为历史/打开 socket 证据保留，并可用 `--state` 精确检查。表格中的 `LOCAL -> PEER` 只表达内核当前记录的两端，不根据端口大小或地址猜测连接由本机主动发起还是被动接受；要证明方向需要连接跟踪、数据包或应用日志。

同一路由可能有多个 FD、共享 socket 或多个可见所有者，因此 `unique_route_count` 按协议、本地、对端、状态和 namespace 去重，`socket_reference_count` 保留逐 PID/FD 证据。JSON 使用 `psmore.network-connections` schema v1，记录 peer/listener 分类、完整所有者上下文、筛选条件、截断、采集完整性和方向解释。

健康门禁针对限制前的全部匹配引用；确认违反策略退出 `3`。如果零命中但权限或采集错误使 owner/namespace/socket 表不完整，结果为 `inconclusive` 并退出 `1`，不会把“看不见连接”当成“没有连接”。Linux 跨可见 network namespace 读取 `/proc` 并按 inode 关联 PID/FD；macOS 使用一次全局 `lsof` 扫描。

### 无交互进程关系树

需要把“它是谁启动的、又启动了什么”粘贴到事故工单或在 SSH 管道中处理时，可以直接围绕 PID 截取上下文：

```bash
# 展示从系统根到 PID 1234 的父链，以及 1234 的完整后代树
psmore tree 1234

# 只展开两级后代；被隐藏的后代数量会明确显示
psmore tree 1234 --depth 2

# PID 0 可用于导出完整系统树；大型主机建议同时限制深度
psmore tree 0 --depth 3

# 嵌套 JSON 适合拓扑分析、归档或后续可视化
psmore tree 1234 --json > process-tree-1234.json
```

祖先链始终完整，不计入 `--depth`；深度从目标进程算起，`0` 表示只展示目标，默认 `all`。表格中 `CPU%/TREE`、`MEM/TREE` 和 `PROCS` 同时给出进程自身与完整后代聚合值，即使视觉上因深度限制隐藏了后代，聚合值仍保持完整。命令执行两次采样，默认 500ms，可用 `--sample-ms` 调整。

JSON 使用 `psmore.process-tree` schema v1，将父链放在 `ancestors`，目标及后代放在嵌套 `tree.children`，并分别记录包含虚拟 PID 0 的可见节点数、真实进程数、隐藏后代数和深度限制。文本输出会把真实控制字符及 macOS `ps` 的 `\\011`、`\\012`、`\\015` 空白转义统一为单个空格，避免恶意或异常命令行破坏终端布局。

### 持续事件追踪

活动审计面板适合 TUI 现场查看；需要抓取间歇出现的进程、保留日志或观察资源条件越界时，使用 watch：

```bash
# 追踪全系统进程启动、退出和父进程变化，Ctrl-C 结束
psmore watch

# 只关心命令行中包含 worker 的相关生命周期事件
psmore watch cmd:worker --interval-ms 250

# 动态条件：进程 CPU 越过 80% 时 MATCH，回落时 UNMATCH
psmore watch 'cpu>80 age>5s'

# JSONL 可直接交给 jq、日志采集器或事件处理程序
psmore watch 'user:deploy tree.mem>1g' --jsonl

# 自动化测试中采样 20 次后正常结束，并输出 complete 记录
psmore watch name:api --jsonl --interval-ms 100 --count 20
```

watch 启动后立即输出 `baseline`，随后按间隔采样。事件类型包括 `started`、`exited`、`reparented`、`matched` 和 `unmatched`；PID 复用会明确产生旧实例退出和新实例启动两条事件，不会合并。watch 自身会从查询匹配中排除，避免观察器成为自己的告警噪声。结构化查询与 TUI、snapshot、check 完全一致，因此支持子树 CPU/内存、运行时间、用户和否定条件；建议优先使用 `name:`、`cmd:` 等字段，避免普通文本同时匹配无关字段。

`--count N` 表示基线之后执行 N 次刷新，默认无限；有限 watch 最后输出 `complete` 及实际进程事件数。JSONL 每行均为独立的 `psmore.process-watch-event` schema v1 文档，包含序号、采样序号、相对/绝对时间、主机、查询、当前匹配数、进程实例、父子关系和自身/子树资源。采样只能发现两次刷新之间至少存在于一个快照中的进程；排查极短命进程时应降低 `--interval-ms`，最小 100ms。

### 进程与服务子树连续追踪

`watch` 适合离散生命周期事件；如果进程一直存在但内存、CPU 或 I/O 逐步恶化，使用 `trace` 保存连续证据：

```bash
# 每秒持续追踪，目标退出、PID 被复用或 Ctrl-C 时停止
psmore trace 1234

# 基线之后采样 40 次，每次目标间隔 250ms
psmore trace 1234 --interval-ms 250 --count 40

# JSONL 可直接保存、送入日志系统或流式分析
psmore trace 1234 --interval-ms 500 --count 120 --jsonl > trace-1234.jsonl
jq 'select(.kind == "sample") | [.elapsed_ms, .process.own.memory_bytes, .process.subtree.memory_bytes]' trace-1234.jsonl
```

表格每行同时展示进程自身/完整后代树的 CPU、内存、读写速率和子树进程数，`ΔBASE/TREE` 显示自身及子树相对初始基线的内存变化。JSONL 使用 `psmore.process-trace-record` schema v1，记录 `baseline`、连续 `sample`、可选的 `exited`/`pid_reused`/`identity_unverifiable` 终止事件以及最终 `complete`；每个 sample 同时包含相对基线和上一采样的内存、子树进程数变化。complete 汇总实际刷新数、有效样本数、最终增长及 CPU、内存、I/O 峰值。

`--interval-ms` 是目标间隔，实际间隔还包含系统进程采集耗时，因此 JSON 同时给出 `configured_interval_ms` 和 `actual_interval_ms`，不会把重主机上的延迟伪装成精确周期。`--count N` 不包含立即生成的 baseline；默认无限。

trace 在开始时固定 PID、启动时间、进程名和命令。目标正常退出或该 PID 被新进程复用时，会先输出明确终止事件，再输出 complete，且不会继续采样新实例；这是成功完成的观察，退出码为 `0`。目标一开始不可见，或采样过程中身份从可验证变为不可验证时退出 `1`。当平台从始至终都拿不到启动时间时，会明确标为 `unverified_fallback`，仅在名称和命令保持一致时继续。JSONL 含完整命令、路径、用户和主机信息，分享前应检查敏感内容。

### 从启动瞬间分析一条命令

短命构建、测试脚本和启动器经常来不及先找 PID 再运行 `trace`。`run` 先启动采集器，再拉起命令，并持续识别其完整后代树：

```bash
# 被测命令照常使用终端；结束后在 stderr 输出子树资源报告
psmore run -- make test

# 提高长任务采样间隔；命令自身的参数必须位于 -- 后
psmore run --interval-ms 250 -- ./server --config ./dev.toml

# 命令 stdout/stderr 均保持原样，JSON 以 0600 权限原子归档
psmore run --output profile.json -- sh -c 'worker & wait' | consumer
```

报告使用 `psmore.command-profile` schema v1，包含命令根 PID、退出码或信号、命令耗时、监控耗时、观察到的进程实例数/峰值并发数、完整进程身份及子树 CPU、内存和 I/O 峰值。默认每 100ms 采样；命令退出后继续观察后代最多 1000ms，可用 `--linger-ms 0..60000` 调整。仍有后代时报告标为 `grace_expired`，不会被脱离父进程的守护进程无限阻塞。

命令继承 stdin、stdout 和 stderr；未指定文件时，最终报告写到 psmore 自己的 stderr，因此 shell 管道只收到命令 stdout。需要可靠机器报告时应使用 `--output FILE`：它隐式选择 JSON、以同目录临时文件完整写入后原子发布、权限为 0600，并默认拒绝覆盖；只有显式 `--force` 才替换已有普通文件。这样即使命令自身写 stderr，JSON 也不会混杂。psmore 镜像命令退出码，Unix 信号按惯例返回 `128+signal`。轮询可能漏掉短于采样间隔的进程和尖峰；JSON 的 `observed_lifecycle_complete`、`root_observed`、`first_observation_ms` 与 warnings 会明确说明证据边界。使用 `--redact` 可遮盖报告中的常见密钥，但分享前仍应检查命令、路径、用户名和主机信息。

### SSH 热点排名

只想快速回答“此刻谁最耗资源”时，不必进入 TUI，也不必先导出全量快照再用外部脚本排序：

```bash
# 默认按进程自身 CPU 排名前 20
psmore top

# 内存前 10 名；表格同时保留自身和完整子树指标供判断
psmore top --by memory --limit 10

# 只看部署用户已运行一分钟以上的进程
psmore top 'user:deploy age>1m' --by cpu

# 按完整服务子树的磁盘写入排名，返回全部匹配项
psmore top name:api --scope tree --by write --limit all

# 版本化 JSON 可直接交给 jq 或归档
psmore top --scope tree --by memory --json | jq '.items[] | [.rank, .pid, .ranking_value, .command]'
```

`--by` 支持 `cpu`、`memory`、`read`、`write`，`--scope process|tree` 决定排名值来自进程自身还是当前进程与全部后代的聚合。默认采样 500ms，可用 `--sample-ms` 调整；CPU 和磁盘读写速率与快照、查询和 TUI 使用相同的两次采样口径。查询支持完整字段、阈值、单位和否定语法，并在排名前应用。

表格明确显示排名口径、匹配数、返回数和实际采样间隔，同时为每一项保留自身/子树 CPU、内存、读写速率与子树进程数。指标相同时按小写进程名、PID 升序稳定排序，重复执行不会因 HashMap 顺序漂移。采集器自身始终排除，避免 `psmore` 的短时 CPU 和 I/O 污染结果；JSON 使用 `psmore.process-top` schema v1，并记录单位、排序方向、平局规则、截断状态和该排除规则。`--limit` 只控制返回行数，`--limit all` 返回全部匹配进程。

子树排名会有意保留父子重叠：例如 API 主进程和某个 worker 都可能进入榜单，因为它们回答的是不同边界上的聚合问题。若要锁定一个业务边界，可先用 `name:`、`user:`、`cmd:` 等查询缩小范围，再使用 `psmore tree PID` 核对关系、`psmore trace PID` 观察趋势。

### Linux OOM 与内存压力

线上出现进程被 `SIGKILL`、容器重启、节点内存告警，或者想在发布前检查谁最可能被内核 OOM killer 选择时：

```bash
# 默认列出 oom_score >= 1 的前 20 个候选，并同时展示主机压力证据
psmore oom

# 只看部署用户的大型服务树，返回全部高优先级候选
psmore oom 'user:deploy tree.mem>1g' --min-score 500 --limit all

# 查看某个服务的 cgroup memory 上限和历史 OOM 事件
psmore oom name:api --min-score 0

# 巡检门禁：不允许出现 oom_score >= 700 的 API 进程
psmore oom name:api --min-score 700 --expect none --quiet

# 保存完整机器可读证据
psmore oom --min-score 250 --json > oom-diagnostics.json
```

`oom_score` 是 Linux 内核在当前时刻选择牺牲进程时使用的相对优先级，范围通常为 0–1000；它高并不等于主机正在 OOM。psmore 因此把它标为 `selection_priority`，而不是故障严重度，并在同一结果中提供可用于确认真实压力的独立证据：`MemAvailable`、Swap 使用量、memory PSI 的 `some/full avg10/60/300`、`/proc/vmstat` 中开机以来的 `oom_kill` 计数。计数是累计值，非零只证明本次开机期间曾发生过事件，不证明它刚刚发生。

候选行还包含 `oom_score_adj`、RSS、Swap、完整命令，以及 cgroup v2 的 `memory.current`、`memory.max`、`memory.events` 中 `oom`/`oom_kill`；旧式 cgroup v1 会尽可能读取 memory usage、limit 和 fail count。cgroup 事件同样是该 cgroup 生命周期内的累计证据。`oom_score_adj=-1000` 标为 `PROTECTED`，但其保护范围、祖先 cgroup 限制和系统策略仍应结合现场核对。

`--min-score` 在完整查询之后筛选，`--limit` 只影响返回行数，健康门禁始终针对全部匹配候选。若查询命中的进程在采集期间退出或 `oom_score` 因权限不可读，零命中不能证明不存在，`--expect` 会返回 `inconclusive` 和退出码 `1`；确认违反策略退出 `3`。JSON 使用 `psmore.oom-diagnostics` schema v1，明确记录 score 覆盖、上下文覆盖、截断和解释文本。

该命令依赖 Linux `/proc`、PSI 和 cgroup 文件系统；macOS 会明确返回“不支持”，可先用 `psmore top --by memory`、`psmore trace PID` 和系统内存压力工具排查，不会伪造 Linux OOM 分数。

### Linux cgroup、systemd 与容器边界

单 PID 深检适合回答“这个进程属于哪里”；需要从整机角度比较 systemd 服务、用户 session 和容器边界时，使用 `cgroup`：

```bash
# 默认按内核 cgroup memory.current 排名前 20 个叶级边界
psmore cgroup

# 搜索路径、unit、容器、PID、用户、进程名或完整命令
psmore cgroup docker --by pressure --limit all
psmore cgroup api.service --by cpu

# 保留所有成员及内核控制器证据
psmore cgroup --by processes --limit all --json > cgroups.json
```

每个进程按 `/proc/<pid>/cgroup` 的实际叶级成员关系只归入一个组，避免把父 slice 与子 service 重复相加。表格中的 CPU、RSS、读写速率是当前权限可见的直接成员在同一 psmore 采样周期内求和；`CGMEM/MAX`、`PIDS`、cgroup CPU/I/O 总量和 `memory.events` 则来自内核控制器，通常包含后代 cgroup，是层级证据。两种口径会并列保留，不把 RSS 冒充 `memory.current`，也不把累计 I/O 冒充实时速率。

`--by` 支持 `memory`、`cpu`、`pressure` 和 `processes`。pressure 使用可计算的 `memory.current / memory.max`，没有有限上限的组稳定排在已知值之后。`MEM_WARN`/`MEM_CRIT` 表示当前内存上限利用率达到 75%/90%，`PIDS_WARN`/`PIDS_CRIT` 同理；`OOM_HISTORY` 只表示该 cgroup 生命周期内 `oom_kill` 非零，是需要核对的累计证据，不等于正在 OOM。

JSON 使用 `psmore.linux-cgroups` schema v1，`coverage` 记录成员归因可见性，`selection` 记录筛选与截断，并附带三条资源口径说明。无法读取或采集期间退出的进程会使 coverage 标为 incomplete。psmore 自身会从可见成员列表和成员资源求和中排除；但 `memory.current/pids.current` 等是内核原始层级计数，采集器若与目标同属该组也会短暂包含在内，报告不会偷偷篡改这些计数。命令全程只读；cgroup v2 提供完整控制器证据，旧式 v1 会尽可能读取 memory/pids controller。macOS 没有 Linux cgroup 层级，因此明确返回不支持。

### 文件、目录与挂载点使用者

发布替换文件、卸载挂载点、删除构建目录，或者怀疑进程仍在使用旧配置时，可以直接从路径反查进程上下文：

```bash
# 精确查找执行、映射、打开或作为 cwd/root 使用 config.yaml 的进程
psmore file ./config.yaml

# 找出挂载点及其全部后代路径的使用者，不截断证据
psmore file /Volumes/data --recursive --limit all

# 机器可读证据，包括完整命令、角色、FD、访问模式和覆盖完整性
psmore file /srv/release --recursive --json

# 发布替换或卸载前门禁：发现任意使用者即退出 3
psmore file /srv/release --recursive --expect none --quiet
```

默认是精确路径匹配；`--recursive` 同时匹配路径本身和所有后代，并使用组件边界，不会把 `/srv/app` 错配到 `/srv/application`。相对路径从当前目录解析，存在的目标会先 canonicalize；精确文件还会使用 device+inode 识别硬链接到同一对象的路径。角色分为 `EXEC`（正在执行）、`CWD`、`ROOT`、`OPEN`（数字 FD）和 `MAPPED`（动态库或 mmap）。同一进程对同一路径的不同关系会保留为独立证据。

Linux 读取 `/proc/<pid>/exe`、`cwd`、`root`、`fd` 和 `maps`；macOS 使用一次全局 `lsof`。psmore 自身及采集辅助进程会被排除。`--limit` 默认 100，仅限制返回行，不影响针对全部匹配项的策略判断。JSON 使用 `psmore.file-usage` schema v1。若零命中但权限或进程竞态导致文件视图不完整，`--expect` 结果为 `inconclusive` 并退出 `1`，不会把“看不见”说成“无人使用”。命令只读，不关闭 FD、不卸载文件系统，也不发送信号。

### 文件描述符压力

出现 `Too many open files`、连接建立失败或怀疑服务存在 FD 泄漏时，可以先从全系统风险排名切入：

```bash
# 默认列出 FD 数至少为 1 的风险前 20 名
psmore fd

# 找出打开至少 1000 个 FD 的进程，返回全部匹配项
psmore fd --min-count 1000 --limit all

# 找出已使用至少 80% 软限制的进程；绝对数量与使用率条件同时生效
psmore fd --min-count 1 --min-percent 80

# 版本化 JSON，适合巡检归档、jq 或监控采集
psmore fd --min-count 500 --json | jq '.processes[]'

# 要求不存在使用率达到 85% 的进程；违反策略退出 3
psmore fd --min-percent 85 --expect none --quiet
```

Linux 直接统计 `/proc/<pid>/fd`，并从 `/proc/<pid>/limits` 读取 `Max open files`。表格按实际风险优先：软限制使用率达到 90% 为 `CRITICAL`、75% 为 `WARNING`、50% 为 `ELEVATED`，同一风险级别再按 FD 数排序。`--min-count` 与 `--min-percent` 同时指定时采用 AND 语义。macOS 通过一次全局 `lsof` 统计 FD；系统没有稳定接口供普通进程读取其他进程的 `rlimit`，因此限制和使用率会明确显示为未知，排名退化为 FD 数量排序，不会伪造使用率。使用率筛选在限制未知的平台或进程上不会暗中匹配；若这使零命中无法被证明，策略结果会是 `inconclusive`。psmore 自身从排名和计数中排除，避免采集过程临时打开的 `/proc` 或系统诊断句柄污染结果。

JSON 使用 `psmore.fd-pressure` schema v1，区分系统进程数、成功检查数、匹配数、返回数、限制覆盖数和结果是否截断。`--limit` 默认 20，仅影响展示，不影响 `--expect` 对全部匹配项的判断；使用 `--limit all` 可返回全部结果。指定 `--expect any|none` 后，已确认违反策略退出 `3`。如果零命中但权限限制或进程竞态导致采集不完整，策略为 `inconclusive`、`passed` 为 `null`，退出 `1`，不会把“看不见”当成“没有”。`--quiet` 必须与 expectation 一起使用，并保持完全静默。

FD 数高不等于泄漏：数据库、代理和浏览器可能合理持有大量连接。应结合使用率、持续增长趋势和业务流量确认根因，再关闭泄漏描述符、滚动重启服务或调整限制；psmore 不会替你关闭 FD 或修改资源限制。

### 已删除但仍占用的文件

日志轮转、发布替换或人工删除后，如果旧进程仍持有 FD，目录中已经看不到文件，但空间不会释放。可以直接找出持有者：

```bash
# 列出所有当前用户权限范围内可见的 deleted-open 文件
psmore deleted

# 只关注预计至少占用 100MiB 的文件，支持小数和 k/m/g/t 单位
psmore deleted --min-size 100m

# JSON 适合巡检归档或接入磁盘告警
psmore deleted --min-size 1g --json

# 发现任意大文件即以退出码 3 失败；cron 只读取退出码
psmore deleted --min-size 500m --expect none --quiet
```

同一个已删除 inode 可能被多个进程或多个 FD 持有。psmore 会保留每条 FD 证据，但总文件数和空间按 device+inode 去重，避免重复计算。Linux 从打开 FD 的 metadata 读取实际分配块，`estimate_basis` 为 `allocated_blocks`；macOS `lsof` 不提供分配块，因此使用逻辑大小上界并明确标记 `logical_size_upper_bound`。稀疏文件、压缩文件系统、快照和文件系统延迟仍可能使最终释放量与估算不同。

JSON 使用 `psmore.deleted-open-files` schema v1，包含唯一文件数、FD 引用数、持有进程数、逻辑大小、预计可释放字节、PID/命令、路径及 inode 身份。指定 `--expect any|none` 后，已确认违反策略退出 `3`；如果零命中但权限或采集竞态使扫描不完整，策略状态为 `inconclusive`、`passed` 为 `null`，命令退出 `1`，不会把“看不见”误判成“没有”。`--quiet` 必须与 expectation 一起使用。psmore 只诊断，不会关闭 FD、截断 `/proc/<pid>/fd/*` 或向进程发送信号；确认业务影响后应优先正常重启或关闭持有进程。

### 持久诊断报告对比

TUI 的 `b`/`d` 适合现场即时观察；需要跨命令、跨发布步骤或保留审计证据时，可以保存两份无交互报告再比较。`diff` 会根据顶层 schema 自动识别进程快照或主机体检：

```bash
psmore --json > before.json
# 执行发布、压测或故障复现
psmore --json > after.json

# 人读结果：生命周期变化，以及子树 CPU/内存/I/O 增长榜单
psmore diff before.json after.json

# 完整结果：适合 CI 规则、归档或后续分析
psmore diff before.json after.json --json > diff.json

# 发布前后保存同口径的一键体检；--deep 必须两侧一致
psmore doctor --deep --redact --output doctor-before.json
# 执行发布或故障修复
psmore doctor --deep --redact --output doctor-after.json

# 直接查看哪些信号新增、恢复、持续或发生严重度变化
psmore diff doctor-before.json doctor-after.json

# JSON schema 为 psmore.host-doctor-diff v1
psmore diff doctor-before.json doctor-after.json --json > doctor-diff.json

# 发布门禁：新观察到任意 finding 或 warning 升级为 critical 时退出 3
psmore diff doctor-before.json doctor-after.json --fail-on regression --quiet

# 门禁结果仍可安全归档；文件为 0600，默认拒绝覆盖
psmore diff doctor-before.json doctor-after.json --fail-on regression \
  --output doctor-regression.json
```

两份输入必须是相同报告类型，并要求平台、主机名和查询字符串完全一致，且 AFTER 的时间不早于 BEFORE。doctor 报告还要求两侧都使用 `--deep` 或都不使用，避免把采集范围变化误判成健康变化。不同 schema、不同主机、不同查询、quick/deep 混比以及损坏元数据都会被明确拒绝。

未使用 `--query` 的完整快照中，“出现/消失”代表进程启动/退出。若两份快照使用了相同查询，diff 仍可比较，但会明确写成“进入/离开筛选结果”，因为 `cpu>20` 之类的动态条件变化不能证明进程生命周期。PID 复用继续以启动时间识别；启动时间两侧都不可用时，才回退到进程名和命令行。

doctor 对比使用稳定 finding code 识别同一类信号，分别列出新观察到、确认恢复、持续和 warning/critical 严重度变化；同时展示有效可用内存、Swap、归一化 15 分钟负载、进程数的前后值与增量。deep 报告还比较暴露监听、FD 压力、已删除文件预计可回收空间，以及 Linux OOM/PSI 计数，并保留采集完整性。若后一次 FD、deleted-open 或 PSI 证据不完整，对应 finding 消失只会归入 `NO LONGER OBSERVED`，不会宣称已经恢复。所有变化仍是两次采样之间的证据，不是已确认根因。

`--fail-on regression` 只适用于 doctor 报告：任何新观察到的 finding，或同一 finding 从 warning 升级为 critical，都使策略失败并退出 `3`；finding 恢复、严重度降低和“因证据不完整而未再观察到”都不会失败。进程快照的 CPU、内存和生命周期变化没有通用的好坏含义，因此快照 diff 会明确拒绝该门禁，不制造武断阈值。`--quiet` 可让 CI 仅读取退出码。

`diff --output FILE` 与 doctor 安全报告使用同一套写入保证：自动选择 JSON，同目录创建 `0600` 临时文件，完整写入并同步后原子发布；默认 no-replace，只有 `--force` 才替换已有文件。成功后标准输出只给出路径、报告类型和回归摘要，配合 `--quiet` 完全静默。JSON 的 `policy` 字段记录本次 `fail_on`、pass/fail 状态和精确定义，便于审计。

快捷键：

| 按键 | 操作 |
| --- | --- |
| `↑` / `↓` | 移动当前节点 |
| `←` | 暴露父进程，展示同级兄弟但默认收起兄弟子树 |
| `→` | 展开当前进程的子进程 |
| `0`–`9` | 直接输入 PID，按 `Enter` 定位并恢复完整进程树；`Backspace` 编辑，`Esc` 取消 |
| `/` | 进入搜索输入；输入期间不改变进程树，`j/k` 也是普通字符；按 `Enter` 才应用搜索并回到选中模式，此时 `k` 可操作选中进程；结果状态下按 `Esc` 清除搜索 |
| `f` | 聚焦当前节点的父链和子树 |
| `F` | 打开持久进程过滤器；`a` 新增包含规则，`x` 新增排除规则，`Enter`/`e` 编辑，`Space` 启停，`d` 删除 |
| `r` | 立即刷新 |
| `Space` | 暂停/恢复自动刷新；暂停期间 `r` 仍可手动刷新 |
| `e` | 打开活动审计，查看进程启动、退出、父进程变化和人工信号操作；`Esc` 或 `e` 关闭 |
| `a` | 打开关注事项工作台；`Enter` 跳到进程，`t` 查看趋势，`i` 深度检查，`p` 进程操作，`r` 立即采样，`Esc` 或 `a` 关闭 |
| `h` | 打开 CPU/内存/读/写热点工作台；`←`/`→`/`Tab` 切换榜单，`v` 切换进程自身/服务子树，`Enter` 跳到进程 |
| `s` | 循环切换稳定排序，以及整个进程子树的 CPU、内存、磁盘读速率、磁盘写速率热点排序 |
| `t` | 打开选中进程的历史趋势；面板内 `i` 切换 CPU/内存与磁盘 I/O，`r` 立即采样，`Space` 暂停/恢复，`Esc` 或 `t` 关闭 |
| `b` | 捕获或覆盖当前内存基线 |
| `d` | 打开基线差异面板；支持方向键、`j/k`、PageUp/PageDown 滚动 |
| `x` | 清除当前基线；在差异面板内同样可用 |
| `n` | 打开全局网络面板；`v` 切换监听/全部连接，`/` 过滤，`r` 重新扫描，`Enter` 跳到所有者进程，`Esc` 或 `n` 关闭 |
| `D` | 并行建立选中进程的 Dossier，汇总深检、服务归属、运行映像与日志并优先展示异常线索；`i`/`M`/`m`/`v`/`l` 跳到相关证据，`L` 切换日志采集，`h` 切换哈希，`Esc` 或 `D` 关闭 |
| `M` | 在后台归因选中进程的内存，展示 RSS/PSS/footprint、匿名/文件/共享页、Swap、区域和映射；`Enter`/`r` 刷新，`D` 跳到 Dossier，`i`/`m`/`v`/`l` 跳到相关证据，`Esc` 或 `M` 关闭 |
| `m` | 在后台解析选中进程的 systemd unit 或 launchd job，展示状态、配置、资源边界和下一步只读命令；`Enter`/`r` 刷新，`Esc` 或 `m` 关闭 |
| `v` | 在后台验证选中进程的运行映像、磁盘漂移、软件包与代码签名；面板内 `h` 切换 SHA-256，`m` 切到服务上下文，`Esc` 或 `v` 关闭 |
| `l` | 后台读取选中进程的原生日志；面板内 `s` 切换 auto/process/service，`p` 切换等级，`w` 切换时间窗，`m`/`v` 跳到关联上下文 |
| `k` | 打开专用结束进程弹窗；选择 TERM 或 KILL、进入复核页后还必须按 `y`，发送前重新校验 PID 实例 |
| `p` | 打开选中进程的操作中心；选择 TERM/KILL/STOP/CONT 后，另按 `y` 才发送信号，`Esc` 取消 |
| `o` | 将当前诊断上下文导出到工作目录中的 `psmore-report-*.json`；任意面板内均可使用 |
| `L` | 在主进程树和现场手册中切换中文/英文；Dossier 内的 `L` 保持为日志采集开关 |
| `F2` | 在主进程树或任意诊断工作区切换中文/英文，选择会持久保存 |
| `?` | 打开三页现场帮助；帮助内 `T` 切换启动 tips，`D` 永久关闭启动卡片 |
| `Enter` | 深度检查选中进程；面板内 `Tab`/`Shift+Tab` 切换概览、线程、端口和文件卡片，`↑`/`↓` 滚动，`Enter`/`r` 重新采样，`Esc` 关闭 |
| `Esc` | 取消当前输入、清除已应用搜索或关闭当前面板；在裸主界面不执行操作，避免误退出 |
| `q` / `Ctrl-C` | 退出 psmore |

代码已经把数据采集放在 `ProcessProvider` 抽象后面；当前 `NativeProcessProvider` 支持 macOS 与 Linux，并将原生进程快照合并到 `sysinfo` 数据中。未来接入 Windows 时，可以替换数据源而不改变 TUI 的进程模型。

代码按 `model`、`provider`、`inspection`、`history`、`snapshot`、`app`、`ui` 分层。平台采集、按需深度检查、滚动历史和基线差异彼此隔离，后续可以独立扩展告警、持久化快照或更多操作系统数据源。

## 平台说明

- macOS：原生 `ps` 用于补齐普通用户权限下可能缺失的 PPID 和完整命令行。
- Linux：支持 systemd 用户态进程和内核线程；不会把普通进程的线程任务混入进程树。无可执行文件路径的内核线程会显示其原生命令名，例如 `[kthreadd]`。
- macOS 与 Linux 的进程读写字节增量由同一采样周期换算为每秒速率；新出现或 PID 被复用的进程首个样本固定为零，避免把进程累计 I/O 误报成瞬时尖峰。
- Linux 深度检查按 PID 读取 `/proc/<pid>/fd`、`fdinfo` 与该进程网络命名空间下的 TCP、UDP、Unix socket 表，避免 `lsof` 扫描 Docker/overlay 挂载造成界面卡顿。
- Linux 热点线程读取 `/proc/<pid>/task/*/stat` 两次，并按内核 `CLK_TCK` 与真实采样耗时换算单线程 CPU；采样期间新建或退出的线程不会被错误继承 CPU 数据。
- macOS 热点线程直接使用系统 `libproc`，不依赖调试器、`sample` 或格式不稳定且缺少 TID 的 `ps -M` 输出。
- Linux 运行上下文来自目标进程自己的 `/proc/<pid>/status`、`cgroup`、`ns` 和 `limits`；容器与 systemd 信息是基于内核暴露路径的诊断线索，不依赖 Docker、Podman 或 systemctl 命令。
- 全局网络扫描仅在按 `n` 或面板内按 `r` 时执行。Linux 按网络命名空间读取 `/proc/<pid>/net` 并通过 socket inode 反查 FD/PID；macOS 使用一次性 `lsof`。权限不足的所有者会明确标记，不会被误报成没有连接。
- 因权限或采集竞态无法读取路径时明确显示 `[path unavailable]`，不会把普通进程误标为系统根。
- 深度检查遵循当前用户权限；看不到其他用户进程的文件或端口时会显示警告，不会伪装成“没有连接”。
- 两个平台都建议使用与目标进程相同的用户运行；更高权限能够看到更多进程参数，但 `psmore` 本身不要求 root。
- 进程操作遵循当前用户权限，不会提权。确认时如果目标已退出、启动时间不可用或 PID 已被复用，操作会拒绝并留下原因；信号只发送给选中 PID，不会隐式发送给整个子树或进程组。
- Linux 原生日志来自 journald，普通用户只能看到其权限允许的记录；macOS 原生日志来自 Unified Logging。两者都会限制时间窗和返回条数，但日志消息仍可能包含业务数据或密钥，`--redact` 只是辅助措施。
- 诊断报告 schema v8 先写临时文件再原子改名，并在 Unix 平台使用 `0600` 权限。报告可嵌入已采集的 process dossier 和内存归因，并可能包含完整命令行、文件路径、用户名、主机名、线程名、socket 端点、systemd/launchd 服务上下文、原生日志、内存布局、可执行映像哈希与签名和人工操作审计，分享前应先检查敏感信息。
