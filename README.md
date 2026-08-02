# psmore

`psmore` 是一个面向开发者和运维人员的跨平台进程关系 TUI：用可导航的树帮助你理解进程的父子关系、启动上下文和运行状态。

当前支持 macOS 和 Linux。两端共用同一套进程模型与交互，数据层结合 `sysinfo` 和系统原生 `ps`，兼顾资源指标、准确的父子关系以及完整启动参数。

## 特性

当前原型验证的产品靶子：

- 上方以树展示进程父子关系，PID 0 是用于承接系统根、不可见父进程和采集期间消失进程的虚拟根节点
- 下方显示当前节点的 PID、PPID、子进程数、状态、CPU、内存、磁盘读写速率、运行时间、路径和命令
- 下方同时聚合当前进程与全部后代的进程数、CPU、内存和磁盘 I/O，便于判断一个完整服务树的真实资源占用
- 每一行在 PID 后显示命令行，若命令行不可用则显示可执行文件路径
- 同级进程按名称、PID 确定性排序，刷新时不会因 HashMap 或同名进程导致顺序漂移
- 键盘导航，实时搜索/过滤，聚焦当前进程的父链和子树
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
- `Enter` 深度检查选中进程，集中展示运行用户、工作目录、TCP/UDP/Unix 套接字和打开的文件描述符
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
- 全局网络扫描和进程深度检查都在后台执行；耗时采集会显示动画与已用时间，期间进程树继续刷新，键盘关闭面板和退出始终可用
- `p` 打开进程操作中心，可发送 TERM、KILL、STOP、CONT；选择操作后必须另按 `y` 确认，执行前会重新校验 PID 与启动时间，避免把信号发给复用该 PID 的新进程
- PID 0、PID 1 和 `psmore` 自身受强制保护；每次已发送、被安全策略拒绝或被操作系统拒绝的结果都会进入活动审计
- `o` 将当前诊断上下文导出为带版本号的 JSON 报告，包括完整进程清单、资源聚合、当前查询及命中数、关注事项、最近事件和进程操作审计；已经打开的端口扫描、深度检查及已捕获基线会一并写入，但导出本身不会触发额外扫描
- 支持无交互快照模式：`--table` 输出适合 SSH 现场查看的稳定表格，`--json` 输出带版本号的机器可读快照；两者复用 TUI 的完整查询语法与子树资源聚合
- 无交互模式执行两次采样，默认间隔 500 ms，使 CPU 与磁盘 I/O 速率具有实际意义；可用 `--sample-ms` 在 100–60000 ms 之间调整
- 所有无交互表格、JSON 和 JSONL 输出支持 `--redact`：在保留命令结构的同时遮盖常见密码、token、API key、认证 header、URL userinfo 和敏感查询参数
- `psmore diff BEFORE.json AFTER.json` 将两份持久快照对比为启动/退出、PID 复用、父进程变化，以及 CPU、内存、I/O 和子树进程数增量；默认输出透明的分类榜单，增加 `--json` 可获得完整机器可读差异
- `psmore check QUERY` 将任意结构化查询变成 CI/运维健康门禁：默认期望零命中，`--expect any` 可反向要求服务存在；支持表格、`psmore.check-result` JSON 和完全静默的 `--quiet`
- `psmore inspect PID` 将 TUI 深度检查直接带到 SSH、脚本和事故工单：一次输出进程身份、完整命令、热点线程、socket、打开文件及平台运行上下文，也可导出 `psmore.process-inspection` JSON
- `psmore port PORT` 直接回答“谁占用了这个端口”：将 TCP/UDP 本地端点关联到 PID、用户、完整命令、FD 和 Linux 网络 namespace，并可作为端口存在/释放健康门禁
- `psmore listen` 从全局监听面反查进程和启动上下文，并将 wildcard、非回环网络、loopback 与 Unix socket 分类；`--exposed` 可直接聚焦需要安全复核的主机暴露面
- `psmore net [FILTER]` 检索全局监听、已建立 TCP/UDP 对端和 Unix 连接，展示本地到对端路由、状态、PID/FD、完整进程上下文和 Linux 网络 namespace，并支持状态门禁
- `psmore tree PID` 在非交互环境输出目标的完整父链和后代树，保留目录连接线、稳定同级排序、进程自身/完整子树资源及显式深度截断，也可导出嵌套 JSON
- `psmore watch [QUERY]` 建立进程基线后持续输出启动、退出、PID 复用、父进程变化及动态查询进入/离开事件；支持实时刷新的表格和每行一个文档的版本化 JSONL
- `psmore trace PID` 连续记录单个进程及完整服务子树的 CPU、内存和 I/O，给出相对基线/上一采样的增长、实际采样间隔和峰值汇总；进程退出或 PID 复用时安全终止
- `psmore top [QUERY]` 将 TUI 热点排名带到 SSH 和脚本：按 CPU、内存、磁盘读或写排序，可在进程自身与完整服务子树口径之间切换，并输出稳定表格或版本化 JSON
- `psmore oom [QUERY]` 在 Linux 上联合展示主机 MemAvailable/Swap、memory PSI、OOM kill 计数与进程 `oom_score`/调整值/cgroup 内存事件，区分“杀进程优先级”和“正在发生内存压力”
- `psmore deleted` 定位“文件已删除但进程仍占用”的磁盘空间泄漏：展示 PID、FD、用户、完整命令、文件身份与大小，并按 device+inode 去重估算真正可释放空间
- `psmore fd` 对全系统打开的文件描述符做风险排名：展示 PID、用户、完整命令、FD 数量以及 Linux 软/硬限制和使用率，可直接作为 FD 泄漏或耗尽的巡检门禁
- 深度检查仅在打开或手动刷新面板时启动后台采样：macOS 调用一次 `lsof`，Linux 直接读取目标进程的 `/proc`，不会加入两秒一次的全局刷新
- 每 2 秒从系统进程数据刷新一次

## 实时查询

普通输入保持原有搜索方式，例如 `/codex` 或 `/8080`。多个条件用空格连接，必须同时满足：

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

## 运行

需要 Rust 1.85 或更高版本，以及系统自带的 `ps`（Linux 通常由 `procps` 提供）。macOS 深度检查使用系统 `lsof`；Linux 直接读取 `/proc`，不需要额外诊断工具。缺少诊断数据源时进程树仍可正常使用，检查面板会明确提示原因。

```bash
cargo run --release
```

从当前源码安装到 Cargo 的用户二进制目录：

```bash
cargo install --path .
psmore --version
psmore --help
```

默认目标通常是 `~/.cargo/bin/psmore`；请确保 `~/.cargo/bin` 已加入 `PATH`。开发中的本地覆盖安装可使用 `cargo install --path . --force`。psmore 不要求 root；以更高权限运行只会扩大受操作系统权限控制的进程、FD 和网络可见范围。

安装后可以启用命令、选项和枚举值补全：

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

### 查询健康门禁

`check` 使用与 TUI 完全相同的字段、单位、否定条件和子树聚合，不需要维护第二套监控表达式：

```bash
# 发现任意僵尸进程即失败，命中时退出 3
psmore check 'state:zombie'

# 要求部署用户的 API 至少存在一个，否则退出 3
psmore check 'name:api user:deploy' --expect any

# 限制完整服务树内存，并输出适合 CI 归档的单一 JSON 文档
psmore check 'tree.mem>2g' --json > memory-gate.json

# cron/探针只关心退出码，不产生标准输出
psmore check 'cpu>90 age>5m' --quiet
```

默认 expectation 是 `none`，即零命中才通过；`--expect any` 表示至少一个命中才通过。命令仍执行两次采样，默认间隔 500 ms，可用 `--sample-ms` 调整。表格首行明确显示 `CHECK PASS` 或 `CHECK FAIL`，随后仅在有命中时列出相关进程；JSON 包含策略、查询、命中数、通过状态以及完整的过滤快照。

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

### 持久快照对比

TUI 的 `b`/`d` 适合现场即时观察；需要跨命令、跨发布步骤或保留审计证据时，可以保存两份无交互快照再比较：

```bash
psmore --json > before.json
# 执行发布、压测或故障复现
psmore --json > after.json

# 人读结果：生命周期变化，以及子树 CPU/内存/I/O 增长榜单
psmore diff before.json after.json

# 完整结果：适合 CI 规则、归档或后续分析
psmore diff before.json after.json --json > diff.json
```

diff 只接受 `psmore.process-snapshot` schema v1，并要求两份快照的平台、主机名和查询字符串完全一致，且 AFTER 的时间不早于 BEFORE。它还会拒绝重复 PID、行数元数据不一致和虚拟 PID 0 等损坏输入，避免跨主机或不同筛选范围产生看似合理但错误的结论。

未使用 `--query` 的完整快照中，“出现/消失”代表进程启动/退出。若两份快照使用了相同查询，diff 仍可比较，但会明确写成“进入/离开筛选结果”，因为 `cpu>20` 之类的动态条件变化不能证明进程生命周期。PID 复用继续以启动时间识别；启动时间两侧都不可用时，才回退到进程名和命令行。

快捷键：

| 按键 | 操作 |
| --- | --- |
| `↑` / `↓`，`j` / `k` | 移动当前节点 |
| `←` | 暴露父进程，展示同级兄弟但默认收起兄弟子树 |
| `→` | 展开当前进程的子进程 |
| `/` | 临时定位进程或输入结构化查询；搜索期间移动仍保留结果，Enter 后才清除定位条件并恢复完整树 |
| `f` | 聚焦当前节点的父链和子树 |
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
| `p` | 打开选中进程的操作中心；选择 TERM/KILL/STOP/CONT 后，另按 `y` 才发送信号，`Esc` 取消 |
| `o` | 将当前诊断上下文导出到工作目录中的 `psmore-report-*.json`；任意面板内均可使用 |
| `Enter` | 深度检查选中进程；面板内 `↑`/`↓` 滚动，`Enter`/`r` 重新采样，`Esc` 关闭 |
| `q` / `Esc` | 退出 |

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
- 诊断报告 schema v3 先写临时文件再原子改名，并在 Unix 平台使用 `0600` 权限。报告可能包含完整命令行、文件路径、用户名、主机名、线程名、socket 端点和人工操作审计，分享前应先检查敏感信息。
