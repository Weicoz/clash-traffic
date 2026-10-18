# Clash Traffic

为 **Clash 兼容核心**提供本地流量账本、实时终端表格和 HTML 报表。提供两个等价实现：Rust 原生二进制（`src_rs/`）与 Python 3.10+ 零第三方依赖脚本（`src/`）。两者共用同一 SQLite 账本格式，命令、选项、环境变量一致，适配 macOS、Linux、Windows。

同一域名换规则或节点后**分行累计**，不把旧流量归到新节点。同一连接 ID 的规则、链、协议变化也会分段保存。

```text
域名 / IP     命中规则                 实际节点链      协议  上传     下载     累计     时长
example.com  RuleSet:download-relay   Node A → Relay   TCP   2 MiB    50 MiB   52 MiB   4.2m
example.com  DOMAIN-SUFFIX:example.com Node B → Proxy  TCP   1 MiB    20 MiB   21 MiB   1.5m
```

## 安装

已有 [uv](https://docs.astral.sh/uv/)：

```bash
uv tool install git+https://github.com/Weicoz/clash-traffic.git
```

或使用 pipx：

```bash
pipx install git+https://github.com/Weicoz/clash-traffic.git
```

也可克隆后安装到自己的 Python 虚拟环境：

```bash
git clone https://github.com/Weicoz/clash-traffic.git
cd clash-traffic
python -m venv .venv
# macOS / Linux
.venv/bin/python -m pip install .
.venv/bin/clash-traffic --help
# Windows：用 .venv\Scripts\python.exe 和 .venv\Scripts\clash-traffic.exe
```

安装提供 `clash-traffic` 和兼容别名 `bett-traffic`；不需要 Ruby、系统管理员权限或修改代理路由。尚未发布 PyPI，请使用上述 Git 安装地址。
### Rust 原生实现

Rust 实现位于 `src_rs/`，只用 `std` 加 `rusqlite`（bundled SQLite）、`ureq`、`clap`、`serde`、`chrono`、`libc`；运行时不依赖 Python 或系统 SQLite。

```bash
cargo build --release          # 产物 target/release/clash-traffic
cargo test --release           # 单元测试
target/release/clash-traffic self-test
install -m 0755 target/release/clash-traffic ~/.local/bin/clash-traffic
```

macOS 替换已安装的二进制后要重新做本地签名（否则 Gatekeeper 拦截）：

```bash
rm -f ~/.local/bin/clash-traffic
cp target/release/clash-traffic ~/.local/bin/clash-traffic
codesign --force --sign - ~/.local/bin/clash-traffic
```

两个实现共用同一数据目录与账本；同一时刻只允许一份采集器（`collector.lock` 互斥，跨实现同样生效）。切换实现前先 `clash-traffic stop` 或等采集器退出。

与 Python 版的差别只在展示层，数值、分组与账本完全一致：

- 数字列右对齐：HTML 加 `class="num"`，终端左补空格。
- 每张分组表末尾加一行 `<p class="meta">共 N 行</p>`。
- 明细表标题写实际行数（Python 固定写「最近 500 条」）。
- 终端超长单元格截断后加 `...`；列数不为 8 时按实际列数分配列宽。
- 终端输出兜底过滤控制字符，避免核心元数据注入转义序列。

行为对拍（CI 会执行）：

```bash
cargo build --release
python tests/parity_rust_python.py
```

脚本起本地 mock Clash `/connections` 服务，让两个实现采集同一快照序列，逐项比较 SQLite 账本、`status` JSON、`report --by` 六个维度、`report.html` 单元格、`export` CSV 与 `--dry-run` 输出；墙钟时间戳与时长列按噪声忽略。

## 配置与一条命令开始

先在代理客户端启用标准 HTTP 控制 API，建议只监听本机，例如：

```yaml
external-controller: 127.0.0.1:9090
secret: "使用你自己设置的密码"
```

工具不会修改客户端配置。控制端口是 API 端口，不是 HTTP/SOCKS 代理端口。

```bash
clash-traffic init --endpoint http://127.0.0.1:9090
# 交互输入控制密码，输入不会显示；只保存在私有本地 config.json。
clash-traffic monitor
```

`monitor` 是持续刷新的终端表格，显示域名、规则、实际节点链、协议、上传、下载、累计、观察时长。没有采集器时它会边采集边显示；已有采集器时只读本地账本，不启动第二份采集。Ctrl+C 退出；若本窗口负责采集，退出也会停止采集。长期采集可用下方 `watch`，然后另开 `monitor`。

```bash
clash-traffic watch                    # 持续采集，日志/报表写本地
clash-traffic monitor                  # 每秒刷新表格
clash-traffic monitor --limit 12       # 显示流量最大的12行
clash-traffic status                   # 活跃连接、累计量、上次成功时间与错误
clash-traffic report                   # 域名＋规则＋节点链＋协议，分行累计
clash-traffic report --hours 24        # 近24小时，分钟桶边界约有1分钟误差
clash-traffic report --by rule         # 命中规则排行
clash-traffic report --by chain        # 节点链排行
clash-traffic report --by process      # 应用排行
clash-traffic report --by protocol     # TCP/UDP排行
clash-traffic report --by inbound      # 入站类型，含单独列出的 Inner
clash-traffic export                   # 导出含规则/链/协议/时长字段的连接分段CSV
clash-traffic stop                     # 请求采集器停止，保留历史
clash-traffic monitor --once           # 非终端或脚本：输出一次
clash-traffic watch --dry-run           # 离线预览，零API/凭据读取/状态写入
```

HTML 报表在数据目录的 `report.html`，每5秒生成，浏览器每5秒刷新。首表按域名、规则、节点链、协议分组，带上传/下载/累计/连接数/观察时长；可筛选。最近连接表保留原始开始时间、分段起止、IP/端口、应用、规则及链。实时窗口需要支持 ANSI 的终端（Windows 推荐 Windows Terminal）；文件和CLI输出统一UTF-8。终端过窄时长列会截断，完整信息用 `report` 或 HTML 查看。

### 环境变量和其他控制端口

每个命令都可使用 `--endpoint`、`--data-dir`、`--secret-env`。

- `CLASH_CONTROLLER`：API根地址，如 `http://127.0.0.1:9097`。
- `CLASH_SECRET`：控制密码，不出现在命令参数或日志里。
- `CLASH_TRAFFIC_HOME`：独立数据目录。
- `init --secret-env YOUR_ENV_NAME`：只保存环境变量名，不保存密码值；由你在自己的 shell/密钥管理器中提供环境变量。
- `init --no-secret`：明确使用未设置密码的本机控制接口。

默认数据目录：macOS/Linux 为 `$XDG_STATE_HOME/clash-traffic`（未设置时 `~/.local/state/clash-traffic`）；Windows 为 `%LOCALAPPDATA%\clash-traffic`。POSIX目录权限700，文件600；Windows使用用户目录继承ACL，分享目录前请自行检查Windows权限。

远端控制器使用 HTTPS；没有 HTTPS 的服务可通过 SSH 转发到本机。拒绝 URL 中的密码、token 查询参数、控制接口重定向和系统 HTTP 代理，避免控制密码被误转发。一个数据目录只用于一个核心；更换核心/API地址请换数据目录，避免混合统计口径。

## 兼容性

这是按 **API 协议**适配，不依赖客户端品牌。任何公开标准 Clash `/connections` HTTP API 的 Clash、Clash Premium、Clash.Meta/Mihomo 及其图形客户端都可接入。客户端是否开源不影响协议；但关闭/隐藏控制接口、使用其他核心或私有IPC的客户端不能直接接入。

| 接口能力 | 行为 |
|---|---|
| `connections`＋连接`id/metadata/upload/download` | 持久记录、增量累计、断开检测 |
| `rule/rulePayload/chains` | 按规则和实际链分行；缺失时明确显示未知 |
| `metadata.network/type/host/process/start` | 显示核心可提供的协议、入站、域名、应用、开始时间；缺失字段不猜测 |
| `uploadTotal/downloadTotal` | 核心累计增量参考，不等同域名累计或账单 |
| `connections: null` | 作为空连接列表处理；无`connections`字段则拒绝快照 |

已进行 Bettbox/Mihomo 真实 API 采集；基础 Clash 字段及字段缺失情况有离线测试。CI 覆盖三种操作系统：Python 3.10/3.14 跑单元测试与 `self-test`，Rust 跑 `fmt`/`clippy`/`test` 与双实现对拍。未逐一实测 Clash Verge Rev、FlClash、ClashX、Clash for Windows、OpenClash 等客户端，不把协议兼容说成所有客户端均已验收。Loon、Shadowrocket、sing-box 私有接口不在此协议范围内。

官方依据：[Mihomo API](https://wiki.metacubex.one/api/)、[连接接口源码](https://github.com/MetaCubeX/mihomo/blob/Meta/hub/route/connections.go)、[Tracker字段源码](https://github.com/MetaCubeX/mihomo/blob/Meta/tunnel/statistic/tracker.go)。

## 计量边界

- **开始时已有连接的旧字节只作基线**，不回填历史。重启保留账本。
- 默认每秒只读 `GET /connections`。很短的连接和消失前最后一段流量可能漏计；采集暂停、电脑休眠或接口离线也会形成空档。
- 失败快照不推断连接已关闭；成功快照中消失的连接才标记观察结束。
- 节点/规则切换后独立分段；采样间切换的准确字节边界未知，增量按本次核心报告的路由归属。同一组合再次出现会在累计表合并，CSV保留逐段历史。
- 核心返回的链按原顺序记录，不猜测完整 dialer 链。`Inner` 内部代理链另列；网站和内部链不可直接相加当机场计费。
- 时长是首次到最后观察的下界，断开时间是首次观察消失的时间；并发连接时长相加不等于实际使用时长。
- 核心未识别域名时记录 IP。协议仅 TCP/UDP 和入站类型，不解密 HTTPS，不把 UDP 一律认作 QUIC。
- 不读取完整URL/请求正文，不修改规则、代理、核心、不重置或关闭连接。数据、报表、日志和密码仅存本地；不自动清理历史。

## 开发

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
clash-traffic self-test

# Rust 实现
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --release
cargo build --release
python tests/parity_rust_python.py    # 双实现对拍（账本/报表/CSV/dry-run）
python tests/parity_live_window.py   # 实时窗口渲染对拍（pty，非 Unix 自动跳过）
```

数据库自动兼容早期本地 Bettbox 流量账本：首次连接会把已有连接导入分段表，保留旧字节、时间、规则与链。移植旧数据前停旧采集、用SQLite备份；不得把配置/数据库/日志/导出文件放进源码仓库。

MIT License。
