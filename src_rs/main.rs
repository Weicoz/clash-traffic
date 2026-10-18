//! clash-traffic 原生 Rust 实现：只读 Clash 控制接口，本地 SQLite 账本与 HTML 报表。
//!
//! 行为契约对齐 Python 旧实现 src/clash_traffic/cli.py：
//! 命令集合、选项、输出文案、错误分类与安全边界（拒绝凭据/路径/查询参数、
//! 拒绝重定向、忽略系统代理、非 loopback 必须 HTTPS、不回显异常正文）逐项一致。

mod models;
mod query;
mod report;
mod selftest;
mod storage;

use clap::{Parser, ValueEnum};
use models::{ClashError, Result};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use storage::Paths;

/// 控制接口响应上限（16 MiB，与 Python 一致）。
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
/// 控制接口超时（秒）。
const REQUEST_TIMEOUT_SECS: u64 = 4;

/// 采集循环收到的停止信号。
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum Commands {
    /// 写入控制接口地址与密码来源（本地配置）
    Init,
    /// 长期采集：每秒只读快照，落本地账本
    Watch,
    /// 实时窗口：无采集器时边采边显示，已有采集器时只读显示
    Monitor,
    /// 打印账本状态 JSON
    Status,
    /// 打印排行并重生成 report.html
    Report,
    /// 导出全部分段明细 CSV
    Export,
    /// 请求停止采集，保留累计数据
    Stop,
    /// 离线自检：临时账本验证计量语义
    #[value(name = "self-test")]
    SelfTest,
}

impl Commands {
    fn name(self) -> &'static str {
        match self {
            Commands::Init => "init",
            Commands::Watch => "watch",
            Commands::Monitor => "monitor",
            Commands::Status => "status",
            Commands::Report => "report",
            Commands::Export => "export",
            Commands::Stop => "stop",
            Commands::SelfTest => "self-test",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum GroupBy {
    Domain,
    Protocol,
    Process,
    Chain,
    Rule,
    Inbound,
}

impl GroupBy {
    fn name(self) -> &'static str {
        match self {
            GroupBy::Domain => "domain",
            GroupBy::Protocol => "protocol",
            GroupBy::Process => "process",
            GroupBy::Chain => "chain",
            GroupBy::Rule => "rule",
            GroupBy::Inbound => "inbound",
        }
    }
}

/// Clash 本地流量计量：只读控制接口，累计保存在本机 SQLite 账本。
#[derive(Parser, Debug)]
#[command(
    name = "clash-traffic",
    version,
    about = "只读 Clash 控制接口的本地流量计量工具",
    disable_help_subcommand = true
)]
struct Cli {
    /// 子命令：init / watch / monitor / status / report / export / stop / self-test
    #[arg(value_enum, default_value_t = Commands::Status)]
    command: Commands,

    /// 只打印将要执行的动作，不访问网络、不读凭据、不写状态
    #[arg(long)]
    dry_run: bool,

    /// 覆盖数据目录（默认 ~/.local/state/clash-traffic）
    #[arg(long, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    /// 控制接口地址（默认 http://127.0.0.1:9090）
    #[arg(long)]
    endpoint: Option<String>,

    /// 从该环境变量读取控制接口密码
    #[arg(long, value_name = "NAME")]
    secret_env: Option<String>,

    /// init 时不保存密码
    #[arg(long)]
    no_secret: bool,

    /// 分组维度（report 命令）
    #[arg(long, value_enum, default_value_t = GroupBy::Domain)]
    by: GroupBy,

    /// 只统计最近 N 小时（分钟桶窗口）
    #[arg(long)]
    hours: Option<f64>,

    /// 采样间隔（秒，最小 0.5）
    #[arg(long, default_value_t = 1.0)]
    interval: f64,

    /// 显示行数上限
    #[arg(long, default_value_t = 20)]
    limit: usize,

    /// 只采一次后退出
    #[arg(long)]
    once: bool,
}

fn main() {
    let cli = Cli::parse();
    if cli.dry_run {
        let paths = resolve_paths(&cli);
        println!("{}", dry_run_payload(&cli, &paths));
        return;
    }
    if let Err(message) = validate(&cli) {
        eprintln!("clash-traffic: error: {}", message);
        std::process::exit(2);
    }
    #[cfg(unix)]
    unsafe {
        // 新建文件默认 0600 / 目录 0700（Python os.umask(0o077)）。
        libc::umask(0o077);
    }
    match run(&cli) {
        Ok(()) => {}
        Err(ClashError::Locked) => {
            eprintln!("已有采集器；使用 clash-traffic monitor 查看");
            std::process::exit(1);
        }
        Err(error) => {
            // 异常正文可能含凭据或响应体，绝不回显（Python main() 同规则）。
            eprintln!(
                "操作未完成：{}；未修改代理，请检查控制接口或本地配置",
                error.type_name()
            );
            std::process::exit(1);
        }
    }
}

fn validate(cli: &Cli) -> std::result::Result<(), String> {
    let ok = cli.interval.is_finite()
        && cli.interval >= 0.5
        && cli.limit >= 1
        && cli
            .hours
            .map(|hours| hours.is_finite() && hours > 0.0)
            .unwrap_or(true);
    if ok {
        Ok(())
    } else {
        Err("间隔至少0.5秒，数量和时间必须为有限正数".to_string())
    }
}

fn resolve_paths(cli: &Cli) -> Paths {
    match &cli.data_dir {
        Some(dir) => Paths::with_root(dir.clone()),
        None => Paths::default_paths(),
    }
}

/// dry-run 只看将要做的事与目标目录：不触网、不读凭据、不写状态。
fn dry_run_payload(cli: &Cli, paths: &Paths) -> String {
    format!(
        "{{\"dry_run\": true, \"command\": \"{}\", \"data_dir\": \"{}\", \"network_calls\": 0, \"credential_reads\": 0, \"state_writes\": 0}}",
        cli.command.name(),
        paths.root.to_string_lossy()
    )
}

fn run(cli: &Cli) -> Result<()> {
    let paths = resolve_paths(cli);
    match cli.command {
        Commands::SelfTest => {
            println!("{}", selftest::selftest()?);
        }
        Commands::Init => init(&paths, cli)?,
        Commands::Watch => {
            paths.ensure_root()?;
            watch(
                &paths,
                cli.interval,
                cli.endpoint.clone(),
                cli.secret_env.clone(),
                false,
                cli.limit,
                cli.once,
            )?;
        }
        Commands::Monitor => {
            paths.ensure_root()?;
            if !models::stdout_isatty() && !cli.once {
                return Err(ClashError::Value(
                    "实时窗口需要终端；非终端使用 --once 或 watch".into(),
                ));
            }
            monitor(
                &paths,
                cli.interval,
                cli.endpoint.clone(),
                cli.secret_env.clone(),
                cli.limit,
                cli.once,
            )?;
        }
        Commands::Stop => {
            if !paths.root.exists() {
                println!("尚未采集");
                return Ok(());
            }
            storage::atomic_write(&paths.stop_file(), "stop\n")?;
            println!("已请求停止采集；保留累计数据");
        }
        Commands::Status => {
            let db = storage::readonly(&paths)?;
            let fields = query::status(&db, &paths)?;
            println!("{}", models::status_json_pretty(&fields));
        }
        Commands::Export => {
            let db = storage::readonly(&paths)?;
            let csv = query::export_csv(&db, &paths)?;
            println!("{}", csv.to_string_lossy());
        }
        Commands::Report => {
            let db = storage::readonly(&paths)?;
            print_group_table(&db, cli.by, cli.hours, cli.limit)?;
            println!(
                "本地报表： {}",
                write_report(&db, &paths)?.to_string_lossy()
            );
        }
    }
    Ok(())
}

/// report 命令的制表符排行输出（Python run() 的 else 分支）。
fn print_group_table(db: &Connection, by: GroupBy, hours: Option<f64>, limit: usize) -> Result<()> {
    println!(
        "{}",
        if by == GroupBy::Domain {
            "域名 / IP\t命中规则\t实际节点链\t协议\t上传\t下载\t合计"
        } else {
            "对象\t上传\t下载\t合计"
        }
    );
    for row in query::groups(db, by.name(), hours)?.into_iter().take(limit) {
        let mut fields = vec![models::sanitize(&row.name)];
        if by == GroupBy::Domain {
            fields.push(models::sanitize(&row.rule));
            fields.push(models::sanitize(&row.chain));
            fields.push(models::sanitize(&row.protocol));
        }
        fields.push(models::fmt_bytes(row.up as f64));
        fields.push(models::fmt_bytes(row.down as f64));
        fields.push(models::fmt_bytes(row.total() as f64));
        println!("{}", fields.join("\t"));
    }
    Ok(())
}

/// 生成并落盘 report.html（等价 Python report()）。
fn write_report(db: &Connection, paths: &Paths) -> Result<PathBuf> {
    let sections = query::report_sections(db)?;
    let headers = query::detail_headers();
    let rows = query::detail_rows(db, 500)?;
    let status_json = models::status_json_pretty(&query::status(db, paths)?);
    let html = report::render_report_html(&sections, &headers, &rows, &status_json, "");
    storage::atomic_write(&paths.report(), &html)?;
    Ok(paths.report())
}

/// init：校验地址、可选保存密码、备份旧配置并原子写入 config.json。
fn init(paths: &Paths, cli: &Cli) -> Result<()> {
    let endpoint = endpoint_url(cli.endpoint.as_deref().unwrap_or("http://127.0.0.1:9090"))?;
    let mut config = serde_json::Map::new();
    config.insert("endpoint".into(), Value::String(endpoint));
    if let Some(name) = &cli.secret_env {
        config.insert("secret_env".into(), Value::String(name.clone()));
    } else if !cli.no_secret {
        if !models::stdin_isatty() {
            return Err(ClashError::Value(
                "非交互 init 请使用 --secret-env 或 --no-secret".into(),
            ));
        }
        let secret = read_password("控制接口密码（输入不显示）：")?;
        config.insert("secret".into(), Value::String(secret));
    }
    paths.ensure_root()?;
    let config_path = paths.config();
    if config_path.exists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let backup = paths.root.join(format!("config.{}.bak", stamp));
        std::fs::copy(&config_path, &backup)?;
    }
    let text = serde_json::to_string_pretty(&Value::Object(config))?;
    storage::atomic_write(&config_path, &text)?;
    println!("本地配置已保存： {}", config_path.to_string_lossy());
    Ok(())
}

/// 读取密码（关闭终端回显，读后恢复；仅 UNIX 有 termios）。
#[cfg(unix)]
fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let fd = libc::STDIN_FILENO;
    let mut original: libc::termios = unsafe { std::mem::zeroed() };
    let has_termios = unsafe { libc::tcgetattr(fd, &mut original) } == 0;
    if has_termios {
        let mut updated = original;
        updated.c_lflag &= !libc::ECHO;
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &updated);
        }
    }
    let mut line = String::new();
    let read = std::io::stdin().read_line(&mut line);
    if has_termios {
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &original);
        }
        println!();
    }
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// 读取密码（非 UNIX 平台无 termios：直接读取一行，不做回显控制）。
#[cfg(not(unix))]
fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// 采集循环（等价 Python watch()）。
fn watch(
    paths: &Paths,
    interval: f64,
    endpoint: Option<String>,
    secret_env: Option<String>,
    live: bool,
    limit: usize,
    once: bool,
) -> Result<()> {
    let mut lock = storage::CollectorLock::new();
    lock.acquire(&paths.lock_file(), false)?;
    let stop = paths.stop_file();
    let _ = std::fs::remove_file(&stop);
    let mut db = storage::connect(&paths.db)?;
    STOP_REQUESTED.store(false, Ordering::SeqCst);
    install_signal_handlers();
    let mut last_report = 0.0f64;
    let mut last_log = 0.0f64;
    if !live {
        println!(
            "采集启动：只读 Clash 控制 API；报表 {}",
            paths.report().to_string_lossy()
        );
    }
    let outcome = (|| -> Result<()> {
        while !STOP_REQUESTED.load(Ordering::SeqCst) && !stop.exists() {
            let tick = Instant::now();
            let now = storage::now_epoch();
            match settings(endpoint.as_deref(), secret_env.as_deref(), paths)
                .and_then(|(controller, secret)| fetch_snapshot(&controller, secret.as_deref()))
                .and_then(|snapshot| storage::ingest_value(&mut db, &snapshot, now))
            {
                Ok(result) => {
                    if storage::now_epoch() - last_log >= 60.0 {
                        storage::log_line(
                            paths,
                            &json!({
                                "status": "采集中",
                                "active": result.active,
                                "observed_upload_delta": result.observed_upload_delta,
                                "observed_download_delta": result.observed_download_delta,
                            }),
                        )?;
                        if !live {
                            println!(
                                "{}",
                                models::status_json_compact(&query::status(&db, paths)?)
                            );
                        }
                        last_log = storage::now_epoch();
                    }
                }
                Err(error) => {
                    let kind = error.type_name();
                    storage::put_json(
                        &db,
                        "last_error",
                        &json!({"type": kind, "at": models::date(storage::now_epoch())}),
                    )?;
                    if storage::now_epoch() - last_log >= 60.0 {
                        storage::log_line(
                            paths,
                            &json!({"status": "等待接口", "error_type": kind}),
                        )?;
                        if !live {
                            println!("等待接口：{}", kind);
                        }
                        last_log = storage::now_epoch();
                    }
                }
            }
            if storage::now_epoch() - last_report >= 5.0 {
                write_report(&db, paths)?;
                last_report = storage::now_epoch();
            }
            if live {
                display_live(&db, paths, limit)?;
            }
            if once {
                break;
            }
            let elapsed = tick.elapsed().as_secs_f64();
            std::thread::sleep(Duration::from_secs_f64((interval - elapsed).max(0.05)));
        }
        Ok(())
    })();
    let finish = write_report(&db, paths)
        .and_then(|_| storage::log_line(paths, &json!({"status": "已停止"})));
    drop(db);
    lock.close();
    if !live {
        println!("采集已停止；数据保留");
    }
    outcome?;
    finish
}

/// monitor：已有采集器时只读显示，否则自行采集（等价 Python monitor()）。
fn monitor(
    paths: &Paths,
    interval: f64,
    endpoint: Option<String>,
    secret_env: Option<String>,
    limit: usize,
    once: bool,
) -> Result<()> {
    if storage::collector_running(paths) {
        let db = storage::readonly(paths)?;
        loop {
            display_live(&db, paths, limit)?;
            if once {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs_f64(interval));
        }
    }
    watch(paths, interval, endpoint, secret_env, true, limit, once)
}

/// 实时窗口刷新（等价 Python display_live + live_table）。
fn display_live(db: &Connection, paths: &Paths, limit: usize) -> Result<()> {
    let headers = query::live_headers();
    let rows = query::live_rows(db, limit)?;
    let fields = query::status(db, paths)?;
    let title = format!(
        "Clash Traffic · {} · Ctrl+C 退出窗口",
        models::date(storage::now_epoch())
    );
    let last_error = match &fields.last_error {
        Some(error) => format!("{{'type': '{}', 'at': '{}'}}", error.kind, error.at),
        None => "None".to_string(),
    };
    let footer = format!(
        "连接 {} · 样本 {} · 最后采样 {} · 上次错误 {}\n业务与 Inner 分开计量；长列在 report 查看。历史/短连接/机场账单边界见 README。",
        fields.active_at_last_sample, fields.samples, fields.last_sample, last_error
    );
    let width = models::terminal_columns(140);
    let table = report::render_live_table(&headers, &rows, &footer, width);
    let mut out = String::new();
    out.push_str(report::clear_screen_sequence());
    out.push_str(&title);
    out.push('\n');
    out.push_str(&table);
    print!("{}", out);
    std::io::stdout().flush()?;
    Ok(())
}

#[cfg(unix)]
extern "C" fn handle_signal(_signal: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGTERM, handle_signal as *const () as usize);
        libc::signal(libc::SIGINT, handle_signal as *const () as usize);
    }
}

/// 校验控制接口地址（等价 Python endpoint_url，拒绝凭据/路径/查询/非 HTTPS 远端）。
pub fn endpoint_url(value: &str) -> Result<String> {
    const MESSAGE: &str = "endpoint 应为 http(s)://host:port，不允许凭据、路径或查询参数";
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return Err(ClashError::Value(MESSAGE.into())),
    };
    if scheme != "http" && scheme != "https" {
        return Err(ClashError::Value(MESSAGE.into()));
    }
    if rest.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err(ClashError::Value(MESSAGE.into()));
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if !path.is_empty() && path != "/" {
        return Err(ClashError::Value(MESSAGE.into()));
    }
    let host = parse_host(authority).ok_or_else(|| ClashError::Value(MESSAGE.into()))?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false);
    if scheme == "http" && !loopback {
        return Err(ClashError::Runtime(
            "远端控制接口必须使用 HTTPS，或通过 SSH 转发到本机".into(),
        ));
    }
    Ok(value.trim_end_matches('/').to_string())
}

/// 从 authority 提取主机名并校验端口语法（支持 [IPv6]:port）。
fn parse_host(authority: &str) -> Option<String> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        if !tail.is_empty() {
            let port = tail.strip_prefix(':')?;
            validate_port(port)?;
        }
        return Some(host.to_string());
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.is_empty() {
                return None;
            }
            validate_port(port)?;
            Some(host.to_string())
        }
        None => Some(authority.to_string()),
    }
}

fn validate_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.chars().all(|value| value.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok()
}

/// 解析控制接口地址与密码来源（等价 Python settings()）。
pub fn settings(
    endpoint: Option<&str>,
    secret_env: Option<&str>,
    paths: &Paths,
) -> Result<(String, Option<String>)> {
    let config = match std::fs::read_to_string(paths.config()) {
        Ok(text) => serde_json::from_str::<Value>(&text).unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    let configured = |key: &str| -> Option<String> {
        config
            .get(key)
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
    };
    let controller = endpoint
        .map(|value| value.to_string())
        .or_else(|| std::env::var("CLASH_CONTROLLER").ok())
        .or_else(|| configured("endpoint"))
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());
    let controller = endpoint_url(&controller)?;
    let env_key = secret_env
        .map(|value| value.to_string())
        .or_else(|| configured("secret_env"));
    let secret = match env_key {
        Some(name) => Some(
            std::env::var(&name)
                .map_err(|_| ClashError::Runtime("所配置的控制密码环境变量未设置".into()))?,
        ),
        None => std::env::var("CLASH_SECRET")
            .ok()
            .or_else(|| configured("secret")),
    };
    Ok((controller, secret))
}

/// 只读拉取 /connections（等价 Python snapshot()）。
pub fn fetch_snapshot(controller: &str, secret: Option<&str>) -> Result<Value> {
    let agent = ureq::AgentBuilder::new()
        .try_proxy_from_env(false)
        .redirects(0)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build();
    let url = format!("{}/connections", controller.trim_end_matches('/'));
    let mut request = agent.get(&url);
    if let Some(secret) = secret {
        request = request.set("Authorization", &format!("Bearer {}", secret));
    }
    let response = match request.call() {
        Ok(response) => response,
        Err(ureq::Error::Status(code, _)) => return Err(ClashError::Http(code)),
        Err(ureq::Error::Transport(transport)) => {
            if transport.kind() == ureq::ErrorKind::TooManyRedirects {
                return Err(ClashError::Runtime("拒绝控制接口重定向".into()));
            }
            return Err(ClashError::Transport(transport.to_string()));
        }
    };
    let mut reader = response.into_reader().take(MAX_RESPONSE_BYTES + 1);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer)?;
    if buffer.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ClashError::Value("控制接口响应过大".into()));
    }
    let document: Value =
        serde_json::from_slice(&buffer).map_err(|error| ClashError::Json(error.to_string()))?;
    match document.get("connections") {
        Some(Value::Array(_)) | Some(Value::Null) => {}
        _ => {
            return Err(ClashError::Value(
                "接口不符合 Clash /connections 格式".into(),
            ))
        }
    }
    Ok(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_url_accepts_loopback_and_rejects_unsafe_forms() {
        assert_eq!(
            endpoint_url("http://127.0.0.1:9090/").unwrap(),
            "http://127.0.0.1:9090"
        );
        assert_eq!(
            endpoint_url("http://localhost:9090").unwrap(),
            "http://localhost:9090"
        );
        assert!(endpoint_url("https://clash.example.com:443").is_ok());
        assert!(endpoint_url("http://user:pass@127.0.0.1:9090").is_err());
        assert!(endpoint_url("http://127.0.0.1:9090/api").is_err());
        assert!(endpoint_url("http://127.0.0.1:9090?token=1").is_err());
        assert!(endpoint_url("ftp://127.0.0.1:9090").is_err());
        assert!(endpoint_url("http://127.0.0.1:abc").is_err());
        match endpoint_url("http://clash.example.com:9090") {
            Err(ClashError::Runtime(message)) => {
                assert!(message.contains("必须使用 HTTPS"))
            }
            other => panic!("远端 HTTP 必须拒绝：{:?}", other.is_ok()),
        }
    }

    #[test]
    fn dry_run_shape_and_validation_message() {
        // 期望值必须来自平台的绝对路径：POSIX 字面量 "/tmp/x" 在 Windows 上属于
        // 「当前盘符下的根路径」，with_root 会补成 D:/tmp/x（Rust 的 join 语义）。
        let dir = std::env::temp_dir().join("clash-traffic-dry-run");
        let dir_text = dir.to_string_lossy().into_owned();
        let cli = Cli::parse_from(["clash-traffic", "self-test", "--data-dir", &dir_text]);
        let paths = resolve_paths(&cli);
        assert_eq!(paths.root, dir);
        assert_eq!(paths.db, dir.join("traffic.sqlite3"));
        let payload = dry_run_payload(&cli, &paths);
        assert!(
            payload.starts_with("{\"dry_run\": true, \"command\": \"self-test\", \"data_dir\": \"")
        );
        assert!(payload.contains(&dir_text));
        assert!(payload
            .ends_with("\", \"network_calls\": 0, \"credential_reads\": 0, \"state_writes\": 0}"));
        // 相对路径必须按当前目录绝对化。
        let relative = resolve_paths(&Cli::parse_from([
            "clash-traffic",
            "status",
            "--data-dir",
            "relative-dir",
        ]));
        assert!(relative.root.is_absolute());
        assert!(relative.root.ends_with("relative-dir"));
        assert!(validate(&cli).is_ok());
        let bad = Cli::parse_from(["clash-traffic", "status", "--interval", "0.1"]);
        assert_eq!(
            validate(&bad).unwrap_err(),
            "间隔至少0.5秒，数量和时间必须为有限正数"
        );
        let bad_hours = Cli::parse_from(["clash-traffic", "report", "--hours", "0"]);
        assert!(validate(&bad_hours).is_err());
    }

    #[test]
    fn parse_host_extracts_hostname_and_port() {
        assert_eq!(parse_host("127.0.0.1:9090").unwrap(), "127.0.0.1");
        assert_eq!(parse_host("localhost").unwrap(), "localhost");
        assert_eq!(parse_host("[::1]:9090").unwrap(), "::1");
        assert_eq!(parse_host("[::1]").unwrap(), "::1");
        assert!(parse_host("host:port").is_none());
        assert!(parse_host("host:").is_none());
        assert!(parse_host("").is_none());
    }
}
