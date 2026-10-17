//! clash-traffic: Clash-compatible read-only traffic accounting and live tables (Native Rust)

mod models;
mod storage;
mod report;

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use models::ClashSnapshot;
use report::{format_bytes, format_duration, generate_html_report};
use storage::{connect, default_data_dir, default_db_path, get_grouped_traffic, get_meta_number, ingest};

#[derive(Parser)]
#[command(
    name = "clash-traffic",
    about = "Clash-compatible read-only traffic accounting and live tables (Native Rust)",
    version = "2.0.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Clash/Mihomo 控制接口地址 (默认: http://127.0.0.1:9090)
    #[arg(short, long, global = true)]
    endpoint: Option<String>,

    /// 控制接口 Secret 口令
    #[arg(short, long, global = true)]
    secret: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// 运行动态自刷新终端看板 (默认命令)
    Monitor {
        #[arg(short, long, default_value_t = 1.0)]
        interval: f64,
        #[arg(short = 'n', long, default_value_t = 25)]
        limit: usize,
    },
    /// 生成静态 HTML 报表
    Report {
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        title: Option<String>,
    },
    /// 查看采集状态与数据库摘要
    Status,
    /// 仅执行单次或连续后台数据拉取入库
    Collect {
        #[arg(short, long, default_value_t = 1.0)]
        interval: f64,
        #[arg(long)]
        once: bool,
    },
}

fn fetch_snapshot(endpoint: &str, secret: &str) -> Result<ClashSnapshot, String> {
    let url = format!("{}/connections", endpoint.trim_end_matches('/'));
    let mut req = ureq::get(&url).timeout(Duration::from_secs(3));
    if !secret.is_empty() {
        req = req.set("Authorization", &format!("Bearer {}", secret));
    }

    match req.call() {
        Ok(resp) => {
            let reader = resp.into_reader().take(32 * 1024 * 1024);
            let snap: ClashSnapshot = serde_json::from_reader(reader).map_err(|e| format!("解析快照 JSON 失败: {}", e))?;
            Ok(snap)
        }
        Err(e) => Err(format!("连接控制接口失败 ({}): {}", url, e)),
    }
}

fn get_settings(cli_endpoint: Option<&str>, cli_secret: Option<&str>) -> (String, String) {
    let endpoint = cli_endpoint
        .map(String::from)
        .or_else(|| std::env::var("CLASH_CONTROLLER").ok())
        .unwrap_or_else(|| "http://127.0.0.1:9090".to_string());

    let secret = cli_secret
        .map(String::from)
        .or_else(|| std::env::var("CLASH_SECRET").ok())
        .unwrap_or_default();

    (endpoint, secret)
}

fn main() {
    let cli = Cli::parse();
    let (endpoint, secret) = get_settings(cli.endpoint.as_deref(), cli.secret.as_deref());

    let cmd = cli.command.unwrap_or(Commands::Monitor {
        interval: 1.0,
        limit: 25,
    });

    match cmd {
        Commands::Status => {
            println!("=======================================================");
            println!(" Clash Traffic Accounting (Native Rust) Status");
            println!("=======================================================");
            let db_path = default_db_path();
            let size_mb = fs::metadata(&db_path).map(|m| m.len() as f64 / (1024.0 * 1024.0)).unwrap_or(0.0);
            println!(" Data Dir     : {}", default_data_dir().display());
            println!(" SQLite DB    : {} ({:.2} MB)", db_path.display(), size_mb);
            println!(" Controller   : {}", endpoint);

            if let Ok(conn) = connect(None) {
                let samples = get_meta_number(&conn, "samples", 0);
                let up = get_meta_number(&conn, "global_upload", 0);
                let down = get_meta_number(&conn, "global_download", 0);
                println!(" Total Samples: {}", samples);
                println!(" Global Up    : {}", format_bytes(up));
                println!(" Global Down  : {}", format_bytes(down));
            }
            println!("=======================================================");
        }
        Commands::Report { output, title } => {
            let conn = connect(None).expect("无法打开本地数据库");
            let rows = get_grouped_traffic(&conn, true).expect("查询聚合数据失败");
            let t = title.unwrap_or_else(|| "Clash Traffic 本地流量报表".to_string());
            let html = generate_html_report(&rows, &t);

            let out_file = output.unwrap_or_else(|| {
                let now = chrono::Local::now().format("%Y%m%d_%H%M%S");
                PathBuf::from(format!("clash_traffic_report_{}.html", now))
            });

            fs::write(&out_file, html).expect("写入报表文件失败");
            println!("✔ 流量报表已成功生成: {}", out_file.display());
            println!("  统计分行: {} 条", rows.len());
        }
        Commands::Collect { interval, once } => {
            let mut conn = connect(None).expect("无法连接数据库");
            setup_signals();

            println!("[clash-traffic] 采集器启动 (目标: {})", endpoint);
            while RUNNING.load(Ordering::SeqCst) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
                match fetch_snapshot(&endpoint, &secret) {
                    Ok(snap) => {
                        if let Ok((active, du, dd)) = ingest(&mut conn, &snap, now) {
                            println!("[{:.0}] 活跃连接: {} | 上传增量: {} | 下载增量: {}", now, active, format_bytes(du as i64), format_bytes(dd as i64));
                        }
                    }
                    Err(e) => {
                        eprintln!("[警告] {}", e);
                    }
                }
                if once {
                    break;
                }
                thread::sleep(Duration::from_secs_f64(interval));
            }
        }
        Commands::Monitor { interval, limit } => {
            let mut conn = connect(None).expect("无法连接本地数据库");
            setup_signals();

            let sleep_dur = Duration::from_secs_f64(interval);

            while RUNNING.load(Ordering::SeqCst) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
                let _ = fetch_snapshot(&endpoint, &secret).map(|snap| {
                    let _ = ingest(&mut conn, &snap, now);
                });

                let rows = get_grouped_traffic(&conn, true).unwrap_or_default();

                // 清屏重绘
                print!("\x1B[2J\x1B[1;1H");
                println!("========================================================================================================================");
                println!(" 🌐 Clash 本地流量动态账本 (Native Rust) | 接口: {} | 记录数: {} (按 Ctrl+C 退出)", endpoint, rows.len());
                println!("========================================================================================================================");
                println!("{:<32} {:<22} {:<24} {:<6} {:<10} {:<10} {:<10} {:<8}",
                    "域名 / IP", "命中规则", "实际节点链", "协议", "上传", "下载", "累计", "时长");
                println!("------------------------------------------------------------------------------------------------------------------------");

                for r in rows.iter().take(limit) {
                    let domain_disp = if r.domain.chars().count() > 30 {
                        format!("{}...", r.domain.chars().take(27).collect::<String>())
                    } else {
                        r.domain.clone()
                    };
                    let rule_disp = if r.rule.chars().count() > 20 {
                        format!("{}...", r.rule.chars().take(17).collect::<String>())
                    } else {
                        r.rule.clone()
                    };
                    let chain_disp = if r.chain.chars().count() > 22 {
                        format!("{}...", r.chain.chars().take(19).collect::<String>())
                    } else {
                        r.chain.clone()
                    };

                    println!("{:<32} {:<22} {:<24} {:<6} {:<10} {:<10} {:<10} {:<8}",
                        domain_disp,
                        rule_disp,
                        chain_disp,
                        r.protocol,
                        format_bytes(r.up),
                        format_bytes(r.down),
                        format_bytes(r.total),
                        format_duration(r.duration_sec)
                    );
                }
                println!("========================================================================================================================");
                let _ = io::stdout().flush();

                thread::sleep(sleep_dur);
            }
            println!("\n[clash-traffic] 监控已退出。");
        }
    }
}

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sig_handler(_: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn setup_signals() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sig_handler as *const () as usize;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}
