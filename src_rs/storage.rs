//! 本地计量存储：目录、采集锁、SQLite 账本与增量写入。
//!
//! 表结构与写入语义对齐 Python 旧实现 src/clash_traffic/cli.py：
//! connections / buckets / segments / meta 四表 + segments_route 索引，
//! 增量按 raw_up/raw_down 差值累计，路由变化按六维分行，Inner 内部链路单独计量。

use crate::models::{parse_snapshot, ClashError, PreparedSnapshot, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// 数据目录与派生路径。
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
    pub db: PathBuf,
}

impl Paths {
    /// \`CLASH_TRAFFIC_HOME\` > \`LOCALAPPDATA\`(Windows) > \`XDG_STATE_HOME\` > \`~/.local/state\`。
    pub fn default_paths() -> Paths {
        let root = match std::env::var_os("CLASH_TRAFFIC_HOME") {
            Some(value) if !value.is_empty() => PathBuf::from(value),
            _ => {
                #[cfg(windows)]
                {
                    let base = std::env::var_os("LOCALAPPDATA")
                        .map(PathBuf::from)
                        .unwrap_or_else(home_dir);
                    base.join("clash-traffic")
                }
                #[cfg(not(windows))]
                {
                    let base = std::env::var_os("XDG_STATE_HOME")
                        .map(PathBuf::from)
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| home_dir().join(".local/state"));
                    base.join("clash-traffic")
                }
            }
        };
        Paths::with_root(root)
    }

    /// 用指定目录构造（--data-dir），相对路径按当前目录绝对化。
    pub fn with_root(root: PathBuf) -> Paths {
        let expanded = expand_user(&root);
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(&expanded))
                .unwrap_or(expanded)
        };
        Paths {
            db: absolute.join("traffic.sqlite3"),
            root: absolute,
        }
    }

    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn report(&self) -> PathBuf {
        self.root.join("report.html")
    }

    pub fn csv(&self) -> PathBuf {
        self.root.join("connections.csv")
    }

    pub fn stop_file(&self) -> PathBuf {
        self.root.join("stop")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.root.join("collector.lock")
    }

    pub fn log_file(&self) -> PathBuf {
        self.root.join("collector.jsonl")
    }

    /// 建立数据目录（0700），对应 Python \`ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)\`。
    pub fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
        Ok(())
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn expand_user(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix("~/") {
        return home_dir().join(rest);
    }
    if raw == "~" {
        return home_dir();
    }
    path.to_path_buf()
}

/// Python 侧的表结构与索引定义（保持逐字一致，共用同一个 SQLite 账本）。
pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,domain TEXT,protocol TEXT,inbound TEXT,process TEXT,chain TEXT,rule TEXT,ip TEXT,port TEXT,start REAL,first REAL,last REAL,closed REAL,up INTEGER,down INTEGER,raw_up INTEGER,raw_down INTEGER);
CREATE TABLE IF NOT EXISTS buckets(minute INTEGER,domain TEXT,protocol TEXT,inbound TEXT,process TEXT,chain TEXT,rule TEXT,up INTEGER,down INTEGER,PRIMARY KEY(minute,domain,protocol,inbound,process,chain,rule));
CREATE TABLE IF NOT EXISTS segments(id TEXT,seq INTEGER,domain TEXT,protocol TEXT,inbound TEXT,process TEXT,chain TEXT,rule TEXT,first REAL,last REAL,closed REAL,up INTEGER,down INTEGER,PRIMARY KEY(id,seq));
CREATE INDEX IF NOT EXISTS segments_route ON segments(domain,rule,chain);
";

/// 历史遗留的空 rule payload 归并键（Python RULE_KEY）。
pub const RULE_KEY: &str =
    "CASE WHEN instr(rule, ':') = length(rule) THEN substr(rule,1,length(rule)-1) ELSE rule END";

/// 尝试对锁文件加独占非阻塞锁（UNIX 用 flock）。
#[cfg(unix)]
fn try_lock(file: &File) -> bool {
    use std::os::unix::io::AsRawFd;
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// 释放锁。
#[cfg(unix)]
fn unlock(file: &File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

#[cfg(windows)]
#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl Overlapped {
    /// 锁第 0 字节起的 1 字节：与 Python `seek(0)` + `locking(fd, LK_NBLCK, 1)` 的范围重叠。
    fn at_first_byte() -> Overlapped {
        Overlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        }
    }
}

#[cfg(windows)]
unsafe extern "system" {
    /// 字节范围锁；带 LOCKFILE_FAIL_IMMEDIATELY 时立即失败而不等待。
    #[link_name = "LockFileEx"]
    fn lock_file_ex(
        handle: *mut std::ffi::c_void,
        flags: u32,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    #[link_name = "UnlockFileEx"]
    fn unlock_file_ex(
        handle: *mut std::ffi::c_void,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
}

/// 尝试对锁文件加独占非阻塞锁（等价 Python `msvcrt.locking(LK_NBLCK)`）。
///
/// 直接调 LockFileEx：CRT 的 `_locking` 内部就是它，字节范围互斥因此与 Python 采集器互通。
/// 不得改回 `_get_osfhandle` + `_locking`——前者的方向是 fd → HANDLE，把 HANDLE 当 fd
/// 喂给 `_locking` 会落到 CRT 的无效参数处理，进程静默 fast-fail（0xC0000409，无任何输出）。
#[cfg(windows)]
fn try_lock(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    let mut overlapped = Overlapped::at_first_byte();
    unsafe {
        lock_file_ex(
            file.as_raw_handle() as *mut std::ffi::c_void,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        ) != 0
    }
}

/// 释放锁（等价 Python `msvcrt.locking(LK_UNLCK)`）。
#[cfg(windows)]
fn unlock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    let mut overlapped = Overlapped::at_first_byte();
    unsafe {
        unlock_file_ex(
            file.as_raw_handle() as *mut std::ffi::c_void,
            0,
            1,
            0,
            &mut overlapped,
        );
    }
}

/// 采集器锁：操作系统级文件锁，进程退出即释放（对应 Python CollectorLock）。
pub struct CollectorLock {
    file: Option<File>,
}

impl CollectorLock {
    pub fn new() -> CollectorLock {
        CollectorLock { file: None }
    }

    /// \`readonly=false\`：抢占采集锁；\`readonly=true\`：只探测是否已有采集器。
    ///
    /// 返回 \`Ok(false)\` 表示只读探测且锁文件不存在（无采集器）。
    pub fn acquire(&mut self, path: &Path, readonly: bool) -> Result<bool> {
        if readonly && !path.exists() {
            return Ok(false);
        }
        // truncate(false)：锁文件已有内容必须保留（Python 用 r+b 打开，不截断）。
        #[cfg(unix)]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        if !readonly && file.metadata()?.len() == 0 {
            let mut writer = &file;
            writer.write_all(b"0")?;
            writer.flush()?;
        }
        if !try_lock(&file) {
            return Err(ClashError::Locked);
        }
        self.file = Some(file);
        Ok(true)
    }

    /// 释放锁（进程退出亦会释放）。
    pub fn close(&mut self) {
        if let Some(file) = self.file.take() {
            unlock(&file);
            drop(file);
        }
    }
}

impl Drop for CollectorLock {
    fn drop(&mut self) {
        self.close();
    }
}

/// 是否已有采集器在跑（Python \`collector_running\`）。
pub fn collector_running(paths: &Paths) -> bool {
    let mut lock = CollectorLock::new();
    match lock.acquire(&paths.lock_file(), true) {
        Ok(false) => false,
        Ok(true) => {
            lock.close();
            false
        }
        Err(_) => true,
    }
}

/// 打开可写账本：建表 + 一次性导入历史 Bettbox 账本（Python \`connect\`）。
pub fn connect(db_path: &Path) -> Result<Connection> {
    let db = Connection::open(db_path)?;
    db.execute_batch(SCHEMA)?;
    db.execute(
        "INSERT INTO segments(id,seq,domain,protocol,inbound,process,chain,rule,first,last,closed,up,down)
         SELECT id,0,domain,protocol,inbound,process,chain,rule,first,last,closed,up,down
         FROM connections c WHERE NOT EXISTS(SELECT 1 FROM segments s WHERE s.id=c.id)",
        [],
    )?;
    Ok(db)
}

/// 只读打开线上账本（Python \`readonly\`）：无账本时报「尚未采集」。
pub fn readonly(paths: &Paths) -> Result<Connection> {
    if !paths.db.exists() {
        return Err(ClashError::Runtime(
            "尚未采集；运行 clash-traffic monitor 或 watch".into(),
        ));
    }
    let db = Connection::open_with_flags(&paths.db, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    Ok(db)
}

/// 当前时间（秒，浮点）——与 Python \`time.time()\` 同源。
pub fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs_f64())
        .unwrap_or(0.0)
}

/// 读取 meta 中的 JSON 值（Python \`meta\`）。
pub fn meta_json(db: &Connection, key: &str) -> Result<Option<Value>> {
    let raw: Option<String> = db
        .query_row("SELECT v FROM meta WHERE k=?", params![key], |row| {
            row.get(0)
        })
        .optional()?;
    Ok(match raw {
        Some(value) => Some(serde_json::from_str(&value)?),
        None => None,
    })
}

/// 写入 meta 的 JSON 值（Python \`put\`）。
pub fn put_json(db: &Connection, key: &str, value: &Value) -> Result<()> {
    db.execute(
        "INSERT OR REPLACE INTO meta VALUES (?,?)",
        params![key, serde_json::to_string(value)?],
    )?;
    Ok(())
}

/// 读取 meta 中的整数（Python \`meta(db, key, default)\` 的整数用法）。
pub fn meta_number(db: &Connection, key: &str, default: i64) -> Result<i64> {
    Ok(match meta_json(db, key)? {
        Some(Value::Number(number)) => number.as_i64().unwrap_or(default),
        _ => default,
    })
}

/// 读取 meta 中的浮点（无值或类型不符时返回 None）。
pub fn meta_f64(db: &Connection, key: &str) -> Result<Option<f64>> {
    Ok(match meta_json(db, key)? {
        Some(Value::Number(number)) => number.as_f64(),
        _ => None,
    })
}

fn meta_number_optional(db: &Connection, key: &str) -> Result<Option<i64>> {
    Ok(match meta_json(db, key)? {
        Some(Value::Number(number)) => number.as_i64(),
        _ => None,
    })
}

/// 单次采样结果（Python \`ingest\` 返回值）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IngestResult {
    pub active: usize,
    pub observed_upload_delta: i64,
    pub observed_download_delta: i64,
}

/// 校验并写入一个原始快照（Python 调用形态：ingest(db, snapshot, now)）。
pub fn ingest_value(db: &mut Connection, snapshot: &Value, now: f64) -> Result<IngestResult> {
    let prepared = parse_snapshot(snapshot, now)?;
    ingest(db, &prepared, now)
}

/// 写入一个已校验快照：事务内累计增量、维护分段与分钟桶（Python \`ingest\`）。
pub fn ingest(db: &mut Connection, snapshot: &PreparedSnapshot, now: f64) -> Result<IngestResult> {
    let tx = db.transaction()?;
    let begin = meta_f64(&tx, "begin")?.unwrap_or(now);
    put_json(&tx, "begin", &serde_json::json!(begin))?;
    let samples = meta_number(&tx, "samples", 0)?;
    let mut total_up = 0i64;
    let mut total_down = 0i64;
    let mut seen: Vec<&str> = Vec::with_capacity(snapshot.connections.len());
    for item in &snapshot.connections {
        seen.push(item.id.as_str());
        let old: Option<(i64, i64)> = tx
            .query_row(
                "SELECT raw_up,raw_down FROM connections WHERE id=?",
                params![item.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (du, dd) = match old {
            Some((raw_up, raw_down)) => {
                let du = if item.up >= raw_up {
                    item.up - raw_up
                } else {
                    item.up
                };
                let dd = if item.down >= raw_down {
                    item.down - raw_down
                } else {
                    item.down
                };
                tx.execute(
                    "UPDATE connections SET domain=?,protocol=?,inbound=?,process=?,chain=?,rule=?,
                     last=?,closed=NULL,up=up+?,down=down+?,raw_up=?,raw_down=? WHERE id=?",
                    params![
                        item.dims[0],
                        item.dims[1],
                        item.dims[2],
                        item.dims[3],
                        item.dims[4],
                        item.dims[5],
                        now,
                        du,
                        dd,
                        item.up,
                        item.down,
                        item.id
                    ],
                )?;
                (du, dd)
            }
            None => {
                let fresh = if samples > 0 && item.start >= begin {
                    (item.up, item.down)
                } else {
                    (0, 0)
                };
                tx.execute(
                    "INSERT INTO connections(id,domain,protocol,inbound,process,chain,rule,ip,port,
                     start,first,last,closed,up,down,raw_up,raw_down)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?)",
                    params![
                        item.id,
                        item.dims[0],
                        item.dims[1],
                        item.dims[2],
                        item.dims[3],
                        item.dims[4],
                        item.dims[5],
                        item.ip,
                        item.port,
                        item.start,
                        now,
                        now,
                        fresh.0,
                        fresh.1,
                        item.up,
                        item.down
                    ],
                )?;
                fresh
            }
        };
        type SegmentRow = (
            i64,
            String,
            String,
            String,
            String,
            String,
            String,
            Option<f64>,
        );
        let segment: Option<SegmentRow> = tx
            .query_row(
                "SELECT seq,domain,protocol,inbound,process,chain,rule,closed FROM segments
                 WHERE id=? ORDER BY seq DESC LIMIT 1",
                params![item.id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let same_route = match &segment {
            Some((_, domain, protocol, inbound, process, chain, rule, _)) => {
                domain == &item.dims[0]
                    && protocol == &item.dims[1]
                    && inbound == &item.dims[2]
                    && process == &item.dims[3]
                    && chain == &item.dims[4]
                    && rule == &item.dims[5]
            }
            None => false,
        };
        match (&segment, same_route) {
            (Some(row), true) if row.7.is_none() => {
                tx.execute(
                    "UPDATE segments SET last=?,up=up+?,down=down+? WHERE id=? AND seq=?",
                    params![now, du, dd, item.id, row.0],
                )?;
            }
            _ => {
                let seq = match &segment {
                    Some(row) => row.0 + 1,
                    None => 0,
                };
                if let Some(row) = &segment {
                    if row.7.is_none() {
                        // 路由边界在本次采样观察到，不在采样间重建。
                        tx.execute(
                            "UPDATE segments SET closed=? WHERE id=? AND seq=?",
                            params![now, item.id, row.0],
                        )?;
                    }
                }
                tx.execute(
                    "INSERT INTO segments(id,seq,domain,protocol,inbound,process,chain,rule,first,last,closed,up,down)
                     VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?,?)",
                    params![
                        item.id,
                        seq,
                        item.dims[0],
                        item.dims[1],
                        item.dims[2],
                        item.dims[3],
                        item.dims[4],
                        item.dims[5],
                        now,
                        now,
                        du,
                        dd
                    ],
                )?;
            }
        }
        total_up += du;
        total_down += dd;
        if du != 0 || dd != 0 {
            tx.execute(
                "INSERT INTO buckets(minute,domain,protocol,inbound,process,chain,rule,up,down)
                 VALUES (?,?,?,?,?,?,?,?,?)
                 ON CONFLICT DO UPDATE SET up=up+excluded.up,down=down+excluded.down",
                params![
                    (now / 60.0).floor() as i64 * 60,
                    item.dims[0],
                    item.dims[1],
                    item.dims[2],
                    item.dims[3],
                    item.dims[4],
                    item.dims[5],
                    du,
                    dd
                ],
            )?;
        }
    }
    let open_ids: Vec<String> = {
        let mut statement = tx.prepare("SELECT id FROM connections WHERE closed IS NULL")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        ids
    };
    for id in open_ids {
        if seen.contains(&id.as_str()) {
            continue;
        }
        tx.execute(
            "UPDATE connections SET closed=? WHERE id=?",
            params![now, id],
        )?;
        tx.execute(
            "UPDATE segments SET closed=? WHERE id=? AND closed IS NULL",
            params![now, id],
        )?;
    }
    for (key, value) in [
        ("upload", snapshot.upload_total),
        ("download", snapshot.download_total),
    ] {
        let previous = meta_number_optional(&tx, &format!("raw_{}", key))?;
        let change = match previous {
            Some(raw) if value > raw => value - raw,
            _ => 0,
        };
        let global = meta_number(&tx, &format!("global_{}", key), 0)? + change;
        put_json(&tx, &format!("global_{}", key), &serde_json::json!(global))?;
        put_json(&tx, &format!("raw_{}", key), &serde_json::json!(value))?;
    }
    put_json(&tx, "last_success", &serde_json::json!(now))?;
    put_json(&tx, "last_error", &Value::Null)?;
    put_json(&tx, "samples", &serde_json::json!(samples + 1))?;
    tx.commit()?;
    Ok(IngestResult {
        active: seen.len(),
        observed_upload_delta: total_up,
        observed_download_delta: total_down,
    })
}

/// 原子写入（Python \`atomic\`）：临时文件 → 0600 → 替换。
pub fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".into());
    let tmp = path.with_file_name(format!("{}.{}.tmp", name, std::process::id()));
    fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// 追加一行采集日志（Python \`log\`）。
pub fn log_line(paths: &Paths, value: &Value) -> Result<()> {
    let mut line = serde_json::Map::new();
    line.insert(
        "time".into(),
        Value::String(crate::models::date(now_epoch())),
    );
    if let Value::Object(map) = value {
        for (key, item) in map {
            line.insert(key.clone(), item.clone());
        }
    }
    #[cfg(unix)]
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(paths.log_file())?;
    #[cfg(not(unix))]
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.log_file())?;
    file.write_all(serde_json::to_string(&Value::Object(line))?.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Python 风格的浮点字符串（整数值补 \`.0\`，供 CSV 与 Python 逐字节对齐）。
pub fn py_float(value: f64) -> String {
    let raw = format!("{}", value);
    if raw.contains('.') || raw.contains('e') || raw.contains('E') {
        raw
    } else {
        format!("{}.0", raw)
    }
}

/// CSV 字段转义（Python csv.writer QUOTE_MINIMAL + 公式注入前缀）。
pub fn csv_field(value: &str) -> String {
    let guarded = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{}", value)
    } else {
        value.to_string()
    };
    if guarded.contains(',')
        || guarded.contains('"')
        || guarded.contains('\n')
        || guarded.contains('\r')
    {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}
