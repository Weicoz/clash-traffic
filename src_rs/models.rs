//! Clash 快照解析、错误类型与格式化辅助。
//!
//! 本文件与 Python 旧实现（src/clash_traffic/cli.py）逐条对齐：
//! 错误分组、文本净化、计数校验、时间戳归一、字节/时长格式化。
//! 校验失败时抛出的中文文案与 Python 完全一致。

use serde_json::Value;
use std::fmt;
use std::io::IsTerminal;

/// 与 Python 异常一一对应的错误分组。
///
/// \`type_name()\` 用于 main() 的「操作未完成：<类型名>」输出，
/// 因此它必须回传 Python 侧会出现的异常类名。
#[derive(Debug)]
pub enum ClashError {
    /// Python ValueError：配置、快照、计数等校验失败。
    Value(String),
    /// Python RuntimeError：重定向、环境变量缺失、尚未采集等运行时失败。
    Runtime(String),
    /// Python BlockingIOError：采集锁被占用（已有采集器）。
    Locked,
    /// Python urllib.error.HTTPError：控制接口回传 4xx/5xx。
    Http(u16),
    /// Python urllib.error.URLError / socket.timeout：连接或传输失败。
    Transport(String),
    /// Python json.JSONDecodeError：响应体不是合法 JSON。
    Json(String),
    /// Python sqlite3.OperationalError：本地数据库失败。
    Sql(String),
    /// Python OSError：本地文件失败。
    Io(String),
}

impl ClashError {
    /// 回传 Python 对应的异常类名（用于「操作未完成：<类型名>」）。
    pub fn type_name(&self) -> &'static str {
        match self {
            ClashError::Value(_) => "ValueError",
            ClashError::Runtime(_) => "RuntimeError",
            ClashError::Locked => "BlockingIOError",
            ClashError::Http(_) => "HTTPError",
            ClashError::Transport(_) => "URLError",
            ClashError::Json(_) => "JSONDecodeError",
            ClashError::Sql(_) => "OperationalError",
            ClashError::Io(_) => "OSError",
        }
    }
}

impl fmt::Display for ClashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClashError::Value(m)
            | ClashError::Runtime(m)
            | ClashError::Json(m)
            | ClashError::Sql(m)
            | ClashError::Io(m)
            | ClashError::Transport(m) => f.write_str(m),
            ClashError::Locked => f.write_str("collector already running"),
            ClashError::Http(code) => write!(f, "HTTP {}", code),
        }
    }
}

impl std::error::Error for ClashError {}

impl From<rusqlite::Error> for ClashError {
    fn from(value: rusqlite::Error) -> Self {
        ClashError::Sql(value.to_string())
    }
}

impl From<serde_json::Error> for ClashError {
    fn from(value: serde_json::Error) -> Self {
        ClashError::Json(value.to_string())
    }
}

impl From<std::io::Error> for ClashError {
    fn from(value: std::io::Error) -> Self {
        ClashError::Io(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, ClashError>;

/// 单条已校验连接：六维路由 + 目标 + 起始时间 + 计数。
#[derive(Debug, Clone)]
pub struct PreparedConnection {
    pub id: String,
    /// (domain, protocol, inbound, process, chain, rule)
    pub dims: [String; 6],
    pub ip: String,
    pub port: String,
    pub start: f64,
    pub up: i64,
    pub down: i64,
}

/// 已校验的快照：连接列表 + 核心累计计数。
#[derive(Debug, Clone)]
pub struct PreparedSnapshot {
    pub connections: Vec<PreparedConnection>,
    pub upload_total: i64,
    pub download_total: i64,
}

/// Python 真值判定（\`bool(value)\`）：None / False / 0 / "" / [] / {} 为假。
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|v| v != 0.0).unwrap_or(true),
        Value::String(raw) => !raw.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// 文本净化：剔除 Cc 控制字符（U+0000-U+001F、U+007F-U+009F）并截断 1024 字符。
///
/// 对应 Python \`text()\`（\`str(value or "")\`），用于阻止外部核心元数据注入终端转义序列。
/// 假值按 Python 语义归零（0、False、空容器 → 空串）；非空容器按 JSON 文本呈现，
/// 与 Python repr 略有差异（真实控制接口的元数据字段均为标量）。
pub fn text(value: Option<&Value>) -> String {
    let raw = match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(flag)) => {
            if *flag {
                "True".into()
            } else {
                String::new()
            }
        }
        Some(Value::Number(number)) => {
            if number.as_f64() == Some(0.0) {
                String::new()
            } else {
                number.to_string()
            }
        }
        Some(Value::Array(items)) if items.is_empty() => String::new(),
        Some(Value::Object(map)) if map.is_empty() => String::new(),
        Some(other) => other.to_string(),
    };
    sanitize(&raw)
}

/// 就地净化：去控制字符 + 截断 1024。
pub fn sanitize(raw: &str) -> String {
    raw.chars().filter(|c| !is_control(*c)).take(1024).collect()
}

/// 是否属于 Python unicodedata 的 Cc 类别。
fn is_control(c: char) -> bool {
    let code = c as u32;
    (0x00..=0x1F).contains(&code) || (0x7F..=0x9F).contains(&code)
}

/// 流量计数校验：必须是 JSON 整数且在 [0, 2^63-1]，否则抛「无效流量计数」。
pub fn number(value: Option<&Value>) -> Result<i64> {
    match value {
        None => Ok(0),
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => {
            if n.as_u64().map(|u| u > i64::MAX as u64).unwrap_or(false)
                || n.as_i64().map(|v| v < 0).unwrap_or(false)
            {
                return Err(ClashError::Value("无效流量计数".into()));
            }
            Ok(n.as_i64().unwrap_or(0))
        }
        _ => Err(ClashError::Value("无效流量计数".into())),
    }
}

/// 起始时间归一：ISO8601 必须带时区，且不得晚于 \`now\`；非法值回退 \`now\`。
pub fn timestamp(value: Option<&Value>, now: f64) -> f64 {
    let raw = match value {
        Some(Value::String(s)) => s.clone(),
        _ => return now,
    };
    let normalized = raw.replace('Z', "+00:00");
    match chrono::DateTime::parse_from_rfc3339(&normalized) {
        Ok(parsed) => {
            let seconds = parsed.timestamp() as f64 + parsed.timestamp_subsec_micros() as f64 / 1e6;
            seconds.min(now)
        }
        Err(_) => now,
    }
}

/// 人类可读字节量（Python \`fmt\`）：B / KiB / MiB / GiB / TiB / PiB，两位小数。
pub fn fmt_bytes(n: f64) -> String {
    let mut value = n;
    for suffix in ["B", "KiB", "MiB", "GiB", "TiB"] {
        if value.abs() < 1024.0 {
            return format!("{:.2} {}", value, suffix);
        }
        value /= 1024.0;
    }
    format!("{:.2} PiB", value)
}

/// 本地时间 \`%m-%d %H:%M:%S\`；0 值显示 \`-\`（Python \`date\`）。
pub fn date(n: f64) -> String {
    if n == 0.0 {
        return "-".into();
    }
    match chrono::DateTime::from_timestamp(n as i64, 0) {
        Some(utc) => utc
            .with_timezone(&chrono::Local)
            .format("%m-%d %H:%M:%S")
            .to_string(),
        None => "-".into(),
    }
}

/// 终端列宽（Python \`shutil.get_terminal_size((140, 40)).columns\`）。
pub fn terminal_columns(default: usize) -> usize {
    // Python shutil.get_terminal_size 的取值顺序：COLUMNS 环境变量 -> 终端 ioctl -> 回退默认值。
    if let Ok(value) = std::env::var("COLUMNS") {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            if parsed > 0 {
                return parsed;
            }
        }
    }
    #[cfg(unix)]
    {
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
        if ok && size.ws_col > 0 {
            return size.ws_col as usize;
        }
    }
    default
}

/// 标准输出是否终端（Python \`sys.stdout.isatty()\`）。
pub fn stdout_isatty() -> bool {
    std::io::stdout().is_terminal()
}

/// 标准输入是否终端（Python \`sys.stdin.isatty()\`）。
pub fn stdin_isatty() -> bool {
    std::io::stdin().is_terminal()
}

/// 上次采样错误（写入 meta.last_error 的结构）。
#[derive(Debug, Clone, PartialEq)]
pub struct LastError {
    pub kind: String,
    pub at: String,
}

/// status() 的全部字段，顺序与 Python 返回的字典完全一致。
#[derive(Debug, Clone)]
pub struct StatusFields {
    pub running: bool,
    pub started: String,
    pub last_sample: String,
    pub sample_age_seconds: Option<f64>,
    pub samples: i64,
    pub connections_observed: i64,
    pub active_at_last_sample: i64,
    pub observed_upload: String,
    pub observed_download: String,
    pub inner_upload_separate: String,
    pub inner_download_separate: String,
    pub core_upload_delta: String,
    pub core_download_delta: String,
    pub last_error: Option<LastError>,
    pub report: String,
}

fn json_string(value: &str) -> String {
    serde_json::to_string(&Value::String(value.to_string())).unwrap_or_else(|_| "\"\"".into())
}

fn sample_age_json(value: Option<f64>) -> String {
    match value {
        Some(raw) => match serde_json::Number::from_f64(raw) {
            Some(number) => number.to_string(),
            None => "null".into(),
        },
        None => "null".into(),
    }
}

/// Python \`json.dumps(status, ensure_ascii=False, indent=2)\`。
pub fn status_json_pretty(fields: &StatusFields) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"running\": {},\n", fields.running));
    out.push_str(&format!(
        "  \"started\": {},\n",
        json_string(&fields.started)
    ));
    out.push_str(&format!(
        "  \"last_sample\": {},\n",
        json_string(&fields.last_sample)
    ));
    out.push_str(&format!(
        "  \"sample_age_seconds\": {},\n",
        sample_age_json(fields.sample_age_seconds)
    ));
    out.push_str(&format!("  \"samples\": {},\n", fields.samples));
    out.push_str(&format!(
        "  \"connections_observed\": {},\n",
        fields.connections_observed
    ));
    out.push_str(&format!(
        "  \"active_at_last_sample\": {},\n",
        fields.active_at_last_sample
    ));
    out.push_str(&format!(
        "  \"observed_upload\": {},\n",
        json_string(&fields.observed_upload)
    ));
    out.push_str(&format!(
        "  \"observed_download\": {},\n",
        json_string(&fields.observed_download)
    ));
    out.push_str(&format!(
        "  \"inner_upload_separate\": {},\n",
        json_string(&fields.inner_upload_separate)
    ));
    out.push_str(&format!(
        "  \"inner_download_separate\": {},\n",
        json_string(&fields.inner_download_separate)
    ));
    out.push_str(&format!(
        "  \"core_upload_delta\": {},\n",
        json_string(&fields.core_upload_delta)
    ));
    out.push_str(&format!(
        "  \"core_download_delta\": {},\n",
        json_string(&fields.core_download_delta)
    ));
    match &fields.last_error {
        Some(error) => {
            out.push_str("  \"last_error\": {\n");
            out.push_str(&format!("    \"type\": {},\n", json_string(&error.kind)));
            out.push_str(&format!("    \"at\": {}\n", json_string(&error.at)));
            out.push_str("  },\n");
        }
        None => out.push_str("  \"last_error\": null,\n"),
    }
    out.push_str(&format!("  \"report\": {}\n", json_string(&fields.report)));
    out.push('}');
    out
}

/// Python \`json.dumps(status, ensure_ascii=False)\`（单行紧凑格式，分隔符为 \`, \` 与 \`: \`）。
pub fn status_json_compact(fields: &StatusFields) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(15);
    parts.push(format!("\"running\": {}", fields.running));
    parts.push(format!("\"started\": {}", json_string(&fields.started)));
    parts.push(format!(
        "\"last_sample\": {}",
        json_string(&fields.last_sample)
    ));
    parts.push(format!(
        "\"sample_age_seconds\": {}",
        sample_age_json(fields.sample_age_seconds)
    ));
    parts.push(format!("\"samples\": {}", fields.samples));
    parts.push(format!(
        "\"connections_observed\": {}",
        fields.connections_observed
    ));
    parts.push(format!(
        "\"active_at_last_sample\": {}",
        fields.active_at_last_sample
    ));
    parts.push(format!(
        "\"observed_upload\": {}",
        json_string(&fields.observed_upload)
    ));
    parts.push(format!(
        "\"observed_download\": {}",
        json_string(&fields.observed_download)
    ));
    parts.push(format!(
        "\"inner_upload_separate\": {}",
        json_string(&fields.inner_upload_separate)
    ));
    parts.push(format!(
        "\"inner_download_separate\": {}",
        json_string(&fields.inner_download_separate)
    ));
    parts.push(format!(
        "\"core_upload_delta\": {}",
        json_string(&fields.core_upload_delta)
    ));
    parts.push(format!(
        "\"core_download_delta\": {}",
        json_string(&fields.core_download_delta)
    ));
    parts.push(format!(
        "\"last_error\": {}",
        match &fields.last_error {
            Some(error) => format!(
                "{{\"type\": {}, \"at\": {}}}",
                json_string(&error.kind),
                json_string(&error.at)
            ),
            None => "null".into(),
        }
    ));
    parts.push(format!("\"report\": {}", json_string(&fields.report)));
    format!("{{{}}}", parts.join(", "))
}

/// 解析并校验核心快照；校验规则与 Python \`ingest\` 前置检查逐条一致。
pub fn parse_snapshot(snapshot: &Value, now: f64) -> Result<PreparedSnapshot> {
    let connections = match snapshot {
        Value::Object(map) => match map.get("connections") {
            None => return Err(ClashError::Value("无效快照".into())),
            Some(Value::Null) => &Vec::new(),
            Some(Value::Array(items)) => items,
            Some(_) => return Err(ClashError::Value("无效快照".into())),
        },
        _ => return Err(ClashError::Value("无效快照".into())),
    };
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(connections.len());
    let mut prepared = Vec::with_capacity(connections.len());
    for item in connections {
        let object = match item {
            Value::Object(map) => map,
            _ => return Err(ClashError::Value("无效连接".into())),
        };
        let metadata = match object.get("metadata") {
            Some(Value::Object(map)) => map,
            _ => return Err(ClashError::Value("无效连接".into())),
        };
        let cid = match object.get("id") {
            Some(Value::String(value)) if !value.is_empty() => value.clone(),
            _ => return Err(ClashError::Value("无效连接".into())),
        };
        if !seen.insert(cid.clone()) {
            return Err(ClashError::Value("重复连接ID".into()));
        }
        let chains: Vec<String> = match object.get("chains") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let mut values = Vec::with_capacity(items.len());
                for chain in items {
                    match chain {
                        Value::String(value) => {
                            values.push(text(Some(&Value::String(value.clone()))))
                        }
                        _ => return Err(ClashError::Value("无效节点链".into())),
                    }
                }
                values
            }
            Some(_) => return Err(ClashError::Value("无效节点链".into())),
        };
        // 按 Python 的 a or b or default 真值链取值：空串/None/0 继续向后取。
        let pick = |keys: &[&str]| -> Option<&Value> {
            keys.iter()
                .find_map(|key| metadata.get(*key).filter(|value| truthy(value)))
        };
        let domain = match pick(&["host", "sniffHost", "destinationIP"]) {
            Some(value) => text(Some(value)),
            None => "(未知目标)".into(),
        };
        let protocol = match pick(&["network"]) {
            Some(value) => text(Some(value)),
            None => "(未知协议)".into(),
        }
        .to_uppercase();
        let inbound = match pick(&["type"]) {
            Some(value) => text(Some(value)),
            None => "(未知入站)".into(),
        };
        let process = match pick(&["process"]) {
            Some(value) => text(Some(value)),
            None => {
                let raw = pick(&["processPath"])
                    .map(|value| text(Some(value)))
                    .unwrap_or_default();
                let tail = raw
                    .replace('\\', "/")
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if tail.is_empty() {
                    "(未知应用)".into()
                } else {
                    tail
                }
            }
        };
        let chain = if chains.is_empty() {
            "(核心未提供节点链)".into()
        } else {
            chains.join(" → ")
        };
        let rule = {
            let first = text(object.get("rule"));
            let second = text(object.get("rulePayload"));
            let joined: Vec<&str> = [first.as_str(), second.as_str()]
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect();
            if joined.is_empty() {
                "(核心未提供规则)".into()
            } else {
                joined.join(":")
            }
        };
        prepared.push(PreparedConnection {
            id: cid,
            dims: [domain, protocol, inbound, process, chain, rule],
            ip: text(metadata.get("destinationIP")),
            port: text(metadata.get("destinationPort")),
            start: timestamp(object.get("start"), now),
            up: number(object.get("upload"))?,
            down: number(object.get("download"))?,
        });
    }
    Ok(PreparedSnapshot {
        connections: prepared,
        upload_total: number(snapshot.get("uploadTotal"))?,
        download_total: number(snapshot.get("downloadTotal"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn number_rejects_float_and_negative() {
        assert_eq!(number(Some(&json!(12))).unwrap(), 12);
        assert!(matches!(
            number(Some(&json!(1.5))),
            Err(ClashError::Value(_))
        ));
        assert!(matches!(
            number(Some(&json!(-1))),
            Err(ClashError::Value(_))
        ));
    }

    #[test]
    fn timestamp_requires_timezone_and_clamps() {
        let now = 1_000_000.0;
        assert_eq!(timestamp(Some(&json!("1970-01-01T00:16:40Z")), now), 1000.0);
        assert_eq!(timestamp(Some(&json!("1970-01-01T00:16:40")), now), now);
        assert_eq!(timestamp(Some(&json!("2999-01-01T00:00:00Z")), now), now);
        assert_eq!(timestamp(None, now), now);
    }

    #[test]
    fn text_strips_control_characters() {
        assert_eq!(text(Some(&json!("\u{1b}[31mred"))), "[31mred");
        assert_eq!(text(None), "");
    }

    #[test]
    fn fmt_matches_python_units() {
        let cases: [(f64, &str); 11] = [
            (0.0, "0.00 B"),
            (1.0, "1.00 B"),
            (1023.0, "1023.00 B"),
            (1024.0, "1.00 KiB"),
            (1536.0, "1.50 KiB"),
            (1024.0 * 1024.0, "1.00 MiB"),
            (1024.0f64.powi(3), "1.00 GiB"),
            (1024.0f64.powi(4), "1.00 TiB"),
            (1024.0f64.powi(4) * 1.5, "1.50 TiB"),
            (-1024.0, "-1.00 KiB"),
            (i64::MAX as f64, "8192.00 PiB"),
        ];
        for (value, expected) in cases {
            assert_eq!(fmt_bytes(value), expected, "fmt_bytes({value})");
        }
    }

    #[test]
    fn parse_snapshot_rejects_duplicate_and_normalizes_dimensions() {
        let snapshot = json!({
            "uploadTotal": 5,
            "downloadTotal": 6,
            "connections": [{
                "id": "a",
                "metadata": {"host": "test.example", "network": "tcp", "process": "test"},
                "upload": 5,
                "download": 6,
                "start": "1970-01-01T00:16:40Z",
                "chains": ["DIRECT"]
            }]
        });
        let parsed = parse_snapshot(&snapshot, 1010.0).unwrap();
        assert_eq!(parsed.connections[0].dims[0], "test.example");
        assert_eq!(parsed.connections[0].dims[1], "TCP");
        assert_eq!(parsed.connections[0].dims[4], "DIRECT");
        assert_eq!(parsed.connections[0].dims[5], "(核心未提供规则)");
        assert_eq!(parsed.connections[0].start, 1000.0);
        let mut duplicated = snapshot.clone();
        let first = duplicated["connections"][0].clone();
        duplicated["connections"]
            .as_array_mut()
            .unwrap()
            .push(first);
        assert!(matches!(
            parse_snapshot(&duplicated, 1010.0),
            Err(ClashError::Value(_))
        ));
    }
}
