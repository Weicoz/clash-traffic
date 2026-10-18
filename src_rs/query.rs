//! 查询与报表数据组装：分组排行、状态字段、报表明细与 CSV 导出。
//!
//! 所有 SQL 与列顺序对齐 Python 旧实现 src/clash_traffic/cli.py 的
//! groups() / status() / report()，保证同一份 SQLite 账本上输出一致。

use crate::models::{date, fmt_bytes, LastError, Result, StatusFields};
use crate::report::{format_minutes, ReportSection};
use crate::storage::{meta_f64, meta_json, meta_number, now_epoch, py_float, Paths, RULE_KEY};
use rusqlite::Connection;
use serde_json::Value;
use std::path::PathBuf;

/// 分组排行的一行（六组通用；域组额外带规则/节点链/协议）。
/// 一行分组聚合结果。
///
/// `first`/`last` 与 Python 行字典保持一致（留作后续列扩展），
/// 当前报表与终端表格不展示这两列。
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct GroupRow {
    pub name: String,
    pub rule: String,
    pub chain: String,
    pub protocol: String,
    pub up: i64,
    pub down: i64,
    pub count: i64,
    pub seconds: f64,
    pub first: f64,
    pub last: f64,
}

impl GroupRow {
    pub fn total(&self) -> i64 {
        self.up + self.down
    }
}

/// 报表分组标题，与 Python report() 完全一致。
pub const GROUP_TITLES: [(&str, &str); 6] = [
    ("domain", "域名 / 未识别目标 IP"),
    ("protocol", "TCP / UDP"),
    ("process", "应用"),
    ("chain", "核心返回的实际节点链"),
    ("rule", "命中规则"),
    ("inbound", "入站类型（含内部链路，勿相加作为计费量）"),
];

/// 归一化分组名（未知值退回 domain，与 Python dict[group] 的默认行为等价）。
pub fn normalize_group(group: &str) -> &'static str {
    match group {
        "protocol" => "protocol",
        "process" => "process",
        "chain" => "chain",
        "rule" => "rule",
        "inbound" => "inbound",
        _ => "domain",
    }
}

fn optional_text(row: &rusqlite::Row<'_>, index: usize) -> String {
    row.get::<_, Option<String>>(index)
        .ok()
        .flatten()
        .unwrap_or_default()
}

fn optional_i64(row: &rusqlite::Row<'_>, index: usize) -> i64 {
    row.get::<_, Option<i64>>(index).ok().flatten().unwrap_or(0)
}

fn optional_f64(row: &rusqlite::Row<'_>, index: usize) -> f64 {
    row.get::<_, Option<f64>>(index)
        .ok()
        .flatten()
        .unwrap_or(0.0)
}

/// 分组排行：\`hours\` 有值时查分钟桶窗口，否则按分段（segments）累计。
pub fn groups(db: &Connection, group: &str, hours: Option<f64>) -> Result<Vec<GroupRow>> {
    let group = normalize_group(group);
    let column = if group == "rule" { RULE_KEY } else { group };
    let where_clause = if group == "inbound" {
        "1=1"
    } else {
        "inbound!='Inner'"
    };
    let has_extra = group == "domain";
    let extra = if has_extra {
        format!(",{} rule,chain,protocol", RULE_KEY)
    } else {
        String::new()
    };
    let grouped = if has_extra {
        // 与 Python 一致：域组按 (domain, RULE_KEY, chain, protocol) 分组；
        // 漏掉 RULE_KEY 会让 SQLite 用裸列语义任取一条规则的名称，同域不同规则被错误合并。
        format!("{},{},chain,protocol", column, RULE_KEY)
    } else {
        column.to_string()
    };
    let sql = if hours.is_some() {
        format!(
            "SELECT {column} name{extra},SUM(up) up,SUM(down) down,0 count,0 seconds,MIN(minute) first,MAX(minute) last \
             FROM buckets WHERE {where_clause} AND minute>=? GROUP BY {grouped} ORDER BY SUM(up+down) DESC",
            column = column,
            extra = extra,
            where_clause = where_clause,
            grouped = grouped
        )
    } else {
        format!(
            "SELECT {column} name{extra},SUM(up) up,SUM(down) down,COUNT(DISTINCT id) count,SUM(MAX(0,last-first)) seconds,MIN(first) first,MAX(last) last \
             FROM segments WHERE {where_clause} GROUP BY {grouped} ORDER BY SUM(up+down) DESC",
            column = column,
            extra = extra,
            where_clause = where_clause,
            grouped = grouped
        )
    };
    let offset = if has_extra { 3 } else { 0 };
    let mut statement = db.prepare(&sql)?;
    let mut collected = Vec::new();
    let mut cursor = match hours {
        Some(hours) => statement.query([now_epoch() - hours * 3600.0])?,
        None => statement.query([])?,
    };
    while let Some(row) = cursor.next()? {
        collected.push(GroupRow {
            name: optional_text(row, 0),
            rule: if has_extra {
                optional_text(row, 1)
            } else {
                String::new()
            },
            chain: if has_extra {
                optional_text(row, 2)
            } else {
                String::new()
            },
            protocol: if has_extra {
                optional_text(row, 3)
            } else {
                String::new()
            },
            up: optional_i64(row, 1 + offset),
            down: optional_i64(row, 2 + offset),
            count: optional_i64(row, 3 + offset),
            seconds: optional_f64(row, 4 + offset),
            first: optional_f64(row, 5 + offset),
            last: optional_f64(row, 6 + offset),
        });
    }
    Ok(collected)
}

/// 摘要计数（Python status() 的三组聚合查询）。
struct Totals {
    inner: (i64, i64),
    count: i64,
    active: i64,
    sums: (i64, i64),
}

fn totals(db: &Connection) -> Result<Totals> {
    let inner = db.query_row(
        "SELECT COALESCE(SUM(up),0) up,COALESCE(SUM(down),0) down FROM segments WHERE inbound='Inner'",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    let count = db.query_row("SELECT COUNT(*) FROM connections", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let active = db.query_row(
        "SELECT COALESCE(SUM(closed IS NULL),0) FROM connections",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let sums = db.query_row(
        "SELECT COALESCE(SUM(up),0) up,COALESCE(SUM(down),0) down FROM segments",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok(Totals {
        inner,
        count,
        active,
        sums,
    })
}

/// status 命令的字段集合（Python status() 语义）。
pub fn status(db: &Connection, paths: &Paths) -> Result<StatusFields> {
    let totals = totals(db)?;
    let last = meta_f64(db, "last_success")?;
    let begin = meta_f64(db, "begin")?;
    let last_error = match meta_json(db, "last_error")? {
        Some(Value::Object(map)) => Some(LastError {
            kind: map
                .get("type")
                .and_then(|value| value.as_str())
                .unwrap_or("未知错误")
                .to_string(),
            at: map
                .get("at")
                .and_then(|value| value.as_str())
                .unwrap_or("-")
                .to_string(),
        }),
        _ => None,
    };
    Ok(StatusFields {
        running: crate::storage::collector_running(paths),
        started: date(begin.unwrap_or(0.0)),
        last_sample: date(last.unwrap_or(0.0)),
        sample_age_seconds: last.map(|raw| ((now_epoch() - raw) * 10.0).round() / 10.0),
        samples: meta_number(db, "samples", 0)?,
        connections_observed: totals.count,
        active_at_last_sample: totals.active,
        observed_upload: fmt_bytes((totals.sums.0 - totals.inner.0) as f64),
        observed_download: fmt_bytes((totals.sums.1 - totals.inner.1) as f64),
        inner_upload_separate: fmt_bytes(totals.inner.0 as f64),
        inner_download_separate: fmt_bytes(totals.inner.1 as f64),
        core_upload_delta: fmt_bytes(meta_number(db, "global_upload", 0)? as f64),
        core_download_delta: fmt_bytes(meta_number(db, "global_download", 0)? as f64),
        last_error,
        report: paths.report().to_string_lossy().to_string(),
    })
}

/// 六张分组表的数据（供 report.rs 渲染）。
pub fn report_sections(db: &Connection) -> Result<Vec<ReportSection>> {
    let mut sections = Vec::with_capacity(GROUP_TITLES.len());
    for (group, title) in GROUP_TITLES {
        let rows = groups(db, group, None)?;
        let mut headers: Vec<String> = if group == "domain" {
            vec![
                "域名 / IP".into(),
                "命中规则".into(),
                "实际节点链".into(),
                "协议".into(),
            ]
        } else {
            vec!["对象".into()]
        };
        headers.extend(
            ["上传", "下载", "合计", "连接数", "观察时长累计 / 分钟"]
                .iter()
                .map(|value| value.to_string()),
        );
        let mut rendered = Vec::with_capacity(rows.len());
        for row in &rows {
            let mut values = vec![row.name.clone()];
            if group == "domain" {
                values.push(row.rule.clone());
                values.push(row.chain.clone());
                values.push(row.protocol.clone());
            }
            values.push(fmt_bytes(row.up as f64));
            values.push(fmt_bytes(row.down as f64));
            values.push(fmt_bytes(row.total() as f64));
            values.push(row.count.to_string());
            values.push(format_minutes(row.seconds));
            rendered.push(values);
        }
        sections.push(ReportSection {
            summary: title.to_string(),
            row_count: rendered.len(),
            headers,
            rows: rendered,
        });
    }
    Ok(sections)
}

/// 明细表表头（与 Python report() 的 13 列一致）。
pub fn detail_headers() -> Vec<String> {
    [
        "目标",
        "协议/入站",
        "IP/端口",
        "应用",
        "命中规则",
        "节点链",
        "核心开始",
        "首次观察",
        "最后观察",
        "观察消失",
        "观察时长",
        "上传",
        "下载",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

/// 明细行（最近 limit 条分段，按最后观察时间倒序）。
pub fn detail_rows(db: &Connection, limit: usize) -> Result<Vec<Vec<String>>> {
    let mut statement = db.prepare(
        "SELECT s.domain,s.protocol,s.inbound,c.ip,c.port,s.process,s.rule,s.chain,
                c.start,s.first,s.last,s.closed,s.up,s.down
         FROM segments s JOIN connections c USING(id) ORDER BY s.last DESC LIMIT ?1",
    )?;
    let mut cursor = statement.query([limit as i64])?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next()? {
        let ip = optional_text(row, 3);
        let port = optional_text(row, 4);
        let first = optional_f64(row, 9);
        let last = optional_f64(row, 10);
        rows.push(vec![
            optional_text(row, 0),
            format!("{} / {}", optional_text(row, 1), optional_text(row, 2)),
            if port.is_empty() {
                ip
            } else {
                format!("{}:{}", ip, port)
            },
            optional_text(row, 5),
            optional_text(row, 6),
            optional_text(row, 7),
            date(optional_f64(row, 8)),
            date(first),
            date(last),
            match row.get::<_, Option<f64>>(11).ok().flatten() {
                Some(value) => date(value),
                None => "上次采样仍活跃".to_string(),
            },
            format!("{:.1}s", (last - first).max(0.0)),
            fmt_bytes(optional_i64(row, 12) as f64),
            fmt_bytes(optional_i64(row, 13) as f64),
        ]);
    }
    Ok(rows)
}

/// 终端实时表头（Python live_table 的 8 列）。
pub fn live_headers() -> Vec<String> {
    [
        "域名 / IP",
        "命中规则",
        "实际节点链",
        "协议",
        "上传",
        "下载",
        "累计",
        "时长",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

/// 终端实时表行（按域 + 规则 + 链 + 协议聚合，时长以分钟计）。
pub fn live_rows(db: &Connection, limit: usize) -> Result<Vec<Vec<String>>> {
    let rows = groups(db, "domain", None)?;
    let mut rendered = Vec::new();
    for row in rows.into_iter().take(limit) {
        let total = row.up + row.down;
        rendered.push(vec![
            row.name,
            row.rule,
            row.chain,
            row.protocol,
            fmt_bytes(row.up as f64),
            fmt_bytes(row.down as f64),
            fmt_bytes(total as f64),
            format!("{}m", format_minutes(row.seconds)),
        ]);
    }
    Ok(rendered)
}

/// 导出 CSV（Python run() 的 export 分支）：完整分段列表，CRLF，权限 0600。
pub fn export_csv(db: &Connection, paths: &Paths) -> Result<PathBuf> {
    let headers = [
        "id", "seq", "domain", "protocol", "inbound", "process", "chain", "rule", "first", "last",
        "closed", "up", "down", "ip", "port", "start",
    ];
    let mut statement = db.prepare(
        "SELECT s.id,s.seq,s.domain,s.protocol,s.inbound,s.process,s.chain,s.rule,s.first,s.last,
                s.closed,s.up,s.down,c.ip,c.port,c.start
         FROM segments s JOIN connections c USING(id) ORDER BY s.id,s.seq",
    )?;
    let mut out = String::new();
    out.push_str(&headers.join(","));
    out.push_str("\r\n");
    let mut cursor = statement.query([])?;
    while let Some(row) = cursor.next()? {
        let mut fields: Vec<String> = Vec::with_capacity(headers.len());
        fields.push(crate::storage::csv_field(&optional_text(row, 0)));
        fields.push(optional_i64(row, 1).to_string());
        for index in 2..=7 {
            fields.push(crate::storage::csv_field(&optional_text(row, index)));
        }
        for index in 8..=10 {
            match row.get::<_, Option<f64>>(index).ok().flatten() {
                Some(value) => fields.push(py_float(value)),
                None => fields.push(String::new()),
            }
        }
        fields.push(optional_i64(row, 11).to_string());
        fields.push(optional_i64(row, 12).to_string());
        fields.push(crate::storage::csv_field(&optional_text(row, 13)));
        fields.push(crate::storage::csv_field(&optional_text(row, 14)));
        match row.get::<_, Option<f64>>(15).ok().flatten() {
            Some(value) => fields.push(py_float(value)),
            None => fields.push(String::new()),
        }
        out.push_str(&fields.join(","));
        out.push_str("\r\n");
    }
    crate::storage::atomic_write(&paths.csv(), &out)?;
    Ok(paths.csv())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{connect, ingest_value, Paths};
    use serde_json::json;

    fn sample(up: i64, down: i64, timestamp: &str, id: &str) -> Value {
        json!({
            "uploadTotal": up,
            "downloadTotal": down,
            "connections": [{
                "id": id,
                "metadata": {"host": "test.example", "network": "tcp", "process": "test"},
                "upload": up,
                "download": down,
                "start": timestamp,
                "chains": ["DIRECT"],
            }],
        })
    }

    fn temp_paths(tag: &str) -> Paths {
        let root = std::env::temp_dir().join(format!("clash-query-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let paths = Paths::with_root(root);
        paths.ensure_root().unwrap();
        paths
    }

    #[test]
    fn groups_and_status_use_python_semantics() {
        let paths = temp_paths("groups");
        let mut db = connect(&paths.db).unwrap();
        ingest_value(
            &mut db,
            &sample(100, 200, "1970-01-01T00:16:40Z", "a"),
            1000.0,
        )
        .unwrap();
        ingest_value(
            &mut db,
            &sample(150, 300, "1970-01-01T00:16:41Z", "a"),
            1011.0,
        )
        .unwrap();
        let rows = groups(&db, "domain", None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "test.example");
        assert_eq!(rows[0].up, 50);
        assert_eq!(rows[0].down, 100);
        assert_eq!(rows[0].count, 1);
        assert_eq!(rows[0].chain, "DIRECT");
        assert_eq!(rows[0].protocol, "TCP");
        let plain = groups(&db, "protocol", None).unwrap();
        assert_eq!(plain.len(), 1);
        assert_eq!(plain[0].name, "TCP");
        assert_eq!(plain[0].up, 50);
        assert!(plain[0].rule.is_empty());
        let fields = status(&db, &paths).unwrap();
        assert_eq!(fields.samples, 2);
        assert_eq!(fields.connections_observed, 1);
        assert_eq!(fields.observed_upload, "50.00 B");
        assert_eq!(fields.observed_download, "100.00 B");
        assert_eq!(fields.core_upload_delta, "50.00 B");
        assert_eq!(fields.inner_upload_separate, "0.00 B");
        assert_eq!(fields.active_at_last_sample, 1);
        assert!(fields.last_error.is_none());
        let sections = report_sections(&db).unwrap();
        assert_eq!(sections.len(), 6);
        assert_eq!(sections[0].summary, "域名 / 未识别目标 IP");
        assert_eq!(sections[0].headers.len(), 9);
        assert_eq!(sections[0].rows[0][1], "(核心未提供规则)");
        let details = detail_rows(&db, 500).unwrap();
        assert_eq!(details.len(), 1);
        assert_eq!(details[0][0], "test.example");
        assert_eq!(details[0][1], "TCP / (未知入站)");
        let live = live_rows(&db, 20).unwrap();
        assert_eq!(live[0].len(), 8);
        assert_eq!(live[0][4], "50.00 B");
        let csv = export_csv(&db, &paths).unwrap();
        let text = std::fs::read_to_string(&csv).unwrap();
        assert!(text.starts_with("id,seq,domain,protocol,inbound,process,chain,rule,first,last,closed,up,down,ip,port,start\r\n"));
        assert!(text.contains("test.example"));
        let _ = std::fs::remove_dir_all(&paths.root);
    }
}
