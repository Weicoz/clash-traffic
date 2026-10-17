//! SQLite Storage & Ingest State Machine for clash-traffic.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use rusqlite::{params, Connection, Result};

use crate::models::{ClashSnapshot, GroupRow};

pub fn default_data_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CLASH_TRAFFIC_HOME") {
        return PathBuf::from(p);
    }
    let mut p = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    p.push(".local/state/clash-traffic");
    p
}

pub fn default_db_path() -> PathBuf {
    default_data_dir().join("traffic.sqlite3")
}

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS connections(
    id TEXT PRIMARY KEY,
    domain TEXT,
    protocol TEXT,
    inbound TEXT,
    process TEXT,
    chain TEXT,
    rule TEXT,
    ip TEXT,
    port TEXT,
    start REAL,
    first REAL,
    last REAL,
    closed REAL,
    up INTEGER,
    down INTEGER,
    raw_up INTEGER,
    raw_down INTEGER
);
CREATE TABLE IF NOT EXISTS buckets(
    minute INTEGER,
    domain TEXT,
    protocol TEXT,
    inbound TEXT,
    process TEXT,
    chain TEXT,
    rule TEXT,
    up INTEGER,
    down INTEGER,
    PRIMARY KEY(minute, domain, protocol, inbound, process, chain, rule)
);
CREATE TABLE IF NOT EXISTS segments(
    id TEXT,
    seq INTEGER,
    domain TEXT,
    protocol TEXT,
    inbound TEXT,
    process TEXT,
    chain TEXT,
    rule TEXT,
    first REAL,
    last REAL,
    closed REAL,
    up INTEGER,
    down INTEGER,
    PRIMARY KEY(id, seq)
);
CREATE INDEX IF NOT EXISTS segments_route ON segments(domain, rule, chain);
";

pub fn connect(db_path: Option<&PathBuf>) -> Result<Connection> {
    let path = db_path.cloned().unwrap_or_else(default_db_path);
    if let Some(p) = path.parent() {
        let _ = fs::create_dir_all(p);
    }

    let conn = Connection::open(&path)?;
    let _ = conn.busy_timeout(std::time::Duration::from_millis(5000));
    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA busy_timeout = 5000;
    ")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn parse_iso_timestamp(ts_str: &str, now: f64) -> f64 {
    chrono::DateTime::parse_from_rfc3339(ts_str)
        .map(|dt| dt.timestamp() as f64)
        .unwrap_or(now)
}

fn sanitize_text(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(1024).collect()
}

pub fn get_meta_number(conn: &Connection, key: &str, default: i64) -> i64 {
    let mut stmt = match conn.prepare("SELECT v FROM meta WHERE k = ?1") {
        Ok(s) => s,
        Err(_) => return default,
    };
    stmt.query_row([key], |row| {
        let v: String = row.get(0)?;
        Ok(v.parse::<i64>().unwrap_or(default))
    })
    .unwrap_or(default)
}

pub fn put_meta_number(conn: &Connection, key: &str, value: i64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta VALUES (?1, ?2)",
        params![key, value.to_string()],
    )?;
    Ok(())
}

pub fn ingest(conn: &mut Connection, snap: &ClashSnapshot, now: f64) -> Result<(usize, u64, u64)> {
    let connections = snap.connections.as_deref().unwrap_or(&[]);
    let mut seen = HashSet::with_capacity(connections.len());

    let tx = conn.transaction()?;

    let samples_count = get_meta_number(&tx, "samples", 0);
    let begin_time = if samples_count == 0 {
        put_meta_number(&tx, "begin", now as i64)?;
        now
    } else {
        get_meta_number(&tx, "begin", now as i64) as f64
    };

    let mut total_up_delta: u64 = 0;
    let mut total_down_delta: u64 = 0;

    for item in connections {
        let cid = &item.id;
        seen.insert(cid.clone());

        let meta = item.metadata.as_ref();
        let domain = meta
            .and_then(|m| m.host.as_ref().or(m.sniff_host.as_ref()).or(m.destination_ip.as_ref()))
            .map(|s| sanitize_text(s))
            .unwrap_or_else(|| "(未知目标)".to_string());

        let protocol = meta
            .and_then(|m| m.network.as_ref())
            .map(|s| sanitize_text(s).to_uppercase())
            .unwrap_or_else(|| "(未知协议)".to_string());

        let inbound = meta
            .and_then(|m| m.conn_type.as_ref())
            .map(|s| sanitize_text(s))
            .unwrap_or_else(|| "(未知入站)".to_string());

        let process = meta
            .and_then(|m| {
                if let Some(ref p) = m.process {
                    if !p.is_empty() {
                        return Some(p.clone());
                    }
                }
                m.process_path.as_ref().and_then(|p| {
                    p.replace('\\', "/").rsplit('/').next().map(|s| s.to_string())
                })
            })
            .map(|s| sanitize_text(&s))
            .unwrap_or_else(|| "(未知应用)".to_string());

        let chain = item
            .chains
            .as_ref()
            .map(|c| c.join(" → "))
            .filter(|s| !s.is_empty())
            .map(|s| sanitize_text(&s))
            .unwrap_or_else(|| "(核心未提供节点链)".to_string());

        let raw_rule = match (&item.rule, &item.rule_payload) {
            (Some(r), Some(p)) if !p.is_empty() => format!("{}:{}", r, p),
            (Some(r), _) => r.clone(),
            _ => "(核心未提供规则)".to_string(),
        };
        let rule = sanitize_text(&raw_rule);

        let ip = meta.and_then(|m| m.destination_ip.clone()).unwrap_or_default();
        let port = meta.and_then(|m| m.destination_port.clone()).unwrap_or_default();
        let start_time = item
            .start
            .as_ref()
            .map(|s| parse_iso_timestamp(s, now))
            .unwrap_or(now);

        let up = item.upload;
        let down = item.download;

        // 检查之前状态
        let old_res: Option<(i64, i64)> = {
            let mut stmt = tx.prepare_cached("SELECT raw_up, raw_down FROM connections WHERE id = ?1")?;
            stmt.query_row([cid], |r| Ok((r.get(0)?, r.get(1)?))).ok()
        };

        let (du, dd) = match old_res {
            Some((old_raw_up, old_raw_down)) => {
                let u_diff = if up >= old_raw_up as u64 { up - old_raw_up as u64 } else { up };
                let d_diff = if down >= old_raw_down as u64 { down - old_raw_down as u64 } else { down };
                (u_diff, d_diff)
            }
            None => {
                if samples_count > 0 && start_time >= begin_time {
                    (up, down)
                } else {
                    (0, 0)
                }
            }
        };

        if old_res.is_some() {
            tx.execute(
                "UPDATE connections SET domain=?1, protocol=?2, inbound=?3, process=?4, chain=?5, rule=?6,
                 last=?7, closed=NULL, up=up+?8, down=down+?9, raw_up=?10, raw_down=?11 WHERE id=?12",
                params![domain, protocol, inbound, process, chain, rule, now, du as i64, dd as i64, up as i64, down as i64, cid],
            )?;
        } else {
            tx.execute(
                "INSERT INTO connections VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, ?13, ?14, ?15, ?16)",
                params![cid, domain, protocol, inbound, process, chain, rule, ip, port, start_time, now, now, du as i64, dd as i64, up as i64, down as i64],
            )?;
        }

        // 维护 Segments (分行独立统计)
        let latest_seg: Option<(i64, String, String, String, Option<f64>)> = {
            let mut stmt = tx.prepare_cached("SELECT seq, domain, rule, chain, closed FROM segments WHERE id=?1 ORDER BY seq DESC LIMIT 1")?;
            stmt.query_row([cid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).ok()
        };

        let same_route = match &latest_seg {
            Some((_, s_domain, s_rule, s_chain, s_closed)) => {
                s_closed.is_none() && s_domain == &domain && s_rule == &rule && s_chain == &chain
            }
            None => false,
        };

        if same_route {
            let seq = latest_seg.unwrap().0;
            tx.execute(
                "UPDATE segments SET last=?1, up=up+?2, down=down+?3 WHERE id=?4 AND seq=?5",
                params![now, du as i64, dd as i64, cid, seq],
            )?;
        } else {
            let next_seq = latest_seg.as_ref().map(|s| s.0 + 1).unwrap_or(0);
            if let Some((old_seq, _, _, _, closed)) = latest_seg {
                if closed.is_none() {
                    tx.execute("UPDATE segments SET closed=?1 WHERE id=?2 AND seq=?3", params![now, cid, old_seq])?;
                }
            }
            tx.execute(
                "INSERT INTO segments VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12)",
                params![cid, next_seq, domain, protocol, inbound, process, chain, rule, now, now, du as i64, dd as i64],
            )?;
        }

        total_up_delta += du;
        total_down_delta += dd;

        if du > 0 || dd > 0 {
            let minute = (now as i64 / 60) * 60;
            tx.execute(
                "INSERT INTO buckets VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(minute, domain, protocol, inbound, process, chain, rule)
                 DO UPDATE SET up=up+excluded.up, down=down+excluded.down",
                params![minute, domain, protocol, inbound, process, chain, rule, du as i64, dd as i64],
            )?;
        }
    }

    // 关闭已消失的连接
    let active_rows: Vec<String> = {
        let mut close_stmt = tx.prepare("SELECT id FROM connections WHERE closed IS NULL")?;
        let rows = close_stmt
            .query_map([], |r| r.get(0))?
            .flatten()
            .collect();
        rows
    };

    for cid in active_rows {
        if !seen.contains(&cid) {
            tx.execute("UPDATE connections SET closed=?1 WHERE id=?2", params![now, cid])?;
            tx.execute("UPDATE segments SET closed=?1 WHERE id=?2 AND closed IS NULL", params![now, cid])?;
        }
    }

    put_meta_number(&tx, "samples", samples_count + 1)?;
    tx.commit()?;

    Ok((seen.len(), total_up_delta, total_down_delta))
}

pub fn get_grouped_traffic(conn: &Connection, exclude_inner: bool) -> Result<Vec<GroupRow>> {
    let sql = if exclude_inner {
        "SELECT domain, rule, chain, protocol, SUM(up) as up_t, SUM(down) as down_t,
                MIN(first) as f_seen, MAX(last) as l_seen
         FROM segments
         WHERE inbound != 'Inner'
         GROUP BY domain, rule, chain, protocol
         ORDER BY (SUM(up) + SUM(down)) DESC"
    } else {
        "SELECT domain, rule, chain, protocol, SUM(up) as up_t, SUM(down) as down_t,
                MIN(first) as f_seen, MAX(last) as l_seen
         FROM segments
         GROUP BY domain, rule, chain, protocol
         ORDER BY (SUM(up) + SUM(down)) DESC"
    };

    let mut stmt = conn.prepare(sql)?;
    let rows = stmt
        .query_map([], |row| {
            let up: i64 = row.get(4)?;
            let down: i64 = row.get(5)?;
            let first: f64 = row.get(6)?;
            let last: f64 = row.get(7)?;
            Ok(GroupRow {
                domain: row.get(0)?,
                rule: row.get(1)?,
                chain: row.get(2)?,
                protocol: row.get(3)?,
                up,
                down,
                total: up + down,
                first_seen: first,
                last_seen: last,
                duration_sec: (last - first).max(1.0),
            })
        })?
        .flatten()
        .collect();

    Ok(rows)
}
