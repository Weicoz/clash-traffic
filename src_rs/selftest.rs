//! 离线自检：等价 Python \`selftest()\`，用临时账本验证计量语义。
//!
//! 断言覆盖：基线不回填、增量去重、断开与恢复、计数回退、重复 ID 回滚、
//! 重启持久化、分组累计、Inner 单独计量、同域名按规则与链分行、分钟桶窗口。

use crate::models::{ClashError, Result};
use crate::query::groups;
use crate::storage::{connect, ingest_value, now_epoch, Paths};
use rusqlite::Connection;
use serde_json::{json, Value};

/// 自检通过时的固定文案（与 Python 一致）。
pub const SUCCESS_MESSAGE: &str = "自检通过：基线、增量去重、断开/恢复、计数回退、事务回滚、重启持久化、分组累计、Inner单独计量、同域名按规则和链分行";

fn sample(upload: i64, download: i64, now: f64, active: bool, id: &str) -> Value {
    let start = "1970-01-01T00:16:40Z";
    json!({
        "uploadTotal": upload,
        "downloadTotal": download,
        "connections": if active {
            json!([{
                "id": id,
                "metadata": {"host": "test.example", "network": "tcp", "process": "test"},
                "upload": upload,
                "download": download,
                "start": start,
                "chains": ["DIRECT"],
            }])
        } else {
            json!([])
        },
        "_now": now,
    })
}

fn route_sample(
    upload: i64,
    download: i64,
    id: &str,
    rule: &str,
    chain: &str,
    start: &str,
) -> Value {
    json!({
        "uploadTotal": upload,
        "downloadTotal": download,
        "connections": [{
            "id": id,
            "metadata": {
                "host": "test.example",
                "network": "tcp",
                "process": "test",
                "type": if id == "inner" { "Inner" } else { "HTTP" },
            },
            "rule": rule,
            "rulePayload": if rule.is_empty() { "" } else { "my-dev-relay" },
            "upload": upload,
            "download": download,
            "start": start,
            "chains": [chain],
        }],
    })
}

fn summary(db: &Connection) -> Result<(i64, i64)> {
    Ok(db.query_row(
        "SELECT COALESCE(SUM(up),0),COALESCE(SUM(down),0) FROM segments",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?)
}

/// 单条连接自身的累计（Python 自检直接读 connections 首行）。
fn connection_totals(db: &Connection, id: &str) -> Result<(i64, i64)> {
    Ok(
        db.query_row("SELECT up,down FROM connections WHERE id=?", [id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?,
    )
}

fn domain_upload(db: &Connection) -> Result<i64> {
    let rows = groups(db, "domain", None)?;
    Ok(rows.iter().map(|row| row.up).sum())
}

fn closed_at(db: &Connection, id: &str) -> Result<Option<f64>> {
    Ok(
        db.query_row("SELECT closed FROM connections WHERE id=?", [id], |row| {
            row.get::<_, Option<f64>>(0)
        })?,
    )
}

/// 执行完整离线自检；成功返回结尾文案，失败返回 ClashError。
pub fn selftest() -> Result<String> {
    let root = std::env::temp_dir().join(format!("clash-traffic-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let paths = Paths::with_root(root.join("state"));
    paths.ensure_root()?;
    let result = run_checks(&paths);
    let _ = std::fs::remove_dir_all(&root);
    result?;
    Ok(SUCCESS_MESSAGE.to_string())
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(ClashError::Value(format!("自检失败：{}", message)))
    }
}

fn run_checks(paths: &Paths) -> Result<()> {
    let mut db = connect(&paths.db)?;

    // 首样本只建立基线。
    ingest_value(&mut db, &sample(100, 200, 1010.0, true, "a"), 1010.0)?;
    let (up, down) = summary(&db)?;
    ensure(up + down == 0, "首样本基线应为 0")?;

    // 增量累计与重复样本去重。
    ingest_value(&mut db, &sample(150, 300, 1011.0, true, "a"), 1011.0)?;
    ingest_value(&mut db, &sample(150, 300, 1012.0, true, "a"), 1012.0)?;
    let (up, down) = summary(&db)?;
    ensure((up, down) == (50, 100), "重复样本不应重复累加")?;

    // 连接消失 → closed；恢复 → closed 清空。
    ingest_value(&mut db, &sample(150, 300, 1013.0, false, "a"), 1013.0)?;
    ensure(
        closed_at(&db, "a")? == Some(1013.0),
        "连接消失应写入 closed",
    )?;
    ingest_value(&mut db, &sample(170, 310, 1014.0, true, "a"), 1014.0)?;
    ensure(closed_at(&db, "a")?.is_none(), "连接恢复应清空 closed")?;

    // 计数回退：新值小于旧值时直接采用新值。
    ingest_value(&mut db, &sample(5, 10, 1015.0, true, "a"), 1015.0)?;
    let (up, down) = summary(&db)?;
    ensure((up, down) == (75, 120), "计数回退应直接采用新值")?;

    // 重复连接 ID 必须整笔拒绝，且已累计的数据不变。
    let mut duplicated = sample(9, 9, 1016.0, true, "a");
    if let Some(connections) = duplicated
        .get_mut("connections")
        .and_then(|v| v.as_array_mut())
    {
        let first = connections[0].clone();
        connections.push(first);
    }
    match ingest_value(&mut db, &duplicated, 1016.0) {
        Err(ClashError::Value(message)) => {
            ensure(message.contains("重复连接ID"), "重复 ID 应报重复连接ID")?;
        }
        other => {
            return Err(ClashError::Value(format!(
                "重复 ID 未被拒绝：{:?}",
                other.is_ok()
            )))
        }
    }
    let (up, down) = summary(&db)?;
    ensure((up, down) == (75, 120), "重复 ID 失败后不应改动累计")?;
    ensure(domain_upload(&db)? == 75, "分组累计应为 75")?;

    // Inner 内部链路单独计量，不进入业务分组。
    ingest_value(
        &mut db,
        &route_sample(90, 90, "inner", "", "", "1970-01-01T00:17:00Z"),
        1020.0,
    )?;
    ensure(domain_upload(&db)? == 75, "Inner 不应计入域名分组")?;
    let inbound = groups(&db, "inbound", None)?;
    let inner = inbound.iter().find(|row| row.name == "Inner");
    ensure(
        inner.map(|row| row.up) == Some(90),
        "入站分组应单独列出 Inner",
    )?;

    // 重开账本：持久化累计不变。
    drop(db);
    let mut db = connect(&paths.db)?;
    let (up, down) = connection_totals(&db, "a")?;
    ensure((up, down) == (75, 120), "重启后应保持累计")?;

    // 同域名更换规则与节点链 → 分行累计。
    ingest_value(
        &mut db,
        &route_sample(7, 8, "b", "RuleSet", "中转", "1970-01-01T00:17:01Z"),
        1021.0,
    )?;
    let rows = groups(&db, "domain", None)?;
    ensure(rows.len() == 2, "同域名不同规则应分行")?;
    // Python 自检按 up 求和（不含下载方向）。
    let total: i64 = rows.iter().map(|row| row.up).sum();
    ensure(total == 82, "分行后合计应为 82")?;
    ensure(
        rows.iter()
            .any(|row| row.rule == "RuleSet:my-dev-relay" && row.chain == "中转" && row.up == 7),
        "应存在 RuleSet / 中转 行为 7",
    )?;

    // 分钟桶窗口查询也必须返回 82。
    let hours = Some(now_epoch() / 3600.0 + 1.0);
    let bucketed = groups(&db, "domain", hours)?;
    let total: i64 = bucketed.iter().map(|row| row.up).sum();
    ensure(total == 82, "分钟桶窗口合计应为 82")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        let message = selftest().unwrap();
        assert_eq!(message, SUCCESS_MESSAGE);
    }
}
