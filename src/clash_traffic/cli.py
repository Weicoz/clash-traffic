"""Clash-compatible read-only traffic accounting and live tables."""

import argparse
import csv
from contextlib import closing
import datetime as dt
import getpass
import html
import ipaddress
import json
import math
import os
import shutil
import signal
import sqlite3
import sys
import time
import unicodedata
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlsplit
from . import __version__


def default_data_dir():
    if os.environ.get("CLASH_TRAFFIC_HOME"):
        return Path(os.environ["CLASH_TRAFFIC_HOME"]).expanduser().absolute()
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "clash-traffic"
    return (
        Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
        / "clash-traffic"
    )


ROOT = default_data_dir()
DB = ROOT / "traffic.sqlite3"
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT);
CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,domain TEXT,protocol TEXT,inbound TEXT,process TEXT,chain TEXT,rule TEXT,ip TEXT,port TEXT,start REAL,first REAL,last REAL,closed REAL,up INTEGER,down INTEGER,raw_up INTEGER,raw_down INTEGER);
CREATE TABLE IF NOT EXISTS buckets(minute INTEGER,domain TEXT,protocol TEXT,inbound TEXT,process TEXT,chain TEXT,rule TEXT,up INTEGER,down INTEGER,PRIMARY KEY(minute,domain,protocol,inbound,process,chain,rule));
CREATE TABLE IF NOT EXISTS segments(id TEXT,seq INTEGER,domain TEXT,protocol TEXT,inbound TEXT,process TEXT,chain TEXT,rule TEXT,first REAL,last REAL,closed REAL,up INTEGER,down INTEGER,PRIMARY KEY(id,seq));
CREATE INDEX IF NOT EXISTS segments_route ON segments(domain,rule,chain);
"""


class CollectorLock:
    """OS-owned lock survives neither crashes nor process exit, unlike PID files."""

    def __init__(self, readonly=False):
        self.path = ROOT / "collector.lock"
        self.readonly = readonly
        self.file = None

    def acquire(self):
        if self.readonly and not self.path.exists():
            return False
        self.file = self.path.open("r+b" if self.path.exists() else "w+b")
        if not self.readonly and not self.path.stat().st_size:
            self.file.write(b"0")
            self.file.flush()
        self.file.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise BlockingIOError("collector already running") from None
        return True

    def close(self):
        if self.file is not None:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
            self.file.close()
            self.file = None


def collector_running():
    lock = CollectorLock(readonly=True)
    try:
        lock.acquire()
        return False
    except BlockingIOError:
        return True
    finally:
        lock.close()


def meta(db, key, default=None):
    row = db.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def put(db, key, value):
    db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))


def connect(path=None):
    db = sqlite3.connect(path or DB)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    # Import the earlier Bettbox ledger once; never reset its counters/history.
    with db:
        db.execute("""INSERT INTO segments
            SELECT id,0,domain,protocol,inbound,process,chain,rule,first,last,closed,up,down
            FROM connections c WHERE NOT EXISTS(SELECT 1 FROM segments s WHERE s.id=c.id)""")
    return db


def readonly():
    if not DB.exists():
        raise RuntimeError("尚未采集；运行 clash-traffic monitor 或 watch")
    db = sqlite3.connect(DB.as_uri() + "?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    return db


def endpoint_url(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError(
            "endpoint 应为 http(s)://host:port，不允许凭据、路径或查询参数"
        )
    parsed.port  # Validate port syntax before any request.
    try:
        local = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        local = parsed.hostname.lower() == "localhost"
    if parsed.scheme == "http" and not local:
        raise ValueError("远端控制接口必须使用 HTTPS，或通过 SSH 转发到本机")
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError("拒绝控制接口重定向")


def settings(endpoint=None, secret_env=None):
    value = (
        json.loads((ROOT / "config.json").read_text())
        if (ROOT / "config.json").exists()
        else {}
    )
    controller = endpoint_url(
        endpoint
        or os.environ.get("CLASH_CONTROLLER")
        or value.get("endpoint", "http://127.0.0.1:9090")
    )
    env_key = secret_env or value.get("secret_env")
    if env_key:
        if env_key not in os.environ:
            raise RuntimeError("所配置的控制密码环境变量未设置")
        secret = os.environ[env_key]
    else:
        secret = os.environ.get("CLASH_SECRET", value.get("secret", ""))
    return controller, secret


def snapshot(endpoint=None, secret_env=None):
    controller, secret = settings(endpoint, secret_env)
    request = urllib.request.Request(
        controller + "/connections", headers={"Authorization": "Bearer " + secret}
    )
    # Controller traffic never follows system HTTP proxy settings or redirects.
    with urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect()
    ).open(request, timeout=4) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("控制接口响应过大")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or "connections" not in value
        or not isinstance(value["connections"], (list, type(None)))
    ):
        raise ValueError("接口不符合 Clash /connections 格式")
    if value["connections"] is None:
        value["connections"] = []
    return value


def number(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("无效流量计数")
    return value


def text(value):
    # Prevent terminal escape sequences in untrusted core metadata.
    return "".join(c for c in str(value or "") if unicodedata.category(c) != "Cc")[
        :1024
    ]


def timestamp(value, now):
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("missing timezone")
        return min(parsed.timestamp(), now)
    except (ValueError, AttributeError, OverflowError):
        return now


def ingest(db, snapshot, now):
    if (
        not isinstance(snapshot, dict)
        or "connections" not in snapshot
        or not isinstance(snapshot["connections"], (list, type(None)))
    ):
        raise ValueError("无效快照")
    seen = set()
    prepared = []
    for item in snapshot["connections"] or []:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("metadata"), dict)
            or not isinstance(item.get("id"), str)
            or not item["id"]
        ):
            raise ValueError("无效连接")
        cid = item["id"]
        if cid in seen:
            raise ValueError("重复连接ID")
        seen.add(cid)
        metadata = item["metadata"]
        chains = item.get("chains") or []
        if not isinstance(chains, list) or any(not isinstance(c, str) for c in chains):
            raise ValueError("无效节点链")
        dimensions = (
            text(
                metadata.get("host")
                or metadata.get("sniffHost")
                or metadata.get("destinationIP")
                or "(未知目标)"
            ),
            text(metadata.get("network") or "(未知协议)").upper(),
            text(metadata.get("type") or "(未知入站)"),
            text(
                metadata.get("process")
                or str(metadata.get("processPath") or "")
                .replace("\\", "/")
                .rsplit("/", 1)[-1]
                or "(未知应用)"
            ),
            " → ".join(text(c) for c in chains) or "(核心未提供节点链)",
            ":".join(
                filter(None, [text(item.get("rule")), text(item.get("rulePayload"))])
            )
            or "(核心未提供规则)",
        )
        prepared.append(
            (
                cid,
                dimensions,
                text(metadata.get("destinationIP")),
                text(metadata.get("destinationPort")),
                timestamp(item.get("start"), now),
                number(item.get("upload", 0)),
                number(item.get("download", 0)),
            )
        )
    global_up = number(snapshot.get("uploadTotal", 0))
    global_down = number(snapshot.get("downloadTotal", 0))
    total_up = total_down = 0
    with db:
        begin = meta(db, "begin", now)
        put(db, "begin", begin)
        for cid, dims, ip, port, start, up, down in prepared:
            old = db.execute("SELECT * FROM connections WHERE id=?", (cid,)).fetchone()
            if old:
                du = up - old["raw_up"] if up >= old["raw_up"] else up
                dd = down - old["raw_down"] if down >= old["raw_down"] else down
                db.execute(
                    """UPDATE connections SET domain=?,protocol=?,inbound=?,process=?,chain=?,rule=?,
                    last=?,closed=NULL,up=up+?,down=down+?,raw_up=?,raw_down=? WHERE id=?""",
                    (*dims, now, du, dd, up, down, cid),
                )
            else:
                du, dd = (
                    (up, down)
                    if meta(db, "samples", 0) > 0 and start >= begin
                    else (0, 0)
                )
                db.execute(
                    "INSERT INTO connections VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cid, *dims, ip, port, start, now, now, None, du, dd, up, down),
                )
            segment = db.execute(
                "SELECT * FROM segments WHERE id=? ORDER BY seq DESC LIMIT 1", (cid,)
            ).fetchone()
            same_route = (
                segment
                and tuple(
                    segment[key]
                    for key in (
                        "domain",
                        "protocol",
                        "inbound",
                        "process",
                        "chain",
                        "rule",
                    )
                )
                == dims
            )
            if same_route and segment["closed"] is None:
                db.execute(
                    "UPDATE segments SET last=?,up=up+?,down=down+? WHERE id=? AND seq=?",
                    (now, du, dd, cid, segment["seq"]),
                )
            else:
                seq = segment["seq"] + 1 if segment else 0
                if segment and segment["closed"] is None:
                    db.execute(
                        "UPDATE segments SET closed=? WHERE id=? AND seq=?",
                        (now, cid, segment["seq"]),
                    )
                # A route boundary is observed at this sample, not reconstructed between samples.
                db.execute(
                    "INSERT INTO segments VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cid, seq, *dims, now, now, None, du, dd),
                )
            total_up += du
            total_down += dd
            if du or dd:
                db.execute(
                    """INSERT INTO buckets VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT DO UPDATE
                    SET up=up+excluded.up,down=down+excluded.down""",
                    (int(now // 60) * 60, *dims, du, dd),
                )
        for row in db.execute(
            "SELECT id FROM connections WHERE closed IS NULL"
        ).fetchall():
            if row["id"] not in seen:
                db.execute(
                    "UPDATE connections SET closed=? WHERE id=?", (now, row["id"])
                )
                db.execute(
                    "UPDATE segments SET closed=? WHERE id=? AND closed IS NULL",
                    (now, row["id"]),
                )
        for key, value in (("upload", global_up), ("download", global_down)):
            previous = meta(db, "raw_" + key)
            change = max(0, value - previous) if previous is not None else 0
            put(db, "global_" + key, meta(db, "global_" + key, 0) + change)
            put(db, "raw_" + key, value)
        put(db, "last_success", now)
        put(db, "last_error", None)
        put(db, "samples", meta(db, "samples", 0) + 1)
    return {
        "active": len(seen),
        "observed_upload_delta": total_up,
        "observed_download_delta": total_down,
    }


def fmt(n):
    n = float(n)
    for suffix in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(n) < 1024:
            return f"{n:.2f} {suffix}"
        n /= 1024
    return f"{n:.2f} PiB"


def date(n):
    return (
        dt.datetime.fromtimestamp(n).astimezone().strftime("%m-%d %H:%M:%S")
        if n
        else "-"
    )


def groups(db, group, hours=None):
    column = {
        "domain": "domain",
        "protocol": "protocol",
        "process": "process",
        "chain": "chain",
        "rule": "rule",
        "inbound": "inbound",
    }[group]
    where = "1=1" if group == "inbound" else "inbound!='Inner'"
    extra = ",rule,chain,protocol" if group == "domain" else ""
    grouped = column + extra
    if hours:
        return db.execute(
            f"SELECT {column} name{extra},SUM(up) up,SUM(down) down,0 count,0 seconds,MIN(minute) first,MAX(minute) last FROM buckets WHERE {where} AND minute>=? GROUP BY {grouped} ORDER BY SUM(up+down) DESC",
            (time.time() - hours * 3600,),
        ).fetchall()
    return db.execute(
        f"SELECT {column} name{extra},SUM(up) up,SUM(down) down,COUNT(DISTINCT id) count,SUM(MAX(0,last-first)) seconds,MIN(first) first,MAX(last) last FROM segments WHERE {where} GROUP BY {grouped} ORDER BY SUM(up+down) DESC"
    ).fetchall()


def status(db):
    inner = db.execute(
        "SELECT COALESCE(SUM(up),0) up,COALESCE(SUM(down),0) down FROM segments WHERE inbound='Inner'"
    ).fetchone()
    totals = db.execute(
        "SELECT COUNT(*) n,SUM(closed IS NULL) active FROM connections"
    ).fetchone()
    sums = db.execute(
        "SELECT COALESCE(SUM(up),0) up,COALESCE(SUM(down),0) down FROM segments"
    ).fetchone()
    last = meta(db, "last_success")
    return {
        "running": collector_running(),
        "started": date(meta(db, "begin")),
        "last_sample": date(last),
        "sample_age_seconds": round(time.time() - last, 1) if last else None,
        "samples": meta(db, "samples", 0),
        "connections_observed": totals["n"],
        "active_at_last_sample": totals["active"] or 0,
        "observed_upload": fmt(sums["up"] - inner["up"]),
        "observed_download": fmt(sums["down"] - inner["down"]),
        "inner_upload_separate": fmt(inner["up"]),
        "inner_download_separate": fmt(inner["down"]),
        "core_upload_delta": fmt(meta(db, "global_upload", 0)),
        "core_download_delta": fmt(meta(db, "global_download", 0)),
        "last_error": meta(db, "last_error"),
        "report": str(ROOT / "report.html"),
    }


def atomic(path, content):
    tmp = path.with_suffix(path.suffix + "." + str(os.getpid()) + ".tmp")
    tmp.write_text(content)
    tmp.chmod(0o600)
    tmp.replace(path)


def report(db):
    escape = lambda x: html.escape(str(x))
    blocks = []
    for group, title in [
        ("domain", "域名 / 未识别目标 IP"),
        ("protocol", "TCP / UDP"),
        ("process", "应用"),
        ("chain", "核心返回的实际节点链"),
        ("rule", "命中规则"),
        ("inbound", "入站类型（含内部链路，勿相加作为计费量）"),
    ]:
        rows = groups(db, group)
        headers = (
            ["域名 / IP", "命中规则", "实际节点链", "协议"]
            if group == "domain"
            else ["对象"]
        )
        headers += ["上传", "下载", "合计", "连接数", "观察时长累计 / 分钟"]
        table = ""
        for row in rows:
            values = (
                [row["name"]]
                + (
                    [row["rule"], row["chain"], row["protocol"]]
                    if group == "domain"
                    else []
                )
                + [
                    fmt(row["up"]),
                    fmt(row["down"]),
                    fmt(row["up"] + row["down"]),
                    row["count"],
                    f"{row['seconds'] / 60:.1f}",
                ]
            )
            table += (
                "<tr>"
                + "".join("<td>" + escape(value) + "</td>" for value in values)
                + "</tr>"
            )
        blocks.append(
            f"<details open><summary>{title}</summary><table><thead><tr>"
            + "".join("<th>" + escape(h) + "</th>" for h in headers)
            + "</tr></thead><tbody>"
            + table
            + "</tbody></table></details>"
        )
    rows = db.execute(
        "SELECT s.*,c.ip,c.port,c.start FROM segments s JOIN connections c USING(id) ORDER BY s.last DESC LIMIT 500"
    ).fetchall()
    detail = "".join(
        "<tr>"
        + "".join(
            "<td>" + escape(v) + "</td>"
            for v in [
                r["domain"],
                r["protocol"] + " / " + r["inbound"],
                r["ip"] + ":" + r["port"],
                r["process"],
                r["rule"],
                r["chain"],
                date(r["start"]),
                date(r["first"]),
                date(r["last"]),
                date(r["closed"]) if r["closed"] else "上次采样仍活跃",
                f"{max(0, r['last'] - r['first']):.1f}s",
                fmt(r["up"]),
                fmt(r["down"]),
            ]
        )
        + "</tr>"
        for r in rows
    )
    summary = escape(json.dumps(status(db), ensure_ascii=False, indent=2))
    document = (
        """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><meta http-equiv="refresh" content="5"><title>Clash Traffic 本地流量</title><style>body{font:15px system-ui;margin:28px;color:#ddd;background:#16191d}h1{font-size:24px}details{margin:24px 0}summary{font-size:19px;cursor:pointer}table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:9px;border-bottom:1px solid #394049;text-align:left;overflow-wrap:anywhere}th{color:#8cd4ff}pre{white-space:pre-wrap}input{padding:10px;width:320px;background:#252a31;color:white;border:1px solid #586675}p{line-height:1.6;color:#abb9c5}</style><h1>Clash Traffic 本地流量分布</h1><p>域名/应用/协议/规则/节点链排行只累计业务连接，排除 Inner 内部链路；内部传输另列入站类型表，不与业务流量相加。每秒只读采样，累计从首次启动开始；首次已存在连接的历史字节不计入。短连接及消失前最后一段流量可能漏计；核心总量与域名量口径可能不同，均不是机场账单。协议仅为核心 TCP/UDP 和入站类型，不解密 HTTPS/QUIC。结束时间是首次观察到消失的时间；时长是观察下界，并发连接时长相加不代表使用时间。同域名更换规则或节点链后分行累计；采样间路由切换的字节归属为近似值。核心未提供的信息显示未知。仅本地文件，不收集 URL/正文/凭据。</p><input placeholder="筛选域名、规则、应用、节点链" oninput="document.querySelectorAll('tbody tr').forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(this.value.toLowerCase()))"><pre>"""
        + summary
        + "</pre>"
        + "".join(blocks)
        + "<details><summary>最近 500 条连接（完整记录在 SQLite / CSV）</summary><table><thead><tr>"
        + "".join(
            "<th>" + h + "</th>"
            for h in [
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
        )
        + "</tr></thead><tbody>"
        + detail
        + "</tbody></table></details></html>"
    )
    atomic(ROOT / "report.html", document)
    return ROOT / "report.html"


def log(value):
    with (ROOT / "collector.jsonl").open("a") as f:
        f.write(
            json.dumps({"time": date(time.time()), **value}, ensure_ascii=False) + "\n"
        )


def fit(value, width):
    output = ""
    size = 0
    for char in text(value):
        amount = 2 if unicodedata.east_asian_width(char) in "WF" else 1
        if size + amount > width:
            break
        output += char
        size += amount
    return output + " " * max(0, width - size)


def live_table(db, limit=20):
    columns = shutil.get_terminal_size((140, 40)).columns
    domain_width = max(12, min(26, (columns - 76) // 3))
    rule_width = max(12, min(28, (columns - 76) // 3))
    chain_width = max(16, columns - domain_width - rule_width - 70)
    widths = [domain_width, rule_width, chain_width, 6, 10, 10, 10, 9]
    headers = [
        "域名 / IP",
        "命中规则",
        "实际节点链",
        "协议",
        "上传",
        "下载",
        "累计",
        "时长",
    ]
    lines = [
        "Clash Traffic · " + date(time.time()) + " · Ctrl+C 退出窗口",
        " | ".join(fit(h, w) for h, w in zip(headers, widths)),
    ]
    rows = db.execute(
        """SELECT domain,rule,chain,protocol,SUM(up) up,SUM(down) down,
        SUM(MAX(0,last-first)) seconds FROM segments WHERE inbound!='Inner'
        GROUP BY domain,rule,chain,protocol ORDER BY SUM(up+down) DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    for row in rows:
        cells = [
            row["domain"],
            row["rule"],
            row["chain"],
            row["protocol"],
            fmt(row["up"]),
            fmt(row["down"]),
            fmt(row["up"] + row["down"]),
            f"{row['seconds'] / 60:.1f}m",
        ]
        lines.append(" | ".join(fit(v, w) for v, w in zip(cells, widths)))
    state = status(db)
    lines.append(
        f"连接 {state['active_at_last_sample']} · 样本 {state['samples']} · 最后采样 {state['last_sample']} · 上次错误 {state['last_error']}"
    )
    lines.append(
        "业务与 Inner 分开计量；长列在 report 查看。历史/短连接/机场账单边界见 README。"
    )
    return "\n".join(lines)


def display_live(db, limit):
    if sys.stdout.isatty():
        print("\033[H\033[2J" + live_table(db, limit), flush=True)
    else:
        print(live_table(db, limit), flush=True)


def watch(interval, endpoint=None, secret_env=None, live=False, limit=20, once=False):
    lock = CollectorLock()
    lock.acquire()
    stop = ROOT / "stop"
    stop.unlink(missing_ok=True)
    db = connect()
    last_report = last_log = 0
    stopping = False

    def halt(*_):
        nonlocal stopping
        stopping = True

    old_handlers = {
        sig: signal.signal(sig, halt) for sig in (signal.SIGTERM, signal.SIGINT)
    }
    if not live:
        print("采集启动：只读 Clash 控制 API；报表", ROOT / "report.html", flush=True)
    try:
        while not stopping and not stop.exists():
            tick = time.monotonic()
            try:
                result = ingest(db, snapshot(endpoint, secret_env), time.time())
                if time.time() - last_log >= 60:
                    log({"status": "采集中", **result})
                    if not live:
                        print(json.dumps(status(db), ensure_ascii=False), flush=True)
                    last_log = time.time()
            except Exception as error:
                kind = type(error).__name__
                with db:
                    put(db, "last_error", {"type": kind, "at": date(time.time())})
                if time.time() - last_log >= 60:
                    log({"status": "等待接口", "error_type": kind})
                    if not live:
                        print("等待接口：" + kind, flush=True)
                    last_log = time.time()
            if time.time() - last_report >= 5:
                report(db)
                last_report = time.time()
            if live:
                display_live(db, limit)
            if once:
                break
            time.sleep(max(0.05, interval - (time.monotonic() - tick)))
    finally:
        report(db)
        log({"status": "已停止"})
        db.close()
        lock.close()
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
        if not live:
            print("采集已停止；数据保留", flush=True)


def monitor(interval, endpoint=None, secret_env=None, limit=20, once=False):
    if collector_running():
        with closing(readonly()) as db:
            while True:
                display_live(db, limit)
                if once:
                    return
                time.sleep(interval)
    else:
        watch(interval, endpoint, secret_env, live=True, limit=limit, once=once)


def selftest():
    import tempfile

    with tempfile.TemporaryDirectory() as temp:
        db = connect(Path(temp) / "test.db")

        def sample(u, d, active=True, start="1970-01-01T00:16:40Z"):
            return {
                "uploadTotal": u,
                "downloadTotal": d,
                "connections": [
                    {
                        "id": "a",
                        "metadata": {
                            "host": "test.example",
                            "network": "tcp",
                            "process": "test",
                        },
                        "upload": u,
                        "download": d,
                        "start": start,
                        "chains": ["DIRECT"],
                    }
                ]
                if active
                else [],
            }

        ingest(db, sample(100, 200), 1010)
        assert db.execute("SELECT up+down FROM connections").fetchone()[0] == 0
        ingest(db, sample(150, 300), 1011)
        ingest(db, sample(150, 300), 1012)
        row = db.execute("SELECT up,down FROM connections").fetchone()
        assert tuple(row) == (50, 100)
        ingest(db, sample(150, 300, False), 1013)
        assert db.execute("SELECT closed FROM connections").fetchone()[0] == 1013
        ingest(db, sample(170, 310), 1014)
        assert db.execute("SELECT closed FROM connections").fetchone()[0] is None
        ingest(db, sample(5, 10), 1015)
        assert tuple(db.execute("SELECT up,down FROM connections").fetchone()) == (
            75,
            120,
        )
        bad = sample(8, 12)
        bad["connections"].append(bad["connections"][0])
        try:
            ingest(db, bad, 1016)
            raise AssertionError("should reject duplicate")
        except ValueError:
            pass
        assert tuple(db.execute("SELECT up,down FROM connections").fetchone()) == (
            75,
            120,
        )
        assert sum(r["up"] for r in groups(db, "domain")) == 75
        inner = sample(90, 90, start="1970-01-01T00:17:00Z")
        inner["connections"][0]["id"] = "inner"
        inner["connections"][0]["metadata"]["type"] = "Inner"
        ingest(db, inner, 1020)
        assert sum(r["up"] for r in groups(db, "domain")) == 75
        assert any(
            r["name"] == "Inner" and r["up"] == 90 for r in groups(db, "inbound")
        )
        db.close()
        db = connect(Path(temp) / "test.db")
        assert tuple(db.execute("SELECT up,down FROM connections").fetchone()) == (
            75,
            120,
        )
        same = sample(7, 8, start="1970-01-01T00:17:01Z")
        same["connections"][0].update(
            id="b", rule="RuleSet", rulePayload="my-dev-relay", chains=["中转"]
        )
        ingest(db, same, 1021)
        rows = groups(db, "domain")
        assert len(rows) == 2 and sum(row["up"] for row in rows) == 82
        assert any(
            row["rule"] == "RuleSet:my-dev-relay"
            and row["chain"] == "中转"
            and row["up"] == 7
            for row in rows
        )
        recent = groups(db, "domain", time.time() / 3600 + 1)
        assert len(recent) == 2
        assert sum(row["up"] for row in recent) == 82
        db.close()
    print(
        "自检通过：基线、增量去重、断开/恢复、计数回退、事务回滚、重启持久化、分组累计、Inner单独计量、同域名按规则和链分行"
    )


def run(argv=None):
    global ROOT, DB
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=[
            "init",
            "watch",
            "monitor",
            "status",
            "report",
            "export",
            "stop",
            "self-test",
        ],
        nargs="?",
        default="status",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--endpoint", help="Clash HTTP(S) 控制接口根地址")
    parser.add_argument(
        "--secret-env", help="保存控制密码的环境变量名称；不会保存该变量的值"
    )
    parser.add_argument(
        "--no-secret", action="store_true", help="init 时明确使用无密码控制接口"
    )
    parser.add_argument(
        "--by",
        choices=["domain", "protocol", "process", "chain", "rule", "inbound"],
        default="domain",
    )
    parser.add_argument("--hours", type=float)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--once", action="store_true", help="watch/monitor 只运行一次")
    args = parser.parse_args(argv)
    if args.data_dir:
        ROOT = args.data_dir.expanduser().absolute()
        DB = ROOT / "traffic.sqlite3"
    if args.dry_run:
        print(
            json.dumps(
                {
                    "dry_run": True,
                    "command": args.command,
                    "data_dir": str(ROOT),
                    "network_calls": 0,
                    "credential_reads": 0,
                    "state_writes": 0,
                },
                ensure_ascii=False,
            )
        )
        return
    if (
        not math.isfinite(args.interval)
        or args.interval < 0.5
        or args.limit < 1
        or (
            args.hours is not None
            and (not math.isfinite(args.hours) or args.hours <= 0)
        )
    ):
        parser.error("间隔至少0.5秒，数量和时间必须为有限正数")
    os.umask(0o077)
    if args.command == "self-test":
        selftest()
        return
    if args.command == "init":
        endpoint = endpoint_url(args.endpoint or "http://127.0.0.1:9090")
        cfg = {"endpoint": endpoint}
        if args.secret_env:
            cfg["secret_env"] = args.secret_env
        elif not args.no_secret:
            if not sys.stdin.isatty():
                parser.error("非交互 init 请使用 --secret-env 或 --no-secret")
            cfg["secret"] = getpass.getpass("控制接口密码（输入不显示）：")
        ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        previous = ROOT / "config.json"
        if previous.exists():
            shutil.copy2(previous, ROOT / ("config." + str(time.time_ns()) + ".bak"))
        atomic(previous, json.dumps(cfg, ensure_ascii=False, indent=2))
        print("本地配置已保存：", previous)
        return
    if args.command in ("watch", "monitor"):
        ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        if args.command == "monitor" and not sys.stdout.isatty() and not args.once:
            parser.error("实时窗口需要终端；非终端使用 --once 或 watch")
        function = monitor if args.command == "monitor" else watch
        function(
            args.interval,
            args.endpoint,
            args.secret_env,
            limit=args.limit,
            once=args.once,
        )
        return
    if args.command == "stop":
        if not ROOT.exists():
            print("尚未采集")
            return
        atomic(ROOT / "stop", "stop\n")
        print("已请求停止采集；保留累计数据")
        return
    with closing(readonly()) as db:
        if args.command == "status":
            print(json.dumps(status(db), ensure_ascii=False, indent=2))
        elif args.command == "export":
            path = ROOT / "connections.csv"
            with path.open("w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                rows = db.execute(
                    "SELECT s.*,c.ip,c.port,c.start FROM segments s JOIN connections c USING(id) ORDER BY s.id,s.seq"
                )
                writer.writerow([v[0] for v in rows.description])
                writer.writerows(
                    [
                        "'" + v
                        if isinstance(v, str)
                        and v.startswith(("=", "+", "-", "@", "\t", "\r"))
                        else v
                        for v in row
                    ]
                    for row in rows
                )
            path.chmod(0o600)
            print(path)
        else:
            print(
                "域名 / IP\t命中规则\t实际节点链\t协议\t上传\t下载\t合计"
                if args.by == "domain"
                else "对象\t上传\t下载\t合计"
            )
            for row in groups(db, args.by, args.hours)[: args.limit]:
                fields = (
                    [row["name"]]
                    + (
                        [row["rule"], row["chain"], row["protocol"]]
                        if args.by == "domain"
                        else []
                    )
                    + [fmt(row["up"]), fmt(row["down"]), fmt(row["up"] + row["down"])]
                )
                print("\t".join(text(value) for value in fields))
            print("本地报表：", report(db))


def main():
    try:
        run()
    except KeyboardInterrupt:
        return
    except BlockingIOError:
        raise SystemExit("已有采集器；使用 clash-traffic monitor 查看") from None
    except Exception as error:
        # Exceptions can contain auth headers or response bodies; never echo them.
        raise SystemExit(
            "操作未完成："
            + type(error).__name__
            + "；未修改代理，请检查控制接口或本地配置"
        ) from None
