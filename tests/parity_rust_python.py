#!/usr/bin/env python3
"""Rust 原生实现与 Python 参考实现的行为对拍。

用法:
    python tests/parity_rust_python.py [--rust-bin PATH] [--repo PATH] [--keep]

流程: 起本地 mock Clash /connections 服务 -> 用 Rust 二进制与 Python 实现各跑 3 轮
watch --once 采集同一快照序列 -> 逐项比较 SQLite 账本、status JSON、report --by 排行、
report.html 单元格、export CSV、--dry-run 输出、CLI 错误文案。

退出码 0 = 全部一致; 1 = 存在真实分歧(逐项打印)。

按噪声处理(不计入比较)的内容: 采集墙钟决定的 first/last/closed 时间戳及其派生的时长列、
status 的 started/last_sample/sample_age_seconds、数据目录路径、report.html 的字节数与
文档化的展示增强(数字列右对齐、每表行数、明细表实际行数)。
"""
import argparse
import csv
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Windows 里指向管道的 stdout 默认是 cp1252，直接 print 中文会 UnicodeEncodeError。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DATE_CELL = re.compile(r"\d\d-\d\d \d\d:\d\d:\d\d")
DURATION_CELL = re.compile(r"\d+\.\d+s")
CSV_NOISY = {8, 9, 10}  # first / last / closed


def conn(case_id, host, up, down, rule="DIRECT", rule_payload="", chains=None, ctype="HTTP",
         ip="1.2.3.4", port="443", proc="test", proc_path="/usr/bin/test", sniff=None,
         start="1970-01-01T00:16:40Z"):
    metadata = {"network": "tcp", "type": ctype, "destinationIP": ip, "destinationPort": port,
                "sourceIP": "127.0.0.1", "sourcePort": "50000"}
    if host is not None:
        metadata["host"] = host
    if sniff is not None:
        metadata["sniffHost"] = sniff
    if proc is not None:
        metadata["process"] = proc
    if proc_path is not None:
        metadata["processPath"] = proc_path
    # rule / rulePayload / chains 在真实 Clash /connections 里是连接对象顶层字段。
    return {"id": case_id, "upload": up, "download": down, "start": start,
            "chains": chains if chains is not None else ["DIRECT"],
            "rule": rule, "rulePayload": rule_payload, "metadata": metadata}


def snap(upload_total, download_total, entries):
    return {"uploadTotal": upload_total, "downloadTotal": download_total, "connections": entries}


def seq(a_up, a_down, inner_up, inner_down, c_up, c_down, extra=None):
    entries = [
        conn("a", "test.example", a_up, a_down),
        conn("inner", "", inner_up, inner_down, ctype="Inner", rule="", chains=[]),
        # host 为空串 -> 真值链必须继续取 sniffHost
        conn("c", "", c_up, c_down, sniff="sniff.example", rule="MATCH"),
        # host 缺失 -> 落到 destinationIP
        conn("d", None, 1, 2, ip="5.6.7.8", proc="curl", chains=["DIRECT", "中转"]),
        # process 缺失 -> 落到 processPath 文件名
        conn("e", "path.example", 11, 12, proc=None, proc_path="/opt/Clash/app/foo bar"),
    ]
    if extra:
        entries.extend(extra)
    return entries


SNAPSHOTS = [
    snap(1000, 2000, seq(100, 200, 5, 6, 3, 4)),
    snap(1100, 2300, seq(150, 300, 5, 6, 4, 5)),
    snap(1200, 2500, seq(150, 300, 9, 10, 4, 5,
         extra=[
             conn("b", "test.example", 7, 8, rule="RuleSet", rule_payload="my-dev-relay",
                  chains=["中转"]),
             # 同域名 + 同链 + 同协议但不同规则: 分组键必须含规则, 否则被错误合并
             conn("g", "test.example", 3, 4, rule="MATCH", chains=["中转"]),
             # 遗留尾冒号规则与规范写法必须归并到同一 RULE_KEY
             conn("h", "colon.example", 5, 6, rule="RuleSet:"),
             conn("i", "colon.example", 7, 8, rule="RuleSet"),
         ])),
]
GROUPS = ["domain", "rule", "chain", "process", "protocol", "inbound"]
requests_seen = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        index = min(len(requests_seen), len(SNAPSHOTS) - 1)
        requests_seen.append(self.path)
        body = json.dumps(SNAPSHOTS[index]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def python_launcher(repo):
    code = ("import sys;sys.path.insert(0,%r);from clash_traffic import cli;cli.run(sys.argv[1:])"
            % os.path.join(repo, "src"))
    return [sys.executable, "-c", code]


def child_env(**extra):
    """子进程环境: 管道必须按 UTF-8 编解码, 否则 Windows 上中文输出失败。"""
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", **extra)
    env.pop("CLASH_SECRET", None)
    return env


def run_case(launcher, data_dir, port, rounds=3):
    global requests_seen
    shutil.rmtree(data_dir, ignore_errors=True)
    env = child_env(CLASH_TRAFFIC_HOME=data_dir,
                    CLASH_CONTROLLER="http://127.0.0.1:%d" % port)
    requests_seen = []
    outs = []
    for _ in range(rounds):
        argv = launcher + ["watch", "--once", "--interval", "0.5", "--data-dir", data_dir]
        proc = subprocess.run(argv, env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120)
        outs.append({"rc": proc.returncode, "err": proc.stderr.strip(),
                     "out": proc.stdout.strip()})
    return {"rounds": outs, "requests": list(requests_seen)}


def cli(launcher, data_dir, port, args):
    env = child_env(CLASH_TRAFFIC_HOME=data_dir,
                    CLASH_CONTROLLER="http://127.0.0.1:%d" % port)
    proc = subprocess.run(launcher + list(args) + ["--data-dir", data_dir], env=env,
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=120)
    return proc


def db_snapshot(data_dir):
    db = sqlite3.connect(os.path.join(data_dir, "traffic.sqlite3"))
    db.row_factory = sqlite3.Row
    out = {}
    out["connections"] = [
        {k: r[k] for k in r.keys() if k not in ("first", "last", "closed")}
        for r in db.execute("SELECT * FROM connections ORDER BY id")]
    out["segments"] = [
        {k: r[k] for k in r.keys() if k not in ("first", "last", "closed")}
        for r in db.execute("SELECT * FROM segments ORDER BY id,seq")]
    out["buckets"] = [dict(r) for r in db.execute(
        "SELECT * FROM buckets ORDER BY minute,domain,protocol,inbound,process,chain,rule")]
    out["totals"] = dict(db.execute(
        "SELECT COALESCE(SUM(up),0) up, COALESCE(SUM(down),0) down FROM segments").fetchone())
    db.close()
    return out


def status_json(launcher, data_dir, port):
    return json.loads(cli(launcher, data_dir, port, ["status"]).stdout)


def report_tsv(launcher, data_dir, port, group, extra=()):
    text = cli(launcher, data_dir, port, ["report", "--by", group] + list(extra)).stdout
    lines = [line for line in text.splitlines() if line and not line.startswith("本地报表：")]
    return lines


def report_cells(data_dir):
    with open(os.path.join(data_dir, "report.html"), encoding="utf-8") as handle:
        html = handle.read()
    cells = []
    for raw in re.findall(r"<t[dh][^>]*>(.*?)</t[dh]>", html, re.S):
        value = re.sub(r"<[^>]+>", "", raw).strip()
        if DATE_CELL.fullmatch(value) or DURATION_CELL.fullmatch(value) or value == "-":
            continue
        cells.append(value)
    summaries = sorted(re.findall(r"<summary>(.*?)</summary>", html, re.S))
    return cells, summaries, len(html)


def csv_rows(data_dir):
    with open(os.path.join(data_dir, "connections.csv"), encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    normalized = [rows[0]] if rows else []
    for row in rows[1:]:
        normalized.append(["" if index in CSV_NOISY else value for index, value in enumerate(row)])
    return normalized


def compare(report, name, left, right, note=""):
    ok = left == right
    report.append((name, ok, note))
    if not ok:
        print("分歧: %s" % name)
        print("  rust  :", json.dumps(left, ensure_ascii=False)[:400])
        print("  python:", json.dumps(right, ensure_ascii=False)[:400])
    return ok


def mask_status(fields):
    masked = {}
    for key, value in fields.items():
        if key in ("started", "last_sample", "sample_age_seconds"):
            continue
        if key == "report":
            value = os.path.basename(str(value))
        masked[key] = value
    return masked


def normalize_tsv(lines):
    """report --by 排行是纯文本 TSV, 只含名称与格式化字节数, 无墙钟字段。"""
    if not lines:
        return []
    head, rows = lines[0], lines[1:]
    if head.strip() == "":
        raise AssertionError("排行表头为空")
    return [head, [row.split("\t") for row in rows]]


def print_round_diagnostics(case, label):
    """子进程异常退出时把 stdout/stderr 打出来：否则 CI 只剩一个退出码可看。"""
    for index, round_info in enumerate(case["rounds"]):
        if round_info["rc"] == 0 and not round_info["err"]:
            continue
        print("  %s 轮%d rc=%s" % (label, index, round_info["rc"]))
        if round_info["err"]:
            print("    stderr: %s" % round_info["err"][:800])
        if round_info.get("out"):
            print("    stdout: %s" % round_info["out"][:300])


def finish(report):
    failed = [name for name, ok, _ in report if not ok]
    print("\n=== 对拍结果: %d 项, 不一致 %d 项 ===" % (len(report), len(failed)))
    for name, ok, _ in report:
        print("  %s %s" % ("一致  " if ok else "不一致", name))
    if failed:
        print("真实分歧: %s" % ", ".join(failed))
        return 1
    print("Rust 与 Python 实现行为一致")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    parser.add_argument("--rust-bin")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    repo = os.path.abspath(args.repo)
    rust_bin = args.rust_bin or os.path.join(
        repo, "target", "release", "clash-traffic" + (".exe" if os.name == "nt" else ""))
    if not os.path.exists(rust_bin):
        print("找不到 Rust 二进制: %s (先运行 cargo build --release)" % rust_bin)
        return 2
    root = tempfile.mkdtemp(prefix="clash-parity-")
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    rust_launcher, py_launcher = [rust_bin], python_launcher(repo)
    report = []
    try:
        rust_dir, py_dir = os.path.join(root, "rs"), os.path.join(root, "py")
        rust_case = run_case(rust_launcher, rust_dir, port)
        py_case = run_case(py_launcher, py_dir, port)
        print("mock 控制接口 http://127.0.0.1:%d; 数据目录 %s" % (port, root))
        compare(report, "采集轮次退出码", [r["rc"] for r in rust_case["rounds"]],
                [r["rc"] for r in py_case["rounds"]])
        compare(report, "采集轮次 stderr", [r["err"] for r in rust_case["rounds"]],
                [r["err"] for r in py_case["rounds"]])
        compare(report, "控制接口请求路径", rust_case["requests"], py_case["requests"])
        compare(report, "产物文件", sorted(os.listdir(rust_dir)), sorted(os.listdir(py_dir)))
        db_name = "traffic.sqlite3"
        if not all(os.path.exists(os.path.join(d, db_name)) for d in (rust_dir, py_dir)):
            # 采集进程没起来时账本根本不存在，后面每一步都会抛无关异常，先把真正的现场打出来。
            print("账本缺失: rust=%s python=%s" % (
                os.path.exists(os.path.join(rust_dir, db_name)),
                os.path.exists(os.path.join(py_dir, db_name))))
            print_round_diagnostics(rust_case, "rust")
            print_round_diagnostics(py_case, "python")
            return finish(report)
        rust_db, py_db = db_snapshot(rust_dir), db_snapshot(py_dir)
        for table in ("connections", "segments", "buckets", "totals"):
            compare(report, "账本 %s" % table, rust_db[table], py_db[table])
        compare(report, "status JSON", mask_status(status_json(rust_launcher, rust_dir, port)),
                mask_status(status_json(py_launcher, py_dir, port)))
        for group in GROUPS:
            compare(report, "report --by %s" % group,
                    normalize_tsv(report_tsv(rust_launcher, rust_dir, port, group)),
                    normalize_tsv(report_tsv(py_launcher, py_dir, port, group)))
        for group in ("domain", "rule", "process"):
            window = ("--hours", "100000")  # 覆盖全部历史, 结果与墙钟无关, 专门对拍 buckets 路径
            compare(report, "report --by %s --hours" % group,
                    normalize_tsv(report_tsv(rust_launcher, rust_dir, port, group, window)),
                    normalize_tsv(report_tsv(py_launcher, py_dir, port, group, window)))
        rust_cells, rust_sum, rust_bytes = report_cells(rust_dir)
        py_cells, py_sum, py_bytes = report_cells(py_dir)
        compare(report, "report.html 单元格", rust_cells, py_cells)
        detail = "最近 "
        rust_sum = [s for s in rust_sum if not s.startswith(detail)]
        py_sum = [s for s in py_sum if not s.startswith(detail)]
        compare(report, "report.html 分节标题", rust_sum, py_sum)
        for launcher, data_dir in ((rust_launcher, rust_dir), (py_launcher, py_dir)):
            cli(launcher, data_dir, port, ["export"])
        compare(report, "export CSV", csv_rows(rust_dir), csv_rows(py_dir))
        print("report.html 字节数: rust %d / python %d (展示增强, 不比较)" % (rust_bytes, py_bytes))
        for argv in (["watch", "--dry-run"], ["monitor", "--dry-run"],
                     ["report", "--dry-run", "--by", "rule"], ["status", "--dry-run"]):
            label = "dry-run %s" % " ".join(argv)
            rust_text = cli(rust_launcher, rust_dir, port, argv).stdout
            py_text = cli(py_launcher, py_dir, port, argv).stdout
            try:
                rust_out = json.loads(rust_text)
                py_out = json.loads(py_text)
            except json.JSONDecodeError as exc:
                # 解析失败不是「取值不同」而是「根本不是 JSON」：给出命令与原文，别只丢一个 traceback。
                print("%s 输出不是合法 JSON: %s" % (label, exc))
                print("  rust  : %s" % rust_text.strip()[:200])
                print("  python: %s" % py_text.strip()[:200])
                report.append((label, False, ""))
                continue
            rust_out.pop("data_dir"), py_out.pop("data_dir")
            compare(report, label, rust_out, py_out)
    finally:
        server.shutdown()
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)
    return finish(report)


if __name__ == "__main__":
    sys.exit(main())
