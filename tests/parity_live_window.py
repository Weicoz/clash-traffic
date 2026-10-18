
"""对拍 monitor 实时窗口（pty 下真实 TTY 渲染）。

用法: python tests/parity_live_window.py [--rust-bin PATH] [--repo PATH]

两个实现各采集 3 轮（2 轮 watch --once 建账本 + 1 轮 monitor --once 渲染实时窗口），
逐单元格比较渲染结果。仅比对内容：终端超长截断（rust 追加 "..."）与数字右对齐属文档化
展示增强，按「前缀相等 + 去空白对齐」处理。非 Unix 平台自动跳过（pty 依赖）。"""
import json, os, re, select, struct, subprocess, sys, threading, time, shutil, tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer

# Windows 的 pty 模块一导入就抛 ImportError，Unix 专属模块必须延迟到平台判断之后。
if os.name == "posix":
    import fcntl, pty, termios

# 指向管道的 stdout 默认是 cp1252，直接 print 中文会 UnicodeEncodeError。
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def conn(cid, host, up, down, rule="DIRECT", chains=None, ctype="HTTP"):
    return {"id": cid, "upload": up, "download": down, "start": "1970-01-01T00:16:40Z",
            "chains": chains or ["DIRECT"], "rule": rule, "rulePayload": "", "metadata": {
                "network": "tcp", "type": ctype, "destinationIP": "1.2.3.4", "destinationPort": "443",
                "sourceIP": "127.0.0.1", "sourcePort": "50000", "host": host, "process": "test",
                "processPath": "/usr/bin/test"}}

def snap(a_up, a_down, b_up, b_down):
    return {"uploadTotal": a_up + b_up + 100, "downloadTotal": a_down + b_down + 200, "connections": [
        conn("a", "alpha.example.com", a_up, a_down, rule="RuleSet", chains=["中转", "DIRECT"]),
        conn("b", "beta.example.com", b_up, b_down, rule="MATCH", chains=["DIRECT"])]}

SNAPS = [snap(1000, 2000, 500, 700), snap(3000, 4000, 1500, 1700), snap(5000, 6000, 2500, 2700)]
counter = [0]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        i = min(counter[0], len(SNAPS) - 1)
        counter[0] += 1
        body = json.dumps(SNAPS[i]).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

def run_pty(argv, env, width=100, height=30, seconds=15):
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
    proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env,
                            start_new_session=True, close_fds=True)
    os.close(slave)
    out = b""
    deadline = time.time() + seconds
    while time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.3)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if proc.poll() is not None and not ready:
            break
    if proc.poll() is None:
        proc.kill()
    proc.wait()
    os.close(master)
    return proc.returncode, out.decode("utf-8", "replace")

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z]")
def clean(text):
    text = ANSI.sub("", text)
    lines = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        line = re.sub(r"Clash Traffic · .* · Ctrl\+C 退出窗口", "Clash Traffic · <date> · Ctrl+C 退出窗口", line)
        line = re.sub(r"最后采样 .*? · 上次错误", "最后采样 <date> · 上次错误", line)
        line = re.sub(r"\s+\d+\.\dm(?=\s*\|?\s*$)", " <dur>m", line)
        lines.append(line)
    return lines

def compare_cells(line_rs, line_py):
    cells_rs = [c.strip() for c in line_rs.split("|")]
    cells_py = [c.strip() for c in line_py.split("|")]
    if len(cells_rs) != len(cells_py):
        return False
    for left, right in zip(cells_rs, cells_py):
        left = re.sub(r"\.\.\.$", "", left)
        if not right.startswith(left):
            return False
    return True


def main():
    if not hasattr(os, "openpty"):
        print("跳过: 当前平台不支持 pty（实时窗口只在交互终端有意义）")
        return 0
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rust_bin = os.path.join(repo, "target", "release", "clash-traffic" + (".exe" if os.name == "nt" else ""))
    for index, value in enumerate(sys.argv):
        if value == "--repo" and index + 1 < len(sys.argv):
            repo = sys.argv[index + 1]
        if value == "--rust-bin" and index + 1 < len(sys.argv):
            rust_bin = sys.argv[index + 1]
    if not os.path.exists(rust_bin):
        print("找不到 Rust 二进制: %s (先运行 cargo build --release)" % rust_bin)
        return 2
    impls = {
        "rs": [rust_bin],
        "py": [sys.executable, "-c", "import sys;sys.path.insert(0,%r);from clash_traffic import cli;cli.run(sys.argv[1:])" % os.path.join(repo, "src")],
    }
    frames = {}
    for name, launcher in impls.items():
        counter[0] = 0
        data_dir = tempfile.mkdtemp(prefix="ct-pty-%s-" % name)
        env = dict(os.environ, CLASH_TRAFFIC_HOME=data_dir, CLASH_CONTROLLER="http://127.0.0.1:%d" % port,
                   COLUMNS="100", LINES="30")
        env.pop("CLASH_SECRET", None)
        for _ in range(2):
            subprocess.run(launcher + ["watch", "--once", "--interval", "0.5", "--data-dir", data_dir],
                           env=env, capture_output=True, text=True, timeout=60)
        rc, out = run_pty(launcher + ["monitor", "--once", "--limit", "5", "--data-dir", data_dir], env, seconds=6)
        frames[name] = clean(out)
        print("=== %s rc=%d 行数=%d" % (name, rc, len(frames[name])))
        for line in frames[name]:
            print("   %r" % line)
        shutil.rmtree(data_dir, ignore_errors=True)
    server.shutdown()
    if len(frames["rs"]) != len(frames["py"]):
        same = False
        print("\n实时窗口渲染: 不一致（rs %d 行 / py %d 行）" % (len(frames["rs"]), len(frames["py"])))
    else:
        same = all(compare_cells(a, b) for a, b in zip(frames["rs"], frames["py"]))
        print("\n实时窗口渲染: %s（内容级比较，忽略文档化的截断与数字对齐差异）"
              % ("一致" if same else "不一致"))
        if not same:
            for i, (a, b) in enumerate(zip(frames["rs"], frames["py"])):
                if not compare_cells(a, b):
                    print("   行%d\n     rs: %r\n     py: %r" % (i, a, b))
    return 0 if same else 1

if __name__ == "__main__":
    sys.exit(main())