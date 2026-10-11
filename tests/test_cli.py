import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from clash_traffic import cli


def connection(
    cid="a",
    up=0,
    down=0,
    chain="Node A",
    rule="RuleSet",
    payload="example-rule",
    start=1000,
):
    return {
        "id": cid,
        "upload": up,
        "download": down,
        "start": "1970-01-01T00:%02d:%02dZ" % divmod(start, 60),
        "metadata": {"host": "example.com", "network": "tcp", "type": "Tun"},
        "chains": [chain],
        "rule": rule,
        "rulePayload": payload,
    }


def snapshot(*items, up=0, down=0):
    return {"connections": list(items), "uploadTotal": up, "downloadTotal": down}


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_root, self.old_db = cli.ROOT, cli.DB
        cli.ROOT = Path(self.tmp.name)
        cli.DB = cli.ROOT / "traffic.sqlite3"
        self.db = cli.connect()

    def tearDown(self):
        self.db.close()
        cli.ROOT, cli.DB = self.old_root, self.old_db
        self.tmp.cleanup()

    def ingest(self, now, *items):
        cli.ingest(self.db, snapshot(*items), now)

    def test_baseline_duplicate_and_restart(self):
        self.ingest(1010, connection(up=100, down=200))
        self.ingest(1011, connection(up=130, down=260))
        self.ingest(1012, connection(up=130, down=260))
        self.db.close()
        self.db = cli.connect()
        self.ingest(1013, connection(up=140, down=270))
        row = cli.groups(self.db, "domain")[0]
        self.assertEqual((row["up"], row["down"]), (40, 70))

    def test_first_snapshot_without_start_is_only_a_baseline(self):
        item = connection(up=100, down=200)
        del item["start"]
        self.ingest(1000, item)
        self.assertEqual(
            tuple(self.db.execute("SELECT up,down FROM connections").fetchone()), (0, 0)
        )

    def test_new_connection_and_inner_separation(self):
        self.ingest(1000)
        app = connection(up=10, down=20, start=1001)
        inner = connection(cid="inner", up=50, down=60, start=1001)
        inner["metadata"]["type"] = "Inner"
        self.ingest(1002, app, inner)
        self.assertEqual(sum(r["up"] for r in cli.groups(self.db, "domain")), 10)
        self.assertEqual(sum(r["up"] for r in cli.groups(self.db, "inbound")), 60)

    def test_same_id_route_change_is_segmented(self):
        self.ingest(1000)
        self.ingest(1002, connection(up=10, down=20, start=1001))
        self.ingest(
            1003,
            connection(
                up=30, down=50, chain="Node B", payload="other-rule", start=1001
            ),
        )
        rows = cli.groups(self.db, "domain")
        self.assertEqual(len(rows), 2)
        by_chain = {row["chain"]: (row["up"], row["down"]) for row in rows}
        self.assertEqual(by_chain, {"Node A": (10, 20), "Node B": (20, 30)})
        self.assertEqual(
            tuple(self.db.execute("SELECT up,down FROM connections").fetchone()),
            (30, 50),
        )
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM segments").fetchone()[0], 2
        )
        buckets = cli.groups(self.db, "domain", hours=time.time() / 3600 + 1)
        self.assertEqual({r["chain"]: (r["up"], r["down"]) for r in buckets}, by_chain)

    def test_same_domain_new_ids_protocol_and_rule_are_separate(self):
        self.ingest(1000)
        a = connection(up=7, down=8, start=1001)
        b = connection(cid="b", up=11, down=12, start=1001)
        b["metadata"]["network"] = "udp"
        c = connection(cid="c", up=13, down=14, start=1001, payload="other-rule")
        self.ingest(1002, a, b, c)
        self.assertEqual(len(cli.groups(self.db, "domain")), 3)

    def test_legacy_trailing_colon_does_not_split_same_rule(self):
        self.ingest(1000)
        a = connection(up=10, down=20, start=1001, rule="Match", payload="")
        b = connection(cid="b", up=30, down=40, start=1001, rule="Match:", payload="")
        self.ingest(1002, a, b)
        rows = cli.groups(self.db, "domain")
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            (rows[0]["rule"], rows[0]["up"], rows[0]["down"]), ("Match", 40, 60)
        )
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM segments").fetchone()[0], 2
        )
        self.assertEqual(
            len(cli.groups(self.db, "domain", hours=time.time() / 3600 + 1)), 1
        )

    def test_close_resume_and_counter_rollback(self):
        self.ingest(1000)
        self.ingest(1002, connection(up=10, down=20, start=1001))
        self.ingest(1003)
        self.ingest(1004, connection(up=15, down=25, start=1001))
        self.ingest(1005, connection(up=3, down=4, start=1001))
        self.assertEqual(
            tuple(self.db.execute("SELECT up,down FROM connections").fetchone()),
            (18, 29),
        )
        self.assertEqual(sum(r["up"] for r in cli.groups(self.db, "domain")), 18)
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM segments").fetchone()[0], 2
        )

    def test_invalid_snapshot_does_not_change_or_close(self):
        self.ingest(1000)
        self.ingest(1002, connection(up=10, down=20, start=1001))
        before = list(self.db.execute("SELECT * FROM connections"))
        for bad in [
            snapshot(connection(), connection()),
            {"connections": "bad"},
            snapshot(connection(up=-1)),
        ]:
            with self.assertRaises(ValueError):
                cli.ingest(self.db, bad, 1003)
            self.assertEqual(
                [tuple(r) for r in self.db.execute("SELECT * FROM connections")],
                [tuple(r) for r in before],
            )

    def test_legacy_migration_keeps_history(self):
        self.ingest(1000)
        self.ingest(1002, connection(up=8, down=9, start=1001))
        self.db.execute("DELETE FROM segments")
        self.db.commit()
        self.db.close()
        self.db = cli.connect()
        self.assertEqual(
            tuple(self.db.execute("SELECT up,down FROM segments").fetchone()), (8, 9)
        )
        self.db.close()
        self.db = cli.connect()
        self.assertEqual(
            self.db.execute("SELECT COUNT(*) FROM segments").fetchone()[0], 1
        )

    def test_missing_optional_fields_and_null_empty_snapshot(self):
        self.ingest(1000)
        c = {
            "id": "legacy",
            "metadata": {"destinationIP": "192.0.2.1"},
            "upload": 4,
            "download": 5,
        }
        self.ingest(1001, c)
        row = cli.groups(self.db, "domain")[0]
        self.assertEqual(row["name"], "192.0.2.1")
        self.assertIn("未提供规则", row["rule"])
        cli.ingest(self.db, {"connections": None}, 1002)
        self.assertEqual(
            self.db.execute("SELECT closed FROM connections").fetchone()[0], 1002
        )

    def test_html_and_terminal_show_rule_chain_protocol(self):
        self.ingest(1000)
        self.ingest(1002, connection(up=8, down=9, start=1001, chain="<script>"))
        path = cli.report(self.db)
        page = path.read_text(encoding="utf-8")
        self.assertIn("<th>命中规则</th><th>实际节点链</th><th>协议</th>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<td><script>", page)
        table = cli.live_table(self.db)
        self.assertIn("example-rule", table)
        self.assertIn("TCP", table)

    def test_single_collector_lock(self):
        first, second = cli.CollectorLock(), cli.CollectorLock()
        first.acquire()
        try:
            self.assertTrue(cli.collector_running())
            with self.assertRaises(BlockingIOError):
                second.acquire()
        finally:
            first.close()
        self.assertFalse(cli.collector_running())

    def test_dry_run_no_network_credential_or_state(self):
        missing = cli.ROOT / "not-created"
        for command in (
            "init",
            "watch",
            "monitor",
            "stop",
            "export",
            "report",
            "status",
        ):
            with (
                patch.object(cli, "snapshot", side_effect=AssertionError("network")),
                patch.object(cli, "settings", side_effect=AssertionError("credential")),
                patch.object(cli, "connect", side_effect=AssertionError("state")),
                redirect_stdout(io.StringIO()),
            ):
                cli.run([command, "--dry-run", "--data-dir", str(missing)])
            self.assertFalse(missing.exists())
        cli.ROOT, cli.DB = Path(self.tmp.name), Path(self.tmp.name) / "traffic.sqlite3"

    def test_monitor_with_collector_only_reads_db(self):
        self.ingest(1000)
        with (
            patch.object(cli, "collector_running", return_value=True),
            patch.object(
                cli, "snapshot", side_effect=AssertionError("second collector")
            ),
            redirect_stdout(io.StringIO()) as output,
        ):
            cli.monitor(1, once=True)
        self.assertIn("命中规则", output.getvalue())

    def test_csv_formula_protection(self):
        self.ingest(1000)
        c = connection(start=1001)
        c["metadata"]["host"] = "=1+1"
        self.ingest(1002, c)
        with redirect_stdout(io.StringIO()):
            cli.run(["export", "--data-dir", str(cli.ROOT)])
        self.assertIn(
            "'=1+1", (cli.ROOT / "connections.csv").read_text(encoding="utf-8")
        )


class TransportTests(unittest.TestCase):
    def test_epoch_time_and_unicode_export_are_cross_platform(self):
        self.assertRegex(cli.date(1000), r"\d{2}-\d{2} \d{2}:\d{2}:\d{2}")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "utf8.txt"
            cli.atomic(path, "中文规则 → 节点")
            self.assertEqual(path.read_bytes(), "中文规则 → 节点".encode("utf-8"))

    def test_endpoint_boundaries(self):
        for url in [
            "http://127.0.0.1:9090",
            "http://[::1]:9090",
            "https://controller.example:443",
        ]:
            self.assertEqual(cli.endpoint_url(url), url)
        for url in [
            "http://remote.example:9090",
            "http://user:pass@localhost:9090",
            "http://localhost:9090?token=secret",
            "http://localhost:9090/other",
            "file:///tmp/secret",
        ]:
            with self.assertRaises(ValueError):
                cli.endpoint_url(url)

    def test_authenticated_get_and_redirect_rejection(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(
                    (self.command, self.path, self.headers.get("Authorization"))
                )
                self.send_response(302 if len(requests) > 1 else 200)
                self.send_header("Content-Type", "application/json")
                if len(requests) > 1:
                    self.send_header("Location", "http://other.invalid/secret")
                self.end_headers()
                self.wfile.write(json.dumps(snapshot()).encode())

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with (
                patch.object(
                    cli,
                    "settings",
                    return_value=(
                        f"http://127.0.0.1:{server.server_port}",
                        "synthetic-test-key",
                    ),
                ),
                patch.dict(
                    os.environ,
                    {
                        "HTTP_PROXY": "http://invalid.example:1",
                        "HTTPS_PROXY": "http://invalid.example:1",
                    },
                ),
            ):
                self.assertEqual(cli.snapshot()["connections"], [])
                with self.assertRaises(RuntimeError):
                    cli.snapshot()
            self.assertEqual(
                requests[0], ("GET", "/connections", "Bearer synthetic-test-key")
            )
            self.assertEqual(len(requests), 2)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == "__main__":
    unittest.main()
