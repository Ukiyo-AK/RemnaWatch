from pathlib import Path
from types import SimpleNamespace
import json
import os
import tempfile
import threading
import time
import unittest
import subprocess
from unittest.mock import Mock, patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from remnawatch.api import make_server
from remnawatch.events import AccessParser, UserMap
from remnawatch.collector import Tailer
from remnawatch.health import HostProbe, PressureGuard
from remnawatch.management import Manager, Conflict, Unsupported, run_command
from remnawatch.store import Store
from test_domains import NOW, LINE, USERS, event


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "server.sqlite", clock=lambda: NOW)
        self.calls = []
        self.settings = {"enabled": True, "compose_file": "/opt/remnanode/docker-compose.yml", "compose_service": "remnanode",
                         "interfaces": ["eth0"], "memory_services": ["remnawatch.service"], "os_kernel_package": "linux-generic"}
        def runner(argv, timeout=600):
            self.calls.append(argv)
            if argv[1:4] == ["-j", "qdisc", "show"]:
                return '[{"root":true,"handle":"0:","kind":"fq_codel"}]'
            return ""
        self.manager = Manager(self.store, self.settings, runner, "Linux")

    def tearDown(self):
        self.manager.close()
        self.store.close()
        self.temp.cleanup()

    def wait_job(self, identity):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            doc = self.manager.jobs(identity)
            if doc["status"] not in ("queued", "running"):
                return doc
            time.sleep(0.01)
        self.fail("job did not finish")

    def fake_probe(self, percent):
        return SimpleNamespace(snapshot=lambda: {"memory": {"used_percent": percent}})

    def healthy_disk(self, path):
        return SimpleNamespace(total=1000000000, used=100000000, free=900000000)

    def full_disk(self, path):
        return SimpleNamespace(total=1000000000, used=999999999, free=1)

    def test_default_plan_never_executes(self):
        result = self.manager.submit({"action": "server_reboot"})
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.calls, [])
        self.assertEqual(result["commands"][0][0], "/usr/sbin/shutdown")

    def test_mutations_require_enable_linux_and_valid_request_id(self):
        self.manager.settings = {"enabled": False}
        with self.assertRaises(PermissionError):
            self.manager.submit({"action": "server_reboot", "dry_run": False, "request_id": "request_01"})
        self.manager.os_name = "Windows"
        with self.assertRaises(Unsupported):
            self.manager.plan("server_reboot")
        self.manager.os_name, self.manager.settings = "Linux", self.settings
        with self.assertRaises(ValueError):
            self.manager.submit({"action": "server_reboot", "dry_run": False})

    def test_node_update_is_scoped_and_no_compose_down(self):
        plan = self.manager.plan("node_update")
        self.assertEqual(plan["commands"][0][-2:], ["pull", "remnanode"])
        self.assertEqual(plan["commands"][1][-4:], ["up", "-d", "--no-deps", "remnanode"])
        self.assertFalse(any("down" in c for c in plan["commands"]))
        self.assertEqual(self.manager.plan("xray_update")["scope"], "node_including_xray")

    def test_standalone_core_restart_and_update_hook(self):
        self.manager.settings = {**self.settings, "xray_service": "xray.service"}
        self.assertEqual(self.manager.plan("xray_restart")["commands"], [["/usr/bin/systemctl", "restart", "xray.service"]])
        with self.assertRaises(Unsupported):
            self.manager.plan("xray_update")
        self.manager.settings["xray_update_hook"] = "/usr/local/libexec/remnawatch-update-xray"
        self.assertEqual(self.manager.plan("xray_update")["commands"][0], ["/usr/local/libexec/remnawatch-update-xray"])

    def test_os_kernel_update_does_not_reboot(self):
        plan = self.manager.plan("os_kernel_update")
        self.assertIn("--only-upgrade", plan["commands"][1])
        self.assertFalse(any("shutdown" in " ".join(c) for c in plan["commands"]))

    def test_job_idempotency_conflict_and_audit(self):
        body = {"action": "node_restart", "dry_run": False, "request_id": "restart_01"}
        self.manager.submit(body)
        result = self.wait_job("restart_01")
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["completed_steps"], 1)
        self.manager.submit(body)
        self.assertEqual(len(self.calls), 1)
        with self.assertRaises(Conflict):
            self.manager.submit({**body, "action": "node_update"})
        self.assertEqual(self.manager.jobs()["total"], 1)

    def test_restart_does_not_replay_pending_actions(self):
        doc = {"id": "pending_01", "status": "running"}
        with self.store.transaction() as db:
            db.execute("INSERT INTO server_jobs VALUES (?,?,?,?,?,?)", ("pending_01", "x", NOW, NOW, "running", json.dumps(doc)))
        restarted = Manager(self.store, self.settings, self.manager.runner, "Linux")
        self.assertEqual(restarted.jobs("pending_01")["status"], "interrupted")
        self.assertEqual(self.calls, [])
        restarted.close()

    def test_failures_and_pressure_block(self):
        self.manager.runner = Mock(side_effect=RuntimeError("password=never-expose"))
        self.manager.submit({"action": "node_restart", "dry_run": False, "request_id": "failed_001"})
        result = self.wait_job("failed_001")
        self.assertEqual(result["status"], "failed")
        self.assertNotIn("password", result["error"])
        self.store.pause_reasons = {"memory_pressure"}
        with self.assertRaises(Conflict):
            self.manager.submit({"action": "node_restart", "dry_run": False, "request_id": "blocked_01"})

    def test_validation_rejects_shell_and_noninteger_rates(self):
        for params in ({"interface": "eth0;reboot", "tx_mbps": 10, "rx_mbps": 10}, {"interface": "eth0", "tx_mbps": True, "rx_mbps": 10}, {"interface": "eth0", "tx_mbps": 0, "rx_mbps": 10}, {"interface": "eth0", "tx_mbps": 10, "rx_mbps": 10, "command": "evil"}):
            with self.assertRaises(ValueError):
                self.manager.plan("traffic_limits", params)
        with self.assertRaises(ValueError):
            self.manager.submit({"action": "node_restart", "params": []})

    def test_tx_rx_apply_rollback_on_failure(self):
        plan = self.manager.plan("traffic_limits", {"interface": "eth0", "tx_mbps": 50, "rx_mbps": 20})
        self.assertIn("50mbit", plan["commands"][0])
        self.assertIn("20mbit", plan["commands"][2])
        self.assertIn("drop", plan["commands"][2])
        def fail_filter(argv, timeout):
            self.calls.append(argv)
            if "-j" in argv:
                return '[{"root":true,"handle":"0:","kind":"fq_codel"}]'
            if argv[1:3] == ["filter", "add"]:
                raise RuntimeError("filter failed")
            return ""
        self.manager.runner = fail_filter
        self.manager.submit({"action": "traffic_limits", "params": plan["params"], "dry_run": False, "request_id": "traffic_01"})
        result = self.wait_job("traffic_01")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["rollback"], "attempted")
        self.assertEqual(sum("del" in c for c in self.calls), 2)
        self.assertIsNone(self.store.state("tc_owned:eth0"))

    def test_foreign_qdisc_is_preserved(self):
        self.manager.runner = Mock(return_value='[{"root":true,"handle":"1:","kind":"htb"}]')
        self.manager.submit({"action": "traffic_limits", "params": {"interface": "eth0", "tx_mbps": 10, "rx_mbps": 10}, "dry_run": False, "request_id": "foreign_01"})
        self.assertEqual(self.wait_job("foreign_01")["status"], "failed")
        self.assertEqual(self.manager.runner.call_count, 1)

    def test_apply_and_clear_owned_traffic_rules(self):
        params = {"interface": "eth0", "tx_mbps": 50, "rx_mbps": 20}
        self.manager.submit({"action": "traffic_limits", "params": params, "dry_run": False, "request_id": "applied_01"})
        self.assertEqual(self.wait_job("applied_01")["status"], "succeeded")
        self.assertEqual(json.loads(self.store.state("tc_owned:eth0")), params)
        def managed(argv, timeout):
            self.calls.append(argv)
            if argv[1:4] == ["-j", "qdisc", "show"]:
                return '[{"root":true,"handle":"7a10:","kind":"tbf"},{"handle":"ffff:","kind":"ingress"}]'
            if argv[1:4] == ["-j", "filter", "show"]:
                return '[{"pref":49152,"kind":"matchall"}]'
            return ""
        self.manager.runner = managed
        self.manager.submit({"action": "traffic_clear", "params": {"interface": "eth0"}, "dry_run": False, "request_id": "clear_001"})
        self.assertEqual(self.wait_job("clear_001")["status"], "succeeded")
        self.assertIsNone(self.store.state("tc_owned:eth0"))

    def test_reboot_schedule_blocks_overlapping_updates(self):
        self.manager.submit({"action": "server_reboot", "dry_run": False, "request_id": "reboot_001"})
        result = self.wait_job("reboot_001")
        self.assertEqual(result["status"], "succeeded")
        self.assertIn("scheduled", result["result"])
        with self.assertRaises(Conflict):
            self.manager.submit({"action": "node_update", "dry_run": False, "request_id": "after_reboot"})

    def test_real_runner_uses_argv_without_shell_and_times_out_process_group(self):
        child = Mock(stdout=None)
        child.wait.return_value = 0
        with patch("remnawatch.management.subprocess.Popen", return_value=child) as popen:
            self.assertEqual(run_command(["/usr/bin/systemctl", "restart", "xray.service"], 1), "")
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        child.wait.side_effect = [subprocess.TimeoutExpired("fake", 1), 0]
        with patch("remnawatch.management.subprocess.Popen", return_value=child), patch("remnawatch.management.os.killpg", create=True) as kill, patch("remnawatch.management.signal.SIGKILL", 9, create=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                run_command(["/usr/bin/systemctl", "restart", "xray.service"], 1)
            kill.assert_called_once()

    def test_oom_protection_does_not_disable_oom_killer(self):
        plan = self.manager.plan("oom_protection", {"service": "remnawatch.service", "memory_high_mb": 256, "memory_max_mb": 384})
        self.assertEqual(plan["commands"][0][-1], "vm.panic_on_oom=0")
        self.assertIn("MemoryHigh=256M", plan["commands"][1])
        for p in ({"service": "ssh.service", "memory_high_mb": 256, "memory_max_mb": 384}, {"service": "remnawatch.service", "memory_high_mb": 512, "memory_max_mb": 384}):
            with self.assertRaises(ValueError):
                self.manager.plan("oom_protection", p)

    def test_memory_guard_hysteresis_and_resume(self):
        guard = PressureGuard(self.store, probe=self.fake_probe(95), disk_usage=self.healthy_disk)
        guard.check()
        self.assertEqual(self.store.pause_reasons, {"memory_pressure"})
        self.assertEqual(self.store.ingest([event()]), 0)
        guard.probe = self.fake_probe(88)
        guard.check()
        self.assertTrue(guard.status()["collection_paused"])
        guard.probe = self.fake_probe(80)
        guard.check()
        self.assertFalse(guard.status()["collection_paused"])
        self.assertEqual(self.store.ingest([event()]), 1)
        self.assertEqual(self.calls, [])

    def test_pressure_preserves_log_cursor(self):
        path = self.root / "access.log"
        path.write_text(LINE)
        parser = AccessParser("n1", UserMap(USERS))
        self.store.clock = lambda: parser.parse(LINE, "clock").timestamp + 1
        tail = Tailer(path, parser, self.store, start_at_end=False)
        self.store.pause_reasons = {"memory_pressure"}
        self.assertEqual(tail.poll(), 0)
        self.assertIsNone(self.store.state(tail.key))
        self.store.pause_reasons.clear()
        self.assertEqual(tail.poll(), 1)
        tail.close()

    def test_emergency_cleanup_preserves_recent_and_dedup(self):
        self.store.ingest([event(1, timestamp=NOW - 2 * 86400), event(2)])
        result = self.store.emergency_prune()
        self.assertEqual(result["removed"]["events"], 1)
        self.assertEqual(result["removed"]["aggregates"], 1)
        self.assertEqual(self.store.ingest([event(1, timestamp=NOW - 2 * 86400)]), 0)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM events").fetchone()[0], 1)
        quality = self.store.query(start=NOW - 3 * 86400, end=NOW)["quality"]
        self.assertTrue(quality["emergency_retention"]["early_deletion"])

    def test_log_cleanup_only_old_rotations_in_allowlisted_root(self):
        logs = self.root / "logs"
        logs.mkdir()
        for name in ("access.log", "access.log.1", "error.log.2026-10-01.gz", "secret.txt", "access.log.2"):
            p = logs / name
            p.write_text("keep-or-delete")
            os.utime(p, (NOW - 7200, NOW - 7200))
        os.utime(logs / "access.log.2", (NOW, NOW))
        guard = PressureGuard(self.store, {"log_directories": [str(logs)], "delete_rotated_logs": True},
                              active_logs=[logs / "access.log"], probe=self.fake_probe(20), disk_usage=self.full_disk)
        guard.check()
        self.assertTrue((logs / "access.log").exists())
        self.assertTrue((logs / "secret.txt").exists())
        self.assertTrue((logs / "access.log.2").exists())
        self.assertFalse((logs / "access.log.1").exists())
        self.assertFalse((logs / "error.log.2026-10-01.gz").exists())
        self.assertIn("disk_pressure", self.store.pause_reasons)
        self.assertTrue(guard.status()["alerts"])

    def test_disk_full_cleanup_failure_does_not_crash_guard(self):
        guard = PressureGuard(self.store, probe=self.fake_probe(20), disk_usage=self.full_disk)
        with patch.object(self.store, "emergency_prune", side_effect=OSError("disk full")):
            guard.check()
        self.assertIn("history_cleanup_failed", [a["code"] for a in guard.status()["alerts"]])

    def test_host_telemetry_cpu_memory_network_rates(self):
        proc = self.root / "proc"
        (proc / "net").mkdir(parents=True)
        (proc / "sys/vm").mkdir(parents=True)
        (proc / "sys/vm/panic_on_oom").write_text("0")
        (proc / "meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 500 kB\nSwapFree: 400 kB\n")
        (proc / "stat").write_text("cpu 10 0 10 80 0 0 0 0 0 0\n")
        (proc / "cpuinfo").write_text("model name : Test CPU\n")
        (proc / "uptime").write_text("100.5 10.0")
        (proc / "net/dev").write_text("eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n")
        ticks = iter([1, 3])
        probe = HostProbe(proc, [self.root], clock=lambda: next(ticks), sys=self.root / "sys")
        first = probe.snapshot()
        self.assertEqual(first["memory"]["used_percent"], 75)
        self.assertIsNone(first["cpu"]["usage_percent"])
        (proc / "stat").write_text("cpu 20 0 20 100 0 0 0 0 0 0\n")
        (proc / "net/dev").write_text("eth0: 300 0 0 0 0 0 0 0 600 0 0 0 0 0 0 0\n")
        second = probe.snapshot()
        self.assertEqual(second["cpu"]["usage_percent"], 50)
        self.assertEqual(second["network"][0]["rx_bytes_per_second"], 100)
        self.assertEqual(second["network"][0]["tx_bytes_per_second"], 200)
        self.assertEqual(second["oom"]["panic_on_oom"], "0")

    def test_missing_proc_reports_unknown_not_fabricated(self):
        probe = HostProbe(self.root / "absent")
        result = probe.snapshot()
        self.assertIsNone(result["memory"]["total_bytes"])
        self.assertIsNone(result["cpu"]["usage_percent"])

    def test_http_server_routes_auth_dryrun_and_errors(self):
        guard = PressureGuard(self.store, probe=HostProbe(self.root / "absent"), disk_usage=self.healthy_disk)
        server = make_server(self.store, "a" * 32, ("127.0.0.1", 0), self.manager, guard)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        auth = {"Authorization": "Bearer " + "a" * 32, "Content-Type": "application/json"}
        try:
            for path in ("/v1/server", "/v1/server/jobs", "/v1/server/jobs/missing"):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(base + path)
                self.assertEqual(caught.exception.code, 401)
            with self.assertRaises(HTTPError) as caught:
                urlopen(Request(base + "/v1/server/actions", data=b'{}', headers={"Content-Type": "application/json"}))
            self.assertEqual(caught.exception.code, 401)
            with urlopen(Request(base + "/v1/server", headers=auth)) as response:
                self.assertIn("management", json.load(response))
            with urlopen(Request(base + "/v1/server/actions", data=b'{"action":"server_reboot"}', headers=auth)) as response:
                self.assertEqual(response.status, 200)
                self.assertTrue(json.load(response)["dry_run"])
            self.assertEqual(self.calls, [])
            for raw in (b'{"action":"server_reboot","action":"node_update"}', b'{"action":"node_restart","dry_run":"false"}', b'[]'):
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(base + "/v1/server/actions", data=raw, headers=auth))
                self.assertEqual(caught.exception.code, 400)
            self.manager.settings = {**self.settings, "enabled": False}
            with self.assertRaises(HTTPError) as caught:
                urlopen(Request(base + "/v1/server/actions", data=b'{"action":"server_reboot","dry_run":false,"request_id":"reboot_001"}', headers=auth))
            self.assertEqual(caught.exception.code, 403)
            self.manager.settings = self.settings
            body = b'{"action":"node_restart","dry_run":false,"request_id":"http_job01"}'
            with urlopen(Request(base + "/v1/server/actions", data=body, headers=auth)) as response:
                self.assertEqual(response.status, 202)
                job = json.load(response)
                self.assertEqual(job["id"], "http_job01")
            self.assertEqual(self.wait_job("http_job01")["status"], "succeeded")
            with urlopen(Request(base + "/v1/server/jobs/http_job01", headers=auth)) as response:
                self.assertEqual(json.load(response)["status"], "succeeded")
        finally:
            server.shutdown()
            thread.join()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
