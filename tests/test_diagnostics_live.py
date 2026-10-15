import errno
import ipaddress
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import os
import subprocess
import sys
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from remnawatch.api import make_server
from remnawatch.diagnostics import Sources
from remnawatch.health import HostProbe, PressureGuard
from remnawatch.live import InetDiag, LiveConnections, ResyncRequired, decode_diag
from remnawatch.network import NetworkProbe
from remnawatch.store import Store, Policy
from remnawatch.events import AccessParser, UserMap
from remnawatch.collector import Tailer
from test_domains import USERS, LINE

NODE = "59cf9ada-b568-4513-8582-923576b05ef3"


def row(key="1", protocol="tcp", state=1):
    return {"key": key, "protocol": protocol, "kernel_state": state, "local_ip": "2001:db8::1", "local_port": 443,
            "peer_ip": "2001:db8::2", "peer_port": 23456}


class FakeSource:
    supported = True
    def __init__(self):
        self.rows = []
    def collect(self):
        return self.rows


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "net").mkdir()
        self.now = 1
        self.probe = NetworkProbe(self.root, self.root / "sys", clock=lambda: self.now, wall=lambda: 1000 + self.now, origin="host")
    def tearDown(self):
        self.tmp.cleanup()
    def write(self, rx=100, tx=200, name="eth0"):
        (self.root / "net/dev").write_text(f"{name}: {rx} 0 0 0 0 0 0 0 {tx} 0 0 0 0 0 0 0\n")
    def test_first_zero_valid_reset_disappearance_and_error(self):
        self.write()
        first = self.probe.sample()[0][0]
        self.assertEqual(first["error_code"], "first_sample")
        self.assertIsNone(first["rx_bytes_per_second"])
        self.now = 3
        zero = self.probe.sample()[0][0]
        self.assertEqual(zero["rx_bytes_per_second"], 0)
        self.assertEqual(zero["sample_interval_seconds"], 2)
        self.write(10, 20)
        self.now = 5
        reset = self.probe.sample()[0][0]
        self.assertTrue(reset["counter_reset"])
        self.assertEqual(reset["error_code"], "counter_reset")
        self.assertIsNone(reset["tx_bytes_per_second"])
        self.write(name="other")
        gone = next(r for r in self.probe.sample()[0] if r["interface"] == "eth0")
        self.assertFalse(gone["available"])
        self.assertEqual(gone["error_code"], "interface_disappeared")
        (self.root / "net/dev").unlink()
        failed = self.probe.sample()[0][0]
        self.assertFalse(failed["available"])
        self.assertEqual(failed["error_code"], "source_missing")
        self.write(name="other")
        self.assertEqual(self.probe.sample()[0][0]["error_code"], "first_sample")
    def test_inventory_does_not_sum_bridge_or_invent_capacity(self):
        base = self.root / "sys/class/net/br0"
        (base / "brif").mkdir(parents=True)
        (base / "bridge").mkdir()
        (base / "brif/eth0").touch()
        for name, data in (("type", "1"), ("ifindex", "3"), ("operstate", "up")):
            (base / name).write_text(data)
        (self.root / "net/route").write_text("Iface Destination Gateway Flags\nbr0 00000000 00000000 0001\n")
        self.write(name="br0")
        rows, interfaces = self.probe.sample()
        self.assertEqual(len(rows), 1)
        interface = interfaces[0]
        self.assertEqual(interface["kind"], "bridge")
        self.assertEqual(interface["members"], ["eth0"])
        self.assertTrue(interface["default_route"])
        self.assertIsNone(interface["capacity_bits_per_second"])
    def test_malformed_source_and_permission_do_not_fabricate_zero(self):
        self.write()
        self.probe.sample()
        with patch.object(self.probe, "read", side_effect=PermissionError(errno.EACCES, "secret-token")):
            result = self.probe.sample()[0][0]
        self.assertEqual(result["error_code"], "permission_denied")
        self.assertIsNone(result["rx_bytes_per_second"])


class StorageDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / "db.sqlite")
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.probe = SimpleNamespace(snapshot=lambda: {"memory": {"used_percent": 20}})
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
    def disk(self, path):
        return SimpleNamespace(total=1000000000, used=1, free=999999999)
    def guard(self, required=False):
        path = self.logs / "access.log"
        return PressureGuard(self.store, {"log_directories": [str(self.logs)]}, [path], self.probe, self.disk,
                             required_logs=[path] if required else [])
    def test_missing_required_and_disabled_optional_classification(self):
        self.logs.rmdir()
        guard = self.guard(True)
        guard.check()
        alert = guard.status()["alerts"][0]
        self.assertEqual(alert["code"], "log_directory_missing")
        self.assertEqual(alert["severity"], "critical")
        for key in ("component", "error_type", "errno", "required", "impact", "remediation"):
            self.assertIn(key, alert)
        self.assertEqual(guard.status()["legacy_alerts"][0]["code"], "log_storage_unavailable")
        self.store.policy.enabled = False
        guard.check()
        self.assertEqual(guard.status()["alerts"][0]["severity"], "info")
        self.assertFalse(self.logs.exists())
    def test_permission_read_only_cleanup_and_io_are_distinct_and_redacted(self):
        for code, expected in ((errno.EACCES, "log_directory_permission_denied"), (errno.EROFS, "log_directory_read_only"), (errno.EIO, "log_storage_io_error")):
            guard = self.guard()
            def fail(path):
                if path == self.logs:
                    raise OSError(code, "SECRET token and domain")
                return False
            with patch.object(guard, "_low_disk", side_effect=fail):
                guard.check()
            alert = guard.status()["alerts"][0]
            self.assertEqual(alert["code"], expected)
            self.assertNotIn("SECRET", json.dumps(alert))
        guard = self.guard()
        with patch.object(guard, "_low_disk", side_effect=lambda p: p == self.logs), patch.object(guard, "_clean_rotated", side_effect=PermissionError(errno.EACCES, "secret")):
            guard.check()
        self.assertIn("log_cleanup_failed", [a["code"] for a in guard.status()["alerts"]])
        self.assertEqual(self.store.pause_reasons, set())
    def test_capabilities_separate_configuration_health_and_support(self):
        live = LiveConnections(NODE)
        sources = Sources({"domains": {"enabled": False}, "access_logs": [{"path": "secret", "required": False}]}, live=live)
        caps = sources.capabilities()["capabilities"]
        self.assertTrue(caps["connection_events"]["supported"])
        self.assertFalse(caps["connection_events"]["configured"])
        self.assertIsNone(caps["connection_events"]["healthy"])
        self.assertFalse(caps["per_connection_bytes"]["supported"])
        self.assertNotIn("secret", json.dumps(sources.report()))
    def test_uuid_mapping_is_immutable_and_old_backlog_not_reassigned(self):
        with self.assertRaises(ValueError):
            UserMap(USERS, require_uuid=True)
        entries = [dict(USERS[0], user_id=NODE)]
        users = UserMap(entries, require_uuid=True)
        with self.assertRaises(TypeError):
            users.entries[("n1", "in", "alice")] = "changed"
        path = self.root / "access.log"
        path.write_text(LINE)
        parser = AccessParser("n1", users)
        self.store.clock = lambda: parser.parse(LINE, "clock").timestamp + 1
        tail = Tailer(path, parser, self.store, start_at_end=False)
        self.assertEqual(tail.poll(), 1)
        tail.close()
        with path.open("a") as output:
            output.write(LINE)
        changed_id = "ab530bb6-acd2-4c15-8737-9c0b6c9fe088"
        changed = UserMap([dict(entries[0], user_id=changed_id)], require_uuid=True)
        tail = Tailer(path, AccessParser("n1", changed), self.store, start_at_end=False)
        self.assertEqual(tail.poll(), 0)
        self.assertEqual(tail.last_gap_reason, "mapping_changed_backlog_skipped")
        with path.open("a") as output:
            output.write(LINE)
        self.assertEqual(tail.poll(), 1)
        tail.close()
        self.assertEqual(set(r[0] for r in self.store.db.execute("SELECT user_id FROM events")), {NODE, changed_id})


class LiveTests(unittest.TestCase):
    def setUp(self):
        self.now = 10
        self.source = FakeSource()
        self.live = LiveConnections(NODE, {"enabled": True, "fields": ["local_ip", "local_port", "peer_ip", "peer_port"]}, self.source,
                                    clock=lambda: self.now, wall=lambda: 1000 + self.now)
    def test_real_kernel_message_layout_ipv4_ipv6_and_no_cookie(self):
        for family, address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
            payload = bytearray(72)
            payload[0], payload[1] = family, 1
            struct.pack_into("!HH", payload, 4, 443, 1234)
            data = ipaddress.ip_address(address).packed
            payload[8:8 + len(data)] = data
            payload[24:24 + len(data)] = data
            payload[44:52] = bytes.fromhex("0100000002000000")
            result = decode_diag(payload, "tcp")
            self.assertEqual(result["local_ip"], address)
            self.assertEqual(result["local_port"], 443)
            payload[44:52] = b"\xff" * 8
            with self.assertRaises(ValueError):
                decode_diag(payload, "tcp")
    def test_nat_multiplexing_missing_domain_and_unknown_bytes(self):
        self.source.rows = [row("one"), row("two")]
        self.live.poll()
        items = self.live.query("live")["items"]
        self.assertEqual(len(items), 2)
        for record in items:
            self.assertIsNone(record["user_id"])
            self.assertIsNone(record["domain"])
            self.assertIsNone(record["transport_stream_id"])
            self.assertIsNone(record["duration_seconds"])
            self.assertIsNone(record["rx_bytes"])
        first_id = items[0]["connection_id"]
        self.live.poll()
        self.assertEqual(self.live.query("live")["items"][0]["connection_id"], first_id)
        self.assertEqual(self.live.query("live", {"user_id": ["telegram-id-or-ip"]})["total"], 0)
    def test_snapshot_pagination_is_stable_under_churn(self):
        self.source.rows = [row(str(i)) for i in range(10)]
        self.live.poll()
        first = self.live.query("live", {"limit": ["5"]})
        self.source.rows = [row("replacement")]
        self.now += 5
        self.live.poll()
        second = self.live.query("live", {"limit": ["5"], "offset": ["5"], "snapshot_id": [first["snapshot_id"]]})
        ids = [r["connection_id"] for r in first["items"] + second["items"]]
        self.assertEqual(len(set(ids)), 10)
        self.assertEqual(second["sampled_at"], first["sampled_at"])
        with self.assertRaises(ValueError):
            self.live.query("live", {"offset": ["5"]})
    def test_changes_filters_tombstones_repeated_close_and_detail(self):
        self.source.rows = [row("tcp"), row("udp", "udp", 7)]
        self.live.poll()
        baseline = self.live.query("live")
        tcp_id = next(r["connection_id"] for r in baseline["items"] if r["protocol"] == "tcp")
        self.source.rows = [row("tcp", state=7)]
        self.now += 5
        self.live.poll()
        changes = self.live.query("changes", {"cursor": [baseline["next_cursor"]], "limit": ["1"]})
        self.assertTrue(changes["has_more"])
        self.assertTrue(changes["items"][0]["tombstone"])
        self.assertEqual(self.live.query("detail", identity=tcp_id)["items"][0]["state"], "closed")
        cursor = self.live.query("live")["next_cursor"]
        self.live.poll()
        self.assertEqual(self.live.query("changes", {"cursor": [cursor]})["items"][0]["kind"], "updated")
        self.source.rows = []
        self.live.poll()
        removed = self.live.query("detail", identity=tcp_id)["items"][0]
        self.assertEqual(removed["state"], "closed")
        self.assertIsNone(removed["closed_at"])
    def test_failed_dump_resync_and_agent_restart(self):
        self.source.rows = [row()]
        self.live.poll()
        snapshot = self.live.query("live")
        identity = snapshot["items"][0]["connection_id"]
        with patch.object(self.source, "collect", side_effect=PermissionError("secret")):
            self.live.poll()
        self.assertFalse(self.live.status()["healthy"])
        with self.assertRaises(ResyncRequired):
            self.live.query("changes", {"cursor": [snapshot["next_cursor"]]})
        self.live.poll()
        self.assertEqual(self.live.query("live")["items"][0]["connection_id"], identity)
        restarted = LiveConnections(NODE, {"enabled": True}, self.source)
        with self.assertRaises(ResyncRequired):
            restarted.query("changes", {"cursor": [snapshot["next_cursor"]]})
    def test_ring_expiry_snapshot_ttl_limits_and_field_whitelist(self):
        self.live.max_changes = 1
        from collections import deque
        self.live.changes = deque(maxlen=1)
        self.source.rows = [row()]
        self.live.poll()
        snapshot = self.live.query("live")
        self.live.poll()
        self.live.poll()
        with self.assertRaises(ResyncRequired):
            self.live.query("changes", {"cursor": [snapshot["next_cursor"]]})
        self.now += 31
        with self.assertRaises(ResyncRequired):
            self.live.query("live", {"snapshot_id": [snapshot["snapshot_id"]]})
        with self.assertRaises(ValueError):
            self.live.query("live", {"limit": ["501"]})
        private = LiveConnections(NODE, {"enabled": True}, self.source)
        private.poll()
        self.assertIsNone(private.query("live")["items"][0]["peer_ip"])
        with self.assertRaises(ValueError):
            LiveConnections(NODE, {"fields": ["payload"]})
    def test_large_snapshot_and_before_pagination_protocol_filter(self):
        self.source.rows = [row(str(i), "udp" if i % 2 else "tcp") for i in range(10000)]
        self.live.poll()
        snapshot = self.live.query("live", {"protocol": ["udp"], "limit": ["500"]})
        self.assertEqual(snapshot["total"], 5000)
        self.assertTrue(all(r["protocol"] == "udp" for r in snapshot["items"]))
        self.assertEqual(len(self.live.changes), 10000)
    def test_state_filtered_replica_receives_exit_and_stale_sample(self):
        self.source.rows = [row()]
        self.live.poll()
        cursor = self.live.query("live")["next_cursor"]
        self.source.rows = []
        self.live.poll()
        changes = self.live.query("changes", {"state": ["active"], "cursor": [cursor]})
        self.assertEqual(changes["items"][0]["kind"], "removed")
        self.assertEqual(changes["items"][0]["previous_state"], "active")
        self.now += 20
        self.assertEqual(self.live.status()["error_code"], "stale_sample")
    def test_empty_frozen_snapshot_does_not_adopt_future_timestamp(self):
        first = self.live.query("live")
        self.source.rows = [row()]
        self.live.poll()
        frozen = self.live.query("live", {"snapshot_id": [first["snapshot_id"]]})
        self.assertIsNone(frozen["sampled_at"])
        self.assertEqual(frozen["total"], 0)
    def test_invalid_optional_adapter_degrades_instead_of_crashing_host(self):
        disabled = LiveConnections.from_config(NODE, {"enabled": True, "adapter": "unverified_exporter"})
        self.assertFalse(disabled.enabled)
        self.assertTrue(disabled.status()["configured"])
        self.assertFalse(disabled.status()["healthy"])
        self.assertEqual(disabled.status()["error_code"], "invalid_configuration")
        self.assertEqual(disabled.query("live")["total"], 0)


class LiveHTTPTests(unittest.TestCase):
    def test_real_startup_with_unavailable_history_and_invalid_live_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            config = {"host": "127.0.0.1", "port": port, "database": str(root / "missing-parent/history.sqlite"),
                      "management": {"enabled": True}, "live_connections": {"enabled": True, "adapter": "not_a_verified_source"}}
            path = root / "config.json"
            path.write_text(json.dumps(config))
            child = subprocess.Popen([sys.executable, "-m", "remnawatch", "--config", str(path)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     env={**os.environ, "REMNAWATCH_API_TOKEN": "a" * 32})
            def read(endpoint):
                request = Request(f"http://127.0.0.1:{port}" + endpoint, headers={"Authorization": "Bearer " + "a" * 32})
                with urlopen(request, timeout=2) as response:
                    return json.load(response)
            try:
                deadline = time.monotonic() + 8
                while True:
                    try:
                        server = read("/v1/server")
                        break
                    except OSError:
                        if time.monotonic() >= deadline or child.poll() is not None:
                            self.fail("Host API did not survive unavailable history")
                        time.sleep(0.05)
                self.assertGreater(server["server"]["cpu"]["logical_cpus"], 0)
                self.assertFalse(server["management"]["enabled"])
                self.assertFalse(read("/v1/domains")["quality"]["history_storage_available"])
                live = read("/v1/capabilities")["capabilities"]["live_connections"]
                self.assertTrue(live["configured"])
                self.assertFalse(live["healthy"])
                if InetDiag.supported:
                    self.assertTrue(any(n["available"] for n in server["server"]["network"]))
            finally:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()

    def test_authenticated_endpoints_resync_and_slow_client_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Store(Path(tmp) / "db.sqlite", Policy(enabled=False))
            health = PressureGuard(store, {"log_directories": [str(Path(tmp) / "missing")]})
            source = FakeSource()
            live = LiveConnections(NODE, {"enabled": True}, source)
            source.rows = [row()]
            live.poll()
            identity = live.query("live")["items"][0]["connection_id"]
            diagnostics = Sources({"domains": {"enabled": False}}, health, live)
            server = make_server(store, "a" * 32, ("127.0.0.1", 0), health=health, diagnostics=diagnostics, live=live)
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            base = f"http://127.0.0.1:{server.server_port}"
            slow = socket.create_connection(("127.0.0.1", server.server_port))
            slow.sendall(b"GET /v1/server HTTP/1.1\r\n")
            try:
                for path in ("/v1/capabilities", "/v1/diagnostics/sources", "/v1/network/interfaces", "/v1/connections/live", "/v1/connections/changes", "/v1/connections/" + identity):
                    with self.assertRaises(HTTPError) as caught:
                        urlopen(base + path)
                    self.assertEqual(caught.exception.code, 401)
                    with urlopen(Request(base + path, headers={"Authorization": "Bearer " + "a" * 32}), timeout=2) as response:
                        self.assertEqual(response.status, 200)
                        self.assertEqual(response.headers["Cache-Control"], "no-store")
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(base + "/v1/connections/changes?cursor=bad", headers={"Authorization": "Bearer " + "a" * 32}))
                self.assertEqual(caught.exception.code, 409)
                self.assertTrue(json.load(caught.exception)["resync_required"])
            finally:
                slow.close()
                server.shutdown()
                worker.join()
                server.server_close()
                store.close()


@unittest.skipUnless(InetDiag.supported, "Requires a real Linux NETLINK_SOCK_DIAG environment")
class LinuxSocketIntegrationTests(unittest.TestCase):
    def test_controlled_tcp_and_udp_sockets(self):
        with socket.socket() as listener, socket.socket() as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            client.connect(listener.getsockname())
            accepted, _ = listener.accept()
            with accepted:
                client.sendall(b"controlled test")
                accepted.recv(100)
                udp.bind(("127.0.0.1", 0))
                rows = InetDiag().collect()
                self.assertTrue(any(r["protocol"] == "tcp" and r["local_port"] == accepted.getsockname()[1] for r in rows))
                self.assertTrue(any(r["protocol"] == "udp" and r["local_port"] == udp.getsockname()[1] for r in rows))
                tracker = LiveConnections(NODE, {"enabled": True, "fields": ["local_port", "peer_port"]})
                tracker.poll()
                local_port, peer_port = accepted.getsockname()[1], client.getsockname()[1]
                record = next(r for r in tracker.current.values() if r["protocol"] == "tcp" and r["local_port"] == local_port and r["peer_port"] == peer_port)
                identity = record["connection_id"]
                self.assertIsNone(record["rx_bytes"])
                self.assertIsNone(record["duration_seconds"])
                self.assertIsNone(record["user_id"])
                tracker.poll()
                self.assertEqual(tracker.query("detail", identity=identity)["items"][0]["state"], "active")
                accepted.close()
                client.close()
                tracker.poll()
                self.assertIn(tracker.query("detail", identity=identity)["items"][0]["state"], ("unknown", "closed"))
