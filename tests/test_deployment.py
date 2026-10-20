"""Deployment, provenance, release and overload regressions; no host mutation."""
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from remnawatch.auth import generate_node_credentials
from remnawatch.api import make_server
from remnawatch.collector import Tailer
from remnawatch.diagnostics import Sources
from remnawatch.events import AccessParser, UserMap
from remnawatch.install import Deployment, MARKER, prepare_release, api_listener
from remnawatch.preflight import CheckError, docker_source, logger_layout, supported
from remnawatch.probe import check_probe, validate
from remnawatch.probe import make_probe
from remnawatch.releases import compare, parse, status, validate_policy
from remnawatch.runtime import discover_versions, identity
from remnawatch.store import Store
from remnawatch.update import acquire, extract, validate_url, public_connection
from remnawatch.user_metrics import SustainedLoad, UserMetrics, limit_status
from remnawatch.transport import HistoryClient, HistoryTransportError, classify
from test_domains import LINE, USERS
from types import SimpleNamespace

USER = "c784d8cc-ce78-4cca-9a66-d5b2ae509cc9"
OTHER = "25854075-e8f9-4465-a3cc-d231b6bad76e"
NODE = "8113f1e4-4854-4353-951e-8bd5e17386bf"
PROBE = {"domain": "node.example.com", "certificate": "cert", "private_key": "key"}


class PlatformTests(unittest.TestCase):
    def test_firewall_optional_and_compose_variants_are_read_only(self):
        from remnawatch.preflight import host_report
        for firewall in ("ufw_active", "ufw_inactive", "absent", "firewalld", "nftables"):
            for compose in ("v1", "v2", "absent"):
                with self.subTest(firewall=firewall, compose=compose):
                    calls = []
                    tools = {"python3", "systemctl", "ss", "docker"}
                    tools |= {"ufw"} if firewall.startswith("ufw") else {"firewall-cmd"} if firewall == "firewalld" else {"nft"} if firewall == "nftables" else set()
                    def runner(args):
                        calls.append(args)
                        if args[0] == "timedatectl":
                            return "yes"
                        if args[0] == "ufw":
                            return "Status: active" if firewall == "ufw_active" else "Status: inactive"
                        if args[:2] == ["docker", "compose"] and compose == "v2":
                            return "2.27.0"
                        if args[0] == "docker-compose" and compose == "v1":
                            return "1.29.2"
                        raise CheckError("command_unavailable", "fixture")
                    def read(path, *args, **kwargs):
                        return 'ID=ubuntu\nVERSION_ID="22.04"' if path.as_posix() == "/etc/os-release" else "systemd\n"
                    with patch("remnawatch.preflight.run", side_effect=runner), patch("pathlib.Path.read_text", read), patch("pathlib.Path.is_dir", return_value=True), patch("platform.machine", return_value="x86_64"), patch("shutil.which", side_effect=lambda name: "/usr/bin/" + name if name in tools else None), patch("shutil.disk_usage", return_value=SimpleNamespace(free=10**9)), patch("os.geteuid", return_value=0, create=True):
                        result = host_report()
                    self.assertTrue(result["supported"])
                    self.assertFalse(result["checks"]["firewall"]["automatic_changes"])
                    self.assertEqual(result["checks"]["compose"]["version"], None if compose == "absent" else "1.29.2" if compose == "v1" else "2.27.0")
                    self.assertTrue(all("enable" not in args and "insert" not in args and "restart" not in args for args in calls))
    def test_all_fourteen_target_platforms(self):
        for os_id, version in (("debian", "11"), ("debian", "12"), ("debian", "13"),
                               ("ubuntu", "20.04"), ("ubuntu", "22.04"), ("ubuntu", "24.04"), ("ubuntu", "26.04")):
            for arch in ("x86_64", "aarch64"):
                with self.subTest(os=os_id, version=version, arch=arch):
                    supported(os_id, version, arch, True, (3, 8))

    def test_unsupported_platforms_refused(self):
        for args in (("ubuntu", "18.04", "x86_64", True), ("debian", "14", "x86_64", True),
                     ("debian", "12", "armv7l", True), ("ubuntu", "24.04", "x86_64", False)):
            with self.subTest(args=args), self.assertRaises(CheckError):
                supported(*args)
        with self.assertRaises(CheckError):
            supported("debian", "12", "x86_64", True, (3, 7))

    def test_both_loggers_and_unknown_without_fallback_on_permission(self):
        self.assertEqual(logger_layout(lambda path: "exec /command/s6-log -b n0 s10485760 /var/log/xray")["logger"], "s6")
        self.assertEqual(logger_layout(lambda path: "[program:xray]\nstdout_logfile=/var/log/supervisor/xray.out.log\n" if path.endswith("conf") else None)["logger"], "supervisor")
        with self.assertRaises(CheckError):
            logger_layout(lambda _: None)
        def denied(_):
            raise CheckError("permission_denied", "safe hint")
        with self.assertRaisesRegex(CheckError, "permission_denied"):
            logger_layout(denied)

    def test_container_not_running_is_not_an_unknown_logger(self):
        def runner(args):
            return json.dumps([{"State": {"Running": False}}])
        with self.assertRaisesRegex(CheckError, "container_stopped"):
            docker_source("custom-node", runner)

    def test_ambiguous_container_and_command_injection_refused(self):
        with self.assertRaisesRegex(CheckError, "container_ambiguous"):
            docker_source(None, lambda _: "a\tremnawave/node:latest\nb\tremnawave/node:2.7.0")
        with self.assertRaisesRegex(CheckError, "container_invalid"):
            docker_source("node;id", lambda _: self.fail("must not execute"))

    def test_mounted_log_provenance_and_missing_log(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "current"
            path.write_text("existing log\n")
            info = {"Image": "sha256:" + "a" * 64, "State": {"Running": True},
                    "Mounts": [{"Destination": "/var/log/xray", "Source": directory}]}
            def runner(args):
                if args[1] == "inspect":
                    return json.dumps([info])
                if args[-1] == "/etc/s6-overlay/s6-rc.d/xray-log/run":
                    return "exec /command/s6-log -b n0 /var/log/xray"
                if args[-1] == "version":
                    return "Xray 26.7.28 (Xray)"
                return '["3.2.0"]'
            result = docker_source("custom-node", runner)
            self.assertEqual(result["container"], "custom-node")
            self.assertEqual(result["remnanode_version"], "3.2.0")
            self.assertFalse(result["growth_verified"])
            path.unlink()
            with self.assertRaisesRegex(CheckError, "source_missing"):
                docker_source("custom-node", runner)
            info["Mounts"] = []
            with self.assertRaisesRegex(CheckError, "log_not_mounted"):
                docker_source("custom-node", runner)


class VersionTests(unittest.TestCase):
    def test_identity_and_unknown_runtime_never_latest(self):
        value = identity()
        parse(value["agent_version"])
        self.assertIsNone(value["remnanode_version"])
        self.assertIsNone(discover_versions("bad;command")["xray_version"])
        for output in ('["latest"]', '["2.7.0","3.4.2"]', "private config", None):
            result = discover_versions("node", lambda _: output)
            self.assertEqual(result, {"remnanode_version": None, "xray_version": None})

    def test_runtime_both_versions(self):
        result = discover_versions("node", lambda args: "Xray 26.7.28 (go)" if args[-1] == "version" else '["0.0.0","3.2.0"]')
        self.assertEqual(result, {"remnanode_version": "3.2.0", "xray_version": "26.7.28"})

    def test_semver_official_precedence(self):
        versions = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0"]
        for left, right in zip(versions, versions[1:]):
            self.assertLess(compare(left, right), 0)
            self.assertGreater(compare(right, left), 0)
        self.assertEqual(compare("1.0.0+build.1", "1.0.0+build.2"), 0)
        for value in ("latest", "1.10", "01.1.0", "1.0.0-01", "1.0.0-x..y", "1.0.0+", "v1.0.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse(value)

    def test_policy_and_stale_or_custom_never_current(self):
        policy = {"minimum": "1.0.0", "recommended": "1.10.0"}
        for reported, expected in ((None, "not_reported"), ("latest", "uncomparable"),
                                   ("0.9.0", "below_minimum"), ("1.9.0", "update_available"),
                                   ("1.10.0", "current"), ("0.1.0-dev+commit", "uncomparable")):
            self.assertEqual(status(reported, policy, 990, now=1000), expected)
        self.assertEqual(status("1.10.0", policy, 0, now=1000), "stale_heartbeat")
        self.assertEqual(status("1.10.0", None, 990, now=1000), "policy_unavailable")
        with self.assertRaises(ValueError):
            validate_policy({"minimum": "2.0.0", "recommended": "1.0.0"})


def archive(version="0.2.0", extra=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as target:
        for name, data in {"repo/remnawatch/__main__.py": b"", "repo/remnawatch/version.py": ('VERSION = "' + version + '"\n').encode(), **(extra or {})}.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            target.addfile(member, io.BytesIO(data))
    return output.getvalue()


class ReleaseTests(unittest.TestCase):
    def test_expansion_budget_also_covers_ignored_archive_members(self):
        data = archive(extra={"repo/ignored.bin": b"x" * 4096})
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.update.MAX_EXPANDED", 2048):
            with self.assertRaisesRegex(ValueError, "expansion_limit"):
                extract(data, Path(directory) / "result", "0.2.0")
            self.assertFalse((Path(directory) / "result").exists())
    def test_release_cache_idempotency_and_modified_source_refused(self):
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.install.trusted"):
            def fetch(url, digest, destination, version):
                extract(archive(), destination, version)
            def build(path):
                target = Path(path) / "bin"; target.mkdir(parents=True)
                (target / "python3").write_text("fixture")
            with patch("remnawatch.install.acquire", side_effect=fetch) as downloaded, patch("venv.EnvBuilder.create", side_effect=build):
                release = prepare_release(Path(directory), "https://example.com/release", "a" * 64, "0.2.0", lambda _: "")
                self.assertEqual(prepare_release(Path(directory), "https://example.com/release", "a" * 64, "0.2.0"), release)
                self.assertEqual(downloaded.call_count, 1)
                (release / "remnawatch/version.py").write_text('VERSION = "0.0.0"')
                with self.assertRaisesRegex(CheckError, "release_modified"):
                    prepare_release(Path(directory), "https://example.com/release", "a" * 64, "0.2.0")

    def test_failed_download_cleans_only_own_staging(self):
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.install.trusted"), patch("remnawatch.install.acquire", side_effect=ValueError("digest_mismatch")):
            keep = Path(directory) / "releases/working"; keep.mkdir(parents=True)
            with self.assertRaises(ValueError):
                prepare_release(Path(directory), "https://example.com/release", "a" * 64, "0.2.0")
            self.assertEqual(list((Path(directory) / "releases").iterdir()), [keep])
    def test_extract_only_verified_package_and_check_version(self):
        with tempfile.TemporaryDirectory() as directory:
            extract(archive(extra={"repo/secrets.env": b"never extract"}), Path(directory) / "good", "0.2.0")
            self.assertTrue((Path(directory) / "good/remnawatch/version.py").is_file())
            self.assertFalse((Path(directory) / "good/secrets.env").exists())
            with self.assertRaisesRegex(ValueError, "version_mismatch"):
                extract(archive(), Path(directory) / "bad", "0.3.0")

    def test_path_traversal_and_symlinks_refused_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ("../outside", "/etc/owned", "repo/../outside", "repo\\outside"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    extract(archive(extra={name: b"bad"}), Path(directory) / "result", "0.2.0")
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w:gz") as target:
                member = tarfile.TarInfo("repo/link")
                member.type, member.linkname = tarfile.SYMTYPE, "/etc"
                target.addfile(member)
            with self.assertRaises(ValueError):
                extract(output.getvalue(), Path(directory) / "result", "0.2.0")
            self.assertFalse((Path(directory) / "result").exists())

    def test_digest_mismatch_unavailable_and_valid_download(self):
        payload = archive()
        class Reply(io.BytesIO):
            status = 200
        class Opener:
            def open(self, url, timeout):
                return Reply(payload)
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.update.validate_url"):
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                acquire("https://example.com/release", "0" * 64, Path(directory) / "bad", "0.2.0", Opener())
            acquire("https://example.com/release", hashlib.sha256(payload).hexdigest(), Path(directory) / "good", "0.2.0", Opener())
            class Down:
                def open(self, *args, **kwargs):
                    raise urllib.error.URLError("unavailable")
            with self.assertRaises(urllib.error.URLError):
                acquire("https://example.com/release", "0" * 64, Path(directory) / "bad", "0.2.0", Down())

    def test_https_credentials_queries_lan_and_rebinding_refused(self):
        for url in ("http://example.com/release", "https://secret@example.com/a", "https://example.com/a?token=secret", "https://example.com/a#x"):
            with self.assertRaises(ValueError):
                validate_url(url)
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("socket.getaddrinfo", return_value=private):
            with self.assertRaises(ValueError):
                validate_url("https://example.com/a")
            with self.assertRaises(ValueError):
                public_connection(("example.com", 443))


class DeploymentTests(unittest.TestCase):
    def test_occupied_api_port_only_accepts_verified_agent_pid(self):
        self.assertTrue(api_listener({"port": 18443}, lambda _: "")["ok"])
        def runner(args):
            return 'LISTEN users:(("python3",pid=123,fd=4))' if args[0] == "ss" else "123"
        self.assertTrue(api_listener({"port": 18443}, runner)["occupied_by_agent"])
        with self.assertRaisesRegex(CheckError, "api_port_occupied"):
            api_listener({"port": 18443}, lambda args: runner(args) if args[0] == "ss" else "456")
        with self.assertRaisesRegex(CheckError, "invalid_api_port"):
            api_listener({"port": True}, runner)
    @unittest.skipUnless(os.name == "posix", "Atomic directory symlink replacement requires POSIX; run on Linux")
    def test_activation_update_health_and_rollback_preserve_operator_config(self):
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.install.trusted"):
            root = Path(directory)
            units, config_dir = root / "units", root / "config"
            units.mkdir(); config_dir.mkdir()
            first, second = root / "releases/first", root / "releases/second"
            first.mkdir(parents=True); second.mkdir()
            calls = []
            def runner(args):
                calls.append(args)
                return "active" if "is-active" in args else "enabled" if "is-enabled" in args else ""
            deployment = Deployment(root, config_dir, units, runner)
            config = {"auth": generate_node_credentials(NODE), "database": str(root / "existing.sqlite"), "custom": "operator setting"}
            health = lambda config, version: None
            deployment.activate(first, config, "0.2.0", health)
            before = (config_dir / "config.json").read_text()
            def broken(config, version):
                raise CheckError("agent_health_failed", "test")
            with self.assertRaises(CheckError):
                deployment.activate(second, {**config, "custom": "new"}, "0.3.0", broken)
            self.assertEqual((root / "current").resolve(), first.resolve())
            self.assertEqual((config_dir / "config.json").read_text(), before)
            self.assertEqual(deployment.results["agent"]["status"], "rolled_back")
            self.assertFalse(any("docker" in cmd or "ufw" in cmd or "caddy" in cmd for cmd in calls))
            # Rerun succeeds without duplicate unit or losing custom configuration.
            deployment.activate(second, config, "0.3.0", health)
            self.assertEqual((root / "current").resolve(), second.resolve())
            self.assertEqual(len(list(units.iterdir())), 1)
            before_commands = len(calls)
            deployment.activate(second, config, "0.3.0", health)
            self.assertEqual(deployment.results["agent"]["status"], "unchanged")
            self.assertEqual(len(calls), before_commands)

    def test_unmanaged_service_and_relative_db_refused_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.install.trusted"):
            root = Path(directory); units = root / "units"; units.mkdir()
            service = units / "remnawatch.service"; service.write_text("operator service")
            deployment = Deployment(root, root / "config", units, lambda _: self.fail("no commands before refusal"))
            config = {"auth": generate_node_credentials(NODE), "database": str(root / "db.sqlite")}
            with self.assertRaisesRegex(CheckError, "unmanaged_unit"):
                deployment.activate(root, config, "0.2.0")
            with self.assertRaisesRegex(CheckError, "relative_database_path"):
                deployment.activate(root, {**config, "database": "relative.sqlite"}, "0.2.0")
            self.assertEqual(service.read_text(), "operator service")


class MetricsTests(unittest.TestCase):
    def setup_metric(self, extra=None):
        entries = [{"node_id": NODE, "inbound": "in", "email": "42", "user_id": USER},
                   {"node_id": NODE, "inbound": "in2", "email": "43", "user_id": USER}, *(extra or [])]
        self.now, self.payload = 1000, {"stat": []}
        metric = UserMetrics(NODE, UserMap(entries, True), {"enabled": True, "mapping_verified": True, "container": "custom-node", "server": "127.0.0.1:10085"},
                             runner=lambda args: json.dumps(self.payload), clock=lambda: self.now, monotonic=lambda: self.now)
        return metric

    def counters(self, first, second):
        self.payload = {"stat": [{"name": f"user>>>{email}>>>traffic>>>{direction}", "value": str(value)}
                                for email, value in (("42", first), ("43", second)) for direction in ("uplink", "downlink")]}

    def test_parallel_totals_first_sample_reset_gap_missing_not_zero(self):
        metrics = self.setup_metric()
        self.counters(100, 100); metrics.sample()
        self.assertFalse(metrics.get(USER)["available"])
        self.now += 5; self.counters(200, 300); metrics.sample()
        self.assertEqual(metrics.get(USER)["rx_bytes_per_second"], 60)
        # One counter resets while the other grows: aggregate must not hide reset.
        self.now += 5; self.counters(10, 1000); metrics.sample()
        self.assertIsNone(metrics.get(USER)["rx_bytes_per_second"])
        self.now += 120; self.counters(100, 1100); metrics.sample()
        self.assertFalse(metrics.get(USER)["available"])
        self.payload = {"stat": []}; metrics.sample()
        self.assertIsNone(metrics.get(USER)["rx_bytes_per_second"])

    def test_ambiguous_email_not_attributed_to_any_uuid(self):
        metrics = self.setup_metric([{"node_id": NODE, "inbound": "other", "email": "42", "user_id": OTHER}])
        self.counters(100, 100); metrics.sample()
        self.now += 5; self.counters(1000, 150); metrics.sample()
        self.assertEqual(metrics.get(USER)["rx_bytes_per_second"], 10)
        self.assertFalse(metrics.get(OTHER)["available"])

    def test_unverified_nodewide_mapping_never_enables_email_attribution(self):
        metrics = self.setup_metric()
        metrics.mapping_verified = False
        metrics.runner = lambda _: self.fail("Unverified mapping must not be queried")
        metrics.sample()
        self.assertFalse(metrics.get(USER)["available"])
        self.assertEqual(metrics.error, "user_mapping_not_verified")

    def test_missing_counter_duplicate_or_failure_resets_window(self):
        metric = self.setup_metric()
        self.counters(100, 100); metric.sample()
        self.payload["stat"].append(self.payload["stat"][0]); metric.sample()
        self.assertEqual(metric.status()["error_code"], "user_counters_unavailable")
        self.assertFalse(metric.get(USER)["available"])
        self.counters(200, 200); self.now += 5; metric.sample()
        self.assertFalse(metric.get(USER)["available"])
        self.now += 5; self.counters(300, 300); metric.sample()
        self.assertTrue(metric.get(USER)["available"])
        self.now += 100
        self.assertEqual(metric.get(USER)["error_code"], "stale_sample")

    def test_invalid_json_object_and_io_do_not_block_snapshot_or_crash_worker(self):
        metric = self.setup_metric()
        metric.runner = lambda _: "[]"
        metric.sample()
        self.assertEqual(metric.error, "user_counters_unavailable")
        entered, release = threading.Event(), threading.Event()
        def blocked(_):
            entered.set(); release.wait(5)
            return '{"stat":[]}'
        metric.runner = blocked
        worker = threading.Thread(target=metric.sample); worker.start()
        try:
            self.assertTrue(entered.wait(2))
            snapshot = threading.Thread(target=lambda: metric.get(USER))
            snapshot.start(); snapshot.join(0.5)
            self.assertFalse(snapshot.is_alive(), "API snapshot must not wait for StatsService I/O")
        finally:
            release.set(); worker.join()

    def test_no_exact_user_shaping_no_node_wide_fallback(self):
        result = limit_status(USER)
        self.assertFalse(result["applied"])
        self.assertEqual(result["state"], "unsupported")
        with self.assertRaises(ValueError):
            limit_status("not-a-uuid")

    def test_speedtest_sustained_gap_one_event_per_episode(self):
        load = SustainedLoad({"enabled": True, "capacity_mbps": 8, "fraction": 0.5, "window_seconds": 600, "minimum_bytes": 100_000_000})
        def sample(now, available=True, speed=600000):
            load.observe({"user_id": USER, "node_id": NODE, "available": available, "sampled_at": now,
                          "sample_interval_seconds": 5, "rx_bytes_per_second": speed, "tx_bytes_per_second": 0})
        for now in range(5, 65, 5):
            sample(now)
        self.assertEqual(len(load.events), 0)
        sample(65, speed=0)
        for now in range(70, 500, 5):
            sample(now)
        sample(500, available=False)
        for now in range(505, 1300, 5):
            sample(now)
        self.assertEqual(len(load.events), 1)
        self.assertGreaterEqual(load.events[0]["duration_seconds"], 600)
        self.assertFalse(load.events[0]["automatic_sanction"])
        sample(1300, speed=0)
        for now in range(1305, 2000, 5):
            sample(now)
        self.assertEqual(len(load.events), 2)


class SourceTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO safety check")
    def test_fifo_source_never_blocks_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"; os.mkfifo(path)
            store = Store(":memory:")
            tailer = Tailer(path, AccessParser("n1", UserMap(USERS)), store)
            try:
                with self.assertRaisesRegex(ValueError, "regular file"):
                    tailer.poll()
                self.assertIsNone(tailer.handle)
            finally:
                tailer.close(); store.close()

    def test_failed_cursor_load_closes_open_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"; path.write_text(LINE)
            store = Store(":memory:")
            tailer = Tailer(path, AccessParser("n1", UserMap(USERS)), store)
            try:
                with patch.object(store, "state", side_effect=ValueError("corrupt cursor")):
                    with self.assertRaises(ValueError):
                        tailer.poll()
                self.assertIsNone(tailer.handle)
                path.unlink()
            finally:
                tailer.close(); store.close()

    def test_idle_is_healthy_and_mapping_and_format_have_separate_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"; path.write_text("")
            store = Store(Path(directory) / "db.sqlite")
            parser = AccessParser("n1", UserMap(USERS))
            tailer = Tailer(path, parser, store, start_at_end=False)
            self.assertEqual(tailer.poll(), 0)
            self.assertIsNone(tailer.poll_error)
            path.write_text("invalid\n" + LINE.replace("alice", "unmapped") + LINE)
            self.assertEqual(tailer.poll(), 1)
            self.assertEqual(tailer.parse_errors, {"invalid_line": 1, "user_mapping_mismatch": 1})
            self.assertIsNotNone(tailer.last_event_at)
            diagnostics = Sources({"access_logs": [{}]}, clock=lambda: 1000)
            diagnostics.event_result(0, error="user_mapping_mismatch", skipped_events=2, last_event_at=990)
            state = diagnostics.report()["sources"][0]
            self.assertFalse(state["healthy"])
            self.assertEqual(state["event_age_seconds"], 10)
            diagnostics.event_result(0)
            self.assertEqual(diagnostics.report()["sources"][0]["last_success_at"], 1000)
            tailer.close(); store.close()

    def test_metadata_and_limits_authenticated_without_secrets(self):
        store = Store(":memory:")
        issued = generate_node_credentials(NODE)
        from remnawatch.auth import NodeAuth
        server = make_server(store, NodeAuth(**issued), ("127.0.0.1", 0))
        thread = threading.Thread(target=server.serve_forever); thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            for path in ("/v1/node", f"/v1/users/{USER}/rate-limit"):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    urllib.request.urlopen(base + path)
                self.assertEqual(caught.exception.code, 401)
                caught.exception.close()
            request = urllib.request.Request(base + f"/v1/users/{USER}/rate-limit", headers={"Authorization": "Bearer " + issued["token"]})
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request)
            self.assertEqual(caught.exception.code, 501)
            raw = caught.exception.read().decode()
            caught.exception.close()
            self.assertNotIn(issued["token"], raw)
            self.assertEqual(json.loads(raw)["state"], "unsupported")
        finally:
            server.shutdown(); thread.join(); server.server_close(); store.close()


class ProbeTests(unittest.TestCase):
    def test_failed_probe_restores_config_unit_and_previous_service_without_agent_mutation(self):
        with tempfile.TemporaryDirectory() as directory, patch("remnawatch.install.trusted"), patch("remnawatch.install.context"), patch("remnawatch.probe.make_probe", return_value=SimpleNamespace(server_close=lambda: None)), patch("remnawatch.install.check_probe", return_value={"healthy": False, "error_code": "connect_error"}):
            root = Path(directory); cfg = root / "cfg"; units = root / "units"; cfg.mkdir(); units.mkdir()
            path, service = cfg / "probe.json", units / "remnawatch-probe.service"
            path.write_text('{"old":"operator"}'); service.write_text(MARKER + "\nold probe unit")
            calls = []
            def runner(args):
                calls.append(args)
                return "active" if "is-active" in args else "enabled" if "is-enabled" in args else ""
            deployment = Deployment(root, cfg, units, runner)
            with self.assertRaisesRegex(CheckError, "connect_error"):
                deployment.probe(PROBE)
            self.assertEqual(path.read_text(), '{"old":"operator"}')
            self.assertEqual(service.read_text(), MARKER + "\nold probe unit")
            self.assertEqual(calls[-1], ["systemctl", "restart", "remnawatch-probe.service"])
            self.assertFalse(any("remnawatch.service" in args or "ufw" in args or "docker" in args for args in calls))
    def test_contract_validates_path_scheme_port(self):
        validate(PROBE)
        for changes in ({"scheme": "http"}, {"path": "/ping?token=x"}, {"port": 18443}, {"domain": "x/y"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate({**PROBE, **changes})

    def test_checks_get_and_head_and_no_redirect_or_secret(self):
        calls = []
        class Response(io.BytesIO):
            status, headers = 204, {"Cache-Control": "no-store"}
        class Opener:
            def open(self, request, timeout):
                calls.append(request)
                return Response(b"")
        result = check_probe(PROBE, Opener())
        self.assertTrue(result["healthy"])
        self.assertEqual([r.method for r in calls], ["GET", "HEAD"])
        self.assertTrue(all(not r.headers for r in calls))
        self.assertTrue(all(r.full_url == "https://node.example.com:44443/ping" for r in calls))

    def test_tls_dns_timeout_and_incompatible_are_distinct(self):
        for reason, code in ((ssl.SSLError("secret"), "tls_error"), (socket.gaierror("secret"), "dns_error"),
                             (TimeoutError("secret"), "timeout"), (ConnectionRefusedError("secret"), "connect_error")):
            class Opener:
                def open(self, *args, **kwargs):
                    raise urllib.error.URLError(reason)
            result = check_probe(PROBE, Opener())
            self.assertEqual(result["error_code"], code)
            self.assertNotIn("secret", json.dumps(result))

    def test_existing_probe_preserved_and_bad_cert_refused_without_mutation(self):
        deployment = Deployment(runner=lambda _: self.fail("must not mutate"))
        with patch("remnawatch.install.check_probe", return_value={"healthy": True}):
            self.assertEqual(deployment.probe(PROBE)["status"], "preserved")
        with patch("remnawatch.install.check_probe", return_value={"healthy": False, "error_code": "tls_error"}):
            with self.assertRaisesRegex(CheckError, "tls_error"):
                deployment.probe(PROBE)


class TransportTests(unittest.TestCase):
    def test_all_http_codes_classified_without_response_contents(self):
        for code in (401, 403, 404, 409, 429, 500, 502, 503, 504):
            error = classify(urllib.error.HTTPError("https://secret", code, "private", {}, None))
            self.assertEqual(error.code, f"central_http_{code}")
            self.assertNotIn("private", str(error))
            self.assertEqual(error.retryable, code in (429, 500, 502, 503, 504))

    def test_network_errors_distinct(self):
        for reason, code in ((ssl.SSLError(), "central_tls_error"), (socket.gaierror(), "central_dns_error"),
                             (TimeoutError(), "central_timeout"), (ConnectionRefusedError(), "central_connect_error")):
            self.assertEqual(classify(urllib.error.URLError(reason)).code, code)

    def test_get_retry_but_post_and_auth_failures_never_replayed(self):
        calls = []
        class Broken:
            def open(self, request, timeout):
                calls.append(request)
                raise urllib.error.URLError(TimeoutError("private"))
        token = "s" * 43
        client = HistoryClient("https://example.com/api/node", token, opener=Broken(), wait=lambda _: None)
        with self.assertRaises(HistoryTransportError):
            client.request("history-map")
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(token not in r.full_url and r.get_header("Authorization") == "Bearer " + token for r in calls))
        calls.clear()
        with self.assertRaises(HistoryTransportError):
            client.request("complete-history", post=True)
        self.assertEqual(len(calls), 1)
        class AuthError:
            def open(self, request, timeout):
                calls.append(request)
                raise urllib.error.HTTPError("private", 401, "private", {}, None)
        calls.clear(); client.opener = AuthError()
        with self.assertRaises(HistoryTransportError):
            client.request("history-map")
        self.assertEqual(len(calls), 1)
        self.assertEqual(client.status()["error_code"], "central_http_401")

    def test_json_success_and_invalid_response_health(self):
        class Opener:
            def open(self, *args, **kwargs):
                return io.BytesIO(b'{"ready":true}')
        client = HistoryClient("https://example.com/api", "s" * 43, opener=Opener())
        self.assertEqual(client.request("history-plan"), {"ready": True})
        self.assertTrue(client.status()["healthy"])
        class Invalid:
            def open(self, *args, **kwargs):
                return io.BytesIO(b'<html>private login</html>')
        client.opener = Invalid()
        with self.assertRaisesRegex(HistoryTransportError, "central_invalid_json"):
            client.request("history-map")
        for base in ("http://example.com", "https://secret@example.com", "https://example.com?token=x"):
            with self.assertRaises(ValueError):
                HistoryClient(base, "s" * 43)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable required for isolated TLS fixtures")
class NativeProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.cert, cls.key = cls.root / "cert.pem", cls.root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
                        "-keyout", str(cls.key), "-out", str(cls.cert)], capture_output=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exercise(self, host):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        try:
            with socket.socket(family) as sock:
                sock.bind((host, 0)); port = sock.getsockname()[1]
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        config = {**PROBE, "domain": host, "host": host, "port": port, "certificate": str(self.cert), "private_key": str(self.key)}
        url_host = "[" + host + "]" if ":" in host else host
        server = make_probe(config)
        thread = threading.Thread(target=server.serve_forever); thread.start()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(self.cert))))
        try:
            if family == socket.AF_INET6:
                try:
                    with socket.create_connection((host, port), timeout=2):
                        pass
                except OSError as exc:
                    if getattr(exc, "winerror", None) == 10013 or exc.errno == 13:
                        self.skipTest("Host security policy denies IPv6 loopback connections")
                    raise
            result = check_probe(config, opener)
            self.assertTrue(result["healthy"], result)
            for method in ("GET", "HEAD"):
                with opener.open(urllib.request.Request(f"https://{url_host}:{port}/ping", method=method)) as response:
                    self.assertEqual(response.status, 204)
                    self.assertEqual(response.read(), b"")
                    self.assertEqual(response.headers["Cache-Control"], "no-store")
                    self.assertNotIn("Python", response.headers["Server"])
            for path in ("/v1/node", "/ping?secret=value"):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    opener.open(f"https://{url_host}:{port}" + path)
                self.assertEqual(caught.exception.code, 404)
                caught.exception.close()
            self.assertEqual(check_probe(config)["error_code"], "tls_error")
            with self.assertRaises(OSError):
                make_probe(config)
        finally:
            server.shutdown(); thread.join(); server.server_close()

    def test_real_https_ipv4_get_head_occupied_certificate_and_private_api_separation(self):
        self.exercise("127.0.0.1")

    def test_real_https_ipv6(self):
        self.exercise("::1")

    def test_private_api_health_uses_local_listener_with_verified_tls_hostname(self):
        from remnawatch.auth import NodeAuth
        from remnawatch.tls import context
        from remnawatch.version import VERSION
        issued = generate_node_credentials(NODE)
        store = Store(":memory:")
        server = make_server(store, NodeAuth(**issued), ("127.0.0.1", 0), tls_context=context(str(self.cert), str(self.key)))
        worker = threading.Thread(target=server.serve_forever); worker.start()
        config = {"host": "127.0.0.1", "port": server.server_port, "auth": issued,
                  "tls": {"enabled": True, "server_name": "localhost", "ca_file": str(self.cert)}}
        try:
            with patch("socket.create_connection", wraps=socket.create_connection) as connect:
                Deployment().health(config, VERSION)
                self.assertEqual(connect.call_args.args[0][0], "127.0.0.1")
        finally:
            server.shutdown(); worker.join(); server.server_close(); store.close()


if __name__ == "__main__":
    unittest.main()
