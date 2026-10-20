"""Missing components, package safety and bootstrap regression tests."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import io
from types import SimpleNamespace
from unittest.mock import patch
from remnawatch.dependencies import dependency_plan, install_dependencies, package_command, apt_error
from remnawatch.preflight import CheckError

REPORT = {"supported": True, "os": "ubuntu", "os_version": "20.04", "architecture": "x86_64"}


class DependencyTests(unittest.TestCase):
    def test_repo_dns_trust_disk_and_lock_failures_have_safe_distinct_codes(self):
        cases = (("404 Not Found https://private:password@example.com", "dependencies_repository_unavailable"),
                 ("Temporary failure resolving private.example", "dependencies_dns_failed"),
                 ("Could not get lock /var/lib/dpkg/lock", "dependencies_apt_locked"),
                 ("No space left on device", "dependencies_disk_full"),
                 ("Certificate verification failed", "dependencies_repository_trust_failed"))
        for raw, code in cases:
            result = apt_error(raw)
            self.assertEqual(result.code, code)
            self.assertNotIn("password", str(result))
            self.assertNotIn("private.example", str(result))
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="Err:1 repo Temporary failure resolving private.example", stderr="")):
            with self.assertRaisesRegex(CheckError, "dependencies_dns_failed"):
                package_command(["apt-get", "update"])
    def test_cli_readonly_apply_and_optout_dependency_behavior(self):
        from remnawatch.install import main
        base = ["--config", "/protected/config.json", "--release-url", "https://example.com/release", "--sha256", "a" * 64]
        for args, expected in (([], False), (["--install-deps"], True),
                               (["--apply", *base], True), (["--apply", "--no-install-deps", *base], False)):
            with self.subTest(args=args), patch("remnawatch.install.host_report", return_value={"supported": False, "checks": {}}), patch("remnawatch.install.install_dependencies", return_value={"status": "unchanged"}) as install, patch("sys.stdout", new_callable=io.StringIO), patch("sys.stderr", new_callable=io.StringIO):
                try:
                    main(args)
                except SystemExit:
                    pass
                self.assertEqual(install.called, expected)
        with patch("remnawatch.install.install_dependencies") as install, patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                main(["--apply"])
            install.assert_not_called()
    def test_missing_package_plan_and_idempotent_noop(self):
        calls = []
        def runner(args):
            calls.append(args)
            return "installed" if args[0] == "dpkg-query" else ""
        self.assertEqual(dependency_plan(runner, lambda _: "/usr/bin/tool", lambda _: True), [])
        with patch("os.geteuid", return_value=0, create=True), patch("shutil.disk_usage", return_value=SimpleNamespace(free=10**9)):
            result = install_dependencies(REPORT, runner=lambda *a, **k: self.fail("No apt call for a healthy install"), planner=lambda: [])
        self.assertEqual(result["status"], "unchanged")

    def test_missing_tools_ca_and_broken_python_modules_are_repaired(self):
        def runner(args):
            if args[0] == "dpkg-query":
                return "installed"
            raise CheckError("command_failed", "fixture")
        result = dependency_plan(runner, lambda name: "/usr/bin/python3" if name == "python3" else None, lambda _: False)
        self.assertEqual(set(result), {"iproute2", "systemd", "ca-certificates", "python3", "python3-venv"})

    def test_only_missing_allowlist_installed_without_upgrades_or_removals(self):
        calls = []
        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return "Inst python3-venv (3.8.2 distro [amd64])\n" if "--simulate" in args else ""
        plans = iter([["python3-venv"], []])
        with patch("os.geteuid", return_value=0, create=True), patch("shutil.disk_usage", return_value=SimpleNamespace(free=10**9)):
            result = install_dependencies(REPORT, runner=runner, planner=lambda: next(plans))
        self.assertEqual(result, {"status": "installed", "packages": ["python3-venv"]})
        self.assertEqual(len(calls), 3)
        actual, kwargs = calls[-1]
        self.assertIn("--no-remove", actual)
        self.assertIn("--no-upgrade", actual)
        self.assertIn("Dpkg::Options::=--force-confold", actual)
        self.assertIsNone(kwargs["timeout"])
        self.assertEqual(actual[actual.index("install") + 1:], ["python3-venv"])
        self.assertFalse(any("upgrade" in args or "dist-upgrade" in args or "ufw" in args or "docker" in args for args, _ in calls))

    def test_root_disk_platform_and_invalid_plan_refused_before_apt(self):
        for report, uid, free, planned in (({**REPORT, "supported": False}, 0, 10**9, []),
                                          (REPORT, 1000, 10**9, []), (REPORT, 0, 0, []),
                                          (REPORT, 0, 10**9, ["docker.io"])):
            with self.subTest(report=report, uid=uid, free=free), patch("os.geteuid", return_value=uid, create=True), patch("shutil.disk_usage", return_value=SimpleNamespace(free=free)):
                with self.assertRaises(CheckError):
                    install_dependencies(report, runner=lambda *a, **k: self.fail("No apt before validation"), planner=lambda: planned)

    def test_resolver_upgrade_removal_and_failed_repository_never_reach_install(self):
        for simulation in ("Remv important-service [1.0]\n", "Inst libssl3 [1.0] (2.0 distro [amd64])\n"):
            calls = []
            def runner(args, **kwargs):
                calls.append(args)
                return simulation if "--simulate" in args else ""
            with patch("os.geteuid", return_value=0, create=True), patch("shutil.disk_usage", return_value=SimpleNamespace(free=10**9)):
                with self.assertRaisesRegex(CheckError, "dependencies_conflict"):
                    install_dependencies(REPORT, runner=runner, planner=lambda: ["python3-venv"])
            self.assertFalse(any("-y" in args for args in calls))

    def test_failed_postinstall_check_and_retry(self):
        with patch("os.geteuid", return_value=0, create=True), patch("shutil.disk_usage", return_value=SimpleNamespace(free=10**9)):
            with self.assertRaisesRegex(CheckError, "dependencies_verification_failed"):
                install_dependencies(REPORT, runner=lambda *a, **k: "", planner=lambda: ["iproute2"])
            self.assertEqual(install_dependencies(REPORT, runner=lambda *a, **k: "", planner=lambda: [])["status"], "unchanged")

    def test_package_errors_do_not_print_repo_or_proxy_credentials(self):
        secret = "https://private:password@proxy.example/"
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=1, stdout=secret, stderr=secret)):
            with self.assertRaises(CheckError) as caught:
                package_command(["apt-get", "update"])
        self.assertNotIn("password", str(caught.exception))
        self.assertNotIn("proxy.example", str(caught.exception))
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("private", 1)):
            with self.assertRaisesRegex(CheckError, "dependencies_timeout"):
                package_command(["apt-get", "update"])

    def test_package_environment_preserves_config_and_prevents_needrestart(self):
        with patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run:
            package_command(["apt-get", "install", "python3-venv"], timeout=None)
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["NEEDRESTART_MODE"], "l")
        self.assertEqual(env["NEEDRESTART_SUSPEND"], "1")
        self.assertEqual(env["UCF_FORCE_CONFFOLD"], "1")


@unittest.skipUnless(os.name == "posix", "POSIX shell bootstrap fixtures")
class BootstrapTests(unittest.TestCase):
    def test_script_syntax(self):
        subprocess.run(["/bin/sh", "-n", "deploy/install.sh"], check=True)

    def test_unsupported_os_or_non_systemd_never_invokes_package_manager(self):
        source = Path("deploy/install.sh").read_text()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "os-release"; comm = root / "comm"; systemd = root / "systemd"
            comm.write_text("not-systemd"); systemd.mkdir()
            adapted = source.replace("/etc/os-release", str(release)).replace("/proc/1/comm", str(comm)).replace("/run/systemd/system", str(systemd))
            script = root / "install.sh"; script.write_text(adapted)
            for contents, code in (("ID=ubuntu\nVERSION_ID=18.04\n", "unsupported_os"),
                                   ("ID=ubuntu\nVERSION_ID=20.04\n", "systemd_unavailable")):
                release.write_text(contents)
                result = subprocess.run(["/bin/sh", str(script), "--install-deps"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn(code, result.stderr)
                self.assertNotIn("Bootstrapping", result.stdout)
