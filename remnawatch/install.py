"""Staged systemd deployment. Default invocation is read-only; --apply is explicit.

Installs missing allowlisted dependencies on --apply; never changes firewall/Caddy
or recreates VPN containers. --no-install-deps keeps package management manual.
Receives secrets through a protected config file, never command arguments.
"""
import argparse
import copy
import hashlib
import http.client
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import time
import urllib.request
from .auth import resolve_auth
from .events import UserMap
from .preflight import CheckError, docker_source, host_report, run
from .probe import check_probe, validate as validate_probe, NoRedirect
from .tls import context
from .update import acquire, validate_url, PublicHTTPSHandler
from .version import VERSION
from .dependencies import install_dependencies

MARKER = "# REMNAWATCH_STAGED_INSTALL_V1"


def atomic(path, text, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise CheckError("unsafe_path", "Refusing symlinked configuration")
    fd, name = tempfile.mkstemp(prefix=".remnawatch-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            if hasattr(os, "fchmod"):
                os.fchmod(output.fileno(), mode)
            else:
                os.chmod(name, mode)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def trusted(path):
    for item in (Path(path), *Path(path).parents):
        if item.is_symlink() or (item.exists() and (item.stat().st_uid != 0 or item.stat().st_mode & 0o022)):
            raise CheckError("unsafe_path", "Use root-owned paths without group/world write permission or symlinks")


def api_listener(config, runner=run):
    port = config.get("port", 8080)
    if type(port) is not int or not 1024 <= port <= 65535:
        raise CheckError("invalid_api_port", "Choose a dedicated unprivileged TCP API port")
    host = config.get("host", "127.0.0.1")
    if host != "localhost":
        try:
            ipaddress.ip_address(host)
        except (ValueError, TypeError):
            raise CheckError("invalid_api_bind_address", "Bind to a literal local interface IP or localhost") from None
    listeners = runner(["ss", "-H", "-ltnp", "sport = :" + str(port)])
    if listeners:
        pid = runner(["systemctl", "show", "--property=MainPID", "--value", "remnawatch.service"])
        if not re.fullmatch(r"[1-9][0-9]*", pid) or any("pid=" + pid + "," not in line for line in listeners.splitlines()):
            raise CheckError("api_port_occupied", "Existing listener preserved; choose a free dedicated API port")
    return {"ok": True, "port": port, "occupied_by_agent": bool(listeners)}


def unit(release_root, config_path, probe=False):
    module = "remnawatch.probe" if probe else "remnawatch"
    hardening = "ProtectSystem=strict\nProtectHome=yes\nPrivateDevices=yes\nCapabilityBoundingSet=\nRestrictSUIDSGID=yes\n" if probe else ""
    return (MARKER + "\n[Unit]\nDescription=RemnaWatch" + (" browser HTTPS RTT" if probe else " agent") +
            "\nAfter=network.target\n[Service]\nType=simple\nUser=root\nWorkingDirectory=" + str(release_root / "current") +
            "\nExecStart=" + str(release_root / "current/.venv/bin/python3") + " -m " + module + " --config " + str(config_path) +
            "\nRestart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nMemoryHigh=256M\nMemoryMax=384M\n"
            + hardening + "[Install]\nWantedBy=multi-user.target\n")


def release_manifest(path):
    package = Path(path) / "remnawatch"
    result = {}
    for item in sorted(package.glob("*.py")):
        trusted(item)
        result[item.name] = hashlib.sha256(item.read_bytes()).hexdigest()
    if "__main__.py" not in result or "version.py" not in result:
        raise CheckError("release_incomplete", "Acquire a verified complete release")
    return result


def prepare_release(root, url, digest, version, runner=run):
    import venv
    # Reuse a previously verified, unchanged release. A manifest is never supplied
    # by the archive: it is generated after verification and kept root-only.
    from .releases import parse
    parse(version)
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise CheckError("trusted_digest_required", "Get SHA256 from authenticated administrator policy")
    releases = Path(root) / "releases"
    trusted(releases)
    releases.mkdir(mode=0o700, parents=True, exist_ok=True)
    release = releases / (version + "-" + digest[:16])
    if release.exists():
        trusted(release)
        manifest = release / ".verified-release.json"
        trusted(manifest)
        try:
            saved = json.loads(manifest.read_text())
            valid = saved == {"sha256": digest, "version": version, "files": release_manifest(release)}
        except (OSError, ValueError):
            valid = False
        if not valid or not (release / ".venv/bin/python3").exists():
            raise CheckError("release_modified", "Existing release preserved; review its manifest and acquire a new trusted release")
        return release
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=releases))
    try:
        acquire(url, digest, staging, version)
        venv.EnvBuilder(with_pip=False).create(staging / ".venv")
        runner([str(staging / ".venv/bin/python3"), "-m", "compileall", "-q", str(staging / "remnawatch")])
        atomic(staging / ".verified-release.json", json.dumps({"sha256": digest, "version": version, "files": release_manifest(staging)}))
        staging.rename(release)
        return release
    except BaseException:
        # Exact path from mkdtemp, verified under the managed releases directory.
        if staging.exists() and staging.resolve().parent == releases.resolve():
            shutil.rmtree(staging)
        raise


class Deployment:
    def __init__(self, root=Path("/opt/remnawatch"), config_dir=Path("/etc/remnawatch"), units=Path("/etc/systemd/system"), runner=run):
        self.root, self.config_dir, self.units, self.run = Path(root), Path(config_dir), Path(units), runner
        self.results = {}

    def health(self, config, expected_version):
        auth = resolve_auth(config)
        tls = config.get("tls", {})
        bind = config.get("host", "127.0.0.1")
        connect_host = "127.0.0.1" if bind in ("0.0.0.0", "localhost") else "::1" if bind == "::" else bind
        host = tls.get("server_name", connect_host) if tls.get("enabled") else connect_host
        ctx = ssl.create_default_context(cafile=tls.get("ca_file")) if tls.get("enabled") else None
        url_host = "[" + host + "]" if ":" in host else host
        url = ("https" if ctx else "http") + "://" + url_host + ":" + str(config.get("port", 8080)) + "/v1/node"
        class LocalConnection(http.client.HTTPSConnection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                # TLS still verifies URL hostname/SNI, but the credential goes
                # only to the configured local listener, never its public DNS.
                self._create_connection = lambda address, timeout=5, source_address=None: socket.create_connection((connect_host, address[1]), timeout, source_address)
        class LocalHTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                return self.do_open(LocalConnection, request, context=ctx)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                             *([LocalHTTPS(context=ctx)] if ctx else []))
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + auth.token})
        for _ in range(10):
            try:
                with opener.open(request, timeout=2) as response:
                    data = json.loads(response.read(8192))
                if data.get("node_id") == auth.node_id and data.get("agent_version") == expected_version and data.get("service") == "remnawatch":
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.5)
        raise CheckError("agent_health_failed", "Previous release and configuration will be restored")

    def activate(self, release, config, expected_version, health=None):
        """Rollback touches only this agent's unit, config and current symlink."""
        config = copy.deepcopy(config)
        resolve_auth(config)
        if not Path(config.get("database", "domains.sqlite")).is_absolute():
            raise CheckError("relative_database_path", "Set an absolute path to the existing database before changing release directories")
        if config.get("host", "127.0.0.1") not in ("localhost", "127.0.0.1", "::1") and not config.get("tls", {}).get("enabled"):
            raise CheckError("public_api_requires_tls", "Configure verified TLS or keep the API on loopback")
        if config.get("tls", {}).get("enabled"):
            context(config["tls"]["certificate"], config["tls"]["private_key"])
        for path in (self.root, self.config_dir, self.units, release):
            trusted(path)
        config_path, unit_path, current = self.config_dir / "config.json", self.units / "remnawatch.service", self.root / "current"
        if unit_path.exists() and MARKER not in unit_path.read_text():
            raise CheckError("unmanaged_unit", "Existing service preserved; review migration to the staged installer explicitly")
        if current.exists() and not current.is_symlink():
            raise CheckError("unsafe_current", "Expected a managed current symlink; existing directory preserved")
        for path in (config_path, unit_path):
            trusted(path)
        database = Path(config["database"])
        trusted(database)
        database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if current.is_symlink():
            resolved = current.resolve(strict=True)
            if self.root.resolve() not in resolved.parents:
                raise CheckError("unsafe_current", "Existing current target is outside managed releases")
        old_link = os.readlink(current) if current.is_symlink() else None
        previous = {p: p.read_text() if p.exists() else None for p in (config_path, unit_path)}
        expected_unit = unit(self.root, config_path)
        if previous[unit_path] is not None and previous[unit_path] != expected_unit:
            raise CheckError("managed_unit_modified", "Operator unit preserved; review changes before migration")
        if (current.is_symlink() and current.resolve() == release.resolve() and previous[config_path] is not None
                and json.loads(previous[config_path]) == config):
            (health or self.health)(config, expected_version)
            self.results["agent"] = {"status": "unchanged", "version": expected_version}
            return
        api_listener(config, self.run)
        def state(operation):
            try:
                return self.run(["systemctl", operation, "remnawatch.service"]) in ("active", "enabled")
            except CheckError:
                return False
        active, enabled = state("is-active"), state("is-enabled")
        backup = self.root / "backups" / str(time.time_ns())
        backup.mkdir(mode=0o700, parents=True)
        for path, text in previous.items():
            if text is not None:
                atomic(backup / path.name, text)
        atomic(backup / "previous-release.json", json.dumps({"target": old_link}))
        self.config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        replacement = self.root / ".current-next"
        if replacement.is_symlink():
            replacement.unlink()
        if replacement.exists():
            raise CheckError("unsafe_current", "Staging link is occupied")
        link_switched = False
        try:
            atomic(config_path, json.dumps(config, indent=2) + "\n")
            atomic(unit_path, expected_unit, 0o644)
            replacement.symlink_to(release.resolve(), target_is_directory=True)
            os.replace(replacement, current)
            link_switched = True
            self.run(["systemctl", "daemon-reload"])
            self.run(["systemctl", "enable", "remnawatch.service"])
            self.run(["systemctl", "restart", "remnawatch.service"])
            (health or self.health)(config, expected_version)
            self.results["agent"] = {"status": "healthy", "version": expected_version, "backup": str(backup)}
        except BaseException:
            # Rollback must still attempt every restoration if one systemctl fails.
            for path, text in previous.items():
                if text is None:
                    path.unlink(missing_ok=True)
                else:
                    atomic(path, text, 0o644 if path == unit_path else 0o600)
            if replacement.is_symlink():
                replacement.unlink()
            if link_switched and old_link is not None:
                replacement.symlink_to(old_link, target_is_directory=True)
                os.replace(replacement, current)
            elif link_switched and current.is_symlink():
                current.unlink()
            rollback_ok = True
            for args in (["daemon-reload"], ["enable" if enabled else "disable", "remnawatch.service"],
                         ["restart" if active else "stop", "remnawatch.service"]):
                try:
                    self.run(["systemctl", *args])
                except CheckError:
                    rollback_ok = False
            self.results["agent"] = {"status": "rolled_back" if rollback_ok else "rollback_failed", "backup": str(backup)}
            raise

    def history(self, config, container):
        # Only an already enabled, operator-provisioned map and existing mount.
        source = docker_source(container, self.run)
        UserMap(config.get("users", []), require_uuid=True)
        if not config.get("users"):
            raise CheckError("user_mapping_missing", "Provision exact (node,inbound,email) -> Remnawave UUID mapping first")
        matching = [log for log in config.get("access_logs", []) if log.get("path") == source["path"] and log.get("enabled", True)]
        if not config.get("domains", {}).get("enabled", False) or not matching:
            raise CheckError("history_not_configured", "Configure the discovered existing path, timezone and exact node ID explicitly; rerun without reinstalling VPN")
        return {"status": "awaiting_real_connection", **source}

    def probe(self, config):
        validate_probe(config)
        existing = check_probe(config)
        if existing["healthy"]:
            return {"status": "preserved", **existing}
        # An invalid existing certificate is not silently replaced.
        if existing["error_code"] in ("tls_error", "incompatible_probe"):
            raise CheckError(existing["error_code"], "Existing endpoint preserved; fix certificate or review listener manually")
        context(config["certificate"], config["private_key"])
        from .probe import make_probe
        try:
            server = make_probe(config)
            server.server_close()
        except OSError:
            raise CheckError("probe_port_occupied", "Existing listener preserved; choose a free dedicated port") from None
        path, service = self.config_dir / "probe.json", self.units / "remnawatch-probe.service"
        for item in (path, service):
            trusted(item)
        if service.exists() and MARKER not in service.read_text():
            raise CheckError("unmanaged_probe", "Existing probe service preserved")
        previous = {p: p.read_text() if p.exists() else None for p in (path, service)}
        def state(operation):
            try:
                return self.run(["systemctl", operation, "remnawatch-probe.service"]) in ("active", "enabled")
            except CheckError:
                return False
        active, enabled = state("is-active"), state("is-enabled")
        try:
            atomic(path, json.dumps(config))
            atomic(service, unit(self.root, path, probe=True), 0o644)
            self.run(["systemctl", "daemon-reload"])
            self.run(["systemctl", "enable", "remnawatch-probe.service"])
            self.run(["systemctl", "restart", "remnawatch-probe.service"])
            result = check_probe(config)
            if not result["healthy"]:
                raise CheckError(result["error_code"], "Probe is not publicly reachable; agent remains running")
            return {"status": "healthy", **result}
        except BaseException:
            for args in (["stop", "remnawatch-probe.service"], ["disable", "remnawatch-probe.service"]):
                try:
                    self.run(["systemctl", *args])
                except CheckError:
                    pass
            for p, text in previous.items():
                if text is None:
                    p.unlink(missing_ok=True)
                else:
                    atomic(p, text, 0o644 if p == service else 0o600)
            for args in (["daemon-reload"], ["enable" if enabled else "disable", "remnawatch-probe.service"],
                         ["restart" if active else "stop", "remnawatch-probe.service"]):
                try:
                    self.run(["systemctl", *args])
                except CheckError:
                    pass
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    dependencies = parser.add_mutually_exclusive_group()
    dependencies.add_argument("--install-deps", action="store_true", help="Install missing distro dependencies and show preflight; --apply does this by default")
    dependencies.add_argument("--no-install-deps", action="store_true", help="Do not install system packages even with --apply")
    parser.add_argument("--config", help="Root-owned JSON file; never put tokens on command line")
    parser.add_argument("--container", help="Actual RemnaNode container; read-only discovery")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--probe-config", help="Explicit opt-in to a public listener; no firewall changes")
    parser.add_argument("--release-url")
    parser.add_argument("--sha256", help="Digest from independent authenticated administrator policy")
    parser.add_argument("--version", default=VERSION)
    args = parser.parse_args(argv)
    if args.apply and (not args.config or not args.release_url or not args.sha256):
        parser.exit(1, "Supply protected --config, HTTPS --release-url, trusted --sha256 and --version; use --install-deps for dependency repair only\n")
    report = host_report()
    if (args.apply and not args.no_install_deps) or args.install_deps:
        try:
            dependency_result = install_dependencies(report)
            report = host_report()
            report["dependencies"] = dependency_result
        except CheckError as exc:
            print(json.dumps({"dependencies": {"status": "failed", "error_code": exc.code, "hint": exc.hint}}))
            raise SystemExit(1) from None
    if report["supported"] and args.config:
        try:
            inspected = json.loads(Path(args.config).read_text())
            if not isinstance(inspected, dict):
                raise ValueError("config must be an object")
            resolve_auth(inspected)
            report["checks"]["api_listener"] = api_listener(inspected)
        except CheckError as exc:
            report["checks"]["api_listener"] = {"ok": False, "error_code": exc.code, "hint": exc.hint}
        except (OSError, ValueError):
            report["checks"]["api_listener"] = {"ok": False, "error_code": "config_unavailable", "hint": "Check protected JSON config and auth; no listener is replaced"}
    if report["supported"] and args.release_url:
        try:
            validate_url(args.release_url)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), PublicHTTPSHandler())
            with opener.open(urllib.request.Request(args.release_url, method="HEAD"), timeout=10) as response:
                report["checks"]["release_https"] = {"ok": response.status == 200}
        except (OSError, ValueError):
            report["checks"]["release_https"] = {"ok": False, "hint": "Check release URL, public DNS, CA chain and clock; redirects are not followed"}
    if not args.apply:
        if report["supported"] and (args.history or args.container):
            try:
                report["history"] = docker_source(args.container)
            except CheckError as exc:
                report["history"] = {"status": "failed", "error_code": exc.code, "hint": exc.hint}
        print(json.dumps(report, indent=2))
        return
    required = ("root", "disk", "venv", "release_https", "api_listener")
    if (not report["supported"] or any(not report["checks"].get(key, {}).get("ok") for key in required)
            or not report["checks"].get("ss", {}).get("available") or report["checks"].get("clock", {}).get("ok") is False):
        parser.exit(1, "Preflight refused installation; run without --apply for checks\n")
    if not args.config or not args.release_url or not args.sha256:
        parser.exit(1, "Supply protected --config, HTTPS --release-url, trusted --sha256 and --version\n")
    import fcntl
    fd = os.open("/run/lock/remnawatch-install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as lock:
        if os.fstat(lock.fileno()).st_uid != 0:
            parser.exit(1, "Unsafe installer lock\n")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deployment = Deployment()
        try:
            trusted(Path(args.config))
            if Path(args.config).stat().st_mode & 0o077:
                raise CheckError("config_permissions", "Use chmod 600 for secret configuration")
            config = json.loads(Path(args.config).read_text())
            resolve_auth(config)
            for path in (deployment.root, deployment.config_dir, deployment.units):
                trusted(path)
            release = prepare_release(deployment.root, args.release_url, args.sha256, args.version, deployment.run)
            deployment.activate(release, config, args.version)
        except BaseException as exc:
            code = exc.code if isinstance(exc, CheckError) else "agent_preparation_failed"
            print(json.dumps({"agent": deployment.results.get("agent", {"status": "failed"}), "error_code": code}))
            raise SystemExit(1) from None
        # Independent optional stages; never stop a successfully deployed agent.
        for name, enabled, action in (
            ("history", args.history, lambda: deployment.history(config, args.container)),
            ("probe", bool(args.probe_config), lambda: deployment.probe(json.loads(Path(args.probe_config).read_text())))):
            if not enabled:
                deployment.results[name] = {"status": "disabled"}
                continue
            try:
                deployment.results[name] = action()
            except (CheckError, OSError, ValueError) as exc:
                deployment.results[name] = {"status": "failed", "error_code": getattr(exc, "code", name + "_setup_failed"),
                                            "hint": getattr(exc, "hint", "Check protected configuration, file permissions and TLS")}
        deployment.results["firewall_tls"] = {"status": "manual", "automatic_changes": False,
            "api_rule": "Allow TCP " + str(config.get("port", 8080)) + " only from the primary server; deny other sources. Keep SSH/VPN rules.",
            "probe_rule": "If probe explicitly selected, allow its configured TCP port for browser clients in IPv4/IPv6. Never enable/reset firewall automatically."}
        print(json.dumps(deployment.results, indent=2))


if __name__ == "__main__":
    main()
