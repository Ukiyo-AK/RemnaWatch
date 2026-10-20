"""Read-only host and Docker inventory. All subprocess output is allowlisted."""
import configparser
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from .runtime import discover_versions

SUPPORTED_PLATFORMS = {("debian", "11"), ("debian", "12"), ("debian", "13"),
                       ("ubuntu", "20.04"), ("ubuntu", "22.04"), ("ubuntu", "24.04"), ("ubuntu", "26.04")}


class CheckError(ValueError):
    def __init__(self, code, hint):
        self.code, self.hint = code, hint
        super().__init__(code + ": " + hint)


def run(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise CheckError("command_unavailable", "Check executable, permissions and Docker daemon") from None
    if result.returncode:
        # No raw stderr: Docker and proxy diagnostics can include configuration.
        raise CheckError("command_failed", "Check local service state and permissions; output suppressed")
    if len(result.stdout) > 4 * 1024 * 1024:
        raise CheckError("metadata_too_large", "Review configuration locally")
    return result.stdout.decode("utf-8", errors="strict").strip()


def supported(os_id, version, arch, systemd, python=sys.version_info[:2]):
    if (os_id, version) not in SUPPORTED_PLATFORMS:
        raise CheckError("unsupported_os", "Use Debian 11/12/13 or Ubuntu LTS 20.04/22.04/24.04/26.04; older and interim releases require separate validation")
    if arch not in {"x86_64", "aarch64", "amd64", "arm64"}:
        raise CheckError("unsupported_architecture", "Use amd64 or arm64")
    if not systemd:
        raise CheckError("systemd_unavailable", "Install on a host with systemd PID 1; container installation is unsupported")
    if tuple(python) < (3, 8):
        raise CheckError("python_unsupported", "Use distro Python 3.8+ and python3-venv; bootstrap with sh deploy/install.sh when Python is missing")


def logger_layout(read):
    """read(path) returns file text or None if absent; permission failures must raise."""
    text = read("/etc/s6-overlay/s6-rc.d/xray-log/run")
    if text is not None:
        if re.search(r"(?:^|\s)(?:/command/)?s6-log\s", text) and "/var/log/xray" in text:
            return {"logger": "s6", "target": "/var/log/xray", "filename": "current"}
        raise CheckError("logger_unsupported", "Review s6 Xray logger locally; no container changes made")
    text = read("/etc/supervisord.conf")
    if text is not None:
        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
            value = parser["program:xray"].get("stdout_logfile")
            if value == "/var/log/supervisor/xray.out.log":
                return {"logger": "supervisor", "target": "/var/log/supervisor", "filename": "xray.out.log"}
        except (configparser.Error, KeyError):
            pass
    raise CheckError("logger_unsupported", "Provide a reviewed existing Xray access-log mount; do not create an empty log")


def docker_source(container=None, runner=run):
    if container is None:
        # Names only, not labels, environment, command or published user addresses.
        names = runner(["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"])
        candidates = [line.split("\t")[0] for line in names.splitlines()
                      if len(line.split("\t")) == 2 and ("remnawave/node" in line.split("\t")[1] or line.split("\t")[0] == "remnanode")]
        if len(candidates) != 1:
            raise CheckError("container_ambiguous", "Select the actual RemnaNode container explicitly")
        container = candidates[0]
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", container):
        raise CheckError("container_invalid", "Use a Docker container name or ID")
    info = json.loads(runner(["docker", "inspect", container]))[0]
    if not info.get("State", {}).get("Running"):
        raise CheckError("container_stopped", "Restore the existing RemnaNode container before enabling history")
    image = info.get("Image", "")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise CheckError("image_unverified", "Inspect immutable image ID locally")
    def read(path):
        # A single known filename, no operator-controlled shell text.
        script = 'const fs=require("fs");try{process.stdout.write(fs.readFileSync(process.argv[1],"utf8"))}catch(e){if(e.code==="ENOENT")process.stdout.write("__MISSING__");else process.exit(2)}'
        value = runner(["docker", "exec", container, "node", "-e", script, path])
        return None if value == "__MISSING__" else value
    layout = logger_layout(read)
    mounts = [m for m in info.get("Mounts", []) if m.get("Destination") == layout["target"]]
    if len(mounts) != 1:
        raise CheckError("log_not_mounted", "Mount the existing Xray log directory after separate backup/consent; container will not be recreated")
    path = Path(mounts[0]["Source"]) / layout["filename"]
    if not path.is_file():
        raise CheckError("source_missing", "Check that the running Xray logger has created its mounted file")
    try:
        with path.open("rb"):
            pass
    except PermissionError:
        raise CheckError("permission_denied", "Grant the agent read access to the existing mounted log") from None
    stat = path.stat()
    def safe_versions(args):
        try:
            return runner(args)
        except CheckError:
            return None
    return {"container": container, "image_digest": image, **layout, "path": str(path),
            "size_bytes": stat.st_size, "modified_at": stat.st_mtime,
            "growth_verified": False, "next_step": "Compare file size after a real VPN connection; idle is not an error",
            **discover_versions(container, safe_versions)}


def host_report():
    report = {"checked_at": time.time(), "read_only": True, "checks": {}, "supported": False}
    checks = report["checks"]
    try:
        values = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
        systemd = Path("/run/systemd/system").is_dir() and Path("/proc/1/comm").read_text().strip() == "systemd"
        supported(values.get("ID"), values.get("VERSION_ID"), platform.machine(), systemd)
        report.update(supported=True, os=values["ID"], os_version=values["VERSION_ID"], architecture=platform.machine())
    except (CheckError, OSError) as exc:
        checks["platform"] = {"ok": False, "code": getattr(exc, "code", "platform_unavailable"), "hint": getattr(exc, "hint", "Use a supported systemd Linux host")}
        return report
    checks["root"] = {"ok": os.geteuid() == 0, "hint": "Use sudo for installation; read-only preflight does not require root"}
    checks["disk"] = {"ok": shutil.disk_usage("/").free >= 256 * 1024**2, "minimum_free_bytes": 256 * 1024**2}
    checks["clock"] = {"ok": None, "hint": "Confirm timedatectl synchronization and UTC; certificate verification remains enabled"}
    try:
        checks["clock"]["ok"] = run(["timedatectl", "show", "--property=NTPSynchronized", "--value"]) == "yes"
    except CheckError:
        pass
    import importlib.util
    checks["venv"] = {"ok": importlib.util.find_spec("venv") is not None, "hint": "Install python3-venv using the OS package manager if missing"}
    for tool in ("python3", "systemctl", "ss", "docker", "caddy", "ufw", "firewall-cmd", "nft"):
        checks[tool] = {"available": shutil.which(tool) is not None}
    checks["firewall"] = {"mode": "external_or_unknown", "automatic_changes": False}
    if shutil.which("ufw"):
        try:
            checks["firewall"]["mode"] = "ufw_active" if run(["ufw", "status"]).startswith("Status: active") else "ufw_inactive"
        except CheckError:
            checks["firewall"]["mode"] = "ufw_unreadable"
    elif shutil.which("firewall-cmd"):
        checks["firewall"]["mode"] = "firewalld"
    elif shutil.which("nft"):
        checks["firewall"]["mode"] = "nftables_or_external"
    checks["compose"] = {"version": None}
    for command in (["docker", "compose", "version", "--short"], ["docker-compose", "version", "--short"]):
        try:
            value = run(command)
            if re.fullmatch(r"v?[0-9][0-9A-Za-z.+-]{0,60}", value):
                checks["compose"] = {"version": value, "command": command[:2] if command[0] == "docker" else command[:1]}
                break
        except CheckError:
            pass
    return report
