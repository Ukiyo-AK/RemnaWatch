"""Install only missing distro dependencies; no OS upgrade, PPA or service restart.

Invoked after platform/init/architecture checks and only for --apply or explicit
--install-deps. Also usable from the Python-free shell bootstrap.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
from .preflight import CheckError, supported

REQUIRED_PACKAGES = ("python3", "python3-venv", "ca-certificates", "iproute2", "systemd")


def apt_error(output):
    text = output.lower()
    for needles, code, hint in (
        (("could not get lock", "unable to acquire", "is another process using it"), "dependencies_apt_locked", "Wait for the existing package manager to finish; never delete its lock files"),
        (("temporary failure resolving", "could not resolve", "couldn't resolve"), "dependencies_dns_failed", "Restore DNS resolution for the configured repositories and retry"),
        (("404  not found", "404 not found", "does not have a release file", "no installation candidate", "unable to locate package"), "dependencies_repository_unavailable", "Configure an available signed repository for this OS release; old releases may need vendor ESM/ELTS. Mirrors and trust are not rewritten automatically"),
        (("no space left", "not enough free space"), "dependencies_disk_full", "Free disk space and retry the package stage"),
        (("certificate verification failed", "certificate verify failed", "no_pubkey", "is not signed", "signatures couldn't be verified"), "dependencies_repository_trust_failed", "Check CA/keyring and system clock; do not disable TLS or signature verification"),
    ):
        if any(needle in text for needle in needles):
            return CheckError(code, hint)
    return CheckError("dependencies_apt_failed", "Check apt/dpkg health, disk, repository signatures and DNS locally; no repositories or trust settings were changed")


def package_command(args, timeout=600):
    """Suppress repository/proxy output; preserve operator's conffiles."""
    env = {**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
           "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "l",
           "NEEDRESTART_SUSPEND": "1", "UCF_FORCE_CONFFOLD": "1"}
    try:
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=env, text=True)
    except subprocess.TimeoutExpired:
        # Do not kill dpkg mid-transaction: timeout applies to planning/update,
        # actual apt install below has no Python-enforced timeout.
        raise CheckError("dependencies_timeout", "Check apt locks, DNS and signed repository availability; rerun after the package manager finishes") from None
    except OSError:
        raise CheckError("package_manager_unavailable", "Requires apt-get and dpkg-query from the distro") from None
    output = result.stdout + "\n" + result.stderr
    incomplete_update = args[-1:] == ["update"] and any(line.startswith(("Err:", "W: Failed to fetch", "W: Some index files failed")) for line in output.splitlines())
    if result.returncode or incomplete_update:
        raise apt_error(output)
    return result.stdout


def dependency_plan(runner=package_command, which=shutil.which, exists=lambda p: Path(p).is_file()):
    missing = []
    for package in REQUIRED_PACKAGES:
        try:
            installed = runner(["dpkg-query", "-W", "-f=${db:Status-Status}", package]).strip() == "installed"
        except CheckError:
            installed = False
        if not installed:
            missing.append(package)
    checks = (("python3", "python3"), ("ss", "iproute2"), ("systemctl", "systemd"))
    for tool, package in checks:
        if not which(tool) and package not in missing:
            missing.append(package)
    if not exists("/etc/ssl/certs/ca-certificates.crt") and "ca-certificates" not in missing:
        missing.append("ca-certificates")
    # A package marked installed may have lost files. Check the distro interpreter,
    # not an arbitrary python alias or a locally shadowing /usr/local executable.
    if which("python3"):
        try:
            runner(["/usr/bin/python3", "-I", "-c", "import ssl, sqlite3, venv"])
        except CheckError:
            for package in ("python3", "python3-venv"):
                if package not in missing:
                    missing.append(package)
    return missing


def install_dependencies(report, runner=package_command, planner=dependency_plan):
    # Never repair packages on an unsupported OS/container. report is read-only
    # inventory; revalidate explicit facts as a guard against accidental callers.
    if not report.get("supported"):
        raise CheckError("dependencies_platform_refused", "Run read-only preflight on a supported systemd host before dependency installation")
    supported(report["os"], report["os_version"], report["architecture"], True)
    if os.geteuid() != 0:
        raise CheckError("dependencies_root_required", "Run with sudo to install missing system packages")
    if shutil.disk_usage("/").free < 256 * 1024**2:
        raise CheckError("dependencies_disk_full", "Free at least 256 MiB before installing dependencies")
    missing = planner()
    if not missing:
        return {"status": "unchanged", "packages": []}
    if set(missing) - set(REQUIRED_PACKAGES):
        raise CheckError("dependencies_invalid_plan", "Only the fixed dependency allowlist can be installed")
    print("Installing missing RemnaWatch dependencies: " + ", ".join(missing), flush=True)
    runner(["apt-get", "-o", "DPkg::Lock::Timeout=60", "-o", "Acquire::Retries=2", "update"])
    options = ["-o", "DPkg::Lock::Timeout=60", "-o", "Dpkg::Options::=--force-confold",
               "--no-upgrade", "--no-remove", "--no-install-recommends", "--reinstall"]
    simulation = runner(["apt-get", *options, "--simulate", "install", *missing])
    for line in simulation.splitlines():
        if line.startswith("Remv "):
            raise CheckError("dependencies_conflict", "APT proposes removing existing packages; resolve the conflict manually")
        match = re.match(r"Inst \S+ \[([^\]]+)\] \((\S+)", line)
        if match and match[1] != match[2]:
            raise CheckError("dependencies_conflict", "APT requires upgrading existing packages; review this separately before rerunning")
    # APT/dpkg owns its locks. Never delete lock files or interrupt dpkg with a
    # subprocess timeout. Existing conffiles and running services are preserved.
    runner(["apt-get", *options, "-y", "install", *missing], timeout=None)
    remaining = planner()
    if remaining:
        raise CheckError("dependencies_verification_failed", "Packages were installed but required files/modules are still unavailable; inspect distro Python and package state")
    return {"status": "installed", "packages": missing}
