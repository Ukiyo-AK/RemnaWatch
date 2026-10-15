"""Bounded host telemetry and pressure protection, without packet inspection."""
from pathlib import Path
import os
import platform
import re
import shutil
import stat
import threading
import time
import errno
from .network import NetworkProbe


class HostProbe:
    def __init__(self, proc="/proc", disk_paths=(), clock=time.monotonic, sys="/sys", origin="unknown"):
        self.proc, self.disk_paths, self.clock = Path(proc), list(disk_paths), clock
        self.previous_cpu = None
        self.previous_net = None
        self.lock = threading.Lock()
        self.network_probe = NetworkProbe(proc, sys, clock, origin=origin)

    def text(self, name):
        try:
            with (self.proc / name).open(encoding="utf-8") as source:
                return source.read(262144)
        except (OSError, UnicodeError):
            return ""

    def snapshot(self):
        with self.lock:
            mem = {}
            for line in self.text("meminfo").splitlines():
                key, _, value = line.partition(":")
                parts = value.split()
                if parts and parts[0].isdigit():
                    mem[key] = int(parts[0]) * 1024
            total, available = mem.get("MemTotal"), mem.get("MemAvailable")
            memory = {"total_bytes": total, "available_bytes": available,
                      "used_percent": 100 * (1 - available / total) if total and available is not None else None,
                      "swap_total_bytes": mem.get("SwapTotal"), "swap_free_bytes": mem.get("SwapFree")}
            cpu = {"logical_cpus": os.cpu_count(), "model": None, "usage_percent": None}
            for line in self.text("cpuinfo").splitlines():
                if line.startswith(("model name", "Hardware")):
                    cpu["model"] = line.partition(":")[2].strip()
                    break
            lines = self.text("stat").splitlines()
            if lines and lines[0].startswith("cpu "):
                # guest/guest_nice are already accounted for in user/nice.
                values = [int(v) for v in lines[0].split()[1:9]]
                current = (sum(values), values[3] + values[4])
                if self.previous_cpu:
                    delta, idle = current[0] - self.previous_cpu[0], current[1] - self.previous_cpu[1]
                    if delta > 0:
                        cpu["usage_percent"] = max(0, min(100, 100 * (1 - idle / delta)))
                self.previous_cpu = current
            network, interfaces = self.network_probe.sample()
            disks = []
            for path in dict.fromkeys(self.disk_paths):
                try:
                    usage = shutil.disk_usage(path)
                    vfs = os.statvfs(path) if hasattr(os, "statvfs") else None
                    disks.append({"path": str(path), "total_bytes": usage.total, "used_bytes": usage.used,
                                  "free_bytes": usage.free, "used_percent": 100 * usage.used / usage.total,
                                  "free_inodes": vfs.f_favail if vfs else None})
                except OSError:
                    disks.append({"path": str(path), "error": "unavailable"})
            uptime = self.text("uptime").split()
            return {"hostname": platform.node(), "os": platform.system(), "os_release": platform.release(),
                    "architecture": platform.machine(), "cpu": cpu, "memory": memory,
                    "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
                    "uptime_seconds": float(uptime[0]) if uptime else None,
                    "network": network, "interfaces": interfaces, "disks": disks,
                    "oom": {"panic_on_oom": self.text("sys/vm/panic_on_oom").strip() or None},
                    "telemetry_scope": "this process host/namespace; run on the node host for host metrics"}


class PressureGuard:
    def __init__(self, store, settings=None, active_logs=(), probe=None, disk_usage=shutil.disk_usage, required_logs=()):
        self.store, self.settings = store, settings or {}
        self.active_logs = {Path(p).resolve() for p in active_logs}
        self.required_logs = {Path(p).resolve() for p in required_logs}
        self.roots = [Path(p).resolve() for p in self.settings.get("log_directories", [])]
        self.probe = probe or HostProbe(disk_paths=[str(Path(store.path).resolve().parent), *map(str, self.roots)])
        self.disk_usage = disk_usage
        self.alerts, self.last_cleanup = [], None
        self.lock = threading.RLock()
        defaults = {"memory_pause_percent": 92, "memory_resume_percent": 85,
                    "disk_max_used_percent": 90, "disk_min_free_bytes": 268435456,
                    "min_rotated_age_seconds": 3600, "keep_event_seconds": 3600,
                    "keep_aggregate_seconds": 86400, "max_delete_files": 100}
        self.options = defaults | {k: v for k, v in self.settings.items() if k in defaults}
        o = self.options
        if not 0 < o["memory_resume_percent"] < o["memory_pause_percent"] < 100 or not 1 <= o["disk_max_used_percent"] <= 99:
            raise ValueError("invalid pressure thresholds")
        for key in ("disk_min_free_bytes", "min_rotated_age_seconds", "keep_event_seconds", "keep_aggregate_seconds", "max_delete_files"):
            if type(o[key]) is not int or o[key] < 1:
                raise ValueError("invalid pressure limits")
        if o["max_delete_files"] > 1000:
            raise ValueError("too many deletes per check")

    def _low_disk(self, path):
        u = self.disk_usage(path)
        return u.free < self.options["disk_min_free_bytes"] or u.used / u.total * 100 >= self.options["disk_max_used_percent"]

    def _clean_rotated(self, root):
        # Only explicitly enabled directories and recognizable rotated log filenames.
        pattern = re.compile(r"(?:access|error)\.log\.(?:\d{1,10}|\d{4}-\d{2}-\d{2})(?:\.gz)?$")
        cutoff = self.store.clock() - self.options["min_rotated_age_seconds"]
        candidates = []
        with os.scandir(root) as files:
            for index, entry in enumerate(files):
                if index >= 5000:
                    break
                if not pattern.fullmatch(entry.name) or entry.is_symlink():
                    continue
                path = Path(entry.path)
                info = path.lstat()
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mtime < cutoff and path.resolve() not in self.active_logs:
                    candidates.append((info.st_mtime, path, info.st_ino, info.st_dev))
        deleted = 0
        for _, path, inode, device in sorted(candidates):
            if deleted >= self.options["max_delete_files"] or not self._low_disk(root):
                break
            # Directory must be controlled by the operator; revalidate before unlink.
            info = path.lstat()
            if path.parent.resolve() != root or path.is_symlink() or info.st_ino != inode or info.st_dev != device or info.st_nlink != 1:
                continue
            path.unlink()
            deleted += 1
        return deleted

    def check(self):
        with self.lock:
            snapshot = self.probe.snapshot()
            alerts = []
            reasons = set(self.store.pause_reasons)
            percent = snapshot["memory"]["used_percent"]
            if percent is not None:
                if percent >= self.options["memory_pause_percent"]:
                    reasons.add("memory_pressure")
                elif percent <= self.options["memory_resume_percent"]:
                    reasons.discard("memory_pressure")
            if "memory_pressure" in reasons:
                alerts.append({"code": "memory_pressure", "severity": "critical", "used_percent": percent,
                               "message": "Domain ingestion paused; server reboot is never triggered by this guard"})
            dbroot = Path(self.store.path).resolve().parent
            deleted = 0
            for root in self.roots:
                required = self.store.policy.enabled and any(p == root or root in p.parents for p in self.required_logs)
                enabled = self.store.policy.enabled and any(p == root or root in p.parents for p in self.active_logs)
                stage = "check"
                try:
                    if not stat.S_ISDIR(root.stat().st_mode):
                        raise NotADirectoryError(errno.ENOTDIR, "log path is not a directory")
                    if self._low_disk(root):
                        alerts.append({"component": "log_storage", "code": "log_disk_pressure",
                                       "severity": "critical" if required else "warning" if enabled else "info", "path": str(root),
                                       "error_type": None, "errno": None, "required": bool(required),
                                       "impact": "log_writes_may_fail" if enabled else "optional_source_disabled",
                                       "remediation": "Review rotated-log retention and free space on this mount"})
                        if self.settings.get("delete_rotated_logs", True):
                            stage = "cleanup"
                            deleted += self._clean_rotated(root)
                except OSError as exc:
                    code = "log_directory_missing" if exc.errno == errno.ENOENT and stage == "check" else "log_directory_permission_denied" if exc.errno in (errno.EACCES, errno.EPERM) and stage == "check" else "log_directory_read_only" if exc.errno == errno.EROFS else "log_cleanup_failed" if stage == "cleanup" else "log_storage_io_error"
                    remedy = {"log_directory_missing": "Verify the configured host mount/path and the real Xray log source; do not create an empty substitute",
                              "log_directory_permission_denied": "Grant the service account access to the configured log directory",
                              "log_directory_read_only": "Check mount write permissions; disable rotated-log deletion if intentional",
                              "log_cleanup_failed": "Check ownership and permissions of rotated logs; host monitoring remains available",
                              "log_storage_io_error": "Check filesystem and mount health"}[code]
                    alerts.append({"component": "log_storage", "code": code, "legacy_code": "log_storage_unavailable",
                                   "severity": "critical" if required else "warning" if enabled else "info",
                                   "path": str(root), "error_type": type(exc).__name__,
                                   "errno": exc.errno if exc.errno in errno.errorcode else None,
                                   "required": bool(required), "impact": "optional_source_disabled" if not enabled else "connection_event_source_unavailable" if stage == "check" else "early_log_cleanup_unavailable",
                                   "remediation": remedy})
            try:
                if self._low_disk(dbroot):
                    alerts.append({"code": "history_disk_pressure", "severity": "critical", "path": str(dbroot)})
                    if self.settings.get("early_history_cleanup", True):
                        result = self.store.emergency_prune(self.options["keep_event_seconds"], self.options["keep_aggregate_seconds"])
                        self.last_cleanup = {"timestamp": int(self.store.clock()), "rotated_files_deleted": deleted, **result}
                if self._low_disk(dbroot):
                    reasons.add("disk_pressure")
                else:
                    reasons.discard("disk_pressure")
            except Exception as exc:
                # Disk-full SQLite errors must not crash the protection loop.
                reasons.add("disk_pressure")
                alerts.append({"code": "history_cleanup_failed", "severity": "critical", "error_type": type(exc).__name__})
            self.store.pause_reasons = reasons
            if deleted and not self.last_cleanup:
                self.last_cleanup = {"timestamp": int(self.store.clock()), "rotated_files_deleted": deleted}
            self.alerts = alerts
            return snapshot

    def status(self):
        with self.lock:
            return {"alerts": list(self.alerts), "collection_paused": bool(self.store.pause_reasons),
                    "diagnostics_version": 2,
                    "legacy_alerts": [{**a, "code": a.get("legacy_code", a["code"])} for a in self.alerts],
                    "pause_reasons": sorted(self.store.pause_reasons), "last_emergency_cleanup": self.last_cleanup,
                    "guarantees_no_oom_reboot": False}

    def run(self, stop):
        while not stop.is_set():
            try:
                self.check()
            except Exception as exc:
                with self.lock:
                    self.alerts = [{"code": "guard_check_failed", "severity": "critical", "error_type": type(exc).__name__}]
            stop.wait(10)
