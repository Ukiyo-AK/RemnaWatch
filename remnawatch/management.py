"""Opt-in Linux administration. API accepts actions, never shell command strings."""
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import platform
import queue
import re
import stat
import subprocess
import signal
import threading
import time
import selectors


class Unsupported(RuntimeError):
    pass


class Conflict(RuntimeError):
    pass


def run_command(argv, timeout=600):
    capture = len(argv) > 1 and argv[1] == "-j" and argv[0] == "/usr/sbin/tc"
    # Only short tc JSON inspections are captured; update output never fills RAM/disk.
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                shell=False, start_new_session=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "HOME": "/root"})
    deadline, data = time.monotonic() + timeout, bytearray()
    try:
        if capture:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    for key, _ in selector.select(min(remaining, 0.5)):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            data.extend(chunk)
                            if len(data) > 65536:
                                raise RuntimeError("command output exceeded budget")
        result = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if result:
            raise RuntimeError("command failed with exit code " + str(result))
        return data.decode("utf-8", errors="replace")
    except Exception:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        raise
    finally:
        if child.stdout:
            child.stdout.close()


class Manager:
    ACTIONS = ("server_reboot", "xray_restart", "xray_update", "node_restart", "node_update",
               "os_kernel_update", "traffic_limits", "traffic_clear", "oom_protection")

    def __init__(self, store, settings=None, runner=run_command, os_name=None):
        self.store, self.settings, self.runner = store, settings or {}, runner
        self.os_name = os_name or platform.system()
        self.lock = threading.RLock()
        self.queue = queue.Queue(maxsize=1)
        self.thread = None
        self.stop = threading.Event()
        with store.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS server_jobs(id TEXT PRIMARY KEY, fingerprint TEXT, created INTEGER, updated INTEGER, status TEXT, document TEXT)")
            # Never retry a reboot/update automatically after process failure.
            rows = db.execute("SELECT id,document FROM server_jobs WHERE status IN ('queued','running')").fetchall()
            for row in rows:
                doc = json.loads(row["document"])
                doc.update(status="interrupted", error="Service restarted; verify host state before retrying")
                db.execute("UPDATE server_jobs SET status='interrupted',document=? WHERE id=?", (json.dumps(doc), row["id"]))

    def start(self):
        if not self.thread:
            self.thread = threading.Thread(target=self._worker, daemon=True)
            self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=2)

    def _compose(self):
        config = self.settings.get("compose_file")
        service = self.settings.get("compose_service", "remnanode")
        if not config or not isinstance(config, str) or not PurePosixPath(config).is_absolute() or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", service):
            raise Unsupported("Absolute compose_file and valid compose_service required")
        return ["/usr/bin/docker", "compose", "--project-directory", str(PurePosixPath(config).parent), "-f", str(config)], service

    def plan(self, action, params=None):
        if self.os_name != "Linux":
            raise Unsupported("Server management requires Linux")
        if action not in self.ACTIONS:
            raise ValueError("unknown action")
        p = {} if params is None else params
        if not isinstance(p, dict):
            raise ValueError("params must be object")
        commands, warnings, scope = [], [], "host"
        if action not in ("traffic_limits", "traffic_clear", "oom_protection") and p:
            raise ValueError("this action takes no params")
        if action == "server_reboot":
            commands = [["/usr/sbin/shutdown", "-r", "+1", "RemnaWatch requested reboot"]]
            warnings = ["All host connections will be interrupted; OS reboot scheduled in one minute"]
        elif action == "xray_restart" and self.settings.get("xray_service"):
            unit = self.settings["xray_service"]
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}\.service", unit):
                raise ValueError("invalid systemd service")
            commands = [["/usr/bin/systemctl", "restart", unit]]
            scope, warnings = "xray", ["Active Xray connections will be interrupted"]
        elif action in ("node_restart", "node_update", "xray_update", "xray_restart"):
            if action == "xray_update" and self.settings.get("xray_service"):
                hook = self.settings.get("xray_update_hook")
                if not hook or not isinstance(hook, str) or not PurePosixPath(hook).is_absolute():
                    raise Unsupported("Standalone Xray update requires operator-installed root-owned update hook")
                commands, scope = [[hook]], "xray"
            else:
                compose, service = self._compose()
                scope = "node_including_xray"
                if action in ("node_update", "xray_update"):
                    commands = [compose + ["pull", service], compose + ["up", "-d", "--no-deps", service]]
                    warnings.append("Uses configured image tag; review its version beforehand. No automatic rollback")
                else:
                    commands = [compose + ["restart", service]]
            warnings.append("Node/core restart interrupts active connections")
        elif action == "os_kernel_update":
            package = self.settings.get("os_kernel_package")
            if package not in ("linux-generic", "linux-image-amd64", "linux-image-arm64"):
                raise Unsupported("Supported Debian/Ubuntu kernel metapackage must be configured explicitly")
            commands = [["/usr/bin/apt-get", "update"], ["/usr/bin/apt-get", "install", "-y", "--only-upgrade", package]]
            warnings = ["Debian/Ubuntu only; separate OS reboot required to activate new kernel; no auto reboot"]
            scope = "os_kernel"
        elif action in ("traffic_limits", "traffic_clear"):
            allowed = {"interface", "tx_mbps", "rx_mbps"} if action == "traffic_limits" else {"interface"}
            if set(p) - allowed:
                raise ValueError("invalid traffic parameters")
            interface = p.get("interface", "")
            if interface not in self.settings.get("interfaces", []) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", interface):
                raise ValueError("interface is not allowlisted")
            scope = "interface:" + interface
            if action == "traffic_limits":
                tx, rx = p.get("tx_mbps"), p.get("rx_mbps")
                if any(type(v) is not int or not 1 <= v <= 100000 for v in (tx, rx)):
                    raise ValueError("TX/RX must be integer Mbit/s from 1 to 100000")
                burst = max(65536, tx * 125000 // 10)
                rxburst = max(65536, rx * 125000 // 10)
                commands = [["/usr/sbin/tc", "qdisc", "add", "dev", interface, "root", "handle", "7a10:", "tbf", "rate", f"{tx}mbit", "burst", str(burst), "latency", "100ms"],
                            ["/usr/sbin/tc", "qdisc", "add", "dev", interface, "handle", "ffff:", "ingress"],
                            ["/usr/sbin/tc", "filter", "add", "dev", interface, "parent", "ffff:", "protocol", "all", "pref", "49152", "handle", "1", "matchall", "action", "police", "rate", f"{rx}mbit", "burst", str(rxburst), "conform-exceed", "drop"]]
                warnings = ["TX uses TBF shaping; RX policing drops excess packets and may affect SSH/panel access", "Refuses existing custom root/ingress qdiscs; clear managed limits before changing them"]
            else:
                commands = [["/usr/sbin/tc", "qdisc", "del", "dev", interface, "root", "handle", "7a10:"],
                            ["/usr/sbin/tc", "qdisc", "del", "dev", interface, "ingress"]]
                warnings = ["Only removes rules created by this service after ownership checks"]
        elif action == "oom_protection":
            if set(p) - {"service", "memory_high_mb", "memory_max_mb"}:
                raise ValueError("invalid memory parameters")
            commands = [["/usr/sbin/sysctl", "-w", "vm.panic_on_oom=0"]]
            if p:
                unit, high, maximum = p.get("service"), p.get("memory_high_mb"), p.get("memory_max_mb")
                if unit not in self.settings.get("memory_services", []) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127}\.service", unit or ""):
                    raise ValueError("memory service is not allowlisted")
                if type(high) is not int or type(maximum) is not int or not 16 <= high < maximum <= 1048576:
                    raise ValueError("memory_high_mb must be less than memory_max_mb")
                commands.append(["/usr/bin/systemctl", "set-property", "--runtime", unit, f"MemoryHigh={high}M", f"MemoryMax={maximum}M"])
            warnings = ["Runtime settings only; Linux may kill processes on OOM; no absolute reboot guarantee", "MemoryMax can terminate the selected service; no swap or watchdog policy is changed"]
        return {"action": action, "params": p, "scope": scope, "commands": commands,
                "warnings": warnings, "execution_enabled": self.settings.get("enabled", False), "dry_run": True}

    def capabilities(self):
        results = {}
        for action in self.ACTIONS:
            try:
                params = {"interface": (self.settings.get("interfaces") or [""])[0], "tx_mbps": 100, "rx_mbps": 100} if action == "traffic_limits" else {"interface": (self.settings.get("interfaces") or [""])[0]} if action == "traffic_clear" else {}
                plan = self.plan(action, params)
                results[action] = {"configured": True, "scope": plan["scope"]}
            except (ValueError, Unsupported) as exc:
                results[action] = {"configured": False, "reason": str(exc)}
        return {"enabled": self.settings.get("enabled", False), "platform": self.os_name,
                "actions": results, "availability_requires": "host privileges, installed tools, verified deployment configuration"}

    def submit(self, body):
        if not isinstance(body, dict) or set(body) - {"action", "params", "dry_run", "request_id"}:
            raise ValueError("invalid action body")
        dry = body.get("dry_run", True)
        if type(dry) is not bool:
            raise ValueError("dry_run must be boolean")
        plan = self.plan(body.get("action"), body.get("params"))
        if dry:
            return plan
        if self.settings.get("enabled") is not True:
            raise PermissionError("Server mutations disabled by configuration")
        identity = body.get("request_id", "")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{8,80}", identity):
            raise ValueError("real execution requires request_id (8..80 alphanumeric, underscore or dash)")
        fingerprint = hashlib.sha256(json.dumps([plan["action"], plan["params"]], sort_keys=True).encode()).hexdigest()
        plan["dry_run"] = False
        with self.lock, self.store.transaction() as db:
            existing = db.execute("SELECT * FROM server_jobs WHERE id=?", (identity,)).fetchone()
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise Conflict("request_id was already used for a different action")
                return json.loads(existing["document"])
            if db.execute("SELECT 1 FROM server_jobs WHERE status IN ('queued','running')").fetchone():
                raise Conflict("Another server operation is in progress")
            now = int(self.store.clock())
            if now < int(self.store.state("server_reboot_until", "0")):
                raise Conflict("OS reboot is scheduled; wait for host restart before other operations")
            if self.store.pause_reasons:
                raise Conflict("Resource pressure: server mutations are temporarily blocked")
            db.execute("DELETE FROM server_jobs WHERE created<? AND status NOT IN ('running','queued')", (now - 30 * 86400,))
            if db.execute("SELECT count(*) FROM server_jobs").fetchone()[0] >= 10000:
                raise Conflict("Audit job limit reached")
            doc = {"id": identity, "status": "queued", "created": now, "updated": now, "plan": plan, "completed_steps": 0}
            db.execute("INSERT INTO server_jobs VALUES (?,?,?,?,?,?)", (identity, fingerprint, now, now, "queued", json.dumps(doc)))
        self.start()
        self.queue.put_nowait(identity)
        return doc

    def jobs(self, identity=None, limit=100, offset=0):
        if not 1 <= limit <= 500 or not 0 <= offset <= 100000:
            raise ValueError("invalid pagination")
        with self.store.lock:
            if identity:
                row = self.store.db.execute("SELECT document FROM server_jobs WHERE id=?", (identity,)).fetchone()
                if not row:
                    raise LookupError("unknown job")
                return json.loads(row[0])
            total = self.store.db.execute("SELECT count(*) FROM server_jobs").fetchone()[0]
            rows = self.store.db.execute("SELECT document FROM server_jobs ORDER BY created DESC,id LIMIT ? OFFSET ?", (limit, offset))
            return {"items": [json.loads(r[0]) for r in rows], "total": total, "limit": limit, "offset": offset}

    def _save(self, doc):
        doc["updated"] = int(self.store.clock())
        with self.store.transaction() as db:
            db.execute("UPDATE server_jobs SET updated=?,status=?,document=? WHERE id=?", (doc["updated"], doc["status"], json.dumps(doc), doc["id"]))

    def _verify_deployment(self, plan):
        if os.geteuid() != 0:
            raise PermissionError("Server mutations require root privileges on the Linux host")
        if plan["action"] in ("node_update", "node_restart") or plan["scope"] == "node_including_xray":
            path = Path(self.settings["compose_file"])
            self._trusted_file(path)
            # Compose-relative env files and mounts are operator-controlled too.
            self._trusted_file(path.parent, directory=True)
        if plan["action"] == "xray_update" and plan["scope"] == "xray":
            self._trusted_file(Path(plan["commands"][0][0]), executable=True)
        for command in plan["commands"]:
            if not Path(command[0]).is_file():
                raise Unsupported("Required system executable is unavailable")

    @staticmethod
    def _trusted_file(path, directory=False, executable=False):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Deployment file/directory must be root-owned and not writable by group/others")
        if directory and not stat.S_ISDIR(info.st_mode) or not directory and not stat.S_ISREG(info.st_mode):
            raise PermissionError("Invalid deployment file type")
        if executable and not info.st_mode & 0o100:
            raise PermissionError("Update hook is not executable")

    def _traffic(self, plan, doc):
        interface = plan["params"]["interface"]
        qdiscs = json.loads(self.runner(["/usr/sbin/tc", "-j", "qdisc", "show", "dev", interface], 10))
        roots = [q for q in qdiscs if q.get("root")]
        ingress = [q for q in qdiscs if q.get("kind") in ("ingress", "clsact")]
        owned = json.loads(self.store.state("tc_owned:" + interface, "null"))
        if plan["action"] == "traffic_clear":
            if not owned:
                raise Conflict("No managed traffic rules to remove")
            if len(roots) != 1 or roots[0].get("handle") != "7a10:" or roots[0].get("kind") != "tbf" or len(ingress) != 1 or ingress[0].get("kind") != "ingress":
                raise Conflict("Traffic rules changed externally; refusing to remove foreign configuration")
            filters = json.loads(self.runner(["/usr/sbin/tc", "-j", "filter", "show", "dev", interface, "parent", "ffff:"], 10))
            if not filters or any(f.get("pref") != 49152 or f.get("kind") != "matchall" for f in filters):
                raise Conflict("Ingress filters changed externally")
            for command in plan["commands"]:
                self.runner(command, 10)
                doc["completed_steps"] += 1
                self._save(doc)
            with self.store.transaction() as db:
                db.execute("DELETE FROM state WHERE key=?", ("tc_owned:" + interface,))
            return
        if ingress or any(q.get("handle") != "0:" or q.get("kind") not in ("noqueue", "fq_codel", "pfifo_fast", "fq") for q in roots):
            raise Conflict("Custom root/ingress rules already exist; no changes made")
        rollback = []
        try:
            for index, command in enumerate(plan["commands"]):
                self.runner(command, 10)
                if index == 0:
                    rollback.append(["/usr/sbin/tc", "qdisc", "del", "dev", interface, "root", "handle", "7a10:"])
                elif index == 1:
                    rollback.append(["/usr/sbin/tc", "qdisc", "del", "dev", interface, "ingress"])
                doc["completed_steps"] += 1
                self._save(doc)
        except Exception:
            doc["rollback"] = "attempted"
            for command in reversed(rollback):
                try:
                    self.runner(command, 10)
                except Exception:
                    doc["rollback"] = "failed; inspect tc state manually"
            raise
        with self.store.transaction() as db:
            db.execute("INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", ("tc_owned:" + interface, json.dumps(plan["params"])))

    def _worker(self):
        while not self.stop.is_set():
            try:
                identity = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            doc = self.jobs(identity)
            try:
                doc["status"] = "running"
                self._save(doc)
                plan = doc["plan"]
                if self.runner is run_command:
                    self._verify_deployment(plan)
                if plan["action"].startswith("traffic_"):
                    self._traffic(plan, doc)
                else:
                    for command in plan["commands"]:
                        self.runner(command, 600)
                        doc["completed_steps"] += 1
                        self._save(doc)
                doc["status"] = "succeeded"
                if plan["action"] == "server_reboot":
                    doc["result"] = "OS reboot scheduled; this is not proof of completed reboot"
                    with self.store.transaction() as db:
                        db.execute("INSERT INTO state VALUES ('server_reboot_until',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(int(self.store.clock()) + 120),))
            except Exception as exc:
                doc["status"] = "failed"
                # Do not expose arbitrary command output, paths with secrets, or env files.
                doc["error"] = str(exc) if isinstance(exc, (Conflict, Unsupported, PermissionError)) else type(exc).__name__ + ": execution failed; inspect host logs"
            finally:
                self._save(doc)
                self.queue.task_done()
