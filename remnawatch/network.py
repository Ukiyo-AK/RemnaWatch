"""Read-only per-interface measurements in the current network namespace."""
from pathlib import Path
import os
import time


class NetworkProbe:
    def __init__(self, proc="/proc", sys="/sys", clock=time.monotonic, wall=time.time, origin="unknown"):
        if origin not in ("host", "container", "unknown"):
            raise ValueError("invalid network origin")
        self.proc, self.sys, self.clock, self.wall = Path(proc), Path(sys), clock, wall
        self.origin = origin
        self.previous, self.known = None, set()
        self.healthy, self.error_code, self.sampled_at = None, "not_sampled", None
        self.last_success_at, self.errors = None, 0

    def read(self, path, limit=262144):
        with path.open(encoding="ascii") as source:
            value = source.read(limit + 1)
        if len(value) > limit:
            raise ValueError("source too large")
        return value

    def optional(self, path):
        try:
            return self.read(path, 8192).strip()
        except (OSError, ValueError, UnicodeError):
            return None

    def inventory(self, names):
        defaults = set()
        route = self.optional(self.proc / "net/route") or ""
        for line in route.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "00000000":
                try:
                    if int(parts[3], 16) & 1:
                        defaults.add(parts[0])
                except ValueError:
                    pass
        for line in (self.optional(self.proc / "net/ipv6_route") or "").splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00":
                defaults.add(fields[-1])
        rows = []
        for name in sorted(names):
            base = self.sys / "class/net" / name
            def number(file):
                value = self.optional(base / file)
                return int(value) if value and value.isdecimal() else None
            members = []
            try:
                members = sorted(p.name for p in (base / "brif").iterdir())[:1024]
            except OSError:
                members = (self.optional(base / "bonding/slaves") or "").split()[:1024]
            try:
                master = Path(os.readlink(base / "master")).name
            except OSError:
                master = None
            kind = "bridge" if (base / "bridge").is_dir() else "bond" if (base / "bonding").is_dir() else None
            speed = number("speed")
            rows.append({"interface": name, "ifindex": number("ifindex"),
                         "state": self.optional(base / "operstate"), "type": number("type"),
                         "kind": kind, "master": master, "members": members,
                         "loopback": number("type") == 772 if number("type") is not None else None,
                         "default_route": name in defaults, "capacity_bits_per_second": speed * 1000000 if speed and speed > 0 else None,
                         "capacity_origin": "driver_reported" if speed and speed > 0 else None,
                         "origin": self.origin})
        return rows

    def sample(self):
        now, sampled = self.clock(), self.wall()
        current, error = {}, None
        try:
            data = self.read(self.proc / "net/dev")
            for line in data.splitlines():
                if ":" not in line:
                    continue
                name, data = line.split(":", 1)
                fields, name = data.split(), name.strip()
                if len(fields) < 16 or not name or "/" in name or len(current) >= 1024:
                    raise ValueError("invalid interface source")
                rx, tx = int(fields[0]), int(fields[8])
                if rx < 0 or tx < 0:
                    raise ValueError("invalid counter")
                current[name] = (rx, tx)
            if not current:
                raise ValueError("empty interface source")
        except PermissionError:
            error = "permission_denied"
        except FileNotFoundError:
            error = "source_missing"
        except (OSError, ValueError, UnicodeError):
            error = "source_read_error"
        if error:
            current = {}
        names = set(current) | self.known
        try:
            with os.scandir(self.sys / "class/net") as interfaces:
                for index, interface in enumerate(interfaces):
                    if index >= 1024:
                        break
                    names.add(interface.name)
        except OSError:
            pass
        inventory = self.inventory(names)
        indexes = {r["interface"]: r["ifindex"] for r in inventory}
        rows = []
        for name in sorted(names):
            rx, tx = current.get(name, (None, None))
            reason = (error or ("interface_disappeared" if name in self.known else "counter_unavailable")) if name not in current else "first_sample"
            interval, rx_rate, tx_rate, reset = None, None, None, False
            if name in current and self.previous:
                then, before, previous_indexes = self.previous
                if name in before:
                    interval = now - then
                    reset = rx < before[name][0] or tx < before[name][1] or indexes[name] != previous_indexes.get(name)
                    if reset:
                        reason = "counter_reset"
                    elif interval <= 0:
                        reason, interval = "invalid_interval", None
                    else:
                        rx_rate, tx_rate = (rx - before[name][0]) / interval, (tx - before[name][1]) / interval
                        reason = None
            rows.append({"interface": name, "rx_bytes": rx, "tx_bytes": tx,
                         "rx_bytes_per_second": rx_rate, "tx_bytes_per_second": tx_rate,
                         "available": name in current, "sampled_at": sampled,
                         "sample_interval_seconds": interval, "counter_reset": reset,
                         "error_code": reason, "origin": self.origin})
        self.previous = None if error else (now, current, indexes)
        if not error:
            self.known = set(current)
        self.healthy, self.error_code, self.sampled_at = error is None, error, sampled
        if error:
            self.errors += 1
        else:
            self.last_success_at = sampled
        return rows, inventory
