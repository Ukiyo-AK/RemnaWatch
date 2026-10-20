"""Opt-in, read-only Xray user counters. Never reset counters or enable policies."""
from collections import deque
import json
import math
import re
import threading
import time
from uuid import UUID
from .preflight import run, CheckError


def user_uuid(value):
    parsed = UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError("canonical Remnawave UUID required")
    return value


def limit_status(user_id):
    user_uuid(user_id)
    return {"user_id": user_id, "supported": False, "state": "unsupported", "applied": False,
            "error_code": "exact_user_shaping_unavailable",
            "reason": "No verified aggregate UUID shaping backend in this Node/Xray combination; no node-wide fallback",
            "expires_at": None}


class SustainedLoad:
    """Conservative continuous exceedance: gaps/low samples reset the episode.

    No sanctions or external messages. Consumes exact user totals only. Memory is
    bounded; losing state can delay a warning, never produce an unmeasured one.
    """
    def __init__(self, config=None):
        config = config or {}
        self.enabled = config.get("enabled", False)
        self.capacity = config.get("capacity_mbps", 0) * 1_000_000 / 8
        self.fraction = config.get("fraction", 0.5)
        self.window = config.get("window_seconds", 600)
        self.minimum = config.get("minimum_bytes", 100_000_000)
        self.samples = config.get("consecutive_samples", 3)
        if self.enabled and (not math.isfinite(self.capacity) or self.capacity <= 0 or not 0 < self.fraction <= 1
                             or not 1 <= self.window <= 86400 or self.minimum < 0 or not 2 <= self.samples <= 10000):
            raise ValueError("invalid sustained load rule")
        self.states = {}
        self.events = deque(maxlen=500)

    def reset(self):
        self.states.clear()

    def observe(self, row):
        if not self.enabled:
            return
        identity = row["user_id"]
        rate = row.get("rx_bytes_per_second")
        tx = row.get("tx_bytes_per_second")
        interval = row.get("sample_interval_seconds")
        now = row["sampled_at"]
        if not row.get("available") or rate is None or tx is None or not interval or (rate + tx) < self.capacity * self.fraction:
            self.states.pop(identity, None)
            return
        if identity not in self.states and len(self.states) >= 20000:
            return
        state = self.states.get(identity)
        if not state or not 0 < now - state["last"] <= interval * 1.5:
            state = {"last": now - interval, "duration": 0, "bytes": 0, "samples": 0, "notified": False}
            self.states[identity] = state
        state.update(last=now, duration=state["duration"] + interval,
                     bytes=state["bytes"] + (rate + tx) * interval, samples=state["samples"] + 1)
        if not state["notified"] and state["duration"] >= self.window and state["bytes"] >= self.minimum and state["samples"] >= self.samples:
            average = state["bytes"] / state["duration"]
            self.events.append({"type": "sustained_user_load", "user_id": identity, "node_id": row["node_id"],
                                "sampled_at": now, "duration_seconds": state["duration"],
                                "bytes_per_second": average, "capacity_fraction": average / self.capacity,
                                "telegram_id": None, "user_card_path": "/users/" + identity,
                                "automatic_sanction": False})
            state["notified"] = True


class UserMetrics:
    def __init__(self, node_id, users, config=None, runner=run, clock=time.time, monotonic=time.monotonic):
        self.node_id, self.users, self.config = node_id, users, config or {}
        self.runner, self.clock, self.monotonic = runner, clock, monotonic
        self.enabled = self.config.get("enabled", False)
        self.mapping_verified = self.config.get("mapping_verified") is True
        self.container = self.config.get("container", "")
        self.server = self.config.get("server", "")
        if self.enabled and (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", self.container)
                             or not re.fullmatch(r"127\.0\.0\.1:[0-9]{1,5}", self.server)
                             or not 1 <= int(self.server.rsplit(":", 1)[1]) <= 65535):
            raise ValueError("Explicit existing loopback Xray StatsService and container required")
        self.lock = threading.RLock()
        self.previous = None
        self.rows = {}
        self.error = "not_sampled" if self.enabled else "not_configured"
        self.sampled_at = None
        self.last_success_at = None
        self.errors = 0
        self.load = SustainedLoad(self.config.get("sustained_load"))
        # StatsService keys contain email, not inbound. Accept only if ALL mappings
        # for this email on this node agree on one UUID. Never infer from client IP.
        emails = {}
        for (node, inbound, email), user in users.entries.items():
            if node == node_id and self.enabled:
                user_uuid(user)
                emails.setdefault(email, set()).add(user)
        self.mapping = {email: next(iter(ids)) for email, ids in emails.items() if len(ids) == 1}

    def sample(self):
        # Docker/StatsService can stall. Never hold the API snapshot lock during I/O.
        raw, failure = None, None
        if self.enabled and self.mapping_verified:
            try:
                raw = self.runner(["docker", "exec", self.container, "xray", "api", "statsquery",
                                   "--server=" + self.server, "-timeout", "3", "-pattern", "user>>>", "-reset=false"])
            except (CheckError, OSError) as exc:
                failure = exc
        with self.lock:
            self.sampled_at = self.clock()
            if not self.enabled:
                return
            if not self.mapping_verified:
                self.error, self.previous, self.rows = "user_mapping_not_verified", None, {}
                self.load.reset()
                return
            try:
                if failure:
                    raise CheckError("user_counters_unavailable", "Check existing StatsService")
                if len(raw) > 4 * 1024 * 1024:
                    raise ValueError()
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError()
                stats = data.get("stat", [])
                if not isinstance(stats, list) or len(stats) > 40000:
                    raise ValueError()
                counters, seen, components = {}, set(), {}
                for item in stats:
                    name, value = item["name"], item["value"]
                    match = re.fullmatch(r"user>>>(.{1,512})>>>traffic>>>(uplink|downlink)", name)
                    if not match:
                        continue
                    if name in seen or isinstance(value, bool) or not re.fullmatch(r"[0-9]{1,19}", str(value)) or int(value) >= 2**63:
                        raise ValueError()
                    seen.add(name)
                    user = self.mapping.get(match[1])
                    if user:
                        counters.setdefault(user, {})[match[2]] = counters.setdefault(user, {}).get(match[2], 0) + int(value)
                        components.setdefault(user, {})[name] = int(value)
                now = self.monotonic()
                old_time, old, old_components = self.previous or (now, {}, {})
                interval = now - old_time
                rows = {}
                for user, values in counters.items():
                    before = old.get(user, {})
                    valid = (0 < interval <= 60 and set(values) == set(before) == {"uplink", "downlink"}
                             and components[user].keys() == old_components.get(user, {}).keys()
                             and all(value >= old_components[user][name] for name, value in components[user].items()))
                    row = {"node_id": self.node_id, "user_id": user, "sampled_at": self.sampled_at,
                           "sample_interval_seconds": interval if valid else None, "source": "xray_stats_user_totals",
                           "available": valid, "error_code": None if valid else "first_sample_reset_or_gap",
                           "rx_bytes_per_second": (values["uplink"] - before["uplink"]) / interval if valid else None,
                           "tx_bytes_per_second": (values["downlink"] - before["downlink"]) / interval if valid else None,
                           "scope": "all_user_connections", "direction": "node_proxy_uplink_downlink"}
                    rows[user] = row
                    self.load.observe(row)
                for missing in set(self.rows) - set(rows):
                    self.load.states.pop(missing, None)
                self.rows, self.previous = rows, (now, counters, components)
                self.error = None if counters else "no_mapped_user_counters"
                self.last_success_at = self.sampled_at
            except (CheckError, ValueError, TypeError, KeyError, OverflowError):
                self.previous, self.rows, self.error = None, {}, "user_counters_unavailable"
                self.errors += 1
                self.load.reset()

    def status(self):
        with self.lock:
            return {"id": "user_rates", "component": "user_rates", "configured": self.enabled,
                    "supported": True, "healthy": self.error is None if self.enabled else None,
                    "error_code": self.error, "sampled_at": self.sampled_at, "last_success_at": self.last_success_at,
                    "errors": self.errors, "skipped_events": None,
                    "source": "xray_stats_user_totals", "exact_user_rate_limit_supported": False}

    def get(self, user):
        user_uuid(user)
        with self.lock:
            result = dict(self.rows.get(user) or {"node_id": self.node_id, "user_id": user,
                       "sampled_at": self.sampled_at, "available": False, "sample_interval_seconds": None,
                       "rx_bytes_per_second": None, "tx_bytes_per_second": None,
                       "source": "xray_stats_user_totals", "error_code": self.error or "user_counters_missing"})
            if result.get("sampled_at") is not None and self.clock() - result["sampled_at"] > 60:
                result.update(available=False, rx_bytes_per_second=None, tx_bytes_per_second=None,
                              sample_interval_seconds=None, error_code="stale_sample")
            return result

    def events(self, limit=100, offset=0):
        if not 1 <= limit <= 500 or not 0 <= offset <= 100000:
            raise ValueError("invalid pagination")
        with self.lock:
            rows = list(reversed(self.load.events))
            return {"items": rows[offset:offset + limit], "total": len(rows), "limit": limit, "offset": offset}

    def run(self, stop):
        while not stop.is_set():
            self.sample()
            stop.wait(5)
