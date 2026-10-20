"""Source health is independent of SQLite history and management privileges."""
import threading
import time
import platform


class Sources:
    def __init__(self, config=None, health=None, live=None, clock=time.time):
        self.config, self.health, self.live, self.clock = config or {}, health, live, clock
        self.lock = threading.RLock()
        self.events = {}
        for index, source in enumerate(self.config.get("access_logs", [])):
            self.events[index] = {"id": f"access_log_{index}", "component": "connection_events", "supported": True,
                                  "configured": self.config.get("domains", {}).get("enabled", True) and source.get("enabled", True),
                                  "required": source.get("required", False), "healthy": None, "sampled_at": None,
                                  "error_code": "not_sampled", "lag_seconds": None, "lost_events": None,
                                  "errors": 0, "last_event_at": None, "last_success_at": None,
                                  "lag_bytes": None, "skipped_events": 0,
                                  "permissions": "read access to existing log file", "limitations": ["accepted events are not live sessions"]}

    def event_result(self, index, *, error=None, lag_bytes=None, gaps=0, gap_reason=None,
                     last_event_at=None, skipped_events=None, parse_errors=None, read_seconds=None, storage_seconds=None):
        with self.lock:
            state = self.events[index]
            state.update(healthy=error is None, sampled_at=self.clock(), error_code=error,
                         lag_bytes=lag_bytes, lag_seconds=None, observed_gaps=gaps, last_gap_reason=gap_reason)
            state.update(read_seconds=read_seconds, storage_seconds=storage_seconds)
            if skipped_events is not None:
                state["skipped_events"] = skipped_events
            if parse_errors is not None:
                state["parse_errors"] = dict(parse_errors)
            if last_event_at is not None:
                state["last_event_at"] = last_event_at
            if error is None:
                state["last_success_at"] = state["sampled_at"]
            state["event_age_seconds"] = max(0, state["sampled_at"] - state["last_event_at"]) if state["last_event_at"] is not None else None
            if error:
                state["errors"] += 1

    def report(self):
        with self.lock:
            states = [dict(s) for s in self.events.values()]
        if self.health:
            probe = getattr(self.health.probe, "network_probe", None)
            states.append({"id": "host_network_rates", "component": "host_network_rates", "supported": probe is not None and platform.system() == "Linux",
                           "configured": True, "healthy": probe.healthy if probe else None,
                           "sampled_at": probe.sampled_at if probe else None, "error_code": probe.error_code if probe else "unavailable",
                           "last_success_at": probe.last_success_at if probe else None,
                           "errors": probe.errors if probe else None,
                           "permissions": "read /proc/net/dev and interface metadata; no root required",
                           "limitations": ["current network namespace", "no aggregate across NIC/bridge/bond"]})
            states.append({"id": "history_storage", "component": "history_storage", "supported": True,
                           "configured": self.config.get("domains", {}).get("enabled", True),
                           "healthy": self.health.store.persistence_available,
                           "error_code": None if self.health.store.persistence_available else "history_storage_unavailable",
                           "permissions": "write database directory", "limitations": ["management mutations disabled when durable audit is unavailable"]})
        if self.live:
            states.append({"id": "live_connections", **self.live.status()})
        if getattr(self, "user_metrics", None):
            states.append(self.user_metrics.status())
        if getattr(self, "central_history", None):
            states.append(self.central_history.status())
        if getattr(self, "probe_state", None):
            states.append({"id": "browser_probe", "component": "browser_https_probe", **self.probe_state})
        for state in states:
            for key in ("last_event_at", "last_success_at", "lag_bytes", "errors", "skipped_events"):
                state.setdefault(key, None)  # Unknown is never presented as measured zero.
        return {"diagnostics_version": 2, "sampled_at": self.clock(), "sources": states,
                "storage": self.health.status() if self.health else None,
                "sensitive_fields_redacted": True}

    def capabilities(self):
        report = self.report()
        network = next((s for s in report["sources"] if s["component"] == "host_network_rates"), {})
        events = [s for s in report["sources"] if s["component"] == "connection_events"]
        configured_events = [s for s in events if s["configured"]]
        event_health = None if not configured_events or any(s["healthy"] is None for s in configured_events) else True
        if any(s["healthy"] is False for s in configured_events):
            event_health = False
        live = self.live.status() if self.live else {}
        def flags(state):
            return {"supported": state.get("supported", False), "configured": state.get("configured", False), "healthy": state.get("healthy")}
        capabilities = {"host_network_rates": flags(network),
                        "connection_events": {"supported": True, "configured": bool(configured_events),
                                              "healthy": event_health},
                        "live_connections": {**flags(live), "measurement_scope": "transport_socket", "user_attribution": False},
                        "per_connection_bytes": {"supported": False, "configured": False, "healthy": None},
                        "per_connection_rates": {"supported": False, "configured": False, "healthy": None},
                        "connection_duration": {"supported": False, "configured": False, "healthy": None},
                        "application_streams": {"supported": False, "configured": False, "healthy": None}}
        capabilities["user_rates"] = flags(self.user_metrics.status()) if getattr(self, "user_metrics", None) else {"supported": True, "configured": False, "healthy": None}
        capabilities["exact_user_rate_limit"] = {"supported": False, "configured": False, "healthy": None}
        return {"api_version": "v1", "capabilities": capabilities}
