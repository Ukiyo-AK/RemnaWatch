import argparse
import json
import threading
import sqlite3
from .api import make_server
from .collector import Tailer, NetworkSampler, run_collector
from .events import AccessParser, UserMap
from .store import Policy, Store
from .management import Manager
from .health import PressureGuard
from .auth import resolve_auth
from .live import LiveConnections
from .diagnostics import Sources


def main():
    parser = argparse.ArgumentParser(description="Passive Xray domain activity monitoring")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as source:
        config = json.load(source)
    # Fail invalid/missing credentials before opening or purging any stored history.
    auth = resolve_auth(config)
    try:
        store = Store(config.get("database", "domains.sqlite"), Policy(**config.get("domains", {})))
    except (sqlite3.Error, OSError):
        store = Store(":memory:", Policy(enabled=False))
        store.persistence_available = False
    mapping_error = False
    try:
        users = UserMap(config.get("users", []), require_uuid=config.get("strict_user_uuid", True))
    except (ValueError, TypeError, KeyError):
        users, mapping_error = UserMap([]), True
    management = dict(config.get("management", {}))
    if not store.persistence_available:
        management["enabled"] = False  # No privileged operation without durable audit.
    manager = Manager(store, management)
    logs = [log for log in config.get("access_logs", []) if log.get("enabled", True)]
    health = PressureGuard(store, config.get("protection", {}), [log["path"] for log in logs],
                           required_logs=[log["path"] for log in logs if log.get("required", False)])
    health.probe.network_probe.origin = config.get("network_origin", "unknown")
    if health.probe.network_probe.origin not in ("unknown", "host", "container"):
        raise ValueError("invalid network_origin")
    live = LiveConnections.from_config(auth.node_id, config.get("live_connections", {}))
    diagnostics = Sources(config, health, live)
    if not store.persistence_available:
        for index in diagnostics.events:
            diagnostics.event_result(index, error="history_storage_unavailable")
    elif mapping_error:
        for index in diagnostics.events:
            diagnostics.event_result(index, error="invalid_user_mapping")
    server = make_server(store, auth, (config.get("host", "127.0.0.1"), config.get("port", 8080)), manager, health, diagnostics, live)
    stop = threading.Event()
    workers = []
    health.check()
    workers.append(threading.Thread(target=health.run, args=(stop,), daemon=True))
    if live.enabled:
        workers.append(threading.Thread(target=live.run, args=(stop,), daemon=True))
    for index, log in enumerate(config.get("access_logs", [])):
        if not log.get("enabled", True) or not store.policy.enabled or mapping_error:
            continue
        access = AccessParser(log["node_id"], users, log["utc_offset_minutes"], log.get("client_request_verified", False))
        tailer = Tailer(log["path"], access, store, log.get("start_at_end", True), log.get("batch_lines", 1000))
        interval = log.get("poll_seconds", 1)
        if not 0.1 <= interval <= 60:
            raise ValueError("invalid poll interval")
        worker = threading.Thread(target=run_collector, args=(tailer, stop, interval, diagnostics, index), daemon=True)
        workers.append(worker)
    def sample_network(settings):
        sampler = NetworkSampler(store, settings["node_id"], settings["interfaces"])
        while not stop.is_set():
            try:
                sampler.sample()
            except (OSError, ValueError, sqlite3.Error):
                try:
                    store.count("network_sample_errors")
                except sqlite3.Error:
                    store.pause_reasons = store.pause_reasons | {"disk_pressure"}
            stop.wait(5)
    for settings in config.get("network", []):
        workers.append(threading.Thread(target=sample_network, args=(settings,), daemon=True))
    # Retention also runs when no collectors are configured.
    def maintenance():
        while not stop.wait(60):
            try:
                store.maintain()
            except sqlite3.Error:
                store.pause_reasons = store.pause_reasons | {"disk_pressure"}
    workers.append(threading.Thread(target=maintenance, daemon=True))
    for worker in workers:
        worker.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        manager.close()
        server.server_close()
        for worker in workers:
            worker.join(timeout=10)
        # A privileged operation cannot safely be cancelled halfway through an update.
        if manager.thread is None or not manager.thread.is_alive():
            store.close()


if __name__ == "__main__":
    main()
