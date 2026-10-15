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


def main():
    parser = argparse.ArgumentParser(description="Passive Xray domain activity monitoring")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as source:
        config = json.load(source)
    # Fail invalid/missing credentials before opening or purging any stored history.
    auth = resolve_auth(config)
    store = Store(config.get("database", "domains.sqlite"), Policy(**config.get("domains", {})))
    users = UserMap(config.get("users", []))
    manager = Manager(store, config.get("management", {}))
    health = PressureGuard(store, config.get("protection", {}), [log["path"] for log in config.get("access_logs", [])])
    server = make_server(store, auth, (config.get("host", "127.0.0.1"), config.get("port", 8080)), manager, health)
    stop = threading.Event()
    workers = []
    health.check()
    workers.append(threading.Thread(target=health.run, args=(stop,), daemon=True))
    for log in config.get("access_logs", []):
        access = AccessParser(log["node_id"], users, log["utc_offset_minutes"], log.get("client_request_verified", False))
        tailer = Tailer(log["path"], access, store, log.get("start_at_end", True), log.get("batch_lines", 1000))
        interval = log.get("poll_seconds", 1)
        if not 0.1 <= interval <= 60:
            raise ValueError("invalid poll interval")
        worker = threading.Thread(target=run_collector, args=(tailer, stop, interval), daemon=True)
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
