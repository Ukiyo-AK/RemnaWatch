import argparse
import json
import os
import threading
from .api import make_server
from .collector import Tailer, NetworkSampler, run_collector
from .events import AccessParser, UserMap
from .store import Policy, Store


def main():
    parser = argparse.ArgumentParser(description="Passive Xray domain activity monitoring")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as source:
        config = json.load(source)
    store = Store(config.get("database", "domains.sqlite"), Policy(**config.get("domains", {})))
    users = UserMap(config.get("users", []))
    token = os.environ.get("REMNAWATCH_API_TOKEN", "")
    server = make_server(store, token, (config.get("host", "127.0.0.1"), config.get("port", 8080)))
    stop = threading.Event()
    workers = []
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
            except (OSError, ValueError):
                store.count("network_sample_errors")
            stop.wait(5)
    for settings in config.get("network", []):
        workers.append(threading.Thread(target=sample_network, args=(settings,), daemon=True))
    # Retention also runs when no collectors are configured.
    def maintenance():
        while not stop.wait(60):
            store.maintain()
    workers.append(threading.Thread(target=maintenance, daemon=True))
    for worker in workers:
        worker.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
        for worker in workers:
            worker.join(timeout=10)
        store.close()


if __name__ == "__main__":
    main()
