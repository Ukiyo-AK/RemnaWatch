"""Synthetic state/API microbenchmark. Does not measure a VPN or kernel dump."""
import argparse
import json
from pathlib import Path
import statistics
import sys
import time
import tracemalloc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from remnawatch.live import LiveConnections


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--connections", type=int, default=50000)
    parser.add_argument("--output")
    args = parser.parse_args()
    if not 1 <= args.connections <= 50000:
        parser.error("connections must be 1..50000")
    class Synthetic:
        supported = True
        def collect(self):
            return [{"key": str(n), "protocol": "tcp", "kernel_state": 1, "local_ip": "192.0.2.1", "local_port": 443,
                     "peer_ip": "192.0.2.2", "peer_port": 10000 + n % 50000} for n in range(args.connections)]
    tracemalloc.start()
    live = LiveConnections("59cf9ada-b568-4513-8582-923576b05ef3", {"enabled": True, "max_connections": args.connections,
                           "max_changes": min(100000, args.connections * 2)}, Synthetic())
    cpu, start = time.process_time(), time.perf_counter()
    live.poll()
    poll_seconds = time.perf_counter() - start
    cpu_seconds = time.process_time() - cpu
    queries = []
    for _ in range(20):
        start = time.perf_counter()
        snapshot = live.query("live", {"limit": ["500"]})
        json.dumps(snapshot)
        queries.append(time.perf_counter() - start)
    live.poll()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    report = {"kind": "synthetic_only", "connections": args.connections, "poll_wall_seconds": poll_seconds,
              "poll_cpu_seconds": cpu_seconds, "snapshot_500_p95_seconds": sorted(queries)[18],
              "snapshot_500_median_seconds": statistics.median(queries), "python_current_bytes": current, "python_peak_bytes": peak,
              "disk_io_bytes": None, "disk_io_measured": False, "kernel_poll_measured": False, "vpn_impact_measured": False,
              "limitations": "tracemalloc overhead included; in-process query plus JSON, not HTTP/network p95 or process RSS"}
    encoded = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
