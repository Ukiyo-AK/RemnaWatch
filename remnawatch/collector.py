"""Polling a local regular log file; no hooks into Xray or network capture."""
import hashlib
import json
import os
import stat
import time
import uuid
import sqlite3


class Tailer:
    def __init__(self, path, parser, store, start_at_end=True, batch_lines=1000):
        self.path, self.parser, self.store = str(path), parser, store
        self.start_at_end, self.batch_lines = start_at_end, batch_lines
        if not 1 <= batch_lines <= 10000:
            raise ValueError("invalid batch size")
        self.key = "cursor:" + hashlib.sha256((parser.node_id + os.path.abspath(self.path)).encode()).hexdigest()
        self.handle = None
        self.identity = None
        self.generation = None
        self.position = 0
        self.anchor = ""
        self.discarding = False
        self.gaps = 0
        self.last_gap_reason = None
        self.last_event_at = None
        self.skipped_events = 0
        self.parse_errors = {"invalid_line": 0, "user_mapping_mismatch": 0}
        self.poll_error = None
        self.read_seconds = None
        self.storage_seconds = None

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None

    def _open(self):
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        handle = os.fdopen(os.open(self.path, flags), "rb")
        try:
            self._open_handle(handle)
        except BaseException:
            handle.close()
            self.handle = None
            raise

    def _open_handle(self, handle):
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            handle.close()
            raise ValueError("access log must be a regular file")
        identity = [info.st_dev, info.st_ino]
        saved = json.loads(self.store.state(self.key, "null"))
        position = 0
        generation = uuid.uuid4().hex
        if saved and saved["identity"] == identity and saved["position"] <= info.st_size:
            position = saved["position"]
            handle.seek(max(0, position - 128))
            if hashlib.sha256(handle.read(min(position, 128))).hexdigest() == saved["anchor"]:
                generation = saved["generation"]
                self.discarding = saved.get("discarding", False)
            else:
                position = 0
                self.store.count("rotation_gaps")
                self.gaps += 1
                self.last_gap_reason = "log_rewritten_or_truncated"
        elif saved is None and self.start_at_end:
            position = info.st_size
        if saved and saved.get("mapping_fingerprint") != self.parser.mapping_fingerprint:
            position, generation = info.st_size, uuid.uuid4().hex
            self.discarding = False
            self.gaps += 1
            self.last_gap_reason = "mapping_changed_backlog_skipped"
            self.store.count("mapping_changes")
        self.handle, self.identity, self.generation, self.position = handle, identity, generation, position
        handle.seek(position)
        self._checkpoint([])

    def _checkpoint(self, events):
        self.handle.seek(max(0, self.position - 128))
        anchor = hashlib.sha256(self.handle.read(min(self.position, 128))).hexdigest()
        self.handle.seek(self.position)
        value = json.dumps({"identity": self.identity, "generation": self.generation,
                            "position": self.position, "anchor": anchor, "discarding": self.discarding,
                            "mapping_fingerprint": self.parser.mapping_fingerprint})
        accepted = self.store.ingest(events, (self.key, value))
        self.anchor = anchor
        return accepted

    def poll(self):
        started = time.monotonic()
        self.poll_error = None
        if self.store.pause_reasons:
            return 0  # Preserve cursor/backlog; unlike deliberate disabling, do not skip.
        if not self.handle:
            self._open()
        info = os.fstat(self.handle.fileno())
        self.handle.seek(max(0, self.position - 128))
        anchor = hashlib.sha256(self.handle.read(min(self.position, 128))).hexdigest()
        if info.st_size < self.position or anchor != self.anchor:
            self.position = 0
            self.generation = uuid.uuid4().hex
            self.discarding = False
            self.store.count("rotation_gaps")
            self.gaps += 1
            self.last_gap_reason = "log_rewritten_or_truncated"
        self.handle.seek(self.position)
        if not self.store.policy.enabled:
            self.position = info.st_size
            self.discarding = False
            self._checkpoint([])
            current = os.stat(self.path)
            if [current.st_dev, current.st_ino] != self.identity:
                self.close()
            return 0
        events, ignored = [], 0
        for _ in range(self.batch_lines):
            offset = self.handle.tell()
            line = self.handle.readline(8193)
            if not line:
                break
            if self.discarding:
                self.position = self.handle.tell()
                if line.endswith(b"\n"):
                    self.discarding = False
                continue
            if not line.endswith(b"\n"):
                if len(line) >= 8193:
                    # Persist skip mode across polls/restarts; a suffix is never a new event.
                    self.discarding = True
                    ignored += 1
                    self.parse_errors["invalid_line"] += 1
                    self.poll_error = "invalid_line"
                    self.position = self.handle.tell()
                    continue
                self.handle.seek(offset)
                break
            self.position = self.handle.tell()
            event = self.parser.parse(line.decode("utf-8", errors="replace"), f"access:{self.generation}:{offset}")
            if event:
                events.append(event)
            else:
                ignored += 1
                reason = self.parser.last_error or "invalid_line"
                self.parse_errors[reason] += 1
                self.poll_error = reason
        self.read_seconds = time.monotonic() - started
        saving = time.monotonic()
        result = self._checkpoint(events)
        self.storage_seconds = time.monotonic() - saving
        if events:
            self.last_event_at = max(self.last_event_at or 0, max(event.timestamp for event in events))
        self.skipped_events += ignored
        if ignored:
            self.store.count("unparsed_or_unmapped", ignored)
        current = os.stat(self.path)
        if [current.st_dev, current.st_ino] != self.identity and self.handle.tell() == info.st_size:
            self.close()  # Drain renamed file before following replacement.
        return result


def run_collector(tailer, stop, interval=1.0, diagnostics=None, source_index=None):
    last_cleanup = 0
    while not stop.is_set():
        try:
            tailer.poll()
            if diagnostics is not None:
                lag = max(0, os.fstat(tailer.handle.fileno()).st_size - tailer.position) if tailer.handle else None
                diagnostics.event_result(source_index, error="collection_paused" if tailer.store.pause_reasons else tailer.poll_error, lag_bytes=lag,
                                         gaps=tailer.gaps, gap_reason=tailer.last_gap_reason, last_event_at=tailer.last_event_at,
                                         skipped_events=tailer.skipped_events, parse_errors=tailer.parse_errors,
                                         read_seconds=tailer.read_seconds, storage_seconds=tailer.storage_seconds)
        except (OSError, ValueError, sqlite3.Error) as exc:
            if diagnostics is not None:
                diagnostics.event_result(source_index, error="history_storage_unavailable" if isinstance(exc, sqlite3.Error) else "permission_denied" if isinstance(exc, PermissionError) else "source_missing" if isinstance(exc, FileNotFoundError) else "source_unavailable")
            try:
                tailer.store.count("collector_errors")
            except sqlite3.Error:
                tailer.store.pause_reasons = tailer.store.pause_reasons | {"disk_pressure"}
            tailer.close()
        if time.monotonic() - last_cleanup >= 60:
            try:
                tailer.store.maintain()
            except sqlite3.Error:
                tailer.store.pause_reasons = tailer.store.pause_reasons | {"disk_pressure"}
            last_cleanup = time.monotonic()
        stop.wait(interval)
    tailer.close()


class NetworkSampler:
    """Optional Linux host interface counters, outside the Xray data path."""
    def __init__(self, store, node_id, interfaces, path="/proc/net/dev"):
        self.store, self.node_id, self.interfaces, self.path = store, node_id, set(interfaces), path
        if not self.interfaces:
            raise ValueError("explicit network interfaces required")
        self.previous = None

    def sample(self):
        totals = {}
        with open(self.path, encoding="ascii") as source:
            for line in source:
                if ":" not in line:
                    continue
                name, values = line.split(":", 1)
                if name.strip() in self.interfaces:
                    values = values.split()
                    totals[name.strip()] = int(values[0]) + int(values[8])
        if set(totals) != self.interfaces:
            self.previous = None
            raise ValueError("missing network interface")
        now = time.monotonic()
        if self.previous:
            before, counters = self.previous
            if now > before and all(totals[k] >= counters[k] for k in totals):
                self.store.network_sample(self.node_id, int(self.store.clock()),
                                          sum(totals[k] - counters[k] for k in totals) / (now - before))
        self.previous = now, totals
