"""SQLite WAL storage with atomic deduplication, rollups and reader limits."""
from contextlib import contextmanager
from dataclasses import dataclass
import sqlite3
import threading
import time
import json


@dataclass
class Policy:
    enabled: bool = True
    event_days: int = 7
    aggregate_days: int = 30
    purge_on_disable: bool = True

    def __post_init__(self):
        if type(self.enabled) is not bool or type(self.purge_on_disable) is not bool:
            raise ValueError("invalid collection policy")
        if not 1 <= self.event_days <= self.aggregate_days <= 365:
            raise ValueError("retention must satisfy 1 <= event_days <= aggregate_days <= 365")


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA secure_delete=ON;
CREATE TABLE IF NOT EXISTS events (
 event_id TEXT, node_id TEXT, user_id TEXT, timestamp INTEGER, domain TEXT,
 destination_ip TEXT, client_ip TEXT, protocol TEXT, destination_port INTEGER,
 inbound TEXT, outbound TEXT, source TEXT, confidence TEXT, bytes_transferred INTEGER,
 PRIMARY KEY(node_id,event_id));
CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_user_time ON events(user_id,timestamp);
CREATE INDEX IF NOT EXISTS events_domain_time ON events(domain,timestamp);
CREATE TABLE IF NOT EXISTS seen(node_id TEXT,event_id TEXT,timestamp INTEGER,
 PRIMARY KEY(node_id,event_id));
CREATE INDEX IF NOT EXISTS seen_time ON seen(timestamp);
CREATE TABLE IF NOT EXISTS aggregates (
 timestamp INTEGER, node_id TEXT, user_id TEXT, domain TEXT NOT NULL,
 destination_ip TEXT NOT NULL, protocol TEXT, destination_port INTEGER,
 inbound TEXT, outbound TEXT, source TEXT, confidence TEXT,
 connections INTEGER, first_seen INTEGER, last_seen INTEGER,
 measured_connections INTEGER, measured_bytes INTEGER,
 PRIMARY KEY(timestamp,node_id,user_id,domain,destination_ip,protocol,destination_port,inbound,outbound,source,confidence));
CREATE INDEX IF NOT EXISTS aggregate_user_time ON aggregates(user_id,timestamp);
CREATE INDEX IF NOT EXISTS aggregate_domain_time ON aggregates(domain,timestamp);
CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS network(timestamp INTEGER,node_id TEXT,bytes_per_second REAL,
 PRIMARY KEY(timestamp,node_id));
"""


class Store:
    def __init__(self, path, policy=None, clock=time.time):
        self.path, self.policy, self.clock = str(path), policy or Policy(), clock
        self.lock = threading.RLock()
        self.pause_reasons = set()
        self.persistence_available = True
        self.db = sqlite3.connect(self.path, check_same_thread=False, timeout=2)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA cache_size=-8192")
        self.db.execute("PRAGMA journal_size_limit=16777216")
        self.maintain()

    def close(self):
        with self.lock:
            self.db.close()

    @contextmanager
    def transaction(self):
        with self.lock, self.db:
            yield self.db

    def state(self, key, default=None):
        with self.lock:
            row = self.db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
            return row[0] if row else default

    def count(self, key, amount=1):
        with self.transaction() as db:
            db.execute("INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=CAST(value AS INTEGER)+excluded.value",
                       ("counter:" + key, str(amount)))

    def ingest(self, events, checkpoint=None):
        now = int(self.clock())
        accepted = 0
        with self.transaction() as db:
            if self.pause_reasons:
                return 0
            for e in events:
                if not self.policy.enabled or e.timestamp < now - self.policy.aggregate_days * 86400 or e.timestamp > now + 60:
                    continue
                if not db.execute("INSERT OR IGNORE INTO seen VALUES (?,?,?)", (e.node_id, e.event_id, e.timestamp)).rowcount:
                    continue
                accepted += 1
                if e.timestamp >= now - self.policy.event_days * 86400:
                    db.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(e.to_dict().values()))
                db.execute("""INSERT INTO aggregates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT DO UPDATE SET connections=connections+1,
                    first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen),
                    measured_connections=measured_connections+excluded.measured_connections,
                    measured_bytes=measured_bytes+excluded.measured_bytes""",
                    (e.timestamp, e.node_id, e.user_id, e.domain or "", e.destination_ip or "", e.protocol,
                     e.destination_port, e.inbound, e.outbound, e.source, e.confidence, 1,
                     e.timestamp, e.timestamp, int(e.bytes_transferred is not None), e.bytes_transferred or 0))
            if checkpoint:
                db.execute("INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", checkpoint)
        return accepted

    def emergency_prune(self, keep_event_seconds=3600, keep_aggregate_seconds=86400, batch=2000):
        """Bounded early deletion; reuse pages and release incremental-vacuum pages."""
        now = int(self.clock())
        removed = {}
        with self.transaction() as db:
            for table, keep in (("events", keep_event_seconds), ("aggregates", keep_aggregate_seconds), ("network", keep_aggregate_seconds)):
                removed[table] = db.execute("DELETE FROM " + table + " WHERE rowid IN (SELECT rowid FROM " + table + " WHERE timestamp<? ORDER BY timestamp LIMIT ?)", (now - keep, batch)).rowcount
            result = {"timestamp": now, "removed": removed, "early_deletion": True}
            db.execute("INSERT INTO state VALUES ('emergency_retention',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(result),))
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute("PRAGMA incremental_vacuum(2000)")
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return result

    def set_enabled(self, enabled):
        with self.lock:
            self.policy.enabled = bool(enabled)
            self.maintain()

    def maintain(self):
        now = int(self.clock())
        with self.transaction() as db:
            if not self.policy.enabled and self.policy.purge_on_disable:
                for table in ("events", "aggregates", "seen", "network"):
                    db.execute("DELETE FROM " + table)
            else:
                db.execute("DELETE FROM events WHERE timestamp < ?", (now - self.policy.event_days * 86400,))
                for table in ("aggregates", "seen", "network"):
                    db.execute("DELETE FROM " + table + " WHERE timestamp < ?", (now - self.policy.aggregate_days * 86400,))
        with self.lock:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def network_sample(self, node_id, timestamp, bytes_per_second):
        import math
        if type(timestamp) is not int or not math.isfinite(bytes_per_second) or bytes_per_second < 0:
            raise ValueError("invalid network sample")
        with self.transaction() as db:
            if not self.policy.enabled or self.pause_reasons:
                return
            db.execute("INSERT OR REPLACE INTO network VALUES (?,?,?)", (timestamp, node_id, bytes_per_second))

    def query(self, *, start, end, limit=100, offset=0, user_id=None, domain=None,
              search=None, node_id=None, mode="domains", bucket="hour"):
        now = int(self.clock())
        if not (type(start) is int and type(end) is int and 0 <= start < end and end - start <= 365 * 86400):
            raise ValueError("invalid period")
        if not 1 <= limit <= 500 or not 0 <= offset <= 100000:
            raise ValueError("invalid pagination")
        if mode not in ("domains", "top", "users", "history", "activity") or bucket not in ("hour", "day"):
            raise ValueError("invalid view")
        clauses, args = ["timestamp >= ?", "timestamp < ?"], [max(start, now - self.policy.aggregate_days * 86400), end]
        for key, value in (("user_id", user_id), ("domain", domain), ("node_id", node_id)):
            if value is not None:
                clauses.append(key + "=?")
                args.append(value)
        if search:
            if len(search) > 253:
                raise ValueError("search too long")
            clauses.append("instr(domain,?)>0")
            args.append(search.lower())
        where = " AND ".join(clauses)
        with self.lock:
            # Abort costly analytics rather than starving ingestion indefinitely.
            deadline = time.monotonic() + 2
            self.db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            try:
                quality_row = self.db.execute("""SELECT coalesce(sum(connections),0) n,
                    coalesce(sum(CASE WHEN domain!='' THEN connections ELSE 0 END),0) known,
                    coalesce(sum(CASE WHEN confidence!='unknown' THEN connections ELSE 0 END),0) attributed
                    FROM aggregates WHERE """ + where, args).fetchone()
                if mode == "history":
                    table, selection, group, order = "events", "*", "", "timestamp DESC,node_id,event_id"
                    where += " AND timestamp >= " + str(now - self.policy.event_days * 86400)
                else:
                    table = "aggregates"
                    if mode == "activity":
                        seconds = 3600 if bucket == "hour" else 86400
                        keys = f"(timestamp / {seconds}) * {seconds} AS bucket_start"
                        group, order = "bucket_start", "bucket_start DESC"
                    elif mode == "users":
                        keys, group, order = "user_id", "user_id", "connections DESC,user_id"
                    else:
                        keys = "NULLIF(domain,'') AS domain,NULLIF(destination_ip,'') AS destination_ip"
                        group, order = "domain,destination_ip", "connections DESC,domain,destination_ip"
                        if mode == "top":
                            where += " AND domain!=''"
                            keys, group, order = "domain", "domain", "connections DESC,domain"
                    selection = keys + """,sum(connections) AS connections,min(first_seen) AS first_seen,
                        max(last_seen) AS last_seen,sum(measured_connections) AS measured_connections,
                        CASE WHEN sum(measured_connections)=sum(connections) THEN sum(measured_bytes) END AS bytes_transferred"""
                base = "SELECT " + selection + " FROM " + table + " WHERE " + where
                if group:
                    base += " GROUP BY " + group
                total = self.db.execute("SELECT count(*) FROM (" + base + ")", args).fetchone()[0]
                items = [dict(r) for r in self.db.execute(base + " ORDER BY " + order + " LIMIT ? OFFSET ?", (*args, limit, offset))]
                if mode == "history":
                    for row in items:
                        row["connections"] = 1
                if mode == "activity":
                    # Host/node load is contemporaneous context, never domain traffic attribution.
                    for row in items:
                        lo, hi = max(start, row["bucket_start"]), min(end, row["bucket_start"] + seconds)
                        sql = "SELECT node_id,avg(bytes_per_second) average_bps,max(bytes_per_second) peak_bps,count(*) samples FROM network WHERE timestamp>=? AND timestamp<?"
                        values = [lo, hi]
                        if node_id:
                            sql += " AND node_id=?"
                            values.append(node_id)
                        row["network_load"] = [dict(r) for r in self.db.execute(sql + " GROUP BY node_id", values)]
                counters = {r["key"][8:]: int(r["value"]) for r in self.db.execute("SELECT * FROM state WHERE key LIKE 'counter:%'")}
            finally:
                self.db.set_progress_handler(None, 0)
        n, known, attributed = quality_row
        return {"items": items, "total": total, "limit": limit, "offset": offset,
                "period": {"from": start, "to": end},
                "quality": {"collection_enabled": self.policy.enabled, "registered_connections": n,
                            "history_storage_available": self.persistence_available,
                            "collection_paused": bool(self.pause_reasons), "pause_reasons": sorted(self.pause_reasons),
                            "emergency_retention": json.loads(self.state("emergency_retention", "null")),
                            "domain_connections": known, "domain_coverage": known / n if n else None,
                            "attributed_connections": attributed, "complete": False,
                            "timestamp_precision": "second", "event_retention_days": self.policy.event_days,
                            "aggregate_retention_days": self.policy.aggregate_days,
                            "period_truncated": start < now - (self.policy.event_days if mode == "history" else self.policy.aggregate_days) * 86400,
                            "collector_counters": counters,
                            "sniffed_domain_export": "unavailable_in_stock_xray",
                            "traffic_semantics": "exact_measurements_only",
                            "limitations": ["ECH", "CDN", "IP-only requests", "missing logs", "Xray source limitations"],
                            "connection_semantics": "registered connection event; not a web page visit"}}
