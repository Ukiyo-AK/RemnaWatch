"""Bounded polling of Linux inet_diag sockets. Never infer Xray users/domains."""
from collections import OrderedDict, deque
import base64
import hashlib
import ipaddress
import json
import platform
import socket
import struct
import threading
import time
import uuid
from .auth import canonical_node_id


class ResyncRequired(Exception):
    """Client must start a new snapshot, not skip an unknown delta interval."""


def decode_diag(payload, protocol):
    if len(payload) < 72 or payload[0] not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError("invalid inet_diag payload")
    family, state = payload[0], payload[1]
    cookie = payload[44:52]
    if cookie == b"\xff" * 8:
        raise ValueError("stable socket cookie unavailable")
    size = 4 if family == socket.AF_INET else 16
    return {"key": f"{family}:{protocol}:" + cookie.hex(), "protocol": protocol,
            "kernel_state": state, "local_ip": str(ipaddress.ip_address(bytes(payload[8:8 + size]))),
            "peer_ip": str(ipaddress.ip_address(bytes(payload[24:24 + size]))),
            "local_port": struct.unpack_from("!H", payload, 4)[0],
            "peer_port": struct.unpack_from("!H", payload, 6)[0]}


class InetDiag:
    """NETLINK_SOCK_DIAG v2 dump. No TCP_INFO byte interpretation or payload."""
    supported = platform.system() == "Linux" and hasattr(socket, "AF_NETLINK")

    def __init__(self, max_connections=10000, max_dump_bytes=16777216, timeout=2, protocols=("tcp", "udp")):
        self.max_connections, self.max_dump_bytes, self.timeout = max_connections, max_dump_bytes, timeout
        self.protocols = protocols

    def collect(self):
        if not self.supported:
            raise OSError("inet_diag unavailable")
        rows, used = [], 0
        deadline = time.monotonic() + self.timeout
        sequence = 0
        for family in (socket.AF_INET, socket.AF_INET6):
            for protocol in self.protocols:
                sequence += 1
                with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 4) as channel:
                    channel.bind((0, 0))
                    request = struct.pack("=BBBBI", family, 6 if protocol == "tcp" else 17, 0, 0, 0xffffffff) + bytes(48)
                    channel.sendto(struct.pack("=IHHII", 16 + len(request), 20, 0x301, sequence, 0) + request, (0, 0))
                    done = False
                    while not done:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("socket dump exceeded budget")
                        channel.settimeout(remaining)
                        data, _, flags, address = channel.recvmsg(262144)
                        used += len(data)
                        if flags & socket.MSG_TRUNC or used > self.max_dump_bytes or address[0] != 0:
                            raise ValueError("incomplete socket dump")
                        position = 0
                        while position < len(data):
                            if position + 16 > len(data):
                                raise ValueError("truncated netlink header")
                            length, kind, nlflags, seq, _ = struct.unpack_from("=IHHII", data, position)
                            if length < 16 or position + length > len(data) or seq != sequence or nlflags & 0x10:
                                raise ValueError("interrupted netlink dump")
                            payload = data[position + 16:position + length]
                            position += (length + 3) & ~3
                            if kind == 3:
                                if len(payload) >= 4 and struct.unpack_from("=i", payload)[0] != 0:
                                    raise OSError("socket dump failed")
                                done = True
                            elif kind == 2:
                                if len(payload) < 4 or struct.unpack_from("=i", payload)[0] != 0:
                                    raise OSError("socket diagnostics rejected")
                            elif kind == 4:
                                raise ValueError("netlink overrun")
                            elif kind == 20:
                                row = decode_diag(payload, protocol)
                                if protocol == "tcp" and row["kernel_state"] == 10:
                                    continue  # Listen sockets are not connection records.
                                rows.append(row)
                                if len(rows) > self.max_connections:
                                    raise ValueError("socket count exceeds budget")
        return rows


class LiveConnections:
    @classmethod
    def from_config(cls, node_id, settings=None):
        try:
            return cls(node_id, settings)
        except (ValueError, TypeError):
            result = cls(node_id)
            result.configuration_error = True
            result.requested_enabled = isinstance(settings, dict) and settings.get("enabled", False) is not False
            result.error_code, result.healthy = "invalid_configuration", False
            return result

    def __init__(self, node_id, settings=None, source=None, clock=time.monotonic, wall=time.time):
        self.settings = {} if settings is None else settings
        if not isinstance(self.settings, dict) or set(self.settings) - {"enabled", "adapter", "node_id", "protocols", "fields", "max_connections", "max_changes", "poll_seconds", "snapshot_ttl_seconds", "tombstone_seconds"}:
            raise ValueError("invalid live configuration")
        self.enabled = self.settings.get("enabled", False)
        if type(self.enabled) is not bool or self.settings.get("adapter", "linux_inet_diag") != "linux_inet_diag":
            raise ValueError("unsupported live adapter configuration")
        self.node_id, self.clock, self.wall = node_id, clock, wall
        if self.enabled:
            self.node_id = canonical_node_id(self.settings.get("node_id", node_id))
        self.boot_id, self.epoch = str(uuid.uuid4()), str(uuid.uuid4())
        self.max_connections = self.settings.get("max_connections", 10000)
        self.max_changes = self.settings.get("max_changes", 10000)
        self.interval = self.settings.get("poll_seconds", 5)
        self.snapshot_ttl = self.settings.get("snapshot_ttl_seconds", 30)
        self.closed_ttl = self.settings.get("tombstone_seconds", 60)
        self.protocols = self.settings.get("protocols", ["tcp", "udp"])
        self.fields = self.settings.get("fields", [])
        if not isinstance(self.fields, list) or set(self.fields) - {"local_ip", "local_port", "peer_ip", "peer_port"}:
            raise ValueError("unsupported live field whitelist")
        if type(self.max_connections) is not int or not 1 <= self.max_connections <= 50000 or type(self.max_changes) is not int or not 1 <= self.max_changes <= 100000:
            raise ValueError("invalid live memory limits")
        if not 1 <= self.interval <= 60 or not 5 <= self.snapshot_ttl <= 120 or not 1 <= self.closed_ttl <= 3600:
            raise ValueError("invalid live polling/retention interval")
        if not isinstance(self.protocols, list) or not self.protocols or len(set(self.protocols)) != len(self.protocols) or set(self.protocols) - {"tcp", "udp"}:
            raise ValueError("invalid live protocols")
        self.source = source or InetDiag(self.max_connections, protocols=self.protocols)
        self.current, self.retired = {}, OrderedDict()
        self.snapshots = OrderedDict()
        self.changes = deque(maxlen=self.max_changes)
        self.sequence = 0
        self.healthy, self.error_code, self.sampled_at = None, "disabled" if not self.enabled else "not_sampled", None
        self.last_success, self.failed_polls, self.lost_intervals = None, 0, 0
        self.lock = threading.RLock()
        self.configuration_error = False
        self.requested_enabled = self.enabled

    def _cursor(self, sequence):
        value = json.dumps([self.boot_id, self.epoch, sequence], separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    def _parse_cursor(self, value):
        try:
            if not isinstance(value, str) or len(value) > 256:
                raise ValueError()
            boot, epoch, sequence = json.loads(base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True))
            oldest = self.changes[0]["sequence"] if self.changes else self.sequence + 1
            if boot != self.boot_id or epoch != self.epoch or type(sequence) is not int or not oldest - 1 <= sequence <= self.sequence:
                raise ValueError()
            return sequence
        except (ValueError, TypeError, UnicodeError):
            raise ResyncRequired("Cursor lost or expired; fetch a new full snapshot") from None

    def _emit(self, kind, record, tombstone=False, previous_state=None):
        self.sequence += 1
        self.changes.append({"sequence": self.sequence, "kind": kind, "record": record, "tombstone": tombstone, "previous_state": previous_state})

    def _record(self, row, previous, sampled):
        identity = hashlib.sha256((self.boot_id + row["key"]).encode()).hexdigest()[:32]
        tcp_state = row["kernel_state"]
        state = "closed" if row["protocol"] == "tcp" and tcp_state in (6, 7) else "active" if row["protocol"] == "tcp" and tcp_state in (1, 2, 3, 4, 5, 8, 9, 11, 12) else "unknown"
        reasons = {"user_id": "no_verified_xray_correlation", "inbound": "no_verified_xray_correlation",
                   "domain": "source_does_not_export_domain", "client_ip": "socket_direction_unknown", "client_port": "socket_direction_unknown",
                   "destination_ip": "socket_direction_unknown", "destination_port": "socket_direction_unknown",
                   "started_at": "socket_start_not_exported", "closed_at": "exact_close_time_not_exported",
                   "duration_seconds": "start_time_unknown", "rx_bytes": "source_no_byte_measurement",
                   "tx_bytes": "source_no_byte_measurement", "rx_bytes_per_second": "unsupported", "tx_bytes_per_second": "unsupported",
                   "transport_stream_id": "logical_stream_not_exported"}
        if row["protocol"] == "udp":
            reasons["state"] = "udp_socket_presence_does_not_prove_flow_activity"
        for field in ("local_ip", "local_port", "peer_ip", "peer_port"):
            if field not in self.fields:
                reasons[field] = "field_not_allowlisted"
        return {"node_id": self.node_id, "agent_boot_id": self.boot_id, "connection_id": identity,
                "user_id": None, "inbound": None, "protocol": row["protocol"], "transport_stream_id": None,
                "client_ip": None, "client_port": None, "destination_ip": None, "destination_port": None,
                **{key: row[key] if key in self.fields else None for key in ("local_ip", "local_port", "peer_ip", "peer_port")},
                "domain": None, "domain_source": None, "confidence": "socket_observed_user_unassigned",
                "state": state, "kernel_state": row["kernel_state"], "started_at": None,
                "first_observed_at": previous["first_observed_at"] if previous else sampled,
                "last_seen_at": sampled, "closed_at": None, "duration_seconds": None,
                "rx_bytes": None, "tx_bytes": None, "rx_bytes_per_second": None, "tx_bytes_per_second": None,
                "measured_at": sampled, "sample_interval_seconds": None if self.last_success is None else self.clock() - self.last_success,
                "measurement_scope": "transport_socket", "source": "linux_inet_diag_v1",
                "byte_direction": "node_socket", "timestamp_origin": "agent_poll_wall_clock", "timestamp_precision": "second_fraction",
                "unavailable_reason": reasons}

    def _expire(self):
        now = self.clock()
        while self.retired and (len(self.retired) > self.max_connections or next(iter(self.retired.values()))[0] <= now):
            self.retired.popitem(last=False)
        for identity in list(self.snapshots):
            if self.snapshots[identity][0] <= now:
                del self.snapshots[identity]

    def poll(self):
        if not self.enabled:
            return
        try:
            rows = self.source.collect()
            if len(rows) > self.max_connections or len({r["key"] for r in rows}) != len(rows):
                raise ValueError("incomplete or duplicate socket dump")
            sampled = self.wall()
            with self.lock:
                updated = {}
                for row in rows:
                    identity = hashlib.sha256((self.boot_id + row["key"]).encode()).hexdigest()[:32]
                    previous = self.current.get(identity)
                    record = self._record(row, previous, sampled)
                    updated[identity] = record
                    closing = record["state"] == "closed" and (previous is None or previous["state"] != "closed")
                    self._emit("closed" if closing else "updated" if previous else "created", record, closing, previous["state"] if previous else None)
                for identity, old in self.current.items():
                    if identity not in updated:
                        proven_closed = old["state"] == "closed"
                        record = {**old, "state": "closed" if proven_closed else "unknown", "measured_at": sampled,
                                  "unavailable_reason": {**old["unavailable_reason"], "state": "previously_observed_closed_no_longer_listed" if proven_closed else "socket_disappeared_not_proven_close"}}
                        self.retired[identity] = (self.clock() + self.closed_ttl, record)
                        self._emit("removed", record, True, old["state"])
                self.current = updated
                self.healthy, self.error_code, self.sampled_at = True, None, sampled
                self.last_success = self.clock()
                self._expire()
        except Exception as exc:
            with self.lock:
                self.failed_polls += 1
                if self.healthy is not False:
                    self.lost_intervals += 1
                    self.epoch = str(uuid.uuid4())  # Any observation gap requires explicit resync.
                    self.current, self.retired, self.snapshots = {}, OrderedDict(), OrderedDict()
                    self.changes.clear()
                    self.sequence = 0
                self.healthy = False
                self.error_code = "permission_denied" if isinstance(exc, PermissionError) else "poll_timeout" if isinstance(exc, TimeoutError) else "source_incomplete_or_unavailable"
                self.last_success = None

    def status(self):
        with self.lock:
            lag = None if self.last_success is None else max(0, self.clock() - self.last_success)
            stale = lag is not None and lag > self.interval * 2 + 2
            return {"component": "live_connections", "adapter": "linux_inet_diag", "supported": bool(self.source.supported),
                    "configured": self.requested_enabled, "healthy": (False if stale else self.healthy) if self.requested_enabled else None,
                    "error_code": "stale_sample" if stale else self.error_code, "sampled_at": self.sampled_at,
                    "lag_seconds": lag,
                    "failed_polls": self.failed_polls, "lost_intervals": self.lost_intervals,
                    "lost_events": None, "measurement_scope": "transport_socket", "permissions": "read-only NETLINK_SOCK_DIAG; no CAP_NET_ADMIN requested",
                    "limitations": ["all visible namespace sockets, not only Xray", "no user/domain correlation", "no per-flow bytes, start time or UDP activity inference"]}

    def _envelope(self, items, snapshot_id, next_cursor, has_more, sampled_at=Ellipsis):
        return {"items": items, "agent_boot_id": self.boot_id, "collector_epoch": self.epoch,
                "next_cursor": next_cursor, "has_more": has_more, "sampled_at": self.sampled_at if sampled_at is Ellipsis else sampled_at,
                "snapshot_id": snapshot_id, "resync_required": False, "source": self.status()}

    def query(self, mode, query=None, identity=None):
        query = query or {}
        allowed = {"limit", "offset", "snapshot_id", "user_id", "inbound", "protocol", "state"} if mode == "live" else {"limit", "cursor", "user_id", "inbound", "protocol", "state"} if mode == "changes" else set()
        if set(query) - allowed or any(len(v) != 1 for v in query.values()):
            raise ValueError("invalid live query")
        q = {k: v[0] for k, v in query.items()}
        limit, offset = int(q.get("limit", 100)), int(q.get("offset", 0))
        if not 1 <= limit <= 500 or not 0 <= offset <= 100000:
            raise ValueError("invalid live pagination")
        if q.get("protocol", "tcp") not in ("tcp", "udp") or q.get("state", "active") not in ("active", "closed", "unknown"):
            raise ValueError("invalid live filter")
        def matches(row):
            return all(row.get(k) == q[k] for k in ("user_id", "inbound", "protocol", "state") if k in q)
        with self.lock:
            self._expire()
            if mode == "detail":
                record = self.current.get(identity) or (self.retired.get(identity) or (None, None))[1]
                if not record:
                    raise LookupError("unknown connection")
                return self._envelope([record], None, self._cursor(self.sequence), False)
            if mode == "live":
                snapshot_id = q.get("snapshot_id")
                if offset and not snapshot_id:
                    raise ValueError("offset requires snapshot_id")
                if snapshot_id:
                    if snapshot_id not in self.snapshots:
                        raise ResyncRequired("Snapshot expired; fetch a new full snapshot")
                else:
                    snapshot_id = str(uuid.uuid4())
                    # Immutable row references: later polls replace records, never mutate them.
                    self.snapshots[snapshot_id] = (self.clock() + self.snapshot_ttl, tuple(self.current[k] for k in sorted(self.current)), self.sequence, self.sampled_at)
                    while len(self.snapshots) > 2:
                        self.snapshots.popitem(last=False)
                _, rows, sequence, sampled = self.snapshots[snapshot_id]
                filtered = [r for r in rows if matches(r)]
                result = self._envelope(filtered[offset:offset + limit], snapshot_id, self._cursor(sequence), offset + limit < len(filtered), sampled)
                result.update(total=len(filtered), limit=limit, offset=offset)
                return result
            sequence = self._parse_cursor(q["cursor"]) if q.get("cursor") else self.sequence
            def matches_change(change):
                if matches(change["record"]):
                    return True
                # A filtered replica must also receive records leaving its state set.
                return "state" in q and change["previous_state"] == q["state"] and matches({**change["record"], "state": q["state"]})
            later = [change for change in self.changes if change["sequence"] > sequence and matches_change(change)]
            selected = later[:limit]
            next_sequence = selected[-1]["sequence"] if len(later) > limit else self.sequence
            return self._envelope(selected, None, self._cursor(next_sequence), len(later) > limit)

    def run(self, stop):
        while not stop.is_set():
            self.poll()
            stop.wait(self.interval)
