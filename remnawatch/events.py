"""Strict metadata-only inputs. Never retain the original log line or payload."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import ipaddress
import re
import uuid
import json
import hashlib
from types import MappingProxyType


def domain_name(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("invalid domain")
    value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("IP is not a domain")
    if len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                               for p in value.split(".")):
        raise ValueError("invalid domain")
    return value


def ip(value):
    return str(ipaddress.ip_address(value)) if value else None


def endpoint(value):
    value = re.sub(r"^(tcp|udp):", "", value)
    host, port = value.rsplit(":", 1)
    host = host.strip("[]")
    port = int(port)
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    try:
        return None, ip(host), port
    except ValueError:
        return domain_name(host), None, port


@dataclass(frozen=True)
class Event:
    event_id: str
    node_id: str
    user_id: str
    timestamp: int
    domain: str | None
    destination_ip: str | None
    client_ip: str | None
    protocol: str
    destination_port: int
    inbound: str
    outbound: str
    source: str
    confidence: str
    bytes_transferred: int | None = None

    def __post_init__(self):
        for key in ("event_id", "node_id", "user_id"):
            value = getattr(self, key)
            if not isinstance(value, str) or not value or len(value) > 512:
                raise ValueError("invalid identity")
        for value in (self.inbound, self.outbound):
            if not isinstance(value, str) or len(value) > 256 or any(ord(c) < 32 for c in value):
                raise ValueError("invalid tag")
        if type(self.timestamp) is not int or self.timestamp < 0:
            raise ValueError("invalid timestamp")
        if self.domain is not None:
            object.__setattr__(self, "domain", domain_name(self.domain))
        object.__setattr__(self, "destination_ip", ip(self.destination_ip))
        object.__setattr__(self, "client_ip", ip(self.client_ip))
        if not self.domain and not self.destination_ip:
            raise ValueError("missing destination")
        if self.protocol not in ("tcp", "udp") or type(self.destination_port) is not int or not 1 <= self.destination_port <= 65535:
            raise ValueError("invalid transport")
        if self.source not in ("client_request", "http_host", "tls_sni", "quic_sni", "fakedns", "dns_metadata", "xray_access", "ip_only"):
            raise ValueError("invalid source")
        if self.confidence not in ("observed", "attributed", "unknown"):
            raise ValueError("invalid confidence")
        if self.bytes_transferred is not None and (type(self.bytes_transferred) is not int or not 0 <= self.bytes_transferred < 2**63):
            raise ValueError("invalid bytes")

    def to_dict(self):
        return asdict(self)


class UserMap:
    """Exact node + inbound + Xray email mapping, no client-IP inference."""
    def __init__(self, entries, require_uuid=False):
        self.entries = {}
        for row in entries:
            key = (row["node_id"], row["inbound"], row["email"])
            if key in self.entries:
                raise ValueError("duplicate user mapping")
            if not all(isinstance(v, str) and v for v in (*key, row["user_id"])):
                raise ValueError("invalid user mapping")
            self.entries[key] = row["user_id"]
            if require_uuid:
                try:
                    identity = uuid.UUID(row["user_id"])
                except ValueError:
                    raise ValueError("user_id must be the persistent Remnawave UUID") from None
                if str(identity) != row["user_id"] or identity.int == 0:
                    raise ValueError("user_id must be a nonzero canonical Remnawave UUID")
        self.entries = MappingProxyType(self.entries)

    def resolve(self, node, inbound, email):
        return self.entries.get((node, inbound, email))


ACCESS = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\s+"
    r"(?:from\s+)?(?P<client>\S+)\s+accepted\s+(?P<network>tcp|udp):(?P<target>\S+)"
    r"(?:\s+\[(?P<detour>[^\]\r\n]{1,512})\])?\s+email:\s+(?P<email>[^\s]{1,512})\s*$"
)


class AccessParser:
    def __init__(self, node_id, users, utc_offset_minutes=0, client_request_verified=False):
        if not -840 <= utc_offset_minutes <= 840:
            raise ValueError("invalid timezone offset")
        self.node_id, self.users = node_id, users
        self.tz = timezone(timedelta(minutes=utc_offset_minutes))
        self.client_request_verified = client_request_verified
        mapping = sorted([*key, value] for key, value in users.entries.items() if key[0] == node_id)
        self.mapping_fingerprint = hashlib.sha256(json.dumps(mapping, separators=(",", ":")).encode()).hexdigest()

    def parse(self, line, event_id):
        if len(line) > 8192:
            return None
        m = ACCESS.fullmatch(line.strip())
        if not m:
            return None
        try:
            detour = re.split(r"\s+(?:->|>>|==>)\s+", m["detour"] or "")
            inbound, outbound = detour if len(detour) == 2 else ("", detour[0])
            user_id = self.users.resolve(self.node_id, inbound, m["email"])
            if not user_id:
                return None
            domain, target_ip, port = endpoint(m["target"])
            _, client_ip, _ = endpoint(m["client"])
            stamp = int(datetime.strptime(m["date"], "%Y/%m/%d %H:%M:%S").replace(tzinfo=self.tz).timestamp())
            source = "client_request" if domain and self.client_request_verified else "xray_access" if domain else "ip_only"
            return Event(event_id, self.node_id, user_id, stamp, domain, target_ip, client_ip,
                         m["network"], port, inbound, outbound, source,
                         "observed" if source == "client_request" else "unknown")
        except (ValueError, OverflowError, UnicodeError):
            return None


def correlated_metadata(data, users):
    """Trusted adapter contract, not a public HTTP ingestion endpoint.

    The producer must supply a stable connection ID and authenticated inbound email.
    No inference from timing, shared DNS cache, or protocol alone is allowed.
    """
    allowed = {"connection_id", "node_id", "inbound", "email", "timestamp", "domain",
               "destination_ip", "client_ip", "protocol", "destination_port", "outbound",
               "source", "exact_connection_bytes", "correlation_verified"}
    if set(data) - allowed or data.get("correlation_verified") is not True:
        raise ValueError("metadata must be explicitly correlated and contain only approved fields")
    user = users.resolve(data["node_id"], data["inbound"], data["email"])
    if not user:
        raise ValueError("unmapped user")
    return Event(data["connection_id"], data["node_id"], user, data["timestamp"],
                 data.get("domain"), data.get("destination_ip"), data.get("client_ip"),
                 data["protocol"], data["destination_port"], data["inbound"], data.get("outbound", ""),
                 data["source"], "attributed", data.get("exact_connection_bytes"))
