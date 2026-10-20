"""One shared authorization mechanism for every HTTP endpoint."""
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re
import sqlite3
from urllib.parse import parse_qs, unquote, urlsplit
from .events import domain_name
from .management import Unsupported, Conflict
from .auth import NodeAuth
from .live import ResyncRequired
from .diagnostics import Sources
from .user_metrics import limit_status
from .tls import TLSListener
import threading
import socket
import os
from socketserver import ThreadingMixIn


class BoundedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, *args):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(*args)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows SO_REUSEADDR otherwise permits a second listener to steal
            # an occupied port. Linux already rejects concurrent TCP listeners.
            self.allow_reuse_address = False
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Never print client addresses, request paths or raw exceptions.


def timestamp(value):
    if value.isdecimal():
        return int(value)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.microsecond:
        raise ValueError("time must include timezone and have whole seconds")
    return int(parsed.timestamp())


def dispatch(store, path, query):
    allowed = {"from", "to", "period", "limit", "offset", "user_id", "node_id", "search", "view", "bucket"}
    if set(query) - allowed or any(len(v) != 1 for v in query.values()):
        raise ValueError("invalid query parameters")
    q = {k: v[0] for k, v in query.items()}
    periods = {"5m": 300, "1h": 3600, "24h": 86400}
    if q.get("period", "24h") not in periods or ("period" in q and ("from" in q or "to" in q)):
        raise ValueError("invalid period")
    if ("from" in q) != ("to" in q):
        raise ValueError("from and to must be supplied together")
    end = timestamp(q["to"]) if "to" in q else int(store.clock())
    start = timestamp(q["from"]) if "from" in q else end - periods[q.get("period", "24h")]
    kwargs = {"start": start, "end": end, "limit": int(q.get("limit", 100)), "offset": int(q.get("offset", 0)),
              "user_id": q.get("user_id"), "node_id": q.get("node_id"), "search": q.get("search"),
              "bucket": q.get("bucket", "hour")}
    if path == "/v1/domains":
        mode = "domains"
    elif path == "/v1/domains/top":
        mode = "top"
    elif m := re.fullmatch(r"/v1/domains/([^/]+)/users", path):
        kwargs["domain"], mode = domain_name(unquote(m[1])), "users"
    elif m := re.fullmatch(r"/v1/users/([^/]+)/domains(?:/(history|top))?", path):
        user_id = unquote(m[1])
        if q.get("user_id") and q["user_id"] != user_id:
            raise ValueError("conflicting user filter")
        kwargs["user_id"], mode = user_id, m[2] or "domains"
    else:
        raise LookupError("not found")
    if "view" in q:
        if q["view"] != "activity" or mode not in ("domains", "history"):
            raise ValueError("invalid view")
        mode = "activity"
    return store.query(mode=mode, **kwargs)


def make_server(store, token, address=("127.0.0.1", 8080), manager=None, health=None, diagnostics=None, live=None, user_metrics=None, tls_context=None):
    auth = token if isinstance(token, NodeAuth) else NodeAuth(token)
    diagnostics = diagnostics or Sources(health=health, live=live)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass  # Paths contain sensitive domain/user activity; do not log them.

        def send_json(self, status, body):
            encoded = json.dumps(body, ensure_ascii=True, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("X-Content-Type-Options", "nosniff")
            if status == 401:
                self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(encoded)

        def authorized(self):
            headers = self.headers.get_all("Authorization", [])
            if not auth.accepts(headers):
                self.send_json(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            if len(self.path) > 4096:
                self.send_json(400, {"error": "request too long"})
                return
            try:
                url = urlsplit(self.path)
                query = parse_qs(url.query, keep_blank_values=True, max_num_fields=16)
                if url.path == "/v1/node":
                    if query:
                        raise ValueError("node verification takes no parameters")
                    result = auth.public_info()
                    result.update(getattr(diagnostics, "runtime_versions", {}))
                elif url.path == "/v1/capabilities":
                    if query:
                        raise ValueError("capabilities takes no parameters")
                    result = diagnostics.capabilities()
                elif url.path == "/v1/diagnostics/sources":
                    if query:
                        raise ValueError("source diagnostics takes no parameters")
                    result = diagnostics.report()
                elif m := re.fullmatch(r"/v1/users/([^/]+)/rate-limit", url.path):
                    if query:
                        raise ValueError("rate limit takes no query")
                    self.send_json(501, limit_status(m[1]))
                    return
                elif (m := re.fullmatch(r"/v1/users/([^/]+)/metrics", url.path)) and user_metrics:
                    if query:
                        raise ValueError("user metrics takes no query")
                    result = user_metrics.get(m[1])
                elif url.path == "/v1/alerts/sustained-load" and user_metrics:
                    if set(query) - {"limit", "offset"} or any(len(v) != 1 for v in query.values()):
                        raise ValueError("invalid pagination")
                    result = user_metrics.events(int(query.get("limit", [100])[0]), int(query.get("offset", [0])[0]))
                elif url.path == "/v1/network/interfaces" and health:
                    if query:
                        raise ValueError("interface inventory takes no parameters")
                    result = {"items": health.probe.snapshot().get("interfaces", []), "aggregation": "none"}
                elif url.path in ("/v1/connections/live", "/v1/connections/changes") and live:
                    result = live.query(url.path.rsplit("/", 1)[1], query)
                elif url.path.startswith("/v1/connections/") and live:
                    result = live.query("detail", query, url.path[len("/v1/connections/"):])
                elif url.path == "/v1/server" and manager and health:
                    if query:
                        raise ValueError("server snapshot takes no parameters")
                    result = {"server": health.probe.snapshot(), "protection": health.status(), "management": manager.capabilities()}
                elif url.path == "/v1/server/jobs" and manager:
                    if set(query) - {"limit", "offset"} or any(len(v) != 1 for v in query.values()):
                        raise ValueError("invalid job query")
                    result = manager.jobs(limit=int(query.get("limit", [100])[0]), offset=int(query.get("offset", [0])[0]))
                elif url.path.startswith("/v1/server/jobs/") and manager:
                    if query:
                        raise ValueError("job detail takes no parameters")
                    result = manager.jobs(url.path[len("/v1/server/jobs/"):])
                else:
                    result = dispatch(store, url.path, query)
                self.send_json(200, result)
            except ResyncRequired:
                self.send_json(409, {"error": "cursor_or_snapshot_expired", "resync_required": True,
                                     "remediation": "Fetch GET /v1/connections/live without cursor or snapshot_id"})
            except LookupError:
                self.send_json(404, {"error": "not found"})
            except (ValueError, UnicodeError, OverflowError):
                self.send_json(400, {"error": "invalid request parameters"})
            except sqlite3.OperationalError:
                self.send_json(503, {"error": "query budget exceeded or storage busy"})

        def do_POST(self):
            if not self.authorized():
                return
            limit_match = re.fullmatch(r"/v1/users/([^/]+)/rate-limit", self.path)
            if not limit_match and (self.path != "/v1/server/actions" or manager is None):
                self.send_json(404, {"error": "not found"})
                return
            try:
                if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json" or self.headers.get("Transfer-Encoding"):
                    raise ValueError("JSON with Content-Length required")
                lengths = self.headers.get_all("Content-Length", [])
                if len(lengths) != 1:
                    raise ValueError("one content length required")
                length = int(lengths[0])
                if not 1 <= length <= 8192:
                    raise ValueError("invalid body size")
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete body")
                def unique_pairs(pairs):
                    result = {}
                    for key, value in pairs:
                        if key in result:
                            raise ValueError("duplicate JSON field")
                        result[key] = value
                    return result
                body = json.loads(raw, object_pairs_hook=unique_pairs)
                if limit_match:
                    if not isinstance(body, dict) or body.get("action") not in ("apply", "revoke"):
                        raise ValueError("invalid limit action")
                    self.send_json(501, limit_status(limit_match[1]))
                    return
                result = manager.submit(body)
                self.send_json(200 if result.get("dry_run") else 202, result)
            except Unsupported as exc:
                self.send_json(501, {"error": str(exc)})
            except PermissionError as exc:
                self.send_json(403, {"error": str(exc)})
            except Conflict as exc:
                self.send_json(409, {"error": str(exc)})
            except (ValueError, UnicodeError, OverflowError, TypeError):
                self.send_json(400, {"error": "invalid action request"})
            except sqlite3.OperationalError:
                self.send_json(503, {"error": "storage busy or unavailable"})

    class NetworkServer(BoundedHTTPServer):
        address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    class SecureServer(TLSListener, NetworkServer):
        pass
    server = (SecureServer if tls_context else NetworkServer)(address, Handler)
    server.tls_context = tls_context
    return server
