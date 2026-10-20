"""Safe HTTPS history control requests. GET retries only; no implicit POST replay."""
import json
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from .probe import NoRedirect


class HistoryTransportError(RuntimeError):
    def __init__(self, code, retryable=False):
        self.code, self.retryable = code, retryable
        super().__init__(code)  # Never retain/print raw request, URL, response or exception.


def classify(exc):
    if isinstance(exc, urllib.error.HTTPError):
        result = HistoryTransportError("central_http_" + str(exc.code), exc.code in (429, 500, 502, 503, 504))
        if getattr(exc, "fp", None) is not None:
            exc.close()  # Python 3.8 HTTPError.close() is broken for fp=None.
        return result
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, ssl.SSLError):
        return HistoryTransportError("central_tls_error")
    if isinstance(reason, socket.gaierror):
        return HistoryTransportError("central_dns_error", True)
    if isinstance(reason, TimeoutError):
        return HistoryTransportError("central_timeout", True)
    return HistoryTransportError("central_connect_error", True)


class HistoryClient:
    def __init__(self, base, token, ca_file=None, opener=None, wait=time.sleep, clock=time.time):
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("central_requires_verified_https_without_credentials")
        if not isinstance(token, str) or not 32 <= len(token) <= 512 or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("invalid_node_credential")
        self.base, self.token, self.wait, self.clock = base.rstrip("/"), token, wait, clock
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                         urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        self.sampled_at, self.last_success_at, self.error_code = None, None, "not_sampled"
        self.errors = 0
        self.transfer_seconds = None

    def request(self, action, post=False):
        if action not in ("history-plan", "history-map", "complete-history"):
            raise ValueError("unknown_history_action")
        for attempt in range(1 if post else 3):
            self.sampled_at = self.clock()
            started = time.monotonic()
            try:
                request = urllib.request.Request(self.base + "/" + action, data=b"{}" if post else None,
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
                with self.opener.open(request, timeout=10) as response:
                    data = response.read(4 * 1024**2 + 1)
                if len(data) > 4 * 1024**2:
                    raise HistoryTransportError("central_response_too_large")
                try:
                    result = json.loads(data)
                    if not isinstance(result, dict):
                        raise ValueError()
                except (ValueError, UnicodeError):
                    raise HistoryTransportError("central_invalid_json") from None
                self.last_success_at, self.error_code = self.clock(), None
                return result
            except (urllib.error.URLError, OSError, HistoryTransportError) as exc:
                error = exc if isinstance(exc, HistoryTransportError) else classify(exc)
                self.error_code, self.errors = error.code, self.errors + 1
                if post or not error.retryable or attempt == 2:
                    raise error from None
                self.wait(attempt + 1)
            finally:
                self.transfer_seconds = time.monotonic() - started

    def status(self):
        return {"id": "central_history", "component": "history_transfer", "configured": True,
                "healthy": None if self.sampled_at is None else self.error_code is None,
                "sampled_at": self.sampled_at, "last_success_at": self.last_success_at, "last_event_at": None,
                "lag_bytes": None, "errors": self.errors, "skipped_events": 0,
                "error_code": self.error_code, "transfer_seconds": self.transfer_seconds}
