"""Public browser HTTPS RTT endpoint, deliberately separate from the private API."""
import argparse
import ipaddress
from http.server import BaseHTTPRequestHandler
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from .api import BoundedHTTPServer
from .tls import TLSListener, context


def validate(config):
    if config.get("scheme", "https") != "https":
        raise ValueError("probe_requires_https")
    if not re.fullmatch(r"/[A-Za-z0-9/_-]{1,128}", config.get("path", "/ping")):
        raise ValueError("invalid_probe_path")
    if type(config.get("port", 44443)) is not int or not 1024 <= config.get("port", 44443) <= 65535 or config.get("port", 44443) == 18443:
        raise ValueError("invalid_probe_port")
    domain = config.get("domain", "")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", domain):
            raise ValueError("invalid_probe_domain") from None
    if not config.get("certificate") or not config.get("private_key"):
        raise ValueError("probe_certificate_required")


def make_probe(config):
    validate(config)
    path = config.get("path", "/ping")
    class Handler(BaseHTTPRequestHandler):
        server_version, sys_version = "RemnaWatchProbe", ""
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass

        def do_GET(self):
            # Queries are deliberately rejected and never logged.
            self.respond(204 if self.path == path else 404)

        def respond(self, status):
            self.send_response(status)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_HEAD = do_GET

        def do_POST(self):
            self.respond(405)

    class Server(TLSListener, BoundedHTTPServer):
        address_family = socket.AF_INET6 if ":" in config.get("host", "0.0.0.0") else socket.AF_INET
    server = Server((config.get("host", "0.0.0.0"), config.get("port", 44443)), Handler)
    try:
        server.tls_context = context(config["certificate"], config["private_key"])
    except BaseException:
        server.server_close()
        raise
    return server


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def check_probe(config, opener=None):
    validate(config)
    host = "[" + config["domain"] + "]" if ":" in config["domain"] else config["domain"]
    url = "https://" + host + ":" + str(config.get("port", 44443)) + config.get("path", "/ping")
    result = {"configured": True, "healthy": False, "last_success_at": None,
              "sampled_at": time.time(), "error_code": None, "measurement_scope": "https_availability"}
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        for method in ("GET", "HEAD"):
            with opener.open(urllib.request.Request(url, method=method), timeout=5) as response:
                if response.status != 204 or response.headers.get("Cache-Control") != "no-store":
                    result["error_code"] = "incompatible_probe"
                    return result
        result.update(healthy=True, last_success_at=time.time())
    except urllib.error.HTTPError as exc:
        if getattr(exc, "fp", None) is not None:
            exc.close()
        result["error_code"] = "incompatible_probe"
    except (OSError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", exc)
        result["error_code"] = "tls_error" if isinstance(reason, ssl.SSLError) else "dns_error" if isinstance(reason, socket.gaierror) else "timeout" if isinstance(reason, TimeoutError) else "connect_error"
    return result


def main():
    parser = argparse.ArgumentParser(description="Opt-in public browser HTTPS RTT probe")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as source:
        config = json.load(source)
    server = make_probe(config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
