"""Verified source acquisition only. Activation/rollback belong to install.py.

Digest MUST come from authenticated administrator policy, independently from the
download. No tokens, query strings, redirects, insecure TLS or executable hooks.
"""
import hashlib
import gzip
import io
from pathlib import Path, PurePosixPath
import re
import socket
import ipaddress
import tarfile
import urllib.parse
import urllib.request
import http.client
from .probe import NoRedirect
from .releases import parse

MAX_ARCHIVE = 32 * 1024**2
MAX_EXPANDED = 64 * 1024**2


def public_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """Resolve and connect to the checked IP, preventing DNS rebinding to LAN."""
    rows = socket.getaddrinfo(address[0], address[1], type=socket.SOCK_STREAM)
    if not rows or any(not ipaddress.ip_address(row[4][0]).is_global for row in rows):
        raise ValueError("release_host_must_be_public")
    failure = None
    for family, kind, proto, _, sockaddr in rows:
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            failure = exc
            sock.close()
    raise failure or OSError("release_connection_failed")


class PublicHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = public_connection


class PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(PublicHTTPSConnection, request, context=self._context)


def validate_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError("release_requires_plain_https_url_without_credentials")
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
        raise ValueError("release_host_must_be_public")


def acquire(url, digest, destination, version, opener=None):
    parse(version)
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("trusted_sha256_required")
    validate_url(url)
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), PublicHTTPSHandler())
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise ValueError("release_download_failed")
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("release_digest_mismatch_or_too_large")
    extract(data, destination, version)


def extract(data, destination, version):
    """Extract ONLY package source, with no tarfile.extract/path traversal or links."""
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("release_destination_not_empty")
    # Bound decompression before tarfile parses even PAX/long-name metadata.
    # Skipped docs or .git entries must not bypass the expanded-size budget.
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_EXPANDED + 1)
    if len(expanded) > MAX_EXPANDED:
        raise ValueError("release_expansion_limit")
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(expanded), mode="r:") as archive:
        for index, member in enumerate(archive):
            if index >= 5000:
                raise ValueError("release_too_many_members")
            path = PurePosixPath(member.name)
            total += member.size
            if member.size < 0 or total > MAX_EXPANDED:
                raise ValueError("release_expansion_limit")
            if path.is_absolute() or ".." in path.parts or "\\" in member.name or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe_release_archive")
            # Root-level package or one GitHub archive prefix, no ambiguous trees.
            parts = path.parts
            package = parts[1:] if len(parts) > 1 and parts[1] == "remnawatch" else parts
            if not package or package[0] != "remnawatch" or member.isdir():
                continue
            if len(package) != 2 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.py", package[1]):
                continue
            name = "/".join(package)
            if name in files:
                raise ValueError("release_too_large_or_duplicate")
            files[name] = archive.extractfile(member).read()
    if "remnawatch/__main__.py" not in files or "remnawatch/version.py" not in files:
        raise ValueError("release_package_missing")
    text = files["remnawatch/version.py"].decode("utf-8")
    if not re.search(r'^VERSION\s*=\s*[\"\']' + re.escape(version) + r'[\"\']\s*$', text, re.M):
        raise ValueError("release_version_mismatch")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in files.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, exist_ok=True)
        with path.open("xb") as output:
            output.write(content)
        path.chmod(0o600)
