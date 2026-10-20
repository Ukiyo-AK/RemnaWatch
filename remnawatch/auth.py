"""Per-node credentials issued by a panel and manually provisioned on the node.

Opaque shared secrets, not JWTs: a node accepts only its configured credential.
No network enrollment, arbitrary token trust, or automatic secret generation at startup.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import argparse
import hmac
import json
import os
import re
import secrets
import uuid
from .runtime import identity


PREFIX = "rw_node_v1."
NODE_TOKEN = re.compile(r"rw_node_v1\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})\Z")


def canonical_node_id(value):
    if not isinstance(value, str):
        raise ValueError("node_id must be a UUID")
    try:
        result = str(uuid.UUID(value))
    except (ValueError, AttributeError):
        raise ValueError("node_id must be a UUID") from None
    if result != value or result == str(uuid.UUID(int=0)):
        raise ValueError("node_id must be a nonzero canonical lowercase UUID")
    return result


def token_node_id(token):
    match = NODE_TOKEN.fullmatch(token)
    if not match:
        raise ValueError("invalid node token format; issue a new token on the main server")
    # token_urlsafe(32) has exactly 256 random bits and a canonical 43-char encoding.
    if match[2][-1] not in "AEIMQUYcgkosw048":
        raise ValueError("invalid node token encoding")
    return canonical_node_id(match[1])


def generate_node_credentials(node_id=None):
    """Run on the main server once per node. Return the block pasted into auth.

    Persist node_id + token in the panel's protected storage: the panel needs the
    original token for outgoing Authorization headers, so a hash alone is not enough.
    """
    identity = str(uuid.uuid4()) if node_id is None else canonical_node_id(node_id)
    return {"node_id": identity, "token": PREFIX + identity + "." + secrets.token_urlsafe(32)}


@dataclass(frozen=True, repr=False)
class NodeAuth:
    token: str = field(repr=False)
    node_id: str | None = None

    def __post_init__(self):
        value = self.token
        if not isinstance(value, str) or not 32 <= len(value) <= 512 or not value.isascii() or any(not 33 <= ord(c) <= 126 for c in value):
            raise ValueError("API token must contain 32..512 printable ASCII characters without whitespace")
        if value.startswith(PREFIX):
            identity = token_node_id(value)
            if self.node_id is not None and self.node_id != identity:
                raise ValueError("auth.node_id does not match the configured node token")
            object.__setattr__(self, "node_id", identity)
        elif self.node_id is not None:
            raise ValueError("auth.node_id requires a versioned node token")

    def __repr__(self):
        return f"NodeAuth(node_id={self.node_id!r}, token=<redacted>)"

    def accepts(self, headers):
        # Exactly one header; no query credentials, cookies or alternate schemes.
        return len(headers) == 1 and hmac.compare_digest(
            headers[0].encode("utf-8"), ("Bearer " + self.token).encode("ascii"))

    def public_info(self):
        return {"node_id": self.node_id,
                "authentication": "node_token_v1" if self.node_id else "legacy_bearer",
                "service": "remnawatch", "api_version": "v1", **identity()}


def resolve_auth(config, environ=None):
    """Explicit config wins over a legacy EnvironmentFile, including during rotation."""
    env = os.environ if environ is None else environ
    section = config.get("auth", {})
    if not isinstance(section, dict) or set(section) - {"node_id", "token"}:
        raise ValueError("auth must contain only token and optional node_id")
    token = section.get("token", "")
    if not isinstance(token, str):
        raise ValueError("auth.token must be a string")
    identity = section.get("node_id")
    if identity is not None:
        canonical_node_id(identity)
    if not token:
        token = env.get("REMNAWATCH_API_TOKEN", "")
    if not token:
        raise ValueError("Configure auth.token issued by the main server, or REMNAWATCH_API_TOKEN")
    # Inline credentials use the per-node format; old plain tokens remain env-compatible.
    if section.get("token") and not token.startswith(PREFIX):
        raise ValueError("auth.token must be a node token issued by the main server")
    return NodeAuth(token, identity)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Issue per-node credentials on the main server")
    parser.add_argument("command", choices=["issue-token"])
    parser.add_argument("--node-id", help="Existing canonical lowercase UUID; omit for a new node")
    args = parser.parse_args(argv)
    try:
        credentials = generate_node_credentials(args.node_id)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(credentials, indent=2))


if __name__ == "__main__":
    main()
