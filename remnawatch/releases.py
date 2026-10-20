"""Reusable panel-side SemVer policy. Node reports never define release policy."""
import re
import time

PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")


def parse(value):
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError("invalid SemVer")
    match = PATTERN.fullmatch(value)
    if not match:
        raise ValueError("invalid SemVer")
    pre = tuple(match[4].split(".")) if match[4] else ()
    if any(p.isdecimal() and len(p) > 1 and p.startswith("0") for p in pre):
        raise ValueError("invalid numeric prerelease")
    return tuple(map(int, match.group(1, 2, 3))), pre


def compare(left, right):
    (lcore, lpre), (rcore, rpre) = parse(left), parse(right)
    def cmp(a, b):
        return (a > b) - (a < b)
    if lcore != rcore:
        return cmp(lcore, rcore)
    if lpre == rpre:
        return 0
    if not lpre or not rpre:
        return 1 if not lpre else -1
    for a, b in zip(lpre, rpre):
        if a != b:
            if a.isdecimal() and b.isdecimal():
                return cmp(int(a), int(b))
            if a.isdecimal() != b.isdecimal():
                return -1 if a.isdecimal() else 1
            return cmp(a, b)
    return cmp(len(lpre), len(rpre))


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) - {"recommended", "minimum", "channel", "updated_at", "release_notes", "update_instructions"}:
        raise ValueError("invalid release policy")
    parse(policy["recommended"])
    parse(policy["minimum"])
    if compare(policy["minimum"], policy["recommended"]) > 0:
        raise ValueError("minimum exceeds recommended")
    if policy.get("channel", "stable") not in ("stable", "beta"):
        raise ValueError("invalid release channel")
    for key in ("release_notes", "update_instructions"):
        if not isinstance(policy.get(key, ""), str) or len(policy.get(key, "")) > 2000:
            raise ValueError("invalid release text")
    return dict(policy)


def status(reported, policy, heartbeat_at, now=None, stale_after=300):
    now = time.time() if now is None else now
    if heartbeat_at is None or heartbeat_at > now + 60 or now - heartbeat_at > stale_after:
        return "stale_heartbeat"
    if not reported:
        return "not_reported"
    try:
        parse(reported)
    except ValueError:
        return "uncomparable"
    if re.search(r"(?:[-+.])(dev|custom|dirty|snapshot)(?:[.+-]|$)", reported, re.I):
        return "uncomparable"
    try:
        policy = validate_policy(policy)
    except (ValueError, TypeError, KeyError):
        return "policy_unavailable"
    if compare(reported, policy["minimum"]) < 0:
        return "below_minimum"
    if compare(reported, policy["recommended"]) < 0:
        return "update_available"
    return "current"
