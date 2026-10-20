"""Bounded, read-only discovery. No environment, configuration or log contents escape."""
from datetime import datetime, timezone
import json
import platform
import re
import subprocess
from .version import VERSION, BUILD

STARTED_AT = datetime.now(timezone.utc).isoformat()
SEMVER = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, timeout=5, check=False)
        if result.returncode or len(result.stdout) > 65536:
            return None
        return result.stdout.decode("utf-8", errors="strict")
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return None


def discover_versions(container, runner=command):
    """Only an explicitly selected container, never discover-and-execute arbitrary images.

    New bundled Node builds expose a literal this.nodeVersion assignment. Read it
    without executing the application. Ambiguous/unknown layouts return null.
    """
    result = {"remnanode_version": None, "xray_version": None}
    if not isinstance(container, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", container):
        return result
    prefix = ["docker", "exec", container]
    text = runner(prefix + ["xray", "version"])
    match = re.match(r"Xray (" + SEMVER + r")(?:\s|$)", text or "")
    if match:
        result["xray_version"] = match[1]
    # Output contains ONLY verified version candidates, never arbitrary app code.
    script = ("const fs=require('fs');let s;try{s=fs.readFileSync('/opt/app/dist/main.js','utf8')}catch{process.exit(2)};"
              "if(s.length>16777216)process.exit(3);"
              "const a=[...s.matchAll(/this\\.nodeVersion\\s*=\\s*[\"']([^\"']{1,80})[\"']/g)].map(x=>x[1]);"
              "process.stdout.write(JSON.stringify([...new Set(a)]));")
    text = runner(prefix + ["node", "-e", script])
    try:
        candidates = json.loads(text or "null")
        if isinstance(candidates, list):
            # Bundled Node initializes this.nodeVersion="0.0.0" before setting
            # the release literal. This sentinel is not a verified release.
            candidates = [value for value in candidates if value != "0.0.0"]
        if isinstance(candidates, list) and len(candidates) == 1 and isinstance(candidates[0], str) and re.fullmatch(SEMVER, candidates[0]):
            result["remnanode_version"] = candidates[0]
    except (ValueError, TypeError):
        pass
    return result


def identity(versions=None):
    return {"agent_version": VERSION, "agent_build": BUILD,
            "platform": platform.system().lower(), "architecture": platform.machine(),
            "started_at": STARTED_AT,
            **(versions or {"remnanode_version": None, "xray_version": None})}
