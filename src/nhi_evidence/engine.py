"""Run every check on a snapshot and apply the allowlist."""

import json
import time
from pathlib import Path

from . import refs
from .checks import CHECKS
from .finding import Finding


def load_allowlist(path: str | Path | None) -> list[dict]:
    """Entries: {"objectId" or "appId", "checks": ["C03", ...] or ["*"], "reason": "..."}. Reasons are required."""
    if not path:
        return []
    entries = json.loads(Path(path).read_text())
    for e in entries:
        if not e.get("reason") or not (e.get("objectId") or e.get("appId")):
            raise ValueError(f"allowlist entry needs objectId or appId, and a reason: {e}")
    return entries


def _sp_for(snap, f: Finding) -> dict | None:
    if f.object_type == "servicePrincipal":
        return snap.sp_by_id.get(f.object_id)
    if f.object_type == "application":
        app = snap.app_by_id.get(f.object_id)
        return snap.sp_of(app) if app else None
    return None


def suppression(snap, f: Finding, allow: list[dict]) -> str | None:
    sp = _sp_for(snap, f)
    if sp and snap.is_first_party(sp):
        return f"Microsoft first-party app (appOwnerOrganizationId {sp['appOwnerOrganizationId']})"
    app_id = (sp or {}).get("appId")
    for e in allow:
        if e.get("objectId") == f.object_id or (app_id and e.get("appId") == app_id):
            if "*" in e["checks"] or f.check_id in e["checks"]:
                return e["reason"]
    return None


def evaluate(snap, cfg, allow: list[dict] | None = None, checks=CHECKS, timings: dict | None = None
             ) -> list[Finding]:
    allow = allow or []
    out = []
    for c in checks:
        t0 = time.perf_counter()
        found = c.run(snap, cfg)
        if timings is not None:
            timings[c.META["id"]] = time.perf_counter() - t0
        for f in found:
            sp = _sp_for(snap, f)
            f.identity_type = snap.identity_type(sp) if sp else f.object_type
            f.suppressed = suppression(snap, f, allow)
            out.append(f)
    return out


def skipped(snap) -> dict[str, str]:
    """Checks that could not run because the snapshot lacks their optional input."""
    return {c.META["id"]: f"needs {c.META['needs']} ({c.META['licence']})" for c in CHECKS
            if c.META.get("needs") and getattr(snap, c.META["needs"]) is None}


def owasp_name(risk: str) -> str:
    return f"{risk} {refs.owasp()[risk]['name']}"
