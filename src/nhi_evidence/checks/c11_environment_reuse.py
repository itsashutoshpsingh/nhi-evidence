"""Check 11: one app identity used for both production and non-production, or for several workloads
(NHI8 Environment Isolation, NHI9 NHI Reuse). Heuristic; findings are marked for review."""

import re
from urllib.parse import urlparse

from ..finding import Finding

META = {
    "id": "C11", "title": "Identity shared across environments", "nhi": ["NHI8", "NHI9"],
    "graph": ["GET /v1.0/applications ($select=web,identifierUris)",
              "GET /beta/applications/{id}/federatedIdentityCredentials"],
    "licence": "free",
}


def env_class(text: str, cfg: dict) -> str | None:
    words = set(re.split(r"[^a-z0-9]+", text.lower()))
    if words & set(cfg["prod_words"]):
        return "prod"
    if words & set(cfg["nonprod_words"]):
        return "nonprod"
    return None


def workload(fic: dict) -> str | None:
    s = fic.get("subject") or ""
    m = re.match(r"^repo:([^:]+/[^:]+):", s)
    if m:
        return m.group(1).lower()
    m = re.match(r"^system:serviceaccount:([^:]+):([^:]+)$", s)
    return f"k8s:{m.group(1)}/{m.group(2)}" if m else None


def run(snap, cfg) -> list[Finding]:
    out = []
    for app in snap.applications:
        fics = snap.federatedIdentityCredentials.get(app["id"], [])
        env_hits = {}
        for f in fics:
            ctx = (f.get("subject") or "").split(":", 2)[-1]
            c = env_class(ctx, cfg)
            if c:
                env_hits.setdefault(c, []).append(f.get("subject"))
        for uri in (app.get("web") or {}).get("redirectUris", []) + app.get("identifierUris", []):
            c = env_class(urlparse(uri).netloc or uri, cfg)
            if c:
                env_hits.setdefault(c, []).append(uri)
        why_verify = ("Entra admin center > App registrations > app > Authentication and Certificates & secrets "
                      f"> Federated credentials; GET /v1.0/applications/{app['id']}?$select=web,identifierUris")
        if len(env_hits) == 2:
            out.append(Finding(
                "C11", "prod_and_nonprod", ["NHI8"], app["id"], "application", app["displayName"], "medium",
                {"prod": sorted(env_hits["prod"]), "nonprod": sorted(env_hits["nonprod"]), "review": True},
                "If the same identity serves test and production, a compromise of the weaker test pipeline or "
                "host reaches production data.",
                why_verify,
            ))
        loads = sorted({w for f in fics if (w := workload(f))})
        if len(loads) > 1:
            out.append(Finding(
                "C11", "multiple_workloads", ["NHI9"], app["id"], "application", app["displayName"], "low",
                {"workloads": loads, "review": True},
                "Several separate workloads share one identity, so each gets the union of what all of them need "
                "and none can be revoked alone.",
                why_verify,
            ))
    return out
