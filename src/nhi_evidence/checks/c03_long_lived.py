"""Check 3: client secret valid for more than N days, or with no end date (NHI7 Long-Lived Secrets)."""

from ..finding import Finding, escalate
from ..snapshot import ts

META = {
    "id": "C03", "title": "Long-lived client secret", "nhi": ["NHI7"],
    "graph": ["GET /v1.0/applications ($select=passwordCredentials)",
              "GET /v1.0/servicePrincipals ($select=passwordCredentials)"],
    "licence": "free",
}


def _secrets(snap):
    for app in snap.applications:
        yield app, "application", snap.sp_of(app), app.get("passwordCredentials", [])
    for sp in snap.servicePrincipals:
        yield sp, "servicePrincipal", sp, sp.get("passwordCredentials", [])


def run(snap, cfg) -> list[Finding]:
    out = []
    limit = cfg["max_secret_days"]
    for obj, kind, sp, creds in _secrets(snap):
        for c in creds:
            if not snap.active(c):
                continue  # expired secrets are check 4
            start, end = ts(c.get("startDateTime")), ts(c.get("endDateTime"))
            days = None if end is None or start is None else (end - start).total_seconds() / 86400
            if days is not None and days <= limit:
                continue
            out.append(Finding(
                "C03", "no_end_date" if end is None else "lifetime_over_limit", META["nhi"], obj["id"], kind,
                obj["displayName"], escalate(snap, cfg, sp, "low"),
                {"keyId": c["keyId"], "startDateTime": c.get("startDateTime"), "endDateTime": c.get("endDateTime"),
                 "lifetime_days": None if days is None else round(days, 1), "limit_days": limit,
                 "on": kind},
                "A secret that stays valid for years gives anyone who copies it years of access; short "
                "lifetimes force rotation and limit the damage of a leak.",
                ("Entra admin center > App registrations > app > Certificates & secrets; "
                 f"GET /v1.0/applications/{obj['id']}?$select=passwordCredentials") if kind == "application" else
                ("Not shown in the portal for service principal secrets; "
                 f"GET /v1.0/servicePrincipals/{obj['id']}?$select=passwordCredentials"),
                extra={"keyId": c["keyId"]},
            ))
    return out
