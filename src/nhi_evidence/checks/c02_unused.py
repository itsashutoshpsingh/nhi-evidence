"""Check 2: enabled service principal that holds access but has not signed in for N days (NHI1)."""

from datetime import timedelta

from ..finding import Finding, escalate
from ..snapshot import ts

META = {
    "id": "C02", "title": "Enabled but unused", "nhi": ["NHI1"],
    "graph": ["GET /beta/reports/servicePrincipalSignInActivities"],
    "licence": "AuditLog.Read.All; beta endpoint",
    "needs": "servicePrincipalSignInActivities",
}


def run(snap, cfg) -> list[Finding]:
    if snap.servicePrincipalSignInActivities is None:
        return []
    last = {}
    for a in snap.servicePrincipalSignInActivities:
        last[a["appId"]] = ts((a.get("lastSignInActivity") or {}).get("lastSignInDateTime"))
    cutoff = snap.now - timedelta(days=cfg["unused_days"])
    out = []
    for sp in snap.servicePrincipals:
        if not sp.get("accountEnabled"):
            continue
        if sp.get("servicePrincipalType") == "ManagedIdentity" or not sp.get("appId"):
            continue  # managed identities follow their Azure resource; agent identities carry no appId
        holds = bool(snap.app_permissions(sp["id"]) or snap.roles_by_principal.get(sp["id"])
                     or snap.grants_by_client.get(sp["id"]))
        if not holds:
            continue
        app = snap.app_of(sp)
        created = ts(app.get("createdDateTime")) if app else None
        if created and created > cutoff:
            continue  # too new to call unused
        seen = last.get(sp["appId"])
        if seen is not None and seen >= cutoff:
            continue
        out.append(Finding(
            "C02", "no_sign_in" if seen is None else "stale_sign_in", META["nhi"], sp["id"], "servicePrincipal",
            sp["displayName"], escalate(snap, cfg, sp, "medium"),
            {"lastSignInDateTime": seen.isoformat() if seen else None, "days_threshold": cfg["unused_days"],
             "appRoleAssignments": len(snap.app_permissions(sp["id"])),
             "directoryRoles": len(snap.roles_by_principal.get(sp["id"], []))},
            "Permissions nobody uses are pure exposure: the identity can still be signed in as, but nothing "
            "would break if it were disabled.",
            "Entra admin center > Monitoring > Usage & insights > Service principal sign-in activity; "
            f"GET /beta/reports/servicePrincipalSignInActivities?$filter=appId eq '{sp['appId']}'",
        ))
    return out
