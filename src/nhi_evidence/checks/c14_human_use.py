"""Check 14: a service account used interactively by a person (NHI10 Human Use of NHI)."""

import re

from ..finding import Finding

META = {
    "id": "C14", "title": "Service account used interactively", "nhi": ["NHI10"],
    "graph": ["GET /v1.0/auditLogs/signIns"],
    "licence": "AuditLog.Read.All and Entra ID P1 or P2",
    "needs": "signIns",
}


def run(snap, cfg) -> list[Finding]:
    if snap.signIns is None:
        return []
    pattern = re.compile(cfg["service_account_pattern"], re.I)
    listed = set(cfg["service_account_ids"])
    by_user = {}
    for s in snap.signIns:
        if not s.get("isInteractive") or (s.get("status") or {}).get("errorCode") != 0:
            continue
        upn = s.get("userPrincipalName") or ""
        if s.get("userId") in listed or pattern.match(upn.split("@")[0]):
            by_user.setdefault(s["userId"], []).append(s)
    out = []
    for uid, rows in by_user.items():
        user = snap.user_by_id.get(uid, {})
        out.append(Finding(
            "C14", "interactive_service_account", META["nhi"], uid, "user",
            user.get("displayName") or rows[0].get("userDisplayName", uid), "medium",
            {"userPrincipalName": rows[0].get("userPrincipalName"), "interactive_sign_ins": len(rows),
             "apps": sorted({r.get("appDisplayName") for r in rows}),
             "clientAppUsed": sorted({r.get("clientAppUsed") for r in rows}),
             "first": min(r["createdDateTime"] for r in rows), "last": max(r["createdDateTime"] for r in rows)},
            "When a person signs in as a service account, its actions can no longer be told apart from the "
            "automation's, and the account's standing access becomes that person's.",
            "Entra admin center > Monitoring > Sign-in logs (filter: user, Interactive); "
            f"GET /v1.0/auditLogs/signIns?$filter=userId eq '{uid}'",
        ))
    return out
