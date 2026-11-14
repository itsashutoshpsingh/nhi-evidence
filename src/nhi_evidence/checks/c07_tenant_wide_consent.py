"""Check 7: delegated consent for all users (AllPrincipals) that includes sensitive scopes (NHI5)."""

from .. import refs
from ..finding import Finding, escalate

META = {
    "id": "C07", "title": "Tenant-wide consent to sensitive scopes", "nhi": ["NHI5"],
    "graph": ["GET /v1.0/oauth2PermissionGrants"],
    "licence": "free",
}


def run(snap, cfg) -> list[Finding]:
    out = []
    sensitive = set(cfg["sensitive_delegated"])
    for g in snap.oauth2PermissionGrants:
        if g.get("consentType") != "AllPrincipals":
            continue
        client = snap.sp_by_id.get(g["clientId"])
        resource = snap.sp_by_id.get(g["resourceId"])
        if not client:
            continue
        if not resource or resource.get("appId") != refs.MS_GRAPH_APP_ID:
            continue
        hits = sorted(set((g.get("scope") or "").split()) & sensitive)
        if not hits:
            continue
        out.append(Finding(
            "C07", "all_principals_sensitive_scope", META["nhi"], client["id"], "servicePrincipal",
            client["displayName"], escalate(snap, cfg, client, "high"),
            {"grantId": g["id"], "consentType": "AllPrincipals", "sensitive_scopes": hits, "scope": g.get("scope")},
            "Consent for all users lets this app act as any user who signs in to it, over that user's mail, files "
            "or directory data, without each user being asked.",
            "Entra admin center > Enterprise applications > app > Permissions (Admin consent tab); "
            f"GET /v1.0/oauth2PermissionGrants?$filter=clientId eq '{client['id']}'",
        ))
    return out
