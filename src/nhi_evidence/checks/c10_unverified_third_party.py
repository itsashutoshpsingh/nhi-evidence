"""Check 10: multi-tenant app from an unverified publisher that holds permissions (NHI3)."""

from ..finding import Finding, escalate

META = {
    "id": "C10", "title": "Unverified third-party app with access", "nhi": ["NHI3"],
    "graph": ["GET /v1.0/servicePrincipals ($select=appOwnerOrganizationId,verifiedPublisher)",
              "GET /v1.0/oauth2PermissionGrants"],
    "licence": "free",
}


def run(snap, cfg) -> list[Finding]:
    out = []
    basic = set(cfg["basic_delegated"])
    for sp in snap.servicePrincipals:
        owner_org = sp.get("appOwnerOrganizationId")
        if not owner_org or snap.is_home_tenant(sp):
            continue
        if (sp.get("verifiedPublisher") or {}).get("verifiedPublisherId"):
            continue
        app_perms = snap.app_permissions(sp["id"])
        wide = sorted({s for g in snap.grants_by_client.get(sp["id"], []) if g.get("consentType") == "AllPrincipals"
                       for s in (g.get("scope") or "").split()} - basic)
        if not app_perms and not wide and not snap.roles_by_principal.get(sp["id"]):
            continue
        out.append(Finding(
            "C10", "unverified_publisher_with_access", META["nhi"], sp["id"], "servicePrincipal",
            sp["displayName"], escalate(snap, cfg, sp, "medium"),
            {"appOwnerOrganizationId": owner_org, "verifiedPublisher": sp.get("verifiedPublisher"),
             "application_permissions": sorted(filter(None, (snap.app_role_value(a) for a in app_perms))),
             "tenant_wide_delegated_scopes": wide},
            "Another organisation controls this app's code and credentials, and Microsoft has not verified who "
            "they are; if they are breached, their access to your tenant goes with it.",
            "Entra admin center > Enterprise applications > app > Properties (Publisher) and Permissions; "
            f"GET /v1.0/servicePrincipals/{sp['id']}?$select=appOwnerOrganizationId,verifiedPublisher",
        ))
    return out
