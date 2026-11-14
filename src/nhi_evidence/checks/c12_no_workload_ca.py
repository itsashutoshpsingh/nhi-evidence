"""Check 12: credentialed, permissioned single-tenant service principal not covered by any enforced
Conditional Access policy for workload identities (NHI4). Needs Workload Identities Premium to fix."""

from ..finding import Finding, escalate

META = {
    "id": "C12", "title": "No workload identity Conditional Access", "nhi": ["NHI4"],
    "graph": ["GET /v1.0/identity/conditionalAccess/policies"],
    "licence": "Workload Identities Premium to create policies; reading is free (Policy.Read.All)",
}


def coverage(snap) -> tuple[set, set, bool]:
    included, excluded, filtered = set(), set(), False
    for p in snap.conditionalAccessPolicies:
        if p.get("state") != "enabled":
            continue  # report-only and disabled policies enforce nothing
        ca = (p.get("conditions") or {}).get("clientApplications") or {}
        if ca.get("servicePrincipalFilter"):
            filtered = True
        included |= set(ca.get("includeServicePrincipals") or [])
        excluded |= set(ca.get("excludeServicePrincipals") or [])
    return included, excluded, filtered


def run(snap, cfg) -> list[Finding]:
    included, excluded, filtered = coverage(snap)
    out = []
    for sp in snap.servicePrincipals:
        # Microsoft: policies apply to single tenant service principals registered in your tenant;
        # multitenant/SaaS apps and managed identities are not covered, so they are not flagged here
        if not snap.is_home_tenant(sp) or sp.get("servicePrincipalType") != "Application":
            continue
        if not sp.get("accountEnabled"):
            continue
        app = snap.app_of(sp)
        if app and app.get("signInAudience") not in (None, "AzureADMyOrg"):
            continue
        holds = snap.app_permissions(sp["id"]) or snap.roles_by_principal.get(sp["id"])
        has_creds = any(snap.active(c) for _, _, c in snap.credentials(sp)) or snap.fics_of(sp)
        if not holds or not has_creds:
            continue
        covered = (sp["id"] in included or "ServicePrincipalsInMyTenant" in included) and sp["id"] not in excluded
        if covered or filtered:
            continue  # shortcut: filter rules use custom security attributes we do not read; counted as covered
        out.append(Finding(
            "C12", "not_in_enforced_policy", META["nhi"], sp["id"], "servicePrincipal", sp["displayName"],
            escalate(snap, cfg, sp, "low"),
            {"enforced_policies": sum(p.get("state") == "enabled" for p in snap.conditionalAccessPolicies)},
            "Without a workload identity policy a stolen credential works from any network; a location or "
            "risk policy is the control that limits where the app can sign in from.",
            "Entra admin center > Conditional Access > Policies (Assignments > Workload identities); "
            "GET /v1.0/identity/conditionalAccess/policies",
        ))
    return out
