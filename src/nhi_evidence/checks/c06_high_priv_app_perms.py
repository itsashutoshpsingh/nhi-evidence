"""Check 6: high-privilege Microsoft Graph application permissions (NHI5 Overprivileged NHI)."""

from ..finding import Finding, privileged_graph

META = {
    "id": "C06", "title": "High-privilege application permission", "nhi": ["NHI5"],
    "graph": ["GET /v1.0/servicePrincipals/{id}/appRoleAssignments"],
    "licence": "free",
}


def run(snap, cfg) -> list[Finding]:
    out = []
    for sp in snap.servicePrincipals:
        perms = privileged_graph(snap, cfg, sp["id"])
        if not perms:
            continue
        tier0 = [p for p, t in perms if t == "tier0"]
        out.append(Finding(
            "C06", "tier0_graph_permission" if tier0 else "data_graph_permission", META["nhi"], sp["id"],
            "servicePrincipal", sp["displayName"], "critical" if tier0 else "high",
            {"permissions": sorted(p for p, _ in perms), "tier0": sorted(tier0)},
            ("This identity can make itself, or anything, Global Administrator without a user present."
             if tier0 else
             "This identity can read or change every user's data of that kind, with no user present and no MFA."),
            "Entra admin center > Enterprise applications > app > Permissions (Admin consent tab); "
            f"GET /v1.0/servicePrincipals/{sp['id']}/appRoleAssignments",
        ))
    return out
