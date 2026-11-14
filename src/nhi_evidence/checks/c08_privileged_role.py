"""Check 8: service principal holding a privileged Entra directory role (NHI5)."""

from ..finding import Finding, privileged_roles

META = {
    "id": "C08", "title": "Privileged directory role", "nhi": ["NHI5"],
    "graph": ["GET /v1.0/roleManagement/directory/roleAssignments",
              "GET /v1.0/roleManagement/directory/roleDefinitions"],
    "licence": "free",
}


def run(snap, cfg) -> list[Finding]:
    out = []
    for sp in snap.servicePrincipals:
        held = privileged_roles(snap, sp["id"])
        if not held:
            continue
        names = sorted({snap.role_name(r) for r in held})
        tenant_wide = [r for r in held if r.get("directoryScopeId", "/") == "/"]
        critical = any(snap.role_name(r) in cfg["critical_roles"] for r in tenant_wide)
        out.append(Finding(
            "C08", "privileged_directory_role", META["nhi"], sp["id"], "servicePrincipal", sp["displayName"],
            "critical" if critical else ("high" if tenant_wide else "medium"),
            {"roles": names, "assignments": [{"id": r["id"], "role": snap.role_name(r),
                                              "directoryScopeId": r.get("directoryScopeId")} for r in held]},
            "A workload signing in with this role has administrator power over the directory, and service "
            "principals cannot do MFA, so the role is only as safe as the app's credentials.",
            "Entra admin center > Roles & admins > role > Assignments; "
            f"GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '{sp['id']}'",
        ))
    return out
