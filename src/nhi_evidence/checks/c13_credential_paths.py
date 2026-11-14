"""Check 13: non-privileged principals that can add a credential to a privileged service principal (NHI5)."""

from .. import graph
from ..finding import Finding

META = {
    "id": "C13", "title": "Credential-control path to a privileged identity", "nhi": ["NHI5"],
    "graph": ["owners, directory role assignments, role-assignable group members and owners, "
              "app role assignments (combined as a graph)"],
    "licence": "free",
}


def run(snap, cfg) -> list[Finding]:
    g = graph.build(snap, cfg)
    out = []
    for sp_id, (count, found) in graph.paths(snap, cfg, g).items():
        sp = snap.sp_by_id[sp_id]
        described = [graph.describe(g, p, snap) for p in found]
        shortest = min(d["hops"] for d in described)
        out.append(Finding(
            "C13", "path_from_non_privileged", META["nhi"], sp_id, "servicePrincipal", sp["displayName"],
            "critical" if shortest <= 2 else "high",
            {"principals_with_path": count, "shortest_hops": shortest, "paths": described},
            "Whoever can add a credential to a privileged service principal can sign in as it and use all of "
            "its permissions, so these people and apps are as privileged as the identity itself.",
            "For each step: Entra admin center > App registrations > app > Owners; Roles & admins > role > "
            "Assignments; Groups > group > Members/Owners. Graph: GET /v1.0/applications/{id}/owners, "
            "GET /v1.0/roleManagement/directory/roleAssignments",
        ))
    return out
