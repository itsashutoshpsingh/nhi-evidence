"""Check 1: app registration or agent identity with no accountable owner (NHI1 Improper Offboarding)."""

from ..finding import Finding, escalate

META = {
    "id": "C01", "title": "No accountable owner", "nhi": ["NHI1"],
    "graph": ["GET /v1.0/applications/{id}/owners", "GET /v1.0/servicePrincipals/{id}/sponsors (agents)"],
    "licence": "free",
}


def _enabled_humans(owners: list[dict]) -> list[dict]:
    return [o for o in owners if o.get("@odata.type") == "#microsoft.graph.user" and o.get("accountEnabled")]


def run(snap, cfg) -> list[Finding]:
    out = []
    for app in snap.applications:
        owners = snap.applicationOwners.get(app["id"], [])
        # serviceManagementReference is Microsoft's documented field for an accountable service/owner
        # record; privileged apps should not have Entra owners (owners can add credentials, check 13).
        if _enabled_humans(owners) or app.get("serviceManagementReference"):
            continue
        sp = snap.sp_of(app)
        rule = "no_owner" if not owners else "only_disabled_or_nonhuman_owners"
        out.append(Finding(
            "C01", rule, META["nhi"], app["id"], "application", app["displayName"],
            escalate(snap, cfg, sp, "medium"),
            {"owners": [{"id": o["id"], "type": o.get("@odata.type"), "accountEnabled": o.get("accountEnabled")}
                        for o in owners],
             "serviceManagementReference": app.get("serviceManagementReference")},
            "Nobody is accountable for this app: no one will rotate its credentials, review its permissions or "
            "retire it, and a forgotten app keeps working for whoever holds its credentials.",
            "Entra admin center > App registrations > All applications > app > Owners; "
            f"GET /v1.0/applications/{app['id']}/owners",
        ))
    sponsors = snap.servicePrincipalSponsors
    for sp in snap.servicePrincipals:
        if not snap.is_agent(sp) or sponsors is None:
            continue
        people = _enabled_humans(sponsors.get(sp["id"], []) + snap.servicePrincipalOwners.get(sp["id"], []))
        if not people:
            out.append(Finding(
                "C01", "agent_no_sponsor", META["nhi"], sp["id"], "servicePrincipal", sp["displayName"],
                escalate(snap, cfg, sp, "medium"),
                {"sponsors": sponsors.get(sp["id"], []), "owners": snap.servicePrincipalOwners.get(sp["id"], [])},
                "An agent identity with no enabled sponsor or owner has nobody to answer for what it does or "
                "to retire it when the agent is gone.",
                "Entra admin center > Agent ID > All agent identities > agent > Sponsors; "
                f"GET /v1.0/servicePrincipals/{sp['id']}/sponsors",
            ))
    return out
