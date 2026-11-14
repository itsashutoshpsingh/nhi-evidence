"""Replay the seeding plan against a simulated, writable Graph and evaluate the result.

This shows what `seed_tenant.py apply` should produce in a fresh tenant before anyone runs it for
real, and tests that every step's request is well formed. It is a simulation: Graph's own validation
(app management policies, licence checks) is not modelled.
Run: python lab/simulate.py  (writes results/lab_plan_replay.json)
"""

import json
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "lab")]
import seed_tenant  # noqa: E402

from nhi_evidence import config, engine, refs  # noqa: E402
from nhi_evidence.fixturekit import Tenant, iso  # noqa: E402

START = datetime(2026, 11, 1, tzinfo=UTC)


class WritableGraph:
    def __init__(self, t: Tenant):
        self.t = t
        self.d = t.d
        self.requests = []

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.requests.append((req.method, req.url.path))
        body = json.loads(req.content) if req.content else {}
        path = req.url.path.removeprefix("/v1.0")
        new = str(uuid.uuid5(self.t.ns, f"{req.method}{path}{len(self.requests)}"))
        d, t = self.d, self.t
        if req.method == "GET" and path == "/servicePrincipals":
            return httpx.Response(200, json={"value": [{"id": t.graph["id"]}]})
        if path == "/users":
            u = {"id": new, "displayName": body["displayName"], "userPrincipalName": body["userPrincipalName"],
                 "accountEnabled": body["accountEnabled"], "userType": "Member"}
            d["users"].append(u)
            return httpx.Response(201, json=u)
        if req.method == "PATCH" and path.startswith("/users/"):
            next(u for u in d["users"] if u["id"] == path.split("/")[2]).update(body)
            for owners in d["applicationOwners"].values():  # owners carry accountEnabled in $select output
                for o in owners:
                    if o["id"] == path.split("/")[2]:
                        o.update(body)
            return httpx.Response(204)
        if path == "/applications":
            a = {"id": new, "appId": str(uuid.uuid5(t.ns, new)), "displayName": body["displayName"],
                 "createdDateTime": iso(START), "signInAudience": body["signInAudience"], "tags": body["tags"],
                 "serviceManagementReference": body.get("serviceManagementReference"), "notes": body["notes"],
                 "passwordCredentials": [], "keyCredentials": [], "identifierUris": [],
                 "web": {"redirectUris": []}, "verifiedPublisher": {"verifiedPublisherId": None}}
            d["applications"].append(a)
            d["applicationOwners"][a["id"]] = []
            d["federatedIdentityCredentials"][a["id"]] = []
            return httpx.Response(201, json=a)
        if path == "/servicePrincipals":
            app = next(a for a in d["applications"] if a["appId"] == body["appId"])
            sp = {"id": new, "appId": body["appId"], "displayName": app["displayName"], "accountEnabled": True,
                  "appOwnerOrganizationId": t.tenant_id, "servicePrincipalType": "Application",
                  "signInAudience": app["signInAudience"], "passwordCredentials": [], "keyCredentials": [],
                  "appRoles": [], "tags": body["tags"], "verifiedPublisher": {"verifiedPublisherId": None}}
            d["servicePrincipals"].append(sp)
            return httpx.Response(201, json=sp)
        parts = path.strip("/").split("/")
        if parts[0] == "applications" and parts[-1] == "$ref":
            user = next(u for u in d["users"] if u["id"] == body["@odata.id"].rsplit("/", 1)[1])
            d["applicationOwners"][parts[1]].append(t.ref(user))
            return httpx.Response(204)
        if parts[0] == "applications" and parts[-1] == "addPassword":
            app = next(a for a in d["applications"] if a["id"] == parts[1])
            c = {"customKeyIdentifier": None, "displayName": body["passwordCredential"]["displayName"],
                 "endDateTime": body["passwordCredential"]["endDateTime"], "hint": "Lab", "keyId": new,
                 "secretText": "returned-once-and-discarded", "startDateTime": iso(START)}
            app["passwordCredentials"].append(dict(c, secretText=None))
            return httpx.Response(200, json=c)
        if parts[0] == "applications" and parts[-1] == "federatedIdentityCredentials":
            d["federatedIdentityCredentials"][parts[1]].append(dict(body, id=new, description=None,
                                                                    claimsMatchingExpression=None))
            return httpx.Response(201, json=body)
        if parts[-1] == "appRoleAssignedTo":
            a = dict(body, id=new, principalType="ServicePrincipal", createdDateTime=iso(START))
            d["appRoleAssignments"].append(a)
            return httpx.Response(201, json=a)
        if path == "/oauth2PermissionGrants":
            d["oauth2PermissionGrants"].append(dict(body, id=new, principalId=None))
            return httpx.Response(201, json=body)
        if path == "/roleManagement/directory/roleAssignments":
            d["roleAssignments"].append(dict(body, id=new))
            return httpx.Response(201, json=body)
        if req.method == "PATCH" and parts[0] == "applications":
            app = next(a for a in d["applications"] if a["id"] == parts[1])
            app["keyCredentials"] = [t.cert(app["displayName"], 0, 90)]  # Graph fills dates from the certificate
            return httpx.Response(204)
        if path == "/identity/conditionalAccess/policies":
            d["conditionalAccessPolicies"].append(dict(body, id=new))
            return httpx.Response(201, json=body)
        return httpx.Response(400, json={"error": f"unhandled {req.method} {path}"})


def replay(days_after: float = 2):
    """Apply the plan to an empty simulated tenant; evaluate `days_after` days later."""
    t = Tenant("lab-replay", START, include_activity=False)
    for name, app_id in [("Azure Portal", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c")]:
        t.first_party(name, app_id)
    t.role(t.user("admin", "Lab Admin"), "Global Administrator")
    sim = WritableGraph(t)
    client = httpx.Client(transport=httpx.MockTransport(sim.handle))
    ids = seed_tenant.apply(client, seed_tenant.plan("lab.example", START), lambda: "Lab-password-1!")
    t.now = START + timedelta(days=days_after)
    snap = t.snapshot("replay of lab/seed_tenant.py against a simulated Graph")
    return snap, sim, ids


def main():
    snap, sim, _ = replay()
    fs = [f for f in engine.evaluate(snap, config.load()) if not f.suppressed]
    by_issue = {}
    for st in seed_tenant.plan():
        by_issue.setdefault(st["issue"], st)
    out = {"steps": len(seed_tenant.plan()), "requests": len(sim.requests),
           "methods": sorted({m for m, _ in sim.requests}),
           "findings": sorted([{"check_id": f.check_id, "rule": f.rule, "object": f.display_name,
                                "severity": f.severity} for f in fs], key=lambda x: (x["check_id"], x["object"]))}
    (ROOT / "results" / "lab_plan_replay.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    assert refs.MS_GRAPH_APP_ID


if __name__ == "__main__":
    main()
