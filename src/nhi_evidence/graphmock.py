"""An in-process stand-in for the Microsoft Graph endpoints the collector reads, serving a Snapshot.

It pages like Graph ($top up to 999, default 100, @odata.nextLink with a $skiptoken), applies $select
(keeping @odata.type, as Graph does for derived types), can return 429 with Retry-After every N requests,
and answers anything but GET with 405. Used by tests and by the collection-cost experiment.
"""

import re
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from .snapshot import Snapshot


class MockGraph:
    def __init__(self, snap: Snapshot, throttle_every: int = 0):
        self.snap = snap
        self.throttle_every = throttle_every
        self.requests = 0
        self.writes = []
        self.versions = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def _collection(self, path: str, query: dict):
        s, d = self.snap, self.snap.data
        routes = [
            (r"^/organization$", lambda m: d["organization"]),
            (r"^/applications$", lambda m: d["applications"]),
            (r"^/applications/([^/]+)/owners$", lambda m: d["applicationOwners"].get(m[1], [])),
            (r"^/applications/([^/]+)/federatedIdentityCredentials$",
             lambda m: d["federatedIdentityCredentials"].get(m[1], [])),
            (r"^/servicePrincipals$", lambda m: d["servicePrincipals"]),
            (r"^/servicePrincipals/([^/]+)/owners$", lambda m: d["servicePrincipalOwners"].get(m[1], [])),
            (r"^/servicePrincipals/([^/]+)/appRoleAssignments$", lambda m: s.assignments_by_principal.get(m[1], [])),
            (r"^/oauth2PermissionGrants$", lambda m: d["oauth2PermissionGrants"]),
            (r"^/roleManagement/directory/roleDefinitions$", lambda m: d["roleDefinitions"]),
            (r"^/roleManagement/directory/roleAssignments$", lambda m: d["roleAssignments"]),
            (r"^/users$", lambda m: d["users"]),
            (r"^/groups$", lambda m: [g for g in d["groups"] if g.get("isAssignableToRole")]),
            (r"^/groups/([^/]+)/members$", lambda m: d["groupMembers"].get(m[1], [])),
            (r"^/groups/([^/]+)/owners$", lambda m: d["groupOwners"].get(m[1], [])),
            (r"^/identity/conditionalAccess/policies$", lambda m: d["conditionalAccessPolicies"]),
            (r"^/reports/servicePrincipalSignInActivities$", lambda m: d["servicePrincipalSignInActivities"] or []),
            (r"^/auditLogs/signIns$", lambda m: self._signins(query)),
        ]
        for pattern, fn in routes:
            m = re.match(pattern, path)
            if m:
                return fn(m)
        return None

    def _signins(self, query):
        rows = self.snap.data["signIns"] or []
        f = query.get("$filter", [""])[0]
        m = re.match(r"createdDateTime ge (\S+)", f)
        return [r for r in rows if not m or r["createdDateTime"] >= m[1]]

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if request.method != "GET":
            self.writes.append((request.method, str(request.url)))
            return httpx.Response(405, json={"error": {"code": "Request_BadRequest", "message": "read-only mock"}})
        if self.throttle_every and self.requests % self.throttle_every == 0:
            return httpx.Response(429, headers={"Retry-After": "1"}, json={"error": {"code": "TooManyRequests"}})
        u = urlsplit(str(request.url))
        version, _, path = u.path.lstrip("/").partition("/")
        self.versions.append(version)
        query = parse_qs(u.query)
        rows = self._collection("/" + path, query)
        if rows is None:
            return httpx.Response(404, json={"error": {"code": "Request_ResourceNotFound"}})
        top = min(int(query.get("$top", ["100"])[0]), 999)
        skip = int(query.get("$skiptoken", ["0"])[0])
        page = rows[skip:skip + top]
        if "$select" in query:
            keep = set(query["$select"][0].split(",")) | {"@odata.type"}
            page = [{k: v for k, v in r.items() if k in keep} for r in page]
        body = {"value": page}
        if skip + top < len(rows):
            q = {k: v[0] for k, v in query.items()} | {"$skiptoken": str(skip + top)}
            body["@odata.nextLink"] = f"{u.scheme}://{u.netloc}{u.path}?{urlencode(q)}"
        return httpx.Response(200, json=body)
