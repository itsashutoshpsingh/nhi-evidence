"""Read-only collector: paged GET requests to Microsoft Graph, written as a snapshot directory.

Only GET is ever sent (Graph.get enforces it). Every call's API version is pinned here and recorded in
the manifest. Paging follows @odata.nextLink to the end; 429, 503 and 504 are retried after the
Retry-After header (Microsoft Graph throttling guidance), with exponential backoff when it is absent.
"""

import time
from collections import Counter
from datetime import UTC, datetime, timedelta

import httpx

from . import __version__
from .snapshot import Snapshot

BASE = "https://graph.microsoft.com"
RETRY = {429, 503, 504}
APP_SELECT = ("id,appId,displayName,createdDateTime,signInAudience,publisherDomain,verifiedPublisher,"
              "passwordCredentials,keyCredentials,web,identifierUris,serviceManagementReference,tags,notes,"
              "isFallbackPublicClient")
SP_SELECT = ("id,appId,displayName,appDisplayName,accountEnabled,appOwnerOrganizationId,servicePrincipalType,"
             "signInAudience,verifiedPublisher,passwordCredentials,keyCredentials,appRoles,tags")
OWNER_SELECT = "id,displayName,userPrincipalName,accountEnabled"
# file -> API version used for it. Flexible federated credentials (claimsMatchingExpression) and service
# principal sign-in activity exist only in beta at the docs commit this was written against.
VERSIONS = {"federatedIdentityCredentials": "beta", "servicePrincipalSignInActivities": "beta"}


def endpoint(url: str) -> str:
    """'https://graph.microsoft.com/v1.0/applications/<id>/owners?x' -> 'v1.0 /applications/{id}/owners'."""
    parts = url.split("?")[0].removeprefix(BASE).strip("/").split("/")
    return parts[0] + " /" + "/".join("{id}" if len(p) == 36 and p.count("-") == 4 else p for p in parts[1:])


class Graph:
    def __init__(self, token: str, client: httpx.Client | None = None, max_retries: int = 6, sleep=time.sleep):
        self.client = client or httpx.Client(timeout=60)
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        self.max_retries = max_retries
        self.sleep = sleep
        self.calls = Counter()
        self.throttled = 0

    def get(self, url: str, extra_headers: dict | None = None) -> dict:
        for attempt in range(self.max_retries + 1):
            r = self.client.request("GET", url, headers=self.headers | (extra_headers or {}))
            if r.status_code in RETRY and attempt < self.max_retries:
                self.throttled += 1
                wait = r.headers.get("Retry-After")
                self.sleep(float(wait) if wait and wait.replace(".", "", 1).isdigit() else min(2 ** attempt, 60))
                continue
            self.calls[endpoint(url)] += 1
            r.raise_for_status()
            return r.json()
        raise RuntimeError("unreachable")

    def paged(self, path: str, version: str = "v1.0", extra_headers: dict | None = None) -> list[dict]:
        url, out = f"{BASE}/{version}{path}", []
        while url:
            body = self.get(url, extra_headers)
            out.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        return out


def collect(g: Graph, activity: bool = True, sign_in_days: int = 30, now: datetime | None = None) -> Snapshot:
    now = now or datetime.now(UTC)
    d = {"organization": g.paged("/organization?$select=id")}
    d["applications"] = g.paged(f"/applications?$select={APP_SELECT}&$top=999")
    d["applicationOwners"] = {a["id"]: g.paged(f"/applications/{a['id']}/owners?$select={OWNER_SELECT}")
                              for a in d["applications"]}
    d["federatedIdentityCredentials"] = {
        a["id"]: g.paged(f"/applications/{a['id']}/federatedIdentityCredentials",
                         VERSIONS["federatedIdentityCredentials"])
        for a in d["applications"]}
    d["servicePrincipals"] = g.paged(f"/servicePrincipals?$select={SP_SELECT}&$top=999")
    d["servicePrincipalOwners"] = {s["id"]: g.paged(f"/servicePrincipals/{s['id']}/owners?$select={OWNER_SELECT}")
                                   for s in d["servicePrincipals"]}
    # Listing agent sponsors needs AgentIdentity.ReadWrite.All (application only) per the Graph docs, which the
    # read-only check refuses, so sponsors are not collected (servicePrincipalSponsors stays absent).
    d["appRoleAssignments"] = [a for s in d["servicePrincipals"]
                               for a in g.paged(f"/servicePrincipals/{s['id']}/appRoleAssignments")]
    d["oauth2PermissionGrants"] = g.paged("/oauth2PermissionGrants")
    d["roleDefinitions"] = g.paged("/roleManagement/directory/roleDefinitions"
                                   "?$select=id,displayName,templateId,isBuiltIn,isEnabled,isPrivileged")
    d["roleAssignments"] = g.paged("/roleManagement/directory/roleAssignments")
    d["users"] = g.paged("/users?$select=id,displayName,userPrincipalName,accountEnabled,userType&$top=999")
    d["groups"] = g.paged("/groups?$filter=isAssignableToRole eq true&$count=true"
                          "&$select=id,displayName,isAssignableToRole,securityEnabled,mailEnabled",
                          extra_headers={"ConsistencyLevel": "eventual"})
    d["groupMembers"] = {x["id"]: g.paged(f"/groups/{x['id']}/members?$select={OWNER_SELECT}") for x in d["groups"]}
    d["groupOwners"] = {x["id"]: g.paged(f"/groups/{x['id']}/owners?$select={OWNER_SELECT}") for x in d["groups"]}
    d["conditionalAccessPolicies"] = g.paged("/identity/conditionalAccess/policies")
    if activity:  # AuditLog.Read.All; sign-in logs also need Entra ID P1 or P2
        d["servicePrincipalSignInActivities"] = g.paged("/reports/servicePrincipalSignInActivities",
                                                        VERSIONS["servicePrincipalSignInActivities"])
        since = (now - timedelta(days=sign_in_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d["signIns"] = g.paged(f"/auditLogs/signIns?$filter=createdDateTime ge {since}&$top=1000")
    else:
        d["servicePrincipalSignInActivities"] = d["signIns"] = None
    d["servicePrincipalSponsors"] = None
    manifest = {"collected_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "source": "Microsoft Graph",
                "tool": f"nhi-evidence {__version__}", "api_versions": {"default": "v1.0", **VERSIONS},
                "calls": dict(g.calls), "throttled_retries": g.throttled}
    return Snapshot(d, manifest)
