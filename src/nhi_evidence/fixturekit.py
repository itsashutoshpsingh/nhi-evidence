"""Build Graph-shaped synthetic tenants (fixtures, mutation tests, scale tests).

Every object uses property names from the Microsoft Graph v1.0 schema (beta for federated credentials and
service principal sign-in activity); tests/test_schema.py checks each key against the docs. IDs are
uuid5 values from a per-tenant namespace, so the same build gives the same bytes. No secret values exist
anywhere: Graph never returns them after creation, and passwordCredential.secretText is always null.
"""

import base64
import hashlib
import uuid
from datetime import datetime, timedelta

from . import refs
from .snapshot import Snapshot

OTHER_TENANTS = {name: str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}.vendor.example"))
                 for name in ("mailmerge", "calendarbooking", "quicksurvey", "ticketdesk", "wallpaper",
                              "backupvault", "notes", "vendor")}
DOMAIN = "lab.example"  # reserved name (RFC 2606); nothing here refers to a real tenant
GITHUB = "https://token.actions.githubusercontent.com"


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Tenant:
    def __init__(self, name: str, now: datetime, include_activity: bool = True):
        self.ns = uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}.{DOMAIN}")
        self.now = now
        self.tenant_id = self.uid("tenant")
        self.d = {k: [] for k in ("applications", "servicePrincipals", "appRoleAssignments",
                                  "oauth2PermissionGrants", "roleAssignments", "users", "groups",
                                  "conditionalAccessPolicies")}
        self.d |= {k: {} for k in ("applicationOwners", "federatedIdentityCredentials", "servicePrincipalOwners",
                                   "servicePrincipalSponsors", "groupMembers", "groupOwners")}
        self.d["organization"] = [{"id": self.tenant_id, "displayName": "Lab tenant (synthetic)"}]
        self.d["roleDefinitions"] = [
            {"id": tid, "templateId": tid, "displayName": r["displayName"], "isBuiltIn": True, "isEnabled": True,
             "isPrivileged": r["privileged"]} for tid, r in sorted(refs.roles().items())]
        self.d["servicePrincipalSignInActivities"] = [] if include_activity else None
        self.d["signIns"] = [] if include_activity else None
        self.by_name = {}
        self.graph = self.first_party("Microsoft Graph", refs.MS_GRAPH_APP_ID, graph_roles=True)

    # ---- ids and times ---------------------------------------------------------------------------
    def uid(self, *parts) -> str:
        return str(uuid.uuid5(self.ns, "/".join(map(str, parts))))

    def opaque(self, *parts) -> str:  # Graph uses base64url-like ids for grants and assignments
        return base64.urlsafe_b64encode(hashlib.sha256("/".join(map(str, parts)).encode()).digest()[:33]).decode()

    def ago(self, days: float) -> str:
        return iso(self.now - timedelta(days=days))

    # ---- directory ---------------------------------------------------------------------------------
    def user(self, nick: str, name: str, enabled: bool = True) -> dict:
        u = {"id": self.uid("user", nick), "displayName": name, "userPrincipalName": f"{nick}@{DOMAIN}",
             "accountEnabled": enabled, "userType": "Member"}
        self.d["users"].append(u)
        self.by_name[nick] = u
        return u

    def group(self, name: str, members=(), owners=()) -> dict:
        g = {"id": self.uid("group", name), "displayName": name, "isAssignableToRole": True,
             "securityEnabled": True, "mailEnabled": False}
        self.d["groups"].append(g)
        self.d["groupMembers"][g["id"]] = [self.ref(m) for m in members]
        self.d["groupOwners"][g["id"]] = [self.ref(o) for o in owners]
        self.by_name[name] = g
        return g

    def ref(self, obj: dict) -> dict:
        """directoryObject as returned by /owners, /members, /sponsors with $select."""
        if "userPrincipalName" in obj:
            return {"@odata.type": "#microsoft.graph.user", "id": obj["id"], "displayName": obj["displayName"],
                    "userPrincipalName": obj["userPrincipalName"], "accountEnabled": obj["accountEnabled"]}
        return {"@odata.type": "#microsoft.graph.servicePrincipal", "id": obj["id"],
                "displayName": obj["displayName"], "accountEnabled": obj.get("accountEnabled", True)}

    def role(self, principal: dict, role_name: str, scope: str = "/") -> dict:
        r = {"id": self.opaque("ra", principal["id"], role_name, scope), "principalId": principal["id"],
             "roleDefinitionId": refs.role_id(role_name), "directoryScopeId": scope}
        self.d["roleAssignments"].append(r)
        return r

    # ---- credentials -------------------------------------------------------------------------------
    def secret(self, key: str, start_ago: float, lifetime: float | None) -> dict:
        start = self.now - timedelta(days=start_ago)
        return {"customKeyIdentifier": None, "displayName": f"{key} secret", "endDateTime":
                iso(start + timedelta(days=lifetime)) if lifetime is not None else None,
                "hint": "Lab", "keyId": self.uid("pw", key, start_ago, lifetime), "secretText": None,
                "startDateTime": iso(start)}

    def cert(self, key: str, start_ago: float = 30, lifetime: float = 365) -> dict:
        start = self.now - timedelta(days=start_ago)
        thumb = hashlib.sha1(f"{self.ns}/{key}/{start_ago}".encode()).hexdigest().upper()
        return {"customKeyIdentifier": thumb, "displayName": f"CN={key}", "endDateTime":
                iso(start + timedelta(days=lifetime)), "key": None, "keyId": self.uid("key", key, start_ago),
                "startDateTime": iso(start), "type": "AsymmetricX509Cert", "usage": "Verify"}

    def fic(self, name: str, subject: str | None, issuer: str = GITHUB, expression: str | None = None,
            audiences=("api://AzureADTokenExchange",)) -> dict:
        return {"audiences": list(audiences), "claimsMatchingExpression":
                {"languageVersion": 1, "value": expression} if expression else None,
                "description": None, "id": self.uid("fic", name, subject, expression), "issuer": issuer,
                "name": name, "subject": subject}

    # ---- applications and service principals ----------------------------------------------------
    def first_party(self, name: str, app_id: str, graph_roles: bool = False) -> dict:
        sp = self._sp(name, app_id, "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
                      {"displayName": "Microsoft Corporation", "verifiedPublisherId": None, "addedDateTime": None})
        if graph_roles:  # the real Graph SP exposes every application permission as an appRole
            sp["appRoles"] = [{"allowedMemberTypes": ["Application"], "description": n, "displayName": n,
                               "id": ids["application"], "isEnabled": True, "origin": "Application", "value": n}
                              for n, ids in sorted(refs.permissions().items()) if ids["application"]]
        return sp

    def _sp(self, name, app_id, owner_org, publisher, sp_type="Application", enabled=True, audience=None):
        sp = {"id": self.uid("sp", name), "appId": app_id, "displayName": name, "appDisplayName": name,
              "accountEnabled": enabled, "appOwnerOrganizationId": owner_org, "servicePrincipalType": sp_type,
              "signInAudience": audience, "verifiedPublisher": publisher, "passwordCredentials": [],
              "keyCredentials": [], "appRoles": [], "tags": []}
        self.d["servicePrincipals"].append(sp)
        self.by_name[name] = sp
        return sp

    def app(self, name: str, owners=(), secrets=(), certs=(), fics=(), smr=None, redirects=(), perms=(),
            all_consent=None, roles=(), created_ago: float = 400, audience="AzureADMyOrg",
            sp_secrets=(), enabled=True, last_sign_in: float | None = 3) -> tuple[dict, dict]:
        """An app registration in this tenant with its service principal. secrets: (start_ago, lifetime)."""
        app_id = self.uid("appId", name)
        app = {"id": self.uid("app", name), "appId": app_id, "displayName": name,
               "createdDateTime": self.ago(created_ago), "signInAudience": audience,
               "publisherDomain": DOMAIN, "isFallbackPublicClient": False, "identifierUris": [],
               "serviceManagementReference": smr, "tags": [], "notes": None,
               "verifiedPublisher": {"displayName": None, "verifiedPublisherId": None, "addedDateTime": None},
               "web": {"homePageUrl": None, "logoutUrl": None, "redirectUris": list(redirects),
                       "implicitGrantSettings": {"enableAccessTokenIssuance": False,
                                                 "enableIdTokenIssuance": False}},
               "passwordCredentials": [self.secret(f"{name}-{i}", *s) for i, s in enumerate(secrets)],
               "keyCredentials": [self.cert(f"{name}-{i}", *c) for i, c in enumerate(certs)]}
        self.d["applications"].append(app)
        self.d["applicationOwners"][app["id"]] = [self.ref(o) for o in owners]
        self.d["federatedIdentityCredentials"][app["id"]] = list(fics)
        sp = self._sp(name, app_id, self.tenant_id, None, enabled=enabled, audience=audience)
        sp["verifiedPublisher"] = {"displayName": None, "verifiedPublisherId": None, "addedDateTime": None}
        sp["passwordCredentials"] = [self.secret(f"{name}-sp-{i}", *s) for i, s in enumerate(sp_secrets)]
        self.by_name[name] = sp
        self.by_name[f"app:{name}"] = app
        self._access(sp, perms, all_consent, roles, last_sign_in)
        return app, sp

    def third_party(self, name: str, vendor: str, verified: bool, perms=(), all_consent=None,
                    principal_consent=None, last_sign_in: float | None = 3) -> dict:
        pub_id = str(int(hashlib.sha256(vendor.encode()).hexdigest(), 16) % 10**7)
        pub = ({"displayName": f"{vendor} Ltd", "verifiedPublisherId": pub_id,
                "addedDateTime": self.ago(900)} if verified else
               {"displayName": None, "verifiedPublisherId": None, "addedDateTime": None})
        sp = self._sp(name, self.uid("appId", name), OTHER_TENANTS[vendor], pub, audience="AzureADMultipleOrgs")
        self._access(sp, perms, all_consent, (), last_sign_in)
        if principal_consent:
            user, scope = principal_consent
            self.d["oauth2PermissionGrants"].append(
                {"id": self.opaque("grant", sp["id"], user["id"]), "clientId": sp["id"], "consentType": "Principal",
                 "principalId": user["id"], "resourceId": self.graph["id"], "scope": scope})
        return sp

    def managed_identity(self, name: str, perms=()) -> dict:
        sp = self._sp(name, self.uid("appId", name), None, None, sp_type="ManagedIdentity")
        sp["keyCredentials"] = [self.cert(f"{name}-mi", 10, 180)]
        self._access(sp, perms, None, (), None)
        return sp

    def agent(self, name: str, sponsors=(), perms=()) -> dict:
        sp = {"@odata.type": "#microsoft.graph.agentIdentity", "id": self.uid("sp", name), "displayName": name,
              "accountEnabled": True, "servicePrincipalType": "ServiceIdentity",
              "agentIdentityBlueprintId": self.uid("appId", "agent-blueprint"),
              "createdByAppId": self.uid("appId", "agent-blueprint"), "createdDateTime": self.ago(60),
              "disabledByMicrosoftStatus": None, "tags": [], "appRoles": []}
        self.d["servicePrincipals"].append(sp)
        self.d["servicePrincipalSponsors"][sp["id"]] = [self.ref(s) for s in sponsors]
        self.by_name[name] = sp
        self._access(sp, perms, None, (), None)
        return sp

    def _access(self, sp, perms, all_consent, roles, last_sign_in):
        for p in perms:
            self.d["appRoleAssignments"].append(
                {"id": self.opaque("ara", sp["id"], p), "appRoleId": refs.app_role_id(p),
                 "createdDateTime": self.ago(200), "deletedDateTime": None,
                 "principalDisplayName": sp["displayName"], "principalId": sp["id"],
                 "principalType": "ServicePrincipal", "resourceDisplayName": "Microsoft Graph",
                 "resourceId": self.graph["id"]})
        if all_consent:
            self.d["oauth2PermissionGrants"].append(
                {"id": self.opaque("grant", sp["id"], "all"), "clientId": sp["id"], "consentType": "AllPrincipals",
                 "principalId": None, "resourceId": self.graph["id"], "scope": all_consent})
        for r in roles:
            self.role(sp, r)
        if last_sign_in is not None and self.d["servicePrincipalSignInActivities"] is not None and sp.get("appId"):
            self.sign_in_activity(sp, last_sign_in)

    def sign_in_activity(self, sp: dict, days_ago: float | None) -> None:
        acts = self.d["servicePrincipalSignInActivities"]
        acts[:] = [a for a in acts if a["appId"] != sp["appId"]]
        if days_ago is None:
            return
        act = {"lastSignInDateTime": self.ago(days_ago), "lastSignInRequestId": self.uid("req", sp["id"])}
        empty = {"lastSignInDateTime": None, "lastSignInRequestId": None}
        acts.append({"id": self.opaque("spsia", sp["appId"]), "appId": sp["appId"], "lastSignInActivity": act,
                     "applicationAuthenticationClientSignInActivity": act,
                     "applicationAuthenticationResourceSignInActivity": empty,
                     "delegatedClientSignInActivity": empty, "delegatedResourceSignInActivity": empty})

    def ca_policy(self, name: str, include=("ServicePrincipalsInMyTenant",), exclude=(), state="enabled") -> dict:
        p = {"id": self.uid("ca", name), "displayName": name, "state": state, "createdDateTime": self.ago(300),
             "modifiedDateTime": self.ago(30),
             "conditions": {"applications": {"includeApplications": ["All"], "excludeApplications": []},
                            "clientApplications": {"includeServicePrincipals": list(include),
                                                   "excludeServicePrincipals": list(exclude),
                                                   "servicePrincipalFilter": None},
                            "locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}},
             "grantControls": {"operator": "OR", "builtInControls": ["block"]}, "sessionControls": None}
        self.d["conditionalAccessPolicies"].append(p)
        return p

    def sign_in(self, user: dict, app_name: str, app_id: str, days_ago: float, interactive=True, error=0,
                client="Browser", n: int = 0) -> None:
        self.d["signIns"].append({
            "id": self.uid("signin", user["id"], days_ago, n), "createdDateTime": self.ago(days_ago),
            "userDisplayName": user["displayName"], "userPrincipalName": user["userPrincipalName"],
            "userId": user["id"], "appId": app_id, "appDisplayName": app_name, "ipAddress": f"203.0.113.{10 + n}",
            "clientAppUsed": client, "correlationId": self.uid("corr", user["id"], days_ago, n),
            "conditionalAccessStatus": "notApplied", "isInteractive": interactive,
            "resourceDisplayName": "Windows Azure Service Management API",
            "resourceId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
            "status": {"errorCode": error, "failureReason": None if error == 0 else "Invalid username or password",
                       "additionalDetails": None},
            "riskDetail": "none", "riskLevelAggregated": "none", "riskLevelDuringSignIn": "none", "riskState": "none",
            "riskEventTypes_v2": [], "appliedConditionalAccessPolicies": []})

    def snapshot(self, source: str = "synthetic fixture") -> Snapshot:
        manifest = {"collected_at": iso(self.now), "source": source, "tenant": "synthetic, not a real tenant",
                    "api_versions": {"servicePrincipalSignInActivities": "beta", "federatedIdentityCredentials": "beta",
                                     "default": "v1.0"}}
        return Snapshot(self.d, manifest)
