"""A snapshot is a directory of Graph-shaped JSON files written by `collect` or by a fixture builder.

Objects keep the exact property names Microsoft Graph returns; this module only indexes them.
"""

import json
from collections import defaultdict
from datetime import datetime
from functools import cached_property
from pathlib import Path

from . import refs

# file -> shape. "list" files hold a JSON array of objects, "map" files map a parent object id to an array.
FILES = {
    "organization": "list",
    "applications": "list",
    "applicationOwners": "map",
    "federatedIdentityCredentials": "map",
    "servicePrincipals": "list",
    "servicePrincipalOwners": "map",
    "servicePrincipalSponsors": "map",
    "appRoleAssignments": "list",
    "oauth2PermissionGrants": "list",
    "roleDefinitions": "list",
    "roleAssignments": "list",
    "users": "list",
    "groups": "list",
    "groupMembers": "map",
    "groupOwners": "map",
    "conditionalAccessPolicies": "list",
    "servicePrincipalSignInActivities": "list",  # optional: beta, AuditLog.Read.All
    "signIns": "list",  # optional: v1.0, AuditLog.Read.All, Entra ID P1 or P2
}
OPTIONAL = {"servicePrincipalSignInActivities", "signIns", "servicePrincipalSponsors"}


def ts(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class Snapshot:
    def __init__(self, data: dict, manifest: dict):
        self.data = data
        self.manifest = manifest
        self.now = ts(manifest["collected_at"])
        self.tenant_id = data["organization"][0]["id"]

    @classmethod
    def load(cls, path: str | Path) -> "Snapshot":
        path = Path(path)
        data = {}
        for name, shape in FILES.items():
            f = path / f"{name}.json"
            if f.exists():
                data[name] = json.loads(f.read_text())
            elif name in OPTIONAL:
                data[name] = None
            else:
                data[name] = [] if shape == "list" else {}
        return cls(data, json.loads((path / "manifest.json").read_text()))

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        (path / "manifest.json").write_text(json.dumps(self.manifest, indent=1) + "\n")
        for name, value in self.data.items():
            if value is not None:
                (path / f"{name}.json").write_text(json.dumps(value, indent=1) + "\n")

    def __getattr__(self, name):  # snap.applications, snap.users, ...
        if name in FILES:
            return self.data[name]
        raise AttributeError(name)

    # ---- indexes -------------------------------------------------------------------------------
    @cached_property
    def app_by_id(self):
        return {a["id"]: a for a in self.applications}

    @cached_property
    def app_by_appid(self):
        return {a["appId"]: a for a in self.applications}

    @cached_property
    def sp_by_id(self):
        return {s["id"]: s for s in self.servicePrincipals}

    @cached_property
    def sp_by_appid(self):
        return {s["appId"]: s for s in self.servicePrincipals if s.get("appId")}

    @cached_property
    def user_by_id(self):
        return {u["id"]: u for u in self.users}

    @cached_property
    def group_by_id(self):
        return {g["id"]: g for g in self.groups}

    @cached_property
    def role_def_by_id(self):
        return {r["id"]: r for r in self.roleDefinitions}

    @cached_property
    def assignments_by_principal(self):
        out = defaultdict(list)
        for a in self.appRoleAssignments:
            out[a["principalId"]].append(a)
        return out

    @cached_property
    def grants_by_client(self):
        out = defaultdict(list)
        for g in self.oauth2PermissionGrants:
            out[g["clientId"]].append(g)
        return out

    @cached_property
    def roles_by_principal(self):
        out = defaultdict(list)
        for r in self.roleAssignments:
            out[r["principalId"]].append(r)
        return out

    # ---- helpers -------------------------------------------------------------------------------
    def app_of(self, sp: dict) -> dict | None:
        return self.app_by_appid.get(sp.get("appId"))

    def sp_of(self, app: dict) -> dict | None:
        return self.sp_by_appid.get(app["appId"])

    def is_first_party(self, sp: dict) -> bool:
        return sp.get("appOwnerOrganizationId") in refs.MICROSOFT_TENANTS

    def is_home_tenant(self, sp: dict) -> bool:
        return sp.get("appOwnerOrganizationId") == self.tenant_id

    def is_agent(self, sp: dict) -> bool:
        return (sp.get("servicePrincipalType") == "ServiceIdentity"
                or sp.get("@odata.type") == "#microsoft.graph.agentIdentity")

    def identity_type(self, sp: dict) -> str:
        if self.is_agent(sp):
            return "agent identity"
        if sp.get("servicePrincipalType") == "ManagedIdentity":
            return "managed identity"
        if self.is_first_party(sp):
            return "Microsoft first-party"
        if self.is_home_tenant(sp):
            return "app (this tenant)"
        return "app (other tenant)"

    def app_role_value(self, assignment: dict) -> str | None:
        """Permission name of an appRoleAssignment, from the resource's appRoles, else the reference table."""
        resource = self.sp_by_id.get(assignment["resourceId"])
        for role in (resource or {}).get("appRoles", []):
            if role["id"] == assignment["appRoleId"]:
                return role["value"]
        return refs.app_role_name(assignment["appRoleId"])

    def graph_permissions(self, sp_id: str) -> list[tuple[str, dict]]:
        """(permission name, assignment) for Microsoft Graph application permissions held by a principal."""
        out = []
        for a in self.assignments_by_principal.get(sp_id, []):
            resource = self.sp_by_id.get(a["resourceId"])
            if resource and resource.get("appId") == refs.MS_GRAPH_APP_ID:
                name = self.app_role_value(a)
                if name:
                    out.append((name, a))
        return out

    def app_permissions(self, sp_id: str) -> list[dict]:
        """Application permissions on any resource (excluding the default 'no role' assignment)."""
        return [a for a in self.assignments_by_principal.get(sp_id, [])
                if a["appRoleId"] != "00000000-0000-0000-0000-000000000000"]

    def role_name(self, assignment: dict) -> str:
        d = self.role_def_by_id.get(assignment["roleDefinitionId"])
        if d:
            return d["displayName"]
        return refs.roles().get(assignment["roleDefinitionId"], {}).get("displayName", assignment["roleDefinitionId"])

    def role_is_privileged(self, assignment: dict) -> bool:
        d = self.role_def_by_id.get(assignment["roleDefinitionId"])
        if d and d.get("isPrivileged") is not None:
            return bool(d["isPrivileged"])
        tid = (d or {}).get("templateId", assignment["roleDefinitionId"])
        return refs.roles().get(tid, {}).get("privileged", False)

    def credentials(self, sp: dict) -> list[tuple[str, str, dict]]:
        """(object kind, credential kind, credential) for the SP and its app registration in this tenant."""
        out = [("servicePrincipal", "password", c) for c in sp.get("passwordCredentials", [])]
        out += [("servicePrincipal", "key", c) for c in sp.get("keyCredentials", [])]
        app = self.app_of(sp)
        if app:
            out += [("application", "password", c) for c in app.get("passwordCredentials", [])]
            out += [("application", "key", c) for c in app.get("keyCredentials", [])]
        return out

    def fics_of(self, sp: dict) -> list[dict]:
        app = self.app_of(sp)
        return self.federatedIdentityCredentials.get(app["id"], []) if app else []

    def active(self, cred: dict) -> bool:
        end = ts(cred.get("endDateTime"))
        return end is None or end > self.now
