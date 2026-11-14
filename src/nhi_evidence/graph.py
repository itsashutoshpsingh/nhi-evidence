"""Credential-control graph (check 13). An edge u -> v means "u can add a credential to v, or can make
itself able to". The query lists the shortest paths from non-privileged principals to every privileged
service principal, with the control that closes each path. BloodHound (AZAddSecret, AZAppAdmin,
AZMGAddSecret) models the same relationships with more depth; this graph is kept small on purpose.
"""

from collections import deque

import networkx as nx

from . import refs
from .finding import is_privileged, privileged_roles

ALL = "all-apps"
APP_ROLES = {"Global Administrator", "Application Administrator", "Cloud Application Administrator"}
CONTROL = {
    "owns_app": "Remove this owner; record accountability in serviceManagementReference instead",
    "owns_sp": "Remove this owner of the service principal",
    "sp_owns": "Remove Application.ReadWrite.OwnedBy from the owning app, or remove its ownership",
    "holds_role": "Make the role eligible in PIM, or scope it to the apps that need it",
    "holds_scoped_role": "Remove the app-scoped role assignment if it is not needed",
    "member_of": "Remove the member, or make membership eligible with PIM for Groups",
    "owns_group": "Remove the owner; owners of a role-assignable group can add themselves as members",
    "graph_all_apps": "Replace Application.ReadWrite.All with Application.ReadWrite.OwnedBy",
    "graph_self_grant": "Remove AppRoleAssignment.ReadWrite.All / RoleManagement.ReadWrite.Directory",
    "role_escalates": "Restrict who holds Privileged Role Administrator; use PIM with approval",
    "role_manages_all": "", "app_to_sp": "", "all_contains": "",
}


def node(kind: str, oid: str) -> str:
    return f"{kind}:{oid}"


def build(snap, cfg) -> nx.DiGraph:
    g = nx.DiGraph()

    def edge(u, v, kind, label):
        g.add_edge(u, v, kind=kind, label=label)

    live_users = {u["id"] for u in snap.users if u.get("accountEnabled")}
    live_sps = {s["id"] for s in snap.servicePrincipals if s.get("accountEnabled")}

    def principal(o: dict) -> str | None:
        t = o.get("@odata.type", "")
        if t.endswith(".user") and o["id"] in live_users:
            return node("user", o["id"])
        if (t.endswith(".servicePrincipal") or t.endswith(".agentIdentity")) and o["id"] in live_sps:
            return node("sp", o["id"])
        return None

    def ownedby_ok(p: str) -> bool:
        if not p.startswith("sp:"):
            return True  # users can manage the apps they own by default
        perms = {n for n, _ in snap.graph_permissions(p[3:])}
        return bool(perms & {"Application.ReadWrite.OwnedBy", "Application.ReadWrite.All"})

    for app in snap.applications:
        a = node("app", app["id"])
        g.add_node(a)
        sp = snap.sp_of(app)
        if sp:
            edge(a, node("sp", sp["id"]), "app_to_sp", "credentials on the app sign in as its service principal")
        for o in snap.applicationOwners.get(app["id"], []):
            p = principal(o)
            if p and ownedby_ok(p):
                edge(p, a, "owns_app" if p.startswith("user:") else "sp_owns", "owner of the application")
        edge(ALL, a, "all_contains", "")
    for sp in snap.servicePrincipals:
        s = node("sp", sp["id"])
        g.add_node(s)
        if not snap.is_first_party(sp):
            edge(ALL, s, "all_contains", "")
        for o in snap.servicePrincipalOwners.get(sp["id"], []):
            p = principal(o)
            if p and ownedby_ok(p):
                edge(p, s, "owns_sp" if p.startswith("user:") else "sp_owns", "owner of the service principal")
        if sp["id"] in live_sps:
            perms = {n for n, _ in snap.graph_permissions(sp["id"])}
            if "Application.ReadWrite.All" in perms:
                edge(s, ALL, "graph_all_apps", "Application.ReadWrite.All: add credentials to any app")
            if perms & {"AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory"}:
                edge(s, node("role", refs.role_id("Global Administrator")), "graph_self_grant",
                     "can grant itself Global Administrator")

    ga = node("role", refs.role_id("Global Administrator"))
    for name in APP_ROLES:
        edge(node("role", refs.role_id(name)), ALL, "role_manages_all", f"{name} manages every application")
    edge(node("role", refs.role_id("Privileged Role Administrator")), ga, "role_escalates",
         "can assign itself Global Administrator")

    group_holds_role = set()
    for r in snap.roleAssignments:
        rid = snap.role_def_by_id.get(r["roleDefinitionId"], {}).get("templateId", r["roleDefinitionId"])
        name = snap.role_name(r)
        pid = r["principalId"]
        if pid in snap.group_by_id:
            src = node("group", pid)
            group_holds_role.add(pid)
        elif pid in live_users:
            src = node("user", pid)
        elif pid in live_sps:
            src = node("sp", pid)
        else:
            continue
        scope = r.get("directoryScopeId", "/")
        if scope == "/":
            edge(src, node("role", rid), "holds_role", f"holds {name}")
        elif name in APP_ROLES:
            obj = scope.strip("/")
            tgt = node("app", obj) if obj in snap.app_by_id else node("sp", obj)
            edge(src, tgt, "holds_scoped_role", f"holds {name} scoped to this object")
    for gid in group_holds_role:
        for m in snap.groupMembers.get(gid, []):
            p = principal(m)
            if p:
                edge(p, node("group", gid), "member_of", "member of a role-assignable group")
        for o in snap.groupOwners.get(gid, []):
            p = principal(o)
            if p:
                edge(p, node("group", gid), "owns_group", "owner of a role-assignable group")
    return g


def _privileged_principals(snap, cfg) -> set[str]:
    out = set()
    for r in snap.roleAssignments:
        if not snap.role_is_privileged(r):
            continue
        pid = r["principalId"]
        if pid in snap.group_by_id:
            out |= {m["id"] for m in snap.groupMembers.get(pid, [])}
        else:
            out.add(pid)
    out |= {s["id"] for s in snap.servicePrincipals if is_privileged(snap, cfg, s["id"])}
    return out


def targets(snap, cfg) -> list[dict]:
    """Enabled, privileged, non-Microsoft service principals (a disabled one cannot sign in)."""
    return [s for s in snap.servicePrincipals if not snap.is_first_party(s) and s.get("accountEnabled")
            and (is_privileged(snap, cfg, s["id"]) or privileged_roles(snap, s["id"]))]


def paths(snap, cfg, g: nx.DiGraph | None = None, cap: int = 10) -> dict[str, tuple[int, list[list[str]]]]:
    """target sp id -> (number of non-privileged principals with a path, up to `cap` of their shortest
    paths as node lists, shortest first)."""
    g = g if g is not None else build(snap, cfg)
    privileged = _privileged_principals(snap, cfg)
    rev = g.reverse(copy=False)
    out = {}
    for sp in targets(snap, cfg):
        t = node("sp", sp["id"])
        parent = {t: None}
        q = deque([t])
        while q:  # BFS on the reversed graph gives one shortest path from every source
            v = q.popleft()
            for u in rev.successors(v):
                if u not in parent:
                    parent[u] = v
                    q.append(u)
        found = []
        for u in parent:
            kind, _, oid = u.partition(":")
            if kind in ("user", "sp") and u != t and oid not in privileged:
                p = [u]
                while parent[p[-1]] is not None:
                    p.append(parent[p[-1]])
                found.append(p)
        found.sort(key=lambda p: (len(p), p))
        if found:
            out[sp["id"]] = (len(found), found[:cap])
    return out


def describe(g: nx.DiGraph, path: list[str], snap) -> dict:
    def name(n):
        kind, _, oid = n.partition(":")
        obj = {"user": snap.user_by_id, "sp": snap.sp_by_id, "app": snap.app_by_id,
               "group": snap.group_by_id}.get(kind, {}).get(oid)
        if kind == "role":
            return refs.roles().get(oid, {}).get("displayName", oid)
        if n == ALL:
            return "every application"
        return f"{kind} {obj['displayName'] if obj else oid}"
    steps = [{"from": name(u), "to": name(v), "edge": g.edges[u, v]["label"], "kind": g.edges[u, v]["kind"]}
             for u, v in zip(path, path[1:], strict=False)]
    return {"source": name(path[0]), "hops": len(steps), "steps": steps,
            "closing_control": CONTROL[steps[0]["kind"]] if steps else ""}
