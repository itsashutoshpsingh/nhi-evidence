"""Drift between two snapshots: the changes a weekly run should alert on."""

from .finding import is_privileged, privileged_graph, privileged_roles


def _privileged_perms(snap, cfg):
    return {(sp["id"], p) for sp in snap.servicePrincipals for p, _ in privileged_graph(snap, cfg, sp["id"])}


def _privileged_roles(snap):
    return {(sp["id"], snap.role_name(r), r.get("directoryScopeId", "/")) for sp in snap.servicePrincipals
            for r in privileged_roles(snap, sp["id"])}


def _creds(snap, cfg):
    out = {}
    for sp in snap.servicePrincipals:
        if is_privileged(snap, cfg, sp["id"]):
            for _, kind, c in snap.credentials(sp):
                out[(sp["id"], kind, c["keyId"])] = c.get("endDateTime")
            for f in snap.fics_of(sp):
                out[(sp["id"], "federated", f["id"])] = f.get("subject") or (f.get("claimsMatchingExpression") or {})
    return out


def _owners(snap):
    return {(a["id"], o["id"]) for a in snap.applications for o in snap.applicationOwners.get(a["id"], [])}


def _consents(snap, cfg):
    sens = set(cfg["sensitive_delegated"])
    return {(g["clientId"], s) for g in snap.oauth2PermissionGrants if g.get("consentType") == "AllPrincipals"
            for s in (g.get("scope") or "").split() if s in sens}


def diff(a, b, cfg) -> list[dict]:
    name = lambda oid: (b.sp_by_id.get(oid) or b.app_by_id.get(oid) or a.app_by_id.get(oid)  # noqa: E731
                        or a.sp_by_id.get(oid) or {}).get("displayName", oid)
    out = []
    for sp_id, perm in sorted(_privileged_perms(b, cfg) - _privileged_perms(a, cfg)):
        out.append({"kind": "new_privileged_permission", "object_id": sp_id, "display_name": name(sp_id),
                    "detail": perm})
    for sp_id, role, scope in sorted(_privileged_roles(b) - _privileged_roles(a)):
        out.append({"kind": "new_privileged_role", "object_id": sp_id, "display_name": name(sp_id),
                    "detail": f"{role} at {scope}"})
    ca, cb = _creds(a, cfg), _creds(b, cfg)
    for key in sorted(set(cb) - set(ca)):
        out.append({"kind": "new_credential_on_privileged", "object_id": key[0], "display_name": name(key[0]),
                    "detail": f"{key[1]} {key[2]}"})
    for app_id, owner in sorted(_owners(a) - _owners(b)):
        out.append({"kind": "owner_removed", "object_id": app_id, "display_name": name(app_id), "detail": owner})
    for sp_id, scope in sorted(_consents(b, cfg) - _consents(a, cfg)):
        out.append({"kind": "new_tenant_wide_consent", "object_id": sp_id, "display_name": name(sp_id),
                    "detail": scope})
    return out
