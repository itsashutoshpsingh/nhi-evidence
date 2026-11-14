"""Check 4: expired credentials still present, or more than one active client secret (NHI7)."""

from ..finding import Finding, escalate

META = {
    "id": "C04", "title": "Expired or duplicate credentials", "nhi": ["NHI7"],
    "graph": ["GET /v1.0/applications ($select=passwordCredentials,keyCredentials)",
              "GET /v1.0/servicePrincipals ($select=passwordCredentials,keyCredentials)"],
    "licence": "free",
}


def _objects(snap):
    for app in snap.applications:
        yield app, "application", snap.sp_of(app)
    for sp in snap.servicePrincipals:
        if sp.get("servicePrincipalType") != "ManagedIdentity":
            yield sp, "servicePrincipal", sp


def run(snap, cfg) -> list[Finding]:
    out = []
    for obj, kind, sp in _objects(snap):
        pw, keys = obj.get("passwordCredentials", []), obj.get("keyCredentials", [])
        expired = [(t, c) for t, cs in (("password", pw), ("key", keys)) for c in cs if not snap.active(c)]
        verify = (f"Entra admin center > App registrations > app > Certificates & secrets; "
                  f"GET /v1.0/{kind}s/{obj['id']}?$select=passwordCredentials,keyCredentials")
        if expired:
            out.append(Finding(
                "C04", "expired_present", META["nhi"], obj["id"], kind, obj["displayName"],
                escalate(snap, cfg, sp, "low"),
                {"expired": [{"type": t, "keyId": c["keyId"], "endDateTime": c.get("endDateTime")}
                             for t, c in expired]},
                "Expired credentials left in place show nobody is managing this identity's lifecycle and hide "
                "which credential is really in use.",
                verify,
            ))
        active_pw = [c for c in pw if snap.active(c)]
        if len(active_pw) > 1:
            out.append(Finding(
                "C04", "multiple_active_secrets", META["nhi"], obj["id"], kind, obj["displayName"],
                escalate(snap, cfg, sp, "medium"),
                {"active_secrets": [{"keyId": c["keyId"], "endDateTime": c.get("endDateTime")} for c in active_pw]},
                "Each extra active secret is another copy that can leak; a rotation that never removed the old "
                "secret leaves both working.",
                verify,
            ))
    return out
