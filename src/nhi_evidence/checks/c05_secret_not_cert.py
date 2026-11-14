"""Check 5: app-only identity that signs in with a client secret only (NHI4 Insecure Authentication)."""

from ..finding import Finding, escalate

META = {
    "id": "C05", "title": "Secret where certificate or federation fits", "nhi": ["NHI4"],
    "graph": ["GET /v1.0/applications", "GET /v1.0/servicePrincipals/{id}/appRoleAssignments",
              "GET /v1.0/applications/{id}/federatedIdentityCredentials"],
    "licence": "free",
}


def run(snap, cfg) -> list[Finding]:
    out = []
    for app in snap.applications:
        sp = snap.sp_of(app)
        if not sp:
            continue
        # app-only access is what a confidential client with a secret is used for; delegated-only apps
        # (web sign-in) are a separate case this check does not judge
        app_only = snap.app_permissions(sp["id"]) or snap.roles_by_principal.get(sp["id"])
        if not app_only:
            continue
        creds = snap.credentials(sp)
        secrets = [c for _, kind, c in creds if kind == "password" and snap.active(c)]
        certs = [c for _, kind, c in creds if kind == "key" and snap.active(c)]
        fics = snap.federatedIdentityCredentials.get(app["id"], [])
        if not secrets or certs or fics:
            continue
        out.append(Finding(
            "C05", "secret_only", META["nhi"], app["id"], "application", app["displayName"],
            escalate(snap, cfg, sp, "medium"),
            {"active_secrets": len(secrets), "active_certificates": 0, "federated_credentials": 0,
             "application_permissions": len(snap.app_permissions(sp["id"])),
             "directory_roles": len(snap.roles_by_principal.get(sp["id"], []))},
            "A client secret is a shared password that can be pasted anywhere; a certificate key can be kept "
            "non-exportable, and federation removes the stored credential altogether.",
            "Entra admin center > App registrations > app > Certificates & secrets (Client secrets, "
            "Certificates, Federated credentials tabs); "
            f"GET /v1.0/applications/{app['id']}/federatedIdentityCredentials",
        ))
    return out
