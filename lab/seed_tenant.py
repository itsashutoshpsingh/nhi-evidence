"""Plant the seeded misconfigurations in YOUR OWN test tenant, and remove them again.

This is the only code in the repository that writes to Microsoft Graph. It is kept out of the package,
prints its plan by default, and only sends requests with --apply plus --confirm set to the same tenant
ID, and only if the token's `tid` claim is that tenant. Every object it creates is named `nhi-lab-*`
and tagged `nhi-evidence-lab`; `cleanup` deletes exactly those. Client secrets that addPassword returns
are discarded at once, never printed or stored, so the seeded apps cannot be signed in to.

  python lab/seed_tenant.py plan
  python lab/seed_tenant.py apply   --tenant-id <id> --client-id <id> --confirm <id>
  python lab/seed_tenant.py cleanup --tenant-id <id> --client-id <id> --confirm <id>

The writing app needs (application permissions, admin consent): Application.ReadWrite.All,
AppRoleAssignment.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All, RoleManagement.ReadWrite.Directory,
User.ReadWrite.All, Policy.ReadWrite.ConditionalAccess (S11 only). Use a separate app from the collector,
and delete it when you are done. docs/run-against-your-tenant.md has the full walk-through.
"""

import argparse
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from nhi_evidence import refs  # noqa: E402

TAG = "nhi-evidence-lab"
PREFIX = "nhi-lab-"
G = "https://graph.microsoft.com/v1.0"
GITHUB = "https://token.actions.githubusercontent.com"


def public_cert(name: str) -> str:
    """Base64 DER of a fresh self-signed certificate. The private key is thrown away, so nobody can use it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, PREFIX + name)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=90)).sign(key, hashes.SHA256()))
    import base64
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def plan(domain: str = "{domain}", start: datetime | None = None) -> list[dict]:
    """Ordered steps. "{app:x}", "{sp:x}", "{user:x}", "{graph}" are filled in from earlier responses."""
    s = []
    start = start or datetime.now(UTC)

    def _end(days: int) -> str:
        return (start + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def step(issue, method, path, body=None, save=None, note=""):
        s.append({"issue": issue, "method": method, "path": path, "body": body, "save": save, "note": note})

    def app(issue, name, audience="AzureADMyOrg", smr=None):
        body = {"displayName": PREFIX + name, "tags": [TAG], "signInAudience": audience,
                "notes": "Seeded misconfiguration for nhi-evidence validation. Safe to delete."}
        if smr:
            body["serviceManagementReference"] = smr
        step(issue, "POST", "/applications", body, save=f"app:{name}")
        step(issue, "POST", "/servicePrincipals", {"appId": f"{{appId:{name}}}", "tags": [TAG]}, save=f"sp:{name}")

    def user(issue, nick, enabled=True):
        step(issue, "POST", "/users", {"accountEnabled": True, "displayName": PREFIX + nick,
                                       "mailNickname": PREFIX + nick, "userPrincipalName": f"{PREFIX}{nick}@{domain}",
                                       "passwordProfile": {"forceChangePasswordNextSignIn": True,
                                                           "password": "{random}"}}, save=f"user:{nick}")
        if not enabled:
            step(issue, "PATCH", f"/users/{{user:{nick}}}", {"accountEnabled": False})

    def owner(issue, name, nick):
        step(issue, "POST", f"/applications/{{app:{name}}}/owners/$ref",
             {"@odata.id": f"{G}/directoryObjects/{{user:{nick}}}"})

    def perm(issue, name, permission):
        step(issue, "POST", "/servicePrincipals/{graph}/appRoleAssignedTo",
             {"principalId": f"{{sp:{name}}}", "resourceId": "{graph}", "appRoleId": refs.app_role_id(permission)})

    def secret(issue, name, days):
        step(issue, "POST", f"/applications/{{app:{name}}}/addPassword",
             {"passwordCredential": {"displayName": "seeded", "endDateTime": _end(days)}},
             note="response secretText is discarded")

    step("setup", "GET", "/servicePrincipals?$filter=appId eq '00000003-0000-0000-c000-000000000000'&$select=id",
         save="graph", note="Microsoft Graph service principal in your tenant")
    user("S01", "departed", enabled=False)
    app("S01", "reporting-export")
    owner("S01", "reporting-export", "departed")
    app("S02", "legacy-crm-connector", smr="LAB")
    secret("S02", "legacy-crm-connector", 730)
    app("S03", "old-billing-api", smr="LAB")
    secret("S03", "old-billing-api", 1)
    s[-1]["note"] += "; run the collector after it has expired (1 day)"
    app("S04", "nightly-report-job", smr="LAB")
    perm("S04", "nightly-report-job", "User.Read.All")
    secret("S04", "nightly-report-job", 90)
    app("S05", "doc-archiver", smr="LAB")
    perm("S05", "doc-archiver", "Files.ReadWrite.All")
    app("S06", "mailmerge", audience="AzureADMultipleOrgs", smr="LAB")
    step("S06", "POST", "/oauth2PermissionGrants", {"clientId": "{sp:mailmerge}", "consentType": "AllPrincipals",
                                                     "resourceId": "{graph}", "scope": "openid User.Read Mail.Read"},
         note="a home-tenant app stands in for the third-party app; C10 needs a second tenant (see docs)")
    app("S07", "identity-automation", smr="LAB")
    step("S07", "POST", "/roleManagement/directory/roleAssignments",
         {"principalId": "{sp:identity-automation}", "roleDefinitionId": refs.role_id("Security Reader"),
          "directoryScopeId": "/"},
         note="Security Reader (labelled privileged) instead of Privileged Role Administrator")
    app("S08", "infra-deployer", smr="LAB")
    step("S08", "POST", "/applications/{app:infra-deployer}/federatedIdentityCredentials",
         {"name": "gh-infra-pr", "issuer": GITHUB, "subject": "repo:lab-org/infra:pull_request",
          "audiences": ["api://AzureADTokenExchange"]})
    app("S10", "orders-api-ci", smr="LAB")
    for env in ("dev", "production"):
        step("S10", "POST", "/applications/{app:orders-api-ci}/federatedIdentityCredentials",
             {"name": f"gh-orders-{env}", "issuer": GITHUB, "subject": f"repo:lab-org/orders:environment:{env}",
              "audiences": ["api://AzureADTokenExchange"]})
    app("S11", "payroll-export", smr="LAB")
    perm("S11", "payroll-export", "User.Read.All")
    step("S11", "PATCH", "/applications/{app:payroll-export}",
         {"keyCredentials": [{"type": "AsymmetricX509Cert", "usage": "Verify", "key": "{cert}"}]},
         note="public certificate only; the private key is discarded")
    step("S11", "POST", "/identity/conditionalAccess/policies",
         {"displayName": PREFIX + "workload-block-untrusted", "state": "enabled",
          "conditions": {"applications": {"includeApplications": ["All"]},
                         "clientApplications": {"includeServicePrincipals": ["{sp:nightly-report-job}"]},
                         "locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}},
          "grantControls": {"operator": "OR", "builtInControls": ["block"]}},
         note="needs Workload Identities Premium; covers only the seeded S04 app, so payroll-export is uncovered")
    user("S12", "builder")
    app("S12", "sharepoint-migrator")
    owner("S12", "sharepoint-migrator", "builder")
    perm("S12", "sharepoint-migrator", "Sites.FullControl.All")
    return s


def fill(value, ids: dict):
    if isinstance(value, dict):
        return {k: fill(v, ids) for k, v in value.items()}
    if isinstance(value, list):
        return [fill(v, ids) for v in value]
    if isinstance(value, str):
        return re.sub(r"\{([a-zA-Z]+(?::[\w.-]+)?)\}", lambda m: ids.get(m[1], m[0]), value)
    return value


def apply(client, steps: list[dict], password_factory, cert_factory=public_cert) -> dict:
    ids = {}
    for st in steps:
        ids["random"] = password_factory()
        ids["cert"] = cert_factory(st["issue"]) if "{cert}" in json.dumps(st["body"]) else ""
        path, body = fill(st["path"], ids), fill(st["body"], ids)
        r = client.request(st["method"], G + path, json=body)
        r.raise_for_status()
        data = r.json() if r.content else {}
        data.pop("secretText", None)  # never kept: the seeded apps must not be usable
        if st["save"] == "graph":
            ids["graph"] = data["value"][0]["id"]
        elif st["save"]:
            ids[st["save"]] = data["id"]
            if st["save"].startswith("app:"):
                ids["appId:" + st["save"][4:]] = data["appId"]
        print(f"{st['issue']} {st['method']} {st['path']} -> {r.status_code}", flush=True)
    ids.pop("random", None)
    ids.pop("cert", None)
    return ids


def cleanup(client) -> list[str]:
    """Delete every application tagged nhi-evidence-lab, every nhi-lab-* user and the nhi-lab-* CA policy."""
    deleted = []
    apps = client.get(f"{G}/applications?$filter=tags/any(t:t eq '{TAG}')&$select=id,displayName").json()["value"]
    users = client.get(f"{G}/users?$filter=startswith(userPrincipalName,'{PREFIX}')&$select=id,userPrincipalName"
                       ).json()["value"]
    pols = client.get(f"{G}/identity/conditionalAccess/policies?$select=id,displayName").json()["value"]
    for kind, objs in (("applications", apps), ("users", users)):
        for o in objs:
            name = o.get("displayName") or o.get("userPrincipalName")
            assert name.startswith(PREFIX), name  # never delete anything this script did not create
            client.delete(f"{G}/{kind}/{o['id']}").raise_for_status()
            client.delete(f"{G}/directory/deletedItems/{o['id']}")  # skip the 30-day recycle bin
            deleted.append(name)
    for p in pols:
        if p["displayName"].startswith(PREFIX):
            client.delete(f"{G}/identity/conditionalAccess/policies/{p['id']}").raise_for_status()
            deleted.append(p["displayName"])
    return deleted


def main(argv=None) -> int:  # pragma: no cover - needs a live tenant
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=["plan", "apply", "cleanup"])
    p.add_argument("--tenant-id")
    p.add_argument("--client-id")
    p.add_argument("--confirm", help="must equal --tenant-id")
    p.add_argument("--domain", help="verified domain for lab users, e.g. yourlab.onmicrosoft.com")
    a = p.parse_args(argv)
    if a.action == "plan":
        print(json.dumps(plan(a.domain or "{domain}"), indent=1))
        return 0
    if not a.tenant_id or a.confirm != a.tenant_id:
        print("refusing: pass --tenant-id and --confirm with the same tenant ID", file=sys.stderr)
        return 2
    import secrets

    import httpx
    import msal

    from nhi_evidence.auth import claims
    cred = __import__("os").environ.get("NHI_LAB_CLIENT_SECRET")
    if not cred:
        print("set NHI_LAB_CLIENT_SECRET for the writing app", file=sys.stderr)
        return 2
    app = msal.ConfidentialClientApplication(a.client_id, authority=f"https://login.microsoftonline.com/{a.tenant_id}",
                                             client_credential=cred)
    tok = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])["access_token"]
    if claims(tok).get("tid") != a.tenant_id:
        print("refusing: token is for a different tenant", file=sys.stderr)
        return 2
    client = httpx.Client(headers={"Authorization": f"Bearer {tok}"}, timeout=60)
    if a.action == "cleanup":
        print("deleted:", ", ".join(cleanup(client)) or "nothing")
        return 0
    if not a.domain:
        print("pass --domain for the lab users", file=sys.stderr)
        return 2
    apply(client, plan(a.domain), lambda: secrets.token_urlsafe(24) + "aA1!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
