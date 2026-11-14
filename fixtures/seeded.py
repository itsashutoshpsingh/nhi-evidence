"""The seeded lab tenant: 12 static misconfigurations, 2 sign-in misconfigurations, and clean look-alikes.

build(set()) is the clean tenant; build(ALL) is the seeded tenant; build({"S05"}) plants one issue.
Each issue's "fixed" form is what the clean tenant contains, so the clean tenant is the seeded tenant
with every misconfiguration repaired. Synthetic data: no real tenant, user or vendor.
Run: python fixtures/seeded.py   (writes fixtures/clean_tenant, fixtures/seeded_tenant)
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from nhi_evidence.fixturekit import Tenant  # noqa: E402

NOW = datetime(2026, 11, 1, tzinfo=UTC)
AKS = "https://eastus.oic.prod-aks.azure.com/{t}/{c}/"

# id: (check, rule, object display name, plain description). S12 plants two expected findings.
ISSUES = {
    "S01": [("C01", "only_disabled_or_nonhuman_owners", "reporting-export",
             "App whose only owner is a disabled (departed) user")],
    "S02": [("C03", "lifetime_over_limit", "legacy-crm-connector", "Client secret valid for 730 days")],
    "S03": [("C04", "expired_present", "old-billing-api", "Expired client secret left on the app")],
    "S04": [("C05", "secret_only", "nightly-report-job", "App-only job signing in with a secret, no certificate")],
    "S05": [("C06", "data_graph_permission", "doc-archiver", "Files.ReadWrite.All application permission")],
    "S06": [("C07", "all_principals_sensitive_scope", "MailMerge Pro",
             "Admin consent for all users to Mail.Read and Files.ReadWrite.All")],
    "S07": [("C08", "privileged_directory_role", "identity-automation",
             "Service principal holds Privileged Role Administrator")],
    "S08": [("C09", "github_pull_request", "infra-deployer",
             "GitHub federated credential trusts every pull request run")],
    "S09": [("C10", "unverified_publisher_with_access", "QuickSurvey",
             "Multi-tenant app, unverified publisher, holds User.Read.All")],
    "S10": [("C11", "prod_and_nonprod", "orders-api-ci", "One app trusted by both dev and production pipelines")],
    "S11": [("C12", "not_in_enforced_policy", "payroll-export",
             "Excluded from the workload identity Conditional Access policy")],
    "S12": [("C13", "path_from_non_privileged", "sharepoint-migrator",
             "Non-admin user owns an app holding Sites.FullControl.All"),
            ("C06", "data_graph_permission", "sharepoint-migrator", "(same app) Sites.FullControl.All")],
    "S13": [("C02", "stale_sign_in", "survey-importer", "Permissioned app with no sign-in for 200 days")],
    "S14": [("C14", "interactive_service_account", "svc-backup",
             "Service account used for an interactive browser sign-in")],
}
STATIC = [k for k, v in ISSUES.items() if v[0][0] not in ("C02", "C14")]
ALL = set(ISSUES)
# Look-alike controls: objects one step away from a seeded issue that must NOT be flagged.
CONTROLS = {
    "invoice-sync": "C01: one disabled and one enabled owner",
    "directory-sync-prod": "C01: no owners but serviceManagementReference set",
    "hr-portal": "C03: secret lifetime exactly 180 days (limit is more than 180)",
    "partner-portal": "C03: secret lifetime 179 days",
    "status-page": "C04: secret expires in 5 days but has not expired",
    "metrics-collector": "C05: app-only access with a certificate",
    "web-signin-app": "C05: secret on a delegated-only web app",
    "people-directory": "C06: Application.Read.All (read, not ReadWrite)",
    "Calendar Booking": "C07: all-user consent to basic sign-in scopes only",
    "Notes Helper": "C07: Mail.Read consented by one user, not all users",
    "audit-reader": "C08: Directory Readers (not a privileged role)",
    "site-builder": "C09: GitHub subject pinned to the main branch",
    "aks-workload": "C09: Kubernetes subject naming one service account",
    "TicketDesk": "C10: verified publisher holding the same permission",
    "Wallpaper Gallery": "C10: unverified publisher with no permissions",
    "orders-web-dev": "C11: separate dev app",
    "orders-web-prod": "C11: separate prod app",
    "mi-backup-vault": "C12: managed identity (Conditional Access cannot cover it)",
    "teams-notifier": "C13: non-admin owner of an app with low permissions",
    "App Admins": "C13: role-assignable group whose owner and members are admins",
    "new-intake-bot": "C02: created 20 days ago, no sign-in yet",
    "retired-tool": "C02: disabled and unused",
    "frank": "C14: a person's own interactive sign-ins",
    "mail-triage-agent": "C01: agent identity with a sponsor",
    "Microsoft Azure CLI": "allowlist: Microsoft first-party app with all-user consent",
    "BackupVault Cloud": "allowlist: vendor app approved in a recorded review",
}


def build(on: set[str], include_activity: bool = True) -> Tenant:
    t = Tenant("seeded-lab", NOW, include_activity)
    alice = t.user("alice", "Alice Admin")
    erin = t.user("erin", "Erin Appadmin")
    bob = t.user("bob", "Bob Builder")
    carol = t.user("carol", "Carol Clark")
    dave = t.user("dave", "Dave Departed", enabled=False)
    frank = t.user("frank", "Frank Field")
    svc = t.user("svc-backup", "svc-backup")
    t.role(alice, "Global Administrator")
    t.group("App Admins", members=[erin], owners=[alice])
    t.role(t.by_name["App Admins"], "Cloud Application Administrator")
    t.role(erin, "Application Administrator")
    for name, app_id in [("Office 365 Exchange Online", "00000002-0000-0ff1-ce00-000000000000"),
                         ("Microsoft Teams", "1fec8e78-bce4-4aaf-ab1b-5451cc387264"),
                         ("Azure Portal", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c")]:
        t.first_party(name, app_id)
    cli = t.first_party("Microsoft Azure CLI", "04b07795-8ddb-461a-bbee-02f9e1bf7b46")
    t._access(cli, (), "openid profile offline_access User.Read Directory.AccessAsUser.All", (), None)

    cert = [(30, 365)]
    short = [(10, 90)]
    # --- C01
    t.app("reporting-export", owners=[dave] if "S01" in on else [dave, carol], secrets=short)
    t.app("invoice-sync", owners=[dave, carol], certs=cert)
    t.app("directory-sync-prod", smr="CMDB-4411", certs=cert, perms=["User.Read.All"])
    # --- C03
    t.app("legacy-crm-connector", owners=[carol], secrets=[(100, 730)] if "S02" in on else [(10, 90)])
    t.app("hr-portal", owners=[bob], secrets=[(20, 180)], redirects=["https://hr.lab.example/auth"])
    t.app("partner-portal", owners=[carol], secrets=[(20, 179)])
    # --- C04
    t.app("old-billing-api", owners=[bob], certs=cert, secrets=[(400, 370)] if "S03" in on else [])
    t.app("status-page", owners=[carol], secrets=[(85, 90)])
    # --- C05
    t.app("nightly-report-job", owners=[carol], perms=["User.Read.All"],
          secrets=short if "S04" in on else [], certs=[] if "S04" in on else cert)
    t.app("metrics-collector", owners=[bob], perms=["User.Read.All"], certs=cert)
    t.app("web-signin-app", owners=[carol], secrets=short, redirects=["https://portal.lab.example/signin"])
    # --- C06
    t.app("doc-archiver", smr="CMDB-5120", certs=cert,
          perms=["Files.ReadWrite.All"] if "S05" in on else ["Sites.Selected"])
    t.app("people-directory", smr="CMDB-5121", certs=cert, perms=["Application.Read.All"])
    # --- C07
    t.third_party("MailMerge Pro", "mailmerge", True, all_consent="openid profile User.Read" +
                  (" Mail.Read Files.ReadWrite.All" if "S06" in on else ""))
    t.third_party("Calendar Booking", "calendarbooking", True,
                  all_consent="openid profile email offline_access User.Read")
    t.third_party("Notes Helper", "notes", True, principal_consent=(carol, "openid User.Read Mail.Read"))
    # --- C08
    t.app("identity-automation", smr="CMDB-6001", certs=cert,
          roles=["Privileged Role Administrator"] if "S07" in on else ["Directory Readers"])
    t.app("audit-reader", smr="CMDB-6002", certs=cert, roles=["Directory Readers"])
    # --- C09
    t.app("infra-deployer", owners=[bob], fics=[t.fic(
        "gh-infra", "repo:lab-org/infra:pull_request" if "S08" in on else "repo:lab-org/infra:environment:production")])
    t.app("site-builder", owners=[bob], fics=[t.fic("gh-site", "repo:lab-org/site:ref:refs/heads/main")])
    t.app("aks-workload", owners=[carol], fics=[t.fic(
        "aks-payments", "system:serviceaccount:payments:api", issuer=AKS.format(t=t.tenant_id, c=t.uid("aks")))])
    # --- C10
    t.third_party("QuickSurvey", "quicksurvey", verified="S09" not in on, perms=["User.Read.All"])
    t.third_party("TicketDesk", "ticketdesk", True, perms=["User.Read.All"])
    t.third_party("Wallpaper Gallery", "wallpaper", False)
    # --- C11
    t.app("orders-api-ci", owners=[bob], fics=[t.fic("gh-orders-prod", "repo:lab-org/orders:environment:production")]
          + ([t.fic("gh-orders-dev", "repo:lab-org/orders:environment:dev")] if "S10" in on else []))
    if "S10" not in on:
        t.app("orders-api-ci-dev", owners=[bob], fics=[t.fic("gh-orders-dev", "repo:lab-org/orders:environment:dev")])
    t.app("orders-web-dev", owners=[bob], secrets=short, redirects=["https://orders-dev.lab.example/auth"])
    t.app("orders-web-prod", owners=[bob], secrets=short, redirects=["https://orders-prod.lab.example/auth"])
    # --- C12
    _, payroll = t.app("payroll-export", owners=[carol], certs=cert, perms=["User.Read.All"])
    t.managed_identity("mi-backup-vault", perms=["User.Read.All"])
    t.ca_policy("Block workload identities outside trusted locations",
                exclude=[payroll["id"]] if "S11" in on else [])
    # --- C13
    t.app("sharepoint-migrator", owners=[bob] if "S12" in on else [], smr=None if "S12" in on else "CMDB-7003",
          certs=cert, perms=["Sites.FullControl.All"] if "S12" in on else ["Sites.Selected"])
    t.app("teams-notifier", owners=[bob], certs=cert, perms=["User.Read.All"])
    # --- C02
    t.app("survey-importer", owners=[carol], certs=cert, perms=["User.Read.All"],
          last_sign_in=200 if "S13" in on else 5)
    t.app("new-intake-bot", owners=[carol], certs=cert, perms=["User.Read.All"], created_ago=20, last_sign_in=None)
    t.app("retired-tool", owners=[carol], certs=cert, perms=["User.Read.All"], enabled=False, last_sign_in=None)
    # --- C14
    portal = t.by_name["Azure Portal"]
    if include_activity:
        for i in range(3):
            t.sign_in(frank, "Azure Portal", portal["appId"], 2 + i, n=i)
        t.sign_in(svc, "Azure Portal", portal["appId"], 4, error=0 if "S14" in on else 50126, n=9)
    # --- agents and allowlisted
    t.agent("mail-triage-agent", sponsors=[carol], perms=["User.Read.All"])
    t.agent("research-agent", sponsors=[bob])
    t.third_party("BackupVault Cloud", "backupvault", False, perms=["Mail.Read"])
    return t


ALLOWLIST = [{"appId": None, "checks": ["C06", "C10"],
              "reason": "Approved vendor backup service: security review SR-2291, re-review due 2027-01"}]


def write(out: Path) -> None:
    for name, on in (("clean_tenant", set()), ("seeded_tenant", ALL)):
        t = build(on)
        t.snapshot().save(out / name)
        allow = [dict(ALLOWLIST[0], appId=t.by_name["BackupVault Cloud"]["appId"])]
        (out / name / "allowlist.json").write_text(json.dumps(allow, indent=1) + "\n")
        exp = [{"issue": k, "check_id": c, "rule": r, "object": obj, "description": desc,
                "object_id": (t.by_name.get(f"app:{obj}") if c in ("C01", "C03", "C04", "C05", "C09", "C11")
                              else t.by_name[obj])["id"]}
               for k in sorted(on) for c, r, obj, desc in ISSUES[k]]
        (out / name / "expected_findings.json").write_text(json.dumps(exp, indent=1) + "\n")


if __name__ == "__main__":
    write(Path(__file__).parent)
