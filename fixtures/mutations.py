"""Single-change mutations of the clean tenant. Each one plants one variant of a misconfiguration and
states exactly which findings it must produce; every other finding on top of the clean baseline counts
as a false finding. Kinds: "app" = application object, "sp" = service principal, "user".
"""

from seeded import allowlist, build

from nhi_evidence import refs


def A(t, name):
    return t.by_name[f"app:{name}"]


def S(t, name):
    return t.by_name[name]


def owners(t, name, *people):
    t.d["applicationOwners"][A(t, name)["id"]] = [t.ref(p) for p in people]


def grant_perm(t, name, *perms):
    t._access(S(t, name), perms, None, (), None)


def set_fic(t, name, **kw):
    t.d["federatedIdentityCredentials"][A(t, name)["id"]] = [t.fic(f"{name}-m", **kw)]


def m_policy_report_only(t):
    t.d["conditionalAccessPolicies"][0]["state"] = "enabledForReportingButNotEnforced"


def _covered_sps(t):
    """Service principals the clean tenant's enforced policy protects (all C12-eligible ones)."""
    names = ["directory-sync-prod", "nightly-report-job", "metrics-collector", "doc-archiver", "people-directory",
             "identity-automation", "audit-reader", "payroll-export", "sharepoint-migrator", "teams-notifier",
             "survey-importer", "new-intake-bot"]
    return [("C12", "not_in_enforced_policy", n, "sp") for n in names]


# A path that reaches "every application" also reaches the allowlisted vendor app (it holds Mail.Read);
# the allowlist covers its C06 and C10 findings only, so a new path to it is still reported.
VENDOR = ("C13", "path_from_non_privileged", "BackupVault Cloud", "sp")

MUTATIONS = [
    # (id, check, description, mutate(tenant), expected [(check, rule, name, kind)])
    ("M01a", "C01", "remove every owner of an app", lambda t: owners(t, "hr-portal"),
     [("C01", "no_owner", "hr-portal", "app")]),
    ("M01b", "C01", "only owner is a service principal", lambda t: owners(t, "status-page", S(t, "teams-notifier")),
     [("C01", "only_disabled_or_nonhuman_owners", "status-page", "app")]),
    ("M01c", "C01", "remove serviceManagementReference from an ownerless app",
     lambda t: A(t, "directory-sync-prod").update(serviceManagementReference=None),
     [("C01", "no_owner", "directory-sync-prod", "app")]),
    ("M01d", "C01", "agent identity loses its sponsor",
     lambda t: t.d["servicePrincipalSponsors"].update({S(t, "mail-triage-agent")["id"]: []}),
     [("C01", "agent_no_sponsor", "mail-triage-agent", "sp")]),
    ("M02a", "C02", "last sign-in 91 days ago", lambda t: t.sign_in_activity(S(t, "survey-importer"), 91),
     [("C02", "stale_sign_in", "survey-importer", "sp")]),
    ("M02b", "C02", "no sign-in activity record", lambda t: t.sign_in_activity(S(t, "survey-importer"), None),
     [("C02", "no_sign_in", "survey-importer", "sp")]),
    ("M02c", "C02", "app created 120 days ago and never used",
     lambda t: A(t, "new-intake-bot").update(createdDateTime=t.ago(120)),
     [("C02", "no_sign_in", "new-intake-bot", "sp")]),
    ("M03a", "C03", "secret lifetime 181 days",
     lambda t: A(t, "hr-portal").update(passwordCredentials=[t.secret("hr-m", 20, 181)]),
     [("C03", "lifetime_over_limit", "hr-portal", "app")]),
    ("M03b", "C03", "secret with no end date",
     lambda t: A(t, "hr-portal").update(passwordCredentials=[t.secret("hr-m", 20, None)]),
     [("C03", "no_end_date", "hr-portal", "app")]),
    ("M03c", "C03", "365-day secret on the service principal object (hidden from App registrations)",
     lambda t: S(t, "payroll-export").update(passwordCredentials=[t.secret("pay-sp", 5, 365)]),
     [("C03", "lifetime_over_limit", "payroll-export", "sp")]),
    ("M04a", "C04", "expired certificate left in place",
     lambda t: A(t, "status-page")["keyCredentials"].append(t.cert("status-old", 500, 365)),
     [("C04", "expired_present", "status-page", "app")]),
    ("M04b", "C04", "second active secret after a rotation",
     lambda t: A(t, "hr-portal")["passwordCredentials"].append(t.secret("hr-2", 5, 90)),
     [("C04", "multiple_active_secrets", "hr-portal", "app")]),
    ("M04c", "C04", "expired secret on the service principal object",
     lambda t: S(t, "teams-notifier").update(passwordCredentials=[t.secret("tn-sp", 400, 300)]),
     [("C04", "expired_present", "teams-notifier", "sp")]),
    ("M05a", "C05", "certificate replaced by a secret",
     lambda t: A(t, "metrics-collector").update(keyCredentials=[], passwordCredentials=[t.secret("mc", 5, 90)]),
     [("C05", "secret_only", "metrics-collector", "app")]),
    ("M05b", "C05", "role-holding app switches to a secret",
     lambda t: A(t, "audit-reader").update(keyCredentials=[], passwordCredentials=[t.secret("ar", 5, 90)]),
     [("C05", "secret_only", "audit-reader", "app")]),
    ("M05c", "C05", "certificate expired, secret active",
     lambda t: A(t, "metrics-collector").update(keyCredentials=[t.cert("mc-old", 400, 365)],
                                                passwordCredentials=[t.secret("mc", 5, 90)]),
     [("C05", "secret_only", "metrics-collector", "app"), ("C04", "expired_present", "metrics-collector", "app")]),
    ("M06a", "C06", "Mail.Send application permission", lambda t: grant_perm(t, "metrics-collector", "Mail.Send"),
     [("C06", "data_graph_permission", "metrics-collector", "sp"),
      ("C13", "path_from_non_privileged", "metrics-collector", "sp")]),  # its owner bob is not an admin
    ("M06b", "C06", "Application.ReadWrite.All on an ownerless app",
     lambda t: grant_perm(t, "people-directory", "Application.ReadWrite.All"),
     [("C06", "tier0_graph_permission", "people-directory", "sp")]),
    ("M06c", "C06", "RoleManagement.ReadWrite.Directory, resolved from the reference table",
     lambda t: (grant_perm(t, "new-intake-bot", "RoleManagement.ReadWrite.Directory"),
                t.graph.update(appRoles=[])),
     [("C06", "tier0_graph_permission", "new-intake-bot", "sp"),
      ("C13", "path_from_non_privileged", "new-intake-bot", "sp"), VENDOR]),
    ("M07a", "C07", "all-user consent gains Files.Read.All",
     lambda t: _grant(t, "Calendar Booking").update(
         scope="openid profile email offline_access User.Read Files.Read.All"),
     [("C07", "all_principals_sensitive_scope", "Calendar Booking", "sp")]),
    ("M07b", "C07", "single-user Mail.Read consent becomes all-user consent",
     lambda t: _grant(t, "Notes Helper").update(consentType="AllPrincipals", principalId=None),
     [("C07", "all_principals_sensitive_scope", "Notes Helper", "sp")]),
    ("M08a", "C08", "Global Administrator to a service principal",
     lambda t: t.role(S(t, "audit-reader"), "Global Administrator"),
     [("C08", "privileged_directory_role", "audit-reader", "sp")]),
    ("M08b", "C08", "Cloud Application Administrator scoped to one app",
     lambda t: t.role(S(t, "audit-reader"), "Cloud Application Administrator", "/" + A(t, "hr-portal")["id"]),
     [("C08", "privileged_directory_role", "audit-reader", "sp")]),
    ("M08c", "C08", "Security Reader (Microsoft labels it privileged)",
     lambda t: t.role(S(t, "audit-reader"), "Security Reader"),
     [("C08", "privileged_directory_role", "audit-reader", "sp")]),
    ("M09a", "C09", "flexible credential with a wildcard repository",
     lambda t: set_fic(t, "site-builder", subject=None,
                       expression="claims['sub'] matches 'repo:lab-org/*:ref:refs/heads/main'"),
     [("C09", "flexible_wildcard_repository", "site-builder", "app")]),
    ("M09b", "C09", "flexible credential trusting any branch",
     lambda t: set_fic(t, "site-builder", subject=None,
                       expression="claims['sub'] matches 'repo:lab-org/site:ref:refs/heads/*'"),
     [("C09", "flexible_wildcard_ref", "site-builder", "app")]),
    ("M09c", "C09", "issuer that is not a known workload platform",
     lambda t: set_fic(t, "site-builder", subject="repo:lab-org/site:ref:refs/heads/main",
                       issuer="https://token.ci.vendor.example"),
     [("C09", "unexpected_issuer", "site-builder", "app")]),
    ("M09d", "C09", "Kubernetes default service account",
     lambda t: t.d["federatedIdentityCredentials"][A(t, "aks-workload")["id"]][0].update(
         subject="system:serviceaccount:default:default"),
     [("C09", "kubernetes_default_service_account", "aks-workload", "app")]),
    ("M09e", "C09", "literal asterisk in a standard subject",
     lambda t: set_fic(t, "site-builder", subject="repo:lab-org/site:*"),
     [("C09", "literal_wildcard_subject", "site-builder", "app"),
      ("C09", "github_subject_unrecognised", "site-builder", "app")]),
    ("M09f", "C09", "'pull-request' spelling copied from Microsoft's docs",
     lambda t: set_fic(t, "site-builder", subject="repo:lab-org/site:pull-request"),
     [("C09", "github_subject_never_matches", "site-builder", "app")]),
    ("M09g", "C09", "audience other than api://AzureADTokenExchange",
     lambda t: t.d["federatedIdentityCredentials"][A(t, "site-builder")["id"]][0].update(
         audiences=["api://site-builder"]),
     [("C09", "non_default_audience", "site-builder", "app")]),
    ("M10a", "C10", "verified publisher removed",
     lambda t: S(t, "TicketDesk").update(verifiedPublisher={"displayName": None, "verifiedPublisherId": None,
                                                              "addedDateTime": None}),
     [("C10", "unverified_publisher_with_access", "TicketDesk", "sp")]),
    ("M10b", "C10", "unverified app gets all-user consent beyond sign-in",
     lambda t: t._access(S(t, "Wallpaper Gallery"), (), "openid profile Calendars.Read", (), None),
     [("C10", "unverified_publisher_with_access", "Wallpaper Gallery", "sp")]),
    ("M11a", "C11", "dev app gains a production redirect URI",
     lambda t: A(t, "orders-web-dev")["web"]["redirectUris"].append("https://orders-prod.lab.example/auth"),
     [("C11", "prod_and_nonprod", "orders-web-dev", "app")]),
    ("M11b", "C11", "second repository trusted by the same app",
     lambda t: t.d["federatedIdentityCredentials"][A(t, "site-builder")["id"]].append(
         t.fic("gh-docs", "repo:lab-org/docs:ref:refs/heads/main")),
     [("C11", "multiple_workloads", "site-builder", "app")]),
    ("M12a", "C12", "workload policy switched to report-only", m_policy_report_only, None),
    ("M12b", "C12", "one app excluded from the policy",
     lambda t: t.d["conditionalAccessPolicies"][0]["conditions"]["clientApplications"][
         "excludeServicePrincipals"].append(S(t, "metrics-collector")["id"]),
     [("C12", "not_in_enforced_policy", "metrics-collector", "sp")]),
    ("M13a", "C13", "non-admin becomes owner of an app with Files.ReadWrite.All",
     lambda t: (grant_perm(t, "doc-archiver", "Files.ReadWrite.All"), owners(t, "doc-archiver", S(t, "carol"))),
     [("C06", "data_graph_permission", "doc-archiver", "sp"), ("C13", "path_from_non_privileged", "doc-archiver", "sp")]),
    ("M13b", "C13", "non-admin becomes owner of a role-assignable admin group",
     lambda t: (grant_perm(t, "doc-archiver", "Files.ReadWrite.All"),
                t.d["groupOwners"][S(t, "App Admins")["id"]].append(t.ref(S(t, "carol")))),
     [("C06", "data_graph_permission", "doc-archiver", "sp"), ("C13", "path_from_non_privileged", "doc-archiver", "sp"),
      VENDOR]),
    ("M13c", "C13", "app owned by a non-admin gets Application.ReadWrite.All (reaches every privileged app)",
     lambda t: (grant_perm(t, "teams-notifier", "Application.ReadWrite.All"),
                grant_perm(t, "doc-archiver", "Files.ReadWrite.All")),
     [("C06", "tier0_graph_permission", "teams-notifier", "sp"),
      ("C06", "data_graph_permission", "doc-archiver", "sp"),
      ("C13", "path_from_non_privileged", "teams-notifier", "sp"),
      ("C13", "path_from_non_privileged", "doc-archiver", "sp"), VENDOR]),
    ("M14a", "C14", "service account signs in interactively",
     lambda t: t.sign_in(S(t, "svc-backup"), "Azure Portal", S(t, "Azure Portal")["appId"], 1, n=20),
     [("C14", "interactive_service_account", "svc-backup", "user")]),
    ("M14b", "C14", "automation account by naming pattern",
     lambda t: (t.user("automation.reports", "automation.reports"),
                t.sign_in(S(t, "automation.reports"), "Azure Portal", S(t, "Azure Portal")["appId"], 1, n=21)),
     [("C14", "interactive_service_account", "automation.reports", "user")]),
]


def _grant(t, name):
    sp = S(t, name)
    return next(g for g in t.d["oauth2PermissionGrants"] if g["clientId"] == sp["id"])


def apply(mid: str):
    """Return (snapshot, expected keys, allowlist) for one mutation of the clean tenant."""
    m = next(m for m in MUTATIONS if m[0] == mid)
    t = build(set())
    m[3](t)
    expected = m[4] if m[4] is not None else _covered_sps(t)
    keys = set()
    for check, rule, name, kind in expected:
        obj = A(t, name) if kind == "app" else S(t, name)
        keys.add((check, rule, obj["id"]))
    return t.snapshot(), keys, allowlist(t)


assert len({m[0] for m in MUTATIONS}) == len(MUTATIONS)
assert all(refs.app_role_id(p) for p in ("Mail.Send", "Files.ReadWrite.All", "Application.ReadWrite.All"))
