"""Seeded synthetic tenants at scale, with planted issues and look-alike controls at known rates.

generate(n, seed) returns (Tenant, expected keys, planted log). n is the number of service principals.
Background objects are clean by construction; each planted issue goes on its own identity and records
the (check, rule, object id) keys it must produce; look-alikes record nothing. All randomness comes from
random.Random(seed), so a (n, seed) pair always gives the same tenant.
"""

import random
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "src"))
from nhi_evidence import refs  # noqa: E402
from nhi_evidence.fixturekit import Tenant  # noqa: E402

NOW = datetime(2026, 11, 1, tzinfo=UTC)
MIX = {"home": 0.60, "third": 0.15, "first": 0.10, "mi": 0.08, "agent": 0.07}
ISSUE_RATE = 0.02  # per check, as a share of identities eligible for that check
CONTROL_RATE = 0.02
LOW_PERMS = ["User.Read.All", "Application.Read.All", "Group.Read.All", "Calendars.Read", "Sites.Selected"]
LOOKALIKE_PERMS = ["Application.Read.All", "Sites.Selected", "Mail.ReadBasic.All", "Directory.Read.All"]
SAFE_ROLES = ["Directory Readers", "Reports Reader", "Message Center Reader", "Usage Summary Reports Reader"]
PRIV_ROLES = sorted(r["displayName"] for r in refs.roles().values() if r["privileged"])
TIER0 = ["RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
         "Directory.ReadWrite.All"]
DATA = ["Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All", "Sites.ReadWrite.All",
        "Sites.FullControl.All", "User.ReadWrite.All", "Group.ReadWrite.All", "Chat.Read.All"]
SENSITIVE = ["Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All",
             "Directory.AccessAsUser.All", "User.ReadWrite.All", "Calendars.ReadWrite"]
GH = "https://token.actions.githubusercontent.com"


def generate(n: int, seed: int):
    rnd = random.Random(seed)
    t = Tenant(f"synth-{n}-{seed}", NOW)
    expected, log = set(), []
    counts = {k: max(1, round(n * v)) for k, v in MIX.items()}
    users = [t.user(f"user{i:05d}", f"User {i:05d}") for i in range(max(20, n // 2))]
    disabled = [t.user(f"left{i:04d}", f"Leaver {i:04d}", enabled=False) for i in range(max(3, n // 50))]
    svc_users = [t.user(f"svc-job{i:04d}", f"svc-job{i:04d}") for i in range(max(3, n // 50))]
    admins = [t.user(f"admin{i}", f"Admin {i}") for i in range(3)]
    for a in admins:
        t.role(a, "Global Administrator")
    appadmins = [t.user(f"appadmin{i}", f"App Admin {i}") for i in range(2)]
    t.group("App Admins", members=appadmins, owners=admins[:1])
    t.role(t.by_name["App Admins"], "Cloud Application Administrator")
    for u in rnd.sample(users, min(len(users), max(5, n // 20))):  # people sign in interactively
        t.sign_in(u, "Azure Portal", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", rnd.uniform(0, 29), n=rnd.randrange(200))
    for s in svc_users:  # service accounts: failed interactive attempts only
        t.sign_in(s, "Azure Portal", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", rnd.uniform(0, 29), error=50126)
    policy = t.ca_policy("Workload identities: block outside trusted locations")
    excluded = policy["conditions"]["clientApplications"]["excludeServicePrincipals"]

    def owners_for():
        return rnd.sample(users, rnd.randint(1, 3))

    homes = []
    for i in range(counts["home"]):
        name = f"app-{i:05d}"
        life = rnd.choice([30, 90, 180])  # background secrets are still valid: started fewer days ago than they last
        kind = rnd.choices(["cert", "fic", "secret_web"], [0.5, 0.25, 0.25])[0]
        perms = [rnd.choice(LOW_PERMS)] if kind != "secret_web" and rnd.random() < 0.6 else []
        roles = ["Directory Readers"] if kind != "secret_web" and not perms and rnd.random() < 0.2 else []
        smr = f"CMDB-{i}" if rnd.random() < 0.15 else None
        fics = [t.fic(f"{name}-gh", f"repo:org/{name}:" + rnd.choice(["environment:production",
                                                                         "ref:refs/heads/main"]))] if kind == "fic" else []
        app, sp = t.app(name, owners=[] if smr else owners_for(), smr=smr,
                        certs=[(rnd.uniform(1, 200), 365)] if kind == "cert" else [],
                        secrets=[(rnd.uniform(1, life - 1), life)] if kind == "secret_web" else [],
                        fics=fics, perms=perms, roles=roles, last_sign_in=rnd.uniform(0, 60),
                        redirects=[f"https://{name}.corp.example/auth"] if kind == "secret_web" else [])
        homes.append((name, kind, app, sp))
    thirds = []
    for i in range(counts["third"]):
        verified = rnd.random() < 0.4
        sp = t.third_party(f"vendor-{i:05d}", "vendor", verified,
                           perms=[rnd.choice(LOW_PERMS)] if verified and rnd.random() < 0.5 else [],
                           all_consent="openid profile User.Read" if rnd.random() < 0.6 else None,
                           last_sign_in=rnd.uniform(0, 60))
        thirds.append((sp, verified))
    for i in range(counts["first"]):
        sp = t.first_party(f"Microsoft service {i:04d}", t.uid("ms", i))
        if rnd.random() < 0.3:  # first-party apps with tenant-wide consent: the allowlist suppresses these
            t._access(sp, (), "openid profile User.Read Directory.AccessAsUser.All", (), None)
    mis = [t.managed_identity(f"mi-{i:05d}", perms=[rnd.choice(LOW_PERMS)] if rnd.random() < 0.5 else [])
           for i in range(counts["mi"])]
    agents = [t.agent(f"agent-{i:05d}", sponsors=[rnd.choice(users)],
                      perms=["User.Read.All"] if rnd.random() < 0.3 else []) for i in range(counts["agent"])]

    used = set()

    def pick(pool, k):
        free = [x for x in pool if id(x) not in used]
        chosen = rnd.sample(free, min(k, len(free)))
        used.update(id(x) for x in chosen)
        return chosen

    def plant(check, rule, obj, variant):
        expected.add((check, rule, obj["id"]))
        log.append({"check": check, "rule": rule, "object": obj["displayName"], "variant": variant})

    def rate(pool, r=ISSUE_RATE):
        return max(1, round(len(pool) * r))

    def apps(pred=lambda h: True):
        return [h for h in homes if pred(h)]

    # ---- C01
    for name, kind, app, sp in pick(apps(), rate(homes)):
        v = rnd.choice(["no_owner", "disabled_owner", "sp_owner"])
        app["serviceManagementReference"] = None
        t.d["applicationOwners"][app["id"]] = {"no_owner": [], "disabled_owner": [t.ref(rnd.choice(disabled))],
                                              "sp_owner": [t.ref(rnd.choice(mis))]}[v]
        plant("C01", "no_owner" if v == "no_owner" else "only_disabled_or_nonhuman_owners", app, v)
    for a in pick(agents, rate(agents, 0.05)):
        t.d["servicePrincipalSponsors"][a["id"]] = []
        plant("C01", "agent_no_sponsor", a, "agent")
    for name, kind, app, sp in pick(apps(), rate(homes, CONTROL_RATE)):  # look-alikes
        if rnd.random() < 0.5:
            t.d["applicationOwners"][app["id"]] = [t.ref(rnd.choice(disabled)), t.ref(rnd.choice(users))]
        else:
            t.d["applicationOwners"][app["id"]], app["serviceManagementReference"] = [], "CMDB-x"
    # ---- C02
    holding = _holders(t)
    for name, kind, app, sp in pick(apps(lambda h: h[3]["id"] in holding), rate(homes)):
        if rnd.random() < 0.5:
            t.sign_in_activity(sp, rnd.uniform(91, 400))
            plant("C02", "stale_sign_in", sp, "stale")
        else:
            t.sign_in_activity(sp, None)
            plant("C02", "no_sign_in", sp, "never")
    for name, kind, app, sp in pick(apps(lambda h: h[1] != "secret_web"), rate(homes, CONTROL_RATE)):
        if rnd.random() < 0.5:
            app["createdDateTime"] = t.ago(rnd.uniform(1, 85))
            t.sign_in_activity(sp, None)
        else:
            sp["accountEnabled"] = False
            t.sign_in_activity(sp, None)
    # ---- C03
    for name, kind, app, sp in pick(apps(), rate(homes)):
        v = rnd.choice(["long", "never", "sp_object"])
        if v == "sp_object":
            sp["passwordCredentials"] = [t.secret(f"{name}-sp", rnd.uniform(1, 50), rnd.uniform(181, 1095))]
            plant("C03", "lifetime_over_limit", sp, v)
            continue
        cred = t.secret(f"{name}-long", rnd.uniform(1, 50), None if v == "never" else rnd.uniform(181, 1095))
        app["passwordCredentials"] = [cred]
        plant("C03", "no_end_date" if v == "never" else "lifetime_over_limit", app, v)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "secret_web"), rate(homes, CONTROL_RATE)):
        app["passwordCredentials"] = [t.secret(f"{name}-180", 1, rnd.choice([179, 180]))]
    # ---- C04
    for name, kind, app, sp in pick(apps(), rate(homes)):
        v = rnd.choice(["expired_secret", "expired_cert", "two_secrets"])
        if v == "two_secrets":
            if kind != "secret_web":
                continue  # a second secret on an app-only app would also be C05's case; keep one cause
            app["passwordCredentials"] = [t.secret(f"{name}-a", 10, 90), t.secret(f"{name}-b", 3, 90)]
            plant("C04", "multiple_active_secrets", app, v)
        elif v == "expired_secret":
            app["passwordCredentials"].append(t.secret(f"{name}-old", rnd.uniform(200, 700), 180))
            plant("C04", "expired_present", app, v)
        else:
            app["keyCredentials"].append(t.cert(f"{name}-old", rnd.uniform(400, 900), 365))
            plant("C04", "expired_present", app, v)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "secret_web"), rate(homes, CONTROL_RATE)):
        app["passwordCredentials"] = [t.secret(f"{name}-soon", 88, 90)]  # expires in 2 days
    # ---- C05
    app_only = _holders(t, grants=False)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "cert" and h[3]["id"] in app_only), rate(homes)):
        app["keyCredentials"], app["passwordCredentials"] = [], [t.secret(f"{name}-s", 5, 90)]
        plant("C05", "secret_only", app, "cert replaced by secret")
    # ---- C06 and C13
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "cert"), rate(homes)):
        perm = rnd.choice(TIER0 + DATA)
        t._access(sp, [perm], None, (), None)
        t.d["applicationOwners"][app["id"]], app["serviceManagementReference"] = [], "CMDB-priv"
        plant("C06", "tier0_graph_permission" if perm in TIER0 else "data_graph_permission", sp, perm)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "cert"), rate(homes, CONTROL_RATE)):
        t._access(sp, [rnd.choice(LOOKALIKE_PERMS)], None, (), None)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "cert"), rate(homes)):
        perm = rnd.choice(DATA)
        t._access(sp, [perm], None, (), None)
        owner = rnd.choice(users)
        if rnd.random() < 0.5:
            t.d["applicationOwners"][app["id"]] = [t.ref(owner)]
            via = "app owner"
        else:
            t.d["applicationOwners"][app["id"]], app["serviceManagementReference"] = [], "CMDB-priv"
            t.d["servicePrincipalOwners"][sp["id"]] = [t.ref(owner)]
            via = "service principal owner"
        plant("C06", "data_graph_permission", sp, perm)
        plant("C13", "path_from_non_privileged", sp, via)
    # ---- C07
    for sp, verified in pick([x for x in thirds if x[1]], rate(thirds)):
        scopes = " ".join(rnd.sample(SENSITIVE, rnd.randint(1, 3)))
        _set_all_consent(t, sp, "openid profile User.Read " + scopes)
        plant("C07", "all_principals_sensitive_scope", sp, scopes)
    for sp, verified in pick([x for x in thirds if x[1]], rate(thirds, CONTROL_RATE)):
        if rnd.random() < 0.5:
            _set_all_consent(t, sp, "openid profile email offline_access User.Read")
        else:
            t.d["oauth2PermissionGrants"].append({"id": t.opaque("pg", sp["id"]), "clientId": sp["id"],
                                                  "consentType": "Principal", "principalId": rnd.choice(users)["id"],
                                                  "resourceId": t.graph["id"], "scope": "Mail.Read"})
    # ---- C08
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "cert"), rate(homes)):
        role = rnd.choice(PRIV_ROLES)
        t.role(sp, role)
        t.d["applicationOwners"][app["id"]], app["serviceManagementReference"] = [], "CMDB-role"
        plant("C08", "privileged_directory_role", sp, role)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "cert"), rate(homes, CONTROL_RATE)):
        t.role(sp, rnd.choice(SAFE_ROLES))
    # ---- C09
    variants = [("subject", "repo:org/{n}:pull_request", GH, "github_pull_request"),
                ("subject", "repo:org/{n}:pull-request", GH, "github_subject_never_matches"),
                ("subject", "repo:org/*:ref:refs/heads/main", GH, "literal_wildcard_subject"),
                ("expr", "claims['sub'] matches 'repo:org/*:ref:refs/heads/main'", GH, "flexible_wildcard_repository"),
                ("expr", "claims['sub'] matches 'repo:org/{n}:ref:refs/heads/*'", GH, "flexible_wildcard_ref"),
                ("subject", "repo:org/{n}:ref:refs/heads/main", "https://ci.untrusted.example", "unexpected_issuer"),
                ("subject", "system:serviceaccount:default:default",
                 "https://eastus.oic.prod-aks.azure.com/{t}/{t}/", "kubernetes_default_service_account")]
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "fic"), rate(homes)):
        how, text, issuer, rule = rnd.choice(variants)
        text, issuer = text.format(n=name), issuer.format(t=t.tenant_id)
        t.d["federatedIdentityCredentials"][app["id"]] = [
            t.fic(f"{name}-x", text if how == "subject" else None, issuer, text if how == "expr" else None)]
        plant("C09", rule, app, text)
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "fic"), rate(homes, CONTROL_RATE)):
        subj = rnd.choice([f"repo:org/{name}:ref:refs/tags/v1", f"repo:org/{name}:environment:production",
                           "system:serviceaccount:payments:api"])
        iss = GH if subj.startswith("repo") else f"https://eastus.oic.prod-aks.azure.com/{t.tenant_id}/{t.tenant_id}/"
        t.d["federatedIdentityCredentials"][app["id"]] = [t.fic(f"{name}-c", subj, iss)]
    # ---- C10
    for sp, verified in pick([x for x in thirds if not x[1]], rate(thirds)):
        if rnd.random() < 0.5:
            t._access(sp, [rnd.choice(LOW_PERMS)], None, (), None)
        else:
            _set_all_consent(t, sp, "openid profile User.Read Calendars.Read")
        plant("C10", "unverified_publisher_with_access", sp, "unverified with access")
    # ---- C11
    for name, kind, app, sp in pick(apps(lambda h: h[1] == "fic"), rate(homes)):
        v = rnd.choice(["fic_envs", "two_repos", "redirects"])
        if v == "fic_envs":
            t.d["federatedIdentityCredentials"][app["id"]] = [
                t.fic(f"{name}-p", f"repo:org/{name}:environment:production"),
                t.fic(f"{name}-d", f"repo:org/{name}:environment:" + rnd.choice(["dev", "staging", "test", "uat"]))]
            plant("C11", "prod_and_nonprod", app, v)
        elif v == "two_repos":
            t.d["federatedIdentityCredentials"][app["id"]] = [
                t.fic(f"{name}-1", f"repo:org/{name}:ref:refs/heads/main"),
                t.fic(f"{name}-2", f"repo:org/{name}-tools:ref:refs/heads/main")]
            plant("C11", "multiple_workloads", app, v)
        else:
            app["web"]["redirectUris"] = [f"https://{name}-prod.corp.example/auth", f"https://{name}-qa.corp.example/a"]
            plant("C11", "prod_and_nonprod", app, v)
    # ---- C12
    app_only = _holders(t, grants=False)
    for name, kind, app, sp in pick(apps(lambda h: h[3]["id"] in app_only and h[3]["accountEnabled"]), rate(homes)):
        excluded.append(sp["id"])
        plant("C12", "not_in_enforced_policy", sp, "excluded")
    holding = _holders(t)
    for mi in pick([m for m in mis if m["id"] in holding], rate(mis, 0.1)):
        excluded.append(mi["id"])  # managed identities are out of CA's scope: excluding one changes nothing
    # ---- C14
    for s in pick(svc_users, rate(svc_users, 0.2)):
        t.sign_in(s, "Azure Portal", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", rnd.uniform(0, 29), n=999)
        plant("C14", "interactive_service_account", s, "interactive")
    return t, expected, log


def _holders(t, grants=True) -> set:
    """Principals holding application permissions or directory roles (and delegated grants if asked)."""
    out = {a["principalId"] for a in t.d["appRoleAssignments"]} | {r["principalId"] for r in t.d["roleAssignments"]}
    return out | {g["clientId"] for g in t.d["oauth2PermissionGrants"]} if grants else out


def _set_all_consent(t, sp, scope):
    grants = [g for g in t.d["oauth2PermissionGrants"] if g["clientId"] == sp["id"] and g["consentType"] == "AllPrincipals"]
    if grants:
        grants[0]["scope"] = scope
    else:
        t._access(sp, (), scope, (), None)
