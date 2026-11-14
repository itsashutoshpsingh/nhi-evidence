"""Every key in every fixture object is a property documented by Microsoft Graph (pinned docs commit)."""

import pytest
from seeded import ALL, build

from nhi_evidence import refs

SCHEMA = refs.load("graph_schema.json")
SP = set(SCHEMA["v1.0/serviceprincipal"]["properties"]) | {"@odata.type"}
AGENT = set(SCHEMA["v1.0/agentidentity"]["properties"]) | {"appRoles"}  # appRoles inherited from servicePrincipal
LIST_FILES = {
    "applications": "v1.0/application", "appRoleAssignments": "v1.0/approleassignment",
    "oauth2PermissionGrants": "v1.0/oauth2permissiongrant", "roleAssignments": "v1.0/unifiedroleassignment",
    "roleDefinitions": "v1.0/unifiedroledefinition", "users": "v1.0/user", "groups": "v1.0/group",
    "conditionalAccessPolicies": "v1.0/conditionalaccesspolicy", "organization": "v1.0/organization",
    "servicePrincipalSignInActivities": "beta/serviceprincipalsigninactivity", "signIns": "v1.0/signin",
}


def props(name):
    return set(SCHEMA[name]["properties"]) | {"@odata.type"}


def check(obj, allowed, where):
    extra = set(obj) - allowed
    assert not extra, f"{where}: undocumented properties {extra}"


@pytest.mark.parametrize("on", [set(), ALL], ids=["clean", "seeded"])
def test_fixture_keys_are_documented(on):
    d = build(on).snapshot().data
    for f, res in LIST_FILES.items():
        for o in d[f] or []:
            check(o, props(res), f)
    for sp in d["servicePrincipals"]:
        check(sp, AGENT if sp.get("@odata.type") == "#microsoft.graph.agentIdentity" else SP, sp["displayName"])
        for c in sp.get("passwordCredentials", []):
            check(c, props("v1.0/passwordcredential"), "sp password")
        for c in sp.get("keyCredentials", []):
            check(c, props("v1.0/keycredential"), "sp key")
        if sp.get("verifiedPublisher"):
            check(sp["verifiedPublisher"], props("v1.0/verifiedpublisher"), "publisher")
        for r in sp.get("appRoles", []):
            check(r, props("v1.0/approle"), "appRole")
    for app in d["applications"]:
        for c in app["passwordCredentials"]:
            check(c, props("v1.0/passwordcredential"), "password")
            assert c["secretText"] is None  # Graph never returns secret values after creation
        for c in app["keyCredentials"]:
            check(c, props("v1.0/keycredential"), "key")
            assert c["key"] is None
        check(app["web"], props("v1.0/webapplication"), "web")
    for fics in d["federatedIdentityCredentials"].values():
        for f in fics:
            check(f, props("beta/federatedidentitycredential"), "fic")
            assert (f["subject"] is None) != (f["claimsMatchingExpression"] is None)  # beta docs: exactly one
    user_props = props("v1.0/user")
    for m in ("applicationOwners", "servicePrincipalOwners", "servicePrincipalSponsors", "groupMembers", "groupOwners"):
        for objs in d[m].values():
            for o in objs:
                check(o, user_props | SP, m)
    for p in d["conditionalAccessPolicies"]:
        check(p["conditions"], props("v1.0/conditionalaccessconditionset"), "conditions")
        check(p["conditions"]["clientApplications"], props("v1.0/conditionalaccessclientapplications"), "clientApps")
    for s in d["signIns"]:
        check(s["status"], props("v1.0/signinstatus"), "status")
    for a in d["servicePrincipalSignInActivities"]:
        check(a["lastSignInActivity"], props("v1.0/signinactivity") | {"lastSignInRequestId"}, "signInActivity")


def test_reference_names_exist():
    from nhi_evidence import config
    perms = refs.permissions()
    cfg = config.DEFAULTS
    for n in cfg["graph_tier0"] + cfg["graph_data"]:
        assert perms[n]["application"], n
    for n in cfg["sensitive_delegated"] + cfg["basic_delegated"]:
        assert perms[n]["delegated"], n
    for r in cfg["critical_roles"] + ["Application Administrator", "Cloud Application Administrator"]:
        assert refs.roles()[refs.role_id(r)]["privileged"], r
    assert set(refs.owasp()) == {f"NHI{i}" for i in range(1, 11)}
