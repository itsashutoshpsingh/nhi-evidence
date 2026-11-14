"""What the refinements in each check buy: one-line versions of the checks (the rule as a quick script
would write it) against the same synthetic tenants. Compared at (check, object) level.

The look-alike controls were designed to sit on exactly these refinements, so the false-finding counts
measure how often the one-line rule trips on them at the rates in experiments/synth.py; they are not an
estimate for real tenants. Writes results/ablation.csv.
"""

import csv
import re
import sys
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "experiments"), str(ROOT / "fixtures")]
from seeded import ISSUES, allowlist, build  # noqa: E402
from synth import generate  # noqa: E402

from nhi_evidence import config, engine, refs  # noqa: E402
from nhi_evidence.snapshot import ts  # noqa: E402

CFG = config.load()
REFINEMENT = {
    "C01": "disabled and non-human owners do not count; serviceManagementReference counts",
    "C02": "grace period for new apps; skip managed identities, first-party and identities with no access",
    "C03": "service principal secrets too; expired secrets left to C04",
    "C04": "count only active secrets as duplicates; include service principal objects",
    "C05": "only app-only identities; federation counts as an alternative",
    "C06": "named permission list (read-only Mail/Files count, ReadWrite names that are not tenant-wide do not)",
    "C07": "only sensitive scopes on Microsoft Graph; allowlist first-party",
    "C08": "only roles Microsoft labels privileged",
    "C09": "flexible expressions, issuers, Kubernetes default account, spellings that never match",
    "C10": "only unverified apps that hold access; allowlist first-party",
    "C12": "enforced policies only; skip managed identities, multi-tenant and disabled apps",
    "C13": "graph of owners, roles, groups and app permissions; disabled and admin principals are not sources",
    "C14": "successful interactive sign-ins only",
}


def naive(snap) -> set:
    out = set()
    add = lambda c, o: out.add((c, o))  # noqa: E731
    cutoff = snap.now - timedelta(days=90)
    for a in snap.applications:
        if not snap.applicationOwners.get(a["id"]):
            add("C01", a["id"])
        for c in a.get("passwordCredentials", []):
            s, e = ts(c.get("startDateTime")), ts(c.get("endDateTime"))
            if e is None or (e - s).days > 180:
                add("C03", a["id"])
        creds = a.get("passwordCredentials", []) + a.get("keyCredentials", [])
        if any(not snap.active(c) for c in creds) or len(a.get("passwordCredentials", [])) > 1:
            add("C04", a["id"])
        if a.get("passwordCredentials") and not a.get("keyCredentials"):
            add("C05", a["id"])
        for f in snap.federatedIdentityCredentials.get(a["id"], []):
            if "*" in (f.get("subject") or "") or (f.get("subject") or "").endswith(":pull_request"):
                add("C09", a["id"])
    last = {x["appId"]: ts((x.get("lastSignInActivity") or {}).get("lastSignInDateTime"))
            for x in snap.servicePrincipalSignInActivities or []}
    policy_ids = set()
    for p in snap.conditionalAccessPolicies:
        policy_ids |= set(((p.get("conditions") or {}).get("clientApplications") or {}).get("includeServicePrincipals")
                          or [])
    excluded = {x for p in snap.conditionalAccessPolicies
                for x in ((p.get("conditions") or {}).get("clientApplications") or {}).get("excludeServicePrincipals")
                or []}
    for sp in snap.servicePrincipals:
        if sp.get("accountEnabled") and sp.get("appId") and (last.get(sp["appId"]) or cutoff) <= cutoff:
            add("C02", sp["id"])
        if any("ReadWrite" in n for n, _ in snap.graph_permissions(sp["id"])):
            add("C06", sp["id"])
        if snap.roles_by_principal.get(sp["id"]):
            add("C08", sp["id"])
        if sp.get("appOwnerOrganizationId") not in (None, snap.tenant_id) and \
                not (sp.get("verifiedPublisher") or {}).get("verifiedPublisherId"):
            add("C10", sp["id"])
        if snap.app_permissions(sp["id"]) and ("ServicePrincipalsInMyTenant" not in policy_ids
                                               and sp["id"] not in policy_ids or sp["id"] in excluded):
            add("C12", sp["id"])
        app = snap.app_of(sp)
        if (snap.app_permissions(sp["id"]) or snap.roles_by_principal.get(sp["id"])) and app and \
                snap.applicationOwners.get(app["id"]) and any(
                    re.search("ReadWrite|Mail|Files|Sites", n or "") for n, _ in snap.graph_permissions(sp["id"])):
            add("C13", sp["id"])
    for g in snap.oauth2PermissionGrants:
        if g.get("consentType") == "AllPrincipals":
            add("C07", g["clientId"])
    pattern = re.compile(CFG["service_account_pattern"])
    for s in snap.signIns or []:
        if pattern.match((s.get("userPrincipalName") or "").split("@")[0]):
            add("C14", s["userId"])
    return out


def refined(snap, allow=None) -> set:
    return {(f.check_id, f.object_id) for f in engine.evaluate(snap, CFG, allow) if not f.suppressed}


def main():
    tenants = []
    t = build(set(ISSUES))
    tenants.append(("seeded fixture", t.snapshot(), allowlist(t), None))
    t = build(set())
    tenants.append(("clean fixture", t.snapshot(), allowlist(t), None))
    for seed in range(1, 6):
        g, exp, _ = generate(1000, seed)
        tenants.append((f"synthetic 1000 seed {seed}", g.snapshot(), None, {(k[0], k[2]) for k in exp}))
    rows = []
    for name, snap, allow, truth in tenants:
        ref = refined(snap, allow)
        truth = ref if truth is None else truth  # fixtures: refined output equals the expected findings (tested)
        nv = naive(snap)
        for cid in REFINEMENT:
            t_ = {k for k in truth if k[0] == cid}
            n_ = {k for k in nv if k[0] == cid}
            r_ = {k for k in ref if k[0] == cid}
            rows.append({"tenant": name, "check": cid, "true": len(t_), "naive_found": len(n_ & t_),
                         "naive_false": len(n_ - t_), "naive_missed": len(t_ - n_), "refined_false": len(r_ - t_),
                         "refined_missed": len(t_ - r_), "refinement": REFINEMENT[cid]})
    with open(ROOT / "results" / "ablation.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    tot = {}
    for r in rows:
        x = tot.setdefault(r["check"], [0, 0, 0, 0])
        x[0] += r["true"]
        x[1] += r["naive_false"]
        x[2] += r["naive_missed"]
        x[3] += r["refined_false"] + r["refined_missed"]
    for k, v in tot.items():
        print(k, "true", v[0], "naive false", v[1], "naive missed", v[2], "refined errors", v[3])
    assert refs.MS_GRAPH_APP_ID


if __name__ == "__main__":
    main()
