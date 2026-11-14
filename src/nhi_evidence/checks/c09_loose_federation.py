"""Check 9: federated identity credential that trusts too much (NHI6 Insecure Cloud Deployment Configurations).

Standard credentials match issuer, subject and audience exactly and case-sensitively; only the preview
"flexible" credentials (beta `claimsMatchingExpression`) support wildcards. Rules, with examples, are in
docs/federation-rules.md.
"""

import re

from ..finding import Finding, escalate

META = {
    "id": "C09", "title": "Loose federated credential", "nhi": ["NHI6"],
    "graph": ["GET /beta/applications/{id}/federatedIdentityCredentials"],
    "licence": "free",
}
GITHUB = re.compile(r"^https://token\.actions\.githubusercontent\.com/?$")
AKS = re.compile(r"\.oic\.prod-aks\.azure\.com/")
EXCHANGE = "api://AzureADTokenExchange"
SUB_MATCH = re.compile(r"claims\['sub'\]\s+matches\s+'((?:[^'\\]|\\.)*)'")


def rules(fic: dict, cfg: dict) -> list[tuple[str, str, str]]:
    """(rule, base severity, explanation) for one credential."""
    out = []
    issuer = fic.get("issuer") or ""
    subject = fic.get("subject")
    expr = (fic.get("claimsMatchingExpression") or {}).get("value")
    if not any(re.match(p, issuer) for p in cfg["known_issuers"]):
        out.append(("unexpected_issuer", "medium", f"issuer {issuer!r} is not a documented workload platform"))
    if fic.get("audiences") != [EXCHANGE]:
        out.append(("non_default_audience", "low", f"audiences {fic.get('audiences')} instead of {EXCHANGE}"))
    if subject is not None:
        if "*" in subject or "?" in subject:
            out.append(("literal_wildcard_subject", "low",
                        "standard credentials match exactly, so this wildcard is literal and never matches"))
        if GITHUB.match(issuer):
            if subject.endswith(":pull_request"):
                out.append(("github_pull_request", "medium",
                            "trusts any workflow run for a pull request in this repository, before review"))
            elif subject.endswith(":pull-request"):
                out.append(("github_subject_never_matches", "low",
                            "GitHub's subject is 'pull_request'; 'pull-request' never matches"))
            elif not re.match(r"^repo:[^:]+/[^:]+:(environment:.+|ref:refs/(heads|tags)/.+)$", subject):
                out.append(("github_subject_unrecognised", "low", "not an environment, branch, tag or PR subject"))
        if AKS.search(issuer) and subject.endswith(":default:default"):
            out.append(("kubernetes_default_service_account", "medium",
                        "any pod running as the default service account in the default namespace"))
    for pat in SUB_MATCH.findall(expr or ""):
        repo = pat.split(":")[1] if pat.startswith("repo:") else pat
        if any(ch in repo for ch in "*?"):
            out.append(("flexible_wildcard_repository", "high", f"wildcard repository in {pat!r}"))
        elif any(ch in pat for ch in "*?"):
            out.append(("flexible_wildcard_ref", "medium", f"wildcard branch, tag or context in {pat!r}"))
    return out


def run(snap, cfg) -> list[Finding]:
    out = []
    for app in snap.applications:
        sp = snap.sp_of(app)
        for fic in snap.federatedIdentityCredentials.get(app["id"], []):
            for rule, sev, why in rules(fic, cfg):
                out.append(Finding(
                    "C09", rule, META["nhi"], app["id"], "application", app["displayName"],
                    escalate(snap, cfg, sp, sev),
                    {"credential": fic.get("name"), "issuer": fic.get("issuer"), "subject": fic.get("subject"),
                     "claimsMatchingExpression": fic.get("claimsMatchingExpression"),
                     "audiences": fic.get("audiences"), "reason": why},
                    "A federated credential lets an outside workload sign in as this app with no secret; the "
                    "subject is the only thing that decides which workload, so a loose subject hands the app's "
                    "permissions to more code than intended.",
                    "Entra admin center > App registrations > app > Certificates & secrets > Federated credentials; "
                    f"GET /beta/applications/{app['id']}/federatedIdentityCredentials",
                    extra={"credential": fic.get("name")},
                ))
    return out
