"""Federated credential rules (docs/federation-rules.md) and other rule edge cases."""

import pytest

from nhi_evidence import config
from nhi_evidence.checks.c09_loose_federation import rules
from nhi_evidence.checks.c11_environment_reuse import env_class

CFG = config.load()
GH = "https://token.actions.githubusercontent.com"
AUD = ["api://AzureADTokenExchange"]


@pytest.mark.parametrize("subject,expr,issuer,want", [
    ("repo:o/r:environment:production", None, GH, set()),
    ("repo:o/r:ref:refs/heads/main", None, GH, set()),
    ("repo:o/r:ref:refs/tags/v1.2", None, GH, set()),
    ("repo:o/r:pull_request", None, GH, {"github_pull_request"}),
    ("repo:o/r:pull-request", None, GH, {"github_subject_never_matches"}),
    ("repo:o/r", None, GH, {"github_subject_unrecognised"}),
    ("repo:o/*:ref:refs/heads/main", None, GH, {"literal_wildcard_subject"}),
    (None, "claims['sub'] matches 'repo:o/*:ref:refs/heads/main'", GH, {"flexible_wildcard_repository"}),
    (None, "claims['sub'] matches 'repo:o/r-??:ref:refs/heads/main'", GH, {"flexible_wildcard_repository"}),
    (None, "claims['sub'] matches 'repo:o/r:ref:refs/heads/*' and claims['repository_id'] eq '1'", GH,
     {"flexible_wildcard_ref"}),
    (None, "claims['sub'] eq 'repo:o/r:ref:refs/heads/main'", GH, set()),
    ("system:serviceaccount:default:default", None,
     "https://westeurope.oic.prod-aks.azure.com/11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222/",
     {"kubernetes_default_service_account"}),
    ("project_path:g/p:ref_type:branch:ref:main", None, "https://gitlab.com", set()),
    ("x", None, "https://issuer.example", {"unexpected_issuer"}),
    ("x", None, "https://token.actions.githubusercontent.com.evil.example", {"unexpected_issuer"}),
])
def test_fic_rules(subject, expr, issuer, want):
    fic = {"issuer": issuer, "subject": subject, "audiences": AUD,
           "claimsMatchingExpression": {"value": expr, "languageVersion": 1} if expr else None}
    assert {r[0] for r in rules(fic, CFG)} == want


def test_audience_rule():
    fic = {"issuer": GH, "subject": "repo:o/r:environment:prod", "audiences": ["api://custom"]}
    assert {r[0] for r in rules(fic, CFG)} == {"non_default_audience"}


@pytest.mark.parametrize("text,want", [
    ("environment:production", "prod"), ("environment:dev", "nonprod"), ("orders-dev.lab.example", "nonprod"),
    ("orders.lab.example", None), ("contest.lab.example", None), ("ref:refs/heads/main", None),
    ("environment:preprod", "nonprod"),
])
def test_env_class(text, want):
    assert env_class(text, CFG) == want
