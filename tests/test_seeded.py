"""The seeded tenant gives exactly its expected findings; the clean tenant gives none; each issue alone
gives exactly its own findings."""

import json
from pathlib import Path

import pytest
from mutations import MUTATIONS, apply
from seeded import ISSUES, allowlist, build

from nhi_evidence import config, engine
from nhi_evidence.snapshot import Snapshot

CFG = config.load()
FIX = Path(__file__).resolve().parents[1] / "fixtures"


def live(snap, allow):
    return {f.key for f in engine.evaluate(snap, CFG, allow) if not f.suppressed}


def expected(t, issues):
    out = set()
    for k in issues:
        for check, rule, name, _ in ISSUES[k]:
            obj = t.by_name.get(f"app:{name}") if check in ("C01", "C03", "C04", "C05", "C09", "C11") else None
            out.add((check, rule, (obj or t.by_name[name])["id"]))
    return out


def test_committed_fixtures_match_builder():
    for name, on in (("clean_tenant", set()), ("seeded_tenant", set(ISSUES))):
        built = build(on).snapshot().data
        for f, v in built.items():
            path = FIX / name / f"{f}.json"
            assert json.loads(path.read_text()) == v, f"{name}/{f}.json is stale: run python fixtures/seeded.py"


def test_seeded_tenant_from_disk():
    snap = Snapshot.load(FIX / "seeded_tenant")
    allow = engine.load_allowlist(FIX / "seeded_tenant" / "allowlist.json")
    exp = {(e["check_id"], e["rule"], e["object_id"])
           for e in json.loads((FIX / "seeded_tenant" / "expected_findings.json").read_text())}
    assert live(snap, allow) == exp
    assert len(exp) == 15


def test_clean_tenant_is_clean():
    t = build(set())
    assert live(t.snapshot(), allowlist(t)) == set()


@pytest.mark.parametrize("issue", sorted(ISSUES))
def test_each_issue_alone(issue):
    t = build({issue})
    assert live(t.snapshot(), allowlist(t)) == expected(t, {issue})


@pytest.mark.parametrize("mid", [m[0] for m in MUTATIONS])
def test_mutation(mid):
    snap, exp, allow = apply(mid)
    assert live(snap, allow) == exp


def test_without_activity_data_two_checks_are_skipped():
    t = build(set(ISSUES), include_activity=False)
    snap = t.snapshot()
    assert set(engine.skipped(snap)) == {"C02", "C14"}
    keys = live(snap, allowlist(t))
    assert {k[0] for k in keys} == {f"C{i:02d}" for i in range(1, 14)} - {"C02"}
