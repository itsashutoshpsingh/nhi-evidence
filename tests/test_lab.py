"""The seeding script: plan shape, replay against a simulated Graph, and cleanup safety."""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))
import seed_tenant  # noqa: E402
import simulate  # noqa: E402

from nhi_evidence import config, engine  # noqa: E402


def test_plan_only_creates_tagged_lab_objects():
    steps = seed_tenant.plan("lab.example")
    assert {s["method"] for s in steps} <= {"GET", "POST", "PATCH"}
    for s in steps:
        if s["path"] in ("/applications", "/servicePrincipals"):
            assert seed_tenant.TAG in s["body"]["tags"]
        if s["path"] == "/applications" or s["path"] == "/users":
            assert s["body"].get("displayName", "").startswith(seed_tenant.PREFIX)
        if s["method"] == "PATCH":
            assert "{" in s["path"]  # only objects this plan created
    assert {s["issue"] for s in steps} - {"setup"} == {"S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08",
                                                       "S10", "S11", "S12"}


def test_replay_finds_each_seeded_issue_and_nothing_else():
    snap, sim, ids = simulate.replay()
    got = {(f.check_id, f.display_name.removeprefix("nhi-lab-")) for f in engine.evaluate(snap, config.load())
           if not f.suppressed}
    assert got == {("C01", "reporting-export"), ("C03", "legacy-crm-connector"), ("C04", "old-billing-api"),
                   ("C05", "nightly-report-job"), ("C06", "doc-archiver"), ("C07", "mailmerge"),
                   ("C08", "identity-automation"), ("C09", "infra-deployer"), ("C11", "orders-api-ci"),
                   ("C12", "payroll-export"), ("C13", "sharepoint-migrator"), ("C06", "sharepoint-migrator")}
    assert "returned-once-and-discarded" not in repr(ids) + repr(snap.data)


def test_cleanup_refuses_foreign_objects():
    def handler(req):
        if req.method == "GET" and req.url.path.endswith("/applications"):
            return httpx.Response(200, json={"value": [{"id": "1", "displayName": "payroll-prod"}]})
        if req.method == "GET":
            return httpx.Response(200, json={"value": []})
        return httpx.Response(204)
    with pytest.raises(AssertionError):
        seed_tenant.cleanup(httpx.Client(transport=httpx.MockTransport(handler)))


def test_cleanup_deletes_lab_objects_only():
    deleted = []

    def handler(req):
        if req.method == "DELETE":
            deleted.append(req.url.path)
            return httpx.Response(204)
        if req.url.path.endswith("/applications"):
            return httpx.Response(200, json={"value": [{"id": "a1", "displayName": "nhi-lab-x"}]})
        if req.url.path.endswith("/users"):
            return httpx.Response(200, json={"value": [{"id": "u1", "userPrincipalName": "nhi-lab-y@lab.example"}]})
        return httpx.Response(200, json={"value": [{"id": "p1", "displayName": "Real policy"},
                                                   {"id": "p2", "displayName": "nhi-lab-workload"}]})
    names = seed_tenant.cleanup(httpx.Client(transport=httpx.MockTransport(handler)))
    assert names == ["nhi-lab-x", "nhi-lab-y@lab.example", "nhi-lab-workload"]
    assert not any("p1" in p for p in deleted)
