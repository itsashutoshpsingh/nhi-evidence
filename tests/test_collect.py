"""The collector against the Graph mock: paging, throttling, $select, GET-only, and a lossless round trip."""

from datetime import UTC, datetime

import httpx
from seeded import ISSUES, allowlist, build

from nhi_evidence import config, engine
from nhi_evidence.collect import Graph, collect
from nhi_evidence.graphmock import MockGraph


def run(snap, **kw):
    mock = MockGraph(snap, **kw)
    sleeps = []
    g = Graph("x.y.z", httpx.Client(transport=mock.transport()), sleep=sleeps.append)
    got = collect(g, now=datetime(2026, 11, 1, tzinfo=UTC), sign_in_days=30)
    return mock, g, got, sleeps


def test_round_trip_gives_identical_findings():
    t = build(set(ISSUES))
    src = t.snapshot()
    mock, g, got, sleeps = run(src, max_page=3, throttle_every=11)
    cfg = config.load()
    before = {f.key for f in engine.evaluate(src, cfg, allowlist(t)) if not f.suppressed}
    after = {f.key for f in engine.evaluate(got, cfg, allowlist(t)) if not f.suppressed}
    assert before == after and len(after) == 15
    assert mock.writes == []
    assert g.throttled > 0 and set(sleeps) == {1.0}  # waited exactly Retry-After
    assert len(got.servicePrincipals) == len(src.servicePrincipals)  # every page was followed
    assert {"v1.0", "beta"} == set(mock.versions)
    assert got.manifest["api_versions"]["servicePrincipalSignInActivities"] == "beta"


def test_select_drops_unlisted_fields():
    t = build(set())
    _, _, got, _ = run(t.snapshot())
    assert "createdByAppId" not in got.servicePrincipals[-1]  # agent field not in $select
    assert all("passwordCredentials" in a for a in got.applications)


def test_backoff_without_retry_after():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"value": [{"id": "1"}]})
    sleeps = []
    g = Graph("t", httpx.Client(transport=httpx.MockTransport(handler)), sleep=sleeps.append)
    assert g.paged("/organization") == [{"id": "1"}]
    assert sleeps == [1, 2]


def test_mock_refuses_writes():
    mock = MockGraph(build(set()).snapshot())
    c = httpx.Client(transport=mock.transport())
    assert c.post("https://graph.microsoft.com/v1.0/applications", json={}).status_code == 405
    assert mock.writes
