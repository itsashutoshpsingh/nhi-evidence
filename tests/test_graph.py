"""Credential-control graph: each edge kind, and the exclusions that keep it honest."""

from seeded import build

from nhi_evidence import config, graph

CFG = config.load()


def paths_for(t):
    snap = t.snapshot()
    return {snap.sp_by_id[k]["displayName"]: v for k, v in graph.paths(snap, CFG).items()}


def sources(t, target):
    snap = t.snapshot()
    g = graph.build(snap, CFG)
    _, found = graph.paths(snap, CFG, g)[t.by_name[target]["id"]]
    return sorted(graph.describe(g, p, snap)["source"] for p in found)


def test_owner_path():
    t = build({"S12"})
    assert sources(t, "sharepoint-migrator") == ["user Bob Builder"]


def test_disabled_owner_is_not_a_path():
    t = build(set())
    t._access(t.by_name["invoice-sync"], ["Files.ReadWrite.All"], None, (), None)
    t.d["applicationOwners"][t.by_name["app:invoice-sync"]["id"]] = [t.ref(t.by_name["dave"])]
    assert "invoice-sync" not in paths_for(t)


def test_admins_are_not_sources():
    t = build({"S05"})  # doc-archiver privileged; reachable only by GA and app admins
    assert "doc-archiver" not in paths_for(t)


def test_sp_owner_needs_ownedby_permission():
    t = build(set())
    app = t.by_name["app:invoice-sync"]
    t._access(t.by_name["invoice-sync"], ["Files.ReadWrite.All"], None, (), None)
    t.d["applicationOwners"][app["id"]] = [t.ref(t.by_name["teams-notifier"])]
    assert "invoice-sync" not in paths_for(t)  # owner SP has no permission to edit apps
    t._access(t.by_name["teams-notifier"], ["Application.ReadWrite.OwnedBy"], None, (), None)
    # teams-notifier is now privileged itself (OwnedBy is on the data list), so the non-privileged source
    # is its owner bob: bob -> teams-notifier app -> its SP -> invoice-sync app -> invoice-sync SP
    snap = t.snapshot()
    g = graph.build(snap, CFG)
    _, found = graph.paths(snap, CFG, g)[t.by_name["invoice-sync"]["id"]]
    d = graph.describe(g, found[0], snap)
    assert d["source"] == "user Bob Builder" and d["hops"] == 4
    assert d["steps"][2]["kind"] == "sp_owns"


def test_scoped_role_reaches_only_its_app():
    t = build({"S05"})
    t.role(t.by_name["carol"], "Cloud Application Administrator", "/" + t.by_name["app:hr-portal"]["id"])
    # carol now holds a privileged role, so she is not a source anywhere; and her scope is hr-portal only
    assert "doc-archiver" not in paths_for(t)


def test_group_owner_path_and_closing_control():
    t = build({"S05"})
    t.d["groupOwners"][t.by_name["App Admins"]["id"]].append(t.ref(t.by_name["carol"]))
    snap = t.snapshot()
    g = graph.build(snap, CFG)
    _, found = graph.paths(snap, CFG, g)[t.by_name["doc-archiver"]["id"]]
    d = graph.describe(g, found[0], snap)
    assert d["source"] == "user Carol Clark" and d["steps"][0]["kind"] == "owns_group"
    assert "role-assignable group" in d["closing_control"]
    assert [s["to"] for s in d["steps"]][-2:] == ["every application", "sp doc-archiver"]
