"""Seeded and clean tenant results, each issue alone, the 42 single-change mutations, and the
mutation x check matrix. All inputs are synthetic fixtures, not a live tenant.

Writes results/seeded_eval.json, results/mutations.csv, results/mutation_matrix.json,
results/seeded_report/ (findings.json, report.md, owasp_mapping.md) and results/paths_seeded.csv.
"""

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "fixtures")]
from mutations import MUTATIONS, apply  # noqa: E402
from seeded import CONTROLS, ISSUES, STATIC, allowlist, build  # noqa: E402

from nhi_evidence import config, engine, graph, report  # noqa: E402
from nhi_evidence.checks import CHECKS  # noqa: E402

RES = ROOT / "results"
CFG = config.load()
IDS = [c.META["id"] for c in CHECKS]


def keys(snap, allow):
    fs = engine.evaluate(snap, CFG, allow)
    return {f.key for f in fs if not f.suppressed}, fs


def expected(t, issues):
    out = {}
    for k in issues:
        for check, rule, name, _ in ISSUES[k]:
            obj = t.by_name.get(f"app:{name}") if check in ("C01", "C03", "C04", "C05", "C09", "C11") else None
            out[(check, rule, (obj or t.by_name[name])["id"])] = k
    return out


def main():
    RES.mkdir(exist_ok=True)
    t = build(set(ISSUES))
    snap = t.snapshot()
    got, findings = keys(snap, allowlist(t))
    exp = expected(t, ISSUES)
    per_issue = []
    for k, items in ISSUES.items():
        ks = [kk for kk, v in exp.items() if v == k]
        alone_t = build({k})
        alone, _ = keys(alone_t.snapshot(), allowlist(alone_t))
        per_issue.append({"issue": k, "static": k in STATIC, "checks": [c for c, *_ in items],
                          "description": items[0][3], "expected": len(ks), "found": sum(x in got for x in ks),
                          "alone_exact": alone == set(expected(alone_t, {k}))})
    ct = build(set())
    clean, clean_findings = keys(ct.snapshot(), allowlist(ct))
    sup = [f for f in findings if f.suppressed]
    static_keys = {k for k, v in exp.items() if v in STATIC}
    out = {
        "source": "synthetic seeded fixtures, not a live tenant",
        "seeded": {"issues": len(ISSUES), "static_issues": len(STATIC), "expected_findings": len(exp),
                   "found": len(got & set(exp)), "missed": len(set(exp) - got), "false": len(got - set(exp)),
                   "static_expected": len(static_keys), "static_found": len(got & static_keys),
                   "suppressed": len(sup),
                   "suppressed_by_reason": {r: sum(f.suppressed == r for f in sup) for r in sorted({f.suppressed for f in sup})},
                   "issues_found_alone_exactly": sum(p["alone_exact"] for p in per_issue)},
        "clean": {"findings": len(clean), "suppressed": sum(1 for f in clean_findings if f.suppressed),
                  "lookalike_controls": len(CONTROLS)},
        "per_issue": per_issue,
        "severity": {s: sum(f.severity == s for f in findings if not f.suppressed)
                     for s in ("critical", "high", "medium", "low", "info")},
        "checks": len(CHECKS),
    }
    # mutations
    base, _ = keys(ct.snapshot(), allowlist(ct))
    rows, matrix = [], []
    for mid, check, desc, _, _ in MUTATIONS:
        msnap, mexp, mallow = apply(mid)
        mgot, _ = keys(msnap, mallow)
        fired = sorted({k[0] for k in mgot - base})
        rows.append({"mutation": mid, "target_check": check, "description": desc, "expected": len(mexp),
                     "found": len(mgot & mexp), "missed": len(mexp - mgot), "false": len(mgot - mexp),
                     "checks_fired": " ".join(fired), "exact": mgot == mexp})
        matrix.append([sum(1 for k in mgot if k[0] == c) for c in IDS])
    with open(RES / "mutations.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    (RES / "mutation_matrix.json").write_text(json.dumps(
        {"checks": IDS, "mutations": [r["mutation"] for r in rows], "targets": [r["target_check"] for r in rows],
         "findings": matrix}, indent=1) + "\n")
    out["mutations"] = {"count": len(rows), "exact": sum(r["exact"] for r in rows),
                        "expected": sum(r["expected"] for r in rows), "found": sum(r["found"] for r in rows),
                        "missed": sum(r["missed"] for r in rows), "false": sum(r["false"] for r in rows),
                        "checks_covered": len({r["target_check"] for r in rows})}
    (RES / "seeded_eval.json").write_text(json.dumps(out, indent=1) + "\n")

    report.write(snap, findings, RES / "seeded_report")
    g = graph.build(snap, CFG)
    with open(RES / "paths_seeded.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["target", "source", "hops", "path", "closing_control"])
        for sp_id, (_, found) in graph.paths(snap, CFG, g).items():
            for p in found:
                d = graph.describe(g, p, snap)
                w.writerow([snap.sp_by_id[sp_id]["displayName"], d["source"], d["hops"],
                            " -> ".join([d["source"]] + [s["to"] for s in d["steps"]]), d["closing_control"]])
    print(json.dumps({k: out[k] for k in ("seeded", "clean", "mutations")}, indent=1))


if __name__ == "__main__":
    main()
