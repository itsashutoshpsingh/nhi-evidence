"""Precision, recall and run time on synthetic tenants of 100 to 100,000 service principals.

Each (size, seed) runs in its own interpreter so peak memory is measured per run. Synthetic data:
planted issues and look-alikes at known rates (experiments/synth.py), not a live tenant.
Writes results/scale_runs.csv (one row per run and check), results/scale_planted.csv and
results/synthetic_snapshots.sha256. Run: python experiments/scale.py
"""

import csv
import hashlib
import json
import resource
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "experiments")]
PLAN = [(100, s) for s in range(1, 6)] + [(1000, s) for s in range(1, 6)] + [(10000, s) for s in range(1, 6)] \
    + [(100000, s) for s in range(1, 4)]


def one(n: int, seed: int) -> dict:
    from synth import generate

    from nhi_evidence import config, engine
    from nhi_evidence.checks import CHECKS
    t0 = time.perf_counter()
    t, expected, log = generate(n, seed)
    snap = t.snapshot()
    gen = time.perf_counter() - t0
    timings = {}
    t1 = time.perf_counter()
    findings = engine.evaluate(snap, config.load(), timings=timings)
    total = time.perf_counter() - t1
    got = {f.key for f in findings if not f.suppressed}
    digest = hashlib.sha256()
    for name in sorted(snap.data):
        digest.update(json.dumps(snap.data[name], sort_keys=True).encode())
    per = {}
    for c in CHECKS:
        cid = c.META["id"]
        e = {k for k in expected if k[0] == cid}
        g = {k for k in got if k[0] == cid}
        per[cid] = {"tp": len(e & g), "fp": len(g - e), "fn": len(e - g), "seconds": timings[cid]}
    return {"n": n, "seed": seed, "service_principals": len(snap.servicePrincipals),
            "applications": len(snap.applications), "users": len(snap.users),
            "app_role_assignments": len(snap.appRoleAssignments), "grants": len(snap.oauth2PermissionGrants),
            "role_assignments": len(snap.roleAssignments), "sign_ins": len(snap.signIns or []),
            "planted": len(expected), "found": len(got), "suppressed": sum(1 for f in findings if f.suppressed),
            "generate_seconds": gen, "evaluate_seconds": total,
            "peak_rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
            "sha256": digest.hexdigest(), "per_check": per,
            "variants": Counter(f"{x['check']}|{x['rule']}" for x in log)}


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--one":
        print(json.dumps(one(int(sys.argv[2]), int(sys.argv[3]))))
        return
    runs = []
    for n, seed in PLAN:
        r = subprocess.run([sys.executable, __file__, "--one", str(n), str(seed)], capture_output=True, text=True,
                           check=True)
        runs.append(json.loads(r.stdout))
        print(n, seed, runs[-1]["planted"], runs[-1]["found"], f"{runs[-1]['evaluate_seconds']:.2f}s", flush=True)
    res = ROOT / "results"
    with open(res / "scale_runs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["n", "seed", "check", "tp", "fp", "fn", "check_seconds", "service_principals", "applications",
                    "users", "app_role_assignments", "grants", "role_assignments", "sign_ins", "planted", "found",
                    "suppressed", "generate_seconds", "evaluate_seconds", "peak_rss_mb"])
        for r in runs:
            for cid, p in r["per_check"].items():
                w.writerow([r["n"], r["seed"], cid, p["tp"], p["fp"], p["fn"], f"{p['seconds']:.6f}",
                            r["service_principals"], r["applications"], r["users"], r["app_role_assignments"],
                            r["grants"], r["role_assignments"], r["sign_ins"], r["planted"], r["found"],
                            r["suppressed"], f"{r['generate_seconds']:.4f}", f"{r['evaluate_seconds']:.4f}",
                            f"{r['peak_rss_mb']:.1f}"])
    pooled = Counter()
    for r in runs:
        pooled.update(r["variants"])
    with open(res / "scale_planted.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["check", "rule", "planted_all_runs"])
        for k, v in sorted(pooled.items()):
            w.writerow([*k.split("|"), v])
    (res / "synthetic_snapshots.sha256").write_text(
        "".join(f"{r['sha256']}  synthetic n={r['n']} seed={r['seed']} (regenerate: experiments/synth.py)\n"
                for r in runs))


if __name__ == "__main__":
    main()
