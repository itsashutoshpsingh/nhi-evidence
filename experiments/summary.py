"""results/summary.json (read by the portfolio) and results/tables.md, from the committed results only."""

import csv
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "results"


def rows(name):
    with open(RES / name) as f:
        return list(csv.DictReader(f))


def main():
    seeded = json.loads((RES / "seeded_eval.json").read_text())
    s, m = seeded["seeded"], seeded["mutations"]
    cm = json.loads((RES / "code_mutants.json").read_text())
    cm1 = json.loads((RES / "code_mutants_run1.json").read_text())
    scale = rows("scale_runs.csv")
    planted = sum(int(r["tp"]) + int(r["fn"]) for r in scale)
    found = sum(int(r["tp"]) for r in scale)
    runs = {(r["n"], r["seed"]): r for r in scale}
    biggest = max(int(r["n"]) for r in scale)
    big = [float(r["evaluate_seconds"]) for (n, _), r in runs.items() if int(n) == biggest]
    big_mean = sum(big) / len(big)
    peak = max(float(r["peak_rss_mb"]) for r in scale)
    cost = [r for r in rows("collect_cost.csv") if r["throttle_every"] == "0"]
    per_sp = int(cost[-1]["successful_gets"]) / int(cost[-1]["n"])
    abl = rows("ablation.csv")
    naive_false = sum(int(r["naive_false"]) for r in abl)
    naive_missed = sum(int(r["naive_missed"]) for r in abl)
    refined_err = sum(int(r["refined_false"]) + int(r["refined_missed"]) for r in abl)
    lab = json.loads((RES / "lab_plan_replay.json").read_text())
    kill = 100 * cm["killed"] / cm["mutants"]
    kill1 = 100 * cm1["killed"] / cm1["mutants"]
    summary = {
        "project": "nhi-evidence",
        "headline": (f"On a seeded test tenant built from fixtures shaped like Microsoft Graph data (not a live tenant), "
                     f"14 read only checks found all {s['found']} planted findings from {s['issues']} misconfigurations "
                     f"with {s['false']} false findings, each mapped to the OWASP NHI Top 10."),
        "metrics": [
            {"label": "seeded findings found", "value": f"{s['found']} of {s['expected_findings']}"},
            {"label": "false findings on the seeded tenant", "value": str(s["false"])},
            {"label": "single-change mutations caught exactly", "value": f"{m['exact']} of {m['count']}"},
            {"label": "code mutants caught by the tests", "value": f"{kill:.1f}%"},
            {"label": "synthetic planted findings found", "value": f"{found:,} of {planted:,}"},
            {"label": f"run time at {biggest:,} identities", "value": f"{big_mean:.1f} s"},
            {"label": "graph requests per service principal", "value": f"{per_sp:.1f}"},
            {"label": "false findings from one-line rules", "value": f"{naive_false:,}"},
            {"label": "owasp nhi risks with a check", "value": "9 of 10"},
            {"label": "checks", "value": "14"},
        ],
        "charts": [
            {"path": "docs/img/hero_seeded.png", "label": "Seeded tenant",
             "alt": "Planted and found findings per check on the seeded fixture tenant, all equal, no false findings"},
            {"path": "docs/img/mutation_matrix.png", "label": "Mutation matrix",
             "alt": "Heat map of 51 single-change mutations against the 14 checks; each fires its own check"},
            {"path": "docs/img/code_mutants.png", "label": "Code mutants",
             "alt": "Code mutants caught and not caught by the test suite, per check module"},
            {"path": "docs/img/scale_runtime.png", "label": "Run time",
             "alt": "Run time of all checks against tenant size from 100 to 100,000, and per check at 100,000"},
            {"path": "docs/img/scale_recall.png", "label": "Recall at scale",
             "alt": "Planted findings per check over 18 synthetic tenants with the Wilson lower bound of recall"},
            {"path": "docs/img/ablation.png", "label": "One-line rules",
             "alt": "False and missed findings of one-line versions of each check compared with the refined checks"},
            {"path": "docs/img/collect_cost.png", "label": "Collection cost",
             "alt": "Graph GET requests the collector sends for 100, 1,000 and 10,000 service principals"},
            {"path": "docs/img/credential_paths.png", "label": "Credential paths",
             "alt": "Diagram of who can add a credential to privileged service principals in the seeded tenant"},
            {"path": "docs/img/owasp_coverage.png", "label": "OWASP coverage",
             "alt": "Number of checks mapped to each OWASP NHI Top 10 risk"},
            {"path": "docs/img/pipeline.png", "label": "Pipeline",
             "alt": "Pipeline from read-only Graph collection to snapshot, checks, allowlist and report"},
        ],
        "viz": [
            {"title": f"All {s['found']} seeded findings found, none false, on the fixture tenant", "unit": "count",
             "bars": [{"label": "found", "value": s["found"], "tone": "good"},
                      {"label": "missed", "value": s["missed"], "tone": "bad"},
                      {"label": "false", "value": s["false"], "tone": "bad"},
                      {"label": "suppressed by allowlist", "value": s["suppressed"], "tone": "neutral"}]},
            {"title": f"The tests catch {kill:.1f}% of deliberately broken check code", "unit": "%",
             "bars": [{"label": "first run", "value": round(kill1, 1), "tone": "warn"},
                      {"label": "final run", "value": round(kill, 1), "tone": "good"}]},
            {"title": "One-line rules trip on look-alike controls; the refined checks do not", "unit": "count",
             "bars": [{"label": "one-line false", "value": naive_false, "tone": "bad"},
                      {"label": "one-line missed", "value": naive_missed, "tone": "warn"},
                      {"label": "refined errors", "value": refined_err, "tone": "good"}]},
        ],
    }
    (RES / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")

    by_check = defaultdict(lambda: [0, 0, 0])
    for r in scale:
        x = by_check[r["check"]]
        x[0] += int(r["tp"])
        x[1] += int(r["fp"])
        x[2] += int(r["fn"])
    by_n = defaultdict(list)
    for r in runs.values():
        by_n[int(r["n"])].append(r)
    t = ["# Result tables", "", "Generated by experiments/summary.py. All inputs are synthetic Graph-shaped fixtures, "
         "not a live tenant.", "", "## Seeded tenant, per issue", "",
         "| Issue | Check(s) | Planted misconfiguration | Static | Expected | Found | Alone, exact |",
         "|---|---|---|---|---|---|---|"]
    for p in seeded["per_issue"]:
        t.append(f"| {p['issue']} | {', '.join(p['checks'])} | {p['description']} | {'yes' if p['static'] else 'no'} | "
                 f"{p['expected']} | {p['found']} | {'yes' if p['alone_exact'] else 'no'} |")
    t += ["", "## Synthetic tenants", "", "| Service principals | Runs | Planted (mean) | Found | False | "
          "Check time (mean s) | Peak memory (MB) |", "|---|---|---|---|---|---|---|"]
    for n in sorted(by_n):
        rs = by_n[n]
        t.append(f"| {n:,} | {len(rs)} | {sum(int(r['planted']) for r in rs) / len(rs):,.0f} | "
                 f"{sum(int(r['found']) for r in rs):,} of {sum(int(r['planted']) for r in rs):,} | "
                 f"{sum(int(x['fp']) for x in scale if int(x['n']) == n)} | "
                 f"{sum(float(r['evaluate_seconds']) for r in rs) / len(rs):.3f} | "
                 f"{max(float(r['peak_rss_mb']) for r in rs):.0f} |")
    t += ["", "## Per check, pooled over all synthetic runs", "", "| Check | Planted | Found | False | Missed |",
          "|---|---|---|---|---|"]
    t += [f"| {c} | {v[0] + v[2]:,} | {v[0]:,} | {v[1]} | {v[2]} |" for c, v in sorted(by_check.items())]
    t += ["", "## Collection cost (Graph mock)", "", "| Service principals | GETs | per object | lists | "
          "429 retries at 1 in 50 | in-process s |", "|---|---|---|---|---|---|"]
    thr = {r["n"]: r for r in rows("collect_cost.csv") if r["throttle_every"] != "0"}
    t += [f"| {int(r['n']):,} | {int(r['successful_gets']):,} | {int(r['per_object_requests']):,} | "
          f"{r['list_requests']} | {thr[r['n']]['retries_429']} | {r['in_process_seconds']} |" for r in cost]
    t += ["", f"Lab seeding plan replayed against a simulated Graph: {lab['steps']} steps, "
          f"{len(lab['findings'])} findings (results/lab_plan_replay.json).", "",
          f"Peak memory over all synthetic runs: {peak:.0f} MB."]
    (RES / "tables.md").write_text("\n".join(t) + "\n")
    print(json.dumps(summary["metrics"], indent=1))


if __name__ == "__main__":
    main()
