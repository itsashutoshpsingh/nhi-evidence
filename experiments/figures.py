"""All charts in docs/img, drawn from the committed results files only. Run: python experiments/figures.py"""

import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402
from matplotlib.patches import FancyBboxPatch, Patch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "fixtures")]
RES, IMG = ROOT / "results", ROOT / "docs" / "img"
# Portfolio chart style (BUILD_RULES.md, "Charts"): solid colours, Carlito, capitalised labels.
BG, TEXT, MUTED, GRID = "#0C1421", "#FFFFFF", "#C9D4E2", "#1F2E45"
BLUE, GREEN, RED, YELLOW, WHITE = "#3B82F6", "#22C55E", "#EF4444", "#FACC15", "#FFFFFF"
FOOT = "Synthetic Graph-shaped fixtures, not a live tenant."
plt.rcParams.update({"figure.facecolor": BG, "axes.facecolor": BG, "savefig.facecolor": BG, "text.color": TEXT,
                     "axes.labelcolor": TEXT, "xtick.color": MUTED, "ytick.color": MUTED, "axes.edgecolor": GRID,
                     "grid.color": GRID, "font.family": "Carlito", "font.size": 11, "axes.titlesize": 15,
                     "axes.titleweight": "bold", "figure.titlesize": 15, "figure.titleweight": "bold",
                     "axes.labelsize": 12, "xtick.labelsize": 11, "ytick.labelsize": 11, "legend.fontsize": 11,
                     "legend.labelcolor": TEXT})


def save(fig, name, foot=FOOT):
    fig.text(0.01, -0.04, foot, color=MUTED, fontsize=11)
    fig.savefig(IMG / name, dpi=200, bbox_inches="tight")
    plt.close(fig)


def grid(ax, axis="y"):
    ax.grid(axis=axis, linewidth=0.6)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)


def labels(ax, bars, fmt="{:.0f}", pad=0.3):
    for b in bars:
        h = b.get_height()
        ax.text(b.get_x() + b.get_width() / 2, h + pad, fmt.format(h), ha="center", va="bottom", color=TEXT,
                fontsize=11)


def hero():
    d = json.loads((RES / "seeded_eval.json").read_text())
    exp = json.loads((ROOT / "fixtures/seeded_tenant/expected_findings.json").read_text())
    checks = [f"C{i:02d}" for i in range(1, 15)]
    found = {c: 0 for c in checks}
    for e in exp:
        found[e["check_id"]] += 1  # the seeded run found every expected finding (seeded_eval.json)
    assert d["seeded"]["found"] == d["seeded"]["expected_findings"] and d["seeded"]["false"] == 0
    fig, ax = plt.subplots(figsize=(11, 4.4))
    x = range(len(checks))
    b1 = ax.bar([i - 0.2 for i in x], [found[c] for c in checks], 0.4, color=BLUE, label="Planted")
    b2 = ax.bar([i + 0.2 for i in x], [found[c] for c in checks], 0.4, color=GREEN, label="Found")
    false_patch = Patch(color=RED, label=f"False findings: {d['seeded']['false']}")
    labels(ax, b1, pad=0.03)
    labels(ax, b2, pad=0.03)
    ax.set_xticks(list(x), checks)
    ax.set_ylim(0, 2.8)
    ax.set_ylabel("Findings (count)")
    ax.set_xlabel("Check")
    ax.set_title(f"Seeded tenant: {d['seeded']['found']} of {d['seeded']['expected_findings']} planted findings found, "
                 f"{d['seeded']['false']} false, {d['seeded']['suppressed']} suppressed by the allowlist")
    ax.legend(handles=[b1, b2, false_patch], frameon=False, ncol=3, loc="upper left")
    grid(ax)
    save(fig, "hero_seeded.png")


def mutation_matrix():
    m = json.loads((RES / "mutation_matrix.json").read_text())
    data, checks, muts, targets = m["findings"], m["checks"], m["mutations"], m["targets"]
    fig, ax = plt.subplots(figsize=(9, 13))
    rgb = matplotlib.colors.to_rgb
    img = [[rgb(BG) if not v else rgb(GREEN) if checks[j] == targets[i] else rgb(BLUE) for j, v in enumerate(row)]
           for i, row in enumerate(data)]
    ax.imshow(img, aspect="auto")
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            if v:
                own = checks[j] == targets[i]
                ax.text(j, i, str(v), ha="center", va="center", color=BG, fontsize=11,
                        fontweight="bold" if own else "normal")
    ax.set_xticks(range(len(checks)), checks)
    ax.set_yticks(range(len(muts)), muts, fontsize=11)
    ax.set_xlabel("Check that fired (number of findings)")
    ax.set_ylabel("Mutation of the clean tenant")
    ax.set_title(f"Every one of {len(muts)} single changes fires its own check (green);\n"
                 "blue cells are findings the change also causes, all of them expected")
    for s in ax.spines.values():
        s.set_visible(False)
    save(fig, "mutation_matrix.png")


def code_mutants():
    final = json.loads((RES / "code_mutants.json").read_text())
    first = json.loads((RES / "code_mutants_run1.json").read_text())
    names = sorted(final["per_file"])
    fig, ax = plt.subplots(figsize=(13, 4.8))
    k = [final["per_file"][n]["killed"] for n in names]
    s = [final["per_file"][n]["mutants"] - final["per_file"][n]["killed"] for n in names]
    short = [n.split("_")[0].upper() if n.startswith("c") and n[1:3].isdigit() else n + ".py" for n in names]
    b = ax.bar(short, k, color=GREEN, label="Caught (killed)")
    ax.bar(short, s, bottom=k, color=RED, label="Not caught (survived)")
    for bar, kk, ss in zip(b, k, s, strict=True):
        ax.text(bar.get_x() + bar.get_width() / 2, kk + ss + 0.5, f"{kk}/{kk + ss}", ha="center", color=TEXT, fontsize=11)
    ax.set_ylabel("Code mutants (count)")
    ax.set_xlabel("Check module, or shared file")
    plt.setp(ax.get_xticklabels(), fontsize=11, rotation=30, ha="right")
    pct = 100 * final["killed"] / final["mutants"]
    pct1 = 100 * first["killed"] / first["mutants"]
    ax.set_title(f"The tests catch {final['killed']} of {final['mutants']} code mutants ({pct:.1f}%); "
                 f"the first run caught {first['killed']} of {first['mutants']} ({pct1:.1f}%)")
    ax.legend(frameon=False)
    grid(ax)
    save(fig, "code_mutants.png")


def scale_rows():
    with open(RES / "scale_runs.csv") as f:
        return list(csv.DictReader(f))


def wilson_low(k, n, z=1.96):
    if n == 0:
        return float("nan")
    p = k / n
    return (p + z * z / (2 * n) - z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / (1 + z * z / n)


def scale_runtime():
    rows = scale_rows()
    per_run = {}
    for r in rows:
        per_run[(int(r["n"]), r["seed"])] = (int(r["service_principals"]), float(r["evaluate_seconds"]),
                                            float(r["peak_rss_mb"]))
    by_n = defaultdict(list)
    for (n, _), v in per_run.items():
        by_n[n].append(v)
    ns = sorted(by_n)
    mean = [sum(v[1] for v in by_n[n]) / len(by_n[n]) for n in ns]
    lo = [min(v[1] for v in by_n[n]) for n in ns]
    hi = [max(v[1] for v in by_n[n]) for n in ns]
    rss = [max(v[2] for v in by_n[n]) for n in ns]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(15, 5))
    a1.errorbar(ns, mean, yerr=[[m - low for m, low in zip(mean, lo, strict=True)],
                                [h - m for m, h in zip(mean, hi, strict=True)]], color=BLUE, marker="o", capsize=3)
    for n, m in zip(ns, mean, strict=True):
        a1.annotate(f"{m:.2f} s" if m >= 0.01 else f"{m * 1000:.1f} ms", (n, m), textcoords="offset points",
                    xytext=(0, 8), ha="center", color=TEXT, fontsize=11)
    a1.set_xscale("log")
    a1.set_yscale("log")
    a1.set_xlabel("Service principals in the tenant (count, log)")
    a1.set_ylabel("All 14 checks, wall time (s, log)")
    a1.set_title("Time grows about linearly with size")
    grid(a1, "both")
    big = max(ns)
    per = defaultdict(list)
    for r in rows:
        if int(r["n"]) == big:
            per[r["check"]].append(float(r["check_seconds"]))
    cs = sorted(per)
    vals = [sum(per[c]) / len(per[c]) for c in cs]
    b = a2.bar(cs, vals, color=BLUE)
    labels(a2, b, "{:.2f}", pad=0.02)
    a2.set_xlabel("Check")
    a2.set_ylabel(f"Mean time at {big:,} service principals (s)")
    a2.set_title(f"Per check at {big:,}: the graph (C13) costs most;\npeak memory {max(rss):.0f} MB")
    plt.setp(a2.get_xticklabels(), rotation=45, fontsize=11)
    grid(a2)
    fig.suptitle(f"All checks finish in {mean[-1]:.1f} s on a {big:,}-identity synthetic tenant", y=1.1)
    save(fig, "scale_runtime.png", FOOT + f" Mean of {len(by_n[big])} to {len(by_n[ns[0]])} seeds; bars show min to max.")


def scale_recall():
    rows = scale_rows()
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    for r in rows:
        tp[r["check"]] += int(r["tp"])
        fp[r["check"]] += int(r["fp"])
        fn[r["check"]] += int(r["fn"])
    cs = sorted(tp)
    fig, ax = plt.subplots(figsize=(12, 4.6))
    planted = [tp[c] + fn[c] for c in cs]
    b = ax.bar(cs, planted, color=BLUE, label="Planted (pooled over all runs)")
    labels(ax, b, pad=30)
    lows = [100 * wilson_low(tp[c], tp[c] + fn[c]) for c in cs]
    ax2 = ax.twinx()
    ax2.plot(cs, lows, color=GREEN, marker="o", label="Recall, 95% lower bound (Wilson)")
    ax2.set_ylim(90, 100.5)
    ax.set_ylim(0, max(planted) * 1.55)
    ax2.set_ylabel("Recall lower bound (%)", color=GREEN)
    ax2.tick_params(colors=GREEN)
    ax.set_ylabel("Planted findings (count)")
    ax.set_xlabel("Check")
    runs = len({(r["n"], r["seed"]) for r in rows})
    ax.set_title(f"Over {runs} synthetic tenants, {sum(fn.values())} of {sum(planted):,} planted findings were missed "
                 f"and {sum(fp.values())} false")
    h1, l1 = ax.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, frameon=False, loc="upper left", bbox_to_anchor=(0, 0.86))
    grid(ax)
    ax2.spines["top"].set_visible(False)
    save(fig, "scale_recall.png", FOOT + " The generator and the checks share an author: this tests consistency.")


def ablation():
    with open(RES / "ablation.csv") as f:
        rows = list(csv.DictReader(f))
    agg = defaultdict(lambda: [0, 0, 0])
    for r in rows:
        a = agg[r["check"]]
        a[0] += int(r["naive_false"])
        a[1] += int(r["naive_missed"])
        a[2] += int(r["refined_false"]) + int(r["refined_missed"])
    cs = sorted(agg)
    fig, ax = plt.subplots(figsize=(14, 4.8))
    x = range(len(cs))
    b1 = ax.bar([i - 0.27 for i in x], [agg[c][0] for c in cs], 0.27, color=RED, label="One-line rule: false")
    b2 = ax.bar(list(x), [agg[c][1] for c in cs], 0.27, color=YELLOW, label="One-line rule: missed")
    b3 = ax.bar([i + 0.27 for i in x], [agg[c][2] for c in cs], 0.27, color=GREEN, label="This tool: false + missed")
    for bs in (b1, b2, b3):
        labels(ax, bs, pad=1)
    ax.set_xticks(list(x), cs)
    ax.set_ylabel("Findings (count, 7 tenants)")
    ax.set_xlabel("Check")
    tf = sum(v[0] for v in agg.values())
    tm = sum(v[1] for v in agg.values())
    ax.set_title(f"One-line versions of the checks: {tf:,} false and {tm} missed findings; the refined checks: "
                 f"{sum(v[2] for v in agg.values())}")
    ax.legend(frameon=False)
    grid(ax)
    save(fig, "ablation.png", FOOT + " Seeded and clean fixtures plus five 1,000-identity tenants.")


def collect_cost():
    with open(RES / "collect_cost.csv") as f:
        rows = [r for r in csv.DictReader(f) if r["throttle_every"] == "0"]
    thr = {r["n"]: r for r in csv.DictReader(open(RES / "collect_cost.csv")) if r["throttle_every"] != "0"}
    ns = [r["n"] for r in rows]
    fig, ax = plt.subplots(figsize=(10, 5))
    per = [int(r["per_object_requests"]) for r in rows]
    lst = [int(r["list_requests"]) for r in rows]
    x = range(len(ns))
    b = ax.bar([i - 0.2 for i in x], per, 0.4, color=BLUE, label="Per-object GETs (owners, credentials, assignments)")
    b2 = ax.bar([i + 0.2 for i in x], lst, 0.4, color=GREEN, label="List GETs (all pages)")
    for bar, r in zip(b, rows, strict=True):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.15,
                f"{int(bar.get_height()):,}\n+{int(thr[r['n']]['retries_429']):,} retries", ha="center", color=TEXT,
                fontsize=11)
    for bar in b2:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.15, f"{int(bar.get_height()):,}",
                ha="center", color=TEXT, fontsize=11)
    ax.set_xticks(list(x), [f"{int(n):,}" for n in ns])
    ax.set_yscale("log")
    ax.set_ylim(5, max(per) * 8)
    ax.set_xlabel("Service principals in the tenant (count)")
    ax.set_ylabel("GET requests (count, log)")
    ratio = (per[-1] + lst[-1]) / int(ns[-1])
    ax.set_title(f"Collection needs about {ratio:.1f} GET requests per service principal")
    ax.legend(frameon=False, loc="upper left")
    grid(ax)
    save(fig, "collect_cost.png", "Measured against the in-process Graph mock; retries: one 429 every 50 requests. "
         "Network time not measured.")


def owasp():
    rows = []
    for line in (RES / "seeded_report/owasp_mapping.md").read_text().splitlines():
        if not line.startswith("| ["):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append((cells[0].split("]")[0].lstrip("["), cells[1], int(cells[2])))
    fig, ax = plt.subplots(figsize=(11, 5))
    names = [r[0] for r in rows]
    nchecks = [0 if r[1].startswith("none") else r[1].count(";") + 1 for r in rows]
    b = ax.barh(names, nchecks, color=[BLUE if n else RED for n in nchecks])
    for bar, n, r in zip(b, nchecks, rows, strict=True):
        ax.text(bar.get_width() + 0.05, bar.get_y() + bar.get_height() / 2,
                f"{n} check{'s' * (n > 1)}, {r[2]} seeded finding{'s' * (r[2] != 1)}" if n else "Not covered: needs a secret scanner",
                va="center", color=TEXT, fontsize=11)
    ax.invert_yaxis()
    ax.set_xlabel("Checks mapped (count)")
    ax.set_xlim(0, 5.5)
    ax.set_title("Nine of the ten OWASP NHI risks have at least one check; NHI2 is outside Graph's view")
    grid(ax, "x")
    save(fig, "owasp_coverage.png")


def paths_diagram():
    from mutations import S
    from seeded import ISSUES, build

    from nhi_evidence import config, graph
    t = build(set(ISSUES))
    t.d["groupOwners"][S(t, "App Admins")["id"]].append(t.ref(S(t, "carol")))  # mutation M13b on the seeded tenant
    snap = t.snapshot()
    cfg = config.load()
    g = graph.build(snap, cfg)
    sub = nx.DiGraph()
    for sp_id, (_, found) in graph.paths(snap, cfg, g).items():
        for p in found:
            nx.add_path(sub, p)
    def name(n):
        k, _, oid = n.partition(":")
        if n == graph.ALL:
            return "Every\napplication"
        if k == "role":
            return snap.role_def_by_id[oid]["displayName"].replace(" Administrator", "\nAdministrator")
        obj = {"user": snap.user_by_id, "sp": snap.sp_by_id, "app": snap.app_by_id, "group": snap.group_by_id}[k][oid]
        kind = {"app": "App reg", "sp": "Service principal", "user": "User", "group": "Group"}[k]
        return f"{kind}\n{obj['displayName']}"
    depth = {}
    for n in nx.topological_sort(sub):
        preds = list(sub.predecessors(n))
        depth[n] = 0 if not preds else max(depth[p] for p in preds) + 1
    sinks = {n for n in sub if sub.out_degree(n) == 0}
    top = max(depth.values())
    for n in sinks:
        depth[n] = top
    cols = defaultdict(list)
    for n, dpt in depth.items():
        cols[dpt].append(n)
    pos = {n: (dpt * 2.2, -i * 1.3) for dpt, ns in cols.items() for i, n in enumerate(sorted(ns))}
    fig, ax = plt.subplots(figsize=(16, 7))
    for u, v in sub.edges:
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        ax.annotate("", xy=(x1 - 0.55, y1), xytext=(x0 + 0.55, y0),
                    arrowprops={"arrowstyle": "-|>", "color": MUTED, "lw": 1})
    for n, (x, y) in pos.items():
        k = n.split(":")[0]
        color = {"user": YELLOW, "group": YELLOW, "role": BLUE, "app": WHITE, "sp": RED if n in sinks else WHITE}.get(
            k, BLUE)
        ax.add_patch(FancyBboxPatch((x - 0.55, y - 0.35), 1.1, 0.7, boxstyle="round,pad=0.02", fc=BG, ec=color, lw=1.5))
        ax.text(x, y, name(n), ha="center", va="center", fontsize=11, color=TEXT)
    ax.set_xlim(-0.8, top * 2.2 + 0.8)
    ax.set_ylim(min(p[1] for p in pos.values()) - 0.8, 0.8)
    ax.axis("off")
    ax.set_title("Who can add a credential to a privileged service principal (red):\nseeded tenant plus one group-owner "
                 "change")
    save(fig, "credential_paths.png", FOOT + " Yellow: people and groups; blue: roles; white: apps along the way.")


def pipeline():
    fig, ax = plt.subplots(figsize=(16, 4.3))
    steps = [("Microsoft Graph\n(GET only, v1.0 + beta)", BLUE), ("Collect\npaging, Retry-After,\nwrite-scope refusal", BLUE),
             ("Snapshot\n(Graph-shaped JSON)", WHITE), ("14 checks\n+ credential graph", GREEN),
             ("Allowlist\n(first-party, reviewed)", YELLOW), ("findings.json\nreport.md\nOWASP mapping", BLUE)]
    for i, (s, c) in enumerate(steps):
        x = i * 2.0
        ax.add_patch(FancyBboxPatch((x, 0), 1.6, 1.0, boxstyle="round,pad=0.04", fc=BG, ec=c, lw=1.6))
        ax.text(x + 0.8, 0.5, s, ha="center", va="center", fontsize=11, color=TEXT)
        if i:
            ax.annotate("", xy=(x - 0.05, 0.5), xytext=(x - 0.35, 0.5), arrowprops={"arrowstyle": "-|>", "color": MUTED})
    ax.text(4.8, -0.45, "Fixtures (seeded, clean, 51 mutations, synthetic 100 to 100,000) enter here, in place of a "
            "live tenant", ha="center", color=MUTED, fontsize=11)
    ax.annotate("", xy=(4.8, -0.02), xytext=(4.8, -0.3), arrowprops={"arrowstyle": "-|>", "color": MUTED})
    ax.text(5.8, 1.35, "Diff: two snapshots -> new privileged grants, new credentials, removed owners", ha="center",
            color=MUTED, fontsize=11)
    ax.set_xlim(-0.2, 11.8)
    ax.set_ylim(-0.7, 1.6)
    ax.axis("off")
    ax.set_title("Read-only collection feeds 14 checks and an evidence report")
    save(fig, "pipeline.png", "")


def main():
    IMG.mkdir(parents=True, exist_ok=True)
    for f in (hero, mutation_matrix, code_mutants, scale_runtime, scale_recall, ablation, collect_cost, owasp,
              paths_diagram, pipeline):
        f()
        print("drew", f.__name__)


if __name__ == "__main__":
    main()
