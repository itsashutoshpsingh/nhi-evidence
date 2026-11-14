"""Mutation testing of the check code itself: does the fixture suite notice when a check is broken?

Each mutant changes one operator or statement in src/nhi_evidence/checks/*.py, finding.py or graph.py
(comparison flipped, `and`/`or` swapped, `not` dropped, `continue` removed, a number nudged by one, a
returned list emptied). The oracle reruns the seeded tenant, the clean tenant, each issue alone, the 42
fixture mutations and three small synthetic tenants in a fresh interpreter. A mutant is killed if any
result changes or the code crashes. Writes results/code_mutants.csv and results/code_mutants.json.
"""

import ast
import csv
import json
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = sorted((ROOT / "src/nhi_evidence/checks").glob("c*.py")) + [ROOT / "src/nhi_evidence/finding.py",
                                                                      ROOT / "src/nhi_evidence/graph.py"]
SWAP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
        ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}
ORACLE = r'''
import sys
sys.path[:0] = [sys.argv[1] + "/src", "{root}/fixtures", "{root}/experiments"]
from mutations import MUTATIONS, apply
from seeded import ISSUES, allowlist, build
from synth import generate
from nhi_evidence import config, engine
cfg = config.load()
def live(snap, allow=None):
    return {{f.key for f in engine.evaluate(snap, cfg, allow) if not f.suppressed}}
def exp(t, issues):
    out = set()
    for k in issues:
        for c, r, name, _ in ISSUES[k]:
            o = t.by_name.get("app:" + name) if c in ("C01", "C03", "C04", "C05", "C09", "C11") else None
            out.add((c, r, (o or t.by_name[name])["id"]))
    return out
t = build(set(ISSUES))
assert live(t.snapshot(), allowlist(t)) == exp(t, ISSUES), "seeded"
t = build(set())
assert live(t.snapshot(), allowlist(t)) == set(), "clean"
for k in ISSUES:
    t = build({{k}})
    assert live(t.snapshot(), allowlist(t)) == exp(t, {{k}}), "alone " + k
for m in MUTATIONS:
    s, e, a = apply(m[0])
    assert live(s, a) == e, "mutation " + m[0]
for seed in (1, 2, 3):
    t, e, _ = generate(100, seed)
    assert live(t.snapshot()) == e, "synthetic " + str(seed)
'''


def sites(tree):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                if type(op) in SWAP:
                    out.append((node, "compare", i, f"{type(op).__name__} -> {SWAP[type(op)].__name__}"))
        elif isinstance(node, ast.BoolOp):
            out.append((node, "boolop", 0, f"{type(node.op).__name__} -> {'Or' if isinstance(node.op, ast.And) else 'And'}"))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            out.append((node, "not", 0, "drop not"))
        elif isinstance(node, ast.Continue):
            out.append((node, "continue", 0, "continue -> pass"))
        elif isinstance(node, ast.Constant) and type(node.value) is int and node.value not in (0, 1):
            out.append((node, "const", 0, f"{node.value} -> {node.value + 1}"))
        elif isinstance(node, ast.Return) and isinstance(node.value, ast.Name) and node.value.id == "out":
            out.append((node, "return", 0, "return out -> return []"))
    return out


def mutate(src: str, index: int) -> tuple[str, int, str]:
    tree = ast.parse(src)
    node, kind, i, desc = sites(tree)[index]
    line = node.lineno
    if kind == "compare":
        node.ops[i] = SWAP[type(node.ops[i])]()
    elif kind == "boolop":
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "not":
        node.op = ast.UAdd()  # placeholder, replaced below
    elif kind == "continue":
        node.__class__ = ast.Pass
    elif kind == "const":
        node.value += 1
    elif kind == "return":
        node.value = ast.List(elts=[], ctx=ast.Load())

    class DropUAdd(ast.NodeTransformer):
        def visit_UnaryOp(self, n):
            self.generic_visit(n)
            return n.operand if isinstance(n.op, ast.UAdd) else n
    tree = ast.fix_missing_locations(DropUAdd().visit(tree))
    return ast.unparse(tree), line, desc


def run_one(job):
    path, index = job
    src = path.read_text()
    mutated, line, desc = mutate(src, index)
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(ROOT / "src", Path(tmp) / "src")
        (Path(tmp) / "src" / path.relative_to(ROOT / "src")).write_text(mutated)
        (Path(tmp) / "oracle.py").write_text(ORACLE.format(root=ROOT))
        try:
            r = subprocess.run([sys.executable, str(Path(tmp) / "oracle.py"), tmp], capture_output=True, text=True,
                               timeout=120)
            status = "survived" if r.returncode == 0 else "killed"
            why = "" if r.returncode == 0 else (r.stderr.strip().splitlines() or ["?"])[-1][:160]
        except subprocess.TimeoutExpired:
            status, why = "killed", "timeout"
    return {"file": str(path.relative_to(ROOT)), "line": line, "mutation": desc, "status": status, "reason": why}


def main():
    jobs = [(p, i) for p in TARGETS for i in range(len(sites(ast.parse(p.read_text()))))]
    with ThreadPoolExecutor(max_workers=2) as ex:  # two interpreters at a time: the machine is shared
        rows = list(ex.map(run_one, jobs))
    out = ROOT / "results"
    with open(out / "code_mutants.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    per = {}
    for r in rows:
        key = Path(r["file"]).stem
        p = per.setdefault(key, {"mutants": 0, "killed": 0})
        p["mutants"] += 1
        p["killed"] += r["status"] == "killed"
    summary = {"mutants": len(rows), "killed": sum(r["status"] == "killed" for r in rows), "per_file": per}
    (out / "code_mutants.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
