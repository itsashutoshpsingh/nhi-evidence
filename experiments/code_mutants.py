"""Mutation testing of the check code itself: does the fixture suite notice when a check is broken?

Each mutant changes one operator or statement in src/nhi_evidence/checks/*.py, finding.py or graph.py
(comparison flipped, `and`/`or` swapped, `not` dropped, `continue` removed, a number nudged by one, a
returned list emptied). The oracle runs the whole pytest suite against the mutated copy, then compares every
finding record (keys, severity, evidence, paths) on the seeded tenant and three 300-identity synthetic
tenants with a golden copy from the unmutated code. A mutant is killed if a test fails, the code
crashes, or any record changes. Writes results/code_mutants.csv and results/code_mutants.json.
"""

import ast
import csv
import json
import os
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
GOLDEN = r'''
import json, sys
sys.path[:0] = [sys.argv[1], "{root}/fixtures", "{root}/experiments"]
from seeded import ISSUES, allowlist, build
from synth import generate
from nhi_evidence import config, engine
cfg = config.load()
def records(snap, allow=None):
    fs = engine.evaluate(snap, cfg, allow)
    return sorted(json.dumps(f.to_dict(), sort_keys=True, default=str) for f in fs)
t = build(set(ISSUES))
out = {{"seeded": records(t.snapshot(), allowlist(t))}}
for seed in (1, 2, 3):
    g, _, _ = generate(300, seed)
    out[f"synthetic-300-{{seed}}"] = records(g.snapshot())
json.dump(out, open(sys.argv[2], "w"))
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


def oracle(src_dir: Path, golden: Path, out: Path) -> tuple[str, str]:
    """(status, reason). Killed if the test suite fails, or any finding record differs from the golden copy."""
    env = dict(os.environ, NHI_SRC=str(src_dir))
    r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", str(ROOT / "tests")],
                       capture_output=True, text=True, timeout=300, env=env, cwd=ROOT)
    if r.returncode != 0:
        failed = [ln for ln in r.stdout.splitlines() if ln.startswith(("FAILED", "ERROR"))]
        return "killed", "tests: " + (failed[0] if failed else r.stdout.strip().splitlines()[-1])[:150]
    script = out.parent / "golden.py"
    script.write_text(GOLDEN.format(root=ROOT))
    r = subprocess.run([sys.executable, str(script), str(src_dir), str(out)], capture_output=True, text=True,
                       timeout=300)
    if r.returncode != 0:
        return "killed", "golden: crashed " + (r.stderr.strip().splitlines() or ["?"])[-1][:120]
    a, b = json.loads(out.read_text()), json.loads(golden.read_text())
    diff = [k for k in b if a.get(k) != b[k]]
    return ("killed", "golden: output differs on " + ", ".join(diff)) if diff else ("survived", "")


def run_one(job):
    path, index, golden = job
    src = path.read_text()
    mutated, line, desc = mutate(src, index)
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(ROOT / "src", Path(tmp) / "src")
        (Path(tmp) / "src" / path.relative_to(ROOT / "src")).write_text(mutated)
        try:
            status, why = oracle(Path(tmp) / "src", golden, Path(tmp) / "out.json")
        except subprocess.TimeoutExpired:
            status, why = "killed", "timeout"
    return {"file": str(path.relative_to(ROOT)), "line": line, "mutation": desc, "status": status, "reason": why}


def main():
    golden = ROOT / "build" / "golden.json"
    golden.parent.mkdir(exist_ok=True)
    (golden.parent / "golden.py").write_text(GOLDEN.format(root=ROOT))
    subprocess.run([sys.executable, str(golden.parent / "golden.py"), str(ROOT / "src"), str(golden)], check=True)
    status, why = oracle(ROOT / "src", golden, golden.parent / "self.json")
    assert status == "survived", f"the unmutated code must pass its own oracle: {why}"
    jobs = [(p, i, golden) for p in TARGETS for i in range(len(sites(ast.parse(p.read_text()))))]
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
