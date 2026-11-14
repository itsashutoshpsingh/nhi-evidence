"""Write findings.json, report.md and owasp_mapping.md for one evaluated snapshot."""

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from . import refs
from .checks import CHECKS, NOT_COVERED
from .engine import skipped
from .finding import SEVERITIES

GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def scrub(text: str, domains: list[str]) -> str:
    """Replace GUIDs and the given domain names with stable pseudonyms, for sharing a report."""
    text = GUID.sub(lambda m: "id-" + hashlib.sha256(m[0].lower().encode()).hexdigest()[:10], text)
    for d in domains:
        text = text.replace(d, "tenant.example")
    return text


def owasp_rows(findings) -> list[dict]:
    rows = []
    for risk, info in sorted(refs.owasp().items(), key=lambda kv: int(kv[0][3:])):
        checks = [c.META for c in CHECKS if risk in c.META["nhi"]]
        n = sum(1 for f in findings if risk in f.nhi_risk and not f.suppressed)
        rows.append({"risk": risk, "name": info["name"], "url": info["url"],
                     "checks": [f"{m['id']} {m['title']}" for m in checks], "findings": n,
                     "not_covered": NOT_COVERED.get(risk)})
    return rows


def write(snap, findings, out: str | Path, scrub_domains: list[str] | None = None) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    live = [f for f in findings if not f.suppressed]
    sup = [f for f in findings if f.suppressed]
    clean = (lambda t: scrub(t, scrub_domains)) if scrub_domains is not None else (lambda t: t)
    meta = {"collected_at": snap.manifest["collected_at"], "source": snap.manifest.get("source"),
            "api_versions": snap.manifest.get("api_versions"), "skipped_checks": skipped(snap),
            "findings": len(live), "suppressed": len(sup)}
    (out / "findings.json").write_text(clean(json.dumps(
        {"meta": meta, "findings": [f.to_dict() for f in findings]}, indent=1, default=str)) + "\n")

    sev = Counter(f.severity for f in live)
    lines = ["# nhi-evidence report", "",
             f"Snapshot: {meta['source']}, collected {meta['collected_at']}. "
             f"{len(live)} findings, {len(sup)} suppressed by the allowlist.", "",
             "| Severity | " + " | ".join(reversed(SEVERITIES)) + " |",
             "|---|" + "---|" * len(SEVERITIES),
             "| Findings | " + " | ".join(str(sev.get(s, 0)) for s in reversed(SEVERITIES)) + " |", "",
             "## Checks", "", "| Check | OWASP NHI | Findings | Suppressed | Licence / input |",
             "|---|---|---|---|---|"]
    for c in CHECKS:
        m = c.META
        state = meta["skipped_checks"].get(m["id"])
        n = sum(f.check_id == m["id"] for f in live)
        s = sum(f.check_id == m["id"] for f in sup)
        lines.append(f"| {m['id']} {m['title']} | {', '.join(m['nhi'])} | {'not run' if state else n} | {s} | "
                     f"{state or m['licence']} |")
    lines += ["", "## Findings by identity type", "", "| Identity type | Findings |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in Counter(f.identity_type for f in live).most_common()]
    lines += ["", "## Findings", ""]
    for f in sorted(live, key=lambda f: (-SEVERITIES.index(f.severity), f.check_id, f.display_name)):
        ev = {k: v for k, v in f.evidence.items() if k != "paths"}
        lines += [f"### [{f.severity}] {f.check_id} {f.rule}: {f.display_name}", "",
                  f"- OWASP: {', '.join(f.nhi_risk)}; object: {f.object_type} `{f.object_id}` ({f.identity_type})",
                  f"- Evidence: `{json.dumps(ev, default=str)}`",
                  f"- Why it matters: {f.why_it_matters}",
                  f"- Verify by hand: {f.how_to_verify_manually}"]
        for p in f.evidence.get("paths", []):
            chain = " -> ".join([p["source"]] + [s["to"] for s in p["steps"]])
            lines.append(f"  - path ({p['hops']} hops): {chain}. Close it: {p['closing_control']}")
        lines.append("")
    if sup:
        lines += ["## Suppressed", "", "| Check | Object | Reason |", "|---|---|---|"]
        lines += [f"| {f.check_id} {f.rule} | {f.display_name} | {f.suppressed} |" for f in sup]
    (out / "report.md").write_text(clean("\n".join(lines)) + "\n")

    rows = owasp_rows(findings)
    ml = ["# OWASP NHI Top 10 (2025) mapping", "",
          "Each check maps to the risk whose description it tests. Risk names and links are from the OWASP "
          "project at commit 16f8b79.", "",
          "| Risk | Checks | Findings |", "|---|---|---|"]
    for r in rows:
        checks = "; ".join(r["checks"]) or f"none: {r['not_covered'] or 'not covered'}"
        ml.append(f"| [{r['risk']} {r['name']}]({r['url']}) | {checks} | {r['findings']} |")
    (out / "owasp_mapping.md").write_text("\n".join(ml) + "\n")
