"""Rebuild the reference data in src/nhi_evidence/data/ from pinned documentation commits.

Sources are the Markdown sources of Microsoft Learn (Microsoft Graph and Entra docs repositories)
and the OWASP NHI Top 10 repository, each at a fixed commit, so the output is reproducible.
Run: python scripts/fetch_refs.py   (network needed; writes data files and data/sources.json)
"""

import hashlib
import json
import re
import urllib.request
from pathlib import Path

GRAPH_SHA = "2329b086341e67d36de55a5743af1a47224046ca"  # microsoftgraph/microsoft-graph-docs-contrib
ENTRA_SHA = "01f21c9cc0b62201307d84ae8b9d42a28b6d1f49"  # MicrosoftDocs/entra-docs
OWASP_SHA = "16f8b79394662c6467eb7a1907b6af7e209b1fd9"  # OWASP/www-project-non-human-identities-top-10
GRAPH = f"https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-docs-contrib/{GRAPH_SHA}"
ENTRA = f"https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/{ENTRA_SHA}/docs"
OWASP = f"https://raw.githubusercontent.com/OWASP/www-project-non-human-identities-top-10/{OWASP_SHA}"

# resource docs whose property names the fixtures are validated against (tests/test_schema.py)
RESOURCES = [
    ("v1.0", "application"), ("v1.0", "serviceprincipal"), ("v1.0", "agentidentity"),
    ("v1.0", "passwordcredential"), ("v1.0", "keycredential"), ("v1.0", "verifiedpublisher"),
    ("v1.0", "oauth2permissiongrant"), ("v1.0", "approleassignment"), ("v1.0", "approle"),
    ("v1.0", "unifiedroleassignment"), ("v1.0", "unifiedroledefinition"),
    ("v1.0", "federatedidentitycredential"), ("beta", "federatedidentitycredential"),
    ("beta", "federatedidentityexpression"),
    ("v1.0", "conditionalaccesspolicy"), ("v1.0", "conditionalaccessconditionset"),
    ("v1.0", "conditionalaccessclientapplications"),
    ("v1.0", "user"), ("v1.0", "group"), ("v1.0", "organization"), ("v1.0", "webapplication"),
    ("v1.0", "signin"), ("v1.0", "signinstatus"),
    ("beta", "serviceprincipalsigninactivity"), ("v1.0", "signinactivity"),
]
ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "build" / "refs"
DATA = ROOT / "src" / "nhi_evidence" / "data"
sources = []


def get(url: str, used_for: str) -> str:
    CACHE.mkdir(parents=True, exist_ok=True)
    f = CACHE / hashlib.sha256(url.encode()).hexdigest()[:16]
    if not f.exists():
        with urllib.request.urlopen(url, timeout=60) as r:
            f.write_bytes(r.read())
    body = f.read_bytes()
    sources.append({"url": url, "sha256": hashlib.sha256(body).hexdigest(), "used_for": used_for})
    return body.decode()


def properties(md: str) -> list[str]:
    """Property names from the '## Properties' table plus keys of the JSON representation."""
    names = []
    sec = re.search(r"^## Properties\s*$(.*?)^## ", md, re.S | re.M)
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r"^\s*\|\s*([A-Za-z@][\w.@]*)\s*\|", line)
            if m and m.group(1) not in ("Property", "Relationship"):
                names.append(m.group(1))
    js = re.search(r"## JSON representation.*?```json\s*(\{.*?\})\s*```", md, re.S)
    if js:
        names += re.findall(r'^\s{2}"([@\w.]+)"\s*:', js.group(1), re.M)
    rel = re.search(r"^## Relationships\s*$(.*?)^## ", md, re.S | re.M)
    rels = []
    if rel:
        for line in rel.group(1).splitlines():
            m = re.match(r"^\s*\|\s*([A-Za-z]\w*)\s*\|", line)
            if m and m.group(1) != "Relationship":
                rels.append(m.group(1))
    return sorted({"@odata.type" if n.endswith("odata.type") else n for n in names}), sorted(set(rels))


def main() -> None:
    schema = {}
    for ver, res in RESOURCES:
        md = get(f"{GRAPH}/api-reference/{ver}/resources/{res}.md", f"Graph {ver} {res} schema")
        props, rels = properties(md)
        schema[f"{ver}/{res}"] = {"properties": props, "relationships": rels}

    perm_md = get(f"{GRAPH}/concepts/permissions-reference.md", "Graph permission names and IDs")
    perms = {}
    for m in re.finditer(r"^### ([\w.]+)\s*\n(.*?)(?=^### |\Z)", perm_md, re.S | re.M):
        idl = re.search(r"\|\s*Identifier\s*\|\s*([^|]*)\|\s*([^|]*)\|", m.group(2))
        if idl:
            app, dele = (x.strip() for x in idl.groups())
            perms[m.group(1)] = {"application": None if app == "-" else app,
                                 "delegated": None if dele == "-" else dele}

    roles_md = get(f"{ENTRA}/identity/role-based-access-control/permissions-reference.md",
                   "Entra built-in role template IDs and privileged label")
    roles = {}
    for line in roles_md.splitlines():
        m = re.match(r"^> \| \[([^\]]+)\]\(#[^)]*\) \| (.*) \| ([0-9a-f-]{36}) \|$", line)
        if m:
            roles[m.group(3)] = {"displayName": m.group(1), "privileged": "privileged-label" in m.group(2)}

    owasp = {}
    top10 = get(f"{OWASP}/2025/docs/top-10-2025.md", "OWASP NHI Top 10 2025 risk IDs and names")
    for m in re.finditer(r"\[(NHI\d+):2025 ([^\]]+)\]\(([^)]+)\)", top10):
        slug = m.group(3).split("/")[-1].removesuffix(".md").strip("/")
        owasp[m.group(1)] = {
            "name": m.group(2).strip(),
            "url": f"https://owasp.org/www-project-non-human-identities-top-10/2025/{slug}/",
        }
    get(f"{OWASP}/2025/docs/detection-resources.md", "OWASP NHI detection resources index entry format")

    DATA.mkdir(parents=True, exist_ok=True)
    out = {"graph_schema.json": schema, "graph_permissions.json": perms,
           "directory_roles.json": roles, "owasp_nhi.json": owasp, "sources.json": sources}
    for name, obj in out.items():
        (DATA / name).write_text(json.dumps(obj, indent=1, sort_keys=True) + "\n")
    print(f"{len(schema)} resources, {len(perms)} permissions, {len(roles)} roles "
          f"({sum(r['privileged'] for r in roles.values())} privileged), {len(owasp)} OWASP risks")


if __name__ == "__main__":
    main()
