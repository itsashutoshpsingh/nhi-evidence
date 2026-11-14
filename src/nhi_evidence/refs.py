"""Reference data shipped with the package (built by scripts/fetch_refs.py from pinned doc commits)."""

import json
from functools import cache
from pathlib import Path

DATA = Path(__file__).parent / "data"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
# Tenants that own Microsoft first-party apps. f8cdef31 is named in Microsoft's support article "Verify
# first-party Microsoft applications in sign-in reports". 72f988bf ("Microsoft tenant ID") and cdc5aeea
# ("Torus tenant ID", owner of Microsoft Graph Command Line Tools) are listed in merill/microsoft-info
# (MIT, commit 847610db), which takes them from Entra docs.
MICROSOFT_TENANTS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47",
                     "cdc5aeea-15c5-4db6-b079-fcadd2505dc2"}


@cache
def load(name: str):
    return json.loads((DATA / name).read_text())


def permissions() -> dict:
    return load("graph_permissions.json")


@cache
def app_role_name(role_id: str) -> str | None:
    for name, ids in permissions().items():
        if ids["application"] == role_id:
            return name
    return None


def app_role_id(name: str) -> str:
    return permissions()[name]["application"]


def delegated_id(name: str) -> str:
    return permissions()[name]["delegated"]


def roles() -> dict:
    return load("directory_roles.json")


def role_id(display_name: str) -> str:
    return next(k for k, v in roles().items() if v["displayName"] == display_name)


def owasp() -> dict:
    return load("owasp_nhi.json")
