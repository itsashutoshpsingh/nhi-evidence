"""The finding record and the privilege helpers that several checks share."""

from dataclasses import asdict, dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Finding:
    check_id: str
    rule: str
    nhi_risk: list[str]
    object_id: str
    object_type: str
    display_name: str
    severity: str
    evidence: dict
    why_it_matters: str
    how_to_verify_manually: str
    identity_type: str = ""
    suppressed: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.check_id, self.rule, self.object_id)

    def to_dict(self) -> dict:
        return asdict(self)


def at_least(sev: str, floor: str) -> str:
    return max(sev, floor, key=SEVERITIES.index)


def privileged_graph(snap, cfg, sp_id: str) -> list[tuple[str, str]]:
    """(permission, tier) for high-privilege Microsoft Graph application permissions held by sp_id."""
    out = []
    for name, _ in snap.graph_permissions(sp_id):
        if name in cfg["graph_tier0"]:
            out.append((name, "tier0"))
        elif name in cfg["graph_data"]:
            out.append((name, "data"))
    return out


def privileged_roles(snap, principal_id: str) -> list[dict]:
    return [r for r in snap.roles_by_principal.get(principal_id, []) if snap.role_is_privileged(r)]


def is_privileged(snap, cfg, sp_id: str) -> bool:
    """True when checks 6 or 8 would flag this service principal. Cached on the snapshot."""
    cache = snap.__dict__.setdefault("_privileged", {})
    if sp_id not in cache:
        cache[sp_id] = bool(privileged_graph(snap, cfg, sp_id) or privileged_roles(snap, sp_id))
    return cache[sp_id]


def escalate(snap, cfg, sp: dict | None, base: str) -> str:
    """Hygiene issues on a privileged identity are at least high (guide: secret age matters most there)."""
    return at_least(base, "high") if sp and is_privileged(snap, cfg, sp["id"]) else base
