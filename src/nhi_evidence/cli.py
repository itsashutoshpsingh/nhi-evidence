"""nhi-evidence collect | check | diff | whoami"""

import argparse
import json
import sys

from . import auth, config, engine, report
from .diff import diff
from .snapshot import Snapshot


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nhi-evidence", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect", help="read a tenant through Microsoft Graph into a snapshot directory")
    c.add_argument("--tenant-id", required=True)
    c.add_argument("--client-id", required=True)
    c.add_argument("--auth", choices=["device", "secret", "certificate"], default="device")
    c.add_argument("--cert", help="PEM private key for --auth certificate")
    c.add_argument("--thumbprint")
    c.add_argument("--no-activity", action="store_true", help="skip sign-in data (no AuditLog.Read.All or P1)")
    c.add_argument("--sign-in-days", type=int, default=30)
    c.add_argument("--out", required=True)
    k = sub.add_parser("check", help="run the checks on a snapshot and write the report")
    k.add_argument("snapshot")
    k.add_argument("--out", required=True)
    k.add_argument("--config")
    k.add_argument("--allowlist")
    k.add_argument("--scrub", nargs="*", metavar="DOMAIN",
                   help="replace object IDs and these domain names with pseudonyms in the output")
    d = sub.add_parser("diff", help="changes between two snapshots")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--config")
    w = sub.add_parser("whoami", help="show a token's permissions and whether collect would accept it")
    w.add_argument("--tenant-id", required=True)
    w.add_argument("--client-id", required=True)
    w.add_argument("--auth", choices=["device", "secret", "certificate"], default="device")
    w.add_argument("--cert")
    w.add_argument("--thumbprint")
    a = p.parse_args(argv)

    if a.cmd in ("collect", "whoami"):
        from .collect import Graph, collect
        token = auth.acquire(a.tenant_id, a.client_id, a.auth, a.cert, a.thumbprint)
        try:
            perms = auth.check_read_only(token)
        except auth.WriteScopeError as e:
            print(e, file=sys.stderr)
            return 3
        print("token permissions (all read-only):", ", ".join(perms))
        if a.cmd == "whoami":
            return 0
        snap = collect(Graph(token), activity=not a.no_activity, sign_in_days=a.sign_in_days)
        snap.manifest["token_permissions"] = perms
        snap.save(a.out)
        print(f"wrote {a.out}: {sum(snap.manifest['calls'].values())} GET requests")
        return 0
    cfg = config.load(a.config)
    if a.cmd == "check":
        snap = Snapshot.load(a.snapshot)
        findings = engine.evaluate(snap, cfg, engine.load_allowlist(a.allowlist))
        report.write(snap, findings, a.out, a.scrub)
        live = [f for f in findings if not f.suppressed]
        print(f"{len(live)} findings ({len(findings) - len(live)} suppressed) -> {a.out}/report.md")
        return 0
    changes = diff(Snapshot.load(a.before), Snapshot.load(a.after), cfg)
    print(json.dumps(changes, indent=1))
    return 1 if changes else 0


if __name__ == "__main__":
    sys.exit(main())
