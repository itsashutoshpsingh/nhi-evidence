"""How many Graph requests the collector sends, measured by running it against the in-process Graph mock
(Graph's paging: $top up to 999 where the collector asks for it, 100 otherwise), with and without
throttling. Time here is in-process only; real Graph adds network latency per request, which this does
not measure. Writes results/collect_cost.csv.
"""

import csv
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "experiments")]
from synth import generate  # noqa: E402

from nhi_evidence import config, engine  # noqa: E402
from nhi_evidence.collect import Graph, collect  # noqa: E402
from nhi_evidence.graphmock import MockGraph  # noqa: E402


def main():
    rows = []
    for n in (100, 1000, 10000):
        t, expected, _ = generate(n, 1)
        src = t.snapshot()
        for throttle in (0, 50):
            mock = MockGraph(src, throttle_every=throttle)
            sleeps = []
            g = Graph("x.y.z", httpx.Client(transport=mock.transport()), sleep=sleeps.append)
            t0 = time.perf_counter()
            got = collect(g, now=datetime(2026, 11, 1, tzinfo=UTC))
            secs = time.perf_counter() - t0
            found = {f.key for f in engine.evaluate(got, config.load()) if not f.suppressed}
            per_object = sum(v for k, v in g.calls.items() if "{id}" in k)
            rows.append({"n": n, "throttle_every": throttle, "requests": mock.requests,
                         "successful_gets": sum(g.calls.values()), "retries_429": g.throttled,
                         "seconds_waited": sum(sleeps), "per_object_requests": per_object,
                         "list_requests": sum(g.calls.values()) - per_object, "writes": len(mock.writes),
                         "in_process_seconds": round(secs, 3), "planted": len(expected),
                         "found_after_collect": len(found & expected), "false_after_collect": len(found - expected),
                         # sponsors need AgentIdentity.ReadWrite.All, so the read-only collector cannot see them
                         "missed_agent_no_sponsor": len({k for k in expected - found if k[1] == "agent_no_sponsor"}),
                         "missed_other": len({k for k in expected - found if k[1] != "agent_no_sponsor"})})
            print(rows[-1], flush=True)
    with open(ROOT / "results" / "collect_cost.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
