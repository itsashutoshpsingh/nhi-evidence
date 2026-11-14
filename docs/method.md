# Method

All results are from synthetic data shaped like Microsoft Graph responses. No live tenant was used.

## Objects and schema

A snapshot is a directory of JSON files holding Graph objects with Graph's own property names
(`src/nhi_evidence/snapshot.py`). `tests/test_schema.py` checks every key of every fixture object against
the property list of its resource in the Microsoft Graph docs (v1.0, or beta for federated identity
credentials and service principal sign-in activity), extracted by `scripts/fetch_refs.py` from
[microsoft-graph-docs-contrib at `2329b08`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/tree/2329b086341e67d36de55a5743af1a47224046ca).
Resources covered: application, servicePrincipal, agentIdentity, passwordCredential, keyCredential,
verifiedPublisher, oAuth2PermissionGrant, appRoleAssignment, appRole, unifiedRoleAssignment,
unifiedRoleDefinition, federatedIdentityCredential (v1.0 and beta), federatedIdentityExpression,
conditionalAccessPolicy, conditionalAccessConditionSet, conditionalAccessClientApplications, user, group,
organization, webApplication, signIn, signInStatus, servicePrincipalSignInActivity, signInActivity.

Permission IDs come from Graph's permissions reference (804 permissions); role template IDs and
Microsoft's "privileged" label from Entra's built-in roles page at
[entra-docs `01f21c9`](https://github.com/MicrosoftDocs/entra-docs/tree/01f21c9cc0b62201307d84ae8b9d42a28b6d1f49)
(139 roles, 35 labelled privileged). A live snapshot uses `roleDefinitions.isPrivileged` from the tenant first.

The checks never read the clock: "now" is the snapshot's `collected_at`, so results are repeatable.

## Finding, expected finding, match

A finding's key is `(check_id, rule, object_id)`. A planted issue states the keys it must produce. For a
tenant:

- **found** = expected keys present among unsuppressed findings;
- **missed** = expected keys absent;
- **false** = unsuppressed findings whose key is not expected.

Precision is found / (found + false); recall is found / (found + missed). Suppressed findings (Microsoft
first-party apps, and allowlist entries with a written reason) are counted separately and are neither
found nor false. Matching on `rule` as well as check means a finding for the right object for the wrong
reason counts as both a miss and a false finding.

## The seeded tenant (`fixtures/seeded.py`)

14 planted misconfigurations, S01 to S14: 12 static ones (one per static check; S12 also produces a check 6
finding because a credential-control path needs a privileged target) and 2 that need sign-in data (checks
2 and 14). Each has a "fixed" form; the clean tenant is the seeded tenant with every issue fixed, and
`build({"S05"})` plants one issue alone. 34 look-alike controls sit one step from an issue on the safe
side (listed in `CONTROLS`): a secret of exactly 180 days, a role Microsoft does not label privileged,
all-user consent to sign-in scopes only, a multi-tenant app the policy cannot cover, and so on.

## Mutation tests

Two kinds.

1. **Fixture mutations** (`fixtures/mutations.py`): 51 single changes to the clean tenant, 2 to 7 per
   check, each stating every finding it must produce. A mutation passes only on an exact match, so a side
   effect nobody predicted fails it. `results/mutation_matrix.json` records which checks fired.
2. **Code mutants** (`experiments/code_mutants.py`): one operator or statement changed in a check module,
   `finding.py` or `graph.py` (comparison flipped, `and`/`or` swapped, `not` removed, `continue` removed,
   an integer constant plus one, `return out` emptied). The oracle runs the whole test suite against the
   mutated copy and then compares every finding record (key, severity, evidence, paths) on the seeded
   tenant and three 300-identity synthetic tenants with a golden copy from the unmutated code. Killed =
   any test fails, the code crashes, or any record differs. Kill rate = killed / mutants. The first run
   used a weaker oracle (finding keys only, no test suite) and is kept as `results/code_mutants_run1.*`.

## Synthetic tenants at scale (`experiments/synth.py`)

n = number of service principals: 60% apps registered in the tenant, 15% third-party multi-tenant apps
(40% verified), 10% Microsoft first-party, 8% managed identities, 7% agent identities; n/2 users, n/50
departed (disabled) users, n/50 `svc-` service accounts, three Global Administrators, an app-admin group.
Background objects are clean by construction (certificates, exact federated subjects, recent sign-ins,
covered by an enforced workload policy). Then each check gets planted issues at 2% of the identities
eligible for it (5% for agent identities without a sponsor, 20% of service accounts for check 14), using
2 to 7 variants per check chosen at random, and look-alikes at 2%. Each identity gets at most one planted
issue, except check 13's, which by definition also carries a check 6 finding. Sizes 100, 1,000 and 10,000
with seeds 1 to 5; 100,000 with seeds 1 to 3. Each run is a separate interpreter; peak memory is
`ru_maxrss`. Snapshot SHA-256 values are in `results/synthetic_snapshots.sha256`; the snapshots
themselves are regenerated, not committed.

Recall lower bounds use the Wilson score interval (95%, z = 1.96) on counts pooled over all runs.

**What this measures and what it does not.** The generator and the checks were written by the same
person from the same reading of the docs, so 0 misses and 0 false findings here show that the checks
implement their written rules consistently across many variants, interactions and sizes. It is not an
estimate of precision on real tenants, where the unknowns are data shapes and practices I did not model.

## One-line rules (ablation)

`experiments/ablation.py` writes the one-line version of each check, as a quick script would (any app
with no owners; any directory role; any all-user grant; any secret without a certificate; permission
names containing `ReadWrite`; and so on), and runs both versions on the seeded and clean fixtures and five
1,000-identity tenants, matching at (check, object) level. The look-alikes were designed around these
refinements, so the counts show what each refinement prevents at this generator's rates, not real-tenant
rates.

## Collection cost

`experiments/collect_cost.py` runs the real collector, with `httpx`, against `graphmock.MockGraph`, which
serves a snapshot with Graph's paging (`$top` up to 999 where the collector asks for it, 100 otherwise,
`@odata.nextLink` with `$skiptoken`), applies `$select`, answers anything but GET with 405, and in the
throttled run returns 429 with `Retry-After: 1` on every 50th request. It counts successful GETs and
retries. In-process time excludes network latency, so it says nothing about wall time against real Graph.

## Lab plan replay

`lab/simulate.py` applies the live seeding plan through a simulated, writable Graph and runs the checks on
the result two days later. It shows what `seed_tenant.py apply` should produce and tests that every
request in the plan is well formed. It does not model Graph's validation or licence checks.
