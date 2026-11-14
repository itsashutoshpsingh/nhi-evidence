# Limits: what this does not show

1. **No live tenant.** Every number comes from synthetic Graph-shaped fixtures. The guide's claim ("12
   seeded misconfigurations in a test tenant: 12 found, 0 false") is shown here only for fixtures and for a
   replay of the seeding plan against a simulated Graph. The live run is written up in
   [run-against-your-tenant.md](run-against-your-tenant.md) and has not been done.
2. **Self-consistency, not field accuracy.** The same person wrote the generator, the expected findings
   and the checks. The scale runs (54,961 planted, 0 missed, 0 false) show the rules are implemented
   consistently; they cannot show the rules are the right ones for real tenants.
3. **Schema conformance is by property name.** Fixtures use only documented property names, but values,
   nesting of rarely used fields, and Graph's real behaviour (for example which properties `$select`
   returns for derived types such as `agentIdentity`, or how `owners` reports deleted objects) are my
   reading of the docs, not observed responses.
4. **Beta endpoints.** Flexible federated credentials and service principal sign-in activity are read
   from `beta`, which Microsoft can change without notice.
5. **Agent identities.** Graph's docs list only `AgentIdentity.ReadWrite.All` for reading sponsors, so the
   read-only collector cannot see them and check 1's agent rule does not run on live data. Agent
   identities have no `appId` in their documented properties, so check 2 skips them. Graph activity logs
   (what an agent actually did) are not read.
6. **Granted versus used was not built.** It needs Microsoft Graph activity logs from a Log Analytics
   workspace (P1 or P2 and an Azure subscription), and a map from request URL to least-privileged
   permission. Synthetic logs would only repeat my own assumptions. Maester MT.1079 and LeastPrivilegedMSGraph
   already do this.
7. **Heuristic checks.** Check 11 (environments) matches words such as `dev` and `prod` in federated
   subjects and redirect hosts, and marks findings for review. An app whose names carry no environment
   words is invisible to it.
8. **Check 13 models four app-management roles, role-assignable groups, owners and three Graph
   permissions.** It ignores PIM-eligible assignments, administrative units, Azure RBAC, Exchange and
   SharePoint permissions, and conditional access on the admin path. A user with any role Microsoft labels
   privileged is treated as privileged and is never a source, even when the role cannot touch apps.
   BloodHound models far more.
9. **Check 12 counts a policy with a `servicePrincipalFilter` as covering everything** (custom security
   attributes are not read), so a filtered policy can hide gaps.
10. **Check 7 only knows Microsoft Graph scopes.** Sensitive scopes on other APIs (Exchange's
    `full_access_as_user`, SharePoint, custom APIs) are not judged.
11. **Collection cost is a request count, not a time.** About 3.2 GETs per service principal (most of
    them per-object owner, credential and assignment calls); JSON batching would cut this and is not
    implemented. Network latency and real throttling limits were not measured.
12. **Severity is my choice** (base severity per rule, raised to at least high on privileged identities).
    It is not calibrated against incidents.
13. **NHI2 Secret Leakage is not covered** and cannot be from Graph.
