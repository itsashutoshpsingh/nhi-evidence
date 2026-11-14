# What went wrong

Misses, dead ends and limits, in the order I hit them, with what each does to the numbers. The running
notes are in [log.md](log.md).

## Research

1. **The web research tool ran out of credits halfway through the novelty search.** The rest of the
   reading used the Markdown sources of Microsoft Learn and the OWASP site from their GitHub repositories at
   fixed commits, plus a general web search. GitHub's web pages were not reachable from the build machine,
   so for EntraFalcon, ScEntra and App Lifecycle Analyzer I read summaries only, and I read Maester's test
   titles plus two test pages, not every test's code. *Effect:* the overlap table in
   [prior_art.md](prior_art.md) may understate what those tools cover; it says so where I did not read deeply.
2. **Microsoft's docs and GitHub's disagree on the pull-request subject.** Entra's *Create trust* page
   (entra-docs `01f21c9`) gives `repo:<org/repo>:pull-request`; GitHub's OIDC reference gives
   `repo:ORG/REPO:pull_request`. A credential copied from Microsoft's page never matches. I made this a
   low-severity rule (`github_subject_never_matches`) rather than ignoring it. *Effect:* one extra rule.
3. **Reading agent sponsors needs a write permission.** Graph lists `AgentIdentity.ReadWrite.All` as the
   only application permission for listing an agent identity's sponsors (delegated: not supported). The
   collector refuses write permissions, so it cannot see sponsors. *Effect:* check 1's agent rule runs on
   fixtures only; on collected data it loses 1, 4 and 35 planted findings at 100, 1,000 and 10,000
   identities (`results/collect_cost.csv`).
4. **Graph's generated permission table for listing groups names a write permission**
   (`Group-NestingSupport.ReadWrite.All`) as least privileged, and the users-list table was missing at the
   docs commit I pinned. I relied on `Directory.Read.All`, which both pages list. *Effect:* none on results.

## Building the fixtures and tests

5. **4 of my first 42 mutation expectations were wrong, and the tool was right in all 4.** A data
   permission on an app whose owner is not an admin is also a credential-control path (M06a), and any path
   that reaches "every application" also reaches the allowlisted vendor app that holds `Mail.Read` (M06c,
   M13b, M13c): the allowlist covers that app's C06 and C10 findings, not new paths to it. I corrected the
   expectations. *Effect:* none on the final numbers, but it shows the expectations are hand-written and
   can be wrong.
6. **My first synthetic tenants were not clean.** Background web apps got secrets that started up to 60
   days ago but lasted 30, so 17 to 23 per 1,000 had already expired, and check 4 reported them. The check
   was right; the generator was wrong. Fixed by drawing the start inside the lifetime. *Effect:* before the
   fix, check 4 had 17 and 23 false findings on the two 1,000-identity trial tenants; after it, every run is
   exact.
7. **The first code-mutation run tested the unmutated code.** `fixtures/seeded.py` put the real `src/` at
   the front of `sys.path`, ahead of the mutated copy, so every mutant "survived". I noticed because
   emptying check 3's return value survived. Fixed (the fixture path is appended, not prepended) before any
   result was recorded.
8. **The first real code-mutation run caught 170 of 212 mutants (80.2%).** Three causes: the oracle compared
   only finding keys, so severity and evidence changes went unseen; several boundaries had no fixture on
   them; and graph guards were exercised only by unit tests the oracle did not run. I made the oracle run
   the whole test suite and compare full finding records against a golden copy (193 of 212), then added
   look-alikes and mutations for the boundaries: an app with no service principal, a grant on a non-Graph
   API, a SAML signing certificate on a third-party service principal, a multi-tenant app registered here,
   last sign-in exactly 90 days ago, an app created exactly 90 days ago, scoped and tenant-wide app-admin
   roles on an owned app, service-principal owners with and without permission to edit apps, a deleted
   service account; and two graph tests (severity by hop count, the 10-path cap). Designing those showed
   one real defect: **check 13 treated disabled service principals as path targets**, though they cannot
   sign in; fixed. Two redundant expressions were deleted rather than tested. Final: 206 of 208 (99.0%).
   *Effect:* the seeded and scale results did not change (no fixture had a disabled privileged target with
   a path); the clean tenant gained 8 look-alikes and the mutation suite 9 cases.
9. **The two surviving mutants are equivalent on any data the checks receive.**
   (a) `c11_environment_reuse.py` line 41, `split(":", 2)` to `split(":", 3)`: for every GitHub and
   Kubernetes subject the context part keeps the same words either way.
   (b) `graph.py` line 105, `continue` removed for a role assignment whose principal is unknown or disabled:
   the loop then reuses the previous principal, which already holds a privileged role and is never a path
   source, so no output changes. I left the guard in because the code is wrong without it.
10. **Generating a 100,000-identity tenant took 492 seconds** because updating a sign-in record rebuilt the
    whole list each time. Fixed with a dictionary (5.7 s). *Effect:* none on results.

## The seeding plan

11. **The first version of the live seeding plan would have produced two unplanned findings.** Replaying it
    against the simulated Graph showed check 5 on payroll-export (it had a secret) and check 12 on
    nightly-report-job (the workload policy was report-only, so nothing was covered). It now uploads a
    certificate (private key discarded) for payroll-export and creates an enforced policy scoped to the
    seeded app only. The replay also caught that S03's one-day secret was timed from the wall clock, not the
    seeding time. *Effect:* the replay now gives the 12 intended findings.
12. **The live plan cannot match the fixture tenant exactly.** S07 uses Security Reader (labelled privileged
    by Microsoft) instead of Privileged Role Administrator, to avoid giving a lab app a path to Global
    Administrator; S06 uses an app in the same tenant in place of a third-party one; S09 needs a second
    tenant; S11 needs Workload Identities Premium; S13 and S14 need time and P1 or P2.

## Scope against the guide

13. **14 seeded misconfigurations, not 12.** The guide's 12 match the 12 static checks; I added one each
    for the two sign-in checks so that all 14 checks have a seeded case. The static ones alone: 13 of 13
    expected findings found, 0 false.
14. **Not done:** the live-tenant run (no tenant or credentials here), the OWASP index pull request (the
    guide ties it to live evidence; the entry is drafted in [owasp_entry.md](owasp_entry.md)), granted
    versus used from Graph activity logs (needs a P1 or P2 trial and Log Analytics; synthetic logs would
    only echo my assumptions), and JSON batching in the collector.
15. **The weakest OWASP mapping is check 12 to NHI4.** OWASP's NHI4 text is about the authentication method;
    a missing Conditional Access policy is a control around it. I say so in the mapping.
16. **The one-line-rule comparison is shaped by my generator.** Most of its 4,440 false findings come from
    background objects the generator makes in fixed shares (ownerless apps with a service record, first-party
    and managed identities with no sign-in record). The per-check direction (which refinement prevents which
    error) is the result; the totals are not a real-tenant estimate.
