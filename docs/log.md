# Build log

Each entry: what I ran, what I saw.

- 2026-11-14. Novelty and overlap search; Graph, Entra and OWASP docs read at pinned commits (`scripts/fetch_refs.py`). Firecrawl credits ran out midway; the rest of the doc reading used raw files from the docs repositories at fixed commits.
- 2026-11-14. First run of the 14 checks on the seeded tenant: 15 of 15 expected findings, 0 extra, 5 suppressed (3 Microsoft first-party, 2 allowlisted vendor).
- 2026-11-14. First run of 42 single-change mutations: 4 did not match my written expectations. In all 4 the tool was right and my expectation was incomplete: a data permission on an app whose owner is not an admin is also a credential-control path (M06a), and any path that reaches "every application" also reaches the allowlisted vendor app that holds Mail.Read (M06c, M13b, M13c). Expectations corrected; recorded in docs/what-went-wrong.md.
- 2026-11-14. First synthetic tenants (n=100, 1000): 17 to 23 unexpected C04 expired_present findings per 1,000. Cause: my generator gave background web apps secrets that started up to 60 days ago but lasted 30, so they had already expired. The check was right; the generator was not clean. Fixed by drawing the start date inside the lifetime.
