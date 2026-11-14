# Prior art and overlap

Searched 14 November 2026: the OWASP NHI detection resources page, Maester's test list, AzureHound and
BloodHound docs, Microsoft Entra recommendations, a code and README index of public repositories
(queries: Entra service principal audit with OWASP NHI mapping; workload identity federation subject
audit), and general web search (Entra app registration audit OWASP NHI; Graph unused application
permissions granted versus used).

**I could not find an open, read-only Entra tool that maps its findings to the OWASP NHI Top 10 and
refuses to run with write permissions. The closest are [Maester](https://maester.dev/docs/tests/maester/),
which has a dozen app and service principal tests, and
[AzureHound / BloodHound CE](https://bloodhound.specterops.io/collect-data/azurehound-data-permissions),
which models who can add credentials to which app in far more depth than check 13.** The individual checks
are not new; commercial NHI products and the tools below cover most of them.

On 14 November 2026 the [OWASP NHI detection resources index](https://owasp.github.io/www-project-non-human-identities-top-10/2025/detection-resources/)
listed one tool, [gh-iga](https://github.com/abhishek20c/gh-iga), for GitHub. Its inclusion criteria: OSI
licence, read-only by default, explicit risk mapping, documented metadata handling.

## Overlap per check

"Yes" means the tool has a test for the same condition; "partly" means a related or narrower test.
Maester IDs are from its [test list](https://maester.dev/docs/tests/maester/); I read the titles and two
test pages (MT.1226, MT.1027), not every test's code.

| Check | Maester | EIDSCA | AzureHound / BloodHound | Entra recommendations | Others found |
|---|---|---|---|---|---|
| C01 no accountable owner | partly: MT.1063 (owners have MFA); MT.1077/1078 say privileged apps should have *no* owners | no | collects owners | no | no |
| C02 enabled but unused | partly: MT.1079 (unused privileged permissions) | no | sign-in activity optional | yes: *Remove unused applications* (90 days, needs Workload ID licence) | [nhinsight](https://github.com/cvemula1/nhinsight) flags disabled SPs with roles (the reverse case) |
| C03 long-lived secret | partly: MT.1198 (certificate validity); MT.1057 (no secrets at all) | no | no | no | nhinsight: secret not rotated over 365 days |
| C04 expired or duplicate credentials | yes: MT.1199 (expired or expiring) | no | no | yes: *Remove unused credentials*, *Renew expiring credentials* | nhinsight, Prowler (`credential_not_expired`) |
| C05 secret where certificate or federation fits | yes: MT.1057 | no | no | no | Prowler (client secrets) |
| C06 high-privilege application permission | yes: MT.1050, MT.1051 (high-risk permissions with a path to Global Administrator) | no | yes (edges for the tier-0 permissions) | no | no |
| C07 tenant-wide consent to sensitive scopes | not found as a per-grant test | tenant consent *settings* (EIDSCA.AP08) | partly | no | no |
| C08 privileged directory role | partly: MT.1027 (SP with secret and permanent control-plane role), MT.1078 | no | yes | no | nhinsight (Azure RBAC roles, not Entra roles) |
| C09 loose federated credential | partly: MT.1226 (mutable GitHub and GitLab subjects) | no | collects federated credentials | no | Prowler issue #12747 notes federated credentials had no check; Checkov checks Terraform source |
| C10 unverified third-party app with access | not found | no | no | no | no |
| C11 identity shared across environments | not found | no | no | no | no |
| C12 no workload identity Conditional Access | partly: MT.1002 (app management restrictions) | Conditional Access settings, not per-SP coverage | no | no | no |
| C13 credential-control paths | partly: MT.1050/1051 | no | **yes, in depth** (AZAddSecret, AZAppAdmin, AZMGAddSecret and more) | no | no |
| C14 human use of a service account | not found | no | no | no | no |
| OWASP NHI mapping | not found | no | no | no | no |
| refuses write permissions | not found | — | read-only by design, no refusal found | — | — |
| granted versus used (phase 3, not built) | MT.1079 | no | no | no | [LeastPrivilegedMSGraph](https://mynster9361.github.io/Least_Privileged_MSGraph) (Log Analytics) |

Other tools I found but did not read in detail: EntraFalcon (Compass Security, enumerates Entra objects
and flags privileged ones), ScEntra (PowerShell, privilege-escalation graph), App Lifecycle Analyzer
(read-only HTML report of app credentials, federated credentials and sign-ins).

## How this differs from Maester

Maester is a broad Pester test suite for Microsoft 365 configuration, run in PowerShell, with pass or fail
results per test. nhi-evidence is narrower: one evidence record per identity and issue, with the raw Graph
fields that triggered it, a manual verification step, an OWASP NHI risk, a credential-control path table,
a drift diff between snapshots, an allowlist with reasons, and a token check that stops the run when the
token holds more than read permissions. On owners the two disagree on purpose: Maester MT.1077 says a
privileged app should have no owners; check 1 accepts that, and asks for `serviceManagementReference` as
the accountability record instead, so the app is neither orphaned nor controllable by its owners.

## How this differs from BloodHound

BloodHound builds a full attack graph across Entra and Azure and is the better tool for path analysis.
Check 13 keeps a small graph (owners, four app-management roles, role-assignable groups, three Graph
permissions) so that each path ends in a finding with a named closing control. If you run BloodHound,
use it for paths and use this for the rest.
