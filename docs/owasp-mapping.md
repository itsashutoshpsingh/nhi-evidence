# Mapping to the OWASP Non-Human Identities Top 10 (2025)

Risk IDs, names and the quoted descriptions are from the OWASP project's
[2025 list](https://owasp.org/www-project-non-human-identities-top-10/2025/top-10-2025/), read from the
project repository at commit
[`16f8b79`](https://github.com/OWASP/www-project-non-human-identities-top-10/tree/16f8b79394662c6467eb7a1907b6af7e209b1fd9)
(`scripts/fetch_refs.py` stores the names and links in `src/nhi_evidence/data/owasp_nhi.json`). The
mapping is mine: each check is placed under the risk whose description names the condition it tests.
The generated table with finding counts is `results/seeded_report/owasp_mapping.md`.

| Check | Risk | The OWASP description it tests (quoted) | Why this risk and not another |
|---|---|---|---|
| C01 No accountable owner | [NHI1 Improper Offboarding](https://owasp.org/www-project-non-human-identities-top-10/2025/1-improper-offboarding/) | "inadequate deactivation or removal of non-human identities ... when they are no longer needed. Unmonitored and deprecated services may remain vulnerable" | An app with no enabled owner is the unmonitored service: nobody is there to remove it. |
| C02 Enabled but unused | NHI1 | same | Enabled, permissioned, and not used for 90 days is the textbook "no longer needed". |
| C03 Long-lived client secret | [NHI7 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/) | "expiration dates that are too far in the future or that don't expire at all" | Direct match: lifetime over 180 days or no end date. |
| C04 Expired or duplicate credentials | NHI7 | same | Several active secrets and stale expired ones are what a missed rotation leaves behind; it is a lifetime-management failure, so NHI7 rather than NHI1. |
| C05 Secret where certificate or federation fits | [NHI4 Insecure Authentication](https://owasp.org/www-project-non-human-identities-top-10/2025/4-insecure-authentication/) | "some authentication methods are deprecated, vulnerable to known attacks, or considered weak due to outdated security practices" | A shared-secret client credential is the weaker of the three methods Entra offers for app-only sign-in. |
| C06 High-privilege application permission | [NHI5 Overprivileged NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/5-overprivileged-nhi/) | "assign NHIs with significantly more privileges than required for their function" | Tenant-wide app-only permissions are the largest grants an app can hold. |
| C07 Tenant-wide consent to sensitive scopes | NHI5 | same | All-user consent multiplies a delegated scope by every user. |
| C08 Privileged directory role | NHI5 | same | Directory roles on a workload are administrator power without MFA. |
| C09 Loose federated credential | [NHI6 Insecure Cloud Deployment Configurations](https://owasp.org/www-project-non-human-identities-top-10/2025/6-insecure-cloud-deployment-configurations/) | "While OIDC offers a more secure alternative, if the identity tokens are not properly validated or there are no strict conditions on token claims unauthorized users might exploit these weaknesses" | A loose subject is exactly "no strict conditions on token claims" for CI/CD OIDC. |
| C10 Unverified third-party app with access | [NHI3 Vulnerable Third-Party NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/3-vulnerable-third-party-nhi/) | "If a third-party extension is compromised ... it can be exploited to steal these credentials or misuse the granted permissions" | A multi-tenant app holding access in your tenant is a third-party NHI; an unverified publisher is one you cannot vet. |
| C11 Identity shared across environments | [NHI8 Environment Isolation](https://owasp.org/www-project-non-human-identities-top-10/2025/8-environment-isolation/), [NHI9 NHI Reuse](https://owasp.org/www-project-non-human-identities-top-10/2025/9-nhi-reuse/) | NHI8: "reusing the same NHIs across multiple environments—especially between testing and production"; NHI9: "Reusing the same NHI across different applications, services, or components" | Rule `prod_and_nonprod` is NHI8; rule `multiple_workloads` (one app trusted by several repositories or service accounts) is NHI9. |
| C12 No workload identity Conditional Access | NHI4 | "Utilizing insecure or obsolete authentication mechanisms can expose organizations to significant risks" | Without a location or risk policy a stolen credential authenticates from anywhere. This is the weakest mapping in the table: OWASP's text is about the method, not the controls around it. NHI5 was the alternative; I kept NHI4 because the control acts at sign-in. |
| C13 Credential-control path | NHI5 | "When an over-privileged NHI is compromised ... attackers can exploit the excessive permissions" | The path makes the people and apps that can add a credential as privileged as the identity. |
| C14 Service account used interactively | [NHI10 Human Use of NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/10-human-use-of-nhi/) | "developers or administrators may misuse NHIs for manual tasks that should be performed using individual human identities" | Direct match. |
| none | [NHI2 Secret Leakage](https://owasp.org/www-project-non-human-identities-top-10/2025/2-secret-leakage/) | "hard-coded into source code, stored in plain text configuration files, or sent over public chat applications" | Graph never returns secret values, so leakage has to be looked for where secrets end up, with a secret scanner. |

Severity is separate from the mapping: hygiene findings (C01 to C05, C09, C10, C12) on an identity that
checks 6 or 8 flag are raised to at least high, following the guide's point that secret age matters most
on privileged apps.
