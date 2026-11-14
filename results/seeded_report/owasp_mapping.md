# OWASP NHI Top 10 (2025) mapping

Each check maps to the risk whose description it tests. Risk names and links are from the OWASP project at commit 16f8b79.

| Risk | Checks | Findings |
|---|---|---|
| [NHI1 Improper Offboarding](https://owasp.org/www-project-non-human-identities-top-10/2025/1-improper-offboarding/) | C01 No accountable owner; C02 Enabled but unused | 2 |
| [NHI2 Secret Leakage](https://owasp.org/www-project-non-human-identities-top-10/2025/2-secret-leakage/) | none: Secret leakage is outside Graph's view; use a secret scanner on code and CI logs. | 0 |
| [NHI3 Vulnerable Third-Party NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/3-vulnerable-third-party-nhi/) | C10 Unverified third-party app with access | 1 |
| [NHI4 Insecure Authentication](https://owasp.org/www-project-non-human-identities-top-10/2025/4-insecure-authentication/) | C05 Secret where certificate or federation fits; C12 No workload identity Conditional Access | 2 |
| [NHI5 Overprivileged NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/5-overprivileged-nhi/) | C06 High-privilege application permission; C07 Tenant-wide consent to sensitive scopes; C08 Privileged directory role; C13 Credential-control path to a privileged identity | 5 |
| [NHI6 Insecure Cloud Deployment Configurations](https://owasp.org/www-project-non-human-identities-top-10/2025/6-insecure-cloud-deployment-configurations/) | C09 Loose federated credential | 1 |
| [NHI7 Long-Lived Secrets](https://owasp.org/www-project-non-human-identities-top-10/2025/7-long-lived-secrets/) | C03 Long-lived client secret; C04 Expired or duplicate credentials | 2 |
| [NHI8 Environment Isolation](https://owasp.org/www-project-non-human-identities-top-10/2025/8-environment-isolation/) | C11 Identity shared across environments | 1 |
| [NHI9 NHI Reuse](https://owasp.org/www-project-non-human-identities-top-10/2025/9-nhi-reuse/) | C11 Identity shared across environments | 0 |
| [NHI10 Human Use of NHI](https://owasp.org/www-project-non-human-identities-top-10/2025/10-human-use-of-nhi/) | C14 Service account used interactively | 1 |
