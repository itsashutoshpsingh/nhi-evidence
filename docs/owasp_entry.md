# Draft entry for the OWASP NHI detection resources index

Not submitted. The guide ties the pull request to a live-tenant result, which does not exist yet (see
[run-against-your-tenant.md](run-against-your-tenant.md)). The row follows the index's entry format and
inclusion criteria as published on 14 November 2026
([detection resources](https://owasp.github.io/www-project-non-human-identities-top-10/2025/detection-resources/)).

| Tool | NHI risk ID(s) | Identity types | Environment(s) | Access | Evidence produced | Blind spots / false positives | Metadata handling | License & maintenance |
|---|---|---|---|---|---|---|---|---|
| [nhi-evidence](https://github.com/itsashutoshpsingh/nhi-evidence) | NHI1, NHI3, NHI4, NHI5, NHI6, NHI7, NHI8, NHI9, NHI10 | App registrations, service principals, managed identities, agent identities, third-party multi-tenant apps, user accounts used as service accounts | Microsoft Entra ID | `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`, optional `AuditLog.Read.All`; read-only, refuses to run if the token holds any other permission | Ownerless or unused apps; long-lived, expired or duplicate secrets; secret-only app-only auth; high-privilege app permissions, all-user consents and directory roles; loose federated credential subjects; unverified third-party apps with access; prod and non-prod sharing one identity; no workload Conditional Access; credential-control paths to privileged service principals; interactive use of service accounts. Each finding carries the triggering Graph fields and a manual verification step | Validated on synthetic Graph-shaped fixtures, not yet a live tenant; agent sponsors unreadable without a write permission; environment check is a naming heuristic; credential-path graph is deliberately small (see BloodHound for depth); Microsoft first-party apps suppressed by owner tenant | Local JSON snapshot and reports; no telemetry; talks only to Microsoft Graph and the Entra token endpoint; `--scrub` pseudonymises IDs and domains | MIT; maintained |

Checklist against the inclusion criteria:

1. OSI licence: MIT.
2. Read-only by default: the collector sends only GET and checks its token; the separate lab seeding
   script writes, and is documented as such.
3. Risk mapping stated: yes, per check, in [owasp-mapping.md](owasp-mapping.md).
4. Metadata handling documented: yes, in [permissions.md](permissions.md) and the runbook.
