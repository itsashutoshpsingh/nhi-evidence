# Permissions

The collector needs four read permissions on Microsoft Graph. It checks its own token before the first
request and refuses to run if the token carries anything else (`src/nhi_evidence/auth.py`).

| Permission | Type | Why |
|---|---|---|
| `Application.Read.All` | delegated or application | applications, service principals, their owners, federated credentials, app role assignments |
| `Directory.Read.All` | delegated or application | users, role-assignable groups and their members and owners, delegated permission grants, directory role assignments and definitions |
| `Policy.Read.All` | delegated or application | Conditional Access policies (check 12) |
| `AuditLog.Read.All` | delegated or application | service principal sign-in activity (check 2) and sign-in logs (check 14). Optional: run `collect --no-activity` without it |

With delegated permissions (device code sign-in) the signed-in user also needs a directory role that can
read these objects, such as Global Reader. Graph returns only what both the token and the user's role allow.

## Every request the collector sends

All requests are `GET`. API versions are pinned per call and recorded in the snapshot's `manifest.json`.
Least-privileged permission is quoted from the Microsoft Graph docs at commit
[`2329b08`](https://github.com/microsoftgraph/microsoft-graph-docs-contrib/tree/2329b086341e67d36de55a5743af1a47224046ca)
(the generated `includes/permissions/*-permissions.md` files).

| Request | Version | Least privileged (application) | Feeds |
|---|---|---|---|
| `GET /organization?$select=id` | v1.0 | covered by `Directory.Read.All` | tenant ID for "home tenant" tests |
| `GET /applications?$select=...&$top=999` | v1.0 | `Application.Read.All` | checks 1, 3, 4, 5, 9, 11 |
| `GET /applications/{id}/owners` | v1.0 | `Application.Read.All` | checks 1, 13 |
| `GET /applications/{id}/federatedIdentityCredentials` | **beta** | `Application.Read.All` | checks 9, 11 (beta returns `claimsMatchingExpression`, the preview flexible credentials) |
| `GET /servicePrincipals?$select=...&$top=999` | v1.0 | `Application.Read.All` | all checks |
| `GET /servicePrincipals/{id}/owners` | v1.0 | `Application.Read.All` | check 13 |
| `GET /servicePrincipals/{id}/appRoleAssignments` | v1.0 | `Application.Read.All` | checks 2, 5, 6, 10, 12, 13 |
| `GET /oauth2PermissionGrants` | v1.0 | `Directory.Read.All` | checks 7, 10 |
| `GET /roleManagement/directory/roleDefinitions` | v1.0 | `RoleManagement.Read.Directory` (covered by `Directory.Read.All`) | check 8 (`isPrivileged`) |
| `GET /roleManagement/directory/roleAssignments` | v1.0 | `RoleManagement.Read.Directory` (covered by `Directory.Read.All`) | checks 8, 13 |
| `GET /users?$select=...&$top=999` | v1.0 | covered by `Directory.Read.All` | checks 1, 13, 14 |
| `GET /groups?$filter=isAssignableToRole eq true` | v1.0 | covered by `Directory.Read.All` | check 13 |
| `GET /groups/{id}/members`, `/groups/{id}/owners` | v1.0 | `GroupMember.ReadBasic.All` / `GroupMember.Read.All` (covered by `Directory.Read.All`) | check 13 |
| `GET /identity/conditionalAccess/policies` | v1.0 | `Policy.Read.All` | check 12 |
| `GET /reports/servicePrincipalSignInActivities` | **beta** | `AuditLog.Read.All` | check 2 |
| `GET /auditLogs/signIns?$filter=createdDateTime ge ...` | v1.0 | `AuditLog.Read.All`; Microsoft: "You must have a Microsoft Entra ID P1 or P2 license" | check 14 |

Paging: every list follows `@odata.nextLink` to the end. Throttling: 429, 503 and 504 are retried after the
`Retry-After` header, as Microsoft's throttling guidance says, with exponential backoff (1, 2, 4 ... 60 s)
when the header is missing. Both are tested against the in-process Graph mock (`tests/test_collect.py`).

Two quirks in the docs at that commit: the `group-list` include names `Group-NestingSupport.ReadWrite.All`
as least privileged for listing groups (a write permission; `Directory.Read.All` is listed as sufficient),
and the `user-list` include file was not present. Neither changes the permission set above.

## What the collector cannot read

- **Agent identity sponsors.** `GET /servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors` lists
  `AgentIdentity.ReadWrite.All` as the only application permission, and delegated is "Not supported". The
  read-only check refuses that permission, so live snapshots have no sponsors and check 1's agent rule
  (`agent_no_sponsor`) does not run on them. In the synthetic runs this loses 1 to 35 planted findings per
  tenant (`results/collect_cost.csv`, column `missed_agent_no_sponsor`).
- **Secret values.** Graph never returns them after creation (`passwordCredential.secretText` is only in
  the `addPassword` response), so NHI2 Secret Leakage is out of scope.
- **Azure RBAC.** Role assignments on subscriptions and resources live in Azure Resource Manager, not Graph.

## The token check

`auth.check_read_only` decodes the access token's payload (it does not verify the signature: Graph does
that) and reads `roles` (application permissions) and `scp` (delegated scopes). It refuses when:

- the audience is not Microsoft Graph, or
- any permission is outside this allowlist: `Application.Read.All`, `Directory.Read.All`, `Policy.Read.All`,
  `AuditLog.Read.All`, `RoleManagement.Read.Directory`, `RoleManagement.Read.All`, `User.Read.All`,
  `Group.Read.All`, `GroupMember.Read.All`, `Organization.Read.All`, `AgentIdentity.Read.All`, `User.Read`,
  `openid`, `profile`, `email`, `offline_access`.

An allowlist refuses read permissions it does not need too (for example `Mail.Read`), which is the point:
the tool should hold exactly what it uses. Try it with `nhi-evidence whoami`.

## The writing script

`lab/seed_tenant.py` is the only code that writes, and only to a tenant you name twice (`--tenant-id` and
`--confirm`) whose ID also matches the token's `tid` claim. It needs a separate app with
`Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`,
`RoleManagement.ReadWrite.Directory`, `User.ReadWrite.All` and, for S11 only, `Policy.ReadWrite.ConditionalAccess`.
Delete that app when you are done. See [run-against-your-tenant.md](run-against-your-tenant.md).
