# nhi-evidence report

Snapshot: synthetic fixture, collected 2026-11-01T00:00:00Z. 15 findings, 5 suppressed by the allowlist.

| Severity | critical | high | medium | low | info |
|---|---|---|---|---|---|
| Findings | 2 | 3 | 7 | 3 | 0 |

## Checks

| Check | OWASP NHI | Findings | Suppressed | Licence / input |
|---|---|---|---|---|
| C01 No accountable owner | NHI1 | 1 | 0 | free |
| C02 Enabled but unused | NHI1 | 1 | 1 | AuditLog.Read.All; beta endpoint |
| C03 Long-lived client secret | NHI7 | 1 | 0 | free |
| C04 Expired or duplicate credentials | NHI7 | 1 | 0 | free |
| C05 Secret where certificate or federation fits | NHI4 | 1 | 0 | free |
| C06 High-privilege application permission | NHI5 | 2 | 1 | free |
| C07 Tenant-wide consent to sensitive scopes | NHI5 | 1 | 1 | free |
| C08 Privileged directory role | NHI5 | 1 | 0 | free |
| C09 Loose federated credential | NHI6 | 1 | 0 | free |
| C10 Unverified third-party app with access | NHI3 | 1 | 2 | free |
| C11 Identity shared across environments | NHI8, NHI9 | 1 | 0 | free |
| C12 No workload identity Conditional Access | NHI4 | 1 | 0 | Workload Identities Premium to create policies; reading is free (Policy.Read.All) |
| C13 Credential-control path to a privileged identity | NHI5 | 1 | 0 | free |
| C14 Service account used interactively | NHI10 | 1 | 0 | AuditLog.Read.All and Entra ID P1 or P2 |

## Findings by identity type

| Identity type | Findings |
|---|---|
| app (this tenant) | 12 |
| app (other tenant) | 2 |
| user | 1 |

## Findings

### [critical] C08 privileged_directory_role: identity-automation

- OWASP: NHI5; object: servicePrincipal `45f6b237-501d-5c1d-953c-d5f09f02ea29` (app (this tenant))
- Evidence: `{"roles": ["Privileged Role Administrator"], "assignments": [{"id": "O3ZOzxyYJeOBKhJbJ7oM0OsWN6WvJIxvlhTiSWwiEW0=", "role": "Privileged Role Administrator", "directoryScopeId": "/"}]}`
- Why it matters: A workload signing in with this role has administrator power over the directory, and service principals cannot do MFA, so the role is only as safe as the app's credentials.
- Verify by hand: Entra admin center > Roles & admins > role > Assignments; GET /v1.0/roleManagement/directory/roleAssignments?$filter=principalId eq '45f6b237-501d-5c1d-953c-d5f09f02ea29'

### [critical] C13 path_from_non_privileged: sharepoint-migrator

- OWASP: NHI5; object: servicePrincipal `5cbd28f9-ba4d-5e7a-a9ff-c3207383caf3` (app (this tenant))
- Evidence: `{"principals_with_path": 1, "shortest_hops": 2}`
- Why it matters: Whoever can add a credential to a privileged service principal can sign in as it and use all of its permissions, so these people and apps are as privileged as the identity itself.
- Verify by hand: For each step: Entra admin center > App registrations > app > Owners; Roles & admins > role > Assignments; Groups > group > Members/Owners. Graph: GET /v1.0/applications/{id}/owners, GET /v1.0/roleManagement/directory/roleAssignments
  - path (2 hops): user Bob Builder -> app sharepoint-migrator -> sp sharepoint-migrator. Close it: Remove this owner; record accountability in serviceManagementReference instead

### [high] C06 data_graph_permission: doc-archiver

- OWASP: NHI5; object: servicePrincipal `015e3144-feb9-5da1-9475-2902d8301dac` (app (this tenant))
- Evidence: `{"permissions": ["Files.ReadWrite.All"], "tier0": []}`
- Why it matters: This identity can read or change every user's data of that kind, with no user present and no MFA.
- Verify by hand: Entra admin center > Enterprise applications > app > Permissions (Admin consent tab); GET /v1.0/servicePrincipals/015e3144-feb9-5da1-9475-2902d8301dac/appRoleAssignments

### [high] C06 data_graph_permission: sharepoint-migrator

- OWASP: NHI5; object: servicePrincipal `5cbd28f9-ba4d-5e7a-a9ff-c3207383caf3` (app (this tenant))
- Evidence: `{"permissions": ["Sites.FullControl.All"], "tier0": []}`
- Why it matters: This identity can read or change every user's data of that kind, with no user present and no MFA.
- Verify by hand: Entra admin center > Enterprise applications > app > Permissions (Admin consent tab); GET /v1.0/servicePrincipals/5cbd28f9-ba4d-5e7a-a9ff-c3207383caf3/appRoleAssignments

### [high] C07 all_principals_sensitive_scope: MailMerge Pro

- OWASP: NHI5; object: servicePrincipal `f1a1ef19-4045-5101-bd9b-94c20d222d9c` (app (other tenant))
- Evidence: `{"grantId": "gjInqhqGYR7cU719YbfoJpZzhlTePC32Cwp3qI5TweE=", "consentType": "AllPrincipals", "sensitive_scopes": ["Files.ReadWrite.All", "Mail.Read"], "scope": "openid profile User.Read Mail.Read Files.ReadWrite.All"}`
- Why it matters: Consent for all users lets this app act as any user who signs in to it, over that user's mail, files or directory data, without each user being asked.
- Verify by hand: Entra admin center > Enterprise applications > app > Permissions (Admin consent tab); GET /v1.0/oauth2PermissionGrants?$filter=clientId eq 'f1a1ef19-4045-5101-bd9b-94c20d222d9c'

### [medium] C01 only_disabled_or_nonhuman_owners: reporting-export

- OWASP: NHI1; object: application `1703235f-b665-5109-b8a2-1dd25b227262` (app (this tenant))
- Evidence: `{"owners": [{"id": "bec5df5a-f42d-53e0-a24b-762597740358", "type": "#microsoft.graph.user", "accountEnabled": false}], "serviceManagementReference": null}`
- Why it matters: Nobody is accountable for this app: no one will rotate its credentials, review its permissions or retire it, and a forgotten app keeps working for whoever holds its credentials.
- Verify by hand: Entra admin center > App registrations > All applications > app > Owners; GET /v1.0/applications/1703235f-b665-5109-b8a2-1dd25b227262/owners

### [medium] C02 stale_sign_in: survey-importer

- OWASP: NHI1; object: servicePrincipal `e8363b95-3036-5f64-a3a5-9983c7062cca` (app (this tenant))
- Evidence: `{"lastSignInDateTime": "2026-04-15T00:00:00+00:00", "days_threshold": 90, "appRoleAssignments": 1, "directoryRoles": 0}`
- Why it matters: Permissions nobody uses are pure exposure: the identity can still be signed in as, but nothing would break if it were disabled.
- Verify by hand: Entra admin center > Monitoring > Usage & insights > Service principal sign-in activity; GET /beta/reports/servicePrincipalSignInActivities?$filter=appId eq '61ae76dd-1d42-5deb-8be5-063057b1cacc'

### [medium] C05 secret_only: nightly-report-job

- OWASP: NHI4; object: application `5b21188f-e267-5ab5-80e2-6340c00adcbc` (app (this tenant))
- Evidence: `{"active_secrets": 1, "active_certificates": 0, "federated_credentials": 0, "application_permissions": 1, "directory_roles": 0}`
- Why it matters: A client secret is a shared password that can be pasted anywhere; a certificate key can be kept non-exportable, and federation removes the stored credential altogether.
- Verify by hand: Entra admin center > App registrations > app > Certificates & secrets (Client secrets, Certificates, Federated credentials tabs); GET /v1.0/applications/5b21188f-e267-5ab5-80e2-6340c00adcbc/federatedIdentityCredentials

### [medium] C09 github_pull_request: infra-deployer

- OWASP: NHI6; object: application `2c339056-3f55-5d2a-9e74-5def96e73917` (app (this tenant))
- Evidence: `{"credential": "gh-infra", "issuer": "https://token.actions.githubusercontent.com", "subject": "repo:lab-org/infra:pull_request", "claimsMatchingExpression": null, "audiences": ["api://AzureADTokenExchange"], "reason": "trusts any workflow run for a pull request in this repository, before review"}`
- Why it matters: A federated credential lets an outside workload sign in as this app with no secret; the subject is the only thing that decides which workload, so a loose subject hands the app's permissions to more code than intended.
- Verify by hand: Entra admin center > App registrations > app > Certificates & secrets > Federated credentials; GET /beta/applications/2c339056-3f55-5d2a-9e74-5def96e73917/federatedIdentityCredentials

### [medium] C10 unverified_publisher_with_access: QuickSurvey

- OWASP: NHI3; object: servicePrincipal `03d968df-7ea7-5aba-bec6-4bef81060828` (app (other tenant))
- Evidence: `{"appOwnerOrganizationId": "78e334d4-e8e7-52f0-843b-98b326ad816c", "verifiedPublisher": {"displayName": null, "verifiedPublisherId": null, "addedDateTime": null}, "application_permissions": ["User.Read.All"], "tenant_wide_delegated_scopes": []}`
- Why it matters: Another organisation controls this app's code and credentials, and Microsoft has not verified who they are; if they are breached, their access to your tenant goes with it.
- Verify by hand: Entra admin center > Enterprise applications > app > Properties (Publisher) and Permissions; GET /v1.0/servicePrincipals/03d968df-7ea7-5aba-bec6-4bef81060828?$select=appOwnerOrganizationId,verifiedPublisher

### [medium] C11 prod_and_nonprod: orders-api-ci

- OWASP: NHI8; object: application `64e9ec4d-d1ff-5047-bbd7-6b933de7f2a2` (app (this tenant))
- Evidence: `{"prod": ["repo:lab-org/orders:environment:production"], "nonprod": ["repo:lab-org/orders:environment:dev"], "review": true}`
- Why it matters: If the same identity serves test and production, a compromise of the weaker test pipeline or host reaches production data.
- Verify by hand: Entra admin center > App registrations > app > Authentication and Certificates & secrets > Federated credentials; GET /v1.0/applications/64e9ec4d-d1ff-5047-bbd7-6b933de7f2a2?$select=web,identifierUris

### [medium] C14 interactive_service_account: svc-backup

- OWASP: NHI10; object: user `22dc1af0-e8f2-5559-946d-80e49575ac1c` (user)
- Evidence: `{"userPrincipalName": "svc-backup@lab.example", "interactive_sign_ins": 1, "apps": ["Azure Portal"], "clientAppUsed": ["Browser"], "first": "2026-10-28T00:00:00Z", "last": "2026-10-28T00:00:00Z"}`
- Why it matters: When a person signs in as a service account, its actions can no longer be told apart from the automation's, and the account's standing access becomes that person's.
- Verify by hand: Entra admin center > Monitoring > Sign-in logs (filter: user, Interactive); GET /v1.0/auditLogs/signIns?$filter=userId eq '22dc1af0-e8f2-5559-946d-80e49575ac1c'

### [low] C03 lifetime_over_limit: legacy-crm-connector

- OWASP: NHI7; object: application `f9f8da14-8c1a-50ac-9905-ad2a8afc2a44` (app (this tenant))
- Evidence: `{"keyId": "9b6302e6-7d46-5ec4-826d-df870b2a84fd", "startDateTime": "2026-07-24T00:00:00Z", "endDateTime": "2028-07-23T00:00:00Z", "lifetime_days": 730.0, "limit_days": 180, "on": "application"}`
- Why it matters: A secret that stays valid for years gives anyone who copies it years of access; short lifetimes force rotation and limit the damage of a leak.
- Verify by hand: Entra admin center > App registrations > app > Certificates & secrets; GET /v1.0/applications/f9f8da14-8c1a-50ac-9905-ad2a8afc2a44?$select=passwordCredentials

### [low] C04 expired_present: old-billing-api

- OWASP: NHI7; object: application `94aa3869-1477-524a-a0f3-93ee8ce2d30f` (app (this tenant))
- Evidence: `{"expired": [{"type": "password", "keyId": "8e011058-a7d7-5a67-ac25-11bf979fa14f", "endDateTime": "2026-10-02T00:00:00Z"}]}`
- Why it matters: Expired credentials left in place show nobody is managing this identity's lifecycle and hide which credential is really in use.
- Verify by hand: Entra admin center > App registrations > app > Certificates & secrets; GET /v1.0/applications/94aa3869-1477-524a-a0f3-93ee8ce2d30f?$select=passwordCredentials,keyCredentials

### [low] C12 not_in_enforced_policy: payroll-export

- OWASP: NHI4; object: servicePrincipal `e68b661c-0e21-51cf-ac0e-bcb286150d55` (app (this tenant))
- Evidence: `{"enforced_policies": 1}`
- Why it matters: Without a workload identity policy a stolen credential works from any network; a location or risk policy is the control that limits where the app can sign in from.
- Verify by hand: Entra admin center > Conditional Access > Policies (Assignments > Workload identities); GET /v1.0/identity/conditionalAccess/policies

## Suppressed

| Check | Object | Reason |
|---|---|---|
| C02 no_sign_in | Microsoft Azure CLI | Microsoft first-party app (appOwnerOrganizationId f8cdef31-a31e-4b4a-93e4-5f571e91255a) |
| C06 data_graph_permission | BackupVault Cloud | Approved vendor backup service: security review SR-2291, re-review due 2027-01 |
| C07 all_principals_sensitive_scope | Microsoft Azure CLI | Microsoft first-party app (appOwnerOrganizationId f8cdef31-a31e-4b4a-93e4-5f571e91255a) |
| C10 unverified_publisher_with_access | Microsoft Azure CLI | Microsoft first-party app (appOwnerOrganizationId f8cdef31-a31e-4b4a-93e4-5f571e91255a) |
| C10 unverified_publisher_with_access | BackupVault Cloud | Approved vendor backup service: security review SR-2291, re-review due 2027-01 |
