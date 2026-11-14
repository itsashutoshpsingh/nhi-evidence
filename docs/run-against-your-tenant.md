# Run it against your own tenant

Every number in this repository comes from synthetic, Graph-shaped fixtures. This page is how to get the
first live result: plant the seeded misconfigurations in a test tenant you own, collect read-only, check,
and clean up. Only ever run it on a tenant you own or have written permission to test; never on an
employer's or client's tenant without that permission.

## 1. A tenant

Any test tenant where you are Global Administrator works:

- a Microsoft 365 developer sandbox, if you can get one (the Microsoft 365 Developer Program restricts who
  qualifies; check its current terms), or
- the Microsoft Entra ID Free tenant that comes with a free Azure account.

What each licence level lets you run:

| Checks | Needs |
|---|---|
| C01, C03 to C11, C13 | Entra ID Free |
| C02 (sign-in activity, beta endpoint) | `AuditLog.Read.All`; reports may need P1 or P2 to return data |
| C14 (sign-in logs) | Entra ID P1 or P2 (Microsoft: required to download sign-in logs through Graph) |
| C12 | reading policies is free; *creating* a workload identity policy needs Workload Identities Premium. On a tenant without it, C12 flags every credentialed, permissioned single-tenant app. Skip it with `check --skip C12`, or read its findings as "no policy exists". |

A P1 or P2 trial covers C02 and C14. Plan it as "seed, wait, collect once during the trial, keep the snapshot".

## 2. The read-only collector app

In the Entra admin center, as Global Administrator:

1. **App registrations > New registration.** Name `nhi-evidence-reader`, single tenant, no redirect URI.
2. **Authentication > Advanced settings > Allow public client flows: Yes** (needed for device code sign-in).
3. **API permissions > Add a permission > Microsoft Graph > Delegated permissions:** `Application.Read.All`,
   `Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`. Remove `User.Read` if you like (it is allowed).
4. **Grant admin consent.**
5. Note the **Directory (tenant) ID** and **Application (client) ID**.

Then, from this repository:

```bash
uv sync --frozen
uv run nhi-evidence whoami  --tenant-id <tenant-id> --client-id <client-id>   # signs in, prints permissions, collects nothing
uv run nhi-evidence collect --tenant-id <tenant-id> --client-id <client-id> --out snapshots/live-1
uv run nhi-evidence check snapshots/live-1 --out out/live-1 --scrub yourlab.onmicrosoft.com
```

Sign in as a user with Global Reader (or Global Administrator). Without a P1 or P2 licence add
`--no-activity` to `collect`; C02 and C14 are then reported as "not run".

App-only instead of a signed-in user: add **Application permissions** with the same four names, grant
consent, upload a certificate, and use `--auth certificate --cert key.pem --thumbprint <thumbprint>`, or
`--auth secret` with the secret in the `NHI_CLIENT_SECRET` environment variable (never on the command line).

To see the write-scope refusal, add `Application.ReadWrite.All` to the app, consent, and run `whoami`
again: it exits with code 3 and names the permission. Remove it afterwards.

## 3. Plant the seeded misconfigurations

Use a **second** app for writing, so the reader never holds write permissions:

1. Register `nhi-evidence-lab-writer`, single tenant.
2. Application permissions: `Application.ReadWrite.All`, `AppRoleAssignment.ReadWrite.All`,
   `DelegatedPermissionGrant.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `User.ReadWrite.All`,
   and `Policy.ReadWrite.ConditionalAccess` if you have Workload Identities Premium (seed S11). Grant consent.
3. Add a client secret with a short lifetime and put it in `NHI_LAB_CLIENT_SECRET`.

```bash
uv run python lab/seed_tenant.py plan                         # the 42 requests it will send, as JSON
uv run python lab/seed_tenant.py apply --tenant-id <id> --client-id <writer-id> --confirm <id> \
    --domain yourlab.onmicrosoft.com
```

Without Workload Identities Premium add `--skip S11`. It refuses unless `--confirm` repeats the tenant ID and the token's `tid` matches it. Every object is named
`nhi-lab-*` and tagged `nhi-evidence-lab`. Client secrets it creates are discarded unread, and the one
certificate it uploads has its private key thrown away, so none of the seeded apps can be signed in to.
Two differences from the fixture tenant: S07 uses Security Reader (labelled privileged by Microsoft)
instead of Privileged Role Administrator, and S09 (a multi-tenant app from an unverified publisher) needs a
second tenant: register a multi-tenant app there and admin-consent to it, with `User.Read.All`, in the
lab tenant. S13 and S14 need time and a P1 or P2 licence: leave an app unused past `unused_days`, and
sign in once to the portal interactively as a user named `svc-...`.

Wait one day (S03's secret is created to expire after one day), then collect and check as in step 2.

### What to expect

Replaying the plan against a simulated Graph (`lab/simulate.py`, result in `results/lab_plan_replay.json`)
gives these 12 findings two days after seeding, and no others:

| Seed | Expected finding |
|---|---|
| S01 | C01 `only_disabled_or_nonhuman_owners` on nhi-lab-reporting-export |
| S02 | C03 `lifetime_over_limit` on nhi-lab-legacy-crm-connector |
| S03 | C04 `expired_present` on nhi-lab-old-billing-api |
| S04 | C05 `secret_only` on nhi-lab-nightly-report-job |
| S05 | C06 `data_graph_permission` on nhi-lab-doc-archiver |
| S06 | C07 `all_principals_sensitive_scope` on nhi-lab-mailmerge |
| S07 | C08 `privileged_directory_role` on nhi-lab-identity-automation |
| S08 | C09 `github_pull_request` on nhi-lab-infra-deployer |
| S10 | C11 `prod_and_nonprod` on nhi-lab-orders-api-ci |
| S11 | C12 `not_in_enforced_policy` on nhi-lab-payroll-export |
| S12 | C06 and C13 on nhi-lab-sharepoint-migrator |

A real tenant will also have Microsoft first-party apps (suppressed, and counted, in the report) and
whatever else you created. The simulation does not model Graph's own validation, such as app management
policies that cap secret lifetimes: if your tenant enforces one, S02 will be refused, which is itself the
control working.

To record the result for the README: copy `out/live-1/findings.json` (already scrubbed) to
`results/live/`, and note the date, licence and any refused seed in `docs/log.md`.

## 4. Clean up

```bash
uv run python lab/seed_tenant.py cleanup --tenant-id <id> --client-id <writer-id> --confirm <id>
```

This deletes every application tagged `nhi-evidence-lab`, every `nhi-lab-*` user and the `nhi-lab-*`
Conditional Access policy, and purges them from deleted items. It stops if a listed object does not carry
the prefix. Then delete the `nhi-evidence-lab-writer` app registration itself, and its secret.

## 5. Before sharing anything

- Run `check` with `--scrub <your domains>`: object IDs and tenant IDs become stable pseudonyms.
- Snapshots contain display names, user principal names and IP addresses from sign-in logs. Keep them out
  of git (`snapshots/` and `out/` are in `.gitignore`).
- Nothing leaves your machine: the tool talks only to `graph.microsoft.com` and `login.microsoftonline.com`.
