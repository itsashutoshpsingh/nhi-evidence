# What "loose" means for a federated identity credential (check 9)

How Entra matches: a standard federated identity credential matches the external token's `issuer`,
`subject` and `audience` exactly and case-sensitively (Entra docs, *Workload identity federation*). Only
the preview *flexible federated identity credentials* (beta `claimsMatchingExpression`) accept wildcards,
through the `matches` operator with `*` and `?` (Entra docs, *Flexible federated identity credentials*).
GitHub's subject formats are from GitHub's OIDC reference. Every row below is a test case in
`tests/test_rules.py`; the rules are in `src/nhi_evidence/checks/c09_loose_federation.py`.

| Rule | Example credential | Finding | Why |
|---|---|---|---|
| — | `repo:org/app:environment:production` | none | GitHub environments can require reviewers and branch protection. |
| — | `repo:org/app:ref:refs/heads/main` | none | One branch. |
| — | `repo:org/app:ref:refs/tags/v1.2` | none | One tag. |
| `github_pull_request` | `repo:org/app:pull_request` | medium | Any workflow run triggered by a pull request in the repository gets the identity, before the change is reviewed or merged. |
| `github_subject_never_matches` | `repo:org/app:pull-request` | low | GitHub's subject uses `pull_request`. Microsoft's *Create trust* page lists the hyphenated form (`repo:< Organization/Repository >:pull-request`, entra-docs commit 01f21c9), so a credential copied from it never matches: dead configuration, not exposure. |
| `github_subject_unrecognised` | `repo:org/app` | low | Not an environment, branch, tag or pull-request subject GitHub issues. |
| `literal_wildcard_subject` | `repo:org/*:ref:refs/heads/main` | low | Standard credentials match exactly, so the `*` is literal: it never matches, and the author probably meant a wildcard. |
| `flexible_wildcard_repository` | `claims['sub'] matches 'repo:org/*:ref:refs/heads/main'` | high | Every repository in the organisation, including ones created later. |
| `flexible_wildcard_ref` | `claims['sub'] matches 'repo:org/app:ref:refs/heads/*'` | medium | Any branch, so anyone who can push a branch can sign in as the app. |
| — | `claims['sub'] matches 'repo:org/app:ref:refs/heads/main'` | none | `matches` with no wildcard is an exact match. |
| `kubernetes_default_service_account` | AKS issuer, `system:serviceaccount:default:default` | medium | Any pod that does not name a service account runs as this one. |
| — | AKS issuer, `system:serviceaccount:payments:api` | none | One named service account. |
| `unexpected_issuer` | `https://token.ci.vendor.example` | medium | Not one of the platforms in Microsoft's federation docs (GitHub, GitLab, Terraform Cloud, AKS, Entra, Google, Azure DevOps). Configure `known_issuers` for others you use. |
| `unexpected_issuer` | `https://token.actions.githubusercontent.com.evil.example` | medium | The issuer patterns are anchored, so look-alike hosts do not pass. |
| `non_default_audience` | audience `api://custom` | low | Microsoft documents `api://AzureADTokenExchange` as the audience for Entra. |

Severity is raised to at least high when the app is privileged (checks 6 or 8).

## Not covered

- **Mutable subjects** (repository names that can be renamed and re-registered). Maester's MT.1226 checks
  for GitHub's immutable `repo:owner@id/repo@id` form; I did not repeat it.
- **Custom claims** in flexible expressions (`job_workflow_ref`, `repository_id`) are read only for the
  `sub` part; an expression that pins `repository_id` but wildcards the name is still reported, which
  overstates the risk for that case.
- **Managed identity** federated credentials live in Azure Resource Manager, not Graph.
