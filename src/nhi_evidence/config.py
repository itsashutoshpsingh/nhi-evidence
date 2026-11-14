"""Check thresholds and permission lists. Override any key with `--config file.json`."""

import copy
import json
from pathlib import Path

DEFAULTS = {
    "max_secret_days": 180,  # check 3
    "unused_days": 90,  # check 2; matches the Entra "Remove unused applications" recommendation
    # check 6: application permissions on Microsoft Graph. tier0 = can reach Global Administrator
    # (directly, or by adding credentials to apps or granting itself roles); data = tenant-wide data access.
    "graph_tier0": [
        "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Application.ReadWrite.All",
        "Directory.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess", "UserAuthenticationMethod.ReadWrite.All",
        "Domain.ReadWrite.All", "DelegatedPermissionGrant.ReadWrite.All",
        "RoleAssignmentSchedule.ReadWrite.Directory", "ServicePrincipalEndpoint.ReadWrite.All",
    ],
    "graph_data": [
        "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All",
        "Sites.ReadWrite.All", "Sites.FullControl.All", "User.ReadWrite.All", "Group.ReadWrite.All",
        "GroupMember.ReadWrite.All", "Chat.Read.All", "Calendars.ReadWrite", "Application.ReadWrite.OwnedBy",
    ],
    # check 7: delegated scopes that matter when consented for every user (AllPrincipals)
    "sensitive_delegated": [
        "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Files.Read.All", "Files.ReadWrite.All", "Sites.Read.All",
        "Sites.ReadWrite.All", "Sites.FullControl.All", "Directory.ReadWrite.All", "Directory.AccessAsUser.All",
        "User.ReadWrite.All", "Group.ReadWrite.All", "Application.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory", "AppRoleAssignment.ReadWrite.All", "Calendars.ReadWrite",
        "Chat.Read", "Chat.ReadWrite", "Notes.ReadWrite.All", "MailboxSettings.ReadWrite",
    ],
    "basic_delegated": ["openid", "profile", "email", "offline_access", "User.Read"],
    # check 8: Microsoft's "privileged" label (roleDefinitions.isPrivileged, or the role docs) decides;
    # these are critical because they reach Global Administrator in one step
    "critical_roles": ["Global Administrator", "Privileged Role Administrator",
                       "Privileged Authentication Administrator"],
    # check 9: issuers seen in Microsoft's workload identity federation docs
    "known_issuers": [
        r"^https://token\.actions\.githubusercontent\.com/?$",
        r"^https://gitlab\.[a-z0-9.-]+/?$",
        r"^https://app(\.eu)?\.terraform\.io/?$",
        r"^https://[a-z0-9-]+\.oic\.prod-aks\.azure\.com/[0-9a-f-]+/[0-9a-f-]+/?$",
        r"^https://login\.microsoftonline\.com/[0-9a-f-]{36}/v2\.0/?$",
        r"^https://sts\.windows\.net/[0-9a-f-]{36}/?$",
        r"^https://accounts\.google\.com/?$",
        r"^https://vstoken\.dev\.azure\.com/[0-9a-f-]{36}/?$",
    ],
    # check 11: environment words in FIC subjects and redirect hosts
    "nonprod_words": ["dev", "development", "test", "testing", "qa", "uat", "stage", "staging", "sandbox",
                      "nonprod", "preprod"],
    "prod_words": ["prod", "production", "prd"],
    # check 14: user accounts that are service accounts (regex on the UPN local part), plus explicit IDs
    "service_account_pattern": r"^(svc|sa|service|app|bot|automation|sync|batch)[-_.]",
    "service_account_ids": [],
}


def load(path: str | Path | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULTS)
    if path:
        cfg.update(json.loads(Path(path).read_text()))
    return cfg
