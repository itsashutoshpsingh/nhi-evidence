"""Get a Microsoft Graph token with MSAL and refuse to continue if it carries anything but read permissions.

The token is decoded only to read its `roles` (application permissions) and `scp` (delegated scopes)
claims; it is never verified here (Graph does that) and never written to disk or printed.
"""

import base64
import json
import os

GRAPH_AUDIENCES = {"https://graph.microsoft.com", "https://graph.microsoft.com/",
                   "00000003-0000-0000-c000-000000000000"}
# Every permission the collector may hold. Anything else, read or write, is refused: an allowlist is
# safer than trying to recognise every write permission by name.
READ_ONLY = {
    "Application.Read.All", "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All",
    "RoleManagement.Read.Directory", "RoleManagement.Read.All", "User.Read.All", "Group.Read.All",
    "GroupMember.Read.All", "Organization.Read.All", "AgentIdentity.Read.All",
    "User.Read", "openid", "profile", "email", "offline_access",
}
COLLECTOR_SCOPES = ["Application.Read.All", "Directory.Read.All", "Policy.Read.All", "AuditLog.Read.All"]


class WriteScopeError(RuntimeError):
    pass


def claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError) as e:
        raise WriteScopeError("not a JWT access token; refusing to continue") from e


def permissions(c: dict) -> list[str]:
    return sorted(set(c.get("roles", [])) | set((c.get("scp") or "").split()))


def check_read_only(token: str) -> list[str]:
    """Return the token's permissions, or raise WriteScopeError if any is not on the read-only list."""
    c = claims(token)
    if c.get("aud") not in GRAPH_AUDIENCES:
        raise WriteScopeError(f"token audience {c.get('aud')!r} is not Microsoft Graph")
    perms = permissions(c)
    extra = [p for p in perms if p not in READ_ONLY]
    if extra:
        raise WriteScopeError(
            "refusing to run: the token carries permissions outside the read-only set: " + ", ".join(extra)
            + ". Remove them from the app registration (or consent) and try again.")
    return perms


def acquire(tenant_id: str, client_id: str, mode: str = "device", cert_path: str | None = None,
            thumbprint: str | None = None) -> str:  # pragma: no cover - needs a live tenant
    """mode: 'device' (delegated, signed-in user), 'secret' (NHI_CLIENT_SECRET env var) or 'certificate'."""
    import msal

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    if mode == "device":
        app = msal.PublicClientApplication(client_id, authority=authority)
        flow = app.initiate_device_flow(scopes=[f"https://graph.microsoft.com/{s}" for s in COLLECTOR_SCOPES])
        if "user_code" not in flow:
            raise RuntimeError(f"device flow failed: {flow.get('error_description')}")
        print(flow["message"], flush=True)
        result = app.acquire_token_by_device_flow(flow)
    else:
        if mode == "secret":
            cred = os.environ.get("NHI_CLIENT_SECRET")
            if not cred:
                raise RuntimeError("set NHI_CLIENT_SECRET in the environment (never on the command line)")
        else:
            with open(cert_path) as f:
                cred = {"private_key": f.read(), "thumbprint": thumbprint}
        app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=cred)
        result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(f"token request failed: {result.get('error')}: {result.get('error_description')}")
    return result["access_token"]
