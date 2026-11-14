import base64
import json

import pytest

from nhi_evidence import auth


def token(**claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


def test_read_only_application_token_accepted():
    t = token(aud="https://graph.microsoft.com", roles=["Application.Read.All", "Directory.Read.All",
                                                         "Policy.Read.All", "AuditLog.Read.All"])
    assert auth.check_read_only(t) == ["Application.Read.All", "AuditLog.Read.All", "Directory.Read.All",
                                       "Policy.Read.All"]


def test_delegated_read_scopes_accepted():
    t = token(aud="00000003-0000-0000-c000-000000000000", scp="Application.Read.All Directory.Read.All openid profile")
    assert "Directory.Read.All" in auth.check_read_only(t)


@pytest.mark.parametrize("perm", ["Application.ReadWrite.All", "Directory.ReadWrite.All", "Mail.Send",
                                  "AgentIdentity.ReadWrite.All", "Sites.FullControl.All", "Mail.Read"])
def test_anything_else_refused(perm):
    with pytest.raises(auth.WriteScopeError, match=perm.replace(".", r"\.")):
        auth.check_read_only(token(aud="https://graph.microsoft.com", roles=["Application.Read.All", perm]))
    with pytest.raises(auth.WriteScopeError):
        auth.check_read_only(token(aud="https://graph.microsoft.com", scp=f"User.Read {perm}"))


def test_wrong_audience_and_garbage_refused():
    with pytest.raises(auth.WriteScopeError, match="audience"):
        auth.check_read_only(token(aud="https://management.azure.com", roles=["Application.Read.All"]))
    with pytest.raises(auth.WriteScopeError):
        auth.check_read_only("not-a-token")
