"""Unit tests for SSO service."""

import pytest
from unittest.mock import AsyncMock, patch

import httpx

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.sso_service import SSOService

_FAKE_REQUEST = httpx.Request("POST", "https://test.com/token")


@pytest.fixture
def svc(test_db, test_settings):
    return SSOService(test_db, test_settings)


async def test_create_oidc_provider(svc):
    result = await svc.create_provider(
        name="Google",
        protocol="oidc",
        issuer_url="https://accounts.google.com",
        client_id="client-123",
        client_secret="secret-456",
    )
    assert result["name"] == "Google"
    assert result["protocol"] == "oidc"
    assert result["client_id"] == "client-123"
    assert result["is_active"] is True
    assert "id" in result


async def test_create_saml_provider(svc):
    result = await svc.create_provider(
        name="Okta",
        protocol="saml",
        issuer_url="https://okta.example.com",
        client_id="saml-entity-id",
        metadata_url="https://okta.example.com/metadata",
    )
    assert result["protocol"] == "saml"
    assert result["metadata_url"] == "https://okta.example.com/metadata"


async def test_create_provider_invalid_protocol(svc):
    with pytest.raises(ValidationError, match="Protocol"):
        await svc.create_provider(
            name="Bad", protocol="ldap", issuer_url="x", client_id="y"
        )


async def test_list_providers(svc):
    await svc.create_provider("P1", "oidc", "https://a.com", "c1")
    await svc.create_provider("P2", "saml", "https://b.com", "c2")
    providers = await svc.list_providers()
    assert len(providers) == 2


async def test_list_providers_filter_tenant(svc):
    await svc.create_provider("P1", "oidc", "https://a.com", "c1", tenant_id="t1")
    await svc.create_provider("P2", "oidc", "https://b.com", "c2", tenant_id="t2")
    providers = await svc.list_providers(tenant_id="t1")
    assert len(providers) == 1
    assert providers[0]["name"] == "P1"


async def test_get_provider(svc):
    created = await svc.create_provider("Google", "oidc", "https://google.com", "c1")
    result = await svc.get_provider(created["id"])
    assert result["name"] == "Google"


async def test_get_provider_not_found(svc):
    with pytest.raises(NotFoundError):
        await svc.get_provider("nonexistent")


async def test_initiate_oidc_login(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    result = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")
    assert "redirect_url" in result
    assert "accounts.google.com/authorize" in result["redirect_url"]
    assert "client_id=client-123" in result["redirect_url"]
    assert len(result["state"]) == 32


async def test_initiate_saml_login(svc):
    provider = await svc.create_provider(
        "Okta", "saml", "https://okta.example.com", "entity-id"
    )
    result = await svc.initiate_login(provider["id"], "http://localhost:3000/callback")
    assert "okta.example.com/sso" in result["redirect_url"]


def _mock_token_response(email="sso-user@google.com", name="SSO User"):
    """Build a mock OIDC token exchange response."""
    return httpx.Response(200, json={
        "access_token": "idp-access-token",
        "token_type": "Bearer",
        "email": email,
        "preferred_username": email.split("@")[0],
        "name": name,
    }, request=_FAKE_REQUEST)


async def test_handle_callback_creates_user(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="secret-456",
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_mock_token_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        result = await svc.handle_callback(provider["id"], "authcode123", "state-abc")
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["sso_provider"] == "Google"
    assert "user_id" in result


async def test_handle_callback_idempotent_user(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="secret-456",
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=_mock_token_response())
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        r1 = await svc.handle_callback(provider["id"], "samecode1", "state1")
        r2 = await svc.handle_callback(provider["id"], "samecode1", "state2")
    assert r1["user_id"] == r2["user_id"]


async def test_handle_callback_token_exchange_failure(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    error_response = httpx.Response(
        400, json={"error": "invalid_grant"}, request=_FAKE_REQUEST,
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=error_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="token exchange failed"):
            await svc.handle_callback(provider["id"], "badcode", "state")


async def test_handle_callback_network_error(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="network error"):
            await svc.handle_callback(provider["id"], "code", "state")


async def test_handle_callback_missing_email(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    response = httpx.Response(200, json={"access_token": "tok"}, request=_FAKE_REQUEST)
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        with pytest.raises(ValidationError, match="email"):
            await svc.handle_callback(provider["id"], "code", "state")


async def test_handle_callback_with_id_token(svc):
    """Verify user info is extracted from JWT id_token."""
    import base64
    import json as _json
    # Construct a fake JWT with email in payload
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        _json.dumps({"email": "jwt@google.com", "name": "JWT User", "sub": "12345"}).encode()
    ).rstrip(b"=").decode()
    fake_jwt = f"{header}.{payload}.fakesignature"

    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123",
        client_secret="s",
    )
    response = httpx.Response(200, json={"id_token": fake_jwt}, request=_FAKE_REQUEST)
    with patch("zuultimate.identity.sso_service.httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        result = await svc.handle_callback(provider["id"], "code", "state")
    assert result["user_id"]
    assert result["sso_provider"] == "Google"


def test_extract_user_info_from_top_level():
    """_extract_user_info works with top-level fields."""
    email, username, name = SSOService._extract_user_info({
        "email": "a@b.com",
        "preferred_username": "auser",
        "name": "A B",
    })
    assert email == "a@b.com"
    assert username == "auser"
    assert name == "A B"


def test_extract_user_info_empty():
    email, username, name = SSOService._extract_user_info({})
    assert email == ""
    assert username == ""
    assert name == ""


async def test_deactivate_provider(svc):
    provider = await svc.create_provider("Tmp", "oidc", "https://x.com", "c1")
    result = await svc.deactivate_provider(provider["id"])
    assert result["is_active"] is False

    # Should not appear in list
    providers = await svc.list_providers()
    assert len(providers) == 0


async def test_deactivate_nonexistent(svc):
    with pytest.raises(NotFoundError):
        await svc.deactivate_provider("nonexistent")
