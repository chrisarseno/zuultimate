"""Unit tests for SSO service."""

import pytest

from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.sso_service import SSOService


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


async def test_handle_callback_creates_user(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    result = await svc.handle_callback(provider["id"], "authcode123", "state-abc")
    assert "access_token" in result
    assert "refresh_token" in result
    assert result["sso_provider"] == "Google"
    assert "user_id" in result


async def test_handle_callback_idempotent_user(svc):
    provider = await svc.create_provider(
        "Google", "oidc", "https://accounts.google.com", "client-123"
    )
    r1 = await svc.handle_callback(provider["id"], "samecode1", "state1")
    r2 = await svc.handle_callback(provider["id"], "samecode1", "state2")
    assert r1["user_id"] == r2["user_id"]


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
