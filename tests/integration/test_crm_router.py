"""Integration tests for CRM router endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_config_and_sync_flow(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser")
    resp = await integration_client.post(
        "/v1/crm/configs",
        json={"provider": "salesforce", "api_url": "https://sf.example.com"},
        headers=headers,
    )
    assert resp.status_code == 200
    config = resp.json()
    assert config["provider"] == "salesforce"
    assert config["is_active"] is True

    # Start sync
    resp = await integration_client.post(
        "/v1/crm/sync", json={"config_id": config["id"]}, headers=headers,
    )
    assert resp.status_code == 200
    job = resp.json()
    assert job["status"] == "pending"

    # Get sync status
    resp = await integration_client.get(
        f"/v1/crm/sync/{job['id']}", headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["config_id"] == config["id"]


async def test_sync_nonexistent_config(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser2")
    resp = await integration_client.post(
        "/v1/crm/sync", json={"config_id": "nonexistent"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_sync_status_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser3")
    resp = await integration_client.get(
        "/v1/crm/sync/nonexistent", headers=headers,
    )
    assert resp.status_code == 404


async def test_create_config_validation(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser4")
    resp = await integration_client.post(
        "/v1/crm/configs", json={"provider": ""}, headers=headers,
    )
    assert resp.status_code == 422


async def test_multiple_configs(integration_client):
    headers = await get_auth_headers(integration_client, "crmuser5")
    resp1 = await integration_client.post(
        "/v1/crm/configs", json={"provider": "salesforce"}, headers=headers,
    )
    resp2 = await integration_client.post(
        "/v1/crm/configs", json={"provider": "hubspot"}, headers=headers,
    )
    assert resp1.json()["id"] != resp2.json()["id"]


async def test_crm_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/crm/configs", json={"provider": "test"},
    )
    assert resp.status_code in (401, 403)
