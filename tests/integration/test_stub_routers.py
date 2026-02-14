"""Integration tests verifying all stub module endpoints return 501."""
import pytest

STUB_ENDPOINTS = [
    ("POST", "/identity/register"),
    ("POST", "/identity/login"),
    ("GET", "/identity/users/test-id"),
    ("POST", "/identity/refresh"),
    ("POST", "/access/check"),
    ("POST", "/access/policies"),
    ("POST", "/access/roles/assign"),
    ("POST", "/vault/encrypt"),
    ("POST", "/vault/decrypt"),
    ("POST", "/vault/tokenize"),
    ("POST", "/vault/detokenize"),
    ("POST", "/pos/terminals"),
    ("POST", "/pos/transactions"),
    ("GET", "/pos/fraud-alerts"),
    ("POST", "/crm/configs"),
    ("POST", "/crm/sync"),
    ("GET", "/crm/sync/test-id"),
    ("POST", "/backup/snapshots"),
    ("POST", "/backup/restore"),
    ("POST", "/backup/integrity-check"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", STUB_ENDPOINTS)
async def test_stub_returns_501(client, method, path):
    if method == "POST":
        response = await client.post(path, json={})
    else:
        response = await client.get(path)
    assert response.status_code == 501
    data = response.json()
    assert data["code"] == "NOT_IMPLEMENTED"
    assert "error" in data


@pytest.mark.asyncio
async def test_stub_count():
    assert len(STUB_ENDPOINTS) == 20
