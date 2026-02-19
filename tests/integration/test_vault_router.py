"""Integration tests for vault router endpoints."""

from tests.integration.conftest import get_auth_headers


async def test_encrypt_decrypt_roundtrip(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser")
    resp = await integration_client.post(
        "/v1/vault/encrypt",
        json={"plaintext": "top secret", "label": "test", "owner_id": "u1"},
        headers=headers,
    )
    assert resp.status_code == 200
    blob_id = resp.json()["blob_id"]

    resp = await integration_client.post(
        "/v1/vault/decrypt", json={"blob_id": blob_id}, headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["plaintext"] == "top secret"


async def test_decrypt_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser2")
    resp = await integration_client.post(
        "/v1/vault/decrypt", json={"blob_id": "nonexistent"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_tokenize_detokenize_roundtrip(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser3")
    resp = await integration_client.post(
        "/v1/vault/tokenize", json={"value": "4111111111111111"}, headers=headers,
    )
    assert resp.status_code == 200
    token = resp.json()["token"]
    assert token.startswith("tok_")

    resp = await integration_client.post(
        "/v1/vault/detokenize", json={"token": token}, headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["value"] == "4111111111111111"


async def test_tokenize_idempotent(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser4")
    resp1 = await integration_client.post(
        "/v1/vault/tokenize", json={"value": "same"}, headers=headers,
    )
    resp2 = await integration_client.post(
        "/v1/vault/tokenize", json={"value": "same"}, headers=headers,
    )
    assert resp1.json()["token"] == resp2.json()["token"]


async def test_detokenize_not_found(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser5")
    resp = await integration_client.post(
        "/v1/vault/detokenize", json={"token": "tok_nonexistent"}, headers=headers,
    )
    assert resp.status_code == 404


async def test_encrypt_empty_plaintext(integration_client):
    headers = await get_auth_headers(integration_client, "vaultuser6")
    resp = await integration_client.post(
        "/v1/vault/encrypt", json={"plaintext": ""}, headers=headers,
    )
    assert resp.status_code == 422


async def test_vault_requires_auth(integration_client):
    resp = await integration_client.post(
        "/v1/vault/encrypt", json={"plaintext": "secret"},
    )
    assert resp.status_code in (401, 403)
