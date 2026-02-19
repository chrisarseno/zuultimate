"""Unit tests for CRM provider adapter framework."""

import pytest

from zuultimate.crm.adapters import (
    CRMAdapter,
    GenericAdapter,
    HubSpotAdapter,
    SalesforceAdapter,
    get_adapter,
    list_adapters,
    register_adapter,
)


async def test_salesforce_test_connection():
    adapter = SalesforceAdapter(api_url="https://sf.example.com")
    result = await adapter.test_connection()
    assert result["connected"] is True
    assert result["provider"] == "salesforce"


async def test_salesforce_fetch_contacts():
    adapter = SalesforceAdapter(api_url="https://sf.example.com")
    contacts = await adapter.fetch_contacts(limit=3)
    assert len(contacts) == 3
    assert "Email" in contacts[0]


async def test_salesforce_push_contacts():
    adapter = SalesforceAdapter(api_url="https://sf.example.com")
    result = await adapter.push_contacts([{"name": "Test"}])
    assert result["pushed"] == 1


async def test_salesforce_map_fields():
    adapter = SalesforceAdapter(api_url="https://sf.example.com")
    record = {"FirstName": "John", "LastName": "Doe", "Email": "john@test.com"}
    mappings = {"FirstName": "first_name", "LastName": "last_name"}
    mapped = adapter.map_fields(record, mappings)
    assert mapped == {"first_name": "John", "last_name": "Doe"}


async def test_hubspot_fetch_contacts():
    adapter = HubSpotAdapter(api_url="https://hs.example.com")
    contacts = await adapter.fetch_contacts(limit=2)
    assert len(contacts) == 2
    assert "email" in contacts[0]


async def test_generic_fetch_returns_empty():
    adapter = GenericAdapter(api_url="https://generic.example.com")
    contacts = await adapter.fetch_contacts()
    assert contacts == []


def test_get_adapter_salesforce():
    adapter = get_adapter("salesforce", "https://sf.com")
    assert isinstance(adapter, SalesforceAdapter)


def test_get_adapter_hubspot():
    adapter = get_adapter("hubspot", "https://hs.com")
    assert isinstance(adapter, HubSpotAdapter)


def test_get_adapter_unknown():
    with pytest.raises(ValueError, match="Unknown CRM provider"):
        get_adapter("unknown_provider", "https://x.com")


def test_list_adapters():
    adapters = list_adapters()
    assert "salesforce" in adapters
    assert "hubspot" in adapters
    assert "generic" in adapters


def test_register_custom_adapter():
    class CustomAdapter(CRMAdapter):
        name = "custom"

        async def test_connection(self):
            return {"connected": True}

        async def fetch_contacts(self, limit=100, offset=0):
            return []

        async def push_contacts(self, contacts):
            return {"pushed": 0}

        def map_fields(self, record, mappings):
            return {}

    register_adapter("custom", CustomAdapter)
    adapter = get_adapter("custom", "https://custom.com")
    assert isinstance(adapter, CustomAdapter)
