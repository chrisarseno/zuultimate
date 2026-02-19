"""CRM provider adapter framework — pluggable sync backends."""

from abc import ABC, abstractmethod


class CRMAdapter(ABC):
    """Base class for CRM provider adapters."""

    name: str = "base"

    def __init__(self, api_url: str, api_key: str = ""):
        self.api_url = api_url
        self.api_key = api_key

    @abstractmethod
    async def test_connection(self) -> dict:
        """Test the connection to the CRM provider."""
        ...

    @abstractmethod
    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        """Fetch contacts from the CRM provider."""
        ...

    @abstractmethod
    async def push_contacts(self, contacts: list[dict]) -> dict:
        """Push contacts to the CRM provider."""
        ...

    @abstractmethod
    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        """Transform record fields using the mapping configuration."""
        ...


class SalesforceAdapter(CRMAdapter):
    """Salesforce CRM adapter (simulated for development)."""

    name = "salesforce"

    async def test_connection(self) -> dict:
        return {"connected": True, "provider": "salesforce", "api_url": self.api_url}

    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        # Simulated response
        return [
            {
                "Id": f"sf-{i}",
                "FirstName": f"Contact{i}",
                "LastName": f"Salesforce{i}",
                "Email": f"contact{i}@salesforce.example.com",
            }
            for i in range(offset, min(offset + limit, offset + 5))
        ]

    async def push_contacts(self, contacts: list[dict]) -> dict:
        return {"pushed": len(contacts), "provider": "salesforce"}

    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        result = {}
        for source, target in mappings.items():
            if source in record:
                result[target] = record[source]
        return result


class HubSpotAdapter(CRMAdapter):
    """HubSpot CRM adapter (simulated for development)."""

    name = "hubspot"

    async def test_connection(self) -> dict:
        return {"connected": True, "provider": "hubspot", "api_url": self.api_url}

    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        return [
            {
                "vid": f"hs-{i}",
                "firstname": f"Contact{i}",
                "lastname": f"HubSpot{i}",
                "email": f"contact{i}@hubspot.example.com",
            }
            for i in range(offset, min(offset + limit, offset + 5))
        ]

    async def push_contacts(self, contacts: list[dict]) -> dict:
        return {"pushed": len(contacts), "provider": "hubspot"}

    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        result = {}
        for source, target in mappings.items():
            if source in record:
                result[target] = record[source]
        return result


class GenericAdapter(CRMAdapter):
    """Generic/webhook-based CRM adapter."""

    name = "generic"

    async def test_connection(self) -> dict:
        return {"connected": True, "provider": "generic", "api_url": self.api_url}

    async def fetch_contacts(self, limit: int = 100, offset: int = 0) -> list[dict]:
        return []

    async def push_contacts(self, contacts: list[dict]) -> dict:
        return {"pushed": len(contacts), "provider": "generic"}

    def map_fields(self, record: dict, mappings: dict[str, str]) -> dict:
        result = {}
        for source, target in mappings.items():
            if source in record:
                result[target] = record[source]
        return result


# Adapter registry
_ADAPTERS: dict[str, type[CRMAdapter]] = {
    "salesforce": SalesforceAdapter,
    "hubspot": HubSpotAdapter,
    "generic": GenericAdapter,
}


def get_adapter(provider: str, api_url: str, api_key: str = "") -> CRMAdapter:
    """Factory function to create a CRM adapter by provider name."""
    adapter_cls = _ADAPTERS.get(provider.lower())
    if adapter_cls is None:
        raise ValueError(f"Unknown CRM provider: {provider}. Available: {list(_ADAPTERS.keys())}")
    return adapter_cls(api_url=api_url, api_key=api_key)


def list_adapters() -> list[str]:
    """Return all registered adapter names."""
    return list(_ADAPTERS.keys())


def register_adapter(name: str, adapter_cls: type[CRMAdapter]) -> None:
    """Register a custom CRM adapter."""
    _ADAPTERS[name.lower()] = adapter_cls
