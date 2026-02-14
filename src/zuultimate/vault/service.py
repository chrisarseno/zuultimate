"""Vault service -- stub (crypto.py is implemented)."""

from zuultimate.common.exceptions import NotImplementedModuleError


class VaultService:
    async def encrypt(self, plaintext: str, label: str = "", owner_id: str = "") -> dict:
        raise NotImplementedModuleError("vault")

    async def decrypt(self, blob_id: str) -> dict:
        raise NotImplementedModuleError("vault")

    async def tokenize(self, value: str) -> dict:
        raise NotImplementedModuleError("vault")

    async def detokenize(self, token: str) -> dict:
        raise NotImplementedModuleError("vault")
