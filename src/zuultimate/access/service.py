"""Access control service -- stub."""

from zuultimate.common.exceptions import NotImplementedModuleError


class AccessService:
    async def check_access(self, user_id: str, resource: str, action: str) -> dict:
        raise NotImplementedModuleError("access")

    async def create_policy(self, **kwargs) -> dict:
        raise NotImplementedModuleError("access")

    async def assign_role(self, role_id: str, user_id: str) -> dict:
        raise NotImplementedModuleError("access")
