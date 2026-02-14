"""Identity service -- stub."""

from zuultimate.common.exceptions import NotImplementedModuleError


class IdentityService:
    async def register(
        self, email: str, username: str, password: str, display_name: str = ""
    ) -> dict:
        raise NotImplementedModuleError("identity")

    async def login(self, username: str, password: str) -> dict:
        raise NotImplementedModuleError("identity")

    async def get_user(self, user_id: str) -> dict:
        raise NotImplementedModuleError("identity")

    async def refresh_token(self, token: str) -> dict:
        raise NotImplementedModuleError("identity")
