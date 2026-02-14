"""CRM service -- stub."""

from zuultimate.common.exceptions import NotImplementedModuleError


class CRMService:
    async def create_config(self, **kwargs) -> dict:
        raise NotImplementedModuleError("crm")

    async def start_sync(self, config_id: str) -> dict:
        raise NotImplementedModuleError("crm")

    async def get_sync_status(self, job_id: str) -> dict:
        raise NotImplementedModuleError("crm")
