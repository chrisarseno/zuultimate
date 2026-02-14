"""Backup & resilience service -- stub."""

from zuultimate.common.exceptions import NotImplementedModuleError


class BackupService:
    async def create_snapshot(self, **kwargs) -> dict:
        raise NotImplementedModuleError("backup_resilience")

    async def restore(self, **kwargs) -> dict:
        raise NotImplementedModuleError("backup_resilience")

    async def check_integrity(self, **kwargs) -> dict:
        raise NotImplementedModuleError("backup_resilience")
