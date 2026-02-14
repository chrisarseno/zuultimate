"""POS service -- stub."""

from zuultimate.common.exceptions import NotImplementedModuleError


class POSService:
    async def register_terminal(self, **kwargs) -> dict:
        raise NotImplementedModuleError("pos")

    async def create_transaction(self, **kwargs) -> dict:
        raise NotImplementedModuleError("pos")

    async def get_fraud_alerts(self) -> list:
        raise NotImplementedModuleError("pos")
