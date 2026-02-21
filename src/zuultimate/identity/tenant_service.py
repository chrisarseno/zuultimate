"""Tenant CRUD service."""

from sqlalchemy import select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.identity.models import Tenant
from zuultimate.identity.schemas import TenantResponse

_DB_KEY = "identity"


class TenantService:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def create_tenant(self, name: str, slug: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            existing = await session.execute(
                select(Tenant).where(Tenant.slug == slug)
            )
            if existing.scalar_one_or_none() is not None:
                raise ValidationError("Tenant slug already exists")

            tenant = Tenant(name=name, slug=slug)
            session.add(tenant)
            await session.flush()

        return TenantResponse(
            id=tenant.id, name=tenant.name, slug=tenant.slug, is_active=tenant.is_active
        ).model_dump()

    async def list_tenants(self, active_only: bool = True) -> list[dict]:
        async with self.db.get_session(_DB_KEY) as session:
            query = select(Tenant).order_by(Tenant.name)
            if active_only:
                query = query.where(Tenant.is_active == True)
            result = await session.execute(query)
            tenants = result.scalars().all()

        return [
            TenantResponse(
                id=t.id, name=t.name, slug=t.slug, is_active=t.is_active
            ).model_dump()
            for t in tenants
        ]

    async def get_tenant(self, tenant_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(Tenant).where(Tenant.id == tenant_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant is None:
                raise NotFoundError("Tenant not found")

        return TenantResponse(
            id=tenant.id, name=tenant.name, slug=tenant.slug, is_active=tenant.is_active
        ).model_dump()

    async def deactivate_tenant(self, tenant_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(Tenant).where(Tenant.id == tenant_id)
            )
            tenant = result.scalar_one_or_none()
            if tenant is None:
                raise NotFoundError("Tenant not found")
            tenant.is_active = False
            await session.flush()

        return TenantResponse(
            id=tenant.id, name=tenant.name, slug=tenant.slug, is_active=tenant.is_active
        ).model_dump()
