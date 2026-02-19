"""SSO service -- OIDC/SAML provider management and authentication flow."""

import hashlib
import os
from urllib.parse import urlencode

from sqlalchemy import select

from zuultimate.common.config import ZuulSettings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import NotFoundError, ValidationError
from zuultimate.common.security import create_jwt
from zuultimate.identity.models import SSOProvider, User, UserSession

_DB_KEY = "identity"


class SSOService:
    def __init__(self, db: DatabaseManager, settings: ZuulSettings):
        self.db = db
        self.settings = settings

    async def create_provider(
        self,
        name: str,
        protocol: str,
        issuer_url: str,
        client_id: str,
        client_secret: str = "",
        metadata_url: str = "",
        tenant_id: str | None = None,
    ) -> dict:
        if protocol not in ("oidc", "saml"):
            raise ValidationError("Protocol must be 'oidc' or 'saml'")

        async with self.db.get_session(_DB_KEY) as session:
            provider = SSOProvider(
                name=name,
                protocol=protocol,
                issuer_url=issuer_url,
                client_id=client_id,
                client_secret_encrypted=client_secret,
                metadata_url=metadata_url or None,
                tenant_id=tenant_id,
            )
            session.add(provider)
            await session.flush()

        return self._to_dict(provider)

    async def list_providers(self, tenant_id: str | None = None) -> list[dict]:
        async with self.db.get_session(_DB_KEY) as session:
            stmt = select(SSOProvider).where(SSOProvider.is_active == True)
            if tenant_id:
                stmt = stmt.where(SSOProvider.tenant_id == tenant_id)
            result = await session.execute(stmt)
            providers = result.scalars().all()
        return [self._to_dict(p) for p in providers]

    async def get_provider(self, provider_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider_id)
            )
            provider = result.scalar_one_or_none()
            if provider is None:
                raise NotFoundError(f"SSO provider '{provider_id}' not found")
        return self._to_dict(provider)

    async def initiate_login(self, provider_id: str, redirect_uri: str) -> dict:
        """Generate SSO login URL for the given provider."""
        provider = await self.get_provider(provider_id)
        state = os.urandom(16).hex()

        if provider["protocol"] == "oidc":
            params = {
                "client_id": provider["client_id"],
                "response_type": "code",
                "scope": "openid email profile",
                "redirect_uri": redirect_uri,
                "state": state,
            }
            redirect_url = f"{provider['issuer_url']}/authorize?{urlencode(params)}"
        else:
            # SAML: redirect to IdP SSO URL
            redirect_url = f"{provider['issuer_url']}/sso?SAMLRequest=placeholder&RelayState={state}"

        return {
            "redirect_url": redirect_url,
            "state": state,
            "provider_id": provider_id,
        }

    async def handle_callback(
        self, provider_id: str, code: str, state: str
    ) -> dict:
        """Handle the SSO callback — exchange code for tokens.

        In production this would call the IdP's token endpoint. Here we
        validate the provider exists and simulate a successful exchange by
        creating/finding a user and issuing JWT tokens.
        """
        provider = await self.get_provider(provider_id)

        # Simulated exchange: derive a deterministic "email" from the code
        # In production: POST to provider's token_endpoint with code + client_secret
        simulated_email = f"sso-{code[:8]}@{provider['name'].lower().replace(' ', '')}.com"
        simulated_username = f"sso_{code[:8]}"

        async with self.db.get_session(_DB_KEY) as session:
            # Find or create user
            result = await session.execute(
                select(User).where(User.email == simulated_email)
            )
            user = result.scalar_one_or_none()

            if user is None:
                user = User(
                    email=simulated_email,
                    username=simulated_username,
                    display_name=simulated_username,
                    is_verified=True,  # SSO users are auto-verified
                    tenant_id=provider.get("tenant_id"),
                )
                session.add(user)
                await session.flush()

            access_token = create_jwt(
                {"sub": user.id, "username": user.username, "type": "access"},
                self.settings.secret_key,
                expires_minutes=self.settings.access_token_expire_minutes,
            )
            refresh_token = create_jwt(
                {"sub": user.id, "username": user.username, "type": "refresh"},
                self.settings.secret_key,
                expires_minutes=self.settings.refresh_token_expire_days * 24 * 60,
            )

            user_session = UserSession(
                user_id=user.id,
                access_token_hash=hashlib.sha256(access_token.encode()).hexdigest(),
                refresh_token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
            )
            session.add(user_session)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.settings.access_token_expire_minutes * 60,
            "user_id": user.id,
            "sso_provider": provider["name"],
        }

    async def deactivate_provider(self, provider_id: str) -> dict:
        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SSOProvider).where(SSOProvider.id == provider_id)
            )
            provider = result.scalar_one_or_none()
            if provider is None:
                raise NotFoundError(f"SSO provider '{provider_id}' not found")
            provider.is_active = False
        return {"id": provider_id, "is_active": False}

    @staticmethod
    def _to_dict(p: SSOProvider) -> dict:
        return {
            "id": p.id,
            "name": p.name,
            "protocol": p.protocol,
            "issuer_url": p.issuer_url,
            "client_id": p.client_id,
            "metadata_url": p.metadata_url,
            "tenant_id": p.tenant_id,
            "is_active": p.is_active,
        }
