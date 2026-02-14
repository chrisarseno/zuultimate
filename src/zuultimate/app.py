"""FastAPI application factory."""

from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from zuultimate.common.config import get_settings
from zuultimate.common.schemas import ErrorResponse, HealthResponse


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check
    @app.get("/health", response_model=HealthResponse)
    async def health():
        return HealthResponse(
            status="ok",
            version=settings.api_version,
            environment=settings.environment,
            timestamp=datetime.now(timezone.utc),
        )

    # Register routers
    from zuultimate.ai_security.router import router as ai_router
    from zuultimate.identity.router import router as identity_router
    from zuultimate.access.router import router as access_router
    from zuultimate.vault.router import router as vault_router
    from zuultimate.pos.router import router as pos_router
    from zuultimate.crm.router import router as crm_router
    from zuultimate.backup_resilience.router import router as backup_router
    from zuultimate.plugins.router import router as plugins_router

    app.include_router(ai_router)
    app.include_router(identity_router)
    app.include_router(access_router)
    app.include_router(vault_router)
    app.include_router(pos_router)
    app.include_router(crm_router)
    app.include_router(backup_router)
    app.include_router(plugins_router)

    return app
