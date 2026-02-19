"""FastAPI application factory."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sqlalchemy import text as sa_text

from zuultimate.common.config import get_settings
from zuultimate.common.database import DatabaseManager
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.logging import get_logger
from zuultimate.common.middleware import RequestIDMiddleware
from zuultimate.common.redis import RedisManager
from zuultimate.common.schemas import ErrorResponse, HealthResponse
from zuultimate.common.tasks import SessionCleanupTask

_log = get_logger("zuultimate.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB engines on startup; dispose on shutdown."""
    settings = get_settings()
    db = DatabaseManager(settings)
    await db.init()

    # Import all models so Base.metadata knows about every table
    import zuultimate.identity.models  # noqa: F401
    import zuultimate.access.models  # noqa: F401
    import zuultimate.vault.models  # noqa: F401
    import zuultimate.pos.models  # noqa: F401
    import zuultimate.crm.models  # noqa: F401
    import zuultimate.backup_resilience.models  # noqa: F401
    import zuultimate.ai_security.models  # noqa: F401
    import zuultimate.common.webhooks  # noqa: F401  -- webhook_configs, webhook_deliveries
    import zuultimate.common.idempotency  # noqa: F401  -- idempotency_records

    await db.create_all()

    redis = RedisManager(settings.redis_url)
    await redis.connect()

    app.state.db = db
    app.state.settings = settings
    app.state.redis = redis
    app.state.shutting_down = False

    cleanup = SessionCleanupTask(db, interval_seconds=300, max_age_hours=24)
    await cleanup.start()
    app.state.session_cleanup = cleanup

    _log.info("Zuultimate started (env=%s)", settings.environment)
    yield

    # Graceful shutdown
    app.state.shutting_down = True
    _log.info("Shutting down — draining connections")
    await asyncio.sleep(0.5)  # brief drain window for in-flight requests
    await cleanup.stop()
    await redis.close()
    await db.close_all()
    _log.info("Shutdown complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        lifespan=lifespan,
    )

    # Middleware — order matters: last added = outermost
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )
    app.add_middleware(RequestIDMiddleware)

    # ── Global error handlers ──

    @app.exception_handler(ZuulError)
    async def _zuul_error(request: Request, exc: ZuulError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=exc.message, code=exc.code
            ).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                error="Validation failed",
                code="VALIDATION_ERROR",
                detail=str(exc.errors()),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def _unhandled_error(request: Request, exc: Exception) -> JSONResponse:
        _log.error("Unhandled error: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                error="Internal server error", code="INTERNAL_ERROR"
            ).model_dump(),
        )

    # ── Health probes ──

    @app.get("/health", response_model=HealthResponse)
    async def health():
        """Detailed health with DB connectivity checks."""
        db: DatabaseManager = app.state.db
        checks: dict[str, str] = {}
        for key in DatabaseManager.DB_KEYS:
            engine = db.engines.get(key)
            if engine is None:
                checks[key] = "missing"
                continue
            try:
                async with engine.connect() as conn:
                    await conn.execute(sa_text("SELECT 1"))
                checks[key] = "ok"
            except Exception:
                checks[key] = "error"

        redis_mgr: RedisManager = app.state.redis
        checks["redis"] = "ok" if redis_mgr.is_available else "unavailable (fallback)"

        all_ok = all(v == "ok" for v in checks.values() if v != "unavailable (fallback)")
        return HealthResponse(
            status="ok" if all_ok else "degraded",
            version=settings.api_version,
            environment=settings.environment,
            timestamp=datetime.now(timezone.utc),
            checks=checks,
        )

    @app.get("/health/live")
    async def liveness():
        """Kubernetes liveness probe — always 200 if process is running."""
        return {"status": "alive"}

    @app.get("/health/ready")
    async def readiness():
        """Kubernetes readiness probe — checks DB connectivity."""
        if getattr(app.state, "shutting_down", False):
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": "shutting_down"},
            )
        db: DatabaseManager = app.state.db
        for key in DatabaseManager.DB_KEYS:
            engine = db.engines.get(key)
            if engine is None:
                return JSONResponse(
                    status_code=503,
                    content={"status": "not_ready", "reason": f"{key} db missing"},
                )
            try:
                async with engine.connect() as conn:
                    await conn.execute(sa_text("SELECT 1"))
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={"status": "not_ready", "reason": f"{key} db unreachable"},
                )
        return {"status": "ready"}

    # API v1 router — all module routers grouped under /v1
    v1 = APIRouter(prefix="/v1")

    from zuultimate.ai_security.router import router as ai_router
    from zuultimate.identity.router import router as identity_router
    from zuultimate.identity.tenant_router import router as tenant_router
    from zuultimate.identity.sso_router import router as sso_router
    from zuultimate.access.router import router as access_router
    from zuultimate.vault.router import router as vault_router
    from zuultimate.pos.router import router as pos_router
    from zuultimate.crm.router import router as crm_router
    from zuultimate.backup_resilience.router import router as backup_router
    from zuultimate.plugins.router import router as plugins_router
    from zuultimate.common.webhook_router import router as webhook_router

    v1.include_router(ai_router)
    v1.include_router(identity_router)
    v1.include_router(tenant_router)
    v1.include_router(sso_router)
    v1.include_router(access_router)
    v1.include_router(vault_router)
    v1.include_router(pos_router)
    v1.include_router(crm_router)
    v1.include_router(backup_router)
    v1.include_router(plugins_router)
    v1.include_router(webhook_router)

    app.include_router(v1)

    return app
