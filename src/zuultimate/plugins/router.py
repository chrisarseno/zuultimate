"""FastAPI router for plugin management endpoints."""
from __future__ import annotations
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from zuultimate.plugins.service import PluginService

router = APIRouter(prefix="/plugins", tags=["plugins"])

_plugin_service = PluginService()


class PluginRegistrationRequest(BaseModel):
    name: str
    version: str = "0.0.0"
    description: str = ""


def get_plugin_service() -> PluginService:
    """Return the module-level PluginService instance."""
    return _plugin_service


@router.get("/")
async def list_plugins() -> list[dict]:
    """List all registered plugins."""
    return _plugin_service.list_plugins()


@router.post("/register", status_code=501)
async def register_plugin_via_api(body: PluginRegistrationRequest) -> dict[str, str]:
    """Plugin registration via API is not supported.

    Plugins must be registered at the code level using PluginService.register_plugin().
    """
    return {"detail": "Plugin registration via API not supported"}


@router.get("/{plugin_id}")
async def get_plugin(plugin_id: str) -> dict:
    """Get information about a specific plugin by name."""
    plugin = _plugin_service.registry.get(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found")
    return {
        "name": plugin.name,
        "version": plugin.version,
        "description": plugin.description,
    }


@router.post("/{plugin_id}/webhook")
async def plugin_webhook(plugin_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Forward a webhook payload to the specified plugin."""
    result = await _plugin_service.handle_webhook(plugin_id, payload)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result
