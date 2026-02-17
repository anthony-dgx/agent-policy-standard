"""Demo backend: a MonitoringPlatform API with integrated policy enforcement.

Combines real CRUD endpoints for monitors and dashboards with the agent policy
layer.  Requests from agents (identified by ``X-Agent-Id`` header) are
automatically evaluated against the policy before reaching the handler.

Usage:
    uvicorn demo.app:app --port 8000
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from server.engine import PolicyEngine
from server.models import (
    AgentInfo,
    EvalRequest,
    EvalResponse,
    Policy,
    Principal,
)

# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

POLICY_PATH = Path(__file__).parent / "policy.json"


def _load_policy(path: Path = POLICY_PATH) -> Policy:
    with open(path) as f:
        data = json.load(f)
    return Policy.model_validate(data)


# ---------------------------------------------------------------------------
# In-memory data store — pre-seeded
# ---------------------------------------------------------------------------

MONITORS: dict[str, dict[str, Any]] = {
    "mon-1": {
        "id": "mon-1",
        "name": "CPU usage > 90%",
        "type": "metric",
        "env": "production",
        "muted": False,
    },
    "mon-2": {
        "id": "mon-2",
        "name": "Error rate spike",
        "type": "metric",
        "env": "production",
        "muted": False,
    },
    "mon-3": {
        "id": "mon-3",
        "name": "Deploy canary check",
        "type": "synthetic",
        "env": "staging",
        "muted": False,
    },
}

DASHBOARDS: dict[str, dict[str, Any]] = {
    "dash-1": {
        "id": "dash-1",
        "title": "Production Overview",
        "env": "production",
        "widgets": 12,
    },
    "dash-2": {
        "id": "dash-2",
        "title": "Staging Deploys",
        "env": "staging",
        "widgets": 6,
    },
}


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateMonitorRequest(BaseModel):
    name: str
    type: str = "metric"
    env: str = "staging"


class CreateDashboardRequest(BaseModel):
    title: str
    env: str = "staging"
    widgets: int = 0


# ---------------------------------------------------------------------------
# Route → action mapping
# ---------------------------------------------------------------------------

_ROUTE_ACTION_MAP: list[tuple[str, str, str]] = [
    # (method, path_regex, action)
    ("GET",    r"^/api/monitors$",           "monitor.list"),
    ("POST",   r"^/api/monitors$",           "monitor.create"),
    ("GET",    r"^/api/monitors/[^/]+$",     "monitor.read"),
    ("DELETE", r"^/api/monitors/[^/]+$",     "monitor.delete"),
    ("POST",   r"^/api/monitors/[^/]+/mute$","monitor.mute"),
    ("GET",    r"^/api/dashboards$",         "dashboard.list"),
    ("POST",   r"^/api/dashboards$",         "dashboard.create"),
    ("DELETE", r"^/api/dashboards/[^/]+$",   "dashboard.delete"),
]


def _resolve_action(method: str, path: str) -> str | None:
    for m, pattern, action in _ROUTE_ACTION_MAP:
        if m == method and re.match(pattern, path):
            return action
    return None


def _extract_resource_id(path: str) -> str | None:
    """Pull the resource id from paths like /api/monitors/mon-1."""
    parts = path.rstrip("/").split("/")
    # /api/<collection>/<id> or /api/<collection>/<id>/mute
    if len(parts) >= 4:
        return parts[3]
    return None


def _get_resource_metadata(action: str, resource_id: str | None) -> dict[str, Any] | None:
    """Look up resource metadata so the policy can inspect env, type, etc."""
    if resource_id is None:
        return None
    if action.startswith("monitor."):
        monitor = MONITORS.get(resource_id)
        if monitor:
            return {"type": "monitor", "env": monitor["env"], "id": resource_id}
    elif action.startswith("dashboard."):
        dashboard = DASHBOARDS.get(resource_id)
        if dashboard:
            return {"type": "dashboard", "env": dashboard["env"], "id": resource_id}
    return None


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(policy_path: Path = POLICY_PATH) -> FastAPI:
    policy = _load_policy(policy_path)
    engine = PolicyEngine(policy)

    app = FastAPI(title="MonitoringPlatform Demo", version="0.1.0")

    # ------------------------------------------------------------------
    # Enforcement middleware
    # ------------------------------------------------------------------

    @app.middleware("http")
    async def enforce_policy(request: Request, call_next) -> Response:  # type: ignore[no-untyped-def]
        # Only enforce on /api/* paths when agent identifies itself
        if not request.url.path.startswith("/api/"):
            return await call_next(request)

        agent_id = request.headers.get("X-Agent-Id")
        if not agent_id:
            return await call_next(request)

        action = _resolve_action(request.method, request.url.path)
        if action is None:
            return await call_next(request)

        resource_id = _extract_resource_id(request.url.path)
        resource = _get_resource_metadata(action, resource_id)

        eval_req = EvalRequest(
            agent=AgentInfo(id=agent_id, name=request.headers.get("X-Agent-Name")),
            principal=None,
            intent=request.headers.get("X-Agent-Intent"),
            action=action,
            resource=resource,
        )
        result = engine.evaluate(eval_req)

        # Store for handler introspection
        request.state.policy_result = result

        if result.decision == "deny":
            body: dict[str, Any] = {
                "error": "policy_denied",
                "rule_id": result.rule_id,
                "reason": result.reason,
            }
            if result.remediation:
                body["remediation"] = {
                    "type": result.remediation.type,
                    "prompt": result.remediation.prompt,
                }
            return JSONResponse(status_code=403, content=body)

        response = await call_next(request)

        if result.decision == "warn":
            response.headers["X-Policy-Warning"] = result.reason or ""
            response.headers["X-Policy-Rule"] = result.rule_id or ""

        return response

    # ------------------------------------------------------------------
    # Policy endpoints (same as server/app.py)
    # ------------------------------------------------------------------

    @app.get("/.well-known/agent-policy.json")
    async def get_policy() -> JSONResponse:
        return JSONResponse(content=policy.model_dump(mode="json"))

    @app.post("/agent/policy/evaluate")
    async def evaluate(request: EvalRequest) -> EvalResponse:
        return engine.evaluate(request)

    @app.get("/agent/policy/rules")
    async def list_rules() -> JSONResponse:
        return JSONResponse(
            content=[rule.model_dump(mode="json") for rule in policy.rules]
        )

    # ------------------------------------------------------------------
    # Business API — Monitors
    # ------------------------------------------------------------------

    @app.get("/api/monitors")
    async def list_monitors() -> JSONResponse:
        return JSONResponse(content=list(MONITORS.values()))

    @app.post("/api/monitors", status_code=201)
    async def create_monitor(body: CreateMonitorRequest) -> JSONResponse:
        monitor_id = f"mon-{uuid.uuid4().hex[:6]}"
        monitor = {
            "id": monitor_id,
            "name": body.name,
            "type": body.type,
            "env": body.env,
            "muted": False,
        }
        MONITORS[monitor_id] = monitor
        return JSONResponse(status_code=201, content=monitor)

    @app.get("/api/monitors/{monitor_id}")
    async def get_monitor(monitor_id: str) -> JSONResponse:
        monitor = MONITORS.get(monitor_id)
        if not monitor:
            raise HTTPException(status_code=404, detail="Monitor not found")
        return JSONResponse(content=monitor)

    @app.delete("/api/monitors/{monitor_id}")
    async def delete_monitor(monitor_id: str) -> JSONResponse:
        monitor = MONITORS.pop(monitor_id, None)
        if not monitor:
            raise HTTPException(status_code=404, detail="Monitor not found")
        return JSONResponse(content={"deleted": monitor_id})

    @app.post("/api/monitors/{monitor_id}/mute")
    async def mute_monitor(monitor_id: str) -> JSONResponse:
        monitor = MONITORS.get(monitor_id)
        if not monitor:
            raise HTTPException(status_code=404, detail="Monitor not found")
        monitor["muted"] = True
        return JSONResponse(content=monitor)

    # ------------------------------------------------------------------
    # Business API — Dashboards
    # ------------------------------------------------------------------

    @app.get("/api/dashboards")
    async def list_dashboards() -> JSONResponse:
        return JSONResponse(content=list(DASHBOARDS.values()))

    @app.post("/api/dashboards", status_code=201)
    async def create_dashboard(body: CreateDashboardRequest) -> JSONResponse:
        dash_id = f"dash-{uuid.uuid4().hex[:6]}"
        dashboard = {
            "id": dash_id,
            "title": body.title,
            "env": body.env,
            "widgets": body.widgets,
        }
        DASHBOARDS[dash_id] = dashboard
        return JSONResponse(status_code=201, content=dashboard)

    @app.delete("/api/dashboards/{dashboard_id}")
    async def delete_dashboard(dashboard_id: str) -> JSONResponse:
        dashboard = DASHBOARDS.pop(dashboard_id, None)
        if not dashboard:
            raise HTTPException(status_code=404, detail="Dashboard not found")
        return JSONResponse(content={"deleted": dashboard_id})

    return app


app = create_app()
