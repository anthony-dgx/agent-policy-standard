"""FastAPI application serving agent policy endpoints."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from server.engine import PolicyEngine
from server.models import EvalRequest, EvalResponse, Policy

POLICY_PATH = Path(__file__).parent / "policies" / "datadog.json"


def load_policy(path: Path) -> Policy:
    with open(path) as f:
        data = json.load(f)
    return Policy.model_validate(data)


def create_app(policy_path: Path = POLICY_PATH) -> FastAPI:
    app = FastAPI(title="Agent Policy Server", version="0.1.0")
    policy = load_policy(policy_path)
    engine = PolicyEngine(policy)

    @app.get("/.well-known/agent-policy.json")
    async def get_policy() -> JSONResponse:
        return JSONResponse(content=policy.model_dump(mode="json"))

    @app.post("/agent/policy/evaluate")
    async def evaluate(request: EvalRequest) -> EvalResponse:
        return engine.evaluate(request)

    @app.get("/agent/policy/rules")
    async def list_rules() -> JSONResponse:
        rules_data = [rule.model_dump(mode="json") for rule in policy.rules]
        return JSONResponse(content=rules_data)

    return app


app = create_app()
