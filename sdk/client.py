"""Agent Policy SDK client — discover, evaluate, and comply with resource policies."""

from __future__ import annotations

from typing import Any

import httpx

from server.engine import PolicyEngine, action_matches, evaluate_condition
from server.models import (
    AgentInfo,
    EvalRequest,
    EvalResponse,
    Policy,
    Principal,
)


class PolicyDeniedError(Exception):
    """Raised when a policy denies an action."""

    def __init__(self, response: EvalResponse) -> None:
        self.response = response
        parts = [f"Policy denied: {response.reason}"]
        if response.remediation:
            parts.append(f"Remediation ({response.remediation.type}): {response.remediation.prompt}")
        super().__init__(" | ".join(parts))


class AgentPolicyClient:
    """Client for discovering and evaluating agent policies.

    Usage:
        client = AgentPolicyClient(agent_id="my-agent", agent_name="My Agent")
        await client.discover("https://api.example.com")
        result = await client.evaluate(
            action="monitor.delete",
            resource={"type": "monitor", "env": "production"},
            principal={"user_id": "user-123", "roles": ["viewer"]},
            intent="Delete stale monitor",
        )
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str | None = None,
        agent_version: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self.agent_info = AgentInfo(id=agent_id, name=agent_name, version=agent_version)
        self._http = http_client or httpx.AsyncClient()
        self._owns_http = http_client is None
        self._policy: Policy | None = None
        self._policy_endpoint: str | None = None
        self._engine: PolicyEngine | None = None

    async def close(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> AgentPolicyClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    @property
    def policy(self) -> Policy | None:
        return self._policy

    async def discover(self, base_url: str) -> Policy:
        """Fetch and cache the agent policy from a resource server."""
        url = f"{base_url.rstrip('/')}/.well-known/agent-policy.json"
        resp = await self._http.get(url)
        resp.raise_for_status()
        data = resp.json()
        self._policy = Policy.model_validate(data)
        self._policy_endpoint = data.get("policy_endpoint")
        self._engine = PolicyEngine(self._policy)
        return self._policy

    async def evaluate(
        self,
        action: str,
        resource: dict[str, Any] | None = None,
        principal: dict[str, Any] | None = None,
        intent: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> EvalResponse:
        """Evaluate an action against the policy via the remote endpoint."""
        if not self._policy_endpoint:
            raise RuntimeError("Policy not discovered yet. Call discover() first.")

        request = EvalRequest(
            agent=self.agent_info,
            principal=Principal.model_validate(principal) if principal else None,
            intent=intent,
            action=action,
            resource=resource,
            context=context,
        )
        resp = await self._http.post(
            self._policy_endpoint,
            json=request.model_dump(mode="json"),
        )
        resp.raise_for_status()
        return EvalResponse.model_validate(resp.json())

    def check(
        self,
        action: str,
        resource: dict[str, Any] | None = None,
        principal: dict[str, Any] | None = None,
        intent: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> EvalResponse:
        """Evaluate an action locally using the cached policy.

        For the reference implementation this uses the same engine as the server.
        """
        if not self._engine:
            raise RuntimeError("Policy not discovered yet. Call discover() first.")

        request = EvalRequest(
            agent=self.agent_info,
            principal=Principal.model_validate(principal) if principal else None,
            intent=intent,
            action=action,
            resource=resource,
            context=context,
        )
        return self._engine.evaluate(request)
