"""Tests for the Agent Policy SDK."""

import pytest
from httpx import ASGITransport, AsyncClient

from sdk.client import AgentPolicyClient, PolicyDeniedError
from sdk.decorator import enforce_policy
from server.app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def http_client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.fixture
async def policy_client(http_client):
    client = AgentPolicyClient(
        agent_id="test-agent",
        agent_name="Test Agent",
        http_client=http_client,
    )
    await client.discover("http://test")
    yield client


class TestDiscovery:
    async def test_discover_policy(self, http_client):
        client = AgentPolicyClient(agent_id="test", http_client=http_client)
        policy = await client.discover("http://test")
        assert policy.version == "1.0"
        assert policy.issuer == "https://api.datadoghq.com"
        assert len(policy.rules) > 0

    async def test_discover_caches_policy(self, http_client):
        client = AgentPolicyClient(agent_id="test", http_client=http_client)
        await client.discover("http://test")
        assert client.policy is not None

    async def test_check_before_discover_raises(self):
        client = AgentPolicyClient(agent_id="test")
        with pytest.raises(RuntimeError, match="not discovered"):
            client.check(action="monitor.read")


class TestLocalEvaluation:
    def test_allow_read(self, policy_client: AgentPolicyClient):
        result = policy_client.check(
            action="monitor.read",
            resource={"type": "monitor", "env": "production"},
        )
        assert result.decision == "allow"

    def test_deny_prod_delete(self, policy_client: AgentPolicyClient):
        result = policy_client.check(
            action="monitor.delete",
            resource={"type": "monitor", "env": "production"},
        )
        assert result.decision == "deny"
        assert result.remediation is not None

    def test_warn_mute(self, policy_client: AgentPolicyClient):
        result = policy_client.check(
            action="monitor.mute",
            resource={"type": "monitor", "env": "production"},
        )
        assert result.decision == "warn"


class TestRemoteEvaluation:
    async def test_evaluate_allow(self, policy_client: AgentPolicyClient):
        result = await policy_client.evaluate(
            action="monitor.read",
            resource={"type": "monitor", "env": "production"},
        )
        assert result.decision == "allow"

    async def test_evaluate_deny(self, policy_client: AgentPolicyClient):
        result = await policy_client.evaluate(
            action="monitor.delete",
            resource={"type": "monitor", "env": "production"},
        )
        assert result.decision == "deny"


class TestDecorator:
    async def test_allowed_action(self, policy_client: AgentPolicyClient):
        @enforce_policy(
            policy_client,
            action="monitor.read",
            resource_fn=lambda: {"type": "monitor", "env": "staging"},
        )
        async def read_monitor():
            return {"status": "ok"}

        result = await read_monitor()
        assert result == {"status": "ok"}

    async def test_denied_action_raises(self, policy_client: AgentPolicyClient):
        @enforce_policy(
            policy_client,
            action="monitor.delete",
            resource_fn=lambda: {"type": "monitor", "env": "production"},
        )
        async def delete_monitor():
            return {"deleted": True}

        with pytest.raises(PolicyDeniedError) as exc_info:
            await delete_monitor()
        assert "human_approval" in str(exc_info.value)

    async def test_warned_action_proceeds(self, policy_client: AgentPolicyClient):
        @enforce_policy(
            policy_client,
            action="monitor.mute",
            resource_fn=lambda: {"type": "monitor", "env": "production"},
        )
        async def mute_monitor():
            return {"muted": True}

        result = await mute_monitor()
        assert result == {"muted": True}
