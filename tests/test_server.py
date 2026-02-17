"""Integration tests for FastAPI server endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from server.app import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestPolicyDiscovery:
    async def test_get_policy(self, client: AsyncClient):
        resp = await client.get("/.well-known/agent-policy.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0"
        assert data["issuer"] == "https://api.datadoghq.com"
        assert "rules" in data
        assert len(data["rules"]) > 0

    async def test_policy_has_required_fields(self, client: AsyncClient):
        resp = await client.get("/.well-known/agent-policy.json")
        data = resp.json()
        assert "policy_endpoint" in data
        assert "updated_at" in data
        assert "agent_requirements" in data

    async def test_list_rules(self, client: AsyncClient):
        resp = await client.get("/agent/policy/rules")
        assert resp.status_code == 200
        rules = resp.json()
        assert isinstance(rules, list)
        assert len(rules) > 0
        assert all("id" in r for r in rules)


class TestPolicyEvaluation:
    async def test_allow_read(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "agent": {"id": "test-agent"},
            "action": "monitor.read",
            "resource": {"type": "monitor", "env": "production"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"

    async def test_deny_prod_delete(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "agent": {"id": "test-agent"},
            "action": "monitor.delete",
            "resource": {"type": "monitor", "env": "production"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "deny"
        assert data["rule_id"] == "dd-001"
        assert data["remediation"] is not None
        assert data["remediation"]["type"] == "human_approval"

    async def test_allow_staging_delete(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "agent": {"id": "test-agent"},
            "action": "monitor.delete",
            "resource": {"type": "monitor", "env": "staging"},
            "intent": "Cleaning up stale monitors from test run",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "allow"

    async def test_warn_mute_production(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "agent": {"id": "test-agent"},
            "action": "monitor.mute",
            "resource": {"type": "monitor", "env": "production"},
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "warn"
        assert data["rule_id"] == "dd-002"

    async def test_missing_agent_returns_422(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "action": "monitor.read",
        })
        assert resp.status_code == 422

    async def test_unknown_action_allowed(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "agent": {"id": "test-agent"},
            "action": "custom.action",
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"
