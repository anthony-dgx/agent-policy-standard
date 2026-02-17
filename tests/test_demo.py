"""Tests for the demo MonitoringPlatform backend."""

import pytest
from httpx import ASGITransport, AsyncClient

from demo.app import DASHBOARDS, MONITORS, create_app

AGENT_HEADERS = {"X-Agent-Id": "test-agent", "X-Agent-Name": "Test Agent"}


@pytest.fixture(autouse=True)
def _reset_stores():
    """Reset in-memory stores before each test."""
    MONITORS.clear()
    MONITORS.update({
        "mon-1": {"id": "mon-1", "name": "CPU usage > 90%", "type": "metric", "env": "production", "muted": False},
        "mon-2": {"id": "mon-2", "name": "Error rate spike", "type": "metric", "env": "production", "muted": False},
        "mon-3": {"id": "mon-3", "name": "Deploy canary check", "type": "synthetic", "env": "staging", "muted": False},
    })
    DASHBOARDS.clear()
    DASHBOARDS.update({
        "dash-1": {"id": "dash-1", "title": "Production Overview", "env": "production", "widgets": 12},
        "dash-2": {"id": "dash-2", "title": "Staging Deploys", "env": "staging", "widgets": 6},
    })


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# -----------------------------------------------------------------------
# Policy endpoints
# -----------------------------------------------------------------------

class TestPolicyEndpoints:
    async def test_well_known(self, client: AsyncClient):
        resp = await client.get("/.well-known/agent-policy.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "1.0"
        assert len(data["rules"]) == 4

    async def test_list_rules(self, client: AsyncClient):
        resp = await client.get("/agent/policy/rules")
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) == 4
        assert rules[0]["id"] == "demo-001"

    async def test_evaluate_endpoint(self, client: AsyncClient):
        resp = await client.post("/agent/policy/evaluate", json={
            "agent": {"id": "test-agent"},
            "action": "monitor.read",
            "resource": {"type": "monitor", "env": "production"},
        })
        assert resp.status_code == 200
        assert resp.json()["decision"] == "allow"


# -----------------------------------------------------------------------
# Business API — no agent header (no enforcement)
# -----------------------------------------------------------------------

class TestBusinessAPINoEnforcement:
    async def test_list_monitors(self, client: AsyncClient):
        resp = await client.get("/api/monitors")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    async def test_create_monitor(self, client: AsyncClient):
        resp = await client.post("/api/monitors", json={"name": "New mon", "env": "staging"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "New mon"
        assert data["id"] in MONITORS

    async def test_get_monitor(self, client: AsyncClient):
        resp = await client.get("/api/monitors/mon-1")
        assert resp.status_code == 200
        assert resp.json()["name"] == "CPU usage > 90%"

    async def test_get_monitor_not_found(self, client: AsyncClient):
        resp = await client.get("/api/monitors/nonexistent")
        assert resp.status_code == 404

    async def test_delete_monitor(self, client: AsyncClient):
        resp = await client.delete("/api/monitors/mon-1")
        assert resp.status_code == 200
        assert "mon-1" not in MONITORS

    async def test_mute_monitor(self, client: AsyncClient):
        resp = await client.post("/api/monitors/mon-1/mute")
        assert resp.status_code == 200
        assert resp.json()["muted"] is True

    async def test_list_dashboards(self, client: AsyncClient):
        resp = await client.get("/api/dashboards")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    async def test_create_dashboard(self, client: AsyncClient):
        resp = await client.post("/api/dashboards", json={"title": "New Dash", "env": "staging"})
        assert resp.status_code == 201
        assert resp.json()["title"] == "New Dash"

    async def test_delete_dashboard(self, client: AsyncClient):
        resp = await client.delete("/api/dashboards/dash-2")
        assert resp.status_code == 200
        assert "dash-2" not in DASHBOARDS

    async def test_delete_production_monitor_no_agent_header(self, client: AsyncClient):
        """Without X-Agent-Id, no enforcement — delete succeeds even on production."""
        resp = await client.delete("/api/monitors/mon-1")
        assert resp.status_code == 200


# -----------------------------------------------------------------------
# Enforcement middleware — agent-identified requests
# -----------------------------------------------------------------------

class TestEnforcementMiddleware:
    async def test_read_allowed_with_audit(self, client: AsyncClient):
        resp = await client.get("/api/monitors", headers=AGENT_HEADERS)
        assert resp.status_code == 200

    async def test_create_allowed(self, client: AsyncClient):
        resp = await client.post(
            "/api/monitors",
            json={"name": "Agent mon", "env": "staging"},
            headers=AGENT_HEADERS,
        )
        assert resp.status_code == 201

    async def test_delete_staging_allowed(self, client: AsyncClient):
        resp = await client.delete("/api/monitors/mon-3", headers=AGENT_HEADERS)
        assert resp.status_code == 200

    async def test_delete_production_denied(self, client: AsyncClient):
        resp = await client.delete("/api/monitors/mon-1", headers=AGENT_HEADERS)
        assert resp.status_code == 403
        body = resp.json()
        assert body["error"] == "policy_denied"
        assert body["rule_id"] == "demo-001"
        assert body["remediation"]["type"] == "human_approval"

    async def test_delete_production_dashboard_denied(self, client: AsyncClient):
        resp = await client.delete("/api/dashboards/dash-1", headers=AGENT_HEADERS)
        assert resp.status_code == 403
        assert resp.json()["rule_id"] == "demo-001"

    async def test_mute_production_warned(self, client: AsyncClient):
        resp = await client.post("/api/monitors/mon-1/mute", headers=AGENT_HEADERS)
        assert resp.status_code == 200
        assert resp.headers.get("X-Policy-Warning") == "Warn on muting production monitors"
        assert resp.headers.get("X-Policy-Rule") == "demo-002"

    async def test_mute_staging_allowed_no_warning(self, client: AsyncClient):
        resp = await client.post("/api/monitors/mon-3/mute", headers=AGENT_HEADERS)
        assert resp.status_code == 200
        assert "X-Policy-Warning" not in resp.headers

    async def test_production_monitor_stays_after_denied_delete(self, client: AsyncClient):
        """Denied delete should not remove the resource."""
        await client.delete("/api/monitors/mon-1", headers=AGENT_HEADERS)
        assert "mon-1" in MONITORS


class TestRateLimit:
    async def test_rate_limit_exceeded(self, client: AsyncClient):
        """Writing more than 5 times in a minute triggers rate limit."""
        for i in range(5):
            resp = await client.post(
                "/api/monitors",
                json={"name": f"Mon {i}", "env": "staging"},
                headers=AGENT_HEADERS,
            )
            assert resp.status_code == 201, f"Write #{i+1} should succeed"

        # 6th write should be denied
        resp = await client.post(
            "/api/monitors",
            json={"name": "One too many", "env": "staging"},
            headers=AGENT_HEADERS,
        )
        assert resp.status_code == 403
        body = resp.json()
        assert body["rule_id"] == "demo-003"
        assert "Rate limit exceeded" in body["reason"]
