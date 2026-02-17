"""MCP server that wraps the MonitoringPlatform demo API.

Each tool maps to a REST endpoint on the running FastAPI backend.
Requests include ``X-Agent-Id: claude-code`` so the enforcement
middleware evaluates every call against the policy.

Usage:
    python demo/mcp_server.py          # started automatically via .mcp.json
    # Requires: uvicorn demo.app:app --port 8000
"""

from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

BASE_URL = "http://localhost:8000"
HEADERS = {"X-Agent-Id": "claude-code"}

mcp = FastMCP("monitoring-platform")


def _format_response(resp: httpx.Response) -> str:
    """Return a human-readable string from an HTTP response."""
    try:
        body = resp.json()
    except Exception:
        body = resp.text

    if resp.status_code == 403:
        # Policy denial — surface the reason and remediation clearly.
        parts = [f"POLICY DENIED (403) — {body.get('reason', 'no reason')}"]
        if "remediation" in body:
            parts.append(f"Remediation: {body['remediation'].get('prompt', '')}")
        return "\n".join(parts)

    warning = resp.headers.get("X-Policy-Warning")
    result = json.dumps(body, indent=2)
    if warning:
        result = f"WARNING: {warning}\n\n{result}"
    return result


# -- Monitors ---------------------------------------------------------------

@mcp.tool()
def list_monitors() -> str:
    """List all monitors on the platform."""
    resp = httpx.get(f"{BASE_URL}/api/monitors", headers=HEADERS)
    return _format_response(resp)


@mcp.tool()
def get_monitor(monitor_id: str) -> str:
    """Get details for a specific monitor by ID (e.g. 'mon-1')."""
    resp = httpx.get(f"{BASE_URL}/api/monitors/{monitor_id}", headers=HEADERS)
    return _format_response(resp)


@mcp.tool()
def create_monitor(name: str, env: str = "staging") -> str:
    """Create a new monitor. Env should be 'staging' or 'production'."""
    resp = httpx.post(
        f"{BASE_URL}/api/monitors",
        headers=HEADERS,
        json={"name": name, "env": env},
    )
    return _format_response(resp)


@mcp.tool()
def delete_monitor(monitor_id: str) -> str:
    """Delete a monitor by ID. Will be denied for production resources."""
    resp = httpx.delete(f"{BASE_URL}/api/monitors/{monitor_id}", headers=HEADERS)
    return _format_response(resp)


@mcp.tool()
def mute_monitor(monitor_id: str) -> str:
    """Mute a monitor by ID. Will trigger a warning for production monitors."""
    resp = httpx.post(f"{BASE_URL}/api/monitors/{monitor_id}/mute", headers=HEADERS)
    return _format_response(resp)


# -- Dashboards -------------------------------------------------------------

@mcp.tool()
def list_dashboards() -> str:
    """List all dashboards on the platform."""
    resp = httpx.get(f"{BASE_URL}/api/dashboards", headers=HEADERS)
    return _format_response(resp)


@mcp.tool()
def create_dashboard(title: str, env: str = "staging") -> str:
    """Create a new dashboard. Env should be 'staging' or 'production'."""
    resp = httpx.post(
        f"{BASE_URL}/api/dashboards",
        headers=HEADERS,
        json={"title": title, "env": env},
    )
    return _format_response(resp)


@mcp.tool()
def delete_dashboard(dashboard_id: str) -> str:
    """Delete a dashboard by ID. Will be denied for production resources."""
    resp = httpx.delete(f"{BASE_URL}/api/dashboards/{dashboard_id}", headers=HEADERS)
    return _format_response(resp)


# -- Policy discovery -------------------------------------------------------

@mcp.tool()
def discover_policy() -> str:
    """Fetch the agent policy document from the platform."""
    resp = httpx.get(f"{BASE_URL}/.well-known/agent-policy.json")
    return _format_response(resp)


if __name__ == "__main__":
    mcp.run()
