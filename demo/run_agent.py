"""End-to-end agent demo against the MonitoringPlatform backend.

Discovers the policy, then exercises every enforcement path:
  1. List monitors                → allowed  (audit)
  2. Create a monitor             → allowed
  3. Read the created monitor     → allowed  (audit)
  4. Delete a staging monitor     → allowed
  5. Delete a production monitor  → DENIED   (403 + remediation)
  6. Mute a production monitor    → WARNED   (but allowed)
  7. Hit the rate limit           → DENIED   (rate limit)

Usage:
    # Start the demo server first:
    #   uvicorn demo.app:app --port 8000
    #
    # Then run:
    #   python demo/run_agent.py
"""

from __future__ import annotations

import asyncio
import sys

import httpx

from sdk.client import AgentPolicyClient

BASE_URL = "http://localhost:8000"
AGENT_ID = "demo-agent-01"
AGENT_NAME = "Demo Agent"
AGENT_HEADERS = {"X-Agent-Id": AGENT_ID, "X-Agent-Name": AGENT_NAME}


def _sep(title: str) -> None:
    print()
    print("=" * 64)
    print(f"  {title}")
    print("=" * 64)


def _print_response(resp: httpx.Response) -> None:
    print(f"  HTTP {resp.status_code}")
    warning = resp.headers.get("X-Policy-Warning")
    if warning:
        print(f"  ⚠  Policy warning: {warning}")
        print(f"     Rule: {resp.headers.get('X-Policy-Rule', '?')}")
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    if isinstance(body, dict) and body.get("error") == "policy_denied":
        print(f"  DENIED by rule {body.get('rule_id')}: {body.get('reason')}")
        rem = body.get("remediation")
        if rem:
            print(f"  Remediation ({rem['type']}): {rem['prompt']}")
    else:
        # Compact print for lists
        if isinstance(body, list) and len(body) > 3:
            print(f"  Body: [{len(body)} items]")
            for item in body[:3]:
                print(f"    - {item}")
            print("    ...")
        else:
            print(f"  Body: {body}")


async def main() -> None:
    async with (
        AgentPolicyClient(
            agent_id=AGENT_ID,
            agent_name=AGENT_NAME,
            agent_version="1.0.0",
        ) as policy_client,
        httpx.AsyncClient(base_url=BASE_URL, headers=AGENT_HEADERS) as http,
    ):
        # ------------------------------------------------------------------
        # Step 0: Discover the policy
        # ------------------------------------------------------------------
        _sep("Step 0 — Discover policy")
        policy = await policy_client.discover(BASE_URL)
        print(f"  Issuer:  {policy.issuer}")
        print(f"  Version: {policy.version}")
        print(f"  Rules:   {len(policy.rules)}")
        for rule in policy.rules:
            print(f"    [{rule.enforcement:6s}] {rule.id}: {rule.description}")

        # ------------------------------------------------------------------
        # Step 1: List monitors (audit — allowed)
        # ------------------------------------------------------------------
        _sep("Step 1 — List monitors (expect: allowed, audit)")
        resp = await http.get("/api/monitors")
        _print_response(resp)

        # ------------------------------------------------------------------
        # Step 2: Create a new monitor (allowed)
        # ------------------------------------------------------------------
        _sep("Step 2 — Create a staging monitor (expect: allowed)")
        resp = await http.post(
            "/api/monitors",
            json={"name": "Agent-created check", "type": "metric", "env": "staging"},
        )
        _print_response(resp)
        created_id = resp.json().get("id") if resp.status_code == 201 else None

        # ------------------------------------------------------------------
        # Step 3: Read the created monitor (audit — allowed)
        # ------------------------------------------------------------------
        _sep("Step 3 — Read the created monitor (expect: allowed, audit)")
        if created_id:
            resp = await http.get(f"/api/monitors/{created_id}")
        else:
            resp = await http.get("/api/monitors/mon-3")
        _print_response(resp)

        # ------------------------------------------------------------------
        # Step 4: Delete a staging monitor (allowed)
        # ------------------------------------------------------------------
        _sep("Step 4 — Delete a staging monitor (expect: allowed)")
        target = created_id or "mon-3"
        resp = await http.delete(f"/api/monitors/{target}")
        _print_response(resp)

        # ------------------------------------------------------------------
        # Step 5: Delete a production monitor (DENIED)
        # ------------------------------------------------------------------
        _sep("Step 5 — Delete a production monitor (expect: DENIED)")
        resp = await http.delete("/api/monitors/mon-1")
        _print_response(resp)

        # ------------------------------------------------------------------
        # Step 6: Mute a production monitor (WARNED but allowed)
        # ------------------------------------------------------------------
        _sep("Step 6 — Mute a production monitor (expect: WARNED)")
        resp = await http.post("/api/monitors/mon-1/mute")
        _print_response(resp)

        # ------------------------------------------------------------------
        # Step 7: Hit the rate limit by writing multiple times
        # ------------------------------------------------------------------
        _sep("Step 7 — Trigger rate limit (5 writes/min, expect: DENIED)")
        # We've already used 2 rate-limited writes (create + staging delete).
        # Steps 5 & 6 matched higher-priority rules and didn't count.
        # Three more will reach 5, the fourth will exceed the limit.
        for i in range(4):
            resp = await http.post(
                "/api/dashboards",
                json={"title": f"Rate limit test #{i+1}", "env": "staging"},
            )
            status = resp.status_code
            if status == 403:
                print(f"  Write #{i+1}: RATE LIMITED")
                _print_response(resp)
                break
            else:
                print(f"  Write #{i+1}: HTTP {status} (allowed)")

        # ------------------------------------------------------------------
        # Done
        # ------------------------------------------------------------------
        _sep("Done — all scenarios demonstrated")
        print("  The demo exercised: audit, allow, deny, warn, and rate-limit.")
        print()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except httpx.ConnectError:
        print("ERROR: Could not connect to the demo server.")
        print("Start it first:  uvicorn demo.app:app --port 8000")
        sys.exit(1)
