"""End-to-end example: agent discovers policy, evaluates actions, handles denials.

Usage:
    # Start the server first:
    #   uvicorn server.app:app --port 8000
    #
    # Then run this example:
    #   python examples/agent_example.py
"""

from __future__ import annotations

import asyncio
import sys

from sdk.client import AgentPolicyClient, PolicyDeniedError


async def main() -> None:
    base_url = "http://localhost:8000"

    async with AgentPolicyClient(
        agent_id="example-agent",
        agent_name="Example Agent",
        agent_version="0.1.0",
    ) as client:
        # Step 1: Discover the policy
        print("=" * 60)
        print("Step 1: Discovering agent policy...")
        print("=" * 60)
        policy = await client.discover(base_url)
        print(f"  Issuer: {policy.issuer}")
        print(f"  Version: {policy.version}")
        print(f"  Rules: {len(policy.rules)}")
        print(f"  Requirements:")
        print(f"    - Identification: {policy.agent_requirements.identification}")
        print(f"    - User attribution: {policy.agent_requirements.user_attribution}")
        print(f"    - Intent declaration: {policy.agent_requirements.intent_declaration}")
        print()

        # Step 2: Read logs (should be allowed)
        print("=" * 60)
        print("Step 2: Reading monitor (should be allowed)...")
        print("=" * 60)
        result = await client.evaluate(
            action="monitor.read",
            resource={"type": "monitor", "id": "mon-123", "env": "production"},
            principal={"user_id": "user-456", "roles": ["viewer"]},
            intent="Check monitor status for incident triage",
        )
        print(f"  Decision: {result.decision}")
        print(f"  Rule: {result.rule_id or 'none (default allow)'}")
        print(f"  Reason: {result.reason or 'n/a'}")
        print()

        # Step 3: Delete monitor in production (should be denied)
        print("=" * 60)
        print("Step 3: Deleting production monitor (should be denied)...")
        print("=" * 60)
        result = await client.evaluate(
            action="monitor.delete",
            resource={"type": "monitor", "id": "mon-123", "env": "production"},
            principal={"user_id": "user-456", "roles": ["editor"]},
            intent="Clean up unused monitor",
        )
        print(f"  Decision: {result.decision}")
        print(f"  Rule: {result.rule_id}")
        print(f"  Reason: {result.reason}")
        if result.remediation:
            print(f"  Remediation type: {result.remediation.type}")
            print(f"  Remediation prompt: {result.remediation.prompt}")
        print()

        # Step 4: Mute monitor in production (should warn)
        print("=" * 60)
        print("Step 4: Muting production monitor (should warn)...")
        print("=" * 60)
        result = await client.evaluate(
            action="monitor.mute",
            resource={"type": "monitor", "id": "mon-456", "env": "production"},
            principal={"user_id": "user-456", "roles": ["editor"]},
            intent="Mute during maintenance window",
        )
        print(f"  Decision: {result.decision}")
        print(f"  Rule: {result.rule_id}")
        print(f"  Reason: {result.reason}")
        print()

        # Step 5: Local evaluation (no network call)
        print("=" * 60)
        print("Step 5: Local policy check (no network call)...")
        print("=" * 60)
        local_result = client.check(
            action="dashboard.delete",
            resource={"type": "dashboard", "env": "production"},
        )
        print(f"  Decision: {local_result.decision}")
        print(f"  Rule: {local_result.rule_id}")
        print()

        # Step 6: Using the decorator pattern
        print("=" * 60)
        print("Step 6: Decorator pattern (deny raises exception)...")
        print("=" * 60)
        try:
            # Simulating a decorated tool call inline
            check = client.check(
                action="monitor.delete",
                resource={"type": "monitor", "env": "production"},
            )
            if check.decision == "deny":
                raise PolicyDeniedError(check)
            print("  Action executed successfully")
        except PolicyDeniedError as e:
            print(f"  Caught PolicyDeniedError: {e}")
        print()

        print("=" * 60)
        print("Done! All scenarios demonstrated.")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
