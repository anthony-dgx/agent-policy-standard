"""@enforce_policy decorator for agent tool calls."""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from sdk.client import AgentPolicyClient, PolicyDeniedError
from server.models import EvalResponse

logger = logging.getLogger(__name__)


def enforce_policy(
    client: AgentPolicyClient,
    action: str,
    resource_fn: Callable[..., dict[str, Any] | None] | None = None,
    principal: dict[str, Any] | None = None,
    intent: str | None = None,
) -> Callable:
    """Decorator that enforces agent policy before executing a tool function.

    Args:
        client: An AgentPolicyClient with a discovered policy.
        action: The action name (e.g., "monitor.delete").
        resource_fn: Optional callable that extracts resource info from the
            decorated function's arguments. Receives the same args/kwargs.
        principal: Optional principal info dict.
        intent: Optional intent description.

    Usage:
        @enforce_policy(client, action="monitor.delete",
                        resource_fn=lambda monitor_id, **kw: {"type": "monitor", "id": monitor_id, "env": "production"})
        async def delete_monitor(monitor_id: str) -> dict:
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            resource = None
            if resource_fn is not None:
                resource = resource_fn(*args, **kwargs)

            result: EvalResponse = client.check(
                action=action,
                resource=resource,
                principal=principal,
                intent=intent,
            )

            if result.decision == "deny":
                logger.warning(
                    "Policy denied: action=%s rule=%s reason=%s",
                    action,
                    result.rule_id,
                    result.reason,
                )
                raise PolicyDeniedError(result)

            if result.decision == "warn":
                logger.warning(
                    "Policy warning: action=%s rule=%s reason=%s",
                    action,
                    result.rule_id,
                    result.reason,
                )

            logger.info("Policy allowed: action=%s", action)
            return await func(*args, **kwargs)

        return wrapper

    return decorator
