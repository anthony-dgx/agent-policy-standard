# Agent Policy Standard

An open standard for **Resource-Defined Agent Policies**: a way for API providers to publish machine-readable rules that AI agents must follow.

## The Problem

AI agents interact with APIs (Datadog, Jira, Slack, etc.) on behalf of users, but there's no standard way for API providers to express constraints like:

- "Don't delete production monitors without human approval"
- "Rate limit write operations to 100/minute"
- "Require intent declarations for destructive actions"

Each provider builds bespoke guardrails. Agents have no way to discover or comply with policies automatically.

## The Solution

A simple, discoverable protocol inspired by `robots.txt` and OAuth's `.well-known`:

1. **Resource servers** publish an `agent-policy.json` at `/.well-known/agent-policy.json`
2. **Agents** discover and fetch this policy before making API calls
3. **Rules** define what actions are allowed, denied, or warned — with conditions, rate limits, and remediation instructions
4. A **runtime evaluation endpoint** lets agents check actions before executing them

## Quickstart

```bash
# Install
cd agent-policy-standard
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/

# Start the policy server
uvicorn server.app:app --port 8000

# Discover the policy
curl http://localhost:8000/.well-known/agent-policy.json | python -m json.tool

# Evaluate an action
curl -X POST http://localhost:8000/agent/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent": {"id": "my-agent"},
    "action": "monitor.delete",
    "resource": {"type": "monitor", "env": "production"}
  }'
```

## Demo: Full End-to-End

The `demo/` directory contains a complete MonitoringPlatform backend that combines real business API endpoints with server-side policy enforcement. This demonstrates the full flow: agent discovers policy, agent calls real API, policy is enforced transparently via middleware.

```bash
# Terminal 1 — start the demo server
source .venv/bin/activate
uvicorn demo.app:app --port 8000

# Terminal 2 — run the agent script
source .venv/bin/activate
python demo/run_agent.py
```

The agent script exercises every enforcement path:

| Step | Action | Expected |
|------|--------|----------|
| 1 | List monitors | Allowed (audit) |
| 2 | Create a staging monitor | Allowed |
| 3 | Read the created monitor | Allowed (audit) |
| 4 | Delete a staging monitor | Allowed |
| 5 | Delete a production monitor | **Denied** (403 + remediation) |
| 6 | Mute a production monitor | **Warned** but allowed |
| 7 | Burst writes past rate limit | **Denied** (rate limit) |

### How the demo enforcement works

Requests to `/api/*` with an `X-Agent-Id` header are automatically evaluated against the policy before reaching the handler:

- HTTP method + path are mapped to action names (e.g., `DELETE /api/monitors/123` becomes `monitor.delete`)
- `deny` decisions return a 403 with reason and remediation instructions
- `warn` decisions proceed but add `X-Policy-Warning` and `X-Policy-Rule` response headers
- Requests without `X-Agent-Id` bypass enforcement entirely (regular API usage)

## Project Structure

```
spec/               JSON Schemas for the policy format and evaluation API
server/             FastAPI policy server + evaluation engine
  engine.py         Safe expression parser (no eval()) + policy evaluator
  models.py         Pydantic models (Policy, Rule, EvalRequest, EvalResponse)
  app.py            FastAPI endpoints
  policies/         Example policy files
sdk/                Agent SDK for discovering and complying with policies
  client.py         AgentPolicyClient (discover, evaluate, check)
  decorator.py      @enforce_policy decorator for tool functions
demo/               Full demo backend with business API + policy enforcement
  app.py            MonitoringPlatform API (monitors + dashboards CRUD)
  policy.json       Demo policy (4 rules: deny, warn, rate limit, audit)
  run_agent.py      End-to-end agent script
tests/              80 tests covering engine, SDK, server, and demo
examples/           Standalone evaluation example
```

## How It Works

### 1. Policy Discovery

Resource servers publish a policy at `/.well-known/agent-policy.json`:

```json
{
  "version": "1.0",
  "issuer": "https://api.example.com",
  "policy_endpoint": "https://api.example.com/agent/policy/evaluate",
  "agent_requirements": {
    "identification": "required",
    "user_attribution": "required",
    "intent_declaration": "recommended"
  },
  "rules": [...]
}
```

### 2. Rules

Each rule targets a set of actions (with glob patterns), specifies an enforcement level, and can include conditions, rate limits, and remediation:

```json
{
  "id": "dd-001",
  "description": "Deny destructive actions on production without approval",
  "actions": ["monitor.delete", "dashboard.delete"],
  "enforcement": "strict",
  "condition": "resource.env == 'production'",
  "remediation": {
    "type": "human_approval",
    "prompt": "Ask the user to confirm this action."
  }
}
```

### 3. Enforcement Levels

| Level | Behavior |
|-------|----------|
| `strict` | Deny the action, return remediation instructions |
| `warn` | Allow but surface a warning to the agent |
| `audit` | Allow silently, log for review |

### 4. Condition Language

Rules can include conditions — safe expressions evaluated against request context:

- Property access: `resource.env`, `principal.user_id`
- Comparisons: `==`, `!=`
- Logic: `AND`, `OR`, `NOT`
- Set membership: `role IN ['admin', 'editor']`
- Parentheses for grouping

Implemented as a hand-rolled tokenizer + recursive descent parser. No `eval()`.

### 5. Rate Limiting

Rules can include rate limits that deny actions once the threshold is exceeded:

```json
{
  "rate_limit": {
    "max": 5,
    "window": "1m",
    "per": "agent"
  }
}
```

### 6. Remediation

When a rule denies an action, it can return structured remediation instructions so agents know how to fix the issue:

| Type | Meaning |
|------|---------|
| `human_approval` | Ask the user to confirm |
| `reduce_scope` | Use a less privileged action |
| `retry_after` | Wait and retry (rate limits) |
| `alternative_action` | Suggest a different action |

## Agent SDK

### Client

```python
from sdk.client import AgentPolicyClient

async with AgentPolicyClient(agent_id="my-agent") as client:
    # Discover policy from the resource server
    await client.discover("https://api.example.com")

    # Remote evaluation (calls the server)
    result = await client.evaluate(
        action="monitor.delete",
        resource={"env": "production"},
    )

    # Local evaluation (uses cached policy, no network call)
    result = client.check(
        action="monitor.delete",
        resource={"env": "production"},
    )

    if result.decision == "deny":
        print(f"Denied: {result.reason}")
        print(f"Fix: {result.remediation.prompt}")
```

### Decorator

```python
from sdk.decorator import enforce_policy

@enforce_policy(
    client,
    action="monitor.delete",
    resource_fn=lambda mid: {"id": mid, "env": "production"},
)
async def delete_monitor(monitor_id: str):
    ...  # Only runs if policy allows; raises PolicyDeniedError on deny
```

## Spec

Full JSON Schemas are in `spec/`:

- `agent-policy-schema.json` — Policy document format
- `evaluation-schema.json` — Evaluation request/response format
