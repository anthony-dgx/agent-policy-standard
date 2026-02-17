# Agent Policy Standard — Phase 1 Reference Implementation

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

### Install

```bash
cd agent-policy-standard
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest tests/
```

### Start the Server

```bash
uvicorn server.app:app --port 8000
```

### Discover the Policy

```bash
curl http://localhost:8000/.well-known/agent-policy.json | python -m json.tool
```

### Evaluate an Action

```bash
curl -X POST http://localhost:8000/agent/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent": {"id": "my-agent"},
    "action": "monitor.delete",
    "resource": {"type": "monitor", "env": "production"}
  }'
```

### Run the Example

```bash
# In one terminal:
uvicorn server.app:app --port 8000

# In another:
python examples/agent_example.py
```

## Project Structure

```
spec/               JSON Schemas for the policy format and evaluation API
server/             FastAPI policy server + evaluation engine
  engine.py         Safe expression parser (no eval()) + policy evaluator
  models.py         Pydantic models
  app.py            FastAPI endpoints
  policies/         Example policy files
sdk/                Agent SDK for discovering and complying with policies
  client.py         AgentPolicyClient (discover, evaluate, check)
  decorator.py      @enforce_policy decorator for tool functions
tests/              Unit and integration tests
examples/           End-to-end usage example
```

## How It Works

### Policy Document

Resource servers publish a policy at `/.well-known/agent-policy.json`:

```json
{
  "version": "1.0",
  "issuer": "https://api.datadoghq.com",
  "policy_endpoint": "https://api.datadoghq.com/agent/policy/evaluate",
  "agent_requirements": {
    "identification": "required",
    "user_attribution": "required",
    "intent_declaration": "recommended"
  },
  "rules": [
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
  ]
}
```

### Condition Language

Rules can include conditions — safe expressions evaluated against request context:

- Property access: `resource.env`, `principal.user_id`
- Comparisons: `==`, `!=`
- Logic: `AND`, `OR`, `NOT`
- Set membership: `role IN ['admin', 'editor']`
- Parentheses for grouping

Implemented as a hand-rolled tokenizer + recursive descent parser — no `eval()`.

### Enforcement Levels

| Level    | Behavior                                |
|----------|-----------------------------------------|
| `strict` | Deny the action, return remediation     |
| `warn`   | Allow but log a warning                 |
| `audit`  | Allow and log for review                |

### Agent SDK

```python
from sdk.client import AgentPolicyClient

async with AgentPolicyClient(agent_id="my-agent") as client:
    # Discover policy
    await client.discover("https://api.example.com")

    # Check before acting
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

@enforce_policy(client, action="monitor.delete",
                resource_fn=lambda mid: {"id": mid, "env": "production"})
async def delete_monitor(monitor_id: str):
    ...  # Only runs if policy allows
```

## Spec Details

Full JSON Schemas are in `spec/`:

- `agent-policy-schema.json` — Policy document format
- `evaluation-schema.json` — Evaluation request/response format
