from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class RateLimit(BaseModel):
    max: int = Field(ge=1)
    window: str
    per: str = "agent"


class Remediation(BaseModel):
    type: str  # human_approval | reduce_scope | retry_after | alternative_action
    prompt: str


class Rule(BaseModel):
    id: str
    description: str
    actions: list[str]
    enforcement: str  # strict | warn | audit
    condition: str | None = None
    rate_limit: RateLimit | None = None
    remediation: Remediation | None = None


class AgentRequirements(BaseModel):
    identification: str = "none"
    user_attribution: str = "none"
    intent_declaration: str = "none"


class Audit(BaseModel):
    log_decisions: bool = False
    log_actions: bool = False
    retention_days: int = 30


class Policy(BaseModel):
    version: str = "1.0"
    issuer: str
    policy_endpoint: str
    updated_at: datetime
    agent_requirements: AgentRequirements = Field(default_factory=AgentRequirements)
    rules: list[Rule]
    audit: Audit = Field(default_factory=Audit)


class AgentInfo(BaseModel):
    id: str
    name: str | None = None
    version: str | None = None


class Principal(BaseModel):
    user_id: str | None = None
    roles: list[str] = Field(default_factory=list)


class EvalRequest(BaseModel):
    agent: AgentInfo
    principal: Principal | None = None
    intent: str | None = None
    action: str
    resource: dict[str, Any] | None = None
    context: dict[str, Any] | None = None


class EvalResponse(BaseModel):
    decision: str  # allow | deny | warn
    rule_id: str | None = None
    reason: str | None = None
    remediation: Remediation | None = None
