"""Tests for the policy condition engine."""

import pytest

from server.engine import (
    PolicyEngine,
    RateLimitState,
    action_matches,
    evaluate_condition,
    parse_condition,
    tokenize,
)
from server.models import (
    AgentInfo,
    EvalRequest,
    Policy,
    Principal,
    RateLimit,
    Remediation,
    Rule,
)


# ---------------------------------------------------------------------------
# Tokenizer tests
# ---------------------------------------------------------------------------

class TestTokenizer:
    def test_simple_comparison(self):
        tokens = tokenize("resource.env == 'production'")
        types = [t.type for t in tokens[:-1]]  # exclude EOF
        assert types == ["PROPERTY", "EQ", "STRING"]

    def test_logical_operators(self):
        tokens = tokenize("a == 'x' AND b != 'y'")
        types = [t.type for t in tokens[:-1]]
        assert types == ["PROPERTY", "EQ", "STRING", "AND", "PROPERTY", "NEQ", "STRING"]

    def test_in_operator(self):
        tokens = tokenize("role IN ['admin', 'editor']")
        types = [t.type for t in tokens[:-1]]
        assert types == ["PROPERTY", "IN", "LIST_OPEN", "STRING", "COMMA", "STRING", "LIST_CLOSE"]

    def test_not_operator(self):
        tokens = tokenize("NOT active")
        types = [t.type for t in tokens[:-1]]
        assert types == ["NOT", "PROPERTY"]

    def test_invalid_character_raises(self):
        with pytest.raises(ValueError, match="Unexpected character"):
            tokenize("a @ b")

    def test_double_quoted_strings(self):
        tokens = tokenize('name == "hello"')
        assert tokens[2].value == "hello"


# ---------------------------------------------------------------------------
# Parser + evaluator tests
# ---------------------------------------------------------------------------

class TestEvaluateCondition:
    def test_simple_equality(self):
        assert evaluate_condition("resource.env == 'production'", {"resource": {"env": "production"}})

    def test_simple_inequality(self):
        assert evaluate_condition("resource.env != 'staging'", {"resource": {"env": "production"}})

    def test_equality_false(self):
        assert not evaluate_condition("resource.env == 'production'", {"resource": {"env": "staging"}})

    def test_and_both_true(self):
        ctx = {"resource": {"env": "production"}, "action": "delete"}
        assert evaluate_condition("resource.env == 'production' AND action == 'delete'", ctx)

    def test_and_one_false(self):
        ctx = {"resource": {"env": "staging"}, "action": "delete"}
        assert not evaluate_condition("resource.env == 'production' AND action == 'delete'", ctx)

    def test_or_one_true(self):
        ctx = {"resource": {"env": "staging"}}
        assert evaluate_condition("resource.env == 'production' OR resource.env == 'staging'", ctx)

    def test_or_both_false(self):
        ctx = {"resource": {"env": "dev"}}
        assert not evaluate_condition("resource.env == 'production' OR resource.env == 'staging'", ctx)

    def test_not(self):
        assert evaluate_condition("NOT resource.env == 'staging'", {"resource": {"env": "production"}})

    def test_not_false(self):
        assert not evaluate_condition("NOT resource.env == 'production'", {"resource": {"env": "production"}})

    def test_in_list(self):
        ctx = {"role": "admin"}
        assert evaluate_condition("role IN ['admin', 'editor']", ctx)

    def test_not_in_list(self):
        ctx = {"role": "viewer"}
        assert not evaluate_condition("role IN ['admin', 'editor']", ctx)

    def test_nested_property(self):
        ctx = {"principal": {"user_id": "user-123"}}
        assert evaluate_condition("principal.user_id == 'user-123'", ctx)

    def test_missing_property_returns_none(self):
        ctx = {"resource": {}}
        assert not evaluate_condition("resource.env == 'production'", ctx)

    def test_parentheses(self):
        ctx = {"a": "1", "b": "2", "c": "3"}
        assert evaluate_condition("(a == '1' OR b == '9') AND c == '3'", ctx)

    def test_complex_expression(self):
        ctx = {"resource": {"env": "production"}, "principal": {"roles": "admin"}}
        expr = "resource.env == 'production' AND NOT principal.roles == 'viewer'"
        assert evaluate_condition(expr, ctx)

    def test_malformed_condition_raises(self):
        with pytest.raises(ValueError):
            parse_condition("== ==")


# ---------------------------------------------------------------------------
# Action glob matching tests
# ---------------------------------------------------------------------------

class TestActionMatching:
    def test_exact_match(self):
        assert action_matches("monitor.delete", ["monitor.delete"])

    def test_wildcard_suffix(self):
        assert action_matches("monitor.delete", ["monitor.*"])

    def test_wildcard_prefix(self):
        assert action_matches("monitor.read", ["*.read"])

    def test_no_match(self):
        assert not action_matches("monitor.read", ["dashboard.*"])

    def test_multiple_patterns(self):
        assert action_matches("slo.delete", ["monitor.delete", "slo.delete"])

    def test_full_wildcard(self):
        assert action_matches("anything.goes", ["*.*"])


# ---------------------------------------------------------------------------
# Rate limiter tests
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_within_limit(self):
        rl = RateLimitState()
        for _ in range(5):
            assert rl.check("key", 5, "1m")

    def test_exceeds_limit(self):
        rl = RateLimitState()
        for _ in range(5):
            rl.check("key", 5, "1m")
        assert not rl.check("key", 5, "1m")

    def test_different_keys_independent(self):
        rl = RateLimitState()
        for _ in range(5):
            rl.check("key1", 5, "1m")
        assert rl.check("key2", 5, "1m")


# ---------------------------------------------------------------------------
# PolicyEngine integration tests
# ---------------------------------------------------------------------------

class TestPolicyEngine:
    def _make_policy(self, rules: list[Rule]) -> Policy:
        return Policy(
            issuer="https://test.example.com",
            policy_endpoint="https://test.example.com/agent/policy/evaluate",
            updated_at="2026-01-01T00:00:00Z",
            rules=rules,
        )

    def _make_request(self, action: str, **kwargs) -> EvalRequest:
        return EvalRequest(
            agent=AgentInfo(id="test-agent"),
            action=action,
            **kwargs,
        )

    def test_allow_when_no_rules_match(self):
        engine = PolicyEngine(self._make_policy([
            Rule(id="r1", description="test", actions=["dashboard.*"], enforcement="strict"),
        ]))
        result = engine.evaluate(self._make_request("monitor.read"))
        assert result.decision == "allow"

    def test_strict_deny(self):
        engine = PolicyEngine(self._make_policy([
            Rule(
                id="r1",
                description="No prod deletes",
                actions=["monitor.delete"],
                enforcement="strict",
                condition="resource.env == 'production'",
                remediation=Remediation(type="human_approval", prompt="Ask a human"),
            ),
        ]))
        result = engine.evaluate(self._make_request(
            "monitor.delete",
            resource={"env": "production"},
        ))
        assert result.decision == "deny"
        assert result.rule_id == "r1"
        assert result.remediation is not None
        assert result.remediation.type == "human_approval"

    def test_strict_allow_when_condition_not_met(self):
        engine = PolicyEngine(self._make_policy([
            Rule(
                id="r1",
                description="No prod deletes",
                actions=["monitor.delete"],
                enforcement="strict",
                condition="resource.env == 'production'",
            ),
        ]))
        result = engine.evaluate(self._make_request(
            "monitor.delete",
            resource={"env": "staging"},
        ))
        assert result.decision == "allow"

    def test_warn_decision(self):
        engine = PolicyEngine(self._make_policy([
            Rule(id="r1", description="Careful!", actions=["monitor.mute"], enforcement="warn"),
        ]))
        result = engine.evaluate(self._make_request("monitor.mute"))
        assert result.decision == "warn"

    def test_audit_decision(self):
        engine = PolicyEngine(self._make_policy([
            Rule(id="r1", description="Log reads", actions=["*.read"], enforcement="audit"),
        ]))
        result = engine.evaluate(self._make_request("monitor.read"))
        assert result.decision == "allow"
        assert result.rule_id == "r1"

    def test_rate_limit_exceeded(self):
        engine = PolicyEngine(self._make_policy([
            Rule(
                id="r1",
                description="Rate limit",
                actions=["*.write"],
                enforcement="strict",
                rate_limit=RateLimit(max=2, window="1m", per="agent"),
            ),
        ]))
        req = self._make_request("data.write")
        engine.evaluate(req)
        engine.evaluate(req)
        result = engine.evaluate(req)
        assert result.decision == "deny"
        assert "Rate limit exceeded" in (result.reason or "")

    def test_rules_evaluated_in_order(self):
        engine = PolicyEngine(self._make_policy([
            Rule(id="r1", description="Deny all deletes", actions=["*.delete"], enforcement="strict"),
            Rule(id="r2", description="Allow all", actions=["*.*"], enforcement="audit"),
        ]))
        result = engine.evaluate(self._make_request("monitor.delete"))
        assert result.decision == "deny"
        assert result.rule_id == "r1"
