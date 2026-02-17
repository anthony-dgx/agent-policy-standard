"""Policy evaluation engine with safe expression parser.

Supports:
- Property access: resource.env, principal.user_id
- String literals: 'production', "staging"
- List literals: ['a', 'b', 'c']
- Comparisons: ==, !=
- Logical: AND, OR, NOT
- Set membership: value IN collection
- Glob matching for action patterns: monitor.* matches monitor.delete
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from typing import Any

from server.models import EvalRequest, EvalResponse, Policy, Remediation, Rule


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

class TokenType:
    PROPERTY = "PROPERTY"
    STRING = "STRING"
    LIST_OPEN = "LIST_OPEN"
    LIST_CLOSE = "LIST_CLOSE"
    COMMA = "COMMA"
    EQ = "EQ"
    NEQ = "NEQ"
    AND = "AND"
    OR = "OR"
    NOT = "NOT"
    IN = "IN"
    LPAREN = "LPAREN"
    RPAREN = "RPAREN"
    EOF = "EOF"


@dataclass
class Token:
    type: str
    value: str


_TOKEN_PATTERNS: list[tuple[str, str | None]] = [
    (r"\s+", None),                     # skip whitespace
    (r"!=", TokenType.NEQ),
    (r"==", TokenType.EQ),
    (r"\(", TokenType.LPAREN),
    (r"\)", TokenType.RPAREN),
    (r"\[", TokenType.LIST_OPEN),
    (r"\]", TokenType.LIST_CLOSE),
    (r",", TokenType.COMMA),
    (r"'[^']*'", TokenType.STRING),
    (r'"[^"]*"', TokenType.STRING),
    (r"\bAND\b", TokenType.AND),
    (r"\bOR\b", TokenType.OR),
    (r"\bNOT\b", TokenType.NOT),
    (r"\bIN\b", TokenType.IN),
    (r"[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*", TokenType.PROPERTY),
]

_COMPILED = [(re.compile(p), t) for p, t in _TOKEN_PATTERNS]


def tokenize(expr: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(expr):
        match = None
        for pattern, token_type in _COMPILED:
            match = pattern.match(expr, pos)
            if match:
                if token_type is not None:
                    value = match.group(0)
                    if token_type == TokenType.STRING:
                        value = value[1:-1]  # strip quotes
                    tokens.append(Token(type=token_type, value=value))
                pos = match.end()
                break
        if not match:
            raise ValueError(f"Unexpected character at position {pos}: {expr[pos:]!r}")
    tokens.append(Token(type=TokenType.EOF, value=""))
    return tokens


# ---------------------------------------------------------------------------
# AST Nodes
# ---------------------------------------------------------------------------

@dataclass
class ASTNode:
    pass


@dataclass
class PropertyNode(ASTNode):
    path: str


@dataclass
class StringNode(ASTNode):
    value: str


@dataclass
class ListNode(ASTNode):
    items: list[ASTNode]


@dataclass
class ComparisonNode(ASTNode):
    op: str  # == | !=
    left: ASTNode
    right: ASTNode


@dataclass
class InNode(ASTNode):
    value: ASTNode
    collection: ASTNode


@dataclass
class NotNode(ASTNode):
    operand: ASTNode


@dataclass
class BinaryLogicNode(ASTNode):
    op: str  # AND | OR
    left: ASTNode
    right: ASTNode


# ---------------------------------------------------------------------------
# Recursive descent parser
# ---------------------------------------------------------------------------

class Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token:
        return self.tokens[self.pos]

    def advance(self) -> Token:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def expect(self, token_type: str) -> Token:
        tok = self.advance()
        if tok.type != token_type:
            raise ValueError(f"Expected {token_type}, got {tok.type} ({tok.value!r})")
        return tok

    def parse(self) -> ASTNode:
        node = self.parse_or()
        if self.peek().type != TokenType.EOF:
            raise ValueError(f"Unexpected token: {self.peek().value!r}")
        return node

    def parse_or(self) -> ASTNode:
        left = self.parse_and()
        while self.peek().type == TokenType.OR:
            self.advance()
            right = self.parse_and()
            left = BinaryLogicNode(op="OR", left=left, right=right)
        return left

    def parse_and(self) -> ASTNode:
        left = self.parse_not()
        while self.peek().type == TokenType.AND:
            self.advance()
            right = self.parse_not()
            left = BinaryLogicNode(op="AND", left=left, right=right)
        return left

    def parse_not(self) -> ASTNode:
        if self.peek().type == TokenType.NOT:
            self.advance()
            operand = self.parse_not()
            return NotNode(operand=operand)
        return self.parse_comparison()

    def parse_comparison(self) -> ASTNode:
        left = self.parse_primary()
        if self.peek().type in (TokenType.EQ, TokenType.NEQ):
            op_tok = self.advance()
            right = self.parse_primary()
            return ComparisonNode(op=op_tok.value, left=left, right=right)
        if self.peek().type == TokenType.IN:
            self.advance()
            collection = self.parse_primary()
            return InNode(value=left, collection=collection)
        return left

    def parse_primary(self) -> ASTNode:
        tok = self.peek()
        if tok.type == TokenType.LPAREN:
            self.advance()
            node = self.parse_or()
            self.expect(TokenType.RPAREN)
            return node
        if tok.type == TokenType.STRING:
            self.advance()
            return StringNode(value=tok.value)
        if tok.type == TokenType.PROPERTY:
            self.advance()
            return PropertyNode(path=tok.value)
        if tok.type == TokenType.LIST_OPEN:
            return self.parse_list()
        raise ValueError(f"Unexpected token: {tok.type} ({tok.value!r})")

    def parse_list(self) -> ListNode:
        self.expect(TokenType.LIST_OPEN)
        items: list[ASTNode] = []
        if self.peek().type != TokenType.LIST_CLOSE:
            items.append(self.parse_primary())
            while self.peek().type == TokenType.COMMA:
                self.advance()
                items.append(self.parse_primary())
        self.expect(TokenType.LIST_CLOSE)
        return ListNode(items=items)


def parse_condition(expr: str) -> ASTNode:
    return Parser(tokenize(expr)).parse()


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------

def _resolve_property(path: str, context: dict[str, Any]) -> Any:
    parts = path.split(".")
    current: Any = context
    for part in parts:
        if isinstance(current, dict):
            if part not in current:
                return None
            current = current[part]
        else:
            return None
    return current


def _eval_node(node: ASTNode, context: dict[str, Any]) -> Any:
    if isinstance(node, StringNode):
        return node.value

    if isinstance(node, PropertyNode):
        return _resolve_property(node.path, context)

    if isinstance(node, ListNode):
        return [_eval_node(item, context) for item in node.items]

    if isinstance(node, ComparisonNode):
        left = _eval_node(node.left, context)
        right = _eval_node(node.right, context)
        if node.op == "==":
            return left == right
        return left != right

    if isinstance(node, InNode):
        value = _eval_node(node.value, context)
        collection = _eval_node(node.collection, context)
        if isinstance(collection, list):
            return value in collection
        return False

    if isinstance(node, NotNode):
        return not _eval_node(node.operand, context)

    if isinstance(node, BinaryLogicNode):
        left = _eval_node(node.left, context)
        if node.op == "AND":
            return left and _eval_node(node.right, context)
        return left or _eval_node(node.right, context)

    raise ValueError(f"Unknown node type: {type(node)}")


def evaluate_condition(expr: str, context: dict[str, Any]) -> bool:
    ast = parse_condition(expr)
    return bool(_eval_node(ast, context))


# ---------------------------------------------------------------------------
# Action glob matching
# ---------------------------------------------------------------------------

def action_matches(action: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(action, pattern) for pattern in patterns)


# ---------------------------------------------------------------------------
# Rate limiter (in-memory, for reference implementation)
# ---------------------------------------------------------------------------

def _parse_window(window: str) -> float:
    """Parse window string like '1m', '1h', '1d' into seconds."""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if not window:
        raise ValueError("Empty window")
    unit = window[-1].lower()
    if unit not in units:
        raise ValueError(f"Unknown time unit: {unit}")
    return float(window[:-1]) * units[unit]


@dataclass
class RateLimitState:
    counters: dict[str, list[float]] = field(default_factory=dict)

    def check(self, key: str, max_count: int, window: str) -> bool:
        """Return True if within rate limit, False if exceeded."""
        window_seconds = _parse_window(window)
        now = time.time()
        cutoff = now - window_seconds

        if key not in self.counters:
            self.counters[key] = []

        # Prune old entries
        self.counters[key] = [t for t in self.counters[key] if t > cutoff]

        if len(self.counters[key]) >= max_count:
            return False

        self.counters[key].append(now)
        return True


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------

class PolicyEngine:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.rate_limiter = RateLimitState()

    def _build_context(self, request: EvalRequest) -> dict[str, Any]:
        ctx: dict[str, Any] = {}
        ctx["agent"] = request.agent.model_dump()
        if request.principal:
            ctx["principal"] = request.principal.model_dump()
        if request.resource:
            ctx["resource"] = request.resource
        if request.context:
            ctx["context"] = request.context
        if request.intent:
            ctx["intent"] = request.intent
        ctx["action"] = request.action
        return ctx

    def evaluate(self, request: EvalRequest) -> EvalResponse:
        context = self._build_context(request)

        for rule in self.policy.rules:
            if not action_matches(request.action, rule.actions):
                continue

            # Evaluate condition if present
            if rule.condition:
                try:
                    condition_met = evaluate_condition(rule.condition, context)
                except Exception:
                    # If condition parsing fails, skip this rule
                    continue
                if not condition_met:
                    continue

            # Check rate limit if present
            if rule.rate_limit:
                per_value = ""
                if rule.rate_limit.per == "agent":
                    per_value = request.agent.id
                elif rule.rate_limit.per == "principal" and request.principal:
                    per_value = request.principal.user_id or ""
                rate_key = f"{rule.id}:{per_value}"
                if not self.rate_limiter.check(
                    rate_key, rule.rate_limit.max, rule.rate_limit.window
                ):
                    return EvalResponse(
                        decision="deny",
                        rule_id=rule.id,
                        reason=f"Rate limit exceeded: {rule.rate_limit.max} per {rule.rate_limit.window}",
                        remediation=Remediation(
                            type="retry_after",
                            prompt=f"Rate limit exceeded. Wait and retry after the {rule.rate_limit.window} window resets.",
                        ),
                    )

            # Rule matched — apply enforcement
            if rule.enforcement == "strict":
                return EvalResponse(
                    decision="deny",
                    rule_id=rule.id,
                    reason=rule.description,
                    remediation=rule.remediation,
                )
            elif rule.enforcement == "warn":
                return EvalResponse(
                    decision="warn",
                    rule_id=rule.id,
                    reason=rule.description,
                )
            # audit — log only, effectively allow
            elif rule.enforcement == "audit":
                return EvalResponse(
                    decision="allow",
                    rule_id=rule.id,
                    reason=f"Audit: {rule.description}",
                )

        # No rule matched → allow
        return EvalResponse(decision="allow")
