"""A1-R9: pure, bounded and typed rule evaluation, not an operational gate.

Thesis: 3.3.2, Figs. 3.4-3.5 (printed pp. 90, 105-106).
No dynamic Python evaluation, external references, I/O, execution, or authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from ardrec.state import Truth

MAX_DEPTH = 24
MAX_NODES = 256
MAX_RULES = 64
MAX_FIELDS = 64
MAX_TEXT = 128
MAX_INT = 2**63 - 1
_FIELD_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_TYPES = frozenset({"boolean", "integer", "string", "string_set"})
_COMPARE = frozenset({"IGUAL", "MENOR", "MENOR_IGUAL", "MAYOR", "MAYOR_IGUAL", "PERTENECE", "SUBCONJUNTO"})


class RuleError(ValueError):
    """A typed deterministic contract violation; NEVER an approval."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise RuleError(code)


def _ref(value: Any, *, digest: bool = False) -> None:
    pattern = _DIGEST_RE if digest else _REF_RE
    _require(type(value) is str and pattern.fullmatch(value) is not None, "IDENTITY_INVALID")


def _field(value: Any) -> None:
    _require(type(value) is str and _FIELD_RE.fullmatch(value) is not None, "FIELD_INVALID")


def _value(value: Any, kind: str) -> Any:
    if kind == "boolean":
        _require(type(value) is bool, "VALUE_TYPE_INVALID")
        return Truth.VERDADERO if value else Truth.FALSO
    if kind == "integer":
        _require(type(value) is int and -MAX_INT <= value <= MAX_INT, "VALUE_TYPE_INVALID")
        return value
    if kind == "string":
        _require(type(value) is str and len(value) <= MAX_TEXT, "VALUE_TYPE_INVALID")
        return value
    if kind == "string_set":
        _require(type(value) in (list, tuple) and len(value) <= MAX_FIELDS,
                 "VALUE_TYPE_INVALID")
        _require(all(type(x) is str and len(x) <= MAX_TEXT for x in value),
                 "VALUE_TYPE_INVALID")
        _require(len(value) == len(set(value)), "VALUE_DUPLICATE")
        return frozenset(value)
    raise RuleError("VALUE_TYPE_INVALID")


def _schema(schema: Any) -> tuple[dict[str, str], frozenset[str]]:
    _require(type(schema) is dict and set(schema) == {"field_types", "optional_fields"},
             "SCHEMA_INVALID")
    types = schema["field_types"]
    optionals = schema["optional_fields"]
    _require(type(types) is dict and 0 < len(types) <= MAX_FIELDS, "SCHEMA_INVALID")
    for name, kind in types.items():
        _field(name)
        _require(type(kind) is str and kind in _TYPES, "SCHEMA_INVALID")
    _require(type(optionals) is list and len(optionals) <= len(types), "SCHEMA_INVALID")
    _require(all(type(x) is str and x in types for x in optionals)
             and len(set(optionals)) == len(optionals), "SCHEMA_INVALID")
    return types, frozenset(optionals)


def _environment(env: Any, types: dict[str, str], optionals: frozenset[str]) -> dict[str, Any]:
    _require(type(env) is dict and set(env) <= set(types), "ENVIRONMENT_INVALID")
    _require(set(types) - optionals <= set(env), "FIELD_REQUIRED_ABSENT")
    # Validate all present values, including fields not referenced by any expression.
    return {name: _value(val, types[name]) for name, val in env.items()}


def _typecheck(node: Any, types: dict[str, str], *, depth: int,
               budget: list[int], ancestors: frozenset[int]) -> str:
    _require(depth <= MAX_DEPTH, "EXPRESSION_DEPTH_EXCEEDED")
    _require(type(node) is dict, "EXPRESSION_INVALID")
    identity = id(node)
    _require(identity not in ancestors, "EXPRESSION_CYCLE")
    budget[0] += 1
    _require(budget[0] <= MAX_NODES, "EXPRESSION_NODES_EXCEEDED")
    ancestor_next = ancestors | {identity}
    op = node.get("op")
    _require(type(op) is str, "EXPRESSION_INVALID")
    if op == "CONST":
        _require(set(node) == {"op", "type", "value"}, "EXPRESSION_INVALID")
        kind = node["type"]
        _require(type(kind) is str and kind in _TYPES, "EXPRESSION_INVALID")
        _value(node["value"], kind)
        return kind
    if op == "FIELD":
        _require(set(node) == {"op", "path"}, "EXPRESSION_INVALID")
        _field(node["path"])
        _require(node["path"] in types, "FIELD_NOT_ALLOWED")
        return types[node["path"]]
    if op == "NO":
        _require(set(node) == {"op", "arg"}, "EXPRESSION_INVALID")
        kind = _typecheck(node["arg"], types, depth=depth+1, budget=budget,
                          ancestors=ancestor_next)
        _require(kind == "boolean", "TYPE_INCOMPATIBLE")
        return "boolean"
    if op in {"Y", "O"}:
        _require(set(node) == {"op", "args"}, "EXPRESSION_INVALID")
        args = node["args"]
        _require(type(args) is list and 1 <= len(args) <= MAX_FIELDS, "EXPRESSION_INVALID")
        for arg in args:
            _require(_typecheck(arg, types, depth=depth+1, budget=budget,
                                ancestors=ancestor_next) == "boolean", "TYPE_INCOMPATIBLE")
        return "boolean"
    if op in _COMPARE:
        _require(set(node) == {"op", "left", "right"}, "EXPRESSION_INVALID")
        left = _typecheck(node["left"], types, depth=depth+1,
                          budget=budget, ancestors=ancestor_next)
        right = _typecheck(node["right"], types, depth=depth+1,
                           budget=budget, ancestors=ancestor_next)
        valid = (left == right if op == "IGUAL" else
                 left == right == "integer" if op in {"MENOR", "MENOR_IGUAL", "MAYOR", "MAYOR_IGUAL"} else
                 left == "string" and right == "string_set" if op == "PERTENECE" else
                 left == right == "string_set")
        _require(valid, "TYPE_INCOMPATIBLE")
        return "boolean"
    raise RuleError("OPERATOR_NOT_ALLOWED")


def _evaluate(node: dict[str, Any], env: dict[str, Any]) -> Any:
    op = node["op"]
    if op == "CONST":
        return _value(node["value"], node["type"])
    if op == "FIELD":
        return env.get(node["path"], Truth.ND)
    if op == "NO":
        v = _evaluate(node["arg"], env)
        return {Truth.VERDADERO: Truth.FALSO, Truth.FALSO: Truth.VERDADERO,
                Truth.ND: Truth.ND}[v]
    if op in {"Y", "O"}:
        values = [_evaluate(arg, env) for arg in node["args"]]
        if op == "Y":
            return (Truth.FALSO if Truth.FALSO in values else
                    Truth.ND if Truth.ND in values else Truth.VERDADERO)
        return (Truth.VERDADERO if Truth.VERDADERO in values else
                Truth.ND if Truth.ND in values else Truth.FALSO)
    left = _evaluate(node["left"], env)
    right = _evaluate(node["right"], env)
    if left is Truth.ND or right is Truth.ND:
        return Truth.ND
    value = {
        "IGUAL": lambda: left == right,
        "MENOR": lambda: left < right,
        "MENOR_IGUAL": lambda: left <= right,
        "MAYOR": lambda: left > right,
        "MAYOR_IGUAL": lambda: left >= right,
        "PERTENECE": lambda: left in right,
        "SUBCONJUNTO": lambda: left <= right,
    }[op]()
    return Truth.VERDADERO if value else Truth.FALSO


def evaluate_expression(expression: dict[str, Any], env: dict[str, Any],
                        schema: dict[str, Any]) -> Any:
    """Pure expression evaluation; schema is an explicit caller-supplied allowlist."""
    types, optionals = _schema(schema)
    safe_env = _environment(env, types, optionals)
    _typecheck(expression, types, depth=1, budget=[0], ancestors=frozenset())
    return _evaluate(expression, safe_env)


@dataclass(frozen=True, slots=True)
class RuleDecision:
    status: str  # DETERMINADO | ND
    rule_id: str | None
    outcome: str | None
    provenance: str | None
    matched_rule_ids: tuple[str, ...]
    indeterminate: bool
    record_id: str
    service_id: str
    case_id: str
    generation: int
    configuration_sha256: str
    authorized: bool = False
    dispatch_allowed: bool = False


def decide(table: Any, env: Any, schema: Any, context: Any) -> RuleDecision:
    """Review a complete finite table; never authorize or dispatch.

    More than one true row is ambiguous; any ND or zero matching rows yields ND.
    A unique matched row is a DETERMINADO *selection*, not operational permission.
    """
    types, optionals = _schema(schema)
    safe_env = _environment(env, types, optionals)
    _require(type(context) is dict and set(context) == {
        "record_id", "service_id", "case_id", "generation", "configuration_sha256"
    }, "CONTEXT_INVALID")
    for key in ("record_id", "service_id", "case_id"):
        _ref(context[key])
    _ref(context["configuration_sha256"], digest=True)
    _require(type(context["generation"]) is int and 0 <= context["generation"] <= MAX_INT,
             "CONTEXT_INVALID")
    _require(type(table) is list and 1 <= len(table) <= MAX_RULES, "TABLE_INVALID")
    seen: set[str] = set()
    matched: list[dict[str, Any]] = []
    indeterminate = False
    budget = [0]
    # Fully validate the table before computing decisions; fail closed on unused rows.
    for row in table:
        _require(type(row) is dict and set(row) == {
            "rule_id", "condition", "outcome", "provenance"
        }, "TABLE_INVALID")
        for key in ("rule_id", "outcome", "provenance"):
            _ref(row[key])
        _require(row["rule_id"] not in seen, "RULE_ID_DUPLICATE")
        seen.add(row["rule_id"])
        _require(_typecheck(row["condition"], types, depth=1,
                            budget=budget, ancestors=frozenset()) == "boolean", "TYPE_INCOMPATIBLE")
    for row in table:
        result = _evaluate(row["condition"], safe_env)
        if result is Truth.ND:
            indeterminate = True
        elif result is Truth.VERDADERO:
            matched.append(row)
    _require(len(matched) <= 1, "RULES_AMBIGUOUS")
    resolved = len(matched) == 1 and not indeterminate
    chosen = matched[0] if resolved else None
    return RuleDecision(
        status="DETERMINADO" if resolved else "ND",
        rule_id=chosen["rule_id"] if chosen else None,
        outcome=chosen["outcome"] if chosen else None,
        provenance=chosen["provenance"] if chosen else None,
        matched_rule_ids=tuple(x["rule_id"] for x in matched),
        indeterminate=indeterminate,
        record_id=context["record_id"], service_id=context["service_id"],
        case_id=context["case_id"], generation=context["generation"],
        configuration_sha256=context["configuration_sha256"],
    )
