"""A1-R16: EVALUAR y DECIDIR, núcleo puro tipado de tres valores.

No lee datos externos, no cambia estado, no ejecuta comandos y no concede
permisos P8. Un ND conserva la incertidumbre y nunca habilita una guarda.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import re
from typing import Any

from ardrec.state import Truth

TYPES = frozenset({"LOGICO", "RACIONAL", "TEXTO"})
RELATIONS = frozenset({"IGUAL", "DISTINTO", "MENOR", "MENOR_IGUAL", "MAYOR", "MAYOR_IGUAL"})
ID = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z", re.ASCII)
RATIONAL = re.compile(r"(?:0|-?[1-9][0-9]*)(?:/[1-9][0-9]*)?\Z", re.ASCII)
MAX_DEPTH, MAX_NODES, MAX_RULES = 20, 256, 128


class A1Error(ValueError):
    """Una regla no satisface el contrato estático o dinámico."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class Node:
    kind: str
    domain: str
    children: tuple[Node, ...] = ()
    data: Any = None


@dataclass(frozen=True, slots=True)
class Decision:
    status: Truth
    selected: str | None
    evaluations: tuple[tuple[str, Truth], ...]

    @property
    def authorized(self) -> bool:
        return self.status is Truth.VERDADERO and self.selected is not None


def _schema(schema: dict[str, str]) -> None:
    if type(schema) is not dict or len(schema) > 128:
        raise A1Error("esquema_invalido")
    for name, domain in schema.items():
        if type(name) is not str or not ID.fullmatch(name) or type(domain) is not str or domain not in TYPES:
            raise A1Error("campo_no_autorizado")


def _keys(expr: dict, names: set[str]) -> None:
    if set(expr) != names:
        raise A1Error("estructura_invalida")


def _fraction(source: str) -> Fraction:
    if type(source) is not str or len(source) > 80 or not RATIONAL.fullmatch(source):
        raise A1Error("racional_invalido")
    value = Fraction(source)
    canonical = str(value.numerator) if value.denominator == 1 else f"{value.numerator}/{value.denominator}"
    if canonical != source:
        raise A1Error("racional_no_canonico")
    return value


def _literal(domain: str, raw: Any) -> Any:
    if domain == "LOGICO":
        if type(raw) is not str or raw not in Truth.__members__:
            raise A1Error("constante_logica_invalida")
        return Truth[raw]
    if domain == "RACIONAL":
        return _fraction(raw)
    if domain == "TEXTO":
        if type(raw) is not str or not 0 < len(raw) <= 128:
            raise A1Error("constante_texto_invalida")
        return raw
    raise A1Error("tipo_invalido")


def compile_expression(expr: dict, schema: dict[str, str]) -> Node:
    """Valida el árbol completo ANTES de cualquier evaluación; no hay eval()."""
    _schema(schema)
    ancestors: set[int] = set()
    count = 0

    def visit(raw: Any, depth: int) -> Node:
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise A1Error("expresion_no_acotada")
        if type(raw) is not dict:
            raise A1Error("estructura_invalida")
        key = id(raw)
        if key in ancestors:
            raise A1Error("expresion_ciclica")
        ancestors.add(key)
        try:
            op = raw.get("op")
            if op == "CONSTANTE":
                _keys(raw, {"op", "tipo", "valor"})
                if type(raw["tipo"]) is not str or raw["tipo"] not in TYPES:
                    raise A1Error("tipo_invalido")
                return Node(op, raw["tipo"], data=_literal(raw["tipo"], raw["valor"]))
            if op == "CAMPO":
                _keys(raw, {"op", "nombre"})
                name = raw["nombre"]
                if type(name) is not str or name not in schema:
                    raise A1Error("campo_no_autorizado")
                return Node(op, schema[name], data=name)
            if op == "NO":
                _keys(raw, {"op", "arg"})
                child = visit(raw["arg"], depth + 1)
                if child.domain != "LOGICO":
                    raise A1Error("tipo_logico_requerido")
                return Node(op, "LOGICO", (child,))
            if op in ("Y", "O"):
                _keys(raw, {"op", "args"})
                args = raw["args"]
                if type(args) is not list or not 2 <= len(args) <= 64:
                    raise A1Error("aridad_invalida")
                children = tuple(visit(arg, depth + 1) for arg in args)
                if any(child.domain != "LOGICO" for child in children):
                    raise A1Error("tipo_logico_requerido")
                return Node(op, "LOGICO", children)
            if op == "COMPARAR":
                _keys(raw, {"op", "relacion", "izq", "der"})
                relation = raw["relacion"]
                if type(relation) is not str or relation not in RELATIONS:
                    raise A1Error("relacion_no_autorizada")
                left, right = visit(raw["izq"], depth + 1), visit(raw["der"], depth + 1)
                if left.domain != right.domain:
                    raise A1Error("tipos_incompatibles")
                if relation not in ("IGUAL", "DISTINTO") and left.domain != "RACIONAL":
                    raise A1Error("relacion_tipo_incompatible")
                return Node(op, "LOGICO", (left, right), data=relation)
            raise A1Error("operador_no_autorizado")
        finally:
            ancestors.remove(key)

    return visit(expr, 0)


def _environment(schema: dict[str, str], env: dict[str, Any]) -> None:
    if type(env) is not dict or not set(env).issubset(schema):
        raise A1Error("ambiente_no_autorizado")
    for name, value in env.items():
        domain = schema[name]
        if domain == "LOGICO" and type(value) is not Truth:
            raise A1Error("ambiente_tipo_invalido")
        if domain == "RACIONAL" and type(value) is not Fraction:
            raise A1Error("ambiente_tipo_invalido")
        if domain == "TEXTO" and (type(value) is not str or not 0 < len(value) <= 128):
            raise A1Error("ambiente_tipo_invalido")


def _trivalent(op: str, args: tuple[Truth, ...]) -> Truth:
    # Lógica fuerte trivalente: la evidencia cierta domina la incertidumbre.
    if op == "NO":
        return {Truth.VERDADERO: Truth.FALSO, Truth.FALSO: Truth.VERDADERO,
                Truth.ND: Truth.ND}[args[0]]
    if op == "Y":
        if Truth.FALSO in args:
            return Truth.FALSO
        return Truth.ND if Truth.ND in args else Truth.VERDADERO
    if Truth.VERDADERO in args:
        return Truth.VERDADERO
    return Truth.ND if Truth.ND in args else Truth.FALSO


def _run(node: Node, env: dict[str, Any]) -> Any:
    if node.kind == "CONSTANTE":
        return node.data
    if node.kind == "CAMPO":
        return env.get(node.data, Truth.ND if node.domain == "LOGICO" else None)
    if node.kind in ("NO", "Y", "O"):
        return _trivalent(node.kind, tuple(_run(c, env) for c in node.children))
    left, right = (_run(c, env) for c in node.children)
    if left is None or right is None or left is Truth.ND or right is Truth.ND:
        return Truth.ND
    relation = node.data
    verdict = {
        "IGUAL": lambda: left == right,
        "DISTINTO": lambda: left != right,
        "MENOR": lambda: left < right,
        "MENOR_IGUAL": lambda: left <= right,
        "MAYOR": lambda: left > right,
        "MAYOR_IGUAL": lambda: left >= right,
    }[relation]()
    return Truth.VERDADERO if verdict else Truth.FALSO


def evaluate(expr: dict, schema: dict[str, str], env: dict[str, Any]) -> Truth:
    """Evalúa una expresión LOGICA; falta de un campo declarado produce ND."""
    node = compile_expression(expr, schema)
    if node.domain != "LOGICO":
        raise A1Error("resultado_no_logico")
    _environment(schema, env)
    return _run(node, env)


def decide(rows: list[dict], schema: dict[str, str], env: dict[str, Any]) -> Decision:
    """Tabla sin prioridad implícita: varias filas verdaderas son ambiguas.

    Una fila indeterminada impide certificar una elección única. No publica
    decisiones ni ejecuta acciones; `authorized` exige verdad acreditada.
    """
    _schema(schema)
    if type(rows) is not list or not 1 <= len(rows) <= MAX_RULES:
        raise A1Error("tabla_invalida")
    compiled: list[tuple[str, Node]] = []
    seen: set[str] = set()
    for row in rows:
        if type(row) is not dict:
            raise A1Error("fila_invalida")
        _keys(row, {"id", "condicion"})
        rid = row["id"]
        if type(rid) is not str or not ID.fullmatch(rid) or rid in seen:
            raise A1Error("id_fila_invalida_o_duplicada")
        seen.add(rid)
        node = compile_expression(row["condicion"], schema)
        if node.domain != "LOGICO":
            raise A1Error("condicion_no_logica")
        compiled.append((rid, node))
    _environment(schema, env)
    observations = tuple(sorted(((rid, _run(node, env)) for rid, node in compiled), key=lambda p: p[0]))
    winners = [rid for rid, truth in observations if truth is Truth.VERDADERO]
    if len(winners) > 1:
        raise A1Error("reglas_ambiguas")
    if any(truth is Truth.ND for _, truth in observations):
        return Decision(Truth.ND, None, observations)
    if winners:
        return Decision(Truth.VERDADERO, winners[0], observations)
    return Decision(Truth.FALSO, None, observations)


def guard_allows(value: Truth) -> bool:
    if type(value) is not Truth:
        raise A1Error("guarda_no_logica")
    return value is Truth.VERDADERO
