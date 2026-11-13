"""A2-R19: vínculos locales de casos y orden de dependencias, sin despacho.

Validación sintética para una instantánea R17/R18 ya obtenida. La procedencia,
autorización, condiciones PTES y ejecución física son responsabilidades ajenas.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import heapq
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.rules.kernel import ID

FORMAT = 'ardrec-p14-r19-a2-local-dependency-preview-v1'
PROTOCOLS = frozenset({'SSH', 'FTP', 'SMB'})
MAX_BYTES = 131072
MAX_UNITS = 64
MAX_EDGES_PER_SERVICE = 1024


class DependencyPreviewError(ValueError):
    """Configuración sin cierre estructural suficiente."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(valid: bool, code: str) -> None:
    if not valid:
        raise DependencyPreviewError(code)


def _fields(value: Any, names: set[str], code: str) -> None:
    _need(type(value) is dict and set(value) == names, code)


def _id(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError, OverflowError, UnicodeError) as exc:
        raise DependencyPreviewError('serializacion_invalida') from exc
    _need(len(raw) <= MAX_BYTES, 'grafo_excesivo')
    return raw


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        _need(key not in out, 'clave_duplicada')
        out[key] = value
    return out


@dataclass(frozen=True, slots=True)
class UnitDependencies:
    unit_id: str
    protocol: str
    edges: tuple[tuple[str, tuple[str, ...]], ...]
    topological_order: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DependencyPreview:
    source: bytes
    sha256: str
    rule_source_sha256: str
    initial_snapshot_sha256: str
    units: tuple[UnitDependencies, ...]

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview) -> bool:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'grafo_alterado')
        _need(type(rules) is FrozenRulePreview and type(initial) is InitialPreview,
              'fuente_invalida')
        initial.verify(rules)
        _need(self.rule_source_sha256 == rules.sha256
              and self.initial_snapshot_sha256 == initial.sha256,
              'origen_no_coincide')
        try:
            document = json.loads(self.source, object_pairs_hook=_no_duplicates)
        except DependencyPreviewError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise DependencyPreviewError('grafo_no_valido') from exc
        _need(_canonical(document) == self.source, 'grafo_no_canonico')
        reconstructed = _parse(rules, initial, document)
        _need(reconstructed == self.units, 'grafo_en_memoria_alterado')
        return True

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def _order(edges: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Orden estable Kahn. Un ciclo o referencia local inválida falla cerrado."""
    indegree = {case: len(req) for case, req in edges.items()}
    dependants: dict[str, list[str]] = {case: [] for case in edges}
    for case, requirements in edges.items():
        for req in requirements:
            _need(req in edges, 'dependencia_no_declarada')
            _need(req != case, 'autodependencia')
            dependants[req].append(case)
    available = [case for case in edges if indegree[case] == 0]
    heapq.heapify(available)
    result = []
    while available:
        current = heapq.heappop(available)
        result.append(current)
        for dependant in dependants[current]:
            indegree[dependant] -= 1
            if indegree[dependant] == 0:
                heapq.heappush(available, dependant)
    _need(len(result) == len(edges), 'dependencias_ciclicas')
    return tuple(result)


def _parse(rules: FrozenRulePreview, initial: InitialPreview,
           document: Any) -> tuple[UnitDependencies, ...]:
    _fields(document, {'format', 'rule_source_sha256',
                       'initial_snapshot_sha256', 'services'}, 'grafo_invalido')
    _need(document['format'] == FORMAT, 'version_incompatible')
    _need(document['rule_source_sha256'] == rules.sha256
          and document['initial_snapshot_sha256'] == initial.sha256,
          'origen_no_coincide')
    services = document['services']
    _need(type(services) is list and len(services) == len(initial.units)
          and 1 <= len(services) <= MAX_UNITS, 'cantidad_servicios_invalida')
    actual = {u.id: u for u in initial.units}
    seen: set[str] = set()
    result: list[UnitDependencies] = []
    for service in services:
        _fields(service, {'id', 'protocol', 'cases'}, 'servicio_invalido')
        sid = service['id']
        _need(_id(sid) and sid in actual and sid not in seen,
              'servicio_desconocido_o_duplicado')
        seen.add(sid)
        proto = service['protocol']
        _need(type(proto) is str and proto in PROTOCOLS, 'protocolo_invalido')
        cases = service['cases']
        _need(type(cases) is list and len(cases) == len(actual[sid].cases),
              'cantidad_casos_invalida')
        expected = {c.id for c in actual[sid].cases}
        graph: dict[str, tuple[str, ...]] = {}
        edge_count = 0
        for case in cases:
            _fields(case, {'id', 'requires'}, 'caso_invalido')
            cid = case['id']
            _need(_id(cid) and cid in expected and cid not in graph,
                  'caso_desconocido_o_duplicado')
            requires = case['requires']
            _need(type(requires) is list and len(requires) <= len(expected),
                  'dependencias_invalidas')
            _need(all(_id(req) for req in requires), 'identidad_dependencia_invalida')
            _need(len(set(requires)) == len(requires), 'dependencia_duplicada')
            edge_count += len(requires)
            _need(edge_count <= MAX_EDGES_PER_SERVICE, 'demasiadas_dependencias')
            graph[cid] = tuple(sorted(requires))
        _need(set(graph) == expected, 'casos_no_coinciden')
        order = _order(graph)
        result.append(UnitDependencies(sid, proto, tuple(sorted(graph.items())), order))
    _need(seen == set(actual), 'servicios_no_coinciden')
    return tuple(sorted(result, key=lambda unit: unit.unit_id))


def prepare_dependency_preview(rules: FrozenRulePreview, initial: InitialPreview,
                               candidate: dict[str, Any]) -> DependencyPreview:
    """Congela los vínculos caso-locales sobre R17/R18; no cambia sus fuentes."""
    _need(type(rules) is FrozenRulePreview and type(initial) is InitialPreview,
          'fuente_invalida')
    initial.verify(rules)
    parsed = _parse(rules, initial, candidate)
    normalized = {
        'format': FORMAT,
        'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'services': [
            {'id': u.unit_id, 'protocol': u.protocol,
             'cases': [{'id': cid, 'requires': list(req)} for cid, req in u.edges]}
            for u in parsed
        ],
    }
    raw = _canonical(normalized)
    result = DependencyPreview(raw, hashlib.sha256(raw).hexdigest(),
                               rules.sha256, initial.sha256, parsed)
    result.verify(rules, initial)
    return result
