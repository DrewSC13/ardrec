"""A2-R20: referencias tipadas de controles, sin habilitación ni efectos.

Vista sintética de controles sobre tres fuentes inmutables de R17-R19. Un
resultado lógico A1 no otorga permisos operacionales; A3 conserva su propia
semántica de guardas, consumo y planificación, pendiente de implementar.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import heapq
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.initialization.dependency_preview import DependencyPreview
from ardrec.rules.kernel import ID

FORMAT = 'ardrec-p14-r20-a2-control-reference-preview-v1'
MAX_CONTROLS = 32
MAX_BYTES = 262144
MAX_PRECEDENCE = 1023


class ControlPreviewError(ValueError):
    """Referencia, dominio o consistencia sintética incumplidos."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ControlPreviewError(code)


def _fields(value: Any, expected: set[str], code: str) -> None:
    _need(type(value) is dict and set(value) == expected, code)


def _id(value: Any) -> bool:
    return type(value) is str and ID.fullmatch(value) is not None


def _canonical(document: Any) -> bytes:
    try:
        raw = json.dumps(document, sort_keys=True, ensure_ascii=True,
                         allow_nan=False, separators=(',', ':')).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise ControlPreviewError('control_no_serializable') from exc
    _need(len(raw) <= MAX_BYTES, 'control_demasiado_grande')
    return raw


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for key, value in pairs:
        _need(key not in out, 'clave_duplicada')
        out[key] = value
    return out


@dataclass(frozen=True, slots=True)
class ControlReference:
    id: str
    guard_rule_id: str
    target_case_id: str
    precedence: int
    requires: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnitControlReferences:
    service_id: str
    controls: tuple[ControlReference, ...]
    topological_order: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlPreview:
    """Huella de consistencia local; no es autorización ni generación A9."""

    source: bytes
    sha256: str
    rule_source_sha256: str
    initial_snapshot_sha256: str
    dependency_snapshot_sha256: str
    units: tuple[UnitControlReferences, ...]

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview,
               dependencies: DependencyPreview) -> bool:
        _validate_sources(rules, initial, dependencies)
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'control_alterado')
        try:
            document = json.loads(self.source, object_pairs_hook=_unique_pairs)
        except ControlPreviewError:
            raise
        except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
            raise ControlPreviewError('control_no_valido') from exc
        _need(_canonical(document) == self.source, 'control_no_canonico')
        _need(self.rule_source_sha256 == rules.sha256
              and self.initial_snapshot_sha256 == initial.sha256
              and self.dependency_snapshot_sha256 == dependencies.sha256,
              'origen_no_coincide')
        _need(_parse(document, rules, initial, dependencies) == self.units,
              'control_en_memoria_alterado')
        return True

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def _validate_sources(rules: FrozenRulePreview, initial: InitialPreview,
                      dependencies: DependencyPreview) -> None:
    _need(type(rules) is FrozenRulePreview and type(initial) is InitialPreview
          and type(dependencies) is DependencyPreview, 'fuentes_invalidas')
    dependencies.verify(rules, initial)


def _topological(controls: dict[str, ControlReference]) -> tuple[str, ...]:
    # La precedencia ordena candidatos disponibles; jamás sustituye una dependencia.
    indegree = {cid: len(c.requires) for cid, c in controls.items()}
    after: dict[str, list[str]] = {cid: [] for cid in controls}
    for cid, c in controls.items():
        for req in c.requires:
            _need(req in controls, 'control_requerido_no_declarado')
            _need(req != cid, 'autodependencia_control')
            after[req].append(cid)
    todo = [(c.precedence, c.id) for c in controls.values() if indegree[c.id] == 0]
    heapq.heapify(todo)
    ordered = []
    while todo:
        _, cid = heapq.heappop(todo)
        ordered.append(cid)
        for succ in after[cid]:
            indegree[succ] -= 1
            if indegree[succ] == 0:
                heapq.heappush(todo, (controls[succ].precedence, succ))
    _need(len(ordered) == len(controls), 'dependencias_control_ciclicas')
    return tuple(ordered)


def _parse(document: Any, rules: FrozenRulePreview, initial: InitialPreview,
           dependencies: DependencyPreview) -> tuple[UnitControlReferences, ...]:
    _fields(document, {'format', 'rule_source_sha256', 'initial_snapshot_sha256',
                       'dependency_snapshot_sha256', 'services'}, 'control_raiz_invalida')
    _need(document['format'] == FORMAT, 'version_incompatible')
    _need(document['rule_source_sha256'] == rules.sha256
          and document['initial_snapshot_sha256'] == initial.sha256
          and document['dependency_snapshot_sha256'] == dependencies.sha256,
          'origen_no_coincide')
    try:
        rule_data = json.loads(rules.source)
        rule_ids = {s['id']: {r['id'] for r in s['rules']}
                    for s in rule_data['services']}
    except (ValueError, KeyError, TypeError) as exc:
        raise ControlPreviewError('reglas_invalidas') from exc
    case_ids = {u.id: {c.id for c in u.cases} for u in initial.units}
    dep_ids = {u.unit_id: {cid for cid, _ in u.edges} for u in dependencies.units}
    services = document['services']
    _need(type(services) is list and len(services) == len(initial.units),
          'servicios_no_coinciden')
    seen_services = set()
    result = []
    for service in services:
        _fields(service, {'id', 'controls'}, 'servicio_control_invalido')
        sid = service['id']
        _need(_id(sid) and sid in case_ids and sid not in seen_services,
              'servicio_control_desconocido_o_duplicado')
        seen_services.add(sid)
        _need(case_ids[sid] == dep_ids[sid], 'casos_de_fuentes_no_coinciden')
        controls = service['controls']
        _need(type(controls) is list and len(controls) <= MAX_CONTROLS,
              'controles_invalidos')
        parsed: dict[str, ControlReference] = {}
        for control in controls:
            _fields(control, {'id', 'guard_rule_id', 'target_case_id',
                              'precedence', 'requires'}, 'control_invalido')
            cid = control['id']
            _need(_id(cid) and cid not in parsed, 'control_duplicado_o_invalido')
            rid = control['guard_rule_id']
            _need(_id(rid) and rid in rule_ids[sid], 'regla_control_no_declarada')
            target = control['target_case_id']
            _need(_id(target) and target in case_ids[sid], 'caso_control_no_declarado')
            priority = control['precedence']
            _need(type(priority) is int and 0 <= priority <= MAX_PRECEDENCE,
                  'precedencia_invalida')
            requires = control['requires']
            _need(type(requires) is list and len(requires) <= MAX_CONTROLS,
                  'referencias_control_invalidas')
            _need(all(_id(dep) for dep in requires), 'id_control_requerido_invalido')
            _need(len(set(requires)) == len(requires), 'control_requerido_duplicado')
            parsed[cid] = ControlReference(cid, rid, target, priority,
                                           tuple(sorted(requires)))
        order = _topological(parsed)
        result.append(UnitControlReferences(sid, tuple(sorted(parsed.values(), key=lambda c:c.id)), order))
    _need(seen_services == set(case_ids), 'servicios_no_coinciden')
    return tuple(sorted(result, key=lambda u: u.service_id))


def prepare_control_preview(rules: FrozenRulePreview, initial: InitialPreview,
                            dependencies: DependencyPreview,
                            candidate: dict[str, Any]) -> ControlPreview:
    """Solo prevalidación A2 de referencias; no simula ni aplica controles A3."""
    _validate_sources(rules, initial, dependencies)
    parsed = _parse(candidate, rules, initial, dependencies)
    normalized = {
        'format': FORMAT,
        'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'dependency_snapshot_sha256': dependencies.sha256,
        'services': [
            {'id': u.service_id,
             'controls': [
                 {'id': c.id, 'guard_rule_id': c.guard_rule_id,
                  'target_case_id': c.target_case_id, 'precedence': c.precedence,
                  'requires': list(c.requires)} for c in u.controls
             ]} for u in parsed
        ],
    }
    raw = _canonical(normalized)
    preview = ControlPreview(raw, hashlib.sha256(raw).hexdigest(), rules.sha256,
                             initial.sha256, dependencies.sha256, parsed)
    preview.verify(rules, initial, dependencies)
    return preview
