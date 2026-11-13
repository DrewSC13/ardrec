"""R21: composición inmutable de cuatro prevalidaciones A1/A2, sin autoridad.

Una instantánea de síntesis contiene exclusivamente valores declarativos de
R17--R20. No representa una generación A9 confirmada, ni habilita A3/P8.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.initialization.dependency_preview import DependencyPreview
from ardrec.initialization.control_preview import ControlPreview
from ardrec.state import ServicePhase

FORMAT = 'ardrec-p14-r21-a2-integrated-contract-preview-v1'
MAX_BYTES = 262144


class IntegratedPreviewError(ValueError):
    """Unión inconsistente, fuente adulterada o identidad no canónica."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise IntegratedPreviewError(code)


def _canonical(doc: Any) -> bytes:
    try:
        raw = json.dumps(doc, ensure_ascii=True, sort_keys=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii')
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError) as exc:
        raise IntegratedPreviewError('serializacion_invalida') from exc
    _need(len(raw) <= MAX_BYTES, 'documento_excesivo')
    return raw


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    d = {}
    for key, value in pairs:
        _need(key not in d, 'clave_duplicada')
        d[key] = value
    return d


@dataclass(frozen=True, slots=True)
class UnitContract:
    service_id: str
    protocol: str
    initial_risk: str
    normalized_criticality: str
    case_order: tuple[str, ...]
    control_order: tuple[str, ...]
    cases: tuple[tuple[str, int, tuple[str, ...], tuple[str, ...]], ...]
    controls: tuple[tuple[str, str, str, int, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class IntegratedPreview:
    """Resultado de solo lectura: SHA identifica contenido, no permisos."""

    source: bytes
    sha256: str
    rule_source_sha256: str
    initial_snapshot_sha256: str
    dependency_snapshot_sha256: str
    control_snapshot_sha256: str
    units: tuple[UnitContract, ...]

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview,
               dependencies: DependencyPreview, controls: ControlPreview) -> bool:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'instantanea_alterada')
        expected, computed = _compose(rules, initial, dependencies, controls)
        _need((self.rule_source_sha256, self.initial_snapshot_sha256,
               self.dependency_snapshot_sha256, self.control_snapshot_sha256)
              == (rules.sha256, initial.sha256, dependencies.sha256, controls.sha256),
              'origen_no_coincide')
        try:
            document = json.loads(self.source, object_pairs_hook=_no_duplicates)
        except IntegratedPreviewError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise IntegratedPreviewError('instantanea_invalida') from exc
        _need(type(document) is dict and document.get('format') == FORMAT,
              'version_incompatible')
        _need(_canonical(document) == self.source, 'instantanea_no_canonica')
        _need(self.source == expected and self.units == computed,
              'contrato_no_coincide')
        return True

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None


def _compose(rules: FrozenRulePreview, initial: InitialPreview,
             dependencies: DependencyPreview,
             controls: ControlPreview) -> tuple[bytes, tuple[UnitContract, ...]]:
    _need(type(rules) is FrozenRulePreview and type(initial) is InitialPreview
          and type(dependencies) is DependencyPreview and type(controls) is ControlPreview,
          'fuentes_invalidas')
    # Cada nivel verifica recursivamente su identidad/huellas, sin fiarse solo de IDs.
    controls.verify(rules, initial, dependencies)
    initial_map = {u.id: u for u in initial.units}
    dependencies_map = {u.unit_id: u for u in dependencies.units}
    controls_map = {u.service_id: u for u in controls.units}
    expected = set(rules.service_ids)
    _need(expected == set(initial_map) == set(dependencies_map) == set(controls_map),
          'servicios_inconsistentes')
    _need(len(expected) == len(initial.units) == len(dependencies.units) == len(controls.units),
          'servicios_duplicados')
    output: list[UnitContract] = []
    for sid in sorted(expected):
        unit = initial_map[sid]
        dep = dependencies_map[sid]
        ctrl = controls_map[sid]
        _need(unit.phase is ServicePhase.PREPARADO
              and unit.accumulated_evidence == 0
              and unit.recalibrated_risk == unit.initial_risk
              and unit.priority is None
              and not unit.local_history,
              'inicializacion_no_preparada')
        cases = {c.id: c for c in unit.cases}
        graph = dict(dep.edges)
        control_map = {c.id: c for c in ctrl.controls}
        _need(set(cases) == set(graph) == set(dep.topological_order),
              'casos_inconsistentes')
        _need(set(control_map) == set(ctrl.topological_order),
              'controles_inconsistentes')
        cases_out = []
        for cid in sorted(cases):
            c = cases[cid]
            _need(c.starts_confirmed == 0 and not c.execution_results,
                  'inicio_no_vacio')
            references = tuple(sorted(ctrl_id for ctrl_id, ref in control_map.items()
                                      if ref.target_case_id == cid))
            cases_out.append((cid, c.permitted_attempts_ceiling,
                              tuple(graph[cid]), references))
        control_out = tuple((c.id, c.guard_rule_id, c.target_case_id,
                             c.precedence, c.requires) for c in ctrl.controls)
        output.append(UnitContract(
            sid, dep.protocol, str(unit.initial_risk), str(unit.normalized_criticality),
            dep.topological_order, ctrl.topological_order,
            tuple(cases_out), control_out))
    record = {
        'format': FORMAT,
        'sources': {'rules_sha256': rules.sha256, 'initial_sha256': initial.sha256,
                    'dependencies_sha256': dependencies.sha256,
                    'controls_sha256': controls.sha256},
        'services': [
            {'id': u.service_id, 'protocol': u.protocol,
             'initial_risk': u.initial_risk,
             'normalized_criticality': u.normalized_criticality,
             'initial_phase': 'PREPARADO', 'accumulated_evidence': '0',
             'recalibrated_risk': u.initial_risk,
             'case_order': list(u.case_order), 'control_order': list(u.control_order),
             'cases': [{'id': cid, 'attempt_ceiling': ceiling,
                        'requires': list(req), 'referenced_by_controls': list(ref)}
                       for cid, ceiling, req, ref in u.cases],
             'controls': [{'id': cid, 'guard_rule_id': guard,
                           'target_case_id': target, 'precedence': prec,
                           'requires': list(req)}
                          for cid, guard, target, prec, req in u.controls]}
            for u in output]
    }
    return _canonical(record), tuple(output)


def assemble_integrated_preview(rules: FrozenRulePreview, initial: InitialPreview,
                                dependencies: DependencyPreview,
                                controls: ControlPreview) -> IntegratedPreview:
    """Compone una previsualización A2, sin I/O ni publicación de generación."""
    source, units = _compose(rules, initial, dependencies, controls)
    preview = IntegratedPreview(source, hashlib.sha256(source).hexdigest(),
                                rules.sha256, initial.sha256, dependencies.sha256,
                                controls.sha256, units)
    preview.verify(rules, initial, dependencies, controls)
    return preview
