"""R22 / A3: diagnóstico puro trivalente de guardas y bloqueos estructurales.

Solo analiza fuentes sintéticas R17-R21: no genera una agenda ejecutable,
no confirma dependencias, no consume controles, ni concede autoridad P8.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import json
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.initialization.dependency_preview import DependencyPreview
from ardrec.initialization.control_preview import ControlPreview
from ardrec.initialization.integrated_preview import IntegratedPreview
from ardrec.rules.kernel import A1Error, decide
from ardrec.state import ServicePhase, Truth

FORMAT = 'ardrec-p14-r22-a3-guard-diagnostic-v1'
MAX_BYTES = 393216
MAX_UNITS = 64


class GuardPreviewError(ValueError):
    """Diagnóstico no reproducible, entrada inválida o guarda ambigua."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise GuardPreviewError(code)


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                         separators=(',', ':')).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise GuardPreviewError('serializacion_invalida') from exc
    _need(len(raw) <= MAX_BYTES, 'diagnostico_excesivo')
    return raw


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _need(key not in result, 'clave_duplicada')
        result[key] = value
    return result


def _freeze_field(value: Any) -> dict[str, str]:
    # Preserva el dominio sin confundir racionales y cadenas, ni usar float.
    if type(value) is Truth:
        return {'type': 'LOGICO', 'value': value.name}
    if type(value) is Fraction:
        return {'type': 'RACIONAL', 'value': str(value)}
    if type(value) is str:
        return {'type': 'TEXTO', 'value': value}
    raise GuardPreviewError('ambiente_tipo_invalido')


@dataclass(frozen=True, slots=True)
class CaseDiagnostic:
    case_id: str
    requires: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class ControlDiagnostic:
    control_id: str
    guard_rule_id: str
    target_case_id: str
    truth: Truth
    blockers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnitGuardDiagnostic:
    service_id: str
    protocol: str
    table_status: Truth
    table_selected: str | None
    evaluations: tuple[tuple[str, Truth], ...]
    cases: tuple[CaseDiagnostic, ...]
    controls: tuple[ControlDiagnostic, ...]


@dataclass(frozen=True, slots=True)
class GuardDiagnosticPreview:
    """Diagnóstico sin permisos; una huella no certifica procedencia ni autoridad."""

    source: bytes
    sha256: str
    integrated_snapshot_sha256: str
    units: tuple[UnitGuardDiagnostic, ...]

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview,
               dependencies: DependencyPreview, controls: ControlPreview,
               integrated: IntegratedPreview,
               environments: dict[str, dict[str, Any]]) -> bool:
        _need(type(self.source) is bytes and type(self.sha256) is str
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'diagnostico_alterado')
        expected, reconstructed = _compose(rules, initial, dependencies, controls,
                                            integrated, environments)
        _need(self.integrated_snapshot_sha256 == integrated.sha256,
              'origen_no_coincide')
        try:
            parsed = json.loads(self.source, object_pairs_hook=_strict_pairs)
        except GuardPreviewError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            raise GuardPreviewError('diagnostico_invalido') from exc
        _need(type(parsed) is dict and parsed.get('format') == FORMAT,
              'version_incompatible')
        _need(_canonical(parsed) == self.source, 'diagnostico_no_canonico')
        _need(expected == self.source and reconstructed == self.units,
              'diagnostico_no_coincide')
        return True

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def published_generation(self) -> None:
        return None

    @property
    def executable_agenda(self) -> None:
        return None


def _compose(rules: FrozenRulePreview, initial: InitialPreview,
             dependencies: DependencyPreview, controls: ControlPreview,
             integrated: IntegratedPreview,
             environments: dict[str, dict[str, Any]]) -> tuple[bytes, tuple[UnitGuardDiagnostic, ...]]:
    _need(type(rules) is FrozenRulePreview and type(initial) is InitialPreview
          and type(dependencies) is DependencyPreview and type(controls) is ControlPreview
          and type(integrated) is IntegratedPreview, 'fuentes_invalidas')
    integrated.verify(rules, initial, dependencies, controls)
    _need(1 <= len(integrated.units) <= MAX_UNITS, 'servicios_invalidos')
    _need(type(environments) is dict and
          set(environments) == {u.service_id for u in integrated.units},
          'ambientes_no_coinciden')
    try:
        rule_data = json.loads(rules.source, object_pairs_hook=_strict_pairs)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise GuardPreviewError('reglas_invalidas') from exc
    rule_services = {u['id']: u['rules'] for u in rule_data['services']}
    fields = rule_data['fields']
    initial_services = {u.id: u for u in initial.units}
    outputs: list[UnitGuardDiagnostic] = []
    env_records: list[dict[str, Any]] = []
    for unit in integrated.units:
        sid = unit.service_id
        _need(initial_services[sid].phase is ServicePhase.PREPARADO,
              'estado_no_preparado')
        env = environments[sid]
        _need(type(env) is dict and len(env) <= 128
              and all(type(k) is str for k in env), 'ambiente_invalido')
        _need(set(env).issubset(fields), 'ambiente_no_autorizado')
        try:
            verdict = decide(rule_services[sid], fields, env)
        except A1Error as exc:
            # Rechazar ambigüedad antes de atribuir verdad a un control.
            raise GuardPreviewError('a1_' + exc.code) from exc
        observed = dict(verdict.evaluations)
        case_items: list[CaseDiagnostic] = []
        for cid, _, requires, _ in unit.cases:
            reason = ('SIN_DEPENDENCIAS_DECLARADAS' if not requires
                      else 'DEPENDENCIAS_NO_CONFIRMADAS')
            case_items.append(CaseDiagnostic(cid, requires, reason))
        controls_out: list[ControlDiagnostic] = []
        for cid, rid, target, _, requires in unit.controls:
            value = observed[rid]
            required_cases = next(x[2] for x in unit.cases if x[0] == target)
            blockers = []
            if value is Truth.ND:
                blockers.append('GUARDA_ND')
            elif value is Truth.FALSO:
                blockers.append('GUARDA_FALSA')
            if verdict.status is not Truth.VERDADERO or verdict.selected != rid:
                blockers.append('TABLA_NO_ACREDITADA')
            if requires:
                blockers.append('CONTROLES_NO_APLICADOS')
            if required_cases:
                blockers.append('CASOS_NO_CONFIRMADOS')
            # Incluso sin bloqueos estructurales, no se concede permiso.
            blockers.append('AUTORIDAD_OPERACIONAL_NO_ACREDITADA')
            controls_out.append(ControlDiagnostic(cid, rid, target, value,
                                                   tuple(blockers)))
        outputs.append(UnitGuardDiagnostic(sid, unit.protocol, verdict.status,
                                           verdict.selected, verdict.evaluations,
                                           tuple(case_items), tuple(controls_out)))
        env_records.append({'id': sid, 'fields': {k: _freeze_field(env[k]) for k in sorted(env)}})
    record = {
        'format': FORMAT,
        'scope': 'SYNTHETIC_DIAGNOSTIC_ONLY',
        'integrated_sha256': integrated.sha256,
        'environments': env_records,
        'services': [
            {'id': u.service_id, 'protocol': u.protocol,
             'table_status': u.table_status.name,
             'table_selected': u.table_selected,
             'evaluations': [{'id': rid, 'truth': value.name} for rid, value in u.evaluations],
             'cases': [{'id': c.case_id, 'requires': list(c.requires),
                        'diagnostic': c.reason} for c in u.cases],
             'controls': [{'id': c.control_id, 'guard_rule_id': c.guard_rule_id,
                           'target_case_id': c.target_case_id, 'truth': c.truth.name,
                           'blockers': list(c.blockers)} for c in u.controls]}
            for u in outputs
        ],
        'executable_agenda': None,
        'published_generation': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    return _canonical(record), tuple(outputs)


def diagnose_guards(rules: FrozenRulePreview, initial: InitialPreview,
                    dependencies: DependencyPreview, controls: ControlPreview,
                    integrated: IntegratedPreview,
                    environments: dict[str, dict[str, Any]]) -> GuardDiagnosticPreview:
    """Diagnóstico A3 de solo lectura, sin agenda ejecutable ni progreso de estado."""
    source, units = _compose(rules, initial, dependencies, controls,
                              integrated, environments)
    preview = GuardDiagnosticPreview(source, hashlib.sha256(source).hexdigest(),
                                     integrated.sha256, units)
    preview.verify(rules, initial, dependencies, controls, integrated, environments)
    return preview
