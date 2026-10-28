"""Proyección analítica estructural; no confirma generaciones ni resuelve referencias."""
from dataclasses import dataclass
from fractions import Fraction
from itertools import combinations
import json
import re

from ardrec.contracts import ContractError, ND, dump_magnitude, parse_magnitude
from ardrec.state import ServicePhase

FORMAT = 'ardrec-analytical-projection-1'
MAX_BYTES = 32768
MAX_GENERATION = 2**63 - 1
REFERENCE_ROLES = ('evidence_repository', 'execution_counters', 'objective_status',
                   'history', 'convergence_window', 'pending_controls')
ANALYSIS_FIELDS = ('accumulated_evidence', 'substituted_baseline', 'upper_bound',
                   'lower_adjustment_bound', 'recalibrated_risk', 'priority')


class AnalyticalError(ValueError):
    """Violación del contrato de proyección, sin efectos de almacenamiento."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(condition, code):
    if not condition:
        raise AnalyticalError(code)


def _id(value):
    _need(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', value) is not None,
          'identifier_invalid')


def _hash(value):
    _need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'hash_invalid')


def _fields(value, names):
    _need(type(value) is dict and set(value) == set(names), 'fields_invalid')


def _magnitude(value):
    try:
        dump_magnitude(value)
    except (ContractError, TypeError, ValueError) as error:
        raise AnalyticalError('magnitude_invalid') from error
    _need(type(value) is ND or Fraction(0) <= value <= Fraction(1), 'magnitude_domain')


@dataclass(frozen=True, slots=True)
class ObjectReference:
    """Declaración de identidad; no acredita existencia, pertenencia ni integridad."""
    reference: str
    sha256: str

    def __post_init__(self):
        _id(self.reference)
        _hash(self.sha256)


@dataclass(frozen=True, slots=True)
class FrozenValues:
    initial_risk: Fraction | ND
    normalized_criticality: Fraction | ND
    characterization: ObjectReference

    def __post_init__(self):
        _magnitude(self.initial_risk)
        _magnitude(self.normalized_criticality)
        _need(type(self.characterization) is ObjectReference, 'reference_invalid')


@dataclass(frozen=True, slots=True)
class AnalysisValues:
    accumulated_evidence: Fraction | ND
    substituted_baseline: Fraction | ND
    upper_bound: Fraction | ND
    lower_adjustment_bound: Fraction | ND
    recalibrated_risk: Fraction | ND
    # Vacía (None), no determinada (ND) y cero son condiciones distintas.
    priority: Fraction | ND | None

    def __post_init__(self):
        for name in ANALYSIS_FIELDS[:-1]:
            _magnitude(getattr(self, name))
        if self.priority is not None:
            _magnitude(self.priority)


@dataclass(frozen=True, slots=True)
class AnalyticalProjection:
    """Copia inmutable por unidad; su validez local no es autoridad global."""
    record_id: str
    execution_id: str
    configuration_sha256: str
    service_scenario_id: str
    generation_index: int
    operational_state: ServicePhase
    frozen: FrozenValues
    analysis: AnalysisValues
    references: tuple[ObjectReference, ...]

    def __post_init__(self):
        for value in (self.record_id, self.execution_id, self.service_scenario_id):
            _id(value)
        _hash(self.configuration_sha256)
        _need(type(self.generation_index) is int and 0 <= self.generation_index <= MAX_GENERATION,
              'generation_invalid')
        _need(type(self.operational_state) is ServicePhase, 'operational_state_invalid')
        _need(type(self.frozen) is FrozenValues and type(self.analysis) is AnalysisValues, 'values_invalid')
        _need(type(self.references) is tuple and len(self.references) == len(REFERENCE_ROLES)
              and all(type(r) is ObjectReference for r in self.references), 'references_invalid')
        if self.operational_state is ServicePhase.PREPARADO:
            _need(self.analysis.priority is None, 'prepared_priority_not_empty')
        a, f = self.analysis, self.frozen
        chains = ((a.substituted_baseline, a.lower_adjustment_bound, f.initial_risk, a.upper_bound),
                  (a.substituted_baseline, a.lower_adjustment_bound, a.recalibrated_risk, a.upper_bound))
        for chain in chains:
            for left, right in combinations(chain, 2):
                if type(left) is Fraction and type(right) is Fraction:
                    _need(left <= right, 'bounds_inconsistent')
        if all(type(v) is Fraction for v in (a.upper_bound, a.lower_adjustment_bound,
                                             f.initial_risk, a.recalibrated_risk)):
            _need(a.recalibrated_risk == a.upper_bound + a.lower_adjustment_bound - f.initial_risk,
                  'risk_identity_inconsistent')


def check_frozen_compatibility(previous, candidate):
    """Solo comprobar contexto y datos congelados; no valida una transición A9."""
    _need(type(previous) is AnalyticalProjection and type(candidate) is AnalyticalProjection,
          'projection_invalid')
    for name in ('record_id', 'execution_id', 'configuration_sha256', 'service_scenario_id'):
        _need(getattr(previous, name) == getattr(candidate, name), 'context_changed')
    _need(previous.frozen == candidate.frozen, 'frozen_values_changed')


def _reference(ref):
    return {'reference': ref.reference, 'sha256': ref.sha256}


def encode_projection(value):
    """Serializar canónicamente sin publicar ni interpretar objetos referenciados."""
    _need(type(value) is AnalyticalProjection, 'projection_invalid')
    result = {
        'format': FORMAT, 'record_id': value.record_id, 'execution_id': value.execution_id,
        'configuration_sha256': value.configuration_sha256,
        'service_scenario_id': value.service_scenario_id, 'generation_index': value.generation_index,
        'operational_state': value.operational_state.value,
        'frozen': {'initial_risk': dump_magnitude(value.frozen.initial_risk),
                   'normalized_criticality': dump_magnitude(value.frozen.normalized_criticality),
                   'characterization': _reference(value.frozen.characterization)},
        'analysis': {name: dump_magnitude(getattr(value.analysis, name)) for name in ANALYSIS_FIELDS[:-1]},
        'references': {name: _reference(ref) for name, ref in zip(REFERENCE_ROLES, value.references)},
    }
    result['analysis']['priority'] = ({'status': 'EMPTY'} if value.analysis.priority is None
                                      else dump_magnitude(value.analysis.priority))
    raw = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    _need(len(raw) <= MAX_BYTES, 'projection_too_large')
    return raw


def decode_projection(raw):
    """Rechazar números aproximados, duplicados, versiones y campos desconocidos."""
    _need(type(raw) is bytes and len(raw) <= MAX_BYTES, 'projection_bytes_invalid')

    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, 'duplicate_key')
            result[key] = value
        return result

    def reject(_):
        raise AnalyticalError('noninteger_number')

    def ref(value):
        _fields(value, ('reference', 'sha256'))
        return ObjectReference(value['reference'], value['sha256'])

    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_float=reject, parse_constant=reject)
        _fields(value, ('format','record_id','execution_id','configuration_sha256','service_scenario_id',
                        'generation_index','operational_state','frozen','analysis','references'))
        _need(value['format'] == FORMAT, 'version_incompatible')
        f, a, refs = value['frozen'], value['analysis'], value['references']
        _fields(f, ('initial_risk','normalized_criticality','characterization'))
        _fields(a, ANALYSIS_FIELDS)
        _fields(refs, REFERENCE_ROLES)
        priority = None if a['priority'] == {'status':'EMPTY'} else parse_magnitude(a['priority'])
        return AnalyticalProjection(
            value['record_id'], value['execution_id'], value['configuration_sha256'],
            value['service_scenario_id'], value['generation_index'], ServicePhase(value['operational_state']),
            FrozenValues(parse_magnitude(f['initial_risk']), parse_magnitude(f['normalized_criticality']),
                         ref(f['characterization'])),
            AnalysisValues(*(parse_magnitude(a[n]) for n in ANALYSIS_FIELDS[:-1]), priority),
            tuple(ref(refs[n]) for n in REFERENCE_ROLES))
    except AnalyticalError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
        raise AnalyticalError('projection_invalid') from error
