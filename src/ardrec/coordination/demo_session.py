"""P14-R26: sesión única A1/A2/A3, puramente sintética y de solo lectura.

Consume los componentes reales de R17-R22; no modifica estado confirmado,
no llama a un ejecutor, no usa red y no publica una generación A9.
La salida constituye un contrato preparatorio para A4 y para la futura TUI.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from ardrec.initialization.rule_preflight import (
    FORMAT as RULE_FORMAT, preflight_rule_configuration,
)
from ardrec.initialization.initial_preview import (
    FORMAT as INITIAL_FORMAT, prepare_initial_preview,
)
from ardrec.initialization.dependency_preview import (
    FORMAT as DEPENDENCY_FORMAT, prepare_dependency_preview,
)
from ardrec.initialization.control_preview import (
    FORMAT as CONTROL_FORMAT, prepare_control_preview,
)
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import diagnose_guards
from ardrec.state import Truth

FORMAT = 'ardrec-p14-r26-a1-a3-development-session-v1'
SCENARIO_FORMAT = 'ardrec-p14-r26-fixed-three-service-scenario-v1'
SOURCE_KIND = 'SYNTHETIC_FIXTURE'
MAX_BYTES = 65536
REQUIRED = {'SSH_DEV': 'SSH', 'FTP_DEV': 'FTP', 'SMB_DEV': 'SMB'}


class SessionError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise SessionError(code)


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        _need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError) as exc:
        raise SessionError('noncanonical_data') from exc
    _need(len(raw) <= MAX_BYTES, 'payload_oversized')
    return raw


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def normalize_scenario(candidate: dict[str, Any]) -> dict[str, Any]:
    """Admite exclusivamente las tres unidades ficticias fijadas; falla cerrado."""
    _need(type(candidate) is dict and set(candidate) ==
          {'format', 'session_id', 'services'}, 'scenario_schema')
    _need(candidate['format'] == SCENARIO_FORMAT, 'scenario_format')
    _need(candidate['session_id'] == 'DEV_TUTOR_001', 'scenario_identity')
    services = candidate['services']
    _need(type(services) is list and len(services) == 3, 'scenario_units')
    result = []
    seen = set()
    for u in services:
        _need(type(u) is dict and set(u) ==
              {'id', 'protocol', 'fact', 'initial_risk', 'normalized_criticality'},
              'scenario_unit_schema')
        sid = u['id']
        _need(type(sid) is str and sid in REQUIRED and sid not in seen,
              'scenario_unit_identity')
        seen.add(sid)
        _need(u['protocol'] == REQUIRED[sid], 'scenario_protocol_mismatch')
        _need(type(u['fact']) is str and u['fact'] in
              {'VERDADERO', 'FALSO', 'AUSENTE'}, 'scenario_fact')
        _need(u['initial_risk'] == '1/4'
              and u['normalized_criticality'] == '1/2', 'scenario_fixed_magnitudes')
        result.append(dict(u))
    _need(seen == set(REQUIRED), 'scenario_missing_unit')
    return {'format': SCENARIO_FORMAT, 'session_id': 'DEV_TUTOR_001',
            'services': sorted(result, key=lambda u: u['id'])}


def read_fixed_scenario(path: Path) -> dict[str, Any]:
    """Lectura local explícita: el CLI jamás toma una ruta de un dato analítico."""
    _need(isinstance(path, Path) and path.is_file() and not path.is_symlink(),
          'scenario_missing_or_symlink')
    raw = path.read_bytes()
    _need(len(raw) <= MAX_BYTES, 'scenario_oversized')
    try:
        source = json.loads(raw, object_pairs_hook=_pairs)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise SessionError('scenario_invalid_json') from exc
    return normalize_scenario(source)


def _event(ordinal: int, stage: str, sid: str, input_sha: str,
           decision: dict[str, Any], previous: str | None) -> dict[str, Any]:
    body: dict[str, Any] = {
        'ordinal': ordinal, 'algorithm': stage, 'service_id': sid,
        'source_kind': SOURCE_KIND, 'input_sha256': input_sha,
        'decision': decision, 'previous_event_sha256': previous,
    }
    body['event_id'] = 'EVT_' + _sha(_canonical(body))[:24].upper()
    body['event_sha256'] = _sha(_canonical(body))
    return body


def verify_session_document(document: dict[str, Any]) -> bool:
    """Comprueba consistencia del contrato/cadena; un hash no acredita verdad."""
    _need(type(document) is dict and document.get('schema') == FORMAT,
          'session_format')
    _need(document.get('source_kind') == SOURCE_KIND
          and document.get('p8_operational') == 'NO-GO'
          and document.get('operational_dispatch') is False
          and document.get('published_generation') is None
          and document.get('final_risk') is None,
          'session_false_authority')
    events = document.get('events')
    units = document.get('units')
    _need(type(events) is list and len(events) == 9 and type(units) is list
          and len(units) == 3 and {u['service_id'] for u in units} == set(REQUIRED),
          'session_event_units')
    previous = None
    for number, event in enumerate(events, 1):
        _need(type(event) is dict and event.get('ordinal') == number
              and event.get('previous_event_sha256') == previous
              and event.get('source_kind') == SOURCE_KIND
              and event.get('algorithm') in {'A1', 'A2', 'A3'}
              and event.get('service_id') in REQUIRED, 'event_chain')
        claimed_sha = event['event_sha256']
        without_sha = {k: v for k, v in event.items() if k != 'event_sha256'}
        _need(_sha(_canonical(without_sha)) == claimed_sha, 'event_digest')
        without_ids = {k: v for k, v in without_sha.items() if k != 'event_id'}
        _need('EVT_' + _sha(_canonical(without_ids))[:24].upper()
              == event['event_id'], 'event_identity')
        previous = claimed_sha
    _need([(e['service_id'], e['algorithm']) for e in events] ==
          [(sid, stage) for sid in sorted(REQUIRED)
           for stage in ('A1', 'A2', 'A3')], 'event_order')
    claimed = document.get('session_sha256')
    without_digest = {k: v for k, v in document.items()
                      if k != 'session_sha256'}
    _need(type(claimed) is str and _sha(_canonical(without_digest)) == claimed,
          'session_digest')
    return True


@dataclass(frozen=True, slots=True)
class DevelopmentSession:
    document: dict[str, Any]
    sha256: str

    def verify(self) -> bool:
        _need(self.sha256 == self.document.get('session_sha256'),
              'session_object_digest')
        return verify_session_document(self.document)

    def json_bytes(self) -> bytes:
        self.verify()
        return _canonical(self.document)


def build_development_session(candidate: dict[str, Any]) -> DevelopmentSession:
    """Una invocación encadena A1 -> A2 -> A3 de verdad, sin despacho técnico."""
    fixture = normalize_scenario(candidate)
    fixture_sha = _sha(_canonical(fixture))
    services = fixture['services']
    ids = [s['id'] for s in services]
    rule_configuration = {
        'format': RULE_FORMAT, 'fields': {'FACT': 'LOGICO'},
        'services': [{'id': sid, 'initial_state': 'PREPARADO', 'rules': [
            {'id': 'ALLOW', 'condicion': {'op': 'CAMPO', 'nombre': 'FACT'}},
            {'id': 'DENY', 'condicion': {
                'op': 'NO', 'arg': {'op': 'CAMPO', 'nombre': 'FACT'}}},
        ]} for sid in ids],
    }
    rules = preflight_rule_configuration(rule_configuration)
    initial = prepare_initial_preview(rules, {
        'format': INITIAL_FORMAT, 'rule_source_sha256': rules.sha256,
        'services': [{'id': s['id'], 'initial_risk': s['initial_risk'],
                      'normalized_criticality': s['normalized_criticality'],
                      'cases': [{'id': 'CASE_POLICY', 'max_repetitions': 0},
                                {'id': 'CASE_REFERENCE', 'max_repetitions': 0}]}
                     for s in services],
    })
    deps = prepare_dependency_preview(rules, initial, {
        'format': DEPENDENCY_FORMAT, 'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'services': [{'id': sid, 'protocol': REQUIRED[sid], 'cases': [
            {'id': 'CASE_POLICY', 'requires': []},
            {'id': 'CASE_REFERENCE', 'requires': []},
        ]} for sid in ids],
    })
    controls = prepare_control_preview(rules, initial, deps, {
        'format': CONTROL_FORMAT, 'rule_source_sha256': rules.sha256,
        'initial_snapshot_sha256': initial.sha256,
        'dependency_snapshot_sha256': deps.sha256,
        'services': [{'id': sid, 'controls': [
            {'id': 'CTRL_POLICY', 'guard_rule_id': 'ALLOW',
             'target_case_id': 'CASE_POLICY', 'precedence': 20, 'requires': []},
            {'id': 'CTRL_REFERENCE', 'guard_rule_id': 'ALLOW',
             'target_case_id': 'CASE_REFERENCE', 'precedence': 10, 'requires': []},
        ]} for sid in ids],
    })
    integrated = assemble_integrated_preview(rules, initial, deps, controls)
    _need(integrated.verify(rules, initial, deps, controls), 'a2_invalid')
    environments = {s['id']: ({} if s['fact'] == 'AUSENTE' else
                              {'FACT': Truth[s['fact']]}) for s in services}
    decisions = {sid: rules.evaluate_service(sid, environments[sid])
                 for sid in ids}
    guard = diagnose_guards(rules, initial, deps, controls,
                            integrated, environments)
    _need(guard.verify(rules, initial, deps, controls, integrated, environments),
          'a3_invalid')
    guard_by_id = {u.service_id: u for u in guard.units}
    contract_by_id = {u.service_id: u for u in integrated.units}
    init_by_id = {u.id: u for u in initial.units}

    units: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    previous: str | None = None

    for s in services:
        sid = s['id']
        d, u, c, i = (decisions[sid], guard_by_id[sid],
                       contract_by_id[sid], init_by_id[sid])
        _need(d.status is u.table_status and d.selected_rule == u.table_selected
              and d.evaluations == u.evaluations, 'a1_a3_disagreement')
        _need(i.phase.value == 'PREPARADO'
              and str(i.initial_risk) == s['initial_risk']
              and i.recalibrated_risk == i.initial_risk
              and i.accumulated_evidence == 0, 'a2_initial_state')
        _need(all('AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in ctrl.blockers
                  for ctrl in u.controls), 'a3_unexpected_authority')
        unit = {
            'service_id': sid, 'protocol': s['protocol'],
            'source_kind': SOURCE_KIND,
            'source_reference': 'FIXTURE:' + fixture['session_id'] + ':' + sid,
            'fact_declared': s['fact'],
            'a1': {'status': d.status.name, 'selected_rule': d.selected_rule,
                   'evaluations': [{'rule_id': rid, 'truth': truth.name}
                                   for rid, truth in d.evaluations]},
            'a2': {'initial_phase': i.phase.value, 'initial_risk': str(i.initial_risk),
                   'normalized_criticality': str(i.normalized_criticality),
                   'accumulated_evidence': '0',
                   'recalibrated_risk_preview': str(i.recalibrated_risk),
                   'cases': list(c.case_order),
                   'control_references': list(c.control_order),
                   'integrated_sha256': integrated.sha256},
            'a3': {'table_status': u.table_status.name,
                   'table_selected': u.table_selected,
                   'controls': [{'id': ctrl.control_id,
                                 'truth': ctrl.truth.name,
                                 'blockers': list(ctrl.blockers)}
                                for ctrl in u.controls],
                   'executable_agenda': None,
                   'operational_dispatch': False},
            'technical_evidence': None, 'final_risk': None,
        }
        units.append(unit)
        stages = [
            ('A1', rules.sha256, {'status': d.status.name,
                                 'selected_rule': d.selected_rule}),
            ('A2', integrated.sha256, {'phase': i.phase.value,
                                      'initial_risk': str(i.initial_risk),
                                      'cases': list(c.case_order)}),
            ('A3', guard.sha256, {'table_status': u.table_status.name,
                                 'blocked_controls': [ctrl.control_id
                                    for ctrl in u.controls if ctrl.blockers],
                                 'operational_dispatch': False}),
        ]
        for stage, input_sha, result in stages:
            e = _event(len(events) + 1, stage, sid, input_sha, result, previous)
            events.append(e)
            previous = e['event_sha256']

    result: dict[str, Any] = {
        'schema': FORMAT, 'session_id': fixture['session_id'],
        'scope': 'FIXED_SYNTHETIC_A1_A2_A3_ONLY',
        'source_kind': SOURCE_KIND, 'fixture_sha256': fixture_sha,
        'sources_sha256': {'rules': rules.sha256, 'initial': initial.sha256,
                           'dependencies': deps.sha256, 'controls': controls.sha256,
                           'integrated': integrated.sha256, 'guard': guard.sha256},
        'units': units, 'events': events,
        'p8_operational': 'NO-GO', 'operational_dispatch': False,
        'published_generation': None, 'final_risk': None,
        'a1_full': False, 'a2_full': False, 'a3_full': False,
        'a4_a10_executed': False,
    }
    result['session_sha256'] = _sha(_canonical(result))
    session = DevelopmentSession(result, result['session_sha256'])
    session.verify()
    return session
