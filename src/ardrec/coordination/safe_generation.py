"""R70: generación analítica DEV de parada segura; jamás ejecuta un intento.

Camino controlado: A1/A2 congelados -> A3 sin autoridad de despacho ->
A4 sin elegibles -> A5 sin reserva/inicio -> A6/A7 ND -> A8 DETENER
por política DEV -> A9 publicación analítica estructural -> A10 monitor R38.
No es la implementación integral del camino técnico A5/A6/A7 ni acredita P8.
"""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
from pathlib import Path
from typing import Any

from ardrec.analytical import AnalyticalProjection, FrozenValues, AnalysisValues, ObjectReference
from ardrec.analytical_references import ROLES, OBJECT_FORMAT, MANIFEST_FORMAT, canonical as ref_canonical
from ardrec.contracts import ND
from ardrec.coordination.demo_session import normalize_scenario, prepare_frozen_development_sources
from ardrec.coordination.durable_dev import (
    DurableDevError, CONFIG_SCHEMA, SCHEMA as R69_SCHEMA, _need,
    _private_root, _read_private, _frozen_configuration, _decision_for_service,
    open_or_create_dev,
)
from ardrec.persistence import DurableStore, FORMAT as STORE_FORMAT
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.persistence.codec import canonical, digest, parse
from ardrec.state import (
    ConfirmedState, GlobalState, ServiceState, ServicePhase, Transition,
    TransitionContext, GuardFact, Truth,
)

SCHEMA = 'ardrec-p14-r70-safe-analytical-generation-v1'
EVENT = 'R70_DEV_NO_DISPATCH_PUBLISH'
REFERENCE_SUFFIX = '_R70_SAFE_GEN1'


def _initial_identity(fixture, config_sha):
    sid = fixture['session_id']
    services = tuple(ServiceState(s['id'], ServicePhase.PREPARADO) for s in fixture['services'])
    confirmed = ConfirmedState(sid, 0, 'GEN_' + sid + '_0', config_sha,
                               'VERS_' + sid, services)
    return replace(GlobalState(confirmed, 'EXE_' + sid, services), authority=Truth.VERDADERO)


def _validate_r69_document(raw, fixture, sources, config_sha):
    _need(raw is not None, 'r69_receipt_missing')
    doc = parse(raw)
    _need(doc.get('schema') == R69_SCHEMA and doc.get('generation') == 0 and
          doc.get('scope') == 'DEV_SYNTHETIC_DURABLE_INITIAL_GENERATION' and
          doc.get('record_id') == fixture['session_id'] and
          doc.get('configuration_sha256') == config_sha and
          doc.get('rules_sha256') == sources[0].sha256 and
          doc.get('integrated_sha256') == sources[4].sha256 and
          doc.get('p8_operational') == 'NO-GO' and
          doc.get('operational_dispatch') is False and
          doc.get('a9_subsequent_publication_attested') is False and
          doc.get('a5_dispatch_performed') is False and
          doc.get('physical_observation_attested') is False and
          doc.get('a7_confirmed_rf') is None and
          doc.get('store_recovery_action') == 'NONE' and
          doc.get('sha256') == digest(canonical({k:v for k,v in doc.items() if k != 'sha256'})),
          'r69_receipt_invalid')
    initial = _initial_identity(fixture, config_sha)
    _need(doc.get('execution_id') == initial.execution_id and
          doc.get('generation_reference') == initial.confirmed.generation_reference and
          doc.get('a1_decisions') == {
              s['id']: _decision_for_service(sources[0], initial, s)
              for s in fixture['services']
          }, 'r69_decisions_not_reproducible')
    return doc



def _verify_genesis_head(store: DurableStore, doc0: dict[str, Any]):
    """Anclar el recibo histórico GEN0 al primer evento del diario recuperado.

    No reconstruir un origen a partir de un SHA auto-declarado por el recibo.
    El replay previo valida toda la cadena hasta HEAD actual.
    """
    first_sha = store._head['journal_digest']
    while True:
        entry = store._object('journal', first_sha)
        if entry['sequence'] == 0:
            break
        _need(type(entry.get('previous')) is str, 'invalid_genesis_chain')
        first_sha = entry['previous']
    _need(entry['operation'] == 'initialize' and
          entry['previous'] is None and entry['sequence'] == 0,
          'unexpected_original_initialization')
    initial_head = {
        'format': STORE_FORMAT,
        'record_id': store.state.confirmed.record_id,
        'configuration_sha256': store.state.confirmed.configuration_sha256,
        'sequence': 0,
        'journal_digest': first_sha,
        'generation_digest': entry['generation_digest'],
        'generation': 0,
    }
    raw = canonical({'head': initial_head,
                     'sha256': digest(canonical(initial_head))})
    _need(digest(raw) == doc0['store_head_sha256'],
          'genesis_head_receipt_mismatch')


def _stop_context(state, sid):
    reason = 'R70_NO_DISPATCH_' + sid
    return TransitionContext(
        record_id=state.confirmed.record_id,
        execution_id=state.execution_id,
        generation=0,
        configuration_sha256=state.confirmed.configuration_sha256,
        event_reference='R70_STOP_' + sid,
        facts=(GuardFact('cause_verified', Truth.VERDADERO, reason),
               GuardFact('effect_processable', Truth.VERDADERO,
                         'R70_SYNTHETIC_STOP_ONLY_' + sid)),
        reason_reference=reason,
        stop_cause='CONTROL',
    )


def _valid_safe_state(state, fixture):
    _need(state.confirmed.generation == 1 and not state.attempts and
          state.services == state.confirmed.services and
          state.confirmed.generation_reference == 'GEN_' + fixture['session_id'] + REFERENCE_SUFFIX and
          set(state.confirmed.incorporated_events) == {
              *(('R70_STOP_' + s['id']) for s in fixture['services']), EVENT
          } and len(state.confirmed.incorporated_events) == 4 and
          all(s.phase is ServicePhase.DETENIDO and s.stop_cause == 'CONTROL' and
              s.reason_reference == 'R70_NO_DISPATCH_' + s.service_scenario_id and
              not s.local_trace for s in state.services),
          'unexpected_safe_generation_state')


def _snapshot(archive, state, fixture):
    """Referencias estructurales, etiquetas explícitas de ausencia de evidencia."""
    ctx = dict(record_id=state.confirmed.record_id,
               execution_id=state.execution_id,
               configuration_sha256=state.confirmed.configuration_sha256,
               generation_index=1)
    objects, bindings, projections = {}, [], []
    for item in fixture['services']:
        sid = item['id']
        refs = {}
        for role in ROLES:
            ref = 'R70_' + sid + '_' + role.upper()
            raw = ref_canonical({
                'format': OBJECT_FORMAT,
                'context': {**ctx, 'generation_index': 0},
                'service_scenario_id': sid, 'role': role, 'reference': ref,
                'payload': {'synthetic': True, 'source': 'R70_DEV_STOP_POLICY',
                            'evidence_accredited': False, 'technical_attempts': 0,
                            'analysis_status': 'ND'},
            })
            sha = digest(raw)
            refs[role] = ObjectReference(ref, sha)
            objects[sha] = raw
            bindings.append(dict(service_scenario_id=sid, role=role, reference=ref, sha256=sha))
        nd = ND('NO_EVIDENCE')
        projections.append(AnalyticalProjection(
            record_id=ctx['record_id'], execution_id=ctx['execution_id'],
            configuration_sha256=ctx['configuration_sha256'],
            service_scenario_id=sid, generation_index=1,
            operational_state=ServicePhase.DETENIDO,
            frozen=FrozenValues(Fraction(item['initial_risk']),
                                Fraction(item['normalized_criticality']),
                                refs['characterization']),
            analysis=AnalysisValues(nd, nd, nd, nd, nd, ND('NO_ELIGIBLE')),
            references=tuple(refs[role] for role in ROLES[1:]),
        ))
    manifest = ref_canonical({'format': MANIFEST_FORMAT, 'context': ctx,
                              'bindings': sorted(bindings, key=lambda x: (
                                  x['service_scenario_id'], x['role']))})
    return archive.store(tuple(projections), manifest, expected_manifest_sha256=digest(manifest),
                         load_object=objects.__getitem__)


def _audit_snapshot(store, fixture):
    snap = store.analytical_snapshot
    _need(snap is not None and store.analytical_validation == 'structural_only' and
          len(snap.projections) == len(fixture['services']), 'missing_safe_snapshot')
    for p, item in zip(snap.projections, fixture['services']):
        _need(p.service_scenario_id == item['id'] and p.generation_index == 1 and
              p.operational_state is ServicePhase.DETENIDO and
              p.frozen.initial_risk == Fraction(item['initial_risk']) and
              p.frozen.normalized_criticality == Fraction(item['normalized_criticality']) and
              all(type(getattr(p.analysis, field)) is ND for field in (
                  'accumulated_evidence', 'substituted_baseline', 'upper_bound',
                  'lower_adjustment_bound', 'recalibrated_risk', 'priority')) and
              p.analysis.recalibrated_risk.reason_code == 'NO_EVIDENCE' and
              p.analysis.priority.reason_code == 'NO_ELIGIBLE',
              'unsafe_analytical_claim')
    for raw in snap.references.object_bytes:
        obj = parse(raw)
        _need(obj.get('payload') == {
            'synthetic': True, 'source': 'R70_DEV_STOP_POLICY',
            'evidence_accredited': False, 'technical_attempts': 0,
            'analysis_status': 'ND'}, 'untrusted_snapshot_payload')


def open_or_publish_safe(root: Path, candidate: dict[str, Any], *, publish: bool = False,
                         expected_config_sha256: str | None = None,
                         expected_head_sha256: str | None = None) -> dict[str, Any]:
    """Lectura idempotente; publicación exclusivamente con `publish=True`.

    La fuente R69 inicial debe existir y estar íntegra. No hay operaciones
    físicas; el archivo puede quedar escrito sin HEAD tras una interrupción.
    """
    fixture = normalize_scenario(candidate)
    sources = prepare_frozen_development_sources(fixture)
    config_bytes = _frozen_configuration(fixture, sources)
    config_sha = digest(config_bytes)
    if expected_config_sha256 is not None:
        _need(type(expected_config_sha256) is str and
              expected_config_sha256 == config_sha, 'external_config_pin_mismatch')
    _private_root(root)
    _need(_read_private(root, 'configuration.json') == config_bytes,
          'frozen_configuration_mismatch')
    doc0 = _validate_r69_document(_read_private(root, 'a1-generation-0.json'),
                                   fixture, sources, config_sha)
    archive_path = root / 'analytical-archive'
    if not archive_path.exists():
        if not publish:
            # sin archivo: solo es admisible GEN0 y se comprueba con replay R69
            return open_or_create_dev(root, fixture,
                                      expected_config_sha256=expected_config_sha256,
                                      expected_head_sha256=expected_head_sha256)
        _need(not archive_path.is_symlink(), 'archive_symlink_forbidden')
    elif archive_path.is_symlink():
        raise DurableDevError('archive_symlink_forbidden')
    with AnalyticalArchive(archive_path, create=not archive_path.exists()) as archive:
        with DurableStore.open(root / 'generational-store',
                               record_id=fixture['session_id'],
                               configuration_sha256=config_sha,
                               expected_head=expected_head_sha256,
                               analytical_archive=archive) as store:
            state = store.state
            _verify_genesis_head(store, doc0)
            _need(state.execution_id == doc0['execution_id'] and not state.simulation and
                  not state.attempts and store.temporal_status == 'PASS',
                  'unexpected_operational_state')
            if state.confirmed.generation == 0:
                _need(store.head_sha256 == doc0['store_head_sha256'] or
                      store.recovery_action == 'PUBLISH_CANDIDATE', 'initial_head_mismatch')
                if not publish:
                    _need(store.recovery_action == 'NONE', 'candidate_requires_review')
                    return doc0
                for item in fixture['services']:
                    sid = item['id']
                    phase = next(s.phase for s in store.state.services if s.service_scenario_id == sid)
                    if phase is ServicePhase.PREPARADO:
                        store.transition(sid, Transition.DETENER, _stop_context(store.state, sid))
                    else:
                        _need(phase is ServicePhase.DETENIDO, 'foreign_staged_transition')
                _need(all(s.phase is ServicePhase.DETENIDO for s in store.state.services)
                      and not store.state.attempts, 'candidate_not_safe')
                for service in store.state.services:
                    expected = _stop_context(store.state, service.service_scenario_id)
                    _need(len(service.local_trace) == 1 and
                          service.local_trace[0].transition is Transition.DETENER and
                          service.local_trace[0].context == expected and
                          service.reason_reference == expected.reason_reference and
                          service.stop_cause == 'CONTROL',
                          'foreign_staged_stop_refused')
                snapshot_sha = _snapshot(archive, store.state, fixture)
                store.publish_analytical(expected_generation=0,
                                         reference='GEN_' + fixture['session_id'] + REFERENCE_SUFFIX,
                                         event=EVENT, snapshot_sha256=snapshot_sha)
                state = store.state
            _valid_safe_state(state, fixture)
            _need(store.recovery_action == 'NONE' and store.temporal_status == 'PASS',
                  'safe_recovery_not_clean')
            _audit_snapshot(store, fixture)
            doc = {
                'schema': SCHEMA,
                'source_kind': 'SYNTHETIC_DEV_STOP_WITHOUT_DISPATCH',
                'scope': 'STRUCTURAL_ANALYTICAL_PUBLICATION_ONLY',
                'record_id': fixture['session_id'],
                'generation': 1,
                'generation_reference': state.confirmed.generation_reference,
                'configuration_sha256': config_sha,
                'r69_receipt_sha256': doc0['sha256'],
                'r69_head_sha256': doc0['store_head_sha256'],
                'head_sha256': store.head_sha256,
                'analytical_snapshot_sha256': store.analytical_snapshot_sha256,
                'analytical_validation': store.analytical_validation,
                'a1_decisions': doc0['a1_decisions'],
                'a3_guard': 'NO_DISPATCH_AUTHORITY_IN_DEV',
                'a4_selected': None,
                'a5_attempt_count': len(state.attempts),
                'a5_start_count': 0,
                'a6_classification': 'ND',
                'a7_confirmed_rf': None,
                'a8_transition': 'DETENER',
                'a8_stop_cause': 'CONTROL',
                'a9_structural_generation_published': True,
                'a9_technical_evidence_published': False,
                'store_recovery_action': store.recovery_action,
                'physical_observation_attested': False,
                'operational_dispatch': False,
                'p8_operational': 'NO-GO',
            }
            doc['sha256'] = digest(canonical(doc))
            return doc
