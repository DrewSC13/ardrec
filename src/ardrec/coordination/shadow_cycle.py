"""R71: recorrido positivo *hipotético* A3/A4 y ejecución benigna local A5.

La proyección R27 NO pertenece a la generación R70; el proceso local es
exclusivamente `BenignPipeline('ok')`. No acredita servicio, A6 ni Rf.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ardrec.analytics.r58d_interval_kernel import build_intervals, verify_intervals
from ardrec.coordination.benign_review import RID, execute_local_review
from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.safe_generation import open_or_publish_safe
from ardrec.persistence.codec import canonical, digest

SCHEMA = 'ardrec-p14-r71-shadow-positive-benign-v1'

class ShadowError(ValueError):
    pass


def _need(condition: bool, code: str) -> None:
    if not condition:
        raise ShadowError(code)


def _separate_roots(durable: Path, benign: Path) -> None:
    _need(isinstance(durable, Path) and isinstance(benign, Path) and
          durable.is_absolute() and benign.is_absolute(), 'root_not_absolute')
    _need(not durable.is_symlink() and not benign.is_symlink(), 'root_symlink')
    # Dos dominios de persistencia aislados, sin escribir dentro de la sesión A9.
    _need(durable != benign and durable not in benign.parents and
          benign not in durable.parents, 'journal_not_separate')


def _oracle(scenario: dict[str, Any]) -> dict[str, Any]:
    ssh = next(s for s in scenario['services'] if s['id'] == 'SSH_DEV')
    result = build_intervals([{
        'service_id': 'SSH_DEV', 'case_id': 'CASE_REFERENCE',
        'assessment_index': 0, 'initial_risk': ssh['initial_risk'],
        'normalized_criticality': ssh['normalized_criticality'],
        'replacement_risk': ssh['initial_risk'],
        'evidence': [{'evidence_id': 'SYNTHETIC_E1',
                      'kind': 'SYNTHETIC_FIXED', 'lower': '1/2', 'upper': '1/2'}],
    }])
    verify_intervals(result)
    _need(result['results'][0]['rf_lower'] == '5/12' and
          result['results'][0]['rf_upper'] == '5/12' and
          result['confirmed_final_risk'] is None,
          'shadow_risk_oracle_mismatch')
    return result


def run_shadow_cycle(durable: Path, benign: Path, candidate: dict[str, Any],
                     *, expected_head_sha256: str | None = None) -> dict[str, Any]:
    """Crea/relee UN fixture benigno; ninguna nueva generación ARDREC.

    Una ejecución interrumpida con inicio ambiguo se rechaza (sin reintento).
    Dos invocaciones completadas conservan el mismo recibo y HEAD R70.
    """
    _separate_roots(durable, benign)
    fixture = normalize_scenario(candidate)
    # Preflight primero: el HEAD/recibo/archivo originales deben ser auténticos.
    r70 = open_or_publish_safe(durable, fixture, publish=False,
                              expected_head_sha256=expected_head_sha256)
    _need(r70['generation'] == 1 and
          r70['source_kind'] == 'SYNTHETIC_DEV_STOP_WITHOUT_DISPATCH' and
          r70['analytical_validation'] == 'structural_only' and
          r70['store_recovery_action'] == 'NONE' and
          r70['a5_attempt_count'] == 0 and
          r70['a7_confirmed_rf'] is None and
          r70['p8_operational'] == 'NO-GO', 'safe_gen1_required')
    # A7 se calcula con un oráculo independiente de la ejecución local.
    oracle = _oracle(fixture)
    # Ejecuta una sola vez el fixture sin acceso a la red ni entrada de comandos.
    result = execute_local_review(fixture, benign)
    select = result['a4_hypothetical']
    _need(result['a4_confirmed']['selected'] is None and
          select['selected'] == {
              'service_id': 'SSH_DEV', 'case_id': 'CASE_REFERENCE',
              'priority': '1/4', 'precedence': 10} and
          select['eligible_count'] == 2 and
          result['a5']['request_id'] == RID and
          result['a5']['state'] == 'RECORDED_LIMITED' and
          result['a5']['start_count_reserved'] == 1 and
          result['a5']['artifacts_verified'] is True and
          result['a5']['outcome'] == 'BENIGN_EXIT_ZERO' and
          result['a6']['classification'] == 'ND' and
          result['a6']['technical_truth_accredited'] is False and
          result['a6']['final_risk'] is None and
          result['p8_operational'] == 'NO-GO' and
          result['vm_checks_executed'] is False,
          'benign_or_shadow_binding_invalid')
    body: dict[str, Any] = {
        'schema': SCHEMA,
        'source_kind': 'SYNTHETIC_SHADOW_SELECTION_AND_LOCAL_BENIGN',
        'record_id': r70['record_id'],
        'generation': 1,
        'configuration_sha256': r70['configuration_sha256'],
        'r70_receipt_sha256': r70['sha256'],
        'r70_head_sha256': r70['head_sha256'],
        'r70_snapshot_sha256': r70['analytical_snapshot_sha256'],
        'a1_decisions': r70['a1_decisions'],
        'a3_shadow_guard': 'VERDADERO_SIMULADO',
        'a3_operational_guard': 'NO_GO',
        'a4_shadow_selection': select['selected'],
        'a4_confirmed_selection': None,
        'a4_shadow_sha256': select['sha256'],
        'a5_local_benign_request': RID,
        'a5_local_benign_outcome': 'BENIGN_EXIT_ZERO',
        'a5_local_benign_starts': 1,
        'a5_event_head_sha256': result['a5']['event_head_sha256'],
        'a5_review_sha256': result['sha256'],
        'a6_classification': 'ND',
        'a7_synthetic_oracle_sha256': oracle['sha256'],
        'a7_hypothetical_rf': oracle['results'][0]['rf_lower'],
        'a7_confirmed_rf': None,
        'a8_original_stop': 'DETENER',
        'a9_structural_generation': 1,
        'a9_new_generation_published': False,
        'a10_dashboard': 'R38_ORIGINAL',
        'physical_observation_attested': False,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    body['sha256'] = digest(canonical(body))
    return body
