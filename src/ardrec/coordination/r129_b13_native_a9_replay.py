"""R129-B13: A8/A9 native reducer review and private-store recovery boundary.

The only actual DurableStore commit path is the native store itself. This
module neither creates a generation nor accepts documentary A6/A7 as physical
truth. The isolated fixture may exercise real native I/O for regression tests;
its HEAD must never be represented as an operational A9 generation.
"""
from __future__ import annotations

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r129_b12_calibration_a9 as b12
from ardrec.state import GlobalState, ServicePhase, Truth

SCHEMA = 'ARDREC-R129-B13-NATIVE-A8-A9-DURABLE-REPLAY-v1'

class Stop(ValueError):
    pass


def need(ok: bool, why: str) -> None:
    if not ok:
        raise Stop(why)


def review_untrusted_a7(*, documentary: dict, staged_state: GlobalState,
                        expected_generation: int, reference: str, event: str) -> dict:
    """Test the native publication reducer, without granting publication.

    A caller-supplied B12 review is copyable, thus cannot establish real A6,
    calibration, or physical source integrity. Only an independent installed
    authority can attest them, separately from this source-only operation.
    """
    need(type(documentary) is dict and
         documentary.get('schema') == b12.SCHEMA + '-documentary-a7-review' and
         documentary.get('sha256') == f1.digest(f1.canonical({
             k:v for k,v in documentary.items() if k != 'sha256'})) and
         documentary.get('source_kind') == 'SIGNED_DOCUMENTARY_CALIBRATION_AND_MATH_ONLY' and
         documentary.get('p8') == 'NO-GO' and documentary.get('a6') == 'ND' and
         documentary.get('confirmed_rf') is None and
         documentary.get('a7_point_candidate_not_proven') is True and
         documentary.get('physical_provenance_reverified_here') is False and
         documentary.get('a8_transition_applied') is None and
         documentary.get('a9_generation') is None and
         documentary.get('a9_native_transaction_executed') is False,
         'DOCUMENTARY_A7_IS_NOT_PHYSICAL_PROOF')
    need(type(staged_state) is GlobalState and
         staged_state.authority is Truth.VERDADERO and
         staged_state.simulation is False,
         'NATIVE_STATE_NOT_AUTHORIZED_FOR_PREFLIGHT')
    need(type(expected_generation) is int and
         staged_state.confirmed.generation == expected_generation,
         'EXPECTED_GENERATION_MISMATCH')
    need(any(s.service_scenario_id == documentary.get('service_id') and
             s.phase in (ServicePhase.DETENIDO,ServicePhase.CERRADO,
                         ServicePhase.PREPARADO,ServicePhase.PENDIENTE,
                         ServicePhase.PAUSADO)
             for s in staged_state.services),
         'SERVICE_SCOPE_MISMATCH')
    result = b12.native_publish_preflight(
        state=staged_state, expected_generation=expected_generation,
        reference=reference, event=event)
    need(result['generation_written'] is False and
         result['technical_risk_published'] is False and
         result['durable_store_opened'] is False,
         'PREFLIGHT_MUST_NOT_WRITE')
    return {
        'schema': SCHEMA + '-nonoperational-preflight',
        'record_id': staged_state.confirmed.record_id,
        'service_id': documentary['service_id'],
        'head': documentary['head'],
        'session': documentary['session'],
        'case_id': documentary['case_id'],
        'a7_documentary_sha256': documentary['sha256'],
        'expected_generation': expected_generation,
        'native_candidate_generation': result['candidate_generation'],
        'native_reducer_checked': True,
        'a8_already_staged_by_caller': True,
        'store_opened': False,
        'store_committed': False,
        'physical_provenance_authenticated': False,
        'experimental_generation_authorized': False,
        'a6': 'ND',
        'confirmed_rf': None,
        'a9': None,
        'p8': 'NO-GO',
    }


def capabilities() -> dict:
    return {
        'schema': SCHEMA + '-capabilities',
        'native_durable_store_used_by_isolated_tests': True,
        'native_a8_reducer_used_by_isolated_tests': True,
        'native_publish_and_reopen_exercised_by_isolated_tests': True,
        'native_crash_head_commit_points_tested': True,
        'documentary_a6_a7_cannot_authorize_physical_a9': True,
        'production_a9_commit_exposed': False,
        'root_installer': False,
        'network_connections': 0,
        'vm_starts': 0,
        'nft_writes': 0,
        'a6': 'ND',
        'confirmed_rf': None,
        'a9': None,
        'p8': 'NO-GO',
    }
