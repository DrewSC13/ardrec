"""R165-F3: cadena A5-A10 nativa, exclusivamente en fixture offline.

Realiza revisión documental B10/B11, cálculo candidato B12,
transición nativa A8 en memoria y preflight nativo A9 con B13.

Una copia inyectada de A6 no constituye admisión física.
No abre DurableStore ni autoriza generación operacional.
"""
from __future__ import annotations

from datetime import datetime
import os
from typing import Any

from ardrec.coordination import (
    r129_b9_receipt_gate as b10,
    r129_b11_independent_a6 as b11,
    r129_b12_calibration_a9 as b12,
    r129_b13_native_a9_replay as b13,
    r165_f2_a5_a10_documentary_controller as f2,
)
from ardrec.state import (
    GlobalState,
    ServicePhase,
    StateError,
    Transition,
    TransitionContext,
    Truth,
    transition_service,
)

SCHEMA = "ARDREC-R165-F3-OFFLINE-NATIVE-CHAIN-v1"
FIXTURE_MARKER = "INJECTED_FIXTURE_NO_PHYSICAL_AUTHORITY"

SOURCE_FIELDS = frozenset((
    "journal", "handoff", "intent", "receipt",
    "guest", "qga", "signed", "now",
))

STAGES = ("A5", "A6", "A7", "A8", "A9", "A10")


class Stop(ValueError):
    """Error de contrato de la integración offline."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise Stop(reason)


def checkpoint(number, algorithm, status, source, previous):
    event = {
        "ordinal": number,
        "algorithm": algorithm,
        "status": status,
        "source_sha256": source,
        "previous_event_sha256": previous,
        "execution_class": "OFFLINE_FIXTURE_ONLY",
        "physical_observation": False,
        "operational_authority": False,
    }
    event["sha256"] = b10.digest(event)
    return event


def integrate_fixture(
    *,
    fixture_marker: str,
    documentary_sources: dict[str, Any],
    injected_a6_copy: dict[str, Any],
    calibration: dict[str, Any],
    calibration_revocation: dict[str, Any],
    calibration_trust: dict[str, Any],
    b11_trust: dict[str, Any],
    catalog_sha256: str,
    initial_state: GlobalState,
    transition_context: TransitionContext,
    expected_generation: int,
    reference: str,
    publication_event: str,
) -> dict[str, Any]:
    """Ejecutar cuatro contratos reales sobre datos inyectados de prueba.

    No debe emplearse para acreditar evidencia física ni publicar.
    """
    need(os.geteuid() != 0, "ROOT_EXECUTION_FORBIDDEN")
    need(
        fixture_marker == FIXTURE_MARKER,
        "OFFLINE_FIXTURE_MARKER_REQUIRED",
    )
    need(
        type(documentary_sources) is dict
        and set(documentary_sources) == SOURCE_FIELDS
        and type(documentary_sources["signed"]) is dict,
        "DOCUMENTARY_SOURCE_FIELDS_INVALID",
    )

    signed = documentary_sources["signed"]

    need(
        type(b11_trust) is dict
        and signed.get("trust") == b11_trust,
        "B11_TRUST_MISMATCH",
    )

    # A5/A6: invocar el controlador documental existente.
    documentary = f2.evaluate(**documentary_sources)

    need(
        f2.verify(
            documentary,
            **documentary_sources,
        )
        and documentary["a6_documentary_signatures_verified"] is True
        and documentary["a6_physical_root_attested"] is False
        and documentary["a6"] == "ND"
        and documentary["a9_generation"] is None
        and documentary["p8"] == "NO-GO",
        "F2_DOCUMENTARY_BOUNDARY_FAILED",
    )

    # Una copia A6 positiva puede utilizarse solamente como fixture.
    # Ni su SHA ni sus banderas prueban su origen físico.
    need(
        type(injected_a6_copy) is dict
        and injected_a6_copy.get("sha256") == b11.sha({
            k: v for k, v in injected_a6_copy.items()
            if k != "sha256"
        }),
        "A6_FIXTURE_INTEGRITY_INVALID",
    )

    need(
        injected_a6_copy.get("head") == documentary["head"]
        and injected_a6_copy.get("session") == documentary["session"]
        and injected_a6_copy.get("case_id") == documentary["case_id"]
        and injected_a6_copy.get("a5_sha256")
            == documentary["a5_candidate_sha256"]
        and injected_a6_copy.get("family_id") == "FTP-T01",
        "A6_FIXTURE_IDENTITY_NOT_BOUND",
    )

    for admission_field, signed_field in (
        ("independent_source_attestation_sha256", "source"),
        ("independent_technical_verdict_sha256", "technical"),
        ("independent_current_revocation_sha256", "revocation"),
        ("independent_root_witness_sha256", "witness"),
    ):
        need(
            injected_a6_copy.get(admission_field)
                == b11.sha(signed[signed_field]),
            "A6_FIXTURE_SIGNATURE_BINDING_INVALID",
        )

    # A7: matemática exacta B12 y firmas de calibración.
    # B12 vuelve a tratar A6 como COPIA no acreditada.
    a7 = b12.preview_signed(
        admission=injected_a6_copy,
        calibration=calibration,
        revocation=calibration_revocation,
        trust=calibration_trust,
        b11_trust=b11_trust,
        now=documentary_sources["now"],
        catalog_sha256=catalog_sha256,
    )

    need(
        a7["head"] == documentary["head"]
        and a7["session"] == documentary["session"]
        and a7["case_id"] == documentary["case_id"]
        and a7["a6_copy_sha256"] == injected_a6_copy["sha256"]
        and a7["service_id"] == "FTP_DEV"
        and a7["family_id"] == "FTP-T01"
        and a7["calibration_signatures_verified"] is True
        and a7["a7_point_candidate_not_proven"] is True
        and a7["physical_provenance_reverified_here"] is False
        and a7["a6"] == "ND"
        and a7["confirmed_rf"] is None
        and a7["a9_generation"] is None
        and a7["p8"] == "NO-GO",
        "A7_DOCUMENTARY_BOUNDARY_FAILED",
    )

    # A8: ejecutar el reductor nativo puro, no un estado paralelo.
    need(
        type(initial_state) is GlobalState
        and initial_state.authority is Truth.VERDADERO
        and initial_state.simulation is False
        and type(expected_generation) is int
        and initial_state.confirmed.generation == expected_generation
        and len(initial_state.services) == 1
        and initial_state.services[0].service_scenario_id == "FTP_DEV"
        and initial_state.services[0].phase is ServicePhase.PREPARADO
        and initial_state.services == initial_state.confirmed.services
        and type(transition_context) is TransitionContext
        and transition_context.record_id
            == initial_state.confirmed.record_id
        and transition_context.execution_id
            == initial_state.execution_id
        and transition_context.generation == expected_generation,
        "NATIVE_TEST_STATE_INVALID",
    )

    try:
        staged = transition_service(
            initial_state,
            "FTP_DEV",
            Transition.DETENER,
            transition_context,
        )
    except (StateError, ValueError, TypeError) as exc:
        raise Stop("NATIVE_A8_TRANSITION_REJECTED") from exc

    need(
        staged.services[0].phase is ServicePhase.DETENIDO
        and staged.confirmed.generation == expected_generation
        and initial_state.services[0].phase is ServicePhase.PREPARADO,
        "NATIVE_A8_MODEL_TRANSITION_INVALID",
    )

    # A9: usar B13 y, a través de él, el reductor A9 original.
    # Solo produce una generación CANDIDATA en memoria.
    preflight = b13.review_untrusted_a7(
        documentary=a7,
        staged_state=staged,
        expected_generation=expected_generation,
        reference=reference,
        event=publication_event,
    )

    need(
        preflight["native_reducer_checked"] is True
        and preflight["a8_already_staged_by_caller"] is True
        and preflight["native_candidate_generation"]
            == expected_generation + 1
        and preflight["store_opened"] is False
        and preflight["store_committed"] is False
        and preflight["physical_provenance_authenticated"] is False
        and preflight["experimental_generation_authorized"] is False
        and preflight["a6"] == "ND"
        and preflight["confirmed_rf"] is None
        and preflight["a9"] is None
        and preflight["p8"] == "NO-GO",
        "NATIVE_A9_PREFLIGHT_BOUNDARY_FAILED",
    )

    state_projection = {
        "record_id": staged.confirmed.record_id,
        "execution_id": staged.execution_id,
        "service_id": "FTP_DEV",
        "phase_before": ServicePhase.PREPARADO.value,
        "phase_after": ServicePhase.DETENIDO.value,
        "transition": Transition.DETENER.value,
        "transition_event": transition_context.event_reference,
        "confirmed_generation_unchanged": expected_generation,
        "scope": "IN_MEMORY_FIXTURE_ONLY",
    }

    # A10: comprobación encadenada de los seis hitos.
    statuses = (
        "B10_REPLAYED_UNTRUSTED",
        "B11_SIGNED_DOCUMENTS_ONLY",
        "B12_EXACT_MATHEMATICAL_CANDIDATE",
        "NATIVE_A8_IN_MEMORY_TEST",
        "NATIVE_A9_PREFLIGHT_NO_COMMIT",
        "REPLAYABLE_FIXTURE_AUDIT",
    )

    sources = (
        documentary["a5_candidate_sha256"],
        documentary["a6_signed_documentary_review_sha256"],
        a7["sha256"],
        b10.digest(state_projection),
        b10.digest(preflight),
        b10.digest(preflight),
    )

    stages = []
    previous = None

    for index, (algorithm, status, source) in enumerate(
        zip(STAGES, statuses, sources),
        1,
    ):
        item = checkpoint(
            index, algorithm, status, source, previous
        )
        stages.append(item)
        previous = item["sha256"]

    report = {
        "schema": SCHEMA,
        "mode": FIXTURE_MARKER,
        "head": documentary["head"],
        "session": documentary["session"],
        "case_id": documentary["case_id"],
        "service_id": "FTP_DEV",
        "family_id": "FTP-T01",
        "f2_documentary_sha256": documentary["sha256"],
        "a6_injected_copy_sha256": injected_a6_copy["sha256"],
        "a6_source_kind": "TEST_INJECTED_NOT_PHYSICAL",
        "a6": "ND",
        "a6_physical_admitted": False,
        "a7_documentary_sha256": a7["sha256"],
        "a7_math_candidate_test_only": a7["a7_math_candidate"],
        "a7_exact_preview_sha256": a7["exact_preview_sha256"],
        "a7_exact_interval_sha256": a7["exact_interval_sha256"],
        "confirmed_rf": None,
        "a8_native_transition_test": state_projection,
        "a8_operational_transition_applied": False,
        "a9_preflight_sha256": b10.digest(preflight),
        "a9_candidate_generation_test_only":
            preflight["native_candidate_generation"],
        "a9_confirmed_generation": None,
        "a9_store_opened": False,
        "a9_store_committed": False,
        "a10_stage_count": len(stages),
        "a10_event_head_sha256": previous,
        "stages": stages,
        "operational_authority": False,
        "physical_observations": 0,
        "network_dispatch": False,
        "vm_starts": 0,
        "nft_writes": 0,
        "p8": "NO-GO",
    }

    report["sha256"] = b10.digest(report)

    need(
        len(b10.f1.canonical(report)) <= 32768,
        "INTEGRATION_REPORT_TOO_LARGE",
    )

    return report


def verify(report: dict[str, Any], **sources: Any) -> bool:
    need(
        type(report) is dict
        and report == integrate_fixture(**sources),
        "NATIVE_CHAIN_REPLAY_MISMATCH",
    )
    return True


def capabilities() -> dict[str, Any]:
    return {
        "schema": SCHEMA + "-capabilities",
        "b10_b11_documentary_pipeline": True,
        "b12_signed_calibration_and_two_math_oracles": True,
        "native_a8_reducer_exercised_in_memory": True,
        "native_a9_reducer_preflight_only": True,
        "a10_hash_linked_replay": True,
        "a6_injected_fixture_never_physical_authority": True,
        "confirmed_rf": None,
        "operational_a8": False,
        "operational_a9": False,
        "durable_store_opened": False,
        "root_execution_allowed": False,
        "network_connections": 0,
        "vm_starts": 0,
        "nft_writes": 0,
        "physical_observations": 0,
        "p8": "NO-GO",
    }
