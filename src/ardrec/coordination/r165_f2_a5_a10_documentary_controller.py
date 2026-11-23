"""R165-F2: controlador documental A5-A10, sin autoridad operacional.

Reutiliza B10 y B11. Una firma verificable no reemplaza la
relectura root de B9/R127 ni permite confirmar A6, Rf o A9.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from ardrec.coordination import (
    r129_b9_receipt_gate as b10,
    r129_b11_independent_a6 as b11,
)

SCHEMA = "ARDREC-R165-F2-A5-A10-DOCUMENTARY-CONTROLLER-v1"

STAGES = ("A5", "A6", "A7", "A8", "A9", "A10")

SIGNED_FIELDS = frozenset({
    "source", "technical", "revocation", "witness", "trust",
})

BLOCKERS = (
    "ORIGINAL_ROOT_B9_NOT_INDEPENDENTLY_REPLAYED",
    "R127_PHYSICAL_CLOSURE_NOT_ATTESTED_HERE",
    "LIVE_B11_ROOT_ADMISSION_NOT_EXECUTED",
    "A7_CONFIRMED_RISK_NOT_AVAILABLE",
    "A8_OPERATIONAL_TRANSITION_NOT_APPLIED",
    "A9_AUTHORIZED_GENERATION_NOT_AVAILABLE",
)


class Stop(ValueError):
    """Violación de identidad, alcance o frontera de autoridad."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise Stop(reason)


def _stage(
    ordinal: int,
    algorithm: str,
    status: str,
    source_sha256: str,
    previous: str | None,
) -> dict[str, Any]:
    event = {
        "ordinal": ordinal,
        "algorithm": algorithm,
        "status": status,
        "source_sha256": source_sha256,
        "previous_event_sha256": previous,
        "physical_execution": False,
        "authority_granted": False,
        "generation_published": False,
    }
    event["sha256"] = b10.digest(event)
    return event


def evaluate(
    *,
    journal: Path,
    handoff: dict,
    intent: dict,
    receipt: dict,
    guest: dict | None = None,
    qga: dict | None = None,
    signed: dict | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Reproduce A5 y, opcionalmente, verifica firmas documentales B11.

    La salida es una decisión fail-closed y una traza hash-encadenada.
    No llama a admit_live, B12, _publish ni DurableStore.
    """
    need(
        isinstance(journal, Path) and journal.is_absolute(),
        "F13_ABSOLUTE_JOURNAL_REQUIRED",
    )

    need(
        signed is None or (
            type(signed) is dict
            and set(signed) == SIGNED_FIELDS
        ),
        "SIGNED_DOCUMENT_SET_INVALID",
    )

    need(
        (signed is None and now is None)
        or (
            signed is not None
            and type(now) is datetime
            and now.tzinfo is not None
            and now.utcoffset() is not None
        ),
        "SIGNED_REVIEW_CLOCK_REQUIRED",
    )

    # Validación real del diario F13, recibo B9 y respuesta QGA.
    candidate = b10.review(
        journal=journal,
        handoff=handoff,
        intent=intent,
        receipt=receipt,
        guest=guest,
        qga=qga,
    )

    # Misma cadena de origen, con bloqueo nativo antes de A9.
    barrier = b10.a9_barrier(
        candidate=candidate,
        journal=journal,
        handoff=handoff,
        intent=intent,
        receipt=receipt,
        guest=guest,
        qga=qga,
    )

    need(
        candidate["local_source_hashes_replayed"] is True
        and candidate["independent_root_origin_verified"] is False
        and candidate["independent_r127_crash_witness_verified"]
            is False
        and candidate["independent_a6_technical_truth_accredited"]
            is False
        and candidate["a6"] == "ND"
        and candidate["a7_confirmed_rf"] is None
        and candidate["a8_applied"] is None
        and candidate["a9"] is None
        and candidate["p8"] == "NO-GO",
        "UNTRUSTED_A5_PROMOTION",
    )

    need(
        barrier["candidate_sha256"] == candidate["sha256"]
        and barrier["a6"] == "ND"
        and barrier["a7_confirmed_rf"] is None
        and barrier["a8_applied"] is None
        and barrier["a9"] is None
        and barrier["durable_store_opened"] is False
        and barrier["generation_written"] is False
        and barrier["p8"] == "NO-GO",
        "A9_BARRIER_FAILED",
    )

    documentary = None

    if signed is not None:
        documentary = b11.signed_review(
            candidate=candidate,
            source=signed["source"],
            technical=signed["technical"],
            revocation=signed["revocation"],
            witness=signed["witness"],
            trust=signed["trust"],
            now=now,
        )

        need(
            documentary["candidate_sha256"]
                == candidate["sha256"]
            and documentary["signatures_verified"] is True
            and documentary["source_root_owned_replayed"] is False
            and documentary["root_r127_physically_verified"] is False
            and documentary["a6"] == "ND"
            and documentary["confirmed_rf"] is None
            and documentary["a8"] is None
            and documentary["a9"] is None
            and documentary["p8"] == "NO-GO",
            "SIGNED_COPY_PROMOTED_TO_PHYSICAL_TRUTH",
        )

    has_signatures = documentary is not None

    statuses = (
        "EXPORTED_A5_CANDIDATE_REPLAYED"
        if candidate["root_receipt_status"]
            == "FTP_GUEST_CANDIDATE_ONLY"
        else "EXPORTED_ATTEMPT_UNRESOLVED",
        "SIGNED_DOCUMENTARY_ONLY_NO_ROOT"
        if has_signatures else "INDEPENDENT_A6_NOT_ATTESTED",
        "CONFIRMED_RISK_UNAVAILABLE",
        "OPERATIONAL_TRANSITION_NOT_APPLIED",
        "NATIVE_A9_PUBLICATION_BLOCKED",
        "HASH_CHAIN_READONLY_AUDIT_AVAILABLE",
    )

    sources = (
        candidate["sha256"],
        b11.sha(documentary)
        if has_signatures else candidate["sha256"],
        barrier["candidate_sha256"],
        b10.digest(barrier),
        b10.digest(barrier),
        b10.digest(barrier),
    )

    entries = []
    previous = None

    for position, (algorithm, status, source) in enumerate(
        zip(STAGES, statuses, sources),
        1,
    ):
        event = _stage(
            position,
            algorithm,
            status,
            source,
            previous,
        )
        entries.append(event)
        previous = event["sha256"]

    need(
        len(entries) == 6
        and entries[-1]["algorithm"] == "A10",
        "STAGE_CHAIN_INCOMPLETE",
    )

    report = {
        "schema": SCHEMA,
        "source_kind": "EXPORTED_UNTRUSTED_F13_B9_DOCUMENTS",
        "case_id": candidate["case_id"],
        "case_key": candidate["case_key"],
        "session": candidate["session"],
        "head": candidate["head"],
        "a5_candidate_sha256": candidate["sha256"],
        "a5_status": candidate["a5"],
        "a5_root_receipt_status":
            candidate["root_receipt_status"],
        "a5_documentary_replay": True,
        "a6_signed_documentary_review_sha256":
            b11.sha(documentary) if has_signatures else None,
        "a6_documentary_signatures_verified": has_signatures,
        "a6_physical_root_attested": False,
        "a6": "ND",
        "a7_calculation_executed_here": False,
        "a7_confirmed_rf": None,
        "a8_transition_applied": False,
        "a9_barrier_sha256": b10.digest(barrier),
        "a9_durable_store_opened": False,
        "a9_generation": None,
        "a10_stage_count": len(entries),
        "a10_event_head_sha256": previous,
        "stages": entries,
        "blockers": list(BLOCKERS),
        "technical_truth_accredited": False,
        "physical_observation_accredited": False,
        "operational_dispatch": False,
        "vm_starts": 0,
        "nft_writes": 0,
        "p8": "NO-GO",
    }

    report["sha256"] = b10.digest(report)

    need(
        len(b10.f1.canonical(report)) <= 32768,
        "CONTROLLER_REPORT_TOO_LARGE",
    )

    return report


def verify(report: dict, **sources: Any) -> bool:
    """Reconstruir todo: identidad, firmas y seis eventos encadenados."""
    need(
        type(report) is dict
        and report == evaluate(**sources),
        "CONTROLLER_REPLAY_MISMATCH",
    )
    return True


def capabilities() -> dict[str, Any]:
    return {
        "schema": SCHEMA + "-capabilities",
        "a5_original_b10_replay": True,
        "a6_documentary_ed25519_b11": True,
        "a6_live_root_admission": False,
        "a7_confirmed_risk": False,
        "a8_operational_transition": False,
        "a9_durable_store_opened": False,
        "a9_generation_published": False,
        "a10_stage_hash_chain": True,
        "native_a9_alternative_implemented": False,
        "physical_observations": 0,
        "network_connections": 0,
        "vm_starts": 0,
        "nft_writes": 0,
        "p8": "NO-GO",
    }
