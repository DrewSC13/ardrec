"""R211: exact synthetic risk trajectories.

Development only. No physical evidence admission, network dispatch,
authoritative state transitions or operational generation publication.
"""
from __future__ import annotations

from ardrec.analytics.exact_preview import rational
from ardrec.analytics.r58d_interval_kernel import (
    build_intervals,
    verify_intervals,
)
from ardrec.experiments.initial_assessment import compute
from ardrec.coordination import prospective_local_pilot as durable
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.stopping.development_stop import preview_stop, verify_stop


SCHEMA = "ARDREC-R211-SYNTHETIC-RISK-TRAJECTORY-v1"

PROTOCOLS = ("SSH", "FTP", "SMB")

WEIGHTS = ("1/3", "1/3", "1/3")

MAX_EVENTS = 24

DEMO_EVENTS = (
    ("POSITIVE_MODEL", "3/4"),
    ("POSITIVE_MODEL", "1/4"),
    ("NEGATIVE_MODEL", "1/6"),
    ("ND_MODEL", None),
)


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def build(protocol, events):

    need(protocol in PROTOCOLS, "PROTOCOL_INVALID")

    need(
        type(events) is list
        and len(events) <= MAX_EVENTS,
        "EVENT_COUNT_INVALID",
    )

    # Fixed synthetic ordinal inputs.
    initial = compute(1, 4, 3, (3, 3, 3))

    r0 = initial["initial_risk"]
    criticality = initial["normalized_criticality"]
    replacement = r0

    accumulated = []
    normalized = []
    windows = []

    previous = "0" * 64

    for index in range(len(events) + 1):

        if index == 0:

            event = {
                "kind": "INITIAL_MODEL",
                "value": None,
            }

        else:

            raw = events[index - 1]

            need(
                type(raw) is dict
                and set(raw) == {"kind", "value"},
                "EVENT_SCHEMA_INVALID",
            )

            kind = raw["kind"]
            value = raw["value"]

            need(
                kind in {
                    "POSITIVE_MODEL",
                    "NEGATIVE_MODEL",
                    "ND_MODEL",
                },
                "EVENT_KIND_INVALID",
            )

            event = {
                "kind": kind,
                "value": value,
            }

            if kind == "POSITIVE_MODEL":

                point = rational(value)

                need(
                    point > 0,
                    "POSITIVE_CONTRIBUTION_REQUIRED",
                )

                accumulated.append({
                    "evidence_id": f"E_{index:03}",
                    "kind": "SYNTHETIC_FIXED",
                    "lower": str(point),
                    "upper": str(point),
                })

            elif kind == "NEGATIVE_MODEL":

                candidate = rational(value)

                need(
                    candidate < rational(replacement),
                    "REPLACEMENT_MUST_DECREASE",
                )

                # Hypothetical replacement supplied to the
                # mathematical kernel, not an A6 admission.
                replacement = str(candidate)

            else:

                need(
                    value is None,
                    "ND_MUST_NOT_HAVE_NUMERIC_VALUE",
                )

                accumulated.append({
                    "evidence_id": f"E_{index:03}",
                    "kind": "UNRESOLVED",
                    "lower": "0",
                    "upper": "1",
                })

            normalized.append(event)

        kernel = build_intervals(
            [{
                "service_id": protocol + "_DEV",
                "case_id": "DEV-R211-" + protocol,
                "assessment_index": index,
                "initial_risk": r0,
                "normalized_criticality": criticality,
                "replacement_risk": replacement,
                "evidence": [
                    dict(item) for item in accumulated
                ],
            }],
            weights=WEIGHTS,
        )

        verify_intervals(kernel)

        result = kernel["results"][0]

        need(
            result["confirmed_rf"] is None
            and kernel["published_generation"] is None,
            "FALSE_OPERATIONAL_PROMOTION",
        )

        window = durable.seal({
            "assessment_index": index,
            "event": event,
            "previous_window_sha256": previous,
            "replacement_risk_model": replacement,
            "evidence_count": len(accumulated),
            "evidence_lower": result["evidence_lower"],
            "evidence_upper": result["evidence_upper"],
            "rf_lower": result["rf_lower"],
            "rf_upper": result["rf_upper"],
            "kernel": kernel,
            "source_kind": "SYNTHETIC_MODEL_ONLY",
            "a6": "ND",
            "confirmed_rf": None,
            "operational_a9_published": False,
        })

        windows.append(window)
        previous = window["sha256"]

    stop = preview_stop(
        a6_classification="ND",
        accredited=False,
        vm_checked=False,
        operational_dispatch=False,
        source_sha256=previous,
    )

    verify_stop(stop)

    return durable.seal({
        "schema": SCHEMA,
        "protocol": protocol,
        "initial_assessment": initial,
        "events": normalized,
        "windows": windows,
        "window_count": len(windows),
        "last_window_sha256": previous,
        "a8_recommendation": stop["recommendation"],
        "synthetic_only": True,
        "technical_truth_accredited": False,
        "confirmed_rf": None,
        "operational_state_mutated": False,
        "operational_a9_published": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def demo(protocol):

    return build(
        protocol,
        [
            {"kind": kind, "value": value}
            for kind, value in DEMO_EVENTS
        ],
    )


def verify(report):

    evidence.verify_digest(report)

    expected = build(
        report["protocol"],
        report["events"],
    )

    need(
        report == expected,
        "TRAJECTORY_REPLAY_MISMATCH",
    )

    return True
