"""Native analytical review snapshots for the six pilot units.

Candidate values and original development observations remain
distinct from confirmed operational magnitudes.

No DurableStore creation, physical dispatch or A9 publication.
"""

from fractions import Fraction
from pathlib import Path
import argparse
import json
import os

from ardrec.analytical import (
    AnalyticalProjection,
    AnalysisValues,
    FrozenValues,
    ObjectReference,
    check_frozen_compatibility,
)

from ardrec.analytical_references import (
    ROLES,
    OBJECT_FORMAT,
    MANIFEST_FORMAT,
    canonical,
    resolve_references,
)

from ardrec.analytics.exact_preview import rational

from ardrec.contracts import ND
from ardrec.coordination.native_review_semantics import verify_review_semantics

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
    pilot_controller,
    pilot_observation,
)

from ardrec.persistence.analytical_archive import (
    AnalyticalArchive,
    digest,
)

from ardrec.state import ServicePhase


SCHEMA = "ARDREC-R276-NATIVE-PILOT-ARCHIVE-v1"

UNITS = pilot_controller.UNITS

CONTROLS = {
    "PILOT-SSH-01",
    "PILOT-FTP-01",
    "PILOT-SMB-01",
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def indexed(rows):

    need(
        type(rows) is list
        and len(rows) == 6
        and {row["unit_id"] for row in rows} == UNITS,
        "UNIT_SET_INVALID",
    )

    return {
        row["unit_id"]: row for row in rows
    }


def build_snapshot(review, observation, generation):
    """Pure review projection. Input provenance is checked by replay."""

    need(
        type(generation) is int
        and generation in (0, 1),
        "REVIEW_GENERATION_INVALID",
    )

    need(
        (generation == 0 and observation is None)
        or (generation == 1 and type(observation) is dict),
        "GENERATION_OBSERVATION_MISMATCH",
    )

    state = pilot_controller.recover_state(review)

    pilot_controller.verify_state(state)

    source_rows = indexed(review["units"])

    observed_rows = {}

    if observation is not None:

        need(
            evidence.verify_digest(observation)
            and observation["schema"] ==
                pilot_observation.SCHEMA
            and observation["controller_sha256"] ==
                review["sha256"]
            and observation["observations_verified"] == 3
            and observation["operational_supports_accredited"] == 0
            and observation["confirmed_rf_count"] == 0
            and observation["operational_a9_publications"] == 0
            and observation["formal_pilot_admitted"] == 0
            and observation["experimental_admitted"] == 0
            and observation["p8"] == "NO-GO",
            "OBSERVATION_SCOPE_INVALID",
        )

        observed_rows = indexed(
            observation["units"]
        )

    ctx = {
        "record_id": state.confirmed.record_id,
        "execution_id": state.execution_id,
        "configuration_sha256":
            state.confirmed.configuration_sha256,
        "generation_index": generation,
    }

    projections = []
    bindings = []
    objects = {}

    for uid in sorted(source_rows):

        unit = source_rows[uid]

        need(
            unit["native_state"] == "PREPARADO"
            and unit["baseline_closed"] is False
            and unit["physical_dispatch_allowed"] is False
            and unit["a6"] == "ND"
            and unit["confirmed_rf"] is None
            and unit["a9"] == "NOT_PUBLISHED",
            "NATIVE_UNIT_SCOPE_INVALID",
        )

        r0 = rational(
            unit["initial_risk_candidate"]
        )

        cn = rational(
            unit["normalized_criticality"]
        )

        interval = [
            rational(value)
            for value in unit[
                "hypothetical_rf_interval"
            ]
        ]

        need(
            len(interval) == 2
            and interval[0] <= interval[1],
            "RISK_INTERVAL_INVALID",
        )

        row = observed_rows.get(uid)

        observed = (
            generation == 1 and uid in CONTROLS
        )

        if row is not None:

            need(
                row["protocol"] == unit["protocol"]
                and row["family_id"] == unit["family_id"]
                and row["profile"] == unit["profile"]
                and row["native_phase"] == "PREPARADO"
                and row["initial_risk"] == str(r0)
                and row["hypothetical_rf_interval"] ==
                    unit["hypothetical_rf_interval"]
                and row["a6"] == "ND"
                and row["confirmed_rf"] is None
                and row["a9"] == "NOT_PUBLISHED"
                and row["formal_pilot_admitted"] is False
                and row["experimental_admitted"] is False
                and row["a8"]["recommendation"] == unit["a8"]
                and row["a8"]["applied_transition"] is None
                and (row["i3"] is not None) == observed
                and (row["i6"] is not None) == observed,
                "CROSS_SNAPSHOT_UNIT_MISMATCH",
            )

            need(
                len(row["i7"]) == 4
                and {
                    item["support"] for item in row["i7"]
                } == set(unit["required_supports"])
                and all(
                    item["operationally_accredited"] is False
                    for item in row["i7"]
                ),
                "SUPPORT_SCOPE_INVALID",
            )

            if observed:

                need(
                    row["i3"]["unit_id"] == uid
                    and row["i3"]["instance_id"] ==
                        unit["instance_id"]
                    and row["i3"]["plan_sha256"] ==
                        unit["plan_sha256"]
                    and row["i3"]["read_bytes"] == 35
                    and row["i6"]["client_invocations"] == 1
                    and row["i6"][
                        "operational_attempt_admitted"
                    ] is False,
                    "OBSERVATION_IDENTITY_INVALID",
                )

        payloads = {

            "characterization": {
                "source_controller_sha256":
                    review["sha256"],
                "source_preregistration_sha256":
                    review["source_sha256"],
                "instance_id": unit["instance_id"],
                "protocol": unit["protocol"],
                "family_id": unit["family_id"],
                "profile": unit["profile"],
                "plan_sha256": unit["plan_sha256"],
                "initial_risk_candidate": str(r0),
                "criticality_candidate": str(cn),
                "operational_baseline_closed": False,
            },

            "evidence_repository": {
                "a6": "ND",
                "i3": row["i3"] if row else None,
                "i7": row["i7"] if row else [
                    {
                        "support": name,
                        "status": "ND_NOT_OBSERVED",
                        "operationally_accredited": False,
                    }
                    for name in unit["required_supports"]
                ],
                "confirmed_evidence_count": 0,
                "source_observation_sha256": (
                    observation["sha256"]
                    if observation else None
                ),
            },

            "execution_counters": {
                "development_observations": int(observed),
                "operational_attempts": 0,
                "i6": row["i6"] if row else None,
                "automatic_retry": False,
            },

            "objective_status": {
                "technical_objective_accredited": False,
                "selected_for_dispatch": False,
                "status": "ND",
            },

            "history": {
                "review_generation": generation,
                "native_phase": "PREPARADO",
                "confirmed_rf": None,
                "operational_publications": 0,
            },

            "convergence_window": {
                "hypothetical_rf_lower":
                    str(interval[0]),
                "hypothetical_rf_upper":
                    str(interval[1]),
                "confirmed_samples": [],
                "convergence_accredited": False,
            },

            "pending_controls": {
                "a3_authority": "ND",
                "a4_operational_selection": None,
                "a8_recommendation": unit["a8"],
                "blockers": unit["blockers"],
                "dispatch_allowed": False,
            },
        }

        need(
            set(payloads) == set(ROLES),
            "REFERENCE_ROLE_SET_INVALID",
        )

        refs = {}

        for role in ROLES:

            reference = uid + ":" + role

            origin = dict(ctx)

            if role == "characterization":
                origin["generation_index"] = 0

            raw = canonical({
                "format": OBJECT_FORMAT,
                "context": origin,
                "service_scenario_id": uid,
                "role": role,
                "reference": reference,
                "payload": payloads[role],
            })

            pin = digest(raw)

            objects[pin] = raw

            refs[role] = ObjectReference(
                reference, pin
            )

            bindings.append({
                "service_scenario_id": uid,
                "role": role,
                "reference": reference,
                "sha256": pin,
            })

        # Candidate R0 and CN are preserved in the
        # characterization object. They are not promoted
        # to confirmed operational magnitudes.

        baseline_nd = ND("BASELINE_NOT_CLOSED")
        evidence_nd = ND("EVIDENCE_NOT_ACCREDITED")

        projections.append(
            AnalyticalProjection(
                **ctx,
                service_scenario_id=uid,
                operational_state=ServicePhase.PREPARADO,
                frozen=FrozenValues(
                    initial_risk=baseline_nd,
                    normalized_criticality=baseline_nd,
                    characterization=refs["characterization"],
                ),
                analysis=AnalysisValues(
                    accumulated_evidence=evidence_nd,
                    substituted_baseline=baseline_nd,
                    upper_bound=evidence_nd,
                    lower_adjustment_bound=baseline_nd,
                    recalibrated_risk=evidence_nd,
                    priority=None,
                ),
                references=tuple(
                    refs[role] for role in ROLES[1:]
                ),
            )
        )

    manifest = canonical({
        "format": MANIFEST_FORMAT,
        "context": ctx,
        "bindings": sorted(
            bindings,
            key=lambda item: (
                item["service_scenario_id"],
                item["role"],
            ),
        ),
    })

    projections = tuple(projections)

    need(
        len(projections) == 6
        and len(bindings) == 42
        and len(objects) == 42,
        "SNAPSHOT_COVERAGE_INVALID",
    )

    resolved = resolve_references(
        projections,
        manifest,
        expected_manifest_sha256=digest(manifest),
        load_object=objects.__getitem__,
    )

    verify_review_semantics(
        projections, resolved, review, observation, generation
    )

    return projections, manifest, objects


def verify_readback(archive, pin, snapshot):

    projections, manifest, objects = snapshot

    recovered = archive.load(pin)

    expected = resolve_references(
        projections,
        manifest,
        expected_manifest_sha256=digest(manifest),
        load_object=objects.__getitem__,
    )

    need(
        recovered.snapshot_sha256 == pin
        and recovered.projections == projections
        and recovered.references == expected,
        "NATIVE_ARCHIVE_READBACK_INVALID",
    )

    return recovered


def persist_review_pair(archive_path, review, observation):

    first = build_snapshot(review, None, 0)

    second = build_snapshot(
        review, observation, 1
    )

    for previous, current in zip(
        first[0], second[0]
    ):
        check_frozen_compatibility(
            previous, current
        )

    pins = []

    with AnalyticalArchive(
        archive_path, create=True
    ) as archive:

        for snapshot in (first, second):

            projections, manifest, objects = snapshot

            pin = archive.store(
                projections,
                manifest,
                expected_manifest_sha256=digest(manifest),
                load_object=objects.__getitem__,
            )

            verify_readback(
                archive, pin, snapshot
            )

            # Idempotent storage of exactly the same
            # snapshot; never create a new revision.

            repeated = archive.store(
                projections,
                manifest,
                expected_manifest_sha256=digest(manifest),
                load_object=objects.__getitem__,
            )

            need(
                repeated == pin,
                "ARCHIVE_IDEMPOTENCE_INVALID",
            )

            pins.append(pin)

    need(
        len(set(pins)) == 2,
        "REVIEW_SNAPSHOT_IDENTITY_COLLISION",
    )

    # Reopen independently after releasing the writer.

    with AnalyticalArchive(archive_path) as archive:

        for generation, (pin, snapshot) in enumerate(zip(
            pins, (first, second)
        )):
            recovered = verify_readback(
                archive, pin, snapshot
            )

            verify_review_semantics(
                recovered.projections,
                recovered.references,
                review,
                observation if generation == 1 else None,
                generation,
            )

    return durable.seal({
        "schema": SCHEMA,
        "scope": "NON_OPERATIONAL_ANALYTICAL_REVIEW",
        "source_controller_sha256": review["sha256"],
        "source_observation_sha256": observation["sha256"],
        "snapshot_sha256": pins,
        "review_snapshots": 2,
        "native_projections_verified": 12,
        "native_reference_bindings_verified": 84,
        "frozen_characterizations_preserved": 6,
        "development_observations_archived": 3,
        "archive_reopen_verified": True,
        "archive_idempotence_verified": True,
        "confirmed_rf_count": 0,
        "operational_a9_publications": 0,
        "operational_dispatch": False,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def main():

    parser = argparse.ArgumentParser(
        description="Archivo analitico nativo del piloto"
    )

    parser.add_argument(
        "--preregistration", required=True, type=Path
    )

    parser.add_argument(
        "--execution", required=True, type=Path
    )

    parser.add_argument(
        "--recovery", required=True, type=Path
    )

    parser.add_argument(
        "--preregistration-sha256", required=True
    )

    parser.add_argument(
        "--recovery-sha256", required=True
    )

    parser.add_argument(
        "--observation-sha256", required=True
    )

    parser.add_argument(
        "--output", required=True, type=Path
    )

    args = parser.parse_args()

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    review = pilot_controller.evaluate(
        args.preregistration,
        args.preregistration_sha256,
    )

    observation = pilot_observation.evaluate(
        args.recovery,
        args.execution,
        args.preregistration,
        args.recovery_sha256,
    )

    need(
        observation["sha256"] ==
            args.observation_sha256,
        "OBSERVATION_REPLAY_PIN_MISMATCH",
    )

    report = persist_review_pair(
        args.output / "analytical-archive",
        review,
        observation,
    )

    destination = (
        args.output / "06-archive-report.json"
    )

    durable.write_once(destination, report)

    need(
        durable.load(destination) == report,
        "REPORT_READBACK_INVALID",
    )

    print("NATIVE_SOURCE_REPLAY=PASS")
    print("REVIEW_SNAPSHOTS=2/2")
    print("NATIVE_PROJECTIONS=12/12")
    print("NATIVE_REFERENCE_BINDINGS=84/84")
    print("FROZEN_CHARACTERIZATIONS=6/6")
    print("DEVELOPMENT_OBSERVATIONS_ARCHIVED=3/3")
    print("ARCHIVE_IDEMPOTENCE=PASS")
    print("ARCHIVE_REOPEN=PASS")
    print("CONFIRMED_RF_COUNT=0")
    print("OPERATIONAL_A9_PUBLICATIONS=0")
    print("REPORT_SHA256=" + report["sha256"])
    print("REPORT_READBACK=PASS")


if __name__ == "__main__":
    main()
