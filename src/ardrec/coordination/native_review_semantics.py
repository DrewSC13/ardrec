"""Semantic gate for native non-operational review snapshots.

Integrity and semantic consistency do not establish technical truth,
authorization, confirmed risk, or operational A9 publication.
"""

from ardrec.analytical import ANALYSIS_FIELDS
from ardrec.analytical_references import (
    ROLES,
    ResolvedReferences,
    canonical,
    decode,
    resolve_references,
)
from ardrec.analytics.exact_preview import rational
from ardrec.contracts import ND
from ardrec.state import ServicePhase
from ardrec.coordination import (
    local_evidence_bridge,
    pilot_controller,
    pilot_observation,
)

import hashlib


class ReviewSemanticError(ValueError):
    """Fail-closed rejection of inconsistent native review content."""


def require(condition, reason):
    if not condition:
        raise ReviewSemanticError(reason)


def equal(actual, expected, reason):
    # Canonical comparison distinguishes false from 0.
    require(canonical(actual) == canonical(expected), reason)


def index_rows(rows):
    require(type(rows) is list, "ROWS_TYPE")

    result = {}

    for row in rows:
        require(type(row) is dict, "ROW_TYPE")

        uid = row["unit_id"]

        require(uid not in result, "DUPLICATE_UNIT")

        result[uid] = row

    require(
        set(result) == pilot_controller.UNITS,
        "UNIT_SCOPE",
    )

    return result


def is_nd(value, reason):
    return type(value) is ND and value.reason_code == reason


def check_projection(projection, state, generation):
    require(
        projection.record_id == state.confirmed.record_id
        and projection.execution_id == state.execution_id
        and projection.configuration_sha256
            == state.confirmed.configuration_sha256
        and projection.generation_index == generation
        and projection.operational_state is ServicePhase.PREPARADO,
        "PROJECTION_CONTEXT",
    )

    require(
        is_nd(
            projection.frozen.initial_risk,
            "BASELINE_NOT_CLOSED",
        )
        and is_nd(
            projection.frozen.normalized_criticality,
            "BASELINE_NOT_CLOSED",
        ),
        "BASELINE_PROMOTION",
    )

    values = projection.analysis

    for field in ANALYSIS_FIELDS:
        value = getattr(values, field)

        if field == "priority":
            require(value is None, "PRIORITY_PROMOTION")

        elif field in (
            "substituted_baseline",
            "lower_adjustment_bound",
        ):
            require(
                is_nd(value, "BASELINE_NOT_CLOSED"),
                "BASELINE_MAGNITUDE_PROMOTION",
            )

        else:
            require(
                is_nd(value, "EVIDENCE_NOT_ACCREDITED"),
                "ANALYTICAL_MAGNITUDE_PROMOTION",
            )


def expected_payloads(unit, row, review, observation, generation):
    uid = unit["unit_id"]

    observed = (
        generation == 1
        and uid.endswith("-01")
    )

    require(
        unit["native_state"] == "PREPARADO"
        and unit["baseline_closed"] is False
        and unit["physical_dispatch_allowed"] is False
        and unit["a6"] == "ND"
        and unit["confirmed_rf"] is None
        and unit["a9"] == "NOT_PUBLISHED",
        "SOURCE_UNIT_PROMOTION",
    )

    supports = unit["required_supports"]

    require(
        type(supports) is list
        and len(supports) == 4
        and all(type(x) is str for x in supports)
        and len(set(supports)) == len(supports),
        "SOURCE_SUPPORT_SCOPE",
    )

    r0 = rational(unit["initial_risk_candidate"])
    cn = rational(unit["normalized_criticality"])

    interval = [
        rational(x)
        for x in unit["hypothetical_rf_interval"]
    ]

    require(
        0 <= r0 <= 1
        and 0 <= cn <= 1
        and len(interval) == 2
        and 0 <= interval[0] <= interval[1] <= 1,
        "SOURCE_MAGNITUDE_DOMAIN",
    )

    if row is None:
        require(generation == 0, "MISSING_OBSERVATION")

        i3 = None
        i6 = None

        i7 = [
            {
                "support": name,
                "status": "ND_NOT_OBSERVED",
                "operationally_accredited": False,
            }
            for name in supports
        ]

    else:
        require(
            row["unit_id"] == uid
            and row["protocol"] == unit["protocol"]
            and row["profile"] == unit["profile"]
            and row["family_id"] == unit["family_id"]
            and row["native_phase"] == "PREPARADO"
            and row["initial_risk"] == str(r0)
            and row["hypothetical_rf_interval"]
                == unit["hypothetical_rf_interval"]
            and row["a6"] == "ND"
            and row["confirmed_rf"] is None
            and row["a9"] == "NOT_PUBLISHED"
            and row["formal_pilot_admitted"] is False
            and row["experimental_admitted"] is False
            and row["a8"]["recommendation"] == unit["a8"]
            and row["a8"]["applied_transition"] is None,
            "OBSERVATION_SCOPE",
        )

        i3, i6, i7 = row["i3"], row["i6"], row["i7"]

        require(
            (i3 is not None) == observed
            and (i6 is not None) == observed,
            "OBSERVATION_PRESENCE",
        )

        require(
            type(i7) is list
            and len(i7) == len(supports)
            and {item["support"] for item in i7}
                == set(supports)
            and all(
                item["operationally_accredited"] is False
                for item in i7
            ),
            "EVIDENCE_AUTHORITY_PROMOTION",
        )

        if observed:
            require(
                i3["unit_id"] == uid
                and i3["instance_id"] == unit["instance_id"]
                and i3["plan_sha256"] == unit["plan_sha256"]
                and type(i3["read_bytes"]) is int
                and i3["read_bytes"] == 35
                and type(i6["client_invocations"]) is int
                and i6["client_invocations"] == 1
                and i6["operational_attempt_admitted"] is False,
                "OBSERVATION_IDENTITY_OR_COUNTER",
            )

    return {
        "characterization": {
            "source_controller_sha256": review["sha256"],
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
            "i3": i3,
            "i7": i7,
            "confirmed_evidence_count": 0,
            "source_observation_sha256":
                observation["sha256"] if observation else None,
        },

        "execution_counters": {
            "development_observations": int(observed),
            "operational_attempts": 0,
            "i6": i6,
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
            "hypothetical_rf_lower": str(interval[0]),
            "hypothetical_rf_upper": str(interval[1]),
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


def verify_review_semantics(
    projections,
    resolved,
    review,
    observation,
    generation,
):
    """Re-derive exact review payloads from the supplied source records."""

    require(
        type(generation) is int and generation in (0, 1),
        "GENERATION_INVALID",
    )

    require(
        (generation == 0 and observation is None)
        or (generation == 1 and type(observation) is dict),
        "GENERATION_OBSERVATION_MISMATCH",
    )

    require(
        type(resolved) is ResolvedReferences,
        "RESOLUTION_REQUIRED",
    )

    state = pilot_controller.recover_state(review)

    source_rows = index_rows(review["units"])

    observed_rows = {}

    if observation is not None:
        require(
            local_evidence_bridge.verify_digest(observation)
            and observation["schema"] == pilot_observation.SCHEMA
            and observation["controller_sha256"] == review["sha256"]
            and observation["observations_verified"] == 3
            and observation["operational_supports_accredited"] == 0
            and observation["confirmed_rf_count"] == 0
            and observation["operational_a9_publications"] == 0
            and observation["formal_pilot_admitted"] == 0
            and observation["experimental_admitted"] == 0
            and observation["p8"] == "NO-GO",
            "OBSERVATION_SOURCE_CONTRACT",
        )

        observed_rows = index_rows(observation["units"])

    # Re-run native structural resolution. A caller cannot
    # obtain acceptance by merely constructing a dataclass.
    objects = {
        hashlib.sha256(raw).hexdigest(): raw
        for raw in resolved.object_bytes
    }

    require(
        len(objects) == len(resolved.object_bytes),
        "DUPLICATE_OBJECT_BYTES",
    )

    verified = resolve_references(
        projections,
        resolved.manifest_bytes,
        expected_manifest_sha256=hashlib.sha256(
            resolved.manifest_bytes
        ).hexdigest(),
        load_object=objects.__getitem__,
    )

    require(
        verified == resolved,
        "RESOLVED_CONTENT_MISMATCH",
    )

    require(
        len(projections) == len(source_rows)
        and {p.service_scenario_id for p in projections}
            == set(source_rows),
        "PROJECTION_SCOPE",
    )

    payload_index = {}

    for raw in verified.object_bytes:
        obj = decode(raw)

        key = (obj["service_scenario_id"], obj["role"])

        require(key not in payload_index, "DUPLICATE_ROLE")

        payload_index[key] = obj

    require(
        set(payload_index) == {
            (uid, role)
            for uid in source_rows
            for role in ROLES
        },
        "SEMANTIC_ROLE_SCOPE",
    )

    for projection in projections:
        check_projection(projection, state, generation)

        uid = projection.service_scenario_id

        expected = expected_payloads(
            source_rows[uid],
            observed_rows.get(uid),
            review,
            observation,
            generation,
        )

        for role in ROLES:
            obj = payload_index[(uid, role)]

            expected_generation = (
                0 if role == "characterization"
                else generation
            )

            require(
                obj["context"]["generation_index"]
                    == expected_generation,
                "STALE_OR_FUTURE_ROLE:" + role,
            )

            equal(
                obj["payload"],
                expected[role],
                "SEMANTIC_MISMATCH:" + uid + ":" + role,
            )
