"""Source-bound mathematical projections and native archive.

This module accepts R279 synthetic mathematical sources only.
It cannot confer operational authority or publish an A9 generation.
"""

from fractions import Fraction

from ardrec.analytical import (
    AnalyticalProjection,
    AnalysisValues,
    FrozenValues,
    ObjectReference,
    ANALYSIS_FIELDS,
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

from ardrec.evidence import evidence_revision as revisions

from ardrec.persistence.analytical_archive import digest

from ardrec.state import ServicePhase


SCHEMA = "ARDREC-R280-SOURCE-BOUND-MODEL-v1"

RECORD_ID = "R280-MATHEMATICAL-MODEL"

EXECUTION_ID = "R280-OFFLINE-REVIEW"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify_source(report, expected_report_sha256):

    revisions.fingerprint(expected_report_sha256)

    need(
        type(report) is dict
        and report.get("sha256") == expected_report_sha256
        and report.get("schema") == revisions.SCHEMA
        and report.get("scope") == revisions.SCOPE,
        "MODEL_SOURCE_IDENTITY_INVALID",
    )

    need(
        revisions.verify(report),
        "MODEL_SOURCE_REPLAY_INVALID",
    )

    need(
        report["technical_truth_accredited"] is False
        and report["operational_authority"] is False
        and report["confirmed_rf"] is None
        and report["published_generation"] is None
        and report["applied_transition"] is None
        and report["a6"] == "ND"
        and report["formal_pilot_admitted"] == 0
        and report["experimental_admitted"] == 0
        and report["p8"] == "NO-GO",
        "MODEL_AUTHORITY_BOUNDARY_INVALID",
    )

    return True


def magnitude(value):

    if value is None:
        return ND("MODEL_MAGNITUDE_UNDETERMINED")

    return rational(value)


def build_snapshot(
    report,
    expected_report_sha256,
    *,
    generation=0,
    phase="PENDIENTE",
):

    verify_source(report, expected_report_sha256)

    need(
        type(generation) is int
        and 0 <= generation < 2**63,
        "MODEL_GENERATION_INVALID",
    )

    # Synthetic phase labels; no native transition is applied.
    need(
        phase in ("PREPARADO", "PENDIENTE"),
        "MODEL_PHASE_INVALID",
    )

    source = report["source"]

    uid = source["unit_id"]

    ctx = {
        "record_id": RECORD_ID,
        "execution_id": EXECUTION_ID,
        "configuration_sha256":
            source["configuration_sha256"],
        "generation_index": generation,
    }

    payloads = {
        "characterization": {
            "scope": SCHEMA,
            "baseline": source["baseline"],
            "frozen": report["frozen"],
        },
        "evidence_repository": {
            "scope": SCHEMA,
            "source_report_sha256": expected_report_sha256,
            "revision_report": report,
            "operationally_accredited": False,
        },
        "execution_counters": {
            "scope": SCHEMA,
            "physical_attempts": 0,
            "operational_attempts": 0,
        },
        "objective_status": {
            "scope": SCHEMA,
            "operational_objective_confirmed": False,
        },
        "history": {
            "scope": SCHEMA,
            "review_index": generation,
            "source_report_sha256": expected_report_sha256,
            "confirmed_rf": None,
            "operational_publications": 0,
        },
        "convergence_window": {
            "scope": SCHEMA,
            "confirmed_samples": [],
            "convergence_accredited": False,
        },
        "pending_controls": {
            "scope": SCHEMA,
            "unresolved_model_conditions": report["pending"],
            "dispatch_allowed": False,
            "operational_authority": False,
            "p8": "NO-GO",
        },
    }

    need(
        set(payloads) == set(ROLES),
        "REFERENCE_ROLE_SET_INVALID",
    )

    refs = {}
    objects = {}
    bindings = []

    for role in ROLES:

        reference = uid + ":" + role

        origin = {
            **ctx,
            "generation_index": (
                0
                if role == "characterization"
                else generation
            ),
        }

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

    values = report["analysis"]

    need(
        set(values) == set(ANALYSIS_FIELDS),
        "ANALYTICAL_VALUE_SET_INVALID",
    )

    priority = (
        None
        if phase == "PREPARADO"
        else magnitude(values["priority"])
    )

    projection = AnalyticalProjection(
        **ctx,
        service_scenario_id=uid,
        operational_state=ServicePhase(phase),
        frozen=FrozenValues(
            initial_risk=rational(
                report["frozen"]["initial_risk"]
            ),
            normalized_criticality=rational(
                report["frozen"]["normalized_criticality"]
            ),
            characterization=refs["characterization"],
        ),
        analysis=AnalysisValues(
            accumulated_evidence=magnitude(
                values["accumulated_evidence"]
            ),
            substituted_baseline=magnitude(
                values["substituted_baseline"]
            ),
            upper_bound=magnitude(
                values["upper_bound"]
            ),
            lower_adjustment_bound=magnitude(
                values["lower_adjustment_bound"]
            ),
            recalibrated_risk=magnitude(
                values["recalibrated_risk"]
            ),
            priority=priority,
        ),
        references=tuple(
            refs[role] for role in ROLES[1:]
        ),
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

    projections = (projection,)

    need(
        len(objects) == len(bindings) == 7,
        "MODEL_REFERENCE_COVERAGE_INVALID",
    )

    resolve_references(
        projections,
        manifest,
        expected_manifest_sha256=digest(manifest),
        load_object=objects.__getitem__,
    )

    return projections, manifest, objects


def verify_projection(
    projection,
    report,
    expected_report_sha256,
    *,
    generation=0,
    phase="PENDIENTE",
):

    expected, _, _ = build_snapshot(
        report,
        expected_report_sha256,
        generation=generation,
        phase=phase,
    )

    need(
        projection == expected[0],
        "SOURCE_PROJECTION_SEMANTIC_MISMATCH",
    )

    return True


def verify_recovered(
    recovered,
    report,
    expected_report_sha256,
    *,
    generation=0,
    phase="PENDIENTE",
):

    projections, manifest, objects = build_snapshot(
        report,
        expected_report_sha256,
        generation=generation,
        phase=phase,
    )

    expected = resolve_references(
        projections,
        manifest,
        expected_manifest_sha256=digest(manifest),
        load_object=objects.__getitem__,
    )

    need(
        recovered.projections == projections
        and recovered.references == expected,
        "SOURCE_ARCHIVE_SEMANTIC_MISMATCH",
    )

    return True


def store_review(
    archive,
    report,
    expected_report_sha256,
    *,
    generation=0,
    phase="PENDIENTE",
):

    projections, manifest, objects = build_snapshot(
        report,
        expected_report_sha256,
        generation=generation,
        phase=phase,
    )

    verify_projection(
        projections[0],
        report,
        expected_report_sha256,
        generation=generation,
        phase=phase,
    )

    pin = archive.store(
        projections,
        manifest,
        expected_manifest_sha256=digest(manifest),
        load_object=objects.__getitem__,
    )

    recovered = archive.load(pin)

    need(
        recovered.snapshot_sha256 == pin,
        "SNAPSHOT_PIN_MISMATCH",
    )

    verify_recovered(
        recovered,
        report,
        expected_report_sha256,
        generation=generation,
        phase=phase,
    )

    return pin
