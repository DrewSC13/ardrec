"""Integrated source-bound analytical review, without operational authority.

Reuses A6, A7, A8 and A1 kernels. Model values are hypothetical.
Archive persistence is not operational A9 publication.
"""

from copy import deepcopy

from ardrec.analytical import check_frozen_compatibility
from ardrec.analytics import model_projection
from ardrec.analytics.exact_preview import canonical, digest
from ardrec.evidence import evidence_revision
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.rules.kernel import evaluate as evaluate_rule
from ardrec.state import Truth, GuardFact
from ardrec.stopping import ordinary_closure

SCHEMA = "ARDREC-R358-INTEGRATED-ANALYTICAL-CYCLE-v1"
SCOPE = "SYNTHETIC_SOURCE_BOUND_REVIEW"
MAX_GENERATIONS = 32
MAX_SOURCE_BYTES = 2 * 1024 * 1024


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def validate_sources(sources, expected_sha256):
    require(
        type(sources) is list
        and 1 <= len(sources) <= MAX_GENERATIONS,
        "GENERATION_DOMAIN_INVALID",
    )

    evidence_revision.fingerprint(expected_sha256)

    raw = canonical(sources)

    require(
        len(raw) <= MAX_SOURCE_BYTES
        and digest(sources) == expected_sha256,
        "TRAJECTORY_SOURCE_PIN_INVALID",
    )

    return deepcopy(sources)


def semantic_projection(report):
    """Exclude revision identifiers and archive generation metadata.

    Equivalent active profiles do not create another convergence sample.
    Different effective conditions remain distinguishable.
    """
    if not report["mathematical_point_available"]:
        return None

    rows = {
        row["revision_id"]: row
        for row in report["source"]["revisions"]
    }

    profiles = []

    for selected in report["active_model_contributions"]:
        revision = rows[selected["revision_id"]]

        profiles.append({
            "condition_id": revision["condition_id"],
            "classification": revision["classification"],
            "dimensions": revision["dimensions"],
            "substitution": revision["substitution"],
        })

    return digest({
        "unit_id": report["source"]["unit_id"],
        "configuration_sha256":
            report["source"]["configuration_sha256"],
        "baseline": report["source"]["baseline"],
        "profiles": sorted(
            profiles,
            key=lambda row: row["condition_id"],
        ),
        "substituted_components":
            report["substituted_components"],
    })


def check_successor(previous, current):
    for field in (
        "scope",
        "unit_id",
        "configuration_sha256",
        "baseline",
    ):
        require(
            canonical(previous[field])
            == canonical(current[field]),
            "FROZEN_CONTEXT_CHANGED:" + field,
        )

    old = previous["revisions"]
    new = current["revisions"]

    require(
        type(old) is list
        and type(new) is list
        and len(new) >= len(old)
        and canonical(new[:len(old)]) == canonical(old),
        "REVISION_HISTORY_REWRITTEN",
    )


def build_guard(report, closure):
    # This mathematical model has explicitly no operational authority.
    env = {
        "model_point": (
            Truth.VERDADERO
            if report["mathematical_point_available"]
            else Truth.ND
        ),
        "closure_gate": Truth(closure["ordinary_gate"]),
        "authority": Truth.FALSO,
    }

    schema = {name: "LOGICO" for name in env}

    rule = {
        "op": "Y",
        "args": [
            {"op": "CAMPO", "nombre": name}
            for name in env
        ],
    }

    result = evaluate_rule(rule, schema, env)

    reference = digest({
        "model_report_sha256": report["sha256"],
        "closure_sha256": closure["sha256"],
        "inputs": {
            name: value.value
            for name, value in env.items()
        },
        "rule": rule,
    })

    fact = GuardFact(
        "synthetic_operational_gate",
        result,
        reference,
    )

    require(
        fact.value is Truth.FALSO,
        "SYNTHETIC_GATE_PROMOTED",
    )

    return {
        "name": fact.name,
        "value": fact.value.value,
        "reference": fact.reference,
        "operationally_accredited": False,
    }


def evaluate(sources, expected_sha256):
    sources = validate_sources(sources, expected_sha256)

    history = []
    generations = []
    reports = []

    previous_source = None
    previous_report = None
    previous_projection = None

    for index, source in enumerate(sources):
        require(
            type(source) is dict,
            "SOURCE_TYPE_INVALID",
        )

        report = evidence_revision.evaluate(source)
        evidence_revision.verify(report)

        if index == 0:
            require(
                source["revisions"] == []
                and source["selections"] == [],
                "INITIAL_REVIEW_MUST_BE_EMPTY",
            )

        else:
            check_successor(previous_source, source)

        native, _, _ = model_projection.build_snapshot(
            report,
            report["sha256"],
            generation=index,
            phase="PENDIENTE",
        )

        projection = native[0]

        if previous_projection is not None:
            check_frozen_compatibility(
                previous_projection,
                projection,
            )

        semantic_pin = semantic_projection(report)
        risk = report["analysis"]["recalibrated_risk"]

        reset_reasons = []

        if previous_report is not None:
            before = previous_report[
                "mathematical_point_available"
            ]
            after = report["mathematical_point_available"]

            if before and not after:
                reset_reasons.append("MODEL_INDETERMINATE")

            if not before and after:
                reset_reasons.append("MODEL_POINT_RECOVERED")

            if (
                canonical(previous_source["selections"])
                != canonical(source["selections"])
            ):
                reset_reasons.append("MODEL_SELECTION_CHANGED")

        event = {
            "event_id": "R358-" + str(index),
            "projection_sha256": semantic_pin,
            "risk": risk,
            "reset": bool(reset_reasons),
        }

        history.append(event)

        # Technical evidence and operational facts remain unknown.
        facts = {
            name: Truth.ND.value
            for name in ordinary_closure.FACTS
        }

        closure = ordinary_closure.evaluate(
            facts=facts,
            history=history,
            executions=None,
            budget=None,
            phase="PENDIENTE",
        )

        ordinary_closure.verify(closure)

        guard = build_guard(report, closure)

        require(
            closure["candidate_transition"] is None
            and closure["applied_transition"] is None,
            "CLOSURE_AUTHORITY_PROMOTED",
        )

        generations.append({
            "generation": index,
            "model_report_sha256": report["sha256"],
            "semantic_projection_sha256": semantic_pin,
            "analysis": report["analysis"],
            "pending": report["pending"],
            "reset_reasons": reset_reasons,
            "window": closure["window"],
            "ordinary_criteria": closure["criteria"],
            "ordinary_gate": closure["ordinary_gate"],
            "closure_candidate": None,
            "guard": guard,
            "a6": "ND",
            "confirmed_rf": None,
            "applied_transition": None,
        })

        reports.append(report)
        previous_source = source
        previous_report = report
        previous_projection = projection

    result = {
        "schema": SCHEMA,
        "scope": SCOPE,
        "source_sha256": expected_sha256,
        "unit_id": sources[0]["unit_id"],
        "configuration_sha256":
            sources[0]["configuration_sha256"],
        "generation_count": len(generations),
        "generations": generations,
        "history": history,
        "last_model_report_sha256": reports[-1]["sha256"],
        "operational_authority": False,
        "technical_truth_accredited": False,
        "physical_attempts": 0,
        "published_generation": None,
        "confirmed_rf": None,
        "experimental_admitted": 0,
        "p8": "NO-GO",
    }

    result["sha256"] = digest(result)

    return result


def verify(report, sources, expected_sha256):
    expected = evaluate(sources, expected_sha256)

    require(
        canonical(report) == canonical(expected),
        "INTEGRATED_REPLAY_MISMATCH",
    )

    return True


def verify_archive(
    archive_path,
    receipt,
    sources,
    expected_sha256,
    expected_receipt_sha256,
):
    require(
        type(receipt) is dict
        and set(receipt) == {
            "schema", "trajectory_sha256", "snapshot_sha256",
            "operational_publication", "sha256",
        },
        "ARCHIVE_RECEIPT_SCHEMA",
    )

    body = {
        key: value for key, value in receipt.items()
        if key != "sha256"
    }

    require(
        receipt["schema"] == SCHEMA + "-archive"
        and receipt["sha256"] == expected_receipt_sha256
        and digest(body) == expected_receipt_sha256
        and receipt["operational_publication"] is False,
        "ARCHIVE_RECEIPT_PIN",
    )

    trajectory = evaluate(sources, expected_sha256)

    require(
        receipt["trajectory_sha256"] == trajectory["sha256"]
        and type(receipt["snapshot_sha256"]) is list
        and len(receipt["snapshot_sha256"]) == len(sources)
        and len(set(receipt["snapshot_sha256"])) == len(sources),
        "ARCHIVE_TRAJECTORY_BINDING",
    )

    with AnalyticalArchive(archive_path) as archive:
        for index, (source, pin) in enumerate(
            zip(sources, receipt["snapshot_sha256"])
        ):
            model = evidence_revision.evaluate(source)
            recovered = archive.load(pin)

            require(
                recovered.snapshot_sha256 == pin,
                "ARCHIVE_SNAPSHOT_IDENTITY",
            )

            model_projection.verify_recovered(
                recovered,
                model,
                model["sha256"],
                generation=index,
                phase="PENDIENTE",
            )

    return True


def persist(archive_path, sources, expected_sha256):
    # Validate the complete trajectory before opening storage.
    sources = validate_sources(sources, expected_sha256)
    trajectory = evaluate(sources, expected_sha256)

    pins = []

    with AnalyticalArchive(
        archive_path,
        create=True,
    ) as archive:

        for index, source in enumerate(sources):
            report = evidence_revision.evaluate(source)

            pin = model_projection.store_review(
                archive,
                report,
                report["sha256"],
                generation=index,
                phase="PENDIENTE",
            )

            pins.append(pin)

    receipt = {
        "schema": SCHEMA + "-archive",
        "trajectory_sha256": trajectory["sha256"],
        "snapshot_sha256": pins,
        "operational_publication": False,
    }

    receipt["sha256"] = digest(receipt)

    verify_archive(
        archive_path,
        receipt,
        sources,
        expected_sha256,
        receipt["sha256"],
    )

    return receipt
