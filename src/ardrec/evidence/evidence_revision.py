"""A6-A7 evidence revision consolidation.

Synthetic mathematical model only. Selections represent
explicit model decisions, never authenticated resolutions.

No operational evidence admission, execution or publication.
"""

from copy import deepcopy
from fractions import Fraction
import re

from ardrec.analytics.exact_preview import (
    canonical,
    digest,
    preview_bounds,
    rational,
    verify_bounds,
)

from ardrec.experiments.initial_assessment import compute

from ardrec.experiments.parameter_sensitivity import (
    contribution,
)


SCHEMA = "ARDREC-R279-EVIDENCE-REVISION-v1"

SCOPE = "SYNTHETIC_MATHEMATICAL_ONLY"

VALID = {
    "POSITIVO_VALIDO",
    "NEGATIVO_VALIDO",
}

OTHER = {
    "INCONCLUSO",
    "INCIDENCIA",
    "INVALIDO",
    "NO_ADMITIDO",
}

SOURCE_FIELDS = {
    "scope",
    "unit_id",
    "configuration_sha256",
    "baseline",
    "revisions",
    "selections",
}

REVISION_FIELDS = {
    "unit_id",
    "configuration_sha256",
    "condition_id",
    "revision_id",
    "previous_revision_id",
    "classification",
    "dimensions",
    "substitution",
}

COMPONENTS = (
    "probability",
    "impact",
)


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def identifier(value):

    need(
        type(value) is str
        and re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}",
            value,
        ) is not None,
        "IDENTIFIER_INVALID",
    )


def fingerprint(value):

    need(
        type(value) is str
        and re.fullmatch(
            r"[a-f0-9]{64}", value
        ) is not None,
        "FINGERPRINT_INVALID",
    )


def ordinal(value):

    need(
        type(value) is int and 1 <= value <= 5,
        "ORDINAL_INVALID",
    )

    return value


def normalize_baseline(baseline):

    need(
        type(baseline) is dict
        and set(baseline) == {
            "exposure",
            "probability",
            "impact",
            "context",
        },
        "BASELINE_SCHEMA_INVALID",
    )

    for name in (
        "exposure",
        "probability",
        "impact",
    ):
        ordinal(baseline[name])

    need(
        type(baseline["context"]) is list
        and len(baseline["context"]) == 3,
        "CONTEXT_INVALID",
    )

    for value in baseline["context"]:
        ordinal(value)

    return compute(
        baseline["exposure"],
        baseline["probability"],
        baseline["impact"],
        baseline["context"],
    )


def normalize_revision(row, source):

    need(
        type(row) is dict
        and set(row) == REVISION_FIELDS,
        "REVISION_SCHEMA_INVALID",
    )

    need(
        row["unit_id"] == source["unit_id"]
        and row["configuration_sha256"] ==
            source["configuration_sha256"],
        "CROSS_CONTEXT_REVISION",
    )

    identifier(row["condition_id"])
    identifier(row["revision_id"])

    previous = row["previous_revision_id"]

    if previous is not None:
        identifier(previous)

    classification = row["classification"]

    need(
        type(classification) is str
        and classification in VALID | OTHER,
        "CLASSIFICATION_INVALID",
    )

    replacement = row["substitution"]

    need(
        type(replacement) is dict
        and set(replacement) == set(COMPONENTS),
        "SUBSTITUTION_SCHEMA_INVALID",
    )

    for component in COMPONENTS:

        value = replacement[component]

        if value is not None:

            ordinal(value)

            need(
                classification == "NEGATIVO_VALIDO"
                and value <= source["baseline"][component],
                "SUBSTITUTION_NOT_ADMISSIBLE",
            )

    dimensions = row["dimensions"]

    if classification not in VALID:

        need(
            dimensions is None,
            "UNDETERMINED_DIMENSIONS_MUST_BE_NULL",
        )

        return None

    need(
        type(dimensions) is list
        and len(dimensions) == 4
        and all(
            type(value) is int
            and 0 <= value <= 4
            for value in dimensions
        ),
        "EVIDENCE_DIMENSIONS_INVALID",
    )

    a, p, q, f = dimensions

    need(
        q >= 1 and f >= 1,
        "EVIDENCE_SUPPORT_INSUFFICIENT",
    )

    if classification == "NEGATIVO_VALIDO":

        need(
            a == 0 and p == 0,
            "NEGATIVE_CONTRIBUTION_NOT_ZERO",
        )

    else:

        need(
            a + p > 0,
            "POSITIVE_CONTRIBUTION_REQUIRED",
        )

    value = contribution(
        tuple(dimensions),
        ("1/2", "1/2"),
        ("1/2", "1/2"),
    )

    need(
        classification != "NEGATIVO_VALIDO"
        or value == 0,
        "NEGATIVE_CONTRIBUTION_INVALID",
    )

    return value


def semantic_key(row):

    return canonical({
        "classification": row["classification"],
        "dimensions": row["dimensions"],
        "substitution": row["substitution"],
    })


def evaluate(source):

    need(
        type(source) is dict
        and set(source) == SOURCE_FIELDS
        and source["scope"] == SCOPE,
        "SYNTHETIC_SOURCE_REQUIRED",
    )

    source = deepcopy(source)

    identifier(source["unit_id"])
    fingerprint(source["configuration_sha256"])

    baseline = source["baseline"]
    frozen = normalize_baseline(baseline)

    revisions = source["revisions"]
    selections = source["selections"]

    need(
        type(revisions) is list
        and len(revisions) <= 128
        and type(selections) is list
        and len(selections) <= 128,
        "REPOSITORY_DOMAIN_INVALID",
    )

    histories = {}
    revisions_by_id = {}
    contributions = {}

    for row in revisions:

        value = normalize_revision(row, source)

        condition = row["condition_id"]
        revision = row["revision_id"]

        need(
            revision not in revisions_by_id,
            "DUPLICATE_REVISION_ID",
        )

        history = histories.setdefault(condition, [])

        expected = (
            history[-1]["revision_id"]
            if history else None
        )

        need(
            row["previous_revision_id"] == expected,
            "REVISION_CHAIN_INVALID",
        )

        history.append(row)
        revisions_by_id[revision] = row

        if value is not None:
            contributions[revision] = value

    selection_map = {}

    for selection in selections:

        need(
            type(selection) is dict
            and set(selection) == {
                "condition_id",
                "candidate_revisions",
                "selected_revision",
                "justification",
            },
            "SELECTION_SCHEMA_INVALID",
        )

        condition = selection["condition_id"]

        identifier(condition)
        identifier(selection["selected_revision"])

        candidates = selection["candidate_revisions"]
        reason = selection["justification"]

        need(
            type(candidates) is list
            and all(type(v) is str for v in candidates)
            and len(set(candidates)) == len(candidates)
            and type(reason) is str
            and 10 <= len(reason.strip()) <= 2000
            and condition in histories
            and condition not in selection_map,
            "MODEL_SELECTION_INVALID",
        )

        selection_map[condition] = selection

    active = []
    pending = []
    condition_reports = []
    consumed_selections = set()

    duplicates = 0

    for condition, history in sorted(histories.items()):

        valid = [
            row for row in history
            if row["classification"] in VALID
        ]

        signatures = {
            semantic_key(row) for row in valid
        }

        duplicates += len(valid) - len(signatures)

        selection = selection_map.get(condition)
        selected = None

        if not valid:

            pending.append(
                "NO_VALID_REVISION:" + condition
            )

        elif len(signatures) == 1:

            # Equivalent model profiles count once.
            # The newest number does not confer validity.

            selected = valid[0]

        elif selection is None:

            pending.append(
                "REVISION_CONFLICT:" + condition
            )

        else:

            expected = {
                row["revision_id"] for row in valid
            }

            need(
                set(selection["candidate_revisions"]) ==
                    expected
                and selection["selected_revision"] in expected,
                "SELECTION_CONTEXT_MISMATCH",
            )

            selected = revisions_by_id[
                selection["selected_revision"]
            ]

            consumed_selections.add(condition)

        if any(
            row["classification"] in {
                "INCONCLUSO", "INCIDENCIA"
            }
            for row in history
        ):

            pending.append(
                "UNRESOLVED_REVIEW:" + condition
            )

        if selected is not None:
            active.append(selected)

        condition_reports.append({
            "condition_id": condition,
            "revision_count": len(history),
            "valid_candidates": [
                row["revision_id"] for row in valid
            ],
            "distinct_valid_profiles": len(signatures),
            "selected_model_revision": (
                selected["revision_id"]
                if selected is not None else None
            ),
            "resolution_authenticated": False,
        })

    need(
        consumed_selections == set(selection_map),
        "UNCONSUMED_MODEL_SELECTION",
    )

    selected_contributions = [
        contributions[row["revision_id"]]
        for row in active
    ]

    known_max = max([
        Fraction(0),
        *selected_contributions,
    ])

    substituted = {}

    for component in COMPONENTS:

        values = {
            row["substitution"][component]
            for row in active
            if row["classification"] == "NEGATIVO_VALIDO"
            and row["substitution"][component] is not None
        }

        if len(values) > 1:

            pending.append(
                "SUBSTITUTION_CONFLICT:" + component
            )

            substituted[component] = None

        else:

            substituted[component] = (
                next(iter(values))
                if values else baseline[component]
            )

    r0 = rational(frozen["initial_risk"])
    cn = rational(frozen["normalized_criticality"])

    analysis = {
        "accumulated_evidence": None,
        "substituted_baseline": None,
        "upper_bound": None,
        "lower_adjustment_bound": None,
        "recalibrated_risk": None,
        "priority": None,
    }

    oracle = None

    if not pending:

        replacement = Fraction(
            baseline["exposure"]
            + substituted["probability"]
            + substituted["impact"]
            - 3,
            12,
        )

        need(
            0 <= replacement <= r0,
            "BASELINE_INVARIANT_INVALID",
        )

        oracle = preview_bounds(
            str(r0),
            str(cn),
            [
                str(value)
                for value in selected_contributions
            ],
            str(replacement),
        )

        verify_bounds(oracle)

        priority = (
            r0 + known_max + cn
        ) / 3

        need(
            0 <= priority <= 1,
            "PRIORITY_INVARIANT_INVALID",
        )

        analysis = {
            "accumulated_evidence":
                oracle["evidence_max"],
            "substituted_baseline":
                oracle["replacement_risk"],
            "upper_bound":
                oracle["upper"],
            "lower_adjustment_bound":
                oracle["lower"],
            "recalibrated_risk":
                oracle["hypothetical_rf"],
            "priority":
                str(priority),
        }

    report = {
        "schema": SCHEMA,
        "scope": SCOPE,
        "source": source,
        "frozen": frozen,
        "conditions": condition_reports,
        "revision_count": len(revisions),
        "equivalent_revision_count": duplicates,
        "active_model_revision_count": len(active),
        "active_model_contributions": [
            {
                "condition_id": row["condition_id"],
                "revision_id": row["revision_id"],
                "contribution": str(
                    contributions[row["revision_id"]]
                ),
            }
            for row in active
        ],
        "known_selected_model_max": str(known_max),
        "substituted_components": {
            "exposure": baseline["exposure"],
            **substituted,
        },
        "pending": sorted(set(pending)),
        "mathematical_point_available": not pending,
        "analysis": analysis,
        "oracle": oracle,
        "a6": "ND",
        "confirmed_rf": None,
        "technical_truth_accredited": False,
        "operational_authority": False,
        "applied_transition": None,
        "published_generation": None,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }

    report["sha256"] = digest(report)

    return report


def verify(report):

    need(
        type(report) is dict
        and "source" in report,
        "REPORT_INVALID",
    )

    expected = evaluate(report["source"])

    need(
        canonical(report) == canonical(expected),
        "REPLAY_MISMATCH",
    )

    return True
