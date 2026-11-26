"""R184: resumen pareado exploratorio; sin autoridad experimental."""
from __future__ import annotations

from decimal import Context, Decimal, ROUND_HALF_EVEN, localcontext
from fractions import Fraction
from statistics import median

from ardrec.experiments import r148_paired_register as r148


def normalized(value):
    if type(value) is str and '/' in value:
        return r148._measurement(value)
    number = Decimal(value)

    r148.need(
        number.is_finite()
        and 0 <= number <= 1
        and -48 <= number.as_tuple().exponent <= 0,
        "NORMALIZED_DECIMAL_REQUIRED",
    )

    return number


def exact(value):
    if value is None:
        return None

    value = Fraction(value)

    return f"{value.numerator}/{value.denominator}"


def analyze(protocol, registry, catalog):
    """Complementa R148 sin modificar su contrato historico."""

    audit = r148.validate(
        protocol, registry, catalog
    )

    selected = [
        row for row in registry["slots"]
        if row["status"] == "RECORDED_UNVERIFIED"
    ]

    if selected:

        scale = registry["common_scale"]

        r148.need(
            normalized(scale["lower"]) == 0
            and normalized(scale["upper"]) == 1,
            "THESIS_COMMON_SCALE_REQUIRED",
        )

    rows = []

    with localcontext(Context(prec=128, rounding=ROUND_HALF_EVEN)):

        for slot in selected:

            static, ardrec, reference = (
                Fraction(normalized(slot[key]))
                for key in r148.VALUES
            )

            error_static = abs(static - reference)
            error_ardrec = abs(ardrec - reference)
            difference = error_static - error_ardrec

            rows.append({
                "slot_id": slot["slot_id"],
                "protocol": slot["protocol"],
                "static_absolute_error": error_static,
                "ardrec_absolute_error": error_ardrec,
                "difference": difference,
            })

        native = r148.analyze(
            protocol, registry, catalog
        )

        differences = [
            row["difference"] for row in rows
        ]

        test = native["primary_comparison"]

        r148.need(
            test["n_pairs"] == len(rows),
            "PAIRED_COUNT_MISMATCH",
        )

        count = len(rows)

        if count:

            mae_static = sum(
                (
                    Fraction(row["static_absolute_error"])
                    for row in rows
                ),
                Fraction(0),
            ) / count

            mae_ardrec = sum(
                (
                    Fraction(row["ardrec_absolute_error"])
                    for row in rows
                ),
                Fraction(0),
            ) / count

            mean_difference = mae_static - mae_ardrec

            median_difference = median(
                [Fraction(value) for value in differences]
            )

        else:

            mae_static = None
            mae_ardrec = None
            mean_difference = None
            median_difference = None

        total_rank = test["w_total_twice"]
        positive_rank = test["w_plus_twice"]

        effect = (
            Fraction(
                2 * positive_rank - total_rank,
                total_rank,
            )
            if total_rank else None
        )

        result = {
            "schema": "ARDREC-R184-PAIRED-SUMMARY-v1",
            "scope": "EXPLORATORY_UNVERIFIED",
            "representation": "EXACT_RATIONAL",
            "planned": audit["planned"],
            "pairs": count,
            "nonzero_pairs": test["n_nonzero"],
            "zero_pairs": test["n_zero"],
            "unassigned": audit["statuses"][
                "PLANNED_UNASSIGNED"
            ],
            "excluded_unverified": audit["statuses"][
                "EXCLUDED_UNVERIFIED"
            ],
            "mae_static": exact(mae_static),
            "mae_ardrec": exact(mae_ardrec),
            "mean_difference": exact(mean_difference),
            "median_difference": exact(median_difference),
            "favor_ardrec": sum(d > 0 for d in differences),
            "favor_static": sum(d < 0 for d in differences),
            "equal_errors": sum(d == 0 for d in differences),
            "rank_biserial": exact(effect),
            "effect_direction": "POSITIVE_FAVORS_ARDREC",
            "wilcoxon": test,
            "paired_errors": [
                {
                    "slot_id": row["slot_id"],
                    "protocol": row["protocol"],
                    "static_absolute_error":
                        exact(row["static_absolute_error"]),
                    "ardrec_absolute_error":
                        exact(row["ardrec_absolute_error"]),
                    "difference":
                        exact(row["difference"]),
                }
                for row in rows
            ],
            "independent_reference_attested": False,
            "confirmatory_analysis_authorized": False,
            "p7": "DRAFT_NOT_FROZEN",
            "p8": "NO-GO",
        }

    result["sha256"] = r148.digest(
        r148.canonical(result)
    )

    return native, result
