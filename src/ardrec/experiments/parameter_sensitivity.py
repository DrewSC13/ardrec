"""R187: sensibilidad matematica exacta, sin evidencia acreditada."""
from __future__ import annotations

from fractions import Fraction as F
from itertools import combinations
import argparse
import json
import sys

from ardrec.analytics.exact_preview import (
    canonical,
    digest,
    preview_bounds,
    verify_bounds,
    rational,
)


SCHEMA = "ARDREC-R187-PARAMETER-SENSITIVITY-v1"

BASE = {
    "beta_ap": ("1/2", "1/2"),
    "beta_qf": ("1/2", "1/2"),
    "lambda": ("1/3", "1/3", "1/3"),
    "w": ("1/3", "1/3", "1/3"),
}


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def weights(values, count):

    need(
        type(values) is tuple and len(values) == count,
        "WEIGHT_COUNT_INVALID",
    )

    result = tuple(rational(v) for v in values)

    need(
        sum(result) == 1 and all(v > 0 for v in result),
        "POSITIVE_SIMPLEX_REQUIRED",
    )

    return result


def configurations():

    yield "BASE", dict(BASE)

    for group in ("beta_ap", "beta_qf"):

        for index, pair in enumerate((
            ("3/4", "1/4"),
            ("1/4", "3/4"),
        ), 1):

            yield f"{group.upper()}_{index}", {
                **BASE,
                group: pair,
            }

    for group in ("lambda", "w"):

        for index in range(3):

            increased = ["1/4"] * 3
            increased[index] = "1/2"

            decreased = ["5/12"] * 3
            decreased[index] = "1/6"

            yield f"{group.upper()}_{index}_UP", {
                **BASE,
                group: tuple(increased),
            }

            yield f"{group.upper()}_{index}_DOWN", {
                **BASE,
                group: tuple(decreased),
            }


def mathematical_profiles():

    # Valores hipoteticos. No representan hallazgos.
    return (
        {
            "id": "SSH_MATH_01",
            "r0": "1/4",
            "criticality": "1/2",
            "replacement": "1/4",
            "dimensions": ((3, 1, 4, 2), (1, 1, 2, 2)),
        },
        {
            "id": "FTP_MATH_01",
            "r0": "2/3",
            "criticality": "1/4",
            "replacement": "1/2",
            "dimensions": ((2, 1, 3, 2),),
        },
        {
            "id": "SMB_MATH_01",
            "r0": "1/3",
            "criticality": "3/4",
            "replacement": "1/3",
            "dimensions": ((4, 2, 3, 4),),
        },
    )


def contribution(dimensions, beta_ap, beta_qf):

    need(
        type(dimensions) is tuple
        and len(dimensions) == 4
        and all(
            type(v) is int and 0 <= v <= 4
            for v in dimensions
        ),
        "DIMENSIONS_INVALID",
    )

    a, p, q, f = dimensions

    need(q >= 1 and f >= 1, "SUPPORT_DIMENSIONS_INVALID")

    ba, bp = weights(beta_ap, 2)
    bq, bf = weights(beta_qf, 2)

    technical = ba * F(a, 4) + bp * F(p, 4)
    support = bq * F(q, 4) + bf * F(f, 4)

    value = technical * support

    need(
        0 <= value <= min(technical, support) <= 1,
        "CONTRIBUTION_INVARIANT",
    )

    return value


def risk_point(r0, criticality, contributions, replacement, w):

    report = preview_bounds(
        r0,
        criticality,
        [str(value) for value in contributions],
        replacement,
        w,
    )

    verify_bounds(report)

    need(
        report["technical_truth_accredited"] is False
        and report["confirmed_rf"] is None
        and report["published_generation"] is None
        and report["p8_operational"] == "NO-GO",
        "AUTHORITY_BOUNDARY_INVALID",
    )

    return report


def evaluate(profile, config):

    need(set(config) == set(BASE), "CONFIG_SCHEMA_INVALID")

    weights(config["beta_ap"], 2)
    weights(config["beta_qf"], 2)

    lr, le, lc = weights(config["lambda"], 3)
    weights(config["w"], 3)

    r0 = rational(profile["r0"])
    c = rational(profile["criticality"])
    replacement = rational(profile["replacement"])

    need(replacement <= r0, "REPLACEMENT_INVALID")

    contributions = [
        contribution(
            item,
            config["beta_ap"],
            config["beta_qf"],
        )
        for item in profile["dimensions"]
    ]

    evidence = max([F(0), *contributions])

    priority = lr * r0 + le * evidence + lc * c

    risk = risk_point(
        str(r0),
        str(c),
        contributions,
        str(replacement),
        config["w"],
    )

    need(0 <= priority <= 1, "PRIORITY_INVARIANT")

    return {
        "profile": profile["id"],
        "r0": str(r0),
        "criticality": str(c),
        "replacement": str(replacement),
        "contributions": [str(v) for v in contributions],
        "hypothetical_evidence": str(evidence),
        "hypothetical_priority": str(priority),
        "hypothetical_rf": risk["hypothetical_rf"],
        "a7_oracle_sha256": risk["sha256"],
        "a6": "ND",
        "confirmed_rf": None,
    }


def relations(rows):

    values = {
        row["profile"]: F(row["hypothetical_priority"])
        for row in rows
    }

    result = {}

    for first, second in combinations(sorted(values), 2):

        a = values[first]
        b = values[second]

        result[first + "|" + second] = (
            "GREATER" if a > b
            else "LESS" if a < b
            else "TIE"
        )

    return result


def build():

    profiles = mathematical_profiles()

    base_rows = [
        evaluate(profile, BASE)
        for profile in profiles
    ]

    baseline = {
        row["profile"]: row
        for row in base_rows
    }

    base_relations = relations(base_rows)

    results = []

    for name, config in configurations():

        rows = [
            evaluate(profile, config)
            for profile in profiles
        ]

        current_relations = relations(rows)

        for row in rows:

            reference = baseline[row["profile"]]

            for field in (
                "hypothetical_evidence",
                "hypothetical_priority",
                "hypothetical_rf",
            ):

                row["delta_" + field] = str(
                    F(row[field]) - F(reference[field])
                )

        results.append({
            "configuration": name,
            "weights": config,
            "rows": rows,
            "priority_relations": current_relations,
            "changed_priority_relations": sum(
                current_relations[key] != value
                for key, value in base_relations.items()
            ),
        })

    ranges = []

    for profile in profiles:

        identifier = profile["id"]

        observations = [
            row
            for config in results
            for row in config["rows"]
            if row["profile"] == identifier
        ]

        entry = {"profile": identifier}

        for field in (
            "hypothetical_evidence",
            "hypothetical_priority",
            "hypothetical_rf",
        ):

            values = [F(row[field]) for row in observations]

            entry[field] = {
                "minimum": str(min(values)),
                "maximum": str(max(values)),
                "range": str(max(values) - min(values)),
            }

        ranges.append(entry)

    # Comparadores preliminares; no constituyen protocolo P7.
    secondary = []

    for profile in profiles:

        r0 = profile["r0"]
        c = profile["criticality"]
        replacement = profile["replacement"]

        original = baseline[profile["id"]]

        contributions = [
            F(value)
            for value in original["contributions"]
        ]

        no_positive = risk_point(
            r0, c, [], replacement, BASE["w"]
        )

        no_replacement = risk_point(
            r0, c, contributions, r0, BASE["w"]
        )

        no_evidence = risk_point(
            r0, c, [], r0, BASE["w"]
        )

        secondary.append({
            "profile": profile["id"],
            "static_r0": r0,
            "contextual_comparator_proposal":
                str((F(r0) + F(c)) / 2),
            "full_hypothetical_rf":
                original["hypothetical_rf"],
            "without_positive_contributions":
                no_positive["hypothetical_rf"],
            "without_negative_replacement":
                no_replacement["hypothetical_rf"],
            "without_both_evidence_components":
                no_evidence["hypothetical_rf"],
            "status": "MATHEMATICAL_PROPOSAL_ONLY",
        })

    doc = {
        "schema": SCHEMA,
        "source_kind": "SYNTHETIC_MATHEMATICAL_ONLY",
        "profiles": profiles,
        "configurations": results,
        "profile_count": len(profiles),
        "configuration_count": len(results),
        "evaluation_count": len(profiles) * len(results),
        "ranges": ranges,
        "secondary_comparators": secondary,
        "secondary_protocol_frozen": False,
        "reference_values_used": False,
        "technical_truth_accredited": False,
        "confirmed_rf": None,
        "operational_dispatch": False,
        "physical_observations": 0,
        "experimental_units_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }

    doc["sha256"] = digest(doc)

    return doc


def verify(document):

    need(
        canonical(document) == canonical(build()),
        "REPORT_NOT_REPRODUCIBLE",
    )

    return True


def main(argv=None):

    parser = argparse.ArgumentParser(
        description="Sensibilidad matematica DEV sin despacho",
    )

    output = parser.add_mutually_exclusive_group(required=True)

    output.add_argument("--json", action="store_true")
    output.add_argument("--texto", action="store_true")

    args = parser.parse_args(argv)

    report = build()

    if args.json:
        sys.stdout.buffer.write(canonical(report) + b"\n")
        return 0

    print("ARDREC / SENSIBILIDAD MATEMATICA DEV")

    print("PROFILES=" + str(report["profile_count"]))
    print("CONFIGURATIONS=" + str(report["configuration_count"]))
    print("EVALUATIONS=" + str(report["evaluation_count"]))

    for row in report["ranges"]:

        risk = row["hypothetical_rf"]
        priority = row["hypothetical_priority"]

        print(
            row["profile"]
            + "|RF=[" + risk["minimum"]
            + "," + risk["maximum"] + "]"
            + "|PA=[" + priority["minimum"]
            + "," + priority["maximum"] + "]"
        )

    for config in report["configurations"]:

        print(
            config["configuration"]
            + "|CHANGED_PRIORITY_RELATIONS="
            + str(config["changed_priority_relations"])
        )

    print("A6=ND")
    print("CONFIRMED_RF=ND")
    print("EXPERIMENTAL_UNITS_ADMITTED=0")
    print("P7=DRAFT_NOT_FROZEN")
    print("P8=NO-GO")
    print("REPORT_SHA256=" + report["sha256"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
