"""R243: reconcile original selection and paired documentary records.

Reuse the native R148/R184 statistical engines.
No measurement, physical evidence or operational authority is created.
"""

import csv
import io
import os

from fractions import Fraction
from statistics import median

from ardrec.experiments import (
    r148_paired_register as r148,
    r149_scenario_design as r149,
    paired_summary as paired,
)

SCHEMA = "ARDREC-R243-PAIRED-RECONCILIATION-v1"


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def seal(document):
    return r148._seal(document)


def reconcile_selection(
    protocol,
    registry,
    catalog,
    plan,
    checklist,
    working_raw,
    proposal_raw,
):
    r148.validate(protocol, registry, catalog)

    # R149 belongs to the original empty planning register.
    # Reconstruct that immutable origin instead of changing it.

    original_protocol, original_registry = r148.build(
        catalog,
        protocol["head"],
    )

    need(
        original_protocol == protocol,
        "ORIGINAL_PROTOCOL_MISMATCH",
    )

    _, _, original_rows = r149.draft(
        catalog,
        original_protocol,
        original_registry,
    )

    need(
        proposal_raw == r149.csv_bytes(original_rows),
        "ORIGINAL_PROPOSAL_CHANGED",
    )

    selection = r149.validate_selection(
        plan,
        checklist,
        working_raw,
        catalog,
        original_protocol,
        original_registry,
    )

    rows = r149.parse_csv(working_raw)

    for slot, selected in zip(registry["slots"], rows):

        need(
            slot["slot_id"] == selected["slot_id"]
            and slot["protocol"] == selected["protocol"],
            "SLOT_SELECTION_MISMATCH",
        )

        if selected["static_estimate"]:
            paired.normalized(selected["static_estimate"])

        if slot["status"] == "PLANNED_UNASSIGNED":
            continue

        need(
            all(selected[key] for key in r149.ENTRY_FIELDS),
            "RECORDED_SLOT_SELECTION_INCOMPLETE",
        )

        need(
            slot["case_id"] == selected["case_id"]
            and slot["scenario_id"] == selected["scenario_id"]
            and slot["family_id"] == selected["chosen_family"],
            "RECORDED_SELECTION_IDENTITY_MISMATCH",
        )

        need(
            not any(
                selected[key].upper().startswith("PILOT-")
                for key in ("case_id", "scenario_id")
            ),
            "PILOT_REUSE_FORBIDDEN",
        )

        if slot["status"] == "RECORDED_UNVERIFIED":

            need(
                paired.normalized(slot["static_estimate"])
                == paired.normalized(selected["static_estimate"]),
                "STATIC_ESTIMATE_SELECTION_MISMATCH",
            )

    return selection, rows


def selection_sources(folder):

    r149._safe_dir(folder)

    return (
        r149.decode(r149._read(folder, "plan.json")),
        r149.decode(r149._read(folder, "family-checklist.json")),
        r149._read(folder, "selection-working.csv"),
        r149._read(folder, "family-proposal.csv"),
    )


def read_selection(folder, catalog, protocol, registry):

    return reconcile_selection(
        protocol,
        registry,
        catalog,
        *selection_sources(folder),
    )


def descriptive(rows, slots):

    recorded = len(rows)

    unassigned = sum(
        slot["status"] == "PLANNED_UNASSIGNED"
        for slot in slots
    )

    excluded = sum(
        slot["status"] == "EXCLUDED_UNVERIFIED"
        for slot in slots
    )

    need(
        recorded + unassigned + excluded == len(slots),
        "GROUP_CARDINALITY_INVALID",
    )

    static = [
        Fraction(row["static_absolute_error"])
        for row in rows
    ]

    ardrec = [
        Fraction(row["ardrec_absolute_error"])
        for row in rows
    ]

    differences = [
        Fraction(row["difference"])
        for row in rows
    ]

    def mean(values):
        return (
            paired.exact(sum(values, Fraction(0)) / len(values))
            if values else None
        )

    return {
        "planned": len(slots),
        "recorded_unverified": recorded,
        "unassigned": unassigned,
        "excluded_unverified": excluded,
        "mae_static": mean(static),
        "mae_ardrec": mean(ardrec),
        "mean_difference": mean(differences),
        "median_difference": (
            paired.exact(median(differences))
            if differences else None
        ),
        "favor_ardrec": sum(x > 0 for x in differences),
        "favor_static": sum(x < 0 for x in differences),
        "equal_errors": sum(x == 0 for x in differences),
        "analysis_scope": "DESCRIPTIVE_ONLY",
    }


def build(
    protocol,
    registry,
    catalog,
    plan,
    checklist,
    working_raw,
    proposal_raw,
):

    selection, selected_rows = reconcile_selection(
        protocol,
        registry,
        catalog,
        plan,
        checklist,
        working_raw,
        proposal_raw,
    )

    native, summary = paired.analyze(
        protocol,
        registry,
        catalog,
    )

    r148._verify_seal(native)
    r148._verify_seal(summary)

    errors = {
        row["slot_id"]: row
        for row in summary["paired_errors"]
    }

    rows = []

    for slot, selected in zip(
        registry["slots"],
        selected_rows,
    ):

        error = errors.get(slot["slot_id"])

        recorded = (
            slot["status"] == "RECORDED_UNVERIFIED"
        )

        need(
            recorded == (error is not None),
            "PAIR_ERROR_BINDING_INVALID",
        )

        row = {
            "slot_id": slot["slot_id"],
            "protocol": slot["protocol"],
            "status": slot["status"],
            "candidate_family": selected["candidate_family"],
            "selected_family": selected["chosen_family"] or None,
            "selected_case_id": selected["case_id"] or None,
            "selected_scenario_id":
                selected["scenario_id"] or None,
            "selected_service_instance_id":
                selected["service_instance_id"] or None,
            "recorded_case_id": slot["case_id"],
            "recorded_scenario_id": slot["scenario_id"],
            "recorded_family": slot["family_id"],
            "exclusion_reason": slot["exclusion_reason"],
            "exclusion_decision_sha256":
                slot["exclusion_decision_sha256"],
            "support_references": {
                key: slot[key]
                for key in r148.REFS
            },
            "support_provenance_authenticated": False,
            "reference_independence_attested": False,
            "experimental_admission": False,
        }

        for key in r148.VALUES:

            row[key] = (
                paired.exact(
                    paired.normalized(slot[key])
                )
                if recorded else None
            )

        for key in (
            "static_absolute_error",
            "ardrec_absolute_error",
            "difference",
        ):

            row[key] = (
                error[key] if recorded else None
            )

        rows.append(row)

    groups = {}

    for proto in r148.PROTOCOLS:

        groups[proto] = descriptive(
            [
                row for row in summary["paired_errors"]
                if row["protocol"] == proto
            ],
            [
                slot for slot in registry["slots"]
                if slot["protocol"] == proto
            ],
        )

    need(
        len(rows) == 54
        and sum(
            group["recorded_unverified"]
            for group in groups.values()
        ) == summary["pairs"],
        "I8_CARDINALITY_INVALID",
    )

    return seal({
        "schema": SCHEMA,
        "source_head": protocol["head"],
        "protocol_sha256": protocol["sha256"],
        "registry_sha256": registry["sha256"],
        "catalog_sha256": r148.digest(catalog),
        "selection_sha256": selection["working_sha256"],
        "selection": selection,
        "planned": 54,
        "selected_complete":
            selection["statuses"]["COMPLETE"],
        "recorded_unverified": summary["pairs"],
        "native_statistics": native,
        "paired_summary": summary,
        "by_protocol_descriptive": groups,
        "i8_rows": rows,
        "confirmed_physical_observations": 0,
        "formal_pilot_admitted": 0,
        "experimental_admitted": 0,
        "confirmatory_analysis_authorized": False,
        "independent_reference_attested": False,
        "a6": "ND",
        "a9": "NOT_PUBLISHED",
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def evaluate(registry_folder, selection_folder, catalog_path):

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    need(
        catalog_path.is_file()
        and not catalog_path.is_symlink(),
        "CATALOG_UNSAFE",
    )

    catalog = catalog_path.read_bytes()

    protocol, registry = r148.read(
        registry_folder,
        catalog,
    )

    return build(
        protocol,
        registry,
        catalog,
        *selection_sources(selection_folder),
    )


CSV_FIELDS = (
    "slot_id",
    "protocol",
    "status",
    "candidate_family",
    "selected_family",
    "selected_case_id",
    "selected_scenario_id",
    "selected_service_instance_id",
    "recorded_case_id",
    "recorded_scenario_id",
    "recorded_family",
    "static_estimate",
    "ardrec_estimate",
    "independent_reference",
    "static_absolute_error",
    "ardrec_absolute_error",
    "difference",
    "exclusion_decision_sha256",
    *r148.REFS,
    "experimental_admission",
)


def export_csv(report):

    r148._verify_seal(report)

    need(
        report["schema"] == SCHEMA
        and report["experimental_admitted"] == 0
        and report["p8"] == "NO-GO"
        and len(report["i8_rows"]) == 54,
        "CSV_SOURCE_INVALID",
    )

    buffer = io.StringIO(newline="")

    writer = csv.DictWriter(
        buffer,
        fieldnames=CSV_FIELDS,
        lineterminator="\n",
    )

    writer.writeheader()

    for row in report["i8_rows"]:

        need(
            row["experimental_admission"] is False,
            "FALSE_ADMISSION",
        )

        merged = {
            **row,
            **row["support_references"],
        }

        writer.writerow({
            key: (
                ""
                if merged[key] is None
                else merged[key]
            )
            for key in CSV_FIELDS
        })

    return buffer.getvalue().encode("utf-8")


def render_text(report):

    summary = report["paired_summary"]

    lines = [
        "ARDREC / CONSOLIDACION I8",
        "PLANNED=54",
        f"SELECTED_COMPLETE={report['selected_complete']}",
        f"RECORDED_UNVERIFIED={report['recorded_unverified']}",
    ]

    for key in (
        "mae_static",
        "mae_ardrec",
        "mean_difference",
        "median_difference",
        "rank_biserial",
    ):

        value = summary[key]

        lines.append(
            key.upper() + "="
            + ("ND" if value is None else value)
        )

    p_value = summary["wilcoxon"]["p_fraction"]

    lines.append(
        "WILCOXON_P="
        + ("ND" if p_value is None else p_value)
    )

    for proto, group in (
        report["by_protocol_descriptive"].items()
    ):

        lines.append(
            f"{proto} PAIRS={group['recorded_unverified']}/18"
            f" UNASSIGNED={group['unassigned']}"
            f" EXCLUDED={group['excluded_unverified']}"
            f" MAE_STATIC={group['mae_static'] or 'ND'}"
            f" MAE_ARDREC={group['mae_ardrec'] or 'ND'}"
        )

    lines.extend([
        "CONFIRMATORY_ANALYSIS_AUTHORIZED=NO",
        "EXPERIMENTAL_ADMITTED=0/54",
        "P7=DRAFT_NOT_FROZEN",
        "P8=NO-GO",
        "REPORT_SHA256=" + report["sha256"],
    ])

    return "\n".join(lines) + "\n"
