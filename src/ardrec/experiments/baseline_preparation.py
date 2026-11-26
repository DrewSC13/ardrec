"""Prospective I2 baseline preparation.

Reuses native study identities and exact initial assessment.
A documentary candidate does not authenticate technical facts,
prove prior chronology, close an operational baseline or authorize tests.
"""

from __future__ import annotations

import hashlib
import os
import stat

from pathlib import Path

from ardrec.experiments import (
    initial_assessment as initial,
    r148_paired_register as r148,
    r149_scenario_design as r149,
)

from ardrec.coordination import (
    prospective_local_pilot as durable,
)


SCHEMA = "ARDREC-R228-PROSPECTIVE-I2-v1"

MAX_SUPPORT_BYTES = 1048576

DIMENSIONS = initial.DIMENSIONS


def need(condition, reason):

    if not condition:
        raise ValueError(reason)


def valid_sha(value):

    return (
        type(value) is str
        and r149.HEX64.fullmatch(value) is not None
    )


def sha(raw):

    return hashlib.sha256(raw).hexdigest()


def template():

    return {
        name: {
            "ordinal": None,
            "support_sha256": None,
            "justification": None,
        }
        for name in DIMENSIONS
    }


def selected(row):

    return all(
        row[name] != ""
        for name in r149.ENTRY_FIELDS
    )


def slot_status(row):

    if selected(row):
        return "COMPLETE_UNVERIFIED"

    if any(row[name] for name in r149.ENTRY_FIELDS):
        return "PARTIAL"

    return "EMPTY"


def boundaries():

    return {
        "baseline_closed": False,
        "physical_initial_state_verified": False,
        "support_semantics_verified": False,
        "prior_chronology_authenticated": False,
        "ordinal_assignments_validated": False,
        "execution_authorized": False,
        "formal_pilot_admission": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    }


def validate_entry(entry):

    need(
        type(entry) is dict
        and set(entry) == {
            "slot_id",
            "selection_sha256",
            "configuration_sha256",
            "ratings",
        },
        "I2_ENTRY_SCHEMA_INVALID",
    )

    need(
        type(entry["slot_id"]) is str
        and valid_sha(entry["selection_sha256"])
        and valid_sha(entry["configuration_sha256"]),
        "I2_IDENTITY_INVALID",
    )

    ratings = entry["ratings"]

    need(
        type(ratings) is dict
        and set(ratings) == set(DIMENSIONS),
        "I2_DIMENSIONS_INVALID",
    )

    for name in DIMENSIONS:

        record = ratings[name]

        need(
            type(record) is dict
            and set(record) == {
                "ordinal",
                "support_sha256",
                "justification",
            },
            "I2_RATING_SCHEMA_INVALID:" + name,
        )

        initial.ordinal(record["ordinal"])

        need(
            valid_sha(record["support_sha256"]),
            "I2_RATING_SUPPORT_INVALID:" + name,
        )

        reason = record["justification"]

        need(
            type(reason) is str
            and 10 <= len(reason.strip()) <= 2000,
            "I2_JUSTIFICATION_INVALID:" + name,
        )

    return True


def required_supports(row, entry):

    validate_entry(entry)

    refs = {
        row["scope_authorization_sha256"],
        row["preregistration_sha256"],
        row["static_support_sha256"],
        entry["configuration_sha256"],
    }

    refs.update(
        record["support_sha256"]
        for record in entry["ratings"].values()
    )

    need(
        all(valid_sha(value) for value in refs),
        "I2_SUPPORT_REFERENCE_INVALID",
    )

    return refs


def locate_selected(rows, entry, working_sha256):

    validate_entry(entry)

    need(
        entry["selection_sha256"] == working_sha256,
        "I2_SELECTION_BINDING_INVALID",
    )

    matches = [
        row
        for row in rows
        if row["slot_id"] == entry["slot_id"]
    ]

    need(
        len(matches) == 1,
        "I2_SLOT_NOT_FOUND",
    )

    row = matches[0]

    need(
        selected(row),
        "I2_SCENARIO_NOT_SELECTED",
    )

    need(
        not any(row[key].upper().startswith("PILOT-")
                for key in ("case_id", "scenario_id", "service_instance_id")),
        "PILOT_IDENTITY_REUSE_FORBIDDEN",
    )

    return row


def candidate(row, entry, supports):

    need(
        selected(row),
        "I2_SCENARIO_NOT_SELECTED",
    )

    validate_entry(entry)

    need(
        not any(row[key].upper().startswith("PILOT-")
                for key in ("case_id", "scenario_id", "service_instance_id")),
        "PILOT_IDENTITY_REUSE_FORBIDDEN",
    )

    need(
        row["slot_id"] == entry["slot_id"],
        "I2_SLOT_BINDING_INVALID",
    )

    refs = required_supports(row, entry)

    need(
        type(supports) is dict
        and set(supports) == refs,
        "I2_SUPPORT_SET_INVALID",
    )

    for ref, raw in supports.items():

        need(
            type(raw) is bytes
            and 0 < len(raw) <= MAX_SUPPORT_BYTES
            and sha(raw) == ref,
            "I2_SUPPORT_INTEGRITY_INVALID",
        )

    static = r148._decimal(
        row["static_estimate"]
    )

    need(
        static <= 1,
        "I2_STATIC_SCALE_INVALID",
    )

    ratings = entry["ratings"]

    values = {
        name: ratings[name]["ordinal"]
        for name in DIMENSIONS
    }

    calculated = initial.compute(
        values["exposure"],
        values["probability"],
        values["impact"],
        [
            values["operational_importance"],
            values["data_sensitivity"],
            values["dependencies"],
        ],
    )

    return durable.seal({
        "schema": SCHEMA + "-candidate",
        "scope": "DOCUMENTARY_BASELINE_CANDIDATE",
        "slot_id": row["slot_id"],
        "protocol": row["protocol"],
        "family_id": row["chosen_family"],
        "case_id": row["case_id"],
        "scenario_id": row["scenario_id"],
        "service_instance_id": row["service_instance_id"],
        "selection_sha256": entry["selection_sha256"],
        "configuration_sha256": entry["configuration_sha256"],
        "static_estimate": row["static_estimate"],
        "static_support_sha256": row["static_support_sha256"],
        "scope_authorization_sha256":
            row["scope_authorization_sha256"],
        "preregistration_sha256":
            row["preregistration_sha256"],
        "ratings": ratings,
        "calculated": calculated,
        "verified_support_sha256": sorted(refs),
        "support_integrity_verified": True,
        "scope_authority_authenticated": False,
        "static_freeze_authenticated": False,
        **boundaries(),
    })


def build(
    catalog,
    protocol,
    registry,
    plan,
    checklist,
    working_raw,
    entry=None,
    supports=None,
):

    audit = r148.validate(
        protocol,
        registry,
        catalog,
    )

    selection = r149.validate_selection(
        plan,
        checklist,
        working_raw,
        catalog,
        protocol,
        registry,
    )

    need(
        audit["planned"] == 54
        and audit["statuses"]["PLANNED_UNASSIGNED"] == 54
        and selection["physical_observations"] == 0
        and selection["p8"] == "NO-GO",
        "I2_STUDY_BOUNDARY_INVALID",
    )

    rows = r149.parse_csv(working_raw)

    result = None

    if entry is not None:

        row = locate_selected(
            rows,
            entry,
            selection["working_sha256"],
        )

        result = candidate(
            row,
            entry,
            supports,
        )

    else:

        need(
            supports is None,
            "I2_UNEXPECTED_SUPPORTS",
        )

    slots = []

    for row in rows:

        slots.append({
            "slot_id": row["slot_id"],
            "protocol": row["protocol"],
            "candidate_family": row["candidate_family"],
            "chosen_family": row["chosen_family"] or None,
            "selection_status": slot_status(row),
            "ratings": template(),
            "initial_risk": None,
            "normalized_criticality": None,
            "baseline_closed": False,
        })

    return durable.seal({
        "schema": SCHEMA,
        "registry_sha256": registry["sha256"],
        "protocol_sha256": protocol["sha256"],
        "selection_sha256": selection["working_sha256"],
        "planned_slots": len(slots),
        "selection_statuses": selection["statuses"],
        "slots": slots,
        "candidate": result,
        "documentary_candidates_calculated": int(result is not None),
        "baselines_closed": 0,
        "experimental_observations": 0,
        "network_operations": 0,
        **boundaries(),
    })


def _same_file(left, right):
    # Ignore atime (ordinary reads may update it); keep nanosecond metadata.
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
              "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    return all(getattr(left, k) == getattr(right, k) for k in fields)


def read_private(path, limit):

    path = Path(path)

    need(
        path.is_absolute()
        and path.resolve(strict=True) == path,
        "I2_PRIVATE_PATH_INVALID",
    )

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
    )

    try:

        before = os.fstat(fd)

        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_nlink == 1
            and 0 < before.st_size <= limit,
            "I2_PRIVATE_FILE_INVALID",
        )

        with os.fdopen(
            os.dup(fd),
            "rb",
        ) as handle:

            raw = handle.read(limit + 1)

        after = os.fstat(fd)

        need(
            len(raw) == before.st_size
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns
            and _same_file(after, path.lstat()),
            "I2_SOURCE_CHANGED_DURING_READ",
        )

        return raw

    finally:

        os.close(fd)


def evaluate(
    registry_folder,
    selection_folder,
    catalog_path,
    entry_path=None,
    supports_folder=None,
):

    need(
        os.geteuid() != 0,
        "ROOT_FORBIDDEN",
    )

    catalog_path = Path(catalog_path)

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

    selection = r149.read(
        selection_folder,
        catalog,
        protocol,
        registry,
    )

    plan = r149.decode(
        r149._read(selection_folder, "plan.json")
    )

    checklist = r149.decode(
        r149._read(selection_folder, "family-checklist.json")
    )

    raw = r149._read(
        selection_folder,
        "selection-working.csv",
    )

    need(
        sha(raw) == selection["working_sha256"],
        "I2_SELECTION_CHANGED_DURING_READ",
    )

    entry = None
    supports = None

    if entry_path is not None:

        need(
            supports_folder is not None,
            "I2_SUPPORT_FOLDER_REQUIRED",
        )

        entry = r149.decode(
            read_private(
                entry_path,
                262144,
            )
        )

        row = locate_selected(
            r149.parse_csv(raw),
            entry,
            selection["working_sha256"],
        )

        directory = Path(supports_folder)

        need(
            directory.is_absolute()
            and directory.resolve(strict=True) == directory
            and directory.is_dir()
            and directory.stat().st_uid == os.geteuid()
            and stat.S_IMODE(directory.stat().st_mode) == 0o700,
            "I2_SUPPORT_FOLDER_UNSAFE",
        )

        supports = {
            ref: read_private(
                directory / (ref + ".bin"),
                MAX_SUPPORT_BYTES,
            )
            for ref in required_supports(row, entry)
        }

    else:

        need(
            supports_folder is None,
            "I2_UNEXPECTED_SUPPORT_FOLDER",
        )

    result = build(
        catalog,
        protocol,
        registry,
        plan,
        checklist,
        raw,
        entry,
        supports,
    )

    need(
        r148.read(registry_folder, catalog)
            == (protocol, registry)
        and r149.read(
            selection_folder,
            catalog,
            protocol,
            registry,
        ) == selection,
        "I2_STUDY_CHANGED_DURING_REVIEW",
    )

    return result


def render_text(report):

    lines = [
        "ARDREC / PREPARACION PROSPECTIVA I2",
        "POSICIONES=" + str(report["planned_slots"]),
        "SELECCION_SHA256=" + report["selection_sha256"],
    ]

    for status, number in report["selection_statuses"].items():

        lines.append(
            status + "=" + str(number)
        )

    for row in report["slots"]:

        lines.append(
            row["slot_id"] + " "
            + row["candidate_family"] + " "
            + row["selection_status"]
            + " R0=ND"
        )

    candidate_report = report["candidate"]

    if candidate_report is not None:

        lines.extend([
            "CANDIDATE_SLOT=" + candidate_report["slot_id"],
            "R0_CANDIDATE="
                + candidate_report["calculated"]["initial_risk"],
            "CN_CANDIDATE="
                + candidate_report["calculated"]["normalized_criticality"],
            "STATIC_DECLARED="
                + candidate_report["static_estimate"],
            "CANDIDATE_SHA256="
                + candidate_report["sha256"],
        ])

    lines.extend([
        "BASELINES_CLOSED=0",
        "EXECUTION_AUTHORIZED=NO",
        "EXPERIMENTAL_OBSERVATIONS=0",
        "P7=DRAFT_NOT_FROZEN",
        "P8=NO-GO",
        "REPORT_SHA256=" + report["sha256"],
    ])

    return "\n".join(lines) + "\n"
