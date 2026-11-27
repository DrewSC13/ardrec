"""Strict binding of native DEV analytical snapshots.

Integrity and review context do not establish physical identity,
operational authority, technical evidence or external freshness.
"""

import hashlib
from pathlib import Path

from ardrec.analytical import ANALYSIS_FIELDS
from ardrec.analytical_references import (
    ROLES,
    CONTEXT_FIELDS,
    MAX_OBJECTS,
    canonical,
    decode,
    context,
    fields,
    fingerprint,
    identifier,
)
from ardrec.contracts import ND
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.state import ServicePhase


SCHEMA = "ARDREC-R379-NATIVE-DEV-SNAPSHOT-BINDING-v1"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_binding(raw, expected_sha256):

    fingerprint(expected_sha256)

    require(
        type(raw) is bytes,
        "R379_BINDING_BYTES_INVALID",
    )

    require(
        sha(raw) == expected_sha256,
        "R379_BINDING_PIN_MISMATCH",
    )

    binding = decode(raw)

    fields(binding, (
        "schema",
        "scope",
        "snapshot_sha256",
        "context",
        "characterizations",
    ))

    require(
        binding["schema"] == SCHEMA
        and binding["scope"] == "NON_OPERATIONAL_DEV_REVIEW",
        "R379_BINDING_SCOPE_INVALID",
    )

    fingerprint(binding["snapshot_sha256"])

    context(binding["context"])

    rows = binding["characterizations"]

    require(
        type(rows) is list
        and 0 < len(rows) <= MAX_OBJECTS // len(ROLES),
        "R379_INVENTORY_INVALID",
    )

    indexed = {}

    for row in rows:

        fields(row, (
            "service_scenario_id",
            "reference",
            "sha256",
        ))

        uid = row["service_scenario_id"]

        identifier(uid)
        identifier(row["reference"])
        fingerprint(row["sha256"])

        require(
            uid not in indexed,
            "R379_DUPLICATE_SERVICE",
        )

        indexed[uid] = row

    require(
        list(indexed) == sorted(indexed),
        "R379_INVENTORY_ORDER_INVALID",
    )

    return binding, indexed


def unknown(value, reason):
    return (
        type(value) is ND
        and value.reason_code == reason
    )


def verify_prepared_projection(projection):

    require(
        projection.operational_state
            is ServicePhase.PREPARADO,
        "R379_NON_PREPARED_PROJECTION",
    )

    frozen = projection.frozen

    require(
        unknown(
            frozen.initial_risk,
            "BASELINE_NOT_CLOSED",
        )
        and unknown(
            frozen.normalized_criticality,
            "BASELINE_NOT_CLOSED",
        ),
        "R379_BASELINE_PROMOTION",
    )

    for field in ANALYSIS_FIELDS:

        value = getattr(projection.analysis, field)

        if field == "priority":

            require(
                value is None,
                "R379_PRIORITY_PROMOTION",
            )

        else:

            reason = (
                "BASELINE_NOT_CLOSED"
                if field in (
                    "substituted_baseline",
                    "lower_adjustment_bound",
                )
                else "EVIDENCE_NOT_ACCREDITED"
            )

            require(
                unknown(value, reason),
                "R379_MAGNITUDE_PROMOTION:" + field,
            )


def load_bound(
    archive_path,
    *,
    binding_bytes,
    expected_binding_sha256,
):
    """Recover one explicitly pinned DEV snapshot.

    Does not discover the latest snapshot or establish
    the external custody of the expected digest.
    """

    binding, expected = validate_binding(
        binding_bytes,
        expected_binding_sha256,
    )

    target = binding["context"]

    pin = binding["snapshot_sha256"]

    with AnalyticalArchive(
        Path(archive_path)
    ) as archive:

        recovered = archive.load(pin)

        require(
            recovered.snapshot_sha256 == pin,
            "R379_SNAPSHOT_IDENTITY_MISMATCH",
        )

        projections = recovered.projections

        actual_units = [
            p.service_scenario_id
            for p in projections
        ]

        require(
            actual_units == sorted(expected),
            "R379_SERVICE_SCOPE_MISMATCH",
        )

        for projection in projections:

            for field in CONTEXT_FIELDS:

                require(
                    getattr(projection, field)
                        == target[field],
                    "R379_CONTEXT_MISMATCH:" + field,
                )

            verify_prepared_projection(projection)

            uid = projection.service_scenario_id

            ref = projection.frozen.characterization

            require(
                ref.reference
                    == expected[uid]["reference"]
                and ref.sha256
                    == expected[uid]["sha256"],
                "R379_CHARACTERIZATION_MISMATCH",
            )

        manifest = decode(
            recovered.references.manifest_bytes
        )

        require(
            canonical(manifest["context"])
                == canonical(target),
            "R379_MANIFEST_CONTEXT_MISMATCH",
        )

        indexed = {}

        for raw in recovered.references.object_bytes:

            obj = decode(raw)

            key = (
                obj["service_scenario_id"],
                obj["role"],
            )

            require(
                key not in indexed,
                "R379_DUPLICATE_ROLE",
            )

            indexed[key] = obj

            origin = obj["context"]

            for field in CONTEXT_FIELDS[:-1]:

                require(
                    origin[field] == target[field],
                    "R379_OBJECT_CONTEXT_MISMATCH",
                )

            expected_generation = (
                0
                if obj["role"] == "characterization"
                else target["generation_index"]
            )

            require(
                origin["generation_index"]
                    == expected_generation,
                "R379_OBJECT_GENERATION_MISMATCH",
            )

        require(
            set(indexed) == {
                (uid, role)
                for uid in expected
                for role in ROLES
            },
            "R379_REFERENCE_SCOPE_MISMATCH",
        )

    result = {
        "schema": SCHEMA + "-receipt",
        "scope": "NON_OPERATIONAL_DEV_REVIEW",
        "snapshot_sha256": pin,
        "binding_sha256": expected_binding_sha256,
        "context": target,
        "services_verified": len(expected),
        "references_verified": len(indexed),
        "frozen_characterizations_verified":
            len(expected),
        "structural_binding_verified": True,
        "prepared_magnitudes_verified": True,
        "payload_full_semantics_accredited": False,
        "external_freshness_accredited": False,
        "effective_service_identity_accredited": False,
        "operational_dispatch": False,
        "technical_truth_accredited": False,
        "formal_pilots_admitted": 0,
        "experimental_admitted": 0,
        "a6": "ND",
        "confirmed_rf": None,
        "a9": "NOT_PUBLISHED",
        "p8": "NO-GO",
    }

    result["sha256"] = sha(canonical(result))

    return result
