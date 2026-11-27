"""Source-bound known-content verification for three read-only families.

Matches verified support digests against a separately pinned
synthetic reference. No physical origin or operational A6 truth
is established by this partial semantic review.
"""

from copy import deepcopy

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.analytical_references import fingerprint, identifier
from ardrec.evidence import native_family_review as family
from ardrec.evidence import native_support_integrity as material

SCHEMA = "ARDREC-R363-NATIVE-CONTENT-REVIEW-v1"
REFERENCE_SCHEMA = SCHEMA + "-references"
DIGEST_SCHEMA = SCHEMA + "-observed-digest"

FAMILIES = {
    "SSH-T06",
    "FTP-T06",
    "SMB-T07",
}

IDENTITY = (
    "attempt_id",
    "service_scenario_id",
    "derived_case_id",
    "condition_id",
    "family_id",
    "request_sha256",
    "report_sha256",
    "incorporation_event",
    "incorporation_generation",
)

REFERENCE_FIELDS = set(IDENTITY) | {
    "expected_content_sha256",
    "expected_byte_count",
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest_record(attempt, observed_sha256, observed_size):

    fingerprint(observed_sha256)

    require(
        type(observed_size) is int
        and 0 <= observed_size <= material.MAX_SUPPORT_BYTES,
        "OBSERVED_CONTENT_SIZE_INVALID",
    )

    return {
        "schema": DIGEST_SCHEMA,
        **{
            name: attempt[name]
            for name in IDENTITY
        },
        "observed_content_sha256": observed_sha256,
        "observed_byte_count": observed_size,
    }


def validate_references(document, pin, family_report):

    fingerprint(pin)

    require(
        type(document) is dict
        and set(document) == {
            "schema",
            "record_id",
            "execution_id",
            "configuration_sha256",
            "references",
        }
        and document["schema"] == REFERENCE_SCHEMA,
        "CONTENT_REFERENCE_SCHEMA",
    )

    require(
        digest(document) == pin,
        "CONTENT_REFERENCE_PIN_MISMATCH",
    )

    for key in (
        "record_id",
        "execution_id",
        "configuration_sha256",
    ):

        require(
            document[key] == family_report[key],
            "CONTENT_REFERENCE_CONTEXT_MISMATCH:" + key,
        )

    eligible = {
        row["attempt_id"]: row
        for row in family_report["attempts"]
        if row["family_id"] in FAMILIES
    }

    refs = document["references"]

    require(
        type(refs) is list
        and len(refs) <= family.MAX_ATTEMPTS,
        "CONTENT_REFERENCE_LIMIT",
    )

    indexed = {}

    for entry in refs:

        require(
            type(entry) is dict
            and set(entry) == REFERENCE_FIELDS,
            "CONTENT_REFERENCE_ENTRY_SCHEMA",
        )

        aid = entry["attempt_id"]
        identifier(aid)

        require(
            aid in eligible
            and aid not in indexed,
            "FOREIGN_OR_DUPLICATE_CONTENT_REFERENCE",
        )

        expected = {
            name: eligible[aid][name]
            for name in IDENTITY
        }

        require(
            canonical({
                name: entry[name]
                for name in IDENTITY
            }) == canonical(expected),
            "CONTENT_REFERENCE_ATTEMPT_MISMATCH",
        )

        fingerprint(entry["expected_content_sha256"])

        require(
            type(entry["expected_byte_count"]) is int
            and 0 < entry["expected_byte_count"]
                <= material.MAX_SUPPORT_BYTES,
            "EXPECTED_CONTENT_SIZE_INVALID",
        )

        indexed[aid] = entry

    require(
        set(indexed) == set(eligible),
        "CONTENT_REFERENCE_INVENTORY_INCOMPLETE",
    )

    return indexed, eligible


def review_content(attempt, reference, entries):

    aid = attempt["attempt_id"]

    roles = {
        row["role"]: row
        for row in attempt["support_roles"]
    }

    require(
        {"RESOURCE_READ", "KNOWN_CONTENT_DIGEST"}
            <= set(roles),
        "KNOWN_CONTENT_ROLES_MISSING",
    )

    read = roles["RESOURCE_READ"]
    proof = roles["KNOWN_CONTENT_DIGEST"]

    result = {
        **{
            name: attempt[name]
            for name in IDENTITY
        },
        "expected_content_sha256":
            reference["expected_content_sha256"],
        "expected_byte_count":
            reference["expected_byte_count"],
        "observed_content_sha256": None,
        "observed_byte_count": None,
        "digest_record_sha256": None,
        "digest_record_consistent": None,
        "reference_comparison": "ND",
        "content_review": "INCOMPLETE",
        "physical_origin_accredited": False,
        "technical_condition_truth": "ND",
        "a6": "ND",
        "confirmed_rf": None,
    }

    if not read["bytes_verified"]:

        return result

    read_entry = entries[
        (aid, read["support_reference"])
    ]

    observed_pin = read_entry["support_sha256"]
    observed_size = read_entry["byte_count"]

    require(
        observed_pin == read["support_sha256"],
        "READ_SUPPORT_BINDING_MISMATCH",
    )

    result["observed_content_sha256"] = observed_pin
    result["observed_byte_count"] = observed_size

    match = (
        observed_pin == reference["expected_content_sha256"]
        and observed_size == reference["expected_byte_count"]
    )

    result["reference_comparison"] = (
        "MATCH" if match else "MISMATCH"
    )

    if not proof["bytes_verified"]:

        return result

    proof_entry = entries[
        (aid, proof["support_reference"])
    ]

    expected_record = digest_record(
        attempt,
        observed_pin,
        observed_size,
    )

    expected_record_pin = digest(expected_record)
    expected_record_size = len(canonical(expected_record))

    result["digest_record_sha256"] = (
        proof_entry["support_sha256"]
    )

    consistent = (
        proof_entry["support_sha256"]
            == proof["support_sha256"]
        and proof_entry["support_sha256"]
            == expected_record_pin
        and proof_entry["byte_count"]
            == expected_record_size
    )

    result["digest_record_consistent"] = consistent

    if not consistent:

        result["content_review"] = (
            "CONTRADICTORY_DIGEST_RECORD"
        )

    elif match:

        result["content_review"] = "MATCH"

    else:

        result["content_review"] = "MISMATCH"

    return result


def build(
    store_path,
    *,
    references,
    expected_reference_sha256,
    family_kwargs,
):

    # Use local immutable snapshots of caller documents.
    references = deepcopy(references)
    family_kwargs = deepcopy(family_kwargs)

    report = family.build(
        store_path,
        **family_kwargs,
    )

    indexed, eligible = validate_references(
        references,
        expected_reference_sha256,
        report,
    )

    manifest = family_kwargs[
        "support_kwargs"
    ]["manifest"]

    entries = {
        (
            row["attempt_id"],
            row["support_reference"],
        ): row
        for row in manifest["entries"]
    }

    reviewed = [
        review_content(
            eligible[aid],
            indexed[aid],
            entries,
        )
        for aid in sorted(indexed)
    ]

    counts = {
        name: sum(
            row["content_review"] == name
            for row in reviewed
        )
        for name in (
            "MATCH",
            "MISMATCH",
            "INCOMPLETE",
            "CONTRADICTORY_DIGEST_RECORD",
        )
    }

    require(
        sum(counts.values()) == len(reviewed),
        "CONTENT_REVIEW_COUNT_MISMATCH",
    )

    result = {
        "schema": SCHEMA,
        "scope": "KNOWN_SYNTHETIC_CONTENT_REVIEW_ONLY",
        "record_id": report["record_id"],
        "execution_id": report["execution_id"],
        "configuration_sha256":
            report["configuration_sha256"],
        "head_sha256": report["head_sha256"],
        "generation": report["generation"],
        "family_report_sha256": report["sha256"],
        "reference_sha256": expected_reference_sha256,
        "supported_families": sorted(FAMILIES),
        "reviewed_attempts": len(reviewed),
        "results": reviewed,
        "content_status_counts": counts,
        "other_family_attempts_not_reviewed":
            report["reviewed_attempts"] - len(reviewed),
        "external_reference_custody_accredited": False,
        "physical_origin_accredited": False,
        "technical_conditions_accredited": 0,
        "effective_parameters_accredited": False,
        "a6": "ND",
        "confirmed_rf": None,
        "published_generation": None,
        "operational_dispatch": False,
        "experimental_admitted": 0,
        "p8": "NO-GO",
    }

    result["sha256"] = digest(result)

    return result


def verify(
    report,
    expected_report_sha256,
    store_path,
    **kwargs,
):

    fingerprint(expected_report_sha256)

    require(
        type(report) is dict
        and report.get("sha256") == expected_report_sha256
        and digest({
            key: value
            for key, value in report.items()
            if key != "sha256"
        }) == expected_report_sha256,
        "CONTENT_REPORT_PIN_MISMATCH",
    )

    require(
        canonical(report) == canonical(
            build(store_path, **kwargs)
        ),
        "CONTENT_REPORT_REPLAY_MISMATCH",
    )

    return True
