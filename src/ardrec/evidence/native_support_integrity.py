"""R361: native support integrity and documentary coverage.

Verifies actual bytes without claiming physical origin,
technical classification or operational authority.
"""

from copy import deepcopy
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.analytical_references import fingerprint, identifier
from ardrec.evidence import native_evidence_provenance as provenance

SCHEMA = "ARDREC-R361-NATIVE-SUPPORT-INTEGRITY-v1"
MANIFEST_SCHEMA = SCHEMA + "-manifest"

MAX_SUPPORT_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 4096

IDENTITY_FIELDS = (
    "service_scenario_id",
    "derived_case_id",
    "condition_id",
    "attempt_id",
    "request_sha256",
    "report_sha256",
    "incorporation_event",
    "incorporation_generation",
    "effective_parameters_reference",
)

ENTRY_FIELDS = set(IDENTITY_FIELDS) | {
    "support_reference",
    "support_sha256",
    "byte_count",
}


class SupportIntegrityError(ValueError):
    """Stable fail-closed support verification failure."""


def require(ok, reason):
    if not ok:
        raise SupportIntegrityError(reason)


def identity(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@contextmanager
def open_private_root(path):

    path = Path(path)

    require(
        path.is_absolute()
        and path != Path("/")
        and ".." not in path.parts,
        "SUPPORT_ROOT_PATH_INVALID",
    )

    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
    )

    fd = os.open("/", flags)

    try:

        for component in path.parts[1:]:

            child = os.open(
                component,
                flags,
                dir_fd=fd,
            )

            os.close(fd)
            fd = child

        info = os.fstat(fd)

        require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) & 0o077 == 0,
            "SUPPORT_ROOT_NOT_PRIVATE",
        )

        yield fd

    finally:

        os.close(fd)


def read_support(root_fd, pin, expected_size):

    fingerprint(pin)

    require(
        type(expected_size) is int
        and 0 <= expected_size <= MAX_SUPPORT_BYTES,
        "SUPPORT_SIZE_DOMAIN_INVALID",
    )

    # The pathname is derived from a validated digest,
    # never from an arbitrary manifest pathname.
    filename = pin + ".bin"

    fd = os.open(
        filename,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
        | os.O_CLOEXEC,
        dir_fd=root_fd,
    )

    try:

        before = os.fstat(fd)

        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) & 0o077 == 0,
            "SUPPORT_FILE_METADATA_INVALID",
        )

        require(
            before.st_size == expected_size,
            "SUPPORT_SIZE_MISMATCH",
        )

        hasher = hashlib.sha256()
        observed_size = 0

        while True:

            block = os.read(fd, 65536)

            if not block:
                break

            observed_size += len(block)

            require(
                observed_size <= expected_size
                and observed_size <= MAX_SUPPORT_BYTES,
                "SUPPORT_SIZE_LIMIT_EXCEEDED",
            )

            hasher.update(block)

        after = os.fstat(fd)

        linked = os.stat(
            filename,
            dir_fd=root_fd,
            follow_symlinks=False,
        )

        require(
            identity(before)
            == identity(after)
            == identity(linked),
            "SUPPORT_CHANGED_DURING_READ",
        )

        require(
            observed_size == expected_size,
            "SUPPORT_READ_SIZE_MISMATCH",
        )

        require(
            hasher.hexdigest() == pin,
            "SUPPORT_HASH_MISMATCH",
        )

        return observed_size

    finally:

        os.close(fd)


def expected_supports(source):

    result = {}

    for attempt in source["attempts"]:

        if not attempt["documentary_link_verified"]:
            continue

        for reference in attempt["declared_support_references"]:

            identifier(reference)

            key = (
                attempt["attempt_id"],
                reference,
            )

            require(
                key not in result,
                "DUPLICATE_NATIVE_SUPPORT",
            )

            result[key] = {
                **{
                    name: attempt[name]
                    for name in IDENTITY_FIELDS
                },
                "support_reference": reference,
            }

    require(
        len(result) <= MAX_ENTRIES,
        "NATIVE_SUPPORT_INVENTORY_LIMIT",
    )

    return result


def validate_manifest(manifest, pin, source, expected):

    fingerprint(pin)

    require(
        type(manifest) is dict
        and set(manifest) == {
            "schema",
            "provenance_sha256",
            "entries",
        }
        and manifest["schema"] == MANIFEST_SCHEMA,
        "SUPPORT_MANIFEST_SCHEMA_INVALID",
    )

    manifest = deepcopy(manifest)

    require(
        digest(manifest) == pin,
        "SUPPORT_MANIFEST_PIN_MISMATCH",
    )

    require(
        manifest["provenance_sha256"] == source["sha256"],
        "SUPPORT_PROVENANCE_PIN_MISMATCH",
    )

    entries = manifest["entries"]

    require(
        type(entries) is list
        and len(entries) <= MAX_ENTRIES,
        "SUPPORT_MANIFEST_DOMAIN_INVALID",
    )

    result = {}
    total = 0

    for row in entries:

        require(
            type(row) is dict
            and set(row) == ENTRY_FIELDS,
            "SUPPORT_ENTRY_SCHEMA_INVALID",
        )

        identifier(row["attempt_id"])
        identifier(row["support_reference"])
        fingerprint(row["support_sha256"])

        key = (
            row["attempt_id"],
            row["support_reference"],
        )

        require(
            key in expected,
            "FOREIGN_OR_UNDECLARED_SUPPORT",
        )

        require(
            key not in result,
            "DUPLICATE_SUPPORT_ENTRY",
        )

        require(
            canonical({
                name: row[name]
                for name in expected[key]
            }) == canonical(expected[key]),
            "SUPPORT_RECEIPT_BINDING_MISMATCH",
        )

        size = row["byte_count"]

        require(
            type(size) is int
            and 0 <= size <= MAX_SUPPORT_BYTES,
            "SUPPORT_SIZE_DOMAIN_INVALID",
        )

        total += size

        require(
            total <= MAX_TOTAL_BYTES,
            "TOTAL_SUPPORT_SIZE_LIMIT",
        )

        result[key] = row

    return result


def coverage(verified, declared):

    if declared == 0:
        return "ABSENT"

    if verified == declared:
        return "COMPLETE"

    if verified == 0:
        return "ABSENT"

    return "PARTIAL"


def build(
    store_path,
    *,
    support_root,
    manifest,
    expected_manifest_sha256,
    provenance_kwargs,
):

    source = provenance.build(
        store_path,
        **provenance_kwargs,
    )

    expected = expected_supports(source)

    entries = validate_manifest(
        manifest,
        expected_manifest_sha256,
        source,
        expected,
    )

    rows = []

    with open_private_root(support_root) as root:

        original_root = os.fstat(root)

        for key, expected_row in sorted(expected.items()):

            entry = entries.get(key)

            row = {
                **expected_row,
                "support_sha256": None,
                "byte_count": None,
                "status": "MANIFEST_ENTRY_MISSING",
                "bytes_verified": False,
                "technical_truth_accredited": False,
            }

            if entry is not None:

                row["support_sha256"] = entry["support_sha256"]
                row["byte_count"] = entry["byte_count"]

                try:

                    read_support(
                        root,
                        entry["support_sha256"],
                        entry["byte_count"],
                    )

                except FileNotFoundError:

                    row["status"] = "SUPPORT_FILE_MISSING"

                else:

                    row["status"] = "BYTES_VERIFIED"
                    row["bytes_verified"] = True

            rows.append(row)

        # Ensure the root pathname still identifies the
        # same directory opened for this verification.
        with open_private_root(support_root) as reopened:

            final_root = os.fstat(reopened)

            require(
                (
                    original_root.st_dev,
                    original_root.st_ino,
                ) == (
                    final_root.st_dev,
                    final_root.st_ino,
                ),
                "SUPPORT_ROOT_REPLACED",
            )

    conditions = []

    for condition in source["conditions"]:

        selected = [
            row for row in rows
            if row["service_scenario_id"]
                == condition["service_scenario_id"]
            and row["condition_id"]
                == condition["condition_id"]
        ]

        verified = sum(
            row["bytes_verified"]
            for row in selected
        )

        conditions.append({
            "service_scenario_id":
                condition["service_scenario_id"],
            "condition_id": condition["condition_id"],
            "declared_supports": len(selected),
            "verified_supports": verified,
            "documentary_coverage": coverage(
                verified,
                len(selected),
            ),
            "required_family_supports_accredited": False,
            "classification": "ND",
            "confirmed_contribution": None,
        })

    # Recover the pinned source again. Do not accept
    # evidence against a journal changed during review.
    final_source = provenance.build(
        store_path,
        **provenance_kwargs,
    )

    require(
        canonical(final_source) == canonical(source),
        "DURABLE_PROVENANCE_CHANGED",
    )

    verified = sum(
        row["bytes_verified"]
        for row in rows
    )

    result = {
        "schema": SCHEMA,
        "scope": "NATIVE_SUPPORT_BYTES_ONLY",
        "record_id": source["record_id"],
        "execution_id": source["execution_id"],
        "configuration_sha256":
            source["configuration_sha256"],
        "generation": source["generation"],
        "head_sha256": source["head_sha256"],
        "provenance_sha256": source["sha256"],
        "manifest_sha256": expected_manifest_sha256,
        "declared_supports": len(rows),
        "verified_supports": verified,
        "verified_logical_bytes": sum(
            row["byte_count"]
            for row in rows
            if row["bytes_verified"]
        ),
        "documentary_coverage": coverage(
            verified,
            len(rows),
        ),
        "supports": rows,
        "conditions": conditions,
        "technical_conditions_accredited": 0,
        "technical_truth_accredited": False,
        "physical_origin_accredited": False,
        "external_freshness_accredited": False,
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


def verify(report, expected_report_sha256, store_path, **kwargs):

    fingerprint(expected_report_sha256)

    require(
        type(report) is dict
        and report.get("sha256") == expected_report_sha256
        and digest({
            key: value
            for key, value in report.items()
            if key != "sha256"
        }) == expected_report_sha256,
        "SUPPORT_REPORT_PIN_INVALID",
    )

    expected = build(store_path, **kwargs)

    require(
        canonical(report) == canonical(expected),
        "SUPPORT_REPORT_REPLAY_MISMATCH",
    )

    return True
