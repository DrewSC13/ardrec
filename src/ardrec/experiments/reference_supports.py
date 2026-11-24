"""R244: content-addressed support integrity for I4.

Authenticates byte equality against supplied pins, not factual
truth, independent human review, or operational authority.
"""

import argparse
import hashlib
import os
import re
import stat
import sys

from pathlib import Path

from ardrec.experiments import (
    reference_rubric as rubric,
    r148_paired_register as r148,
)

SCHEMA = "ARDREC-R244-I4-SUPPORT-INTEGRITY-v1"

HEX64 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)

MAX_OBJECT_BYTES = 1048576
MAX_TOTAL_BYTES = 16777216
MAX_SUPPORTS = 128


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def required_supports(document):
    normalized = rubric.normalize(document)

    records = (
        list(normalized["common_checks"].values())
        + list(normalized["facts"].values())
    )

    result = sorted({
        support
        for record in records
        for support in record["supports"]
    })

    need(
        len(result) <= MAX_SUPPORTS,
        "SUPPORT_COUNT_LIMIT",
    )

    return result


def manifest_template(document):

    normalized = rubric.normalize(document)

    return {
        "schema": SCHEMA + "-manifest",
        "unit_id": normalized["unit_id"],
        "protocol": normalized["protocol"],
        "reference_input_sha256": rubric.digest(normalized),
        "bindings": {
            identifier: None
            for identifier in required_supports(normalized)
        },
    }


def evaluate(
    document,
    manifest,
    objects,
    *,
    expected_document_sha256,
    expected_manifest_sha256,
):

    normalized = rubric.normalize(document)

    document_pin = rubric.digest(normalized)
    manifest_pin = sha(r148.canonical(manifest))

    need(
        document_pin == expected_document_sha256,
        "REFERENCE_INPUT_PIN_MISMATCH",
    )

    need(
        manifest_pin == expected_manifest_sha256,
        "MANIFEST_PIN_MISMATCH",
    )

    template = manifest_template(normalized)

    need(
        type(manifest) is dict
        and set(manifest) == set(template),
        "MANIFEST_SCHEMA_INVALID",
    )

    need(
        all(
            manifest[key] == template[key]
            for key in template
            if key != "bindings"
        ),
        "MANIFEST_UNIT_BINDING_INVALID",
    )

    bindings = manifest["bindings"]

    need(
        type(bindings) is dict
        and set(bindings) == set(template["bindings"]),
        "SUPPORT_SET_MISMATCH",
    )

    need(
        all(
            type(value) is str
            and HEX64.fullmatch(value)
            for value in bindings.values()
        ),
        "SUPPORT_DIGEST_REQUIRED",
    )

    need(
        type(objects) is dict
        and set(objects) == set(bindings.values()),
        "OBJECT_SET_MISMATCH",
    )

    total = 0

    for digest, raw in objects.items():

        need(
            type(raw) is bytes
            and 0 < len(raw) <= MAX_OBJECT_BYTES,
            "OBJECT_SIZE_INVALID",
        )

        total += len(raw)

        need(
            total <= MAX_TOTAL_BYTES,
            "OBJECT_TOTAL_LIMIT",
        )

        need(
            sha(raw) == digest,
            "OBJECT_DIGEST_MISMATCH",
        )

    native = rubric.evaluate(normalized)

    need(
        rubric.verify(normalized, native),
        "NATIVE_REFERENCE_REPLAY_FAILED",
    )

    return r148._seal({
        "schema": SCHEMA,
        "unit_id": normalized["unit_id"],
        "protocol": normalized["protocol"],
        "reference_input_sha256": document_pin,
        "manifest_sha256": manifest_pin,
        "support_identifiers": len(bindings),
        "unique_objects_verified": len(objects),
        "object_bytes_verified": total,
        "bindings": bindings,
        "provided_pins_matched": True,
        "reference_report": native,
        "support_semantics_authenticated": False,
        "source_chronology_authenticated": False,
        "independent_human_review_attested": False,
        "academic_content_validation_attested": False,
        "reference_method_outputs_used": False,
        "confirmed_reference_score": None,
        "a6_operational_accreditation": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def read_file(path, limit):

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW
        | os.O_CLOEXEC | os.O_NONBLOCK,
    )

    try:

        before = os.fstat(fd)

        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and not (before.st_mode & 0o077)
            and 0 < before.st_size <= limit,
            "PRIVATE_FILE_REQUIRED",
        )

        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)

        after = os.fstat(fd)

        need(
            len(raw) == before.st_size
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns,
            "FILE_CHANGED_DURING_READ",
        )

        return raw

    finally:
        os.close(fd)


def from_files(
    document_path,
    manifest_path,
    object_directory,
    *,
    expected_document_sha256,
    expected_manifest_sha256,
):

    need(os.geteuid() != 0, "ROOT_FORBIDDEN")

    directory = Path(object_directory)

    info = directory.lstat()

    need(
        stat.S_ISDIR(info.st_mode)
        and not directory.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "PRIVATE_OBJECT_DIRECTORY_REQUIRED",
    )

    document = r148.decode(
        read_file(document_path, r148.MAX_BYTES)
    )

    manifest = r148.decode(
        read_file(manifest_path, r148.MAX_BYTES)
    )

    need(
        sha(r148.canonical(manifest))
        == expected_manifest_sha256,
        "MANIFEST_PIN_MISMATCH",
    )

    bindings = manifest.get("bindings")

    need(
        type(bindings) is dict
        and len(bindings) <= MAX_SUPPORTS,
        "BINDINGS_INVALID",
    )

    objects = {}
    total = 0

    for digest in bindings.values():

        need(
            type(digest) is str
            and HEX64.fullmatch(digest),
            "SUPPORT_DIGEST_REQUIRED",
        )

        if digest in objects:
            continue

        raw = read_file(
            directory / digest,
            MAX_OBJECT_BYTES,
        )

        total += len(raw)

        need(
            total <= MAX_TOTAL_BYTES,
            "OBJECT_TOTAL_LIMIT",
        )

        objects[digest] = raw

    return evaluate(
        document,
        manifest,
        objects,
        expected_document_sha256=expected_document_sha256,
        expected_manifest_sha256=expected_manifest_sha256,
    )


def main(argv=None):

    parser = argparse.ArgumentParser(
        description="Verificacion documental de soportes I4"
    )

    parser.add_argument("--documento", type=Path, required=True)
    parser.add_argument("--manifiesto", type=Path, required=True)
    parser.add_argument("--objetos", type=Path, required=True)
    parser.add_argument("--documento-sha256", required=True)
    parser.add_argument("--manifiesto-sha256", required=True)

    args = parser.parse_args(argv)

    try:

        report = from_files(
            args.documento,
            args.manifiesto,
            args.objetos,
            expected_document_sha256=args.documento_sha256,
            expected_manifest_sha256=args.manifiesto_sha256,
        )

        sys.stdout.buffer.write(r148.canonical(report))

        return 0

    except (ValueError, OSError, TypeError, KeyError) as exc:

        print(
            "I4_SUPPORT_STOP=" + type(exc).__name__,
            file=sys.stderr,
        )

        return 2


if __name__ == "__main__":
    raise SystemExit(main())
