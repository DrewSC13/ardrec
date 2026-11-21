"""ARDREC R117 release integrity and cryptographic approval core.

Pure source-only admission. No Git, host installation, VM, network,
external command from archive, shell, P8 or root authorization.

A passing verification against a caller-supplied key is NOT proof
that the key was provisioned independently on the host.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile

SCHEMA = "ARDREC-R117-F4-ROOT-FTP-PILOT-v1-root-bundle"
APPROVAL_SCHEMA = "ARDREC-R117-F5B-ROOT-INSTALL-APPROVAL-v1"
PREFIX = b"ARDREC-R117-F5B-ROOT-RELEASE-APPROVAL-v1\x00"
R116 = "fdb6efa0c297ce18b28cddb9494514f51d88bdb4"
LOCK = b"R117_F4_ROOT_LOCK_V1\n"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_NAME = re.compile(
    r"(?:root-pilot\.py|runtime/ardrec/"
    r"(?:coordination|evidence)/[a-z0-9_]+\.py)\Z"
)
MANIFEST_FIELDS = {
    "schema", "head", "base", "source_sha256", "p8", "a6",
    "window_seconds", "network_automatic", "authority_paths",
    "catalog_sha256",
}
APPROVAL_FIELDS = {
    "schema", "head", "candidate_sha256", "valid_from",
    "valid_until", "purpose", "authority", "p8",
}


class Stop(ValueError):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(doc):
    return (
        json.dumps(
            doc, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ) + "\n"
    ).encode("ascii")


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def document(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 8192,
         "DOCUMENT_SIZE_INVALID")
    try:
        doc = json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _:
                (_ for _ in ()).throw(Stop("NONFINITE_JSON")),
        )
        need(type(doc) is dict and canonical(doc) == raw,
             "DOCUMENT_NOT_CANONICAL")
    except (UnicodeError, TypeError, OverflowError, ValueError) as e:
        raise Stop("DOCUMENT_INVALID") from e
    return doc


def utc(value):
    need(
        type(value) is str
        and re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value
        ) is not None,
        "INVALID_UTC_FORMAT",
    )
    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as e:
        raise Stop("INVALID_UTC_DATE") from e


def verify_candidate(raw, *, head, expected_sha):
    """Verify the entire immutable ZIP without using the checkout."""
    need(type(head) is str and HEX40.fullmatch(head),
         "HEAD_INVALID")
    need(type(expected_sha) is str and HEX64.fullmatch(expected_sha),
         "CANDIDATE_SHA_INVALID")
    need(type(raw) is bytes and 0 < len(raw) <= 2_000_000,
         "CANDIDATE_SIZE_INVALID")
    need(sha(raw) == expected_sha, "CANDIDATE_HASH_CHANGED")

    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]

            need(
                len(names) == len(set(names)) == 39,
                "CANDIDATE_NOT_39_UNIQUE_FILES",
            )
            need(names == sorted(names),
                 "CANDIDATE_ENTRY_ORDER_INVALID")

            items = {}
            for entry in entries:
                name = entry.filename
                path = PurePosixPath(name)

                need(
                    re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                    and not name.startswith("/")
                    and ".." not in path.parts
                    and "." not in path.parts
                    and not entry.is_dir()
                    and entry.create_system == 3
                    and entry.date_time ==
                        (1980, 1, 1, 0, 0, 0)
                    and (entry.external_attr >> 16) ==
                        0o100600
                    and entry.compress_type == zipfile.ZIP_STORED
                    and not (entry.flag_bits & 1)
                    and 0 < entry.file_size <= 200_000,
                    "UNTRUSTED_ARCHIVE_ENTRY",
                )
                items[name] = archive.read(entry)

    except (
        zipfile.BadZipFile, RuntimeError, OSError,
        UnicodeError, EOFError, ValueError
    ) as e:
        if isinstance(e, Stop):
            raise
        raise Stop("CANDIDATE_ZIP_INVALID") from e

    need(
        "manifest.json" in items
        and "catalog.json" in items
        and "lock" in items,
        "CANDIDATE_REQUIRED_FILES_MISSING",
    )

    manifest = document(items["manifest.json"])
    need(set(manifest) == MANIFEST_FIELDS,
         "MANIFEST_FIELDS_CHANGED")

    need(
        manifest["schema"] == SCHEMA
        and manifest["head"] == head
        and manifest["base"] == R116
        and manifest["p8"] == "NO-GO"
        and manifest["a6"] == "ND"
        and type(manifest["window_seconds"]) is int
        and manifest["window_seconds"] == 60
        and manifest["network_automatic"] is False
        and manifest["authority_paths"] == [
            "contract.json",
            "scope-authorization.json",
            "pilot-permit.json",
        ],
        "MANIFEST_SCOPE_INVALID",
    )

    hashes = manifest["source_sha256"]
    need(type(hashes) is dict and len(hashes) == 36,
         "SOURCE_COUNT_INVALID")
    need(
        all(
            type(name) is str
            and SOURCE_NAME.fullmatch(name)
            and type(value) is str
            and HEX64.fullmatch(value)
            for name, value in hashes.items()
        ),
        "SOURCE_ENTRIES_INVALID",
    )

    need(
        set(items) == set(hashes) |
            {"manifest.json", "catalog.json", "lock"},
        "CANDIDATE_SCOPE_MISMATCH",
    )

    for name, expected in hashes.items():
        need(sha(items[name]) == expected,
             "SOURCE_DIGEST_MISMATCH_" + name)

    need(
        type(manifest["catalog_sha256"]) is str
        and HEX64.fullmatch(manifest["catalog_sha256"])
        and sha(items["catalog.json"]) ==
            manifest["catalog_sha256"],
        "CATALOG_DIGEST_INVALID",
    )
    need(items["lock"] == LOCK, "CANDIDATE_LOCK_INVALID")

    return {
        "head": head,
        "candidate_sha256": expected_sha,
        "file_count": 39,
        "source_count": 36,
        "manifest_sha256": sha(items["manifest.json"]),
        "catalog_sha256": sha(items["catalog.json"]),
        "p8": "NO-GO",
        "a6": "ND",
    }


def approval_fields(raw, *, head, candidate_sha, now):
    need(
        type(now) is datetime
        and now.tzinfo is not None
        and now.utcoffset().total_seconds() == 0,
        "VERIFICATION_TIME_INVALID",
    )
    doc = document(raw)
    need(set(doc) == APPROVAL_FIELDS,
         "APPROVAL_FIELDS_INVALID")

    need(
        doc["schema"] == APPROVAL_SCHEMA
        and doc["head"] == head
        and doc["candidate_sha256"] == candidate_sha
        and doc["purpose"] == "INSTALL_SOURCE_ONLY"
        and doc["p8"] == "NO-GO"
        and type(doc["authority"]) is str
        and 3 <= len(doc["authority"]) <= 80,
        "APPROVAL_SCOPE_INVALID",
    )

    start = utc(doc["valid_from"])
    stop = utc(doc["valid_until"])
    need(
        start <= now < stop
        and 0 < (stop - start).total_seconds() <= 600,
        "APPROVAL_WINDOW_INVALID",
    )
    return doc


def verify_signature(
    public_pem, signature, signed_bytes, *,
    expected_public_sha
):
    need(
        hasattr(os, "memfd_create"),
        "LINUX_MEMFD_REQUIRED",
    )
    need(
        type(public_pem) is bytes
        and 0 < len(public_pem) <= 4096
        and type(signature) is bytes
        and len(signature) == 64
        and type(signed_bytes) is bytes
        and 0 < len(signed_bytes) <= 8192
        and type(expected_public_sha) is str
        and HEX64.fullmatch(expected_public_sha),
        "SIGNATURE_INPUT_INVALID",
    )
    need(
        sha(public_pem) == expected_public_sha,
        "APPROVAL_PUBLIC_KEY_PIN_MISMATCH",
    )

    descriptors = []
    try:
        for label, data in (
            ("key", public_pem),
            ("signature", signature),
            ("message", signed_bytes),
        ):
            fd = os.memfd_create(
                "ardrec-r117-" + label, os.MFD_CLOEXEC
            )
            descriptors.append(fd)
            need(
                os.write(fd, data) == len(data),
                "MEMFD_WRITE_INCOMPLETE",
            )
            os.lseek(fd, 0, os.SEEK_SET)

        paths = [
            "/proc/self/fd/" + str(fd)
            for fd in descriptors
        ]

        converted = subprocess.run(
            [
                "/usr/bin/openssl", "pkey",
                "-pubin", "-in", paths[0],
                "-outform", "DER",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            pass_fds=tuple(descriptors),
            timeout=10,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        need(
            converted.returncode == 0
            and len(converted.stdout) == 44
            and converted.stdout.startswith(SPKI_PREFIX),
            "PUBLIC_KEY_NOT_ED25519",
        )

        checked = subprocess.run(
            [
                "/usr/bin/openssl", "pkeyutl",
                "-verify", "-rawin", "-pubin",
                "-inkey", paths[0],
                "-sigfile", paths[1],
                "-in", paths[2],
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            pass_fds=tuple(descriptors),
            timeout=10,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )

        need(
            checked.returncode == 0,
            "APPROVAL_SIGNATURE_INVALID",
        )

    except (OSError, subprocess.TimeoutExpired) as e:
        raise Stop("CRYPTO_VERIFIER_FAILED") from e
    finally:
        for fd in descriptors:
            os.close(fd)

    return True


def verify_signed_candidate(
    candidate, approval_raw, signature, public_pem, *,
    head, candidate_sha, public_sha, now
):
    report = verify_candidate(
        candidate, head=head, expected_sha=candidate_sha
    )
    approval_fields(
        approval_raw,
        head=head,
        candidate_sha=candidate_sha,
        now=now,
    )
    verify_signature(
        public_pem, signature, PREFIX + approval_raw,
        expected_public_sha=public_sha,
    )
    return {
        **report,
        "approval_signature": "VALID",
        "approval_public_sha256": public_sha,
        "root_provenance_attested": False,
        "independent_custody_attested": False,
        "root_install_executed": False,
        "boot_authorized": False,
        "network_authorized": False,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive-only", action="store_true")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()

    try:
        need(args.archive_only, "ARCHIVE_ONLY_MODE_REQUIRED")
        need(os.geteuid() != 0, "OFFLINE_MUST_NOT_RUN_AS_ROOT")
        need(
            args.archive.is_file()
            and not args.archive.is_symlink(),
            "ARCHIVE_PATH_INVALID",
        )
        data = args.archive.read_bytes()
        report = verify_candidate(
            data,
            head=args.head,
            expected_sha=args.sha256,
        )
        print(
            "R117_INSTALL_CORE_ARCHIVE=" +
            json.dumps(report, sort_keys=True)
        )
        print("R117_INSTALL_CORE_SIGNED_APPROVAL=NOT_PROVIDED")
        print("R117_INSTALL_CORE_ROOT_INSTALL=NOT_EXECUTED")
        print("R117_INSTALL_CORE_P8=NO-GO")
        return 0
    except (Stop, OSError, TypeError, KeyError) as e:
        print(
            "R117_INSTALL_CORE_STOP=" +
            type(e).__name__ + ":" + str(e)[:160]
        )
        print("R117_INSTALL_CORE_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
