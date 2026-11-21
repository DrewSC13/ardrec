"""ARDREC R117: read-only reconciliation of interrupted F5B releases.

Requires exact candidate, signed approval and strict tree inventory.

This module never writes, publishes, boots, opens traffic or grants P8.
Caller-provided paths and public keys are not host-root provenance.
"""
from __future__ import annotations

from datetime import datetime
from io import BytesIO
import os
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

import ardrec_r117_release_core_v1 as core


TXN = re.compile(r"\.r117-f5b-transaction-[0-9a-f]{24}\Z")

PILOT = "r117-f4-ftp-pilot-root-v1"
RELEASE = "r117-f4-boot-release-v1"
ACTIVATION = "r117-f5b-activation-v1.json"

MARKERS = {
    "prepared.once": b"PREPARED_NOT_PUBLISHED\n",
    "pilot-visible.once": b"PILOT_VISIBLE_RELEASE_PENDING\n",
    "release-visible.once":
        b"RELEASE_VISIBLE_INSPECTION_REQUIRED\n",
}

F4 = (
    "src/ardrec/coordination/r117_f4_controlled_boot.py",
    "src/ardrec/coordination/r117_f4_runner_ftp_boot.py",
    "src/ardrec/coordination/r117_f4_root_release.py",
)


class Stop(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def present(item):
    return item.exists() or item.is_symlink()


def directory(item):
    info = item.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not item.is_symlink()
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "DIRECTORY_UNTRUSTED_" + str(item),
    )


def regular(item, limit=200000):
    fd = os.open(
        item,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= limit,
            "FILE_UNTRUSTED_" + str(item),
        )
        raw = os.read(fd, limit + 1)
        need(len(raw) == info.st_size,
             "FILE_CHANGED_" + str(item))
        return raw
    finally:
        os.close(fd)


def tree(folder, expected, *, authority=False):
    """Strict inventory and byte comparison for a staged payload."""
    directory(folder)

    expected_dirs = {"."}
    for name in expected:
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            expected_dirs.add(str(parent))
            parent = parent.parent

    if authority:
        expected_dirs.add("authority")

    seen_files = {}
    seen_dirs = {"."}

    for item in folder.rglob("*"):
        relative = item.relative_to(folder).as_posix()
        info = item.lstat()

        if stat.S_ISDIR(info.st_mode):
            directory(item)
            seen_dirs.add(relative)
        elif stat.S_ISREG(info.st_mode):
            need(relative in expected,
                 "UNEXPECTED_PAYLOAD_FILE_" + relative)
            seen_files[relative] = regular(item)
        else:
            raise Stop("UNTRUSTED_TREE_ENTRY_" + relative)

    need(
        seen_dirs == expected_dirs,
        "PAYLOAD_DIRECTORY_INVENTORY_CHANGED",
    )
    need(
        set(seen_files) == set(expected),
        "PAYLOAD_FILE_INVENTORY_CHANGED",
    )

    for name, raw in expected.items():
        need(
            seen_files[name] == raw,
            "PAYLOAD_BYTES_CHANGED_" + name,
        )


def signed_approval(raw, signature, public, pin, head, sha, now):
    doc = core.document(raw)

    need(
        set(doc) == core.APPROVAL_FIELDS
        and doc["schema"] == core.APPROVAL_SCHEMA
        and doc["head"] == head
        and doc["candidate_sha256"] == sha
        and doc["purpose"] == "INSTALL_SOURCE_ONLY"
        and doc["p8"] == "NO-GO"
        and type(doc["authority"]) is str
        and 3 <= len(doc["authority"]) <= 80,
        "APPROVAL_SCOPE_INVALID",
    )

    start = core.utc(doc["valid_from"])
    stop = core.utc(doc["valid_until"])

    need(
        0 < (stop - start).total_seconds() <= 600,
        "APPROVAL_DURATION_INVALID",
    )

    core.verify_signature(
        public, signature, core.PREFIX + raw,
        expected_public_sha=pin,
    )

    return start <= now < stop


def expected_activation(
    head, candidate_sha, txn_name, approval,
    manifest, receipt, completion
):
    return core.canonical({
        "schema": "ARDREC-R117-F5B-ACTIVATION-v1",
        "head": head,
        "transaction": txn_name,
        "candidate_sha256": candidate_sha,
        "approval_sha256": core.sha(approval),
        "pilot_manifest_sha256": core.sha(manifest),
        "receipt_sha256": core.sha(receipt),
        "complete_sha256": core.sha(completion),
        "boot_authorized": False,
        "network_authorized": False,
        "p8": "NO-GO",
    })


def inspect(
    root, candidate, *,
    head, candidate_sha, public, public_sha, now
):
    """Reconcile a release snapshot without changing it.

    The function verifies an unprivileged test tree. Its result is
    not a privileged installation certificate.
    """
    need(isinstance(root, Path) and root.is_absolute(),
         "ABSOLUTE_ROOT_REQUIRED")
    need(
        type(now) is datetime
        and now.tzinfo is not None
        and now.utcoffset().total_seconds() == 0,
        "UTC_NOW_REQUIRED",
    )

    core.verify_candidate(
        candidate,
        head=head,
        expected_sha=candidate_sha,
    )

    directory(root)

    transactions = sorted(
        item for item in root.iterdir()
        if item.name.startswith(".r117-f5b-transaction-")
    )

    need(len(transactions) == 1,
         "TRANSACTION_COUNT_NOT_ONE")

    txn = transactions[0]
    need(TXN.fullmatch(txn.name) is not None,
         "TRANSACTION_NAME_INVALID")
    directory(txn)

    pending_name = (
        ".r117-f5b-activation-pending-" +
        txn.name.removeprefix(".r117-f5b-transaction-")
    )

    pending = root / pending_name
    pending_entries = [
        item for item in root.iterdir()
        if item.name.startswith(".r117-f5b-activation-pending-")
    ]

    need(
        not pending_entries or (
            len(pending_entries) == 1
            and pending_entries[0].name == pending_name
        ),
        "ACTIVATION_PENDING_INVENTORY_INVALID",
    )

    with zipfile.ZipFile(BytesIO(candidate)) as bundle:
        members = {
            name: bundle.read(name)
            for name in bundle.namelist()
        }

    pilot_public = present(root / PILOT)
    release_public = present(root / RELEASE)

    txn_pilot = present(txn / "pilot")
    txn_release = present(txn / "release")

    need(pilot_public != txn_pilot,
         "PILOT_LOCATION_AMBIGUOUS")
    need(release_public != txn_release,
         "RELEASE_LOCATION_AMBIGUOUS")

    pilot_location = (
        root / PILOT if pilot_public else txn / "pilot"
    )
    release_location = (
        root / RELEASE if release_public else txn / "release"
    )

    tree(pilot_location, members, authority=True)

    receipt = core.canonical({
        "schema": "ARDREC-R117-F4-BOOT-RELEASE-v1",
        "head": head,
        "source_sha256": {
            source: core.sha(
                members[
                    "runtime/ardrec/coordination/" +
                    Path(source).name
                ]
            )
            for source in F4
        },
        "pilot_manifest_sha256":
            core.sha(members["manifest.json"]),
        "pilot_schema": core.SCHEMA,
        "p8": "NO-GO",
        "authorized_to_boot": False,
    })

    approval = regular(release_location / "approval.json", 8192)
    signature = regular(release_location / "approval.sig", 64)

    tree(release_location, {
        "receipt.json": receipt,
        "approval.json": approval,
        "approval.sig": signature,
    })

    approval_fresh = signed_approval(
        approval, signature, public, public_sha,
        head, candidate_sha, now
    )

    intent_raw = regular(txn / "intent.json", 8192)
    intent = core.document(intent_raw)

    need(
        set(intent) == {
            "schema", "head", "candidate_sha256",
            "approval_sha256", "status", "p8",
        }
        and intent["schema"] ==
            "ARDREC-R117-F5B-TRANSACTION-v1"
        and intent["head"] == head
        and intent["candidate_sha256"] == candidate_sha
        and intent["approval_sha256"] == core.sha(approval)
        and intent["status"] == "SOURCE_INSTALL_ATTEMPT"
        and intent["p8"] == "NO-GO",
        "INTENT_NOT_AUTHENTIC",
    )

    entries = {item.name for item in txn.iterdir()}
    prepared = "prepared.once" in entries
    pilot_marker = "pilot-visible.once" in entries
    release_marker = "release-visible.once" in entries
    completed = "complete.json" in entries
    activated = present(root / ACTIVATION)

    need(prepared, "PREPARED_MARKER_MISSING")

    for marker, raw in MARKERS.items():
        if marker in entries:
            need(
                regular(txn / marker, 128) == raw,
                "JOURNAL_MARKER_CHANGED_" + marker,
            )

    common = {"intent.json", "prepared.once"}

    if not pilot_public and not release_public:
        need(
            entries == common | {"pilot", "release"},
            "PREPARED_JOURNAL_INVALID",
        )
        need(not completed and not activated and not present(pending),
             "PREPARED_HAS_ACTIVATION")
        phase = "PREPARED_UNPUBLISHED"

    elif pilot_public and not release_public:
        allowed = common | {"release"}
        if pilot_marker:
            allowed.add("pilot-visible.once")

        need(
            entries == allowed
            and not release_marker
            and not completed
            and not activated
            and not present(pending),
            "PILOT_JOURNAL_INVALID",
        )
        phase = "PILOT_ONLY_UNPUBLISHED"

    else:
        need(
            pilot_public and release_public
            and pilot_marker,
            "RELEASE_PUBLICATION_ORDER_INVALID",
        )

        if not completed:
            allowed = common | {"pilot-visible.once"}
            if release_marker:
                allowed.add("release-visible.once")

            need(
                entries == allowed
                and not activated
                and not present(pending),
                "RELEASE_JOURNAL_INVALID",
            )
            phase = "RELEASE_VISIBLE_INCOMPLETE"
        else:
            need(
                entries == common | {
                    "pilot-visible.once",
                    "release-visible.once",
                    "complete.json",
                },
                "COMPLETE_JOURNAL_INVALID",
            )

            complete_raw = regular(
                txn / "complete.json", 8192
            )
            complete = core.document(complete_raw)

            need(
                set(complete) == {
                    "schema", "head",
                    "pilot_manifest_sha256",
                    "receipt_sha256", "approved_install",
                    "boot_permit_issued",
                    "network_connections", "vm_starts", "p8",
                }
                and complete["schema"] ==
                    "ARDREC-R117-F5B-COMPLETE-v1"
                and complete["head"] == head
                and complete["pilot_manifest_sha256"] ==
                    core.sha(members["manifest.json"])
                and complete["receipt_sha256"] ==
                    core.sha(receipt)
                and complete["approved_install"] is True
                and complete["boot_permit_issued"] is False
                and type(complete["network_connections"]) is int
                and complete["network_connections"] == 0
                and type(complete["vm_starts"]) is int
                and complete["vm_starts"] == 0
                and complete["p8"] == "NO-GO",
                "COMPLETE_DOCUMENT_NOT_AUTHENTIC",
            )

            expected = expected_activation(
                head, candidate_sha, txn.name,
                approval, members["manifest.json"],
                receipt, complete_raw
            )

            if present(pending):
                need(
                    regular(pending, 8192) == expected,
                    "PENDING_ACTIVATION_CHANGED",
                )

            if activated:
                need(
                    regular(root / ACTIVATION, 8192) == expected
                    and not present(pending),
                    "ACTIVATION_NOT_AUTHENTIC",
                )
                phase = "ACTIVATED_VERIFIED"
            else:
                phase = "COMPLETE_NOT_ACTIVATED"

    recommendations = {
        "PREPARED_UNPUBLISHED":
            "MANUAL_REVIEW_NO_AUTOMATIC_PUBLICATION",
        "PILOT_ONLY_UNPUBLISHED":
            "MANUAL_REVIEW_NO_AUTOMATIC_PUBLICATION",
        "RELEASE_VISIBLE_INCOMPLETE":
            "MANUAL_REVIEW_NO_AUTOMATIC_PUBLICATION",
        "COMPLETE_NOT_ACTIVATED":
            "ROOT_AUTHENTICATED_ACTIVATION_REQUIRED",
        "ACTIVATED_VERIFIED":
            "NO_REPLAY_REQUIRED",
    }

    return {
        "schema": "ARDREC-R117-RECOVERY-INSPECTION-v1",
        "head": head,
        "candidate_sha256": candidate_sha,
        "phase": phase,
        "transaction": txn.name,
        "file_count_verified": 39,
        "approval_signature": "VALID",
        "approval_fresh_for_new_install": approval_fresh,
        "recommended_action": recommendations[phase],
        "installation_authorized_by_this_inspection": False,
        "physical_root_provenance_attested": False,
        "boot_authorized": False,
        "network_authorized": False,
        "p8": "NO-GO",
    }
