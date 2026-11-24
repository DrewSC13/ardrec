"""Private, chained history of signed documentary revocations.

An independently retained expected head is required.
This is not root-owned trust, operational dispatch or study admission.
"""

from contextlib import contextmanager
from pathlib import Path

import fcntl
import os
import stat

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
    r237_scope_review as scope,
)

from ardrec.experiments import (
    prospective_attempt_journal as journal,
)


SCHEMA = "ARDREC-R240-REVOCATION-HISTORY-v1"
MAX_ENTRIES = 128


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def genesis_document(
    plan_sha256,
    trust_sha256,
    authorization_sha256,
    minimum_sequence,
):
    need(
        all(
            journal.valid_hex(value, 64)
            for value in (
                plan_sha256,
                trust_sha256,
                authorization_sha256,
            )
        ),
        "GENESIS_DIGEST_INVALID",
    )

    need(
        type(minimum_sequence) is int
        and 1 <= minimum_sequence < 2**63,
        "GENESIS_SEQUENCE_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA + "-genesis",
        "plan_sha256": plan_sha256,
        "trust_sha256": trust_sha256,
        "authorization_sha256": authorization_sha256,
        "minimum_sequence": minimum_sequence,
        "operational_authority": False,
        "p8": "NO-GO",
    })


def check_private_file(path):
    info = path.lstat()

    need(
        not path.is_symlink()
        and stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1,
        "PRIVATE_HISTORY_FILE_REQUIRED",
    )


def read_private(path):
    check_private_file(path)

    document = durable.load(path)

    need(
        evidence.verify_digest(document),
        "HISTORY_DIGEST_INVALID",
    )

    return document


def initialize(
    directory,
    *,
    plan_sha256,
    trust_sha256,
    authorization_sha256,
    minimum_sequence,
):
    need(os.geteuid() > 0, "ROOT_FORBIDDEN")

    directory = Path(directory).absolute()

    journal.private_directory(directory.parent)

    genesis = genesis_document(
        plan_sha256,
        trust_sha256,
        authorization_sha256,
        minimum_sequence,
    )

    directory.mkdir(mode=0o700)

    fd = os.open(
        directory / "history.lock",
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | os.O_NOFOLLOW,
        0o600,
    )

    os.close(fd)

    durable.write_once(
        directory / "genesis.json",
        genesis,
    )

    need(
        read_private(directory / "genesis.json")
        == genesis,
        "GENESIS_READBACK_INVALID",
    )

    return genesis["sha256"]


@contextmanager
def locked(directory):
    journal.private_directory(directory)

    path = directory / "history.lock"

    check_private_file(path)

    fd = os.open(
        path,
        os.O_RDWR
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
    )

    try:
        fcntl.flock(fd, fcntl.LOCK_EX)

        current = os.fstat(fd)
        named = path.lstat()

        need(
            current.st_dev == named.st_dev
            and current.st_ino == named.st_ino
            and current.st_uid == os.geteuid()
            and current.st_nlink == 1
            and stat.S_ISREG(current.st_mode)
            and stat.S_IMODE(current.st_mode) == 0o600,
            "HISTORY_LOCK_IDENTITY_INVALID",
        )

        yield

    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def make_entry(index, previous, raw, status):
    return durable.seal({
        "schema": SCHEMA + "-entry",
        "index": index,
        "previous_sha256": previous,
        "revocation_hex": raw.hex(),
        "signed_status": status,
    })


def check_transition(previous, status):
    if previous is None:
        return

    need(
        previous["revoked"] is False,
        "REVOCATION_TERMINAL",
    )

    need(
        status["revocation_sequence"]
        > previous["revocation_sequence"],
        "REVOCATION_SEQUENCE_NOT_INCREASING",
    )

    need(
        status["revocation_issued_at"]
        >= previous["revocation_issued_at"],
        "REVOCATION_ISSUE_TIME_ROLLBACK",
    )

    need(
        status["verified_at"]
        >= previous["verified_at"],
        "OBSERVATION_TIME_ROLLBACK",
    )


def result(head, status, count, replayed):
    return durable.seal({
        "schema": SCHEMA,
        "head_sha256": head,
        "entries": count,
        "revocation_sequence":
            status["revocation_sequence"],
        "revoked": status["revoked"],
        "valid_until": status["valid_until"],
        "replayed": replayed,
        "local_history_verified": True,
        "external_head_pin_matched": True,
        "root_owned_trust_attested": False,
        "trusted_clock_attested": False,
        "operational_authority": False,
        "operational_dispatch": False,
        "historical_authority_granted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "a9_generation": None,
        "experimental_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def record(
    directory,
    *,
    plan,
    trust_raw,
    authorization_raw,
    revocation_raw,
    expected_genesis,
    expected_head,
    now,
):
    need(os.geteuid() > 0, "ROOT_FORBIDDEN")

    need(
        journal.valid_hex(expected_genesis, 64)
        and journal.valid_hex(expected_head, 64),
        "EXTERNAL_HISTORY_PIN_REQUIRED",
    )

    journal.verify_plan(plan)

    directory = Path(directory).absolute()

    with locked(directory):
        genesis = read_private(
            directory / "genesis.json"
        )

        need(
            genesis["sha256"] == expected_genesis,
            "GENESIS_PIN_MISMATCH",
        )

        expected = genesis_document(
            plan["sha256"],
            scope.sha(trust_raw),
            scope.sha(authorization_raw),
            genesis["minimum_sequence"],
        )

        need(
            expected == genesis,
            "HISTORY_SCOPE_MISMATCH",
        )

        def inspect(raw, observed_at, floor):
            return scope.inspect_signed_status(
                plan=plan,
                trust_raw=trust_raw,
                authorization_raw=authorization_raw,
                revocation_raw=raw,
                expected_trust_sha256=
                    genesis["trust_sha256"],
                expected_plan_sha256=
                    genesis["plan_sha256"],
                minimum_revocation_sequence=floor,
                now=observed_at,
            )

        names = {
            item.name
            for item in directory.iterdir()
        }

        names -= {
            "genesis.json",
            "history.lock",
        }

        count = len(names)

        need(
            count <= MAX_ENTRIES
            and names == {
                f"{index:06}.json"
                for index in range(1, count + 1)
            },
            "HISTORY_LAYOUT_INVALID",
        )

        head = genesis["sha256"]
        floor = genesis["minimum_sequence"]
        last = None
        last_raw = None

        # Replay all signed records, in their original chronology.
        for index in range(1, count + 1):
            entry = read_private(
                directory / f"{index:06}.json"
            )

            raw = bytes.fromhex(
                entry["revocation_hex"]
            )

            status = inspect(
                raw,
                entry["signed_status"]["verified_at"],
                floor,
            )

            check_transition(last, status)

            need(
                entry == make_entry(
                    index, head, raw, status
                ),
                "HISTORY_CHAIN_INVALID",
            )

            last = status
            last_raw = raw
            head = entry["sha256"]
            floor = status["revocation_sequence"]

        need(
            head == expected_head,
            "HISTORY_HEAD_PIN_MISMATCH",
        )

        status = inspect(
            revocation_raw,
            now,
            floor,
        )

        if last is not None:
            need(
                status["verified_at"]
                >= last["verified_at"],
                "OBSERVATION_TIME_ROLLBACK",
            )

            if (
                status["revocation_sequence"]
                == last["revocation_sequence"]
            ):
                need(
                    revocation_raw == last_raw,
                    "REVOCATION_EQUIVOCATION",
                )

                return result(
                    head, last, count, True
                )

        check_transition(last, status)

        need(
            count < MAX_ENTRIES,
            "HISTORY_CAPACITY_EXHAUSTED",
        )

        entry = make_entry(
            count + 1,
            head,
            revocation_raw,
            status,
        )

        path = (
            directory
            / f"{count + 1:06}.json"
        )

        durable.write_once(path, entry)

        need(
            read_private(path) == entry,
            "HISTORY_ENTRY_READBACK_INVALID",
        )

        return result(
            entry["sha256"],
            status,
            count + 1,
            False,
        )
