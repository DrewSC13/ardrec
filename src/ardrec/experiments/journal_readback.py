"""R294: readback historico de diarios R205.

No reserva intentos, no realiza operaciones y no concede autoridad.
"""
import hashlib
import os
import sqlite3
import stat
import tempfile

from contextlib import closing
from pathlib import Path

from ardrec.experiments import prospective_attempt_journal as native
from ardrec.coordination import prospective_local_pilot as durable

SCHEMA = "ARDREC-R294-JOURNAL-READBACK-v1"
MAX_BYTES = 32 * 1024 * 1024
MAX_PLANS = 1024


def need(condition, code):
    if not condition:
        raise ValueError(code)


def identity(info):
    return (
        info.st_dev, info.st_ino, info.st_mode,
        info.st_uid, info.st_gid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def no_sidecars(path):
    for suffix in ("-wal", "-shm", "-journal"):
        need(
            not os.path.lexists(str(path) + suffix),
            "JOURNAL_SIDECAR_PRESENT",
        )


def original_bytes(path, expected):
    need(os.geteuid() > 0, "ROOT_FORBIDDEN")
    need(native.valid_hex(expected, 64), "PIN_INVALID")

    path = Path(path)
    need(
        path.is_absolute() and path.resolve(strict=True) == path,
        "SOURCE_PATH_INVALID",
    )

    no_sidecars(path)

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW |
        os.O_NONBLOCK | os.O_CLOEXEC,
    )
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_nlink == 1
            and 0 < before.st_size <= MAX_BYTES,
            "SOURCE_FILE_INVALID",
        )

        data = bytearray()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            data.extend(block)
            need(len(data) <= MAX_BYTES, "SOURCE_TOO_LARGE")

        after = os.fstat(fd)
        named = path.lstat()

        need(
            identity(before) == identity(after) == identity(named)
            and len(data) == before.st_size,
            "SOURCE_CHANGED",
        )

        raw = bytes(data)

        need(
            hashlib.sha256(raw).hexdigest() == expected,
            "SOURCE_PIN_MISMATCH",
        )

        no_sidecars(path)
        return raw

    finally:
        os.close(fd)


def reconcile(snapshot):
    state = None
    attempts = 0
    receipt = None
    reservation = None
    dispatch_claimed = False
    last_sequence = 0
    last_time = None
    issues = []
    events = []

    for event in snapshot["events"]:
        seq = event["sequence"]
        action = event["action"]
        timestamp = event["timestamp"]
        detail = event["detail"]

        need(
            type(seq) is int and seq > last_sequence
            and type(timestamp) is int and timestamp > 0,
            "EVENT_IDENTITY_INVALID",
        )

        if last_time is not None and timestamp < last_time:
            issues.append("UTC_REGRESSION:" + str(seq))

        if action == "REGISTERED" and state is None:
            state = "PLANNED"

        elif action == "LOCAL_CONSENT_RECORDED" and state == "PLANNED":
            need(
                detail == snapshot["plan_sha256"],
                "CONSENT_BINDING_INVALID",
            )
            state = "AUTHORIZED"

        elif action == "ATTEMPT_RESERVED" and state == "AUTHORIZED":
            need(
                attempts == 0 and native.valid_hex(detail, 64),
                "RESERVATION_INVALID",
            )
            attempts = 1
            reservation = detail
            state = "RESERVED"

        elif action == "DISPATCH_CLAIMED":
            need(
                state == "RESERVED" and attempts == 1,
                "HISTORICAL_DISPATCH_STATE_INVALID",
            )
            need(
                not dispatch_claimed,
                "HISTORICAL_DISPATCH_DUPLICATE",
            )
            need(
                reservation is not None
                and native.valid_hex(detail, 64)
                and detail == reservation,
                "HISTORICAL_DISPATCH_BINDING_INVALID",
            )
            dispatch_claimed = True
            # Historical metadata only: no state change,
            # no new reservation and no current authority.

        elif action == "EXPIRED" and state == "AUTHORIZED":
            state = "EXPIRED"

        elif action == "REVOKED" and state in (
            "PLANNED", "AUTHORIZED", "RESERVED"
        ):
            state = "UNCERTAIN" if state == "RESERVED" else "REVOKED"
            need(detail == state, "REVOCATION_STATE_INVALID")

        elif action == "ATTEMPT_UNCERTAIN" and state == "RESERVED":
            state = "UNCERTAIN"

        elif action == "RECEIPT_RECORDED_UNVERIFIED" and state == "RESERVED":
            need(native.valid_hex(detail, 64), "RECEIPT_INVALID")
            receipt = detail
            state = "RECEIPT_RECORDED_UNVERIFIED"

        else:
            raise ValueError("EVENT_TRANSITION_INVALID:" + str(action))

        events.append({
            "sequence": seq,
            "action": action,
            "timestamp": timestamp,
        })
        last_sequence = seq
        last_time = timestamp

    need(
        state == snapshot["state"]
        and attempts == snapshot["attempt_count"]
        and receipt == snapshot["receipt_sha256"],
        "JOURNAL_RECONCILIATION_MISMATCH",
    )

    return {
        "plan_id": snapshot["plan_id"],
        "plan_sha256": snapshot["plan_sha256"],
        "protocol": snapshot["protocol"],
        "state": state,
        "attempt_count": attempts,
        "receipt_sha256": receipt,
        "native_snapshot_sha256": snapshot["sha256"],
        "events": events,
        "chronology_issues": issues,
        "receipt_technically_validated": False,
        "current_authority": "ND",
    }


def evaluate(path, expected_sha256):
    raw = original_bytes(path, expected_sha256)

    with tempfile.TemporaryDirectory(prefix="ardrec-r294-") as tmp:
        copy = Path(tmp) / "journal.sqlite3"

        fd = os.open(
            copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)

        with closing(sqlite3.connect(
            copy.as_uri() + "?mode=ro", uri=True
        )) as db:
            need(
                db.execute("PRAGMA integrity_check").fetchall()
                == [("ok",)],
                "SQLITE_INTEGRITY_INVALID",
            )
            need(
                db.execute("PRAGMA foreign_key_check").fetchall() == [],
                "SQLITE_FOREIGN_KEY_INVALID",
            )

            plan_ids = [
                row[0] for row in db.execute(
                    "SELECT plan_id FROM plans ORDER BY plan_id LIMIT ?",
                    (MAX_PLANS + 1,),
                )
            ]

        need(len(plan_ids) <= MAX_PLANS, "PLAN_LIMIT_EXCEEDED")

        journal = native.Journal(copy)
        records = [
            reconcile(journal.snapshot(plan_id))
            for plan_id in plan_ids
        ]

    need(
        original_bytes(path, expected_sha256) == raw,
        "ORIGINAL_CHANGED_AFTER_READBACK",
    )

    counts = {state: 0 for state in native.STATES}
    for record in records:
        counts[record["state"]] += 1

    return durable.seal({
        "schema": SCHEMA,
        "scope": "HISTORICAL_LOCAL_JOURNAL_ONLY",
        "source_sha256": expected_sha256,
        "source_bytes": len(raw),
        "original_preserved": True,
        "plans": len(records),
        "historical_reservations": sum(
            record["attempt_count"] for record in records
        ),
        "states": counts,
        "records": records,
        "current_authority": "ND",
        "operational_dispatch": False,
        "new_attempts": 0,
        "new_observations": 0,
        "a6": "ND",
        "confirmed_rf": None,
        "a9": "NOT_PUBLISHED",
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })


def render_text(report):
    lines = [
        "ARDREC / R294 / REAPERTURA HISTORICA A5",
        "SCOPE=" + report["scope"],
        "SOURCE_SHA256=" + report["source_sha256"],
        "PLANS=" + str(report["plans"]),
        "HISTORICAL_RESERVATIONS=" +
            str(report["historical_reservations"]),
    ]

    for state, count in sorted(report["states"].items()):
        lines.append(state + "=" + str(count))

    for row in report["records"]:
        lines.append(
            "PLAN=" + row["plan_id"]
            + " PROTOCOL=" + row["protocol"]
            + " STATE=" + row["state"]
            + " ATTEMPTS=" + str(row["attempt_count"])
        )
        lines.append(
            "NATIVE_SNAPSHOT_SHA256=" + row["native_snapshot_sha256"]
        )
        for issue in row["chronology_issues"]:
            lines.append("CHRONOLOGY_ISSUE=" + issue)

    lines.extend([
        "ORIGINAL_PRESERVED=YES",
        "CURRENT_AUTHORITY=ND",
        "NEW_ATTEMPTS=0",
        "NEW_OBSERVATIONS=0",
        "A6=ND",
        "RF_CONFIRMED=ND",
        "A9=NOT_PUBLISHED",
        "P7=DRAFT_NOT_FROZEN",
        "P8=NO-GO",
        "REPORT_SHA256=" + report["sha256"],
    ])

    return "\n".join(lines) + "\n"
