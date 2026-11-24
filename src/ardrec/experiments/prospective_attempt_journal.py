"""R205: local prospective attempt journal.

Software-fixture authorization only. No network dispatch, privileged
authorization, historical gate replacement or technical admission.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import stat
import time

from contextlib import contextmanager
from pathlib import Path

from ardrec.coordination import local_ssh_pilot as ssh
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import prospective_local_pilot as durable


SCHEMA = "ARDREC-R205-PROSPECTIVE-JOURNAL-v1"

PROTOCOLS = ("SSH", "FTP", "SMB")

OPERATIONS = {
    "SSH": "FIXED_DIAGNOSTIC_SUBSYSTEM",
    "FTP": "AUTHORIZED_READ_ONLY_FILE",
    "SMB": "AUTHORIZED_READ_ONLY_FILE",
}

MAX_TTL_SECONDS = 600

STATES = (
    "PLANNED",
    "AUTHORIZED",
    "RESERVED",
    "REVOKED",
    "EXPIRED",
    "UNCERTAIN",
    "RECEIPT_RECORDED_UNVERIFIED",
)


class Refusal(ValueError):
    pass


def need(value, reason):

    if not value:
        raise Refusal(reason)


def clock():

    return int(time.time())


def valid_hex(value, length):

    return (
        type(value) is str
        and re.fullmatch(
            f"[a-f0-9]{{{length}}}",
            value,
        ) is not None
    )


def make_plan(
    *,
    plan_id,
    protocol,
    head,
    tree,
    coverage_sha256,
    runner_sha256,
    fixture_sha256,
    operator_uid,
    created_at,
    expires_at,
):

    need(
        valid_hex(plan_id, 32),
        "PLAN_ID_INVALID",
    )

    need(
        protocol in PROTOCOLS,
        "PROTOCOL_INVALID",
    )

    need(
        valid_hex(head, 40)
        and valid_hex(tree, 40),
        "CODE_IDENTITY_INVALID",
    )

    need(
        all(
            valid_hex(value, 64)
            for value in (
                coverage_sha256,
                runner_sha256,
                fixture_sha256,
            )
        ),
        "SOURCE_IDENTITY_INVALID",
    )

    need(
        type(operator_uid) is int
        and operator_uid > 0,
        "OPERATOR_UID_INVALID",
    )

    need(
        type(created_at) is int
        and type(expires_at) is int
        and created_at > 0
        and 0 < expires_at - created_at <= MAX_TTL_SECONDS,
        "PLAN_VALIDITY_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA + "-plan",
        "plan_id": plan_id,
        "protocol": protocol,
        "operation": OPERATIONS[protocol],
        "code_head": head,
        "code_tree": tree,
        "coverage_sha256": coverage_sha256,
        "runner_sha256": runner_sha256,
        "fixture_sha256": fixture_sha256,
        "operator_uid": operator_uid,
        "created_at": created_at,
        "expires_at": expires_at,
        "destination": "127.0.0.1",
        "scope": "LOCAL_ISOLATED_SOFTWARE_FIXTURE_ONLY",
        "maximum_attempts": 1,
        "baseline_closed": False,
        "historical_authority_granted": False,
        "privileged_execution_authorized": False,
        "experimental_admission": False,
        "p8": "NO-GO",
    })


def verify_plan(plan):

    evidence.verify_digest(plan)

    expected = make_plan(
        plan_id=plan["plan_id"],
        protocol=plan["protocol"],
        head=plan["code_head"],
        tree=plan["code_tree"],
        coverage_sha256=plan["coverage_sha256"],
        runner_sha256=plan["runner_sha256"],
        fixture_sha256=plan["fixture_sha256"],
        operator_uid=plan["operator_uid"],
        created_at=plan["created_at"],
        expires_at=plan["expires_at"],
    )

    need(
        plan == expected,
        "PLAN_SCHEMA_OR_SCOPE_CHANGED",
    )

    return True


def consent_for(plan):

    verify_plan(plan)

    return (
        "AUTORIZO_FIXTURE_LOCAL_R205:"
        + plan["sha256"]
    )


def private_directory(path):

    path = Path(path)

    info = path.lstat()

    need(
        not path.is_symlink()
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "PRIVATE_DIRECTORY_REQUIRED",
    )


class Journal:

    def __init__(self, path, *, create=False):

        need(
            os.geteuid() > 0,
            "ROOT_EXECUTION_FORBIDDEN",
        )

        self.path = Path(path).absolute()

        private_directory(self.path.parent)

        if create:

            fd = os.open(
                self.path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW,
                0o600,
            )

            os.close(fd)

            self._initialize()

            directory = os.open(
                self.path.parent,
                os.O_RDONLY | os.O_DIRECTORY,
            )

            try:

                os.fsync(directory)

            finally:

                os.close(directory)

        self._check_file()

        with self._connection() as conn:

            schema = conn.execute(
                "SELECT value FROM metadata "
                "WHERE name='schema'"
            ).fetchone()

            need(
                schema == (SCHEMA,),
                "JOURNAL_SCHEMA_INVALID",
            )

    def _check_file(self):

        private_directory(self.path.parent)

        info = self.path.lstat()

        need(
            not self.path.is_symlink()
            and stat.S_ISREG(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1,
            "PRIVATE_JOURNAL_REQUIRED",
        )

    @contextmanager
    def _connection(self):

        self._check_file()

        conn = sqlite3.connect(
            self.path,
            timeout=5,
            isolation_level=None,
        )

        try:

            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")

            yield conn

        finally:

            conn.close()

    @contextmanager
    def _transaction(self):

        with self._connection() as conn:

            conn.execute("BEGIN IMMEDIATE")

            try:

                yield conn

                conn.commit()

            except BaseException:

                conn.rollback()
                raise

    def _initialize(self):

        with self._connection() as conn:

            conn.execute("PRAGMA journal_mode=DELETE")

            conn.executescript("""
                BEGIN IMMEDIATE;

                CREATE TABLE metadata (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE plans (
                    plan_id TEXT PRIMARY KEY,
                    plan_sha256 TEXT NOT NULL UNIQUE,
                    document BLOB NOT NULL,
                    state TEXT NOT NULL CHECK (
                        state IN (
                            'PLANNED',
                            'AUTHORIZED',
                            'RESERVED',
                            'REVOKED',
                            'EXPIRED',
                            'UNCERTAIN',
                            'RECEIPT_RECORDED_UNVERIFIED'
                        )
                    ),
                    attempt_count INTEGER NOT NULL
                        DEFAULT 0
                        CHECK (attempt_count IN (0,1)),
                    reservation_sha256 TEXT UNIQUE,
                    receipt_sha256 TEXT UNIQUE,
                    authorized_at INTEGER,
                    reserved_at INTEGER,
                    revoked_at INTEGER
                );

                CREATE TABLE events (
                    sequence INTEGER PRIMARY KEY,
                    plan_id TEXT NOT NULL
                        REFERENCES plans(plan_id),
                    action TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    detail TEXT NOT NULL
                );

                INSERT INTO metadata
                    VALUES (
                        'schema',
                        'ARDREC-R205-PROSPECTIVE-JOURNAL-v1'
                    );

                COMMIT;
            """)

    def _event(
        self, conn, plan_id, action, now, detail=""
    ):

        conn.execute(
            "INSERT INTO events "
            "(plan_id,action,timestamp,detail) "
            "VALUES (?,?,?,?)",
            (plan_id, action, now, detail),
        )

    def _load(self, conn, plan_id):

        need(
            valid_hex(plan_id, 32),
            "PLAN_ID_INVALID",
        )

        row = conn.execute(
            "SELECT document,plan_sha256,state,"
            "attempt_count,reservation_sha256,"
            "receipt_sha256,authorized_at,"
            "reserved_at,revoked_at "
            "FROM plans WHERE plan_id=?",
            (plan_id,),
        ).fetchone()

        need(
            row is not None,
            "PLAN_NOT_FOUND",
        )

        doc = json.loads(row[0])

        verify_plan(doc)

        need(
            doc["plan_id"] == plan_id
            and doc["sha256"] == row[1]
            and row[0] == ssh.canonical(doc)
            and doc["operator_uid"] == os.geteuid(),
            "PLAN_BINDING_INVALID",
        )

        return {
            "plan": doc,
            "state": row[2],
            "attempt_count": row[3],
            "reservation_sha256": row[4],
            "receipt_sha256": row[5],
            "authorized_at": row[6],
            "reserved_at": row[7],
            "revoked_at": row[8],
        }

    def register(self, plan):

        verify_plan(plan)

        need(
            plan["operator_uid"] == os.geteuid(),
            "OPERATOR_MISMATCH",
        )

        with self._transaction() as conn:

            now = clock()

            need(
                plan["created_at"] <= now
                    < plan["expires_at"],
                "PLAN_NOT_CURRENT",
            )

            conn.execute(
                "INSERT INTO plans "
                "(plan_id,plan_sha256,document,state) "
                "VALUES (?,?,?,'PLANNED')",
                (
                    plan["plan_id"],
                    plan["sha256"],
                    ssh.canonical(plan),
                ),
            )

            self._event(
                conn,
                plan["plan_id"],
                "REGISTERED",
                now,
            )

    def authorize(self, plan_id, consent):

        with self._transaction() as conn:

            row = self._load(conn, plan_id)
            plan = row["plan"]

            now = clock()

            need(
                row["state"] == "PLANNED"
                and row["attempt_count"] == 0,
                "PLAN_NOT_AUTHORIZABLE",
            )

            need(
                plan["created_at"] <= now
                    < plan["expires_at"],
                "PLAN_NOT_CURRENT",
            )

            need(
                consent == consent_for(plan),
                "EXPLICIT_CONSENT_REQUIRED",
            )

            conn.execute(
                "UPDATE plans SET "
                "state='AUTHORIZED',authorized_at=? "
                "WHERE plan_id=?",
                (now, plan_id),
            )

            self._event(
                conn,
                plan_id,
                "LOCAL_CONSENT_RECORDED",
                now,
                plan["sha256"],
            )

    def reserve(
        self, plan_id, *, head, tree, runner_sha256
    ):

        expired = False
        token = None

        with self._transaction() as conn:

            row = self._load(conn, plan_id)
            plan = row["plan"]

            now = clock()

            need(
                row["state"] == "AUTHORIZED"
                and row["attempt_count"] == 0
                and row["revoked_at"] is None,
                "ATTEMPT_NOT_AVAILABLE",
            )

            need(
                row["authorized_at"] is not None
                and plan["created_at"]
                    <= row["authorized_at"]
                    <= now,
                "AUTHORIZATION_TIME_INVALID",
            )

            need(
                head == plan["code_head"]
                and tree == plan["code_tree"]
                and runner_sha256 ==
                    plan["runner_sha256"],
                "RUNTIME_IDENTITY_MISMATCH",
            )

            if now >= plan["expires_at"]:

                conn.execute(
                    "UPDATE plans SET state='EXPIRED' "
                    "WHERE plan_id=?",
                    (plan_id,),
                )

                self._event(
                    conn, plan_id, "EXPIRED", now
                )

                expired = True

            else:

                token = secrets.token_hex(32)

                token_hash = ssh.digest(
                    token.encode("ascii")
                )

                changed = conn.execute(
                    "UPDATE plans SET "
                    "state='RESERVED',attempt_count=1,"
                    "reservation_sha256=?,reserved_at=? "
                    "WHERE plan_id=? "
                    "AND state='AUTHORIZED' "
                    "AND attempt_count=0",
                    (token_hash, now, plan_id),
                )

                need(
                    changed.rowcount == 1,
                    "ATTEMPT_RESERVATION_CONFLICT",
                )

                self._event(
                    conn,
                    plan_id,
                    "ATTEMPT_RESERVED",
                    now,
                    token_hash,
                )

        need(
            not expired,
            "AUTHORIZATION_EXPIRED",
        )

        return token

    def revoke(self, plan_id):

        with self._transaction() as conn:

            row = self._load(conn, plan_id)

            now = clock()

            need(
                row["state"] in (
                    "PLANNED",
                    "AUTHORIZED",
                    "RESERVED",
                ),
                "REVOCATION_NOT_APPLICABLE",
            )

            next_state = (
                "UNCERTAIN"
                if row["state"] == "RESERVED"
                else "REVOKED"
            )

            conn.execute(
                "UPDATE plans SET state=?,revoked_at=? "
                "WHERE plan_id=?",
                (next_state, now, plan_id),
            )

            self._event(
                conn,
                plan_id,
                "REVOKED",
                now,
                next_state,
            )

    def _reserved(self, conn, plan_id, token):

        row = self._load(conn, plan_id)

        need(
            valid_hex(token, 64),
            "RESERVATION_TOKEN_INVALID",
        )

        need(
            row["state"] == "RESERVED"
            and row["attempt_count"] == 1
            and row["revoked_at"] is None
            and row["reservation_sha256"] ==
                ssh.digest(token.encode("ascii")),
            "RESERVATION_NOT_ACTIVE",
        )

        return row

    def record_receipt(
        self, plan_id, token, receipt_sha256
    ):

        need(
            valid_hex(receipt_sha256, 64),
            "RECEIPT_IDENTITY_INVALID",
        )

        with self._transaction() as conn:

            row = self._reserved(
                conn, plan_id, token
            )

            now = clock()

            need(
                row["reserved_at"] is not None
                and now >= row["reserved_at"],
                "RECEIPT_TIME_INVALID",
            )

            conn.execute(
                "UPDATE plans SET "
                "state='RECEIPT_RECORDED_UNVERIFIED',"
                "receipt_sha256=? WHERE plan_id=?",
                (receipt_sha256, plan_id),
            )

            self._event(
                conn,
                plan_id,
                "RECEIPT_RECORDED_UNVERIFIED",
                now,
                receipt_sha256,
            )

    def mark_uncertain(self, plan_id, token):

        with self._transaction() as conn:

            self._reserved(
                conn, plan_id, token
            )

            conn.execute(
                "UPDATE plans SET state='UNCERTAIN' "
                "WHERE plan_id=?",
                (plan_id,),
            )

            self._event(
                conn,
                plan_id,
                "ATTEMPT_UNCERTAIN",
                clock(),
            )

    def snapshot(self, plan_id):

        with self._connection() as conn:

            conn.execute("BEGIN")

            row = self._load(conn, plan_id)

            events = conn.execute(
                "SELECT sequence,action,timestamp,detail "
                "FROM events WHERE plan_id=? "
                "ORDER BY sequence",
                (plan_id,),
            ).fetchall()

            result = {
                "plan_sha256": row["plan"]["sha256"],
                "plan_id": plan_id,
                "protocol": row["plan"]["protocol"],
                "state": row["state"],
                "attempt_count": row["attempt_count"],
                "receipt_sha256": row["receipt_sha256"],
                "events": [
                    {
                        "sequence": event[0],
                        "action": event[1],
                        "timestamp": event[2],
                        "detail": event[3],
                    }
                    for event in events
                ],
                "receipt_technically_validated": False,
                "operational_a5_admitted": False,
                "a6": "ND",
                "confirmed_rf": None,
                "operational_a9_published": False,
                "experimental_admission": False,
                "p8": "NO-GO",
            }

            conn.commit()

            return durable.seal(result)
