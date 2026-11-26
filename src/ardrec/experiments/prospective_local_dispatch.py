"""R206: one-shot local fixture dispatch and conservative reporting.

No historical authorization, external targets, operational evidence
admission or experimental admission.
"""
from __future__ import annotations

import os
import stat
import json
import subprocess

from pathlib import Path

from ardrec.experiments import prospective_attempt_journal as journal
from ardrec.experiments import functional_ftp_fixture as ftp
from ardrec.coordination import local_ssh_pilot as ssh
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import prospective_local_pilot as durable

from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge,
    verify_unit_bridge,
)

from ardrec.stopping.development_stop import (
    preview_stop,
    verify_stop,
)


SCHEMA = "ARDREC-R206-LOCAL-DISPATCH-v1"

COVERAGE_PIN = (
    "afb022ba18f85c335ef855e2a9f7eabb7"
    "c5d5387488b60ec05189caf0894b7e1"
)

WEIGHTS = ("1/3", "1/3", "1/3")


def need(condition, reason):

    if not condition:
        raise journal.Refusal(reason)


class DispatchJournal(journal.Journal):

    def claim_dispatch(self, plan_id, token, *, expected_plan_sha256=None):

        with self._transaction() as conn:

            row = self._reserved(
                conn, plan_id, token
            )

            plan = row["plan"]
            if expected_plan_sha256 is not None:
                need(plan["sha256"] == expected_plan_sha256, "JOURNAL_PLAN_PIN_MISMATCH")

            now = journal.clock()

            need(
                row["reserved_at"] is not None
                and row["reserved_at"] <= now
                and now < plan["expires_at"],
                "DISPATCH_AUTHORIZATION_EXPIRED",
            )

            previous = conn.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE plan_id=? AND action=?",
                (plan_id, "DISPATCH_CLAIMED"),
            ).fetchone()[0]

            need(
                previous == 0,
                "DISPATCH_ALREADY_CLAIMED",
            )

            self._event(
                conn,
                plan_id,
                "DISPATCH_CLAIMED",
                now,
                row["reservation_sha256"],
            )

        return True


def private_bytes(path, limit, *, private=True):
    """Read a bounded, owner-controlled regular file without following aliases."""
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path,
         "SOURCE_PATH_ALIAS")
    if private:
        journal.private_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        def identity(st):
            return (st.st_dev, st.st_ino, st.st_uid, st.st_mode, st.st_nlink,
                    st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        mode = stat.S_IMODE(before.st_mode)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
             and before.st_nlink == 1 and (mode == 0o600 if private else mode in (0o400, 0o440, 0o444, 0o600, 0o640, 0o644))
             and 0 < before.st_size <= limit, "SOURCE_OWNER_MODE_SIZE_INVALID")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(limit + 1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), "SOURCE_CHANGED_DURING_READ")
        return raw
    finally:
        os.close(fd)


def private_document(path):
    raw = private_bytes(path, 262144)
    value = json.loads(raw)
    need(raw == ssh.canonical(value) + b"\n", "NONCANONICAL_DOCUMENT")
    evidence.verify_digest(value)
    return value


def check_plan_snapshot(database, plan, state, attempts):
    snapshot = database.snapshot(plan["plan_id"])
    need(snapshot["plan_sha256"] == plan["sha256"] and snapshot["protocol"] == plan["protocol"],
         "JOURNAL_PLAN_PIN_MISMATCH")
    need(snapshot["state"] == state and snapshot["attempt_count"] == attempts,
         "JOURNAL_PLAN_STATE_INVALID")
    return snapshot


def verify_ftp_archive(archive):
    from ardrec.coordination import local_protocol_pilot as transport
    raw = private_bytes(Path(archive).absolute(), transport.FTP_SOURCE_MAX_BYTES, private=False)
    need(ssh.digest(raw) == transport.FTP_SOURCE_SHA256, "FTP_SOURCE_SHA256_INVALID")


def verify_checkout(plan):

    def git(*args):

        return subprocess.check_output(
            ["/usr/bin/git", *args],
            stdin=subprocess.DEVNULL,
            timeout=5,
        ).decode("ascii").strip()

    need(
        git("rev-parse", "HEAD") == plan["code_head"]
        and git("rev-parse", "HEAD^{tree}") ==
            plan["code_tree"]
        and not git("status", "--porcelain=v1"),
        "CHECKOUT_IDENTITY_INVALID",
    )

    return True


def verify_coverage(coverage):

    evidence.verify_digest(coverage)

    need(
        coverage["sha256"] == COVERAGE_PIN
        and coverage["functional_protocols_verified"] == 3
        and coverage["historical_authority_granted"] is False
        and coverage["experimental_observations_admitted"] == 0
        and coverage["p8"] == "NO-GO",
        "COVERAGE_INVALID",
    )

    return True


def validate_ftp_plan(plan, coverage):

    journal.verify_plan(plan)
    verify_coverage(coverage)

    need(
        plan["protocol"] == "FTP"
        and plan["coverage_sha256"] ==
            coverage["sha256"]
        and plan["runner_sha256"] ==
            ssh.digest(ftp.RUNNER.encode("ascii"))
        and plan["fixture_sha256"] ==
            ssh.digest(ftp.PAYLOAD)
        and plan["operator_uid"] == os.geteuid(),
        "FTP_PLAN_BINDING_INVALID",
    )

    return True


def validate_result(folder, plan, consolidation):

    folder = Path(folder)

    internal_plan = durable.load(
        folder / "plan.json"
    )

    intent = durable.load(
        folder / "intent.json"
    )

    result = durable.load(
        folder / "result.json"
    )

    for document in (
        internal_plan, intent, result
    ):

        evidence.verify_digest(document)

    need(
        internal_plan["code_head"] ==
            plan["code_head"]
        and internal_plan["prior_consolidation_sha256"] ==
            consolidation["sha256"]
        and internal_plan["runner_sha256"] ==
            plan["runner_sha256"]
        and internal_plan["fixture_sha256"] ==
            plan["fixture_sha256"]
        and intent["plan_sha256"] ==
            internal_plan["sha256"]
        and intent["attempt"] == 1
        and result["plan_sha256"] ==
            internal_plan["sha256"]
        and result["intent_sha256"] ==
            intent["sha256"]
        and internal_plan["created_at_utc"]
            <= intent["reserved_at_utc"]
            <= result["completed_at_utc"],
        "FUNCTIONAL_RESULT_BINDING_INVALID",
    )

    need(
        result["status"] ==
            "AUTHORIZED_READ_TRANSFER_VERIFIED"
        and result["temporary_workspace_removed"] is True
        and result["historical_authority_granted"] is False
        and result["operational_a5_admitted"] is False
        and result["a6"] == "ND"
        and result["confirmed_rf"] is None
        and result["operational_a9_published"] is False
        and result["experimental_admission"] is False
        and result["p8"] == "NO-GO",
        "FUNCTIONAL_RESULT_AUTHORITY_INVALID",
    )

    ftp.verify_observation(
        result["observation"],
        internal_plan["host_namespace"],
    )

    return result


def dispatch_ftp(
    database,
    plan,
    coverage,
    consolidation,
    archive,
    folder,
    consent,
):

    validate_ftp_plan(plan, coverage)
    evidence.verify_digest(consolidation)
    verify_checkout(plan)

    need(
        consolidation["assessments_reproduced"] == 3
        and consolidation["static_estimates_closed"] == 0
        and consolidation["experimental_observations_admitted"] == 0,
        "ASSESSMENT_BOUNDARY_INVALID",
    )

    folder = Path(folder).absolute()
    need(folder.resolve(strict=True) == folder, "SESSION_PATH_ALIAS")
    journal.private_directory(folder)

    need(
        not os.path.lexists(folder / "fixture-session"),
        "SESSION_ALREADY_EXISTS",
    )

    plan_id = plan["plan_id"]

    check_plan_snapshot(database, plan, "PLANNED", 0)
    need(consent == journal.consent_for(plan), "EXPLICIT_CONSENT_REQUIRED")
    verify_ftp_archive(archive)
    database.authorize(plan_id, consent, expected_plan_sha256=plan["sha256"])

    token = database.reserve(
        plan_id,
        head=plan["code_head"],
        tree=plan["code_tree"],
        runner_sha256=plan["runner_sha256"],
        expected_plan_sha256=plan["sha256"],
    )

    try:

        verify_checkout(plan)

        database.claim_dispatch(
            plan_id, token, expected_plan_sha256=plan["sha256"]
        )

        reserved = check_plan_snapshot(database, plan, "RESERVED", 1)

        need(
            reserved["state"] == "RESERVED"
            and reserved["attempt_count"] == 1
            and reserved["events"][-1]["action"] ==
                "DISPATCH_CLAIMED"
            and journal.clock() < plan["expires_at"],
            "DISPATCH_NO_LONGER_CURRENT",
        )

        durable.write_once(
            folder / "dispatch-intent.json",
            durable.seal({
                "schema": SCHEMA + "-intent",
                "plan_sha256": plan["sha256"],
                "reservation_snapshot_sha256":
                    reserved["sha256"],
                "consolidation_sha256":
                    consolidation["sha256"],
                "coverage_sha256":
                    coverage["sha256"],
                "created_at_utc": ssh.utc(),
                "attempt": 1,
                "historical_authority_granted": False,
                "experimental_admission": False,
            }),
        )

        # Recheck immediately before entering the fixed local runner.
        verify_checkout(plan)
        verify_ftp_archive(archive)
        current = check_plan_snapshot(database, plan, "RESERVED", 1)

        need(
            current == reserved
            and journal.clock() < plan["expires_at"],
            "DISPATCH_REVOKED_OR_EXPIRED",
        )

        ftp.run(
            folder / "fixture-session",
            archive,
            plan["code_head"],
            consolidation,
            ftp.CONFIRM,
        )

        result = validate_result(
            folder / "fixture-session",
            plan,
            consolidation,
        )

        dispatch_intent = durable.load(
            folder / "dispatch-intent.json"
        )

        binding = durable.seal({
            "schema": SCHEMA + "-binding",
            "plan_sha256": plan["sha256"],
            "dispatch_intent_sha256":
                dispatch_intent["sha256"],
            "functional_receipt_sha256":
                result["sha256"],
            "functional_validation_passed": True,
            "technical_evidence_accredited": False,
            "operational_a5_admitted": False,
            "experimental_admission": False,
        })

        durable.write_once(
            folder / "dispatch-binding.json",
            binding,
        )

        database.record_receipt(
            plan_id,
            token,
            result["sha256"],
        )

        snapshot = database.snapshot(plan_id)

        need(
            snapshot["state"] ==
                "RECEIPT_RECORDED_UNVERIFIED"
            and snapshot["attempt_count"] == 1
            and snapshot["receipt_sha256"] ==
                result["sha256"],
            "JOURNAL_FINAL_STATE_INVALID",
        )

        durable.write_once(
            folder / "final-snapshot.json",
            snapshot,
        )

        return result, binding, snapshot

    except BaseException as exc:

        try:

            current = database.snapshot(plan_id)

            if current["state"] == "RESERVED":

                database.mark_uncertain(
                    plan_id, token
                )

        finally:

            durable.write_once(
                folder / "dispatch-failure.json",
                durable.seal({
                    "schema": SCHEMA + "-failure",
                    "plan_sha256": plan["sha256"],
                    "error_type": type(exc).__name__,
                    "automatic_retry": False,
                    "completed_at_utc": ssh.utc(),
                }),
            )

        raise


def hypothetical_analysis(consolidation):

    evidence.verify_digest(consolidation)

    rows = [
        item for item in consolidation["cases"]
        if item["protocol"] == "FTP"
    ]

    need(
        len(rows) == 1,
        "FTP_ASSESSMENT_NOT_UNIQUE",
    )

    row = rows[0]

    need(
        row["baseline_closed"] is False
        and row["initial_risk_candidate"] == "1/6"
        and row["normalized_criticality_candidate"] == "0",
        "CANDIDATE_ASSESSMENT_INVALID",
    )

    # Counterfactual calculation using the old candidate baseline.
    # Not the risk of the newly configured functional fixture.
    report = build_unit_bridge(
        [{
            "service_id": "FTP_DEV",
            "case_id": "PILOT-MET-FTP-001",
            "assessment_index": 0,
            "initial_risk": "1/6",
            "normalized_criticality": "0",
            "replacement_risk": "1/6",
            "evidence": [],
        }],
        [],
        weights=WEIGHTS,
    )

    verify_unit_bridge(report)

    interval = report["a7"]["results"][0]

    need(
        interval["rf_lower"] == "1/6"
        and interval["rf_upper"] == "7/18"
        and interval["confirmed_rf"] is None,
        "HYPOTHETICAL_INTERVAL_INVALID",
    )

    return durable.seal({
        "schema": SCHEMA + "-hypothetical-analysis",
        "source_consolidation_sha256":
            consolidation["sha256"],
        "input_kind":
            "COUNTERFACTUAL_OLD_CANDIDATE_BASELINE",
        "applicable_to_new_functional_configuration":
            False,
        "replacement_applied": False,
        "weights_frozen": False,
        "analytical_bridge": report,
        "interval": {
            "lower": interval["rf_lower"],
            "upper": interval["rf_upper"],
        },
        "confirmed_rf": None,
        "experimental_admission": False,
    })


def final_report(
    plan,
    result,
    binding,
    snapshot,
    consolidation,
):

    for document in (
        plan, result, binding, snapshot,
        consolidation,
    ):

        evidence.verify_digest(document)

    need(
        binding["plan_sha256"] == plan["sha256"]
        and binding["functional_receipt_sha256"] ==
            result["sha256"]
        and snapshot["plan_sha256"] == plan["sha256"]
        and snapshot["receipt_sha256"] == result["sha256"]
        and snapshot["attempt_count"] == 1
        and snapshot["state"] ==
            "RECEIPT_RECORDED_UNVERIFIED",
        "FINAL_REPORT_BINDING_INVALID",
    )

    stop = preview_stop(
        a6_classification="ND",
        accredited=False,
        vm_checked=False,
        operational_dispatch=False,
        source_sha256=result["sha256"],
    )

    verify_stop(stop)

    return durable.seal({
        "schema": SCHEMA + "-report",
        "plan_sha256": plan["sha256"],
        "functional_receipt_sha256":
            result["sha256"],
        "dispatch_binding_sha256":
            binding["sha256"],
        "journal_snapshot_sha256":
            snapshot["sha256"],
        "local_functional_dispatch_verified": True,
        "functional_receipt_validated": True,
        "hypothetical_analysis":
            hypothetical_analysis(consolidation),
        "actual_functional_baseline_closed": False,
        "operational_a5_admitted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "a8": stop,
        "operational_a9_published": False,
        "a10_local_report_generated": True,
        "reference_i4": "ND",
        "historical_authority_granted": False,
        "experimental_observations_admitted": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })
