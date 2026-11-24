"""R221: transactional local SSH/SFTP and SMB read batch.

Controlador monousuario de fixtures locales.
No concede autoridad historica, privilegiada ni experimental.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess

from pathlib import Path

from ardrec.coordination import local_ssh_pilot as ssh
from ardrec.coordination import local_evidence_bridge as evidence
from ardrec.coordination import prospective_local_pilot as durable

from ardrec.experiments import prospective_attempt_journal as journal
from ardrec.experiments import prospective_local_dispatch as dispatch
from ardrec.experiments import r220_local_read as fixture


SCHEMA = "ARDREC-R221-LOCAL-READ-BATCH-v1"

OPERATIONS = {
    "SSH": "FIXED_SYNTHETIC_SFTP_READ",
    "SMB": "FIXED_SYNTHETIC_SMB_READ",
}

FAMILIES = {
    "SSH": "SSH-T06",
    "SMB": "SMB-T09",
}

R219_SUMMARY_PIN = (
    "91ece5ed310232b84ce076cc8e164fc939"
    "16e8cc9058ff74141ef8261b6a979c"
)

R219_CONTRACT_PIN = (
    "68d13d48c6ba0eb8993af7cc1b4fab723"
    "a081b5f858e92970c5e30822fbe0ba8"
)

R220_HEAD = (
    "0932861f8d3e842be4cdcdea481602ace6d4c3a5"
)


def need(condition, reason):

    if not condition:
        raise journal.Refusal(reason)


def file_digest(path):

    return hashlib.sha256(
        Path(path).read_bytes()
    ).hexdigest()


def git(*args):

    return subprocess.check_output(
        ["/usr/bin/git", *args],
        stdin=subprocess.DEVNULL,
        timeout=10,
    ).decode("ascii").strip()


def checkout():

    need(
        not git("status", "--porcelain=v1"),
        "CHECKOUT_NOT_CLEAN",
    )

    need(
        git("branch", "--show-current")
        == "feat/r220-local-ssh-smb-read",
        "BRANCH_INVALID",
    )

    subprocess.run(
        [
            "/usr/bin/git",
            "merge-base",
            "--is-ancestor",
            R220_HEAD,
            "HEAD",
        ],
        check=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )

    return (
        git("rev-parse", "HEAD"),
        git("rev-parse", "HEAD^{tree}"),
    )


def source_pin(path, expected):

    raw = Path(path).read_bytes()

    need(
        0 < len(raw) <= 1048576,
        "PRIOR_DOCUMENT_SIZE_INVALID",
    )

    actual = hashlib.sha256(raw).hexdigest()

    if actual == expected:
        return actual

    document = json.loads(raw)

    evidence.verify_digest(document)

    need(
        document["sha256"] == expected,
        "PRIOR_DOCUMENT_PIN_INVALID",
    )

    return actual


def load_prior(r219):

    r219 = Path(r219)

    summary = r219 / "03-pilot-rehearsal-summary.json"
    contract = r219 / "01-pilot-contract.json"

    return {
        "r219_summary_pin": R219_SUMMARY_PIN,
        "r219_summary_file_sha256": source_pin(
            summary,
            R219_SUMMARY_PIN,
        ),
        "r219_contract_pin": R219_CONTRACT_PIN,
        "r219_contract_file_sha256": source_pin(
            contract,
            R219_CONTRACT_PIN,
        ),
        "ftp_reexecution": False,
        "retrospective_admission": False,
    }


def find_coverage(patch_root):

    """Locate only the existing R204/R206 coverage artifact."""

    candidates = (
        "R204-20261124T133852Z-EMSkrX",
        "R206-20261124T135339Z-443Fhc",
        "R207-20261124T135849Z-J1MXk0",
    )

    for directory in candidates:

        root = Path(patch_root) / directory

        if not root.is_dir():
            continue

        for path in sorted(root.rglob("*.json")):

            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > 262144
            ):
                continue

            try:
                document = json.loads(
                    path.read_bytes()
                )
            except (OSError, ValueError):
                continue

            if (
                isinstance(document, dict)
                and document.get("sha256")
                == dispatch.COVERAGE_PIN
            ):

                dispatch.verify_coverage(document)

                return document

    raise journal.Refusal(
        "PRIOR_COVERAGE_ARTIFACT_NOT_FOUND"
    )


def fixture_identity(case_id, protocol, profile):

    return durable.seal({
        "schema": SCHEMA + "-fixture",
        "case_id": case_id,
        "family": FAMILIES[protocol],
        "protocol": protocol,
        "profile": profile,
        "operation": OPERATIONS[protocol],
        "destination": "127.0.0.1",
        "allowed_sha256": fixture.digest(
            fixture.ALLOWED
        ),
        "restricted_sha256": fixture.digest(
            fixture.RESTRICTED
        ),
        "restricted_mode":
            0 if profile == "CONTROL" else 0o400,
        "read_limit_bytes": fixture.LIMIT,
        "resource_names": [
            "allowed.txt",
            "restricted.txt",
        ],
        "arbitrary_commands": False,
        "write_operations": False,
        "maximum_attempts": 1,
        "experimental_admission": False,
    })


def batch_consent(batch):

    evidence.verify_digest(batch)

    return (
        "AUTORIZO_R221:"
        + batch["sha256"]
    )


def prepare(folder, r219, patch_root):

    need(
        os.geteuid() > 0,
        "ROOT_EXECUTION_FORBIDDEN",
    )

    head, tree = checkout()

    prior = load_prior(r219)

    coverage = find_coverage(patch_root)

    folder = Path(folder)
    folder.mkdir(mode=0o700, exist_ok=False)

    durable.write_once(
        folder / "prior-coverage.json",
        coverage,
    )

    database = dispatch.DispatchJournal(
        folder / "attempts.sqlite3",
        create=True,
    )

    now = journal.clock()

    runner_sha = fixture.digest(
        fixture.RUNNER.encode("ascii")
    )

    cases = []

    for case_id, protocol, profile in fixture.CASES:

        identity = fixture_identity(
            case_id,
            protocol,
            profile,
        )

        plan = journal.make_plan(
            plan_id=secrets.token_hex(16),
            protocol=protocol,
            operation=OPERATIONS[protocol],
            head=head,
            tree=tree,
            coverage_sha256=coverage["sha256"],
            runner_sha256=runner_sha,
            fixture_sha256=identity["sha256"],
            operator_uid=os.geteuid(),
            created_at=now,
            expires_at=now + journal.MAX_TTL_SECONDS,
        )

        case_folder = folder / case_id

        case_folder.mkdir(mode=0o700)

        durable.write_once(
            case_folder / "fixture-identity.json",
            identity,
        )

        durable.write_once(
            case_folder / "plan.json",
            plan,
        )

        database.register(plan)

        cases.append({
            "case_id": case_id,
            "protocol": protocol,
            "profile": profile,
            "family": FAMILIES[protocol],
            "fixture_sha256": identity["sha256"],
            "plan_sha256": plan["sha256"],
            "plan_id": plan["plan_id"],
        })

    batch = durable.seal({
        "schema": SCHEMA + "-plan",
        "code_head": head,
        "code_tree": tree,
        "runner_sha256": runner_sha,
        "coverage_sha256": coverage["sha256"],
        "operator_uid": os.geteuid(),
        "human_operators": 1,
        "created_at": now,
        "expires_at":
            now + journal.MAX_TTL_SECONDS,
        "cases": cases,
        "prior": prior,
        "maximum_attempts_per_case": 1,
        "scope":
            "LOCAL_ISOLATED_SOFTWARE_FIXTURE_ONLY",
        "historical_authority_granted": False,
        "formal_pilot_admission": False,
        "experimental_admission": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })

    durable.write_once(
        folder / "batch.json",
        batch,
    )

    print("BATCH_PREPARED=YES")
    print("PLANS_REGISTERED=4")
    print("PHYSICAL_EXECUTIONS=0")
    print("BATCH_SHA256=" + batch["sha256"])


def load_batch(folder):

    journal.private_directory(folder)

    batch = durable.load(
        folder / "batch.json"
    )

    evidence.verify_digest(batch)

    coverage = durable.load(
        folder / "prior-coverage.json"
    )

    dispatch.verify_coverage(coverage)

    need(
        batch["schema"] == SCHEMA + "-plan"
        and batch["coverage_sha256"]
            == coverage["sha256"]
        and batch["operator_uid"] == os.geteuid()
        and batch["human_operators"] == 1
        and batch["maximum_attempts_per_case"] == 1
        and batch["scope"]
            == "LOCAL_ISOLATED_SOFTWARE_FIXTURE_ONLY"
        and batch["runner_sha256"]
            == fixture.digest(
                fixture.RUNNER.encode("ascii")
            )
        and batch["historical_authority_granted"] is False
        and batch["formal_pilot_admission"] is False
        and batch["experimental_admission"] is False
        and batch["p8"] == "NO-GO",
        "BATCH_SCOPE_INVALID",
    )

    expected = list(fixture.CASES)

    actual = [
        (
            case["case_id"],
            case["protocol"],
            case["profile"],
        )
        for case in batch["cases"]
    ]

    need(
        actual == expected,
        "BATCH_CASES_INVALID",
    )

    need(
        len({
            case["plan_id"]
            for case in batch["cases"]
        }) == 4,
        "DUPLICATE_PLAN_ID",
    )

    return batch


def load_case(folder, batch, case):

    case_folder = folder / case["case_id"]

    journal.private_directory(case_folder)

    plan = durable.load(
        case_folder / "plan.json"
    )

    identity = durable.load(
        case_folder / "fixture-identity.json"
    )

    journal.verify_plan(plan)
    evidence.verify_digest(identity)

    protocol = case["protocol"]
    profile = case["profile"]

    need(
        identity == fixture_identity(
            case["case_id"],
            protocol,
            profile,
        )
        and plan["sha256"] == case["plan_sha256"]
        and plan["plan_id"] == case["plan_id"]
        and plan["protocol"] == protocol
        and plan["operation"] == OPERATIONS[protocol]
        and plan["code_head"] == batch["code_head"]
        and plan["code_tree"] == batch["code_tree"]
        and plan["coverage_sha256"]
            == batch["coverage_sha256"]
        and plan["runner_sha256"]
            == batch["runner_sha256"]
        and plan["fixture_sha256"]
            == identity["sha256"]
            == case["fixture_sha256"]
        and plan["created_at"] == batch["created_at"]
        and plan["expires_at"] == batch["expires_at"],
        "CASE_PLAN_BINDING_INVALID",
    )

    return case_folder, plan


def verify_result(case_folder, case, plan):

    session = case_folder / "fixture-session"

    result = durable.load(
        session / "result.json"
    )

    context = durable.load(
        session / "fixture-context.json"
    )

    evidence.verify_digest(result)
    evidence.verify_digest(context)

    need(
        result["schema"] == fixture.SCHEMA + "-result"
        and context["schema"]
            == fixture.SCHEMA + "-fixture-context"
        and context["runner_sha256"]
            == plan["runner_sha256"]
        and context["protocol"] == case["protocol"]
        and context["profile"] == case["profile"]
        and result["protocol"] == case["protocol"]
        and result["profile"] == case["profile"]
        and context["allowed_sha256"]
            == fixture.digest(fixture.ALLOWED)
        and context["restricted_sha256"]
            == fixture.digest(fixture.RESTRICTED)
        and context["started_at_utc"]
            <= result["completed_at_utc"],
        "RESULT_CONTEXT_INVALID",
    )

    need(
        result["functional_read_verified"] is True
        and result["temporary_workspace_removed"] is True
        and result["historical_authority_granted"] is False
        and result["operational_a5_admitted"] is False
        and result["a6"] == "ND"
        and result["confirmed_rf"] is None
        and result["operational_a9_published"] is False
        and result["formal_pilot_admission"] is False
        and result["experimental_admission"] is False
        and result["p7"] == "DRAFT_NOT_FROZEN"
        and result["p8"] == "NO-GO",
        "RESULT_AUTHORITY_INVALID",
    )

    raw_stdout = session / "stdout.bin"
    raw_stderr = session / "stderr.bin"

    need(
        json.loads(raw_stdout.read_bytes())
            == result["observation"],
        "RAW_OBSERVATION_MISMATCH",
    )

    fixture.verify_observation(
        case["protocol"],
        case["profile"],
        result["observation"],
        context["host_namespace"],
    )

    for path in (raw_stdout, raw_stderr):

        with path.open("rb") as handle:
            os.fsync(handle.fileno())

    return result, {
        "context_sha256": context["sha256"],
        "stdout_sha256": file_digest(raw_stdout),
        "stderr_sha256": file_digest(raw_stderr),
    }


def execute_case(
    database,
    folder,
    batch,
    case,
    consent_record,
):

    case_folder, plan = load_case(
        folder,
        batch,
        case,
    )

    plan_id = plan["plan_id"]

    dispatch.verify_checkout(plan)

    need(
        not (case_folder / "fixture-session").exists(),
        "SESSION_ALREADY_EXISTS",
    )

    token = database.reserve(
        plan_id,
        head=plan["code_head"],
        tree=plan["code_tree"],
        runner_sha256=plan["runner_sha256"],
    )

    try:

        database.claim_dispatch(plan_id, token)

        reserved = database.snapshot(plan_id)

        need(
            reserved["state"] == "RESERVED"
            and reserved["attempt_count"] == 1
            and reserved["events"][-1]["action"]
                == "DISPATCH_CLAIMED"
            and journal.clock() < plan["expires_at"],
            "RESERVATION_INVALID",
        )

        intent = durable.seal({
            "schema": SCHEMA + "-dispatch-intent",
            "case_id": case["case_id"],
            "batch_sha256": batch["sha256"],
            "consent_sha256":
                consent_record["sha256"],
            "plan_sha256": plan["sha256"],
            "fixture_sha256":
                case["fixture_sha256"],
            "reservation_sha256":
                reserved["sha256"],
            "created_at_utc": ssh.utc(),
            "attempt": 1,
            "experimental_admission": False,
        })

        durable.write_once(
            case_folder / "dispatch-intent.json",
            intent,
        )

        dispatch.verify_checkout(plan)

        need(
            database.snapshot(plan_id) == reserved
            and journal.clock() < plan["expires_at"],
            "DISPATCH_REVOKED_OR_EXPIRED",
        )

        fixture.run_fixture(
            case_folder / "fixture-session",
            case["protocol"],
            case["profile"],
        )

        result, hashes = verify_result(
            case_folder,
            case,
            plan,
        )

        binding = durable.seal({
            "schema": SCHEMA + "-binding",
            "case_id": case["case_id"],
            "batch_sha256": batch["sha256"],
            "plan_sha256": plan["sha256"],
            "dispatch_intent_sha256":
                intent["sha256"],
            "functional_receipt_sha256":
                result["sha256"],
            **hashes,
            "functional_validation_passed": True,
            "technical_evidence_accredited": False,
            "operational_a5_admitted": False,
            "experimental_admission": False,
        })

        durable.write_once(
            case_folder / "dispatch-binding.json",
            binding,
        )

        database.record_receipt(
            plan_id,
            token,
            result["sha256"],
        )

        snapshot = database.snapshot(plan_id)

        need(
            snapshot["state"]
                == "RECEIPT_RECORDED_UNVERIFIED"
            and snapshot["attempt_count"] == 1
            and snapshot["receipt_sha256"]
                == result["sha256"],
            "JOURNAL_FINAL_STATE_INVALID",
        )

        durable.write_once(
            case_folder / "final-snapshot.json",
            snapshot,
        )

        return result

    except BaseException as exc:

        current = database.snapshot(plan_id)

        if current["state"] == "RESERVED":

            database.mark_uncertain(
                plan_id,
                token,
            )

        durable.write_once(
            case_folder / "dispatch-failure.json",
            durable.seal({
                "schema": SCHEMA + "-failure",
                "case_id": case["case_id"],
                "plan_sha256": plan["sha256"],
                "error_type": type(exc).__name__,
                "automatic_retry": False,
                "completed_at_utc": ssh.utc(),
                "experimental_admission": False,
            }),
        )

        raise


def replay(folder, publish_summary=False):

    folder = Path(folder)

    batch = load_batch(folder)

    database = dispatch.DispatchJournal(
        folder / "attempts.sqlite3",
    )

    consent_record = durable.load(
        folder / "batch-consent.json"
    )

    evidence.verify_digest(consent_record)

    need(
        consent_record["batch_sha256"]
            == batch["sha256"],
        "CONSENT_BINDING_INVALID",
    )

    rows = []

    for case in batch["cases"]:

        case_folder, plan = load_case(
            folder,
            batch,
            case,
        )

        result, hashes = verify_result(
            case_folder,
            case,
            plan,
        )

        intent = durable.load(
            case_folder / "dispatch-intent.json"
        )

        binding = durable.load(
            case_folder / "dispatch-binding.json"
        )

        saved = durable.load(
            case_folder / "final-snapshot.json"
        )

        for document in (intent, binding, saved):

            evidence.verify_digest(document)

        current = database.snapshot(
            plan["plan_id"]
        )

        need(
            current == saved
            and saved["state"]
                == "RECEIPT_RECORDED_UNVERIFIED"
            and saved["attempt_count"] == 1
            and saved["receipt_sha256"]
                == result["sha256"]
            and intent["batch_sha256"]
                == batch["sha256"]
            and intent["plan_sha256"]
                == plan["sha256"]
            and intent["consent_sha256"]
                == consent_record["sha256"]
            and binding["dispatch_intent_sha256"]
                == intent["sha256"]
            and binding["functional_receipt_sha256"]
                == result["sha256"]
            and all(
                binding[key] == value
                for key, value in hashes.items()
            ),
            "REPLAY_BINDING_INVALID",
        )

        actions = [
            event["action"]
            for event in current["events"]
        ]

        need(
            actions == [
                "REGISTERED",
                "LOCAL_CONSENT_RECORDED",
                "ATTEMPT_RESERVED",
                "DISPATCH_CLAIMED",
                "RECEIPT_RECORDED_UNVERIFIED",
            ],
            "EVENT_SEQUENCE_INVALID",
        )

        resources = result["observation"]["resources"]

        rows.append({
            "case_id": case["case_id"],
            "family": case["family"],
            "protocol": case["protocol"],
            "profile": case["profile"],
            "allowed_status":
                resources["allowed.txt"]["status"],
            "allowed_bytes":
                resources["allowed.txt"]["bytes"],
            "restricted_status":
                resources["restricted.txt"]["status"],
            "restricted_bytes":
                resources["restricted.txt"]["bytes"],
            "condition":
                "POLICY_CONFORMS"
                if case["profile"] == "CONTROL"
                else "CONTRAST_READ_OBSERVED",
            "receipt_sha256": result["sha256"],
            "attempts": 1,
            "a6": "ND",
            "confirmed_rf": None,
            "experimental_admission": False,
        })

    summary = durable.seal({
        "schema": SCHEMA + "-summary",
        "batch_sha256": batch["sha256"],
        "code_head": batch["code_head"],
        "code_tree": batch["code_tree"],
        "cases": rows,
        "real_local_functional_receipts": len(rows),
        "ssh_receipts": 2,
        "smb_receipts": 2,
        "ftp_reexecuted": False,
        "transactional_attempts": 4,
        "replay_network_operations": 0,
        "human_operators": 1,
        "historical_authority_granted": False,
        "operational_a5_admitted": False,
        "a6": "ND",
        "confirmed_rf": None,
        "operational_a9_published": False,
        "formal_pilot_observations_added": 0,
        "experimental_observations_added": 0,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
    })

    if publish_summary:

        durable.write_once(
            folder / "batch-summary.json",
            summary,
        )

    else:

        previous = durable.load(
            folder / "batch-summary.json"
        )

        need(
            previous == summary,
            "SUMMARY_REPLAY_MISMATCH",
        )

    for row in rows:

        print(
            row["case_id"],
            row["profile"],
            "ALLOWED=" + row["allowed_status"],
            "RESTRICTED=" + row["restricted_status"],
            "RESTRICTED_BYTES="
                + str(row["restricted_bytes"]),
            "ATTEMPTS=1",
        )

    print("LOCAL_FUNCTIONAL_RECEIPTS=4/4")
    print("TRANSACTIONAL_ATTEMPTS=4/4")
    print("REPLAY_NETWORK_OPERATIONS=0")
    print("FTP_REEXECUTED=NO")
    print("A6=ND")
    print("FORMAL_PILOT_ADMITTED=0")
    print("EXPERIMENTAL_ADMITTED=0")
    print("SUMMARY_SHA256=" + summary["sha256"])

    return summary


def execute(folder, consent):

    folder = Path(folder)

    batch = load_batch(folder)

    need(
        consent == batch_consent(batch),
        "EXPLICIT_BATCH_CONSENT_REQUIRED",
    )

    need(
        journal.clock() < batch["expires_at"],
        "BATCH_EXPIRED",
    )

    head, tree = checkout()

    need(
        head == batch["code_head"]
        and tree == batch["code_tree"],
        "BATCH_CHECKOUT_INVALID",
    )

    database = dispatch.DispatchJournal(
        folder / "attempts.sqlite3",
    )

    for case in batch["cases"]:

        snapshot = database.snapshot(
            case["plan_id"]
        )

        need(
            snapshot["state"] == "PLANNED"
            and snapshot["attempt_count"] == 0,
            "BATCH_ALREADY_USED",
        )

    consent_record = durable.seal({
        "schema": SCHEMA + "-consent",
        "batch_sha256": batch["sha256"],
        "operator_uid": os.geteuid(),
        "human_operators": 1,
        "consent_sha256":
            fixture.digest(consent.encode("ascii")),
        "created_at_utc": ssh.utc(),
        "authorized_plans": [
            case["plan_sha256"]
            for case in batch["cases"]
        ],
        "historical_authority_granted": False,
        "experimental_admission": False,
    })

    durable.write_once(
        folder / "batch-consent.json",
        consent_record,
    )

    try:

        for case in batch["cases"]:

            _, plan = load_case(
                folder,
                batch,
                case,
            )

            database.authorize(
                plan["plan_id"],
                journal.consent_for(plan),
            )

        for case in batch["cases"]:

            print(
                "START_CASE=" + case["case_id"],
                flush=True,
            )

            result = execute_case(
                database,
                folder,
                batch,
                case,
                consent_record,
            )

            print(
                "RECEIPT_RECORDED="
                + result["sha256"],
                flush=True,
            )

        replay(
            folder,
            publish_summary=True,
        )

    except BaseException as exc:

        states = []

        for case in batch["cases"]:

            snapshot = database.snapshot(
                case["plan_id"]
            )

            if snapshot["state"] in (
                "PLANNED",
                "AUTHORIZED",
                "RESERVED",
            ):

                database.revoke(
                    case["plan_id"]
                )

            snapshot = database.snapshot(
                case["plan_id"]
            )

            states.append({
                "case_id": case["case_id"],
                "state": snapshot["state"],
                "attempt_count":
                    snapshot["attempt_count"],
            })

        durable.write_once(
            folder / "batch-failure.json",
            durable.seal({
                "schema": SCHEMA + "-batch-failure",
                "batch_sha256": batch["sha256"],
                "error_type": type(exc).__name__,
                "states": states,
                "automatic_retry": False,
                "experimental_admission": False,
            }),
        )

        raise


def main():

    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("folder", type=Path)
    prepare_parser.add_argument("r219", type=Path)
    prepare_parser.add_argument("patch_root", type=Path)

    execute_parser = sub.add_parser("execute")
    execute_parser.add_argument("folder", type=Path)
    execute_parser.add_argument("consent")

    replay_parser = sub.add_parser("replay")
    replay_parser.add_argument("folder", type=Path)

    args = parser.parse_args()

    if args.command == "prepare":

        prepare(
            args.folder,
            args.r219,
            args.patch_root,
        )

    elif args.command == "execute":

        execute(
            args.folder,
            args.consent,
        )

    else:

        replay(args.folder)


if __name__ == "__main__":
    main()
