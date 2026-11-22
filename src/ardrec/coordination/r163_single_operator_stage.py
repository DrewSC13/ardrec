"""R163-F4: durable quarantined source staging, never a live B4/B9 install.

Reuses the hardened R146 filesystem primitives and the R163 signed
four-phase gate. No credential generation, network or root authority.
The installed candidates are deliberately INCOMPATIBLE with the
historical live B4/B9 manifests that assert independent staging.
"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import stat

from . import r146_independent_install as engine
from . import r163_install_phase_gate as phase

SCHEMA = "ARDREC-R163-QUARANTINED-SOURCE-STAGING-v1"
B4_NAME = "r163-b4-source-candidate-v1"
B9_NAME = "r163-b9-source-candidate-v1"
STAGES = {"b4": B4_NAME, "b9": B9_NAME}

Refusal = engine.Refusal
need = engine.need


def candidate_payload(b4, b9, head):
    need(type(b4) is bytes and type(b9) is bytes,
         "SOURCE_BYTES_REQUIRED")
    need(type(head) is str and engine.HEX40.fullmatch(head),
         "HEAD_INVALID")
    need(engine.sha(b4) == engine.B4_SHA, "B4_PIN_INVALID")
    need(engine.sha(b9) == engine.B9_SHA, "B9_PIN_INVALID")

    b4_manifest = {
        "schema": SCHEMA + "-b4-manifest",
        "head": head,
        "source_sha256": engine.B4_SHA,
        "root_install_independent": False,
        "runtime_activated": False,
        "candidate_only": True,
        "p8": "NO-GO",
    }
    b9_manifest = {
        "schema": SCHEMA + "-b9-manifest",
        "head": head,
        "source_sha256": engine.B9_SHA,
        "root_staged_independently": False,
        "runtime_activated": False,
        "candidate_only": True,
        "p8": "NO-GO",
    }
    return {
        "b4": {
            "source.py": b4,
            "manifest.json": engine.canonical(b4_manifest),
        },
        "b9": {
            "source.py": b9,
            "manifest.json": engine.canonical(b9_manifest),
        },
    }


def stage(*, root_parent, state_dir, gate, b4, b9, fail=None):
    """Stage source candidates with durable journal and restart recovery.

    The caller must already own private directories. When privileged,
    the caller additionally needs an externally staged root agent;
    invoking this module from the checkout does not confer authority.
    """
    need(fail in (None, "after_journal", "after_b4", "after_b9"),
         "UNKNOWN_FAULT")
    need(isinstance(gate, phase.PhaseGate), "SIGNED_GATE_REQUIRED")
    need(gate.receipts == (), "GATE_ALREADY_CONSUMED")
    need(phase.require_plan(gate.plan) == gate.plan_sha256,
         "PLAN_CHANGED")
    need(isinstance(root_parent, Path) and root_parent.is_absolute()
         and not root_parent.is_symlink(),
         "ROOT_PARENT_INVALID")
    need(isinstance(state_dir, Path) and state_dir.is_absolute()
         and not state_dir.is_symlink(),
         "STATE_PATH_INVALID")

    owner = os.geteuid()

    # A root caller cannot run the mutable checkout as an install agent.
    if owner == 0:
        approved = Path(
            "/opt/ardrec/r163-installer-v1/runtime/"
            "r163_single_operator_stage.py"
        )
        need(Path(__file__).absolute() == approved,
             "ROOT_CHECKOUT_EXECUTION_FORBIDDEN")

    engine.check_folder(state_dir, owner)

    root_stat = root_parent.lstat()
    need(stat.S_ISDIR(root_stat.st_mode)
         and root_stat.st_uid == owner
         and not (root_stat.st_mode & 0o022),
         "ROOT_PARENT_METADATA_INVALID")
    need(root_stat.st_dev == state_dir.stat().st_dev,
         "FILESYSTEM_MISMATCH")

    body = candidate_payload(
        b4, b9, gate.plan["head"]
    )
    plan_hash = phase.require_plan(gate.plan)
    need(plan_hash == gate.plan_sha256, "PLAN_DIGEST_INVALID")

    auth_hash = engine.sha(gate.authorization_raw)
    sources = {
        "b4": engine.sha(b4),
        "b9": engine.sha(b9),
    }

    journal_raw = engine.canonical({
        "schema": SCHEMA + "-journal",
        "plan_sha256": plan_hash,
        "authorization_sha256": auth_hash,
        "head": gate.plan["head"],
        "tree": gate.plan["tree"],
        "boot_id": gate.plan["boot_id"],
        "sources": sources,
        "destinations": {
            key: str(root_parent / name)
            for key, name in STAGES.items()
        },
        "candidate_only": True,
        "root_install_authorized": False,
        "runtime_activated": False,
        "p8": "NO-GO",
    })
    journal_sha = engine.sha(journal_raw)

    receipt_raw = engine.canonical({
        "schema": SCHEMA + "-receipt",
        "journal_sha256": journal_sha,
        "authorization_sha256": auth_hash,
        "sources": sources,
        "readback_required": True,
        "candidate_only": True,
        "root_install_authorized": False,
        "network_traffic_authorized": False,
        "runtime_activated": False,
        "p8": "NO-GO",
    })

    destinations = {
        key: root_parent / name
        for key, name in STAGES.items()
    }

    # First signed review occurs before any journal or lock creation.
    gate.review("before_journal")
    need(phase.require_plan(gate.plan) == plan_hash,
         "PLAN_MUTATED_BEFORE_WRITE")

    lock = state_dir / "stage.lock"
    descriptor = os.open(
        lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
        os.O_CLOEXEC, 0o600
    )
    try:
        info = os.fstat(descriptor)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == owner
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size == 0,
            "STAGING_LOCK_UNSAFE"
        )
        try:
            fcntl.flock(
                descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB
            )
        except BlockingIOError as exc:
            raise Refusal("CONCURRENT_STAGING") from exc

        permitted = {
            "stage.lock", "journal.json", "receipt.json",
            "pending-b4", "pending-b9",
        }
        need(
            {entry.name for entry in state_dir.iterdir()}
            <= permitted,
            "STAGING_STATE_SCOPE_DRIFT"
        )

        journal = state_dir / "journal.json"
        receipt = state_dir / "receipt.json"

        if journal.exists() or journal.is_symlink():
            engine.read_exact(journal, journal_raw, owner)
        else:
            need(
                not any(
                    target.exists() or target.is_symlink()
                    for target in destinations.values()
                ),
                "CANDIDATE_EXISTS_WITHOUT_JOURNAL"
            )
            need(
                not receipt.exists() and
                not receipt.is_symlink(),
                "ORPHAN_RECEIPT"
            )
            engine.write_file(journal, journal_raw)
            engine.fsync_dir(state_dir)

        if fail == "after_journal":
            raise Refusal("INJECTED_AFTER_JOURNAL")

        for key in ("b4", "b9"):
            gate.review("before_" + key)

            need(
                phase.require_plan(gate.plan) == plan_hash,
                "PLAN_MUTATED_BEFORE_STAGE"
            )

            target = destinations[key]
            contents = body[key]

            if target.exists() or target.is_symlink():
                engine.verify_dir(target, contents, owner)
            else:
                pending = "pending-" + key
                engine.stage_dir(
                    state_dir, pending, contents, owner
                )
                engine.noreplace(
                    state_dir / pending, target
                )
                engine.fsync_dir(root_parent)
                engine.fsync_dir(state_dir)

            engine.verify_dir(target, contents, owner)

            if fail == "after_" + key:
                raise Refusal(
                    "INJECTED_AFTER_" + key.upper()
                )

        gate.review("before_receipt")

        for key in ("b4", "b9"):
            engine.verify_dir(
                destinations[key], body[key], owner
            )

        if receipt.exists() or receipt.is_symlink():
            engine.read_exact(receipt, receipt_raw, owner)
            status = "CANDIDATES_ALREADY_VERIFIED"
        else:
            engine.write_file(receipt, receipt_raw)
            engine.fsync_dir(state_dir)
            engine.read_exact(receipt, receipt_raw, owner)
            status = "CANDIDATES_STAGED_VERIFIED"

        chain = gate.review_history()
        need(
            chain["complete"] is True and
            chain["record_count"] == 4 and
            chain["root_install_authorized"] is False,
            "PHASE_REVIEW_INCOMPLETE"
        )

        return {
            "schema": SCHEMA + "-result",
            "status": status,
            "journal_sha256": journal_sha,
            "receipt_sha256": engine.sha(receipt_raw),
            "phase_review_count": 4,
            "candidate_only": True,
            "root_install_authorized": False,
            "runtime_activated": False,
            "p8": "NO-GO",
        }
    finally:
        os.close(descriptor)


def capabilities():
    return {
        "schema": SCHEMA + "-capabilities",
        "transactional": True,
        "recoverable": True,
        "signed_phase_reviews": 4,
        "live_install_destinations": False,
        "candidate_only": True,
        "root_install_authorized": False,
        "runtime_activated": False,
        "traffic": False,
        "p8": "NO-GO",
    }
