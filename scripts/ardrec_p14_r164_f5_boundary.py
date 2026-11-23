#!/usr/bin/env python3
"""R164-F5: reconstrucción y auditoría offline, sin despacho."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

REPO = Path("/home/cicada/Development/GitHub/ardrec")

sys.path[:0] = [
    str(REPO / "src"),
    str(REPO / "scripts"),
]

from ardrec.coordination import (
    r59d_a5_result_intake as a5,
    r106_ssh_case_provenance as r106,
    r107_offline_a1_a10_orchestrator as r107,
    r108_offline_state_execution as r108,
    r109_executable_decision_chain as r109,
)
from ardrec.experiments import (
    r148_paired_register as r148,
    r149_scenario_design as r149,
    r164_identity_boundary as boundary,
)

import ardrec_p14_r104_prototype as cli104
import ardrec_p14_r106_ssh_case_bridge as cli106
import ardrec_p14_r164_f3_workspace as workspace

BRANCH = "feat/ardrec-integracion-funcional-experimental-v1"
BASE = "41a552fd385843e1f700ea35c5315f9bdec89be2"

STUDY = Path(
    "/home/cicada/ardrec-lab/r164-study-312debcf0aac"
)

STUDY_HEAD = "312debcf0aac20eea5f6979b64992cf56308f695"

STUDY_MANIFEST = (
    "c3f0f9c3309a9a63363943afd552ed14ade74424bc440fee1104768abd8e97c8"
)

CATALOG = REPO / "lab/operational-catalog-v1/catalog.json"

OUTPUT = Path(
    "/home/cicada/ardrec-lab/r164-f5-cross-population-v1"
)

MAX_BYTES = 524288


def need(condition, reason):
    if not condition:
        raise boundary.Stop(reason)


def git(*args):
    process = subprocess.run(
        ["/usr/bin/git", *args],
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=20,
    )

    need(
        process.returncode == 0,
        "GIT_COMMAND_FAILED",
    )

    return process.stdout.decode("ascii").strip()


def guard():
    need(
        os.geteuid() != 0
        and Path.cwd().resolve() == REPO,
        "REPOSITORY_AND_NONROOT_REQUIRED",
    )

    need(
        git("branch", "--show-current") == BRANCH,
        "BRANCH_CHANGED",
    )

    need(
        git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ) == "",
        "WORKTREE_NOT_CLEAN",
    )

    head = git("rev-parse", "HEAD")

    need(
        git("rev-parse", "main") == BASE,
        "MAIN_REFERENCE_CHANGED",
    )

    need(
        subprocess.run(
            ["/usr/bin/git", "verify-commit", head],
            cwd=REPO,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
        ).returncode == 0,
        "UNSIGNED_HEAD",
    )

    need(
        subprocess.run(
            [
                "/usr/bin/git",
                "merge-base",
                "--is-ancestor",
                BASE,
                head,
            ],
            cwd=REPO,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
        ).returncode == 0,
        "BASE_NOT_ANCESTOR",
    )

    return head


def sources_offline():
    """Reconstruir fuentes sintéticas sin abrir sockets."""

    with tempfile.TemporaryDirectory(
        prefix="ardrec-r164-f5-synthetic-"
    ) as temporary:
        unified = cli104.build(54)
        _, m104 = cli104.persist(
            unified,
            Path(temporary),
        )

    need(
        unified["sha256"] == r106.R104_REPORT_PIN
        and m104["sha256"] == r106.R104_MANIFEST_PIN,
        "R104_SOURCE_DRIFT",
    )

    observation = {
        "schema": r106.R105_SCHEMA,
        "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
        "server_identification":
            "SSH-2.0-ARDREC_R105_FIXTURE",
        "identification_sha256": r106.R105_SERVER_SHA,
        "kexinit_sha256": r106.R105_KEX_SHA,
        "kexinit_bytes": 160,
        "offered_kex_algorithms": ["curve25519-sha256"],
        "offered_host_key_algorithms": ["ssh-ed25519"],
        "elapsed_ms": 2,
        "tcp_connections": 1,
        "client_identifications_sent": 1,
        "keys_negotiated": False,
        "authenticated": False,
        "remote_commands": 0,
        "a5_operational_attempts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "evidence_accredited": False,
        "dispatch_allowed": False,
        "p8_operational": "NO-GO",
    }

    # Estos son datos de fixture, NO una nueva observación TCP.
    f11 = {
        "schema": r106.F11_SCHEMA,
        "target": "ardrec-r33-dev-ssh",
        "original_result_sha256": r106.F11_R103_RESULT,
        "physical_hook_denial_recorded": True,
        "virsh_start_rejected": True,
        "watcher_finalization_defect_confirmed": True,
        "original_strict_acceptance": "FAIL_PRESERVED",
        "independent_boot_lifecycle_attested": False,
        "new_start_attempts": 0,
        "p8_operational": "NO-GO",
        "authorized_dispatch": False,
    }

    f11["sha256"] = a5.digest(f11)

    link = r106.build(
        unified, m104, observation, f11,
        f11_expected_sha=f11["sha256"],
    )

    m106 = cli106.manifest_for(
        link, observation
    )

    trace = r107.build(
        unified, m104, link, m106
    )

    need(
        r107.verify_trace(
            trace, unified, m104, link, m106
        ),
        "R107_REPLAY_FAILED",
    )

    model = r108.build(trace)

    need(
        r108.verify(model, trace),
        "R108_REPLAY_FAILED",
    )

    decision = r109.build(
        unified, trace, model
    )

    need(
        r109.verify(
            decision, unified, trace, model
        ),
        "R109_REPLAY_FAILED",
    )

    return unified, trace, model, decision


def study_documents():
    catalog = CATALOG.read_bytes()

    reviewed = workspace.audit(
        STUDY, catalog
    )

    need(
        reviewed["manifest"]["source_head"] == STUDY_HEAD,
        "STUDY_ORIGINAL_HEAD_CHANGED",
    )

    need(
        workspace.sha(
            workspace.read_private(
                STUDY, "manifest.json"
            )
        ) == STUDY_MANIFEST,
        "STUDY_MANIFEST_CHANGED",
    )

    protocol, registry = r148.read(
        STUDY / "register", catalog
    )

    folder = STUDY / "selection"

    plan = r149.decode(
        r149._read(folder, "plan.json")
    )

    checklist = r149.decode(
        r149._read(folder, "family-checklist.json")
    )

    working = r149._read(
        folder, "selection-working.csv"
    )

    return (
        catalog,
        protocol,
        registry,
        plan,
        checklist,
        working,
    )


def private_directory(path):
    info = path.lstat()

    need(
        path.is_absolute()
        and not path.is_symlink()
        and stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "PRIVATE_DIRECTORY_INVALID",
    )


def exclusive(path, raw):
    need(
        type(raw) is bytes
        and 0 < len(raw) <= MAX_BYTES,
        "OUTPUT_BYTES_INVALID",
    )

    fd = os.open(
        path,
        os.O_CREAT | os.O_EXCL |
        os.O_WRONLY | os.O_NOFOLLOW |
        os.O_CLOEXEC,
        0o600,
    )

    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def persist(document):
    private_directory(OUTPUT.parent)

    if not OUTPUT.exists() and not OUTPUT.is_symlink():
        OUTPUT.mkdir(mode=0o700)

    private_directory(OUTPUT)

    folder = Path(
        tempfile.mkdtemp(
            prefix="run-",
            dir=OUTPUT,
        )
    )

    private_directory(folder)

    raw = r148.canonical(document)

    manifest = {
        "schema": "ARDREC-R164-F5-REPLAY-MANIFEST-v1",
        "report_sha256": document["sha256"],
        "report_file_sha256": r148.digest(raw),
        "source_head": document["source_head"],
        "cross_population_pair_count": 0,
        "confirmed_physical_observations": 0,
        "p8": "NO-GO",
        "mode": "OFFLINE_UNVERIFIED_BOUNDARY_ONLY",
    }

    manifest["sha256"] = r148.digest(
        r148.canonical(manifest)
    )

    exclusive(folder / "report.json", raw)

    exclusive(
        folder / "manifest.json",
        r148.canonical(manifest),
    )

    fd = os.open(
        folder,
        os.O_RDONLY |
        os.O_DIRECTORY |
        os.O_NOFOLLOW,
    )

    try:
        os.fsync(fd)
    finally:
        os.close(fd)

    need(
        r148.decode(
            a5._read_private(
                folder / "report.json", MAX_BYTES
            )
        ) == document,
        "REPORT_READBACK_FAILED",
    )

    need(
        r148.decode(
            a5._read_private(
                folder / "manifest.json", MAX_BYTES
            )
        ) == manifest,
        "MANIFEST_READBACK_FAILED",
    )

    return folder, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--audit", action="store_true")
    action.add_argument("--save", action="store_true")

    args = parser.parse_args()

    try:
        head = guard()

        (
            catalog,
            protocol,
            registry,
            plan,
            checklist,
            working,
        ) = study_documents()

        unified, trace, model, decision = sources_offline()

        document = boundary.build(
            catalog,
            protocol,
            registry,
            plan,
            checklist,
            working,
            unified,
            trace,
            model,
            decision,
        )

        need(
            boundary.verify(
                document,
                catalog,
                protocol,
                registry,
                plan,
                checklist,
                working,
                unified,
                trace,
                model,
                decision,
            ),
            "BOUNDARY_REBUILD_FAILED",
        )

        if args.save:
            folder, manifest = persist(document)

            print(
                "R164_F5_RECEIPT_FOLDER=" + str(folder)
            )

            print(
                "R164_F5_RECEIPT_SHA256="
                + manifest["sha256"]
            )

        need(
            git("rev-parse", "HEAD") == head
            and git(
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ) == "",
            "GIT_CHANGED_DURING_AUDIT",
        )

        print("R164_F5_MODEL_COUNTS=SSH:16,FTP:20,SMB:18")
        print("R164_F5_STUDY_COUNTS=SSH:18,FTP:18,SMB:18")
        print("R164_F5_CANDIDATES=" + str(document["candidate_counts"]))
        print("R164_F5_R109_SHA256=" + document["r109_model_sha256"])
        print("R164_F5_BOUNDARY_SHA256=" + document["sha256"])
        print("R164_F5_CROSS_POPULATION_PAIRS=0")
        print("R164_F5_OBSERVATIONS_CONFIRMED=0")
        print("R164_F5_A6=ND")
        print("R164_F5_A9=NOT_PUBLISHED")
        print("R164_F5_VM_STARTS=0")
        print("R164_F5_LAB_TRAFFIC=0")
        print("R164_F5_P8=NO-GO")
        print("R164_F5_FINAL=PASS_OFFLINE_SEPARATE_POPULATIONS")

        return 0

    except (
        boundary.Stop,
        r148.Stop,
        r149.Stop,
        ValueError,
        KeyError,
        OSError,
        subprocess.SubprocessError,
        TypeError,
    ) as exc:
        print("R164_F5_FINAL=STOP")
        print(
            "REASON="
            + type(exc).__name__
            + ":"
            + str(exc)[:240]
        )
        print("AUTOMATIC_RESET=NO")
        print("R164_F5_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
