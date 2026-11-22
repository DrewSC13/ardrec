"""R130/B17-R6B3: transacción privada de fuentes root candidatas.

Construye manifiestos NO AUTORIZADOS y publica una unidad atómica
de revisión. No instala en /var, no provisiona autoridad, no crea
permisos operacionales y no ejecuta ningún controlador root.

La futura instalación privilegiada requiere un agente autónomo
autenticado, revisión externa y revocaciones actuales.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from ardrec.coordination import (
    r130_b17_r6_install_contract as historical,
)

SCHEMA = "ARDREC-R130-B17-R6B3-ROOT-CANDIDATE-v1"
BASE = historical.HEAD
B4_SHA = "f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8"
B9_SHA = "c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3"

REQUIRED_B4 = (
    "manifest.json", "root-controller.py", "grant.json",
    "contract.json", "scope-authorization.json",
    "pilot-permit.json", "traffic-window.json",
)
REQUIRED_B9 = (
    "root-executor.py", "manifest.json", "release.json",
    "traffic-grant.json", "f13-handoff.json", "lock",
)

TARGET_B4 = "/var/lib/ardrec/r126-ftp-session-guard-v1"
TARGET_B9 = "/var/lib/ardrec/r128-one-session-v2"

class Stop(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Stop(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canon(doc):
    return historical.canon(doc)

def parse(raw):
    return historical.parse(raw)

def review_pair(lock_raw, b4, b9):
    """Validación de bytes exactos; no confiere autoridad."""
    need(type(b4) is bytes and type(b9) is bytes,
         "SOURCE_BYTES_REQUIRED")
    need(sha(b4) == B4_SHA, "B4_V2_PIN_MISMATCH")
    need(sha(b9) == B9_SHA, "B9_V2_PIN_MISMATCH")

    lock = parse(lock_raw)
    need(
        lock.get("schema") ==
            "ARDREC-R130-B17-R6B2-ROOT-COMPAT-CANDIDATE-v1"
        and lock.get("historical_source_commit") == BASE
        and lock.get("historical_b4_sha256") == historical.B4_SHA
        and lock.get("historical_b9_sha256") == historical.B9_SHA
        and lock.get("candidate_b4_sha256") == B4_SHA
        and lock.get("candidate_b9_sha256") == B9_SHA
        and lock.get("candidate_b4_path") ==
            "scripts/ardrec_p14_r130_b4_root_guard_v2.py"
        and lock.get("candidate_b9_path") ==
            "scripts/ardrec_p14_r130_b9_ftp_executor_v2.py"
        and lock.get("installed_r116_guard_expected_sha256")
            == historical.R116_GUARD
        and lock.get("installed_r116_f3_expected_sha256")
            == historical.R116_F3
        and lock.get("change_class") ==
            "LINUX_PATH_TYPE_COMPATIBILITY"
        and lock.get("candidate_git_commit_signed") is False
        and lock.get("independent_release_issued") is False
        and lock.get("root_install_authorized") is False
        and lock.get("root_install_performed") is False
        and lock.get("physical_execution_performed") is False
        and lock.get("a6") == "ND"
        and lock.get("a9") is None
        and lock.get("p8") == "NO-GO",
        "CANDIDATE_LOCK_INVALID",
    )

    manifest_b4 = {
        "schema":
            "ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle",
        "script_sha256": B4_SHA,
        "guard_sha256": historical.R116_GUARD,
        "approved_head": None,
        "deny_only": True,
        "root_install_independent": False,
    }

    manifest_b9 = {
        "schema":
            "ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle",
        "approved_head": None,
        "script_sha256": B9_SHA,
        "r126_deny_controller_sha256": B4_SHA,
        "legacy_f3_sha256": historical.R116_F3,
        "guard_sha256": historical.R116_GUARD,
        "root_staged_independently": False,
        "automatic_network": False,
        "p8": "NO-GO",
    }

    plan = {
        "schema": SCHEMA,
        "historical_source_head": BASE,
        "candidate_approved_head": None,
        "b4_sha256": B4_SHA,
        "b9_sha256": B9_SHA,
        "r116_guard_sha256": historical.R116_GUARD,
        "r116_f3_sha256": historical.R116_F3,
        "root_destinations": [TARGET_B4, TARGET_B9],
        "b4_operational_files_required": list(REQUIRED_B4),
        "b9_operational_files_required": list(REQUIRED_B9),
        "independent_signed_release_required": True,
        "root_owned_trust_required": True,
        "fresh_signed_revocations_required": True,
        "current_physical_five_one_required": True,
        "root_install_authorized": False,
        "root_install_performed": False,
        "traffic_executed": False,
        "candidate_files_are_source_only": True,
        "a6": "ND",
        "a9": None,
        "p8": "NO-GO",
    }
    plan["sha256"] = sha(canon(plan))

    contents = {
        "source-b4.py": b4,
        "source-b9.py": b9,
        "manifest-b4.draft.json": canon(manifest_b4),
        "manifest-b9.draft.json": canon(manifest_b9),
        "candidate-plan.json": canon(plan),
    }
    return plan, contents

def from_repository(repo):
    """Consume solamente rutas fijas del repositorio para revisión."""
    need(isinstance(repo, Path) and repo.is_dir()
         and not repo.is_symlink(), "REPOSITORY_INVALID")
    paths = (
        repo / "lab/operational-controller/"
               "r130-b17-r6b2-compat-lock.json",
        repo / "scripts/ardrec_p14_r130_b4_root_guard_v2.py",
        repo / "scripts/ardrec_p14_r130_b9_ftp_executor_v2.py",
    )
    blobs = []
    for path in paths:
        need(path.is_file() and not path.is_symlink(),
             "SOURCE_PATH_UNSAFE")
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1
             and 0 < s.st_size <= 131072, "SOURCE_METADATA_UNSAFE")
        raw = path.read_bytes()
        need(len(raw) == s.st_size, "SOURCE_SIZE_DRIFT")
        blobs.append(raw)
    return tuple(blobs)

def fsync_dir(path):
    fd = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_once(path, raw):
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
    )
    with os.fdopen(fd, "wb") as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())

def private_parent(parent):
    # Rechazar UID 0 antes de consultar la propiedad de la ruta.
    # Esto evita que el error de metadatos oculte la prohibición root.
    need(os.geteuid() != 0, "ROOT_EXECUTION_FORBIDDEN")
    need(isinstance(parent, Path) and parent.is_absolute()
         and not parent.is_symlink(), "PRIVATE_PATH_INVALID")
    st = parent.lstat()
    need(stat.S_ISDIR(st.st_mode)
         and st.st_uid == os.geteuid()
         and stat.S_IMODE(st.st_mode) == 0o700,
         "PRIVATE_PARENT_REQUIRED")
    return parent

def stage(lock_raw, b4, b9, *, parent, fault=None):
    """Un solo rename para publicar ambas fuentes de revisión.

    La exclusión mediante flock es cooperativa dentro de un
    directorio privado del mismo usuario. NO es un instalador root.
    """
    need(
        fault in (None, "after_b4", "after_b9", "before_publish"),
        "UNKNOWN_FAULT",
    )
    private_parent(parent)
    plan, contents = review_pair(lock_raw, b4, b9)

    lock_path = parent / ".r130-b3-stage.lock"
    lockfd = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        st = os.fstat(lockfd)
        need(
            stat.S_ISREG(st.st_mode)
            and st.st_uid == os.geteuid()
            and st.st_nlink == 1
            and st.st_size == 0
            and stat.S_IMODE(st.st_mode) == 0o600,
            "STAGING_LOCK_UNSAFE",
        )
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Stop("TRANSACTION_LOCK_BUSY") from exc

        final = parent / (
            "r130-b3-review-" + plan["sha256"][:24]
        )
        need(not final.exists() and not final.is_symlink(),
             "CANDIDATE_ALREADY_PUBLISHED")

        pending = Path(
            tempfile.mkdtemp(
                prefix=".r130-b3-incomplete-", dir=parent
            )
        )
        need(stat.S_IMODE(pending.stat().st_mode) == 0o700,
             "PENDING_MODE_INVALID")

        order = (
            "source-b4.py", "source-b9.py",
            "manifest-b4.draft.json",
            "manifest-b9.draft.json",
            "candidate-plan.json",
        )
        for name in order:
            write_once(pending / name, contents[name])
            if fault == "after_b4" and name == "source-b4.py":
                fsync_dir(pending)
                raise Stop("INJECTED_STOP_AFTER_B4")
            if fault == "after_b9" and name == "source-b9.py":
                fsync_dir(pending)
                raise Stop("INJECTED_STOP_AFTER_B9")

        receipt = {
            "schema": SCHEMA + "-private-receipt",
            "plan_sha256": plan["sha256"],
            "files": {
                name: sha(contents[name])
                for name in sorted(contents)
            },
            "root_install_authorized": False,
            "root_install_performed": False,
            "root_traffic_enabled": False,
            "p8": "NO-GO",
        }
        write_once(pending / "receipt.json", canon(receipt))
        fsync_dir(pending)
        fsync_dir(parent)

        if fault == "before_publish":
            raise Stop("INJECTED_STOP_BEFORE_PUBLICATION")

        # Publica solo la unidad de revisión, nunca dos
        # directorios operacionales por separado.
        need(not final.exists() and not final.is_symlink(),
             "CANDIDATE_ALREADY_PUBLISHED")
        os.rename(pending, final)
        fsync_dir(parent)

        return {
            "schema": SCHEMA + "-staged",
            "path": str(final),
            "plan_sha256": plan["sha256"],
            "root_install": False,
            "root_activation": False,
            "p8": "NO-GO",
        }
    finally:
        os.close(lockfd)

def capabilities():
    return {
        "schema": SCHEMA + "-capabilities",
        "pinned_b4_sha256": B4_SHA,
        "pinned_b9_sha256": B9_SHA,
        "single_private_review_publication": True,
        "retains_incomplete_evidence": True,
        "supports_fault_injection": True,
        "independent_release_required": True,
        "can_install_root": False,
        "can_start_vm": False,
        "can_open_network": False,
        "can_issue_authority": False,
        "p8": "NO-GO",
    }
