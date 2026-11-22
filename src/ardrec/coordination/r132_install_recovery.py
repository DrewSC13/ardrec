"""R132: recuperación de publicación parcial B4/B9.

Implementación estrictamente privada, sin autorización root ni tráfico.
Reutiliza las fuentes y la validación R130 existentes.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import stat

from ardrec.coordination import r130_b17_r6b3_root_candidate as r130


class Stop(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Stop(reason)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sync_dir(path: Path) -> None:
    fd = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path: Path) -> None:
    need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    need(
        isinstance(path, Path)
        and path.is_absolute()
        and not path.is_symlink(),
        "DIRECTORY_PATH_INVALID",
    )
    st = path.lstat()
    need(
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == os.geteuid()
        and stat.S_IMODE(st.st_mode) == 0o700,
        "PRIVATE_DIRECTORY_REQUIRED",
    )


def read_exact(path: Path, expected: bytes) -> None:
    need(not path.is_symlink(), "SYMLINK_DENIED")

    fd = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and before.st_size == len(expected),
            "FILE_METADATA_INVALID",
        )

        with os.fdopen(os.dup(fd), "rb") as stream:
            observed = stream.read(len(expected) + 1)

        after = os.fstat(fd)

        need(
            (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
                before.st_mode, before.st_uid, before.st_nlink,
            ) == (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
                after.st_mode, after.st_uid, after.st_nlink,
            ),
            "FILE_CHANGED_DURING_READ",
        )
        need(observed == expected, "FILE_CONTENT_MISMATCH")
    finally:
        os.close(fd)


def write_once(path: Path, value: bytes) -> None:
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def ensure_payload(folder: Path, payload: dict[str, bytes]) -> None:
    if folder.is_symlink():
        raise Stop("STAGING_SYMLINK_DENIED")

    if not folder.exists():
        folder.mkdir(mode=0o700)
        sync_dir(folder.parent)

    private_directory(folder)

    actual = {p.name for p in folder.iterdir()}
    need(actual <= set(payload), "UNEXPECTED_STAGING_ENTRY")

    for name, raw in sorted(payload.items()):
        path = folder / name
        if not path.exists() and not path.is_symlink():
            write_once(path, raw)
        read_exact(path, raw)

    sync_dir(folder)


def verify_published(
    folder: Path,
    payload: dict[str, bytes],
) -> None:
    """Verifica publicación existente sin crear ni reparar archivos."""

    need(
        folder.exists() and not folder.is_symlink(),
        "PUBLISHED_DIRECTORY_MISSING_OR_UNSAFE",
    )

    private_directory(folder)

    actual = {p.name for p in folder.iterdir()}

    need(
        actual == set(payload),
        "PUBLISHED_FILE_SET_CHANGED",
    )

    for name, raw in sorted(payload.items()):
        read_exact(folder / name, raw)


def apply(
    repo: Path,
    parent: Path,
    *,
    fault: str | None = None,
) -> dict:
    """Conciliación de dos publicaciones privadas.

    Una interrupción conserva el diario y los destinos.
    Nunca borra ni reemplaza un destino preexistente.
    """
    allowed_faults = {
        None, "before_b4", "after_b4",
        "after_b9", "before_receipt",
    }
    need(fault in allowed_faults, "UNKNOWN_FAULT")
    private_directory(parent)

    lock_raw, b4, b9 = r130.from_repository(repo)
    plan, files = r130.review_pair(lock_raw, b4, b9)

    payload_b4 = {
        "root-controller.py": files["source-b4.py"],
        "manifest.json": files["manifest-b4.draft.json"],
    }
    payload_b9 = {
        "root-executor.py": files["source-b9.py"],
        "manifest.json": files["manifest-b9.draft.json"],
    }

    journal = {
        "schema": "ARDREC-R132-PRIVATE-RECOVERY-v1",
        "plan_sha256": plan["sha256"],
        "b4_sha256": digest(payload_b4["root-controller.py"]),
        "b9_sha256": digest(payload_b9["root-executor.py"]),
        "privileged_install": False,
        "traffic_enabled": False,
        "p8": "NO-GO",
    }

    journal_raw = r130.canon(journal)

    lock = parent / ".r132-install.lock"
    fd = os.open(
        lock,
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )

    try:
        fst = os.fstat(fd)
        need(
            stat.S_ISREG(fst.st_mode)
            and fst.st_uid == os.geteuid()
            and fst.st_nlink == 1
            and fst.st_size == 0
            and stat.S_IMODE(fst.st_mode) == 0o600,
            "LOCK_METADATA_INVALID",
        )

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Stop("INSTALL_TRANSACTION_BUSY") from exc

        journal_path = parent / "transaction.json"

        b4_final = parent / "installed-b4"
        b9_final = parent / "installed-b9"

        if not journal_path.exists() and not journal_path.is_symlink():
            need(
                not b4_final.exists() and not b4_final.is_symlink()
                and not b9_final.exists() and not b9_final.is_symlink(),
                "PREEXISTING_DESTINATION_WITHOUT_JOURNAL",
            )
            write_once(journal_path, journal_raw)
            sync_dir(parent)

        read_exact(journal_path, journal_raw)

        receipt_path = parent / "receipt.json"

        if receipt_path.exists() or receipt_path.is_symlink():
            need(
                b4_final.is_dir()
                and not b4_final.is_symlink()
                and b9_final.is_dir()
                and not b9_final.is_symlink(),
                "PUBLISHED_PAIR_INCOMPLETE_AFTER_RECEIPT",
            )

        need(
            not (b9_final.exists() or b9_final.is_symlink())
            or (b4_final.exists() and not b4_final.is_symlink()),
            "B9_PUBLISHED_WITHOUT_B4",
        )

        if b4_final.exists() or b4_final.is_symlink():
            verify_published(b4_final, payload_b4)

        if b9_final.exists() or b9_final.is_symlink():
            verify_published(b9_final, payload_b9)

        staged_b4 = parent / ".pending-b4"
        staged_b9 = parent / ".pending-b9"

        if not b4_final.exists() and not b4_final.is_symlink():
            ensure_payload(staged_b4, payload_b4)

        if not b9_final.exists() and not b9_final.is_symlink():
            ensure_payload(staged_b9, payload_b9)

        if fault == "before_b4":
            raise Stop("INJECTED_BEFORE_B4")

        if not b4_final.exists() and not b4_final.is_symlink():
            os.rename(staged_b4, b4_final)
            sync_dir(parent)

        verify_published(b4_final, payload_b4)

        if fault == "after_b4":
            raise Stop("INJECTED_AFTER_B4")

        if not b9_final.exists() and not b9_final.is_symlink():
            os.rename(staged_b9, b9_final)
            sync_dir(parent)

        verify_published(b9_final, payload_b9)

        if fault == "after_b9":
            raise Stop("INJECTED_AFTER_B9")

        receipt = {
            "schema": "ARDREC-R132-PRIVATE-RECOVERY-RECEIPT-v1",
            "journal_sha256": digest(journal_raw),
            "b4_sha256": journal["b4_sha256"],
            "b9_sha256": journal["b9_sha256"],
            "privileged_install": False,
            "physical_execution": False,
            "traffic_enabled": False,
            "a6": "ND",
            "a9": None,
            "p8": "NO-GO",
        }

        receipt_raw = r130.canon(receipt)

        if fault == "before_receipt":
            raise Stop("INJECTED_BEFORE_RECEIPT")

        receipt_path = parent / "receipt.json"

        if not receipt_path.exists() and not receipt_path.is_symlink():
            write_once(receipt_path, receipt_raw)
            sync_dir(parent)

        read_exact(receipt_path, receipt_raw)

        return {
            "schema": receipt["schema"],
            "status": "PRIVATE_PAIR_CONCILED",
            "journal_sha256": digest(journal_raw),
            "receipt_sha256": digest(receipt_raw),
            "root_installed": False,
            "traffic_enabled": False,
            "p8": "NO-GO",
        }

    finally:
        os.close(fd)


def capabilities() -> dict:
    return {
        "schema": "ARDREC-R132-PRIVATE-RECOVERY-CAPABILITIES-v1",
        "partial_recovery": True,
        "idempotent_reconciliation": True,
        "preserves_existing_b4": True,
        "uses_pinned_r130_sources": True,
        "root_installer": False,
        "can_open_network": False,
        "p8": "NO-GO",
    }
