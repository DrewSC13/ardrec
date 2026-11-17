"""R59-C: preparar y ensayar una instalación F11 DENY en un árbol PRIVADO.

NO instala nada en /etc, no ejecuta systemctl, nft, sudo o virsh, no toca VM.
Este módulo no contiene ninguna ruta de aplicación privilegiada. Sólo ensaya
creación, comprobación e inversión de cuatro archivos versionados en un
subdirectorio fijo de una caja de pruebas privada.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "ardrec-r59c-f11-staging-transaction-simulation-v1"
PLAN_SCHEMA = "ardrec-r59c-f11-source-plan-v1"
FILES = {
    "00-ardrec-r33-deny": (
        "8bad829fa029d78375f28f6978669721dc934481a97ee867449f45a1662dbc38",
        "etc/libvirt/hooks/qemu.d/00-ardrec-r33-deny", 0o755),
    "libvirtd-f11-guard.conf": (
        "5368b91b633b271da037633e374e4b04df801a3fe1d76dafa72e5876b79b6009",
        "etc/systemd/system/libvirtd.service.d/90-ardrec-r34-boot.conf", 0o644),
    "ardrec-r34-deny-watchdog.service": (
        "4a70c34311cf8980f05bdb14d82ef87d2b9fb4b377f6d26201c4d5f41532e079",
        "etc/systemd/system/ardrec-r34-deny-watchdog.service", 0o644),
    "ardrec-r34-deny-watchdog.timer": (
        "5e50b1ddf916c2389d015cf4e627a70f6e17765f4cc40104345a933ce9654a14",
        "etc/systemd/system/ardrec-r34-deny-watchdog.timer", 0o644),
}
ORDER = tuple(FILES)
STAGE = "F11_SANDBOX_SIMULATED_NOT_ETC"
RECEIPT = "r59c-simulation-receipt.json"
MAX_BLOB = 16384

class StageError(ValueError):
    pass

def require(ok: bool, reason: str) -> None:
    if not ok:
        raise StageError(reason)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")

def _private_root(root: Path) -> None:
    require(isinstance(root, Path) and root.is_absolute() and
            root.is_dir() and not root.is_symlink() and root != Path("/") and
            root != Path("/etc") and not root.is_relative_to(Path("/etc")) and
            not root.is_relative_to(Path("/usr")) and
            not root.is_relative_to(Path("/var/lib/ardrec")),
            "SIMULATION_PRIVATE_ROOT_REQUIRED")
    s = root.stat()
    require(s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == 0o700,
            "SIMULATION_ROOT_OWNER_OR_PERMISSIONS")
    # Parent filesystem symlinks can redirect a simulator outside private root.
    for p in (root, *root.parents):
        require(not p.is_symlink(), "SIMULATION_PARENT_SYMLINK")

def _source_file(path: Path, expected: str) -> bytes:
    require(not path.is_symlink(), "SOURCE_SYMLINK")
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and 0 < s.st_size < MAX_BLOB and
            not (stat.S_IMODE(s.st_mode) & 0o022), "SOURCE_TYPE_MODE_OR_LENGTH")
    # O_NOFOLLOW makes the final component non-following even if replaced.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        data = os.read(fd, MAX_BLOB)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    require((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns, before.st_mode) ==
            (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns, after.st_mode) and len(data) == before.st_size,
            "SOURCE_CHANGED_DURING_READ")
    require(sha(data) == expected, "PINNED_SOURCE_HASH_MISMATCH:" + path.name)
    return data

def verified_sources(repo: Path) -> dict[str, bytes]:
    require(isinstance(repo, Path) and repo.is_absolute() and repo.is_dir() and
            not repo.is_symlink(), "REPOSITORY_INVALID")
    location = repo / "lab/f11-runtime-v1"
    return {name: _source_file(location / name, FILES[name][0])
            for name in ORDER}

def plan(repo: Path) -> dict:
    sources = verified_sources(repo)
    require(set(sources) == set(FILES), "SOURCE_COMPLETENESS")
    result = {
        "schema": PLAN_SCHEMA,
        "status": "SOURCE_VERIFIED_STAGE_ONLY_NO_HOST_INSTALL",
        "target_files": {name: {
            "target": "/" + FILES[name][1],
            "sha256": FILES[name][0], "mode_octal": oct(FILES[name][2]),
        } for name in ORDER},
        "privileged_install_implemented": False,
        "privileged_installer_executed": False,
        "systemd_daemon_reload": False,
        "libvirtd_restarted": False,
        "watchdog_enabled": False,
        "qemu_hook_loaded_attested": False,
        "manual_boot_denial_attested": False,
        "f11_accepted": False,
        "vm_starts": 0,
        "host_mutations": 0,
        "operational_dispatch": False,
        "p8": "NO-GO",
    }
    return result

def _safe_path(stage: Path, relative: str) -> Path:
    require(stage.name == STAGE and stage.parent.is_dir(), "SIM_STAGE_NAME")
    rel = Path(relative)
    require(not rel.is_absolute() and all(x not in ("", ".", "..") for x in rel.parts),
            "SIM_RELATIVE_PATH")
    child = stage / rel
    require(child.is_relative_to(stage), "SIM_PATH_ESCAPE")
    return child

def _receipt(sources: dict[str, bytes]) -> dict:
    doc = {
        "schema": SCHEMA,
        "stage_name": STAGE,
        "source_sha256": {n: sha(sources[n]) for n in ORDER},
        "destinations": {n: FILES[n][1] for n in ORDER},
        "mode_octal": {n: oct(FILES[n][2]) for n in ORDER},
        "host_mutations": 0,
        "privileged_install": False,
        "p8": "NO-GO",
    }
    doc["sha256"] = sha(canonical(doc))
    return doc

def _file_matches(path: Path, raw: bytes, mode: int) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    s = path.stat()
    return (s.st_uid == os.getuid() and stat.S_IMODE(s.st_mode) == mode and
            s.st_size == len(raw) and path.read_bytes() == raw)

def _write_new(path: Path, raw: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(path, mode, follow_symlinks=False)
    except BaseException:
        try:
            if path.is_file() and not path.is_symlink():
                path.unlink()
        finally:
            raise

def _verify_inventory(root: Path) -> None:
    expected_files = {root / RECEIPT} | {root / FILES[n][1] for n in ORDER}
    expected_dirs = {root}
    for target in expected_files:
        current = target.parent
        while current != root:
            expected_dirs.add(current)
            current = current.parent
    observed_files = set()
    observed_dirs = set()
    for current, dirs, files in os.walk(root, followlinks=False):
        d = Path(current)
        observed_dirs.add(d)
        st = d.stat()
        require(not d.is_symlink() and st.st_uid == os.getuid() and
                stat.S_IMODE(st.st_mode) == 0o700, "SIM_DIRECTORY_MODE_OR_OWNER")
        for name in dirs:
            p = d / name
            require(not p.is_symlink(), "SIM_DIRECTORY_SYMLINK")
        for name in files:
            p = d / name
            require(not p.is_symlink() and p.is_file(), "SIM_FILE_SYMLINK_OR_TYPE")
            observed_files.add(p)
    require(observed_files == expected_files and observed_dirs == expected_dirs,
            "SIM_UNEXPECTED_PATH_OR_MISSING_ITEM")

def simulate(sandbox: Path, sources: dict[str, bytes], *, fail_after: int = 0) -> dict:
    """Only sandbox writes, idempotence, and all-or-nothing rollback by source."""
    _private_root(sandbox)
    require(type(sources) is dict and set(sources) == set(FILES) and
            all(type(x) is bytes and 0 < len(x) < MAX_BLOB for x in sources.values()),
            "SIM_INPUT_SCHEMA")
    require(type(fail_after) is int and 0 <= fail_after <= 4, "SIM_FAULT_INJECTION")
    root = sandbox / STAGE
    receipt = _receipt(sources)
    if root.exists() or root.is_symlink():
        require(root.is_dir() and not root.is_symlink(), "SIM_ALREADY_EXISTS_NOT_DIRECTORY")
        actual = root / RECEIPT
        require(actual.is_file() and not actual.is_symlink(), "SIM_PARTIAL_NO_RECEIPT")
        require(actual.read_bytes() == canonical(receipt), "SIM_RECEIPT_CONFLICT")
        for n in ORDER:
            require(_file_matches(_safe_path(root, FILES[n][1]), sources[n], FILES[n][2]),
                    "SIM_REPLAY_DESTINATION_TAMPERED:" + n)
        require(stat.S_IMODE(actual.stat().st_mode) == 0o600, "SIM_RECEIPT_MODE")
        _verify_inventory(root)
        return {"status": "REPLAY_IDENTICAL", "receipt_sha256": receipt["sha256"],
                "files": 4, "host_mutations": 0, "p8": "NO-GO"}
    root.mkdir(mode=0o700, exist_ok=False)
    created_dirs = [root]
    created_files: list[Path] = []
    try:
        for index, n in enumerate(ORDER, 1):
            target = _safe_path(root, FILES[n][1])
            missing = []
            current = target.parent
            while not current.exists():
                require(current.is_relative_to(root), "SIM_DIR_ESCAPE")
                missing.append(current)
                current = current.parent
            require(current.is_dir() and not current.is_symlink(), "SIM_DIR_CONFLICT")
            for d in reversed(missing):
                d.mkdir(mode=0o700, exist_ok=False)
                created_dirs.append(d)
            require(not target.exists() and not target.is_symlink(), "SIM_TARGET_CONFLICT")
            _write_new(target, sources[n], FILES[n][2])
            created_files.append(target)
            require(_file_matches(target, sources[n], FILES[n][2]), "SIM_READBACK_MISMATCH")
            if fail_after == index:
                raise StageError("SIM_INJECTED_FAILURE_AFTER_" + str(index))
        target = root / RECEIPT
        _write_new(target, canonical(receipt), 0o600)
        created_files.append(target)
        require(target.read_bytes() == canonical(receipt), "SIM_RECEIPT_READBACK")
        _verify_inventory(root)
        return {"status": "STAGED_ONLY_IN_PRIVATE_SANDBOX", "receipt_sha256": receipt["sha256"],
                "files": 4, "host_mutations": 0, "p8": "NO-GO"}
    except BaseException:
        # Only unlink paths created in this invocation. Never remove prior state.
        for path in reversed(created_files):
            if path.is_file() and not path.is_symlink():
                path.unlink()
        for d in reversed(created_dirs):
            if d.is_dir() and not d.is_symlink():
                d.rmdir()
        raise

def verify_simulation(sandbox: Path, sources: dict[str, bytes]) -> dict:
    _private_root(sandbox)
    result = simulate(sandbox, sources)
    require(result["status"] == "REPLAY_IDENTICAL", "SIM_NOT_PREVIOUSLY_STAGED")
    return result
