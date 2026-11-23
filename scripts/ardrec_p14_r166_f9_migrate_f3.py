#!/usr/bin/env python3
"""R166-F9: reconciliación F3 exclusiva, firmada, DENY y reversible.

--inspect: solo lectura.
--apply: requiere confirmación explícita, firma Git y preflight íntegro.
No modifica F1, no instala permisos, no arranca VM y no abre tráfico.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import runpy
import stat
import subprocess
import sys
from pathlib import Path

REPO = Path("/home/cicada/Development/GitHub/ardrec")
ROOT = Path("/var/lib/ardrec")
F1 = ROOT / "r116-f1-five-one-deny-v1"
F3 = ROOT / "r116-f3-ftp-pilot-root-v1"
CANDIDATE = ROOT / ".r166-f9-f3-candidate-v1"
ARCHIVE = ROOT / "r166-f9-f3-archive-v1"
OLD_HEAD = "81b1ed51d1a6a130d70b7790c34feec9d1a1d8af"
BASE = "36b4799c51ff7fb2dded22135f1da346a5954314"
BRANCH = "feat/ardrec-a1-a10-cierre-integral-v1"
SELF = "scripts/ardrec_p14_r166_f9_migrate_f3.py"
STAGER = "scripts/ardrec_p14_r116_f3_root_stage.py"
LOCK = "lab/operational-controller/r116-f3-root-source-lock-v1.json"
CATALOG = "lab/operational-catalog-v1/catalog.json"
TWO = {
    "runtime/ardrec/coordination/r115_f16_physical_pilot_controller.py",
    "runtime/ardrec/coordination/r115_f7_controlled_boot.py",
}
DIRS = {
    "runtime",
    "runtime/ardrec",
    "runtime/ardrec/coordination",
    "runtime/ardrec/evidence",
    "authority",
}

class Stop(ValueError):
    pass

def need(condition, reason):
    if not condition:
        raise Stop(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canon(doc):
    return (
        json.dumps(
            doc, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False
        ) + "\n"
    ).encode("ascii")

def git(*args):
    p = subprocess.run(
        ["/usr/bin/git", "-c", "safe.directory=" + str(REPO),
         "-C", str(REPO), *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=30,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"},
    )
    need(p.returncode == 0, "GIT_COMMAND_FAILED")
    return p.stdout

def directory(path, exact=None):
    s = path.lstat()
    need(
        stat.S_ISDIR(s.st_mode) and s.st_uid == 0
        and not (s.st_mode & 0o022) and not path.is_symlink(),
        "ROOT_DIRECTORY_UNTRUSTED"
    )
    if exact is not None:
        need(stat.S_IMODE(s.st_mode) == exact, "DIRECTORY_MODE_INVALID")

def root_file(path):
    need(not path.is_symlink(), "ROOT_FILE_SYMLINK")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        need(
            stat.S_ISREG(s.st_mode) and s.st_uid == 0
            and s.st_nlink == 1
            and stat.S_IMODE(s.st_mode) == 0o600
            and 0 < s.st_size <= 524288,
            "ROOT_FILE_CUSTODY_INVALID"
        )
        raw = os.read(fd, 524289)
        need(len(raw) == s.st_size, "ROOT_FILE_READ_CHANGED")
        return raw
    finally:
        os.close(fd)

def source_path(name):
    need(
        re.fullmatch(
            r"root-pilot\.py|runtime/ardrec/"
            r"(?:coordination|evidence)/[a-z0-9_]+\.py",
            name
        ) is not None,
        "SOURCE_DESTINATION_INVALID"
    )
    return (
        "scripts/ardrec_p14_r116_f3_root_pilot.py"
        if name == "root-pilot.py"
        else "src/" + name.removeprefix("runtime/")
    )

def signed_source(rel):
    raw = git("show", "HEAD:" + rel)
    path = REPO / rel
    need(
        path.is_file() and not path.is_symlink()
        and path.read_bytes() == raw,
        "SIGNED_SOURCE_DRIFT"
    )
    return raw

def safe_manifest(path):
    data = json.loads(root_file(path / "manifest.json"))
    need(type(data) is dict, "ROOT_MANIFEST_INVALID")
    return data

def compare_bundle(path, pins, expected_head):
    directory(path, 0o700)
    for name in DIRS:
        directory(path / name, 0o700)

    manifest = safe_manifest(path)
    need(
        manifest.get("head") == expected_head
        and manifest.get("source_sha256") == pins
        and manifest.get("p8") == "NO-GO"
        and manifest.get("a6") == "ND"
        and manifest.get("window_seconds") == 60
        and manifest.get("network_automatic") is False,
        "ROOT_MANIFEST_SCOPE_MISMATCH"
    )

    need(
        root_file(path / "lock") == b"R116_F3_ROOT_LOCK_V1\n",
        "ROOT_LOCK_MISMATCH"
    )
    need(
        not any((path / "authority").iterdir()),
        "AUTHORITY_DIRECTORY_NOT_EMPTY"
    )

    files = set()
    dirs = set()
    for item in path.rglob("*"):
        need(not item.is_symlink(), "ROOT_TREE_SYMLINK")
        relative = str(item.relative_to(path))
        if item.is_dir():
            dirs.add(relative)
        elif item.is_file():
            files.add(relative)
        else:
            raise Stop("ROOT_TREE_UNKNOWN_OBJECT")

    need(dirs == DIRS, "ROOT_DIRECTORY_SET_MISMATCH")
    need(
        files == set(pins) | {"manifest.json", "catalog.json", "lock"},
        "ROOT_FILE_SET_MISMATCH"
    )

    for name, digest in pins.items():
        need(
            sha(root_file(path / name)) == digest,
            "ROOT_SOURCE_DIGEST_MISMATCH"
        )

    return manifest

def deny_check():
    p = subprocess.run(
        ["/usr/bin/python3", "-I", "-B",
         str(F1 / "root-guard.py"), "--check"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=40,
        check=False,
    )
    need(p.returncode == 0, "F1_DENY_CHECK_FAILED")
    doc = json.loads(p.stdout)
    policy = doc.get("policy", {})
    need(
        doc.get("deny") == "MATCH"
        and doc.get("host_writes") == 0
        and doc.get("p8") == "NO-GO"
        and policy.get("active_count") == 0
        and policy.get("absent_count") == 6
        and doc.get("states") == {
            "ssh": "OFF", "runner": "OFF",
            "ftp": "OFF", "smb": "OFF"
        },
        "DENY_OFFLINE_NOT_ATTESTED"
    )

def preflight(*, candidate_allowed=False):
    need(os.geteuid() == 0, "ROOT_REQUIRED")
    for d in (Path("/"), Path("/var"), Path("/var/lib"), ROOT):
        directory(d)

    directory(F1, 0o700)

    need(
        git("branch", "--show-current").strip() == BRANCH.encode(),
        "BRANCH_MISMATCH"
    )
    need(
        git("status", "--porcelain=v1", "--untracked-files=all") == b"",
        "DIRTY_REPOSITORY"
    )
    need(
        git("log", "-1", "--format=%G?").strip() == b"G",
        "CURRENT_COMMIT_NOT_SIGNED"
    )
    git("merge-base", "--is-ancestor", BASE, "HEAD")

    head = git("rev-parse", "HEAD").decode().strip()
    need(re.fullmatch(r"[0-9a-f]{40}", head), "HEAD_INVALID")

    need(
        signed_source(SELF) == (REPO / SELF).read_bytes(),
        "MIGRATOR_NOT_SIGNED"
    )
    signed_source(STAGER)

    need(
        git("log", "-1", "--format=%G?", OLD_HEAD).strip() == b"G",
        "OLD_COMMIT_NOT_SIGNED"
    )
    git("merge-base", "--is-ancestor", OLD_HEAD, "HEAD")

    old_lock = json.loads(git("show", OLD_HEAD + ":" + LOCK))
    new_lock = json.loads(signed_source(LOCK))

    old_pins = old_lock["files"]
    new_pins = new_lock["files"]

    need(
        type(old_pins) is dict
        and type(new_pins) is dict
        and len(old_pins) == len(new_pins) == 33
        and set(old_pins) == set(new_pins),
        "SOURCE_LOCK_SET_CHANGED"
    )

    old = compare_bundle(F3, old_pins, OLD_HEAD)

    need(
        root_file(F3 / "catalog.json") == signed_source(CATALOG),
        "CATALOG_MISMATCH"
    )

    differences = set()
    for name in sorted(old_pins):
        relative = source_path(name)
        previous = git("show", OLD_HEAD + ":" + relative)
        current = signed_source(relative)
        installed = root_file(F3 / name)

        need(
            installed == previous and sha(previous) == old_pins[name],
            "OLD_SOURCE_PROVENANCE_FAILED"
        )
        need(
            sha(current) == new_pins[name],
            "NEW_SOURCE_PIN_FAILED"
        )
        if installed != current:
            differences.add(name)

    need(differences == TWO, "DIFFERENCE_SET_NOT_EXACT_TWO")

    need(
        root_file(F1 / "root-guard.py")
        == signed_source("scripts/ardrec_p14_r116_f1_root_deny_guard.py"),
        "F1_SOURCE_DRIFT"
    )
    need(
        root_file(F1 / "manifest.json")
        == signed_source("lab/operational-controller/r116-f1-root-bundle.json"),
        "F1_MANIFEST_DRIFT"
    )

    need(
        not (F1 / "arm-consumed.once").exists()
        and not (F3 / "pilot-attempted.once").exists(),
        "ONE_SHOT_ATTEMPT_PRESENT"
    )

    timer = subprocess.run(
        ["/usr/bin/systemctl", "list-units", "--all",
         "--plain", "--no-legend",
         "ardrec-r116-f1-deny-*.timer",
         "ardrec-r116-f1-deny-*.service"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    need(timer.returncode == 0, "TIMER_INVENTORY_FAILED")
    for line in timer.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split()
        need(
            len(fields) < 3 or fields[2] not in ("active", "activating"),
            "ACTIVE_GUARDIAN_TIMER_PRESENT"
        )

    need(
        not ARCHIVE.exists() and not ARCHIVE.is_symlink(),
        "ARCHIVE_ALREADY_PRESENT"
    )
    if not candidate_allowed:
        need(
            not CANDIDATE.exists() and not CANDIDATE.is_symlink(),
            "CANDIDATE_ALREADY_PRESENT"
        )

    deny_check()

    return head, old_pins, new_pins

def fsync_dir(path):
    fd = os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def receipt(path, data):
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600
    )
    with os.fdopen(fd, "wb") as output:
        output.write(canon(data))
        output.flush()
        os.fsync(output.fileno())

def migrate():
    head, old_pins, new_pins = preflight()

    # Reutiliza el instalador F3 firmado sin alterar su fuente.
    # Solo redirige el destino hacia un candidato root independiente.
    stage = runpy.run_path(
        str(REPO / STAGER),
        run_name="ardrec_r166_f9_signed_source_stage"
    )
    function = stage["stage"]
    function.__globals__["DEST"] = CANDIDATE
    function()

    compare_bundle(CANDIDATE, new_pins, head)
    need(
        root_file(CANDIDATE / "catalog.json")
        == signed_source(CATALOG),
        "CANDIDATE_CATALOG_MISMATCH"
    )

    # Repetición íntegra justo antes de cambiar nombres.
    preflight(candidate_allowed=True)

    os.mkdir(ARCHIVE, 0o700)
    old_path = ARCHIVE / "previous-f3"
    rejected = ARCHIVE / "rejected-new-f3"
    moved = False

    try:
        os.rename(F3, old_path)
        moved = True
        fsync_dir(ROOT)
        fsync_dir(ARCHIVE)

        os.rename(CANDIDATE, F3)
        fsync_dir(ROOT)

        compare_bundle(F3, new_pins, head)
        deny_check()

        receipt(
            ARCHIVE / "result.json",
            {
                "schema": "ARDREC-R166-F9-F3-MIGRATION-v1",
                "result": "PASS",
                "old_head": OLD_HEAD,
                "new_head": head,
                "old_sources_verified": 33,
                "new_sources_verified": 33,
                "changed_sources": sorted(TWO),
                "old_preserved": True,
                "f1_modified": False,
                "root_traffic": 0,
                "guest_starts": 0,
                "pilot_authority": "NOT_PROVISIONED",
                "a6": "ND",
                "p8": "NO-GO",
            },
        )
        fsync_dir(ARCHIVE)
        fsync_dir(ROOT)

    except BaseException:
        if moved:
            try:
                if F3.exists():
                    need(
                        not rejected.exists(),
                        "REJECTED_DESTINATION_ALREADY_PRESENT"
                    )
                    os.rename(F3, rejected)
                if old_path.exists() and not F3.exists():
                    os.rename(old_path, F3)
                fsync_dir(ROOT)
                fsync_dir(ARCHIVE)
                print("R166_F9_ROLLBACK=ATTEMPTED")
            except Exception:
                print("R166_F9_ROLLBACK=MANUAL_REVIEW_REQUIRED")
        raise

    print("R166_F9_OLD_F3=ARCHIVED")
    print("R166_F9_NEW_F3=PASS_33_SIGNED_SOURCES")
    print("R166_F9_F1=UNCHANGED")
    print("R166_F9_DENY=PASS_OFFLINE_0_6")
    print("R166_F9_MIGRATION=PASS_SOURCE_ONLY")
    print("R166_F9_VM_STARTS=0")
    print("R166_F9_TRAFFIC=0")
    print("R166_F9_A6=ND")
    print("R166_F9_P8=NO-GO")

def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--inspect", action="store_true")
    mode.add_argument("--apply", action="store_true")
    ap.add_argument("--confirm", default="")
    args = ap.parse_args()

    os.umask(0o077)
    try:
        if args.inspect:
            need(not args.confirm, "CONFIRM_NOT_ALLOWED_IN_INSPECT")
            head, old_pins, new_pins = preflight()
            print("R166_F9_SOURCE_HEAD=" + head)
            print("R166_F9_OLD_VERIFIED=" + str(len(old_pins)))
            print("R166_F9_NEW_VERIFIED=" + str(len(new_pins)))
            print("R166_F9_DIFFERENCES=EXACT_2")
            print("R166_F9_INSPECT=PASS_READONLY")
            print("R166_F9_P8=NO-GO")
            return 0

        need(
            args.confirm == "AUTORIZO_MIGRAR_SOLO_F3",
            "EXPLICIT_OPERATOR_CONSENT_REQUIRED"
        )
        migrate()
        return 0

    except (Stop, OSError, KeyError, TypeError, ValueError,
            subprocess.TimeoutExpired) as error:
        print("R166_F9_STOP=" + type(error).__name__
              + ":" + str(error)[:180].replace("\n", "_"))
        print("R166_F9_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
