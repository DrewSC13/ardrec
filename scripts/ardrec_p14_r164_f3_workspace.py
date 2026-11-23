#!/usr/bin/env python3
"""ARDREC R164-F3: espacio experimental R148/R149 vinculado a Git.

No reinterpreta registros históricos ni acredita observaciones físicas.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess

from ardrec.experiments import r148_paired_register as r148
from ardrec.experiments import r149_scenario_design as r149

REPO = Path("/home/cicada/Development/GitHub/ardrec")
BRANCH = "feat/ardrec-integracion-funcional-experimental-v1"
BASE = "41a552fd385843e1f700ea35c5315f9bdec89be2"
CATALOG = REPO / "lab/operational-catalog-v1/catalog.json"
CATALOG_SHA = "5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e"

SCHEMA = "ARDREC-R164-F3-EXPERIMENTAL-WORKSPACE-v1"
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
FILES = {"register", "selection", "manifest.json"}


class Stop(ValueError):
    """Fallo cerrado, sin limpieza automática."""


def need(ok, reason):
    if not ok:
        raise Stop(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(path):
    need(
        path.is_absolute() and ".." not in path.parts,
        "DIRECTORY_PATH_INVALID",
    )
    st = path.lstat()
    need(
        stat.S_ISDIR(st.st_mode)
        and not path.is_symlink()
        and st.st_uid == os.geteuid()
        and stat.S_IMODE(st.st_mode) == 0o700,
        "DIRECTORY_NOT_PRIVATE:" + path.name,
    )


def read_private(folder, name):
    directory(folder)
    need(
        name in (
            "manifest.json", "protocol.json", "observations.json",
            "plan.json", "family-checklist.json",
            "family-proposal.csv",
        ),
        "FILENAME_DENIED",
    )
    fd = os.open(
        folder / name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        before = os.fstat(fd)
        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.geteuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= r148.MAX_BYTES,
            "FILE_NOT_PRIVATE:" + name,
        )
        data = bytearray()
        while len(data) < before.st_size:
            part = os.read(fd, before.st_size - len(data))
            need(bool(part), "SHORT_READ:" + name)
            data.extend(part)
        after = os.fstat(fd)
        need(
            (
                before.st_dev, before.st_ino, before.st_size,
                before.st_mtime_ns, before.st_ctime_ns,
            ) == (
                after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            ),
            "FILE_CHANGED:" + name,
        )
        return bytes(data)
    finally:
        os.close(fd)


def exclusive(path, raw):
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        with os.fdopen(fd, "wb") as output:
            fd = -1
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def metadata(catalog, head, tree, protocol, registry,
             plan, checklist, rows):
    return {
        "schema": SCHEMA,
        "catalog_sha256": sha(catalog),
        "source_head": head,
        "source_tree": tree,
        "r148_protocol_sha256": protocol["sha256"],
        "r148_registry_sha256": registry["sha256"],
        "r149_plan_sha256": plan["sha256"],
        "r149_checklist_sha256": checklist["sha256"],
        "r149_proposal_sha256": sha(r149.csv_bytes(rows)),
        "work_csv_editable": True,
        "records_verified_physically": 0,
        "human_independence_verified": False,
        "p7": "DRAFT_NOT_FROZEN",
        "p8": "NO-GO",
        "a6": "ND",
        "a9": "NOT_PUBLISHED",
    }


def prepare(folder, catalog, head, tree):
    need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    need(
        type(head) is str and HEX40.fullmatch(head)
        and type(tree) is str and HEX40.fullmatch(tree),
        "GIT_PINS_INVALID",
    )
    need(sha(catalog) == CATALOG_SHA, "CATALOG_CHANGED")
    need(
        folder.is_absolute()
        and ".." not in folder.parts
        and not folder.exists()
        and not folder.is_symlink(),
        "FOLDER_MUST_BE_NEW",
    )
    parent = folder.parent
    st = parent.lstat()
    need(
        stat.S_ISDIR(st.st_mode)
        and not parent.is_symlink()
        and st.st_uid == os.geteuid()
        and not (st.st_mode & 0o022),
        "PARENT_UNSAFE",
    )

    protocol, registry = r148.build(catalog, head)
    plan, checklist, rows = r149.draft(
        catalog, protocol, registry
    )
    os.mkdir(folder, 0o700)
    directory(folder)

    # Nunca borrar automáticamente un expediente parcialmente creado.
    r148.initialize(folder / "register", catalog, head)
    r149.create(
        folder / "selection", catalog, protocol, registry
    )
    document = metadata(
        catalog, head, tree, protocol, registry,
        plan, checklist, rows,
    )
    exclusive(
        folder / "manifest.json",
        r148.canonical(document),
    )
    return audit(folder, catalog)


def audit(folder, catalog):
    need(os.geteuid() != 0, "ROOT_FORBIDDEN")
    need(sha(catalog) == CATALOG_SHA, "CATALOG_CHANGED")
    directory(folder)
    need(
        {entry.name for entry in folder.iterdir()} == FILES,
        "WORKSPACE_FILE_SET_INVALID",
    )

    protocol, registry = r148.read(
        folder / "register", catalog
    )
    selection = r149.read(
        folder / "selection", catalog, protocol, registry
    )
    plan, checklist, rows = r149.draft(
        catalog, protocol, registry
    )
    manifest = r148.decode(
        read_private(folder, "manifest.json")
    )
    expected_keys = metadata(
        catalog, "0" * 40, "0" * 40,
        protocol, registry, plan, checklist, rows,
    )
    need(
        set(manifest) == set(expected_keys),
        "MANIFEST_KEYS_CHANGED",
    )
    head = manifest["source_head"]
    tree = manifest["source_tree"]
    need(
        type(head) is str and HEX40.fullmatch(head)
        and type(tree) is str and HEX40.fullmatch(tree)
        and head == protocol["head"],
        "MANIFEST_SOURCE_MISMATCH",
    )
    need(
        manifest == metadata(
            catalog, head, tree, protocol, registry,
            plan, checklist, rows,
        ),
        "MANIFEST_DRIFT",
    )
    need(
        sha(read_private(
            folder / "selection", "family-proposal.csv"
        )) == manifest["r149_proposal_sha256"],
        "PROPOSAL_DRIFT",
    )

    status = r148.validate(protocol, registry, catalog)
    analysis = r148.analyze(protocol, registry, catalog)

    need(
        status["confirmed_physical_observations"] == 0
        and selection["physical_observations"] == 0
        and analysis["claim"] ==
            "EXPLORATORY_UNVERIFIED_NOT_THESIS_RESULT"
        and status["p8"] == selection["p8"] ==
            analysis["p8"] == "NO-GO",
        "FALSE_PHYSICAL_CLAIM",
    )
    return {
        "manifest": manifest,
        "r148": status,
        "r149": selection,
        "analysis": analysis,
    }


def git(*args):
    result = subprocess.run(
        ["/usr/bin/git", *args],
        cwd=REPO,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        check=False,
    )
    need(
        result.returncode == 0,
        "GIT_FAILED:" + args[0],
    )
    return result.stdout.decode("utf-8").strip()


def git_guard():
    need(Path.cwd().resolve() == REPO, "NOT_REPOSITORY_ROOT")
    need(
        git("branch", "--show-current") == BRANCH,
        "BRANCH_MISMATCH",
    )
    need(
        git("status", "--porcelain=v1",
            "--untracked-files=all") == "",
        "WORKTREE_DIRTY",
    )
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    git("merge-base", "--is-ancestor", BASE, head)
    git("verify-commit", head)
    return head, tree


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--audit", action="store_true")
    parser.add_argument("--folder", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        head, tree = git_guard()
        catalog = CATALOG.read_bytes()
        result = (
            prepare(args.folder, catalog, head, tree)
            if args.prepare
            else audit(args.folder, catalog)
        )
        source = result["manifest"]["source_head"]
        git("merge-base", "--is-ancestor", source, head)
        need(
            git("rev-parse", source + "^{tree}") ==
                result["manifest"]["source_tree"],
            "SOURCE_TREE_CHANGED",
        )
        git("verify-commit", source)

        print("R164_F3_WORKSPACE=" + str(args.folder))
        print("R164_F3_GIT_SOURCE=" + source)
        print(
            "R164_F3_MANIFEST_SHA256=" +
            sha(read_private(args.folder, "manifest.json"))
        )
        print("R164_F3_PLANNED=54")
        print("R164_F3_FAMILIES=SSH:8,FTP:8,SMB:9")
        print(
            "R164_F3_SELECTION=" +
            result["r149"]["readiness"]
        )
        print("R164_F3_CONFIRMED_PHYSICAL=0")
        print(
            "R164_F3_ANALYSIS=" +
            result["analysis"]["claim"]
        )
        print("R164_F3_ROOT_WRITES=0")
        print("R164_F3_VM_STARTS=0")
        print("R164_F3_TRAFFIC=0")
        print("R164_F3_P8=NO-GO")
        print("R164_F3_FINAL=PASS_UNVERIFIED_WORKSPACE")
        return 0
    except (
        Stop, r148.Stop, r149.Stop, OSError,
        ValueError, subprocess.SubprocessError,
        KeyError, TypeError,
    ) as exc:
        print("R164_F3_FINAL=STOP")
        print(
            "REASON=" + type(exc).__name__ +
            ":" + str(exc)[:240]
        )
        print("AUTOMATIC_CLEANUP=NO")
        print("P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
