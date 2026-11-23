#!/usr/bin/env python3
"""ARDREC R163-F7: pinned atomic bootstrap for V3 source candidates.

The privileged operation requires an externally installed, root-owned
bootstrap and a separately staged, root-owned bundle.

This module NEVER activates the historical B4/B9 executors, starts
virtual machines, opens FTP traffic, or grants P8.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile

SCHEMA = "ARDREC-R163-V3-ROOT-SOURCE-BUNDLE-v1"

HEAD = "db23e9927e6a8c6f78ef7dde6ebedc7843a2e769"
TREE = "6f43be2f5b7bbf338cc29c442cd4116ea89ac97c"

ZIP_SHA = (
    "d9a8371cdef6b7d628c1d07e00a9c267b1203d7ab46f5f1deb8305d9342fd4a0"
)

B4_SHA = (
    "f64ce5f8c31cd80f98d07f47eb99728e15e406a66b697044e3d5eefd6a3f73e8"
)

B9_SHA = (
    "c3c840f66476f3f0bbd87e48f657fdc6270e09b57b130eaf9c5b3cb68980cbd3"
)

SELF = Path(
    "/opt/ardrec/r163-bootstrap-v1/bootstrap.py"
)

SOURCE_DIR = Path(
    "/var/lib/ardrec/r163-bootstrap-source-v1"
)

SOURCE_ZIP = SOURCE_DIR / "agent.zip"

TARGET = Path(
    "/opt/ardrec/r163-installer-v1"
)

PENDING = Path(
    "/opt/ardrec/.r163-installer-v1.pending"
)

STATE = Path(
    "/var/lib/ardrec/r163-stage-state-v1"
)

FILES = (
    "installer.py",
    "runtime/r146_independent_install.py",
    "runtime/r163_single_operator_install_policy.py",
    "runtime/r163_install_phase_gate.py",
    "runtime/r163_single_operator_stage.py",
    "source/B4/source.py",
    "source/B9/source.py",
)

ENTRIES = frozenset(FILES) | {
    "manifest.json"
}


class Refusal(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Refusal(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(document):
    return (
        json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ) + "\n"
    ).encode("ascii")


def parse(raw):
    need(
        type(raw) is bytes
        and 0 < len(raw) <= 20000,
        "MANIFEST_BYTES_INVALID",
    )

    def pairs(items):
        document = {}
        for key, value in items:
            need(
                key not in document,
                "DUPLICATE_JSON_KEY",
            )
            document[key] = value
        return document

    try:
        document = json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: need(
                False,
                "NONFINITE_JSON",
            ),
        )
    except Refusal:
        raise
    except (ValueError, UnicodeError, TypeError) as exc:
        raise Refusal(
            "MANIFEST_JSON_INVALID"
        ) from exc

    need(
        type(document) is dict
        and canonical(document) == raw,
        "MANIFEST_NONCANONICAL",
    )

    return document


def audit_bytes(raw, expected_sha):
    """Bounded source-bundle audit without filesystem mutation."""

    need(
        type(raw) is bytes
        and 0 < len(raw) <= 2_000_000,
        "BUNDLE_SIZE_INVALID",
    )

    need(
        type(expected_sha) is str
        and sha(raw) == expected_sha,
        "BUNDLE_SHA_INVALID",
    )

    try:
        with zipfile.ZipFile(
            io.BytesIO(raw)
        ) as archive:

            names = archive.namelist()

            need(
                len(names) == len(set(names))
                and set(names) == ENTRIES,
                "BUNDLE_ENTRY_SET_INVALID",
            )

            content = {}

            for name in names:
                info = archive.getinfo(name)

                mode = info.external_attr >> 16

                need(
                    stat.S_IFMT(mode) == stat.S_IFREG
                    and not info.is_dir()
                    and 0 < info.file_size <= 500000,
                    "BUNDLE_ENTRY_METADATA_INVALID",
                )

                data = archive.read(info)

                need(
                    len(data) == info.file_size,
                    "BUNDLE_ENTRY_SIZE_INVALID",
                )

                content[name] = data

            need(
                archive.testzip() is None,
                "BUNDLE_CRC_INVALID",
            )

    except (
        zipfile.BadZipFile,
        EOFError,
        OSError,
    ) as exc:
        raise Refusal(
            "BUNDLE_ARCHIVE_INVALID"
        ) from exc

    document = parse(
        content["manifest.json"]
    )

    expected_fields = {
        "schema",
        "approved_head",
        "approved_tree",
        "operator_uid",
        "operator_id",
        "files",
        "inventory_sha256",
        "custody_mode",
        "independent_authority",
        "operational_activation",
        "candidate_only",
        "network_traffic_authorized",
        "p8",
    }

    need(
        set(document) == expected_fields,
        "BUNDLE_MANIFEST_FIELDS_INVALID",
    )

    need(
        document["schema"] == SCHEMA
        and document["approved_head"] == HEAD
        and document["approved_tree"] == TREE
        and type(document["operator_uid"]) is int
        and document["operator_uid"] > 0
        and type(document["operator_id"]) is str
        and re.fullmatch(
            r"[A-Za-z0-9_.-]{1,64}",
            document["operator_id"],
        ) is not None
        and document["custody_mode"]
            == "SINGLE_HUMAN_OPERATOR"
        and document["independent_authority"] is False
        and document["operational_activation"] is False
        and document["candidate_only"] is True
        and document["network_traffic_authorized"] is False
        and document["p8"] == "NO-GO",
        "BUNDLE_SCOPE_INVALID",
    )

    inventory = canonical({
        "B4/source.py": B4_SHA,
        "B9/source.py": B9_SHA,
    })

    need(
        document["inventory_sha256"] == sha(inventory)
        and type(document["files"]) is dict
        and set(document["files"]) == set(FILES),
        "BUNDLE_INVENTORY_INVALID",
    )

    for name in FILES:
        need(
            document["files"][name] == sha(content[name]),
            "BUNDLE_SOURCE_HASH_INVALID:" + name,
        )

    need(
        sha(content["source/B4/source.py"]) == B4_SHA,
        "B4_SOURCE_PIN_INVALID",
    )

    need(
        sha(content["source/B9/source.py"]) == B9_SHA,
        "B9_SOURCE_PIN_INVALID",
    )

    return content, document


def check_directory(path, private=False):
    info = path.lstat()

    need(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == 0
        and not (info.st_mode & 0o022),
        "ROOT_DIRECTORY_INVALID:" + str(path),
    )

    if private:
        need(
            stat.S_IMODE(info.st_mode) == 0o700,
            "PRIVATE_DIRECTORY_INVALID:" + str(path),
        )


def read_root_file(path, limit):
    need(
        isinstance(path, Path)
        and path.is_absolute()
        and not path.is_symlink(),
        "ROOT_FILE_PATH_INVALID",
    )

    for parent in reversed(path.parents):
        check_directory(parent)

    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
    )

    try:
        before = os.fstat(descriptor)

        need(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == 0
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= limit,
            "ROOT_FILE_METADATA_INVALID",
        )

        data = bytearray()

        while len(data) < before.st_size:
            chunk = os.read(
                descriptor,
                before.st_size - len(data),
            )

            need(
                bool(chunk),
                "ROOT_FILE_SHORT_READ",
            )

            data.extend(chunk)

        after = os.fstat(descriptor)

        need(
            (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ),
            "ROOT_FILE_READ_DRIFT",
        )

        return bytes(data)

    finally:
        os.close(descriptor)


def fsync_directory(path):
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
    )

    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive(path, raw):
    descriptor = os.open(
        path,
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC,
        0o600,
    )

    try:
        os.fchmod(descriptor, 0o600)

        with os.fdopen(
            descriptor,
            "wb",
        ) as output:

            descriptor = -1

            output.write(raw)
            output.flush()
            os.fsync(output.fileno())

    finally:
        if descriptor >= 0:
            os.close(descriptor)


def rename_noreplace(source, target):
    libc = ctypes.CDLL(
        None,
        use_errno=True,
    )

    need(
        hasattr(libc, "renameat2"),
        "ATOMIC_RENAME_UNAVAILABLE",
    )

    call = libc.renameat2

    call.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]

    call.restype = ctypes.c_int

    result = call(
        -100,
        os.fsencode(source),
        -100,
        os.fsencode(target),
        1,
    )

    if result != 0:
        error = ctypes.get_errno()

        raise OSError(
            error,
            os.strerror(error),
            str(target),
        )


def check_installed(content):
    check_directory(
        TARGET,
        private=True,
    )

    expected_directories = {
        "runtime": {
            Path(name).name
            for name in FILES
            if name.startswith("runtime/")
        },
        "source": {"B4", "B9"},
        "source/B4": {"source.py"},
        "source/B9": {"source.py"},
    }

    need(
        {entry.name for entry in TARGET.iterdir()}
        == {
            "installer.py",
            "manifest.json",
            "runtime",
            "source",
        },
        "INSTALLED_ROOT_ENTRY_SET_INVALID",
    )

    for relative, expected in expected_directories.items():
        folder = TARGET / relative

        check_directory(
            folder,
            private=True,
        )

        need(
            {entry.name for entry in folder.iterdir()}
            == expected,
            "INSTALLED_DIRECTORY_SCOPE_INVALID:" + relative,
        )

    for name, raw in content.items():
        installed = read_root_file(
            TARGET / name,
            500000,
        )

        need(
            installed == raw,
            "INSTALLED_SOURCE_READBACK_INVALID:" + name,
        )


def root_entry():
    need(
        os.geteuid() == 0,
        "ROOT_REQUIRED",
    )

    need(
        sys.flags.isolated == 1
        and sys.dont_write_bytecode,
        "ISOLATED_PYTHON_REQUIRED",
    )

    need(
        Path(__file__).absolute() == SELF
        and not Path(__file__).is_symlink(),
        "EXTERNAL_BOOTSTRAP_REQUIRED",
    )

    for path in (
        Path("/"),
        Path("/opt"),
        Path("/opt/ardrec"),
        SELF.parent,
        Path("/var"),
        Path("/var/lib"),
        Path("/var/lib/ardrec"),
        SOURCE_DIR,
    ):
        check_directory(
            path,
            private=path in (
                SELF.parent,
                SOURCE_DIR,
            ),
        )

    need(
        bool(read_root_file(SELF, 500000)),
        "BOOTSTRAP_SOURCE_UNAVAILABLE",
    )


def apply():
    """Privileged publication of non-operational sources only."""

    root_entry()

    content, _document = audit_bytes(
        read_root_file(
            SOURCE_ZIP,
            2_000_000,
        ),
        ZIP_SHA,
    )

    if not STATE.exists() and not STATE.is_symlink():
        STATE.mkdir(mode=0o700)
        os.chmod(STATE, 0o700)
        fsync_directory(STATE.parent)

    check_directory(
        STATE,
        private=True,
    )

    if TARGET.exists() or TARGET.is_symlink():
        check_installed(content)
        return "ALREADY_INSTALLED_VERIFIED"

    need(
        not PENDING.exists()
        and not PENDING.is_symlink(),
        "PENDING_STAGE_REQUIRES_MANUAL_REVIEW",
    )

    PENDING.mkdir(mode=0o700)
    os.chmod(PENDING, 0o700)

    for relative in (
        "runtime",
        "source",
        "source/B4",
        "source/B9",
    ):
        (PENDING / relative).mkdir(mode=0o700)
        os.chmod(PENDING / relative, 0o700)

    for name, raw in sorted(content.items()):
        write_exclusive(
            PENDING / name,
            raw,
        )

    for relative in (
        "runtime",
        "source/B4",
        "source/B9",
        "source",
        "",
    ):
        fsync_directory(
            PENDING / relative
        )

    rename_noreplace(
        PENDING,
        TARGET,
    )

    fsync_directory(
        TARGET.parent
    )

    check_installed(content)

    return "SOURCE_AGENT_INSTALLED_VERIFIED"


def main():
    parser = argparse.ArgumentParser()

    actions = parser.add_mutually_exclusive_group(
        required=True
    )

    actions.add_argument(
        "--capabilities",
        action="store_true",
    )

    actions.add_argument(
        "--audit",
        type=Path,
    )

    actions.add_argument(
        "--apply",
        action="store_true",
    )

    args = parser.parse_args()

    if args.capabilities:
        print("R163_F7=PINNED_SOURCE_BOOTSTRAP")
        print("R163_F7_EXTERNAL_BOOTSTRAP_REQUIRED=YES")
        print("R163_F7_RUNTIME_ACTIVATION=NO")
        print("R163_F7_P8=NO-GO")
        return 0

    try:
        if args.audit is not None:
            path = args.audit

            need(
                path.is_file()
                and not path.is_symlink(),
                "AUDIT_INPUT_INVALID",
            )

            audit_bytes(
                path.read_bytes(),
                ZIP_SHA,
            )

            print("R163_F7_BUNDLE_AUDIT=PASS")
            return 0

        result = apply()

        print("R163_F7_RESULT=" + result)
        print("R163_F7_ROOT_SOURCE_ONLY=YES")
        print("R163_F7_TRAFFIC=0")
        print("R163_F7_P8=NO-GO")

        return 0

    except (
        Refusal,
        OSError,
        KeyError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:

        print(
            "R163_F7_STOP="
            + type(exc).__name__
            + ":"
            + str(exc)[:200]
        )

        print("R163_F7_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
