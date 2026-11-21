"""R117 F5B: preflight root de solo lectura, fail-closed.

No importa modulos del checkout mutable y no ofrece apply,
boot, network, recuperacion ni publicacion.
"""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

ROOT = Path("/var/lib/ardrec")
EXECUTOR = ROOT / "r117-f5b-root-preflight-v2.py"
AGENT = ROOT / "r117-f5b-root-agent-v1"
PILOT = ROOT / "r117-f4-ftp-pilot-root-v1"
RELEASE = ROOT / "r117-f4-boot-release-v1"
ACTIVATION = ROOT / "r117-f5b-activation-v1.json"

PATCHES = Path(
    "/home/cicada/Development/GitHub/ardrec-patches"
)

HEAD = "1521f3af69e7875f6c79a60d7a905e5fbffdcba1"
CANDIDATE_SHA = (
    "fd75683758681684447d5f3c59c249d8077de914aa324b5c880a6fa23d03b11a"
)
AGENT_SHA = (
    "6e570b0eaeb0657b6be18a06de3fea34afb2f3b3294ddcbe6b882e9b2f92c2ee"
)

CANDIDATE_ZIP = PATCHES / (
    "R117_F5A_ROOT_CANDIDATE_" + HEAD[:12] + ".zip"
)
AGENT_ZIP = PATCHES / (
    "R117_ROOT_AGENT_SOURCE_ba7a184406a0.zip"
)

AGENT_NAMES = {
    "ardrec_r117_recovery_v1.py",
    "ardrec_r117_release_core_v1.py",
    "candidate.py",
    "installer.py",
    "source-manifest.json",
}

TRUST = {
    "bootstrap": (
        "/etc/ardrec/r117-authorities-v2/bootstrap-public.pem",
        "94d2038a17fd27efab4a4fc2bdb77dafff9eb3ebb1f659a516273080394e59aa",
    ),
    "approval": (
        "/etc/ardrec/r117-authorities-v1/approval-public.pem",
        "9c6753b9a439de6eb4a17ae87fe5a09b95816461f93a76a100b4e7b2c4843389",
    ),
    "revocation": (
        "/etc/ardrec/r117-authorities-v1/revocation-public.pem",
        "db3ac74dc6121d894b63cac0c55fec8405f281147df03c34d148d71c030dc828",
    ),
    "approval_alias": (
        "/etc/ardrec/r117-f5b-release-trust-v1.pem",
        "9c6753b9a439de6eb4a17ae87fe5a09b95816461f93a76a100b4e7b2c4843389",
    ),
}


class Stop(RuntimeError):
    pass


def need(condition, code):
    if not condition:
        raise Stop(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_bytes(path):
    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not info.st_mode & 0o022
            and 0 < info.st_size <= 2_000_000,
            "ARCHIVE_METADATA_INVALID",
        )
        raw = os.read(fd, 2_000_001)
        need(len(raw) == info.st_size, "ARCHIVE_READ_CHANGED")
        return raw
    finally:
        os.close(fd)


def members(raw, expected_count, strict=False):
    with zipfile.ZipFile(BytesIO(raw)) as bundle:
        entries = bundle.infolist()
        names = [item.filename for item in entries]

        need(
            len(entries) == len(set(names)) == expected_count,
            "ZIP_INVENTORY_INVALID",
        )

        for item in entries:
            parts = item.filename.split("/")
            need(
                re.fullmatch(r"[A-Za-z0-9_./-]+", item.filename)
                and all(part not in ("", ".", "..") for part in parts)
                and not item.is_dir()
                and item.file_size <= 200000,
                "ZIP_MEMBER_INVALID",
            )

            if strict:
                need(
                    item.compress_type == zipfile.ZIP_STORED
                    and item.external_attr >> 16 == 0o100600,
                    "ZIP_SOURCE_METADATA_CHANGED",
                )

        return {
            name: bundle.read(name)
            for name in names
        }


def verify_candidate(raw):
    need(sha(raw) == CANDIDATE_SHA, "CANDIDATE_SHA_CHANGED")
    files = members(raw, 39, strict=True)

    need(
        {"manifest.json", "catalog.json", "lock"} <= set(files),
        "CANDIDATE_CONTROL_FILES_MISSING",
    )

    manifest_raw = files["manifest.json"]
    manifest = json.loads(manifest_raw)

    canonical = (
        json.dumps(
            manifest, sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ) + "\n"
    ).encode("ascii")

    need(
        canonical == manifest_raw,
        "CANDIDATE_MANIFEST_NOT_CANONICAL",
    )

    sources = manifest.get("source_sha256")

    need(
        manifest.get("head") == HEAD
        and manifest.get("schema") ==
            "ARDREC-R117-F4-ROOT-FTP-PILOT-v1-root-bundle"
        and manifest.get("p8") == "NO-GO"
        and manifest.get("a6") == "ND"
        and manifest.get("network_automatic") is False
        and type(sources) is dict
        and len(sources) == 36
        and set(files) == set(sources) |
            {"manifest.json", "catalog.json", "lock"},
        "CANDIDATE_SCOPE_INVALID",
    )

    for name, expected in sources.items():
        need(
            type(expected) is str
            and sha(files[name]) == expected,
            "CANDIDATE_SOURCE_BYTES_CHANGED",
        )

    return files


def verify_agent(raw):
    need(sha(raw) == AGENT_SHA, "AGENT_SHA_CHANGED")
    files = members(raw, 5)
    need(set(files) == AGENT_NAMES, "AGENT_SCOPE_CHANGED")
    return files


def root_dir(path, mode=None):
    info = path.lstat()
    need(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == 0
        and not info.st_mode & 0o022,
        "ROOT_DIRECTORY_INVALID_" + str(path),
    )
    if mode is not None:
        need(
            stat.S_IMODE(info.st_mode) == mode,
            "ROOT_DIRECTORY_MODE_INVALID",
        )


def root_bytes(path, limit=200000):
    for parent in reversed(path.parents):
        root_dir(parent)

    fd = os.open(
        path,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        info = os.fstat(fd)
        need(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= limit,
            "ROOT_FILE_INVALID_" + str(path),
        )
        raw = os.read(fd, limit + 1)
        need(
            len(raw) == info.st_size,
            "ROOT_FILE_READ_CHANGED",
        )
        return raw
    finally:
        os.close(fd)


def check_unpublished(root):
    for name in (PILOT.name, RELEASE.name, ACTIVATION.name):
        item = root / name
        need(
            not item.exists() and not item.is_symlink(),
            "RELEASE_ALREADY_PRESENT_" + name,
        )

    need(
        not list(root.glob(".r117-f5b-transaction-*")),
        "PREVIOUS_RELEASE_TRANSACTION",
    )
    need(
        not list(root.glob(".r117-f5b-activation-pending-*")),
        "PENDING_RELEASE_ACTIVATION",
    )


def check_deny(doc):
    policy = doc.get("policy", {})

    need(
        doc.get("deny") == "MATCH"
        and doc.get("p8") == "NO-GO"
        and doc.get("host_writes") == 0
        and doc.get("states") == {
            "ssh": "OFF",
            "runner": "OFF",
            "ftp": "OFF",
            "smb": "OFF",
        }
        and type(policy) is dict
        and policy.get("active_count") == 0
        and policy.get("absent_count") == 6
        and policy.get("allow_traffic") is False,
        "PHYSICAL_DENY_CHANGED",
    )


def inspect_root():
    need(os.geteuid() == 0, "ROOT_REQUIRED")
    need(
        Path(__file__).absolute() == EXECUTOR,
        "EXECUTOR_NOT_INSTALLED_IN_ROOT",
    )

    root_bytes(EXECUTOR)
    root_dir(ROOT, 0o700)
    root_dir(AGENT, 0o700)

    candidate = verify_candidate(
        archive_bytes(CANDIDATE_ZIP)
    )
    originals = verify_agent(
        archive_bytes(AGENT_ZIP)
    )

    need(
        set(item.name for item in AGENT.iterdir()) ==
            set(originals),
        "ROOT_AGENT_INVENTORY_CHANGED",
    )

    for name, expected in originals.items():
        need(
            root_bytes(AGENT / name) == expected,
            "ROOT_AGENT_FILE_CHANGED_" + name,
        )

    for role, (path, expected) in TRUST.items():
        need(
            sha(root_bytes(Path(path), 4096)) == expected,
            "ROOT_TRUST_CHANGED_" + role,
        )

    guard = (
        ROOT / "r116-f1-five-one-deny-v1" /
        "root-guard.py"
    )

    root_bytes(guard)

    process = subprocess.run(
        [
            "/usr/bin/python3", "-I", "-B",
            str(guard), "--check",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=35,
        env={
            "PATH": "/usr/sbin:/usr/bin:/bin",
            "LC_ALL": "C",
        },
    )

    need(
        process.returncode == 0
        and len(process.stdout) <= 65536,
        "ROOT_DENY_GUARD_FAILED",
    )

    check_deny(json.loads(process.stdout))
    check_unpublished(ROOT)

    return {
        "head": HEAD,
        "candidate_sha256": CANDIDATE_SHA,
        "candidate_files": len(candidate),
        "root_agent_files": len(originals),
        "root_trust_pins": len(TRUST),
        "physical_deny": "PASS_0_6",
        "release_installed": False,
        "boot_authorized": False,
        "network_authorized": False,
        "p8": "NO-GO",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--offline", action="store_true")
    mode.add_argument("--root", action="store_true")
    args = parser.parse_args()

    try:
        if args.offline:
            need(
                os.geteuid() != 0,
                "OFFLINE_MUST_BE_UNPRIVILEGED",
            )
            verify_candidate(archive_bytes(CANDIDATE_ZIP))
            verify_agent(archive_bytes(AGENT_ZIP))
            print("R117_F5B_OFFLINE=PASS_39_AND_5")
            print("R117_F5B_PHYSICAL_PREFLIGHT=NOT_EXECUTED")
        else:
            report = inspect_root()
            print(
                "R117_F5B_ROOT_REPORT=" +
                json.dumps(report, sort_keys=True)
            )
            print("R117_F5B_ROOT_PREFLIGHT=PASS_READ_ONLY")

        print("R117_F5B_APPLY=BLOCKED")
        print("R117_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, KeyError, TypeError,
        zipfile.BadZipFile, subprocess.TimeoutExpired,
    ) as error:
        print(
            "R117_F5B_PREFLIGHT_STOP=" +
            type(error).__name__ + ":" + str(error)[:180]
        )
        print("R117_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
