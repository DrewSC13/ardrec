#!/usr/bin/env python3
"""R117-F5A: reproducible root candidate. SOURCE_ONLY, NO-GO."""
from __future__ import annotations

import argparse
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True

REPO = Path("/home/cicada/Development/GitHub/ardrec")
BASE = "8c3d2b4647747898684c9211bcc41c9968eb3cfe"
R116 = "fdb6efa0c297ce18b28cddb9494514f51d88bdb4"
BRANCH = "feat/p14-r117-piloto-real-a5-a10"
LOCK = "lab/operational-controller/r116-f3-root-source-lock-v1.json"

# R168-F12: hashes exactos; el manifiesto historico no cambia.
R168_HISTORIC_LOCK_SHA = 'eb6e1dc56576fe59d973eb76b6b563d0baf44cdabcd06d5857f908ee345ca53d'
R168_DERIVED_LOCK_SHA = '2d15b24c9101d7615ca6f43dca3b050f1f6058ac3672592b621d3da042dd319a'
DISPATCH = "lab/operational-controller/r117-f4-dispatch-sources-v1.json"
CATALOG = "lab/operational-catalog-v1/catalog.json"
PILOT = "scripts/ardrec_p14_r116_f3_root_pilot.py"
SCHEMA = "ARDREC-R117-F4-ROOT-FTP-PILOT-v1-root-bundle"

F4 = (
    "src/ardrec/coordination/r117_f4_controlled_boot.py",
    "src/ardrec/coordination/r117_f4_runner_ftp_boot.py",
    "src/ardrec/coordination/r117_f4_root_release.py",
)

TRANSFORMS = (
    ("r116-f3-ftp-pilot-root-v1", "r117-f4-ftp-pilot-root-v1"),
    ("'ARDREC-R116-F3-ROOT-FTP-PILOT-v1'",
     "'ARDREC-R117-F4-ROOT-FTP-PILOT-v1'"),
    ("'e193b1dcf97f72ba4245fc7dfc6d0d4b9814eecc'",
     "'" + R116 + "'"),
    ("r116-f12-runner-ftp-deny-v1", "r117-f4-runner-ftp-deny-v1"),
    ("from ardrec.coordination import r116_f12_runner_ftp_boot as f8",
     "from ardrec.coordination import r117_f4_runner_ftp_boot as f8"),
    ("'version':'R116-F12'", "'version':'R117-F4'"),
)

class Stop(ValueError):
    pass

def need(ok, reason):
    if not ok:
        raise Stop(reason)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(obj):
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=True, allow_nan=False) + "\n"
    ).encode("ascii")

def strict_json(raw):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            need(key not in obj, "DUPLICATE_JSON_FIELD")
            obj[key] = value
        return obj

    result = json.loads(
        raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(
            Stop("NONFINITE_JSON"))
    )
    need(type(result) is dict, "JSON_OBJECT_REQUIRED")
    return result

def read_source(repo, name):
    relative = Path(name)
    need(not relative.is_absolute() and
         ".." not in relative.parts, "INVALID_SOURCE_PATH")
    item = repo / relative
    need(item.is_file() and not item.is_symlink() and
         item.resolve().is_relative_to(repo.resolve()),
         "UNTRUSTED_SOURCE_" + name)
    return item.read_bytes()

def transform(raw):
    source = raw.decode("utf-8")
    for old, new in TRANSFORMS:
        need(source.count(old) == 1,
             "SOURCE_TRANSFORM_DRIFT_" + old[:30])
        source = source.replace(old, new, 1)

    need("r116-f3-ftp-pilot-root-v1" not in source and
         "r116-f12-runner-ftp-deny-v1" not in source,
         "OBSOLETE_ROOT_REFERENCE")

    result = source.encode("utf-8")
    compile(result, "root-pilot.py", "exec", dont_inherit=True)
    return result

def checked_sources(repo=REPO):
    lock_raw = read_source(repo, LOCK)
    lock = strict_json(lock_raw)
    dispatch = strict_json(read_source(repo, DISPATCH))

    need(
        lock.get("schema") ==
        "ARDREC-R116-F3-ROOT-FTP-PILOT-v1-source-lock"
        and lock.get("p8") == "NO-GO"
        and lock.get("window_seconds") == 60
        and type(lock.get("files")) is dict
        and len(lock["files"]) == 33,
        "HISTORICAL_LOCK_INVALID",
    )

    need(
        dispatch.get("schema") ==
        "ARDREC-R117-F4-VERSIONED-BOOT-DISPATCH-v1"
        and dispatch.get("p8") == "NO-GO"
        and dispatch.get("root_release") == "NOT_INSTALLED"
        and dispatch.get("historical_f3_lock_sha256")
            == R168_HISTORIC_LOCK_SHA
        and sha(lock_raw) in (
            R168_HISTORIC_LOCK_SHA,
            R168_DERIVED_LOCK_SHA,
        )
        and type(dispatch.get("source_sha256")) is dict
        and set(dispatch["source_sha256"]) == set(F4),
        "R117_F4_DISPATCH_INVALID",
    )

    payload = {}

    for name, expected in sorted(lock["files"].items()):
        need(
            re.fullmatch(
                r"(root-pilot\.py|runtime/ardrec/"
                r"(?:coordination|evidence)/[a-z0-9_]+\.py)",
                name,
            ) is not None
            and type(expected) is str
            and re.fullmatch("[0-9a-f]{64}", expected),
            "HISTORICAL_ENTRY_INVALID",
        )

        source_name = (
            PILOT if name == "root-pilot.py"
            else "src/" + name.removeprefix("runtime/")
        )

        original = read_source(repo, source_name)
        need(sha(original) == expected,
             "HISTORICAL_SOURCE_CHANGED_" + name)

        payload[name] = (
            transform(original) if name == "root-pilot.py"
            else original
        )

    for name in F4:
        data = read_source(repo, name)
        need(sha(data) == dispatch["source_sha256"][name],
             "R117_SOURCE_CHANGED_" + name)

        runtime_name = "runtime/ardrec/coordination/" + Path(name).name
        need(runtime_name not in payload, "RUNTIME_DUPLICATE")
        payload[runtime_name] = data

    catalog = read_source(repo, CATALOG)
    need(sha(catalog) == lock["catalog_sha256"],
         "CATALOG_BYTES_CHANGED")

    payload["catalog.json"] = catalog
    payload["lock"] = b"R117_F4_ROOT_LOCK_V1\n"
    return payload, lock

def manifest(head, payload, lock):
    need(type(head) is str and
         re.fullmatch("[0-9a-f]{40}", head), "INVALID_HEAD")

    runtime = sorted(
        name for name in payload
        if name == "root-pilot.py" or
        name.startswith("runtime/")
    )
    need(len(runtime) == 36, "RUNTIME_COUNT_DRIFT")

    return {
        "schema": SCHEMA,
        "head": head,
        "base": R116,
        "source_sha256": {
            name: sha(payload[name]) for name in runtime
        },
        "p8": "NO-GO",
        "a6": "ND",
        "window_seconds": 60,
        "network_automatic": False,
        "authority_paths": [
            "contract.json",
            "scope-authorization.json",
            "pilot-permit.json",
        ],
        "catalog_sha256": lock["catalog_sha256"],
    }

def pack(items):
    buffer = BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_STORED,
        allowZip64=False
    ) as archive:
        for name in sorted(items):
            need(
                re.fullmatch("[A-Za-z0-9_./-]+", name)
                and not name.startswith("/")
                and ".." not in Path(name).parts,
                "INVALID_ARCHIVE_NAME",
            )
            entry = zipfile.ZipInfo(
                name, date_time=(1980, 1, 1, 0, 0, 0)
            )
            entry.create_system = 3
            entry.external_attr = 0o100600 << 16
            entry.compress_type = zipfile.ZIP_STORED
            archive.writestr(entry, items[name])
    return buffer.getvalue()

def candidate(head, repo=REPO):
    payload, lock = checked_sources(repo)
    payload["manifest.json"] = canonical(
        manifest(head, payload, lock)
    )
    return pack(payload)

def audit(raw, repo=REPO, expected_head=None):
    need(type(raw) is bytes and
         0 < len(raw) < 2000000, "ARCHIVE_SIZE_LIMIT")

    with zipfile.ZipFile(BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = [item.filename for item in entries]

        need(len(names) == len(set(names)) == 39,
             "ARCHIVE_FILE_COUNT_OR_DUPLICATES")

        for entry in entries:
            need(
                re.fullmatch("[A-Za-z0-9_./-]+", entry.filename)
                and not entry.filename.startswith("/")
                and ".." not in Path(entry.filename).parts
                and not entry.is_dir()
                and (entry.external_attr >> 16) == 0o100600
                and entry.compress_type == zipfile.ZIP_STORED
                and entry.file_size <= 200000,
                "ARCHIVE_MEMBER_UNTRUSTED",
            )

        records = {
            name: archive.read(name) for name in names
        }

    document = strict_json(records["manifest.json"])

    need(
        set(document) == {
            "schema", "head", "base", "source_sha256",
            "p8", "a6", "window_seconds",
            "network_automatic", "authority_paths",
            "catalog_sha256",
        }
        and document["schema"] == SCHEMA
        and document["base"] == R116
        and document["p8"] == "NO-GO"
        and document["a6"] == "ND"
        and document["window_seconds"] == 60
        and document["network_automatic"] is False
        and document["authority_paths"] == [
            "contract.json",
            "scope-authorization.json",
            "pilot-permit.json",
        ]
        and type(document["source_sha256"]) is dict
        and len(document["source_sha256"]) == 36,
        "ARCHIVE_MANIFEST_INVALID",
    )

    need(expected_head is None or
         document["head"] == expected_head,
         "ARCHIVE_HEAD_MISMATCH")

    need(
        records["manifest.json"] == canonical(document),
        "MANIFEST_NOT_CANONICAL",
    )

    need(
        set(records) ==
        set(document["source_sha256"]) |
        {"manifest.json", "catalog.json", "lock"},
        "ARCHIVE_FILE_SCOPE",
    )

    payload, lock = checked_sources(repo)
    expected = dict(payload)
    expected["manifest.json"] = canonical(
        manifest(document["head"], expected, lock)
    )

    need(set(records) == set(expected),
         "ARCHIVE_SOURCE_SET_CHANGED")

    for name in records:
        need(records[name] == expected[name],
             "ARCHIVE_BYTES_NOT_AUTHENTIC_" + name)

    return document

def git(*args):
    process = subprocess.run(
        ["git", "-C", str(REPO), *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=20,
    )
    need(process.returncode == 0,
         "GIT_CHECK_FAILED")
    return process.stdout.decode("utf-8").strip()

def signed_head():
    need(os.geteuid() != 0 and
         Path.cwd().resolve() == REPO,
         "REPOSITORY_OR_USER_INVALID")
    need(git("branch", "--show-current") == BRANCH,
         "BRANCH_MISMATCH")
    need(git("log", "-1", "--format=%G?") == "G",
         "UNVERIFIED_CURRENT_COMMIT")
    need(not git(
        "status", "--porcelain=v1", "--untracked-files=all"
    ), "DIRTY_REPOSITORY")
    git("merge-base", "--is-ancestor", BASE, "HEAD")
    return git("rev-parse", "HEAD")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--offline", action="store_true")
    modes.add_argument("--build", type=Path)
    modes.add_argument("--audit", type=Path)
    args = parser.parse_args()

    try:
        need(os.geteuid() != 0,
             "ROOT_EXECUTION_FORBIDDEN")

        if args.offline:
            payload, lock = checked_sources()
            need(len(payload) == 38 and
                 len(lock["files"]) == 33,
                 "ROOT_CANDIDATE_SOURCE_COUNT")
            print(
                "R117_F5A_OFFLINE="
                "PASS_33_HISTORICAL_PLUS_3_F4_SOURCES"
            )

        elif args.build is not None:
            head = signed_head()
            data = candidate(head)
            audit(data, expected_head=head)

            target = args.build.expanduser().absolute()
            need(target.parent.is_dir() and
                 not target.is_symlink(),
                 "CANDIDATE_PATH_UNSAFE")

            fd = os.open(
                target, os.O_WRONLY | os.O_CREAT |
                os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())

            print("R117_F5A_CANDIDATE=" + str(target))
            print("R117_F5A_CANDIDATE_SHA256=" + sha(data))
            print("R117_F5A_HEAD=" + head)

        else:
            need(args.audit.is_file() and
                 not args.audit.is_symlink(),
                 "ARCHIVE_NOT_REGULAR")
            data = args.audit.read_bytes()
            report = audit(data)
            print("R117_F5A_ARCHIVE=PASS_EXACT_SOURCE_BYTES")
            print("R117_F5A_HEAD=" + report["head"])
            print("R117_F5A_CANDIDATE_SHA256=" + sha(data))

        print("R117_F5A_ROOT_INSTALLED=FALSE")
        print("R117_F5A_VM_STARTS=0")
        print("R117_F5A_TRAFFIC=0")
        print("R117_F5A_P8=NO-GO")
        return 0

    except (
        Stop, OSError, ValueError, KeyError, TypeError,
        zipfile.BadZipFile, subprocess.TimeoutExpired
    ) as error:
        print(
            "R117_F5A_STOP=" + type(error).__name__ +
            ":" + str(error)[:160]
        )
        print("R117_F5A_P8=NO-GO")
        return 23

if __name__ == "__main__":
    raise SystemExit(main())
