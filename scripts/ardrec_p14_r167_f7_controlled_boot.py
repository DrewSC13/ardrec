#!/usr/bin/env python3
"""R167-F7: versioned, source-only DENY controller."""
from pathlib import Path
import hashlib
import json
import sys

REPO = Path("/home/cicada/Development/GitHub/ardrec")
ROOT = REPO / "lab/operational-controller/r167-f7-source-v1.json"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def admission():
    if not ROOT.is_file() or ROOT.is_symlink():
        raise RuntimeError("R167_ADMISSION_MANIFEST_UNSAFE")

    doc = json.loads(ROOT.read_bytes())

    required = {
        "schema", "historical_f7_sha256", "files_sha256",
        "boot_release", "root_install", "network_traffic",
        "vm_starts", "p8",
    }

    if type(doc) is not dict or set(doc) != required:
        raise RuntimeError("R167_ADMISSION_FIELDS_INVALID")

    if not (
        doc["schema"] == "ARDREC-R167-F7-SOURCE-ONLY-v1"
        and doc["p8"] == "NO-GO"
        and doc["boot_release"] == "NOT_ATTESTED"
        and doc["root_install"] is False
        and doc["network_traffic"] is False
        and type(doc["vm_starts"]) is int
        and doc["vm_starts"] == 0
        and doc["historical_f7_sha256"] ==
        "361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af"
    ):
        raise RuntimeError("R167_ADMISSION_SOURCE_ONLY_INVALID")

    required_files = {
        "src/ardrec/coordination/r167_f7_controlled_boot.py",
        "scripts/ardrec_p14_r167_f7_controlled_boot.py",
        "lab/tests/test_p14_r167_f7_versioned.py",
    }

    pinned = doc["files_sha256"]

    if type(pinned) is not dict or set(pinned) != required_files:
        raise RuntimeError("R167_ADMISSION_FILE_SET_INVALID")

    for name, expected in sorted(pinned.items()):
        source = REPO / name

        if not (
            type(expected) is str
            and len(expected) == 64
            and all(ch in "0123456789abcdef" for ch in expected)
            and source.is_file()
            and not source.is_symlink()
            and source.resolve().is_relative_to(REPO.resolve())
            and sha(source.read_bytes()) == expected
        ):
            raise RuntimeError("R167_ADMISSION_SOURCE_DRIFT:" + name)

if __name__ == "__main__":
    admission()
    sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]
    from ardrec.coordination.r167_f7_controlled_boot import main
    raise SystemExit(main())
