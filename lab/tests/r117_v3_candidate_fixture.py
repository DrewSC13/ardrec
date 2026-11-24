"""Historical R117-F5B V3 candidate, rebuilt from signed Git history.

The archived source-only candidate is immutable. It is NOT a current
root installation, boot permit, network authorization or physical replay.
"""
from pathlib import Path
import hashlib

import ardrec_r117_release_core_v1 as core

HEAD = "197785a38bf166ec0b4c8d3ae17346d1fa217265"
SHA = "5ef729690589497c787f34e99dba8fefea798459fc6c10a2d144a64a71cb2bf7"

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "lab/fixtures/r117/f5b-v3-candidate-197785a38bf1.zip"

def candidate_bytes():
    if not ARCHIVE.is_file() or ARCHIVE.is_symlink():
        raise RuntimeError("HISTORICAL_CANDIDATE_ARCHIVE_MISSING")

    raw = ARCHIVE.read_bytes()

    if hashlib.sha256(raw).hexdigest() != SHA:
        raise RuntimeError("HISTORICAL_CANDIDATE_SHA_CHANGED")

    report = core.verify_candidate(
        raw, head=HEAD, expected_sha=SHA
    )

    if report["file_count"] != 39 or report["p8"] != "NO-GO":
        raise RuntimeError("HISTORICAL_CANDIDATE_SCOPE_CHANGED")

    return raw
