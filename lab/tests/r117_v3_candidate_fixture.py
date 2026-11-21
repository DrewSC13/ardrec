"""Reproduce the pinned R117 F5B V3 candidate from repository sources."""

from pathlib import Path
import hashlib
import importlib.util

HEAD = "197785a38bf166ec0b4c8d3ae17346d1fa217265"
SHA = "5ef729690589497c787f34e99dba8fefea798459fc6c10a2d144a64a71cb2bf7"

ROOT = Path(__file__).resolve().parents[2]


def candidate_bytes():
    path = ROOT / "scripts/ardrec_p14_r117_f5_root_candidate.py"

    spec = importlib.util.spec_from_file_location(
        "ardrec_r117_f5a_reproducible_builder",
        path,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("CANDIDATE_BUILDER_NOT_FOUND")

    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)

    raw = builder.candidate(HEAD, repo=ROOT)

    if hashlib.sha256(raw).hexdigest() != SHA:
        raise RuntimeError("CANDIDATE_REBUILD_SHA_CHANGED")

    return raw
