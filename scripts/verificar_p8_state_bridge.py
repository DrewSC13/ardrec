"""P8-R8 fail-closed source/trust audit, no laboratory or runtime operation."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = "517aa57183ca6a406c890fc92ccd00211eb79c3c"
THESIS = "6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72"
SOURCES = ["3.5.2", "3.5.3", "3.5.4", "3.7.5", "3.9.2"]
ANCHORS = {
    "src/ardrec/state.py": "012f74cefa551a130dfdf1106cb578230253c705",
    "src/ardrec/p8_diagnostic.py": "dddc217dd2a1a565e1c9216893a57748afc30862",
    "tests/fixtures/p8-diagnostic-v1.json": "e6c2217d72db121d4636f2f6af45a439a08c9617",
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def read(root: Path, name: str):
    path = root
    for segment in name.split("/"):
        need(segment not in ("", ".", ".."), "unsafe path")
        path = path / segment
        need(not path.is_symlink(), "symlink forbidden")
    need(path.is_file(), "missing: " + name)
    return path.read_bytes()


def blob(payload: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()


def verify(root: Path = ROOT):
    for path, expected in ANCHORS.items():
        need(blob(read(root, path)) == expected, "upstream anchor changed: " + path)
    contract = json.loads(read(root, "lab/p8-state-bridge-v1/contract.json"))
    trace = json.loads(read(root, "docs/traceability/p8-state-bridge-r8.json"))
    need(contract["base_commit"] == trace["base_commit"] == BASE, "base mismatch")
    need(contract["thesis_sha256"] == THESIS, "thesis provenance mismatch")
    need(contract["sources"] == trace["source_sections"] == SOURCES, "source drift")
    need(contract["upstream_state_git_blob"] == ANCHORS["src/ardrec/state.py"], "state drift")
    need(contract["upstream_p8_diagnostic_git_blob"] == ANCHORS["src/ardrec/p8_diagnostic.py"], "P8 drift")
    need(contract["upstream_p8_fixture_git_blob"] == ANCHORS["tests/fixtures/p8-diagnostic-v1.json"], "corpus drift")
    need(contract["state_phases"] == 8 and contract["transition_variants"] == 11, "state matrix drift")
    need(contract["shared_p8_vectors"] == 106 and contract["profile_slots"] == 29, "P8 coverage drift")
    need(contract["status"] == "PURE_SYNTHETIC_STRUCTURAL_REVIEW_DENY_ALL" and
         trace["status"] == "SOURCE_ONLY_UNMERGED", "false integration")
    need(contract["real_cases"] == trace["real_cases"] == 0 and
         contract["physical_laboratory"] == trace["physical_laboratory"] == "NOT_TOUCHED",
         "real environment promoted")
    for key in ("operational_authorization", "dispatch_allowed", "transition_applied",
                "publication_allowed", "provenance_verified", "authoritative_guard_evaluation"):
        need(contract[key] is False, "false authority claim: " + key)
    for key in ("operational_authorization", "dispatch_allowed", "system_acceptance",
                "state_transition_applied", "publication_allowed", "experimental_validation"):
        need(trace[key] is False, "false trace acceptance: " + key)
    need(contract["system_functional_acceptance"] == "PENDING" and
         contract["algorithm_implementation"] == "NOT_STARTED" and
         contract["experimental_validation"] == "NOT_RUN", "algorithm promoted")
    need(contract["open_findings"] == trace["open_findings"] == ["AL-06", "AL-07"], "findings erased")
    need(contract["open_development_obligations"] == trace["open_development_obligations"] == 7,
         "obligations erased")
    need(trace["historical_merged_prs"] == [36, 37, 38, 39], "past PR lineage changed")
    need(trace["implementation"] == ["src/ardrec/p8_state_bridge.py"] and
         trace["tests"] == ["tests/unit/test_p8_state_bridge.py", "scripts/verificar_p8_state_bridge.py"],
         "source inventory altered")
    # This verifier does not run code, read device files, or inspect physical artifacts.
    for name in (*trace["implementation"], *trace["tests"],
                 "docs/estado-vigente-p8-r8.md", "lab/p8-state-bridge-v1/README.md"):
        read(root, name)
    return {"status": "PASS_P8_R8_SYNTHETIC_STATE_BOUNDARY_DENY_ALL",
            "base_commit": BASE, "state_phases": 8, "transition_variants": 11,
            "p8_profiles": 29, "r7_shared_vectors": 106,
            "real_cases_authorized": 0, "dispatch_allowed": False,
            "transition_applied": False, "publication_allowed": False,
            "physical_laboratory": "NOT_TOUCHED"}


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), sort_keys=True, ensure_ascii=False))
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("ARDREC_P8_R8=FAIL_CLOSED: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
