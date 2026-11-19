#!/usr/bin/env python3
"""R108: execute 54 offline MODEL state transitions from verified R107 receipts.

No SSH/FTP/SMB commands, no host or guest actions, no actual A3/A8 transitions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "src"), str(REPO / "scripts")]

from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r101_ssh_authority as r101
from ardrec.coordination import r108_offline_state_execution as engine
import ardrec_p14_r107_a1_a10_offline as r107_cli

ROOT = Path("/home/cicada/ardrec-lab/r108-offline-model-transitions-v1")
MANIFEST_SCHEMA = "ardrec-r108-private-state-model-replay-v1"
FILES = frozenset({"model.json", "manifest.json"})


def _doc(root: Path, name: str) -> dict:
    return r101.parse_private(a5._read_private(root / name, a5.MAX_SUPPORT))


def source_trace(r104_session: Path, r106_session: Path,
                 r107_session: Path, f11_file: Path) -> dict:
    report, m104, link, m106 = r107_cli.source_documents(
        r104_session, r106_session, f11_file)
    engine.need(r107_session.is_absolute() and r107_session.parent == r107_cli.ROOT
                and r107_session.name.startswith("run-")
                and not r107_session.is_symlink(), "R107_SESSION_PATH_INVALID")
    trace, _ = r107_cli.verify(r107_session, report, m104, link, m106)
    return trace


def manifest_for(model_report: dict) -> dict:
    engine.need(model_report.get("schema") == engine.SCHEMA
                and model_report.get("model_event_count") == 72
                and model_report.get("counterfactual_transitions_executed") == 72
                and model_report.get("a5_operational_starts") == 0
                and model_report.get("a6_classification") == "ND"
                and model_report.get("a9_published_generations") == 0
                and model_report.get("p8_operational") == "NO-GO",
                "MODEL_AUTHORITY_DRIFT")
    result = {
        "schema": MANIFEST_SCHEMA,
        "mode": engine.MODE,
        "model_sha256": model_report["sha256"],
        "model_file_sha256": a5.sha(a5.canonical(model_report) + b"\n"),
        "r107_trace_sha256": model_report["r107_trace_sha256"],
        "case_window_count": 54,
        "model_event_count": 72,
        "model_event_head_sha256": model_report["model_event_head_sha256"],
        "operational_transitions_applied": 0,
        "a5_operational_starts": 0,
        "a6_classification": "ND",
        "a7_confirmed_rf": None,
        "a9_published_generations": 0,
        "dispatch_allowed": False,
        "vm_starts": 0,
        "p8_operational": "NO-GO",
    }
    result["sha256"] = a5.digest(result)
    return result


def verify(root: Path, trace: dict) -> tuple[dict, dict]:
    a5._private_root(root)
    engine.need({p.name for p in root.iterdir()} == FILES,
                "MODEL_SESSION_INVENTORY")
    model_report = _doc(root, "model.json")
    manifest = _doc(root, "manifest.json")
    engine.verify(model_report, trace)
    engine.need(manifest == manifest_for(model_report),
                "MODEL_MANIFEST_REPLAY_INVALID")
    return model_report, manifest


def persist(trace: dict, base: Path) -> tuple[Path, dict, dict]:
    engine.need(isinstance(base, Path) and base.is_absolute(),
                "MODEL_PRIVATE_ROOT_INVALID")
    base.mkdir(parents=True, mode=0o700, exist_ok=True)
    a5._private_root(base)
    model_report = engine.build(trace)
    manifest = manifest_for(model_report)
    session = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    a5._private_root(session)
    for name, value in (("model.json", model_report), ("manifest.json", manifest)):
        a5._store_once(session / name, a5.canonical(value) + b"\n", a5.MAX_SUPPORT)
    descriptor = os.open(session, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    engine.need(verify(session, trace) == (model_report, manifest),
                "MODEL_PERSISTENCE_REPLAY_FAILED")
    return session, model_report, manifest


def show(session: Path, result: dict, manifest: dict, *, table: bool = False) -> None:
    print("R108_CASES=" + str(result["case_window_count"]))
    print("R108_MODEL_TRANSITIONS=" + str(result["model_event_count"]))
    print("R108_FINAL_MODEL_PHASES=" + json.dumps(result["model_phase_counts"], sort_keys=True))
    print("R108_SOURCE_R107_SHA256=" + result["r107_trace_sha256"])
    print("R108_EVENT_CHAIN_SHA256=" + result["model_event_head_sha256"])
    print("R108_REPORT_SHA256=" + result["sha256"])
    print("R108_MANIFEST_SHA256=" + manifest["sha256"])
    print("R108_SESSION=" + str(session))
    print("R108_OPERATIONAL_TRANSITIONS=0")
    print("R108_A5=NO_OPERATIONAL_START")
    print("R108_A6=ND")
    print("R108_A7_RF=NOT_CONFIRMED")
    print("R108_A9=PUBLISHED_0")
    print("R108_VM_STARTS=0")
    print("R108_P8=NO-GO")
    if table:
        print("R108_TABLE_HEADER=CASE|SERVICE|FAMILY|MODEL_BRANCH|MODEL_FINAL_PHASE|REVISION")
        for case in result["cases"]:
            print("R108_TABLE_ROW=" + "|".join((
                case["case_id_a7"], case["service_id"], case["family_id"],
                case["model_branch"], case["final_model_phase"],
                str(case["model_revision"]))))
    print("R108_RESULT=DURABLE_COUNTERFACTUAL_STATE_REPLAY_VERIFIED")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline-model", action="store_true")
    parser.add_argument("--r104-session", type=Path, required=True)
    parser.add_argument("--r106-session", type=Path, required=True)
    parser.add_argument("--r107-session", type=Path, required=True)
    parser.add_argument("--f11-review", type=Path, required=True)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--table", action="store_true")
    args = parser.parse_args()
    if Path.cwd().resolve() != REPO or (args.verify is None) != args.offline_model:
        print("R108_STOP=REPOSITORY_OR_EXPLICIT_OFFLINE_MODEL_REQUIRED")
        return 23
    try:
        trace = source_trace(args.r104_session, args.r106_session,
                             args.r107_session, args.f11_review)
        if args.verify is None:
            session, result, manifest = persist(trace, ROOT)
        else:
            engine.need(args.verify.is_absolute() and args.verify.parent == ROOT
                        and args.verify.name.startswith("run-")
                        and not args.verify.is_symlink(), "MODEL_VERIFY_PATH_INVALID")
            session = args.verify
            result, manifest = verify(session, trace)
        show(session, result, manifest, table=args.table)
        return 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print("R108_STOP=" + type(exc).__name__ + ":" + str(exc)[:180])
        print("R108_P8=NO-GO")
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
