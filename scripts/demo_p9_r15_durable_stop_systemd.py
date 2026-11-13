#!/usr/bin/env python3
"""R15: demo activa benigno con parada dirigida R14 y entrega durable R15."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from ardrec.benign_r14_stop_handoff import DurableR14StopHandoff


def summary(b: DurableR14StopHandoff, rid: str) -> dict:
    row = b.pipe.read(rid)
    proof = b.verify(rid)
    result = row.get("result") or {}
    return {
        "id": rid,
        "state": row["state"],
        "start_count": row["start_count"],
        "outcome": result.get("outcome"),
        "r14_report_sha256": result.get("r14_report_sha256"),
        "r14_ready_sha256": result.get("r14_ready_sha256"),
        "r14_targeted_stop_rc": result.get("r14_targeted_stop_rc"),
        "event_head_sha256": proof["event_head_sha256"],
        "global_tree_cleanup_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="R15: solo prueba benigna")
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.state_dir.exists() and any(args.state_dir.iterdir()):
        parser.error("state directory must be new and empty")
    bridge = DurableR14StopHandoff(args.state_dir)
    result = {"schema": "ardrec-p9-r15-durable-active-stop-demo-v1",
              "p8_operational": "NO-GO", "general_cleanup_certified": False,
              "scenarios": []}

    a = bridge.start("r15-direct", wait=True)
    result["scenarios"].append(summary(bridge,"r15-direct"))
    if a["state"] != "RECORDED_LIMITED" or a["result"]["outcome"] != "R14_ACTIVE_STOP_REPORTED_PASS":
        result["verdict"] = "INCONCLUSIVE_DIRECT"
        print(json.dumps(result, sort_keys=True))
        return 2

    child_code = (
        "import os,sys;sys.path.insert(0," + repr(str(REPO / "src")) + ");"
        "from ardrec.benign_r14_stop_handoff import DurableR14StopHandoff;"
        "b=DurableR14StopHandoff(" + repr(str(args.state_dir)) + ");"
        "r=b.start('r15-crash',wait=False);"
        "assert r['state']=='START_INTENT' and r['start_count']==1;"
        "os._exit(77)"
    )
    child = subprocess.run([sys.executable, "-c", child_code],
                           capture_output=True, timeout=8, check=False)
    result["coordinator_crash_returncode"] = child.returncode
    if child.returncode != 77:
        result["verdict"] = "INCONCLUSIVE_CRASH_NOT_OBSERVED"
        print(json.dumps(result, sort_keys=True))
        return 2

    deadline = time.monotonic() + 32
    state = "START_INTENT"
    while time.monotonic() < deadline:
        state = bridge.recover().get("r15-crash") or bridge.pipe.read("r15-crash")["state"]
        if state != "START_INTENT":
            break
        time.sleep(.15)
    result["scenarios"].append(summary(bridge,"r15-crash"))
    if state != "RECORDED_LIMITED" or bridge.pipe.read("r15-crash")["result"]["outcome"] != "R14_ACTIVE_STOP_REPORTED_PASS":
        result["verdict"] = "INCONCLUSIVE_CRASH_RECOVERY"
        print(json.dumps(result, sort_keys=True))
        return 2

    result["verdict"] = "PASS_TWO_BENIGN_DURABLE_ACTIVE_STOP_SCENARIOS"
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
