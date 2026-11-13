#!/usr/bin/env python3
"""R13: ensayo activo acotado con systemd real y caída del coordinador."""
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
from ardrec.benign_r12_handoff import DurableR12Handoff


def _summary(bridge: DurableR12Handoff, rid: str) -> dict:
    state = bridge.pipe.read(rid)
    proof = bridge.verify(rid)
    return {
        "id": rid,
        "state": state["state"],
        "start_count": state["start_count"],
        "outcome": state.get("result", {}).get("outcome"),
        "report_sha256": state.get("result", {}).get("r12_report_sha256"),
        "event_head_sha256": proof["event_head_sha256"],
        "global_tree_cleanup_proven": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    root = args.state_dir
    if root.exists() and any(root.iterdir()):
        parser.error("state directory must be new and empty")
    bridge = DurableR12Handoff(root)
    out: dict = {
        "schema": "ardrec-p9-r13-active-demo-v1",
        "p8_operational": "NO-GO",
        "general_cleanup_certified": False,
        "scenarios": [],
    }

    # Escenario A: resultado directo, recibo R12 persistido.
    direct = bridge.start("r13-direct", wait=True)
    out["scenarios"].append(_summary(bridge, "r13-direct"))
    if direct["state"] != "RECORDED_LIMITED" or direct["result"]["outcome"] != "R12_OBSERVATION_REPORTED_PASS":
        out["verdict"] = "INCONCLUSIVE_DIRECT_R12"
        print(json.dumps(out, sort_keys=True, ensure_ascii=False))
        return 2

    # Escenario B: el coordinador MUERE justo después de lanzar el observador.
    # El proceso del servicio pertenece a systemd, no al padre ya desaparecido.
    child_code = (
        "import os,sys;sys.path.insert(0," + repr(str(REPO / "src")) + ");"
        "from ardrec.benign_r12_handoff import DurableR12Handoff;"
        "b=DurableR12Handoff(" + repr(str(root)) + ");"
        "r=b.start('r13-crash',wait=False);"
        "assert r['state']=='START_INTENT' and r['start_count']==1;"
        "os._exit(77)"
    )
    child = subprocess.run([sys.executable, "-c", child_code], capture_output=True,
                           timeout=8, check=False)
    out["coordinator_crash_returncode"] = child.returncode
    if child.returncode != 77:
        out["verdict"] = "INCONCLUSIVE_CRASH_NOT_REPRODUCED"
        print(json.dumps(out, sort_keys=True, ensure_ascii=False))
        return 2

    # Reconciliar el recibo SIN llamar a start ni al R12 probe de nuevo.
    deadline = time.monotonic() + 28
    status = "START_INTENT"
    while time.monotonic() < deadline:
        states = bridge.recover()
        status = states.get("r13-crash") or bridge.pipe.read("r13-crash")["state"]
        if status != "START_INTENT":
            break
        time.sleep(0.15)
    out["scenarios"].append(_summary(bridge, "r13-crash"))
    if status != "RECORDED_LIMITED" or bridge.pipe.read("r13-crash")["result"]["outcome"] != "R12_OBSERVATION_REPORTED_PASS":
        out["verdict"] = "INCONCLUSIVE_OR_UNCERTAIN_AFTER_CRASH"
        print(json.dumps(out, sort_keys=True, ensure_ascii=False))
        return 2
    out["verdict"] = "PASS_TWO_BENIGN_SCENARIOS_WITH_DURABLE_RECOVERY"
    print(json.dumps(out, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
