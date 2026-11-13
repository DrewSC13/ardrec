#!/usr/bin/env python3
"""Reproducción acotada P9-P12; estado explícito en directorio temporal propio."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from ardrec.benign_pipeline import BenignPipeline


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, required=True)
    args = parser.parse_args()
    engine = BenignPipeline(args.state_dir)
    scenarios = [("R01", "ok", 1000, 4096),
                 ("R02", "nonzero", 1000, 4096),
                 ("R03", "noisy", 1000, 512),
                 ("R04", "slow", 100, 4096)]
    results = []
    for rid, fixture, ms, cap in scenarios:
        engine.submit(rid, fixture, deadline_ms=ms, output_cap=cap)
        outcome = engine.execute(rid)
        verification = engine.verify(rid)
        # Segundo pedido identico no produce una nueva ejecución.
        engine.submit(rid, fixture, deadline_ms=ms, output_cap=cap)
        duplicate = engine.execute(rid)
        assert outcome["start_count"] == duplicate["start_count"] == 1
        assert outcome["state"] == "RECORDED_LIMITED"
        assert verification["artifacts_verified"]
        results.append({"id": rid, "state": outcome["state"],
                        "outcome": outcome["result"]["outcome"],
                        "truncated_stdout": outcome["result"]["bounded_capture"]["stdout"]["truncated"],
                        "verification": verification})
    engine.submit("R05", "ok")
    engine.accept("R05")
    assert engine._claim_start("R05") is not None  # intención antes de spawn
    assert engine.recover() == ["R05"]
    recovered = engine.execute("R05")
    assert recovered["state"] == "RECOVERY_UNCERTAIN" and recovered["start_count"] == 1
    results.append({"id": "R05", "state": recovered["state"],
                    "verification": engine.verify("R05")})
    print(json.dumps({"demo": "P9-P12_BENIGN_ONLY", "p8_operational": "NO-GO",
                      "global_cleanup_certified": False, "results": results},
                     sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
