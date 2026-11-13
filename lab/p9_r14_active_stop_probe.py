#!/usr/bin/env python3
"""P9-R14: parada POSITIVA de una unidad systemd propia, exclusivamente benigna.

La prueba no autoriza despachos P8 ni certifica limpieza general. Su resultado
solo demuestra el stop dirigido y las identidades observadas en este ensayo.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
from typing import Any

SCHEMA = "ardrec-p9-r14-active-stop-v1"
BASE = "1a50e30a37e43bddb8897dbf0b21b79662bb5ad9"
R12_PATH = "lab/p9_r12_systemd_user_probe.py"
R12_SHA256 = "bd3d750468ffbb1934d46d39974c5a9b9bcc476b6b39021c4b5a026430542726"
SUCCESS = "PASS_OWNED_ACTIVE_STOP"


def _source(repo: Path):
    path = repo / R12_PATH
    if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != R12_SHA256:
        raise ValueError("r12_source_missing_or_unpinned")
    spec = importlib.util.spec_from_file_location("ardrec_p9_r14_pinned_r12", path)
    if spec is None or spec.loader is None:
        raise ValueError("r12_source_cannot_load")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _safe_evidence(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("unsafe_evidence_dir")
    s = path.stat()
    if s.st_uid != os.getuid() or s.st_mode & 0o077 or any(path.iterdir()):
        raise ValueError("evidence_not_private_empty_owned")


def _unit_name() -> str:
    return "ardrec-p9r12-" + secrets.token_hex(6) + ".service"


def _assess(report: dict[str, Any]) -> bool:
    """Guardas negativas; ningún único indicador constituye éxito."""
    return (
        report.get("scope") == "one_owned_benign_transient_user_service"
        and report.get("p8_operational") == "NO-GO"
        and report.get("general_tree_cleanup_proven") is False
        and report.get("live_group_verified") is True
        and report.get("prestop_is_active_rc") == 0
        and report.get("prestop_two_identities_alive") is True
        and report.get("targeted_stop_rc") == 0
        and report.get("two_identities_absent") is True
        and report.get("poststop_cgroup_absent_or_unpopulated") is True
        and report.get("systemd_run_wrapper_rc") == 0
        and report.get("effective_limits") == {
            "pids.max": "16", "memory.max": "134217728", "cpu.max": "100000 100000"
        }
    )


def _cgroup_absent_or_empty(r12: Any, relative: str) -> tuple[bool, str | None]:
    """Solo ausencia del cgroup propio o populated=0, nunca limpieza universal."""
    current = r12._cgpath(relative)
    if current is None:
        # _cgpath puede fallar también por permisos o path inválido: solo
        # FileNotFoundError directo de la ruta propia acredita su ausencia.
        if (not isinstance(relative, str) or not relative.startswith("/")
                or ".." in Path(relative).parts):
            return False, None
        root = Path("/sys/fs/cgroup")
        target = root / relative.lstrip("/")
        try:
            target.stat()
        except FileNotFoundError:
            return True, None
        except OSError:
            return False, None
        return False, None
    events = r12._read(current / "cgroup.events")
    if events is None:
        return False, None
    fields = dict(line.split(maxsplit=1) for line in events.splitlines() if len(line.split()) == 2)
    return fields.get("populated") == "0", events


def _stop_own_unit(unit: str) -> subprocess.CompletedProcess:
    """Nombre generado localmente; nunca se acepta un destino del usuario."""
    if not isinstance(unit, str) or re.fullmatch(r"ardrec-p9r12-[0-9a-f]{12}\.service", unit) is None:
        raise ValueError("unexpected_unit_name")
    return subprocess.run(
        ["systemctl", "--user", "--no-ask-password", "stop", unit],
        capture_output=True, timeout=5, check=False,
    )


def _run(outdir: Path, r12: Any) -> tuple[dict[str, Any], int]:
    unit = _unit_name()
    report: dict[str, Any] = {
        "schema": SCHEMA, "base_sha": BASE,
        "scope": "one_owned_benign_transient_user_service",
        "unit": unit, "result": "INCONCLUSIVE", "p8_operational": "NO-GO",
        "general_tree_cleanup_proven": False,
        "stop_command_success": False, "two_identities_absent": False,
        "poststop_cgroup_absent_or_unpopulated": False,
    }
    if (sys.platform != "linux" or os.geteuid() == 0 or
            not shutil.which("systemd-run") or not shutil.which("systemctl") or
            not Path("/sys/fs/cgroup/cgroup.controllers").is_file()):
        report["result"] = "UNSUPPORTED"
        report["reason"] = "unprivileged_linux_systemd_cgroup2_required"
        return report, 3

    run: subprocess.Popen | None = None
    live_receipt: dict[str, Any] | None = None
    try:
        cmd = r12._command(unit, outdir)
        # El comando proviene del archivo R12 fijado por hash, nunca de argv libre.
        if ("--user" not in cmd or "--property=KillMode=control-group" not in cmd
                or "--property=TasksMax=16" not in cmd or "--property=MemoryMax=134217728" not in cmd
                or "--property=CPUQuota=100%" not in cmd):
            raise ValueError("unsafe_r12_command")
        run = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True,
        )
        ready_path = outdir / "ready.json"
        end = time.monotonic() + 4.0
        while time.monotonic() < end:
            if ready_path.is_file() and not ready_path.is_symlink():
                st = ready_path.stat()
                if st.st_uid != os.getuid() or st.st_mode & 0o077 or st.st_size > 16_384:
                    report["reason"] = "unsafe_ready_receipt"
                    break
                live_receipt = json.loads(ready_path.read_text(encoding="utf-8"))
                break
            if run.poll() is not None:
                break
            time.sleep(0.015)

        if live_receipt is None:
            report.setdefault("reason", "no_owned_ready_receipt_before_deadline")
        else:
            rel = live_receipt.get("worker_cgroup", "")
            cg = r12._cgpath(rel)
            live = r12._read_live_group(cg) if cg is not None else {}
            verified = bool(
                cg is not None and r12._observation_pass(live_receipt, unit, live)
                and r12._independent_live_identity(live_receipt)
            )
            report["live_group_verified"] = verified
            report["worker"] = live_receipt.get("worker")
            report["witness"] = live_receipt.get("witness")
            report["cgroup_relative"] = rel
            report["effective_limits"] = {
                k: live.get(k) for k in ("pids.max", "memory.max", "cpu.max")
            }
            if not verified:
                report["reason"] = "live_ownership_or_limits_not_proven"
            else:
                active = subprocess.run(
                    ["systemctl", "--user", "--no-ask-password", "is-active", "--quiet", unit],
                    capture_output=True, timeout=3, check=False,
                )
                report["prestop_is_active_rc"] = active.returncode
                report["prestop_two_identities_alive"] = r12._independent_live_identity(live_receipt)
                if active.returncode != 0 or not report["prestop_two_identities_alive"]:
                    report["reason"] = "unit_or_identities_not_active_before_stop"
                else:
                    stop = _stop_own_unit(unit)
                    report["targeted_stop_rc"] = stop.returncode
                    report["targeted_stop_stderr_sha256"] = hashlib.sha256(stop.stderr).hexdigest()
                    report["targeted_stop_stderr_preview"] = stop.stderr.decode("utf-8", "replace")[:250]
                    report["stop_command_success"] = stop.returncode == 0
                    end = time.monotonic() + 3.0
                    while time.monotonic() < end:
                        missing = (r12._identity_absent(live_receipt["worker"])
                                   and r12._identity_absent(live_receipt["witness"]))
                        absent, events = _cgroup_absent_or_empty(r12, rel)
                        report["two_identities_absent"] = missing
                        report["poststop_cgroup_absent_or_unpopulated"] = absent
                        report["poststop_cgroup_events"] = events
                        if missing and absent:
                            break
                        time.sleep(0.04)
                    if not (report["stop_command_success"] and report["two_identities_absent"]
                            and report["poststop_cgroup_absent_or_unpopulated"]):
                        report["reason"] = "stop_or_absence_not_proven"
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        report["reason"] = type(exc).__name__
    finally:
        if run is not None:
            if not report["stop_command_success"]:
                # Exclusivamente la unidad de nombre aleatorio propia, nunca Konsole.
                try:
                    fallback = _stop_own_unit(unit)
                    report["fallback_own_unit_stop_rc"] = fallback.returncode
                except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                    report["fallback_stop_error"] = type(exc).__name__
            try:
                stdout, stderr = run.communicate(timeout=15)
                report["systemd_run_wrapper_rc"] = run.returncode
                report["systemd_run_stdout_sha256"] = hashlib.sha256(stdout).hexdigest()
                report["systemd_run_stderr_sha256"] = hashlib.sha256(stderr).hexdigest()
            except subprocess.TimeoutExpired:
                report["wrapper_timeout"] = True
                run.terminate()  # Únicamente nuestro subprocess wrapper, no un PID histórico.
                try:
                    run.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    run.kill()
                    run.communicate()
    if _assess(report):
        report["result"] = SUCCESS
        return report, 0
    report.setdefault("reason", "one_or_more_success_gates_unverified")
    return report, 2


def main() -> int:
    parser = argparse.ArgumentParser(description="ARDREC R14: ensayo benigno de parada activa")
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    _safe_evidence(args.evidence_dir)
    repo = Path(__file__).resolve().parents[1]
    r12 = _source(repo)
    report, rc = _run(args.evidence_dir, r12)
    r12._atomic_json(args.evidence_dir / "r14_report.json", report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
