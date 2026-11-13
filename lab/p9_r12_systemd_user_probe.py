#!/usr/bin/env python3
"""P9-R12: evidencia acotada de servicio systemd --user (solo procesos propios).

NO es una API de despacho. No reutiliza ni modifica el cgroup de la terminal.
No usa sudo, mata PID externos, ni autoriza P8 operacional.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

SCHEMA = "ardrec-p9-r12-user-transient-unit-probe-v1"
BASE = "1c6ea04489a685cbd9b12c9e6e0bd956839cefe9"
CGROOT = Path("/sys/fs/cgroup")
PIDS_MAX = "16"
MEMORY_MAX = str(128 * 1024 * 1024)
CPU_QUOTA = "100%"
RUN_TIMEOUT_S = 17
UNIT_RUNTIME_MAX_S = 11
TIMEOUT_STOP_S = 2
WORKER_HOLD_S = 2.4
WITNESS_HOLD_S = 20


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_json(path: Path, obj: dict) -> None:
    payload = (json.dumps(obj, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _proc_identity(pid: int) -> dict | None:
    """PID+start_ticks+UID real, estado y PGID. Sin enviar señales."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
        uid_line = next(x for x in status.splitlines() if x.startswith("Uid:"))
        real_uid = int(uid_line.split()[1])
        fields = raw.rsplit(") ", 1)[1].split()
        return {"pid": pid, "ppid": int(fields[1]), "pgid": int(fields[2]),
                "start_ticks": int(fields[19]), "state": fields[0], "uid": real_uid}
    except (OSError, IndexError, ValueError):
        return None


def _cgroup_relative(pid: int) -> str | None:
    try:
        for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8").splitlines():
            if line.startswith("0::"):
                value = line[3:]
                return value if value.startswith("/") and "\x00" not in value else None
    except OSError:
        pass
    return None


def _cgpath(relative: str) -> Path | None:
    if not relative or not relative.startswith("/") or ".." in Path(relative).parts:
        return None
    try:
        root = CGROOT.resolve(strict=True)
        target = (root / relative.lstrip("/")).resolve(strict=True)
    except OSError:
        return None
    return target if target != root and target.is_relative_to(root) else None


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="ascii").strip()
    except OSError:
        return None


def _read_live_group(cg: Path) -> dict:
    names = ("pids.max", "memory.max", "cpu.max", "cgroup.procs",
             "cgroup.events", "cgroup.controllers", "cgroup.kill")
    values = {name: _read(cg / name) for name in names}
    # El control cgroup.kill es solo indicador de presencia: no escribirlo.
    values["cgroup.kill_present"] = (cg / "cgroup.kill").exists()
    values.pop("cgroup.kill")
    return values


def _valid_limits(values: dict) -> bool:
    cpu = values.get("cpu.max")
    if not isinstance(cpu, str) or len(cpu.split()) != 2:
        return False
    try:
        quota, period = map(int, cpu.split())
        effective = quota == period and quota > 0
    except ValueError:
        return False
    return (values.get("pids.max") == PIDS_MAX
            and values.get("memory.max") == MEMORY_MAX and effective)


def _worker(outdir: Path, unit: str) -> int:
    """Proceso fijo ejecutado SOLO por systemd en su propia unidad transitoria."""
    if re.fullmatch(r"ardrec-p9r12-[0-9a-f]{12}\.service", unit) is None:
        return 21
    location = _cgroup_relative(os.getpid())
    if not location or not location.endswith("/" + unit) or _cgpath(location) is None:
        return 26
    if not outdir.is_dir() or outdir.is_symlink() or outdir.stat().st_uid != os.getuid():
        return 22
    if outdir.stat().st_mode & 0o077:
        return 23
    python = sys.executable
    child = subprocess.Popen(
        [python, "-I", "-c", "import time; time.sleep(20)"],
        start_new_session=True, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    try:
        mine = _proc_identity(os.getpid())
        witness = _proc_identity(child.pid)
        relative = _cgroup_relative(os.getpid())
        witness_relative = _cgroup_relative(child.pid)
        if mine is None or witness is None or relative is None:
            return 24
        _atomic_json(outdir / "ready.json", {
            "schema": SCHEMA,
            "unit": unit,
            "worker": mine,
            "witness": witness,
            "worker_cgroup": relative,
            "witness_cgroup": witness_relative,
            "worker_uid": os.getuid(),
            "witness_escaped_pgid": mine["pgid"] != witness["pgid"],
            "p8_operational": "NO-GO",
        })
        # El hijo deliberadamente sobrevive al líder; KillMode=control-group
        # debe terminarlo, no el shell ni un kill(PID) desde el observador.
        time.sleep(WORKER_HOLD_S)
        return 0
    except (OSError, ValueError):
        return 25
    # No matar el hijo aquí: la propiedad que se comprueba es la limpieza
    # del cgroup por el gestor al terminar el proceso líder de la unidad.


def _outdir_check(outdir: Path) -> None:
    if not outdir.exists() or not outdir.is_dir() or outdir.is_symlink():
        raise ValueError("evidence_directory_missing_or_symlink")
    s = outdir.stat()
    if s.st_uid != os.getuid() or s.st_mode & 0o077:
        raise ValueError("evidence_directory_not_private")
    if any(outdir.iterdir()):
        raise ValueError("evidence_directory_must_be_empty")


def _command(unit: str, outdir: Path) -> list[str]:
    exe = shutil.which("systemd-run") or "/usr/bin/systemd-run"
    return [exe, "--user", "--wait", "--collect", "--quiet", "--no-ask-password",
            "--service-type=exec", "--unit=" + unit,
            "--property=TasksMax=" + PIDS_MAX,
            "--property=MemoryMax=" + MEMORY_MAX,
            "--property=CPUQuota=" + CPU_QUOTA,
            "--property=KillMode=control-group",
            "--property=RuntimeMaxSec=" + str(UNIT_RUNTIME_MAX_S),
            "--property=TimeoutStopSec=" + str(TIMEOUT_STOP_S),
            "--property=NoNewPrivileges=yes",
            sys.executable, "-I", str(Path(__file__).resolve()),
            "--worker", str(outdir), "--unit", unit]


def _observation_pass(ready: dict, unit: str, live: dict) -> bool:
    w, c = ready["worker"], ready["witness"]
    procs = set((live.get("cgroup.procs") or "").split())
    return (ready["unit"] == unit
            and ready["p8_operational"] == "NO-GO"
            and ready["witness_escaped_pgid"] is True
            and ready["worker_uid"] == os.getuid()
            and w["pid"] != c["pid"] and c["ppid"] == w["pid"]
            and w["uid"] == os.getuid() and c["uid"] == os.getuid()
            and ready["worker_cgroup"] == ready["witness_cgroup"]
            and ready["worker_cgroup"].endswith("/" + unit)
            and str(w["pid"]) in procs and str(c["pid"]) in procs
            and w["pgid"] != c["pgid"]
            and _valid_limits(live)
            and bool(w["start_ticks"]) and bool(c["start_ticks"]))



def _independent_live_identity(ready: dict) -> bool:
    """Validación por el OBSERVADOR; no confiar solamente en ready.json."""
    try:
        for role in ("worker", "witness"):
            declared = ready[role]
            actual = _proc_identity(declared["pid"])
            if (actual is None or actual["start_ticks"] != declared["start_ticks"]
                    or actual["pgid"] != declared["pgid"]
                    or actual["uid"] != os.getuid()
                    or actual["state"] in ("Z", "X")
                    or _cgroup_relative(declared["pid"]) != ready["worker_cgroup"]):
                return False
        return True
    except (TypeError, KeyError, ValueError):
        return False

def _identity_absent(original: dict) -> bool:
    now = _proc_identity(int(original["pid"]))
    return now is None or now["start_ticks"] != original["start_ticks"]


def _probe(outdir: Path) -> tuple[dict, int]:
    _outdir_check(outdir)
    unit = "ardrec-p9r12-" + secrets.token_hex(6) + ".service"
    result = {"schema": SCHEMA, "main_sha": BASE,
              "unit": unit, "scope": "owned_benign_transient_user_service_only",
              "p8_operational": "NO-GO", "general_cleanup_certified": False,
              "result": "INCONCLUSIVE", "live_group_proven": False,
              "poststop_absence_proven": False}
    if sys.platform != "linux" or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
        result.update(result="UNSUPPORTED", reason="cgroup2_unavailable")
        return result, 3
    if not shutil.which("systemd-run") or not shutil.which("systemctl"):
        result.update(result="UNSUPPORTED", reason="systemd_user_commands_unavailable")
        return result, 3
    command = _command(unit, outdir)
    result["requested_controls"] = {"pids.max": PIDS_MAX, "memory.max": MEMORY_MAX,
                                     "CPUQuota": CPU_QUOTA, "KillMode": "control-group",
                                     "RuntimeMaxSec": UNIT_RUNTIME_MAX_S}
    run = None
    ready = None
    live = None
    proc_rc = None
    try:
        run = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               close_fds=True)
        end = time.monotonic() + 6.0
        while time.monotonic() < end:
            path = outdir / "ready.json"
            if path.is_file():
                try:
                    ready = json.loads(path.read_text(encoding="utf-8"))
                    cg = _cgpath(ready["worker_cgroup"])
                    if cg is not None:
                        live = _read_live_group(cg)
                        result["live_identity_confirmed"] = _independent_live_identity(ready)
                        result["live_group_proven"] = (
                            _observation_pass(ready, unit, live)
                            and result["live_identity_confirmed"]
                        )
                        result["cgroup_relative"] = ready["worker_cgroup"]
                        result["observed_limits"] = live
                except (ValueError, KeyError, TypeError, OSError):
                    result["reason"] = "witness_data_invalid"
                break
            if run.poll() is not None:
                break
            time.sleep(0.02)
        try:
            stdout, stderr = run.communicate(timeout=RUN_TIMEOUT_S)
            proc_rc = run.returncode
            result["systemd_run_rc"] = proc_rc
            result["systemd_run_stdout_sha256"] = _sha(stdout)
            result["systemd_run_stderr_sha256"] = _sha(stderr)
            result["systemd_run_stderr_preview"] = stderr.decode("utf-8", "replace")[:400]
        except subprocess.TimeoutExpired:
            result["reason"] = "systemd_run_wrapper_timeout"
            run.terminate()
            try:
                run.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                run.kill()
                run.communicate()
        if ready is not None:
            result["worker"] = ready.get("worker")
            result["witness"] = ready.get("witness")
            cleanup_deadline = time.monotonic() + 1.8
            while True:
                result["poststop_absence_proven"] = (
                    _identity_absent(ready["worker"])
                    and _identity_absent(ready["witness"])
                )
                if result["poststop_absence_proven"] or time.monotonic() > cleanup_deadline:
                    break
                time.sleep(0.04)
        if (proc_rc == 0 and result["live_group_proven"]
                and result["poststop_absence_proven"]):
            result["result"] = "PASS_BENIGN_TRANSIENT_UNIT"
            return result, 0
        result.setdefault("reason", "missing_required_ownership_limit_or_cleanup_proof")
        return result, 2
    except (OSError, ValueError, TypeError, KeyError) as error:
        result["reason"] = type(error).__name__
        return result, 2
    finally:
        # Se pide parada SOLO de la unidad aleatoria generada por este ensayo.
        # Si ya fue recolectada, systemctl devuelve error y no hay cambio.
        # Nunca se toca el scope Konsole ni un cgroup por ruta externa.
        try:
            stop = subprocess.run([shutil.which("systemctl") or "/usr/bin/systemctl",
                                   "--user", "--no-ask-password", "stop", unit],
                                  capture_output=True, timeout=5, check=False)
            result["targeted_stop_rc"] = stop.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["targeted_stop_error"] = type(exc).__name__


def main() -> int:
    parser = argparse.ArgumentParser(description="ARDREC R12 - prueba benigna de control efectivo")
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--unit", type=str, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker is not None:
        if args.evidence_dir is not None or args.unit is None:
            return 20
        return _worker(args.worker, args.unit)
    if args.unit is not None or args.evidence_dir is None:
        parser.error("required: --evidence-dir")
    try:
        report, rc = _probe(args.evidence_dir)
    except (OSError, ValueError) as exc:
        report, rc = {"schema": SCHEMA, "result": "INCONCLUSIVE",
                      "reason": type(exc).__name__, "p8_operational": "NO-GO"}, 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    if args.evidence_dir.is_dir() and not args.evidence_dir.is_symlink():
        st = args.evidence_dir.stat()
        if (st.st_uid == os.getuid() and not (st.st_mode & 0o077)
                and not (args.evidence_dir / "report.json").exists()):
            _atomic_json(args.evidence_dir / "report.json", report)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
