#!/usr/bin/env python3
"""P9-R10: ensayo benigno autocontenido, no despachador operacional.

El proceso supervisor adopta un testigo de doble-fork que abandona el PGID.
Nunca admite comandos arbitrarios ni argumentaciones externas como ejecutables.
No se usa para acreditar la limpieza de un arbol general ni recuperacion post-SIGKILL.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37
MAX_SECONDS = 3.0
BENIGN_LIFETIME_SECONDS = 8.0


def _subreaper_enable() -> tuple[bool, str]:
    if sys.platform != "linux":
        return False, "not_linux"
    if os.environ.get("ARDREC_R10_FORCE_UNSUPPORTED") == "1":
        return False, "forced_unsupported_for_negative_test"
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False, "pidfd_not_supported"
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        before = ctypes.c_int(-1)
        if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.addressof(before), 0, 0, 0) != 0:
            return False, f"prctl_get_errno_{ctypes.get_errno()}"
        if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
            return False, f"prctl_set_errno_{ctypes.get_errno()}"
        after = ctypes.c_int(-1)
        if libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.addressof(after), 0, 0, 0) != 0:
            return False, f"prctl_verify_errno_{ctypes.get_errno()}"
        if after.value != 1:
            return False, "subreaper_not_confirmed"
        return True, "subreaper_confirmed"
    except (OSError, AttributeError) as exc:
        return False, type(exc).__name__


def _stat_identity(pid: int) -> tuple[int, int, int]:
    """(ppid, pgid, start_ticks): primero el ultimo ')' para nombres con espacios."""
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    split = text.rfind(") ")
    if split < 0:
        raise ValueError("bad_proc_stat")
    fields = text[split + 2:].split()
    return int(fields[1]), int(fields[2]), int(fields[19])


def _fixture(witness_file: Path) -> int:
    """Solo ejecuta dobles forks y espera; nunca efectua red ni muta servicios."""
    child = os.fork()
    if child > 0:
        os._exit(0)
    os.setsid()                 # Sale del PGID que lideraba el primer proceso.
    grandchild = os.fork()
    if grandchild > 0:
        os._exit(0)
    # Solo el nieto llega aqui. Archivo exclusivo para que el supervisor lo reconozca.
    witness = {"pid": os.getpid(), "pgid": os.getpgrp(), "uid": os.getuid()}
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(witness_file, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(witness, out, sort_keys=True)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    time.sleep(BENIGN_LIFETIME_SECONDS)
    return 0


def _report(outcome: str, **fields: object) -> dict[str, object]:
    return {"schema": "ardrec-p9-r10-benign-demo-v1", "outcome": outcome,
            "scope": "local_benign_fixture_only", "p8_operational": "NO-GO", **fields}


def _live_identity(pid: int, start_ticks: int) -> bool:
    try:
        return _stat_identity(pid)[2] == start_ticks
    except (FileNotFoundError, ProcessLookupError):
        return False


def _demo() -> tuple[dict[str, object], int]:
    supported, reason = _subreaper_enable()
    if not supported:
        return _report("UNSUPPORTED", reason=reason, cleanup_verified=False), 3
    source_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="ardrec-p9r10-") as temp:
        witness_file = Path(temp) / "witness.json"
        leader = subprocess.Popen([sys.executable, os.path.abspath(__file__),
                                   "--fixture", str(witness_file)],
                                  start_new_session=True,
                                  stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL,
                                  close_fds=True)
        witness_pid = None
        witness_ticks = None
        pidfd = None
        terminated = False
        adopted = False
        escaped_pgid = False
        leader_rc = None
        try:
            leader_rc = leader.wait(timeout=MAX_SECONDS)
            cutoff = time.monotonic() + MAX_SECONDS
            while time.monotonic() < cutoff and not witness_file.is_file():
                time.sleep(0.01)
            if not witness_file.is_file():
                return _report("INCONCLUSIVE", reason="witness_not_reported",
                               leader_returncode=leader_rc, cleanup_verified=False), 2
            raw = json.loads(witness_file.read_text(encoding="utf-8"))
            witness_pid = raw["pid"]
            if type(witness_pid) is not int or witness_pid <= 1:
                return _report("INCONCLUSIVE", reason="bad_witness_pid", cleanup_verified=False), 2
            # Pidfd estabiliza la identidad antes de emitir una senal.
            pidfd = os.pidfd_open(witness_pid, 0)
            ppid, pgid, witness_ticks = _stat_identity(witness_pid)
            adopted = ppid == os.getpid()
            escaped_pgid = pgid != leader.pid and pgid == raw["pgid"]
            if not (adopted and escaped_pgid and raw["uid"] == os.getuid() and leader_rc == 0):
                return _report("INCONCLUSIVE", reason="attribution_not_proven",
                               leader_returncode=leader_rc, witness_pid=witness_pid,
                               adopted=adopted, escaped_original_pgid=escaped_pgid,
                               cleanup_verified=False), 2
            # Comprobar adopcion otra vez inmediatamente antes de la senal.
            if _stat_identity(witness_pid) != (os.getpid(), pgid, witness_ticks):
                return _report("INCONCLUSIVE", reason="identity_changed",
                               cleanup_verified=False), 2
            signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
            # Solo puede hacer waitpid sobre un descendiente propio ya adoptado.
            waited, waitstatus = os.waitpid(witness_pid, 0)
            terminated = (waited == witness_pid and os.WIFSIGNALED(waitstatus)
                          and os.WTERMSIG(waitstatus) == signal.SIGTERM)
            absent = not _live_identity(witness_pid, witness_ticks)
            cleaned = bool(terminated and absent)
            return _report("PASS_BENIGN_WITNESS" if cleaned else "INCONCLUSIVE",
                           leader_returncode=leader_rc,
                           witness_pid=witness_pid, witness_start_ticks=witness_ticks,
                           witness_pgid=pgid, leader_pgid=leader.pid,
                           adopted=adopted, escaped_original_pgid=escaped_pgid,
                           termination_reaped=terminated, cleanup_verified=cleaned,
                           source_sha256=source_hash), 0 if cleaned else 2
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            return _report("INCONCLUSIVE", reason=type(exc).__name__,
                           leader_returncode=leader_rc,
                           cleanup_verified=False), 2
        finally:
            # Limpieza del lider que creamos nosotros; nunca senalizar un PGID reciclable.
            if leader.poll() is None:
                leader.terminate()
                try:
                    leader.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    leader.kill()
                    leader.wait()
            # Si ocurre un error antes de la terminacion, solo tocar el testigo
            # si tenemos pidfd y sigue adoptado por ESTE supervisor.
            if pidfd is not None:
                if (not terminated and witness_pid is not None and witness_ticks is not None):
                    try:
                        if _stat_identity(witness_pid)[0] == os.getpid() and _live_identity(witness_pid, witness_ticks):
                            signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
                            os.waitpid(witness_pid, 0)
                    except (OSError, ChildProcessError):
                        pass
                os.close(pidfd)


def main() -> int:
    parser = argparse.ArgumentParser(description="ARDREC P9-R10: ensayo de supervisor benigno")
    parser.add_argument("--fixture", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.fixture is not None:
        return _fixture(args.fixture)
    result, rc = _demo()
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
