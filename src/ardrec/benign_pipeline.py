"""P9-P12: recorrido de DESARROLLO para fixtures propios, no despacho P8.

La reserva START_INTENT es durable antes de Popen. No existe reintento
tras un fallo ambiguo. Se conservan muestras acotadas de stdout/stderr;
la limpieza demostrada es exclusivamente la del lider propio.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any, Callable

ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
FIXTURES = frozenset({"ok", "nonzero", "noisy", "slow"})
# Ninguna entrada ni argv del usuario puede cambiar este codigo.
FIXTURE_SOURCE = r'''
import sys, time
mode = sys.argv[1]
if mode == 'ok':
    sys.stdout.write('ARDREC_BENIGN_OK\n')
    sys.stderr.write('ARDREC_BENIGN_TRACE\n')
elif mode == 'nonzero':
    sys.stderr.write('ARDREC_BENIGN_NONZERO\n')
    sys.exit(7)
elif mode == 'noisy':
    sys.stdout.buffer.write(b'A' * 131072)
    sys.stdout.flush()
elif mode == 'slow':
    time.sleep(2.5)
    sys.stdout.write('ARDREC_BENIGN_AFTER_DELAY\n')
else:
    sys.exit(99)
'''
SCHEMA = "ardrec-p9-p12-benign-pipeline-v1"


class GateError(ValueError):
    """Una solicitud no cumple el contrato de desarrollo."""


class VerificationError(RuntimeError):
    """Una prueba de integridad o identidad no coincide."""


def _canon(data: Any) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _safe_dir(path: Path) -> None:
    if path.is_symlink():
        raise GateError("directory_is_symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir() or path.is_symlink():
        raise GateError("invalid_directory")
    if path.stat().st_mode & 0o022:
        raise GateError("directory_writable_by_other_users")


def _start_ticks(pid: int) -> int | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        return int(raw.rsplit(") ", 1)[1].split()[19])
    except (OSError, ValueError, IndexError):
        return None


def _atomic_file(parent: Path, name: str, data: bytes) -> dict[str, Any]:
    """Escribe bytes acotados sin exponer un nombre parcial. Fsync archivo+directorio."""
    if not re.fullmatch(r"[a-f0-9]{64}\.(stdout|stderr)", name):
        raise GateError("invalid_artifact_name")
    dest = parent / name
    if dest.exists() or dest.is_symlink():
        raise VerificationError("artifact_path_already_exists")
    fd, temp_name = tempfile.mkstemp(prefix=".writing-", dir=parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, dest)
        dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        temp.unlink(missing_ok=True)
    return {"name": name, "sha256": _sha(data), "bytes": len(data)}


class BenignPipeline:
    """Un solo fixture local en desarrollo; nunca admite binarios arbitrarios."""

    def __init__(self, root: str | Path):
        self.root = Path(root).absolute()
        _safe_dir(self.root)
        self.artifacts = self.root / "artifacts"
        _safe_dir(self.artifacts)
        self.db_path = self.root / "attempts.sqlite3"
        if self.db_path.is_symlink():
            raise GateError("database_is_symlink")
        with self._managed() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS attempts (
                    id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    fixture TEXT NOT NULL,
                    deadline_ms INTEGER NOT NULL,
                    output_cap INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    start_count INTEGER NOT NULL DEFAULT 0,
                    pid INTEGER,
                    pid_start_ticks INTEGER,
                    result_json TEXT,
                    created_utc TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES attempts(id)
                );
                CREATE INDEX IF NOT EXISTS events_by_attempt
                    ON events(request_id, seq);
            """)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def _managed(self):
        db = self._connect()
        try:
            yield db
        finally:
            db.close()

    def accept(self, rid: str) -> dict[str, Any]:
        """Aceptación durable separada de la reserva y del inicio irrevocable."""
        with self._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,fingerprint FROM attempts WHERE id=?", (rid,)).fetchone()
            if row is None:
                db.execute("ROLLBACK")
                raise GateError("unknown_request")
            if row["state"] == "RESERVED":
                db.execute("UPDATE attempts SET state='ACCEPTED' WHERE id=? AND state='RESERVED'", (rid,))
                self._event(db, rid, "ACCEPTED", {"fingerprint": row["fingerprint"],
                                                  "profile": "FIXTURE_ONLY", "p8": "NO-GO"})
            db.execute("COMMIT")
        return self.read(rid)

    @staticmethod
    def _event(db: sqlite3.Connection, rid: str, action: str, payload: dict[str, Any]) -> None:
        last = db.execute("SELECT entry_sha256 FROM events WHERE request_id=? ORDER BY seq DESC LIMIT 1", (rid,)).fetchone()
        previous = last[0] if last else "0" * 64
        body = _canon({"id": rid, "action": action, "payload": payload, "previous": previous})
        digest = _sha(body)
        db.execute("INSERT INTO events(request_id,action,payload_json,previous_sha256,entry_sha256) VALUES(?,?,?,?,?)",
                   (rid, action, _canon(payload).decode(), previous, digest))

    def submit(self, rid: str, fixture: str, *, deadline_ms: int = 1000,
               output_cap: int = 4096) -> dict[str, Any]:
        if not isinstance(rid, str) or not ID_PATTERN.fullmatch(rid):
            raise GateError("invalid_request_id")
        if fixture not in FIXTURES:
            raise GateError("only_predefined_benign_fixtures")
        if type(deadline_ms) is not int or not 100 <= deadline_ms <= 3000:
            raise GateError("invalid_deadline")
        if type(output_cap) is not int or not 128 <= output_cap <= 65536:
            raise GateError("invalid_capture_cap")
        spec = {"schema": SCHEMA, "fixture": fixture, "deadline_ms": deadline_ms,
                "output_cap": output_cap, "p8_operational": "NO-GO"}
        fingerprint = _sha(_canon(spec))
        with self._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT fingerprint FROM attempts WHERE id=?", (rid,)).fetchone()
            if current:
                if current["fingerprint"] != fingerprint:
                    db.execute("ROLLBACK")
                    raise GateError("request_id_reuse_with_different_payload")
            else:
                db.execute("INSERT INTO attempts(id,fingerprint,fixture,deadline_ms,output_cap,state,created_utc) VALUES(?,?,?,?,?,?,?)",
                           (rid, fingerprint, fixture, deadline_ms, output_cap, "RESERVED", _utc()))
                self._event(db, rid, "RESERVED", {"fingerprint": fingerprint, **spec})
            db.execute("COMMIT")
        return self.read(rid)

    def read(self, rid: str) -> dict[str, Any]:
        with self._managed() as db:
            row = db.execute("SELECT * FROM attempts WHERE id=?", (rid,)).fetchone()
        if row is None:
            raise GateError("unknown_request")
        value = dict(row)
        if value["result_json"]:
            value["result"] = json.loads(value.pop("result_json"))
        else:
            value.pop("result_json")
        value["p8_operational"] = "NO-GO"
        return value

    def _claim_start(self, rid: str) -> dict[str, Any] | None:
        with self._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM attempts WHERE id=?", (rid,)).fetchone()
            if row is None:
                db.execute("ROLLBACK")
                raise GateError("unknown_request")
            if row["state"] != "ACCEPTED":
                db.execute("COMMIT")
                return None
            updated = db.execute("UPDATE attempts SET state='START_INTENT', start_count=start_count+1 WHERE id=? AND state='ACCEPTED' AND start_count=0", (rid,))
            if updated.rowcount != 1:
                db.execute("ROLLBACK")
                raise VerificationError("unique_start_intent_failed")
            self._event(db, rid, "START_INTENT", {"prior": "ACCEPTED", "start_count": 1})
            db.execute("COMMIT")
            return dict(row)

    def _record_pid(self, rid: str, pid: int, ticks: int | None) -> None:
        with self._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute("UPDATE attempts SET pid=?, pid_start_ticks=? WHERE id=? AND state='START_INTENT'",
                                 (pid, ticks, rid))
            if updated.rowcount == 1:
                self._event(db, rid, "LEADER_OBSERVED", {"pid": pid, "start_ticks": ticks})
            db.execute("COMMIT")

    @staticmethod
    def _bounded_run(fixture: str, deadline_ms: int, cap: int,
                     on_spawn: Callable[[int, int | None], None]) -> tuple[dict[str, Any], bytes, bytes]:
        cmd = [sys.executable, "-I", "-c", FIXTURE_SOURCE, fixture]
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
        started_ns = time.monotonic_ns()
        observed_ticks = _start_ticks(proc.pid)
        on_spawn(proc.pid, observed_ticks)
        pidfd = None
        if sys.platform == "linux" and hasattr(os, "pidfd_open"):
            try:
                pidfd = os.pidfd_open(proc.pid)
            except OSError:
                pass
        streams = {"stdout": bytearray(), "stderr": bytearray()}
        totals = {"stdout": 0, "stderr": 0}
        complete = {"stdout": False, "stderr": False}
        started = time.monotonic()
        term_sent = False
        signal_sent = False
        emergency = False
        selector = selectors.DefaultSelector()
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        try:
            while selector.get_map() or proc.poll() is None:
                elapsed = time.monotonic() - started
                if elapsed >= deadline_ms / 1000 and proc.poll() is None and not term_sent:
                    term_sent = True
                    if pidfd is not None and hasattr(signal, "pidfd_send_signal"):
                        try:
                            signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
                            signal_sent = True
                        except ProcessLookupError:
                            pass
                    else:
                        # Sin pidfd no señalizamos un PID potencialmente reciclado.
                        emergency = True
                if elapsed > 4.5 and proc.poll() is None:
                    # Fixtures predefinidos terminan solos como maximo a 2.5 s.
                    # Nunca reemplazar una falla de esa propiedad por PASS.
                    emergency = True
                    break
                for key, _ in selector.select(timeout=0.02):
                    name = key.data
                    try:
                        data = os.read(key.fileobj.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        complete[name] = True
                        continue
                    totals[name] += len(data)
                    remaining = cap - len(streams[name])
                    if remaining > 0:
                        streams[name].extend(data[:remaining])
            if emergency and proc.poll() is None:
                # No usar kill(-PGID), kill(pid) ni afirmar limpieza.
                proc.wait(timeout=4)
            rc = proc.wait(timeout=1)
        finally:
            selector.close()
            for stream in (proc.stdout, proc.stderr):
                if stream is not None:
                    stream.close()
            if pidfd is not None:
                os.close(pidfd)
        result = {
            "fixture": fixture,
            "leader_pid": proc.pid,
            "leader_start_ticks": observed_ticks,
            "leader_returncode": rc,
            "duration_ns": time.monotonic_ns() - started_ns,
            "deadline_exceeded": term_sent,
            "deadline_signal_sent": signal_sent,
            "pidfd_observed": pidfd is not None,
            "bounded_capture": {name: {
                "observed_bytes": totals[name],
                "stored_bytes": len(streams[name]),
                "truncated": totals[name] > len(streams[name]),
                "eof_observed": complete[name],
            } for name in streams},
            "capture_complete": all(complete.values()) and not emergency,
            "leader_reaped": True,
            "global_tree_cleanup_proven": False,
            "cleanup_scope": "OWNED_LEADER_ONLY_NO_DESCENDANT_CERTIFICATION",
            "p8_operational": "NO-GO",
        }
        return result, bytes(streams["stdout"]), bytes(streams["stderr"])

    def execute(self, rid: str) -> dict[str, Any]:
        self.accept(rid)
        row = self._claim_start(rid)
        if row is None:
            return self.read(rid)
        if os.environ.get("ARDREC_DEV_FAILPOINT_AFTER_START_INTENT") == "1":
            # Uso exclusivo en pruebas de crash: la muerte ocurre antes de Popen.
            os._exit(77)
        try:
            result, stdout, stderr = self._bounded_run(
                row["fixture"], row["deadline_ms"], row["output_cap"],
                lambda pid, ticks: self._record_pid(rid, pid, ticks))
            output = {}
            slug = _sha(rid.encode())
            for channel, data in (("stdout", stdout), ("stderr", stderr)):
                output[channel] = _atomic_file(self.artifacts, f"{slug}.{channel}", data)
            result["artifacts"] = output
            result["schema"] = SCHEMA
            result["outcome"] = (
                "CAPTURE_INCOMPLETE" if not result["capture_complete"] else
                "DEADLINE" if result["deadline_exceeded"] else
                "BENIGN_EXIT_ZERO" if result["leader_returncode"] == 0 else
                "BENIGN_EXIT_NONZERO"
            )
            # El resultado NO constituye limpieza global certificada.
            with self._managed() as db:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute("UPDATE attempts SET state='RECORDED_LIMITED', result_json=?, pid=? WHERE id=? AND state='START_INTENT'",
                                     (_canon(result).decode(), result["leader_pid"], rid))
                if changed.rowcount == 1:
                    self._event(db, rid, "RECORDED_LIMITED", {
                        "outcome": result["outcome"], "result_sha256": _sha(_canon(result)),
                        "cleanup_scope": result["cleanup_scope"]})
                db.execute("COMMIT")
        except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
            # Dejar evidencia de incertidumbre sin reintentar ejecución.
            with self._managed() as db:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute("UPDATE attempts SET state='RECOVERY_UNCERTAIN' WHERE id=? AND state='START_INTENT'", (rid,))
                if changed.rowcount == 1:
                    self._event(db, rid, "RECOVERY_UNCERTAIN", {"reason": type(exc).__name__})
                db.execute("COMMIT")
        return self.read(rid)

    def recover(self) -> list[str]:
        """Sin señales por PID, sin relanzamiento. Un START_INTENT queda incierto."""
        recovered = []
        with self._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT id FROM attempts WHERE state='START_INTENT' ORDER BY id").fetchall()
            for row in rows:
                rid = row["id"]
                db.execute("UPDATE attempts SET state='RECOVERY_UNCERTAIN' WHERE id=? AND state='START_INTENT'", (rid,))
                self._event(db, rid, "RECOVERY_UNCERTAIN", {
                    "reason": "unreconciled_start_intent",
                    "no_auto_retry": True,
                    "no_signal_without_owned_identity": True})
                recovered.append(rid)
            db.execute("COMMIT")
        return recovered

    def verify(self, rid: str) -> dict[str, Any]:
        record = self.read(rid)
        with self._managed() as db:
            rows = db.execute("SELECT action,payload_json,previous_sha256,entry_sha256 FROM events WHERE request_id=? ORDER BY seq", (rid,)).fetchall()
        if not rows or rows[0]["action"] != "RESERVED":
            raise VerificationError("event_chain_missing_initial_reservation")
        previous = "0" * 64
        for event in rows:
            raw = {"id": rid, "action": event["action"],
                   "payload": json.loads(event["payload_json"]), "previous": previous}
            if event["previous_sha256"] != previous or event["entry_sha256"] != _sha(_canon(raw)):
                raise VerificationError("event_chain_mismatch")
            previous = event["entry_sha256"]
        initial = json.loads(rows[0]["payload_json"])
        if initial.get("fingerprint") != record["fingerprint"]:
            raise VerificationError("request_fingerprint_changed")
        if record["state"] == "RECORDED_LIMITED":
            result = record["result"]
            terminal = rows[-1]
            proof = json.loads(terminal["payload_json"])
            if terminal["action"] != "RECORDED_LIMITED" or proof.get("result_sha256") != _sha(_canon(result)):
                raise VerificationError("result_record_mismatch")
            for channel in ("stdout", "stderr"):
                info = result["artifacts"][channel]
                file = self.artifacts / info["name"]
                if not file.is_file() or file.is_symlink():
                    raise VerificationError("missing_or_symlinked_artifact")
                data = file.read_bytes()
                if len(data) != info["bytes"] or _sha(data) != info["sha256"]:
                    raise VerificationError("artifact_integrity_mismatch")
            if result["global_tree_cleanup_proven"] is not False:
                raise VerificationError("forbidden_cleanup_claim")
        return {"request_id": rid, "state": record["state"],
                "event_count": len(rows), "event_head_sha256": previous,
                "artifacts_verified": record["state"] == "RECORDED_LIMITED",
                "p8_operational": "NO-GO", "no_global_tree_claim": True}
