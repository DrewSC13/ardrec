"""P9-R15: puente durable, acotado y NO operacional hacia la parada benigna R14.

La fuente de autoridad es la reserva START_INTENT irrevocable en SQLite. El
observador R14 es un proceso fijo independiente; sus reportes son observaciones
locales, nunca autorizaciones P8 ni certificados de limpieza universal.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

from ardrec.benign_pipeline import (
    BenignPipeline, GateError, VerificationError, _atomic_file, _canon,
    _safe_dir, _sha, _start_ticks,
)

R14_SCHEMA = "ardrec-p9-r14-active-stop-v1"
R12_READY_SCHEMA = "ardrec-p9-r12-user-transient-unit-probe-v1"
R14_BASE_SHA = "1a50e30a37e43bddb8897dbf0b21b79662bb5ad9"
BRIDGE_SCHEMA = "ardrec-p9-r15-durable-stop-user-service-v1"
R14_FILE_SHA256 = "8741bf4c4af8b2059c98f8cba3a36af553270d478b2b42b386ef5cbfe6014439"
R14_FILENAME = "lab/p9_r14_active_stop_probe.py"
R14_UNIT_PATTERN = re.compile(r"^ardrec-p9r12-[a-f0-9]{12}\.service$")
PENDING_TIMEOUT_S = 38.0
MAX_REPORT_BYTES = 65536


class DurableR14StopHandoff:
    """Admite SOLO el ensayo R14 predefinido; no recibe argv ni perfiles P8."""

    def __init__(self, root: str | Path):
        self.pipe = BenignPipeline(root)
        self.receipts = self.pipe.root / "r14_stop_handoff"
        _safe_dir(self.receipts)
        with self.pipe._managed() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS r14_claims (
                    id TEXT PRIMARY KEY REFERENCES attempts(id),
                    claimed_epoch REAL NOT NULL,
                    observer_pid INTEGER,
                    observer_start_ticks INTEGER
                )
            """)

    @staticmethod
    def _r14_script() -> Path:
        path = Path(__file__).resolve().parents[2] / R14_FILENAME
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise GateError("r14_source_missing") from exc
        if _sha(raw) != R14_FILE_SHA256 or path.is_symlink():
            raise GateError("r14_source_not_pinned")
        return path

    def _directory(self, rid: str) -> Path:
        return self.receipts / _sha(rid.encode("ascii"))

    def submit(self, rid: str) -> dict[str, Any]:
        row = self.pipe.submit(rid, "r14_systemd_stop", deadline_ms=30000,
                               output_cap=MAX_REPORT_BYTES)
        _safe_dir(self._directory(rid))
        return row

    def _claim(self, rid: str) -> bool:
        """CAS del inicio y fecha persistida en UNA transacción FULL+WAL."""
        self.pipe.accept(rid)
        with self.pipe._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,fixture,start_count FROM attempts WHERE id=?", (rid,)).fetchone()
            if row is None or row["fixture"] != "r14_systemd_stop":
                db.execute("ROLLBACK")
                raise GateError("not_r14_stop_bridge_request")
            if row["state"] != "ACCEPTED":
                db.execute("COMMIT")
                return False
            n = db.execute("UPDATE attempts SET state='START_INTENT',start_count=1 "
                           "WHERE id=? AND state='ACCEPTED' AND start_count=0", (rid,)).rowcount
            if n != 1:
                db.execute("ROLLBACK")
                raise VerificationError("concurrent_claim_rejected")
            now = time.time()
            db.execute("INSERT INTO r14_claims(id,claimed_epoch) VALUES(?,?)", (rid, now))
            self.pipe._event(db, rid, "START_INTENT", {
                "prior": "ACCEPTED", "start_count": 1,
                "bridge": BRIDGE_SCHEMA, "r14_source_sha256": R14_FILE_SHA256,
                "no_auto_retry": True,
            })
            db.execute("COMMIT")
        return True

    def _observe_child(self, rid: str, proc: subprocess.Popen) -> None:
        with self.pipe._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute("UPDATE r14_claims SET observer_pid=?,observer_start_ticks=? "
                                 "WHERE id=? AND observer_pid IS NULL",
                                 (proc.pid, _start_ticks(proc.pid), rid)).rowcount
            if updated != 1:
                db.execute("ROLLBACK")
                raise VerificationError("observer_registration_failed")
            self.pipe._event(db, rid, "OBSERVER_OBSERVED", {
                "observer_pid": proc.pid, "observer_start_ticks": _start_ticks(proc.pid),
                "not_systemd_worker_identity": True,
            })
            db.execute("COMMIT")

    def start(self, rid: str, *, wait: bool = True) -> dict[str, Any]:
        self.submit(rid)
        # Verificar fuente R14 antes del START_INTENT durable.
        script = self._r14_script()
        if not self._claim(rid):
            return self.pipe.read(rid)
        proc = None
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", str(script), "--evidence-dir", str(self._directory(rid))],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
            )
            self._observe_child(rid, proc)
        except BaseException:
            # Solo el hijo Popen del coordinador; no se envía señal a una unidad
            # systemd ni a PIDs históricos. Dejar START_INTENT incierto.
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(timeout=5)
                finally:
                    pass
            raise
        if wait:
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                # El servicio systemd tiene RuntimeMaxSec=11s, pero no fabricar
                # un resultado ni señalizar PIDs por identidad almacenada.
                return self.pipe.read(rid)
            return self.reconcile(rid)
        return self.pipe.read(rid)

    @staticmethod
    def _receipt_check(report: dict[str, Any], ready: dict[str, Any] | None = None) -> bool:
        if not isinstance(report, dict):
            return False
        if (report.get("schema") != R14_SCHEMA or report.get("base_sha") != R14_BASE_SHA
                or report.get("scope") != "one_owned_benign_transient_user_service"
                or report.get("p8_operational") != "NO-GO"
                or report.get("general_tree_cleanup_proven") is not False):
            return False
        if report.get("result") in ("INCONCLUSIVE", "UNSUPPORTED"):
            return True  # Registro negativo, NUNCA éxito.
        if report.get("result") != "PASS_OWNED_ACTIVE_STOP":
            return False
        unit = report.get("unit")
        if not isinstance(unit, str) or R14_UNIT_PATTERN.fullmatch(unit) is None:
            return False
        cg = report.get("cgroup_relative")
        if (not isinstance(cg, str) or not cg.endswith("/" + unit)
                or not cg.startswith("/") or ".." in Path(cg).parts):
            return False
        flags = ("live_group_verified", "prestop_two_identities_alive",
                 "stop_command_success", "two_identities_absent",
                 "poststop_cgroup_absent_or_unpopulated")
        if not all(report.get(flag) is True for flag in flags):
            return False
        for key in ("prestop_is_active_rc", "targeted_stop_rc", "systemd_run_wrapper_rc"):
            if type(report.get(key)) is not int or report[key] != 0:
                return False
        if report.get("effective_limits") != {
            "pids.max": "16", "memory.max": "134217728", "cpu.max": "100000 100000"
        }:
            return False
        if not isinstance(ready, dict) or ready.get("schema") != R12_READY_SCHEMA:
            return False
        if (ready.get("unit") != unit or ready.get("p8_operational") != "NO-GO"
                or ready.get("worker_cgroup") != cg or ready.get("witness_cgroup") != cg
                or ready.get("witness_escaped_pgid") is not True
                or ready.get("worker_uid") != os.getuid()):
            return False
        worker, witness = ready.get("worker"), ready.get("witness")
        if not isinstance(worker, dict) or not isinstance(witness, dict):
            return False
        if report.get("worker") != worker or report.get("witness") != witness:
            return False
        try:
            return (type(worker["pid"]) is int and worker["pid"] > 1
                    and type(witness["pid"]) is int and witness["pid"] > 1
                    and worker["pid"] != witness["pid"]
                    and witness["ppid"] == worker["pid"]
                    and worker["uid"] == os.getuid() and witness["uid"] == os.getuid()
                    and worker["pgid"] != witness["pgid"]
                    and type(worker["start_ticks"]) is int and worker["start_ticks"] > 0
                    and type(witness["start_ticks"]) is int and witness["start_ticks"] > 0)
        except (KeyError, ValueError, TypeError):
            return False

    @staticmethod
    def _owned_receipt(path: Path, max_bytes: int) -> bytes | None:
        if not path.exists() and not path.is_symlink():
            return None
        if path.is_symlink() or not path.is_file():
            raise VerificationError("receipt_path_not_regular")
        st = path.stat()
        if (st.st_uid != os.getuid() or st.st_size > max_bytes
                or st.st_mode & 0o077 or st.st_nlink != 1):
            raise VerificationError("receipt_permissions_size_or_links")
        return path.read_bytes()

    def _receipt_bytes(self, rid: str) -> tuple[bytes, bytes] | None:
        folder = self._directory(rid)
        data = self._owned_receipt(folder / "r14_report.json", MAX_REPORT_BYTES)
        if data is None:
            return None
        ready_data = self._owned_receipt(folder / "ready.json", 16_384)
        try:
            report = json.loads(data)
            ready = json.loads(ready_data) if ready_data is not None else None
        except (ValueError, UnicodeError, TypeError) as exc:
            raise VerificationError("r14_receipt_json_invalid") from exc
        if not self._receipt_check(report, ready):
            raise VerificationError("r14_receipt_claim_invalid")
        return data, ready_data or b""

    def reconcile(self, rid: str, *, now: float | None = None) -> dict[str, Any]:
        row = self.pipe.read(rid)
        if row["fixture"] != "r14_systemd_stop":
            raise GateError("not_r14_stop_bridge_request")
        if row["state"] != "START_INTENT":
            return row
        with self.pipe._managed() as db:
            claimed = db.execute("SELECT claimed_epoch FROM r14_claims WHERE id=?", (rid,)).fetchone()
        if claimed is None:
            raise VerificationError("r14_claim_missing")
        try:
            data = self._receipt_bytes(rid)
        except VerificationError:
            # Un recibo alterado no puede ser promovido; conservar START_INTENT
            # para diagnóstico hasta vencer el plazo de conciliación.
            data = None
        if data is not None:
            report_data, ready_data = data
            report = json.loads(report_data)
            slug = _sha(rid.encode("ascii"))
            # Reescritura idempotente, únicamente si los bytes son idénticos.
            artifacts: dict[str, dict[str, Any]] = {}
            for channel, payload in (("stdout", report_data), ("stderr", ready_data)):
                name = f"{slug}.{channel}"
                dest = self.pipe.artifacts / name
                if dest.is_file() and not dest.is_symlink():
                    existing = dest.read_bytes()
                    if existing != payload:
                        raise VerificationError("r15_existing_artifact_mismatch")
                    artifacts[channel] = {"name": name, "sha256": _sha(payload), "bytes": len(payload)}
                else:
                    artifacts[channel] = _atomic_file(self.pipe.artifacts, name, payload)
            result = {
                "schema": BRIDGE_SCHEMA,
                "fixture": "r14_systemd_stop",
                "outcome": ("R14_ACTIVE_STOP_REPORTED_PASS" if report["result"] == "PASS_OWNED_ACTIVE_STOP"
                            else "R14_ACTIVE_STOP_INCONCLUSIVE"),
                "r14_report_sha256": _sha(report_data),
                "r14_ready_sha256": _sha(ready_data),
                "r14_reported_result": report["result"],
                "r14_targeted_stop_rc": report.get("targeted_stop_rc"),
                "global_tree_cleanup_proven": False,
                "cleanup_scope": "R14_TWO_IDENTITIES_AND_CGROUP_OBSERVED_ONLY",
                "p8_operational": "NO-GO", "artifacts": artifacts,
            }
            with self.pipe._managed() as db:
                db.execute("BEGIN IMMEDIATE")
                n = db.execute("UPDATE attempts SET state='RECORDED_LIMITED',result_json=? "
                               "WHERE id=? AND state='START_INTENT'",
                               (_canon(result).decode(), rid)).rowcount
                if n:
                    self.pipe._event(db, rid, "RECORDED_LIMITED", {
                        "outcome": result["outcome"],
                        "result_sha256": _sha(_canon(result)),
                        "cleanup_scope": result["cleanup_scope"],
                    })
                db.execute("COMMIT")
            return self.pipe.read(rid)
        age = (time.time() if now is None else now) - claimed["claimed_epoch"]
        if age < PENDING_TIMEOUT_S:
            return self.pipe.read(rid)
        with self.pipe._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            n = db.execute("UPDATE attempts SET state='RECOVERY_UNCERTAIN' "
                           "WHERE id=? AND state='START_INTENT'", (rid,)).rowcount
            if n:
                self.pipe._event(db, rid, "RECOVERY_UNCERTAIN", {
                    "reason": "r14_receipt_absent_or_invalid_after_deadline",
                    "no_auto_retry": True, "no_global_cleanup_claim": True,
                })
            db.execute("COMMIT")
        return self.pipe.read(rid)

    def recover(self, *, now: float | None = None) -> dict[str, str]:
        with self.pipe._managed() as db:
            rows = db.execute("SELECT id FROM attempts WHERE state='START_INTENT' "
                              "AND fixture='r14_systemd_stop' ORDER BY id").fetchall()
        return {r["id"]: self.reconcile(r["id"], now=now)["state"] for r in rows}

    def verify(self, rid: str) -> dict[str, Any]:
        proof = self.pipe.verify(rid)
        row = self.pipe.read(rid)
        if row["fixture"] != "r14_systemd_stop":
            raise GateError("not_r14_stop_bridge_request")
        if row["state"] == "RECORDED_LIMITED":
            data = self._receipt_bytes(rid)
            if (data is None or _sha(data[0]) != row["result"]["r14_report_sha256"]
                    or _sha(data[1]) != row["result"]["r14_ready_sha256"]):
                raise VerificationError("r14_receipt_integrity_mismatch")
        return proof
