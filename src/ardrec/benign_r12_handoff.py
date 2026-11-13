"""P9-R13: puente durable, acotado y NO operacional hacia el ensayo benigno R12.

La fuente de autoridad es la reserva START_INTENT irrevocable en SQLite. El
observador R12 es un proceso fijo independiente; sus reportes son observaciones
locales, nunca autorizaciones P8 ni certificados de limpieza universal.
"""
from __future__ import annotations

import hashlib
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

R12_SCHEMA = "ardrec-p9-r12-user-transient-unit-probe-v1"
R12_MAIN_SHA = "1c6ea04489a685cbd9b12c9e6e0bd956839cefe9"
BRIDGE_SCHEMA = "ardrec-p9-r13-durable-user-service-v1"
R12_FILE_SHA256 = "bd3d750468ffbb1934d46d39974c5a9b9bcc476b6b39021c4b5a026430542726"
R12_FILENAME = "lab/p9_r12_systemd_user_probe.py"
R12_UNIT_PATTERN = re.compile(r"^ardrec-p9r12-[a-f0-9]{12}\.service$")
PENDING_TIMEOUT_S = 38.0
MAX_REPORT_BYTES = 65536


class DurableR12Handoff:
    """Admite SOLO el ensayo R12 predefinido; no recibe argv ni perfiles P8."""

    def __init__(self, root: str | Path):
        self.pipe = BenignPipeline(root)
        self.receipts = self.pipe.root / "r12_handoff"
        _safe_dir(self.receipts)
        with self.pipe._managed() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS r12_claims (
                    id TEXT PRIMARY KEY REFERENCES attempts(id),
                    claimed_epoch REAL NOT NULL,
                    observer_pid INTEGER,
                    observer_start_ticks INTEGER
                )
            """)

    @staticmethod
    def _r12_script() -> Path:
        path = Path(__file__).resolve().parents[2] / R12_FILENAME
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise GateError("r12_source_missing") from exc
        if _sha(raw) != R12_FILE_SHA256 or path.is_symlink():
            raise GateError("r12_source_not_pinned")
        return path

    def _directory(self, rid: str) -> Path:
        return self.receipts / _sha(rid.encode("ascii"))

    def submit(self, rid: str) -> dict[str, Any]:
        row = self.pipe.submit(rid, "r12_systemd", deadline_ms=30000,
                               output_cap=MAX_REPORT_BYTES)
        _safe_dir(self._directory(rid))
        return row

    def _claim(self, rid: str) -> bool:
        """CAS del inicio y fecha persistida en UNA transacción FULL+WAL."""
        self.pipe.accept(rid)
        with self.pipe._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT state,fixture,start_count FROM attempts WHERE id=?", (rid,)).fetchone()
            if row is None or row["fixture"] != "r12_systemd":
                db.execute("ROLLBACK")
                raise GateError("not_r12_bridge_request")
            if row["state"] != "ACCEPTED":
                db.execute("COMMIT")
                return False
            n = db.execute("UPDATE attempts SET state='START_INTENT',start_count=1 "
                           "WHERE id=? AND state='ACCEPTED' AND start_count=0", (rid,)).rowcount
            if n != 1:
                db.execute("ROLLBACK")
                raise VerificationError("concurrent_claim_rejected")
            now = time.time()
            db.execute("INSERT INTO r12_claims(id,claimed_epoch) VALUES(?,?)", (rid, now))
            self.pipe._event(db, rid, "START_INTENT", {
                "prior": "ACCEPTED", "start_count": 1,
                "bridge": BRIDGE_SCHEMA, "r12_source_sha256": R12_FILE_SHA256,
                "no_auto_retry": True,
            })
            db.execute("COMMIT")
        return True

    def _observe_child(self, rid: str, proc: subprocess.Popen) -> None:
        with self.pipe._managed() as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute("UPDATE r12_claims SET observer_pid=?,observer_start_ticks=? "
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
        # Verificar PIN ANTES del commit irreversible START_INTENT.
        script = self._r12_script()
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
    def _receipt_check(report: dict[str, Any]) -> bool:
        if (not isinstance(report, dict) or report.get("schema") != R12_SCHEMA
                or report.get("main_sha") != R12_MAIN_SHA):
            return False
        if report.get("p8_operational") != "NO-GO" or report.get("general_cleanup_certified") is not False:
            return False
        if report.get("result") == "PASS_BENIGN_TRANSIENT_UNIT":
            unit = report.get("unit")
            if not isinstance(unit, str) or R12_UNIT_PATTERN.fullmatch(unit) is None:
                return False
            cg = report.get("cgroup_relative", "")
            limits = report.get("observed_limits", {})
            if not isinstance(cg, str) or not cg.endswith("/" + unit) or not isinstance(limits, dict):
                return False
            if (limits.get("pids.max") != "16" or limits.get("memory.max") != "134217728"
                    or limits.get("cpu.max") != "100000 100000"):
                return False
            if not (report.get("live_group_proven") is True
                    and report.get("live_identity_confirmed") is True
                    and report.get("poststop_absence_proven") is True
                    and report.get("systemd_run_rc") == 0):
                return False
            return True
        return report.get("result") in ("INCONCLUSIVE", "UNSUPPORTED")

    def _receipt_bytes(self, rid: str) -> bytes | None:
        path = self._directory(rid) / "report.json"
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise VerificationError("r12_report_file_not_regular")
        st = path.stat()
        if st.st_uid != os.getuid() or st.st_size > MAX_REPORT_BYTES or st.st_mode & 0o077:
            raise VerificationError("r12_report_permissions_or_size")
        data = path.read_bytes()
        try:
            obj = json.loads(data)
        except (ValueError, UnicodeError) as exc:
            raise VerificationError("r12_report_json_invalid") from exc
        if not self._receipt_check(obj):
            raise VerificationError("r12_report_claim_invalid")
        return data

    def reconcile(self, rid: str, *, now: float | None = None) -> dict[str, Any]:
        row = self.pipe.read(rid)
        if row["fixture"] != "r12_systemd":
            raise GateError("not_r12_bridge_request")
        if row["state"] != "START_INTENT":
            return row
        with self.pipe._managed() as db:
            claimed = db.execute("SELECT claimed_epoch FROM r12_claims WHERE id=?", (rid,)).fetchone()
        if claimed is None:
            raise VerificationError("r12_claim_missing")
        try:
            data = self._receipt_bytes(rid)
        except VerificationError:
            # Un recibo alterado no puede ser promovido; conservar START_INTENT
            # para diagnóstico hasta vencer el plazo de conciliación.
            data = None
        if data is not None:
            report = json.loads(data)
            slug = _sha(rid.encode("ascii"))
            # Reescritura idempotente, únicamente si los bytes son idénticos.
            artifacts: dict[str, dict[str, Any]] = {}
            for channel, payload in (("stdout", data), ("stderr", b"")):
                name = f"{slug}.{channel}"
                dest = self.pipe.artifacts / name
                if dest.is_file() and not dest.is_symlink():
                    existing = dest.read_bytes()
                    if existing != payload:
                        raise VerificationError("r13_existing_artifact_mismatch")
                    artifacts[channel] = {"name": name, "sha256": _sha(payload), "bytes": len(payload)}
                else:
                    artifacts[channel] = _atomic_file(self.pipe.artifacts, name, payload)
            result = {
                "schema": BRIDGE_SCHEMA,
                "fixture": "r12_systemd",
                "outcome": ("R12_OBSERVATION_REPORTED_PASS" if report["result"] == "PASS_BENIGN_TRANSIENT_UNIT"
                            else "R12_OBSERVATION_INCONCLUSIVE"),
                "r12_report_sha256": _sha(data),
                "r12_reported_result": report["result"],
                "r12_targeted_stop_rc": report.get("targeted_stop_rc"),
                "global_tree_cleanup_proven": False,
                "cleanup_scope": "R12_TWO_IDENTITIES_OBSERVED_ONLY",
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
                    "reason": "r12_receipt_absent_or_invalid_after_deadline",
                    "no_auto_retry": True, "no_global_cleanup_claim": True,
                })
            db.execute("COMMIT")
        return self.pipe.read(rid)

    def recover(self, *, now: float | None = None) -> dict[str, str]:
        with self.pipe._managed() as db:
            rows = db.execute("SELECT id FROM attempts WHERE state='START_INTENT' "
                              "AND fixture='r12_systemd' ORDER BY id").fetchall()
        return {r["id"]: self.reconcile(r["id"], now=now)["state"] for r in rows}

    def verify(self, rid: str) -> dict[str, Any]:
        proof = self.pipe.verify(rid)
        row = self.pipe.read(rid)
        if row["fixture"] != "r12_systemd":
            raise GateError("not_r12_bridge_request")
        if row["state"] == "RECORDED_LIMITED":
            data = self._receipt_bytes(rid)
            if data is None or _sha(data) != row["result"]["r12_report_sha256"]:
                raise VerificationError("r12_receipt_integrity_mismatch")
        return proof
