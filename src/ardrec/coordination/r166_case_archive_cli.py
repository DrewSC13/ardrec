"""R166-F1: entrada CLI para reproduccion documental B9/F13 y archivo privado.

No captura red, no genera intentos, no admite A6 fisica ni publica A9.
El archivo es un indice DERIVADO, distinto de la generacion nativa A9.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r165_f2_a5_a10_documentary_controller as f2

SCHEMA = "ARDREC-R166-F1-SOURCE-MANIFEST-v1"
RECORD_SCHEMA = "ARDREC-R166-F1-DOCUMENTARY-ARCHIVE-v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DOCS = ("handoff", "intent", "receipt", "guest", "qga")
SIGNED = ("source", "technical", "revocation", "witness", "trust")
MAX_FILE = 200000
MAX_MANIFEST = 8192
MAX_RECORD = 100000


class Stop(ValueError):
    """Rechazo verificable con codigo estable, no autorizacion operacional."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def _abs_path(value: str | Path) -> Path:
    p = Path(value)
    need(p.is_absolute() and ".." not in p.parts, "ABSOLUTE_PATH_REQUIRED")
    return p


def _private_dir(path: Path, *, create: bool = False) -> None:
    path = _abs_path(path)
    if create and not path.exists() and not path.is_symlink():
        # El padre es privado: rechaza enlazar a un arbol controlado por terceros.
        _private_dir(path.parent)
        path.mkdir(mode=0o700)
    st = path.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
         and stat.S_IMODE(st.st_mode) == 0o700 and not path.is_symlink(),
         "PRIVATE_DIR_OWNER_MODE")


def _private_file(path: Path, limit: int) -> bytes:
    path = _abs_path(path)
    _private_dir(path.parent)
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
         and stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1,
         "PRIVATE_FILE_OWNER_MODE")
    need(0 < st.st_size <= limit, "PRIVATE_FILE_SIZE_INVALID")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        need((st.st_dev, st.st_ino, st.st_size, st.st_uid) ==
             (current.st_dev, current.st_ino, current.st_size, current.st_uid),
             "PRIVATE_FILE_READ_RACE")
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        need(len(data) == current.st_size and
             (current.st_mtime_ns, current.st_ctime_ns, current.st_size) ==
             (after.st_mtime_ns, after.st_ctime_ns, after.st_size),
             "PRIVATE_FILE_CHANGED_DURING_READ")
        return data
    finally:
        os.close(fd)


def _json(raw: bytes, code: str) -> dict:
    try:
        doc = f1.load(raw)
    except (f1.Rejected, UnicodeError, ValueError, RecursionError) as exc:
        raise Stop(code) from exc
    need(f1.canonical(doc) == raw, code + "_NOT_CANONICAL")
    return doc


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _create_exclusive(file: Path, data: bytes) -> bool:
    """Publicacion durable de manifiesto con bloqueo y recuperacion idempotente."""
    _private_dir(file.parent)
    lock_file = file.parent / ".r166-manifest.lock"
    fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                 os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
             st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600,
             "MANIFEST_LOCK_UNTRUSTED")
        fcntl.flock(fd, fcntl.LOCK_EX)
        if file.exists() or file.is_symlink():
            need(_private_file(file, max(MAX_RECORD, MAX_MANIFEST)) == data,
                 "EXISTING_RECORD_CONFLICT")
            return False
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=".pending-manifest-",
                                            dir=file.parent)
        tmp = Path(tmp_name)
        with os.fdopen(tmp_fd, "wb") as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        _sync_dir(file.parent)
        need(not (file.exists() or file.is_symlink()),
             "EXISTING_RECORD_CONFLICT")
        os.replace(tmp, file)
        _sync_dir(file.parent)
        return True
    finally:
        os.close(fd)


def _review_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    need(type(value) is str and len(value) <= 40,
         "REVIEW_CLOCK_FORMAT")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Stop("REVIEW_CLOCK_FORMAT") from exc
    need(dt.tzinfo is not None and dt.utcoffset() is not None and
         dt.utcoffset().total_seconds() == 0,
         "REVIEW_CLOCK_MUST_BE_UTC")
    need(dt <= datetime.now(timezone.utc), "REVIEW_CLOCK_IN_FUTURE")
    return dt


def _source_docs(folder: Path, names: tuple[str, ...]) -> dict:
    result = {}
    for name in names:
        path = folder / (name + ".json")
        data = _private_file(path, MAX_FILE)
        _json(data, "SOURCE_JSON_INVALID_" + name)
        result[name] = {"path": str(path), "sha256": _digest(data)}
    return result


def build_manifest(*, origin: Path, journal: Path,
                   review_at_utc: str | None = None) -> dict:
    """Sellar las referencias a originales, sin copiar ni recrear evidencia."""
    _private_dir(origin)
    journal = _abs_path(journal)
    need((journal / "spent.json").exists(), "F13_SPENT_ORIGINAL_REQUIRED")
    present = {p.name for p in origin.iterdir()}
    names = {x + ".json" for x in DOCS}
    need({"handoff.json", "intent.json", "receipt.json"} <= present,
         "EXPORTED_REQUIRED_FILES_MISSING")
    need(present <= names | {"signed"}, "EXPORTED_EXTRA_ENTRIES")
    need(("guest.json" in present) == ("qga.json" in present),
         "GUEST_QGA_PAIR_REQUIRED")
    docs = _source_docs(origin, tuple(x for x in DOCS if x + ".json" in present))
    if "signed" in present:
        signed = origin / "signed"
        _private_dir(signed)
        need({p.name for p in signed.iterdir()} ==
             {x + ".json" for x in SIGNED}, "SIGNED_SOURCE_SET_INVALID")
        docs.update({"signed/" + k: v for k, v in _source_docs(signed, SIGNED).items()})
    else:
        need(review_at_utc is None, "UNSIGNED_REVIEW_CLOCK_FORBIDDEN")
    clock = _review_at(review_at_utc)
    if "signed" in present:
        need(clock is not None, "SIGNED_REVIEW_CLOCK_REQUIRED")
    handoff = _json(_private_file(Path(docs["handoff"]["path"]), MAX_FILE),
                    "HANDOFF_JSON_INVALID")
    need(all(type(handoff.get(k)) is str and handoff[k] for k in
             ("head", "session", "case_id", "case_key", "attempt_id")),
         "HANDOFF_IDENTITY_MISSING")
    m = {"schema": SCHEMA, "journal": str(journal),
         "documents": docs, "review_at_utc": review_at_utc,
         "identity": {k: handoff[k] for k in
                      ("head", "session", "case_id", "case_key", "attempt_id")}}
    # Verificar la semantica completa antes de aceptar el manifiesto.
    evaluate_manifest(m)
    need(len(f1.canonical(m)) <= MAX_MANIFEST, "MANIFEST_TOO_LARGE")
    return m


def _load_manifest(path: Path) -> tuple[dict, bytes]:
    raw = _private_file(path, MAX_MANIFEST)
    m = _json(raw, "MANIFEST_INVALID")
    need(type(m) is dict and set(m) ==
         {"schema", "journal", "documents", "review_at_utc", "identity"}
         and m["schema"] == SCHEMA and type(m["documents"]) is dict and
         type(m["identity"]) is dict and set(m["identity"]) ==
         {"head", "session", "case_id", "case_key", "attempt_id"},
         "MANIFEST_SCHEMA_INVALID")
    return m, raw


def evaluate_manifest(m: dict) -> dict:
    need(type(m) is dict and m.get("schema") == SCHEMA,
         "MANIFEST_SCHEMA_INVALID")
    entries = m.get("documents")
    need(type(entries) is dict and
         {"handoff", "intent", "receipt"} <= set(entries) and
         (("guest" in entries) == ("qga" in entries)) and
         (set(entries) == set(DOCS) or
          set(entries) == {"handoff", "intent", "receipt"} or
          set(entries) == set(DOCS) | {"signed/" + x for x in SIGNED} or
          set(entries) == {"handoff", "intent", "receipt"} |
           {"signed/" + x for x in SIGNED}),
         "MANIFEST_DOCUMENT_SET_INVALID")
    need(type(m.get("identity")) is dict and
         set(m["identity"]) == {"head", "session", "case_id", "case_key", "attempt_id"},
         "MANIFEST_IDENTITY_INVALID")
    now = _review_at(m.get("review_at_utc"))
    has_signed = "signed/source" in entries
    need((now is not None) == has_signed, "SIGNED_REVIEW_CLOCK_MISMATCH")
    decoded: dict[str, dict] = {}
    for name, entry in entries.items():
        need(type(entry) is dict and set(entry) == {"path", "sha256"} and
             type(entry["path"]) is str and
             type(entry["sha256"]) is str and HEX64.fullmatch(entry["sha256"]),
             "MANIFEST_SOURCE_ENTRY_INVALID")
        b = _private_file(_abs_path(entry["path"]), MAX_FILE)
        need(_digest(b) == entry["sha256"], "SOURCE_SHA256_MISMATCH_" + name)
        decoded[name] = _json(b, "SOURCE_JSON_INVALID_" + name)
    need(all(decoded["handoff"].get(k) == v for k, v in m["identity"].items()),
         "MANIFEST_HANDOFF_IDENTITY_MISMATCH")
    signed = None
    if has_signed:
        signed = {k: decoded["signed/" + k] for k in SIGNED}
    report = f2.evaluate(journal=_abs_path(m["journal"]),
                         handoff=decoded["handoff"], intent=decoded["intent"],
                         receipt=decoded["receipt"], guest=decoded.get("guest"),
                         qga=decoded.get("qga"), signed=signed, now=now)
    need(report["case_id"] == m["identity"]["case_id"] and
         report["case_key"] == m["identity"]["case_key"] and
         report["session"] == m["identity"]["session"] and
         report["head"] == m["identity"]["head"],
         "DOCUMENTARY_REPORT_IDENTITY_MISMATCH")
    need(report["a6"] == "ND" and report["a7_confirmed_rf"] is None and
         report["a9_generation"] is None and report["p8"] == "NO-GO",
         "DOCUMENTARY_BOUNDARY_VIOLATED")
    return report


def _record(m: dict, raw_manifest: bytes, report: dict) -> dict:
    result = {
        "schema": RECORD_SCHEMA,
        "source_manifest_sha256": _digest(raw_manifest),
        "source_sha256": {k: v["sha256"] for k, v in m["documents"].items()},
        "identity": m["identity"],
        "review_at_utc": m["review_at_utc"],
        "documentary": report,
        "archive_only": True,
        "native_a9_committed": False,
        "a6_physical_admitted": False,
        "confirmed_rf": None,
        "experimental_unit_admitted": False,
        "p8": "NO-GO",
    }
    result["sha256"] = _digest(f1.canonical(result))
    return result


def _read_record(archive: Path) -> dict:
    doc = _json(_private_file(archive / "record.json", MAX_RECORD),
                "ARCHIVE_RECORD_INVALID")
    need(type(doc) is dict and doc.get("schema") == RECORD_SCHEMA and
         doc.get("sha256") == _digest(f1.canonical({k: v for k, v in doc.items()
                                                 if k != "sha256"})),
         "ARCHIVE_RECORD_SHA256_INVALID")
    return doc


def _lock(archive: Path) -> int:
    _private_dir(archive, create=True)
    path = archive / ".record.lock"
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600)
        st = os.fstat(fd)
        need(st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600
             and stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
             "ARCHIVE_LOCK_UNTRUSTED")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        if 'fd' in locals():
            os.close(fd)
        raise


def _persist(archive: Path, record: dict) -> str:
    """Flock + rename atomico; reintento idempotente; sin reescribir conflictos."""
    target = archive / "record.json"
    data = f1.canonical(record)
    need(len(data) <= MAX_RECORD, "ARCHIVE_RECORD_TOO_LARGE")
    fd = _lock(archive)
    try:
        if target.exists() or target.is_symlink():
            need(_read_record(archive) == record, "ARCHIVE_CAS_CONFLICT")
            return "ALREADY_INCORPORATED"
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=".pending-", dir=archive)
        tmp = Path(tmp_name)
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            _sync_dir(archive)
            # Protegido por flock exclusivo, no sobreescribe registros confirmados.
            need(not (target.exists() or target.is_symlink()), "ARCHIVE_CAS_CONFLICT")
            os.replace(tmp, target)
            _sync_dir(archive)
        except BaseException:
            # Si hubo interrupcion, .pending-* permanece para auditoria.
            raise
        return "DOCUMENTARY_RECORD_WRITTEN"
    finally:
        os.close(fd)


def process(*, manifest: Path, archive: Path | None, action: str) -> tuple[dict, str]:
    m, raw = _load_manifest(manifest)
    report = evaluate_manifest(m)
    record = _record(m, raw, report)
    if action == "revisar":
        return record, "REPLAY_ONLY"
    need(archive is not None, "ARCHIVE_REQUIRED")
    archive = _abs_path(archive)
    if action == "incorporar":
        status = _persist(archive, record)
    elif action == "reabrir":
        _private_dir(archive)
        need(_read_record(archive) == record, "ARCHIVE_REOPEN_DRIFT")
        status = "ARCHIVE_REOPEN_VERIFIED_FROM_ORIGINALS"
    else:
        raise Stop("UNKNOWN_ACTION")
    return record, status


def _show(record: dict, status: str, *, mode: str) -> None:
    if mode == "json":
        sys.stdout.buffer.write(f1.canonical({"status": status, "record": record}))
    else:
        ident = record["identity"]
        doc = record["documentary"]
        print("ARDREC_R166_STATUS=" + status)
        print("CASE_ID=" + ident["case_id"])
        print("CASE_KEY=" + ident["case_key"])
        print("ATTEMPT_ID=" + ident["attempt_id"])
        print("SESSION=" + ident["session"])
        print("SOURCE_HEAD=" + ident["head"])
        print("SOURCE_MANIFEST_SHA256=" + record["source_manifest_sha256"])
        print("DOCUMENTARY_SHA256=" + doc["sha256"])
        print("DOCUMENTARY_ARCHIVE_SHA256=" + record["sha256"])
        for stage in doc["stages"]:
            print(stage["algorithm"] + "=" + stage["status"] + ":" + stage["sha256"])
        print("A6=ND")
        print("RF_CONFIRMADO=ND")
        print("A9_GENERACION_OPERACIONAL=NO_PUBLICADA")
        print("P8=NO-GO")
        print("PRIMER_BLOQUEO=" + doc["blockers"][0])
        print("OBSERVACIONES_EXPERIMENTALES_ADMITIDAS=0")


def development_case(*, origin: Path, archive: Path, case_id: str,
                     scenario_pin: str, reopen: bool = False) -> tuple[dict, str]:
    """Open or recover a prospective DEV case; no dispatch or promotion."""
    from ardrec.experiments import initial_assessment as a2
    from ardrec.rules.kernel import decide
    from ardrec.state import Truth

    need(os.geteuid() > 0, "ROOT_CLI_FORBIDDEN")
    need(re.fullmatch(r"DEV-[a-f0-9]{32}", case_id) is not None,
         "DEV_CASE_ID_INVALID")
    need(HEX64.fullmatch(scenario_pin) is not None, "SCENARIO_PIN_INVALID")
    origin, archive = _abs_path(origin), _abs_path(archive)
    for folder in (origin, archive):
        need(folder.resolve(strict=True) == folder, "DEV_PATH_ALIAS")
        _private_dir(folder)
    need(origin != archive and origin not in archive.parents and
         archive not in origin.parents, "DEV_SOURCE_ARCHIVE_OVERLAP")

    names = ("scenario.json", "inventory.json", "assessment-template.json")
    raw = {name: _private_file(origin / name, MAX_FILE) for name in names}
    manifest = _json(raw["scenario.json"], "SCENARIO_INVALID")
    inventory = _json(raw["inventory.json"], "INVENTORY_INVALID")
    template = _json(raw["assessment-template.json"], "TEMPLATE_INVALID")
    need(_digest(raw["scenario.json"]) == scenario_pin, "SCENARIO_PIN_MISMATCH")
    protocol = manifest["protocol"]
    need(protocol in a2.PROTOCOLS, "PROTOCOL_INVALID")
    config_name = a2.CONFIG_NAMES[protocol]
    raw[config_name] = _private_file(origin / config_name, MAX_FILE)
    a2.verify_manifest(manifest, raw[config_name], inventory)
    need(template == {
        "schema": a2.SCHEMA + "-assessment-template",
        "candidate_id": manifest["candidate_id"],
        "scenario_manifest_sha256": manifest["sha256"],
        "ratings": {name: {"ordinal": None, "support_sha256": None,
                           "justification": None} for name in a2.DIMENSIONS},
        "initial_risk": None, "normalized_criticality": None,
        "baseline_closed": False, "execution_authorized": False,
        "experimental_unit": False,
    }, "ASSESSMENT_TEMPLATE_INVALID")

    # Native A1: this is a DEV hold decision, not the complete operational A3 table.
    facts = {"baseline_closed": Truth.FALSO,
             "service_identity_verified": Truth.ND,
             "technical_evidence_accredited": Truth.ND}
    rule = {"id": "DEV_HOLD", "condicion": {"op": "NO", "arg": {
        "op": "CAMPO", "nombre": "baseline_closed"}}, "salida": "PREPARADO"}
    decision = decide([rule], {name: "LOGICO" for name in facts}, facts)
    need(decision.authorized and decision.output == "PREPARADO", "DEV_HOLD_INVALID")
    record = {
        "schema": "ARDREC-R302-DEV-CASE-v1", "case_id": case_id,
        "scope": "PROSPECTIVE_DEVELOPMENT_PREPARATION_ONLY",
        "source_directory": str(origin), "protocol": protocol,
        "candidate_id": manifest["candidate_id"],
        "source_head": manifest["code_head"],
        "scenario_manifest_sha256": manifest["sha256"],
        "source_files": {name: _digest(data) for name, data in raw.items()},
        "decision": {"rule": decision.selected, "truth": decision.status.name,
                     "output": decision.output,
                     "facts": {name: value.name for name, value in facts.items()}},
        "state": "PREPARADO", "operator_uid": os.geteuid(),
        "operator_model": "SINGLE_USER", "execution_authorized": False,
        "baseline_closed": False, "attempts": 0, "evidence": [],
        "initial_risk": None, "normalized_criticality": None,
        "confirmed_rf": None, "operational_a9_published": False,
        "experimental_admission": False, "p8": "NO-GO",
    }
    record["sha256"] = _digest(f1.canonical(record))
    path = archive / (case_id + ".json")
    expected = f1.canonical(record)
    if reopen:
        need(_private_file(path, MAX_RECORD) == expected, "DEV_CASE_SOURCE_OR_RECORD_CHANGED")
        return record, "DEV_CASE_REOPENED"
    written = _create_exclusive(path, expected)
    return record, "DEV_CASE_OPENED" if written else "DEV_CASE_REOPENED"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ardrec caso",
                                 description="R166: expediente documental privado, sin trafico ni A9 operacional")
    p = ap.add_subparsers(dest="action", required=True)
    seal = p.add_parser("sellar", help="crear manifiesto SHA-256 desde originales exportados")
    seal.add_argument("--origen", required=True, type=Path)
    seal.add_argument("--journal", required=True, type=Path)
    seal.add_argument("--manifiesto", required=True, type=Path)
    seal.add_argument("--evaluacion-utc", help="hora historica para evaluar firmas; NO validez actual")
    for name in ("revisar", "incorporar", "reabrir"):
        pp = p.add_parser(name, help="replay documental y comprobacion de archivo privado")
        pp.add_argument("--manifiesto", required=True, type=Path)
        if name != "revisar":
            pp.add_argument("--archivo", required=True, type=Path)
    for name in ("abrir-dev", "reabrir-dev"):
        pp = p.add_parser(name, help="caso prospectivo DEV sin autorizacion de ejecucion")
        pp.add_argument("--origen", required=True, type=Path)
        pp.add_argument("--archivo", required=True, type=Path)
        pp.add_argument("--id", required=True)
        pp.add_argument("--sha256", required=True, help="SHA-256 de scenario.json")
    for pp in p.choices.values():
        g = pp.add_mutually_exclusive_group(required=True)
        g.add_argument("--texto", action="store_true")
        g.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        need(os.geteuid() != 0, "ROOT_CLI_FORBIDDEN")
        if args.action in ("abrir-dev", "reabrir-dev"):
            record, status = development_case(
                origin=args.origen, archive=args.archivo, case_id=args.id,
                scenario_pin=args.sha256, reopen=args.action == "reabrir-dev")
            if args.json:
                sys.stdout.buffer.write(f1.canonical(record))
            else:
                print("ARDREC / CASO DEV / " + status)
                print("CASE_ID=" + record["case_id"])
                print("PROTOCOL=" + record["protocol"])
                print("STATE=PREPARADO | ATTEMPTS=0 | A6/A7=ND | P8=NO-GO")
                print("RECORD_SHA256=" + record["sha256"])
            return 0
        if args.action == "sellar":
            m = build_manifest(origin=args.origen, journal=args.journal,
                               review_at_utc=args.evaluacion_utc)
            written = _create_exclusive(_abs_path(args.manifiesto), f1.canonical(m))
            record = _record(m, f1.canonical(m), evaluate_manifest(m))
            status = "MANIFEST_SEALED" if written else "MANIFEST_ALREADY_SEALED"
        else:
            record, status = process(manifest=_abs_path(args.manifiesto),
                                     archive=getattr(args, "archivo", None),
                                     action=args.action)
        _show(record, status, mode="texto" if args.texto else "json")
        return 0
    except (Stop, f2.Stop, f1.Rejected, OSError, ValueError, TypeError,
            KeyError, RecursionError) as exc:
        print("R166_STOP=" + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
