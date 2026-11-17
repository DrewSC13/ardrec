"""R58-Y: registro DEV durable de observaciones R42.2/R42.3, SIN admisión A6.

La autenticación semántica de los recibos corresponde al validador R42.4
existente. Un hash no equivale a firma ni transforma instantáneas de red en
prueba de vulnerabilidad. Nunca ejecuta red, VM, A5 ni publica A9.
"""
from __future__ import annotations

from contextlib import closing
from hashlib import sha256
from pathlib import Path
import json
import os
import re
import sqlite3
import stat
from typing import Any

from ardrec.coordination import r424_evidence_tui as r424

SCHEMA = 'ardrec-p14-r58y-observation-registry-v1'
DB_SCHEMA = 'ardrec-p14-r58y-sqlite-v1'
SERVICES = ('SSH', 'FTPS', 'SMB')
MAX_ROWS = 128
HEX = re.compile(r'[0-9a-f]{64}\Z')


class ObservationError(ValueError):
    """Bloqueo explícito de admisión, integridad o procedencia."""


def need(condition: bool, code: str) -> None:
    if not condition:
        raise ObservationError(code)


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def safe_path(value: Path, *, must_exist: bool) -> Path:
    need(isinstance(value, Path) and value.is_absolute(), 'absolute_path_required')
    need(not any(part.is_symlink() for part in (value, *value.parents)),
         'symlink_path_denied')
    need(value.parent.is_dir(), 'parent_directory_missing')
    if must_exist:
        need(value.exists(), 'source_missing')
    return value


def verify_sources(r422_dir: Path, r423_dir: Path) -> dict[str, Any]:
    """Reverifica R42.2/R42.3 con el contrato existente, sin mutar los recibos."""
    safe_path(r422_dir, must_exist=True)
    safe_path(r423_dir, must_exist=True)
    need(r422_dir.is_dir() and r423_dir.is_dir(), 'source_directory_required')
    first = r424.read_physical(r422_dir, r423_dir)
    witness = r424.r422.verify_private_receipt(r422_dir)
    files = r424.verified_directory(r423_dir,
                                     frozenset({r424.r423.INTENT, r424.r423.RESULT}))
    route = r424.r365.read_json(files[r424.r423.RESULT])
    r424.r423.verify_report(route)
    second = r424.read_physical(r422_dir, r423_dir)
    need(first == second, 'source_changed_during_read')
    need(first['r422_report_sha256'] == r424.R422_PIN and
         first['r423_report_sha256'] == r424.R423_PIN and
         first['source_kind'] == 'REAL_READONLY_SSH_SNAPSHOT' and
         first['p8_operational'] == 'NO-GO' and
         first['isolation_proven'] is False, 'unrecognized_physical_receipt')
    stamps = {'r422': witness['captured_at_utc'],
              'r423': route['captured_at_utc']}
    need(all(type(t) is str and len(t) <= 40 for t in stamps.values()),
         'captured_time_invalid')
    return {'physical': first, 'captured_at_utc': stamps}


def build_ssh_record(r422_dir: Path, r423_dir: Path) -> dict[str, Any]:
    source = verify_sources(r422_dir, r423_dir)
    identity = digest(canon(source))
    record = {
        'schema': SCHEMA,
        'record_id': 'OBS_SSH_' + identity,
        'service': 'SSH',
        'mode': 'LABORATORY_HISTORICAL_READONLY',
        'source_kind': 'REAL_READONLY_SSH_SNAPSHOT',
        'r422_directory': str(r422_dir),
        'r423_directory': str(r423_dir),
        'captured_at_utc': source['captured_at_utc'],
        'physical': source['physical'],
        'a5_attempt_id': None,
        'a6_classification': 'ND',
        'a6_reason': 'NO_A5_OR_DECLARED_CONDITION_BINDING',
        'a7_confirmed_rf': None,
        'a9_published_generation': None,
        'p8_operational': 'NO-GO',
        'operational_dispatch': False,
        'technical_truth_accredited': False,
    }
    validate_record(record)
    return record


def validate_record(record: dict[str, Any]) -> None:
    need(type(record) is dict and set(record) == {
        'schema', 'record_id', 'service', 'mode', 'source_kind',
        'r422_directory', 'r423_directory', 'captured_at_utc', 'physical',
        'a5_attempt_id', 'a6_classification', 'a6_reason', 'a7_confirmed_rf',
        'a9_published_generation', 'p8_operational', 'operational_dispatch',
        'technical_truth_accredited',
    }, 'record_schema_invalid')
    need(record['schema'] == SCHEMA and record['service'] == 'SSH' and
         record['mode'] == 'LABORATORY_HISTORICAL_READONLY' and
         record['source_kind'] == 'REAL_READONLY_SSH_SNAPSHOT' and
         record['a5_attempt_id'] is None and
         record['a6_classification'] == 'ND' and
         record['a6_reason'] == 'NO_A5_OR_DECLARED_CONDITION_BINDING' and
         record['a7_confirmed_rf'] is None and
         record['a9_published_generation'] is None and
         record['p8_operational'] == 'NO-GO' and
         record['operational_dispatch'] is False and
         record['technical_truth_accredited'] is False,
         'record_authority_escalation')
    p = record['physical']
    need(type(p) is dict and
         p.get('r422_report_sha256') == r424.R422_PIN and
         p.get('r423_report_sha256') == r424.R423_PIN and
         p.get('source_kind') == 'REAL_READONLY_SSH_SNAPSHOT' and
         p.get('p8_operational') == 'NO-GO' and
         p.get('isolation_proven') is False and
         p.get('route') == 'DIRECT_ENS3_EXPECTED' and
         p.get('arp') in ('ABSENT', 'INCOMPLETE', 'RESOLVED') and
         all(type(p.get(k)) is int and 0 <= p[k] <= 2**64 - 1
             for k in ('tx_snapshot', 'rx_snapshot')) and
         p.get('tap_frames_r422') == 0 and
         p.get('bridge_frames_r422') == 0 and
         p.get('guest_ping_reported_transmitted_r422') == 1,
         'record_physical_invalid')
    stamps = record['captured_at_utc']
    need(type(stamps) is dict and set(stamps) == {'r422', 'r423'} and
         all(type(t) is str and len(t) <= 40 for t in stamps.values()),
         'record_capture_times_invalid')
    for field in ('r422_directory', 'r423_directory'):
        need(type(record[field]) is str and len(record[field]) <= 4096 and
             Path(record[field]).is_absolute(), 'record_source_path_invalid')
    identity = digest(canon({'physical': p, 'captured_at_utc': stamps}))
    need(record['record_id'] == 'OBS_SSH_' + identity,
         'record_identity_mismatch')


def _connect(db: Path, *, readonly: bool) -> sqlite3.Connection:
    safe_path(db, must_exist=readonly)
    if not db.exists():
        need(not readonly, 'database_missing')
        fd = os.open(db, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
    info = db.stat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         (info.st_mode & 0o077) == 0, 'database_file_unsafe')
    if readonly:
        # Path.as_uri escapes special characters and uses SQLite's readonly mode.
        conn = sqlite3.connect(f'{db.as_uri()}?mode=ro', uri=True, timeout=5)
        conn.execute('PRAGMA query_only=ON')
    else:
        conn = sqlite3.connect(db, timeout=5)
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.execute('PRAGMA synchronous=FULL')
    need(conn.execute('PRAGMA quick_check').fetchone() == ('ok',),
         'database_integrity_failed')
    return conn


def _schema(conn: sqlite3.Connection, *, initialize: bool) -> None:
    if initialize:
        with conn:
            conn.execute('CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS observations ('
                         'record_id TEXT PRIMARY KEY, payload TEXT NOT NULL, sha256 TEXT NOT NULL)')
            conn.execute('INSERT OR IGNORE INTO metadata VALUES (?, ?)', ('schema', DB_SCHEMA))
    row = conn.execute('SELECT value FROM metadata WHERE key=?', ('schema',)).fetchone()
    need(row == (DB_SCHEMA,), 'database_schema_mismatch')
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    need(tables == {'metadata', 'observations'}, 'database_extra_tables')
    need(conn.execute('SELECT count(*) FROM observations').fetchone()[0] <= MAX_ROWS,
         'database_row_limit')


def _read_rows(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute('SELECT record_id, payload, sha256 FROM observations ORDER BY record_id').fetchall()
    need(len(rows) <= MAX_ROWS, 'database_row_limit')
    result = []
    for rid, raw, stored_hash in rows:
        need(type(raw) is str and len(raw) <= 16000 and
             type(stored_hash) is str and HEX.fullmatch(stored_hash) is not None,
             'row_invalid')
        try:
            rec = json.loads(raw)
        except (ValueError, TypeError, RecursionError) as exc:
            raise ObservationError('row_json_invalid') from exc
        validate_record(rec)
        need(rec['record_id'] == rid and
             digest(canon(rec)) == stored_hash and
             canon(rec).decode('ascii') == raw, 'row_digest_mismatch')
        result.append(rec)
    return result


def initialize_database(db: Path) -> int:
    """Abre o crea el registro privado sin inventar ni incorporar observaciones."""
    with closing(_connect(db, readonly=False)) as conn:
        _schema(conn, initialize=True)
        return len(_read_rows(conn))


def import_ssh(db: Path, r422_dir: Path, r423_dir: Path) -> tuple[str, dict[str, Any]]:
    """Importación idempotente; no elimina ni cambia observaciones anteriores."""
    record = build_ssh_record(r422_dir, r423_dir)
    with closing(_connect(db, readonly=False)) as conn:
        _schema(conn, initialize=True)
        conn.execute('BEGIN IMMEDIATE')
        previous = _read_rows(conn)
        for candidate in previous:
            if candidate['record_id'] == record['record_id']:
                need(candidate == record, 'duplicate_identity_conflict')
                conn.rollback()
                return 'REPLAY_IDENTICAL', record
        need(len(previous) < MAX_ROWS, 'database_full')
        conn.execute('INSERT INTO observations VALUES (?, ?, ?)',
                     (record['record_id'], canon(record).decode('ascii'), digest(canon(record))))
        conn.commit()
    return 'IMPORTED', record


def load_records(db: Path, *, revalidate_sources: bool = True) -> list[dict[str, Any]]:
    """Reapertura solo lectura; con fuente privada faltante/alterada, DENY."""
    with closing(_connect(db, readonly=True)) as conn:
        _schema(conn, initialize=False)
        result = _read_rows(conn)
    if revalidate_sources:
        for record in result:
            actual = build_ssh_record(Path(record['r422_directory']),
                                      Path(record['r423_directory']))
            need(actual == record, 'source_no_longer_matches_imported_record')
    return result


def service_rows(records: list[dict[str, Any]], service: str) -> list[str]:
    need(service in SERVICES, 'unknown_service')
    out = [f'SERVICIO: {service}  /  P8: NO-GO',
           'REGISTRO: HISTORICO / SOLO LECTURA / NO EN VIVO', '']
    relevant = [r for r in records if r['service'] == service]
    for r in relevant:
        validate_record(r)
        p = r['physical']
        out.extend([
            'ID: ' + r['record_id'],
            'CAPTURA R42.2 UTC: ' + r['captured_at_utc']['r422'],
            'CAPTURA R42.3 UTC: ' + r['captured_at_utc']['r423'],
            'R42.2 SHA256: ' + p['r422_report_sha256'],
            'R42.3 SHA256: ' + p['r423_report_sha256'],
            'RUTA: ' + p['route'] + '  ARP: ' + p['arp'],
            f"ENS3 TX: {p['tx_snapshot']}  RX: {p['rx_snapshot']}",
            f"PCAP TAP: {p['tap_frames_r422']}  BRIDGE: {p['bridge_frames_r422']}",
            'OBSERVADO: instantaneas de red; aislamiento NO PROBADO',
        ])
    if not relevant:
        out.extend(['SIN RECIBO FISICO VERIFICADO PARA ESTE SERVICIO',
                    'No se puede afirmar funcionamiento ni vulnerabilidad.'])
    out += ['', 'A5: SIN INTENTO VINCULADO A ESTE REGISTRO',
            'A6: ND - NO HAY VINCULO A CONDICION DECLARADA',
            'A7: Rf NO CALCULADO CON ESTA OBSERVACION',
            'A9: GENERACION NO PUBLICADA',
            'R58-X: NO_START sintetico -> ND (modelo independiente)',
            'Una lectura historica NO acredita inicio A5 ni evidencia A6.']
    return out


def render_frame(records: list[dict[str, Any]], selected: int = 0,
                 width: int = 112, height: int = 33, offset: int = 0) -> list[str]:
    need(type(selected) is int and 0 <= selected < 3 and
         70 <= width <= 240 and 16 <= height <= 120 and offset >= 0,
         'frame_geometry_invalid')
    for rec in records:
        validate_record(rec)
    service = SERVICES[selected]
    nav = [f"{'>' if i == selected else ' '} {s:<5} | {sum(r['service']==s for r in records)} recibos"
           for i, s in enumerate(SERVICES)]
    detail = service_rows(records, service)
    def fit(s: str, n: int) -> str:
        return ''.join(ch if ch.isprintable() else ' ' for ch in s)[:n].ljust(n)
    top = [fit('ARDREC / R58-Y  |  OBSERVACIONES DEV RECUPERABLES', width),
           fit('P8:NO-GO | A6:ND | A9:NO PUBLICADA | FUENTES REVALIDADAS AL ABRIR', width),
           '-' * width]
    nw = 23
    dw = width - nw - 1
    lines = []
    for index in range(height-5):
        left = nav[index] if index < len(nav) else ''
        right = detail[index + offset] if index+offset < len(detail) else ''
        lines.append('| ' + fit(left, nw-3) + '|' + ' ' + fit(right, dw))
    return top + lines + [fit('1 SSH | 2 FTPS | 3 SMB | j/k cambiar | UP/DOWN desplazar | q salir', width),
                          fit('Sin VM, sin red, sin ejecucion A5, sin publicacion A9', width)]


def run_tui(records: list[dict[str, Any]]) -> None:
    import curses
    import sys
    need(sys.stdin.isatty() and sys.stdout.isatty(), 'tui_requires_tty')
    def app(screen: Any) -> None:
        screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        selected = 0
        offset = 0
        while True:
            screen.erase()
            h, w = screen.getmaxyx()
            if w < 70 or h < 16:
                screen.addnstr(0, 0, 'Minimo 70x16 (q salir)', max(1,w-1))
            else:
                frame = render_frame(records,selected,min(w-1,240),min(h,120),offset)
                for n, line in enumerate(frame[:h]):
                    try:
                        screen.addnstr(n,0,line,max(1,w-1))
                    except curses.error:
                        pass
            screen.refresh()
            key=screen.getch()
            if key in (ord('q'),ord('Q'),27):
                return
            if key in (ord('1'),ord('2'),ord('3')):
                selected=key-ord('1');offset=0
            elif key in (ord('j'),ord('l')):
                selected=(selected+1)%3;offset=0
            elif key in (ord('k'),ord('h')):
                selected=(selected-1)%3;offset=0
            elif key==curses.KEY_DOWN:
                offset=min(offset+1,len(service_rows(records,SERVICES[selected]))-1)
            elif key==curses.KEY_UP:
                offset=max(0,offset-1)
    curses.wrapper(app)
