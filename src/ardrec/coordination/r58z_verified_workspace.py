"""R58-Z: sesión de observaciones REALMENTE verificadas para A10/TUI.

Consume exclusivamente el SQLite R58-Y con revalidación física de origen.
La instantánea histórica NO es A5, A6, Rf ni generación A9. Ningún comando
al huésped, socket, subprocess ni modificación del SQLite R58-Y.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import json
import os
import re
import stat
from typing import Any

from ardrec.coordination import r58y_observation_register as r58y

SCHEMA = 'ardrec-p14-r58z-verified-observation-workspace-v1'
SERVICES = ('SSH', 'FTPS', 'SMB')
STAGES = tuple('A' + str(i) for i in range(1, 11))
HEX = re.compile(r'[0-9a-f]{64}\Z')
MAX_BYTES = 200_000


class WorkspaceError(ValueError):
    """Denegación estable de integridad, fuente, o autoridad."""


def need(ok: bool, reason: str) -> None:
    if not ok:
        raise WorkspaceError(reason)


def canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('ascii')


def sha(raw: bytes) -> str:
    return sha256(raw).hexdigest()


def _sane_private_path(path: Path, *, existing: bool) -> None:
    need(isinstance(path, Path) and path.is_absolute(), 'absolute_path_required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink_path_forbidden')
    need(path.parent.is_dir() and (not existing or path.is_file()), 'private_path_missing')
    if existing:
        info = path.stat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
             (info.st_mode & 0o077) == 0, 'unsafe_private_file')


def _stage_rows(service: str, count: int) -> list[dict[str, str]]:
    # Una observación de red no constituye inicialización ni inicio de A5.
    desc = (
        ('SIN_VINCULO', 'Sin vínculo a sesión de reglas evaluada'),
        ('SIN_VINCULO', 'Sin inicialización operacional confirmada'),
        ('NO_AUTORIZADO', 'No hay guardas de autorización operacional confirmadas'),
        ('NO_SELECCIONADO', 'Sin selección ejecutable A4 confirmada'),
        ('SIN_INICIO', 'No hay intento A5 vinculado con soporte de inicio'),
        ('ND', 'No hay soporte ligado a condición declarada; evidencia A6=ND'),
        ('SIN_RF', 'Riesgo final no calculado ni confirmado con la observación'),
        ('SIN_TRANSICION', 'No hay criterio de parada aplicado al estado real'),
        ('NO_PUBLICADA', 'No existe generación A9 publicada y confirmada'),
        ('OBSERVACION_VERIFICADA' if count else 'SIN_OBSERVACION',
         'A10 expone instantánea histórica del registro R58-Y, no ejecución'),
    )
    return [{'algorithm': stage, 'status': status, 'detail': detail}
            for stage, (status, detail) in zip(STAGES, desc, strict=True)]


def build_workspace(records: list[dict[str, Any]]) -> dict[str, Any]:
    need(type(records) is list and len(records) <= r58y.MAX_ROWS, 'record_collection_invalid')
    for row in records:
        r58y.validate_record(row)
    ids = [row['record_id'] for row in records]
    need(len(ids) == len(set(ids)), 'duplicate_observation_identity')
    services = []
    for service in SERVICES:
        matching = sorted((row for row in records if row['service'] == service),
                          key=lambda r: r['record_id'])
        services.append({
            'service': service,
            'observation_count': len(matching),
            'observations': [{
                'record_id': row['record_id'],
                'captured_at_utc': row['captured_at_utc'],
                'source_r422_sha256': row['physical']['r422_report_sha256'],
                'source_r423_sha256': row['physical']['r423_report_sha256'],
                'route': row['physical']['route'],
                'arp': row['physical']['arp'],
                'tx_packets': row['physical']['tx_snapshot'],
                'rx_packets': row['physical']['rx_snapshot'],
                'origin': row['source_kind'],
                'a6_classification': 'ND',
                'a5_attempt_id': None,
            } for row in matching],
            'stages': _stage_rows(service, len(matching)),
        })
    doc = {
        'schema': SCHEMA,
        'record_source': r58y.DB_SCHEMA,
        'source_type': 'VERIFIED_HISTORICAL_R58Y_SQLITE',
        'services': services,
        'total_observations': len(records),
        'service_count': 3,
        'stage_count': 10,
        'a5_operational_starts': 0,
        'a6_accredited_conditions': 0,
        'a7_confirmed_rf': None,
        'a9_published_generation': None,
        'technical_truth_accredited': False,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
        'publication_type': 'READONLY_OBSERVATION_SNAPSHOT_NOT_A9',
    }
    doc['sha256'] = sha(canon(doc))
    verify_workspace(doc)
    return doc


def verify_workspace(doc: dict[str, Any]) -> bool:
    need(type(doc) is dict and type(doc.get('sha256')) is str and
         HEX.fullmatch(doc['sha256']) is not None and
         sha(canon({k: v for k, v in doc.items() if k != 'sha256'})) == doc['sha256'],
         'workspace_digest_mismatch')
    need(set(doc) == {'schema', 'record_source', 'source_type', 'services',
                      'total_observations', 'service_count', 'stage_count',
                      'a5_operational_starts', 'a6_accredited_conditions',
                      'a7_confirmed_rf', 'a9_published_generation',
                      'technical_truth_accredited', 'operational_dispatch',
                      'p8_operational', 'publication_type', 'sha256'}, 'workspace_schema_invalid')
    need(doc['schema'] == SCHEMA and doc['record_source'] == r58y.DB_SCHEMA and
         doc['source_type'] == 'VERIFIED_HISTORICAL_R58Y_SQLITE' and
         doc['service_count'] == 3 and doc['stage_count'] == 10 and
         doc['a5_operational_starts'] == 0 and
         doc['a6_accredited_conditions'] == 0 and
         doc['a7_confirmed_rf'] is None and
         doc['a9_published_generation'] is None and
         doc['technical_truth_accredited'] is False and
         doc['operational_dispatch'] is False and
         doc['p8_operational'] == 'NO-GO' and
         doc['publication_type'] == 'READONLY_OBSERVATION_SNAPSHOT_NOT_A9',
         'workspace_authority_escalation')
    groups = doc['services']
    need(type(groups) is list and len(groups) == 3 and
         [g.get('service') for g in groups if type(g) is dict] == list(SERVICES),
         'service_order_invalid')
    total = 0
    all_ids = set()
    for group in groups:
        observations = group.get('observations')
        stages = group.get('stages')
        need(type(observations) is list and
             type(group.get('observation_count')) is int and
             group['observation_count'] == len(observations) and
             type(stages) is list and stages == _stage_rows(group['service'],len(observations)),
             'stage_or_count_invalid')
        need(group['service'] != 'SSH' or len(observations) <= r58y.MAX_ROWS,
             'observation_overflow')
        # R58-Y actualmente admite recibos SOLO de SSH.
        need(group['service'] == 'SSH' or not observations, 'invented_ftp_smb_observation')
        for obs in observations:
            need(type(obs) is dict and set(obs) == {
                'record_id', 'captured_at_utc', 'source_r422_sha256',
                'source_r423_sha256', 'route', 'arp', 'tx_packets', 'rx_packets',
                'origin', 'a6_classification', 'a5_attempt_id'}, 'observation_schema_invalid')
            need(type(obs['record_id']) is str and
                 re.fullmatch(r'OBS_SSH_[0-9a-f]{64}', obs['record_id']) is not None and
                 obs['record_id'] not in all_ids and
                 obs['source_r422_sha256'] == r58y.r424.R422_PIN and
                 obs['source_r423_sha256'] == r58y.r424.R423_PIN and
                 obs['route'] == 'DIRECT_ENS3_EXPECTED' and
                 obs['arp'] in ('ABSENT', 'INCOMPLETE', 'RESOLVED') and
                 all(type(obs[n]) is int and 0 <= obs[n] <= 2**64-1
                     for n in ('tx_packets', 'rx_packets')) and
                 obs['origin'] == 'REAL_READONLY_SSH_SNAPSHOT' and
                 obs['a6_classification'] == 'ND' and obs['a5_attempt_id'] is None and
                 type(obs['captured_at_utc']) is dict and
                 set(obs['captured_at_utc']) == {'r422', 'r423'} and
                 all(type(v) is str and len(v) <= 40
                     for v in obs['captured_at_utc'].values()), 'observation_provenance_invalid')
            all_ids.add(obs['record_id'])
        total += len(observations)
    need(total == doc['total_observations'], 'workspace_count_mismatch')
    return True


def from_database(db: Path) -> dict[str, Any]:
    """Ejecuta revalidación de fuentes REAL R42.2/R42.3 en cada lectura."""
    return build_workspace(r58y.load_records(db, revalidate_sources=True))


def _filename(doc: dict[str, Any]) -> str:
    verify_workspace(doc)
    return 'r58z-observation-' + doc['sha256'] + '.json'


def persist_snapshot(directory: Path, doc: dict[str, Any]) -> tuple[str, Path]:
    """Publica solo un testigo DOCUMENTAL, nunca la generación A9 de la tesis."""
    verify_workspace(doc)
    need(isinstance(directory, Path) and directory.is_absolute() and directory.is_dir(),
         'private_snapshot_directory_missing')
    need(not any(x.is_symlink() for x in (directory, *directory.parents)),
         'snapshot_directory_symlink')
    need((directory.stat().st_mode & 0o077) == 0, 'snapshot_directory_permissions')
    path = directory / _filename(doc)
    raw = canon(doc) + b'\n'
    need(len(raw) < MAX_BYTES, 'snapshot_oversized')
    if path.exists() or path.is_symlink():
        need(read_snapshot(path) == doc, 'snapshot_conflict')
        return 'REPLAY_IDENTICAL', path
    fd = None
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            fd = None
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        need(read_snapshot(path) == doc, 'write_readback_mismatch')
        return 'CREATED_DOCUMENTARY_ONLY', path
    except FileExistsError:
        need(read_snapshot(path) == doc, 'snapshot_race_conflict')
        return 'REPLAY_IDENTICAL', path
    finally:
        if fd is not None:
            os.close(fd)


def read_snapshot(path: Path) -> dict[str, Any]:
    _sane_private_path(path, existing=True)
    need(path.stat().st_size <= MAX_BYTES, 'snapshot_bytes_excess')
    with path.open('rb') as source:
        raw = source.read(MAX_BYTES + 1)
    need(raw.endswith(b'\n') and len(raw) <= MAX_BYTES, 'snapshot_format')
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise WorkspaceError('snapshot_json_invalid') from exc
    verify_workspace(doc)
    need(raw == canon(doc) + b'\n' and path.name == _filename(doc),
         'snapshot_bytes_or_filename_mismatch')
    return doc


def verify_saved_against_sources(path: Path, db: Path) -> dict[str, Any]:
    saved = read_snapshot(path)
    current = from_database(db)
    need(saved == current, 'verified_source_changed_since_snapshot')
    return saved


def view_lines(doc: dict[str, Any], service_index: int = 0,
               stage_index: int = 9) -> list[str]:
    verify_workspace(doc)
    need(type(service_index) is int and 0 <= service_index < 3 and
         type(stage_index) is int and 0 <= stage_index < 10, 'selection_out_of_range')
    item = doc['services'][service_index]
    stage = item['stages'][stage_index]
    lines = [
        'ARDREC / SESION DE OBSERVACIONES RECUPERABLES / R58-Z',
        'P8:NO-GO | A6:ND | A7:Rf SIN CONFIRMAR | A9:NO PUBLICADA',
        'SERVICIO: ' + item['service'],
        'OBSERVACIONES HISTORICAS VERIFICADAS: ' + str(item['observation_count']),
        'ETAPA: ' + stage['algorithm'] + '  ESTADO: ' + stage['status'],
        'DETALLE: ' + stage['detail'],
        'SHA256 SESION DOCUMENTAL: ' + doc['sha256'],
    ]
    for obs in item['observations']:
        lines.extend([
            'OBSERVACION: ' + obs['record_id'],
            'CAPTURA SSH R42.2: ' + obs['captured_at_utc']['r422'],
            'CAPTURA SSH R42.3: ' + obs['captured_at_utc']['r423'],
            'R422_SHA: ' + obs['source_r422_sha256'],
            'R423_SHA: ' + obs['source_r423_sha256'],
            'RUTA: ' + obs['route'] + ' ARP: ' + obs['arp'],
            'TX: ' + str(obs['tx_packets']) + ' RX: ' + str(obs['rx_packets']),
        ])
    lines.extend(['', 'ALGORITMOS A1-A10'])
    for row in item['stages']:
        lines.append(row['algorithm'] + ' ' + row['status'])
    lines += ['', 'NO es evidencia A6 ni generacion A9; no se ejecuta VM.']
    return lines


def frame(doc: dict[str, Any], service_index: int = 0,
          stage_index: int = 9, width: int = 110, height: int = 31,
          offset: int = 0) -> list[str]:
    need(type(width) is int and 70 <= width <= 240 and
         type(height) is int and 16 <= height <= 120 and
         type(offset) is int and offset >= 0, 'frame_size_invalid')
    detail = view_lines(doc, service_index, stage_index)
    nav = [f"{'>' if i == stage_index else ' '} {row['algorithm']:<3} {row['status']:<20}"
           for i, row in enumerate(doc['services'][service_index]['stages'])]
    fit = lambda text,n: ''.join(ch if ch.isprintable() else ' ' for ch in text)[:n].ljust(n)
    nw = 31
    out = [fit('ARDREC R58-Z / SERVICIO ' + SERVICES[service_index], width),
           fit('P8:NO-GO  A6:ND  A9:NINGUNA  DOCUMENTAL:SI', width), '-' * width]
    for i in range(height-5):
        a = nav[i] if i < len(nav) else ''
        b = detail[offset+i] if offset+i < len(detail) else ''
        out.append('| ' + fit(a, nw-3) + ' | ' + fit(b, width-nw-2))
    out.extend([fit('1 SSH / 2 FTPS / 3 SMB | 0..9 etapa | j/k recorrer | flechas scroll | q salir', width),
                fit('SIN INICIO A5  |  SIN ACLARACION TECNICA A6  |  SIN Rf  |  SIN A9', width)])
    need(len(out) == height and all(len(s) == width for s in out), 'frame_inconsistent')
    return out


def run_tui(doc: dict[str, Any]) -> None:
    verify_workspace(doc)
    import curses
    import sys
    need(sys.stdin.isatty() and sys.stdout.isatty(), 'tui_requires_real_terminal')
    def app(screen: Any) -> None:
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.keypad(True)
        service, stage, offset = 0, 9, 0
        while True:
            screen.erase()
            h, w = screen.getmaxyx()
            if w < 71 or h < 16:
                screen.addnstr(0, 0, 'Minimo 71x16; q salir', max(1,w-1))
            else:
                for i, line in enumerate(frame(doc,service,stage,min(240,w-1),min(h,120),offset)):
                    try:
                        screen.addnstr(i,0,line,max(1,w-1))
                    except curses.error:
                        pass
            screen.refresh()
            key=screen.getch()
            if key in (ord('q'),ord('Q'),27): return
            if key in (ord('1'),ord('2'),ord('3')):
                service=key-ord('1'); offset=0
            elif key in (ord('j'),ord('k')):
                stage=(stage+(1 if key==ord('j') else -1))%10;offset=0
            elif key in (ord('0'),ord('4'),ord('5'),ord('6'),ord('7'),ord('8'),ord('9')):
                # '0' = A10, 4..9 directos; 1-3 reservados para servicios.
                stage=9 if key==ord('0') else key-ord('1');offset=0
            elif key==curses.KEY_DOWN: offset=min(len(view_lines(doc,service,stage))-1,offset+1)
            elif key==curses.KEY_UP: offset=max(0,offset-1)
    curses.wrapper(app)
