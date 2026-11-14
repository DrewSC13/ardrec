"""R36.2: evidence-bound monitoring dashboard; no VM access or network dispatch.

Three independent sources, deliberately NOT merged into purported pen-test results:
  - R35 physically verified completion (immutable host receipt)
  - R36.0 read-only libvirt/nft snapshot (real host observation)
  - R36.1 A1-A10 development report (synthetic scenario, explicitly labelled)

Live CPU/RAM observations use /proc on the machine running the viewer. No
subprocess, sudo, virsh, nft, ip, sockets, writes, or background work here.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import textwrap
from typing import Any

R36_SCHEMA = 'ardrec-r36-readonly-snapshot-v1'
DASH_SCHEMA = 'ardrec-p14-r362-observability-dashboard-v1'
R35_MAIN = 'b9af5eb0669d19881b18cb78dee7878858fcb753'
STAGES = tuple('A' + str(i) for i in range(1, 11))
ROLES = ('ssh', 'ftp', 'smb', 'runner')
NETWORK_ROLES = ('ssh', 'ftp', 'smb')
STAGE_NAMES = (
    'Reglas deterministas',
    'Inicializacion del riesgo',
    'Evaluacion de guardas',
    'Seleccion del siguiente caso',
    'Registro de intento',
    'Clasificacion de evidencia',
    'Recalibracion de riesgo',
    'Decision de continuidad',
    'Persistencia y trazabilidad',
    'Coordinacion y salida',
)
STAGE_PROCESS = (
    'Evalua hechos trivalentes (VERDADERO, FALSO, ND) y el orden de reglas.',
    'Construye PREPARADO, R0, criticidad y catalogo de casos aplicables.',
    'Resuelve condiciones y bloqueos antes de habilitar ejecucion.',
    'Distingue seleccion efectiva de una proyeccion hipotetica.',
    'Exige autoridad y registra intentos; el escenario actual no usa VM.',
    'Separa resultados y evidencia acreditada; ND no es prueba de ausencia.',
    'Calcula un oraculo racional hipotetico; Rf real queda indeterminado.',
    'Aplica criterio conservador: no avanzar sin evidencia y permiso.',
    'Vincula huellas y recibos; no publica una generacion operacional.',
    'Presenta el estado conjunto con su procedencia y restricciones.',
)
EXPECTED_R36_FILES = frozenset({
    'r36_snapshot.json', 'nft_guard.json', 'nwfilter.xml',
    'networks.txt', 'domains.txt', 'networks_active.txt',
    'domains_active.txt', 'interfaces.json',
    *(f'network_{r}.xml' for r in NETWORK_ROLES),
    *(f'network_{r}_info.txt' for r in NETWORK_ROLES),
    *(f'domain_{r}.xml' for r in ROLES),
    *(f'domain_{r}_state.txt' for r in ROLES),
    *(f'domain_{r}_info.txt' for r in ROLES),
})
EXPECTED_R361_FILES = frozenset({'tests.log', 'a1_a10.json', 'a1_a10.txt'})
EXPECTED_R35_FILES = frozenset({
    'commands.jsonl', 'r35_deployment.json', 'r35_host_preflight.json',
    'r35_source_attestation.json', 'r35_resume_attestation.json',
    'r35_recovery3_attestation.json', 'r35_recovery4_attestation.json',
})
HEX = re.compile(r'[0-9a-f]{64}\Z')


class DashboardError(ValueError):
    """Untrusted source, inconsistent observation or invalid attribution."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise DashboardError(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for k, v in pairs:
        require(k not in result, 'duplicate_json_key')
        result[k] = v
    return result


def _read_json(raw: bytes) -> dict[str, Any]:
    require(len(raw) < 262144, 'json_size_limit')
    try:
        result = json.loads(raw, object_pairs_hook=_unique_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                DashboardError('nonfinite_json')))
    except (ValueError, UnicodeError, TypeError) as exc:
        raise DashboardError('json_invalid') from exc
    require(type(result) is dict, 'json_object_required')
    return result


def verified_directory(directory: Path, expected: frozenset[str]) -> dict[str, bytes]:
    """Verify private, exact SHA256SUMS inventory; never follow any source symlink."""
    require(isinstance(directory, Path) and directory.is_absolute(), 'directory_not_absolute')
    require(not any(path.is_symlink() for path in (directory, *directory.parents)),
            'source_symlink_forbidden')
    st = directory.stat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and
            stat.S_IMODE(st.st_mode) == 0o700, 'directory_not_private')
    names = {p.name for p in directory.iterdir()}
    require(names == set(expected) | {'SHA256SUMS'}, 'source_inventory_mismatch')
    manifest = directory / 'SHA256SUMS'
    require(not manifest.is_symlink() and manifest.is_file(), 'manifest_type_invalid')
    lines = manifest.read_text(encoding='ascii').splitlines()
    require(len(lines) == len(expected), 'manifest_length_invalid')
    inventory = {}
    for line in lines:
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
        require(match is not None, 'manifest_line_invalid')
        value, name = match.groups()
        require(name in expected and name not in inventory, 'manifest_member_invalid')
        inventory[name] = value
    require(set(inventory) == set(expected), 'manifest_members_missing')
    result = {}
    for name in sorted(expected):
        path = directory / name
        st = path.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
                st.st_uid == os.geteuid() and (stat.S_IMODE(st.st_mode) & 0o077) == 0 and
                st.st_size <= 2_000_000, 'source_file_mode_or_size_invalid_' + name)
        raw = path.read_bytes()
        require(sha(raw) == inventory[name], 'source_digest_mismatch_' + name)
        result[name] = raw
    return result


def _names(raw: bytes) -> set[str]:
    try:
        strings = raw.decode('utf-8').splitlines()
    except UnicodeError as exc:
        raise DashboardError('name_list_encoding_invalid') from exc
    require(len(strings) == len(set(strings)), 'duplicate_resource_name')
    return {x for x in strings if x}


def _snapshot_files_validate(raw: dict[str, bytes], snapshot: dict[str, Any]) -> None:
    # These imports are deliberately deferred: plain rendering and unit tests
    # require no libvirt and no external runtime dependencies.
    from ardrec.coordination import r33_offline_topology as t33
    from ardrec.coordination import r34_containment as t34
    from ardrec.coordination.r35_inactive_deployment import (
        _verify_nft_json, _network_bridge_mac, _verify_domain_dump,
        _verify_inactive_info, _verify_domain_autostart,
        _verify_network_mac_inventory, R354_EXISTING_BRIDGE_MACS,
        NETWORKS, DOMAINS, TAPS, BRIDGES,
    )

    require(snapshot.get('schema') == R36_SCHEMA and
            snapshot.get('main') == R35_MAIN and
            snapshot.get('nft_verified') is True and
            snapshot.get('nwfilter_verified') is True and
            snapshot.get('networks_inactive') == list(NETWORKS) and
            snapshot.get('domains_shut_off') == list(DOMAINS) and
            snapshot.get('reserved_interfaces_absent') is True and
            snapshot.get('physical_activation') is False and
            snapshot.get('experimental_validation') == 'NOT_RUN' and
            snapshot.get('p8_operational') == 'NO-GO', 'r36_snapshot_semantics_invalid')
    expected = t33.render_xml(t33.R32_RECEIPT_FILE_SHA256)
    _verify_nft_json(raw['nft_guard.json'])
    t34.verify_filter(raw['nwfilter.xml'])
    macs = {}
    for role in NETWORK_ROLES:
        macs[role] = _network_bridge_mac(raw[f'network_{role}.xml'],
                                          expected[f'network-{role}.xml'], role)
        _verify_inactive_info(raw[f'network_{role}_info.txt'], kind='network')
    _verify_network_mac_inventory(macs, prior_ssh=True)
    require(macs == R354_EXISTING_BRIDGE_MACS, 'bridge_mac_drift')
    for role in ROLES:
        _verify_domain_dump(raw[f'domain_{role}.xml'],
                            expected[f'domain-{role}.xml'], role)
        _verify_inactive_info(raw[f'domain_{role}_state.txt'], kind='domain')
        _verify_domain_autostart(raw[f'domain_{role}_info.txt'])
    require(set(NETWORKS) <= _names(raw['networks.txt']) and
            set(DOMAINS) <= _names(raw['domains.txt']) and
            not (set(NETWORKS) & _names(raw['networks_active.txt'])) and
            not (set(DOMAINS) & _names(raw['domains_active.txt'])),
            'active_resources_or_inventory_mismatch')
    interfaces = _read_json(b'{"rows":' + raw['interfaces.json'] + b'}')['rows']
    require(type(interfaces) is list and
            all(type(x) is dict and type(x.get('ifname')) is str for x in interfaces),
            'interfaces_json_invalid')
    require(not ({x['ifname'] for x in interfaces} & (set(TAPS) | set(BRIDGES))),
            'reserved_interfaces_present')


def load_sources(*, r35_dir: Path, r36_dir: Path, r361_dir: Path) -> dict[str, Any]:
    """Read actual saved observations, maintaining their separate epistemic status."""
    from ardrec.coordination.r35_inactive_deployment import (
        verify_deployment_report, verify_host_report,
    )
    from ardrec.coordination.development_cycle import verify_development_cycle

    r35 = verified_directory(r35_dir, EXPECTED_R35_FILES)
    r36 = verified_directory(r36_dir, EXPECTED_R36_FILES)
    r361 = verified_directory(r361_dir, EXPECTED_R361_FILES)
    deployment = _read_json(r35['r35_deployment.json'])
    preflight = _read_json(r35['r35_host_preflight.json'])
    verify_deployment_report(deployment)
    verify_host_report(preflight)
    require(deployment['status'] == 'DEPLOYMENT_COMPLETE_INACTIVE' and
            deployment['failure_code'] is None and
            deployment['host_preflight_sha256'] == preflight['sha256'] and
            deployment['p8_operational'] == 'NO-GO', 'r35_not_completed_inactive')
    snapshot = _read_json(r36['r36_snapshot.json'])
    require(snapshot.get('source_r35_report_sha256') == deployment['sha256'],
            'r36_not_bound_to_r35')
    _snapshot_files_validate(r36, snapshot)
    report = _read_json(r361['a1_a10.json'])
    verify_development_cycle(report)
    require(report['source_kind'] == 'SYNTHETIC_FIXTURE_ONLY' and
            report['vm_checks_executed'] is False and
            report['operational_dispatch'] is False and
            report['final_risk'] is None and
            report['p8_operational'] == 'NO-GO' and
            [row['algorithm'] for row in report['a10']['stages']] == list(STAGES),
            'r361_misattributed_experiment')
    return make_view(snapshot=snapshot, report=report,
                     r35_sha=sha(r35['r35_deployment.json']),
                     r36_sha=sha(r36['r36_snapshot.json']),
                     r361_sha=sha(r361['a1_a10.json']),
                     r36_mtime=r36_dir.joinpath('r36_snapshot.json').stat().st_mtime)


def make_view(*, snapshot: dict[str, Any], report: dict[str, Any],
              r35_sha: str, r36_sha: str, r361_sha: str,
              r36_mtime: float | None = None) -> dict[str, Any]:
    """Pure presentation model. It never promotes host inventory to a pen-test result."""
    require(snapshot.get('schema') == R36_SCHEMA and
            snapshot.get('p8_operational') == 'NO-GO' and
            snapshot.get('physical_activation') is False and
            snapshot.get('networks_inactive') == [f'ardrec-r33-dev-net-{r}' for r in NETWORK_ROLES] and
            snapshot.get('domains_shut_off') == [f'ardrec-r33-dev-{r}' for r in ROLES],
            'view_snapshot_invalid')
    require(report.get('source_kind') == 'SYNTHETIC_FIXTURE_ONLY' and
            report.get('vm_checks_executed') is False and
            report.get('operational_dispatch') is False and
            report.get('p8_operational') == 'NO-GO' and
            [x['algorithm'] for x in report['a10']['stages']] == list(STAGES),
            'view_report_invalid')
    require(all(type(x) is str and HEX.fullmatch(x) for x in
                (r35_sha, r36_sha, r361_sha)), 'view_source_hash_invalid')
    result = {
        'schema': DASH_SCHEMA,
        'source_kind': 'REAL_HOST_SNAPSHOT_PLUS_SYNTHETIC_ALGORITHMIC_PREVIEW',
        'host_evidence': {
            'kind': 'REAL_READONLY_SNAPSHOT', 'r35_file_sha256': r35_sha,
            'r36_file_sha256': r36_sha,
            'networks_inactive': list(snapshot['networks_inactive']),
            'domains_shut_off': list(snapshot['domains_shut_off']),
            'nft_verified': snapshot['nft_verified'],
            'nwfilter_verified': snapshot['nwfilter_verified'],
            'interfaces_absent': snapshot['reserved_interfaces_absent'],
            'snapshot_file_mtime_utc': (datetime.fromtimestamp(r36_mtime, tz=timezone.utc)
                                        .strftime('%Y-%m-%d %H:%M UTC') if r36_mtime is not None else 'ND'),
        },
        'algorithm_evidence': {
            'kind': 'SYNTHETIC_PREVIEW_ONLY', 'r361_file_sha256': r361_sha,
            'session_id': report['session_id'],
            'states': [{'algorithm': x['algorithm'], 'source': x['source'],
                        'status': x['status']} for x in report['a10']['stages']],
        },
        'laboratory_pentesting': 'NOT_EXECUTED',
        'real_algorithmic_evidence': 'NOT_ACCREDITED',
        'final_risk': None,
        'p8_operational': 'NO-GO',
        'viewer_host_mutations': False,
        'viewer_network_calls': False,
        '_report': report,
    }
    return result


def _wrap(label: str, value: Any, width: int) -> list[str]:
    prefix = label + ': '
    return textwrap.wrap(prefix + str(value), width=max(36, width),
                         subsequent_indent=' ' * len(prefix),
                         break_long_words=False, break_on_hyphens=False) or [prefix]


def stage_detail(view: dict[str, Any], index: int, width: int = 78) -> list[str]:
    require(type(index) is int and 0 <= index < 10, 'invalid_stage_index')
    report = view['_report']
    stage = report['a10']['stages'][index]
    out = [f'{stage["algorithm"]}  {STAGE_NAMES[index]}',
           'ESTADO: ' + stage['status'],
           'ORIGEN: ' + stage['source'],
           'TIPO: DESARROLLO / NO ES PENTESTING',
           '', 'QUE HACE:', *textwrap.wrap(STAGE_PROCESS[index], width=max(36,width)),
           '', 'SALIDA DE LA SESION:']
    out.extend(textwrap.wrap(stage['detail'], width=max(36,width)))
    out.append('')
    if index in (0, 1, 2):
        out.append('UNIDADES DE DESARROLLO (SINTETICAS):')
        for unit in report['r26_units']:
            out.extend(_wrap(unit['protocol'],
                  f'{unit["service_id"]}  A1={unit["a1"]}  A2={unit["a2"]}  A3={unit["a3"]}',width))
        if index == 1:
            for unit in report['r26_units']:
                out.append(f'R0  {unit["service_id"]} = {unit["initial_risk"]}')
    elif index == 3:
        out.extend(_wrap('SELECCION APLICADA', report['r27']['selected_actual'], width))
        out.extend(_wrap('PROYECCION (NO APLICADA)', report['r27']['selected_hypothetical'], width))
    elif index in (4, 5):
        out.extend(_wrap('ESTADO A5', report['r27']['a5_state'], width))
        out.extend(_wrap('CLASE A6', report['r27']['a6_classification'], width))
    elif index == 6:
        out.extend(_wrap('Rf HIPOTETICO', report['a7']['hypothetical_rf'], width))
        out.append('Rf OPERACIONAL: ND (NO ACREDITADO)')
    elif index == 7:
        out.extend(_wrap('RECOMENDACION', report['a8'].get('recommendation'), width))
        out.append('TRANSICION REAL: NO')
    elif index == 8:
        out.extend(_wrap('RECIBO DESARROLLO SHA', report['a9']['receipt_sha256'][:28] + '...', width))
        out.append('GENERACION OPERACIONAL PUBLICADA: NO')
    else:
        out.extend(_wrap('REPORTE SHA', report['sha256'][:28] + '...', width))
        out.append('TUI DE OBSERVABILIDAD: SIN DESPACHO')
    out.extend(['', 'VINCULO CON EL LABORATORIO REAL:',
        '3 REDES INACTIVAS / 4 VM APAGADAS / NFT+NWFILTER VERIFICADOS',
        'Estos datos reales son de infraestructura; NO son resultados del algoritmo.',
        'BLOQUEO: FALTAN ARRANQUE AISLADO, PRUEBAS AUTORIZADAS Y EVIDENCIA.'])
    return out


def text_report(view: dict[str, Any], width: int = 100) -> str:
    width = max(58, min(140, width))
    host = view['host_evidence']
    lines = [
        'ARDREC R36.2 | MONITOR REAL + ALGORITMOS DE DESARROLLO | P8 NO-GO',
        '=' * min(width, 94),
        'ORIGEN REAL: R35 COMPLETO + R36.0 SNAPSHOT LIBVIRT/NFT',
        'CAPTURA (mtime): ' + host['snapshot_file_mtime_utc'],
        'REDES REALES: SSH INACTIVA | FTP INACTIVA | SMB INACTIVA',
        'VM REALES: SSH APAGADA | FTP APAGADA | SMB APAGADA | RUNNER APAGADA',
        'NFT: VERIFICADO | NWFILTER: VERIFICADO | TAPS: AUSENTES',
        'A1-A10: ESCENARIO SINTETICO R36.1; NO PENTESTING REAL',
        'Rf real: ND | P8: NO-GO | Sin cambios fisicos',
    ]
    for i in range(10):
        lines.extend(['', '-' * min(width, 94),
                      *stage_detail(view, i, width=width)])
    return '\n'.join(lines) + '\n'


@dataclass(frozen=True)
class HostTelemetry:
    cpu: float | None
    ram: float | None
    total_mib: int | None
    load: tuple[float, float, float] | None
    ticks: tuple[int, int] | None

    @staticmethod
    def read(prior: 'HostTelemetry | None' = None) -> 'HostTelemetry':
        """Actual /proc host telemetry; no subprocess and no network calls."""
        cpu = None
        ticks = None
        ram = None
        total_mib = None
        try:
            raw = Path('/proc/stat').read_text(encoding='ascii').splitlines()[0].split()
            if raw[0] == 'cpu' and len(raw) >= 5:
                values = [int(x) for x in raw[1:]]
                idle = values[3] + (values[4] if len(values) > 4 else 0)
                ticks = (sum(values), idle)
                if prior and prior.ticks:
                    dt = ticks[0] - prior.ticks[0]
                    di = ticks[1] - prior.ticks[1]
                    if dt > 0:
                        cpu = max(0.0, min(100.0, 100 * (1 - di / dt)))
            mem = {}
            for line in Path('/proc/meminfo').read_text(encoding='ascii').splitlines():
                m = re.fullmatch(r'(MemTotal|MemAvailable):\s+(\d+) kB', line)
                if m:
                    mem[m.group(1)] = int(m.group(2))
            if 0 < mem.get('MemTotal', 0) and 'MemAvailable' in mem:
                total_mib = mem['MemTotal'] // 1024
                ram = max(0.0, min(100.0,
                          100 * (1 - mem['MemAvailable'] / mem['MemTotal'])))
        except (OSError, ValueError, IndexError, UnicodeError):
            pass
        try:
            load = tuple(os.getloadavg())
        except (OSError, AttributeError):
            load = None
        return HostTelemetry(cpu=cpu, ram=ram, total_mib=total_mib,
                             load=load, ticks=ticks)


def run_tui(view: dict[str, Any]) -> None:
    """Responsive ncurses screen; keyboard never invokes a host operation."""
    import curses
    import sys
    require(sys.stdin.isatty() and sys.stdout.isatty(), 'interactive_terminal_required')

    def loop(screen: Any) -> None:
        curses.noecho()
        screen.keypad(True)
        screen.timeout(1250)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        use_color = curses.has_colors()
        if use_color:
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
            palette = [(1, curses.COLOR_CYAN), (2, curses.COLOR_GREEN),
                       (3, curses.COLOR_YELLOW), (4, curses.COLOR_RED),
                       (5, curses.COLOR_MAGENTA), (6, curses.COLOR_WHITE)]
            for n, fg in palette:
                curses.init_pair(n, fg, -1)

        def style(number: int, bold: bool = False) -> int:
            attr = curses.color_pair(number) if use_color else 0
            return attr | (curses.A_BOLD if bold else 0)

        def put(y: int, x: int, string: str, kind: int = 6, bold: bool = False) -> None:
            if y < 0 or x < 0 or y >= height or x >= width:
                return
            try:
                screen.addnstr(y, x, string, max(0, width - x - 1), style(kind, bold))
            except curses.error:
                pass

        def section(y: int, x: int, label: str, w: int) -> None:
            put(y, x, (' ' + label + ' ').ljust(max(1, w - 1), '-'), 1, True)

        def meter(y: int, x: int, name: str, value: float | None, w: int) -> None:
            if w < 17:
                return
            barw = max(8, w - 14)
            ratio = 0 if value is None else max(0, min(1, value / 100))
            fill = int(round(ratio * barw))
            bar = '[' + ('|' * fill) + (' ' * (barw - fill)) + ']'
            put(y, x, f'{name} ', 1, True)
            put(y, x + 5, bar, 2 if ratio < 0.8 else 3)
            put(y, x + 7 + barw, f'{value:4.0f}%' if value is not None else ' ND', 6)

        selected = 0
        offset = 0
        help_mode = False
        telemetry: HostTelemetry | None = None
        while True:
            telemetry = HostTelemetry.read(telemetry)
            height, width = screen.getmaxyx()
            screen.erase()
            if width < 76 or height < 20:
                put(0, 0, 'ARDREC R36.2 | ampliar ventana a 76x20', 3, True)
                put(2, 0, 'q salir | 1-9/0 seleccionar algoritmo', 6)
                screen.refresh()
            else:
                put(0, 0, ' ARDREC | OBSERVABILIDAD R36.2 ', 1, True)
                put(0, 37, '[R36 HOST REAL]', 2, True)
                put(0, 57, '[A1-A10 DEV]', 3, True)
                put(1, 0, ('=' * (width - 1)), 1)
                put(2, 1, 'Prometheus / SO REAL (en vivo, solo lectura)', 6)
                barw = min(42, max(28, width // 2 - 22))
                meter(3, 1, 'CPU', telemetry.cpu, barw)
                meter(4, 1, 'RAM', telemetry.ram, barw)
                loads = telemetry.load or (0, 0, 0)
                put(3, width // 2, f'LOAD: {loads[0]:.2f} / {loads[1]:.2f} / {loads[2]:.2f}', 6)
                put(4, width // 2, 'MEM TOTAL: ' + (str(telemetry.total_mib) + ' MiB'
                                           if telemetry.total_mib is not None else 'ND'), 6)
                put(5, 1, 'R35: INACTIVO VERIFICADO | nft: PASS | nwfilter: DROP ALL', 2, True)
                put(6, 1, 'P8: NO-GO | Pruebas reales de servicios: NO EJECUTADAS', 3, True)
                put(7, 0, '-' * (width - 1), 1)

                left = min(40, max(30, width // 3))
                pane_width = width - left - 4
                section(8, 1, 'LABORATORIO REAL / R36 SNAPSHOT', left - 1)
                for i, role in enumerate(ROLES):
                    put(9 + i, 2, f'{role.upper():<7} VM   APAGADA', 2)
                for i, role in enumerate(NETWORK_ROLES):
                    put(13 + i, 2, f'{role.upper():<7} RED  INACTIVA', 2)
                section(17, 1, 'A1-A10  /  ESCENARIO DEV', left - 1)
                menu_y = 18
                for i, stage in enumerate(view['algorithm_evidence']['states']):
                    y = menu_y + i
                    if y >= height - 2:
                        break
                    selected_mark = '>' if i == selected else ' '
                    label = f'{selected_mark} {i+1:02d} {stage["algorithm"]} {STAGE_NAMES[i]}'
                    put(y, 2, label[:left - 4], 1 if i == selected else 6, i == selected)
                detail_x = left + 1
                section(8, detail_x, 'TRAZA Y GUARDAS / ALGORITMO ' + STAGES[selected], pane_width)
                details = stage_detail(view, selected, width=pane_width - 2)
                available = max(0, height - 12)
                offset = min(offset, max(0, len(details) - available))
                for n, row in enumerate(details[offset:offset+available]):
                    color = (3 if row.startswith(('ORIGEN:', 'TIPO:', 'BLOQUEO:')) else
                             2 if row.startswith(('ESTADO:', '3 REDES')) else 6)
                    put(9 + n, detail_x + 1, row[:pane_width - 2], color,
                        row.startswith(('ESTADO:', 'BLOQUEO:')))
                put(height - 2, 0, '-' * (width - 1), 1)
                footer = ('[1-9,0] algoritmo  [< > / h l] navegar  [Up/Down] desplazar'
                          '  [?] ayuda  [q] salir')
                if help_mode:
                    footer = 'SIN RED / SIN SUDO / SIN INICIO / SIN DESPACHO; r refresca vista, q sale'
                put(height - 1, 1, footer, 3)
                screen.refresh()
            key = screen.getch()
            if key in (ord('q'), ord('Q'), 27):
                break
            if key in (ord('r'), ord('R')):
                continue
            if key == ord('?'):
                help_mode = not help_mode
                continue
            if key in (ord('l'), ord('n'), curses.KEY_RIGHT):
                selected = (selected + 1) % 10
                offset = 0
            elif key in (ord('h'), ord('p'), curses.KEY_LEFT):
                selected = (selected - 1) % 10
                offset = 0
            elif key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                offset += 1 if key == curses.KEY_DOWN else 6
            elif key in (curses.KEY_UP, curses.KEY_PPAGE):
                offset = max(0, offset - (1 if key == curses.KEY_UP else 6))
            elif ord('1') <= key <= ord('9'):
                selected = key - ord('1')
                offset = 0
            elif key == ord('0'):
                selected = 9
                offset = 0

    curses.wrapper(loop)
