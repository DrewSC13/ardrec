"""R69: sesión DEV A2 -> A9(inicialización durable) -> A1 R68 -> recuperación.

Los tres servicios proceden de la fixture sintética R26. No despacha pruebas
físicas, no publica una generación analítica y no acredita Rf ni P8.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import stat
import uuid
from typing import Any

from ardrec.coordination.demo_session import (
    normalize_scenario, prepare_frozen_development_sources,
)
from ardrec.persistence import DurableStore
from ardrec.persistence.codec import canonical, digest, pack, parse
from ardrec.rules.complete_a1 import evaluate_complete_a1
from ardrec.rules.global_binding import evaluate_global_a1
from ardrec.state import ConfirmedState, GlobalState, ServicePhase, ServiceState, Truth

SCHEMA = 'ardrec-p14-r69-a2-a1-a9-dev-session-v1'
CONFIG_SCHEMA = 'ardrec-p14-r69-frozen-dev-configuration-v1'
MAX_FILE = 1_048_576


class DurableDevError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(condition: bool, code: str):
    if not condition:
        raise DurableDevError(code)


def _private_root(root: Path) -> None:
    _need(isinstance(root, Path) and root.is_absolute() and '..' not in root.parts,
          'root_must_be_absolute')
    # Rechazar redirecciones por symlinks en los padres; nunca operar como root.
    _need(os.geteuid() != 0, 'root_user_forbidden')
    for component in (root, *root.parents):
        if component.exists() or component.is_symlink():
            _need(not component.is_symlink(), 'symlink_in_path')
    if not root.exists():
        _need(root.parent.is_dir(), 'parent_missing')
        root.mkdir(mode=0o700)
    st = root.lstat()
    _need(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()
          and stat.S_IMODE(st.st_mode) & 0o077 == 0,
          'root_not_private')


def _read_private(root: Path, name: str) -> bytes | None:
    _need('/' not in name and name not in ('', '.', '..'), 'invalid_filename')
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=root_fd)
        except FileNotFoundError:
            return None
        try:
            st = os.fstat(fd)
            _need(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid()
                  and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) & 0o077 == 0
                  and st.st_size <= MAX_FILE, 'private_file_invalid')
            with os.fdopen(os.dup(fd), 'rb') as reader:
                raw = reader.read(MAX_FILE + 1)
            _need(len(raw) == st.st_size, 'private_file_changed')
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)


def _write_once(root: Path, name: str, raw: bytes) -> None:
    """Archivo derivado, inmutable por contenido y duradero antes de confirmar."""
    existing = _read_private(root, name)
    if existing is not None:
        _need(existing == raw, 'existing_receipt_mismatch')
        return
    _need(type(raw) is bytes and len(raw) <= MAX_FILE, 'receipt_too_large')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temp = '.pending-r69-' + uuid.uuid4().hex
    try:
        fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(os.dup(fd), 'wb', buffering=0) as writer:
                writer.write(raw)
                writer.flush()
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            # No sustituir un recibo existente; proteger frente a dobles escritores.
            os.link(temp, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        except FileExistsError:
            _need(_read_private(root, name) == raw, 'existing_receipt_mismatch')
        os.fsync(directory)
    finally:
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _frozen_configuration(fixture: dict[str, Any], sources) -> bytes:
    rules, initial, deps, controls, integrated, _ = sources
    document = {
        'schema': CONFIG_SCHEMA,
        'source_kind': 'SYNTHETIC_FIXTURE',
        'fixture': fixture,
        'rules': parse(rules.source),
        'initial': parse(initial.source),
        'dependencies': parse(deps.source),
        'controls': parse(controls.source),
        'integrated': parse(integrated.source),
        'sha256_sources': {
            'rules': rules.sha256, 'initial': initial.sha256,
            'dependencies': deps.sha256, 'controls': controls.sha256,
            'integrated': integrated.sha256,
        },
    }
    return canonical(document)


def _decision_for_service(rules, state: GlobalState, service: dict[str, Any]):
    sid = service['id']
    global_raw = canonical(pack(state))
    confirmed_raw = canonical(pack(state.confirmed))
    gp, cp = digest(global_raw), digest(confirmed_raw)
    environment = ({} if service['fact'] == 'AUSENTE' else
                   {'FACT': Truth[service['fact']]})
    case_id, condition_id, context_id = 'CASE_POLICY', 'COND_' + sid, 'CTX_' + sid
    a1 = evaluate_complete_a1(
        rules, global_raw, gp, confirmed_raw, cp, sid, environment,
        case_id=case_id, condition_id=condition_id, context_id=context_id)
    a1.verify(rules, global_raw, gp, confirmed_raw, cp, sid, environment,
              case_id=case_id, condition_id=condition_id, context_id=context_id)
    bound = evaluate_global_a1(
        rules, global_raw, gp, confirmed_raw, cp, sid, environment,
        case_id=case_id, condition_id=condition_id, context_id=context_id)
    bind_doc = parse(bound.json_bytes())
    contextual = bind_doc['a1_recovered_receipt']['confirmed_model_receipt']['a1_contextual']
    _need(contextual['regla_seleccionada'] == parse(a1.json_bytes())['selected_rule'],
          'a1_decision_disagreement')
    return {'r68_sha256': a1.sha256, 'r68': parse(a1.json_bytes()),
            'seven_field_context': {k: contextual[k] for k in (
                'estado', 'configuracion', 'origen', 'servicio', 'caso',
                'condicion', 'contexto')},
            'rule_evaluations': contextual['evaluaciones']}


def _build_document(store: DurableStore, fixture, sources, configuration_sha256):
    rules = sources[0]
    state = store.state
    _need(state.confirmed.configuration_sha256 == configuration_sha256,
          'confirmed_config_drift')
    _need(state.confirmed.record_id == fixture['session_id'], 'record_drift')
    _need(state.confirmed.generation == 0 and not state.attempts,
          'noninitial_state_not_supported')
    _need(state.confirmed.services == state.services and not state.confirmed.incorporated_events,
          'candidate_or_events_present')
    _need(all(s.phase is ServicePhase.PREPARADO for s in state.services),
          'unexpected_service_phase')
    _need(store.recovery_action == 'NONE' and store.temporal_status == 'PASS',
          'recovery_not_clean')
    head_hash = store.head_sha256
    doc = {
        'schema': SCHEMA,
        'scope': 'DEV_SYNTHETIC_DURABLE_INITIAL_GENERATION',
        'source_kind': 'SYNTHETIC_FIXTURE',
        'record_id': state.confirmed.record_id,
        'execution_id': state.execution_id,
        'configuration_sha256': configuration_sha256,
        'rules_sha256': rules.sha256,
        'integrated_sha256': sources[4].sha256,
        'generation': 0,
        'generation_reference': state.confirmed.generation_reference,
        'a9_initialization_durable': True,
        'a9_subsequent_publication_attested': False,
        'store_head_sha256': head_hash,
        'store_recovery_action': store.recovery_action,
        'a1_decisions': {s['id']: _decision_for_service(rules, state, s)
                         for s in fixture['services']},
        'external_pin_authority_attested': False,
        'physical_observation_attested': False,
        'a5_dispatch_performed': False,
        'a7_confirmed_rf': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }
    doc['sha256'] = digest(canonical(doc))
    return doc


def open_or_create_dev(root: Path, candidate: dict[str, Any], *,
                       expected_config_sha256: str | None = None,
                       expected_head_sha256: str | None = None) -> dict[str, Any]:
    """Crea o recupera sin sobrescribir una sesión y reproduce A1 en A9 gen=0.

    El hash esperado de CLI, cuando existe, actúa como pin externo al archivo;
    sin él NO se atribuye confianza externa al contenido del almacén.
    """
    fixture = normalize_scenario(candidate)
    sources = prepare_frozen_development_sources(fixture)
    config_bytes = _frozen_configuration(fixture, sources)
    config_sha = digest(config_bytes)
    if expected_config_sha256 is not None:
        _need(type(expected_config_sha256) is str
              and expected_config_sha256 == config_sha, 'external_config_pin_mismatch')
    _private_root(root)
    existing = _read_private(root, 'configuration.json')
    store_path = root / 'generational-store'
    created_frozen = existing is None
    if existing is None:
        _need(not store_path.exists() and not store_path.is_symlink(),
              'configuration_missing_for_existing_store')
        _write_once(root, 'configuration.json', config_bytes)
    else:
        _need(existing == config_bytes and digest(existing) == config_sha,
              'frozen_configuration_mismatch')
    sid = fixture['session_id']
    if store_path.exists() or store_path.is_symlink():
        _need(store_path.is_dir() and not store_path.is_symlink(), 'store_path_invalid')
        store = DurableStore.open(store_path, record_id=sid,
                                  configuration_sha256=config_sha,
                                  expected_head=expected_head_sha256)
    else:
        _need(created_frozen, 'store_missing_with_frozen_configuration')
        _need(expected_head_sha256 is None, 'expected_head_missing')
        services = tuple(ServiceState(s['id'], ServicePhase.PREPARADO)
                         for s in fixture['services'])
        confirmed = ConfirmedState(sid, 0, 'GEN_' + sid + '_0', config_sha,
                                   'VERS_' + sid, services)
        state = GlobalState(confirmed, 'EXE_' + sid, services)
        store = DurableStore.create(store_path, state)
    with store:
        doc = _build_document(store, fixture, sources, config_sha)
    _write_once(root, 'a1-generation-0.json', canonical(doc))
    _need(_read_private(root, 'a1-generation-0.json') == canonical(doc),
          'decision_receipt_unreadable')
    return doc


def render_dev_text(doc: dict[str, Any]) -> str:
    lines = [
        'ARDREC R69 | Sesion DEV durable A2-A1-A9',
        f"Registro={doc['record_id']} | Generacion={doc['generation']} | origen=FICTICIO/DEV",
        f"Configuracion SHA256={doc['configuration_sha256']}",
        f"HEAD SHA256={doc['store_head_sha256']}",
        f"Almacen A9 inicializado={doc['a9_initialization_durable']} | P8={doc['p8_operational']}",
    ]
    for sid, details in doc['a1_decisions'].items():
        result = details['r68']
        lines.append(f"{sid}: {result['status']} | regla={result['selected_rule']} | "
                     f"salida={result['declared_output']} | SHA={details['r68_sha256']}")
    lines.append('Solo datos sinteticos. No hay intento fisico, Rf ni publicacion A9 posterior.')
    lines.append(f"Recibo R69 SHA256={doc['sha256']}")
    return '\n'.join(lines) + '\n'


def run_dev_tui(doc: dict[str, Any]) -> None:
    """Vista provisional DEV sin nueva dependencia; finaliza con Q sin salir de Zsh."""
    import curses

    def panel(scr):
        curses.curs_set(0)
        scr.keypad(True)
        while True:
            scr.erase()
            y, x = scr.getmaxyx()
            lines = render_dev_text(doc).splitlines()
            lines.insert(1, 'TUI DEV de solo lectura | q: volver a la terminal')
            for i, line in enumerate(lines[:max(0, y - 1)]):
                try:
                    scr.addnstr(i, 0, line, max(1, x - 1))
                except curses.error:
                    pass
            scr.refresh()
            if scr.getch() in (ord('q'), ord('Q'), 27):
                break
    curses.wrapper(panel)
