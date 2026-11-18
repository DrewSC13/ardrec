"""R88: único ciclo DEV ejecutable: R69 -> R70 -> R71 -> R38 con P8 Rust deny.

Usa los módulos de producción existentes, no simula evidencia técnica SSH.
Solo permite UN fixture benigno local (Python), nunca despacho a VMs.
La sonda Rust P8-R7 es una prueba independiente deny-only, NO el ejecutor A5.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any

from ardrec.benign_pipeline import BenignPipeline
from ardrec.coordination.benign_review import RID
from ardrec.coordination.demo_session import normalize_scenario
from ardrec.coordination.durable_dev import _private_root, _read_private, _write_once, open_or_create_dev
from ardrec.coordination.safe_generation import open_or_publish_safe
from ardrec.coordination.shadow_cycle import run_shadow_cycle, _separate_roots
from ardrec.coordination.shadow_dashboard_bridge import build_shadow_dashboard
from ardrec.coordination.dashboard_tui import validate_dashboard_report
from ardrec.p8_diagnostic import evaluate_bytes
from ardrec.persistence.codec import canonical, digest, parse

SCHEMA = 'ardrec-p14-r88-one-benign-vertical-with-rust-denial-v1'
FILE = 'r88-original-module-join.json'
DENIAL = 'P8_R7_UNVERIFIED_AUTHORITY'


class VerticalError(ValueError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise VerticalError(reason)


def rust_deny_probe(probe: Path, expected_sha256: str, fixture_json: Path) -> dict[str, str]:
    """Compara diagnóstico Rust real vs Python sobre una entrada segura.

    La comparación NO acredita autoridad de laboratorio ni identidad A2↔P8.
    El hash de binario es un pin local, NO testigo externo.
    """
    need(isinstance(probe, Path) and probe.is_absolute() and not probe.is_symlink(),
         'probe_path_invalid')
    need(isinstance(fixture_json, Path) and fixture_json.is_file() and
         not fixture_json.is_symlink(), 'probe_fixture_invalid')
    st = probe.stat()
    need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and bool(st.st_mode & 0o111),
         'probe_not_executable_regular_file')
    need(type(expected_sha256) is str and len(expected_sha256) == 64 and
         all(c in '0123456789abcdef' for c in expected_sha256), 'probe_pin_invalid')
    need(st.st_size <= 100_000_000, 'probe_size_exceeded')
    raw_binary = probe.read_bytes()
    need(len(raw_binary) == st.st_size and
         hashlib.sha256(raw_binary).hexdigest() == expected_sha256,
         'probe_binary_pin_mismatch')
    fixture = json.loads(fixture_json.read_bytes())
    need(fixture.get('schema_version') == '1.0' and fixture.get('contract') == 'P8-R7',
         'diagnostic_fixture_schema_invalid')
    cases = [x for x in fixture['cases'] if x.get('name') == 'valid_synthetic_denied']
    need(len(cases) == 1 and cases[0].get('reason_code') == DENIAL,
         'diagnostic_fixture_case_invalid')
    raw = cases[0]['payload'].encode('utf-8')
    expected = evaluate_bytes(raw)
    need(expected.get('reason_code') == DENIAL and
         expected.get('decision') == 'BLOCKED_UNBOUND_NO_EXECUTION' and
         expected.get('authorized') is False and
         expected.get('dispatch_allowed') is False, 'python_diagnostic_not_denied')
    proc = subprocess.run([str(probe)], input=raw, capture_output=True,
                          timeout=5, check=False, close_fds=True)
    need(proc.returncode == 0 and not proc.stderr and len(proc.stdout) <= 1024,
         'rust_probe_execution_failed')
    try:
        actual = json.loads(proc.stdout)
    except (ValueError, UnicodeError) as error:
        raise VerticalError('rust_probe_json_invalid') from error
    need(actual == expected, 'python_rust_deny_divergence')
    return {'probe_sha256': expected_sha256, 'reason_code': DENIAL,
            'dispatch_allowed': 'false', 'identity_relation': 'UNBOUND_DIAGNOSTIC'}


def _existing_review(root: Path, data: dict[str, Any]) -> None:
    """Verificación real de A5 durable SIN llamar execute/submit/accept."""
    pipeline = BenignPipeline(root)
    row = pipeline.read(RID)
    att = pipeline.verify(RID)
    need(row.get('fixture') == 'ok' and row.get('id') == RID and
         row.get('state') == 'RECORDED_LIMITED' and
         row.get('start_count') == 1 and row.get('p8_operational') == 'NO-GO' and
         row.get('result', {}).get('outcome') == 'BENIGN_EXIT_ZERO' and
         att.get('request_id') == RID and att.get('artifacts_verified') is True and
         att.get('p8_operational') == 'NO-GO' and
         att.get('event_head_sha256') == data['shadow']['a5_event_head_sha256'],
         'original_a5_journal_not_verified')


def _verify_document(raw: bytes) -> dict[str, Any]:
    doc = parse(raw)
    need(type(doc) is dict and doc.get('schema') == SCHEMA and
         doc.get('sha256') == digest(canonical({k: v for k, v in doc.items()
                                                  if k != 'sha256'})),
         'vertical_document_invalid')
    need(doc.get('p8_operational') == 'NO-GO' and
         doc.get('physical_executions') == 0 and
         doc.get('operational_dispatch') is False and
         doc.get('a6') == 'ND' and doc.get('rf_confirmed') is None and
         doc.get('system_acceptance') == 'PENDING' and
         doc.get('experimental_validation') == 'NOT_RUN' and
         doc.get('rust_probe', {}).get('reason_code') == DENIAL and
         doc.get('rust_probe', {}).get('dispatch_allowed') == 'false' and
         doc.get('rust_probe', {}).get('identity_relation') == 'UNBOUND_DIAGNOSTIC',
         'vertical_authority_claim_invalid')
    return doc


def verify_vertical(durable: Path, benign: Path, scenario: dict[str, Any],
                    probe: Path, probe_sha256: str, diagnostic_fixture: Path,
                    *, expected_sha256: str | None = None) -> dict[str, Any]:
    """Audita fuentes persistidas y R38 sin arrancar un proceso ni publicar."""
    _separate_roots(durable, benign)
    fixture = normalize_scenario(scenario)
    rust = rust_deny_probe(probe, probe_sha256, diagnostic_fixture)
    need(durable.exists() and benign.exists(), 'source_roots_missing')
    _private_root(durable)
    _private_root(benign)
    raw = _read_private(benign, FILE)
    need(raw is not None, 'vertical_document_missing')
    data = _verify_document(raw)
    if expected_sha256 is not None:
        need(data['sha256'] == expected_sha256, 'external_vertical_pin_mismatch')
    need(data['record_id'] == fixture['session_id'] and
         data['rust_probe'] == rust, 'vertical_source_or_rust_pin_mismatch')
    gen = open_or_publish_safe(durable, fixture, publish=False)
    need(gen.get('generation') == 1 and gen.get('head_sha256') == data['r70_head_sha256']
         and gen.get('sha256') == data['r70_sha256'] and
         gen.get('analytical_validation') == 'structural_only' and
         gen.get('a7_confirmed_rf') is None and
         gen.get('p8_operational') == 'NO-GO', 'r70_source_drift')
    _existing_review(benign, data)
    shadow = data['shadow']
    need(shadow.get('record_id') == fixture['session_id'] and
         shadow.get('a6_classification') == 'ND' and
         shadow.get('a7_confirmed_rf') is None and
         shadow.get('a9_new_generation_published') is False,
         'r71_shadow_claim_invalid')
    view = build_shadow_dashboard(shadow, fixture, gen)
    validate_dashboard_report(view)
    need(view['sha256'] == data['r38_sha256'] and
         shadow.get('r70_head_sha256') == gen['head_sha256'] and
         shadow.get('a5_local_benign_starts') == 1,
         'r38_original_view_mismatch')
    return {'status': 'PASS_ORIGINAL_MODULES_REPLAY_NO_A5', 'sha256': data['sha256'],
            'record_id': fixture['session_id'], 'r70_head_sha256': gen['head_sha256'],
            'r38_sha256': view['sha256'], 'p8_operational': 'NO-GO',
            'rust_gate': 'DENY_ONLY', 'a5_new_starts': 0,
            'system_acceptance': 'PENDING', 'experimental_validation': 'NOT_RUN'}


def run_vertical_once(durable: Path, benign: Path, scenario: dict[str, Any],
                      probe: Path, probe_sha256: str, diagnostic_fixture: Path) -> dict[str, Any]:
    """Un solo ciclo DEV real sobre módulos originales; A5 es `ok` local.

    Si R88 ya existe, solo verifica: jamás vuelve a invocar A5.
    Ante caída antes del documento, R71 conserva reserva idempotente de 1 inicio.
    """
    _separate_roots(durable, benign)
    fixture = normalize_scenario(scenario)
    rust = rust_deny_probe(probe, probe_sha256, diagnostic_fixture)
    if benign.exists() and _read_private(benign, FILE) is not None:
        return verify_vertical(durable, benign, fixture, probe, probe_sha256,
                               diagnostic_fixture)
    new_benign_journal = not benign.exists()
    if not (durable / 'analytical-archive').exists():
        open_or_create_dev(durable, fixture)
    gen = open_or_publish_safe(durable, fixture, publish=True)
    need(gen['generation'] == 1 and gen['p8_operational'] == 'NO-GO' and
         gen['a5_attempt_count'] == 0 and gen['a7_confirmed_rf'] is None,
         'gen1_not_safe_for_benign')
    shadow = run_shadow_cycle(durable, benign, fixture,
                              expected_head_sha256=gen['head_sha256'])
    view = build_shadow_dashboard(shadow, fixture, gen)
    validate_dashboard_report(view)
    document: dict[str, Any] = {
        'schema': SCHEMA, 'record_id': fixture['session_id'],
        'mode': 'DEV_SINGLE_LOCAL_BENIGN', 'rust_probe': rust,
        'r70_head_sha256': gen['head_sha256'], 'r70_sha256': gen['sha256'],
        'shadow': shadow, 'r38_sha256': view['sha256'],
        'p8_operational': 'NO-GO', 'physical_executions': 0,
        'operational_dispatch': False, 'a6': 'ND', 'rf_confirmed': None,
        'system_acceptance': 'PENDING', 'experimental_validation': 'NOT_RUN',
    }
    document['sha256'] = digest(canonical(document))
    _private_root(benign)
    _write_once(benign, FILE, canonical(document))
    result = verify_vertical(durable, benign, fixture, probe, probe_sha256,
                             diagnostic_fixture, expected_sha256=document['sha256'])
    result['status'] = 'PASS_ONE_LOCAL_BENIGN_INTEGRATED'
    # Tras una interrupción, la invocación pudo limitarse a recuperar A5.
    result['a5_new_starts'] = 1 if new_benign_journal else 'UNKNOWN_RECOVERED'
    return result
