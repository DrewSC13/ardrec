#!/usr/bin/env python3
"""R81: prueba funcional integrada nueva en DEV sintético, de principio a fin.

--create: una ÚNICA sesión nueva R75, un proceso benigno local A5,
          derivación R76/R78/R79 y ocho vistas R80; sin VM ni red.
--verify: reconstrucción de fuentes, hashes y ocho vistas sin subprocesos.
Ningún modo acredita verdad técnica, aceptación completa ni habilita P8.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'scripts'))

from ardrec.persistence.codec import canonical, digest
import ardrec_p14_r75_integrated_demo as r75
import ardrec_p14_r76_a5_a8_offline_bridge as r76
import ardrec_p14_r77_signed_a5_a8_bridge as r77
import ardrec_p14_r78_a7_whatif_sensitivity as r78
import ardrec_p14_r79_tutor_walkthrough as r79
import ardrec_p14_r80_terminal_presentation as r80

SCHEMA = 'ardrec-p14-r81-fresh-offline-functional-smoke-v1'
SOURCE = 'SYNTHETIC_DEV_SOFTWARE_SMOKE_NOT_EXPERIMENTAL_ACCEPTANCE'
MAX_BYTES = 400_000
SOURCES = ('r76.json', 'r78.json', 'r79.json')
VIEWS: tuple[tuple[str, str, dict[str, str]], ...] = (
    ('resumen.txt', 'resumen', {}),
    ('etapas.txt', 'etapas', {}),
    ('algoritmo_A7.txt', 'etapa', {'stage':'A7'}),
    ('familias.txt', 'familias', {}),
    ('familia_SSH_T01.txt', 'familia', {'family':'SSH-T01'}),
    ('evidencias.txt', 'evidencias', {}),
    ('monitor_r38.txt', 'r38', {}),
    ('todo.txt', 'todo', {}),
)

class R81Error(ValueError):
    pass

def need(ok: bool, code: str) -> None:
    if not ok:
        raise R81Error(code)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def checked_root(root: Path, *, existing: bool) -> None:
    r75.check_directory(root, existing=existing)
    if existing:
        for name in ('r75', 'sources', 'views'):
            path = root / name
            need(not path.is_symlink(), 'SUBDIRECTORY_SYMLINK_'+name)
            st = path.lstat()
            need(stat.S_ISDIR(st.st_mode) and
                 st.st_uid == os.getuid() and
                 stat.S_IMODE(st.st_mode) == 0o700,
                 'SUBDIRECTORY_NOT_PRIVATE_'+name)

def write(root: Path, rel: str, content: bytes) -> None:
    need(0 < len(content) <= MAX_BYTES, 'WRITTEN_CONTENT_SIZE_'+rel)
    r75.write_file(root / rel, content)

def present(doc: dict[str, Any], receipt: Path) -> dict[str, bytes]:
    monitor = r75.read_file(receipt / 'reports' / 'r38_pantalla.txt').decode('utf-8')
    output = {}
    for name, view, kw in VIEWS:
        result = r80.render(doc, view, monitor=monitor if view == 'r38' else None, **kw)
        raw = result.encode('utf-8')
        need(len(raw) <= MAX_BYTES and 'P8=NO-GO' in result and
             'Rf confirmado=NULL' in result,
             'PRESENTATION_LOST_BOUNDARY_'+name)
        output[name] = raw
    return output

def recompute(root: Path) -> dict[str, Any]:
    receipt = root / 'r75'
    # R75 verifica la generación y sus artefactos inmutables.
    r75_doc = r75.verify(receipt)
    src = root / 'sources'
    docs = {name:r77.read_canonical(src / name) for name in SOURCES}
    need(r76.verify(docs['r76.json'], receipt), 'R76_INVALID')
    need(r78.verify(docs['r78.json'], receipt, docs['r76.json']), 'R78_INVALID')
    need(r79.verify(docs['r79.json'], receipt, docs['r76.json'], docs['r78.json']),
         'R79_INVALID')
    doc = r80.load(receipt, src/'r76.json', src/'r78.json', src/'r79.json')
    need(doc == docs['r79.json'], 'R80_BINDING_INVALID')
    need(doc['stage_count'] == 10 and doc['r75_synthetic_units'] == 54 and
         doc['r78_mathematical_family_count'] == 25 and
         doc['r75_local_benign_starts'] == 1 and
         doc['a6_classification'] == 'ND' and
         doc['a7_confirmed_rf'] is None and
         doc['a8_applied_transitions'] == 0 and
         doc['a9_new_generations'] == 0 and
         doc['physical_executions'] == 0 and
         doc['p8_operational'] == 'NO-GO' and
         doc['system_functional_acceptance'] == 'PENDING' and
         doc['experimental_validation'] == 'NOT_RUN',
         'FALSE_FUNCTIONAL_ACCEPTANCE_OR_AUTHORITY')
    rendered = present(doc, receipt)
    for name, raw in rendered.items():
        need(r77.read_private(root/'views'/name) == raw,
             'VIEW_REPLAY_DRIFT_'+name)
    blob_map = {
        'r75_manifest': r75.read_file(receipt/'MANIFEST.json'),
        **{name:r77.read_private(src/name) for name in SOURCES},
        **rendered,
    }
    body: dict[str, Any] = {
        'schema':SCHEMA,
        'source_kind':SOURCE,
        'software_dev_smoke':'PASS',
        'source_links':{name:sha(value) for name, value in sorted(blob_map.items())},
        'r75_gen1_head':r75_doc['source_links']['r70_head_sha256'],
        'r76_sha256':docs['r76.json']['sha256'],
        'r78_sha256':docs['r78.json']['sha256'],
        'r79_sha256':docs['r79.json']['sha256'],
        'stage_count':10,
        'synthetic_units':54,
        'family_count':25,
        'local_benign_starts':1,
        'presentation_count':len(VIEWS),
        'a6':'ND',
        'confirmed_rf':None,
        'a8_applied_transitions':0,
        'a9_new_generations':0,
        'physical_executions':0,
        'operational_dispatch':False,
        'p8_operational':'NO-GO',
        'system_functional_acceptance':'PENDING',
        'experimental_validation':'NOT_RUN',
    }
    body['sha256'] = digest(canonical(body))
    return body

def create(root: Path) -> dict[str, Any]:
    need(os.geteuid() != 0 and Path.cwd().resolve() == REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    checked_root(root, existing=False)
    root.mkdir(mode=0o700)
    (root / 'sources').mkdir(mode=0o700)
    (root / 'views').mkdir(mode=0o700)
    # Parcial inesperado queda bloqueado y preservado, sin reintento automático.
    r75.create(root / 'r75')
    receipt = root / 'r75'
    docs = {
        'r76.json':r76.build(receipt),
    }
    docs['r78.json'] = r78.build(receipt, docs['r76.json'])
    docs['r79.json'] = r79.build(receipt, docs['r76.json'], docs['r78.json'])
    for name, value in docs.items():
        write(root,'sources/'+name,canonical(value)+b'\n')
    presentations = present(docs['r79.json'],receipt)
    for name, value in presentations.items():
        write(root,'views/'+name,value)
    verified = recompute(root)
    write(root,'MANIFEST.json',canonical(verified)+b'\n')
    return verify(root)

def verify(root: Path) -> dict[str, Any]:
    need(os.geteuid() != 0 and Path.cwd().resolve() == REPO,
         'NONROOT_CANONICAL_CHECKOUT_REQUIRED')
    checked_root(root, existing=True)
    stored = r77.read_canonical(root/'MANIFEST.json')
    expected = recompute(root)
    need(type(stored) is dict and canonical(stored) == canonical(expected),
         'DEV_SMOKE_MANIFEST_REPLAY_DRIFT')
    names = {x.name for x in (root/'sources').iterdir()}
    need(names == set(SOURCES),'EXTRA_OR_MISSING_SOURCE')
    names = {x.name for x in (root/'views').iterdir()}
    need(names == {name for name,_,_ in VIEWS},'EXTRA_OR_MISSING_VIEW')
    need({p.name for p in root.iterdir()} == {'MANIFEST.json','r75','sources','views'},
         'EXTRA_OR_MISSING_ROOT_FILE')
    return stored

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument('--create',action='store_true')
    modes.add_argument('--verify',action='store_true')
    ap.add_argument('--work-dir',required=True,type=Path)
    opt = ap.parse_args(argv)
    try:
        # Controlar modos de nuevos archivos, sin modificar permisos existentes.
        if opt.create:
            old = os.umask(0o077)
            try: result = create(opt.work_dir)
            finally: os.umask(old)
        else:
            result = verify(opt.work_dir)
    except (ValueError, TypeError, KeyError, OSError, RuntimeError) as e:
        print('R81=BLOCKED:'+type(e).__name__+':'+str(e)[:170],file=sys.stderr)
        print('R81_P8=NO-GO',file=sys.stderr)
        return 23
    print('R81_DEV_FUNCTIONAL_SMOKE=PASS_'+('CREATED' if opt.create else 'VERIFIED_NO_EXECUTION'))
    print('R81_A1_A10=10_STAGES')
    print('R81_A2=54_SYNTHETIC_UNITS')
    print('R81_A5=1_LOCAL_BENIGN_START')
    print('R81_A6=ND_25_FAMILIES')
    print('R81_A7=25_EXACT_HYPOTHETICAL_SENSITIVITIES')
    print('R81_A8_APPLIED_TRANSITIONS=0')
    print('R81_A9_NEW_GENERATIONS=0')
    print('R81_A10=8_PRESENTATIONS')
    print('R81_SHA256='+result['sha256'])
    print('R81_SYSTEM_ACCEPTANCE=PENDING')
    print('R81_EXPERIMENTAL_VALIDATION=NOT_RUN')
    print('R81_P8=NO-GO')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
