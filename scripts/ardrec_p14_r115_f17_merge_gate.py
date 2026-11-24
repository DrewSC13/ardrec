#!/usr/bin/env python3
"""R115 integration-only source integrity gate. No host or network operations."""
from __future__ import annotations
import argparse
import hashlib
import json
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = 'lab/closure/r115-source-merge-gate-v1.json'
CATALOG = 'lab/operational-catalog-v1/catalog.json'
CI = '.github/workflows/ci.yml'
DOC = 'docs/development/p14-r115-f17-cierre-integracion-no-go-r116-v1.md'

# Two *exact* pinned variants, not a general bypass. R115 historical lock stays immutable.
R138_F7_SOURCE = 'src/ardrec/coordination/r115_f7_controlled_boot.py'
R115_F7_ORIGINAL_SHA256 = '90086ec330b1b9513d096fa6996e7dfe994ba10511702d4becbcc1fddee3688d'
R138_F7_SIGNED_VARIANT_SHA256 = 'bc1403601138e9e2c31bad6a7bc1603806e29cc2c65eb5ffd2e516c28df62e13'

# R168-F10: variante completa de cinco fuentes del commit firmado.
# El manifiesto historico R115 permanece inmutable.
R168_SIGNED_SOURCE_HEAD = 'a5c4e66978a5f7038b1153aec7ad0783321d0f51'
R168_WHOLE_SOURCE_VARIANT = {
    'lab/tests/test_p14_r115_f16_physical_pilot_controller.py': ('ec8d773a45545e93f6e0cc686de29619cb0ca2098e42cbb17be6e8b877105ea7', '52b3d020844912fd946bfada566247eb4ac632be504d1ec42ea83aba8a968595'),
    'lab/tests/test_p14_r115_f7_controlled_boot.py': ('a7ae80133cf710f1bb1152995bdb2a118e48593d1d5beb900520faa66d74d7ac', '6fb0d659374d2921e49282266846c66d1034e66fe6986973094e56c079746081'),
    'scripts/ardrec_p14_r115_f16_physical_pilot_controller.py': ('00bdafb935eab7b528667145647d6c3494fd2b62b64cacbb32dbf3da01e99b88', 'd661d0e15ce25367b66fd8ba94aa66159a550f01416ad07c628dc4b9388917f6'),
    'src/ardrec/coordination/r115_f16_physical_pilot_controller.py': ('480783a68c88a0e1a28ea43da9419e0ca67cb6d02a05a12658348f31b3930c49', 'fae85aa10c4cf033eacd4ab42208dad66ad516d2dd0300c550d8bbb796c6c4e0'),
    'src/ardrec/coordination/r115_f7_controlled_boot.py': ('90086ec330b1b9513d096fa6996e7dfe994ba10511702d4becbcc1fddee3688d', '361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af'),
}

class GateFailure(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, val in pairs:
        if key in result:
            raise GateFailure('DUPLICATE_JSON_KEY')
        result[key] = val
    return result


def _secure_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or relative.startswith('/'):
        raise GateFailure('INVALID_RELATIVE_PATH')
    path = Path(relative)
    if (path.is_absolute() or path.as_posix() != relative or
        any(part in ('..', '.') for part in path.parts)):
        raise GateFailure('INVALID_RELATIVE_PATH')
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise GateFailure('SYMLINK_FORBIDDEN:' + relative)
    try:
        st = current.lstat()
    except FileNotFoundError as exc:
        raise GateFailure('FILE_MISSING:' + relative) from exc
    if not stat.S_ISREG(st.st_mode):
        raise GateFailure('NOT_REGULAR_FILE:' + relative)
    return current


def _read_json(root: Path, relative: str) -> tuple[bytes, dict]:
    data = _secure_path(root, relative).read_bytes()
    if len(data) > 200_000:
        raise GateFailure('JSON_TOO_LARGE:' + relative)
    try:
        parsed = json.loads(data, object_pairs_hook=_unique)
    except (ValueError, TypeError) as exc:
        raise GateFailure('INVALID_JSON:' + relative) from exc
    if type(parsed) is not dict:
        raise GateFailure('JSON_OBJECT_REQUIRED:' + relative)
    return data, parsed


def evaluate(root: Path = ROOT) -> dict:
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise GateFailure('INVALID_ROOT')
    _, lock = _read_json(root, LOCK)
    if lock.get('schema') != 'ARDREC-R115-F17-SOURCE-MERGE-GATE-v1':
        raise GateFailure('LOCK_SCHEMA_MISMATCH')
    if (lock.get('source_baseline_head') !=
        '3732b0c28926b86e35835972e8b7b256dfe7be13'):
        raise GateFailure('BASELINE_IDENTITY_MISMATCH')
    if lock.get('source_branch') != 'feat/p14-r115-a3-p7-a6-real':
        raise GateFailure('BRANCH_IDENTITY_MISMATCH')
    if lock.get('acceptance_scope') != 'MERGE_SOURCE_ONLY_NO_OPERATIONAL_GO':
        raise GateFailure('UNSAFE_ACCEPTANCE_SCOPE')
    checks = {
        'a5_physical': 'NOT_ATTESTED',
        'a6': 'ND', 'p8': 'NO-GO',
        'p7_pilot_completed': False,
        'p7_execution_enabled': False,
        'a9_generation_published': False,
    }
    for key, value in checks.items():
        if lock.get(key) != value or type(lock.get(key)) is not type(value):
            raise GateFailure('UNSAFE_LOCK_STATE:' + key)
    sources = lock.get('source_sha256')
    if (type(sources) is not dict or len(sources) != 58 or
        type(lock.get('source_count')) is not int or lock['source_count'] != 58):
        raise GateFailure('LOCK_SOURCE_COUNT_MISMATCH')
    # Admitir la derivacion solamente si coinciden TODOS los cinco
    # archivos y TODOS los hashes originales del cierre historico.
    r168_exact_variant = all(
        sources.get(name) == historical
        and sha(_secure_path(root, name).read_bytes()) == derived
        for name, (historical, derived)
        in R168_WHOLE_SOURCE_VARIANT.items()
    )
    for name, digest in sources.items():
        if (not name.startswith(('docs/development/p14-r115-',
                                 'lab/tests/test_p14_r115_',
                                 'scripts/ardrec_p14_r115_',
                                 'src/ardrec/coordination/r115_')) or
            type(digest) is not str or len(digest) != 64 or
            any(c not in '0123456789abcdef' for c in digest)):
            raise GateFailure('INVALID_LOCK_SOURCE:' + name)
        actual_sha256 = sha(_secure_path(root, name).read_bytes())
        if actual_sha256 != digest:
            # R138: only the exact signed branch-provenance derivative of R115-F7.
            # Keep the historical 58-source R115 lock unchanged.
            if not (name == R138_F7_SOURCE and
                    digest == R115_F7_ORIGINAL_SHA256 and
                    actual_sha256 == R138_F7_SIGNED_VARIANT_SHA256) and not (
                    r168_exact_variant
                    and name in R168_WHOLE_SOURCE_VARIANT):
                raise GateFailure('SOURCE_DRIFT:' + name)
    raw_catalog, catalog = _read_json(root, CATALOG)
    if sha(raw_catalog) != lock.get('catalog_sha256'):
        raise GateFailure('CATALOG_PIN_MISMATCH')
    if (catalog.get('status') != lock.get('catalog_status') or
        catalog.get('status') != 'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' or
        catalog.get('execution_enabled') is not False or
        catalog.get('pilot_completed') is not False or
        catalog.get('catalog_frozen') is not False or
        catalog.get('counts') != {'ssh':8,'ftp':8,'smb':9,'total':25}):
        raise GateFailure('CATALOG_NO_GO_INVARIANT_FAILED')
    ci_text = _secure_path(root, CI).read_text(encoding='utf-8')
    if 'CI_R115_DISCOVERED=' not in ci_text or 'ardrec_p14_r115_f17_merge_gate.py --verify' not in ci_text:
        raise GateFailure('R115_CI_GATE_NOT_REGISTERED')
    doc = _secure_path(root, DOC).read_text(encoding='utf-8')
    if 'R116' not in doc or 'NO-GO' not in doc or 'NO_ADMITIDO' not in doc:
        raise GateFailure('CLOSURE_RISK_DISCLOSURE_MISSING')
    if type(lock.get('open_requirements')) is not list or len(lock['open_requirements']) < 7:
        raise GateFailure('OPEN_REQUIREMENTS_MISSING')
    return {
        'schema':'ARDREC-R115-F17-MERGE-SOURCE-READINESS-v1',
        'source_integrity':'PASS_58',
        'catalog':'PINNED_DRAFT_NOT_EXECUTABLE',
        'ci':'R115_REGISTERED',
        'merge_scope':'SOURCE_ONLY_NO_OPERATIONAL_GO',
        'p7_pilot_completed':False, 'a5_physical':'NOT_ATTESTED',
        'a6':'ND', 'p8':'NO-GO', 'a9':'NOT_PUBLISHED',
        'pending_requirements':len(lock['open_requirements']),
        'vm_starts':0, 'network_probes':0, 'host_mutations':0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='R115 integration-only NO-GO gate')
    parser.add_argument('--verify', action='store_true', help='verify pinned source-only closure')
    args = parser.parse_args()
    if not args.verify:
        parser.error('--verify is required')
    try:
        result = evaluate()
    except (GateFailure, OSError, UnicodeError) as exc:
        print('R115_F17_GATE=STOP_' + type(exc).__name__)
        print('R115_F17_REASON=' + str(exc))
        return 2
    for key, value in result.items():
        print('R115_F17_' + key.upper() + '=' + str(value))
    print('R115_F17_GATE=PASS_SOURCE_ONLY_NO_GO')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
