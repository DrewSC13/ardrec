#!/usr/bin/env python3
"""R116-F13 exact-source closure. No network, root operations or operational GO."""
from __future__ import annotations
import argparse
import hashlib
import json
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = 'lab/closure/r116-source-merge-gate-v1.json'
CATALOG = 'lab/operational-catalog-v1/catalog.json'
CI = '.github/workflows/ci.yml'
DOC = 'docs/development/p14-r116-f13-cierre-integracion-no-go-r117-v1.md'
PATH_DIGEST = '837812ae33a9e873c6c4289f674d5d8585f38bdbd6613969ce0aa1eafe5d5c89'
BASE = '210ff5312b1af87e4123f00f6706f7c312d26687'

# R162 source-only integration gate derivative. No exception to root F3 pins.
R162_GATE_PATH = 'scripts/ardrec_p14_r115_f17_merge_gate.py'
R115_ORIGINAL_GATE_SHA256 = 'fb3315b705470295f0fdb4c4936150ae408b217ab1f997baf30802f4637a4a03'
R162_EXACT_GATE_SHA256 = '662841c7d0f7f8e19b1e5ca2b9920db0662434be23dd1df3a7d5dec042e64316'

# R168-F11: admision exacta de R115-F17 desde el HEAD firmado.
# No se modifica el manifiesto historico de 87 fuentes.
R168_F10_SIGNED_HEAD = 'f7f8abe38c954d9f15f82c1cc1977ab6c5e3fd78'
R168_F10_GATE_SHA256 = 'ba8c914b42e72f0f364b45f039d92814771ab6d6ab009dd47cc300ef854dd914'
R168_F10_REQUIRED_FIVE = (
    'lab/tests/test_p14_r115_f16_physical_pilot_controller.py',
    'lab/tests/test_p14_r115_f7_controlled_boot.py',
    'scripts/ardrec_p14_r115_f16_physical_pilot_controller.py',
    'src/ardrec/coordination/r115_f16_physical_pilot_controller.py',
    'src/ardrec/coordination/r115_f7_controlled_boot.py',
)


# R166: derived source hashes only; historical lock unchanged.
# F5 sources come from a verified signed commit.
# F8 sources come from a SHA-256 verified patch.
R166_EXACT_DERIVATIVES = {
    'lab/operational-controller/r116-f3-root-source-lock-v1.json': ('eb6e1dc56576fe59d973eb76b6b563d0baf44cdabcd06d5857f908ee345ca53d', '2d15b24c9101d7615ca6f43dca3b050f1f6058ac3672592b621d3da042dd319a'),
    'lab/tests/test_p14_r115_f16_physical_pilot_controller.py': ('ec8d773a45545e93f6e0cc686de29619cb0ca2098e42cbb17be6e8b877105ea7', '52b3d020844912fd946bfada566247eb4ac632be504d1ec42ea83aba8a968595'),
    'lab/tests/test_p14_r115_f7_controlled_boot.py': ('a7ae80133cf710f1bb1152995bdb2a118e48593d1d5beb900520faa66d74d7ac', '6fb0d659374d2921e49282266846c66d1034e66fe6986973094e56c079746081'),
    'scripts/ardrec_p14_r115_f16_physical_pilot_controller.py': ('00bdafb935eab7b528667145647d6c3494fd2b62b64cacbb32dbf3da01e99b88', 'd661d0e15ce25367b66fd8ba94aa66159a550f01416ad07c628dc4b9388917f6'),
    'scripts/ardrec_p14_r116_f1_root_stage.py': ('badaf3cf9a92d4aa1b6663c7f42c3fb7e7b392b8b817ac4259126339a9f8a659', 'e3aeed02c57766ff64b239732d741d796608f4e9c2ef7abacd279cc80e6af836'),
    'scripts/ardrec_p14_r116_f3_root_stage.py': ('6f6af46d3ff3b2e55719f3452731ced86d83964d277e269de7d3e7b29cddbf04', '72405e0743a412e1e3b7f0ea15fb0303890f6b105d7e2624215d325ddb4dfe76'),
    'src/ardrec/coordination/r115_f16_physical_pilot_controller.py': ('480783a68c88a0e1a28ea43da9419e0ca67cb6d02a05a12658348f31b3930c49', 'fae85aa10c4cf033eacd4ab42208dad66ad516d2dd0300c550d8bbb796c6c4e0'),
    'src/ardrec/coordination/r115_f7_controlled_boot.py': ('90086ec330b1b9513d096fa6996e7dfe994ba10511702d4becbcc1fddee3688d', '361e338d1948f8be31504bdd2b8108346ab96b80e58ae56ebdb32fb4de25e3af'),
}

class GateFailure(ValueError):
    pass

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def unique(pairs):
    data = {}
    for key, value in pairs:
        if key in data:
            raise GateFailure('DUPLICATE_JSON_KEY')
        data[key] = value
    return data

def secure_file(root: Path, rel: str) -> Path:
    if type(rel) is not str or not rel or rel.startswith('/'):
        raise GateFailure('INVALID_PATH')
    p = Path(rel)
    if p.is_absolute() or p.as_posix() != rel or any(x in ('.','..') for x in p.parts):
        raise GateFailure('INVALID_PATH')
    cur = root
    for part in p.parts:
        cur = cur / part
        if cur.is_symlink():
            raise GateFailure('SYMLINK_FORBIDDEN:' + rel)
    try:
        mode = cur.lstat().st_mode
    except FileNotFoundError as exc:
        raise GateFailure('FILE_MISSING:' + rel) from exc
    if not stat.S_ISREG(mode):
        raise GateFailure('NOT_REGULAR:' + rel)
    return cur

def read_json(root: Path, rel: str):
    raw = secure_file(root, rel).read_bytes()
    if len(raw) > 500_000:
        raise GateFailure('JSON_TOO_LARGE:' + rel)
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, TypeError) as exc:
        raise GateFailure('INVALID_JSON:' + rel) from exc
    if type(value) is not dict:
        raise GateFailure('JSON_OBJECT_REQUIRED:' + rel)
    return raw, value

def evaluate(root: Path = ROOT) -> dict:
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise GateFailure('ROOT_INVALID')
    _, lock = read_json(root, LOCK)
    required = {
        'schema':'ARDREC-R116-F13-SOURCE-MERGE-GATE-v1',
        'source_baseline_head':BASE,
        'source_branch':'feat/p14-r116-piloto-ftp-fisico-a5-a10',
        'main_merge_parent':'46dccd948d2d61c4fd777c64dafad3efa71cf035',
        'acceptance_scope':'MERGE_SOURCE_ONLY_NO_OPERATIONAL_GO',
        'catalog_status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
        'root_redeploy_f12':'NOT_PERFORMED',
        'new_a5_physical':'NOT_ATTESTED',
        'p7_pilot_completed':False,
        'p7_execution_enabled':False,
        'a6':'ND','a7_confirmed':'NONE','a8_applied':'NONE',
        'a9_generation_published':False,'p8':'NO-GO',
        'independent_authority':'NOT_PROVISIONED',
        'live_5_1_recovery':'NOT_ATTESTED','restore_from_allow':'NOT_ATTESTED',
        'max_pilot_seconds':60,'backup_scheduled_seconds':45,
    }
    for key, expected in required.items():
        value = lock.get(key)
        if type(value) is not type(expected) or value != expected:
            raise GateFailure('UNSAFE_LOCK:' + key)
    if not (0 < lock['backup_scheduled_seconds'] < lock['max_pilot_seconds']):
        raise GateFailure('INVALID_TIME_ENVELOPE')
    sources = lock.get('source_sha256')
    if (type(sources) is not dict or len(sources) != 87 or
        type(lock.get('source_count')) is not int or lock['source_count'] != 87):
        raise GateFailure('SOURCE_COUNT_MISMATCH')
    digest = sha(('\n'.join(sorted(sources))+'\n').encode())
    if lock.get('source_path_digest') != PATH_DIGEST or digest != PATH_DIGEST:
        raise GateFailure('SOURCE_PATH_INDEX_MISMATCH')
    # El cierre R116 conserva el SHA original de R115-F17.
    if sources.get(R162_GATE_PATH) != R115_ORIGINAL_GATE_SHA256:
        raise GateFailure('R115_GATE_HISTORICAL_PIN_CHANGED')
    for rel, expected_sha in sources.items():
        if type(expected_sha) is not str or len(expected_sha)!=64 or any(c not in '0123456789abcdef' for c in expected_sha):
            raise GateFailure('SOURCE_HASH_FORMAT:' + rel)
        actual_sha = sha(secure_file(root, rel).read_bytes())
        if actual_sha != expected_sha:
            # R162: one exact source-only derivative of the historical R115 gate.
            # Never relax the independently signed root-source release lock.
            historical_derivative = (
                rel == R162_GATE_PATH and
                expected_sha == R115_ORIGINAL_GATE_SHA256 and
                actual_sha == R162_EXACT_GATE_SHA256
            )
            r166_exact_derivative = (
                R166_EXACT_DERIVATIVES.get(rel)
                == (expected_sha, actual_sha)
            )
            # El nuevo R115-F17 solo es admisible junto a la
            # derivacion completa de cinco fuentes ya fijadas por R166.
            r168_exact_derivative = (
                rel == R162_GATE_PATH
                and expected_sha == R115_ORIGINAL_GATE_SHA256
                and actual_sha == R168_F10_GATE_SHA256
                and all(
                    sources.get(name) == R166_EXACT_DERIVATIVES[name][0]
                    and sha(secure_file(root, name).read_bytes())
                        == R166_EXACT_DERIVATIVES[name][1]
                    for name in R168_F10_REQUIRED_FIVE
                )
            )
            if not (
                historical_derivative
                or r166_exact_derivative
                or r168_exact_derivative
            ):
                raise GateFailure('SOURCE_DRIFT:' + rel)
    raw, catalog = read_json(root, CATALOG)
    if sha(raw) != lock.get('catalog_sha256'):
        raise GateFailure('CATALOG_SHA_MISMATCH')
    if (catalog.get('status') != lock['catalog_status'] or
        catalog.get('execution_enabled') is not False or
        catalog.get('pilot_completed') is not False or
        catalog.get('catalog_frozen') is not False or
        catalog.get('counts') != {'ssh':8,'ftp':8,'smb':9,'total':25}):
        raise GateFailure('CATALOG_NO_GO_VIOLATION')
    # The source locks are themselves SHA-pinned above, but their semantics also matter.
    _, f1 = read_json(root, 'lab/operational-controller/r116-f1-root-bundle.json')
    _, f3 = read_json(root, 'lab/operational-controller/r116-f3-root-source-lock-v1.json')
    if (f1.get('p8')!='NO-GO' or f1.get('opens_ports') is not False or
        f1.get('window_seconds')!=60 or f3.get('p8')!='NO-GO' or
        f3.get('window_seconds')!=60 or len(f3.get('files',{}))!=33):
        raise GateFailure('ROOT_CONTRACT_MISMATCH')
    guard = secure_file(root,'scripts/ardrec_p14_r116_f1_root_deny_guard.py').read_text(encoding='utf-8')
    if 'BACKUP_DELAY_SECONDS = 45' not in guard or "'--on-active=45s'" not in guard:
        raise GateFailure('BACKUP_POLICY_DRIFT')
    ci = secure_file(root, CI).read_text(encoding='utf-8')
    if ('CI_R116_F13_DISCOVERED=' not in ci or
        'ardrec_p14_r116_f13_merge_gate.py --verify' not in ci or
        'CI_R115_DISCOVERED=' not in ci):
        raise GateFailure('CLOSURE_CI_NOT_REGISTERED')
    doc = secure_file(root, DOC).read_text(encoding='utf-8')
    if not all(x in doc for x in ('NO-GO','R117','NO_ADMITIDO','45','60','A5','A6')):
        raise GateFailure('DEFERRED_SCOPE_NOT_DOCUMENTED')
    pending = lock.get('open_requirements')
    if type(pending) is not list or len(pending) < 8 or any(type(x) is not str or not x for x in pending):
        raise GateFailure('UNRECORDED_BLOCKERS')
    expected = {'r116':210,'r115':440,'r114':250,'r113':350,'r112':303}
    if lock.get('test_regression') != expected:
        raise GateFailure('REGRESSION_MATRIX_DRIFT')
    return {
        'source_integrity':'PASS_87_PLUS_CI_SEPARATE',
        'catalog':'PINNED_DRAFT_NOT_EXECUTABLE',
        'ci':'R116_REGISTERED',
        'merge_scope':'SOURCE_ONLY_NO_OPERATIONAL_GO',
        'p7':'DRAFT_NOT_CALIBRATED',
        'new_a5_physical':'NOT_ATTESTED',
        'a6':'ND','a9':'NOT_PUBLISHED','p8':'NO-GO',
        'pending_requirements':len(pending),
        'max_window_seconds':60,'backup_scheduled_seconds':45,
        'vm_starts':0,'network_connections':0,'host_mutations':0,
    }

def main():
    parser=argparse.ArgumentParser(description='R116 source-only NO-GO merge gate')
    parser.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    if not args.verify:
        parser.error('--verify required')
    try:
        record=evaluate()
    except (GateFailure, OSError, UnicodeError) as exc:
        print('R116_F13_GATE=STOP_'+type(exc).__name__)
        print('R116_F13_REASON='+str(exc))
        return 2
    for key,val in record.items():
        print('R116_F13_'+key.upper()+'='+str(val))
    print('R116_F13_GATE=PASS_SOURCE_ONLY_NO_GO')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
