"""B8: bind an existing, independently provisioned R116-F3 guest result to F13.

Read-only importer, NOT a dispatcher or signer. The legacy R116-F3 runtime
allocates its own random token and is historically commit-pinned; it therefore
cannot be used as the B4 root controller or to bypass the F13 pre-reservation.
Only a *future*, separately reviewed executor that accepts a prebound token can
produce evidence meeting this contract. Root-owned bytes are never promoted to
A6 without a separate technical/provenance authority and A9 stays absent.
"""
from __future__ import annotations

import base64
import binascii
from pathlib import Path
import json
import re
import subprocess
from typing import Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f13_ftp_a5_journal as f13

SCHEMA = 'ARDREC-R128-B8-EXISTING-F3-FTP-RESULT-BRIDGE-v1'
F3_SHA256 = '37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c'
ROOT = Path('/var/lib/ardrec/r116-f3-ftp-pilot-root-v1')
SOURCE = ROOT / 'root-pilot.py'
HEX16 = re.compile(r'[0-9a-f]{16}\Z')
MAX_BYTES = 131072
F3_SCHEMA = 'ARDREC-R116-F3-ROOT-FTP-PILOT-v1'
GUEST_SCHEMA = 'ARDREC-R116-F3-FTP-T01-PILOT-PROBE-v1'


class Stop(ValueError):
    """Stable denial reason."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def decoded(raw: bytes) -> dict:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'SOURCE_BYTES_INVALID')
    try:
        item = f1.load(raw)
    except (ValueError, TypeError, UnicodeError, f1.Rejected) as exc:
        raise Stop('SOURCE_JSON_INVALID') from exc
    need(type(item) is dict and f1.canonical(item) == raw,
         'SOURCE_NOT_CANONICAL')
    return item


def dig(doc: dict) -> str:
    return f1.digest(f1.canonical(doc))


def _receipt(root_doc: dict, result: dict, qga: dict, context: dict,
             manifest: dict, *, session: str, intent: dict) -> dict:
    need(type(session) is str and HEX16.fullmatch(session) is not None,
         'SESSION_MUST_BE_FIXED_16_HEX')
    f13.check_intent(intent)
    need(intent['session_id'] == session, 'F13_SESSION_NOT_PREBOUND')
    need(type(manifest) is dict and set(manifest) == {
        'schema', 'head', 'base', 'source_sha256', 'p8', 'window_seconds',
        'authority_paths', 'network_automatic', 'a6', 'catalog_sha256'},
        'F3_MANIFEST_FIELDS')
    need(manifest['schema'] == F3_SCHEMA+'-root-bundle' and
         manifest['head'] == intent['head'] and
         manifest['source_sha256'].get('root-pilot.py') == F3_SHA256 and
         manifest['p8'] == 'NO-GO' and manifest['a6'] == 'ND' and
         manifest['window_seconds'] == 60 and
         manifest['network_automatic'] is False,
         'HISTORICAL_EXECUTOR_SOURCE_NOT_CURRENT')
    need(type(context) is dict and
         context.get('schema') == 'ARDREC-R116-F3-FTP-T01-ROOT-SESSION-v1-signed-review' and
         context.get('head') == intent['head'] and
         context.get('p8') == 'NO-GO' and context.get('a6') == 'ND',
         'ROOT_CONTEXT_NOT_THIS_HEAD')
    need(type(root_doc) is dict and set(root_doc) == {
        'schema', 'status', 'opened', 'backup_timer_armed',
        'denies_restored_and_verified', 'result_sha256', 'error', 'a6',
        'p8', 'p7_calibrated', 'a9_published'}, 'F3_RECEIPT_FIELDS')
    need(root_doc['schema'] == F3_SCHEMA+'-receipt' and
         root_doc['status'] == 'FTP_CANDIDATE_RECORDED' and
         root_doc['opened'] is True and
         root_doc['backup_timer_armed'] is True and
         root_doc['denies_restored_and_verified'] is True and
         root_doc['error'] is None and
         root_doc['a6'] == 'ND' and root_doc['p8'] == 'NO-GO' and
         root_doc['p7_calibrated'] is False and
         root_doc['a9_published'] is False and
         root_doc['result_sha256'] == dig(result),
         'F3_TERMINAL_NOT_SAFE_OR_DIGEST_MISMATCH')
    need(type(result) is dict and result.get('schema') == GUEST_SCHEMA and
         result.get('case_id') == intent['case_id'] and
         result.get('src') == '10.203.31.1' and
         result.get('dst') == '10.203.31.2' and
         type(result.get('port')) is int and result['port'] == 21 and
         result.get('tcp') in ('CONNECTED', 'FAILED') and
         result.get('response') in ('RECEIVED','EMPTY','READ_ERROR','CONNECT_ERROR'),
         'FTP_GUEST_RESULT_SCOPE')
    try:
        answer=bytes.fromhex(result['response_hex'])
    except (KeyError, ValueError, TypeError) as exc:
        raise Stop('FTP_RESULT_ENCODING') from exc
    need(len(answer) <= 256 and answer.count(b'\r\n') <= 16 and
         ((result['response']=='RECEIVED') == bool(answer)) and
         ((result['tcp']=='FAILED') == (result['response']=='CONNECT_ERROR')),
         'FTP_RESULT_SEMANTICS')
    need(type(qga) is dict and set(qga)=={'return'} and
         type(qga['return']) is dict and
         qga['return'].get('exited') is True and
         type(qga['return'].get('exitcode')) is int and
         qga['return']['exitcode'] == 0 and
         qga['return'].get('err-data') in ('',None),
         'QGA_RECEIPT_NOT_SUCCESSFUL')
    try:
        replay = base64.b64decode(qga['return']['out-data'],validate=True)
    except (KeyError,ValueError,binascii.Error,TypeError) as exc:
        raise Stop('QGA_DATA_INVALID') from exc
    need(len(replay) <= 8192 and decoded(replay)==result,
         'QGA_AND_RESULT_DIVERGE')
    return {'f3_receipt_sha256':dig(root_doc),
            'guest_result_sha256':dig(result),
            'qga_result_sha256':dig(qga),
            'signed_context_sha256':dig(context),
            'manifest_sha256':dig(manifest)}


def bridge(*, session: str, journal: Path, manifest_raw: bytes,
           receipt_raw: bytes, result_raw: bytes, qga_raw: bytes,
           context_raw: bytes, root_source_sha256: str,
           ) -> dict[str, Any]:
    """Reconcile one already-consumed F13 attempt, NEVER initiate a probe.

    Untrusted caller-supplied bytes can never claim root provenance.
    A positive readback remains an A5 CANDIDATE, not A6.
    """
    need(isinstance(journal,Path) and journal.is_absolute(),
         'F13_JOURNAL_PATH_REQUIRED')
    need(root_source_sha256 == F3_SHA256,'F3_ROOT_SOURCE_NOT_PINNED')
    state=f13.inspect(journal)
    need(state['status']=='ATTEMPT_CONSUMED_UNRESOLVED',
         'F13_MUST_BE_SPENT_WITHOUT_DUPLICATE_SOCKET')
    reservation=f13._read_json(journal,'reservation.json')
    intent=reservation['intent']
    fields=_receipt(decoded(receipt_raw),decoded(result_raw),decoded(qga_raw),
                    decoded(context_raw),decoded(manifest_raw),
                    session=session,intent=intent)
    report={'schema':SCHEMA,'head':intent['head'],'session':session,
            'case_id':intent['case_id'],'case_key':state['case_key'],
            'f13_reservation_sha256':state['reservation_sha256'],
            **fields,'f3_source_sha256':F3_SHA256,
            'root_owned_readback_verified':False,
            'physical_ftp_probe_result_candidate':True,
            'f13_socket_consumption_performed_by_bridge':False,
            'independent_ftp_origin_attested':False,
            'independent_root_closure_attested':False,
            'a5':'ROOT_F3_RESULT_CANDIDATE_ONLY','a6':'ND',
            'a7_confirmed_rf':None,'a8_applied':None,'a9':None,
            'p8':'NO-GO','network_connections_by_bridge':0,
            'nft_writes_by_bridge':0,'vm_starts_by_bridge':0}
    report['sha256']=dig(report)
    return report


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'installed_r116_f3_source_pin_sha256':F3_SHA256,
            'existing_root_physical_engine_reused_as_data_source':True,
            'legacy_f3_generates_session_internally':True,
            'legacy_f3_head_is_historically_pinned':True,
            'f13_one_shot_requires_prebound_session':True,
            'independent_current_head_v2_root_executor_still_required':True,
            'physical_ftp_window_opened_by_bridge':False,
            'root_code_execution':False,'f13_socket_execution':False,
            'source_to_a6_authoritatively_admitted':False,
            'p8':'NO-GO','a6':'ND','a9':None}


def _host(cmd: tuple[str, ...]) -> bytes:
    """Fixed root-owned read-only opcodes, never a shell or root source execution."""
    need(type(cmd) is tuple and len(cmd)>=5 and
         cmd[:3]==('/usr/bin/sudo','-n','--') and
         cmd[3] in ('/usr/bin/stat','/usr/bin/cat','/usr/bin/sha256sum'),
         'HOST_COMMAND_UNEXPECTED')
    try:
        result=subprocess.run(cmd,stdin=subprocess.DEVNULL,capture_output=True,
                              timeout=12,check=False,close_fds=True,
                              env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
    except (OSError,subprocess.TimeoutExpired) as exc:
        raise Stop('ROOT_READ_COMMAND_UNAVAILABLE') from exc
    need(result.returncode==0 and 0<len(result.stdout)<=MAX_BYTES and
         len(result.stderr)<=4096,'ROOT_READ_COMMAND_REJECTED')
    return result.stdout


def _stat(path: Path, *, directory: bool) -> str:
    path_text=str(path)
    raw=_host(('/usr/bin/sudo','-n','--','/usr/bin/stat',
               '-c','%u|%a|%h|%F|%s','--',path_text))
    parts=raw.decode('ascii','strict').strip().split('|')
    need(len(parts)==5 and parts[0]=='0' and
         parts[3]==('directory' if directory else 'regular file') and
         (parts[1]=='700' if directory else parts[1]=='600') and
         (directory or parts[2]=='1'),
         'ROOT_FILE_OR_DIRECTORY_PERMISSIONS')
    return raw.decode('ascii','strict').strip()


def _source_digest() -> str:
    raw=_host(('/usr/bin/sudo','-n','--','/usr/bin/sha256sum','--',str(SOURCE)))
    output=raw.decode('ascii','strict').strip()
    need(output==F3_SHA256+'  '+str(SOURCE),
         'INSTALLED_LEGACY_F3_BINARY_NOT_PINNED')
    return F3_SHA256


def inspect_source() -> dict:
    """Read fixed installed legacy root binary: existence is NOT readiness."""
    _stat(ROOT,directory=True)
    _stat(SOURCE,directory=False)
    _source_digest()
    _stat(SOURCE,directory=False)
    return {'schema':SCHEMA+'-root-source-inspection',
            'f3_root_script_sha256':F3_SHA256,
            'source_pinned_and_root_owned':True,
            'source_is_current_approved_executor':False,
            'root_controller_v2_deployed':False,
            'legacy_manifest_head_accepted_as_current':False,
            'opened_traffic_by_bridge':False,
            'a6':'ND','a9':None,'p8':'NO-GO'}


def read_installed(*, session: str, journal: Path) -> dict:
    """Read only a fixed, one-session root-owned R116-F3 receipt bundle.

    Cannot be used on today's offline 0/6 lab: no root pilot-<session> exists.
    An on-disk authenticated candidate still cannot prove that F13 was spent
    BEFORE the executor started, because historical F3 picks its own token.
    """
    need(type(session) is str and HEX16.fullmatch(session) is not None,
         'SESSION_INVALID')
    inspect_source()
    _stat(ROOT/'authority',directory=True)
    folder=ROOT/('pilot-'+session)
    _stat(folder,directory=True)
    names=('manifest.json','receipt.json','guest-result.json',
           'guest-qga.json','signed-context.json')
    files={}
    for name in names:
        path=ROOT/name if name=='manifest.json' else folder/name
        pre=_stat(path,directory=False)
        raw=_host(('/usr/bin/sudo','-n','--','/usr/bin/cat','--',str(path)))
        need(_stat(path,directory=False)==pre,
             'ROOT_FILE_METADATA_CHANGED_AFTER_READ')
        files[name]=raw
    _source_digest()
    report=bridge(session=session,journal=journal,
        manifest_raw=files['manifest.json'],
        receipt_raw=files['receipt.json'],
        result_raw=files['guest-result.json'],
        qga_raw=files['guest-qga.json'],
        context_raw=files['signed-context.json'],
        root_source_sha256=F3_SHA256)
    report['root_owned_readback_verified']=True
    report['sha256']=dig({k:v for k,v in report.items() if k!='sha256'})
    return report
