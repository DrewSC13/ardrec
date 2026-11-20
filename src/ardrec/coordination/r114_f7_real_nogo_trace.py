"""R114-F7: recomputable A1-A10 fail-closed trace over real FTP-T01 evidence.

Not an operational A3 approval, P7 enablement, A6 admission or risk run.
Observational facts come solely from SHA-pinned F6 and postboot receipts.
"""
from __future__ import annotations
import hashlib
import json
import re
from typing import Any
from ardrec.coordination import r114_f6_ftp_a5_a6_bridge as f6
from ardrec.coordination import r114_f5_ftp_case as f5
from ardrec.evidence.r58h_ssh_family_logic import CATALOG_SHA256

SCHEMA = 'ARDREC-R114-F7-REAL-FTP-A1-A10-FAIL-CLOSED-TRACE-v1'
F6_RECEIPT_MANIFEST_SHA = 'db39be6b144888c978fa35fb4aa6620342f81c6458acd9687cb99204d50e4686'
BOOT_RECEIPT_SHA = '0eb4342ece47e75d11b1d3acf2be492183b8c7bd2e8f8afb4286fda57e8c7548'
F5_ROOT_RECEIPT_SHA = 'e80e6f33d7a82ac6e3c76bb70a262d0e65d2b4be0a7feb3558d0d2cd0711a742'
RECOVERY_COMMIT = 'aaeec6ac66680c6c0dae9dc399ef9d47cb2526f9'
F11_SHA = '1b35c2205a70ebdb1156d3cddd2e044a404763da3a9134df1f05dca48200269b'
F6_SESSION = '/home/cicada/ardrec-lab/r114-f6-ftp-a5-evidence-bridge-v1/intake-39e569b8'
BOOT_SESSION = '/home/cicada/ardrec-lab/r114-f6r-cold-boot-recovery-v1/session-80d39f15dad2'
OUTPUT_ROOT = '/home/cicada/ardrec-lab/r114-f7-real-ftp-nogo-a1-a10-v1'
REQUIRED = ('SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED',
            'DESTINATION_AUTHORIZED','CLIENT_COMPATIBLE','SERVICE_READY')
EXPECTED_REPLAY_F6 = ('R114_F6_REPLAY=PASS_F5_F5C_F4_P7_AND_A6_PREVIEW',
                      'R114_F6_A6=ND','R114_F6_REPLAY_ROOT_COMMANDS=0',
                      'R114_F6_RISK_RECALCULATED=NO')
EXPECTED_REPLAY_BOOT = ('R114_POSTBOOT_REPLAY=PASS_SEVEN_TRANSITIONS_F11_F6_R34',
                        'R114_POSTBOOT_REPLAY_NEW_TCP=0','R114_POSTBOOT_REPLAY_P8=NO-GO')
HEX = re.compile('[a-f0-9]{64}\\Z')

class Stop(ValueError): pass

def need(value: bool, reason: str) -> None:
    if not value: raise Stop(reason)

def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def canon(doc: Any) -> bytes:
    return (json.dumps(doc, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')

def obj(raw: bytes) -> dict:
    need(type(raw) is bytes and 0 < len(raw) < 100000, 'SOURCE_SIZE_INVALID')
    try:
        data=json.loads(raw, object_pairs_hook=_unique)
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise Stop('SOURCE_JSON_INVALID') from exc
    need(type(data) is dict and canon(data)==raw,'SOURCE_NOT_CANONICAL')
    return data

def _unique(items):
    data={}
    for k,v in items:
        need(k not in data,'DUPLICATE_SOURCE_JSON_KEY')
        data[k]=v
    return data

def _log(raw: bytes, required: tuple[str, ...], label: str):
    need(type(raw) is bytes and 0<len(raw)<=8000, label+'_LOG_SIZE')
    try: lines=raw.decode('utf-8').splitlines()
    except UnicodeError as exc: raise Stop(label+'_LOG_NONUTF8') from exc
    for item in required:
        need(lines.count(item)==1,label+'_REPLAY_LINE_MISSING_OR_REPEATED_'+item)
    need(not any('STOP=' in line or 'Traceback' in line for line in lines),label+'_LOG_HAS_FAILURE')
    return True

def make_report(f6_report: dict, f6_manifest_raw: bytes, boot_receipt_raw: bytes,
                f6_replay_log: bytes, boot_replay_log: bytes,
                *, _expected_f6_sha: str | None = None,
                _expected_boot_sha: str | None = None) -> dict:
    """Pure. Test-only expected checksum injection is not reachable by CLI."""
    expected_f6 = F6_RECEIPT_MANIFEST_SHA if _expected_f6_sha is None else _expected_f6_sha
    expected_boot = BOOT_RECEIPT_SHA if _expected_boot_sha is None else _expected_boot_sha
    need(sha(f6_manifest_raw)==expected_f6,'F6_RECEIPT_SHA_MISMATCH')
    need(sha(boot_receipt_raw)==expected_boot,'BOOT_RECEIPT_SHA_MISMATCH')
    f6_manifest=obj(f6_manifest_raw)
    boot=obj(boot_receipt_raw)
    _log(f6_replay_log,EXPECTED_REPLAY_F6,'F6')
    _log(boot_replay_log,EXPECTED_REPLAY_BOOT,'BOOT')
    need(f6_manifest.get('schema')=='ARDREC-R114-F6-PRIVATE-A5-A6-EVIDENCE-v1' and
         f6_manifest.get('source_root_receipt_sha256')==F5_ROOT_RECEIPT_SHA and
         f6_manifest.get('source_f5c_replay_sha256')==f6.F5C_PINS['replay.log'] and
         f6_manifest.get('a6_classification')=='ND' and
         f6_manifest.get('risk_recalculated') is False and
         f6_manifest.get('p8')=='NO-GO', 'F6_MANIFEST_AUTHORITY_INVALID')
    need(type(f6_manifest.get('files_sha256')) is dict and
         f6_manifest['files_sha256'].get('report.json')==sha(canon(f6_report)) and
         all(type(x) is str and HEX.fullmatch(x) for x in f6_manifest['files_sha256'].values()),
         'F6_REPORT_NOT_LINKED_TO_RECEIPT')
    need(type(f6_report) is dict and f6_report.get('schema')==f6.SCHEMA and
         f6_report.get('mode')=='REAL_A5_SOURCE_VERIFIED_A6_OFFLINE_GUARD_ONLY' and
         f6_report.get('family_id')=='FTP-T01' and
         f6_report.get('case_id')==f5.CASE and
         f6_report.get('attempt_id')==f5.ATTEMPT and
         f6_report.get('root_f5_receipt_sha256')==F5_ROOT_RECEIPT_SHA and
         f6_report.get('f5c_replay_sha256')==f6.F5C_PINS['replay.log'] and
         f6_report.get('p7_catalog_sha256')==CATALOG_SHA256 and
         f6_report.get('p7_catalog_status')=='P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE' and
         f6_report.get('a5_physical_attempt_accredited') is True and
         f6_report.get('ftp_220_control_response_verified') is True and
         f6_report.get('required_preconditions_pending_formal_A3')==list(REQUIRED) and
         f6_report.get('a6_rule_preview_mode')=='SYNTHETIC_RULE_EVALUATION_ONLY' and
         f6_report.get('a6_rule_preview_class')=='NO_ADMITIDO' and
         f6_report.get('a6_rule_preview_reason')=='PRECONDITION_ND' and
         f6_report.get('a6_classification')=='ND' and
         f6_report.get('a6_technical_truth_admitted') is False and
         f6_report.get('confirmed_vulnerability') is False and
         f6_report.get('a7_confirmed_rf') is None and
         f6_report.get('a8_applied_transitions')==0 and
         f6_report.get('a9_published_generation') is None and
         f6_report.get('new_network_connections')==0 and
         f6_report.get('new_guest_exec')==0 and
         f6_report.get('new_root_scripts')==0 and
         f6_report.get('p8')=='NO-GO', 'F6_SOURCE_REPORT_FALSE_AUTHORITY')
    supports=f6_report.get('candidate_supports_from_physical_evidence')
    need(type(supports) is dict and set(supports)=={
        'TARGET_ATTESTATION','CONTROL_CHANNEL_RESPONSE','INTEGRITY_PROVENANCE'} and
         supports['CONTROL_CHANNEL_RESPONSE'].get('status')=='SOURCE_PROVED_NOT_A6_ADMITTED' and
         supports['INTEGRITY_PROVENANCE'].get('status')=='SOURCE_PROVED_NOT_A6_ADMITTED' and
         supports['TARGET_ATTESTATION'].get('status')=='SOURCE_CORRELATED_NOT_A6_ADMITTED',
         'CANDIDATE_SUPPORTS_PROMOTED')
    need(boot.get('schema')=='ARDREC-R114-F6R-COLD-BOOT-RECOVERY-RECEIPT-v1' and
         boot.get('repo_commit')==RECOVERY_COMMIT and
         boot.get('network_starts')==3 and boot.get('guest_starts')==4 and
         boot.get('f11')==F11_SHA and
         boot.get('r34')=='FOUR_DROPS_ZERO_ACCEPT' and
         boot.get('f6')=='SIX_BINDING_DENY_ATTESTED' and
         boot.get('network_traffic_opened') is False and
         boot.get('protocol_probes')==0 and boot.get('a5_reexecutions')==0 and
         boot.get('a6')=='ND' and boot.get('p8')=='NO-GO' and
         boot.get('push') is False and boot.get('merge') is False and
         type(boot.get('boot_id')) is str and len(boot['boot_id'])>0 and
         all(type(boot.get(x)) is str and HEX.fullmatch(boot[x]) for x in
             ('initial_sha256','final_sha256')), 'BOOT_REPLAY_FALSE_AUTHORITY')
    # Evidence that is authentic for a historical observation does not automatically
    # satisfy a formally authorized A3/P7 assessment in a subsequent interval.
    evidence={
      'SCOPE_APPROVED':('F5_SPECIFIC_OPERATOR_CONSENT','NO_PERMANENT_A3_P7_SCOPE'),
      'LAB_ISOLATION_CONFIRMED':('F5_F6_DENY_AND_NEW_BOOT_F6_DENY', 'NO_GENERAL_OPERATIONAL_A3_APPROVAL'),
      'DESTINATION_AUTHORIZED':('F5_FTP_MAC_IP_TARGET_PINNED','NO_GENERAL_A3_TARGET_GRANT'),
      'CLIENT_COMPATIBLE':('FTP_CONTROL_220_FROM_SINGLE_CLIENT','NO_FULL_PROTOCOL_COMPATIBILITY_CERTIFICATE'),
      'SERVICE_READY':('FTP_220_AT_HISTORICAL_ATTEMPT','NO_CURRENT_SERVICE_READINESS_PROBE'),
    }
    gates=[{
      'precondition': key,
      'source_evidence': evidence[key][0],
      'formal_a3_status':'ND',
      'pending_reason':evidence[key][1],
    } for key in REQUIRED]
    steps={
      'A1':'REAL_F5_FTP_OBSERVATION_LINKED_NOT_A1_EXECUTED',
      'A2':'P7_CATALOGUE_PINNED_DRAFT_NOT_EXECUTABLE',
      'A3':'FIVE_FORMAL_PRECONDITIONS_ND_NO_ADMISSION',
      'A4':'NO_NEW_OPERATIONAL_SCHEDULING',
      'A5':'ONE_REAL_FTP_T01_A5_ATTEMPT_ATTESTED',
      'A6':'ND_NO_TECHNICAL_TRUTH_ADMITTED',
      'A7':'NO_CONFIRMED_FINAL_RISK',
      'A8':'NO_APPLIED_TRANSITION',
      'A9':'NO_PUBLISHED_GENERATION',
      'A10':'PRIVATE_SOURCE_REPLAYS_PASSED_NO_A10_OPERATIONAL_DISPATCH',
    }
    result={
      'schema':SCHEMA,
      'mode':'REAL_FTP_A5_EVIDENCE_WITH_REPRODUCIBLE_A3_A10_NO_GO_BOUNDARY',
      'case_id':f5.CASE,'attempt_id':f5.ATTEMPT,'family_id':'FTP-T01',
      'f6_source_manifest_sha256':sha(f6_manifest_raw),
      'f6_report_sha256':sha(canon(f6_report)),
      'postboot_receipt_sha256':sha(boot_receipt_raw),
      'f5_physical_root_receipt_sha256':F5_ROOT_RECEIPT_SHA,
      'p7_catalogue_sha256':CATALOG_SHA256,
      'technical_precondition_review':gates,
      'formal_a3_preconditions_satisfied':0,
      'formal_a3_preconditions_unresolved':5,
      'a1_to_a10_verified_authority_boundaries':steps,
      'a5_real_attempts_in_evidence':1,
      'a6_admitted_conditions':0,'a6_classification':'ND',
      'a7_confirmed_rf':None,'a8_applied_transitions':0,
      'a9_published_generation':None,
      'p7_execution_enabled':False,'merge_scope':'SOURCE_ONLY_CLOSURE_REQUIRES_REVIEW',
      'operational_ready':False,'new_network_connections':0,
      'new_guest_exec':0,'root_mutations':0,'p8':'NO-GO',
    }
    need(len(canon(result))<7000,'REPORT_TOO_LARGE')
    return result
