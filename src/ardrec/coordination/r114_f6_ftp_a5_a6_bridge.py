"""R114-F6: admissibility bridge for the verified *real* FTP-T01 A5 observation.

Reads historical F5 root bytes via unprivileged caller's explicit read-only copy,
validates the F5C replay and F4 lineage, and evaluates an offline A6 preview.
Never promotes P7 draft catalogue to executable or records a final risk.
"""
from __future__ import annotations
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Mapping
from ardrec.coordination import r114_f5_ftp_case as f5
from ardrec.evidence import r58i_ftp_family_logic as ftp
from ardrec.evidence.r58h_ssh_family_logic import CATALOG_SHA256

SCHEMA='ARDREC-R114-F6-FTP-T01-REAL-A5-TO-A6-GATED-PREVIEW-v1'
ROOT_RECEIPT_SHA='e80e6f33d7a82ac6e3c76bb70a262d0e65d2b4be0a7feb3558d0d2cd0711a742'
F5C_ROOT='/home/cicada/Development/GitHub/ardrec-patches/R114_F5C_KsIGKbW0'
F5_ROOT='/var/lib/ardrec/r114-f5-ftp-t01-root-v1/window-46ebd6a6'
F6_OUTPUT='/home/cicada/ardrec-lab/r114-f6-ftp-a5-evidence-bridge-v1'
F4_ROOT=f5.F4_DIR
F5C_PINS={
 'pins.log':'ce2750abe34cf49afeef1cfdf098528ce38b3bd3d69346fc55c505ca84011377',
 'replay.log':'171b20dc608e4c3d81d2f019287409fc38605a43b768dbfea14c74ac9fe3d4c2',
 'f6_antes.json':'ec9ee26d718abded94e19f811f5766b0c12efbc927c0237606d9f1dad4bacd28',
 'f6_despues.json':'ec9ee26d718abded94e19f811f5766b0c12efbc927c0237606d9f1dad4bacd28',
 'nft_antes.json':'c6804ef98abddcfe90b708ba24921446b31aca0585aafc30da7c569c7dee5a38',
 'nft_despues.json':'c6804ef98abddcfe90b708ba24921446b31aca0585aafc30da7c569c7dee5a38',
}
ROOT_FILES=(
 'receipt.json','case-report.json','runner_probe.json','qga_completion.json',
 'f6_before.stdout','f6_restore_final.stdout','f6_attest_final.stdout',
 'timer_active.stdout','nft_live.stdout','xml_runner.stdout','xml_ftp.stdout',
 'vm_runner.stdout','vm_ftp.stdout','ftp-only-window-open.once',
 'f11_sha.stdout','r34_watchdog.stdout',
)
F4_FILES=('manifest.json','report.json')
HEX=re.compile(r'[a-f0-9]{64}\Z')
class Stop(ValueError):pass
def need(test,code):
 if not test:raise Stop(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canon(doc):return (json.dumps(doc,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
def obj(raw):
 try:return json.loads(raw,object_pairs_hook=reject_duplicates)
 except (ValueError,UnicodeError,RecursionError,TypeError) as exc:raise Stop('JSON_INVALID_OR_DUPLICATE') from exc
def reject_duplicates(pairs):
 doc={}
 for k,v in pairs:
  need(k not in doc,'DUPLICATE_JSON_KEY')
  doc[k]=v
 return doc
def check_map(m,expected,allow_empty=False):
 need(type(m) is dict and set(m)==set(expected),'COPIED_FILE_SET_INVALID')
 for name in expected:
  raw=m[name]
  need(type(raw) is bytes and len(raw)<=200000 and (allow_empty or len(raw)>0),
       'SOURCE_SIZE_INVALID_'+name)

def _deny(doc,expected):
 need(type(doc) is dict and doc.get('result')==expected and
      doc.get('bindings')==6 and doc.get('p8')=='NO-GO' and
      (doc.get('host_writes')==0 if expected=='SIX_BINDING_DENY_ATTESTED' else True),
      'F6_DENY_CHAIN_INVALID')
def _nft_four_drop(raw):
 doc=obj(raw)
 need(type(doc) is dict and type(doc.get('nftables')) is list,'NFT_SCHEMA_INVALID')
 rules=[x['rule'] for x in doc['nftables'] if type(x) is dict and 'rule' in x]
 need(len(rules)==4,'NFT_DENY_RULES_NOT_FOUR')
 need(Counter(r.get('chain') for r in rules)==Counter({'input':1,'output':1,'forward':2}),
      'NFT_DENY_CHAIN_DISTRIBUTION')
 for r in rules:
  ex=r.get('expr',[])
  need(r.get('family')=='bridge' and r.get('table')=='ardrec_r34_guard' and
       type(ex) is list and any(type(x) is dict and 'drop' in x for x in ex) and
       not any(type(x) is dict and 'accept' in x for x in ex),
       'NFT_DENY_RULE_INVALID')
def _nft_ftp_only(raw):
 doc=obj(raw)
 rules=[x['rule'] for x in doc['nftables'] if type(x) is dict and 'rule' in x]
 need(len(rules)==8,'NFT_FTP_WINDOW_RULES_INVALID')
 accepts=[r for r in rules if any('accept' in x for x in r.get('expr',[]))]
 drops=[r for r in rules if any('drop' in x for x in r.get('expr',[]))]
 need(len(accepts)==4 and len(drops)==4,'NFT_WINDOW_NOT_FTP_FOUR_FOUR')
 for r in accepts:
  s=json.dumps(r,sort_keys=True)
  need(r.get('family')=='bridge' and r.get('table')=='ardrec_r34_guard' and
       r.get('chain')=='forward' and '10.203.31.1' in s and
       '10.203.31.2' in s and 'a33d31r' in s and 'a33d31t' in s and
       'a33d30' not in s and 'a33d32' not in s,'NFT_NON_FTP_ACCEPT')

def _vm_xml(raw,mac):
 try:tree=ET.fromstring(raw)
 except ET.ParseError as exc:raise Stop('VM_XML_INVALID') from exc
 found=[iface for iface in tree.findall('./devices/interface')
        if iface.find('mac') is not None and iface.find('mac').get('address')==mac]
 need(len(found)==1,'VM_MAC_IDENTITY_DRIFT')
 return True

def inspect(root:Mapping[str,bytes],f5c:Mapping[str,bytes],f4:Mapping[str,bytes],
            *,_test_receipt_sha:str|None=None,_test_f5c_pins:dict|None=None):
 """Pure, reproducible inspection. Test-only injections cannot be selected from CLI."""
 check_map(root,ROOT_FILES)
 check_map(f5c,F5C_PINS)
 check_map(f4,F4_FILES)
 root_sha=ROOT_RECEIPT_SHA if _test_receipt_sha is None else _test_receipt_sha
 pins=F5C_PINS if _test_f5c_pins is None else _test_f5c_pins
 need(sha(root['receipt.json'])==root_sha,'F5_ROOT_RECEIPT_SHA_MISMATCH')
 need(all(sha(f5c[k])==pins[k] for k in F5C_PINS),'F5C_PIN_DRIFT')
 receipt=obj(root['receipt.json'])
 need(type(receipt) is dict and receipt.get('schema')=='ARDREC-R114-F5-ROOT-FTP-ATTEMPT-RECEIPT-v1' and
      receipt.get('status')=='CLOSED_DENY_FTP_220_A5_ATTEMPT' and
      receipt.get('source_f4_manifest_sha256')==f5.F4_MANIFEST_SHA and
      receipt.get('case_id')==f5.CASE and receipt.get('attempt_id')==f5.ATTEMPT and
      receipt.get('a6_admitted')==0 and receipt.get('risk_calculated') is False and
      receipt.get('p8')=='NO-GO','F5_ROOT_RECEIPT_AUTHORITY_INVALID')
 hashes=receipt.get('files_sha256')
 need(type(hashes) is dict and len(hashes)>=len(ROOT_FILES)-1 and
      all(type(k) is str and re.fullmatch('[a-z0-9_.-]{2,70}',k) and
          type(v) is str and HEX.fullmatch(v) for k,v in hashes.items()),
      'F5_ROOT_HASH_SCOPE_INVALID')
 for k in ROOT_FILES:
  if k=='receipt.json':continue
  need(k in hashes and sha(root[k])==hashes[k],'F5_ROOT_FILE_SHA_MISMATCH_'+k)
 p=f5c['pins.log'].decode('ascii')
 lines=p.splitlines()
 need(len(lines)==2 and lines[0].split()[0]=='904083c970411a16d388e6f4dd73afc843267f58c4395e43c3469b7cad6db67b' and
      lines[1].split()[0]==ROOT_RECEIPT_SHA,'F5C_ROOT_PINS_CHANGED')
 replay=f5c['replay.log'].decode('ascii')
 need('R114_F5_REPLAY=PASS_ROOT_RECEIPT_BYTE_INTEGRITY\n' in replay and
      'R114_F5_REPLAY_SOURCE_OUTCOME=CLOSED_DENY_FTP_220_A5_ATTEMPT\n' in replay and
      'R114_F5_REPLAY_HOST_COMMANDS=0\n' in replay and
      'R114_F5_REPLAY_A6=ND\n' in replay,'F5C_REPLAY_NOT_ACCREDITED')
 need(f5c['f6_antes.json']==f5c['f6_despues.json'] and
      f5c['nft_antes.json']==f5c['nft_despues.json'],'F5C_DENY_CHANGED')
 _deny(obj(f5c['f6_antes.json']),'SIX_BINDING_DENY_ATTESTED')
 _deny(obj(root['f6_before.stdout']),'SIX_BINDING_DENY_ATTESTED')
 _deny(obj(root['f6_restore_final.stdout']),'SIX_BINDING_DENY_RESTORED')
 _deny(obj(root['f6_attest_final.stdout']),'SIX_BINDING_DENY_ATTESTED')
 _nft_four_drop(f5c['nft_despues.json'])
 _nft_ftp_only(root['nft_live.stdout'])
 need(b'ActiveState=active' in root['timer_active.stdout'] and
      b'LoadState=loaded' in root['timer_active.stdout'],
      'WATCHDOG_NOT_ARMED')
 need(root['ftp-only-window-open.once']==b'R34_FTP_ONLY_4_ACCEPT_4_DROP\n',
      'FTP_WINDOW_TIMELINE_INVALID')
 need(b'active' in root['r34_watchdog.stdout'] and
      b'loaded' in root['r34_watchdog.stdout'], 'R34_WATCHDOG_NOT_ACTIVE')
 _vm_xml(root['xml_runner.stdout'],f5.SRC_MAC)
 _vm_xml(root['xml_ftp.stdout'],f5.DST_MAC)
 need(root['vm_runner.stdout'].strip() in (b'running',b'ejecutando') and
      root['vm_ftp.stdout'].strip() in (b'running',b'ejecutando'),
      'VM_NOT_RUNNING_AT_A5')
 need(sha(f4['manifest.json'])==f5.F4_MANIFEST_SHA,'F4_MANIFEST_SHA_DRIFT')
 f4man=obj(f4['manifest.json']);f4rep=obj(f4['report.json'])
 f5.validate_f4_source(f4rep,f4man,manifest_sha=sha(f4['manifest.json']),
                       report_sha=sha(f4['report.json']))
 need(f4man.get('report_sha256')==sha(f4['report.json']),'F4_REPORT_PIN_MISMATCH')
 observed=f5.classify_attempt(raw_probe=root['runner_probe.json'],
           qga_raw_status=root['qga_completion.json'],
           f6_final_raw=root['f6_attest_final.stdout'],
           f4_manifest_sha=f5.F4_MANIFEST_SHA,
           f4_report_sha=sha(f4['report.json']))
 need(observed['ftp_220_response_observed'] is True and
      f5.canon(observed)==root['case-report.json'] and
      observed['a6_classification']=='ND' and
      observed['a7_final_risk'] is None,'A5_ROOT_REPORT_MISMATCH')
 need(CATALOG_SHA256==ftp.CATALOG_SHA256,'CATALOG_SOURCE_DRIFT')
 families=ftp.load_pinned_ftp_catalog()
 spec=next(s for s in families if s['id']=='FTP-T01')
 need(spec['preconditions']==['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED',
        'DESTINATION_AUTHORIZED','CLIENT_COMPATIBLE','SERVICE_READY'] and
      spec['required_supports']==['TARGET_ATTESTATION','INTEGRITY_PROVENANCE',
                                  'CONTROL_CHANNEL_RESPONSE'] and
      spec['acceptance_supports']==['CONTROL_CHANNEL_RESPONSE'] and
      spec['cleanup']=='NO_MUTATION','FTP_T01_CATALOG_REQUIREMENTS_CHANGED')
 # The existing engine is explicitly a *synthetic* preview, never an A6 admission.
 preview=ftp.build_ftp_simulation([{
      'family_id':'FTP-T01','derived_case_id':f5.CASE,
      'assessment_index':0,'session_id':'R114_F5','phase':'PENDIENTE',
      'variant':None,
      'preconditions':{k:'ND' for k in spec['preconditions']},
      'supports':{k:'VERDADERO' for k in spec['required_supports']},
      'integrity':'VERDADERO','provenance':'VERDADERO',
      'cleanup':'NO_APLICA','outcome':'OBSERVADO_POSITIVO'}])
 need(ftp.verify_ftp_simulation(preview) and
      preview['decisions'][0]['hypothetical_result_class']=='NO_ADMITIDO' and
      preview['decisions'][0]['hypothetical_reason']=='PRECONDITION_ND' and
      preview['a6_classification']=='ND' and
      preview['p8_operational']=='NO-GO', 'A6_ENGINE_FAIL_CLOSED_PREVIEW')
 report={
  'schema':SCHEMA,'mode':'REAL_A5_SOURCE_VERIFIED_A6_OFFLINE_GUARD_ONLY',
  'root_f5_receipt_sha256':sha(root['receipt.json']),
  'f5c_replay_sha256':sha(f5c['replay.log']),
  'f4_manifest_sha256':sha(f4['manifest.json']),
  'f4_report_sha256':sha(f4['report.json']),
  'p7_catalog_sha256':CATALOG_SHA256,
  'p7_catalog_status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
  'family_id':'FTP-T01','case_id':f5.CASE,'attempt_id':f5.ATTEMPT,
  'source_runner_ip':f5.SRC_IP,'target_ip':f5.DST_IP,'target_port':f5.DST_PORT,
  'a5_physical_attempt_accredited':True,
  'ftp_220_control_response_verified':True,
  'raw_ftp_greeting_sha256':observed['raw_banner_sha256'],
  'raw_ftp_greeting_bytes':observed['raw_banner_bytes'],
  'candidate_supports_from_physical_evidence':{
   'CONTROL_CHANNEL_RESPONSE':{'status':'SOURCE_PROVED_NOT_A6_ADMITTED',
                               'source':'runner_probe.json+qga_completion.json'},
   'INTEGRITY_PROVENANCE':{'status':'SOURCE_PROVED_NOT_A6_ADMITTED',
                           'source':'receipt.json+f5c/replay.log'},
   'TARGET_ATTESTATION':{'status':'SOURCE_CORRELATED_NOT_A6_ADMITTED',
                         'source':'xml_ftp.stdout+f4/report.json'},
  },
  'required_preconditions_pending_formal_A3':spec['preconditions'],
  'a6_rule_preview_mode':'SYNTHETIC_RULE_EVALUATION_ONLY',
  'a6_rule_preview_sha256':preview['sha256'],
  'a6_rule_preview_class':'NO_ADMITIDO',
  'a6_rule_preview_reason':'PRECONDITION_ND',
  'a6_classification':'ND','a6_technical_truth_admitted':False,
  'confirmed_vulnerability':False,'a7_confirmed_rf':None,
  'a8_applied_transitions':0,'a9_published_generation':None,
  'new_network_connections':0,'new_guest_exec':0,'new_root_scripts':0,
  'p8':'NO-GO',
 }
 need(len(canon(report))<6000,'REPORT_TOO_LARGE')
 return report,preview
