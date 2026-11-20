"""R114-F6: offline contract/falsification tests only; NO physical evidence simulated."""
from __future__ import annotations
import copy,json,unittest,base64
from unittest.mock import patch
from pathlib import Path
from ardrec.coordination import r114_f6_ftp_a5_a6_bridge as m
from ardrec.evidence import r58i_ftp_family_logic as engine
from ardrec.coordination import r114_f5_ftp_case as f5

REPO=Path(__file__).resolve().parents[2]
DENY=m.canon({'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,'p8':'NO-GO','host_writes':0})
RESTORE=m.canon({'result':'SIX_BINDING_DENY_RESTORED','bindings':6,'p8':'NO-GO'})
VM=lambda mac:f'<domain><devices><interface><mac address="{mac}"/><filterref filter="x"/></interface></devices></domain>'.encode()

def nft(allow=False):
 rows=[{'rule':{'family':'bridge','table':'ardrec_r34_guard','chain':chain,
                'expr':[{'drop':None}]}}
       for chain in ['input','output','forward','forward']]
 if allow:
  rows+= [{'rule':{'family':'bridge','table':'ardrec_r34_guard','chain':'forward',
            'expr':[{'match':{'left':{'meta':{'key':'iifname'}},'right':'a33d31r'}},
                     {'match':{'left':{'meta':{'key':'oifname'}},'right':'a33d31t'}},
                     {'match':{'left':{'payload':{'protocol':'ip','field':'saddr'}},'right':'10.203.31.1'}},
                     {'match':{'left':{'payload':{'protocol':'ip','field':'daddr'}},'right':'10.203.31.2'}},
                     {'accept':None}]}}
            for _ in range(4)]
 return m.canon({'nftables':rows})

class F6P7AndA5(unittest.TestCase):
 def test_01_root_receipt_pinned(self):self.assertEqual(len(m.ROOT_RECEIPT_SHA),64)
 def test_02_root_source_set_exact(self):self.assertEqual(len(m.ROOT_FILES),16)
 def test_03_no_duplicated_sources(self):self.assertEqual(len(set(m.ROOT_FILES)),16)
 def test_04_f5c_replay_pinned(self):self.assertEqual(len(m.F5C_PINS['replay.log']),64)
 def test_05_p7_ftp_t01_exact_requirements(self):
  spec=engine.load_pinned_ftp_catalog()[0]
  self.assertEqual(spec['id'],'FTP-T01')
  self.assertEqual(spec['required_supports'],['TARGET_ATTESTATION','INTEGRITY_PROVENANCE','CONTROL_CHANNEL_RESPONSE'])
 def test_06_p7_draft_not_executable(self):
  doc=json.loads((REPO/'lab/operational-catalog-v1/catalog.json').read_bytes())
  self.assertFalse(doc['execution_enabled'])
  self.assertEqual(doc['status'],'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE')
 def test_07_A6_engine_default_preconditions_nd_blocks(self):
  spec=engine.load_pinned_ftp_catalog()[0]
  value={'family_id':'FTP-T01','derived_case_id':f5.CASE,'assessment_index':0,
    'session_id':'R114_F5','phase':'PENDIENTE','variant':None,
    'preconditions':{k:'ND' for k in spec['preconditions']},
    'supports':{k:'VERDADERO' for k in spec['required_supports']},
    'integrity':'VERDADERO','provenance':'VERDADERO',
    'cleanup':'NO_APLICA','outcome':'OBSERVADO_POSITIVO'}
  x=engine.build_ftp_simulation([value])
  self.assertTrue(engine.verify_ftp_simulation(x))
  self.assertEqual(x['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
  self.assertEqual(x['a6_classification'],'ND')
 def test_08_F5_no_vulnerability_in_source(self):
  source=REPO/'src/ardrec/coordination/r114_f5_ftp_case.py'
  self.assertIn("'vulnerability_confirmed':False",source.read_text())
 def test_09_F5_case_id_immutable(self):self.assertEqual(f5.CASE,'FTP-T01-S01-01')
 def test_10_F5_port_immutable(self):self.assertEqual(f5.DST_PORT,21)

class F6AntiForgery(unittest.TestCase):
 def test_11_bad_Deny_result(self):
  with self.assertRaises(m.Stop):m._deny({'result':'OTHER','bindings':6,'p8':'NO-GO','host_writes':0},'SIX_BINDING_DENY_ATTESTED')
 def test_12_bad_Deny_bindings(self):
  with self.assertRaises(m.Stop):m._deny({'result':'SIX_BINDING_DENY_ATTESTED','bindings':5,'p8':'NO-GO','host_writes':0},'SIX_BINDING_DENY_ATTESTED')
 def test_13_bad_Deny_writes(self):
  with self.assertRaises(m.Stop):m._deny({'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,'p8':'NO-GO','host_writes':1},'SIX_BINDING_DENY_ATTESTED')
 def test_14_good_Deny(self):m._deny(m.obj(DENY),'SIX_BINDING_DENY_ATTESTED')
 def test_15_good_restore(self):m._deny(m.obj(RESTORE),'SIX_BINDING_DENY_RESTORED')
 def test_16_good_four_Drops(self):m._nft_four_drop(nft())
 def test_17_missing_four_Drop(self):
  x=json.loads(nft());x['nftables'].pop()
  with self.assertRaises(m.Stop):m._nft_four_drop(m.canon(x))
 def test_18_changed_Drop_action(self):
  x=json.loads(nft());x['nftables'][0]['rule']['expr']=[{'accept':None}]
  with self.assertRaises(m.Stop):m._nft_four_drop(m.canon(x))
 def test_19_wrong_Drop_chain(self):
  x=json.loads(nft());x['nftables'][0]['rule']['chain']='forward'
  with self.assertRaises(m.Stop):m._nft_four_drop(m.canon(x))
 def test_20_wrong_Drop_table(self):
  x=json.loads(nft());x['nftables'][0]['rule']['table']='other'
  with self.assertRaises(m.Stop):m._nft_four_drop(m.canon(x))
 def test_21_good_ftp_only_live_nft(self):m._nft_ftp_only(nft(True))
 def test_22_wrong_nonFTP_accept(self):
  x=json.loads(nft(True));x['nftables'][-1]['rule']['expr'][0]['match']['right']='a33d30r'
  with self.assertRaises(m.Stop):m._nft_ftp_only(m.canon(x))
 def test_23_accept_count_changed(self):
  x=json.loads(nft(True));x['nftables'].pop()
  with self.assertRaises(m.Stop):m._nft_ftp_only(m.canon(x))
 def test_24_valid_VM_mac(self):self.assertTrue(m._vm_xml(VM(f5.DST_MAC),f5.DST_MAC))
 def test_25_wrong_VM_mac(self):
  with self.assertRaises(m.Stop):m._vm_xml(VM(f5.DST_MAC),'52:54:00:ad:31:08')
 def test_26_duplicate_VM_mac(self):
  a=VM(f5.DST_MAC).replace(b'</devices>',b'<interface><mac address="52:54:00:ad:31:02"/></interface></devices>')
  with self.assertRaises(m.Stop):m._vm_xml(a,f5.DST_MAC)
 def test_27_json_duplicate_key(self):
  with self.assertRaises(m.Stop):m.obj(b'{"a":1,"a":2}')
 def test_28_source_copies_absent(self):
  with self.assertRaises(m.Stop):m.inspect({}, {}, {})
 def test_29_root_sources_wrong_type(self):
  with self.assertRaises(m.Stop):m.check_map({n:'string' for n in m.ROOT_FILES},m.ROOT_FILES)
 def test_30_snapshot_missing_role(self):
  with self.assertRaises(m.Stop):m.check_map({n:b'a' for n in m.ROOT_FILES[:-1]},m.ROOT_FILES)
 def test_31_no_network_imports_in_cli(self):
  text=(REPO/'scripts/ardrec_p14_r114_f6_ftp_bridge.py').read_text()
  self.assertNotIn('import socket',text)
  self.assertNotIn('qemu-agent-command',text)
  self.assertNotIn('nwfilter-binding-create',text)
 def test_32_cli_only_sudo_cat(self):
  text=(REPO/'scripts/ardrec_p14_r114_f6_ftp_bridge.py').read_text()
  self.assertIn("'/usr/bin/cat'",text)
  self.assertNotIn('systemd-run',text)
  self.assertNotIn('nft_open',text)



def fake_full_sources():
 """Deliberately manufactured TEST-ONLY bytes, never physical evidence."""
 report_f4={'schema':'ARDREC-R114-F4-FTP-CONFIG-SOURCE-OBSERVATION-v1',
  'vm':f5.VM_TARGET,'mac':f5.DST_MAC,'ipv4_cidr':f5.DST_IP+'/28',
  'observed_file':'/etc/vsftpd.conf','config_file_sha256':f5.F4_CONFIG_SHA,
  'case_intent':{'family_id':'FTP-T01','derived_case_id':f5.CASE},
  'a5_family_execution_completed':False,'effective_configuration_accredited':False,
  'a6_classification':'ND','p8':'NO-GO'}
 f4_report=m.canon(report_f4)
 f4_m={'schema':'ARDREC-R114-F4-FTP-QGA-PARTIAL-REPLAY-v1',
  'report_sha256':m.sha(f4_report),
  'source_f3_manifest_sha256':'9a216b641f01fdeba5c5e559bb4819393212ecc6c5bbc6f7d90e79f8663f2acf',
  'a5_family_completed':False,'a6_conditions_admitted':0,
  'new_network_connections':0,'risk_recalculated':False,'p8':'NO-GO',
  'files_sha256':{'config.bytes':f5.F4_CONFIG_SHA}}
 f4_manifest=m.canon(f4_m)
 f4_pin=m.sha(f4_manifest)
 raw=m.canon({'schema':f5.PROBE_SCHEMA,'src':f5.SRC_IP,'dst':f5.DST_IP,
  'port':21,'case_id':f5.CASE,'attempt':f5.ATTEMPT,
  'tcp':'CONNECTED','response':'BANNER_RECEIVED',
  'response_hex':b'220 (vsFTPd 3.0.5)\r\n'.hex()})
 qga=m.canon({'return':{'exited':True,'exitcode':0,
   'out-data':base64.b64encode(raw).decode('ascii'),'err-data':''}})
 root={k:b'example' for k in m.ROOT_FILES}
 root.update({'runner_probe.json':raw,'qga_completion.json':qga,
   'f6_before.stdout':DENY,'f6_restore_final.stdout':RESTORE,
   'f6_attest_final.stdout':DENY,'timer_active.stdout':b'LoadState=loaded\nActiveState=active\n',
   'nft_live.stdout':nft(True),'xml_runner.stdout':VM(f5.SRC_MAC),
   'xml_ftp.stdout':VM(f5.DST_MAC),'vm_runner.stdout':b'running\n',
   'vm_ftp.stdout':b'running\n',
   'ftp-only-window-open.once':b'R34_FTP_ONLY_4_ACCEPT_4_DROP\n',
   'r34_watchdog.stdout':b'LoadState=loaded\nActiveState=active\n'})
 with patch.object(f5,'F4_MANIFEST_SHA',f4_pin):
  result=f5.classify_attempt(raw_probe=raw,qga_raw_status=qga,
   f6_final_raw=DENY,f4_manifest_sha=f4_pin,
   f4_report_sha=m.sha(f4_report))
 root['case-report.json']=f5.canon(result)
 root['receipt.json']=m.canon({'schema':'ARDREC-R114-F5-ROOT-FTP-ATTEMPT-RECEIPT-v1',
    'status':'CLOSED_DENY_FTP_220_A5_ATTEMPT','case_id':f5.CASE,
    'attempt_id':f5.ATTEMPT,'source_f4_manifest_sha256':f4_pin,
    'a6_admitted':0,'risk_calculated':False,'p8':'NO-GO',
    'files_sha256':{k:m.sha(v) for k,v in root.items() if k!='receipt.json'}})
 h=m.sha(root['receipt.json'])
 pins=b'904083c970411a16d388e6f4dd73afc843267f58c4395e43c3469b7cad6db67b  /root/root-window.py\n'+h.encode()+b'  /root/receipt.json\n'
 replay=b'R114_F5_REPLAY=PASS_ROOT_RECEIPT_BYTE_INTEGRITY\nR114_F5_REPLAY_SOURCE_OUTCOME=CLOSED_DENY_FTP_220_A5_ATTEMPT\nR114_F5_REPLAY_A6=ND\nR114_F5_REPLAY_HOST_COMMANDS=0\n'
 f5c={'pins.log':pins,'replay.log':replay,'f6_antes.json':DENY,
      'f6_despues.json':DENY,'nft_antes.json':nft(),'nft_despues.json':nft()}
 return root,f5c,{'manifest.json':f4_manifest,'report.json':f4_report}

class F6IntegrationSyntheticFixtures(unittest.TestCase):
 def sources(self):
  return fake_full_sources()
 def run_fixture(self,mod=None):
  root,f5c,f4=self.sources()
  if mod:mod(root,f5c,f4)
  with patch.object(f5,'F4_MANIFEST_SHA',m.sha(f4['manifest.json'])):
   with patch.object(m,'ROOT_RECEIPT_SHA',m.sha(root['receipt.json'])):
    return m.inspect(root,f5c,f4,_test_f5c_pins={k:m.sha(v) for k,v in f5c.items()})
 def test_33_valid_synthetic_chain_preview_blocks_a6(self):
  report,preview=self.run_fixture()
  self.assertTrue(report['a5_physical_attempt_accredited'])
  self.assertEqual(report['a6_classification'],'ND')
  self.assertEqual(report['a6_rule_preview_class'],'NO_ADMITIDO')
  self.assertEqual(preview['decisions'][0]['hypothetical_reason'],'PRECONDITION_ND')
 def test_34_forged_root_receipt_rejected(self):
  with self.assertRaises(m.Stop):self.run_fixture(lambda root,a,b:root.__setitem__('receipt.json',b'{}'))
 def test_35_edited_case_report_rejected(self):
  with self.assertRaises(m.Stop):self.run_fixture(lambda root,a,b:root.__setitem__('case-report.json',b'{}'))
 def test_36_guest_provenance_missing_rejected(self):
  with self.assertRaises(m.Stop):self.run_fixture(lambda root,a,b:root.pop('qga_completion.json'))
 def test_37_corrupt_final_deny_rejected(self):
  with self.assertRaises(m.Stop):self.run_fixture(lambda root,a,b:root.__setitem__('f6_attest_final.stdout',b'{}'))
 def test_38_timestamp_not_claimed(self):
  raw=(REPO/'src/ardrec/coordination/r114_f6_ftp_a5_a6_bridge.py').read_text()
  self.assertNotIn("'a6_classification':'VERDADERO'",raw)
 def test_39_case_report_reference_only(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f6_ftp_bridge.py').read_text()
  self.assertIn('R114_F6_A6=ND_DRAFT_CATALOG_AND_A3_GUARDS',raw)
 def test_40_no_root_execution_during_replay(self):
  raw=(REPO/'scripts/ardrec_p14_r114_f6_ftp_bridge.py').read_text()
  seg=raw.split('def _read_session(',1)[1].split('def main():',1)[0]
  self.assertNotIn('read_fixed(',seg)

if __name__=='__main__':unittest.main()
