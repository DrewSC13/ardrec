"""R114-F7: false-authority and byte-lineage tests, without any real host calls."""
from __future__ import annotations
import copy
import unittest
from ardrec.coordination import r114_f7_real_nogo_trace as m
from ardrec.coordination import r114_f6_ftp_a5_a6_bridge as f6
from ardrec.coordination import r114_f5_ftp_case as f5

class F7Evidence(unittest.TestCase):
    def setUp(self):
        self.report={
            'schema':f6.SCHEMA,
            'mode':'REAL_A5_SOURCE_VERIFIED_A6_OFFLINE_GUARD_ONLY',
            'family_id':'FTP-T01','case_id':f5.CASE,'attempt_id':f5.ATTEMPT,
            'root_f5_receipt_sha256':m.F5_ROOT_RECEIPT_SHA,
            'f5c_replay_sha256':f6.F5C_PINS['replay.log'],
            'p7_catalog_sha256':m.CATALOG_SHA256,
            'p7_catalog_status':'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE',
            'a5_physical_attempt_accredited':True,
            'ftp_220_control_response_verified':True,
            'required_preconditions_pending_formal_A3':list(m.REQUIRED),
            'a6_rule_preview_mode':'SYNTHETIC_RULE_EVALUATION_ONLY',
            'a6_rule_preview_class':'NO_ADMITIDO',
            'a6_rule_preview_reason':'PRECONDITION_ND',
            'a6_classification':'ND','a6_technical_truth_admitted':False,
            'confirmed_vulnerability':False,'a7_confirmed_rf':None,
            'a8_applied_transitions':0,'a9_published_generation':None,
            'new_network_connections':0,'new_guest_exec':0,
            'new_root_scripts':0,'p8':'NO-GO',
            'candidate_supports_from_physical_evidence':{
                'TARGET_ATTESTATION':{'status':'SOURCE_CORRELATED_NOT_A6_ADMITTED'},
                'CONTROL_CHANNEL_RESPONSE':{'status':'SOURCE_PROVED_NOT_A6_ADMITTED'},
                'INTEGRITY_PROVENANCE':{'status':'SOURCE_PROVED_NOT_A6_ADMITTED'},
            },
        }
        self.manifest={
            'schema':'ARDREC-R114-F6-PRIVATE-A5-A6-EVIDENCE-v1',
            'source_root_receipt_sha256':m.F5_ROOT_RECEIPT_SHA,
            'source_f5c_replay_sha256':f6.F5C_PINS['replay.log'],
            'files_sha256':{'report.json':m.sha(m.canon(self.report))},
            'a6_classification':'ND','risk_recalculated':False,'p8':'NO-GO',
        }
        self.boot={
            'schema':'ARDREC-R114-F6R-COLD-BOOT-RECOVERY-RECEIPT-v1',
            'repo_commit':m.RECOVERY_COMMIT,
            'network_starts':3,'guest_starts':4,'f11':m.F11_SHA,
            'r34':'FOUR_DROPS_ZERO_ACCEPT','f6':'SIX_BINDING_DENY_ATTESTED',
            'network_traffic_opened':False,'protocol_probes':0,'a5_reexecutions':0,
            'a6':'ND','p8':'NO-GO','push':False,'merge':False,
            'boot_id':'proof-id','initial_sha256':'1'*64,'final_sha256':'2'*64,
        }
        self.f6log=('\n'.join(m.EXPECTED_REPLAY_F6)+'\n').encode()
        self.bootlog=('\n'.join(m.EXPECTED_REPLAY_BOOT)+'\n').encode()

    def make(self, report=None,manifest=None,boot=None,flog=None,blog=None):
        r=copy.deepcopy(self.report if report is None else report)
        mf=copy.deepcopy(self.manifest if manifest is None else manifest)
        if manifest is None:mf['files_sha256']['report.json']=m.sha(m.canon(r))
        b=copy.deepcopy(self.boot if boot is None else boot)
        fm=m.canon(mf);bb=m.canon(b)
        return m.make_report(r,fm,bb,
               self.f6log if flog is None else flog,
               self.bootlog if blog is None else blog,
               _expected_f6_sha=m.sha(fm),_expected_boot_sha=m.sha(bb))

    def change(self, key,value,which='report'):
        r=copy.deepcopy(self.report); mf=copy.deepcopy(self.manifest); b=copy.deepcopy(self.boot)
        target={'report':r,'manifest':mf,'boot':b}[which]
        target[key]=value
        if which=='report':return lambda:self.make(report=r)
        if which=='manifest':return lambda:self.make(manifest=mf)
        return lambda:self.make(boot=b)

    def test_01_real_ftp_case(self):
        d=self.make();self.assertEqual(d['case_id'],f5.CASE)
    def test_02_exact_10_steps(self):
        d=self.make();self.assertEqual(set(d['a1_to_a10_verified_authority_boundaries']),{
            'A'+str(i) for i in range(1,11)})
    def test_03_all_formal_a3_nd(self):
        self.assertEqual([x['formal_a3_status'] for x in self.make()['technical_precondition_review']],['ND']*5)
    def test_04_a6_no_admission(self):
        self.assertEqual(self.make()['a6_admitted_conditions'],0)
    def test_05_a7_no_final_rf(self):
        self.assertIsNone(self.make()['a7_confirmed_rf'])
    def test_06_a8_no_applied_transitions(self):
        self.assertEqual(self.make()['a8_applied_transitions'],0)
    def test_07_a9_no_published_generation(self):
        self.assertIsNone(self.make()['a9_published_generation'])
    def test_08_p7_never_enabled(self):
        self.assertFalse(self.make()['p7_execution_enabled'])
    def test_09_no_new_network(self):
        self.assertEqual(self.make()['new_network_connections'],0)
    def test_10_no_p8_promotion(self):
        self.assertEqual(self.make()['p8'],'NO-GO')
    def test_11_reproducible_canonical(self):
        self.assertEqual(m.canon(self.make()),m.canon(self.make()))
    def test_12_bad_ftp_case(self):
        with self.assertRaises(m.Stop):self.change('case_id','FTP-T02-S01-01')()
    def test_13_invented_a6_positive(self):
        with self.assertRaises(m.Stop):self.change('a6_classification','POSITIVO_VALIDO')()
    def test_14_false_a3_guards(self):
        with self.assertRaises(m.Stop):self.change('required_preconditions_pending_formal_A3',[])()
    def test_15_catalog_exec_promoted(self):
        with self.assertRaises(m.Stop):self.change('p7_catalog_status','EXECUTABLE')()
    def test_16_unverified_ftp(self):
        with self.assertRaises(m.Stop):self.change('ftp_220_control_response_verified',False)()
    def test_17_wrong_root_source(self):
        with self.assertRaises(m.Stop):self.change('root_f5_receipt_sha256','0'*64)()
    def test_18_nonreal_case(self):
        with self.assertRaises(m.Stop):self.change('a5_physical_attempt_accredited',False)()
    def test_19_risk_forged(self):
        with self.assertRaises(m.Stop):self.change('a7_confirmed_rf',0.0)()
    def test_20_forged_transition(self):
        with self.assertRaises(m.Stop):self.change('a8_applied_transitions',1)()
    def test_21_forged_publication(self):
        with self.assertRaises(m.Stop):self.change('a9_published_generation',1)()
    def test_22_guest_reexecution(self):
        with self.assertRaises(m.Stop):self.change('new_guest_exec',1)()
    def test_23_boot_3_networks(self):
        with self.assertRaises(m.Stop):self.change('network_starts',2,'boot')()
    def test_24_boot_denial(self):
        with self.assertRaises(m.Stop):self.change('f6','UNVERIFIED','boot')()
    def test_25_reboot_traffic_forbidden(self):
        with self.assertRaises(m.Stop):self.change('network_traffic_opened',True,'boot')()
    def test_26_wrong_git_parent(self):
        with self.assertRaises(m.Stop):self.change('repo_commit','0'*40,'boot')()
    def test_27_boot_postfact_a5_repeat(self):
        with self.assertRaises(m.Stop):self.change('a5_reexecutions',1,'boot')()
    def test_28_boot_scope_p8_go(self):
        with self.assertRaises(m.Stop):self.change('p8','GO','boot')()
    def test_29_false_source_manifest_a6(self):
        with self.assertRaises(m.Stop):self.change('a6_classification','VERDADERO','manifest')()
    def test_30_missing_replay_line(self):
        with self.assertRaises(m.Stop):self.make(flog=b'R114_F6_A6=ND\n')
    def test_31_fake_boot_replay(self):
        with self.assertRaises(m.Stop):self.make(blog=b'REPLAY=PASS\n')
    def test_32_replay_with_stop(self):
        with self.assertRaises(m.Stop):self.make(flog=self.f6log+b'STOP=FAIL\n')
    def test_33_wrong_support_admission(self):
        r=copy.deepcopy(self.report)
        r['candidate_supports_from_physical_evidence']['TARGET_ATTESTATION']['status']='A6_ADMITTED'
        with self.assertRaises(m.Stop):self.make(report=r)
    def test_34_wrong_catalog(self):
        with self.assertRaises(m.Stop):self.change('p7_catalog_sha256','f'*64)()
    def test_35_forged_vulnerability(self):
        with self.assertRaises(m.Stop):self.change('confirmed_vulnerability',True)()
    def test_36_forged_preview(self):
        with self.assertRaises(m.Stop):self.change('a6_rule_preview_class','POSITIVO_VALIDO')()
    def test_37_wrong_f6_source_pin(self):
        with self.assertRaises(m.Stop):self.change('source_root_receipt_sha256','0'*64,'manifest')()
    def test_38_missing_source_hash(self):
        with self.assertRaises(m.Stop):self.change('files_sha256',{},'manifest')()
    def test_39_changing_boot_sha_rejected(self):
        mf=m.canon(self.manifest); b=m.canon(self.boot)
        with self.assertRaises(m.Stop):m.make_report(self.report,mf,b,self.f6log,self.bootlog,
            _expected_f6_sha=m.sha(mf), _expected_boot_sha='0'*64)
    def test_40_duplicate_json_key_rejected(self):
        with self.assertRaises(m.Stop):m.obj(b'{"x":1,"x":2}\n')
    def test_41_noncanonical_json_rejected(self):
        with self.assertRaises(m.Stop):m.obj(b'{"x": 1}\n')
    def test_42_wrong_attempt(self):
        with self.assertRaises(m.Stop):self.change('attempt_id','FAKE')()
    def test_43_wrong_f6_source_report_sha(self):
        with self.assertRaises(m.Stop):self.change('files_sha256',{'report.json':'0'*64},'manifest')()
    def test_44_f11_changed(self):
        with self.assertRaises(m.Stop):self.change('f11','0'*64,'boot')()

if __name__=='__main__':unittest.main()
