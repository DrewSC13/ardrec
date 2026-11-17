"""Tests R60-E1 contract validation without host, VM, or network calls."""
from __future__ import annotations

import copy
from pathlib import Path
import importlib.util
import json
import os
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2] / 'scripts' / 'ardrec_p14_r60e1_integracion_offline.py'
spec = importlib.util.spec_from_file_location('r60e1', SOURCE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def fixture():
    rows = []
    groups = (('SSH_DEV',8,'SSH'),('FTP_DEV',10,'FTP'),('SMB_DEV',11,'SMB'))
    for service,count,prefix in groups:
        for idx in range(count):
            rows.append({'service_id':service,'derived_case_id':prefix+'-T%02d'%(idx+1),
                         'variant':None,'a6_classification':'ND',
                         'a8_recommendation':'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'})
    k = {'unit_count':29,'covered_family_count':25,
         'count_by_service':{'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11},
         'a6_classification':'ND','confirmed_final_risk':None,
         'published_generation':None,'p8_operational':'NO-GO',
         'technical_truth_accredited':False,'a8_applied_transition':None,
         'decisions':rows,'sha256':'a'*64,'catalog_sha256':'b'*64,
         'a6_a7_a8_bridge_sha256':'c'*64}
    v = {'case_count':29,'family_count':25,'source_denials_preserved':True,
         'source_t1_unchanged':True,'source_overlay_unchanged':True,
         'a5_intents_submitted':0,'a5_attempts_reserved':0,'a5_attempts_started':0,
         'a6_accredited_evidence_count':0,'a6_classification':'ND',
         'p8_operational':'NO-GO','confirmed_final_risk':None,
         'published_generation':None,'operational_dispatch':False,
         'operational_transitions_applied':0,
         'handoff_verification':'PASS_READONLY_MODEL_HANDOFF_NO_A5_OR_A6',
         'sha256':'d'*64}
    o = {'stage_count':10,'stages':['A'+str(i) for i in range(1,11)],
         'a1_a3_service_count':3,'a1_a3_event_count':9,
         'a4_a8_case_count':29,'a4_a8_family_count':25,
         'a5_local_fixture_start_intent_count':0,
         'a9_local_declared_receipt_verified':True,
         'a1_a3_to_family_case_binding_attested':False,
         'independent_physical_case_binding_attested':False,
         'a1_a10_implementation_complete':False,
         'experimental_hypothesis_validated':False,
         'operational_dispatch':False,'confirmed_final_risk':None,
         'published_generation':None,'applied_state_transition':None,
         'a6_classification':'ND','p8_operational':'NO-GO',
         'sha256':'e'*64,'stage_ledger_head_sha256':'f'*64}
    return {'R58K':k,'R58V':v,'R58O':o}


class ContractTests(unittest.TestCase):
    def test_01_correct_three_modules(self):
        self.assertEqual([name for name,_ in r.DEMOS],['R58K','R58V','R58O'])

    def test_02_pins_five_source_files(self):
        self.assertEqual(len(r.GIT_PINS),5)

    def test_03_anchored_base(self):
        self.assertEqual(r.BASE,'ce9478eb04fb9e6607af534fa415542e7cbf24cd')

    def test_04_clean_fixture_passes(self):
        summary = r.reconcile(fixture())
        self.assertEqual(summary['model_demo_case_count'],29)
        self.assertEqual(summary['model_case_capacity'],54)

    def test_05_no_false_full_coverage(self):
        self.assertEqual(r.reconcile(fixture())['remaining_capacity_not_demonstrated'],25)

    def test_06_no_false_case_binding(self):
        self.assertIs(r.reconcile(fixture())['per_case_cross_contract_identity_attested'],False)

    def test_07_no_false_a5_evidence(self):
        self.assertEqual(r.reconcile(fixture())['a5_physical_attempts_accredited'],0)

    def test_08_no_false_a9(self):
        self.assertIsNone(r.reconcile(fixture())['published_generation'])

    def test_09_p8_no_go(self):
        self.assertEqual(r.reconcile(fixture())['p8_operational'],'NO-GO')

    def test_10_missing_component(self):
        data=fixture(); del data['R58V']
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_11_extra_component(self):
        data=fixture(); data['EVIL']={}
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_12_bad_k_count(self):
        data=fixture();data['R58K']['unit_count']=54
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_13_bad_k_family_count(self):
        data=fixture();data['R58K']['covered_family_count']=26
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_14_bad_service_count(self):
        data=fixture();data['R58K']['count_by_service']['FTP_DEV']=9
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_15_bad_decision_count(self):
        data=fixture();data['R58K']['decisions'].pop()
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_16_duplicate_decision(self):
        data=fixture();data['R58K']['decisions'][1]=copy.deepcopy(data['R58K']['decisions'][0])
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_17_false_technical_result(self):
        data=fixture();data['R58K']['decisions'][0]['a6_classification']='POSITIVO_VALIDO'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_18_missing_conservative_pause(self):
        data=fixture();data['R58K']['decisions'][0]['a8_recommendation']='CONTINUAR'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_19_fake_risk_published(self):
        data=fixture();data['R58K']['confirmed_final_risk']='1'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_20_v_real_attempt_blocked(self):
        data=fixture();data['R58V']['a5_attempts_started']=1
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_21_v_source_changed(self):
        data=fixture();data['R58V']['source_t1_unchanged']=False
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_22_v_handoff_not_verified(self):
        data=fixture();data['R58V']['handoff_verification']='PASS'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_23_o_missing_a10(self):
        data=fixture();data['R58O']['stages'].pop()
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_24_o_false_complete(self):
        data=fixture();data['R58O']['a1_a10_implementation_complete']=True
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_25_o_false_link(self):
        data=fixture();data['R58O']['independent_physical_case_binding_attested']=True
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_26_o_false_generation(self):
        data=fixture();data['R58O']['published_generation']='1'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_27_json_duplicate_key_rejected(self):
        with self.assertRaises(r.Blocked):r.strict_json(b'{"x":1,"x":2}')

    def test_28_json_nan_rejected(self):
        with self.assertRaises(r.Blocked):r.strict_json(b'{"x":NaN}')

    def test_29_json_invalid_utf8(self):
        with self.assertRaises(r.Blocked):r.strict_json(b'\xff')

    def test_30_json_output_limit(self):
        with self.assertRaises(r.Blocked):r.strict_json(b'a'*(r.MAX_OUTPUT+1))

    def test_31_json_array_rejected(self):
        with self.assertRaises(r.Blocked):r.strict_json(b'[]')

    def test_32_canonical_deterministic(self):
        self.assertEqual(r.canonical({'b':1,'a':2}),r.canonical({'a':2,'b':1}))

    def test_33_digest_reproducible(self):
        self.assertEqual(r.sha(b'x'),r.sha(b'x'))

    def test_34_source_only_three_offline_commands(self):
        text=SOURCE.read_text()
        self.assertIn("'--synthetic-offline'",text)
        for bad in ('virsh start','systemctl start','nft -f','sudo -n','systemctl restart'):
            self.assertNotIn(bad,text)

    def test_35_write_once(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)
            r.write_once(p,'receipt.json',b'x')
            with self.assertRaises(FileExistsError):r.write_once(p,'receipt.json',b'y')

    def test_36_no_parent_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(r.Blocked):r.write_once(Path(td),'../evil',b'x')

    def test_37_unexpected_repo_path(self):
        with self.assertRaises(r.Blocked):r.validate_checkout(Path('/tmp'))

    def test_38_non_root_required(self):
        with patch.object(r.os,'geteuid',return_value=0):
            self.assertEqual(r.main(['--run']),23)

    def test_39_explicit_mode_required(self):
        self.assertEqual(r.main([]),23)

    def test_40_source_manifest_sha(self):
        docs=fixture()
        pins={script:{'git_blob_sha1':'a'*40,'sha256':'b'*64}
              for _,script in r.DEMOS}
        report=r.build_report(pins, docs)
        self.assertEqual(report['p8_operational'],'NO-GO')
        self.assertEqual(len(report['components']),3)

    def test_41_source_sha_forged(self):
        data=fixture();data['R58K']['sha256']='nothex'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_42_v_p8_override(self):
        data=fixture();data['R58V']['p8_operational']='GO'
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_43_o_operational_dispatch(self):
        data=fixture();data['R58O']['operational_dispatch']=True
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_44_o_self_claim_evaluation(self):
        data=fixture();data['R58O']['experimental_hypothesis_validated']=True
        with self.assertRaises(r.Blocked):r.reconcile(data)

    def test_45_zero_vm_sources(self):
        text=SOURCE.read_text()
        self.assertNotIn('libvirt.open',text)
        self.assertNotIn('paramiko',text)
        self.assertNotIn('ftplib',text)
        self.assertNotIn('smbclient',text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
