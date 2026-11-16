"""R58-E unit tests: strict A6 documentary identity and A7/A8 ND boundaries."""
from __future__ import annotations
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from ardrec.analytics.exact_preview import digest
from ardrec.coordination.r58e_evidence_risk_bridge import (
    build_unit_bridge, verify_unit_bridge, BridgeError,
)
from scripts.ardrec_p14_r58e_unit_bridge import synthetic_units


def admission(rid='DEV-SSH-0001', claim='INCONCLUSIVE'):
    doc = {
        'schema': 'ardrec-p14-r37-a6-defensive-observation-v1',
        'admission': 'ACCEPTED_FOR_DOCUMENTARY_REVIEW',
        'record_id': rid, 'session_id': 'DEV_TUTOR_001',
        'service_id': 'SSH_DEV', 'case_id': 'CASE_REFERENCE',
        'source_kind': 'SYNTHETIC_FIXTURE',
        'method_id': 'SSH_EFFECTIVE_CONFIG_READONLY',
        'captured_at_utc': '2026-11-14T19:59:00Z',
        'review_as_of_utc': '2026-11-14T20:00:00Z',
        'observed_claim_unverified': claim,
        'configuration_sha256_declared': 'a'*64,
        'support_sha256_verified': 'b'*64,
        'receipt_sha256': 'c'*64,
        'provenance_independently_attested': False,
        'classification': 'ND', 'technical_truth_accredited': False,
        'confirmed_rf': None,
        'reason': 'SUPPORT_INTEGRITY_ONLY_INDEPENDENT_REVIEW_PENDING',
    }
    doc['sha256'] = digest(doc)
    return doc


def fresh(doc):
    doc['sha256'] = digest({k:v for k,v in doc.items() if k!='sha256'})
    return doc


class TestR58EBridge(unittest.TestCase):
    def setUp(self):
        self.units = synthetic_units()
        self.a6 = admission()
        self.doc = build_unit_bridge(self.units, [self.a6])

    def test_synthetic_cli_end_to_end(self):
        repo=Path(__file__).resolve().parents[2]
        env=dict(os.environ)
        env['PYTHONPATH']=str(repo/'src')
        cp=subprocess.run([sys.executable,'-B',str(repo/'scripts/ardrec_p14_r58e_unit_bridge.py'),
                           '--synthetic-offline'],cwd=repo,env=env,
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=20,check=False)
        self.assertEqual(cp.returncode,0,cp.stdout.decode('utf-8','replace')+cp.stderr.decode('utf-8','replace'))
        doc=json.loads(cp.stdout)
        self.assertEqual(doc['unit_count'],3)
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertTrue(verify_unit_bridge(doc))

    def test_round_trip(self):
        self.assertTrue(verify_unit_bridge(self.doc))
    def test_three_units(self):
        self.assertEqual(self.doc['unit_count'],3)
    def test_only_ssh_has_admission(self):
        self.assertEqual(self.doc['documentary_admission_count'],1)
        self.assertEqual(self.doc['missing_documentary_admission_count'],2)
        ssh=next(u for u in self.doc['decisions'] if u['service_id']=='SSH_DEV')
        self.assertEqual(ssh['a6_admission_sha256'],self.a6['sha256'])
    def test_inconclusive_is_not_contribution(self):
        self.assertTrue(all(r['a7_interval_source']=='MATHEMATICAL_ONLY_FULL_UNRESOLVED' for r in self.doc['decisions']))
        self.assertTrue(all(r['a7_rf_lower']=='1/4' and r['a7_rf_upper']=='7/12' for r in self.doc['decisions']))
    def test_claim_match_does_not_accredit(self):
        doc=build_unit_bridge(self.units,[admission(claim='MATCH')])
        self.assertFalse(doc['technical_truth_accredited'])
        self.assertIsNone(doc['confirmed_final_risk'])
        self.assertEqual(doc['decisions'][2]['a6_observed_claim_unverified'],'MATCH')
    def test_claim_diff_does_not_accredit(self):
        doc=build_unit_bridge(self.units,[admission(claim='DIFF')])
        self.assertIsNone(doc['decisions'][2]['confirmed_rf'])
    def test_no_admissions_means_full_unresolved(self):
        d=build_unit_bridge(self.units,[])
        self.assertEqual(d['missing_documentary_admission_count'],3)
        self.assertTrue(all(r['a7_rf_upper']=='7/12' for r in d['decisions']))
    def test_a8_only_recommendation(self):
        for d in self.doc['decisions']:
            self.assertEqual(d['a8_recommendation'],'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')
            self.assertIsNone(d['a8_applied_transition'])
            self.assertIsNone(d['confirmed_phase'])
    def test_a9_unpublished(self):
        self.assertIsNone(self.doc['published_generation'])
        self.assertIsNone(self.doc['applied_state_transition'])
    def test_no_execution(self):
        self.assertIs(self.doc['operational_dispatch'],False)
        self.assertIs(self.doc['vm_checks_executed'],False)
        self.assertEqual(self.doc['p8_operational'],'NO-GO')
    def test_deterministic(self):
        self.assertEqual(self.doc,build_unit_bridge(self.units,[self.a6]))
    def test_permutation_invariant(self):
        self.assertEqual(self.doc,build_unit_bridge(list(reversed(self.units)),[self.a6]))
    def test_no_input_units(self):
        with self.assertRaises(BridgeError):build_unit_bridge([],[])
    def test_not_a_list(self):
        with self.assertRaises(BridgeError):build_unit_bridge({},[])
    def test_54_units(self):
        units=[{**self.units[0],'case_id':f'CASE_{i}'} for i in range(54)]
        d=build_unit_bridge(units,[])
        self.assertEqual(d['unit_count'],54)
        self.assertTrue(verify_unit_bridge(d))
    def test_55_units(self):
        units=[{**self.units[0],'case_id':f'CASE_{i}'} for i in range(55)]
        with self.assertRaises(BridgeError):build_unit_bridge(units,[])
    def test_no_forged_fixed_point(self):
        units=deepcopy(self.units)
        units[0]['evidence']=[{'evidence_id':'E_INJECTED','kind':'SYNTHETIC_FIXED','lower':'1/2','upper':'1/2'}]
        with self.assertRaisesRegex(BridgeError,'UNACCREDITED_A7_EVIDENCE_INJECTION'):build_unit_bridge(units,[])
    def test_no_forged_unresolved_input(self):
        units=deepcopy(self.units)
        units[0]['evidence']=[{'evidence_id':'E_UNKNOWN','kind':'UNRESOLVED','lower':'0','upper':'1'}]
        with self.assertRaisesRegex(BridgeError,'UNACCREDITED_A7_EVIDENCE_INJECTION'):build_unit_bridge(units,[])
    def test_missing_field(self):
        u=deepcopy(self.units);del u[0]['replacement_risk']
        with self.assertRaises(BridgeError):build_unit_bridge(u,[])
    def test_extra_field(self):
        u=deepcopy(self.units);u[0]['provenance_verified']=True
        with self.assertRaises(BridgeError):build_unit_bridge(u,[])
    def test_bool_index(self):
        u=deepcopy(self.units);u[0]['assessment_index']=True
        with self.assertRaises(ValueError):build_unit_bridge(u,[])
    def test_bad_fraction(self):
        u=deepcopy(self.units);u[0]['initial_risk']='0.25'
        with self.assertRaises(ValueError):build_unit_bridge(u,[])
    def test_duplicate_unit(self):
        with self.assertRaises(ValueError):build_unit_bridge([self.units[0],self.units[0]],[])
    def test_duplicate_record_id(self):
        with self.assertRaisesRegex(BridgeError,'A6_DUPLICATE_RECORD'):
            build_unit_bridge(self.units,[self.a6,self.a6])
    def test_duplicate_same_claim_different_id(self):
        with self.assertRaisesRegex(BridgeError,'A6_DUPLICATE_UNIT_ADMISSION'):
            build_unit_bridge(self.units,[self.a6,admission(rid='DEV-SSH-0002')])
    def test_conflict_different_claim(self):
        with self.assertRaisesRegex(BridgeError,'A6_CONFLICTING_CLAIMS'):
            build_unit_bridge(self.units,[self.a6,admission(rid='DEV-SSH-0002',claim='MATCH')])
    def test_unbound_admission(self):
        with self.assertRaisesRegex(BridgeError,'A6_UNBOUND_UNIT'):
            build_unit_bridge([self.units[1]], [self.a6])
    def test_ambiguous_window(self):
        u=deepcopy(self.units);u.append({**u[0],'assessment_index':1})
        with self.assertRaisesRegex(BridgeError,'A6_AMBIGUOUS_ASSESSMENT_WINDOW'):
            build_unit_bridge(u,[self.a6])
    def test_window_without_admission_is_allowed(self):
        u=deepcopy(self.units);u.append({**u[2],'assessment_index':1})
        self.assertEqual(build_unit_bridge(u,[])['unit_count'],4)
    def test_altered_hash(self):
        a=deepcopy(self.a6);a['observed_claim_unverified']='MATCH'
        with self.assertRaises(ValueError):build_unit_bridge(self.units,[a])
    def test_forged_accreditation_with_rehash(self):
        a=deepcopy(self.a6);a['technical_truth_accredited']=True;fresh(a)
        with self.assertRaises(ValueError):build_unit_bridge(self.units,[a])
    def test_forged_final_risk_with_rehash(self):
        a=deepcopy(self.a6);a['confirmed_rf']='1/2';fresh(a)
        with self.assertRaises(ValueError):build_unit_bridge(self.units,[a])
    def test_forged_provenance_with_rehash(self):
        a=deepcopy(self.a6);a['provenance_independently_attested']=True;fresh(a)
        with self.assertRaises(ValueError):build_unit_bridge(self.units,[a])
    def test_extra_admission_field_rehashed(self):
        a=deepcopy(self.a6);a['foo']='bar';fresh(a)
        with self.assertRaisesRegex(BridgeError,'A6_ADMISSION_SCHEMA_DRIFT'):
            build_unit_bridge(self.units,[a])
    def test_schema_wrong_rehash(self):
        a=deepcopy(self.a6);a['schema']='unknown';fresh(a)
        with self.assertRaises(ValueError):build_unit_bridge(self.units,[a])
    def test_admission_batch_max(self):
        with self.assertRaisesRegex(BridgeError,'A6_BATCH_SIZE'):
            build_unit_bridge(self.units,[self.a6]*17)
    def test_wrong_weights(self):
        with self.assertRaises(ValueError):build_unit_bridge(self.units,[],weights=('1/2','1/2','1/2'))
    def test_rehashed_forged_report(self):
        doc=deepcopy(self.doc);doc['decisions'][0]['confirmed_rf']='1/4';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_a8_transition(self):
        doc=deepcopy(self.doc);doc['decisions'][0]['a8_applied_transition']='T8';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_a7_point(self):
        doc=deepcopy(self.doc);doc['a7']['results'][0]['confirmed_rf']='1/4';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_p8(self):
        doc=deepcopy(self.doc);doc['p8_operational']='GO';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_a9(self):
        doc=deepcopy(self.doc);doc['published_generation']='GEN1';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_unit_key(self):
        doc=deepcopy(self.doc);doc['decisions'][0]['service_id']='SSH_DEV';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_missing_count(self):
        doc=deepcopy(self.doc);doc['missing_documentary_admission_count']=0;fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_claim(self):
        doc=deepcopy(self.doc);doc['decisions'][2]['a6_observed_claim_unverified']='MATCH';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)
    def test_rehashed_forged_interval(self):
        doc=deepcopy(self.doc);doc['decisions'][0]['a7_rf_upper']='1/4';fresh(doc)
        with self.assertRaises(BridgeError):verify_unit_bridge(doc)

if __name__=='__main__':unittest.main()
