"""P8-R30 adversarial acceptance-oracle tests; synthetic, no system interaction."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import p8_r30_synthetic_acceptance as r30

ROOT=Path(__file__).resolve().parents[2]
SPEC=json.loads((ROOT/'lab/p8-r30-synthetic-acceptance-v1/spec.json').read_text())


def sample_r29():
    padded=[{'profile_id':f'SSH-T{i:02d}-BASE'} for i in range(1,9)]
    for row in SPEC['profiles']:
        padded.append({'profile_id':row['profile_id'],'protocol':row['protocol'],
            'operation_id':row['operation_id'],
            'required_acceptance_supports':list(row['acceptance_supports']),
            'cleanup_contract':row['cleanup_contract'],
            'write_variant':row['write_variant'],'authorization':'DENIED',
            'argv_renderable':False,'dispatch_allowed':False,
            'material_fields_unbound':[f'FIELD_{i}' for i in range(12)]})
    return tuple(padded)


def vector(row, outcome='PASS_SYNTHETIC'):
    return {'schema_version':'1.0','profile_id':row['profile_id'],
        'origin':r30.SYNTHETIC_ORIGIN,
        'observations':[{'support_id':s,'outcome':outcome}
                        for s in row['acceptance_supports']],
        'runtime_capability_asserted':False,'case_authorization_asserted':False,
        'dispatch_asserted':False}


class SyntheticAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.legacy=sample_r29()
        cls.catalog=r30.build_catalog(cls.legacy,SPEC)

    def reject_spec(self,mutate):
        s=copy.deepcopy(SPEC);mutate(s)
        with self.assertRaises(r30.Rejected):r30.build_catalog(self.legacy,s)

    def reject_legacy(self,mutate):
        r=copy.deepcopy(self.legacy);mutate(r)
        with self.assertRaises(r30.Rejected):r30.build_catalog(r,SPEC)

    def test_catalog_exact_counts(self):
        self.assertEqual(len(self.catalog),21)
        self.assertEqual(r30.summarize(self.catalog)['protocol_counts'],{'ftp':10,'smb':11})
        self.assertEqual(r30.summarize(self.catalog)['write_variants'],4)

    def test_all_synthetic_positive_never_authorize(self):
        for row in self.catalog:
            with self.subTest(id=row['profile_id']):
                out=r30.evaluate_synthetic(self.catalog,vector(row))
                self.assertEqual(out['decision'],'DENY')
                self.assertTrue(out['synthetic_all_positive'])
                self.assertEqual(out['proof_gates_closed'],0)
                self.assertEqual(out['material_bindings_completed'],0)
                self.assertIsNone(out['argv'])
                self.assertFalse(out['spawn'])

    def test_all_synthetic_negative_never_authorize(self):
        for row in self.catalog:
            out=r30.evaluate_synthetic(self.catalog,vector(row,'FAIL_SYNTHETIC'))
            self.assertTrue(out['synthetic_negative'])
            self.assertEqual(out['classification'],'SYNTHETIC_NEGATIVE_ORACLE')
            self.assertEqual(out['decision'],'DENY')

    def test_all_nd_never_authorize(self):
        for row in self.catalog:
            out=r30.evaluate_synthetic(self.catalog,vector(row,'ND_SYNTHETIC'))
            self.assertEqual(out['classification'],'SYNTHETIC_ND_ORACLE')
            self.assertFalse(out['synthetic_all_positive'])

    def test_ftp_data_requires_distinct_correlation(self):
        c=next(x for x in self.catalog if x['profile_id']=='FTP-T02-CONTROL')
        d=next(x for x in self.catalog if x['profile_id']=='FTP-T02-DATA')
        self.assertNotIn('CONTROL_DATA_CORRELATION',c['acceptance_supports'])
        self.assertIn('CONTROL_DATA_CORRELATION',d['acceptance_supports'])

    def test_smb_signing_distinct_encryption(self):
        s=next(x for x in self.catalog if x['profile_id']=='SMB-T03-SIGNING')
        e=next(x for x in self.catalog if x['profile_id']=='SMB-T03-ENCRYPTION')
        self.assertIn('SMB_SIGNATURE',s['acceptance_supports'])
        self.assertNotIn('SMB_ENCRYPTION',s['acceptance_supports'])
        self.assertIn('SMB_ENCRYPTION',e['acceptance_supports'])
        self.assertNotIn('SMB_SIGNATURE',e['acceptance_supports'])

    def test_all_four_writes_require_cleanup(self):
        self.assertEqual({x['profile_id'] for x in self.catalog if x['write_variant']},r30.WRITES)
        for row in self.catalog:
            if row['write_variant']:
                self.assertIn('CLEANUP_CONFIRMED',row['acceptance_supports'])

    def test_positive_write_with_nd_cleanup_is_not_positive(self):
        for row in self.catalog:
            if row['write_variant']:
                v=vector(row)
                next(x for x in v['observations'] if x['support_id']=='CLEANUP_CONFIRMED')['outcome']='ND_SYNTHETIC'
                out=r30.evaluate_synthetic(self.catalog,v)
                self.assertEqual(out['classification'],'SYNTHETIC_ND_ORACLE')
                self.assertFalse(out['synthetic_cleanup_positive'])

    def test_positive_write_with_failed_cleanup_is_negative(self):
        for row in self.catalog:
            if row['write_variant']:
                v=vector(row)
                next(x for x in v['observations'] if x['support_id']=='CLEANUP_CONFIRMED')['outcome']='FAIL_SYNTHETIC'
                out=r30.evaluate_synthetic(self.catalog,v)
                self.assertEqual(out['classification'],'SYNTHETIC_NEGATIVE_ORACLE')

    def test_reject_extra_vector_command(self):
        v=vector(self.catalog[0]);v['argv']=['curl']
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_runtime_capability_claim(self):
        v=vector(self.catalog[0]);v['runtime_capability_asserted']=True
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_case_authorization_claim(self):
        v=vector(self.catalog[0]);v['case_authorization_asserted']=True
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_dispatch_claim(self):
        v=vector(self.catalog[0]);v['dispatch_asserted']=True
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_real_evidence_origin(self):
        v=vector(self.catalog[0]);v['origin']='REAL_QCOW2_EVIDENCE'
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_unsupported_status_token(self):
        v=vector(self.catalog[0]);v['observations'][0]['outcome']='PASS'
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_boolean_outcome(self):
        v=vector(self.catalog[0]);v['observations'][0]['outcome']=True
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_duplicate_support_observation(self):
        row=self.catalog[1];v=vector(row)
        v['observations'][0]=copy.deepcopy(v['observations'][1])
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_permuted_observation_order(self):
        v=vector(self.catalog[1]);v['observations'].reverse()
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_extra_observation(self):
        v=vector(self.catalog[0]);v['observations'].append({'support_id':'UNKNOWN','outcome':'PASS_SYNTHETIC'})
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_missing_observation(self):
        v=vector(self.catalog[0]);v['observations'].pop()
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_injected_field_inside_observation(self):
        v=vector(self.catalog[0]);v['observations'][0]['secret']='abc'
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_unknown_profile(self):
        v=vector(self.catalog[0]);v['profile_id']='FTP-T99-BASE'
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_ssh_profile(self):
        v=vector(self.catalog[0]);v['profile_id']='SSH-T07-BASE'
        with self.assertRaises(r30.Rejected):r30.evaluate_synthetic(self.catalog,v)

    def test_reject_spec_missing_profile(self):
        self.reject_spec(lambda s:s['profiles'].pop())

    def test_reject_spec_reordered_profile(self):
        self.reject_spec(lambda s:s['profiles'].reverse())

    def test_reject_spec_false_safety(self):
        self.reject_spec(lambda s:s.update(dispatch_allowed=True))

    def test_reject_spec_tampered_operation(self):
        self.reject_spec(lambda s:s['profiles'][0].update(operation_id='OTHER'))

    def test_reject_spec_wrong_protocol(self):
        self.reject_spec(lambda s:s['profiles'][0].update(protocol='smb'))

    def test_reject_ftp_tls_promotion(self):
        self.reject_spec(lambda s:s['profiles'][1]['acceptance_supports'].append('CONTROL_DATA_CORRELATION'))

    def test_reject_smb_signing_to_encryption(self):
        self.reject_spec(lambda s:s['profiles'][12]['acceptance_supports'].__setitem__(1,'SMB_ENCRYPTION'))

    def test_reject_loss_of_write_cleanup(self):
        self.reject_spec(lambda s:s['profiles'][7]['acceptance_supports'].remove('CLEANUP_CONFIRMED'))

    def test_reject_read_profile_marked_write(self):
        self.reject_spec(lambda s:s['profiles'][8].update(write_variant=True))

    def test_reject_upstream_binding_material_promoted(self):
        self.reject_legacy(lambda r:r[8]['material_fields_unbound'].clear())

    def test_reject_upstream_dispatch_promoted(self):
        self.reject_legacy(lambda r:r[8].update(dispatch_allowed=True))

    def test_reject_upstream_support_modified(self):
        self.reject_legacy(lambda r:r[8]['required_acceptance_supports'].append('UNTRUSTED'))

if __name__=='__main__':unittest.main()
