"""R58-K end-to-end source-only A6 -> A7 -> A8 synthetic coordinator tests."""
from __future__ import annotations

from copy import deepcopy
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from ardrec.analytics.exact_preview import digest
from ardrec.coordination import r58k_unified_family_bridge as m
from ardrec.evidence import r58h_ssh_family_logic as ssh
from ardrec.evidence import r58i_ftp_family_logic as ftp
from ardrec.evidence import r58j_smb_family_logic as smb
from scripts import ardrec_p14_r58k_unified_family_demo as demo


class UnifiedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # In a real checkout the original byte-pinned P7 catalogue is mandatory.
        # A reconstructed scratch test environment may use explicit test specs;
        # production code has no such fallback.
        cls.patches=[]
        if not ssh.CATALOG_PATH.exists():
            from test_p14_r58h_ssh_family_logic import specs as ssh_specs
            from test_p14_r58i_ftp_family_logic import specs as ftp_specs
            from test_p14_r58j_smb_family_logic import specs as smb_specs
            lookups=(
                (ssh, 'load_pinned_catalog', lambda: ssh._specs(ssh_specs())),
                (ftp, 'load_pinned_ftp_catalog', lambda: ftp._specs(ftp_specs())),
                (smb, 'load_pinned_smb_catalog', lambda: smb._specs(smb_specs())),
                (demo, 'load_pinned_catalog', lambda: ssh._specs(ssh_specs())),
                (demo, 'load_pinned_ftp_catalog', lambda: ftp._specs(ftp_specs())),
                (demo, 'load_pinned_smb_catalog', lambda: smb._specs(smb_specs())),
            )
            for obj, name, fn in lookups:
                p=patch.object(obj,name,side_effect=fn)
                p.start()
                cls.patches.append(p)
        cls.inputs=demo.synthetic_unified_inputs()

    @classmethod
    def tearDownClass(cls):
        for p in reversed(cls.patches):p.stop()

    def build(self, cases=None, *, weights=('1/3','1/3','1/3')):
        return m.build_unified_preview(deepcopy(self.inputs if cases is None else cases), weights=weights)

    def sample(self, service):
        return deepcopy(next(x for x in self.inputs if x['service_id']==service))

    def bad(self, change):
        v=deepcopy(self.inputs);change(v)
        with self.assertRaises((ValueError,TypeError,KeyError)):
            m.build_unified_preview(v)

    def test_full_29_cases_and_25_families(self):
        r=self.build()
        self.assertEqual(r['unit_count'],29)
        self.assertEqual(r['covered_family_count_in_batch'],25)
        self.assertEqual(r['supported_family_count'],25)
        self.assertEqual(r['count_by_service'],{'SSH_DEV':8,'FTP_DEV':10,'SMB_DEV':11})
        self.assertEqual(len({d['family_id'] for d in r['decisions']}),25)
        self.assertEqual(len({d['case_id_a7'] for d in r['decisions']}),29)

    def test_all_protocols_linked(self):
        r=self.build()
        self.assertEqual(set(r['protocol_reports']),set(m.SERVICES))
        for service, report in r['protocol_reports'].items():
            self.assertIsInstance(report,dict)
            self.assertEqual(report['source_catalog_sha256'],m.CATALOG_SHA256)
            self.assertEqual(report['a6_classification'],'ND')
            self.assertEqual(report['p8_operational'],'NO-GO')

    def test_report_reproducible(self):
        r=self.build();self.assertTrue(m.verify_unified_preview(r))
        self.assertEqual(r,self.build())

    def test_permutation_invariance(self):
        self.assertEqual(self.build(),self.build(list(reversed(self.inputs))))

    def test_synthetic_positive_is_not_a6_truth(self):
        r=self.build()
        self.assertTrue(any(d['hypothetical_result_class']=='POSITIVO_VALIDO' for d in r['decisions']))
        self.assertTrue(all(d['a6_classification']=='ND' and
                            d['technical_truth_accredited'] is False and
                            d['technical_contribution'] is None and
                            d['confirmed_rf'] is None for d in r['decisions']))

    def test_negative_is_not_proof_of_zero(self):
        r=self.build()
        neg=[d for d in r['decisions'] if d['hypothetical_result_class']=='NEGATIVO_VALIDO']
        self.assertTrue(neg)
        self.assertTrue(all(d['a7_rf_upper']=='7/12' and d['a7_rf_lower']=='1/4' for d in neg))

    def test_unknown_is_full_interval(self):
        r=self.build()
        for d in r['decisions']:
            self.assertEqual((d['a7_rf_lower'],d['a7_rf_upper']),('1/4','7/12'))
            self.assertEqual(d['a8_recommendation'],'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA')

    def test_no_promotion_or_dispatch(self):
        r=self.build()
        self.assertEqual(r['a6_classification'],'ND')
        self.assertEqual(r['p8_operational'],'NO-GO')
        self.assertTrue(r['all_a6_nd'])
        self.assertIs(r['technical_truth_accredited'],False)
        self.assertIs(r['operational_dispatch'],False)
        self.assertIs(r['vm_checks_executed'],False)
        self.assertEqual(r['host_mutations'],0)
        for field in ('confirmed_final_risk','applied_state_transition','published_generation'):
            self.assertIsNone(r[field])

    def test_bridge_no_fake_admissions(self):
        r=self.build();b=r['a6_a7_a8_bridge']
        self.assertEqual(b['a6_inputs'],[])
        self.assertEqual(b['documentary_admission_count'],0)
        self.assertEqual(b['unit_count'],29)
        self.assertEqual(len(b['a7']['results']),29)

    def test_bridge_risk_units_empty_evidence(self):
        r=self.build()
        self.assertTrue(all(u['evidence']==[] for u in r['a6_a7_a8_bridge']['inputs']))
        self.assertTrue(all(v['evidence']==[{'evidence_id':'E_A6_UNRESOLVED',
                     'kind':'UNRESOLVED','lower':'0','upper':'1'}]
                     for v in r['a6_a7_a8_bridge']['a7']['inputs']))

    def test_binding_unique_full_identity(self):
        r=self.build();byrisk={(v['service_id'],v['case_id'],v['assessment_index'])
            for v in r['a6_a7_a8_bridge']['inputs']}
        self.assertEqual({(d['service_id'],d['case_id_a7'],d['assessment_index'])
                        for d in r['decisions']},byrisk)

    def test_hash_is_domain_separated_and_safe_for_a7(self):
        x=self.inputs[0]
        key=m._key(x['service_id'],x['unit'])
        cid=m._case_id(key)
        self.assertRegex(cid,r'^CASE_[A-F0-9]{48}$')
        self.assertNotEqual(cid,x['unit']['derived_case_id'])
        self.assertNotEqual(m._case_id((key[0],'OTHER',key[2],key[3])),cid)
        self.assertNotEqual(m._case_id((key[0],key[1],key[2],key[3]+1)),cid)

    def test_sparse_ssh_only(self):
        r=self.build([self.sample('SSH_DEV')])
        self.assertEqual(r['count_by_service'],{'SSH_DEV':1,'FTP_DEV':0,'SMB_DEV':0})
        self.assertIsNone(r['protocol_reports']['FTP_DEV'])
        self.assertIsNone(r['protocol_reports']['SMB_DEV'])

    def test_sparse_ftp_only(self):
        self.assertEqual(self.build([self.sample('FTP_DEV')])['unit_count'],1)

    def test_sparse_smb_only(self):
        self.assertEqual(self.build([self.sample('SMB_DEV')])['unit_count'],1)

    def test_one_case_each(self):
        r=self.build([self.sample(s) for s in m.SERVICES])
        self.assertEqual(r['unit_count'],3)
        self.assertEqual(r['covered_family_count_in_batch'],3)

    def test_maximum_54(self):
        many=deepcopy(self.inputs)
        for e in self.inputs[:25]:
            v=deepcopy(e);v['unit']['assessment_index']=1;many.append(v)
        self.assertEqual(self.build(many)['unit_count'],54)

    def test_reject_55(self):
        many=deepcopy(self.inputs)
        for e in self.inputs[:26]:
            v=deepcopy(e);v['unit']['assessment_index']=1;many.append(v)
        with self.assertRaisesRegex(ValueError,'ENVELOPE_COUNT'):
            self.build(many)

    def test_reject_empty(self):
        with self.assertRaisesRegex(ValueError,'ENVELOPE_COUNT'):self.build([])

    def test_reject_not_list(self):
        with self.assertRaisesRegex(ValueError,'ENVELOPE_COUNT'):self.build({})

    def test_reject_extra_envelope_field(self):
        self.bad(lambda e:e[0].update({'claim_accredited':True}))

    def test_reject_missing_envelope_field(self):
        self.bad(lambda e:e[0].pop('risk'))

    def test_reject_unknown_service(self):
        self.bad(lambda e:e[0].update(service_id='LOCALHOST'))

    def test_reject_wrong_service_family(self):
        self.bad(lambda e:e[0].update(service_id='FTP_DEV'))

    def test_reject_extra_risk_field(self):
        self.bad(lambda e:e[0]['risk'].update(evidence=[{'kind':'SYNTHETIC_FIXED'}]))

    def test_reject_risk_truth_field(self):
        self.bad(lambda e:e[0]['risk'].update(technical_truth_accredited=True))

    def test_reject_risk_nonnumeric(self):
        self.bad(lambda e:e[0]['risk'].update(initial_risk='NOT_A_FRACTION'))

    def test_reject_risk_invalid_order(self):
        self.bad(lambda e:e[0]['risk'].update(initial_risk='1/4',replacement_risk='1/2'))

    def test_reject_risk_outside_domain(self):
        self.bad(lambda e:e[0]['risk'].update(normalized_criticality='5/4'))

    def test_reject_risk_boolean(self):
        self.bad(lambda e:e[0]['risk'].update(initial_risk=True))

    def test_reject_risk_empty(self):
        self.bad(lambda e:e[0].update(risk={}))

    def test_reject_duplicate_case_window(self):
        self.bad(lambda e:e.append(deepcopy(e[0])))

    def test_distinct_sessions_do_not_mix(self):
        e=deepcopy(self.inputs[:1]);z=deepcopy(e[0]);z['unit']['session_id']='DEV_TUTOR_002';e.append(z)
        r=self.build(e)
        self.assertEqual(r['unit_count'],2)
        self.assertNotEqual(r['decisions'][0]['case_id_a7'],r['decisions'][1]['case_id_a7'])

    def test_distinct_assessments_do_not_mix(self):
        e=deepcopy(self.inputs[:1]);z=deepcopy(e[0]);z['unit']['assessment_index']=1;e.append(z)
        self.assertEqual(self.build(e)['unit_count'],2)

    def test_reject_duplicate_hash_case_id(self):
        e=deepcopy(self.inputs[:2]);e[1]['unit']['assessment_index']=1
        with patch.object(m,'_case_id',return_value='CASE_'+'A'*48):
            with self.assertRaisesRegex(ValueError,'HASHED_CASE_ID_COLLISION'):
                self.build(e)

    def test_reject_wrong_derived_id(self):
        self.bad(lambda e:e[0]['unit'].update(derived_case_id='FTP-T01-S01-01'))

    def test_reject_wrong_unit_format(self):
        self.bad(lambda e:e[0]['unit'].update(unexpected=True))

    def test_reject_unsupported_family(self):
        self.bad(lambda e:e[0]['unit'].update(family_id='SSH-T09'))

    def test_reject_boolean_assessment(self):
        self.bad(lambda e:e[0]['unit'].update(assessment_index=True))

    def test_reject_missing_case_identity(self):
        self.bad(lambda e:e[0]['unit'].pop('session_id'))

    def test_negative_requires_real_support_in_simulation(self):
        e=self.sample('SSH_DEV')
        e['unit']['outcome']='OBSERVADO_NEGATIVO'
        e['unit']['supports'].pop(next(iter(e['unit']['supports'])))
        self.assertNotEqual(self.build([e])['decisions'][0]['hypothetical_result_class'],'NEGATIVO_VALIDO')

    def test_false_guard_never_promotes(self):
        e=self.sample('FTP_DEV')
        e['unit']['preconditions']['SCOPE_APPROVED']='FALSO'
        r=self.build([e]);self.assertEqual(r['decisions'][0]['hypothetical_result_class'],'NO_ADMITIDO')
        self.assertEqual(r['decisions'][0]['a6_classification'],'ND')

    def test_failed_cleanup_in_smb_is_incident(self):
        e=next(deepcopy(v) for v in self.inputs if v['unit']['family_id']=='SMB-T08')
        e['unit']['cleanup']='FALSO'
        e['unit']['supports']['CLEANUP_CONFIRMED']='FALSO'
        r=self.build([e]);self.assertEqual(r['decisions'][0]['hypothetical_result_class'],'INCIDENCIA')
        self.assertEqual(r['decisions'][0]['a6_classification'],'ND')

    def test_ftp_tls_variants_distinct(self):
        r=self.build([x for x in self.inputs if x['unit']['family_id']=='FTP-T02'])
        self.assertEqual(len(r['decisions']),2)
        self.assertEqual({x['variant'] for x in r['decisions']},{'CONTROL','DATA'})
        self.assertEqual({x['precedence'] for x in r['decisions']},{1,3})

    def test_ftp_access_variants_distinct(self):
        r=self.build([x for x in self.inputs if x['unit']['family_id']=='FTP-T08'])
        self.assertEqual({x['variant'] for x in r['decisions']},{'READ','WRITE'})
        self.assertEqual({x['precedence'] for x in r['decisions']},{3,4})

    def test_smb_protection_variants_distinct(self):
        r=self.build([x for x in self.inputs if x['unit']['family_id']=='SMB-T03'])
        self.assertEqual({x['variant'] for x in r['decisions']},{'SIGNING','ENCRYPTION'})
        self.assertEqual({x['precedence'] for x in r['decisions']},{3})

    def test_smb_access_variants_distinct(self):
        r=self.build([x for x in self.inputs if x['unit']['family_id']=='SMB-T09'])
        self.assertEqual({x['variant'] for x in r['decisions']},{'READ','WRITE'})
        self.assertEqual({x['precedence'] for x in r['decisions']},{3,4})

    def test_reject_ftp_variant_reused_case_id(self):
        e=[deepcopy(x) for x in self.inputs if x['unit']['family_id']=='FTP-T02']
        e[1]['unit']['derived_case_id']=e[0]['unit']['derived_case_id']
        with self.assertRaisesRegex(ValueError,'DUPLICATE_CASE_WINDOW'):
            self.build(e)

    def test_reject_smb_variant_reused_case_id(self):
        e=[deepcopy(x) for x in self.inputs if x['unit']['family_id']=='SMB-T03']
        e[1]['unit']['derived_case_id']=e[0]['unit']['derived_case_id']
        with self.assertRaisesRegex(ValueError,'DUPLICATE_CASE_WINDOW'):
            self.build(e)

    def test_distinct_derived_id_across_services(self):
        a=self.sample('SSH_DEV');b=self.sample('FTP_DEV')
        self.assertNotEqual(self.build([a,b])['decisions'][0]['case_id_a7'],
                            self.build([a,b])['decisions'][1]['case_id_a7'])

    def test_no_bare_user_evidence(self):
        self.bad(lambda e:e[0]['unit'].update(evidence=[]))

    def test_report_invalid_type(self):
        with self.assertRaises(ValueError):m.verify_unified_preview('')

    def test_report_invalid_digest(self):
        r=self.build();r['sha256']='0'*64
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_fake_a6_truth(self):
        r=self.build();r['a6_classification']='VERDADERO'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_fake_risk(self):
        r=self.build();r['confirmed_final_risk']='1/4'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_fake_transition(self):
        r=self.build();r['applied_state_transition']='ACTUALIZADO'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_fake_publication(self):
        r=self.build();r['published_generation']=42
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_fake_pin(self):
        r=self.build();r['source_catalog_sha256']='a'*64
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_fake_p8_go(self):
        r=self.build();r['p8_operational']='GO'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_nested_fake_a7(self):
        r=self.build();r['a6_a7_a8_bridge']['a7']['results'][0]['rf_lower']='1'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_nested_fake_class(self):
        r=self.build();r['protocol_reports']['SSH_DEV']['decisions'][0]['a6_classification']='FALSO'
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_report_rehashed_hypothetical_not_real(self):
        r=self.build();r['decisions'][0]['technical_truth_accredited']=True
        r['sha256']=digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(ValueError):m.verify_unified_preview(r)

    def test_risk_changes_are_not_a6_evidence(self):
        e=self.sample('SSH_DEV');e['risk']['initial_risk']='1/2';e['risk']['replacement_risk']='1/2'
        r=self.build([e]);self.assertIsNone(r['confirmed_final_risk'])
        self.assertEqual(r['a6_a7_a8_bridge']['a7']['inputs'][0]['evidence'][0]['upper'],'1')

    def test_weights_enforced_simplex(self):
        with self.assertRaises(ValueError):self.build(weights=('1/2','1/2','1/2'))

    def test_weights_canonical(self):
        r=self.build(weights=('1/2','1/4','1/4'))
        self.assertEqual(r['weights'],['1/2','1/4','1/4'])
        self.assertTrue(m.verify_unified_preview(r))

    def test_no_network_or_host_actions_in_source(self):
        src=__import__('inspect').getsource(m)
        for banned in ('subprocess.run(', 'socket.', 'libvirt.', 'systemctl', 'nft add', 'os.system('):
            self.assertNotIn(banned,src)

    def test_thesis_catalog_identity(self):
        self.assertEqual(m.CATALOG_SHA256,'5161cdfc3c88281adbf21b839b40b12f92298d5a58f650ad761c0c6dbe16f88e')
        self.assertEqual(m.THESIS_SHA256,'6a6d2d7889a683e459da46559c03dcd62616141b39f0d2680542f0e744c46c72')

    def test_cli_in_process_synthetic_summary(self):
        import io
        from contextlib import redirect_stdout
        with patch.object(sys, 'argv', ['r58k-demo', '--synthetic-offline']):
            output=io.StringIO()
            with redirect_stdout(output):
                rc=demo.main()
        self.assertEqual(rc,0)
        doc=json.loads(output.getvalue())
        self.assertEqual(doc['unit_count'],29)
        self.assertEqual(doc['covered_family_count'],25)
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertIsNone(doc['confirmed_final_risk'])
        self.assertEqual(len(doc['decisions']),29)

    def test_cli_requires_explicit_offline_flag(self):
        import io
        from contextlib import redirect_stderr
        with patch.object(sys,'argv',['r58k-demo']):
            output=io.StringIO()
            with redirect_stderr(output):
                rc=demo.main()
        self.assertEqual(rc,23)
        self.assertIn('NO-GO',output.getvalue())

    def test_demo_real_pinned_catalog(self):
        if not ssh.CATALOG_PATH.exists():
            self.skipTest('Temporary fixture has no authoritative P7 catalogue')
        cmd=[sys.executable,'-B','scripts/ardrec_p14_r58k_unified_family_demo.py','--synthetic-offline']
        env=__import__('os').environ.copy();env['PYTHONPATH']='src'
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=20,env=env)
        self.assertEqual(p.returncode,0,msg=p.stderr)
        doc=json.loads(p.stdout)
        self.assertEqual(doc['unit_count'],29)
        self.assertEqual(doc['covered_family_count'],25)
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertIsNone(doc['confirmed_final_risk'])


if __name__=='__main__':
    unittest.main()
