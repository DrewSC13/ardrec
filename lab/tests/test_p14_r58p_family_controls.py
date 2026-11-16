"""R58-P: typed A2/A3 case-reference coordination, with real P7 integration."""
from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace as S
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO))
from ardrec.coordination import r58p_a3_family_controls as p

SCENARIO = {
    'format': 'ardrec-p14-r26-fixed-three-service-scenario-v1',
    'session_id': 'DEV_TUTOR_001',
    'services': [
        {'id': sid, 'protocol': proto, 'fact': fact,
         'initial_risk': '1/4', 'normalized_criticality': '1/2'}
        for sid, proto, fact in (
            ('SSH_DEV','SSH','VERDADERO'),
            ('FTP_DEV','FTP','AUSENTE'),
            ('SMB_DEV','SMB','FALSO'))
    ],
}


def fake_review():
    counts = {'SSH_DEV': 8, 'FTP_DEV': 10, 'SMB_DEV': 11}
    rows = []
    for sid, count in counts.items():
        for n in range(count):
            raw_case = sid[:3] + '-T%02d-S01-01' % (n + 1)
            rows.append({
                'service_id': sid, 'session_id': 'DEV_TUTOR_001',
                'derived_case_id': raw_case, 'assessment_index': 0,
                'case_id_a7': 'CASE_' + format(len(rows) + 1, '048X'),
                'family_id': raw_case[:7], 'variant': None,
                'a4_precedence': (n % 4) + 1,
                'a4_guard_simulated': 'VERDADERO',
                'a4_eligible_simulated': True,
                'a6_classification': 'ND',
                'technical_truth_accredited': False,
                'confirmed_rf': None, 'applied_transition': None,
                'published_generation': None,
            })
    return {
        'session_id': 'DEV_TUTOR_001', 'decisions': rows,
        'unit_count': 29, 'covered_family_count': 25,
        'sha256': 'b' * 64,
        'source_catalog_sha256': 'c' * 64,
        'source_thesis_sha256': 'd' * 64,
        'a6_classification': 'ND',
        'technical_truth_accredited': False,
        'confirmed_final_risk': None,
        'published_generation': None,
        'operational_dispatch': False,
        'p8_operational': 'NO-GO',
    }


class FakeSnapshot:
    def __init__(self, sha):
        self.sha256 = sha
    def verify(self, *args):
        return True


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.scenario = deepcopy(SCENARIO)
        self.review = fake_review()
        self.captured = {}

    def mocked(self):
        ctx = ExitStack()
        def apply(name, **kw):
            return ctx.enter_context(patch.object(p, name, **kw))
        apply('normalize_scenario', side_effect=lambda obj: obj)
        apply('verify_a4_a5_review', return_value=True)
        session = S(sha256='1'*64, document={
            'sources_sha256': {'rules': 'a'*64},
            'units': [{'service_id': sid,
                       'a1': {'status': status},
                       'a3': {'table_status': status,
                              'table_selected': selected}}
                      for sid, status, selected in (
                          ('SSH_DEV','VERDADERO','ALLOW'),
                          ('FTP_DEV','ND',None),
                          ('SMB_DEV','VERDADERO','DENY'))]},
                    verify=lambda: True)
        apply('build_development_session', return_value=session)
        apply('preflight_rule_configuration', return_value=FakeSnapshot('a'*64))

        def initial(rules, data):
            self.captured['initial'] = data
            return S(sha256='2'*64,
                     units=tuple(S(id=u['id'],phase=S(value='PREPARADO'),
                                   cases=tuple(S(starts_confirmed=0) for c in u['cases']))
                                 for u in data['services']))
        apply('prepare_initial_preview', side_effect=initial)
        apply('prepare_dependency_preview', side_effect=lambda *a: FakeSnapshot('3'*64))
        def controls(rules, initial, deps, data):
            self.captured['controls'] = data
            return FakeSnapshot('4'*64)
        apply('prepare_control_preview', side_effect=controls)
        apply('assemble_integrated_preview', return_value=FakeSnapshot('5'*64))

        def guards(rules, initial, deps, controls, integrated, environments):
            units = []
            for sv in self.captured['controls']['services']:
                sid = sv['id']
                fact = {'SSH_DEV':'VERDADERO', 'FTP_DEV':'ND',
                        'SMB_DEV':'FALSO'}[sid]
                status = 'ND' if sid == 'FTP_DEV' else 'VERDADERO'
                selected = {'SSH_DEV':'ALLOW','FTP_DEV':None,'SMB_DEV':'DENY'}[sid]
                details = []
                for c in sv['controls']:
                    blockers = ['AUTORIDAD_OPERACIONAL_NO_ACREDITADA']
                    if fact != 'VERDADERO':
                        blockers.insert(0, 'GUARDA_ND' if fact == 'ND' else 'GUARDA_FALSA')
                    details.append(S(target_case_id=c['target_case_id'],
                                     control_id=c['id'],guard_rule_id='ALLOW',
                                     truth=S(name=fact),blockers=tuple(blockers)))
                units.append(S(service_id=sid,table_status=S(name=status),
                               table_selected=selected,controls=tuple(details)))
            return S(sha256='6'*64,units=tuple(units),verify=lambda *a: True)
        apply('diagnose_guards', side_effect=guards)
        return ctx

    def build(self):
        with self.mocked():
            return p.build_family_a3_projection(self.scenario, self.review)

    def test_29_controls_25_families(self):
        result=self.build()
        self.assertEqual(result['control_reference_count'],29)
        self.assertEqual(result['family_count'],25)
        self.assertEqual(result['case_count_by_service'],
                         {'FTP_DEV':10,'SMB_DEV':11,'SSH_DEV':8})

    def test_trivalent_a3_counts(self):
        self.assertEqual(self.build()['a3_guard_truth_counts'],
                         {'VERDADERO':8,'FALSO':11,'ND':10})

    def test_projection_mismatches_21(self):
        self.assertEqual(self.build()['a3_a4_guard_mismatch_count'],21)

    def test_control_list_unique(self):
        rows=self.build()['control_cases']
        self.assertEqual(len({x['control_id_a3'] for x in rows}),29)

    def test_all_controls_block_operational_authority(self):
        for row in self.build()['control_cases']:
            self.assertIn('AUTORIDAD_OPERACIONAL_NO_ACREDITADA',row['a3_blockers'])
            self.assertFalse(row['operational_eligibility_attested'])

    def test_phase_is_prepared_not_assumed_pending(self):
        for row in self.build()['control_cases']:
            self.assertEqual(row['a3_phase'],'PREPARADO')
            self.assertEqual(row['a4_phase_assumed'],'PENDIENTE')

    def test_review_a6_remains_nd(self):
        r=self.build()
        self.assertEqual(r['a6_classification'],'ND')
        self.assertIsNone(r['confirmed_final_risk'])
        self.assertIsNone(r['applied_transition'])
        self.assertIsNone(r['published_generation'])
        self.assertFalse(r['operational_dispatch'])
        self.assertEqual(r['p8_operational'],'NO-GO')

    def test_case_refs_are_real_a2_inputs(self):
        self.build()
        raw=self.captured['initial']
        self.assertEqual(sum(len(x['cases']) for x in raw['services']),29)
        self.assertTrue(all(c['max_repetitions']==0
                            for s in raw['services'] for c in s['cases']))

    def test_controls_use_guard_allow_and_precedence(self):
        self.build()
        original={d['case_id_a7']:d['a4_precedence'] for d in self.review['decisions']}
        for s in self.captured['controls']['services']:
            for c in s['controls']:
                self.assertEqual(c['guard_rule_id'],'ALLOW')
                self.assertEqual(c['precedence'],original[c['target_case_id']])
                self.assertEqual(c['requires'],[])

    def test_no_a3_source_replacement(self):
        self.assertFalse(self.build()['r26_a3_control_targets_replaced_in_source'])

    def test_no_claim_full_algorithm_or_hypothesis(self):
        result=self.build()
        self.assertFalse(result['a1_a10_implementation_complete'])
        self.assertFalse(result['experimental_hypothesis_validated'])
        self.assertFalse(result['a1_a3_to_family_case_authority_attested'])

    def test_verified_deterministic(self):
        result=self.build()
        with self.mocked():
            self.assertTrue(p.verify_family_a3_projection(result,self.scenario,self.review))

    def test_rehashed_tamper_refused(self):
        result=self.build()
        for field, changed in [('operational_dispatch',True),
                               ('a3_case_guard_is_operational_authority',True),
                               ('confirmed_final_risk','0'),
                               ('published_generation',1),
                               ('a1_a10_implementation_complete',True)]:
            with self.subTest(field=field):
                modified=deepcopy(result)
                modified[field]=changed
                modified['sha256']=p.digest({k:v for k,v in modified.items()
                                             if k!='sha256'})
                with self.mocked(), self.assertRaises(p.ProjectionError):
                    p.verify_family_a3_projection(modified,self.scenario,self.review)

    def test_tamper_control_row_rejected(self):
        result=self.build()
        result['control_cases'][0]['operational_eligibility_attested']=True
        result['sha256']=p.digest({k:v for k,v in result.items() if k!='sha256'})
        with self.mocked(), self.assertRaises(p.ProjectionError):
            p.verify_family_a3_projection(result,self.scenario,self.review)

    def test_tamper_digest_rejected(self):
        result=self.build()
        result['sha256']='0'*64
        with self.mocked(),self.assertRaises(p.ProjectionError):
            p.verify_family_a3_projection(result,self.scenario,self.review)

    def test_wrong_session_refused(self):
        self.review['session_id']='ANOTHER'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'SESSION_MISMATCH'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_duplicate_identity_refused(self):
        self.review['decisions'][1]['derived_case_id']=self.review['decisions'][0]['derived_case_id']
        self.review['decisions'][1]['assessment_index']=0
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'DUPLICATE_CASE'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_duplicate_hashed_case_refused(self):
        self.review['decisions'][1]['case_id_a7']=self.review['decisions'][0]['case_id_a7']
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'DUPLICATE_CASE'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_case_window_mixed_session_refused(self):
        self.review['decisions'][0]['session_id']='OTHER'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_SERVICE_OR_SESSION'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_wrong_service_refused(self):
        self.review['decisions'][0]['service_id']='TELNET_DEV'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_SERVICE_OR_SESSION'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_empty_service_refused(self):
        self.review['decisions']=[d for d in self.review['decisions'] if d['service_id']!='SSH_DEV']
        self.review['unit_count']=len(self.review['decisions'])
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'THREE_SERVICES_REQUIRED'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_count_55_refused(self):
        self.review['unit_count']=55
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_COUNT_INVALID'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_count_mismatch_refused(self):
        self.review['unit_count']=28
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_COUNT_INVALID'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_invalid_a7_id_refused(self):
        for invalid in ('CASE_A', 'FTP-T01', 'CASE_'+('z'*48)):
            with self.subTest(invalid=invalid):
                altered=deepcopy(self.review)
                altered['decisions'][0]['case_id_a7']=invalid
                with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'A7_CASE_ID_INVALID'):
                    p.build_family_a3_projection(self.scenario,altered)

    def test_bool_precedence_refused(self):
        self.review['decisions'][0]['a4_precedence']=True
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_A4_DOMAIN'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_out_of_bounds_precedence_refused(self):
        self.review['decisions'][0]['a4_precedence']=1024
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_A4_DOMAIN'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_invalid_guard_refused(self):
        self.review['decisions'][0]['a4_guard_simulated']='TRUE'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_A4_DOMAIN'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_forged_accreditation_refused(self):
        self.review['technical_truth_accredited']=True
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'REVIEW_FALSE_AUTHORITY'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_forged_dispatch_refused(self):
        self.review['operational_dispatch']=True
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'REVIEW_FALSE_AUTHORITY'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_forged_risk_refused(self):
        self.review['confirmed_final_risk']='0'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'REVIEW_FALSE_AUTHORITY'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_forged_p8_refused(self):
        self.review['p8_operational']='GO'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'REVIEW_FALSE_AUTHORITY'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_forged_case_a6_refused(self):
        self.review['decisions'][0]['a6_classification']='POSITIVO_VALIDO'
        with self.mocked(),self.assertRaisesRegex(p.ProjectionError,'CASE_FALSE_AUTHORITY'):
            p.build_family_a3_projection(self.scenario,self.review)

    def test_wrong_r26_rule_source_refused(self):
        with self.mocked() as ctx:
            with patch.object(p,'preflight_rule_configuration',return_value=FakeSnapshot('c'*64)):
                with self.assertRaisesRegex(p.ProjectionError,'R26_RULE_SOURCE_MISMATCH'):
                    p.build_family_a3_projection(self.scenario,self.review)

    def test_control_missing_authority_blocker_refused(self):
        with self.mocked() as ctx:
            original = p.diagnose_guards
            def no_auth(*a):
                diag=original(*a)
                for unit in diag.units:
                    for row in unit.controls:
                        row.blockers=()
                return diag
            with patch.object(p,'diagnose_guards',side_effect=no_auth):
                with self.assertRaisesRegex(p.ProjectionError,'CONTROL_REFERENCES_INVALID'):
                    p.build_family_a3_projection(self.scenario,self.review)

    def test_permutation_invariant(self):
        one=self.build()
        self.review['decisions'].reverse()
        two=self.build()
        self.assertEqual(one,two)


class RealCatalogIntegration(unittest.TestCase):
    def test_r17_r22_29_cases_against_pinned_p7(self):
        catalog=REPO/'lab/operational-catalog-v1/catalog.json'
        scenario=REPO/'lab/p14-r26-session-v1/scenario.json'
        if not catalog.is_file() or not scenario.is_file():
            self.skipTest('FULL_PINNED_GITHUB_WORKTREE_REQUIRED')
        from ardrec.coordination.demo_session import read_fixed_scenario
        from ardrec.coordination.r58l_a4_a5_family_review import build_a4_a5_review
        from scripts.ardrec_p14_r58l_a4_a5_review_demo import synthetic_entries
        source=read_fixed_scenario(scenario)
        review=build_a4_a5_review(synthetic_entries())
        result=p.build_family_a3_projection(source,review)
        self.assertTrue(p.verify_family_a3_projection(result,source,review))
        self.assertEqual(result['control_reference_count'],29)
        self.assertEqual(result['family_count'],25)
        self.assertEqual(result['a3_guard_truth_counts'],
                         {'VERDADERO':8,'FALSO':11,'ND':10})
        self.assertEqual(result['a3_a4_guard_mismatch_count'],21)
        self.assertFalse(result['a1_a3_to_family_case_authority_attested'])
        self.assertEqual(result['p8_operational'],'NO-GO')


if __name__ == '__main__':
    unittest.main()
