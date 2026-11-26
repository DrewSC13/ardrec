"""Synthetic exact-rational regressions; no observations or authority."""
import unittest
from decimal import localcontext, Inexact, ROUND_UP, Decimal
from fractions import Fraction
from itertools import product
from pathlib import Path

from ardrec.experiments import (
    initial_assessment as initial, r148_paired_register as r148,
    paired_summary as summary, r149_scenario_design as r149,
    baseline_preparation as i2, paired_reconciliation as i8,
)
import test_r228_baseline_preparation as fixture
import test_r336_matrix_batch as batch_fixture
import test_r184_paired_summary as legacy_fixture

CAT = Path('lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD = 'f46f50390ed9d2257053b0f84c56bda5f037db5a'

class RationalMeasurementTests(unittest.TestCase):
    def build(self, triples):
        p, r = r148.build(CAT, HEAD)
        r['common_scale'] = {'lower':'0','upper':'1'}
        for i, t in enumerate(triples):
            s = r['slots'][i]
            s.update(status='RECORDED_UNVERIFIED', case_id=f'C-{i}',
                     scenario_id=f'S-{i}', family_id='SSH-T01')
            s.update(zip(r148.VALUES,t)); s.update({k:'a'*64 for k in r148.REFS})
        r.pop('sha256')
        return p, r148._seal(r)

    def test_every_initial_risk(self):
        for x,p,i in product(range(1,6), repeat=3):
            raw=initial.compute(x,p,i,[1,1,1])['initial_risk']
            self.assertEqual(Fraction(r148._measurement(raw)),Fraction(x+p+i-3,12))

    def test_nonterminating_risk(self):
        p,r=self.build([('1/3','1/6','1/4')])
        a,b=summary.analyze(p,r,CAT)
        self.assertEqual(b['paired_errors'][0]['static_absolute_error'],'1/12')
        self.assertEqual(b['paired_errors'][0]['ardrec_absolute_error'],'1/12')
        self.assertEqual(a['primary_comparison']['n_zero'],1)
        self.assertIsNone(a['primary_comparison']['p_fraction'])

    def test_exact_ties_mixed(self):
        p,r=self.build([('1/3','1/6','0'),('0.25','5/12','0')])
        a,b=summary.analyze(p,r,CAT)
        self.assertEqual([x['difference'] for x in b['paired_errors']],['1/6','-1/6'])
        self.assertEqual(b['wilcoxon']['w_plus_twice'],3)
        self.assertEqual(b['wilcoxon']['p_fraction'],'3/4')
        self.assertEqual(a['primary_comparison'],b['wilcoxon'])

    def test_near_tie_not_tie(self):
        p,r=self.build([('1/3','0','0'),('0','0.3333333333333333333333333333333333333333333333','0')])
        a,b=summary.analyze(p,r,CAT)
        self.assertEqual(b['wilcoxon']['w_plus_twice'],4)
        self.assertEqual(b['wilcoxon']['p_fraction'],'1/2')

    def test_ambient_context(self):
        p,r=self.build([('1/3','1/7','1/4'),('2/3','1/3','0.25')])
        expected=summary.analyze(p,r,CAT)
        with localcontext() as ctx:
            ctx.prec=4; ctx.rounding=ROUND_UP; ctx.traps[Inexact]=True
            self.assertEqual(summary.analyze(p,r,CAT),expected)

    def test_reject_invalid_fraction(self):
        for val in ('1/0','2/6','01/3','1/03','1/-3','-1/3','1 /3','2/1','1/'+ '1'*25,'1/3/2'):
            with self.subTest(val=val),self.assertRaises(r148.Stop):
                r148._measurement(val)

    def test_i2_native_candidate(self):
        t=fixture.BaselineTests(); t.setUp()
        t.row['static_estimate']='1/3'
        t.entry['selection_sha256']=i2.sha(r149.csv_bytes(t.rows))
        report=t.calculate()
        self.assertEqual(report['candidate']['static_estimate'],'1/3')
        self.assertEqual(report['candidate']['calculated']['initial_risk'],'1/2')
        self.assertEqual(report['baselines_closed'],0)

    def test_i8_selection_exact(self):
        t=fixture.BaselineTests(); t.setUp()
        t.row['static_estimate']='1/3'
        proposal=r149.csv_bytes(r149.draft(CAT,t.protocol,t.registry)[2])
        p,r=self.build([('1/3','1/4','1/4')])
        # Use the same original study protocol and selection identity.
        r['protocol_sha256']=t.protocol['sha256']
        s=r['slots'][0];s.update(case_id=t.row['case_id'],scenario_id=t.row['scenario_id'],family_id=t.row['chosen_family'])
        r.pop('sha256');r=r148._seal(r)
        report=i8.build(t.protocol,r,CAT,t.plan,t.checklist,r149.csv_bytes(t.rows),proposal)
        self.assertEqual(report['i8_rows'][0]['static_estimate'],'1/3')
        self.assertEqual(report['i8_rows'][0]['difference'],'1/12')
        self.assertEqual(report['experimental_admitted'],0)

    def test_batch_native_candidate(self):
        t=batch_fixture.MatrixBatchTests(); t.setUp()
        t.rows[0]['static_estimate']='1/3'
        report=t.run_batch()
        self.assertEqual(report['counts']['DOCUMENTARY_CANDIDATE_UNVERIFIED'],1)
        self.assertEqual(report['records'][0]['decision']['candidate_initial_risk'],'1/2')
        self.assertEqual(report['experimental_admitted'],0)

    def test_legacy_decimal_and_mixed_ranks(self):
        self.assertEqual(r148._measurement('0.2500'),Decimal('0.2500'))
        self.assertEqual(r148.wilcoxon_exact([Fraction(1,4),Decimal('-0.25')]),
                         r148.wilcoxon_exact([Decimal('0.25'),Decimal('-0.25')]))
        self.assertEqual(summary.normalized('0/1'),0)
        self.assertEqual(summary.normalized('1/1'),1)

    def test_full_54_rational_pairs(self):
        p,r=r148.build(CAT,HEAD)
        r['common_scale']={'lower':'0','upper':'1'}
        families={'SSH':'SSH-T01','FTP':'FTP-T01','SMB':'SMB-T01'}
        for i,s in enumerate(r['slots']):
            # Large distinct reduced denominators; no decimal approximation.
            values=[f'1/{10**23+3*i+j}' for j in range(1,4)]
            s.update(status='RECORDED_UNVERIFIED',case_id=f'C-{i}',scenario_id=f'S-{i}',family_id=families[s['protocol']])
            s.update(zip(r148.VALUES,values));s.update({k:'a'*64 for k in r148.REFS})
        r.pop('sha256');r=r148._seal(r)
        native,report=summary.analyze(p,r,CAT)
        self.assertEqual(report['pairs'],54)
        self.assertEqual(report['favor_ardrec'],54)
        self.assertEqual(report['wilcoxon']['p_fraction'],f'1/{2**54}')
        self.assertEqual(native['primary_comparison'],report['wilcoxon'])
        self.assertFalse(report['confirmatory_analysis_authorized'])

    def test_legacy_report_hashes(self):
        # Hashes reproduced against the unmodified R336 source subset.
        fixtures=[
            ([],('23ce548c21962326531dd04a2c35f6613f866c6edc8ecfd12edeb656140bb539','8867297d9bb686a69dfb62bcd9b9023de17c24dd0fa6fffa9b64d05657d5cf41')),
            ([('0.8','0.4','0.2'),('0.2','0.6','0.2'),('0.5','0.5','0.2')],('84595968e0b9b2abe562238643566d85f66b405a5426f01b9732c059638ae75a','e92bf0b7c800f098dcc71a3cdbee93cff88f4f954a0d43bf2c2880c249d75938')),
            ([('0.50000000000000000000000000001','0.5','0.0')],('a28602ac19a7290d496d1679c4f7fe9a69bd4664a71953b0e5ddeaf4f289d51b','a1e776d30422cc439a62c799d40ac38002f1a71a450bf3a91e8e2e33b5d71aed')),
        ]
        for values,expected in fixtures:
            p,r=legacy_fixture.R184Tests().build(values)
            self.assertEqual(tuple(r148.digest(r148.canonical(x)) for x in summary.analyze(p,r,CAT)),expected)

if __name__=='__main__':unittest.main()
