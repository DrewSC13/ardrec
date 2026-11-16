"""R58-D: 33 deterministic and adversarial tests of the A7 exact envelope."""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import json
from pathlib import Path
import subprocess
import sys
import unittest

from ardrec.analytics.r58d_interval_kernel import (
    build_intervals, verify_intervals, IntervalError, MAX_UNITS, MAX_EVIDENCE)


BASE = {'service_id':'SSH_DEV','case_id':'CASE_REFERENCE','assessment_index':0,
        'initial_risk':'1/4','normalized_criticality':'1/2',
        'replacement_risk':'1/4','evidence':[]}
FIXED = {'evidence_id':'E01','kind':'SYNTHETIC_FIXED','lower':'1/2','upper':'1/2'}
UNKNOWN = {'evidence_id':'E02','kind':'UNRESOLVED','lower':'0','upper':'1'}


def expect_block(row, label=None, weights=('1/3','1/3','1/3')):
    with unittest.TestCase().assertRaises((IntervalError, ValueError)):
        build_intervals(row,weights=weights)


class TestR58DA7(unittest.TestCase):
    def doc(self, items=None, *, weights=('1/3','1/3','1/3')):
        return build_intervals([deepcopy(BASE)] if items is None else items, weights=weights)

    def test_baseline_zero_evidence(self):
        r=self.doc()['results'][0]
        self.assertEqual(r['rf_lower'],'1/4')
        self.assertEqual(r['rf_upper'],'1/4')
        self.assertTrue(r['point_identified'])

    def test_fixed_half_exact(self):
        row=deepcopy(BASE);row['evidence']=[deepcopy(FIXED)]
        r=self.doc([row])['results'][0]
        self.assertEqual(r['rf_lower'],'5/12')
        self.assertEqual(r['rf_upper'],'5/12')

    def test_unknown_envelope(self):
        row=deepcopy(BASE);row['evidence']=[deepcopy(UNKNOWN)]
        r=self.doc([row])['results'][0]
        self.assertEqual(r['rf_lower'],'1/4')
        self.assertEqual(r['rf_upper'],'7/12')
        self.assertFalse(r['point_identified'])

    def test_mixed_max_evidence(self):
        row=deepcopy(BASE);row['evidence']=[deepcopy(FIXED),deepcopy(UNKNOWN)]
        r=self.doc([row])['results'][0]
        self.assertEqual((r['evidence_lower'],r['evidence_upper']),('1/2','1'))
        self.assertEqual((r['rf_lower'],r['rf_upper']),('5/12','7/12'))

    def test_document_integrity(self): self.assertTrue(verify_intervals(self.doc()))
    def test_no_authority(self):
        d=self.doc()
        self.assertIs(d['technical_truth_accredited'],False)
        self.assertIsNone(d['confirmed_final_risk'])
        self.assertIsNone(d['published_generation'])
        self.assertIs(d['operational_dispatch'],False)
        self.assertEqual(d['p8_operational'],'NO-GO')

    def test_no_units_rejected(self): expect_block([])
    def test_too_many_units_rejected(self):
        items=[dict(deepcopy(BASE),case_id=f'CASE_{i:02d}') for i in range(MAX_UNITS+1)]
        expect_block(items)

    def test_max_54_units_accepted(self):
        items=[dict(deepcopy(BASE),case_id=f'CASE_{i:02d}') for i in range(MAX_UNITS)]
        d=self.doc(items)
        self.assertEqual(d['unit_count'],54)
        self.assertTrue(verify_intervals(d))

    def test_sort_units(self):
        a=deepcopy(BASE);b=dict(deepcopy(BASE),service_id='FTP_DEV')
        self.assertEqual(self.doc([a,b]),self.doc([b,a]))

    def test_sort_evidence(self):
        a=deepcopy(BASE);a['evidence']=[deepcopy(UNKNOWN),deepcopy(FIXED)]
        b=deepcopy(a);b['evidence'].reverse()
        self.assertEqual(self.doc([a]),self.doc([b]))

    def test_duplicate_case_window(self): expect_block([deepcopy(BASE),deepcopy(BASE)])
    def test_distinct_assessment_indices(self):
        a=deepcopy(BASE);b=dict(deepcopy(BASE),assessment_index=1)
        self.assertEqual(self.doc([a,b])['unit_count'],2)

    def test_negative_index(self): expect_block([dict(deepcopy(BASE),assessment_index=-1)])
    def test_boolean_index(self): expect_block([dict(deepcopy(BASE),assessment_index=True)])
    def test_too_large_index(self): expect_block([dict(deepcopy(BASE),assessment_index=2**31)])
    def test_bad_service(self): expect_block([dict(deepcopy(BASE),service_id='ANY')])
    def test_bad_case(self): expect_block([dict(deepcopy(BASE),case_id='../bad')])
    def test_extra_unit_field(self): expect_block([dict(deepcopy(BASE),authorized=True)])
    def test_missing_unit_field(self):
        a=deepcopy(BASE);del a['initial_risk'];expect_block([a])

    def test_bad_fraction_noncanonical(self): expect_block([dict(deepcopy(BASE),initial_risk='2/8')])
    def test_fraction_out_of_range(self): expect_block([dict(deepcopy(BASE),initial_risk='5/4')])
    def test_replacement_greater_than_initial(self):
        expect_block([dict(deepcopy(BASE),replacement_risk='1/2')])

    def test_unknown_lower_must_be_zero(self):
        a=deepcopy(BASE);a['evidence']=[dict(UNKNOWN,lower='1/4')];expect_block([a])
    def test_unknown_upper_must_be_one(self):
        a=deepcopy(BASE);a['evidence']=[dict(UNKNOWN,upper='3/4')];expect_block([a])
    def test_fixed_must_be_point(self):
        a=deepcopy(BASE);a['evidence']=[dict(FIXED,upper='3/4')];expect_block([a])
    def test_duplicate_evidence(self):
        a=deepcopy(BASE);a['evidence']=[deepcopy(FIXED),deepcopy(FIXED)];expect_block([a])
    def test_too_many_evidence(self):
        a=deepcopy(BASE);a['evidence']=[dict(FIXED,evidence_id=f'E{i}') for i in range(MAX_EVIDENCE+1)];expect_block([a])
    def test_invalid_evidence_kind(self):
        a=deepcopy(BASE);a['evidence']=[dict(FIXED,kind='REAL_ATTESTED')];expect_block([a])
    def test_extra_evidence_field(self):
        a=deepcopy(BASE);a['evidence']=[dict(FIXED,pass_authority=True)];expect_block([a])
    def test_bad_weights(self): expect_block([deepcopy(BASE)],weights=('1/2','1/3','1/3'))
    def test_zero_weight(self): expect_block([deepcopy(BASE)],weights=('0','1/2','1/2'))

    def test_report_tamper_sha(self):
        d=self.doc();d['results'][0]['rf_lower']='1'
        with self.assertRaises(IntervalError):verify_intervals(d)

    def test_report_rehashed_forgery(self):
        from ardrec.analytics.exact_preview import digest
        d=self.doc();d['operational_dispatch']=True
        d['sha256']=digest({k:v for k,v in d.items() if k!='sha256'})
        with self.assertRaises(IntervalError):verify_intervals(d)

    def test_report_noncanonical_rejected(self):
        d=self.doc();d['weights']=['1/2','1/2','0']
        with self.assertRaises((IntervalError,ValueError)):verify_intervals(d)

    def test_monotonic_generated_grid(self):
        for i in range(11):
            for j in range(i,11):
                a=deepcopy(BASE)
                a['initial_risk']=str(Fraction(i,10))
                a['replacement_risk']='0'
                a['normalized_criticality']=str(Fraction(j,10))
                a['evidence']=[{'evidence_id':'E01','kind':'SYNTHETIC_FIXED',
                                'lower':str(Fraction(i,10)), 'upper':str(Fraction(i,10))},deepcopy(UNKNOWN)]
                r=self.doc([a])['results'][0]
                self.assertLessEqual(Fraction(r['rf_lower']),Fraction(r['rf_upper']))
                self.assertGreaterEqual(Fraction(r['rf_lower']),0)
                self.assertLessEqual(Fraction(r['rf_upper']),1)

    def test_read_only_script_contract(self):
        src=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r58d_a7_intervals.py'
        data=src.read_text()
        self.assertIn('--synthetic-offline',data)
        for phrase in ('sudo ', 'virsh ', 'nft -f', 'systemctl start', 'subprocess.run'):
            self.assertNotIn(phrase,data)

    def test_cli_offline(self):
        import contextlib
        from io import StringIO
        from scripts import ardrec_p14_r58d_a7_intervals as cli
        with contextlib.redirect_stdout(StringIO()) as out:
            # Avoid argparse and execute the actual data transformation directly.
            doc=cli.build_intervals(cli.synthetic_units())
            self.assertTrue(cli.verify_intervals(doc))
        self.assertEqual(doc['unit_count'],3)
        self.assertEqual(doc['p8_operational'],'NO-GO')


if __name__ == '__main__':
    unittest.main()
