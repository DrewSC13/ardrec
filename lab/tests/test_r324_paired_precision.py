"""Regresión de precisión del análisis pareado; fixtures no experimentales."""
from decimal import Decimal, localcontext, ROUND_UP, Inexact
from fractions import Fraction
from pathlib import Path
import unittest

from ardrec.experiments import r148_paired_register as native
from ardrec.experiments import paired_summary

CAT = Path('lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD = '319d99fe9937f7d29cab6a3f3b8c8c35a8120b66'


class PairedPrecisionTests(unittest.TestCase):
    def build(self, triples):
        protocol, registry = native.build(CAT, HEAD)
        registry['common_scale'] = {'lower': '0', 'upper': '1'}
        for i, triple in enumerate(triples):
            slot = registry['slots'][i]
            slot.update(status='RECORDED_UNVERIFIED', scenario_id=f'fixture-{i}',
                        case_id=f'case-{i}', family_id='SSH-T01')
            slot.update(zip(native.VALUES, triple))
            slot.update({key: 'a' * 64 for key in native.REFS})
        registry.pop('sha256')
        registry = native._seal(registry)
        return protocol, registry

    def test_near_ties_not_ties(self):
        values = [Decimal('0.10000000000000000000000000002'),
                  Decimal('-0.10000000000000000000000000001')]
        with localcontext() as ctx:
            ctx.prec = 5
            result = native.wilcoxon_exact(values)
        self.assertEqual(result['w_plus_twice'], 4)
        self.assertEqual(result['p_fraction'], '1/2')

    def test_small_difference_not_zero(self):
        p, r = self.build([('0.50000000000000000000000000001', '0.5', '0')])
        report = native.analyze(p, r, CAT)
        self.assertEqual(report['primary_comparison']['n_nonzero'], 1)
        self.assertEqual(report['primary_comparison']['p_fraction'], '1/2')

    def test_ambient_context_independence(self):
        p, r = self.build([('0.50000000000000000000000000001', '0.5', '0'),
                           ('0.2', '0.4', '0'), ('0.1', '0.1', '0')])
        expected = paired_summary.analyze(p, r, CAT)
        with localcontext() as ctx:
            ctx.prec = 5
            ctx.rounding = ROUND_UP
            ctx.traps[Inexact] = True
            self.assertEqual(paired_summary.analyze(p, r, CAT), expected)
        self.assertEqual(expected[1]['nonzero_pairs'], 2)
        self.assertEqual(expected[1]['zero_pairs'], 1)

    def test_exact_probability_54(self):
        result = native.wilcoxon_exact([Decimal(1)] * 54)
        self.assertEqual(Fraction(Decimal(result['p_one_sided_exact'])), Fraction(1, 2**54))

    def test_exponent_bounds(self):
        for text in ('1e-49', '0e-99999', '0e99999'):
            with self.subTest(text=text), self.assertRaises(native.Stop):
                native._decimal(text)
        self.assertEqual(native._decimal('1e-48'), Decimal('1e-48'))

    def test_registry_unchanged_and_no_authority(self):
        p, r = self.build([('0.9', '0.3', '0.2')])
        before = native.canonical(r)
        a, b = paired_summary.analyze(p, r, CAT)
        self.assertEqual(before, native.canonical(r))
        self.assertEqual(a['p8'], 'NO-GO')
        self.assertFalse(b['confirmatory_analysis_authorized'])
        self.assertEqual(a['primary_comparison'], b['wilcoxon'])


if __name__ == '__main__':
    unittest.main()
