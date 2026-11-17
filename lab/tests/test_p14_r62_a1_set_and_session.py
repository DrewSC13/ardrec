"""R62 — Oráculos A1 independientes: conjuntos y traza integrada R26 (P8 NO-GO)."""
from __future__ import annotations

import copy
from fractions import Fraction
from itertools import permutations, product
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.rules.kernel import A1Error, decide, evaluate
from ardrec.state import Truth
from ardrec.coordination.demo_session import (
    build_development_session, read_fixed_scenario, verify_session_document,
)
from ardrec.scheduling.guard_preview import diagnose_guards
from test_p14_r22_a3_guard_preview import custom


def constant(domain: str, value: object) -> dict:
    return {'op': 'CONSTANTE', 'tipo': domain, 'valor': value}


def field(name: str) -> dict:
    return {'op': 'CAMPO', 'nombre': name}


def compare(op: str, left: dict, right: dict) -> dict:
    return {'op': 'COMPARAR', 'relacion': op, 'izq': left, 'der': right}


def logical(value: Truth) -> dict:
    return constant('LOGICO', value.name)


class A1SetOperatorIndependentOracle(unittest.TestCase):
    def test_membership_text_true_false(self):
        expr = compare('PERTENECE', constant('TEXTO', 'SSH'),
                       constant('CONJUNTO_TEXTO', ['FTP', 'SMB', 'SSH']))
        self.assertIs(evaluate(expr, {}, {}), Truth.VERDADERO)
        expr['izq'] = constant('TEXTO', 'HTTP')
        self.assertIs(evaluate(expr, {}, {}), Truth.FALSO)

    def test_membership_rational_exact(self):
        expr = compare('PERTENECE', constant('RACIONAL', '1/3'),
                       constant('CONJUNTO_RACIONAL', ['1/3', '2/3']))
        self.assertIs(evaluate(expr, {}, {}), Truth.VERDADERO)
        expr['izq'] = constant('RACIONAL', '1/2')
        self.assertIs(evaluate(expr, {}, {}), Truth.FALSO)

    def test_subset_proper_equal_empty(self):
        right = constant('CONJUNTO_TEXTO', ['FTP', 'SMB', 'SSH'])
        for left, truth in [(['FTP'], Truth.VERDADERO),
                            (['FTP', 'SMB', 'SSH'], Truth.VERDADERO),
                            ([], Truth.VERDADERO),
                            (['HTTP'], Truth.FALSO)]:
            with self.subTest(left=left):
                expression = compare('SUBCONJUNTO', constant('CONJUNTO_TEXTO', left), right)
                self.assertIs(evaluate(expression, {}, {}), truth)

    def test_subset_rational_exact_and_negative(self):
        for left, expected in [(['-1', '1/2'], Truth.VERDADERO),
                               (['-1', '3/4'], Truth.FALSO)]:
            expr = compare('SUBCONJUNTO', constant('CONJUNTO_RACIONAL', left),
                           constant('CONJUNTO_RACIONAL', ['-1', '1/2', '2']))
            self.assertIs(evaluate(expr, {}, {}), expected)

    def test_missing_field_is_nd_even_when_other_operand_empty(self):
        expr = compare('PERTENECE', field('item'), constant('CONJUNTO_TEXTO', []))
        self.assertIs(evaluate(expr, {'item': 'TEXTO'}, {}), Truth.ND)
        expr = compare('SUBCONJUNTO', field('observados'),
                       constant('CONJUNTO_TEXTO', []))
        self.assertIs(evaluate(expr, {'observados': 'CONJUNTO_TEXTO'}, {}), Truth.ND)

    def test_known_empty_set_is_not_nd(self):
        expr = compare('SUBCONJUNTO', field('a'), field('b'))
        schema = {'a': 'CONJUNTO_TEXTO', 'b': 'CONJUNTO_TEXTO'}
        self.assertIs(evaluate(expr, schema, {'a': frozenset(), 'b': frozenset()}),
                      Truth.VERDADERO)

    def test_frozen_environment_sets_and_no_casts(self):
        schema = {'protocolo': 'TEXTO', 'alcance': 'CONJUNTO_TEXTO'}
        expr = compare('PERTENECE', field('protocolo'), field('alcance'))
        self.assertIs(evaluate(expr, schema, {'protocolo': 'SSH',
                                             'alcance': frozenset({'SSH', 'FTP'})}),
                      Truth.VERDADERO)
        with self.assertRaisesRegex(A1Error, 'ambiente_tipo_invalido'):
            evaluate(expr, schema, {'protocolo': 'SSH', 'alcance': ['SSH']})
        with self.assertRaisesRegex(A1Error, 'ambiente_tipo_invalido'):
            evaluate(expr, schema, {'protocolo': 'SSH', 'alcance': frozenset({1})})

    def test_membership_rejects_nonmatching_domains(self):
        cases = [
            compare('PERTENECE', constant('TEXTO', 'SSH'),
                    constant('CONJUNTO_RACIONAL', ['1'])),
            compare('PERTENECE', constant('CONJUNTO_TEXTO', ['SSH']),
                    constant('CONJUNTO_TEXTO', ['SSH'])),
            compare('SUBCONJUNTO', constant('TEXTO', 'SSH'),
                    constant('CONJUNTO_TEXTO', ['SSH'])),
            compare('SUBCONJUNTO', constant('CONJUNTO_TEXTO', ['SSH']),
                    constant('CONJUNTO_RACIONAL', ['1'])),
        ]
        for expr in cases:
            with self.subTest(expr=expr), self.assertRaisesRegex(A1Error, 'tipos_incompatibles'):
                evaluate(expr, {}, {})

    def test_constant_sets_reject_duplicates_noncanonical_and_invalid_values(self):
        samples = [
            ('CONJUNTO_TEXTO', ['SSH', 'SSH'], 'conjunto_no_canonico'),
            ('CONJUNTO_TEXTO', ['SMB', 'FTP'], 'conjunto_no_canonico'),
            ('CONJUNTO_RACIONAL', ['2/4'], 'racional_no_canonico'),
            ('CONJUNTO_TEXTO', [''], 'constante_texto_invalida'),
            ('CONJUNTO_TEXTO', ['A'] * 65, 'conjunto_invalido'),
            ('CONJUNTO_TEXTO', {'SSH'}, 'conjunto_invalido'),
            ('CONJUNTO_RACIONAL', [True], 'racional_invalido'),
        ]
        for domain, raw, error in samples:
            with self.subTest(domain=domain, raw=str(raw)[:40]), self.assertRaisesRegex(A1Error, error):
                evaluate(compare('IGUAL', constant(domain, raw), constant(domain, [])), {}, {})

    def test_set_equality_explicit_not_subset(self):
        expr = compare('IGUAL', constant('CONJUNTO_TEXTO', ['FTP']),
                       constant('CONJUNTO_TEXTO', ['FTP', 'SSH']))
        self.assertIs(evaluate(expr, {}, {}), Truth.FALSO)
        expr['relacion'] = 'DISTINTO'
        self.assertIs(evaluate(expr, {}, {}), Truth.VERDADERO)

    def test_trivalent_composition_set_membership(self):
        member = compare('PERTENECE', field('item'),
                         constant('CONJUNTO_TEXTO', ['SSH']))
        combined = {'op': 'Y', 'args': [member, logical(Truth.VERDADERO)]}
        self.assertIs(evaluate(combined, {'item': 'TEXTO'}, {}), Truth.ND)
        combined['args'][1] = logical(Truth.FALSO)
        self.assertIs(evaluate(combined, {'item': 'TEXTO'}, {}), Truth.FALSO)

    def test_deterministic_decision_table_all_three_value_combinations(self):
        # Oráculo independiente fijado antes de invocar decide(); 3^4 casos.
        statuses = (Truth.FALSO, Truth.ND, Truth.VERDADERO)
        for combination in product(statuses, repeat=4):
            rows = [{'id': 'R' + str(i), 'condicion': logical(truth),
                     'salida': 'OUTPUT' + str(i)}
                    for i, truth in enumerate(combination)]
            winner_indices = [i for i, truth in enumerate(combination)
                              if truth is Truth.VERDADERO]
            if len(winner_indices) > 1:
                with self.assertRaisesRegex(A1Error, 'reglas_ambiguas'):
                    decide(rows, {}, {})
                continue
            d = decide(rows, {}, {})
            if Truth.ND in combination or not winner_indices:
                expected = (Truth.ND, None, None)
            else:
                index = winner_indices[0]
                expected = (Truth.VERDADERO, 'R' + str(index), 'OUTPUT' + str(index))
            self.assertEqual((d.status, d.selected, d.output), expected)
            self.assertEqual(d.evaluations,
                             tuple(('R' + str(i), value) for i, value in enumerate(combination)))

    def test_permutation_invariant_with_membership_and_outputs(self):
        rows = [
            {'id': 'A', 'condicion': compare('PERTENECE', field('service'),
                                          constant('CONJUNTO_TEXTO', ['SSH'])),
             'salida': 'CASE_A'},
            {'id': 'B', 'condicion': logical(Truth.FALSO), 'salida': 'CASE_B'},
            {'id': 'C', 'condicion': logical(Truth.FALSO), 'salida': 'CASE_C'},
        ]
        baseline = decide(rows, {'service': 'TEXTO'}, {'service': 'SSH'})
        for order in permutations(rows):
            self.assertEqual(decide(list(order), {'service': 'TEXTO'}, {'service': 'SSH'}),
                             baseline)

    def test_a3_diagnostic_preserves_set_origin(self):
        condition = compare('PERTENECE', field('servicio'), field('permitidos'))
        sources = custom(conditions=[{'id': 'G1', 'condicion': condition,
                                     'salida': 'CASE_REFERENCE'}],
                         fields={'servicio': 'TEXTO', 'permitidos': 'CONJUNTO_TEXTO'})
        env = {'SSH_01': {'servicio': 'SSH',
                          'permitidos': frozenset({'SSH', 'FTP'})}}
        result = diagnose_guards(*sources, env)
        self.assertTrue(result.verify(*sources, env))
        self.assertIs(result.units[0].table_status, Truth.VERDADERO)
        self.assertEqual(result.units[0].table_output, 'CASE_REFERENCE')
        self.assertFalse(result.operational_dispatch_allowed)
        self.assertIsNone(result.published_generation)


class A1R26IntegrationOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = read_fixed_scenario(ROOT / 'lab/p14-r26-session-v1/scenario.json')

    def test_selected_row_output_reaches_a1_and_a3_in_session(self):
        session = build_development_session(copy.deepcopy(self.fixture))
        wanted = {
            'SSH_DEV': (Truth.VERDADERO, 'ALLOW', 'CASE_POLICY'),
            'FTP_DEV': (Truth.ND, None, None),
            'SMB_DEV': (Truth.VERDADERO, 'DENY', 'CASE_REFERENCE'),
        }
        for u in session.document['units']:
            status, selected, output = wanted[u['service_id']]
            self.assertEqual(u['a1']['status'], status.name)
            self.assertEqual(u['a1']['selected_rule'], selected)
            self.assertEqual(u['a1']['selected_output'], output)
            self.assertEqual(u['a3']['table_output'], output)
            self.assertEqual(u['a3']['table_status'], status.name)
            if output is not None:
                self.assertIn(output, u['a2']['cases'])
        self.assertTrue(session.verify())
        self.assertFalse(session.document['operational_dispatch'])
        self.assertIsNone(session.document['published_generation'])
        self.assertIsNone(session.document['final_risk'])

    def test_a1_and_a3_events_include_output_and_digest(self):
        session = build_development_session(copy.deepcopy(self.fixture))
        for event in session.document['events']:
            if event['algorithm'] in ('A1', 'A3'):
                key = 'selected_output' if event['algorithm'] == 'A1' else 'table_output'
                self.assertIn(key, event['decision'])
                self.assertIn(event['decision'][key], (None, 'CASE_POLICY', 'CASE_REFERENCE'))
        self.assertTrue(verify_session_document(copy.deepcopy(session.document)))

    def test_permuting_fixture_does_not_change_session_digest(self):
        a = build_development_session(copy.deepcopy(self.fixture))
        b = copy.deepcopy(self.fixture)
        b['services'].reverse()
        c = build_development_session(b)
        self.assertEqual(a.sha256, c.sha256)
        self.assertEqual(a.json_bytes(), c.json_bytes())

    def test_no_state_generation_or_p8_authority_claim(self):
        session = build_development_session(copy.deepcopy(self.fixture))
        self.assertFalse(session.document['a1_full'])
        self.assertFalse(session.document['a2_full'])
        self.assertFalse(session.document['a3_full'])
        self.assertFalse(session.document['a4_a10_executed'])
        self.assertEqual(session.document['p8_operational'], 'NO-GO')


if __name__ == '__main__':
    unittest.main()
