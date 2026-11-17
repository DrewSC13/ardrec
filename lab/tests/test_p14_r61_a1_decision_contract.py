"""R61 / A1: oráculo independiente de la figura 3.4 (p. impresa 105).
Alcance: núcleo puro, instantánea R17 y consumidor diagnóstico A3; P8 NO-GO.
"""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.state import Truth
from ardrec.rules.kernel import A1Error, decide, evaluate
from ardrec.initialization.rule_preflight import FORMAT, preflight_rule_configuration, RulePreflightError
from ardrec.scheduling.guard_preview import diagnose_guards
from test_p14_r22_a3_guard_preview import custom


def literal(value: Truth) -> dict:
    return {'op': 'CONSTANTE', 'tipo': 'LOGICO', 'valor': value.name}


def row(name: str, value: Truth, output=None) -> dict:
    item = {'id': name, 'condicion': literal(value)}
    if output is not None:
        item['salida'] = output
    return item


class Figure34IndependentOracle(unittest.TestCase):
    def test_all_false_rows_return_nd_without_erasing_individual_false(self):
        rows = [row('Z', Truth.FALSO), row('B', Truth.FALSO), row('A', Truth.FALSO)]
        decision = decide(rows, {}, {})
        self.assertIs(decision.status, Truth.ND)
        self.assertIsNone(decision.selected)
        self.assertIsNone(decision.output)
        self.assertFalse(decision.authorized)
        self.assertEqual(decision.evaluations, (
            ('A', Truth.FALSO), ('B', Truth.FALSO), ('Z', Truth.FALSO)))
        self.assertIs(evaluate(literal(Truth.FALSO), {}, {}), Truth.FALSO)

    def test_single_winning_row_preserves_declarative_output(self):
        rows = [row('Z', Truth.FALSO, 'NO_ELEGIDA'),
                row('A', Truth.VERDADERO, 'CONTROL_ESPERADO')]
        decision = decide(rows, {}, {})
        self.assertIs(decision.status, Truth.VERDADERO)
        self.assertEqual(decision.selected, 'A')
        self.assertEqual(decision.output, 'CONTROL_ESPERADO')
        self.assertEqual(decision, decide(list(reversed(rows)), {}, {}))
        self.assertTrue(decision.authorized)  # Verdad LOGICA, no permiso P8.

    def test_legacy_rows_keep_selected_rule_without_inventing_output(self):
        decision = decide([row('LEGACY', Truth.VERDADERO)], {}, {})
        self.assertEqual(decision.selected, 'LEGACY')
        self.assertIsNone(decision.output)

    def test_nd_plus_unique_true_still_nd(self):
        result = decide([row('A', Truth.VERDADERO, 'NO_AUTORIZAR'),
                         row('B', Truth.ND, 'DESCONOCIDA')], {}, {})
        self.assertIs(result.status, Truth.ND)
        self.assertIsNone(result.selected)
        self.assertIsNone(result.output)
        self.assertFalse(result.authorized)

    def test_two_true_rows_are_ambiguous_regardless_of_output(self):
        with self.assertRaisesRegex(A1Error, 'reglas_ambiguas'):
            decide([row('A', Truth.VERDADERO, 'VALOR'),
                    row('B', Truth.VERDADERO, 'VALOR')], {}, {})

    def test_invalid_output_never_becomes_a_command_or_authority(self):
        for invalid in (None, False, 10, [], {}, '', 'X' * 129):
            malformed = row('A', Truth.VERDADERO)
            malformed['salida'] = invalid
            with self.subTest(value=repr(invalid)), self.assertRaisesRegex(A1Error, 'salida_invalida'):
                decide([malformed], {}, {})

    def test_extra_row_metadata_denied(self):
        malformed = row('A', Truth.VERDADERO, 'OUTPUT')
        malformed['argv'] = ['echo', 'danger']
        with self.assertRaisesRegex(A1Error, 'estructura_invalida'):
            decide([malformed], {}, {})

    def test_frozen_consumer_carries_output_and_preserves_hash(self):
        candidate = {'format': FORMAT, 'fields': {}, 'services': [{
            'id': 'SSH01', 'initial_state': 'PREPARADO',
            'rules': [row('A', Truth.VERDADERO, 'CASO_DECLARADO'),
                      row('B', Truth.FALSO)]}]}
        original = copy.deepcopy(candidate)
        frozen = preflight_rule_configuration(candidate)
        selected = frozen.evaluate_service('SSH01', {})
        self.assertEqual(selected.selected_rule, 'A')
        self.assertEqual(selected.selected_output, 'CASO_DECLARADO')
        self.assertTrue(selected.logical_guard_satisfied)
        self.assertFalse(selected.operationally_authorized)
        candidate['services'][0]['rules'][0]['salida'] = 'MANIPULADA'
        self.assertEqual(frozen.evaluate_service('SSH01', {}).selected_output, 'CASO_DECLARADO')
        original['services'][0]['rules'].reverse()
        self.assertEqual(preflight_rule_configuration(original).sha256, frozen.sha256)

    def test_frozen_consumer_all_false_remains_nd(self):
        data = {'format': FORMAT, 'fields': {}, 'services': [{
            'id': 'FTP01', 'initial_state': 'PREPARADO',
            'rules': [row('X', Truth.FALSO, 'NO_APLICA')]}]}
        result = preflight_rule_configuration(data).evaluate_service('FTP01', {})
        self.assertIs(result.status, Truth.ND)
        self.assertIsNone(result.selected_rule)
        self.assertIsNone(result.selected_output)
        self.assertEqual(result.evaluations, (('X', Truth.FALSO),))
        self.assertFalse(result.logical_guard_satisfied)

    def test_preflight_rejects_invalid_output(self):
        data = {'format': FORMAT, 'fields': {}, 'services': [{
            'id': 'FTP01', 'initial_state': 'PREPARADO',
            'rules': [row('X', Truth.VERDADERO)]}]}
        data['services'][0]['rules'][0]['salida'] = {'ejecutar': 'no'}
        with self.assertRaisesRegex(RulePreflightError, 'salida_invalida'):
            preflight_rule_configuration(data)

    def test_a3_consumer_exposes_output_in_verifiable_diagnostic(self):
        conditions = [row('G1', Truth.VERDADERO, 'CASO_ELEGIDO'),
                      row('G2', Truth.FALSO, 'NO_ELEGIDO')]
        sources = custom(conditions=conditions, fields={})
        result = diagnose_guards(*sources, {'SSH_01': {}})
        unit = result.units[0]
        self.assertIs(unit.table_status, Truth.VERDADERO)
        self.assertEqual(unit.table_selected, 'G1')
        self.assertEqual(unit.table_output, 'CASO_ELEGIDO')
        self.assertEqual(json.loads(result.source)['services'][0]['table_output'], 'CASO_ELEGIDO')
        self.assertTrue(result.verify(*sources, {'SSH_01': {}}))
        self.assertFalse(result.operational_dispatch_allowed)
        self.assertIsNone(result.published_generation)

    def test_a3_consumer_no_match_is_nd_but_false_control_preserved(self):
        conditions = [row('G1', Truth.FALSO, 'DESCARTADO'), row('G2', Truth.FALSO)]
        sources = custom(conditions=conditions, fields={})
        result = diagnose_guards(*sources, {'SSH_01': {}})
        unit = result.units[0]
        self.assertIs(unit.table_status, Truth.ND)
        self.assertIsNone(unit.table_selected)
        self.assertIsNone(unit.table_output)
        self.assertIs(unit.controls[0].truth, Truth.FALSO)
        self.assertIn('GUARDA_FALSA', unit.controls[0].blockers)
        self.assertIn('TABLA_NO_ACREDITADA', unit.controls[0].blockers)
        self.assertNotIn('table_output', json.loads(result.source)['services'][0])
        self.assertTrue(result.verify(*sources, {'SSH_01': {}}))


if __name__ == '__main__':
    unittest.main()
