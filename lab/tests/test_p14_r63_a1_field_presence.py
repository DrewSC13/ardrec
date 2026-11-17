"""Oráculos independientes P14-R63: CAMPO opcional/obligatorio según figura 3.5.

Los resultados esperados son literales y no se generan usando la implementación.
Sin llamadas de red, perfiles, ejecutor ni permisos P8.
"""
from __future__ import annotations

from fractions import Fraction
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
from ardrec.rules.kernel import A1Error, compile_expression, decide, evaluate
from ardrec.initialization.rule_preflight import (
    FORMAT as RULE_FORMAT, preflight_rule_configuration,
)
from ardrec.scheduling.guard_preview import GuardPreviewError, diagnose_guards
from ardrec.state import Truth
from test_p14_r22_a3_guard_preview import custom


def campo(nombre='fact', opcional=None):
    raw = {'op':'CAMPO', 'nombre':nombre}
    if opcional is not None:
        raw['opcional'] = opcional
    return raw


def logico(valor):
    return {'op':'CONSTANTE', 'tipo':'LOGICO', 'valor':valor.name}


def comparar(relacion, izquierda, derecha):
    return {'op':'COMPARAR', 'relacion':relacion, 'izq':izquierda, 'der':derecha}


class A1PresenceOracle(unittest.TestCase):
    def test_legacy_field_absent_remains_nd(self):
        self.assertIs(evaluate(campo(), {'fact':'LOGICO'}, {}), Truth.ND)

    def test_explicit_optional_field_absent_returns_nd(self):
        self.assertIs(evaluate(campo(opcional=True), {'fact':'LOGICO'}, {}), Truth.ND)

    def test_required_logical_field_absent_rejected(self):
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            evaluate(campo(opcional=False), {'fact':'LOGICO'}, {})

    def test_required_field_present_with_nd_is_not_missing(self):
        self.assertIs(evaluate(campo(opcional=False), {'fact':'LOGICO'},
                               {'fact':Truth.ND}), Truth.ND)

    def test_required_field_present_true_and_false(self):
        for value in (Truth.VERDADERO, Truth.FALSO):
            with self.subTest(value=value):
                self.assertIs(evaluate(campo(opcional=False), {'fact':'LOGICO'},
                                       {'fact':value}), value)

    def test_optional_field_present_still_evaluates_normally(self):
        self.assertIs(evaluate(campo(opcional=True), {'fact':'LOGICO'},
                               {'fact':Truth.FALSO}), Truth.FALSO)

    def test_nonlogical_required_rational_field_in_comparison(self):
        e = comparar('MAYOR', campo('riesgo', False),
                     {'op':'CONSTANTE', 'tipo':'RACIONAL', 'valor':'1/2'})
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            evaluate(e, {'riesgo':'RACIONAL'}, {})
        self.assertIs(evaluate(e, {'riesgo':'RACIONAL'}, {'riesgo':Fraction(3,4)}),
                      Truth.VERDADERO)

    def test_optional_rational_absent_yields_nd(self):
        e = comparar('IGUAL', campo('riesgo', True),
                     {'op':'CONSTANTE','tipo':'RACIONAL','valor':'0'})
        self.assertIs(evaluate(e, {'riesgo':'RACIONAL'}, {}), Truth.ND)

    def test_required_text_in_membership(self):
        e = comparar('PERTENECE', campo('servicio', False),
                     {'op':'CONSTANTE','tipo':'CONJUNTO_TEXTO','valor':['FTP','SSH']})
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            evaluate(e, {'servicio':'TEXTO'}, {})
        self.assertIs(evaluate(e, {'servicio':'TEXTO'}, {'servicio':'SSH'}),
                      Truth.VERDADERO)

    def test_required_set_in_subset(self):
        e = comparar('SUBCONJUNTO', campo('observados', False),
                     {'op':'CONSTANTE','tipo':'CONJUNTO_TEXTO','valor':['FTP','SSH']})
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            evaluate(e, {'observados':'CONJUNTO_TEXTO'}, {})
        self.assertIs(evaluate(e, {'observados':'CONJUNTO_TEXTO'},
                               {'observados':frozenset(['SSH'])}), Truth.VERDADERO)

    def test_required_set_present_and_empty_is_not_missing(self):
        e = comparar('SUBCONJUNTO', campo('observados', False),
                     {'op':'CONSTANTE','tipo':'CONJUNTO_TEXTO','valor':[]})
        self.assertIs(evaluate(e, {'observados':'CONJUNTO_TEXTO'},
                               {'observados':frozenset()}), Truth.VERDADERO)

    def test_invalid_optional_types_rejected_statically(self):
        for bad in (None, 0, 1, 'false', [], {}, Truth.FALSO):
            with self.subTest(bad=repr(bad)):
                e = campo()
                e['opcional']=bad
                with self.assertRaisesRegex(A1Error, 'opcional_invalido'):
                    compile_expression(e, {'fact':'LOGICO'})

    def test_extra_metadata_denied(self):
        e = campo(opcional=False)
        e['shell'] = 'never'
        with self.assertRaisesRegex(A1Error, 'estructura_invalida'):
            evaluate(e, {'fact':'LOGICO'}, {})

    def test_unknown_field_rejected_even_optional(self):
        for flag in (False, True):
            with self.subTest(flag=flag), self.assertRaisesRegex(A1Error, 'campo_no_autorizado'):
                compile_expression(campo('undeclared', flag), {'fact':'LOGICO'})

    def test_wrong_supplied_type_never_coerced(self):
        with self.assertRaisesRegex(A1Error, 'ambiente_tipo_invalido'):
            evaluate(campo(opcional=False), {'fact':'LOGICO'}, {'fact':True})

    def test_no_short_circuit_hides_missing_required_field(self):
        expr={'op':'O', 'args':[logico(Truth.VERDADERO),campo(opcional=False)]}
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            evaluate(expr, {'fact':'LOGICO'}, {})

    def test_optional_field_and_trivalent_and(self):
        expr={'op':'Y','args':[logico(Truth.VERDADERO),campo(opcional=True)]}
        self.assertIs(evaluate(expr, {'fact':'LOGICO'}, {}), Truth.ND)

    def test_decide_missing_required_in_nonwinning_row_fails_closed(self):
        rows=[{'id':'A','condicion':logico(Truth.VERDADERO)},
              {'id':'B','condicion':campo(opcional=False)}]
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            decide(rows, {'fact':'LOGICO'}, {})

    def test_frozen_preflight_required_present_and_absent(self):
        config={'format':RULE_FORMAT, 'fields':{'fact':'LOGICO'},'services':[
            {'id':'SSH01','initial_state':'PREPARADO',
             'rules':[{'id':'R1','condicion':campo(opcional=False)}]}]}
        frozen=preflight_rule_configuration(config)
        with self.assertRaisesRegex(A1Error, 'campo_obligatorio_ausente'):
            frozen.evaluate_service('SSH01', {})
        self.assertEqual(frozen.evaluate_service('SSH01', {'fact':Truth.VERDADERO}).selected_rule,
                         'R1')
        self.assertFalse(frozen.evaluate_service('SSH01', {'fact':Truth.VERDADERO}).operationally_authorized)

    def test_r22_consumer_rejects_missing_required_instead_of_nd(self):
        conditions=[{'id':'G1','condicion':campo('FACT',False)},
                    {'id':'G2','condicion':logico(Truth.FALSO)}]
        sources=custom(conditions=conditions,fields={'FACT':'LOGICO'})
        with self.assertRaisesRegex(GuardPreviewError, 'a1_campo_obligatorio_ausente'):
            diagnose_guards(*sources,{'SSH_01':{}})

    def test_legacy_compiled_node_remains_identical_with_explicit_optional_true(self):
        a=compile_expression(campo(), {'fact':'LOGICO'})
        b=compile_expression(campo(opcional=True), {'fact':'LOGICO'})
        self.assertEqual(a,b)

    def test_legacy_false_row_remains_no_match_nd(self):
        rows=[{'id':'R1','condicion':campo()}]
        result=decide(rows, {'fact':'LOGICO'}, {'fact':Truth.FALSO})
        self.assertIs(result.status, Truth.ND)
        self.assertEqual(result.evaluations,(('R1', Truth.FALSO),))


if __name__ == '__main__':
    unittest.main()
