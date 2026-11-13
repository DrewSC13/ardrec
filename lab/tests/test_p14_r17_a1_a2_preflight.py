"""R17: oráculos de prevalidación estructural A1/A2, sin despacho."""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.initialization.rule_preflight import (
    FORMAT, FrozenRulePreview, RulePreflightError, preflight_rule_configuration,
)
from ardrec.rules.kernel import A1Error, decide
from ardrec.state import Truth


def field(name='control'):
    return {'op': 'CAMPO', 'nombre': name}


def row(rid='R1', expr=None):
    return {'id': rid, 'condicion': field() if expr is None else expr}


def source():
    return {'format': FORMAT, 'fields': {'control': 'LOGICO', 'riesgo': 'RACIONAL'},
            'services': [{'id': 'SSH01', 'initial_state': 'PREPARADO', 'rules': [row()]}]}


class RulePreflightTests(unittest.TestCase):
    def assert_code(self, obj, code):
        with self.assertRaises(RulePreflightError) as err:
            preflight_rule_configuration(obj)
        self.assertEqual(err.exception.code, code)

    def test_preflight_accepts_minimal(self):
        result = preflight_rule_configuration(source())
        self.assertEqual(result.service_ids, ('SSH01',))
        self.assertEqual(len(result.sha256), 64)

    def test_preflight_canonical_same_inputs(self):
        self.assertEqual(preflight_rule_configuration(source()),
                         preflight_rule_configuration(copy.deepcopy(source())))

    def test_service_order_invariant(self):
        a = source()
        a['services'].append({'id': 'SMB01', 'initial_state': 'PREPARADO',
                              'rules': [row('R2')]})
        b = copy.deepcopy(a); b['services'].reverse()
        self.assertEqual(preflight_rule_configuration(a).sha256,
                         preflight_rule_configuration(b).sha256)

    def test_rule_order_invariant(self):
        a = source();a['services'][0]['rules'].append(row('R2',
                     {'op': 'CONSTANTE', 'tipo': 'LOGICO', 'valor': 'FALSO'}))
        b = copy.deepcopy(a);b['services'][0]['rules'].reverse()
        self.assertEqual(preflight_rule_configuration(a).source,
                         preflight_rule_configuration(b).source)

    def test_schema_field_order_invariant(self):
        a = source();b = copy.deepcopy(a)
        b['fields'] = {'riesgo': 'RACIONAL', 'control': 'LOGICO'}
        self.assertEqual(preflight_rule_configuration(a).sha256,
                         preflight_rule_configuration(b).sha256)

    def test_source_mutation_does_not_change_frozen(self):
        a = source();frozen = preflight_rule_configuration(a)
        a['fields']['control'] = 'TEXTO';a['services'][0]['rules'][0]['id']='MUTADA'
        self.assertEqual(frozen.evaluate_service('SSH01',{'control':Truth.VERDADERO}).selected_rule,'R1')

    def test_frozen_bytes_immutable(self):
        frozen=preflight_rule_configuration(source())
        with self.assertRaises(AttributeError):
            frozen.source=b'changed'

    def test_modified_frozen_bytes_detected(self):
        frozen=preflight_rule_configuration(source())
        with self.assertRaisesRegex(RulePreflightError,'instantanea_alterada'):
            replace(frozen,source=frozen.source+b'X').evaluate_service('SSH01',{})

    def test_modified_frozen_digest_detected(self):
        frozen=preflight_rule_configuration(source())
        with self.assertRaisesRegex(RulePreflightError,'instantanea_alterada'):
            replace(frozen,sha256='0'*64).evaluate_service('SSH01',{})

    def test_undeclared_service_denied(self):
        frozen=preflight_rule_configuration(source())
        with self.assertRaisesRegex(RulePreflightError,'servicio_no_declarado'):
            frozen.evaluate_service('FTP01',{})

    def test_nd_guard_does_not_authorize(self):
        result=preflight_rule_configuration(source()).evaluate_service('SSH01',{})
        self.assertEqual(result.status,Truth.ND)
        self.assertFalse(result.logical_guard_satisfied)
        self.assertFalse(result.operationally_authorized)

    def test_false_guard_does_not_authorize(self):
        result=preflight_rule_configuration(source()).evaluate_service('SSH01',{'control':Truth.FALSO})
        self.assertEqual(result.status,Truth.FALSO)
        self.assertFalse(result.logical_guard_satisfied)
        self.assertFalse(result.operationally_authorized)

    def test_true_guard_only_logical_not_p8(self):
        result=preflight_rule_configuration(source()).evaluate_service('SSH01',{'control':Truth.VERDADERO})
        self.assertEqual(result.status,Truth.VERDADERO)
        self.assertTrue(result.logical_guard_satisfied)
        self.assertFalse(result.operationally_authorized)

    def test_matches_direct_a1_for_truth_table(self):
        original=source();snapshot=preflight_rule_configuration(original)
        for truth in [Truth.VERDADERO,Truth.FALSO,Truth.ND]:
            env={'control':truth}
            expected=decide(original['services'][0]['rules'],original['fields'],env)
            seen=snapshot.evaluate_service('SSH01',env)
            self.assertEqual(seen.status,expected.status)
            self.assertEqual(seen.selected_rule,expected.selected)
            self.assertEqual(seen.evaluations,expected.evaluations)

    def test_nd_and_true_stays_uncertain(self):
        a=source();a['services'][0]['rules'].append(row('R2',{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}))
        f=preflight_rule_configuration(a)
        self.assertEqual(f.evaluate_service('SSH01',{}).status,Truth.ND)
        self.assertFalse(f.evaluate_service('SSH01',{}).logical_guard_satisfied)

    def test_two_true_rules_rejected_ambiguously(self):
        a=source();a['services'][0]['rules'].append(row('R2',{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}))
        f=preflight_rule_configuration(a)
        with self.assertRaisesRegex(A1Error,'reglas_ambiguas'):
            f.evaluate_service('SSH01',{'control':Truth.VERDADERO})

    def test_exact_fraction_boundary(self):
        a=source();a['services'][0]['rules']=[row('R1',{'op':'COMPARAR','relacion':'MAYOR_IGUAL',
          'izq':field('riesgo'),'der':{'op':'CONSTANTE','tipo':'RACIONAL','valor':'1/2'}})]
        f=preflight_rule_configuration(a)
        for value,truth in [(Fraction(1,3),Truth.FALSO),(Fraction(1,2),Truth.VERDADERO),
                            (Fraction(2,3),Truth.VERDADERO)]:
            self.assertEqual(f.evaluate_service('SSH01',{'riesgo':value}).status,truth)

    def test_float_environment_denied(self):
        f=preflight_rule_configuration(source())
        with self.assertRaisesRegex(A1Error,'ambiente_tipo_invalido'):
            f.evaluate_service('SSH01',{'riesgo':0.25})

    def test_extra_environment_denied(self):
        f=preflight_rule_configuration(source())
        with self.assertRaisesRegex(A1Error,'ambiente_no_autorizado'):
            f.evaluate_service('SSH01',{'comando':'ssh'})

    def test_no_indirect_state_publication(self):
        a=source();f=preflight_rule_configuration(a)
        f.evaluate_service('SSH01',{'control':Truth.VERDADERO})
        self.assertEqual(a,source())

    def test_bad_root_keys(self):
        a=source();a['dispatch']=True
        self.assert_code(a,'configuracion_invalida')

    def test_wrong_format(self):
        a=source();a['format']='v0'
        self.assert_code(a,'version_incompatible')

    def test_duplicate_services(self):
        a=source();a['services'].append(copy.deepcopy(a['services'][0]))
        self.assert_code(a,'identidad_servicio_invalida_o_duplicada')

    def test_wrong_initial_state(self):
        a=source();a['services'][0]['initial_state']='ACTIVO'
        self.assert_code(a,'estado_inicial_no_preparado')

    def test_nonlogical_root_expression(self):
        a=source();a['services'][0]['rules']=[row('R1',field('riesgo'))]
        self.assert_code(a,'condicion_no_logica')

    def test_duplicate_row_ids(self):
        a=source();a['services'][0]['rules'].append(copy.deepcopy(a['services'][0]['rules'][0]))
        self.assert_code(a,'identidad_regla_invalida_o_duplicada')

    def test_nonexistent_field_fails_preflight(self):
        a=source();a['services'][0]['rules']=[row('R1',field('otra'))]
        with self.assertRaisesRegex(A1Error,'campo_no_autorizado'):
            preflight_rule_configuration(a)

    def test_unknown_operator_fails_preflight(self):
        a=source();a['services'][0]['rules']=[row('R1',{'op':'LANZAR','argv':['ssh']})]
        with self.assertRaisesRegex(A1Error,'operador_no_autorizado'):
            preflight_rule_configuration(a)

    def test_missing_service_denied(self):
        a=source();a['services']=[]
        self.assert_code(a,'servicios_invalidos')

    def test_missing_rules_denied(self):
        a=source();a['services'][0]['rules']=[]
        self.assert_code(a,'tabla_invalida')

    def test_service_over_limit_denied(self):
        a=source();a['services']=[{'id':f'S{i}','initial_state':'PREPARADO','rules':[row()]} for i in range(33)]
        self.assert_code(a,'servicios_invalidos')

    def test_schema_type_denied(self):
        a=source();a['fields']['riesgo']='FLOAT'
        self.assert_code(a,'esquema_invalido')

    def test_cyclic_expression_denied(self):
        a=source();expr={'op':'NO'};expr['arg']=expr
        a['services'][0]['rules']=[row('R1',expr)]
        with self.assertRaisesRegex(A1Error,'expresion_ciclica'):
            preflight_rule_configuration(a)

    def test_noncanonical_fraction_denied(self):
        a=source();a['services'][0]['rules']=[row('R1',{'op':'COMPARAR','relacion':'IGUAL',
          'izq':field('riesgo'),'der':{'op':'CONSTANTE','tipo':'RACIONAL','valor':'2/4'}})]
        with self.assertRaisesRegex(A1Error,'racional_no_canonico'):
            preflight_rule_configuration(a)

    def test_extraneous_rule_metadata_denied(self):
        a=source();a['services'][0]['rules'][0]['authorization']='P8_GO'
        self.assert_code(a,'fila_invalida')

    def test_invalid_schema_identifier(self):
        a=source();a['fields']['bad/name']='LOGICO'
        self.assert_code(a,'esquema_invalido')

    def test_no_implicit_dict_in_decision(self):
        a=source();a['services'][0]['rules'][0]['condicion']={}
        with self.assertRaisesRegex(A1Error,'operador_no_autorizado'):
            preflight_rule_configuration(a)


if __name__=='__main__':
    unittest.main()
