"""Oráculo independiente R64: resultado contextual de DECIDIR, sin autoridad P8."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))

from ardrec.initialization.rule_preflight import (
    FORMAT, FrozenRulePreview, RulePreflightError,
    preflight_rule_configuration,
)
from ardrec.rules.contextual import ContextualDecision, evaluate_contextual
from ardrec.rules.kernel import A1Error
from ardrec.state import ServicePhase, Truth


def field(name='FACT'):
    return {'op': 'CAMPO', 'nombre': name}


def literal(value: Truth):
    return {'op': 'CONSTANTE', 'tipo': 'LOGICO', 'valor': value.name}


def config(rows=None):
    if rows is None:
        rows = [
            {'id': 'ALLOW', 'condicion': field(), 'salida': 'CASE_POLICY'},
            {'id': 'NEVER', 'condicion': literal(Truth.FALSO), 'salida': 'NO_COINCIDE'},
        ]
    return {'format': FORMAT, 'fields': {'FACT': 'LOGICO'},
            'services': [{'id': 'SSH_DEV', 'initial_state': 'PREPARADO',
                          'rules': rows}]}


KW = dict(current_state=ServicePhase.PREPARADO, origin='SYNTHETIC_FIXTURE',
          case_id='CASE_POLICY', condition_id='COND_EVIDENCIA',
          context_id='CTX_R64_001')


class ContextualDecisionIndependentOracle(unittest.TestCase):
    def setUp(self):
        self.frozen = preflight_rule_configuration(config())

    def result(self, environment, **kw):
        return self.frozen.evaluate_service_contextual('SSH_DEV', environment,
                                                       **(dict(KW) | kw))

    def test_true_receipt_all_seven_fields_and_selected_output(self):
        r = self.result({'FACT': Truth.VERDADERO})
        j = json.loads(r.json_bytes())
        self.assertEqual({k: j[k] for k in (
            'estado','origen','configuracion','servicio','caso','condicion','contexto')}, {
            'estado':'PREPARADO', 'origen':'SYNTHETIC_FIXTURE',
            'configuracion':self.frozen.sha256,'servicio':'SSH_DEV',
            'caso':'CASE_POLICY','condicion':'COND_EVIDENCIA',
            'contexto':'CTX_R64_001'})
        self.assertEqual(j['estado_tabla'], 'VERDADERO')
        self.assertEqual(j['regla_seleccionada'], 'ALLOW')
        self.assertEqual(j['salida_declarativa'], 'CASE_POLICY')
        self.assertEqual(j['evaluaciones'], [
            {'id':'ALLOW', 'valor':'VERDADERO'},
            {'id':'NEVER', 'valor':'FALSO'}])

    def test_false_individual_no_match_is_nd_without_selected_output(self):
        j = json.loads(self.result({'FACT':Truth.FALSO}).json_bytes())
        self.assertEqual(j['estado_tabla'], 'ND')
        self.assertIsNone(j['regla_seleccionada'])
        self.assertIsNone(j['salida_declarativa'])
        self.assertEqual(j['evaluaciones'], [
            {'id':'ALLOW', 'valor':'FALSO'}, {'id':'NEVER', 'valor':'FALSO'}])
        self.assertEqual(j['condicion'], 'COND_EVIDENCIA')

    def test_absent_optional_fact_remains_nd_and_preserves_context(self):
        j = json.loads(self.result({}).json_bytes())
        self.assertEqual(j['estado_tabla'], 'ND')
        self.assertEqual(j['evaluaciones'][0]['valor'], 'ND')
        self.assertEqual(j['origen'], 'SYNTHETIC_FIXTURE')

    def test_deterministic_order_and_hash(self):
        r = self.result({'FACT': Truth.VERDADERO})
        again = self.result({'FACT': Truth.VERDADERO})
        self.assertEqual(r.source, again.source)
        self.assertEqual(r.sha256, hashlib.sha256(r.source).hexdigest())
        self.assertEqual(r.sha256, again.sha256)
        self.assertEqual(r.configuration_sha256, self.frozen.sha256)
        self.assertTrue(r.verify(self.frozen, 'SSH_DEV', {'FACT':Truth.VERDADERO}, **KW))

    def test_reordered_rules_same_receipt(self):
        source = config()
        source['services'][0]['rules'].reverse()
        other = preflight_rule_configuration(source)
        r = self.result({'FACT':Truth.VERDADERO})
        self.assertEqual(r.source, other.evaluate_service_contextual(
            'SSH_DEV', {'FACT':Truth.VERDADERO}, **KW).source)

    def test_configuration_mutation_does_not_change_receipt(self):
        source = config()
        frozen = preflight_rule_configuration(source)
        before = frozen.evaluate_service_contextual('SSH_DEV', {'FACT':Truth.VERDADERO}, **KW)
        source['services'][0]['rules'][0]['salida'] = 'FALSIFICADA'
        after = frozen.evaluate_service_contextual('SSH_DEV', {'FACT':Truth.VERDADERO}, **KW)
        self.assertEqual(before.source, after.source)

    def test_tamper_bytes_detected_by_verification(self):
        r = self.result({'FACT':Truth.VERDADERO})
        modified = r.source.replace(b'CASE_POLICY', b'CASE_FAILXX')
        forged = ContextualDecision(modified, r.sha256, r.configuration_sha256)
        with self.assertRaisesRegex(A1Error, 'recibo_contextual_alterado'):
            forged.json_bytes()
        with self.assertRaisesRegex(A1Error, 'recibo_contextual_no_coincide'):
            forged.verify(self.frozen, 'SSH_DEV', {'FACT':Truth.VERDADERO}, **KW)

    def test_rehashed_forgery_rejected_by_recomputation(self):
        r = self.result({'FACT':Truth.VERDADERO})
        content = json.loads(r.source)
        content['origen'] = 'OTRA_FUENTE'
        raw = json.dumps(content, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True).encode('ascii')
        forged = ContextualDecision(raw, hashlib.sha256(raw).hexdigest(), self.frozen.sha256)
        self.assertEqual(forged.json_bytes(), raw)  # El hash no acredita origen.
        with self.assertRaisesRegex(A1Error, 'recibo_contextual_no_coincide'):
            forged.verify(self.frozen, 'SSH_DEV', {'FACT':Truth.VERDADERO}, **KW)

    def test_wrong_configuration_reference_rejected(self):
        r = self.result({'FACT':Truth.VERDADERO})
        forged = ContextualDecision(r.source, r.sha256, '0'*64)
        with self.assertRaisesRegex(A1Error, 'recibo_contextual_no_coincide'):
            forged.verify(self.frozen, 'SSH_DEV', {'FACT':Truth.VERDADERO}, **KW)

    def test_changed_condition_context_or_state_fails_verification(self):
        r = self.result({'FACT':Truth.VERDADERO})
        for change in ({'condition_id':'OTRA_COND'}, {'context_id':'CTX_2'},
                       {'current_state':ServicePhase.PENDIENTE},
                       {'origin':'OTRA_FUENTE'}, {'case_id':'CASE_OTHER'}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(A1Error, 'recibo_contextual_no_coincide'):
                    r.verify(self.frozen, 'SSH_DEV', {'FACT':Truth.VERDADERO},
                             **(dict(KW)|change))

    def test_invalid_contextual_identities_rejected(self):
        for name, bad in [('origin',''),('origin','FUENTE EXTERNA'),
                          ('origin',None),('case_id','x'*65),
                          ('case_id','../escape'),('condition_id',False),
                          ('context_id',[]),('context_id','')]:
            with self.subTest(name=name, bad=bad), self.assertRaisesRegex(
                    A1Error,'identidad_contextual_invalida'):
                self.result({'FACT':Truth.VERDADERO}, **{name:bad})

    def test_invalid_state_rejected(self):
        for bad in ('PREPARADO', None, 0, True):
            with self.subTest(bad=bad), self.assertRaisesRegex(
                    A1Error,'estado_actual_invalido'):
                self.result({'FACT':Truth.VERDADERO}, current_state=bad)

    def test_unregistered_service_is_not_invented(self):
        with self.assertRaises(RulePreflightError):
            self.frozen.evaluate_service_contextual('SMB_DEV',
                {'FACT':Truth.VERDADERO}, **KW)

    def test_invalid_environment_rejected(self):
        with self.assertRaisesRegex(A1Error,'ambiente_tipo_invalido'):
            self.result({'FACT': True})

    def test_multiple_true_rows_remain_ambiguous(self):
        rows = [{'id':'A','condicion':literal(Truth.VERDADERO)},
                {'id':'B','condicion':literal(Truth.VERDADERO)}]
        frozen = preflight_rule_configuration(config(rows))
        with self.assertRaisesRegex(A1Error, 'reglas_ambiguas'):
            frozen.evaluate_service_contextual('SSH_DEV', {}, **KW)

    def test_required_field_missing_fails_closed(self):
        rows = [{'id':'REQUIRED','condicion':{
            'op':'CAMPO','nombre':'FACT','opcional':False}}]
        frozen = preflight_rule_configuration(config(rows))
        with self.assertRaisesRegex(A1Error,'campo_obligatorio_ausente'):
            frozen.evaluate_service_contextual('SSH_DEV', {}, **KW)

    def test_p8_and_publication_are_always_denied(self):
        r = self.result({'FACT':Truth.VERDADERO})
        self.assertFalse(r.operationally_authorized)
        self.assertIsNone(r.published_generation)
        doc = json.loads(r.source)
        self.assertIs(doc['procedencia_externa_acreditada'], False)
        self.assertIs(doc['autoridad_operacional'], False)
        self.assertIs(doc['generacion_publicada'], False)
        self.assertEqual(doc['p8'], 'NO-GO')

    def test_receipt_is_immutable(self):
        r = self.result({'FACT':Truth.VERDADERO})
        with self.assertRaises(FrozenInstanceError):
            r.sha256 = '0'*64

    def test_origin_declared_not_attested_by_hash(self):
        a = self.result({'FACT':Truth.VERDADERO}, origin='SYNTHETIC_FIXTURE')
        b = self.result({'FACT':Truth.VERDADERO}, origin='DOCUMENTARY_INPUT')
        self.assertNotEqual(a.sha256, b.sha256)
        self.assertFalse(json.loads(a.source)['procedencia_externa_acreditada'])
        self.assertFalse(json.loads(b.source)['procedencia_externa_acreditada'])

    def test_normal_core_preview_unchanged(self):
        normal = self.frozen.evaluate_service('SSH_DEV', {'FACT':Truth.VERDADERO})
        extra = self.result({'FACT':Truth.VERDADERO})
        j = json.loads(extra.source)
        self.assertEqual(normal.status.value, j['estado_tabla'])
        self.assertEqual(normal.selected_rule, j['regla_seleccionada'])
        self.assertEqual(normal.selected_output, j['salida_declarativa'])
        self.assertFalse(normal.operationally_authorized)


if __name__ == '__main__':
    unittest.main()
