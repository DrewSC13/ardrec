"""P14-R65 — Independiente: A1 contextual contra modelo ConfirmedState, NO-GO."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'src'))

from ardrec.initialization.rule_preflight import (
    FORMAT as RULE_FORMAT, preflight_rule_configuration, RulePreflightError,
)
from ardrec.rules.confirmed_context import (
    ConfirmedContextDecision, ORIGIN, evaluate_confirmed_context,
)
from ardrec.rules.kernel import A1Error
from ardrec.state import ConfirmedState, ServiceState, ServicePhase, Truth


def field(required=False):
    return {'op': 'CAMPO', 'nombre': 'FACT', 'opcional': False} if required else {
        'op': 'CAMPO', 'nombre': 'FACT'}


def literal(value):
    return {'op':'CONSTANTE', 'tipo':'LOGICO', 'valor':value.name}


def config(rows=None, services=('SSH_DEV',)):
    if rows is None:
        rows = [{'id':'ALLOW', 'condicion':field(), 'salida':'CASE_POLICY'},
                {'id':'NEVER', 'condicion':literal(Truth.FALSO)}]
    return {'format':RULE_FORMAT, 'fields':{'FACT':'LOGICO'},
            'services':[{'id':s,'initial_state':'PREPARADO', 'rules':rows}
                        for s in services]}


def confirmed(services=('SSH_DEV',), *, generation=0, config_sha='a'*64,
              version='VERSIONS_1', generation_ref='GENERATION_0'):
    phase = ServicePhase.PREPARADO if generation == 0 else ServicePhase.PENDIENTE
    return ConfirmedState(record_id='RECORD_001',generation=generation,
                          generation_reference=generation_ref,
                          configuration_sha256=config_sha,
                          versions_reference=version,
                          services=tuple(ServiceState(s, phase) for s in services))


KW = {'case_id':'CASE_POLICY', 'condition_id':'COND_FACT', 'context_id':'CTX_R65_001'}


class A1ConfirmedModelIndependentOracle(unittest.TestCase):
    def setUp(self):
        self.frozen = preflight_rule_configuration(config())
        self.state = confirmed()

    def run_model(self, env=None, **kwargs):
        return evaluate_confirmed_context(self.frozen, self.state, 'SSH_DEV',
                                          {'FACT':Truth.VERDADERO} if env is None else env,
                                          **(KW | kwargs))

    def test_01_phase_from_confirmed_model(self):
        j=json.loads(self.run_model().json_bytes())
        self.assertEqual(j['confirmed_service_phase'],'PREPARADO')
        self.assertEqual(j['a1_contextual']['estado'],'PREPARADO')
        self.assertEqual(j['a1_contextual']['origen'],ORIGIN)

    def test_02_nonzero_generation_uses_its_own_phase(self):
        state=confirmed(generation=1, generation_ref='GENERATION_1')
        r=evaluate_confirmed_context(self.frozen,state,'SSH_DEV',
                                     {'FACT':Truth.VERDADERO},**KW)
        j=json.loads(r.source)
        self.assertEqual(j['confirmed_generation'],1)
        self.assertEqual(j['confirmed_generation_reference'],'GENERATION_1')
        self.assertEqual(j['a1_contextual']['estado'],'PENDIENTE')

    def test_03_model_contains_generation_identity_and_config(self):
        j=json.loads(self.run_model().source)
        self.assertEqual(j['confirmed_record_id'],'RECORD_001')
        self.assertEqual(j['confirmed_generation'],0)
        self.assertEqual(j['confirmed_versions_reference'],'VERSIONS_1')
        self.assertEqual(j['confirmed_configuration_sha256'],'a'*64)
        self.assertEqual(j['rule_configuration_sha256'],self.frozen.sha256)

    def test_04_independent_config_digests_not_auto_attested(self):
        j=json.loads(self.run_model().source)
        self.assertNotEqual(j['confirmed_configuration_sha256'],
                            j['rule_configuration_sha256'])
        self.assertIs(j['full_configuration_to_rule_source_attested'],False)

    def test_05_integrity_and_reproducibility(self):
        a=self.run_model(); b=self.run_model()
        self.assertEqual(a,b)
        self.assertEqual(a.sha256,hashlib.sha256(a.source).hexdigest())
        self.assertTrue(a.verify(self.frozen,self.state,'SSH_DEV',
                                 {'FACT':Truth.VERDADERO},**KW))
        self.assertEqual(a.json_bytes(),a.source)

    def test_06_selected_output_is_original_a1_not_invented(self):
        j=json.loads(self.run_model().source)['a1_contextual']
        self.assertEqual(j['estado_tabla'],'VERDADERO')
        self.assertEqual(j['regla_seleccionada'],'ALLOW')
        self.assertEqual(j['salida_declarativa'],'CASE_POLICY')

    def test_07_all_false_is_nd(self):
        j=json.loads(self.run_model({'FACT':Truth.FALSO}).source)['a1_contextual']
        self.assertEqual(j['estado_tabla'],'ND')
        self.assertEqual(j['evaluaciones'],[{'id':'ALLOW','valor':'FALSO'},
                                            {'id':'NEVER','valor':'FALSO'}])

    def test_08_optional_absent_is_nd(self):
        j=json.loads(self.run_model({}).source)['a1_contextual']
        self.assertEqual(j['estado_tabla'],'ND')
        self.assertEqual(j['evaluaciones'][0]['valor'],'ND')

    def test_09_required_absent_fails_closed(self):
        f=preflight_rule_configuration(config([{'id':'MANDATORY','condicion':field(True)}]))
        with self.assertRaisesRegex(A1Error,'campo_obligatorio_ausente'):
            evaluate_confirmed_context(f,self.state,'SSH_DEV',{},**KW)

    def test_10_ambiguous_table_fails_closed(self):
        f=preflight_rule_configuration(config([
            {'id':'A','condicion':literal(Truth.VERDADERO)},
            {'id':'B','condicion':literal(Truth.VERDADERO)}]))
        with self.assertRaisesRegex(A1Error,'reglas_ambiguas'):
            evaluate_confirmed_context(f,self.state,'SSH_DEV',{},**KW)

    def test_11_absent_confirmed_service_rejected(self):
        state=confirmed(services=('FTP_DEV',))
        with self.assertRaisesRegex(A1Error,'servicio_no_confirmado'):
            evaluate_confirmed_context(self.frozen,state,'SSH_DEV',{},**KW)

    def test_12_absent_rule_service_rejected(self):
        f=preflight_rule_configuration(config(services=('FTP_DEV',)))
        with self.assertRaises(RulePreflightError):
            evaluate_confirmed_context(f,self.state,'SSH_DEV',{},**KW)

    def test_13_foreign_model_rejected(self):
        with self.assertRaisesRegex(A1Error,'estado_confirmado_modelo_invalido'):
            evaluate_confirmed_context(self.frozen,{},'SSH_DEV',{},**KW)

    def test_14_input_id_validation(self):
        for k,bad in [('case_id',''),('case_id','../FILE'),('condition_id',False),
                      ('context_id',[]),('context_id','x'*70)]:
            with self.subTest(k=k),self.assertRaisesRegex(A1Error,'identidad_contextual_invalida'):
                self.run_model(**{k:bad})

    def test_15_forged_payload_detected(self):
        r=self.run_model()
        j=json.loads(r.source)
        j['confirmed_service_phase']='CERRADO'
        raw=json.dumps(j,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        forged=ConfirmedContextDecision(raw,hashlib.sha256(raw).hexdigest(),
                                        r.confirmed_model_sha256,r.rules_source_sha256)
        self.assertEqual(forged.json_bytes(),raw)  # hash propio NO es prueba.
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_no_coincide'):
            forged.verify(self.frozen,self.state,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)

    def test_16_wrong_digest_detected(self):
        r=self.run_model()
        f=ConfirmedContextDecision(r.source,'0'*64,r.confirmed_model_sha256,r.rules_source_sha256)
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_alterado'):
            f.json_bytes()
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_no_coincide'):
            f.verify(self.frozen,self.state,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)

    def test_17_change_confirmed_generation_invalidates_replay(self):
        r=self.run_model()
        other=confirmed(generation=1,generation_ref='GENERATION_1')
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_no_coincide'):
            r.verify(self.frozen,other,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)

    def test_18_change_global_config_identity_invalidates_replay(self):
        r=self.run_model()
        other=confirmed(config_sha='b'*64)
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_no_coincide'):
            r.verify(self.frozen,other,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)

    def test_19_change_rule_source_invalidates_replay(self):
        r=self.run_model()
        f=preflight_rule_configuration(config([
            {'id':'OTHER','condicion':field()}]))
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_no_coincide'):
            r.verify(f,self.state,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)

    def test_20_change_environment_invalidates_replay(self):
        r=self.run_model()
        with self.assertRaisesRegex(A1Error,'recibo_estado_modelo_no_coincide'):
            r.verify(self.frozen,self.state,'SSH_DEV',{'FACT':Truth.FALSO},**KW)

    def test_21_change_case_condition_context_invalidates_replay(self):
        r=self.run_model()
        for changed in [{'case_id':'CASE_OTHER'}, {'condition_id':'COND_OTHER'},
                        {'context_id':'CTX_OTHER'}]:
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    A1Error,'recibo_estado_modelo_no_coincide'):
                r.verify(self.frozen,self.state,'SSH_DEV',
                         {'FACT':Truth.VERDADERO},**(KW|changed))

    def test_22_service_order_in_confirmed_model_not_semantically_meaningful(self):
        f=preflight_rule_configuration(config(services=('SSH_DEV','FTP_DEV')))
        x=confirmed(services=('SSH_DEV','FTP_DEV'))
        y=confirmed(services=('FTP_DEV','SSH_DEV'))
        a=evaluate_confirmed_context(f,x,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)
        b=evaluate_confirmed_context(f,y,'SSH_DEV',{'FACT':Truth.VERDADERO},**KW)
        self.assertEqual(a,b)

    def test_23_foreign_origin_never_attested_by_snapshot(self):
        j=json.loads(self.run_model().source)
        self.assertEqual(j['source_kind'],ORIGIN)
        self.assertIs(j['model_external_origin_attested'],False)
        self.assertIs(j['state_phase_derived_from_model'],True)

    def test_24_no_dispatch_no_publication(self):
        result=self.run_model()
        doc=json.loads(result.source)
        self.assertEqual(doc['p8_operational'],'NO-GO')
        self.assertFalse(result.operationally_authorized)
        self.assertIsNone(result.published_generation)
        self.assertIs(doc['operational_dispatch'],False)
        self.assertIsNone(doc['published_generation'])

    def test_25_immutable_receipt(self):
        r=self.run_model()
        with self.assertRaises(FrozenInstanceError):
            r.sha256='other'

    def test_26_public_frozen_api_delegation(self):
        a=self.frozen.evaluate_service_confirmed('SSH_DEV',
            {'FACT':Truth.VERDADERO},self.state,**KW)
        self.assertEqual(a,self.run_model())


if __name__ == '__main__':
    unittest.main()
