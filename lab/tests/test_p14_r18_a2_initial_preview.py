"""R18: oráculos sin ejecutor para la inicialización sintética vinculada a R17."""
from __future__ import annotations

from dataclasses import replace
from fractions import Fraction
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.initialization.rule_preflight import FORMAT as RULE_FORMAT, preflight_rule_configuration
from ardrec.initialization.initial_preview import (
    FORMAT, InitialPreviewError, prepare_initial_preview, _canonical,
    _bounded_fraction, CaseInitial, UnitInitial,
)
from ardrec.state import Truth, ServicePhase


def c(name):
    return {'id': name, 'max_repetitions': 0}


def rule_config():
    return {'format': RULE_FORMAT, 'fields': {'permiso': 'LOGICO'},
            'services': [{'id': 'SSH_LAB', 'initial_state': 'PREPARADO',
                          'rules': [{'id': 'R1', 'condicion': {'op': 'CAMPO', 'nombre': 'permiso'}}]},
                         {'id': 'SMB_LAB', 'initial_state': 'PREPARADO',
                          'rules': [{'id': 'R2', 'condicion': {'op': 'CONSTANTE',
                          'tipo': 'LOGICO', 'valor': 'VERDADERO'}}]}]}


def pair():
    p = preflight_rule_configuration(rule_config())
    inp = {'format': FORMAT, 'rule_source_sha256': p.sha256,
           'services': [
             {'id': 'SSH_LAB', 'initial_risk': '1/4', 'normalized_criticality': '1/2',
              'cases': [c('CHK1'), {'id': 'CHK2', 'max_repetitions': 1}]},
             {'id': 'SMB_LAB', 'initial_risk': '0', 'normalized_criticality': '3/4',
              'cases': [c('SMBCHK')]},
           ]}
    return p, inp


class InitialPreviewTests(unittest.TestCase):
    def setUp(self):
        self.rules,self.inp=pair()

    def err(self,code,modify):
        a=copy.deepcopy(self.inp)
        modify(a)
        with self.assertRaises(InitialPreviewError) as cm:
            prepare_initial_preview(self.rules,a)
        self.assertEqual(cm.exception.code,code)

    def test_initial_values_exact(self):
        p=prepare_initial_preview(self.rules,self.inp)
        self.assertEqual([u.id for u in p.units],['SMB_LAB','SSH_LAB'])
        self.assertEqual(p.units[0].initial_risk,Fraction(0))
        self.assertEqual(p.units[1].initial_risk,Fraction(1,4))
        self.assertEqual(p.units[1].normalized_criticality,Fraction(1,2))
        self.assertEqual(p.units[1].recalibrated_risk,Fraction(1,4))
        self.assertEqual(p.units[1].accumulated_evidence,Fraction(0))

    def test_empty_initial_history_priority_and_state(self):
        p=prepare_initial_preview(self.rules,self.inp)
        for unit in p.units:
            self.assertIs(unit.phase, ServicePhase.PREPARADO)
            self.assertIsNone(unit.priority)
            self.assertFalse(unit.local_history)
            for case in unit.cases:
                self.assertEqual(case.starts_confirmed,0)
                self.assertFalse(case.execution_results)

    def test_repeat_policy_only_zero_or_one(self):
        p=prepare_initial_preview(self.rules,self.inp)
        self.assertEqual([x.permitted_attempts_ceiling for x in p.units[1].cases],[1,2])

    def test_no_authority_and_no_generation(self):
        p=prepare_initial_preview(self.rules,self.inp)
        self.assertIsNone(p.published_generation)
        self.assertFalse(p.operational_dispatch_allowed)

    def test_verification(self):
        p=prepare_initial_preview(self.rules,self.inp)
        self.assertTrue(p.verify(self.rules))
        self.assertEqual(hashlib.sha256(p.source).hexdigest(),p.sha256)

    def test_order_independent(self):
        a=prepare_initial_preview(self.rules,self.inp)
        other=copy.deepcopy(self.inp)
        other['services'].reverse()
        other['services'][1]['cases'].reverse()
        b=prepare_initial_preview(self.rules,other)
        self.assertEqual(a.sha256,b.sha256)
        self.assertEqual(a.source,b.source)

    def test_no_source_aliasing(self):
        p=prepare_initial_preview(self.rules,self.inp)
        self.inp['services'][1]['initial_risk']='1'
        self.inp['services'][0]['cases'][0]['id']='BAD'
        self.assertTrue(p.verify(self.rules))

    def test_uneditable(self):
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaises(AttributeError):p.sha256='0'*64
        with self.assertRaises(AttributeError):p.units[0].phase=ServicePhase.PENDIENTE

    def test_guard_links_to_a1_and_does_not_change_init(self):
        p=prepare_initial_preview(self.rules,self.inp)
        for env,result in [({},Truth.ND),({'permiso':Truth.FALSO},Truth.FALSO),
                           ({'permiso':Truth.VERDADERO},Truth.VERDADERO)]:
            seen=p.evaluate_guard(self.rules,'SSH_LAB',env)
            self.assertIs(seen.status,result)
            self.assertFalse(seen.operationally_authorized)
        self.assertTrue(p.verify(self.rules))
        self.assertEqual(p.units[1].initial_risk,Fraction(1,4))

    def test_missing_service_guard(self):
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaisesRegex(InitialPreviewError,'servicio_no_declarado'):
            p.evaluate_guard(self.rules,'FTP_LAB',{})

    def test_wrong_rule_snapshot(self):
        other=rule_config();other['services'][0]['rules'][0]['id']='ALTERED'
        wrong=preflight_rule_configuration(other)
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaisesRegex(InitialPreviewError,'reglas_no_coinciden'):
            p.verify(wrong)

    def test_tamper_source(self):
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaisesRegex(InitialPreviewError,'instantanea_alterada'):
            replace(p,source=p.source+b' ').verify(self.rules)

    def test_tamper_digest(self):
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaisesRegex(InitialPreviewError,'instantanea_alterada'):
            replace(p,sha256='0'*64).verify(self.rules)

    def test_tamper_unit_memory(self):
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaisesRegex(InitialPreviewError,'riesgo_recalculado_inicial_invalido'):
            replace(p.units[0],recalibrated_risk=Fraction(1))
        altered=replace(p,units=(p.units[1],p.units[0]))
        with self.assertRaisesRegex(InitialPreviewError,'identidad_inicial_alterada'):
            altered.verify(self.rules)

    def test_bad_fraction_not_reduced(self):
        self.err('magnitud_no_canonica',lambda a:a['services'][0].update(initial_risk='2/8'))

    def test_float(self):
        self.err('magnitud_no_canonica',lambda a:a['services'][0].update(initial_risk=0.25))

    def test_negative_risk(self):
        self.err('magnitud_no_canonica',lambda a:a['services'][0].update(initial_risk='-1/2'))

    def test_risk_above_one(self):
        self.err('magnitud_fuera_de_dominio',lambda a:a['services'][0].update(initial_risk='5/4'))

    def test_criticality_above_one(self):
        self.err('magnitud_fuera_de_dominio',lambda a:a['services'][0].update(normalized_criticality='2'))

    def test_bool_magnitude(self):
        self.err('magnitud_no_canonica',lambda a:a['services'][0].update(initial_risk=True))

    def test_long_fraction(self):
        self.err('magnitud_no_canonica',lambda a:a['services'][0].update(initial_risk='1/'+'9'*81))

    def test_zero_one_boundaries(self):
        a=copy.deepcopy(self.inp)
        a['services'][0]['initial_risk']='1'
        a['services'][1]['normalized_criticality']='0'
        self.assertTrue(prepare_initial_preview(self.rules,a).verify(self.rules))

    def test_wrong_root_key(self):
        self.err('configuracion_inicial_invalida',lambda a:a.update(argv=['ssh']))

    def test_wrong_format(self):
        self.err('version_incompatible',lambda a:a.update(format='unknown'))

    def test_wrong_source_hash(self):
        self.err('reglas_no_coinciden',lambda a:a.update(rule_source_sha256='0'*64))

    def test_service_missing(self):
        self.err('cantidad_servicios_no_coincide',lambda a:a['services'].pop())

    def test_service_extra(self):
        self.err('cantidad_servicios_no_coincide',lambda a:a['services'].append(copy.deepcopy(a['services'][0])))

    def test_service_duplicate(self):
        self.err('servicio_duplicado_o_invalido',lambda a:a['services'][1].update(id='SSH_LAB'))

    def test_wrong_service_identity(self):
        self.err('servicios_no_coinciden',lambda a:a['services'][1].update(id='OTHER'))

    def test_service_unexpected_field(self):
        self.err('servicio_inicial_invalido',lambda a:a['services'][0].update(authorized=True))

    def test_missing_cases(self):
        self.err('casos_iniciales_invalidos',lambda a:a['services'][0].update(cases=[]))

    def test_duplicate_case(self):
        self.err('caso_duplicado_o_invalido',lambda a:a['services'][0]['cases'].append(c('CHK1')))

    def test_bad_case_id(self):
        self.err('caso_duplicado_o_invalido',lambda a:a['services'][0]['cases'][0].update(id='../evil'))

    def test_no_repetition_beyond_one(self):
        self.err('repeticion_no_permitida',lambda a:a['services'][0]['cases'][0].update(max_repetitions=2))

    def test_bool_repeat_denied(self):
        self.err('repeticion_no_permitida',lambda a:a['services'][0]['cases'][0].update(max_repetitions=True))

    def test_case_extra_field_denied(self):
        self.err('caso_invalido',lambda a:a['services'][0]['cases'][0].update(command='ssh host'))

    def test_nonlist_cases(self):
        self.err('casos_iniciales_invalidos',lambda a:a['services'][0].update(cases={}))

    def test_malformed_root(self):
        with self.assertRaisesRegex(InitialPreviewError,'configuracion_inicial_invalida'):
            prepare_initial_preview(self.rules, ['not','dict'])

    def test_malformed_service(self):
        self.err('servicio_inicial_invalido',lambda a:a['services'].__setitem__(0,False))

    def test_malformed_case(self):
        self.err('caso_invalido',lambda a:a['services'][0]['cases'].__setitem__(0,'bad'))

    def test_total_bounds(self):
        a=copy.deepcopy(self.inp)
        a['services'][0]['cases']=[c(f'C{i}') for i in range(65)]
        with self.assertRaisesRegex(InitialPreviewError,'casos_iniciales_invalidos'):
            prepare_initial_preview(self.rules,a)

    def test_initial_case_immutable_rejects_invalid(self):
        with self.assertRaisesRegex(InitialPreviewError,'contador_inicial_invalido'):
            CaseInitial('A',1,starts_confirmed=1)

    def test_initial_unit_constructor_rejects_wrong_state(self):
        p=prepare_initial_preview(self.rules,self.inp)
        with self.assertRaisesRegex(InitialPreviewError,'estado_inicial_invalido'):
            replace(p.units[0],phase=ServicePhase.PENDIENTE)

    def test_rejects_rule_snapshot_forged_not_preflight(self):
        with self.assertRaisesRegex(InitialPreviewError,'prevalidacion_requerida'):
            prepare_initial_preview(None,self.inp)

    def test_identity_normalization_matches_rule_source(self):
        p=prepare_initial_preview(self.rules,self.inp)
        self.assertEqual([x.id for x in p.units], list(self.rules.service_ids))
        self.assertEqual(p.rule_source_sha256,self.rules.sha256)

    def test_reject_noncanonical_serialized_fragment(self):
        with self.assertRaisesRegex(InitialPreviewError,'serializacion_invalida'):
            _canonical({'x':object()})


if __name__ == '__main__':
    unittest.main()
