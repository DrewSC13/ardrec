"""Pruebas negativas R20: controles sintéticos sin autoridad ni despachos."""
from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from ardrec.initialization.rule_preflight import (FORMAT as RF,
    preflight_rule_configuration)
from ardrec.initialization.initial_preview import (FORMAT as IF,
    prepare_initial_preview)
from ardrec.initialization.dependency_preview import (FORMAT as DF,
    prepare_dependency_preview)
from ardrec.initialization.control_preview import (FORMAT, MAX_CONTROLS,
    ControlPreviewError, prepare_control_preview)
from ardrec.state import ServicePhase


def input_set(n=3):
    names=[f'{("SSH","FTP","SMB")[i%3]}_{i:02d}' for i in range(n)]
    rules=preflight_rule_configuration({
        'format':RF,'fields':{},'services':[
            {'id':sid,'initial_state':'PREPARADO','rules':[
                {'id':'ALLOW','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}},
                {'id':'DENY','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'FALSO'}}
            ]} for sid in names]
    })
    initial=prepare_initial_preview(rules,{'format':IF,'rule_source_sha256':rules.sha256,
        'services':[{'id':sid,'initial_risk':'1/4','normalized_criticality':'3/4',
                     'cases':[{'id':'C1','max_repetitions':0},
                              {'id':'C2','max_repetitions':1}]}
                    for sid in names]})
    deps=prepare_dependency_preview(rules,initial,{'format':DF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'services':[{'id':sid,'protocol':sid.split('_')[0],
                     'cases':[{'id':'C1','requires':[]},
                              {'id':'C2','requires':['C1']}]}
                    for sid in names]})
    doc={'format':FORMAT,'rule_source_sha256':rules.sha256,
         'initial_snapshot_sha256':initial.sha256,'dependency_snapshot_sha256':deps.sha256,
         'services':[{'id':sid,'controls':[
             {'id':'CONTROL_A','guard_rule_id':'ALLOW','target_case_id':'C1',
              'precedence':20,'requires':[]},
             {'id':'CONTROL_B','guard_rule_id':'DENY','target_case_id':'C2',
              'precedence':10,'requires':['CONTROL_A']}
         ]} for sid in names]}
    return rules,initial,deps,doc


class ControlPreviewR20Tests(unittest.TestCase):
    def setUp(self):
        self.rules,self.initial,self.deps,self.doc=input_set()

    def result(self,doc=None):
        return prepare_control_preview(self.rules,self.initial,self.deps,
                                       self.doc if doc is None else doc)

    def reject(self,code,mutate):
        doc=copy.deepcopy(self.doc)
        mutate(doc)
        with self.assertRaises(ControlPreviewError) as cm:
            self.result(doc)
        self.assertEqual(cm.exception.code,code)

    def test_54_units_by_protocol_and_no_operation(self):
        rules,initial,deps,doc=input_set(54)
        view=prepare_control_preview(rules,initial,deps,doc)
        self.assertTrue(view.verify(rules,initial,deps))
        self.assertEqual(len(view.units),54)
        self.assertEqual(sum(len(u.controls) for u in view.units),108)
        self.assertTrue(all(u.topological_order==('CONTROL_A','CONTROL_B') for u in view.units))
        self.assertTrue(all(x.phase is ServicePhase.PREPARADO for x in initial.units))
        self.assertTrue(all(x.accumulated_evidence == 0 and x.initial_risk == x.recalibrated_risk for x in initial.units))
        self.assertFalse(view.operational_dispatch_allowed)
        self.assertIsNone(view.published_generation)

    def test_stable_order_for_all_input_permutations(self):
        original=self.result()
        alt=copy.deepcopy(self.doc)
        alt['services'].reverse()
        for service in alt['services']:
            service['controls'].reverse()
            for c in service['controls']:
                c['requires'].reverse()
        other=self.result(alt)
        self.assertEqual(original.source,other.source)
        self.assertEqual(original.sha256,other.sha256)

    def test_precedence_does_not_break_dependency(self):
        self.assertEqual(self.result().units[0].topological_order,('CONTROL_A','CONTROL_B'))

    def test_precedence_orders_free_controls(self):
        doc=copy.deepcopy(self.doc)
        for s in doc['services']:
            s['controls'][1]['requires']=[]
        self.assertEqual(self.result(doc).units[0].topological_order,('CONTROL_B','CONTROL_A'))

    def test_empty_controls_for_every_service(self):
        doc=copy.deepcopy(self.doc)
        for s in doc['services']: s['controls']=[]
        self.assertTrue(all(not u.controls and not u.topological_order for u in self.result(doc).units))

    def test_equal_precedence_sorted_by_identity(self):
        doc=copy.deepcopy(self.doc)
        for s in doc['services']:
            s['controls'][1]['precedence']=20
            s['controls'][1]['requires']=[]
        self.assertEqual(self.result(doc).units[0].topological_order,('CONTROL_A','CONTROL_B'))

    def test_cycle_two(self):
        self.reject('dependencias_control_ciclicas',lambda d:d['services'][0]['controls'][0].update(requires=['CONTROL_B']))

    def test_self_dependency(self):
        self.reject('autodependencia_control',lambda d:d['services'][0]['controls'][0].update(requires=['CONTROL_A']))

    def test_missing_control_reference(self):
        self.reject('control_requerido_no_declarado',lambda d:d['services'][0]['controls'][1].update(requires=['X']))

    def test_other_service_control_reference(self):
        self.reject('control_requerido_no_declarado',lambda d:d['services'][0]['controls'][1].update(requires=['FOREIGN']))

    def test_duplicate_requires(self):
        self.reject('control_requerido_duplicado',lambda d:d['services'][0]['controls'][1].update(requires=['CONTROL_A','CONTROL_A']))

    def test_requires_not_list(self):
        self.reject('referencias_control_invalidas',lambda d:d['services'][0]['controls'][1].update(requires={'CONTROL_A':1}))

    def test_bad_requires_identifier(self):
        self.reject('id_control_requerido_invalido',lambda d:d['services'][0]['controls'][1].update(requires=['../CONTROL_A']))

    def test_requires_boolean_identifier(self):
        self.reject('id_control_requerido_invalido',lambda d:d['services'][0]['controls'][1].update(requires=[True]))

    def test_requires_too_many(self):
        self.reject('referencias_control_invalidas',lambda d:d['services'][0]['controls'][1].update(requires=['CONTROL_A']*(MAX_CONTROLS+1)))

    def test_unknown_guard_rule(self):
        self.reject('regla_control_no_declarada',lambda d:d['services'][0]['controls'][0].update(guard_rule_id='FOREIGN'))

    def test_boolean_guard_rule(self):
        self.reject('regla_control_no_declarada',lambda d:d['services'][0]['controls'][0].update(guard_rule_id=True))

    def test_unknown_case_target(self):
        self.reject('caso_control_no_declarado',lambda d:d['services'][0]['controls'][0].update(target_case_id='MISSING'))

    def test_case_target_path(self):
        self.reject('caso_control_no_declarado',lambda d:d['services'][0]['controls'][0].update(target_case_id='../C1'))

    def test_boolean_case_target(self):
        self.reject('caso_control_no_declarado',lambda d:d['services'][0]['controls'][0].update(target_case_id=True))

    def test_duplicate_control(self):
        self.reject('control_duplicado_o_invalido',lambda d:d['services'][0]['controls'][1].update(id='CONTROL_A'))

    def test_control_path_identifier(self):
        self.reject('control_duplicado_o_invalido',lambda d:d['services'][0]['controls'][1].update(id='../CONTROL'))

    def test_negative_precedence(self):
        self.reject('precedencia_invalida',lambda d:d['services'][0]['controls'][0].update(precedence=-1))

    def test_max_precedence_exceeded(self):
        self.reject('precedencia_invalida',lambda d:d['services'][0]['controls'][0].update(precedence=1024))

    def test_boolean_precedence(self):
        self.reject('precedencia_invalida',lambda d:d['services'][0]['controls'][0].update(precedence=True))

    def test_string_precedence(self):
        self.reject('precedencia_invalida',lambda d:d['services'][0]['controls'][0].update(precedence='1'))

    def test_zero_precedence_allowed(self):
        doc=copy.deepcopy(self.doc)
        doc['services'][0]['controls'][0]['precedence']=0
        self.assertTrue(self.result(doc).verify(self.rules,self.initial,self.deps))

    def test_no_unbounded_controls(self):
        def mutation(d):
            row=d['services'][0]['controls'][0]
            d['services'][0]['controls']=[{**row,'id':f'CTRL_{i:02d}'} for i in range(33)]
        self.reject('controles_invalidos',mutation)

    def test_control_not_dict(self):
        self.reject('control_invalido',lambda d:d['services'][0]['controls'].__setitem__(0,1))

    def test_extra_command_field_denied(self):
        self.reject('control_invalido',lambda d:d['services'][0]['controls'][0].update(argv=['ssh']))

    def test_extra_authorization_denied(self):
        self.reject('control_invalido',lambda d:d['services'][0]['controls'][0].update(authorized=True))

    def test_control_missing_field(self):
        self.reject('control_invalido',lambda d:d['services'][0]['controls'][0].pop('guard_rule_id'))

    def test_controls_not_list(self):
        self.reject('controles_invalidos',lambda d:d['services'][0].update(controls={}))

    def test_service_not_dict(self):
        self.reject('servicio_control_invalido',lambda d:d['services'].__setitem__(0,'bad'))

    def test_service_duplicate(self):
        self.reject('servicio_control_desconocido_o_duplicado',lambda d:d['services'][1].update(id=d['services'][0]['id']))

    def test_service_unknown(self):
        self.reject('servicio_control_desconocido_o_duplicado',lambda d:d['services'][1].update(id='UNKNOWN'))

    def test_service_extra_field(self):
        self.reject('servicio_control_invalido',lambda d:d['services'][1].update(operational=True))

    def test_service_missing_field(self):
        self.reject('servicio_control_invalido',lambda d:d['services'][1].pop('controls'))

    def test_service_count_missing(self):
        self.reject('servicios_no_coinciden',lambda d:d['services'].pop())

    def test_service_count_excess(self):
        self.reject('servicios_no_coinciden',lambda d:d['services'].append(copy.deepcopy(d['services'][0])))

    def test_service_input_not_list(self):
        self.reject('servicios_no_coinciden',lambda d:d.update(services={}))

    def test_root_extra_field(self):
        self.reject('control_raiz_invalida',lambda d:d.update(dispatch=True))

    def test_root_missing_field(self):
        self.reject('control_raiz_invalida',lambda d:d.pop('services'))

    def test_wrong_format(self):
        self.reject('version_incompatible',lambda d:d.update(format='wrong'))

    def test_wrong_rules_sha(self):
        self.reject('origen_no_coincide',lambda d:d.update(rule_source_sha256='0'*64))

    def test_wrong_initial_sha(self):
        self.reject('origen_no_coincide',lambda d:d.update(initial_snapshot_sha256='0'*64))

    def test_wrong_dependency_sha(self):
        self.reject('origen_no_coincide',lambda d:d.update(dependency_snapshot_sha256='0'*64))

    def test_frozen_source_unchanged_by_mutated_candidate(self):
        view=self.result()
        source=view.source
        self.doc['services'][0]['controls'][0]['id']='MUTATED'
        self.assertEqual(view.source,source)
        self.assertTrue(view.verify(self.rules,self.initial,self.deps))

    def test_frozen_source_mutated_detected(self):
        view=self.result()
        with self.assertRaisesRegex(ControlPreviewError,'control_alterado'):
            replace(view,source=view.source+b' ').verify(self.rules,self.initial,self.deps)

    def test_forged_sha_without_canonical_detected(self):
        view=self.result()
        source=view.source+b' '
        with self.assertRaisesRegex(ControlPreviewError,'control_no_valido|control_no_canonico'):
            replace(view,source=source,sha256=hashlib.sha256(source).hexdigest()).verify(self.rules,self.initial,self.deps)

    def test_in_memory_control_tamper_detected(self):
        view=self.result()
        with self.assertRaisesRegex(ControlPreviewError,'control_en_memoria_alterado'):
            replace(view,units=()).verify(self.rules,self.initial,self.deps)

    def test_wrong_sources_detected(self):
        view=self.result()
        with self.assertRaisesRegex(ControlPreviewError,'fuentes_invalidas'):
            view.verify(None,self.initial,self.deps)

    def test_wrong_source_sha_in_object_detected(self):
        view=self.result()
        with self.assertRaisesRegex(ControlPreviewError,'origen_no_coincide'):
            replace(view,rule_source_sha256='0'*64).verify(self.rules,self.initial,self.deps)

    def test_other_sources_not_reusable(self):
        view=self.result()
        rules,initial,deps,_=input_set(2)
        with self.assertRaises(ControlPreviewError):
            view.verify(rules,initial,deps)

    def test_json_duplicate_key_is_denied(self):
        view=self.result()
        raw=view.source.replace(b'"format":',b'"format":"duplicate","format":',1)
        with self.assertRaisesRegex(ControlPreviewError,'clave_duplicada'):
            replace(view,source=raw,sha256=hashlib.sha256(raw).hexdigest()).verify(self.rules,self.initial,self.deps)

    def test_hashes_separate_three_layers(self):
        view=self.result()
        self.assertNotEqual(view.sha256,self.rules.sha256)
        self.assertNotEqual(view.sha256,self.initial.sha256)
        self.assertNotEqual(view.sha256,self.deps.sha256)
        self.assertEqual(len(view.sha256),64)


if __name__=='__main__':
    unittest.main()
