"""R19: cierre referencial sintético de A2, sin autoridad ni ejecución."""
from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from ardrec.initialization.rule_preflight import (
    FORMAT as RULE_FORMAT, MAX_SERVICES, RulePreflightError,
    preflight_rule_configuration,
)
from ardrec.initialization.initial_preview import FORMAT as INITIAL_FORMAT, prepare_initial_preview
from ardrec.initialization.dependency_preview import (
    FORMAT, DependencyPreviewError, prepare_dependency_preview,
)
from ardrec.state import ServicePhase


def make_inputs(n=3):
    names=[f'{("SSH","FTP","SMB")[i%3]}_{i:02d}' for i in range(n)]
    rules=preflight_rule_configuration({
        'format':RULE_FORMAT,'fields':{},
        'services':[{'id':sid,'initial_state':'PREPARADO','rules':[
            {'id':'ALLOW','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}}
        ]} for sid in names],
    })
    initial=prepare_initial_preview(rules,{
        'format':INITIAL_FORMAT,'rule_source_sha256':rules.sha256,
        'services':[{'id':sid,'initial_risk':'1/4','normalized_criticality':'3/4',
                     'cases':[{'id':'C1','max_repetitions':0},
                              {'id':'C2','max_repetitions':1},
                              {'id':'C3','max_repetitions':0}]}
                    for sid in names],
    })
    doc={'format':FORMAT,'rule_source_sha256':rules.sha256,
         'initial_snapshot_sha256':initial.sha256,
         'services':[{'id':sid,'protocol':sid.split('_')[0], 'cases':[
             {'id':'C1','requires':[]}, {'id':'C2','requires':['C1']},
             {'id':'C3','requires':['C2','C1']}]}
             for sid in names]}
    return rules,initial,doc


class R19DependencyPreviewTests(unittest.TestCase):
    def setUp(self):
        self.rules,self.initial,self.doc=make_inputs()

    def rejection(self, code, update):
        doc=copy.deepcopy(self.doc)
        update(doc)
        with self.assertRaises(DependencyPreviewError) as ctx:
            prepare_dependency_preview(self.rules,self.initial,doc)
        self.assertEqual(ctx.exception.code,code)

    def test_54_units_18_per_protocol(self):
        rules,initial,doc=make_inputs(54)
        self.assertGreaterEqual(MAX_SERVICES,54)
        view=prepare_dependency_preview(rules,initial,doc)
        self.assertTrue(view.verify(rules,initial))
        self.assertEqual(len(view.units),54)
        self.assertEqual({proto:sum(u.protocol==proto for u in view.units)
                          for proto in ('SSH','FTP','SMB')},
                         {'SSH':18,'FTP':18,'SMB':18})
        self.assertTrue(all(u.topological_order==('C1','C2','C3') for u in view.units))
        self.assertTrue(all(x.phase is ServicePhase.PREPARADO for x in initial.units))
        self.assertTrue(all(x.accumulated_evidence==0 for x in initial.units))
        self.assertEqual(len({u.unit_id for u in view.units}),54)

    def test_order_deterministic(self):
        orig=prepare_dependency_preview(self.rules,self.initial,self.doc)
        other=copy.deepcopy(self.doc)
        other['services'].reverse()
        for unit in other['services']:
            unit['cases'].reverse()
            for case in unit['cases']:
                case['requires'].reverse()
        alt=prepare_dependency_preview(self.rules,self.initial,other)
        self.assertEqual(orig.source,alt.source)
        self.assertEqual(orig.sha256,alt.sha256)

    def test_expected_topological_order(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        self.assertEqual(x.units[0].topological_order,('C1','C2','C3'))
        self.assertEqual(x.units[0].edges,(('C1',()),('C2',('C1',)),('C3',('C1','C2'))))

    def test_no_edges_sorted_order(self):
        for s in self.doc['services']:
            for c in s['cases']:
                c['requires']=[]
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        self.assertEqual(x.units[0].topological_order,('C1','C2','C3'))

    def test_cycle_two_nodes(self):
        self.rejection('dependencias_ciclicas',lambda d:d['services'][0]['cases'][0].update(requires=['C2']))

    def test_self_reference(self):
        self.rejection('autodependencia',lambda d:d['services'][0]['cases'][0].update(requires=['C1']))

    def test_unknown_reference(self):
        self.rejection('dependencia_no_declarada',lambda d:d['services'][0]['cases'][0].update(requires=['X']))

    def test_cross_service_reference_denied(self):
        self.rejection('dependencia_no_declarada',lambda d:d['services'][0]['cases'][1].update(requires=['FOREIGN']))

    def test_duplicate_reference(self):
        self.rejection('dependencia_duplicada',lambda d:d['services'][0]['cases'][2].update(requires=['C1','C1']))

    def test_bad_reference_type(self):
        self.rejection('identidad_dependencia_invalida',lambda d:d['services'][0]['cases'][1].update(requires=[False]))

    def test_bad_reference_path(self):
        self.rejection('identidad_dependencia_invalida',lambda d:d['services'][0]['cases'][1].update(requires=['../C1']))

    def test_non_list_deps(self):
        self.rejection('dependencias_invalidas',lambda d:d['services'][0]['cases'][1].update(requires={'C1':1}))

    def test_excess_reference_items(self):
        self.rejection('dependencias_invalidas',lambda d:d['services'][0]['cases'][1].update(requires=['C1']*4))

    def test_duplicate_case(self):
        self.rejection('caso_desconocido_o_duplicado',lambda d:d['services'][0]['cases'][1].update(id='C1'))

    def test_unknown_case(self):
        self.rejection('caso_desconocido_o_duplicado',lambda d:d['services'][0]['cases'][1].update(id='C9'))

    def test_missing_case(self):
        self.rejection('cantidad_casos_invalida',lambda d:d['services'][0]['cases'].pop())

    def test_extra_case(self):
        self.rejection('cantidad_casos_invalida',lambda d:d['services'][0]['cases'].append({'id':'C4','requires':[]}))

    def test_case_extra_field_denied(self):
        self.rejection('caso_invalido',lambda d:d['services'][0]['cases'][0].update(argv=['ssh']))

    def test_non_dict_case(self):
        self.rejection('caso_invalido',lambda d:d['services'][0]['cases'].__setitem__(0,'bad'))

    def test_wrong_service_id(self):
        self.rejection('servicio_desconocido_o_duplicado',lambda d:d['services'][0].update(id='UNKNOWN'))

    def test_duplicate_service(self):
        self.rejection('servicio_desconocido_o_duplicado',lambda d:d['services'][1].update(id=d['services'][0]['id']))

    def test_wrong_service_count(self):
        self.rejection('cantidad_servicios_invalida',lambda d:d['services'].pop())

    def test_extra_service(self):
        self.rejection('cantidad_servicios_invalida',lambda d:d['services'].append(copy.deepcopy(d['services'][0])))

    def test_bad_protocol(self):
        self.rejection('protocolo_invalido',lambda d:d['services'][0].update(protocol='TELNET'))

    def test_non_str_protocol(self):
        self.rejection('protocolo_invalido',lambda d:d['services'][0].update(protocol=True))

    def test_service_extra_field(self):
        self.rejection('servicio_invalido',lambda d:d['services'][0].update(authorization=True))

    def test_service_not_dict(self):
        self.rejection('servicio_invalido',lambda d:d['services'].__setitem__(0,True))

    def test_missing_required_root_field(self):
        self.rejection('grafo_invalido',lambda d:d.pop('services'))

    def test_unexpected_root_key(self):
        self.rejection('grafo_invalido',lambda d:d.update(command='ssh'))

    def test_wrong_format(self):
        self.rejection('version_incompatible',lambda d:d.update(format='wrong'))

    def test_wrong_rule_hash(self):
        self.rejection('origen_no_coincide',lambda d:d.update(rule_source_sha256='0'*64))

    def test_wrong_initial_hash(self):
        self.rejection('origen_no_coincide',lambda d:d.update(initial_snapshot_sha256='0'*64))

    def test_no_mutation_after_freeze(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        self.doc['services'][0]['cases'][1]['requires'].append('C3')
        self.assertTrue(x.verify(self.rules,self.initial))

    def test_hash_is_exact(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        self.assertEqual(x.sha256,hashlib.sha256(x.source).hexdigest())

    def test_tampered_raw(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        with self.assertRaisesRegex(DependencyPreviewError,'grafo_alterado'):
            replace(x,source=x.source+b' ').verify(self.rules,self.initial)

    def test_tampered_hash(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        with self.assertRaisesRegex(DependencyPreviewError,'grafo_alterado'):
            replace(x,sha256='0'*64).verify(self.rules,self.initial)

    def test_tampered_memory(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        with self.assertRaisesRegex(DependencyPreviewError,'grafo_en_memoria_alterado'):
            replace(x,units=tuple(reversed(x.units))).verify(self.rules,self.initial)

    def test_wrong_snapshot_from_other_config(self):
        other=copy.deepcopy(self.doc)
        other['services'][0]['cases'][1]['requires']=[]
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        y=prepare_dependency_preview(self.rules,self.initial,other)
        self.assertNotEqual(x.sha256,y.sha256)

    def test_rejects_bad_json_duplicate_keys_when_raw_forged(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        extra=x.source[:-1]+b',"services":[]}'
        with self.assertRaisesRegex(DependencyPreviewError,'clave_duplicada'):
            replace(x,source=extra,sha256=hashlib.sha256(extra).hexdigest()).verify(self.rules,self.initial)

    def test_no_execution_or_publication(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        self.assertFalse(x.operational_dispatch_allowed)
        self.assertIsNone(x.published_generation)
        self.assertFalse(self.initial.operational_dispatch_allowed)
        self.assertIsNone(self.initial.published_generation)

    def test_frozen_dataclasses(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        with self.assertRaises(AttributeError):
            x.sha256='not allowed'
        with self.assertRaises(AttributeError):
            x.units[0].protocol='FTP'

    def test_rejects_other_source_type(self):
        with self.assertRaisesRegex(DependencyPreviewError,'fuente_invalida'):
            prepare_dependency_preview({},self.initial,self.doc)

    def test_empty_units_not_allowed(self):
        with self.assertRaises(RulePreflightError):
            preflight_rule_configuration({'format':RULE_FORMAT,'fields':{},'services':[]})

    def test_more_than_64_services_denied(self):
        with self.assertRaises(RulePreflightError):
            make_inputs(65)

    def test_synthetic_counts_stay_zero(self):
        x=prepare_dependency_preview(self.rules,self.initial,self.doc)
        self.assertTrue(x.verify(self.rules,self.initial))
        self.assertTrue(all(c.starts_confirmed==0 and c.permitted_attempts_ceiling in (1,2)
                            for u in self.initial.units for c in u.cases))


if __name__=='__main__':
    unittest.main()
