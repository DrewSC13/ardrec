"""R24: pruebas de conservación, contradicción y cero autorización operacional."""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'src'))
sys.path.insert(0, str(ROOT/'scripts'))
from ardrec.scheduling.readiness_preview import (
    FORMAT, ReadinessError, preview_hypothetical_readiness)
from ardrec.scheduling.agenda_preview import plan_candidate_order
from demo_p14_r24_a3_readiness_preview import example


class ReadinessR24Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources, cls.plan, cls.scenario = example(6)

    def view(self, scenario=None, plan=None, sources=None):
        return preview_hypothetical_readiness(*(sources or self.sources),
               plan or self.plan, self.scenario if scenario is None else scenario)

    def reject(self, code, mutation):
        scenario = copy.deepcopy(self.scenario)
        mutation(scenario)
        with self.assertRaises(ReadinessError) as cm:
            self.view(scenario)
        self.assertEqual(cm.exception.code, code)

    def test_full_chain_reverified(self):
        v = self.view()
        self.assertTrue(v.verify(*self.sources, self.plan, self.scenario))
        self.assertEqual(v.sha256, hashlib.sha256(v.source).hexdigest())
        self.assertEqual(v.scenario_sha256, hashlib.sha256(v.scenario_source).hexdigest())

    def test_54_synthetic_units(self):
        sources, candidates, scenario = example(54)
        v = self.view(scenario, candidates, sources)
        self.assertEqual(len(v.units), 54)
        self.assertEqual(sum(len(u.inherited_exclusions) for u in v.units), 72)
        states = {name: sum(c.state == name for u in v.units for c in u.controls)
                  for name in ('LISTO_CONDICIONAL','BLOQUEADO','OMITIDO_SUPUESTO')}
        self.assertEqual(states, {'LISTO_CONDICIONAL':18,'BLOQUEADO':9,'OMITIDO_SUPUESTO':9})
        self.assertTrue(v.verify(*sources, candidates, scenario))

    def test_inherited_exclusions_never_added(self):
        v = self.view()
        for u, prior in zip(v.units, self.plan.units):
            self.assertEqual({c.control_id for c in u.controls},
                             {c.control_id for c in prior.candidates})
            self.assertEqual({x[0] for x in u.inherited_exclusions},
                             {x.control_id for x in prior.excluded})

    def test_assumed_complete_does_not_create_executable_permission(self):
        v = self.view()
        self.assertFalse(v.operational_dispatch_allowed)
        self.assertIsNone(v.executable_agenda)
        self.assertIsNone(v.published_generation)
        self.assertTrue(all(not c.executable for u in v.units for c in u.controls))
        self.assertTrue(all('AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in c.reasons
                            for u in v.units for c in u.controls))

    def test_assumed_completed_control_omitted(self):
        v = self.view()
        by = {u.service_id:u for u in v.units}
        self.assertEqual(by['SSH_01'].controls[0].state, 'OMITIDO_SUPUESTO')
        self.assertEqual(by['SSH_01'].controls[0].reasons[0], 'CONTROL_ASUMIDO_SATISFECHO')

    def test_downstream_ready_only_with_both_prerequisites(self):
        v = self.view()
        by = {u.service_id:u for u in v.units}
        self.assertEqual(by['SSH_01'].controls[1].state, 'LISTO_CONDICIONAL')
        self.assertEqual(by['SSH_04'].controls[1].state, 'LISTO_CONDICIONAL')

    def test_all_unknown_downstream_blocked(self):
        v = self.view()
        by = {u.service_id:u for u in v.units}
        self.assertEqual(by['SSH_02'].controls, ())
        self.assertEqual(by['SSH_03'].controls, ())
        # SSH_01 en la muestra tiene la hipótesis TRUE; usar estado ND explícito.
        d=copy.deepcopy(self.scenario)
        for s in d['services']:
            for group in ('cases','controls'):
                for item in s[group]: item['assumed']='ND'
        u={x.service_id:x for x in self.view(d).units}
        a=u['SSH_01'].controls
        self.assertEqual(a[0].state,'LISTO_CONDICIONAL')
        self.assertEqual(a[1].state,'BLOQUEADO')
        self.assertEqual(a[1].reasons[:-1],
            ('CONTROL_REQUERIDO_ND:CONTROL_A','CASO_REQUERIDO_ND:CHECK_A'))

    def test_guard_false_nd_cannot_become_candidate(self):
        v=self.view()
        u={x.service_id:x for x in v.units}
        self.assertFalse(u['SSH_02'].controls)
        self.assertFalse(u['SSH_03'].controls)

    def test_permutations_are_canonical(self):
        data=copy.deepcopy(self.scenario)
        data['services'].reverse()
        for s in data['services']:
            s['controls'].reverse();s['cases'].reverse()
        a=self.view(); b=self.view(data)
        self.assertEqual(a.source,b.source)
        self.assertEqual(a.scenario_source,b.scenario_source)

    def test_input_immutable(self):
        copied=copy.deepcopy(self.scenario)
        before=[x.source for x in self.sources[:6]]
        self.view()
        self.assertEqual(copied,self.scenario)
        self.assertEqual(before,[x.source for x in self.sources[:6]])

    def test_sha_changes_if_assumption_changes(self):
        a=self.view()
        data=copy.deepcopy(self.scenario)
        for s in data['services']:
            for item in s['controls']:
                if item['id']=='CONTROL_B':item['assumed']='FALSO'
        b=self.view(data)
        self.assertNotEqual(a.sha256,b.sha256)
        self.assertNotEqual(a.scenario_sha256,b.scenario_sha256)

    def test_output_source_tamper(self):
        v=self.view()
        with self.assertRaises(ReadinessError) as cm:
            replace(v,source=v.source+b' ').verify(*self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'informe_alterado')

    def test_output_sha_tamper(self):
        v=self.view()
        with self.assertRaises(ReadinessError) as cm:
            replace(v,sha256='a'*64).verify(*self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'informe_alterado')

    def test_scenario_sha_tamper(self):
        v=self.view()
        with self.assertRaises(ReadinessError) as cm:
            replace(v,scenario_sha256='b'*64).verify(*self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'supuestos_alterados')

    def test_scenario_source_tamper(self):
        v=self.view()
        with self.assertRaises(ReadinessError) as cm:
            replace(v,scenario_source=v.scenario_source+b' ').verify(*self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'supuestos_alterados')

    def test_candidate_sha_tamper(self):
        v=self.view()
        with self.assertRaises(ReadinessError) as cm:
            replace(v,candidate_sha256='a'*64).verify(*self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'candidatos_no_coinciden')

    def test_in_memory_units_tamper(self):
        v=self.view()
        with self.assertRaises(ReadinessError) as cm:
            replace(v,units=()).verify(*self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'reconciliacion_inconsistente')

    def test_semantic_forged_dispatch_denied(self):
        v=self.view();bad=json.loads(v.source)
        bad['operational_dispatch']=True
        raw=json.dumps(bad,sort_keys=True,separators=(',', ':'),ensure_ascii=True).encode('ascii')
        with self.assertRaises(ReadinessError) as cm:
            replace(v,source=raw,sha256=hashlib.sha256(raw).hexdigest()).verify(
                *self.sources,self.plan,self.scenario)
        self.assertEqual(cm.exception.code,'reconciliacion_inconsistente')

    def test_wrong_format(self):
        self.reject('version_incompatible',lambda d:d.update(format='R25'))

    def test_wrong_candidate_reference(self):
        self.reject('candidatos_no_coinciden',lambda d:d.update(candidate_sha256='f'*64))

    def test_extra_root_key(self):
        self.reject('escenario_invalido',lambda d:d.update(dispatch=True))

    def test_missing_root_key(self):
        self.reject('escenario_invalido',lambda d:d.pop('services'))

    def test_root_list(self):
        with self.assertRaises(ReadinessError) as cm:self.view([])
        self.assertEqual(cm.exception.code,'escenario_invalido')

    def test_missing_service(self):
        self.reject('cantidad_servicios_invalida',lambda d:d['services'].pop())

    def test_extra_service(self):
        self.reject('cantidad_servicios_invalida',lambda d:d['services'].append(copy.deepcopy(d['services'][0])))

    def test_duplicate_service(self):
        self.reject('servicio_no_declarado_o_duplicado',lambda d:d['services'][1].update(id=d['services'][0]['id']))

    def test_unknown_service(self):
        self.reject('servicio_no_declarado_o_duplicado',lambda d:d['services'][1].update(id='OTHER'))

    def test_service_wrong_type(self):
        self.reject('servicio_invalido',lambda d:d['services'].__setitem__(0,'SSH_01'))

    def test_extra_service_key(self):
        self.reject('servicio_invalido',lambda d:d['services'][0].update(authorize=True))

    def test_missing_service_key(self):
        self.reject('servicio_invalido',lambda d:d['services'][0].pop('cases'))

    def test_missing_case_mark(self):
        self.reject('cantidad_marcas_invalida',lambda d:d['services'][0]['cases'].pop())

    def test_missing_control_mark(self):
        self.reject('cantidad_marcas_invalida',lambda d:d['services'][0]['controls'].pop())

    def test_case_marks_wrong_container(self):
        self.reject('cantidad_marcas_invalida',lambda d:d['services'][0].update(cases={}))

    def test_control_marks_wrong_container(self):
        self.reject('cantidad_marcas_invalida',lambda d:d['services'][0].update(controls={}))

    def test_case_mark_wrong_type(self):
        self.reject('marca_invalida',lambda d:d['services'][0]['cases'].__setitem__(0,1))

    def test_control_mark_extra_key(self):
        self.reject('marca_invalida',lambda d:d['services'][0]['controls'][0].update(command='ssh'))

    def test_control_mark_missing_value(self):
        self.reject('marca_invalida',lambda d:d['services'][0]['controls'][0].pop('assumed'))

    def test_duplicate_case_mark(self):
        self.reject('marca_desconocida_o_duplicada',lambda d:d['services'][0]['cases'][1].update(id='CHECK_A'))

    def test_duplicate_control_mark(self):
        self.reject('marca_desconocida_o_duplicada',lambda d:d['services'][0]['controls'][1].update(id='CONTROL_A'))

    def test_foreign_case_mark(self):
        self.reject('marca_desconocida_o_duplicada',lambda d:d['services'][0]['cases'][1].update(id='FOREIGN'))

    def test_foreign_control_mark(self):
        self.reject('marca_desconocida_o_duplicada',lambda d:d['services'][0]['controls'][1].update(id='FOREIGN'))

    def test_boolean_assumed(self):
        self.reject('valor_hipotetico_invalido',lambda d:d['services'][0]['cases'][0].update(assumed=True))

    def test_fraction_assumed(self):
        self.reject('valor_hipotetico_invalido',lambda d:d['services'][0]['controls'][0].update(assumed=1))

    def test_empty_assumed(self):
        self.reject('valor_hipotetico_invalido',lambda d:d['services'][0]['controls'][0].update(assumed=''))

    def test_other_truth_assumed(self):
        self.reject('valor_hipotetico_invalido',lambda d:d['services'][0]['controls'][0].update(assumed='TRUE'))

    def test_control_dependency_inconsistent(self):
        def mutate(d):
            s=d['services'][0]
            s['controls'][0]['assumed']='ND'
            s['controls'][1]['assumed']='VERDADERO'
        self.reject('hipotesis_control_inconsistente',mutate)

    def test_case_dependency_inconsistent(self):
        def mutate(d):
            s=d['services'][0]
            s['cases'][0]['assumed']='ND'
            s['cases'][1]['assumed']='VERDADERO'
        self.reject('hipotesis_caso_inconsistente',mutate)

    def test_negative_false_dependency(self):
        d=copy.deepcopy(self.scenario)
        for s in d['services']:
            if s['id']=='SSH_01':
                s['cases'][0]['assumed']='FALSO';s['controls'][0]['assumed']='FALSO'
        u={x.service_id:x for x in self.view(d).units}
        self.assertEqual(u['SSH_01'].controls[0].state,'LISTO_CONDICIONAL')
        self.assertEqual(u['SSH_01'].controls[1].state,'BLOQUEADO')
        self.assertEqual(u['SSH_01'].controls[1].reasons[:-1],
            ('CONTROL_REQUERIDO_FALSO:CONTROL_A','CASO_REQUERIDO_FALSO:CHECK_A'))

    def test_scenario_changes_do_not_mutate_plan(self):
        before=self.plan.source
        d=copy.deepcopy(self.scenario)
        for s in d['services']:
            for c in s['controls']:c['assumed']='ND'
            for c in s['cases']:c['assumed']='ND'
        self.view(d)
        self.assertEqual(self.plan.source,before)

    def test_many_input_cross_checks(self):
        src,prior,scenario=example(54)
        v=self.view(scenario,prior,src)
        self.assertEqual(sum(len(x.controls) for x in v.units),
                         sum(len(x.candidates) for x in prior.units))
        self.assertTrue(all(len(u.controls)+len(u.inherited_exclusions)==2 for u in v.units))
        self.assertFalse(v.operational_dispatch_allowed)

if __name__ == '__main__':
    unittest.main()
