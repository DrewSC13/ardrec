"""R22: diagnóstico trivalente A3 sin licencia para ejecutar ni mutar."""
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
sys.path.insert(0, str(ROOT/'src'))
from test_p14_r21_a2_integrated_preview import make
from ardrec.state import Truth
from ardrec.initialization.rule_preflight import FORMAT as RF, preflight_rule_configuration
from ardrec.initialization.initial_preview import FORMAT as IF, prepare_initial_preview
from ardrec.initialization.dependency_preview import FORMAT as DF, prepare_dependency_preview
from ardrec.initialization.control_preview import FORMAT as CF, prepare_control_preview
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import (
    FORMAT, GuardDiagnosticPreview, GuardPreviewError, diagnose_guards)


def custom(*, conditions=None, fields=None):
    if conditions is None:
        conditions=[{'id':'G1','condicion':{'op':'CAMPO','nombre':'FACT'}},
                    {'id':'G2','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'FALSO'}}]
    if fields is None:
        fields={'FACT':'LOGICO'}
    sid='SSH_01'
    rules=preflight_rule_configuration({'format':RF,'fields':fields,'services':[
        {'id':sid,'initial_state':'PREPARADO','rules':conditions}]})
    initial=prepare_initial_preview(rules,{'format':IF,'rule_source_sha256':rules.sha256,
        'services':[{'id':sid,'initial_risk':'1/4','normalized_criticality':'1/2',
                     'cases':[{'id':'CHECK','max_repetitions':0}]}]})
    deps=prepare_dependency_preview(rules,initial,{'format':DF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'services':[{'id':sid,'protocol':'SSH','cases':[{'id':'CHECK','requires':[]}]}]})
    controls=prepare_control_preview(rules,initial,deps,{'format':CF,
        'rule_source_sha256':rules.sha256,'initial_snapshot_sha256':initial.sha256,
        'dependency_snapshot_sha256':deps.sha256,
        'services':[{'id':sid,'controls':[
            {'id':'CONTROL','guard_rule_id':'G1','target_case_id':'CHECK',
             'precedence':0,'requires':[]}]}]})
    integrated=assemble_integrated_preview(rules,initial,deps,controls)
    return rules,initial,deps,controls,integrated


class GuardR22Tests(unittest.TestCase):
    def setUp(self):
        self.sources=(*make(),)
        self.sources=(*self.sources,assemble_integrated_preview(*self.sources))
        self.environments={u.service_id:{} for u in self.sources[4].units}
        self.view=diagnose_guards(*self.sources,self.environments)

    def result(self, env=None, source=None):
        return diagnose_guards(*(self.sources if source is None else source),
                               self.environments if env is None else env)

    def reject(self,code, env):
        with self.assertRaises(GuardPreviewError) as cm:
            self.result(env)
        self.assertEqual(cm.exception.code,code)

    def test_verified_source(self):
        self.assertTrue(self.view.verify(*self.sources,self.environments))
        self.assertEqual(hashlib.sha256(self.view.source).hexdigest(),self.view.sha256)

    def test_synthetic_54_services(self):
        four=make(54)
        integrated=assemble_integrated_preview(*four)
        env={u.service_id:{} for u in integrated.units}
        result=diagnose_guards(*four,integrated,env)
        self.assertTrue(result.verify(*four,integrated,env))
        self.assertEqual(len(result.units),54)
        self.assertEqual({p:sum(u.protocol==p for u in result.units)
                          for p in ('SSH','FTP','SMB')},{'SSH':18,'FTP':18,'SMB':18})
        self.assertEqual(sum(len(u.cases) for u in result.units),108)
        self.assertEqual(sum(len(u.controls) for u in result.units),108)

    def test_false_control_keeps_false(self):
        self.assertTrue(all(u.controls[1].truth is Truth.FALSO for u in self.view.units))
        self.assertTrue(all('GUARDA_FALSA' in u.controls[1].blockers for u in self.view.units))

    def test_true_control_never_authorized(self):
        for unit in self.view.units:
            self.assertIs(unit.controls[0].truth,Truth.VERDADERO)
            self.assertEqual(unit.table_selected,'ALLOW')
            self.assertIn('AUTORIDAD_OPERACIONAL_NO_ACREDITADA',unit.controls[0].blockers)
            self.assertFalse(self.view.operational_dispatch_allowed)
            self.assertIsNone(self.view.executable_agenda)
            self.assertIsNone(self.view.published_generation)

    def test_structural_dependencies_not_progress(self):
        for unit in self.view.units:
            self.assertEqual(unit.cases[0].reason,'SIN_DEPENDENCIAS_DECLARADAS')
            self.assertEqual(unit.cases[1].reason,'DEPENDENCIAS_NO_CONFIRMADAS')
            self.assertIn('CASOS_NO_CONFIRMADOS',unit.controls[1].blockers)
            self.assertIn('CONTROLES_NO_APLICADOS',unit.controls[1].blockers)

    def test_nd_guard_missing_field(self):
        sources=custom()
        p=diagnose_guards(*sources,{'SSH_01':{}})
        self.assertIs(p.units[0].table_status,Truth.ND)
        self.assertIs(p.units[0].controls[0].truth,Truth.ND)
        self.assertIn('GUARDA_ND',p.units[0].controls[0].blockers)
        self.assertIn('TABLA_NO_ACREDITADA',p.units[0].controls[0].blockers)

    def test_nd_guard_explicit(self):
        p=diagnose_guards(*custom(),{'SSH_01':{'FACT':Truth.ND}})
        self.assertEqual(p.units[0].table_status,Truth.ND)

    def test_true_guard_from_explicit_fact(self):
        p=diagnose_guards(*custom(),{'SSH_01':{'FACT':Truth.VERDADERO}})
        self.assertIs(p.units[0].controls[0].truth,Truth.VERDADERO)
        self.assertEqual(p.units[0].table_selected,'G1')
        self.assertEqual(p.units[0].controls[0].blockers,('AUTORIDAD_OPERACIONAL_NO_ACREDITADA',))

    def test_false_guard_from_explicit_fact(self):
        p=diagnose_guards(*custom(),{'SSH_01':{'FACT':Truth.FALSO}})
        self.assertIs(p.units[0].controls[0].truth,Truth.FALSO)
        self.assertIs(p.units[0].table_status,Truth.FALSO)

    def test_ambiguity_denied(self):
        true={'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}
        src=custom(conditions=[{'id':'G1','condicion':true},
                               {'id':'G2','condicion':true}],fields={})
        with self.assertRaises(GuardPreviewError) as cm:
            diagnose_guards(*src,{'SSH_01':{}})
        self.assertEqual(cm.exception.code,'a1_reglas_ambiguas')

    def test_multiple_true_with_nd_denied(self):
        true={'op':'CONSTANTE','tipo':'LOGICO','valor':'VERDADERO'}
        src=custom(conditions=[{'id':'G1','condicion':true},
                               {'id':'G2','condicion':{'op':'CAMPO','nombre':'FACT'}}])
        p=diagnose_guards(*src,{'SSH_01':{}})
        self.assertEqual(p.units[0].table_status,Truth.ND)
        self.assertIn('TABLA_NO_ACREDITADA',p.units[0].controls[0].blockers)

    def test_unknown_environment_field(self):
        env=copy.deepcopy(self.environments)
        env[next(iter(env))]['OUTSIDE']='X'
        self.reject('ambiente_no_autorizado',env)

    def test_environment_wrong_boolean_type(self):
        with self.assertRaises(GuardPreviewError) as cm:
            diagnose_guards(*custom(),{'SSH_01':{'FACT':True}})
        self.assertEqual(cm.exception.code,'a1_ambiente_tipo_invalido')

    def test_environment_missing_unit(self):
        e=copy.deepcopy(self.environments)
        e.pop(next(iter(e)))
        self.reject('ambientes_no_coinciden',e)

    def test_environment_extra_unit(self):
        e=copy.deepcopy(self.environments)
        e['OUTSIDE']={}
        self.reject('ambientes_no_coinciden',e)

    def test_environment_not_mapping(self):
        with self.assertRaises(GuardPreviewError) as cm:
            diagnose_guards(*self.sources,[])
        self.assertEqual(cm.exception.code,'ambientes_no_coinciden')

    def test_environment_nested_list_denied(self):
        e=copy.deepcopy(self.environments)
        e[next(iter(e))]=[]
        self.reject('ambiente_invalido',e)

    def test_environment_mapping_keys_bool(self):
        e=copy.deepcopy(self.environments)
        e[next(iter(e))]={True:Truth.VERDADERO}
        self.reject('ambiente_invalido',e)

    def test_source_alteration_denied(self):
        p=replace(self.view,source=self.view.source+b' ')
        with self.assertRaises(GuardPreviewError) as cm:
            p.verify(*self.sources,self.environments)
        self.assertEqual(cm.exception.code,'diagnostico_alterado')

    def test_hash_alteration_denied(self):
        p=replace(self.view,sha256='0'*64)
        with self.assertRaises(GuardPreviewError) as cm:
            p.verify(*self.sources,self.environments)
        self.assertEqual(cm.exception.code,'diagnostico_alterado')

    def test_source_canonical(self):
        record=json.loads(self.view.source)
        self.assertEqual(record['format'],FORMAT)
        self.assertEqual(record['scope'],'SYNTHETIC_DIAGNOSTIC_ONLY')
        self.assertIsNone(record['executable_agenda'])
        self.assertIsNone(record['published_generation'])
        self.assertFalse(record['operational_dispatch'])

    def test_altered_provenance_denied(self):
        p=replace(self.view,integrated_snapshot_sha256='0'*64)
        with self.assertRaises(GuardPreviewError) as cm:
            p.verify(*self.sources,self.environments)
        self.assertEqual(cm.exception.code,'origen_no_coincide')

    def test_fabricated_document_denied_even_with_matching_hash(self):
        d=json.loads(self.view.source)
        d['operational_dispatch']=True
        raw=json.dumps(d,sort_keys=True,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('ascii')
        p=replace(self.view,source=raw,sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(GuardPreviewError) as cm:
            p.verify(*self.sources,self.environments)
        self.assertEqual(cm.exception.code,'diagnostico_no_coincide')

    def test_permutations_stable(self):
        backwards=dict(reversed(list(self.environments.items())))
        other=self.result(backwards)
        self.assertEqual(other.source,self.view.source)
        self.assertEqual(other.sha256,self.view.sha256)

    def test_source_unchanged_after_diagnosis(self):
        before=tuple(x.source for x in self.sources)
        self.result()
        self.assertEqual(before,tuple(x.source for x in self.sources))

    def test_distinct_source_chain_denied(self):
        different=make(4)
        different=(*different,assemble_integrated_preview(*different))
        with self.assertRaises(GuardPreviewError):
            self.view.verify(*different,{u.service_id:{} for u in different[4].units})

    def test_diagnostic_immutable(self):
        with self.assertRaises((AttributeError,TypeError)):
            self.view.units[0].service_id='ALTERADO'

    def test_fields_dont_carry_operational_commands(self):
        d=json.loads(self.view.source)
        self.assertNotIn('argv',d)
        self.assertNotIn('authorized',d)
        self.assertTrue(all('AUTORIDAD_OPERACIONAL_NO_ACREDITADA' in c['blockers']
                            for u in d['services'] for c in u['controls']))

    def test_noncanonical_float_rejected_as_env_type(self):
        fields={'NUMBER':'RACIONAL'}
        src=custom(fields=fields,conditions=[
            {'id':'G1','condicion':{'op':'COMPARAR','relacion':'MAYOR',
                'izq':{'op':'CAMPO','nombre':'NUMBER'},
                'der':{'op':'CONSTANTE','tipo':'RACIONAL','valor':'0'}}},
            {'id':'G2','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'FALSO'}}])
        with self.assertRaises(GuardPreviewError) as cm:
            diagnose_guards(*src,{'SSH_01':{'NUMBER':0.5}})
        self.assertEqual(cm.exception.code,'a1_ambiente_tipo_invalido')

    def test_exact_fraction_environment(self):
        fields={'NUMBER':'RACIONAL'}
        src=custom(fields=fields,conditions=[
            {'id':'G1','condicion':{'op':'COMPARAR','relacion':'MAYOR',
                'izq':{'op':'CAMPO','nombre':'NUMBER'},
                'der':{'op':'CONSTANTE','tipo':'RACIONAL','valor':'0'}}},
            {'id':'G2','condicion':{'op':'CONSTANTE','tipo':'LOGICO','valor':'FALSO'}}])
        p=diagnose_guards(*src,{'SSH_01':{'NUMBER':Fraction(1,3)}})
        self.assertIs(p.units[0].controls[0].truth,Truth.VERDADERO)
        d=json.loads(p.source)
        self.assertEqual(d['environments'][0]['fields']['NUMBER'],{'type':'RACIONAL','value':'1/3'})

    def test_no_controls_no_dispatch(self):
        src4=make(with_controls=False)
        integrated=assemble_integrated_preview(*src4)
        src=(*src4,integrated)
        env={x.service_id:{} for x in integrated.units}
        p=diagnose_guards(*src,env)
        self.assertTrue(all(not u.controls for u in p.units))
        self.assertIsNone(p.executable_agenda)


if __name__ == '__main__':
    unittest.main()
