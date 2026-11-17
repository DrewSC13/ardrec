"""R68 / A1: oráculo de aceptación final de su núcleo, sin atribuir A9/P8."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from fractions import Fraction
from itertools import product
import hashlib
import json
import unittest

from ardrec.initialization.rule_preflight import preflight_rule_configuration
from ardrec.persistence.codec import canonical, pack
from ardrec.rules.complete_a1 import A1ClosureDecision, evaluate_complete_a1
from ardrec.rules.kernel import A1Error, decide, evaluate, guard_allows
from ardrec.state import GlobalState, Truth
from test_p14_r65_a1_confirmed_context import config, confirmed

KW = {'case_id':'CASE_POLICY', 'condition_id':'COND_FACT', 'context_id':'CTX_R68_1'}


def s(raw):
    return hashlib.sha256(raw).hexdigest()


def lit(t):
    return {'op':'CONSTANTE', 'tipo':'LOGICO','valor':t.name}


class A1FinalAcceptanceOracle(unittest.TestCase):
    def setUp(self):
        self.frozen=preflight_rule_configuration(config())
        c=confirmed()
        g=GlobalState(confirmed=c, execution_id='EXEC_R68_1',
                      services=c.services, authority=Truth.ND)
        self.cr=canonical(pack(c)); self.gr=canonical(pack(g))
        self.cp=s(self.cr); self.gp=s(self.gr)
        self.env={'FACT':Truth.VERDADERO}

    def run_a1(self, **overrides):
        args=dict(frozen=self.frozen, global_raw=self.gr, global_pin=self.gp,
                  confirmed_raw=self.cr, confirmed_pin=self.cp,
                  service_id='SSH_DEV',environment=self.env, **KW)
        args.update(overrides)
        return evaluate_complete_a1(**args)

    def test_01_single_entry_point_evaluates_real_R17_R67(self):
        j=json.loads(self.run_a1().source)
        self.assertEqual(j['status'],'VERDADERO')
        self.assertEqual(j['selected_rule'],'ALLOW')
        self.assertEqual(j['declared_output'],'CASE_POLICY')
        self.assertTrue(j['global_confirmed_same_generation'])
        self.assertTrue(j['rule_choice_matches_frozen_R17'])

    def test_02_integrity_of_three_exact_sources(self):
        j=json.loads(self.run_a1().json_bytes())
        self.assertEqual(j['global_storage_sha256'],self.gp)
        self.assertEqual(j['confirmed_storage_sha256'],self.cp)
        self.assertEqual(j['rules_source_sha256'],self.frozen.sha256)
        self.assertEqual(j['generation_reference'],'GENERATION_0')
        self.assertEqual(j['state'],'PREPARADO')

    def test_03_context_seven_fields_bound(self):
        j=json.loads(self.run_a1().source)
        self.assertEqual((j['state'],j['origin'],j['rules_source_sha256'],
                          j['service_id'],j['case_id'],j['condition_id'],j['context_id']),
                         ('PREPARADO','CONFIRMED_STATE_MODEL',self.frozen.sha256,
                          'SSH_DEV','CASE_POLICY','COND_FACT','CTX_R68_1'))

    def test_04_false_rows_keep_false_but_table_nd(self):
        j=json.loads(self.run_a1(environment={'FACT':Truth.FALSO}).source)
        self.assertEqual(j['status'],'ND')
        self.assertEqual(j['evaluations'],[{'id':'ALLOW','valor':'FALSO'},
                                           {'id':'NEVER','valor':'FALSO'}])
        self.assertIsNone(j['selected_rule'])
        self.assertIsNone(j['declared_output'])

    def test_05_optional_missing_remains_nd(self):
        j=json.loads(self.run_a1(environment={}).source)
        self.assertEqual(j['status'],'ND')
        self.assertEqual(j['evaluations'][0]['valor'],'ND')

    def test_06_3_to_power_3_table_exhaustive(self):
        values=(Truth.VERDADERO,Truth.FALSO,Truth.ND)
        for seq in product(values, repeat=3):
            rows=[{'id':'R'+str(i),'condicion':lit(x),'salida':'OUT'+str(i)}
                  for i,x in enumerate(seq)]
            winners=[i for i,x in enumerate(seq) if x is Truth.VERDADERO]
            if len(winners)>1:
                with self.assertRaisesRegex(A1Error,'reglas_ambiguas'):
                    decide(rows, {}, {})
            else:
                d=decide(rows,{}, {})
                expected='VERDADERO' if len(winners)==1 and Truth.ND not in seq else 'ND'
                self.assertEqual(d.status.value, expected)
                self.assertEqual(d.evaluations,tuple(('R'+str(i),x) for i,x in enumerate(seq)))
                if expected=='VERDADERO':
                    self.assertEqual(d.output,'OUT'+str(winners[0]))
                else:
                    self.assertIsNone(d.output)

    def test_07_boolean_operators_strong_kleene(self):
        V,F,N=Truth.VERDADERO,Truth.FALSO,Truth.ND
        for op, truth in [('Y',{(V,V):V,(V,F):F,(V,N):N,(F,V):F,(F,F):F,(F,N):F,(N,V):N,(N,F):F,(N,N):N}),
                          ('O',{(V,V):V,(V,F):V,(V,N):V,(F,V):V,(F,F):F,(F,N):N,(N,V):V,(N,F):N,(N,N):N})]:
            for pair,expected in truth.items():
                self.assertIs(evaluate({'op':op,'args':[lit(pair[0]),lit(pair[1])]}, {},{}),expected)
        for value,expected in ((V,F),(F,V),(N,N)):
            self.assertIs(evaluate({'op':'NO','arg':lit(value)}, {},{}),expected)

    def test_08_typed_rational_comparisons(self):
        for rel,a,b,exp in [('IGUAL','1/2','1/2',True),('DISTINTO','1/2','2/3',True),
                            ('MENOR','1/2','2/3',True),('MENOR_IGUAL','1/2','1/2',True),
                            ('MAYOR','2/3','1/2',True),('MAYOR_IGUAL','2/3','2/3',True)]:
            expr={'op':'COMPARAR','relacion':rel,
                  'izq':{'op':'CONSTANTE','tipo':'RACIONAL','valor':a},
                  'der':{'op':'CONSTANTE','tipo':'RACIONAL','valor':b}}
            self.assertIs(evaluate(expr,{},{}),Truth.VERDADERO if exp else Truth.FALSO)

    def test_09_membership_subset_and_empty_set(self):
        def val(kind,value): return {'op':'CONSTANTE','tipo':kind,'valor':value}
        for relation,left,right,expected in [
            ('PERTENECE',val('TEXTO','SSH'),val('CONJUNTO_TEXTO',['FTP','SSH']),Truth.VERDADERO),
            ('PERTENECE',val('TEXTO','SMB'),val('CONJUNTO_TEXTO',['FTP','SSH']),Truth.FALSO),
            ('SUBCONJUNTO',val('CONJUNTO_TEXTO',[]),val('CONJUNTO_TEXTO',[]),Truth.VERDADERO),
            ('SUBCONJUNTO',val('CONJUNTO_TEXTO',['FTP']),val('CONJUNTO_TEXTO',[]),Truth.FALSO),
        ]:
            e={'op':'COMPARAR','relacion':relation,'izq':left,'der':right}
            self.assertIs(evaluate(e,{},{}),expected)

    def test_10_required_missing_refused_even_in_discarded_row(self):
        expr={'op':'CAMPO','nombre':'FACT','opcional':False}
        with self.assertRaisesRegex(A1Error,'campo_obligatorio_ausente'):
            decide([{'id':'WIN','condicion':lit(Truth.VERDADERO)},
                    {'id':'REQ','condicion':expr}],{'FACT':'LOGICO'}, {})

    def test_11_guard_only_allows_true(self):
        for truth,expected in ((Truth.VERDADERO,True),(Truth.FALSO,False),(Truth.ND,False)):
            self.assertIs(guard_allows(truth),expected)
        with self.assertRaises(A1Error): guard_allows(True)

    def test_12_replay_identity_and_immutability(self):
        a=self.run_a1();b=self.run_a1()
        self.assertEqual(a,b)
        self.assertEqual(s(a.source),a.sha256)
        self.assertTrue(a.verify(self.frozen,self.gr,self.gp,self.cr,self.cp,'SSH_DEV',self.env,**KW))
        with self.assertRaises(FrozenInstanceError): a.sha256='0'*64

    def test_13_tamper_rehash_refused_recompute(self):
        a=self.run_a1();j=json.loads(a.source)
        j['declared_output']='FORGED_OUTPUT'
        raw=json.dumps(j,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        forged=A1ClosureDecision(raw,s(raw),a.global_sha256,a.confirmed_sha256,a.rules_sha256)
        with self.assertRaisesRegex(A1Error,'a1_recibo_no_reproducible'):
            forged.verify(self.frozen,self.gr,self.gp,self.cr,self.cp,'SSH_DEV',self.env,**KW)

    def test_14_modified_environment_invalidates_replay(self):
        a=self.run_a1()
        with self.assertRaisesRegex(A1Error,'a1_recibo_no_reproducible'):
            a.verify(self.frozen,self.gr,self.gp,self.cr,self.cp,'SSH_DEV',
                     {'FACT':Truth.FALSO},**KW)

    def test_15_modified_identity_invalidates_replay(self):
        a=self.run_a1()
        with self.assertRaisesRegex(A1Error,'a1_recibo_no_reproducible'):
            a.verify(self.frozen,self.gr,self.gp,self.cr,self.cp,'SSH_DEV',
                     self.env,**(KW|{'context_id':'CTX_DIFFERENT'}))

    def test_16_invalid_global_pin_rejected(self):
        with self.assertRaisesRegex(A1Error,'estado_global_hash_invalido'):
            self.run_a1(global_pin='0'*64)

    def test_17_invalid_confirmed_pin_rejected(self):
        with self.assertRaisesRegex(A1Error,'estado_serializado_hash_invalido'):
            self.run_a1(confirmed_pin='0'*64)

    def test_18_nonexistent_service_rejected(self):
        with self.assertRaisesRegex(A1Error,'servicio_no_confirmado'):
            self.run_a1(service_id='UNREGISTERED')

    def test_19_changed_frozen_configuration_invalidates_replay(self):
        original=self.run_a1()
        changed=config()
        changed['services'][0]['rules'][0]['salida']='CHANGED_RULE_OUTPUT'
        different=preflight_rule_configuration(changed)
        with self.assertRaisesRegex(A1Error,'a1_recibo_no_reproducible'):
            original.verify(different,self.gr,self.gp,self.cr,self.cp,
                            'SSH_DEV',self.env,**KW)

    def test_20_p8_and_external_trust_never_inferred(self):
        obj=self.run_a1()
        self.assertFalse(obj.operationally_authorized)
        self.assertIsNone(obj.published_generation)
        j=json.loads(obj.source)
        for field in ('global_configuration_r17_membership_attested',
                      'external_pin_authority_attested','a9_publication_attested',
                      'physical_observation_attested','operational_dispatch'):
            self.assertIs(j[field], False)
        self.assertIsNone(j['published_generation'])
        self.assertEqual(j['p8_operational'],'NO-GO')

    def test_21_r17_snapshot_is_frozen(self):
        src=config()
        frozen=preflight_rule_configuration(src)
        first=frozen.evaluate_service('SSH_DEV',self.env)
        src['services'][0]['rules'][0]['salida']='ALTERED'
        self.assertEqual(first.selected_output, frozen.evaluate_service('SSH_DEV',self.env).selected_output)
        self.assertEqual(first.selected_output,'CASE_POLICY')

    def test_22_set_noncanonical_rejected(self):
        expr={'op':'COMPARAR','relacion':'PERTENECE',
              'izq':{'op':'CONSTANTE','tipo':'TEXTO','valor':'SSH'},
              'der':{'op':'CONSTANTE','tipo':'CONJUNTO_TEXTO','valor':['SSH','FTP']}}
        with self.assertRaisesRegex(A1Error,'conjunto_no_canonico'):
            evaluate(expr,{}, {})

    def test_23_no_implicit_numeric_coercion(self):
        e={'op':'COMPARAR','relacion':'IGUAL',
           'izq':{'op':'CONSTANTE','tipo':'RACIONAL','valor':'1/2'},
           'der':{'op':'CAMPO','nombre':'R'}}
        with self.assertRaisesRegex(A1Error,'ambiente_tipo_invalido'):
            evaluate(e,{'R':'RACIONAL'},{'R':0.5})

    def test_24_protected_errors_ambiguous_table(self):
        with self.assertRaisesRegex(A1Error,'reglas_ambiguas'):
            decide([{'id':'A','condicion':lit(Truth.VERDADERO)},
                    {'id':'B','condicion':lit(Truth.VERDADERO)}],{}, {})

    def test_25_context_status_is_from_confirmed_not_caller(self):
        j=json.loads(self.run_a1().source)
        self.assertEqual(j['state'],'PREPARADO')
        self.assertEqual(j['origin'],'CONFIRMED_STATE_MODEL')


if __name__=='__main__': unittest.main()
