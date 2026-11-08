"""A1-R9: exact, adversarial, side-effect-free rule semantics from thesis figures."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from ardrec.rules import RuleError, decide, evaluate_expression
from ardrec.state import Truth

FIXTURES = json.loads((Path(__file__).resolve().parents[1] / 'fixtures/a1-rules-v1.json').read_text())


def C(kind, value):
    return {'op': 'CONST', 'type': kind, 'value': value}


def F(path):
    return {'op': 'FIELD', 'path': path}


def B(op, left, right):
    return {'op': op, 'left': left, 'right': right}


class A1RulesCoreTests(unittest.TestCase):
    def setUp(self):
        self.fx = deepcopy(FIXTURES['base'])
        self.schema = self.fx['schema']
        self.env = self.fx['env']
        self.ctx = self.fx['context']
        self.rows = self.fx['table']

    def deny(self, code, f):
        with self.assertRaises(RuleError) as cm:
            f()
        self.assertEqual(cm.exception.code, code)

    def evaluate(self, expr):
        return evaluate_expression(expr, self.env, self.schema)

    def test_boolean_constants_exact_and_truth_enum(self):
        self.assertIs(self.evaluate(C('boolean', True)), Truth.VERDADERO)
        self.assertIs(self.evaluate(C('boolean', False)), Truth.FALSO)
        for x in (0, 1, 'true', None, 1.0):
            self.deny('VALUE_TYPE_INVALID', lambda: self.evaluate(C('boolean', x)))

    def test_field_allowlist_no_object_traversal(self):
        self.assertIs(self.evaluate(F('allowed')), Truth.VERDADERO)
        self.deny('FIELD_NOT_ALLOWED', lambda: self.evaluate(F('os.system')))
        self.deny('FIELD_INVALID', lambda: self.evaluate(F('__class__')))

    def test_optional_missing_is_nd_not_false(self):
        self.assertIs(self.evaluate(F('optional')), Truth.ND)
        self.assertIs(self.evaluate({'op':'NO', 'arg':F('optional')}), Truth.ND)

    def test_mandatory_missing_fails(self):
        del self.env['allowed']
        self.deny('FIELD_REQUIRED_ABSENT', lambda: self.evaluate(F('score')))

    def test_no_truthiness_or_implicit_int_bool(self):
        self.env['score'] = True
        self.deny('VALUE_TYPE_INVALID', lambda: self.evaluate(F('allowed')))
        self.deny('VALUE_TYPE_INVALID', lambda: self.evaluate(C('integer', False)))

    def test_kleene_and_full_truth_table(self):
        self.env.pop('optional', None)
        for a in (True, False, None):
            for b in (True, False, None):
                args=[F('optional') if x is None else C('boolean',x) for x in (a,b)]
                expected=Truth.FALSO if False in (a,b) else Truth.ND if None in (a,b) else Truth.VERDADERO
                self.assertIs(self.evaluate({'op':'Y','args':args}),expected)

    def test_kleene_or_full_truth_table(self):
        for a in (True, False, None):
            for b in (True, False, None):
                # A missing optional field expresses ND; present booleans via constants.
                self.env.pop('optional', None)
                args=[F('optional') if x is None else C('boolean',x) for x in (a,b)]
                expected=Truth.VERDADERO if True in (a,b) else Truth.ND if None in (a,b) else Truth.FALSO
                self.assertIs(self.evaluate({'op':'O','args':args}),expected)

    def test_not_complete_truth_table(self):
        for value, target in [(True, Truth.FALSO),(False, Truth.VERDADERO)]:
            self.assertIs(self.evaluate({'op':'NO','arg':C('boolean',value)}),target)
        self.assertIs(self.evaluate({'op':'NO','arg':F('optional')}),Truth.ND)

    def test_integer_comparisons_exact(self):
        for op, expected in [('IGUAL',False),('MENOR',False),('MENOR_IGUAL',False),
                             ('MAYOR',True),('MAYOR_IGUAL',True)]:
            got=self.evaluate(B(op,F('score'),C('integer',4)))
            self.assertIs(got,Truth.VERDADERO if expected else Truth.FALSO)

    def test_membership_and_subset(self):
        self.assertIs(self.evaluate(B('PERTENECE',C('string','SSH'),F('tags'))), Truth.VERDADERO)
        self.assertIs(self.evaluate(B('PERTENECE',C('string','HTTP'),F('tags'))), Truth.FALSO)
        self.assertIs(self.evaluate(B('SUBCONJUNTO',C('string_set',['SSH']),F('tags'))),Truth.VERDADERO)
        self.assertIs(self.evaluate(B('SUBCONJUNTO',F('tags'),C('string_set',['SSH']))),Truth.FALSO)

    def test_comparison_nd_propagation(self):
        expr=B('IGUAL',F('optional'),C('boolean',False))
        self.assertIs(self.evaluate(expr),Truth.ND)

    def test_comparison_type_mismatch_rejected(self):
        self.deny('TYPE_INCOMPATIBLE',lambda: self.evaluate(B('IGUAL',F('score'),F('service'))))
        self.deny('TYPE_INCOMPATIBLE',lambda: self.evaluate(B('MENOR',F('service'),C('string','z'))))
        self.deny('TYPE_INCOMPATIBLE',lambda: self.evaluate({'op':'NO','arg':F('score')}))

    def test_unknown_operator_and_extra_key_rejected(self):
        self.deny('OPERATOR_NOT_ALLOWED',lambda: self.evaluate({'op':'EVAL','arg':F('allowed')}))
        self.deny('EXPRESSION_INVALID',lambda: self.evaluate({'op':'FIELD','path':'allowed','extra':1}))

    def test_expression_cycle_rejected(self):
        a={'op':'NO'}
        a['arg']=a
        self.deny('EXPRESSION_CYCLE',lambda: self.evaluate(a))

    def test_expression_depth_and_size_bounded(self):
        a=C('boolean',True)
        for _ in range(25):a={'op':'NO','arg':a}
        self.deny('EXPRESSION_DEPTH_EXCEEDED',lambda: self.evaluate(a))
        node=C('boolean',True)
        giant={'op':'Y','args':[node for _ in range(64)]}
        giant={'op':'Y','args':[giant for _ in range(5)]}
        self.deny('EXPRESSION_NODES_EXCEEDED',lambda: self.evaluate(giant))

    def test_schema_strict_optional_list(self):
        self.schema['optional_fields']=['optional','optional']
        self.deny('SCHEMA_INVALID',lambda: self.evaluate(F('allowed')))

    def test_schema_unexpected_and_bad_fields(self):
        self.schema['field_types']['__private']='string'
        self.deny('FIELD_INVALID',lambda: self.evaluate(F('allowed')))

    def test_environment_unknown_field_rejected(self):
        self.env['inject']='x'
        self.deny('ENVIRONMENT_INVALID',lambda: self.evaluate(F('allowed')))

    def test_set_duplicate_and_wrong_type(self):
        self.env['tags']=['SSH','SSH']
        self.deny('VALUE_DUPLICATE',lambda: self.evaluate(F('allowed')))
        self.env['tags']=['SSH',True]
        self.deny('VALUE_TYPE_INVALID',lambda: self.evaluate(F('allowed')))

    def test_integer_and_string_boundaries(self):
        self.env['score']=2**63
        self.deny('VALUE_TYPE_INVALID',lambda: self.evaluate(F('allowed')))
        self.env['score']=5
        self.env['service']='x'*129
        self.deny('VALUE_TYPE_INVALID',lambda: self.evaluate(F('allowed')))

    def test_decide_unique_row_and_provenance(self):
        res=decide(self.rows,self.env,self.schema,self.ctx)
        self.assertEqual((res.status,res.rule_id,res.outcome,res.provenance),
                         ('DETERMINADO','R-ALLOW','ELEGIBLE_SINTETICO','SRC-ALLOW'))
        self.assertEqual(res.matched_rule_ids,('R-ALLOW',))
        self.assertFalse(res.indeterminate)
        self.assertFalse(res.authorized)
        self.assertFalse(res.dispatch_allowed)

    def test_decide_zero_matches_is_nd(self):
        self.env['score']=0
        out=decide(self.rows,self.env,self.schema,self.ctx)
        self.assertEqual(out.status,'ND')
        self.assertIsNone(out.outcome)
        self.assertEqual(out.matched_rule_ids,())

    def test_decide_indeterminate_overrides_one_true(self):
        self.rows.append({'rule_id':'R-OPTIONAL', 'condition':F('optional'),
                          'outcome':'ALTERNATIVE','provenance':'SRC-OPT'})
        out=decide(self.rows,self.env,self.schema,self.ctx)
        self.assertEqual(out.status,'ND')
        self.assertEqual(out.matched_rule_ids,('R-ALLOW',))
        self.assertTrue(out.indeterminate)
        self.assertIsNone(out.rule_id)

    def test_ambiguous_rows_explicit_error(self):
        self.rows.append({'rule_id':'R-ALSO', 'condition':F('allowed'),
                          'outcome':'ALTERNATIVE','provenance':'SRC-ALSO'})
        self.deny('RULES_AMBIGUOUS',lambda: decide(self.rows,self.env,self.schema,self.ctx))

    def test_invalid_row_after_match_is_not_ignored(self):
        self.rows.append({'rule_id':'R-BAD', 'condition':{'op':'EXEC','x':1},
                          'outcome':'BAD','provenance':'SRC-BAD'})
        self.deny('OPERATOR_NOT_ALLOWED',lambda: decide(self.rows,self.env,self.schema,self.ctx))

    def test_duplicate_rule_id_rejected(self):
        self.rows.append(deepcopy(self.rows[0]))
        self.deny('RULE_ID_DUPLICATE',lambda: decide(self.rows,self.env,self.schema,self.ctx))

    def test_context_generation_exact_and_frozen(self):
        self.ctx['generation']=True
        self.deny('CONTEXT_INVALID',lambda: decide(self.rows,self.env,self.schema,self.ctx))
        self.ctx['generation']=1
        self.ctx['configuration_sha256']='wrong'
        self.deny('IDENTITY_INVALID',lambda: decide(self.rows,self.env,self.schema,self.ctx))

    def test_input_unchanged_and_result_immutable(self):
        before=deepcopy((self.rows,self.env,self.schema,self.ctx))
        output=decide(self.rows,self.env,self.schema,self.ctx)
        self.assertEqual(before,(self.rows,self.env,self.schema,self.ctx))
        with self.assertRaises(FrozenInstanceError):
            output.authorized=True
        self.assertFalse(output.dispatch_allowed)

    def test_all_fixture_scenarios_expected(self):
        self.assertGreaterEqual(len(FIXTURES['cases']),10)
        for case in FIXTURES['cases']:
            with self.subTest(case=case['name']):
                fx=deepcopy(self.fx)
                fx['env'].update(case.get('env_overrides',{}))
                for absent in case.get('missing_fields',[]):fx['env'].pop(absent,None)
                if case.get('additional_rule'):
                    fx['table'].append(case['additional_rule'])
                if 'error' in case:
                    self.deny(case['error'],lambda: decide(fx['table'],fx['env'],fx['schema'],fx['context']))
                else:
                    result=decide(fx['table'],fx['env'],fx['schema'],fx['context'])
                    self.assertEqual(result.status,case['status'])
                    self.assertEqual(result.rule_id,case['rule_id'])
                    self.assertFalse(result.authorized or result.dispatch_allowed)

    def test_no_operational_import_or_eval(self):
        source=(Path(__file__).resolve().parents[2]/'src/ardrec/rules/core.py').read_text()
        for forbidden in ('subprocess','socket','os.system','exec(', 'eval(', 'open(', 'transition_service(', 'reserve_attempt('):
            self.assertNotIn(forbidden, source)


if __name__=='__main__':
    unittest.main()
