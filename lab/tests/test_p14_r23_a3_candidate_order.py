"""R23: oráculos negativos, límites, procedencia y ausencia de autoridad P8."""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))
from ardrec.state import Truth
from ardrec.initialization.control_preview import FORMAT as CF, prepare_control_preview
from ardrec.initialization.integrated_preview import assemble_integrated_preview
from ardrec.scheduling.guard_preview import diagnose_guards
from ardrec.scheduling.agenda_preview import (
    FORMAT, CandidateAgendaError, CandidateAgendaPreview, plan_candidate_order)
from demo_p14_r23_a3_candidate_order import sample


class CandidateR23Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = sample(4)

    def view(self, *args, **limits):
        return plan_candidate_order(*(args or self.original), **limits)

    def reject(self, code, **limits):
        with self.assertRaises(CandidateAgendaError) as err:
            self.view(**limits)
        self.assertEqual(err.exception.code, code)

    def test_exact_verification(self):
        v = self.view()
        self.assertTrue(v.verify(*self.original))
        self.assertEqual(v.sha256, hashlib.sha256(v.source).hexdigest())

    def test_54_units_and_trivalent_counts(self):
        args = sample(54)
        v = self.view(*args)
        self.assertTrue(v.verify(*args))
        self.assertEqual(len(v.units), 54)
        self.assertEqual(sum(len(x.candidates) for x in v.units), 36)
        self.assertEqual(sum(len(x.excluded) for x in v.units), 72)
        self.assertEqual({p: sum(x.protocol == p for x in v.units)
                          for p in ('SSH', 'FTP', 'SMB')},
                         {'SSH': 18, 'FTP': 18, 'SMB': 18})
        self.assertEqual([c.control_id for c in next(
            x for x in v.units if x.candidates).candidates],
            ['CONTROL_A', 'CONTROL_B'])

    def test_truth_vs_eligibility(self):
        v = self.view()
        unit = {x.service_id: x for x in v.units}
        self.assertEqual(tuple(c.control_id for c in unit['SSH_01'].candidates),
                         ('CONTROL_A', 'CONTROL_B'))
        self.assertEqual(len(unit['SSH_02'].candidates), 0)
        self.assertEqual(len(unit['SSH_03'].candidates), 0)
        self.assertEqual(tuple(c.control_id for c in unit['SSH_04'].candidates),
                         ('CONTROL_A', 'CONTROL_B'))

    def test_false_and_nd_explicit_reasons(self):
        v = self.view()
        u = {x.service_id: x for x in v.units}
        self.assertEqual([x.reason for x in u['SSH_02'].excluded],
                         ['GUARDA_FALSA', 'GUARDA_FALSA'])
        self.assertEqual([x.reason for x in u['SSH_03'].excluded],
                         ['GUARDA_ND', 'GUARDA_ND'])

    def test_pending_control_and_case_distinction(self):
        slot = self.view().units[0].candidates[1]
        self.assertEqual(slot.pending_controls, ('CONTROL_A',))
        self.assertEqual(slot.pending_cases, ('CHECK_A',))
        self.assertIn('CONTROLES_REQUERIDOS_NO_APLICADOS', slot.blockers)
        self.assertIn('CASOS_REQUERIDOS_NO_CONFIRMADOS', slot.blockers)

    def test_root_has_only_operational_authority_block(self):
        slot = self.view().units[0].candidates[0]
        self.assertEqual(slot.pending_controls, ())
        self.assertEqual(slot.pending_cases, ())
        self.assertEqual(slot.blockers, ('AUTORIDAD_OPERACIONAL_NO_ACREDITADA',))

    def test_no_authority_even_for_true(self):
        v = self.view()
        self.assertFalse(v.operational_dispatch_allowed)
        self.assertIsNone(v.published_generation)
        self.assertIsNone(v.executable_agenda)
        self.assertTrue(all(not c.executable for u in v.units for c in u.candidates))

    def test_zero_per_service(self):
        v = self.view(max_per_service=0)
        self.assertEqual(sum(len(u.candidates) for u in v.units), 0)
        for u in v.units:
            if u.service_id in ('SSH_01', 'SSH_04'):
                self.assertEqual([x.reason for x in u.excluded],
                    ['PRESUPUESTO_SERVICIO_AGOTADO', 'CONTROL_REQUERIDO_NO_CANDIDATO'])

    def test_one_per_service_preserves_prefix(self):
        v = self.view(max_per_service=1)
        self.assertEqual(sum(len(u.candidates) for u in v.units), 2)
        self.assertTrue(all(u.candidates[0].control_id == 'CONTROL_A'
                            for u in v.units if u.candidates))
        self.assertEqual(v.units[0].excluded[-1].reason, 'PRESUPUESTO_SERVICIO_AGOTADO')

    def test_service_limit_two(self):
        self.assertEqual(sum(len(u.candidates) for u in self.view(max_per_service=2).units), 4)

    def test_service_limit_32(self):
        self.assertEqual(sum(len(u.candidates) for u in self.view(max_per_service=32).units), 4)

    def test_global_limit_zero(self):
        v = self.view(max_total=0)
        self.assertFalse(any(u.candidates for u in v.units))
        self.assertEqual(v.units[0].excluded[0].reason, 'PRESUPUESTO_GLOBAL_AGOTADO')

    def test_global_limit_one(self):
        v = self.view(max_total=1)
        self.assertEqual(sum(len(u.candidates) for u in v.units), 1)
        self.assertEqual(v.units[0].candidates[0].control_id, 'CONTROL_A')
        self.assertEqual(v.units[0].excluded[0].reason, 'PRESUPUESTO_GLOBAL_AGOTADO')

    def test_global_limit_two(self):
        v = self.view(max_total=2)
        self.assertEqual(sum(len(u.candidates) for u in v.units), 2)
        self.assertEqual(v.units[3].excluded[0].reason, 'PRESUPUESTO_GLOBAL_AGOTADO')

    def test_global_limit_four(self):
        self.assertEqual(sum(len(u.candidates) for u in self.view(max_total=4).units), 4)

    def test_global_limit_2048(self):
        self.assertEqual(sum(len(u.candidates) for u in self.view(max_total=2048).units), 4)

    def test_reject_service_negative(self):
        self.reject('limite_servicio_invalido', max_per_service=-1)

    def test_reject_service_above_ceiling(self):
        self.reject('limite_servicio_invalido', max_per_service=33)

    def test_reject_service_bool(self):
        self.reject('limite_servicio_invalido', max_per_service=True)

    def test_reject_service_float(self):
        self.reject('limite_servicio_invalido', max_per_service=2.0)

    def test_reject_service_string(self):
        self.reject('limite_servicio_invalido', max_per_service='2')

    def test_reject_global_negative(self):
        self.reject('limite_global_invalido', max_total=-1)

    def test_reject_global_above_ceiling(self):
        self.reject('limite_global_invalido', max_total=2049)

    def test_reject_global_bool(self):
        self.reject('limite_global_invalido', max_total=False)

    def test_reject_global_float(self):
        self.reject('limite_global_invalido', max_total=3.5)

    def test_reject_global_string(self):
        self.reject('limite_global_invalido', max_total='8')

    def test_different_budget_produces_different_digest(self):
        self.assertNotEqual(self.view().sha256, self.view(max_total=1).sha256)

    def test_permuted_environment_order_stable(self):
        *five, diagnostic, environments = self.original
        permuted = dict(reversed(list(environments.items())))
        v1 = self.view()
        v2 = self.view(*five, diagnostic, permuted)
        self.assertEqual(v1.source, v2.source)
        self.assertEqual(v1.sha256, v2.sha256)

    def test_no_mutation_of_inputs(self):
        before = [x.source for x in self.original[:6]]
        env = copy.deepcopy(self.original[-1])
        self.view()
        self.assertEqual(before, [x.source for x in self.original[:6]])
        self.assertEqual(env, self.original[-1])

    def test_source_tamper(self):
        v = replace(self.view(), source=self.view().source + b' ')
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'agenda_alterada')

    def test_digest_tamper(self):
        v = replace(self.view(), sha256='a'*64)
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'agenda_alterada')

    def test_integrated_provenance_tamper(self):
        v = replace(self.view(), integrated_sha256='a'*64)
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'origen_no_coincide')

    def test_diagnostic_provenance_tamper(self):
        v = replace(self.view(), diagnostic_sha256='a'*64)
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'origen_no_coincide')

    def test_recomputed_fake_operational_permission_denied(self):
        v = self.view()
        d = json.loads(v.source)
        d['operational_dispatch'] = True
        raw = json.dumps(d, sort_keys=True, ensure_ascii=True,
                         allow_nan=False, separators=(',', ':')).encode('ascii')
        counterfeit = replace(v, source=raw, sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(CandidateAgendaError) as cm:
            counterfeit.verify(*self.original)
        self.assertEqual(cm.exception.code, 'agenda_no_coincide')

    def test_recomputed_fake_executable_agenda_denied(self):
        v = self.view()
        d = json.loads(v.source)
        d['executable_agenda'] = ['CONTROL_A']
        raw = json.dumps(d, sort_keys=True, ensure_ascii=True,
                         allow_nan=False, separators=(',', ':')).encode('ascii')
        v = replace(v, source=raw, sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'agenda_no_coincide')

    def test_noncanonical_json_denied(self):
        v = self.view()
        raw = v.source.replace(b':', b': ', 1)
        v = replace(v, source=raw, sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'agenda_no_canonica')

    def test_duplicate_json_keys_denied(self):
        v = self.view()
        raw = v.source.replace(b'{"candidate_order":', b'{"candidate_order":[],"candidate_order":', 1)
        v = replace(v, source=raw, sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'clave_duplicada')

    def test_immutable_view(self):
        v = self.view()
        with self.assertRaises((AttributeError, TypeError)):
            v.units[0].service_id = 'ALTERADO'

    def test_published_output_is_explicitly_false(self):
        d = json.loads(self.view().source)
        self.assertEqual(d['format'], FORMAT)
        self.assertEqual(d['scope'], 'SYNTHETIC_NON_EXECUTABLE_CANDIDATE_ORDER')
        self.assertIsNone(d['generation_published'])
        self.assertIsNone(d['executable_agenda'])
        self.assertFalse(d['operational_dispatch'])
        self.assertFalse(d['controls_applied'])
        self.assertEqual(d['p8_operational'], 'NO-GO')
        self.assertTrue(all(not c['executable'] for x in d['services']
                            for c in x['candidates']))

    def test_distinct_input_chain_rejected(self):
        args = sample(3)
        with self.assertRaises((CandidateAgendaError, ValueError)):
            self.view().verify(*args)

    def test_missing_diagnostic_denied(self):
        args = list(self.original)
        args[5] = None
        with self.assertRaises(CandidateAgendaError) as cm:
            self.view(*args)
        self.assertEqual(cm.exception.code, 'diagnostico_requerido')

    def test_dependency_on_excluded_control_denied(self):
        rules, initial, deps, _controls, _integrated, _diag, environments = sample(1)
        controls = prepare_control_preview(rules, initial, deps, {'format': CF,
            'rule_source_sha256': rules.sha256,
            'initial_snapshot_sha256': initial.sha256,
            'dependency_snapshot_sha256': deps.sha256,
            'services': [{'id': 'SSH_01', 'controls': [
                {'id': 'CONTROL_A', 'guard_rule_id': 'NEVER', 'target_case_id': 'CHECK_A',
                 'precedence': 20, 'requires': []},
                {'id': 'CONTROL_B', 'guard_rule_id': 'ALLOW', 'target_case_id': 'CHECK_B',
                 'precedence': 10, 'requires': ['CONTROL_A']}]}]})
        integrated = assemble_integrated_preview(rules, initial, deps, controls)
        diag = diagnose_guards(rules, initial, deps, controls, integrated, environments)
        v = plan_candidate_order(rules, initial, deps, controls, integrated, diag, environments)
        self.assertEqual([x.reason for x in v.units[0].excluded],
                         ['GUARDA_FALSA', 'CONTROL_REQUERIDO_NO_CANDIDATO'])
        self.assertFalse(v.units[0].candidates)

    def test_true_rule_with_indeterminate_competitor_denied(self):
        from test_p14_r22_a3_guard_preview import custom
        rules, initial, deps, controls, integrated = custom(
            conditions=[
                {'id': 'G1', 'condicion': {
                    'op': 'CONSTANTE', 'tipo': 'LOGICO', 'valor': 'VERDADERO'}},
                {'id': 'G2', 'condicion': {'op': 'CAMPO', 'nombre': 'FACT'}}],
            fields={'FACT': 'LOGICO'})
        env = {'SSH_01': {}}
        diagnostic = diagnose_guards(rules, initial, deps, controls, integrated, env)
        self.assertIs(diagnostic.units[0].controls[0].truth, Truth.VERDADERO)
        self.assertIs(diagnostic.units[0].table_status, Truth.ND)
        view = plan_candidate_order(rules, initial, deps, controls, integrated,
                                    diagnostic, env)
        self.assertFalse(view.units[0].candidates)
        self.assertEqual(view.units[0].excluded[0].reason, 'TABLA_NO_ACREDITADA')

    def test_empty_controls_remains_empty(self):
        from test_p14_r21_a2_integrated_preview import make
        first = make(with_controls=False)
        integrated = assemble_integrated_preview(*first)
        env = {x.service_id: {} for x in integrated.units}
        diagnostic = diagnose_guards(*first, integrated, env)
        view = plan_candidate_order(*first, integrated, diagnostic, env)
        self.assertTrue(all(not u.candidates and not u.excluded for u in view.units))
        self.assertIsNone(view.executable_agenda)

    def test_diagnostic_env_change_denied(self):
        args = list(self.original)
        env = copy.deepcopy(args[-1])
        env['SSH_01']['FACT'] = Truth.FALSO
        with self.assertRaises((CandidateAgendaError, ValueError)):
            self.view(*args[:-1], env)

    def test_plan_own_budget_integrity(self):
        v = replace(self.view(), max_total=0)
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'agenda_no_coincide')

    def test_bad_plan_budget_integrity(self):
        v = replace(self.view(), max_total=-1)
        with self.assertRaises(CandidateAgendaError) as cm:
            v.verify(*self.original)
        self.assertEqual(cm.exception.code, 'limite_global_invalido')


if __name__ == '__main__':
    unittest.main()
