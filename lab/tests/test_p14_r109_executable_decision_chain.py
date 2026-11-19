"""R109: independent offline decision execution, cross-kernel proofs, fail-closed."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from pathlib import Path
import ast
import sys
from tempfile import TemporaryDirectory
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'src'), str(REPO / 'scripts')]

from ardrec.analytics.exact_preview import rational
from ardrec.coordination import r59d_a5_result_intake as a5
from ardrec.coordination import r106_ssh_case_provenance as r106
from ardrec.coordination import r107_offline_a1_a10_orchestrator as r107
from ardrec.coordination import r108_offline_state_execution as r108
from ardrec.coordination import r109_executable_decision_chain as r109
from ardrec.coordination.r58k_unified_family_bridge import build_unified_preview
from ardrec_p14_r58k_unified_family_demo import synthetic_unified_inputs


class R109DecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        units = synthetic_unified_inputs()
        extras = deepcopy(units[:25])
        for item in extras:
            item['unit']['session_id'] = 'DEV_TUTOR_002'
            item['unit']['assessment_index'] = 1
        cls.unified = build_unified_preview(units + extras)
        m104 = {
            'schema': r106.R104_SCHEMA, 'mode': 'SYNTHETIC_OFFLINE_NO_AUTHORITY',
            'case_count': 54, 'family_count': 25,
            'count_by_service': cls.unified['count_by_service'],
            'report_sha256': cls.unified['sha256'],
            'report_file_sha256': a5.sha(a5.canonical(cls.unified) + b'\n'),
            'a6_classification': 'ND', 'confirmed_rf': None,
            'published_generation': None, 'operational_dispatch': False,
            'p8_operational': 'NO-GO', 'vm_starts': 0, 'host_mutations': 0,
        }
        m104['sha256'] = a5.digest(m104)
        observation = {
            'schema': r106.R105_SCHEMA,
            'transport': 'REAL_TCP_IPV4_LOOPBACK_ONLY',
            'server_identification': 'SSH-2.0-ARDREC_R105_FIXTURE',
            'identification_sha256': r106.R105_SERVER_SHA,
            'kexinit_sha256': r106.R105_KEX_SHA,
            'kexinit_bytes': 160,
            'offered_kex_algorithms': ['curve25519-sha256'],
            'offered_host_key_algorithms': ['ssh-ed25519'],
            'elapsed_ms': 2, 'tcp_connections': 1,
            'client_identifications_sent': 1,
            'keys_negotiated': False, 'authenticated': False,
            'remote_commands': 0, 'a5_operational_attempts': 0,
            'a6_classification': 'ND', 'a7_confirmed_rf': None,
            'evidence_accredited': False, 'dispatch_allowed': False,
            'p8_operational': 'NO-GO',
        }
        f11 = {
            'schema': r106.F11_SCHEMA, 'target': 'ardrec-r33-dev-ssh',
            'original_result_sha256': r106.F11_R103_RESULT,
            'physical_hook_denial_recorded': True,
            'virsh_start_rejected': True,
            'watcher_finalization_defect_confirmed': True,
            'original_strict_acceptance': 'FAIL_PRESERVED',
            'independent_boot_lifecycle_attested': False,
            'new_start_attempts': 0, 'p8_operational': 'NO-GO',
            'authorized_dispatch': False,
        }
        f11['sha256'] = a5.digest(f11)
        link = r106.build(cls.unified, m104, observation, f11,
                          f11_expected_sha=f11['sha256'])
        m106 = {
            'schema': 'ardrec-r106-private-provenance-manifest-v1',
            'mode': 'DURABLE_MIXED_PROVENANCE_NO_CASE_ATTESTATION',
            'link_sha256': link['sha256'],
            'observation_sha256': a5.digest(observation),
            'r104_report_sha256': link['r104_synthetic_report_sha256'],
            'r103_f11_review_sha256': link['r103_f11_forensic_review_sha256'],
            'r105_rust_source_sha256': r106.R105_SOURCE_PIN,
            'boot_test_repeated': False, 'vm_starts': 0,
            'ssh_authentication': False, 'a5_operational_starts': 0,
            'a6_classification': 'ND', 'a7_confirmed_rf': None,
            'a8_transition_applied': None,
            'dispatch_allowed': False, 'p8_operational': 'NO-GO',
        }
        m106['sha256'] = a5.digest(m106)
        cls.trace = r107.build(cls.unified, m104, link, m106)
        cls.model = r108.build(cls.trace)
        cls.result = r109.build(cls.unified, cls.trace, cls.model)

    def test_54_bijective_cases(self):
        self.assertEqual(len(self.result['cases']), 54)
        self.assertEqual(len({x['case_id_a7'] for x in self.result['cases']}), 54)

    def test_25_family_coverage(self):
        self.assertEqual(len({x['family_id'] for x in self.result['cases']}), 25)
        self.assertEqual(self.result['family_count'], 25)

    def test_exact_service_distribution(self):
        self.assertEqual(self.result['protocol_counts'], r107.COUNTS)

    def test_540_decision_checkpoints(self):
        self.assertEqual(self.result['status_stage_count'], 540)
        for x in self.result['cases']:
            self.assertEqual([s['algorithm'] for s in x['stage_chain']], list(r109.ALGOS))
            self.assertEqual(len(x['stage_chain']), 10)

    def test_270_real_offline_kernel_calls_recorded(self):
        self.assertEqual(self.result['offline_case_checks_by_stage'],
                         {x: 54 for x in ('A4','A6','A7','A8','A10')})

    def test_a7_exact_rational_bounds(self):
        for x in self.result['cases']:
            self.assertLessEqual(rational(x['a7_rf_lower']), rational(x['a7_rf_upper']))
            self.assertIsNone(x['a7_rf_confirmed'])
        self.assertEqual(self.result['mathematical_interval_count'], 54)

    def test_a6_three_valued_nd(self):
        self.assertEqual({x['a6_truth'] for x in self.result['cases']}, {'ND'})
        self.assertEqual(self.result['a6_classification'], 'ND')

    def test_a8_recomputed_without_transition(self):
        self.assertEqual({x['a8_recommendation'] for x in self.result['cases']},
                         {'PAUSAR_HASTA_EVIDENCIA_AUTORIZADA'})
        self.assertTrue(all(x['a8_operational_transition'] is None for x in self.result['cases']))

    def test_model_phases_from_executed_T8_T9_T10(self):
        counts = Counter(x['counterfactual_final_phase'] for x in self.result['cases'])
        self.assertEqual(dict(counts), {'PAUSADO':18,'PENDIENTE':18,'DETENIDO':18})
        self.assertEqual(self.result['rechecked_r108_model_events'], 72)

    def test_r106_one_case_never_guest_proof(self):
        self.assertEqual(sum(x['r106_fixture_association_only'] for x in self.result['cases']), 1)
        self.assertEqual(self.result['a5_operational_starts'], 0)

    def test_never_operationally_promoted(self):
        for key in ('a5_operational_starts','a8_operational_transitions',
                    'a9_published_generations','vm_starts','host_mutations'):
            self.assertEqual(self.result[key], 0)
        self.assertFalse(self.result['operational_dispatch'])
        self.assertFalse(self.result['a1_a10_operational_implementation_complete'])
        self.assertEqual(self.result['p8_operational'], 'NO-GO')

    def test_case_and_stage_hash_chain(self):
        previous = None
        for row in self.result['cases']:
            self.assertEqual(row['previous_case_sha256'], previous)
            self.assertEqual(row['sha256'], a5.digest({k:v for k,v in row.items() if k!='sha256'}))
            stage_head = None
            for step in row['stage_chain']:
                self.assertEqual(step['previous_stage_sha256'], stage_head)
                self.assertEqual(step['sha256'], a5.digest({k:v for k,v in step.items() if k!='sha256'}))
                stage_head = step['sha256']
            self.assertEqual(row['stage_head_sha256'], stage_head)
            previous = row['sha256']
        self.assertEqual(previous, self.result['case_chain_head_sha256'])

    def test_deterministic_reexecution(self):
        self.assertEqual(self.result, r109.build(self.unified,self.trace,self.model))
        self.assertTrue(r109.verify(self.result,self.unified,self.trace,self.model))

    def test_fake_a6_truth_even_if_rehashed_rejected(self):
        bad = deepcopy(self.result)
        bad['cases'][0]['a6_truth'] = 'VERDADERO'
        bad['cases'][0]['sha256'] = a5.digest({k:v for k,v in bad['cases'][0].items() if k!='sha256'})
        bad['sha256'] = a5.digest({k:v for k,v in bad.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r109.verify(bad,self.unified,self.trace,self.model)

    def test_altered_a7_interval_rejected(self):
        bad = deepcopy(self.trace)
        bad['cases'][0]['a7_interval_upper'] = '0'
        bad['sha256'] = a5.digest({k:v for k,v in bad.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r109.build(self.unified,bad,self.model)

    def test_wrong_model_source_sha_rejected(self):
        bad = deepcopy(self.model)
        bad['r107_trace_sha256'] = '0'*64
        bad['sha256'] = a5.digest({k:v for k,v in bad.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r109.build(self.unified,self.trace,bad)

    def test_forged_unified_publication_rejected(self):
        bad = deepcopy(self.unified)
        bad['published_generation'] = 1
        bad['sha256'] = a5.digest({k:v for k,v in bad.items() if k!='sha256'})
        with self.assertRaises(ValueError):
            r109.build(bad,self.trace,self.model)

    def test_no_process_network_or_host_actions(self):
        module_path = REPO / 'src/ardrec/coordination/r109_executable_decision_chain.py'
        script_path = REPO / 'scripts/ardrec_p14_r109_executable_decision_chain.py'
        for path in (module_path,script_path):
            tree = ast.parse(path.read_text('utf-8'))
            imports = [alias.name.split('.')[0] for node in ast.walk(tree)
                       if isinstance(node,(ast.Import, ast.ImportFrom))
                       for alias in (node.names if isinstance(node,ast.Import) else [])]
            self.assertFalse({'subprocess','socket','libvirt','paramiko'}.intersection(imports))

    def test_private_durable_replay(self):
        from ardrec_p14_r109_executable_decision_chain import persist,verify
        with TemporaryDirectory(prefix='ardrec-r109-private-') as temp:
            session, report, manifest = persist(self.unified,self.trace,self.model,Path(temp))
            self.assertEqual((report,manifest),verify(session,self.unified,self.trace,self.model))
            self.assertEqual({p.name for p in session.iterdir()}, {'decision.json','manifest.json'})
            self.assertEqual({p.stat().st_mode & 0o777 for p in session.iterdir()}, {0o600})

    def test_private_tampering_rejected(self):
        from ardrec_p14_r109_executable_decision_chain import persist,verify
        with TemporaryDirectory(prefix='ardrec-r109-tamper-') as temp:
            session, _, _ = persist(self.unified,self.trace,self.model,Path(temp))
            target=session/'decision.json'
            target.write_bytes(target.read_bytes()[:-1]+b' ')
            with self.assertRaises(ValueError):
                verify(session,self.unified,self.trace,self.model)

    def test_private_extra_file_rejected(self):
        from ardrec_p14_r109_executable_decision_chain import persist,verify
        with TemporaryDirectory(prefix='ardrec-r109-inventory-') as temp:
            session, _, _ = persist(self.unified,self.trace,self.model,Path(temp))
            (session/'rogue.json').write_text('{}')
            with self.assertRaises(ValueError):
                verify(session,self.unified,self.trace,self.model)


if __name__ == '__main__':
    unittest.main()
