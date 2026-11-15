"""Pruebas adversariales de fichas R51; solo documentos, cero VM/red/host."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'lab'))
import verify_p14_r51_dev_contract as v

class R51DevContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def load(p):
            return v.parse(v.secure_read(ROOT, p))
        cls.m = load(v.MANIFEST)
        cls.catalog = load(cls.m['catalog_path'])
        cls.topology = load(cls.m['topology_path'])
        cls.resources = load(cls.m['resource_path'])
        cls.versions = load(cls.m['version_path'])
        cls.evidence = load(cls.m['evidence_path'])
        cls.configs = {r: v.secure_read(ROOT, f'lab/services-v1/config/{r}.conf') for r in v.ROLES}

    def setUp(self):
        self.m = deepcopy(self.__class__.m)
        self.catalog = deepcopy(self.__class__.catalog)
        self.topology = deepcopy(self.__class__.topology)
        self.resources = deepcopy(self.__class__.resources)
        self.versions = deepcopy(self.__class__.versions)
        self.evidence = deepcopy(self.__class__.evidence)
        self.configs = dict(self.__class__.configs)

    def check(self):
        return v.valid(ROOT, self.m, self.catalog, self.topology,
                       self.resources, self.versions, self.evidence, self.configs)

    def fail_with(self, marker):
        with self.assertRaisesRegex(v.ContractError, marker):
            self.check()

    def test_source_is_accepted_only_as_offline_projection(self):
        expected = self.check()
        self.assertEqual(expected['r51_result'], 'PASS_OFFLINE_CONSISTENCY_ONLY')
        self.assertEqual(expected['families_total'], 25)
        self.assertEqual([x['families'] for x in expected['units']], [8, 8, 9])
        self.assertEqual(expected['confirmed_live_services'], 0)
        self.assertEqual(expected['complete_family_acceptance'], 0)
        self.assertEqual(expected['scientific_sample_n'], 0)
        self.assertEqual(expected['p8_operational'], 'NO-GO')
        self.assertFalse(expected['host_queried'])

    def test_manifest_is_self_consistent_on_disk(self):
        expected = v.verify(ROOT)
        self.assertEqual(expected['families_total'], 25)

    def test_identity_duplicated_fails(self):
        self.m['units'][1]['unit_id'] = self.m['units'][0]['unit_id']
        self.fail_with('unit_identity')

    def test_role_swapped_fails(self):
        self.m['units'].reverse()
        self.fail_with('unit_order_or_protocol')

    def test_network_prefix_drift_fails(self):
        self.m['units'][0]['expected_network_cidr'] = '10.203.30.0/24'
        self.fail_with('network_mismatch')

    def test_unapproved_default_route_fails(self):
        self.topology['networks'][0]['default_gateway'] = '10.203.30.1'
        self.fail_with('network_route_escape')

    def test_runner_forwarding_cannot_be_enabled(self):
        self.topology['runner_forwarding'] = True
        self.fail_with('topology_deny_first_drift')

    def test_catalog_missing_family_fails(self):
        self.catalog['families'].pop()
        self.fail_with('catalog_family_count')

    def test_catalog_cannot_claim_enabled(self):
        self.catalog['execution_enabled'] = True
        self.fail_with('catalog_false_operational_state')

    def test_coverage_not_earned_by_historical_smoke(self):
        self.m['units'][0]['case_families'][6]['coverage'] = 'COVERED'
        self.fail_with('family_false_acceptance')

    def test_partial_without_smoke_fails(self):
        self.m['units'][0]['case_families'][0]['coverage'] = 'PARTIAL'
        self.fail_with('coverage_without_historical_support')

    def test_cross_service_smoke_fails(self):
        self.m['units'][1]['case_families'][0]['historical_smoke_checks'] = ['ssh-reference']
        self.fail_with('family_smoke_cross_scope')

    def test_nonexistent_smoke_fails(self):
        self.m['units'][0]['case_families'][0]['historical_smoke_checks'] = ['ssh-fiction']
        self.fail_with('family_smoke_cross_scope')

    def test_credential_reference_cannot_be_changed(self):
        self.resources['targets'][1]['credential'] = 'secret-inline'
        self.fail_with('synthetic_account_drift')

    def test_configs_change_fails(self):
        self.configs['ftp'] += b'\nlisten=NO\n'
        self.fail_with('service_config_changed_ftp')

    def test_wrong_package_version_fails(self):
        self.versions['guest_packages']['samba'] = '2:0.0'
        self.fail_with('package_source_drift')

    def test_reported_r34_pass_without_new_proof_fails(self):
        self.m['r34_live_containment'] = 'PASS'
        self.fail_with('manifest_r34_live_containment')

    def test_unearned_A6_is_rejected(self):
        self.m['units'][0]['admitted_evidence'] = [{'fake': 'PASS'}]
        self.fail_with('unearned_A6_A9_or_risk')

    def test_unearned_A9_is_rejected(self):
        self.m['units'][0]['confirmed_generation'] = 1
        self.fail_with('unearned_A6_A9_or_risk')

    def test_unearned_risk_is_rejected(self):
        self.m['units'][0]['recalibrated_risk'] = '1/2'
        self.fail_with('unearned_A6_A9_or_risk')

    def test_attempt_to_enable_dispatch_fails(self):
        self.m['operational_dispatch'] = True
        self.fail_with('unauthorized_claim_operational_dispatch')

    def test_experimental_unit_not_frozen(self):
        self.m['units'][2]['purpose'] = 'EXPERIMENT'
        self.fail_with('unit_experiment_promotion')

    def test_duplicate_json_field_fails(self):
        with self.assertRaisesRegex(v.ContractError, 'json_duplicate_key'):
            v.parse(b'{"a":1,"a":2}')

    def test_nonfinite_json_fails(self):
        with self.assertRaisesRegex(v.ContractError, 'json_nonfinite'):
            v.parse(b'{"n":NaN}')

    def test_path_escape_rejected(self):
        with self.assertRaisesRegex(v.ContractError, 'path_escape'):
            v.secure_read(ROOT, 'lab/../secret')

    def test_historical_evidence_is_not_scientific_sample(self):
        self.evidence['experimental_data'] = True
        self.fail_with('historical_evidence_mismatch')

if __name__ == '__main__':
    unittest.main()
