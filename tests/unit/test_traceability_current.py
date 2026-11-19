"""Rechazar deriva de trazabilidad y cumplimiento inventado / Reject traceability drift."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ardrec_current_traceability',ROOT/'scripts/verificar_trazabilidad_actual.py')
checker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

class CurrentTraceabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory=checker.discover(ROOT)
    def setUp(self):
        self.registry=json.loads((ROOT/checker.REGISTRY).read_text())
        self.evidence=json.loads((ROOT/checker.EVIDENCE).read_text())
    def validate(self):
        return checker.validate(ROOT,self.registry,self.evidence,discovered=self.inventory,check_note=False)
    def reject(self):
        with self.assertRaises(ValueError):self.validate()
    def test_current_registered_graph(self):
        result=self.validate()
        self.assertEqual((result['requirements'],result['components'],result['development_obligations']),(44,18,7))
        self.assertEqual((result['baseline_python_tests'],result['baseline_rust_tests'],result['integration_scripts']),(405,73,7))
    def test_missing_requirement(self):
        self.registry['requirements'].pop();self.reject()
    def test_duplicate_requirement(self):
        self.registry['requirements'].append(deepcopy(self.registry['requirements'][0]));self.reject()
    def test_unknown_component(self):
        self.registry['requirements'][0]['components'].append('UNKNOWN');self.reject()
    def test_renamed_dynamic_python_test(self):
        t=next(t for t in self.registry['test_inventory'] if t.get('unittest_id','').endswith('test_wrong_object_version'))
        t['unittest_id']+='missing';self.reject()
    def test_missing_rust_test(self):
        self.registry['test_inventory']=[x for x in self.registry['test_inventory'] if x['id']!='crates/ardrec-executor/src/timing.rs::actual_clock_available'];self.reject()
    def test_external_module_path(self):
        self.registry['components'][0]['modules'].append('../outside.py');self.reject()
    def test_changed_source_hash(self):
        self.registry['source_files']['src/ardrec/state.py']='0'*64;self.reject()
    def test_missing_source_hash(self):
        del self.registry['source_files']['src/ardrec/state.py'];self.reject()
    def test_wrong_ci_commit(self):
        self.evidence['items'][0]['commit']='0'*40;self.reject()
    def test_wrong_ci_run(self):
        self.evidence['items'][0]['run_id']+=1;self.reject()
    def test_suite_cannot_be_individual_execution(self):
        self.evidence['items'][0]['per_test_results_available']=True;self.reject()
    def test_no_system_acceptance_promotion(self):
        self.registry['system_functional_acceptance']='PASS';self.reject()
    def test_oracles_are_not_algorithm_execution(self):
        self.registry['reference_cases'][0]['production_verification']='PASS';self.reject()
    def test_methodology_requires_external_owner(self):
        row=next(r for r in self.registry['requirements'] if r['id']=='MET-01')
        row['algorithms']=['A10'];self.reject()
    def test_gate_cannot_be_weakened(self):
        self.registry['development_obligations'][0]['gate']='OPTIONAL';self.reject()
    def test_obligation_cannot_disappear(self):
        self.registry['development_obligations'].pop();self.reject()
    def test_reverse_index_cannot_drift(self):
        self.registry['reverse_indexes']['evidence']['EV-MAIN26-CI']=[];self.reject()
    def test_baseline_evidence_not_new_execution(self):
        self.evidence['new_increment_execution']='PASS';self.reject()
    def test_r7_inventory_is_exact(self):
        observed = sorted(
            x for x in self.inventory
            if x.startswith(checker.R7_TEST_MODULE + '.')
        )
        self.assertEqual(observed, sorted(checker.R7_TEST_IDS))

    def test_missing_r7_method_is_rejected(self):
        missing = 'test_p8_diagnostic.P8DiagnosticTests.test_shared_vectors_exact_codes'
        self.inventory = [x for x in self.inventory if x != missing]
        self.reject()

    def test_unregistered_r7_method_is_rejected(self):
        self.inventory = [
            *self.inventory,
            'test_p8_diagnostic.P8DiagnosticTests.test_unregistered_method'
        ]
        self.reject()

    def test_r8_inventory_is_exact(self):
        observed = sorted(x for x in self.inventory
                          if x.startswith(checker.R8_TEST_MODULE + '.'))
        self.assertEqual(observed, sorted(checker.R8_TEST_IDS))

    def test_missing_r8_method_rejected(self):
        missing = next(iter(checker.R8_TEST_IDS))
        self.inventory = [x for x in self.inventory if x != missing]
        self.reject()

    def test_unregistered_r8_method_rejected(self):
        self.inventory = [*self.inventory,
                          'test_p8_state_bridge.P8StateBridgeTests.test_fake']
        self.reject()

    def test_rendered_document_matches_registry(self):
        self.assertEqual((ROOT/checker.NOTE).read_text(),checker.render(self.registry))


    def test_r99_rust_inventory_exact(self):
        path = ROOT / "crates/ardrec-executor/src/r99_ssh_loopback.rs"
        symbols = checker.re.findall(
            r"#\[test\]\s*fn\s+(\w+)\s*\(",
            path.read_text(encoding="utf-8")
        )
        declared = checker.R99_RUST_TESTS[
            "crates/ardrec-executor/src/r99_ssh_loopback.rs"
        ]
        self.assertEqual(len(symbols), 7)
        self.assertEqual(frozenset(symbols), declared)

    def test_r99_rust_inventory_rejects_missing_and_extra(self):
        checks = checker.indexed(self.registry["test_inventory"])
        observed = {}

        for path in (
            ROOT / "crates/ardrec-executor/src"
        ).rglob("*.rs"):
            for name in checker.re.findall(
                r"#\[test\]\s*fn\s+(\w+)\s*\(",
                path.read_text(encoding="utf-8")
            ):
                test_id = (
                    path.relative_to(ROOT).as_posix()
                    + "::" + name
                )
                self.assertNotIn(test_id, observed)
                observed[test_id] = name

        report = checker.verify_p8_rust_inventory(
            observed, checks
        )
        self.assertEqual(
            report["current_rust_lib_tests"], 118
        )
        self.assertEqual(report["r99_rust_tests"], 7)
        self.assertEqual(report["r105_rust_tests"], 10)
        self.assertFalse(report["historical_inventory_changed"])

        missing = dict(observed)
        missing.pop(
            "crates/ardrec-executor/src/"
            "r99_ssh_loopback.rs::r99_eof_rejected"
        )

        with self.assertRaisesRegex(
            ValueError, "Inventario Rust incompleto"
        ):
            checker.verify_p8_rust_inventory(
                missing, checks
            )

        extra = dict(observed)
        extra[
            "crates/ardrec-executor/src/"
            "r99_ssh_loopback.rs::r99_unregistered_test"
        ] = "r99_unregistered_test"

        with self.assertRaisesRegex(
            ValueError, "Inventario Rust incompleto"
        ):
            checker.verify_p8_rust_inventory(
                extra, checks
            )

    def test_r105_rust_inventory_exact(self):
        path = ROOT / "crates/ardrec-executor/src/r105_ssh_kexinit_loopback.rs"
        symbols = checker.re.findall(
            r"#\[test\]\s*fn\s+(\w+)\s*\(",
            path.read_text(encoding="utf-8")
        )
        self.assertEqual(len(symbols), 10)
        self.assertEqual(
            frozenset(symbols),
            checker.R105_RUST_TESTS["crates/ardrec-executor/src/r105_ssh_kexinit_loopback.rs"]
        )

    def test_r105_rust_inventory_rejects_missing_and_extra(self):
        checks = checker.indexed(self.registry["test_inventory"])
        observed = {}
        for path in (ROOT / "crates/ardrec-executor/src").rglob("*.rs"):
            for name in checker.re.findall(
                r"#\[test\]\s*fn\s+(\w+)\s*\(",
                path.read_text(encoding="utf-8")
            ):
                identity = path.relative_to(ROOT).as_posix() + "::" + name
                self.assertNotIn(identity, observed)
                observed[identity] = name
        self.assertEqual(
            checker.verify_p8_rust_inventory(observed, checks)[
                "current_rust_lib_tests"
            ], 118
        )
        target = "crates/ardrec-executor/src/r105_ssh_kexinit_loopback.rs::r105_rejects_non_ssh"
        missing = dict(observed)
        missing.pop(target)
        with self.assertRaisesRegex(ValueError, "Inventario Rust incompleto"):
            checker.verify_p8_rust_inventory(missing, checks)
        extra = dict(observed)
        extra["crates/ardrec-executor/src/r105_ssh_kexinit_loopback.rs::r105_unregistered"] = "r105_unregistered"
        with self.assertRaisesRegex(ValueError, "Inventario Rust incompleto"):
            checker.verify_p8_rust_inventory(extra, checks)

if __name__=='__main__':unittest.main()
