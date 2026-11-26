"""Native archive integration for documentary DEV, with no transport."""
import json
import os
import subprocess
import sys
import unittest

import test_r303_dev_assessment as fixture
from ardrec.coordination import r166_case_archive_cli as cli
from ardrec.contracts import ND
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.analytical_references import decode


@unittest.skipIf(os.geteuid() == 0, "non-root contract")
class DevelopmentSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.f = fixture.DevelopmentAssessmentTests()
        self.addCleanup(self.f.doCleanups)
        self.f.setUp()
        self.native = self.f.archive / (self.f.case_id + ".analytical")
        self.index = self.f.archive / (self.f.case_id + ".snapshot.json")

    def call(self, **kwargs):
        f = self.f
        params = dict(origin=f.origin, archive=f.archive, case_id=f.case_id,
                      scenario_pin=f.pin, inputs=f.inputs, input_pin=f.input_pin)
        params.update(kwargs)
        return cli.development_snapshot(**params)

    def test_native_projection_and_no_promotion(self):
        self.f.call()
        record, status = self.call()
        self.assertEqual(status, "DEV_SNAPSHOT_CREATED")
        self.assertEqual(record["references"], 7)
        self.assertEqual(record["a8"]["recommendation"], "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA")
        self.assertIsNone(record["a8"]["applied_transition"])
        self.assertFalse(record["operational_a9_published"])
        self.assertFalse(record["execution_authorized"])
        self.assertEqual(record["p8"], "NO-GO")
        with AnalyticalArchive(self.native) as a:
            native = a.load(record["snapshot_sha256"])
        self.assertEqual(len(native.projections), 1)
        p = native.projections[0]
        self.assertEqual(p.operational_state.value, "PREPARADO")
        self.assertIsInstance(p.frozen.initial_risk, ND)
        self.assertIsInstance(p.analysis.recalibrated_risk, ND)
        objs = {obj["role"]: obj["payload"] for obj in map(decode, native.references.object_bytes)}
        self.assertEqual(len(objs), 7)
        self.assertEqual(objs["characterization"]["initial_risk_candidate"], "1/3")
        self.assertEqual(objs["convergence_window"]["hypothetical_rf_upper"], "11/18")
        self.assertEqual(objs["execution_counters"]["operational_attempts"], 0)

    def test_idempotent_readback_and_index_recovery(self):
        self.f.call()
        record, _ = self.call()
        self.assertEqual(self.call(), (record, "DEV_SNAPSHOT_REOPENED"))
        self.assertEqual(self.call(reopen=True), (record, "DEV_SNAPSHOT_REOPENED"))
        self.index.unlink()  # Simulate interruption before index creation, test only.
        self.assertEqual(self.call(), (record, "DEV_SNAPSHOT_CREATED"))

    def test_missing_assessment_does_not_create_archive(self):
        with self.assertRaises(OSError):
            self.call()
        self.assertFalse(self.native.exists())
        self.assertFalse(self.index.exists())

    def test_changed_source_rejected(self):
        self.f.call()
        self.call()
        fixture.put(self.f.inputs / (self.f.support_pin + ".bin"), b"TEST ALTERATION")
        with self.assertRaises(ValueError):
            self.call(reopen=True)

    def test_corrupted_archive_rejected_on_both_paths(self):
        self.f.call()
        record, _ = self.call()
        blob = self.native / record["snapshot_sha256"] / (record["manifest_sha256"] + ".json")
        blob.chmod(0o600)
        blob.write_bytes(b"{}")
        for reopen in (False, True):
            with self.assertRaises((ValueError, OSError)):
                self.call(reopen=reopen)

    def test_normal_cli_and_invalid_index(self):
        f = self.f
        f.call()
        args = ["--origen", str(f.origin), "--archivo", str(f.archive), "--id", f.case_id,
                "--sha256", f.pin, "--valoracion", str(f.inputs), "--sha256-valoracion", f.input_pin, "--json"]
        docs = []
        for action in ("archivar-analisis-dev", "reabrir-analisis-dev"):
            result = subprocess.run([sys.executable, "-m", "ardrec", "caso", action, *args],
                                    capture_output=True, check=True)
            docs.append(json.loads(result.stdout))
        self.assertEqual(docs[0], docs[1])
        fixture.put(self.index, b"{}\n")
        with self.assertRaises((KeyError, ValueError)):
            self.call(reopen=True)
