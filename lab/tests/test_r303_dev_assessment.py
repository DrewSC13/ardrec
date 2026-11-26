"""Documentary arithmetic and persistence; no operational activity."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ardrec.coordination import r166_case_archive_cli as cli
from ardrec.coordination.r115_dev_admission_contract import canonical
from ardrec.experiments import initial_assessment as a2


def put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


@unittest.skipIf(os.geteuid() == 0, "non-root contract")
class DevelopmentAssessmentTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.origin = self.root / "source"
        self.archive = self.root / "archive"
        self.inputs = self.root / "inputs"
        for p in (self.archive, self.inputs):
            p.mkdir(mode=0o700)
        self.case_id = "DEV-" + "a" * 32
        a2.materialize_case(self.origin, "SSH", "b" * 40, {"fixture": "TEST_ONLY"})
        self.pin = hashlib.sha256((self.origin / "scenario.json").read_bytes()).hexdigest()
        self.case, _ = cli.development_case(origin=self.origin, archive=self.archive,
                                            case_id=self.case_id, scenario_pin=self.pin)
        support = b"TEST ONLY: hypothetical documented ordinal assignment."
        self.support_pin = hashlib.sha256(support).hexdigest()
        put(self.inputs / (self.support_pin + ".bin"), support)
        self.entry = {"schema": "ARDREC-R303-DEV-ASSESSMENT-INPUT-v1",
                      "case_id": self.case_id, "case_sha256": self.case["sha256"],
                      "ratings": {name: {"ordinal": 1 if name == "exposure" else 3,
                                         "support_sha256": self.support_pin,
                                         "justification": "Synthetic test only; not an observed condition."}
                                  for name in a2.DIMENSIONS}}
        self.save()

    def save(self):
        self.input_pin = put(self.inputs / "ratings.json", canonical(self.entry))

    def call(self, **kwargs):
        params = dict(origin=self.origin, archive=self.archive, case_id=self.case_id,
                      scenario_pin=self.pin, inputs=self.inputs, input_pin=self.input_pin)
        params.update(kwargs)
        return cli.development_assessment(**params)

    def test_exact_math_and_boundaries(self):
        record, status = self.call()
        self.assertEqual(status, "DEV_ASSESSMENT_CREATED")
        self.assertEqual(record["draft"]["calculated"]["initial_risk"], "1/3")
        self.assertEqual(record["draft"]["calculated"]["normalized_criticality"], "1/2")
        bounds = record["interval"]["results"][0]
        self.assertEqual((bounds["evidence_lower"], bounds["evidence_upper"]), ("0", "1"))
        self.assertEqual((bounds["rf_lower"], bounds["rf_upper"]), ("1/3", "11/18"))
        self.assertEqual(record["state"], "PREPARADO")
        self.assertEqual(record["p8"], "NO-GO")
        self.assertIsNone(record["confirmed_rf"])
        self.assertFalse(record["execution_authorized"])
        self.assertFalse(record["experimental_admission"])
        self.assertFalse(record["draft"]["support_semantics_verified"])

    def test_recovery_and_conflict(self):
        record, _ = self.call()
        self.assertEqual(self.call(reopen=True), (record, "DEV_ASSESSMENT_REOPENED"))
        self.assertEqual(self.call(), (record, "DEV_ASSESSMENT_REOPENED"))
        self.entry["ratings"]["impact"]["ordinal"] = 4
        self.save()
        with self.assertRaises(ValueError):
            self.call()

    def test_binding_and_pin(self):
        with self.assertRaises(ValueError):
            self.call(input_pin="f" * 64)
        self.entry["case_sha256"] = "c" * 64
        self.save()
        with self.assertRaises(ValueError):
            self.call()

    def test_support_tamper(self):
        self.call()
        put(self.inputs / (self.support_pin + ".bin"), b"changed")
        with self.assertRaises(ValueError):
            self.call(reopen=True)

    def test_bad_ordinal_and_missing_support(self):
        self.entry["ratings"]["impact"]["ordinal"] = True
        self.save()
        with self.assertRaises(ValueError):
            self.call()
        (self.inputs / (self.support_pin + ".bin")).unlink()
        with self.assertRaises(OSError):
            self.call()

    def test_cli_normal(self):
        args = ["--origen", str(self.origin), "--archivo", str(self.archive),
                "--id", self.case_id, "--sha256", self.pin,
                "--valoracion", str(self.inputs), "--sha256-valoracion", self.input_pin, "--json"]
        outputs = []
        for action in ("valorar-dev", "reabrir-valoracion-dev"):
            result = subprocess.run([sys.executable, "-m", "ardrec", "caso", action, *args],
                                    capture_output=True, check=True)
            outputs.append(json.loads(result.stdout))
        self.assertEqual(outputs[0], outputs[1])
