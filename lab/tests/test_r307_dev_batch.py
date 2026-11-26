"""R307: multi-case documentary integration, synthetic fixtures only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from unittest.mock import patch

from ardrec.coordination import r166_case_archive_cli as cli
from ardrec.coordination.r115_dev_admission_contract import canonical
from ardrec.experiments import initial_assessment as a2


def put(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return hashlib.sha256(data).hexdigest()


@unittest.skipIf(os.geteuid() == 0, "non-root contract")
class DevBatchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.archive = self.root / "archive"
        self.archive.mkdir(mode=0o700)
        self.manifest = self.root / "batch.json"
        self.rows = []
        self.ordinals = {}
        for index, protocol in enumerate(("SSH", "FTP", "SMB"), 1):
            self.add_case(index, protocol)
        self.save()

    def add_case(self, index, protocol):
        case_id = "DEV-" + format(index, "032x")
        origin = self.root / (str(index) + "-source")
        inputs = self.root / (str(index) + "-input")
        inputs.mkdir(mode=0o700)
        a2.materialize_case(origin, protocol, "b" * 40, {"fixture": "TEST_ONLY", "index": index})
        pin = hashlib.sha256((origin / "scenario.json").read_bytes()).hexdigest()
        case, _ = cli.development_case(origin=origin, archive=self.archive,
                                       case_id=case_id, scenario_pin=pin)
        support = ("Synthetic ordinal inputs, case " + str(index)).encode()
        support_pin = hashlib.sha256(support).hexdigest()
        put(inputs / (support_pin + ".bin"), support)
        values = (1, 1 + index % 5, 1 + (index + 1) % 5, 2, 3, 5)
        self.ordinals[case_id] = values
        doc = dict(schema="ARDREC-R303-DEV-ASSESSMENT-INPUT-v1", case_id=case_id,
                   case_sha256=case["sha256"], ratings={key: dict(ordinal=val,
                       support_sha256=support_pin, justification="Synthetic test, not a measured condition.")
                       for key, val in zip(a2.DIMENSIONS, values)})
        input_pin = put(inputs / "ratings.json", canonical(doc))
        self.rows.append(dict(case_id=case_id, origin=str(origin), inputs=str(inputs),
                              scenario_pin=pin, input_pin=input_pin))

    def save(self):
        self.pin = put(self.manifest, canonical(dict(schema="ARDREC-R307-DEV-BATCH-v1", cases=self.rows)))

    def call(self, **kwargs):
        args = dict(manifest=self.manifest, manifest_pin=self.pin, archive=self.archive)
        args.update(kwargs)
        return cli.development_batch(**args)

    def files(self):
        return {str(p.relative_to(self.archive)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.archive.rglob("*") if p.is_file()}

    def assert_no_assessment(self):
        self.assertFalse(list(self.archive.glob("*.assessment.json")))
        self.assertFalse(list(self.archive.glob("*.analytical")))

    def test_three_protocols_native_reconciliation_and_math_oracle(self):
        result = self.call()
        self.assertEqual(result["case_count"], 3)
        self.assertEqual(result["references"], 21)
        self.assertEqual({r["protocol"] for r in result["cases"]}, {"SSH", "FTP", "SMB"})
        for row in result["cases"]:
            x, p, i, *ctx = self.ordinals[row["case_id"]]
            r0 = Fraction(x + p + i - 3, 12)
            c = Fraction(max(sorted(ctx)[1], max(ctx) - 1) - 1, 4)
            self.assertEqual(row["initial_risk_candidate"], str(r0))
            self.assertEqual(row["criticality_candidate"], str(c))
            self.assertEqual(row["rf_hypothetical"]["rf_lower"], str(r0))
            self.assertEqual(row["rf_hypothetical"]["rf_upper"], str(max(r0, (r0 + 1 + c) / 3)))
            self.assertEqual(row["state"], "PREPARADO")
            self.assertEqual(row["a6"], "ND")
            self.assertIsNone(row["confirmed_rf"])
            self.assertIsNone(row["a8"]["applied_transition"])
        self.assertEqual(result["a3_authority"], "ND")
        self.assertIsNone(result["a4_selected"])
        self.assertEqual(result["a5_attempts"], 0)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["operational_a9_published"])
        self.assertFalse(result["experimental_admission"])
        self.assertEqual(result["experimental_observations"], 0)
        self.assertEqual(result["p8"], "NO-GO")

    def test_reopen_and_idempotence_preserve_bytes(self):
        first = self.call()
        before = self.files()
        self.assertEqual(first, self.call(reopen=True))
        self.assertEqual(first, self.call())
        self.assertEqual(before, self.files())

    def test_full_preflight_rejects_last_input_before_writing(self):
        self.rows[-1]["input_pin"] = "0" * 64
        self.save()
        with self.assertRaises(ValueError):
            self.call()
        self.assert_no_assessment()

    def test_duplicate_identity_and_cross_paths(self):
        original = self.rows[-1].copy()
        self.rows[-1]["case_id"] = self.rows[0]["case_id"]
        self.save()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_OR_INVALID"):
            self.call()
        self.rows[-1] = original
        self.rows[-1]["inputs"] = self.rows[0]["inputs"]
        self.save()
        with self.assertRaisesRegex(ValueError, "PATH_OVERLAP"):
            self.call()
        self.assert_no_assessment()

    def test_manifest_pin_and_private_permissions(self):
        with self.assertRaisesRegex(ValueError, "PIN_INVALID"):
            self.call(manifest_pin="0" * 64)
        self.manifest.chmod(0o644)
        with self.assertRaises(ValueError):
            self.call()
        self.assert_no_assessment()

    def test_reopen_missing_is_read_only(self):
        before = self.files()
        with self.assertRaises(OSError):
            self.call(reopen=True)
        self.assertEqual(before, self.files())

    def test_tampered_support_refuses_entire_batch(self):
        self.call()
        support = next(Path(self.rows[-1]["inputs"]).glob("*.bin"))
        put(support, b"tampered")
        before = self.files()
        for reopen in (False, True):
            with self.assertRaises(ValueError):
                self.call(reopen=reopen)
        self.assertEqual(before, self.files())

    def test_interruption_then_resume(self):
        actual = cli.development_snapshot
        blocked = self.rows[1]["case_id"]
        def stop(**kwargs):
            if kwargs["case_id"] == blocked:
                raise OSError("synthetic interruption")
            return actual(**kwargs)
        with patch.object(cli, "development_snapshot", side_effect=stop):
            with self.assertRaises(OSError):
                self.call()
        self.assertTrue((self.archive / (self.rows[0]["case_id"] + ".snapshot.json")).exists())
        self.assertFalse((self.archive / (blocked + ".snapshot.json")).exists())
        result = self.call()
        self.assertEqual(result, self.call(reopen=True))

    def test_canonical_cli_text_and_json(self):
        args = ["--manifiesto", str(self.manifest), "--sha256", self.pin,
                "--archivo", str(self.archive)]
        docs = []
        for action in ("preparar-lote-dev", "reabrir-lote-dev"):
            p = subprocess.run([sys.executable, "-m", "ardrec", "caso", action, *args, "--json"],
                               capture_output=True, check=True)
            docs.append(json.loads(p.stdout))
        self.assertEqual(docs[0], docs[1])
        p = subprocess.run([sys.executable, "-m", "ardrec", "caso", "reabrir-lote-dev", *args, "--texto"],
                           capture_output=True, check=True)
        self.assertIn(b"A3=ND | A4=NONE | A5=0 | A6=ND", p.stdout)

    def test_54_synthetic_documentary_cases(self):
        for index in range(4, 55):
            self.add_case(index, ("SSH", "FTP", "SMB")[(index - 1) % 3])
        self.save()
        result = self.call()
        self.assertEqual(result["case_count"], 54)
        self.assertEqual(result["references"], 378)
        self.assertEqual(result["experimental_observations"], 0)
        self.assertEqual(result, self.call(reopen=True))
        self.rows.append(self.rows[-1])
        self.save()
        with self.assertRaisesRegex(ValueError, "SCHEMA_INVALID"):
            self.call()
