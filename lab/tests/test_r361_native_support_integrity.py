"""R361: real filesystem verification with synthetic native receipts."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from ardrec.analytics.exact_preview import digest
from ardrec.evidence import native_evidence_provenance as provenance
from ardrec.evidence import native_support_integrity as engine
from ardrec.persistence import DurableStore
from ardrec.state import Transition

import test_r360_native_evidence_provenance as previous

native = previous.native


class NativeSupportIntegrityTests(unittest.TestCase):

    def setUp(self):

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        self.root = Path(tmp.name)
        self.store = self.root / "store"
        self.supports = self.root / "supports"

        self.supports.mkdir(mode=0o700)

        self.catalog = {
            "schema": provenance.CATALOG_SCHEMA,
            "record_id": "REG-1",
            "execution_id": "EXE-1",
            "configuration_sha256": "a" * 64,
            "bindings": [{
                "service_scenario_id": "S01",
                "derived_case_id": "CASE-1",
                "condition_id": "COND-1",
                "profile_reference": "PROFILE-1",
                "parameters_reference": "PARAM-1",
            }],
        }

    def prepare(self, pending=False, two=False):

        with DurableStore.create(
            self.store,
            native.INITIAL,
        ) as store:

            native.prepare(store)
            native.reserve(store)

            if not pending:

                message = deepcopy(
                    native.FIXTURES["result_completed"]
                )

                if two:

                    message["payload"]["outcome"]["supports"] = [
                        "SUP-1",
                        "SUP-2",
                    ]

                store.report("ATT-1", message)

                for step in (
                    Transition.ACREDITAR_INICIO,
                    Transition.VALIDAR_RESULTADO,
                    Transition.APLICAR_RESULTADO,
                    Transition.CONTINUAR,
                ):

                    store.transition(
                        "S01",
                        step,
                        native.context(store, step),
                    )

                store.publish(
                    expected_generation=1,
                    reference="GEN-2",
                    event="PUB-2",
                )

            head = store.head_sha256

        self.source_kwargs = {
            "catalog": self.catalog,
            "expected_catalog_sha256":
                digest(self.catalog),
            "expected_head": head,
        }

        self.source = provenance.build(
            self.store,
            **self.source_kwargs,
        )

        self.expected = engine.expected_supports(
            self.source
        )

        self.manifest = {
            "schema": engine.MANIFEST_SCHEMA,
            "provenance_sha256":
                self.source["sha256"],
            "entries": [],
        }

    def add(self, reference="SUP-1", raw=b"synthetic support"):

        pin = hashlib.sha256(raw).hexdigest()

        path = self.supports / (pin + ".bin")
        path.write_bytes(raw)
        path.chmod(0o600)

        self.manifest["entries"].append({
            **self.expected[("ATT-1", reference)],
            "support_sha256": pin,
            "byte_count": len(raw),
        })

        return path

    def kwargs(self):

        return {
            "support_root": self.supports,
            "manifest": self.manifest,
            "expected_manifest_sha256":
                digest(self.manifest),
            "provenance_kwargs": self.source_kwargs,
        }

    def build(self):

        return engine.build(
            self.store,
            **self.kwargs(),
        )

    def test_01_complete_actual_bytes(self):

        self.prepare()
        self.add()

        report = self.build()

        self.assertEqual(report["verified_supports"], 1)
        self.assertEqual(report["declared_supports"], 1)
        self.assertEqual(
            report["documentary_coverage"],
            "COMPLETE",
        )

        self.assertEqual(
            report["conditions"][0]["documentary_coverage"],
            "COMPLETE",
        )

        self.assertEqual(
            report["verified_logical_bytes"],
            len(b"synthetic support"),
        )

        self.assertEqual(report["a6"], "ND")
        self.assertFalse(report["technical_truth_accredited"])

    def test_02_partial_declared_coverage(self):

        self.prepare(two=True)
        self.add()

        report = self.build()

        self.assertEqual(report["verified_supports"], 1)
        self.assertEqual(report["declared_supports"], 2)
        self.assertEqual(
            report["documentary_coverage"], "PARTIAL"
        )

        self.assertEqual(
            report["conditions"][0]["documentary_coverage"],
            "PARTIAL",
        )

    def test_03_missing_manifest_entry(self):

        self.prepare()

        report = self.build()

        self.assertEqual(report["verified_supports"], 0)
        self.assertEqual(
            report["supports"][0]["status"],
            "MANIFEST_ENTRY_MISSING",
        )
        self.assertEqual(
            report["documentary_coverage"], "ABSENT"
        )

    def test_04_missing_support_file(self):

        self.prepare()
        path = self.add()

        path.unlink()

        report = self.build()

        self.assertEqual(
            report["supports"][0]["status"],
            "SUPPORT_FILE_MISSING",
        )
        self.assertEqual(report["verified_supports"], 0)

    def test_05_altered_support_rejected(self):

        self.prepare()
        path = self.add(raw=b"abcd")

        path.write_bytes(b"wxyz")

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_HASH_MISMATCH"
        ):
            self.build()

    def test_06_size_and_type_rejected(self):

        self.prepare()
        self.add(raw=b"abcd")

        for size in (True, -1, 5, engine.MAX_SUPPORT_BYTES + 1):

            with self.subTest(size=size):

                self.manifest["entries"][0]["byte_count"] = size

                with self.assertRaises(ValueError):
                    self.build()

    def test_07_foreign_receipt_binding_rejected(self):

        self.prepare()
        self.add()

        original = deepcopy(self.manifest)

        for field, value in (
            ("attempt_id", "FOREIGN"),
            ("condition_id", "FOREIGN"),
            ("derived_case_id", "FOREIGN"),
            ("service_scenario_id", "S02"),
            ("request_sha256", "f" * 64),
            ("report_sha256", "f" * 64),
            ("incorporation_event", "OTHER"),
            ("incorporation_generation", 1),
            ("effective_parameters_reference", "OTHER"),
            ("support_reference", "FOREIGN"),
        ):

            with self.subTest(field=field):

                self.manifest = deepcopy(original)

                self.manifest["entries"][0][field] = value

                with self.assertRaises(ValueError):
                    self.build()

    def test_08_duplicate_and_invalid_pins(self):

        self.prepare()
        self.add()

        original = deepcopy(self.manifest)

        self.manifest["entries"].append(
            deepcopy(self.manifest["entries"][0])
        )

        with self.assertRaisesRegex(
            ValueError, "DUPLICATE_SUPPORT_ENTRY"
        ):
            self.build()

        self.manifest = original

        kwargs = self.kwargs()
        kwargs["expected_manifest_sha256"] = "f" * 64

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_MANIFEST_PIN_MISMATCH"
        ):
            engine.build(self.store, **kwargs)

        self.manifest["provenance_sha256"] = "f" * 64

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_PROVENANCE_PIN_MISMATCH"
        ):
            self.build()

    def test_09_symbolic_links_rejected(self):

        self.prepare()
        path = self.add()

        external = self.root / "external"
        path.rename(external)

        path.symlink_to(external)

        with self.assertRaises((ValueError, OSError)):
            self.build()

        path.unlink()
        external.rename(path)

        moved = self.root / "moved"
        self.supports.rename(moved)
        self.supports.symlink_to(moved, target_is_directory=True)

        with self.assertRaises((ValueError, OSError)):
            self.build()

    def test_10_hardlink_fifo_and_permissions_rejected(self):

        self.prepare()
        path = self.add()

        raw = path.read_bytes()

        path.chmod(0o644)

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_FILE_METADATA_INVALID"
        ):
            self.build()

        path.chmod(0o600)

        external = self.root / "hardlink"
        os.link(path, external)

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_FILE_METADATA_INVALID"
        ):
            self.build()

        external.unlink()
        path.unlink()

        os.mkfifo(path, 0o600)

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_FILE_METADATA_INVALID"
        ):
            self.build()

        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o600)

        self.supports.chmod(0o755)

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_ROOT_NOT_PRIVATE"
        ):
            self.build()

        self.supports.chmod(0o700)

    def test_11_pending_attempt_cannot_admit_support(self):

        self.prepare(pending=True)

        report = self.build()

        self.assertEqual(report["declared_supports"], 0)
        self.assertEqual(report["verified_supports"], 0)

        row = self.source["attempts"][0]

        self.manifest["entries"].append({
            **{
                key: row[key]
                for key in engine.IDENTITY_FIELDS
            },
            "support_reference": "SUP-1",
            "support_sha256": "a" * 64,
            "byte_count": 4,
        })

        with self.assertRaisesRegex(
            ValueError, "FOREIGN_OR_UNDECLARED_SUPPORT"
        ):
            self.build()

    def test_12_replay_nonpromotion_and_storage_preservation(self):

        self.prepare()
        self.add()

        def contents():

            return {
                str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob("*")
                if p.is_file()
            }

        before = contents()

        report = self.build()

        self.assertTrue(
            engine.verify(
                report,
                report["sha256"],
                self.store,
                **self.kwargs(),
            )
        )

        self.assertEqual(report["technical_conditions_accredited"], 0)
        self.assertIsNone(report["confirmed_rf"])
        self.assertFalse(report["operational_dispatch"])

        altered = deepcopy(report)

        altered["conditions"][0]["classification"] = (
            "POSITIVO_VALIDO"
        )

        altered.pop("sha256")
        altered["sha256"] = digest(altered)

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_REPORT_REPLAY_MISMATCH"
        ):

            engine.verify(
                altered,
                altered["sha256"],
                self.store,
                **self.kwargs(),
            )

        self.assertEqual(before, contents())
        self.assertEqual(report["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
