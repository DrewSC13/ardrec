"""Synthetic I4 support integrity regression."""

import copy
import tempfile
import unittest

from pathlib import Path

from ardrec.experiments import (
    reference_rubric as rubric,
    reference_supports as m,
    r148_paired_register as r148,
)


class ReferenceSupportTests(unittest.TestCase):

    def setUp(self):

        self.raw = b"synthetic technical support\n"

        self.digest = m.sha(self.raw)

        def record(value):

            return {
                "value": value,
                "supports": ["SYNTHETIC-SUPPORT"],
                "reason": "Synthetic test only",
            }

        self.document = {
            "unit_id": "SYNTHETIC-I4-01",
            "protocol": "SSH",
            "common_checks": {
                key: record("COMPLETE")
                for key in rubric.COMMON_CHECKS
            },
            "facts": {
                "exposure": record("PRESENT"),
                "access_controls": record("EFFECTIVE"),
                "capability": record("NONE"),
                "confidentiality": record("NONE"),
                "integrity": record("NONE"),
                "availability": record("NONE"),
                "context": record("NONE"),
            },
        }

        self.manifest = m.manifest_template(self.document)

        self.manifest["bindings"]["SYNTHETIC-SUPPORT"] = (
            self.digest
        )

        self.objects = {self.digest: self.raw}

    def verify(self, **overrides):

        args = {
            "document": self.document,
            "manifest": self.manifest,
            "objects": self.objects,
            "expected_document_sha256": rubric.digest(
                rubric.normalize(self.document)
            ),
            "expected_manifest_sha256": m.sha(
                r148.canonical(self.manifest)
            ),
        }

        args.update(overrides)

        return m.evaluate(**args)

    def test_01_native_reference_reused(self):

        report = self.verify()

        self.assertEqual(
            report["reference_report"],
            rubric.evaluate(self.document),
        )

        self.assertEqual(
            report["reference_report"]["candidate_reference_score"],
            "0.25",
        )

        self.assertEqual(report["unique_objects_verified"], 1)
        self.assertEqual(report["object_bytes_verified"], len(self.raw))

    def test_02_modified_original_rejected(self):

        self.objects[self.digest] += b"modified"

        with self.assertRaisesRegex(
            ValueError, "OBJECT_DIGEST_MISMATCH"
        ):
            self.verify()

    def test_03_missing_object_rejected(self):

        with self.assertRaisesRegex(
            ValueError, "OBJECT_SET_MISMATCH"
        ):
            self.verify(objects={})

    def test_04_extra_binding_rejected(self):

        self.manifest["bindings"]["EXTRA"] = self.digest

        with self.assertRaisesRegex(
            ValueError, "SUPPORT_SET_MISMATCH"
        ):
            self.verify()

    def test_05_document_pin_mismatch(self):

        with self.assertRaisesRegex(
            ValueError, "REFERENCE_INPUT_PIN_MISMATCH"
        ):
            self.verify(expected_document_sha256="0"*64)

    def test_06_cross_unit_binding_rejected(self):

        self.manifest["unit_id"] = "OTHER-UNIT"

        with self.assertRaisesRegex(
            ValueError, "MANIFEST_UNIT_BINDING_INVALID"
        ):
            self.verify()

    def test_07_unresolved_support_stays_nd(self):

        original = copy.deepcopy(self.document)

        original["common_checks"][
            "CE08_FINAL_STATE_RESTORATION"
        ] = {
            "value": "ND",
            "supports": [],
            "reason": "Restoration not verified",
        }

        manifest = m.manifest_template(original)

        manifest["bindings"]["SYNTHETIC-SUPPORT"] = (
            self.digest
        )

        report = self.verify(
            document=original,
            manifest=manifest,
            expected_document_sha256=rubric.digest(
                rubric.normalize(original)
            ),
            expected_manifest_sha256=m.sha(
                r148.canonical(manifest)
            ),
        )

        self.assertIsNone(
            report["reference_report"]["candidate_reference_score"]
        )

        self.assertFalse(report["experimental_admission"])

    def test_08_file_readback_and_no_authority(self):

        with tempfile.TemporaryDirectory() as temporary:

            root = Path(temporary)

            objects = root / "objects"
            objects.mkdir(mode=0o700)

            document = root / "input.json"
            manifest = root / "manifest.json"
            payload = objects / self.digest

            for path, raw in (
                (document, r148.canonical(self.document)),
                (manifest, r148.canonical(self.manifest)),
                (payload, self.raw),
            ):

                path.write_bytes(raw)
                path.chmod(0o600)

            report = m.from_files(
                document,
                manifest,
                objects,
                expected_document_sha256=rubric.digest(
                    rubric.normalize(self.document)
                ),
                expected_manifest_sha256=m.sha(
                    r148.canonical(self.manifest)
                ),
            )

            self.assertEqual(report, self.verify())

            self.assertFalse(
                report["support_semantics_authenticated"]
            )

            self.assertFalse(
                report["independent_human_review_attested"]
            )

            self.assertFalse(
                report["a6_operational_accreditation"]
            )

            self.assertIsNone(report["confirmed_reference_score"])
            self.assertEqual(report["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
