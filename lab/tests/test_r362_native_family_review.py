"""R362: family catalogue, source-bound support roles and review."""

from copy import deepcopy
from unittest.mock import patch
import unittest

from ardrec.analytics.exact_preview import digest
from ardrec.evidence import native_family_review as engine

import test_r361_native_support_integrity as fixtures


class NativeFamilyReviewTests(unittest.TestCase):

    def setUp(self):

        self.fixture = fixtures.NativeSupportIntegrityTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

        self.specs = engine.family_catalog()
        self.spec = self.specs[("SSH-T01", None)]

        self.required = self.spec["required_supports"]
        self.case = "SSH-T01-S01-01"

    def prepare(self, complete=False):

        f = self.fixture

        f.catalog["bindings"][0]["derived_case_id"] = self.case

        request = deepcopy(
            fixtures.native.FIXTURES["request"]
        )

        result = deepcopy(
            fixtures.native.FIXTURES["result_completed"]
        )

        request["derived_case_id"] = self.case
        result["derived_case_id"] = self.case

        refs = [
            "SUP-" + str(index + 1)
            for index in range(len(self.required))
        ]

        result["payload"]["outcome"]["supports"] = refs

        with patch.dict(fixtures.native.FIXTURES, {
            "request": request,
            "result_completed": result,
        }):
            f.prepare()

        roles = {}

        for ref, role in zip(refs, self.required):

            roles[ref] = role

            if complete or ref == refs[0]:

                f.add(
                    reference=ref,
                    raw=("fixture-" + ref).encode(),
                )

        self.plan = {
            "schema": engine.PLAN_SCHEMA,
            "provenance_sha256": f.source["sha256"],
            "manifest_sha256": digest(f.manifest),
            "attempts": [{
                "attempt_id": "ATT-1",
                "family_id": "SSH-T01",
                "variant": None,
                "assessment_index": 0,
                "support_roles": roles,
                "initial_risk": "1/2",
                "normalized_criticality": "1/2",
            }],
        }

    def kwargs(self):

        return {
            "plan": self.plan,
            "expected_plan_sha256": digest(self.plan),
            "support_kwargs": self.fixture.kwargs(),
        }

    def build(self):

        return engine.build(
            self.fixture.store,
            **self.kwargs(),
        )

    def test_01_all_families_and_variants(self):

        self.assertEqual(len(self.specs), 29)

        self.assertEqual(
            len({key[0] for key in self.specs}), 25
        )

        self.assertEqual(
            {
                protocol: sum(
                    row["protocol"] == protocol
                    for row in self.specs.values()
                )
                for protocol in ("ssh", "ftp", "smb")
            },
            {"ssh": 8, "ftp": 10, "smb": 11},
        )

    def test_02_all_29_rule_previews_reused(self):

        for index, (key, spec) in enumerate(self.specs.items()):

            with self.subTest(key=key):

                fid = spec["family_id"]

                result = engine.preview_family(
                    spec,
                    fid + "-S01-01",
                    "DEV-R362",
                    index,
                    spec["required_supports"],
                )

                self.assertEqual(result["a6"], "ND")
                self.assertEqual(result["guard"], "ND")

    def test_03_ftp_variants_separated(self):

        control = self.specs[("FTP-T02", "CONTROL")]
        data = self.specs[("FTP-T02", "DATA")]

        self.assertNotIn(
            "CONTROL_DATA_CORRELATION",
            control["required_supports"],
        )

        self.assertIn(
            "CONTROL_DATA_CORRELATION",
            data["required_supports"],
        )

    def test_04_smb_variants_separated(self):

        signing = self.specs[("SMB-T03", "SIGNING")]
        encryption = self.specs[("SMB-T03", "ENCRYPTION")]

        self.assertIn("SMB_SIGNATURE", signing["required_supports"])
        self.assertNotIn("SMB_ENCRYPTION", signing["required_supports"])

        self.assertIn("SMB_ENCRYPTION", encryption["required_supports"])
        self.assertNotIn("SMB_SIGNATURE", encryption["required_supports"])

    def test_05_cleanup_requirements(self):

        for fid in ("FTP-T08", "SMB-T09"):

            with self.subTest(fid=fid):

                read = self.specs[(fid, "READ")]
                write = self.specs[(fid, "WRITE")]

                self.assertFalse(read["cleanup_required"])
                self.assertTrue(write["cleanup_required"])

                self.assertIn(
                    "CLEANUP_CONFIRMED",
                    write["required_supports"],
                )

    def test_06_partial_material_coverage(self):

        self.prepare()

        result = self.build()
        row = result["attempts"][0]

        self.assertEqual(row["required_supports_bytes_verified"], 1)

        self.assertEqual(
            row["required_material_coverage"],
            "PARTIAL",
        )

        self.assertEqual(
            row["required_semantic_supports_accredited"],
            0,
        )

    def test_07_complete_bytes_not_technical_truth(self):

        self.prepare(complete=True)

        result = self.build()
        row = result["attempts"][0]

        self.assertEqual(
            row["required_material_coverage"],
            "COMPLETE",
        )

        self.assertEqual(
            row["acceptance_material_coverage"],
            "COMPLETE",
        )

        self.assertEqual(row["a6"], "ND")
        self.assertEqual(result["technical_conditions_accredited"], 0)
        self.assertIsNone(row["confirmed_rf"])

        for support in row["support_roles"]:
            self.assertEqual(support["semantic_truth"], "ND")

    def test_08_foreign_family_variant_or_attempt(self):

        self.prepare()

        original = deepcopy(self.plan)

        for field, value in (
            ("family_id", "FTP-T01"),
            ("family_id", "SSH-T02"),
            ("variant", "WRITE"),
            ("attempt_id", "FOREIGN"),
        ):

            with self.subTest(field=field, value=value):

                self.plan = deepcopy(original)
                self.plan["attempts"][0][field] = value

                with self.assertRaises(ValueError):
                    self.build()

    def test_09_invalid_role_associations(self):

        self.prepare()

        original = deepcopy(self.plan)

        for mapping in (
            {"FOREIGN": self.required[0]},
            {"SUP-1": "NOT_A_ROLE"},
            {
                "SUP-1": self.required[0],
                "SUP-2": self.required[0],
            },
        ):

            with self.subTest(mapping=mapping):

                self.plan = deepcopy(original)

                self.plan["attempts"][0]["support_roles"] = mapping

                with self.assertRaises(ValueError):
                    self.build()

    def test_10_same_bytes_cannot_fill_two_roles(self):

        self.prepare(complete=True)

        first, second = self.fixture.manifest["entries"][:2]

        second["support_sha256"] = first["support_sha256"]
        second["byte_count"] = first["byte_count"]

        self.plan["manifest_sha256"] = digest(
            self.fixture.manifest
        )

        with self.assertRaisesRegex(
            ValueError,
            "SAME_BYTES_REUSED_ACROSS_ROLES",
        ):
            self.build()

    def test_11_uncertainty_and_stop_preserved(self):

        self.prepare(complete=True)

        result = self.build()
        row = result["attempts"][0]

        interval = row["hypothetical_interval"]

        self.assertEqual(interval["evidence_lower"], "0")
        self.assertEqual(interval["evidence_upper"], "1")
        self.assertFalse(interval["point_identified"])

        self.assertFalse(row["baseline_accredited"])
        self.assertFalse(row["downward_replacement_applied"])

        self.assertEqual(
            row["a8"]["recommendation"],
            "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA",
        )

        self.assertIsNone(row["a8"]["applied_transition"])

        self.assertFalse(result["operational_dispatch"])
        self.assertIsNone(result["published_generation"])
        self.assertEqual(result["p8"], "NO-GO")

    def test_12_source_pins_inventory_and_replay(self):

        self.prepare(complete=True)

        report = self.build()

        self.assertTrue(engine.verify(
            report,
            report["sha256"],
            self.fixture.store,
            **self.kwargs(),
        ))

        altered = deepcopy(report)
        altered["attempts"][0]["a6"] = "POSITIVO_VALIDO"
        altered.pop("sha256")
        altered["sha256"] = digest(altered)

        with self.assertRaisesRegex(
            ValueError,
            "FAMILY_REPORT_REPLAY_MISMATCH",
        ):
            engine.verify(
                altered,
                altered["sha256"],
                self.fixture.store,
                **self.kwargs(),
            )

        original = deepcopy(self.plan)

        self.plan["attempts"] = []

        with self.assertRaisesRegex(
            ValueError,
            "FAMILY_PLAN_INVENTORY_INCOMPLETE",
        ):
            self.build()

        self.plan = original

        kwargs = self.kwargs()
        kwargs["expected_plan_sha256"] = "f" * 64

        with self.assertRaisesRegex(
            ValueError,
            "FAMILY_PLAN_PIN_MISMATCH",
        ):
            engine.build(self.fixture.store, **kwargs)


if __name__ == "__main__":
    unittest.main()
