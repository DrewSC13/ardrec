"""R363: semantic content comparison with native durable fixtures."""

from copy import deepcopy
import hashlib
import unittest
from unittest.mock import patch

from ardrec.analytics.exact_preview import canonical, digest
from ardrec.evidence import native_content_review as engine

import test_r362_native_family_review as previous
import test_r361_native_support_integrity as fixtures


class NativeContentReviewTests(unittest.TestCase):

    EXPECTED = b"ARDREC synthetic reference\n"

    def prepare(
        self,
        family_id="SSH-T06",
        *,
        observed=None,
        missing_read=False,
        missing_digest=False,
        contradictory=False,
    ):

        fixture = previous.NativeFamilyReviewTests()

        fixture.setUp()
        self.addCleanup(fixture.doCleanups)

        f = fixture.fixture

        fixture.spec = fixture.specs[(family_id, None)]
        fixture.required = fixture.spec["required_supports"]
        fixture.case = family_id + "-S01-01"

        protocol = fixture.spec["protocol"]

        request = deepcopy(fixtures.native.FIXTURES["request"])

        request["payload"]["protocol"] = protocol
        request["payload"]["port"] = {
            "ssh": 22,
            "ftp": 21,
            "smb": 445,
        }[protocol]

        with patch.dict(
            fixtures.native.FIXTURES,
            {"request": request},
        ):

            fixture.prepare(complete=True)

        # R362's helper defaults its plan to SSH-T01.
        # Keep the selected family bound to this native case.
        fixture.plan["attempts"][0]["family_id"] = family_id

        self.assertEqual(
            f.source["attempts"][0]["derived_case_id"],
            fixture.case,
        )
        self.assertEqual(
            f.source["attempts"][0]["protocol"],
            protocol,
        )

        roles = fixture.plan["attempts"][0]["support_roles"]

        native_attempt = f.source["attempts"][0]

        row = {
            **{
                name: native_attempt[name]
                for name in engine.IDENTITY
                if name != "family_id"
            },
            "family_id": family_id,
        }

        read_ref = next(
            ref for ref, role in roles.items()
            if role == "RESOURCE_READ"
        )

        digest_ref = next(
            ref for ref, role in roles.items()
            if role == "KNOWN_CONTENT_DIGEST"
        )

        body = self.EXPECTED if observed is None else observed

        f.manifest["entries"] = [
            entry for entry in f.manifest["entries"]
            if entry["support_reference"]
                not in {read_ref, digest_ref}
        ]

        if not missing_read:

            f.add(read_ref, body)

        if not missing_digest:

            record = engine.digest_record(
                row,
                hashlib.sha256(body).hexdigest(),
                len(body),
            )

            if contradictory:

                record["observed_content_sha256"] = "f" * 64

            f.add(digest_ref, canonical(record))

        fixture.plan["manifest_sha256"] = digest(f.manifest)

        references = {
            "schema": engine.REFERENCE_SCHEMA,
            "record_id": f.source["record_id"],
            "execution_id": f.source["execution_id"],
            "configuration_sha256":
                f.source["configuration_sha256"],
            "references": [{
                **row,
                "expected_content_sha256":
                    hashlib.sha256(self.EXPECTED).hexdigest(),
                "expected_byte_count": len(self.EXPECTED),
            }],
        }

        return f.store, {
            "references": references,
            "expected_reference_sha256": digest(references),
            "family_kwargs": fixture.kwargs(),
        }

    def test_01_three_protocol_content_matches(self):

        for fid in sorted(engine.FAMILIES):

            with self.subTest(family=fid):

                path, kwargs = self.prepare(fid)
                report = engine.build(path, **kwargs)

                row = report["results"][0]

                self.assertEqual(row["content_review"], "MATCH")
                self.assertTrue(row["digest_record_consistent"])
                self.assertEqual(row["a6"], "ND")
                self.assertEqual(
                    row["technical_condition_truth"], "ND"
                )

    def test_02_verified_content_mismatch(self):

        path, kwargs = self.prepare(
            observed=b"Different synthetic reference\n"
        )

        row = engine.build(path, **kwargs)["results"][0]

        self.assertEqual(row["reference_comparison"], "MISMATCH")
        self.assertEqual(row["content_review"], "MISMATCH")
        self.assertTrue(row["digest_record_consistent"])
        self.assertEqual(row["a6"], "ND")

    def test_03_missing_read_is_unknown(self):

        path, kwargs = self.prepare(missing_read=True)

        row = engine.build(path, **kwargs)["results"][0]

        self.assertEqual(row["reference_comparison"], "ND")
        self.assertEqual(row["content_review"], "INCOMPLETE")
        self.assertIsNone(row["observed_content_sha256"])

    def test_04_missing_digest_is_incomplete(self):

        path, kwargs = self.prepare(missing_digest=True)

        row = engine.build(path, **kwargs)["results"][0]

        self.assertEqual(row["reference_comparison"], "MATCH")
        self.assertEqual(row["content_review"], "INCOMPLETE")
        self.assertIsNone(row["digest_record_consistent"])

    def test_05_verified_bytes_can_contain_contradiction(self):

        path, kwargs = self.prepare(contradictory=True)

        row = engine.build(path, **kwargs)["results"][0]

        self.assertFalse(row["digest_record_consistent"])

        self.assertEqual(
            row["content_review"],
            "CONTRADICTORY_DIGEST_RECORD",
        )

        self.assertEqual(row["a6"], "ND")

    def test_06_reference_pin_and_context(self):

        path, kwargs = self.prepare()

        original = deepcopy(kwargs)

        kwargs["expected_reference_sha256"] = "f" * 64

        with self.assertRaisesRegex(
            ValueError, "CONTENT_REFERENCE_PIN_MISMATCH"
        ):
            engine.build(path, **kwargs)

        for field, value in (
            ("attempt_id", "FOREIGN"),
            ("condition_id", "FOREIGN"),
            ("family_id", "FTP-T06"),
            ("report_sha256", "f" * 64),
            ("incorporation_generation", True),
        ):

            with self.subTest(field=field):

                kwargs = deepcopy(original)
                refs = kwargs["references"]

                refs["references"][0][field] = value
                kwargs["expected_reference_sha256"] = digest(refs)

                with self.assertRaises(ValueError):
                    engine.build(path, **kwargs)

    def test_07_missing_or_duplicate_reference(self):

        path, kwargs = self.prepare()

        baseline = engine.build(path, **kwargs)

        self.assertEqual(
            baseline["results"][0]["content_review"],
            "MATCH",
        )

        original = deepcopy(kwargs)

        for duplicate in (False, True):

            with self.subTest(duplicate=duplicate):

                kwargs = deepcopy(original)
                refs = kwargs["references"]

                refs["references"] = (
                    refs["references"] * 2
                    if duplicate else []
                )

                kwargs["expected_reference_sha256"] = digest(refs)

                expected = (
                    "FOREIGN_OR_DUPLICATE_CONTENT_REFERENCE"
                    if duplicate
                    else "CONTENT_REFERENCE_INVENTORY_INCOMPLETE"
                )

                with self.assertRaisesRegex(
                    ValueError, expected,
                ):
                    engine.build(path, **kwargs)

    def test_08_replay_and_no_operational_promotion(self):

        path, kwargs = self.prepare()

        report = engine.build(path, **kwargs)

        self.assertTrue(engine.verify(
            report, report["sha256"], path, **kwargs
        ))

        self.assertFalse(report["physical_origin_accredited"])
        self.assertFalse(report["operational_dispatch"])
        self.assertEqual(report["technical_conditions_accredited"], 0)
        self.assertEqual(report["experimental_admitted"], 0)
        self.assertIsNone(report["confirmed_rf"])
        self.assertIsNone(report["published_generation"])

        altered = deepcopy(report)

        altered["results"][0]["a6"] = "POSITIVO_VALIDO"
        altered.pop("sha256")
        altered["sha256"] = digest(altered)

        with self.assertRaisesRegex(
            ValueError, "CONTENT_REPORT_REPLAY_MISMATCH"
        ):
            engine.verify(
                altered,
                altered["sha256"],
                path,
                **kwargs,
            )

        self.assertEqual(report["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
