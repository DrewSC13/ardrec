"""Pruebas de I4 con hechos declarados sinteticos."""
import copy
import unittest

from ardrec.experiments import reference_rubric as m


def record(value, name="DEV_SUPPORT"):

    return {
        "value": value,
        "supports": [name],
        "reason": "Synthetic test fixture",
    }


def fixture(
    exposure="NONE",
    controls="EFFECTIVE",
    capability="NONE",
    severity="NONE",
):

    values = {
        "exposure": exposure,
        "access_controls": controls,
        "capability": capability,
        "confidentiality": severity,
        "integrity": "NONE",
        "availability": "NONE",
        "context": "NONE",
    }

    return {
        "unit_id": "DEV_RUBRIC_001",
        "protocol": "SSH",
        "common_checks": {
            key: record("COMPLETE", key)
            for key in m.COMMON_CHECKS
        },
        "facts": {
            key: record(value, key)
            for key, value in values.items()
        },
    }


class ReferenceRubricTests(unittest.TestCase):

    def test_five_levels(self):

        cases = (
            (fixture(), 0, "0.00"),
            (
                fixture("LIMITED"),
                1,
                "0.25",
            ),
            (
                fixture(
                    "PRESENT",
                    "WEAK",
                    "VERIFIED_WEAKNESS",
                    "LIMITED",
                ),
                2,
                "0.50",
            ),
            (
                fixture(
                    "PRESENT",
                    "FAILED",
                    "VERIFIED_UNAUTHORIZED_CAPABILITY",
                    "RELEVANT",
                ),
                3,
                "0.75",
            ),
            (
                fixture(
                    "PRESENT",
                    "FAILED",
                    "VERIFIED_UNAUTHORIZED_CAPABILITY",
                    "GRAVE",
                ),
                4,
                "1.00",
            ),
        )

        for document, level, score in cases:

            with self.subTest(level=level):

                result = m.evaluate(document)

                self.assertEqual(result["level"], level)

                self.assertEqual(
                    result["candidate_reference_score"],
                    score,
                )

    def test_missing_common_evidence(self):

        for key in m.COMMON_CHECKS:

            document = fixture()
            document["common_checks"][key] = record("ND")

            result = m.evaluate(document)

            self.assertIsNone(
                result["candidate_reference_score"]
            )

            self.assertEqual(
                result["decision_reason"],
                "COMMON_EVIDENCE_INCOMPLETE",
            )

    def test_nd_is_not_zero(self):

        document = fixture()
        document["facts"]["integrity"] = record("ND")

        result = m.evaluate(document)

        self.assertEqual(result["classification"], "ND")
        self.assertIsNone(result["candidate_reference_score"])

    def test_na_handling(self):

        document = fixture()
        document["facts"]["integrity"] = record("NA")

        self.assertEqual(m.evaluate(document)["level"], 0)

        for key in m.IMPACTS:
            document["facts"][key] = record("NA")

        self.assertIsNone(m.evaluate(document)["level"])

    def test_contradictions(self):

        documents = (
            fixture(
                "NONE",
                "FAILED",
                "VERIFIED_UNAUTHORIZED_CAPABILITY",
                "GRAVE",
            ),
            fixture(
                "PRESENT",
                "EFFECTIVE",
                "VERIFIED_UNAUTHORIZED_CAPABILITY",
                "RELEVANT",
            ),
            fixture(
                "PRESENT",
                "WEAK",
                "NONE",
                "LIMITED",
            ),
        )

        for document in documents:

            self.assertIsNone(m.evaluate(document)["level"])

    def test_ambiguous_relevant_consequence(self):

        document = fixture(
            "PRESENT",
            "WEAK",
            "VERIFIED_WEAKNESS",
            "RELEVANT",
        )

        self.assertIsNone(m.evaluate(document)["level"])

    def test_method_output_rejected(self):

        for key in (
            "R0", "Rf", "PA", "ardrec_score", "Rref"
        ):

            document = fixture()
            document[key] = "0.75"

            with self.assertRaises(ValueError):
                m.evaluate(document)

    def test_support_required(self):

        document = fixture()

        document["facts"]["exposure"]["supports"] = []

        with self.assertRaises(ValueError):
            m.evaluate(document)

    def test_invalid_facts(self):

        document = fixture()

        document["facts"]["exposure"]["value"] = "NA"

        with self.assertRaises(ValueError):
            m.evaluate(document)

    def test_all_protocols(self):

        for protocol in ("SSH", "FTP", "SMB"):

            document = fixture()
            document["protocol"] = protocol

            result = m.evaluate(document)

            self.assertEqual(result["protocol"], protocol)
            self.assertEqual(result["level"], 0)

    def test_replay_and_mutation(self):

        document = fixture()
        original = m.evaluate(document)

        self.assertTrue(m.verify(document, original))

        reordered = dict(reversed(list(document.items())))

        self.assertEqual(
            m.evaluate(reordered),
            original,
        )

        modified = copy.deepcopy(original)
        modified["experimental_admission"] = True

        with self.assertRaises(ValueError):
            m.verify(document, modified)

    def test_no_authority_promotion(self):

        report = m.evaluate(fixture())

        self.assertIsNone(
            report["confirmed_reference_score"]
        )

        self.assertFalse(
            report["experimental_admission"]
        )

        self.assertFalse(report["rubric_frozen"])
        self.assertFalse(report["method_outputs_used"])

        self.assertFalse(
            report["external_validation_claimed"]
        )

        self.assertEqual(report["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
