"""Synthetic integration tests, not study observations."""

import copy
import unittest

import test_r228_baseline_preparation as fixtures

from ardrec.coordination import (
    local_evidence_bridge as evidence,
    prospective_local_pilot as durable,
)

from ardrec.coordination.r58e_evidence_risk_bridge import (
    verify_unit_bridge,
)

from ardrec.experiments import (
    prospective_risk_integration as m,
    study_cli,
)


def reseal(document):

    return durable.seal({
        key: value
        for key, value in document.items()
        if key != "sha256"
    })


class IntegrationTests(unittest.TestCase):

    def setUp(self):

        self.fixture = fixtures.BaselineTests()
        self.fixture.setUp()

    def source(self):

        return self.fixture.calculate()

    def test_01_missing_baseline(self):

        result = m.build(self.fixture.build())

        self.assertEqual(
            result["status"],
            "BLOCKED_BASELINE_UNAVAILABLE",
        )

        self.assertIsNone(result["native_bridge"])
        self.assertIsNone(result["candidate_decision"])

    def test_02_native_exact_interval(self):

        result = m.build(self.source())

        row = result["candidate_decision"]

        self.assertEqual(row["candidate_initial_risk"], "1/2")

        self.assertEqual(
            row["candidate_normalized_criticality"],
            "1/2",
        )

        self.assertEqual(row["hypothetical_rf_lower"], "1/2")
        self.assertEqual(row["hypothetical_rf_upper"], "2/3")

    def test_03_unknown_not_zero(self):

        row = m.build(self.source())["candidate_decision"]

        self.assertEqual(row["evidence_lower"], "0")
        self.assertEqual(row["evidence_upper"], "1")

    def test_04_native_bridge_replay(self):

        result = m.build(self.source())

        self.assertTrue(
            verify_unit_bridge(result["native_bridge"])
        )

    def test_05_native_stop_guard(self):

        row = m.build(self.source())["candidate_decision"]

        self.assertEqual(
            row["a8_recommendation"],
            "PAUSAR_HASTA_EVIDENCIA_AUTORIZADA",
        )

        self.assertIsNone(row["applied_transition"])

    def test_06_no_operational_promotion(self):

        result = m.build(self.source())

        self.assertFalse(result["operational_dispatch"])
        self.assertIsNone(result["confirmed_rf"])
        self.assertIsNone(result["published_generation"])
        self.assertIsNone(result["a4_operational_selection"])
        self.assertEqual(result["a5_attempts_started"], 0)
        self.assertEqual(result["experimental_admitted"], 0)
        self.assertEqual(result["p8"], "NO-GO")

    def test_07_exact_replay(self):

        source = self.source()

        first = m.build(source)

        self.assertEqual(first, m.build(source))
        self.assertTrue(m.verify(first, source))

    def test_08_modified_source_refused(self):

        source = self.source()

        source["planned_slots"] = 53

        with self.assertRaises(ValueError):

            m.build(source)

    def test_09_resealed_authority_refused(self):

        source = self.source()

        source["baseline_closed"] = True

        with self.assertRaises(ValueError):

            m.build(reseal(source))

    def test_10_resealed_arithmetic_refused(self):

        source = self.source()

        candidate = source["candidate"]

        candidate["calculated"]["initial_risk"] = "1"

        source["candidate"] = reseal(candidate)

        with self.assertRaisesRegex(
            ValueError,
            "BASELINE_ARITHMETIC_MISMATCH",
        ):

            m.build(reseal(source))

    def test_11_candidate_slot_mismatch(self):

        source = self.source()

        candidate = source["candidate"]

        candidate["slot_id"] = "FTP-01"

        source["candidate"] = reseal(candidate)

        with self.assertRaisesRegex(
            ValueError,
            "CANDIDATE_SLOT_BINDING_INVALID",
        ):

            m.build(reseal(source))

    def test_12_modified_risk_report_refused(self):

        source = self.source()
        result = m.build(source)

        result["confirmed_rf"] = "1/2"

        with self.assertRaises(ValueError):

            m.verify(reseal(result), source)

    def test_13_original_source_unchanged(self):

        source = self.source()
        original = copy.deepcopy(source)

        result = m.build(source)

        self.assertEqual(source, original)
        self.assertTrue(evidence.verify_digest(result))

    def test_14_cli_requires_i2(self):

        with self.assertRaises(SystemExit) as context:

            study_cli.main([
                "--registro", "unused",
                "--revisar-riesgo",
                "--json",
            ])

        self.assertEqual(context.exception.code, 2)

    def test_15_identity_mapping_explicit(self):

        row = m.build(self.source())["candidate_decision"]

        self.assertEqual(
            row["identity_mapping"],
            "MATHEMATICAL_SURROGATE_ONLY",
        )

        self.assertNotEqual(
            row["case_id"],
            row["native_dev_identity"]["case_id"],
        )


if __name__ == "__main__":
    unittest.main()
