"""R262: exact A4 and missing-data regressions."""

import copy
import unittest

from ardrec.coordination import (
    prospective_local_pilot as durable,
)

from ardrec.selection import (
    prospective_priority as engine,
)


class PriorityTests(unittest.TestCase):

    def candidate(self, index, **overrides):

        row = {
            "service_id": "SSH_PILOT",
            "case_id": "CASE_" + str(index),
            "protocol": "SSH",
            "family_id": "SSH-T06",
            "instance_id": "INSTANCE_" + str(index),
            "phase": "PENDIENTE",
            "guard": "VERDADERO",
            "applicable": True,
            "baseline_closed": True,
            "precedence": index,
            "initial_risk": "1/2",
            "evidence": "1/4",
            "criticality": "0",
            "source_preparation_sha256": "a" * 64,
        }

        row.update(overrides)

        return row

    def source(self, candidates):

        return durable.seal({
            "schema": engine.INPUT_SCHEMA,
            "scope": "PROSPECTIVE_REVIEW_ONLY",
            "candidates": candidates,
            "operational_authority": False,
            "formal_pilot_admitted": 0,
            "experimental_admitted": 0,
            "p7": "DRAFT_NOT_FROZEN",
            "p8": "NO-GO",
        })

    def evaluate(self, *rows):

        source = self.source(list(rows))

        report = engine.build(
            source, source["sha256"]
        )

        self.assertTrue(
            engine.verify(
                report, source, source["sha256"]
            )
        )

        return report

    def test_01_exact_priority(self):

        report = self.evaluate(self.candidate(1))

        self.assertEqual(
            report["selected_preview"]["priority"],
            "1/4",
        )

    def test_02_adaptive_recalculation(self):

        first = self.candidate(1)
        second = self.candidate(2)

        before = self.evaluate(first, second)

        second["evidence"] = "1"

        after = self.evaluate(first, second)

        self.assertEqual(
            before["selected_preview"]["case_id"],
            "CASE_1",
        )

        self.assertEqual(
            after["selected_preview"]["case_id"],
            "CASE_2",
        )

        self.assertEqual(
            after["selected_preview"]["priority"],
            "1/2",
        )

    def test_03_precedence_and_stable_tie(self):

        first = self.candidate(1, precedence=5)
        second = self.candidate(2, precedence=1)

        report = self.evaluate(first, second)

        self.assertEqual(
            report["selected_preview"]["case_id"],
            "CASE_2",
        )

        first["precedence"] = 1

        report = self.evaluate(second, first)

        self.assertEqual(
            report["selected_preview"]["case_id"],
            "CASE_1",
        )

    def test_04_unknown_eligible_priority_blocks(self):

        report = self.evaluate(
            self.candidate(1),
            self.candidate(2, evidence=None),
        )

        self.assertEqual(
            report["status"],
            "ELIGIBLE_PRIORITY_UNRESOLVED",
        )

        self.assertIsNone(
            report["selected_preview"]
        )

        self.assertIsNone(
            report["native_selection"]
        )

    def test_05_unknown_ineligible_does_not_block(self):

        report = self.evaluate(
            self.candidate(1),
            self.candidate(
                2, phase="PREPARADO",
                initial_risk=None,
                evidence=None,
                criticality=None,
            ),
        )

        self.assertEqual(
            report["selected_preview"]["case_id"],
            "CASE_1",
        )

    def test_06_guard_and_baseline(self):

        report = self.evaluate(
            self.candidate(1, guard="ND"),
            self.candidate(
                2, baseline_closed=False
            ),
            self.candidate(
                3, applicable=None
            ),
        )

        self.assertEqual(
            report["eligible_count"], 0
        )

        self.assertIsNone(
            report["selected_preview"]
        )

    def test_07_terminal_cases_excluded(self):

        report = self.evaluate(
            self.candidate(1, phase="CERRADO"),
            self.candidate(2, phase="DETENIDO"),
            self.candidate(3, phase="PAUSADO"),
        )

        self.assertEqual(
            report["eligible_count"], 0
        )

    def test_08_duplicate_rejected(self):

        with self.assertRaisesRegex(
            ValueError, "DUPLICATE_CANDIDATE"
        ):
            self.evaluate(
                self.candidate(1),
                self.candidate(1),
            )

    def test_09_changed_source_rejected(self):

        source = self.source([
            self.candidate(1)
        ])

        changed = copy.deepcopy(source)

        changed["candidates"][0]["evidence"] = "1"

        with self.assertRaises(ValueError):

            engine.build(
                changed, source["sha256"]
            )

    def test_10_no_operational_promotion(self):

        report = self.evaluate(
            self.candidate(1)
        )

        self.assertIsNotNone(
            report["selected_preview"]
        )

        self.assertIsNone(
            report["confirmed_operational_selection"]
        )

        self.assertFalse(
            report["operational_dispatch"]
        )

        self.assertEqual(
            report["a5_attempts_started"], 0
        )

        self.assertEqual(
            report["experimental_admitted"], 0
        )

        self.assertEqual(
            report["p8"], "NO-GO"
        )


if __name__ == "__main__":
    unittest.main()
