"""Exact ordinary closure and convergence regression tests."""

import unittest

from ardrec.stopping import ordinary_closure as a8


def event(index, risk, *, reset=False, projection=None):

    return {
        "event_id": "EVENT-" + str(index),
        "projection_sha256": (
            projection
            if projection is not None
            else f"{index:064x}"
        ),
        "risk": risk,
        "reset": reset,
    }


def evaluate(history=None, executions=0, budget=5,
             phase="ACTUALIZADO", **changes):

    facts = {
        name: "FALSO"
        for name in a8.FACTS
    }

    facts.update({
        "safety_clear": "VERDADERO",
        "attempt_reconciled": "VERDADERO",
        "precedence_resolved": "VERDADERO",
    })

    facts.update(changes)

    return a8.evaluate(
        facts=facts,
        history=[] if history is None else history,
        executions=executions,
        budget=budget,
        phase=phase,
    )


class OrdinaryClosureTests(unittest.TestCase):

    def test_01_evidence_sufficiency(self):

        report = evaluate(
            evidence_current="VERDADERO",
            contradiction_free="VERDADERO",
            maximum_demonstration="VERDADERO",
        )

        self.assertEqual(report["criteria"]["ES"], "VERDADERO")
        self.assertEqual(report["candidate_transition"], "T7")
        self.assertIsNone(report["applied_transition"])

    def test_02_no_remaining_actions(self):

        report = evaluate(
            no_executable_cases="VERDADERO",
            no_potential_cases="VERDADERO",
            no_pending_work="VERDADERO",
        )

        self.assertEqual(report["primary_reason"], "SA")

    def test_03_exact_budget_exhaustion(self):

        report = evaluate(executions=5, budget=5)

        self.assertEqual(report["primary_reason"], "LE")
        self.assertEqual(report["criteria"]["ES"], "FALSO")

    def test_04_all_criteria_and_precedence(self):

        report = evaluate(
            history=[event(i, "1/4") for i in range(1, 5)],
            executions=5,
            budget=5,
            evidence_current="VERDADERO",
            contradiction_free="VERDADERO",
            complete_coverage="VERDADERO",
            no_executable_cases="VERDADERO",
            no_potential_cases="VERDADERO",
            no_pending_work="VERDADERO",
            no_larger_case="VERDADERO",
        )

        self.assertEqual(
            report["criteria_satisfied"],
            ["ES", "SA", "CV", "LE"],
        )

        self.assertEqual(report["primary_reason"], "ES")

    def test_05_three_exact_variations(self):

        risks = [
            "1/2", "501/1000",
            "251/500", "503/1000",
        ]

        result = a8.convergence([
            event(i, risk)
            for i, risk in enumerate(risks, 1)
        ])

        self.assertEqual(
            result["variations"],
            ["1/1000"] * 3,
        )

        self.assertTrue(result["window_stable"])

    def test_06_variation_above_tolerance(self):

        result = a8.convergence([
            event(1, "1/4"),
            event(2, "1/3"),
            event(3, "1/3"),
            event(4, "1/3"),
        ])

        self.assertFalse(result["window_stable"])

    def test_07_duplicates_do_not_create_samples(self):

        first = event(1, "1/4")

        result = a8.convergence([
            first,
            first.copy(),
            event(
                2,
                "1/4",
                projection=first["projection_sha256"],
            ),
        ])

        self.assertEqual(result["duplicate_events"], 1)
        self.assertEqual(result["repeated_projections"], 1)
        self.assertEqual(result["variations"], [])

    def test_08_reset_precedes_update(self):

        history = [
            event(i, "1/4")
            for i in range(1, 5)
        ]

        history.append(
            event(5, "1/3", reset=True)
        )

        result = a8.convergence(history)

        self.assertEqual(result["variations"], [])
        self.assertFalse(result["window_complete"])
        self.assertEqual(result["resets"], 1)

    def test_09_indetermination_not_false(self):

        report = evaluate(
            budget=None,
            no_executable_cases="VERDADERO",
            no_potential_cases="ND",
            no_pending_work="VERDADERO",
        )

        self.assertEqual(report["criteria"]["SA"], "ND")
        self.assertEqual(report["criteria"]["LE"], "ND")
        self.assertEqual(report["ordinary_stop"], "ND")

    def test_10_safety_and_uncertainty_block_closure(self):

        for key in (
            "safety_clear",
            "attempt_reconciled",
            "precedence_resolved",
        ):

            report = evaluate(
                executions=5,
                budget=5,
                **{key: "ND"},
            )

            self.assertIsNone(report["candidate_transition"])

    def test_11_invalid_history_and_budget(self):

        with self.assertRaises(ValueError):
            evaluate(executions=6, budget=5)

        with self.assertRaises(ValueError):
            evaluate(executions=True, budget=5)

        with self.assertRaises(ValueError):
            a8.convergence([
                event(1, "1/4"),
                event(1, "1/3"),
            ])

        with self.assertRaises(ValueError):
            a8.convergence([
                event(1, "1/4"),
                event(
                    2,
                    "1/3",
                    projection=f"{1:064x}",
                ),
            ])

    def test_12_terminal_state_and_replay(self):

        report = evaluate(
            phase="CERRADO",
            executions=5,
            budget=5,
        )

        self.assertIsNone(report["candidate_transition"])
        self.assertTrue(a8.verify(report))

        report["applied_transition"] = "T7"

        with self.assertRaises(ValueError):
            a8.verify(report)


if __name__ == "__main__":
    unittest.main()
