import unittest

from ardrec.experiments import prospective_research_review as m


RATINGS = {
    "exposure": 1,
    "probability": 2,
    "impact": 2,
    "operational_importance": 2,
    "data_sensitivity": 1,
    "dependencies": 1,
}


class ResearchReviewTests(unittest.TestCase):

    def test_exact_candidate_interval(self):

        for protocol in m.PROTOCOLS:

            values, bridge = m.calculate(
                protocol, RATINGS
            )

            self.assertEqual(
                values["initial_risk"], "1/6"
            )

            result = bridge["a7"]["results"][0]

            self.assertEqual(result["rf_lower"], "1/6")
            self.assertEqual(result["rf_upper"], "7/18")

    def test_unknown_never_promoted(self):

        _, bridge = m.calculate("FTP", RATINGS)

        self.assertTrue(bridge["all_a6_nd"])
        self.assertIsNone(bridge["confirmed_final_risk"])
        self.assertIsNone(bridge["published_generation"])

    def test_invalid_ratings(self):

        for value in (None, True, 0, 6):

            with self.assertRaises(ValueError):

                m.calculate("SSH", {
                    **RATINGS,
                    "probability": value,
                })

    def test_unsupported_protocol(self):

        with self.assertRaises(ValueError):

            m.calculate("OTHER", RATINGS)


if __name__ == "__main__":
    unittest.main()
