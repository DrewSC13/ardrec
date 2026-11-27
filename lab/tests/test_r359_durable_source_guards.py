"""R359 tests using real native persistence and synthetic messages."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
import tempfile
import unittest

from ardrec.analytics.exact_preview import digest
from ardrec.coordination import durable_source_guards as engine
from ardrec.persistence import DurableStore
from ardrec.persistence.analytical_archive import AnalyticalArchive
from ardrec.state import Transition, Truth, InvocationPhase

# Reuse existing native persistence fixtures, not a second state model.
unit_tests = str(
    Path(__file__).resolve().parents[2] / "tests/unit"
)

sys.path.insert(0, unit_tests)

try:
    import test_persistence as native
    import test_analytical_counters as native_counters
finally:
    sys.path.remove(unit_tests)


class DurableSourceGuardTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "store"

    def kwargs(self, head):
        return {
            "record_id": "REG-1",
            "configuration_sha256": "a" * 64,
            "expected_head": head,
        }

    def inspect(self, head, **extra):
        return engine.inspect(
            self.path,
            **{**self.kwargs(head), **extra},
        )

    def prepare(self, store):
        native.prepare(store)

    def service(self, report, sid="S01"):
        return next(
            item for item in report["services"]
            if item["service_scenario_id"] == sid
        )

    def test_01_initial_native_recovery(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            head = store.head_sha256

        result = self.inspect(head)

        self.assertEqual(result["generation"], 0)
        self.assertEqual(len(result["services"]), 2)
        self.assertEqual(
            self.service(result)["confirmed_phase"],
            "PREPARADO",
        )
        self.assertFalse(result["dispatch_allowed"])
        self.assertEqual(
            result["external_operational_authority"], "ND"
        )

    def test_02_stale_head_rejected(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            old_head = store.head_sha256
            self.prepare(store)

        with self.assertRaises(ValueError):
            self.inspect(old_head)

    def test_03_wrong_context_rejected(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            head = store.head_sha256

        for changes in (
            {"record_id": "FOREIGN"},
            {"configuration_sha256": "b" * 64},
            {"expected_head": None},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.inspect(head, **changes)

    def test_04_reserved_attempt_is_not_execution(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            self.prepare(store)
            native.reserve(store)
            head = store.head_sha256

        result = self.inspect(head)

        self.assertEqual(result["pending_attempts"], ["ATT-1"])
        self.assertEqual(result["incorporated_execution_count"], 0)
        self.assertEqual(result["journal_quiescence"], "FALSO")
        self.assertEqual(
            self.service(result)["execution_counters"]["cases"],
            [],
        )

    def test_05_received_result_not_incorporated(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            self.prepare(store)
            native.reserve(store)

            store.report(
                "ATT-1",
                deepcopy(native.FIXTURES["result_completed"]),
            )

            head = store.head_sha256

        result = self.inspect(head)

        self.assertEqual(result["incorporated_execution_count"], 0)
        self.assertEqual(result["pending_attempts"], ["ATT-1"])
        self.assertIsNone(result["confirmed_rf"])

    def test_06_incorporated_start_counted_once(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            self.prepare(store)
            native.reserve(store)
            native.outcome(store)

            store.publish(
                expected_generation=1,
                reference="GEN-2",
                event="PUB-2",
            )

            head = store.head_sha256

        result = self.inspect(head)

        self.assertEqual(result["incorporated_execution_count"], 1)
        self.assertEqual(
            self.service(result)["incorporated_case_executions"],
            1,
        )
        self.assertEqual(
            self.service(result, "S02")[
                "incorporated_case_executions"
            ],
            0,
        )
        self.assertFalse(result["dispatch_allowed"])

    def test_07_verified_non_start_remains_zero(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            self.prepare(store)
            native.reserve(store)
            native.outcome(store, no_start=True)

            store.publish(
                expected_generation=1,
                reference="GEN-2",
                event="PUB-2",
            )

            head = store.head_sha256

        result = self.inspect(head)

        case = self.service(result)["execution_counters"]["cases"][0]

        self.assertEqual(case["confirmed_executions"], 0)
        self.assertEqual(
            case["receipts"][0]["start_status"],
            "NO_INICIADO",
        )

    def test_08_candidate_not_promoted(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            store.transition(
                "S01",
                Transition.PREPARAR,
                native.context(store, Transition.PREPARAR),
            )

            head = store.head_sha256

        result = self.inspect(head)

        row = self.service(result)

        self.assertTrue(result["candidate_present"])
        self.assertEqual(row["confirmed_phase"], "PREPARADO")
        self.assertEqual(row["candidate_phase"], "PENDIENTE")
        self.assertEqual(result["generation"], 0)
        self.assertEqual(result["journal_quiescence"], "FALSO")

    def test_09_ended_invocation_blocks_gate(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            store.finish(
                InvocationPhase.DETENIDA,
                "SYNTHETIC-STOP",
            )

            head = store.head_sha256

        result = self.inspect(head)

        self.assertEqual(result["invocation"], "DETENIDA")
        self.assertEqual(result["journal_quiescence"], "FALSO")
        self.assertFalse(result["dispatch_allowed"])

    def test_10_anchored_archive_and_counter_scope(self):
        archive_path = self.root / "archive"

        with AnalyticalArchive(
            archive_path, create=True
        ) as archive:

            snapshot = native_counters.snapshot(
                archive,
                replace(
                    native.INITIAL,
                    authority=Truth.VERDADERO,
                ),
            )

            with DurableStore.create(
                self.path,
                native.INITIAL,
                analytical_archive=archive,
                snapshot_sha256=snapshot,
                validate_counters=True,
            ) as store:
                head = store.head_sha256

        result = self.inspect(
            head,
            archive_path=archive_path,
            expected_snapshot=snapshot,
        )

        self.assertEqual(
            result["snapshot_validation"],
            "execution_counters_v1",
        )

        self.assertFalse(
            result["snapshot_full_semantics_accredited"]
        )

        with self.assertRaises(ValueError):
            self.inspect(
                head,
                archive_path=archive_path,
                expected_snapshot="b" * 64,
            )

    def test_11_rehashed_guard_forgery_rejected(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            head = store.head_sha256

        result = self.inspect(head)

        result["dispatch_allowed"] = True
        result.pop("sha256")
        result["sha256"] = digest(result)

        with self.assertRaisesRegex(
            ValueError,
            "DURABLE_DIAGNOSTIC_REPLAY_MISMATCH",
        ):
            engine.verify(
                result,
                result["sha256"],
                self.path,
                **self.kwargs(head),
            )

    def test_12_replay_preserves_durable_bytes(self):
        with DurableStore.create(
            self.path, native.INITIAL
        ) as store:
            self.prepare(store)
            head = store.head_sha256

        def contents():
            return {
                str(path.relative_to(self.path)):
                    path.read_bytes()
                for path in self.path.rglob("*")
                if path.is_file()
            }

        before = contents()

        first = self.inspect(head)
        second = self.inspect(head)

        self.assertEqual(first, second)

        self.assertTrue(
            engine.verify(
                first,
                first["sha256"],
                self.path,
                **self.kwargs(head),
            )
        )

        self.assertEqual(contents(), before)
        self.assertEqual(first["p8"], "NO-GO")


if __name__ == "__main__":
    unittest.main()
