"""Recuperación de consultas sin reejecución ni confirmaciones parciales."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ardrec.messages import MessageError, decode_message, encode_message
from ardrec.persistence import DurableStore, StorageError
from ardrec.reconciliation import (
    QUERY, REPLY, ReconciliationError, begin_query, complete_query,
    fail_query, inspect_recovery,
)
from ardrec.state import InvocationPhase, StateError, Transition
from test_persistence import FIXTURES, INITIAL, context, prepare, reopen, reserve

STAMP = "2026-10-19T12:00:02Z"
POINTS = tuple("journal:" + p for p in ("created", "partial", "written", "synced", "installed", "durable")) + (
    "head:created", "head:partial", "head:written", "head:synced", "head:before_replace",
    "head:replaced", "head:durable", "commit:acknowledge",
)


def query(store, number=1, limit=3):
    return begin_query(store, message_id=f"QUERY-{number}", created_at=STAMP, limit=limit)


def reply(raw, phase="completed", *, full=True, result=None):
    q = decode_message(raw)
    message = deepcopy(FIXTURES["status_" + phase])
    for field in ("record_id", "execution_id", "correlation_id", "decision_index", "scope",
                  "service_scenario_id", "derived_case_id", "attempt_id", "versions", "simulation"):
        message[field] = q[field]
    message["message_id"] = "R-" + q["message_id"]
    message["created_at"] = STAMP
    message["payload"]["query_reference"] = q["message_id"]
    message["payload"]["request_reference"] = q["payload"]["request_reference"]
    message["payload"]["snapshot"]["observed_at"] = STAMP
    if phase in {"completed", "interrupted"}:
        result = deepcopy(result if result is not None else FIXTURES["result_" + phase])
        message["payload"]["snapshot"]["result"]["reference"] = result["message_id"]
        return encode_message(message), encode_message(result) if full else None
    return encode_message(message), None


CHILD = '''
import os, signal, sys
from test_reconciliation import *
path, point, operation = sys.argv[1:]
def crash(current):
    if current == point: os.kill(os.getpid(), signal.SIGKILL)
with reopen(path, fault=crash) as store:
    if operation == "query": query(store)
    else:
        raw = store.reconciliation_history[-1]["query"]
        response, result = reply(raw)
        complete_query(store, raw, response, result=result)
raise RuntimeError("No se alcanzó la interrupción")
'''


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ardrec-reconcile-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "store"
        self.store = DurableStore.create(self.path, INITIAL)
        self.addCleanup(self.store.close)
        prepare(self.store)
        reserve(self.store)

    def recover(self):
        self.store.close()
        self.store = reopen(self.path)
        self.addCleanup(self.store.close)
        return self.store

    def complete(self, raw, phase="completed", **kwargs):
        response, result = reply(raw, phase, **kwargs)
        return complete_query(self.store, raw, response, result=result)

    def unchanged_on_error(self, action):
        before = self.store.head_sha256
        with self.assertRaises((ReconciliationError, MessageError, StateError, StorageError)):
            action()
        self.assertEqual(self.store.head_sha256, before)

    def test_query_is_durable_before_return(self):
        old = self.store.head_sha256
        raw = query(self.store)
        self.assertNotEqual(old, self.store.head_sha256)
        message = decode_message(raw)
        self.assertEqual(message["message_type"], "attempt_status_request")
        self.assertEqual(message["attempt_id"], "ATT-1")
        self.assertEqual(message["payload"]["request_reference"], "REQ-1")
        recovered = inspect_recovery(self.recover())
        self.assertEqual((recovered.action, recovered.queries_used, recovered.open_query), ("QUERY_INCOMPLETE", 1, raw))
        self.assertFalse(recovered.new_execution_authorized)

    def test_read_only_inspection(self):
        before = self.store.head_sha256
        self.assertEqual(inspect_recovery(self.store).action, "QUERY_REQUIRED")
        self.assertEqual(self.store.head_sha256, before)

    def test_open_query_blocks_new_queries_and_publication(self):
        query(self.store)
        self.unchanged_on_error(lambda: query(self.store, 2))
        self.unchanged_on_error(lambda: self.store.publish(expected_generation=1, reference="GEN-2", event="PUB-2"))
        self.unchanged_on_error(lambda: self.store.transition("S01", Transition.ACREDITAR_INICIO,
                                                             context(self.store, Transition.ACREDITAR_INICIO)))

    def test_timeout_preserves_intention_and_count(self):
        raw = query(self.store)
        original = self.store.state.attempts[0].request
        result = fail_query(self.store, raw, failure="TIMEOUT")
        self.assertEqual(result.action, "QUERY_REQUIRED")
        self.recover()
        self.assertEqual(self.store.state.attempts[0].request, original)
        self.assertEqual(self.store.state.pending_attempts, ("ATT-1",))
        self.assertEqual(self.store.state.incorporated_execution_count, 0)
        self.assertEqual(inspect_recovery(self.store).queries_used, 1)

    def test_budget_survives_restarts_and_cannot_increase(self):
        for number in (1, 2):
            raw = query(self.store, number, limit=2)
            fail_query(self.store, raw, failure="CONNECTION_LOST")
            self.recover()
        self.assertEqual(inspect_recovery(self.store).action, "BUDGET_EXHAUSTED")
        self.unchanged_on_error(lambda: query(self.store, 3, limit=3))
        self.assertEqual(self.store.state.pending_attempts, ("ATT-1",))

    def test_limit_change_before_exhaustion_rejected(self):
        raw = query(self.store, limit=3)
        fail_query(self.store, raw, failure="TIMEOUT")
        self.unchanged_on_error(lambda: query(self.store, 2, limit=4))

    def test_invalid_limits_and_timestamp(self):
        for limit in (True, False, 0, -1, 1001, 3.0, "3", None):
            self.unchanged_on_error(lambda: query(self.store, limit=limit))
        self.unchanged_on_error(lambda: begin_query(self.store, message_id="Q", created_at="2000-01-01T00:00:00Z"))

    def test_complete_result_is_atomic_and_not_incorporated(self):
        raw = query(self.store)
        decision = self.complete(raw)
        self.assertEqual(decision.action, "READY_FOR_VALIDATION")
        self.assertEqual(decision.result, encode_message(FIXTURES["result_completed"]))
        self.recover()
        self.assertEqual(inspect_recovery(self.store), decision)
        self.assertEqual(self.store.state.confirmed.generation, 1)
        self.assertEqual(self.store.state.incorporated_execution_count, 0)
        self.assertEqual(self.store.state.pending_attempts, ("ATT-1",))

    def test_status_without_result_remains_uncertain(self):
        raw = query(self.store)
        self.assertEqual(self.complete(raw, full=False).action, "RESULT_REQUIRED")
        self.recover()
        self.assertFalse(self.store.state.attempts[0].technical_resolved)
        self.unchanged_on_error(lambda: self.store.publish(expected_generation=1, reference="GEN-2", event="PUB-2"))
        second = query(self.store, 2)
        self.assertEqual(self.complete(second).action, "READY_FOR_VALIDATION")

    def test_old_result_can_be_recovered_after_later_status(self):
        raw = query(self.store)
        self.complete(raw, full=False)
        self.recover()
        second = query(self.store, 2)
        result = self.complete(second).result
        self.assertEqual(decode_message(result)["created_at"], "2026-10-19T12:00:01Z")

    def test_interrupted_result_never_becomes_success(self):
        raw = query(self.store)
        decision = self.complete(raw, "interrupted")
        self.assertEqual(decision.action, "READY_FOR_VALIDATION")
        self.assertEqual(self.store.state.attempts[0].snapshot["phase"], "interrupted")

    def test_no_start_requires_snapshot_not_rejection(self):
        raw = query(self.store)
        decision = self.complete(raw, "not_started")
        self.assertEqual(decision.action, "READY_FOR_VALIDATION")
        self.assertIsNone(decision.result)
        self.assertEqual(self.store.state.incorporated_execution_count, 0)

    def test_query_rejection_preserves_uncertainty(self):
        raw = query(self.store)
        q = decode_message(raw)
        rejection = deepcopy(FIXTURES["rejection"])
        rejection["created_at"] = STAMP
        rejection["payload"].update(rejected_message_id=q["message_id"],
                                    rejected_message_type=q["message_type"],
                                    rejected_sha256=hashlib.sha256(raw).hexdigest())
        decision = complete_query(self.store, raw, encode_message(rejection))
        self.assertEqual(decision.action, "QUERY_REQUIRED")
        self.assertIsNone(self.store.state.attempts[0].snapshot)
        self.recover()
        self.assertIsNotNone(self.store.state.attempts[0].uncertainty_reference)

    def test_running_then_connection_loss_preserves_start(self):
        first = query(self.store)
        self.complete(first, "running")
        second = query(self.store, 2)
        fail_query(self.store, second, failure="CONNECTION_LOST")
        self.recover()
        self.assertEqual(self.store.state.attempts[0].snapshot["start"]["status"], "VERIFICADO")

    def test_accepted_and_uncertain_stay_blocked(self):
        for number, phase in enumerate(("accepted", "uncertain"), 1):
            raw = query(self.store, number)
            self.assertEqual(self.complete(raw, phase).action, "QUERY_REQUIRED")
            self.assertFalse(self.store.state.attempts[0].technical_resolved)
            self.assertIn("attempt_pending_incorporation", self.store.state.dispatch_blockers)

    def test_malformed_input_keeps_query_open(self):
        raw = query(self.store)
        for response in (b"{", b"{}", b"\xff", b'{"a":1,"a":2}', "wrong", None):
            self.unchanged_on_error(lambda: complete_query(self.store, raw, response))
        self.assertEqual(inspect_recovery(self.store).action, "QUERY_INCOMPLETE")
        fail_query(self.store, raw, failure="INVALID_RESPONSE")

    def test_cross_identity_version_and_query_rejected(self):
        raw = query(self.store)
        response, result = reply(raw)
        for field, value in (("record_id", "OTHER"), ("attempt_id", "OTHER"),
                             ("schema_version", "9.0"), ("simulation", True), ("decision_index", 2)):
            changed = decode_message(response)
            changed[field] = value
            self.unchanged_on_error(lambda: complete_query(self.store, raw, encode_message(changed), result=result))
        changed = decode_message(response)
        changed["payload"]["query_reference"] = "OTHER"
        self.unchanged_on_error(lambda: complete_query(self.store, raw, encode_message(changed), result=result))

    def test_result_fact_reference_and_time_conflicts(self):
        raw = query(self.store)
        response, result = reply(raw)
        for field in ("start", "termination", "cleanup"):
            changed = decode_message(result)
            changed["payload"]["snapshot"][field]["reference"] = "OTHER"
            self.unchanged_on_error(lambda: complete_query(self.store, raw, response, result=encode_message(changed)))
        changed = decode_message(result)
        changed["created_at"] = "2026-10-19T13:00:00Z"
        self.unchanged_on_error(lambda: complete_query(self.store, raw, response, result=encode_message(changed)))

    def test_duplicate_completion_is_noop_after_recovery(self):
        raw = query(self.store)
        response, result = reply(raw)
        complete_query(self.store, raw, response, result=result)
        self.recover()
        before = self.store.head_sha256
        complete_query(self.store, raw, response, result=result)
        self.assertEqual(self.store.head_sha256, before)
        self.assertEqual(inspect_recovery(self.store).queries_used, 1)

    def test_conflicting_duplicate_is_rejected(self):
        raw = query(self.store)
        self.complete(raw)
        self.unchanged_on_error(lambda: fail_query(self.store, raw, failure="TIMEOUT"))

    def test_old_duplicate_does_not_clear_new_uncertainty(self):
        raw = query(self.store)
        response, result = reply(raw, "running")
        complete_query(self.store, raw, response)
        newer = query(self.store, 2)
        fail_query(self.store, newer, failure="TIMEOUT")
        before = self.store.head_sha256
        complete_query(self.store, raw, response)
        self.assertEqual(self.store.head_sha256, before)
        self.assertIsNotNone(self.store.state.attempts[0].uncertainty_reference)

    def test_open_query_can_be_abandoned_after_restart(self):
        raw = query(self.store)
        self.recover()
        fail_query(self.store, raw, failure="ABANDONED")
        self.assertEqual(inspect_recovery(self.store).queries_used, 1)
        self.assertEqual(inspect_recovery(self.store).action, "QUERY_REQUIRED")

    def test_query_identifiers_cannot_be_reused(self):
        self.unchanged_on_error(lambda: begin_query(self.store, message_id="REQ-1", created_at=STAMP))
        raw = query(self.store)
        fail_query(self.store, raw, failure="TIMEOUT")
        self.unchanged_on_error(lambda: query(self.store))

    def test_unknown_query_and_invalid_failure_rejected(self):
        raw = encode_message(FIXTURES["query"])
        self.unchanged_on_error(lambda: fail_query(self.store, raw, failure="TIMEOUT"))
        raw = query(self.store)
        for failure in (True, {}, "SPAWN_FAILED", None):
            self.unchanged_on_error(lambda: fail_query(self.store, raw, failure=failure))

    def test_history_copies_cannot_change_authority(self):
        query(self.store)
        entry = self.store.reconciliation_history[0]
        entry["limit"] = 1000
        entry["query"] = b"changed"
        self.assertEqual(inspect_recovery(self.store).query_limit, 3)
        self.recover()
        self.assertEqual(inspect_recovery(self.store).query_limit, 3)

    def test_invocation_stop_retains_query_and_reservation(self):
        query(self.store)
        before = self.store.state.confirmed
        self.store.finish(InvocationPhase.DETENIDA, "CONCILIACION-AGOTADA")
        self.recover()
        self.assertEqual(inspect_recovery(self.store).action, "INVOCATION_ENDED")
        self.assertEqual(self.store.state.confirmed, before)
        self.assertEqual(self.store.state.pending_attempts, ("ATT-1",))

    def test_exact_result_values_survive_recovery(self):
        raw = query(self.store)
        result = deepcopy(FIXTURES["result_completed"])
        result["payload"]["outcome"]["duration_ms"] = 2**53 + 1
        self.complete(raw, result=result)
        self.recover()
        recovered = decode_message(inspect_recovery(self.store).result)
        self.assertEqual(recovered["payload"]["outcome"]["duration_ms"], 2**53 + 1)

    def test_resolved_attempt_needs_no_query(self):
        self.store.report("ATT-1", deepcopy(FIXTURES["result_completed"]))
        self.assertEqual(inspect_recovery(self.store).action, "READY_FOR_VALIDATION")
        self.unchanged_on_error(lambda: query(self.store))

    def test_discovery_uses_same_durable_protocol(self):
        self.store.close()
        path = Path(self.temporary.name) / "discovery"
        with DurableStore.create(path, INITIAL) as store:
            request = deepcopy(FIXTURES["discovery_request"])
            request["decision_index"] = 0
            store.reserve(request, decision_reference="DISC-DEC")
            raw = query(store)
            result = deepcopy(FIXTURES["discovery_result"])
            result["decision_index"] = 0
            response, _ = reply(raw)
            response = decode_message(response)
            response["payload"]["snapshot"] = deepcopy(result["payload"]["snapshot"])
            response["payload"]["snapshot"]["observed_at"] = STAMP
            decision = complete_query(store, raw, encode_message(response), result=encode_message(result))
            self.assertEqual(decision.action, "READY_FOR_VALIDATION")
            self.assertEqual(store.state.confirmed.generation, 0)

    def test_new_result_identity_cannot_change_after_cleanup(self):
        raw = query(self.store)
        response, result = reply(raw)
        response = decode_message(response)
        result = decode_message(result)
        for obj in (response, result):
            obj["payload"]["snapshot"]["cleanup"] = {"status": "pending", "reference": None}
            obj["payload"]["snapshot"]["reconciliation_required"] = True
        complete_query(self.store, raw, encode_message(response), result=encode_message(result))
        raw = query(self.store, 2)
        changed = deepcopy(result)
        changed["payload"]["outcome"]["exit_code"] = 17
        response, _ = reply(raw)
        self.unchanged_on_error(lambda: complete_query(self.store, raw, response, result=encode_message(changed)))
        complete_query(self.store, raw, response, result=encode_message(result))
        self.assertEqual(inspect_recovery(self.store).action, "READY_FOR_VALIDATION")

    def test_sync_failure_after_pointer_requires_recovery(self):
        self.store.close()
        def fail(point):
            if point == "head:replaced":
                raise OSError("Fallo inyectado después de sustituir HEAD")
        with reopen(self.path, fault=fail) as store:
            with self.assertRaises(OSError): query(store)
            with self.assertRaises(StorageError): inspect_recovery(store)
        self.recover()
        self.assertEqual(inspect_recovery(self.store).action, "QUERY_INCOMPLETE")
        self.assertEqual(inspect_recovery(self.store).queries_used, 1)

    def test_result_identifier_cannot_become_query(self):
        raw = query(self.store)
        response, result = reply(raw)
        response, result = decode_message(response), decode_message(result)
        for obj in (response, result):
            obj["payload"]["snapshot"]["cleanup"] = {"status": "pending", "reference": None}
            obj["payload"]["snapshot"]["reconciliation_required"] = True
        complete_query(self.store, raw, encode_message(response), result=encode_message(result))
        self.unchanged_on_error(lambda: begin_query(self.store, message_id=result["message_id"], created_at=STAMP))

    def test_interruption_reason_must_match(self):
        raw = query(self.store)
        response, result = reply(raw, "interrupted")
        response = decode_message(response)
        original = response["payload"]["snapshot"]["reason_code"]
        response["payload"]["snapshot"]["reason_code"] = "EXECUTOR_FAILURE" if original != "EXECUTOR_FAILURE" else "INTERRUPTED"
        self.unchanged_on_error(lambda: complete_query(self.store, raw, encode_message(response), result=result))

    def test_no_network_or_tool_launch(self):
        with patch("subprocess.Popen", side_effect=AssertionError("Ejecución no permitida")), \
             patch("socket.socket", side_effect=AssertionError("Red no permitida")):
            raw = query(self.store)
            self.complete(raw)
            self.assertEqual(inspect_recovery(self.store).action, "READY_FOR_VALIDATION")

    def test_28_sigkill_boundaries(self):
        self.store.close()
        root = Path(__file__).resolve().parents[2]
        env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(root / "src"), str(root / "tests/unit"))),
                   PYTHONDONTWRITEBYTECODE="1")
        for operation in ("query", "reply"):
            for index, point in enumerate(POINTS):
                with self.subTest(operation=operation, point=point):
                    path = Path(self.temporary.name) / f"crash-{operation}-{index}"
                    with DurableStore.create(path, INITIAL) as store:
                        prepare(store)
                        reserve(store)
                        if operation == "reply": query(store)
                    child = subprocess.run([sys.executable, "-c", CHILD, str(path), point, operation],
                                           env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(child.returncode, -signal.SIGKILL, child.stdout + child.stderr)
                    published = point in {"head:replaced", "head:durable", "commit:acknowledge"}
                    for _ in range(2):
                        with reopen(path) as store:
                            decision = inspect_recovery(store)
                            expected = (("QUERY_INCOMPLETE" if published else "QUERY_REQUIRED") if operation == "query"
                                        else ("READY_FOR_VALIDATION" if published else "QUERY_INCOMPLETE"))
                            self.assertEqual(decision.action, expected)
                            self.assertEqual(decision.queries_used, int(operation == "reply" or published))
                            self.assertEqual(store.state.confirmed.generation, 1)
                            self.assertEqual(store.state.incorporated_execution_count, 0)
                            self.assertEqual(store.state.pending_attempts, ("ATT-1",))
                            if operation == "reply": self.assertEqual(decision.result is not None, published)


if __name__ == "__main__":
    unittest.main()
