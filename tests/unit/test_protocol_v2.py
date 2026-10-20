"""Contrastar perfiles, correlaciones y contradicciones sin ejecutar herramientas."""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import unittest

from ardrec.messages import (
    MessageError, compare_delivery, correlate, correlate_status,
    decode_message, encode_message, validate_message,
)
from ardrec.messages_v2 import ERROR_CODES, PRODUCERS
from ardrec.transport import MAX_FRAME_BYTES, read_frame, write_frame

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "fixtures/messages-v2.json").read_text(encoding="utf-8"))
LEGACY = json.loads((ROOT / "fixtures/messages.json").read_text(encoding="utf-8"))


class ProtocolV2Tests(unittest.TestCase):
    """Comprobar contratos y límites semánticos del protocolo 2.0."""

    def setUp(self):
        self.data = deepcopy(FIXTURES)

    def reject(self, value, code="schema_invalid"):
        with self.assertRaises(MessageError) as caught:
            validate_message(value)
        self.assertEqual(caught.exception.code, code)

    def test_all_message_types_and_frame_round_trips(self):
        self.assertEqual({m["message_type"] for m in self.data.values()}, set(PRODUCERS))
        for name, message in self.data.items():
            with self.subTest(name=name):
                raw = encode_message(message)
                stream = io.BytesIO()
                write_frame(stream, raw.decode("utf-8"))
                stream.seek(0)
                self.assertEqual(decode_message(read_frame(stream).encode()), message)
                self.assertEqual(encode_message(decode_message(raw)), raw)
        self.assertEqual(self.data, FIXTURES)

    def test_required_and_unknown_fields_at_every_object(self):
        def objects(value, path=()):
            if type(value) is dict:
                yield path, value
                for key, child in value.items():
                    yield from objects(child, (*path, key))
        for name, message in self.data.items():
            for path, obj in objects(message):
                for key in [*obj, None]:
                    bad = deepcopy(message)
                    target = bad
                    for part in path:
                        target = target[part]
                    if key is None:
                        target["unexpected"] = True
                    else:
                        del target[key]
                    with self.subTest(name=name, path=path, key=key):
                        self.reject(bad)

    def test_scalar_types_do_not_escape_as_type_errors(self):
        for path in [("message_type",), ("scope",), ("producer",),
                     ("payload", "snapshot", "phase"),
                     ("payload", "snapshot", "start", "status")]:
            for value in [[], {}, None, True, 1]:
                bad = deepcopy(self.data["result_completed"])
                target = bad
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.reject(bad)

    def test_explicit_versions_and_legacy_compatibility(self):
        for message in LEGACY.values():
            self.assertEqual(decode_message(encode_message(message)), message)
        for version in ["1.1", "3.0", None, [], 2, True]:
            bad = deepcopy(self.data["request"])
            bad["schema_version"] = version
            self.reject(bad, "version_incompatible")
        with self.assertRaises(MessageError) as caught:
            correlate(LEGACY["request"], self.data["result_completed"])
        self.assertEqual(caught.exception.code, "version_incompatible")

    def test_request_limits_authentication_and_protocols(self):
        request = self.data["request"]
        for protocol in ("ssh", "ftp", "smb"):
            request["payload"]["protocol"] = protocol
            request["payload"]["authentication"] = {"mode": "none"}
            validate_message(request)
        for key, values in {
            "timeout_seconds": [0, 86401, True, 1.0],
            "stdout_max_bytes": [0, -1, 2**63, True],
            "stderr_max_bytes": [0, None],
            "artifact_max_bytes": [0, "10"],
            "max_supports": [-1, 1025, True],
        }.items():
            for value in values:
                bad = deepcopy(request)
                bad["payload"]["limits"][key] = value
                self.reject(bad)
        for value in [0, 65536, True, "22"]:
            bad = deepcopy(request)
            bad["payload"]["port"] = value
            self.reject(bad)
        request["payload"]["authentication"] = {"mode": "none", "credential_reference": "SECRET"}
        self.reject(request)

    def test_scopes_and_structural_nulls(self):
        for name, key in [("request", "attempt_id"), ("request", "derived_case_id"),
                          ("discovery_request", "service_scenario_id")]:
            bad = deepcopy(self.data[name])
            bad[key] = None
            self.reject(bad)
        for name, key in [("closure", "attempt_id"), ("supervision", "derived_case_id"),
                          ("discovery_request", "derived_case_id")]:
            bad = deepcopy(self.data[name])
            bad[key] = "FABRICADO"
            self.reject(bad)
        bad = self.data["request"]
        bad["payload"]["host_reference"] = None
        self.reject(bad)

    def test_acceptance_running_and_unknown_are_distinct(self):
        for name, start, termination in [
            ("acceptance", "VERIFICADO", "NO_DETERMINADO"),
            ("status_running", "NO_ACREDITADO", "EN_CURSO"),
            ("status_uncertain", "NO_INICIADO", "NO_APLICA"),
        ]:
            bad = deepcopy(self.data[name])
            state = bad["payload"]["snapshot"]
            state["start"] = {"status": start, "reference": "INI-1" if start in {"VERIFICADO", "NO_INICIADO"} else None}
            state["termination"] = {"status": termination, "reference": None}
            self.reject(bad)

    def test_unknown_never_fabricates_absence_or_evidence(self):
        bad = self.data["result_uncertain"]
        for field, value in [("exit_code", 0), ("ended_at", "2026-10-19T12:00:01Z"),
                             ("supports", ["SUP-1"]), ("started_at", "2026-10-19T12:00:00Z")]:
            mutated = deepcopy(bad)
            mutated["payload"]["outcome"][field] = value
            self.reject(mutated)

    def test_uncertainty_reasons_do_not_claim_rejection(self):
        for reason in ("SPAWN_FAILED", "REQUEST_REJECTED", "TIMEOUT", "CLEANUP_FAILED"):
            bad = deepcopy(self.data["status_uncertain"])
            bad["payload"]["snapshot"]["reason_code"] = reason
            self.reject(bad)

    def test_verified_start_with_unknown_termination(self):
        message = self.data["result_uncertain"]
        state = message["payload"]["snapshot"]
        state["start"] = {"status": "VERIFICADO", "reference": "INI-1"}
        result = message["payload"]["outcome"]
        result.update(started_at="2026-10-19T12:00:00Z", effective_parameters_reference="PARAM-1",
                      stdout_reference="OUT-1", stdout_truncated=True)
        validate_message(message)
        state["cleanup"] = {"status": "completed", "reference": "LIM-1"}
        self.reject(message)

    def test_cleanup_failure_requires_reconciliation(self):
        for cleanup in ("failed", "pending", "unknown"):
            bad = deepcopy(self.data["result_completed"])
            state = bad["payload"]["snapshot"]
            state["cleanup"] = {"status": cleanup, "reference": "LIM-1" if cleanup == "failed" else None}
            self.reject(bad)
            state["reconciliation_required"] = True
            validate_message(bad)

    def test_no_response_authorizes_execution(self):
        for name, original in self.data.items():
            if "snapshot" not in original["payload"]:
                continue
            bad = deepcopy(original)
            bad["payload"]["snapshot"]["new_execution_authorized"] = True
            with self.subTest(name=name):
                self.reject(bad)

    def test_no_start_requires_documented_absence(self):
        bad = self.data["result_not_started"]
        bad["payload"]["snapshot"]["start"]["reference"] = None
        self.reject(bad)

    def test_interruption_timeout_and_exit_variants(self):
        bad = self.data["result_interrupted"]
        bad["payload"]["outcome"]["exit_code"] = 0
        self.reject(bad)
        bad["payload"]["outcome"]["signal"] = None
        validate_message(bad)
        bad["payload"]["outcome"]["timed_out"] = False
        self.reject(bad)
        bad["payload"]["snapshot"]["reason_code"] = "INTERRUPTED"
        validate_message(bad)

    def test_timestamps_are_calendar_valid_and_ordered(self):
        for stamp in ["2026-02-30T00:00:00Z", "2026-01-01T00:00:00+00:00", None]:
            bad = deepcopy(self.data["request"])
            bad["created_at"] = stamp
            self.reject(bad)
        for field, stamp in [("started_at", "2026-10-20T00:00:00Z"),
                             ("ended_at", "2026-10-18T00:00:00Z")]:
            bad = deepcopy(self.data["result_completed"])
            bad["payload"]["outcome"][field] = stamp
            self.reject(bad)

    def test_query_response_requires_original_and_query(self):
        for name in [n for n in self.data if n.startswith("status_")]:
            correlate_status(self.data["request"], self.data["query"], self.data[name])
        for key, value in [("query_reference", "OTHER"), ("request_reference", "OTHER"),
                           ("requested_information", ["INICIO"])]:
            bad = deepcopy(self.data["status_running"])
            bad["payload"][key] = value
            with self.assertRaises(MessageError):
                correlate_status(self.data["request"], self.data["query"], bad)

    def test_context_simulation_and_version_hash_mismatches(self):
        for key, value in [("execution_id", "OTHER"), ("decision_index", 2), ("attempt_id", "OTHER"),
                           ("simulation", True), ("versions", {"reference": "VERS-1", "sha256": "f" * 64})]:
            bad = deepcopy(self.data["result_completed"])
            bad[key] = value
            validate_message(bad)
            with self.assertRaises(MessageError) as caught:
                correlate(self.data["request"], bad)
            self.assertEqual(caught.exception.code, "identifier_mismatch")

    def test_result_references_and_support_budget(self):
        request = self.data["request"]
        result = self.data["result_completed"]
        correlate(request, result)
        request["payload"]["limits"]["max_supports"] = 0
        with self.assertRaises(MessageError):
            correlate(request, result)
        result["payload"]["snapshot"]["result"]["reference"] = "OTHER"
        self.reject(result, "identifier_mismatch")

    def test_discovery_and_nonzero_exit_do_not_calculate_risk(self):
        result = self.data["discovery_result"]
        result["payload"]["outcome"]["exit_code"] = 1
        correlate(self.data["discovery_request"], result)
        result["payload"]["risk"] = 0
        self.reject(result)

    def test_rejections_codes_hash_and_direction(self):
        for code in ERROR_CODES:
            self.data["rejection"]["payload"]["error_code"] = code
            correlate(self.data["request"], self.data["rejection"])
        bad = self.data["rejection"]
        bad["payload"]["rejected_sha256"] = "0" * 64
        with self.assertRaises(MessageError) as caught:
            correlate(self.data["request"], bad)
        self.assertEqual(caught.exception.code, "integrity_failure")
        bad["payload"]["rejected_sha256"] = hashlib.sha256(encode_message(self.data["request"])).hexdigest()
        bad["producer"] = "analitico"
        with self.assertRaises(MessageError):
            correlate(self.data["request"], bad)
        bad["producer"] = "persistencia"
        with self.assertRaises(MessageError):
            correlate(self.data["request"], bad)

    def test_duplicate_delivery_and_attempt_reuse(self):
        original = self.data["request"]
        self.assertEqual(compare_delivery(original, deepcopy(original)), "REPLAY")
        changed = deepcopy(original)
        changed["payload"]["port"] = 23
        with self.assertRaises(MessageError) as caught:
            compare_delivery(original, changed)
        self.assertEqual(caught.exception.code, "duplicate_conflict")
        changed = deepcopy(original)
        changed["message_id"] = "NEW-ID"
        with self.assertRaises(MessageError):
            compare_delivery(original, changed)
        changed["attempt_id"] = "NEW-ATTEMPT"
        self.assertEqual(compare_delivery(original, changed), "NEW")

    def test_closure_publication_correlation(self):
        correlate(self.data["closure"], self.data["persisted"])
        bad = self.data["persisted"]
        bad["payload"]["state_sha256"] = "0" * 64
        with self.assertRaises(MessageError):
            correlate(self.data["closure"], bad)
        bad["payload"]["status"] = "WRITTEN"
        self.reject(bad)

    def test_supervision_cannot_directly_set_terminal_state(self):
        bad = self.data["supervision"]
        for action in ("record_control", "request_pause", "request_stop", "request_resume"):
            bad["payload"]["action"] = action
            validate_message(bad)
        bad["payload"]["state"] = "CERRADO"
        self.reject(bad)

    def test_json_rejections_and_frame_boundary(self):
        raw = encode_message(self.data["request"])
        for invalid in [b"null", b"[]", b"\xff", raw + raw,
                        raw.replace(b'"port":22', b'"port":22,"port":22'),
                        raw.replace(b'"port":22', b'"port":22.0'),
                        raw.replace(b'"port":22', b'"port":NaN'),
                        b'[' * 1500 + b']' * 1500]:
            with self.assertRaises(MessageError):
                decode_message(invalid)
        self.assertEqual(decode_message(raw.ljust(MAX_FRAME_BYTES, b' ')), self.data["request"])
        with self.assertRaises(MessageError) as caught:
            decode_message(raw.ljust(MAX_FRAME_BYTES + 1, b' '))
        self.assertEqual(caught.exception.code, "message_too_large")


if __name__ == "__main__":
    unittest.main()
