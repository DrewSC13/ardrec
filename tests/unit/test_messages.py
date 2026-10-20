"""Validación y correlación con ejemplos de la especificación académica."""

from copy import deepcopy
import io
import json
from pathlib import Path
import unittest

from ardrec.messages import MessageError, correlate, decode_message, encode_message, validate_message
from ardrec.transport import MAX_FRAME_BYTES, read_frame, write_frame

FIXTURES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/messages.json").read_text(encoding="utf-8")
)


class MessageTests(unittest.TestCase):
    """Probar entradas válidas y rechazos sin ejecutar acciones técnicas."""

    def setUp(self):
        self.data = deepcopy(FIXTURES)

    def reject(self, value, code="schema_invalid"):
        with self.assertRaises(MessageError) as caught:
            validate_message(value)
        self.assertEqual(caught.exception.code, code)

    def test_examples_and_frames(self):
        for name, message in self.data.items():
            with self.subTest(name=name):
                raw = encode_message(message)
                stream = io.BytesIO()
                write_frame(stream, raw.decode("utf-8"))
                stream.seek(0)
                self.assertEqual(decode_message(read_frame(stream).encode("utf-8")), message)
                self.assertEqual(encode_message(decode_message(raw)), raw)

    def test_valid_correlations(self):
        for name in ["acceptance", "query", "result"]:
            correlate(self.data["request"], self.data[name])
        self.assertEqual(self.data, FIXTURES)

    def test_required_and_unknown_fields(self):
        for name, message in self.data.items():
            for field in list(message):
                bad = deepcopy(message)
                del bad[field]
                with self.subTest(name=name, field=field):
                    self.reject(bad)
            for field in list(message["payload"]):
                bad = deepcopy(message)
                del bad["payload"][field]
                with self.subTest(name=name, payload_field=field):
                    self.reject(bad)
            for location in [(), ("payload",), ("versions",)]:
                bad = deepcopy(message)
                target = bad[location[0]] if location else bad
                target["unexpected"] = 1
                self.reject(bad)

    def test_version_type_and_producer(self):
        bad = self.data["request"]
        bad["schema_version"] = "9.0"
        self.reject(bad, "version_incompatible")
        bad["schema_version"] = "1.0"
        bad["message_type"] = "unknown"
        self.reject(bad)
        bad["message_type"] = "execution_request"
        bad["producer"] = "tecnico"
        self.reject(bad)

    def test_identifiers_and_timestamp(self):
        for field, invalid in {
            "message_id": ["", "a b", "á", "x" * 129, None],
            "created_at": ["2026-02-30T00:00:00Z", "2026-01-01", "2026-01-01T00:00:00+00:00"],
        }.items():
            for value in invalid:
                bad = deepcopy(self.data["request"])
                bad[field] = value
                self.reject(bad)

    def test_numeric_types_and_ranges(self):
        for field, invalid in {
            "port": [True, 0, 65536, "22", 22.0],
            "timeout_seconds": [False, 0, 86401],
        }.items():
            for value in invalid:
                bad = deepcopy(self.data["request"])
                bad["payload"][field] = value
                self.reject(bad)
        for value in [True, -1, 2**63, 17.0]:
            bad = deepcopy(self.data["request"])
            bad["decision_index"] = value
            self.reject(bad)

    def test_acceptance_is_not_start(self):
        self.data["acceptance"]["payload"]["start_status"] = "VERIFICADO"
        self.reject(self.data["acceptance"])

    def test_inner_identity_mismatches(self):
        for name, field in [("request", "case_reference"), ("acceptance", "attempt_id"),
                            ("query", "decision_reference"), ("query", "attempt_id")]:
            bad = deepcopy(self.data[name])
            bad["payload"][field] = "OTRO"
            self.reject(bad, "identifier_mismatch")

    def test_cross_message_mismatches(self):
        # La respuesta es válida aisladamente, pero pertenece a otro contexto.
        for field in ["record_id", "execution_id", "correlation_id", "service_scenario_id",
                      "derived_case_id", "attempt_id", "decision_index", "versions"]:
            bad = deepcopy(self.data["result"])
            bad[field] = ({"reference": "OTRA"} if field == "versions" else
                          18 if field == "decision_index" else "OTRO")
            validate_message(bad)
            with self.subTest(field=field), self.assertRaises(MessageError) as caught:
                correlate(self.data["request"], bad)
            self.assertEqual(caught.exception.code, "identifier_mismatch")

    def test_request_reference_and_simulation(self):
        for field, value in [("request_reference", "OTRA"), ("simulation", True)]:
            bad = deepcopy(self.data["result"])
            bad["payload"][field] = value
            with self.assertRaises(MessageError) as caught:
                correlate(self.data["request"], bad)
            self.assertEqual(caught.exception.code, "identifier_mismatch")

    def test_query_information(self):
        for values in [[], ["INICIO", "INICIO"], ["OTRO"], [None]]:
            bad = deepcopy(self.data["query"])
            bad["payload"]["requested_information"] = values
            self.reject(bad)

    def test_result_profile_and_supports(self):
        for field, value in [("timed_out", True), ("technical_status", "unknown"),
                             ("exit_code", True), ("duration_ms", -1),
                             ("supports", ["SUP", "SUP"]),
                             ("cleanup", {"status": "pending", "reference": "LIM"})]:
            bad = deepcopy(self.data["result"])
            bad["payload"][field] = value
            self.reject(bad)
        self.data["result"]["payload"]["exit_code"] = 1
        validate_message(self.data["result"])

    def test_json_rejections(self):
        valid = encode_message(self.data["request"])
        invalid = [
            b'null', b'{}', b'[]', b'\xff', valid + b'{}',
            valid.replace(b'"port":22', b'"port":22,"port":22'),
            valid.replace(b'"port":22', b'"port":22.0'),
            valid.replace(b'"port":22', b'"port":NaN'),
        ]
        for raw in invalid:
            with self.subTest(raw=raw[:40]), self.assertRaises(MessageError):
                decode_message(raw)

    def test_payload_size(self):
        raw = encode_message(self.data["request"])
        self.assertEqual(
            decode_message(raw.ljust(MAX_FRAME_BYTES, b' ')),
            self.data["request"],
        )
        with self.assertRaises(MessageError) as caught:
            decode_message(raw.ljust(MAX_FRAME_BYTES + 1, b' '))
        self.assertEqual(caught.exception.code, "message_too_large")


if __name__ == "__main__":
    unittest.main()
