"""Casos de frontera independientes para contrastar ambos validadores."""

from copy import deepcopy
import json
from pathlib import Path
import unittest

from ardrec.messages import (
    MessageError, compare_delivery, correlate, correlate_status,
    decode_message, encode_message, validate_message,
)
from ardrec.transport import MAX_FRAME_BYTES

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
V1 = json.loads((FIXTURES / "messages.json").read_text(encoding="utf-8"))
V2 = json.loads((FIXTURES / "messages-v2.json").read_text(encoding="utf-8"))


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class ProtocolEquivalenceTests(unittest.TestCase):
    """Exigir resultados literales sin generar expectativas desde el código Rust."""

    def reject_raw(self, payload, code="schema_invalid"):
        with self.assertRaises(MessageError) as caught:
            decode_message(payload)
        self.assertEqual(caught.exception.code, code)

    def test_exact_integer_round_trips(self):
        for source in (V1, V2):
            for value in (0, 1, 2**31 - 1, 2**53 - 1, 2**53, 2**53 + 1, 2**63 - 1):
                message = deepcopy(source["request"])
                message["decision_index"] = value
                wire = raw(message)
                decoded = decode_message(wire)
                self.assertIs(type(decoded["decision_index"]), int)
                self.assertEqual(decoded["decision_index"], value)
                self.assertEqual(encode_message(decoded), wire)
                self.assertIn(b'"decision_index":' + str(value).encode() + b',', wire)
            for value in (-1, 2**63, 2**64, 2**255, 2**256, True, 1.0, "1"):
                message = deepcopy(source["request"])
                message["decision_index"] = value
                self.reject_raw(raw(message))

    def test_all_numeric_boundaries(self):
        for profile in (V1, V2):
            for port in (1, 65535):
                message = deepcopy(profile["request"])
                message["payload"]["port"] = port
                self.assertEqual(decode_message(raw(message)), message)
        source = V2["request"]
        for key, low, high in (
            ("timeout_seconds", 1, 86400), ("max_supports", 0, 1024),
            ("stdout_max_bytes", 1, 2**63 - 1),
            ("stderr_max_bytes", 1, 2**63 - 1),
            ("artifact_max_bytes", 1, 2**63 - 1),
        ):
            for value in (low, high):
                message = deepcopy(source)
                message["payload"]["limits"][key] = value
                self.assertEqual(decode_message(raw(message)), message)
            for value in (low - 1, high + 1, True, False, None, 1.0, [], {}):
                message = deepcopy(source)
                message["payload"]["limits"][key] = value
                self.reject_raw(raw(message))
        for source in (V1["result"], V2["result_completed"]):
            message = deepcopy(source)
            p = message["payload"].get("outcome", message["payload"])
            p["duration_ms"] = 2**63 - 1
            self.assertEqual(decode_message(raw(message)), message)
            p["duration_ms"] = 2**63
            self.reject_raw(raw(message))
        message = deepcopy(V1["result"])
        for value in (-(2**31), 2**31 - 1):
            message["payload"]["exit_code"] = value
            self.assertEqual(decode_message(raw(message)), message)
        message = deepcopy(V2["result_completed"])
        message["payload"]["outcome"]["exit_code"] = -1
        self.reject_raw(raw(message))

    def test_json_integer_grammar(self):
        message = deepcopy(V2["request"])
        message["decision_index"] = 0
        wire = raw(message)
        negative_zero = wire.replace(b'"decision_index":0', b'"decision_index":-0')
        self.assertEqual(decode_message(negative_zero), message)
        self.assertEqual(encode_message(decode_message(negative_zero)), wire)
        for token in (b"00", b"01", b"-01", b"+0", b"0.0", b"-0.0", b"0e0", b"1E+0", b"NaN", b"Infinity", b"-Infinity", b"1e9999", b"0x10"):
            self.reject_raw(wire.replace(b'"decision_index":0', b'"decision_index":' + token))

    def test_malformed_bytes_and_documents(self):
        wire = raw(V2["request"])
        for value in (
            b"", b" ", b"null", b"[]", b"true", b"0", b"{}",
            b"\xff", b"\xc0\xaf", b"\xef\xbb\xbf" + wire,
            wire + b"null", wire + b"\x00", wire[:-1],
            b"/* comentario */" + wire, wire[:-1] + b",}",
            b"[" * 2000 + b"0" + b"]" * 2000,
            wire.replace(b'"REQ-1"', b'"\\ud800"'),
            wire.replace(b'"REQ-1"', b'"a\x01b"'),
        ):
            self.reject_raw(value)
        for whitespace in (b" ", b"\t\r\n", b"\n"):
            self.assertEqual(decode_message(whitespace + wire + whitespace), V2["request"])
        self.reject_raw(wire + b"\x0b")

    def test_duplicate_keys_at_every_object(self):
        def objects(value):
            if type(value) is dict:
                yield value
                for child in value.values():
                    yield from objects(child)
        for message in [*V1.values(), *V2.values()]:
            wire = raw(message)
            for obj in objects(message):
                fragment = raw(obj)
                key = next(iter(obj))
                pair = raw({key: obj[key]})[1:-1]
                duplicated = b"{" + pair + b"," + fragment[1:]
                self.assertIn(fragment, wire)
                self.reject_raw(wire.replace(fragment, duplicated, 1))
        wire = raw(V2["request"])
        self.reject_raw(wire.replace(b'"port":22', b'"port":22,"\\u0070ort":22'))
        # Las mismas claves son válidas en objetos diferentes.
        self.assertEqual(decode_message(raw(V2["result_completed"])), V2["result_completed"])

    def test_canonical_encoding_and_escapes(self):
        for message in [*V1.values(), *V2.values()]:
            unsorted = json.dumps(message, indent=2).encode()
            self.assertEqual(encode_message(decode_message(unsorted)), raw(message))
        message = deepcopy(V2["request"])
        message["message_id"] = "A-0"
        wire = raw(message)
        escaped = wire.replace(b'"A-0"', b'"\\u0041-0"')
        self.assertEqual(encode_message(decode_message(escaped)), wire)
        for token in (b'"\\ud83d\\ude00"', b'"\\u00e9"', b'"a/b"', b'"a\\nb"'):
            self.reject_raw(wire.replace(b'"A-0"', token))

    def test_exact_byte_limits(self):
        for source in (V1, V2):
            message = source["request"]
            wire = raw(message)
            for size in (MAX_FRAME_BYTES - 1, MAX_FRAME_BYTES):
                self.assertEqual(decode_message(wire.ljust(size, b" ")), message)
            self.reject_raw(wire.ljust(MAX_FRAME_BYTES + 1, b" "), "message_too_large")
            self.reject_raw(b"\xff" * (MAX_FRAME_BYTES + 1), "message_too_large")

    def test_calendar_and_precision_boundaries(self):
        for source in (V1, V2):
            for stamp in ("0001-01-01T00:00:00Z", "2000-02-29T23:59:59.000001Z", "2024-02-29T00:00:00.1Z", "9999-12-31T23:59:59.999999Z"):
                message = deepcopy(source["request"])
                message["created_at"] = stamp
                self.assertEqual(decode_message(raw(message)), message)
            for stamp in ("0000-01-01T00:00:00Z", "1900-02-29T00:00:00Z", "2100-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-01-01T25:00:00Z", "2026-01-01T23:59:60Z", "2026-01-01T00:00:00.1234567Z", "2026-01-01T00:00:00.Z", "2026-01-01T00:00:00+00:00"):
                message = deepcopy(source["request"])
                message["created_at"] = stamp
                self.reject_raw(raw(message))

    def test_python314_midnight_rollover(self):
        for profile in (V1, V2):
            for stamp in ("2026-01-01T24:00:00Z", "2026-01-01T24:00:00.000000Z", "2024-02-28T24:00:00Z", "2024-02-29T24:00:00Z", "2026-12-31T24:00:00Z", "9999-12-30T24:00:00Z"):
                message = deepcopy(profile["request"])
                message["created_at"] = stamp
                self.assertEqual(decode_message(raw(message)), message)
                self.assertEqual(encode_message(message), raw(message))
            for stamp in ("2026-01-01T24:00:00.000001Z", "2026-01-01T24:00:01Z", "2026-01-01T24:01:00Z", "9999-12-31T24:00:00Z", "0000-12-31T24:00:00Z", "2026-01-00T24:00:00Z", "2026-00-01T24:00:00Z", "2026-13-01T24:00:00Z", "2026-04-31T24:00:00Z"):
                message["created_at"] = stamp
                self.reject_raw(raw(message))
        message = deepcopy(V2["result_completed"])
        message["created_at"] = "2026-10-20T00:00:00Z"
        message["payload"]["snapshot"]["observed_at"] = "2026-10-19T24:00:00Z"
        message["payload"]["outcome"]["started_at"] = "2026-10-19T23:59:59.999999Z"
        message["payload"]["outcome"]["ended_at"] = "2026-10-20T00:00:00Z"
        self.assertEqual(decode_message(raw(message)), message)
        message["created_at"] = "2026-10-19T23:59:59.999999Z"
        self.reject_raw(raw(message))

    def test_all_scalar_substitutions(self):
        def leaves(value, path=()):
            if type(value) is dict:
                for key, child in value.items():
                    yield from leaves(child, (*path, key))
            elif type(value) is not list:
                yield path, value
        for message in [*V1.values(), *V2.values()]:
            for path, original in leaves(message):
                for replacement in ([], {}):
                    changed = deepcopy(message)
                    target = changed
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = replacement
                    code = "version_incompatible" if path == ("schema_version",) else "schema_invalid"
                    self.reject_raw(raw(changed), code)

    def test_support_and_identifier_limits(self):
        for source in (V1["result"], V2["result_completed"]):
            message = deepcopy(source)
            payload = message["payload"].get("outcome", message["payload"])
            payload["supports"] = [f"SUP-{i}" for i in range(1024)]
            self.assertEqual(decode_message(raw(message)), message)
            payload["supports"].append("SUP-1024")
            self.reject_raw(raw(message))
        for length in (1, 128):
            message = deepcopy(V2["request"])
            message["message_id"] = "a" * length
            self.assertEqual(decode_message(raw(message)), message)
        for length in (0, 129):
            message["message_id"] = "a" * length
            self.reject_raw(raw(message))


if __name__ == "__main__":
    unittest.main()
