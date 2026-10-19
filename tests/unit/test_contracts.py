"""Pruebas del contrato numérico. / Numeric contract tests."""

from dataclasses import FrozenInstanceError
from fractions import Fraction
import unittest

from ardrec.contracts import (
    ContractError, MAX_INTEGER_BITS, MAX_JSON_BYTES, ND,
    decode_magnitude, dump_magnitude, dump_rational, encode_magnitude,
    parse_magnitude, parse_rational,
)


class ContractTests(unittest.TestCase):
    """Casos válidos, adversos y de frontera. / Valid, adverse and boundary cases."""

    def test_exact_arithmetic(self):
        a = parse_rational({"numerator": 1, "denominator": 3})
        b = parse_rational({"numerator": 1, "denominator": 6})
        self.assertEqual(dump_rational(a + b), {"numerator": 1, "denominator": 2})

    def test_canonical_input(self):
        for n, d in [(2, 4), (0, 2), (1, 0), (1, -2), (-1, -2)]:
            with self.subTest(n=n, d=d), self.assertRaises(ContractError):
                parse_rational({"numerator": n, "denominator": d})

    def test_exact_integer_types(self):
        for field in ["numerator", "denominator"]:
            for bad in [True, False, 1.0, "1", None]:
                data = {"numerator": 1, "denominator": 2, field: bad}
                with self.subTest(field=field, bad=bad), self.assertRaises(ContractError):
                    parse_rational(data)

    def test_fields(self):
        for bad in [None, [], {}, {"numerator": 1},
                    {"numerator": 1, "denominator": 2, "extra": 0}]:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                parse_rational(bad)

    def test_integer_boundaries(self):
        limit = (1 << MAX_INTEGER_BITS) - 1
        for value in [Fraction(limit), Fraction(-limit), Fraction(1, limit)]:
            self.assertEqual(decode_magnitude(encode_magnitude(value)), value)
        for value in [Fraction(limit + 1), Fraction(-limit - 1), Fraction(1, limit + 1)]:
            with self.subTest(value=value), self.assertRaises(ContractError):
                encode_magnitude(value)

    def test_round_trips(self):
        for n in range(-20, 21):
            for d in range(1, 21):
                value = Fraction(n, d)
                with self.subTest(n=n, d=d):
                    wire = encode_magnitude(value)
                    self.assertEqual(decode_magnitude(wire), value)
                    self.assertEqual(encode_magnitude(decode_magnitude(wire)), wire)

    def test_nd_preserves_reason(self):
        value = ND("SOPORTE_INSUFICIENTE")
        self.assertEqual(decode_magnitude(encode_magnitude(value)), value)
        self.assertNotEqual(value, Fraction(0))
        with self.assertRaises(FrozenInstanceError):
            value.reason_code = "OTRO"

    def test_invalid_nd(self):
        for bad in [None, "", " ", "motivo", "A" * 65, 1, True]:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                ND(bad)

    def test_variants(self):
        for bad in [None, {}, {"status": "ND"}, {"status": "OTRO", "value": 0},
                    {"status": "DETERMINADO", "value": None},
                    {"status": "ND", "reason_code": "X", "value": None}]:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                parse_magnitude(bad)
        for bad in [None, 0, 0.5, True, "ND"]:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                dump_magnitude(bad)

    def test_json_rejections(self):
        for bad in [b'null', b'[]', b'{}', b'\xff', b'{',
                    b'{"status":"ND","status":"ND","reason_code":"X"}',
                    b'{"status":"DETERMINADO","value":{"numerator":1,"numerator":1,"denominator":2}}',
                    b'{"status":"ND","reason_code":"X"} {}']:
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                decode_magnitude(bad)
        for token in [b'1.0', b'1e0', b'NaN', b'Infinity', b'true']:
            bad = b'{"status":"DETERMINADO","value":{"numerator":' + token + b',"denominator":2}}'
            with self.subTest(token=token), self.assertRaises(ContractError):
                decode_magnitude(bad)

    def test_payload_limit(self):
        wire = encode_magnitude(ND("X"))
        self.assertEqual(decode_magnitude(wire.ljust(MAX_JSON_BYTES, b' ')), ND("X"))
        with self.assertRaises(ContractError):
            decode_magnitude(wire.ljust(MAX_JSON_BYTES + 1, b' '))

    def test_fixed_encoding(self):
        self.assertEqual(encode_magnitude(Fraction(0)),
                         b'{"status":"DETERMINADO","value":{"denominator":1,"numerator":0}}')


if __name__ == "__main__":
    unittest.main()
