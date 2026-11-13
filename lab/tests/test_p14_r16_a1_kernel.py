"""Oráculos independientes para el núcleo puro A1-R16; ninguna ejecución técnica."""
from __future__ import annotations

from fractions import Fraction
from itertools import product
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from ardrec.state import Truth
from ardrec.rules import A1Error, compile_expression, decide, evaluate, guard_allows


def logical(value):
    return {"op": "CONSTANTE", "tipo": "LOGICO", "valor": value.name}


def rational(text):
    return {"op": "CONSTANTE", "tipo": "RACIONAL", "valor": text}


def field(name):
    return {"op": "CAMPO", "nombre": name}


class KernelA1Tests(unittest.TestCase):
    def test_not_exhaustive(self):
        expected = {Truth.VERDADERO: Truth.FALSO, Truth.FALSO: Truth.VERDADERO,
                    Truth.ND: Truth.ND}
        for a in Truth:
            self.assertIs(evaluate({"op": "NO", "arg": logical(a)}, {}, {}), expected[a])

    def test_and_truth_table_exhaustive_independent(self):
        # Tabla explícita que no invoca el algoritmo para construir el esperado.
        f, n, t = Truth.FALSO, Truth.ND, Truth.VERDADERO
        expected = {(f,f):f,(f,n):f,(f,t):f,(n,f):f,(n,n):n,
                    (n,t):n,(t,f):f,(t,n):n,(t,t):t}
        for a, b in product(Truth, repeat=2):
            expr = {"op":"Y", "args":[logical(a), logical(b)]}
            self.assertIs(evaluate(expr, {}, {}), expected[(a,b)])

    def test_or_truth_table_exhaustive_independent(self):
        f, n, t = Truth.FALSO, Truth.ND, Truth.VERDADERO
        expected = {(f,f):f,(f,n):n,(f,t):t,(n,f):n,(n,n):n,
                    (n,t):t,(t,f):t,(t,n):t,(t,t):t}
        for a, b in product(Truth, repeat=2):
            self.assertIs(evaluate({"op":"O", "args":[logical(a), logical(b)]}, {}, {}), expected[(a,b)])

    def test_three_input_conjunction_is_associative(self):
        for a,b,c in product(Truth,repeat=3):
            x={"op":"Y","args":[logical(a),logical(b),logical(c)]}
            y={"op":"Y","args":[logical(a),{"op":"Y","args":[logical(b),logical(c)]}]}
            self.assertIs(evaluate(x,{},{}),evaluate(y,{},{}))

    def test_three_input_disjunction_is_associative(self):
        for a,b,c in product(Truth,repeat=3):
            x={"op":"O","args":[logical(a),logical(b),logical(c)]}
            y={"op":"O","args":[logical(a),{"op":"O","args":[logical(b),logical(c)]}]}
            self.assertIs(evaluate(x,{},{}),evaluate(y,{},{}))

    def test_missing_declared_field_is_nd(self):
        self.assertIs(evaluate(field("autorizado"),{"autorizado":"LOGICO"},{}),Truth.ND)

    def test_missing_rational_is_nd_in_comparison(self):
        exp={"op":"COMPARAR","relacion":"MENOR","izq":field("riesgo"),"der":rational("1/2")}
        self.assertIs(evaluate(exp,{"riesgo":"RACIONAL"},{}),Truth.ND)

    def test_numeric_comparisons_exact(self):
        for op,expected in (("IGUAL",Truth.VERDADERO),("MENOR",Truth.FALSO),
                            ("MENOR_IGUAL",Truth.VERDADERO),("MAYOR",Truth.FALSO),
                            ("MAYOR_IGUAL",Truth.VERDADERO),("DISTINTO",Truth.FALSO)):
            exp={"op":"COMPARAR","relacion":op,"izq":rational("1/3"),"der":rational("1/3")}
            self.assertIs(evaluate(exp,{},{}),expected)

    def test_numeric_field_uses_fraction_not_float(self):
        e={"op":"COMPARAR","relacion":"MAYOR","izq":field("p"),"der":rational("1/3")}
        self.assertIs(evaluate(e,{"p":"RACIONAL"},{"p":Fraction(34,100)}),Truth.VERDADERO)

    def test_text_same_domain_equality(self):
        e={"op":"COMPARAR","relacion":"IGUAL","izq":field("protocol"),
           "der":{"op":"CONSTANTE","tipo":"TEXTO","valor":"SSH"}}
        self.assertIs(evaluate(e,{"protocol":"TEXTO"},{"protocol":"SSH"}),Truth.VERDADERO)

    def test_text_relational_rejected(self):
        e={"op":"COMPARAR","relacion":"MAYOR","izq":field("a"),"der":field("b")}
        with self.assertRaisesRegex(A1Error,"relacion_tipo_incompatible"):
            evaluate(e,{"a":"TEXTO","b":"TEXTO"},{"a":"z","b":"a"})

    def test_mixed_domains_rejected(self):
        e={"op":"COMPARAR","relacion":"IGUAL","izq":field("a"),"der":field("b")}
        with self.assertRaisesRegex(A1Error,"tipos_incompatibles"):
            evaluate(e,{"a":"TEXTO","b":"RACIONAL"},{"a":"5","b":Fraction(5)})

    def test_unauthorized_field_rejected_even_if_missing(self):
        with self.assertRaisesRegex(A1Error,"campo_no_autorizado"):
            evaluate(field("not_listed"),{"safe":"LOGICO"},{})

    def test_unauthorized_environment_rejected(self):
        with self.assertRaisesRegex(A1Error,"ambiente_no_autorizado"):
            evaluate(logical(Truth.VERDADERO),{}, {"intruder":Truth.VERDADERO})

    def test_bool_is_not_rational(self):
        e={"op":"COMPARAR","relacion":"IGUAL","izq":field("p"),"der":rational("1")}
        with self.assertRaisesRegex(A1Error,"ambiente_tipo_invalido"):
            evaluate(e,{"p":"RACIONAL"},{"p":True})

    def test_float_rejected(self):
        with self.assertRaisesRegex(A1Error,"racional_invalido"):
            evaluate({"op":"COMPARAR","relacion":"IGUAL","izq":rational(0.5),"der":rational("1/2")},{},{})

    def test_fraction_noncanonical_rejected(self):
        with self.assertRaisesRegex(A1Error,"racional_no_canonico"):
            evaluate({"op":"COMPARAR","relacion":"IGUAL","izq":rational("2/4"),"der":rational("1/2")},{},{})

    def test_operator_unknown_rejected(self):
        with self.assertRaisesRegex(A1Error,"operador_no_autorizado"):
            evaluate({"op":"EJECUTAR","command":"true"},{},{})

    def test_extra_keys_rejected(self):
        with self.assertRaisesRegex(A1Error,"estructura_invalida"):
            evaluate({**logical(Truth.VERDADERO),"silent":True},{},{})

    def test_invalid_arity_rejected(self):
        with self.assertRaisesRegex(A1Error,"aridad_invalida"):
            evaluate({"op":"Y","args":[logical(Truth.VERDADERO)]},{},{})

    def test_cycle_rejected(self):
        a={"op":"NO"};a["arg"]=a
        with self.assertRaisesRegex(A1Error,"expresion_ciclica"):
            compile_expression(a,{})

    def test_too_deep_rejected(self):
        a=logical(Truth.VERDADERO)
        for _ in range(22):a={"op":"NO","arg":a}
        with self.assertRaisesRegex(A1Error,"expresion_no_acotada"):
            compile_expression(a,{})

    def test_only_true_allows(self):
        self.assertEqual([guard_allows(v) for v in Truth],
                         [v is Truth.VERDADERO for v in Truth])
        with self.assertRaisesRegex(A1Error,"guarda_no_logica"):
            guard_allows(True)

    def test_decide_unique_true(self):
        rows=[{"id":"rB","condicion":logical(Truth.FALSO)},
              {"id":"rA","condicion":logical(Truth.VERDADERO)}]
        d=decide(rows,{}, {})
        self.assertTrue(d.authorized);self.assertEqual(d.selected,"rA")
        self.assertEqual(d.evaluations,(("rA",Truth.VERDADERO),("rB",Truth.FALSO)))

    def test_decide_permutation_deterministic(self):
        rows=[{"id":"a","condicion":logical(Truth.VERDADERO)},
              {"id":"b","condicion":logical(Truth.FALSO)}]
        self.assertEqual(decide(rows,{},{}),decide(list(reversed(rows)),{},{}))

    def test_decide_uncertainty_denies(self):
        rows=[{"id":"a","condicion":logical(Truth.VERDADERO)},
              {"id":"b","condicion":logical(Truth.ND)}]
        d=decide(rows,{},{});self.assertIs(d.status,Truth.ND)
        self.assertFalse(d.authorized);self.assertIsNone(d.selected)

    def test_decide_all_false(self):
        d=decide([{"id":"a","condicion":logical(Truth.FALSO)}],{}, {})
        self.assertIs(d.status,Truth.FALSO);self.assertFalse(d.authorized)

    def test_decide_multiple_true_rejected(self):
        rows=[{"id":"a","condicion":logical(Truth.VERDADERO)},
              {"id":"b","condicion":logical(Truth.VERDADERO)}]
        with self.assertRaisesRegex(A1Error,"reglas_ambiguas"):
            decide(rows,{}, {})

    def test_decide_duplicate_rows_rejected(self):
        rows=[{"id":"a","condicion":logical(Truth.VERDADERO)}]*2
        with self.assertRaisesRegex(A1Error,"id_fila_invalida_o_duplicada"):
            decide(rows,{}, {})

    def test_decide_invalid_row_even_after_true_rejected(self):
        rows=[{"id":"a","condicion":logical(Truth.VERDADERO)},
              {"id":"b","condicion":{"op":"EJECUTAR"}}]
        with self.assertRaisesRegex(A1Error,"operador_no_autorizado"):
            decide(rows,{}, {})

    def test_unhashable_schema_type_rejected(self):
        with self.assertRaisesRegex(A1Error,"campo_no_autorizado"):
            evaluate(field("x"),{"x":[]},{})

    def test_unhashable_constant_type_rejected(self):
        e={"op":"CONSTANTE","tipo":[],"valor":"ND"}
        with self.assertRaisesRegex(A1Error,"tipo_invalido"):
            evaluate(e,{},{})

    def test_unhashable_relation_rejected(self):
        e={"op":"COMPARAR","relacion":[],"izq":rational("0"),"der":rational("0")}
        with self.assertRaisesRegex(A1Error,"relacion_no_autorizada"):
            evaluate(e,{},{})

    def test_decide_no_side_effects(self):
        rows=[{"id":"a","condicion":field("x")}]
        schema={"x":"LOGICO"};env={"x":Truth.VERDADERO}
        before=repr((rows,schema,env))
        d=decide(rows,schema,env)
        self.assertTrue(d.authorized);self.assertEqual(repr((rows,schema,env)),before)


if __name__ == "__main__":
    unittest.main()
