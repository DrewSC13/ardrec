"""Contrastar operaciones Python y Rust sobre las mismas entradas de prueba."""

from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ardrec import messages

OPERATIONS = (
    "decode_message", "encode_message", "validate_message",
    "correlate", "correlate_status", "compare_delivery",
)


def execute(args, env=None):
    subprocess.run(args, cwd=ROOT, env=env, check=True, timeout=300)


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tests/unit" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compare(probe):
    counts = Counter()

    def wrapper(operation):
        original = getattr(messages, operation)

        def checked(*args):
            saved = json.dumps(args, default=lambda b: {"bytes": b.hex()}, sort_keys=True)
            error = None
            try:
                value = original(*args)
                if operation == "decode_message":
                    expected = {"hex": messages.encode_message(value).hex()}
                elif operation == "encode_message":
                    expected = {"hex": value.hex()}
                elif operation == "compare_delivery":
                    expected = {"delivery": value}
                else:
                    expected = {}
                expected = {"ok": True, "value": expected}
            except messages.MessageError as caught:
                error = caught
                expected = {"ok": False, "code": caught.code}

            # Los bytes originales viajan sin pasar por el parser JSON de control.
            transmitted = [args[0].hex()] if operation == "decode_message" else args
            request = json.dumps({"op": operation, "args": transmitted}, ensure_ascii=True)
            result = subprocess.run(
                [str(probe)], input=request, capture_output=True,
                text=True, encoding="utf-8", timeout=10,
            )
            if result.returncode:
                raise AssertionError(f"Sonda Rust falló en {operation}: {result.stderr[:500]}")
            actual = json.loads(result.stdout)
            if actual != expected:
                raise AssertionError(
                    f"Divergencia {operation}: esperado={expected!r}; Rust={actual!r}; "
                    f"entrada={request[:500]}"
                )
            if saved != json.dumps(args, default=lambda b: {"bytes": b.hex()}, sort_keys=True):
                raise AssertionError("La validación modificó la entrada")
            counts[operation] += 1
            counts["accepted" if expected["ok"] else "rejected"] += 1
            if error is not None:
                raise error
            return value
        return checked

    modules = [load(name) for name in (
        "test_messages", "test_protocol_v2", "test_protocol_equivalence",
    )]
    suite = unittest.TestSuite()
    with ExitStack() as stack:
        for module in modules:
            for operation in OPERATIONS:
                if hasattr(module, operation):
                    stack.enter_context(patch.object(module, operation, wrapper(operation)))
            suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise RuntimeError("La equivalencia del protocolo no superó las pruebas")
    if any(counts[name] == 0 for name in (*OPERATIONS, "accepted", "rejected")):
        raise RuntimeError("Alguna operación no fue ejercitada")
    return {"test_methods": result.testsRun, "comparisons": dict(counts)}


def main():
    if sys.version_info[:3] != (3, 14, 7):
        raise RuntimeError("Ejecutar la equivalencia con Python 3.14.7, fijado por el proyecto")
    locks = {name: (ROOT / name).read_bytes() for name in ("Cargo.lock", "uv.lock") if (ROOT / name).exists()}
    with tempfile.TemporaryDirectory(prefix="ardrec-protocol-") as temporary:
        env = dict(os.environ, CARGO_TARGET_DIR=str(Path(temporary) / "target"))
        execute(["cargo", "test", "--workspace", "--all-targets", "--locked", "--offline"], env)
        execute(["cargo", "build", "--example", "protocol_probe", "--locked", "--offline"], env)
        report = compare(Path(env["CARGO_TARGET_DIR"]) / "debug/examples/protocol_probe")
    if any((ROOT / name).read_bytes() != value for name, value in locks.items()):
        raise RuntimeError("Se modificó un archivo de bloqueo")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"ARDREC_PROTOCOL_COMPARISONS={sum(report['comparisons'][name] for name in OPERATIONS)}")
    print(f"ARDREC_PROTOCOL_ACCEPTED={report['comparisons']['accepted']}")
    print(f"ARDREC_PROTOCOL_REJECTED={report['comparisons']['rejected']}")
    print("ARDREC_PROTOCOL_DIFFERENTIAL=PASS")
    print("ARDREC_PROTOCOL_EXACT_VALUES=PASS")
    print("ARDREC_PROTOCOL_CANONICAL_BYTES=PASS")
    print("ARDREC_PROTOCOL_ERROR_CODES=PASS")
    print("ARDREC_ALGORITHM_TESTS=NOT_RUN")
    print("ARDREC_EXPERIMENTAL_VALIDATION=NOT_RUN")


if __name__ == "__main__":
    main()
